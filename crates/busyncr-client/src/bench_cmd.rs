//! The `bench-chunking` subcommand: offline chunk-size sizing tool
//! (PRD §3.7, FR10) and, with `--compression`, the compression policy
//! simulator (FR-C1 §4, FR-C5). CLI wiring and rendering only — both
//! measurement engines live in `busyncr_core::bench` /
//! `busyncr_core::policy_bench`.

use std::collections::{HashMap, HashSet};
use std::fmt::Write as _;
use std::path::PathBuf;

use anyhow::{bail, Context};
use serde::Serialize;

use busyncr_core::bench::{
    build_report, chunk_tree, recommend, steady_state_snapshots, BenchReport, ChunkMeta,
    FileChunking, DEFAULT_PROJECTION_HORIZON_DAYS,
};
use busyncr_core::chunking::{ChunkId, ChunkerConfig};
use busyncr_core::policy_bench::{
    self, build_compression_report, chunk_tree_with_bytes, file_class_diagnostics,
    recommend_policy, throughput_mbps, BuildInputs, ChurnSource, CompressionReport, FileClass,
    PolicyKind, StageRates,
};

/// Long help shown by `bench-chunking --help`, documenting the method and
/// the recommendation heuristic (PRD §3.7).
pub const LONG_ABOUT: &str = "\
Offline chunk-size benchmark (PRD §3.7). Fully offline: no daemon, no keys, \
no network.

Every file under <PATH> is read from disk exactly once; the byte stream is \
fanned out to one content-defined chunker per candidate size running \
concurrently, hashing chunk boundaries with BLAKE3. Cost is about one full \
dataset read regardless of how many candidates you test.

Per candidate the report shows measured values (total/unique chunks, \
intra-dataset dedup ratio = total bytes / unique bytes, mean/median/p95 \
actual chunk size) and exact metadata projections (daemon index bytes = \
unique chunks x 48-byte index record; manifest bytes per snapshot; total \
bookkeeping for N retained snapshots, where N defaults to the steady-state \
occupancy of the PRD 3.5 retention grid over a 1-year horizon = 36).

Recommendation heuristic: the candidate with the smallest combined cost \
`unique_bytes + projected_bookkeeping_bytes` (best storage x metadata \
trade-off) is highlighted; ties go to the smaller size. The choice stays \
with you — commit it in config before the first backup; changing it later \
resets dedup continuity.

Without --baseline, dedup figures are intra-snapshot only and understate \
versioned savings. Point --baseline at an older copy of the same data to \
measure real cross-version chunk overlap.

Chunk IDs here are unkeyed BLAKE3, not the keyed chunk identity the real \
backup uses (FR-K1): the tool must run before any enrollment exists, and \
dedup ratios are key-invariant, so the measurements carry over unchanged to \
keyed backups.

--compression simulates five candidate compression policies (FR-C1 §4.1: \
raw-only, zstd3-always, zstd3, probe+zstd3, zstd3+escalate) over the \
unique-chunk stream of a single selected chunk size (--sizes must resolve \
to exactly one candidate in this mode). Every figure is measured against \
the real busyncr_core::compression policy engine, not estimated: total \
stored bytes (post-policy, +AEAD overhead), compression MB/s, and a \
backup-speed projection (read/CDC/BLAKE3/compress MB/s measured on your \
data plus a synthetic AEAD microbenchmark, combined per --threads) at the \
CPU-bound floor and at each --net-mbps bandwidth point (default \
50,200,1000). --baseline turns on the incremental-update row (real \
new-chunk volume); --assume-churn <pct> models it instead, labeled assumed. \
Escalation is always off in the primary columns, matching FR-C6's real \
phase gate on a first backup; its payoff shows up only in the incremental \
row. Recommendation heuristic: smallest projected steady-state store size \
among policies whose initial-backup CPU-bound time is within 1.5x of \
zstd3's.";

/// Arguments for `bench-chunking`.
#[derive(Debug, clap::Args)]
pub struct BenchArgs {
    /// Directory tree to measure.
    pub path: PathBuf,

    /// Comma-separated candidate target chunk sizes. Suffixes: K = KiB,
    /// M = MiB; plain numbers are bytes.
    #[arg(long, value_delimiter = ',', default_value = "256K,512K,1M,2M,4M")]
    pub sizes: Vec<String>,

    /// Older copy of the same data; measures real cross-version chunk
    /// overlap (the honest proxy for cross-snapshot dedup).
    #[arg(long)]
    pub baseline: Option<PathBuf>,

    /// Retained snapshot count N for the bookkeeping projection
    /// [default: steady-state retention-grid occupancy over 1 year = 36].
    #[arg(long)]
    pub snapshots: Option<u64>,

    /// Emit a machine-readable JSON report instead of the table.
    #[arg(long)]
    pub json: bool,

    /// Simulate compression policies (FR-C1 §4) over the unique-chunk
    /// stream. Requires --sizes to resolve to exactly one candidate.
    #[arg(long)]
    pub compression: bool,

    /// CPU threads assumed for the backup-speed projection (FR-C1 §4.4)
    /// [default: available parallelism].
    #[arg(long)]
    pub threads: Option<u32>,

    /// Bandwidth points (Mbit/s) for the backup-speed projection.
    #[arg(long, value_delimiter = ',', default_value = "50,200,1000")]
    pub net_mbps: Vec<f64>,

    /// Assumed incremental churn percentage (0-100), used only when
    /// --baseline is not given; the report labels this figure "assumed".
    #[arg(long)]
    pub assume_churn: Option<f64>,
}

/// JSON envelope: the core report plus the recommendation and honesty note.
#[derive(Serialize)]
struct JsonOutput<'a> {
    #[serde(flatten)]
    report: &'a BenchReport,
    /// Target size chosen by the documented heuristic (see `--help`).
    recommended_target_size: Option<u64>,
    /// Interpretation caveat for the dedup figures.
    note: &'a str,
    /// `--compression` policy simulation (FR-C1 §4.5: "extend the existing
    /// schema; policy simulation under a `compression_policies` key").
    #[serde(skip_serializing_if = "Option::is_none")]
    compression_policies: Option<CompressionPoliciesJson>,
}

/// `compression_policies` JSON payload: the raw report plus the
/// recommendation, mirroring the top-level envelope's shape.
#[derive(Serialize)]
struct CompressionPoliciesJson {
    #[serde(flatten)]
    report: CompressionReport,
    recommended_policy: Option<&'static str>,
    /// FR-C1 §4.3 diagnostics, under the recommended policy.
    file_classes: Vec<policy_bench::FileClassRow>,
}

/// Parses a size like `256K`, `1M`, or `4096` into bytes (K = KiB, M = MiB).
fn parse_size(s: &str) -> anyhow::Result<usize> {
    let t = s.trim();
    if t.is_empty() {
        bail!("empty size in --sizes");
    }
    let (digits, multiplier) = match t.chars().last() {
        Some('k') | Some('K') => (&t[..t.len() - 1], 1024usize),
        Some('m') | Some('M') => (&t[..t.len() - 1], 1024 * 1024),
        _ => (t, 1),
    };
    let value: usize = digits
        .parse()
        .with_context(|| format!("invalid size {t:?} (use e.g. 256K, 1M, or bytes)"))?;
    value
        .checked_mul(multiplier)
        .with_context(|| format!("size {t:?} overflows"))
}

/// Formats a byte count as its most compact exact K/M form (else bytes).
fn size_label(bytes: u64) -> String {
    const MIB: u64 = 1024 * 1024;
    const KIB: u64 = 1024;
    if bytes >= MIB && bytes.is_multiple_of(MIB) {
        format!("{}M", bytes / MIB)
    } else if bytes >= KIB && bytes.is_multiple_of(KIB) {
        format!("{}K", bytes / KIB)
    } else {
        format!("{bytes}B")
    }
}

/// Human-readable byte quantity (binary units, two decimals).
fn human_bytes(bytes: f64) -> String {
    const UNITS: [&str; 5] = ["B", "KiB", "MiB", "GiB", "TiB"];
    let mut value = bytes;
    let mut unit = 0;
    while value >= 1024.0 && unit + 1 < UNITS.len() {
        value /= 1024.0;
        unit += 1;
    }
    if unit == 0 {
        format!("{value:.0} {}", UNITS[unit])
    } else {
        format!("{value:.2} {}", UNITS[unit])
    }
}

/// Renders the human-readable table for one report.
fn render_table(report: &BenchReport, recommended: Option<u64>) -> String {
    let mut out = String::new();
    let _ = writeln!(
        out,
        "bench-chunking: {} — {} files, {}",
        report.root,
        report.files_scanned,
        human_bytes(report.total_bytes as f64)
    );
    if let Some(baseline) = &report.baseline_root {
        let _ = writeln!(out, "baseline: {baseline}");
    }
    let _ = writeln!(
        out,
        "bookkeeping projected for N = {} retained snapshots",
        report.snapshots_projected
    );
    let _ = writeln!(out);

    let overlap_col = report.baseline_root.is_some();
    let mut header = format!(
        "{:>8} {:>10} {:>10} {:>7} {:>11} {:>11} {:>11} {:>11} {:>14} {:>14}",
        "target",
        "chunks",
        "unique",
        "dedup",
        "mean",
        "p50",
        "p95",
        "index",
        "manifest/snap",
        "bookkeeping"
    );
    if overlap_col {
        let _ = write!(header, " {:>9}", "overlap%");
    }
    let _ = writeln!(out, "{header}");

    for c in &report.candidates {
        let mut row = format!(
            "{:>8} {:>10} {:>10} {:>7.3} {:>11} {:>11} {:>11} {:>11} {:>14} {:>14}",
            size_label(c.target_size),
            c.total_chunks,
            c.unique_chunks,
            c.dedup_ratio,
            human_bytes(c.mean_chunk_size),
            human_bytes(c.median_chunk_size as f64),
            human_bytes(c.p95_chunk_size as f64),
            human_bytes(c.index_bytes as f64),
            human_bytes(c.manifest_bytes_per_snapshot as f64),
            human_bytes(c.projected_bookkeeping_bytes as f64),
        );
        if let Some(overlap) = &c.baseline {
            let _ = write!(row, " {:>9.2}", overlap.overlap_percent);
        }
        if recommended == Some(c.target_size) {
            row.push_str("  <== recommended");
        }
        let _ = writeln!(out, "{row}");
    }

    let _ = writeln!(out);
    if let Some(target) = recommended {
        let _ = writeln!(
            out,
            "recommended: {} (lowest unique_bytes + projected bookkeeping; \
             see --help for the heuristic — the choice stays with you)",
            size_label(target)
        );
    }
    let _ = writeln!(out, "note: {}", dedup_note(report));
    out
}

/// The honesty note about intra-snapshot vs cross-version dedup figures.
fn dedup_note(report: &BenchReport) -> &'static str {
    if report.baseline_root.is_some() {
        "overlap% measures real chunk overlap against the baseline tree — \
         the honest proxy for cross-snapshot dedup."
    } else {
        "no --baseline given: dedup figures are intra-snapshot only and \
         understate versioned savings."
    }
}

/// Validates candidate sizes into chunker configs (deduplicated, order kept).
fn candidate_configs(sizes: &[String]) -> anyhow::Result<Vec<ChunkerConfig>> {
    let mut seen = Vec::new();
    let mut configs = Vec::new();
    for raw in sizes {
        let target = parse_size(raw)?;
        if seen.contains(&target) {
            continue;
        }
        seen.push(target);
        let config = ChunkerConfig::with_target(target)
            .with_context(|| format!("candidate size {raw:?} is not usable"))?;
        configs.push(config);
    }
    if configs.is_empty() {
        bail!("--sizes produced no candidates");
    }
    Ok(configs)
}

/// Runs `bench-chunking` and prints the report to stdout.
pub fn run(args: &BenchArgs) -> anyhow::Result<()> {
    let configs = candidate_configs(&args.sizes)?;
    let snapshots = args
        .snapshots
        .unwrap_or_else(|| steady_state_snapshots(DEFAULT_PROJECTION_HORIZON_DAYS));

    if args.compression && configs.len() != 1 {
        bail!(
            "--compression requires --sizes to resolve to exactly one candidate \
             (got {}); pass a single size, e.g. --sizes 1M",
            configs.len()
        );
    }

    // The size-report input: either the fast (data-discarding) multi-
    // candidate fan-out `chunk_tree` uses everywhere else, or — only when
    // --compression needs the real chunk bytes anyway — a single combined
    // pass ([`chunk_tree_with_bytes`]) that serves both features from one
    // disk read (FR-C5a: enabling policy simulation must not add a second
    // read of the same tree).
    let (files, compression_source): (Vec<FileChunking>, Option<CompressionSource>) =
        if args.compression {
            let (full, io_time) = chunk_tree_with_bytes(&args.path, &configs[0])
                .with_context(|| format!("failed to benchmark {}", args.path.display()))?;
            let meta = full.iter().map(file_chunking_meta).collect();
            (meta, Some(CompressionSource { full, io_time }))
        } else {
            let files = chunk_tree(&args.path, &configs)
                .with_context(|| format!("failed to benchmark {}", args.path.display()))?;
            (files, None)
        };

    let baseline_files = match &args.baseline {
        Some(path) => Some(
            chunk_tree(path, &configs)
                .with_context(|| format!("failed to benchmark baseline {}", path.display()))?,
        ),
        None => None,
    };

    let root = args.path.display().to_string();
    let baseline_root = args.baseline.as_ref().map(|p| p.display().to_string());
    let baseline_arg = match (&baseline_root, &baseline_files) {
        (Some(label), Some(files)) => Some((label.as_str(), files.as_slice())),
        _ => None,
    };

    let report = build_report(&root, &files, &configs, snapshots, baseline_arg)?;
    let recommended = recommend(&report);

    let compression = compression_source.map(|source| {
        build_compression(
            &configs[0],
            args,
            &source.full,
            source.io_time,
            report.candidates[0].projected_bookkeeping_bytes,
            baseline_files.as_deref(),
        )
    });

    if args.json {
        let output = JsonOutput {
            report: &report,
            recommended_target_size: recommended,
            note: dedup_note(&report),
            compression_policies: compression.as_ref().map(|c| CompressionPoliciesJson {
                report: c.report.clone(),
                recommended_policy: c.recommended,
                file_classes: c.diagnostics.clone(),
            }),
        };
        println!("{}", serde_json::to_string_pretty(&output)?);
    } else {
        print!("{}", render_table(&report, recommended));
        if let Some(c) = &compression {
            print!("{}", render_compression_table(c));
        }
    }
    Ok(())
}

/// The `--compression` mode's raw retained input from the single combined
/// pass: full chunk bytes plus the measured I/O time.
struct CompressionSource {
    full: Vec<busyncr_core::policy_bench::FileChunkingFull>,
    io_time: std::time::Duration,
}

/// Converts a full (bytes-retaining) file chunking into the lightweight
/// [`FileChunking`]/[`ChunkMeta`] shape [`build_report`] expects, without
/// re-reading or re-chunking anything.
fn file_chunking_meta(f: &busyncr_core::policy_bench::FileChunkingFull) -> FileChunking {
    let metas: Vec<ChunkMeta> = f
        .chunks
        .iter()
        .map(|c| ChunkMeta {
            id: c.id,
            len: c.len() as u64,
        })
        .collect();
    FileChunking {
        rel_path: f.rel_path.clone(),
        file_bytes: metas.iter().map(|m| m.len).sum(),
        per_candidate: vec![metas],
    }
}

/// Everything needed to render/serialize one `--compression` run's output.
struct CompressionOutput {
    report: CompressionReport,
    recommended: Option<&'static str>,
    diagnostics: Vec<policy_bench::FileClassRow>,
}

/// Physical/available CPU parallelism, the `--threads` default (FR-C1
/// §4.4).
fn default_threads() -> u32 {
    std::thread::available_parallelism()
        .map(|n| n.get() as u32)
        .unwrap_or(1)
}

/// Builds the full compression-policy simulation from the single-pass
/// retained chunk bytes (FR-C1 §4, FR-C5).
fn build_compression(
    cfg: &ChunkerConfig,
    args: &BenchArgs,
    full: &[busyncr_core::policy_bench::FileChunkingFull],
    io_time: std::time::Duration,
    bookkeeping_bytes: u64,
    baseline_files: Option<&[FileChunking]>,
) -> CompressionOutput {
    let mut unique: HashMap<ChunkId, Vec<u8>> = HashMap::new();
    let mut class_chunks: Vec<(FileClass, Vec<u8>)> = Vec::new();
    let mut total_bytes = 0u64;
    // Concatenated in read order so the CDC/BLAKE3 microbenchmarks below
    // exercise the corpus's own bytes without a second disk read (they were
    // already read once, in this same pass, to produce `full`).
    let mut all_bytes: Vec<u8> = Vec::new();
    for f in full {
        let class = FileClass::classify(&f.rel_path);
        for c in &f.chunks {
            total_bytes += c.len() as u64;
            all_bytes.extend_from_slice(&c.data);
            if let std::collections::hash_map::Entry::Vacant(e) = unique.entry(c.id) {
                e.insert(c.data.clone());
                class_chunks.push((class, c.data.clone()));
            }
        }
    }
    let unique_chunks: Vec<Vec<u8>> = unique.values().cloned().collect();

    let delta_chunks: Option<Vec<Vec<u8>>> = baseline_files.map(|bf| {
        let baseline_ids: HashSet<ChunkId> = bf
            .iter()
            .flat_map(|f| f.per_candidate[0].iter().map(|m| m.id))
            .collect();
        unique
            .iter()
            .filter(|(id, _)| !baseline_ids.contains(id))
            .map(|(_, v)| v.clone())
            .collect()
    });

    let read_mbps = throughput_mbps(total_bytes, io_time);
    let cdc_mbps = policy_bench::measure_cdc_mbps(&all_bytes, cfg);
    let blake3_mbps = policy_bench::measure_blake3_mbps(&all_bytes);
    let encrypt_mbps = policy_bench::measure_encrypt_mbps(&mut rand::rng());
    let stage_rates = StageRates {
        read_mbps,
        cdc_mbps,
        blake3_mbps,
        encrypt_mbps,
    };
    let threads = args.threads.unwrap_or_else(default_threads);

    let inputs = BuildInputs {
        unique_chunks: &unique_chunks,
        delta_chunks: delta_chunks.as_deref(),
        assume_churn_percent: if delta_chunks.is_some() {
            None
        } else {
            args.assume_churn
        },
        total_bytes,
        stage_rates,
        threads,
        net_mbps: &args.net_mbps,
        bookkeeping_bytes,
    };
    let report = build_compression_report(&inputs);
    let recommended = recommend_policy(&report.policies);
    let diagnostics = recommended
        .and_then(PolicyKind::from_name)
        .map(|kind| file_class_diagnostics(&class_chunks, kind))
        .unwrap_or_default();

    CompressionOutput {
        report,
        recommended,
        diagnostics,
    }
}

/// Renders the `--compression` section (FR-C1 §4.2/§4.4/§4.5).
fn render_compression_table(c: &CompressionOutput) -> String {
    let mut out = String::new();
    let _ = writeln!(out);
    let _ = writeln!(out, "compression policy simulation (FR-C1 §4)");
    let rates = &c.report.stage_rates;
    let _ = writeln!(
        out,
        "measured rates: read {:.1} MB/s, cdc {:.1} MB/s, blake3 {:.1} MB/s, \
         encrypt {:.1} MB/s (synthetic); threads={}",
        rates.read_mbps, rates.cdc_mbps, rates.blake3_mbps, rates.encrypt_mbps, c.report.threads
    );
    let _ = writeln!(
        out,
        "{:>16} {:>9} {:>14} {:>14} {:>10}  initial-backup seconds @ net-mbps {:?}",
        "policy", "ratio", "stored", "steady-state", "cpu-s", c.report.net_mbps
    );
    for row in &c.report.policies {
        let mut line = format!(
            "{:>16} {:>9.3} {:>14} {:>14} {:>10.3} ",
            row.policy,
            row.stored.ratio,
            human_bytes(row.stored.stored_bytes as f64),
            human_bytes(row.projected_steady_state_bytes as f64),
            row.initial_backup.cpu_bound_seconds,
        );
        for point in &row.initial_backup.at_bandwidth {
            let _ = write!(line, " {:.2}s", point.seconds);
        }
        if Some(row.policy) == c.recommended {
            line.push_str("  <== recommended");
        }
        let _ = writeln!(out, "{line}");
        match &row.incremental {
            Some(inc) => {
                let assumed = match inc.source {
                    ChurnSource::Measured => String::new(),
                    ChurnSource::Assumed { percent } => format!(" (assumed {percent}% churn)"),
                };
                let _ = writeln!(
                    out,
                    "{:>16} incremental: {} new, {:.3}s cpu-bound{}",
                    "",
                    human_bytes(inc.delta.stored_bytes as f64),
                    inc.cpu_bound_seconds,
                    assumed
                );
            }
            None => {
                let _ = writeln!(
                    out,
                    "{:>16} incremental: n/a (run with --baseline or --assume-churn)",
                    ""
                );
            }
        }
    }
    if !c.diagnostics.is_empty() {
        let _ = writeln!(out, "file-class diagnostics (recommended policy):");
        for row in &c.diagnostics {
            let _ = writeln!(
                out,
                "  {:>12} in {:>10} out {:>10} ({:.1}% of savings)",
                row.class,
                human_bytes(row.bytes_in as f64),
                human_bytes(row.bytes_out as f64),
                row.share_of_savings_percent
            );
        }
    }
    out
}

/// Compile-time sanity: keep the doc'd default in sync with the grid math.
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_size_understands_suffixes() {
        assert_eq!(parse_size("256K").unwrap(), 256 * 1024);
        assert_eq!(parse_size("1m").unwrap(), 1024 * 1024);
        assert_eq!(parse_size("4096").unwrap(), 4096);
        assert!(parse_size("").is_err());
        assert!(parse_size("12Q").is_err());
    }

    #[test]
    fn size_label_roundtrips_common_sizes() {
        assert_eq!(size_label(256 * 1024), "256K");
        assert_eq!(size_label(4 * 1024 * 1024), "4M");
        assert_eq!(size_label(1000), "1000B");
    }

    #[test]
    fn candidate_configs_dedupes_and_validates() {
        let configs = candidate_configs(&["256K".into(), "256K".into(), "1M".into()]).unwrap();
        assert_eq!(configs.len(), 2);
        // 32 MiB target exceeds the FastCDC ceiling (see S1 note).
        assert!(candidate_configs(&["32M".into()]).is_err());
    }

    #[test]
    fn documented_default_snapshot_count_is_36() {
        assert_eq!(
            steady_state_snapshots(DEFAULT_PROJECTION_HORIZON_DAYS),
            36,
            "LONG_ABOUT documents N = 36; update it if the grid changes"
        );
    }
}
