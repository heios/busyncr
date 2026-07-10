//! The `bench-chunking` subcommand: offline chunk-size sizing tool
//! (PRD §3.7, FR10). CLI wiring and rendering only — the measurement engine
//! lives in `busyncr_core::bench`.

use std::fmt::Write as _;
use std::path::PathBuf;

use anyhow::{bail, Context};
use serde::Serialize;

use busyncr_core::bench::{
    build_report, chunk_tree, recommend, steady_state_snapshots, BenchReport,
    DEFAULT_PROJECTION_HORIZON_DAYS,
};
use busyncr_core::chunking::ChunkerConfig;

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
measure real cross-version chunk overlap.";

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

    let files = chunk_tree(&args.path, &configs)
        .with_context(|| format!("failed to benchmark {}", args.path.display()))?;

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

    if args.json {
        let output = JsonOutput {
            report: &report,
            recommended_target_size: recommended,
            note: dedup_note(&report),
        };
        println!("{}", serde_json::to_string_pretty(&output)?);
    } else {
        print!("{}", render_table(&report, recommended));
    }
    Ok(())
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
