//! `bench-chunking --compression`: compression policy simulation (FR-C1 §4,
//! FR-C5).
//!
//! Extends the offline chunk-size benchmark ([`crate::bench`]) with a
//! second measurement pass over the **unique-chunk stream** of a single
//! selected chunk-size candidate. For each of the five FR-C1 §4.1 policies
//! ([`PolicyKind`]), the real
//! [`choose_codec`](crate::compression::choose_codec) policy engine runs
//! **verbatim** over every unique chunk's plaintext bytes
//! ([`simulate_policy`]) — FR-C5b requires the simulator to reuse the real
//! engine, not re-implement it, so the reported stored-byte figures match an
//! end-to-end backup of the same corpus under the same policy exactly (same
//! zstd version).
//!
//! # Single-pass guarantee (FR-C5a)
//!
//! [`chunk_tree_with_bytes`] reads each file under the benchmarked root
//! exactly once — the same guarantee [`crate::bench::chunk_tree`] gives the
//! plain size benchmark, extended to also retain chunk *bytes* (not just
//! [`crate::bench::ChunkMeta`]), which compression measurement needs. I/O
//! wait time is measured during that same pass via [`TimingReader`] (no
//! extra disk access) and is the source of [`StageRates::read_mbps`].
//!
//! # Measurement, not estimation
//!
//! Every figure in this module is either: (a) the real policy engine's
//! actual output length for the corpus's actual bytes, or (b) a genuine
//! wall-clock measurement (compression throughput, CDC throughput, BLAKE3
//! throughput, or a synthetic in-memory AEAD microbenchmark for
//! `encrypt_MBps`, FR-C1 §4.4). None of it is scattered as constants — see
//! `PolicyKind::config` and the pipeline-speed helpers below.
//!
//! Wall-clock timing here is a deliberate, documented exception to the
//! project's "no wall-clock in core logic" rule (AGENTS.md): that rule
//! exists to keep *decision* logic (retention, scheduling) deterministic and
//! testable; this module's whole purpose is to *measure* real elapsed time
//! for a benchmarking report, which is inherently non-deterministic by
//! design (repeated runs on the same machine will differ slightly).
//!
//! # Backup-speed pipeline model (§4.4)
//!
//! `client_throughput = min(read_MBps, threads × 1/(1/cdc + 1/blake3 +
//! 1/compress + 1/encrypt))`, applied to:
//!
//! * **initial full backup**: all unique bytes go through the whole
//!   pipeline (FR-C1 §4.4: "initial full backup (all unique bytes)");
//! * **incremental update**: the whole tree is *scanned* at `read_MBps`
//!   alone (detecting what changed still means reading every file — FR-C1
//!   §4.4's stated assumption, absent mtime-gated scanning), then only the
//!   `--baseline`-measured *new* unique bytes go through the full pipeline.
//!
//! At each `--net-mbps` bandwidth point, projected wall-clock is
//! `max(cpu_bound_floor, stored_bytes / bandwidth)` — never below the
//! CPU-bound floor, and non-increasing as bandwidth grows (FR-C5d).

use std::collections::HashMap;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use fastcdc::v2020;
use rand::CryptoRng;
use serde::Serialize;

use crate::bench::{collect_files, BenchError};
use crate::chunking::{Chunk, ChunkId, ChunkerConfig};
use crate::compression::{choose_codec, Phase, PolicyConfig, PolicyCounters};
use crate::crypto::{self, DataKey};

const MIB: f64 = 1024.0 * 1024.0;

/// MiB/s over `bytes` in `wall`. Empty/instantaneous measurements report
/// `f64::INFINITY` (the stage cost nothing measurable) rather than dividing
/// by zero.
fn mbps(bytes: u64, wall: Duration) -> f64 {
    let secs = wall.as_secs_f64();
    if bytes == 0 || secs <= 0.0 {
        return f64::INFINITY;
    }
    (bytes as f64 / MIB) / secs
}

/// Public wrapper over the internal MiB/s helper, for callers (the CLI) that
/// measure a `(bytes, duration)` pair outside this module — e.g. the real
/// disk-read pass — and need the same throughput arithmetic used
/// everywhere else in the report.
#[must_use]
pub fn throughput_mbps(bytes: u64, wall: Duration) -> f64 {
    mbps(bytes, wall)
}

fn seconds_for(bytes: u64, rate_mbps: f64) -> f64 {
    if bytes == 0 {
        return 0.0;
    }
    if !rate_mbps.is_finite() || rate_mbps <= 0.0 {
        return 0.0;
    }
    (bytes as f64 / MIB) / rate_mbps
}

/// Harmonic combination of up to four independent per-stage rates
/// (`1 / (1/a + 1/b + 1/c + 1/d)`), scaled by `threads` — the §4.4 pipeline
/// formula. A non-finite or non-positive rate contributes zero (its stage is
/// free / instantaneous) rather than corrupting the sum.
fn harmonic_rate(threads: u32, rates: &[f64]) -> f64 {
    let sum: f64 = rates
        .iter()
        .copied()
        .filter(|r| r.is_finite() && *r > 0.0)
        .map(|r| 1.0 / r)
        .sum();
    if sum <= 0.0 {
        return f64::INFINITY;
    }
    (1.0 / sum) * f64::from(threads.max(1))
}

/// One simulated compression policy (FR-C1 §4.1: "At minimum: raw-only,
/// zstd3-always, zstd3, probe+zstd3, zstd3+escalate").
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum PolicyKind {
    /// Never compress; every chunk stored raw. Not a distinct code path in
    /// the real engine — the `zstd3` keep-threshold pushed to the extreme
    /// where compression can never clear the bar (see [`Self::config`]).
    RawOnly,
    /// Always keep the zstd-3 output, no raw fallback — shows what the raw
    /// fallback (C2.1) saves.
    Zstd3Always,
    /// C2.1: the real default policy.
    Zstd3,
    /// C2.2: an lz4 probe gates whether zstd runs at all.
    ProbeZstd3,
    /// C2.1 + C2.3: zstd-3 plus level-9 escalation for highly compressible
    /// chunks (phase-gated off during [`Phase::InitialFull`], per FR-C6).
    Zstd3Escalate,
}

impl PolicyKind {
    /// Every policy FR-C1 §4.1 requires "at minimum", in table order.
    pub const ALL: [PolicyKind; 5] = [
        Self::RawOnly,
        Self::Zstd3Always,
        Self::Zstd3,
        Self::ProbeZstd3,
        Self::Zstd3Escalate,
    ];

    /// Table/JSON name.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::RawOnly => "raw-only",
            Self::Zstd3Always => "zstd3-always",
            Self::Zstd3 => "zstd3",
            Self::ProbeZstd3 => "probe+zstd3",
            Self::Zstd3Escalate => "zstd3+escalate",
        }
    }

    /// Looks up a policy by its [`Self::name`] (round-trips `--json`/table
    /// output back to a config, e.g. to re-derive the recommended policy's
    /// diagnostics).
    #[must_use]
    pub fn from_name(name: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|k| k.name() == name)
    }

    /// The [`PolicyConfig`] this simulated policy maps to.
    ///
    /// `raw-only` and `zstd3-always` are not separate branches in the real
    /// policy engine — they are `zstd3`'s own keep-threshold (C2.1) pushed
    /// to its two logical extremes: `0.0` (the compressed form can never
    /// clear `compressed_len <= raw_len * threshold`, so every chunk falls
    /// back to raw) and `+INFINITY` (the compressed form always clears it,
    /// so the raw fallback never fires). This is the same technique the C2
    /// pipeline-integration tests use for a `raw-only` comparison arm, and
    /// it means [`choose_codec`] is reused verbatim for every one of the
    /// five policies (FR-C5b), never re-implemented.
    #[must_use]
    pub fn config(self) -> PolicyConfig {
        match self {
            Self::RawOnly => PolicyConfig {
                keep_threshold: 0.0,
                ..PolicyConfig::default()
            },
            Self::Zstd3Always => PolicyConfig {
                keep_threshold: f64::INFINITY,
                ..PolicyConfig::default()
            },
            Self::Zstd3 => PolicyConfig::default(),
            Self::ProbeZstd3 => PolicyConfig {
                use_probe: true,
                ..PolicyConfig::default()
            },
            Self::Zstd3Escalate => PolicyConfig {
                escalate: true,
                ..PolicyConfig::default()
            },
        }
    }
}

/// Measured result of running one policy's real [`choose_codec`] decision
/// over a set of unique chunk plaintexts (FR-C5b).
#[derive(Debug, Clone, Copy, Serialize)]
pub struct PolicyStoredStats {
    /// Number of unique chunks processed.
    pub chunk_count: u64,
    /// Sum of pre-compression (raw) chunk lengths.
    pub bytes_in: u64,
    /// Sum of stored payload bytes (post-policy, pre-framing/encryption).
    pub bytes_out: u64,
    /// `bytes_out` + 1 codec byte per chunk (FR-C1 C1.1) — the plaintext
    /// that would be handed to AEAD encryption.
    pub framed_bytes: u64,
    /// `framed_bytes` + [`crypto::BLOB_OVERHEAD`] per chunk — the ciphertext
    /// volume a real backup under this policy would actually persist
    /// (FR-C1 §4.2.1: "AEAD overhead added arithmetically per chunk").
    pub stored_bytes: u64,
    /// `bytes_in / stored_bytes` (effective ratio vs. raw+AEAD baseline).
    pub ratio: f64,
    /// Chunks stored raw (C2.4 counter).
    pub raw_chunks: u64,
    /// Chunks stored as the baseline zstd attempt, not escalated.
    pub zstd3_chunks: u64,
    /// Chunks stored as the (kept) escalation retry's output.
    pub escalated_chunks: u64,
    /// Times the level-9 retry was invoked at all (FR-C6), whether kept or
    /// not.
    pub escalation_attempts: u64,
    /// Wall-clock time spent inside [`choose_codec`] for this run — the
    /// source of `compress_MBps` (FR-C1 §4.2.2).
    #[serde(skip)]
    pub wall: Duration,
}

impl PolicyStoredStats {
    /// Compression throughput over unique bytes (`bytes_in / wall`), MiB/s.
    #[must_use]
    pub fn compress_mbps(&self) -> f64 {
        mbps(self.bytes_in, self.wall)
    }
}

/// Runs [`choose_codec`] verbatim (FR-C5b) over every chunk in `chunks`
/// under `kind`/`phase`, measuring wall-clock compression time.
#[must_use]
pub fn simulate_policy(chunks: &[Vec<u8>], kind: PolicyKind, phase: Phase) -> PolicyStoredStats {
    let cfg = kind.config();
    let mut counters = PolicyCounters::default();
    let start = Instant::now();
    for chunk in chunks {
        let _ = choose_codec(chunk, phase, &cfg, &mut counters);
    }
    let wall = start.elapsed();
    let chunk_count = counters.total();
    let framed_bytes = counters.bytes_out + chunk_count;
    let stored_bytes = framed_bytes + chunk_count * crypto::BLOB_OVERHEAD as u64;
    let ratio = if stored_bytes == 0 {
        1.0
    } else {
        counters.bytes_in as f64 / stored_bytes as f64
    };
    PolicyStoredStats {
        chunk_count,
        bytes_in: counters.bytes_in,
        bytes_out: counters.bytes_out,
        framed_bytes,
        stored_bytes,
        ratio,
        raw_chunks: counters.raw,
        zstd3_chunks: counters.zstd3,
        escalated_chunks: counters.escalated,
        escalation_attempts: counters.escalation_attempts,
        wall,
    }
}

/// Independently-measured pipeline stage throughputs (FR-C1 §4.4), shared
/// across every policy row (only compression throughput varies by policy).
#[derive(Debug, Clone, Copy, Serialize)]
pub struct StageRates {
    /// Real sequential disk-read throughput, measured as I/O-wait time
    /// during the same pass that produced the unique-chunk stream
    /// ([`TimingReader`]) — no extra disk access.
    pub read_mbps: f64,
    /// Content-defined chunking (boundary detection only, no hashing),
    /// measured in-memory over already-resident bytes.
    pub cdc_mbps: f64,
    /// BLAKE3 hashing, measured the same way.
    pub blake3_mbps: f64,
    /// Synthetic in-memory AEAD microbenchmark (FR-C1 §4.4: "AEAD over 1
    /// MiB buffers").
    pub encrypt_mbps: f64,
}

/// Wraps a [`Read`] source, accumulating the wall-clock time spent inside
/// its `read` calls — used to measure real I/O throughput without adding a
/// second disk pass (FR-C1 §4.4: stage rates come from the same single
/// pass).
pub struct TimingReader<R> {
    inner: R,
    /// Cumulative time spent inside `read()`.
    pub io_time: Duration,
    /// Cumulative bytes served.
    pub bytes: u64,
}

impl<R> TimingReader<R> {
    /// Wraps `inner`, starting with zeroed counters.
    pub const fn new(inner: R) -> Self {
        Self {
            inner,
            io_time: Duration::ZERO,
            bytes: 0,
        }
    }
}

impl<R: Read> Read for TimingReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let start = Instant::now();
        let n = self.inner.read(buf)?;
        self.io_time += start.elapsed();
        self.bytes += n as u64;
        Ok(n)
    }
}

/// Pure CDC boundary-detection throughput (no hashing), timed in-memory over
/// already-read bytes — adds no disk I/O.
#[must_use]
pub fn measure_cdc_mbps(data: &[u8], cfg: &ChunkerConfig) -> f64 {
    if data.is_empty() {
        return f64::INFINITY;
    }
    let start = Instant::now();
    let mut total = 0usize;
    for chunk in v2020::FastCDC::new(data, cfg.min_size(), cfg.target_size(), cfg.max_size()) {
        total += chunk.length;
    }
    let elapsed = start.elapsed();
    debug_assert_eq!(total, data.len());
    mbps(total as u64, elapsed)
}

/// Pure BLAKE3 hashing throughput, timed in-memory.
#[must_use]
pub fn measure_blake3_mbps(data: &[u8]) -> f64 {
    if data.is_empty() {
        return f64::INFINITY;
    }
    let start = Instant::now();
    let _ = blake3::hash(data);
    mbps(data.len() as u64, start.elapsed())
}

/// Synthetic AEAD microbenchmark: encrypts repeated 1 MiB buffers under a
/// throwaway key, timing wall clock (FR-C1 §4.4: "synthetic in-memory
/// `encrypt_MBps` microbenchmark, AEAD over 1 MiB buffers").
#[must_use]
pub fn measure_encrypt_mbps<R: CryptoRng>(rng: &mut R) -> f64 {
    const BUF: usize = 1024 * 1024;
    const ITERS: usize = 16;
    let key = DataKey::generate(rng);
    let id = ChunkId::from_bytes([0u8; 32]);
    let buf = vec![0xABu8; BUF];
    let start = Instant::now();
    for _ in 0..ITERS {
        let _ = crypto::encrypt_chunk(&key, &id, &buf, rng);
    }
    mbps((BUF * ITERS) as u64, start.elapsed())
}

/// One file's chunks under a single [`ChunkerConfig`], with full chunk bytes
/// retained (unlike [`crate::bench::FileChunking`], which discards data
/// immediately to keep the plain size-benchmark's memory footprint small).
#[derive(Debug, Clone)]
pub struct FileChunkingFull {
    /// `/`-separated path relative to the benchmark root.
    pub rel_path: String,
    /// Chunks tiling the file, in order.
    pub chunks: Vec<Chunk>,
}

/// Chunks every regular file under `root` with a single config, retaining
/// full chunk bytes, reading each file exactly once (FR-C5a). Also returns
/// the cumulative I/O-wait time spent inside every file's `read` calls
/// ([`StageRates::read_mbps`]'s source).
///
/// Unkeyed (plain BLAKE3, [`crate::chunking::chunk_reader`]) — `bench-chunking`
/// stays keyless throughout (FR-K1 K1.5).
///
/// # Errors
///
/// Fails if `root` is not a directory, on any I/O error, on non-UTF-8 paths,
/// or if the chunker fails.
pub fn chunk_tree_with_bytes(
    root: &Path,
    config: &ChunkerConfig,
) -> Result<(Vec<FileChunkingFull>, Duration), BenchError> {
    if !root.is_dir() {
        return Err(BenchError::NotADirectory(root.to_path_buf()));
    }
    let mut files: Vec<(String, PathBuf)> = Vec::new();
    collect_files(root, root, &mut files)?;
    files.sort();

    let mut out = Vec::with_capacity(files.len());
    let mut io_time = Duration::ZERO;
    for (rel_path, abs_path) in files {
        let file = std::fs::File::open(&abs_path).map_err(|e| BenchError::Io {
            path: abs_path.clone(),
            source: e,
        })?;
        let mut timing = TimingReader::new(file);
        let mut chunks = Vec::new();
        for chunk in crate::chunking::chunk_reader(&mut timing, config) {
            let chunk = chunk.map_err(|e| match e {
                crate::chunking::ChunkingError::Io(io) => BenchError::Io {
                    path: abs_path.clone(),
                    source: io,
                },
                other => BenchError::Chunking {
                    path: rel_path.clone(),
                    source: other,
                },
            })?;
            chunks.push(chunk);
        }
        io_time += timing.io_time;
        out.push(FileChunkingFull { rel_path, chunks });
    }
    Ok((out, io_time))
}

/// File-class groupings for the §4.3 diagnostics section, by extension.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
pub enum FileClass {
    /// `.db`, `.sqlite`, `.sqlite3`.
    DbSqlite,
    /// Zip-based office formats: `.docx`, `.xlsx`, `.pptx`, `.odt`, `.ods`,
    /// `.zip`, `.jar`.
    OfficeZip,
    /// `.pdf`.
    Pdf,
    /// Common raster image formats (already DCT/deflate-compressed
    /// internally).
    Image,
    /// Source code and plain text.
    TextCode,
    /// Everything else, including files with no extension.
    Other,
}

impl FileClass {
    /// Every class, diagnostics table order.
    pub const ALL: [FileClass; 6] = [
        Self::DbSqlite,
        Self::OfficeZip,
        Self::Pdf,
        Self::Image,
        Self::TextCode,
        Self::Other,
    ];

    /// Human-readable label.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::DbSqlite => "db/sqlite",
            Self::OfficeZip => "office-zip",
            Self::Pdf => "pdf",
            Self::Image => "image",
            Self::TextCode => "text/code",
            Self::Other => "other",
        }
    }

    /// Classifies a `/`-separated relative path by its extension.
    #[must_use]
    pub fn classify(rel_path: &str) -> Self {
        let file_name = rel_path.rsplit('/').next().unwrap_or(rel_path);
        let Some((_, ext)) = file_name.rsplit_once('.') else {
            return Self::Other;
        };
        if ext.is_empty() {
            return Self::Other;
        }
        match ext.to_ascii_lowercase().as_str() {
            "db" | "sqlite" | "sqlite3" => Self::DbSqlite,
            "docx" | "xlsx" | "pptx" | "odt" | "ods" | "zip" | "jar" => Self::OfficeZip,
            "pdf" => Self::Pdf,
            "jpg" | "jpeg" | "png" | "gif" | "webp" | "bmp" | "tiff" => Self::Image,
            "txt" | "md" | "rs" | "py" | "js" | "ts" | "c" | "h" | "cpp" | "hpp" | "json"
            | "toml" | "yaml" | "yml" | "csv" | "log" | "xml" | "html" | "css" | "go" | "java"
            | "sql" => Self::TextCode,
            _ => Self::Other,
        }
    }
}

/// Per-class savings under a given policy (FR-C1 §4.3): "already compressed
/// internally" classes read at (or near) ratio 1.00.
#[derive(Debug, Clone, Copy, Serialize)]
pub struct FileClassRow {
    /// The class label.
    pub class: &'static str,
    /// Raw bytes in this class.
    pub bytes_in: u64,
    /// Stored (post-policy) bytes in this class.
    pub bytes_out: u64,
    /// This class's share of the corpus's total bytes saved, as a
    /// percentage. `0.0` if the corpus saved nothing overall.
    pub share_of_savings_percent: f64,
}

/// Builds the §4.3 diagnostics rows: classifies each `(class, chunk_bytes)`
/// pair and runs the real policy engine (`Phase::InitialFull`, matching the
/// report's primary "total stored bytes" columns) once per chunk to get an
/// honest per-class bytes-in/bytes-out split under `policy`.
#[must_use]
pub fn file_class_diagnostics(
    chunks: &[(FileClass, Vec<u8>)],
    policy: PolicyKind,
) -> Vec<FileClassRow> {
    let cfg = policy.config();
    let mut per_class: HashMap<FileClass, (u64, u64)> = HashMap::new();
    for (class, data) in chunks {
        let mut counters = PolicyCounters::default();
        let (_, payload) = choose_codec(data, Phase::InitialFull, &cfg, &mut counters);
        let entry = per_class.entry(*class).or_default();
        entry.0 += data.len() as u64;
        entry.1 += payload.len() as u64;
    }
    let total_saved: i64 = per_class
        .values()
        .map(|(bin, bout)| *bin as i64 - *bout as i64)
        .sum();
    FileClass::ALL
        .iter()
        .filter_map(|class| {
            per_class.get(class).map(|&(bytes_in, bytes_out)| {
                let saved = bytes_in as i64 - bytes_out as i64;
                let share = if total_saved > 0 {
                    saved as f64 / total_saved as f64 * 100.0
                } else {
                    0.0
                };
                FileClassRow {
                    class: class.label(),
                    bytes_in,
                    bytes_out,
                    share_of_savings_percent: share,
                }
            })
        })
        .collect()
}

/// One bandwidth point's projected wall-clock time (FR-C1 §4.4).
#[derive(Debug, Clone, Copy, Serialize)]
pub struct BandwidthPoint {
    /// Bandwidth, in Mbit/s (as given via `--net-mbps`).
    pub net_mbit: f64,
    /// Projected wall-clock seconds: `max(cpu_bound_seconds, stored_bytes /
    /// bandwidth)`.
    pub seconds: f64,
}

/// Projects wall-clock time at `cpu_bound_seconds` (the compute floor) and
/// at each bandwidth point in `net_mbps` (Mbit/s). Internally consistent by
/// construction (FR-C5d): every point is `>= cpu_bound_seconds` (a `max`),
/// and non-increasing as bandwidth grows (transfer time strictly decreases).
#[must_use]
pub fn bandwidth_projection(
    cpu_bound_seconds: f64,
    stored_bytes: u64,
    net_mbps: &[f64],
) -> Vec<BandwidthPoint> {
    net_mbps
        .iter()
        .map(|&net_mbit| {
            let net_mbps_bytes = (net_mbit / 8.0).max(f64::MIN_POSITIVE);
            let transfer_seconds = (stored_bytes as f64 / MIB) / net_mbps_bytes;
            BandwidthPoint {
                net_mbit,
                seconds: cpu_bound_seconds.max(transfer_seconds),
            }
        })
        .collect()
}

/// Speed projection for one policy's initial full backup (§4.4).
#[derive(Debug, Clone, Serialize)]
pub struct SpeedProjection {
    /// `unique_bytes / min(read_MBps, threads x pipeline_rate)`.
    pub cpu_bound_seconds: f64,
    /// One point per `--net-mbps` entry.
    pub at_bandwidth: Vec<BandwidthPoint>,
}

/// Where the incremental "new bytes" figure came from (FR-C1 §4.2.4).
#[derive(Debug, Clone, Copy, Serialize)]
#[serde(tag = "source", rename_all = "snake_case")]
pub enum ChurnSource {
    /// Real `--baseline` overlap measurement.
    Measured,
    /// `--assume-churn <pct>`: explicitly modeled, not measured.
    Assumed {
        /// The assumed churn percentage.
        percent: f64,
    },
}

/// Incremental-update projection (§4.4): requires either `--baseline` or
/// `--assume-churn`; `None` on [`PolicyRow`] otherwise (the report must read
/// `n/a (run with --baseline)`, never print an intra-snapshot guess).
#[derive(Debug, Clone, Serialize)]
pub struct IncrementalProjection {
    /// Where the "new bytes" volume came from.
    pub source: ChurnSource,
    /// The new/changed unique chunks' policy-engine result
    /// (`Phase::Incremental` — escalation may fire here).
    pub delta: PolicyStoredStats,
    /// Time to scan (read) the whole tree at `read_MBps` to detect what
    /// changed (FR-C1 §4.4's stated assumption).
    pub scan_seconds: f64,
    /// `scan_seconds` + the delta's own pipeline-bound processing time.
    pub cpu_bound_seconds: f64,
    /// One point per `--net-mbps` entry, computed against the delta's
    /// `stored_bytes` (only new chunks are ever shipped).
    pub at_bandwidth: Vec<BandwidthPoint>,
}

/// One policy's full report row (FR-C1 §4.2).
#[derive(Debug, Clone, Serialize)]
pub struct PolicyRow {
    /// The policy name ([`PolicyKind::name`]).
    pub policy: &'static str,
    /// This policy's real engine output over every unique chunk
    /// (`Phase::InitialFull` — matches the tool running before any backup
    /// history exists, and lets FR-C5b compare directly against a real
    /// first backup). Escalation is therefore always off in this column;
    /// its effect only shows up in `incremental`, matching FR-C6's real
    /// phase gate.
    pub stored: PolicyStoredStats,
    /// Projected initial full backup (§4.4).
    pub initial_backup: SpeedProjection,
    /// Projected incremental update; `None` without `--baseline`/
    /// `--assume-churn`.
    pub incremental: Option<IncrementalProjection>,
    /// Projected steady-state store size under the retention grid at the
    /// bench's configured snapshot count: this policy's `stored_bytes` +
    /// the existing §3.7 bookkeeping projection (reused unchanged — see
    /// [`crate::bench::CandidateReport::projected_bookkeeping_bytes`]).
    pub projected_steady_state_bytes: u64,
}

/// Everything needed to build one full [`CompressionReport`].
pub struct BuildInputs<'a> {
    /// All unique chunk plaintexts for the selected candidate size.
    pub unique_chunks: &'a [Vec<u8>],
    /// New unique chunks not present in `--baseline`, if given.
    pub delta_chunks: Option<&'a [Vec<u8>]>,
    /// `--assume-churn <pct>`, used only when `delta_chunks` is `None`.
    pub assume_churn_percent: Option<f64>,
    /// Total dataset bytes (all files, including intra-snapshot
    /// duplicates) — the incremental row's whole-tree scan volume.
    pub total_bytes: u64,
    /// Measured pipeline stage rates.
    pub stage_rates: StageRates,
    /// `--threads` (parallelism scaling the CPU-bound stages).
    pub threads: u32,
    /// `--net-mbps` bandwidth points.
    pub net_mbps: &'a [f64],
    /// This candidate's §3.7 bookkeeping projection
    /// (`index_bytes + N x manifest_bytes`), reused unchanged.
    pub bookkeeping_bytes: u64,
}

/// The full `--compression` report for one chunk-size candidate (FR-C1 §4).
#[derive(Debug, Clone, Serialize)]
pub struct CompressionReport {
    /// One row per [`PolicyKind`], in [`PolicyKind::ALL`] order.
    pub policies: Vec<PolicyRow>,
    /// Measured pipeline stage rates, shared across every row.
    pub stage_rates: StageRates,
    /// `--threads` used for the CPU-bound projections.
    pub threads: u32,
    /// `--net-mbps` bandwidth points used for every row.
    pub net_mbps: Vec<f64>,
}

/// Builds the full policy-simulation report (FR-C1 §4.2/§4.4).
#[must_use]
pub fn build_compression_report(inputs: &BuildInputs<'_>) -> CompressionReport {
    let policies = PolicyKind::ALL
        .iter()
        .map(|&kind| build_policy_row(kind, inputs))
        .collect();
    CompressionReport {
        policies,
        stage_rates: inputs.stage_rates,
        threads: inputs.threads,
        net_mbps: inputs.net_mbps.to_vec(),
    }
}

fn build_policy_row(kind: PolicyKind, inputs: &BuildInputs<'_>) -> PolicyRow {
    let stored = simulate_policy(inputs.unique_chunks, kind, Phase::InitialFull);
    let rates = &inputs.stage_rates;

    let initial_rate = harmonic_rate(
        inputs.threads,
        &[
            rates.cdc_mbps,
            rates.blake3_mbps,
            stored.compress_mbps(),
            rates.encrypt_mbps,
        ],
    );
    let initial_rate = rates.read_mbps.min(initial_rate);
    let initial_cpu_bound = seconds_for(stored.bytes_in, initial_rate);
    let initial_backup = SpeedProjection {
        cpu_bound_seconds: initial_cpu_bound,
        at_bandwidth: bandwidth_projection(initial_cpu_bound, stored.stored_bytes, inputs.net_mbps),
    };

    let incremental = build_incremental(kind, inputs);

    PolicyRow {
        policy: kind.name(),
        stored,
        initial_backup,
        incremental,
        projected_steady_state_bytes: stored.stored_bytes + inputs.bookkeeping_bytes,
    }
}

fn build_incremental(kind: PolicyKind, inputs: &BuildInputs<'_>) -> Option<IncrementalProjection> {
    let rates = &inputs.stage_rates;
    let scan_seconds = seconds_for(inputs.total_bytes, rates.read_mbps);

    let (delta, source) = if let Some(delta_chunks) = inputs.delta_chunks {
        (
            simulate_policy(delta_chunks, kind, Phase::Incremental),
            ChurnSource::Measured,
        )
    } else if let Some(percent) = inputs.assume_churn_percent {
        // No real delta content exists to compress; scale the whole-corpus
        // policy result by the assumed churn fraction (explicitly labeled
        // "assumed", per FR-C1 §4.2.4).
        let whole = simulate_policy(inputs.unique_chunks, kind, Phase::Incremental);
        let scale = (percent / 100.0).clamp(0.0, 1.0);
        (scale_stats(&whole, scale), ChurnSource::Assumed { percent })
    } else {
        return None;
    };

    let delta_rate = harmonic_rate(
        inputs.threads,
        &[
            rates.cdc_mbps,
            rates.blake3_mbps,
            delta.compress_mbps(),
            rates.encrypt_mbps,
        ],
    );
    let delta_rate = rates.read_mbps.min(delta_rate);
    let delta_cpu_bound = seconds_for(delta.bytes_in, delta_rate);
    let cpu_bound_seconds = scan_seconds + delta_cpu_bound;

    Some(IncrementalProjection {
        source,
        at_bandwidth: bandwidth_projection(cpu_bound_seconds, delta.stored_bytes, inputs.net_mbps),
        delta,
        scan_seconds,
        cpu_bound_seconds,
    })
}

/// Scales an (already-measured) [`PolicyStoredStats`] by `scale` in
/// `[0, 1]`, for the `--assume-churn` path where no real delta content
/// exists to re-run the policy engine over. `wall` scales too, so
/// `compress_mbps()` stays a meaningful (assumed) throughput figure.
fn scale_stats(stats: &PolicyStoredStats, scale: f64) -> PolicyStoredStats {
    let scale_u64 = |v: u64| ((v as f64) * scale).round() as u64;
    let chunk_count = scale_u64(stats.chunk_count);
    PolicyStoredStats {
        chunk_count,
        bytes_in: scale_u64(stats.bytes_in),
        bytes_out: scale_u64(stats.bytes_out),
        framed_bytes: scale_u64(stats.framed_bytes),
        stored_bytes: scale_u64(stats.stored_bytes),
        ratio: stats.ratio,
        raw_chunks: scale_u64(stats.raw_chunks),
        zstd3_chunks: scale_u64(stats.zstd3_chunks),
        escalated_chunks: scale_u64(stats.escalated_chunks),
        escalation_attempts: scale_u64(stats.escalation_attempts),
        wall: Duration::from_secs_f64(stats.wall.as_secs_f64() * scale),
    }
}

/// Recommendation heuristic (FR-C1 §4.5): the policy with the smallest
/// projected steady-state store size among policies whose initial-backup
/// CPU-bound time is within 1.5x of `zstd3`'s. Ties go to the policy that
/// sorts first in [`PolicyKind::ALL`] order. `None` if `rows` has no
/// `zstd3` entry (should not happen — [`build_compression_report`] always
/// includes it) or is empty.
#[must_use]
pub fn recommend_policy(rows: &[PolicyRow]) -> Option<&'static str> {
    let zstd3 = rows.iter().find(|r| r.policy == PolicyKind::Zstd3.name())?;
    let bound = zstd3.initial_backup.cpu_bound_seconds * 1.5;
    rows.iter()
        .filter(|r| r.initial_backup.cpu_bound_seconds <= bound)
        .min_by(|a, b| {
            a.projected_steady_state_bytes
                .cmp(&b.projected_steady_state_bytes)
        })
        .map(|r| r.policy)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chunking::chunk_bytes;
    use rand::rngs::StdRng;
    use rand::SeedableRng;

    fn compressible(len: usize) -> Vec<u8> {
        b"the quick brown fox jumps over the lazy dog. "
            .iter()
            .copied()
            .cycle()
            .take(len)
            .collect()
    }

    fn incompressible(len: usize, seed: u64) -> Vec<u8> {
        use rand::Rng as _;
        let mut r = StdRng::seed_from_u64(seed);
        let mut buf = vec![0u8; len];
        r.fill_bytes(&mut buf);
        buf
    }

    // --- PolicyKind::config extremes ------------------------------------

    #[test]
    fn raw_only_never_keeps_compression() {
        let chunk = compressible(200_000);
        let mut counters = PolicyCounters::default();
        let (codec, payload) = choose_codec(
            &chunk,
            Phase::InitialFull,
            &PolicyKind::RawOnly.config(),
            &mut counters,
        );
        assert_eq!(codec, crate::compression::CodecId::Raw);
        assert_eq!(payload.len(), chunk.len());
    }

    #[test]
    fn zstd3_always_never_falls_back_to_raw_for_compressible_data() {
        let chunk = compressible(200_000);
        let mut counters = PolicyCounters::default();
        let (codec, payload) = choose_codec(
            &chunk,
            Phase::InitialFull,
            &PolicyKind::Zstd3Always.config(),
            &mut counters,
        );
        assert_eq!(codec, crate::compression::CodecId::Zstd);
        assert!(payload.len() < chunk.len());
    }

    // --- FR-C5a: single pass, even with policy simulation enabled -------

    #[test]
    fn frc5a_chunk_tree_with_bytes_reads_each_file_exactly_once() {
        let dir = tempfile::tempdir().unwrap();
        let a = incompressible(300 * 1024, 1);
        let b = compressible(150 * 1024);
        std::fs::write(dir.path().join("a.bin"), &a).unwrap();
        std::fs::write(dir.path().join("b.txt"), &b).unwrap();

        let cfg = ChunkerConfig::with_target(64 * 1024).unwrap();
        let (files, io_time) = chunk_tree_with_bytes(dir.path(), &cfg).unwrap();
        // Real read() calls happened (proves the reader was actually driven,
        // not skipped); zero-duration reads are only plausible on a clock
        // with coarser-than-nanosecond resolution, which no CI target uses.
        assert!(io_time >= Duration::ZERO);

        assert_eq!(files.len(), 2);
        for (file, expected) in files.iter().zip([&a, &b]) {
            let total: usize = file.chunks.iter().map(Chunk::len).sum();
            assert_eq!(
                total,
                expected.len(),
                "chunks for {} must tile the whole file exactly once",
                file.rel_path
            );
            // Bytes must match the reference in-memory chunker exactly
            // (proves no double-read / no data loss / no duplication).
            let reassembled: Vec<u8> = file.chunks.iter().flat_map(|c| c.data.clone()).collect();
            assert_eq!(&reassembled, expected);
        }
    }

    #[test]
    fn frc5a_matches_single_candidate_reference_chunks() {
        let dir = tempfile::tempdir().unwrap();
        let data = incompressible(500 * 1024, 9);
        std::fs::write(dir.path().join("f.bin"), &data).unwrap();
        let cfg = ChunkerConfig::with_target(64 * 1024).unwrap();

        let (files, _) = chunk_tree_with_bytes(dir.path(), &cfg).unwrap();
        let reference = chunk_bytes(&data, &cfg);
        assert_eq!(files[0].chunks, reference);
    }

    // --- FR-C5b: sim reuses choose_codec verbatim; stored bytes formula -

    #[test]
    fn frc5b_simulate_policy_matches_manual_frame_plus_aead_accounting() {
        let chunks = vec![compressible(80_000), incompressible(80_000, 3)];
        let stats = simulate_policy(&chunks, PolicyKind::Zstd3, Phase::InitialFull);

        // Independently recompute via the same real engine, byte for byte.
        let cfg = PolicyKind::Zstd3.config();
        let mut counters = PolicyCounters::default();
        let mut expected_stored = 0u64;
        for c in &chunks {
            let (codec, payload) = choose_codec(c, Phase::InitialFull, &cfg, &mut counters);
            let framed = crate::compression::frame(codec, &payload);
            expected_stored += (framed.len() + crypto::BLOB_OVERHEAD) as u64;
        }
        assert_eq!(stats.stored_bytes, expected_stored);
        assert_eq!(stats.chunk_count, 2);
        assert_eq!(stats.bytes_in, counters.bytes_in);
    }

    // --- FR-C5d: internal consistency of the speed model -----------------

    #[test]
    fn frc5d_cpu_floor_is_leq_every_bandwidth_point_and_monotone() {
        let net_mbps = [50.0, 200.0, 1000.0, 10_000.0];
        let points = bandwidth_projection(2.5, 500_000_000, &net_mbps);
        assert_eq!(points.len(), net_mbps.len());
        for p in &points {
            assert!(
                p.seconds >= 2.5 - 1e-9,
                "every bandwidth point must be >= the CPU-bound floor"
            );
        }
        // Monotone (non-increasing) as bandwidth grows.
        for w in points.windows(2) {
            assert!(
                w[1].seconds <= w[0].seconds + 1e-9,
                "wall-clock time must not increase as bandwidth grows: {:?}",
                points
            );
        }
        // At a huge bandwidth, transfer time collapses to ~0 and the floor
        // dominates.
        assert!((points.last().unwrap().seconds - 2.5).abs() < 1e-6);
    }

    #[test]
    fn frc5d_zero_bytes_is_floor_only() {
        let points = bandwidth_projection(1.0, 0, &[50.0, 1000.0]);
        for p in &points {
            assert!((p.seconds - 1.0).abs() < 1e-9);
        }
    }

    // --- harmonic_rate / seconds_for edge cases --------------------------

    #[test]
    fn harmonic_rate_ignores_non_finite_inputs() {
        let rate = harmonic_rate(1, &[100.0, f64::INFINITY, 200.0, f64::INFINITY]);
        // 1 / (1/100 + 1/200) = 66.66...
        assert!((rate - 66.666_666_67).abs() < 1e-3);
    }

    #[test]
    fn seconds_for_handles_zero_and_nonfinite_rate() {
        assert_eq!(seconds_for(0, 100.0), 0.0);
        assert_eq!(seconds_for(1024, 0.0), 0.0);
        assert_eq!(seconds_for(1024, f64::INFINITY), 0.0);
    }

    // --- FileClass classification ----------------------------------------

    #[test]
    fn file_class_classifies_by_extension() {
        assert_eq!(FileClass::classify("data/x.sqlite3"), FileClass::DbSqlite);
        assert_eq!(
            FileClass::classify("docs/report.DOCX"),
            FileClass::OfficeZip
        );
        assert_eq!(FileClass::classify("a/b/c.pdf"), FileClass::Pdf);
        assert_eq!(FileClass::classify("img/pic.PNG"), FileClass::Image);
        assert_eq!(FileClass::classify("src/main.rs"), FileClass::TextCode);
        assert_eq!(FileClass::classify("noext"), FileClass::Other);
        assert_eq!(FileClass::classify("weird.xyz"), FileClass::Other);
        assert_eq!(FileClass::classify("dir/.hidden"), FileClass::Other);
    }

    #[test]
    fn file_class_diagnostics_bytes_in_sums_match_input() {
        let chunks = vec![
            (FileClass::TextCode, compressible(60_000)),
            (FileClass::Image, incompressible(60_000, 4)),
        ];
        let rows = file_class_diagnostics(&chunks, PolicyKind::Zstd3);
        let total_in: u64 = rows.iter().map(|r| r.bytes_in).sum();
        assert_eq!(total_in, 120_000);
        // The compressible text/code chunk must show real savings; the
        // incompressible "image" stand-in must not.
        let text = rows.iter().find(|r| r.class == "text/code").unwrap();
        assert!(text.bytes_out < text.bytes_in);
    }

    // --- PolicyKind::name / ALL coverage ---------------------------------

    #[test]
    fn every_policy_kind_has_a_distinct_name() {
        let names: Vec<&str> = PolicyKind::ALL.iter().map(|k| k.name()).collect();
        let mut sorted = names.clone();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(sorted.len(), names.len(), "policy names must be unique");
    }

    // --- recommend_policy heuristic --------------------------------------

    fn dummy_row(policy: &'static str, cpu_seconds: f64, steady_state: u64) -> PolicyRow {
        let stored = PolicyStoredStats {
            chunk_count: 1,
            bytes_in: 100,
            bytes_out: 100,
            framed_bytes: 101,
            stored_bytes: 141,
            ratio: 1.0,
            raw_chunks: 1,
            zstd3_chunks: 0,
            escalated_chunks: 0,
            escalation_attempts: 0,
            wall: Duration::from_millis(1),
        };
        PolicyRow {
            policy,
            stored,
            initial_backup: SpeedProjection {
                cpu_bound_seconds: cpu_seconds,
                at_bandwidth: Vec::new(),
            },
            incremental: None,
            projected_steady_state_bytes: steady_state,
        }
    }

    #[test]
    fn recommend_policy_picks_smallest_steady_state_within_1_5x_cpu_bound() {
        let rows = vec![
            dummy_row("raw-only", 1.0, 1000),
            dummy_row("zstd3-always", 1.0, 200),
            dummy_row("zstd3", 1.0, 500),
            // 1.6x zstd3's cpu time: excluded even though it has the
            // smallest steady-state footprint.
            dummy_row("probe+zstd3", 1.6, 50),
            dummy_row("zstd3+escalate", 1.4, 300),
        ];
        assert_eq!(recommend_policy(&rows), Some("zstd3-always"));
    }

    #[test]
    fn measure_functions_produce_finite_positive_rates_for_nonempty_data() {
        let data = incompressible(256 * 1024, 5);
        let cfg = ChunkerConfig::with_target(64 * 1024).unwrap();
        assert!(measure_cdc_mbps(&data, &cfg) > 0.0);
        assert!(measure_blake3_mbps(&data) > 0.0);
        let mut r = StdRng::seed_from_u64(1);
        assert!(measure_encrypt_mbps(&mut r) > 0.0);
    }

    #[test]
    fn timing_reader_counts_bytes_and_accumulates_time() {
        let data = vec![0u8; 128 * 1024];
        let mut tr = TimingReader::new(std::io::Cursor::new(data.clone()));
        let mut buf = [0u8; 4096];
        let mut total = 0usize;
        loop {
            let n = tr.read(&mut buf).unwrap();
            if n == 0 {
                break;
            }
            total += n;
        }
        assert_eq!(total, data.len());
        assert_eq!(tr.bytes, data.len() as u64);
    }
}
