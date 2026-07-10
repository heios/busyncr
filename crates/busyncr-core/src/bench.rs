//! Offline chunk-size benchmark engine (PRD §3.7, FR10).
//!
//! Measures, for each candidate target chunk size, what a backup of a given
//! directory tree would cost in storage and daemon bookkeeping — fully
//! offline: no daemon, no keys, no network.
//!
//! # Single-pass design
//!
//! Each file is read from disk exactly once. The byte stream is fanned out
//! ([`fan_out_chunks`]) to one CDC chunker per candidate size, each running
//! concurrently on its own thread, with BLAKE3 hashing at each chunker's
//! boundaries. Total cost is therefore ≈ one full dataset read (I/O-bound)
//! regardless of the number of candidates.
//!
//! # Projection layout
//!
//! All metadata projections are exact arithmetic over documented record
//! layouts, not estimates:
//!
//! * daemon index bytes = `unique_chunks ×`
//!   [`IndexEntry::WIRE_SIZE`](crate::index::IndexEntry::WIRE_SIZE);
//! * manifest bytes per snapshot = [`MANIFEST_HEADER_BYTES`] + Σ over files
//!   ([`MANIFEST_FILE_FIXED_BYTES`] + path bytes + 32 × chunk count);
//! * projected bookkeeping for `N` snapshots = index bytes + `N` × manifest
//!   bytes (steady-state assumption: the unique chunk set is shared across
//!   retained snapshots, each snapshot pays its own manifest).
//!
//! The default `N` is the steady-state occupancy of the PRD §3.5 retention
//! grid ([`steady_state_snapshots`]).

use std::collections::HashSet;
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::mpsc;
use std::sync::Arc;

use serde::Serialize;

use crate::chunking::{chunk_reader, ChunkId, ChunkerConfig, ChunkingError};
use crate::index::IndexEntry;

// The manifest layout constants moved to `crate::manifest` in slice S3,
// where the real serializer lives; re-exported here so bench callers and the
// documented projection formula keep working unchanged. `Manifest::encode`
// produces exactly these sizes (pinned by test), so projections stay exact.
pub use crate::manifest::{MANIFEST_FILE_FIXED_BYTES, MANIFEST_HEADER_BYTES};

/// PRD §3.5 retention grid tiers as `(tier_start_hours, cell_width_hours)`:
/// age < 24 h → one per 3 h; 24 h – 4 d → one per 24 h; 4 d – 16 d → one per
/// 4 d; ≥ 16 d → one per 16 d.
pub const RETENTION_TIERS: [(u64, u64); 4] = [(0, 3), (24, 24), (96, 96), (384, 384)];

/// Default horizon (days) over which steady-state grid occupancy is counted.
///
/// The final retention tier (≥ 16 d) is unbounded, so "steady-state
/// occupancy" needs a documented horizon to be finite; one year is the
/// default planning window.
pub const DEFAULT_PROJECTION_HORIZON_DAYS: u64 = 365;

/// Number of snapshots retained at steady state by the PRD §3.5 grid over a
/// history of `horizon_days` days: the number of grid cells the tiers carve
/// out of `[0, horizon)` (one retained snapshot per cell, partial trailing
/// cells count as occupied).
///
/// `steady_state_snapshots(DEFAULT_PROJECTION_HORIZON_DAYS)` = 36
/// (8 three-hour cells + 3 daily + 3 four-day + 22 sixteen-day).
#[must_use]
pub fn steady_state_snapshots(horizon_days: u64) -> u64 {
    let horizon_hours = horizon_days.saturating_mul(24);
    let mut cells = 0u64;
    for (i, (start, width)) in RETENTION_TIERS.iter().enumerate() {
        let end = RETENTION_TIERS
            .get(i + 1)
            .map_or(u64::MAX, |&(next_start, _)| next_start);
        let upper = end.min(horizon_hours);
        if upper > *start {
            cells += (upper - start).div_ceil(*width);
        }
    }
    cells
}

/// Errors produced by the benchmark engine.
#[derive(Debug, thiserror::Error)]
pub enum BenchError {
    /// Chunking failed for a file.
    #[error("chunking failed for {path}: {source}")]
    Chunking {
        /// The file (relative path) being chunked.
        path: String,
        /// The underlying chunking error.
        #[source]
        source: ChunkingError,
    },
    /// Filesystem I/O failed.
    #[error("I/O error at {path}")]
    Io {
        /// The path the failing operation touched.
        path: PathBuf,
        /// The underlying I/O error.
        #[source]
        source: std::io::Error,
    },
    /// The benchmark root is not a directory.
    #[error("not a directory: {0}")]
    NotADirectory(PathBuf),
    /// A file path under the root is not valid UTF-8 and cannot be recorded
    /// in a manifest.
    #[error("path is not valid UTF-8: {0}")]
    NonUtf8Path(PathBuf),
    /// A [`FileChunking`] carries a different number of per-candidate results
    /// than the candidate list given to [`build_report`].
    #[error("file {path} has {got} candidate results, expected {expected}")]
    CandidateMismatch {
        /// The offending file.
        path: String,
        /// Candidate result count found on the file.
        got: usize,
        /// Candidate count expected (length of the config list).
        expected: usize,
    },
}

/// Identity and length of a single chunk (data bytes are not retained).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChunkMeta {
    /// BLAKE3 chunk ID of the chunk's plaintext.
    pub id: ChunkId,
    /// Chunk length in bytes.
    pub len: u64,
}

/// Result of fanning one byte stream out to several chunkers.
#[derive(Debug)]
pub struct FanOut {
    /// Chunk sequences, one per candidate config, in the order the configs
    /// were given.
    pub per_candidate: Vec<Vec<ChunkMeta>>,
    /// Total bytes read from the source (exactly once).
    pub bytes_read: u64,
}

/// Size of the blocks broadcast from the reader to the chunker threads.
const FAN_OUT_BLOCK_SIZE: usize = 256 * 1024;

/// Bounded channel depth per chunker (backpressure so a slow chunker cannot
/// force unbounded buffering).
const FAN_OUT_CHANNEL_DEPTH: usize = 4;

/// Adapts a channel of shared byte blocks into a [`Read`] for a chunker
/// thread.
struct ChannelReader {
    rx: mpsc::Receiver<Arc<[u8]>>,
    current: Option<Arc<[u8]>>,
    pos: usize,
}

impl Read for ChannelReader {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        loop {
            if let Some(cur) = &self.current {
                if self.pos < cur.len() {
                    let n = buf.len().min(cur.len() - self.pos);
                    buf[..n].copy_from_slice(&cur[self.pos..self.pos + n]);
                    self.pos += n;
                    return Ok(n);
                }
                self.current = None;
            }
            match self.rx.recv() {
                Ok(block) => {
                    self.current = Some(block);
                    self.pos = 0;
                }
                // Sender dropped: clean end of stream.
                Err(mpsc::RecvError) => return Ok(0),
            }
        }
    }
}

/// Chunks one byte stream under every candidate config while reading the
/// source **exactly once**.
///
/// Blocks are read on the calling thread and broadcast (as shared `Arc`
/// slices — no per-candidate copies) to one chunker thread per config; each
/// thread hashes chunk boundaries with BLAKE3 as they are found. Chunk
/// boundaries and IDs are identical to a standalone
/// [`chunk_reader`](crate::chunking::chunk_reader) run with the same config
/// (verified by test).
///
/// # Errors
///
/// Returns [`ChunkingError::Io`] if the source fails, or the first chunker
/// error if a chunker fails.
pub fn fan_out_chunks<R: Read>(
    mut source: R,
    configs: &[ChunkerConfig],
) -> Result<FanOut, ChunkingError> {
    if configs.is_empty() {
        // Still honor the contract of reading the source once so
        // `bytes_read` is meaningful.
        let mut total = 0u64;
        let mut buf = vec![0u8; FAN_OUT_BLOCK_SIZE];
        loop {
            match source.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => total += n as u64,
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
                Err(e) => return Err(ChunkingError::Io(e)),
            }
        }
        return Ok(FanOut {
            per_candidate: Vec::new(),
            bytes_read: total,
        });
    }

    std::thread::scope(|scope| {
        let mut senders = Vec::with_capacity(configs.len());
        let mut handles = Vec::with_capacity(configs.len());
        for cfg in configs {
            let (tx, rx) = mpsc::sync_channel::<Arc<[u8]>>(FAN_OUT_CHANNEL_DEPTH);
            senders.push(tx);
            let cfg = *cfg;
            handles.push(
                scope.spawn(move || -> Result<Vec<ChunkMeta>, ChunkingError> {
                    let reader = ChannelReader {
                        rx,
                        current: None,
                        pos: 0,
                    };
                    chunk_reader(reader, &cfg)
                        .map(|res| {
                            res.map(|c| ChunkMeta {
                                id: c.id,
                                len: c.len() as u64,
                            })
                        })
                        .collect()
                }),
            );
        }

        let mut bytes_read = 0u64;
        let mut read_err: Option<std::io::Error> = None;
        let mut buf = vec![0u8; FAN_OUT_BLOCK_SIZE];
        loop {
            match source.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => {
                    bytes_read += n as u64;
                    let block: Arc<[u8]> = Arc::from(&buf[..n]);
                    for tx in &senders {
                        // A failed send means that chunker already stopped
                        // (with an error we will surface from its handle).
                        let _ = tx.send(Arc::clone(&block));
                    }
                }
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
                Err(e) => {
                    read_err = Some(e);
                    break;
                }
            }
        }
        // Dropping the senders signals end-of-stream to every chunker.
        drop(senders);

        let mut per_candidate = Vec::with_capacity(handles.len());
        let mut worker_err: Option<ChunkingError> = None;
        for handle in handles {
            match handle.join() {
                Ok(Ok(chunks)) => per_candidate.push(chunks),
                Ok(Err(e)) => {
                    if worker_err.is_none() {
                        worker_err = Some(e);
                    }
                    per_candidate.push(Vec::new());
                }
                Err(_) => {
                    if worker_err.is_none() {
                        worker_err =
                            Some(ChunkingError::Internal("chunker thread panicked".into()));
                    }
                    per_candidate.push(Vec::new());
                }
            }
        }

        if let Some(e) = read_err {
            return Err(ChunkingError::Io(e));
        }
        if let Some(e) = worker_err {
            return Err(e);
        }
        Ok(FanOut {
            per_candidate,
            bytes_read,
        })
    })
}

/// Per-file chunking results across every candidate config.
#[derive(Debug, Clone)]
pub struct FileChunking {
    /// Path relative to the benchmark root, `/`-separated on every platform
    /// (the form a manifest would store).
    pub rel_path: String,
    /// File length in bytes (as read).
    pub file_bytes: u64,
    /// Chunk sequences, one per candidate config, in config order.
    pub per_candidate: Vec<Vec<ChunkMeta>>,
}

/// Chunks a set of named byte sources, each read exactly once via
/// [`fan_out_chunks`].
///
/// This is the instrumentable core of [`chunk_tree`]: FR10's I/O-accounting
/// test drives it with counting readers.
///
/// # Errors
///
/// Propagates I/O and chunking failures tagged with the source's name.
pub fn chunk_sources<R, I>(
    sources: I,
    configs: &[ChunkerConfig],
) -> Result<Vec<FileChunking>, BenchError>
where
    R: Read,
    I: IntoIterator<Item = (String, R)>,
{
    let mut out = Vec::new();
    for (rel_path, reader) in sources {
        let fan = fan_out_chunks(reader, configs).map_err(|e| match e {
            ChunkingError::Io(io) => BenchError::Io {
                path: PathBuf::from(&rel_path),
                source: io,
            },
            other => BenchError::Chunking {
                path: rel_path.clone(),
                source: other,
            },
        })?;
        out.push(FileChunking {
            rel_path,
            file_bytes: fan.bytes_read,
            per_candidate: fan.per_candidate,
        });
    }
    Ok(out)
}

/// Recursively collects regular files under `dir`, recording each one's
/// `/`-separated path relative to `root`. Symlinks are skipped (never
/// followed) so cycles cannot occur.
///
/// `pub(crate)`: reused by [`crate::policy_bench`], which needs the same
/// deterministic file walk but retains full chunk bytes rather than just
/// [`ChunkMeta`].
pub(crate) fn collect_files(
    root: &Path,
    dir: &Path,
    out: &mut Vec<(String, PathBuf)>,
) -> Result<(), BenchError> {
    let entries = fs::read_dir(dir).map_err(|e| BenchError::Io {
        path: dir.to_path_buf(),
        source: e,
    })?;
    for entry in entries {
        let entry = entry.map_err(|e| BenchError::Io {
            path: dir.to_path_buf(),
            source: e,
        })?;
        let path = entry.path();
        let file_type = entry.file_type().map_err(|e| BenchError::Io {
            path: path.clone(),
            source: e,
        })?;
        if file_type.is_symlink() {
            continue;
        }
        if file_type.is_dir() {
            collect_files(root, &path, out)?;
        } else if file_type.is_file() {
            let rel = path
                .strip_prefix(root)
                .map_err(|_| BenchError::NonUtf8Path(path.clone()))?;
            let mut parts = Vec::new();
            for component in rel.components() {
                let s = component
                    .as_os_str()
                    .to_str()
                    .ok_or_else(|| BenchError::NonUtf8Path(path.clone()))?;
                parts.push(s.to_owned());
            }
            out.push((parts.join("/"), path));
        }
    }
    Ok(())
}

/// Chunks every regular file under `root` with every candidate config,
/// reading each file exactly once (see [`fan_out_chunks`]).
///
/// Files are processed in sorted relative-path order for deterministic
/// output. Symlinks are skipped.
///
/// # Errors
///
/// Fails if `root` is not a directory, on any I/O error, on non-UTF-8 paths,
/// or if a chunker fails.
pub fn chunk_tree(root: &Path, configs: &[ChunkerConfig]) -> Result<Vec<FileChunking>, BenchError> {
    if !root.is_dir() {
        return Err(BenchError::NotADirectory(root.to_path_buf()));
    }
    let mut files = Vec::new();
    collect_files(root, root, &mut files)?;
    files.sort();
    let mut out = Vec::with_capacity(files.len());
    for (rel_path, abs_path) in files {
        let file = fs::File::open(&abs_path).map_err(|e| BenchError::Io {
            path: abs_path.clone(),
            source: e,
        })?;
        let fan = fan_out_chunks(file, configs).map_err(|e| match e {
            ChunkingError::Io(io) => BenchError::Io {
                path: abs_path.clone(),
                source: io,
            },
            other => BenchError::Chunking {
                path: rel_path.clone(),
                source: other,
            },
        })?;
        out.push(FileChunking {
            rel_path,
            file_bytes: fan.bytes_read,
            per_candidate: fan.per_candidate,
        });
    }
    Ok(out)
}

/// Cross-version overlap against a baseline tree (PRD §3.7 `--baseline`).
#[derive(Debug, Clone, Serialize)]
pub struct BaselineOverlap {
    /// Unique chunks in the baseline tree under this candidate.
    pub baseline_unique_chunks: u64,
    /// Unique chunk IDs present in **both** trees under this candidate.
    pub shared_unique_chunks: u64,
    /// `shared_unique_chunks / unique_chunks(current) × 100` — the share of
    /// the current tree's unique chunks the daemon would already hold.
    pub overlap_percent: f64,
}

/// Measured results and exact metadata projections for one candidate size.
#[derive(Debug, Clone, Serialize)]
pub struct CandidateReport {
    /// Candidate target (average) chunk size in bytes.
    pub target_size: u64,
    /// Derived minimum chunk size (target / 4).
    pub min_size: u64,
    /// Derived maximum chunk size (target × 4, capped by FastCDC).
    pub max_size: u64,
    /// Total chunks emitted across all files.
    pub total_chunks: u64,
    /// Distinct chunk IDs across all files.
    pub unique_chunks: u64,
    /// Total chunked bytes (equals the dataset size).
    pub total_bytes: u64,
    /// Bytes of the distinct chunks (what the store would hold).
    pub unique_bytes: u64,
    /// Intra-dataset dedup ratio: `total_bytes / unique_bytes` (1.0 = no
    /// duplication; higher is better).
    pub dedup_ratio: f64,
    /// Mean actual chunk size in bytes.
    pub mean_chunk_size: f64,
    /// Median (nearest-rank p50) actual chunk size in bytes.
    pub median_chunk_size: u64,
    /// Nearest-rank p95 actual chunk size in bytes.
    pub p95_chunk_size: u64,
    /// Daemon index metadata: `unique_chunks × IndexEntry::WIRE_SIZE`.
    pub index_bytes: u64,
    /// Manifest bytes for one snapshot of this tree (header + per-file fixed
    /// metadata + path bytes + 32 bytes per chunk).
    pub manifest_bytes_per_snapshot: u64,
    /// `index_bytes + snapshots × manifest_bytes_per_snapshot`.
    pub projected_bookkeeping_bytes: u64,
    /// Cross-version overlap; `None` without `--baseline` (figures above are
    /// then intra-snapshot only and understate versioned savings).
    pub baseline: Option<BaselineOverlap>,
}

/// Full benchmark report across every candidate.
#[derive(Debug, Clone, Serialize)]
pub struct BenchReport {
    /// The benchmarked tree.
    pub root: String,
    /// The baseline tree, when `--baseline` was given.
    pub baseline_root: Option<String>,
    /// Number of regular files measured.
    pub files_scanned: u64,
    /// Total dataset bytes.
    pub total_bytes: u64,
    /// Snapshot count `N` used for the bookkeeping projection.
    pub snapshots_projected: u64,
    /// Per-candidate results, in the order candidates were given.
    pub candidates: Vec<CandidateReport>,
}

/// Nearest-rank percentile over a sorted slice (`p` in percent). Returns 0
/// for an empty slice.
fn nearest_rank(sorted: &[u64], p: u64) -> u64 {
    if sorted.is_empty() {
        return 0;
    }
    let rank = (sorted.len() as u64 * p).div_ceil(100).max(1);
    sorted[(rank - 1) as usize]
}

/// Collects the distinct chunk IDs of candidate `ci` across `files`.
fn unique_ids(files: &[FileChunking], ci: usize) -> HashSet<ChunkId> {
    let mut set = HashSet::new();
    for file in files {
        for meta in &file.per_candidate[ci] {
            set.insert(meta.id);
        }
    }
    set
}

/// Verifies every file carries exactly one result per candidate.
fn check_candidate_counts(files: &[FileChunking], expected: usize) -> Result<(), BenchError> {
    for file in files {
        if file.per_candidate.len() != expected {
            return Err(BenchError::CandidateMismatch {
                path: file.rel_path.clone(),
                got: file.per_candidate.len(),
                expected,
            });
        }
    }
    Ok(())
}

/// Builds the per-candidate report from chunked trees.
///
/// All figures are measured or exact arithmetic over the documented layouts
/// (see the module docs); nothing is sampled or estimated.
///
/// # Errors
///
/// Returns [`BenchError::CandidateMismatch`] if any [`FileChunking`] does not
/// carry exactly one result per config.
pub fn build_report(
    root: &str,
    files: &[FileChunking],
    configs: &[ChunkerConfig],
    snapshots: u64,
    baseline: Option<(&str, &[FileChunking])>,
) -> Result<BenchReport, BenchError> {
    check_candidate_counts(files, configs.len())?;
    if let Some((_, baseline_files)) = baseline {
        check_candidate_counts(baseline_files, configs.len())?;
    }

    let total_bytes: u64 = files.iter().map(|f| f.file_bytes).sum();
    let mut candidates = Vec::with_capacity(configs.len());

    for (ci, cfg) in configs.iter().enumerate() {
        let mut lens: Vec<u64> = Vec::new();
        let mut unique = HashSet::new();
        let mut unique_bytes = 0u64;
        let mut manifest_bytes = MANIFEST_HEADER_BYTES;

        for file in files {
            let metas = &file.per_candidate[ci];
            manifest_bytes += MANIFEST_FILE_FIXED_BYTES
                + file.rel_path.len() as u64
                + ChunkId::LEN as u64 * metas.len() as u64;
            for meta in metas {
                lens.push(meta.len);
                if unique.insert(meta.id) {
                    unique_bytes += meta.len;
                }
            }
        }

        let total_chunks = lens.len() as u64;
        let candidate_total_bytes: u64 = lens.iter().sum();
        lens.sort_unstable();
        let mean_chunk_size = if total_chunks == 0 {
            0.0
        } else {
            candidate_total_bytes as f64 / total_chunks as f64
        };
        let dedup_ratio = if unique_bytes == 0 {
            1.0
        } else {
            candidate_total_bytes as f64 / unique_bytes as f64
        };
        let index_bytes = unique.len() as u64 * IndexEntry::WIRE_SIZE;
        let projected_bookkeeping_bytes = index_bytes + snapshots * manifest_bytes;

        let baseline_overlap = baseline.map(|(_, baseline_files)| {
            let baseline_set = unique_ids(baseline_files, ci);
            let shared = unique.intersection(&baseline_set).count() as u64;
            let overlap_percent = if unique.is_empty() {
                0.0
            } else {
                shared as f64 / unique.len() as f64 * 100.0
            };
            BaselineOverlap {
                baseline_unique_chunks: baseline_set.len() as u64,
                shared_unique_chunks: shared,
                overlap_percent,
            }
        });

        candidates.push(CandidateReport {
            target_size: cfg.target_size() as u64,
            min_size: cfg.min_size() as u64,
            max_size: cfg.max_size() as u64,
            total_chunks,
            unique_chunks: unique.len() as u64,
            total_bytes: candidate_total_bytes,
            unique_bytes,
            dedup_ratio,
            mean_chunk_size,
            median_chunk_size: nearest_rank(&lens, 50),
            p95_chunk_size: nearest_rank(&lens, 95),
            index_bytes,
            manifest_bytes_per_snapshot: manifest_bytes,
            projected_bookkeeping_bytes,
            baseline: baseline_overlap,
        });
    }

    Ok(BenchReport {
        root: root.to_owned(),
        baseline_root: baseline.map(|(r, _)| r.to_owned()),
        files_scanned: files.len() as u64,
        total_bytes,
        snapshots_projected: snapshots,
        candidates,
    })
}

/// Recommendation heuristic (documented in `bench-chunking --help`): the
/// candidate with the smallest combined cost
/// `unique_bytes + projected_bookkeeping_bytes` — i.e. the best
/// storage × metadata trade-off. Ties go to the smaller target size. Returns
/// the winning candidate's target size, or `None` with no candidates.
#[must_use]
pub fn recommend(report: &BenchReport) -> Option<u64> {
    report
        .candidates
        .iter()
        .min_by_key(|c| {
            (
                c.unique_bytes + c.projected_bookkeeping_bytes,
                c.target_size,
            )
        })
        .map(|c| c.target_size)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chunking::chunk_bytes;
    use rand::rngs::StdRng;
    use rand::{Rng, SeedableRng};
    use std::io::Cursor;
    use std::sync::atomic::{AtomicU64, Ordering};

    fn random_bytes(len: usize, seed: u64) -> Vec<u8> {
        let mut rng = StdRng::seed_from_u64(seed);
        let mut buf = vec![0u8; len];
        rng.fill_bytes(&mut buf);
        buf
    }

    fn cfg(target: usize) -> ChunkerConfig {
        ChunkerConfig::with_target(target).unwrap()
    }

    /// Instrumented reader: counts every byte served, for FR10a I/O
    /// accounting.
    struct CountingReader<R> {
        inner: R,
        bytes: Arc<AtomicU64>,
    }

    impl<R: Read> Read for CountingReader<R> {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            let n = self.inner.read(buf)?;
            self.bytes.fetch_add(n as u64, Ordering::Relaxed);
            Ok(n)
        }
    }

    #[test]
    fn fr10_each_file_read_exactly_once_despite_many_candidates() {
        let configs = [cfg(16 * 1024), cfg(32 * 1024), cfg(64 * 1024)];
        let file_sizes = [512 * 1024, 300 * 1024 + 7, 64 * 1024];
        let data: Vec<Vec<u8>> = file_sizes
            .iter()
            .enumerate()
            .map(|(i, &len)| random_bytes(len, 42 + i as u64))
            .collect();

        let counters: Vec<Arc<AtomicU64>> = (0..data.len())
            .map(|_| Arc::new(AtomicU64::new(0)))
            .collect();
        let sources: Vec<(String, CountingReader<Cursor<Vec<u8>>>)> = data
            .iter()
            .zip(&counters)
            .enumerate()
            .map(|(i, (bytes, counter))| {
                (
                    format!("file{i}.bin"),
                    CountingReader {
                        inner: Cursor::new(bytes.clone()),
                        bytes: Arc::clone(counter),
                    },
                )
            })
            .collect();

        let files = chunk_sources(sources, &configs).unwrap();

        // I/O accounting: each file's reader served exactly its length once,
        // even though three candidate chunkers all consumed the stream.
        for ((counter, expected_len), file) in counters.iter().zip(file_sizes).zip(&files) {
            assert_eq!(
                counter.load(Ordering::Relaxed),
                expected_len as u64,
                "file must be read exactly once (not once per candidate)"
            );
            assert_eq!(file.file_bytes, expected_len as u64);
            // Every candidate's chunks must tile the whole file.
            for metas in &file.per_candidate {
                let sum: u64 = metas.iter().map(|m| m.len).sum();
                assert_eq!(sum, expected_len as u64);
            }
        }
    }

    #[test]
    fn fr10_fan_out_matches_single_candidate_reference_runs() {
        let data = random_bytes(3 * 1024 * 1024 + 123, 7);
        let configs = [cfg(16 * 1024), cfg(64 * 1024), cfg(256 * 1024)];

        let fan = fan_out_chunks(Cursor::new(data.clone()), &configs).unwrap();
        assert_eq!(fan.bytes_read, data.len() as u64);
        assert_eq!(fan.per_candidate.len(), configs.len());

        for (config, fanned) in configs.iter().zip(&fan.per_candidate) {
            let reference: Vec<ChunkMeta> = chunk_bytes(&data, config)
                .into_iter()
                .map(|c| ChunkMeta {
                    id: c.id,
                    len: c.len() as u64,
                })
                .collect();
            assert!(!reference.is_empty());
            assert_eq!(
                fanned,
                &reference,
                "fan-out chunks must match a standalone run for target {}",
                config.target_size()
            );
        }
    }

    #[test]
    fn fr10_chunk_tree_matches_references_and_orders_paths() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        std::fs::create_dir_all(root.join("sub/inner")).unwrap();
        let a = random_bytes(200 * 1024, 11);
        let b = random_bytes(90 * 1024, 12);
        let c = random_bytes(10, 13);
        std::fs::write(root.join("zeta.bin"), &a).unwrap();
        std::fs::write(root.join("sub/alpha.bin"), &b).unwrap();
        std::fs::write(root.join("sub/inner/tiny.bin"), &c).unwrap();

        let configs = [cfg(16 * 1024), cfg(64 * 1024)];
        let files = chunk_tree(root, &configs).unwrap();

        let rel_paths: Vec<&str> = files.iter().map(|f| f.rel_path.as_str()).collect();
        assert_eq!(
            rel_paths,
            ["sub/alpha.bin", "sub/inner/tiny.bin", "zeta.bin"],
            "files must be sorted by /-separated relative path"
        );

        for (file, data) in files.iter().zip([&b, &c, &a]) {
            assert_eq!(file.file_bytes, data.len() as u64);
            for (config, fanned) in configs.iter().zip(&file.per_candidate) {
                let reference: Vec<ChunkMeta> = chunk_bytes(data, config)
                    .into_iter()
                    .map(|ch| ChunkMeta {
                        id: ch.id,
                        len: ch.len() as u64,
                    })
                    .collect();
                assert_eq!(fanned, &reference);
            }
        }
    }

    #[test]
    fn fr10_projection_arithmetic_exact() {
        let id1 = ChunkId::from_bytes([1; 32]);
        let id2 = ChunkId::from_bytes([2; 32]);
        let configs = [cfg(64 * 1024)];
        let files = [
            FileChunking {
                rel_path: "a/b.txt".into(), // 7 path bytes
                file_bytes: 300,
                per_candidate: vec![vec![
                    ChunkMeta { id: id1, len: 100 },
                    ChunkMeta { id: id2, len: 200 },
                ]],
            },
            FileChunking {
                rel_path: "c.bin".into(), // 5 path bytes
                file_bytes: 200,
                per_candidate: vec![vec![ChunkMeta { id: id2, len: 200 }]],
            },
        ];

        let report = build_report("corpus", &files, &configs, 17, None).unwrap();
        assert_eq!(report.files_scanned, 2);
        assert_eq!(report.total_bytes, 500);
        assert_eq!(report.snapshots_projected, 17);

        let c = &report.candidates[0];
        assert_eq!(c.total_chunks, 3);
        assert_eq!(c.unique_chunks, 2);
        assert_eq!(c.total_bytes, 500);
        assert_eq!(c.unique_bytes, 300);
        assert!((c.dedup_ratio - 500.0 / 300.0).abs() < 1e-12);
        assert!((c.mean_chunk_size - 500.0 / 3.0).abs() < 1e-12);
        // sorted lens [100, 200, 200]: p50 rank ceil(150/100)=2 -> 200,
        // p95 rank ceil(285/100)=3 -> 200.
        assert_eq!(c.median_chunk_size, 200);
        assert_eq!(c.p95_chunk_size, 200);
        // Index: 2 unique x 48-byte record.
        assert_eq!(c.index_bytes, 2 * IndexEntry::WIRE_SIZE);
        assert_eq!(c.index_bytes, 96);
        // Manifest: 28 header + (32 + 7 + 32*2) + (32 + 5 + 32*1).
        assert_eq!(
            c.manifest_bytes_per_snapshot,
            MANIFEST_HEADER_BYTES + (32 + 7 + 64) + (32 + 5 + 32)
        );
        assert_eq!(c.manifest_bytes_per_snapshot, 200);
        // Projection: index + N x manifest, exact.
        assert_eq!(c.projected_bookkeeping_bytes, 96 + 17 * 200);
        assert!(c.baseline.is_none());
    }

    #[test]
    fn fr10_steady_state_grid_occupancy() {
        // 1 day: only the 3-hour tier is populated: 24/3 = 8 cells.
        assert_eq!(steady_state_snapshots(1), 8);
        // 60 days (the FR5 horizon): 8 + 3 + 3 + ceil((60-16)/16) = 17.
        assert_eq!(steady_state_snapshots(60), 17);
        // Default 1-year horizon: 8 + 3 + 3 + ceil((365-16)/16) = 36.
        assert_eq!(steady_state_snapshots(DEFAULT_PROJECTION_HORIZON_DAYS), 36);
    }

    #[test]
    fn fr10_baseline_overlap_correct_for_known_mutation_rate() {
        let baseline_dir = tempfile::tempdir().unwrap();
        let current_dir = tempfile::tempdir().unwrap();
        let configs = [cfg(16 * 1024)];
        let n_files = 10usize;
        let mutated = 3usize; // 30% of files fully replaced.
        let file_len = 128 * 1024;

        let mut current_data = Vec::new();
        let mut baseline_data = Vec::new();
        for i in 0..n_files {
            let old = random_bytes(file_len, 1000 + i as u64);
            let new = if i < n_files - mutated {
                old.clone()
            } else {
                random_bytes(file_len, 9000 + i as u64)
            };
            std::fs::write(baseline_dir.path().join(format!("f{i}.bin")), &old).unwrap();
            std::fs::write(current_dir.path().join(format!("f{i}.bin")), &new).unwrap();
            baseline_data.push(old);
            current_data.push(new);
        }

        let current = chunk_tree(current_dir.path(), &configs).unwrap();
        let baseline = chunk_tree(baseline_dir.path(), &configs).unwrap();
        let report = build_report(
            "current",
            &current,
            &configs,
            1,
            Some(("baseline", &baseline)),
        )
        .unwrap();

        // Expected overlap, computed independently with the in-memory
        // reference chunker.
        let set_of = |datasets: &[Vec<u8>]| -> HashSet<ChunkId> {
            datasets
                .iter()
                .flat_map(|d| chunk_bytes(d, &configs[0]))
                .map(|c| c.id)
                .collect()
        };
        let current_ids = set_of(&current_data);
        let baseline_ids = set_of(&baseline_data);
        let expected_shared = current_ids.intersection(&baseline_ids).count() as u64;

        let c = &report.candidates[0];
        let overlap = c.baseline.as_ref().unwrap();
        assert_eq!(c.unique_chunks, current_ids.len() as u64);
        assert_eq!(overlap.baseline_unique_chunks, baseline_ids.len() as u64);
        assert_eq!(overlap.shared_unique_chunks, expected_shared);
        let expected_percent = expected_shared as f64 / current_ids.len() as f64 * 100.0;
        assert!((overlap.overlap_percent - expected_percent).abs() < 1e-9);
        // 7 of 10 equally-sized random files unchanged -> overlap near 70%.
        assert!(
            (60.0..=80.0).contains(&overlap.overlap_percent),
            "expected ~70% overlap for a 30% mutation rate, got {:.2}%",
            overlap.overlap_percent
        );
    }

    #[test]
    fn recommend_picks_lowest_combined_cost_smaller_target_on_tie() {
        let mk = |target: u64, unique_bytes: u64, projected: u64| CandidateReport {
            target_size: target,
            min_size: target / 4,
            max_size: target * 4,
            total_chunks: 1,
            unique_chunks: 1,
            total_bytes: unique_bytes,
            unique_bytes,
            dedup_ratio: 1.0,
            mean_chunk_size: unique_bytes as f64,
            median_chunk_size: unique_bytes,
            p95_chunk_size: unique_bytes,
            index_bytes: 48,
            manifest_bytes_per_snapshot: projected,
            projected_bookkeeping_bytes: projected,
            baseline: None,
        };
        let report = BenchReport {
            root: "r".into(),
            baseline_root: None,
            files_scanned: 1,
            total_bytes: 100,
            snapshots_projected: 1,
            candidates: vec![mk(1024, 100, 50), mk(512, 100, 40), mk(256, 100, 40)],
        };
        // 512 and 256 tie on combined cost; smaller target wins.
        assert_eq!(recommend(&report), Some(256));
        let empty = BenchReport {
            candidates: Vec::new(),
            ..report
        };
        assert_eq!(recommend(&empty), None);
    }

    #[test]
    fn fan_out_propagates_source_io_error() {
        struct FailingReader;
        impl Read for FailingReader {
            fn read(&mut self, _buf: &mut [u8]) -> std::io::Result<usize> {
                Err(std::io::Error::other("simulated disk failure"))
            }
        }
        let configs = [cfg(16 * 1024)];
        let result = fan_out_chunks(FailingReader, &configs);
        assert!(matches!(result, Err(ChunkingError::Io(_))));
    }

    #[test]
    fn empty_tree_produces_zeroed_report() {
        let dir = tempfile::tempdir().unwrap();
        let configs = [cfg(64 * 1024)];
        let files = chunk_tree(dir.path(), &configs).unwrap();
        assert!(files.is_empty());
        let report = build_report("empty", &files, &configs, 36, None).unwrap();
        let c = &report.candidates[0];
        assert_eq!(c.total_chunks, 0);
        assert_eq!(c.unique_chunks, 0);
        assert_eq!(c.index_bytes, 0);
        assert_eq!(c.manifest_bytes_per_snapshot, MANIFEST_HEADER_BYTES);
        assert_eq!(c.dedup_ratio, 1.0);
        assert_eq!(c.median_chunk_size, 0);
    }

    #[test]
    fn build_report_rejects_candidate_count_mismatch() {
        let configs = [cfg(64 * 1024), cfg(128 * 1024)];
        let files = [FileChunking {
            rel_path: "x".into(),
            file_bytes: 0,
            per_candidate: vec![Vec::new()], // only one result for two configs
        }];
        assert!(matches!(
            build_report("r", &files, &configs, 1, None),
            Err(BenchError::CandidateMismatch { .. })
        ));
    }
}
