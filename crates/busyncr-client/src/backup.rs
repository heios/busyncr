//! The backup pipeline (FR2, FR3; PRD §3.3/§3.4).
//!
//! One [`run_backup`] call = one snapshot:
//!
//! 1. Walk every configured folder tree deterministically (directory entries
//!    sorted by name; symlinks and other non-regular files skipped). Each
//!    root contributes manifest paths prefixed with its final path
//!    component, `/`-separated on every platform.
//! 2. Stream-chunk each file with the committed [`ChunkerConfig`] (CDC —
//!    whole files are never held in memory) and hash every chunk to its
//!    [`ChunkId`] — the *keyed* BLAKE3 of the plaintext under the backup
//!    set's chunk-ID key (FR-K1, PRD §3.3), so the daemon cannot confirm
//!    known plaintext.
//! 3. Dedup: batch chunk IDs through `HasChunks`; only chunks the daemon
//!    reports missing are encrypted (XChaCha20-Poly1305, AAD = chunk ID) and
//!    shipped via `UploadChunks` (FR3 — the transfer-size ledger in
//!    [`BackupReport`] counts exactly these ciphertext bytes).
//! 4. Encode the [`Manifest`], encrypt it under the data key (AAD = snapshot
//!    ULID), and `PutManifest` with the snapshot ID and chunk references as
//!    explicit fields — the daemon never sees the manifest plaintext
//!    (PRD §3.4).
//!
//! Determinism: the snapshot ID, creation time, and all randomness (nonces)
//! are injected by the caller — this module never reads the wall clock or
//! ambient entropy (project rule; the CLI passes real values, tests pass
//! seeded ones).

// `tonic::Status` is 176 bytes and rides inside `BackupError`; tonic returns
// it by value everywhere, so boxing at every conversion would outweigh the
// win (same rationale as the enroll module).
#![allow(clippy::result_large_err)]

use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::UNIX_EPOCH;

use busyncr_core::chunking::{chunk_reader_keyed, ChunkId, ChunkerConfig, ChunkingError};
use busyncr_core::crypto::{self, CryptoError, DataKey};
use busyncr_core::manifest::{FileEntry, Manifest, ManifestError};
use busyncr_proto::v1::busyncr_client::BusyncrClient;
use busyncr_proto::v1::{ChunkBlob, HasChunksRequest, PutManifestRequest};
use rand::CryptoRng;
use tonic::transport::Channel;
use ulid::Ulid;

use crate::enroll::{self, EnrollError};

/// Upper bound on chunks buffered before a dedup/upload flush.
const BATCH_MAX_CHUNKS: usize = 64;
/// Upper bound on plaintext bytes buffered before a dedup/upload flush.
const BATCH_MAX_BYTES: usize = 32 * 1024 * 1024;

/// Errors from the backup pipeline.
#[derive(Debug, thiserror::Error)]
pub enum BackupError {
    /// Filesystem access under a backup root failed.
    #[error("backup source I/O failed at {path}")]
    Io {
        /// Path being read.
        path: PathBuf,
        /// Underlying I/O error.
        #[source]
        source: std::io::Error,
    },

    /// A configured root is unusable (missing, not a directory, or has no
    /// final path component to name it by).
    #[error("backup root {path} is not a usable directory")]
    BadRoot {
        /// The offending root.
        path: PathBuf,
    },

    /// Two configured roots share a final path component, so their manifest
    /// paths would collide.
    #[error("two backup roots share the name {name:?}; rename one folder")]
    DuplicateRootName {
        /// The colliding final path component.
        name: String,
    },

    /// A file or directory name is not valid UTF-8 (manifest paths are
    /// UTF-8 strings).
    #[error("path {path} is not valid UTF-8 and cannot be recorded in a manifest")]
    NonUtf8Path {
        /// The offending path.
        path: PathBuf,
    },

    /// Chunking a source file failed.
    #[error("chunking failed")]
    Chunking(#[from] ChunkingError),

    /// Client-side encryption failed.
    #[error("encryption failed")]
    Crypto(#[from] CryptoError),

    /// Manifest serialization failed.
    #[error("manifest encoding failed")]
    Manifest(#[from] ManifestError),

    /// Loading local identity/key state or connecting to the daemon failed.
    #[error(transparent)]
    Enroll(#[from] EnrollError),

    /// The daemon refused an RPC.
    #[error("daemon refused the backup RPC: {0}")]
    Rpc(#[from] tonic::Status),

    /// The daemon's response violated the protocol contract.
    #[error("daemon returned an unusable response: {0}")]
    BadResponse(&'static str),
}

/// Everything [`run_backup`] needs.
#[derive(Debug)]
pub struct BackupRequest<'a> {
    /// Daemon endpoint, e.g. `https://backup-server:47820`.
    pub daemon_url: &'a str,
    /// Client state directory holding the enrolled identity and data key.
    pub state_dir: &'a Path,
    /// Folder trees to back up (from the TOML config).
    pub roots: &'a [PathBuf],
    /// The committed chunker configuration (PRD §3.7).
    pub chunker: ChunkerConfig,
    /// Snapshot identity for this run (injected — the CLI mints a fresh
    /// ULID, tests pass fixed ones).
    pub snapshot_id: Ulid,
    /// Snapshot creation time, whole seconds since the Unix epoch
    /// (injected).
    pub created_at: i64,
}

/// What one backup run did — including the exact transfer ledger FR3's
/// acceptance test asserts on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BackupReport {
    /// The snapshot this run stored.
    pub snapshot_id: Ulid,
    /// Files captured in the manifest.
    pub files: u64,
    /// Total plaintext bytes across all captured files.
    pub source_bytes: u64,
    /// Chunk references in the manifest (duplicates included).
    pub chunks_total: u64,
    /// Distinct chunk IDs seen this run.
    pub chunks_unique: u64,
    /// Chunks actually encrypted and shipped (daemon did not have them).
    pub chunks_uploaded: u64,
    /// Chunks skipped because the daemon already stored them (dedup, FR3).
    pub chunks_deduped: u64,
    /// Ciphertext bytes shipped through `UploadChunks` — the transfer-size
    /// ledger (FR3). Excludes the manifest; see `manifest_bytes`.
    pub upload_bytes: u64,
    /// Size of the encrypted manifest blob shipped via `PutManifest`.
    pub manifest_bytes: u64,
}

/// One file scheduled for capture: where it lives and its manifest path.
struct FileSpec {
    /// Absolute path on disk.
    abs: PathBuf,
    /// `/`-separated manifest path (`<root-name>/<relative...>`).
    rel: String,
}

/// Runs one backup: walk, chunk, dedup, upload, put encrypted manifest
/// (FR2/FR3). See the module docs for the pipeline.
///
/// # Errors
///
/// Any [`BackupError`]; the snapshot is only stored if every step succeeded
/// (the daemon refuses manifests referencing chunks it does not hold).
pub async fn run_backup<R: CryptoRng>(
    req: &BackupRequest<'_>,
    rng: &mut R,
) -> Result<BackupReport, BackupError> {
    let key = enroll::load_data_key(req.state_dir)?;
    let chunk_id_key = enroll::load_chunk_id_key(req.state_dir)?;
    let client = enroll::connect_authenticated(req.daemon_url, req.state_dir).await?;

    let specs = collect_files(req.roots)?;

    let mut session = Session {
        client,
        key,
        report: BackupReport {
            snapshot_id: req.snapshot_id,
            files: 0,
            source_bytes: 0,
            chunks_total: 0,
            chunks_unique: 0,
            chunks_uploaded: 0,
            chunks_deduped: 0,
            upload_bytes: 0,
            manifest_bytes: 0,
        },
    };

    // Chunks already handled this run (uploaded or confirmed present):
    // intra-run dedup so the same content in two files ships at most once.
    let mut seen: HashSet<ChunkId> = HashSet::new();
    // Plaintext chunks awaiting a HasChunks/UploadChunks round.
    let mut pending: Vec<(ChunkId, Vec<u8>)> = Vec::new();
    let mut pending_bytes = 0usize;

    let mut files = Vec::with_capacity(specs.len());
    for spec in specs {
        let file = fs::File::open(&spec.abs).map_err(|source| BackupError::Io {
            path: spec.abs.clone(),
            source,
        })?;
        let metadata = file.metadata().map_err(|source| BackupError::Io {
            path: spec.abs.clone(),
            source,
        })?;

        let mut chunk_ids = Vec::new();
        let mut content_len = 0u64;
        for chunk in chunk_reader_keyed(std::io::BufReader::new(file), &req.chunker, &chunk_id_key)
        {
            let chunk = chunk?;
            content_len += chunk.len() as u64;
            chunk_ids.push(chunk.id);
            session.report.chunks_total += 1;
            if seen.insert(chunk.id) {
                session.report.chunks_unique += 1;
                pending_bytes += chunk.len();
                pending.push((chunk.id, chunk.data));
                if pending.len() >= BATCH_MAX_CHUNKS || pending_bytes >= BATCH_MAX_BYTES {
                    session.flush(&mut pending, rng).await?;
                    pending_bytes = 0;
                }
            }
        }

        let (mtime_secs, mtime_nanos) = mtime_parts(&metadata);
        session.report.files += 1;
        session.report.source_bytes += content_len;
        files.push(FileEntry {
            path: spec.rel,
            // The size the manifest promises is what was actually chunked
            // (a file changing mid-read cannot desynchronize size vs chunks).
            size: content_len,
            mtime_secs,
            mtime_nanos,
            mode: file_mode(&metadata),
            chunks: chunk_ids,
        });
    }
    session.flush(&mut pending, rng).await?;

    let manifest = Manifest {
        snapshot_id: req.snapshot_id,
        created_at: req.created_at,
        files,
    };
    let encoded = manifest.encode()?;
    let sealed = crypto::encrypt_manifest(&session.key, req.snapshot_id, &encoded, rng)?;
    session.report.manifest_bytes = sealed.len() as u64;
    session
        .client
        .put_manifest(PutManifestRequest {
            manifest: sealed,
            snapshot_id: req.snapshot_id.to_bytes().to_vec(),
            chunk_ids: manifest
                .chunk_refs()
                .map(|id| id.as_bytes().to_vec())
                .collect(),
        })
        .await?;

    Ok(session.report)
}

/// Connection + key + running ledger for one backup.
struct Session {
    client: BusyncrClient<Channel>,
    key: DataKey,
    report: BackupReport,
}

impl Session {
    /// Dedups `pending` against the daemon (`HasChunks`), encrypts only the
    /// missing chunks, ships them (`UploadChunks`), and updates the ledger.
    /// Drains `pending` in all cases.
    async fn flush<R: CryptoRng>(
        &mut self,
        pending: &mut Vec<(ChunkId, Vec<u8>)>,
        rng: &mut R,
    ) -> Result<(), BackupError> {
        if pending.is_empty() {
            return Ok(());
        }

        let asked: Vec<Vec<u8>> = pending
            .iter()
            .map(|(id, _)| id.as_bytes().to_vec())
            .collect();
        let missing_wire = self
            .client
            .has_chunks(HasChunksRequest { chunk_ids: asked })
            .await?
            .into_inner()
            .missing_chunk_ids;
        let mut missing = HashSet::with_capacity(missing_wire.len());
        for raw in &missing_wire {
            let bytes: [u8; ChunkId::LEN] = raw
                .as_slice()
                .try_into()
                .map_err(|_| BackupError::BadResponse("malformed chunk ID in HasChunks reply"))?;
            missing.insert(ChunkId::from_bytes(bytes));
        }

        let mut blobs = Vec::new();
        for (id, data) in pending.drain(..) {
            if missing.contains(&id) {
                let ciphertext = crypto::encrypt_chunk(&self.key, &id, &data, rng)?;
                self.report.upload_bytes += ciphertext.len() as u64;
                self.report.chunks_uploaded += 1;
                blobs.push(ChunkBlob {
                    chunk_id: id.as_bytes().to_vec(),
                    data: ciphertext,
                });
            } else {
                self.report.chunks_deduped += 1;
            }
        }

        if !blobs.is_empty() {
            let expected = blobs.len() as u64;
            let outcome = self
                .client
                .upload_chunks(tokio_stream::iter(blobs))
                .await?
                .into_inner();
            if outcome.stored + outcome.already_present != expected {
                return Err(BackupError::BadResponse(
                    "UploadChunks acknowledged a different number of blobs than were sent",
                ));
            }
        }
        Ok(())
    }
}

/// Walks every root and returns the deterministic file list (each root's
/// entries prefixed with its final path component).
fn collect_files(roots: &[PathBuf]) -> Result<Vec<FileSpec>, BackupError> {
    let mut root_names: HashSet<String> = HashSet::new();
    let mut specs = Vec::new();
    for root in roots {
        if !root.is_dir() {
            return Err(BackupError::BadRoot { path: root.clone() });
        }
        let name = root
            .file_name()
            .and_then(|n| n.to_str())
            .ok_or_else(|| BackupError::BadRoot { path: root.clone() })?
            .to_owned();
        if !root_names.insert(name.clone()) {
            return Err(BackupError::DuplicateRootName { name });
        }
        walk_dir(root, &name, &mut specs)?;
    }
    Ok(specs)
}

/// Recursively walks `dir`, appending regular files in name-sorted order.
/// Symlinks and other non-regular entries are skipped (v1 scope: file
/// content + metadata; no symlink capture).
fn walk_dir(dir: &Path, rel_prefix: &str, out: &mut Vec<FileSpec>) -> Result<(), BackupError> {
    let io_err = |path: &Path| {
        let path = path.to_owned();
        move |source| BackupError::Io { path, source }
    };
    let mut entries = Vec::new();
    for entry in fs::read_dir(dir).map_err(io_err(dir))? {
        entries.push(entry.map_err(io_err(dir))?);
    }
    entries.sort_by_key(std::fs::DirEntry::file_name);

    for entry in entries {
        let path = entry.path();
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| BackupError::NonUtf8Path { path: path.clone() })?;
        let rel = format!("{rel_prefix}/{name}");
        // Does not follow symlinks: a symlinked directory is skipped, not
        // traversed (no cycle risk).
        let file_type = entry.file_type().map_err(io_err(&path))?;
        if file_type.is_dir() {
            walk_dir(&path, &rel, out)?;
        } else if file_type.is_file() {
            out.push(FileSpec { abs: path, rel });
        }
    }
    Ok(())
}

/// Splits a file's mtime into (whole seconds since the Unix epoch,
/// nanosecond part), handling pre-epoch times; platforms that cannot report
/// an mtime record the epoch.
fn mtime_parts(metadata: &fs::Metadata) -> (i64, u32) {
    let Ok(modified) = metadata.modified() else {
        return (0, 0);
    };
    match modified.duration_since(UNIX_EPOCH) {
        Ok(after) => (after.as_secs() as i64, after.subsec_nanos()),
        Err(before) => {
            let d = before.duration();
            let (secs, nanos) = (d.as_secs() as i64, d.subsec_nanos());
            if nanos == 0 {
                (-secs, 0)
            } else {
                // -3.25 s before the epoch = secs -4, nanos 750_000_000.
                (-(secs + 1), 1_000_000_000 - nanos)
            }
        }
    }
}

/// Platform metadata word for the manifest: Unix `st_mode` on Unix,
/// `FILE_ATTRIBUTE_*` bits on Windows (PRD §3.3).
#[cfg(unix)]
fn file_mode(metadata: &fs::Metadata) -> u32 {
    use std::os::unix::fs::MetadataExt as _;
    metadata.mode()
}

/// Platform metadata word for the manifest: Unix `st_mode` on Unix,
/// `FILE_ATTRIBUTE_*` bits on Windows (PRD §3.3).
#[cfg(windows)]
fn file_mode(metadata: &fs::Metadata) -> u32 {
    use std::os::windows::fs::MetadataExt as _;
    metadata.file_attributes()
}

/// Fallback for platforms that are neither Unix nor Windows.
#[cfg(not(any(unix, windows)))]
fn file_mode(_metadata: &fs::Metadata) -> u32 {
    0
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    /// The wire message limit must fit the largest chunk any supported
    /// chunker configuration can emit (16 MiB CDC ceiling), plus the AEAD
    /// overhead and generous slack for protobuf framing — otherwise
    /// `UploadChunks`/`GetChunks` fail exactly on max-size chunks
    /// (regression guard for the tonic 4 MiB default that broke
    /// `--default-chunking`).
    #[test]
    fn grpc_message_limit_fits_largest_chunk_blob() {
        use busyncr_core::chunking::MAX_SIZE_CEILING;
        use busyncr_core::crypto::BLOB_OVERHEAD;
        const FRAMING_SLACK: usize = 64 * 1024;
        const {
            assert!(
                busyncr_proto::MAX_MESSAGE_SIZE >= MAX_SIZE_CEILING + BLOB_OVERHEAD + FRAMING_SLACK,
                "MAX_MESSAGE_SIZE cannot carry a max-size chunk blob plus AEAD overhead and framing"
            );
        }
    }

    #[test]
    fn collect_files_is_sorted_prefixed_and_skips_non_files() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("data");
        fs::create_dir_all(root.join("sub")).unwrap();
        fs::write(root.join("b.txt"), b"b").unwrap();
        fs::write(root.join("a.txt"), b"a").unwrap();
        fs::write(root.join("sub").join("c.txt"), b"c").unwrap();
        #[cfg(unix)]
        std::os::unix::fs::symlink(root.join("a.txt"), root.join("link")).unwrap();

        let specs = collect_files(&[root]).unwrap();
        let rels: Vec<&str> = specs.iter().map(|s| s.rel.as_str()).collect();
        assert_eq!(rels, vec!["data/a.txt", "data/b.txt", "data/sub/c.txt"]);
    }

    #[test]
    fn collect_files_rejects_bad_and_colliding_roots() {
        let dir = tempfile::tempdir().unwrap();
        let missing = dir.path().join("nope");
        assert!(matches!(
            collect_files(&[missing]),
            Err(BackupError::BadRoot { .. })
        ));

        let a = dir.path().join("x").join("same");
        let b = dir.path().join("y").join("same");
        fs::create_dir_all(&a).unwrap();
        fs::create_dir_all(&b).unwrap();
        assert!(matches!(
            collect_files(&[a, b]),
            Err(BackupError::DuplicateRootName { name }) if name == "same"
        ));
    }

    #[test]
    fn mtime_parts_handles_pre_epoch() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("old.txt");
        fs::write(&path, b"x").unwrap();
        let file = fs::File::options().write(true).open(&path).unwrap();
        file.set_modified(UNIX_EPOCH - Duration::new(3, 250_000_000))
            .unwrap();
        drop(file);
        let metadata = fs::metadata(&path).unwrap();
        let (secs, nanos) = mtime_parts(&metadata);
        // -3.25 s = secs -4 + 0.75 s of nanos (filesystems may round the
        // fractional part; the whole-second floor must hold).
        assert!(
            secs == -4 || (secs == -3 && nanos == 0),
            "got {secs}/{nanos}"
        );
    }
}
