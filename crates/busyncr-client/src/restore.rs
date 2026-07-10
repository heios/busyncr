//! The restore pipeline (FR4, FR9; PRD §3.3/§3.4).
//!
//! One [`run_restore`] call = one snapshot reassembled to an empty directory:
//!
//! 1. `GetManifest` the requested snapshot, decrypt it under the local data
//!    key (AAD = snapshot ULID) and decode it.
//! 2. For every file in manifest order, `GetChunks` its ordered chunk-ID list
//!    (duplicates included) and stream the blobs back in that exact order.
//! 3. Decrypt each blob (AAD = chunk ID — a blob only opens under the ID it
//!    was uploaded for), then decode the codec-framed plaintext
//!    ([`compression::decode_chunk`], FR-C1 §2 — the codec byte was
//!    encrypted together with the payload, so decompression happens only
//!    after decrypt+verify of the AEAD tag) and recompute the decompressed
//!    plaintext's [`ChunkId`] with the backup set's chunk-ID key (keyed
//!    BLAKE3, FR-K1; identity is always over the *uncompressed* bytes per
//!    C1.3), refusing any mismatch (FR9: the client is the only party that
//!    can verify a chunk's *plaintext* hash, since the daemon is
//!    zero-knowledge; see `busyncr-daemon::store` module docs). An unknown
//!    codec byte or a broken compressed frame is the same class of integrity
//!    failure as a hash mismatch — a typed error naming the chunk, never
//!    silent output. Corruption the daemon detects on its own stored bytes
//!    surfaces as a `DATA_LOSS` RPC status naming the chunk, which
//!    propagates here unmodified.
//! 4. Write the reassembled bytes and restore mtime/permissions from the
//!    manifest (FR4: byte-exact tree including metadata).
//!
//! The target directory must be empty (created if it does not yet exist) —
//! restore never overwrites or merges into existing content.

// `tonic::Status` is 176 bytes and rides inside `RestoreError`; tonic returns
// it by value everywhere, so boxing at every conversion would outweigh the
// win (same rationale as the backup/enroll modules).
#![allow(clippy::result_large_err)]

use std::fs;
use std::io::Write as _;
use std::path::{Path, PathBuf};

use busyncr_core::chunking::{ChunkId, ChunkIdKey};
use busyncr_core::compression::{self, CompressionError};
use busyncr_core::crypto::{self, CryptoError};
use busyncr_core::manifest::{FileEntry, Manifest, ManifestError};
use busyncr_proto::v1::busyncr_client::BusyncrClient;
use busyncr_proto::v1::{GetChunksRequest, GetManifestRequest};
use filetime::FileTime;
use tonic::transport::Channel;
use ulid::Ulid;

use crate::enroll::{self, EnrollError};

/// Errors from the restore pipeline.
#[derive(Debug, thiserror::Error)]
pub enum RestoreError {
    /// Filesystem access under the restore target failed.
    #[error("restore target I/O failed at {path}")]
    Io {
        /// Path being read or written.
        path: PathBuf,
        /// Underlying I/O error.
        #[source]
        source: std::io::Error,
    },

    /// The target directory exists and already has content.
    #[error("restore target {path} is not an empty directory")]
    TargetNotEmpty {
        /// The offending target directory.
        path: PathBuf,
    },

    /// A manifest path is absolute, empty, or escapes the target directory
    /// via `..` — refused rather than risk writing outside the restore tree.
    #[error("manifest path {path:?} is not a safe relative path")]
    UnsafePath {
        /// The offending manifest path.
        path: String,
    },

    /// Loading local identity/key state or connecting to the daemon failed.
    #[error(transparent)]
    Enroll(#[from] EnrollError),

    /// The daemon refused an RPC, or reported corruption on a stored chunk
    /// (`DATA_LOSS`, naming the chunk — FR9).
    #[error("daemon refused the restore RPC: {0}")]
    Rpc(#[from] tonic::Status),

    /// The daemon's response violated the protocol contract.
    #[error("daemon returned an unusable response: {0}")]
    BadResponse(&'static str),

    /// Manifest decoding failed.
    #[error("manifest decoding failed")]
    Manifest(#[from] ManifestError),

    /// Client-side decryption failed (tampered ciphertext, wrong key, or
    /// mismatched associated data).
    #[error("chunk or manifest decryption failed")]
    Crypto(#[from] CryptoError),

    /// A chunk decrypted cleanly but its plaintext does not hash to the
    /// chunk ID the manifest declared (FR9: end-to-end plaintext
    /// verification, the one check only the client can perform).
    #[error("chunk {chunk} failed content-address verification: plaintext hashes to {actual}")]
    ChunkIdMismatch {
        /// The chunk ID the manifest declared.
        chunk: ChunkId,
        /// What the decrypted plaintext actually hashes to.
        actual: ChunkId,
    },

    /// A chunk decrypted cleanly but its framed plaintext failed to decode:
    /// an unknown codec byte or a broken compressed payload (FR-C1 §2,
    /// FR9-class integrity failure — never silently reassembled).
    #[error("chunk {chunk} failed to decode: {source}")]
    CodecDecode {
        /// The chunk ID whose decode failed.
        chunk: ChunkId,
        /// The underlying codec framing/decompression error.
        #[source]
        source: CompressionError,
    },

    /// A file's reassembled byte count does not match the manifest's
    /// declared size.
    #[error("size mismatch reassembling {path}: manifest declares {expected} bytes, got {actual}")]
    SizeMismatch {
        /// The offending manifest path.
        path: String,
        /// Size the manifest declared.
        expected: u64,
        /// Size actually reassembled.
        actual: u64,
    },
}

/// Everything [`run_restore`] needs.
#[derive(Debug)]
pub struct RestoreRequest<'a> {
    /// Daemon endpoint, e.g. `https://backup-server:47820`.
    pub daemon_url: &'a str,
    /// Client state directory holding the enrolled identity and data key.
    pub state_dir: &'a Path,
    /// The snapshot to restore.
    pub snapshot_id: Ulid,
    /// Target directory. Created if it does not exist; must be empty either
    /// way (FR4: "restore ... to an empty directory").
    pub target_dir: &'a Path,
}

/// What one restore run did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RestoreReport {
    /// The snapshot this run restored.
    pub snapshot_id: Ulid,
    /// Files written.
    pub files: u64,
    /// Total plaintext bytes written across all files.
    pub bytes: u64,
    /// Chunk blobs fetched and verified (duplicates counted once per file
    /// occurrence, matching the manifest's chunk-reference count).
    pub chunks_fetched: u64,
}

/// Runs one restore: fetch the manifest, decrypt it, then for every file
/// fetch/decrypt/verify its chunks in order and reassemble it byte-exact
/// with metadata (FR4). Any stored corruption on the daemon or plaintext
/// content-address mismatch aborts with a typed error naming the chunk
/// (FR9) — nothing is silently written wrong.
///
/// # Errors
///
/// Any [`RestoreError`].
pub async fn run_restore(req: &RestoreRequest<'_>) -> Result<RestoreReport, RestoreError> {
    ensure_empty_target(req.target_dir)?;

    let key = enroll::load_data_key(req.state_dir)?;
    let chunk_id_key = enroll::load_chunk_id_key(req.state_dir)?;
    let mut client = enroll::connect_authenticated(req.daemon_url, req.state_dir).await?;

    let manifest_blob = client
        .get_manifest(GetManifestRequest {
            snapshot_id: req.snapshot_id.to_bytes().to_vec(),
        })
        .await?
        .into_inner()
        .manifest;
    let manifest_plaintext = crypto::decrypt_manifest(&key, req.snapshot_id, &manifest_blob)?;
    let manifest = Manifest::decode(&manifest_plaintext)?;

    let mut report = RestoreReport {
        snapshot_id: req.snapshot_id,
        files: 0,
        bytes: 0,
        chunks_fetched: 0,
    };

    for file in &manifest.files {
        let written = restore_file(
            &mut client,
            &key,
            &chunk_id_key,
            req.target_dir,
            file,
            &mut report,
        )
        .await?;
        if written != file.size {
            return Err(RestoreError::SizeMismatch {
                path: file.path.clone(),
                expected: file.size,
                actual: written,
            });
        }
        report.files += 1;
        report.bytes += written;
    }

    Ok(report)
}

/// Reassembles one file: fetches its ordered chunk list, verifies and
/// decrypts each blob, writes the plaintext, and restores mtime/permissions.
/// Returns the number of plaintext bytes written.
async fn restore_file(
    client: &mut BusyncrClient<Channel>,
    key: &busyncr_core::crypto::DataKey,
    chunk_id_key: &ChunkIdKey,
    target_dir: &Path,
    file: &FileEntry,
    report: &mut RestoreReport,
) -> Result<u64, RestoreError> {
    let rel = sanitize_path(&file.path)?;
    let out_path = target_dir.join(&rel);
    if let Some(parent) = out_path.parent() {
        fs::create_dir_all(parent).map_err(|source| RestoreError::Io {
            path: parent.to_owned(),
            source,
        })?;
    }

    let mut out = fs::File::create(&out_path).map_err(|source| RestoreError::Io {
        path: out_path.clone(),
        source,
    })?;

    let mut written = 0u64;
    if !file.chunks.is_empty() {
        let wire_ids: Vec<Vec<u8>> = file
            .chunks
            .iter()
            .map(|id| id.as_bytes().to_vec())
            .collect();
        let mut stream = client
            .get_chunks(GetChunksRequest {
                chunk_ids: wire_ids,
            })
            .await?
            .into_inner();

        for expected_id in &file.chunks {
            let blob = stream.message().await?.ok_or(RestoreError::BadResponse(
                "GetChunks stream ended before every requested chunk arrived",
            ))?;
            let got_id = parse_chunk_id(&blob.chunk_id)?;
            if got_id != *expected_id {
                return Err(RestoreError::BadResponse(
                    "GetChunks streamed a chunk out of the requested order",
                ));
            }
            let framed = crypto::decrypt_chunk(key, expected_id, &blob.data)?;
            let plaintext =
                compression::decode_chunk(&framed).map_err(|source| RestoreError::CodecDecode {
                    chunk: *expected_id,
                    source,
                })?;
            let actual_id = ChunkId::keyed(chunk_id_key, &plaintext);
            if actual_id != *expected_id {
                return Err(RestoreError::ChunkIdMismatch {
                    chunk: *expected_id,
                    actual: actual_id,
                });
            }
            out.write_all(&plaintext)
                .map_err(|source| RestoreError::Io {
                    path: out_path.clone(),
                    source,
                })?;
            written += plaintext.len() as u64;
            report.chunks_fetched += 1;
        }
        if stream.message().await?.is_some() {
            return Err(RestoreError::BadResponse(
                "GetChunks streamed more chunks than were requested",
            ));
        }
    }
    out.sync_all().map_err(|source| RestoreError::Io {
        path: out_path.clone(),
        source,
    })?;
    drop(out);

    let mtime = FileTime::from_unix_time(file.mtime_secs, file.mtime_nanos);
    filetime::set_file_mtime(&out_path, mtime).map_err(|source| RestoreError::Io {
        path: out_path.clone(),
        source,
    })?;
    set_mode(&out_path, file.mode)?;

    Ok(written)
}

/// Ensures `dir` exists and is empty, creating it if absent (FR4: restore
/// targets an empty directory).
fn ensure_empty_target(dir: &Path) -> Result<(), RestoreError> {
    match fs::metadata(dir) {
        Ok(meta) => {
            if !meta.is_dir() {
                return Err(RestoreError::TargetNotEmpty {
                    path: dir.to_owned(),
                });
            }
            let mut entries = fs::read_dir(dir).map_err(|source| RestoreError::Io {
                path: dir.to_owned(),
                source,
            })?;
            if entries.next().is_some() {
                return Err(RestoreError::TargetNotEmpty {
                    path: dir.to_owned(),
                });
            }
            Ok(())
        }
        Err(source) if source.kind() == std::io::ErrorKind::NotFound => fs::create_dir_all(dir)
            .map_err(|source| RestoreError::Io {
                path: dir.to_owned(),
                source,
            }),
        Err(source) => Err(RestoreError::Io {
            path: dir.to_owned(),
            source,
        }),
    }
}

/// Validates a manifest path (`/`-separated, PRD §3.3) and turns it into a
/// relative [`PathBuf`] safe to join under the restore target: rejects
/// absolute paths, empty components, and `.`/`..` segments.
fn sanitize_path(path: &str) -> Result<PathBuf, RestoreError> {
    let mut rel = PathBuf::new();
    let mut any = false;
    for part in path.split('/') {
        match part {
            "" | "." | ".." => {
                return Err(RestoreError::UnsafePath {
                    path: path.to_owned(),
                })
            }
            _ => {
                rel.push(part);
                any = true;
            }
        }
    }
    if !any {
        return Err(RestoreError::UnsafePath {
            path: path.to_owned(),
        });
    }
    Ok(rel)
}

/// Parses a wire chunk ID from a `GetChunks` response blob.
fn parse_chunk_id(bytes: &[u8]) -> Result<ChunkId, RestoreError> {
    let arr: [u8; ChunkId::LEN] = bytes
        .try_into()
        .map_err(|_| RestoreError::BadResponse("malformed chunk ID in GetChunks reply"))?;
    Ok(ChunkId::from_bytes(arr))
}

/// Restores the platform metadata word: Unix `st_mode` permission bits on
/// Unix, the `FILE_ATTRIBUTE_READONLY` bit on Windows (the only attribute
/// std can restore without a non-palette crate).
#[cfg(unix)]
fn set_mode(path: &Path, mode: u32) -> Result<(), RestoreError> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(mode)).map_err(|source| RestoreError::Io {
        path: path.to_owned(),
        source,
    })
}

/// Restores the platform metadata word: Unix `st_mode` permission bits on
/// Unix, the `FILE_ATTRIBUTE_READONLY` bit on Windows (the only attribute
/// std can restore without a non-palette crate).
#[cfg(windows)]
fn set_mode(path: &Path, mode: u32) -> Result<(), RestoreError> {
    const FILE_ATTRIBUTE_READONLY: u32 = 0x1;
    let io_err = |source| RestoreError::Io {
        path: path.to_owned(),
        source,
    };
    let mut perms = fs::metadata(path).map_err(io_err)?.permissions();
    perms.set_readonly(mode & FILE_ATTRIBUTE_READONLY != 0);
    fs::set_permissions(path, perms).map_err(io_err)
}

/// Fallback for platforms that are neither Unix nor Windows.
#[cfg(not(any(unix, windows)))]
fn set_mode(_path: &Path, _mode: u32) -> Result<(), RestoreError> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sanitize_path_accepts_ordinary_relative_paths() {
        assert_eq!(
            sanitize_path("data/sub/file.txt").unwrap(),
            PathBuf::from("data").join("sub").join("file.txt")
        );
    }

    #[test]
    fn sanitize_path_rejects_traversal_and_absolute() {
        assert!(matches!(
            sanitize_path("../etc/passwd"),
            Err(RestoreError::UnsafePath { .. })
        ));
        assert!(matches!(
            sanitize_path("/etc/passwd"),
            Err(RestoreError::UnsafePath { .. })
        ));
        assert!(matches!(
            sanitize_path("data/../../escape"),
            Err(RestoreError::UnsafePath { .. })
        ));
        assert!(matches!(
            sanitize_path(""),
            Err(RestoreError::UnsafePath { .. })
        ));
        assert!(matches!(
            sanitize_path("data//double"),
            Err(RestoreError::UnsafePath { .. })
        ));
    }

    #[test]
    fn ensure_empty_target_creates_missing_and_accepts_empty() {
        let dir = tempfile::tempdir().unwrap();
        let fresh = dir.path().join("fresh");
        assert!(!fresh.exists());
        ensure_empty_target(&fresh).unwrap();
        assert!(fresh.is_dir());
        // Already-empty existing directory is fine too.
        ensure_empty_target(&fresh).unwrap();
    }

    #[test]
    fn ensure_empty_target_refuses_nonempty_and_files() {
        let dir = tempfile::tempdir().unwrap();
        let nonempty = dir.path().join("nonempty");
        std::fs::create_dir_all(&nonempty).unwrap();
        std::fs::write(nonempty.join("x"), b"y").unwrap();
        assert!(matches!(
            ensure_empty_target(&nonempty),
            Err(RestoreError::TargetNotEmpty { .. })
        ));

        let file_path = dir.path().join("a_file");
        std::fs::write(&file_path, b"x").unwrap();
        assert!(matches!(
            ensure_empty_target(&file_path),
            Err(RestoreError::TargetNotEmpty { .. })
        ));
    }
}
