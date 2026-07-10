//! Snapshot manifests: the versioned record of one backup run.
//!
//! A [`Manifest`] lists every file captured in a snapshot — relative path,
//! size, mtime, unix mode / windows attributes — together with the ordered
//! [`ChunkId`]s that reassemble the file's content (PRD §3.3).
//!
//! # Canonical wire format
//!
//! Manifests serialize to a fixed-width little-endian layout (the ULID is
//! its standard 16-byte big-endian binary form) so that the `bench-chunking`
//! metadata projections (PRD §3.7) are exact arithmetic over this real
//! layout, not estimates:
//!
//! * header — [`MANIFEST_HEADER_BYTES`]: snapshot ULID (16) +
//!   `created_at` seconds (i64, 8) + file count (u32, 4);
//! * per file — [`MANIFEST_FILE_FIXED_BYTES`] fixed bytes: path length
//!   prefix (u32, 4) + file size (u64, 8) + mtime seconds (i64, 8) + mtime
//!   nanos (u32, 4) + unix mode / windows attrs (u32, 4) + chunk count
//!   (u32, 4) — plus the variable parts: the UTF-8 path bytes (after the
//!   length prefix) and [`ChunkId::LEN`] bytes per chunk ID.
//!
//! [`Manifest::encoded_len`] computes the same arithmetic without
//! serializing, and a test pins `encode().len()` to it.

use serde::{Deserialize, Serialize};
use ulid::Ulid;

use crate::chunking::ChunkId;

/// Fixed manifest header bytes: snapshot ULID (16) + created-at seconds
/// (i64, 8) + file count (u32, 4).
///
/// Single source of truth shared with the bench projections
/// (re-exported as `bench::MANIFEST_HEADER_BYTES`).
pub const MANIFEST_HEADER_BYTES: u64 = 16 + 8 + 4;

/// Fixed per-file metadata bytes in a manifest entry: path length prefix
/// (u32, 4) + file size (u64, 8) + mtime seconds (i64, 8) + mtime nanos
/// (u32, 4) + unix mode / windows attrs (u32, 4) + chunk count (u32, 4).
///
/// The variable parts — path bytes and [`ChunkId::LEN`] bytes per chunk
/// ID — are added per file. Single source of truth shared with the bench
/// projections (re-exported as `bench::MANIFEST_FILE_FIXED_BYTES`).
pub const MANIFEST_FILE_FIXED_BYTES: u64 = 4 + 8 + 8 + 4 + 4 + 4;

/// Errors produced when encoding or decoding a [`Manifest`].
#[derive(Debug, thiserror::Error)]
pub enum ManifestError {
    /// A count or length exceeds what the wire format can represent.
    #[error("{what} ({value}) exceeds the wire format limit of {limit}")]
    TooLarge {
        /// What overflowed (e.g. "file count", "path length").
        what: &'static str,
        /// The offending value.
        value: u64,
        /// The maximum the wire format can carry.
        limit: u64,
    },
    /// The input ended before the structure was complete.
    #[error("truncated manifest: needed {needed} more bytes for {what}")]
    Truncated {
        /// What was being read when the input ran out.
        what: &'static str,
        /// How many further bytes were required.
        needed: usize,
    },
    /// Bytes remained after the last declared file entry.
    #[error("trailing garbage: {0} bytes after the final file entry")]
    TrailingBytes(usize),
    /// A path field did not decode as UTF-8.
    #[error("file path at entry {index} is not valid UTF-8")]
    InvalidPath {
        /// Zero-based index of the offending file entry.
        index: usize,
        /// The underlying UTF-8 error.
        #[source]
        source: std::str::Utf8Error,
    },
}

/// One file captured in a snapshot.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileEntry {
    /// Path relative to the backup root, with `/` separators on every
    /// platform.
    pub path: String,
    /// File size in bytes (must equal the sum of the chunk lengths).
    pub size: u64,
    /// Modification time: whole seconds since the Unix epoch.
    pub mtime_secs: i64,
    /// Modification time: nanosecond part in `0..1_000_000_000`.
    pub mtime_nanos: u32,
    /// Unix `st_mode` on Unix; `FILE_ATTRIBUTE_*` bits on Windows.
    pub mode: u32,
    /// The file's content as an ordered list of chunk IDs.
    pub chunks: Vec<ChunkId>,
}

/// A snapshot manifest: files → ordered chunk IDs + metadata (PRD §3.3).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Manifest {
    /// Unique, lexicographically time-sortable snapshot identity.
    pub snapshot_id: Ulid,
    /// Snapshot creation time: whole seconds since the Unix epoch
    /// (injected by the caller — core never reads the wall clock).
    pub created_at: i64,
    /// The files captured in this snapshot.
    pub files: Vec<FileEntry>,
}

/// Reads a fixed-size array from the front of `input`, advancing it.
fn take<'a, const N: usize>(
    input: &mut &'a [u8],
    what: &'static str,
) -> Result<&'a [u8; N], ManifestError> {
    if input.len() < N {
        return Err(ManifestError::Truncated {
            what,
            needed: N - input.len(),
        });
    }
    let (head, rest) = input.split_at(N);
    *input = rest;
    // Length was checked above, so the conversion cannot fail.
    head.try_into()
        .map_err(|_| ManifestError::Truncated { what, needed: N })
}

/// Reads a variable-size prefix from the front of `input`, advancing it.
fn take_slice<'a>(
    input: &mut &'a [u8],
    len: usize,
    what: &'static str,
) -> Result<&'a [u8], ManifestError> {
    if input.len() < len {
        return Err(ManifestError::Truncated {
            what,
            needed: len - input.len(),
        });
    }
    let (head, rest) = input.split_at(len);
    *input = rest;
    Ok(head)
}

/// Checks that `value` fits in a `u32` wire field.
fn fit_u32(value: u64, what: &'static str) -> Result<u32, ManifestError> {
    u32::try_from(value).map_err(|_| ManifestError::TooLarge {
        what,
        value,
        limit: u64::from(u32::MAX),
    })
}

impl Manifest {
    /// Exact size in bytes of [`Self::encode`]'s output, computed without
    /// serializing: [`MANIFEST_HEADER_BYTES`] + Σ over files
    /// ([`MANIFEST_FILE_FIXED_BYTES`] + path bytes + [`ChunkId::LEN`] ×
    /// chunk count). This is the same arithmetic the bench projections use.
    #[must_use]
    pub fn encoded_len(&self) -> u64 {
        let mut total = MANIFEST_HEADER_BYTES;
        for file in &self.files {
            total += MANIFEST_FILE_FIXED_BYTES
                + file.path.len() as u64
                + (ChunkId::LEN as u64) * file.chunks.len() as u64;
        }
        total
    }

    /// Iterates over every chunk reference in manifest order (duplicates
    /// included) — the daemon's refcounting walks exactly this sequence.
    pub fn chunk_refs(&self) -> impl Iterator<Item = ChunkId> + '_ {
        self.files.iter().flat_map(|f| f.chunks.iter().copied())
    }

    /// Serializes to the canonical wire format described in the module docs.
    ///
    /// # Errors
    ///
    /// Returns [`ManifestError::TooLarge`] if the file count, a path length,
    /// or a per-file chunk count exceeds `u32::MAX`.
    pub fn encode(&self) -> Result<Vec<u8>, ManifestError> {
        let file_count = fit_u32(self.files.len() as u64, "file count")?;
        let capacity = usize::try_from(self.encoded_len()).unwrap_or(0);
        let mut out = Vec::with_capacity(capacity);
        out.extend_from_slice(&self.snapshot_id.to_bytes());
        out.extend_from_slice(&self.created_at.to_le_bytes());
        out.extend_from_slice(&file_count.to_le_bytes());
        for file in &self.files {
            let path_len = fit_u32(file.path.len() as u64, "path length")?;
            let chunk_count = fit_u32(file.chunks.len() as u64, "chunk count")?;
            out.extend_from_slice(&path_len.to_le_bytes());
            out.extend_from_slice(file.path.as_bytes());
            out.extend_from_slice(&file.size.to_le_bytes());
            out.extend_from_slice(&file.mtime_secs.to_le_bytes());
            out.extend_from_slice(&file.mtime_nanos.to_le_bytes());
            out.extend_from_slice(&file.mode.to_le_bytes());
            out.extend_from_slice(&chunk_count.to_le_bytes());
            for chunk in &file.chunks {
                out.extend_from_slice(chunk.as_bytes());
            }
        }
        Ok(out)
    }

    /// Parses the canonical wire format produced by [`Self::encode`].
    ///
    /// Strict: truncated input, non-UTF-8 paths, and trailing bytes after
    /// the final file entry are all rejected.
    ///
    /// # Errors
    ///
    /// Returns [`ManifestError::Truncated`], [`ManifestError::InvalidPath`],
    /// or [`ManifestError::TrailingBytes`] as described above.
    pub fn decode(bytes: &[u8]) -> Result<Self, ManifestError> {
        let mut input = bytes;
        let ulid_bytes = take::<16>(&mut input, "snapshot id")?;
        let snapshot_id = Ulid::from_bytes(*ulid_bytes);
        let created_at = i64::from_le_bytes(*take::<8>(&mut input, "created_at")?);
        let file_count = u32::from_le_bytes(*take::<4>(&mut input, "file count")?);

        let mut files = Vec::new();
        for index in 0..file_count as usize {
            let path_len = u32::from_le_bytes(*take::<4>(&mut input, "path length")?) as usize;
            let path_bytes = take_slice(&mut input, path_len, "path bytes")?;
            let path = std::str::from_utf8(path_bytes)
                .map_err(|source| ManifestError::InvalidPath { index, source })?
                .to_owned();
            let size = u64::from_le_bytes(*take::<8>(&mut input, "file size")?);
            let mtime_secs = i64::from_le_bytes(*take::<8>(&mut input, "mtime seconds")?);
            let mtime_nanos = u32::from_le_bytes(*take::<4>(&mut input, "mtime nanos")?);
            let mode = u32::from_le_bytes(*take::<4>(&mut input, "mode")?);
            let chunk_count = u32::from_le_bytes(*take::<4>(&mut input, "chunk count")?) as usize;
            let mut chunks = Vec::new();
            for _ in 0..chunk_count {
                let id = take::<{ ChunkId::LEN }>(&mut input, "chunk id")?;
                chunks.push(ChunkId::from_bytes(*id));
            }
            files.push(FileEntry {
                path,
                size,
                mtime_secs,
                mtime_nanos,
                mode,
                chunks,
            });
        }
        if !input.is_empty() {
            return Err(ManifestError::TrailingBytes(input.len()));
        }
        Ok(Self {
            snapshot_id,
            created_at,
            files,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_manifest() -> Manifest {
        Manifest {
            snapshot_id: Ulid::from_parts(1_700_000_000_000, 42),
            created_at: 1_700_000_000,
            files: vec![
                FileEntry {
                    path: "docs/report.txt".into(),
                    size: 70_000,
                    mtime_secs: 1_699_999_000,
                    mtime_nanos: 123_456_789,
                    mode: 0o100644,
                    chunks: vec![ChunkId::of(b"alpha"), ChunkId::of(b"beta")],
                },
                FileEntry {
                    path: "img/€.png".into(), // multi-byte UTF-8 in the path
                    size: 0,
                    mtime_secs: -5, // pre-epoch mtimes must survive
                    mtime_nanos: 0,
                    mode: 0x20, // FILE_ATTRIBUTE_ARCHIVE-style bits
                    chunks: vec![],
                },
            ],
        }
    }

    #[test]
    fn encode_decode_roundtrip() {
        let manifest = sample_manifest();
        let bytes = manifest.encode().unwrap();
        let decoded = Manifest::decode(&bytes).unwrap();
        assert_eq!(decoded, manifest);
    }

    #[test]
    fn empty_manifest_roundtrip() {
        let manifest = Manifest {
            snapshot_id: Ulid::from_parts(0, 0),
            created_at: 0,
            files: vec![],
        };
        let bytes = manifest.encode().unwrap();
        assert_eq!(bytes.len() as u64, MANIFEST_HEADER_BYTES);
        assert_eq!(Manifest::decode(&bytes).unwrap(), manifest);
    }

    #[test]
    fn encoded_len_matches_bench_projection_arithmetic() {
        // The bench-chunking tool projects manifest size as
        // header + Σ (fixed + path bytes + 32 × chunks); the real encoder
        // must produce exactly that many bytes (PRD §3.7 "exact arithmetic").
        let manifest = sample_manifest();
        let expected: u64 = MANIFEST_HEADER_BYTES
            + manifest
                .files
                .iter()
                .map(|f| {
                    MANIFEST_FILE_FIXED_BYTES + f.path.len() as u64 + 32 * f.chunks.len() as u64
                })
                .sum::<u64>();
        assert_eq!(manifest.encoded_len(), expected);
        assert_eq!(manifest.encode().unwrap().len() as u64, expected);
        // And the constants themselves stay pinned to the documented layout.
        assert_eq!(MANIFEST_HEADER_BYTES, 28);
        assert_eq!(MANIFEST_FILE_FIXED_BYTES, 32);
    }

    #[test]
    fn bench_reexports_are_the_same_constants() {
        assert_eq!(crate::bench::MANIFEST_HEADER_BYTES, MANIFEST_HEADER_BYTES);
        assert_eq!(
            crate::bench::MANIFEST_FILE_FIXED_BYTES,
            MANIFEST_FILE_FIXED_BYTES
        );
    }

    #[test]
    fn decode_rejects_truncation_at_every_length() {
        let bytes = sample_manifest().encode().unwrap();
        for cut in 0..bytes.len() {
            let err = Manifest::decode(&bytes[..cut]).unwrap_err();
            assert!(
                matches!(err, ManifestError::Truncated { .. }),
                "cut at {cut} gave {err:?}, expected Truncated"
            );
        }
    }

    #[test]
    fn decode_rejects_trailing_bytes() {
        let mut bytes = sample_manifest().encode().unwrap();
        bytes.push(0);
        assert!(matches!(
            Manifest::decode(&bytes),
            Err(ManifestError::TrailingBytes(1))
        ));
    }

    #[test]
    fn decode_rejects_non_utf8_path() {
        let mut manifest = sample_manifest();
        manifest.files.truncate(1);
        manifest.files[0].path = "abcd".into();
        let mut bytes = manifest.encode().unwrap();
        // Corrupt the first path byte (header is 28 bytes, then 4 bytes of
        // path length, then the path itself).
        bytes[32] = 0xFF;
        assert!(matches!(
            Manifest::decode(&bytes),
            Err(ManifestError::InvalidPath { index: 0, .. })
        ));
    }

    #[test]
    fn chunk_refs_walks_manifest_order_with_duplicates() {
        let dup = ChunkId::of(b"shared");
        let manifest = Manifest {
            snapshot_id: Ulid::from_parts(1, 1),
            created_at: 10,
            files: vec![
                FileEntry {
                    path: "a".into(),
                    size: 1,
                    mtime_secs: 0,
                    mtime_nanos: 0,
                    mode: 0,
                    chunks: vec![dup, ChunkId::of(b"only-a")],
                },
                FileEntry {
                    path: "b".into(),
                    size: 1,
                    mtime_secs: 0,
                    mtime_nanos: 0,
                    mode: 0,
                    chunks: vec![dup],
                },
            ],
        };
        let refs: Vec<ChunkId> = manifest.chunk_refs().collect();
        assert_eq!(refs, vec![dup, ChunkId::of(b"only-a"), dup]);
    }

    #[test]
    fn serde_roundtrip_preserves_manifest() {
        // The wire format is canonical, but the types stay serde-capable
        // for tooling; a postcard round-trip must be lossless.
        let manifest = sample_manifest();
        let bytes = postcard::to_allocvec(&manifest).unwrap();
        let back: Manifest = postcard::from_bytes(&bytes).unwrap();
        assert_eq!(back, manifest);
    }
}
