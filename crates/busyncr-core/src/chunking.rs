//! Content-defined chunking (CDC) engine.
//!
//! Wraps the FastCDC (2020) algorithm with a validated configuration
//! ([`ChunkerConfig`]), streaming support over any [`Read`] source without
//! loading whole files into memory ([`chunk_reader`]), and an in-memory path
//! for already-buffered data ([`chunk_bytes`]).
//!
//! Every chunk is identified by [`ChunkId`]: the BLAKE3 hash of the chunk's
//! *plaintext* content, computed client-side before any encryption. Identical
//! content therefore yields identical IDs across files, snapshots, and time,
//! which is the foundation of BusyNCR's deduplication (PRD §3.3).

use std::fmt;
use std::io::Read;
use std::str::FromStr;

use fastcdc::v2020;

/// Smallest permitted `min_size`, inherited from the FastCDC v2020 layer.
pub const MIN_SIZE_FLOOR: usize = v2020::MINIMUM_MIN;
/// Largest permitted `min_size`, inherited from the FastCDC v2020 layer.
pub const MIN_SIZE_CEILING: usize = v2020::MINIMUM_MAX;
/// Smallest permitted `target_size`, inherited from the FastCDC v2020 layer.
pub const TARGET_SIZE_FLOOR: usize = v2020::AVERAGE_MIN;
/// Largest permitted `target_size`, inherited from the FastCDC v2020 layer.
pub const TARGET_SIZE_CEILING: usize = v2020::AVERAGE_MAX;
/// Smallest permitted `max_size`, inherited from the FastCDC v2020 layer.
pub const MAX_SIZE_FLOOR: usize = v2020::MAXIMUM_MIN;
/// Largest permitted `max_size`, inherited from the FastCDC v2020 layer.
pub const MAX_SIZE_CEILING: usize = v2020::MAXIMUM_MAX;

/// Errors produced by the chunking engine.
#[derive(Debug, thiserror::Error)]
pub enum ChunkingError {
    /// The requested min/target/max sizes are outside the supported ranges
    /// or not ordered `min <= target <= max`.
    #[error("invalid chunker configuration: {0}")]
    InvalidConfig(String),
    /// The underlying reader failed while streaming.
    #[error("I/O error while chunking")]
    Io(#[from] std::io::Error),
    /// The FastCDC layer reported an unexpected internal error.
    #[error("internal chunker error: {0}")]
    Internal(String),
}

/// Error returned when parsing a [`ChunkId`] from its hex representation.
#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub enum ChunkIdParseError {
    /// The string was not exactly 64 characters long.
    #[error("chunk id must be exactly 64 hex characters, got {0}")]
    BadLength(usize),
    /// The string contained a non-hex character.
    #[error("chunk id contains non-hex character {0:?}")]
    BadChar(char),
}

/// Identity of a chunk: the BLAKE3 hash of its plaintext content.
///
/// Computed client-side before encryption, so equal plaintext always maps to
/// the same ID regardless of file, snapshot, or encryption nonce (PRD §3.3).
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ChunkId([u8; 32]);

impl ChunkId {
    /// Number of raw bytes in a chunk ID.
    pub const LEN: usize = 32;

    /// Computes the chunk ID of the given plaintext content.
    #[must_use]
    pub fn of(content: &[u8]) -> Self {
        Self(*blake3::hash(content).as_bytes())
    }

    /// Wraps raw hash bytes as a chunk ID.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Returns the raw hash bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Display for ChunkId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in self.0 {
            write!(f, "{byte:02x}")?;
        }
        Ok(())
    }
}

impl fmt::Debug for ChunkId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ChunkId({self})")
    }
}

impl FromStr for ChunkId {
    type Err = ChunkIdParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.chars().count() != 64 {
            return Err(ChunkIdParseError::BadLength(s.chars().count()));
        }
        let mut bytes = [0u8; 32];
        let mut chars = s.chars();
        for byte in &mut bytes {
            let mut value = 0u8;
            for _ in 0..2 {
                // Length was checked above, so both draws succeed.
                let c = chars.next().ok_or(ChunkIdParseError::BadLength(64))?;
                let digit = c.to_digit(16).ok_or(ChunkIdParseError::BadChar(c))? as u8;
                value = (value << 4) | digit;
            }
            *byte = value;
        }
        Ok(Self(bytes))
    }
}

/// Validated min/target/max sizes for the chunker.
///
/// `target_size` is the average chunk size the cut-point selection aims for;
/// `min_size`/`max_size` are hard bounds on emitted chunk lengths (the final
/// chunk of a stream may be shorter than `min_size`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChunkerConfig {
    min_size: usize,
    target_size: usize,
    max_size: usize,
}

impl ChunkerConfig {
    /// Default target chunk size (1 MiB), per PRD §3.7's fallback default.
    pub const DEFAULT_TARGET_SIZE: usize = 1024 * 1024;

    /// Builds a config from a target size using the default ratios
    /// `min = target / 4`, `max = target * 4` (SLICES.md S1).
    pub fn with_target(target_size: usize) -> Result<Self, ChunkingError> {
        Self::new(target_size / 4, target_size, target_size.saturating_mul(4))
    }

    /// Builds a config from explicit min/target/max sizes.
    ///
    /// # Errors
    ///
    /// Returns [`ChunkingError::InvalidConfig`] unless
    /// `min_size <= target_size <= max_size` and each value lies within the
    /// FastCDC-supported range ([`MIN_SIZE_FLOOR`]..=[`MAX_SIZE_CEILING`] and
    /// friends).
    pub fn new(
        min_size: usize,
        target_size: usize,
        max_size: usize,
    ) -> Result<Self, ChunkingError> {
        if !(MIN_SIZE_FLOOR..=MIN_SIZE_CEILING).contains(&min_size) {
            return Err(ChunkingError::InvalidConfig(format!(
                "min_size {min_size} outside supported range \
                 {MIN_SIZE_FLOOR}..={MIN_SIZE_CEILING}"
            )));
        }
        if !(TARGET_SIZE_FLOOR..=TARGET_SIZE_CEILING).contains(&target_size) {
            return Err(ChunkingError::InvalidConfig(format!(
                "target_size {target_size} outside supported range \
                 {TARGET_SIZE_FLOOR}..={TARGET_SIZE_CEILING}"
            )));
        }
        if !(MAX_SIZE_FLOOR..=MAX_SIZE_CEILING).contains(&max_size) {
            return Err(ChunkingError::InvalidConfig(format!(
                "max_size {max_size} outside supported range \
                 {MAX_SIZE_FLOOR}..={MAX_SIZE_CEILING}"
            )));
        }
        if !(min_size <= target_size && target_size <= max_size) {
            return Err(ChunkingError::InvalidConfig(format!(
                "sizes must satisfy min <= target <= max, \
                 got {min_size} / {target_size} / {max_size}"
            )));
        }
        Ok(Self {
            min_size,
            target_size,
            max_size,
        })
    }

    /// Minimum chunk size (hard lower bound except for a stream's final chunk).
    #[must_use]
    pub const fn min_size(&self) -> usize {
        self.min_size
    }

    /// Target (average) chunk size.
    #[must_use]
    pub const fn target_size(&self) -> usize {
        self.target_size
    }

    /// Maximum chunk size (hard upper bound).
    #[must_use]
    pub const fn max_size(&self) -> usize {
        self.max_size
    }
}

impl Default for ChunkerConfig {
    /// The 1 MiB-target default configuration (min 256 KiB, max 4 MiB).
    fn default() -> Self {
        // Valid by construction: 256 KiB / 1 MiB / 4 MiB all sit inside the
        // FastCDC ranges checked in `new`.
        Self {
            min_size: Self::DEFAULT_TARGET_SIZE / 4,
            target_size: Self::DEFAULT_TARGET_SIZE,
            max_size: Self::DEFAULT_TARGET_SIZE * 4,
        }
    }
}

/// A single content-defined chunk: its identity, position, and bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Chunk {
    /// BLAKE3 hash of `data` (the plaintext chunk content).
    pub id: ChunkId,
    /// Byte offset of this chunk within the source stream.
    pub offset: u64,
    /// The chunk's plaintext bytes.
    pub data: Vec<u8>,
}

impl Chunk {
    /// Length of the chunk in bytes.
    #[must_use]
    pub fn len(&self) -> usize {
        self.data.len()
    }

    /// Whether the chunk contains no bytes (never true for emitted chunks).
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }
}

/// Streaming chunk iterator over any [`Read`] source.
///
/// Buffers at most `max_size` bytes at a time (the FastCDC window), so whole
/// files are never held in memory. Created by [`chunk_reader`].
pub struct ChunkStream<R: Read> {
    inner: v2020::StreamCDC<R>,
}

impl<R: Read> Iterator for ChunkStream<R> {
    type Item = Result<Chunk, ChunkingError>;

    fn next(&mut self) -> Option<Self::Item> {
        match self.inner.next()? {
            Ok(cd) => {
                let id = ChunkId::of(&cd.data);
                Some(Ok(Chunk {
                    id,
                    offset: cd.offset,
                    data: cd.data,
                }))
            }
            // `Empty` signals a clean end of stream, not a failure.
            Err(v2020::Error::Empty) => None,
            Err(v2020::Error::IoError(e)) => Some(Err(ChunkingError::Io(e))),
            Err(v2020::Error::Other(msg)) => Some(Err(ChunkingError::Internal(msg))),
        }
    }
}

/// Chunks a byte stream read incrementally from `source`.
///
/// Memory use is bounded by `config.max_size()`; the source is read exactly
/// once, in order. An empty source yields no chunks; a source shorter than
/// `config.min_size()` yields exactly one chunk.
pub fn chunk_reader<R: Read>(source: R, config: &ChunkerConfig) -> ChunkStream<R> {
    ChunkStream {
        inner: v2020::StreamCDC::new(source, config.min_size, config.target_size, config.max_size),
    }
}

/// Chunks an in-memory byte slice.
///
/// Produces exactly the same chunk boundaries and IDs as [`chunk_reader`]
/// over the same bytes (verified by test); infallible because no I/O occurs.
#[must_use]
pub fn chunk_bytes(data: &[u8], config: &ChunkerConfig) -> Vec<Chunk> {
    v2020::FastCDC::new(data, config.min_size, config.target_size, config.max_size)
        .map(|c| {
            let bytes = &data[c.offset..c.offset + c.length];
            Chunk {
                id: ChunkId::of(bytes),
                offset: c.offset as u64,
                data: bytes.to_vec(),
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::StdRng;
    use rand::{Rng, SeedableRng};
    use std::collections::HashSet;
    use std::io::Cursor;

    /// Deterministic pseudo-random bytes for reproducible tests.
    fn random_bytes(len: usize, seed: u64) -> Vec<u8> {
        let mut rng = StdRng::seed_from_u64(seed);
        let mut buf = vec![0u8; len];
        rng.fill_bytes(&mut buf);
        buf
    }

    /// Test config small enough to produce many chunks from a few MiB.
    fn small_config() -> ChunkerConfig {
        ChunkerConfig::with_target(64 * 1024).unwrap()
    }

    fn collect_stream(data: &[u8], config: &ChunkerConfig) -> Vec<Chunk> {
        chunk_reader(Cursor::new(data.to_vec()), config)
            .collect::<Result<Vec<_>, _>>()
            .unwrap()
    }

    #[test]
    fn determinism_same_input_same_chunks_and_ids() {
        let data = random_bytes(3 * 1024 * 1024, 1);
        let cfg = small_config();
        let a = chunk_bytes(&data, &cfg);
        let b = chunk_bytes(&data, &cfg);
        assert!(!a.is_empty());
        assert_eq!(a, b, "same input must produce identical chunk sequences");

        // Chunks must tile the input exactly, in order.
        let mut expected_offset = 0u64;
        let mut reassembled = Vec::with_capacity(data.len());
        for chunk in &a {
            assert_eq!(chunk.offset, expected_offset, "chunks must be contiguous");
            expected_offset += chunk.len() as u64;
            reassembled.extend_from_slice(&chunk.data);
        }
        assert_eq!(reassembled, data, "concatenated chunks must equal input");
    }

    #[test]
    fn boundary_shift_one_byte_insert_keeps_over_90_percent_of_ids() {
        let original = random_bytes(10 * 1024 * 1024, 2);
        let mut shifted = Vec::with_capacity(original.len() + 1);
        shifted.push(0xA5);
        shifted.extend_from_slice(&original);

        let cfg = small_config();
        let ids_original: Vec<ChunkId> =
            chunk_bytes(&original, &cfg).iter().map(|c| c.id).collect();
        let ids_shifted: HashSet<ChunkId> =
            chunk_bytes(&shifted, &cfg).iter().map(|c| c.id).collect();

        assert!(
            ids_original.len() >= 100,
            "need a statistically meaningful chunk count, got {}",
            ids_original.len()
        );
        let surviving = ids_original
            .iter()
            .filter(|id| ids_shifted.contains(id))
            .count();
        let ratio = surviving as f64 / ids_original.len() as f64;
        assert!(
            ratio > 0.90,
            "expected >90% of chunk IDs to survive a 1-byte prefix insert, \
             got {surviving}/{} ({ratio:.3})",
            ids_original.len()
        );
    }

    #[test]
    fn size_bounds_honored() {
        let data = random_bytes(5 * 1024 * 1024, 3);
        let cfg = small_config();
        let chunks = chunk_bytes(&data, &cfg);
        assert!(chunks.len() > 1);
        for (i, chunk) in chunks.iter().enumerate() {
            assert!(
                chunk.len() <= cfg.max_size(),
                "chunk {i} length {} exceeds max {}",
                chunk.len(),
                cfg.max_size()
            );
            if i + 1 != chunks.len() {
                assert!(
                    chunk.len() >= cfg.min_size(),
                    "non-final chunk {i} length {} below min {}",
                    chunk.len(),
                    cfg.min_size()
                );
            }
            assert!(!chunk.is_empty());
        }
    }

    #[test]
    fn empty_input_yields_zero_chunks() {
        let cfg = small_config();
        assert!(chunk_bytes(&[], &cfg).is_empty());
        assert!(collect_stream(&[], &cfg).is_empty());
    }

    #[test]
    fn input_smaller_than_min_yields_single_chunk() {
        let cfg = small_config();
        let data = random_bytes(100, 4);
        assert!(data.len() < cfg.min_size());

        for chunks in [chunk_bytes(&data, &cfg), collect_stream(&data, &cfg)] {
            assert_eq!(chunks.len(), 1, "sub-min input must yield exactly 1 chunk");
            assert_eq!(chunks[0].offset, 0);
            assert_eq!(chunks[0].data, data);
            assert_eq!(chunks[0].id, ChunkId::of(&data));
        }
    }

    #[test]
    fn streaming_equals_in_memory() {
        let data = random_bytes(4 * 1024 * 1024 + 12345, 5);
        let cfg = small_config();
        let in_memory = chunk_bytes(&data, &cfg);
        let streamed = collect_stream(&data, &cfg);
        assert!(in_memory.len() > 1);
        assert_eq!(
            in_memory, streamed,
            "streaming and in-memory chunking must produce identical results"
        );
    }

    #[test]
    fn streaming_propagates_io_errors() {
        struct FailingReader;
        impl Read for FailingReader {
            fn read(&mut self, _buf: &mut [u8]) -> std::io::Result<usize> {
                Err(std::io::Error::other("simulated disk failure"))
            }
        }
        let cfg = small_config();
        let result: Result<Vec<_>, _> = chunk_reader(FailingReader, &cfg).collect();
        assert!(matches!(result, Err(ChunkingError::Io(_))));
    }

    #[test]
    fn chunk_id_is_blake3_of_plaintext() {
        let data = b"busyncr chunk identity check";
        let id = ChunkId::of(data);
        assert_eq!(id.as_bytes(), blake3::hash(data).as_bytes());
        assert_eq!(id.to_string(), blake3::hash(data).to_hex().to_string());
    }

    #[test]
    fn chunk_id_hex_display_fromstr_roundtrip() {
        let id = ChunkId::of(b"roundtrip");
        let hex = id.to_string();
        assert_eq!(hex.len(), 64);
        assert!(hex.chars().all(|c| c.is_ascii_hexdigit()));
        let parsed: ChunkId = hex.parse().unwrap();
        assert_eq!(parsed, id);

        // Uppercase hex parses to the same ID.
        let parsed_upper: ChunkId = hex.to_uppercase().parse().unwrap();
        assert_eq!(parsed_upper, id);
    }

    #[test]
    fn chunk_id_fromstr_rejects_bad_input() {
        assert_eq!(
            "abc".parse::<ChunkId>(),
            Err(ChunkIdParseError::BadLength(3))
        );
        let too_long = "0".repeat(65);
        assert_eq!(
            too_long.parse::<ChunkId>(),
            Err(ChunkIdParseError::BadLength(65))
        );
        let bad_char = format!("g{}", "0".repeat(63));
        assert_eq!(
            bad_char.parse::<ChunkId>(),
            Err(ChunkIdParseError::BadChar('g'))
        );
        // Multi-byte characters must not slip through the length check.
        let emoji = "🦀".repeat(32);
        assert!(emoji.parse::<ChunkId>().is_err());
    }

    #[test]
    fn config_defaults_follow_target_ratios() {
        let cfg = ChunkerConfig::with_target(1024 * 1024).unwrap();
        assert_eq!(cfg.min_size(), 256 * 1024);
        assert_eq!(cfg.target_size(), 1024 * 1024);
        assert_eq!(cfg.max_size(), 4 * 1024 * 1024);
        assert_eq!(cfg, ChunkerConfig::default());
    }

    #[test]
    fn config_rejects_invalid_sizes() {
        // Unordered.
        assert!(matches!(
            ChunkerConfig::new(8192, 4096, 65536),
            Err(ChunkingError::InvalidConfig(_))
        ));
        // min below FastCDC floor.
        assert!(matches!(
            ChunkerConfig::new(16, 4096, 65536),
            Err(ChunkingError::InvalidConfig(_))
        ));
        // max above FastCDC ceiling.
        assert!(matches!(
            ChunkerConfig::new(4096, 65536, MAX_SIZE_CEILING + 1),
            Err(ChunkingError::InvalidConfig(_))
        ));
        // target above FastCDC ceiling (e.g. with_target(32 MiB)).
        assert!(matches!(
            ChunkerConfig::with_target(32 * 1024 * 1024),
            Err(ChunkingError::InvalidConfig(_))
        ));
        // PRD §3.7's largest benchmark candidate (4 MiB target) must be valid.
        let cfg = ChunkerConfig::with_target(4 * 1024 * 1024).unwrap();
        assert_eq!(cfg.max_size(), MAX_SIZE_CEILING);
    }
}
