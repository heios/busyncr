//! Shared record layout for the daemon's chunk index.
//!
//! The `bench-chunking` sizing tool (PRD §3.7) projects daemon index metadata
//! as `unique_chunks × IndexEntry::WIRE_SIZE`, so the constants here are the
//! single source of truth for the on-disk index record layout. Slice S3's
//! `redb`-backed store MUST serialize its per-chunk records with exactly this
//! layout (fixed-width, little-endian, no framing) so that the projections
//! stay exact arithmetic rather than estimates.

use crate::chunking::ChunkId;

/// One record in the daemon's chunk index: the value fields stored against a
/// 32-byte chunk-ID key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IndexEntry {
    /// Stored blob length in bytes (ciphertext length once clients encrypt
    /// uploads, from slice S7 onward).
    pub chunk_len: u64,
    /// Number of live manifest references to the chunk (drives GC).
    pub refcount: u64,
}

impl IndexEntry {
    /// Serialized size of the value part of a record:
    /// `chunk_len` (8 bytes LE) + `refcount` (8 bytes LE).
    pub const VALUE_SIZE: u64 = 16;

    /// Exact per-entry wire size of one index record: the 32-byte chunk-ID
    /// key plus [`Self::VALUE_SIZE`] bytes of value.
    ///
    /// This is the "exact per-entry cost from the real index record layout"
    /// used by the bench-chunking metadata projection (PRD §3.7). It counts
    /// the serialized record only; storage-engine page/B-tree overhead is
    /// intentionally excluded because it is amortized and engine-specific.
    pub const WIRE_SIZE: u64 = ChunkId::LEN as u64 + Self::VALUE_SIZE;

    /// Serializes the value fields in the canonical wire layout
    /// (`chunk_len` LE, then `refcount` LE).
    #[must_use]
    pub fn to_wire_value(&self) -> [u8; 16] {
        let mut out = [0u8; 16];
        out[..8].copy_from_slice(&self.chunk_len.to_le_bytes());
        out[8..].copy_from_slice(&self.refcount.to_le_bytes());
        out
    }

    /// Parses value fields from the canonical wire layout produced by
    /// [`Self::to_wire_value`].
    #[must_use]
    pub fn from_wire_value(bytes: [u8; 16]) -> Self {
        let mut len = [0u8; 8];
        let mut rc = [0u8; 8];
        len.copy_from_slice(&bytes[..8]);
        rc.copy_from_slice(&bytes[8..]);
        Self {
            chunk_len: u64::from_le_bytes(len),
            refcount: u64::from_le_bytes(rc),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wire_size_matches_serialized_layout() {
        let entry = IndexEntry {
            chunk_len: 0x0102_0304_0506_0708,
            refcount: 42,
        };
        let value = entry.to_wire_value();
        assert_eq!(value.len() as u64, IndexEntry::VALUE_SIZE);
        assert_eq!(
            IndexEntry::WIRE_SIZE,
            ChunkId::LEN as u64 + value.len() as u64
        );
        assert_eq!(IndexEntry::WIRE_SIZE, 48);
        assert_eq!(IndexEntry::from_wire_value(value), entry);
    }
}
