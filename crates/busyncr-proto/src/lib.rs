//! BusyNCR wire protocol: prost message types and tonic client/server stubs
//! generated from `proto/busyncr.proto` (PRD §3.2).
//!
//! Conventions carried by the raw `bytes` fields:
//!
//! * chunk IDs are exactly [`CHUNK_ID_LEN`] bytes — the BLAKE3 hash of the
//!   chunk plaintext (`busyncr_core::chunking::ChunkId`);
//! * snapshot IDs are exactly [`SNAPSHOT_ID_LEN`] bytes — a raw ULID.
//!
//! The daemon rejects malformed IDs with `INVALID_ARGUMENT`.

/// Generated protocol types for `package busyncr.v1`.
#[allow(clippy::doc_markdown, clippy::missing_errors_doc)]
pub mod v1 {
    tonic::include_proto!("busyncr.v1");
}

/// Byte length of a chunk ID on the wire (raw BLAKE3-256 digest).
pub const CHUNK_ID_LEN: usize = 32;

/// Byte length of a snapshot ID on the wire (raw ULID).
pub const SNAPSHOT_ID_LEN: usize = 16;

/// DNS name baked into the daemon's server certificate SAN list and used by
/// clients as the TLS server-name override (S6, FR1).
///
/// Pinning a fixed logical name decouples certificate verification from
/// whatever address the client happens to dial (IP, LAN hostname, tunnel).
pub const TLS_SERVER_NAME: &str = "busyncr-daemon";

pub use tonic;
