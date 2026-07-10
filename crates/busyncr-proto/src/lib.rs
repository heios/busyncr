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

/// Upper bound (bytes) on a single gRPC message in either direction.
///
/// tonic's built-in decode limit is 4 MiB — smaller than a single legal
/// `ChunkBlob`: the CDC layer allows chunks up to 16 MiB
/// (`busyncr_core::chunking::MAX_SIZE_CEILING`; already 4 MiB at the 1 MiB
/// `--default-chunking` target), and every uploaded blob adds the AEAD
/// nonce+tag overhead plus protobuf framing on top. 32 MiB covers the
/// largest legal chunk blob with headroom.
///
/// Every stub — the daemon's `BusyncrServer` and each client `BusyncrClient`
/// — must apply this via `max_decoding_message_size` (and, symmetrically,
/// `max_encoding_message_size` so oversize sends fail fast locally), or
/// backups/restores of data with ≥4 MiB boundary-free runs abort mid-stream.
///
/// Known ceiling: `PutManifestRequest` carries the encrypted manifest blob
/// plus one 32-byte reference per distinct chunk in one message, so a single
/// snapshot is limited to roughly 900k chunk references (~1 TB of source at
/// the 1 MiB default target) until the request is restructured as a stream.
pub const MAX_MESSAGE_SIZE: usize = 32 * 1024 * 1024;

/// Byte length of a snapshot ID on the wire (raw ULID).
pub const SNAPSHOT_ID_LEN: usize = 16;

/// DNS name baked into the daemon's server certificate SAN list and used by
/// clients as the TLS server-name override (S6, FR1).
///
/// Pinning a fixed logical name decouples certificate verification from
/// whatever address the client happens to dial (IP, LAN hostname, tunnel).
pub const TLS_SERVER_NAME: &str = "busyncr-daemon";

pub use tonic;
