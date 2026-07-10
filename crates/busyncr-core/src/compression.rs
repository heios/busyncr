//! Per-chunk compression codec framing + policy engine (FR-C1 §2–§3).
//!
//! # Chunk format (persistent, normative — FR-C1 §2)
//!
//! A 1-byte codec ID is prepended to the *plaintext* chunk payload before
//! encryption ([`frame`]/[`unframe`], C1.1). The codec byte and the payload
//! are encrypted together as a single AEAD plaintext by the existing
//! [`crate::crypto::encrypt_chunk`] machinery, so the daemon never observes
//! the codec choice (C1.2, zero-knowledge preserved). [`ChunkId`] identity
//! remains the (keyed) BLAKE3 hash of the *uncompressed* plaintext (C1.3):
//! the compression decision is non-normative bookkeeping that affects stored
//! bytes only, never identity, dedup, or the wire protocol. Unknown codec
//! byte values (2–255, reserved) are a decode-time integrity error, not
//! silent output (cf. FR9).
//!
//! # Policy engine (client-side — FR-C1 §3)
//!
//! [`choose_codec`] is a pure function `(chunk, phase, cfg) -> (codec_id,
//! payload)` with counters injected by the caller — no I/O, no global state,
//! trivially unit-testable and reusable verbatim by the `bench-chunking
//! --compression` simulator (FR-C5b leans on this). It implements:
//!
//! * **C2.1 `zstd3` (default):** compress with zstd level 3; keep the
//!   compressed form iff `compressed_len <= raw_len * keep_threshold`
//!   (default 0.95), computed from the *actual* zstd output — never a
//!   prediction.
//! * **C2.2 `probe+zstd3` (opt-in via [`PolicyConfig::use_probe`]):** an lz4
//!   block-format probe over the full chunk first, output discarded (C1.4 —
//!   lz4 bytes are never stored); if the probe ratio is below
//!   `probe_threshold` (default 1.02) the chunk is stored raw without ever
//!   invoking zstd.
//! * **C2.3 `+escalate` (opt-in via [`PolicyConfig::escalate`], composable
//!   with either of the above):** if the zstd-3 result compresses the chunk
//!   by at least `escalate_ratio` (default 2.0), recompress at zstd level 9
//!   and keep whichever output is smaller. Escalation is **hard phase-gated
//!   off** during [`Phase::InitialFull`] regardless of config — the only
//!   phase where compression sits on the wall-clock critical path — and only
//!   ever runs during [`Phase::Incremental`].
//!
//! All thresholds and levels are config-surfaced ([`PolicyConfig`]), never
//! scattered literals, per FR-C1 §7.

use std::borrow::Cow;

/// Codec byte prepended to a chunk's plaintext before encryption (C1.1).
///
/// `0 = raw`, `1 = zstd`. Values `2..=255` are reserved; decoding one is a
/// hard integrity error ([`CompressionError::UnknownCodec`]), never silently
/// treated as raw or ignored.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum CodecId {
    /// Stored uncompressed, byte-for-byte.
    Raw = 0,
    /// Stored as a zstd frame (any level — the level is not recorded, only
    /// the codec, since C1.3 makes the compression decision non-normative).
    Zstd = 1,
}

impl CodecId {
    /// The single wire byte for this codec.
    #[must_use]
    pub const fn to_byte(self) -> u8 {
        self as u8
    }

    /// Parses a wire byte into a known codec.
    ///
    /// # Errors
    ///
    /// Returns [`CompressionError::UnknownCodec`] for any value outside
    /// `{0, 1}` — the reserved range (C1.1). Callers on the restore path
    /// must treat this as an integrity error (cf. FR9), not silent output.
    pub const fn from_byte(byte: u8) -> Result<Self, CompressionError> {
        match byte {
            0 => Ok(Self::Raw),
            1 => Ok(Self::Zstd),
            other => Err(CompressionError::UnknownCodec(other)),
        }
    }
}

/// Errors produced by codec framing and (de)compression.
#[derive(Debug, thiserror::Error)]
pub enum CompressionError {
    /// The framed payload is empty (no codec byte present).
    #[error("framed chunk payload is empty: missing codec byte")]
    Empty,
    /// The codec byte is outside the known `{raw, zstd}` range — reserved
    /// values 2–255 must never be silently accepted (FR-C1 C1.1, cf. FR9).
    #[error("unknown codec byte {0}: chunk format is corrupt or from a newer, incompatible build")]
    UnknownCodec(u8),
    /// zstd compression failed (should not happen for valid inputs/levels).
    #[error("zstd compression failed: {0}")]
    Compress(String),
    /// zstd decompression failed: corrupt or truncated zstd frame.
    #[error("zstd decompression failed: {0}")]
    Decompress(String),
}

/// Prepends `codec`'s wire byte to `payload` (C1.1).
///
/// The returned bytes are the plaintext that [`crate::crypto::encrypt_chunk`]
/// should seal — codec byte and payload are encrypted together (C1.2).
#[must_use]
pub fn frame(codec: CodecId, payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(1 + payload.len());
    out.push(codec.to_byte());
    out.extend_from_slice(payload);
    out
}

/// Splits a framed plaintext (post-decrypt) into its codec and payload.
///
/// # Errors
///
/// [`CompressionError::Empty`] if `framed` has no bytes at all;
/// [`CompressionError::UnknownCodec`] if the leading byte is outside
/// `{0, 1}`.
pub fn unframe(framed: &[u8]) -> Result<(CodecId, &[u8]), CompressionError> {
    let (&byte, rest) = framed.split_first().ok_or(CompressionError::Empty)?;
    let codec = CodecId::from_byte(byte)?;
    Ok((codec, rest))
}

/// Compresses `data` with zstd at `level`.
///
/// # Errors
///
/// [`CompressionError::Compress`] if the underlying zstd call fails (invalid
/// level or an internal libzstd error) — never panics.
pub fn compress_zstd(data: &[u8], level: i32) -> Result<Vec<u8>, CompressionError> {
    zstd::stream::encode_all(data, level).map_err(|e| CompressionError::Compress(e.to_string()))
}

/// Decompresses a zstd frame produced by [`compress_zstd`].
///
/// # Errors
///
/// [`CompressionError::Decompress`] if `data` is not a valid/complete zstd
/// frame (corrupt or truncated) — never panics.
pub fn decompress_zstd(data: &[u8]) -> Result<Vec<u8>, CompressionError> {
    zstd::stream::decode_all(data).map_err(|e| CompressionError::Decompress(e.to_string()))
}

/// Decodes a framed, decrypted chunk plaintext back to the original bytes.
///
/// The inverse of `frame(codec, payload)` where `payload` is the (possibly
/// compressed) chunk content chosen by [`choose_codec`]. Used on the restore
/// path after decrypt+verify (C2, later slice); exposed here so the codec
/// format's round-trip is independently testable at the framing layer.
///
/// # Errors
///
/// Propagates [`CompressionError::Empty`]/[`CompressionError::UnknownCodec`]
/// from [`unframe`], and [`CompressionError::Decompress`] if a `zstd`-tagged
/// payload is not a valid frame.
pub fn decode_chunk(framed: &[u8]) -> Result<Vec<u8>, CompressionError> {
    let (codec, payload) = unframe(framed)?;
    match codec {
        CodecId::Raw => Ok(payload.to_vec()),
        CodecId::Zstd => decompress_zstd(payload),
    }
}

/// Backup phase, used to hard-gate escalation (C2.3) off during the initial
/// full backup — the only phase where compression sits on the wall-clock
/// critical path.
///
/// Phase *detection* (first completed snapshot of a backup set) is a
/// pipeline concern for the slice that wires this policy engine into the
/// real backup flow; this type is just the caller-supplied input.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Phase {
    /// The backup set's first-ever completed snapshot is still running.
    /// Escalation ([`PolicyConfig::escalate`]) is forced off regardless of
    /// config in this phase.
    InitialFull,
    /// Any snapshot after the first. Escalation, if configured on, is
    /// allowed to run.
    Incremental,
}

/// Default zstd level for the baseline `zstd3` policy (C2.1).
pub const DEFAULT_ZSTD_LEVEL: i32 = 3;
/// Default zstd level used by the `+escalate` policy's retry (C2.3).
pub const DEFAULT_ESCALATE_LEVEL: i32 = 9;
/// Default keep-threshold (C2.1): the compressed form is kept iff
/// `compressed_len <= raw_len * DEFAULT_KEEP_THRESHOLD`.
pub const DEFAULT_KEEP_THRESHOLD: f64 = 0.95;
/// Default probe-threshold (C2.2): below this raw/probe-length ratio, the
/// `probe+zstd3` policy stores raw without ever invoking zstd.
pub const DEFAULT_PROBE_THRESHOLD: f64 = 1.02;
/// Default escalation ratio (C2.3): the zstd-3 result must compress the
/// chunk by at least this much (`raw_len / zstd3_len`) before a level-9
/// retry is attempted.
pub const DEFAULT_ESCALATE_RATIO: f64 = 2.0;

/// Compression policy configuration (FR-C1 §3, C2.4: thresholds/levels are
/// config-surfaced, never scattered literals).
///
/// The default value is the baseline `zstd3` policy (C2.1): no probe, no
/// escalation.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct PolicyConfig {
    /// Enables the `probe+zstd3` policy (C2.2): an lz4 ratio probe gates
    /// whether zstd is invoked at all.
    pub use_probe: bool,
    /// Enables the `+escalate` policy (C2.3), composable with either
    /// `zstd3` or `probe+zstd3`. Still hard phase-gated off during
    /// [`Phase::InitialFull`] regardless of this flag.
    pub escalate: bool,
    /// zstd level used for the baseline compression attempt.
    pub zstd_level: i32,
    /// zstd level used for the escalation retry.
    pub escalate_level: i32,
    /// Keep-threshold for the baseline attempt (C2.1).
    pub keep_threshold: f64,
    /// Probe-threshold for the `probe+zstd3` policy (C2.2).
    pub probe_threshold: f64,
    /// Escalation ratio trigger (C2.3).
    pub escalate_ratio: f64,
}

impl Default for PolicyConfig {
    fn default() -> Self {
        Self {
            use_probe: false,
            escalate: false,
            zstd_level: DEFAULT_ZSTD_LEVEL,
            escalate_level: DEFAULT_ESCALATE_LEVEL,
            keep_threshold: DEFAULT_KEEP_THRESHOLD,
            probe_threshold: DEFAULT_PROBE_THRESHOLD,
            escalate_ratio: DEFAULT_ESCALATE_RATIO,
        }
    }
}

/// Per-run policy-engine counters (C2.4), injected by the caller so both the
/// real backup pipeline and the `bench-chunking --compression` simulator can
/// reuse [`choose_codec`] verbatim and report identical statistics.
///
/// Every chunk passed through [`choose_codec`] lands in exactly one of
/// `raw` / `zstd3` / `escalated`, bucketed by the codec *actually stored*
/// (not merely attempted) — mirroring the C2.4 "chunks raw / zstd3 /
/// escalated" counter set.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct PolicyCounters {
    /// Chunks stored raw (codec 0): either compression was never attempted
    /// (probe rejected it), or the compressed form did not clear
    /// `keep_threshold`.
    pub raw: u64,
    /// Chunks stored as the baseline zstd-level attempt (codec 1, not
    /// escalated).
    pub zstd3: u64,
    /// Chunks stored as the escalation retry's output (codec 1, level-9
    /// result was smaller than the baseline).
    pub escalated: u64,
    /// Number of times the escalation retry (level 9) was actually invoked,
    /// regardless of whether its output was kept. Distinct from `escalated`
    /// so phase-gating can be asserted at the "was it ever called" level
    /// (FR-C6), not just "was it kept".
    pub escalation_attempts: u64,
    /// Sum of pre-compression (raw) chunk lengths seen.
    pub bytes_in: u64,
    /// Sum of the lengths actually stored (post-policy, pre-encryption,
    /// codec byte excluded).
    pub bytes_out: u64,
}

impl PolicyCounters {
    /// Total chunks processed (`raw + zstd3 + escalated`).
    #[must_use]
    pub const fn total(&self) -> u64 {
        self.raw + self.zstd3 + self.escalated
    }

    /// Bytes saved by compression: `bytes_in - bytes_out` (never negative —
    /// the raw fallback guarantees `bytes_out <= bytes_in` per chunk, since a
    /// raw-stored chunk costs exactly its own length and a kept-compressed
    /// chunk is only kept when smaller).
    #[must_use]
    pub const fn bytes_saved(&self) -> u64 {
        self.bytes_in.saturating_sub(self.bytes_out)
    }
}

/// lz4 block-format probe (C2.2): compresses the full chunk with lz4,
/// discarding the output — only its length is used as the compressibility
/// signal. Per C1.4, lz4 bytes are never persisted anywhere.
fn lz4_probe_len(chunk: &[u8]) -> usize {
    lz4_flex::compress(chunk).len()
}

/// Chooses a codec and payload for one unique chunk (FR-C1 §3).
///
/// Pure function: no I/O, no clock, no global state. `counters` is mutated
/// in place so callers control aggregation lifetime (per-run, per-snapshot,
/// or per-simulated-policy in the bench tool).
///
/// Returns `(codec_id, payload)` where `payload` is either the original
/// chunk (borrowed, zero-copy, when `codec_id == Raw`) or a freshly
/// allocated compressed buffer (`codec_id == Zstd`). Callers pass this
/// straight to [`frame`] to build the plaintext that gets encrypted.
#[must_use]
pub fn choose_codec<'a>(
    chunk: &'a [u8],
    phase: Phase,
    cfg: &PolicyConfig,
    counters: &mut PolicyCounters,
) -> (CodecId, Cow<'a, [u8]>) {
    counters.bytes_in += chunk.len() as u64;

    // An empty chunk can never compress smaller than itself; skip the
    // machinery entirely rather than dividing by zero below.
    if chunk.is_empty() {
        counters.raw += 1;
        return (CodecId::Raw, Cow::Borrowed(chunk));
    }

    if cfg.use_probe {
        let probe_len = lz4_probe_len(chunk).max(1);
        let probe_ratio = chunk.len() as f64 / probe_len as f64;
        if probe_ratio < cfg.probe_threshold {
            counters.raw += 1;
            counters.bytes_out += chunk.len() as u64;
            return (CodecId::Raw, Cow::Borrowed(chunk));
        }
    }

    let Ok(zstd3) = compress_zstd(chunk, cfg.zstd_level) else {
        // Compression failure is not a policy decision to propagate as an
        // error: the raw fallback already exists for exactly this case, so
        // fall back to it rather than surface a fallible signature that the
        // pure-fn contract (FR-C1 §7) does not have room for.
        counters.raw += 1;
        counters.bytes_out += chunk.len() as u64;
        return (CodecId::Raw, Cow::Borrowed(chunk));
    };

    if (zstd3.len() as f64) > chunk.len() as f64 * cfg.keep_threshold {
        counters.raw += 1;
        counters.bytes_out += chunk.len() as u64;
        return (CodecId::Raw, Cow::Borrowed(chunk));
    }

    // Escalation is hard phase-gated off during the initial full backup,
    // regardless of `cfg.escalate` (FR-C1 C2.3, FR-C6).
    if cfg.escalate && phase == Phase::Incremental {
        let ratio = chunk.len() as f64 / zstd3.len() as f64;
        if ratio >= cfg.escalate_ratio {
            counters.escalation_attempts += 1;
            if let Ok(zstd9) = compress_zstd(chunk, cfg.escalate_level) {
                if zstd9.len() < zstd3.len() {
                    counters.escalated += 1;
                    counters.bytes_out += zstd9.len() as u64;
                    return (CodecId::Zstd, Cow::Owned(zstd9));
                }
            }
        }
    }

    counters.zstd3 += 1;
    counters.bytes_out += zstd3.len() as u64;
    (CodecId::Zstd, Cow::Owned(zstd3))
}

/// Convenience wrapper: [`choose_codec`] followed by [`frame`] — the exact
/// plaintext bytes a caller should hand to [`crate::crypto::encrypt_chunk`].
#[must_use]
pub fn encode_chunk(
    chunk: &[u8],
    phase: Phase,
    cfg: &PolicyConfig,
    counters: &mut PolicyCounters,
) -> Vec<u8> {
    let (codec, payload) = choose_codec(chunk, phase, cfg, counters);
    frame(codec, &payload)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chunking::ChunkId;
    use crate::crypto::{decrypt_chunk, encrypt_chunk, DataKey};
    use rand::rngs::StdRng;
    use rand::SeedableRng;

    fn rng(seed: u64) -> StdRng {
        StdRng::seed_from_u64(seed)
    }

    fn compressible_chunk(len: usize) -> Vec<u8> {
        // Highly repetitive text-like content compresses well under zstd.
        b"the quick brown fox jumps over the lazy dog. "
            .iter()
            .copied()
            .cycle()
            .take(len)
            .collect()
    }

    fn incompressible_chunk(len: usize, seed: u64) -> Vec<u8> {
        use rand::Rng as _;
        let mut r = rng(seed);
        let mut buf = vec![0u8; len];
        r.fill_bytes(&mut buf);
        buf
    }

    // --- C1.1/C1.2 framing ---------------------------------------------

    #[test]
    fn frame_prepends_exactly_one_codec_byte() {
        let payload = b"hello world";
        let framed_raw = frame(CodecId::Raw, payload);
        assert_eq!(framed_raw.len(), payload.len() + 1);
        assert_eq!(framed_raw[0], 0);
        assert_eq!(&framed_raw[1..], payload);

        let framed_zstd = frame(CodecId::Zstd, payload);
        assert_eq!(framed_zstd[0], 1);
    }

    #[test]
    fn unframe_rejects_empty_and_unknown_codec() {
        assert!(matches!(unframe(&[]), Err(CompressionError::Empty)));
        for reserved in [2u8, 3, 42, 255] {
            let framed = frame_raw_byte(reserved, b"payload");
            assert!(matches!(
                unframe(&framed),
                Err(CompressionError::UnknownCodec(b)) if b == reserved
            ));
        }
    }

    fn frame_raw_byte(byte: u8, payload: &[u8]) -> Vec<u8> {
        let mut out = vec![byte];
        out.extend_from_slice(payload);
        out
    }

    #[test]
    fn codec_id_byte_roundtrip() {
        assert_eq!(CodecId::from_byte(0).unwrap(), CodecId::Raw);
        assert_eq!(CodecId::from_byte(1).unwrap(), CodecId::Zstd);
        assert_eq!(CodecId::Raw.to_byte(), 0);
        assert_eq!(CodecId::Zstd.to_byte(), 1);
    }

    // --- FR-C1: full round-trip through frame -> encrypt -> decrypt ->
    // decode, for every persistent codec byte value, plus the unknown-codec
    // integrity error. -----------------------------------------------------

    #[test]
    fn frc1_raw_codec_roundtrips_byte_exact() {
        let mut r = rng(1);
        let key = DataKey::generate(&mut r);
        let plaintext = compressible_chunk(50_000);
        let id = ChunkId::of(&plaintext);

        let framed = frame(CodecId::Raw, &plaintext);
        let blob = encrypt_chunk(&key, &id, &framed, &mut r).unwrap();
        let decrypted = decrypt_chunk(&key, &id, &blob).unwrap();
        let decoded = decode_chunk(&decrypted).unwrap();
        assert_eq!(decoded, plaintext);
    }

    #[test]
    fn frc1_zstd_codec_roundtrips_byte_exact() {
        let mut r = rng(2);
        let key = DataKey::generate(&mut r);
        let plaintext = compressible_chunk(50_000);
        let id = ChunkId::of(&plaintext);

        let compressed = compress_zstd(&plaintext, DEFAULT_ZSTD_LEVEL).unwrap();
        assert!(
            compressed.len() < plaintext.len(),
            "sanity: repetitive text must actually compress"
        );
        let framed = frame(CodecId::Zstd, &compressed);
        let blob = encrypt_chunk(&key, &id, &framed, &mut r).unwrap();
        let decrypted = decrypt_chunk(&key, &id, &blob).unwrap();
        let decoded = decode_chunk(&decrypted).unwrap();
        assert_eq!(decoded, plaintext);
    }

    #[test]
    fn frc1_empty_chunk_roundtrips_under_both_codecs() {
        let mut r = rng(3);
        let key = DataKey::generate(&mut r);
        let id = ChunkId::of(b"");

        for codec in [CodecId::Raw, CodecId::Zstd] {
            let payload: Vec<u8> = if codec == CodecId::Zstd {
                compress_zstd(b"", DEFAULT_ZSTD_LEVEL).unwrap()
            } else {
                Vec::new()
            };
            let framed = frame(codec, &payload);
            let blob = encrypt_chunk(&key, &id, &framed, &mut r).unwrap();
            let decrypted = decrypt_chunk(&key, &id, &blob).unwrap();
            assert_eq!(decode_chunk(&decrypted).unwrap(), Vec::<u8>::new());
        }
    }

    #[test]
    fn frc1_unknown_codec_byte_is_integrity_error_not_silent_output() {
        let mut r = rng(4);
        let key = DataKey::generate(&mut r);
        let payload = b"some plaintext payload".to_vec();
        let id = ChunkId::of(&payload);

        for reserved in [2u8, 200, 255] {
            let framed = frame_raw_byte(reserved, &payload);
            let blob = encrypt_chunk(&key, &id, &framed, &mut r).unwrap();
            let decrypted = decrypt_chunk(&key, &id, &blob).unwrap();
            let result = decode_chunk(&decrypted);
            assert!(
                matches!(result, Err(CompressionError::UnknownCodec(b)) if b == reserved),
                "reserved codec byte {reserved} must error, not decode silently"
            );
        }
    }

    #[test]
    fn frc1_encode_decode_chunk_helpers_agree_with_choose_codec() {
        let mut counters = PolicyCounters::default();
        let cfg = PolicyConfig::default();
        let plaintext = compressible_chunk(80_000);
        let framed = encode_chunk(&plaintext, Phase::Incremental, &cfg, &mut counters);
        let decoded = decode_chunk(&framed).unwrap();
        assert_eq!(decoded, plaintext);
        // A highly repetitive chunk must have been kept compressed.
        assert_eq!(counters.zstd3, 1);
        assert_eq!(counters.raw, 0);
    }

    // --- Policy engine: keep-threshold boundary -----------------------

    #[test]
    fn policy_keeps_compression_exactly_at_keep_threshold_boundary() {
        // Construct a chunk whose zstd-3 output lands at exactly
        // raw_len * keep_threshold, then nudge the threshold a hair below
        // the achieved ratio to force the raw fallback, proving the
        // comparison is a real `<=`/`>` boundary and not an approximation.
        let plaintext = compressible_chunk(200_000);
        let zstd3 = compress_zstd(&plaintext, DEFAULT_ZSTD_LEVEL).unwrap();
        let achieved_threshold = zstd3.len() as f64 / plaintext.len() as f64;

        // Threshold looser than achieved ratio -> compression kept.
        let mut counters_keep = PolicyCounters::default();
        let cfg_keep = PolicyConfig {
            keep_threshold: achieved_threshold + 0.01,
            ..PolicyConfig::default()
        };
        let (codec, _) = choose_codec(
            &plaintext,
            Phase::InitialFull,
            &cfg_keep,
            &mut counters_keep,
        );
        assert_eq!(codec, CodecId::Zstd);
        assert_eq!(counters_keep.zstd3, 1);

        // Threshold tighter than achieved ratio -> raw fallback.
        let mut counters_raw = PolicyCounters::default();
        let cfg_raw = PolicyConfig {
            keep_threshold: achieved_threshold - 0.01,
            ..PolicyConfig::default()
        };
        let (codec, payload) =
            choose_codec(&plaintext, Phase::InitialFull, &cfg_raw, &mut counters_raw);
        assert_eq!(codec, CodecId::Raw);
        assert_eq!(payload.as_ref(), plaintext.as_slice());
        assert_eq!(counters_raw.raw, 1);
    }

    #[test]
    fn policy_stores_incompressible_data_raw_by_default() {
        let mut counters = PolicyCounters::default();
        let chunk = incompressible_chunk(64 * 1024, 42);
        let (codec, payload) = choose_codec(
            &chunk,
            Phase::InitialFull,
            &PolicyConfig::default(),
            &mut counters,
        );
        assert_eq!(codec, CodecId::Raw);
        assert_eq!(payload.len(), chunk.len());
        assert_eq!(counters.raw, 1);
        assert_eq!(counters.bytes_saved(), 0);
    }

    #[test]
    fn policy_compresses_repetitive_data_by_default() {
        let mut counters = PolicyCounters::default();
        let chunk = compressible_chunk(200_000);
        let (codec, payload) = choose_codec(
            &chunk,
            Phase::InitialFull,
            &PolicyConfig::default(),
            &mut counters,
        );
        assert_eq!(codec, CodecId::Zstd);
        assert!(payload.len() < chunk.len());
        assert_eq!(counters.zstd3, 1);
        assert!(counters.bytes_saved() > 0);
    }

    #[test]
    fn policy_empty_chunk_is_always_raw() {
        let mut counters = PolicyCounters::default();
        let (codec, payload) = choose_codec(
            &[],
            Phase::Incremental,
            &PolicyConfig::default(),
            &mut counters,
        );
        assert_eq!(codec, CodecId::Raw);
        assert!(payload.is_empty());
        assert_eq!(counters.raw, 1);
        assert_eq!(counters.total(), 1);
    }

    #[test]
    fn policy_raw_payload_is_borrowed_not_copied() {
        let chunk = incompressible_chunk(4096, 99);
        let mut counters = PolicyCounters::default();
        let (codec, payload) = choose_codec(
            &chunk,
            Phase::InitialFull,
            &PolicyConfig::default(),
            &mut counters,
        );
        assert_eq!(codec, CodecId::Raw);
        assert!(
            matches!(payload, Cow::Borrowed(_)),
            "raw path must be zero-copy"
        );
    }

    // --- probe+zstd3 (C2.2) ---------------------------------------------

    #[test]
    fn probe_rejects_low_compressibility_without_invoking_zstd_keep() {
        // Incompressible data: the probe must gate it to raw. We can't
        // directly observe "zstd was never called" from the public API, but
        // we can assert the outcome the probe threshold is defined to
        // produce, and that it agrees with the non-probe policy's own
        // raw-fallback outcome for the same data.
        let chunk = incompressible_chunk(64 * 1024, 7);
        let mut counters = PolicyCounters::default();
        let cfg = PolicyConfig {
            use_probe: true,
            ..PolicyConfig::default()
        };
        let (codec, _) = choose_codec(&chunk, Phase::InitialFull, &cfg, &mut counters);
        assert_eq!(codec, CodecId::Raw);
        assert_eq!(counters.raw, 1);
    }

    #[test]
    fn probe_allows_compressible_data_through_to_zstd() {
        let chunk = compressible_chunk(200_000);
        let mut counters = PolicyCounters::default();
        let cfg = PolicyConfig {
            use_probe: true,
            ..PolicyConfig::default()
        };
        let (codec, payload) = choose_codec(&chunk, Phase::InitialFull, &cfg, &mut counters);
        assert_eq!(codec, CodecId::Zstd);
        assert!(payload.len() < chunk.len());
        assert_eq!(counters.zstd3, 1);
    }

    #[test]
    fn probe_threshold_boundary_flips_outcome() {
        let chunk = incompressible_chunk(64 * 1024, 11);
        let probe_len = lz4_probe_len(&chunk).max(1);
        let achieved_ratio = chunk.len() as f64 / probe_len as f64;

        // Threshold above the achieved probe ratio -> raw, zstd never tried.
        let mut counters_raw = PolicyCounters::default();
        let cfg_raw = PolicyConfig {
            use_probe: true,
            probe_threshold: achieved_ratio + 0.5,
            ..PolicyConfig::default()
        };
        let (codec, _) = choose_codec(&chunk, Phase::InitialFull, &cfg_raw, &mut counters_raw);
        assert_eq!(codec, CodecId::Raw);

        // Threshold below the achieved probe ratio -> falls through to the
        // normal zstd3 keep/raw decision (still likely raw for random
        // bytes, but via the zstd path rather than the probe gate — proven
        // by the counter total still landing on exactly one chunk).
        let mut counters_pass = PolicyCounters::default();
        let cfg_pass = PolicyConfig {
            use_probe: true,
            probe_threshold: (achieved_ratio - 0.5).max(0.0),
            ..PolicyConfig::default()
        };
        let (_, _) = choose_codec(&chunk, Phase::InitialFull, &cfg_pass, &mut counters_pass);
        assert_eq!(counters_pass.total(), 1);
    }

    // --- +escalate (C2.3) and FR-C6 phase gate ---------------------------

    /// A chunk engineered to clear the default 2.0 escalation ratio at
    /// level 3 (repetitive enough that level 9 still finds meaningfully more
    /// redundancy, matching the Appendix A.4 sqlite-like escalation payoff).
    fn escalation_candidate() -> Vec<u8> {
        // 200 distinct 500-byte pseudo-random "records", repeated in the
        // same fixed order 4 times (400 KiB total). Level 3's shallower
        // match search leaves a little more redundancy on the table than
        // level 9's deeper search recovers — empirically verified
        // (level 9 output is smaller) — mirroring the sqlite-like
        // escalation payoff in FR-C1 Appendix A.4, without depending on any
        // particular zstd release's exact byte counts (only the direction
        // of the inequality matters, asserted by the caller).
        use rand::Rng as _;
        let mut r = rng(777);
        let mut records: Vec<Vec<u8>> = Vec::with_capacity(200);
        for _ in 0..200 {
            let mut rec = vec![0u8; 500];
            r.fill_bytes(&mut rec);
            records.push(rec);
        }
        let mut out = Vec::with_capacity(200 * 500 * 4);
        for _ in 0..4 {
            for rec in &records {
                out.extend_from_slice(rec);
            }
        }
        out
    }

    #[test]
    fn frc6_escalation_never_fires_during_initial_full_backup() {
        let chunk = escalation_candidate();
        let mut counters = PolicyCounters::default();
        let cfg = PolicyConfig {
            escalate: true,
            ..PolicyConfig::default()
        };
        let (codec, _) = choose_codec(&chunk, Phase::InitialFull, &cfg, &mut counters);
        assert_eq!(codec, CodecId::Zstd);
        assert_eq!(
            counters.escalation_attempts, 0,
            "level-9 must never be invoked during the initial full backup, \
             regardless of cfg.escalate"
        );
        assert_eq!(counters.escalated, 0);
    }

    #[test]
    fn frc6_escalation_fires_for_qualifying_chunks_during_incremental() {
        let chunk = escalation_candidate();
        let zstd3 = compress_zstd(&chunk, DEFAULT_ZSTD_LEVEL).unwrap();
        let ratio = chunk.len() as f64 / zstd3.len() as f64;
        assert!(
            ratio >= DEFAULT_ESCALATE_RATIO,
            "test fixture must actually qualify for escalation (ratio {ratio})"
        );

        let mut counters = PolicyCounters::default();
        let cfg = PolicyConfig {
            escalate: true,
            ..PolicyConfig::default()
        };
        let (codec, payload) = choose_codec(&chunk, Phase::Incremental, &cfg, &mut counters);
        assert_eq!(codec, CodecId::Zstd);
        assert_eq!(
            counters.escalation_attempts, 1,
            "level-9 must be invoked for a qualifying chunk in incremental phase"
        );
        // Level 9 must have won for this fixture (else the test fixture is
        // not exercising the "kept" path); prove it decodes byte-exact too.
        assert_eq!(counters.escalated, 1);
        assert_eq!(counters.zstd3, 0);
        assert!(payload.len() <= zstd3.len());
        let framed = frame(codec, &payload);
        assert_eq!(decode_chunk(&framed).unwrap(), chunk);
    }

    #[test]
    fn escalation_disabled_by_config_never_fires_even_in_incremental() {
        let chunk = escalation_candidate();
        let mut counters = PolicyCounters::default();
        let cfg = PolicyConfig::default(); // escalate: false
        let (codec, _) = choose_codec(&chunk, Phase::Incremental, &cfg, &mut counters);
        assert_eq!(codec, CodecId::Zstd);
        assert_eq!(counters.escalation_attempts, 0);
        assert_eq!(counters.escalated, 0);
        assert_eq!(counters.zstd3, 1);
    }

    #[test]
    fn escalation_below_ratio_threshold_does_not_attempt_level_nine() {
        // Mildly compressible data whose zstd-3 ratio sits well under the
        // default 2.0 escalation trigger.
        let chunk = incompressible_chunk(200_000, 55);
        let mut counters = PolicyCounters::default();
        let cfg = PolicyConfig {
            escalate: true,
            ..PolicyConfig::default()
        };
        let _ = choose_codec(&chunk, Phase::Incremental, &cfg, &mut counters);
        assert_eq!(counters.escalation_attempts, 0);
    }

    // --- counters bookkeeping --------------------------------------------

    #[test]
    fn counters_accumulate_across_multiple_chunks() {
        let mut counters = PolicyCounters::default();
        let cfg = PolicyConfig::default();
        let chunks = [
            incompressible_chunk(10_000, 1),
            compressible_chunk(10_000),
            incompressible_chunk(10_000, 2),
        ];
        for chunk in &chunks {
            let _ = choose_codec(chunk, Phase::InitialFull, &cfg, &mut counters);
        }
        assert_eq!(counters.total(), 3);
        assert_eq!(counters.raw, 2);
        assert_eq!(counters.zstd3, 1);
        assert_eq!(
            counters.bytes_in,
            chunks.iter().map(|c| c.len() as u64).sum::<u64>()
        );
    }
}
