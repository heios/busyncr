//! Client-side encryption and keyfile handling (PRD §3.4).
//!
//! BusyNCR's daemon is zero-knowledge: every chunk and every manifest is
//! encrypted on the client with a client-held [`DataKey`] before upload, so
//! the daemon only ever sees chunk IDs and opaque blobs (FR7).
//!
//! # Scheme
//!
//! * AEAD: XChaCha20-Poly1305, one random 24-byte nonce per blob.
//! * Chunk blobs bind their [`ChunkId`] as associated data, so a blob cannot
//!   be silently substituted under a different ID.
//! * Manifest blobs bind the 16-byte snapshot ULID as associated data.
//! * Wire layout of every encrypted blob: `nonce (24) || ciphertext+tag`,
//!   i.e. plaintext length + [`BLOB_OVERHEAD`] bytes total.
//!
//! # Keyfile v2 (export / migration, FR6 + FR-K1)
//!
//! The backup set's secrets are exportable as a passphrase-protected keyfile:
//! a KEK is derived from the passphrase with Argon2id ([`KdfParams`]), and the
//! sealed payload — the [`DataKey`] **and** the [`ChunkIdKey`], 64 bytes — is
//! sealed under the KEK with the same AEAD. Carrying the chunk-ID key means
//! migration (FR6) preserves chunk identity, so imported history dedups
//! against new backups exactly as before (FR-K1 K1.2). The whole keyfile
//! header (magic, version, KDF parameters, salt) is bound as associated data,
//! so tampering with any header field is detected at import. The format is
//! versioned via [`KEYFILE_MAGIC`] and [`KEYFILE_VERSION`]; a v1 keyfile
//! (data key only) is rejected at import with [`CryptoError::KeyfileVersion`]
//! — no silent misinterpretation (FR-K1 K1.4/K1d). Nothing was released at
//! v1, so no migration path from it is needed.
//!
//! # Randomness
//!
//! All randomness (key material, salts, nonces) is drawn from a
//! caller-provided [`CryptoRng`], per the project rule that core logic takes
//! injected entropy. Binaries pass an OS-backed RNG; tests pass a seeded one.

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{Key, XChaCha20Poly1305, XNonce};
use rand::CryptoRng;
use ulid::Ulid;

use crate::chunking::{ChunkId, ChunkIdKey};

/// Length in bytes of a [`DataKey`].
pub const DATA_KEY_LEN: usize = 32;
/// Length in bytes of a [`ChunkIdKey`] (mirrors [`ChunkIdKey::LEN`]).
pub const CHUNK_ID_KEY_LEN: usize = ChunkIdKey::LEN;
/// Length in bytes of the XChaCha20-Poly1305 nonce prefixed to every blob.
pub const NONCE_LEN: usize = 24;
/// Length in bytes of the Poly1305 authentication tag appended to every blob.
pub const TAG_LEN: usize = 16;
/// Fixed per-blob size overhead: nonce prefix + authentication tag.
pub const BLOB_OVERHEAD: usize = NONCE_LEN + TAG_LEN;

/// Magic bytes opening every BusyNCR keyfile.
pub const KEYFILE_MAGIC: [u8; 8] = *b"BUSYNCRK";
/// Current keyfile format version. v2 seals the data key **and** the chunk-ID
/// key (FR-K1); v1 (data key only) is rejected at import.
pub const KEYFILE_VERSION: u8 = 2;
/// Length in bytes of the Argon2id salt stored in the keyfile.
pub const KEYFILE_SALT_LEN: usize = 16;
/// Length of the sealed secret payload: data key followed by chunk-ID key.
pub const KEYFILE_PAYLOAD_LEN: usize = DATA_KEY_LEN + CHUNK_ID_KEY_LEN;
/// Keyfile header length: magic (8) + version (1) + m_cost/t_cost/p_cost
/// (3 × u32 LE) + salt ([`KEYFILE_SALT_LEN`]). The header is the associated
/// data of the sealed payload, so it is tamper-evident.
pub const KEYFILE_HEADER_LEN: usize = 8 + 1 + 4 + 4 + 4 + KEYFILE_SALT_LEN;
/// Total length in bytes of a version-2 keyfile: header + nonce + sealed
/// payload ([`KEYFILE_PAYLOAD_LEN`] + tag).
pub const KEYFILE_LEN: usize = KEYFILE_HEADER_LEN + NONCE_LEN + KEYFILE_PAYLOAD_LEN + TAG_LEN;

/// Errors produced by encryption, decryption, and keyfile handling.
#[derive(Debug, thiserror::Error)]
pub enum CryptoError {
    /// AEAD encryption failed (should not happen with valid inputs).
    #[error("encryption failed")]
    Encrypt,
    /// The blob failed authentication: tampered ciphertext, wrong key, or
    /// mismatched associated data (e.g. blob presented under a different
    /// chunk ID).
    #[error("decryption failed: ciphertext tampered, wrong key, or mismatched context")]
    Decrypt,
    /// The blob is shorter than the fixed nonce + tag overhead.
    #[error(
        "encrypted blob truncated: {got} bytes, need at least {}",
        BLOB_OVERHEAD
    )]
    BlobTooShort {
        /// Actual blob length in bytes.
        got: usize,
    },
    /// The keyfile is structurally invalid (bad magic, wrong length).
    #[error("invalid keyfile: {0}")]
    KeyfileFormat(&'static str),
    /// The keyfile declares a format version this build does not support.
    #[error("unsupported keyfile version {0} (this build supports version {KEYFILE_VERSION})")]
    KeyfileVersion(u8),
    /// The keyfile's KDF parameters are outside what Argon2id accepts.
    #[error("key derivation failed: {0}")]
    Kdf(String),
    /// Unsealing the data key failed: wrong passphrase, or the keyfile was
    /// corrupted/tampered after export (the AEAD cannot distinguish the two).
    #[error("keyfile unlock failed: wrong passphrase or corrupted keyfile")]
    KeyfileUnlock,
}

/// The client-held symmetric key protecting one backup set (PRD §3.4).
///
/// Never leaves the client in plaintext; exportable only inside a
/// passphrase-protected keyfile ([`export_keyfile`]).
#[derive(Clone, PartialEq, Eq)]
pub struct DataKey([u8; DATA_KEY_LEN]);

impl DataKey {
    /// Generates a fresh random data key from the provided RNG.
    #[must_use]
    pub fn generate<R: CryptoRng>(rng: &mut R) -> Self {
        let mut bytes = [0u8; DATA_KEY_LEN];
        rng.fill_bytes(&mut bytes);
        Self(bytes)
    }

    /// Wraps existing raw key bytes (e.g. read from local client state).
    #[must_use]
    pub const fn from_bytes(bytes: [u8; DATA_KEY_LEN]) -> Self {
        Self(bytes)
    }

    /// Raw key bytes, for persisting into local client state.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; DATA_KEY_LEN] {
        &self.0
    }
}

impl std::fmt::Debug for DataKey {
    /// Redacted: key material must never appear in logs or panics.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("DataKey(..redacted..)")
    }
}

/// Argon2id cost parameters stored in (and read back from) the keyfile.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KdfParams {
    /// Memory cost in KiB.
    pub m_cost_kib: u32,
    /// Number of iterations (time cost).
    pub t_cost: u32,
    /// Degree of parallelism.
    pub p_cost: u32,
}

impl Default for KdfParams {
    /// Production defaults: 64 MiB memory, 3 iterations, 1 lane —
    /// comfortably above the OWASP Argon2id minimum recommendation.
    fn default() -> Self {
        Self {
            m_cost_kib: 64 * 1024,
            t_cost: 3,
            p_cost: 1,
        }
    }
}

/// Seals `plaintext` under `key` with `aad` as associated data.
///
/// Returns `nonce || ciphertext+tag`. The nonce is drawn fresh from `rng`
/// for every call, so encrypting the same plaintext twice yields different
/// blobs.
fn seal<R: CryptoRng>(
    key: &DataKey,
    aad: &[u8],
    plaintext: &[u8],
    rng: &mut R,
) -> Result<Vec<u8>, CryptoError> {
    let cipher = XChaCha20Poly1305::new(Key::from_slice(key.as_bytes()));
    let mut nonce = [0u8; NONCE_LEN];
    rng.fill_bytes(&mut nonce);
    let ciphertext = cipher
        .encrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|_| CryptoError::Encrypt)?;
    let mut blob = Vec::with_capacity(NONCE_LEN + ciphertext.len());
    blob.extend_from_slice(&nonce);
    blob.extend_from_slice(&ciphertext);
    Ok(blob)
}

/// Opens a blob produced by [`seal`] with the same `key` and `aad`.
fn open(key: &DataKey, aad: &[u8], blob: &[u8]) -> Result<Vec<u8>, CryptoError> {
    if blob.len() < BLOB_OVERHEAD {
        return Err(CryptoError::BlobTooShort { got: blob.len() });
    }
    let (nonce, ciphertext) = blob.split_at(NONCE_LEN);
    let cipher = XChaCha20Poly1305::new(Key::from_slice(key.as_bytes()));
    cipher
        .decrypt(
            XNonce::from_slice(nonce),
            Payload {
                msg: ciphertext,
                aad,
            },
        )
        .map_err(|_| CryptoError::Decrypt)
}

/// Encrypts one plaintext chunk for upload.
///
/// The chunk's [`ChunkId`] (BLAKE3 of the plaintext, PRD §3.3) is bound as
/// associated data: a stored blob only decrypts under the exact ID it was
/// uploaded for.
pub fn encrypt_chunk<R: CryptoRng>(
    key: &DataKey,
    id: &ChunkId,
    plaintext: &[u8],
    rng: &mut R,
) -> Result<Vec<u8>, CryptoError> {
    seal(key, id.as_bytes(), plaintext, rng)
}

/// Decrypts a chunk blob fetched from the daemon, verifying it was sealed
/// under exactly this [`ChunkId`].
pub fn decrypt_chunk(key: &DataKey, id: &ChunkId, blob: &[u8]) -> Result<Vec<u8>, CryptoError> {
    open(key, id.as_bytes(), blob)
}

/// Encrypts an encoded manifest, binding its snapshot ULID as associated
/// data (same scheme as chunks, PRD §3.4).
pub fn encrypt_manifest<R: CryptoRng>(
    key: &DataKey,
    snapshot_id: Ulid,
    plaintext: &[u8],
    rng: &mut R,
) -> Result<Vec<u8>, CryptoError> {
    seal(key, &snapshot_id.to_bytes(), plaintext, rng)
}

/// Decrypts a manifest blob, verifying it was sealed under exactly this
/// snapshot ULID.
pub fn decrypt_manifest(
    key: &DataKey,
    snapshot_id: Ulid,
    blob: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    open(key, &snapshot_id.to_bytes(), blob)
}

/// Derives the passphrase KEK with Argon2id (version 0x13).
fn derive_kek(
    passphrase: &[u8],
    salt: &[u8; KEYFILE_SALT_LEN],
    params: &KdfParams,
) -> Result<DataKey, CryptoError> {
    let argon_params = argon2::Params::new(
        params.m_cost_kib,
        params.t_cost,
        params.p_cost,
        Some(DATA_KEY_LEN),
    )
    .map_err(|e| CryptoError::Kdf(e.to_string()))?;
    let argon = argon2::Argon2::new(
        argon2::Algorithm::Argon2id,
        argon2::Version::V0x13,
        argon_params,
    );
    let mut kek = [0u8; DATA_KEY_LEN];
    argon
        .hash_password_into(passphrase, salt, &mut kek)
        .map_err(|e| CryptoError::Kdf(e.to_string()))?;
    Ok(DataKey::from_bytes(kek))
}

/// Exports the backup set's `data_key` and `chunk_id_key` as a
/// passphrase-protected keyfile v2 (FR6 + FR-K1, PRD §3.4).
///
/// Layout (version 2, [`KEYFILE_LEN`] bytes total):
///
/// ```text
/// magic (8) | version (1) | m_cost KiB (u32 LE) | t_cost (u32 LE)
/// | p_cost (u32 LE) | salt (16)          <- header, bound as AAD
/// | nonce (24) | sealed payload (32 data key + 32 chunk-ID key + 16 tag)
/// ```
///
/// Salt and nonce are drawn fresh from `rng` on every export.
pub fn export_keyfile<R: CryptoRng>(
    data_key: &DataKey,
    chunk_id_key: &ChunkIdKey,
    passphrase: &[u8],
    params: &KdfParams,
    rng: &mut R,
) -> Result<Vec<u8>, CryptoError> {
    let mut salt = [0u8; KEYFILE_SALT_LEN];
    rng.fill_bytes(&mut salt);
    let kek = derive_kek(passphrase, &salt, params)?;

    let mut header = Vec::with_capacity(KEYFILE_HEADER_LEN);
    header.extend_from_slice(&KEYFILE_MAGIC);
    header.push(KEYFILE_VERSION);
    header.extend_from_slice(&params.m_cost_kib.to_le_bytes());
    header.extend_from_slice(&params.t_cost.to_le_bytes());
    header.extend_from_slice(&params.p_cost.to_le_bytes());
    header.extend_from_slice(&salt);

    let mut payload = Vec::with_capacity(KEYFILE_PAYLOAD_LEN);
    payload.extend_from_slice(data_key.as_bytes());
    payload.extend_from_slice(chunk_id_key.as_bytes());

    let sealed = seal(&kek, &header, &payload, rng)?;
    let mut file = header;
    file.extend_from_slice(&sealed);
    Ok(file)
}

/// Imports a keyfile v2 produced by [`export_keyfile`], recovering the data
/// key and the chunk-ID key.
///
/// Fails with [`CryptoError::KeyfileFormat`] / [`CryptoError::KeyfileVersion`]
/// on structural problems (a v1 keyfile fails with `KeyfileVersion(1)` — no
/// silent misinterpretation, FR-K1 K1.4) and with [`CryptoError::KeyfileUnlock`]
/// when the passphrase is wrong or the file was tampered with after export.
pub fn import_keyfile(
    bytes: &[u8],
    passphrase: &[u8],
) -> Result<(DataKey, ChunkIdKey), CryptoError> {
    if bytes.len() < 9 {
        return Err(CryptoError::KeyfileFormat("file too short"));
    }
    if bytes[..8] != KEYFILE_MAGIC {
        return Err(CryptoError::KeyfileFormat("bad magic bytes"));
    }
    let version = bytes[8];
    if version != KEYFILE_VERSION {
        return Err(CryptoError::KeyfileVersion(version));
    }
    if bytes.len() != KEYFILE_LEN {
        return Err(CryptoError::KeyfileFormat("wrong length for version 2"));
    }

    let read_u32 = |offset: usize| -> Result<u32, CryptoError> {
        let slice = bytes
            .get(offset..offset + 4)
            .ok_or(CryptoError::KeyfileFormat("file too short"))?;
        let arr: [u8; 4] = slice
            .try_into()
            .map_err(|_| CryptoError::KeyfileFormat("file too short"))?;
        Ok(u32::from_le_bytes(arr))
    };
    let params = KdfParams {
        m_cost_kib: read_u32(9)?,
        t_cost: read_u32(13)?,
        p_cost: read_u32(17)?,
    };
    let mut salt = [0u8; KEYFILE_SALT_LEN];
    salt.copy_from_slice(&bytes[21..21 + KEYFILE_SALT_LEN]);

    let header = &bytes[..KEYFILE_HEADER_LEN];
    let sealed = &bytes[KEYFILE_HEADER_LEN..];
    let kek = derive_kek(passphrase, &salt, &params)?;
    let payload = open(&kek, header, sealed).map_err(|e| match e {
        // Any authentication failure here means wrong passphrase or a
        // tampered/corrupted keyfile; surface the dedicated variant.
        CryptoError::Decrypt | CryptoError::BlobTooShort { .. } => CryptoError::KeyfileUnlock,
        other => other,
    })?;
    if payload.len() != KEYFILE_PAYLOAD_LEN {
        return Err(CryptoError::KeyfileFormat(
            "sealed payload is not a 64-byte data key + chunk-ID key",
        ));
    }
    let mut data_key = [0u8; DATA_KEY_LEN];
    data_key.copy_from_slice(&payload[..DATA_KEY_LEN]);
    let mut chunk_id_key = [0u8; CHUNK_ID_KEY_LEN];
    chunk_id_key.copy_from_slice(&payload[DATA_KEY_LEN..]);
    Ok((
        DataKey::from_bytes(data_key),
        ChunkIdKey::from_bytes(chunk_id_key),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::StdRng;
    use rand::SeedableRng;

    /// Cheap Argon2id parameters so the test suite stays fast; production
    /// strength is covered separately by `keyfile_default_params_roundtrip`.
    const TEST_KDF: KdfParams = KdfParams {
        m_cost_kib: 16,
        t_cost: 1,
        p_cost: 1,
    };

    fn rng(seed: u64) -> StdRng {
        StdRng::seed_from_u64(seed)
    }

    fn sample_chunk() -> (DataKey, ChunkId, Vec<u8>, Vec<u8>) {
        let mut r = rng(7);
        let key = DataKey::generate(&mut r);
        let plaintext = b"the quick brown fox jumps over the lazy dog".repeat(100);
        let id = ChunkId::of(&plaintext);
        let blob = encrypt_chunk(&key, &id, &plaintext, &mut r).unwrap();
        (key, id, plaintext, blob)
    }

    #[test]
    fn chunk_roundtrip() {
        let (key, id, plaintext, blob) = sample_chunk();
        assert_eq!(blob.len(), plaintext.len() + BLOB_OVERHEAD);
        let out = decrypt_chunk(&key, &id, &blob).unwrap();
        assert_eq!(out, plaintext);
    }

    #[test]
    fn empty_plaintext_roundtrip() {
        let mut r = rng(8);
        let key = DataKey::generate(&mut r);
        let id = ChunkId::of(b"");
        let blob = encrypt_chunk(&key, &id, b"", &mut r).unwrap();
        assert_eq!(blob.len(), BLOB_OVERHEAD);
        assert_eq!(decrypt_chunk(&key, &id, &blob).unwrap(), b"");
    }

    #[test]
    fn nonces_are_fresh_per_blob() {
        let mut r = rng(9);
        let key = DataKey::generate(&mut r);
        let plaintext = b"same bytes twice";
        let id = ChunkId::of(plaintext);
        let a = encrypt_chunk(&key, &id, plaintext, &mut r).unwrap();
        let b = encrypt_chunk(&key, &id, plaintext, &mut r).unwrap();
        assert_ne!(a, b, "two encryptions of the same chunk must differ");
        // Both still decrypt to the same plaintext.
        assert_eq!(decrypt_chunk(&key, &id, &a).unwrap(), plaintext);
        assert_eq!(decrypt_chunk(&key, &id, &b).unwrap(), plaintext);
    }

    #[test]
    fn tampered_ciphertext_fails() {
        let (key, id, _plaintext, mut blob) = sample_chunk();
        // Flip one bit in every region: nonce, ciphertext body, tag.
        for &pos in &[3usize, NONCE_LEN + 10, blob.len() - 1] {
            let mut bad = blob.clone();
            bad[pos] ^= 0x01;
            assert!(
                matches!(decrypt_chunk(&key, &id, &bad), Err(CryptoError::Decrypt)),
                "bit flip at {pos} must fail authentication"
            );
        }
        // Truncation fails too (never panics).
        blob.truncate(BLOB_OVERHEAD - 1);
        assert!(matches!(
            decrypt_chunk(&key, &id, &blob),
            Err(CryptoError::BlobTooShort { .. })
        ));
    }

    #[test]
    fn chunk_blob_bound_to_its_id() {
        let (key, _id, _plaintext, blob) = sample_chunk();
        let other_id = ChunkId::of(b"a different chunk");
        assert!(
            matches!(
                decrypt_chunk(&key, &other_id, &blob),
                Err(CryptoError::Decrypt)
            ),
            "blob presented under a different chunk ID must fail"
        );
    }

    #[test]
    fn manifest_roundtrip_and_snapshot_binding() {
        let mut r = rng(10);
        let key = DataKey::generate(&mut r);
        let snap_a = Ulid::from_parts(1_700_000_000_000, 42);
        let snap_b = Ulid::from_parts(1_700_000_000_000, 43);
        let encoded = b"pretend this is an encoded manifest".to_vec();
        let blob = encrypt_manifest(&key, snap_a, &encoded, &mut r).unwrap();
        assert_eq!(decrypt_manifest(&key, snap_a, &blob).unwrap(), encoded);
        assert!(matches!(
            decrypt_manifest(&key, snap_b, &blob),
            Err(CryptoError::Decrypt)
        ));
    }

    #[test]
    fn fr7_blob_undecryptable_without_key() {
        // FR7 groundwork: what the daemon stores is useless without the
        // client key — a different 32-byte key fails authentication, and the
        // blob does not leak the plaintext in the clear.
        let (key, id, plaintext, blob) = sample_chunk();
        let mut r = rng(11);
        let wrong_key = DataKey::generate(&mut r);
        assert_ne!(wrong_key, key);
        assert!(matches!(
            decrypt_chunk(&wrong_key, &id, &blob),
            Err(CryptoError::Decrypt)
        ));
        // No plaintext window survives in the blob.
        let window = &plaintext[..16];
        assert!(
            !blob.windows(window.len()).any(|w| w == window),
            "ciphertext must not contain plaintext runs"
        );
    }

    #[test]
    fn frk1d_keyfile_v2_roundtrip_carries_both_keys() {
        // FR-K1d + FR6: export on machine A, import on machine B → both the
        // data key and the chunk-ID key come back identical, so migrated
        // history both decrypts (data key) and dedups (chunk-ID key).
        let mut r = rng(12);
        let data_key = DataKey::generate(&mut r);
        let chunk_id_key = ChunkIdKey::generate(&mut r);
        let file = export_keyfile(
            &data_key,
            &chunk_id_key,
            b"correct horse battery staple",
            &TEST_KDF,
            &mut r,
        )
        .expect("export");
        assert_eq!(file.len(), KEYFILE_LEN);
        assert_eq!(file[8], KEYFILE_VERSION, "keyfile must declare version 2");

        let (imported_data, imported_chunk) =
            import_keyfile(&file, b"correct horse battery staple").expect("import");
        assert_eq!(imported_data.as_bytes(), data_key.as_bytes());
        assert_eq!(imported_chunk.as_bytes(), chunk_id_key.as_bytes());
        // The imported data key actually decrypts data sealed by the original.
        let plaintext = b"cross-machine history".to_vec();
        let id = ChunkId::keyed(&chunk_id_key, &plaintext);
        let blob = encrypt_chunk(&data_key, &id, &plaintext, &mut r).unwrap();
        assert_eq!(
            decrypt_chunk(&imported_data, &id, &blob).unwrap(),
            plaintext
        );
        // ...and the imported chunk-ID key reproduces the same keyed identity.
        assert_eq!(ChunkId::keyed(&imported_chunk, &plaintext), id);
    }

    #[test]
    fn frk1d_v1_keyfile_is_rejected_with_versioned_error() {
        // FR-K1d: a v1 keyfile (magic BUSYNCRK, version byte 1, data key only)
        // must fail import with a clear versioned error — never silently
        // misinterpreted as v2.
        let mut v1 = Vec::new();
        v1.extend_from_slice(&KEYFILE_MAGIC);
        v1.push(1); // version 1
        v1.extend_from_slice(&TEST_KDF.m_cost_kib.to_le_bytes());
        v1.extend_from_slice(&TEST_KDF.t_cost.to_le_bytes());
        v1.extend_from_slice(&TEST_KDF.p_cost.to_le_bytes());
        v1.extend_from_slice(&[0x11u8; KEYFILE_SALT_LEN]);
        // A v1-length sealed body (24 nonce + 32 key + 16 tag) — its exact
        // contents are irrelevant; the version check must fire first.
        v1.extend_from_slice(&[0u8; NONCE_LEN + DATA_KEY_LEN + TAG_LEN]);
        assert!(matches!(
            import_keyfile(&v1, b"pw"),
            Err(CryptoError::KeyfileVersion(1))
        ));
    }

    #[test]
    fn fr6_wrong_passphrase_fails_cleanly() {
        let mut r = rng(13);
        let data_key = DataKey::generate(&mut r);
        let chunk_id_key = ChunkIdKey::generate(&mut r);
        let file =
            export_keyfile(&data_key, &chunk_id_key, b"right", &TEST_KDF, &mut r).expect("export");
        assert!(matches!(
            import_keyfile(&file, b"wrong"),
            Err(CryptoError::KeyfileUnlock)
        ));
    }

    #[test]
    fn keyfile_rejects_bad_magic_version_and_length() {
        let mut r = rng(14);
        let data_key = DataKey::generate(&mut r);
        let chunk_id_key = ChunkIdKey::generate(&mut r);
        let file =
            export_keyfile(&data_key, &chunk_id_key, b"pw", &TEST_KDF, &mut r).expect("export");

        let mut bad_magic = file.clone();
        bad_magic[0] ^= 0xFF;
        assert!(matches!(
            import_keyfile(&bad_magic, b"pw"),
            Err(CryptoError::KeyfileFormat(_))
        ));

        let mut bad_version = file.clone();
        bad_version[8] = 99;
        assert!(matches!(
            import_keyfile(&bad_version, b"pw"),
            Err(CryptoError::KeyfileVersion(99))
        ));

        let truncated = &file[..file.len() - 1];
        assert!(matches!(
            import_keyfile(truncated, b"pw"),
            Err(CryptoError::KeyfileFormat(_))
        ));

        assert!(matches!(
            import_keyfile(b"nope", b"pw"),
            Err(CryptoError::KeyfileFormat(_))
        ));
    }

    #[test]
    fn keyfile_header_tamper_detected() {
        // Weakening the stored KDF parameters (or salt) after export must
        // fail import: the header is bound as associated data.
        let mut r = rng(15);
        let data_key = DataKey::generate(&mut r);
        let chunk_id_key = ChunkIdKey::generate(&mut r);
        let file =
            export_keyfile(&data_key, &chunk_id_key, b"pw", &TEST_KDF, &mut r).expect("export");
        for pos in [9usize, 13, 17, 21] {
            let mut bad = file.clone();
            bad[pos] ^= 0x01;
            assert!(
                matches!(
                    import_keyfile(&bad, b"pw"),
                    Err(CryptoError::KeyfileUnlock) | Err(CryptoError::Kdf(_))
                ),
                "header tamper at {pos} must not import"
            );
        }
    }

    #[test]
    fn keyfile_default_params_roundtrip() {
        // Production-strength Argon2id parameters work end to end.
        let mut r = rng(16);
        let data_key = DataKey::generate(&mut r);
        let chunk_id_key = ChunkIdKey::generate(&mut r);
        let file = export_keyfile(
            &data_key,
            &chunk_id_key,
            b"pw",
            &KdfParams::default(),
            &mut r,
        )
        .expect("export");
        let (imported_data, imported_chunk) = import_keyfile(&file, b"pw").expect("import");
        assert_eq!(imported_data.as_bytes(), data_key.as_bytes());
        assert_eq!(imported_chunk.as_bytes(), chunk_id_key.as_bytes());
    }

    #[test]
    fn data_key_debug_is_redacted() {
        let mut r = rng(17);
        let key = DataKey::generate(&mut r);
        assert_eq!(format!("{key:?}"), "DataKey(..redacted..)");
        // And the generator actually uses the RNG (not zeroed).
        assert_ne!(key.as_bytes(), &[0u8; DATA_KEY_LEN]);
    }
}
