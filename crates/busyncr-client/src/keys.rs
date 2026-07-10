//! Keyfile export and import: the client-side halves of migration (FR6,
//! PRD §3.4).
//!
//! The backup set's two secrets — the [`DataKey`](busyncr_core::crypto::DataKey)
//! and the chunk-ID key (FR-K1) — live in plaintext only inside the client
//! state directory (`data.key` / `chunk-id.key`, created at enrollment). To
//! survive machine loss, the operator exports them as a single
//! passphrase-protected keyfile v2 ([`export_key`], Argon2id-wrapped — see
//! [`busyncr_core::crypto`]) and stores that file somewhere safe. Migration
//! to a new machine is then:
//!
//! 1. `busyncr-client enroll` with a fresh one-time token → new certificate
//!    (identity is per-machine and never migrated) plus fresh keys.
//! 2. `busyncr-client import-key` with the old machine's keyfile → the old
//!    data key **and** chunk-ID key replace the fresh ones, so every
//!    historical snapshot decrypts again *and* new backups keep deduplicating
//!    against the migrated history (FR-K1 K1.2).
//! 3. `list` / `restore` work on the full history.
//!
//! Import never destroys key material: differing pre-existing key files are
//! renamed to `<name>.old-<n>` before the imported keys are installed
//! ([`ImportOutcome::Replaced`]), so even a mistaken import is reversible.

// EnrollError (which embeds a 176-byte tonic::Status) rides inside KeyError;
// same call as the other client modules — boxing at every `?` conversion
// would cost more than the large variant does.
#![allow(clippy::result_large_err)]

use std::fs;
use std::path::{Path, PathBuf};

use busyncr_core::crypto::{self, CryptoError, KdfParams};
use rand::CryptoRng;

use crate::enroll::{self, EnrollError, CHUNK_ID_KEY_FILE, DATA_KEY_FILE};

/// How many `data.key.old-<n>` backup slots [`import_key`] will probe before
/// giving up (a state directory with this many replaced keys is corrupt or
/// abused, not a migration).
const MAX_KEY_BACKUPS: u32 = 1000;

/// Errors from keyfile export/import.
#[derive(Debug, thiserror::Error)]
pub enum KeyError {
    /// Filesystem access failed.
    #[error("keyfile I/O failed at {path}")]
    Io {
        /// Path being read or written.
        path: PathBuf,
        /// Underlying I/O error.
        #[source]
        source: std::io::Error,
    },

    /// Loading or persisting client state (the local `data.key`) failed.
    #[error(transparent)]
    State(#[from] EnrollError),

    /// Sealing or unsealing the keyfile failed (wrong passphrase, tampered
    /// file, unsupported version, ...).
    #[error(transparent)]
    Crypto(#[from] CryptoError),

    /// The export target already exists; refused rather than silently
    /// clobbering a previous (possibly the only surviving) export.
    #[error("refusing to overwrite existing keyfile {path} — pick a new path or delete it first")]
    OutputExists {
        /// The occupied output path.
        path: PathBuf,
    },

    /// No free `data.key.old-<n>` slot was found while preserving the
    /// pre-existing key during import.
    #[error("could not find a free backup slot for the existing data key in {state_dir}")]
    NoBackupSlot {
        /// The client state directory.
        state_dir: PathBuf,
    },
}

/// What [`import_key`] did with the local key state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ImportOutcome {
    /// No `data.key` existed; the imported key was installed fresh.
    Installed,
    /// The existing `data.key` already equals the imported key; nothing was
    /// written (importing the same keyfile twice is a no-op).
    AlreadyCurrent,
    /// Different key material existed; the previous key files were preserved
    /// (each `<name>.old-<n>`) before the imported keys were installed. The
    /// contained path is the preserved `data.key.old-<n>`.
    Replaced {
        /// Where the previous data key now lives (`data.key.old-<n>`); its
        /// sibling `chunk-id.key.old-<n>` is preserved alongside it.
        backed_up: PathBuf,
    },
}

/// Exports the backup set's data key and chunk-ID key from `state_dir` as a
/// passphrase-protected keyfile v2 at `output` (FR6 + FR-K1, PRD §3.4).
///
/// Refuses to overwrite an existing `output` file. The written file is
/// permission-restricted like the raw keys (owner-only on Unix).
///
/// # Errors
///
/// [`KeyError::State`] when the state directory is missing a key (not
/// enrolled yet), [`KeyError::OutputExists`] when `output` is occupied,
/// [`KeyError::Crypto`] / [`KeyError::State`] on sealing or write trouble.
pub fn export_key<R: CryptoRng>(
    state_dir: &Path,
    output: &Path,
    passphrase: &[u8],
    params: &KdfParams,
    rng: &mut R,
) -> Result<(), KeyError> {
    let data_key = enroll::load_data_key(state_dir)?;
    let chunk_id_key = enroll::load_chunk_id_key(state_dir)?;
    if output.exists() {
        return Err(KeyError::OutputExists {
            path: output.to_owned(),
        });
    }
    let file = crypto::export_keyfile(&data_key, &chunk_id_key, passphrase, params, rng)?;
    enroll::write_atomic(output, &file, true)?;
    Ok(())
}

/// Imports a keyfile produced by [`export_key`] into `state_dir`, installing
/// the recovered data key and chunk-ID key as this machine's `data.key` /
/// `chunk-id.key` (FR6 migration + FR-K1).
///
/// Pre-existing, *different* key files (e.g. the fresh keys `enroll` creates
/// on a new machine) are renamed to `<name>.old-<n>` first, so no key
/// material is ever destroyed. A failed import (wrong passphrase, corrupt
/// keyfile) leaves the state directory untouched. Nothing is written if both
/// keys already match the keyfile ([`ImportOutcome::AlreadyCurrent`]).
///
/// # Errors
///
/// [`KeyError::Crypto`] when the keyfile is malformed or the passphrase is
/// wrong ([`CryptoError::KeyfileUnlock`]), [`KeyError::Io`] /
/// [`KeyError::State`] on filesystem trouble.
pub fn import_key(
    state_dir: &Path,
    keyfile_path: &Path,
    passphrase: &[u8],
) -> Result<ImportOutcome, KeyError> {
    let bytes = fs::read(keyfile_path).map_err(|source| KeyError::Io {
        path: keyfile_path.to_owned(),
        source,
    })?;
    let (imported_data, imported_chunk) = crypto::import_keyfile(&bytes, passphrase)?;

    let data_path = state_dir.join(DATA_KEY_FILE);
    let chunk_path = state_dir.join(CHUNK_ID_KEY_FILE);

    // A malformed existing key file reads as "not loadable" here; the
    // `*.exists()` checks below still back it up rather than clobber it.
    let existing_data = load_optional(enroll::load_data_key(state_dir))?;
    let existing_chunk = load_optional(enroll::load_chunk_id_key(state_dir))?;

    let both_current = existing_data.as_ref().map(|k| k == &imported_data) == Some(true)
        && existing_chunk.as_ref().map(|k| k == &imported_chunk) == Some(true);
    if both_current {
        return Ok(ImportOutcome::AlreadyCurrent);
    }

    let outcome = if data_path.exists() || chunk_path.exists() {
        let backed_up = back_up_existing_keys(state_dir, &data_path, &chunk_path)?;
        ImportOutcome::Replaced { backed_up }
    } else {
        fs::create_dir_all(state_dir).map_err(|source| KeyError::Io {
            path: state_dir.to_owned(),
            source,
        })?;
        ImportOutcome::Installed
    };

    enroll::write_atomic(&data_path, imported_data.as_bytes(), true)?;
    enroll::write_atomic(&chunk_path, imported_chunk.as_bytes(), true)?;
    Ok(outcome)
}

/// Maps a key-load result to `Some(key)` when present, `None` when the file is
/// absent or malformed (both cases are handled by the caller as "no current
/// key to compare, but preserve any bytes on disk"), propagating other errors.
fn load_optional<T>(result: Result<T, EnrollError>) -> Result<Option<T>, KeyError> {
    match result {
        Ok(key) => Ok(Some(key)),
        Err(EnrollError::Io { ref source, .. })
            if source.kind() == std::io::ErrorKind::NotFound =>
        {
            Ok(None)
        }
        Err(EnrollError::BadDataKey { .. }) => Ok(None),
        Err(other) => Err(other.into()),
    }
}

/// Renames every existing backup-set key file to a shared free `.old-<n>`
/// slot (so a data key and its chunk-ID key are preserved together and stay
/// correlated). Returns the preserved `data.key.old-<n>` path when the data
/// key was present, otherwise the preserved chunk-ID key path.
fn back_up_existing_keys(
    state_dir: &Path,
    data_path: &Path,
    chunk_path: &Path,
) -> Result<PathBuf, KeyError> {
    for n in 1..=MAX_KEY_BACKUPS {
        let data_bak = state_dir.join(format!("{DATA_KEY_FILE}.old-{n}"));
        let chunk_bak = state_dir.join(format!("{CHUNK_ID_KEY_FILE}.old-{n}"));
        if data_bak.exists() || chunk_bak.exists() {
            continue;
        }
        let mut preserved: Option<PathBuf> = None;
        if data_path.exists() {
            fs::rename(data_path, &data_bak).map_err(|source| KeyError::Io {
                path: data_bak.clone(),
                source,
            })?;
            preserved = Some(data_bak);
        }
        if chunk_path.exists() {
            fs::rename(chunk_path, &chunk_bak).map_err(|source| KeyError::Io {
                path: chunk_bak.clone(),
                source,
            })?;
            preserved.get_or_insert(chunk_bak);
        }
        return preserved.ok_or_else(|| KeyError::NoBackupSlot {
            state_dir: state_dir.to_owned(),
        });
    }
    Err(KeyError::NoBackupSlot {
        state_dir: state_dir.to_owned(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::StdRng;
    use rand::SeedableRng;

    /// Cheap Argon2id parameters so tests stay fast (production strength is
    /// covered in busyncr-core's crypto tests).
    const TEST_KDF: KdfParams = KdfParams {
        m_cost_kib: 16,
        t_cost: 1,
        p_cost: 1,
    };

    fn rng(seed: u64) -> StdRng {
        StdRng::seed_from_u64(seed)
    }

    #[test]
    fn fr6_export_import_roundtrip_installs_identical_key() {
        let dir = tempfile::tempdir().unwrap();
        let machine_a = dir.path().join("a");
        let machine_b = dir.path().join("b");
        let mut r = rng(1);
        enroll::ensure_data_key(&machine_a, &mut r).unwrap();
        let original = enroll::load_data_key(&machine_a).unwrap();

        let keyfile = dir.path().join("busyncr.keyfile");
        export_key(&machine_a, &keyfile, b"pass", &TEST_KDF, &mut r).unwrap();

        // Machine B has no key yet: plain install.
        let outcome = import_key(&machine_b, &keyfile, b"pass").unwrap();
        assert_eq!(outcome, ImportOutcome::Installed);
        assert_eq!(enroll::load_data_key(&machine_b).unwrap(), original);
    }

    #[test]
    fn fr6_import_preserves_existing_different_key() {
        let dir = tempfile::tempdir().unwrap();
        let machine_a = dir.path().join("a");
        let machine_b = dir.path().join("b");
        let mut r = rng(2);
        enroll::ensure_data_key(&machine_a, &mut r).unwrap();
        enroll::ensure_data_key(&machine_b, &mut r).unwrap();
        let fresh_b = enroll::load_data_key(&machine_b).unwrap();
        let original_a = enroll::load_data_key(&machine_a).unwrap();
        assert_ne!(fresh_b, original_a);

        let keyfile = dir.path().join("busyncr.keyfile");
        export_key(&machine_a, &keyfile, b"pass", &TEST_KDF, &mut r).unwrap();

        let outcome = import_key(&machine_b, &keyfile, b"pass").unwrap();
        let backed_up = match outcome {
            ImportOutcome::Replaced { backed_up } => backed_up,
            other => panic!("expected Replaced, got {other:?}"),
        };
        // The imported key is live; the fresh key survives at the backup path.
        assert_eq!(enroll::load_data_key(&machine_b).unwrap(), original_a);
        assert_eq!(
            std::fs::read(&backed_up).unwrap(),
            fresh_b.as_bytes().to_vec()
        );

        // Importing the same keyfile again is a no-op.
        assert_eq!(
            import_key(&machine_b, &keyfile, b"pass").unwrap(),
            ImportOutcome::AlreadyCurrent
        );
    }

    #[test]
    fn fr6_wrong_passphrase_fails_and_leaves_state_untouched() {
        let dir = tempfile::tempdir().unwrap();
        let machine_a = dir.path().join("a");
        let machine_b = dir.path().join("b");
        let mut r = rng(3);
        enroll::ensure_data_key(&machine_a, &mut r).unwrap();
        enroll::ensure_data_key(&machine_b, &mut r).unwrap();
        let fresh_b = enroll::load_data_key(&machine_b).unwrap();

        let keyfile = dir.path().join("busyncr.keyfile");
        export_key(&machine_a, &keyfile, b"right", &TEST_KDF, &mut r).unwrap();

        let err = import_key(&machine_b, &keyfile, b"wrong").unwrap_err();
        assert!(matches!(err, KeyError::Crypto(CryptoError::KeyfileUnlock)));
        // Machine B's key is exactly what it was; no backup file appeared.
        assert_eq!(enroll::load_data_key(&machine_b).unwrap(), fresh_b);
        assert!(!machine_b.join(format!("{DATA_KEY_FILE}.old-1")).exists());
    }

    #[test]
    fn fr6_export_refuses_to_overwrite_existing_keyfile() {
        let dir = tempfile::tempdir().unwrap();
        let state = dir.path().join("state");
        let mut r = rng(4);
        enroll::ensure_data_key(&state, &mut r).unwrap();

        let keyfile = dir.path().join("busyncr.keyfile");
        export_key(&state, &keyfile, b"pass", &TEST_KDF, &mut r).unwrap();
        let first = std::fs::read(&keyfile).unwrap();

        let err = export_key(&state, &keyfile, b"pass", &TEST_KDF, &mut r).unwrap_err();
        assert!(matches!(err, KeyError::OutputExists { .. }));
        assert_eq!(std::fs::read(&keyfile).unwrap(), first, "file untouched");
    }

    #[test]
    fn export_without_enrollment_fails_cleanly() {
        let dir = tempfile::tempdir().unwrap();
        let mut r = rng(5);
        let err = export_key(
            &dir.path().join("no-state"),
            &dir.path().join("out.keyfile"),
            b"pass",
            &TEST_KDF,
            &mut r,
        )
        .unwrap_err();
        assert!(matches!(err, KeyError::State(EnrollError::Io { .. })));
    }

    #[test]
    fn import_of_garbage_keyfile_fails_cleanly() {
        let dir = tempfile::tempdir().unwrap();
        let garbage = dir.path().join("garbage.keyfile");
        std::fs::write(&garbage, b"not a keyfile").unwrap();
        let err = import_key(&dir.path().join("state"), &garbage, b"pass").unwrap_err();
        assert!(matches!(
            err,
            KeyError::Crypto(CryptoError::KeyfileFormat(_))
        ));
        assert!(!dir.path().join("state").join(DATA_KEY_FILE).exists());
    }
}
