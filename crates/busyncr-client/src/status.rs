//! The persisted "last backup" record `busyncr-client status` shows
//! (FR-M1 M3.1). Every successful one-shot `backup`, scheduled `run` tick,
//! and Windows service iteration writes one of these to the state
//! directory, overwriting whatever was there — only the most recent backup
//! is kept.
//!
//! ```text
//! <state>/last-backup.toml
//! ```
//!
//! The record itself is deliberately small and derived straight from
//! [`crate::backup::BackupReport`] (the FR3 byte-accounting ledger) plus a
//! caller-measured wall-clock duration — the backup pipeline never reads
//! the clock (project determinism rule), so duration is injected at the
//! same CLI edge that already injects the snapshot ID and creation time.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::backup::BackupReport;

/// File name of the persisted last-backup record inside the state dir.
pub const LAST_BACKUP_FILE: &str = "last-backup.toml";

/// Errors reading or writing the persisted last-backup record.
#[derive(Debug, thiserror::Error)]
pub enum StatusError {
    /// Filesystem access under the state directory failed.
    #[error("client state I/O failed at {path}")]
    Io {
        /// Path being read or written.
        path: PathBuf,
        /// Underlying I/O error.
        #[source]
        source: std::io::Error,
    },

    /// The persisted record does not parse as TOML.
    #[error("last-backup record at {path} does not parse")]
    Parse {
        /// The offending file.
        path: PathBuf,
        /// Underlying TOML error.
        #[source]
        source: Box<toml::de::Error>,
    },

    /// Serializing the record failed (should not happen for valid data).
    #[error("encoding last-backup record failed")]
    Encode(#[from] toml::ser::Error),
}

/// What one completed backup left behind for `busyncr-client status`
/// (FR-M1 M3.1).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LastBackupRecord {
    /// The snapshot's ULID, in text form.
    pub snapshot_id: String,
    /// Snapshot creation time, whole seconds since the Unix epoch.
    pub created_at: i64,
    /// Files captured in the manifest.
    pub files: u64,
    /// Ciphertext bytes shipped (the FR3 `upload_bytes` ledger).
    pub upload_bytes: u64,
    /// Wall-clock duration of the backup attempt, in milliseconds.
    pub duration_ms: u64,
}

impl LastBackupRecord {
    /// Builds a record from a completed [`BackupReport`] plus the wall-clock
    /// duration and creation time the CLI measured around the call.
    #[must_use]
    pub fn from_report(report: &BackupReport, created_at: i64, duration_ms: u64) -> Self {
        Self {
            snapshot_id: report.snapshot_id.to_string(),
            created_at,
            files: report.files,
            upload_bytes: report.upload_bytes,
            duration_ms,
        }
    }

    /// Persists this record to `<state_dir>/last-backup.toml`, overwriting
    /// any previous one (only the most recent backup is kept).
    ///
    /// # Errors
    ///
    /// [`StatusError::Io`] on filesystem trouble, [`StatusError::Encode`] if
    /// encoding fails (should not happen for valid data).
    pub fn save(&self, state_dir: &Path) -> Result<(), StatusError> {
        std::fs::create_dir_all(state_dir).map_err(|source| StatusError::Io {
            path: state_dir.to_owned(),
            source,
        })?;
        let path = state_dir.join(LAST_BACKUP_FILE);
        let body = toml::to_string_pretty(self)?;
        std::fs::write(&path, body).map_err(|source| StatusError::Io { path, source })
    }

    /// Loads the persisted record, if any backup has ever completed here.
    ///
    /// # Errors
    ///
    /// [`StatusError::Io`] on trouble other than "not found yet";
    /// [`StatusError::Parse`] if the file is corrupt.
    pub fn load(state_dir: &Path) -> Result<Option<Self>, StatusError> {
        let path = state_dir.join(LAST_BACKUP_FILE);
        match std::fs::read_to_string(&path) {
            Ok(text) => toml::from_str(&text)
                .map(Some)
                .map_err(|source| StatusError::Parse {
                    path,
                    source: Box::new(source),
                }),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(source) => Err(StatusError::Io { path, source }),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ulid::Ulid;

    fn sample_report() -> BackupReport {
        BackupReport {
            snapshot_id: Ulid::from_parts(1_700_000_000_000, 1),
            files: 3,
            source_bytes: 1000,
            chunks_total: 5,
            chunks_unique: 4,
            chunks_uploaded: 2,
            chunks_deduped: 2,
            upload_bytes: 512,
            manifest_bytes: 64,
            compression: Default::default(),
        }
    }

    #[test]
    fn load_before_any_backup_is_none() {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(LastBackupRecord::load(dir.path()).unwrap(), None);
    }

    #[test]
    fn save_then_load_roundtrips_and_overwrites() {
        let dir = tempfile::tempdir().unwrap();
        let report = sample_report();
        let record = LastBackupRecord::from_report(&report, 1_700_000_000, 1234);
        record.save(dir.path()).unwrap();

        let loaded = LastBackupRecord::load(dir.path()).unwrap().unwrap();
        assert_eq!(loaded, record);
        assert_eq!(loaded.snapshot_id, report.snapshot_id.to_string());
        assert_eq!(loaded.upload_bytes, 512);

        // A second backup overwrites — only the most recent is kept.
        let mut report2 = sample_report();
        report2.snapshot_id = Ulid::from_parts(1_700_000_100_000, 2);
        report2.upload_bytes = 999;
        let record2 = LastBackupRecord::from_report(&report2, 1_700_000_100, 555);
        record2.save(dir.path()).unwrap();

        let loaded2 = LastBackupRecord::load(dir.path()).unwrap().unwrap();
        assert_eq!(loaded2, record2);
        assert_ne!(loaded2, loaded);
    }

    #[test]
    fn corrupt_record_is_a_typed_parse_error() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join(LAST_BACKUP_FILE), "not = [valid").unwrap();
        assert!(matches!(
            LastBackupRecord::load(dir.path()),
            Err(StatusError::Parse { .. })
        ));
    }
}
