//! Daemon-wide configuration: the `auto_prune` control (FR-M1 M1.2), which
//! makes the PRD §3.5 auto-prune behavior an explicit, operator-visible
//! setting instead of an accident of `serve`'s internals.
//!
//! Persisted as `<store>/daemon.toml`, sitting next to `identity/` and
//! `objects/` at the store root. [`DaemonConfig::load_or_init`] creates the
//! file with the PRD §3.5 default (`auto_prune = true`) the first time a
//! store is opened without one, and reloads whatever is on disk on every
//! later `serve` start — so an operator's choice (and any hand-edit of the
//! file) survives restarts and is always visible by just reading the file.
//!
//! ```toml
//! # <store>/daemon.toml
//! auto_prune = true   # PRD §3.5 default: prune after every completed
//!                      # backup and on a daily timer. `false` = the grid
//!                      # is only applied by `busyncr-daemon prune`.
//! ```
//!
//! Manual `prune` (and `gc`, which is never automatic) stay available in
//! both modes — `auto_prune` only controls whether `serve` *also* triggers
//! prunes on its own.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

/// Errors loading or saving the daemon configuration.
#[derive(Debug, thiserror::Error)]
pub enum DaemonConfigError {
    /// The config file could not be read or written.
    #[error("daemon config I/O failed at {path}")]
    Io {
        /// The config file path.
        path: PathBuf,
        /// Underlying I/O error.
        #[source]
        source: std::io::Error,
    },

    /// The config file is not valid TOML for [`DaemonConfig`].
    #[error("daemon config {path} does not parse")]
    Parse {
        /// The config file path.
        path: PathBuf,
        /// Underlying TOML error.
        #[source]
        source: Box<toml::de::Error>,
    },

    /// Serializing the config failed (should not happen for valid data).
    #[error("encoding daemon config failed")]
    Encode(#[from] toml::ser::Error),
}

/// Daemon-wide configuration (currently just the FR-M1 M1.2 auto-prune
/// control; more fields land here as later slices need them).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DaemonConfig {
    /// Apply the retention grid after every completed backup and on a daily
    /// timer (`true`, the PRD §3.5 default) — or only when the operator
    /// runs `busyncr-daemon prune` (`false`). Manual `prune`/`gc` remain
    /// available either way (FR-M1 M1.2).
    #[serde(default = "default_auto_prune")]
    pub auto_prune: bool,
}

/// The PRD §3.5 default: prune automatically.
const fn default_auto_prune() -> bool {
    true
}

impl Default for DaemonConfig {
    fn default() -> Self {
        Self {
            auto_prune: default_auto_prune(),
        }
    }
}

impl DaemonConfig {
    /// File name of the daemon config inside the store root.
    pub const FILE_NAME: &'static str = "daemon.toml";

    /// Loads `<store_root>/daemon.toml`, writing the default (`auto_prune =
    /// true`) file if the store does not have one yet.
    ///
    /// # Errors
    ///
    /// [`DaemonConfigError::Io`] on filesystem trouble,
    /// [`DaemonConfigError::Parse`] if an existing file does not parse.
    pub fn load_or_init(store_root: &Path) -> Result<Self, DaemonConfigError> {
        let path = store_root.join(Self::FILE_NAME);
        match std::fs::read_to_string(&path) {
            Ok(text) => toml::from_str(&text).map_err(|source| DaemonConfigError::Parse {
                path,
                source: Box::new(source),
            }),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                let config = Self::default();
                config.save(store_root)?;
                Ok(config)
            }
            Err(source) => Err(DaemonConfigError::Io { path, source }),
        }
    }

    /// Writes this configuration to `<store_root>/daemon.toml`, creating the
    /// store root directory if it does not exist yet.
    ///
    /// # Errors
    ///
    /// [`DaemonConfigError::Io`] on filesystem trouble.
    pub fn save(&self, store_root: &Path) -> Result<(), DaemonConfigError> {
        std::fs::create_dir_all(store_root).map_err(|source| DaemonConfigError::Io {
            path: store_root.to_owned(),
            source,
        })?;
        let path = store_root.join(Self::FILE_NAME);
        let body = toml::to_string_pretty(self)?;
        std::fs::write(&path, body).map_err(|source| DaemonConfigError::Io { path, source })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn load_or_init_writes_and_reloads_the_default() {
        let dir = tempfile::tempdir().unwrap();
        let store_root = dir.path().join("store");
        std::fs::create_dir_all(&store_root).unwrap();

        let config = DaemonConfig::load_or_init(&store_root).unwrap();
        assert!(config.auto_prune, "PRD §3.5 default is auto_prune = true");
        assert!(store_root.join(DaemonConfig::FILE_NAME).is_file());

        // Reload picks up the persisted (default) value, not a fresh one.
        let reloaded = DaemonConfig::load_or_init(&store_root).unwrap();
        assert_eq!(reloaded, config);
    }

    #[test]
    fn load_or_init_respects_an_operator_hand_edit() {
        let dir = tempfile::tempdir().unwrap();
        let store_root = dir.path().join("store");
        std::fs::create_dir_all(&store_root).unwrap();
        std::fs::write(
            store_root.join(DaemonConfig::FILE_NAME),
            "auto_prune = false\n",
        )
        .unwrap();

        let config = DaemonConfig::load_or_init(&store_root).unwrap();
        assert!(!config.auto_prune);
    }

    #[test]
    fn malformed_config_is_a_typed_parse_error() {
        let dir = tempfile::tempdir().unwrap();
        let store_root = dir.path().join("store");
        std::fs::create_dir_all(&store_root).unwrap();
        std::fs::write(store_root.join(DaemonConfig::FILE_NAME), "not = [valid").unwrap();

        assert!(matches!(
            DaemonConfig::load_or_init(&store_root),
            Err(DaemonConfigError::Parse { .. })
        ));
    }
}
