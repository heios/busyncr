//! Client configuration file (TOML) for the `backup` subcommand (PRD §3.7,
//! SLICES S7).
//!
//! ```toml
//! # busyncr-client.toml
//! daemon = "https://backup-server:47820"
//! folders = ["C:/Users/alex/Documents", "D:/projects"]
//! # Committed after running `busyncr-client bench-chunking` (PRD §3.7).
//! # Suffixes: K = KiB, M = MiB; plain numbers are bytes.
//! chunk_target_size = "1M"
//! ```
//!
//! `folders` entries may be relative; they are resolved against the config
//! file's own directory by [`ClientConfig::load`].
//!
//! `chunk_target_size` is deliberately optional: until a size is committed,
//! `backup` refuses to run and points at `bench-chunking` (PRD §3.7 —
//! changing the size later resets dedup continuity), unless the operator
//! passes `--default-chunking` to accept the 1 MiB default.

use std::path::{Path, PathBuf};

use busyncr_core::chunking::{ChunkerConfig, ChunkingError};
use serde::Deserialize;

/// Errors from loading or interpreting the client configuration.
#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    /// The config file could not be read.
    #[error("cannot read config file {path}")]
    Io {
        /// The config file path.
        path: PathBuf,
        /// Underlying I/O error.
        #[source]
        source: std::io::Error,
    },

    /// The config file is not valid TOML for [`ClientConfig`].
    #[error("config file {path} does not parse")]
    Parse {
        /// The config file path.
        path: PathBuf,
        /// Underlying TOML error.
        #[source]
        source: Box<toml::de::Error>,
    },

    /// `folders` is empty — nothing to back up.
    #[error("config lists no folders to back up")]
    NoFolders,

    /// No chunk size committed and the default was not explicitly accepted
    /// (PRD §3.7).
    #[error(
        "no chunk_target_size committed in config: run `busyncr-client \
         bench-chunking <folder>` to pick a size empirically and set \
         chunk_target_size, or pass --default-chunking to accept the 1 MiB \
         default (changing the size later resets dedup continuity)"
    )]
    ChunkSizeUnset,

    /// `chunk_target_size` did not parse as a byte size.
    #[error("invalid chunk_target_size {value:?}: {reason} (use e.g. 256K, 1M, or bytes)")]
    BadChunkSize {
        /// The offending config value.
        value: String,
        /// Why it was rejected.
        reason: &'static str,
    },

    /// The parsed size is not a usable chunker configuration.
    #[error("chunk_target_size is not usable")]
    Chunking(#[from] ChunkingError),
}

/// Parsed client configuration.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClientConfig {
    /// Daemon endpoint, e.g. `https://backup-server:47820`.
    pub daemon: String,
    /// Folder trees to back up. Relative entries are resolved against the
    /// config file's directory by [`Self::load`].
    pub folders: Vec<PathBuf>,
    /// Committed CDC target chunk size (`256K`, `1M`, plain bytes, ...).
    /// `None` until the operator commits one — see [`Self::chunker`].
    #[serde(default)]
    pub chunk_target_size: Option<String>,
}

impl ClientConfig {
    /// Loads and validates the config file at `path`, resolving relative
    /// `folders` entries against the file's directory.
    ///
    /// # Errors
    ///
    /// [`ConfigError::Io`] / [`ConfigError::Parse`] on unreadable or
    /// malformed files, [`ConfigError::NoFolders`] if nothing is configured.
    pub fn load(path: &Path) -> Result<Self, ConfigError> {
        let text = std::fs::read_to_string(path).map_err(|source| ConfigError::Io {
            path: path.to_owned(),
            source,
        })?;
        let mut config: Self = toml::from_str(&text).map_err(|source| ConfigError::Parse {
            path: path.to_owned(),
            source: Box::new(source),
        })?;
        if config.folders.is_empty() {
            return Err(ConfigError::NoFolders);
        }
        if let Some(base) = path.parent() {
            for folder in &mut config.folders {
                if folder.is_relative() {
                    *folder = base.join(&*folder);
                }
            }
        }
        Ok(config)
    }

    /// Resolves the committed chunk size into a [`ChunkerConfig`]
    /// (min = target/4, max = target×4, per SLICES S1).
    ///
    /// With no committed size, refuses unless `allow_default` is set (the
    /// `--default-chunking` flag), in which case the 1 MiB default applies
    /// (PRD §3.7).
    ///
    /// # Errors
    ///
    /// [`ConfigError::ChunkSizeUnset`] when unset without `allow_default`;
    /// [`ConfigError::BadChunkSize`] / [`ConfigError::Chunking`] for values
    /// that do not parse or are outside the supported CDC range.
    pub fn chunker(&self, allow_default: bool) -> Result<ChunkerConfig, ConfigError> {
        match &self.chunk_target_size {
            Some(value) => {
                let bytes = parse_size(value)?;
                Ok(ChunkerConfig::with_target(bytes)?)
            }
            None if allow_default => Ok(ChunkerConfig::with_target(
                ChunkerConfig::DEFAULT_TARGET_SIZE,
            )?),
            None => Err(ConfigError::ChunkSizeUnset),
        }
    }
}

/// Parses a size like `256K`, `1M`, or `4096` into bytes (K = KiB, M = MiB).
///
/// # Errors
///
/// [`ConfigError::BadChunkSize`] on empty, non-numeric, or overflowing input.
pub fn parse_size(s: &str) -> Result<usize, ConfigError> {
    let bad = |reason: &'static str| ConfigError::BadChunkSize {
        value: s.to_owned(),
        reason,
    };
    let t = s.trim();
    if t.is_empty() {
        return Err(bad("empty size"));
    }
    let (digits, multiplier) = match t.chars().last() {
        Some('k') | Some('K') => (&t[..t.len() - 1], 1024usize),
        Some('m') | Some('M') => (&t[..t.len() - 1], 1024 * 1024),
        _ => (t, 1),
    };
    let value: usize = digits.parse().map_err(|_| bad("not a number"))?;
    value
        .checked_mul(multiplier)
        .ok_or_else(|| bad("overflows"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write_config(dir: &Path, body: &str) -> PathBuf {
        let path = dir.join("busyncr-client.toml");
        std::fs::write(&path, body).unwrap();
        path
    }

    #[test]
    fn load_parses_and_resolves_relative_folders() {
        let dir = tempfile::tempdir().unwrap();
        let path = write_config(
            dir.path(),
            r#"
daemon = "https://127.0.0.1:47820"
folders = ["data", "/absolute/other"]
chunk_target_size = "4K"
"#,
        );
        let config = ClientConfig::load(&path).unwrap();
        assert_eq!(config.daemon, "https://127.0.0.1:47820");
        assert_eq!(config.folders[0], dir.path().join("data"));
        assert_eq!(config.folders[1], PathBuf::from("/absolute/other"));
        let chunker = config.chunker(false).unwrap();
        assert_eq!(chunker.target_size(), 4096);
        assert_eq!(chunker.min_size(), 1024);
        assert_eq!(chunker.max_size(), 16384);
    }

    #[test]
    fn unset_chunk_size_refuses_and_points_at_bench_chunking() {
        let dir = tempfile::tempdir().unwrap();
        let path = write_config(dir.path(), "daemon = \"https://h:1\"\nfolders = [\"x\"]\n");
        let config = ClientConfig::load(&path).unwrap();
        let err = config.chunker(false).unwrap_err();
        assert!(matches!(err, ConfigError::ChunkSizeUnset));
        assert!(
            err.to_string().contains("bench-chunking"),
            "refusal must point the operator at bench-chunking: {err}"
        );
        assert!(
            err.to_string().contains("--default-chunking"),
            "refusal must mention the escape hatch: {err}"
        );

        // --default-chunking accepts the PRD §3.7 1 MiB default.
        let chunker = config.chunker(true).unwrap();
        assert_eq!(chunker.target_size(), 1024 * 1024);
    }

    #[test]
    fn bad_inputs_are_typed_errors() {
        let dir = tempfile::tempdir().unwrap();

        let missing = dir.path().join("nope.toml");
        assert!(matches!(
            ClientConfig::load(&missing),
            Err(ConfigError::Io { .. })
        ));

        let garbled = write_config(dir.path(), "daemon = [not toml");
        assert!(matches!(
            ClientConfig::load(&garbled),
            Err(ConfigError::Parse { .. })
        ));

        let empty = write_config(dir.path(), "daemon = \"https://h:1\"\nfolders = []\n");
        assert!(matches!(
            ClientConfig::load(&empty),
            Err(ConfigError::NoFolders)
        ));

        let bad_size = write_config(
            dir.path(),
            "daemon = \"https://h:1\"\nfolders = [\"x\"]\nchunk_target_size = \"12Q\"\n",
        );
        let config = ClientConfig::load(&bad_size).unwrap();
        assert!(matches!(
            config.chunker(false),
            Err(ConfigError::BadChunkSize { .. })
        ));
    }

    #[test]
    fn parse_size_understands_suffixes() {
        assert_eq!(parse_size("256K").unwrap(), 256 * 1024);
        assert_eq!(parse_size("1m").unwrap(), 1024 * 1024);
        assert_eq!(parse_size("4096").unwrap(), 4096);
        assert!(parse_size("").is_err());
        assert!(parse_size("12Q").is_err());
    }
}
