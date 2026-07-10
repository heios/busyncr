//! Client-side enrollment and mTLS identity state (FR1, PRD §3.4).
//!
//! Enrollment flow:
//!
//! 1. The operator runs `busyncr-daemon enroll-token` on the server, copies
//!    the printed one-time token and the daemon's `ca-cert.pem` to this
//!    host.
//! 2. [`request_enrollment`] generates a fresh keypair + CSR (Common Name =
//!    the client's enrollment name), connects over TLS trusting exactly
//!    that CA (server certificate pinning), and trades token + CSR for a
//!    CA-signed client certificate.
//! 3. [`save_identity`] persists the material into the client state
//!    directory; [`ensure_data_key`] creates the backup set's data key on
//!    first enrollment (FR1 "keyfile creation" — the key later exported via
//!    the passphrase-protected keyfile of PRD §3.4).
//! 4. [`connect_authenticated`] opens the mTLS channel every other RPC uses.
//!
//! State directory layout:
//!
//! ```text
//! <state>/
//!   client-key.pem   this machine's TLS private key   (0600 on unix)
//!   client-cert.pem  CA-signed client certificate
//!   ca-cert.pem      daemon CA certificate (trust anchor)
//!   data.key         32-byte backup-set data key      (0600 on unix)
//! ```

// `tonic::Status` alone is 176 bytes and rides inside `EnrollError`; tonic's
// API returns it by value everywhere, so boxing at every conversion would
// outweigh the win.
#![allow(clippy::result_large_err)]

use std::fs;
use std::io::Write as _;
use std::path::{Path, PathBuf};

use busyncr_core::crypto::DataKey;
use busyncr_proto::v1::busyncr_client::BusyncrClient;
use busyncr_proto::v1::{EnrollRequest, EnrollResponse};
use busyncr_proto::{MAX_MESSAGE_SIZE, TLS_SERVER_NAME};
use rand::CryptoRng;
use rcgen::{CertificateParams, DnType, KeyPair};
use tonic::transport::{Certificate, Channel, ClientTlsConfig, Endpoint, Identity};

/// Applies the protocol-wide message-size limits to a client stub
/// ([`busyncr_proto::MAX_MESSAGE_SIZE`]): tonic's 4 MiB decode default is
/// smaller than a single legal chunk blob (max chunk size + AEAD overhead),
/// so every stub — upload and the S8 restore/download path alike — must
/// raise it or large-chunk transfers abort mid-stream.
fn with_message_limits(client: BusyncrClient<Channel>) -> BusyncrClient<Channel> {
    client
        .max_decoding_message_size(MAX_MESSAGE_SIZE)
        .max_encoding_message_size(MAX_MESSAGE_SIZE)
}

/// File name of the client TLS private key inside the state directory.
pub const CLIENT_KEY_FILE: &str = "client-key.pem";
/// File name of the client TLS certificate inside the state directory.
pub const CLIENT_CERT_FILE: &str = "client-cert.pem";
/// File name of the pinned daemon CA certificate inside the state directory.
pub const CA_CERT_FILE: &str = "ca-cert.pem";
/// File name of the raw backup-set data key inside the state directory.
pub const DATA_KEY_FILE: &str = "data.key";

/// Errors from enrollment and mTLS channel setup.
#[derive(Debug, thiserror::Error)]
pub enum EnrollError {
    /// Filesystem access under the client state directory failed.
    #[error("client state I/O failed at {path}")]
    Io {
        /// Path being read or written.
        path: PathBuf,
        /// Underlying I/O error.
        #[source]
        source: std::io::Error,
    },

    /// Key or CSR generation failed.
    #[error("key/CSR generation failed")]
    Keygen(#[from] rcgen::Error),

    /// The daemon URL is not a valid endpoint, TLS setup failed, or the
    /// connection could not be established.
    #[error("connecting to daemon failed")]
    Transport(#[from] tonic::transport::Error),

    /// The daemon refused the RPC (bad token, name taken, revoked, ...).
    #[error("daemon refused enrollment: {0}")]
    Rpc(#[from] tonic::Status),

    /// The daemon's response was structurally unusable.
    #[error("daemon returned an unusable enrollment response: {0}")]
    BadResponse(&'static str),

    /// The persisted data key has the wrong size.
    #[error("corrupt data key at {path}: expected 32 bytes, found {found}")]
    BadDataKey {
        /// Offending key file.
        path: PathBuf,
        /// Actual byte length found.
        found: usize,
    },
}

/// Everything [`request_enrollment`] needs.
#[derive(Debug, Clone)]
pub struct EnrollmentRequest {
    /// Daemon endpoint, e.g. `https://backup.local:47820`.
    pub daemon_url: String,
    /// PEM contents of the daemon's CA certificate (the pin).
    pub ca_cert_pem: String,
    /// One-time token from `busyncr-daemon enroll-token`.
    pub token: String,
    /// This machine's enrollment name (certificate Common Name; the handle
    /// `busyncr-daemon revoke <name>` uses).
    pub name: String,
}

/// The identity material a successful enrollment yields.
#[derive(Clone)]
pub struct EnrolledIdentity {
    /// CA-signed client certificate (PEM).
    pub cert_pem: String,
    /// The private key generated locally for the CSR (PEM). Never left this
    /// machine.
    pub key_pem: String,
    /// The daemon CA certificate (PEM) — the pin we verified against.
    pub ca_cert_pem: String,
}

impl std::fmt::Debug for EnrolledIdentity {
    /// Redacted: the private key must never appear in logs or panics.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EnrolledIdentity")
            .field("cert_pem", &self.cert_pem)
            .finish_non_exhaustive()
    }
}

/// Performs FR1 enrollment against a fresh or running daemon: generate
/// keypair + CSR locally, connect over TLS trusting exactly the provided CA
/// certificate, present the one-time token, receive the signed certificate.
///
/// The private key is generated on this machine and never transmitted
/// (PRD §3.4: identity is per-machine, never migrated).
///
/// # Errors
///
/// [`EnrollError::Keygen`] for local key/CSR trouble,
/// [`EnrollError::Transport`] when the daemon is unreachable or its
/// certificate does not verify against the pinned CA, [`EnrollError::Rpc`]
/// when the daemon refuses (invalid token, name taken, ...).
pub async fn request_enrollment(req: &EnrollmentRequest) -> Result<EnrolledIdentity, EnrollError> {
    let key = KeyPair::generate()?;
    let mut params = CertificateParams::new(Vec::<String>::new())?;
    params
        .distinguished_name
        .push(DnType::CommonName, req.name.as_str());
    let csr_pem = params.serialize_request(&key)?.pem()?;

    let tls = ClientTlsConfig::new()
        .ca_certificate(Certificate::from_pem(&req.ca_cert_pem))
        .domain_name(TLS_SERVER_NAME);
    let channel = Endpoint::from_shared(req.daemon_url.clone())?
        .tls_config(tls)?
        .connect()
        .await?;

    let response: EnrollResponse = with_message_limits(BusyncrClient::new(channel))
        .enroll(EnrollRequest {
            token: req.token.clone(),
            csr_pem,
        })
        .await?
        .into_inner();
    if response.cert_pem.trim().is_empty() {
        return Err(EnrollError::BadResponse("empty certificate"));
    }

    Ok(EnrolledIdentity {
        cert_pem: response.cert_pem,
        key_pem: key.serialize_pem(),
        // Keep trusting the CA we pinned for this enrollment, not whatever
        // the response carried.
        ca_cert_pem: req.ca_cert_pem.clone(),
    })
}

/// Persists enrolled identity material into `state_dir` (created if absent).
///
/// # Errors
///
/// [`EnrollError::Io`] on filesystem trouble.
pub fn save_identity(state_dir: &Path, identity: &EnrolledIdentity) -> Result<(), EnrollError> {
    fs::create_dir_all(state_dir).map_err(|source| EnrollError::Io {
        path: state_dir.to_owned(),
        source,
    })?;
    write_atomic(
        &state_dir.join(CLIENT_KEY_FILE),
        identity.key_pem.as_bytes(),
        true,
    )?;
    write_atomic(
        &state_dir.join(CLIENT_CERT_FILE),
        identity.cert_pem.as_bytes(),
        false,
    )?;
    write_atomic(
        &state_dir.join(CA_CERT_FILE),
        identity.ca_cert_pem.as_bytes(),
        false,
    )?;
    Ok(())
}

/// Ensures the backup set's data key exists in `state_dir`, generating a
/// fresh one from `rng` on first enrollment (FR1 "keyfile creation").
///
/// Returns `true` if a new key was created, `false` if one already existed
/// (re-enrollment after certificate loss must not rotate the data key —
/// existing history stays decryptable, PRD §3.4).
///
/// # Errors
///
/// [`EnrollError::Io`] on filesystem trouble, [`EnrollError::BadDataKey`] if
/// an existing key file is malformed.
pub fn ensure_data_key<R: CryptoRng>(state_dir: &Path, rng: &mut R) -> Result<bool, EnrollError> {
    load_data_key(state_dir)
        .map(|_| false)
        .or_else(|e| match e {
            EnrollError::Io { ref source, .. } if source.kind() == std::io::ErrorKind::NotFound => {
                fs::create_dir_all(state_dir).map_err(|source| EnrollError::Io {
                    path: state_dir.to_owned(),
                    source,
                })?;
                let key = DataKey::generate(rng);
                write_atomic(&state_dir.join(DATA_KEY_FILE), key.as_bytes(), true)?;
                Ok(true)
            }
            other => Err(other),
        })
}

/// Loads the backup set's data key from `state_dir`.
///
/// # Errors
///
/// [`EnrollError::Io`] if the file is unreadable (including not-yet-created),
/// [`EnrollError::BadDataKey`] if it has the wrong size.
pub fn load_data_key(state_dir: &Path) -> Result<DataKey, EnrollError> {
    let path = state_dir.join(DATA_KEY_FILE);
    let bytes = fs::read(&path).map_err(|source| EnrollError::Io {
        path: path.clone(),
        source,
    })?;
    let raw: [u8; 32] = bytes
        .as_slice()
        .try_into()
        .map_err(|_| EnrollError::BadDataKey {
            path,
            found: bytes.len(),
        })?;
    Ok(DataKey::from_bytes(raw))
}

/// Opens an mTLS channel to the daemon using the enrolled identity in
/// `state_dir` and returns the ready gRPC client (used by every
/// post-enrollment RPC).
///
/// # Errors
///
/// [`EnrollError::Io`] if identity files are missing (not enrolled),
/// [`EnrollError::Transport`] if the connection or TLS handshake fails.
pub async fn connect_authenticated(
    daemon_url: &str,
    state_dir: &Path,
) -> Result<BusyncrClient<Channel>, EnrollError> {
    let read = |name: &str| -> Result<String, EnrollError> {
        let path = state_dir.join(name);
        fs::read_to_string(&path).map_err(|source| EnrollError::Io { path, source })
    };
    let tls = ClientTlsConfig::new()
        .ca_certificate(Certificate::from_pem(read(CA_CERT_FILE)?))
        .identity(Identity::from_pem(
            read(CLIENT_CERT_FILE)?,
            read(CLIENT_KEY_FILE)?,
        ))
        .domain_name(TLS_SERVER_NAME);
    let channel = Endpoint::from_shared(daemon_url.to_owned())?
        .tls_config(tls)?
        .connect()
        .await?;
    Ok(with_message_limits(BusyncrClient::new(channel)))
}

/// Opens a TLS channel that trusts `ca_cert_pem` but presents **no** client
/// certificate. Only `Enroll` is reachable this way; exposed so tests can
/// prove every other RPC refuses un-enrolled callers (FR1).
///
/// # Errors
///
/// [`EnrollError::Transport`] if the connection or TLS handshake fails.
pub async fn connect_unauthenticated(
    daemon_url: &str,
    ca_cert_pem: &str,
) -> Result<BusyncrClient<Channel>, EnrollError> {
    let tls = ClientTlsConfig::new()
        .ca_certificate(Certificate::from_pem(ca_cert_pem))
        .domain_name(TLS_SERVER_NAME);
    let channel = Endpoint::from_shared(daemon_url.to_owned())?
        .tls_config(tls)?
        .connect()
        .await?;
    Ok(with_message_limits(BusyncrClient::new(channel)))
}

/// Writes `data` atomically (tmp + rename); `restrict` narrows permissions
/// to owner-only before the rename (private key material).
fn write_atomic(path: &Path, data: &[u8], restrict: bool) -> Result<(), EnrollError> {
    let io_err = |source| EnrollError::Io {
        path: path.to_owned(),
        source,
    };
    let parent = path.parent().ok_or_else(|| {
        io_err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "path has no parent directory",
        ))
    })?;
    let tmp = parent.join(format!(
        ".tmp-{}",
        path.file_name().and_then(|n| n.to_str()).unwrap_or("state")
    ));
    let mut file = fs::File::create(&tmp).map_err(io_err)?;
    file.write_all(data).map_err(io_err)?;
    file.sync_all().map_err(io_err)?;
    drop(file);
    #[cfg(unix)]
    if restrict {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&tmp, fs::Permissions::from_mode(0o600)).map_err(io_err)?;
    }
    #[cfg(not(unix))]
    let _ = restrict; // Windows ACLs inherit from the state directory.
    fs::rename(&tmp, path).map_err(io_err)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::StdRng;
    use rand::SeedableRng;

    #[test]
    fn data_key_created_once_and_reloaded_stable() {
        let dir = tempfile::tempdir().unwrap();
        let state = dir.path().join("state");
        let mut rng = StdRng::seed_from_u64(7);

        assert!(
            ensure_data_key(&state, &mut rng).unwrap(),
            "first call creates"
        );
        let key = load_data_key(&state).unwrap();
        assert!(
            !ensure_data_key(&state, &mut rng).unwrap(),
            "second call must keep the existing key"
        );
        assert_eq!(load_data_key(&state).unwrap(), key);
    }

    #[test]
    fn corrupt_data_key_is_reported_not_used() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join(DATA_KEY_FILE), b"short").unwrap();
        let err = load_data_key(dir.path()).unwrap_err();
        assert!(matches!(err, EnrollError::BadDataKey { found: 5, .. }));
        // ensure_data_key must refuse to silently overwrite it.
        let mut rng = StdRng::seed_from_u64(7);
        assert!(matches!(
            ensure_data_key(dir.path(), &mut rng).unwrap_err(),
            EnrollError::BadDataKey { .. }
        ));
    }
}
