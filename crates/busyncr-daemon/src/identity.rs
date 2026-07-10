//! Daemon-side identity: internal CA, server TLS identity, one-time
//! enrollment tokens, and the enrolled-client registry (PRD §3.4, FR1).
//!
//! Everything lives under one directory (by convention
//! `<store-root>/identity/`):
//!
//! ```text
//! identity/
//!   ca-cert.pem      internal CA certificate (public; copy to clients)
//!   ca-key.pem       internal CA private key           (0600 on unix)
//!   server-cert.pem  daemon TLS certificate, CA-signed
//!   server-key.pem   daemon TLS private key            (0600 on unix)
//!   tokens/<h>       one outstanding enrollment token per file, named by
//!                    the BLAKE3 hex of the token string; consumption is
//!                    `remove_file`, so a token is spendable exactly once
//!                    even with `enroll-token` running beside `serve`
//!   clients/<fp>.toml  one enrolled client per file, named by the BLAKE3
//!                    hex fingerprint of the client certificate DER
//! ```
//!
//! First call to [`DaemonIdentity::open_or_init`] bootstraps the CA and the
//! server certificate; later calls reload the same material, so the CA
//! survives daemon restarts (FR1 "CA bootstrap", FR8 groundwork).
//!
//! Revocation is registry-side: a revoked client still holds a certificate
//! that chains to the CA (the TLS handshake succeeds), but every RPC checks
//! the presented certificate's fingerprint against the registry and refuses
//! revoked or unknown entries.

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

use rand::CryptoRng;
use rcgen::{
    BasicConstraints, CertificateParams, CertificateSigningRequestParams, DnType, DnValue,
    ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair, KeyUsagePurpose,
};

/// File name of the CA certificate inside the identity directory.
pub const CA_CERT_FILE: &str = "ca-cert.pem";
/// File name of the CA private key inside the identity directory.
pub const CA_KEY_FILE: &str = "ca-key.pem";
/// File name of the server TLS certificate inside the identity directory.
pub const SERVER_CERT_FILE: &str = "server-cert.pem";
/// File name of the server TLS private key inside the identity directory.
pub const SERVER_KEY_FILE: &str = "server-key.pem";
/// Subdirectory holding outstanding one-time enrollment tokens.
pub const TOKENS_DIR: &str = "tokens";
/// Subdirectory holding the enrolled-client registry.
pub const CLIENTS_DIR: &str = "clients";

/// Byte length of a freshly minted enrollment token (hex-encoded on print).
const TOKEN_LEN: usize = 32;
/// Longest accepted client enrollment name.
const MAX_NAME_LEN: usize = 64;

/// Errors from identity bootstrap, enrollment, and the client registry.
#[derive(Debug, thiserror::Error)]
pub enum IdentityError {
    /// Filesystem access under the identity directory failed.
    #[error("identity I/O failed at {path}")]
    Io {
        /// Path being read or written.
        path: PathBuf,
        /// Underlying I/O error.
        #[source]
        source: std::io::Error,
    },

    /// Certificate or key generation/signing failed.
    #[error("certificate operation failed")]
    Cert(#[from] rcgen::Error),

    /// The presented CSR does not parse, fails its self-signature, or is
    /// otherwise unusable.
    #[error("certificate signing request rejected: {0}")]
    CsrRejected(String),

    /// The CSR carries no usable Common Name to enroll under.
    #[error("CSR must carry a Common Name (1..={MAX_NAME_LEN} printable chars) as the client's enrollment name")]
    BadName,

    /// An active (non-revoked) client with this name is already enrolled.
    #[error("a client named {0:?} is already enrolled; revoke it first or pick another name")]
    NameTaken(String),

    /// A registry file exists but does not parse as a client record.
    #[error("corrupt client registry entry at {path}")]
    RegistryParse {
        /// Offending registry file.
        path: PathBuf,
        /// Underlying TOML error.
        #[source]
        source: toml::de::Error,
    },

    /// Serializing a client record failed (should not happen for valid data).
    #[error("encoding client registry entry failed")]
    RegistryEncode(#[from] toml::ser::Error),
}

/// Standing of a certificate fingerprint in the client registry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClientStatus {
    /// Fingerprint never enrolled (or registry entry lost).
    Unknown,
    /// Enrolled and in good standing.
    Active,
    /// Enrolled but revoked by `busyncr-daemon revoke <name>`.
    Revoked,
}

/// A certificate freshly issued to an enrolling client.
#[derive(Debug, Clone)]
pub struct IssuedCert {
    /// PEM-encoded client certificate, signed by the daemon CA.
    pub cert_pem: String,
    /// Enrollment name (the CSR's Common Name).
    pub name: String,
    /// BLAKE3 hex fingerprint of the certificate DER (registry key).
    pub fingerprint: String,
}

/// One enrolled client, persisted as `clients/<fingerprint>.toml`.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct ClientRecord {
    name: String,
    fingerprint: String,
    revoked: bool,
}

/// The daemon's persistent cryptographic identity plus enrollment state.
pub struct DaemonIdentity {
    dir: PathBuf,
    ca_cert_pem: String,
    ca_cert_der: Vec<u8>,
    ca_key_pem: String,
    server_cert_pem: String,
    server_key_pem: String,
}

impl std::fmt::Debug for DaemonIdentity {
    /// Redacted: private keys must never appear in logs or panics.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DaemonIdentity")
            .field("dir", &self.dir)
            .field("ca_fingerprint", &self.ca_fingerprint())
            .finish_non_exhaustive()
    }
}

impl DaemonIdentity {
    /// Opens the identity directory, bootstrapping the internal CA and the
    /// server TLS certificate on first run (FR1 "CA bootstrap").
    ///
    /// Idempotent: subsequent calls reload the persisted material, so the CA
    /// (and therefore every issued client certificate) survives restarts.
    ///
    /// # Errors
    ///
    /// [`IdentityError::Io`] on filesystem trouble, [`IdentityError::Cert`]
    /// if generation of the CA or server certificate fails.
    pub fn open_or_init(dir: impl Into<PathBuf>) -> Result<Self, IdentityError> {
        let dir = dir.into();
        create_dir_all(&dir)?;
        create_dir_all(&dir.join(TOKENS_DIR))?;
        create_dir_all(&dir.join(CLIENTS_DIR))?;

        let ca_cert_path = dir.join(CA_CERT_FILE);
        let ca_key_path = dir.join(CA_KEY_FILE);
        let (ca_cert_pem, ca_key_pem) = if ca_cert_path.is_file() && ca_key_path.is_file() {
            (read_string(&ca_cert_path)?, read_string(&ca_key_path)?)
        } else {
            let key = KeyPair::generate()?;
            let mut params = CertificateParams::new(Vec::<String>::new())?;
            params
                .distinguished_name
                .push(DnType::CommonName, "BusyNCR internal CA");
            params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
            params.key_usages = vec![
                KeyUsagePurpose::KeyCertSign,
                KeyUsagePurpose::CrlSign,
                KeyUsagePurpose::DigitalSignature,
            ];
            let cert = params.self_signed(&key)?;
            let (cert_pem, key_pem) = (cert.pem(), key.serialize_pem());
            write_atomic(&ca_cert_path, cert_pem.as_bytes(), false)?;
            write_atomic(&ca_key_path, key_pem.as_bytes(), true)?;
            (cert_pem, key_pem)
        };
        let ca_cert_der = pem_to_der(&ca_cert_pem).ok_or_else(|| {
            IdentityError::CsrRejected("stored CA certificate is not valid PEM".into())
        })?;

        let server_cert_path = dir.join(SERVER_CERT_FILE);
        let server_key_path = dir.join(SERVER_KEY_FILE);
        let (server_cert_pem, server_key_pem) = if server_cert_path.is_file()
            && server_key_path.is_file()
        {
            (
                read_string(&server_cert_path)?,
                read_string(&server_key_path)?,
            )
        } else {
            let issuer = Issuer::from_ca_cert_pem(&ca_cert_pem, KeyPair::from_pem(&ca_key_pem)?)?;
            let key = KeyPair::generate()?;
            let mut params = CertificateParams::new(vec![
                busyncr_proto::TLS_SERVER_NAME.to_owned(),
                "localhost".to_owned(),
                "127.0.0.1".to_owned(),
                "::1".to_owned(),
            ])?;
            params
                .distinguished_name
                .push(DnType::CommonName, busyncr_proto::TLS_SERVER_NAME);
            params.is_ca = IsCa::ExplicitNoCa;
            params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
            params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
            let cert = params.signed_by(&key, &issuer)?;
            let (cert_pem, key_pem) = (cert.pem(), key.serialize_pem());
            write_atomic(&server_cert_path, cert_pem.as_bytes(), false)?;
            write_atomic(&server_key_path, key_pem.as_bytes(), true)?;
            (cert_pem, key_pem)
        };

        Ok(Self {
            dir,
            ca_cert_pem,
            ca_cert_der,
            ca_key_pem,
            server_cert_pem,
            server_key_pem,
        })
    }

    /// The identity directory this state lives in.
    #[must_use]
    pub fn dir(&self) -> &Path {
        &self.dir
    }

    /// PEM-encoded CA certificate (safe to hand to clients).
    #[must_use]
    pub fn ca_cert_pem(&self) -> &str {
        &self.ca_cert_pem
    }

    /// PEM-encoded server TLS certificate.
    #[must_use]
    pub fn server_cert_pem(&self) -> &str {
        &self.server_cert_pem
    }

    /// PEM-encoded server TLS private key.
    #[must_use]
    pub fn server_key_pem(&self) -> &str {
        &self.server_key_pem
    }

    /// BLAKE3 hex fingerprint of the CA certificate DER — print this next to
    /// enrollment tokens so operators can cross-check the CA file they copy.
    #[must_use]
    pub fn ca_fingerprint(&self) -> String {
        blake3::hash(&self.ca_cert_der).to_hex().to_string()
    }

    /// Mints a one-time enrollment token and persists its spend record.
    ///
    /// The token itself (hex, printed once, never stored) is returned; only
    /// its BLAKE3 hash touches disk, as an empty file whose removal is the
    /// atomic "spend" operation.
    ///
    /// # Errors
    ///
    /// [`IdentityError::Io`] if the token record cannot be written.
    pub fn mint_token<R: CryptoRng>(&self, rng: &mut R) -> Result<String, IdentityError> {
        let mut raw = [0u8; TOKEN_LEN];
        rng.fill_bytes(&mut raw);
        let token = hex(&raw);
        let path = self.token_path(&token);
        write_atomic(&path, b"", false)?;
        Ok(token)
    }

    /// Atomically consumes `token`. Returns `true` if it was outstanding
    /// (and is now spent), `false` if unknown or already used.
    ///
    /// # Errors
    ///
    /// [`IdentityError::Io`] on filesystem trouble other than "not found".
    pub fn consume_token(&self, token: &str) -> Result<bool, IdentityError> {
        let path = self.token_path(token);
        match fs::remove_file(&path) {
            Ok(()) => Ok(true),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
            Err(source) => Err(IdentityError::Io { path, source }),
        }
    }

    /// Signs an enrolling client's CSR and registers the resulting
    /// certificate (FR1 "cert issuance").
    ///
    /// The CSR's Common Name becomes the client's enrollment name. The
    /// issued certificate is forced to a client-auth profile (no CA bit, no
    /// SANs, EKU = ClientAuth) regardless of what the CSR asked for.
    ///
    /// # Errors
    ///
    /// [`IdentityError::CsrRejected`] / [`IdentityError::BadName`] for
    /// unusable CSRs, [`IdentityError::NameTaken`] if an active client
    /// already enrolled under that name.
    pub fn enroll_client(&self, csr_pem: &str) -> Result<IssuedCert, IdentityError> {
        let mut csr = CertificateSigningRequestParams::from_pem(csr_pem)
            .map_err(|e| IdentityError::CsrRejected(e.to_string()))?;
        let name = common_name(&csr.params).ok_or(IdentityError::BadName)?;

        if self.active_client_named(&name)?.is_some() {
            return Err(IdentityError::NameTaken(name));
        }

        // Enforce the client-auth certificate profile server-side.
        csr.params.is_ca = IsCa::ExplicitNoCa;
        csr.params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        csr.params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
        csr.params.subject_alt_names.clear();

        let issuer =
            Issuer::from_ca_cert_pem(&self.ca_cert_pem, KeyPair::from_pem(&self.ca_key_pem)?)?;
        let cert = csr.signed_by(&issuer)?;
        let fingerprint = blake3::hash(cert.der()).to_hex().to_string();

        let record = ClientRecord {
            name: name.clone(),
            fingerprint: fingerprint.clone(),
            revoked: false,
        };
        let body = toml::to_string_pretty(&record)?;
        write_atomic(&self.client_path(&fingerprint), body.as_bytes(), false)?;

        Ok(IssuedCert {
            cert_pem: cert.pem(),
            name,
            fingerprint,
        })
    }

    /// Looks up the registry standing of a certificate fingerprint (BLAKE3
    /// hex of the presented certificate DER). Called on every RPC.
    ///
    /// # Errors
    ///
    /// [`IdentityError::Io`] / [`IdentityError::RegistryParse`] on registry
    /// trouble; a missing entry is `Ok(ClientStatus::Unknown)`, not an error.
    pub fn client_status(&self, fingerprint: &str) -> Result<ClientStatus, IdentityError> {
        let path = self.client_path(fingerprint);
        let body = match fs::read_to_string(&path) {
            Ok(body) => body,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(ClientStatus::Unknown),
            Err(source) => return Err(IdentityError::Io { path, source }),
        };
        let record: ClientRecord = toml::from_str(&body)
            .map_err(|source| IdentityError::RegistryParse { path, source })?;
        Ok(if record.revoked {
            ClientStatus::Revoked
        } else {
            ClientStatus::Active
        })
    }

    /// Enrollment name registered under a certificate fingerprint, if any
    /// (FR-M1 M3.2: attributing a stored snapshot to the client that shipped
    /// it, for `busyncr-daemon status`'s "per enrolled client" breakdown).
    /// Returns the name regardless of revocation status — a revoked
    /// client's *past* snapshots still belong to it.
    ///
    /// # Errors
    ///
    /// [`IdentityError::Io`] / [`IdentityError::RegistryParse`] on registry
    /// trouble; an unknown fingerprint is `Ok(None)`, not an error.
    pub fn client_name(&self, fingerprint: &str) -> Result<Option<String>, IdentityError> {
        let path = self.client_path(fingerprint);
        match fs::read_to_string(&path) {
            Ok(body) => {
                let record: ClientRecord = toml::from_str(&body)
                    .map_err(|source| IdentityError::RegistryParse { path, source })?;
                Ok(Some(record.name))
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(source) => Err(IdentityError::Io { path, source }),
        }
    }

    /// Marks every active certificate enrolled under `name` as revoked.
    /// Returns how many certificates were revoked (0 = no such client).
    ///
    /// # Errors
    ///
    /// [`IdentityError::Io`] / [`IdentityError::RegistryParse`] on registry
    /// trouble.
    pub fn revoke(&self, name: &str) -> Result<usize, IdentityError> {
        let mut revoked = 0;
        for (path, mut record) in self.read_registry()? {
            if record.name == name && !record.revoked {
                record.revoked = true;
                let body = toml::to_string_pretty(&record)?;
                write_atomic(&path, body.as_bytes(), false)?;
                revoked += 1;
            }
        }
        Ok(revoked)
    }

    /// Returns the fingerprint of the active client enrolled as `name`, if
    /// any.
    fn active_client_named(&self, name: &str) -> Result<Option<String>, IdentityError> {
        Ok(self
            .read_registry()?
            .into_iter()
            .find(|(_, r)| r.name == name && !r.revoked)
            .map(|(_, r)| r.fingerprint))
    }

    /// Reads every registry entry (skipping stray non-`.toml` files).
    fn read_registry(&self) -> Result<Vec<(PathBuf, ClientRecord)>, IdentityError> {
        let dir = self.dir.join(CLIENTS_DIR);
        let entries = fs::read_dir(&dir).map_err(|source| IdentityError::Io {
            path: dir.clone(),
            source,
        })?;
        let mut out = Vec::new();
        for entry in entries {
            let entry = entry.map_err(|source| IdentityError::Io {
                path: dir.clone(),
                source,
            })?;
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) != Some("toml") {
                continue;
            }
            let body = read_string(&path)?;
            let record: ClientRecord =
                toml::from_str(&body).map_err(|source| IdentityError::RegistryParse {
                    path: path.clone(),
                    source,
                })?;
            out.push((path, record));
        }
        Ok(out)
    }

    fn token_path(&self, token: &str) -> PathBuf {
        let hash = blake3::hash(token.as_bytes()).to_hex().to_string();
        self.dir.join(TOKENS_DIR).join(hash)
    }

    fn client_path(&self, fingerprint: &str) -> PathBuf {
        // Fingerprints are hex we computed ourselves, but sanitize anyway so
        // a hostile value can never traverse out of the registry dir.
        let safe: String = fingerprint
            .chars()
            .filter(char::is_ascii_alphanumeric)
            .collect();
        self.dir.join(CLIENTS_DIR).join(format!("{safe}.toml"))
    }
}

/// Extracts and validates the CSR's Common Name.
fn common_name(params: &CertificateParams) -> Option<String> {
    let name = match params.distinguished_name.get(&DnType::CommonName)? {
        DnValue::Utf8String(s) => s.clone(),
        DnValue::PrintableString(s) => s.as_str().to_owned(),
        _ => return None,
    };
    let ok_len = !name.is_empty() && name.len() <= MAX_NAME_LEN;
    let ok_chars = name.chars().all(|c| !c.is_control());
    (ok_len && ok_chars).then_some(name)
}

/// Lowercase hex of arbitrary bytes.
fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    bytes
        .iter()
        .fold(String::with_capacity(bytes.len() * 2), |mut s, b| {
            let _ = write!(s, "{b:02x}");
            s
        })
}

/// Extracts the DER payload of the first PEM block in `pem`.
fn pem_to_der(pem: &str) -> Option<Vec<u8>> {
    let body: String = pem
        .lines()
        .filter(|l| !l.starts_with("-----"))
        .collect::<Vec<_>>()
        .join("");
    base64_decode(body.trim())
}

/// Minimal standard-alphabet base64 decoder (std has none; a full crate for
/// one PEM body would be overkill).
fn base64_decode(s: &str) -> Option<Vec<u8>> {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut rev = [255u8; 256];
    for (i, &c) in ALPHABET.iter().enumerate() {
        rev[c as usize] = u8::try_from(i).ok()?;
    }
    let raw: Vec<u8> = s.bytes().filter(|b| !b.is_ascii_whitespace()).collect();
    let stripped = match raw.iter().rev().take_while(|&&b| b == b'=').count() {
        pad @ (0..=2) => &raw[..raw.len() - pad],
        _ => return None,
    };
    let mut out = Vec::with_capacity(stripped.len() * 3 / 4);
    for chunk in stripped.chunks(4) {
        if chunk.len() == 1 {
            return None;
        }
        let mut acc = 0u32;
        for &c in chunk {
            let v = rev[c as usize];
            if v == 255 {
                return None;
            }
            acc = (acc << 6) | u32::from(v);
        }
        acc <<= 6 * (4 - chunk.len());
        let bytes = acc.to_be_bytes();
        out.extend_from_slice(&bytes[1..chunk.len()]);
    }
    Some(out)
}

fn create_dir_all(path: &Path) -> Result<(), IdentityError> {
    fs::create_dir_all(path).map_err(|source| IdentityError::Io {
        path: path.to_owned(),
        source,
    })
}

fn read_string(path: &Path) -> Result<String, IdentityError> {
    fs::read_to_string(path).map_err(|source| IdentityError::Io {
        path: path.to_owned(),
        source,
    })
}

/// Writes `data` atomically (tmp + rename); `restrict` narrows permissions
/// to owner-only before the rename (private keys).
fn write_atomic(path: &Path, data: &[u8], restrict: bool) -> Result<(), IdentityError> {
    let io_err = |source| IdentityError::Io {
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
        path.file_name().and_then(|n| n.to_str()).unwrap_or("id")
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
    let _ = restrict; // Windows ACLs inherit from the identity directory.
    fs::rename(&tmp, path).map_err(io_err)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fresh() -> (tempfile::TempDir, DaemonIdentity) {
        let dir = tempfile::tempdir().unwrap();
        let id = DaemonIdentity::open_or_init(dir.path().join("identity")).unwrap();
        (dir, id)
    }

    /// FR1 groundwork: the CA is created once and survives reopen — a daemon
    /// restart must not orphan previously issued client certificates.
    #[test]
    fn fr1_ca_bootstrap_is_idempotent_across_reopen() {
        let (dir, id) = fresh();
        let fp = id.ca_fingerprint();
        let server_pem = id.server_cert_pem().to_owned();
        drop(id);
        let id2 = DaemonIdentity::open_or_init(dir.path().join("identity")).unwrap();
        assert_eq!(id2.ca_fingerprint(), fp, "CA must persist across restarts");
        assert_eq!(id2.server_cert_pem(), server_pem);
    }

    #[test]
    fn fr1_token_is_single_use() {
        let (_dir, id) = fresh();
        let token = id.mint_token(&mut rand::rng()).unwrap();
        assert_eq!(token.len(), TOKEN_LEN * 2, "token prints as hex");
        assert!(id.consume_token(&token).unwrap(), "first spend succeeds");
        assert!(!id.consume_token(&token).unwrap(), "second spend fails");
        assert!(!id.consume_token("never-minted").unwrap());
    }

    #[test]
    fn fr1_enroll_register_revoke_lifecycle() {
        let (_dir, id) = fresh();

        // Build a CSR the way the client does.
        let key = KeyPair::generate().unwrap();
        let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
        params
            .distinguished_name
            .push(DnType::CommonName, "laptop-a");
        let csr_pem = params.serialize_request(&key).unwrap().pem().unwrap();

        let issued = id.enroll_client(&csr_pem).unwrap();
        assert_eq!(issued.name, "laptop-a");
        assert_eq!(
            id.client_status(&issued.fingerprint).unwrap(),
            ClientStatus::Active
        );

        // Same active name cannot enroll twice.
        let err = id.enroll_client(&csr_pem).unwrap_err();
        assert!(matches!(err, IdentityError::NameTaken(n) if n == "laptop-a"));

        // Revocation flips the registry status; unknown fingerprints stay Unknown.
        assert_eq!(id.revoke("laptop-a").unwrap(), 1);
        assert_eq!(
            id.client_status(&issued.fingerprint).unwrap(),
            ClientStatus::Revoked
        );
        assert_eq!(id.revoke("laptop-a").unwrap(), 0, "already revoked");
        assert_eq!(id.revoke("no-such").unwrap(), 0);
        assert_eq!(
            id.client_status(&"0".repeat(64)).unwrap(),
            ClientStatus::Unknown
        );

        // After revocation the name is free again.
        let issued2 = id.enroll_client(&csr_pem).unwrap();
        assert_ne!(issued2.fingerprint, issued.fingerprint);
        assert_eq!(
            id.client_status(&issued2.fingerprint).unwrap(),
            ClientStatus::Active
        );
    }

    #[test]
    fn enroll_rejects_garbage_and_nameless_csrs() {
        let (_dir, id) = fresh();
        assert!(matches!(
            id.enroll_client("not a csr").unwrap_err(),
            IdentityError::CsrRejected(_)
        ));

        // rcgen's default params pre-fill a placeholder CN; clear the DN to
        // produce a genuinely nameless CSR.
        let key = KeyPair::generate().unwrap();
        let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
        params.distinguished_name = rcgen::DistinguishedName::new();
        let csr_pem = params.serialize_request(&key).unwrap().pem().unwrap();
        assert!(matches!(
            id.enroll_client(&csr_pem).unwrap_err(),
            IdentityError::BadName
        ));
    }

    #[test]
    fn base64_decoder_roundtrips_pem_payloads() {
        assert_eq!(base64_decode("aGVsbG8=").unwrap(), b"hello");
        assert_eq!(base64_decode("aGVsbG8h").unwrap(), b"hello!");
        assert_eq!(base64_decode("aA==").unwrap(), b"h");
        assert_eq!(base64_decode("").unwrap(), Vec::<u8>::new());
        assert!(base64_decode("a").is_none());
        assert!(base64_decode("a!b=").is_none());
        // The identity's own CA PEM decodes to the DER we fingerprint.
        let (_dir, id) = fresh();
        assert_eq!(pem_to_der(id.ca_cert_pem()).unwrap(), id.ca_cert_der);
    }
}
