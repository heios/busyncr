//! gRPC service (PRD §3.2): tonic implementation of `busyncr.v1.Busyncr`
//! backed by the [`ChunkStore`].
//!
//! Since S6 the production path is [`serve_tls`]: mutual TLS against the
//! daemon's internal CA ([`DaemonIdentity`]), with `Enroll` the only RPC a
//! connection without a client certificate may call (that is how a new
//! client gets its certificate, FR1). Every other RPC demands a presented
//! certificate whose fingerprint is registered and not revoked. The plain
//! [`serve`] path remains for in-process tests only; without an identity
//! attached, `Enroll` answers `UNIMPLEMENTED`.
//!
//! Chunk and manifest payloads are opaque to the daemon: since S7 they are
//! encrypted client-side (PRD §3.4), so no handler decodes or verifies them
//! against plaintext hashes — `PutManifest` carries the snapshot ID and the
//! chunk-reference list as explicit request fields instead.
//!
//! # Status mapping
//!
//! | outcome                               | gRPC status          |
//! |---------------------------------------|----------------------|
//! | malformed chunk/snapshot ID           | `INVALID_ARGUMENT`   |
//! | chunk/snapshot not found              | `NOT_FOUND`          |
//! | snapshot already exists               | `ALREADY_EXISTS`     |
//! | manifest references unknown chunk     | `FAILED_PRECONDITION`|
//! | stored blob fails verification (FR9)  | `DATA_LOSS`          |
//! | I/O / index failure                   | `INTERNAL`           |
//! | no client certificate presented (FR1) | `UNAUTHENTICATED`    |
//! | certificate unknown to the registry   | `UNAUTHENTICATED`    |
//! | certificate revoked (FR1)             | `PERMISSION_DENIED`  |
//! | bad / reused enrollment token (FR1)   | `PERMISSION_DENIED`  |
//! | unusable CSR                          | `INVALID_ARGUMENT`   |
//! | enrollment name already active        | `ALREADY_EXISTS`     |

// `tonic::Status` is 176 bytes; every tonic handler and helper in the
// ecosystem returns `Result<_, Status>` by value. Boxing it here would only
// add friction at the trait boundary we don't control.
#![allow(clippy::result_large_err)]

use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;

use busyncr_core::chunking::ChunkId;
use busyncr_proto::v1::busyncr_server::{Busyncr, BusyncrServer};
use busyncr_proto::v1::{
    ChunkBlob, EnrollRequest, EnrollResponse, GetChunksRequest, GetManifestRequest,
    GetManifestResponse, HasChunksRequest, HasChunksResponse, ListSnapshotsRequest,
    ListSnapshotsResponse, PutManifestRequest, PutManifestResponse, UploadChunksResponse,
};
use tokio::net::TcpListener;
use tokio_stream::wrappers::{ReceiverStream, TcpListenerStream};
use tokio_stream::StreamExt;
use tonic::transport::{Certificate, Identity, ServerTlsConfig};
use tonic::{Request, Response, Status, Streaming};
use ulid::Ulid;

use crate::identity::{ClientStatus, DaemonIdentity, IdentityError};
use crate::store::{ChunkStore, StoreError};

/// Errors from running the gRPC server.
#[derive(Debug, thiserror::Error)]
pub enum ServeError {
    /// The tonic transport failed (bind, accept, or protocol error).
    #[error("gRPC transport error")]
    Transport(#[from] tonic::transport::Error),
}

/// The daemon's implementation of the `busyncr.v1.Busyncr` service.
#[derive(Clone)]
pub struct BusyncrService {
    store: Arc<ChunkStore>,
    /// mTLS enforcement state; `None` only on the insecure in-process test
    /// path ([`serve`]), where enrollment is unavailable and no RPC checks
    /// client certificates.
    auth: Option<Arc<DaemonIdentity>>,
}

impl BusyncrService {
    /// Wraps a chunk store for serving **without** authentication.
    ///
    /// In-process tests only: no RPC checks client certificates and
    /// `Enroll` answers `UNIMPLEMENTED`. Production serving goes through
    /// [`Self::with_auth`] / [`serve_tls`].
    #[must_use]
    pub fn new(store: Arc<ChunkStore>) -> Self {
        Self { store, auth: None }
    }

    /// Wraps a chunk store plus the daemon identity: every RPC except
    /// `Enroll` then requires a registered, non-revoked client certificate
    /// (FR1).
    #[must_use]
    pub fn with_auth(store: Arc<ChunkStore>, identity: Arc<DaemonIdentity>) -> Self {
        Self {
            store,
            auth: Some(identity),
        }
    }

    /// Enforces mTLS client authentication for one request (FR1).
    ///
    /// `fingerprint` comes from [`peer_fingerprint`] (extracted before any
    /// await so streaming requests need not be `Sync`). No-op when this
    /// service was built without auth ([`Self::new`]). Otherwise the
    /// connection must have presented a certificate (rustls has already
    /// verified it chains to the internal CA) whose BLAKE3 fingerprint is
    /// registered and not revoked.
    async fn authenticate(&self, fingerprint: Option<String>) -> Result<(), Status> {
        let Some(identity) = &self.auth else {
            return Ok(());
        };
        let fingerprint = fingerprint.ok_or_else(|| {
            Status::unauthenticated(
                "client certificate required: enroll first (busyncr-client enroll)",
            )
        })?;
        let identity = Arc::clone(identity);
        let status = tokio::task::spawn_blocking(move || identity.client_status(&fingerprint))
            .await
            .map_err(|e| Status::internal(format!("auth task failed: {e}")))?
            .map_err(status_from_identity)?;
        match status {
            ClientStatus::Active => Ok(()),
            ClientStatus::Revoked => Err(Status::permission_denied(
                "client certificate has been revoked",
            )),
            ClientStatus::Unknown => Err(Status::unauthenticated(
                "client certificate is not enrolled with this daemon",
            )),
        }
    }

    /// Wraps this service in the tonic-generated server type, ready to be
    /// added to a `tonic::transport::Server`.
    #[must_use]
    pub fn into_server(self) -> BusyncrServer<Self> {
        BusyncrServer::new(self)
    }

    /// Runs a store operation on the blocking pool (redb + file I/O must not
    /// block the async executor).
    async fn blocking<T, F>(&self, op: F) -> Result<T, Status>
    where
        T: Send + 'static,
        F: FnOnce(&ChunkStore) -> Result<T, StoreError> + Send + 'static,
    {
        let store = Arc::clone(&self.store);
        tokio::task::spawn_blocking(move || op(&store))
            .await
            .map_err(|e| Status::internal(format!("store task failed: {e}")))?
            .map_err(status_from_store)
    }
}

/// Serves the Busyncr service on an already-bound listener until `shutdown`
/// resolves — **without TLS or authentication**.
///
/// In-process tests only (bind loopback). The production path is
/// [`serve_tls`]. Binding first (rather than passing an address) lets tests
/// use an ephemeral port and know it before the server starts.
///
/// # Errors
///
/// Returns [`ServeError::Transport`] if the transport fails.
pub async fn serve(
    store: Arc<ChunkStore>,
    listener: TcpListener,
    shutdown: impl Future<Output = ()>,
) -> Result<(), ServeError> {
    tonic::transport::Server::builder()
        .add_service(BusyncrService::new(store).into_server())
        .serve_with_incoming_shutdown(TcpListenerStream::new(listener), shutdown)
        .await?;
    Ok(())
}

/// Serves the Busyncr service over mutual TLS until `shutdown` resolves
/// (FR1, PRD §3.4).
///
/// The server presents `identity`'s CA-signed certificate; clients may
/// present a certificate chaining to the internal CA (`client_auth_optional`
/// — a certificate-less connection can still reach `Enroll`, which is how it
/// obtains one). Per-RPC enforcement of "registered and not revoked" happens
/// in [`BusyncrService::authenticate`].
///
/// # Errors
///
/// Returns [`ServeError::Transport`] if TLS setup or the transport fails.
pub async fn serve_tls(
    store: Arc<ChunkStore>,
    identity: Arc<DaemonIdentity>,
    listener: TcpListener,
    shutdown: impl Future<Output = ()>,
) -> Result<(), ServeError> {
    let tls = ServerTlsConfig::new()
        .identity(Identity::from_pem(
            identity.server_cert_pem(),
            identity.server_key_pem(),
        ))
        .client_ca_root(Certificate::from_pem(identity.ca_cert_pem()))
        .client_auth_optional(true);
    tonic::transport::Server::builder()
        .tls_config(tls)?
        .add_service(BusyncrService::with_auth(store, identity).into_server())
        .serve_with_incoming_shutdown(TcpListenerStream::new(listener), shutdown)
        .await?;
    Ok(())
}

/// Binds `addr` and returns the listener plus its actual local address
/// (useful with port 0).
///
/// # Errors
///
/// Returns the bind error unchanged.
pub async fn bind(addr: SocketAddr) -> std::io::Result<(TcpListener, SocketAddr)> {
    let listener = TcpListener::bind(addr).await?;
    let local = listener.local_addr()?;
    Ok((listener, local))
}

/// BLAKE3 hex fingerprint of the TLS client certificate presented on this
/// request's connection, if any.
fn peer_fingerprint<T>(request: &Request<T>) -> Option<String> {
    request.peer_certs().and_then(|certs| {
        certs
            .first()
            .map(|c| blake3::hash(c.as_ref()).to_hex().to_string())
    })
}

/// Maps an identity/enrollment failure onto the closest gRPC status (table
/// in the module docs).
fn status_from_identity(err: IdentityError) -> Status {
    match &err {
        IdentityError::CsrRejected(_) | IdentityError::BadName => {
            Status::invalid_argument(err.to_string())
        }
        IdentityError::NameTaken(_) => Status::already_exists(err.to_string()),
        _ => Status::internal(err.to_string()),
    }
}

/// Maps a store failure onto the closest gRPC status (table in the module
/// docs).
fn status_from_store(err: StoreError) -> Status {
    match &err {
        StoreError::ChunkNotFound(_) | StoreError::SnapshotNotFound(_) => {
            Status::not_found(err.to_string())
        }
        StoreError::SnapshotExists(_) => Status::already_exists(err.to_string()),
        StoreError::UnknownChunkRef { .. } | StoreError::StillReferenced { .. } => {
            Status::failed_precondition(err.to_string())
        }
        StoreError::Integrity(_) => Status::data_loss(err.to_string()),
        StoreError::Manifest(_) => Status::invalid_argument(err.to_string()),
        _ => Status::internal(err.to_string()),
    }
}

/// Parses a wire chunk ID (must be exactly 32 raw bytes).
fn parse_chunk_id(bytes: &[u8]) -> Result<ChunkId, Status> {
    let raw: [u8; ChunkId::LEN] = bytes.try_into().map_err(|_| {
        Status::invalid_argument(format!(
            "chunk ID must be {} bytes, got {}",
            ChunkId::LEN,
            bytes.len()
        ))
    })?;
    Ok(ChunkId::from_bytes(raw))
}

/// Parses a wire snapshot ID (must be exactly 16 raw ULID bytes).
fn parse_snapshot_id(bytes: &[u8]) -> Result<Ulid, Status> {
    let raw: [u8; 16] = bytes.try_into().map_err(|_| {
        Status::invalid_argument(format!("snapshot ID must be 16 bytes, got {}", bytes.len()))
    })?;
    Ok(Ulid::from_bytes(raw))
}

#[tonic::async_trait]
impl Busyncr for BusyncrService {
    async fn enroll(
        &self,
        request: Request<EnrollRequest>,
    ) -> Result<Response<EnrollResponse>, Status> {
        // Deliberately NOT behind `authenticate`: enrollment is how a
        // certificate-less client obtains its certificate (FR1). The
        // one-time token is the credential here.
        let Some(identity) = &self.auth else {
            return Err(Status::unimplemented(
                "enrollment (FR1) requires the TLS-enabled server; this instance runs the \
                 insecure in-process test path",
            ));
        };
        let identity = Arc::clone(identity);
        let EnrollRequest { token, csr_pem } = request.into_inner();
        let response = tokio::task::spawn_blocking(move || {
            if !identity
                .consume_token(&token)
                .map_err(status_from_identity)?
            {
                return Err(Status::permission_denied(
                    "invalid or already-used enrollment token; mint one with \
                     `busyncr-daemon enroll-token`",
                ));
            }
            let issued = identity
                .enroll_client(&csr_pem)
                .map_err(status_from_identity)?;
            Ok(EnrollResponse {
                cert_pem: issued.cert_pem,
                ca_cert_pem: identity.ca_cert_pem().to_owned(),
            })
        })
        .await
        .map_err(|e| Status::internal(format!("enrollment task failed: {e}")))??;
        Ok(Response::new(response))
    }

    async fn list_snapshots(
        &self,
        request: Request<ListSnapshotsRequest>,
    ) -> Result<Response<ListSnapshotsResponse>, Status> {
        self.authenticate(peer_fingerprint(&request)).await?;
        let ids = self.blocking(|store| store.list_snapshots()).await?;
        Ok(Response::new(ListSnapshotsResponse {
            snapshot_ids: ids.into_iter().map(|u| u.to_bytes().to_vec()).collect(),
        }))
    }

    async fn has_chunks(
        &self,
        request: Request<HasChunksRequest>,
    ) -> Result<Response<HasChunksResponse>, Status> {
        self.authenticate(peer_fingerprint(&request)).await?;
        let ids = request
            .into_inner()
            .chunk_ids
            .iter()
            .map(|b| parse_chunk_id(b))
            .collect::<Result<Vec<_>, _>>()?;

        let missing = self
            .blocking(move |store| {
                let mut missing = Vec::new();
                for id in ids {
                    if !store.has_chunk(id)? {
                        missing.push(id);
                    }
                }
                Ok(missing)
            })
            .await?;

        Ok(Response::new(HasChunksResponse {
            missing_chunk_ids: missing
                .into_iter()
                .map(|id| id.as_bytes().to_vec())
                .collect(),
        }))
    }

    async fn upload_chunks(
        &self,
        request: Request<Streaming<ChunkBlob>>,
    ) -> Result<Response<UploadChunksResponse>, Status> {
        self.authenticate(peer_fingerprint(&request)).await?;
        let mut stream = request.into_inner();
        let mut stored = 0u64;
        let mut already_present = 0u64;

        while let Some(blob) = stream.next().await {
            let blob = blob?;
            let id = parse_chunk_id(&blob.chunk_id)?;
            // The blob is opaque ciphertext (PRD §3.4): stored as-is under
            // the client's declared chunk ID.
            let newly_stored = self
                .blocking(move |store| store.put_chunk(id, &blob.data))
                .await?;
            if newly_stored {
                stored += 1;
            } else {
                already_present += 1;
            }
        }

        Ok(Response::new(UploadChunksResponse {
            stored,
            already_present,
        }))
    }

    async fn put_manifest(
        &self,
        request: Request<PutManifestRequest>,
    ) -> Result<Response<PutManifestResponse>, Status> {
        self.authenticate(peer_fingerprint(&request)).await?;
        let PutManifestRequest {
            manifest,
            snapshot_id,
            chunk_ids,
        } = request.into_inner();
        // The blob is opaque (encrypted client-side, PRD §3.4): the snapshot
        // ID and chunk references arrive as explicit fields, never by
        // decoding the blob.
        let snapshot = parse_snapshot_id(&snapshot_id)?;
        let refs = chunk_ids
            .iter()
            .map(|b| parse_chunk_id(b))
            .collect::<Result<Vec<_>, _>>()?;
        self.blocking(move |store| store.put_snapshot(snapshot, &manifest, &refs))
            .await?;
        Ok(Response::new(PutManifestResponse {}))
    }

    async fn get_manifest(
        &self,
        request: Request<GetManifestRequest>,
    ) -> Result<Response<GetManifestResponse>, Status> {
        self.authenticate(peer_fingerprint(&request)).await?;
        let snapshot = parse_snapshot_id(&request.into_inner().snapshot_id)?;
        let blob = self
            .blocking(move |store| store.get_manifest_blob(snapshot))
            .await?;
        Ok(Response::new(GetManifestResponse { manifest: blob }))
    }

    type GetChunksStream =
        Pin<Box<dyn tokio_stream::Stream<Item = Result<ChunkBlob, Status>> + Send>>;

    async fn get_chunks(
        &self,
        request: Request<GetChunksRequest>,
    ) -> Result<Response<Self::GetChunksStream>, Status> {
        self.authenticate(peer_fingerprint(&request)).await?;
        let ids = request
            .into_inner()
            .chunk_ids
            .iter()
            .map(|b| parse_chunk_id(b))
            .collect::<Result<Vec<_>, _>>()?;

        let (tx, rx) = tokio::sync::mpsc::channel::<Result<ChunkBlob, Status>>(4);
        let store = Arc::clone(&self.store);
        // One blocking task walks the requested IDs in order; each blob is
        // integrity-verified by get_chunk before it is sent (FR9 groundwork).
        // If the client hangs up, blocking_send fails and the task stops.
        tokio::task::spawn_blocking(move || {
            for id in ids {
                let item = store
                    .get_chunk(id)
                    .map(|data| ChunkBlob {
                        chunk_id: id.as_bytes().to_vec(),
                        data,
                    })
                    .map_err(status_from_store);
                let is_err = item.is_err();
                if tx.blocking_send(item).is_err() || is_err {
                    return;
                }
            }
        });

        Ok(Response::new(Box::pin(ReceiverStream::new(rx))))
    }
}
