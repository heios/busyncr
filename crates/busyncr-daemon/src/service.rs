//! gRPC service (PRD §3.2): tonic implementation of `busyncr.v1.Busyncr`
//! backed by the [`ChunkStore`].
//!
//! Slice S5 serves plain TCP on localhost; TLS + enrollment arrive in S6
//! (until then [`Enroll`](BusyncrService::enroll) answers `UNIMPLEMENTED`).
//!
//! # Status mapping
//!
//! | store outcome                         | gRPC status          |
//! |---------------------------------------|----------------------|
//! | malformed chunk/snapshot ID or blob   | `INVALID_ARGUMENT`   |
//! | chunk/snapshot not found              | `NOT_FOUND`          |
//! | snapshot already exists               | `ALREADY_EXISTS`     |
//! | manifest references unknown chunk     | `FAILED_PRECONDITION`|
//! | stored blob fails verification (FR9)  | `DATA_LOSS`          |
//! | I/O / index failure                   | `INTERNAL`           |

// `tonic::Status` is 176 bytes; every tonic handler and helper in the
// ecosystem returns `Result<_, Status>` by value. Boxing it here would only
// add friction at the trait boundary we don't control.
#![allow(clippy::result_large_err)]

use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;

use busyncr_core::chunking::ChunkId;
use busyncr_core::manifest::Manifest;
use busyncr_proto::v1::busyncr_server::{Busyncr, BusyncrServer};
use busyncr_proto::v1::{
    ChunkBlob, EnrollRequest, EnrollResponse, GetChunksRequest, GetManifestRequest,
    GetManifestResponse, HasChunksRequest, HasChunksResponse, ListSnapshotsRequest,
    ListSnapshotsResponse, PutManifestRequest, PutManifestResponse, UploadChunksResponse,
};
use tokio::net::TcpListener;
use tokio_stream::wrappers::{ReceiverStream, TcpListenerStream};
use tokio_stream::StreamExt;
use tonic::{Request, Response, Status, Streaming};
use ulid::Ulid;

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
}

impl BusyncrService {
    /// Wraps a chunk store for serving.
    #[must_use]
    pub fn new(store: Arc<ChunkStore>) -> Self {
        Self { store }
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
/// resolves.
///
/// Plain TCP — slice S5. The caller is expected to bind to localhost only
/// until S6 adds mTLS. Binding first (rather than passing an address) lets
/// tests use an ephemeral port and know it before the server starts.
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
        _request: Request<EnrollRequest>,
    ) -> Result<Response<EnrollResponse>, Status> {
        Err(Status::unimplemented(
            "enrollment (FR1) is served from slice S6; this daemon build predates it",
        ))
    }

    async fn list_snapshots(
        &self,
        _request: Request<ListSnapshotsRequest>,
    ) -> Result<Response<ListSnapshotsResponse>, Status> {
        let ids = self.blocking(|store| store.list_snapshots()).await?;
        Ok(Response::new(ListSnapshotsResponse {
            snapshot_ids: ids.into_iter().map(|u| u.to_bytes().to_vec()).collect(),
        }))
    }

    async fn has_chunks(
        &self,
        request: Request<HasChunksRequest>,
    ) -> Result<Response<HasChunksResponse>, Status> {
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
        let mut stream = request.into_inner();
        let mut stored = 0u64;
        let mut already_present = 0u64;

        while let Some(blob) = stream.next().await {
            let blob = blob?;
            let id = parse_chunk_id(&blob.chunk_id)?;
            let newly_stored = self
                .blocking(move |store| store.put_chunk(id, &blob.data))
                .await
                // put_chunk verifies data hashes to id; a mismatch here is a
                // client-supplied bad address, not stored-data loss.
                .map_err(|s| match s.code() {
                    tonic::Code::DataLoss => Status::invalid_argument(s.message().to_owned()),
                    _ => s,
                })?;
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
        let manifest = Manifest::decode(&request.into_inner().manifest)
            .map_err(|e| Status::invalid_argument(format!("manifest does not decode: {e}")))?;
        self.blocking(move |store| store.put_manifest(&manifest))
            .await?;
        Ok(Response::new(PutManifestResponse {}))
    }

    async fn get_manifest(
        &self,
        request: Request<GetManifestRequest>,
    ) -> Result<Response<GetManifestResponse>, Status> {
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
