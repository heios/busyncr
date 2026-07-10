//! S5 integration test: a real tonic client talking to a real in-process
//! daemon over localhost TCP, exercising every RPC against the S3 store
//! (PRD §3.2; groundwork for FR2/FR3/FR9 — acceptance-level `fr<N>_` tests
//! land with the end-to-end slices).

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;

use busyncr_core::chunking::ChunkId;
use busyncr_core::manifest::{FileEntry, Manifest};
use busyncr_daemon::service;
use busyncr_daemon::store::ChunkStore;
use busyncr_proto::v1::busyncr_client::BusyncrClient;
use busyncr_proto::v1::{
    ChunkBlob, EnrollRequest, GetChunksRequest, GetManifestRequest, HasChunksRequest,
    ListSnapshotsRequest, PutManifestRequest,
};
use tokio_stream::StreamExt;
use tonic::transport::Channel;
use tonic::Code;
use ulid::Ulid;

/// Spawns an in-process daemon on an ephemeral localhost port and returns a
/// connected client plus a shutdown handle.
async fn spawn_daemon(
    store: Arc<ChunkStore>,
) -> (
    BusyncrClient<Channel>,
    tokio::sync::oneshot::Sender<()>,
    tokio::task::JoinHandle<()>,
) {
    let addr = SocketAddr::from((Ipv4Addr::LOCALHOST, 0));
    let (listener, local) = service::bind(addr).await.unwrap();
    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
    let server = tokio::spawn(async move {
        service::serve(store, listener, async {
            let _ = shutdown_rx.await;
        })
        .await
        .unwrap();
    });

    let channel = tonic::transport::Endpoint::from_shared(format!("http://{local}"))
        .unwrap()
        .connect()
        .await
        .unwrap();
    (BusyncrClient::new(channel), shutdown_tx, server)
}

/// Deterministic test chunks: contents differ, IDs are honest BLAKE3.
fn test_chunks() -> Vec<(ChunkId, Vec<u8>)> {
    [b"alpha".to_vec(), b"beta-beta".to_vec(), vec![0u8; 4096]]
        .into_iter()
        .map(|data| (ChunkId::of(&data), data))
        .collect()
}

fn test_manifest(chunks: &[(ChunkId, Vec<u8>)]) -> Manifest {
    Manifest {
        snapshot_id: Ulid::from_parts(1_700_000_000_000, 42),
        created_at: 1_700_000_000,
        files: vec![FileEntry {
            path: "dir/file.bin".to_owned(),
            size: chunks.iter().map(|(_, d)| d.len() as u64).sum(),
            mtime_secs: 1_699_999_999,
            mtime_nanos: 123_456_789,
            mode: 0o644,
            chunks: chunks.iter().map(|(id, _)| *id).collect(),
        }],
    }
}

#[tokio::test]
async fn grpc_full_roundtrip_against_real_store() {
    let dir = tempfile::tempdir().unwrap();
    let store = Arc::new(ChunkStore::open(dir.path().join("store")).unwrap());
    let (mut client, shutdown, server) = spawn_daemon(Arc::clone(&store)).await;

    let chunks = test_chunks();
    let manifest = test_manifest(&chunks);
    let wire_ids: Vec<Vec<u8>> = chunks
        .iter()
        .map(|(id, _)| id.as_bytes().to_vec())
        .collect();

    // Enroll needs the daemon identity, which only the TLS path (S6) wires
    // up: this insecure in-process server must answer UNIMPLEMENTED.
    let err = client
        .enroll(EnrollRequest {
            token: "tok".into(),
            csr_pem: "not a csr".into(),
        })
        .await
        .unwrap_err();
    assert_eq!(err.code(), Code::Unimplemented);

    // Fresh daemon: no snapshots, every chunk missing.
    let listed = client
        .list_snapshots(ListSnapshotsRequest {})
        .await
        .unwrap()
        .into_inner();
    assert!(listed.snapshot_ids.is_empty());

    let missing = client
        .has_chunks(HasChunksRequest {
            chunk_ids: wire_ids.clone(),
        })
        .await
        .unwrap()
        .into_inner()
        .missing_chunk_ids;
    assert_eq!(
        missing, wire_ids,
        "fresh store must report all chunks missing"
    );

    // PutManifest before the chunks exist must be refused (referential
    // integrity lives on the daemon).
    let err = client
        .put_manifest(PutManifestRequest {
            manifest: manifest.encode().unwrap(),
        })
        .await
        .unwrap_err();
    assert_eq!(err.code(), Code::FailedPrecondition);

    // Upload all chunks via the client stream.
    let blobs: Vec<ChunkBlob> = chunks
        .iter()
        .map(|(id, data)| ChunkBlob {
            chunk_id: id.as_bytes().to_vec(),
            data: data.clone(),
        })
        .collect();
    let report = client
        .upload_chunks(tokio_stream::iter(blobs.clone()))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(report.stored, chunks.len() as u64);
    assert_eq!(report.already_present, 0);

    // Dedup: re-uploading the same blobs stores nothing new.
    let report = client
        .upload_chunks(tokio_stream::iter(blobs))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(report.stored, 0);
    assert_eq!(report.already_present, chunks.len() as u64);

    // Now nothing is missing.
    let missing = client
        .has_chunks(HasChunksRequest {
            chunk_ids: wire_ids.clone(),
        })
        .await
        .unwrap()
        .into_inner()
        .missing_chunk_ids;
    assert!(missing.is_empty());

    // Manifest roundtrip.
    client
        .put_manifest(PutManifestRequest {
            manifest: manifest.encode().unwrap(),
        })
        .await
        .unwrap();
    let err = client
        .put_manifest(PutManifestRequest {
            manifest: manifest.encode().unwrap(),
        })
        .await
        .unwrap_err();
    assert_eq!(err.code(), Code::AlreadyExists, "manifests are immutable");

    let listed = client
        .list_snapshots(ListSnapshotsRequest {})
        .await
        .unwrap()
        .into_inner();
    assert_eq!(
        listed.snapshot_ids,
        vec![manifest.snapshot_id.to_bytes().to_vec()]
    );

    let fetched = client
        .get_manifest(GetManifestRequest {
            snapshot_id: manifest.snapshot_id.to_bytes().to_vec(),
        })
        .await
        .unwrap()
        .into_inner()
        .manifest;
    assert_eq!(Manifest::decode(&fetched).unwrap(), manifest);

    // GetChunks streams the blobs back byte-exact, in request order.
    let mut stream = client
        .get_chunks(GetChunksRequest {
            chunk_ids: wire_ids.clone(),
        })
        .await
        .unwrap()
        .into_inner();
    let mut got = Vec::new();
    while let Some(blob) = stream.next().await {
        got.push(blob.unwrap());
    }
    assert_eq!(got.len(), chunks.len());
    for ((id, data), blob) in chunks.iter().zip(&got) {
        assert_eq!(blob.chunk_id, id.as_bytes().to_vec());
        assert_eq!(&blob.data, data);
    }

    drop(shutdown);
    server.await.unwrap();
}

#[tokio::test]
async fn grpc_rejects_bad_input_and_detects_corruption() {
    let dir = tempfile::tempdir().unwrap();
    let store = Arc::new(ChunkStore::open(dir.path().join("store")).unwrap());
    let (mut client, shutdown, server) = spawn_daemon(Arc::clone(&store)).await;

    // Malformed chunk ID length.
    let err = client
        .has_chunks(HasChunksRequest {
            chunk_ids: vec![vec![0u8; 7]],
        })
        .await
        .unwrap_err();
    assert_eq!(err.code(), Code::InvalidArgument);

    // Uploading a blob whose data does not hash to its claimed ID is a
    // client error, not accepted silently.
    let dishonest = ChunkBlob {
        chunk_id: ChunkId::of(b"claimed").as_bytes().to_vec(),
        data: b"actual".to_vec(),
    };
    let err = client
        .upload_chunks(tokio_stream::iter(vec![dishonest]))
        .await
        .unwrap_err();
    assert_eq!(err.code(), Code::InvalidArgument);

    // Unknown snapshot and unknown chunk → NOT_FOUND.
    let err = client
        .get_manifest(GetManifestRequest {
            snapshot_id: Ulid::from_parts(1, 1).to_bytes().to_vec(),
        })
        .await
        .unwrap_err();
    assert_eq!(err.code(), Code::NotFound);

    let mut stream = client
        .get_chunks(GetChunksRequest {
            chunk_ids: vec![ChunkId::of(b"nowhere").as_bytes().to_vec()],
        })
        .await
        .unwrap()
        .into_inner();
    let err = stream.next().await.unwrap().unwrap_err();
    assert_eq!(err.code(), Code::NotFound);

    // FR9 groundwork over the wire: corrupt the stored blob on disk; the
    // daemon must answer DATA_LOSS, never ship corrupt bytes.
    let data = b"soon to be corrupted".to_vec();
    let id = ChunkId::of(&data);
    client
        .upload_chunks(tokio_stream::iter(vec![ChunkBlob {
            chunk_id: id.as_bytes().to_vec(),
            data,
        }]))
        .await
        .unwrap();
    let hex = id.to_string();
    let blob_path = dir
        .path()
        .join("store")
        .join("objects")
        .join(&hex[..2])
        .join(&hex);
    assert!(blob_path.is_file(), "expected CAS blob at {blob_path:?}");
    std::fs::write(&blob_path, b"XXXX to be corrupted").unwrap();

    let mut stream = client
        .get_chunks(GetChunksRequest {
            chunk_ids: vec![id.as_bytes().to_vec()],
        })
        .await
        .unwrap()
        .into_inner();
    let err = stream.next().await.unwrap().unwrap_err();
    assert_eq!(err.code(), Code::DataLoss);
    assert!(
        err.message().contains(&hex),
        "integrity error must name the chunk: {}",
        err.message()
    );

    drop(shutdown);
    server.await.unwrap();
}
