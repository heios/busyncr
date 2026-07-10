//! FR2/FR3 acceptance tests: backup end to end over real mutual TLS.
//!
//! FR2 — back up a configured folder tree → the snapshot appears in the
//! daemon's version list, and its (encrypted) manifest describes the tree.
//!
//! FR3 — a second backup after a small edit ships only the new/changed
//! chunks, proven by an exact byte-accounting assertion on the uploaded
//! ciphertext volume against independently recomputed chunk boundaries.

use std::collections::HashSet;
use std::net::{Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use busyncr_client::backup::{run_backup, BackupReport, BackupRequest};
use busyncr_client::config::ClientConfig;
use busyncr_client::enroll::{self, request_enrollment, EnrollmentRequest};
use busyncr_core::chunking::{chunk_bytes_keyed, ChunkId, ChunkIdKey, ChunkerConfig};
use busyncr_core::crypto::{self, BLOB_OVERHEAD};
use busyncr_core::manifest::Manifest;
use busyncr_daemon::identity::DaemonIdentity;
use busyncr_daemon::service;
use busyncr_daemon::store::ChunkStore;
use busyncr_proto::v1::{GetChunksRequest, GetManifestRequest, ListSnapshotsRequest};
use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};
use ulid::Ulid;

struct TlsDaemon {
    identity: Arc<DaemonIdentity>,
    url: String,
    shutdown: Option<tokio::sync::oneshot::Sender<()>>,
    server: tokio::task::JoinHandle<()>,
}

impl TlsDaemon {
    /// Spawns a fresh in-process daemon serving mutual TLS on an ephemeral
    /// localhost port, bootstrapping its CA under `root/identity`.
    async fn spawn(root: &Path) -> Self {
        let store = Arc::new(ChunkStore::open(root.join("store")).unwrap());
        let identity = Arc::new(DaemonIdentity::open_or_init(root.join("identity")).unwrap());

        let addr = SocketAddr::from((Ipv4Addr::LOCALHOST, 0));
        let (listener, local) = service::bind(addr).await.unwrap();
        let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
        let serve_identity = Arc::clone(&identity);
        let server = tokio::spawn(async move {
            service::serve_tls(store, serve_identity, listener, async {
                let _ = shutdown_rx.await;
            })
            .await
            .unwrap();
        });

        Self {
            identity,
            url: format!("https://{local}"),
            shutdown: Some(shutdown_tx),
            server,
        }
    }

    async fn stop(mut self) {
        drop(self.shutdown.take());
        self.server.await.unwrap();
    }
}

/// A fully enrolled client + configured source tree, ready to back up.
struct Fixture {
    daemon: TlsDaemon,
    state: PathBuf,
    /// The configured backup root (named `data`).
    root: PathBuf,
    config: ClientConfig,
    chunker: ChunkerConfig,
    /// The backup set's keyed-chunk-ID key, loaded from state, so the test
    /// can recompute chunk IDs exactly as the backup pipeline does (FR-K1).
    chunk_id_key: ChunkIdKey,
    rng: StdRng,
}

impl Fixture {
    /// Fixture with the standard 4 KiB test chunking (many chunks from small
    /// files).
    async fn new(base: &Path) -> Self {
        Self::with_chunking(base, Some("chunk_target_size = \"4K\"\n"), false).await
    }

    /// Fixture exercising the `--default-chunking` path: no committed size
    /// in the config, the 1 MiB default accepted explicitly.
    async fn new_default_chunking(base: &Path) -> Self {
        Self::with_chunking(base, None, true).await
    }

    async fn with_chunking(base: &Path, chunk_line: Option<&str>, allow_default: bool) -> Self {
        let daemon = TlsDaemon::spawn(base).await;
        let state = base.join("client-state");

        // Enroll (FR1 machinery from S6).
        let identity = request_enrollment(&EnrollmentRequest {
            daemon_url: daemon.url.clone(),
            ca_cert_pem: daemon.identity.ca_cert_pem().to_owned(),
            token: daemon.identity.mint_token(&mut rand::rng()).unwrap(),
            name: "backup-host".to_owned(),
        })
        .await
        .unwrap();
        enroll::save_identity(&state, &identity).unwrap();
        let mut rng = StdRng::seed_from_u64(4242);
        enroll::ensure_data_key(&state, &mut rng).unwrap();
        let chunk_id_key = enroll::load_chunk_id_key(&state).unwrap();

        // Source tree under a root named `data` (manifest paths carry that
        // prefix).
        let root = base.join("src").join("data");
        std::fs::create_dir_all(root.join("notes")).unwrap();
        let mut big = vec![0u8; 300 * 1024];
        StdRng::seed_from_u64(7).fill_bytes(&mut big);
        std::fs::write(root.join("big.bin"), &big).unwrap();
        std::fs::write(root.join("empty.bin"), b"").unwrap();
        std::fs::write(root.join("notes").join("hello.txt"), b"hello busyncr\n").unwrap();

        // The folder walk + chunk size come from a real TOML config file
        // (FR2: "a configured folder tree"). The default 4 KiB target makes
        // the 300 KiB file span many chunks; `chunk_line = None` leaves the
        // size uncommitted so `allow_default` exercises --default-chunking.
        let config_path = base.join("busyncr-client.toml");
        std::fs::write(
            &config_path,
            format!(
                "daemon = \"{}\"\nfolders = [\"src/data\"]\n{}",
                daemon.url,
                chunk_line.unwrap_or("")
            ),
        )
        .unwrap();
        let config = ClientConfig::load(&config_path).unwrap();
        assert_eq!(config.folders, vec![root.clone()]);
        let chunker = config.chunker(allow_default).unwrap();

        Self {
            daemon,
            state,
            root,
            config,
            chunker,
            chunk_id_key,
            rng,
        }
    }

    /// Runs one backup with an injected snapshot identity.
    async fn backup(&mut self, seq: u64) -> BackupReport {
        let request = BackupRequest {
            daemon_url: &self.config.daemon,
            state_dir: &self.state,
            roots: &self.config.folders,
            chunker: self.chunker,
            snapshot_id: Ulid::from_parts(1_700_000_000_000 + seq, u128::from(seq)),
            created_at: 1_700_000_000 + seq as i64,
        };
        run_backup(&request, &mut self.rng).await.unwrap()
    }

    /// Chunk IDs (with plaintext lengths) of every file currently in the
    /// tree, computed independently of the backup pipeline.
    fn local_chunks(&self) -> Vec<(ChunkId, usize)> {
        let mut out = Vec::new();
        let mut stack = vec![self.root.clone()];
        while let Some(dir) = stack.pop() {
            for entry in std::fs::read_dir(&dir).unwrap() {
                let path = entry.unwrap().path();
                if path.is_dir() {
                    stack.push(path);
                } else {
                    let data = std::fs::read(&path).unwrap();
                    out.extend(
                        chunk_bytes_keyed(&data, &self.chunker, &self.chunk_id_key)
                            .into_iter()
                            .map(|c| (c.id, c.len())),
                    );
                }
            }
        }
        out
    }

    async fn list_snapshots(&self) -> Vec<Ulid> {
        let mut client = enroll::connect_authenticated(&self.daemon.url, &self.state)
            .await
            .unwrap();
        client
            .list_snapshots(ListSnapshotsRequest {})
            .await
            .unwrap()
            .into_inner()
            .snapshot_ids
            .iter()
            .map(|raw| {
                let bytes: [u8; 16] = raw.as_slice().try_into().unwrap();
                Ulid::from_bytes(bytes)
            })
            .collect()
    }

    async fn fetch_manifest_blob(&self, snapshot: Ulid) -> Vec<u8> {
        let mut client = enroll::connect_authenticated(&self.daemon.url, &self.state)
            .await
            .unwrap();
        client
            .get_manifest(GetManifestRequest {
                snapshot_id: snapshot.to_bytes().to_vec(),
            })
            .await
            .unwrap()
            .into_inner()
            .manifest
    }
}

/// Exact expected ciphertext volume for a set of chunks: every uploaded blob
/// is plaintext + the fixed XChaCha20-Poly1305 overhead (nonce + tag).
fn expected_upload_bytes(chunks: &[(ChunkId, usize)], ids: &HashSet<ChunkId>) -> u64 {
    let mut counted: HashSet<ChunkId> = HashSet::new();
    chunks
        .iter()
        .filter(|(id, _)| ids.contains(id) && counted.insert(*id))
        .map(|(_, len)| (len + BLOB_OVERHEAD) as u64)
        .sum()
}

/// FR2: back up a configured folder tree → the snapshot appears in the
/// daemon's version list; the stored manifest is encrypted (daemon-opaque)
/// yet decrypts client-side to an exact description of the tree.
#[tokio::test]
async fn fr2_backup_snapshot_listed_and_manifest_describes_tree() {
    let dir = tempfile::tempdir().unwrap();
    let mut fx = Fixture::new(dir.path()).await;

    let report = fx.backup(1).await;
    let snapshot = report.snapshot_id;

    // The snapshot appears in the daemon version list (FR2).
    assert_eq!(fx.list_snapshots().await, vec![snapshot]);

    // First backup of a fresh daemon ships every unique chunk.
    let local = fx.local_chunks();
    let unique: HashSet<ChunkId> = local.iter().map(|(id, _)| *id).collect();
    assert_eq!(report.files, 3);
    assert_eq!(report.chunks_total, local.len() as u64);
    assert_eq!(report.chunks_unique, unique.len() as u64);
    assert_eq!(report.chunks_uploaded, unique.len() as u64);
    assert_eq!(report.chunks_deduped, 0);
    assert!(
        report.chunks_uploaded >= 50,
        "4K target over 300 KiB must span many chunks"
    );
    assert_eq!(report.upload_bytes, expected_upload_bytes(&local, &unique));

    // The stored manifest blob is NOT readable by the daemon (PRD §3.4)...
    let blob = fx.fetch_manifest_blob(snapshot).await;
    assert_eq!(blob.len() as u64, report.manifest_bytes);
    assert!(
        Manifest::decode(&blob).is_err(),
        "stored manifest must be opaque ciphertext, not a decodable manifest"
    );

    // ...but decrypts client-side into an exact description of the tree.
    let key = enroll::load_data_key(&fx.state).unwrap();
    let plaintext = crypto::decrypt_manifest(&key, snapshot, &blob).unwrap();
    let manifest = Manifest::decode(&plaintext).unwrap();
    assert_eq!(manifest.snapshot_id, snapshot);
    assert_eq!(manifest.created_at, 1_700_000_001);

    let paths: Vec<&str> = manifest.files.iter().map(|f| f.path.as_str()).collect();
    assert_eq!(
        paths,
        vec!["data/big.bin", "data/empty.bin", "data/notes/hello.txt"],
        "deterministic sorted walk with the root-name prefix"
    );
    assert_eq!(manifest.files[0].size, 300 * 1024);
    assert_eq!(manifest.files[1].size, 0);
    assert!(manifest.files[1].chunks.is_empty(), "empty file → 0 chunks");
    assert_eq!(manifest.files[2].size, 14);

    // Chunk references match an independent chunking of the source, and the
    // recorded mtimes/mode are real.
    let big = std::fs::read(fx.root.join("big.bin")).unwrap();
    let expected_ids: Vec<ChunkId> = chunk_bytes_keyed(&big, &fx.chunker, &fx.chunk_id_key)
        .iter()
        .map(|c| c.id)
        .collect();
    assert_eq!(manifest.files[0].chunks, expected_ids);
    for file in &manifest.files {
        assert!(file.mtime_secs > 0, "mtime must be captured");
        assert_ne!(file.mode, 0, "platform metadata word must be captured");
    }

    fx.daemon.stop().await;
}

/// FR3: a second backup after a small in-place edit ships only the
/// new/changed chunks — asserted byte-exactly against independently
/// recomputed chunk boundaries — and an unchanged third backup ships zero
/// chunk bytes.
#[tokio::test]
async fn fr3_second_backup_ships_only_changed_chunks_byte_accounted() {
    let dir = tempfile::tempdir().unwrap();
    let mut fx = Fixture::new(dir.path()).await;

    let chunks_v1 = fx.local_chunks();
    let ids_v1: HashSet<ChunkId> = chunks_v1.iter().map(|(id, _)| *id).collect();
    let report1 = fx.backup(1).await;
    assert_eq!(report1.chunks_uploaded, ids_v1.len() as u64);

    // Small edit: overwrite 16 bytes in the middle of the big file
    // (same length, so most CDC boundaries survive).
    let big_path = fx.root.join("big.bin");
    let mut big = std::fs::read(&big_path).unwrap();
    big[150_000..150_016].copy_from_slice(b"EDITEDEDITEDEDIT");
    std::fs::write(&big_path, &big).unwrap();

    let chunks_v2 = fx.local_chunks();
    let ids_v2: HashSet<ChunkId> = chunks_v2.iter().map(|(id, _)| *id).collect();
    let new_ids: HashSet<ChunkId> = ids_v2.difference(&ids_v1).copied().collect();
    assert!(
        !new_ids.is_empty(),
        "the edit must produce at least one new chunk"
    );
    assert!(
        new_ids.len() <= 4,
        "a 16-byte in-place edit must only disturb a few 4K-target chunks, got {}",
        new_ids.len()
    );

    let report2 = fx.backup(2).await;

    // FR3 transfer-size assertion, byte-exact: the second backup uploaded
    // exactly the new chunks' ciphertext (plaintext + AEAD overhead each),
    // nothing else.
    assert_eq!(report2.chunks_uploaded, new_ids.len() as u64);
    assert_eq!(
        report2.upload_bytes,
        expected_upload_bytes(&chunks_v2, &new_ids)
    );
    assert_eq!(
        report2.chunks_deduped + report2.chunks_uploaded,
        report2.chunks_unique
    );
    assert!(
        report2.upload_bytes < report1.upload_bytes / 10,
        "small edit must ship a small fraction of the initial volume \
         ({} vs {})",
        report2.upload_bytes,
        report1.upload_bytes
    );

    // Both snapshots are retained, chronologically (FR2 continues to hold).
    assert_eq!(
        fx.list_snapshots().await,
        vec![report1.snapshot_id, report2.snapshot_id]
    );

    // Third backup with no edits: a new snapshot, zero chunk bytes shipped.
    let report3 = fx.backup(3).await;
    assert_eq!(report3.chunks_uploaded, 0);
    assert_eq!(report3.upload_bytes, 0);
    assert_eq!(report3.chunks_deduped, report3.chunks_unique);
    assert_eq!(fx.list_snapshots().await.len(), 3);

    fx.daemon.stop().await;
}

/// Regression (S7 fix round 1): a max-size chunk's encrypted blob exceeds
/// tonic's built-in 4 MiB message limit. At the spec-mandated 1 MiB
/// `--default-chunking` target any ≥4 MiB boundary-free run — zero runs are
/// commonplace: sparse files, VM images, DB preallocation — emits
/// 4,194,304-byte chunks, so backup at the *default* configuration aborted
/// mid-upload with `OutOfRange` before the stubs raised the limit
/// (`busyncr_proto::MAX_MESSAGE_SIZE`). Drives the full pipeline over real
/// mTLS with such data, then pulls the oversized blob back through
/// `GetChunks` (the S8 restore path decodes on the client side and hits the
/// same wall).
#[tokio::test]
async fn fr2_default_chunking_backs_up_max_size_chunks() {
    let dir = tempfile::tempdir().unwrap();
    let mut fx = Fixture::new_default_chunking(dir.path()).await;

    // 1 MiB default target → 4 MiB max chunk; its ciphertext must exceed
    // the old 4 MiB wire limit or this test would not cover the regression.
    assert_eq!(fx.chunker.target_size(), 1024 * 1024);
    assert_eq!(fx.chunker.max_size(), 4 * 1024 * 1024);
    assert!(
        fx.chunker.max_size() + BLOB_OVERHEAD > 4 * 1024 * 1024,
        "max-size chunk blob must be larger than tonic's default limit"
    );

    // 12 MiB of zeros (no CDC boundary anywhere) plus a random tail: three
    // max-size all-zero chunks (a single unique ID) followed by ordinary
    // content.
    let mut data = vec![0u8; 12 * 1024 * 1024 + 512 * 1024];
    StdRng::seed_from_u64(99).fill_bytes(&mut data[12 * 1024 * 1024..]);
    std::fs::write(fx.root.join("vm.img"), &data).unwrap();

    let local = fx.local_chunks();
    let max_chunk = local
        .iter()
        .find(|(_, len)| *len == fx.chunker.max_size())
        .map(|(id, _)| *id)
        .expect("corpus must produce at least one max-size chunk");
    let unique: HashSet<ChunkId> = local.iter().map(|(id, _)| *id).collect();

    // The backup must survive shipping >4 MiB blobs (this aborted with
    // BackupError::Rpc(OutOfRange) before the fix) and keep the exact
    // FR3 byte ledger.
    let report = fx.backup(1).await;
    assert_eq!(report.files, 4);
    assert_eq!(report.chunks_unique, unique.len() as u64);
    assert_eq!(report.chunks_uploaded, unique.len() as u64);
    assert_eq!(report.upload_bytes, expected_upload_bytes(&local, &unique));
    assert_eq!(fx.list_snapshots().await, vec![report.snapshot_id]);

    // The manifest round-trips and records the boundary-free file exactly.
    let key = enroll::load_data_key(&fx.state).unwrap();
    let blob = fx.fetch_manifest_blob(report.snapshot_id).await;
    let plaintext = crypto::decrypt_manifest(&key, report.snapshot_id, &blob).unwrap();
    let manifest = Manifest::decode(&plaintext).unwrap();
    let vm = manifest
        .files
        .iter()
        .find(|f| f.path == "data/vm.img")
        .expect("vm.img must be in the manifest");
    assert_eq!(vm.size, data.len() as u64);
    let expected_ids: Vec<ChunkId> = chunk_bytes_keyed(&data, &fx.chunker, &fx.chunk_id_key)
        .iter()
        .map(|c| c.id)
        .collect();
    assert_eq!(vm.chunks, expected_ids);

    // Download direction (what S8 restore will do): the oversized blob must
    // also fit through the client-side decode of the GetChunks stream and
    // decrypt back to the original max-size zero chunk.
    let mut client = enroll::connect_authenticated(&fx.daemon.url, &fx.state)
        .await
        .unwrap();
    let mut stream = client
        .get_chunks(GetChunksRequest {
            chunk_ids: vec![max_chunk.as_bytes().to_vec()],
        })
        .await
        .unwrap()
        .into_inner();
    let downloaded = stream.message().await.unwrap().expect("one blob streamed");
    assert!(stream.message().await.unwrap().is_none());
    assert_eq!(downloaded.chunk_id, max_chunk.as_bytes().to_vec());
    assert_eq!(
        downloaded.data.len(),
        fx.chunker.max_size() + BLOB_OVERHEAD,
        "the downloaded ciphertext blob itself must exceed 4 MiB"
    );
    let restored = crypto::decrypt_chunk(&key, &max_chunk, &downloaded.data).unwrap();
    assert_eq!(restored, vec![0u8; fx.chunker.max_size()]);

    fx.daemon.stop().await;
}
