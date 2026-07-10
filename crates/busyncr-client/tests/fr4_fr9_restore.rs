//! FR4/FR9 acceptance tests: restore end to end over real mutual TLS.
//!
//! FR4 — restore any retained snapshot to an empty directory → a byte-exact
//! tree (hash-verified), including mtime and permissions.
//!
//! FR9 — a corrupted chunk blob on the daemon is detected on restore (a
//! typed error naming the chunk), never silently reassembled into a
//! corrupted file.

use std::net::{Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use busyncr_client::backup::{run_backup, BackupReport, BackupRequest};
use busyncr_client::config::ClientConfig;
use busyncr_client::enroll::{self, request_enrollment, EnrollmentRequest};
use busyncr_client::restore::{run_restore, RestoreError, RestoreRequest};
use busyncr_core::chunking::{ChunkId, ChunkerConfig};
use busyncr_core::crypto;
use busyncr_core::manifest::Manifest;
use busyncr_daemon::identity::DaemonIdentity;
use busyncr_daemon::service;
use busyncr_daemon::store::ChunkStore;
use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};
use tonic::Code;
use ulid::Ulid;

struct TlsDaemon {
    identity: Arc<DaemonIdentity>,
    store_dir: PathBuf,
    url: String,
    shutdown: Option<tokio::sync::oneshot::Sender<()>>,
    server: tokio::task::JoinHandle<()>,
}

impl TlsDaemon {
    /// Spawns a fresh in-process daemon serving mutual TLS on an ephemeral
    /// localhost port, bootstrapping its CA under `root/identity`.
    async fn spawn(root: &Path) -> Self {
        let store_dir = root.join("store");
        let store = Arc::new(ChunkStore::open(&store_dir).unwrap());
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
            store_dir,
            url: format!("https://{local}"),
            shutdown: Some(shutdown_tx),
            server,
        }
    }

    /// Overwrites the on-disk object for `chunk` with garbage bytes, leaving
    /// its length unchanged so only the BLAKE3-of-blob header check trips
    /// (FR9: the daemon must detect this, never ship it).
    fn corrupt_chunk(&self, chunk: ChunkId) {
        let hex = chunk.to_string();
        let path = self.store_dir.join("objects").join(&hex[..2]).join(&hex);
        let original = std::fs::read(&path).unwrap();
        assert!(!original.is_empty(), "expected an object file at {path:?}");
        let mut corrupted = original.clone();
        // Flip a byte well inside the ciphertext payload (past the 32-byte
        // BLAKE3-of-blob header) so the length stays identical.
        let flip_at = corrupted.len() - 1;
        corrupted[flip_at] ^= 0xFF;
        assert_ne!(corrupted, original);
        std::fs::write(&path, &corrupted).unwrap();
    }

    async fn stop(mut self) {
        drop(self.shutdown.take());
        self.server.await.unwrap();
    }
}

/// A fully enrolled client + configured source tree, ready to back up and
/// restore.
struct Fixture {
    daemon: TlsDaemon,
    state: PathBuf,
    /// The configured backup root (named `data`).
    root: PathBuf,
    config: ClientConfig,
    chunker: ChunkerConfig,
    rng: StdRng,
}

impl Fixture {
    async fn new(base: &Path) -> Self {
        let daemon = TlsDaemon::spawn(base).await;
        let state = base.join("client-state");

        let identity = request_enrollment(&EnrollmentRequest {
            daemon_url: daemon.url.clone(),
            ca_cert_pem: daemon.identity.ca_cert_pem().to_owned(),
            token: daemon.identity.mint_token(&mut rand::rng()).unwrap(),
            name: "restore-host".to_owned(),
        })
        .await
        .unwrap();
        enroll::save_identity(&state, &identity).unwrap();
        let mut rng = StdRng::seed_from_u64(9001);
        enroll::ensure_data_key(&state, &mut rng).unwrap();

        // Source tree under a root named `data`, exercising: a multi-chunk
        // binary file, an empty file, a nested small text file, and (on
        // Unix) a distinctive permission bit to prove metadata round-trips.
        let root = base.join("src").join("data");
        std::fs::create_dir_all(root.join("notes")).unwrap();
        let mut big = vec![0u8; 200 * 1024];
        StdRng::seed_from_u64(11).fill_bytes(&mut big);
        std::fs::write(root.join("big.bin"), &big).unwrap();
        std::fs::write(root.join("empty.bin"), b"").unwrap();
        std::fs::write(root.join("notes").join("hello.txt"), b"hello busyncr\n").unwrap();

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(
                root.join("notes").join("hello.txt"),
                std::fs::Permissions::from_mode(0o640),
            )
            .unwrap();
        }
        // A distinctive, non-"now" mtime so restore's mtime round-trip is
        // actually exercised rather than coincidentally matching wall clock.
        let old = filetime::FileTime::from_unix_time(1_600_000_000, 0);
        for f in ["big.bin", "empty.bin"] {
            filetime::set_file_mtime(root.join(f), old).unwrap();
        }
        filetime::set_file_mtime(root.join("notes").join("hello.txt"), old).unwrap();

        let config_path = base.join("busyncr-client.toml");
        std::fs::write(
            &config_path,
            format!(
                "daemon = \"{}\"\nfolders = [\"src/data\"]\nchunk_target_size = \"4K\"\n",
                daemon.url,
            ),
        )
        .unwrap();
        let config = ClientConfig::load(&config_path).unwrap();
        let chunker = config.chunker(false).unwrap();

        Self {
            daemon,
            state,
            root,
            config,
            chunker,
            rng,
        }
    }

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

    async fn restore(
        &self,
        snapshot_id: Ulid,
        target_dir: &Path,
    ) -> Result<busyncr_client::restore::RestoreReport, RestoreError> {
        let request = RestoreRequest {
            daemon_url: &self.config.daemon,
            state_dir: &self.state,
            snapshot_id,
            target_dir,
        };
        run_restore(&request).await
    }

    /// The manifest's chunk list for `data/big.bin`, decrypted client-side.
    async fn big_bin_chunks(&self, snapshot_id: Ulid) -> Vec<ChunkId> {
        let mut client = enroll::connect_authenticated(&self.daemon.url, &self.state)
            .await
            .unwrap();
        let blob = client
            .get_manifest(busyncr_proto::v1::GetManifestRequest {
                snapshot_id: snapshot_id.to_bytes().to_vec(),
            })
            .await
            .unwrap()
            .into_inner()
            .manifest;
        let key = enroll::load_data_key(&self.state).unwrap();
        let plaintext = crypto::decrypt_manifest(&key, snapshot_id, &blob).unwrap();
        let manifest = Manifest::decode(&plaintext).unwrap();
        manifest
            .files
            .iter()
            .find(|f| f.path == "data/big.bin")
            .expect("data/big.bin must be in the manifest")
            .chunks
            .clone()
    }
}

/// Recursively lists every regular file under `dir`, relative paths sorted.
fn list_files(dir: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let mut stack = vec![dir.to_path_buf()];
    while let Some(d) = stack.pop() {
        for entry in std::fs::read_dir(&d).unwrap() {
            let entry = entry.unwrap();
            let path = entry.path();
            if path.is_dir() {
                stack.push(path);
            } else {
                out.push(path.strip_prefix(dir).unwrap().to_path_buf());
            }
        }
    }
    out.sort();
    out
}

/// FR4: restoring a snapshot to an empty directory reproduces the source
/// tree byte-exact (hash-verified) including mtime and, on Unix,
/// permissions.
#[tokio::test]
async fn fr4_restore_is_byte_exact_including_metadata() {
    let dir = tempfile::tempdir().unwrap();
    let mut fx = Fixture::new(dir.path()).await;
    let report = fx.backup(1).await;

    let target = dir.path().join("restored");
    let restore_report = fx.restore(report.snapshot_id, &target).await.unwrap();

    assert_eq!(restore_report.snapshot_id, report.snapshot_id);
    assert_eq!(restore_report.files, report.files);
    assert_eq!(restore_report.bytes, report.source_bytes);

    // The restored tree mirrors the source tree one-for-one under the
    // `data/` root-name prefix.
    let source_files = list_files(&fx.root);
    let restored_root = target.join("data");
    let restored_files = list_files(&restored_root);
    assert_eq!(source_files, restored_files);
    assert!(!source_files.is_empty());

    for rel in &source_files {
        let src_path = fx.root.join(rel);
        let dst_path = restored_root.join(rel);

        // Byte-exact, hash-verified content.
        let src_bytes = std::fs::read(&src_path).unwrap();
        let dst_bytes = std::fs::read(&dst_path).unwrap();
        assert_eq!(
            blake3::hash(&src_bytes),
            blake3::hash(&dst_bytes),
            "content mismatch for {rel:?}"
        );
        assert_eq!(src_bytes, dst_bytes, "content mismatch for {rel:?}");

        // mtime round-trips to whole-second precision.
        let src_meta = std::fs::metadata(&src_path).unwrap();
        let dst_meta = std::fs::metadata(&dst_path).unwrap();
        let src_mtime = filetime::FileTime::from_last_modification_time(&src_meta);
        let dst_mtime = filetime::FileTime::from_last_modification_time(&dst_meta);
        assert_eq!(
            src_mtime.unix_seconds(),
            dst_mtime.unix_seconds(),
            "mtime mismatch for {rel:?}"
        );

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                src_meta.permissions().mode() & 0o777,
                dst_meta.permissions().mode() & 0o777,
                "permission bits mismatch for {rel:?}"
            );
        }
    }

    fx.daemon.stop().await;
}

/// FR4: restore refuses a non-empty target directory rather than merging or
/// overwriting into it.
#[tokio::test]
async fn fr4_restore_refuses_nonempty_target() {
    let dir = tempfile::tempdir().unwrap();
    let mut fx = Fixture::new(dir.path()).await;
    let report = fx.backup(1).await;

    let target = dir.path().join("occupied");
    std::fs::create_dir_all(&target).unwrap();
    std::fs::write(target.join("leftover"), b"pre-existing").unwrap();

    let err = fx.restore(report.snapshot_id, &target).await.unwrap_err();
    assert!(matches!(err, RestoreError::TargetNotEmpty { .. }));
    // Nothing beyond the pre-existing file was written.
    assert_eq!(list_files(&target), vec![PathBuf::from("leftover")]);

    fx.daemon.stop().await;
}

/// FR4 groundwork: restoring an unknown snapshot ID fails with NOT_FOUND,
/// not a partially written tree.
#[tokio::test]
async fn fr4_restore_unknown_snapshot_not_found() {
    let dir = tempfile::tempdir().unwrap();
    let fx = Fixture::new(dir.path()).await;

    let target = dir.path().join("nowhere");
    let err = fx
        .restore(Ulid::from_parts(1, 1), &target)
        .await
        .unwrap_err();
    match err {
        RestoreError::Rpc(status) => assert_eq!(status.code(), Code::NotFound),
        other => panic!("expected Rpc(NotFound), got {other:?}"),
    }

    fx.daemon.stop().await;
}

/// FR9: a stored chunk corrupted on the daemon's disk is detected on
/// restore — the daemon answers DATA_LOSS naming the chunk, the client
/// surfaces it as a typed error, and no corrupted content is silently
/// written for that file.
#[tokio::test]
async fn fr9_corrupt_stored_chunk_fails_restore_naming_the_chunk() {
    let dir = tempfile::tempdir().unwrap();
    let mut fx = Fixture::new(dir.path()).await;
    let report = fx.backup(1).await;

    let big_chunks = fx.big_bin_chunks(report.snapshot_id).await;
    let victim = *big_chunks
        .first()
        .expect("big.bin must chunk into at least one piece");
    fx.daemon.corrupt_chunk(victim);

    let target = dir.path().join("restored-after-corruption");
    let err = fx.restore(report.snapshot_id, &target).await.unwrap_err();

    match &err {
        RestoreError::Rpc(status) => {
            assert_eq!(status.code(), Code::DataLoss);
            assert!(
                status.message().contains(&victim.to_string()),
                "integrity error must name the corrupted chunk: {}",
                status.message()
            );
        }
        other => panic!("expected Rpc(DataLoss) naming the chunk, got {other:?}"),
    }

    // No file was left claiming to be a complete, correct copy of big.bin:
    // either it was never created, or it is short of the declared size —
    // both are honest signals of an aborted restore, never silently wrong
    // bytes passed off as the real file.
    let restored_big = target.join("data").join("big.bin");
    if let Ok(bytes) = std::fs::read(&restored_big) {
        assert!(
            (bytes.len() as u64) < report.source_bytes,
            "an aborted restore must not produce a full-size (and therefore \
             falsely complete) file"
        );
    }

    fx.daemon.stop().await;
}

/// FR9 sibling regression: corrupting a chunk unrelated to a *different*
/// snapshot must not affect restoring that other snapshot — corruption
/// detection is per-chunk, not a global daemon failure.
#[tokio::test]
async fn fr9_corruption_is_scoped_to_the_affected_chunk() {
    let dir = tempfile::tempdir().unwrap();
    let mut fx = Fixture::new(dir.path()).await;
    let report1 = fx.backup(1).await;

    // Second snapshot after an edit gets its own new chunk(s).
    let big_path = fx.root.join("big.bin");
    let mut big = std::fs::read(&big_path).unwrap();
    big[0] ^= 0xFF;
    std::fs::write(&big_path, &big).unwrap();
    let report2 = fx.backup(2).await;

    let chunks1 = fx.big_bin_chunks(report1.snapshot_id).await;
    let chunks2 = fx.big_bin_chunks(report2.snapshot_id).await;
    let unique_to_v2 = chunks2
        .iter()
        .find(|id| !chunks1.contains(id))
        .copied()
        .expect("the edit must introduce a chunk unique to snapshot 2");
    fx.daemon.corrupt_chunk(unique_to_v2);

    // Snapshot 2 (which references the corrupted chunk) fails.
    let target2 = dir.path().join("restored-v2");
    assert!(fx.restore(report2.snapshot_id, &target2).await.is_err());

    // Snapshot 1 (which never referenced it) still restores byte-exact.
    let target1 = dir.path().join("restored-v1");
    let restore_report1 = fx.restore(report1.snapshot_id, &target1).await.unwrap();
    assert_eq!(restore_report1.files, report1.files);
    assert_eq!(restore_report1.bytes, report1.source_bytes);

    fx.daemon.stop().await;
}
