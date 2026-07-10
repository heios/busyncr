//! FR5 end-to-end: prune + GC integrated with the real, encrypted client path.
//!
//! The store-level 60-day simulation lives in `busyncr-daemon`'s
//! `fr5_retention` suite. This test proves the same prune/GC works against
//! snapshots produced by real backups over mutual TLS — encrypted chunks and
//! manifests, refcounts driven by the `snapshot_refs` table (PRD §3.4) — and
//! that a surviving snapshot still restores byte-exact over the wire while a
//! pruned one is gone.
//!
//! Scenario (times injected via snapshot ULIDs, the daemon's only time
//! source): three backups of an evolving file —
//!   * `old`  at now − 30 d  (>=16 d tier, its own cell) → survives,
//!   * `b`    at now − 2 h    (same 3 h cell as `a`)      → pruned,
//!   * `a`    at now − 1 h    (newest in that cell)       → survives.

use std::net::{Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use busyncr_client::backup::{run_backup, BackupRequest};
use busyncr_client::config::ClientConfig;
use busyncr_client::enroll::{self, request_enrollment, EnrollmentRequest};
use busyncr_client::restore::{run_restore, RestoreError, RestoreRequest};
use busyncr_core::retention::RetentionPolicy;
use busyncr_daemon::identity::DaemonIdentity;
use busyncr_daemon::service;
use busyncr_daemon::store::ChunkStore;
use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};
use tonic::Code;
use ulid::Ulid;

const STEP_MS: i64 = 3 * 60 * 60 * 1000;
const DAY_MS: i64 = 24 * 60 * 60 * 1000;

/// Counts object files under `objects/<2hex>/<hex>` (ignoring `.tmp-` files).
fn object_file_count(store_root: &Path) -> usize {
    let objects = store_root.join("objects");
    let mut count = 0;
    let Ok(shards) = std::fs::read_dir(&objects) else {
        return 0;
    };
    for shard in shards.flatten() {
        if !shard.path().is_dir() {
            continue;
        }
        for entry in std::fs::read_dir(shard.path()).unwrap().flatten() {
            if !entry.file_name().to_string_lossy().starts_with(".tmp-") {
                count += 1;
            }
        }
    }
    count
}

struct Harness {
    store: Arc<ChunkStore>,
    store_dir: PathBuf,
    state: PathBuf,
    root: PathBuf,
    config: ClientConfig,
    rng: StdRng,
    shutdown: Option<tokio::sync::oneshot::Sender<()>>,
    server: tokio::task::JoinHandle<()>,
}

impl Harness {
    async fn new(base: &Path) -> Self {
        let store_dir = base.join("store");
        let store = Arc::new(ChunkStore::open(&store_dir).unwrap());
        let identity = Arc::new(DaemonIdentity::open_or_init(base.join("identity")).unwrap());

        let addr = SocketAddr::from((Ipv4Addr::LOCALHOST, 0));
        let (listener, local) = service::bind(addr).await.unwrap();
        let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
        let serve_store = Arc::clone(&store);
        let serve_identity = Arc::clone(&identity);
        let server = tokio::spawn(async move {
            service::serve_tls(serve_store, serve_identity, listener, async {
                let _ = shutdown_rx.await;
            })
            .await
            .unwrap();
        });
        let url = format!("https://{local}");

        let state = base.join("client-state");
        let ident = request_enrollment(&EnrollmentRequest {
            daemon_url: url.clone(),
            ca_cert_pem: identity.ca_cert_pem().to_owned(),
            token: identity.mint_token(&mut rand::rng()).unwrap(),
            name: "fr5-host".to_owned(),
        })
        .await
        .unwrap();
        enroll::save_identity(&state, &ident).unwrap();
        let mut rng = StdRng::seed_from_u64(4242);
        enroll::ensure_data_key(&state, &mut rng).unwrap();

        let root = base.join("src").join("data");
        std::fs::create_dir_all(&root).unwrap();

        let config_path = base.join("busyncr-client.toml");
        std::fs::write(
            &config_path,
            format!("daemon = \"{url}\"\nfolders = [\"src/data\"]\nchunk_target_size = \"4K\"\n"),
        )
        .unwrap();
        let config = ClientConfig::load(&config_path).unwrap();

        Self {
            store,
            store_dir,
            state,
            root,
            config,
            rng,
            shutdown: Some(shutdown_tx),
            server,
        }
    }

    /// Writes a distinct version of `data/file.bin` and returns its bytes.
    fn write_version(&self, seed: u64) -> Vec<u8> {
        let mut bytes = vec![0u8; 8 * 1024];
        StdRng::seed_from_u64(seed).fill_bytes(&mut bytes);
        std::fs::write(self.root.join("file.bin"), &bytes).unwrap();
        bytes
    }

    /// Backs up the current tree as a snapshot dated `time_ms`.
    async fn backup_at(&mut self, time_ms: i64, counter: u128) -> Ulid {
        let snapshot_id = Ulid::from_parts(time_ms as u64, counter);
        let request = BackupRequest {
            daemon_url: &self.config.daemon,
            state_dir: &self.state,
            roots: &self.config.folders,
            chunker: self.config.chunker(false).unwrap(),
            snapshot_id,
            created_at: time_ms / 1000,
        };
        run_backup(&request, &mut self.rng).await.unwrap();
        snapshot_id
    }

    async fn restore(
        &self,
        snapshot_id: Ulid,
        target: &Path,
    ) -> Result<busyncr_client::restore::RestoreReport, RestoreError> {
        run_restore(&RestoreRequest {
            daemon_url: &self.config.daemon,
            state_dir: &self.state,
            snapshot_id,
            target_dir: target,
        })
        .await
    }

    async fn stop(mut self) {
        drop(self.shutdown.take());
        self.server.await.unwrap();
    }
}

#[tokio::test]
async fn fr5_prune_and_gc_over_real_backups_keep_plan_survivors_restorable() {
    let dir = tempfile::tempdir().unwrap();
    let mut hx = Harness::new(dir.path()).await;

    // now aligned to a whole 3 h boundary so the two recent snapshots share
    // one 3 h cell.
    let now = (1_700_000_000_000i64 / STEP_MS) * STEP_MS;

    let v_old = hx.write_version(1);
    let old = hx.backup_at(now - 30 * DAY_MS, 1).await;
    let _v_b = hx.write_version(2);
    let b = hx.backup_at(now - 2 * 60 * 60 * 1000, 2).await;
    let _v_a = hx.write_version(3);
    let a = hx.backup_at(now - 60 * 60 * 1000, 3).await;

    assert_eq!(hx.store.list_snapshots().unwrap().len(), 3);
    let objects_before = object_file_count(&hx.store_dir);

    // Prune: `b` collides with the newer `a` in the same 3 h cell and is
    // dropped; `a` and `old` survive.
    let outcome = hx
        .store
        .prune(now, &RetentionPolicy::default_grid())
        .unwrap();
    assert_eq!(
        outcome.dropped,
        vec![b],
        "only the older same-cell snapshot is pruned"
    );
    let survivors: Vec<Ulid> = hx.store.list_snapshots().unwrap();
    assert_eq!(survivors.len(), 2);
    assert!(survivors.contains(&a) && survivors.contains(&old));
    assert!(!survivors.contains(&b));

    // The pruned snapshot is gone: restoring it fails NOT_FOUND, not a
    // partial tree.
    let gone = dir.path().join("restore-b");
    match hx.restore(b, &gone).await.unwrap_err() {
        RestoreError::Rpc(status) => assert_eq!(status.code(), Code::NotFound),
        other => panic!("expected NotFound for pruned snapshot, got {other:?}"),
    }

    // A surviving snapshot still restores byte-exact over real mTLS.
    let restored = dir.path().join("restore-old");
    let report = hx.restore(old, &restored).await.unwrap();
    assert_eq!(report.snapshot_id, old);
    let got = std::fs::read(restored.join("data").join("file.bin")).unwrap();
    assert_eq!(
        blake3::hash(&got),
        blake3::hash(&v_old),
        "restored survivor must be byte-exact"
    );
    assert_eq!(got, v_old);

    // GC reclaims the pruned snapshot's now-unreferenced chunks after grace,
    // shrinking the store; the survivors' chunks are spared.
    let grace = Duration::from_secs(3600);
    assert!(hx.store.gc(now, grace).unwrap().reclaimed.is_empty());
    let later = now + grace.as_millis() as i64 + 1;
    let reclaimed = hx.store.gc(later, grace).unwrap();
    assert!(
        !reclaimed.reclaimed.is_empty(),
        "GC must reclaim the pruned snapshot's unique chunks"
    );
    let objects_after = object_file_count(&hx.store_dir);
    assert!(
        objects_after < objects_before,
        "GC must shrink the store ({objects_after} < {objects_before})"
    );

    // The survivor still restores byte-exact after GC.
    let restored2 = dir.path().join("restore-old-2");
    let got2 = hx.restore(old, &restored2).await.unwrap();
    assert_eq!(got2.snapshot_id, old);
    assert_eq!(
        std::fs::read(restored2.join("data").join("file.bin")).unwrap(),
        v_old
    );

    hx.stop().await;
}
