//! FR8 acceptance (non-Windows part, SLICES S10): scheduler + restart
//! robustness.
//!
//! `fr8_daemon_restart_mid_upload_converges_and_stays_consistent` kills the
//! daemon abruptly (no graceful drain — every open connection is dropped
//! mid-request, standing in for `kill -9`) while a backup is mid-upload,
//! restarts it against the same on-disk store, and proves: the interrupted
//! attempt left no phantom snapshot, the next backup converges to a
//! complete, byte-exact-restorable snapshot, and every chunk the store
//! considers zero-ref (GC-eligible) is one the surviving snapshot does *not*
//! reference — i.e. nothing left over from the crash is miscounted as live.
//!
//! `fr8_client_run_scheduler_survives_restart` drives `run_scheduler`
//! against a real daemon on a short real interval, stops it (simulating the
//! client process being killed), and starts a fresh `run_scheduler` call
//! (simulating the client restarting) to prove the schedule resumes rather
//! than getting stuck.

use std::collections::HashSet;
use std::net::{Ipv4Addr, SocketAddr};
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use busyncr_client::backup::{run_backup, BackupRequest};
use busyncr_client::enroll::{self, request_enrollment, EnrollmentRequest};
use busyncr_client::restore::{run_restore, RestoreRequest};
use busyncr_client::run::{run_scheduler, RunRequest, SystemClock};
use busyncr_core::chunking::{chunk_bytes_keyed, ChunkId, ChunkerConfig};
use busyncr_core::scheduler::SchedulePolicy;
use busyncr_daemon::identity::DaemonIdentity;
use busyncr_daemon::service;
use busyncr_daemon::store::ChunkStore;
use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};
use ulid::Ulid;

/// Counts object files under `objects/<2hex>/<hex>` (ignoring `.tmp-` files
/// a torn write may have left behind — see `ChunkStore::sweep_tmp_files`).
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

/// A daemon standing on its own dedicated tokio runtime (its own worker
/// thread pool) — the closest in-process stand-in for a separate OS
/// process. [`Self::kill`] tears the whole runtime down abruptly: every
/// open connection and in-flight request it was serving is dropped without
/// completing, unlike tonic's graceful shutdown (which drains in-flight
/// work before returning) or aborting a single task within a *shared*
/// runtime (which would not touch the independently-spawned per-connection
/// tasks hyper creates).
struct DaemonProcess {
    runtime: Option<tokio::runtime::Runtime>,
    url: String,
}

impl DaemonProcess {
    /// Starts a fresh daemon serving `store`/`identity` on an ephemeral
    /// localhost port.
    async fn start(store: Arc<ChunkStore>, identity: Arc<DaemonIdentity>) -> Self {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .unwrap();
        let (addr_tx, addr_rx) = tokio::sync::oneshot::channel::<SocketAddr>();
        runtime.spawn(async move {
            let (listener, local) = service::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
                .await
                .unwrap();
            let _ = addr_tx.send(local);
            // No shutdown signal ever fires here on purpose: this daemon is
            // only ever stopped via `kill`, which tears the whole runtime
            // down regardless of what `serve_tls` is doing.
            let _ = service::serve_tls(store, identity, listener, std::future::pending()).await;
        });
        let local = addr_rx.await.unwrap();
        Self {
            runtime: Some(runtime),
            url: format!("https://{local}"),
        }
    }

    /// Abruptly terminates the daemon ("kill -9"): blocks (briefly, on a
    /// blocking-pool thread so this is callable from async test code) until
    /// every task and resource belonging to this runtime — including every
    /// `Arc<ChunkStore>` clone it was holding — has actually been torn
    /// down, so the caller can safely reopen the same on-disk store the
    /// instant this returns (mirroring a real process exit releasing its
    /// file handles before a restart can reopen them).
    async fn kill(&mut self) {
        if let Some(rt) = self.runtime.take() {
            tokio::task::spawn_blocking(move || rt.shutdown_timeout(Duration::from_secs(5)))
                .await
                .unwrap();
        }
    }
}

impl Drop for DaemonProcess {
    fn drop(&mut self) {
        // Best-effort, non-blocking cleanup for the common "test just ended"
        // path — `Drop::drop` cannot `.await`, so this cannot offer the same
        // synchronous teardown guarantee as `kill`; call `kill` explicitly
        // wherever the test relies on that guarantee (e.g. before reopening
        // the same on-disk store).
        if let Some(rt) = self.runtime.take() {
            rt.shutdown_background();
        }
    }
}

/// Enrolls a fresh client identity (state dir) against `daemon`.
async fn enroll_client(daemon: &DaemonProcess, identity: &DaemonIdentity, state: &Path) {
    let issued = request_enrollment(&EnrollmentRequest {
        daemon_url: daemon.url.clone(),
        ca_cert_pem: identity.ca_cert_pem().to_owned(),
        token: identity.mint_token(&mut rand::rng()).unwrap(),
        name: "fr8-host".to_owned(),
    })
    .await
    .unwrap();
    enroll::save_identity(state, &issued).unwrap();
    enroll::ensure_data_key(state, &mut StdRng::seed_from_u64(2024)).unwrap();
}

/// FR8: a daemon killed mid-upload, restarted against the same store,
/// converges on the next backup attempt and leaves no inconsistency behind.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn fr8_daemon_restart_mid_upload_converges_and_stays_consistent() {
    let dir = tempfile::tempdir().unwrap();
    let store_dir = dir.path().join("store");
    let identity_dir = dir.path().join("identity");
    let state = dir.path().join("client-state");

    let store1 = Arc::new(ChunkStore::open(&store_dir).unwrap());
    let identity1 = Arc::new(DaemonIdentity::open_or_init(&identity_dir).unwrap());
    let mut daemon = DaemonProcess::start(Arc::clone(&store1), Arc::clone(&identity1)).await;
    enroll_client(&daemon, &identity1, &state).await;

    // A large tree of unique random content: many CDC chunks at a small
    // target size, so a real backup spans many upload round trips — plenty
    // of window to catch it mid-flight and kill the daemon underneath it.
    let root = dir.path().join("src").join("data");
    std::fs::create_dir_all(&root).unwrap();
    let mut data = vec![0u8; 6 * 1024 * 1024];
    StdRng::seed_from_u64(55).fill_bytes(&mut data);
    std::fs::write(root.join("big.bin"), &data).unwrap();

    let chunker = ChunkerConfig::with_target(4096).unwrap();
    // Recompute chunk IDs with the backup set's keyed-chunk-ID key, exactly as
    // the backup pipeline does (FR-K1), so this set matches what the daemon
    // actually stores.
    let chunk_id_key = enroll::load_chunk_id_key(&state).unwrap();
    let local_chunks: Vec<ChunkId> = chunk_bytes_keyed(&data, &chunker, &chunk_id_key)
        .iter()
        .map(|c| c.id)
        .collect();
    let unique_chunks: HashSet<ChunkId> = local_chunks.iter().copied().collect();
    assert!(
        unique_chunks.len() > 200,
        "the corpus must span many chunks to give the kill a wide window, got {}",
        unique_chunks.len()
    );

    // First (doomed) attempt: run in the background while we watch the
    // store fill up, then kill the daemon out from under it.
    let attempt1 = {
        let daemon_url = daemon.url.clone();
        let state = state.clone();
        let root = root.clone();
        tokio::spawn(async move {
            let request = BackupRequest {
                daemon_url: &daemon_url,
                state_dir: &state,
                roots: &[root],
                chunker,
                compression: Default::default(),
                snapshot_id: Ulid::from_parts(1, 1),
                created_at: 1_700_000_000,
            };
            run_backup(&request, &mut StdRng::seed_from_u64(9)).await
        })
    };

    let deadline = tokio::time::Instant::now() + Duration::from_secs(20);
    loop {
        assert!(
            tokio::time::Instant::now() < deadline,
            "backup never reached the kill threshold before the test deadline"
        );
        if object_file_count(&store_dir) >= 40 {
            break;
        }
        if attempt1.is_finished() {
            // Finished (or errored) before we ever caught it mid-flight —
            // the scenario this test targets did not occur.
            panic!(
                "first backup attempt finished before the mid-upload kill point \
                 (only {} objects stored) — widen the corpus or lower the threshold",
                object_file_count(&store_dir)
            );
        }
        tokio::time::sleep(Duration::from_millis(3)).await;
    }
    let partial_objects = object_file_count(&store_dir);
    assert!(
        partial_objects < unique_chunks.len(),
        "the kill must land before the upload finished ({partial_objects} of {})",
        unique_chunks.len()
    );

    daemon.kill().await;
    // `kill` guarantees the daemon's own clone is gone; drop ours too so the
    // "restart" below can reopen the same on-disk store (redb refuses a
    // second concurrent open of the same file within one process).
    drop(store1);

    let result1 = attempt1.await.unwrap();
    assert!(
        result1.is_err(),
        "a backup whose daemon was killed mid-upload must fail, not silently succeed"
    );

    // Store consistency right after the crash: no snapshot exists (the
    // crashed attempt never reached PutManifest).
    {
        let store_check = ChunkStore::open(&store_dir).unwrap();
        assert!(
            store_check.list_snapshots().unwrap().is_empty(),
            "an interrupted upload must never leave a partial snapshot behind"
        );
    }

    // Restart: reopen the same store and identity (a real daemon restart
    // would do exactly this) and serve again.
    let store2 = Arc::new(ChunkStore::open(&store_dir).unwrap());
    let identity2 = Arc::new(DaemonIdentity::open_or_init(&identity_dir).unwrap());
    let daemon2 = DaemonProcess::start(Arc::clone(&store2), Arc::clone(&identity2)).await;

    // Second attempt against the restarted daemon must converge: it dedups
    // whatever survived the crash (cheaper than attempt 1) and completes.
    let request2 = BackupRequest {
        daemon_url: &daemon2.url,
        state_dir: &state,
        roots: std::slice::from_ref(&root),
        chunker,
        compression: Default::default(),
        snapshot_id: Ulid::from_parts(2, 2),
        created_at: 1_700_000_100,
    };
    let report2 = run_backup(&request2, &mut rand::rng()).await.unwrap();
    assert_eq!(report2.chunks_unique, unique_chunks.len() as u64);
    assert_eq!(
        report2.chunks_uploaded + report2.chunks_deduped,
        report2.chunks_unique
    );
    assert!(
        report2.chunks_uploaded < unique_chunks.len() as u64,
        "the second attempt must dedup at least some chunks the crashed \
         attempt already stored, got {} uploaded of {} unique",
        report2.chunks_uploaded,
        unique_chunks.len()
    );

    // Exactly one snapshot exists — the converged one.
    assert_eq!(
        store2.list_snapshots().unwrap(),
        vec![report2.snapshot_id],
        "the store must hold exactly the one snapshot that actually completed"
    );

    // No orphaned partial is counted as live: every chunk the manifest
    // needs is referenced (refcount >= 1); every zero-ref chunk (GC
    // fodder, possibly leftover from the crashed attempt) is one the
    // surviving snapshot does *not* need.
    for id in &unique_chunks {
        let entry = store2.chunk_entry(*id).unwrap().unwrap_or_else(|| {
            panic!("chunk {id} referenced by the surviving manifest must be stored")
        });
        assert!(
            entry.refcount >= 1,
            "chunk {id} is referenced by the live snapshot but has refcount 0"
        );
    }
    for zero_ref in store2.zero_ref_chunks().unwrap() {
        assert!(
            !unique_chunks.contains(&zero_ref),
            "chunk {zero_ref} is both zero-ref and part of the live snapshot's chunk set"
        );
    }

    // The converged snapshot restores byte-exact.
    let restored = dir.path().join("restored");
    let restore_report = run_restore(&RestoreRequest {
        daemon_url: &daemon2.url,
        state_dir: &state,
        snapshot_id: report2.snapshot_id,
        target_dir: &restored,
    })
    .await
    .unwrap();
    assert_eq!(restore_report.snapshot_id, report2.snapshot_id);
    let got = std::fs::read(restored.join("data").join("big.bin")).unwrap();
    assert_eq!(blake3::hash(&got), blake3::hash(&data));

    drop(daemon2);
}

/// FR8: the client `run` scheduler survives being stopped and started again
/// — a fresh `run_scheduler` call after "restart" keeps producing backups
/// on schedule rather than getting stuck, and every attempt (before and
/// after) lands a real, listed snapshot.
#[tokio::test]
async fn fr8_client_run_scheduler_survives_restart() {
    let dir = tempfile::tempdir().unwrap();
    let store = Arc::new(ChunkStore::open(dir.path().join("store")).unwrap());
    let identity = Arc::new(DaemonIdentity::open_or_init(dir.path().join("identity")).unwrap());

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

    let state = dir.path().join("client-state");
    let issued = request_enrollment(&EnrollmentRequest {
        daemon_url: url.clone(),
        ca_cert_pem: identity.ca_cert_pem().to_owned(),
        token: identity.mint_token(&mut rand::rng()).unwrap(),
        name: "fr8-scheduler-host".to_owned(),
    })
    .await
    .unwrap();
    enroll::save_identity(&state, &issued).unwrap();
    enroll::ensure_data_key(&state, &mut StdRng::seed_from_u64(11)).unwrap();

    let root = dir.path().join("src").join("data");
    std::fs::create_dir_all(&root).unwrap();
    std::fs::write(root.join("note.txt"), b"hello scheduler\n").unwrap();

    // A short real interval: the scheduler cadence itself is unit-tested
    // deterministically against a virtual clock in `busyncr_client::run`;
    // here `SystemClock` + a real (small) interval exercises the whole
    // "restart resumes the schedule" flow against a real daemon.
    let schedule = SchedulePolicy::new(Duration::from_millis(120), 0.0).unwrap();
    let request = RunRequest {
        daemon_url: &url,
        state_dir: &state,
        roots: std::slice::from_ref(&root),
        chunker: ChunkerConfig::with_target(4096).unwrap(),
        compression: Default::default(),
        schedule,
    };

    // First "process lifetime": run the scheduler for 3 ticks, then stop it
    // (simulating the client being killed).
    let mut rng1 = StdRng::seed_from_u64(1);
    let seen1 = std::sync::Mutex::new(Vec::new());
    let mut remaining1 = 3;
    let (cancel1_tx, cancel1_rx) = tokio::sync::oneshot::channel::<()>();
    let mut cancel1_tx = Some(cancel1_tx);
    run_scheduler(
        &request,
        &SystemClock,
        &mut rng1,
        Box::pin(async move {
            let _ = cancel1_rx.await;
        }),
        |tick| {
            seen1
                .lock()
                .unwrap()
                .push(tick.result.map(|r| r.snapshot_id));
            remaining1 -= 1;
            if remaining1 == 0 {
                if let Some(tx) = cancel1_tx.take() {
                    let _ = tx.send(());
                }
            }
        },
    )
    .await;
    let first_run: Vec<_> = seen1.into_inner().unwrap();
    assert_eq!(first_run.len(), 3);
    for outcome in &first_run {
        assert!(
            outcome.is_ok(),
            "every tick against a live daemon must back up successfully: {outcome:?}"
        );
    }

    // "Restart": a brand new run_scheduler call — new RNG, new tick
    // counter, nothing carried over except the same config/state — must
    // still produce backups immediately and keep going.
    let mut rng2 = StdRng::seed_from_u64(2);
    let seen2 = std::sync::Mutex::new(Vec::new());
    let mut remaining2 = 2;
    let (cancel2_tx, cancel2_rx) = tokio::sync::oneshot::channel::<()>();
    let mut cancel2_tx = Some(cancel2_tx);
    run_scheduler(
        &request,
        &SystemClock,
        &mut rng2,
        Box::pin(async move {
            let _ = cancel2_rx.await;
        }),
        |tick| {
            seen2
                .lock()
                .unwrap()
                .push(tick.result.map(|r| r.snapshot_id));
            remaining2 -= 1;
            if remaining2 == 0 {
                if let Some(tx) = cancel2_tx.take() {
                    let _ = tx.send(());
                }
            }
        },
    )
    .await;
    let second_run: Vec<_> = seen2.into_inner().unwrap();
    assert_eq!(
        second_run.len(),
        2,
        "the restarted scheduler must resume ticking rather than stalling"
    );
    for outcome in &second_run {
        assert!(
            outcome.is_ok(),
            "post-restart ticks must also succeed: {outcome:?}"
        );
    }

    // All 5 snapshots across both "process lifetimes" are on the daemon,
    // distinct, and every one still restores byte-exact.
    let mut client = enroll::connect_authenticated(&url, &state).await.unwrap();
    let listed = client
        .list_snapshots(busyncr_proto::v1::ListSnapshotsRequest {})
        .await
        .unwrap()
        .into_inner()
        .snapshot_ids
        .len();
    assert_eq!(
        listed, 5,
        "every tick across both runs must be a real, listed snapshot"
    );

    let all_ids: HashSet<Ulid> = first_run
        .iter()
        .chain(second_run.iter())
        .map(|r| r.as_ref().unwrap())
        .copied()
        .collect();
    assert_eq!(
        all_ids.len(),
        5,
        "every tick must produce a distinct snapshot"
    );

    let last = *second_run.last().unwrap().as_ref().unwrap();
    let restored = dir.path().join("restored");
    let report = run_restore(&RestoreRequest {
        daemon_url: &url,
        state_dir: &state,
        snapshot_id: last,
        target_dir: &restored,
    })
    .await
    .unwrap();
    assert_eq!(report.snapshot_id, last);
    assert_eq!(
        std::fs::read(restored.join("data").join("note.txt")).unwrap(),
        b"hello scheduler\n"
    );

    drop(shutdown_tx);
    server.await.unwrap();
}
