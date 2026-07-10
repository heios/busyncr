//! FR-M1 acceptance: CLI monitoring + explicit manual/auto prune control.
//!
//! - `frm1a_*` — M1.2: `auto_prune = true` makes a completed backup trigger
//!   a prune whose surviving set matches `retention::plan`'s output;
//!   `auto_prune = false` leaves the store untouched across several backups
//!   until a manual prune runs (FR-M1a).
//! - `frm1b_*` — M2.1/M2.2: progress events mirror the exact same counters
//!   `BackupReport`/`RestoreReport` end with (never a shadow copy), and the
//!   real CLI's `--quiet` / `--json-progress` flags behave as documented
//!   (FR-M1b).
//! - `frm1c_*` — M3.1/M3.3: `busyncr-client status` surfaces enrollment
//!   identity, the persisted last-backup record, and daemon-side snapshot
//!   history once reachable (FR-M1c). `busyncr-daemon status`'s own ground
//!   truth is covered store-side by `busyncr-daemon`'s
//!   `frm1_status_and_prune_mode` suite (no client pipeline needed there).

use std::net::{Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;

use busyncr_client::backup::{run_backup, run_backup_with_progress, BackupReport, BackupRequest};
use busyncr_client::enroll::{self, request_enrollment, EnrollmentRequest};
use busyncr_core::retention::RetentionPolicy;
use busyncr_daemon::identity::DaemonIdentity;
use busyncr_daemon::service;
use busyncr_daemon::store::ChunkStore;
use rand::rngs::StdRng;
use rand::SeedableRng;
use ulid::Ulid;

const STEP_MS: i64 = 3 * 60 * 60 * 1000; // 3 hours
const DAY_MS: i64 = 24 * 60 * 60 * 1000;

fn client_bin() -> Command {
    Command::new(env!("CARGO_BIN_EXE_busyncr-client"))
}

/// An in-process mTLS daemon with a controllable `auto_prune` setting
/// (FR-M1 M1.2) — `serve_tls_with_config`'s test-facing knob.
struct TlsDaemon {
    identity: Arc<DaemonIdentity>,
    store: Arc<ChunkStore>,
    url: String,
    shutdown: Option<tokio::sync::oneshot::Sender<()>>,
    server: tokio::task::JoinHandle<()>,
}

impl TlsDaemon {
    async fn spawn(root: &Path, auto_prune: bool) -> Self {
        let store = Arc::new(ChunkStore::open(root.join("store")).unwrap());
        let identity = Arc::new(DaemonIdentity::open_or_init(root.join("identity")).unwrap());
        let addr = SocketAddr::from((Ipv4Addr::LOCALHOST, 0));
        let (listener, local) = service::bind(addr).await.unwrap();
        let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
        let serve_store = Arc::clone(&store);
        let serve_identity = Arc::clone(&identity);
        let server = tokio::spawn(async move {
            service::serve_tls_with_config(
                serve_store,
                serve_identity,
                listener,
                async {
                    let _ = shutdown_rx.await;
                },
                auto_prune,
            )
            .await
            .unwrap();
        });
        Self {
            identity,
            store,
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

/// Enrolls `name` against `daemon`, returning its state directory.
async fn enroll_client(base: &Path, daemon: &TlsDaemon, name: &str) -> PathBuf {
    let state = base.join(format!("client-state-{name}"));
    let identity = request_enrollment(&EnrollmentRequest {
        daemon_url: daemon.url.clone(),
        ca_cert_pem: daemon.identity.ca_cert_pem().to_owned(),
        token: daemon.identity.mint_token(&mut rand::rng()).unwrap(),
        name: name.to_owned(),
    })
    .await
    .unwrap();
    enroll::save_identity(&state, &identity).unwrap();
    let mut rng = StdRng::seed_from_u64(9000);
    enroll::ensure_data_key(&state, &mut rng).unwrap();
    state
}

/// Backs up `root` (containing a single `file.bin`) as a snapshot dated
/// `time_ms`, against `daemon`, using `state`.
async fn backup_at(
    daemon: &TlsDaemon,
    state: &Path,
    root: &Path,
    time_ms: i64,
    counter: u128,
) -> Ulid {
    let snapshot_id = Ulid::from_parts(time_ms as u64, counter);
    let request = BackupRequest {
        daemon_url: &daemon.url,
        state_dir: state,
        roots: &[root.to_owned()],
        chunker: busyncr_core::chunking::ChunkerConfig::with_target(4096).unwrap(),
        compression: Default::default(),
        snapshot_id,
        created_at: time_ms / 1000,
    };
    run_backup(&request, &mut StdRng::seed_from_u64(counter as u64 + 1))
        .await
        .unwrap();
    snapshot_id
}

/// FR-M1a: `auto_prune = true` makes each completed backup trigger a prune
/// whose surviving set equals what `retention::plan` (FR5's own machinery)
/// would compute independently for the same instant.
#[tokio::test]
async fn frm1a_auto_prune_true_triggers_grid_prune_matching_plan_after_each_backup() {
    let dir = tempfile::tempdir().unwrap();
    let daemon = TlsDaemon::spawn(dir.path(), true).await;
    let state = enroll_client(dir.path(), &daemon, "auto-host").await;

    let root = dir.path().join("data");
    std::fs::create_dir_all(&root).unwrap();
    std::fs::write(root.join("file.bin"), b"v1").unwrap();

    // Real "now", aligned to a whole 3h boundary (matches FR5's own
    // retention-grid tests) so `old`/`b`/`a` land in predictable cells
    // regardless of when this test happens to run.
    let real_now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as i64;
    let now = (real_now_ms / STEP_MS) * STEP_MS;

    let old = backup_at(&daemon, &state, &root, now - 30 * DAY_MS, 1).await;
    std::fs::write(root.join("file.bin"), b"v2").unwrap();
    let b = backup_at(&daemon, &state, &root, now - 2 * 60 * 60 * 1000, 2).await;
    std::fs::write(root.join("file.bin"), b"v3").unwrap();
    // The daemon's auto-prune runs with its *own* real-clock "now" at the
    // instant each PutManifest completes (a few ms after ours, at most) —
    // irrelevant to which 3h/24h/4d/16d cell any of these land in.
    let a = backup_at(&daemon, &state, &root, now - 60 * 60 * 1000, 3).await;

    // `b` collides with the newer `a` in the same 3h cell and must already
    // be gone — no manual `prune` was ever run.
    let survivors = daemon.store.list_snapshots().unwrap();
    assert!(
        survivors.contains(&a) && survivors.contains(&old) && !survivors.contains(&b),
        "auto-prune must have already dropped {b} by the time backup() returned: got {survivors:?}"
    );

    // Cross-check against retention::plan computed independently, using the
    // real "now" at the moment of this check (a race-tolerant upper bound —
    // any auto-prune that already ran used an earlier or equal "now").
    let check_now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as i64;
    let items: Vec<(i64, Ulid)> = vec![old, b, a]
        .into_iter()
        .map(|id| (id.timestamp_ms() as i64, id))
        .collect();
    let plan = busyncr_core::retention::plan(check_now, &items, &RetentionPolicy::default_grid());
    assert_eq!(
        survivors
            .into_iter()
            .collect::<std::collections::HashSet<_>>(),
        plan.keep
            .into_iter()
            .collect::<std::collections::HashSet<_>>(),
        "auto-prune's surviving set must equal retention::plan's output"
    );

    let status = daemon.store.status().unwrap();
    let last_prune = status
        .last_prune
        .expect("auto-prune must have recorded an event");
    assert_eq!(last_prune.mode, busyncr_daemon::store::PruneMode::Auto);

    daemon.stop().await;
}

/// FR-M1a: `auto_prune = false` never prunes on its own, even across
/// several backups that would collide in the same grid cell — only the
/// operator's manual `prune` changes anything.
#[tokio::test]
async fn frm1a_auto_prune_false_leaves_snapshots_untouched_without_manual_prune() {
    let dir = tempfile::tempdir().unwrap();
    let daemon = TlsDaemon::spawn(dir.path(), false).await;
    let state = enroll_client(dir.path(), &daemon, "manual-host").await;

    let root = dir.path().join("data");
    std::fs::create_dir_all(&root).unwrap();

    let real_now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as i64;
    let now = (real_now_ms / STEP_MS) * STEP_MS;

    // Five backups, all within the same 3h cell: under any auto-pruning
    // policy this would immediately thin to one survivor. With
    // auto_prune = false, none of them may disappear on their own.
    let mut ids = Vec::new();
    for i in 0..5u128 {
        std::fs::write(root.join("file.bin"), format!("v{i}")).unwrap();
        let id = backup_at(&daemon, &state, &root, now, i + 1).await;
        ids.push(id);
    }

    let mut survivors = daemon.store.list_snapshots().unwrap();
    survivors.sort();
    let mut expected = ids.clone();
    expected.sort();
    assert_eq!(
        survivors, expected,
        "auto_prune = false must never drop a snapshot on its own"
    );
    assert!(
        daemon.store.status().unwrap().last_prune.is_none(),
        "no prune of any kind has run yet"
    );

    // Manual prune (still available in both modes, FR-M1 M1.2) now thins
    // the same set down to the grid's prediction.
    let outcome = daemon
        .store
        .prune(
            now,
            &RetentionPolicy::default_grid(),
            busyncr_daemon::store::PruneMode::Manual,
        )
        .unwrap();
    assert_eq!(
        outcome.kept.len(),
        1,
        "five same-cell snapshots collapse to one on manual prune"
    );
    let status = daemon.store.status().unwrap();
    assert_eq!(
        status.last_prune.unwrap().mode,
        busyncr_daemon::store::PruneMode::Manual
    );

    daemon.stop().await;
}

/// FR-M1b/M2.2: every progress observation during a real backup carries the
/// exact same counters the final `BackupReport` ends with — the last event
/// equals the final report field-for-field, and every field the renderer
/// uses is monotone non-decreasing across the run.
#[tokio::test]
async fn frm1b_progress_events_are_monotone_and_final_event_matches_final_report() {
    let dir = tempfile::tempdir().unwrap();
    let daemon = TlsDaemon::spawn(dir.path(), false).await;
    let state = enroll_client(dir.path(), &daemon, "progress-host").await;

    let root = dir.path().join("data");
    std::fs::create_dir_all(&root).unwrap();
    // Several files spanning multiple chunks so more than one progress
    // event fires.
    for i in 0..6 {
        std::fs::write(root.join(format!("f{i}.bin")), vec![i as u8; 20_000]).unwrap();
    }

    let request = BackupRequest {
        daemon_url: &daemon.url,
        state_dir: &state,
        roots: std::slice::from_ref(&root),
        chunker: busyncr_core::chunking::ChunkerConfig::with_target(4096).unwrap(),
        compression: Default::default(),
        snapshot_id: Ulid::new(),
        created_at: 1_700_000_000,
    };

    let events: std::sync::Mutex<Vec<(BackupReport, bool)>> = std::sync::Mutex::new(Vec::new());
    let report = run_backup_with_progress(
        &request,
        &mut StdRng::seed_from_u64(3),
        &mut |report, _totals, final_tick| {
            events.lock().unwrap().push((report.clone(), final_tick));
        },
    )
    .await
    .unwrap();

    let events = events.into_inner().unwrap();
    assert!(
        events.len() >= 2,
        "expected multiple progress observations, got {}",
        events.len()
    );

    let (last_report, last_final) = events.last().unwrap();
    assert!(*last_final, "the last observation must be marked final");
    // The FR3 transfer-ledger fields progress actually renders must match
    // the final report exactly (FR-M1b). `manifest_bytes`/`compression` are
    // finalized after the last progress tick (they belong to the
    // manifest-upload step, not the chunk-shipping ledger progress tracks)
    // so they are deliberately excluded from this comparison.
    assert_eq!(last_report.snapshot_id, report.snapshot_id);
    assert_eq!(last_report.files, report.files);
    assert_eq!(last_report.source_bytes, report.source_bytes);
    assert_eq!(last_report.chunks_total, report.chunks_total);
    assert_eq!(last_report.chunks_unique, report.chunks_unique);
    assert_eq!(last_report.chunks_uploaded, report.chunks_uploaded);
    assert_eq!(last_report.chunks_deduped, report.chunks_deduped);
    assert_eq!(
        last_report.upload_bytes, report.upload_bytes,
        "the final progress event's upload_bytes must equal the final FR3 ledger"
    );
    assert_eq!(
        events.iter().filter(|(_, f)| *f).count(),
        1,
        "exactly one observation is marked final"
    );

    for pair in events.windows(2) {
        let (a, _) = &pair[0];
        let (b, _) = &pair[1];
        assert!(b.files >= a.files);
        assert!(b.chunks_total >= a.chunks_total);
        assert!(b.chunks_unique >= a.chunks_unique);
        assert!(b.chunks_uploaded >= a.chunks_uploaded);
        assert!(b.chunks_deduped >= a.chunks_deduped);
        assert!(
            b.upload_bytes >= a.upload_bytes,
            "upload_bytes must never decrease"
        );
    }

    daemon.stop().await;
}

/// FR-M1b: the real CLI's `--quiet` suppresses progress entirely (a
/// successful run's stderr is empty), and `--json-progress` emits NDJSON
/// lines that all parse and whose final line's counters match the run's own
/// printed summary.
///
/// `multi_thread`: this test blocks the calling task on real subprocess I/O
/// (`Command::output`) while the in-process daemon it talks to runs as a
/// spawned task on the same runtime — a `current_thread` runtime would
/// starve the daemon task for the duration of the blocking call and
/// deadlock (same rationale as `fr8_scheduler_restart`'s equivalent test).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn frm1b_cli_quiet_is_silent_and_json_progress_emits_parseable_monotone_ndjson() {
    let dir = tempfile::tempdir().unwrap();
    let daemon = TlsDaemon::spawn(dir.path(), false).await;
    let state = enroll_client(dir.path(), &daemon, "cli-host").await;

    let root = dir.path().join("data");
    std::fs::create_dir_all(&root).unwrap();
    for i in 0..4 {
        std::fs::write(root.join(format!("f{i}.bin")), vec![7u8; 30_000]).unwrap();
    }
    let config_path = dir.path().join("busyncr-client.toml");
    std::fs::write(
        &config_path,
        format!(
            "daemon = \"{}\"\nfolders = [{:?}]\nchunk_target_size = \"4K\"\n",
            daemon.url,
            root.to_str().unwrap()
        ),
    )
    .unwrap();

    // --quiet: stderr must be empty on a successful run.
    let quiet_out = client_bin()
        .args(["backup", "--config"])
        .arg(&config_path)
        .arg("--state")
        .arg(&state)
        .arg("--quiet")
        .output()
        .unwrap();
    assert!(quiet_out.status.success(), "{:?}", quiet_out);
    assert!(
        quiet_out.stderr.is_empty(),
        "--quiet must emit nothing on stderr, got: {}",
        String::from_utf8_lossy(&quiet_out.stderr)
    );

    // A second backup (new content, so it actually ships something) with
    // --json-progress: every stderr line is NDJSON, fields are monotone,
    // and the last line's cumulative counters match the human summary this
    // same run printed on stdout.
    std::fs::write(root.join("f0.bin"), vec![9u8; 30_000]).unwrap();
    let json_out = client_bin()
        .args(["backup", "--config"])
        .arg(&config_path)
        .arg("--state")
        .arg(&state)
        .arg("--json-progress")
        .output()
        .unwrap();
    assert!(json_out.status.success(), "{:?}", json_out);

    let stderr = String::from_utf8(json_out.stderr).unwrap();
    let lines: Vec<&str> = stderr.lines().filter(|l| !l.trim().is_empty()).collect();
    assert!(
        !lines.is_empty(),
        "--json-progress must emit at least one NDJSON line"
    );

    let mut prev_bytes_up = 0u64;
    let mut prev_files = 0u64;
    let mut last_value: Option<serde_json::Value> = None;
    for line in &lines {
        let value: serde_json::Value = serde_json::from_str(line)
            .unwrap_or_else(|e| panic!("line {line:?} did not parse as JSON: {e}"));
        assert_eq!(value["event"], "backup_progress");
        let bytes_up = value["bytes_up"].as_u64().unwrap();
        let files = value["files"].as_u64().unwrap();
        assert!(
            bytes_up >= prev_bytes_up,
            "bytes_up must be monotone non-decreasing"
        );
        assert!(files >= prev_files, "files must be monotone non-decreasing");
        prev_bytes_up = bytes_up;
        prev_files = files;
        last_value = Some(value);
    }

    let stdout = String::from_utf8(json_out.stdout).unwrap();
    // The human summary prints "shipped <n> new chunk(s) = <bytes> encrypted bytes".
    let shipped_bytes: u64 = stdout
        .lines()
        .find_map(|l| {
            let l = l.trim();
            l.strip_prefix("shipped ").and_then(|rest| {
                let after_eq = rest.split("= ").nth(1)?;
                after_eq.split_whitespace().next()?.parse().ok()
            })
        })
        .expect("summary line with shipped bytes");
    let last = last_value.unwrap();
    assert_eq!(
        last["bytes_up"].as_u64().unwrap(),
        shipped_bytes,
        "the last NDJSON event's bytes_up must match the run's own final tally"
    );

    daemon.stop().await;
}

/// FR-M1c: `busyncr-client status --json` shows the enrolled identity, the
/// last-backup record persisted by the backup just run, and (with a
/// reachable daemon) the snapshot it just stored.
///
/// `multi_thread`: see the rationale on `frm1b_cli_quiet_...` above — this
/// test also blocks on real subprocess I/O beside the in-process daemon.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn frm1c_client_status_shows_identity_last_backup_and_daemon_snapshots() {
    let dir = tempfile::tempdir().unwrap();
    let daemon = TlsDaemon::spawn(dir.path(), false).await;
    let state = enroll_client(dir.path(), &daemon, "status-host").await;

    let root = dir.path().join("data");
    std::fs::create_dir_all(&root).unwrap();
    std::fs::write(root.join("f.bin"), b"hello status").unwrap();
    let config_path = dir.path().join("busyncr-client.toml");
    std::fs::write(
        &config_path,
        format!(
            "daemon = \"{}\"\nfolders = [{:?}]\nchunk_target_size = \"4K\"\n",
            daemon.url,
            root.to_str().unwrap()
        ),
    )
    .unwrap();

    // Before any backup: enrolled, but no last-backup record yet.
    let pre = client_bin()
        .args(["status", "--state"])
        .arg(&state)
        .arg("--config")
        .arg(&config_path)
        .arg("--json")
        .output()
        .unwrap();
    assert!(pre.status.success(), "{:?}", pre);
    let pre_json: serde_json::Value = serde_json::from_slice(&pre.stdout).unwrap();
    assert_eq!(pre_json["enrolled"], true);
    assert_eq!(pre_json["name"], "status-host");
    assert!(pre_json["last_backup"].is_null());

    let backup_out = client_bin()
        .args(["backup", "--config"])
        .arg(&config_path)
        .arg("--state")
        .arg(&state)
        .arg("--quiet")
        .output()
        .unwrap();
    assert!(backup_out.status.success(), "{:?}", backup_out);
    let stdout = String::from_utf8(backup_out.stdout).unwrap();
    let snapshot_id = stdout
        .lines()
        .next()
        .and_then(|l| l.split_whitespace().nth(1))
        .expect("first line: \"snapshot <id> stored on ...\"")
        .to_owned();

    let post = client_bin()
        .args(["status", "--state"])
        .arg(&state)
        .arg("--config")
        .arg(&config_path)
        .arg("--json")
        .output()
        .unwrap();
    assert!(post.status.success(), "{:?}", post);
    let post_json: serde_json::Value = serde_json::from_slice(&post.stdout).unwrap();
    assert_eq!(post_json["enrolled"], true);
    assert_eq!(post_json["daemon_reachable"], true);
    assert_eq!(post_json["last_backup"]["snapshot_id"], snapshot_id);
    assert_eq!(post_json["last_backup"]["files"], 1);
    let recent = post_json["recent_snapshots"].as_array().unwrap();
    assert!(
        recent.iter().any(|s| s["id"] == snapshot_id),
        "recent_snapshots must include the snapshot just backed up: {recent:?}"
    );

    daemon.stop().await;
}
