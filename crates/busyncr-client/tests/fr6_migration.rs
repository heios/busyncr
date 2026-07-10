//! FR6 acceptance test: keyfile export + import on a "new machine" (fresh
//! client state, new certificate) restores the old machine's history.
//!
//! Flow under test (PRD §3.4 "Key export / migration"):
//!
//! 1. Machine A enrolls, backs up two snapshots (with an edit in between —
//!    real history, not one state twice), and exports its data key as a
//!    passphrase-protected keyfile.
//! 2. Machine B starts from a completely fresh state directory, enrolls
//!    with a *new* one-time token (its own certificate — identity is never
//!    migrated), and `import-key`s A's keyfile.
//! 3. `list` on machine B shows A's full history; both snapshots restore
//!    byte-exact against copies of the source tree taken at backup time.
//!
//! Plus the negative halves that make the positive halves meaningful:
//! without the import the manifests do not decrypt, and a wrong passphrase
//! imports nothing.

use std::net::{Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use busyncr_client::backup::{run_backup, BackupReport, BackupRequest};
use busyncr_client::config::ClientConfig;
use busyncr_client::enroll::{self, request_enrollment, EnrollmentRequest};
use busyncr_client::keys::{self, ImportOutcome, KeyError};
use busyncr_client::restore::{run_restore, RestoreError, RestoreRequest};
use busyncr_client::snapshots;
use busyncr_core::crypto::{CryptoError, KdfParams};
use busyncr_daemon::identity::DaemonIdentity;
use busyncr_daemon::service;
use busyncr_daemon::store::ChunkStore;
use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};
use ulid::Ulid;

/// Cheap Argon2id parameters so the suite stays fast; production-strength
/// parameters are exercised in busyncr-core's crypto tests.
const TEST_KDF: KdfParams = KdfParams {
    m_cost_kib: 16,
    t_cost: 1,
    p_cost: 1,
};

const PASSPHRASE: &[u8] = b"correct horse battery staple";

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

    /// Enrolls a machine: fresh one-time token, new keypair + certificate,
    /// state persisted under `state_dir`, data key created (FR1 flow — what
    /// a real migration runs on the new machine too).
    async fn enroll_machine(&self, state_dir: &Path, name: &str, rng: &mut StdRng) {
        let identity = request_enrollment(&EnrollmentRequest {
            daemon_url: self.url.clone(),
            ca_cert_pem: self.identity.ca_cert_pem().to_owned(),
            token: self.identity.mint_token(&mut rand::rng()).unwrap(),
            name: name.to_owned(),
        })
        .await
        .unwrap();
        enroll::save_identity(state_dir, &identity).unwrap();
        enroll::ensure_data_key(state_dir, rng).unwrap();
    }

    async fn stop(mut self) {
        drop(self.shutdown.take());
        self.server.await.unwrap();
    }
}

/// Recursively copies `src` into `dst` (contents, mtimes not needed — the
/// copies only serve as byte-content references).
fn copy_tree(src: &Path, dst: &Path) {
    std::fs::create_dir_all(dst).unwrap();
    for entry in std::fs::read_dir(src).unwrap() {
        let entry = entry.unwrap();
        let from = entry.path();
        let to = dst.join(entry.file_name());
        if from.is_dir() {
            copy_tree(&from, &to);
        } else {
            std::fs::copy(&from, &to).unwrap();
        }
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

/// Asserts the restored tree under `restored_root` is byte-identical to the
/// reference copy at `reference_root`.
fn assert_trees_equal(reference_root: &Path, restored_root: &Path) {
    let reference = list_files(reference_root);
    let restored = list_files(restored_root);
    assert_eq!(reference, restored, "file sets differ");
    assert!(!reference.is_empty());
    for rel in &reference {
        let want = std::fs::read(reference_root.join(rel)).unwrap();
        let got = std::fs::read(restored_root.join(rel)).unwrap();
        assert_eq!(
            blake3::hash(&want),
            blake3::hash(&got),
            "content mismatch for {rel:?}"
        );
        assert_eq!(want, got, "content mismatch for {rel:?}");
    }
}

/// Backs up `roots` as one snapshot with a deterministic ULID.
async fn backup(
    daemon_url: &str,
    state: &Path,
    roots: &[PathBuf],
    chunker: busyncr_core::chunking::ChunkerConfig,
    seq: u64,
    rng: &mut StdRng,
) -> BackupReport {
    let request = BackupRequest {
        daemon_url,
        state_dir: state,
        roots,
        chunker,
        compression: Default::default(),
        snapshot_id: Ulid::from_parts(1_700_000_000_000 + seq * 3_600_000, u128::from(seq)),
        created_at: 1_700_000_000 + (seq * 3600) as i64,
    };
    run_backup(&request, rng).await.unwrap()
}

/// FR6: full migration flow — machine A backs up history, exports its key;
/// a fresh machine B enrolls with a new token (new cert), imports the
/// keyfile, sees the history via `list`, and restores every snapshot
/// byte-exact. Without the import (or with a wrong passphrase) the history
/// stays sealed.
#[tokio::test]
async fn fr6_new_machine_with_imported_keyfile_restores_old_history() {
    let dir = tempfile::tempdir().unwrap();
    let base = dir.path();
    let daemon = TlsDaemon::spawn(base).await;
    let mut rng = StdRng::seed_from_u64(6001);

    // --- Machine A: enroll, build two-snapshot history, export keyfile. ---
    let state_a = base.join("machine-a");
    daemon.enroll_machine(&state_a, "machine-a", &mut rng).await;

    let root = base.join("src").join("data");
    std::fs::create_dir_all(root.join("nested")).unwrap();
    let mut big = vec![0u8; 128 * 1024];
    StdRng::seed_from_u64(21).fill_bytes(&mut big);
    std::fs::write(root.join("big.bin"), &big).unwrap();
    std::fs::write(root.join("nested").join("note.txt"), b"version one\n").unwrap();

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

    let v1_copy = base.join("copies").join("v1");
    copy_tree(&root, &v1_copy);
    let report1 = backup(&daemon.url, &state_a, &config.folders, chunker, 1, &mut rng).await;

    // Edit between snapshots: mutate the big file, change the note, add a
    // file — snapshot 2 is genuinely different history.
    big[4096] ^= 0xFF;
    std::fs::write(root.join("big.bin"), &big).unwrap();
    std::fs::write(root.join("nested").join("note.txt"), b"version two\n").unwrap();
    std::fs::write(root.join("added-later.txt"), b"only in v2\n").unwrap();
    let v2_copy = base.join("copies").join("v2");
    copy_tree(&root, &v2_copy);
    let report2 = backup(&daemon.url, &state_a, &config.folders, chunker, 2, &mut rng).await;
    assert_ne!(report1.snapshot_id, report2.snapshot_id);

    let keyfile = base.join("busyncr-a.keyfile");
    keys::export_key(&state_a, &keyfile, PASSPHRASE, &TEST_KDF, &mut rng).unwrap();

    // --- Machine B: fresh state dir, NEW token → its own certificate. ---
    let state_b = base.join("machine-b");
    assert!(!state_b.exists(), "machine B must start from nothing");
    daemon.enroll_machine(&state_b, "machine-b", &mut rng).await;
    // Its own identity, not A's...
    assert_ne!(
        std::fs::read(state_a.join(enroll::CLIENT_CERT_FILE)).unwrap(),
        std::fs::read(state_b.join(enroll::CLIENT_CERT_FILE)).unwrap(),
        "machine B must have its own certificate (identity is never migrated)"
    );
    // ...and (pre-import) its own fresh data key.
    let fresh_key_b = enroll::load_data_key(&state_b).unwrap();
    assert_ne!(fresh_key_b, enroll::load_data_key(&state_a).unwrap());

    // Before import, the history is sealed: the manifest does not decrypt
    // under B's fresh key.
    let sealed = run_restore(&RestoreRequest {
        daemon_url: &daemon.url,
        state_dir: &state_b,
        snapshot_id: report2.snapshot_id,
        target_dir: &base.join("restored-sealed"),
    })
    .await
    .unwrap_err();
    assert!(
        matches!(sealed, RestoreError::Crypto(CryptoError::Decrypt)),
        "without the keyfile the history must stay sealed, got {sealed:?}"
    );

    // Wrong passphrase imports nothing and changes nothing.
    let bad = keys::import_key(&state_b, &keyfile, b"not the passphrase").unwrap_err();
    assert!(matches!(bad, KeyError::Crypto(CryptoError::KeyfileUnlock)));
    assert_eq!(enroll::load_data_key(&state_b).unwrap(), fresh_key_b);

    // The real import replaces B's fresh key (preserving it on disk).
    let outcome = keys::import_key(&state_b, &keyfile, PASSPHRASE).unwrap();
    let backed_up = match outcome {
        ImportOutcome::Replaced { backed_up } => backed_up,
        other => panic!("expected Replaced, got {other:?}"),
    };
    assert!(backed_up.exists(), "B's fresh key must be preserved");
    assert_eq!(
        enroll::load_data_key(&state_b).unwrap(),
        enroll::load_data_key(&state_a).unwrap(),
        "import must install exactly A's data key"
    );

    // `list` on machine B shows A's full history, oldest first.
    let listed = snapshots::list_snapshots(&daemon.url, &state_b)
        .await
        .unwrap();
    assert_eq!(
        listed.iter().map(|e| e.id).collect::<Vec<_>>(),
        vec![report1.snapshot_id, report2.snapshot_id],
        "machine B must see machine A's snapshot history"
    );
    for entry in &listed {
        assert_eq!(entry.timestamp_ms, entry.id.timestamp_ms());
    }

    // Both snapshots restore byte-exact against the reference copies taken
    // at backup time.
    let restored_v1 = base.join("restored-v1");
    let r1 = run_restore(&RestoreRequest {
        daemon_url: &daemon.url,
        state_dir: &state_b,
        snapshot_id: report1.snapshot_id,
        target_dir: &restored_v1,
    })
    .await
    .unwrap();
    assert_eq!(r1.files, report1.files);
    assert_trees_equal(&v1_copy, &restored_v1.join("data"));

    let restored_v2 = base.join("restored-v2");
    let r2 = run_restore(&RestoreRequest {
        daemon_url: &daemon.url,
        state_dir: &state_b,
        snapshot_id: report2.snapshot_id,
        target_dir: &restored_v2,
    })
    .await
    .unwrap();
    assert_eq!(r2.files, report2.files);
    assert_trees_equal(&v2_copy, &restored_v2.join("data"));

    daemon.stop().await;
}

/// FR6 continuation: the migrated machine is not read-only — after the key
/// import it continues the same backup set, deduplicating against machine
/// A's chunks, and the new snapshot appears in the shared history.
#[tokio::test]
async fn fr6_migrated_machine_continues_the_backup_set() {
    let dir = tempfile::tempdir().unwrap();
    let base = dir.path();
    let daemon = TlsDaemon::spawn(base).await;
    let mut rng = StdRng::seed_from_u64(6002);

    let state_a = base.join("machine-a");
    daemon.enroll_machine(&state_a, "machine-a", &mut rng).await;

    let root = base.join("src").join("data");
    std::fs::create_dir_all(&root).unwrap();
    let mut payload = vec![0u8; 96 * 1024];
    StdRng::seed_from_u64(31).fill_bytes(&mut payload);
    std::fs::write(root.join("payload.bin"), &payload).unwrap();

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

    let report_a = backup(&daemon.url, &state_a, &config.folders, chunker, 1, &mut rng).await;
    let keyfile = base.join("busyncr-a.keyfile");
    keys::export_key(&state_a, &keyfile, PASSPHRASE, &TEST_KDF, &mut rng).unwrap();

    // Migrate to machine B (the "same data moved to new hardware" story).
    let state_b = base.join("machine-b");
    daemon.enroll_machine(&state_b, "machine-b", &mut rng).await;
    keys::import_key(&state_b, &keyfile, PASSPHRASE).unwrap();

    // B backs up the unchanged tree: with A's keys installed (data key AND
    // keyed-chunk-ID key, FR-K1), every chunk it produces hashes to the same
    // keyed ID A stored, so it already exists on the daemon — importing the
    // keyfile v2 is exactly what preserves this dedup continuity across the
    // migration.
    let report_b = backup(&daemon.url, &state_b, &config.folders, chunker, 2, &mut rng).await;
    assert_eq!(
        report_b.chunks_uploaded, 0,
        "an unchanged tree from the migrated machine must fully deduplicate"
    );
    assert_eq!(report_b.upload_bytes, 0);

    // The shared history now lists A's and B's snapshots side by side.
    let listed = snapshots::list_snapshots(&daemon.url, &state_b)
        .await
        .unwrap();
    assert_eq!(
        listed.iter().map(|e| e.id).collect::<Vec<_>>(),
        vec![report_a.snapshot_id, report_b.snapshot_id]
    );

    // And B's snapshot restores byte-exact too.
    let restored = base.join("restored-b");
    run_restore(&RestoreRequest {
        daemon_url: &daemon.url,
        state_dir: &state_b,
        snapshot_id: report_b.snapshot_id,
        target_dir: &restored,
    })
    .await
    .unwrap();
    assert_eq!(
        std::fs::read(restored.join("data").join("payload.bin")).unwrap(),
        payload
    );

    daemon.stop().await;
}
