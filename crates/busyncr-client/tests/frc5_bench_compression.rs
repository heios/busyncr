//! FR-C5 acceptance tests: `bench-chunking --compression` (FR-C1 §4)
//! against the CLI and against the real backup pipeline.
//!
//! * `frc5a_*` — CLI-level: single-pass guarantee already has a dedicated
//!   core-level test (`busyncr_core::policy_bench::tests::frc5a_*`); here we
//!   check the CLI surface itself — JSON schema (`compression_policies` key,
//!   five named policies, FR-C1 §4.5), and the `--sizes` validation guard.
//! * `frc5b_*` — per-policy stored-bytes figures from the simulator match an
//!   end-to-end real backup of the same corpus under the same policy
//!   exactly (same zstd version, FR-C1 §5).
//! * `frc5c_*` — `--baseline` incremental projection matches a real second
//!   backup's shipped bytes within ±5%.
//!
//! FR-C5d (speed-model internal consistency) is covered at the core level
//! (`busyncr_core::policy_bench::tests::frc5d_*`), which is where the model
//! actually lives; nothing pipeline-specific to add here.

use std::net::{Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;

use busyncr_client::backup::{run_backup, BackupReport, BackupRequest};
use busyncr_client::enroll::{self, request_enrollment, EnrollmentRequest};
use busyncr_core::chunking::ChunkerConfig;
use busyncr_core::compression::{Phase, PolicyConfig};
use busyncr_core::policy_bench::{chunk_tree_with_bytes, simulate_policy, PolicyKind};
use busyncr_daemon::identity::DaemonIdentity;
use busyncr_daemon::service;
use busyncr_daemon::store::ChunkStore;
use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};
use ulid::Ulid;

fn client_bin() -> Command {
    Command::new(env!("CARGO_BIN_EXE_busyncr-client"))
}

fn compressible_bytes(len: usize) -> Vec<u8> {
    b"the quick brown fox jumps over the lazy dog; SELECT * FROM t; "
        .iter()
        .copied()
        .cycle()
        .take(len)
        .collect()
}

fn incompressible_bytes(len: usize, seed: u64) -> Vec<u8> {
    let mut buf = vec![0u8; len];
    StdRng::seed_from_u64(seed).fill_bytes(&mut buf);
    buf
}

/// A daemon + enrolled client, mirroring `frc2_frc7_compression_pipeline`'s
/// harness — the minimal pieces FR-C5b/c need to run a *real* backup to
/// compare against the offline simulator.
struct Harness {
    state: PathBuf,
    root: PathBuf,
    daemon_url: String,
    chunker: ChunkerConfig,
    rng: StdRng,
    shutdown: Option<tokio::sync::oneshot::Sender<()>>,
    server: tokio::task::JoinHandle<()>,
}

impl Harness {
    async fn new(base: &Path, target_size: usize) -> Self {
        let store = Arc::new(ChunkStore::open(base.join("store")).unwrap());
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
        let daemon_url = format!("https://{local}");

        let state = base.join("client-state");
        let issued = request_enrollment(&EnrollmentRequest {
            daemon_url: daemon_url.clone(),
            ca_cert_pem: identity.ca_cert_pem().to_owned(),
            token: identity.mint_token(&mut rand::rng()).unwrap(),
            name: "frc5-host".to_owned(),
        })
        .await
        .unwrap();
        enroll::save_identity(&state, &issued).unwrap();
        let mut rng = StdRng::seed_from_u64(271828);
        enroll::ensure_data_key(&state, &mut rng).unwrap();

        let root = base.join("src").join("data");
        std::fs::create_dir_all(&root).unwrap();

        Self {
            state,
            root,
            daemon_url,
            chunker: ChunkerConfig::with_target(target_size).unwrap(),
            rng,
            shutdown: Some(shutdown_tx),
            server,
        }
    }

    async fn backup(&mut self, seq: u64, compression: PolicyConfig) -> BackupReport {
        let request = BackupRequest {
            daemon_url: &self.daemon_url,
            state_dir: &self.state,
            roots: std::slice::from_ref(&self.root),
            chunker: self.chunker,
            compression,
            snapshot_id: Ulid::from_parts(1_700_100_000_000 + seq, u128::from(seq)),
            created_at: 1_700_100_000 + seq as i64,
        };
        run_backup(&request, &mut self.rng).await.unwrap()
    }

    async fn stop(mut self) {
        drop(self.shutdown.take());
        self.server.await.unwrap();
    }
}

// --- FR-C5a: CLI surface ------------------------------------------------

#[test]
fn frc5a_cli_reports_all_five_policies_under_compression_policies_key() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("a.txt"), compressible_bytes(200 * 1024)).unwrap();
    std::fs::write(
        dir.path().join("b.bin"),
        incompressible_bytes(120 * 1024, 5),
    )
    .unwrap();

    let output = client_bin()
        .args([
            "bench-chunking",
            dir.path().to_str().unwrap(),
            "--sizes",
            "64K",
            "--compression",
            "--json",
        ])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "bench-chunking --compression failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let json: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    let policies = json["compression_policies"]["policies"].as_array().unwrap();
    let names: Vec<&str> = policies
        .iter()
        .map(|p| p["policy"].as_str().unwrap())
        .collect();
    assert_eq!(
        names,
        vec![
            "raw-only",
            "zstd3-always",
            "zstd3",
            "probe+zstd3",
            "zstd3+escalate"
        ],
        "FR-C1 §4.1: at minimum these five policies, in table order"
    );

    // Every row carries the §4.2 stored-bytes/ratio figures and a §4.4
    // initial-backup speed projection with one entry per default
    // --net-mbps point (50, 200, 1000).
    for row in policies {
        assert!(row["stored"]["stored_bytes"].as_u64().unwrap() > 0);
        assert!(row["stored"]["ratio"].as_f64().unwrap() > 0.0);
        let bandwidth = row["initial_backup"]["at_bandwidth"].as_array().unwrap();
        assert_eq!(bandwidth.len(), 3);
        assert!(row["incremental"].is_null(), "no --baseline given");
    }

    let recommended = json["compression_policies"]["recommended_policy"]
        .as_str()
        .unwrap();
    assert!(names.contains(&recommended));
}

#[test]
fn frc5a_cli_compression_rejects_multiple_size_candidates() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("a.bin"), incompressible_bytes(4096, 1)).unwrap();

    let output = client_bin()
        .args([
            "bench-chunking",
            dir.path().to_str().unwrap(),
            "--sizes",
            "64K,256K",
            "--compression",
        ])
        .output()
        .unwrap();
    assert!(
        !output.status.success(),
        "--compression with >1 --sizes candidate must be rejected"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("exactly one"),
        "error must explain the single-candidate restriction: {stderr}"
    );
}

// --- FR-C5b: sim stored bytes match a real backup exactly ---------------

/// Builds the unkeyed unique-chunk set bench-chunking would see for `root`
/// under `cfg` (mirrors the CLI's own single-pass collection, at the core
/// level, so this test is independent of the CLI's rendering/JSON layer).
fn unique_chunk_bytes(root: &Path, cfg: &ChunkerConfig) -> Vec<Vec<u8>> {
    let (files, _io_time) = chunk_tree_with_bytes(root, cfg).unwrap();
    let mut unique = std::collections::HashMap::new();
    for f in &files {
        for c in &f.chunks {
            unique.entry(c.id).or_insert_with(|| c.data.clone());
        }
    }
    unique.into_values().collect()
}

#[tokio::test]
async fn frc5b_simulated_stored_bytes_match_real_first_backup_exactly() {
    let dir = tempfile::tempdir().unwrap();
    let target = 64 * 1024;

    // A mixed corpus: compressible text, incompressible "media", and a
    // duplicated file (exercises intra-snapshot dedup in both the real
    // pipeline and the offline simulator identically, per FR-C1 C1.3: chunk
    // identity — and therefore which byte runs are "the same chunk" — does
    // not depend on compression policy or on keyed vs. unkeyed hashing).
    let text = compressible_bytes(300 * 1024);
    let media = incompressible_bytes(180 * 1024, 42);

    for kind in [
        PolicyKind::RawOnly,
        PolicyKind::Zstd3Always,
        PolicyKind::Zstd3,
        PolicyKind::ProbeZstd3,
    ] {
        // Fresh daemon per policy so dedup from a previous iteration cannot
        // make this backup's upload volume artificially smaller.
        let iter_dir = dir.path().join(format!("iter-{}", kind.name()));
        std::fs::create_dir_all(&iter_dir).unwrap();
        let mut iter_hx = Harness::new(&iter_dir, target).await;
        std::fs::write(iter_hx.root.join("log.txt"), &text).unwrap();
        std::fs::write(iter_hx.root.join("blob.bin"), &media).unwrap();
        std::fs::write(iter_hx.root.join("log-copy.txt"), &text).unwrap();

        let report = iter_hx.backup(1, kind.config()).await;

        let unique = unique_chunk_bytes(&iter_hx.root, &iter_hx.chunker);
        let sim = simulate_policy(&unique, kind, Phase::InitialFull);

        assert_eq!(
            report.upload_bytes,
            sim.stored_bytes,
            "policy {}: real first-backup upload bytes must equal the \
             simulator's stored_bytes exactly (same zstd version)",
            kind.name()
        );
        assert_eq!(report.chunks_unique, sim.chunk_count);

        iter_hx.stop().await;
    }
}

// --- FR-C5c: baseline incremental projection within ±5% of a real second
// backup's shipped bytes ---------------------------------------------------

#[tokio::test]
async fn frc5c_baseline_incremental_projection_within_five_percent_of_real_second_backup() {
    let dir = tempfile::tempdir().unwrap();
    let target = 32 * 1024;
    let mut hx = Harness::new(dir.path(), target).await;

    // Baseline snapshot: three files.
    let unchanged = incompressible_bytes(200 * 1024, 1);
    let old_a = compressible_bytes(150 * 1024);
    let old_b = incompressible_bytes(90 * 1024, 2);
    std::fs::write(hx.root.join("unchanged.bin"), &unchanged).unwrap();
    std::fs::write(hx.root.join("a.txt"), &old_a).unwrap();
    std::fs::write(hx.root.join("b.bin"), &old_b).unwrap();
    let report1 = hx.backup(1, PolicyConfig::default()).await;
    assert_eq!(report1.chunks_deduped, 0);

    // Snapshot the baseline tree on disk (the offline tool's --baseline
    // input) before mutating it for the incremental snapshot.
    let baseline_dir = dir.path().join("baseline-copy");
    copy_tree(&hx.root, &baseline_dir);

    // Mutation: one file changes, one new file appears, one is untouched.
    let new_a = {
        let mut v = old_a.clone();
        v.extend_from_slice(b" -- appended tail changes the CDC boundary near the end");
        v
    };
    let new_c = compressible_bytes(64 * 1024);
    std::fs::write(hx.root.join("a.txt"), &new_a).unwrap();
    std::fs::write(hx.root.join("c.txt"), &new_c).unwrap();

    let report2 = hx.backup(2, PolicyConfig::default()).await;
    assert!(
        report2.chunks_uploaded > 0,
        "the mutation must actually ship new chunks"
    );

    // Offline projection: current tree vs. the baseline copy, zstd3,
    // Phase::Incremental (a prior snapshot exists in the real timeline).
    let cfg = hx.chunker;
    let current_unique: std::collections::HashMap<_, _> = {
        let (files, _) = chunk_tree_with_bytes(&hx.root, &cfg).unwrap();
        files
            .iter()
            .flat_map(|f| f.chunks.iter().map(|c| (c.id, c.data.clone())))
            .collect()
    };
    let baseline_ids: std::collections::HashSet<_> = {
        let (files, _) = chunk_tree_with_bytes(&baseline_dir, &cfg).unwrap();
        files
            .iter()
            .flat_map(|f| f.chunks.iter().map(|c| c.id))
            .collect()
    };
    let delta: Vec<Vec<u8>> = current_unique
        .iter()
        .filter(|(id, _)| !baseline_ids.contains(id))
        .map(|(_, data)| data.clone())
        .collect();
    assert!(!delta.is_empty(), "the mutation must produce new chunks");

    let sim = simulate_policy(&delta, PolicyKind::Zstd3, Phase::Incremental);

    let real = report2.upload_bytes as f64;
    let projected = sim.stored_bytes as f64;
    let relative_error = (projected - real).abs() / real;
    assert!(
        relative_error <= 0.05,
        "projected incremental stored bytes ({projected}) must be within \
         ±5% of the real second backup's shipped bytes ({real}); got {:.2}% error",
        relative_error * 100.0
    );

    hx.stop().await;
}

fn copy_tree(src: &Path, dst: &Path) {
    std::fs::create_dir_all(dst).unwrap();
    for entry in std::fs::read_dir(src).unwrap() {
        let entry = entry.unwrap();
        let dest = dst.join(entry.file_name());
        if entry.file_type().unwrap().is_dir() {
            copy_tree(&entry.path(), &dest);
        } else {
            std::fs::copy(entry.path(), &dest).unwrap();
        }
    }
}
