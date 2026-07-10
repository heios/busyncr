//! FR10 acceptance tests for the `bench-chunking` CLI (PRD §3.7).
//!
//! The engine-level FR10 guarantees (single read pass, reference-run
//! equivalence, exact projection arithmetic, baseline overlap) are asserted
//! in `busyncr-core::bench`; these tests drive the real binary end to end
//! and cross-check its JSON output against independent reference runs.

use std::collections::HashSet;
use std::path::Path;
use std::process::Command;

use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};

use busyncr_core::chunking::{chunk_bytes, ChunkerConfig};
use busyncr_core::index::IndexEntry;

fn client_bin() -> Command {
    Command::new(env!("CARGO_BIN_EXE_busyncr-client"))
}

fn random_bytes(len: usize, seed: u64) -> Vec<u8> {
    let mut rng = StdRng::seed_from_u64(seed);
    let mut buf = vec![0u8; len];
    rng.fill_bytes(&mut buf);
    buf
}

/// Writes a small deterministic corpus; returns (file name, bytes) pairs.
fn write_corpus(root: &Path) -> Vec<(String, Vec<u8>)> {
    let sizes = [220 * 1024, 150 * 1024 + 33, 64 * 1024, 512];
    let mut files = Vec::new();
    std::fs::create_dir_all(root.join("sub")).unwrap();
    for (i, len) in sizes.into_iter().enumerate() {
        let name = if i % 2 == 0 {
            format!("file{i}.bin")
        } else {
            format!("sub/file{i}.bin")
        };
        let data = random_bytes(len, 500 + i as u64);
        std::fs::write(root.join(&name), &data).unwrap();
        files.push((name, data));
    }
    files
}

#[test]
fn fr10_cli_json_report_matches_reference_measurements() {
    let dir = tempfile::tempdir().unwrap();
    let corpus = write_corpus(dir.path());
    let corpus_bytes: u64 = corpus.iter().map(|(_, d)| d.len() as u64).sum();

    let output = client_bin()
        .args([
            "bench-chunking",
            dir.path().to_str().unwrap(),
            "--sizes",
            "16K,64K",
            "--snapshots",
            "5",
            "--json",
        ])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "bench-chunking failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let json: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(json["files_scanned"], 4);
    assert_eq!(json["total_bytes"], corpus_bytes);
    assert_eq!(json["snapshots_projected"], 5);
    assert!(json["baseline_root"].is_null());
    assert!(json["note"]
        .as_str()
        .unwrap()
        .contains("intra-snapshot only"));

    let candidates = json["candidates"].as_array().unwrap();
    assert_eq!(candidates.len(), 2);

    for (candidate, target) in candidates.iter().zip([16 * 1024usize, 64 * 1024]) {
        assert_eq!(candidate["target_size"], target as u64);

        // Independent single-candidate reference run per file.
        let config = ChunkerConfig::with_target(target).unwrap();
        let mut total_chunks = 0u64;
        let mut unique = HashSet::new();
        let mut unique_bytes = 0u64;
        for (_, data) in &corpus {
            for chunk in chunk_bytes(data, &config) {
                total_chunks += 1;
                if unique.insert(chunk.id) {
                    unique_bytes += chunk.len() as u64;
                }
            }
        }

        assert_eq!(
            candidate["total_chunks"], total_chunks,
            "fan-out totals must match single-candidate reference for {target}"
        );
        assert_eq!(candidate["unique_chunks"], unique.len() as u64);
        assert_eq!(candidate["unique_bytes"], unique_bytes);
        assert_eq!(candidate["total_bytes"], corpus_bytes);
        // Projection arithmetic: exact, from the shared index layout.
        assert_eq!(
            candidate["index_bytes"],
            unique.len() as u64 * IndexEntry::WIRE_SIZE
        );
        let manifest = candidate["manifest_bytes_per_snapshot"].as_u64().unwrap();
        assert_eq!(
            candidate["projected_bookkeeping_bytes"].as_u64().unwrap(),
            candidate["index_bytes"].as_u64().unwrap() + 5 * manifest
        );
        assert!(candidate["baseline"].is_null());
    }

    // The recommendation must be one of the candidates.
    let recommended = json["recommended_target_size"].as_u64().unwrap();
    assert!([16 * 1024, 64 * 1024].contains(&recommended));
}

#[test]
fn fr10_cli_baseline_identical_tree_reports_full_overlap() {
    let current = tempfile::tempdir().unwrap();
    let baseline = tempfile::tempdir().unwrap();
    for (name, data) in write_corpus(current.path()) {
        let dest = baseline.path().join(&name);
        std::fs::create_dir_all(dest.parent().unwrap()).unwrap();
        std::fs::write(dest, data).unwrap();
    }

    let output = client_bin()
        .args([
            "bench-chunking",
            current.path().to_str().unwrap(),
            "--sizes",
            "16K",
            "--baseline",
            baseline.path().to_str().unwrap(),
            "--json",
        ])
        .output()
        .unwrap();
    assert!(output.status.success());

    let json: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    let candidate = &json["candidates"][0];
    let overlap = &candidate["baseline"];
    assert_eq!(
        overlap["shared_unique_chunks"],
        candidate["unique_chunks"].as_u64().unwrap()
    );
    assert_eq!(overlap["overlap_percent"], 100.0);
}

#[test]
fn fr10_cli_default_snapshots_is_steady_state_grid_occupancy() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("one.bin"), random_bytes(4096, 1)).unwrap();

    let output = client_bin()
        .args([
            "bench-chunking",
            dir.path().to_str().unwrap(),
            "--sizes",
            "64K",
            "--json",
        ])
        .output()
        .unwrap();
    assert!(output.status.success());
    let json: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    // PRD §3.5 grid over the documented 1-year horizon: 8 + 3 + 3 + 22 = 36.
    assert_eq!(json["snapshots_projected"], 36);
}

#[test]
fn fr10_cli_human_table_highlights_recommendation() {
    let dir = tempfile::tempdir().unwrap();
    write_corpus(dir.path());

    let output = client_bin()
        .args([
            "bench-chunking",
            dir.path().to_str().unwrap(),
            "--sizes",
            "16K,64K",
        ])
        .output()
        .unwrap();
    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.contains("recommended:"), "table output: {stdout}");
    assert!(stdout.contains("intra-snapshot only"));
    assert!(stdout.contains("16K"));
    assert!(stdout.contains("64K"));
}

#[test]
fn fr10_cli_rejects_missing_path() {
    let output = client_bin()
        .args(["bench-chunking", "/definitely/not/a/real/path"])
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(!output.stderr.is_empty());
}
