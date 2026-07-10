//! FR5 acceptance: retention grid + prune + GC over a simulated 60-day clock.
//!
//! This drives the daemon's [`ChunkStore`] directly (no network): the
//! retention plan, prune, and GC are all daemon/store logic, and the store
//! path is identical for plaintext and encrypted manifests (both populate the
//! `snapshot_refs` table that prune/GC decrement, PRD §3.4). Restore over real
//! mutual TLS is covered by the FR4 suite and by `fr5_retention_e2e` on the
//! client side; here "restore byte-exact" is proven by reassembling each
//! survivor's files from `get_chunk` and comparing to the original bytes.
//!
//! The scenario: 481 snapshots taken exactly every 3 hours across 60 days
//! (`t_k = k * 3h`, `now = t_480`). Each snapshot stores one chunk unique to
//! it plus one chunk shared by every snapshot, so prune leaves the dropped
//! snapshots' unique chunks unreferenced (GC fodder) while the shared chunk
//! and the survivors' unique chunks stay live.

use std::collections::HashSet;
use std::path::Path;
use std::time::Duration;

use busyncr_core::chunking::ChunkId;
use busyncr_core::manifest::{FileEntry, Manifest};
use busyncr_core::retention::{self, RetentionPolicy};
use busyncr_daemon::store::ChunkStore;
use ulid::Ulid;

const STEP_MS: i64 = 3 * 60 * 60 * 1000; // 3 hours
const LAST_K: i64 = 60 * 8; // 8 snapshots/day * 60 days = 480

/// Content of snapshot `k`'s unique file.
fn unique_content(k: i64) -> Vec<u8> {
    format!("snapshot {k} unique payload — distinct across the whole history")
        .into_bytes()
        .repeat(4)
}

/// The one chunk every snapshot shares.
fn shared_content() -> Vec<u8> {
    b"shared payload present in every single snapshot of the history".to_vec()
}

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
            let name = entry.file_name();
            if !name.to_string_lossy().starts_with(".tmp-") {
                count += 1;
            }
        }
    }
    count
}

/// Reassembles a survivor's files from the store and asserts each is
/// byte-exact against the original content it was built from.
fn assert_survivor_restores_byte_exact(store: &ChunkStore, snapshot: Ulid, k: i64) {
    let manifest = store
        .get_manifest(snapshot)
        .expect("survivor manifest present");
    assert_eq!(manifest.files.len(), 2, "each snapshot has two files");
    for file in &manifest.files {
        let mut assembled = Vec::new();
        for chunk in &file.chunks {
            assembled.extend_from_slice(&store.get_chunk(*chunk).expect("survivor chunk present"));
        }
        let expected = match file.path.as_str() {
            p if p.ends_with("unique.bin") => unique_content(k),
            p if p.ends_with("shared.bin") => shared_content(),
            other => panic!("unexpected file path {other}"),
        };
        assert_eq!(
            assembled, expected,
            "byte-exact reassembly of {}",
            file.path
        );
    }
}

#[test]
fn fr5_sixty_day_grid_prunes_to_plan_survivors_restore_and_gc_shrinks_disk() {
    let dir = tempfile::tempdir().unwrap();
    let store_root = dir.path().join("store");
    let store = ChunkStore::open(&store_root).unwrap();

    // The shared chunk, stored once.
    let shared = shared_content();
    let shared_id = ChunkId::of(&shared);
    store.put_chunk(shared_id, &shared).unwrap();

    // Build 481 snapshots, one every 3 hours; remember each snapshot's ULID
    // and the `k` it was built from (for byte-exact restore checks).
    let mut items: Vec<(i64, Ulid)> = Vec::new();
    let mut k_of: std::collections::HashMap<Ulid, i64> = std::collections::HashMap::new();
    for k in 0..=LAST_K {
        let time_ms = k * STEP_MS;
        let snapshot = Ulid::from_parts(time_ms as u64, k as u128);
        items.push((time_ms, snapshot));
        k_of.insert(snapshot, k);

        let unique = unique_content(k);
        let unique_id = ChunkId::of(&unique);
        store.put_chunk(unique_id, &unique).unwrap();

        let manifest = Manifest {
            snapshot_id: snapshot,
            created_at: time_ms / 1000,
            files: vec![
                FileEntry {
                    path: "data/unique.bin".into(),
                    size: unique.len() as u64,
                    mtime_secs: time_ms / 1000,
                    mtime_nanos: 0,
                    mode: 0o100644,
                    chunks: vec![unique_id],
                },
                FileEntry {
                    path: "data/shared.bin".into(),
                    size: shared.len() as u64,
                    mtime_secs: 0,
                    mtime_nanos: 0,
                    mode: 0o100644,
                    chunks: vec![shared_id],
                },
            ],
        };
        store.put_manifest(&manifest).unwrap();
    }

    let total = (LAST_K + 1) as usize;
    assert_eq!(store.list_snapshots().unwrap().len(), total);
    // 481 unique chunks + 1 shared chunk.
    assert_eq!(object_file_count(&store_root), total + 1);

    // Independent expected survivor set from the pure planner.
    let now = LAST_K * STEP_MS;
    let policy = RetentionPolicy::default_grid();
    let expected = retention::plan(now, &items, &policy);
    let expected_keep: HashSet<Ulid> = expected.keep.iter().copied().collect();
    // Ties the integration scenario to the hand-computed FR5a count (19).
    assert_eq!(
        expected_keep.len(),
        19,
        "grid must retain 19 of 481 snapshots"
    );

    // Prune applies exactly that plan.
    let outcome = store.prune(now, &policy).unwrap();
    assert_eq!(
        outcome.kept.iter().copied().collect::<HashSet<_>>(),
        expected_keep,
        "prune's kept set must equal the planner's"
    );
    let surviving: HashSet<Ulid> = store.list_snapshots().unwrap().into_iter().collect();
    assert_eq!(
        surviving, expected_keep,
        "the store's surviving snapshots must equal the plan exactly"
    );
    assert_eq!(outcome.dropped.len(), total - 19);

    // Every survivor still restores byte-exact (manifest + chunks intact).
    for &snapshot in &expected.keep {
        assert_survivor_restores_byte_exact(&store, snapshot, k_of[&snapshot]);
    }

    // After prune, the 462 dropped snapshots' unique chunks are zero-ref; the
    // shared chunk (19 refs) and the 19 survivors' unique chunks (1 ref each)
    // remain live.
    let dropped_count = total - 19;
    assert_eq!(store.zero_ref_chunks().unwrap().len(), dropped_count);
    let objects_before_gc = object_file_count(&store_root);
    assert_eq!(objects_before_gc, total + 1);

    // First GC run only marks zero-ref chunks (grace not yet elapsed): disk
    // unchanged.
    let grace = Duration::from_secs(3600);
    let first = store.gc(now, grace).unwrap();
    assert!(
        first.reclaimed.is_empty(),
        "grace must defer the first sweep"
    );
    assert_eq!(first.pending, dropped_count);
    assert_eq!(object_file_count(&store_root), objects_before_gc);

    // A second GC run past the grace window reclaims exactly the dropped
    // snapshots' unique chunks — disk shrinks.
    let later = now + grace.as_millis() as i64 + 1;
    let second = store.gc(later, grace).unwrap();
    assert_eq!(second.reclaimed.len(), dropped_count);
    assert!(second.bytes_reclaimed > 0);
    assert_eq!(second.pending, 0);
    // 19 survivor unique chunks + 1 shared chunk remain.
    assert_eq!(object_file_count(&store_root), 20);
    assert!(
        object_file_count(&store_root) < objects_before_gc,
        "GC must reduce on-disk object count"
    );

    // Survivors still restore byte-exact after GC (their chunks were spared).
    for &snapshot in &expected.keep {
        assert_survivor_restores_byte_exact(&store, snapshot, k_of[&snapshot]);
    }
    // The shared chunk is still live and readable.
    assert_eq!(store.get_chunk(shared_id).unwrap(), shared);
}

/// GC's grace period protects a freshly uploaded chunk that is not yet
/// referenced by any manifest — the exact upload→PutManifest window a
/// concurrent backup occupies (PRD §3.3 "safe under concurrent backup").
#[test]
fn fr5_gc_grace_protects_unmanifested_chunk_until_grace_elapses() {
    let dir = tempfile::tempdir().unwrap();
    let store = ChunkStore::open(dir.path().join("store")).unwrap();

    let data = b"just uploaded, manifest still in flight".to_vec();
    let id = ChunkId::of(&data);
    store.put_chunk(id, &data).unwrap();
    assert_eq!(store.zero_ref_chunks().unwrap(), vec![id]);

    let grace = Duration::from_secs(3600);
    let t0 = 1_000_000i64;

    // Mark, but do not sweep.
    assert!(store.gc(t0, grace).unwrap().reclaimed.is_empty());
    assert!(store.has_chunk(id).unwrap());

    // Still inside grace: not swept.
    let within = t0 + grace.as_millis() as i64 - 1;
    assert!(store.gc(within, grace).unwrap().reclaimed.is_empty());
    assert!(store.has_chunk(id).unwrap());

    // Grace elapsed: swept.
    let after = t0 + grace.as_millis() as i64;
    let out = store.gc(after, grace).unwrap();
    assert_eq!(out.reclaimed, vec![id]);
    assert!(!store.has_chunk(id).unwrap());
}

/// A chunk that regains a reference between GC runs has its grace timer
/// dropped and is never swept while referenced.
#[test]
fn fr5_gc_spares_chunk_that_regains_a_reference() {
    let dir = tempfile::tempdir().unwrap();
    let store = ChunkStore::open(dir.path().join("store")).unwrap();

    let data = b"chunk that will be referenced after its first GC mark".to_vec();
    let id = ChunkId::of(&data);
    store.put_chunk(id, &data).unwrap();

    let grace = Duration::from_secs(3600);
    let t0 = 5_000_000i64;
    // First GC marks it zero-ref.
    assert!(store.gc(t0, grace).unwrap().reclaimed.is_empty());

    // Now a manifest references it (as a concurrent backup would).
    let snapshot = Ulid::from_parts(t0 as u64, 1);
    let manifest = Manifest {
        snapshot_id: snapshot,
        created_at: 0,
        files: vec![FileEntry {
            path: "data/f.bin".into(),
            size: data.len() as u64,
            mtime_secs: 0,
            mtime_nanos: 0,
            mode: 0o100644,
            chunks: vec![id],
        }],
    };
    store.put_manifest(&manifest).unwrap();

    // Well past grace, but the chunk is referenced: it must survive, and its
    // stale mark must have been cleared.
    let after = t0 + 10 * grace.as_millis() as i64;
    let out = store.gc(after, grace).unwrap();
    assert!(
        out.reclaimed.is_empty(),
        "referenced chunk must never be swept"
    );
    assert!(store.has_chunk(id).unwrap());

    // If the snapshot is later pruned, the chunk becomes eligible again — but
    // only after a fresh grace period (mark starts at deletion-observation).
    store.delete_snapshot(snapshot).unwrap();
    assert!(
        store.gc(after, grace).unwrap().reclaimed.is_empty(),
        "re-marked, fresh grace"
    );
    let final_sweep = store.gc(after + grace.as_millis() as i64, grace).unwrap();
    assert_eq!(final_sweep.reclaimed, vec![id]);
    assert!(!store.has_chunk(id).unwrap());
}
