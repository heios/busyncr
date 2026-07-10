//! FR-M1 (M1.2, M3.2): `ChunkStore::status()` ground truth and the
//! prune/gc "last event" bookkeeping, exercised directly against the store
//! (no network) — the client-side auto-prune-over-real-backups and
//! per-client-attribution acceptance lives in
//! `busyncr-client`'s `frm1_auto_prune` suite, which needs the real mTLS
//! pipeline this crate does not have.

use std::path::Path;

use busyncr_core::chunking::ChunkId;
use busyncr_core::manifest::{FileEntry, Manifest};
use busyncr_core::retention::RetentionPolicy;
use busyncr_daemon::store::{ChunkStore, PruneMode};
use ulid::Ulid;

fn open_store(dir: &Path) -> ChunkStore {
    ChunkStore::open(dir.join("store")).unwrap()
}

fn manifest_for(snapshot_id: Ulid, files: Vec<FileEntry>) -> Manifest {
    Manifest {
        snapshot_id,
        created_at: 1_700_000_000,
        files,
    }
}

fn file_entry(path: &str, chunks: Vec<ChunkId>, size: u64) -> FileEntry {
    FileEntry {
        path: path.into(),
        size,
        mtime_secs: 1_699_999_999,
        mtime_nanos: 0,
        mode: 0o100644,
        chunks,
    }
}

/// FR-M1c: before anything has run, `status` reports empty/`None`
/// everywhere rather than erroring.
#[test]
fn frm1c_status_on_a_fresh_store_is_all_zero() {
    let dir = tempfile::tempdir().unwrap();
    let store = open_store(dir.path());
    let status = store.status().unwrap();
    assert_eq!(status.snapshots_total, 0);
    assert!(status.snapshots_by_client.is_empty());
    assert_eq!(status.chunks_unique, 0);
    assert_eq!(status.store_bytes, 0);
    assert_eq!(status.zero_ref_chunks, 0);
    assert!(status.last_prune.is_none());
    assert!(status.last_gc.is_none());
}

/// FR-M1c: `status`'s aggregate figures match direct store inspection after
/// a handful of snapshots (some attributed to a client, some not), and the
/// per-client breakdown adds up to the total.
#[test]
fn frm1c_status_matches_ground_truth_with_per_client_attribution() {
    let dir = tempfile::tempdir().unwrap();
    let store = open_store(dir.path());

    let a = b"chunk a payload".to_vec();
    let b = b"chunk b payload, a bit longer".to_vec();
    let (id_a, id_b) = (ChunkId::of(&a), ChunkId::of(&b));
    store.put_chunk(id_a, &a).unwrap();
    store.put_chunk(id_b, &b).unwrap();

    let snap1 = Ulid::from_parts(1, 1);
    let snap2 = Ulid::from_parts(2, 2);
    let snap3 = Ulid::from_parts(3, 3);

    // snap1, snap2: attributed to "laptop-a"; snap3: no owner (mirrors the
    // unauthenticated in-process test path / pre-M1 history).
    store
        .put_snapshot_as(snap1, b"blob1", &[id_a], Some("laptop-a"))
        .unwrap();
    store
        .put_snapshot_as(snap2, b"blob2", &[id_a, id_b], Some("laptop-a"))
        .unwrap();
    store.put_snapshot(snap3, b"blob3", &[id_b]).unwrap();

    let status = store.status().unwrap();
    assert_eq!(status.snapshots_total, 3);
    assert_eq!(status.snapshots_by_client.get("laptop-a"), Some(&2));
    assert_eq!(status.snapshots_by_client.get(""), Some(&1));
    let total_by_client: u64 = status.snapshots_by_client.values().sum();
    assert_eq!(total_by_client, status.snapshots_total);

    assert_eq!(status.chunks_unique, 2, "matches store's two put chunks");
    assert_eq!(status.store_bytes, (a.len() + b.len()) as u64);
    assert_eq!(
        status.zero_ref_chunks, 0,
        "both chunks are referenced by at least one live snapshot"
    );

    // Dropping the snapshot that solely references id_a's *extra* reference
    // (snap2 references both; deleting snap1 leaves id_a referenced once by
    // snap2) does not zero anything out yet.
    store.delete_snapshot(snap1).unwrap();
    let status = store.status().unwrap();
    assert_eq!(status.snapshots_total, 2);
    assert_eq!(status.snapshots_by_client.get("laptop-a"), Some(&1));
    assert_eq!(status.zero_ref_chunks, 0);

    // Deleting every snapshot referencing id_a takes it to zero-ref.
    store.delete_snapshot(snap2).unwrap();
    let status = store.status().unwrap();
    assert_eq!(status.snapshots_total, 1);
    assert!(!status.snapshots_by_client.contains_key("laptop-a"));
    assert_eq!(status.zero_ref_chunks, 1, "id_a is now unreferenced");
}

/// FR-M1.2: `prune`'s mode (auto vs manual) round-trips through `status`,
/// and each new prune overwrites the "last prune" record.
#[test]
fn frm1_prune_mode_is_recorded_and_overwritten() {
    let dir = tempfile::tempdir().unwrap();
    let store = open_store(dir.path());

    let data = b"only chunk".to_vec();
    let id = ChunkId::of(&data);
    store.put_chunk(id, &data).unwrap();
    let snap = Ulid::from_parts(1_700_000_000_000, 1);
    store
        .put_manifest(&manifest_for(
            snap,
            vec![file_entry("f", vec![id], data.len() as u64)],
        ))
        .unwrap();

    assert!(store.status().unwrap().last_prune.is_none());

    let t1 = 1_700_100_000_000i64;
    store
        .prune(t1, &RetentionPolicy::default_grid(), PruneMode::Auto)
        .unwrap();
    let status = store.status().unwrap();
    let last = status.last_prune.expect("a prune has now run");
    assert_eq!(last.at_ms, t1);
    assert_eq!(last.mode, PruneMode::Auto);

    let t2 = t1 + 1;
    store
        .prune(t2, &RetentionPolicy::default_grid(), PruneMode::Manual)
        .unwrap();
    let status = store.status().unwrap();
    let last = status.last_prune.expect("still recorded");
    assert_eq!(
        last.at_ms, t2,
        "the most recent prune overwrites the record"
    );
    assert_eq!(last.mode, PruneMode::Manual);
}

/// FR-M1.2/M3.2: `gc` records its own "last ran at" independent of prune,
/// even on a run that reclaims nothing.
#[test]
fn frm1_gc_records_last_run_even_when_nothing_is_reclaimed() {
    let dir = tempfile::tempdir().unwrap();
    let store = open_store(dir.path());
    assert!(store.status().unwrap().last_gc.is_none());

    let t1 = 1_700_000_000_000i64;
    let outcome = store.gc(t1, std::time::Duration::from_secs(3600)).unwrap();
    assert!(outcome.reclaimed.is_empty(), "nothing to reclaim yet");

    let status = store.status().unwrap();
    let last_gc = status.last_gc.expect("gc always records that it ran");
    assert_eq!(last_gc.at_ms, t1);
    assert!(
        status.last_prune.is_none(),
        "gc must not touch the prune record"
    );
}
