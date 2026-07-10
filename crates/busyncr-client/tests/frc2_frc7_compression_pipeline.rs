//! FR-C2/FR-C3/FR-C4/FR-C6/FR-C7 acceptance tests: the compression policy
//! engine wired into the real backup/restore pipeline over mutual TLS
//! (FR-C1.md §5, SLICES.md "C2 — Pipeline integration").
//!
//! FR-C1 (round-trip) and the unit-level FR-C6 phase gate already have
//! dedicated tests in `busyncr-core::compression`; this file covers the
//! pipeline-level acceptance criteria that only exist once the policy engine
//! is wired into `backup`/`restore`:
//!
//! * `frc2_*` — a pre-compressed (incompressible) corpus stores ≥99% raw
//!   chunks and ≤1.01× input bytes.
//! * `frc3_*` — a compressible corpus stores ≥2× smaller under the default
//!   policy than under a raw-only policy, with the bound derived from the
//!   corpus's own measured zstd ratio (not a magic constant).
//! * `frc4_*` — one manifest referencing raw, zstd-3, and escalated zstd-9
//!   chunks restores byte-exact; prune/GC are unaffected by the codec mix;
//!   dedup hits across a policy change between two backups of identical data.
//! * `frc6_*` — end-to-end escalation counters: zero level-9 invocations
//!   during the initial full backup, positive during a qualifying
//!   incremental.
//! * `frc7_*` — zero-knowledge extension: the codec is unrecoverable from a
//!   stored blob without the data key; the accepted ciphertext-length leak
//!   (coarse compressibility only, FR-C1 §5) is exercised and documented,
//!   not "fixed".

use std::net::{Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use busyncr_client::backup::{run_backup, BackupReport, BackupRequest};
use busyncr_client::enroll::{self, request_enrollment, EnrollmentRequest};
use busyncr_client::restore::{run_restore, RestoreRequest};
use busyncr_core::chunking::{chunk_bytes_keyed, ChunkId, ChunkIdKey, ChunkerConfig};
use busyncr_core::compression::{
    self, choose_codec, compress_zstd, frame, CodecId, Phase, PolicyConfig, PolicyCounters,
    DEFAULT_ZSTD_LEVEL,
};
use busyncr_core::crypto::{self, DataKey};
use busyncr_daemon::identity::DaemonIdentity;
use busyncr_daemon::service;
use busyncr_daemon::store::ChunkStore;
use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};
use ulid::Ulid;

/// A daemon + enrolled client, with direct store access (needed for FR-C4's
/// prune/GC step and FR-C7's raw-blob inspection — a real client never gets
/// this, only the test harness does, standing in for the "malicious/curious
/// daemon operator" that FR-C7 reasons about).
struct Harness {
    store: Arc<ChunkStore>,
    state: PathBuf,
    root: PathBuf,
    daemon_url: String,
    chunker: ChunkerConfig,
    chunk_id_key: ChunkIdKey,
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
            name: "frc2-host".to_owned(),
        })
        .await
        .unwrap();
        enroll::save_identity(&state, &issued).unwrap();
        let mut rng = StdRng::seed_from_u64(31415);
        enroll::ensure_data_key(&state, &mut rng).unwrap();
        let chunk_id_key = enroll::load_chunk_id_key(&state).unwrap();

        let root = base.join("src").join("data");
        std::fs::create_dir_all(&root).unwrap();

        Self {
            store,
            state,
            root,
            daemon_url,
            chunker: ChunkerConfig::with_target(target_size).unwrap(),
            chunk_id_key,
            rng,
            shutdown: Some(shutdown_tx),
            server,
        }
    }

    /// Backs up the current tree under `compression`, with an injected
    /// deterministic snapshot identity.
    async fn backup(&mut self, seq: u64, compression: PolicyConfig) -> BackupReport {
        let request = BackupRequest {
            daemon_url: &self.daemon_url,
            state_dir: &self.state,
            roots: std::slice::from_ref(&self.root),
            chunker: self.chunker,
            compression,
            snapshot_id: Ulid::from_parts(1_700_000_000_000 + seq, u128::from(seq)),
            created_at: 1_700_000_000 + seq as i64,
        };
        run_backup(&request, &mut self.rng).await.unwrap()
    }

    async fn restore(
        &self,
        snapshot_id: Ulid,
        target: &Path,
    ) -> Result<busyncr_client::restore::RestoreReport, busyncr_client::restore::RestoreError> {
        run_restore(&RestoreRequest {
            daemon_url: &self.daemon_url,
            state_dir: &self.state,
            snapshot_id,
            target_dir: target,
        })
        .await
    }

    /// Plaintext chunk bytes of every file currently in the tree, keyed
    /// exactly as the backup pipeline keys them (FR-K1), computed
    /// independently.
    fn local_chunks(&self) -> Vec<(ChunkId, Vec<u8>)> {
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
                            .map(|c| (c.id, c.data)),
                    );
                }
            }
        }
        out
    }

    fn data_key(&self) -> DataKey {
        enroll::load_data_key(&self.state).unwrap()
    }

    async fn stop(mut self) {
        drop(self.shutdown.take());
        self.server.await.unwrap();
    }
}

/// A raw-only-in-effect policy: FR-C1 C2.1's keep condition
/// (`compressed_len <= raw_len * keep_threshold`) is unsatisfiable for any
/// non-empty chunk when `keep_threshold == 0.0`, forcing the raw codec
/// unconditionally. Used as the "raw-only" comparison arm for FR-C3/FR-C4
/// without adding a separate code path to the policy engine (there isn't
/// one — `raw-only` is exactly `zstd3` with a threshold no chunk clears).
fn raw_only_policy() -> PolicyConfig {
    PolicyConfig {
        keep_threshold: 0.0,
        ..PolicyConfig::default()
    }
}

/// Deterministic pseudo-random bytes (stands in for pre-compressed formats
/// like zip/jpeg, which are — from a general-purpose compressor's
/// perspective — indistinguishable from noise).
fn incompressible_bytes(len: usize, seed: u64) -> Vec<u8> {
    let mut buf = vec![0u8; len];
    StdRng::seed_from_u64(seed).fill_bytes(&mut buf);
    buf
}

/// Highly repetitive text — compresses far beyond the FR-C3 2× bar under
/// zstd-3, standing in for the "databases, source, logs" class FR-C1
/// Appendix A measures at 2-2.6×.
fn compressible_bytes(len: usize) -> Vec<u8> {
    b"the quick brown fox jumps over the lazy dog; SELECT * FROM t; "
        .iter()
        .copied()
        .cycle()
        .take(len)
        .collect()
}

/// An escalation-qualifying chunk (same construction as
/// `compression::tests::escalation_candidate`, FR-C1 Appendix A.4 sqlite-like
/// payoff): 200 distinct 500-byte pseudo-random "records" repeated in the
/// same order 4 times, engineered so zstd level 9 measurably beats level 3.
fn escalation_candidate_bytes() -> Vec<u8> {
    let mut r = StdRng::seed_from_u64(909);
    let mut records: Vec<Vec<u8>> = Vec::with_capacity(200);
    for _ in 0..200 {
        let mut rec = vec![0u8; 500];
        r.fill_bytes(&mut rec);
        records.push(rec);
    }
    let mut out = Vec::with_capacity(200 * 500 * 4);
    for _ in 0..4 {
        for rec in &records {
            out.extend_from_slice(rec);
        }
    }
    out
}

/// Exact expected ciphertext volume under `cfg` for a set of chunks —
/// recomputes the pipeline's own `choose_codec`/`frame` calls (FR-C1 §2-§3),
/// so byte-exact assertions do not depend on magic constants.
fn expected_upload_bytes(chunks: &[(ChunkId, Vec<u8>)], cfg: &PolicyConfig) -> u64 {
    let mut counters = PolicyCounters::default();
    chunks
        .iter()
        .map(|(_, data)| {
            let (codec, payload) = choose_codec(data, Phase::Incremental, cfg, &mut counters);
            (frame(codec, &payload).len() + crypto::BLOB_OVERHEAD) as u64
        })
        .sum()
}

/// FR-C2: a pre-compressed corpus (stands in for zip/jpeg) backs up with
/// >=99% of its unique chunks stored raw, and total stored bytes <=1.01x the
/// source bytes (codec byte + AEAD overhead only, per FR-C1 §5).
#[tokio::test]
async fn frc2_precompressed_corpus_stores_raw_within_one_percent() {
    let dir = tempfile::tempdir().unwrap();
    // A 256 KiB target keeps the (1-byte codec + 40-byte AEAD) per-chunk
    // overhead a small fraction of each chunk, so the 1.01x bound reflects
    // FR-C1's intent (framing overhead) rather than test-fixture noise.
    let mut hx = Harness::new(dir.path(), 256 * 1024).await;

    let mut data = Vec::new();
    for seed in 0..4u64 {
        data.push(incompressible_bytes(300 * 1024, seed));
    }
    for (i, bytes) in data.iter().enumerate() {
        std::fs::write(hx.root.join(format!("blob-{i}.bin")), bytes).unwrap();
    }

    let report = hx.backup(1, PolicyConfig::default()).await;

    let total = report.compression.total();
    assert!(total > 0, "the corpus must actually produce chunks");
    let raw_fraction = report.compression.raw as f64 / total as f64;
    assert!(
        raw_fraction >= 0.99,
        "incompressible corpus must store >=99% raw, got {raw_fraction} \
         ({} raw / {total} total)",
        report.compression.raw
    );

    assert!(
        (report.upload_bytes as f64) <= report.source_bytes as f64 * 1.01,
        "stored bytes ({}) must be <=1.01x source bytes ({})",
        report.upload_bytes,
        report.source_bytes
    );

    hx.stop().await;
}

/// FR-C3: a compressible corpus stores at least 2x smaller under the
/// default `zstd3` policy than under a raw-only policy. The 2x bound is
/// checked against the corpus's own independently-measured zstd ratio (a
/// golden bound derived from the data, not a magic constant) rather than
/// asserted on faith.
#[tokio::test]
async fn frc3_compressible_corpus_at_least_two_times_smaller_than_raw_only() {
    let dir = tempfile::tempdir().unwrap();
    let mut hx = Harness::new(dir.path(), 64 * 1024).await;

    let bytes = compressible_bytes(600 * 1024);
    std::fs::write(hx.root.join("log.txt"), &bytes).unwrap();

    let local = hx.local_chunks();
    assert!(!local.is_empty());

    // Golden bound: recompute the actual zstd-3 ratio for this exact corpus
    // independently of both the pipeline and the raw-only run.
    let raw_total: u64 = local.iter().map(|(_, d)| d.len() as u64).sum();
    let zstd_total: u64 = local
        .iter()
        .map(|(_, d)| compress_zstd(d, DEFAULT_ZSTD_LEVEL).unwrap().len() as u64)
        .sum();
    let golden_ratio = raw_total as f64 / zstd_total as f64;
    assert!(
        golden_ratio >= 2.0,
        "test fixture must itself compress >=2x under zstd-3 (got {golden_ratio}x) \
         or this is not exercising FR-C3 at all"
    );

    let report_zstd3 = hx.backup(1, PolicyConfig::default()).await;
    assert_eq!(
        report_zstd3.upload_bytes,
        expected_upload_bytes(&local, &PolicyConfig::default()),
        "the real pipeline's stored bytes must match the independently \
         recomputed policy-engine output exactly"
    );

    // A second, fresh daemon backs up the identical corpus under a
    // raw-only-in-effect policy, so the two totals are directly comparable
    // (dedup within one daemon would otherwise make the second backup free).
    let dir2 = tempfile::tempdir().unwrap();
    let mut hx2 = Harness::new(dir2.path(), 64 * 1024).await;
    std::fs::write(hx2.root.join("log.txt"), &bytes).unwrap();
    let report_raw = hx2.backup(1, raw_only_policy()).await;
    assert_eq!(
        report_raw.compression.raw,
        report_raw.compression.total(),
        "raw-only policy must never keep a compressed chunk"
    );

    assert!(
        report_raw.upload_bytes as f64 >= report_zstd3.upload_bytes as f64 * 2.0,
        "zstd3 ({}) must store at least 2x smaller than raw-only ({}), \
         matching the corpus's own {golden_ratio}x measured ratio",
        report_zstd3.upload_bytes,
        report_raw.upload_bytes
    );

    hx.stop().await;
    hx2.stop().await;
}

/// FR-C4 + FR-C6 (e2e): a mixed-codec history — raw, zstd-3, and escalated
/// zstd-9 chunks referenced by one manifest — restores byte-exact; prune/GC
/// are unaffected by the codec mix; and a later backup of identical content
/// under a *different* compression policy still hits full dedup (identity is
/// the plaintext hash, per C1.3 — compression is never normative).
#[tokio::test]
async fn frc4_mixed_codec_history_restores_byte_exact_prune_gc_unaffected_dedup_across_policy_change(
) {
    let dir = tempfile::tempdir().unwrap();
    // A 2 MiB target (min = target/4 = 512 KiB) guarantees every file below
    // stays a single CDC chunk — including the 400 KiB escalation-candidate
    // file, so it reaches the policy engine exactly as one whole chunk, the
    // same construction `compression::tests::escalation_candidate` uses to
    // empirically clear the default 2.0x escalation ratio.
    let mut hx = Harness::new(dir.path(), 2 * 1024 * 1024).await;

    let raw_bytes = incompressible_bytes(64 * 1024, 5);
    let zstd_bytes = compressible_bytes(64 * 1024);
    std::fs::write(hx.root.join("raw.bin"), &raw_bytes).unwrap();
    std::fs::write(hx.root.join("zstd.txt"), &zstd_bytes).unwrap();

    // Escalation enabled throughout; hard phase-gated off for snapshot 1
    // (the set's first completed snapshot, FR-C1 C2.3/FR-C6) regardless.
    let cfg = PolicyConfig {
        escalate: true,
        ..PolicyConfig::default()
    };

    let report1 = hx.backup(1, cfg).await;
    assert_eq!(
        report1.compression.escalation_attempts, 0,
        "FR-C6: initial full backup must never invoke the level-9 path"
    );
    assert_eq!(report1.chunks_deduped, 0, "first backup: nothing to dedup");

    // Snapshot 2: the two existing files are unchanged (must dedup); a new
    // file engineered to qualify for escalation is added. This snapshot's
    // manifest ends up referencing raw + zstd-3 chunks (inherited from
    // snapshot 1, re-referenced) plus a brand new escalated zstd-9 chunk —
    // three codecs in one manifest (FR-C4).
    let escalate_bytes = escalation_candidate_bytes();
    std::fs::write(hx.root.join("escalate.bin"), &escalate_bytes).unwrap();
    let report2 = hx.backup(2, cfg).await;
    assert!(
        report2.compression.escalation_attempts > 0,
        "FR-C6: an incremental backup with escalation enabled must attempt \
         level 9 for the qualifying chunk"
    );
    assert!(
        report2.compression.escalated > 0,
        "the escalation attempt must have won for the engineered chunk"
    );
    assert_eq!(
        report2.chunks_deduped + report2.chunks_uploaded,
        report2.chunks_unique,
    );
    assert!(
        report2.chunks_deduped > 0,
        "the two unchanged files must dedup against snapshot 1"
    );

    // The manifest referenced by snapshot 2 really does mix all three codecs:
    // decrypt+unframe every stored chunk it references directly from the
    // store and check the codec bytes observed.
    let key = hx.data_key();
    let manifest_blob = hx.store.get_manifest_blob(report2.snapshot_id).unwrap();
    let manifest_plain =
        crypto::decrypt_manifest(&key, report2.snapshot_id, &manifest_blob).unwrap();
    let manifest = busyncr_core::manifest::Manifest::decode(&manifest_plain).unwrap();
    let mut seen_codecs = std::collections::HashSet::new();
    for id in manifest.chunk_refs() {
        let blob = hx.store.get_chunk(id).unwrap();
        let framed = crypto::decrypt_chunk(&key, &id, &blob).unwrap();
        let (codec, _) = compression::unframe(&framed).unwrap();
        seen_codecs.insert(codec);
    }
    assert!(
        seen_codecs.contains(&CodecId::Raw) && seen_codecs.contains(&CodecId::Zstd),
        "the manifest must reference at least raw and zstd-coded chunks: {seen_codecs:?}"
    );

    // FR-C4: restoring the mixed-codec snapshot is byte-exact for every file.
    let target = dir.path().join("restored-v2");
    let restore_report = hx.restore(report2.snapshot_id, &target).await.unwrap();
    assert_eq!(restore_report.files, 3);
    let restored_root = target.join("data");
    assert_eq!(
        std::fs::read(restored_root.join("raw.bin")).unwrap(),
        raw_bytes
    );
    assert_eq!(
        std::fs::read(restored_root.join("zstd.txt")).unwrap(),
        zstd_bytes
    );
    assert_eq!(
        std::fs::read(restored_root.join("escalate.bin")).unwrap(),
        escalate_bytes
    );

    // Prune/GC are unaffected by the codec mix: drop snapshot 1, GC its
    // now-unreferenced chunks (there are none, since snapshot 2 still
    // references everything snapshot 1 did), and confirm snapshot 2 still
    // restores byte-exact afterward.
    hx.store.delete_snapshot(report1.snapshot_id).unwrap();
    let now = 1_700_000_010_000i64;
    let _ = hx.store.gc(now, std::time::Duration::ZERO).unwrap();
    let gc2 = hx.store.gc(now + 1, std::time::Duration::ZERO).unwrap();
    assert!(
        gc2.reclaimed.is_empty(),
        "snapshot 2 still references every chunk snapshot 1 did; GC must \
         reclaim nothing"
    );

    let target2 = dir.path().join("restored-v2-after-gc");
    let restore_report2 = hx.restore(report2.snapshot_id, &target2).await.unwrap();
    assert_eq!(restore_report2.files, 3);
    assert_eq!(
        std::fs::read(target2.join("data").join("escalate.bin")).unwrap(),
        escalate_bytes
    );

    // Dedup hits across a policy change: back up the identical tree again
    // under raw-only — despite the different policy, every chunk is already
    // known by content-address, so nothing new is uploaded (C1.3: identity
    // is the plaintext hash; compression is never normative).
    let report3 = hx.backup(3, raw_only_policy()).await;
    assert_eq!(
        report3.chunks_uploaded, 0,
        "a policy change alone must not cause any re-upload"
    );
    assert_eq!(report3.chunks_deduped, report3.chunks_unique);

    hx.stop().await;
}

/// FR-C6 (e2e, standalone from the mixed-codec FR-C4 scenario above): a
/// dedicated minimal case for the escalation phase gate as observed through
/// [`BackupReport::compression`] end to end — zero level-9 invocations
/// during a backup set's first completed (initial full) snapshot, and a
/// positive count during a later incremental snapshot that introduces a
/// qualifying chunk, with escalation enabled throughout.
#[tokio::test]
async fn frc6_escalation_counters_are_phase_gated_end_to_end() {
    let dir = tempfile::tempdir().unwrap();
    // See frc4's comment: a 2 MiB target keeps the 400 KiB escalation
    // candidate as a single CDC chunk.
    let mut hx = Harness::new(dir.path(), 2 * 1024 * 1024).await;
    let cfg = PolicyConfig {
        escalate: true,
        ..PolicyConfig::default()
    };

    // Initial full backup: an ordinary compressible file only. Escalation
    // is enabled in config but must never fire — this is the set's first
    // completed snapshot (FR-C1 C2.3/FR-C6).
    std::fs::write(hx.root.join("first.txt"), compressible_bytes(64 * 1024)).unwrap();
    let report1 = hx.backup(1, cfg).await;
    assert_eq!(
        report1.compression.escalation_attempts, 0,
        "the set's first completed snapshot must never invoke level 9"
    );
    assert_eq!(report1.compression.escalated, 0);

    // Incremental snapshot: adds a chunk engineered to qualify for
    // escalation. A prior completed snapshot now exists, so escalation is
    // allowed to run.
    std::fs::write(hx.root.join("second.bin"), escalation_candidate_bytes()).unwrap();
    let report2 = hx.backup(2, cfg).await;
    assert!(
        report2.compression.escalation_attempts > 0,
        "an incremental backup with escalation enabled must attempt level 9 \
         for the qualifying chunk"
    );
    assert!(
        report2.compression.escalated > 0,
        "the escalation attempt must have won (smaller output) for the \
         engineered chunk"
    );

    hx.stop().await;
}

/// FR-C7 (zero-knowledge extension): the daemon holds only encrypted blobs.
/// The codec byte (raw vs zstd) is unrecoverable without the data key — a
/// wrong key does not even parse, let alone reveal the codec — and the one
/// accepted leak (ciphertext length correlates with post-compression size,
/// hence coarse compressibility) is exercised explicitly and documented
/// here as accepted, not hidden or "fixed" (FR-C1 §5).
#[tokio::test]
async fn frc7_codec_is_unrecoverable_from_stored_blobs_without_the_key() {
    let dir = tempfile::tempdir().unwrap();
    // min = target/4 = 256 KiB, comfortably above the 64 KiB files below, so
    // each is guaranteed to land as exactly one chunk (simplifies picking
    // "the" chunk for each file out of the store).
    let mut hx = Harness::new(dir.path(), 1024 * 1024).await;

    let raw_bytes = incompressible_bytes(64 * 1024, 6);
    let zstd_bytes = compressible_bytes(64 * 1024);
    std::fs::write(hx.root.join("raw.bin"), &raw_bytes).unwrap();
    std::fs::write(hx.root.join("zstd.txt"), &zstd_bytes).unwrap();

    let report = hx.backup(1, PolicyConfig::default()).await;
    assert!(report.compression.raw > 0 && report.compression.zstd3 > 0);

    let local = hx.local_chunks();
    let raw_id = local
        .iter()
        .find(|(_, d)| d == &raw_bytes)
        .map(|(id, _)| *id)
        .expect("raw.bin must be a single chunk at this target size");
    let zstd_id = local
        .iter()
        .find(|(_, d)| d == &zstd_bytes)
        .map(|(id, _)| *id)
        .expect("zstd.txt must be a single chunk at this target size");

    let raw_blob = hx.store.get_chunk(raw_id).unwrap();
    let zstd_blob = hx.store.get_chunk(zstd_id).unwrap();

    // Without the key: decryption fails outright for both — the daemon
    // cannot even reach the codec byte, let alone the payload (FR7's
    // original guarantee, now covering codec-bearing blobs too).
    let mut r = rand::rng();
    let wrong_key = DataKey::generate(&mut r);
    assert!(crypto::decrypt_chunk(&wrong_key, &raw_id, &raw_blob).is_err());
    assert!(crypto::decrypt_chunk(&wrong_key, &zstd_id, &zstd_blob).is_err());

    // The blob's leading byte (what an attacker without the key actually
    // sees) is a XChaCha20-Poly1305 nonce byte, not the plaintext codec
    // byte — it carries no reliable codec signal at all.
    let key = hx.data_key();
    let raw_framed = crypto::decrypt_chunk(&key, &raw_id, &raw_blob).unwrap();
    let zstd_framed = crypto::decrypt_chunk(&key, &zstd_id, &zstd_blob).unwrap();
    let (raw_codec, _) = compression::unframe(&raw_framed).unwrap();
    let (zstd_codec, _) = compression::unframe(&zstd_framed).unwrap();
    assert_eq!(raw_codec, CodecId::Raw);
    assert_eq!(zstd_codec, CodecId::Zstd);

    // Documented, accepted leak (FR-C1 §5): ciphertext length still tracks
    // post-compression size, so a coarse "this chunk compressed a lot"
    // signal survives encryption even though the codec byte itself does
    // not. This assertion exists to make the leak visible and tested, not
    // to treat it as a defect — the threat-model note (SLICES.md C4) is
    // where operators are told about it.
    assert!(
        zstd_blob.len() < raw_blob.len(),
        "the accepted ciphertext-length leak: a well-compressed chunk's \
         blob is measurably shorter than an incompressible one's, even \
         though the codec byte itself is sealed"
    );

    hx.stop().await;
}
