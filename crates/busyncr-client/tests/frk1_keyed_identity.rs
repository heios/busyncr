//! FR-K1 acceptance tests: keyed chunk identity closes the known-plaintext
//! confirmation channel (FR-K1.md §3).
//!
//! FR-K1b — the load-bearing new property. A malicious daemon that possesses
//! the *full* store AND the *exact* plaintext of a backed-up file, but not the
//! backup set's `chunk_id_key`, cannot confirm the client stores that content:
//! recomputing plain (unkeyed) BLAKE3 chunk IDs — or keyed IDs under any wrong
//! key — matches zero stored chunk IDs. The test drives a real backup over
//! mutual TLS, then plays the attacker over the daemon's own `HasChunks` RPC
//! (which reports exactly which of a candidate ID set it already stores).
//!
//! The test is made non-vacuous by the mirror assertion: recomputing with the
//! *real* `chunk_id_key` (which the legitimate client holds in its state dir)
//! matches every stored chunk — so "zero matches" for the wrong keys is a
//! property of the keying, not of an empty/misconfigured store.

use std::net::{Ipv4Addr, SocketAddr};
use std::path::Path;
use std::sync::Arc;

use busyncr_client::backup::{run_backup, BackupRequest};
use busyncr_client::enroll::{self, request_enrollment, EnrollmentRequest};
use busyncr_core::chunking::{chunk_bytes, chunk_bytes_keyed, ChunkId, ChunkIdKey, ChunkerConfig};
use busyncr_daemon::identity::DaemonIdentity;
use busyncr_daemon::service;
use busyncr_daemon::store::ChunkStore;
use busyncr_proto::v1::HasChunksRequest;
use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};
use ulid::Ulid;

struct TlsDaemon {
    identity: Arc<DaemonIdentity>,
    url: String,
    shutdown: Option<tokio::sync::oneshot::Sender<()>>,
    server: tokio::task::JoinHandle<()>,
}

impl TlsDaemon {
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

    async fn enroll(&self, state_dir: &Path, name: &str, rng: &mut StdRng) {
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

/// How many of `candidate_ids` the daemon already stores, asked over the real
/// `HasChunks` RPC (present = asked − reported-missing). This is precisely the
/// oracle a malicious daemon operator has.
async fn count_present(state: &Path, daemon_url: &str, candidate_ids: &[ChunkId]) -> usize {
    let mut client = enroll::connect_authenticated(daemon_url, state)
        .await
        .unwrap();
    let asked: Vec<Vec<u8>> = candidate_ids
        .iter()
        .map(|id| id.as_bytes().to_vec())
        .collect();
    let missing = client
        .has_chunks(HasChunksRequest { chunk_ids: asked })
        .await
        .unwrap()
        .into_inner()
        .missing_chunk_ids;
    candidate_ids.len() - missing.len()
}

/// FR-K1b: with the full store and the exact plaintext but not the
/// `chunk_id_key`, no unkeyed / wrong-key recomputation matches any stored
/// chunk ID; only the real key does.
#[tokio::test]
async fn frk1b_confirmation_attack_matches_zero_stored_ids_without_the_key() {
    let dir = tempfile::tempdir().unwrap();
    let base = dir.path();
    let daemon = TlsDaemon::spawn(base).await;
    let mut rng = StdRng::seed_from_u64(9100);

    let state = base.join("state");
    daemon.enroll(&state, "keyed-host", &mut rng).await;

    // A file whose exact plaintext the attacker also possesses. Small target
    // size so it spans many chunks — a meaningful ID set to probe.
    let root = base.join("src").join("data");
    std::fs::create_dir_all(&root).unwrap();
    let mut plaintext = vec![0u8; 240 * 1024];
    StdRng::seed_from_u64(77).fill_bytes(&mut plaintext);
    std::fs::write(root.join("secret.bin"), &plaintext).unwrap();

    let chunker = ChunkerConfig::with_target(4096).unwrap();
    let request = BackupRequest {
        daemon_url: &daemon.url,
        state_dir: &state,
        roots: std::slice::from_ref(&root),
        chunker,
        snapshot_id: Ulid::from_parts(1_700_000_000_000, 1),
        created_at: 1_700_000_000,
    };
    let report = run_backup(&request, &mut rng).await.unwrap();
    assert!(
        report.chunks_uploaded >= 30,
        "corpus must span many chunks for a meaningful probe, got {}",
        report.chunks_uploaded
    );

    // Attacker recomputation 1: plain (unkeyed) BLAKE3, exactly what the
    // offline bench tool computes and what chunk IDs used to be.
    let unkeyed_ids: Vec<ChunkId> = chunk_bytes(&plaintext, &chunker)
        .iter()
        .map(|c| c.id)
        .collect();
    // Attacker recomputation 2: keyed, but under a key the attacker guessed.
    let wrong_key = ChunkIdKey::generate(&mut rng);
    let wrong_ids: Vec<ChunkId> = chunk_bytes_keyed(&plaintext, &chunker, &wrong_key)
        .iter()
        .map(|c| c.id)
        .collect();
    // Legitimate recomputation: the real key from the client's state dir.
    let real_key = enroll::load_chunk_id_key(&state).unwrap();
    let real_ids: Vec<ChunkId> = chunk_bytes_keyed(&plaintext, &chunker, &real_key)
        .iter()
        .map(|c| c.id)
        .collect();

    // Same boundaries throughout (keying does not move CDC cut points): the
    // three ID vectors have equal length but different contents.
    assert_eq!(unkeyed_ids.len(), real_ids.len());
    assert_eq!(wrong_ids.len(), real_ids.len());
    assert_ne!(unkeyed_ids, real_ids, "unkeyed IDs must differ from stored");
    assert_ne!(wrong_ids, real_ids, "wrong-key IDs must differ from stored");

    // The confirmation channel is closed: neither the unkeyed nor the
    // wrong-key IDs match anything in the store.
    assert_eq!(
        count_present(&state, &daemon.url, &unkeyed_ids).await,
        0,
        "plain-BLAKE3 recomputation must confirm nothing (FR-K1b)"
    );
    assert_eq!(
        count_present(&state, &daemon.url, &wrong_ids).await,
        0,
        "wrong-key recomputation must confirm nothing (FR-K1b)"
    );

    // Non-vacuous: the real key confirms every stored chunk.
    assert_eq!(
        count_present(&state, &daemon.url, &real_ids).await,
        real_ids.len(),
        "the real key must match every stored chunk (store is genuine)"
    );

    daemon.stop().await;
}

/// FR-K1b, second angle: two enrolled clients with *different* keyfiles do not
/// dedup against each other — one client's stored keyed IDs are invisible to
/// the other's recomputation. (Dedup scope is per-backup-set, FR-K1 K1.4.)
#[tokio::test]
async fn frk1b_distinct_keys_do_not_share_chunk_identity() {
    let dir = tempfile::tempdir().unwrap();
    let base = dir.path();
    let daemon = TlsDaemon::spawn(base).await;
    let mut rng = StdRng::seed_from_u64(9200);

    let state_a = base.join("state-a");
    let state_b = base.join("state-b");
    daemon.enroll(&state_a, "host-a", &mut rng).await;
    daemon.enroll(&state_b, "host-b", &mut rng).await;
    let key_a = enroll::load_chunk_id_key(&state_a).unwrap();
    let key_b = enroll::load_chunk_id_key(&state_b).unwrap();
    assert_ne!(
        key_a.as_bytes(),
        key_b.as_bytes(),
        "independent enrollments must have independent chunk-ID keys"
    );

    // Client A backs up a shared payload.
    let root = base.join("src").join("shared");
    std::fs::create_dir_all(&root).unwrap();
    let mut payload = vec![0u8; 160 * 1024];
    StdRng::seed_from_u64(88).fill_bytes(&mut payload);
    std::fs::write(root.join("shared.bin"), &payload).unwrap();

    let chunker = ChunkerConfig::with_target(4096).unwrap();
    let request = BackupRequest {
        daemon_url: &daemon.url,
        state_dir: &state_a,
        roots: std::slice::from_ref(&root),
        chunker,
        snapshot_id: Ulid::from_parts(1_700_000_000_000, 7),
        created_at: 1_700_000_000,
    };
    run_backup(&request, &mut rng).await.unwrap();

    // B, holding the identical bytes but a different key, sees none of A's
    // chunks as present — the confirmation channel is closed even between two
    // legitimate clients of the same daemon.
    let b_ids: Vec<ChunkId> = chunk_bytes_keyed(&payload, &chunker, &key_b)
        .iter()
        .map(|c| c.id)
        .collect();
    assert_eq!(
        count_present(&state_b, &daemon.url, &b_ids).await,
        0,
        "a different key must not dedup against A's stored chunks (FR-K1 K1.4)"
    );
    // Sanity: A's own key would have found them all.
    let a_ids: Vec<ChunkId> = chunk_bytes_keyed(&payload, &chunker, &key_a)
        .iter()
        .map(|c| c.id)
        .collect();
    assert_eq!(
        count_present(&state_a, &daemon.url, &a_ids).await,
        a_ids.len()
    );

    daemon.stop().await;
}

/// The daemon's stored chunk IDs are the keyed ones — a small direct proof at
/// the store level that backup persisted keyed identities, complementing the
/// RPC-level attack test above (FR-K1a/b).
#[tokio::test]
async fn frk1_store_holds_keyed_ids_not_plain_blake3() {
    let dir = tempfile::tempdir().unwrap();
    let base = dir.path();
    let mut rng = StdRng::seed_from_u64(9300);

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
    let url = format!("https://{local}");

    let state = base.join("state");
    let issued = request_enrollment(&EnrollmentRequest {
        daemon_url: url.clone(),
        ca_cert_pem: identity.ca_cert_pem().to_owned(),
        token: identity.mint_token(&mut rand::rng()).unwrap(),
        name: "keyed-host".to_owned(),
    })
    .await
    .unwrap();
    enroll::save_identity(&state, &issued).unwrap();
    enroll::ensure_data_key(&state, &mut rng).unwrap();

    let root = base.join("src").join("data");
    std::fs::create_dir_all(&root).unwrap();
    let mut data = vec![0u8; 200 * 1024];
    StdRng::seed_from_u64(99).fill_bytes(&mut data);
    std::fs::write(root.join("f.bin"), &data).unwrap();

    let chunker = ChunkerConfig::with_target(4096).unwrap();
    run_backup(
        &BackupRequest {
            daemon_url: &url,
            state_dir: &state,
            roots: std::slice::from_ref(&root),
            chunker,
            snapshot_id: Ulid::from_parts(1_700_000_000_000, 3),
            created_at: 1_700_000_000,
        },
        &mut rng,
    )
    .await
    .unwrap();

    let key = enroll::load_chunk_id_key(&state).unwrap();
    for chunk in chunk_bytes_keyed(&data, &chunker, &key) {
        // The keyed ID is stored...
        assert!(
            store.chunk_entry(chunk.id).unwrap().is_some(),
            "keyed chunk {} must be stored",
            chunk.id
        );
        // ...while the plain-BLAKE3 ID of the same bytes is not.
        let plain = ChunkId::of(&chunk.data);
        assert_ne!(plain, chunk.id);
        assert!(
            store.chunk_entry(plain).unwrap().is_none(),
            "plain-BLAKE3 ID {plain} must NOT be in the store (keyed identity)"
        );
    }

    drop(shutdown_tx);
    server.await.unwrap();
}
