//! FR1 acceptance tests: enroll a client against a fresh daemon over real
//! mutual TLS (CA bootstrap, one-time token, cert issuance, data-key
//! creation), then prove the access-control matrix — enrolled succeeds,
//! un-enrolled rejected, revoked rejected, tokens single-use.

use std::net::{Ipv4Addr, SocketAddr};
use std::path::Path;
use std::sync::Arc;

use busyncr_client::enroll::{
    self, connect_authenticated, connect_unauthenticated, request_enrollment, EnrollmentRequest,
};
use busyncr_daemon::identity::DaemonIdentity;
use busyncr_daemon::service;
use busyncr_daemon::store::ChunkStore;
use busyncr_proto::v1::ListSnapshotsRequest;
use tonic::Code;

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

    fn enrollment_request(&self, name: &str) -> EnrollmentRequest {
        EnrollmentRequest {
            daemon_url: self.url.clone(),
            ca_cert_pem: self.identity.ca_cert_pem().to_owned(),
            token: self.identity.mint_token(&mut rand::rng()).unwrap(),
            name: name.to_owned(),
        }
    }

    async fn stop(mut self) {
        drop(self.shutdown.take());
        self.server.await.unwrap();
    }
}

/// FR1 happy path: fresh daemon → enroll → authenticated RPC succeeds; the
/// client state directory ends up with cert, private key, pinned CA, and a
/// freshly created 32-byte data key.
#[tokio::test]
async fn fr1_fresh_daemon_enroll_then_authenticated_call_succeeds() {
    let dir = tempfile::tempdir().unwrap();
    let daemon = TlsDaemon::spawn(dir.path()).await;
    let state = dir.path().join("client-state");

    let identity = request_enrollment(&daemon.enrollment_request("laptop-a"))
        .await
        .unwrap();
    assert!(identity.cert_pem.contains("BEGIN CERTIFICATE"));
    assert!(identity.key_pem.contains("PRIVATE KEY"));
    assert_eq!(identity.ca_cert_pem, daemon.identity.ca_cert_pem());

    enroll::save_identity(&state, &identity).unwrap();
    assert!(
        enroll::ensure_data_key(&state, &mut rand::rng()).unwrap(),
        "first enrollment must create the data key (FR1 keyfile creation)"
    );

    // All four state files exist; the data key is exactly 32 bytes.
    for file in [
        enroll::CLIENT_CERT_FILE,
        enroll::CLIENT_KEY_FILE,
        enroll::CA_CERT_FILE,
        enroll::DATA_KEY_FILE,
    ] {
        assert!(state.join(file).is_file(), "missing {file}");
    }
    assert_eq!(
        std::fs::read(state.join(enroll::DATA_KEY_FILE))
            .unwrap()
            .len(),
        32
    );

    // The enrolled identity authenticates: a real RPC over mTLS succeeds.
    let mut client = connect_authenticated(&daemon.url, &state).await.unwrap();
    let listed = client
        .list_snapshots(ListSnapshotsRequest {})
        .await
        .unwrap()
        .into_inner();
    assert!(
        listed.snapshot_ids.is_empty(),
        "fresh daemon has no snapshots"
    );

    daemon.stop().await;
}

/// FR1: a client that never enrolled (TLS, but no client certificate) is
/// rejected on every data-plane RPC.
#[tokio::test]
async fn fr1_unenrolled_client_rejected() {
    let dir = tempfile::tempdir().unwrap();
    let daemon = TlsDaemon::spawn(dir.path()).await;

    let mut client = connect_unauthenticated(&daemon.url, daemon.identity.ca_cert_pem())
        .await
        .unwrap();
    let err = client
        .list_snapshots(ListSnapshotsRequest {})
        .await
        .unwrap_err();
    assert_eq!(err.code(), Code::Unauthenticated);
    assert!(
        err.message().contains("certificate"),
        "rejection must explain the missing certificate: {}",
        err.message()
    );

    daemon.stop().await;
}

/// FR1: revocation. An enrolled client works until `revoke <name>`; from the
/// next connection on it is refused with PERMISSION_DENIED.
#[tokio::test]
async fn fr1_revoked_client_rejected() {
    let dir = tempfile::tempdir().unwrap();
    let daemon = TlsDaemon::spawn(dir.path()).await;
    let state = dir.path().join("client-state");

    let identity = request_enrollment(&daemon.enrollment_request("laptop-b"))
        .await
        .unwrap();
    enroll::save_identity(&state, &identity).unwrap();

    // Sanity: works before revocation.
    let mut client = connect_authenticated(&daemon.url, &state).await.unwrap();
    client
        .list_snapshots(ListSnapshotsRequest {})
        .await
        .unwrap();

    assert_eq!(daemon.identity.revoke("laptop-b").unwrap(), 1);

    let mut client = connect_authenticated(&daemon.url, &state).await.unwrap();
    let err = client
        .list_snapshots(ListSnapshotsRequest {})
        .await
        .unwrap_err();
    assert_eq!(err.code(), Code::PermissionDenied);
    assert!(
        err.message().contains("revoked"),
        "rejection must name revocation: {}",
        err.message()
    );

    daemon.stop().await;
}

/// FR1: enrollment tokens are strictly one-time, garbage tokens are refused,
/// and an active enrollment name cannot be claimed twice.
#[tokio::test]
async fn fr1_token_single_use_and_name_uniqueness() {
    let dir = tempfile::tempdir().unwrap();
    let daemon = TlsDaemon::spawn(dir.path()).await;

    let first = daemon.enrollment_request("laptop-c");
    request_enrollment(&first).await.unwrap();

    // Same token again (different name): refused, the token is spent.
    let mut reuse = first.clone();
    reuse.name = "laptop-d".to_owned();
    let err = match request_enrollment(&reuse).await {
        Err(enroll::EnrollError::Rpc(status)) => status,
        other => panic!("expected RPC rejection, got {other:?}"),
    };
    assert_eq!(err.code(), Code::PermissionDenied);

    // Garbage token: refused.
    let mut bogus = daemon.enrollment_request("laptop-e");
    bogus.token = "0badc0ffee".to_owned();
    let err = match request_enrollment(&bogus).await {
        Err(enroll::EnrollError::Rpc(status)) => status,
        other => panic!("expected RPC rejection, got {other:?}"),
    };
    assert_eq!(err.code(), Code::PermissionDenied);

    // Fresh token but an already-active name: refused as ALREADY_EXISTS.
    let dup_name = daemon.enrollment_request("laptop-c");
    let err = match request_enrollment(&dup_name).await {
        Err(enroll::EnrollError::Rpc(status)) => status,
        other => panic!("expected RPC rejection, got {other:?}"),
    };
    assert_eq!(err.code(), Code::AlreadyExists);

    daemon.stop().await;
}

/// FR1 continuity: the CA bootstrapped on first run persists, so a client
/// enrolled before a daemon restart still authenticates after it.
#[tokio::test]
async fn fr1_enrollment_survives_daemon_restart() {
    let dir = tempfile::tempdir().unwrap();
    let state = dir.path().join("client-state");

    let daemon = TlsDaemon::spawn(dir.path()).await;
    let ca_fingerprint = daemon.identity.ca_fingerprint();
    let identity = request_enrollment(&daemon.enrollment_request("laptop-f"))
        .await
        .unwrap();
    enroll::save_identity(&state, &identity).unwrap();
    daemon.stop().await;

    // Same directories, new process lifecycle: identity + registry reload.
    let daemon = TlsDaemon::spawn(dir.path()).await;
    assert_eq!(
        daemon.identity.ca_fingerprint(),
        ca_fingerprint,
        "restart must not mint a new CA"
    );
    let mut client = connect_authenticated(&daemon.url, &state).await.unwrap();
    client
        .list_snapshots(ListSnapshotsRequest {})
        .await
        .unwrap();

    daemon.stop().await;
}
