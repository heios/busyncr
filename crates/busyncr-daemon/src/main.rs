//! BusyNCR daemon: runs on the backup server. Stores versioned snapshots in a
//! content-addressed chunk store, enforces the retention grid, garbage-collects.
//! CLI surface grows slice by slice: serve | prune | gc | enroll-token | revoke

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use anyhow::Context;
use busyncr_core::retention::RetentionPolicy;
use busyncr_daemon::config::DaemonConfig;
use busyncr_daemon::identity::{DaemonIdentity, CA_CERT_FILE};
use busyncr_daemon::store::{ChunkStore, PruneMode};
use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "busyncr-daemon", version, about = "BusyNCR backup daemon")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Serve the gRPC API over mutual TLS, backed by the chunk store.
    ///
    /// First run bootstraps the daemon's internal CA and server certificate
    /// under `<store>/identity/`. Clients enroll with a one-time token (see
    /// `enroll-token`); every other RPC requires an enrolled, non-revoked
    /// client certificate (FR1).
    Serve {
        /// Chunk store root directory (created if absent).
        #[arg(long)]
        store: PathBuf,
        /// Address to listen on.
        #[arg(long, default_value = "0.0.0.0:47820")]
        listen: SocketAddr,
    },

    /// Mint and print a one-time enrollment token (FR1).
    ///
    /// Also prints the CA certificate path + fingerprint; copy that file to
    /// the enrolling host and pass it to `busyncr-client enroll --ca`.
    EnrollToken {
        /// Chunk store root directory (identity lives under it).
        #[arg(long)]
        store: PathBuf,
    },

    /// Revoke an enrolled client's certificate(s) by enrollment name (FR1).
    ///
    /// The client's TLS certificate keeps verifying, but every RPC it makes
    /// is refused with PERMISSION_DENIED from the next connection on.
    Revoke {
        /// Chunk store root directory (identity lives under it).
        #[arg(long)]
        store: PathBuf,
        /// Enrollment name (the CSR Common Name shown at enrollment).
        name: String,
    },

    /// Apply the retention grid, dropping over-retained snapshots (FR5).
    ///
    /// Uses the PRD §3.5 default grid (3 h / 24 h / 4 d / 16 d cells). Drops
    /// each pruned snapshot's manifest and decrements chunk refcounts; run
    /// `gc` afterwards to reclaim the freed chunks.
    Prune {
        /// Chunk store root directory.
        #[arg(long)]
        store: PathBuf,
    },

    /// Garbage-collect chunks with zero live references (FR5).
    ///
    /// A chunk is only reclaimed after it has been continuously unreferenced
    /// for the grace period, so a concurrent backup's just-uploaded (not yet
    /// manifested) chunks are never swept.
    Gc {
        /// Chunk store root directory.
        #[arg(long)]
        store: PathBuf,
        /// Grace period in seconds a chunk must stay zero-ref before it is
        /// reclaimed.
        #[arg(long, default_value_t = 3600)]
        grace_secs: u64,
    },

    /// Read-only daemon health: snapshot counts, unique chunks, store bytes,
    /// zero-ref chunks awaiting gc, last prune/gc time+mode, CA fingerprint
    /// (FR-M1 M3.2).
    ///
    /// Safe to run while `serve` is up on the same store *within this
    /// process's model* (redb readers never block writers); as a genuinely
    /// separate OS process it can fail with a store-busy error while `serve`
    /// holds the store's file lock — the underlying storage engine does not
    /// offer cross-process concurrent access, so this surfaces cleanly
    /// rather than corrupting anything.
    Status {
        /// Chunk store root directory.
        #[arg(long)]
        store: PathBuf,
        /// Emit machine-readable JSON instead of the human-readable report.
        #[arg(long)]
        json: bool,
    },
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Command::Serve { store, listen } => serve(store, listen),
        Command::EnrollToken { store } => enroll_token(&store),
        Command::Revoke { store, name } => revoke(&store, &name),
        Command::Prune { store } => prune(&store),
        Command::Gc { store, grace_secs } => gc(&store, grace_secs),
        Command::Status { store, json } => status(&store, json),
    }
}

/// Opens (bootstrapping on first use) the daemon identity under the store.
fn open_identity(store_root: &std::path::Path) -> anyhow::Result<DaemonIdentity> {
    let dir = store_root.join("identity");
    DaemonIdentity::open_or_init(&dir)
        .with_context(|| format!("opening daemon identity at {}", dir.display()))
}

/// Daily auto-prune cadence (PRD §3.5 / FR-M1 M1.2).
const AUTO_PRUNE_INTERVAL: std::time::Duration = std::time::Duration::from_secs(24 * 60 * 60);

fn serve(store_root: PathBuf, listen: SocketAddr) -> anyhow::Result<()> {
    let identity = Arc::new(open_identity(&store_root)?);
    let store = Arc::new(
        ChunkStore::open(&store_root)
            .with_context(|| format!("opening chunk store at {}", store_root.display()))?,
    );
    let config = DaemonConfig::load_or_init(&store_root).with_context(|| {
        format!(
            "loading daemon config at {}",
            store_root.join(DaemonConfig::FILE_NAME).display()
        )
    })?;

    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .context("starting tokio runtime")?
        .block_on(async move {
            let (listener, local) = busyncr_daemon::service::bind(listen)
                .await
                .with_context(|| format!("binding {listen}"))?;
            eprintln!(
                "busyncr-daemon {} serving mTLS on {local} (CA fingerprint {}); auto_prune={}",
                busyncr_core::VERSION,
                identity.ca_fingerprint(),
                config.auto_prune
            );
            if config.auto_prune {
                let timer_store = Arc::clone(&store);
                tokio::spawn(busyncr_daemon::service::run_prune_timer(
                    timer_store,
                    AUTO_PRUNE_INTERVAL,
                    Box::pin(shutdown_signal()),
                ));
            }
            busyncr_daemon::service::serve_tls_with_config(
                store,
                identity,
                listener,
                shutdown_signal(),
                config.auto_prune,
            )
            .await
            .context("gRPC server failed")
        })
}

/// Resolves once Ctrl-C (SIGINT) fires or, on Unix, SIGTERM does — whichever
/// comes first. `serve_tls` stops accepting new connections and lets
/// in-flight RPCs finish (FR8: the daemon is a long-lived process that must
/// shut down cleanly, not mid-write, on a normal stop/restart signal).
async fn shutdown_signal() {
    let ctrl_c = async {
        let _ = tokio::signal::ctrl_c().await;
    };
    #[cfg(unix)]
    let terminate = async {
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut sig) => {
                sig.recv().await;
            }
            Err(_) => std::future::pending::<()>().await,
        }
    };
    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        () = ctrl_c => {},
        () = terminate => {},
    }
    eprintln!("shutting down");
}

fn enroll_token(store_root: &std::path::Path) -> anyhow::Result<()> {
    let identity = open_identity(store_root)?;
    let token = identity
        .mint_token(&mut rand::rng())
        .context("minting enrollment token")?;
    println!("enrollment token (one-time): {token}");
    println!(
        "CA certificate:              {}",
        identity.dir().join(CA_CERT_FILE).display()
    );
    println!("CA fingerprint (BLAKE3):     {}", identity.ca_fingerprint());
    println!();
    println!("On the client host, run:");
    println!(
        "  busyncr-client enroll --daemon https://<this-host>:47820 \
         --ca ca-cert.pem --token {token} --name <client-name> --state <state-dir>"
    );
    Ok(())
}

fn revoke(store_root: &std::path::Path, name: &str) -> anyhow::Result<()> {
    let identity = open_identity(store_root)?;
    let count = identity
        .revoke(name)
        .with_context(|| format!("revoking client {name:?}"))?;
    anyhow::ensure!(count > 0, "no active enrolled client named {name:?}");
    println!("revoked {count} certificate(s) enrolled as {name:?}");
    Ok(())
}

/// Whole seconds since the Unix epoch, or 0 if the clock predates it.
fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| i64::try_from(d.as_millis()).unwrap_or(i64::MAX))
        .unwrap_or(0)
}

/// `prune` subcommand (FR5): apply the default retention grid at the wall
/// clock. The clock is injected here at the binary edge; the store's prune is
/// deterministic given `now`.
fn prune(store_root: &std::path::Path) -> anyhow::Result<()> {
    let store = ChunkStore::open(store_root)
        .with_context(|| format!("opening chunk store at {}", store_root.display()))?;
    let outcome = store
        .prune(
            now_ms(),
            &RetentionPolicy::default_grid(),
            PruneMode::Manual,
        )
        .context("applying retention grid")?;
    println!(
        "prune complete: kept {} snapshot(s), dropped {}",
        outcome.kept.len(),
        outcome.dropped.len()
    );
    for snapshot in &outcome.dropped {
        println!("  dropped {snapshot}");
    }
    println!("run `busyncr-daemon gc` to reclaim now-unreferenced chunks");
    Ok(())
}

/// `gc` subcommand (FR5): reclaim chunks that have been unreferenced longer
/// than the grace period.
fn gc(store_root: &std::path::Path, grace_secs: u64) -> anyhow::Result<()> {
    let store = ChunkStore::open(store_root)
        .with_context(|| format!("opening chunk store at {}", store_root.display()))?;
    let outcome = store
        .gc(now_ms(), std::time::Duration::from_secs(grace_secs))
        .context("garbage-collecting unreferenced chunks")?;
    println!(
        "gc complete: reclaimed {} chunk(s) ({} bytes); {} chunk(s) marked and awaiting grace",
        outcome.reclaimed.len(),
        outcome.bytes_reclaimed,
        outcome.pending
    );
    Ok(())
}

/// Machine-readable `busyncr-daemon status --json` payload (FR-M1 M3.2/M3.3).
#[derive(serde::Serialize)]
struct StatusJson {
    snapshots_total: u64,
    snapshots_by_client: std::collections::BTreeMap<String, u64>,
    chunks_unique: u64,
    store_bytes: u64,
    zero_ref_chunks: u64,
    last_prune_at_ms: Option<i64>,
    last_prune_mode: Option<String>,
    last_gc_at_ms: Option<i64>,
    ca_fingerprint: Option<String>,
}

/// `status` subcommand (FR-M1 M3.2/M3.3): read-only daemon health. See the
/// `Command::Status` doc comment for the cross-process concurrency caveat.
fn status(store_root: &std::path::Path, json: bool) -> anyhow::Result<()> {
    // The CA fingerprint only exists once a daemon has been bootstrapped
    // here; a store that was never served has no identity yet, which is a
    // legitimate ("not set up") status rather than an error — do not
    // bootstrap one just to answer a read-only question.
    let identity_bootstrapped = store_root.join("identity").join(CA_CERT_FILE).is_file();
    let ca_fingerprint = if identity_bootstrapped {
        Some(open_identity(store_root)?.ca_fingerprint())
    } else {
        None
    };

    let store = ChunkStore::open(store_root).with_context(|| {
        format!(
            "opening chunk store at {} (if `serve` is currently running against this store, \
             its exclusive file lock can make a separate `status` process unable to open it — \
             this is a limitation of the storage engine, not a corruption)",
            store_root.display()
        )
    })?;
    let status = store.status().context("reading daemon status")?;

    if json {
        let payload = StatusJson {
            snapshots_total: status.snapshots_total,
            snapshots_by_client: status.snapshots_by_client,
            chunks_unique: status.chunks_unique,
            store_bytes: status.store_bytes,
            zero_ref_chunks: status.zero_ref_chunks,
            last_prune_at_ms: status.last_prune.map(|p| p.at_ms),
            last_prune_mode: status.last_prune.map(|p| p.mode.to_string()),
            last_gc_at_ms: status.last_gc.map(|g| g.at_ms),
            ca_fingerprint,
        };
        println!("{}", serde_json::to_string_pretty(&payload)?);
        return Ok(());
    }

    println!("store:              {}", store_root.display());
    if let Some(fp) = &ca_fingerprint {
        println!("CA fingerprint:      {fp}");
    } else {
        println!("CA fingerprint:      (not bootstrapped yet — no `serve` or `enroll-token` has run here)");
    }
    println!("snapshots:           {}", status.snapshots_total);
    for (client, count) in &status.snapshots_by_client {
        let label = if client.is_empty() {
            "(unattributed)"
        } else {
            client
        };
        println!("  {label:<18} {count}");
    }
    println!("unique chunks:       {}", status.chunks_unique);
    println!("store bytes:         {}", status.store_bytes);
    println!("zero-ref (gc-able):  {}", status.zero_ref_chunks);
    match status.last_prune {
        Some(p) => println!("last prune:          {} ({})", p.at_ms, p.mode),
        None => println!("last prune:          never"),
    }
    match status.last_gc {
        Some(g) => println!("last gc:             {}", g.at_ms),
        None => println!("last gc:             never"),
    }
    Ok(())
}
