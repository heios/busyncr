//! BusyNCR daemon: runs on the backup server. Stores versioned snapshots in a
//! content-addressed chunk store, enforces the retention grid, garbage-collects.
//! CLI surface grows slice by slice: serve | prune | gc | enroll-token | revoke

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use anyhow::Context;
use busyncr_daemon::identity::{DaemonIdentity, CA_CERT_FILE};
use busyncr_daemon::store::ChunkStore;
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
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Command::Serve { store, listen } => serve(store, listen),
        Command::EnrollToken { store } => enroll_token(&store),
        Command::Revoke { store, name } => revoke(&store, &name),
    }
}

/// Opens (bootstrapping on first use) the daemon identity under the store.
fn open_identity(store_root: &std::path::Path) -> anyhow::Result<DaemonIdentity> {
    let dir = store_root.join("identity");
    DaemonIdentity::open_or_init(&dir)
        .with_context(|| format!("opening daemon identity at {}", dir.display()))
}

fn serve(store_root: PathBuf, listen: SocketAddr) -> anyhow::Result<()> {
    let identity = Arc::new(open_identity(&store_root)?);
    let store = Arc::new(
        ChunkStore::open(&store_root)
            .with_context(|| format!("opening chunk store at {}", store_root.display()))?,
    );

    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .context("starting tokio runtime")?
        .block_on(async move {
            let (listener, local) = busyncr_daemon::service::bind(listen)
                .await
                .with_context(|| format!("binding {listen}"))?;
            eprintln!(
                "busyncr-daemon {} serving mTLS on {local} (CA fingerprint {})",
                busyncr_core::VERSION,
                identity.ca_fingerprint()
            );
            busyncr_daemon::service::serve_tls(store, identity, listener, async {
                let _ = tokio::signal::ctrl_c().await;
                eprintln!("shutting down");
            })
            .await
            .context("gRPC server failed")
        })
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
