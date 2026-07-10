//! BusyNCR daemon: runs on the backup server. Stores versioned snapshots in a
//! content-addressed chunk store, enforces the retention grid, garbage-collects.
//! CLI surface grows slice by slice: serve | prune | gc | enroll-token

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use anyhow::Context;
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
    /// Serve the gRPC API backed by the chunk store.
    ///
    /// Slice S5: plain TCP, so bind localhost only. TLS + enrollment land in
    /// slice S6.
    Serve {
        /// Chunk store root directory (created if absent).
        #[arg(long)]
        store: PathBuf,
        /// Address to listen on.
        #[arg(long, default_value = "127.0.0.1:47820")]
        listen: SocketAddr,
    },
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Command::Serve { store, listen } => serve(store, listen),
    }
}

fn serve(store_root: PathBuf, listen: SocketAddr) -> anyhow::Result<()> {
    if !listen.ip().is_loopback() {
        anyhow::bail!(
            "refusing to serve plain TCP on non-loopback address {listen}; \
             TLS arrives in slice S6"
        );
    }
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
                "busyncr-daemon {} serving on {local}",
                busyncr_core::VERSION
            );
            busyncr_daemon::service::serve(store, listener, async {
                let _ = tokio::signal::ctrl_c().await;
                eprintln!("shutting down");
            })
            .await
            .context("gRPC server failed")
        })
}
