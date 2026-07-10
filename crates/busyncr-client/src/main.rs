//! BusyNCR client: runs on the host being backed up (Windows service in
//! production; Linux for dev/test). CLI surface grows slice by slice:
//! backup | restore | list | bench-chunking | export-key | import-key | enroll

mod bench_cmd;

use std::path::PathBuf;

use anyhow::Context;
use busyncr_client::enroll;
use clap::{Parser, Subcommand};

/// Top-level CLI.
#[derive(Parser)]
#[command(name = "busyncr-client", version, about = "BusyNCR backup client")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

/// Available subcommands (grows slice by slice).
#[derive(Subcommand)]
enum Command {
    /// Offline chunk-size benchmark: measure candidate CDC target sizes over
    /// a real directory tree before committing one to config (PRD §3.7).
    #[command(name = "bench-chunking", long_about = bench_cmd::LONG_ABOUT)]
    BenchChunking(bench_cmd::BenchArgs),

    /// Enroll this machine against a BusyNCR daemon (FR1).
    ///
    /// Requires a one-time token and the daemon's CA certificate, both
    /// produced by `busyncr-daemon enroll-token` on the server. Generates a
    /// local keypair (the private key never leaves this machine), receives a
    /// CA-signed client certificate, and creates the backup set's data key
    /// on first enrollment.
    Enroll {
        /// Daemon endpoint, e.g. https://backup-server:47820
        #[arg(long)]
        daemon: String,
        /// Path to the daemon's CA certificate (ca-cert.pem).
        #[arg(long)]
        ca: PathBuf,
        /// One-time enrollment token.
        #[arg(long)]
        token: String,
        /// Enrollment name for this machine (certificate Common Name).
        #[arg(long)]
        name: String,
        /// Client state directory (created if absent).
        #[arg(long)]
        state: PathBuf,
    },
}

fn main() -> std::process::ExitCode {
    let cli = Cli::parse();
    let result = match cli.command {
        Command::BenchChunking(args) => bench_cmd::run(&args),
        Command::Enroll {
            daemon,
            ca,
            token,
            name,
            state,
        } => run_enroll(daemon, &ca, token, name, &state),
    };
    match result {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("error: {err:#}");
            std::process::ExitCode::FAILURE
        }
    }
}

/// `enroll` subcommand: FR1 end to end from the client side.
fn run_enroll(
    daemon: String,
    ca: &std::path::Path,
    token: String,
    name: String,
    state: &std::path::Path,
) -> anyhow::Result<()> {
    let ca_cert_pem = std::fs::read_to_string(ca)
        .with_context(|| format!("reading CA certificate {}", ca.display()))?;
    let request = enroll::EnrollmentRequest {
        daemon_url: daemon,
        ca_cert_pem,
        token,
        name,
    };

    let identity = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .context("starting tokio runtime")?
        .block_on(enroll::request_enrollment(&request))
        .context("enrollment failed")?;

    enroll::save_identity(state, &identity).context("saving enrolled identity")?;
    let created =
        enroll::ensure_data_key(state, &mut rand::rng()).context("creating backup data key")?;

    println!(
        "enrolled as {:?}; identity saved under {}",
        request.name,
        state.display()
    );
    if created {
        println!(
            "created new backup data key ({}); export a passphrase-protected \
             copy once export-key lands (PRD §3.4)",
            state.join(enroll::DATA_KEY_FILE).display()
        );
    } else {
        println!("existing backup data key kept (history stays decryptable)");
    }
    Ok(())
}
