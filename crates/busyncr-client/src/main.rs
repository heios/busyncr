//! BusyNCR client: runs on the host being backed up (Windows service in
//! production; Linux for dev/test). CLI surface grows slice by slice:
//! backup | restore | list | bench-chunking | export-key | import-key | enroll

mod bench_cmd;

use std::path::PathBuf;

use anyhow::Context;
use busyncr_client::{backup, config, enroll};
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

    /// Back up the configured folders as one new snapshot (FR2, FR3).
    ///
    /// Walks every folder listed in the TOML config, chunks changed data
    /// with the committed chunk size, encrypts everything client-side, and
    /// ships only the chunks the daemon is missing. Refuses to run until a
    /// chunk size is committed in the config (run bench-chunking first) or
    /// --default-chunking is passed.
    Backup {
        /// Path to the client TOML config (daemon URL, folders,
        /// chunk_target_size).
        #[arg(long)]
        config: PathBuf,
        /// Client state directory (from `enroll`).
        #[arg(long)]
        state: PathBuf,
        /// Accept the 1 MiB default chunk size instead of committing one
        /// measured by bench-chunking (PRD §3.7).
        #[arg(long)]
        default_chunking: bool,
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
        Command::Backup {
            config,
            state,
            default_chunking,
        } => run_backup(&config, &state, default_chunking),
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

/// `backup` subcommand: FR2/FR3 end to end from the client side. Injects the
/// wall clock and OS entropy here at the binary edge; the library pipeline
/// itself is deterministic.
fn run_backup(
    config_path: &std::path::Path,
    state: &std::path::Path,
    default_chunking: bool,
) -> anyhow::Result<()> {
    let config = config::ClientConfig::load(config_path)?;
    let chunker = config.chunker(default_chunking)?;

    let snapshot_id = ulid::Ulid::new();
    let created_at = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    let request = backup::BackupRequest {
        daemon_url: &config.daemon,
        state_dir: state,
        roots: &config.folders,
        chunker,
        snapshot_id,
        created_at,
    };

    let report = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .context("starting tokio runtime")?
        .block_on(backup::run_backup(&request, &mut rand::rng()))
        .context("backup failed")?;

    println!(
        "snapshot {} stored on {}",
        report.snapshot_id, config.daemon
    );
    println!(
        "  {} file(s), {} bytes scanned; {} chunk refs ({} unique)",
        report.files, report.source_bytes, report.chunks_total, report.chunks_unique
    );
    println!(
        "  shipped {} new chunk(s) = {} encrypted bytes; {} deduplicated; \
         manifest {} bytes (encrypted)",
        report.chunks_uploaded, report.upload_bytes, report.chunks_deduped, report.manifest_bytes
    );
    Ok(())
}
