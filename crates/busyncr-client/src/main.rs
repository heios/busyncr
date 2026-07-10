//! BusyNCR client: runs on the host being backed up (Windows service in
//! production; Linux for dev/test). CLI surface grows slice by slice:
//! backup | restore | list | bench-chunking | export-key | import-key | enroll

mod bench_cmd;

use std::path::PathBuf;

use anyhow::Context;
use busyncr_client::run::{run_scheduler, RunRequest, SystemClock};
use busyncr_client::service::ServiceAction;
use busyncr_client::{backup, config, enroll, restore, service};
use busyncr_core::scheduler::SchedulePolicy;
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

    /// Run backups on a recurring jittered schedule until interrupted (FR8).
    ///
    /// Backs up immediately, then repeats on the configured interval
    /// (default 3 h, PRD §3.5) with random jitter so many clients do not all
    /// hit the daemon at the same instant. Stops cleanly on Ctrl-C (SIGINT)
    /// or, on Unix, SIGTERM. Safe to kill and restart at any time: the next
    /// `run` invocation always starts with an immediate backup, so time
    /// spent stopped is caught up on restart rather than lost, and a backup
    /// attempt that fails (daemon unreachable, daemon restarted mid-upload,
    /// ...) is logged but never stops the schedule.
    Run {
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
        /// Nominal interval between backups, e.g. `3h`, `90m`, `5400s`
        /// (PRD §3.5 default: 3 h).
        #[arg(long, default_value = "3h")]
        interval: String,
        /// Jitter fraction applied to the interval, in `[0, 1]`
        /// (`0.1` = the actual delay is `interval ± 10 %`).
        #[arg(long, default_value_t = 0.1)]
        jitter: f64,
    },

    /// Manage this client as a Windows service (FR8 Windows part; PRD §3.6).
    ///
    /// Wraps the same scheduled backup loop as `run` (S10), but installed,
    /// started, and stopped through the Windows Service Control Manager
    /// instead of run in the foreground. Every action other than `run`
    /// fails cleanly with an "unsupported platform" error when this binary
    /// is not built for Windows.
    Service {
        #[command(subcommand)]
        action: ServiceAction,
    },

    /// Restore a retained snapshot to an empty directory (FR4, FR9).
    ///
    /// Fetches the manifest and every chunk it references, decrypts and
    /// verifies each chunk's content address, and reassembles the tree
    /// byte-exact including mtime and permissions. The target directory is
    /// created if missing but must be empty either way.
    Restore {
        /// Path to the client TOML config (daemon URL).
        #[arg(long)]
        config: PathBuf,
        /// Client state directory (from `enroll`).
        #[arg(long)]
        state: PathBuf,
        /// Snapshot ULID to restore (as printed by `backup` or `list`).
        snapshot: String,
        /// Target directory: created if missing, must be empty.
        target: PathBuf,
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
        Command::Run {
            config,
            state,
            default_chunking,
            interval,
            jitter,
        } => run_scheduled(&config, &state, default_chunking, &interval, jitter),
        Command::Service { action } => run_service_command(action),
        Command::Restore {
            config,
            state,
            snapshot,
            target,
        } => run_restore(&config, &state, &snapshot, &target),
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

/// `run` subcommand: FR8 non-Windows scheduling from the client side. Wires
/// the real wall clock and OS entropy at this binary edge; the loop itself
/// ([`run_scheduler`]) never touches either directly.
fn run_scheduled(
    config_path: &std::path::Path,
    state: &std::path::Path,
    default_chunking: bool,
    interval: &str,
    jitter: f64,
) -> anyhow::Result<()> {
    let config = config::ClientConfig::load(config_path)?;
    let chunker = config.chunker(default_chunking)?;
    let interval = parse_duration(interval)?;
    let schedule = SchedulePolicy::new(interval, jitter).with_context(|| {
        format!("interval {interval:?} / jitter {jitter} is not a usable schedule")
    })?;

    let request = RunRequest {
        daemon_url: &config.daemon,
        state_dir: state,
        roots: &config.folders,
        chunker,
        schedule,
    };

    println!(
        "busyncr-client run: backing up to {} every {:?} (±{:.0}% jitter); Ctrl-C to stop",
        config.daemon,
        schedule.interval(),
        schedule.jitter() * 100.0
    );

    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .context("starting tokio runtime")?
        .block_on(async {
            run_scheduler(
                &request,
                &SystemClock,
                &mut rand::rng(),
                Box::pin(shutdown_signal()),
                report_tick,
            )
            .await;
        });
    Ok(())
}

/// Prints the outcome of one scheduled backup attempt. A failed attempt is
/// logged, not fatal — the schedule keeps running (FR8).
fn report_tick(tick: busyncr_client::run::Tick) {
    match tick.result {
        Ok(report) => println!(
            "[t={}ms] snapshot {} stored: {} file(s), {} chunk(s) shipped \
             ({} bytes), {} deduplicated",
            tick.started_at_ms,
            report.snapshot_id,
            report.files,
            report.chunks_uploaded,
            report.upload_bytes,
            report.chunks_deduped
        ),
        Err(err) => eprintln!(
            "[t={}ms] backup attempt failed: {err:#}",
            tick.started_at_ms
        ),
    }
}

/// Resolves once Ctrl-C (SIGINT) fires or, on Unix, SIGTERM does — whichever
/// comes first — for the `run` loop's graceful shutdown (FR8).
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
    eprintln!("stopping scheduled backups");
}

/// `service` subcommand: Windows Service Control Manager integration (FR8
/// Windows part; PRD §3.6). See `busyncr_client::service` module docs for
/// the install/start/stop/run design.
fn run_service_command(action: ServiceAction) -> anyhow::Result<()> {
    match action {
        ServiceAction::Install(run_args) => {
            service::install(&run_args).context("installing the Windows service")?;
            println!(
                "service {:?} installed (auto-start); `service start` to run it now",
                service::SERVICE_NAME
            );
        }
        ServiceAction::Uninstall => {
            service::uninstall().context("uninstalling the Windows service")?;
            println!("service {:?} uninstalled", service::SERVICE_NAME);
        }
        ServiceAction::Start => {
            service::start().context("starting the Windows service")?;
            println!("service {:?} start requested", service::SERVICE_NAME);
        }
        ServiceAction::Stop => {
            service::stop().context("stopping the Windows service")?;
            println!("service {:?} stop requested", service::SERVICE_NAME);
        }
        ServiceAction::Restart => {
            service::restart().context("restarting the Windows service")?;
            println!("service {:?} restart requested", service::SERVICE_NAME);
        }
        ServiceAction::Run(run_args) => {
            service::run(run_args).context("running as a Windows service")?;
        }
    }
    Ok(())
}

/// Parses a duration like `3h`, `90m`, `5400s`, or plain seconds.
fn parse_duration(s: &str) -> anyhow::Result<std::time::Duration> {
    let t = s.trim();
    anyhow::ensure!(!t.is_empty(), "empty interval");
    let last = t.chars().last().context("empty interval")?;
    let (digits, multiplier) = match last {
        'h' | 'H' => (&t[..t.len() - 1], 3600u64),
        'm' | 'M' => (&t[..t.len() - 1], 60u64),
        's' | 'S' => (&t[..t.len() - 1], 1u64),
        _ => (t, 1u64),
    };
    let value: u64 = digits
        .parse()
        .with_context(|| format!("{s:?} is not a valid interval (e.g. 3h, 90m, 5400s)"))?;
    let secs = value
        .checked_mul(multiplier)
        .context("interval overflows")?;
    Ok(std::time::Duration::from_secs(secs))
}

/// `restore` subcommand: FR4/FR9 end to end from the client side.
fn run_restore(
    config_path: &std::path::Path,
    state: &std::path::Path,
    snapshot: &str,
    target: &std::path::Path,
) -> anyhow::Result<()> {
    let config = config::ClientConfig::load(config_path)?;
    let snapshot_id: ulid::Ulid = snapshot
        .parse()
        .with_context(|| format!("{snapshot:?} is not a valid snapshot ULID"))?;

    let request = restore::RestoreRequest {
        daemon_url: &config.daemon,
        state_dir: state,
        snapshot_id,
        target_dir: target,
    };

    let report = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .context("starting tokio runtime")?
        .block_on(restore::run_restore(&request))
        .context("restore failed")?;

    println!(
        "snapshot {} restored to {}",
        report.snapshot_id,
        target.display()
    );
    println!(
        "  {} file(s), {} bytes written, {} chunk(s) fetched and verified",
        report.files, report.bytes, report.chunks_fetched
    );
    Ok(())
}
