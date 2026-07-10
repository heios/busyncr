//! Windows service integration (FR8 Windows part; PRD §3.6).
//!
//! `busyncr-client service <action>` wraps the S10 scheduled backup loop
//! ([`crate::run::run_scheduler`]) as a native Windows service via the
//! AGENTS.md palette's `windows-service` crate:
//!
//! - `service install` registers this binary as the `BusyNCRClient` service
//!   (auto-start), configuring the Service Control Manager to launch it with
//!   `service run` plus the given [`ServiceRunArgs`] every time it starts
//!   the service ([`launch_argv`]). Windows launches a service by running
//!   the *whole* stored command line via `CreateProcess`, so those become
//!   ordinary `std::env::args()` the next time this binary starts — no
//!   custom argv channel is needed between `install` and `run`.
//! - `service start` / `service stop` / `service restart` ask the SCM to
//!   transition the installed service.
//! - `service run` is the service entry point: it registers a control
//!   handler with the SCM, reports `Running`, drives
//!   [`crate::run::run_scheduler`] until a `Stop` control arrives, reports
//!   `Stopped`, and logs lifecycle events to the Windows Event Log
//!   ([`eventlog`]). It is not meant to be invoked directly by an operator —
//!   only the SCM starts a process this way in practice, since
//!   `service_dispatcher::start` fails outside of an SCM-launched process.
//!
//! All of the above (registering with the real SCM, writing to the real
//! Event Log) only exists on Windows (`#[cfg(windows)]`), per AGENTS.md.
//! Everything else in this module — [`ServiceRunArgs`], [`ServiceAction`],
//! [`launch_argv`], and the CLI argument parsing that builds and consumes
//! them — is ordinary, cross-platform, unit-testable Rust: SLICES S11 asks
//! for exactly that split ("Linux-side: code must compile with `cargo
//! check`... and unit tests for service-arg parsing").
//!
//! On non-Windows platforms every `#[cfg(not(windows))]` fallback below
//! returns [`ServiceError::UnsupportedPlatform`] — the cross-platform
//! scheduled loop itself lives in `busyncr-client run` (S10), which keeps
//! working unchanged everywhere.

#[cfg(windows)]
mod eventlog;

use std::ffi::OsString;
use std::path::PathBuf;
#[cfg(any(windows, test))]
use std::time::Duration;

use clap::{Args, Subcommand};

/// Windows Service Control Manager service name this binary registers under.
pub const SERVICE_NAME: &str = "BusyNCRClient";

/// User-facing service name shown in `services.msc` / `Get-Service`.
pub const SERVICE_DISPLAY_NAME: &str = "BusyNCR Backup Client";

/// Errors from Windows service management (install/uninstall/start/stop/
/// restart/run) and from resolving a [`ServiceRunArgs`] into a runnable
/// schedule.
#[derive(Debug, thiserror::Error)]
pub enum ServiceError {
    /// Windows service management is only implemented on Windows; the
    /// cross-platform equivalent is `busyncr-client run` (S10).
    #[error("Windows service management is only available when built for Windows")]
    UnsupportedPlatform,

    /// `service run` was dispatched by the Service Control Manager without
    /// `run` having stashed its arguments first — an internal-wiring bug,
    /// never a user input error (the CLI always calls `run` with args in
    /// hand before starting the dispatcher).
    #[error("internal error: service run arguments were not configured before dispatch")]
    NotConfigured,

    /// `std::env::current_exe` failed while building the SCM launch path.
    #[error("could not determine this executable's own path")]
    ExecutablePath(#[source] std::io::Error),

    /// The async runtime backing the service loop failed to start.
    #[error("could not start the async runtime")]
    Runtime(#[source] std::io::Error),

    /// `--interval` did not parse as a duration.
    #[error("{0:?} is not a valid interval (e.g. 3h, 90m, 5400s)")]
    BadInterval(String),

    /// `--interval` parsed but overflows when converted to seconds.
    #[error("interval overflows")]
    IntervalOverflow,

    /// The parsed interval/jitter do not form a usable schedule.
    #[error(transparent)]
    Schedule(#[from] busyncr_core::scheduler::ScheduleError),

    /// The client config file failed to load or resolve a chunker.
    #[error(transparent)]
    Config(#[from] crate::config::ConfigError),

    /// The underlying Windows Service Control Manager call failed.
    #[cfg(windows)]
    #[error("Windows service control manager call failed")]
    Scm(#[source] windows_service::Error),
}

#[cfg(windows)]
impl From<windows_service::Error> for ServiceError {
    fn from(err: windows_service::Error) -> Self {
        ServiceError::Scm(err)
    }
}

/// Everything the scheduled backup loop needs, captured once at
/// `service install` time and reconstructed every time the Service Control
/// Manager launches this process to run the service (see [`launch_argv`]).
/// Mirrors `busyncr-client run`'s own arguments (S10) field for field.
#[derive(Args, Debug, Clone, PartialEq)]
pub struct ServiceRunArgs {
    /// Path to the client TOML config (daemon URL, folders,
    /// chunk_target_size).
    #[arg(long)]
    pub config: PathBuf,
    /// Client state directory (from `enroll`).
    #[arg(long)]
    pub state: PathBuf,
    /// Accept the 1 MiB default chunk size instead of committing one
    /// measured by bench-chunking (PRD §3.7).
    #[arg(long)]
    pub default_chunking: bool,
    /// Nominal interval between backups, e.g. `3h`, `90m`, `5400s`
    /// (PRD §3.5 default: 3 h).
    #[arg(long, default_value = "3h")]
    pub interval: String,
    /// Jitter fraction applied to the interval, in `[0, 1]`.
    #[arg(long, default_value_t = 0.1)]
    pub jitter: f64,
}

impl ServiceRunArgs {
    /// Renders these settings as the argv tail (after `service run`) that
    /// reconstructs them when reparsed by the same clap CLI that parses
    /// them the first time around.
    fn to_args(&self) -> Vec<String> {
        let mut args = vec![
            "--config".to_string(),
            self.config.to_string_lossy().into_owned(),
            "--state".to_string(),
            self.state.to_string_lossy().into_owned(),
            "--interval".to_string(),
            self.interval.clone(),
            "--jitter".to_string(),
            self.jitter.to_string(),
        ];
        if self.default_chunking {
            args.push("--default-chunking".to_string());
        }
        args
    }
}

/// The full argv (after the executable path) the Service Control Manager
/// should launch this process with to run the service — `service run` plus
/// [`ServiceRunArgs::to_args`]. `service install` bakes this into the
/// service's registered launch command; a human can reproduce it manually to
/// run the same configuration in the foreground for debugging (though
/// outside an SCM-managed process, `service run` itself refuses to start,
/// same as any Windows service binary).
pub fn launch_argv(run_args: &ServiceRunArgs) -> Vec<OsString> {
    let mut argv = vec![OsString::from("service"), OsString::from("run")];
    argv.extend(run_args.to_args().into_iter().map(OsString::from));
    argv
}

/// `busyncr-client service <action>` — Windows Service Control Manager
/// integration (FR8 Windows part; PRD §3.6).
#[derive(Subcommand, Debug, Clone, PartialEq)]
pub enum ServiceAction {
    /// Register this binary as the `BusyNCRClient` Windows service
    /// (auto-start). The Service Control Manager launches it with
    /// `service run` plus these arguments every time it starts the service.
    Install(ServiceRunArgs),
    /// Unregister the service (stops it first if it is running).
    Uninstall,
    /// Start the previously installed service via the SCM.
    Start,
    /// Stop the running service via the SCM.
    Stop,
    /// Stop then start the service via the SCM.
    Restart,
    /// The service entry point: registers with the SCM, runs the scheduled
    /// backup loop (FR8; PRD §3.5) until a Stop control is received, and
    /// logs lifecycle events to the Windows Event Log. Only meaningful when
    /// launched by the SCM (which is what `service install` wires up) —
    /// invoking it directly from an interactive shell fails, by design of
    /// the Windows service model.
    Run(ServiceRunArgs),
}

/// Parses a duration like `3h`, `90m`, `5400s`, or a plain integer of
/// seconds — mirrors `busyncr-client run`'s own `--interval` parsing (S10)
/// so a schedule set up via `service install` behaves identically to one run
/// in the foreground.
///
/// Only ever called from the Windows service loop in production
/// ([`run_service_body`]); `cfg`-gated to `windows`-or-`test` so it is still
/// fully unit-testable on Linux (SLICES S11: "Linux-side ... unit tests for
/// service-arg parsing") without leaving genuinely dead code in a non-test
/// non-Windows build.
#[cfg(any(windows, test))]
fn parse_interval(s: &str) -> Result<Duration, ServiceError> {
    let t = s.trim();
    let last = match t.chars().last() {
        Some(c) => c,
        None => return Err(ServiceError::BadInterval(s.to_string())),
    };
    let (digits, multiplier) = match last {
        'h' | 'H' => (&t[..t.len() - 1], 3600u64),
        'm' | 'M' => (&t[..t.len() - 1], 60u64),
        's' | 'S' => (&t[..t.len() - 1], 1u64),
        _ => (t, 1u64),
    };
    let value: u64 = digits
        .parse()
        .map_err(|_| ServiceError::BadInterval(s.to_string()))?;
    let secs = value
        .checked_mul(multiplier)
        .ok_or(ServiceError::IntervalOverflow)?;
    Ok(Duration::from_secs(secs))
}

// ---------------------------------------------------------------------
// Windows: real Service Control Manager integration.
// ---------------------------------------------------------------------

/// The one service type this binary ever registers as: a normal standalone
/// process (not a shared/driver service).
#[cfg(windows)]
const SERVICE_TYPE: windows_service::service::ServiceType =
    windows_service::service::ServiceType::OWN_PROCESS;

/// Poll spacing/attempts `restart` uses while waiting for a running service
/// to reach `Stopped` before requesting the next start (the Win32 API gives
/// no "wait for stop" primitive beyond polling `query_status`).
#[cfg(windows)]
const RESTART_POLL_ATTEMPTS: u32 = 30;
#[cfg(windows)]
const RESTART_POLL_INTERVAL: Duration = Duration::from_millis(500);

/// Holds the [`ServiceRunArgs`] `service run`'s CLI handler received, for
/// [`my_service_main`] to pick up. `define_windows_service!` generates a
/// plain `fn(Vec<OsString>) `service entry point that cannot capture a
/// closure, and the argv the SCM actually delivers to it is a *different*,
/// usually-empty list (the `StartService` argv, not the `CreateProcess`
/// command line) — see the module doc. `run` sets this immediately before
/// handing control to the dispatcher, which only then can invoke
/// `my_service_main` on a fresh thread, so the write always happens-before
/// the read.
#[cfg(windows)]
static RUN_ARGS: std::sync::OnceLock<ServiceRunArgs> = std::sync::OnceLock::new();

#[cfg(windows)]
windows_service::define_windows_service!(ffi_service_main, my_service_main);

/// Installs (registers) this binary as the `BusyNCRClient` Windows service,
/// configured to auto-start and launch with `service run` plus `run_args`.
#[cfg(windows)]
pub fn install(run_args: &ServiceRunArgs) -> Result<(), ServiceError> {
    use windows_service::service::{ServiceErrorControl, ServiceInfo, ServiceStartType};
    use windows_service::service_manager::{ServiceManager, ServiceManagerAccess};

    let executable_path = std::env::current_exe().map_err(ServiceError::ExecutablePath)?;

    let service_manager = ServiceManager::local_computer(
        None::<&str>,
        ServiceManagerAccess::CONNECT | ServiceManagerAccess::CREATE_SERVICE,
    )?;
    let service_info = ServiceInfo {
        name: OsString::from(SERVICE_NAME),
        display_name: OsString::from(SERVICE_DISPLAY_NAME),
        service_type: SERVICE_TYPE,
        start_type: ServiceStartType::AutoStart,
        error_control: ServiceErrorControl::Normal,
        executable_path,
        launch_arguments: launch_argv(run_args),
        dependencies: vec![],
        account_name: None, // LocalSystem
        account_password: None,
    };
    let service = service_manager.create_service(
        &service_info,
        windows_service::service::ServiceAccess::CHANGE_CONFIG,
    )?;
    service.set_description(
        "BusyNCR scheduled backup client (PRD FR8): runs the jittered \
         backup schedule (PRD §3.5) as a Windows service.",
    )?;
    Ok(())
}

#[cfg(not(windows))]
/// Windows-only; see [`ServiceError::UnsupportedPlatform`].
pub fn install(_run_args: &ServiceRunArgs) -> Result<(), ServiceError> {
    Err(ServiceError::UnsupportedPlatform)
}

/// Unregisters the `BusyNCRClient` service (stopping it first if running).
#[cfg(windows)]
pub fn uninstall() -> Result<(), ServiceError> {
    use windows_service::service::{ServiceAccess, ServiceState};
    use windows_service::service_manager::{ServiceManager, ServiceManagerAccess};

    let service_manager =
        ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)?;
    let service = service_manager.open_service(
        SERVICE_NAME,
        ServiceAccess::QUERY_STATUS | ServiceAccess::STOP | ServiceAccess::DELETE,
    )?;
    if service.query_status()?.current_state != ServiceState::Stopped {
        service.stop()?;
    }
    service.delete()?;
    Ok(())
}

#[cfg(not(windows))]
/// Windows-only; see [`ServiceError::UnsupportedPlatform`].
pub fn uninstall() -> Result<(), ServiceError> {
    Err(ServiceError::UnsupportedPlatform)
}

/// Asks the SCM to start the installed `BusyNCRClient` service. Returns as
/// soon as the start request is accepted — it does not wait for the service
/// to report `Running`.
#[cfg(windows)]
pub fn start() -> Result<(), ServiceError> {
    use windows_service::service::ServiceAccess;
    use windows_service::service_manager::{ServiceManager, ServiceManagerAccess};

    let service_manager =
        ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)?;
    let service = service_manager.open_service(SERVICE_NAME, ServiceAccess::START)?;
    service.start(&[] as &[&std::ffi::OsStr])?;
    Ok(())
}

#[cfg(not(windows))]
/// Windows-only; see [`ServiceError::UnsupportedPlatform`].
pub fn start() -> Result<(), ServiceError> {
    Err(ServiceError::UnsupportedPlatform)
}

/// Asks the SCM to stop the running `BusyNCRClient` service.
#[cfg(windows)]
pub fn stop() -> Result<(), ServiceError> {
    use windows_service::service::ServiceAccess;
    use windows_service::service_manager::{ServiceManager, ServiceManagerAccess};

    let service_manager =
        ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)?;
    let service = service_manager.open_service(SERVICE_NAME, ServiceAccess::STOP)?;
    service.stop()?;
    Ok(())
}

#[cfg(not(windows))]
/// Windows-only; see [`ServiceError::UnsupportedPlatform`].
pub fn stop() -> Result<(), ServiceError> {
    Err(ServiceError::UnsupportedPlatform)
}

/// Stops (if running) then starts the `BusyNCRClient` service, polling for
/// the stop to complete first (bounded by [`RESTART_POLL_ATTEMPTS`] ×
/// [`RESTART_POLL_INTERVAL`] — the Win32 API has no "wait for stop"
/// primitive beyond polling).
#[cfg(windows)]
pub fn restart() -> Result<(), ServiceError> {
    use windows_service::service::{ServiceAccess, ServiceState};
    use windows_service::service_manager::{ServiceManager, ServiceManagerAccess};

    let service_manager =
        ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)?;
    let service = service_manager.open_service(
        SERVICE_NAME,
        ServiceAccess::QUERY_STATUS | ServiceAccess::START | ServiceAccess::STOP,
    )?;
    if service.query_status()?.current_state != ServiceState::Stopped {
        service.stop()?;
        for _ in 0..RESTART_POLL_ATTEMPTS {
            if service.query_status()?.current_state == ServiceState::Stopped {
                break;
            }
            std::thread::sleep(RESTART_POLL_INTERVAL);
        }
    }
    service.start(&[] as &[&std::ffi::OsStr])?;
    Ok(())
}

#[cfg(not(windows))]
/// Windows-only; see [`ServiceError::UnsupportedPlatform`].
pub fn restart() -> Result<(), ServiceError> {
    Err(ServiceError::UnsupportedPlatform)
}

/// The `service run` entry point: stashes `run_args` for [`my_service_main`]
/// and hands this thread to the SCM dispatcher, which blocks it until the
/// service is asked to stop.
#[cfg(windows)]
pub fn run(run_args: ServiceRunArgs) -> Result<(), ServiceError> {
    // `run` is only ever reached once per process (one CLI invocation parses
    // exactly one subcommand), so `set` cannot legitimately fail; ignoring a
    // hypothetical second write rather than panicking keeps this a library
    // path with no panics, per AGENTS.md.
    let _ = RUN_ARGS.set(run_args);
    windows_service::service_dispatcher::start(SERVICE_NAME, ffi_service_main)?;
    Ok(())
}

#[cfg(not(windows))]
/// Windows-only; see [`ServiceError::UnsupportedPlatform`].
pub fn run(_run_args: ServiceRunArgs) -> Result<(), ServiceError> {
    Err(ServiceError::UnsupportedPlatform)
}

/// Service entry function the SCM calls on its own background thread once
/// [`run`] hands control to the dispatcher. There is no stdout/stderr at
/// this point (PRD §3.6 "event-log logging" is exactly why) — any failure is
/// reported to the Windows Event Log instead of propagated, matching the
/// `windows-service` crate's own documented pattern.
#[cfg(windows)]
fn my_service_main(_arguments: Vec<OsString>) {
    if let Err(err) = run_service_body() {
        eventlog::log_error(&format!(
            "busyncr-client service exited with an error: {err}"
        ));
    }
}

#[cfg(windows)]
fn run_service_body() -> Result<(), ServiceError> {
    use windows_service::service::{
        ServiceControl, ServiceControlAccept, ServiceExitCode, ServiceState, ServiceStatus,
    };
    use windows_service::service_control_handler::{self, ServiceControlHandlerResult};

    let run_args = RUN_ARGS.get().ok_or(ServiceError::NotConfigured)?.clone();

    let (stop_tx, stop_rx) = std::sync::mpsc::channel::<()>();
    let event_handler = move |control_event| -> ServiceControlHandlerResult {
        match control_event {
            ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
            ServiceControl::Stop => {
                let _ = stop_tx.send(());
                ServiceControlHandlerResult::NoError
            }
            _ => ServiceControlHandlerResult::NotImplemented,
        }
    };
    let status_handle = service_control_handler::register(SERVICE_NAME, event_handler)?;

    let report = |current_state, controls_accepted, exit_code| {
        status_handle.set_service_status(ServiceStatus {
            service_type: SERVICE_TYPE,
            current_state,
            controls_accepted,
            exit_code,
            checkpoint: 0,
            wait_hint: Duration::default(),
            process_id: None,
        })
    };
    report(
        ServiceState::StartPending,
        ServiceControlAccept::empty(),
        ServiceExitCode::Win32(0),
    )?;

    // Resolve config/chunker/schedule before declaring Running: a bad config
    // should surface as a clean, immediate Stopped rather than a service
    // that appears to run but can never back anything up.
    let config = crate::config::ClientConfig::load(&run_args.config)?;
    let chunker = config.chunker(run_args.default_chunking)?;
    let interval = parse_interval(&run_args.interval)?;
    let schedule = busyncr_core::scheduler::SchedulePolicy::new(interval, run_args.jitter)?;

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(ServiceError::Runtime)?;

    report(
        ServiceState::Running,
        ServiceControlAccept::STOP,
        ServiceExitCode::Win32(0),
    )?;
    eventlog::log_info("busyncr-client service started");

    // Bridge the control handler's synchronous Stop signal into the async
    // shutdown future `run_scheduler` expects.
    let (async_stop_tx, async_stop_rx) = tokio::sync::oneshot::channel::<()>();
    std::thread::spawn(move || {
        let _ = stop_rx.recv();
        let _ = async_stop_tx.send(());
    });

    let request = crate::run::RunRequest {
        daemon_url: &config.daemon,
        state_dir: &run_args.state,
        roots: &config.folders,
        chunker,
        compression: config.compression,
        schedule,
    };

    runtime.block_on(async {
        crate::run::run_scheduler(
            &request,
            &crate::run::SystemClock,
            &mut rand::rng(),
            Box::pin(async move {
                let _ = async_stop_rx.await;
            }),
            |tick| match &tick.result {
                Ok(report) => eventlog::log_info(&format!(
                    "snapshot {} stored: {} file(s), {} chunk(s) shipped \
                     ({} bytes), {} deduplicated",
                    report.snapshot_id,
                    report.files,
                    report.chunks_uploaded,
                    report.upload_bytes,
                    report.chunks_deduped
                )),
                Err(err) => eventlog::log_error(&format!("scheduled backup attempt failed: {err}")),
            },
        )
        .await;
    });

    eventlog::log_info("busyncr-client service stopping");
    report(
        ServiceState::Stopped,
        ServiceControlAccept::empty(),
        ServiceExitCode::Win32(0),
    )?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    /// Mirrors `main.rs`'s real nesting — `busyncr-client service <action>`
    /// — so a round-trip through this test double exercises the exact same
    /// two levels of subcommand parsing [`launch_argv`]'s output has to
    /// survive when the SCM actually invokes this binary.
    #[derive(Parser)]
    struct TestCli {
        #[command(subcommand)]
        top: TopCommand,
    }

    #[derive(clap::Subcommand)]
    enum TopCommand {
        Service {
            #[command(subcommand)]
            action: ServiceAction,
        },
    }

    fn full_argv<'a>(rest: impl IntoIterator<Item = &'a str>) -> Vec<String> {
        std::iter::once("busyncr-client-test".to_string())
            .chain(rest.into_iter().map(str::to_string))
            .collect()
    }

    /// Parses `argv` (already including the leading `service` verb, as
    /// [`launch_argv`] produces) and returns the [`ServiceAction`] inside.
    fn parse_service_action(argv: &[String]) -> ServiceAction {
        let parsed = TestCli::try_parse_from(argv).expect("round-trip argv must reparse");
        let TopCommand::Service { action } = parsed.top;
        action
    }

    #[test]
    fn fr8_service_run_launch_argv_round_trips_through_clap() {
        let original = ServiceRunArgs {
            config: PathBuf::from("/etc/busyncr/client.toml"),
            state: PathBuf::from("/var/lib/busyncr/state"),
            default_chunking: false,
            interval: "90m".to_string(),
            jitter: 0.25,
        };
        let argv = launch_argv(&original);
        let mut argv_strings: Vec<String> = argv
            .into_iter()
            .map(|s| s.to_string_lossy().into_owned())
            .collect();
        let mut full = full_argv([]);
        full.append(&mut argv_strings);

        match parse_service_action(&full) {
            ServiceAction::Run(run_args) => assert_eq!(run_args, original),
            other => panic!("expected ServiceAction::Run, got {other:?}"),
        }
    }

    #[test]
    fn fr8_service_run_launch_argv_round_trips_with_default_chunking_flag() {
        let original = ServiceRunArgs {
            config: PathBuf::from("C:/ProgramData/BusyNCR/client.toml"),
            state: PathBuf::from("C:/ProgramData/BusyNCR/state"),
            default_chunking: true,
            interval: "3h".to_string(),
            jitter: 0.1,
        };
        let argv = launch_argv(&original);
        let mut argv_strings: Vec<String> = argv
            .into_iter()
            .map(|s| s.to_string_lossy().into_owned())
            .collect();
        let mut full = full_argv([]);
        full.append(&mut argv_strings);

        match parse_service_action(&full) {
            ServiceAction::Run(run_args) => assert_eq!(run_args, original),
            other => panic!("expected ServiceAction::Run, got {other:?}"),
        }
    }

    #[test]
    fn fr8_service_install_args_parse_independently_of_run() {
        let full = full_argv([
            "service",
            "install",
            "--config",
            "cfg.toml",
            "--state",
            "state-dir",
            "--interval",
            "45m",
            "--jitter",
            "0.2",
        ]);
        match parse_service_action(&full) {
            ServiceAction::Install(run_args) => {
                assert_eq!(run_args.config, PathBuf::from("cfg.toml"));
                assert_eq!(run_args.state, PathBuf::from("state-dir"));
                assert_eq!(run_args.interval, "45m");
                assert_eq!(run_args.jitter, 0.2);
                assert!(!run_args.default_chunking);
            }
            other => panic!("expected ServiceAction::Install, got {other:?}"),
        }
    }

    #[test]
    fn fr8_service_action_no_args_subcommands_parse() {
        for verb in ["uninstall", "start", "stop", "restart"] {
            let full = full_argv(["service", verb]);
            TestCli::try_parse_from(&full)
                .unwrap_or_else(|e| panic!("{verb} must parse with no extra args: {e}"));
        }
    }

    #[test]
    fn fr8_parse_interval_understands_suffixes_and_rejects_garbage() {
        assert_eq!(parse_interval("3h").unwrap(), Duration::from_secs(3 * 3600));
        assert_eq!(parse_interval("90m").unwrap(), Duration::from_secs(90 * 60));
        assert_eq!(parse_interval("5400s").unwrap(), Duration::from_secs(5400));
        assert_eq!(parse_interval("120").unwrap(), Duration::from_secs(120));
        assert!(parse_interval("").is_err());
        assert!(parse_interval("abc").is_err());
        assert!(matches!(
            parse_interval(""),
            Err(ServiceError::BadInterval(_))
        ));
    }

    #[test]
    fn fr8_parse_interval_rejects_overflow() {
        let huge = format!("{}h", u64::MAX);
        assert!(matches!(
            parse_interval(&huge),
            Err(ServiceError::IntervalOverflow)
        ));
    }

    #[cfg(not(windows))]
    #[test]
    fn fr8_non_windows_service_actions_fail_cleanly() {
        let args = ServiceRunArgs {
            config: PathBuf::from("x"),
            state: PathBuf::from("y"),
            default_chunking: false,
            interval: "3h".to_string(),
            jitter: 0.1,
        };
        assert!(matches!(
            install(&args),
            Err(ServiceError::UnsupportedPlatform)
        ));
        assert!(matches!(
            uninstall(),
            Err(ServiceError::UnsupportedPlatform)
        ));
        assert!(matches!(start(), Err(ServiceError::UnsupportedPlatform)));
        assert!(matches!(stop(), Err(ServiceError::UnsupportedPlatform)));
        assert!(matches!(restart(), Err(ServiceError::UnsupportedPlatform)));
        assert!(matches!(run(args), Err(ServiceError::UnsupportedPlatform)));
    }
}
