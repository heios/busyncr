//! Live progress reporting for `backup`/`restore` (FR-M1 M2.1/M2.2).
//!
//! [`ProgressReporter`] renders the running [`crate::backup::BackupReport`]
//! / [`crate::restore::RestoreReport`] snapshots that [`crate::backup`] and
//! [`crate::restore`]'s `*_with_progress` entry points hand it — the exact
//! same counters FR3's byte-accounting tests assert on, never a shadow copy
//! (M2.2) — to stderr, in one of three modes selected once at construction:
//!
//! - **quiet** (`--quiet`): nothing at all (errors still go through the
//!   ordinary `anyhow` error path in `main.rs`, untouched by this module).
//! - **NDJSON** (`--json-progress`): one JSON object per line, for
//!   scripting. Every event carries the *cumulative* counters, so consuming
//!   only the last line already gives the final tally, and the stream is
//!   monotone by construction (the counters it mirrors only grow).
//! - **human**: a carriage-return-updating single line when stderr is a
//!   TTY, or one full line per interval (log-safe, no `\r`) when it is not
//!   — detected once via [`std::io::IsTerminal`], never guessed from an
//!   environment variable.
//!
//! Rendering is throttled to at most once every [`MIN_INTERVAL`] except for
//! the final tick of a run, which always renders (so the last line/event
//! always reflects the true final counters, per FR-M1b).

use std::io::{IsTerminal, Write as _};
use std::time::{Duration, Instant};

use serde::Serialize;

use crate::backup::{BackupReport, BackupTotals};
use crate::restore::{RestoreReport, RestoreTotals};

/// Minimum wall-clock gap between two non-final renders.
const MIN_INTERVAL: Duration = Duration::from_millis(150);

/// How progress is rendered, resolved once at construction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Mode {
    /// `--quiet`: render nothing.
    Quiet,
    /// `--json-progress`: one NDJSON object per line.
    Json,
    /// Human-readable, `\r`-updating (stderr is a TTY).
    Tty,
    /// Human-readable, one line per interval (stderr is not a TTY).
    Plain,
}

/// Renders live `backup`/`restore` progress to stderr (FR-M1 M2.1).
pub struct ProgressReporter {
    mode: Mode,
    start: Instant,
    last_render: Option<Instant>,
    /// Length of the last `\r`-line written, so the next one can pad over
    /// any leftover tail from a longer previous line.
    last_tty_len: usize,
    seq: u64,
}

impl ProgressReporter {
    /// Builds a reporter. `quiet` wins over `json` if both are set (M2.1:
    /// "--quiet suppresses" is unconditional). Otherwise picks NDJSON, or
    /// human rendering with the TTY-vs-log-safe format chosen from whether
    /// stderr is currently a terminal.
    #[must_use]
    pub fn new(quiet: bool, json: bool) -> Self {
        let mode = if quiet {
            Mode::Quiet
        } else if json {
            Mode::Json
        } else if std::io::stderr().is_terminal() {
            Mode::Tty
        } else {
            Mode::Plain
        };
        Self {
            mode,
            start: Instant::now(),
            last_render: None,
            last_tty_len: 0,
            seq: 0,
        }
    }

    /// Whether this render should actually happen: always for the final
    /// tick of a run, otherwise at most once per [`MIN_INTERVAL`].
    fn should_render(&mut self, final_tick: bool) -> bool {
        if final_tick {
            self.last_render = Some(Instant::now());
            return true;
        }
        match self.last_render {
            Some(t) if t.elapsed() < MIN_INTERVAL => false,
            _ => {
                self.last_render = Some(Instant::now());
                true
            }
        }
    }

    /// Renders one backup progress observation. `final_tick` marks the last
    /// call of a run (always rendered, bypassing throttling) so the final
    /// line/event exactly matches `report` (FR-M1b).
    pub fn backup_tick(&mut self, report: &BackupReport, totals: BackupTotals, final_tick: bool) {
        if self.mode == Mode::Quiet || !self.should_render(final_tick) {
            return;
        }
        let elapsed = self.start.elapsed();
        let mb_per_sec = mb_per_sec(report.upload_bytes, elapsed);
        let eta_secs = eta_secs(totals.total_files, report.files, elapsed);

        match self.mode {
            Mode::Json => {
                self.seq += 1;
                let event = BackupProgressEvent {
                    event: "backup_progress",
                    seq: self.seq,
                    elapsed_ms: elapsed.as_millis(),
                    files: report.files,
                    total_files: totals.total_files,
                    chunks_hashed: report.chunks_total,
                    chunks_to_ship: report.chunks_unique,
                    chunks_shipped: report.chunks_uploaded,
                    bytes_up: report.upload_bytes,
                    mb_per_sec,
                    eta_secs,
                };
                emit_json(&event);
            }
            Mode::Tty | Mode::Plain => {
                let line = format!(
                    "backup: {}/{} files, {} chunks hashed, {} to ship, {} shipped, \
                     {} bytes up, {mb_per_sec:.2} MB/s{}",
                    report.files,
                    totals.total_files,
                    report.chunks_total,
                    report.chunks_unique,
                    report.chunks_uploaded,
                    report.upload_bytes,
                    eta_suffix(eta_secs),
                );
                self.emit_line(&line, final_tick);
            }
            Mode::Quiet => unreachable!("returned above"),
        }
    }

    /// Renders one restore progress observation. `final_tick` marks the
    /// last call of a run.
    pub fn restore_tick(
        &mut self,
        report: &RestoreReport,
        totals: RestoreTotals,
        final_tick: bool,
    ) {
        if self.mode == Mode::Quiet || !self.should_render(final_tick) {
            return;
        }
        let elapsed = self.start.elapsed();
        let mb_per_sec = mb_per_sec(report.bytes, elapsed);
        let eta_secs = eta_secs(totals.total_bytes, report.bytes, elapsed);

        match self.mode {
            Mode::Json => {
                self.seq += 1;
                let event = RestoreProgressEvent {
                    event: "restore_progress",
                    seq: self.seq,
                    elapsed_ms: elapsed.as_millis(),
                    files: report.files,
                    total_files: totals.total_files,
                    chunks_fetched: report.chunks_fetched,
                    bytes_down: report.bytes,
                    total_bytes: totals.total_bytes,
                    mb_per_sec,
                    eta_secs,
                };
                emit_json(&event);
            }
            Mode::Tty | Mode::Plain => {
                let line = format!(
                    "restore: {}/{} files, {} chunks fetched, {}/{} bytes down, \
                     {mb_per_sec:.2} MB/s{}",
                    report.files,
                    totals.total_files,
                    report.chunks_fetched,
                    report.bytes,
                    totals.total_bytes,
                    eta_suffix(eta_secs),
                );
                self.emit_line(&line, final_tick);
            }
            Mode::Quiet => unreachable!("returned above"),
        }
    }

    /// Writes one human-readable line: `\r`-updating in place on a TTY (no
    /// trailing newline until [`Self::finish`], per M2.1's "carriage-return
    /// updating line"), one full line per call otherwise (log-safe).
    fn emit_line(&mut self, line: &str, final_tick: bool) {
        let mut stderr = std::io::stderr();
        if self.mode == Mode::Tty {
            let pad = self.last_tty_len.saturating_sub(line.len());
            let _ = write!(stderr, "\r{line}{}", " ".repeat(pad));
            self.last_tty_len = line.len();
            if final_tick {
                let _ = writeln!(stderr);
            }
            let _ = stderr.flush();
        } else {
            let _ = writeln!(stderr, "{line}");
        }
    }

    /// Ensures a `\r`-updating TTY line is left on its own line afterwards
    /// (a no-op if nothing was ever rendered, or the last render already was
    /// the final tick — [`Self::emit_line`] handles that case itself).
    pub fn finish(&mut self) {
        if self.mode == Mode::Tty && self.last_tty_len > 0 {
            let _ = writeln!(std::io::stderr());
            self.last_tty_len = 0;
        }
    }
}

/// One `--json-progress` NDJSON line for `backup`.
#[derive(Serialize)]
struct BackupProgressEvent {
    event: &'static str,
    seq: u64,
    elapsed_ms: u128,
    files: u64,
    total_files: u64,
    chunks_hashed: u64,
    chunks_to_ship: u64,
    chunks_shipped: u64,
    bytes_up: u64,
    mb_per_sec: f64,
    eta_secs: Option<f64>,
}

/// One `--json-progress` NDJSON line for `restore`.
#[derive(Serialize)]
struct RestoreProgressEvent {
    event: &'static str,
    seq: u64,
    elapsed_ms: u128,
    files: u64,
    total_files: u64,
    chunks_fetched: u64,
    bytes_down: u64,
    total_bytes: u64,
    mb_per_sec: f64,
    eta_secs: Option<f64>,
}

/// Serializes and writes one NDJSON line to stderr. Serialization of these
/// fixed, all-primitive event structs cannot fail; a write failure (closed
/// stderr) is not actionable here and is silently dropped, same as the
/// human-readable renderer.
fn emit_json<T: Serialize>(event: &T) {
    if let Ok(line) = serde_json::to_string(event) {
        let _ = writeln!(std::io::stderr(), "{line}");
    }
}

/// Throughput in MiB/s from a cumulative byte count and elapsed time; `0.0`
/// before any time has passed (avoids a division by zero on the very first
/// tick).
fn mb_per_sec(bytes: u64, elapsed: Duration) -> f64 {
    let secs = elapsed.as_secs_f64();
    if secs <= 0.0 {
        return 0.0;
    }
    (bytes as f64 / secs) / (1024.0 * 1024.0)
}

/// A coarse ETA (seconds) extrapolated from the current linear rate of
/// `done` out of `total` over `elapsed` — "coarse" per FR-M1 M2.1: no
/// smoothing, no lookahead, just `elapsed / done * (total - done)`. `None`
/// before there is a rate to extrapolate from (nothing done yet, or the
/// total is already known to be reached/exceeded).
fn eta_secs(total: u64, done: u64, elapsed: Duration) -> Option<f64> {
    if done == 0 || total <= done {
        return None;
    }
    let secs = elapsed.as_secs_f64();
    if secs <= 0.0 {
        return None;
    }
    let rate = done as f64 / secs;
    if rate <= 0.0 {
        return None;
    }
    Some((total - done) as f64 / rate)
}

/// Human-readable `", ETA ~<n>s"` suffix, or empty when no ETA is available.
fn eta_suffix(eta_secs: Option<f64>) -> String {
    match eta_secs {
        Some(secs) => format!(", ETA ~{}s", secs.round().max(0.0)),
        None => String::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mb_per_sec_is_zero_at_the_very_start() {
        assert_eq!(mb_per_sec(1_000_000, Duration::ZERO), 0.0);
    }

    #[test]
    fn eta_secs_is_none_until_something_is_done_or_total_is_reached() {
        assert_eq!(eta_secs(100, 0, Duration::from_secs(1)), None);
        assert_eq!(eta_secs(100, 100, Duration::from_secs(1)), None);
        assert_eq!(eta_secs(100, 150, Duration::from_secs(1)), None);
        assert!(eta_secs(100, 50, Duration::from_secs(1)).is_some());
    }

    #[test]
    fn eta_secs_extrapolates_linearly() {
        // 50/100 done in 10s -> rate 5/s -> 50 remaining -> ETA 10s.
        let eta = eta_secs(100, 50, Duration::from_secs(10)).unwrap();
        assert!((eta - 10.0).abs() < 1e-9, "got {eta}");
    }

    #[test]
    fn quiet_mode_never_renders() {
        let mut reporter = ProgressReporter::new(true, false);
        assert_eq!(reporter.mode, Mode::Quiet);
        // Rendering is a stderr side effect only; the meaningful assertion
        // here (and in the FR-M1b integration test) is that Mode::Quiet is
        // selected and every *_tick short-circuits on it before formatting
        // or writing anything.
        let report = BackupReport {
            snapshot_id: ulid::Ulid::nil(),
            files: 1,
            source_bytes: 1,
            chunks_total: 1,
            chunks_unique: 1,
            chunks_uploaded: 1,
            chunks_deduped: 0,
            upload_bytes: 1,
            manifest_bytes: 1,
            compression: Default::default(),
        };
        reporter.backup_tick(
            &report,
            BackupTotals {
                total_files: 1,
                total_bytes: 1,
            },
            true,
        );
        reporter.finish();
    }
}
