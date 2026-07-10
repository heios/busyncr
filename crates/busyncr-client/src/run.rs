//! Scheduled backup loop (FR8, non-Windows part; PRD §3.5).
//!
//! [`run_scheduler`] drives repeated [`run_backup`] calls on a jittered
//! interval ([`SchedulePolicy`]) until a shutdown signal fires. Time is
//! injected through the [`Clock`] trait so tests can observe many scheduled
//! ticks without waiting real hours (project determinism rule) while still
//! exercising real backup I/O against a real daemon on every tick.
//!
//! **Restart robustness (FR8).** There is no persisted "last run" timestamp:
//! every call to [`run_scheduler`] performs its first backup immediately,
//! then falls into the wait/backup cadence. A client process that is killed
//! (crash, reboot, service restart) and started again therefore always
//! converges back onto its schedule on the very next `run` invocation rather
//! than needing to recover state — restarting *is* how the schedule resumes.
//! A failed attempt (daemon unreachable, daemon crashed mid-upload, ...) is
//! reported to the caller via `on_tick` but never stops the loop: the next
//! scheduled tick tries again, so a daemon outage is bridged automatically
//! once the daemon comes back.

use std::future::Future;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use busyncr_core::chunking::ChunkerConfig;
use busyncr_core::scheduler::SchedulePolicy;
use rand::CryptoRng;
use ulid::Ulid;

use crate::backup::{run_backup, BackupError, BackupReport, BackupRequest};

/// Abstraction over wall-clock time and sleeping so [`run_scheduler`] is
/// testable without waiting real hours. Production drives the loop with
/// [`SystemClock`]; tests inject a virtual clock that advances instantly
/// while real backup I/O against a real (in-process) daemon still takes real
/// (short) time — see `busyncr-client/tests/fr8_scheduler_restart.rs`.
pub trait Clock: Send + Sync {
    /// Current time, milliseconds since the Unix epoch.
    fn now_ms(&self) -> i64;

    /// Sleeps for `dur` (from this clock's perspective — a virtual clock may
    /// return far sooner in wall-clock terms).
    fn sleep(&self, dur: Duration) -> Pin<Box<dyn Future<Output = ()> + Send + '_>>;
}

/// The real wall clock: sleeps via `tokio::time::sleep`. What `busyncr-client
/// run` uses in production.
#[derive(Debug, Default, Clone, Copy)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now_ms(&self) -> i64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| i64::try_from(d.as_millis()).unwrap_or(i64::MAX))
            .unwrap_or(0)
    }

    fn sleep(&self, dur: Duration) -> Pin<Box<dyn Future<Output = ()> + Send + '_>> {
        Box::pin(tokio::time::sleep(dur))
    }
}

/// Everything [`run_scheduler`] needs for every scheduled backup attempt.
pub struct RunRequest<'a> {
    /// Daemon endpoint, e.g. `https://backup-server:47820`.
    pub daemon_url: &'a str,
    /// Client state directory (from `enroll`).
    pub state_dir: &'a Path,
    /// Folder trees to back up (from the TOML config).
    pub roots: &'a [PathBuf],
    /// The committed chunker configuration (PRD §3.7).
    pub chunker: ChunkerConfig,
    /// The jittered schedule to run backups on.
    pub schedule: SchedulePolicy,
}

/// One tick of the scheduler loop: when it started (per the injected
/// [`Clock`]) and what happened.
#[derive(Debug)]
pub struct Tick {
    /// Clock time the backup attempt started.
    pub started_at_ms: i64,
    /// The backup outcome. An error here does not stop the schedule (FR8):
    /// the next tick tries again regardless.
    pub result: Result<BackupReport, BackupError>,
}

/// Runs backups on `req.schedule` until `shutdown` resolves (FR8).
///
/// The first backup happens immediately; subsequent ones follow a jittered
/// delay ([`SchedulePolicy::next_delay`]). `rng` draws both that jitter and,
/// transitively, the AEAD nonces `run_backup` needs — one injected source
/// keeps a whole run reproducible from a single seed in tests.
///
/// `on_tick` observes every attempt (tests assert cadence and outcomes on
/// it; the CLI uses it to print progress); it never influences control flow
/// — a failed attempt is reported, not propagated, so a temporarily
/// unreachable or crashed daemon cannot wedge the schedule.
pub async fn run_scheduler<C, R>(
    req: &RunRequest<'_>,
    clock: &C,
    rng: &mut R,
    mut shutdown: impl Future<Output = ()> + Unpin,
    mut on_tick: impl FnMut(Tick),
) where
    C: Clock + ?Sized,
    R: CryptoRng,
{
    loop {
        let started_at_ms = clock.now_ms();
        let request = BackupRequest {
            daemon_url: req.daemon_url,
            state_dir: req.state_dir,
            roots: req.roots,
            chunker: req.chunker,
            snapshot_id: Ulid::new(),
            created_at: started_at_ms.div_euclid(1000),
        };
        let result = run_backup(&request, rng).await;
        on_tick(Tick {
            started_at_ms,
            result,
        });

        let delay = req.schedule.next_delay(rng);
        tokio::select! {
            () = &mut shutdown => break,
            () = clock.sleep(delay) => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicI64, Ordering};
    use std::sync::Mutex;

    /// A virtual clock: `sleep` never actually waits — it advances an
    /// internal counter by `dur` and returns immediately, so a scheduler
    /// test can observe thousands of "hours" of cadence in milliseconds of
    /// real time. `now_ms` reflects that virtual timeline.
    #[derive(Default)]
    struct VirtualClock {
        now_ms: AtomicI64,
        /// Every duration passed to `sleep`, in call order (assert on
        /// spacing without needing real waits).
        slept: Mutex<Vec<Duration>>,
    }

    impl Clock for VirtualClock {
        fn now_ms(&self) -> i64 {
            self.now_ms.load(Ordering::SeqCst)
        }

        fn sleep(&self, dur: Duration) -> Pin<Box<dyn Future<Output = ()> + Send + '_>> {
            // The side effect (and the readiness itself) is deferred inside
            // the returned future's poll, not run at construction time:
            // `tokio::select!` in `run_scheduler` constructs this future on
            // every iteration even on the one where `shutdown` also becomes
            // ready, and a future that already "happened" at construction
            // would over-count. The extra `yield_now` also guarantees this
            // future needs at least one more poll than an already-fired
            // `shutdown` receiver, so shutdown deterministically wins a
            // same-round race instead of the two racing on which gets
            // polled first.
            Box::pin(async move {
                tokio::task::yield_now().await;
                self.slept.lock().unwrap().push(dur);
                self.now_ms.fetch_add(
                    i64::try_from(dur.as_millis()).unwrap_or(i64::MAX),
                    Ordering::SeqCst,
                );
            })
        }
    }

    /// The loop performs its first attempt immediately (`sleep` is called
    /// zero times before the first tick), then waits between every
    /// subsequent pair — proving "restart resumes the schedule immediately"
    /// at the unit level without any network I/O.
    #[tokio::test]
    async fn first_tick_is_immediate_then_spaced_by_the_schedule() {
        use rand::rngs::StdRng;
        use rand::SeedableRng;

        let clock = VirtualClock::default();
        let schedule = SchedulePolicy::new(Duration::from_secs(3 * 60 * 60), 0.0).unwrap();
        let req = RunRequest {
            daemon_url: "https://unreachable.invalid:1",
            state_dir: Path::new("/nonexistent-state"),
            roots: &[],
            chunker: ChunkerConfig::with_target(4096).unwrap(),
            schedule,
        };
        let mut rng = StdRng::seed_from_u64(1);
        let ticks = Mutex::new(Vec::new());
        let mut remaining = 4;
        // `run_scheduler` has no built-in "run N times" mode (production
        // wants "forever until shutdown"), so drive it via a tick counter
        // that fires a cancel through a channel once satisfied.
        let (cancel_tx, cancel_rx) = tokio::sync::oneshot::channel::<()>();
        let mut cancel_tx = Some(cancel_tx);
        let shutdown: Pin<Box<dyn Future<Output = ()> + Send>> = Box::pin(async move {
            let _ = cancel_rx.await;
        });
        run_scheduler(&req, &clock, &mut rng, shutdown, |tick| {
            ticks.lock().unwrap().push(tick.started_at_ms);
            remaining -= 1;
            if remaining == 0 {
                if let Some(tx) = cancel_tx.take() {
                    let _ = tx.send(());
                }
            }
        })
        .await;

        let started = ticks.into_inner().unwrap();
        assert_eq!(started.len(), 4, "must have run exactly 4 ticks");
        assert_eq!(started[0], 0, "first tick must fire immediately");
        for pair in started.windows(2) {
            assert_eq!(
                pair[1] - pair[0],
                3 * 60 * 60 * 1000,
                "unjittered ticks must be spaced by exactly the interval"
            );
        }

        let slept = clock.slept.lock().unwrap();
        assert_eq!(slept.len(), 3, "one sleep between each pair of ticks");
    }
}
