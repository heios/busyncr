//! Backup scheduling policy (PRD §3.5, FR8): pure jitter arithmetic around a
//! fixed interval — "every 3 h, jittered" by default.
//!
//! This module reads no clock and no ambient entropy: the interval, jitter
//! fraction, and RNG are all injected by the caller (project determinism
//! rule), which is what makes the spacing tests deterministic. The actual
//! sleep/tick loop that drives backups on this schedule — and survives the
//! client process being restarted mid-wait (FR8) — lives in
//! `busyncr-client::run`; this crate has no async runtime dependency.

use std::time::Duration;

use rand::{Rng, RngExt};

/// Default schedule interval (PRD §3.5): back up every 3 hours.
pub const DEFAULT_INTERVAL: Duration = Duration::from_secs(3 * 60 * 60);
/// Default jitter fraction: the actual delay is `interval ± 10 %`.
pub const DEFAULT_JITTER: f64 = 0.1;

/// Error constructing a [`SchedulePolicy`].
#[derive(Debug, Clone, Copy, PartialEq, thiserror::Error)]
pub enum ScheduleError {
    /// The interval was zero — no meaningful schedule (would spin forever).
    #[error("schedule interval must be non-zero")]
    ZeroInterval,
    /// The jitter fraction was outside `[0, 1]`.
    #[error("jitter fraction {0} must be within [0, 1] (0 = none, 1 = ±100 %)")]
    JitterOutOfRange(f64),
}

/// A jittered fixed-interval schedule: "every `interval`, ± `jitter`
/// fraction" (PRD §3.5 default: every 3 h, ±10 %).
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct SchedulePolicy {
    interval: Duration,
    jitter: f64,
}

impl SchedulePolicy {
    /// Builds a policy from an interval and a jitter fraction in `[0, 1]`
    /// (e.g. `0.1` = the delay before each run is `interval ± 10 %`).
    ///
    /// # Errors
    ///
    /// [`ScheduleError::ZeroInterval`] if `interval` is zero;
    /// [`ScheduleError::JitterOutOfRange`] if `jitter` is outside `[0, 1]`.
    pub fn new(interval: Duration, jitter: f64) -> Result<Self, ScheduleError> {
        if interval.is_zero() {
            return Err(ScheduleError::ZeroInterval);
        }
        if !(0.0..=1.0).contains(&jitter) {
            return Err(ScheduleError::JitterOutOfRange(jitter));
        }
        Ok(Self { interval, jitter })
    }

    /// The PRD §3.5 default schedule: every 3 h, ±10 %.
    #[must_use]
    pub fn default_policy() -> Self {
        Self {
            interval: DEFAULT_INTERVAL,
            jitter: DEFAULT_JITTER,
        }
    }

    /// The nominal (unjittered) interval.
    #[must_use]
    pub const fn interval(&self) -> Duration {
        self.interval
    }

    /// The jitter fraction (`0` = none).
    #[must_use]
    pub const fn jitter(&self) -> f64 {
        self.jitter
    }

    /// Draws the next delay: `interval` perturbed by up to `± jitter`
    /// fraction, using the caller's injected RNG (project determinism rule —
    /// this function itself never reads ambient entropy; a seeded RNG in
    /// tests reproduces an exact delay sequence, `rand::rng()` at the CLI
    /// edge draws real jitter in production).
    ///
    /// Always returns a duration `>= 0`; the clamp only matters for a
    /// pathologically tiny `interval` combined with `jitter == 1.0`.
    pub fn next_delay(&self, rng: &mut impl Rng) -> Duration {
        if self.jitter == 0.0 {
            return self.interval;
        }
        let base = self.interval.as_secs_f64();
        let offset = rng.random_range(-self.jitter..=self.jitter);
        Duration::from_secs_f64((base * (1.0 + offset)).max(0.0))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::StdRng;
    use rand::SeedableRng;

    #[test]
    fn new_rejects_zero_interval_and_bad_jitter() {
        assert_eq!(
            SchedulePolicy::new(Duration::ZERO, 0.1),
            Err(ScheduleError::ZeroInterval)
        );
        assert_eq!(
            SchedulePolicy::new(Duration::from_secs(1), 1.5),
            Err(ScheduleError::JitterOutOfRange(1.5))
        );
        assert_eq!(
            SchedulePolicy::new(Duration::from_secs(1), -0.1),
            Err(ScheduleError::JitterOutOfRange(-0.1))
        );
        assert!(SchedulePolicy::new(Duration::from_secs(1), 0.0).is_ok());
        assert!(SchedulePolicy::new(Duration::from_secs(1), 1.0).is_ok());
    }

    #[test]
    fn default_policy_matches_prd_3_5() {
        let policy = SchedulePolicy::default_policy();
        assert_eq!(policy.interval(), Duration::from_secs(3 * 60 * 60));
        assert_eq!(policy.jitter(), 0.1);
    }

    #[test]
    fn zero_jitter_returns_the_exact_interval_every_time() {
        let policy = SchedulePolicy::new(Duration::from_secs(1000), 0.0).unwrap();
        let mut rng = StdRng::seed_from_u64(1);
        for _ in 0..50 {
            assert_eq!(policy.next_delay(&mut rng), Duration::from_secs(1000));
        }
    }

    /// The drawn delay always stays within `interval ± jitter` fraction —
    /// the property the client `run` loop's spacing relies on (FR8).
    #[test]
    fn next_delay_stays_within_the_jitter_band() {
        let interval = Duration::from_secs(3 * 60 * 60);
        let jitter = 0.1;
        let policy = SchedulePolicy::new(interval, jitter).unwrap();
        let lo = interval.mul_f64(1.0 - jitter);
        let hi = interval.mul_f64(1.0 + jitter);
        let mut rng = StdRng::seed_from_u64(99);
        let mut saw_below_nominal = false;
        let mut saw_above_nominal = false;
        for _ in 0..2000 {
            let delay = policy.next_delay(&mut rng);
            assert!(
                delay >= lo && delay <= hi,
                "delay {delay:?} escaped the ±{jitter} band [{lo:?}, {hi:?}]"
            );
            if delay < interval {
                saw_below_nominal = true;
            }
            if delay > interval {
                saw_above_nominal = true;
            }
        }
        assert!(
            saw_below_nominal,
            "jitter must be able to shorten the delay"
        );
        assert!(
            saw_above_nominal,
            "jitter must be able to lengthen the delay"
        );
    }

    #[test]
    fn next_delay_is_deterministic_given_the_same_seed() {
        let policy = SchedulePolicy::default_policy();
        let seq = |seed| {
            let mut rng = StdRng::seed_from_u64(seed);
            (0..10)
                .map(|_| policy.next_delay(&mut rng))
                .collect::<Vec<_>>()
        };
        assert_eq!(seq(7), seq(7), "same seed must reproduce the same delays");
        assert_ne!(
            seq(7),
            seq(8),
            "different seeds should (overwhelmingly likely) diverge"
        );
    }

    #[test]
    fn full_jitter_never_produces_a_negative_duration() {
        let policy = SchedulePolicy::new(Duration::from_nanos(1), 1.0).unwrap();
        let mut rng = StdRng::seed_from_u64(3);
        for _ in 0..200 {
            // Duration::from_secs_f64 would panic on a negative value; the
            // clamp inside next_delay must prevent that.
            let _ = policy.next_delay(&mut rng);
        }
    }
}
