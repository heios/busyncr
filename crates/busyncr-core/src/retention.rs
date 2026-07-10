//! Retention grid (PRD §3.5): the pure, deterministic thinning plan.
//!
//! Snapshots are thinned by an *exponential grid*. A snapshot's age (relative
//! to an injected `now`) selects a **tier**; each tier keeps at most one
//! snapshot per fixed-width **cell** window, dropping the rest. The defaults
//! (configurable) are:
//!
//! | age                | keep one per |
//! |--------------------|--------------|
//! | `< 24 h`           | 3 h          |
//! | `24 h .. 4 d`      | 24 h         |
//! | `4 d .. 16 d`      | 4 d          |
//! | `>= 16 d`          | 16 d         |
//!
//! Cells are aligned to the Unix epoch: a snapshot at time `t` falls in cell
//! `floor(t / cell_width)` of its tier. As snapshots age across tier
//! boundaries their cells widen, so previously distinct snapshots collide in
//! one cell and all but the newest are pruned — the "keep the newest in each
//! grid cell" rule from PRD §3.5. Epoch alignment (rather than aligning to
//! `now`) makes the plan stable: the same snapshot lands in the same cell
//! regardless of when the plan is computed, so repeated prunes converge
//! instead of churning.
//!
//! This module is pure: it reads no clock and no entropy. `now` and the
//! snapshot times are injected by the caller (the daemon derives snapshot
//! times from their ULID timestamps), which is what makes the 60-day
//! simulation in the tests deterministic (project rule; FR5a).

use std::collections::HashMap;
use std::time::Duration;

/// Error building a [`RetentionPolicy`] from caller-supplied tiers.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum RetentionError {
    /// A policy needs at least one tier.
    #[error("a retention policy needs at least one tier")]
    NoTiers,
    /// A tier's cell width was zero (every snapshot would collide).
    #[error("tier {index} has a zero-width cell")]
    ZeroCell {
        /// Zero-based index of the offending tier.
        index: usize,
    },
    /// Tiers must be ordered by ascending `max_age`.
    #[error("tier {index} has a smaller max_age than the tier before it")]
    Unordered {
        /// Zero-based index of the out-of-order tier.
        index: usize,
    },
}

/// One tier of the retention grid: snapshots younger than [`Tier::max_age`]
/// are thinned to one per [`Tier::cell`] window.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Tier {
    max_age: Duration,
    cell: Duration,
}

impl Tier {
    /// A tier covering ages below `max_age`, keeping one snapshot per `cell`.
    ///
    /// The last tier of a policy is the catch-all for the oldest snapshots;
    /// give it `Duration::MAX` so no snapshot falls past it.
    #[must_use]
    pub const fn new(max_age: Duration, cell: Duration) -> Self {
        Self { max_age, cell }
    }

    /// Upper age bound (exclusive) for snapshots handled by this tier.
    #[must_use]
    pub const fn max_age(&self) -> Duration {
        self.max_age
    }

    /// Width of this tier's grid cell (one survivor per cell).
    #[must_use]
    pub const fn cell(&self) -> Duration {
        self.cell
    }

    /// Cell width in whole milliseconds, clamped to `1..=i64::MAX` so cell
    /// arithmetic never divides by zero or overflows `i64`.
    fn cell_ms(&self) -> i64 {
        i64::try_from(self.cell.as_millis())
            .unwrap_or(i64::MAX)
            .max(1)
    }
}

/// An ordered set of [`Tier`]s defining a retention grid (PRD §3.5).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RetentionPolicy {
    tiers: Vec<Tier>,
}

/// Three hours.
const THREE_HOURS: Duration = Duration::from_secs(3 * 60 * 60);
/// One day.
const ONE_DAY: Duration = Duration::from_secs(24 * 60 * 60);
/// Four days.
const FOUR_DAYS: Duration = Duration::from_secs(4 * 24 * 60 * 60);
/// Sixteen days.
const SIXTEEN_DAYS: Duration = Duration::from_secs(16 * 24 * 60 * 60);

impl RetentionPolicy {
    /// The PRD §3.5 default grid: 3 h / 24 h / 4 d / 16 d cells across the
    /// four age tiers.
    #[must_use]
    pub fn default_grid() -> Self {
        Self {
            tiers: vec![
                Tier::new(ONE_DAY, THREE_HOURS),
                Tier::new(FOUR_DAYS, ONE_DAY),
                Tier::new(SIXTEEN_DAYS, FOUR_DAYS),
                Tier::new(Duration::MAX, SIXTEEN_DAYS),
            ],
        }
    }

    /// Builds a policy from caller-supplied tiers (the "configurable" part of
    /// PRD §3.5).
    ///
    /// # Errors
    ///
    /// [`RetentionError::NoTiers`] if `tiers` is empty,
    /// [`RetentionError::ZeroCell`] if any tier has a zero-width cell, or
    /// [`RetentionError::Unordered`] if `max_age` is not non-decreasing.
    pub fn from_tiers(tiers: Vec<Tier>) -> Result<Self, RetentionError> {
        if tiers.is_empty() {
            return Err(RetentionError::NoTiers);
        }
        for (index, tier) in tiers.iter().enumerate() {
            if tier.cell.is_zero() {
                return Err(RetentionError::ZeroCell { index });
            }
            if index > 0 && tier.max_age < tiers[index - 1].max_age {
                return Err(RetentionError::Unordered { index });
            }
        }
        Ok(Self { tiers })
    }

    /// The tiers, in age order.
    #[must_use]
    pub fn tiers(&self) -> &[Tier] {
        &self.tiers
    }

    /// Selects the tier (and its index) for a snapshot of the given `age`:
    /// the first tier whose `max_age` exceeds `age`, else the last tier (the
    /// oldest-snapshot catch-all).
    fn tier_for(&self, age: Duration) -> (usize, &Tier) {
        for (index, tier) in self.tiers.iter().enumerate() {
            if age < tier.max_age {
                return (index, tier);
            }
        }
        // `from_tiers`/`default_grid` guarantee a non-empty tier list.
        let last = self.tiers.len() - 1;
        (last, &self.tiers[last])
    }
}

/// The outcome of [`plan`]: which snapshots survive and which are pruned,
/// each preserving the input order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Plan<T> {
    /// Snapshots to retain (the newest in each occupied grid cell).
    pub keep: Vec<T>,
    /// Snapshots to prune (older collisions within a cell).
    pub drop: Vec<T>,
}

/// Computes the retention plan for `snapshots` at instant `now_ms`.
///
/// Each snapshot is `(time_ms, id)` — its time in milliseconds since the Unix
/// epoch and a caller-chosen identity (e.g. a ULID) returned verbatim in the
/// plan. Snapshots dated after `now_ms` are treated as age zero (youngest
/// tier). Within each (tier, cell) the newest snapshot is kept; on identical
/// timestamps the one appearing later in `snapshots` wins. An empty policy
/// (no tiers) keeps everything.
///
/// The plan is a pure function of its inputs — no clock, no randomness.
#[must_use]
pub fn plan<T: Copy>(now_ms: i64, snapshots: &[(i64, T)], policy: &RetentionPolicy) -> Plan<T> {
    if policy.tiers.is_empty() {
        return Plan {
            keep: snapshots.iter().map(|&(_, id)| id).collect(),
            drop: Vec::new(),
        };
    }

    // (tier index, cell index) -> (best time so far, input index of the
    // survivor). The survivor is the newest snapshot in the cell.
    let mut best: HashMap<(usize, i64), (i64, usize)> = HashMap::new();
    for (idx, &(time_ms, _)) in snapshots.iter().enumerate() {
        let age_ms = now_ms.saturating_sub(time_ms).max(0);
        // `age_ms >= 0`, so the `as u64` cast is lossless.
        let age = Duration::from_millis(age_ms as u64);
        let (tier_index, tier) = policy.tier_for(age);
        let cell = time_ms.div_euclid(tier.cell_ms());
        let key = (tier_index, cell);
        match best.get(&key) {
            // A strictly-newer survivor already holds the cell; keep it.
            Some(&(best_time, _)) if best_time > time_ms => {}
            // Otherwise this snapshot wins the cell (newer, or equal time in
            // which case the later input entry takes it).
            _ => {
                best.insert(key, (time_ms, idx));
            }
        }
    }

    let survivors: std::collections::HashSet<usize> = best.values().map(|&(_, idx)| idx).collect();
    let mut keep = Vec::with_capacity(survivors.len());
    let mut drop = Vec::with_capacity(snapshots.len() - survivors.len());
    for (idx, &(_, id)) in snapshots.iter().enumerate() {
        if survivors.contains(&idx) {
            keep.push(id);
        } else {
            drop.push(id);
        }
    }
    Plan { keep, drop }
}

#[cfg(test)]
mod tests {
    use super::*;

    const HOUR_MS: i64 = 60 * 60 * 1000;
    const DAY_MS: i64 = 24 * HOUR_MS;

    #[test]
    fn from_tiers_validates() {
        assert_eq!(
            RetentionPolicy::from_tiers(vec![]),
            Err(RetentionError::NoTiers)
        );
        assert_eq!(
            RetentionPolicy::from_tiers(vec![Tier::new(ONE_DAY, Duration::ZERO)]),
            Err(RetentionError::ZeroCell { index: 0 })
        );
        assert_eq!(
            RetentionPolicy::from_tiers(vec![
                Tier::new(FOUR_DAYS, ONE_DAY),
                Tier::new(ONE_DAY, THREE_HOURS),
            ]),
            Err(RetentionError::Unordered { index: 1 })
        );
        assert!(RetentionPolicy::from_tiers(vec![Tier::new(ONE_DAY, THREE_HOURS)]).is_ok());
    }

    #[test]
    fn empty_input_and_single_snapshot() {
        let policy = RetentionPolicy::default_grid();
        let empty: [(i64, u32); 0] = [];
        assert_eq!(
            plan(0, &empty, &policy),
            Plan {
                keep: vec![],
                drop: vec![]
            }
        );
        assert_eq!(
            plan(1_000, &[(1_000, 7u32)], &policy),
            Plan {
                keep: vec![7],
                drop: vec![]
            }
        );
    }

    #[test]
    fn two_snapshots_in_one_cell_keep_the_newest() {
        // Two snapshots 1 h apart, both < 24 h old → same 3 h cell → the
        // newer survives, the older is pruned.
        let policy = RetentionPolicy::default_grid();
        let now = 100 * DAY_MS;
        // Place both inside one epoch-aligned 3 h window: 3 h cell index is
        // floor(t / 3h). now is a whole number of days = whole 3 h windows,
        // so [now-3h, now) is a single cell.
        let a = (now - 3 * HOUR_MS, 'a'); // start of the window
        let b = (now - 1, 'b'); // same window, newer
        let got = plan(now, &[a, b], &policy);
        assert_eq!(got.keep, vec!['b']);
        assert_eq!(got.drop, vec!['a']);
    }

    #[test]
    fn distinct_cells_all_survive() {
        // Snapshots exactly one cell apart never collide.
        let policy = RetentionPolicy::default_grid();
        let now = 100 * DAY_MS;
        let snaps = [(now, 0u32), (now - 3 * HOUR_MS, 1), (now - 6 * HOUR_MS, 2)];
        let got = plan(now, &snaps, &policy);
        assert_eq!(got.keep, vec![0, 1, 2]);
        assert!(got.drop.is_empty());
    }

    /// Builds 60 days of snapshots taken exactly every 3 hours (`t_k = k *
    /// 3h`, `now = t_last`) and asserts the surviving set against a fully
    /// hand-computed expectation (FR5a).
    #[test]
    fn fr5_sixty_day_three_hourly_simulation_matches_hand_computed_survivors() {
        let policy = RetentionPolicy::default_grid();
        let step = 3 * HOUR_MS;
        let last: i64 = 60 * 8; // 8 snapshots/day * 60 days = 480 (k = 0..=480)
        let snaps: Vec<(i64, i64)> = (0..=last).map(|k| (k * step, k)).collect();
        let now = last * step;

        let got = plan(now, &snaps, &policy);
        let mut kept: Vec<i64> = got.keep.clone();
        kept.sort_unstable();

        // Hand-computed survivors (derivation in the module/slice notes):
        //   tier <24h  (3h cell):  k = 473..=480               → 8
        //   tier 24h-4d (24h cell): k = 455, 463, 471, 472      → 4
        //   tier 4d-16d (4d cell):  k = 383, 415, 447, 448      → 4
        //   tier >=16d (16d cell):  k = 127, 255, 352           → 3
        let mut expected = vec![
            127, 255, 352, // >=16d tier
            383, 415, 447, 448, // 4d-16d tier
            455, 463, 471, 472, // 24h-4d tier
            473, 474, 475, 476, 477, 478, 479, 480, // <24h tier
        ];
        expected.sort_unstable();
        assert_eq!(kept, expected, "surviving snapshot set must match the grid");
        assert_eq!(got.keep.len() + got.drop.len(), snaps.len());
        // keep and drop partition the input with no overlap.
        for id in &got.drop {
            assert!(!got.keep.contains(id));
        }
    }

    #[test]
    fn plan_is_idempotent_over_survivors() {
        // Re-planning the survivors (at the same `now`) keeps all of them:
        // each already occupies its cell alone.
        let policy = RetentionPolicy::default_grid();
        let step = 3 * HOUR_MS;
        let last: i64 = 60 * 8;
        let snaps: Vec<(i64, i64)> = (0..=last).map(|k| (k * step, k)).collect();
        let now = last * step;

        let first = plan(now, &snaps, &policy);
        let survivor_pairs: Vec<(i64, i64)> = snaps
            .iter()
            .copied()
            .filter(|(_, id)| first.keep.contains(id))
            .collect();
        let second = plan(now, &survivor_pairs, &policy);
        assert_eq!(
            second.keep, first.keep,
            "planning survivors must keep them all"
        );
        assert!(second.drop.is_empty());
    }

    #[test]
    fn every_cell_keeps_exactly_one_survivor() {
        // Independent cross-check of the grid invariant: group the survivors
        // by (tier, cell) and assert each group has exactly one member, and
        // that every dropped snapshot shares a cell with a newer survivor.
        let policy = RetentionPolicy::default_grid();
        let step = 3 * HOUR_MS;
        let last: i64 = 60 * 8;
        let snaps: Vec<(i64, i64)> = (0..=last).map(|k| (k * step, k)).collect();
        let now = last * step;
        let got = plan(now, &snaps, &policy);

        let cell_of = |t: i64| -> (usize, i64) {
            let age = Duration::from_millis((now - t).max(0) as u64);
            let (ti, tier) = policy.tier_for(age);
            (ti, t.div_euclid(tier.cell_ms()))
        };

        let mut per_cell: HashMap<(usize, i64), Vec<i64>> = HashMap::new();
        for &id in &got.keep {
            per_cell.entry(cell_of(id * step)).or_default().push(id);
        }
        for (cell, members) in &per_cell {
            assert_eq!(members.len(), 1, "cell {cell:?} kept {members:?}");
        }
        // Every dropped snapshot's cell is occupied by a strictly newer kept
        // snapshot.
        for &dropped in &got.drop {
            let cell = cell_of(dropped * step);
            let survivor = per_cell.get(&cell).and_then(|v| v.first()).copied();
            assert!(
                survivor.is_some_and(|s| s > dropped),
                "dropped {dropped} must yield to a newer survivor in cell {cell:?}"
            );
        }
    }

    #[test]
    fn future_dated_snapshot_is_youngest_tier() {
        // A snapshot dated after `now` must not panic or land in a stale
        // tier; it is treated as age zero.
        let policy = RetentionPolicy::default_grid();
        let now = 10 * DAY_MS;
        let got = plan(now, &[(now + DAY_MS, 1u32), (now, 2u32)], &policy);
        // Both are "young"; different 3h cells (a day apart) → both kept.
        assert_eq!(got.keep.len(), 2);
        assert!(got.drop.is_empty());
    }
}
