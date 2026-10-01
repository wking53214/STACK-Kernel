//! The brief's design: the target follows a trailing window of observed
//! work times.
//!
//! Kept as a reference so its three leaks can be demonstrated and measured
//! (see the crate docs). Do not deploy it: a late release puts the raw,
//! secret-dependent work time on the wire. It still honours the anti-DoS
//! limits: the target never leaves `floor ..= cap`, the window is a
//! fixed-size ring allocated once, and the pad's admission limits apply.
//!
//! The percentile is read from a sorted copy of the window that is updated
//! in place on each observation (binary search, then one remove and one
//! insert), so the work under the pad's mutex is two `O(log n)` searches
//! and two `O(n)` memmoves of at most 512 KiB, never an `O(n log n)` sort.

use super::{
    epoch_bound_bits, nanos_u64, Changes, ControllerKind, ControllerStatus, MissRule, Snapshot,
    TargetController,
};
use crate::config::{ConfigError, NaiveConfig, WindowStatistic};
use std::time::{Duration, Instant};

/// Naive rolling target: `clamp(statistic(window) + margin, floor, cap)`.
///
/// Every observation can move the target by any amount, and a request
/// slower than the target is released at completion. Both are leaks; this
/// type exists to measure them. Use [`crate::EpochQuantizedTarget`] instead.
#[derive(Debug)]
pub struct NaiveRollingTarget {
    cfg: NaiveConfig,
    /// Ring of the last `cfg.window` work times, in nanoseconds.
    ring: Vec<u64>,
    /// Next slot to overwrite once the ring is full.
    head: usize,
    /// Sum of `ring`, for the mean.
    sum: u128,
    /// The values of `ring` in ascending order, allocated once with
    /// capacity `window`.
    sorted: Vec<u64>,
    target: Duration,
    increases_total: u64,
    decreases_total: u64,
    requests_total: u64,
}

impl NaiveRollingTarget {
    /// A controller with the given config. Allocates the window and its
    /// sorted copy once (at most 1 MiB, see [`crate::config::MAX_WINDOW`]).
    pub fn new(cfg: NaiveConfig) -> Result<Self, ConfigError> {
        cfg.validate()?;
        Ok(Self {
            ring: Vec::with_capacity(cfg.window),
            head: 0,
            sum: 0,
            sorted: Vec::with_capacity(cfg.window),
            target: cfg.initial_target,
            increases_total: 0,
            decreases_total: 0,
            requests_total: 0,
            cfg,
        })
    }

    /// The configuration in force.
    pub fn config(&self) -> &NaiveConfig {
        &self.cfg
    }

    /// The current target.
    pub fn target(&self) -> Duration {
        self.target
    }

    /// Observations currently in the window.
    pub fn window_len(&self) -> usize {
        self.ring.len()
    }

    fn push(&mut self, x: u64) {
        if self.ring.len() < self.cfg.window {
            self.ring.push(x);
        } else if let Some(slot) = self.ring.get_mut(self.head) {
            let old = *slot;
            self.sum = self.sum.saturating_sub(u128::from(old));
            *slot = x;
            self.head = (self.head + 1) % self.cfg.window;
            // `old` is in `sorted` (the two hold the same multiset), so the
            // search finds it; the guard keeps this total regardless.
            if let Ok(i) = self.sorted.binary_search(&old) {
                self.sorted.remove(i);
            }
        }
        self.sum = self.sum.saturating_add(u128::from(x));
        // Never grows past `window`: one value left above when full. The
        // insert position is `<= len`, so `insert` cannot panic.
        let at = self.sorted.partition_point(|&v| v < x);
        self.sorted.insert(at, x);
    }

    /// The window statistic in nanoseconds, or `None` when the window is
    /// empty.
    fn statistic(&self) -> Option<u128> {
        let n = self.ring.len();
        if n == 0 {
            return None;
        }
        match self.cfg.statistic {
            WindowStatistic::Mean => Some(self.sum / n as u128),
            WindowStatistic::Percentile { permille } => {
                // Nearest rank: ceil(p * n), 1-based.
                let rank = (usize::from(permille) * n).div_ceil(1_000).clamp(1, n);
                self.sorted.get(rank - 1).map(|&v| u128::from(v))
            }
        }
    }

    fn snapshot(&self) -> Snapshot {
        Snapshot {
            target: self.target,
            cap: self.cfg.cap,
            rule: MissRule::ReleaseLate,
        }
    }
}

impl TargetController for NaiveRollingTarget {
    fn kind(&self) -> ControllerKind {
        ControllerKind::Naive
    }

    fn admit(&mut self, _now: Instant) -> (Snapshot, Changes) {
        self.requests_total = self.requests_total.saturating_add(1);
        (self.snapshot(), Changes::default())
    }

    fn record(&mut self, _snapshot: &Snapshot, work: Duration, _now: Instant) -> Changes {
        self.push(nanos_u64(work));
        let Some(stat) = self.statistic() else {
            return Changes::default();
        };
        let lo = self.cfg.floor.as_nanos();
        let hi = self.cfg.cap.as_nanos();
        let want = stat
            .saturating_add(self.cfg.margin.as_nanos())
            .clamp(lo, hi);
        // `want <= cap <= MAX_TARGET`, so it fits in u64 nanoseconds.
        let new = Duration::from_nanos(u64::try_from(want).unwrap_or(u64::MAX));
        let mut ch = Changes::default();
        if new > self.target {
            ch.increases = 1;
            self.increases_total = self.increases_total.saturating_add(1);
        } else if new < self.target {
            ch.decreases = 1;
            self.decreases_total = self.decreases_total.saturating_add(1);
        }
        self.target = new;
        ch
    }

    fn status(&self) -> ControllerStatus {
        let changes = self.increases_total.saturating_add(self.decreases_total);
        ControllerStatus {
            kind: ControllerKind::Naive,
            target: self.target,
            level: None,
            cap: self.cfg.cap,
            changes_total: changes,
            increases_total: self.increases_total,
            decreases_total: self.decreases_total,
            rollbacks_total: 0,
            requests_total: self.requests_total,
            window_changes: changes,
            window_requests: self.requests_total,
            leak_bits: epoch_bound_bits(changes, self.requests_total),
            leak_budget_bits: None,
            lifetime_bits: epoch_bound_bits(changes, self.requests_total),
            lifetime_budget_bits: None,
            frozen: false,
            frozen_until_reset: false,
        }
    }

    /// The naive controller has no budget and no freeze; a reset only
    /// clears the window, returning the target to `initial_target`.
    fn operator_reset(&mut self, _now: Instant) -> Changes {
        self.ring.clear();
        self.sorted.clear();
        self.head = 0;
        self.sum = 0;
        let mut ch = Changes::default();
        let init = self.cfg.initial_target;
        if init > self.target {
            ch.increases = 1;
            self.increases_total = self.increases_total.saturating_add(1);
        } else if init < self.target {
            ch.decreases = 1;
            self.decreases_total = self.decreases_total.saturating_add(1);
        }
        self.target = init;
        ch
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    fn us(n: u64) -> Duration {
        Duration::from_micros(n)
    }

    #[test]
    fn mean_and_percentile() {
        let now = Instant::now();
        let mut m = NaiveRollingTarget::new(NaiveConfig {
            statistic: WindowStatistic::Mean,
            window: 4,
            margin: us(1),
            ..NaiveConfig::new(us(1_000))
        })
        .unwrap();
        let (s, _) = m.admit(now);
        for w in [10, 20, 30, 40] {
            m.record(&s, us(w), now);
        }
        assert_eq!(m.target(), us(26)); // mean 25 + 1
        m.record(&s, us(50), now); // window now 20,30,40,50
        assert_eq!(m.target(), us(36));

        let mut p = NaiveRollingTarget::new(NaiveConfig {
            statistic: WindowStatistic::Percentile { permille: 500 },
            window: 5,
            margin: Duration::ZERO,
            ..NaiveConfig::new(us(1_000))
        })
        .unwrap();
        for w in [50, 10, 40, 20, 30] {
            p.record(&s, us(w), now);
        }
        assert_eq!(p.target(), us(30)); // median of 10..50
    }

    #[test]
    fn clamps_to_floor_and_cap() {
        let now = Instant::now();
        let mut m = NaiveRollingTarget::new(NaiveConfig {
            statistic: WindowStatistic::Mean,
            window: 2,
            margin: Duration::ZERO,
            floor: us(5),
            ..NaiveConfig::new(us(100))
        })
        .unwrap();
        let (s, _) = m.admit(now);
        m.record(&s, us(1), now);
        m.record(&s, us(1), now);
        assert_eq!(m.target(), us(5));
        m.record(&s, Duration::from_secs(1_000), now);
        assert_eq!(m.target(), us(100));
    }
}
