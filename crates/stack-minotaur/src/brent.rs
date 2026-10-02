//! Brent's cycle detection, in a streaming form, for the degraded mode.
//!
//! Classic Brent's algorithm finds the cycle of an iterated function
//! `x, f(x), f(f(x)), ...` with O(1) memory: keep one saved value (the
//! "tortoise"), compare every new value to it, and move the tortoise up to
//! the current value each time a power-of-two number of steps passes without
//! a match. Once the window is at least as long as the cycle and the
//! tortoise sits inside the cycle, the tortoise comes round again after
//! exactly one period.
//!
//! Two changes make it fit a walk that is fed one step at a time and must
//! tolerate some legitimate revisits:
//!
//! 1. A match does not end the search. It counts as one revisit of the
//!    tortoise state, and the gap since the previous visit is kept as the
//!    candidate period. Only when the tortoise has been revisited more than
//!    the allowance does the detector report a loop. That is the exact
//!    set's rule, but applied only to whichever state is the tortoise.
//! 2. The window stops doubling at `max_cycle_period`. Past that it keeps
//!    re-anchoring every `max_cycle_period` steps, so memory and work per
//!    step stay constant forever, and any cycle up to that length is still
//!    found. Longer cycles are left to the untracked-transition and step
//!    budgets.
//!
//! Limitation: the tortoise moves at fixed offsets (1, 3, 7, 15, ... steps
//! after the first degraded step, then every `max_cycle_period` steps). A
//! walk that is not strictly periodic, such as one state repeated with a
//! fresh filler state between visits, can be lined up by the walker so the
//! tortoise always lands on a filler and never on the repeated state. The
//! recent-state table (`recent.rs`) runs beside this detector and counts
//! such repeats directly, so the degraded mode as a whole applies the exact
//! set's rule to any untracked state revisited at gaps below the table size.
//!
//! Memory: one fingerprint and four integers, whatever the walk does.

use crate::fingerprint::Fingerprint;

#[derive(Debug, Clone)]
pub(crate) struct Brent {
    tortoise: Option<Fingerprint>,
    /// Current window length (a power of two, capped).
    power: u64,
    /// Steps since the tortoise was set or last matched.
    lam: u64,
    /// Revisits of the current tortoise.
    hits: u32,
    max_power: u64,
}

impl Brent {
    pub(crate) fn new(max_cycle_period: u64) -> Self {
        Self {
            tortoise: None,
            power: 1,
            lam: 0,
            hits: 0,
            max_power: max_cycle_period.max(1),
        }
    }

    pub(crate) fn reset(&mut self) {
        self.tortoise = None;
        self.power = 1;
        self.lam = 0;
        self.hits = 0;
    }

    /// Feed one step. Returns the period when the tortoise state has been
    /// revisited more than `allowance` times.
    pub(crate) fn observe(&mut self, x: Fingerprint, allowance: u32) -> Option<u64> {
        let Some(t) = self.tortoise else {
            self.tortoise = Some(x);
            self.power = 1;
            self.lam = 0;
            self.hits = 0;
            return None;
        };
        self.lam = self.lam.saturating_add(1);
        if x == t {
            self.hits = self.hits.saturating_add(1);
            let gap = self.lam;
            self.lam = 0;
            if self.hits > allowance {
                return Some(gap);
            }
        } else if self.lam >= self.power {
            self.tortoise = Some(x);
            self.power = self.power.saturating_mul(2).min(self.max_power);
            self.lam = 0;
            self.hits = 0;
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fp(n: u64) -> Fingerprint {
        Fingerprint::of_bytes(&n.to_le_bytes())
    }

    fn first_detection(
        seq: impl Iterator<Item = u64>,
        cap: u64,
        allowance: u32,
    ) -> Option<(usize, u64)> {
        let mut b = Brent::new(cap);
        for (i, v) in seq.enumerate() {
            if let Some(p) = b.observe(fp(v), allowance) {
                return Some((i, p));
            }
        }
        None
    }

    #[test]
    fn finds_every_period_up_to_cap_after_a_tail() {
        for period in 1..=40u64 {
            let seq = (0..100u64)
                .map(|i| 1_000 + i)
                .chain((0..10_000u64).map(move |i| i % period));
            let got = first_detection(seq, 64, 2);
            assert_eq!(got.map(|g| g.1), Some(period), "period {period}");
        }
    }

    #[test]
    fn misses_cycles_longer_than_cap() {
        let seq = (0..10_000u64).map(|i| i % 100);
        assert_eq!(first_detection(seq, 32, 0), None);
    }

    #[test]
    fn non_repeating_walk_never_trips() {
        assert_eq!(first_detection(0..50_000u64, 256, 0), None);
    }
}
