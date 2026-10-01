//! Epoch-quantized predictive target, after Askarov, Zhang and Myers
//! ("Predictive black-box mitigation of timing channels", CCS 2010) and
//! Zhang, Askarov and Myers ("Predictive mitigation of timing channels in
//! interactive systems", CCS 2011).
//!
//! Rules, in order of precedence:
//! 1. The target is always a public level `min(floor * 2^i, cap)`.
//! 2. Up: when a request's work runs past its admission target (a
//!    misprediction), the level rises to the smallest level that covers
//!    the work (each doubling counts as one change), and the current epoch
//!    is marked, which restarts the decrease clock: the earliest possible
//!    decrease is at the end of the next full epoch.
//! 3. Down: only at epoch boundaries on a wall-clock grid anchored at
//!    construction (public times, never observed durations), by exactly
//!    one level, and only if the epoch that just ended had at least one
//!    request, no misprediction, and a largest work time that the lower
//!    level would also have covered. Idle epochs hold the level.
//! 4. Leak budget. Every observable event that depends on work times is
//!    charged as a change, and the bound [`crate::epoch_bound_bits`] is
//!    computed over the charged changes of the current accounting window:
//!    * each level increase (one per doubling);
//!    * a miss that raises nothing (the level was already raised by a
//!      concurrent request, or the controller is frozen): one change,
//!      because its escalated release still says "this request was slow";
//!    * an overrun past the cap: `ceil(log2(k))` changes on top of any
//!      increase, where `k >= 2` is the cap multiple it is released on, so
//!      the release's `ceil(work / cap)` is charged even when frozen;
//!    * each decrease, except during warm-up (below).
//! 5. Warm-up. The starting level is public (the configured initial level,
//!    or the cap after an operator reset or a thaw). From there, a run of
//!    one-step decreases, one per non-idle epoch boundary, is the public
//!    default and is not charged. The run ends at the first miss (charged
//!    as above) or at the first non-idle boundary that holds a level above
//!    the floor; that hold is charged as one change. The run's whole
//!    outcome is where it stopped, one of at most `R + 1` positions among
//!    the window's requests, which one change already covers.
//! 6. Freeze. When the current window's charged bound reaches
//!    `leak_budget.bits`, the target rolls back to the cap and adaptation
//!    stops for the rest of that window (RETRY for the controller,
//!    rollback). At the next window boundary it thaws and warms up again
//!    from the cap. Every window's bound is added to a lifetime sum; when
//!    that sum reaches [`crate::EpochConfig::leak_lifetime_bits`] the
//!    freeze lasts until an operator reset (TERMINAL_BREACH for the
//!    controller, rollback). Requests are served throughout.

use super::{
    epoch_bound_bits, ladder, Changes, ControllerKind, ControllerStatus, MissRule, Snapshot,
    TargetController,
};
use crate::config::{ConfigError, EpochConfig};
use std::time::{Duration, Instant};

/// Epoch-quantized predictive target (the hardened strategy 2).
#[derive(Debug)]
pub struct EpochQuantizedTarget {
    cfg: EpochConfig,
    top: u32,
    level: u32,
    /// Anchor of the epoch and accounting-window grids.
    origin: Instant,
    epoch_index: u64,
    epoch_requests: u64,
    epoch_max: Duration,
    epoch_mispredicted: bool,
    window_index: u64,
    window_changes: u64,
    window_requests: u64,
    /// Charged bound of every closed accounting window since construction
    /// or the last operator reset.
    lifetime_prior_bits: f64,
    /// True while the level follows the public warm-up descent (rule 5).
    warmup: bool,
    frozen: bool,
    /// True when the freeze lasts until an operator reset.
    frozen_until_reset: bool,
    increases_total: u64,
    decreases_total: u64,
    rollbacks_total: u64,
    exhaustions_total: u64,
    requests_total: u64,
    boundaries_total: u64,
}

/// Changes charged for the cap multiple of an overrun released at
/// `k * cap` (`k >= 2`): `ceil(log2(k))`, at least 1. With the charge per
/// change of at least one bit, this covers the `log2(k)` bits the multiple
/// can carry. At most 128.
fn overrun_charge(cap: Duration, work: Duration) -> u32 {
    let c = cap.as_nanos().max(1);
    let k = work.as_nanos().div_ceil(c).max(2);
    // ceil(log2(k)) for k >= 2 is the bit length of k - 1.
    (u128::BITS - (k - 1).leading_zeros()).max(1)
}

fn grid_index(origin: Instant, now: Instant, period: Duration) -> u64 {
    let elapsed = now.saturating_duration_since(origin).as_nanos();
    let p = period.as_nanos().max(1);
    u64::try_from(elapsed / p).unwrap_or(u64::MAX)
}

impl EpochQuantizedTarget {
    /// A controller whose epoch and window grids start at `origin`
    /// (normally the pad's clock at construction).
    pub fn new(cfg: EpochConfig, origin: Instant) -> Result<Self, ConfigError> {
        cfg.validate()?;
        Ok(Self {
            top: cfg.top_level(),
            level: cfg.initial_level,
            origin,
            epoch_index: 0,
            epoch_requests: 0,
            epoch_max: Duration::ZERO,
            epoch_mispredicted: false,
            window_index: 0,
            window_changes: 0,
            window_requests: 0,
            lifetime_prior_bits: 0.0,
            warmup: true,
            frozen: false,
            frozen_until_reset: false,
            increases_total: 0,
            decreases_total: 0,
            rollbacks_total: 0,
            exhaustions_total: 0,
            requests_total: 0,
            boundaries_total: 0,
            cfg,
        })
    }

    /// The configuration in force.
    pub fn config(&self) -> &EpochConfig {
        &self.cfg
    }

    /// The current target.
    pub fn target(&self) -> Duration {
        self.cfg.level_target(self.level)
    }

    /// The current level index (0 is the floor).
    pub fn level(&self) -> u32 {
        self.level
    }

    /// True while adaptation is stopped after a leak budget was spent.
    pub fn is_frozen(&self) -> bool {
        self.frozen
    }

    /// True while the freeze lasts until an operator reset (the lifetime
    /// budget was spent).
    pub fn is_frozen_until_reset(&self) -> bool {
        self.frozen_until_reset
    }

    /// True while the level follows the uncharged warm-up descent from a
    /// public starting level.
    pub fn is_warming_up(&self) -> bool {
        self.warmup
    }

    /// Times a leak budget was spent (the controller froze) since
    /// construction.
    pub fn exhaustions_total(&self) -> u64 {
        self.exhaustions_total
    }

    /// Epoch boundaries evaluated since construction (`U` in the ladder
    /// bound for the downward direction).
    pub fn boundaries_total(&self) -> u64 {
        self.boundaries_total
    }

    fn snapshot(&self) -> Snapshot {
        Snapshot {
            target: self.target(),
            cap: self.cfg.cap,
            rule: MissRule::Escalate {
                floor: self.cfg.floor,
                level: self.level,
            },
        }
    }

    fn count_change(&mut self, n: u32) {
        let n = u64::from(n);
        self.window_changes = self.window_changes.saturating_add(n);
    }

    fn window_bits(&self) -> f64 {
        epoch_bound_bits(self.window_changes, self.window_requests)
    }

    /// Close the accounting window if `now` is past its end: add its bound
    /// to the lifetime sum, start a fresh window, and thaw a window-scoped
    /// freeze (the level is then the cap, a public start, so warm-up
    /// restarts).
    fn roll_window(&mut self, now: Instant) {
        let idx = grid_index(self.origin, now, self.cfg.leak_budget.window);
        if idx > self.window_index {
            self.lifetime_prior_bits += self.window_bits();
            self.window_index = idx;
            self.window_changes = 0;
            self.window_requests = 0;
            if self.frozen && !self.frozen_until_reset {
                self.frozen = false;
                self.warmup = true;
                // The epoch in progress began while frozen; start the
                // warm-up from a clean epoch so a miss from the frozen
                // period does not end it.
                self.epoch_requests = 0;
                self.epoch_max = Duration::ZERO;
                self.epoch_mispredicted = false;
            }
        }
    }

    fn roll_epoch(&mut self, now: Instant, ch: &mut Changes) {
        let idx = grid_index(self.origin, now, self.cfg.epoch);
        if idx <= self.epoch_index {
            return;
        }
        self.boundaries_total = self.boundaries_total.saturating_add(1);
        let eligible = !self.frozen && self.level > 0 && self.epoch_requests > 0;
        if eligible
            && !self.epoch_mispredicted
            && self.epoch_max <= self.cfg.level_target(self.level - 1)
        {
            self.level -= 1;
            self.decreases_total = self.decreases_total.saturating_add(1);
            // Rule 5: a warm-up step follows the public default; only the
            // end of the run is charged.
            if !self.warmup {
                self.count_change(1);
            }
            ch.decreases = ch.decreases.saturating_add(1);
        } else if eligible && self.warmup {
            // The warm-up run stops here: charge its end once.
            self.warmup = false;
            self.count_change(1);
        }
        // Any epochs skipped between the old index and `idx` were idle, so
        // they hold the level (rule 3); evaluating them is a no-op.
        self.epoch_index = idx;
        self.epoch_requests = 0;
        self.epoch_max = Duration::ZERO;
        self.epoch_mispredicted = false;
    }

    /// Freeze (rule 6) when the window bound reaches the window budget or
    /// the lifetime sum reaches the lifetime budget. Charges keep counting
    /// while frozen (overruns and misses still leak), so a window-frozen
    /// controller can still spend the lifetime budget.
    fn check_budget(&mut self, ch: &mut Changes) {
        if self.frozen_until_reset {
            return;
        }
        let bits = self.window_bits();
        let window_spent = bits >= self.cfg.leak_budget.bits;
        let lifetime_spent = self.lifetime_prior_bits + bits >= self.cfg.leak_lifetime_bits();
        if !self.frozen && (window_spent || lifetime_spent) {
            self.frozen = true;
            self.warmup = false;
            self.exhaustions_total = self.exhaustions_total.saturating_add(1);
            ch.exhausted = true;
            if self.level != self.top {
                self.level = self.top;
                self.rollbacks_total = self.rollbacks_total.saturating_add(1);
                ch.rollback = true;
            }
        }
        if lifetime_spent {
            self.frozen_until_reset = true;
            ch.lifetime_exhausted = true;
        }
    }
}

impl TargetController for EpochQuantizedTarget {
    fn kind(&self) -> ControllerKind {
        ControllerKind::Epoch
    }

    fn admit(&mut self, now: Instant) -> (Snapshot, Changes) {
        let mut ch = Changes::default();
        self.roll_window(now);
        self.roll_epoch(now, &mut ch);
        self.window_requests = self.window_requests.saturating_add(1);
        self.requests_total = self.requests_total.saturating_add(1);
        self.check_budget(&mut ch);
        (self.snapshot(), ch)
    }

    fn record(&mut self, snapshot: &Snapshot, work: Duration, now: Instant) -> Changes {
        let mut ch = Changes::default();
        self.roll_window(now);
        self.epoch_requests = self.epoch_requests.saturating_add(1);
        self.epoch_max = self.epoch_max.max(work);
        if work <= snapshot.target {
            return ch;
        }
        // A miss: the release (a higher level, or the cap grid) depends on
        // this request's work time, so it is charged whatever the level
        // does (rule 4).
        self.epoch_mispredicted = true;
        self.warmup = false;
        let mut charge = 0u32;
        if !self.frozen {
            let needed =
                ladder::covering_level(self.cfg.floor, self.cfg.cap, 0, work).unwrap_or(self.top);
            if needed > self.level {
                let steps = needed - self.level;
                self.level = needed;
                self.increases_total = self.increases_total.saturating_add(u64::from(steps));
                charge = steps;
                ch.increases = steps;
            }
        }
        if work > self.cfg.cap {
            charge = charge.saturating_add(overrun_charge(self.cfg.cap, work));
        } else if charge == 0 {
            charge = 1;
        }
        self.count_change(charge);
        self.check_budget(&mut ch);
        ch
    }

    fn status(&self) -> ControllerStatus {
        ControllerStatus {
            kind: ControllerKind::Epoch,
            target: self.target(),
            level: Some(self.level),
            cap: self.cfg.cap,
            changes_total: self
                .increases_total
                .saturating_add(self.decreases_total)
                .saturating_add(self.rollbacks_total),
            increases_total: self.increases_total,
            decreases_total: self.decreases_total,
            rollbacks_total: self.rollbacks_total,
            requests_total: self.requests_total,
            window_changes: self.window_changes,
            window_requests: self.window_requests,
            leak_bits: self.window_bits(),
            leak_budget_bits: Some(self.cfg.leak_budget.bits),
            lifetime_bits: self.lifetime_prior_bits + self.window_bits(),
            lifetime_budget_bits: Some(self.cfg.leak_lifetime_bits()),
            frozen: self.frozen,
            frozen_until_reset: self.frozen_until_reset,
        }
    }

    /// Lift a freeze, clear the lifetime sum and start a fresh accounting
    /// window at `now`. The level stays where it is (the cap after a
    /// rollback) and steps down through an uncharged warm-up descent.
    fn operator_reset(&mut self, now: Instant) -> Changes {
        self.frozen = false;
        self.frozen_until_reset = false;
        self.lifetime_prior_bits = 0.0;
        self.warmup = true;
        self.window_index = grid_index(self.origin, now, self.cfg.leak_budget.window);
        self.window_changes = 0;
        self.window_requests = 0;
        self.epoch_index = grid_index(self.origin, now, self.cfg.epoch);
        self.epoch_requests = 0;
        self.epoch_max = Duration::ZERO;
        self.epoch_mispredicted = false;
        Changes::default()
    }
}
