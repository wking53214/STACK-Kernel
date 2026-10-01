//! Target controllers: who decides how long each response is padded.
//!
//! A controller is a small state machine behind the pad's mutex. The pad
//! calls it twice per request:
//!
//! 1. [`TargetController::admit`] at admission, before any secret work. It
//!    applies updates that are due at public times (epoch boundaries,
//!    accounting windows) and returns a [`Snapshot`]: the target for this
//!    request plus what is needed to plan a release without the lock.
//! 2. [`TargetController::record`] after the operation, inside the padded
//!    window (so its own run time, which may depend on the work time, is
//!    hidden by the pad when the request is on time). It folds the work
//!    time into the controller's state.
//!
//! [`Snapshot::plan`] is a pure function from the snapshot and the work
//! time to a release offset, so the release schedule can be tested without
//! a clock.

pub(crate) mod epoch;
pub(crate) mod ladder;
pub(crate) mod naive;

use std::fmt::Debug;
use std::time::{Duration, Instant};

/// Which controller a pad runs. Used as a closed-set metric label.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ControllerKind {
    /// [`crate::NaiveRollingTarget`].
    Naive,
    /// [`crate::EpochQuantizedTarget`].
    Epoch,
}

impl ControllerKind {
    /// Closed-set metric label (`naive` | `epoch`).
    pub const fn label(self) -> &'static str {
        match self {
            ControllerKind::Naive => "naive",
            ControllerKind::Epoch => "epoch",
        }
    }
}

/// What a controller does when work runs past the target.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MissRule {
    /// Naive: release at completion.
    ReleaseLate,
    /// Epoch: release at the smallest public level at or above the work
    /// time. `floor` and `level` describe the ladder position at admission.
    Escalate {
        /// The ladder floor.
        floor: Duration,
        /// The level index of `Snapshot::target`.
        level: u32,
    },
}

/// The target in force for one request, taken at admission.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Snapshot {
    /// Pad the response to `admission + target` when the work fits.
    pub target: Duration,
    /// The controller's cap (hard ceiling).
    pub cap: Duration,
    /// What happens on a miss.
    pub rule: MissRule,
}

/// The release decision for one request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Plan {
    /// Released at `admission + release`, which is the target.
    OnTime {
        /// Offset from admission.
        release: Duration,
    },
    /// Naive only: released at completion, `release` equals the work time.
    Late {
        /// Offset from admission.
        release: Duration,
    },
    /// Epoch only: released at a higher public level.
    Escalated {
        /// Offset from admission: the covering level.
        release: Duration,
        /// Doublings above the admission level.
        steps: u32,
    },
    /// Work ran past the cap. The value is discarded (RETRY). Epoch:
    /// released at the next whole multiple of the cap, so the release still
    /// tells `ceil(work / cap)`; the epoch controller charges that to the
    /// leak budget (see [`crate::EpochQuantizedTarget`]). Naive: at
    /// completion.
    HardOverrun {
        /// Offset from admission.
        release: Duration,
    },
}

impl Plan {
    /// The planned release offset from admission.
    pub const fn release(&self) -> Duration {
        match *self {
            Plan::OnTime { release }
            | Plan::Late { release }
            | Plan::Escalated { release, .. }
            | Plan::HardOverrun { release } => release,
        }
    }
}

impl Snapshot {
    /// Where to release a request whose work took `work`. Pure; never
    /// releases before `work` and never before the target. The pad passes
    /// the work time plus the spin tail in Hybrid mode (see
    /// [`crate::WaitMode::Hybrid`]).
    pub fn plan(&self, work: Duration) -> Plan {
        if work <= self.target {
            return Plan::OnTime {
                release: self.target,
            };
        }
        match self.rule {
            MissRule::ReleaseLate => {
                if work <= self.cap {
                    Plan::Late { release: work }
                } else {
                    Plan::HardOverrun { release: work }
                }
            }
            MissRule::Escalate { floor, level } => {
                match ladder::covering_level(floor, self.cap, level, work) {
                    Some(to) => Plan::Escalated {
                        release: ladder::level_target(floor, self.cap, to),
                        steps: to.saturating_sub(level).max(1),
                    },
                    None => Plan::HardOverrun {
                        release: ladder::cap_grid(self.cap, work),
                    },
                }
            }
        }
    }
}

/// Target changes made by one controller call. Emitted as metrics after
/// release.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Changes {
    /// Upward steps (epoch: doublings; naive: 1 when the target rose).
    pub increases: u32,
    /// Downward steps (epoch: halvings at epoch boundaries; naive: 1 when
    /// the target fell).
    pub decreases: u32,
    /// True when the target was rolled back to the cap because the leak
    /// budget was spent (counted separately, not in `increases`).
    pub rollback: bool,
    /// True when this call froze the controller (a window or the lifetime
    /// leak budget was spent).
    pub exhausted: bool,
    /// True when this call spent the lifetime leak budget: the freeze now
    /// lasts until an operator reset.
    pub lifetime_exhausted: bool,
}

impl Changes {
    /// Field-wise sum of two change records.
    pub fn merge(self, other: Changes) -> Changes {
        Changes {
            increases: self.increases.saturating_add(other.increases),
            decreases: self.decreases.saturating_add(other.decreases),
            rollback: self.rollback || other.rollback,
            exhausted: self.exhausted || other.exhausted,
            lifetime_exhausted: self.lifetime_exhausted || other.lifetime_exhausted,
        }
    }

    /// True if nothing changed.
    pub fn is_empty(&self) -> bool {
        *self == Changes::default()
    }
}

/// A read-only view of a controller's state, for operators, tests and
/// telemetry.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct ControllerStatus {
    /// Which controller.
    pub kind: ControllerKind,
    /// The current target.
    pub target: Duration,
    /// The current level index (epoch only).
    pub level: Option<u32>,
    /// The controller's cap (hard ceiling on the target).
    pub cap: Duration,
    /// Every target change since construction (increases, decreases and
    /// rollbacks), whether or not it was charged to the leak budget.
    pub changes_total: u64,
    /// Upward steps since construction.
    pub increases_total: u64,
    /// Downward steps since construction.
    pub decreases_total: u64,
    /// Rollbacks to the cap since construction (epoch only).
    pub rollbacks_total: u64,
    /// Requests admitted since construction.
    pub requests_total: u64,
    /// Epoch: changes CHARGED to the leak budget in the current accounting
    /// window. That is every level increase, every escalated or overrun
    /// release that did not raise the level, the extra charge for an
    /// overrun's cap multiple, every decrease after warm-up, and one change
    /// for the end of a warm-up descent; warm-up decreases themselves are
    /// not charged (see [`crate::EpochQuantizedTarget`]). Naive: every
    /// target change since construction.
    pub window_changes: u64,
    /// Requests admitted in the current accounting window (epoch), or
    /// since construction (naive).
    pub window_requests: u64,
    /// Leak bound spent: [`epoch_bound_bits`] of `window_changes` and
    /// `window_requests`.
    pub leak_bits: f64,
    /// The configured budget per window (epoch only).
    pub leak_budget_bits: Option<f64>,
    /// Epoch: the charged bound summed over every accounting window since
    /// construction or the last operator reset (the current window
    /// included). Naive: equal to `leak_bits`.
    pub lifetime_bits: f64,
    /// The configured lifetime budget (epoch only).
    pub lifetime_budget_bits: Option<f64>,
    /// True while adaptation is stopped after a budget was spent (until the
    /// next window boundary, or until an operator reset when
    /// `frozen_until_reset` is set).
    pub frozen: bool,
    /// True while the freeze lasts until an operator reset (the lifetime
    /// budget was spent).
    pub frozen_until_reset: bool,
}

/// A padding-target controller. Implemented by [`crate::NaiveRollingTarget`]
/// and [`crate::EpochQuantizedTarget`]; a third implementation must keep
/// every method bounded in time and memory and must never panic.
pub trait TargetController: Send + Debug {
    /// Which controller this is.
    fn kind(&self) -> ControllerKind;

    /// Admission at time `now`: apply updates due at public times, count
    /// the request, and return the target for it.
    fn admit(&mut self, now: Instant) -> (Snapshot, Changes);

    /// Fold in one observed work time. `snapshot` is what `admit` returned
    /// for this request.
    fn record(&mut self, snapshot: &Snapshot, work: Duration, now: Instant) -> Changes;

    /// Current state.
    fn status(&self) -> ControllerStatus;

    /// Operator reset: lift a freeze, start a fresh accounting window and
    /// clear the lifetime sum.
    fn operator_reset(&mut self, now: Instant) -> Changes;
}

/// The epoch-form leak bound in bits for `changes` target changes among
/// `requests` requests: `changes * log2(2 * (requests + 1))`.
///
/// Each change can happen before any of the `requests` requests or after
/// the last (`requests + 1` positions, `log2(requests + 1)` bits), and can
/// go up or down (1 more bit). The theorist's form `N * log2(R + 1)` omits
/// the direction bit; this crate charges it, so its bound is the larger of
/// the two. Zero changes cost zero bits.
pub fn epoch_bound_bits(changes: u64, requests: u64) -> f64 {
    if changes == 0 {
        return 0.0;
    }
    let positions = 2.0 * (requests as f64 + 1.0);
    changes as f64 * positions.log2()
}

/// The ladder-form bound in bits: `updates * log2(levels)`, for a target
/// drawn from `levels` public values and updated only at `updates` public
/// times. Reported for comparison only: the epoch controller's doublings
/// happen at request times, not at public times, so the ladder form does
/// not bound it and the budget uses [`epoch_bound_bits`].
pub fn ladder_bound_bits(updates: u64, levels: u32) -> f64 {
    if updates == 0 || levels <= 1 {
        return 0.0;
    }
    updates as f64 * f64::from(levels).log2()
}

pub(crate) fn nanos_u64(d: Duration) -> u64 {
    u64::try_from(d.as_nanos()).unwrap_or(u64::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bound_examples() {
        assert_eq!(epoch_bound_bits(0, 1_000), 0.0);
        // One change among 0 requests: 2 positions-times-directions, 1 bit.
        assert!((epoch_bound_bits(1, 0) - 1.0).abs() < 1e-12);
        // 3 changes among 1023 requests: 3 * log2(2048) = 33 bits.
        assert!((epoch_bound_bits(3, 1_023) - 33.0).abs() < 1e-9);
        assert!((ladder_bound_bits(10, 8) - 30.0).abs() < 1e-12);
        assert_eq!(ladder_bound_bits(10, 1), 0.0);
    }

    #[test]
    fn naive_plan() {
        let s = Snapshot {
            target: Duration::from_micros(100),
            cap: Duration::from_micros(500),
            rule: MissRule::ReleaseLate,
        };
        let us = Duration::from_micros;
        assert_eq!(s.plan(us(40)), Plan::OnTime { release: us(100) });
        assert_eq!(s.plan(us(130)), Plan::Late { release: us(130) });
        assert_eq!(s.plan(us(900)), Plan::HardOverrun { release: us(900) });
    }

    #[test]
    fn epoch_plan() {
        let us = Duration::from_micros;
        let s = Snapshot {
            target: us(20),
            cap: us(100),
            rule: MissRule::Escalate {
                floor: us(10),
                level: 1,
            },
        };
        assert_eq!(s.plan(us(20)), Plan::OnTime { release: us(20) });
        assert_eq!(
            s.plan(us(21)),
            Plan::Escalated {
                release: us(40),
                steps: 1
            }
        );
        assert_eq!(
            s.plan(us(70)),
            Plan::Escalated {
                release: us(80),
                steps: 2
            }
        );
        assert_eq!(
            s.plan(us(95)),
            Plan::Escalated {
                release: us(100),
                steps: 3
            }
        );
        assert_eq!(s.plan(us(101)), Plan::HardOverrun { release: us(200) });
        assert_eq!(s.plan(us(250)), Plan::HardOverrun { release: us(300) });
    }
}
