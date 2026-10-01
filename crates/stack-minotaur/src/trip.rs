//! The typed verdict a [`crate::Thread`] returns when a cap is hit.
//!
//! [`GateOutcome`] mirrors `GateOutcome` in `cns.gate` (the CNS repository,
//! `/home/user/CNS/cns/gate.py`) with the same string values. It is
//! re-declared here, not imported, because CNS is a Python package; the
//! string values are what must agree across languages.

use core::fmt;

use thiserror::Error;

use crate::fingerprint::Fingerprint;

/// Name this component reports itself under, for a caller building a CNS
/// `GateResult` from a [`Trip`].
pub const GATE_NAME: &str = "tack_minotaur";

/// A verdict, in increasing order of finality (CNS `GateOutcome`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum GateOutcome {
    /// Nothing objected. A [`Trip`] is never `Pass`; a successful call
    /// returns `Ok`, which is this outcome.
    Pass,
    /// Repairable: the caller may resubmit with a correction (a shallower
    /// plan, a smaller task, a narrower search, a different next step).
    Retry,
    /// Abort: no correction repairs it.
    TerminalBreach,
}

impl GateOutcome {
    /// The CNS string value, also used as the `outcome` metric label.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Pass => "pass",
            Self::Retry => "retry",
            Self::TerminalBreach => "terminal_breach",
        }
    }
}

/// What happens to state when a check trips (kernel convention 1).
///
/// The Minotaur String produces [`Resolution::Rollback`],
/// [`Resolution::Halt`] and, for a call made through a stale guard,
/// [`Resolution::Reject`]. [`Resolution::Quarantine`] exists so every STACK
/// component shares one vocabulary.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Resolution {
    /// Nothing changed. Produced only for [`TripKind::StaleGuard`]: the call
    /// was refused without touching the Thread.
    Reject,
    /// Input, sender or agent isolated for review. Not produced by this
    /// crate: the Thread has no identity for the walker.
    Quarantine,
    /// State restored to the last good snapshot. The Thread rewinds itself to
    /// the anchor; the caller restores its own snapshot (see the crate docs
    /// for the contract).
    Rollback,
    /// The Thread refuses all work until `operator_reset`.
    Halt,
}

impl Resolution {
    /// Lowercase name, used in log events.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Reject => "reject",
            Self::Quarantine => "quarantine",
            Self::Rollback => "rollback",
            Self::Halt => "halt",
        }
    }
}

/// Which detector found a loop.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Detector {
    /// The bounded exact revisit set counted too many visits to one state.
    Exact,
    /// Brent's cycle detection, used once the exact set is full.
    Brent,
    /// The bounded table of recently seen untracked states, used once the
    /// exact set is full, counted too many visits to one state. It catches
    /// repeats that Brent's single saved state can be steered away from.
    Recent,
}

impl Detector {
    /// The `detector` metric label.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Exact => "exact",
            Self::Brent => "brent",
            Self::Recent => "recent",
        }
    }
}

/// Why the Thread tripped.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TripKind {
    /// A descent would have gone deeper than `max_depth`: runaway recursion.
    DepthExceeded {
        /// The configured `max_depth`.
        limit: u32,
    },
    /// The walk used more than `max_steps` transitions.
    StepBudgetExhausted {
        /// The configured `max_steps`.
        limit: u64,
    },
    /// One state was revisited more than `revisit_allowance` times.
    LoopDetected {
        /// Steps between the last two visits to the repeating state. For a
        /// walk whose next state is a function of the current one, this is
        /// the exact cycle length; otherwise it is the most recent revisit
        /// gap.
        period: u64,
        /// Which detector found it.
        detector: Detector,
    },
    /// The walk kept reaching states the full exact set could not hold, more
    /// than `max_untracked_transitions` times: a state-space explosion.
    StateSpaceExhausted {
        /// States held in the exact set (its cap) when the trip fired.
        tracked: usize,
        /// The configured `max_untracked_transitions`.
        limit: u64,
    },
    /// The Thread is halted; the call was refused and nothing changed.
    /// This is an addition to the four kinds in the specification.
    Halted,
    /// `descend` or `record` was called through a guard issued before the
    /// Thread's last rewind (a trip deeper in the walk, or a rewind). The
    /// call was refused and nothing changed; the caller must unwind to the
    /// root holder of the Thread. This is an addition to the specification.
    StaleGuard,
    /// The Thread accepted `max_steps * max_trips_before_halt` transitions
    /// since construction or the last `operator_reset`, across all walks.
    /// This bounds a caller that replays walks and rewinds just before each
    /// per-walk cap. Always halts. This is an addition to the specification.
    LifetimeBudgetExhausted {
        /// The lifetime limit, `max_steps * max_trips_before_halt`.
        limit: u64,
    },
}

/// Closed set of trip reasons, used as the `reason` metric label.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Reason {
    /// [`TripKind::DepthExceeded`].
    DepthExceeded,
    /// [`TripKind::StepBudgetExhausted`].
    StepBudgetExhausted,
    /// [`TripKind::LoopDetected`].
    LoopDetected,
    /// [`TripKind::StateSpaceExhausted`].
    StateSpaceExhausted,
    /// [`TripKind::Halted`].
    Halted,
    /// [`TripKind::StaleGuard`].
    StaleGuard,
    /// [`TripKind::LifetimeBudgetExhausted`].
    LifetimeBudgetExhausted,
}

impl Reason {
    /// The `reason` metric label.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::DepthExceeded => "depth_exceeded",
            Self::StepBudgetExhausted => "step_budget_exhausted",
            Self::LoopDetected => "loop_detected",
            Self::StateSpaceExhausted => "state_space_exhausted",
            Self::Halted => "halted",
            Self::StaleGuard => "stale_guard",
            Self::LifetimeBudgetExhausted => "lifetime_budget_exhausted",
        }
    }
}

impl TripKind {
    /// The closed reason for this kind.
    #[must_use]
    pub const fn reason(&self) -> Reason {
        match self {
            Self::DepthExceeded { .. } => Reason::DepthExceeded,
            Self::StepBudgetExhausted { .. } => Reason::StepBudgetExhausted,
            Self::LoopDetected { .. } => Reason::LoopDetected,
            Self::StateSpaceExhausted { .. } => Reason::StateSpaceExhausted,
            Self::Halted => Reason::Halted,
            Self::StaleGuard => Reason::StaleGuard,
            Self::LifetimeBudgetExhausted { .. } => Reason::LifetimeBudgetExhausted,
        }
    }
}

impl fmt::Display for TripKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DepthExceeded { limit } => write!(f, "depth exceeded (limit {limit})"),
            Self::StepBudgetExhausted { limit } => {
                write!(f, "step budget exhausted (limit {limit})")
            }
            Self::LoopDetected { period, detector } => {
                write!(
                    f,
                    "loop detected (period {period}, {} detector)",
                    detector.as_str()
                )
            }
            Self::StateSpaceExhausted { tracked, limit } => write!(
                f,
                "state space exhausted ({tracked} states tracked, untracked limit {limit})"
            ),
            Self::Halted => f.write_str("thread halted; operator reset required"),
            Self::StaleGuard => {
                f.write_str("stale guard; unwind to the root holder of the thread")
            }
            Self::LifetimeBudgetExhausted { limit } => {
                write!(f, "lifetime step budget exhausted (limit {limit})")
            }
        }
    }
}

/// A tripped cap: what happened, where the walk had been, and what the
/// caller must do.
///
/// When a `Trip` other than [`TripKind::Halted`] or [`TripKind::StaleGuard`]
/// is returned, the Thread has already rewound to the anchor (depth 0, step
/// count 0, revisit set empty), and every guard still alive is stale. The
/// caller must unwind to the root, discard work done since its last snapshot
/// and restore that snapshot. A `Halted` or `StaleGuard` trip changed
/// nothing.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[error("minotaur trip: {kind} ({outcome}, {resolution})", outcome = .outcome.as_str(), resolution = .resolution.as_str())]
pub struct Trip {
    /// Why it tripped.
    pub kind: TripKind,
    /// The last `breadcrumb_len` fingerprints recorded before the trip,
    /// oldest first, including the one that tripped. Bounded by config.
    /// Empty for `Halted` and `StaleGuard`. Its allocation always has room
    /// for `breadcrumb_len` entries, so its size does not reveal the walk
    /// length (its `len()` does).
    /// This reveals the walk; do not hand it to a party that should not see
    /// state fingerprints.
    pub path: Vec<Fingerprint>,
    /// CNS outcome. `Retry` for a single trip; `TerminalBreach` for the trip
    /// that halts the Thread and for every refusal while halted.
    pub outcome: GateOutcome,
    /// `Rollback` normally; `Halt` when the Thread is halted; `Reject` for
    /// `StaleGuard`.
    pub resolution: Resolution,
    /// Depth at the moment of the trip, before the rewind.
    pub depth: u32,
    /// Transitions recorded in the walk at the moment of the trip, before the
    /// rewind (including the tripping one).
    pub steps: u64,
}

impl Trip {
    /// The closed reason for this trip.
    #[must_use]
    pub const fn reason(&self) -> Reason {
        self.kind.reason()
    }

    /// The loop period, when this is a [`TripKind::LoopDetected`].
    #[must_use]
    pub const fn period(&self) -> Option<u64> {
        match self.kind {
            TripKind::LoopDetected { period, .. } => Some(period),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn labels_match_cns_strings() {
        assert_eq!(GateOutcome::Pass.as_str(), "pass");
        assert_eq!(GateOutcome::Retry.as_str(), "retry");
        assert_eq!(GateOutcome::TerminalBreach.as_str(), "terminal_breach");
    }

    #[test]
    fn display_names_kind_and_outcome() {
        let t = Trip {
            kind: TripKind::LoopDetected {
                period: 2,
                detector: Detector::Exact,
            },
            path: Vec::new(),
            outcome: GateOutcome::Retry,
            resolution: Resolution::Rollback,
            depth: 0,
            steps: 5,
        };
        let s = t.to_string();
        assert!(s.contains("period 2"), "{s}");
        assert!(s.contains("retry"), "{s}");
        assert!(s.contains("rollback"), "{s}");
        assert_eq!(t.period(), Some(2));
    }
}
