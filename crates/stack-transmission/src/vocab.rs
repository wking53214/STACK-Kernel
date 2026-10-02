//! The closed vocabulary of verdicts. Every string here is a fixed label
//! value; nothing a caller supplies ever becomes one.
//!
//! The outcome words follow the CNS contract in `/home/user/CNS/cns/gate.py`
//! (`GateOutcome`: PASS, RETRY, TERMINAL_BREACH). This crate mirrors the
//! vocabulary rather than depending on the Python package.

use std::fmt;

/// The CNS gate outcome of one call.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum GateOutcome {
    /// The call succeeded.
    Pass,
    /// Repairable. The caller may try again, possibly after a correction
    /// (a smaller timeout, waiting for the shift to finish, and so on).
    Retry,
    /// Not repairable by the caller. Only an operator can change things.
    TerminalBreach,
}

impl GateOutcome {
    /// Label spelling.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Pass => "pass",
            Self::Retry => "retry",
            Self::TerminalBreach => "terminal_breach",
        }
    }
}

/// What happened to transmission state when a call was refused.
///
/// The kernel vocabulary also has `quarantine`. The transmission never
/// uses it: it has no notion of a sender or agent to isolate, only one
/// gear and a count of work in flight.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Resolution {
    /// Nothing changed. The gear, the clutch and the in-flight count are as
    /// they were before the call.
    Reject,
    /// The clutch was pressed and then released without a swap. The old gear
    /// is still engaged. The new configuration is handed back to the caller.
    Rollback,
    /// The transmission is halted and refuses all new work until
    /// [`crate::Transmission::operator_reset`].
    Halt,
}

impl Resolution {
    /// Label spelling.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Reject => "reject",
            Self::Rollback => "rollback",
            Self::Halt => "halt",
        }
    }
}

/// Which public call produced a verdict.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Operation {
    /// [`crate::Transmission::engage`].
    Engage,
    /// [`crate::Transmission::shift`].
    Shift,
}

impl Operation {
    /// Label spelling.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Engage => "engage",
            Self::Shift => "shift",
        }
    }
}

/// Why a call was refused. Each reason has exactly one outcome and one
/// resolution, fixed by [`Reason::outcome`] and [`Reason::resolution`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Reason {
    /// `engage()` asked to wait longer than `max_engage_wait`.
    EngageTimeoutOverBudget,
    /// `shift()` asked to drain longer than `max_shift_timeout`.
    ShiftTimeoutOverBudget,
    /// The clutch was pressed and too many callers were already waiting.
    WaitQueueFull,
    /// The clutch stayed pressed for the whole `engage()` timeout.
    ClutchWaitTimeout,
    /// `max_in_flight` guards are already out.
    InFlightCapacity,
    /// Another shift holds the clutch, or is waiting out the cooldown before
    /// pressing it.
    ShiftInProgress,
    /// [`crate::Transmission::shift_from`] named an epoch that is no longer
    /// engaged: another shift won the race, or the request is a replay of an
    /// old one. Nothing changed; the configuration is handed back.
    EpochMismatch,
    /// In-flight work did not reach zero before the shift timeout. The shift
    /// was rolled back.
    DrainTimeout,
    /// The epoch counter is at `u64::MAX`; no further shift can be numbered.
    EpochExhausted,
    /// The transmission is halted (operator halt, a recovered poisoned lock,
    /// or a broken internal invariant), or a halt happened while this call
    /// was waiting, even if an operator has reset it since. See
    /// [`crate::TransmissionStatus::halted`] for the cause.
    Halted,
}

impl Reason {
    /// Every reason, for exhaustive tests and documentation.
    pub const ALL: [Reason; 10] = [
        Self::EngageTimeoutOverBudget,
        Self::ShiftTimeoutOverBudget,
        Self::WaitQueueFull,
        Self::ClutchWaitTimeout,
        Self::InFlightCapacity,
        Self::ShiftInProgress,
        Self::EpochMismatch,
        Self::DrainTimeout,
        Self::EpochExhausted,
        Self::Halted,
    ];

    /// Label spelling.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::EngageTimeoutOverBudget => "engage_timeout_over_budget",
            Self::ShiftTimeoutOverBudget => "shift_timeout_over_budget",
            Self::WaitQueueFull => "wait_queue_full",
            Self::ClutchWaitTimeout => "clutch_wait_timeout",
            Self::InFlightCapacity => "in_flight_capacity",
            Self::ShiftInProgress => "shift_in_progress",
            Self::EpochMismatch => "epoch_mismatch",
            Self::DrainTimeout => "drain_timeout",
            Self::EpochExhausted => "epoch_exhausted",
            Self::Halted => "halted",
        }
    }

    /// The CNS outcome for this reason. Never [`GateOutcome::Pass`]: a
    /// refusal always fails closed.
    pub const fn outcome(self) -> GateOutcome {
        match self {
            Self::EngageTimeoutOverBudget
            | Self::ShiftTimeoutOverBudget
            | Self::WaitQueueFull
            | Self::ClutchWaitTimeout
            | Self::InFlightCapacity
            | Self::ShiftInProgress
            | Self::EpochMismatch
            | Self::DrainTimeout => GateOutcome::Retry,
            Self::EpochExhausted | Self::Halted => GateOutcome::TerminalBreach,
        }
    }

    /// What happened to state.
    pub const fn resolution(self) -> Resolution {
        match self {
            Self::DrainTimeout => Resolution::Rollback,
            Self::Halted => Resolution::Halt,
            Self::EngageTimeoutOverBudget
            | Self::ShiftTimeoutOverBudget
            | Self::WaitQueueFull
            | Self::ClutchWaitTimeout
            | Self::InFlightCapacity
            | Self::ShiftInProgress
            | Self::EpochMismatch
            | Self::EpochExhausted => Resolution::Reject,
        }
    }
}

/// Why the transmission is halted. Closed; used as the `cause` label.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum HaltCause {
    /// An operator called [`crate::Transmission::operator_halt`].
    Operator,
    /// The internal mutex was found poisoned (a thread panicked while
    /// holding it). The state was recovered, but new work is refused until
    /// an operator has looked.
    Poisoned,
    /// An internal counter would have gone below zero. This cannot happen
    /// through the public API; if it does, something is badly wrong.
    Invariant,
}

impl HaltCause {
    /// Label spelling.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Operator => "operator",
            Self::Poisoned => "poisoned",
            Self::Invariant => "invariant",
        }
    }
}

/// A refused call. Carries no caller data, so it is safe to log whole.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, thiserror::Error)]
#[error("stack-transmission {operation} refused: {reason} ({outcome}, {resolution})",
    operation = .operation.as_str(),
    reason = .reason.as_str(),
    outcome = .reason.outcome().as_str(),
    resolution = .reason.resolution().as_str())]
pub struct Trip {
    /// The call that was refused.
    pub operation: Operation,
    /// Why.
    pub reason: Reason,
}

impl Trip {
    pub(crate) const fn new(operation: Operation, reason: Reason) -> Self {
        Self { operation, reason }
    }

    /// RETRY or TERMINAL_BREACH.
    pub const fn outcome(&self) -> GateOutcome {
        self.reason.outcome()
    }

    /// What happened to state.
    pub const fn resolution(&self) -> Resolution {
        self.reason.resolution()
    }
}

impl fmt::Display for GateOutcome {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl fmt::Display for Resolution {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_reason_passes() {
        for r in Reason::ALL {
            assert_ne!(r.outcome(), GateOutcome::Pass, "{r:?}");
        }
    }

    #[test]
    fn only_drain_timeout_rolls_back_and_only_halted_halts() {
        for r in Reason::ALL {
            match r {
                Reason::DrainTimeout => assert_eq!(r.resolution(), Resolution::Rollback),
                Reason::Halted => assert_eq!(r.resolution(), Resolution::Halt),
                _ => assert_eq!(r.resolution(), Resolution::Reject),
            }
        }
    }

    #[test]
    fn label_spellings_are_distinct_snake_case() {
        let mut seen = std::collections::HashSet::new();
        for r in Reason::ALL {
            let s = r.as_str();
            assert!(s.chars().all(|c| c.is_ascii_lowercase() || c == '_'), "{s}");
            assert!(seen.insert(s), "duplicate {s}");
        }
    }

    #[test]
    fn trip_display_names_everything() {
        let t = Trip::new(Operation::Shift, Reason::DrainTimeout);
        assert_eq!(
            t.to_string(),
            "stack-transmission shift refused: drain_timeout (retry, rollback)"
        );
    }
}
