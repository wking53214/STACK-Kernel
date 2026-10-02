//! Typed results: what a padded request returns, and how each failure maps
//! to the CNS vocabulary.

use crate::config::WaitMode;
use std::time::Duration;
use thiserror::Error;

/// Mirror of the CNS `GateOutcome` vocabulary (`CNS/cns/gate.py`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum GateOutcome {
    /// The request was served.
    Pass,
    /// Repairable: the caller may resubmit (later, or with a correction).
    Retry,
    /// Not repairable by resubmission.
    TerminalBreach,
}

impl GateOutcome {
    /// The CNS spelling: `PASS`, `RETRY` or `TERMINAL_BREACH`.
    pub const fn as_str(self) -> &'static str {
        match self {
            GateOutcome::Pass => "PASS",
            GateOutcome::Retry => "RETRY",
            GateOutcome::TerminalBreach => "TERMINAL_BREACH",
        }
    }

    /// Closed-set metric label.
    pub const fn label(self) -> &'static str {
        match self {
            GateOutcome::Pass => "pass",
            GateOutcome::Retry => "retry",
            GateOutcome::TerminalBreach => "terminal_breach",
        }
    }
}

/// The kernel-wide state resolutions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Resolution {
    /// Nothing changed; the request is refused.
    Reject,
    /// The input, sender or agent is isolated for review and counted. Used
    /// for [`Trip::OperationPanicked`]: the pad counts the request and
    /// returns a fixed code; the caller isolates the input or sender (the
    /// pad has no sender identity of its own).
    Quarantine,
    /// State restored to the last good snapshot. Used by the epoch
    /// controller when its leak budget is spent: the target returns to the
    /// configured public maximum (the cap).
    Rollback,
    /// The component stops accepting work until an operator calls
    /// [`crate::AdaptivePad::reset`].
    Halt,
}

/// Why a request was not served. Every variant is a unit variant, so a
/// caller that turns a trip into a reply sends one of six fixed codes and
/// nothing derived from the input or the secret.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Error)]
pub enum Trip {
    /// Every concurrency slot was taken. Shed at admission, before any
    /// secret-dependent work, returned at once (the fast reply reflects
    /// load only). RETRY, reject.
    #[error("RETRY: admission full")]
    SlotsFull,
    /// The input was longer than `max_input_len`. Checked before admission
    /// and before any secret-dependent work, returned at once. RETRY,
    /// reject.
    #[error("RETRY: input too large")]
    InputTooLarge,
    /// The operation ran past the controller's cap (the hard ceiling). The
    /// value is discarded. The epoch controller releases the reply at the
    /// next whole multiple of the cap after completion (a public grid). The
    /// multiple still tells `ceil(work / cap)`, so the epoch controller
    /// charges it to the leak budget, frozen or not. The naive controller
    /// releases it at completion (it has no grid, which is one of its
    /// leaks). RETRY, reject.
    #[error("RETRY: target cap overrun")]
    Overrun,
    /// The pad is halted after a clock failure. Returned at once until an
    /// operator calls reset. TERMINAL_BREACH, halt.
    #[error("TERMINAL_BREACH: halted")]
    Halted,
    /// The monotonic clock went backwards, stopped advancing, or produced a
    /// time that does not fit. Padding cannot be trusted without a clock,
    /// so the pad halts. The reply is released at once. TERMINAL_BREACH,
    /// halt.
    #[error("TERMINAL_BREACH: monotonic clock failure")]
    ClockFailure,
    /// The operation panicked. The panic is caught inside the pad, the
    /// reply is released on the same schedule as any other request (the
    /// work time is the time until the panic), the request is counted, and
    /// the panic payload is dropped. A resubmission would hit the same bug,
    /// so TERMINAL_BREACH; quarantine, not halt, because a request that can
    /// trigger the panic would otherwise halt the pad for everyone.
    #[error("TERMINAL_BREACH: operation panicked")]
    OperationPanicked,
}

impl Trip {
    /// CNS outcome.
    pub const fn gate_outcome(self) -> GateOutcome {
        match self {
            Trip::SlotsFull | Trip::InputTooLarge | Trip::Overrun => GateOutcome::Retry,
            Trip::Halted | Trip::ClockFailure | Trip::OperationPanicked => {
                GateOutcome::TerminalBreach
            }
        }
    }

    /// State resolution.
    pub const fn resolution(self) -> Resolution {
        match self {
            Trip::SlotsFull | Trip::InputTooLarge | Trip::Overrun => Resolution::Reject,
            Trip::Halted | Trip::ClockFailure => Resolution::Halt,
            Trip::OperationPanicked => Resolution::Quarantine,
        }
    }

    /// Closed-set metric label.
    pub const fn label(self) -> &'static str {
        match self {
            Trip::SlotsFull => "slots_full",
            Trip::InputTooLarge => "input_too_large",
            Trip::Overrun => "overrun",
            Trip::Halted => "halted",
            Trip::ClockFailure => "clock_failure",
            Trip::OperationPanicked => "operation_panicked",
        }
    }
}

/// A trip of the controller itself, not of a request. Requests keep being
/// served when it fires.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Error)]
pub enum ControllerTrip {
    /// The epoch controller's leak bound reached its budget for the current
    /// accounting window. The target is rolled back to the cap and
    /// adaptation stops for the rest of that window; it resumes (warming up
    /// from the cap) at the next window boundary. RETRY for the controller
    /// (waiting repairs it), rollback, requests unaffected. A flood that
    /// spends the budget again every window spends the lifetime budget
    /// instead ([`ControllerTrip::LeakLifetimeSpent`]). It does not halt,
    /// because a flood that forces overruns could otherwise force the halt.
    #[error("RETRY: adaptive leak budget spent for this window; target rolled back to the cap")]
    LeakBudgetSpent,
    /// The lifetime sum of the epoch controller's charged bound reached
    /// [`crate::EpochConfig::leak_lifetime_bits`]. The target is rolled
    /// back to the cap and adaptation stops until an operator calls
    /// [`crate::AdaptivePad::reset_controller`]; waiting does not lift it.
    /// TERMINAL_BREACH for the controller, rollback, requests unaffected.
    #[error("TERMINAL_BREACH: adaptive lifetime leak budget spent; target rolled back to the cap")]
    LeakLifetimeSpent,
}

impl ControllerTrip {
    /// CNS outcome.
    pub const fn gate_outcome(self) -> GateOutcome {
        match self {
            ControllerTrip::LeakBudgetSpent => GateOutcome::Retry,
            ControllerTrip::LeakLifetimeSpent => GateOutcome::TerminalBreach,
        }
    }

    /// State resolution.
    pub const fn resolution(self) -> Resolution {
        Resolution::Rollback
    }

    /// Closed-set metric label.
    pub const fn label(self) -> &'static str {
        match self {
            ControllerTrip::LeakBudgetSpent => "leak_budget_spent",
            ControllerTrip::LeakLifetimeSpent => "leak_lifetime_spent",
        }
    }
}

/// How a served response was released relative to its target.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Disposition {
    /// Work finished within the target; released at `admission + target`.
    OnTime,
    /// Naive controller only: work ran past the target and the response was
    /// released at completion. This is leak 1 of the naive design: the
    /// release time is the raw, secret-dependent work time.
    Late,
    /// Epoch controller only: work ran past the target (a misprediction).
    /// The response was released at the smallest higher public level that
    /// covers the work, `steps` doublings above the admission target.
    Escalated {
        /// Doublings above the admission target (at least 1).
        steps: u32,
    },
}

impl Disposition {
    /// Closed-set label (`on_time` | `late` | `escalated`).
    pub const fn label(self) -> &'static str {
        match self {
            Disposition::OnTime => "on_time",
            Disposition::Late => "late",
            Disposition::Escalated { .. } => "escalated",
        }
    }
}

/// When and how a served response was released. Contains only post-padding
/// facts and the target, never the operation's own run time.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReleaseInfo {
    /// The target in force at admission.
    pub target: Duration,
    /// The planned release offset from admission.
    pub release: Duration,
    /// On time, late (naive) or escalated (epoch).
    pub disposition: Disposition,
    /// The wait mode actually used (Sleep when the spin budget was empty).
    pub mode: WaitMode,
    /// Observed release offset from admission, padding included: what the
    /// client sees.
    pub observed: Duration,
}

/// A served response: the operation's value, released on schedule.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Padded<T> {
    /// What the operation returned.
    pub value: T,
    /// Release facts.
    pub release: ReleaseInfo,
}

impl<T> Padded<T> {
    /// Always [`GateOutcome::Pass`]: the pad served the request. Whether
    /// the operation's own answer was "valid" is in `value`.
    pub const fn gate_outcome(&self) -> GateOutcome {
        GateOutcome::Pass
    }
}

/// Result of one padded request.
pub type PadResult<T> = Result<Padded<T>, Trip>;
