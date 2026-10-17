//! Typed results: what a padded request returns, and how each failure maps
//! to the CNS vocabulary.

use crate::config::WaitMode;
use std::time::Duration;
use thiserror::Error;

/// Mirror of the CNS `GateOutcome` vocabulary (`CNS/cns/gate.py`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum GateOutcome {
    /// The request was served and released on schedule.
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

/// The kernel-wide state resolutions. This crate uses `Reject` and `Halt`;
/// the other two are listed so the vocabulary matches the other STACK
/// components.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Resolution {
    /// Nothing changed; the request is refused.
    Reject,
    /// The input, sender or agent is isolated for review. Not used here.
    Quarantine,
    /// State restored to the last good snapshot. Not used here.
    Rollback,
    /// The component stops accepting work until an operator calls
    /// [`crate::CeilingPad::reset`].
    Halt,
}

/// Why a request was not served. Every variant is a unit variant, so every
/// trip has the same fixed shape: a caller that turns it into a reply sends
/// one of six fixed codes and nothing derived from the input or the secret.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Error)]
pub enum Trip {
    /// Every concurrency slot was taken. Shed at admission, before any
    /// secret-dependent work, and returned immediately (unpadded: the fast
    /// reply reflects load only). RETRY, reject.
    #[error("RETRY: admission full")]
    SlotsFull,
    /// The input was longer than `max_input_len`. Checked before admission
    /// and before any secret-dependent work, returned immediately. The
    /// length is already known to the sender. RETRY, reject.
    #[error("RETRY: input too large")]
    InputTooLarge,
    /// The operation finished after the hard ceiling
    /// (`ceiling * hard_ceiling_buckets`), or (async API) was cancelled
    /// there. Its result, or the cancelled future, is dropped first, inside
    /// the padded time. The reply is then released at the first whole
    /// multiple of the retry window
    /// (`hard ceiling * retry_release_factor`) at or after that drop
    /// finished (async API: and at or after the hard ceiling plus
    /// [`crate::config::ASYNC_TIMER_SLACK`]). Never released at the raw
    /// completion time. RETRY, reject.
    #[error("RETRY: hard ceiling overrun")]
    Overrun,
    /// The pad is halted after a clock failure. Returned immediately until
    /// an operator calls reset. TERMINAL_BREACH, halt.
    #[error("TERMINAL_BREACH: halted")]
    Halted,
    /// The monotonic clock went backwards, stopped advancing, or produced a
    /// time that does not fit. Padding cannot be trusted without a clock,
    /// so the pad halts. The reply is released immediately (there is no
    /// trustworthy time to wait for). TERMINAL_BREACH, halt.
    #[error("TERMINAL_BREACH: monotonic clock failure")]
    ClockFailure,
    /// Async API only: the call is not running inside a tokio runtime with
    /// the time driver enabled, so there is no timer to pad with. Checked
    /// before admission and before any secret-dependent work, returned
    /// immediately. The pad itself is fine, so it is not halted, but
    /// resubmitting on the same runtime can never succeed. A deployment
    /// error: run [`crate::CeilingPad::check_async_runtime`] once at
    /// startup. TERMINAL_BREACH, reject.
    #[error("TERMINAL_BREACH: no tokio timer")]
    TimerUnavailable,
}

impl Trip {
    /// CNS outcome.
    pub const fn gate_outcome(self) -> GateOutcome {
        match self {
            Trip::SlotsFull | Trip::InputTooLarge | Trip::Overrun => GateOutcome::Retry,
            Trip::Halted | Trip::ClockFailure | Trip::TimerUnavailable => {
                GateOutcome::TerminalBreach
            }
        }
    }

    /// State resolution.
    pub const fn resolution(self) -> Resolution {
        match self {
            Trip::SlotsFull | Trip::InputTooLarge | Trip::Overrun | Trip::TimerUnavailable => {
                Resolution::Reject
            }
            Trip::Halted | Trip::ClockFailure => Resolution::Halt,
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
            Trip::TimerUnavailable => "timer_unavailable",
        }
    }
}

/// When and how a served response was released. Contains only
/// post-padding facts; the operation's own run time is never exposed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReleaseInfo {
    /// Release offset as a multiple of the ceiling: 1 on time, 2 or more
    /// after an overrun.
    pub buckets: u64,
    /// The wait mode actually used (Sleep when the spin budget was empty).
    pub mode: WaitMode,
    /// Observed release offset from admission. What the client sees,
    /// padding included.
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
