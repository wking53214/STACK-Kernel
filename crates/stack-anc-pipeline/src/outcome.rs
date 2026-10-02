//! Typed results and their mapping to the CNS vocabulary.

use thiserror::Error;

/// Mirror of the CNS `GateOutcome` vocabulary (`CNS/cns/gate.py`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum GateOutcome {
    /// The token matched.
    Pass,
    /// Repairable: the caller may resubmit (later, or with a correction).
    Retry,
    /// Not repairable by resubmission. No request-path trip in this crate
    /// produces it; it is listed so the vocabulary matches the kernel.
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

/// The kernel-wide state resolutions. Every trip in this crate resolves to
/// [`Resolution::Reject`]: the gate holds no state besides an in-flight
/// counter that is restored when the request ends, so there is nothing to
/// quarantine, roll back or halt. The other variants are listed so the
/// vocabulary matches the other TACK components.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Resolution {
    /// Nothing changed; the request is refused.
    Reject,
    /// Isolate the input, sender or agent for review. Not used here.
    Quarantine,
    /// Restore the last good snapshot. Not used here.
    Rollback,
    /// Stop accepting work until an operator resets. Not used here.
    Halt,
}

/// Why a request was not accepted. Every variant is a unit variant with a
/// fixed message, so a reply built from it carries one of four fixed codes
/// and nothing derived from the input or the secret. In particular
/// [`Trip::Mismatch`] never says which byte was wrong.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Error)]
pub enum Trip {
    /// Every in-flight slot was taken. Checked before any secret-dependent
    /// work; the fast reply reflects load only. RETRY, reject.
    #[error("RETRY: admission full")]
    SlotsFull,
    /// The input was longer than [`crate::TOKEN_LEN`]. Decided from the
    /// length alone, before a single input byte is read. RETRY, reject.
    #[error("RETRY: input too large")]
    InputTooLarge,
    /// The input was shorter than [`crate::TOKEN_LEN`]. Decided from the
    /// length alone. The sender already knows the length, so the fast reply
    /// reveals nothing. RETRY, reject.
    #[error("RETRY: malformed input")]
    Malformed,
    /// Well-formed token that does not match. The caller may resubmit with
    /// the right token. RETRY, reject. Repeated mismatches from one sender
    /// are a guessing attack; rate limiting and quarantine of the sender
    /// belong to the caller (for example TACK Inlet), not to this crate.
    #[error("RETRY: token mismatch")]
    Mismatch,
}

impl Trip {
    /// CNS outcome. Every trip here is repairable by resubmission.
    pub const fn gate_outcome(self) -> GateOutcome {
        match self {
            Trip::SlotsFull | Trip::InputTooLarge | Trip::Malformed | Trip::Mismatch => {
                GateOutcome::Retry
            }
        }
    }

    /// State resolution.
    pub const fn resolution(self) -> Resolution {
        match self {
            Trip::SlotsFull | Trip::InputTooLarge | Trip::Malformed | Trip::Mismatch => {
                Resolution::Reject
            }
        }
    }

    /// Closed-set metric label.
    pub const fn label(self) -> &'static str {
        match self {
            Trip::SlotsFull => "slots_full",
            Trip::InputTooLarge => "input_too_large",
            Trip::Malformed => "malformed",
            Trip::Mismatch => "mismatch",
        }
    }

    /// Whether the trip happened at admission, before any secret work.
    pub const fn is_admission(self) -> bool {
        !matches!(self, Trip::Mismatch)
    }
}

/// A token that matched.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Accepted;

impl Accepted {
    /// Always [`GateOutcome::Pass`].
    pub const fn gate_outcome(&self) -> GateOutcome {
        GateOutcome::Pass
    }
}

/// Result of one check.
pub type CheckResult = Result<Accepted, Trip>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_trip_is_retry_reject() {
        for t in [
            Trip::SlotsFull,
            Trip::InputTooLarge,
            Trip::Malformed,
            Trip::Mismatch,
        ] {
            assert_eq!(t.gate_outcome(), GateOutcome::Retry);
            assert_eq!(t.resolution(), Resolution::Reject);
            assert_eq!(t.gate_outcome().as_str(), "RETRY");
            assert!(t.to_string().starts_with("RETRY: "));
        }
        assert!(!Trip::Mismatch.is_admission());
        assert!(Trip::InputTooLarge.is_admission());
        assert_eq!(Accepted.gate_outcome().as_str(), "PASS");
        assert_eq!(GateOutcome::TerminalBreach.as_str(), "TERMINAL_BREACH");
    }
}
