//! The verdict vocabulary shared across the TACK kernel.
//!
//! These enums mirror `GateOutcome` and `GatePosition` in the CNS contracts
//! package (`cns/gate.py`). They are redeclared here, not imported, because
//! CNS is a Python package and this crate must stand alone. The string forms
//! returned by `as_str` are the CNS row values exactly, so a verdict from
//! this crate can be written into a CNS `GateResult` without translation.

/// The result of a gate, in the CNS vocabulary.
///
/// The derived ordering is by severity: `Pass < Retry < TerminalBreach`.
/// That lets a set of trips be resolved the way CNS `resolve` does it: any
/// terminal breach wins, then any retry, and PASS only when nothing objected.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum GateOutcome {
    /// Nothing objected. The normalized values may be used.
    Pass,
    /// Repairable. The caller may resubmit with a correction.
    Retry,
    /// Abort. No correction to this request repairs it.
    TerminalBreach,
}

impl GateOutcome {
    /// The CNS row value, also used as the `outcome` metric label.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Pass => "pass",
            Self::Retry => "retry",
            Self::TerminalBreach => "terminal_breach",
        }
    }
}

/// Which end of the CNS two-ended gate a check runs at.
///
/// ALPHA runs before execution, so its failure means the work never starts.
/// OMEGA runs on the produced result. Bumpers always run at ALPHA: they judge
/// the parameters of a request before anything acts on them.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum GatePosition {
    /// Precondition, evaluated before execution.
    Alpha,
    /// Outcome condition, evaluated on the result.
    Omega,
}

impl GatePosition {
    /// The CNS row value.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Alpha => "alpha",
            Self::Omega => "omega",
        }
    }
}

/// What happens to state when a check trips. The kernel allows exactly one.
///
/// The bumper only ever produces [`Resolution::Reject`]. It is a pure
/// function of its configuration and the request: it holds no state that
/// could be rolled back, it has no identity for a sender that it could
/// quarantine, and one bad request is not a reason to stop serving the next
/// one. The other variants exist so that the whole kernel speaks one
/// vocabulary. A caller that tracks senders can escalate to quarantine
/// using the bumper's trip counters.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Resolution {
    /// Nothing changed. The request is refused as a whole.
    Reject,
    /// The input, sender or agent is isolated for review and counted.
    Quarantine,
    /// State is restored to the last good snapshot.
    Rollback,
    /// The component stops accepting work until an operator resets it.
    Halt,
}

impl Resolution {
    /// A stable lowercase name for records.
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn severity_order_matches_cns_resolve() {
        assert!(GateOutcome::Pass < GateOutcome::Retry);
        assert!(GateOutcome::Retry < GateOutcome::TerminalBreach);
    }

    #[test]
    fn row_values_match_cns() {
        assert_eq!(GateOutcome::Pass.as_str(), "pass");
        assert_eq!(GateOutcome::Retry.as_str(), "retry");
        assert_eq!(GateOutcome::TerminalBreach.as_str(), "terminal_breach");
        assert_eq!(GatePosition::Alpha.as_str(), "alpha");
        assert_eq!(GatePosition::Omega.as_str(), "omega");
        assert_eq!(Resolution::Reject.as_str(), "reject");
        assert_eq!(Resolution::Quarantine.as_str(), "quarantine");
        assert_eq!(Resolution::Rollback.as_str(), "rollback");
        assert_eq!(Resolution::Halt.as_str(), "halt");
    }
}
