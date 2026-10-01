//! The verdict vocabulary shared across the STACK kernel.
//!
//! These enums mirror `GateOutcome` and `GatePosition` in the CNS contracts
//! package (`cns/gate.py`). They are redeclared here, not imported, because
//! CNS is a Python package and this crate must stand alone. The strings
//! returned by `as_str` are the lower-case forms of the CNS row values, and
//! they double as metric label values.

/// The result of a check, in the CNS vocabulary.
///
/// The derived ordering is by severity: `Pass < Retry < TerminalBreach`, so a
/// set of verdicts resolves the way CNS `resolve` does: any terminal breach
/// wins, then any retry, and PASS only when nothing objected.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum GateOutcome {
    /// Nothing objected.
    Pass,
    /// Repairable. The caller may resubmit, for example after `retry_after`.
    Retry,
    /// Abort. No correction to this request repairs it.
    TerminalBreach,
}

impl GateOutcome {
    /// The label value for this outcome.
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
/// OMEGA runs on the produced result.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum GatePosition {
    /// Precondition, evaluated before execution.
    Alpha,
    /// Outcome condition, evaluated on the result.
    Omega,
}

impl GatePosition {
    /// The label value for this position.
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
/// This crate uses [`Resolution::Reject`] for every request-level trip and
/// [`Resolution::Halt`] for a clock fault. It never quarantines and never
/// rolls back; see the crate documentation for why.
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
    /// The label value for this resolution.
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
