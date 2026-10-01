//! Trips (typed refusals) and configuration errors.
//!
//! Every refusal this crate returns is a [`Trip`]. A trip names the operation
//! that refused ([`Op`]), the reason ([`TripReason`]), and, for a repairable
//! refusal, the time at which retrying can succeed. The CNS outcome and the
//! state resolution are derived from the reason, in one table, so they cannot
//! drift apart between call sites.

use crate::clock::Nanos;
use crate::outcome::{GateOutcome, GatePosition, Resolution};

/// The scheduler operation that produced a verdict. Closed set; used as the
/// `op` metric label.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Op {
    /// Putting a request into its lane queue.
    Admit,
    /// Dispatching queued requests for the current phase.
    Poll,
    /// Asking whether a request's green light at a stage has come.
    StageCheck,
    /// Reporting completion and getting the quantized release time.
    Complete,
    /// An operator reset. Only trips when the reset itself finds a clock
    /// regression that no other operation had observed yet.
    Reset,
}

impl Op {
    /// The label value for this operation.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Admit => "admit",
            Self::Poll => "poll",
            Self::StageCheck => "stage_check",
            Self::Complete => "complete",
            Self::Reset => "reset",
        }
    }

    /// Which end of the CNS gate this operation sits at. Admission, dispatch
    /// and stage checks decide whether work may start (ALPHA). Completion
    /// judges a produced result and decides when it may leave (OMEGA). A
    /// reset decides whether work may start again (ALPHA).
    #[must_use]
    pub const fn position(self) -> GatePosition {
        match self {
            Self::Admit | Self::Poll | Self::StageCheck | Self::Reset => GatePosition::Alpha,
            Self::Complete => GatePosition::Omega,
        }
    }
}

/// Why a check refused. Closed set; used as the `reason` metric label.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TripReason {
    /// The lane's queue is at its cap. RETRY, reject. The caller gets the
    /// start of the lane's next phase as `retry_after`, which is the earliest
    /// time the queue can have drained.
    QueueFull,
    /// The lane id is not in the validated phase table. TERMINAL_BREACH,
    /// reject. Lane identity is assigned upstream (tenant or priority class),
    /// so an unknown lane is a routing fault or a forged claim; letting the
    /// caller "correct" it by picking another lane would be lane hopping.
    UnknownLane,
    /// The stage index is past the green wave table. TERMINAL_BREACH, reject.
    UnknownStage,
    /// The stage's green light has not come yet. RETRY, reject, with
    /// `retry_after` set to the stage's due time.
    NotYetDue,
    /// The completion time is earlier than the dispatch time on the ticket,
    /// so the ticket did not come from this scheduler's timeline.
    /// TERMINAL_BREACH, reject.
    CompletionBeforeDispatch,
    /// The ticket was issued by a different scheduler instance. Every
    /// scheduler carries a process-unique issuer number and stamps it on the
    /// tickets it issues. TERMINAL_BREACH, reject: no correction makes a
    /// foreign ticket valid here.
    ForeignTicket,
    /// The ticket is not live on this scheduler: it was already completed
    /// (a replay), or it expired because its lane dispatched more than its
    /// live-ticket cap of newer requests (see
    /// [`crate::config::live_ticket_cap`]). TERMINAL_BREACH, reject.
    TicketNotLive,
    /// The clock read earlier than a previous reading. TERMINAL_BREACH, halt.
    /// Every bound this crate promises assumes monotonic time, so the
    /// scheduler stops until an operator calls `reset`.
    ClockRegressed,
    /// The scheduler is halted from an earlier clock fault. TERMINAL_BREACH,
    /// halt. Nothing the caller changes repairs it; an operator must reset.
    Halted,
    /// A time or id computation would overflow `u64`. TERMINAL_BREACH,
    /// reject. Only reachable with a clock near the end of its range.
    Overflow,
    /// The tokio driver's dispatch loop did not run to completion because
    /// the runtime would not run its blocking-pool thread (it was shutting
    /// down). TERMINAL_BREACH, reject: nothing was dequeued that was not
    /// handed on, and retrying on a stopping runtime cannot help.
    DriverStopped,
}

impl TripReason {
    /// The label value for this reason.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::QueueFull => "queue_full",
            Self::UnknownLane => "unknown_lane",
            Self::UnknownStage => "unknown_stage",
            Self::NotYetDue => "not_yet_due",
            Self::CompletionBeforeDispatch => "completion_before_dispatch",
            Self::ForeignTicket => "foreign_ticket",
            Self::TicketNotLive => "ticket_not_live",
            Self::ClockRegressed => "clock_regressed",
            Self::Halted => "halted",
            Self::Overflow => "overflow",
            Self::DriverStopped => "driver_stopped",
        }
    }

    /// The CNS outcome for this reason. Never PASS: a trip is a refusal.
    #[must_use]
    pub const fn outcome(self) -> GateOutcome {
        match self {
            Self::QueueFull | Self::NotYetDue => GateOutcome::Retry,
            Self::UnknownLane
            | Self::UnknownStage
            | Self::CompletionBeforeDispatch
            | Self::ForeignTicket
            | Self::TicketNotLive
            | Self::ClockRegressed
            | Self::Halted
            | Self::Overflow
            | Self::DriverStopped => GateOutcome::TerminalBreach,
        }
    }

    /// The state resolution for this reason.
    #[must_use]
    pub const fn resolution(self) -> Resolution {
        match self {
            Self::ClockRegressed | Self::Halted => Resolution::Halt,
            Self::QueueFull
            | Self::UnknownLane
            | Self::UnknownStage
            | Self::NotYetDue
            | Self::CompletionBeforeDispatch
            | Self::ForeignTicket
            | Self::TicketNotLive
            | Self::Overflow
            | Self::DriverStopped => Resolution::Reject,
        }
    }
}

/// A typed refusal. Returned, never panicked.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error(
    "tack-greenwave {} refused: {} ({}, {})",
    .op.as_str(),
    .reason.as_str(),
    .reason.outcome().as_str(),
    .reason.resolution().as_str()
)]
pub struct Trip {
    op: Op,
    reason: TripReason,
    retry_after: Option<Nanos>,
}

impl Trip {
    pub(crate) const fn new(op: Op, reason: TripReason, retry_after: Option<Nanos>) -> Self {
        Self {
            op,
            reason,
            retry_after,
        }
    }

    /// The operation that refused.
    #[must_use]
    pub const fn op(&self) -> Op {
        self.op
    }

    /// Why it refused.
    #[must_use]
    pub const fn reason(&self) -> TripReason {
        self.reason
    }

    /// The CNS outcome: RETRY or TERMINAL_BREACH, never PASS.
    #[must_use]
    pub const fn outcome(&self) -> GateOutcome {
        self.reason.outcome()
    }

    /// The state resolution.
    #[must_use]
    pub const fn resolution(&self) -> Resolution {
        self.reason.resolution()
    }

    /// Which end of the CNS gate refused.
    #[must_use]
    pub const fn position(&self) -> GatePosition {
        self.op.position()
    }

    /// For a RETRY, the clock time at which retrying can succeed. `None` for
    /// a terminal breach.
    #[must_use]
    pub const fn retry_after(&self) -> Option<Nanos> {
        self.retry_after
    }
}

/// A configuration the scheduler refuses to build from.
///
/// Building fails closed: no scheduler exists until the whole configuration
/// validates. The CNS reading is TERMINAL_BREACH with resolution halt (the
/// component never starts), because no request can repair a bad table.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ConfigError {
    /// No lanes were configured.
    #[error("no lanes configured")]
    NoLanes,
    /// More lanes than [`crate::config::MAX_LANES`].
    #[error("{count} lanes exceeds the cap of {max}")]
    TooManyLanes {
        /// Lanes configured.
        count: usize,
        /// The cap.
        max: usize,
    },
    /// A lane has weight zero and would never get a phase.
    #[error("lane {lane} has weight 0; every lane needs at least one phase")]
    ZeroWeight {
        /// Index of the lane.
        lane: usize,
    },
    /// Lane weights do not add up to the number of phases per epoch.
    #[error("lane weights sum to {sum}, but phases_per_epoch is {phases}")]
    WeightSumMismatch {
        /// Sum of the weights.
        sum: u64,
        /// Phases per epoch.
        phases: u32,
    },
    /// Phases per epoch is zero or above [`crate::config::MAX_PHASES_PER_EPOCH`].
    #[error("phases_per_epoch {phases} is outside 1..={max}")]
    PhasesOutOfRange {
        /// Configured value.
        phases: u32,
        /// The cap.
        max: u32,
    },
    /// Phase length is below [`crate::config::MIN_PHASE_LEN_NS`].
    #[error("phase_len_ns {phase_len_ns} is below the minimum {min}")]
    PhaseTooShort {
        /// Configured value.
        phase_len_ns: Nanos,
        /// The minimum.
        min: Nanos,
    },
    /// Phase length is below [`crate::config::DRIVER_MIN_PHASE_LEN_NS`], the
    /// shortest phase the tokio driver can keep. Only
    /// [`crate::GreenWaveDriver::new`] returns this; the pure core accepts
    /// shorter phases for simulation.
    #[error("phase_len_ns {phase_len_ns} is below the driver minimum {min}")]
    PhaseTooShortForDriver {
        /// Configured value.
        phase_len_ns: Nanos,
        /// The driver minimum.
        min: Nanos,
    },
    /// Phase length times phases per epoch exceeds [`crate::config::MAX_EPOCH_NS`].
    #[error("epoch length exceeds the cap of {max} ns")]
    EpochTooLong {
        /// The cap.
        max: Nanos,
    },
    /// A lane's queue cap is zero or above [`crate::config::MAX_QUEUE_CAP`].
    #[error("lane {lane} queue_cap {cap} is outside 1..={max}")]
    QueueCapOutOfRange {
        /// Index of the lane.
        lane: usize,
        /// Configured value.
        cap: u32,
        /// The cap.
        max: u32,
    },
    /// The sum of all queue caps exceeds [`crate::config::MAX_TOTAL_QUEUED`].
    #[error("total queue capacity {total} exceeds the cap of {max}")]
    TotalQueueTooLarge {
        /// Sum of the lane caps.
        total: u64,
        /// The cap.
        max: u64,
    },
    /// Per-phase dispatch budget is zero or above
    /// [`crate::config::MAX_DISPATCH_PER_PHASE`].
    #[error("max_dispatch_per_phase {value} is outside 1..={max}")]
    DispatchBudgetOutOfRange {
        /// Configured value.
        value: u32,
        /// The cap.
        max: u32,
    },
    /// No green wave stages were configured.
    #[error("no stages configured")]
    NoStages,
    /// More stages than [`crate::config::MAX_STAGES`].
    #[error("{count} stages exceeds the cap of {max}")]
    TooManyStages {
        /// Stages configured.
        count: usize,
        /// The cap.
        max: usize,
    },
    /// A stage offset is not below phases per epoch, so the wave would not
    /// fit in one epoch and the modulo map would be ambiguous.
    #[error("stage {stage} offset {offset} is not below phases_per_epoch {phases}")]
    OffsetOutOfRange {
        /// Stage index.
        stage: usize,
        /// Configured offset.
        offset: u32,
        /// Phases per epoch.
        phases: u32,
    },
    /// A stage offset is smaller than the one before it. A green wave only
    /// moves forward.
    #[error("stage {stage} offset {offset} is below the previous offset {previous}")]
    OffsetsNotMonotonic {
        /// Stage index.
        stage: usize,
        /// Its offset.
        offset: u32,
        /// The previous stage's offset.
        previous: u32,
    },
    /// Internal consistency check on the built table failed. Should be
    /// unreachable after validation; kept so a bug fails closed.
    #[error("phase table gave lane {lane} {got} phases, expected {expected}")]
    TableMismatch {
        /// Index of the lane.
        lane: usize,
        /// Phases assigned.
        got: usize,
        /// Its weight.
        expected: u32,
    },
}

impl ConfigError {
    /// The label value for this error, for `tack_greenwave_config_rejected_total`.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::NoLanes => "no_lanes",
            Self::TooManyLanes { .. } => "too_many_lanes",
            Self::ZeroWeight { .. } => "zero_weight",
            Self::WeightSumMismatch { .. } => "weight_sum_mismatch",
            Self::PhasesOutOfRange { .. } => "phases_out_of_range",
            Self::PhaseTooShort { .. } => "phase_too_short",
            Self::PhaseTooShortForDriver { .. } => "phase_too_short_for_driver",
            Self::EpochTooLong { .. } => "epoch_too_long",
            Self::QueueCapOutOfRange { .. } => "queue_cap_out_of_range",
            Self::TotalQueueTooLarge { .. } => "total_queue_too_large",
            Self::DispatchBudgetOutOfRange { .. } => "dispatch_budget_out_of_range",
            Self::NoStages => "no_stages",
            Self::TooManyStages { .. } => "too_many_stages",
            Self::OffsetOutOfRange { .. } => "offset_out_of_range",
            Self::OffsetsNotMonotonic { .. } => "offsets_not_monotonic",
            Self::TableMismatch { .. } => "table_mismatch",
        }
    }

    /// Always TERMINAL_BREACH: no request repairs a bad configuration.
    #[must_use]
    pub const fn outcome(&self) -> GateOutcome {
        GateOutcome::TerminalBreach
    }

    /// Always halt: the scheduler is never constructed.
    #[must_use]
    pub const fn resolution(&self) -> Resolution {
        Resolution::Halt
    }
}
