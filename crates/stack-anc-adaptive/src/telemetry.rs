//! Metrics and log helpers.
//!
//! Rules this module follows:
//! * Every metric and log line is emitted AFTER the release time (or on an
//!   unpadded early reject, where no secret-dependent work ran), never
//!   inside the padded window.
//! * Every label value comes from a closed enum in this crate: `strategy`
//!   is always `adaptive`, `controller` is `naive` or `epoch`. Nothing from
//!   a request becomes a label.
//! * No metric carries the operation's own run time. The only duration
//!   histogram is the observed, post-padding response time, which the
//!   client already sees. Spin CPU is exported as the fixed amount RESERVED
//!   at admission, not the amount actually spun (the actual spin is the
//!   target minus the work time, a direct pre-padding leak).
//! * The target is exported as a gauge for the epoch controller only. Its
//!   value is a public ladder level. The naive target is a window
//!   statistic of pre-padding work times, so it is not exported.
//! * Inputs are logged as length plus full SHA-256 hex, never raw, and only
//!   at debug level.

use crate::controller::{Changes, ControllerKind, ControllerStatus};
use crate::outcome::{GateOutcome, Trip};
use sha2::{Digest, Sha256};
use std::time::Duration;

/// Value of the `strategy` label on every metric this crate emits.
pub const STRATEGY: &str = "adaptive";

/// Metric names (component `anc`). Every metric carries the labels
/// `strategy` (`adaptive`) and `controller` (`naive` | `epoch`), plus the
/// ones listed.
pub mod names {
    /// Counter, label `outcome` (`pass` | `retry` | `terminal_breach`). One
    /// increment per request.
    pub const REQUESTS_TOTAL: &str = "stack_anc_requests_total";
    /// Counter, label `reason` (`slots_full` | `input_too_large` |
    /// `halted`). Requests refused at admission, before secret work.
    pub const SHED_TOTAL: &str = "stack_anc_shed_total";
    /// Counter, label `disposition` (`late`: naive released at completion;
    /// `escalated`: epoch released at a higher level; `retry`: past the
    /// cap, value discarded).
    pub const OVERRUN_TOTAL: &str = "stack_anc_overrun_total";
    /// Counter, label `direction` (`increase` | `decrease` | `rollback`).
    /// Target changes; each epoch doubling or halving counts one.
    pub const TARGET_CHANGES_TOTAL: &str = "stack_anc_target_changes_total";
    /// Gauge. Leak bound spent in the current accounting window (epoch) or
    /// since construction (naive), in bits.
    pub const LEAK_BUDGET_BITS: &str = "stack_anc_leak_budget_bits";
    /// Gauge, epoch only. The configured leak budget per window, in bits.
    pub const LEAK_BUDGET_LIMIT_BITS: &str = "stack_anc_leak_budget_limit_bits";
    /// Counter, epoch only. Times a leak budget was spent (each freezes
    /// the controller at the cap, until the next window boundary or, for
    /// the lifetime budget, until an operator reset).
    pub const LEAK_BUDGET_EXHAUSTED_TOTAL: &str = "stack_anc_leak_budget_exhausted_total";
    /// Gauge. Charged bound summed over every accounting window since
    /// construction or the last operator reset (epoch), or equal to
    /// `stack_anc_leak_budget_bits` (naive), in bits.
    pub const LEAK_LIFETIME_BITS: &str = "stack_anc_leak_lifetime_bits";
    /// Gauge, epoch only. The configured lifetime budget, in bits.
    pub const LEAK_LIFETIME_LIMIT_BITS: &str = "stack_anc_leak_lifetime_limit_bits";
    /// Counter, epoch only. Times the lifetime budget was spent (each
    /// freezes the controller until an operator reset).
    pub const LEAK_LIFETIME_EXHAUSTED_TOTAL: &str = "stack_anc_leak_lifetime_exhausted_total";
    /// Gauge. 1 while the controller is frozen, 0 otherwise.
    pub const CONTROLLER_FROZEN: &str = "stack_anc_controller_frozen";
    /// Gauge. 1 while the controller is frozen until an operator reset, 0
    /// otherwise.
    pub const CONTROLLER_FROZEN_UNTIL_RESET: &str = "stack_anc_controller_frozen_until_reset";
    /// Counter. Operations that panicked inside the pad (each caught,
    /// padded, and returned as `Trip::OperationPanicked`).
    pub const OPERATION_PANICS_TOTAL: &str = "stack_anc_operation_panics_total";
    /// Gauge, epoch only. Current target, seconds (a public ladder level).
    pub const TARGET_SECONDS: &str = "stack_anc_target_seconds";
    /// Counter, label `mode` (`hybrid`). Requests whose spin charge the
    /// budget could not cover, so they slept.
    pub const SPIN_FALLBACK_TOTAL: &str = "stack_anc_spin_fallback_total";
    /// Counter. Spin CPU nanoseconds reserved from the budget (an upper
    /// bound on the spin actually done). Nanoseconds because metrics
    /// counters are integers.
    pub const SPIN_RESERVED_NANOSECONDS_TOTAL: &str = "stack_anc_spin_reserved_nanoseconds_total";
    /// Counter. Clock failures (each also halts the pad).
    pub const CLOCK_FAILURES_TOTAL: &str = "stack_anc_clock_failures_total";
    /// Counter, label `scope` (`pad`: halt lifted; `controller`: freeze
    /// lifted). Operator resets.
    pub const RESETS_TOTAL: &str = "stack_anc_resets_total";
    /// Gauge. 1 while the pad is halted, 0 otherwise.
    pub const HALTED: &str = "stack_anc_halted";
    /// Histogram, label `outcome`. Observed response time from admission to
    /// release, seconds, post-padding only.
    pub const RESPONSE_SECONDS: &str = "stack_anc_response_seconds";
}

/// Which overrun counter to bump.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum OverrunKind {
    Late,
    Escalated,
    Retry,
}

impl OverrunKind {
    const fn label(self) -> &'static str {
        match self {
            OverrunKind::Late => "late",
            OverrunKind::Escalated => "escalated",
            OverrunKind::Retry => "retry",
        }
    }
}

/// What happened to one request, gathered so that telemetry is emitted in
/// one place after release.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Event {
    pub kind: ControllerKind,
    pub outcome: GateOutcome,
    pub trip: Option<Trip>,
    pub overrun: Option<OverrunKind>,
    pub fallback: bool,
    pub reserved_spin: Duration,
    pub observed: Duration,
    pub changes: Changes,
    pub status: Option<ControllerStatus>,
}

impl Event {
    pub(crate) fn early(kind: ControllerKind, trip: Trip, observed: Duration) -> Self {
        Self {
            kind,
            outcome: trip.gate_outcome(),
            trip: Some(trip),
            overrun: None,
            fallback: false,
            reserved_spin: Duration::ZERO,
            observed,
            changes: Changes::default(),
            status: None,
        }
    }
}

pub(crate) fn emit(ev: &Event) {
    let c = ev.kind.label();
    metrics::counter!(
        names::REQUESTS_TOTAL,
        "strategy" => STRATEGY,
        "controller" => c,
        "outcome" => ev.outcome.label()
    )
    .increment(1);
    metrics::histogram!(
        names::RESPONSE_SECONDS,
        "strategy" => STRATEGY,
        "controller" => c,
        "outcome" => ev.outcome.label()
    )
    .record(ev.observed.as_secs_f64());
    match ev.trip {
        Some(t @ (Trip::SlotsFull | Trip::InputTooLarge | Trip::Halted)) => {
            metrics::counter!(
                names::SHED_TOTAL,
                "strategy" => STRATEGY,
                "controller" => c,
                "reason" => t.label()
            )
            .increment(1);
        }
        Some(Trip::ClockFailure) => {
            metrics::counter!(names::CLOCK_FAILURES_TOTAL, "strategy" => STRATEGY, "controller" => c)
                .increment(1);
            metrics::gauge!(names::HALTED, "strategy" => STRATEGY, "controller" => c).set(1.0);
        }
        Some(Trip::OperationPanicked) => {
            metrics::counter!(names::OPERATION_PANICS_TOTAL, "strategy" => STRATEGY, "controller" => c)
                .increment(1);
        }
        Some(Trip::Overrun) | None => {}
    }
    if let Some(o) = ev.overrun {
        metrics::counter!(
            names::OVERRUN_TOTAL,
            "strategy" => STRATEGY,
            "controller" => c,
            "disposition" => o.label()
        )
        .increment(1);
    }
    if ev.fallback {
        metrics::counter!(
            names::SPIN_FALLBACK_TOTAL,
            "strategy" => STRATEGY,
            "controller" => c,
            "mode" => "hybrid"
        )
        .increment(1);
    }
    if !ev.reserved_spin.is_zero() {
        let ns = u64::try_from(ev.reserved_spin.as_nanos()).unwrap_or(u64::MAX);
        metrics::counter!(
            names::SPIN_RESERVED_NANOSECONDS_TOTAL,
            "strategy" => STRATEGY,
            "controller" => c
        )
        .increment(ns);
    }
    emit_changes(ev.kind, &ev.changes);
    if let Some(s) = &ev.status {
        emit_status(s);
    }
}

pub(crate) fn emit_changes(kind: ControllerKind, ch: &Changes) {
    let c = kind.label();
    let dirs = [
        ("increase", u64::from(ch.increases)),
        ("decrease", u64::from(ch.decreases)),
        ("rollback", u64::from(ch.rollback)),
    ];
    for (direction, n) in dirs {
        if n > 0 {
            metrics::counter!(
                names::TARGET_CHANGES_TOTAL,
                "strategy" => STRATEGY,
                "controller" => c,
                "direction" => direction
            )
            .increment(n);
        }
    }
    if ch.exhausted {
        metrics::counter!(
            names::LEAK_BUDGET_EXHAUSTED_TOTAL,
            "strategy" => STRATEGY,
            "controller" => c
        )
        .increment(1);
    }
    if ch.lifetime_exhausted {
        metrics::counter!(
            names::LEAK_LIFETIME_EXHAUSTED_TOTAL,
            "strategy" => STRATEGY,
            "controller" => c
        )
        .increment(1);
    }
}

pub(crate) fn emit_status(s: &ControllerStatus) {
    let c = s.kind.label();
    metrics::gauge!(names::LEAK_BUDGET_BITS, "strategy" => STRATEGY, "controller" => c)
        .set(s.leak_bits);
    metrics::gauge!(names::LEAK_LIFETIME_BITS, "strategy" => STRATEGY, "controller" => c)
        .set(s.lifetime_bits);
    metrics::gauge!(names::CONTROLLER_FROZEN, "strategy" => STRATEGY, "controller" => c)
        .set(if s.frozen { 1.0 } else { 0.0 });
    metrics::gauge!(names::CONTROLLER_FROZEN_UNTIL_RESET, "strategy" => STRATEGY, "controller" => c)
        .set(if s.frozen_until_reset { 1.0 } else { 0.0 });
    if let Some(limit) = s.leak_budget_bits {
        metrics::gauge!(names::LEAK_BUDGET_LIMIT_BITS, "strategy" => STRATEGY, "controller" => c)
            .set(limit);
    }
    if let Some(limit) = s.lifetime_budget_bits {
        metrics::gauge!(names::LEAK_LIFETIME_LIMIT_BITS, "strategy" => STRATEGY, "controller" => c)
            .set(limit);
    }
    if s.kind == ControllerKind::Epoch {
        metrics::gauge!(names::TARGET_SECONDS, "strategy" => STRATEGY, "controller" => c)
            .set(s.target.as_secs_f64());
    }
}

pub(crate) fn emit_reset(kind: ControllerKind, scope: &'static str) {
    let c = kind.label();
    metrics::counter!(
        names::RESETS_TOTAL,
        "strategy" => STRATEGY,
        "controller" => c,
        "scope" => scope
    )
    .increment(1);
    if scope == "pad" {
        metrics::gauge!(names::HALTED, "strategy" => STRATEGY, "controller" => c).set(0.0);
    }
}

/// Full lowercase SHA-256 hex of `input` (64 characters, never truncated).
pub fn sha256_hex(input: &[u8]) -> String {
    hex::encode(Sha256::digest(input))
}

/// Debug log of one request's input: length always, digest only when the
/// input was within `max_input_len` (hashing an oversized input would let
/// the sender choose how much CPU the log line costs). Called after
/// release; the digest is computed only when debug logging is enabled.
pub(crate) fn log_input(input: &[u8], max_input_len: usize, ev: &Event) {
    if !tracing::enabled!(tracing::Level::DEBUG) {
        return;
    }
    let trip = ev.trip.map_or("none", Trip::label);
    if input.len() <= max_input_len {
        let digest = sha256_hex(input);
        tracing::debug!(
            input_len = input.len(),
            input_sha256 = %digest,
            outcome = ev.outcome.as_str(),
            trip,
            controller = ev.kind.label(),
            "adaptive pad released"
        );
    } else {
        tracing::debug!(
            input_len = input.len(),
            input_sha256 = "not computed: input over max_input_len",
            outcome = ev.outcome.as_str(),
            trip,
            controller = ev.kind.label(),
            "adaptive pad rejected oversized input"
        );
    }
}
