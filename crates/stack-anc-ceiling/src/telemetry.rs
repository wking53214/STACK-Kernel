//! Metrics and log helpers.
//!
//! Rules this module follows:
//! * Every metric is emitted AFTER the release time (or on an unpadded
//!   early reject, where there was no secret-dependent work), never inside
//!   the padded window.
//! * Every label value comes from a closed enum in this crate. Nothing from
//!   a request becomes a label.
//! * No metric carries the operation's own run time. The only duration
//!   exported is the observed, post-padding release offset, which is what
//!   the client already sees. Spin CPU is exported as the fixed amount
//!   RESERVED at admission, not the amount actually spun, because the
//!   actual spin is the ceiling minus the work time, a direct pre-padding
//!   leak.
//! * Inputs are logged as length plus full SHA-256 hex, never raw, and only
//!   at debug level.
//! * An admitted async request whose future is dropped before release (for
//!   example a client disconnect) is still counted, as
//!   `stack_anc_requests_total{outcome="cancelled"}` plus its reserved spin.
//!   That is emitted when the future is dropped, after the client left.
//!
//! # Alerts (Prometheus rule expressions)
//!
//! Every series is shared by all ceiling pads in a process (the only label
//! that identifies the source is `strategy="ceiling"`), so thresholds that
//! depend on configuration use the sum over those pads.
//!
//! * `TackAncCeilingHalted` (critical):
//!   `max(stack_anc_halted{strategy="ceiling"}) > 0`. The gauge counts
//!   halted pads: +1 on the transition to halted, -1 on the reset of a
//!   halted pad. A reset of a pad that is not halted does not touch it, so
//!   one pad's reset cannot clear another pad's halt. A halted pad that is
//!   dropped without a reset keeps the count raised until the process
//!   restarts.
//! * `TackAncCeilingTerminal` (critical):
//!   `increase(stack_anc_requests_total{strategy="ceiling",outcome="terminal_breach"}[5m]) > 0`.
//! * `TackAncCeilingOverrun` (warning):
//!   `increase(stack_anc_overrun_total{strategy="ceiling"}[15m]) > 0`.
//!   Meaning: some work ran past the ceiling. If the work time depends on a
//!   secret, each overrun can leak up to `log2(hard_ceiling_buckets + 1)`
//!   bits, provided the work plus the drop of a discarded value ends
//!   inside the first retry window (`hard ceiling * retry_release_factor`).
//!   Beyond that, in the blocking API each further window of work adds
//!   one more distinguishable RETRY time. Overruns are also visible to
//!   third parties, because an overrunning request holds its slot longer
//!   and so changes who else is shed. Raise the ceiling.
//! * `TackAncCeilingSpinOverBudget` (warning), `for: 10m`:
//!   `rate(stack_anc_spin_reserved_nanoseconds_total{strategy="ceiling"}[5m]) / 1e9 > T`
//!   with `T` from [`spin_over_budget_threshold`] for a 5 minute window
//!   (`cpu_per_second + burst / 300s`, summed over pads). A token bucket
//!   allows up to `cpu_per_second * W + burst` over any window `W`, so a
//!   threshold of `cpu_per_second` alone would fire on a correctly
//!   configured pad at saturation. Above `T` the budget is not doing its
//!   job (a bug, or pads missing from the sum).
//! * `TackAncCeilingCancelled` (info):
//!   `rate(stack_anc_requests_total{strategy="ceiling",outcome="cancelled"}[5m]) > 0`
//!   sustained may be a connect-and-abort flood.

use crate::config::{SpinBudgetConfig, WaitMode};
use crate::outcome::{GateOutcome, Trip};
use sha2::{Digest, Sha256};
use std::time::Duration;

/// Value of the `strategy` label on every metric this crate emits.
pub const STRATEGY: &str = "ceiling";

/// Metric names (component `anc`).
pub mod names {
    /// Counter, labels `strategy`, `outcome` (`pass` | `retry` |
    /// `terminal_breach` | `cancelled`). One increment per request.
    /// `cancelled`: an admitted async request whose future was dropped
    /// before release; not a CNS outcome, the caller never saw a verdict.
    pub const REQUESTS_TOTAL: &str = "stack_anc_requests_total";
    /// Counter, labels `strategy`, `reason` (`slots_full` |
    /// `input_too_large` | `halted` | `timer_unavailable`). Requests refused at admission,
    /// before secret-dependent work.
    pub const SHED_TOTAL: &str = "stack_anc_shed_total";
    /// Counter, labels `strategy`, `disposition` (`released`: value
    /// returned at a later bucket; `retry`: past the hard ceiling, value
    /// discarded).
    pub const OVERRUN_TOTAL: &str = "stack_anc_overrun_total";
    /// Counter, labels `strategy`, `mode` (`spin` | `hybrid`). Requests
    /// whose spin charge the budget could not cover, so they slept.
    pub const SPIN_FALLBACK_TOTAL: &str = "stack_anc_spin_fallback_total";
    /// Counter, label `strategy`. Spin CPU nanoseconds reserved from the
    /// budget (an upper bound on the spin actually done). Nanoseconds
    /// because metrics counters are integers.
    pub const SPIN_RESERVED_NANOSECONDS_TOTAL: &str = "stack_anc_spin_reserved_nanoseconds_total";
    /// Counter, label `strategy`. Clock failures (each also halts the pad).
    pub const CLOCK_FAILURES_TOTAL: &str = "stack_anc_clock_failures_total";
    /// Counter, label `strategy`. Operator resets.
    pub const RESETS_TOTAL: &str = "stack_anc_resets_total";
    /// Gauge, label `strategy`. Number of ceiling pads in this process
    /// currently halted (0 when none).
    pub const HALTED: &str = "stack_anc_halted";
    /// Histogram, labels `strategy`, `outcome`. Observed release offset
    /// from admission, seconds, post-padding only.
    pub const RESPONSE_SECONDS: &str = "stack_anc_response_seconds";
}

/// What happened to one request, gathered so that telemetry is emitted in
/// one place after release.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Event {
    pub outcome: GateOutcome,
    pub trip: Option<Trip>,
    /// `Some(true)` overrun released with value; `Some(false)` overrun retry.
    pub overrun_released: Option<bool>,
    /// The requested mode, when the budget forced a fallback to Sleep.
    pub fallback_from: Option<WaitMode>,
    pub reserved_spin: Duration,
    pub observed: Duration,
    /// This request moved the pad from running to halted.
    pub newly_halted: bool,
}

impl Event {
    pub(crate) fn early(trip: Trip, observed: Duration) -> Self {
        Self {
            outcome: trip.gate_outcome(),
            trip: Some(trip),
            overrun_released: None,
            fallback_from: None,
            reserved_spin: Duration::ZERO,
            observed,
            newly_halted: false,
        }
    }
}

pub(crate) fn emit(ev: &Event) {
    metrics::counter!(
        names::REQUESTS_TOTAL,
        "strategy" => STRATEGY,
        "outcome" => ev.outcome.label()
    )
    .increment(1);
    metrics::histogram!(
        names::RESPONSE_SECONDS,
        "strategy" => STRATEGY,
        "outcome" => ev.outcome.label()
    )
    .record(ev.observed.as_secs_f64());
    match ev.trip {
        Some(
            t @ (Trip::SlotsFull | Trip::InputTooLarge | Trip::Halted | Trip::TimerUnavailable),
        ) => {
            metrics::counter!(names::SHED_TOTAL, "strategy" => STRATEGY, "reason" => t.label())
                .increment(1);
        }
        Some(Trip::ClockFailure) => {
            metrics::counter!(names::CLOCK_FAILURES_TOTAL, "strategy" => STRATEGY).increment(1);
            if ev.newly_halted {
                metrics::gauge!(names::HALTED, "strategy" => STRATEGY).increment(1.0);
            }
        }
        Some(Trip::Overrun) | None => {}
    }
    if let Some(released) = ev.overrun_released {
        let disposition = if released { "released" } else { "retry" };
        metrics::counter!(
            names::OVERRUN_TOTAL,
            "strategy" => STRATEGY,
            "disposition" => disposition
        )
        .increment(1);
    }
    if let Some(mode) = ev.fallback_from {
        metrics::counter!(
            names::SPIN_FALLBACK_TOTAL,
            "strategy" => STRATEGY,
            "mode" => mode.label()
        )
        .increment(1);
    }
    emit_reserved(ev.reserved_spin);
}

fn emit_reserved(reserved: Duration) {
    if !reserved.is_zero() {
        let ns = u64::try_from(reserved.as_nanos()).unwrap_or(u64::MAX);
        metrics::counter!(names::SPIN_RESERVED_NANOSECONDS_TOTAL, "strategy" => STRATEGY)
            .increment(ns);
    }
}

/// An admitted async request was dropped before release.
pub(crate) fn emit_cancelled(reserved: Duration) {
    metrics::counter!(
        names::REQUESTS_TOTAL,
        "strategy" => STRATEGY,
        "outcome" => "cancelled"
    )
    .increment(1);
    emit_reserved(reserved);
    tracing::debug!("ceiling pad request cancelled before release");
}

/// Operator reset. The halted count drops only when this pad was halted.
pub(crate) fn emit_reset(was_halted: bool) {
    metrics::counter!(names::RESETS_TOTAL, "strategy" => STRATEGY).increment(1);
    if was_halted {
        metrics::gauge!(names::HALTED, "strategy" => STRATEGY).decrement(1.0);
    }
}

/// Threshold for the `TackAncCeilingSpinOverBudget` alert, in cores (spin
/// seconds per wall second) averaged over `window`: the most a correctly
/// working budget allows, `(cpu_per_second * window + burst) / window`.
/// `None` for [`SpinBudgetConfig::Unlimited`] or a zero window. For several
/// pads, add their thresholds.
pub fn spin_over_budget_threshold(budget: SpinBudgetConfig, window: Duration) -> Option<f64> {
    match budget {
        SpinBudgetConfig::Limited {
            cpu_per_second,
            burst,
        } if !window.is_zero() => {
            let w = window.as_secs_f64();
            Some((cpu_per_second.as_secs_f64() * w + burst.as_secs_f64()) / w)
        }
        _ => None,
    }
}

/// Full lowercase SHA-256 hex of `input` (64 characters, never truncated).
pub fn sha256_hex(input: &[u8]) -> String {
    hex::encode(Sha256::digest(input))
}

/// Debug log of one request's input: length always, digest only when the
/// input was within `max_input_len` (hashing an oversized input would let
/// the sender choose how much CPU the log line costs). Called after
/// release. The digest is computed only when debug logging is enabled.
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
            "ceiling pad released"
        );
    } else {
        tracing::debug!(
            input_len = input.len(),
            input_sha256 = "not computed: input over max_input_len",
            outcome = ev.outcome.as_str(),
            trip,
            "ceiling pad rejected oversized input"
        );
    }
}
