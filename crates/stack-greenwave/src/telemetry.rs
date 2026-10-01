//! Metrics and span names.
//!
//! Every metric name starts with `tack_greenwave_`. Every label value comes
//! from a closed enum in this crate ([`GateOutcome`], [`crate::TripReason`],
//! [`Op`], [`crate::Resolution`], [`ConfigError::as_str`]), never from request data, because
//! a label built from caller data lets the caller create unbounded time
//! series (a cardinality attack on the metrics backend). Lane ids are not
//! used as labels either: they are bounded by configuration, but the rule is
//! closed enums only, and per-lane depth is available from
//! [`crate::TrafficCop::lane_depth`] instead.
//!
//! The scheduler never sees request content (payloads are an opaque generic
//! type it does not inspect), so there is no raw input to log. Logs carry
//! request ids, lane indexes, phase numbers and times on the phase grid.
//!
//! Timing side channel: nothing here records a per-request service time or
//! the hold time between completion and release. Either would expose, to
//! anyone who can read the metrics, the fine-grained completion time that
//! release quantization exists to hide. The one duration histogram,
//! [`QUEUE_WAIT_SECONDS`], measures arrival to dispatch, which is a function
//! of arrival time, lane schedule and queue depth: public inputs only.
//!
//! Tracing timestamps are a second channel. Any subscriber stamps each span
//! and event with the wall clock when it is created, so a span opened inside
//! `complete` records the completion instant even if no field carries it.
//! The `complete` and `stage_check` spans and events are therefore emitted at
//! TRACE level, below the DEBUG and INFO levels a production subscriber is
//! expected to enable. Enabling TRACE for this crate's target gives any trace
//! reader the fine-grained completion and per-stage times; do that only
//! where trace readers are as trusted as the scheduler itself.
//!
//! Gauges are shared by every scheduler in the process (they carry no
//! instance label, because labels come only from closed enums). They are
//! therefore kept as sums, changed by increments and decrements, and never
//! set outright: [`HALTED`] is the number of halted schedulers and
//! [`QUEUE_DEPTH`] the number of requests waiting across all of them. Building
//! a scheduler adds zero to each, so a new scheduler never clears another
//! one's halt.

use crate::clock::Nanos;
use crate::error::{ConfigError, Op, Trip};
use crate::outcome::GateOutcome;

/// Counter, label `outcome`: one per `admit` call.
pub const ADMISSIONS_TOTAL: &str = "tack_greenwave_admissions_total";
/// Counter, labels `op`, `reason`, `outcome`, `resolution`: one per trip.
pub const TRIPS_TOTAL: &str = "tack_greenwave_trips_total";
/// Counter, label `outcome`: one per `poll` call.
pub const POLLS_TOTAL: &str = "tack_greenwave_polls_total";
/// Counter, no labels: one per request dispatched.
pub const DISPATCHED_TOTAL: &str = "tack_greenwave_dispatched_total";
/// Counter, label `outcome`: one per `stage_check` call.
pub const STAGE_CHECKS_TOTAL: &str = "tack_greenwave_stage_checks_total";
/// Counter, no labels: stage checks that passed after the stage's phase had
/// already ended (the wave was broken for that request).
pub const STAGE_LATE_TOTAL: &str = "tack_greenwave_stage_late_total";
/// Counter, label `outcome`: one per `complete` call.
pub const RELEASES_TOTAL: &str = "tack_greenwave_releases_total";
/// Counter, no labels: phases that passed with no poll. A missed phase means
/// the driver fell behind and the no-starvation bound is not guaranteed.
pub const PHASES_MISSED_TOTAL: &str = "tack_greenwave_phases_missed_total";
/// Counter, label `reason`: configurations refused at build time.
pub const CONFIG_REJECTED_TOTAL: &str = "tack_greenwave_config_rejected_total";
/// Counter, no labels: operator resets that cleared a halt or found nothing
/// to clear. A reset that finds an unobserved clock regression trips instead
/// and is counted in [`TRIPS_TOTAL`] with `op="reset"`.
pub const RESETS_TOTAL: &str = "tack_greenwave_resets_total";
/// Counter, no labels: live tickets expired because their lane reached its
/// live-ticket cap. An expired ticket fails `stage_check` and `complete` with
/// `ticket_not_live`.
pub const TICKETS_EXPIRED_TOTAL: &str = "tack_greenwave_tickets_expired_total";
/// Histogram, no labels: seconds from admission to dispatch, on the injected
/// clock.
pub const QUEUE_WAIT_SECONDS: &str = "tack_greenwave_queue_wait_seconds";
/// Gauge, no labels: requests waiting across all lanes of every scheduler in
/// the process.
pub const QUEUE_DEPTH: &str = "tack_greenwave_queue_depth";
/// Gauge, no labels: number of schedulers in the process that are halted.
/// Raised by one on a halt, lowered by one when a halted scheduler is reset
/// or dropped. Alert on `max(tack_greenwave_halted) >= 1`.
pub const HALTED: &str = "tack_greenwave_halted";

/// Span names, `stack.greenwave.<operation>`.
pub mod spans {
    /// Building a scheduler from configuration.
    pub const BUILD: &str = "stack.greenwave.build";
    /// One `admit` call.
    pub const ADMIT: &str = "stack.greenwave.admit";
    /// One `poll` call.
    pub const POLL: &str = "stack.greenwave.poll";
    /// One `stage_check` call.
    pub const STAGE_CHECK: &str = "stack.greenwave.stage_check";
    /// One `complete` call.
    pub const COMPLETE: &str = "stack.greenwave.complete";
    /// One operator `reset`.
    pub const RESET: &str = "stack.greenwave.reset";
    /// The tokio driver's dispatch loop.
    pub const DRIVE: &str = "stack.greenwave.drive";
    /// The tokio driver holding a result until its release time.
    pub const RELEASE_WAIT: &str = "stack.greenwave.release_wait";
}

/// Register descriptions and units with the installed recorder. Optional:
/// the metrics work without it, but exporters show the help text.
pub fn describe_metrics() {
    use metrics::{describe_counter, describe_gauge, describe_histogram, Unit};
    describe_counter!(ADMISSIONS_TOTAL, Unit::Count, "Admit calls, by outcome.");
    describe_counter!(
        TRIPS_TOTAL,
        Unit::Count,
        "Refusals, by operation, reason, outcome and resolution."
    );
    describe_counter!(POLLS_TOTAL, Unit::Count, "Poll calls, by outcome.");
    describe_counter!(DISPATCHED_TOTAL, Unit::Count, "Requests dispatched.");
    describe_counter!(STAGE_CHECKS_TOTAL, Unit::Count, "Stage checks, by outcome.");
    describe_counter!(
        STAGE_LATE_TOTAL,
        Unit::Count,
        "Stage checks that passed after the stage's phase had ended."
    );
    describe_counter!(RELEASES_TOTAL, Unit::Count, "Complete calls, by outcome.");
    describe_counter!(PHASES_MISSED_TOTAL, Unit::Count, "Phases that passed with no poll.");
    describe_counter!(
        CONFIG_REJECTED_TOTAL,
        Unit::Count,
        "Configurations refused at build time, by reason."
    );
    describe_counter!(RESETS_TOTAL, Unit::Count, "Operator resets.");
    describe_counter!(
        TICKETS_EXPIRED_TOTAL,
        Unit::Count,
        "Live tickets expired at their lane's live-ticket cap."
    );
    describe_histogram!(
        QUEUE_WAIT_SECONDS,
        Unit::Seconds,
        "Time from admission to dispatch."
    );
    describe_gauge!(
        QUEUE_DEPTH,
        Unit::Count,
        "Requests waiting across all lanes of every scheduler."
    );
    describe_gauge!(HALTED, Unit::Count, "Number of halted schedulers.");
}

pub(crate) fn record_trip(trip: &Trip) {
    metrics::counter!(
        TRIPS_TOTAL,
        "op" => trip.op().as_str(),
        "reason" => trip.reason().as_str(),
        "outcome" => trip.outcome().as_str(),
        "resolution" => trip.resolution().as_str()
    )
    .increment(1);
}

pub(crate) fn record_op(op: Op, outcome: GateOutcome) {
    let name = match op {
        Op::Admit => ADMISSIONS_TOTAL,
        Op::Poll => POLLS_TOTAL,
        Op::StageCheck => STAGE_CHECKS_TOTAL,
        Op::Complete => RELEASES_TOTAL,
        // Resets are counted in RESETS_TOTAL (no labels) or, when they trip,
        // in TRIPS_TOTAL.
        Op::Reset => return,
    };
    metrics::counter!(name, "outcome" => outcome.as_str()).increment(1);
}

pub(crate) fn record_dispatched(count: u64) {
    metrics::counter!(DISPATCHED_TOTAL).increment(count);
}

pub(crate) fn record_queue_wait(wait: Nanos) {
    // u64 nanoseconds to f64 seconds; precision loss above 2^53 ns (104
    // days) is irrelevant for a wait bounded by a few epochs.
    #[allow(clippy::cast_precision_loss)]
    let secs = wait as f64 / 1e9;
    metrics::histogram!(QUEUE_WAIT_SECONDS).record(secs);
}

pub(crate) fn record_stage_late() {
    metrics::counter!(STAGE_LATE_TOTAL).increment(1);
}

pub(crate) fn record_phases_missed(count: u64) {
    metrics::counter!(PHASES_MISSED_TOTAL).increment(count);
}

pub(crate) fn record_config_rejected(err: &ConfigError) {
    metrics::counter!(CONFIG_REJECTED_TOTAL, "reason" => err.as_str()).increment(1);
}

pub(crate) fn record_reset() {
    metrics::counter!(RESETS_TOTAL).increment(1);
}

pub(crate) fn record_tickets_expired(count: u64) {
    metrics::counter!(TICKETS_EXPIRED_TOTAL).increment(count);
}

/// Register both shared gauges for a new scheduler without changing them.
pub(crate) fn register_gauges() {
    metrics::gauge!(QUEUE_DEPTH).increment(0.0);
    metrics::gauge!(HALTED).increment(0.0);
}

pub(crate) fn queue_depth_add(count: usize) {
    #[allow(clippy::cast_precision_loss)]
    metrics::gauge!(QUEUE_DEPTH).increment(count as f64);
}

pub(crate) fn queue_depth_sub(count: usize) {
    #[allow(clippy::cast_precision_loss)]
    metrics::gauge!(QUEUE_DEPTH).decrement(count as f64);
}

pub(crate) fn halted_enter() {
    metrics::gauge!(HALTED).increment(1.0);
}

pub(crate) fn halted_leave() {
    metrics::gauge!(HALTED).decrement(1.0);
}
