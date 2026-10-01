//! Metrics, span names and log events.
//!
//! Every metric name starts `tack_minotaur_`. Labels come only from closed
//! enums ([`crate::Reason`], [`crate::GateOutcome`], [`crate::Detector`] and
//! [`WalkEnd`]). Nothing derived from a fingerprint or any caller data is
//! ever a label, because a free-form label is a cardinality attack (each new
//! value creates a new time series in the metrics store).
//!
//! Nothing is emitted per step or per descent: the hot path only enters a
//! `trace`-level span, which costs a static check when tracing is off.
//! Metrics fire when a walk ends (trip or rewind), when the Thread degrades,
//! halts, or is reset by an operator.
//!
//! Log events never carry fingerprints or states. A trip event carries the
//! breadcrumb path's length and the full 64-character SHA-256 hex digest of
//! the path padded to `breadcrumb_len` slots (see [`path_digest`]), so two
//! log lines can be matched to the same path without revealing it.
//!
//! Refusals that change nothing (`reason="halted"` and
//! `reason="stale_guard"`) are counted but logged at debug level only, so a
//! caller spinning on a refused call cannot flood the log.

use std::time::Duration;

use metrics::{counter, describe_counter, describe_histogram, histogram, Unit};
use sha2::{Digest, Sha256};

use crate::config::usize_to_u64;
use crate::fingerprint::Fingerprint;
use crate::trip::{Trip, TripKind};

/// Counter, labels `reason` and `outcome`: one per trip, including refusals
/// while halted (`reason="halted"`).
pub const TRIPS_TOTAL: &str = "tack_minotaur_trips_total";
/// Counter, label `detector` (`exact`, `brent` or `recent`): loops found.
pub const LOOPS_DETECTED_TOTAL: &str = "tack_minotaur_loops_detected_total";
/// Counter, no labels: trips resolved by rewinding to the anchor (every trip
/// except a refusal while halted and a refusal through a stale guard).
pub const ROLLBACKS_TOTAL: &str = "tack_minotaur_rollbacks_total";
/// Counter, no labels: times a Thread entered the halted state.
pub const HALTS_TOTAL: &str = "tack_minotaur_halts_total";
/// Counter, no labels: `operator_reset` calls.
pub const OPERATOR_RESETS_TOTAL: &str = "tack_minotaur_operator_resets_total";
/// Counter, no labels: walks whose exact set filled up, switching them to
/// Brent's detection. Counted once per walk.
pub const DEGRADED_TOTAL: &str = "tack_minotaur_degraded_total";
/// Histogram, label `end`: transitions recorded in a walk when it ended.
pub const WALK_STEPS: &str = "tack_minotaur_walk_steps";
/// Histogram, label `end`: deepest depth reached in a walk.
pub const WALK_MAX_DEPTH: &str = "tack_minotaur_walk_max_depth";
/// Histogram, label `end`: states held in the exact set when a walk ended.
pub const WALK_DISTINCT_STATES: &str = "tack_minotaur_walk_distinct_states";
/// Histogram, label `end`: wall time from the anchor to the end of a walk,
/// in seconds.
pub const WALK_DURATION_SECONDS: &str = "tack_minotaur_walk_duration_seconds";

/// Span names.
pub mod spans {
    /// One `descend` call (trace level).
    pub const DESCEND: &str = "tack.minotaur.descend";
    /// One `record` call (trace level).
    pub const RECORD: &str = "tack.minotaur.record";
    /// Handling a trip: rewind, metrics, log event (info level).
    pub const TRIP: &str = "tack.minotaur.trip";
    /// A caller-initiated rewind to the anchor (debug level).
    pub const REWIND: &str = "tack.minotaur.rewind";
    /// An operator reset that clears a halt (info level).
    pub const OPERATOR_RESET: &str = "tack.minotaur.operator_reset";
}

/// How a walk ended; the `end` label on walk histograms.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum WalkEnd {
    /// A cap tripped and the Thread rewound itself.
    Trip,
    /// The caller called `rewind` after finishing its work.
    Rewind,
    /// An operator reset.
    OperatorReset,
}

impl WalkEnd {
    /// The `end` label value.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Trip => "trip",
            Self::Rewind => "rewind",
            Self::OperatorReset => "operator_reset",
        }
    }
}

/// Register descriptions and units with the installed recorder. Optional;
/// call once at start-up if the exporter shows descriptions.
pub fn describe_metrics() {
    describe_counter!(TRIPS_TOTAL, "Minotaur trips, by reason and CNS outcome");
    describe_counter!(LOOPS_DETECTED_TOTAL, "Loops found, by detector");
    describe_counter!(ROLLBACKS_TOTAL, "Trips resolved by rewinding to the anchor");
    describe_counter!(HALTS_TOTAL, "Threads that entered the halted state");
    describe_counter!(OPERATOR_RESETS_TOTAL, "Operator resets of a Thread");
    describe_counter!(
        DEGRADED_TOTAL,
        "Walks that filled the exact set and degraded to Brent"
    );
    describe_histogram!(
        WALK_STEPS,
        Unit::Count,
        "Transitions in a walk when it ended"
    );
    describe_histogram!(
        WALK_MAX_DEPTH,
        Unit::Count,
        "Deepest depth reached in a walk"
    );
    describe_histogram!(
        WALK_DISTINCT_STATES,
        Unit::Count,
        "States in the exact set when a walk ended"
    );
    describe_histogram!(
        WALK_DURATION_SECONDS,
        Unit::Seconds,
        "Time from anchor to end of a walk"
    );
}

/// Summary of a walk, recorded when it ends.
#[derive(Debug, Clone, Copy)]
pub(crate) struct WalkStats {
    pub steps: u64,
    pub max_depth: u32,
    pub distinct: usize,
    pub elapsed: Duration,
}

pub(crate) fn walk_ended(end: WalkEnd, s: WalkStats) {
    let e = end.as_str();
    // Precision loss above 2^53 steps is irrelevant for a histogram.
    #[allow(clippy::cast_precision_loss)]
    let steps = s.steps as f64;
    histogram!(WALK_STEPS, "end" => e).record(steps);
    histogram!(WALK_MAX_DEPTH, "end" => e).record(f64::from(s.max_depth));
    #[allow(clippy::cast_precision_loss)]
    let distinct = usize_to_u64(s.distinct) as f64;
    histogram!(WALK_DISTINCT_STATES, "end" => e).record(distinct);
    histogram!(WALK_DURATION_SECONDS, "end" => e).record(s.elapsed.as_secs_f64());
}

pub(crate) fn degraded(tracked: usize, steps: u64) {
    counter!(DEGRADED_TOTAL).increment(1);
    tracing::info!(
        target: "tack.minotaur",
        tracked,
        steps,
        "exact revisit set full; degrading to Brent cycle detection"
    );
}

pub(crate) fn operator_reset(was_halted: bool, trips: u32) {
    counter!(OPERATOR_RESETS_TOTAL).increment(1);
    tracing::info!(target: "tack.minotaur", was_halted, trips, "operator reset");
}

/// Full SHA-256 hex of the concatenated bytes of `padded`, the breadcrumb
/// path followed by all-zero fingerprints up to `breadcrumb_len` slots.
///
/// The Thread always passes exactly `breadcrumb_len` slots and computes this
/// on every trip, whatever the log level, so the cost of a trip does not
/// depend on how long the walk ran or on the logging configuration.
pub(crate) fn path_digest(padded: &[Fingerprint]) -> String {
    let mut h = Sha256::new();
    for fp in padded {
        h.update(fp.as_bytes());
    }
    hex::encode(h.finalize())
}

/// Metrics and one log event for a trip. `halted_now` is true when this
/// trip is the one that moved the Thread into the halted state. `digest` is
/// the precomputed [`path_digest`]; `None` for refusals, which have no path.
pub(crate) fn trip(t: &Trip, halted_now: bool, digest: Option<&str>) {
    let reason = t.reason().as_str();
    let outcome = t.outcome.as_str();
    counter!(TRIPS_TOTAL, "reason" => reason, "outcome" => outcome).increment(1);
    if let TripKind::LoopDetected { detector, .. } = t.kind {
        counter!(LOOPS_DETECTED_TOTAL, "detector" => detector.as_str()).increment(1);
    }
    let refusal = matches!(t.kind, TripKind::Halted | TripKind::StaleGuard);
    if !refusal {
        counter!(ROLLBACKS_TOTAL).increment(1);
    }
    if halted_now {
        counter!(HALTS_TOTAL).increment(1);
    }

    if refusal {
        // A halted Thread under load, or a caller spinning on a stale guard,
        // would otherwise flood the log at warn.
        tracing::debug!(target: "tack.minotaur", reason, outcome, "refused; nothing changed");
        return;
    }
    let path_sha256 = digest.unwrap_or_default();
    let period = t.period().unwrap_or(0);
    let resolution = t.resolution.as_str();
    if halted_now {
        tracing::error!(
            target: "tack.minotaur",
            reason, outcome, resolution, period,
            depth = t.depth, steps = t.steps,
            path_len = t.path.len(),
            path_sha256,
            "minotaur trip; thread halted until operator reset"
        );
    } else if tracing::enabled!(target: "tack.minotaur", tracing::Level::WARN) {
        tracing::warn!(
            target: "tack.minotaur",
            reason, outcome, resolution, period,
            depth = t.depth, steps = t.steps,
            path_len = t.path.len(),
            path_sha256,
            "minotaur trip; rewound to anchor"
        );
    }
}
