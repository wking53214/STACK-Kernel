//! Metrics and log helpers.
//!
//! Every metric name starts with `tack_bumpers_`. Every label value comes
//! from a closed enum in this crate ([`crate::GateOutcome`],
//! [`crate::TripReason`], [`crate::CorrectionKind`]), never from request
//! data, because a label built from caller text lets the caller create
//! unbounded time series (a cardinality attack on the metrics backend).
//!
//! Raw input is never logged. Where a log line has to identify a value, it
//! carries the value's byte length and the full SHA-256 hex digest. Text
//! over `max_input_bytes` carries its byte length and `input_over_cap=true`
//! instead, never a digest of a prefix.

use std::fmt;
use std::time::Duration;

use sha2::{Digest, Sha256};

use crate::error::TripReason;
use crate::outcome::GateOutcome;

/// Counter, label `outcome`: one per `Bumper::normalize` call.
pub const REQUESTS_TOTAL: &str = "tack_bumpers_requests_total";
/// Counter, labels `reason` and `outcome`: one per trip in a refused request.
pub const TRIPS_TOTAL: &str = "tack_bumpers_trips_total";
/// Counter, label `kind`: one per correction in a request that passed.
pub const CORRECTIONS_TOTAL: &str = "tack_bumpers_corrections_total";
/// Histogram, no labels: corrections applied per request that passed.
pub const CORRECTIONS_PER_REQUEST: &str = "tack_bumpers_corrections_per_request";
/// Histogram, label `outcome`: wall time of `Bumper::normalize` in seconds.
pub const NORMALIZE_DURATION_SECONDS: &str = "tack_bumpers_normalize_duration_seconds";

/// Register descriptions and units with the installed recorder. Optional:
/// the metrics work without it, but exporters show the help text.
pub fn describe_metrics() {
    metrics::describe_counter!(REQUESTS_TOTAL, metrics::Unit::Count, "Bumper normalize calls, by outcome.");
    metrics::describe_counter!(
        TRIPS_TOTAL,
        metrics::Unit::Count,
        "Trips in refused requests, by reason and outcome."
    );
    metrics::describe_counter!(
        CORRECTIONS_TOTAL,
        metrics::Unit::Count,
        "Corrections applied in passing requests, by kind."
    );
    metrics::describe_histogram!(
        CORRECTIONS_PER_REQUEST,
        metrics::Unit::Count,
        "Corrections applied per passing request."
    );
    metrics::describe_histogram!(
        NORMALIZE_DURATION_SECONDS,
        metrics::Unit::Seconds,
        "Wall time of one normalize call, by outcome."
    );
}

pub(crate) fn record_request(outcome: GateOutcome, elapsed: Duration) {
    metrics::counter!(REQUESTS_TOTAL, "outcome" => outcome.as_str()).increment(1);
    metrics::histogram!(NORMALIZE_DURATION_SECONDS, "outcome" => outcome.as_str()).record(elapsed.as_secs_f64());
}

pub(crate) fn record_trip(reason: TripReason) {
    metrics::counter!(
        TRIPS_TOTAL,
        "reason" => reason.as_str(),
        "outcome" => reason.outcome().as_str()
    )
    .increment(1);
}

pub(crate) fn record_correction(kind_label: &'static str) {
    metrics::counter!(CORRECTIONS_TOTAL, "kind" => kind_label).increment(1);
}

pub(crate) fn record_corrections_per_request(count: usize) {
    // usize to f64 is exact for any count this crate can produce (bounded by
    // three per parameter times max_params).
    #[allow(clippy::cast_precision_loss)]
    metrics::histogram!(CORRECTIONS_PER_REQUEST).record(count as f64);
}

/// Full lowercase SHA-256 hex digest of `bytes`: always 64 characters,
/// never truncated.
#[must_use]
pub fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

/// Formats as the full SHA-256 hex digest of the wrapped bytes, computed
/// only when a log event is actually written. With no subscriber, or with
/// the level filtered out, no hashing happens.
pub(crate) struct LazySha256<'a>(pub(crate) &'a [u8]);

impl fmt::Display for LazySha256<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let digest = Sha256::digest(self.0);
        let mut buf = [0u8; 64];
        match hex::encode_to_slice(digest, &mut buf) {
            Ok(()) => f.write_str(std::str::from_utf8(&buf).map_err(|_| fmt::Error)?),
            Err(_) => Err(fmt::Error),
        }
    }
}

impl fmt::Debug for LazySha256<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn digest_is_full_length() {
        let d = sha256_hex(b"abc");
        assert_eq!(d.len(), 64);
        assert_eq!(d, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
        assert_eq!(LazySha256(b"abc").to_string(), d);
    }

    #[test]
    fn names_follow_convention() {
        for n in [REQUESTS_TOTAL, TRIPS_TOTAL, CORRECTIONS_TOTAL] {
            assert!(n.starts_with("tack_bumpers_") && n.ends_with("_total"));
        }
        assert!(NORMALIZE_DURATION_SECONDS.ends_with("_seconds"));
        assert!(CORRECTIONS_PER_REQUEST.starts_with("tack_bumpers_"));
    }
}
