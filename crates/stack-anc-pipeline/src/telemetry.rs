//! Metrics and log helpers.
//!
//! Rules this module follows:
//! * Every label value comes from a closed enum in this crate
//!   ([`crate::Validator`], [`crate::GateOutcome`], [`crate::Trip`]).
//!   Nothing from a request becomes a label.
//! * This strategy has no padded window: the response leaves as soon as the
//!   decision is made, and telemetry is emitted just before `check`
//!   returns, so its cost is inside what the client times. It is safe only
//!   because its cost depends on nothing but the outcome and the trip
//!   reason, which the reply already reveals. Two wrong guesses (wrong at
//!   byte 0, wrong at byte 31) take exactly the same telemetry path.
//! * `stack_anc_response_seconds` records admission to decision. For this
//!   strategy that is the same span of time the client observes (minus the
//!   network), so it is not a pre-padding leak; but for the leaky
//!   validators it does carry the leak, which is why the endpoint must not
//!   be reachable by the attacker (threat-model assumption).
//! * Nothing about the dummy work of `balanced_dummy` is exported. A
//!   counter of dummy steps would equal `31 - i` per request for a guess
//!   wrong at byte `i`, a direct position leak to anyone who can read it.
//! * Inputs are logged as length plus full SHA-256 hex, never raw, only at
//!   debug level, and the digest only for inputs within the length cap
//!   (hashing an oversized input would let the sender choose the cost of a
//!   log line).

use crate::outcome::{GateOutcome, Trip};
use crate::validators::{Validator, TOKEN_LEN};
use sha2::{Digest, Sha256};
use std::time::Duration;

/// Value of the `strategy` label on every metric this crate emits.
pub const STRATEGY: &str = "pipeline";

/// Metric names (component `anc`).
pub mod names {
    /// Counter, labels `strategy`, `validator`, `outcome` (`pass` |
    /// `retry`). One increment per request.
    pub const REQUESTS_TOTAL: &str = "stack_anc_requests_total";
    /// Counter, labels `strategy`, `reason` (`slots_full` |
    /// `input_too_large` | `malformed`). Requests refused at admission,
    /// before any secret-dependent work.
    pub const SHED_TOTAL: &str = "stack_anc_shed_total";
    /// Counter, labels `strategy`, `validator`. Well-formed tokens that did
    /// not match.
    pub const TOKEN_MISMATCH_TOTAL: &str = "stack_anc_token_mismatch_total";
    /// Gauge, labels `strategy`, `validator`. Set to 1 when a gate is built
    /// with a leaky validator (only possible with
    /// `allow_leaky_validators`). Never set for `constant_time`.
    pub const LEAKY_VALIDATOR_ACTIVE: &str = "stack_anc_leaky_validator_active";
    /// Histogram, labels `strategy`, `validator`, `outcome`. Admission to
    /// decision, seconds. Only when `record_response_time` is on.
    pub const RESPONSE_SECONDS: &str = "stack_anc_response_seconds";
}

/// What happened to one request.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Event {
    pub validator: Validator,
    pub outcome: GateOutcome,
    pub trip: Option<Trip>,
    pub observed: Option<Duration>,
}

pub(crate) fn emit(ev: &Event) {
    let v = ev.validator.label();
    let o = ev.outcome.label();
    metrics::counter!(
        names::REQUESTS_TOTAL,
        "strategy" => STRATEGY,
        "validator" => v,
        "outcome" => o
    )
    .increment(1);
    if let Some(observed) = ev.observed {
        metrics::histogram!(
            names::RESPONSE_SECONDS,
            "strategy" => STRATEGY,
            "validator" => v,
            "outcome" => o
        )
        .record(observed.as_secs_f64());
    }
    match ev.trip {
        Some(Trip::Mismatch) => {
            metrics::counter!(
                names::TOKEN_MISMATCH_TOTAL,
                "strategy" => STRATEGY,
                "validator" => v
            )
            .increment(1);
        }
        Some(t @ (Trip::SlotsFull | Trip::InputTooLarge | Trip::Malformed)) => {
            metrics::counter!(names::SHED_TOTAL, "strategy" => STRATEGY, "reason" => t.label())
                .increment(1);
        }
        None => {}
    }
}

pub(crate) fn emit_leaky_active(validator: Validator) {
    if validator.is_leaky() {
        metrics::gauge!(
            names::LEAKY_VALIDATOR_ACTIVE,
            "strategy" => STRATEGY,
            "validator" => validator.label()
        )
        .set(1.0);
    }
}

/// Full lowercase SHA-256 hex of `input` (64 characters, never truncated).
pub fn sha256_hex(input: &[u8]) -> String {
    hex::encode(Sha256::digest(input))
}

/// Debug log of one request. Length always; digest only when the input was
/// within the length cap. The digest is computed only when debug logging
/// is enabled, and SHA-256 of a 32-byte input costs the same for every
/// value, so enabling it adds a constant, not a class-dependent, cost.
pub(crate) fn log_input(input: &[u8], ev: &Event) {
    if !tracing::enabled!(tracing::Level::DEBUG) {
        return;
    }
    let reason = ev.trip.map_or("none", Trip::label);
    if input.len() <= TOKEN_LEN {
        tracing::debug!(
            input_len = input.len(),
            input_sha256 = %sha256_hex(input),
            validator = ev.validator.label(),
            outcome = ev.outcome.as_str(),
            reason,
            "pipeline check"
        );
    } else {
        tracing::debug!(
            input_len = input.len(),
            validator = ev.validator.label(),
            outcome = ev.outcome.as_str(),
            reason,
            "pipeline check (oversized input not hashed)"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sha256_hex_is_full_length() {
        let h = sha256_hex(b"abc");
        assert_eq!(h.len(), 64);
        assert_eq!(
            h,
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }
}
