//! The admission gate: length cap, in-flight cap, validator, telemetry.
//!
//! Order of work for one request, cheapest and most public first:
//!
//! 1. Read the monotonic clock (only when `record_response_time` is on).
//! 2. Length check, from `candidate.len()` alone, before a single byte is
//!    read: longer than [`TOKEN_LEN`] is [`Trip::InputTooLarge`], shorter
//!    is [`Trip::Malformed`]. An attacker who sends a gigabyte costs the
//!    server one integer comparison.
//! 3. Take an in-flight slot or return [`Trip::SlotsFull`].
//! 4. Run the configured validator on exactly [`TOKEN_LEN`] bytes.
//! 5. Give the slot back, read the clock, emit telemetry, return.
//!
//! Per-request cost bound (constant-time validator): one length compare,
//! one atomic compare-and-swap loop on the slot counter (bounded by
//! contention, not by input), 32 XOR plus 32 OR on bytes, one `subtle`
//! equality, two clock reads, and a fixed set of metric updates. No heap
//! allocation on the request path, except the 64-character hex digest when
//! debug logging is enabled. There is no padding loop, so there is nothing
//! for an attacker to stretch: the most an attacker controls is the number
//! of requests, which `max_in_flight` caps in concurrency and an upstream
//! rate limiter must cap in rate.

use crate::error::ConfigError;
use crate::outcome::{Accepted, CheckResult, GateOutcome, Trip};
use crate::telemetry::{self, Event};
use crate::validators::{Validator, TOKEN_LEN};
use core::hint::black_box;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Instant;
use subtle::ConstantTimeEq;

/// Hard upper bound on [`PipelineConfig::max_in_flight`].
pub const MAX_IN_FLIGHT: usize = 65_536;
/// Default [`PipelineConfig::max_in_flight`].
pub const DEFAULT_MAX_IN_FLIGHT: usize = 64;

/// Gate configuration. Every field has a documented default and a bound
/// checked by [`PipelineConfig::validate`]; out-of-bound values are
/// rejected, never clamped.
///
/// The input length cap is not a field: it is the constant [`TOKEN_LEN`]
/// (32 bytes), because every validator compares exactly that many bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PipelineConfig {
    /// Which validator runs. Default [`Validator::ConstantTime`].
    pub validator: Validator,
    /// Must be `true` to build a gate with a leaky validator
    /// ([`Validator::EarlyExit`] or [`Validator::BalancedDummy`]). Default
    /// `false`, so a production profile cannot pick a leaky validator by
    /// accident. Measurement code sets it.
    pub allow_leaky_validators: bool,
    /// Largest number of checks running at once. Default
    /// [`DEFAULT_MAX_IN_FLIGHT`] (64). Bounds `1 ..= MAX_IN_FLIGHT`.
    pub max_in_flight: usize,
    /// Record `stack_anc_response_seconds`. Default `true`. Turning it off
    /// removes the two clock reads from the request path. (Rust's
    /// `Instant::now` has no error return; on Linux it reads
    /// `CLOCK_MONOTONIC`, which cannot fail, and the decision never depends
    /// on it.)
    pub record_response_time: bool,
}

impl Default for PipelineConfig {
    fn default() -> Self {
        Self {
            validator: Validator::ConstantTime,
            allow_leaky_validators: false,
            max_in_flight: DEFAULT_MAX_IN_FLIGHT,
            record_response_time: true,
        }
    }
}

impl PipelineConfig {
    /// Check every bound.
    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.max_in_flight == 0 {
            return Err(ConfigError::Invalid {
                field: "max_in_flight",
                reason: "must be at least 1",
            });
        }
        if self.max_in_flight > MAX_IN_FLIGHT {
            return Err(ConfigError::Invalid {
                field: "max_in_flight",
                reason: "exceeds MAX_IN_FLIGHT",
            });
        }
        if self.validator.is_leaky() && !self.allow_leaky_validators {
            return Err(ConfigError::LeakyValidator);
        }
        Ok(())
    }
}

/// The server's secret token. Supplied by the caller from its key store;
/// there is no default and no constructor without bytes.
///
/// `Debug` prints no bytes. On drop the bytes are overwritten with zeros
/// (best effort: without `unsafe` volatile writes or a zeroize crate, the
/// overwrite is kept alive with `black_box`, which the compiler honours in
/// practice but does not promise).
pub struct TokenSecret([u8; TOKEN_LEN]);

impl TokenSecret {
    /// Build from exactly [`TOKEN_LEN`] bytes. Rejects the wrong length and
    /// the all-zero token (the usual shape of an unset default).
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, ConfigError> {
        let arr: [u8; TOKEN_LEN] = bytes.try_into().map_err(|_| ConfigError::SecretLength)?;
        if bool::from(arr.ct_eq(&[0u8; TOKEN_LEN])) {
            return Err(ConfigError::SecretAllZero);
        }
        Ok(Self(arr))
    }

    pub(crate) fn bytes(&self) -> &[u8; TOKEN_LEN] {
        &self.0
    }
}

impl std::fmt::Debug for TokenSecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("TokenSecret(<redacted>)")
    }
}

impl Drop for TokenSecret {
    fn drop(&mut self) {
        self.0.fill(0);
        black_box(&self.0);
    }
}

/// An in-flight slot, returned when dropped.
struct Slot<'a>(&'a AtomicUsize);

impl Drop for Slot<'_> {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::AcqRel);
    }
}

/// Admission gate plus validator for one secret token.
#[derive(Debug)]
pub struct PipelineGate {
    secret: TokenSecret,
    config: PipelineConfig,
    in_flight: AtomicUsize,
}

impl PipelineGate {
    /// Build a gate. Fails on an out-of-bound config or on a leaky
    /// validator without `allow_leaky_validators`.
    pub fn new(secret: TokenSecret, config: PipelineConfig) -> Result<Self, ConfigError> {
        config.validate()?;
        telemetry::emit_leaky_active(config.validator);
        Ok(Self {
            secret,
            config,
            in_flight: AtomicUsize::new(0),
        })
    }

    /// The configuration in force.
    pub fn config(&self) -> &PipelineConfig {
        &self.config
    }

    /// Checks running right now (a load figure, not secret).
    pub fn in_flight(&self) -> usize {
        self.in_flight.load(Ordering::Acquire)
    }

    fn try_slot(&self) -> Option<Slot<'_>> {
        let max = self.config.max_in_flight;
        self.in_flight
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |n| {
                if n < max {
                    Some(n + 1)
                } else {
                    None
                }
            })
            .ok()
            .map(|_| Slot(&self.in_flight))
    }

    /// Check one candidate token. Never panics; every failure is a typed
    /// [`Trip`] (all RETRY, all reject).
    pub fn check(&self, candidate: &[u8]) -> CheckResult {
        let start = self.config.record_response_time.then(Instant::now);
        let span = tracing::debug_span!(
            "tack.anc.pipeline_check",
            validator = self.config.validator.label(),
            input_len = candidate.len(),
            outcome = tracing::field::Empty,
            reason = tracing::field::Empty,
        );
        let _guard = span.enter();

        let result = self.decide(candidate);

        let observed = start.map(|s| s.elapsed());
        let ev = Event {
            validator: self.config.validator,
            outcome: match result {
                Ok(_) => GateOutcome::Pass,
                Err(t) => t.gate_outcome(),
            },
            trip: result.err(),
            observed,
        };
        span.record("outcome", ev.outcome.as_str());
        span.record("reason", ev.trip.map_or("none", Trip::label));
        telemetry::emit(&ev);
        telemetry::log_input(candidate, &ev);
        result
    }

    fn decide(&self, candidate: &[u8]) -> CheckResult {
        if candidate.len() > TOKEN_LEN {
            return Err(Trip::InputTooLarge);
        }
        let Ok(token) = <&[u8; TOKEN_LEN]>::try_from(candidate) else {
            return Err(Trip::Malformed);
        };
        let Some(_slot) = self.try_slot() else {
            return Err(Trip::SlotsFull);
        };
        if self.config.validator.run(self.secret.bytes(), token) {
            Ok(Accepted)
        } else {
            Err(Trip::Mismatch)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::validators::probe;

    // Test fixture, not a key.
    const FIXTURE: [u8; TOKEN_LEN] = [0x42; TOKEN_LEN];

    fn gate(validator: Validator, max_in_flight: usize) -> PipelineGate {
        let cfg = PipelineConfig {
            validator,
            allow_leaky_validators: true,
            max_in_flight,
            record_response_time: true,
        };
        PipelineGate::new(TokenSecret::from_bytes(&FIXTURE).unwrap(), cfg).unwrap()
    }

    #[test]
    fn over_length_input_is_rejected_before_any_validator_step() {
        for v in Validator::ALL {
            let g = gate(v, 4);
            let _ = probe::take();
            for len in [TOKEN_LEN + 1, 64, 4096, 1 << 20] {
                let big = vec![0x42u8; len];
                assert_eq!(g.check(&big), Err(Trip::InputTooLarge), "{v:?} len {len}");
            }
            assert_eq!(probe::take(), probe::Counts::default(), "{v:?}");
            assert_eq!(g.in_flight(), 0);
        }
    }

    #[test]
    fn short_input_is_malformed_before_any_validator_step() {
        let g = gate(Validator::ConstantTime, 4);
        let _ = probe::take();
        for len in [0, 1, TOKEN_LEN - 1] {
            assert_eq!(g.check(&FIXTURE[..len]), Err(Trip::Malformed));
        }
        assert_eq!(probe::take(), probe::Counts::default());
    }

    #[test]
    fn slots_full_is_retry_and_does_no_secret_work() {
        let g = gate(Validator::ConstantTime, 2);
        g.in_flight.store(2, Ordering::Release);
        let _ = probe::take();
        assert_eq!(g.check(&FIXTURE), Err(Trip::SlotsFull));
        assert_eq!(probe::take().ct, 0);
        g.in_flight.store(0, Ordering::Release);
        assert_eq!(g.check(&FIXTURE), Ok(Accepted));
        assert_eq!(probe::take().ct, TOKEN_LEN as u64);
        assert_eq!(g.in_flight(), 0, "slot returned");
    }

    #[test]
    fn slots_full_shed_metric_fires() {
        use metrics_util::debugging::{DebugValue, DebuggingRecorder};
        let rec = DebuggingRecorder::new();
        let snap = rec.snapshotter();
        metrics::with_local_recorder(&rec, || {
            let g = gate(Validator::ConstantTime, 1);
            g.in_flight.store(1, Ordering::Release);
            assert_eq!(g.check(&FIXTURE), Err(Trip::SlotsFull));
        });
        let entries = snap.snapshot().into_vec();
        let shed = entries.iter().any(|(ck, _, _, v)| {
            ck.key().name() == crate::telemetry::names::SHED_TOTAL
                && ck
                    .key()
                    .labels()
                    .any(|l| l.key() == "reason" && l.value() == "slots_full")
                && *v == DebugValue::Counter(1)
        });
        let retry = entries.iter().any(|(ck, _, _, v)| {
            ck.key().name() == crate::telemetry::names::REQUESTS_TOTAL
                && ck
                    .key()
                    .labels()
                    .any(|l| l.key() == "outcome" && l.value() == "retry")
                && *v == DebugValue::Counter(1)
        });
        assert!(shed && retry, "{entries:?}");
    }

    #[test]
    fn gate_accepts_match_and_rejects_mismatch() {
        for v in Validator::ALL {
            let g = gate(v, 1);
            assert_eq!(g.check(&FIXTURE), Ok(Accepted));
            let mut wrong = FIXTURE;
            wrong[31] ^= 0x80;
            assert_eq!(g.check(&wrong), Err(Trip::Mismatch));
            assert_eq!(g.in_flight(), 0);
        }
    }

    #[test]
    fn config_bounds() {
        let ok = PipelineConfig::default();
        assert_eq!(ok.validator, Validator::ConstantTime);
        assert!(!ok.allow_leaky_validators);
        assert_eq!(ok.max_in_flight, DEFAULT_MAX_IN_FLIGHT);
        assert!(ok.validate().is_ok());
        let zero = PipelineConfig {
            max_in_flight: 0,
            ..ok
        };
        assert!(matches!(
            zero.validate(),
            Err(ConfigError::Invalid {
                field: "max_in_flight",
                ..
            })
        ));
        let big = PipelineConfig {
            max_in_flight: MAX_IN_FLIGHT + 1,
            ..ok
        };
        assert!(big.validate().is_err());
        for v in [Validator::EarlyExit, Validator::BalancedDummy] {
            let leaky = PipelineConfig { validator: v, ..ok };
            assert_eq!(leaky.validate(), Err(ConfigError::LeakyValidator));
        }
    }

    #[test]
    fn secret_rules() {
        assert_eq!(
            TokenSecret::from_bytes(&[0u8; TOKEN_LEN]).unwrap_err(),
            ConfigError::SecretAllZero
        );
        assert_eq!(
            TokenSecret::from_bytes(&[1u8; TOKEN_LEN - 1]).unwrap_err(),
            ConfigError::SecretLength
        );
        assert_eq!(
            TokenSecret::from_bytes(&[1u8; TOKEN_LEN + 1]).unwrap_err(),
            ConfigError::SecretLength
        );
        let s = TokenSecret::from_bytes(&FIXTURE).unwrap();
        let shown = format!("{s:?}");
        assert_eq!(shown, "TokenSecret(<redacted>)");
        let g = gate(Validator::ConstantTime, 1);
        assert!(!format!("{g:?}").contains("66"), "no secret bytes in Debug");
    }
}
