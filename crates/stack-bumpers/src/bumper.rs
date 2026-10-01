//! The bumper: normalizes a parameter map against its specs.

use std::collections::BTreeMap;
use std::time::Instant;

use crate::config::BumperConfig;
use crate::error::{Rejection, SpecError, Trip, TripParam, TripReason};
use crate::outcome::{GateOutcome, GatePosition, Resolution};
use crate::spec::{
    canonical_zero, check_name, is_control_or_format, CharPolicy, EnumSpec, NumericSpec, ParamSpec, Presence, SpecKind,
    StringSpec, TrimPolicy, UnitMatch,
};
use crate::telemetry::{self, LazySha256};
use crate::value::{Correction, CorrectionKind, NormalizedValue, ParamValue, SoftEdge};

/// A request that passed, with every change the bumper made to it.
#[derive(Debug, Clone, PartialEq)]
pub struct Normalized {
    values: BTreeMap<String, NormalizedValue>,
    corrections: Vec<Correction>,
}

impl Normalized {
    /// Always PASS. A refused request is a [`Rejection`] instead.
    #[must_use]
    pub fn outcome(&self) -> GateOutcome {
        GateOutcome::Pass
    }

    /// The normalized values, by parameter name.
    #[must_use]
    pub fn values(&self) -> &BTreeMap<String, NormalizedValue> {
        &self.values
    }

    /// One normalized value.
    #[must_use]
    pub fn get(&self, name: &str) -> Option<&NormalizedValue> {
        self.values.get(name)
    }

    /// Every correction applied, in request key order. Never longer than
    /// the correction budget.
    #[must_use]
    pub fn corrections(&self) -> &[Correction] {
        &self.corrections
    }

    /// The normalized values as an input map, for re-submission. Normalizing
    /// this map again yields the same values and no corrections.
    #[must_use]
    pub fn to_input(&self) -> BTreeMap<String, ParamValue> {
        self.values
            .iter()
            .map(|(k, v)| (k.clone(), v.to_param_value()))
            .collect()
    }

    /// Take the values and corrections apart.
    #[must_use]
    pub fn into_parts(self) -> (BTreeMap<String, NormalizedValue>, Vec<Correction>) {
        (self.values, self.corrections)
    }
}

/// Normalizes parameter maps against a fixed set of specs.
///
/// A `Bumper` is immutable after construction and holds no per-request
/// state, so it is `Send + Sync` and one instance can serve every thread.
#[derive(Debug, Clone)]
pub struct Bumper {
    config: BumperConfig,
    specs: BTreeMap<String, ParamSpec>,
}

impl Bumper {
    /// Bumpers judge parameters before anything acts on them.
    pub const POSITION: GatePosition = GatePosition::Alpha;

    /// Build a bumper from a config and its parameter specs.
    ///
    /// # Errors
    ///
    /// Any [`SpecError`]: an invalid config, a duplicate or badly formed
    /// parameter name, or a spec that exceeds a configured cap.
    pub fn new(config: BumperConfig, specs: impl IntoIterator<Item = ParamSpec>) -> Result<Self, SpecError> {
        let span = tracing::debug_span!("stack.bumpers.build");
        let _entered = span.enter();
        let built = Self::build(config, specs);
        match &built {
            Ok(b) => tracing::debug!(params = b.specs.len(), "bumper built"),
            Err(e) => tracing::warn!(error = %e, "bumper spec refused"),
        }
        built
    }

    fn build(config: BumperConfig, specs: impl IntoIterator<Item = ParamSpec>) -> Result<Self, SpecError> {
        config.validate()?;
        let check_len = |name: &str| -> Result<(), SpecError> {
            if name.len() > config.max_name_bytes {
                return Err(SpecError::NameTooLong {
                    len: name.len(),
                    max: config.max_name_bytes,
                });
            }
            Ok(())
        };
        let mut map = BTreeMap::new();
        for (i, spec) in specs.into_iter().enumerate() {
            if i >= config.max_params {
                return Err(SpecError::TooManyParams { max: config.max_params });
            }
            check_name(spec.name())?;
            check_len(spec.name())?;
            match spec.kind() {
                SpecKind::Numeric(n) => {
                    if n.unit_count() > config.max_units {
                        return Err(SpecError::TooManyUnits {
                            param: spec.name().to_owned(),
                            count: n.unit_count(),
                            max: config.max_units,
                        });
                    }
                    n.names().try_for_each(check_len)?;
                }
                SpecKind::Enum(e) => {
                    if e.name_count() > config.max_enum_names {
                        return Err(SpecError::TooManyEnumNames {
                            param: spec.name().to_owned(),
                            count: e.name_count(),
                            max: config.max_enum_names,
                        });
                    }
                    e.names().try_for_each(check_len)?;
                }
                SpecKind::Text(s) => {
                    if s.max_len() > config.max_input_bytes {
                        return Err(SpecError::StringCapAboveInputCap {
                            param: spec.name().to_owned(),
                            max_len: s.max_len(),
                            cap: config.max_input_bytes,
                        });
                    }
                }
            }
            if map.contains_key(spec.name()) {
                return Err(SpecError::DuplicateParam {
                    name: spec.name().to_owned(),
                });
            }
            map.insert(spec.name().to_owned(), spec);
        }
        Ok(Self { config, specs: map })
    }

    /// The configuration this bumper enforces.
    #[must_use]
    pub fn config(&self) -> &BumperConfig {
        &self.config
    }

    /// The spec for one parameter.
    #[must_use]
    pub fn spec(&self, name: &str) -> Option<&ParamSpec> {
        self.specs.get(name)
    }

    /// Normalize a request's parameters.
    ///
    /// Every entry is evaluated, even after one has tripped, so the caller
    /// learns every problem in one round and so the amount of work does not
    /// reveal which entry failed first. The verdict follows the CNS
    /// precedence: any TERMINAL_BREACH trip wins, then any RETRY, and PASS
    /// only when there are no trips.
    ///
    /// # Errors
    ///
    /// A [`Rejection`] with outcome RETRY or TERMINAL_BREACH and resolution
    /// REJECT. Nothing is changed on rejection: this function has no side
    /// effects apart from telemetry.
    pub fn normalize(&self, input: &BTreeMap<String, ParamValue>) -> Result<Normalized, Rejection> {
        let start = Instant::now();
        let span = tracing::debug_span!(
            "stack.bumpers.normalize",
            params = input.len(),
            outcome = tracing::field::Empty,
            corrections = tracing::field::Empty,
            trips = tracing::field::Empty,
        );
        let _entered = span.enter();

        let result = self.evaluate(input);

        let outcome = match &result {
            Ok(n) => {
                span.record("corrections", n.corrections.len());
                for c in &n.corrections {
                    tracing::debug!(param = c.param.as_str(), kind = c.kind.label(), "bumper correction");
                    telemetry::record_correction(c.kind.label());
                }
                telemetry::record_corrections_per_request(n.corrections.len());
                GateOutcome::Pass
            }
            Err(r) => {
                span.record("trips", r.trips.len());
                for t in &r.trips {
                    telemetry::record_trip(t.reason);
                }
                if r.outcome == GateOutcome::TerminalBreach {
                    log_breach_summary(r);
                }
                r.outcome
            }
        };
        span.record("outcome", outcome.as_str());
        telemetry::record_request(outcome, start.elapsed());
        result
    }

    fn evaluate(&self, input: &BTreeMap<String, ParamValue>) -> Result<Normalized, Rejection> {
        if input.len() > self.config.max_params {
            log_trip(None, TripReason::TooManyParams, LogInput::None);
            return Err(reject(vec![Trip {
                param: TripParam::Request,
                reason: TripReason::TooManyParams,
            }]));
        }

        let mut trips = Vec::new();
        let mut values = BTreeMap::new();
        let mut corrections = Vec::new();

        for (key, value) in input {
            let Some(spec) = self.specs.get(key) else {
                // The value under an unknown key is still checked for the
                // TERMINAL conditions, so an oversized or non-finite value
                // cannot hide behind the repairable unknown_param verdict.
                let key_over_cap = key.len() > self.config.max_input_bytes;
                let reason = if key_over_cap || self.text_over_cap(value) {
                    TripReason::InputTooLarge
                } else if is_non_finite(value) {
                    TripReason::NonFinite
                } else {
                    TripReason::UnknownParam
                };
                // The key is hashed at most once, and never when it is over
                // the cap, so refusal work stays bounded by the cap.
                let param = if key_over_cap {
                    log_trip(None, reason, LogInput::OverCap(key.len()));
                    TripParam::UnknownOverCap { len: key.len() }
                } else {
                    let sha256 = telemetry::sha256_hex(key.as_bytes());
                    log_trip(None, reason, LogInput::Digest(key.len(), &sha256));
                    TripParam::Unknown { len: key.len(), sha256 }
                };
                trips.push(Trip { param, reason });
                continue;
            };
            let mut local = Vec::new();
            match self.normalize_one(spec, value, &mut local) {
                Ok(v) => {
                    values.insert(key.clone(), v);
                    corrections.append(&mut local);
                }
                Err(reason) => {
                    log_trip(Some(spec.name()), reason, self.log_input(value));
                    trips.push(Trip {
                        param: TripParam::Named(spec.name().to_owned()),
                        reason,
                    });
                }
            }
        }

        for spec in self.specs.values() {
            if spec.presence() == Presence::Required && !input.contains_key(spec.name()) {
                log_trip(Some(spec.name()), TripReason::MissingRequired, LogInput::None);
                trips.push(Trip {
                    param: TripParam::Named(spec.name().to_owned()),
                    reason: TripReason::MissingRequired,
                });
            }
        }

        let budget = usize::try_from(self.config.correction_budget).unwrap_or(usize::MAX);
        if corrections.len() > budget {
            tracing::debug!(
                corrections = corrections.len(),
                budget,
                reason = TripReason::CorrectionBudgetExceeded.as_str(),
                "bumper trip"
            );
            trips.push(Trip {
                param: TripParam::Request,
                reason: TripReason::CorrectionBudgetExceeded,
            });
        }

        if trips.is_empty() {
            Ok(Normalized { values, corrections })
        } else {
            Err(reject(trips))
        }
    }

    fn normalize_one(&self, spec: &ParamSpec, value: &ParamValue, out: &mut Vec<Correction>) -> Result<NormalizedValue, TripReason> {
        if self.text_over_cap(value) {
            return Err(TripReason::InputTooLarge);
        }
        // NaN and infinities are TERMINAL whatever shape the parameter has,
        // so a non-finite number sent to an enum or string parameter is not
        // downgraded to a repairable type_mismatch.
        if is_non_finite(value) {
            return Err(TripReason::NonFinite);
        }
        let name = spec.name();
        match spec.kind() {
            SpecKind::Numeric(n) => normalize_numeric(name, n, value, out).map(NormalizedValue::Number),
            SpecKind::Enum(e) => normalize_enum(name, e, value, out).map(NormalizedValue::Variant),
            SpecKind::Text(s) => normalize_text(name, s, value, out).map(NormalizedValue::Text),
        }
    }

    /// True when the value's text part is longer than `max_input_bytes`.
    fn text_over_cap(&self, value: &ParamValue) -> bool {
        text_part(value).is_some_and(|t| t.len() > self.config.max_input_bytes)
    }

    /// How a declared parameter's value appears in its trip log line: a lazy
    /// digest when it is within the cap, its length only when it is over.
    fn log_input<'a>(&self, value: &'a ParamValue) -> LogInput<'a> {
        match text_part(value) {
            None => LogInput::None,
            Some(t) if t.len() > self.config.max_input_bytes => LogInput::OverCap(t.len()),
            Some(t) => LogInput::Lazy(t),
        }
    }
}

/// True for a `Number` or `Quantity` whose magnitude is NaN or infinite.
fn is_non_finite(value: &ParamValue) -> bool {
    match value {
        ParamValue::Number(x) | ParamValue::Quantity { value: x, .. } => !x.is_finite(),
        ParamValue::Text(_) => false,
    }
}

fn reject(trips: Vec<Trip>) -> Rejection {
    // `trips` is never empty here. If it were, RETRY is the fail-closed
    // default: an empty rejection must still not read as PASS.
    let outcome = trips
        .iter()
        .map(|t| t.reason.outcome())
        .max()
        .unwrap_or(GateOutcome::Retry);
    Rejection {
        outcome,
        resolution: Resolution::Reject,
        trips,
    }
}

/// The text inside a value: the string itself, or a quantity's unit name.
fn text_part(value: &ParamValue) -> Option<&[u8]> {
    match value {
        ParamValue::Number(_) => None,
        ParamValue::Quantity { unit, .. } => Some(unit.as_bytes()),
        ParamValue::Text(s) => Some(s.as_bytes()),
    }
}

/// The caller text a trip log line identifies, never the text itself.
enum LogInput<'a> {
    /// No caller text (a missing parameter, a request-level trip, a number).
    None,
    /// Text within `max_input_bytes`, hashed only if the event is written.
    Lazy(&'a [u8]),
    /// Text within `max_input_bytes` whose digest is already computed, so it
    /// is not hashed a second time.
    Digest(usize, &'a str),
    /// Text over `max_input_bytes`: its length only, with
    /// `input_over_cap=true`. It is not hashed, so refusal work stays
    /// bounded by the cap and does not depend on the log level.
    OverCap(usize),
}

/// Log one trip at DEBUG. `param` is a spec name (operator text) or `None`
/// for an unknown key or a request-level trip. Caller text is logged only as
/// its length and full SHA-256 digest (or its length alone when it is over
/// the cap). For an unknown key the logged input is the key.
///
/// Per-trip lines stay at DEBUG so one request cannot write up to
/// `max_params` lines at a level production enables. A TERMINAL_BREACH
/// request also gets one WARN summary from [`log_breach_summary`].
fn log_trip(param: Option<&str>, reason: TripReason, raw: LogInput<'_>) {
    let outcome = reason.outcome();
    let (input_len, input_over_cap) = match raw {
        LogInput::None => (None, None),
        LogInput::Lazy(b) => (Some(b.len()), None),
        LogInput::Digest(len, _) => (Some(len), None),
        LogInput::OverCap(len) => (Some(len), Some(true)),
    };
    match raw {
        LogInput::Lazy(b) => tracing::debug!(
            param,
            reason = reason.as_str(),
            outcome = outcome.as_str(),
            input_len,
            input_sha256 = %LazySha256(b),
            "bumper trip"
        ),
        LogInput::Digest(_, d) => tracing::debug!(
            param,
            reason = reason.as_str(),
            outcome = outcome.as_str(),
            input_len,
            input_sha256 = d,
            "bumper trip"
        ),
        LogInput::None | LogInput::OverCap(_) => tracing::debug!(
            param,
            reason = reason.as_str(),
            outcome = outcome.as_str(),
            input_len,
            input_over_cap,
            "bumper trip"
        ),
    }
}

/// One WARN line per TERMINAL_BREACH request, with trip counts by reason.
/// Every field is a count or a closed-enum string, never caller data, and
/// there is exactly one callsite, so an operator can rate-limit it.
fn log_breach_summary(r: &Rejection) {
    let count = |reason: TripReason| r.trips.iter().filter(|t| t.reason == reason).count();
    let retry_trips = r.trips.iter().filter(|t| t.reason.outcome() == GateOutcome::Retry).count();
    tracing::warn!(
        outcome = r.outcome.as_str(),
        trips = r.trips.len(),
        non_finite = count(TripReason::NonFinite),
        outside_hard_band = count(TripReason::OutsideHardBand),
        input_too_large = count(TripReason::InputTooLarge),
        too_many_params = count(TripReason::TooManyParams),
        retry_trips,
        "bumper terminal breach"
    );
}

/// Move a finite value into the soft band, or refuse it.
///
/// This is written out with comparisons instead of `f64::clamp` on purpose.
/// `f64::clamp` returns NaN for a NaN input, which would let NaN through a
/// clamp that looks safe, and it panics when `min > max`. NaN is refused
/// before this point; the hard band test is also written so that a NaN
/// would fail it (`!(x >= lo && x <= hi)` is true for NaN).
fn clamp_number(spec: &NumericSpec, x: f64) -> Result<(f64, Option<(f64, SoftEdge)>), TripReason> {
    if !x.is_finite() {
        return Err(TripReason::NonFinite);
    }
    let x = canonical_zero(x);
    if !(x >= spec.hard_min() && x <= spec.hard_max()) {
        return Err(TripReason::OutsideHardBand);
    }
    if x < spec.soft_min() {
        Ok((spec.soft_min(), Some((x, SoftEdge::Min))))
    } else if x > spec.soft_max() {
        Ok((spec.soft_max(), Some((x, SoftEdge::Max))))
    } else {
        Ok((x, None))
    }
}

fn normalize_numeric(name: &str, spec: &NumericSpec, value: &ParamValue, out: &mut Vec<Correction>) -> Result<f64, TripReason> {
    let (raw, unit) = match value {
        ParamValue::Number(x) => (*x, None),
        ParamValue::Quantity { value, unit } => (*value, Some(unit.as_str())),
        ParamValue::Text(_) => return Err(TripReason::TypeMismatch),
    };
    // NaN and infinities are refused before any unit lookup or arithmetic.
    if !raw.is_finite() {
        return Err(TripReason::NonFinite);
    }
    let mut x = raw;
    if let Some(unit) = unit {
        match spec.resolve_unit(unit) {
            None => return Err(TripReason::UnknownUnit),
            Some(UnitMatch::Canonical) => {}
            Some(UnitMatch::Alternate(from_unit, scale)) => {
                // A finite value times a finite, normal, positive factor is
                // finite or overflows to infinity. Infinity then fails the
                // hard band below as OUTSIDE_HARD_BAND, because the caller
                // sent a finite number that is simply too big.
                x = scale.apply(x);
                if !x.is_finite() {
                    return Err(TripReason::OutsideHardBand);
                }
                out.push(Correction {
                    param: name.to_owned(),
                    kind: CorrectionKind::UnitConverted {
                        from_unit: from_unit.to_owned(),
                        scale,
                    },
                });
            }
        }
    }
    let (clamped, moved) = clamp_number(spec, x)?;
    if let Some((from, edge)) = moved {
        out.push(Correction {
            param: name.to_owned(),
            kind: CorrectionKind::Clamped { from, to: clamped, edge },
        });
    }
    Ok(clamped)
}

fn normalize_enum(name: &str, spec: &EnumSpec, value: &ParamValue, out: &mut Vec<Correction>) -> Result<String, TripReason> {
    let ParamValue::Text(s) = value else {
        return Err(TripReason::TypeMismatch);
    };
    let trimmed = s.trim();
    if trimmed.len() > spec.longest() {
        // Cannot match any declared name. Refused before folding, so the
        // folded copy below is never larger than the longest declared name.
        return Err(TripReason::UnknownVariant);
    }
    let folded = trimmed.to_ascii_lowercase();
    let entry = spec.lookup(&folded).ok_or(TripReason::UnknownVariant)?;
    let canonical = spec.variant(entry.variant).ok_or(TripReason::UnknownVariant)?;
    if trimmed.len() != s.len() {
        out.push(Correction {
            param: name.to_owned(),
            kind: CorrectionKind::Trimmed {
                removed_bytes: s.len() - trimmed.len(),
            },
        });
    }
    if entry.exact != trimmed {
        out.push(Correction {
            param: name.to_owned(),
            kind: CorrectionKind::CaseFolded,
        });
    }
    if entry.is_alias {
        out.push(Correction {
            param: name.to_owned(),
            kind: CorrectionKind::AliasResolved {
                alias: entry.exact.clone(),
                canonical: canonical.to_owned(),
            },
        });
    }
    Ok(canonical.to_owned())
}

fn normalize_text(name: &str, spec: &StringSpec, value: &ParamValue, out: &mut Vec<Correction>) -> Result<String, TripReason> {
    let ParamValue::Text(s) = value else {
        return Err(TripReason::TypeMismatch);
    };
    let kept = match spec.trim() {
        TrimPolicy::Preserve => s.as_str(),
        TrimPolicy::Trim => s.trim(),
        TrimPolicy::Reject => {
            if s.trim().len() != s.len() {
                return Err(TripReason::WhitespaceRejected);
            }
            s.as_str()
        }
    };
    if kept.len() > spec.max_len() {
        return Err(TripReason::TooLong);
    }
    // Checked after the trim policy, so whitespace-only text under `Trim`
    // cannot satisfy the parameter as an empty string.
    if kept.len() < spec.min_len() {
        return Err(TripReason::TooShort);
    }
    // Bounded by max_len, which the check above has already enforced.
    if spec.char_policy() == CharPolicy::RefuseControlAndFormat && kept.chars().any(is_control_or_format) {
        return Err(TripReason::DisallowedChar);
    }
    if kept.len() != s.len() {
        out.push(Correction {
            param: name.to_owned(),
            kind: CorrectionKind::Trimmed {
                removed_bytes: s.len() - kept.len(),
            },
        });
    }
    Ok(kept.to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn band() -> NumericSpec {
        NumericSpec::new(-10.0, 0.0, 1.0, 10.0).unwrap()
    }

    #[test]
    fn clamp_refuses_nan_even_though_f64_clamp_would_not() {
        // The classic bug this function exists to avoid.
        assert!(f64::NAN.clamp(0.0, 1.0).is_nan());
        assert_eq!(clamp_number(&band(), f64::NAN), Err(TripReason::NonFinite));
    }

    #[test]
    fn clamp_edges() {
        assert_eq!(clamp_number(&band(), -5.0), Ok((0.0, Some((-5.0, SoftEdge::Min)))));
        assert_eq!(clamp_number(&band(), 5.0), Ok((1.0, Some((5.0, SoftEdge::Max)))));
        assert_eq!(clamp_number(&band(), 0.5), Ok((0.5, None)));
        assert_eq!(clamp_number(&band(), 10.0), Ok((1.0, Some((10.0, SoftEdge::Max)))));
        assert_eq!(clamp_number(&band(), 10.000_001), Err(TripReason::OutsideHardBand));
    }

    #[test]
    fn reject_of_empty_trips_fails_closed() {
        assert_eq!(reject(Vec::new()).outcome, GateOutcome::Retry);
    }

    #[test]
    fn bumper_is_send_and_sync() {
        fn check<T: Send + Sync>() {}
        check::<Bumper>();
    }
}
