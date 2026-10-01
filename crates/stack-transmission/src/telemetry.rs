//! Metric names, span names, alert rules and the small helpers that emit
//! them.
//!
//! Every label value comes from a closed enum in [`crate::vocab`]. The
//! transmission never sees raw request bytes, and it never formats the gear
//! configuration (which may hold keys) into a log line, a span field or a
//! label. What it records is counts, epochs and durations.
//!
//! Gauges and the halt counters are emitted while the state lock is held, so
//! a gauge can never be left showing a stale value by two threads racing
//! after the lock is released. Everything else is emitted after the lock is
//! released. See the lock order in [`crate::transmission`]. A backend that
//! panics during one of those gauge writes poisons the lock; the
//! transmission undoes the half-made state change and halts (see
//! "Poisoning" in [`crate::transmission`]).
//!
//! The gauges are process-global: every instance writes the same series.
//! [`crate::Transmission::new`] only registers them (it adds zero), so
//! building a second instance never clears a halt or an in-flight count that
//! another instance is showing. Two live instances still overwrite each
//! other's gauge values on every change; give each its own recorder, or add
//! a closed-enum instance label, if a process runs more than one.

use std::time::Duration;

use crate::vocab::{GateOutcome, HaltCause, Operation, Reason};

/// Counter. One per `engage()` call. Label `outcome`.
pub const ENGAGE_TOTAL: &str = "tack_transmission_engage_total";
/// Counter. One per `shift()` call. Label `outcome`.
pub const SHIFT_TOTAL: &str = "tack_transmission_shift_total";
/// Counter. One per refused call. Labels `operation` (engage, shift),
/// `reason` (a [`Reason`] spelling), `outcome` (retry, terminal_breach),
/// `resolution` (reject, rollback, halt).
pub const TRIPS_TOTAL: &str = "tack_transmission_trips_total";
/// Histogram, seconds. Wall time of one `engage()` call, including any wait
/// for the clutch. Label `outcome`.
pub const ENGAGE_WAIT_SECONDS: &str = "tack_transmission_engage_wait_seconds";
/// Histogram, seconds. How long the clutch was pressed during one shift,
/// from press to swap or rollback. Only recorded for shifts that pressed the
/// clutch. Label `outcome`.
pub const SHIFT_DRAIN_SECONDS: &str = "tack_transmission_shift_drain_seconds";
/// Gauge. Drive guards currently out. No labels.
pub const IN_FLIGHT: &str = "tack_transmission_in_flight";
/// Gauge. `engage()` callers parked on the clutch. No labels.
pub const WAITING_ENGAGERS: &str = "tack_transmission_waiting_engagers";
/// Gauge. 1 while the clutch is pressed, else 0. No labels.
pub const CLUTCH_PRESSED: &str = "tack_transmission_clutch_pressed";
/// Gauge. Epoch of the engaged gear. Exact up to 2^53. No labels.
pub const GEAR_EPOCH: &str = "tack_transmission_gear_epoch";
/// Gauge. 1 while halted, else 0. No labels.
pub const HALTED: &str = "tack_transmission_halted";
/// Counter. Transitions into the halted state. Label `cause` (operator,
/// poisoned, invariant).
pub const HALTS_TOTAL: &str = "tack_transmission_halts_total";
/// Counter. Operator resets that cleared a halt. No labels.
pub const OPERATOR_RESETS_TOTAL: &str = "tack_transmission_operator_resets_total";
/// Counter. Drive guards dropped while their thread was panicking. The
/// in-flight count was still decremented. No labels.
pub const GUARD_PANICS_TOTAL: &str = "tack_transmission_guard_panics_total";
/// Counter. Times the state mutex was found poisoned and recovered. No
/// labels.
pub const LOCK_POISON_RECOVERIES_TOTAL: &str = "tack_transmission_lock_poison_recoveries_total";

/// Counter. Times dropping a replaced gear's configuration (the caller's
/// `G::drop`) panicked inside `shift()`. The panic was contained and the
/// shift's verdict was already recorded. No labels.
pub const GEAR_DROP_PANICS_TOTAL: &str = "tack_transmission_gear_drop_panics_total";

/// Every metric name this crate emits.
pub const ALL_METRICS: [&str; 15] = [
    ENGAGE_TOTAL,
    SHIFT_TOTAL,
    TRIPS_TOTAL,
    ENGAGE_WAIT_SECONDS,
    SHIFT_DRAIN_SECONDS,
    IN_FLIGHT,
    WAITING_ENGAGERS,
    CLUTCH_PRESSED,
    GEAR_EPOCH,
    HALTED,
    HALTS_TOTAL,
    OPERATOR_RESETS_TOTAL,
    GUARD_PANICS_TOTAL,
    LOCK_POISON_RECOVERIES_TOTAL,
    GEAR_DROP_PANICS_TOTAL,
];

/// Span around one `engage()` call (debug level; it is on the hot path).
pub const SPAN_ENGAGE: &str = "stack.transmission.engage";
/// Span around one `shift()` call.
pub const SPAN_SHIFT: &str = "stack.transmission.shift";
/// Span around an operator halt.
pub const SPAN_OPERATOR_HALT: &str = "stack.transmission.operator_halt";
/// Span around an operator reset.
pub const SPAN_OPERATOR_RESET: &str = "stack.transmission.operator_reset";

/// Prometheus alerting rules over the metrics above, in the rule-file YAML
/// format. Thresholds are starting points; tune `for` windows to the shift
/// cadence of the deployment.
pub const PROMETHEUS_RULES: &str = r#"groups:
  - name: stack-transmission
    rules:
      - alert: TackTransmissionHalted
        expr: max(tack_transmission_halted) == 1
        for: 1m
        labels: { severity: critical }
        annotations:
          summary: "Transmission halted; all engage and shift calls are refused until operator_reset."
      - alert: TackTransmissionLockPoisoned
        expr: increase(tack_transmission_lock_poison_recoveries_total[1h]) > 0
        labels: { severity: critical }
        annotations:
          summary: "A thread panicked while holding the transmission state lock. This points at a bug."
      - alert: TackTransmissionClutchStuck
        expr: max(tack_transmission_clutch_pressed) == 1
        for: 2m
        labels: { severity: critical }
        annotations:
          summary: "Clutch pressed longer than any allowed shift timeout; admission is paused."
      - alert: TackTransmissionShiftRolledBack
        expr: increase(tack_transmission_trips_total{operation="shift",reason="drain_timeout"}[15m]) > 0
        labels: { severity: warning }
        annotations:
          summary: "A mode change timed out draining and was rolled back; the old gear is still engaged."
      - alert: TackTransmissionEngageRetryRatio
        expr: sum(rate(tack_transmission_engage_total{outcome="retry"}[5m])) / clamp_min(sum(rate(tack_transmission_engage_total[5m])), 1e-9) > 0.05
        for: 10m
        labels: { severity: warning }
        annotations:
          summary: "More than 5% of engage calls are being told to retry (clutch waits or capacity)."
      - alert: TackTransmissionInFlightSaturated
        expr: increase(tack_transmission_trips_total{operation="engage",reason="in_flight_capacity"}[5m]) > 0
        labels: { severity: warning }
        annotations:
          summary: "max_in_flight reached; work is being refused."
      - alert: TackTransmissionGuardPanics
        expr: increase(tack_transmission_guard_panics_total[10m]) > 0
        labels: { severity: warning }
        annotations:
          summary: "A worker panicked while holding a drive guard. The count was released, but the worker failed."
      - alert: TackTransmissionGearDropPanics
        expr: increase(tack_transmission_gear_drop_panics_total[1h]) > 0
        labels: { severity: warning }
        annotations:
          summary: "A replaced configuration panicked in Drop during a shift. The shift completed; the configuration type has a bug."
"#;

pub(crate) fn epoch_value(epoch: u64) -> f64 {
    // Precision loss above 2^53 is acceptable for a dashboard gauge; the
    // exact epoch is in the API and in span fields.
    epoch as f64
}

pub(crate) fn count_value(n: usize) -> f64 {
    // Counts are bounded by config caps far below 2^53.
    n as f64
}

pub(crate) fn flag_value(b: bool) -> f64 {
    if b {
        1.0
    } else {
        0.0
    }
}

/// Registers every gauge without changing its value. Adding zero leaves a
/// value another instance wrote in place, where `set(0.0)` would clear it.
pub(crate) fn register_gauges() {
    for name in [IN_FLIGHT, WAITING_ENGAGERS, CLUTCH_PRESSED, GEAR_EPOCH, HALTED] {
        metrics::gauge!(name).increment(0.0);
    }
}

pub(crate) fn set_in_flight(n: usize) {
    metrics::gauge!(IN_FLIGHT).set(count_value(n));
}

pub(crate) fn set_waiting(n: usize) {
    metrics::gauge!(WAITING_ENGAGERS).set(count_value(n));
}

pub(crate) fn set_clutch(pressed: bool) {
    metrics::gauge!(CLUTCH_PRESSED).set(flag_value(pressed));
}

pub(crate) fn set_epoch(epoch: u64) {
    metrics::gauge!(GEAR_EPOCH).set(epoch_value(epoch));
}

pub(crate) fn set_halted(halted: bool) {
    metrics::gauge!(HALTED).set(flag_value(halted));
}

pub(crate) fn halt(cause: HaltCause) {
    metrics::counter!(HALTS_TOTAL, "cause" => cause.as_str()).increment(1);
    set_halted(true);
}

pub(crate) fn poison_recovered() {
    metrics::counter!(LOCK_POISON_RECOVERIES_TOTAL).increment(1);
}

pub(crate) fn operator_reset() {
    metrics::counter!(OPERATOR_RESETS_TOTAL).increment(1);
}

pub(crate) fn gear_drop_panicked() {
    metrics::counter!(GEAR_DROP_PANICS_TOTAL).increment(1);
}

pub(crate) fn guard_panicked() {
    metrics::counter!(GUARD_PANICS_TOTAL).increment(1);
}

/// Records the end of one `engage()` or `shift()` call.
pub(crate) fn finish(op: Operation, result: Result<(), Reason>, elapsed: Duration) {
    let outcome = match result {
        Ok(()) => GateOutcome::Pass,
        Err(r) => r.outcome(),
    };
    let secs = elapsed.as_secs_f64();
    match op {
        Operation::Engage => {
            metrics::counter!(ENGAGE_TOTAL, "outcome" => outcome.as_str()).increment(1);
            metrics::histogram!(ENGAGE_WAIT_SECONDS, "outcome" => outcome.as_str()).record(secs);
        }
        Operation::Shift => {
            metrics::counter!(SHIFT_TOTAL, "outcome" => outcome.as_str()).increment(1);
        }
    }
    if let Err(r) = result {
        metrics::counter!(
            TRIPS_TOTAL,
            "operation" => op.as_str(),
            "reason" => r.as_str(),
            "outcome" => outcome.as_str(),
            "resolution" => r.resolution().as_str()
        )
        .increment(1);
    }
}

/// Records how long the clutch was pressed for one shift.
pub(crate) fn shift_drain(outcome: GateOutcome, pressed_for: Duration) {
    metrics::histogram!(SHIFT_DRAIN_SECONDS, "outcome" => outcome.as_str())
        .record(pressed_for.as_secs_f64());
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_follow_the_kernel_convention() {
        for name in ALL_METRICS {
            assert!(name.starts_with("tack_transmission_"), "{name}");
        }
        for name in [ENGAGE_WAIT_SECONDS, SHIFT_DRAIN_SECONDS] {
            assert!(name.ends_with("_seconds"), "{name}");
        }
        for name in ALL_METRICS {
            if name.contains("total") {
                assert!(name.ends_with("_total"), "{name}");
            }
        }
        for span in [SPAN_ENGAGE, SPAN_SHIFT, SPAN_OPERATOR_HALT, SPAN_OPERATOR_RESET] {
            assert!(span.starts_with("stack.transmission."), "{span}");
        }
    }

    #[test]
    fn every_alert_references_only_declared_metrics() {
        let mut referenced = 0;
        for word in PROMETHEUS_RULES
            .split(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
            .filter(|w| w.starts_with("tack_transmission_"))
        {
            assert!(ALL_METRICS.contains(&word), "undeclared metric {word}");
            referenced += 1;
        }
        assert!(referenced >= 7);
        assert!(!PROMETHEUS_RULES.contains('\u{2014}'));
    }
}
