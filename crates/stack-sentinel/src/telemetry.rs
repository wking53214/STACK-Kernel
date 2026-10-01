//! Metric names, label sets and the Prometheus alert rules for this crate.
//!
//! Every label value comes from a closed enum in this crate
//! ([`crate::Verdict`], [`crate::Reason`], [`crate::GateOutcome`],
//! [`crate::Resolution`], or [`VerifyError::label`]). No label is ever built from export content,
//! because a free-form label is a cardinality attack.
//!
//! | metric | type | labels |
//! |---|---|---|
//! | `stack_sentinel_verifications_total` | counter | `verdict`, `outcome` |
//! | `stack_sentinel_trips_total` | counter | `verdict`, `reason`, `outcome`, `resolution` |
//! | `stack_sentinel_input_rejected_total` | counter | `reason`, `outcome` |
//! | `stack_sentinel_rows_checked_total` | counter | none |
//! | `stack_sentinel_verify_duration_seconds` | histogram | `outcome` |

use std::time::Duration;

use crate::error::VerifyError;
use crate::verdict::{Finding, GateOutcome, Report};

/// One per export that reached a verdict.
pub const VERIFICATIONS_TOTAL: &str = "stack_sentinel_verifications_total";
/// One per finding in a report: the first finding and, when present, the
/// anchor finding printed beside it and the escalation finding.
pub const TRIPS_TOTAL: &str = "stack_sentinel_trips_total";
/// One per export or key input refused before a verdict.
pub const INPUT_REJECTED_TOTAL: &str = "stack_sentinel_input_rejected_total";
/// Rows the chain walk examined.
pub const ROWS_CHECKED_TOTAL: &str = "stack_sentinel_rows_checked_total";
/// Wall time of one `verify_export` call, verdict or refusal.
pub const VERIFY_DURATION_SECONDS: &str = "stack_sentinel_verify_duration_seconds";

/// Register descriptions with the installed recorder. Optional.
pub fn describe_metrics() {
    metrics::describe_counter!(VERIFICATIONS_TOTAL, "Ledger exports that reached a verdict, by verdict and CNS outcome.");
    metrics::describe_counter!(TRIPS_TOTAL, "Findings in verification reports, by verdict, reason, CNS outcome and resolution.");
    metrics::describe_counter!(INPUT_REJECTED_TOTAL, "Exports or key inputs refused before a verdict, by reason.");
    metrics::describe_counter!(ROWS_CHECKED_TOTAL, "Ledger rows examined by the chain walk.");
    metrics::describe_histogram!(
        VERIFY_DURATION_SECONDS,
        metrics::Unit::Seconds,
        "Wall time of one export verification."
    );
}

fn record_trip(f: &Finding) {
    let r = f.reason;
    metrics::counter!(
        TRIPS_TOTAL,
        "verdict" => r.verdict().label(),
        "reason" => r.label(),
        "outcome" => r.gate_outcome().as_str(),
        "resolution" => r.resolution().as_str()
    )
    .increment(1);
}

/// The verification outcome label is [`Report::gate_outcome`], the most
/// severe across every finding.
pub(crate) fn record_report(report: &Report, elapsed: Duration) {
    let outcome = report.gate_outcome();
    metrics::counter!(
        VERIFICATIONS_TOTAL,
        "verdict" => report.verdict().label(),
        "outcome" => outcome.as_str()
    )
    .increment(1);
    for f in report.findings() {
        record_trip(f);
    }
    metrics::counter!(ROWS_CHECKED_TOTAL).increment(report.rows_checked as u64);
    metrics::histogram!(VERIFY_DURATION_SECONDS, "outcome" => outcome.as_str()).record(elapsed.as_secs_f64());
}

pub(crate) fn record_rejected(err: &VerifyError, elapsed: Option<Duration>) {
    metrics::counter!(
        INPUT_REJECTED_TOTAL,
        "reason" => err.label(),
        "outcome" => err.gate_outcome().as_str()
    )
    .increment(1);
    if let Some(elapsed) = elapsed {
        metrics::histogram!(VERIFY_DURATION_SECONDS, "outcome" => GateOutcome::Retry.as_str())
            .record(elapsed.as_secs_f64());
    }
}

/// One Prometheus alert rule over the metrics above.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AlertRule {
    /// Rule name.
    pub name: &'static str,
    /// PromQL expression.
    pub expr: &'static str,
    /// How long the expression must hold, when the rule needs it.
    pub for_duration: Option<&'static str>,
    /// `critical`, `warning` or `info`.
    pub severity: &'static str,
    /// What it means and what to do.
    pub meaning: &'static str,
}

/// The alert rules shipped with this crate.
pub const ALERT_RULES: [AlertRule; 5] = [
    AlertRule {
        name: "TackSentinelTamperEvidence",
        expr: "sum(increase(stack_sentinel_trips_total{outcome=\"terminal_breach\"}[15m])) > 0",
        for_duration: None,
        severity: "critical",
        meaning: "An export failed a hash, link, signature, subject binding, seed or anchor-head check, \
                  or carries a signature by a retired key or by an unknown key after the attestation policy. \
                  The ledger or its export was altered. Quarantine the export and compare it with the witness copy.",
    },
    AlertRule {
        name: "TackSentinelTruncation",
        expr: "sum(increase(stack_sentinel_trips_total{verdict=\"truncated\",outcome=\"terminal_breach\"}[15m])) > 0",
        for_duration: None,
        severity: "critical",
        meaning: "The chain is shorter than its signed anchor, or the anchored head is not in it, \
                  or the anchor itself was altered. Rows were cut or the chain was rebuilt.",
    },
    AlertRule {
        name: "TackSentinelVerificationCannotComplete",
        expr: "sum(increase(stack_sentinel_verifications_total{outcome=\"retry\"}[1h])) \
               + sum(increase(stack_sentinel_input_rejected_total[1h])) > 3",
        for_duration: Some("15m"),
        severity: "warning",
        meaning: "Verifications keep ending in RETRY: the anchor is missing, stale, empty or sealed \
                  with a retired key, a key is not held, or exports are malformed or over budget. \
                  Audits are not happening even though nothing tripped.",
    },
    AlertRule {
        name: "TackSentinelNoCleanVerification",
        expr: "absent_over_time(stack_sentinel_verifications_total{verdict=\"verified\"}[26h])",
        for_duration: None,
        severity: "warning",
        meaning: "No export verified cleanly in 26 hours. For a daily audit job this means the job \
                  stopped or every run failed.",
    },
    AlertRule {
        name: "TackSentinelSlowVerification",
        expr: "histogram_quantile(0.99, sum by (le) (rate(stack_sentinel_verify_duration_seconds_bucket[1h]))) > 60",
        for_duration: Some("30m"),
        severity: "info",
        meaning: "Verification p99 above one minute. The ledger has outgrown the export cap planning, \
                  or the host is starved.",
    },
];
