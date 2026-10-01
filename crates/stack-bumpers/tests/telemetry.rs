//! The metrics fire and carry only closed-enum labels.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use common::{fixture, num, qty, req, text};
use metrics_util::debugging::{DebugValue, DebuggingRecorder, Snapshotter};
use tack_bumpers::telemetry::{
    self, CORRECTIONS_PER_REQUEST, CORRECTIONS_TOTAL, NORMALIZE_DURATION_SECONDS, REQUESTS_TOTAL, TRIPS_TOTAL,
};
use tack_bumpers::{CorrectionKind, GateOutcome, TripReason};

type Row = (String, Vec<(String, String)>, DebugValue);

fn rows(snap: &Snapshotter) -> Vec<Row> {
    snap.snapshot()
        .into_vec()
        .into_iter()
        .map(|(ck, _unit, _desc, v)| {
            let key = ck.key();
            let labels = key
                .labels()
                .map(|l| (l.key().to_owned(), l.value().to_owned()))
                .collect();
            (key.name().to_owned(), labels, v)
        })
        .collect()
}

fn counter(rows: &[Row], name: &str, labels: &[(&str, &str)]) -> u64 {
    rows.iter()
        .filter(|(n, ls, _)| {
            n == name && labels.iter().all(|(k, v)| ls.iter().any(|(lk, lv)| lk == k && lv == v))
        })
        .map(|(_, _, v)| match v {
            DebugValue::Counter(c) => *c,
            other => panic!("{name} is not a counter: {other:?}"),
        })
        .sum()
}

fn histogram_len(rows: &[Row], name: &str, labels: &[(&str, &str)]) -> usize {
    rows.iter()
        .filter(|(n, ls, _)| {
            n == name && labels.iter().all(|(k, v)| ls.iter().any(|(lk, lv)| lk == k && lv == v))
        })
        .map(|(_, _, v)| match v {
            DebugValue::Histogram(h) => h.len(),
            other => panic!("{name} is not a histogram: {other:?}"),
        })
        .sum()
}

fn run<F: FnOnce()>(f: F) -> Vec<Row> {
    let recorder = DebuggingRecorder::new();
    let snap = recorder.snapshotter();
    metrics::with_local_recorder(&recorder, || {
        telemetry::describe_metrics();
        f();
    });
    rows(&snap)
}

#[test]
fn pass_emits_request_duration_and_corrections() {
    let r = run(|| {
        fixture()
            .normalize(&req(&[("timeout", qty(1500.0, "ms")), ("priority", text("High"))]))
            .unwrap();
    });
    assert_eq!(counter(&r, REQUESTS_TOTAL, &[("outcome", "pass")]), 1);
    assert_eq!(counter(&r, CORRECTIONS_TOTAL, &[("kind", "unit_converted")]), 1);
    assert_eq!(counter(&r, CORRECTIONS_TOTAL, &[("kind", "case_folded")]), 1);
    assert_eq!(counter(&r, CORRECTIONS_TOTAL, &[]), 2);
    assert_eq!(histogram_len(&r, NORMALIZE_DURATION_SECONDS, &[("outcome", "pass")]), 1);
    assert_eq!(histogram_len(&r, CORRECTIONS_PER_REQUEST, &[]), 1);
    assert_eq!(counter(&r, TRIPS_TOTAL, &[]), 0);
}

#[test]
fn every_correction_kind_is_counted() {
    let r = run(|| {
        let b = fixture();
        b.normalize(&req(&[("timeout", num(0.1))])).unwrap(); // clamped
        b.normalize(&req(&[("timeout", qty(1500.0, "ms"))])).unwrap(); // unit_converted
        b.normalize(&req(&[("label", text(" x "))])).unwrap(); // trimmed
        b.normalize(&req(&[("priority", text("LOW"))])).unwrap(); // case_folded
        b.normalize(&req(&[("priority", text("hi"))])).unwrap(); // alias_resolved
    });
    for kind in CorrectionKind::LABELS {
        assert_eq!(counter(&r, CORRECTIONS_TOTAL, &[("kind", kind)]), 1, "{kind}");
    }
    assert_eq!(counter(&r, REQUESTS_TOTAL, &[("outcome", "pass")]), 5);
}

#[test]
fn retry_emits_trip_with_reason_and_outcome() {
    let r = run(|| {
        let _ = fixture().normalize(&req(&[("priority", text("urgent"))]));
    });
    assert_eq!(counter(&r, REQUESTS_TOTAL, &[("outcome", "retry")]), 1);
    assert_eq!(
        counter(&r, TRIPS_TOTAL, &[("reason", "unknown_variant"), ("outcome", "retry")]),
        1
    );
    assert_eq!(histogram_len(&r, NORMALIZE_DURATION_SECONDS, &[("outcome", "retry")]), 1);
    assert_eq!(counter(&r, CORRECTIONS_TOTAL, &[]), 0);
    assert_eq!(histogram_len(&r, CORRECTIONS_PER_REQUEST, &[]), 0);
}

#[test]
fn terminal_breach_emits_trip() {
    let r = run(|| {
        let _ = fixture().normalize(&req(&[("timeout", num(f64::NAN))]));
    });
    assert_eq!(counter(&r, REQUESTS_TOTAL, &[("outcome", "terminal_breach")]), 1);
    assert_eq!(
        counter(&r, TRIPS_TOTAL, &[("reason", "non_finite"), ("outcome", "terminal_breach")]),
        1
    );
}

#[test]
fn budget_exhaustion_is_counted_and_corrections_are_not() {
    let r = run(|| {
        let _ = fixture().normalize(&req(&[("timeout", qty(2.0, "min")), ("priority", text(" HI "))]));
    });
    assert_eq!(
        counter(&r, TRIPS_TOTAL, &[("reason", "correction_budget_exceeded")]),
        1
    );
    assert_eq!(counter(&r, CORRECTIONS_TOTAL, &[]), 0, "a refused request applies nothing");
}

#[test]
fn one_trip_counter_per_trip() {
    let r = run(|| {
        let mut m = req(&[("a", num(1.0)), ("b", num(1.0)), ("timeout", num(f64::INFINITY))]);
        m.remove("priority");
        let rej = fixture().normalize(&m).unwrap_err();
        assert_eq!(rej.outcome, GateOutcome::TerminalBreach);
        assert_eq!(rej.trips.len(), 4);
    });
    assert_eq!(counter(&r, TRIPS_TOTAL, &[("reason", "unknown_param")]), 2);
    assert_eq!(counter(&r, TRIPS_TOTAL, &[("reason", "missing_required")]), 1);
    assert_eq!(counter(&r, TRIPS_TOTAL, &[("reason", "non_finite")]), 1);
    assert_eq!(counter(&r, TRIPS_TOTAL, &[]), 4);
    assert_eq!(counter(&r, REQUESTS_TOTAL, &[]), 1);
}

#[test]
fn labels_never_carry_request_data() {
    let hostile = "evil\"} 1\nx{label";
    let r = run(|| {
        let b = fixture();
        let _ = b.normalize(&req(&[(hostile, text(hostile))]));
        let _ = b.normalize(&req(&[("priority", text(hostile))]));
        let _ = b.normalize(&req(&[("timeout", qty(1.0, hostile))]));
        let _ = b.normalize(&req(&[("label", text(hostile))]));
    });
    let mut allowed: Vec<&str> = vec!["pass", "retry", "terminal_breach"];
    allowed.extend(TripReason::ALL.iter().map(|t| t.as_str()));
    allowed.extend(CorrectionKind::LABELS);
    assert!(!r.is_empty());
    for (name, labels, _) in &r {
        assert!(name.starts_with("tack_bumpers_"), "{name}");
        for (k, v) in labels {
            assert!(["outcome", "reason", "kind"].contains(&k.as_str()), "label key {k}");
            assert!(allowed.contains(&v.as_str()), "label value {v:?} on {name}");
        }
    }
}
