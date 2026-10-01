//! The metrics and logs fire, with closed-set labels only, and logs never
//! carry raw input.

#![allow(clippy::unwrap_used, clippy::panic)] // test code: failures should abort the test

use metrics_util::debugging::{DebugValue, DebuggingRecorder, Snapshotter};
use std::collections::BTreeSet;
use tack_anc_pipeline::telemetry::names;
use tack_anc_pipeline::{
    Accepted, PipelineConfig, PipelineGate, TokenSecret, Trip, Validator, TOKEN_LEN,
};

// Test fixture, not a key. Printable so a raw leak into a log is easy to spot.
const FIXTURE: &[u8; TOKEN_LEN] = b"FIXTURE-not-a-key-0123456789abcd";

type Entry = (String, Vec<(String, String)>, DebugValue);

fn snapshot(s: &Snapshotter) -> Vec<Entry> {
    s.snapshot()
        .into_vec()
        .into_iter()
        .map(|(ck, _, _, v)| {
            let key = ck.key();
            let mut labels: Vec<(String, String)> = key
                .labels()
                .map(|l| (l.key().to_string(), l.value().to_string()))
                .collect();
            labels.sort();
            (key.name().to_string(), labels, v)
        })
        .collect()
}

fn find<'a>(snap: &'a [Entry], name: &str, labels: &[(&str, &str)]) -> Option<&'a DebugValue> {
    let mut want: Vec<(String, String)> = labels
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect();
    want.sort();
    snap.iter()
        .find(|(n, l, _)| n == name && *l == want)
        .map(|(_, _, v)| v)
}

fn counter(snap: &[Entry], name: &str, labels: &[(&str, &str)]) -> u64 {
    match find(snap, name, labels) {
        Some(DebugValue::Counter(c)) => *c,
        _ => 0,
    }
}

fn hist_len(snap: &[Entry], name: &str, labels: &[(&str, &str)]) -> usize {
    match find(snap, name, labels) {
        Some(DebugValue::Histogram(v)) => v.len(),
        _ => 0,
    }
}

fn gate(validator: Validator, record_response_time: bool) -> PipelineGate {
    let cfg = PipelineConfig {
        validator,
        allow_leaky_validators: true,
        record_response_time,
        ..PipelineConfig::default()
    };
    PipelineGate::new(TokenSecret::from_bytes(FIXTURE).unwrap(), cfg).unwrap()
}

fn wrong_at(pos: usize) -> [u8; TOKEN_LEN] {
    let mut c = *FIXTURE;
    c[pos] ^= 0x01;
    c
}

#[test]
fn metrics_fire_for_every_outcome() {
    let rec = DebuggingRecorder::new();
    let snap = rec.snapshotter();
    metrics::with_local_recorder(&rec, || {
        let g = gate(Validator::ConstantTime, true);
        assert_eq!(g.check(FIXTURE), Ok(Accepted));
        assert_eq!(g.check(&wrong_at(0)), Err(Trip::Mismatch));
        assert_eq!(g.check(&wrong_at(31)), Err(Trip::Mismatch));
        assert_eq!(g.check(&[0u8; TOKEN_LEN + 1]), Err(Trip::InputTooLarge));
        assert_eq!(g.check(&[0u8; 3]), Err(Trip::Malformed));
    });
    let s = snapshot(&snap);
    let base = [("strategy", "pipeline"), ("validator", "constant_time")];
    let with = |o: &'static str| [base[0], base[1], ("outcome", o)];
    assert_eq!(counter(&s, names::REQUESTS_TOTAL, &with("pass")), 1);
    assert_eq!(counter(&s, names::REQUESTS_TOTAL, &with("retry")), 4);
    assert_eq!(counter(&s, names::TOKEN_MISMATCH_TOTAL, &base), 2);
    let shed = |r: &'static str| [("strategy", "pipeline"), ("reason", r)];
    assert_eq!(counter(&s, names::SHED_TOTAL, &shed("input_too_large")), 1);
    assert_eq!(counter(&s, names::SHED_TOTAL, &shed("malformed")), 1);
    assert_eq!(counter(&s, names::SHED_TOTAL, &shed("slots_full")), 0);
    assert_eq!(hist_len(&s, names::RESPONSE_SECONDS, &with("pass")), 1);
    assert_eq!(hist_len(&s, names::RESPONSE_SECONDS, &with("retry")), 4);
    // constant_time never sets the leaky gauge.
    assert!(s.iter().all(|(n, _, _)| n != names::LEAKY_VALIDATOR_ACTIVE));
}

#[test]
fn class_a_and_class_b_take_the_same_telemetry_path() {
    // Wrong at byte 0 and wrong at byte 31 must produce identical metric
    // updates, or the telemetry itself would be a timing channel.
    for v in Validator::ALL {
        let mut seen = Vec::new();
        for pos in [0usize, 31] {
            let rec = DebuggingRecorder::new();
            let snap = rec.snapshotter();
            metrics::with_local_recorder(&rec, || {
                let g = gate(v, true);
                let _ = g.check(&wrong_at(pos));
            });
            let mut keys: Vec<(String, Vec<(String, String)>)> = snapshot(&snap)
                .into_iter()
                .filter(|(n, _, _)| n != names::LEAKY_VALIDATOR_ACTIVE)
                .map(|(n, l, _)| (n, l))
                .collect();
            keys.sort();
            seen.push(keys);
        }
        assert_eq!(seen[0], seen[1], "{v:?}");
    }
}

#[test]
fn leaky_validator_gauge_fires() {
    for v in [Validator::EarlyExit, Validator::BalancedDummy] {
        let rec = DebuggingRecorder::new();
        let snap = rec.snapshotter();
        metrics::with_local_recorder(&rec, || {
            let _g = gate(v, true);
        });
        let s = snapshot(&snap);
        match find(
            &s,
            names::LEAKY_VALIDATOR_ACTIVE,
            &[("strategy", "pipeline"), ("validator", v.label())],
        ) {
            Some(DebugValue::Gauge(g)) => assert_eq!(g.into_inner(), 1.0),
            other => panic!("gauge missing for {v:?}: {other:?}"),
        }
    }
}

#[test]
fn response_histogram_off_when_disabled() {
    let rec = DebuggingRecorder::new();
    let snap = rec.snapshotter();
    metrics::with_local_recorder(&rec, || {
        let g = gate(Validator::ConstantTime, false);
        let _ = g.check(FIXTURE);
    });
    let s = snapshot(&snap);
    assert!(s.iter().all(|(n, _, _)| n != names::RESPONSE_SECONDS));
    assert!(s.iter().any(|(n, _, _)| n == names::REQUESTS_TOTAL));
}

#[test]
fn labels_come_from_closed_sets() {
    let rec = DebuggingRecorder::new();
    let snap = rec.snapshotter();
    metrics::with_local_recorder(&rec, || {
        for v in Validator::ALL {
            let g = gate(v, true);
            let _ = g.check(FIXTURE);
            let _ = g.check(&wrong_at(7));
            let _ = g.check(b"attacker-chosen-label-value?");
            let _ = g.check(&[b'x'; 5000]);
        }
    });
    let allowed: BTreeSet<&str> = [
        "pipeline",
        "early_exit",
        "balanced_dummy",
        "constant_time",
        "pass",
        "retry",
        "terminal_breach",
        "slots_full",
        "input_too_large",
        "malformed",
    ]
    .into_iter()
    .collect();
    let s = snapshot(&snap);
    assert!(!s.is_empty());
    for (name, labels, _) in &s {
        assert!(name.starts_with("tack_anc_"), "{name}");
        for (k, v) in labels {
            assert!(
                ["strategy", "validator", "outcome", "reason"].contains(&k.as_str()),
                "label key {k}"
            );
            assert!(allowed.contains(v.as_str()), "label value {v} on {name}");
        }
        if name.ends_with("_total") {
            assert!(!labels.is_empty());
        }
    }
}
