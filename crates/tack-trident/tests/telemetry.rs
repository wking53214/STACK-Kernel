//! Telemetry tests: every metric the crate emits fires, with closed labels,
//! and a payload bomb is refused before any prong hashing happens.

mod common;

use common::*;
use metrics_util::debugging::{DebugValue, DebuggingRecorder};
use metrics_util::MetricKind;
use serde_json::json;
use tack_trident::telemetry as t;
use tack_trident::{ReasonCode, TridentConfig};

#[derive(Debug)]
struct Seen {
    kind: MetricKind,
    name: String,
    labels: Vec<(String, String)>,
    value: DebugValue,
}

fn record<F: FnOnce()>(f: F) -> Vec<Seen> {
    let recorder = DebuggingRecorder::new();
    let snapshotter = recorder.snapshotter();
    metrics::with_local_recorder(&recorder, f);
    snapshotter
        .snapshot()
        .into_vec()
        .into_iter()
        .map(|(ck, _, _, value)| {
            let (kind, key) = ck.into_parts();
            let mut labels: Vec<(String, String)> = key
                .labels()
                .map(|l| (l.key().to_owned(), l.value().to_owned()))
                .collect();
            labels.sort();
            Seen {
                kind,
                name: key.name().to_owned(),
                labels,
                value,
            }
        })
        .collect()
}

fn counter(seen: &[Seen], name: &str, labels: &[(&str, &str)]) -> u64 {
    let mut want: Vec<(String, String)> = labels.iter().map(|(k, v)| ((*k).to_owned(), (*v).to_owned())).collect();
    want.sort();
    seen.iter()
        .filter(|s| s.kind == MetricKind::Counter && s.name == name && s.labels == want)
        .map(|s| match s.value {
            DebugValue::Counter(n) => n,
            _ => 0,
        })
        .sum()
}

fn gauge(seen: &[Seen], name: &str) -> Option<f64> {
    seen.iter()
        .find(|s| s.kind == MetricKind::Gauge && s.name == name)
        .and_then(|s| match &s.value {
            DebugValue::Gauge(g) => Some(g.into_inner()),
            _ => None,
        })
}

fn histogram_count(seen: &[Seen], name: &str, outcome: &str) -> usize {
    seen.iter()
        .filter(|s| {
            s.kind == MetricKind::Histogram
                && s.name == name
                && s.labels == vec![("outcome".to_owned(), outcome.to_owned())]
        })
        .map(|s| match &s.value {
            DebugValue::Histogram(v) => v.len(),
            _ => 0,
        })
        .sum()
}

#[test]
fn verification_metrics_fire_with_closed_labels() {
    let fx = setup();
    let seen = record(|| {
        assert!(fx.trident.verify(&fx.sealed(1)).is_accepted());
        let mut forged = fx.sealed(2);
        forged.payload = json!({"x": 1});
        fx.trident.verify(&forged);
        fx.trident.verify_wire(b"{");
    });
    assert_eq!(
        counter(&seen, t::VERIFICATIONS_TOTAL, &[("outcome", "pass"), ("resolution", "accept")]),
        1
    );
    assert_eq!(
        counter(&seen, t::VERIFICATIONS_TOTAL, &[("outcome", "terminal_breach"), ("resolution", "reject")]),
        1
    );
    assert_eq!(
        counter(&seen, t::VERIFICATIONS_TOTAL, &[("outcome", "retry"), ("resolution", "reject")]),
        1
    );
    assert_eq!(
        counter(&seen, t::CHECK_FAILURES_TOTAL, &[("check", "authenticity"), ("reason", "mac_mismatch")]),
        1
    );
    assert_eq!(
        counter(
            &seen,
            t::CHECK_FAILURES_TOTAL,
            &[("check", "binding"), ("reason", "subject_digest_mismatch")]
        ),
        1
    );
    assert_eq!(
        counter(&seen, t::CHECK_FAILURES_TOTAL, &[("check", "admission"), ("reason", "malformed_json")]),
        1
    );
    assert_eq!(histogram_count(&seen, t::VERIFY_DURATION_SECONDS, "pass"), 1);
    assert_eq!(histogram_count(&seen, t::VERIFY_DURATION_SECONDS, "terminal_breach"), 1);
    assert_eq!(histogram_count(&seen, t::VERIFY_DURATION_SECONDS, "retry"), 1);
    assert!(counter(&seen, t::HASHED_BYTES_TOTAL, &[]) > 0);
    assert_eq!(gauge(&seen, t::REPLAY_CACHE_ENTRIES), Some(1.0));

    // Every name follows the convention and every label value is from a
    // closed vocabulary.
    let reason_spellings: Vec<&str> = ReasonCode::ALL.iter().map(|r| r.as_str()).collect();
    for s in &seen {
        assert!(s.name.starts_with("tack_trident_"), "{}", s.name);
        if s.kind == MetricKind::Counter {
            assert!(s.name.ends_with("_total"), "{}", s.name);
        }
        if s.kind == MetricKind::Histogram {
            assert!(s.name.ends_with("_seconds"), "{}", s.name);
        }
        for (k, v) in &s.labels {
            let closed = match k.as_str() {
                "outcome" => ["pass", "retry", "terminal_breach"].contains(&v.as_str()),
                "resolution" => ["accept", "reject", "quarantine", "halt"].contains(&v.as_str()),
                "check" => ["admission", "custody", "authenticity", "binding", "freshness", "capacity"]
                    .contains(&v.as_str()),
                "reason" => reason_spellings.contains(&v.as_str()),
                "cause" => ["poisoned", "operator"].contains(&v.as_str()),
                _ => false,
            };
            assert!(closed, "label {k}={v} on {}", s.name);
        }
    }
}

#[test]
fn payload_bombs_are_refused_before_any_prong_hashing() {
    let fx = setup();
    let seen = record(|| {
        let depth = format!("{{\"payload\":{}{}}}", "[".repeat(30_000), "]".repeat(30_000));
        assert!(fx.trident.verify_wire(depth.as_bytes()).refusal().unwrap().has(ReasonCode::TooDeep));
        let size = vec![b'['; 5 * fx.cfg.max_envelope_bytes];
        assert!(fx
            .trident
            .verify_wire(&size)
            .refusal()
            .unwrap()
            .has(ReasonCode::EnvelopeTooLarge));
        let mut env = fx.sealed(1);
        let mut deep = json!(0);
        for _ in 0..500 {
            deep = json!([deep]);
        }
        env.payload = deep;
        assert!(fx.trident.verify(&env).refusal().unwrap().has(ReasonCode::TooDeep));
    });
    assert_eq!(counter(&seen, t::HASHED_BYTES_TOTAL, &[]), 0);
    assert_eq!(
        counter(&seen, t::CHECK_FAILURES_TOTAL, &[("check", "admission"), ("reason", "too_deep")]),
        2
    );
    assert_eq!(
        counter(
            &seen,
            t::CHECK_FAILURES_TOTAL,
            &[("check", "admission"), ("reason", "envelope_too_large")]
        ),
        1
    );
}

#[test]
fn unknown_and_known_senders_cost_the_same_hashing() {
    let fx = setup();
    let unknown = fx.sealed_by(&fx.key_x, 1);
    let mut forged = fx.sealed(1);
    forged.mac = "33".repeat(32);
    assert_eq!(unknown.sender.len(), forged.sender.len());
    let a = record(|| {
        fx.trident.verify(&unknown);
    });
    let b = record(|| {
        fx.trident.verify(&forged);
    });
    let (ha, hb) = (counter(&a, t::HASHED_BYTES_TOTAL, &[]), counter(&b, t::HASHED_BYTES_TOTAL, &[]));
    assert!(ha > 0);
    assert_eq!(ha, hb);
}

#[test]
fn breaker_release_halt_and_reset_metrics_fire() {
    let fx = setup_with(TridentConfig {
        breaker_threshold: 1,
        ..TridentConfig::default()
    });
    let seen = record(|| {
        let mut env = fx.sealed(1);
        env.payload = json!({"moved": true});
        remac(&mut env, "a");
        fx.trident.verify(&env);
        fx.trident.verify(&fx.sealed(2));
    });
    assert_eq!(counter(&seen, t::QUARANTINE_TRIPS_TOTAL, &[]), 1);
    assert_eq!(gauge(&seen, t::QUARANTINED_SENDERS), Some(1.0));
    assert_eq!(
        counter(&seen, t::VERIFICATIONS_TOTAL, &[("outcome", "terminal_breach"), ("resolution", "quarantine")]),
        2
    );
    assert_eq!(
        counter(&seen, t::CHECK_FAILURES_TOTAL, &[("check", "custody"), ("reason", "quarantined")]),
        1
    );

    let seen = record(|| {
        assert!(fx.trident.release(&fx.fp_a).unwrap());
        fx.trident.operator_halt();
        fx.trident.operator_halt(); // second call does not count again
        fx.trident.verify(&fx.sealed(3));
        fx.trident.operator_reset();
    });
    assert_eq!(counter(&seen, t::QUARANTINE_RELEASES_TOTAL, &[]), 1);
    assert_eq!(counter(&seen, t::HALTS_TOTAL, &[("cause", "operator")]), 1);
    assert_eq!(
        counter(&seen, t::VERIFICATIONS_TOTAL, &[("outcome", "retry"), ("resolution", "halt")]),
        1
    );
    assert_eq!(counter(&seen, t::OPERATOR_RESETS_TOTAL, &[]), 1);
    assert_eq!(gauge(&seen, t::QUARANTINED_SENDERS), Some(0.0));
    assert_eq!(gauge(&seen, t::REPLAY_CACHE_ENTRIES), Some(0.0));
}

#[test]
fn untracked_breach_is_counted() {
    let fx = setup_with(TridentConfig {
        max_tracked_senders: 1,
        ..TridentConfig::default()
    });
    assert!(fx.trident.verify(&fx.sealed(1)).is_accepted());
    let seen = record(|| {
        let mut env = fx.sealed_by(&fx.key_b, 1);
        env.payload = json!({"moved": true});
        remac(&mut env, "b");
        fx.trident.verify(&env);
    });
    assert_eq!(counter(&seen, t::BREAKER_UNTRACKED_TOTAL, &[]), 1);
}
