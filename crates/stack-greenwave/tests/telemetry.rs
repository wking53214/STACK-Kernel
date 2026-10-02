//! The metrics fire, with the documented names and closed label sets.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::collections::HashMap;

use metrics_util::debugging::{DebugValue, DebuggingRecorder};
use metrics_util::MetricKind;
use stack_greenwave::telemetry as t;
use stack_greenwave::{GreenWaveConfig, LaneId, LaneSpec, ManualClock, TrafficCop};

const PHASE: u64 = 1_000;

type Labels = Vec<(String, String)>;

fn snapshot(recorder: &DebuggingRecorder) -> Vec<(MetricKind, String, Labels, DebugValue)> {
    recorder
        .snapshotter()
        .snapshot()
        .into_vec()
        .into_iter()
        .map(|(ck, _, _, v)| {
            let key = ck.key();
            let mut labels: Labels = key
                .labels()
                .map(|l| (l.key().to_string(), l.value().to_string()))
                .collect();
            labels.sort();
            (ck.kind(), key.name().to_string(), labels, v)
        })
        .collect()
}

fn counter(snap: &[(MetricKind, String, Labels, DebugValue)], name: &str, want: &[(&str, &str)]) -> u64 {
    snap.iter()
        .filter(|(k, n, labels, _)| {
            *k == MetricKind::Counter
                && n == name
                && want
                    .iter()
                    .all(|(wk, wv)| labels.iter().any(|(lk, lv)| lk == wk && lv == wv))
        })
        .map(|(_, _, _, v)| match v {
            DebugValue::Counter(c) => *c,
            _ => 0,
        })
        .sum()
}

fn gauge(snap: &[(MetricKind, String, Labels, DebugValue)], name: &str) -> Option<f64> {
    snap.iter().find_map(|(k, n, _, v)| match (k, v) {
        (MetricKind::Gauge, DebugValue::Gauge(g)) if n == name => Some(g.0),
        _ => None,
    })
}

fn histogram_len(snap: &[(MetricKind, String, Labels, DebugValue)], name: &str) -> usize {
    snap.iter()
        .filter_map(|(k, n, _, v)| match (k, v) {
            (MetricKind::Histogram, DebugValue::Histogram(h)) if n == name => Some(h.len()),
            _ => None,
        })
        .sum()
}

fn config() -> GreenWaveConfig {
    GreenWaveConfig {
        phase_len_ns: PHASE,
        phases_per_epoch: 2,
        lanes: vec![
            LaneSpec {
                weight: 1,
                queue_cap: 2,
            },
            LaneSpec {
                weight: 1,
                queue_cap: 2,
            },
        ],
        stage_offsets: vec![0, 1],
        max_dispatch_per_phase: 4,
    }
}

#[test]
fn every_metric_fires_with_closed_labels() {
    let recorder = DebuggingRecorder::new();
    metrics::with_local_recorder(&recorder, || {
        t::describe_metrics();
        let clock = ManualClock::new(0);
        let mut cop: TrafficCop<&'static str, _> = TrafficCop::new(&config(), clock.clone()).unwrap();

        // Admissions: 2 pass, 1 queue_full (retry), 1 unknown lane (breach).
        cop.admit(LaneId::new(0), "a").unwrap();
        cop.admit(LaneId::new(0), "b").unwrap();
        assert!(cop.admit(LaneId::new(0), "c").is_err());
        assert!(cop.admit(LaneId::new(9), "d").is_err());

        // Poll: dispatch 2 after 300 ns of queue wait.
        clock.set(300);
        let out = cop.poll().unwrap();
        assert_eq!(out.len(), 2);
        let ticket = out[0].ticket;

        // Stage checks: pass, not_yet_due (retry), unknown_stage, late.
        cop.stage_check(&ticket, 0).unwrap();
        assert!(cop.stage_check(&ticket, 1).is_err());
        assert!(cop.stage_check(&ticket, 5).is_err());
        clock.set(3 * PHASE);
        assert!(cop.stage_check(&ticket, 1).unwrap().late);

        // Release.
        cop.complete(&ticket).unwrap();

        // Missed phases: last poll was phase 0, now phase 5, so 4 missed.
        clock.set(5 * PHASE);
        cop.poll().unwrap();

        // Clock regression, halted refusal, reset.
        clock.set(PHASE);
        assert!(cop.poll().is_err());
        assert!(cop.is_halted());
        let _ = cop.admit(LaneId::new(0), "e");
        cop.reset();

        // A bad configuration.
        let mut bad = config();
        bad.phases_per_epoch = 3;
        assert!(TrafficCop::<(), _>::new(&bad, ManualClock::new(0)).is_err());
    });
    let snap = snapshot(&recorder);

    assert_eq!(counter(&snap, t::ADMISSIONS_TOTAL, &[("outcome", "pass")]), 2);
    assert_eq!(counter(&snap, t::ADMISSIONS_TOTAL, &[("outcome", "retry")]), 1);
    assert_eq!(counter(&snap, t::ADMISSIONS_TOTAL, &[("outcome", "terminal_breach")]), 2);
    assert_eq!(
        counter(
            &snap,
            t::TRIPS_TOTAL,
            &[("op", "admit"), ("reason", "queue_full"), ("outcome", "retry"), ("resolution", "reject")]
        ),
        1
    );
    assert_eq!(
        counter(&snap, t::TRIPS_TOTAL, &[("reason", "unknown_lane"), ("outcome", "terminal_breach")]),
        1
    );
    assert_eq!(counter(&snap, t::TRIPS_TOTAL, &[("op", "stage_check"), ("reason", "not_yet_due")]), 1);
    assert_eq!(counter(&snap, t::TRIPS_TOTAL, &[("op", "stage_check"), ("reason", "unknown_stage")]), 1);
    assert_eq!(
        counter(&snap, t::TRIPS_TOTAL, &[("op", "poll"), ("reason", "clock_regressed"), ("resolution", "halt")]),
        1
    );
    assert_eq!(counter(&snap, t::TRIPS_TOTAL, &[("op", "admit"), ("reason", "halted")]), 1);
    assert_eq!(counter(&snap, t::POLLS_TOTAL, &[("outcome", "pass")]), 2);
    assert_eq!(counter(&snap, t::POLLS_TOTAL, &[("outcome", "terminal_breach")]), 1);
    assert_eq!(counter(&snap, t::DISPATCHED_TOTAL, &[]), 2);
    assert_eq!(counter(&snap, t::STAGE_CHECKS_TOTAL, &[("outcome", "pass")]), 2);
    assert_eq!(counter(&snap, t::STAGE_CHECKS_TOTAL, &[("outcome", "retry")]), 1);
    assert_eq!(counter(&snap, t::STAGE_CHECKS_TOTAL, &[("outcome", "terminal_breach")]), 1);
    assert_eq!(counter(&snap, t::STAGE_LATE_TOTAL, &[]), 1);
    assert_eq!(counter(&snap, t::RELEASES_TOTAL, &[("outcome", "pass")]), 1);
    assert_eq!(counter(&snap, t::PHASES_MISSED_TOTAL, &[]), 4);
    assert_eq!(counter(&snap, t::RESETS_TOTAL, &[]), 1);
    assert_eq!(counter(&snap, t::CONFIG_REJECTED_TOTAL, &[("reason", "weight_sum_mismatch")]), 1);
    assert_eq!(histogram_len(&snap, t::QUEUE_WAIT_SECONDS), 2);
    let waits: Vec<f64> = snap
        .iter()
        .filter_map(|(_, n, _, v)| match v {
            DebugValue::Histogram(h) if n == t::QUEUE_WAIT_SECONDS => Some(h.iter().map(|x| x.0).collect::<Vec<_>>()),
            _ => None,
        })
        .flatten()
        .collect();
    assert!(waits.iter().all(|w| (*w - 300e-9).abs() < 1e-12), "{waits:?}");
    assert_eq!(gauge(&snap, t::QUEUE_DEPTH), Some(0.0));
    assert_eq!(gauge(&snap, t::HALTED), Some(0.0), "reset clears the halted gauge");

    // Naming and label conventions over everything that was emitted.
    let allowed: HashMap<&str, Vec<&str>> = HashMap::from([
        ("outcome", vec!["pass", "retry", "terminal_breach"]),
        ("resolution", vec!["reject", "quarantine", "rollback", "halt"]),
        ("op", vec!["admit", "poll", "stage_check", "complete"]),
        (
            "reason",
            vec![
                "queue_full",
                "unknown_lane",
                "unknown_stage",
                "not_yet_due",
                "completion_before_dispatch",
                "clock_regressed",
                "halted",
                "overflow",
                "weight_sum_mismatch",
            ],
        ),
    ]);
    for (kind, name, labels, _) in &snap {
        assert!(name.starts_with("tack_greenwave_"), "{name}");
        if *kind == MetricKind::Counter {
            assert!(name.ends_with("_total"), "{name}");
        }
        if *kind == MetricKind::Histogram {
            assert!(name.ends_with("_seconds"), "{name}");
        }
        for (k, v) in labels {
            let set = allowed.get(k.as_str()).unwrap_or_else(|| panic!("unexpected label key {k}"));
            assert!(set.contains(&v.as_str()), "label {k}={v} outside closed set");
        }
    }
}

#[test]
fn halted_gauge_is_set_on_clock_regression() {
    let recorder = DebuggingRecorder::new();
    metrics::with_local_recorder(&recorder, || {
        let clock = ManualClock::new(10 * PHASE);
        let mut cop: TrafficCop<(), _> = TrafficCop::new(&config(), clock.clone()).unwrap();
        clock.set(0);
        assert!(cop.admit(LaneId::new(0), ()).is_err());
    });
    let snap = snapshot(&recorder);
    assert_eq!(gauge(&snap, t::HALTED), Some(1.0));
    assert_eq!(
        counter(&snap, t::TRIPS_TOTAL, &[("op", "admit"), ("reason", "clock_regressed"), ("resolution", "halt")]),
        1
    );
}
