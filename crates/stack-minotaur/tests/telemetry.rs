//! The metrics fire, with closed-enum labels only.

// Test code: unwrapping and panicking on an unexpected result is the assertion.
#![allow(clippy::unwrap_used, clippy::panic)]

use metrics_util::debugging::{DebugValue, DebuggingRecorder};
use metrics_util::MetricKind;
use stack_minotaur::telemetry::{
    describe_metrics, DEGRADED_TOTAL, HALTS_TOTAL, LOOPS_DETECTED_TOTAL, OPERATOR_RESETS_TOTAL,
    ROLLBACKS_TOTAL, TRIPS_TOTAL, WALK_DISTINCT_STATES, WALK_DURATION_SECONDS, WALK_MAX_DEPTH,
    WALK_STEPS,
};
use stack_minotaur::{Fingerprint, MinotaurConfig, Thread};

type Row = (MetricKind, String, Vec<(String, String)>, DebugValue);

fn capture(f: impl FnOnce()) -> Vec<Row> {
    let recorder = DebuggingRecorder::new();
    let snapshotter = recorder.snapshotter();
    metrics::with_local_recorder(&recorder, f);
    snapshotter
        .snapshot()
        .into_vec()
        .into_iter()
        .map(|(ck, _, _, v)| {
            let (kind, key) = ck.into_parts();
            let mut labels: Vec<(String, String)> = key
                .labels()
                .map(|l| (l.key().to_string(), l.value().to_string()))
                .collect();
            labels.sort();
            (kind, key.name().to_string(), labels, v)
        })
        .collect()
}

fn want(labels: &[(&str, &str)]) -> Vec<(String, String)> {
    let mut w: Vec<(String, String)> = labels
        .iter()
        .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
        .collect();
    w.sort();
    w
}

fn counter(rows: &[Row], name: &str, labels: &[(&str, &str)]) -> u64 {
    let w = want(labels);
    rows.iter()
        .filter(|(k, n, l, _)| *k == MetricKind::Counter && n == name && *l == w)
        .map(|(_, _, _, v)| match v {
            DebugValue::Counter(c) => *c,
            _ => 0,
        })
        .sum()
}

fn histogram(rows: &[Row], name: &str, labels: &[(&str, &str)]) -> Vec<f64> {
    let w = want(labels);
    rows.iter()
        .filter(|(k, n, l, _)| *k == MetricKind::Histogram && n == name && *l == w)
        .flat_map(|(_, _, _, v)| match v {
            DebugValue::Histogram(h) => h.iter().map(|x| x.into_inner()).collect::<Vec<_>>(),
            _ => Vec::new(),
        })
        .collect()
}

fn fp(n: u64) -> Fingerprint {
    Fingerprint::of_bytes(&n.to_le_bytes())
}

#[test]
fn exact_loop_trip_fires_counters_and_walk_histograms() {
    let rows = capture(|| {
        describe_metrics();
        let mut t = Thread::new(MinotaurConfig {
            revisit_allowance: 0,
            ..Default::default()
        })
        .unwrap();
        let mut g = t.descend().unwrap();
        let mut g2 = g.descend().unwrap();
        g2.record(fp(1)).unwrap();
        g2.record(fp(2)).unwrap();
        g2.record(fp(1)).unwrap_err();
    });
    assert_eq!(
        counter(
            &rows,
            TRIPS_TOTAL,
            &[("reason", "loop_detected"), ("outcome", "retry")]
        ),
        1
    );
    assert_eq!(
        counter(&rows, LOOPS_DETECTED_TOTAL, &[("detector", "exact")]),
        1
    );
    assert_eq!(counter(&rows, ROLLBACKS_TOTAL, &[]), 1);
    assert_eq!(counter(&rows, HALTS_TOTAL, &[]), 0);
    assert_eq!(histogram(&rows, WALK_STEPS, &[("end", "trip")]), vec![3.0]);
    assert_eq!(
        histogram(&rows, WALK_MAX_DEPTH, &[("end", "trip")]),
        vec![2.0]
    );
    assert_eq!(
        histogram(&rows, WALK_DISTINCT_STATES, &[("end", "trip")]),
        vec![2.0]
    );
    let d = histogram(&rows, WALK_DURATION_SECONDS, &[("end", "trip")]);
    assert_eq!(d.len(), 1);
    assert!(d[0] >= 0.0);
}

#[test]
fn degraded_and_brent_loop_fire() {
    let rows = capture(|| {
        let cfg = MinotaurConfig {
            max_distinct_states: 4,
            revisit_allowance: 1,
            ..Default::default()
        };
        let mut t = Thread::new(cfg).unwrap();
        for n in 0..4 {
            t.record(fp(n)).unwrap();
        }
        let mut i = 0u64;
        while t.record(fp(100 + (i % 3))).is_ok() {
            i += 1;
            assert!(i < 1_000);
        }
    });
    assert_eq!(counter(&rows, DEGRADED_TOTAL, &[]), 1);
    // The period-3 cycle fits the recent-state table (4 slots), which counts
    // the third visit of state 100 exactly, before Brent's saved
    // state has been revisited enough.
    assert_eq!(
        counter(&rows, LOOPS_DETECTED_TOTAL, &[("detector", "recent")]),
        1
    );
    assert_eq!(
        counter(
            &rows,
            TRIPS_TOTAL,
            &[("reason", "loop_detected"), ("outcome", "retry")]
        ),
        1
    );
}

#[test]
fn brent_loop_fires_when_the_recent_table_is_too_small() {
    let rows = capture(|| {
        // One exact slot, so the recent-state table also has one slot and
        // cannot hold a period-3 cycle; Brent finds it.
        let cfg = MinotaurConfig {
            max_distinct_states: 1,
            revisit_allowance: 1,
            ..Default::default()
        };
        let mut t = Thread::new(cfg).unwrap();
        t.record(fp(0)).unwrap();
        let mut i = 0u64;
        while t.record(fp(100 + (i % 3))).is_ok() {
            i += 1;
            assert!(i < 1_000);
        }
    });
    assert_eq!(
        counter(&rows, LOOPS_DETECTED_TOTAL, &[("detector", "brent")]),
        1
    );
    assert_eq!(
        counter(&rows, LOOPS_DETECTED_TOTAL, &[("detector", "recent")]),
        0
    );
}

#[test]
fn stale_guard_refusal_is_counted_but_not_a_rollback() {
    let rows = capture(|| {
        let mut t = Thread::new(MinotaurConfig {
            max_depth: 1,
            ..Default::default()
        })
        .unwrap();
        let mut g = t.descend().unwrap();
        g.descend().unwrap_err(); // DepthExceeded: g is now stale
        g.record(fp(1)).unwrap_err();
        g.descend().unwrap_err();
    });
    assert_eq!(
        counter(
            &rows,
            TRIPS_TOTAL,
            &[("reason", "stale_guard"), ("outcome", "retry")]
        ),
        2
    );
    assert_eq!(counter(&rows, ROLLBACKS_TOTAL, &[]), 1);
}

#[test]
fn lifetime_budget_halts_and_is_labelled() {
    let rows = capture(|| {
        let mut t = Thread::new(MinotaurConfig {
            max_steps: 2,
            max_trips_before_halt: 3,
            ..Default::default()
        })
        .unwrap();
        assert_eq!(t.lifetime_step_limit(), 6);
        for _ in 0..3 {
            t.record(fp(1)).unwrap();
            t.record(fp(2)).unwrap();
            t.rewind();
        }
        assert_eq!(t.lifetime_steps(), 6);
        let e = t.record(fp(1)).unwrap_err();
        assert_eq!(
            e.kind,
            tack_minotaur::TripKind::LifetimeBudgetExhausted { limit: 6 }
        );
        assert_eq!(e.outcome, tack_minotaur::GateOutcome::TerminalBreach);
        assert!(t.is_halted());
        t.operator_reset();
        assert_eq!(t.lifetime_steps(), 0);
        t.record(fp(1)).unwrap();
    });
    assert_eq!(
        counter(
            &rows,
            TRIPS_TOTAL,
            &[
                ("reason", "lifetime_budget_exhausted"),
                ("outcome", "terminal_breach")
            ]
        ),
        1
    );
    assert_eq!(counter(&rows, HALTS_TOTAL, &[]), 1);
}

#[test]
fn every_trip_reason_is_labelled() {
    let rows = capture(|| {
        let mut t = Thread::new(MinotaurConfig {
            max_depth: 1,
            max_steps: 3,
            max_distinct_states: 2,
            max_untracked_transitions: 0,
            ..Default::default()
        })
        .unwrap();
        {
            let mut g = t.descend().unwrap();
            g.descend().unwrap_err();
        }
        t.record(fp(1)).unwrap();
        t.record(fp(2)).unwrap();
        t.record(fp(3)).unwrap_err(); // set full, zero untracked budget

        let mut t2 = Thread::new(MinotaurConfig {
            max_steps: 1,
            ..Default::default()
        })
        .unwrap();
        t2.record(fp(1)).unwrap();
        t2.record(fp(2)).unwrap_err();
    });
    for reason in [
        "depth_exceeded",
        "state_space_exhausted",
        "step_budget_exhausted",
    ] {
        assert_eq!(
            counter(
                &rows,
                TRIPS_TOTAL,
                &[("reason", reason), ("outcome", "retry")]
            ),
            1,
            "{reason}"
        );
    }
    assert_eq!(counter(&rows, ROLLBACKS_TOTAL, &[]), 3);
}

#[test]
fn halt_refusals_and_operator_reset_fire() {
    let rows = capture(|| {
        let mut t = Thread::new(MinotaurConfig {
            max_steps: 1,
            max_trips_before_halt: 2,
            ..Default::default()
        })
        .unwrap();
        for _ in 0..2 {
            t.record(fp(1)).unwrap();
            t.record(fp(2)).unwrap_err();
        }
        assert!(t.is_halted());
        t.record(fp(3)).unwrap_err();
        t.descend().unwrap_err();
        t.operator_reset();
        t.record(fp(4)).unwrap();
        t.rewind();
    });
    assert_eq!(
        counter(
            &rows,
            TRIPS_TOTAL,
            &[("reason", "step_budget_exhausted"), ("outcome", "retry")]
        ),
        1
    );
    assert_eq!(
        counter(
            &rows,
            TRIPS_TOTAL,
            &[
                ("reason", "step_budget_exhausted"),
                ("outcome", "terminal_breach")
            ]
        ),
        1
    );
    assert_eq!(
        counter(
            &rows,
            TRIPS_TOTAL,
            &[("reason", "halted"), ("outcome", "terminal_breach")]
        ),
        2
    );
    assert_eq!(counter(&rows, HALTS_TOTAL, &[]), 1);
    assert_eq!(
        counter(&rows, ROLLBACKS_TOTAL, &[]),
        2,
        "halted refusals are not rollbacks"
    );
    assert_eq!(counter(&rows, OPERATOR_RESETS_TOTAL, &[]), 1);
    assert_eq!(
        histogram(&rows, WALK_STEPS, &[("end", "operator_reset")]),
        vec![0.0]
    );
    assert_eq!(
        histogram(&rows, WALK_STEPS, &[("end", "rewind")]),
        vec![1.0]
    );
}

#[test]
fn passing_steps_emit_nothing() {
    let rows = capture(|| {
        let mut t = Thread::new(MinotaurConfig::default()).unwrap();
        let mut g = t.descend().unwrap();
        for n in 0..100 {
            g.record(fp(n)).unwrap();
        }
    });
    assert!(rows.is_empty(), "no per-step metrics: {rows:?}");
}

#[test]
fn metric_names_follow_the_convention() {
    let counters = [
        TRIPS_TOTAL,
        LOOPS_DETECTED_TOTAL,
        ROLLBACKS_TOTAL,
        HALTS_TOTAL,
        OPERATOR_RESETS_TOTAL,
        DEGRADED_TOTAL,
    ];
    for c in counters {
        assert!(
            c.starts_with("tack_minotaur_") && c.ends_with("_total"),
            "{c}"
        );
    }
    for h in [
        WALK_STEPS,
        WALK_MAX_DEPTH,
        WALK_DISTINCT_STATES,
        WALK_DURATION_SECONDS,
    ] {
        assert!(h.starts_with("tack_minotaur_"), "{h}");
    }
    assert!(WALK_DURATION_SECONDS.ends_with("_seconds"));
}
