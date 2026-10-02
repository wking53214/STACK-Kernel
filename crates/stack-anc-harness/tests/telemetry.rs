//! The harness's metrics fire, with closed-set labels only.
#![allow(clippy::unwrap_used, clippy::panic)] // test code: failures should abort the test

use metrics_util::debugging::{DebugValue, DebuggingRecorder};
use sstack_anc_harness::{measure_pair, Class, HarnessError, MeasureConfig, T_THRESHOLD};

fn find<'s>(
    snap: &'s [(
        metrics_util::CompositeKey,
        Option<metrics::Unit>,
        Option<metrics::SharedString>,
        DebugValue,
    )],
    name: &str,
    labels: &[(&str, &str)],
) -> Option<&'s DebugValue> {
    snap.iter()
        .find(|(k, _, _, _)| {
            let key = k.key();
            key.name() == name
                && labels
                    .iter()
                    .all(|(lk, lv)| key.labels().any(|l| l.key() == *lk && l.value() == *lv))
        })
        .map(|(_, _, _, v)| v)
}

#[test]
fn metrics_fire_for_run_and_verdict() {
    let recorder = DebuggingRecorder::new();
    let snapshotter = recorder.snapshotter();
    metrics::with_local_recorder(&recorder, || {
        let cfg = MeasureConfig {
            warmup: 10,
            ..MeasureConfig::with_samples(400)
        };
        let report = measure_pair(&cfg, |c, _| c, |c: &Class| *c == Class::A).unwrap();
        let _ = report.verdict(T_THRESHOLD);
        let bad = MeasureConfig {
            samples: 1,
            ..Default::default()
        };
        assert!(matches!(
            measure_pair(&bad, |c, _| c, |_: &Class| ()),
            Err(HarnessError::InvalidConfig { .. })
        ));
    });
    let snap = snapshotter.snapshot().into_vec();

    assert_eq!(
        find(
            &snap,
            "stack_anc_harness_runs_total",
            &[("outcome", "completed")]
        ),
        Some(&DebugValue::Counter(1))
    );
    assert_eq!(
        find(
            &snap,
            "stack_anc_harness_runs_total",
            &[("outcome", "invalid_config")]
        ),
        Some(&DebugValue::Counter(1))
    );
    let a = find(&snap, "stack_anc_harness_samples_total", &[("class", "a")]);
    let b = find(&snap, "stack_anc_harness_samples_total", &[("class", "b")]);
    match (a, b) {
        (Some(DebugValue::Counter(a)), Some(DebugValue::Counter(b))) => assert_eq!(a + b, 400),
        other => panic!("samples counters missing: {other:?}"),
    }
    assert!(matches!(
        find(&snap, "stack_anc_harness_run_seconds", &[]),
        Some(DebugValue::Histogram(h)) if h.len() == 1
    ));
    assert!(matches!(
        find(&snap, "stack_anc_harness_max_abs_t", &[]),
        Some(DebugValue::Gauge(_))
    ));
    let verdicts: u64 = snap
        .iter()
        .filter(|(k, _, _, _)| k.key().name() == "stack_anc_harness_verdicts_total")
        .map(|(_, _, _, v)| match v {
            DebugValue::Counter(c) => *c,
            _ => 0,
        })
        .sum();
    assert_eq!(verdicts, 1);

    // Every label value is from a closed set.
    let allowed = [
        "completed",
        "invalid_config",
        "unsupported",
        "a",
        "b",
        "no_leak",
        "leak",
        "inconclusive",
        "none",
        "too_few_samples",
        "no_statistic",
        "invalid_threshold",
    ];
    for (k, _, _, _) in &snap {
        for l in k.key().labels() {
            assert!(
                allowed.contains(&l.value()),
                "unexpected label {}",
                l.value()
            );
        }
    }
}
