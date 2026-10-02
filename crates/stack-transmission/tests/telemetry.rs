//! The metrics fire, with closed-enum labels only.
//!
//! `metrics::with_local_recorder` installs the recorder for the current
//! thread only, so every call whose metrics are asserted runs on the test
//! thread. Helper threads only hold guards or the clutch.

// Test crate: helpers outside #[test] functions may unwrap and panic.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use std::collections::HashMap;
use std::thread;
use std::time::Duration;

use common::{tx, wait_until, Mode};
use metrics_util::debugging::{DebugValue, DebuggingRecorder, Snapshotter};
use stack_transmission::telemetry as tm;
use stack_transmission::{Reason, TransmissionConfig};

const LONG: Duration = Duration::from_secs(5);

type Labels = Vec<(String, String)>;

struct Snap(Vec<(String, Labels, DebugValue)>);

impl Snap {
    fn take(s: &Snapshotter) -> Self {
        Self(
            s.snapshot()
                .into_vec()
                .into_iter()
                .map(|(k, _, _, v)| {
                    let key = k.key();
                    let mut labels: Labels = key
                        .labels()
                        .map(|l| (l.key().to_string(), l.value().to_string()))
                        .collect();
                    labels.sort();
                    (key.name().to_string(), labels, v)
                })
                .collect(),
        )
    }

    fn matches(labels: &Labels, want: &[(&str, &str)]) -> bool {
        want.iter()
            .all(|(k, v)| labels.iter().any(|(lk, lv)| lk == k && lv == v))
    }

    fn counter(&self, name: &str, want: &[(&str, &str)]) -> u64 {
        self.0
            .iter()
            .filter(|(n, l, _)| n == name && Self::matches(l, want))
            .map(|(_, _, v)| match v {
                DebugValue::Counter(c) => *c,
                other => panic!("{name} is not a counter: {other:?}"),
            })
            .sum()
    }

    fn gauge(&self, name: &str) -> f64 {
        let found: Vec<f64> = self
            .0
            .iter()
            .filter(|(n, _, _)| n == name)
            .map(|(_, _, v)| match v {
                DebugValue::Gauge(g) => g.0,
                other => panic!("{name} is not a gauge: {other:?}"),
            })
            .collect();
        // Later snapshots are appended after earlier ones, so the last
        // entry is the latest value.
        *found.last().unwrap_or_else(|| panic!("gauge {name} missing"))
    }

    /// Snapshots drain the recorder (counters and gauges are swapped to
    /// zero), so a test that looks twice appends the second look.
    fn then(mut self, later: Snap) -> Snap {
        self.0.extend(later.0);
        self
    }

    fn histogram_len(&self, name: &str, want: &[(&str, &str)]) -> usize {
        self.0
            .iter()
            .filter(|(n, l, _)| n == name && Self::matches(l, want))
            .map(|(_, _, v)| match v {
                DebugValue::Histogram(h) => h.len(),
                other => panic!("{name} is not a histogram: {other:?}"),
            })
            .sum()
    }

    fn names(&self) -> Vec<&str> {
        self.0.iter().map(|(n, _, _)| n.as_str()).collect()
    }
}

#[test]
fn engage_and_shift_emit_counters_histograms_and_gauges() {
    let recorder = DebuggingRecorder::new();
    let snapshotter = recorder.snapshotter();
    metrics::with_local_recorder(&recorder, || {
        let t = tx(TransmissionConfig::default());
        let g = t.engage(LONG).unwrap();
        drop(g);
        t.shift(Mode::for_epoch(1), LONG).unwrap();
        let _g = t.engage(LONG).unwrap();
    });
    let s = Snap::take(&snapshotter);
    assert_eq!(s.counter(tm::ENGAGE_TOTAL, &[("outcome", "pass")]), 2);
    assert_eq!(s.counter(tm::SHIFT_TOTAL, &[("outcome", "pass")]), 1);
    assert_eq!(s.histogram_len(tm::ENGAGE_WAIT_SECONDS, &[("outcome", "pass")]), 2);
    assert_eq!(s.histogram_len(tm::SHIFT_DRAIN_SECONDS, &[("outcome", "pass")]), 1);
    assert_eq!(s.gauge(tm::GEAR_EPOCH), 1.0);
    // The second guard was dropped at the end of the closure, after which
    // the gauge went back to zero.
    assert_eq!(s.gauge(tm::IN_FLIGHT), 0.0);
    assert_eq!(s.gauge(tm::CLUTCH_PRESSED), 0.0);
    assert_eq!(s.gauge(tm::HALTED), 0.0);
    assert_eq!(s.gauge(tm::WAITING_ENGAGERS), 0.0);
    assert_eq!(s.counter(tm::TRIPS_TOTAL, &[]), 0);
}

#[test]
fn every_trip_is_counted_with_its_closed_labels() {
    let recorder = DebuggingRecorder::new();
    let snapshotter = recorder.snapshotter();
    let t = tx(TransmissionConfig {
        max_in_flight: 1,
        ..TransmissionConfig::default()
    });
    metrics::with_local_recorder(&recorder, || {
        // Over budget, both kinds.
        let e = t.engage(Duration::from_secs(3600)).unwrap_err();
        assert_eq!(e.reason, Reason::EngageTimeoutOverBudget);
        let e = t.shift(Mode::for_epoch(1), Duration::from_secs(3600)).unwrap_err();
        assert_eq!(e.trip().reason, Reason::ShiftTimeoutOverBudget);

        // Capacity, then a drain timeout (rollback) while that guard is held.
        let held = t.engage(LONG).unwrap();
        assert_eq!(t.engage(LONG).unwrap_err().reason, Reason::InFlightCapacity);
        let e = t.shift(Mode::for_epoch(1), Duration::from_millis(20)).unwrap_err();
        assert_eq!(e.trip().reason, Reason::DrainTimeout);
        drop(held);
    });

    // Clutch-wait timeout and shift-in-progress need a clutch held by
    // another thread.
    let held = t.engage(LONG).unwrap();
    let t2 = t.clone();
    let shifter = thread::spawn(move || t2.shift(Mode::for_epoch(1), LONG));
    wait_until("clutch pressed", || t.status().clutch_pressed);
    metrics::with_local_recorder(&recorder, || {
        let e = t.engage(Duration::from_millis(10)).unwrap_err();
        assert_eq!(e.reason, Reason::ClutchWaitTimeout);
        let e = t.shift(Mode::for_epoch(2), LONG).unwrap_err();
        assert_eq!(e.trip().reason, Reason::ShiftInProgress);
    });
    drop(held);
    shifter.join().unwrap().unwrap();

    // Halt and reset.
    metrics::with_local_recorder(&recorder, || {
        assert!(t.operator_halt());
        assert!(!t.operator_halt());
        assert_eq!(t.engage(LONG).unwrap_err().reason, Reason::Halted);
        assert_eq!(t.shift(Mode::for_epoch(3), LONG).unwrap_err().trip().reason, Reason::Halted);
    });
    let halted = Snap::take(&snapshotter);
    assert_eq!(halted.gauge(tm::HALTED), 1.0);
    metrics::with_local_recorder(&recorder, || {
        assert!(t.operator_reset());
        assert!(!t.operator_reset());
    });

    let s = halted.then(Snap::take(&snapshotter));
    let trip = |op: &str, reason: &str, outcome: &str, resolution: &str| {
        s.counter(
            tm::TRIPS_TOTAL,
            &[
                ("operation", op),
                ("reason", reason),
                ("outcome", outcome),
                ("resolution", resolution),
            ],
        )
    };
    assert_eq!(trip("engage", "engage_timeout_over_budget", "retry", "reject"), 1);
    assert_eq!(trip("shift", "shift_timeout_over_budget", "retry", "reject"), 1);
    assert_eq!(trip("engage", "in_flight_capacity", "retry", "reject"), 1);
    assert_eq!(trip("shift", "drain_timeout", "retry", "rollback"), 1);
    assert_eq!(trip("engage", "clutch_wait_timeout", "retry", "reject"), 1);
    assert_eq!(trip("shift", "shift_in_progress", "retry", "reject"), 1);
    assert_eq!(trip("engage", "halted", "terminal_breach", "halt"), 1);
    assert_eq!(trip("shift", "halted", "terminal_breach", "halt"), 1);
    assert_eq!(s.counter(tm::TRIPS_TOTAL, &[]), 8);
    assert_eq!(s.counter(tm::ENGAGE_TOTAL, &[("outcome", "retry")]), 3);
    assert_eq!(s.counter(tm::ENGAGE_TOTAL, &[("outcome", "terminal_breach")]), 1);
    assert_eq!(s.counter(tm::SHIFT_TOTAL, &[("outcome", "retry")]), 3);
    assert_eq!(s.histogram_len(tm::SHIFT_DRAIN_SECONDS, &[("outcome", "retry")]), 1);
    assert_eq!(s.counter(tm::HALTS_TOTAL, &[("cause", "operator")]), 1);
    assert_eq!(s.counter(tm::OPERATOR_RESETS_TOTAL, &[]), 1);
    assert_eq!(s.gauge(tm::HALTED), 0.0);

    // Every label value is from a closed set; nothing else leaks in.
    let allowed: HashMap<&str, Vec<&str>> = HashMap::from([
        ("outcome", vec!["pass", "retry", "terminal_breach"]),
        ("operation", vec!["engage", "shift"]),
        ("resolution", vec!["reject", "rollback", "halt"]),
        ("reason", Reason::ALL.iter().map(|r| r.as_str()).collect()),
        ("cause", vec!["operator", "poisoned", "invariant"]),
    ]);
    for (name, labels, _) in &s.0 {
        assert!(tm::ALL_METRICS.contains(&name.as_str()), "undeclared metric {name}");
        for (k, v) in labels {
            let ok = allowed.get(k.as_str()).is_some_and(|vs| vs.contains(&v.as_str()));
            assert!(ok, "{name} has open label {k}={v}");
        }
    }
}

#[test]
fn panicking_guard_holder_is_counted_and_released() {
    let recorder = DebuggingRecorder::new();
    let snapshotter = recorder.snapshotter();
    let t = tx(TransmissionConfig::default());
    metrics::with_local_recorder(&recorder, || {
        let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _g = t.engage(LONG).unwrap();
            panic!("test fixture: fail while holding a guard");
        }));
        assert!(r.is_err());
    });
    assert_eq!(t.status().in_flight, 0);
    let s = Snap::take(&snapshotter);
    assert_eq!(s.counter(tm::GUARD_PANICS_TOTAL, &[]), 1);
    assert_eq!(s.gauge(tm::IN_FLIGHT), 0.0);
}

#[test]
fn parked_engager_moves_the_waiting_gauge() {
    let recorder = DebuggingRecorder::new();
    let snapshotter = recorder.snapshotter();
    let t = tx(TransmissionConfig::default());
    let held = t.engage(LONG).unwrap();
    let t2 = t.clone();
    let shifter = thread::spawn(move || t2.shift(Mode::for_epoch(1), LONG));
    wait_until("clutch pressed", || t.status().clutch_pressed);
    let t3 = t.clone();
    let releaser = thread::spawn(move || {
        wait_until("engager parked", || t3.status().waiting_engagers == 1);
        drop(held);
    });
    metrics::with_local_recorder(&recorder, || {
        let g = t.engage(LONG).unwrap();
        assert_eq!(g.epoch(), 1);
    });
    releaser.join().unwrap();
    shifter.join().unwrap().unwrap();
    let s = Snap::take(&snapshotter);
    assert!(s.names().contains(&tm::WAITING_ENGAGERS));
    assert_eq!(s.gauge(tm::WAITING_ENGAGERS), 0.0);
    assert_eq!(s.counter(tm::ENGAGE_TOTAL, &[("outcome", "pass")]), 1);
    assert_eq!(s.histogram_len(tm::ENGAGE_WAIT_SECONDS, &[("outcome", "pass")]), 1);
}
