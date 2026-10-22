//! Every metric the pad emits fires, with closed-set labels only.
#![allow(clippy::unwrap_used, clippy::panic)]

mod common;

use common::{wait_for, BackwardsOnce};
use metrics_util::debugging::{DebugValue, DebuggingRecorder};
use stack_anc_ceiling::telemetry::{names, sha256_hex, STRATEGY, STRATEGY_FAST};
use stack_anc_ceiling::{
    CeilingConfig, CeilingPad, LanedPad, SlotScaling, SpinBudgetConfig, Trip, WaitMode,
};
use std::sync::mpsc;
use std::time::Duration;

type Snap = Vec<(
    metrics_util::CompositeKey,
    Option<metrics::Unit>,
    Option<metrics::SharedString>,
    DebugValue,
)>;

fn find<'s>(snap: &'s Snap, name: &str, labels: &[(&str, &str)]) -> Option<&'s DebugValue> {
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

fn counter(snap: &Snap, name: &str, labels: &[(&str, &str)]) -> u64 {
    match find(snap, name, labels) {
        Some(DebugValue::Counter(c)) => *c,
        other => panic!("{name} {labels:?} missing or wrong type: {other:?}"),
    }
}

#[test]
fn metrics_fire_with_closed_labels() {
    let recorder = DebuggingRecorder::new();
    let snapshotter = recorder.snapshotter();
    metrics::with_local_recorder(&recorder, || {
        // pass, spin reservation, budget fallback
        let pad = CeilingPad::new(CeilingConfig {
            mode: WaitMode::Spin,
            spin_budget: SpinBudgetConfig::Limited {
                cpu_per_second: Duration::from_micros(1),
                burst: Duration::from_millis(2),
            },
            hard_ceiling_buckets: 2,
            max_input_len: 4,
            ..CeilingConfig::new(Duration::from_millis(2))
        })
        .unwrap();
        assert_eq!(pad.pad(|| ()).unwrap().release.mode, WaitMode::Spin);
        assert_eq!(pad.pad(|| ()).unwrap().release.mode, WaitMode::Sleep);
        // overrun released (bucket 2) and overrun retry (past bucket 2)
        let p = pad
            .pad(|| std::thread::sleep(Duration::from_micros(2_600)))
            .unwrap();
        assert!(p.release.buckets >= 2);
        assert_eq!(
            pad.pad(|| std::thread::sleep(Duration::from_millis(5))),
            Err(Trip::Overrun)
        );
        // input too large
        assert_eq!(pad.pad_input(b"12345", |_| ()), Err(Trip::InputTooLarge));

        // slots full: the holder runs on another thread; the shed happens
        // on this one, so it is recorded by the local recorder.
        let one = CeilingPad::new(CeilingConfig {
            max_concurrent: 1,
            mode: WaitMode::Sleep,
            ..CeilingConfig::new(Duration::from_millis(5))
        })
        .unwrap();
        let (tx, rx) = mpsc::channel::<()>();
        std::thread::scope(|s| {
            let one_ref = &one;
            let h = s.spawn(move || one_ref.pad(move || rx.recv().is_ok()));
            assert!(wait_for(|| one.in_flight() == 1, 20_000));
            assert_eq!(one.pad(|| ()), Err(Trip::SlotsFull));
            tx.send(()).unwrap();
            assert!(h.join().unwrap().is_ok());
        });

        // clock failure, halted, reset
        let broken = CeilingPad::with_clock(
            CeilingConfig {
                spin_budget: SpinBudgetConfig::Unlimited,
                ..CeilingConfig::new(Duration::from_micros(100))
            },
            BackwardsOnce::new(2),
        )
        .unwrap();
        assert_eq!(broken.pad(|| ()), Err(Trip::ClockFailure));
        assert_eq!(broken.pad(|| ()), Err(Trip::Halted));
        broken.reset();

        // async path records through the same functions
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let apad = CeilingPad::new(CeilingConfig {
            mode: WaitMode::Sleep,
            ..CeilingConfig::new(Duration::from_millis(2))
        })
        .unwrap();
        rt.block_on(async {
            assert!(apad.pad_async(|| async { 1u8 }).await.is_ok());
        });
    });
    let snap: Snap = snapshotter.snapshot().into_vec();
    let s = ("strategy", STRATEGY);

    // Passes: 2 spin/sleep, 1 overrun released, 1 async, 1 holder is on
    // another thread (not recorded here).
    assert_eq!(
        counter(&snap, names::REQUESTS_TOTAL, &[s, ("outcome", "pass")]),
        4
    );
    // Retries: overrun, input too large, slots full.
    assert_eq!(
        counter(&snap, names::REQUESTS_TOTAL, &[s, ("outcome", "retry")]),
        3
    );
    // Terminal: clock failure, halted.
    assert_eq!(
        counter(
            &snap,
            names::REQUESTS_TOTAL,
            &[s, ("outcome", "terminal_breach")]
        ),
        2
    );
    assert_eq!(
        counter(&snap, names::SHED_TOTAL, &[s, ("reason", "slots_full")]),
        1
    );
    assert_eq!(
        counter(
            &snap,
            names::SHED_TOTAL,
            &[s, ("reason", "input_too_large")]
        ),
        1
    );
    assert_eq!(
        counter(&snap, names::SHED_TOTAL, &[s, ("reason", "halted")]),
        1
    );
    assert_eq!(
        counter(
            &snap,
            names::OVERRUN_TOTAL,
            &[s, ("disposition", "released")]
        ),
        1
    );
    assert_eq!(
        counter(&snap, names::OVERRUN_TOTAL, &[s, ("disposition", "retry")]),
        1
    );
    assert!(counter(&snap, names::SPIN_FALLBACK_TOTAL, &[s, ("mode", "spin")]) >= 1);
    // The first request reserved exactly one ceiling of spin.
    assert!(counter(&snap, names::SPIN_RESERVED_NANOSECONDS_TOTAL, &[s]) >= 2_000_000);
    assert_eq!(counter(&snap, names::CLOCK_FAILURES_TOTAL, &[s]), 1);
    assert_eq!(counter(&snap, names::RESETS_TOTAL, &[s]), 1);
    assert!(matches!(
        find(&snap, names::HALTED, &[s]),
        Some(DebugValue::Gauge(g)) if g.into_inner() == 0.0
    ));
    match find(&snap, names::RESPONSE_SECONDS, &[s, ("outcome", "pass")]) {
        Some(DebugValue::Histogram(h)) => {
            assert_eq!(h.len(), 4);
            assert!(h.iter().all(|v| v.into_inner() >= 0.002));
        }
        other => panic!("response histogram missing: {other:?}"),
    }

    // Names follow the convention and labels come from closed sets.
    let allowed = [
        STRATEGY,
        "pass",
        "retry",
        "terminal_breach",
        "slots_full",
        "input_too_large",
        "halted",
        "released",
        "spin",
        "hybrid",
    ];
    for (k, _, _, v) in &snap {
        let name = k.key().name();
        assert!(name.starts_with("stack_anc_"), "{name}");
        if matches!(v, DebugValue::Counter(_)) {
            assert!(name.ends_with("_total"), "counter {name}");
        }
        if matches!(v, DebugValue::Histogram(_)) {
            assert!(name.ends_with("_seconds"), "histogram {name}");
        }
        for l in k.key().labels() {
            assert!(
                allowed.contains(&l.value()),
                "unexpected label value {}",
                l.value()
            );
        }
    }
}

#[test]
fn digest_is_full_length_hex() {
    let d = sha256_hex(b"abc");
    assert_eq!(d.len(), 64);
    assert_eq!(
        d,
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    );
}

fn record(f: impl FnOnce()) -> Snap {
    let recorder = DebuggingRecorder::new();
    let snapshotter = recorder.snapshotter();
    metrics::with_local_recorder(&recorder, f);
    snapshotter.snapshot().into_vec()
}

fn gauge(snap: &Snap, name: &str, labels: &[(&str, &str)]) -> Option<f64> {
    match find(snap, name, labels) {
        Some(DebugValue::Gauge(g)) => Some(g.into_inner()),
        _ => None,
    }
}

fn ms(n: u64) -> Duration {
    Duration::from_millis(n)
}

#[test]
fn slots_open_gauge_follows_scaling() {
    let snap = record(|| {
        // Ceiling 2 ms, so a slot is held 8 ms (4 x ceiling hard ceiling).
        let pad = CeilingPad::new(CeilingConfig {
            mode: WaitMode::Sleep,
            max_concurrent: 1,
            scaling: SlotScaling {
                max_slots: 3,
                reaction_delay: ms(5),
                ..SlotScaling::default()
            },
            ..CeilingConfig::new(ms(2))
        })
        .unwrap();
        pad.pad(|| ()).unwrap();
        // The only slot is held: shed, and that counts as pressure.
        assert_eq!(pad.pad(|| ()), Err(Trip::SlotsFull));
        std::thread::sleep(ms(12));
        // The window rolled with pressure, so a second slot opened.
        pad.pad(|| ()).unwrap();
        assert_eq!(pad.slots_open(), 2);
    });
    let s = ("strategy", STRATEGY);
    assert_eq!(gauge(&snap, names::SLOTS_OPEN, &[s]), Some(2.0));
}

#[test]
fn spilled_arrivals_are_counted_and_their_wait_is_in_the_histogram() {
    let snap = record(|| {
        let pad = CeilingPad::new(CeilingConfig {
            mode: WaitMode::Sleep,
            max_concurrent: 1,
            scaling: SlotScaling {
                spillway_size: 1,
                spillway_wait: ms(3),
                ..SlotScaling::default()
            },
            ..CeilingConfig::new(ms(5))
        })
        .unwrap();
        pad.pad(|| ()).unwrap();
        // Finds the slot held, waits 3 ms, retries once, is shed.
        assert_eq!(pad.pad(|| ()), Err(Trip::SlotsFull));
    });
    let s = ("strategy", STRATEGY);
    assert_eq!(counter(&snap, names::SPILLED_TOTAL, &[s]), 1);
    assert_eq!(
        counter(&snap, names::SHED_TOTAL, &[s, ("reason", "slots_full")]),
        1
    );
    match find(&snap, names::RESPONSE_SECONDS, &[s, ("outcome", "retry")]) {
        Some(DebugValue::Histogram(h)) => {
            assert!(h.iter().any(|v| v.into_inner() >= 0.003), "{h:?}");
        }
        other => panic!("retry histogram missing: {other:?}"),
    }
}

#[test]
fn the_fast_lane_has_its_own_series() {
    let snap = record(|| {
        let lanes = LanedPad::new(
            CeilingConfig {
                mode: WaitMode::Sleep,
                ..CeilingConfig::new(ms(20))
            },
            CeilingConfig {
                mode: WaitMode::Sleep,
                hard_ceiling_buckets: 1,
                retry_release_factor: 1,
                ..CeilingConfig::new(ms(2))
            },
        )
        .unwrap();
        lanes.standard().pad(|| ()).unwrap();
        lanes.fast().pad(|| ()).unwrap();
        lanes.fast().pad(|| ()).unwrap();
        std::thread::sleep(ms(10));
        // A mislabeled operation: far past the fast ceiling.
        assert_eq!(
            lanes.fast().pad(|| std::thread::sleep(ms(8))),
            Err(Trip::Overrun)
        );
        assert_eq!(lanes.fast_overruns(), 1);
    });
    let std_s = ("strategy", STRATEGY);
    let fast_s = ("strategy", STRATEGY_FAST);
    assert_eq!(
        counter(&snap, names::REQUESTS_TOTAL, &[std_s, ("outcome", "pass")]),
        1
    );
    assert_eq!(
        counter(&snap, names::REQUESTS_TOTAL, &[fast_s, ("outcome", "pass")]),
        2
    );
    assert_eq!(
        counter(
            &snap,
            names::OVERRUN_TOTAL,
            &[fast_s, ("disposition", "retry")]
        ),
        1
    );
    // The standard lane saw no overrun.
    assert!(find(&snap, names::OVERRUN_TOTAL, &[std_s]).is_none());
    assert!(gauge(&snap, names::SLOTS_OPEN, &[fast_s]).is_some());
}

#[test]
fn a_panicking_operation_is_counted_once_as_a_terminal_breach() {
    let snap = record(|| {
        let pad = CeilingPad::new(CeilingConfig::new(ms(2))).unwrap();
        let r = pad.pad(|| -> u8 { panic!("operation failed") });
        assert_eq!(r, Err(Trip::OperationPanicked));
    });
    let s = ("strategy", STRATEGY);
    assert_eq!(
        counter(&snap, names::REQUESTS_TOTAL, &[s, ("outcome", "terminal_breach")]),
        1
    );
    assert!(
        find(&snap, names::REQUESTS_TOTAL, &[s, ("outcome", "pass")]).is_none(),
        "a panic must not also count as a pass"
    );
}
