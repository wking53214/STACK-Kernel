//! Every metric the pad emits fires, with closed-set labels only.
#![allow(clippy::unwrap_used, clippy::panic)]

mod common;

use common::{wait_for, BackwardsOnce};
use metrics_util::debugging::{DebugValue, DebuggingRecorder};
use std::sync::mpsc;
use std::time::Duration;
use tack_anc_ceiling::telemetry::{names, sha256_hex, STRATEGY};
use tack_anc_ceiling::{CeilingConfig, CeilingPad, SpinBudgetConfig, Trip, WaitMode};

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
        assert!(name.starts_with("tack_anc_"), "{name}");
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
