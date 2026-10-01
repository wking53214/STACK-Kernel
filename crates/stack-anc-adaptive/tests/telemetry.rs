//! The metrics fire, with closed-set labels only.
#![allow(clippy::unwrap_used, clippy::panic)] // test code: failures should abort the test

mod common;

use common::{counter, find, gauge, ms, us, BackwardsOnce, Snap};
use metrics_util::debugging::{DebugValue, DebuggingRecorder};
use std::sync::Barrier;
use std::time::{Duration, Instant};
use tack_anc_adaptive::telemetry::{names, sha256_hex};
use tack_anc_adaptive::{
    AdaptivePad, EpochConfig, EpochQuantizedTarget, LeakBudgetConfig, NaiveConfig, PadConfig,
    SpinBudgetConfig, Trip, WaitMode, WindowStatistic,
};

const E: (&str, &str) = ("controller", "epoch");
const N: (&str, &str) = ("controller", "naive");
const S: (&str, &str) = ("strategy", "adaptive");

fn record(f: impl FnOnce()) -> Snap {
    let recorder = DebuggingRecorder::new();
    let snapshotter = recorder.snapshotter();
    metrics::with_local_recorder(&recorder, f);
    snapshotter.snapshot().into_vec()
}

#[test]
fn epoch_pad_metrics_fire() {
    let snap = record(|| {
        let pad = AdaptivePad::epoch(
            PadConfig {
                mode: WaitMode::Hybrid,
                spin_tail: us(100),
                spin_budget: SpinBudgetConfig::Limited {
                    cpu_per_second: us(1),
                    burst: us(100),
                },
                max_concurrent: 1,
                max_input_len: 8,
            },
            EpochConfig {
                initial_level: 0,
                ..EpochConfig::new(ms(1), ms(4))
            },
        )
        .unwrap();
        // 1: on time, spin granted (the burst covers one tail).
        pad.pad(|| ()).unwrap();
        // 2: escalated 1 ms -> 2 ms; the budget is empty, so it sleeps.
        pad.pad(|| std::thread::sleep(us(1_300))).unwrap();
        // 3: past the 4 ms cap: RETRY, overrun retry, 1 ms -> ... -> cap.
        assert_eq!(
            pad.pad(|| std::thread::sleep(ms(5))).unwrap_err(),
            Trip::Overrun
        );
        // 4: oversized input, shed.
        assert_eq!(
            pad.pad_input(&[0u8; 9], |_| ()).unwrap_err(),
            Trip::InputTooLarge
        );
        // 5: slots full, shed (another thread holds the only slot; its own
        // metrics go to no recorder).
        let entered = Barrier::new(2);
        let release = Barrier::new(2);
        std::thread::scope(|s| {
            s.spawn(|| {
                pad.pad(|| {
                    entered.wait();
                    release.wait();
                })
                .unwrap();
            });
            entered.wait();
            assert_eq!(pad.pad(|| ()).unwrap_err(), Trip::SlotsFull);
            release.wait();
        });
        pad.reset_controller();
    });

    assert_eq!(
        counter(&snap, names::REQUESTS_TOTAL, &[S, E, ("outcome", "pass")]),
        2
    );
    assert_eq!(
        counter(&snap, names::REQUESTS_TOTAL, &[S, E, ("outcome", "retry")]),
        3
    );
    assert_eq!(
        counter(
            &snap,
            names::SHED_TOTAL,
            &[S, E, ("reason", "input_too_large")]
        ),
        1
    );
    assert_eq!(
        counter(&snap, names::SHED_TOTAL, &[S, E, ("reason", "slots_full")]),
        1
    );
    assert_eq!(
        counter(
            &snap,
            names::OVERRUN_TOTAL,
            &[S, E, ("disposition", "escalated")]
        ),
        1
    );
    assert_eq!(
        counter(
            &snap,
            names::OVERRUN_TOTAL,
            &[S, E, ("disposition", "retry")]
        ),
        1
    );
    // 1 ms -> 2 ms (1 step), then 2 ms -> 4 ms cap (1 step).
    assert_eq!(
        counter(
            &snap,
            names::TARGET_CHANGES_TOTAL,
            &[S, E, ("direction", "increase")]
        ),
        2
    );
    assert_eq!(
        counter(
            &snap,
            names::SPIN_FALLBACK_TOTAL,
            &[S, E, ("mode", "hybrid")]
        ),
        2
    );
    assert_eq!(
        counter(&snap, names::SPIN_RESERVED_NANOSECONDS_TOTAL, &[S, E]),
        100_000
    );
    assert_eq!(
        counter(&snap, names::RESETS_TOTAL, &[S, E, ("scope", "controller")]),
        1
    );
    assert_eq!(gauge(&snap, names::TARGET_SECONDS, &[S, E]), Some(0.004));
    assert_eq!(gauge(&snap, names::CONTROLLER_FROZEN, &[S, E]), Some(0.0));
    assert!(gauge(&snap, names::LEAK_BUDGET_BITS, &[S, E]).is_some());
    assert_eq!(
        gauge(&snap, names::LEAK_BUDGET_LIMIT_BITS, &[S, E]),
        Some(128.0)
    );
    match find(&snap, names::RESPONSE_SECONDS, &[S, E, ("outcome", "pass")]) {
        Some(DebugValue::Histogram(h)) => {
            assert_eq!(h.len(), 2);
            // Post-padding only: every pass response took at least 1 ms.
            assert!(h.iter().all(|v| v.into_inner() >= 0.001), "{h:?}");
        }
        other => panic!("response histogram missing: {other:?}"),
    }
    assert_no_free_form_labels(&snap);
}

#[test]
fn leak_budget_exhaustion_metrics_fire() {
    let snap = record(|| {
        let pad = AdaptivePad::epoch(
            PadConfig::default(),
            EpochConfig {
                initial_level: 0,
                leak_budget: LeakBudgetConfig {
                    bits: 1.0,
                    window: Duration::from_secs(60),
                },
                ..EpochConfig::new(ms(1), ms(8))
            },
        )
        .unwrap();
        // One doubling among 1 request costs log2(4) = 2 bits >= 1: spent.
        let p = pad.pad(|| std::thread::sleep(us(1_300))).unwrap();
        assert_eq!(p.release.target, ms(1));
        let s = pad.status();
        assert!(s.frozen);
        assert_eq!(s.target, ms(8));
        // Requests are still served, at the cap.
        let p = pad.pad(|| ()).unwrap();
        assert_eq!(p.release.target, ms(8));
    });
    assert_eq!(
        counter(&snap, names::LEAK_BUDGET_EXHAUSTED_TOTAL, &[S, E]),
        1
    );
    assert_eq!(
        counter(
            &snap,
            names::TARGET_CHANGES_TOTAL,
            &[S, E, ("direction", "rollback")]
        ),
        1
    );
    assert_eq!(
        counter(
            &snap,
            names::TARGET_CHANGES_TOTAL,
            &[S, E, ("direction", "increase")]
        ),
        1
    );
    assert_eq!(gauge(&snap, names::CONTROLLER_FROZEN, &[S, E]), Some(1.0));
    assert_eq!(
        gauge(&snap, names::LEAK_BUDGET_LIMIT_BITS, &[S, E]),
        Some(1.0)
    );
    let bits = gauge(&snap, names::LEAK_BUDGET_BITS, &[S, E]).unwrap();
    assert!(bits >= 1.0, "{bits}");
    assert_eq!(gauge(&snap, names::TARGET_SECONDS, &[S, E]), Some(0.008));
    assert_eq!(
        counter(&snap, names::REQUESTS_TOTAL, &[S, E, ("outcome", "pass")]),
        2
    );
}

#[test]
fn naive_pad_metrics_fire() {
    let snap = record(|| {
        let pad = AdaptivePad::naive(
            PadConfig::default(),
            NaiveConfig {
                statistic: WindowStatistic::Mean,
                window: 4,
                margin: Duration::ZERO,
                initial_target: ms(1),
                ..NaiveConfig::new(ms(20))
            },
        )
        .unwrap();
        // Late: 2 ms of work against a 1 ms target.
        let p = pad.pad(|| std::thread::sleep(ms(2))).unwrap();
        assert_eq!(p.release.disposition, tack_anc_adaptive::Disposition::Late);
        pad.pad(|| ()).unwrap();
    });
    assert_eq!(
        counter(&snap, names::REQUESTS_TOTAL, &[S, N, ("outcome", "pass")]),
        2
    );
    assert_eq!(
        counter(
            &snap,
            names::OVERRUN_TOTAL,
            &[S, N, ("disposition", "late")]
        ),
        1
    );
    let ups = counter(
        &snap,
        names::TARGET_CHANGES_TOTAL,
        &[S, N, ("direction", "increase")],
    );
    let downs = counter(
        &snap,
        names::TARGET_CHANGES_TOTAL,
        &[S, N, ("direction", "decrease")],
    );
    assert_eq!((ups, downs), (1, 1));
    assert!(gauge(&snap, names::LEAK_BUDGET_BITS, &[S, N]).unwrap() > 0.0);
    // The naive target is a statistic of pre-padding work times: never
    // exported, and it has no budget.
    assert!(find(&snap, names::TARGET_SECONDS, &[S, N]).is_none());
    assert!(find(&snap, names::LEAK_BUDGET_LIMIT_BITS, &[S, N]).is_none());
    assert_no_free_form_labels(&snap);
}

#[test]
fn clock_failure_and_reset_metrics_fire() {
    let snap = record(|| {
        let ctl =
            EpochQuantizedTarget::new(EpochConfig::new(us(100), ms(1)), Instant::now()).unwrap();
        let pad =
            AdaptivePad::with_parts(PadConfig::default(), ctl, BackwardsOnce::new(2)).unwrap();
        assert_eq!(pad.pad(|| ()).unwrap_err(), Trip::ClockFailure);
        assert_eq!(pad.pad(|| ()).unwrap_err(), Trip::Halted);
        pad.reset();
    });
    assert_eq!(counter(&snap, names::CLOCK_FAILURES_TOTAL, &[S, E]), 1);
    assert_eq!(
        counter(&snap, names::SHED_TOTAL, &[S, E, ("reason", "halted")]),
        1
    );
    assert_eq!(
        counter(
            &snap,
            names::REQUESTS_TOTAL,
            &[S, E, ("outcome", "terminal_breach")]
        ),
        2
    );
    assert_eq!(
        counter(&snap, names::RESETS_TOTAL, &[S, E, ("scope", "pad")]),
        1
    );
    assert_eq!(gauge(&snap, names::HALTED, &[S, E]), Some(0.0));
}

#[test]
fn sha256_hex_is_full_length() {
    let h = sha256_hex(b"abc");
    assert_eq!(h.len(), 64);
    assert_eq!(
        h,
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    );
}

/// Every label value on every metric comes from a closed set.
fn assert_no_free_form_labels(snap: &Snap) {
    let allowed = [
        ("strategy", &["adaptive"][..]),
        ("controller", &["naive", "epoch"][..]),
        ("outcome", &["pass", "retry", "terminal_breach"][..]),
        ("reason", &["slots_full", "input_too_large", "halted"][..]),
        ("disposition", &["late", "escalated", "retry"][..]),
        ("direction", &["increase", "decrease", "rollback"][..]),
        ("mode", &["hybrid"][..]),
        ("scope", &["pad", "controller"][..]),
    ];
    for (k, _, _, _) in snap {
        let key = k.key();
        assert!(key.name().starts_with("tack_anc_"), "{}", key.name());
        for l in key.labels() {
            let ok = allowed
                .iter()
                .any(|(name, vals)| *name == l.key() && vals.contains(&l.value()));
            assert!(ok, "label {}={} on {}", l.key(), l.value(), key.name());
        }
    }
}
