//! Behaviour of the pad: release offsets, overruns, budget, shedding,
//! async, halting. Tolerances are loose on the late side because other
//! builds share this machine; the never-early bound is strict.
#![allow(clippy::unwrap_used, clippy::panic)]

mod common;

use common::{median, wait_for, BackwardsOnce};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;
use std::sync::Arc;
use std::time::{Duration, Instant};
use sstack_anc_ceiling::{
    CeilingConfig, CeilingPad, GateOutcome, Resolution, SpinBudgetConfig, Trip, WaitMode,
};

fn cfg(ceiling: Duration, mode: WaitMode) -> CeilingConfig {
    CeilingConfig {
        mode,
        spin_budget: SpinBudgetConfig::Unlimited,
        ..CeilingConfig::new(ceiling)
    }
}

#[test]
fn spin_release_offset_equals_ceiling_within_tolerance() {
    let ceiling = Duration::from_millis(1);
    let pad = CeilingPad::new(cfg(ceiling, WaitMode::Spin)).unwrap();
    let mut internal = Vec::new();
    let mut external = Vec::new();
    for i in 0..200u32 {
        let t0 = Instant::now();
        let p = pad.pad(|| std::hint::black_box(i).wrapping_mul(3)).unwrap();
        let ext = t0.elapsed();
        assert_eq!(p.value, i * 3);
        assert_eq!(p.release.buckets, 1);
        assert_eq!(p.release.mode, WaitMode::Spin);
        assert!(
            p.release.observed >= ceiling,
            "released early: {:?}",
            p.release.observed
        );
        assert!(ext >= ceiling, "released early (external): {ext:?}");
        internal.push(p.release.observed - ceiling);
        external.push(ext - ceiling);
    }
    let mi = median(&internal);
    let me = median(&external);
    assert!(
        mi < Duration::from_micros(20),
        "median internal late {mi:?}"
    );
    assert!(
        me < Duration::from_micros(100),
        "median external late {me:?}"
    );
}

#[test]
fn every_mode_never_releases_early() {
    for mode in [WaitMode::Sleep, WaitMode::Spin, WaitMode::Hybrid] {
        let ceiling = Duration::from_micros(700);
        let pad = CeilingPad::new(cfg(ceiling, mode)).unwrap();
        for _ in 0..50 {
            let t0 = Instant::now();
            let p = pad.pad(|| ()).unwrap();
            assert!(t0.elapsed() >= ceiling, "{mode:?} early");
            assert!(p.release.observed >= ceiling);
        }
    }
}

#[test]
fn overrun_is_quantized_to_the_next_ceiling_multiple() {
    let ceiling = Duration::from_millis(2);
    let pad = CeilingPad::new(cfg(ceiling, WaitMode::Spin)).unwrap();
    let p = pad
        .pad(|| std::thread::sleep(Duration::from_micros(4_500)))
        .unwrap();
    let k = p.release.buckets;
    assert!(
        k >= 3,
        "4.5 ms of work at a 2 ms ceiling needs bucket 3, got {k}"
    );
    let boundary = ceiling * u32::try_from(k).unwrap();
    assert!(
        p.release.observed >= boundary,
        "released before bucket boundary"
    );
    assert!(
        p.release.observed - boundary < Duration::from_micros(300),
        "released {:?} after boundary {boundary:?}",
        p.release.observed - boundary
    );
    assert_eq!(p.gate_outcome(), GateOutcome::Pass);
}

#[test]
fn hard_overrun_is_retry_released_on_a_boundary_not_at_completion() {
    let ceiling = Duration::from_millis(2);
    let pad = CeilingPad::new(CeilingConfig {
        hard_ceiling_buckets: 2,
        ..cfg(ceiling, WaitMode::Spin)
    })
    .unwrap();
    let t0 = Instant::now();
    let r = pad.pad(|| std::thread::sleep(Duration::from_millis(5)));
    let ext = t0.elapsed();
    assert_eq!(r, Err(Trip::Overrun));
    assert_eq!(Trip::Overrun.gate_outcome(), GateOutcome::Retry);
    assert_eq!(Trip::Overrun.resolution(), Resolution::Reject);
    // Completion was at about 5 ms; the release is at a multiple of 2 ms.
    assert!(ext >= Duration::from_millis(6), "released at {ext:?}");
    let c = ceiling.as_nanos();
    let rem = ext.as_nanos() % c;
    assert!(rem < 400_000, "release {ext:?} is {rem} ns past a boundary");
    assert!(!pad.is_halted());
}

#[test]
fn budget_exhaustion_switches_to_sleep() {
    let ceiling = Duration::from_millis(2);
    let pad = CeilingPad::new(CeilingConfig {
        mode: WaitMode::Spin,
        spin_budget: SpinBudgetConfig::Limited {
            cpu_per_second: Duration::from_millis(1),
            burst: Duration::from_millis(5),
        },
        ..CeilingConfig::new(ceiling)
    })
    .unwrap();
    let modes: Vec<WaitMode> = (0..4)
        .map(|_| pad.pad(|| ()).unwrap().release.mode)
        .collect();
    assert_eq!(
        modes,
        vec![
            WaitMode::Spin,
            WaitMode::Spin,
            WaitMode::Sleep,
            WaitMode::Sleep
        ]
    );
    // Sleep-mode requests are still padded.
    let p = pad.pad(|| ()).unwrap();
    assert_eq!(p.release.mode, WaitMode::Sleep);
    assert!(p.release.observed >= ceiling);
}

#[test]
fn budget_charge_does_not_depend_on_work_time() {
    let ceiling = Duration::from_millis(2);
    let burst = Duration::from_millis(20);
    let pad = CeilingPad::new(CeilingConfig {
        mode: WaitMode::Spin,
        spin_budget: SpinBudgetConfig::Limited {
            cpu_per_second: Duration::from_micros(1),
            burst,
        },
        ..CeilingConfig::new(ceiling)
    })
    .unwrap();
    // One fast and one slow operation each reserve exactly one ceiling.
    pad.pad(|| ()).unwrap();
    let after_fast = pad.spin_budget_remaining().unwrap();
    pad.pad(|| std::thread::sleep(Duration::from_micros(1_500)))
        .unwrap();
    let after_slow = pad.spin_budget_remaining().unwrap();
    let fast_cost = burst - after_fast;
    let slow_cost = after_fast.saturating_sub(after_slow);
    // Refill at 1 us per second adds at most a few nanoseconds here.
    let diff = fast_cost.abs_diff(slow_cost);
    assert!(
        diff < Duration::from_micros(1),
        "fast {fast_cost:?} slow {slow_cost:?}"
    );
    assert!(fast_cost.abs_diff(ceiling) < Duration::from_micros(1));
}

#[test]
fn semaphore_sheds_beyond_cap_before_any_work() {
    let pad = Arc::new(
        CeilingPad::new(CeilingConfig {
            max_concurrent: 2,
            ..cfg(Duration::from_millis(20), WaitMode::Sleep)
        })
        .unwrap(),
    );
    let (tx1, rx1) = mpsc::channel::<()>();
    let (tx2, rx2) = mpsc::channel::<()>();
    std::thread::scope(|s| {
        let p1 = Arc::clone(&pad);
        let p2 = Arc::clone(&pad);
        let h1 = s.spawn(move || p1.pad(|| rx1.recv().is_ok()));
        let h2 = s.spawn(move || p2.pad(|| rx2.recv().is_ok()));
        assert!(
            wait_for(|| pad.in_flight() == 2, 20_000),
            "holders never admitted"
        );

        let called = AtomicBool::new(false);
        let t0 = Instant::now();
        let r = pad.pad(|| called.store(true, Ordering::SeqCst));
        let took = t0.elapsed();
        assert_eq!(r, Err(Trip::SlotsFull));
        assert!(!called.load(Ordering::SeqCst), "shed request must not run");
        assert!(
            took < Duration::from_millis(5),
            "shed must be immediate, took {took:?}"
        );
        assert_eq!(Trip::SlotsFull.gate_outcome(), GateOutcome::Retry);
        assert_eq!(Trip::SlotsFull.resolution(), Resolution::Reject);

        tx1.send(()).unwrap();
        tx2.send(()).unwrap();
        assert!(h1.join().unwrap().unwrap().value);
        assert!(h2.join().unwrap().unwrap().value);
    });
    assert_eq!(pad.in_flight(), 0);
    assert!(pad.pad(|| ()).is_ok());
}

#[test]
fn panicking_operation_frees_its_slot() {
    let pad = CeilingPad::new(CeilingConfig {
        max_concurrent: 1,
        ..cfg(Duration::from_micros(100), WaitMode::Sleep)
    })
    .unwrap();
    let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        pad.pad(|| -> u8 { panic!("operation failed") })
    }));
    assert!(r.is_err());
    assert_eq!(pad.in_flight(), 0);
    assert!(pad.pad(|| ()).is_ok());
}

#[test]
fn oversized_input_is_rejected_before_admission() {
    let pad = CeilingPad::new(CeilingConfig {
        max_input_len: 8,
        ..cfg(Duration::from_millis(5), WaitMode::Sleep)
    })
    .unwrap();
    let called = AtomicBool::new(false);
    let t0 = Instant::now();
    let r = pad.pad_input(&[0u8; 9], |_| called.store(true, Ordering::SeqCst));
    assert_eq!(r, Err(Trip::InputTooLarge));
    assert!(!called.load(Ordering::SeqCst));
    assert!(t0.elapsed() < Duration::from_millis(5));
    assert_eq!(Trip::InputTooLarge.gate_outcome(), GateOutcome::Retry);
    let p = pad.pad_input(&[1u8; 8], |b| b.len()).unwrap();
    assert_eq!(p.value, 8);
    assert!(p.release.observed >= Duration::from_millis(5));
}

#[test]
fn clock_failure_halts_until_reset() {
    // Call 0 is construction, 1 is admission, 2 is completion.
    let pad = CeilingPad::with_clock(
        cfg(Duration::from_micros(200), WaitMode::Spin),
        BackwardsOnce::new(2),
    )
    .unwrap();
    assert_eq!(pad.pad(|| 1u8), Err(Trip::ClockFailure));
    assert_eq!(
        Trip::ClockFailure.gate_outcome(),
        GateOutcome::TerminalBreach
    );
    assert_eq!(Trip::ClockFailure.resolution(), Resolution::Halt);
    assert!(pad.is_halted());
    let called = AtomicBool::new(false);
    assert_eq!(
        pad.pad(|| called.store(true, Ordering::SeqCst)),
        Err(Trip::Halted)
    );
    assert!(!called.load(Ordering::SeqCst));
    assert_eq!(Trip::Halted.gate_outcome(), GateOutcome::TerminalBreach);
    pad.reset();
    assert!(!pad.is_halted());
    assert_eq!(pad.pad(|| 2u8).unwrap().value, 2);
}

#[test]
fn config_bounds_are_enforced() {
    let ok = CeilingConfig::new(Duration::from_millis(1));
    assert!(ok.validate().is_ok());
    let cases = [
        CeilingConfig::new(Duration::ZERO),
        CeilingConfig::new(Duration::from_secs(11)),
        CeilingConfig {
            max_concurrent: 0,
            ..ok.clone()
        },
        CeilingConfig {
            max_concurrent: 1 << 20,
            ..ok.clone()
        },
        CeilingConfig {
            hard_ceiling_buckets: 0,
            ..ok.clone()
        },
        CeilingConfig {
            hard_ceiling_buckets: 5_000,
            ..ok.clone()
        },
        CeilingConfig {
            max_input_len: usize::MAX,
            ..ok.clone()
        },
        CeilingConfig {
            mode: WaitMode::Spin,
            spin_budget: SpinBudgetConfig::Limited {
                cpu_per_second: Duration::from_millis(100),
                burst: Duration::from_micros(500),
            },
            ..ok.clone()
        },
        CeilingConfig {
            spin_budget: SpinBudgetConfig::Limited {
                cpu_per_second: Duration::ZERO,
                burst: Duration::from_millis(10),
            },
            ..ok.clone()
        },
    ];
    for c in cases {
        assert!(CeilingPad::new(c.clone()).is_err(), "accepted {c:?}");
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn async_hybrid_releases_at_the_ceiling() {
    let ceiling = Duration::from_millis(10);
    let pad = CeilingPad::new(cfg(ceiling, WaitMode::Hybrid)).unwrap();
    let mut late = Vec::new();
    for i in 0..20u32 {
        let t0 = Instant::now();
        let p = pad
            .pad_async(|| async move {
                tokio::task::yield_now().await;
                i + 1
            })
            .await
            .unwrap();
        let ext = t0.elapsed();
        assert_eq!(p.value, i + 1);
        assert_eq!(p.release.buckets, 1);
        assert!(ext >= ceiling, "async early: {ext:?}");
        late.push(p.release.observed - ceiling);
    }
    let m = median(&late);
    assert!(
        m < Duration::from_micros(200),
        "async hybrid median late {m:?}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn async_sleep_mode_is_padded() {
    let ceiling = Duration::from_millis(5);
    let pad = CeilingPad::new(cfg(ceiling, WaitMode::Sleep)).unwrap();
    for _ in 0..5 {
        let p = pad.pad_async(|| async { 7u8 }).await.unwrap();
        assert!(p.release.observed >= ceiling);
        assert_eq!(p.release.mode, WaitMode::Sleep);
    }
    let p = pad
        .pad_input_async(b"abc", |b| async move { b.len() })
        .await
        .unwrap();
    assert_eq!(p.value, 3);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn async_hard_overrun_is_cancelled_at_the_hard_ceiling() {
    let ceiling = Duration::from_millis(5);
    let pad = CeilingPad::new(CeilingConfig {
        hard_ceiling_buckets: 2,
        ..cfg(ceiling, WaitMode::Hybrid)
    })
    .unwrap();
    let t0 = Instant::now();
    let r = pad
        .pad_async(|| async {
            tokio::time::sleep(Duration::from_millis(200)).await;
            1u8
        })
        .await;
    let ext = t0.elapsed();
    assert_eq!(r, Err(Trip::Overrun));
    assert!(
        ext >= Duration::from_millis(10),
        "before the hard ceiling: {ext:?}"
    );
    // Released on the retry window (hard ceiling 10 ms * factor 16 =
    // 160 ms). Not cancelled, the 200 ms operation would be released at the
    // second window, 320 ms.
    assert!(ext < Duration::from_millis(300), "not cancelled: {ext:?}");
    assert_eq!(pad.in_flight(), 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn async_shares_the_concurrency_cap() {
    let pad = Arc::new(
        CeilingPad::new(CeilingConfig {
            max_concurrent: 1,
            ..cfg(Duration::from_millis(30), WaitMode::Sleep)
        })
        .unwrap(),
    );
    let p2 = Arc::clone(&pad);
    let holder = tokio::spawn(async move { p2.pad_async(|| async { 1u8 }).await });
    for _ in 0..2_000 {
        if pad.in_flight() == 1 {
            break;
        }
        tokio::time::sleep(Duration::from_micros(200)).await;
    }
    assert_eq!(pad.in_flight(), 1);
    assert_eq!(pad.pad_async(|| async { 2u8 }).await, Err(Trip::SlotsFull));
    assert_eq!(pad.pad(|| 3u8), Err(Trip::SlotsFull));
    assert!(holder.await.unwrap().is_ok());
}
