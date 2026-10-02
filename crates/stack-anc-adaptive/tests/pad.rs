//! Pad mechanics shared by both controllers: admission shedding, input
//! limits, clock failure and halt, config bounds, and the flood test.
#![allow(clippy::unwrap_used, clippy::panic)] // test code: failures should abort the test

mod common;

use common::{ms, spin_for, us, BackwardsOnce};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Barrier;
use std::time::{Duration, Instant};
use sstack_anc_adaptive::{
    AdaptivePad, EpochConfig, EpochQuantizedTarget, GateOutcome, NaiveConfig, PadConfig,
    Resolution, SpinBudgetConfig, Trip, WaitMode,
};

fn epoch_pad(pad: PadConfig) -> AdaptivePad<EpochQuantizedTarget> {
    AdaptivePad::epoch(pad, EpochConfig::new(us(200), ms(4))).unwrap()
}

#[test]
fn defaults_are_sleep_mode_with_a_limited_spin_budget() {
    let c = PadConfig::default();
    assert_eq!(c.mode, WaitMode::Sleep);
    assert!(matches!(c.spin_budget, SpinBudgetConfig::Limited { .. }));
    assert_eq!(c.spin_charge(), Duration::ZERO);
    let e = EpochConfig::new(us(100), ms(3));
    assert_eq!(e.initial_level, e.top_level());
    assert_eq!(e.level_target(e.initial_level), ms(3));
}

#[test]
fn slots_full_is_shed_before_any_work() {
    let pad = epoch_pad(PadConfig {
        max_concurrent: 1,
        ..PadConfig::default()
    });
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
        let ran = AtomicBool::new(false);
        let t0 = Instant::now();
        let r = pad.pad(|| ran.store(true, Ordering::SeqCst));
        let seen = t0.elapsed();
        assert_eq!(r.unwrap_err(), Trip::SlotsFull);
        assert!(!ran.load(Ordering::SeqCst), "shed request must not run");
        assert!(seen < ms(4), "shed must not be padded: {seen:?}");
        assert_eq!(Trip::SlotsFull.gate_outcome(), GateOutcome::Retry);
        assert_eq!(Trip::SlotsFull.resolution(), Resolution::Reject);
        release.wait();
    });
    assert_eq!(pad.in_flight(), 0);
    assert!(pad.pad(|| ()).is_ok());
}

#[test]
fn oversized_input_is_rejected_before_work() {
    let pad = epoch_pad(PadConfig {
        max_input_len: 4,
        ..PadConfig::default()
    });
    let ran = AtomicBool::new(false);
    let r = pad.pad_input(&[0u8; 5], |_| ran.store(true, Ordering::SeqCst));
    assert_eq!(r.unwrap_err(), Trip::InputTooLarge);
    assert!(!ran.load(Ordering::SeqCst));
    let ok = pad.pad_input(&[1u8, 2, 3, 4], |b| b.len()).unwrap();
    assert_eq!(ok.value, 4);
}

#[test]
fn clock_failure_halts_until_operator_reset() {
    // Clock calls: 0 = construction, 1 = admission, 2 = completion.
    let clock = BackwardsOnce::new(2);
    let ctl = EpochQuantizedTarget::new(EpochConfig::new(us(200), ms(4)), Instant::now()).unwrap();
    let pad = AdaptivePad::with_parts(PadConfig::default(), ctl, clock).unwrap();
    let r = pad.pad(|| 1);
    assert_eq!(r.unwrap_err(), Trip::ClockFailure);
    assert_eq!(
        Trip::ClockFailure.gate_outcome(),
        GateOutcome::TerminalBreach
    );
    assert_eq!(Trip::ClockFailure.resolution(), Resolution::Halt);
    assert!(pad.is_halted());
    let ran = AtomicBool::new(false);
    assert_eq!(
        pad.pad(|| ran.store(true, Ordering::SeqCst)).unwrap_err(),
        Trip::Halted
    );
    assert!(!ran.load(Ordering::SeqCst));
    pad.reset();
    assert!(!pad.is_halted());
    assert_eq!(pad.pad(|| 2).unwrap().value, 2);
}

#[test]
fn config_bounds_are_rejected_not_clamped() {
    let bad_pad = [
        PadConfig {
            max_concurrent: 0,
            ..PadConfig::default()
        },
        PadConfig {
            mode: WaitMode::Hybrid,
            spin_tail: ms(10),
            spin_budget: SpinBudgetConfig::Limited {
                cpu_per_second: ms(100),
                burst: ms(1),
            },
            ..PadConfig::default()
        },
        PadConfig {
            spin_budget: SpinBudgetConfig::Limited {
                cpu_per_second: Duration::ZERO,
                burst: ms(1),
            },
            ..PadConfig::default()
        },
    ];
    for p in bad_pad {
        assert!(p.validate().is_err(), "{p:?}");
    }
    let e = EpochConfig::new(us(100), ms(1));
    let bad_epoch = [
        EpochConfig::new(ms(2), ms(1)),
        EpochConfig::new(Duration::from_nanos(10), ms(1)),
        EpochConfig::new(us(100), Duration::from_secs(11)),
        EpochConfig {
            initial_level: e.top_level() + 1,
            ..e
        },
        EpochConfig {
            epoch: Duration::from_micros(10),
            ..e
        },
        EpochConfig {
            leak_budget: stack_anc_adaptive::LeakBudgetConfig {
                bits: f64::NAN,
                window: ms(100),
            },
            ..e
        },
        EpochConfig {
            leak_budget: stack_anc_adaptive::LeakBudgetConfig {
                bits: 0.0,
                window: ms(100),
            },
            ..e
        },
    ];
    for c in bad_epoch {
        assert!(c.validate().is_err(), "{c:?}");
        assert!(AdaptivePad::epoch(PadConfig::default(), c).is_err());
    }
    let n = NaiveConfig::new(ms(1));
    let bad_naive = [
        NaiveConfig { window: 0, ..n },
        NaiveConfig {
            window: stack_anc_adaptive::config::MAX_WINDOW + 1,
            ..n
        },
        NaiveConfig {
            initial_target: ms(2),
            ..n
        },
        NaiveConfig {
            statistic: stack_anc_adaptive::WindowStatistic::Percentile { permille: 1_001 },
            ..n
        },
    ];
    for c in bad_naive {
        assert!(c.validate().is_err(), "{c:?}");
        assert!(AdaptivePad::naive(PadConfig::default(), c).is_err());
    }
}

/// Flood: 10 times the admission cap in concurrent fast-fail clients for a
/// fixed wall time, Hybrid mode with a limited spin budget. Sheds are
/// counted, reserved spin stays within the budget, and a legitimate client
/// still completes requests.
#[test]
fn flood_is_shed_spin_stays_in_budget_and_legit_requests_complete() {
    const CAP: usize = 2;
    let rate = ms(20);
    let burst = ms(2);
    let tail = us(200);
    let pad = AdaptivePad::epoch(
        PadConfig {
            mode: WaitMode::Hybrid,
            spin_tail: tail,
            spin_budget: SpinBudgetConfig::Limited {
                cpu_per_second: rate,
                burst,
            },
            max_concurrent: CAP,
            ..PadConfig::default()
        },
        EpochConfig {
            epoch: ms(50),
            ..EpochConfig::new(us(400), ms(6))
        },
    )
    .unwrap();
    let stop = AtomicBool::new(false);
    let (served, shed, hybrid) = (AtomicU64::new(0), AtomicU64::new(0), AtomicU64::new(0));
    let (legit_ok, legit_attempts) = (AtomicU64::new(0), AtomicU64::new(0));
    let t0 = Instant::now();
    std::thread::scope(|s| {
        for _ in 0..(10 * CAP) {
            s.spawn(|| {
                while !stop.load(Ordering::Relaxed) {
                    match pad.pad(|| false) {
                        Ok(p) => {
                            served.fetch_add(1, Ordering::Relaxed);
                            if p.release.mode == WaitMode::Hybrid {
                                hybrid.fetch_add(1, Ordering::Relaxed);
                            }
                        }
                        Err(Trip::SlotsFull) => {
                            shed.fetch_add(1, Ordering::Relaxed);
                            std::thread::sleep(us(100));
                        }
                        Err(other) => panic!("unexpected trip {other:?}"),
                    }
                }
            });
        }
        s.spawn(|| {
            while !stop.load(Ordering::Relaxed) {
                for _ in 0..500 {
                    legit_attempts.fetch_add(1, Ordering::Relaxed);
                    let r = pad.pad(|| {
                        spin_for(us(50));
                        true
                    });
                    if let Ok(p) = r {
                        assert!(p.value);
                        if p.release.mode == WaitMode::Hybrid {
                            hybrid.fetch_add(1, Ordering::Relaxed);
                        }
                        legit_ok.fetch_add(1, Ordering::Relaxed);
                        break;
                    }
                    std::thread::sleep(us(100));
                }
                std::thread::sleep(ms(5));
            }
        });
        std::thread::sleep(Duration::from_millis(1_000));
        stop.store(true, Ordering::Relaxed);
    });
    let wall = t0.elapsed();
    let (served, shed, hybrid) = (
        served.load(Ordering::Relaxed),
        shed.load(Ordering::Relaxed),
        hybrid.load(Ordering::Relaxed),
    );
    assert!(shed > 0, "no sheds: served {served}");
    assert!(
        legit_ok.load(Ordering::Relaxed) > 0,
        "legitimate client starved"
    );
    // Reserved spin (an upper bound on the spin actually done: a request
    // spins at most its tail) stays within the budget, rate * wall + burst,
    // counting flood and legitimate requests together.
    let reserved = tail.as_secs_f64() * hybrid as f64;
    let bound = rate.as_secs_f64() * wall.as_secs_f64() + burst.as_secs_f64();
    assert!(reserved <= bound, "spin {reserved} s over budget {bound} s");
    // And the budget really limited it: most served flood requests slept.
    assert!(hybrid < served, "hybrid {hybrid} of {served}");
    assert!(legit_attempts.load(Ordering::Relaxed) >= legit_ok.load(Ordering::Relaxed));
    assert!(pad.status().target <= ms(6));
}

/// Hybrid plans each request as work + spin tail, so every released Hybrid
/// request sleeps before it spins, whatever its work time. A request whose
/// work would end inside the tail window is escalated instead of skipping
/// the sleep (which would make the wait path depend on the secret).
#[test]
fn hybrid_reserves_tail_headroom_in_the_target() {
    let pad = AdaptivePad::epoch(
        PadConfig {
            mode: WaitMode::Hybrid,
            spin_tail: us(600),
            spin_budget: SpinBudgetConfig::Unlimited,
            ..PadConfig::default()
        },
        EpochConfig {
            initial_level: 0,
            ..EpochConfig::new(ms(2), ms(16))
        },
    )
    .unwrap();
    // 0.5 ms of work + 0.6 ms tail fits the 2 ms level: on time.
    let r = pad.pad(|| spin_for(us(500))).unwrap();
    assert_eq!(
        r.release.disposition,
        stack_anc_adaptive::Disposition::OnTime
    );
    assert_eq!(r.release.mode, WaitMode::Hybrid);
    assert!(r.release.observed >= ms(2));
    // 1.6 ms of work fits 2 ms, but not with the 0.6 ms tail: escalated to
    // 4 ms, so it still sleeps before spinning.
    let r = pad.pad(|| spin_for(us(1_600))).unwrap();
    assert_eq!(
        r.release.disposition,
        stack_anc_adaptive::Disposition::Escalated { steps: 1 }
    );
    assert_eq!(r.release.release, ms(4));
    assert!(r.release.observed >= ms(4));
    // Sleep mode has no tail, so the same work is on time at 2 ms.
    let sleep = AdaptivePad::epoch(
        PadConfig::default(),
        EpochConfig {
            initial_level: 0,
            ..EpochConfig::new(ms(2), ms(16))
        },
    )
    .unwrap();
    let r = sleep.pad(|| spin_for(us(1_600))).unwrap();
    assert_eq!(
        r.release.disposition,
        stack_anc_adaptive::Disposition::OnTime
    );
}
