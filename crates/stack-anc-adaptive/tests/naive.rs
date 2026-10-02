//! The naive rolling target (the brief's design): its three leaks, shown
//! deterministically on the controller and once through a real pad, plus
//! its cap and change counter.
#![allow(clippy::unwrap_used, clippy::panic)] // test code: failures should abort the test

mod common;

use common::{ms, us};
use std::time::{Duration, Instant};
use sstack_anc_adaptive::{
    AdaptivePad, Disposition, NaiveConfig, NaiveRollingTarget, PadConfig, Plan, TargetController,
    WindowStatistic,
};

/// Class A work (fast path) and class B work (slow path), microseconds.
const A: u64 = 100;
const B: u64 = 200;

fn feed(c: &mut NaiveRollingTarget, works: impl IntoIterator<Item = u64>) {
    let now = Instant::now();
    for w in works {
        let (snap, _) = c.admit(now);
        c.record(&snap, us(w), now);
    }
}

#[test]
fn leak_1_slow_request_is_released_late() {
    // Mean of a 50/50 window is 150 us; with a 20 us margin the target is
    // 170 us, below the slow path.
    let mut c = NaiveRollingTarget::new(NaiveConfig {
        statistic: WindowStatistic::Mean,
        window: 64,
        margin: us(20),
        ..NaiveConfig::new(ms(10))
    })
    .unwrap();
    feed(&mut c, (0..64).map(|i| if i % 2 == 0 { A } else { B }));
    assert_eq!(c.target(), us(170));
    let (snap, _) = c.admit(Instant::now());
    // Class A leaves at the target; class B leaves at its own work time.
    assert_eq!(snap.plan(us(A)), Plan::OnTime { release: us(170) });
    assert_eq!(snap.plan(us(B)), Plan::Late { release: us(B) });
}

#[test]
fn leak_2_target_poisoning_by_fast_flood() {
    // p99 over a window of 16 with a 50 us margin. In honest mixed traffic
    // the window holds some slow requests, so the target covers class B
    // and nothing is released late.
    let mut c = NaiveRollingTarget::new(NaiveConfig {
        statistic: WindowStatistic::Percentile { permille: 990 },
        window: 16,
        margin: us(50),
        ..NaiveConfig::new(ms(10))
    })
    .unwrap();
    feed(&mut c, (0..16).map(|i| if i % 4 == 0 { B } else { A }));
    let (honest, _) = c.admit(Instant::now());
    assert_eq!(honest.target, us(B + 50));
    assert!(matches!(honest.plan(us(B)), Plan::OnTime { .. }));

    // The attacker floods one window of fast requests (class A, which they
    // can always produce: a guess wrong at byte 0), then probes.
    feed(&mut c, std::iter::repeat_n(A, 16));
    let (poisoned, _) = c.admit(Instant::now());
    assert_eq!(poisoned.target, us(A + 50));
    // Now a slow-path probe is released late and stands out, while a
    // fast-path probe is on time: the two classes are distinguishable.
    assert_eq!(poisoned.plan(us(B)), Plan::Late { release: us(B) });
    assert!(matches!(poisoned.plan(us(A)), Plan::OnTime { .. }));

    // The other direction: a flood of slow requests raises the target (and
    // everyone's latency) up to the cap, then the attacker watches it fall
    // as honest traffic refills the window.
    feed(&mut c, std::iter::repeat_n(5_000, 16));
    assert_eq!(c.target(), us(5_050));
    feed(&mut c, std::iter::repeat_n(A, 8));
    assert_eq!(c.target(), us(5_050), "p99 still sees the slow half");
    feed(&mut c, std::iter::repeat_n(A, 8));
    assert_eq!(c.target(), us(A + 50));
}

#[test]
fn leak_2_poisoning_through_a_real_pad() {
    // The same attack end to end, with sleeping operations (ms scale so
    // scheduler noise does not matter).
    let pad = AdaptivePad::naive(
        PadConfig::default(),
        NaiveConfig {
            statistic: WindowStatistic::Percentile { permille: 990 },
            window: 8,
            margin: ms(1),
            ..NaiveConfig::new(ms(50))
        },
    )
    .unwrap();
    let fast = || ();
    let slow = || std::thread::sleep(ms(6));
    // Honest mixed traffic: slow probes are on time.
    for i in 0..8 {
        if i % 4 == 0 {
            pad.pad(slow).unwrap();
        } else {
            pad.pad(fast).unwrap();
        }
    }
    let honest = pad.pad(slow).unwrap();
    assert_eq!(honest.release.disposition, Disposition::OnTime);
    // Flood of fast requests, then a slow probe: released late, at its own
    // work time, well past the target every fast request is released at.
    for _ in 0..8 {
        pad.pad(fast).unwrap();
    }
    let probe_fast = pad.pad(fast).unwrap();
    assert_eq!(probe_fast.release.disposition, Disposition::OnTime);
    for _ in 0..8 {
        pad.pad(fast).unwrap();
    }
    let probe_slow = pad.pad(slow).unwrap();
    assert_eq!(probe_slow.release.disposition, Disposition::Late);
    assert!(probe_slow.release.target < ms(6));
    assert!(probe_slow.release.observed >= ms(6));
    assert!(probe_slow.release.observed > probe_fast.release.observed + ms(3));
}

#[test]
fn leak_3_target_tracks_secret_dependent_history() {
    // Two servers with the same config see the same number of requests;
    // only the share of slow-path (class B) requests from other users
    // differs. The target, which every response time reveals, differs.
    let cfg = NaiveConfig {
        statistic: WindowStatistic::Mean,
        window: 128,
        margin: us(20),
        ..NaiveConfig::new(ms(10))
    };
    let mut mostly_a = NaiveRollingTarget::new(cfg).unwrap();
    let mut mostly_b = NaiveRollingTarget::new(cfg).unwrap();
    // Real work times jitter by a few microseconds from request to request.
    let jitter = |i: u64| (i * 37) % 11;
    feed(
        &mut mostly_a,
        (0..1_000).map(|i| jitter(i) + if i % 10 == 0 { B } else { A }),
    );
    feed(
        &mut mostly_b,
        (0..1_000).map(|i| jitter(i) + if i % 10 == 0 { A } else { B }),
    );
    assert!(mostly_a.target() < us(145), "{:?}", mostly_a.target());
    assert!(mostly_b.target() > mostly_a.target() + us(50));
    // And the target moves on almost every request, so the change count
    // (and its leakage bound) grows with the traffic, without limit.
    let s = mostly_a.status();
    assert!(s.changes_total > 900, "{s:?}");
    assert!(s.leak_bits > 5_000.0, "{s:?}");
    assert_eq!(s.leak_budget_bits, None);
}

#[test]
fn cap_holds_under_slow_flood() {
    let cap = ms(2);
    let mut c = NaiveRollingTarget::new(NaiveConfig {
        statistic: WindowStatistic::Mean,
        window: 32,
        ..NaiveConfig::new(cap)
    })
    .unwrap();
    for _ in 0..1_000 {
        let (snap, _) = c.admit(Instant::now());
        assert!(snap.target <= cap);
        c.record(&snap, Duration::from_secs(3_600), Instant::now());
        assert!(c.target() <= cap);
    }
    assert_eq!(c.target(), cap);

    // Through a pad with concurrent slow work: past the cap is a RETRY.
    let pad = AdaptivePad::naive(PadConfig::default(), NaiveConfig::new(ms(3))).unwrap();
    std::thread::scope(|s| {
        for _ in 0..4 {
            s.spawn(|| {
                for _ in 0..3 {
                    let r = pad.pad(|| std::thread::sleep(ms(5)));
                    assert_eq!(r.unwrap_err(), stack_anc_adaptive::Trip::Overrun);
                    assert!(pad.status().target <= ms(3));
                }
            });
        }
    });
    assert_eq!(pad.status().target, ms(3));
}

#[test]
fn target_change_counter_is_exact() {
    let mut c = NaiveRollingTarget::new(NaiveConfig {
        statistic: WindowStatistic::Mean,
        window: 2,
        margin: Duration::ZERO,
        initial_target: us(50),
        ..NaiveConfig::new(ms(1))
    })
    .unwrap();
    feed(&mut c, [100]); // 50 -> 100: up
    feed(&mut c, [100]); // 100: none
    feed(&mut c, [300]); // 200: up
    feed(&mut c, [100]); // 200: none (window 300,100)
    feed(&mut c, [10]); // 55: down
    let s = c.status();
    assert_eq!(
        (s.increases_total, s.decreases_total, s.changes_total),
        (2, 1, 3)
    );
    assert_eq!(s.requests_total, 5);
    // Reset returns to the initial target (a counted change).
    let ch = c.operator_reset(Instant::now());
    assert_eq!(ch.decreases, 1);
    assert_eq!(c.target(), us(50));
    assert_eq!(c.window_len(), 0);
}
