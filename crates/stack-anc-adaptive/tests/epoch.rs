//! The epoch-quantized controller: doubling, epoch-only decreases, the cap,
//! the change counter, the leak budget and trajectories.
#![allow(clippy::unwrap_used, clippy::panic)] // test code: failures should abort the test

mod common;

use common::{ms, us};
use proptest::prelude::*;
use std::time::{Duration, Instant};
use sstack_anc_adaptive::{
    epoch_bound_bits, AdaptivePad, ControllerTrip, Disposition, EpochConfig, EpochQuantizedTarget,
    GateOutcome, LeakBudgetConfig, PadConfig, Resolution, TargetController, Trip,
};
use sstack_anc_harness::SplitMix64;

/// Ladder 100, 200, 400, 800, 1600 us; epoch 1 s; generous budget.
fn cfg(initial_level: u32) -> EpochConfig {
    EpochConfig {
        initial_level,
        epoch: Duration::from_secs(1),
        leak_budget: LeakBudgetConfig {
            bits: 10_000.0,
            window: Duration::from_secs(3_600),
        },
        ..EpochConfig::new(us(100), us(1_600))
    }
}

/// One request through the controller at `at`, with work time `work`.
fn step(
    c: &mut EpochQuantizedTarget,
    at: Instant,
    work: Duration,
) -> (Duration, stack_anc_adaptive::Changes) {
    let (snap, a) = c.admit(at);
    let r = c.record(&snap, work, at);
    (snap.target, a.merge(r))
}

#[test]
fn epoch_doubles_on_misprediction() {
    let o = Instant::now();
    let mut c = EpochQuantizedTarget::new(cfg(0), o).unwrap();
    assert_eq!(c.target(), us(100));

    // Fits: no change.
    let (t, ch) = step(&mut c, o, us(90));
    assert_eq!(t, us(100));
    assert!(ch.is_empty());

    // Misprediction by a little: one doubling.
    let (_, ch) = step(&mut c, o + ms(1), us(150));
    assert_eq!(ch.increases, 1);
    assert_eq!(c.target(), us(200));

    // Misprediction by a lot: doubles until it covers (200 -> 400 -> 800).
    let (_, ch) = step(&mut c, o + ms(2), us(700));
    assert_eq!(ch.increases, 2);
    assert_eq!(c.target(), us(800));
    assert_eq!(c.status().increases_total, 3);

    // The plan for a mispredicted request releases at the covering level,
    // never at the raw work time.
    let (snap, _) = c.admit(o + ms(3));
    let plan = snap.plan(us(1_000));
    assert_eq!(plan.release(), us(1_600));
}

#[test]
fn pad_releases_misprediction_at_doubled_level() {
    let e = EpochConfig {
        initial_level: 0,
        ..EpochConfig::new(ms(2), ms(32))
    };
    let pad = AdaptivePad::epoch(PadConfig::default(), e).unwrap();
    let r = pad.pad(|| std::thread::sleep(us(2_500))).unwrap();
    assert_eq!(r.release.target, ms(2));
    assert_eq!(r.release.disposition, Disposition::Escalated { steps: 1 });
    assert_eq!(r.release.release, ms(4));
    assert!(r.release.observed >= ms(4), "{:?}", r.release);
    assert_eq!(pad.status().target, ms(4));
    assert_eq!(pad.status().increases_total, 1);
    // The next request uses the doubled target.
    let r = pad.pad(|| ()).unwrap();
    assert_eq!(r.release.target, ms(4));
    assert_eq!(r.release.disposition, Disposition::OnTime);
    assert!(r.release.observed >= ms(4));
}

#[test]
fn no_decrease_within_an_epoch() {
    let o = Instant::now();
    let mut c = EpochQuantizedTarget::new(cfg(4), o).unwrap();
    assert_eq!(c.target(), us(1_600));
    // Many fast requests throughout epoch 0: the level holds.
    for i in 0..1_000u64 {
        let (t, ch) = step(&mut c, o + Duration::from_micros(i * 999), us(10));
        assert_eq!(t, us(1_600));
        assert!(
            ch.is_empty(),
            "changed inside epoch 0 at request {i}: {ch:?}"
        );
    }
    // First admission at or after the boundary: exactly one step down.
    let (t, ch) = step(&mut c, o + ms(1_000), us(10));
    assert_eq!(t, us(800));
    assert_eq!(ch.decreases, 1);
    // Still inside epoch 1: holds even though every request is fast.
    for i in 1..100u64 {
        let (t, ch) = step(&mut c, o + ms(1_000 + i * 9), us(10));
        assert_eq!(t, us(800));
        assert!(ch.is_empty());
    }
    let (t, _) = step(&mut c, o + ms(2_000), us(10));
    assert_eq!(t, us(400));
    assert_eq!(c.status().decreases_total, 2);
    assert_eq!(c.boundaries_total(), 2);
}

#[test]
fn decrease_rules_misprediction_idle_and_coverage() {
    let o = Instant::now();
    let mut c = EpochQuantizedTarget::new(cfg(2), o).unwrap(); // 400 us
                                                               // Epoch 0: a misprediction raises to 800 and blocks the decrease at the
                                                               // end of epoch 0.
    step(&mut c, o + ms(10), us(500));
    assert_eq!(c.target(), us(800));
    let (t, ch) = step(&mut c, o + ms(1_000), us(10));
    assert_eq!(t, us(800));
    assert_eq!(ch.decreases, 0);
    // Epoch 1 was clean: step down at its end.
    let (t, ch) = step(&mut c, o + ms(2_000), us(10));
    assert_eq!((t, ch.decreases), (us(400), 1));
    // Epoch 2 had a request of 250 us: the lower level (200) would not
    // have covered it, so the level holds.
    step(&mut c, o + ms(2_500), us(250));
    let (t, ch) = step(&mut c, o + ms(3_000), us(10));
    assert_eq!((t, ch.decreases), (us(400), 0));
    // Epochs 4..9 are idle (no requests at all): idle epochs hold the
    // level. Epoch 3 (the request at 3.0 s) was clean, so the first
    // admission after the gap takes exactly one step, not six.
    let (t, ch) = step(&mut c, o + ms(9_500), us(10));
    assert_eq!((t, ch.decreases), (us(200), 1));
    // Never below the floor.
    for s in 10..20u64 {
        step(&mut c, o + ms(s * 1_000), us(10));
    }
    assert_eq!(c.target(), us(100));
    assert_eq!(c.level(), 0);
}

#[test]
fn cap_holds_under_slow_flood() {
    // Controller: work times far past the cap never push the target past it.
    let o = Instant::now();
    let mut c = EpochQuantizedTarget::new(cfg(0), o).unwrap();
    for i in 0..10_000u64 {
        let (snap, _) = c.admit(o + Duration::from_micros(i));
        assert!(snap.target <= us(1_600));
        let plan = snap.plan(Duration::from_secs(3_600));
        assert!(matches!(plan, stack_anc_adaptive::Plan::HardOverrun { .. }));
        c.record(&snap, Duration::from_secs(3_600), o);
        assert!(c.target() <= us(1_600));
    }
    assert_eq!(c.target(), us(1_600));
    assert_eq!(c.status().increases_total, 4); // 0 -> 4, once

    // Pad, several threads of slow work: every result is a RETRY released
    // on the cap grid, and the target stays at the cap.
    let e = EpochConfig {
        initial_level: 0,
        ..EpochConfig::new(ms(1), ms(4))
    };
    let pad = AdaptivePad::epoch(PadConfig::default(), e).unwrap();
    std::thread::scope(|s| {
        for _ in 0..4 {
            s.spawn(|| {
                for _ in 0..3 {
                    let t0 = Instant::now();
                    let r = pad.pad(|| std::thread::sleep(ms(9)));
                    let seen = t0.elapsed();
                    assert_eq!(r.unwrap_err(), Trip::Overrun);
                    // 9 ms of work: released at 12 ms, the next multiple of
                    // the 4 ms cap, never at the raw 9 ms.
                    assert!(seen >= ms(12), "released at {seen:?}");
                    assert!(pad.status().target <= ms(4));
                }
            });
        }
    });
    assert_eq!(pad.status().target, ms(4));
    assert_eq!(Trip::Overrun.gate_outcome(), GateOutcome::Retry);
    assert_eq!(Trip::Overrun.resolution(), Resolution::Reject);
}

#[test]
fn target_change_counter_is_exact() {
    let o = Instant::now();
    let mut c = EpochQuantizedTarget::new(cfg(0), o).unwrap();
    step(&mut c, o, us(150)); // +1 (100 -> 200)
    step(&mut c, o, us(1_500)); // +3 (200 -> 1600)
    step(&mut c, o, us(90)); // 0
                             // Epoch 0 mispredicted: its boundary holds.
    step(&mut c, o + ms(1_000), us(90)); // 0
    step(&mut c, o + ms(2_000), us(90)); // -1 (1600 -> 800): epoch 1 clean
    step(&mut c, o + ms(3_000), us(90)); // -1 (800 -> 400)
    let s = c.status();
    assert_eq!(s.increases_total, 4);
    assert_eq!(s.decreases_total, 2);
    assert_eq!(s.rollbacks_total, 0);
    assert_eq!(s.changes_total, 6);
    assert_eq!(s.requests_total, 6);
    assert_eq!(s.window_changes, 6);
    assert_eq!(s.window_requests, 6);
    assert!((s.leak_bits - epoch_bound_bits(6, 6)).abs() < 1e-9);
    assert_eq!(s.leak_budget_bits, Some(10_000.0));
}

#[test]
fn leak_budget_spent_rolls_back_to_cap_and_stops_adapting() {
    // Ladder 1 us .. 1 ms (levels 1,2,4,...,1000): room for many doublings.
    let o = Instant::now();
    let e = EpochConfig {
        initial_level: 0,
        epoch: ms(10),
        leak_budget: LeakBudgetConfig {
            bits: 20.0,
            window: Duration::from_secs(1),
        },
        ..EpochConfig::new(us(1), ms(1))
    };
    let mut c = EpochQuantizedTarget::new(e, o).unwrap();
    // Each request mispredicts by one level. Bound after k changes among k
    // requests: k * log2(2(k+1)); 5 -> 17.9 bits, 6 -> 22.8 bits >= 20.
    let mut exhausted_at = None;
    for k in 1..=10u32 {
        let work = Duration::from_micros(1u64 << k);
        let (_, ch) = step(&mut c, o + Duration::from_micros(u64::from(k)), work);
        if ch.exhausted {
            assert!(ch.rollback, "budget spent below the cap must roll back");
            exhausted_at = Some(k);
            break;
        }
    }
    assert_eq!(exhausted_at, Some(6));
    assert!(c.is_frozen());
    assert_eq!(c.target(), ms(1), "rolled back to the public maximum");
    assert_eq!(c.status().rollbacks_total, 1);
    let t = ControllerTrip::LeakBudgetSpent;
    assert_eq!(t.gate_outcome(), GateOutcome::Retry);
    assert_eq!(t.resolution(), Resolution::Rollback);

    // Frozen: requests are still served at the cap, nothing adapts, even
    // across epochs, for the rest of the accounting window.
    for i in 0..10u64 {
        let (target, ch) = step(&mut c, o + ms(i * 90), us(5));
        assert_eq!(target, ms(1));
        assert!(ch.is_empty());
    }
    assert!(c.is_frozen());

    // Operator reset lifts the freeze; the level then steps down through
    // normal epochs.
    let now = o + ms(950);
    c.operator_reset(now);
    assert!(!c.is_frozen());
    assert_eq!(c.status().window_changes, 0);
    step(&mut c, now + ms(1), us(5));
    let (t, ch) = step(&mut c, now + ms(10), us(5));
    assert_eq!(ch.decreases, 1);
    assert!(t < ms(1));
}

#[test]
fn warmup_descent_is_not_charged_and_its_end_is_charged_once() {
    let o = Instant::now();
    let mut c = EpochQuantizedTarget::new(cfg(4), o).unwrap(); // starts at the cap
    assert!(c.is_warming_up());
    // Epochs 0..2 are clean and fast: three uncharged steps, 1600 -> 200.
    for s in 0..4u64 {
        step(&mut c, o + ms(s * 1_000), us(10));
    }
    let st = c.status();
    assert_eq!(c.target(), us(200));
    assert_eq!(st.decreases_total, 3);
    assert_eq!(st.changes_total, 3, "every level move is still counted");
    assert_eq!(st.window_changes, 0, "warm-up steps are not charged");
    assert_eq!(st.leak_bits, 0.0);
    // Epoch 3 had a 150 us request: 100 would not cover it, so the run
    // stops at 200. That hold is charged once.
    step(&mut c, o + ms(3_500), us(150));
    step(&mut c, o + ms(4_000), us(10));
    assert_eq!(c.target(), us(200));
    assert!(!c.is_warming_up());
    assert_eq!(c.status().window_changes, 1);
    // After warm-up, decreases are charged.
    step(&mut c, o + ms(5_000), us(10));
    assert_eq!(c.target(), us(100));
    assert_eq!(c.status().window_changes, 2);
}

#[test]
fn every_miss_and_overrun_is_charged_even_without_a_level_change() {
    let o = Instant::now();
    let mut c = EpochQuantizedTarget::new(cfg(0), o).unwrap();
    // Two requests admitted at 100 us; the first raises the level to 800.
    let (s1, _) = c.admit(o);
    let (s2, _) = c.admit(o);
    c.record(&s1, us(700), o);
    assert_eq!(c.status().window_changes, 3);
    // The second misses its own target but raises nothing: still charged.
    let ch = c.record(&s2, us(150), o);
    assert_eq!(ch.increases, 0);
    assert_eq!(c.status().window_changes, 4);
    // An overrun at the top level: released on cap multiple k = 3, so
    // ceil(log2(3)) = 2 changes are charged.
    let (s3, _) = c.admit(o);
    c.record(&s3, us(1_600) * 5 / 2, o);
    assert_eq!(c.status().window_changes, 4 + 1 + 2); // +1 raise to 1600
}

#[test]
fn window_freeze_thaws_at_the_next_window_and_lifetime_freeze_needs_an_operator() {
    let o = Instant::now();
    let e = EpochConfig {
        initial_level: 0,
        epoch: ms(10),
        leak_budget: LeakBudgetConfig {
            bits: 4.0,
            window: Duration::from_secs(1),
        },
        leak_lifetime_windows: 2,
        ..EpochConfig::new(us(100), us(1_600))
    };
    assert!((e.leak_lifetime_bits() - 8.0).abs() < 1e-12);
    let mut c = EpochQuantizedTarget::new(e, o).unwrap();
    // Window 0: 4 doublings among 1 request = 8 bits >= 4. That also
    // reaches the 8-bit lifetime budget, so use a smaller first spend:
    // one doubling among 1 request = 2 bits, then one more = 2*log2(6).
    step(&mut c, o + ms(1), us(150)); // +1: 2 bits
    assert!(!c.is_frozen());
    step(&mut c, o + ms(2), us(300)); // +1: 2 * log2(6) = 5.2 bits >= 4
    assert!(c.is_frozen());
    assert!(!c.is_frozen_until_reset());
    assert_eq!(c.target(), us(1_600));
    // Next window: thawed, warming up again from the cap.
    let (snap, _) = c.admit(o + ms(1_000));
    assert!(!c.is_frozen());
    assert!(c.is_warming_up());
    assert_eq!(snap.target, us(1_600));
    c.record(&snap, us(10), o + ms(1_000));
    let st = c.status();
    assert!((st.lifetime_bits - epoch_bound_bits(2, 2)).abs() < 1e-9);
    assert_eq!(st.lifetime_budget_bits, Some(8.0));
    // Window 1: an overrun charges enough to cross the lifetime budget:
    // frozen until an operator reset, across any number of windows.
    let (snap, _) = c.admit(o + ms(1_010));
    let ch = c.record(&snap, ms(4), o + ms(1_010));
    assert!(ch.lifetime_exhausted);
    assert!(c.is_frozen_until_reset());
    for s in 2..6u64 {
        let (snap, ch) = c.admit(o + ms(s * 1_000));
        assert!(ch.is_empty());
        assert_eq!(snap.target, us(1_600));
    }
    assert!(c.is_frozen());
    assert_eq!(
        ControllerTrip::LeakLifetimeSpent.gate_outcome(),
        GateOutcome::TerminalBreach
    );
    c.operator_reset(o + ms(6_000));
    let st = c.status();
    assert!(!st.frozen && !st.frozen_until_reset);
    assert_eq!(st.lifetime_bits, 0.0);
}

#[test]
fn accounting_window_resets_on_its_public_grid() {
    let o = Instant::now();
    let e = EpochConfig {
        initial_level: 0,
        leak_budget: LeakBudgetConfig {
            bits: 1_000.0,
            window: ms(100),
        },
        ..cfg(0)
    };
    let mut c = EpochQuantizedTarget::new(e, o).unwrap();
    step(&mut c, o + ms(1), us(150));
    step(&mut c, o + ms(2), us(10));
    let s = c.status();
    assert_eq!((s.window_changes, s.window_requests), (1, 2));
    assert!(s.leak_bits > 0.0);
    step(&mut c, o + ms(100), us(10));
    let s = c.status();
    assert_eq!((s.window_changes, s.window_requests), (0, 1));
    assert_eq!(s.leak_bits, 0.0);
    assert_eq!(s.changes_total, 1, "lifetime count is kept");
}

/// Simulated traffic: 1 request per ms, epoch 10 ms. Class A work is 30 us,
/// class B 45 us, plus `load` us during requests 200..400 (a public load
/// phase). `share_b` is the fraction of class B.
fn trajectory(floor: Duration, share_b_permille: u64, seed: u64) -> (Vec<Duration>, u64) {
    let o = Instant::now();
    let e = EpochConfig {
        initial_level: 0,
        epoch: ms(10),
        leak_budget: LeakBudgetConfig {
            bits: 100_000.0,
            window: Duration::from_secs(3_600),
        },
        ..EpochConfig::new(floor, ms(4))
    };
    let mut c = EpochQuantizedTarget::new(e, o).unwrap();
    let mut rng = SplitMix64::new(seed);
    let mut targets = Vec::new();
    for i in 0..600u64 {
        let is_b = rng.next_u64() % 1_000 < share_b_permille;
        let class_cost = if is_b { 45 } else { 30 };
        let load = if (200..400).contains(&i) { 200 } else { 0 };
        let (t, _) = step(&mut c, o + ms(i), us(class_cost + load));
        targets.push(t);
    }
    (targets, c.status().changes_total)
}

#[test]
fn trajectory_is_identical_whichever_class_dominates_when_floor_covers_both() {
    // Floor 64 us covers both classes at idle (30, 45); under load both
    // need 256 us (230, 245). The trajectory follows load only.
    let (a_heavy, a_changes) = trajectory(us(64), 100, 1);
    let (b_heavy, b_changes) = trajectory(us(64), 900, 2);
    assert_eq!(a_heavy, b_heavy, "trajectory depends on the class mix");
    assert_eq!(a_changes, b_changes);
    // Up two levels when load starts, down two when it ends.
    assert_eq!(a_changes, 4);
    assert_eq!(*a_heavy.iter().max().unwrap(), us(256));
}

#[test]
fn trajectory_differs_when_classes_straddle_a_level() {
    // Floor 32 us: class A (30) fits the floor, class B (45) needs 64. The
    // trajectory then tells which class dominated; the change counter (and
    // so the leak budget) is what bounds that.
    let (a_only, a_changes) = trajectory(us(32), 0, 1);
    let (b_only, b_changes) = trajectory(us(32), 1_000, 2);
    assert_ne!(a_only, b_only);
    assert!(a_changes > 0 && b_changes > 0);
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(64))]

    /// Whatever the work times and arrival times, the target is a ladder
    /// level in floor ..= cap, every planned release is at or after both the
    /// target and the work, and the counted changes match the level moves.
    #[test]
    fn target_stays_on_the_ladder(
        works in proptest::collection::vec(0u64..20_000, 1..300),
        gaps in proptest::collection::vec(0u64..400, 1..300),
    ) {
        let o = Instant::now();
        let e = EpochConfig { initial_level: 0, epoch: ms(1), ..cfg(0) };
        let levels: Vec<Duration> = (0..=e.top_level()).map(|i| e.level_target(i)).collect();
        let mut c = EpochQuantizedTarget::new(e, o).unwrap();
        let mut now = o;
        let mut moves = 0u64;
        let mut last = c.level();
        for (i, w) in works.iter().enumerate() {
            now += Duration::from_micros(gaps[i % gaps.len()]);
            let work = Duration::from_micros(*w);
            let (snap, _) = c.admit(now);
            moves += u64::from(c.level().abs_diff(last));
            last = c.level();
            prop_assert!(levels.contains(&snap.target));
            let rel = snap.plan(work).release();
            prop_assert!(rel >= snap.target && rel >= work);
            c.record(&snap, work, now);
            moves += u64::from(c.level().abs_diff(last));
            last = c.level();
            prop_assert!(levels.contains(&c.target()));
        }
        prop_assert_eq!(moves, c.status().changes_total);
    }
}
