//! The two lanes: wiring rules, speed, separation, and a timing test per
//! lane.
#![allow(clippy::unwrap_used)]

use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};
use stack_anc_ceiling::{CeilingConfig, ConfigError, LanedPad, SpinBudgetConfig, Trip, WaitMode};
use stack_anc_harness::{measure_pair, Class, MeasureConfig, Report, T_THRESHOLD};

fn ms(n: u64) -> Duration {
    Duration::from_millis(n)
}

fn std_cfg() -> CeilingConfig {
    CeilingConfig {
        mode: WaitMode::Sleep,
        spin_budget: SpinBudgetConfig::Unlimited,
        max_concurrent: 2,
        ..CeilingConfig::new(ms(20))
    }
}

fn fast_cfg() -> CeilingConfig {
    CeilingConfig {
        mode: WaitMode::Sleep,
        spin_budget: SpinBudgetConfig::Unlimited,
        max_concurrent: 2,
        hard_ceiling_buckets: 1,
        retry_release_factor: 1,
        ..CeilingConfig::new(ms(2))
    }
}

fn err(r: Result<LanedPad, ConfigError>) -> &'static str {
    r.unwrap_err().field
}

#[test]
fn wiring_rules_are_enforced() {
    assert!(LanedPad::new(std_cfg(), fast_cfg()).is_ok());
    let multi = CeilingConfig { hard_ceiling_buckets: 2, ..fast_cfg() };
    assert_eq!(err(LanedPad::new(std_cfg(), multi)), "fast.hard_ceiling_buckets");
    let slow = CeilingConfig { hard_ceiling_buckets: 1, ..CeilingConfig::new(ms(20)) };
    assert_eq!(err(LanedPad::new(std_cfg(), slow)), "fast.ceiling");
    let longer = CeilingConfig { hard_ceiling_buckets: 1, ..CeilingConfig::new(ms(40)) };
    assert_eq!(err(LanedPad::new(std_cfg(), longer)), "fast.ceiling");
}

#[test]
fn the_fast_lane_is_fast_and_the_standard_lane_is_not() {
    let lanes = LanedPad::new(std_cfg(), fast_cfg()).unwrap();
    let t = Instant::now();
    lanes.fast().pad(|| ()).unwrap();
    let fast = t.elapsed();
    let t = Instant::now();
    lanes.standard().pad(|| ()).unwrap();
    let standard = t.elapsed();
    println!("fast {fast:?}, standard {standard:?}");
    assert!(fast >= ms(2) && fast < ms(10), "fast {fast:?}");
    assert!(standard >= ms(20), "standard {standard:?}");
}

#[test]
fn a_mislabeled_slow_operation_gets_a_retry_and_is_counted() {
    let lanes = LanedPad::new(std_cfg(), fast_cfg()).unwrap();
    assert_eq!(lanes.fast_overruns(), 0);
    let t = Instant::now();
    let r = lanes.fast().pad(|| std::thread::sleep(ms(3)));
    let took = t.elapsed();
    assert_eq!(r.unwrap_err(), Trip::Overrun);
    assert_eq!(lanes.fast_overruns(), 1);
    // Released on the retry window (2 ms hard ceiling x 1), not at some
    // later multiple of the work time.
    assert!(took < ms(12), "retry took {took:?}");
    // A well-behaved operation on the same lane still works.
    assert!(lanes.fast().pad(|| ()).is_ok());
    assert_eq!(lanes.fast_overruns(), 1);
}

#[test]
fn a_flood_on_one_lane_does_not_shed_the_other() {
    // Fast lane: flood it until it sheds. The standard lane stays open.
    let lanes = LanedPad::new(std_cfg(), fast_cfg()).unwrap();
    let stop = AtomicBool::new(false);
    std::thread::scope(|s| {
        for _ in 0..6 {
            s.spawn(|| {
                while !stop.load(Ordering::Relaxed) {
                    let _ = lanes.fast().pad(|| ());
                }
            });
        }
        std::thread::sleep(ms(10));
        let mut shed = 0;
        for _ in 0..5 {
            if lanes.fast().pad(|| ()).is_err() {
                shed += 1;
            }
        }
        assert!(shed > 0, "the fast lane should be shedding under this flood");
        let t = Instant::now();
        assert!(lanes.standard().pad(|| ()).is_ok(), "standard lane shed by a fast flood");
        let took = t.elapsed();
        assert!(took >= ms(20) && took < ms(35), "standard took {took:?}");
        stop.store(true, Ordering::Relaxed);
    });

    // Standard lane: flood it; the fast lane stays open.
    let lanes = LanedPad::new(std_cfg(), fast_cfg()).unwrap();
    let stop = AtomicBool::new(false);
    std::thread::scope(|s| {
        for _ in 0..6 {
            s.spawn(|| {
                while !stop.load(Ordering::Relaxed) {
                    let _ = lanes.standard().pad(|| ());
                }
            });
        }
        std::thread::sleep(ms(30));
        assert!(lanes.standard().pad(|| ()).is_err(), "standard lane should be shedding");
        assert!(lanes.fast().pad(|| ()).is_ok(), "fast lane shed by a standard flood");
        stop.store(true, Ordering::Relaxed);
    });
}

#[test]
fn the_async_fast_lane_works() {
    let rt = tokio::runtime::Builder::new_current_thread().enable_time().build().unwrap();
    rt.block_on(async {
        let lanes = LanedPad::new(std_cfg(), fast_cfg()).unwrap();
        let t = Instant::now();
        lanes.fast().pad_async(|| async {}).await.unwrap();
        assert!(t.elapsed() >= ms(2));
        let r = lanes
            .fast()
            .pad_async(|| async { tokio::time::sleep(ms(6)).await })
            .await;
        assert_eq!(r.unwrap_err(), Trip::Overrun);
        assert_eq!(lanes.fast_overruns(), 1);
    });
}

// ---------------------------------------------------------------------
// A timing test per lane. Classes: two different cheap operations (a short
// and a longer busy loop). Debug-build, small n, regression guard only; the
// released numbers come from the verify example.
// ---------------------------------------------------------------------

const N_PER_CLASS: usize = 3_000;
const CROP_LINE: f64 = 10.0;

fn cheap_op(iters: u32) -> u32 {
    let mut x = 0u32;
    for i in 0..iters {
        x = std::hint::black_box(x.wrapping_add(i));
    }
    x
}

fn cfg() -> MeasureConfig {
    MeasureConfig {
        warmup: 300,
        seed: 0x1a4e_5001,
        ..MeasureConfig::with_samples(2 * N_PER_CLASS)
    }
}

fn max_first_order(r: &Report) -> f64 {
    let mut m = r.t_raw.map_or(0.0, f64::abs);
    for c in &r.cropped {
        if let Some(t) = c.t {
            m = m.max(t.abs());
        }
    }
    m
}

fn assert_lane_hides_cost(name: &str, run: impl Fn(u32) -> u32) {
    let prepare = |c: Class, _: &mut stack_anc_harness::SplitMix64| match c {
        Class::A => 50u32,
        Class::B => 1_500u32,
    };
    // Calibration: the bare operations differ measurably.
    let bare = measure_pair(&cfg(), prepare, |n| cheap_op(*n)).unwrap();
    assert!(
        max_first_order(&bare) > T_THRESHOLD,
        "{name}: calibration failed, bare operations not distinguishable: {bare:?}"
    );
    let padded = measure_pair(&cfg(), prepare, |n| run(*n)).unwrap();
    let t_raw = padded.t_raw.unwrap().abs();
    let t2 = padded.t_second_order.unwrap().abs();
    let crop_max = padded
        .cropped
        .iter()
        .filter_map(|c| c.t)
        .fold(0.0f64, |m, t| m.max(t.abs()));
    println!("{name}: t_raw {t_raw:.2} t2 {t2:.2} crop {crop_max:.2}");
    assert!(t_raw < T_THRESHOLD, "{name}: first-order leak: {padded:?}");
    assert!(t2 < T_THRESHOLD, "{name}: second-order leak: {padded:?}");
    assert!(crop_max < CROP_LINE, "{name}: cropped leak: {padded:?}");
}

#[test]
fn the_fast_lane_hides_the_cost_of_cheap_operations() {
    let lanes = LanedPad::new(
        CeilingConfig {
            mode: WaitMode::Spin,
            spin_budget: SpinBudgetConfig::Unlimited,
            ..CeilingConfig::new(Duration::from_micros(1_000))
        },
        CeilingConfig {
            mode: WaitMode::Spin,
            spin_budget: SpinBudgetConfig::Unlimited,
            hard_ceiling_buckets: 1,
            ..CeilingConfig::new(Duration::from_micros(250))
        },
    )
    .unwrap();
    assert_lane_hides_cost("fast lane", |n| lanes.fast().pad(|| cheap_op(n)).map(|p| p.value).unwrap_or(0));
    // A debug build on a shared machine can be preempted past a 250 us
    // ceiling now and then; a real mislabel would overrun nearly every time.
    assert!(lanes.fast_overruns() * 100 < 2 * N_PER_CLASS as u64, "overruns {}", lanes.fast_overruns());
}

#[test]
fn the_standard_lane_hides_the_cost_of_cheap_operations() {
    let lanes = LanedPad::new(
        CeilingConfig {
            mode: WaitMode::Spin,
            spin_budget: SpinBudgetConfig::Unlimited,
            ..CeilingConfig::new(Duration::from_micros(1_000))
        },
        CeilingConfig {
            mode: WaitMode::Spin,
            spin_budget: SpinBudgetConfig::Unlimited,
            hard_ceiling_buckets: 1,
            ..CeilingConfig::new(Duration::from_micros(250))
        },
    )
    .unwrap();
    assert_lane_hides_cost("standard lane", |n| lanes.standard().pad(|| cheap_op(n)).map(|p| p.value).unwrap_or(0));
}
