//! Red-team tests for tack-anc-ceiling (ANC strategy 1).
//!
//! Each test asserts the SAFE behaviour, so a test FAILS while the weakness
//! it targets exists. Tests named `rt0x_` target a suspected weakness;
//! tests named `rt1x_` probe a claim that is expected to hold.
//!
//! All keys and secrets here are test fixtures.
#![allow(clippy::unwrap_used, clippy::panic, clippy::expect_used)]

mod common;

use common::{median, BackwardsOnce};
use metrics_util::debugging::{DebugValue, DebuggingRecorder};
use std::collections::BTreeSet;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tack_anc_ceiling::config::{MAX_CEILING, MAX_INPUT_LEN_LIMIT};
use tack_anc_ceiling::telemetry::names;
use tack_anc_ceiling::{
    bucket_offset, release_bucket, CeilingConfig, CeilingPad, Clock, GateOutcome,
    SpinBudgetConfig, Trip, WaitMode,
};

fn cfg(ceiling: Duration, mode: WaitMode) -> CeilingConfig {
    CeilingConfig {
        mode,
        spin_budget: SpinBudgetConfig::Unlimited,
        ..CeilingConfig::new(ceiling)
    }
}

/// A value whose destructor costs `self.0`. Stands in for a
/// secret-dependent destructor (for example a buffer whose size, or a
/// cache whose population, depends on how far a comparison got).
struct CostlyDrop(Duration);
impl Drop for CostlyDrop {
    fn drop(&mut self) {
        if !self.0.is_zero() {
            std::thread::sleep(self.0);
        }
    }
}

/// A clock that never advances.
#[derive(Debug)]
struct Frozen(Instant);
impl Clock for Frozen {
    fn now(&self) -> Instant {
        self.0
    }
}

// ---------------------------------------------------------------------
// rt01: blocking API, discarded value dropped inside caller-visible time.
// ---------------------------------------------------------------------

/// Claim: "Only then: drop any discarded value ... so its drop cost cannot
/// land inside the window." The internal `observed` is read before the
/// drop, but the CALLER sees the time at which `pad` returns, and the
/// discarded value is dropped before that. A secret-dependent destructor
/// on a hard-overrun value therefore shifts the RETRY reply time.
#[test]
fn rt01_blocking_discarded_value_drop_cost_not_visible_to_caller() {
    let ceiling = Duration::from_millis(2);
    let pad = CeilingPad::new(CeilingConfig {
        hard_ceiling_buckets: 1,
        ..cfg(ceiling, WaitMode::Spin)
    })
    .unwrap();
    let mut a = Vec::new();
    let mut b = Vec::new();
    for i in 0..20 {
        for (drop_cost, out) in [(Duration::ZERO, &mut a), (Duration::from_millis(8), &mut b)] {
            let t0 = Instant::now();
            let r = pad.pad(|| {
                // Past the hard ceiling (k = 2 > 1): the value is discarded.
                std::thread::sleep(Duration::from_micros(2_600));
                CostlyDrop(drop_cost)
            });
            let ext = t0.elapsed();
            assert!(matches!(r, Err(Trip::Overrun)), "iteration {i}");
            out.push(ext);
        }
    }
    let (ma, mb) = (median(&a), median(&b));
    let diff = mb.abs_diff(ma);
    println!("rt01 caller-observed RETRY median: cheap drop {ma:?}, costly drop {mb:?}, diff {diff:?}");
    assert!(
        diff < Duration::from_millis(1),
        "destructor cost of a discarded value leaks into the caller-observed RETRY time: \
         cheap {ma:?} vs costly {mb:?}"
    );
}

// ---------------------------------------------------------------------
// rt02: async API, cancelled future dropped inside caller-visible time.
// ---------------------------------------------------------------------

/// Claim: "The cancelled future stays pinned until after release, so its
/// drop cost cannot land inside the window." The pinned future drops when
/// `run_async` returns, which is before `pad_async` returns to the caller.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rt02_async_cancelled_future_drop_cost_not_visible_to_caller() {
    let ceiling = Duration::from_millis(3);
    let pad = CeilingPad::new(CeilingConfig {
        hard_ceiling_buckets: 1,
        ..cfg(ceiling, WaitMode::Sleep)
    })
    .unwrap();
    let mut a = Vec::new();
    let mut b = Vec::new();
    for _ in 0..15 {
        for (drop_cost, out) in [(Duration::ZERO, &mut a), (Duration::from_millis(8), &mut b)] {
            let t0 = Instant::now();
            let r = pad
                .pad_async(|| async move {
                    let _state = CostlyDrop(drop_cost);
                    std::future::pending::<()>().await;
                })
                .await;
            let ext = t0.elapsed();
            assert_eq!(r, Err(Trip::Overrun));
            out.push(ext);
        }
    }
    let (ma, mb) = (median(&a), median(&b));
    let diff = mb.abs_diff(ma);
    println!("rt02 caller-observed async RETRY median: cheap drop {ma:?}, costly drop {mb:?}, diff {diff:?}");
    assert!(
        diff < Duration::from_millis(1),
        "drop cost of the cancelled future leaks into the caller-observed RETRY time: \
         cheap {ma:?} vs costly {mb:?}"
    );
}

// ---------------------------------------------------------------------
// rt03: blocking hard-overrun RETRY time encodes the work time.
// ---------------------------------------------------------------------

/// Claim: "overrun buckets leak up to log2(H+1) bits per overrun". With
/// H = 1 that is at most 1 bit, so at most 2 distinguishable release
/// times. In the blocking API a hard-overrun RETRY is released at the next
/// ceiling multiple after completion, for any k, so the release time
/// tracks the work time with no cap.
#[test]
fn rt03_blocking_hard_overrun_release_time_bounded_to_h_plus_1_values() {
    let ceiling = Duration::from_millis(1);
    let pad = CeilingPad::new(CeilingConfig {
        hard_ceiling_buckets: 1,
        ..cfg(ceiling, WaitMode::Spin)
    })
    .unwrap();
    let mut buckets_seen = BTreeSet::new();
    for work_us in [1_500u64, 2_500, 3_500, 4_500, 5_500, 6_500, 7_500, 8_500] {
        let t0 = Instant::now();
        let r = pad.pad(|| std::thread::sleep(Duration::from_micros(work_us)));
        let ext = t0.elapsed();
        assert_eq!(r, Err(Trip::Overrun));
        // Round the caller-observed release to the nearest whole ceiling.
        let k = (ext.as_micros() + 500) / 1_000;
        println!("rt03 work {work_us} us -> RETRY released at {ext:?} (bucket {k})");
        buckets_seen.insert(k);
    }
    assert!(
        buckets_seen.len() <= 2,
        "hard-overrun RETRY release time takes {} distinct values {:?}; the documented \
         bound log2(H+1) = 1 bit allows at most 2",
        buckets_seen.len(),
        buckets_seen
    );
}

// ---------------------------------------------------------------------
// rt04: async hard overrun is not always released at the hard ceiling.
// ---------------------------------------------------------------------

/// Claim: "The async API ... is released at the hard ceiling (plus timer
/// lateness)". `timeout_at` rides tokio's 1 ms timer wheel and polls the
/// inner future first, so an operation that finishes after the hard
/// deadline but before the timer fires returns Ok, gets k > H, and its
/// RETRY is released at k * ceiling: the work time again. With the claimed
/// behaviour the RETRY time would depend on the timer only, identically
/// for both classes.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rt04_async_hard_overrun_release_independent_of_work_time() {
    let ceiling = Duration::from_micros(100);
    let pad = CeilingPad::new(CeilingConfig {
        hard_ceiling_buckets: 1,
        ..cfg(ceiling, WaitMode::Spin)
    })
    .unwrap();
    async fn yielding_work(d: Duration) {
        let t = Instant::now();
        while t.elapsed() < d {
            tokio::task::yield_now().await;
        }
    }
    let mut a = Vec::new();
    let mut b = Vec::new();
    for _ in 0..150 {
        for (work, out) in [
            (Duration::from_micros(300), &mut a),
            (Duration::from_micros(700), &mut b),
        ] {
            let r = pad.pad_async(|| yielding_work(work)).await;
            assert_eq!(r, Err(Trip::Overrun));
            // Measure what the caller sees with a fresh admission each time.
            let t0 = Instant::now();
            let r = pad.pad_async(|| yielding_work(work)).await;
            let ext = t0.elapsed();
            assert_eq!(r, Err(Trip::Overrun));
            out.push(ext.as_nanos() as f64);
        }
    }
    let mean = |v: &[f64]| v.iter().sum::<f64>() / v.len() as f64;
    let (ma, mb) = (mean(&a) / 1e3, mean(&b) / 1e3);
    let max = |v: &[f64]| v.iter().cloned().fold(0.0, f64::max) / 1e3;
    println!(
        "rt04 async RETRY mean release: 300 us work {ma:.1} us (max {:.1}), \
         700 us work {mb:.1} us (max {:.1}); hard ceiling 100 us",
        max(&a),
        max(&b)
    );
    assert!(
        (mb - ma).abs() < 100.0,
        "async hard-overrun RETRY time depends on the work time: {ma:.1} us vs {mb:.1} us"
    );
}

// ---------------------------------------------------------------------
// rt05: a frozen clock is detected only after many multiples of the ceiling.
// ---------------------------------------------------------------------

/// Claim: "Every wait loop is bounded, so a frozen clock trips instead of
/// hanging." Bounded yes, but the spin cap is an ITERATION count equal to
/// the remaining nanoseconds (each iteration costs tens of ns), and the
/// sleep cap is 64 full sleeps. The slot and the thread are held for many
/// times the ceiling before the halt. Safe: trip within 3 ceilings + 20 ms.
#[test]
fn rt05_frozen_clock_trips_within_small_multiple_of_ceiling() {
    let ceiling = Duration::from_millis(5);
    let limit = ceiling * 3 + Duration::from_millis(20);
    let mut worst = Vec::new();
    for mode in [WaitMode::Spin, WaitMode::Sleep, WaitMode::Hybrid] {
        let pad = CeilingPad::with_clock(cfg(ceiling, mode), Frozen(Instant::now())).unwrap();
        let t0 = Instant::now();
        let r = pad.pad(|| 1u8);
        let ext = t0.elapsed();
        assert_eq!(r, Err(Trip::ClockFailure), "{mode:?}");
        println!("rt05 {mode:?}: frozen clock tripped after {ext:?} (ceiling {ceiling:?})");
        worst.push((mode, ext));
    }
    for (mode, ext) in worst {
        assert!(
            ext <= limit,
            "{mode:?}: frozen clock held the request {ext:?}, {:.0}x the ceiling",
            ext.as_secs_f64() / ceiling.as_secs_f64()
        );
    }
}

// ---------------------------------------------------------------------
// rt06: shared halted gauge cleared by another pad's reset.
// ---------------------------------------------------------------------

/// Every pad writes the same series `tack_anc_halted{strategy="ceiling"}`.
/// A reset of a healthy pad sets it to 0 while another pad is still
/// halted, which silences the critical TackAncCeilingHalted alert.
#[test]
fn rt06_reset_of_other_pad_does_not_clear_halted_signal() {
    let recorder = DebuggingRecorder::new();
    let snap = recorder.snapshotter();
    metrics::with_local_recorder(&recorder, || {
        let halted_pad = CeilingPad::with_clock(
            cfg(Duration::from_micros(200), WaitMode::Spin),
            BackwardsOnce::new(2),
        )
        .unwrap();
        assert_eq!(halted_pad.pad(|| 1u8), Err(Trip::ClockFailure));
        assert!(halted_pad.is_halted());
        let healthy = CeilingPad::new(cfg(Duration::from_micros(200), WaitMode::Spin)).unwrap();
        healthy.reset();
        assert!(halted_pad.is_halted(), "the first pad is still halted");
    });
    let gauge = snap
        .snapshot()
        .into_vec()
        .into_iter()
        .find(|(k, _, _, _)| k.key().name() == names::HALTED)
        .map(|(_, _, _, v)| v);
    println!("rt06 tack_anc_halted after other pad's reset: {gauge:?}");
    match gauge {
        Some(DebugValue::Gauge(g)) => assert!(
            g.into_inner() > 0.0,
            "halted gauge reads {} while a pad is halted",
            g.into_inner()
        ),
        other => panic!("halted gauge missing: {other:?}"),
    }
}

// ---------------------------------------------------------------------
// rt07: async API panics across the request boundary on a runtime
// without the time driver.
// ---------------------------------------------------------------------

/// Kernel convention 1: never panic across a request boundary. The docs
/// make the time driver a precondition; this checks what actually happens.
#[test]
fn rt07_async_without_time_driver_returns_verdict_not_panic() {
    let rt = tokio::runtime::Builder::new_current_thread().build().unwrap();
    let pad = CeilingPad::new(cfg(Duration::from_micros(500), WaitMode::Sleep)).unwrap();
    let prev = std::panic::take_hook();
    std::panic::set_hook(Box::new(|_| {}));
    let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        rt.block_on(pad.pad_async(|| async { 1u8 }))
    }));
    std::panic::set_hook(prev);
    let panicked = r.is_err();
    println!(
        "rt07 pad_async on a runtime without the time driver: panicked = {panicked}; \
         slot freed = {}",
        pad.in_flight() == 0
    );
    assert!(!panicked, "pad_async panicked instead of returning a typed Trip");
}

// ---------------------------------------------------------------------
// rt08: a cancelled async request leaves no telemetry.
// ---------------------------------------------------------------------

/// A server drops the handler future when a client disconnects. The
/// request was admitted, took a slot and a spin charge, but no counter
/// records it, so a connect-and-abort flood is invisible in
/// tack_anc_requests_total and in the spin accounting.
#[test]
fn rt08_cancelled_async_request_is_counted() {
    let recorder = DebuggingRecorder::new();
    let snap = recorder.snapshotter();
    let pad = CeilingPad::new(CeilingConfig {
        mode: WaitMode::Hybrid,
        ..CeilingConfig::new(Duration::from_millis(20))
    })
    .unwrap();
    let before = pad.spin_budget_remaining().unwrap();
    metrics::with_local_recorder(&recorder, || {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            for _ in 0..5 {
                let fut = pad.pad_async(std::future::pending::<u8>);
                let r = tokio::time::timeout(Duration::from_millis(2), fut).await;
                assert!(r.is_err(), "outer timeout cancels the pad future");
            }
        });
    });
    let after = pad.spin_budget_remaining().unwrap();
    let total: u64 = snap
        .snapshot()
        .into_vec()
        .into_iter()
        .filter(|(k, _, _, _)| k.key().name() == names::REQUESTS_TOTAL)
        .map(|(_, _, _, v)| match v {
            DebugValue::Counter(c) => c,
            _ => 0,
        })
        .sum();
    println!(
        "rt08 5 cancelled requests: tack_anc_requests_total = {total}; spin budget {before:?} -> {after:?}; in_flight {}",
        pad.in_flight()
    );
    assert_eq!(pad.in_flight(), 0);
    assert!(
        total >= 5,
        "cancelled requests consumed slots and spin budget but were not counted (total {total})"
    );
}

// ---------------------------------------------------------------------
// Shared flood for rt09 and rt16.
// ---------------------------------------------------------------------

struct FloodResult {
    wall: Duration,
    spun_requests: u64,
    slept_requests: u64,
    shed: u64,
    charge: Duration,
    rate: Duration,
    burst: Duration,
}

fn spin_flood() -> FloodResult {
    let ceiling = Duration::from_micros(300);
    let rate = Duration::from_millis(250);
    let burst = Duration::from_millis(50);
    let pad = Arc::new(
        CeilingPad::new(CeilingConfig {
            mode: WaitMode::Spin,
            spin_budget: SpinBudgetConfig::Limited {
                cpu_per_second: rate,
                burst,
            },
            max_concurrent: 4,
            ..CeilingConfig::new(ceiling)
        })
        .unwrap(),
    );
    let spun = Arc::new(AtomicU64::new(0));
    let slept = Arc::new(AtomicU64::new(0));
    let shed = Arc::new(AtomicU64::new(0));
    let stop = Arc::new(AtomicBool::new(false));
    let t0 = Instant::now();
    let handles: Vec<_> = (0..4)
        .map(|_| {
            let (pad, spun, slept, shed, stop) = (
                pad.clone(),
                spun.clone(),
                slept.clone(),
                shed.clone(),
                stop.clone(),
            );
            std::thread::spawn(move || {
                while !stop.load(Ordering::Relaxed) {
                    match pad.pad(|| 0u8) {
                        Ok(p) if p.release.mode == WaitMode::Spin => {
                            spun.fetch_add(1, Ordering::Relaxed);
                        }
                        Ok(_) => {
                            slept.fetch_add(1, Ordering::Relaxed);
                        }
                        Err(_) => {
                            shed.fetch_add(1, Ordering::Relaxed);
                            std::thread::sleep(Duration::from_micros(100));
                        }
                    }
                }
            })
        })
        .collect();
    std::thread::sleep(Duration::from_millis(400));
    stop.store(true, Ordering::Relaxed);
    for h in handles {
        h.join().unwrap();
    }
    FloodResult {
        wall: t0.elapsed(),
        spun_requests: spun.load(Ordering::Relaxed),
        slept_requests: slept.load(Ordering::Relaxed),
        shed: shed.load(Ordering::Relaxed),
        charge: ceiling,
        rate,
        burst,
    }
}

// ---------------------------------------------------------------------
// rt09: TackAncCeilingSpinOverBudget alert semantics.
// ---------------------------------------------------------------------

/// Claim on the alert: reserved spin per second "is bounded by
/// construction [by cpu_per_second], so firing means a misconfiguration".
/// The true bound over a window W is cpu_per_second * W + burst, so at
/// saturation the reserved rate exceeds cpu_per_second and the alert fires
/// on a correctly configured pad.
///
/// Corrected after the fix: the original assertion (reserved <=
/// cpu_per_second * W) is not a property of any token bucket that holds a
/// burst, and the finding's own fix was to change the alert threshold. The
/// test now asserts that the alert threshold the crate publishes
/// (`spin_over_budget_threshold`) is not crossed by a correctly configured
/// pad at saturation over the measured window.
#[test]
fn rt09_reserved_spin_rate_never_exceeds_cpu_per_second() {
    let f = spin_flood();
    let reserved = f.charge * u32::try_from(f.spun_requests).unwrap();
    let threshold = tack_anc_ceiling::telemetry::spin_over_budget_threshold(
        SpinBudgetConfig::Limited {
            cpu_per_second: f.rate,
            burst: f.burst,
        },
        f.wall,
    )
    .unwrap();
    let observed_cores = reserved.as_secs_f64() / f.wall.as_secs_f64();
    println!(
        "rt09 wall {:?}: reserved spin {reserved:?} = {observed_cores:.3} cores vs alert \
         threshold {threshold:.3} cores (spun {}, slept {}, shed {})",
        f.wall, f.spun_requests, f.slept_requests, f.shed
    );
    assert!(
        observed_cores <= threshold,
        "reserved spin {observed_cores:.3} cores exceeds the SpinOverBudget threshold \
         {threshold:.3}: the alert fires on a correctly configured pad at saturation"
    );
}

/// Held check: the anti-DoS bound the budget really gives is
/// cpu_per_second * W + burst, whatever the flood does.
#[test]
fn rt16_spin_cpu_bounded_by_rate_plus_burst_under_flood() {
    let f = spin_flood();
    let reserved = f.charge * u32::try_from(f.spun_requests).unwrap();
    let bound = f.rate.mul_f64(f.wall.as_secs_f64()) + f.burst;
    println!(
        "rt16 wall {:?}: reserved spin {reserved:?} vs rate*W + burst = {bound:?} \
         (spun {}, slept {}, shed {})",
        f.wall, f.spun_requests, f.slept_requests, f.shed
    );
    assert!(f.slept_requests > 0, "flood must exhaust the budget");
    assert!(reserved <= bound, "spin exceeded the budget bound");
}

// ---------------------------------------------------------------------
// rt10: secret-dependent overrun changes another client's shed verdict.
// ---------------------------------------------------------------------

/// Attack class "shedding decisions that depend on a secret". The shed
/// check itself reads only the slot counter, but an overrun holds its slot
/// until k * ceiling, so a second observer probing at 1.5 ceilings is shed
/// or served depending on whether the victim's secret work overran.
#[test]
fn rt10_probe_shed_verdict_independent_of_victim_secret() {
    let ceiling = Duration::from_millis(4);
    let pad = CeilingPad::new(CeilingConfig {
        max_concurrent: 1,
        ..cfg(ceiling, WaitMode::Sleep)
    })
    .unwrap();
    let mut verdicts = Vec::new();
    for victim_work in [Duration::ZERO, Duration::from_millis(5)] {
        let started = AtomicBool::new(false);
        let probe = std::thread::scope(|s| {
            let v = s.spawn(|| {
                pad.pad(|| {
                    started.store(true, Ordering::SeqCst);
                    std::thread::sleep(victim_work);
                })
            });
            while !started.load(Ordering::SeqCst) {
                std::hint::spin_loop();
            }
            // 1.5 ceilings after the victim was admitted.
            std::thread::sleep(ceiling.mul_f64(1.5));
            let probe = pad.pad(|| ()).map(|_| ());
            let _ = v.join().unwrap();
            probe
        });
        println!("rt10 victim work {victim_work:?}: probe verdict {probe:?}");
        verdicts.push(probe);
    }
    assert_eq!(
        verdicts[0], verdicts[1],
        "a third party's shed verdict reveals whether the victim's work overran"
    );
}

// ---------------------------------------------------------------------
// Held probes.
// ---------------------------------------------------------------------

/// Fail-open and early release: across modes, overrun policies and work
/// times, PASS only when k <= H, never before the ceiling (internal and
/// caller view), and every non-PASS is a typed RETRY.
#[test]
fn rt11_no_fail_open_and_no_early_release() {
    let ceiling = Duration::from_millis(1);
    for mode in [WaitMode::Sleep, WaitMode::Spin, WaitMode::Hybrid] {
        for h in [1u32, 2, 3] {
            let pad = CeilingPad::new(CeilingConfig {
                hard_ceiling_buckets: h,
                ..cfg(ceiling, mode)
            })
            .unwrap();
            for work_us in [0u64, 200, 500, 1_300, 2_300, 3_300] {
                let t0 = Instant::now();
                let r = pad.pad(|| std::thread::sleep(Duration::from_micros(work_us)));
                let ext = t0.elapsed();
                assert!(ext >= ceiling, "{mode:?} h={h} work={work_us}: early {ext:?}");
                match r {
                    Ok(p) => {
                        assert_eq!(p.gate_outcome(), GateOutcome::Pass);
                        assert!(p.release.buckets <= u64::from(h), "PASS past the hard ceiling");
                        assert!(p.release.observed >= ceiling * u32::try_from(p.release.buckets).unwrap());
                    }
                    Err(t) => {
                        assert_eq!(t, Trip::Overrun);
                        assert_eq!(t.gate_outcome(), GateOutcome::Retry);
                        assert!(work_us >= 500, "fast work (well inside the ceiling) was refused");
                    }
                }
            }
        }
    }
}

/// Panics and integer confusion from extreme values in public functions
/// and configuration.
#[test]
fn rt12_extreme_values_do_not_panic() {
    let r = std::panic::catch_unwind(|| {
        for c in [Duration::ZERO, Duration::from_nanos(1), MAX_CEILING, Duration::MAX] {
            for e in [Duration::ZERO, Duration::from_nanos(1), Duration::MAX] {
                let k = release_bucket(e, c);
                assert!(k >= 1);
                let _ = bucket_offset(c, k);
                let _ = bucket_offset(c, u64::MAX);
            }
        }
        let bad = [
            CeilingConfig::new(Duration::MAX),
            CeilingConfig::new(Duration::ZERO),
            CeilingConfig {
                spin_tail: Duration::MAX,
                async_spin_tail: Duration::MAX,
                ..CeilingConfig::new(MAX_CEILING)
            },
            CeilingConfig {
                hard_ceiling_buckets: u32::MAX,
                ..CeilingConfig::new(MAX_CEILING)
            },
            CeilingConfig {
                max_concurrent: usize::MAX,
                ..CeilingConfig::new(MAX_CEILING)
            },
            CeilingConfig {
                max_input_len: usize::MAX,
                ..CeilingConfig::new(MAX_CEILING)
            },
            CeilingConfig {
                spin_budget: SpinBudgetConfig::Limited {
                    cpu_per_second: Duration::MAX,
                    burst: Duration::MAX,
                },
                ..CeilingConfig::new(MAX_CEILING)
            },
        ];
        for c in bad {
            assert!(CeilingPad::new(c.clone()).is_err(), "accepted {c:?}");
        }
        // Largest accepted config still constructs and pads.
        let pad = CeilingPad::new(CeilingConfig {
            mode: WaitMode::Sleep,
            max_input_len: MAX_INPUT_LEN_LIMIT,
            hard_ceiling_buckets: 1_024,
            ..CeilingConfig::new(Duration::from_micros(1))
        })
        .unwrap();
        let _ = pad.pad_input(&[0u8; 16], |x| x.len());
    });
    assert!(r.is_ok(), "a public function panicked on an extreme value");
}

/// Collects every field of every span and event at every level.
#[derive(Default)]
struct Capture {
    lines: Mutex<Vec<String>>,
    next: AtomicU64,
}
struct Visit<'a>(&'a mut String);
impl tracing::field::Visit for Visit<'_> {
    fn record_debug(&mut self, f: &tracing::field::Field, v: &dyn std::fmt::Debug) {
        self.0.push_str(&format!(" {}={:?}", f.name(), v));
    }
    fn record_str(&mut self, f: &tracing::field::Field, v: &str) {
        self.0.push_str(&format!(" {}={}", f.name(), v));
    }
}
impl tracing::Subscriber for Capture {
    fn enabled(&self, _: &tracing::Metadata<'_>) -> bool {
        true
    }
    fn max_level_hint(&self) -> Option<tracing::level_filters::LevelFilter> {
        Some(tracing::level_filters::LevelFilter::TRACE)
    }
    fn new_span(&self, a: &tracing::span::Attributes<'_>) -> tracing::span::Id {
        let mut s = format!("span {}", a.metadata().name());
        a.record(&mut Visit(&mut s));
        self.lines.lock().unwrap().push(s);
        tracing::span::Id::from_u64(self.next.fetch_add(1, Ordering::Relaxed) + 1)
    }
    fn record(&self, _: &tracing::span::Id, v: &tracing::span::Record<'_>) {
        let mut s = String::from("record");
        v.record(&mut Visit(&mut s));
        self.lines.lock().unwrap().push(s);
    }
    fn record_follows_from(&self, _: &tracing::span::Id, _: &tracing::span::Id) {}
    fn event(&self, e: &tracing::Event<'_>) {
        let mut s = format!("event {}", e.metadata().level());
        e.record(&mut Visit(&mut s));
        self.lines.lock().unwrap().push(s);
    }
    fn enter(&self, _: &tracing::span::Id) {}
    fn exit(&self, _: &tracing::span::Id) {}
}

/// Telemetry abuse: raw input never logged, log injection impossible,
/// digest full length, oversized input not hashed.
#[test]
fn rt13_raw_input_never_logged_and_digest_full() {
    let cap = Arc::new(Capture::default());
    let dispatch = tracing::Dispatch::from(cap.clone());
    let marker = b"RAWSECRETMARKER\nlevel=ERROR fake=\"injected\"";
    tracing::dispatcher::with_default(&dispatch, || {
        let pad = CeilingPad::new(CeilingConfig {
            max_input_len: 64,
            ..cfg(Duration::from_micros(300), WaitMode::Spin)
        })
        .unwrap();
        let _ = pad.pad_input(marker, |x| x.len());
        let big = [b'Z'; 65];
        assert_eq!(pad.pad_input(&big, |x| x.len()), Err(Trip::InputTooLarge));
        let _ = pad.pad_input(&[0xff, 0xfe, 0x00, b'\n'], |x| x.len());
    });
    let lines = cap.lines.lock().unwrap().clone();
    for l in &lines {
        println!("rt13 log: {l}");
        assert!(!l.contains("RAWSECRETMARKER"), "raw input logged: {l}");
        assert!(!l.contains("injected"), "attacker text reached the log: {l}");
        assert!(!l.contains("ZZZZ"), "oversized raw input logged: {l}");
    }
    let digest = tack_anc_ceiling::telemetry::sha256_hex(marker);
    assert_eq!(digest.len(), 64);
    assert!(lines.iter().any(|l| l.contains(&digest)), "full digest not logged");
    assert!(lines
        .iter()
        .any(|l| l.contains("input_len=65") && l.contains("not computed")));
}

/// Label cardinality: hostile inputs and every outcome produce only
/// closed-set label values and a bounded number of series.
#[test]
fn rt14_metric_labels_closed_under_hostile_input() {
    let recorder = DebuggingRecorder::new();
    let snap = recorder.snapshotter();
    metrics::with_local_recorder(&recorder, || {
        let pad = CeilingPad::with_clock(
            CeilingConfig {
                max_input_len: 8,
                hard_ceiling_buckets: 1,
                ..cfg(Duration::from_micros(500), WaitMode::Hybrid)
            },
            BackwardsOnce::new(40),
        )
        .unwrap();
        for i in 0..40u32 {
            let input: Vec<u8> = format!("in{i}\n{{label=\"x{i}\"}}").into_bytes();
            let _ = pad.pad_input(&input, |x| x.len());
            let _ = pad.pad_input(&input[..4], |x| {
                if i % 3 == 0 {
                    std::thread::sleep(Duration::from_micros(1_200));
                }
                x.len()
            });
        }
        pad.reset();
    });
    let allowed: BTreeSet<&str> = [
        "ceiling",
        "pass",
        "retry",
        "terminal_breach",
        "slots_full",
        "input_too_large",
        "halted",
        "released",
        "spin",
        "hybrid",
    ]
    .into_iter()
    .collect();
    let entries = snap.snapshot().into_vec();
    for (k, _, _, _) in &entries {
        for l in k.key().labels() {
            assert!(allowed.contains(l.value()), "open label {}={}", l.key(), l.value());
        }
    }
    println!("rt14 series emitted: {}", entries.len());
    assert!(entries.len() <= 20, "series count {}", entries.len());
}

/// Budget-exhaustion leak: for a sequential client, when the next Spin is
/// granted must not depend on how long the secret work took. Single runs
/// differ by Sleep wake-up jitter (the refill is driven by admission
/// times), so this compares the mean position of the third Spin grant over
/// many interleaved trials per class.
#[test]
fn rt15_budget_fallback_sequence_independent_of_work_time() {
    let ceiling = Duration::from_millis(2);
    let third_spin = |work: Duration| -> f64 {
        let pad = CeilingPad::new(CeilingConfig {
            mode: WaitMode::Spin,
            spin_budget: SpinBudgetConfig::Limited {
                cpu_per_second: Duration::from_millis(100),
                burst: Duration::from_millis(5),
            },
            ..CeilingConfig::new(ceiling)
        })
        .unwrap();
        let mut spins = 0;
        for i in 0..16 {
            if pad.pad(|| std::thread::sleep(work)).unwrap().release.mode == WaitMode::Spin {
                spins += 1;
                if spins == 3 {
                    return i as f64;
                }
            }
        }
        16.0
    };
    let (mut a, mut b) = (Vec::new(), Vec::new());
    for _ in 0..30 {
        a.push(third_spin(Duration::ZERO));
        b.push(third_spin(Duration::from_micros(1_500)));
    }
    let mean = |v: &[f64]| v.iter().sum::<f64>() / v.len() as f64;
    let (ma, mb) = (mean(&a), mean(&b));
    println!("rt15 mean index of the third Spin grant: fast work {ma:.2}, slow work {mb:.2}");
    println!("rt15 fast {a:?}");
    println!("rt15 slow {b:?}");
    assert!(
        (ma - mb).abs() < 1.0,
        "fallback pattern depends on work time: {ma:.2} vs {mb:.2}"
    );
}

/// Concurrency: slot counter never exceeds the cap, returns to zero, and
/// the budget never exceeds its burst, under a mixed hammer.
#[test]
fn rt17_concurrent_hammer_keeps_invariants() {
    let pad = Arc::new(
        CeilingPad::new(CeilingConfig {
            max_concurrent: 3,
            mode: WaitMode::Hybrid,
            spin_tail: Duration::from_micros(50),
            spin_budget: SpinBudgetConfig::Limited {
                cpu_per_second: Duration::from_millis(10),
                burst: Duration::from_micros(200),
            },
            ..CeilingConfig::new(Duration::from_micros(200))
        })
        .unwrap(),
    );
    let max_seen = Arc::new(AtomicUsize::new(0));
    let handles: Vec<_> = (0..8)
        .map(|t| {
            let (pad, max_seen) = (pad.clone(), max_seen.clone());
            std::thread::spawn(move || {
                for i in 0..300 {
                    let r = pad.pad(|| {
                        max_seen.fetch_max(pad.in_flight(), Ordering::Relaxed);
                        if (i + t) % 7 == 0 {
                            std::thread::sleep(Duration::from_micros(300));
                        }
                    });
                    if let Err(t) = r {
                        assert!(matches!(t, Trip::SlotsFull | Trip::Overrun), "{t:?}");
                    }
                    assert!(pad.spin_budget_remaining().unwrap() <= Duration::from_micros(200));
                }
            })
        })
        .collect();
    for h in handles {
        h.join().unwrap();
    }
    println!("rt17 max in flight {}", max_seen.load(Ordering::Relaxed));
    assert!(max_seen.load(Ordering::Relaxed) <= 3);
    assert_eq!(pad.in_flight(), 0);
    assert!(!pad.is_halted());
}
