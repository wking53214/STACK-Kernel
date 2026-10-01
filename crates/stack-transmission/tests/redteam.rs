//! Independent red-team tests for stack-transmission.
//!
//! Each test asserts the SAFE behaviour. A failing test means the weakness
//! named in its doc comment exists. Test keys and configs here are test
//! fixtures, not real key material.

// Test crate: helpers outside #[test] functions may unwrap and panic.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use std::collections::HashSet;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use common::{tx, wait_until, Mode};
use metrics::{
    Counter, Gauge, GaugeFn, Histogram, Key, KeyName, Metadata, Recorder, SharedString, Unit,
};
use metrics_util::debugging::{DebugValue, DebuggingRecorder};
use tack_transmission::telemetry as tm;
use tack_transmission::{GateOutcome, Reason, Resolution, Transmission, TransmissionConfig};

const SHORT: Duration = Duration::from_millis(20);
const LONG: Duration = Duration::from_secs(5);

// ---------------------------------------------------------------------------
// A telemetry backend that panics on one chosen gauge write. This models the
// "panicking telemetry backend" the crate names as its only poison source.
// ---------------------------------------------------------------------------

struct PanicGauge {
    trigger: f64,
    armed: Arc<AtomicBool>,
}

impl GaugeFn for PanicGauge {
    fn increment(&self, _: f64) {}
    fn decrement(&self, _: f64) {}
    fn set(&self, value: f64) {
        if value == self.trigger && self.armed.swap(false, Ordering::SeqCst) {
            panic!("test fixture: telemetry backend panics on gauge write");
        }
    }
}

struct PanicRecorder {
    target: &'static str,
    trigger: f64,
    armed: Arc<AtomicBool>,
}

impl Recorder for PanicRecorder {
    fn describe_counter(&self, _: KeyName, _: Option<Unit>, _: SharedString) {}
    fn describe_gauge(&self, _: KeyName, _: Option<Unit>, _: SharedString) {}
    fn describe_histogram(&self, _: KeyName, _: Option<Unit>, _: SharedString) {}
    fn register_counter(&self, _: &Key, _: &Metadata<'_>) -> Counter {
        Counter::noop()
    }
    fn register_gauge(&self, key: &Key, _: &Metadata<'_>) -> Gauge {
        if key.name() == self.target {
            Gauge::from_arc(Arc::new(PanicGauge {
                trigger: self.trigger,
                armed: Arc::clone(&self.armed),
            }))
        } else {
            Gauge::noop()
        }
    }
    fn register_histogram(&self, _: &Key, _: &Metadata<'_>) -> Histogram {
        Histogram::noop()
    }
}

fn panic_recorder(target: &'static str, trigger: f64) -> PanicRecorder {
    PanicRecorder {
        target,
        trigger,
        armed: Arc::new(AtomicBool::new(true)),
    }
}

/// Runs `f` with the panicking recorder installed on this thread and
/// returns whether it panicked.
fn run_with_panicking_backend<F: FnOnce()>(rec: &PanicRecorder, f: F) -> bool {
    metrics::with_local_recorder(rec, || catch_unwind(AssertUnwindSafe(f)).is_err())
}

type Row = (String, Vec<(String, String)>, DebugValue);

fn gauge(snap: &[Row], name: &str) -> Option<f64> {
    snap.iter()
        .filter(|(n, _, _)| n == name)
        .map(|(_, _, v)| match v {
            DebugValue::Gauge(g) => g.into_inner(),
            other => panic!("{name} is not a gauge: {other:?}"),
        })
        .next_back()
}

fn take(rec: &DebuggingRecorder) -> Vec<Row> {
    rec.snapshotter()
        .snapshot()
        .into_vec()
        .into_iter()
        .map(|(k, _, _, v)| {
            let key = k.key();
            let labels = key
                .labels()
                .map(|l| (l.key().to_string(), l.value().to_string()))
                .collect();
            (key.name().to_string(), labels, v)
        })
        .collect()
}

// ---------------------------------------------------------------------------
// A1-A3. State corruption after poison recovery.
// ---------------------------------------------------------------------------

/// A1. The telemetry backend panics while `shift()` holds the lock right
/// after pressing the clutch. Recovery must leave a working gearbox after
/// operator_reset: clutch up, engage admits, shift works. Weakness: the
/// clutch flag stays true forever, so every engage parks and times out and
/// every shift gets shift_in_progress, even after the operator reset.
#[test]
fn a1_poison_during_clutch_press_must_not_wedge_the_clutch() {
    let t = tx(TransmissionConfig::default());
    let rec = panic_recorder(tm::CLUTCH_PRESSED, 1.0);
    let panicked = run_with_panicking_backend(&rec, || {
        let _ = t.shift(Mode::for_epoch(1), SHORT);
    });
    assert!(panicked, "fixture: backend panic should reach the test");

    // Recovery happens on the next lock; the transmission halts (by design).
    let s = t.status();
    assert!(s.halted.is_some(), "poison should halt");
    assert!(t.operator_reset(), "operator reset should clear the halt");

    let s = t.status();
    assert!(
        !s.clutch_pressed,
        "clutch still pressed after poison recovery and operator reset: {s:?}"
    );
    let e = t.engage(SHORT);
    assert!(e.is_ok(), "engage after reset: {:?}", e.err());
    drop(e);
    let r = t.shift(Mode::for_epoch(1), SHORT);
    assert!(r.is_ok(), "shift after reset: {:?}", r.err().map(|x| x.trip()));
}

/// A2. The backend panics in `engage()` right after `in_flight += 1`, before
/// the guard exists. Weakness: the in-flight count is leaked by one, no
/// guard can ever release it, and every later shift rolls back with
/// drain_timeout. operator_reset does not repair it.
#[test]
fn a2_poison_during_engage_must_not_leak_in_flight() {
    let t = tx(TransmissionConfig::default());
    let rec = panic_recorder(tm::IN_FLIGHT, 1.0);
    let panicked = run_with_panicking_backend(&rec, || {
        let _ = t.engage(SHORT);
    });
    assert!(panicked, "fixture: backend panic should reach the test");
    let _ = t.status();
    t.operator_reset();

    let s = t.status();
    assert_eq!(s.in_flight, 0, "in-flight leaked with no guard alive: {s:?}");
    let r = t.shift(Mode::for_epoch(1), Duration::from_millis(50));
    assert!(r.is_ok(), "shift after reset: {:?}", r.err().map(|x| x.trip()));
}

/// A3. The backend panics while a parked engager bumps waiting_engagers.
/// Weakness: waiting_engagers is leaked; with max_waiting_engagers = 1 every
/// later clutch wait is refused with wait_queue_full although nobody waits.
#[test]
fn a3_poison_while_parking_must_not_leak_waiting_engagers() {
    let cfg = TransmissionConfig {
        max_waiting_engagers: 1,
        ..TransmissionConfig::default()
    };
    let t = tx(cfg);
    let guard = t.engage(SHORT).unwrap();
    let t2 = t.clone();
    let shifter = thread::spawn(move || t2.shift(Mode::for_epoch(1), Duration::from_millis(400)));
    wait_until("clutch pressed", || t.status().clutch_pressed);

    let rec = panic_recorder(tm::WAITING_ENGAGERS, 1.0);
    let panicked = run_with_panicking_backend(&rec, || {
        let _ = t.engage(SHORT);
    });
    assert!(panicked, "fixture: backend panic should reach the test");
    drop(guard);
    let _ = shifter.join().unwrap();
    t.operator_reset();

    let s = t.status();
    assert_eq!(s.waiting_engagers, 0, "waiting_engagers leaked: {s:?}");
}

// ---------------------------------------------------------------------------
// A4. Halt then reset during a drain.
// ---------------------------------------------------------------------------

/// A4. The builder claims a halt during a drain rolls the shift back. An
/// operator halts to stop a bad mode change, then resets to restore
/// traffic. Weakness: if the reset lands before the parked shifter wakes,
/// the shifter never sees the halt, keeps draining, and swaps the gear the
/// operator meant to stop.
#[test]
fn a4_halt_then_quick_reset_must_still_cancel_the_pending_shift() {
    let mut completed = 0;
    for _ in 0..20 {
        let t = tx(TransmissionConfig::default());
        let guard = t.engage(SHORT).unwrap();
        let t2 = t.clone();
        let shifter = thread::spawn(move || t2.shift(Mode::for_epoch(1), Duration::from_secs(2)));
        wait_until("clutch pressed", || t.status().clutch_pressed);
        assert!(t.operator_halt());
        assert!(t.operator_reset());
        drop(guard);
        if shifter.join().unwrap().is_ok() {
            completed += 1;
        }
    }
    assert_eq!(
        completed, 0,
        "{completed}/20 shifts that were in progress during an operator halt still swapped the gear"
    );
}

// ---------------------------------------------------------------------------
// A5. Telemetry masking: a second Transmission::new clears the halted gauge.
// ---------------------------------------------------------------------------

/// A5. `Transmission::new` writes the process-global gauges (halted,
/// in_flight, clutch_pressed, gear_epoch) to 0. Weakness: building any
/// second instance while the first is halted sets tack_transmission_halted
/// to 0 and silences the critical TackTransmissionHalted alert.
#[test]
fn a5_constructing_a_second_instance_must_not_clear_the_halt_gauge() {
    let rec = DebuggingRecorder::new();
    metrics::with_local_recorder(&rec, || {
        let a = tx(TransmissionConfig::default());
        let _held = a.engage(SHORT).unwrap();
        assert!(a.operator_halt());
        let _b = tx(TransmissionConfig::default());
        let snap = take(&rec);
        assert!(a.status().halted.is_some());
        assert_eq!(
            gauge(&snap, tm::HALTED),
            Some(1.0),
            "instance A is halted but the halted gauge reads 0 after B was built"
        );
        assert_eq!(
            gauge(&snap, tm::IN_FLIGHT),
            Some(1.0),
            "instance A has a guard out but the in_flight gauge reads 0"
        );
    });
}

// ---------------------------------------------------------------------------
// A6. Starvation by a retrying shifter (bounded DoS by amplification).
// ---------------------------------------------------------------------------

/// A6. One long request holds a guard. A controller does what RETRY tells
/// it to: it resubmits the shift at once after each drain_timeout. There is
/// no minimum clutch-up interval between shifts. Safe behaviour: a steady
/// engager still gets admitted for most of its attempts. Weakness: admission
/// is paused almost all the time, because the clutch is down for the whole
/// shift timeout and up only for microseconds.
#[test]
fn a6_retrying_shifter_must_not_starve_admission() {
    let cfg = TransmissionConfig {
        max_engage_wait: Duration::from_millis(250),
        max_shift_timeout: Duration::from_millis(100),
        ..TransmissionConfig::default()
    };
    let t = tx(cfg);
    let long_request = t.engage(SHORT).unwrap();
    let stop = Arc::new(AtomicBool::new(false));
    let t2 = t.clone();
    let stop2 = Arc::clone(&stop);
    let shifts = Arc::new(AtomicU64::new(0));
    let shifts2 = Arc::clone(&shifts);
    let shifter = thread::spawn(move || {
        let mut cfg = Mode::for_epoch(1);
        while !stop2.load(Ordering::Relaxed) {
            match t2.shift(cfg, Duration::from_millis(100)) {
                Ok(_) => unreachable!("a guard is held"),
                Err(e) => {
                    assert_eq!(e.trip().reason, Reason::DrainTimeout);
                    cfg = e.into_config();
                }
            }
            shifts2.fetch_add(1, Ordering::Relaxed);
        }
    });
    wait_until("clutch pressed", || t.status().clutch_pressed);

    // Sampler: how much of the time is the clutch up (admission open)?
    let t3 = t.clone();
    let stop3 = Arc::clone(&stop);
    let sampler = thread::spawn(move || {
        let (mut up, mut total) = (0u64, 0u64);
        while !stop3.load(Ordering::Relaxed) {
            if !t3.status().clutch_pressed {
                up += 1;
            }
            total += 1;
            thread::sleep(Duration::from_micros(200));
        }
        (up, total)
    });

    let mut ok = 0u32;
    let mut retry = 0u32;
    let started = Instant::now();
    while started.elapsed() < Duration::from_millis(1500) {
        match t.engage(Duration::from_millis(250)) {
            Ok(g) => {
                ok += 1;
                drop(g);
            }
            Err(trip) => {
                assert_eq!(trip.reason, Reason::ClutchWaitTimeout);
                retry += 1;
            }
        }
    }
    stop.store(true, Ordering::Relaxed);
    shifter.join().unwrap();
    let (up, total) = sampler.join().unwrap();
    drop(long_request);
    eprintln!(
        "a6: {ok} admitted, {retry} clutch_wait_timeout, {} shift attempts, clutch up in {up}/{total} samples",
        shifts.load(Ordering::Relaxed)
    );
    assert!(
        up * 2 >= total,
        "no minimum clutch-up interval: admission open in only {up}/{total} samples"
    );
    assert!(
        ok >= retry,
        "admission starved by a retrying shifter: {ok} admitted vs {retry} refused"
    );
}

// ---------------------------------------------------------------------------
// A7. Replay / lost update: no compare-and-set on shift.
// ---------------------------------------------------------------------------

/// A7. Controller A prepares a config against epoch 0. Controller B shifts
/// to epoch 1 first. A's stale config (or a replayed old shift, for example
/// one that re-installs a retired key) is then accepted and given the
/// newest epoch, so it looks newer than B's change. Safe behaviour: a shift
/// prepared against epoch N is refused once the epoch has moved. There is
/// no API to express that, so the stale shift is accepted.
#[test]
fn a7_stale_or_replayed_shift_must_be_refused() {
    let t = tx(TransmissionConfig::default());
    let seen_by_a = t.current_epoch();
    let stale_from_a = Mode::for_epoch(0); // e.g. the old, retired key id
    t.shift(Mode::for_epoch(1), SHORT).unwrap(); // controller B wins
    assert_ne!(t.current_epoch(), seen_by_a);
    // Controller A states the epoch it prepared against. Plain shift() has no
    // way to know that, so the refusal can only come from shift_from().
    let r = t.shift_from(seen_by_a, stale_from_a, SHORT);
    assert!(
        r.is_err(),
        "stale shift prepared against epoch {seen_by_a} was accepted as epoch {}",
        t.current_epoch()
    );
    let refused = r.unwrap_err();
    assert_eq!(refused.trip().reason, Reason::EpochMismatch);
    assert_eq!(refused.trip().outcome(), GateOutcome::Retry);
    assert_eq!(refused.trip().resolution(), Resolution::Reject);
    assert_eq!(refused.into_config(), Mode::for_epoch(0), "config handed back");
    assert_eq!(t.current_epoch(), 1, "the stale shift changed nothing");
}

// ---------------------------------------------------------------------------
// A8. Caller-supplied Drop panics out of shift().
// ---------------------------------------------------------------------------

struct DropBomb {
    armed: bool,
}
impl Drop for DropBomb {
    fn drop(&mut self) {
        if self.armed && !thread::panicking() {
            panic!("test fixture: G::drop panics");
        }
    }
}

/// A8. The crate says no call panics across a request boundary. The old
/// gear is dropped inside `shift()`, after unlock. If the caller's G::drop
/// panics, the panic leaves `shift()` after the swap, and the shift is never
/// counted in tack_transmission_shift_total. State itself stays consistent.
#[test]
fn a8_panicking_old_gear_drop_must_not_escape_shift() {
    let t = Transmission::new(DropBomb { armed: true }, TransmissionConfig::default()).unwrap();
    let rec = DebuggingRecorder::new();
    let escaped = metrics::with_local_recorder(&rec, || {
        catch_unwind(AssertUnwindSafe(|| {
            let _ = t.shift(DropBomb { armed: false }, SHORT);
        }))
        .is_err()
    });
    let s = t.status();
    assert_eq!(s.epoch, 1, "the swap itself happened");
    assert!(!s.clutch_pressed);
    let counted = take(&rec)
        .iter()
        .any(|(n, _, _)| n == tm::SHIFT_TOTAL);
    assert!(!escaped, "G::drop panic escaped shift(); shift counted = {counted}");
}

// ---------------------------------------------------------------------------
// Attacks expected to hold.
// ---------------------------------------------------------------------------

/// A9. Integer and unit confusion: extreme timeouts must fail closed with
/// RETRY over-budget and change nothing, never panic on Instant arithmetic.
#[test]
fn a9_extreme_timeouts_fail_closed_without_panic() {
    let t = tx(TransmissionConfig::default());
    let e = t.engage(Duration::MAX).unwrap_err();
    assert_eq!(e.reason, Reason::EngageTimeoutOverBudget);
    assert_eq!(e.outcome(), GateOutcome::Retry);
    let e = t.engage(t.config().max_engage_wait + Duration::from_nanos(1)).unwrap_err();
    assert_eq!(e.reason, Reason::EngageTimeoutOverBudget);
    let r = t.shift(Mode::for_epoch(1), Duration::MAX).unwrap_err();
    assert_eq!(r.trip().reason, Reason::ShiftTimeoutOverBudget);
    assert_eq!(r.into_config(), Mode::for_epoch(1));
    let s = t.status();
    assert_eq!((s.epoch, s.in_flight, s.clutch_pressed), (0, 0, false));

    // Largest legal budgets: 24 h. Must build and work, no overflow.
    let cfg = TransmissionConfig {
        max_in_flight: usize::MAX,
        max_waiting_engagers: usize::MAX,
        max_engage_wait: tack_transmission::MAX_CONFIGURABLE_WAIT,
        max_shift_timeout: tack_transmission::MAX_CONFIGURABLE_WAIT,
    };
    let t = tx(cfg);
    let g = t.engage(tack_transmission::MAX_CONFIGURABLE_WAIT).unwrap();
    drop(g);
    t.shift(Mode::for_epoch(1), tack_transmission::MAX_CONFIGURABLE_WAIT).unwrap();

    // Zero timeouts are legal and fail closed under the clutch.
    let t = tx(TransmissionConfig::default());
    let g = t.engage(Duration::ZERO).unwrap();
    let r = t.shift(Mode::for_epoch(1), Duration::ZERO).unwrap_err();
    assert_eq!(r.trip().reason, Reason::DrainTimeout);
    assert_eq!(r.trip().resolution(), Resolution::Rollback);
    drop(g);
}

/// A10. Bounded parking: with the clutch down, at most max_waiting_engagers
/// callers park; the rest are refused at once with wait_queue_full. No
/// refusal is PASS.
#[test]
fn a10_wait_queue_is_bounded_and_fails_closed() {
    let cfg = TransmissionConfig {
        max_waiting_engagers: 2,
        max_engage_wait: Duration::from_secs(2),
        ..TransmissionConfig::default()
    };
    let t = tx(cfg);
    let guard = t.engage(SHORT).unwrap();
    let t2 = t.clone();
    let shifter = thread::spawn(move || t2.shift(Mode::for_epoch(1), Duration::from_millis(800)));
    wait_until("clutch pressed", || t.status().clutch_pressed);
    let parked: Vec<_> = (0..2)
        .map(|_| {
            let t = t.clone();
            thread::spawn(move || t.engage(Duration::from_secs(2)).map(|g| g.epoch()))
        })
        .collect();
    wait_until("two parked", || t.status().waiting_engagers == 2);
    let started = Instant::now();
    for _ in 0..50 {
        let e = t.engage(Duration::from_secs(2)).unwrap_err();
        assert_eq!(e.reason, Reason::WaitQueueFull);
        assert_eq!(e.outcome(), GateOutcome::Retry);
    }
    assert!(started.elapsed() < Duration::from_millis(500), "queue-full refusals must not wait");
    assert_eq!(t.status().waiting_engagers, 2);
    drop(guard);
    shifter.join().unwrap().unwrap();
    for p in parked {
        assert_eq!(p.join().unwrap().unwrap(), 1, "parked callers run on the new gear");
    }
}

/// A11. Leaked guard (mem::forget): shifts must fail closed (drain_timeout,
/// rollback, old gear kept), never swap with work in flight.
#[test]
fn a11_forgotten_guard_never_lets_a_shift_through() {
    let t = tx(TransmissionConfig::default());
    std::mem::forget(t.engage(SHORT).unwrap());
    for _ in 0..3 {
        let r = t.shift(Mode::for_epoch(1), SHORT).unwrap_err();
        assert_eq!(r.trip().reason, Reason::DrainTimeout);
        assert_eq!(r.trip().outcome(), GateOutcome::Retry);
    }
    let s = t.status();
    assert_eq!((s.epoch, s.in_flight, s.clutch_pressed), (0, 1, false));
    // Admission still works on the old gear.
    assert_eq!(t.engage(SHORT).unwrap().epoch(), 0);
}

/// A12. Telemetry cardinality: across every reachable path, every label key
/// and value comes from the closed vocabulary.
#[test]
fn a12_all_labels_are_closed_enums() {
    let rec = DebuggingRecorder::new();
    metrics::with_local_recorder(&rec, || {
        let cfg = TransmissionConfig {
            max_in_flight: 1,
            max_waiting_engagers: 1,
            ..TransmissionConfig::default()
        };
        let t = tx(cfg);
        let _ = t.engage(Duration::MAX);
        let g = t.engage(SHORT).unwrap();
        let _ = t.engage(SHORT); // capacity
        let _ = t.shift(Mode::for_epoch(1), Duration::MAX);
        let _ = t.shift(Mode::for_epoch(1), SHORT); // drain timeout
        drop(g);
        let _ = t.shift(Mode::for_epoch(1), SHORT); // pass
        t.operator_halt();
        let _ = t.engage(SHORT);
        let _ = t.shift(Mode::for_epoch(2), SHORT);
        t.operator_reset();
    });
    let mut allowed: HashSet<&str> = HashSet::new();
    for r in Reason::ALL {
        allowed.insert(r.as_str());
        allowed.insert(r.outcome().as_str());
        allowed.insert(r.resolution().as_str());
    }
    allowed.extend(["pass", "engage", "shift", "operator", "poisoned", "invariant"]);
    let keys: HashSet<&str> = ["outcome", "reason", "operation", "resolution", "cause"].into();
    let snap = take(&rec);
    assert!(!snap.is_empty());
    for (name, labels, _) in &snap {
        assert!(tm::ALL_METRICS.contains(&name.as_str()), "undeclared metric {name}");
        for (k, v) in labels {
            assert!(keys.contains(k.as_str()), "{name}: label key {k}");
            assert!(allowed.contains(v.as_str()), "{name}: label value {v}");
        }
    }
}

/// A13. ANC: engage cost must not depend on the gear's content. A 32 MiB
/// config and a 1-byte config must admit in comparable time (G is never
/// read or copied).
#[test]
fn a13_engage_latency_is_independent_of_gear_size() {
    fn median_engage<G>(t: &Transmission<G>) -> Duration {
        let mut v: Vec<Duration> = (0..2001)
            .map(|_| {
                let s = Instant::now();
                let g = t.engage(SHORT).unwrap();
                drop(g);
                s.elapsed()
            })
            .collect();
        v.sort();
        v[v.len() / 2]
    }
    let small = Transmission::new(vec![0u8; 1], TransmissionConfig::default()).unwrap();
    let big = Transmission::new(vec![7u8; 32 << 20], TransmissionConfig::default()).unwrap();
    let _ = median_engage(&small);
    let (a, b) = (median_engage(&small), median_engage(&big));
    eprintln!("a13: median engage small={a:?} big={b:?}");
    let (lo, hi) = if a < b { (a, b) } else { (b, a) };
    assert!(hi <= lo * 5 + Duration::from_micros(20), "size leak: {a:?} vs {b:?}");
}

/// A14. Drain guarantee under racing threads with halts and resets mixed
/// in: a guard's epoch never differs from current_epoch while it is held,
/// and no count is left behind.
#[test]
fn a14_no_mixed_gear_under_halt_reset_churn() {
    let t = tx(TransmissionConfig {
        max_in_flight: 3,
        max_waiting_engagers: 2,
        ..TransmissionConfig::default()
    });
    let stop = Arc::new(AtomicBool::new(false));
    let bad = Arc::new(AtomicU64::new(0));
    let workers: Vec<_> = (0..6)
        .map(|_| {
            let t = t.clone();
            let stop = Arc::clone(&stop);
            let bad = Arc::clone(&bad);
            thread::spawn(move || {
                while !stop.load(Ordering::Relaxed) {
                    if let Ok(g) = t.engage(Duration::from_millis(5)) {
                        let e = g.epoch();
                        if t.current_epoch() != e || !g.config().is_consistent() {
                            bad.fetch_add(1, Ordering::Relaxed);
                        }
                        thread::yield_now();
                        if t.current_epoch() != e {
                            bad.fetch_add(1, Ordering::Relaxed);
                        }
                    }
                }
            })
        })
        .collect();
    let t2 = t.clone();
    let stop2 = Arc::clone(&stop);
    let chaos = thread::spawn(move || {
        while !stop2.load(Ordering::Relaxed) {
            t2.operator_halt();
            thread::yield_now();
            t2.operator_reset();
            thread::sleep(Duration::from_micros(200));
        }
    });
    let started = Instant::now();
    let mut n = 1;
    while started.elapsed() < Duration::from_millis(600) {
        if t.shift(Mode::for_epoch(n), Duration::from_millis(5)).is_ok() {
            n += 1;
        }
    }
    stop.store(true, Ordering::Relaxed);
    for w in workers {
        w.join().unwrap();
    }
    chaos.join().unwrap();
    t.operator_reset();
    let s = t.status();
    assert_eq!(bad.load(Ordering::Relaxed), 0, "mixed gear observed");
    assert_eq!((s.in_flight, s.waiting_engagers, s.clutch_pressed), (0, 0, false));
    assert_eq!(s.epoch, n - 1);
    let _ = LONG;
}
