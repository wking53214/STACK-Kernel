//! Independent red-team tests for tack-anc-adaptive (ANC strategy 2).
//!
//! Each test asserts the SAFE behaviour, so a test FAILS while the weakness
//! it probes exists. Tests whose names start with `held_` probe an attack
//! that the crate is expected to resist; they should pass.
//!
//! Most attacks drive the controllers directly with synthetic `Instant`s, so
//! they are deterministic. `Snapshot::plan` is the exact function the pad
//! uses to pick the release offset (`start + plan.release()`), so a finding
//! on a plan is a finding on the pad. A few tests use a real pad with
//! millisecond margins.
#![allow(clippy::unwrap_used, clippy::panic, clippy::expect_used)] // test code

mod common;

use common::{ms, us};
use metrics_util::debugging::DebuggingRecorder;
use proptest::prelude::*;
use std::fmt::Write as _;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tack_anc_adaptive::config::MAX_WINDOW;
use tack_anc_adaptive::telemetry::{names, sha256_hex};
use tack_anc_adaptive::{
    epoch_bound_bits, AdaptivePad, EpochConfig, EpochQuantizedTarget, GateOutcome,
    LeakBudgetConfig, MissRule, NaiveConfig, NaiveRollingTarget, PadConfig, Plan, Snapshot,
    SpinBudgetConfig, TargetController, Trip, WaitMode, WindowStatistic,
};

fn record_metrics(f: impl FnOnce()) -> common::Snap {
    let recorder = DebuggingRecorder::new();
    let snapshotter = recorder.snapshotter();
    metrics::with_local_recorder(&recorder, f);
    snapshotter.snapshot().into_vec()
}

/// One request through a controller: admit at `at`, record `work`.
fn step<K: TargetController>(c: &mut K, at: Instant, work: Duration) -> Snapshot {
    let (s, _) = c.admit(at);
    c.record(&s, work, at + work);
    s
}

// ---------------------------------------------------------------------------
// Attack 1. Leak-budget self-exhaustion on honest traffic (warm-up).
// ---------------------------------------------------------------------------

/// With the documented defaults (initial level = the cap, 128 bits per 60 s,
/// 1 s epochs), honest traffic that only ever takes the fast path spends the
/// whole leak budget while the controller walks down from the cap during
/// warm-up, because every step down is a counted change and the bound grows
/// with the request count. The controller then freezes at the cap until an
/// operator reset: the adaptive pad silently becomes strategy 1 at the cap.
/// SAFE: honest fast traffic never exhausts the default budget.
#[test]
fn attack_warmup_on_honest_traffic_spends_default_budget() {
    let mut report = String::new();
    let mut frozen_any = false;
    for (floor, cap) in [(us(10), ms(10)), (us(1), Duration::from_secs(10))] {
        let o = Instant::now();
        let cfg = EpochConfig::new(floor, cap); // every default
        let mut c = EpochQuantizedTarget::new(cfg, o).unwrap();
        let mut frozen_at = None;
        // 100 requests per second, 60 s (one accounting window), all taking
        // 50% of the floor.
        'outer: for sec in 0..60u64 {
            for k in 0..100u64 {
                let at = o + ms(sec * 1_000 + k * 10);
                step(&mut c, at, floor / 2);
                if c.is_frozen() {
                    frozen_at = Some((sec, c.status()));
                    break 'outer;
                }
            }
        }
        if let Some((sec, s)) = frozen_at {
            frozen_any = true;
            let _ = writeln!(
                report,
                "floor {floor:?} cap {cap:?} ({} levels): FROZEN after {sec} s of honest fast traffic, \
                 window_changes {} window_requests {} leak_bits {:.1} >= budget 128; target now {:?}",
                cfg.levels(),
                s.window_changes,
                s.window_requests,
                s.leak_bits,
                s.target
            );
        } else {
            let _ = writeln!(report, "floor {floor:?} cap {cap:?}: not frozen");
        }
    }
    println!("{report}");
    assert!(
        !frozen_any,
        "honest traffic alone spent the default leak budget during warm-up:\n{report}"
    );
}

// ---------------------------------------------------------------------------
// Attack 2. One attacker request forces an operator-only freeze (DoS).
// ---------------------------------------------------------------------------

/// The builder's own ladder (64 us to 2048 us, 6 levels) and default budget.
/// After warm-up, the attacker sends ONE slow request (work just under the
/// cap). It escalates the level to the cap (5 counted changes); honest
/// traffic then steps it back down (5 more). The bound then crosses 128 bits
/// on honest request volume alone, the controller freezes at the cap, and
/// the freeze outlives the accounting window: it lasts until an operator
/// reset. SAFE: a single attacker request does not put the pad into an
/// operator-only state; the controller adapts again once the window that
/// held the attack has passed.
#[test]
fn attack_single_slow_request_forces_permanent_cap_freeze() {
    let o = Instant::now();
    let cfg = EpochConfig::new(us(64), us(2_048));
    let mut c = EpochQuantizedTarget::new(cfg, o).unwrap();
    let honest = us(20);
    let mut froze_at = None;
    for sec in 0..180u64 {
        for k in 0..20u64 {
            let at = o + ms(sec * 1_000 + k * 50);
            // The attack: one request, second 10, just under the cap.
            let work = if sec == 10 && k == 0 {
                us(2_000)
            } else {
                honest
            };
            step(&mut c, at, work);
            if froze_at.is_none() && c.is_frozen() {
                froze_at = Some((sec, c.status()));
            }
        }
    }
    let end = c.status();
    println!(
        "froze at {:?}; at 180 s (two windows after the attack): frozen {} level {:?} target {:?} \
         window_changes {} leak_bits {:.1}",
        froze_at.map(|(s, st)| (s, st.window_changes, st.window_requests, st.leak_bits)),
        end.frozen,
        end.level,
        end.target,
        end.window_changes,
        end.leak_bits
    );
    assert!(
        !end.frozen,
        "one attacker request at t=10 s left the controller frozen at the cap ({:?}) 170 s later, \
         two accounting windows after the attack; only reset_controller() lifts it \
         (honest traffic now pays {:?} instead of {:?})",
        end.target, end.target, cfg.floor
    );
}

// ---------------------------------------------------------------------------
// Attack 3. Concurrent escalations leak without a counted change.
// ---------------------------------------------------------------------------

/// Two requests are admitted at level 0 (both hold snapshots at 100 us).
/// Request 1 is slow and raises the level to 800 us (3 counted changes).
/// Request 2 then misses its snapshot target too, but the level already
/// covers it, so no change is counted, yet request 2 is released at the
/// level covering ITS OWN work: 200 us for the fast-ish class, 400 us for the
/// slower class. The release time reveals which class request 2 was in, and
/// the leak bound does not charge for it. With 64 slots, one raise can carry
/// up to 63 such uncounted escalations. SAFE: two secret classes that are
/// both below the current (counted) level get the same release, or the
/// difference is charged to the leak budget.
#[test]
fn attack_concurrent_escalation_is_uncounted_leak() {
    let o = Instant::now();
    let cfg = EpochConfig {
        initial_level: 0,
        leak_budget: LeakBudgetConfig {
            bits: 1.0e6,
            window: Duration::from_secs(3_600),
        },
        ..EpochConfig::new(us(100), us(1_600))
    };
    let mut releases = Vec::new();
    let mut extra_changes = Vec::new();
    for class_work in [us(150), us(350)] {
        let mut c = EpochQuantizedTarget::new(cfg, o).unwrap();
        let (s1, _) = c.admit(o);
        let (s2, _) = c.admit(o);
        c.record(&s1, us(700), o + us(700));
        let before = c.status().window_changes;
        let plan = s2.plan(class_work);
        c.record(&s2, class_work, o + class_work);
        let after = c.status().window_changes;
        println!(
            "victim work {class_work:?}: plan {plan:?}, controller target now {:?}, \
             changes charged for the victim: {}",
            c.target(),
            after - before
        );
        releases.push(plan.release());
        extra_changes.push(after - before);
    }
    let uncounted = releases[0] != releases[1] && extra_changes.iter().all(|&n| n == 0);
    assert!(
        !uncounted,
        "escalated releases {releases:?} distinguish the two secret classes while \
         0 changes were charged ({extra_changes:?})"
    );
}

// ---------------------------------------------------------------------------
// Attack 4. Overrun releases leak the work time in cap multiples, even when
// the controller is frozen ("remaining leakage is then zero").
// ---------------------------------------------------------------------------

/// The crate docs say that once the budget is spent and the target rolled
/// back to the cap, "the remaining leakage is then zero". An overrun is
/// released at the next whole multiple of the cap, so the release time
/// still encodes ceil(work / cap), and nothing is charged. SAFE: two
/// overrunning secret classes are released at the same time on a frozen
/// controller, or the overrun is charged to the budget.
#[test]
fn attack_overrun_multiples_leak_after_freeze() {
    let o = Instant::now();
    let cfg = EpochConfig {
        initial_level: 0,
        leak_budget: LeakBudgetConfig {
            bits: 1.0,
            window: Duration::from_secs(60),
        },
        ..EpochConfig::new(us(100), us(1_600))
    };
    let mut c = EpochQuantizedTarget::new(cfg, o).unwrap();
    // One misprediction spends the tiny budget: frozen at the cap.
    step(&mut c, o, us(150));
    assert!(c.is_frozen());
    let bits_frozen = c.status().leak_bits;
    let changes_frozen = c.status().window_changes;
    let cap = cfg.cap;
    let mut rel = Vec::new();
    for (i, work) in [cap * 3 / 2, cap * 5 / 2, cap * 7 / 2]
        .into_iter()
        .enumerate()
    {
        let at = o + ms(10 + i as u64);
        let (s, _) = c.admit(at);
        let p = s.plan(work);
        c.record(&s, work, at + work);
        rel.push((work, p));
    }
    let bits_after = c.status().leak_bits;
    let changes_after = c.status().window_changes;
    // leak_bits can creep up only because the request count R grew; the
    // overruns themselves add no counted change.
    println!(
        "frozen at cap {cap:?}; overrun plans: {rel:?}; window_changes {changes_frozen} -> \
         {changes_after}; leak_bits {bits_frozen} -> {bits_after:.2} (R growth only)"
    );

    // Same thing through a real pad: a single-level ladder (floor = cap =
    // 2 ms) is the strategy-1 shape; overruns of 3 ms and 5 ms.
    let pad = AdaptivePad::epoch(PadConfig::default(), EpochConfig::new(ms(2), ms(2))).unwrap();
    let mut observed = Vec::new();
    for w in [ms(3), ms(5)] {
        let t0 = Instant::now();
        let r = pad.pad(|| std::thread::sleep(w));
        observed.push((w, r.map(|_| ()), t0.elapsed()));
    }
    println!("real pad, cap 2 ms: {observed:?}");

    let distinct = rel.windows(2).any(|w| w[0].1.release() != w[1].1.release());
    assert!(
        !(distinct && changes_after == changes_frozen),
        "frozen controller still releases overruns on distinct cap multiples {:?} with no \
         change charged (window_changes {changes_frozen} -> {changes_after}); real pad observed {:?}",
        rel.iter().map(|(_, p)| p.release()).collect::<Vec<_>>(),
        observed.iter().map(|o| o.2).collect::<Vec<_>>()
    );
}

// ---------------------------------------------------------------------------
// Attack 5. Shedding decision depends on a victim's secret (slot occupancy).
// ---------------------------------------------------------------------------

/// A padded request holds its concurrency slot until release. On-time
/// requests hold it for the public target, but an overrunning request holds
/// it until the next cap multiple. An attacker probing admission at a fixed
/// offset after a victim is admitted learns whether the victim overran:
/// SlotsFull versus served. SAFE: the probe outcome is the same whichever
/// class the victim was in.
#[test]
fn attack_shed_decision_reveals_victim_overrun() {
    let mut outcomes = Vec::new();
    for victim_work in [ms(1), ms(30)] {
        let pad = AdaptivePad::epoch(
            PadConfig {
                max_concurrent: 1,
                ..PadConfig::default()
            },
            EpochConfig::new(ms(20), ms(20)),
        )
        .unwrap();
        let started = AtomicBool::new(false);
        let probe = std::thread::scope(|s| {
            s.spawn(|| {
                let _ = pad.pad(|| {
                    started.store(true, Ordering::SeqCst);
                    std::thread::sleep(victim_work);
                });
            });
            while !started.load(Ordering::SeqCst) {
                std::hint::spin_loop();
            }
            // Probe well after the fast victim's release (20 ms) and well
            // after the slow victim finished its work (30 ms), but before
            // the slow victim's cap-grid release (40 ms).
            std::thread::sleep(ms(34));
            pad.pad(|| ()).map(|_| ()).map_err(|t| t.label())
        });
        println!("victim work {victim_work:?}: probe at +34 ms -> {probe:?}");
        outcomes.push(probe);
    }
    assert_eq!(
        outcomes[0], outcomes[1],
        "admission probe outcome depends on the victim's secret work time"
    );
}

// ---------------------------------------------------------------------------
// Attack 6. A panic inside the operation escapes padding and telemetry.
// ---------------------------------------------------------------------------

/// Kernel convention 1: never panic across a request boundary. If the
/// secret-dependent operation panics on one path (for example an index
/// out of bounds only reached by a near-correct guess), the panic unwinds
/// straight out of `pad`, unpadded, at the raw work time, and no metric
/// records the request. SAFE: the request is still padded to its target,
/// returns a typed outcome, and is counted.
#[test]
fn attack_panicking_op_escapes_padding_and_telemetry() {
    let target = ms(50);
    let crossed = AtomicBool::new(false);
    let mut elapsed = Duration::ZERO;
    let prev = std::panic::take_hook();
    std::panic::set_hook(Box::new(|_| {})); // keep the output readable
    let snap = record_metrics(|| {
        let pad =
            AdaptivePad::epoch(PadConfig::default(), EpochConfig::new(target, target)).unwrap();
        let t0 = Instant::now();
        let r = catch_unwind(AssertUnwindSafe(|| {
            pad.pad(|| -> u32 { panic!("secret-dependent path") })
        }));
        elapsed = t0.elapsed();
        crossed.store(r.is_err(), Ordering::SeqCst);
        assert_eq!(pad.in_flight(), 0, "slot leaked by the panic");
    });
    std::panic::set_hook(prev);
    let counted: u64 = [
        GateOutcome::Pass,
        GateOutcome::Retry,
        GateOutcome::TerminalBreach,
    ]
    .iter()
    .map(|o| {
        common::counter(
            &snap,
            names::REQUESTS_TOTAL,
            &[("outcome", o.label()), ("controller", "epoch")],
        )
    })
    .sum();
    let crossed = crossed.load(Ordering::SeqCst);
    println!(
        "panic crossed the pad boundary: {crossed}; elapsed {elapsed:?} vs target {target:?}; \
         requests counted: {counted}"
    );
    assert!(
        !crossed && elapsed >= target && counted == 1,
        "op panic escaped: crossed boundary {crossed}, released after {elapsed:?} \
         (target {target:?}), requests_total {counted}"
    );
}

// ---------------------------------------------------------------------------
// Attack 7. Hybrid spin tail at or above the cap is accepted.
// ---------------------------------------------------------------------------

/// `PadConfig::validate` bounds `spin_tail` by MAX_SPIN_TAIL (10 s) but never
/// against the controller's cap. In Hybrid mode every request is planned as
/// `work + spin_tail`, so a tail at or above the cap makes every
/// spin-granted request an Overrun RETRY with its value discarded (and
/// forces the level to the cap on each). Requests that fall back to Sleep
/// because the spin budget is empty are served. SAFE: the pad refuses the
/// configuration at construction, or serves a zero-work request.
#[test]
fn attack_hybrid_tail_above_cap_turns_every_request_into_retry() {
    let built = AdaptivePad::epoch(
        PadConfig {
            mode: WaitMode::Hybrid,
            spin_tail: ms(2),
            spin_budget: SpinBudgetConfig::Limited {
                cpu_per_second: Duration::from_secs(1),
                burst: Duration::from_secs(1),
            },
            ..PadConfig::default()
        },
        EpochConfig::new(us(100), ms(1)),
    );
    let Ok(pad) = built else {
        return; // refused at construction: safe
    };
    let results: Vec<_> = (0..5).map(|_| pad.pad(|| 7u8).map(|p| p.value)).collect();
    println!("hybrid tail 2 ms, cap 1 ms, zero-work op: {results:?}");
    assert!(
        results.iter().all(|r| r.is_ok()),
        "config accepted and zero-work requests were refused: {results:?}"
    );
}

// ---------------------------------------------------------------------------
// Attack 8. Naive percentile: O(window log window) under the lock per request.
// ---------------------------------------------------------------------------

/// Each naive `record` copies and sorts the whole window while holding the
/// pad's controller mutex. At the accepted maximum window (65_536) that is a
/// 65_536-element sort per request, serialising every request of the pad
/// behind it (admission also takes this mutex, after the admission
/// timestamp, so the wait lands inside every other request's padded window).
/// SAFE: the per-request controller cost stays near constant (under 100 us
/// here, which an order-statistic structure achieves easily).
#[test]
fn attack_naive_percentile_sort_amplification() {
    // Filling a 65_536 window through `record` is itself quadratic (each
    // fill step sorts), so measure at n = 4_096 and scale by n log n.
    let o = Instant::now();
    let n = 4_096usize;
    let mut c = NaiveRollingTarget::new(NaiveConfig {
        window: MAX_WINDOW,
        statistic: WindowStatistic::Percentile { permille: 990 },
        ..NaiveConfig::new(ms(10))
    })
    .unwrap();
    let (s, _) = c.admit(o);
    let mut x: u64 = 0x9e37_79b9_7f4a_7c15;
    while c.window_len() < n {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        let _ = c.record(&s, Duration::from_nanos(1_000 + x % 100_000), o);
    }
    let reps = 50u32;
    let t = Instant::now();
    for _ in 0..reps {
        let _ = c.record(&s, us(5), o);
    }
    let per_n = t.elapsed() / reps;
    let scale = (MAX_WINDOW as f64 * (MAX_WINDOW as f64).log2()) / (n as f64 * (n as f64).log2());
    let per_max = per_n.mul_f64(scale);
    // Reference: the epoch controller's record.
    let mut e = EpochQuantizedTarget::new(EpochConfig::new(us(100), us(1_600)), o).unwrap();
    let (es, _) = e.admit(o);
    let t = Instant::now();
    for _ in 0..reps {
        let _ = e.record(&es, us(5), o);
    }
    let per_epoch = t.elapsed() / reps;
    println!(
        "naive p99 record() under the controller mutex (this build): {per_n:?} at window {n}; \
         scaled by n log n to the accepted maximum {MAX_WINDOW}: about {per_max:?}; \
         epoch record() for comparison: {per_epoch:?}"
    );
    assert!(
        per_max < us(100),
        "one request's mutex-held controller update costs about {per_max:?} at window {MAX_WINDOW} \
         ({per_n:?} measured at {n})"
    );
}

// ---------------------------------------------------------------------------
// Attack 9. The leak budget is a per-window rate, not a total.
// ---------------------------------------------------------------------------

/// The budget resets with each 60 s accounting window, and the freeze only
/// fires when ONE window's bound reaches it. An attacker who paces changes
/// to stay just under 128 bits per window extracts that much every window,
/// forever, and the controller never freezes. SAFE: once the cumulative
/// charged bound passes the budget, the controller freezes (or the budget
/// is otherwise not renewable without an operator).
#[test]
fn attack_leak_budget_renews_every_window() {
    let o = Instant::now();
    let cfg = EpochConfig {
        initial_level: 0,
        ..EpochConfig::new(us(100), us(1_600)) // default 128 bits / 60 s, 1 s epochs
    };
    let mut c = EpochQuantizedTarget::new(cfg, o).unwrap();
    let mut cumulative = 0.0;
    let mut window_peak = 0.0f64;
    let mut last_window = 0u64;
    let windows = 10u64;
    for sec in 0..(60 * windows) {
        let w = sec / 60;
        if w != last_window {
            cumulative += window_peak;
            window_peak = 0.0;
            last_window = w;
        }
        // Attacker: a slow request at seconds 1 and 31 of each window
        // (4 doublings each); honest fast traffic, one per second, steps it
        // back down (4 halvings each). 16 changes per window.
        let off = sec % 60;
        let work = if off == 1 || off == 31 {
            us(1_500)
        } else {
            us(50)
        };
        step(&mut c, o + ms(sec * 1_000 + 1), work);
        window_peak = window_peak.max(c.status().leak_bits);
        if c.is_frozen() {
            break;
        }
    }
    cumulative += window_peak;
    let s = c.status();
    println!(
        "{windows} windows: changes_total {} requests_total {}; per-window peak about {:.1} bits; \
         cumulative charged {:.1} bits against a 128-bit budget; frozen {}",
        s.changes_total, s.requests_total, window_peak, cumulative, s.frozen
    );
    assert!(
        s.frozen || cumulative < cfg.leak_budget.bits,
        "attacker paced {:.1} bits of charged leakage across {windows} windows without a freeze",
        cumulative
    );
}

// ---------------------------------------------------------------------------
// Attack 10. One slow request per epoch pins everyone at the cap.
// ---------------------------------------------------------------------------

/// A decrease needs the whole epoch's largest work time to fit the lower
/// level. One attacker request per epoch with work near the cap therefore
/// holds every honest request at the cap forever, at a cost of one request
/// per second against any honest volume. SAFE: with 1 slow request per 1000
/// fast ones, the target leaves the cap within 30 epochs.
#[test]
fn attack_one_slow_request_per_epoch_pins_cap() {
    let o = Instant::now();
    let cfg = EpochConfig {
        leak_budget: LeakBudgetConfig {
            bits: 1.0e6,
            window: Duration::from_secs(3_600),
        },
        ..EpochConfig::new(us(100), us(1_600))
    };
    let mut c = EpochQuantizedTarget::new(cfg, o).unwrap();
    for sec in 0..30u64 {
        for k in 0..1_000u64 {
            let work = if k == 500 { us(1_500) } else { us(50) };
            step(&mut c, o + ms(sec * 1_000) + us(k * 900), work);
        }
    }
    println!(
        "after 30 epochs with 1 slow per 1000 fast: target {:?} (floor {:?}, cap {:?})",
        c.target(),
        cfg.floor,
        cfg.cap
    );
    assert!(
        c.target() < cfg.cap,
        "0.1 percent attacker traffic holds 100 percent of requests at the cap"
    );
}

// ---------------------------------------------------------------------------
// Attack 11. Naive late release: the raw work time is the response time.
// ---------------------------------------------------------------------------

/// The naive controller is reachable through the public constructor
/// `AdaptivePad::naive` with no opt-in, and its late release puts the raw,
/// secret-dependent work time on the wire. Documented as a leak kept for
/// measurement. SAFE: a late naive release is not the raw work time.
#[test]
fn attack_naive_late_release_is_raw_work_time() {
    let s = Snapshot {
        target: us(100),
        cap: us(1_000),
        rule: MissRule::ReleaseLate,
    };
    let a = s.plan(us(123));
    let b = s.plan(us(456));
    println!("naive plans: {a:?} {b:?}");
    assert!(
        a.release() == b.release(),
        "naive late releases equal the raw work times {:?} and {:?}",
        a.release(),
        b.release()
    );
}

// ---------------------------------------------------------------------------
// Held checks.
// ---------------------------------------------------------------------------

/// A tracing subscriber that captures every span field and event field as
/// text, so tests can check what is logged.
#[derive(Debug, Default)]
struct Capture {
    lines: Mutex<Vec<String>>,
    next: AtomicU64,
}

struct V<'a>(&'a mut String);
impl tracing::field::Visit for V<'_> {
    fn record_debug(&mut self, f: &tracing::field::Field, v: &dyn std::fmt::Debug) {
        let _ = write!(self.0, "{}={:?} ", f.name(), v);
    }
    fn record_str(&mut self, f: &tracing::field::Field, v: &str) {
        let _ = write!(self.0, "{}={} ", f.name(), v);
    }
}

impl tracing::Subscriber for Capture {
    fn enabled(&self, _: &tracing::Metadata<'_>) -> bool {
        true
    }
    fn new_span(&self, a: &tracing::span::Attributes<'_>) -> tracing::span::Id {
        let mut s = format!("SPAN {} ", a.metadata().name());
        a.record(&mut V(&mut s));
        self.lines.lock().unwrap().push(s);
        tracing::span::Id::from_u64(self.next.fetch_add(1, Ordering::Relaxed) + 1)
    }
    fn record(&self, _: &tracing::span::Id, r: &tracing::span::Record<'_>) {
        let mut s = String::from("RECORD ");
        r.record(&mut V(&mut s));
        self.lines.lock().unwrap().push(s);
    }
    fn record_follows_from(&self, _: &tracing::span::Id, _: &tracing::span::Id) {}
    fn event(&self, e: &tracing::Event<'_>) {
        let mut s = format!("EVENT {} ", e.metadata().level());
        e.record(&mut V(&mut s));
        self.lines.lock().unwrap().push(s);
    }
    fn enter(&self, _: &tracing::span::Id) {}
    fn exit(&self, _: &tracing::span::Id) {}
}

/// Raw input never reaches logs; the digest is the full 64-hex SHA-256; an
/// injected newline or fake field in the input cannot forge a log line;
/// oversized input is not hashed.
#[test]
fn held_logs_never_carry_raw_input_or_truncated_hash() {
    let cap = Arc::new(Capture::default());
    let input: &[u8] = b"RAWSECRET\nEVENT ERROR outcome=PASS input_sha256=deadbeef";
    let big = vec![b'Z'; 65];
    tracing::subscriber::with_default(cap.clone(), || {
        let pad = AdaptivePad::epoch(
            PadConfig {
                max_input_len: 64,
                ..PadConfig::default()
            },
            EpochConfig::new(us(100), us(400)),
        )
        .unwrap();
        pad.pad_input(input, |b| b.len()).unwrap();
        assert_eq!(
            pad.pad_input(&big, |b| b.len()).unwrap_err(),
            Trip::InputTooLarge
        );
    });
    let lines = cap.lines.lock().unwrap().clone();
    let all = lines.join("\n");
    assert!(!all.contains("RAWSECRET"), "raw input logged:\n{all}");
    assert!(!all.contains("ZZZZ"), "raw oversized input logged:\n{all}");
    let digest = sha256_hex(input);
    assert_eq!(digest.len(), 64);
    assert!(all.contains(&digest), "full digest missing:\n{all}");
    assert!(
        all.contains("not computed"),
        "oversized input was hashed:\n{all}"
    );
    assert!(
        !all.contains(&sha256_hex(&big)),
        "oversized input was hashed"
    );
    // Every event line is one line: the input never splits it.
    for l in &lines {
        assert!(!l.contains('\n'), "a log field contains a raw newline: {l}");
    }
}

/// Every label value on every metric comes from a closed set, whatever the
/// input bytes and whatever the outcome (served, escalated, overrun, input
/// too large, slots full).
#[test]
fn held_metric_labels_are_closed_set() {
    let allowed: &[(&str, &[&str])] = &[
        ("strategy", &["adaptive"]),
        ("controller", &["naive", "epoch"]),
        ("outcome", &["pass", "retry", "terminal_breach"]),
        ("reason", &["slots_full", "input_too_large", "halted"]),
        ("disposition", &["late", "escalated", "retry"]),
        ("direction", &["increase", "decrease", "rollback"]),
        ("mode", &["hybrid"]),
        ("scope", &["pad", "controller"]),
    ];
    let snap = record_metrics(|| {
        let pad = AdaptivePad::epoch(
            PadConfig {
                max_input_len: 16,
                ..PadConfig::default()
            },
            EpochConfig {
                initial_level: 0,
                ..EpochConfig::new(us(200), ms(2))
            },
        )
        .unwrap();
        for i in 0..40u8 {
            let input: Vec<u8> = (0..(i % 20)).map(|j| j.wrapping_mul(i) ^ b'"').collect();
            let _ = pad.pad_input(&input, |b| {
                if b.len() == 3 {
                    std::thread::sleep(us(500));
                }
                if b.len() == 5 {
                    std::thread::sleep(ms(3));
                }
            });
        }
        let naive = AdaptivePad::naive(PadConfig::default(), NaiveConfig::new(us(300))).unwrap();
        for _ in 0..5 {
            let _ = naive.pad_input(b"x\ny=z", |_| ());
        }
        pad.reset();
        pad.reset_controller();
    });
    let mut seen = 0;
    for (k, _, _, _) in &snap {
        let key = k.key();
        assert!(
            key.name().starts_with("tack_anc_"),
            "bad name {}",
            key.name()
        );
        for l in key.labels() {
            seen += 1;
            let ok = allowed
                .iter()
                .any(|(lk, vs)| *lk == l.key() && vs.contains(&l.value()));
            assert!(
                ok,
                "label {}={} on {} is not closed-set",
                l.key(),
                l.value(),
                key.name()
            );
        }
    }
    assert!(seen > 20);
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(2_000))]
    /// `Snapshot::plan` is pure and total on arbitrary (even invalid)
    /// snapshots: no panic, never releases before the work or the target.
    #[test]
    fn held_plan_is_total_and_never_early(
        target in 0u64..u64::MAX / 2,
        cap in 0u64..u64::MAX / 2,
        floor in 0u64..u64::MAX / 2,
        level in any::<u32>(),
        work in 0u64..u64::MAX / 2,
        naive in any::<bool>(),
    ) {
        let s = Snapshot {
            target: Duration::from_nanos(target),
            cap: Duration::from_nanos(cap),
            rule: if naive {
                MissRule::ReleaseLate
            } else {
                MissRule::Escalate { floor: Duration::from_nanos(floor), level }
            },
        };
        let w = Duration::from_nanos(work);
        let p = s.plan(w);
        prop_assert!(p.release() >= w, "{:?} {:?}", s, p);
        prop_assert!(p.release() >= s.target, "{:?} {:?}", s, p);
        if let Plan::Escalated { steps, .. } = p {
            prop_assert!(steps >= 1);
        }
    }
}

/// No trip maps to PASS; the overrun discards the value.
#[test]
fn held_no_trip_fails_open() {
    for t in [
        Trip::SlotsFull,
        Trip::InputTooLarge,
        Trip::Overrun,
        Trip::Halted,
        Trip::ClockFailure,
    ] {
        assert_ne!(t.gate_outcome(), GateOutcome::Pass, "{t:?}");
    }
    let pad = AdaptivePad::epoch(PadConfig::default(), EpochConfig::new(ms(1), ms(1))).unwrap();
    let r = pad.pad(|| {
        std::thread::sleep(ms(2));
        42u32
    });
    assert_eq!(r.unwrap_err(), Trip::Overrun);
}

/// Configuration bounds reject attacker-scale numbers (no allocation sized
/// by an unchecked count).
#[test]
fn held_config_bounds_reject_huge_or_nonfinite_values() {
    assert!(NaiveRollingTarget::new(NaiveConfig {
        window: MAX_WINDOW + 1,
        ..NaiveConfig::new(ms(1))
    })
    .is_err());
    for bits in [f64::NAN, f64::INFINITY, -1.0, 0.0, 1.0e9] {
        let c = EpochConfig {
            leak_budget: LeakBudgetConfig {
                bits,
                window: Duration::from_secs(60),
            },
            ..EpochConfig::new(us(10), ms(1))
        };
        assert!(c.validate().is_err(), "bits {bits} accepted");
    }
    assert!(EpochConfig::new(us(10), Duration::from_secs(11))
        .validate()
        .is_err());
    assert!(EpochConfig {
        initial_level: 64,
        ..EpochConfig::new(us(10), ms(1))
    }
    .validate()
    .is_err());
    assert!(PadConfig {
        max_concurrent: usize::MAX,
        ..PadConfig::default()
    }
    .validate()
    .is_err());
    assert!(PadConfig {
        max_input_len: usize::MAX,
        ..PadConfig::default()
    }
    .validate()
    .is_err());
}

/// Many threads on one pad: slot counter returns to zero, the concurrency
/// cap is never exceeded, the controller counts exactly the admitted
/// requests, and nothing panics.
#[test]
fn held_concurrent_state_stays_consistent() {
    let pad = Arc::new(
        AdaptivePad::epoch(
            PadConfig {
                max_concurrent: 4,
                ..PadConfig::default()
            },
            EpochConfig {
                initial_level: 0,
                epoch: ms(5),
                ..EpochConfig::new(us(50), us(800))
            },
        )
        .unwrap(),
    );
    let admitted = Arc::new(AtomicUsize::new(0));
    let max_seen = Arc::new(AtomicUsize::new(0));
    std::thread::scope(|s| {
        for t in 0..12u64 {
            let pad = pad.clone();
            let admitted = admitted.clone();
            let max_seen = max_seen.clone();
            s.spawn(move || {
                for i in 0..150u64 {
                    let r = pad.pad(|| {
                        max_seen.fetch_max(pad.in_flight(), Ordering::Relaxed);
                        if (t + i) % 17 == 0 {
                            std::thread::sleep(us(300));
                        }
                    });
                    match r {
                        Ok(_) | Err(Trip::Overrun) => {
                            admitted.fetch_add(1, Ordering::Relaxed);
                        }
                        Err(Trip::SlotsFull) => {}
                        Err(e) => panic!("unexpected trip {e:?}"),
                    }
                }
            });
        }
    });
    assert_eq!(pad.in_flight(), 0);
    assert!(max_seen.load(Ordering::Relaxed) <= 4);
    let st = pad.status();
    assert_eq!(st.requests_total, admitted.load(Ordering::Relaxed) as u64);
    assert!(st.leak_bits.is_finite());
    assert!((st.leak_bits - epoch_bound_bits(st.window_changes, st.window_requests)).abs() < 1e-9);
}
