//! Independent red-team tests for tack-minotaur.
//!
//! Every test asserts the SAFE behaviour. A failing test means the weakness
//! it names is present. Test keys: none are used; fingerprints here are test
//! fixtures derived from counters.

// Test code: unwrapping and panicking on an unexpected result is the assertion.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::collections::BTreeSet;
use std::fmt::Debug;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use metrics_util::debugging::{DebugValue, DebuggingRecorder};
use metrics_util::MetricKind;
use proptest::prelude::*;
use tack_minotaur::telemetry::{HALTS_TOTAL, OPERATOR_RESETS_TOTAL, TRIPS_TOTAL};
use tack_minotaur::{
    Detector, Fingerprint, GateOutcome, MinotaurConfig, Resolution, Thread, Trip, TripKind, Walk,
};
use tracing::field::{Field, Visit};
use tracing::span::{Attributes, Id, Record};
use tracing::{Event, Level, Metadata, Subscriber};

fn fp(n: u64) -> Fingerprint {
    Fingerprint::of_bytes(&n.to_le_bytes())
}

// ---------------------------------------------------------------------------
// Minimal capturing tracing subscriber (tracing-subscriber is not a
// dependency of this crate, and only tests/redteam.rs may change).
// ---------------------------------------------------------------------------

#[derive(Clone, Debug)]
struct Captured {
    level: Level,
    kind: &'static str,
    name: String,
    fields: Vec<(String, String)>,
}

#[derive(Clone, Default)]
struct Cap {
    rows: Arc<Mutex<Vec<Captured>>>,
    next: Arc<AtomicU64>,
}

struct FieldVisitor<'a>(&'a mut Vec<(String, String)>);

impl Visit for FieldVisitor<'_> {
    fn record_debug(&mut self, field: &Field, value: &dyn Debug) {
        self.0.push((field.name().to_string(), format!("{value:?}")));
    }
    fn record_str(&mut self, field: &Field, value: &str) {
        self.0.push((field.name().to_string(), value.to_string()));
    }
}

impl Subscriber for Cap {
    fn enabled(&self, _: &Metadata<'_>) -> bool {
        true
    }
    fn new_span(&self, attrs: &Attributes<'_>) -> Id {
        let mut fields = Vec::new();
        attrs.record(&mut FieldVisitor(&mut fields));
        self.rows.lock().unwrap().push(Captured {
            level: *attrs.metadata().level(),
            kind: "span",
            name: attrs.metadata().name().to_string(),
            fields,
        });
        Id::from_u64(self.next.fetch_add(1, Ordering::Relaxed) + 1)
    }
    fn record(&self, _: &Id, values: &Record<'_>) {
        let mut fields = Vec::new();
        values.record(&mut FieldVisitor(&mut fields));
        self.rows.lock().unwrap().push(Captured {
            level: Level::TRACE,
            kind: "span_record",
            name: String::new(),
            fields,
        });
    }
    fn record_follows_from(&self, _: &Id, _: &Id) {}
    fn event(&self, event: &Event<'_>) {
        let mut fields = Vec::new();
        event.record(&mut FieldVisitor(&mut fields));
        self.rows.lock().unwrap().push(Captured {
            level: *event.metadata().level(),
            kind: "event",
            name: event.metadata().name().to_string(),
            fields,
        });
    }
    fn enter(&self, _: &Id) {}
    fn exit(&self, _: &Id) {}
}

fn with_logs<R>(f: impl FnOnce() -> R) -> (R, Vec<Captured>) {
    let cap = Cap::default();
    let rows = cap.rows.clone();
    let r = tracing::subscriber::with_default(cap, f);
    let out = rows.lock().unwrap().clone();
    (r, out)
}

type Row = (MetricKind, String, Vec<(String, String)>, DebugValue);

fn with_metrics<R>(f: impl FnOnce() -> R) -> (R, Vec<Row>) {
    let recorder = DebuggingRecorder::new();
    let snap = recorder.snapshotter();
    let r = metrics::with_local_recorder(&recorder, f);
    let rows = snap
        .snapshot()
        .into_vec()
        .into_iter()
        .map(|(ck, _, _, v)| {
            let (kind, key) = ck.into_parts();
            let labels = key
                .labels()
                .map(|l| (l.key().to_string(), l.value().to_string()))
                .collect();
            (kind, key.name().to_string(), labels, v)
        })
        .collect();
    (r, rows)
}

fn counter_sum(rows: &[Row], name: &str) -> u64 {
    rows.iter()
        .filter(|(k, n, _, _)| *k == MetricKind::Counter && n == name)
        .map(|(_, _, _, v)| match v {
            DebugValue::Counter(c) => *c,
            _ => 0,
        })
        .sum()
}

// ---------------------------------------------------------------------------
// ATTACK 1: bypass of loop detection in degraded mode.
//
// The attacker first spends max_distinct_states cheap, fresh states to fill
// the exact map (the "map flush"). It then loops on one state A, but puts a
// fresh nonce state between every visit: A, n1, A, n2, A, n3, ...
// This is the shape of an agent that repeats the same tool call with the
// same arguments, interleaved with a call whose argument carries a
// timestamp or request id. A is revisited thousands of times against an
// allowance of 3. The streaming Brent detector re-anchors its tortoise at
// offsets 1, 3, 7, 15, ... (all odd) after the first degraded step, and
// then every max_cycle_period (even) steps, so when the first degraded
// state is A the tortoise only ever sits on a nonce and never matches.
// ---------------------------------------------------------------------------

fn map_flush_then_nonce_loop(cfg: &MinotaurConfig, align_on_a: bool) -> (Trip, u64, u64) {
    let mut t = Thread::new(cfg.clone()).unwrap();
    let fill = u64::try_from(cfg.max_distinct_states).unwrap();
    for n in 0..fill {
        t.record(fp(n)).unwrap();
    }
    assert_eq!(t.tracked_states(), cfg.max_distinct_states);
    let a = fp(1 << 40);
    let mut a_visits = 0u64;
    let offset = u64::from(!align_on_a);
    for i in 0.. {
        let s = if (i + offset) % 2 == 0 {
            a_visits += 1;
            a
        } else {
            fp((1 << 41) + i)
        };
        if let Err(trip) = t.record(s) {
            return (trip, a_visits, i + 1);
        }
    }
    unreachable!()
}

#[test]
fn redteam_brent_misses_loop_interleaved_with_fresh_nonces_after_map_flush() {
    let cfg = MinotaurConfig::default();
    let (trip, a_visits, steps_after_fill) = map_flush_then_nonce_loop(&cfg, true);
    let allowed = 1 + u64::from(cfg.revisit_allowance);
    assert!(
        matches!(trip.kind, TripKind::LoopDetected { .. }) && a_visits <= 64,
        "state A was visited {a_visits} times (allowance permits {allowed}) over \
         {steps_after_fill} degraded steps before the walk tripped, and the trip \
         kind was {:?}, not LoopDetected",
        trip.kind
    );
}

/// Control for attack 1: without the map flush, the exact map catches the
/// same pattern immediately. This shows the gap is specific to degraded mode.
#[test]
fn redteam_control_exact_map_catches_nonce_interleaved_loop() {
    let cfg = MinotaurConfig::default();
    let mut t = Thread::new(cfg.clone()).unwrap();
    let a = fp(1 << 40);
    let mut a_visits = 0u64;
    let mut trip = None;
    for i in 0..10_000u64 {
        let s = if i % 2 == 0 {
            a_visits += 1;
            a
        } else {
            fp((1 << 41) + i)
        };
        if let Err(e) = t.record(s) {
            trip = Some(e);
            break;
        }
    }
    let trip = trip.unwrap();
    assert_eq!(
        trip.kind,
        TripKind::LoopDetected {
            period: 2,
            detector: Detector::Exact
        }
    );
    assert_eq!(a_visits, 2 + u64::from(cfg.revisit_allowance));
}

/// Control for attack 1: the opposite alignment (first degraded state is a
/// nonce) is caught by Brent. The attacker chooses the alignment, because
/// the attacker decides which step first overflows the map.
#[test]
fn redteam_control_brent_catches_nonce_loop_when_misaligned() {
    let cfg = MinotaurConfig::default();
    let (trip, a_visits, _) = map_flush_then_nonce_loop(&cfg, false);
    assert_eq!(
        trip.kind,
        TripKind::LoopDetected {
            period: 2,
            detector: Detector::Brent
        }
    );
    assert!(a_visits <= 64, "{a_visits}");
}

// ---------------------------------------------------------------------------
// ATTACK 2: depth bypass through a stale guard.
//
// After a DepthExceeded trip the Thread rewinds to depth 0, but the Rust
// stack is still max_depth frames deep and the innermost guard is still
// live. Its DerefMut still reaches descend(), which succeeds from depth 0.
// A caller that treats RETRY as "try another branch at this level" (instead
// of unwinding to its snapshot) keeps recursing. Real nesting reaches about
// max_depth * max_trips_before_halt before the halt stops it.
// ---------------------------------------------------------------------------

// Edited after the fix: `t` was `&mut Thread`, reached from a guard through
// DerefMut, which no longer exists. `Walk` is the crate's trait for "the root
// Thread or a guard". The body is unchanged.
fn dig(t: &mut dyn Walk, real: u32, max_real: &mut u32, budget: &mut u32) {
    *max_real = (*max_real).max(real);
    while *budget > 0 {
        *budget -= 1;
        match t.descend() {
            Ok(mut child) => {
                dig(&mut child, real + 1, max_real, budget);
                return;
            }
            Err(trip) if trip.outcome == GateOutcome::Retry => continue,
            Err(_) => return,
        }
    }
}

#[test]
fn redteam_stale_guard_can_descend_past_max_depth() {
    let cfg = MinotaurConfig {
        max_depth: 4,
        max_trips_before_halt: 8,
        ..Default::default()
    };
    let mut t = Thread::new(cfg.clone()).unwrap();
    let mut max_real = 0;
    let mut budget = 10_000;
    dig(&mut t, 0, &mut max_real, &mut budget);
    assert!(
        max_real <= cfg.max_depth,
        "real nesting reached {max_real} live guards with max_depth = {}; a stale \
         guard kept accepting descend() after each DepthExceeded trip",
        cfg.max_depth
    );
}

// ---------------------------------------------------------------------------
// ATTACK 3: depth bypass through guard.rewind().
//
// DepthGuard derefs mutably to Thread, so code deep in the walk can call
// rewind(), which zeroes depth while every outer guard is still live.
// Real nesting is then unbounded and nothing trips.
// ---------------------------------------------------------------------------

// Edited after the fix: `t` was `&mut Thread` reached through DerefMut. The
// attack step `t.rewind()` through a guard no longer compiles (rewind needs
// `&mut Thread`, and a guard derefs only to `&Thread`); the compile_fail
// doctests in the crate docs (lib.rs) pin that. The recursion that the
// rewind was meant to unblock is kept, so the runtime assertion still checks
// that real nesting past max_depth trips.
fn deep_with_rewind(t: &mut dyn Walk, real: u32, target: u32) -> Result<u32, Trip> {
    if real == target {
        return Ok(real);
    }
    if t.thread().depth() == t.thread().config().max_depth {
        // Was: t.rewind(); see the comment above.
    }
    let mut g = t.descend()?;
    deep_with_rewind(&mut g, real + 1, target)
}

#[test]
fn redteam_guard_rewind_resets_depth_with_outer_guards_live() {
    let cfg = MinotaurConfig {
        max_depth: 8,
        ..Default::default()
    };
    let mut t = Thread::new(cfg).unwrap();
    let r = deep_with_rewind(&mut t, 0, 400);
    assert!(
        r.is_err(),
        "reached real nesting {:?} with max_depth 8 and no trip, by calling \
         rewind() through a DepthGuard",
        r
    );
}

// ---------------------------------------------------------------------------
// ATTACK 4: halt bypass by whoever holds a guard.
//
// The crate says operator_reset must stay with the orchestrator. But a
// DepthGuard is exactly what gets handed to deeper work, and DerefMut hands
// out &mut Thread. Deeper code can replace the whole Thread (clearing halt,
// trip count and even the config) with std::mem::replace, which also skips
// the operator_reset metric, so the audit trail shows no reset.
// ---------------------------------------------------------------------------

#[test]
fn redteam_guard_holder_can_clear_halt_and_swap_config_silently() {
    let cfg = MinotaurConfig {
        max_steps: 1,
        max_trips_before_halt: 2,
        max_depth: 2,
        ..Default::default()
    };
    let ((still_halted, accepted_after, depth_after), rows) = with_metrics(|| {
        let mut t = Thread::new(cfg.clone()).unwrap();
        // Edited after the fix: a RETRY trip makes the guard stale, so the
        // second walk starts from a fresh guard at the root, as the rollback
        // contract requires. The original reused the stale guard.
        {
            let mut g = t.descend().unwrap();
            g.record(fp(1)).unwrap();
            assert_eq!(g.record(fp(2)).unwrap_err().outcome, GateOutcome::Retry);
        }
        let mut g = t.descend().unwrap();
        g.record(fp(1)).unwrap();
        let e = g.record(fp(2)).unwrap_err();
        assert_eq!(e.outcome, GateOutcome::TerminalBreach);
        assert!(g.is_halted());

        // Deeper code that only ever received the guard. Edited after the
        // fix: the original attack line
        //     std::mem::replace(&mut *g, Thread::new(permissive).unwrap());
        // and g.operator_reset() / g.rewind() no longer compile, because a
        // DepthGuard derefs only to &Thread. The compile_fail doctests in
        // lib.rs pin all three. The permissive config is kept to show what
        // the attacker would have swapped in; everything a guard holder can
        // still do (record, descend) is attempted below.
        let _permissive = MinotaurConfig {
            max_depth: 1 << 16,
            max_steps: 1 << 40,
            max_trips_before_halt: 1 << 16,
            ..Default::default()
        };
        let halted = g.is_halted();
        let accepted = g.record(fp(3)).is_ok();
        let mut deepest = 0;
        {
            // Edited: was `g.descend().unwrap_or_else(|e| panic!("{e}"))`,
            // which panics exactly in the safe case (a halted Thread refuses
            // the descent) and so could never reach the assertion below.
            if let Ok(mut g2) = g.descend() {
                for _ in 0..10 {
                    if let Ok(g3) = g2.descend() {
                        deepest = g3.depth();
                        std::mem::forget(g3);
                    }
                }
            }
        }
        (halted, accepted, deepest)
    });
    let resets = counter_sum(&rows, OPERATOR_RESETS_TOTAL);
    assert!(
        still_halted && !accepted_after,
        "a guard holder cleared the halt without operator_reset (operator_resets_total = \
         {resets}, halts_total = {}); record() after the swap accepted = {accepted_after}; \
         depth then reached {depth_after} against the configured max_depth 2",
        counter_sum(&rows, HALTS_TOTAL)
    );
}

// ---------------------------------------------------------------------------
// ATTACK 5: replay. A caller replays the identical walk forever, rewinding
// just before each cap. Nothing trips and the halt escalation (whose stated
// purpose is to stop a caller that keeps resubmitting) never engages.
// ---------------------------------------------------------------------------

#[test]
fn redteam_replayed_identical_walk_with_rewind_is_never_stopped() {
    let cfg = MinotaurConfig {
        max_steps: 100,
        max_trips_before_halt: 8,
        ..Default::default()
    };
    let mut t = Thread::new(cfg.clone()).unwrap();
    let lifetime_cap = cfg.max_steps * u64::from(cfg.max_trips_before_halt);
    let mut total = 0u64;
    let mut stopped = false;
    'outer: for _walk in 0..1_000 {
        for n in 0..cfg.max_steps {
            if t.record(fp(n)).is_err() {
                stopped = true;
                break 'outer;
            }
            total += 1;
        }
        t.rewind();
    }
    assert!(
        stopped && total <= lifetime_cap,
        "the same {}-step walk was replayed {} times ({total} transitions, {} trips) \
         and was never stopped",
        cfg.max_steps,
        total / cfg.max_steps,
        t.trips()
    );
}

// ---------------------------------------------------------------------------
// ATTACK 6: timing and size side channel from the trip path.
//
// A trip copies the breadcrumb ring and (when warn is enabled) hashes it,
// so trip latency grows with min(steps, breadcrumb_len). An observer that
// times the tripping call learns roughly how long the walk ran.
// ---------------------------------------------------------------------------

fn time_trip_after(steps: u64, k: usize) -> Duration {
    let cfg = MinotaurConfig {
        max_steps: steps,
        breadcrumb_len: k,
        max_distinct_states: 8192,
        max_trips_before_halt: 1 << 16,
        ..Default::default()
    };
    let mut t = Thread::new(cfg).unwrap();
    for n in 0..steps {
        t.record(fp(n)).unwrap();
    }
    let start = Instant::now();
    let e = t.record(fp(1 << 50)).unwrap_err();
    let d = start.elapsed();
    assert_eq!(e.kind, TripKind::StepBudgetExhausted { limit: steps });
    d
}

fn median(mut v: Vec<Duration>) -> Duration {
    v.sort();
    v[v.len() / 2]
}

#[test]
fn redteam_trip_latency_does_not_reveal_walk_length() {
    let ((short, long), _logs) = with_logs(|| {
        let short: Vec<_> = (0..15).map(|_| time_trip_after(4, 4096)).collect();
        let long: Vec<_> = (0..15).map(|_| time_trip_after(4096, 4096)).collect();
        (median(short), median(long))
    });
    // Same measurement with no subscriber (warn off): isolates the path copy
    // from the SHA-256 that only runs when warn logging is enabled.
    let short_quiet = median((0..15).map(|_| time_trip_after(4, 4096)).collect());
    let long_quiet = median((0..15).map(|_| time_trip_after(4096, 4096)).collect());
    let ratio = long.as_secs_f64() / short.as_secs_f64().max(1e-9);
    let ratio_quiet = long_quiet.as_secs_f64() / short_quiet.as_secs_f64().max(1e-9);
    assert!(
        ratio < 4.0,
        "warn on: trip after 4 steps took {short:?}, trip after 4096 steps took {long:?} \
         (ratio {ratio:.1}); warn off: {short_quiet:?} vs {long_quiet:?} (ratio \
         {ratio_quiet:.1}); trip latency reveals the walk length"
    );
}

// ---------------------------------------------------------------------------
// ATTACK 7: metric label cardinality from hostile fingerprints.
// ---------------------------------------------------------------------------

#[test]
fn redteam_metric_labels_stay_closed_under_hostile_input() {
    let (_, rows) = with_metrics(|| {
        let cfg = MinotaurConfig {
            max_depth: 3,
            max_steps: 50,
            max_distinct_states: 8,
            max_untracked_transitions: 5,
            revisit_allowance: 1,
            max_trips_before_halt: 6,
            ..Default::default()
        };
        let mut t = Thread::new(cfg).unwrap();
        let mut seed = 0xdead_beef_u64;
        for _ in 0..2_000 {
            seed = seed.wrapping_mul(6_364_136_223_846_793_005).wrapping_add(1);
            let _ = t.record(fp(seed % 17));
            if seed % 11 == 0 {
                if let Ok(mut g) = t.descend() {
                    let _ = g.descend().map(|mut g2| g2.descend().map(|mut g3| g3.descend().is_ok()));
                }
            }
            if seed % 97 == 0 {
                t.rewind();
            }
            if t.is_halted() && seed % 5 == 0 {
                t.operator_reset();
            }
        }
    });
    let allowed: &[(&str, &[&str])] = &[
        (
            "reason",
            &[
                "depth_exceeded",
                "step_budget_exhausted",
                "loop_detected",
                "state_space_exhausted",
                "halted",
            ],
        ),
        ("outcome", &["retry", "terminal_breach"]),
        ("detector", &["exact", "brent"]),
        ("end", &["trip", "rewind", "operator_reset"]),
    ];
    let mut series = BTreeSet::new();
    for (_, name, labels, _) in &rows {
        assert!(name.starts_with("tack_minotaur_"), "{name}");
        for (k, v) in labels {
            let ok = allowed
                .iter()
                .any(|(ak, avs)| ak == k && avs.contains(&v.as_str()));
            assert!(ok, "label {k}={v} on {name} is outside the closed set");
        }
        series.insert((name.clone(), labels.clone()));
    }
    assert!(series.len() <= 40, "{} series", series.len());
    assert!(counter_sum(&rows, TRIPS_TOTAL) > 0);
}

// ---------------------------------------------------------------------------
// ATTACK 8: raw state or fingerprint leakage into logs and spans, and hash
// truncation.
// ---------------------------------------------------------------------------

#[test]
fn redteam_logs_carry_no_fingerprints_and_no_truncated_hashes() {
    let recorded: Vec<Fingerprint> = (0..40).map(|n| fp(n % 20)).collect();
    let (_, logs) = with_logs(|| {
        let mut t = Thread::new(MinotaurConfig {
            max_distinct_states: 10,
            revisit_allowance: 0,
            max_trips_before_halt: 2,
            ..Default::default()
        })
        .unwrap();
        for f in &recorded {
            let _ = t.record(*f);
        }
        let _ = t.record(fp(1));
        t.operator_reset();
    });
    assert!(logs.iter().any(|r| r.kind == "event"), "no events captured");
    let hexes: Vec<String> = recorded.iter().map(Fingerprint::to_hex).collect();
    let mut digests = 0;
    for r in &logs {
        for (k, v) in &r.fields {
            for h in &hexes {
                assert!(
                    !v.contains(&h[..16]),
                    "{} {} field {k} leaks a fingerprint: {v}",
                    r.kind,
                    r.name
                );
            }
            if k == "path_sha256" {
                digests += 1;
                assert_eq!(v.len(), 64, "truncated digest {v}");
                assert!(v.bytes().all(|b| b.is_ascii_hexdigit()));
            }
        }
    }
    assert!(digests > 0, "no path_sha256 field seen");
}

// ---------------------------------------------------------------------------
// ATTACK 9: log and metric flood from a halted Thread (DoS by amplification).
// ---------------------------------------------------------------------------

#[test]
fn redteam_halted_refusal_flood_is_cheap_and_quiet() {
    let ((), logs) = with_logs(|| {
        let mut t = Thread::new(MinotaurConfig {
            max_steps: 1,
            max_trips_before_halt: 1,
            breadcrumb_len: 4096,
            ..Default::default()
        })
        .unwrap();
        t.record(fp(0)).unwrap();
        let e = t.record(fp(1)).unwrap_err();
        assert_eq!(e.resolution, Resolution::Halt);
        for n in 0..50_000u64 {
            let e = t.record(fp(n)).unwrap_err();
            assert_eq!(e.kind, TripKind::Halted);
            assert_eq!(e.outcome, GateOutcome::TerminalBreach);
            assert!(e.path.is_empty());
            assert_eq!(t.steps(), 0);
            assert_eq!(t.breadcrumbs().len(), 0);
        }
    });
    let loud = logs
        .iter()
        .filter(|r| r.kind == "event" && r.level <= Level::WARN)
        .count();
    assert_eq!(loud, 1, "expected exactly the one halting error event");
}

// ---------------------------------------------------------------------------
// ATTACK 10: panics and overflow at the config ceilings (overflow checks on).
// ---------------------------------------------------------------------------

#[test]
fn redteam_ceiling_config_does_not_panic_or_overflow() {
    let cfg = MinotaurConfig {
        max_depth: 1 << 16,
        max_steps: 1 << 40,
        max_distinct_states: 1,
        revisit_allowance: 1 << 16,
        breadcrumb_len: 1,
        max_cycle_period: 1 << 24,
        max_untracked_transitions: 1 << 40,
        max_trips_before_halt: 1 << 16,
    };
    let mut t = Thread::new(cfg.clone()).unwrap();
    // Leak every guard: depth counts to the ceiling without recursion.
    for _ in 0..cfg.max_depth {
        let g = t.descend().unwrap();
        std::mem::forget(g);
    }
    let e = t.descend().unwrap_err();
    assert_eq!(e.kind, TripKind::DepthExceeded { limit: 1 << 16 });
    // Degraded ping-pong with the largest allowance.
    t.record(fp(0)).unwrap();
    let mut trip = None;
    for i in 0..400_000u64 {
        if let Err(e) = t.record(fp(1 + i % 2)) {
            trip = Some(e);
            break;
        }
    }
    let trip = trip.unwrap();
    assert!(matches!(
        trip.kind,
        TripKind::LoopDetected {
            period: 2,
            detector: Detector::Brent
        }
    ));
    assert_eq!(trip.path.len(), 1);
}

// ---------------------------------------------------------------------------
// ATTACK 11: fail-open and invariant breaks under random operation mixes,
// including rewind and operator_reset issued through guards.
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
enum Op {
    Descend,
    Ascend,
    Record(u8),
    Rewind,
    Reset,
}

fn op() -> impl Strategy<Value = Op> {
    prop_oneof![
        3 => Just(Op::Descend),
        2 => Just(Op::Ascend),
        8 => any::<u8>().prop_map(Op::Record),
        1 => Just(Op::Rewind),
        1 => Just(Op::Reset),
    ]
}

fn check_invariants(t: &Thread, cap0: usize) {
    let c = t.config();
    assert!(t.depth() <= c.max_depth);
    assert!(t.steps() <= c.max_steps);
    assert!(t.tracked_states() <= c.max_distinct_states);
    assert_eq!(t.tracked_capacity(), cap0);
    assert!(t.breadcrumbs().len() <= c.breadcrumb_len);
    assert!(t.trips() <= c.max_trips_before_halt);
}

// Edited after the fix: `t` was `&mut Thread` reached through DerefMut.
// rewind() and operator_reset() through a guard no longer compile (see the
// compile_fail doctests in lib.rs), so a Rewind or Reset op unwinds to the
// root holder, which applies it; the op stream and its random interleaving
// are unchanged. Returns the op the root must apply, if any.
fn run_ops(t: &mut dyn Walk, ops: &[Op], i: &mut usize, cap0: usize) -> Option<Op> {
    while *i < ops.len() {
        let o = ops[*i].clone();
        *i += 1;
        let r: Option<Trip> = match o {
            Op::Descend => match t.descend() {
                Ok(mut g) => {
                    if let Some(root_op) = run_ops(&mut g, ops, i, cap0) {
                        return Some(root_op);
                    }
                    None
                }
                Err(e) => Some(e),
            },
            Op::Ascend => return None,
            Op::Record(n) => t.record(fp(u64::from(n % 24))).err(),
            Op::Rewind | Op::Reset => return Some(o),
        };
        if let Some(e) = r {
            assert_ne!(e.outcome, GateOutcome::Pass, "a trip mapped to PASS");
            assert!(e.path.len() <= t.thread().config().breadcrumb_len);
            if e.kind == TripKind::Halted {
                assert_eq!(e.outcome, GateOutcome::TerminalBreach);
            }
        }
        check_invariants(t.thread(), cap0);
    }
    None
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 256, ..ProptestConfig::default() })]
    #[test]
    fn redteam_random_op_mix_never_fails_open_or_breaks_caps(
        ops in proptest::collection::vec(op(), 0..400),
        max_depth in 1u32..6,
        max_steps in 1u64..60,
        states in 1usize..12,
        allowance in 0u32..3,
        k in 1usize..6,
        period in 1u64..8,
        untracked in 0u64..10,
        halt in 1u32..5,
    ) {
        let cfg = MinotaurConfig {
            max_depth,
            max_steps,
            max_distinct_states: states,
            revisit_allowance: allowance,
            breadcrumb_len: k,
            max_cycle_period: period,
            max_untracked_transitions: untracked,
            max_trips_before_halt: halt,
        };
        let mut t = Thread::new(cfg).unwrap();
        let cap0 = t.tracked_capacity();
        let mut i = 0;
        while i < ops.len() {
            match run_ops(&mut t, &ops, &mut i, cap0) {
                Some(Op::Rewind) => t.rewind(),
                Some(Op::Reset) => t.operator_reset(),
                _ => {}
            }
            check_invariants(&t, cap0);
        }
        check_invariants(&t, cap0);
    }
}
