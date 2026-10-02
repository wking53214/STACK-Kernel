//! Independent red-team tests for stack-trident.
//!
//! Every test asserts the SAFE behaviour, so a test FAILS while the weakness
//! it names exists. Every key here is a TEST FIXTURE derived from a public
//! label (see tests/common/mod.rs) and must never be used outside tests.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use std::collections::BTreeSet;
use std::fmt::Write as _;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{mpsc, Arc, Mutex};
use std::time::{Duration, Instant};

use common::*;
use metrics::{Counter, CounterFn, Gauge, Histogram, Key, KeyName, Metadata, Recorder, SharedString, Unit};
use metrics_util::debugging::{DebugValue, DebuggingRecorder};
use metrics_util::MetricKind;
use serde_json::{json, Map, Value};
use stack_trident::telemetry as t;
use stack_trident::{
    seal, seal_for, Clock, EnvelopeDraft, GateOutcome, GatePosition, HandoffEnvelope, KeyRing, ManualClock, Nonce,
    ReasonCode, Trident, TridentConfig, Verdict,
};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn draft(seq: u64, issued_at: u64, payload: Value) -> EnvelopeDraft {
    EnvelopeDraft {
        sequence: seq,
        issued_at_unix_ms: issued_at,
        nonce: nonce_for(seq),
        gate_position: GatePosition::Alpha,
        gate_outcome: GateOutcome::Pass,
        payload,
    }
}

fn ring_of(labels: &[&str]) -> KeyRing {
    let mut ring = KeyRing::new(16);
    for l in labels {
        ring.insert(fixture_key(l)).unwrap();
    }
    ring
}

/// An envelope the key holder for "a" signed with a digest that does not
/// match its payload (a transplanted verdict). Authentic, TERMINAL_BREACH,
/// counted by the default breaker.
fn transplanted(fx: &Fx, seq: u64) -> HandoffEnvelope {
    let mut env = fx.sealed(seq);
    env.payload = json!({"swapped": seq});
    remac(&mut env, "a");
    env
}

/// Tiny deterministic PRNG for fuzz loops (xorshift64*).
struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545_f491_4f6c_dd1d)
    }
    fn below(&mut self, n: usize) -> usize {
        (self.next() % (n as u64)) as usize
    }
}

// ---- A metrics recorder that pauses a verification at a fixed point -----
//
// `tack_trident_hashed_bytes_total` is incremented after the custody check
// and the key-ring snapshot, and before the prong 3 lock is taken. Pausing
// inside that increment gives a deterministic window in which another
// thread can change receiver state while the paused verification holds
// stale custody and key-ring facts.

struct Pause {
    reached: Mutex<Option<mpsc::Sender<()>>>,
    go: Mutex<Option<mpsc::Receiver<()>>>,
}

impl CounterFn for Pause {
    fn increment(&self, _value: u64) {
        let tx = self.reached.lock().unwrap().take();
        if let Some(tx) = tx {
            tx.send(()).unwrap();
            let rx = self.go.lock().unwrap().take();
            if let Some(rx) = rx {
                rx.recv().unwrap();
            }
        }
    }
    fn absolute(&self, _value: u64) {}
}

struct PauseRecorder(Arc<Pause>);

impl Recorder for PauseRecorder {
    fn describe_counter(&self, _: KeyName, _: Option<Unit>, _: SharedString) {}
    fn describe_gauge(&self, _: KeyName, _: Option<Unit>, _: SharedString) {}
    fn describe_histogram(&self, _: KeyName, _: Option<Unit>, _: SharedString) {}
    fn register_counter(&self, key: &Key, _: &Metadata<'_>) -> Counter {
        if key.name() == t::HASHED_BYTES_TOTAL {
            Counter::from_arc(Arc::clone(&self.0))
        } else {
            Counter::noop()
        }
    }
    fn register_gauge(&self, _: &Key, _: &Metadata<'_>) -> Gauge {
        Gauge::noop()
    }
    fn register_histogram(&self, _: &Key, _: &Metadata<'_>) -> Histogram {
        Histogram::noop()
    }
}

/// Runs `trident.verify(env)` on another thread, pauses it between the
/// custody check and prong 3, runs `during` on this thread, then lets the
/// paused verification finish and returns its verdict.
fn verify_with_interleave(trident: &Trident, env: &HandoffEnvelope, during: impl FnOnce()) -> Verdict {
    let (reached_tx, reached_rx) = mpsc::channel();
    let (go_tx, go_rx) = mpsc::channel();
    let rec = PauseRecorder(Arc::new(Pause {
        reached: Mutex::new(Some(reached_tx)),
        go: Mutex::new(Some(go_rx)),
    }));
    std::thread::scope(|s| {
        let h = s.spawn(|| metrics::with_local_recorder(&rec, || trident.verify(env)));
        reached_rx.recv_timeout(Duration::from_secs(10)).expect("verification never reached the pause point");
        during();
        go_tx.send(()).unwrap();
        h.join().unwrap()
    })
}

// ---- Metric capture ------------------------------------------------------

type Seen = (MetricKind, String, Vec<(String, String)>, DebugValue);

fn capture<F: FnOnce()>(f: F) -> Vec<Seen> {
    let recorder = DebuggingRecorder::new();
    let snap = recorder.snapshotter();
    metrics::with_local_recorder(&recorder, f);
    snap.snapshot()
        .into_vec()
        .into_iter()
        .map(|(ck, _, _, v)| {
            let (kind, key) = ck.into_parts();
            let labels = key
                .labels()
                .map(|l| (l.key().to_owned(), l.value().to_owned()))
                .collect();
            (kind, key.name().to_owned(), labels, v)
        })
        .collect()
}

fn counter_sum(seen: &[Seen], name: &str) -> u64 {
    seen.iter()
        .filter(|(k, n, _, _)| *k == MetricKind::Counter && n == name)
        .map(|(_, _, _, v)| match v {
            DebugValue::Counter(c) => *c,
            _ => 0,
        })
        .sum()
}

// ---- Tracing capture -----------------------------------------------------

// A global subscriber (so tracing's per-callsite interest cache is never
// "off" for any callsite, whichever thread hits it first) that records only
// on threads that opted in through a thread-local sink.

thread_local! {
    static SINK: std::cell::RefCell<Option<Arc<Mutex<Vec<String>>>>> = const { std::cell::RefCell::new(None) };
}

fn sink_push(s: String) {
    SINK.with(|k| {
        if let Some(v) = k.borrow().as_ref() {
            v.lock().unwrap().push(s);
        }
    });
}

struct Vis<'a>(&'a mut String);
impl tracing::field::Visit for Vis<'_> {
    fn record_debug(&mut self, f: &tracing::field::Field, v: &dyn std::fmt::Debug) {
        let _ = write!(self.0, "{}={:?};", f.name(), v);
    }
    fn record_str(&mut self, f: &tracing::field::Field, v: &str) {
        let _ = write!(self.0, "{}={};", f.name(), v);
    }
}

struct CaptureSub {
    next: AtomicU64,
}

impl tracing::Subscriber for CaptureSub {
    fn enabled(&self, _: &tracing::Metadata<'_>) -> bool {
        true
    }
    fn new_span(&self, attrs: &tracing::span::Attributes<'_>) -> tracing::span::Id {
        let mut s = format!("SPAN {} ", attrs.metadata().name());
        attrs.record(&mut Vis(&mut s));
        sink_push(s);
        tracing::span::Id::from_u64(self.next.fetch_add(1, Ordering::SeqCst))
    }
    fn record(&self, _: &tracing::span::Id, values: &tracing::span::Record<'_>) {
        let mut s = String::from("RECORD ");
        values.record(&mut Vis(&mut s));
        sink_push(s);
    }
    fn record_follows_from(&self, _: &tracing::span::Id, _: &tracing::span::Id) {}
    fn event(&self, e: &tracing::Event<'_>) {
        let mut s = format!("EVENT {} ", e.metadata().level());
        e.record(&mut Vis(&mut s));
        sink_push(s);
    }
    fn enter(&self, _: &tracing::span::Id) {}
    fn exit(&self, _: &tracing::span::Id) {}
}

fn capture_logs<F: FnOnce()>(f: F) -> Vec<String> {
    static INIT: std::sync::Once = std::sync::Once::new();
    INIT.call_once(|| {
        tracing::subscriber::set_global_default(CaptureSub {
            next: AtomicU64::new(1),
        })
        .unwrap();
    });
    let buf = Arc::new(Mutex::new(Vec::new()));
    SINK.with(|k| *k.borrow_mut() = Some(Arc::clone(&buf)));
    f();
    SINK.with(|k| *k.borrow_mut() = None);
    let out = buf.lock().unwrap().clone();
    out
}

// ===========================================================================
// 1. TOCTOU: custody facts are read outside the prong 3 critical section.
// ===========================================================================

/// The quarantine check runs in its own lock section, before the prongs.
/// If the breaker quarantines the sender while a genuine envelope from it
/// is between that check and the commit, the envelope is still accepted,
/// after the quarantine took effect.
#[test]
fn rt_toctou_quarantine_trip_during_verification_is_honoured() {
    let fx = setup();
    let valid = fx.sealed(1);
    let breaches: Vec<HandoffEnvelope> = (100..105).map(|s| transplanted(&fx, s)).collect();
    let v = verify_with_interleave(&fx.trident, &valid, || {
        for b in &breaches {
            let _ = fx.trident.verify(b);
        }
        assert_eq!(fx.trident.quarantined().unwrap(), vec![fx.fp_a], "setup: sender must be quarantined");
    });
    assert!(
        !v.is_accepted(),
        "an envelope from a sender quarantined before its commit was accepted: {v:?}"
    );
}

/// `operator_halt` sets the halted flag, but `evaluate` only checks it on
/// entry. A verification already past the entry check commits and accepts
/// after `operator_halt` has returned.
#[test]
fn rt_toctou_operator_halt_stops_in_flight_acceptance() {
    let fx = setup();
    let valid = fx.sealed(1);
    let v = verify_with_interleave(&fx.trident, &valid, || {
        fx.trident.operator_halt();
        assert!(fx.trident.is_halted());
    });
    assert!(
        !v.is_accepted(),
        "an envelope was accepted after operator_halt returned: {v:?}"
    );
}

/// `replace_keyring` revokes sender A. A verification that snapshotted the
/// old ring before the swap still accepts A's envelope after
/// `replace_keyring` has returned Ok, and re-creates sender state for a
/// fingerprint that is no longer in the ring.
#[test]
fn rt_toctou_keyring_revocation_stops_in_flight_acceptance() {
    let fx = setup();
    let valid = fx.sealed(1);
    let v = verify_with_interleave(&fx.trident, &valid, || {
        fx.trident.replace_keyring(ring_of(&["b"])).unwrap();
    });
    assert!(
        !v.is_accepted(),
        "an envelope signed by a revoked key was accepted after replace_keyring returned: {v:?}"
    );
}

// ===========================================================================
// 2. Replay and ordering
// ===========================================================================

/// An envelope accepted by one receiver is accepted again by a second
/// receiver that trusts the same sender key: nothing in the MAC input names
/// the intended recipient, so a captured envelope can be redirected.
#[test]
fn rt_cross_receiver_replay_is_refused() {
    // Two receivers can only be told apart if they have distinct
    // identities: each is configured with its own audience, and the sender
    // seals for receiver 1.
    let fx1 = setup_with(TridentConfig {
        audience: "receiver-1".into(),
        ..TridentConfig::default()
    });
    let fx2 = setup_with(TridentConfig {
        audience: "receiver-2".into(),
        ..TridentConfig::default()
    });
    let env = seal_for(draft(1, fx1.now(), payload_for(1)), &fx1.key_a, "receiver-1", &fx1.cfg.limits()).unwrap();
    assert!(fx1.trident.verify_wire(&fx1.wire(&env)).is_accepted());
    let v = fx2.trident.verify_wire(&fx1.wire(&env));
    assert!(
        !v.is_accepted(),
        "an envelope meant for receiver 1 was accepted by receiver 2 (no audience binding): {v:?}"
    );
}

/// The epoch floor is `now + future_skew` at start. If the receiver's clock
/// at restart is behind the clock it had when it accepted an envelope, the
/// floor lands below that envelope's issue time and the (empty) replay
/// cache lets it through again.
#[test]
fn rt_replay_after_restart_with_clock_regression_is_refused() {
    let fx = setup();
    let env = fx.sealed(1);
    assert!(fx.trident.verify(&env).is_accepted());
    // Restart: fresh process state, clock stepped back 30 s (RTC before NTP
    // sync, VM migration, manual correction). The only state that crosses a
    // process boundary is what the caller persisted: the high-water mark.
    let persisted = fx.trident.high_water_ms().unwrap();
    let cfg = TridentConfig {
        restored_high_water_ms: persisted,
        ..fx.cfg.clone()
    };
    let clock = Arc::new(ManualClock::new(fx.now() - 30_000));
    let restarted = Trident::new(cfg, ring_of(&["a", "b"]), clock.clone()).unwrap();
    clock.advance(30_000);
    let v = restarted.verify(&env);
    assert!(
        !v.is_accepted(),
        "a previously accepted envelope was replayed into a restarted receiver: {v:?}"
    );
}

/// Same hole without a restart: an operator reset clears the replay cache
/// and every sequence, and trusts the current clock for the new floor.
#[test]
fn rt_replay_after_operator_reset_with_clock_regression_is_refused() {
    let fx = setup();
    let env = fx.sealed(1);
    assert!(fx.trident.verify(&env).is_accepted());
    fx.clock.set(fx.now() - 30_000);
    fx.trident.operator_halt();
    fx.trident.operator_reset();
    fx.clock.advance(30_000);
    let v = fx.trident.verify(&env);
    assert!(
        !v.is_accepted(),
        "a previously accepted envelope was replayed after an operator reset: {v:?}"
    );
}

/// Off-by-one between replay-cache expiry (`expires_at <= now`) and the
/// stale check (`issued_at < now - past_skew`). Once a key-ring swap has
/// dropped the sender's sequence, an envelope issued at the future-skew
/// edge is replayable at exactly `accepted_at + past + future`.
#[test]
fn rt_replay_at_retention_boundary_after_keyring_churn_is_refused() {
    let fx = setup();
    let accepted_at = fx.now();
    let env = seal(
        draft(1, accepted_at + fx.cfg.max_future_skew_ms, payload_for(1)),
        &fx.key_a,
        &fx.cfg.limits(),
    )
    .unwrap();
    assert!(fx.trident.verify(&env).is_accepted());
    // Routine ring reload that briefly lacks A (rotation rollback, config
    // reload), then restores it.
    fx.trident.replace_keyring(ring_of(&["b"])).unwrap();
    fx.trident.replace_keyring(ring_of(&["a", "b"])).unwrap();
    fx.clock.set(accepted_at + fx.cfg.replay_retention_ms());
    let v = fx.trident.verify(&env);
    assert!(!v.is_accepted(), "the same envelope was accepted twice: {v:?}");
}

/// A key-ring swap that drops and restores a sender resets its sequence
/// high-water mark, so an older envelope that was refused as out of order
/// is accepted after a newer one: ordering regresses.
#[test]
fn rt_sequence_does_not_regress_after_keyring_churn() {
    let fx = setup();
    let e1 = fx.sealed(1);
    let e2 = fx.sealed(2);
    assert!(fx.trident.verify(&e2).is_accepted());
    assert!(fx.trident.verify(&e1).refusal().unwrap().has(ReasonCode::SequenceNotIncreasing));
    fx.trident.replace_keyring(ring_of(&["b"])).unwrap();
    fx.trident.replace_keyring(ring_of(&["a", "b"])).unwrap();
    let v = fx.trident.verify(&e1);
    assert!(
        !v.is_accepted(),
        "sequence 1 was accepted after sequence 2 from the same sender: {v:?}"
    );
}

/// The replay cache is shared by all senders. One key holder filling it
/// makes every other sender's valid envelopes RETRY (replay_cache_full),
/// and the breaker never sees it because each envelope is valid.
#[test]
fn rt_one_sender_cannot_exhaust_replay_cache_for_others() {
    let cfg = TridentConfig {
        replay_cache_capacity: 64,
        ..TridentConfig::default()
    };
    let fx = setup_with(cfg);
    for seq in 1..=64 {
        assert!(fx.trident.verify(&fx.sealed(seq)).is_accepted(), "seq {seq}");
    }
    let v = fx.trident.verify(&fx.sealed_by(&fx.key_b, 1));
    assert!(
        v.is_accepted(),
        "sender B was refused because sender A filled the shared replay cache: {:?}",
        v.reasons()
    );
}

/// The sender table is never evicted except by a ring swap, and the ring
/// size is never checked against it. A ring larger than
/// `max_tracked_senders` leaves the later senders refused forever.
#[test]
fn rt_ring_larger_than_sender_table_is_refused_or_evicts() {
    let cfg = TridentConfig {
        max_tracked_senders: 1,
        ..TridentConfig::default()
    };
    let clock = Arc::new(ManualClock::new(T0));
    let built = Trident::new(cfg.clone(), ring_of(&["a", "b"]), clock.clone());
    let Ok(trident) = built else {
        return; // Safe: a ring the table cannot hold is refused at start.
    };
    clock.advance(cfg.max_future_skew_ms + 1);
    let now = clock.now_unix_ms();
    let a = seal(draft(1, now, payload_for(1)), &fixture_key("a"), &cfg.limits()).unwrap();
    assert!(trident.verify(&a).is_accepted());
    // Hours later A is idle, B is still locked out.
    clock.advance(3_600_000);
    let now = clock.now_unix_ms();
    let b = seal(draft(1, now, payload_for(1)), &fixture_key("b"), &cfg.limits()).unwrap();
    let v = trident.verify(&b);
    assert!(
        v.is_accepted(),
        "ring member B is permanently refused because idle A holds the only table slot: {:?}",
        v.reasons()
    );
}

// ===========================================================================
// 3. Outcome mapping
// ===========================================================================

/// An envelope whose sender gate said TERMINAL_BREACH is returned with
/// Trident outcome PASS. Under the kernel's CNS precedence the combined
/// outcome must be the worst of the two, so a consumer that follows the
/// convention (act on `verdict.outcome()`) proceeds on a refused subject.
#[test]
fn rt_upstream_terminal_breach_is_not_reported_as_pass() {
    let fx = setup();
    let mut d = draft(1, fx.now(), json!({"refused": true}));
    d.gate_outcome = GateOutcome::TerminalBreach;
    let env = seal(d, &fx.key_a, &fx.cfg.limits()).unwrap();
    let v = fx.trident.verify(&env);
    assert_ne!(
        v.outcome(),
        GateOutcome::Pass,
        "upstream TERMINAL_BREACH surfaced as Trident PASS"
    );
}

/// Unknown and malformed inputs are never PASS, and a verdict with no
/// reasons is never produced. Empty ring, garbage fields, seconds instead of
/// milliseconds, a clock before 1970 and a clock at u64::MAX.
#[test]
fn rt_fail_closed_and_unit_confusion() {
    let fx = setup();
    // Seconds instead of milliseconds.
    let secs = seal(draft(1, fx.now() / 1000, payload_for(1)), &fx.key_a, &fx.cfg.limits()).unwrap();
    let r = fx.trident.verify(&secs);
    assert!(r.refusal().unwrap().has(ReasonCode::Stale), "{r:?}");
    // Empty ring.
    let empty = Trident::new(TridentConfig::default(), KeyRing::new(4), fx.clock.clone()).unwrap();
    fx.clock.advance(10_000);
    assert!(!empty.verify(&fx.sealed(2)).is_accepted());
    // Pre-1970 clock (SystemClock reads 0) and a saturated clock.
    for at in [0u64, u64::MAX] {
        let c = Arc::new(ManualClock::new(at));
        let tr = Trident::new(TridentConfig::default(), ring_of(&["a"]), c.clone()).unwrap();
        let e = seal(draft(1, fx.now(), payload_for(1)), &fx.key_a, &fx.cfg.limits()).unwrap();
        let v = tr.verify(&e);
        assert!(!v.is_accepted(), "clock {at}: {v:?}");
        assert!(!v.reasons().is_empty());
        let e2 = seal(draft(2, at.min(tack_trident::MAX_SAFE_INTEGER), payload_for(2)), &fx.key_a, &fx.cfg.limits()).unwrap();
        assert!(!tr.verify(&e2).is_accepted(), "clock {at}");
    }
    // In-process u64 fields above 2^53 - 1 are refused, not wrapped.
    let mut big = fx.sealed(3);
    big.sequence = u64::MAX;
    let v = fx.trident.verify(&big);
    assert!(v.refusal().unwrap().has(ReasonCode::IntegerOutOfRange), "{v:?}");
    // Every refusal carries at least one reason and is never PASS.
    let mut rng = Rng(0x9e37_79b9_7f4a_7c15);
    for _ in 0..500 {
        let mut e = fx.sealed(4);
        match rng.below(6) {
            0 => e.sender = "Z".repeat(rng.below(80)),
            1 => e.mac = format!("{:064x}", rng.next()),
            2 => e.gate_outcome = "PASS".into(),
            3 => e.nonce.clear(),
            4 => e.version = rng.next() % 5 + 2,
            _ => e.subject_digest = "0".repeat(64),
        }
        let v = fx.trident.verify(&e);
        assert!(!v.is_accepted());
        assert_ne!(v.outcome(), GateOutcome::Pass);
        assert!(!v.reasons().is_empty());
    }
}

// ===========================================================================
// 4. Breaker abuse and masking
// ===========================================================================

/// A keyless attacker (forgeries naming A) and an eavesdropper (replays of
/// a genuine envelope) cannot quarantine A under the default attribution.
#[test]
fn rt_keyless_and_replay_floods_cannot_quarantine_a_sender() {
    let fx = setup();
    let genuine = fx.sealed(1);
    assert!(fx.trident.verify(&genuine).is_accepted());
    for i in 0..50u64 {
        let mut forged = fx.sealed(10 + i);
        forged.mac = format!("{:064x}", i);
        assert!(!fx.trident.verify(&forged).is_accepted());
        assert!(!fx.trident.verify(&genuine).is_accepted());
        assert!(!fx.trident.verify_wire(&fx.wire(&genuine)).is_accepted());
    }
    assert!(fx.trident.quarantined().unwrap().is_empty());
    assert!(fx.trident.verify(&fx.sealed(100)).is_accepted());
}

/// A keyless prober naming A cannot learn A's sequence counter or replay
/// cache: the reply and the reason metrics are identical whether the probe
/// reuses an accepted nonce or a lower sequence or not.
#[test]
fn rt_masking_hides_sender_freshness_state_from_forgers() {
    let fx = setup();
    let accepted = fx.sealed(50);
    assert!(fx.trident.verify(&accepted).is_accepted());
    let probe = |seq: u64, nonce: Nonce| {
        let mut e = seal(
            EnvelopeDraft {
                nonce,
                ..draft(seq, fx.now(), payload_for(seq))
            },
            &fx.key_x,
            &fx.cfg.limits(),
        )
        .unwrap();
        e.sender = fx.fp_a.to_hex();
        let mut verdict = None;
        let seen = capture(|| verdict = Some(fx.trident.verify(&e)));
        let mut labels: Vec<Vec<(String, String)>> = seen
            .into_iter()
            .filter(|(_, n, _, _)| n == t::CHECK_FAILURES_TOTAL)
            .map(|(_, _, l, _)| l)
            .collect();
        labels.sort();
        (verdict.unwrap().refusal().unwrap().clone(), labels)
    };
    let hit = probe(50, nonce_for(50)); // replayed nonce, equal sequence
    let miss = probe(51, nonce_for(51)); // fresh nonce, higher sequence
    assert_eq!(hit.0, miss.0);
    assert_eq!(hit.1, miss.1);
}

// ===========================================================================
// 5. Telemetry abuse
// ===========================================================================

/// Envelopes stuffed with attacker-chosen strings never mint new metric
/// label values: every label is from the closed vocabularies.
#[test]
fn rt_metric_labels_stay_closed_under_attacker_strings() {
    let fx = setup();
    let mut rng = Rng(42);
    let seen = capture(|| {
        for i in 0..300u64 {
            let mut e = fx.sealed(i + 1);
            let junk: String = (0..rng.below(40)).map(|_| char::from(b'!' + (rng.below(90) as u8))).collect();
            match i % 5 {
                0 => e.sender = junk,
                1 => e.gate_outcome = junk,
                2 => e.gate_position = junk,
                3 => e.nonce = junk,
                _ => e.payload = json!({ junk: "x" }),
            }
            let _ = fx.trident.verify(&e);
            let wire = format!("{{\"{}\":1}}", "k".repeat(rng.below(30)));
            let _ = fx.trident.verify_wire(wire.as_bytes());
        }
    });
    let reasons: BTreeSet<&str> = ReasonCode::ALL.iter().map(|r| r.as_str()).collect();
    let checks: BTreeSet<&str> =
        ["admission", "custody", "authenticity", "binding", "freshness", "capacity"].into_iter().collect();
    let outcomes: BTreeSet<&str> = ["pass", "retry", "terminal_breach"].into_iter().collect();
    let resolutions: BTreeSet<&str> = ["accept", "reject", "quarantine", "halt"].into_iter().collect();
    for (_, name, labels, _) in &seen {
        assert!(name.starts_with("tack_trident_"), "{name}");
        for (k, v) in labels {
            let ok = match k.as_str() {
                "reason" => reasons.contains(v.as_str()),
                "check" => checks.contains(v.as_str()),
                "outcome" => outcomes.contains(v.as_str()),
                "resolution" => resolutions.contains(v.as_str()),
                "cause" => v == "poisoned" || v == "operator",
                _ => false,
            };
            assert!(ok, "open label {k}={v:?} on {name}");
        }
    }
}

/// Raw input never reaches the log, a hostile sender string with a newline
/// is never echoed (no log injection), and every logged digest is a full
/// 64-hex SHA-256.
#[test]
fn rt_logs_never_carry_raw_input_or_attacker_strings() {
    let fx = setup();
    const MARK: &str = "SECRET-PAYLOAD-MARKER-7f3a";
    const INJECT: &str = "INJECTED\nlevel=ERROR forged=1";
    let lines = capture_logs(|| {
        let mut e = seal(draft(1, fx.now(), json!({"s": MARK})), &fx.key_a, &fx.cfg.limits()).unwrap();
        let _ = fx.trident.verify_wire(&fx.wire(&e));
        e.sender = INJECT.into();
        let _ = fx.trident.verify(&e);
        let mut e2 = fx.sealed(2);
        e2.gate_position = INJECT.into();
        e2.payload = json!({ INJECT: MARK });
        let _ = fx.trident.verify(&e2);
        let raw = format!("{{\"x\":\"{MARK}\"}}");
        let _ = fx.trident.verify_wire(raw.as_bytes());
        for b in (100..105).map(|s| transplanted(&fx, s)) {
            let _ = fx.trident.verify(&b);
        }
    });
    assert!(!lines.is_empty(), "capture subscriber saw nothing");
    let mut digests = 0;
    for l in &lines {
        assert!(!l.contains(MARK), "raw payload in log: {l}");
        assert!(!l.contains("INJECTED"), "attacker string in log: {l}");
        for part in l.split(';') {
            if let Some(d) = part.find("input_sha256=").map(|i| &part[i + "input_sha256=".len()..]) {
                digests += 1;
                assert_eq!(d.len(), 64, "{l}");
                assert!(d.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)), "{l}");
            }
        }
    }
    assert!(digests >= 4, "expected digests in the log, saw {digests}");
}

// ===========================================================================
// 6. Equal work, amplification, bounds
// ===========================================================================

/// Malformed sender, unknown sender and known sender with a bad MAC do the
/// same prong work, and prong work per wire byte is bounded (no
/// amplification beyond a small constant).
#[test]
fn rt_equal_work_and_bounded_amplification() {
    let fx = setup();
    let base = fx.sealed(1);
    let mut bad_mac = base.clone();
    bad_mac.mac = "ab".repeat(32);
    let mut unknown = base.clone();
    unknown.sender = "cd".repeat(32);
    let mut malformed = base.clone();
    malformed.sender = "g".repeat(64);
    let hashed = |e: &HandoffEnvelope| {
        let s = capture(|| {
            let _ = fx.trident.verify(e);
        });
        counter_sum(&s, t::HASHED_BYTES_TOTAL)
    };
    let (a, b, c) = (hashed(&bad_mac), hashed(&unknown), hashed(&malformed));
    assert_eq!(a, b);
    assert_eq!(a, c);
    // Largest accepted payload: prong hashing stays within 2x the wire.
    let big = seal(
        draft(2, fx.now(), json!({"blob": "z".repeat(60_000)})),
        &fx.key_a,
        &fx.cfg.limits(),
    )
    .unwrap();
    let wire = fx.wire(&big);
    let s = capture(|| {
        assert!(fx.trident.verify_wire(&wire).is_accepted());
    });
    assert!(counter_sum(&s, t::HASHED_BYTES_TOTAL) <= 2 * wire.len() as u64);
}

/// No panic is reachable from bytes: random input, every prefix of a valid
/// envelope, and random single-byte edits. None of them is accepted.
#[test]
fn rt_no_panic_from_arbitrary_bytes() {
    let fx = setup();
    let env = fx.sealed(1);
    let wire = fx.wire(&env);
    for n in 0..wire.len() {
        assert!(!fx.trident.verify_wire(&wire[..n]).is_accepted());
    }
    let mut rng = Rng(7);
    let alphabet = b"{}[]\":,-0123456789.eE\\u tfnrlsaNIy\x00\xff\xc3\xa9";
    for _ in 0..4000 {
        let len = rng.below(200);
        let bytes: Vec<u8> = (0..len).map(|_| alphabet[rng.below(alphabet.len())]).collect();
        assert!(!fx.trident.verify_wire(&bytes).is_accepted());
        let mut edited = wire.clone();
        let i = rng.below(edited.len());
        edited[i] = alphabet[rng.below(alphabet.len())];
        if edited != wire {
            let _ = fx.trident.verify_wire(&edited);
        }
    }
    // Deep nesting at the maximum configured depth does not blow the stack.
    let cfg = TridentConfig {
        max_depth: tack_trident::config::MAX_DEPTH_CEILING,
        max_nodes: tack_trident::config::MAX_NODES_CEILING,
        max_envelope_bytes: tack_trident::config::MAX_ENVELOPE_BYTES_CEILING,
        ..TridentConfig::default()
    };
    let deep = Trident::new(cfg, ring_of(&["a"]), fx.clock.clone()).unwrap();
    let bomb = "[".repeat(1_000_000);
    assert!(!deep.verify_wire(bomb.as_bytes()).is_accepted());
}

/// Worst-case wire shapes at the default caps each finish quickly: wide
/// objects (sort cost), maximal escapes, maximal nesting repeated.
#[test]
fn rt_wire_admission_cost_is_bounded() {
    let fx = setup();
    let cap = fx.cfg.max_envelope_bytes;
    let mut wide = String::from("{");
    let mut i = 0;
    while wide.len() < cap - 16 {
        if i > 0 {
            wide.push(',');
        }
        let _ = write!(wide, "\"{:x}\":0", i * 7919 % 1_000_003);
        i += 1;
    }
    wide.push('}');
    let escapes = format!("\"{}\"", "\\u00e9".repeat((cap - 2) / 6));
    let unit = "[".repeat(31) + &"]".repeat(31);
    let mut nested = String::from("[");
    while nested.len() + unit.len() + 2 < cap {
        if nested.len() > 1 {
            nested.push(',');
        }
        nested.push_str(&unit);
    }
    nested.push(']');
    for (name, body) in [("wide", wide), ("escapes", escapes), ("nested", nested)] {
        let started = Instant::now();
        let _ = fx.trident.verify_wire(body.as_bytes());
        let took = started.elapsed();
        assert!(took < Duration::from_millis(1500), "{name} took {took:?}");
    }
}

/// In-process admission is claimed to be "one bounded pass" under the same
/// caps. The encoder collects and sorts every key of an object before the
/// node cap is checked, so the refusal cost grows with the caller's object
/// size, not with the caps.
#[test]
fn rt_in_process_refusal_cost_is_bounded_by_caps() {
    let fx = setup();
    let make = |n: usize| {
        let mut m = Map::new();
        for i in 0..n {
            m.insert(format!("k{i:08}"), Value::Null);
        }
        let mut e = fx.sealed(1);
        e.payload = Value::Object(m);
        e
    };
    let small = make(fx.cfg.max_nodes + 1);
    let big = make(2_000_000);
    let time = |e: &HandoffEnvelope| {
        let started = Instant::now();
        let v = fx.trident.verify(e);
        let r = v.refusal().unwrap();
        assert!(r.has(ReasonCode::TooManyNodes) || r.has(ReasonCode::EnvelopeTooLarge), "{v:?}");
        started.elapsed()
    };
    let _ = time(&small);
    let ts = time(&small);
    let tb = time(&big);
    assert!(
        tb < ts * 10 + Duration::from_millis(20),
        "refusing a 2,000,000-key object took {tb:?}, versus {ts:?} for one just over the cap"
    );
}

/// The wire path counts the envelope object and its nine scalar fields
/// against max_nodes; the in-process path counts only payload nodes. An
/// envelope accepted in-process has a wire form the same receiver refuses.
#[test]
fn rt_wire_and_in_process_caps_agree() {
    let fx = setup();
    let in_process = Trident::new(fx.cfg.clone(), ring_of(&["a"]), fx.clock.clone()).unwrap();
    let on_wire = Trident::new(fx.cfg.clone(), ring_of(&["a"]), fx.clock.clone()).unwrap();
    fx.clock.advance(10_000);
    let items = vec![json!(0); fx.cfg.max_nodes - 1];
    let env = seal(draft(1, fx.now(), Value::Array(items)), &fx.key_a, &fx.cfg.limits()).unwrap();
    let wire = env.to_wire_bytes(&fx.cfg.limits()).unwrap();
    let a = in_process.verify(&env);
    let b = on_wire.verify_wire(&wire);
    assert_eq!(
        a.is_accepted(),
        b.is_accepted(),
        "in-process {:?} versus wire {:?} for the same envelope",
        a.reasons(),
        b.reasons()
    );
}

/// Concurrency: many threads racing distinct and duplicate envelopes from
/// one sender never accept a nonce twice, and never accept two envelopes
/// with the same sequence.
#[test]
fn rt_concurrent_race_never_double_accepts() {
    let fx = setup();
    let envs: Vec<HandoffEnvelope> = (1..=32).map(|s| fx.sealed(s)).collect();
    let accepted = Mutex::new(Vec::new());
    std::thread::scope(|s| {
        for t_idx in 0..16 {
            let envs = &envs;
            let accepted = &accepted;
            let tr = &fx.trident;
            s.spawn(move || {
                for k in 0..envs.len() {
                    let e = &envs[(k + t_idx) % envs.len()];
                    if let Verdict::Accepted(h) = tr.verify(e) {
                        accepted.lock().unwrap().push((h.sequence, h.nonce));
                    }
                }
            });
        }
    });
    let acc = accepted.into_inner().unwrap();
    let seqs: BTreeSet<u64> = acc.iter().map(|(s, _)| *s).collect();
    assert_eq!(seqs.len(), acc.len(), "a sequence was accepted twice: {acc:?}");
    assert!(!acc.is_empty());
}
