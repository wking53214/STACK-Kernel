//! Behaviour of the puzzle gate through a real Trident: real signed
//! envelopes, a manual clock, a deny-list inspector.

#![allow(clippy::unwrap_used)]

mod common;

use std::cell::Cell;
use std::sync::Arc;

use common::{fixture_key, nonce_for, T0};
use serde_json::{json, Value};
use stack_trident::canonical::to_hex;
use stack_trident::puzzle::{
    abort_payload, root_of, split, BusyReason, CloseReason, DenyListInspector, Finding, InspectInput, Inspector, Outcome,
    PieceError, PuzzleConfig, PuzzleGate, PuzzleId, PuzzleRefusal,
};
use stack_trident::{
    seal, Clock, EnvelopeDraft, Fingerprint, GateOutcome, GatePosition, KeyRing, ManualClock, SecretKey, Trident, TridentConfig,
};

struct Who {
    key: SecretKey,
    fp: Fingerprint,
    seq: Cell<u64>,
}

struct World {
    clock: Arc<ManualClock>,
    gate: PuzzleGate,
    tcfg: TridentConfig,
    a: Who,
    b: Who,
    x: Who,
}

fn who(label: &str) -> Who {
    let key = fixture_key(label);
    Who { fp: Fingerprint::of(&key), key, seq: Cell::new(0) }
}

fn id(n: u8) -> PuzzleId {
    PuzzleId::from_bytes([n; 16])
}

#[derive(Debug)]
struct Fixed(Finding);
impl Inspector for Fixed {
    fn inspect(&self, _: &InspectInput<'_>) -> Finding {
        self.0
    }
}

impl World {
    fn new(cfg: PuzzleConfig) -> Self {
        let deny = DenyListInspector::new(vec![b"TROJAN".to_vec()]).unwrap();
        Self::with_inspector(cfg, Arc::new(deny))
    }

    fn with_inspector(cfg: PuzzleConfig, inspector: Arc<dyn Inspector>) -> Self {
        let clock = Arc::new(ManualClock::new(T0));
        let (a, b, x) = (who("a"), who("b"), who("x"));
        let mut ring = KeyRing::new(16);
        ring.insert(fixture_key("a")).unwrap();
        ring.insert(fixture_key("b")).unwrap();
        let tcfg = TridentConfig::default();
        let trident = Arc::new(Trident::new(tcfg.clone(), ring, clock.clone()).unwrap());
        clock.advance(tcfg.max_future_skew_ms + 1);
        let gate = PuzzleGate::new(cfg, trident, inspector, clock.clone()).unwrap();
        World { clock, gate, tcfg, a, b, x }
    }

    fn advance(&self, ms: u64) {
        self.clock.advance(ms);
    }

    fn envelope(&self, who: &Who, outcome: GateOutcome, payload: Value) -> stack_trident::HandoffEnvelope {
        let seq = who.seq.get() + 1;
        who.seq.set(seq);
        seal(
            EnvelopeDraft {
                sequence: seq,
                issued_at_unix_ms: self.clock.now_unix_ms(),
                nonce: nonce_for(seq),
                gate_position: GatePosition::Alpha,
                gate_outcome: outcome,
                payload,
            },
            &who.key,
            &self.tcfg.limits(),
        )
        .unwrap()
    }

    fn send(&self, who: &Who, payload: Value) -> Outcome {
        self.gate.offer_envelope(&self.envelope(who, GateOutcome::Pass, payload))
    }

    /// Sends every payload in order and returns the last outcome.
    fn send_all(&self, who: &Who, payloads: &[Value]) -> Outcome {
        let mut last = None;
        for p in payloads {
            last = Some(self.send(who, p.clone()));
        }
        last.unwrap()
    }
}

fn whole_of(n: usize) -> Vec<u8> {
    (0..n).map(|i| u8::try_from(i % 251).unwrap()).collect()
}

fn small_cfg() -> PuzzleConfig {
    PuzzleConfig::default()
}

// ---------------------------------------------------------------------------
// The basic promise
// ---------------------------------------------------------------------------

#[test]
fn nothing_is_released_until_the_last_piece_arrives() {
    let w = World::new(small_cfg());
    let whole = whole_of(10);
    let pieces = split(&whole, 3, id(1), 64).unwrap();
    assert_eq!(pieces.len(), 4);
    assert_eq!(w.send(&w.a, pieces[0].clone()), Outcome::Held { remaining: 3 });
    assert_eq!(w.send(&w.a, pieces[1].clone()), Outcome::Held { remaining: 2 });
    assert_eq!(w.send(&w.a, pieces[2].clone()), Outcome::Held { remaining: 1 });
    let Outcome::Released(done) = w.send(&w.a, pieces[3].clone()) else {
        panic!("the last piece must release the whole");
    };
    assert_eq!(done.bytes, whole);
    assert_eq!(done.pieces, 4);
    assert_eq!(done.sender, w.a.fp);
    assert_eq!(w.gate.stats().open_puzzles, 0);
    assert_eq!(w.gate.stats().held_bytes, 0);
}

#[test]
fn pieces_may_arrive_in_any_order() {
    let w = World::new(small_cfg());
    let whole = whole_of(10);
    let pieces = split(&whole, 3, id(1), 64).unwrap();
    for i in [2usize, 0, 3] {
        assert!(matches!(w.send(&w.a, pieces[i].clone()), Outcome::Held { .. }));
    }
    let Outcome::Released(done) = w.send(&w.a, pieces[1].clone()) else {
        panic!("complete in any order");
    };
    assert_eq!(done.bytes, whole, "the whole is joined in index order, not arrival order");
}

#[test]
fn a_wire_path_works_the_same() {
    let w = World::new(small_cfg());
    let pieces = split(b"abcdef", 3, id(2), 64).unwrap();
    for (i, p) in pieces.iter().enumerate() {
        let env = w.envelope(&w.a, GateOutcome::Pass, p.clone());
        let out = w.gate.offer_wire(&env.to_wire_bytes(&w.tcfg.limits()).unwrap());
        if i == 0 {
            assert_eq!(out, Outcome::Held { remaining: 1 });
        } else {
            assert!(matches!(out, Outcome::Released(_)));
        }
    }
}

// ---------------------------------------------------------------------------
// The Trojan horse: hostile content hidden by cutting it up
// ---------------------------------------------------------------------------

#[test]
fn a_marker_cut_across_pieces_is_blocked_at_the_whole_and_no_piece_leaks() {
    let w = World::new(small_cfg());
    let whole = b"hello TROJAN world".to_vec();
    let pieces = split(&whole, 4, id(3), 64).unwrap();
    // Each slice alone is harmless: the marker never sits inside one piece.
    for chunk in whole.chunks(4) {
        assert!(!chunk.windows(6).any(|x| x == b"TROJAN"));
    }
    let n = pieces.len();
    for (i, p) in pieces.iter().enumerate() {
        let out = w.send(&w.a, p.clone());
        if i + 1 < n {
            assert!(matches!(out, Outcome::Held { .. }), "{i}: {out:?}");
        } else {
            assert_eq!(out, Outcome::Refused(PuzzleRefusal::ContentBlocked("deny-list pattern in the whole")));
        }
    }
    let closed = w.gate.take_closed();
    assert_eq!(closed.len(), 1);
    assert_eq!(closed[0].reason, CloseReason::Hostile);
    assert!(closed[0].breach);
    assert_eq!(w.gate.stats().held_bytes, 0, "everything the puzzle held is gone");
}

#[test]
fn a_marker_split_over_two_and_three_whole_puzzles_is_caught_by_look_back() {
    let w = World::new(small_cfg());
    // Two puzzles: ...TRO | JAN...
    assert!(matches!(w.send_all(&w.a, &split(b"xx TRO", 100, id(1), 64).unwrap()), Outcome::Released(_)));
    let out = w.send_all(&w.a, &split(b"JAN yy", 100, id(2), 64).unwrap());
    assert_eq!(out, Outcome::Refused(PuzzleRefusal::ContentBlocked("deny-list pattern across a join")));
    // Three puzzles: TR | OJ | AN, from the other sender.
    assert!(matches!(w.send_all(&w.b, &split(b"zz TR", 100, id(1), 64).unwrap()), Outcome::Released(_)));
    assert!(matches!(w.send_all(&w.b, &split(b"OJ", 100, id(2), 64).unwrap()), Outcome::Released(_)));
    let out = w.send_all(&w.b, &split(b"AN zz", 100, id(3), 64).unwrap());
    assert!(matches!(out, Outcome::Refused(PuzzleRefusal::ContentBlocked(_))), "{out:?}");
}

#[test]
fn look_back_has_a_limit_and_is_a_setting() {
    // Off: the two halves each pass.
    let off = World::new(PuzzleConfig { lookback_wholes: 0, ..small_cfg() });
    assert!(matches!(off.send_all(&off.a, &split(b"xx TRO", 100, id(1), 64).unwrap()), Outcome::Released(_)));
    assert!(matches!(off.send_all(&off.a, &split(b"JAN yy", 100, id(2), 64).unwrap()), Outcome::Released(_)));
    // Looking back over one whole: a three-way split gets through.
    let one = World::new(PuzzleConfig { lookback_wholes: 1, ..small_cfg() });
    for (n, part) in [b"zz TR".as_slice(), b"OJ", b"AN zz"].iter().enumerate() {
        let out = one.send_all(&one.a, &split(part, 100, id(u8::try_from(n).unwrap() + 1), 64).unwrap());
        assert!(matches!(out, Outcome::Released(_)), "part {n}: {out:?}");
    }
}

// ---------------------------------------------------------------------------
// Conflicts and misfits
// ---------------------------------------------------------------------------

#[test]
fn a_duplicate_piece_is_ignored_and_a_conflicting_one_destroys_the_puzzle() {
    let w = World::new(small_cfg());
    let pieces = split(&whole_of(9), 3, id(1), 64).unwrap();
    assert_eq!(w.send(&w.a, pieces[0].clone()), Outcome::Held { remaining: 2 });
    assert_eq!(w.send(&w.a, pieces[0].clone()), Outcome::Held { remaining: 2 }, "same bytes again changes nothing");
    let mut evil = pieces[0].clone();
    evil["data"] = json!("ffffff");
    assert_eq!(w.send(&w.a, evil), Outcome::Refused(PuzzleRefusal::Conflict));
    // The puzzle is gone; a late piece neither revives it nor opens a new one.
    assert_eq!(w.send(&w.a, pieces[1].clone()), Outcome::Refused(PuzzleRefusal::AlreadyClosed));
    assert_eq!(w.gate.stats().open_puzzles, 0);
}

#[test]
fn a_changed_declaration_is_a_conflict() {
    let w = World::new(small_cfg());
    let pieces = split(&whole_of(9), 3, id(1), 64).unwrap();
    assert!(matches!(w.send(&w.a, pieces[0].clone()), Outcome::Held { .. }));
    let mut liar = pieces[1].clone();
    liar["total"] = json!(5);
    assert_eq!(w.send(&w.a, liar), Outcome::Refused(PuzzleRefusal::Conflict));
}

#[test]
fn a_set_that_does_not_match_its_root_is_destroyed_at_completion() {
    let w = World::new(small_cfg());
    let mut pieces = split(&whole_of(9), 3, id(1), 64).unwrap();
    pieces[2]["data"] = json!(to_hex(b"not the third piece"[..3].as_ref()));
    let out = w.send_all(&w.a, &pieces);
    assert_eq!(out, Outcome::Refused(PuzzleRefusal::RootMismatch));
    assert_eq!(w.gate.take_closed()[0].reason, CloseReason::RootMismatch);
    // The root really is what the format says it is.
    let real = split(&whole_of(9), 3, id(1), 64).unwrap();
    let whole = whole_of(9);
    let chunks: Vec<&[u8]> = vec![&whole[..3], &whole[3..6], &whole[6..]];
    assert_eq!(real[0]["root"], json!(to_hex(&root_of(chunks))));
}

// ---------------------------------------------------------------------------
// The microwave timer
// ---------------------------------------------------------------------------

#[test]
fn an_incomplete_puzzle_explodes_and_the_sender_takes_a_breach() {
    let w = World::new(small_cfg());
    let pieces = split(&whole_of(9), 3, id(1), 64).unwrap();
    assert!(matches!(w.send(&w.a, pieces[0].clone()), Outcome::Held { .. }));
    w.advance(w.gate.config().idle_ms - 1);
    assert_eq!(w.gate.sweep(), 0, "not yet");
    w.advance(1);
    assert_eq!(w.gate.sweep(), 1, "the idle limit has passed");
    let closed = w.gate.take_closed();
    assert_eq!(closed.len(), 1);
    assert_eq!((closed[0].reason, closed[0].breach, closed[0].pieces), (CloseReason::Exploded, true, 1));
    assert_eq!(w.send(&w.a, pieces[1].clone()), Outcome::Refused(PuzzleRefusal::AlreadyClosed));
    assert_eq!(w.gate.stats().held_bytes, 0);
}

#[test]
fn explosions_also_happen_on_the_next_message_without_a_timer() {
    let w = World::new(small_cfg());
    let pieces = split(&whole_of(9), 3, id(1), 64).unwrap();
    assert!(matches!(w.send(&w.a, pieces[0].clone()), Outcome::Held { .. }));
    w.advance(w.gate.config().idle_ms + 1);
    // Any message from anyone sweeps first.
    assert!(matches!(w.send(&w.b, split(b"zzz", 3, id(9), 64).unwrap()[0].clone()), Outcome::Released(_)));
    assert_eq!(w.gate.take_closed().iter().filter(|c| c.reason == CloseReason::Exploded).count(), 1);
}

#[test]
fn a_steady_slow_stream_lives_but_never_past_the_hard_cap() {
    let cfg = PuzzleConfig { idle_ms: 1_000, max_lifetime_ms: 2_500, ..small_cfg() };
    let w = World::new(cfg);
    let pieces = split(&whole_of(15), 3, id(1), 64).unwrap();
    assert_eq!(pieces.len(), 5);
    for p in pieces.iter().take(4) {
        assert!(matches!(w.send(&w.a, p.clone()), Outcome::Held { .. }));
        w.advance(800);
    }
    // 3,200 ms after the first piece: the hard cap (2,500) has long passed.
    assert_eq!(w.send(&w.a, pieces[4].clone()), Outcome::Refused(PuzzleRefusal::AlreadyClosed));
    assert_eq!(w.gate.take_closed()[0].reason, CloseReason::Exploded);

    // Same stream under a roomy cap completes: each piece resets the idle limit.
    let roomy = World::new(PuzzleConfig { idle_ms: 1_000, max_lifetime_ms: 30_000, ..small_cfg() });
    for (i, p) in pieces.iter().enumerate() {
        let out = roomy.send(&roomy.a, p.clone());
        if i < 4 {
            assert!(matches!(out, Outcome::Held { .. }));
            roomy.advance(800);
        } else {
            assert!(matches!(out, Outcome::Released(_)), "{out:?}");
        }
    }
}

// ---------------------------------------------------------------------------
// The slit: abort is clean, and "busy" is not "guilty"
// ---------------------------------------------------------------------------

#[test]
fn aborting_costs_nothing_however_often_it_happens() {
    let w = World::new(small_cfg());
    for n in 1..=20u8 {
        let pieces = split(&whole_of(9), 3, id(n), 64).unwrap();
        assert!(matches!(w.send(&w.a, pieces[0].clone()), Outcome::Held { .. }));
        assert_eq!(w.send(&w.a, abort_payload(id(n))), Outcome::Aborted);
    }
    for n in 100..120u8 {
        assert_eq!(w.send(&w.a, abort_payload(id(n))), Outcome::Refused(PuzzleRefusal::UnknownPuzzle));
    }
    // Still in good standing.
    let pieces = split(b"ok", 2, id(50), 64).unwrap();
    assert!(matches!(w.send(&w.a, pieces[0].clone()), Outcome::Released(_)));
    assert!(w.gate.take_closed().iter().all(|c| !c.breach));
}

#[test]
fn nobody_else_can_abort_my_puzzle() {
    let w = World::new(small_cfg());
    let pieces = split(&whole_of(9), 3, id(1), 64).unwrap();
    assert!(matches!(w.send(&w.a, pieces[0].clone()), Outcome::Held { .. }));
    assert_eq!(w.send(&w.b, abort_payload(id(1))), Outcome::Refused(PuzzleRefusal::UnknownPuzzle), "puzzles are namespaced by sender");
    assert_eq!(w.gate.stats().open_puzzles, 1);
}

#[test]
fn too_many_open_puzzles_is_busy_and_costs_no_breach() {
    let w = World::new(PuzzleConfig { max_open_per_sender: 2, ..small_cfg() });
    for n in 1..=2u8 {
        assert!(matches!(w.send(&w.a, split(&whole_of(9), 3, id(n), 64).unwrap()[0].clone()), Outcome::Held { .. }));
    }
    for n in 3..=40u8 {
        let out = w.send(&w.a, split(&whole_of(9), 3, id(n), 64).unwrap()[0].clone());
        assert_eq!(out, Outcome::Refused(PuzzleRefusal::Busy(BusyReason::TooManyOpen)));
        assert!(!PuzzleRefusal::Busy(BusyReason::TooManyOpen).counts_as_breach());
    }
    // Forty refusals later the sender can still finish what it opened.
    let rest = split(&whole_of(9), 3, id(1), 64).unwrap();
    assert!(matches!(w.send(&w.a, rest[1].clone()), Outcome::Held { .. }));
    assert!(matches!(w.send(&w.a, rest[2].clone()), Outcome::Released(_)));
}

// ---------------------------------------------------------------------------
// The breaker
// ---------------------------------------------------------------------------

fn bad_piece() -> Value {
    json!({"kind": "piece", "puzzle": id(77).to_hex(), "index": 0, "total": 0, "root": "00".repeat(32), "data": "ab"})
}

#[test]
fn six_breaches_quarantine_a_sender_and_the_quarantine_ends_by_itself() {
    let w = World::new(small_cfg());
    for _ in 0..6 {
        assert_eq!(w.send(&w.a, bad_piece()), Outcome::Refused(PuzzleRefusal::Malformed(PieceError::TotalOutOfRange)));
    }
    let Outcome::Refused(PuzzleRefusal::Quarantined { until_ms }) = w.send(&w.a, split(b"ok", 2, id(1), 64).unwrap()[0].clone()) else {
        panic!("the sixth breach must quarantine");
    };
    assert_eq!(until_ms, w.clock.now_unix_ms() + w.gate.config().quarantine_ms);
    // Another sender is untouched.
    assert!(matches!(w.send(&w.b, split(b"ok", 2, id(1), 64).unwrap()[0].clone()), Outcome::Released(_)));
    w.advance(w.gate.config().quarantine_ms);
    assert!(matches!(w.send(&w.a, split(b"ok", 2, id(2), 64).unwrap()[0].clone()), Outcome::Released(_)));
}

#[test]
fn five_breaches_are_survivable() {
    let w = World::new(small_cfg());
    for _ in 0..5 {
        w.send(&w.a, bad_piece());
    }
    assert!(matches!(w.send(&w.a, split(b"ok", 2, id(1), 64).unwrap()[0].clone()), Outcome::Released(_)));
}

#[test]
fn a_quarantine_destroys_the_senders_open_puzzles() {
    let w = World::new(small_cfg());
    for n in 1..=2u8 {
        assert!(matches!(w.send(&w.a, split(&whole_of(9), 3, id(n), 64).unwrap()[0].clone()), Outcome::Held { .. }));
    }
    for _ in 0..6 {
        w.send(&w.a, bad_piece());
    }
    let closed = w.gate.take_closed();
    assert_eq!(closed.iter().filter(|c| c.reason == CloseReason::Quarantined).count(), 2);
    assert_eq!(w.gate.stats().open_puzzles, 0);
    assert_eq!(w.gate.stats().held_bytes, 0);
}

#[test]
fn a_suspicious_finding_never_quarantines_but_a_hostile_one_does() {
    let sus = World::with_inspector(small_cfg(), Arc::new(Fixed(Finding::Suspicious("maybe"))));
    for n in 1..=30u8 {
        let out = sus.send(&sus.a, split(b"x", 1, id(n), 64).unwrap()[0].clone());
        assert_eq!(out, Outcome::Refused(PuzzleRefusal::ContentSuspicious("maybe")), "refusal {n}");
    }
    let hostile = World::with_inspector(small_cfg(), Arc::new(Fixed(Finding::Hostile("sure"))));
    for n in 1..=6u8 {
        let out = hostile.send(&hostile.a, split(b"x", 1, id(n), 64).unwrap()[0].clone());
        assert_eq!(out, Outcome::Refused(PuzzleRefusal::ContentBlocked("sure")));
    }
    let out = hostile.send(&hostile.a, split(b"x", 1, id(7), 64).unwrap()[0].clone());
    assert!(matches!(out, Outcome::Refused(PuzzleRefusal::Quarantined { .. })), "{out:?}");
}

#[test]
fn declarations_over_the_limits_are_breaches() {
    let w = World::new(small_cfg());
    let mut big = split(b"ab", 1, id(1), 64).unwrap()[0].clone();
    big["total"] = json!(65);
    assert_eq!(w.send(&w.a, big), Outcome::Refused(PuzzleRefusal::Malformed(PieceError::TotalOutOfRange)));
    let mut fat = split(b"ab", 1, id(2), 64).unwrap()[0].clone();
    fat["data"] = json!("ab".repeat(4097));
    assert_eq!(w.send(&w.a, fat), Outcome::Refused(PuzzleRefusal::Malformed(PieceError::DataSize)));
    let mut extra = split(b"ab", 1, id(3), 64).unwrap()[0].clone();
    extra["note"] = json!("smuggled");
    assert_eq!(w.send(&w.a, extra), Outcome::Refused(PuzzleRefusal::Malformed(PieceError::WrongKeys)));
    assert!(PuzzleRefusal::Malformed(PieceError::WrongKeys).counts_as_breach());
}

// ---------------------------------------------------------------------------
// Memory of released wholes
// ---------------------------------------------------------------------------

#[test]
fn a_repeated_whole_is_refused_inside_the_window_and_accepted_after_it() {
    let w = World::new(small_cfg());
    let first = split(b"the same whole", 100, id(1), 64).unwrap();
    assert!(matches!(w.send_all(&w.a, &first), Outcome::Released(_)));
    let again = split(b"the same whole", 100, id(2), 64).unwrap();
    assert_eq!(w.send_all(&w.a, &again), Outcome::Refused(PuzzleRefusal::ReplayedWhole));
    // A different sender may send identical content.
    assert!(matches!(w.send_all(&w.b, &split(b"the same whole", 100, id(1), 64).unwrap()), Outcome::Released(_)));
    w.advance(w.gate.config().replay_window_ms);
    assert!(matches!(w.send_all(&w.a, &split(b"the same whole", 100, id(3), 64).unwrap()), Outcome::Released(_)));
}

// ---------------------------------------------------------------------------
// Authenticity is the hinge
// ---------------------------------------------------------------------------

#[test]
fn a_forged_envelope_never_reaches_the_gate_and_costs_the_claimed_sender_nothing() {
    let w = World::new(small_cfg());
    for n in 0..30u64 {
        // Signed with a key the receiver does not hold, claiming to be sender A.
        let mut env = w.envelope(&w.x, GateOutcome::Pass, bad_piece());
        env.sender = w.a.fp.to_hex();
        env.sequence = 1_000 + n;
        let out = w.gate.offer_envelope(&env);
        assert!(matches!(out, Outcome::Rejected(_)), "{out:?}");
    }
    assert_eq!(w.gate.stats().tracked_senders, 0, "forgeries create no gate state at all");
    // The real A is in good standing and can use the gate.
    assert!(matches!(w.send(&w.a, split(b"ok", 2, id(1), 64).unwrap()[0].clone()), Outcome::Released(_)));
}

#[test]
fn a_piece_whose_sender_gate_did_not_pass_is_not_released() {
    let w = World::new(small_cfg());
    let piece = split(b"ok", 2, id(1), 64).unwrap()[0].clone();
    let env = w.envelope(&w.a, GateOutcome::Retry, piece);
    assert_eq!(w.gate.offer_envelope(&env), Outcome::Refused(PuzzleRefusal::SenderGateNotPass));
}

// ---------------------------------------------------------------------------
// A full holding area
// ---------------------------------------------------------------------------

#[test]
fn a_full_gate_evicts_the_oldest_incomplete_puzzle_not_the_newcomer() {
    let w = World::new(PuzzleConfig { max_open_total: 3, ..small_cfg() });
    // A opens two puzzles (the oldest), B opens one.
    for n in 1..=2u8 {
        assert!(matches!(w.send(&w.a, split(&whole_of(9), 3, id(n), 64).unwrap()[0].clone()), Outcome::Held { .. }));
        w.advance(10);
    }
    assert!(matches!(w.send(&w.b, split(&whole_of(9), 3, id(1), 64).unwrap()[0].clone()), Outcome::Held { .. }));
    w.advance(10);
    // B opens a fourth: the gate is full, so A's oldest goes.
    assert!(matches!(w.send(&w.b, split(&whole_of(9), 3, id(2), 64).unwrap()[0].clone()), Outcome::Held { .. }));
    let closed = w.gate.take_closed();
    assert_eq!(closed.len(), 1);
    assert_eq!((closed[0].reason, closed[0].sender, closed[0].puzzle), (CloseReason::Evicted, w.a.fp, id(1)));
    assert_eq!(w.gate.stats().open_puzzles, 3);
    // The evicted puzzle stays closed.
    assert_eq!(w.send(&w.a, split(&whole_of(9), 3, id(1), 64).unwrap()[1].clone()), Outcome::Refused(PuzzleRefusal::AlreadyClosed));
}

#[test]
fn the_holding_area_never_exceeds_its_byte_budget() {
    let cfg = PuzzleConfig { max_pieces: 4, max_piece_bytes: 64, max_held_bytes: 256, ..small_cfg() };
    let w = World::new(cfg);
    for n in 1..=40u8 {
        let pieces = split(&vec![n; 64 * 4], 64, id(n), 4).unwrap();
        w.send(&w.a, pieces[0].clone());
        w.send(&w.a, pieces[1].clone());
        assert!(w.gate.stats().held_bytes <= 256, "puzzle {n}: {}", w.gate.stats().held_bytes);
        w.advance(1);
    }
}

#[test]
fn an_invalid_config_refuses_to_build_a_gate() {
    let clock = Arc::new(ManualClock::new(T0));
    let trident = Arc::new(Trident::new(TridentConfig::default(), KeyRing::new(4), clock.clone()).unwrap());
    let inspector = Arc::new(DenyListInspector::new(vec![b"x".to_vec()]).unwrap());
    let bad = PuzzleConfig { max_pieces: 0, ..small_cfg() };
    let err = PuzzleGate::new(bad, trident, inspector, clock).unwrap_err();
    assert_eq!(err.field, "max_pieces");
}
