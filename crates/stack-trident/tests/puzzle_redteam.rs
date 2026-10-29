//! Attack scenarios against the puzzle gate, ending in a small mixed run.

#![allow(clippy::unwrap_used)]

mod common;

use std::cell::Cell;
use std::sync::Arc;

use common::{fixture_key, nonce_for, T0};
use serde_json::Value;
use stack_trident::puzzle::{
    abort_payload, split, CloseReason, DenyListInspector, Outcome, PuzzleConfig, PuzzleGate, PuzzleId, PuzzleRefusal,
};
use stack_trident::{seal, Clock, EnvelopeDraft, GateOutcome, GatePosition, KeyRing, ManualClock, SecretKey, Trident, TridentConfig};

struct Who {
    key: SecretKey,
    seq: Cell<u64>,
}

struct World {
    clock: Arc<ManualClock>,
    gate: PuzzleGate,
    tcfg: TridentConfig,
}

fn who(label: &str) -> Who {
    let key = fixture_key(label);
    Who { key, seq: Cell::new(0) }
}

fn pid(n: u32) -> PuzzleId {
    let mut b = [0u8; 16];
    b[..4].copy_from_slice(&n.to_be_bytes());
    PuzzleId::from_bytes(b)
}

impl World {
    fn new(cfg: PuzzleConfig, senders: &[&str]) -> Self {
        let clock = Arc::new(ManualClock::new(T0));
        let mut ring = KeyRing::new(64);
        for s in senders {
            ring.insert(fixture_key(s)).unwrap();
        }
        let tcfg = TridentConfig::default();
        let trident = Arc::new(Trident::new(tcfg.clone(), ring, clock.clone()).unwrap());
        clock.advance(tcfg.max_future_skew_ms + 1);
        let inspector = Arc::new(DenyListInspector::new(vec![b"TROJAN".to_vec(), b"EXFIL".to_vec()]).unwrap());
        let gate = PuzzleGate::new(cfg, trident, inspector, clock.clone()).unwrap();
        World { clock, gate, tcfg }
    }

    fn send(&self, who: &Who, payload: Value) -> Outcome {
        let seq = who.seq.get() + 1;
        who.seq.set(seq);
        let env = seal(
            EnvelopeDraft {
                sequence: seq,
                issued_at_unix_ms: self.clock.now_unix_ms(),
                nonce: nonce_for(seq),
                gate_position: GatePosition::Alpha,
                gate_outcome: GateOutcome::Pass,
                payload,
            },
            &who.key,
            &self.tcfg.limits(),
        )
        .unwrap();
        self.gate.offer_envelope(&env)
    }

    fn send_all(&self, who: &Who, payloads: &[Value]) -> Outcome {
        let mut last = None;
        for p in payloads {
            last = Some(self.send(who, p.clone()));
        }
        last.unwrap()
    }
}

#[test]
fn a_hoarder_is_quarantined_by_its_own_explosions_and_loses_everything_it_held() {
    let w = World::new(PuzzleConfig::default(), &["hoard", "honest"]);
    let (hoard, honest) = (who("hoard"), who("honest"));
    // Six puzzles opened and never finished: each one explodes into a breach.
    for n in 1..=6u32 {
        let pieces = split(&[7u8; 30], 10, pid(n), 64).unwrap();
        assert!(matches!(w.send(&hoard, pieces[0].clone()), Outcome::Held { .. }));
        w.clock.advance(w.gate.config().idle_ms + 1);
        assert_eq!(w.gate.sweep(), 1);
    }
    let closed = w.gate.take_closed();
    assert_eq!(closed.iter().filter(|c| c.reason == CloseReason::Exploded && c.breach).count(), 6);
    let out = w.send(&hoard, split(b"x", 100, pid(99), 64).unwrap()[0].clone());
    assert!(matches!(out, Outcome::Refused(PuzzleRefusal::Quarantined { .. })), "{out:?}");
    // The honest neighbour never noticed.
    assert!(matches!(w.send(&honest, split(b"hello", 5, pid(1), 64).unwrap()[0].clone()), Outcome::Released(_)));
}

#[test]
fn a_marker_cut_over_four_puzzles_is_caught_with_the_default_look_back() {
    let w = World::new(PuzzleConfig::default(), &["a"]);
    let a = who("a");
    let parts: [&[u8]; 4] = [b"..TR", b"OJ", b"A", b"N.."];
    let mut outs = Vec::new();
    for (i, part) in parts.iter().enumerate() {
        outs.push(w.send_all(&a, &split(part, 100, pid(u32::try_from(i).unwrap() + 1), 64).unwrap()));
    }
    assert!(outs[..3].iter().all(|o| matches!(o, Outcome::Released(_))));
    assert!(matches!(outs[3], Outcome::Refused(PuzzleRefusal::ContentBlocked(_))), "{:?}", outs[3]);
}

#[test]
fn honest_traffic_survives_a_flood_from_another_sender() {
    let cfg = PuzzleConfig { max_open_total: 8, max_open_per_sender: 8, ..PuzzleConfig::default() };
    let w = World::new(cfg, &["flood", "honest"]);
    let (flood, honest) = (who("flood"), who("honest"));
    let mut finished = 0;
    for round in 0..40u32 {
        // The flooder opens eight puzzles it will never finish.
        for k in 0..8u32 {
            w.send(&flood, split(&[1u8; 40], 10, pid(round * 100 + k), 64).unwrap()[0].clone());
        }
        // The honest sender completes a small puzzle in the same instant.
        let pieces = split(format!("msg {round}").as_bytes(), 3, pid(round), 64).unwrap();
        if matches!(w.send_all(&honest, &pieces), Outcome::Released(_)) {
            finished += 1;
        }
        w.clock.advance(5);
    }
    assert!(finished >= 36, "honest puzzles finished: {finished} of 40");
    assert!(w.gate.stats().open_puzzles <= 8);
}

#[test]
fn a_small_mixed_garden_releases_no_hostile_whole_and_quarantines_no_honest_sender() {
    let names = ["h0", "h1", "h2", "h3", "evil", "hoard"];
    let w = World::new(PuzzleConfig::default(), &names);
    let honest: Vec<Who> = names[..4].iter().map(|n| who(n)).collect();
    let (evil, hoard) = (who("evil"), who("hoard"));

    let (mut honest_done, mut honest_total, mut hostile_released) = (0u32, 0u32, 0u32);
    let mut n = 0u32;
    for round in 0..120u32 {
        for (i, h) in honest.iter().enumerate() {
            n += 1;
            honest_total += 1;
            let body = format!("report {round}-{i} balance ok").into_bytes();
            let mut pieces = split(&body, 7, pid(n), 64).unwrap();
            // Honest senders sometimes cancel, which must never cost them.
            if (round + u32::try_from(i).unwrap()) % 11 == 0 {
                w.send(h, pieces.remove(0));
                assert_eq!(w.send(h, abort_payload(pid(n))), Outcome::Aborted);
                honest_done += 1;
                continue;
            }
            if matches!(w.send_all(h, &pieces), Outcome::Released(_)) {
                honest_done += 1;
            }
        }
        // The attacker hides the marker in a whole, cut small, every round.
        n += 1;
        let mut whole = format!("filler {round} ").into_bytes();
        whole.extend_from_slice(if round % 2 == 0 { b"TROJAN" } else { b"EXFIL" });
        if matches!(w.send_all(&evil, &split(&whole, 3, pid(n), 64).unwrap()), Outcome::Released(_)) {
            hostile_released += 1;
        }
        // The hoarder opens a puzzle and walks away.
        n += 1;
        w.send(&hoard, split(&[9u8; 60], 10, pid(n), 64).unwrap()[0].clone());
        w.clock.advance(400);
        w.gate.sweep();
    }

    assert_eq!(hostile_released, 0, "a hostile whole got through");
    assert_eq!(honest_done, honest_total, "an honest puzzle was lost");
    // The attacker and the hoarder were stopped; the honest senders were not.
    let out = w.send(&evil, split(b"x", 100, pid(900_000), 64).unwrap()[0].clone());
    assert!(matches!(out, Outcome::Refused(PuzzleRefusal::Quarantined { .. })), "{out:?}");
    for h in &honest {
        let out = w.send(h, split(b"still fine", 100, pid(900_001), 64).unwrap()[0].clone());
        assert!(matches!(out, Outcome::Released(_)), "{out:?}");
    }
    assert!(w.gate.stats().held_bytes <= w.gate.config().max_held_bytes);
}
