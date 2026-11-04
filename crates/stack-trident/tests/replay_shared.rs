//! TRAIT-SEMANTICS tests for a replay store shared by more than one
//! `Trident` (R2-E-04, decision D). NOT a multi-host test: everything here
//! runs in one process, on one machine, with one clock. Multi-host proof
//! is BLOCKED in this environment and nothing here claims it.
//!
//! `SharedStore` below is a test-only store whose state lives behind an
//! `Arc<Mutex<..>>`, so two `Trident` instances can each hold a handle to
//! the same state through the `ReplayStore` trait. The `FileStore` cannot
//! be shared this way (its exclusive lock refuses a second open), which is
//! exactly why the trait itself has to carry the atomicity a shared store
//! needs.
//!
//! Every key is a TEST FIXTURE derived from a public label (see
//! tests/common/mod.rs) and must never be used outside tests.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use common::*;
use stack_trident::{
    seal, AcceptRecord, Clock, EnvelopeDraft, Fingerprint, GateOutcome, GatePosition, HandoffEnvelope, KeyRing,
    ManualClock, Nonce, ReasonCode, ReplayStore, RestoredState, SecretKey, StoreError, Trident, TridentConfig, Verdict,
};
use stack_trident::store::{RestoredNonce, RestoredSender};

// ---------------------------------------------------------------------------
// A store over shared in-process state (test only)
// ---------------------------------------------------------------------------

#[derive(Debug, Default)]
struct SharedState {
    records: Vec<AcceptRecord>,
    quarantined: HashMap<Fingerprint, u64>,
    epoch_floor_ms: u64,
}

/// A handle to shared replay state. Cloning it gives a second handle to
/// the SAME state, which is what two verifiers sharing one store look like
/// through the trait.
#[derive(Debug, Clone, Default)]
struct SharedStore(Arc<Mutex<SharedState>>);

impl SharedStore {
    fn view(st: &SharedState) -> RestoredState {
        let mut senders: HashMap<Fingerprint, (u64, u64)> = HashMap::new();
        let mut nonces: HashMap<(Fingerprint, Nonce), u64> = HashMap::new();
        let mut high_water_ms = 0;
        for r in &st.records {
            let e = senders.entry(r.sender).or_insert((r.sequence, r.accepted_at_unix_ms));
            e.0 = e.0.max(r.sequence);
            e.1 = e.1.max(r.accepted_at_unix_ms);
            let n = nonces.entry((r.sender, r.nonce)).or_insert(0);
            *n = (*n).max(r.nonce_expires_at_unix_ms);
            high_water_ms = high_water_ms.max(r.issued_at_unix_ms);
        }
        RestoredState {
            senders: senders
                .into_iter()
                .map(|(sender, (last_sequence, last_accepted_at_unix_ms))| RestoredSender {
                    sender,
                    last_sequence,
                    last_accepted_at_unix_ms,
                })
                .collect(),
            nonces: nonces
                .into_iter()
                .map(|((sender, nonce), expires_at_unix_ms)| RestoredNonce {
                    sender,
                    nonce,
                    expires_at_unix_ms,
                })
                .collect(),
            high_water_ms,
            quarantined: st.quarantined.iter().map(|(k, v)| (*k, *v)).collect(),
            epoch_floor_ms: st.epoch_floor_ms,
        }
    }

    fn accepted(&self) -> usize {
        self.0.lock().unwrap().records.len()
    }
}

impl ReplayStore for SharedStore {
    fn load(&mut self) -> Result<RestoredState, StoreError> {
        Ok(Self::view(&self.0.lock().unwrap()))
    }

    fn commit(&mut self, record: &AcceptRecord) -> Result<(), StoreError> {
        // Check-and-commit under ONE lock of the shared state, written
        // independently of the crate's own stores: a linear scan of every
        // record ever committed.
        let mut st = self.0.lock().unwrap();
        let mine = st.records.iter().filter(|r| r.sender == record.sender);
        let nonce_consumed = mine
            .clone()
            .any(|r| r.nonce == record.nonce && r.nonce_expires_at_unix_ms > record.accepted_at_unix_ms);
        let stored_sequence = mine.map(|r| r.sequence).max().filter(|s| record.sequence <= *s);
        let epoch_floor_ms = Some(st.epoch_floor_ms).filter(|f| record.issued_at_unix_ms < *f);
        if nonce_consumed || stored_sequence.is_some() || epoch_floor_ms.is_some() {
            return Err(StoreError::Conflict {
                nonce_consumed,
                stored_sequence,
                epoch_floor_ms,
            });
        }
        st.records.push(*record);
        Ok(())
    }

    fn is_durable(&self) -> bool {
        false
    }

    fn record_quarantine(&mut self, sender: &Fingerprint, since_unix_ms: u64) -> Result<(), StoreError> {
        self.0.lock().unwrap().quarantined.insert(*sender, since_unix_ms);
        Ok(())
    }

    fn record_release(&mut self, sender: &Fingerprint) -> Result<(), StoreError> {
        self.0.lock().unwrap().quarantined.remove(sender);
        Ok(())
    }

    fn raise_epoch_floor(&mut self, floor_ms: u64) -> Result<(), StoreError> {
        let mut st = self.0.lock().unwrap();
        st.epoch_floor_ms = st.epoch_floor_ms.max(floor_ms);
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn ring() -> KeyRing {
    let mut ring = KeyRing::new(16);
    ring.insert(fixture_key("a")).unwrap();
    ring.insert(fixture_key("b")).unwrap();
    ring
}

fn cfg() -> TridentConfig {
    TridentConfig::unbound_audience()
}

fn start(store: &SharedStore, clock: &Arc<ManualClock>) -> Trident {
    Trident::new_with_store(cfg(), ring(), Arc::clone(clock) as Arc<dyn Clock>, Box::new(store.clone())).unwrap()
}

/// Two verifiers on one shared store, both started at `T0`, with the clock
/// stepped past the start-up floor.
fn pair() -> (Arc<ManualClock>, SharedStore, Trident, Trident) {
    let clock = Arc::new(ManualClock::new(T0));
    let store = SharedStore::default();
    let a = start(&store, &clock);
    let b = start(&store, &clock);
    clock.advance(cfg().max_future_skew_ms + 1);
    (clock, store, a, b)
}

fn sealed_at(key: &SecretKey, seq: u64, nonce: Nonce, at: u64) -> HandoffEnvelope {
    seal(
        EnvelopeDraft {
            sequence: seq,
            issued_at_unix_ms: at,
            nonce,
            gate_position: GatePosition::Alpha,
            gate_outcome: GateOutcome::Pass,
            payload: payload_for(seq),
        },
        key,
        &cfg().limits(),
    )
    .unwrap()
}

fn sealed(seq: u64, clock: &ManualClock) -> HandoffEnvelope {
    sealed_at(&fixture_key("a"), seq, nonce_for(seq), clock.now_unix_ms())
}

// ---------------------------------------------------------------------------
// Step 1 reproduction (R2-E-04)
// ---------------------------------------------------------------------------

/// The same envelope offered to two verifiers that share one store through
/// the trait. Each verifier decides freshness from its own memory, so the
/// second one, which has never seen the envelope, must learn from the
/// store's commit that the nonce and sequence are already consumed.
#[test]
fn two_verifiers_sharing_one_store_accept_the_same_envelope_at_most_once() {
    let (clock, store, a, b) = pair();
    let env = sealed(1, &clock);
    let first = a.verify(&env);
    assert!(first.is_accepted(), "{first:?}");
    let second = b.verify(&env);
    let accepted = [&first, &second].iter().filter(|v| v.is_accepted()).count();
    assert_eq!(
        accepted, 1,
        "the same envelope was accepted by both verifiers sharing one store: second verdict {second:?}"
    );
    assert_eq!(store.accepted(), 1, "the store recorded more than one acceptance");
    assert!(matches!(second, Verdict::Refused(_)));
}

// ---------------------------------------------------------------------------
// Step 2: the shared test store meets the check-and-commit contract
// ---------------------------------------------------------------------------

#[test]
fn shared_store_conforms() {
    common::conformance::replay_store_conformance(|| Box::new(SharedStore::default()));
}

#[test]
fn shared_store_conforms_when_reached_through_many_handles() {
    common::conformance::replay_store_shared_conformance(|n| {
        let store = SharedStore::default();
        (0..n).map(|_| Box::new(store.clone()) as Box<dyn ReplayStore>).collect()
    });
}

/// Many threads, two verifiers, one envelope: the store lets exactly one
/// acceptance through, whichever verifier gets there first.
#[test]
fn two_verifiers_racing_one_envelope_accept_it_exactly_once() {
    for round in 0..20 {
        let (clock, store, a, b) = pair();
        let (a, b) = (Arc::new(a), Arc::new(b));
        let env = Arc::new(sealed(1, &clock));
        let barrier = Arc::new(std::sync::Barrier::new(16));
        let threads: Vec<_> = (0..16)
            .map(|i| {
                let tr = if i % 2 == 0 { Arc::clone(&a) } else { Arc::clone(&b) };
                let (env, barrier) = (Arc::clone(&env), Arc::clone(&barrier));
                std::thread::spawn(move || {
                    barrier.wait();
                    tr.verify(&env).is_accepted()
                })
            })
            .collect();
        let accepted = threads.into_iter().map(|t| t.join().unwrap()).filter(|x| *x).count();
        assert_eq!(accepted, 1, "round {round}: accepted {accepted} times across two verifiers");
        assert_eq!(store.accepted(), 1, "round {round}");
    }
}

/// A conflict is refused with the reason the in-memory check would give,
/// as a terminal breach, and leaves the refusing verifier's memory as it
/// was: its high-water mark does not move and fresh work still passes.
#[test]
fn a_store_conflict_refuses_with_the_matching_reason_and_does_not_poison_memory() {
    let (clock, _store, a, b) = pair();
    let env = sealed(1, &clock);
    assert!(a.verify(&env).is_accepted());
    let hw_before = b.high_water_ms().unwrap();
    let v = b.verify(&env);
    assert_eq!(v.reasons(), &[ReasonCode::Replay, ReasonCode::SequenceNotIncreasing], "{v:?}");
    assert_eq!(v.outcome(), GateOutcome::TerminalBreach);
    assert_eq!(b.high_water_ms().unwrap(), hw_before, "a refused envelope moved the high-water mark");
    // The refusal did not teach B a false sequence or nonce: the next
    // envelope from the same sender is accepted by B.
    clock.advance(1);
    assert!(b.verify(&sealed(2, &clock)).is_accepted());
    // And A, which never saw sequence 2, refuses it through the store.
    let v = a.verify(&sealed(2, &clock));
    assert!(!v.is_accepted(), "{v:?}");
}

/// An operator reset on one verifier publishes its epoch floor; the other
/// verifier, whose own floor is lower, is held to it by the store.
#[test]
fn an_epoch_floor_raised_by_one_verifier_binds_the_other_through_the_store() {
    let (clock, store, a, b) = pair();
    let before = sealed(1, &clock);
    clock.advance(1_000);
    a.operator_halt();
    a.operator_reset();
    let v = b.verify(&before);
    assert_eq!(v.reasons(), &[ReasonCode::IssuedBeforeEpoch], "{v:?}");
    // A verifier started later on the same store starts at that floor.
    let c = start(&store, &clock);
    assert!(c.verify(&before).refusal().unwrap().has(ReasonCode::IssuedBeforeEpoch));
    clock.advance(cfg().max_future_skew_ms + 1);
    assert!(b.verify(&sealed(2, &clock)).is_accepted());
}

/// Behaviour change made by the check-and-commit contract, pinned here so
/// it is visible: an operator reset clears this verifier's memory of
/// sequences, but not the store's. A lower sequence after a reset was
/// accepted before Step 2 (on `Trident::new`, whose `MemoryStore` kept
/// nothing); it is now refused by the store, which is also what a
/// `FileStore` restart already did.
#[test]
fn a_sequence_lowered_after_an_operator_reset_is_refused_by_the_store() {
    let fx = setup();
    assert!(fx.trident.verify(&fx.sealed(5)).is_accepted());
    fx.trident.operator_halt();
    fx.trident.operator_reset();
    fx.clock.advance(fx.cfg.max_future_skew_ms + 1);
    let v = fx.trident.verify(&fx.sealed(4));
    assert_eq!(v.reasons(), &[ReasonCode::SequenceNotIncreasing], "{v:?}");
    assert!(fx.trident.verify(&fx.sealed(6)).is_accepted());
}
