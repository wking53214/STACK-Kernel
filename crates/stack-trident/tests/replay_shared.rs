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
    ManualClock, Nonce, ReplayStore, RestoredState, SecretKey, StoreError, Trident, TridentConfig, Verdict,
};
use stack_trident::store::{RestoredNonce, RestoredSender};

// ---------------------------------------------------------------------------
// A store over shared in-process state (test only)
// ---------------------------------------------------------------------------

#[derive(Debug, Default)]
struct SharedState {
    records: Vec<AcceptRecord>,
    quarantined: HashMap<Fingerprint, u64>,
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
        // The contract before decision D: make the acceptance durable.
        // There is no way to say "another writer already consumed this".
        self.0.lock().unwrap().records.push(*record);
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
