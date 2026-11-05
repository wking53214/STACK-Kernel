//! Step 2 (R-7, G-5): the use store returns evidence of where it recorded a
//! use, and `AuthorizedAction` carries it. A durable store gives a record hash
//! and a position; the memory store gives a clearly labeled non-durable
//! marker; a store that predates the API gives `NotProvided`.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use common::{
    authority_with, baseline_capability, baseline_request, fixture_nonce, issue, memory_authority, memory_store,
    production_config, TempDir, T0,
};
use stack_authority::{
    Capability, CapabilityDigest, Digest32, FileUseStore, ManualClock, MemoryUseStore, UseError, UseEvidence, UseKey,
    UseStore,
};

fn wire(id: &str, one_time: bool) -> Vec<u8> {
    let mut cap: Capability = baseline_capability();
    cap.cap_id = id.into();
    cap.one_time = one_time;
    cap.nonce = fixture_nonce(id);
    issue(&cap, "issuer-1")
}

fn clock() -> ManualClock {
    ManualClock::new(T0 + 1_000)
}

#[test]
fn a_durable_store_returns_a_record_hash_a_position_and_the_head() {
    let dir = TempDir::new("evidence-durable");
    let store = FileUseStore::open(dir.file("uses.log"), 64).unwrap();
    let auth = authority_with(production_config());
    let a1 = auth.authorize(&wire("e-1", true), &baseline_request(), &clock(), &store).unwrap();
    let a2 = auth.authorize(&wire("e-2", true), &baseline_request(), &clock(), &store).unwrap();
    let (UseEvidence::Durable { record_hash: h1, position: p1, head: k1 }, UseEvidence::Durable { record_hash: h2, position: p2, head: k2 }) =
        (*a1.use_evidence(), *a2.use_evidence())
    else {
        panic!("expected durable evidence: {:?} {:?}", a1.use_evidence(), a2.use_evidence());
    };
    assert_eq!((p1, p2), (1, 2), "positions count records from 1");
    assert_ne!(h1, h2, "each use is its own record");
    assert_eq!((h1, h2), (k1, k2), "the head after an append is the new record's hash");
    assert_eq!(Digest32::from_bytes(store.head().unwrap()), k2, "the evidence head is the store head");
}

#[test]
fn a_reusable_capability_seen_again_writes_nothing_and_says_so() {
    let dir = TempDir::new("evidence-reuse");
    let store = FileUseStore::open(dir.file("uses.log"), 64).unwrap();
    let auth = authority_with(production_config());
    let w = wire("reuse", false);
    let first = auth.authorize(&w, &baseline_request(), &clock(), &store).unwrap();
    let second = auth.authorize(&w, &baseline_request(), &clock(), &store).unwrap();
    assert!(matches!(first.use_evidence(), UseEvidence::Durable { position: 1, .. }));
    let UseEvidence::NoNewRecord { position, head } = *second.use_evidence() else {
        panic!("{:?}", second.use_evidence());
    };
    assert_eq!(position, 1);
    assert_eq!(Digest32::from_bytes(store.head().unwrap()), head);
}

#[test]
fn the_memory_store_returns_the_non_durable_marker_never_a_position() {
    let store = memory_store();
    let a = memory_authority().authorize(&wire("mem", true), &baseline_request(), &clock(), &store).unwrap();
    assert_eq!(*a.use_evidence(), UseEvidence::NonDurableMemory);
}

#[derive(Debug)]
struct LegacyStore(MemoryUseStore);

impl UseStore for LegacyStore {
    fn record_use(&self, key: &UseKey<'_>, one_time: bool, expires_at_ms: u64, now_ms: u64) -> Result<(), UseError> {
        self.0.record_use(key, one_time, expires_at_ms, now_ms)
    }
    fn is_durable(&self) -> bool {
        true
    }
}

#[test]
fn a_store_that_predates_the_api_is_never_credited_with_a_position() {
    let store = LegacyStore(memory_store());
    let a = authority_with(production_config())
        .authorize(&wire("legacy", true), &baseline_request(), &clock(), &store)
        .unwrap();
    assert_eq!(*a.use_evidence(), UseEvidence::NotProvided);
    // And the one-time guarantee is exactly what it was.
    let digest = CapabilityDigest::of_wire(&[1]);
    let key = UseKey { cap_id: "x", digest: &digest };
    assert_eq!(store.record_use(&key, true, 100, 0), Ok(()));
    assert_eq!(store.record_use(&key, true, 100, 0), Err(UseError::AlreadyUsed));
}
