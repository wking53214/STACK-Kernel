//! A verifier that requires one-time capabilities refuses a reusable one before it records
//! anything. Found by the independent review: the kernel used to refuse a reusable capability
//! only after the authority had recorded its first presentation, so each refusal still used a
//! slot in the use store's fixed capacity and a holder of many reusable capabilities could fill it.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use common::*;
use stack_authority::{AuthorityConfig, AuthzError, Capability, MemoryUseStore};

fn one_time_required() -> AuthorityConfig {
    AuthorityConfig {
        require_one_time: true,
        ..memory_store_config()
    }
}

fn reusable(id: &str) -> Capability {
    let mut cap = baseline_capability();
    cap.cap_id = id.into();
    cap.nonce = fixture_nonce(id);
    cap.one_time = false;
    cap
}

fn one_time(id: &str) -> Capability {
    let mut cap = reusable(id);
    cap.one_time = true;
    cap
}

fn clock() -> stack_authority::ManualClock {
    stack_authority::ManualClock::new(T0 + 1)
}

#[test]
fn a_reusable_capability_is_refused_when_one_time_is_required() {
    let a = authority_with(one_time_required());
    let store = memory_store();
    let wire = issue(&reusable("cap-r1"), "issuer-1");
    assert_eq!(
        a.authorize(&wire, &baseline_request(), &clock(), &store).unwrap_err(),
        AuthzError::ReusableNotAllowed
    );
}

#[test]
fn a_one_time_capability_is_accepted_when_one_time_is_required() {
    let a = authority_with(one_time_required());
    let store = memory_store();
    let wire = issue(&one_time("cap-o1"), "issuer-1");
    assert!(a.authorize(&wire, &baseline_request(), &clock(), &store).is_ok());
}

#[test]
fn control_a_reusable_capability_is_accepted_when_one_time_is_not_required() {
    let a = memory_authority();
    let store = memory_store();
    let wire = issue(&reusable("cap-r2"), "issuer-1");
    assert!(a.authorize(&wire, &baseline_request(), &clock(), &store).is_ok());
}

#[test]
fn refused_reusable_capabilities_use_no_store_slot() {
    // A store with room for exactly one use. If a refusal recorded anything, the honest one-time
    // capability afterwards would find the store full.
    let a = authority_with(one_time_required());
    let store = MemoryUseStore::new(1);
    for i in 0..5 {
        let wire = issue(&reusable(&format!("cap-flood-{i}")), "issuer-1");
        assert_eq!(
            a.authorize(&wire, &baseline_request(), &clock(), &store).unwrap_err(),
            AuthzError::ReusableNotAllowed
        );
    }
    let wire = issue(&one_time("cap-honest"), "issuer-1");
    assert!(a.authorize(&wire, &baseline_request(), &clock(), &store).is_ok());
}
