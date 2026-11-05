//! R-5: the revocation epoch, the change hook and `recheck`, which let a
//! holder of an earlier AuthorizedAction find out that it no longer stands.

#![allow(clippy::unwrap_used)]

mod common;

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use common::{baseline_request, baseline_wire, fixture_key_id, memory_authority, memory_store, T0};
use stack_authority::{AuthorizedAction, Authority, AuthzError, CapabilityDigest, ManualClock};

fn authorized(auth: &Authority) -> AuthorizedAction {
    auth.authorize(&baseline_wire(), &baseline_request(), &ManualClock::new(T0 + 1_000), &memory_store())
        .unwrap()
}

#[test]
fn epoch_starts_at_zero_and_is_monotonic_across_both_write_paths() {
    let auth = memory_authority();
    assert_eq!(auth.revocation_epoch(), 0);
    auth.with_revocations(|r| r.revoke_id("a").unwrap()).unwrap();
    assert_eq!(auth.revocation_epoch(), 1);
    auth.with_trust(|t| t.revoke(&fixture_key_id("nobody"))).unwrap();
    assert_eq!(auth.revocation_epoch(), 2);
    // Authorizing is a read: it never moves the epoch.
    let _ = authorized(&auth);
    assert_eq!(auth.revocation_epoch(), 2);
    // A write that changes nothing still advances: an extra re-check, never a missed one.
    auth.with_revocations(|r| r.revoke_id("a").unwrap()).unwrap();
    assert_eq!(auth.revocation_epoch(), 3);
}

#[test]
fn recheck_passes_until_the_capability_is_revoked_by_id_or_digest() {
    let auth = memory_authority();
    let action = authorized(&auth);
    assert_eq!(auth.recheck(&action), Ok(()));
    auth.with_revocations(|r| r.revoke_id("cap-9999").unwrap()).unwrap();
    assert_eq!(auth.recheck(&action), Ok(()), "an unrelated revocation changes nothing");
    auth.with_revocations(|r| r.revoke_id(action.cap_id()).unwrap()).unwrap();
    assert_eq!(auth.recheck(&action), Err(AuthzError::Revoked));

    let auth = memory_authority();
    let action = authorized(&auth);
    auth.with_revocations(|r| r.revoke_digest(CapabilityDigest::of_wire(&baseline_wire())).unwrap())
        .unwrap();
    assert_eq!(auth.recheck(&action), Err(AuthzError::Revoked));
}

#[test]
fn recheck_fails_when_the_issuer_key_is_revoked() {
    let auth = memory_authority();
    let action = authorized(&auth);
    auth.with_trust(|t| assert!(t.revoke(&fixture_key_id("issuer-1")))).unwrap();
    assert_eq!(auth.recheck(&action), Err(AuthzError::IssuerRevoked));
}

#[test]
fn recheck_fails_closed_when_the_revocation_list_is_poisoned() {
    let auth = Arc::new(memory_authority());
    let action = authorized(&auth);
    let a2 = Arc::clone(&auth);
    let _ = std::thread::spawn(move || {
        let _ = a2.with_revocations(|_| panic!("poison the revocation lock"));
    })
    .join();
    assert_eq!(auth.recheck(&action), Err(AuthzError::TrustUnavailable));
    // And the write path refuses too.
    assert_eq!(auth.with_revocations(|_| ()), Err(AuthzError::TrustUnavailable));
}

#[test]
fn recheck_fails_closed_when_the_trust_set_is_poisoned() {
    let auth = Arc::new(memory_authority());
    let action = authorized(&auth);
    let a2 = Arc::clone(&auth);
    let _ = std::thread::spawn(move || {
        let _ = a2.with_trust(|_| panic!("poison the trust lock"));
    })
    .join();
    assert_eq!(auth.recheck(&action), Err(AuthzError::TrustUnavailable));
}

#[test]
fn the_change_hook_runs_after_each_write_with_the_epoch_already_advanced() {
    let auth = memory_authority();
    let action = authorized(&auth);
    let calls = Arc::new(AtomicUsize::new(0));
    let seen_epoch = Arc::new(AtomicUsize::new(usize::MAX));
    let (c, s) = (Arc::clone(&calls), Arc::clone(&seen_epoch));
    assert!(auth.set_change_hook(move |a| {
        c.fetch_add(1, Ordering::SeqCst);
        s.store(usize::try_from(a.revocation_epoch()).unwrap(), Ordering::SeqCst);
        // The write lock is released: the hook may read without deadlock.
        assert_eq!(a.recheck(&action), Ok(()));
    }));
    assert!(!auth.set_change_hook(|_| {}), "the first hook stays");
    auth.with_revocations(|r| r.revoke_id("x").unwrap()).unwrap();
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    assert_eq!(seen_epoch.load(Ordering::SeqCst), 1);
    auth.with_trust(|_| ()).unwrap();
    assert_eq!(calls.load(Ordering::SeqCst), 2);
    assert_eq!(seen_epoch.load(Ordering::SeqCst), 2);
}
