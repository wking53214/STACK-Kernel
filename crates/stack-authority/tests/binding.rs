//! Capability format version 2: the execution binding.
//!
//! A version 1 capability authorizes an operation on a resource and nothing about
//! how it runs. A version 2 capability also commits to the digest of the arguments,
//! the worker kind and the digest of the limits the kernel will run it under, and
//! the verifier refuses a request that describes anything else. These tests use
//! the real encoder, parser, verifier and use store with fixture keys.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use common::*;
use stack_authority::{
    ActionRequest, AuthorityConfig, AuthzError, Capability, Digest32, ExecutionBinding, Field, ParseError,
    SignedCapability, DOMAIN_TAG, DOMAIN_TAG_V2,
};

fn binding() -> ExecutionBinding {
    ExecutionBinding {
        args_digest: fixture_digest("args"),
        worker: "return_bytes".into(),
        limits_digest: fixture_digest("limits"),
    }
}

fn bound_capability() -> Capability {
    let mut cap = baseline_capability();
    cap.binding = Some(binding());
    cap
}

fn bound_wire() -> Vec<u8> {
    issue(&bound_capability(), "issuer-1")
}

fn request_with(execution: Option<ExecutionBinding>) -> ActionRequest {
    ActionRequest {
        execution,
        ..baseline_request()
    }
}

#[test]
fn a_bound_capability_is_written_under_the_version_2_tag_and_an_unbound_one_under_version_1() {
    let v2 = bound_wire();
    assert!(v2.starts_with(DOMAIN_TAG_V2));
    assert!(baseline_wire().starts_with(DOMAIN_TAG));

    let parsed = SignedCapability::parse(&v2, 16 * 1024).unwrap();
    assert_eq!(parsed.capability().binding, Some(binding()));
    let parsed_v1 = SignedCapability::parse(&baseline_wire(), 16 * 1024).unwrap();
    assert_eq!(parsed_v1.capability().binding, None);
}

#[test]
fn a_record_has_one_encoding_so_the_version_and_the_body_must_agree() {
    // A version 2 body under the version 1 tag has trailing bytes before the key id and signature.
    let mut as_v1 = bound_wire();
    as_v1[..DOMAIN_TAG.len()].copy_from_slice(DOMAIN_TAG);
    assert!(SignedCapability::parse(&as_v1, 16 * 1024).is_err());
    // A version 1 body under the version 2 tag is missing the binding.
    let mut as_v2 = baseline_wire();
    as_v2[..DOMAIN_TAG_V2.len()].copy_from_slice(DOMAIN_TAG_V2);
    assert!(SignedCapability::parse(&as_v2, 16 * 1024).is_err());
    // A later version is not guessed at.
    let mut v3 = bound_wire();
    v3[17] = b'3';
    assert_eq!(SignedCapability::parse(&v3, 16 * 1024).unwrap_err(), ParseError::UnsupportedVersion);
}

#[test]
fn a_request_that_describes_what_the_capability_binds_is_authorized() {
    let a = memory_authority();
    let store = memory_store();
    let clock = stack_authority::ManualClock::new(T0 + 1);
    let action = a
        .authorize(&bound_wire(), &request_with(Some(binding())), &clock, &store)
        .unwrap();
    assert_eq!(action.operation(), "read");
}

#[test]
fn a_request_that_describes_other_arguments_workers_or_limits_is_refused_each_for_its_own_reason() {
    let a = memory_authority();
    let clock = stack_authority::ManualClock::new(T0 + 1);
    let cases: [(ExecutionBinding, AuthzError); 3] = [
        (
            ExecutionBinding {
                args_digest: fixture_digest("other args"),
                ..binding()
            },
            AuthzError::ArgsMismatch,
        ),
        (
            ExecutionBinding {
                worker: "spin_forever".into(),
                ..binding()
            },
            AuthzError::WorkerMismatch,
        ),
        (
            ExecutionBinding {
                limits_digest: fixture_digest("other limits"),
                ..binding()
            },
            AuthzError::LimitsMismatch,
        ),
    ];
    for (wrong, want) in cases {
        let store = memory_store();
        let got = a
            .authorize(&bound_wire(), &request_with(Some(wrong)), &clock, &store)
            .unwrap_err();
        assert_eq!(got, want);
    }
}

#[test]
fn a_refused_binding_consumes_nothing_so_the_one_time_capability_still_works() {
    let mut cap = bound_capability();
    cap.one_time = true;
    let wire = issue(&cap, "issuer-1");
    let a = memory_authority();
    let store = memory_store();
    let clock = stack_authority::ManualClock::new(T0 + 1);
    let wrong = ExecutionBinding {
        args_digest: fixture_digest("other args"),
        ..binding()
    };
    assert_eq!(
        a.authorize(&wire, &request_with(Some(wrong)), &clock, &store).unwrap_err(),
        AuthzError::ArgsMismatch
    );
    // The mismatch happened before the use was recorded: the same capability is still unspent.
    assert!(a.authorize(&wire, &request_with(Some(binding())), &clock, &store).is_ok());
    // And now it is spent.
    assert_eq!(
        a.authorize(&wire, &request_with(Some(binding())), &clock, &store).unwrap_err(),
        AuthzError::Replay
    );
}

#[test]
fn a_bound_capability_is_refused_when_the_request_does_not_say_what_will_run() {
    let a = memory_authority();
    let store = memory_store();
    let clock = stack_authority::ManualClock::new(T0 + 1);
    assert_eq!(
        a.authorize(&bound_wire(), &request_with(None), &clock, &store).unwrap_err(),
        AuthzError::ExecutionNotDescribed
    );
}

#[test]
fn control_an_unbound_capability_still_authorizes_when_the_verifier_does_not_require_a_binding() {
    let a = memory_authority();
    let store = memory_store();
    let clock = stack_authority::ManualClock::new(T0 + 1);
    // With and without a described execution: version 1 behaves as it always did.
    assert!(a.authorize(&baseline_wire(), &request_with(None), &clock, &store).is_ok());
    let store = memory_store();
    assert!(a
        .authorize(&baseline_wire(), &request_with(Some(binding())), &clock, &store)
        .is_ok());
}

#[test]
fn a_verifier_that_requires_a_binding_refuses_an_unbound_capability_and_accepts_a_bound_one() {
    let config = AuthorityConfig {
        require_execution_binding: true,
        ..memory_store_config()
    };
    let a = authority_with(config);
    let clock = stack_authority::ManualClock::new(T0 + 1);
    let store = memory_store();
    assert_eq!(
        a.authorize(&baseline_wire(), &request_with(Some(binding())), &clock, &store)
            .unwrap_err(),
        AuthzError::ExecutionBindingRequired
    );
    let store = memory_store();
    assert!(a
        .authorize(&bound_wire(), &request_with(Some(binding())), &clock, &store)
        .is_ok());
}

#[test]
fn every_single_byte_flip_of_a_bound_capability_is_refused() {
    let a = memory_authority();
    let clock = stack_authority::ManualClock::new(T0 + 1);
    let wire = bound_wire();
    for i in 0..wire.len() {
        for bit in 0..8 {
            let mut m = wire.clone();
            m[i] ^= 1 << bit;
            let store = memory_store();
            assert!(
                a.authorize(&m, &request_with(Some(binding())), &clock, &store).is_err(),
                "byte {i} bit {bit}: a flipped capability was authorized"
            );
        }
    }
}

#[test]
fn the_encoder_refuses_a_worker_label_that_is_empty_too_long_or_holds_a_control_character() {
    let key_id = fixture_key_id("issuer-1");
    for bad in [String::new(), "x".repeat(65), "bad\nlabel".to_owned()] {
        let mut cap = bound_capability();
        cap.binding = Some(ExecutionBinding {
            worker: bad.clone(),
            ..binding()
        });
        let err = cap.encode_signed_region(key_id.as_bytes()).unwrap_err();
        assert!(
            matches!(
                err,
                ParseError::LengthOutOfBounds(Field::Worker) | ParseError::ControlCharacter(Field::Worker)
            ),
            "{bad:?}: {err:?}"
        );
    }
}

#[test]
fn two_capabilities_that_differ_only_in_the_binding_have_different_digests() {
    let a = SignedCapability::parse(&bound_wire(), 16 * 1024).unwrap();
    let mut other = bound_capability();
    other.binding = Some(ExecutionBinding {
        args_digest: Digest32::from_bytes([0xEE; 32]),
        ..binding()
    });
    let b = SignedCapability::parse(&issue(&other, "issuer-1"), 16 * 1024).unwrap();
    assert_ne!(a.digest(), b.digest());
}
