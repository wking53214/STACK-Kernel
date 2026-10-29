//! The envelope's `subject_digest` is the CNS digest, not a Trident-only hash.
//!
//! The vectors come from `cns.gate.subject_digest` through the Sentinel
//! fixture (`cns_composition.digest_vectors` regenerates and drift-checks it),
//! so this file checks the Trident against the Python function directly.

#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use common::{remac, setup};
use serde_json::{json, Value};
use stack_trident::canonical::{sha256_hex, to_canonical_bytes, CanonicalError};
use stack_trident::cns_digest::subject_digest;
use stack_trident::{ReasonCode, TridentConfig};

const VECTORS: &str = include_str!("../../stack-sentinel/tests/fixtures/cns-digest-vectors.json");

/// Whether the Trident's grammar can carry `v` at all: no float, no integer
/// outside plus or minus 2^53 - 1. Python renders those; the Trident refuses.
fn carriable(v: &Value) -> bool {
    match v {
        Value::Number(n) => {
            n.as_i64()
                .is_some_and(|i| i.unsigned_abs() <= 9_007_199_254_740_991)
                || n.as_u64().is_some_and(|u| u <= 9_007_199_254_740_991)
        }
        Value::Array(a) => a.iter().all(carriable),
        Value::Object(m) => m.values().all(carriable),
        _ => true,
    }
}

#[test]
fn every_carriable_cns_vector_digests_identically() {
    let doc: Value = serde_json::from_str(VECTORS).unwrap();
    let limits = TridentConfig::default().limits();
    let (mut matched, mut refused) = (0, 0);
    for v in doc["vectors"].as_array().unwrap() {
        let name = v["name"].as_str().unwrap();
        let want = v["digest"].as_str().unwrap();
        let got = subject_digest(&v["content"], &limits);
        if carriable(&v["content"]) {
            match got {
                Ok(d) => {
                    assert_eq!(d, want, "vector {name}");
                    matched += 1;
                }
                // Deeper than the configured cap is a limit, not a mismatch.
                Err(CanonicalError::TooDeep) => refused += 1,
                Err(e) => panic!("vector {name} refused: {e}"),
            }
        } else {
            assert!(
                got.is_err(),
                "vector {name} has a float or a big integer and must be refused"
            );
            refused += 1;
        }
    }
    // Guards against a fixture that quietly stopped exercising anything.
    assert!(
        matched >= 15,
        "only {matched} vectors matched ({refused} refused)"
    );
}

/// Keys above U+FFFF are where CNS (code point order) and RFC 8785 (UTF-16
/// order) disagree. Known answers from `cns.gate.subject_digest`.
#[test]
fn key_order_follows_code_points_not_utf16() {
    let limits = TridentConfig::default().limits();
    let astral = json!({"\u{ffff}": 1, "\u{10000}": 2});
    assert_eq!(
        subject_digest(&astral, &limits).unwrap(),
        "8898c97692034cad808f9ad7115765c8e8d5c3c68e731b8dfcba2fce9e19c0a3"
    );
    let mixed = json!({"t": "x", "n": [1, -5, null, true, {"k": "é中😀"}]});
    assert_eq!(
        subject_digest(&mixed, &limits).unwrap(),
        "64f872ca42a7983f86b48cbf8a598e480290f072160cbc40aa5f6a4c46ceeb3e"
    );
}

#[test]
fn sealed_envelope_carries_the_cns_digest_not_a_sha256_of_json() {
    let fx = setup();
    let env = fx.sealed(1);
    let limits = fx.cfg.limits();
    assert_eq!(
        env.subject_digest,
        subject_digest(&env.payload, &limits).unwrap()
    );
    let json_hash = sha256_hex(&to_canonical_bytes(&env.payload, &limits).unwrap());
    assert_ne!(env.subject_digest, json_hash);
}

/// A producer that computes the CNS digest on its own (as the Python side
/// does) and signs the envelope is accepted.
#[test]
fn an_independent_cns_producer_is_accepted() {
    let fx = setup();
    let mut env = fx.sealed(1);
    env.payload = json!({"t": "x", "n": [1, -5, null, true, {"k": "é中😀"}]});
    env.subject_digest =
        "64f872ca42a7983f86b48cbf8a598e480290f072160cbc40aa5f6a4c46ceeb3e".to_owned();
    remac(&mut env, "a");
    let v = fx.trident.verify(&env);
    assert!(v.is_accepted(), "{v:?}");
}

/// The old Trident-only digest, even with a valid MAC, no longer binds.
#[test]
fn a_sha256_of_canonical_json_digest_is_refused() {
    let fx = setup();
    let mut env = fx.sealed(1);
    env.subject_digest = sha256_hex(&to_canonical_bytes(&env.payload, &fx.cfg.limits()).unwrap());
    remac(&mut env, "a");
    let v = fx.trident.verify(&env);
    assert!(!v.is_accepted());
    assert!(
        v.reasons().contains(&ReasonCode::SubjectDigestMismatch),
        "{v:?}"
    );
}

/// A digest that is correct for different content (a transplanted verdict)
/// is refused even when the sender signed it.
#[test]
fn a_digest_of_other_content_is_refused() {
    let fx = setup();
    let mut env = fx.sealed(1);
    env.subject_digest = subject_digest(&json!({"other": 1}), &fx.cfg.limits()).unwrap();
    remac(&mut env, "a");
    let v = fx.trident.verify(&env);
    assert!(!v.is_accepted());
    assert!(
        v.reasons().contains(&ReasonCode::SubjectDigestMismatch),
        "{v:?}"
    );
}
