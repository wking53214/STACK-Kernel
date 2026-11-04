//! The envelope's `subject_digest` is the CNS digest, not a Trident-only hash.
//!
//! The vectors and the differential corpus come from `cns.gate.subject_digest`
//! through the Sentinel fixtures (`cns_composition.digest_vectors` regenerates
//! and drift-checks them), so this file checks the Trident against the Python
//! function directly. The Trident accepts the restricted_v1 sub-domain the
//! vectors file declares: inside it, rendering and digest must be identical;
//! outside it, the Trident must refuse with a typed error, never compute a
//! different digest (docs/cns-digest-contract.md).

#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use common::{nonce_for, remac, setup, Fx};
use serde_json::{json, Value};
use stack_trident::canonical::{sha256_hex, to_canonical_bytes, to_hex, CanonicalError};
use stack_trident::cns_digest::{canonical_rendering, subject_digest};
use stack_trident::{
    seal, EnvelopeDraft, GateOutcome, GatePosition, HandoffEnvelope, ReasonCode, SealError, TridentConfig,
};

const VECTORS: &str = include_str!("../../stack-sentinel/tests/fixtures/cns-digest-vectors.json");
const DIFFERENTIAL: &str = include_str!("../../stack-sentinel/tests/fixtures/digest-differential.json");

/// Exact sizes of the vendored files and of their restricted_v1 subsets.
const VECTOR_COUNT: usize = 38;
const RESTRICTED_VECTOR_COUNT: usize = 27;
const DIFFERENTIAL_COUNT: usize = 400;
const RESTRICTED_DIFFERENTIAL_COUNT: usize = 283;
/// `domain.restricted_v1.max_container_depth` in the vectors file: the envelope object is level 1, so a
/// payload may nest `max_depth - 1` levels.
const RESTRICTED_MAX_DEPTH: usize = 31;

fn entries(doc: &str, key: &str) -> Vec<Value> {
    let doc: Value = serde_json::from_str(doc).unwrap();
    doc[key].as_array().unwrap().clone()
}

/// 0 for a scalar, 1 plus the deepest member for an object or array (the vectors file's `depth`).
fn container_depth(v: &Value) -> usize {
    match v {
        Value::Array(a) => 1 + a.iter().map(container_depth).max().unwrap_or(0),
        Value::Object(m) => 1 + m.values().map(container_depth).max().unwrap_or(0),
        _ => 0,
    }
}

fn seal_payload(fx: &Fx, seq: u64, payload: &Value) -> Result<HandoffEnvelope, SealError> {
    seal(
        EnvelopeDraft {
            sequence: seq,
            issued_at_unix_ms: fx.now(),
            nonce: nonce_for(seq),
            gate_position: GatePosition::Alpha,
            gate_outcome: GateOutcome::Pass,
            payload: payload.clone(),
        },
        &fx.key_a,
        &fx.cfg.limits(),
    )
}

fn typed_refusal(e: CanonicalError) -> bool {
    matches!(
        e,
        CanonicalError::NonInteger | CanonicalError::IntegerOutOfRange | CanonicalError::TooDeep
    )
}

/// restricted_v1 entries: identical rendering and digest, and an envelope that seals and verifies.
/// Every other entry: a typed refusal on the envelope path, never a different digest. Returns
/// (matched, refused).
fn hold_to_cns(fx: &Fx, entries: &[Value], next_seq: &mut u64) -> (usize, usize) {
    let limits = fx.cfg.limits();
    let (mut matched, mut refused) = (0, 0);
    for (i, v) in entries.iter().enumerate() {
        let name = v["name"].as_str().map_or_else(|| format!("case {i}"), str::to_owned);
        let want = v["digest"].as_str().unwrap();
        let content = &v["content"];
        *next_seq += 1;
        if v["restricted_v1"].as_bool().unwrap() {
            assert_eq!(
                canonical_rendering(content, &limits).unwrap(),
                v["rendering"].as_str().unwrap(),
                "{name}"
            );
            assert_eq!(subject_digest(content, &limits).unwrap(), want, "{name}");
            let env = seal_payload(fx, *next_seq, content).unwrap();
            assert_eq!(env.subject_digest, want, "{name}");
            let verdict = fx.trident.verify(&env);
            assert!(verdict.is_accepted(), "{name}: {verdict:?}");
            matched += 1;
        } else {
            let sealed = seal_payload(fx, *next_seq, content);
            assert!(
                matches!(sealed, Err(SealError::Encoding(e)) if typed_refusal(e)),
                "{name} is outside restricted_v1 and must be refused with a typed error, got {sealed:?}"
            );
            match subject_digest(content, &limits) {
                Err(e) => assert!(typed_refusal(e), "{name}: {e}"),
                // Called directly, the function accepts depth max_depth (32), one more than an envelope
                // payload may have. It is still the CNS digest, never a different one.
                Ok(d) => {
                    assert_eq!(container_depth(content), RESTRICTED_MAX_DEPTH + 1, "{name}");
                    assert_eq!(d, want, "{name}");
                }
            }
            refused += 1;
        }
    }
    (matched, refused)
}

#[test]
fn every_carriable_cns_vector_digests_identically() {
    let fx = setup();
    let vectors = entries(VECTORS, "vectors");
    assert_eq!(vectors.len(), VECTOR_COUNT);
    let (matched, refused) = hold_to_cns(&fx, &vectors, &mut 0);
    assert_eq!(matched, RESTRICTED_VECTOR_COUNT);
    assert_eq!(refused, VECTOR_COUNT - RESTRICTED_VECTOR_COUNT);
}

#[test]
fn every_restricted_differential_case_matches_and_every_other_is_refused() {
    let fx = setup();
    let cases = entries(DIFFERENTIAL, "cases");
    let doc: Value = serde_json::from_str(DIFFERENTIAL).unwrap();
    assert_eq!(doc["count"].as_u64(), Some(DIFFERENTIAL_COUNT as u64));
    assert_eq!(cases.len(), DIFFERENTIAL_COUNT);
    let (matched, refused) = hold_to_cns(&fx, &cases, &mut 0);
    assert_eq!(matched, RESTRICTED_DIFFERENTIAL_COUNT);
    assert_eq!(refused, DIFFERENTIAL_COUNT - RESTRICTED_DIFFERENTIAL_COUNT);
}

/// Content of container depth exactly `depth`: a top-level object, then arrays and objects alternating.
fn nested(depth: usize) -> Value {
    let mut v = json!("bottom");
    for level in (2..=depth).rev() {
        v = if level % 2 == 0 { json!([v]) } else { json!({"m": v}) };
    }
    json!({"m": v})
}

/// The depth rule exactly as `domain.restricted_v1` in the vectors file states it.
#[test]
fn the_depth_boundary_is_the_documented_one() {
    let doc: Value = serde_json::from_str(VECTORS).unwrap();
    let restricted = &doc["domain"]["restricted_v1"];
    assert_eq!(restricted["max_container_depth"].as_u64(), Some(RESTRICTED_MAX_DEPTH as u64));
    assert_eq!(restricted["max_abs_integer"].as_u64(), Some(stack_trident::MAX_SAFE_INTEGER));
    let fx = setup();
    let limits = fx.cfg.limits();
    assert_eq!(limits.max_depth, 32);
    assert_eq!(TridentConfig::default().max_depth, 32);
    assert_eq!(RESTRICTED_MAX_DEPTH, limits.max_depth - 1);
    assert_eq!(container_depth(&nested(31)), 31);
    assert_eq!(container_depth(&nested(32)), 32);
    // The envelope path: 31 seals and verifies, 32 is refused before any digest is computed.
    let env = seal_payload(&fx, 1, &nested(31)).unwrap();
    assert!(fx.trident.verify(&env).is_accepted());
    assert_eq!(
        seal_payload(&fx, 2, &nested(32)).unwrap_err(),
        SealError::Encoding(CanonicalError::TooDeep)
    );
    let mut deeper = seal_payload(&fx, 3, &nested(31)).unwrap();
    deeper.payload = nested(32);
    let v = fx.trident.verify(&deeper);
    assert!(!v.is_accepted());
    assert!(v.reasons().contains(&ReasonCode::TooDeep), "{v:?}");
    // The function called directly: depth max_depth is accepted, one more is refused.
    assert!(subject_digest(&nested(32), &limits).is_ok());
    assert_eq!(subject_digest(&nested(33), &limits), Err(CanonicalError::TooDeep));
    assert_eq!(canonical_rendering(&nested(33), &limits), Err(CanonicalError::TooDeep));
}

/// The algorithm the Trident used before it adopted the CNS digest: SHA-256 of its canonical JSON.
/// For every restricted content it differs from the CNS digest and, signed into an envelope, is refused.
/// A fresh receiver per envelope, so the sender's breaker never trips and every refusal is the digest's.
#[test]
fn a_canonical_json_digest_never_equals_the_cns_digest_and_never_verifies() {
    let limits = setup().cfg.limits();
    let mut checked = 0;
    for v in entries(VECTORS, "vectors").iter().chain(entries(DIFFERENTIAL, "cases").iter()) {
        if !v["restricted_v1"].as_bool().unwrap() {
            continue;
        }
        let content = &v["content"];
        let json_hash = sha256_hex(&to_canonical_bytes(content, &limits).unwrap());
        assert_ne!(json_hash, v["digest"].as_str().unwrap());
        let fx = setup();
        let mut env = seal_payload(&fx, 1, content).unwrap();
        env.subject_digest = json_hash;
        remac(&mut env, "a");
        let verdict = fx.trident.verify(&env);
        assert!(!verdict.is_accepted());
        assert!(verdict.reasons().contains(&ReasonCode::SubjectDigestMismatch), "{verdict:?}");
        checked += 1;
    }
    assert_eq!(checked, RESTRICTED_VECTOR_COUNT + RESTRICTED_DIFFERENTIAL_COUNT);
}

/// The CNS rendering with object keys in UTF-16 code unit order instead of code point order.
fn render_utf16_order(v: &Value, out: &mut String) {
    let text = |s: &str, out: &mut String| out.push_str(&format!("s:{}:{s}", s.chars().count()));
    match v {
        Value::Null => out.push_str("n:"),
        Value::Bool(b) => out.push_str(if *b { "b:1" } else { "b:0" }),
        Value::Number(n) => out.push_str(&format!("i:{n}:")),
        Value::String(s) => text(s, out),
        Value::Array(a) => {
            out.push_str(&format!("l:{}:", a.len()));
            a.iter().for_each(|x| render_utf16_order(x, out));
        }
        Value::Object(m) => {
            out.push_str(&format!("d:{}:", m.len()));
            let mut keys: Vec<&String> = m.keys().collect();
            keys.sort_by(|a, b| a.encode_utf16().cmp(b.encode_utf16()));
            for k in keys {
                text(k, out);
                render_utf16_order(&m[k], out);
            }
        }
    }
}

/// A digest from any algorithm other than the CNS one, signed into an envelope by a key holder, is refused.
#[test]
fn an_envelope_carrying_a_digest_from_a_non_cns_algorithm_cannot_verify() {
    use sha2::{Digest, Sha256, Sha512};
    let limits = setup().cfg.limits();
    let vectors = entries(VECTORS, "vectors");
    let astral = vectors
        .iter()
        .find(|v| v["name"] == "astral_keys_sort_after_high_bmp_keys")
        .unwrap();
    let content = &astral["content"];
    let cns = astral["digest"].as_str().unwrap().to_owned();
    let rendering = canonical_rendering(content, &limits).unwrap();
    let mut utf16_order = String::new();
    render_utf16_order(content, &mut utf16_order);
    assert_ne!(utf16_order, rendering);
    let utf16_bytes: Vec<u8> = rendering.encode_utf16().flat_map(u16::to_le_bytes).collect();
    let others = [
        ("sha256 of canonical JSON", sha256_hex(&to_canonical_bytes(content, &limits).unwrap())),
        ("sha256 of serde_json text", sha256_hex(&serde_json::to_vec(content).unwrap())),
        ("sha256 of the rendering with UTF-16 key order", sha256_hex(utf16_order.as_bytes())),
        ("sha256 of the rendering as UTF-16LE", sha256_hex(&utf16_bytes)),
        ("sha512 of the rendering, truncated", to_hex(&Sha512::digest(rendering.as_bytes())[..32])),
        ("sha256 of the rendering twice", to_hex(&Sha256::digest(Sha256::digest(rendering.as_bytes())))),
        ("the CNS digest in upper case", cns.to_uppercase()),
    ];
    assert_eq!(sha256_hex(rendering.as_bytes()), cns);
    for (label, digest) in others {
        assert_ne!(digest, cns, "{label}");
        let fx = setup(); // a fresh receiver, so the sender's breaker never trips
        let mut env = seal_payload(&fx, 1, content).unwrap();
        env.subject_digest = digest;
        remac(&mut env, "a");
        let verdict = fx.trident.verify(&env);
        assert!(!verdict.is_accepted(), "{label}");
        assert!(
            verdict.reasons().contains(&ReasonCode::SubjectDigestMismatch)
                || verdict.reasons().contains(&ReasonCode::MalformedDigest),
            "{label}: {verdict:?}"
        );
    }
}

/// Keys above U+FFFF are where CNS (code point order) and RFC 8785 (UTF-16
/// order) disagree. Known answers from `cns.gate.subject_digest`.
#[test]
fn key_order_follows_code_points_not_utf16() {
    let limits = TridentConfig::unbound_audience().limits();
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
