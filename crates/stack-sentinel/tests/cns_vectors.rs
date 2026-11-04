//! The Rust reproduction of `cns.gate.subject_digest`, held to CNS's own answer key.
//!
//! `fixtures/cns-digest-vectors.json` is a copy of CNS's `contracts/digest-vectors.json`: contents, and
//! the digest CNS gives each. They were chosen to catch what a near-miss gets wrong (a bool that is
//! not 1, a length counted in bytes, keys sorted by locale, `-0.0`, a float rendered the long way, an
//! integer past 64 bits). This test recomputes every one and requires an exact match.
//!
//! `fixtures/digest-differential.json` is a copy of CNS's `contracts/digest-differential.json`: 400
//! seeded pseudo-random contents with their rendering and digest. Every vector and every case is
//! checked on its rendering bytes and its digest, and every named refusal is refused.
//!
//! When CNS changes the file, copy it over this one and make this test pass again. CNS checks this
//! copy against its own (`python -m cns_composition.digest_vectors --stack ...`), so a stale copy is
//! reported there rather than discovered when a real ledger row fails to verify.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use stack_sentinel::cns::{canonical_rendering, CnsError};
use stack_sentinel::pyjson::{parse, Object, ParseLimits, Value};
use stack_sentinel::subject_digest;

/// Exact sizes of the vendored files. A fixture that lost entries fails here, not by checking less.
const VECTOR_COUNT: usize = 38;
const RESTRICTED_VECTOR_COUNT: usize = 27;
const REFUSAL_COUNT: usize = 7;
const DIFFERENTIAL_COUNT: usize = 400;
const RESTRICTED_DIFFERENTIAL_COUNT: usize = 283;

#[test]
fn every_cns_vector_is_reproduced() {
    let file = common::load("cns-digest-vectors.json");
    assert_eq!(file["schema"].as_str(), Some("cns-digest-vectors/2"));
    let Value::Array(vectors) = &file["vectors"] else {
        panic!("no vectors")
    };
    assert_eq!(vectors.len(), VECTOR_COUNT, "the vectors file holds {} vectors", vectors.len());
    let mut wrong = Vec::new();
    for v in vectors {
        let v = v.as_object().unwrap();
        let name = v["name"].as_str().unwrap();
        let want = v["digest"].as_str().unwrap();
        match subject_digest(&v["content"]) {
            Ok(got) if got == want => {}
            Ok(got) => wrong.push(format!("{name}: got {got}, CNS says {want}")),
            Err(e) => wrong.push(format!("{name}: refused ({e}), CNS says {want}")),
        }
    }
    assert!(wrong.is_empty(), "{} vector(s) differ from CNS:\n{}", wrong.len(), wrong.join("\n"));
}

#[test]
fn the_vectors_are_distinct_so_a_constant_cannot_pass() {
    let file = common::load("cns-digest-vectors.json");
    let Value::Array(vectors) = &file["vectors"] else {
        panic!("no vectors")
    };
    let mut seen = std::collections::BTreeSet::new();
    for v in vectors {
        seen.insert(v.as_object().unwrap()["digest"].as_str().unwrap().to_owned());
    }
    // Every vector has its own digest except the two pairs meant to coincide: key order, and -0.0 with 0.0.
    assert_eq!(seen.len(), vectors.len() - 2, "only key order and the sign of zero may digest alike");
}

fn entries<'a>(file: &'a Object, key: &str) -> &'a [Value] {
    match &file[key] {
        Value::Array(items) => items,
        _ => panic!("{key} is not a list"),
    }
}

fn flag(v: &Object) -> bool {
    match v["restricted_v1"] {
        Value::Bool(b) => b,
        _ => panic!("restricted_v1 is not a boolean"),
    }
}

/// Every entry's rendering and digest, compared exactly. Returns how many were checked and how many are
/// flagged restricted_v1.
fn check_rendering_and_digest(entries: &[Value], label: &str) -> (usize, usize) {
    let (mut checked, mut restricted) = (0, 0);
    let mut wrong = Vec::new();
    for (i, v) in entries.iter().enumerate() {
        let v = v.as_object().unwrap();
        let name = v.get("name").and_then(Value::as_str).map_or_else(|| format!("{label} {i}"), str::to_owned);
        let want_rendering = v["rendering"].as_str().unwrap();
        let want_digest = v["digest"].as_str().unwrap();
        match canonical_rendering(&v["content"]) {
            Ok(r) if r == want_rendering => {}
            Ok(r) => wrong.push(format!("{name}: rendering differs at byte {}", first_difference(&r, want_rendering))),
            Err(e) => wrong.push(format!("{name}: refused ({e})")),
        }
        match subject_digest(&v["content"]) {
            Ok(d) if d == want_digest => {}
            Ok(d) => wrong.push(format!("{name}: digest {d}, CNS says {want_digest}")),
            Err(e) => wrong.push(format!("{name}: refused ({e})")),
        }
        checked += 1;
        restricted += usize::from(flag(v));
    }
    assert!(wrong.is_empty(), "{} difference(s) from CNS:\n{}", wrong.len(), wrong.join("\n"));
    (checked, restricted)
}

fn first_difference(a: &str, b: &str) -> usize {
    a.bytes().zip(b.bytes()).take_while(|(x, y)| x == y).count()
}

#[test]
fn the_vectors_file_names_its_digest_version() {
    let file = common::load("cns-digest-vectors.json");
    assert_eq!(file["digest_version"].as_str(), Some("cns-digest/1"));
    let differential = common::load("digest-differential.json");
    assert_eq!(differential["schema"].as_str(), Some("cns-digest-differential/1"));
    assert_eq!(differential["digest_version"].as_str(), Some("cns-digest/1"));
}

#[test]
fn every_vector_renders_byte_for_byte_as_cns_renders_it() {
    let file = common::load("cns-digest-vectors.json");
    let (checked, restricted) = check_rendering_and_digest(entries(&file, "vectors"), "vector");
    assert_eq!(checked, VECTOR_COUNT);
    assert_eq!(restricted, RESTRICTED_VECTOR_COUNT);
}

#[test]
fn every_differential_case_renders_and_digests_as_cns_does() {
    let file = common::load("digest-differential.json");
    let cases = entries(&file, "cases");
    let Value::Int(count) = &file["count"] else {
        panic!("count is not an integer")
    };
    assert_eq!(count.to_i64(), Some(i64::try_from(DIFFERENTIAL_COUNT).unwrap()));
    assert_eq!(cases.len(), DIFFERENTIAL_COUNT);
    let (checked, restricted) = check_rendering_and_digest(cases, "case");
    assert_eq!(checked, DIFFERENTIAL_COUNT);
    assert_eq!(restricted, RESTRICTED_DIFFERENTIAL_COUNT);
}

/// The full-domain reproduction has no envelope and no depth cap below its parser's 256, so it renders
/// every vector, restricted or not. This holds the number of each to the file.
#[test]
fn the_restricted_flags_partition_the_vectors_exactly() {
    let file = common::load("cns-digest-vectors.json");
    let flags: Vec<bool> = entries(&file, "vectors").iter().map(|v| flag(v.as_object().unwrap())).collect();
    assert_eq!(flags.iter().filter(|b| **b).count(), RESTRICTED_VECTOR_COUNT);
    assert_eq!(flags.iter().filter(|b| !**b).count(), VECTOR_COUNT - RESTRICTED_VECTOR_COUNT);
}

/// No variant of the reader's value type is bytes, and object keys are `String`, so the two refusals
/// JSON cannot write (`non_text_key`, `bytes`) cannot reach the digest. This match has no wildcard:
/// adding a variant stops it compiling.
fn representable(v: &Value) -> &'static str {
    match v {
        Value::Null => "null",
        Value::Bool(_) => "bool",
        Value::Int(_) => "int",
        Value::Float(_) => "float",
        Value::Str(_) => "str",
        Value::Object(o) => {
            let _keys_are_text: Option<&String> = o.keys().next();
            "object"
        }
        Value::Array(_) => "array",
    }
}

#[test]
fn every_named_refusal_is_refused() {
    let file = common::load("cns-digest-vectors.json");
    let refusals = entries(&file, "refusals");
    assert_eq!(refusals.len(), REFUSAL_COUNT);
    let mut names = Vec::new();
    for r in refusals {
        let r = r.as_object().unwrap();
        let name = r["name"].as_str().unwrap().to_owned();
        match &r["lenient_json"] {
            Value::Str(text) => match parse(text.as_bytes(), ParseLimits::default()) {
                // The reader keeps NaN and the infinities, as Python's json does; the digest refuses them.
                Ok(v) => assert_eq!(subject_digest(&v), Err(CnsError::NonFiniteFloat), "{name}"),
                // The reader refuses a lone surrogate escape before the digest is reached.
                Err(e) => assert_eq!(e.label(), "lone_surrogate", "{name}"),
            },
            Value::Null => {
                let _ = representable(&Value::Null);
            }
            other => panic!("{name}: lenient_json is {}", other.type_name()),
        }
        names.push(name);
    }
    assert_eq!(
        names,
        [
            "nan",
            "positive_infinity",
            "negative_infinity",
            "lone_high_surrogate",
            "lone_low_surrogate",
            "non_text_key",
            "bytes"
        ]
    );
    let unwritable: Vec<&str> = refusals
        .iter()
        .map(|r| r.as_object().unwrap())
        .filter(|r| matches!(r["lenient_json"], Value::Null))
        .map(|r| r["name"].as_str().unwrap())
        .collect();
    assert_eq!(unwritable, ["non_text_key", "bytes"]);
}
