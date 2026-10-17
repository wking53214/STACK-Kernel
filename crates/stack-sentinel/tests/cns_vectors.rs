//! The Rust reproduction of `cns.gate.subject_digest`, held to CNS's own answer key.
//!
//! `fixtures/cns-digest-vectors.json` is a copy of CNS's `contracts/digest-vectors.json`: contents, and
//! the digest CNS gives each. They were chosen to catch what a near-miss gets wrong (a bool that is
//! not 1, a length counted in bytes, keys sorted by locale, `-0.0`, a float rendered the long way, an
//! integer past 64 bits). This test recomputes every one and requires an exact match.
//!
//! When CNS changes the file, copy it over this one and make this test pass again. CNS checks this
//! copy against its own (`python -m cns_composition.digest_vectors --stack ...`), so a stale copy is
//! reported there rather than discovered when a real ledger row fails to verify.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use stack_sentinel::pyjson::Value;
use stack_sentinel::subject_digest;

#[test]
fn every_cns_vector_is_reproduced() {
    let file = common::load("cns-digest-vectors.json");
    assert_eq!(file["schema"].as_str(), Some("cns-digest-vectors/1"));
    let Value::Array(vectors) = &file["vectors"] else {
        panic!("no vectors")
    };
    assert!(vectors.len() >= 20, "expected at least 20 vectors, found {}", vectors.len());
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
