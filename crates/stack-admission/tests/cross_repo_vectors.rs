//! R-9: one corpus, three implementations of the CNS subject digest, and
//! all three must agree on every entry.
//!
//! The corpus is the vendored CNS digest vectors v2 (`cns-digest-vectors`)
//! and the vendored differential corpus (`digest-differential`), both
//! copied from CNS's `contracts/` and kept under `stack-sentinel`. The
//! fixtures are read, never edited. The three implementations:
//!
//! * (a) `stack_sentinel::subject_digest`, the FULL normative domain: every
//!   entry has a digest and it must equal the file's.
//! * (b) `stack_trident::cns_digest::subject_digest`, the RESTRICTED domain
//!   (`restricted_v1`): entries flagged restricted must equal the file's
//!   digest; every other entry must be refused with a typed error, never a
//!   different digest.
//! * (c) `stack_admission::binding::subject_digest`, the admission
//!   binding step's recomputation: it must behave exactly as (b), entry by
//!   entry.
//!
//! The Python reference itself is not run here: the file's digests ARE its
//! answers (CNS regenerates and drift-checks them; see
//! `docs/cns-digest-contract.md`). `stack-sentinel` is a dev-dependency of
//! this crate for this test only.
//!
//! Counts are read from the files and cross-checked against the pinned
//! sizes, so a fixture that loses entries fails here instead of being
//! checked less.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::path::PathBuf;

use serde_json::Value as Json;
use stack_sentinel::pyjson::{parse, ParseLimits, Value as Py};
use stack_trident::canonical::{CanonicalError, Limits};
use stack_trident::TridentConfig;

const PINNED_VECTORS: usize = 38;
const PINNED_RESTRICTED_VECTORS: usize = 27;
const PINNED_REFUSALS: usize = 7;
const PINNED_DIFFERENTIAL: usize = 400;
const PINNED_RESTRICTED_DIFFERENTIAL: usize = 283;

fn sentinel_fixture(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../stack-sentinel/tests/fixtures").join(name)
}

fn read(name: &str) -> Vec<u8> {
    std::fs::read(sentinel_fixture(name)).unwrap()
}

/// What an implementation said about one entry.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Said {
    Digest(String),
    Refused,
}

fn typed(e: CanonicalError) -> bool {
    matches!(e, CanonicalError::NonInteger | CanonicalError::IntegerOutOfRange | CanonicalError::TooDeep)
}

fn trident_says(content: &Json, limits: &Limits) -> Said {
    match stack_trident::cns_digest::subject_digest(content, limits) {
        Ok(d) => Said::Digest(d),
        Err(e) => {
            assert!(typed(e), "the Trident refused with an untyped error: {e}");
            Said::Refused
        }
    }
}

fn admission_says(content: &Json, limits: &Limits) -> Said {
    match stack_admission::binding::subject_digest(content, limits) {
        Ok(d) => Said::Digest(d.to_hex()),
        Err(e) => {
            assert!(typed(e), "the admission binding refused with an untyped error: {e}");
            Said::Refused
        }
    }
}

/// Container depth as the vectors file counts it.
fn depth(v: &Json) -> usize {
    match v {
        Json::Array(a) => 1 + a.iter().map(depth).max().unwrap_or(0),
        Json::Object(m) => 1 + m.values().map(depth).max().unwrap_or(0),
        _ => 0,
    }
}

#[derive(Debug, Default, PartialEq, Eq)]
struct Tally {
    total: usize,
    restricted: usize,
    /// Restricted entries all three reproduced exactly.
    agreed_digest: usize,
    /// Entries outside restricted_v1 that the Sentinel digested (every one)
    /// and the Trident and admission both refused.
    full_domain_only: usize,
    /// Entries outside restricted_v1 that both kernel paths digested
    /// identically to the file (depth 32: the direct call allows it, the
    /// envelope path does not).
    boundary_depth: usize,
}

fn run(entries_py: &[Py], entries_js: &[Json]) -> Tally {
    assert_eq!(entries_py.len(), entries_js.len());
    let limits = TridentConfig::production("kernel-a").limits();
    let mut t = Tally::default();
    for (py, js) in entries_py.iter().zip(entries_js) {
        let name = js.get("name").and_then(Json::as_str).map_or_else(|| format!("index {}", js["index"]), str::to_owned);
        let want = js["digest"].as_str().unwrap().to_owned();
        let restricted = js["restricted_v1"].as_bool().unwrap();
        t.total += 1;

        // (a) The Sentinel: full domain, every entry.
        let py_content = &py.as_object().unwrap()["content"];
        let sentinel = stack_sentinel::subject_digest(py_content);
        assert_eq!(sentinel.as_deref(), Ok(want.as_str()), "(a) sentinel disagrees with the file on {name}");

        // (b) and (c): the restricted domain.
        let content = &js["content"];
        let trident = trident_says(content, &limits);
        let admission = admission_says(content, &limits);
        assert_eq!(trident, admission, "(b) and (c) disagree on {name}");

        if restricted {
            t.restricted += 1;
            assert_eq!(trident, Said::Digest(want.clone()), "restricted entry {name} not reproduced by (b) and (c)");
            t.agreed_digest += 1;
        } else {
            match trident {
                Said::Refused => t.full_domain_only += 1,
                Said::Digest(d) => {
                    assert_eq!(d, want, "{name}: outside restricted_v1 the kernel paths must never compute a different digest");
                    assert_eq!(depth(content), 32, "{name}: only the depth-32 boundary may be digested outside restricted_v1");
                    t.boundary_depth += 1;
                }
            }
        }
    }
    t
}

#[test]
fn the_vectors_v2_are_accepted_identically_by_sentinel_trident_and_admission() {
    let bytes = read("cns-digest-vectors.json");
    let py = parse(&bytes, ParseLimits::default()).unwrap();
    let js: Json = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(js["schema"].as_str(), Some("cns-digest-vectors/2"));
    let Py::Object(py_file) = py else { panic!("vectors file is not an object") };
    let Py::Array(py_vectors) = &py_file["vectors"] else { panic!("no vectors") };
    let js_vectors = js["vectors"].as_array().unwrap();

    // Counts read from the file.
    let in_file = js_vectors.len();
    let restricted_in_file = js_vectors.iter().filter(|v| v["restricted_v1"].as_bool().unwrap()).count();
    assert_eq!((in_file, restricted_in_file), (PINNED_VECTORS, PINNED_RESTRICTED_VECTORS));

    let t = run(py_vectors, js_vectors);
    println!("vectors: {t:?}");
    assert_eq!((t.full_domain_only, t.boundary_depth), (10, 1), "{t:?}");
    assert_eq!(t.total, in_file);
    assert_eq!(t.restricted, restricted_in_file);
    assert_eq!(t.agreed_digest, restricted_in_file, "every restricted vector is reproduced by all three");
    assert_eq!(
        t.full_domain_only + t.boundary_depth,
        in_file - restricted_in_file,
        "every other vector is refused by (b) and (c) or sits on the depth boundary"
    );
}

#[test]
fn the_differential_corpus_is_accepted_identically_by_sentinel_trident_and_admission() {
    let bytes = read("digest-differential.json");
    let py = parse(&bytes, ParseLimits::default()).unwrap();
    let js: Json = serde_json::from_slice(&bytes).unwrap();
    let Py::Object(py_file) = py else { panic!("differential file is not an object") };
    let Py::Array(py_cases) = &py_file["cases"] else { panic!("no cases") };
    let js_cases = js["cases"].as_array().unwrap();

    let in_file = js_cases.len();
    assert_eq!(js["count"].as_u64(), Some(u64::try_from(in_file).unwrap()), "the file's own count");
    let restricted_in_file = js_cases.iter().filter(|v| v["restricted_v1"].as_bool().unwrap()).count();
    assert_eq!((in_file, restricted_in_file), (PINNED_DIFFERENTIAL, PINNED_RESTRICTED_DIFFERENTIAL));

    let t = run(py_cases, js_cases);
    println!("differential: {t:?}");
    assert_eq!((t.full_domain_only, t.boundary_depth), (111, 6), "{t:?}");
    assert_eq!(t.total, in_file);
    assert_eq!(t.agreed_digest, restricted_in_file);
    assert_eq!(t.full_domain_only + t.boundary_depth, in_file - restricted_in_file);
}

#[test]
fn the_named_refusals_are_refused_by_all_three_before_a_digest_exists() {
    let bytes = read("cns-digest-vectors.json");
    let js: Json = serde_json::from_slice(&bytes).unwrap();
    let refusals = js["refusals"].as_array().unwrap();
    assert_eq!(refusals.len(), PINNED_REFUSALS);
    let (mut refused_everywhere, mut unrepresentable) = (0, 0);
    for r in refusals {
        let name = r["name"].as_str().unwrap();
        match r["lenient_json"].as_str() {
            // JSON cannot write this content (a non-text key, raw bytes): it
            // cannot reach any of the three.
            None => {
                assert!(r["lenient_json"].is_null(), "{name}");
                unrepresentable += 1;
            }
            Some(text) => {
                // (a) The Sentinel's reader keeps NaN and the infinities and its digest refuses them,
                // or its reader refuses a lone surrogate.
                if let Ok(v) = parse(text.as_bytes(), ParseLimits::default()) {
                    assert!(stack_sentinel::subject_digest(&v).is_err(), "(a) digested {name}");
                }
                // (b) and (c) only ever receive strict JSON: the text does not parse.
                assert!(serde_json::from_str::<Json>(text).is_err(), "{name} parsed as strict JSON");
                refused_everywhere += 1;
            }
        }
    }
    assert_eq!((refused_everywhere, unrepresentable), (PINNED_REFUSALS - 2, 2));
}

#[test]
fn the_two_vendored_copies_of_the_vectors_are_byte_identical() {
    let sentinel = read("cns-digest-vectors.json");
    let receipt =
        std::fs::read(PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../stack-receipt/tests/fixtures/cns-digest-vectors.json")).unwrap();
    assert_eq!(sentinel, receipt, "the Sentinel and Receipt copies of the CNS vectors drifted");
}
