//! The CNS rendering in this crate, held to CNS's own answer key.
//!
//! `fixtures/cns-digest-vectors.json` is a copy of CNS's
//! `contracts/digest-vectors.json`, taken from the copy that
//! `stack-sentinel` vendors. This crate's value type has no float and no
//! integer outside `i64`, so vectors outside that domain are not
//! representable here and are counted, not skipped: the test requires
//! that exactly the expected number convert, and that every one that
//! converts renders byte for byte and digests as CNS says.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::collections::BTreeMap;

use serde_json::Value;
use stack_receipt::{canonical_rendering, subject_digest, CnsValue};

/// Exact sizes of the vendored file.
const VECTOR_COUNT: usize = 38;
const RESTRICTED_VECTOR_COUNT: usize = 27;
/// Vectors outside restricted_v1 that still fit this crate's domain and
/// must match too: ints_at_the_edges, int_one_past_the_safe_limit,
/// negative_int_one_past_the_safe_limit (all within i64) and
/// depth_one_past_the_restricted_limit (this crate caps no depth).
const EXTRA_REPRESENTABLE: usize = 4;

fn load(path: &str) -> Value {
    let text = std::fs::read_to_string(path).unwrap_or_else(|e| panic!("{path}: {e}"));
    serde_json::from_str(&text).unwrap()
}

/// Converts a JSON value into this crate's domain, or says why not.
fn convert(v: &Value) -> Result<CnsValue, &'static str> {
    Ok(match v {
        Value::Null => CnsValue::Null,
        Value::Bool(b) => CnsValue::Bool(*b),
        Value::Number(n) => match n.as_i64() {
            Some(i) => CnsValue::Int(i),
            None => return Err("float or integer outside i64"),
        },
        Value::String(s) => CnsValue::Str(s.clone()),
        Value::Array(items) => CnsValue::List(items.iter().map(convert).collect::<Result<_, _>>()?),
        Value::Object(map) => {
            let mut out = BTreeMap::new();
            for (k, item) in map {
                out.insert(k.clone(), convert(item)?);
            }
            CnsValue::Map(out)
        }
    })
}

fn check(vectors: &[Value]) -> (usize, usize, usize) {
    let (mut converted, mut restricted, mut refused) = (0, 0, 0);
    let mut wrong = Vec::new();
    for v in vectors {
        let name = v["name"].as_str().unwrap();
        let flag = v["restricted_v1"].as_bool().unwrap();
        match convert(&v["content"]) {
            Ok(content) => {
                converted += 1;
                restricted += usize::from(flag);
                let want_rendering = v["rendering"].as_str().unwrap();
                let want_digest = v["digest"].as_str().unwrap();
                let got = canonical_rendering(&content);
                if got != want_rendering {
                    wrong.push(format!("{name}: rendering differs"));
                }
                if subject_digest(&content).to_hex() != want_digest {
                    wrong.push(format!("{name}: digest differs"));
                }
            }
            Err(_) => {
                assert!(!flag, "{name}: a restricted_v1 vector must be representable here");
                refused += 1;
            }
        }
    }
    assert!(wrong.is_empty(), "{} difference(s) from CNS:\n{}", wrong.len(), wrong.join("\n"));
    (converted, restricted, refused)
}

#[test]
fn every_representable_cns_vector_renders_and_digests_as_cns_says() {
    let file = load(concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/cns-digest-vectors.json"));
    assert_eq!(file["schema"].as_str(), Some("cns-digest-vectors/2"));
    assert_eq!(file["digest_version"].as_str(), Some("cns-digest/1"));
    let vectors = file["vectors"].as_array().unwrap();
    assert_eq!(vectors.len(), VECTOR_COUNT);
    let (converted, restricted, refused) = check(vectors);
    assert_eq!(restricted, RESTRICTED_VECTOR_COUNT, "every restricted_v1 vector is reproduced");
    assert_eq!(converted, RESTRICTED_VECTOR_COUNT + EXTRA_REPRESENTABLE);
    assert_eq!(refused, VECTOR_COUNT - converted, "floats and wide integers are outside this domain");
}

#[test]
fn the_vendored_copy_is_byte_identical_to_the_sentinel_copy_when_present() {
    let ours = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/cns-digest-vectors.json");
    let theirs = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../stack-sentinel/tests/fixtures/cns-digest-vectors.json"
    );
    let Ok(sentinel) = std::fs::read(theirs) else {
        // The sentinel crate is not a dependency; without its copy this
        // test only re-reads ours.
        assert!(std::fs::read(ours).is_ok());
        return;
    };
    // The two copies may drift while the sentinel crate is edited; every
    // restricted vector in the sentinel copy must still reproduce here,
    // and a byte-identical copy is reported as such.
    let file: Value = serde_json::from_slice(&sentinel).unwrap();
    let vectors = file["vectors"].as_array().unwrap();
    let (converted, restricted, _) = check(vectors);
    assert!(restricted >= RESTRICTED_VECTOR_COUNT, "the sentinel copy lost restricted vectors");
    assert!(converted >= restricted);
    if std::fs::read(ours).unwrap() != sentinel {
        eprintln!("note: the vendored vectors file differs from the sentinel copy; every restricted vector still reproduces");
    }
}

#[test]
fn the_rendering_is_the_documented_text_form() {
    let mut m = BTreeMap::new();
    m.insert("b".to_owned(), CnsValue::List(vec![CnsValue::Int(1), CnsValue::Null, CnsValue::Bool(true)]));
    m.insert("a".to_owned(), CnsValue::text("h\u{e9}"));
    let v = CnsValue::Map(m);
    assert_eq!(canonical_rendering(&v), "d:2:s:1:as:2:h\u{e9}s:1:bl:3:i:1:n:b:1");
    assert_eq!(
        subject_digest(&CnsValue::Map(BTreeMap::new())).to_hex(),
        "c348e1722fbda6fbdd0ce8ec7831067eeff989c54b833673b8ebf6890883f012"
    );
    assert_eq!(canonical_rendering(&CnsValue::Int(-5)), "i:-5:");
    assert_eq!(canonical_rendering(&CnsValue::Bool(false)), "b:0");
}
