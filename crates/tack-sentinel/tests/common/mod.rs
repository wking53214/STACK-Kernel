#![allow(dead_code, clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::path::PathBuf;

use tack_sentinel::pyjson::{dumps, parse, Object, ParseLimits, Separators, Value};
use tack_sentinel::{KeySet, SecretKey, Verifier, VerifierConfig};

/// TEST FIXTURE KEY. sentinel_os's own suite labels it
/// "fixture-attestation-key-not-a-real-secret". Not a real secret.
pub const FIXTURE_KEY: &[u8] = b"fixture-attestation-key-not-a-real-secret";
/// TEST FIXTURE KEY, used as the key an auditor does not trust.
pub const OTHER_KEY: &[u8] = b"tack-sentinel-other-test-fixture-key-not-a-real-secret";

pub fn fixtures() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests").join("fixtures")
}

pub fn read(rel: &str) -> Vec<u8> {
    std::fs::read(fixtures().join(rel)).unwrap()
}

pub fn load(rel: &str) -> Object {
    match parse(&read(rel), ParseLimits::default()).unwrap() {
        Value::Object(o) => o,
        _ => panic!("{rel} is not an object"),
    }
}

pub fn base_rows(rel: &str) -> Vec<Object> {
    match load(rel).remove("rows").unwrap() {
        Value::Array(rows) => rows
            .into_iter()
            .map(|r| match r {
                Value::Object(o) => o,
                _ => panic!("row not an object"),
            })
            .collect(),
        _ => panic!("rows not a list"),
    }
}

pub fn columns(rel: &str) -> Value {
    load(rel).remove("columns").unwrap()
}

pub fn export_value(columns: &Value, rows: &[Object]) -> Value {
    let mut top = Object::new();
    top.insert("format".into(), Value::Str("sentinel_os.ledger_export.v1".into()));
    top.insert("columns".into(), columns.clone());
    top.insert(
        "rows".into(),
        Value::Array(rows.iter().cloned().map(Value::Object).collect()),
    );
    Value::Object(top)
}

pub fn export_bytes(columns: &Value, rows: &[Object]) -> Vec<u8> {
    dumps(&export_value(columns, rows), Separators::Python).into_bytes()
}

pub fn key(bytes: &[u8]) -> SecretKey {
    SecretKey::new(bytes.to_vec()).unwrap()
}

pub fn verifier(keys: &[&[u8]]) -> Verifier {
    let set = KeySet::new(None, keys.iter().map(|k| key(k)).collect(), Vec::new());
    Verifier::new(VerifierConfig::default(), set).unwrap()
}

/// The fixture key alone, as a trusted key set.
pub fn verifier_keys() -> KeySet {
    KeySet::new(None, vec![key(FIXTURE_KEY)], Vec::new())
}

/// A head anchor built the way `twin_custody.build_head_anchor` builds it.
pub fn anchor_bytes(rows: &[Object], entries: usize, signing_key: &[u8]) -> Vec<u8> {
    use tack_sentinel::anchor::{anchor_payload, HeadAnchor};
    use tack_sentinel::pyjson::PyInt;
    let head = if entries == 0 {
        "0".repeat(64)
    } else {
        rows[entries - 1]["current_hash"].as_str().unwrap().to_owned()
    };
    let mut a = HeadAnchor {
        head,
        entries: PyInt::from_i64(entries as i64),
        sealed_at: "2026-09-30T00:00:00+00:00".into(),
        key_fingerprint: tack_sentinel::key_fingerprint(signing_key),
        hmac: String::new(),
    };
    a.hmac = hmac_hex(signing_key, &anchor_payload(&a));
    let mut o = Object::new();
    o.insert("v".into(), Value::Int(PyInt::from_i64(1)));
    o.insert("head".into(), Value::Str(a.head));
    o.insert("entries".into(), Value::Int(a.entries));
    o.insert("sealed_at".into(), Value::Str(a.sealed_at));
    o.insert("key_fingerprint".into(), Value::Str(a.key_fingerprint));
    o.insert("hmac".into(), Value::Str(a.hmac));
    dumps(&Value::Object(o), Separators::Python).into_bytes()
}

pub fn hmac_hex(key: &[u8], msg: &[u8]) -> String {
    use hmac::{Hmac, Mac};
    let mut mac = <Hmac<sha2::Sha256> as Mac>::new_from_slice(key).unwrap();
    mac.update(msg);
    hex::encode(mac.finalize().into_bytes())
}

/// What an attacker holding the file does after an edit: recompute every
/// later hash so the unkeyed chain is self-consistent again.
pub fn rechain(rows: &mut [Object], start: usize) {
    for i in start..rows.len() {
        if i > 0 {
            let prev = rows[i - 1]["current_hash"].clone();
            rows[i].insert("previous_hash".into(), prev);
        }
        let h = tack_sentinel::recompute_current_hash(&rows[i]).unwrap();
        rows[i].insert("current_hash".into(), Value::Str(h));
    }
}
