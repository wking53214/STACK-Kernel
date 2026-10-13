//! Differential tests against the Python implementation.
//!
//! `tests/fixtures/differential/generate.py` built mutated ledger exports
//! (edit a field, delete a row, reorder rows, flip a hash character, copy a
//! subject_digest, forge a seed, strip a signature, alter the anchor, and
//! 100 random mutations), ran `sentinel_os/tools/verify_receipts.py` on each,
//! and recorded what it printed. Each case is stored as a diff against a
//! base export, so this test rebuilds exactly the export Python checked
//! (asserted by the SHA-256 of its Python serialization) and requires the
//! Rust verdict, failing row and anchor note to match.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use std::collections::BTreeMap;

use stack_sentinel::canonical::sha256_hex;
use stack_sentinel::pyjson::{dumps, parse, Object, ParseLimits, Separators, Value};
use stack_sentinel::{parse_key_file, subject_digest, KeySet, Verifier, VerifierConfig, VerifyError};

fn obj(v: &Value) -> &Object {
    v.as_object().unwrap()
}

#[test]
fn every_python_verdict_is_reproduced() {
    let manifest = common::load("differential/manifest.json");
    let bases_spec = obj(&manifest["bases"]);
    // The generator writes every export with twin_custody.SHIPPED_COLUMNS
    // as its columns list, which is the list the post-receipts base carries.
    let shipped = common::columns("differential/base_post_receipts.json");
    let mut bases: BTreeMap<String, Vec<Object>> = BTreeMap::new();
    for (name, path) in bases_spec {
        let rel = format!("differential/{}", path.as_str().unwrap());
        bases.insert(name.clone(), common::base_rows(&rel));
    }
    let Value::Array(cases) = &manifest["cases"] else {
        panic!("no cases")
    };
    assert!(cases.len() >= 200, "expected at least 200 cases, found {}", cases.len());
    let mut mismatches = Vec::new();
    let mut tally: BTreeMap<String, usize> = BTreeMap::new();
    for c in cases {
        let c = obj(c);
        let name = c["name"].as_str().unwrap();
        let base = &bases[c["base"].as_str().unwrap()];
        let Value::Array(entries) = &c["rows"] else { panic!() };
        let mut rows = Vec::new();
        for e in entries {
            let e = obj(e);
            let origin = e["base"].to_owned();
            let Value::Int(i) = origin else { panic!() };
            let mut row = base[i.to_i64().unwrap() as usize].clone();
            if let Some(Value::Object(sets)) = e.get("set") {
                for (k, v) in sets {
                    row.insert(k.clone(), v.clone());
                }
            }
            if let Some(Value::Array(dels)) = e.get("del") {
                for d in dels {
                    row.remove(d.as_str().unwrap());
                }
            }
            rows.push(row);
        }
        let export = common::export_value(&shipped, &rows);
        let text = dumps(&export, Separators::Python);
        assert_eq!(
            sha256_hex(text.as_bytes()),
            c["export_sha256"].as_str().unwrap(),
            "{name}: rebuilt export differs from the one Python checked"
        );

        let held = parse_key_file(c["key_file"].as_str().unwrap().as_bytes(), 1 << 20, 64).unwrap();
        let Value::Array(fps) = &c["fingerprints"] else { panic!() };
        let fps: Vec<&str> = fps.iter().map(|f| f.as_str().unwrap()).collect();
        let keys = KeySet::from_trusted_fingerprints(held, &fps);
        let anchor = c["anchor"].as_str().map(|s| s.as_bytes().to_vec());

        let py = obj(&c["python"]);
        let py_exit = match &py["exit"] {
            Value::Int(i) => i.to_i64().unwrap(),
            _ => panic!(),
        };
        let py_verdict = py["verdict"].as_str().map(str::to_owned);
        let py_row = py["row"].as_str().map(str::to_owned);
        let py_also = py["also"] == Value::Bool(true);

        // The Python-compatible config: the default refuses a zero-entry
        // anchor (anchor_makes_no_claim), which the Python prints VERIFIED.
        let (rs_exit, rs_verdict, rs_row, rs_also) = match Verifier::new(VerifierConfig::python_compatible(), keys) {
            Err(VerifyError::NoTrustedKeyMaterial) => (2, None, None, false),
            Err(e) => panic!("{name}: unexpected {e}"),
            Ok(v) => {
                let report = v.verify_export(text.as_bytes(), anchor.as_deref()).unwrap();
                let row = report.finding.as_ref().map(|f| f.row_id.map_or("-".to_owned(), |i| i.to_string()));
                (
                    i64::from(report.finding.is_some()),
                    Some(report.verdict().as_str().to_owned()),
                    row,
                    report.also.is_some(),
                )
            }
        };
        *tally.entry(py_verdict.clone().unwrap_or_else(|| format!("exit {py_exit}"))).or_default() += 1;
        if (py_exit, &py_verdict, &py_row, py_also) != (rs_exit, &rs_verdict, &rs_row, rs_also) {
            mismatches.push(format!(
                "{name}: python exit={py_exit} {py_verdict:?} row={py_row:?} also={py_also}; \
                 rust exit={rs_exit} {rs_verdict:?} row={rs_row:?} also={rs_also}"
            ));
        }
    }
    assert!(mismatches.is_empty(), "{} mismatches:\n{}", mismatches.len(), mismatches.join("\n"));
    // Every one of the six verdicts, and the refusal, is exercised.
    for word in ["VERIFIED", "TAMPERED", "TRANSPLANTED", "SEED_FORGED", "TRUNCATED", "UNATTESTED", "exit 2"] {
        assert!(tally.contains_key(word), "no case produced {word}: {tally:?}");
    }
}

#[test]
fn serializer_and_cns_digest_match_python_byte_for_byte() {
    let corpus = common::load("differential/corpus.json");
    let Value::Array(entries) = &corpus["entries"] else { panic!() };
    assert!(entries.len() >= 400);
    for e in entries {
        let e = obj(e);
        let text = e["text"].as_str().unwrap();
        let v = parse(text.as_bytes(), ParseLimits::default()).unwrap();
        assert_eq!(dumps(&v, Separators::Python), e["ledger"].as_str().unwrap(), "ledger form of {text:?}");
        assert_eq!(dumps(&v, Separators::Compact), e["compact"].as_str().unwrap(), "compact form of {text:?}");
        assert_eq!(
            sha256_hex(dumps(&v, Separators::Python).as_bytes()),
            e["ledger_sha256"].as_str().unwrap()
        );
        let cns = obj(&e["cns"]);
        match (subject_digest(&v), cns.get("digest")) {
            (Ok(d), Some(want)) => assert_eq!(d, want.as_str().unwrap(), "cns digest of {text:?}"),
            (Err(_), None) => assert_eq!(cns["error"].as_str(), Some("TypeError")),
            (got, want) => panic!("cns disagreement on {text:?}: rust {got:?}, python {want:?}"),
        }
    }
}

#[test]
fn where_python_crashes_rust_reports_tampered() {
    // The one random mutation the generator found where the Python tool
    // printed no verdict: a governance_decision whose data column is a
    // string. twin_custody.canonical_form calls .get on it and raises an
    // AttributeError that nothing catches. This crate reports TAMPERED.
    let rel = "differential/base_post_receipts.json";
    let columns = common::columns(rel);
    let mut rows = common::base_rows(rel);
    rows[2].insert("data".into(), Value::Str("x".into()));
    let anchor = common::anchor_bytes(&rows, rows.len(), common::FIXTURE_KEY);
    let report = common::verifier(&[common::FIXTURE_KEY])
        .verify_export(&common::export_bytes(&columns, &rows), Some(&anchor))
        .unwrap();
    assert_eq!(report.verdict().as_str(), "TAMPERED");
    assert_eq!(report.finding.unwrap().reason, stack_sentinel::Reason::RecomputeFailed);
}
