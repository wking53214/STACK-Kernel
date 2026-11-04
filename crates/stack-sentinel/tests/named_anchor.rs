//! D-21: a named head anchor. The Python writer signs an optional `name`
//! with the other four fields (`twin_custody.py:633-639`); before Step 4
//! this crate ignored it, so every genuine named anchor failed its HMAC and
//! printed TRUNCATED.
//!
//! The anchors in `tests/fixtures/named_anchor/` were written by the real
//! Python code, `twin_custody.write_head_anchor`, run read-only by
//! `tests/fixtures/named_anchor/generate.py` (see its docstring) over the
//! head of `differential/base_post_receipts.json`, under the TEST FIXTURE
//! KEY, with a fixed `sealed_at`.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use stack_sentinel::anchor::{anchor_payload, anchor_payload_named};
use stack_sentinel::pyjson::{dumps, parse, ParseLimits, Separators, Value};
use stack_sentinel::{
    check_head_anchor_with, parse_head_anchor, read_anchor_file, GateOutcome, Reason, Verdict, VerifierConfig,
};

const POST: &str = "differential/base_post_receipts.json";
const ASCII: &str = "named_anchor/named_ascii.anchor";
const NON_ASCII: &str = "named_anchor/named_non_ascii.anchor";

fn export() -> Vec<u8> {
    common::export_bytes(&common::columns(POST), &common::base_rows(POST))
}

fn verify(anchor: &[u8]) -> stack_sentinel::Report {
    common::verifier(&[common::FIXTURE_KEY]).verify_export(&export(), Some(anchor)).unwrap()
}

fn with_name(rel: &str, name: Option<Value>) -> Vec<u8> {
    let mut o = common::load(rel);
    match name {
        Some(v) => o.insert("name".into(), v),
        None => o.remove("name"),
    };
    dumps(&Value::Object(o), Separators::Python).into_bytes()
}

#[test]
fn a_python_written_named_anchor_verifies() {
    for rel in [ASCII, NON_ASCII] {
        let r = verify(&common::read(rel));
        assert_eq!(r.verdict(), Verdict::Verified, "{rel}: {}", r.render());
        assert!(r.anchor.as_ref().unwrap().vouched, "{rel}");
    }
}

#[test]
fn the_cli_verifies_a_python_written_named_anchor() {
    let dir = std::env::temp_dir().join(format!("stack-sentinel-named-anchor-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("export.json"), export()).unwrap();
    std::fs::write(dir.join("keys.txt"), format!("{}\n", std::str::from_utf8(common::FIXTURE_KEY).unwrap())).unwrap();
    let fp = stack_sentinel::key_fingerprint(common::FIXTURE_KEY);
    let out = std::process::Command::new(env!("CARGO_BIN_EXE_stack-sentinel-verify"))
        .args(["--export", dir.join("export.json").to_str().unwrap()])
        .args(["--anchor", common::fixtures().join(NON_ASCII).to_str().unwrap()])
        .args(["--trusted-fingerprints", fp.as_str()])
        .args(["--key-file", dir.join("keys.txt").to_str().unwrap()])
        .output()
        .unwrap();
    let _ = std::fs::remove_dir_all(&dir);
    assert_eq!(out.status.code(), Some(0));
    assert_eq!(String::from_utf8(out.stdout).unwrap(), "VERIFIED\n");
}

/// Why the fix was needed: the four-field path signs no name, so it fails
/// the genuine named anchor, as every version before Step 4 did.
#[test]
fn the_four_field_path_still_fails_a_named_anchor() {
    let a = parse_head_anchor(&common::read(ASCII), 64 * 1024, ParseLimits::default()).unwrap();
    let rows = stack_sentinel::parse_export(&export(), &VerifierConfig::default()).unwrap();
    let f = check_head_anchor_with(&rows, &a, &common::verifier_keys(), &VerifierConfig::default()).unwrap();
    assert_eq!(f.reason, Reason::AnchorInvalid);
}

#[test]
fn the_name_is_covered_by_the_hmac() {
    let cases = [
        ("renamed", with_name(ASCII, Some(Value::Str("nightly-checkpoint 2026-11-05".into())))),
        ("name removed", with_name(ASCII, None)),
        ("name emptied", with_name(ASCII, Some(Value::Str(String::new())))),
        ("name nulled", with_name(ASCII, Some(Value::Null))),
        ("name added to an unnamed anchor", {
            let rows = common::base_rows(POST);
            let mut o = match parse(&common::anchor_bytes(&rows, rows.len(), common::FIXTURE_KEY), ParseLimits::default())
                .unwrap()
            {
                Value::Object(o) => o,
                _ => panic!(),
            };
            o.insert("name".into(), Value::Str("added".into()));
            dumps(&Value::Object(o), Separators::Python).into_bytes()
        }),
    ];
    for (what, anchor) in cases {
        let r = verify(&anchor);
        let f = r.finding.as_ref().unwrap_or_else(|| panic!("{what}: verified"));
        assert_eq!(f.reason, Reason::AnchorInvalid, "{what}: {}", r.render());
        assert_eq!(r.verdict(), Verdict::Truncated, "{what}");
        assert_eq!(r.gate_outcome(), GateOutcome::TerminalBreach, "{what}");
        assert!(!r.anchor.as_ref().unwrap().vouched, "{what}");
    }
}

#[test]
fn a_name_that_is_not_a_string_is_unreadable() {
    let r = verify(&with_name(ASCII, Some(Value::Array(vec![Value::Str("x".into())]))));
    assert_eq!(r.finding.unwrap().reason, Reason::AnchorUnreadable);
    let f = read_anchor_file(&with_name(ASCII, Some(Value::Bool(false))), 64 * 1024, ParseLimits::default()).unwrap();
    assert_eq!(f.name.as_deref(), Some(""), "a falsy name is kept as empty, which never verifies");
}

/// The unnamed path is byte-identical to before: same payload for no name
/// and for an empty one, and the exact bytes `head_anchor_payload` gives.
#[test]
fn the_unnamed_payload_is_unchanged() {
    let f = read_anchor_file(&common::read(ASCII), 64 * 1024, ParseLimits::default()).unwrap();
    let a = &f.anchor;
    let expected = format!(
        "sentinel_os.head_anchor.v1\0{{\"entries\":16,\"head\":\"{}\",\"key_fingerprint\":\"acdf8e81f938b3ca\",\
         \"sealed_at\":\"2026-11-04T00:00:00+00:00\"}}",
        a.head
    );
    assert_eq!(anchor_payload(a), expected.as_bytes());
    assert_eq!(anchor_payload_named(a, None), expected.as_bytes());
    assert_eq!(anchor_payload_named(a, Some("")), expected.as_bytes());
}

/// A non-ASCII name is signed in `canonical_json`'s ensure_ascii form; the
/// Python HMAC on the fixture is the proof, this pins the bytes.
#[test]
fn a_non_ascii_name_is_signed_escaped() {
    let f = read_anchor_file(&common::read(NON_ASCII), 64 * 1024, ParseLimits::default()).unwrap();
    let name = f.name.as_deref().unwrap();
    assert_eq!(name, "Kontrollpunkt \u{fc}ber Nacht \u{2713}");
    let payload = anchor_payload_named(&f.anchor, Some(name));
    let text = String::from_utf8(payload.clone()).unwrap();
    assert!(text.ends_with(",\"name\":\"Kontrollpunkt \\u00fcber Nacht \\u2713\",\"sealed_at\":\"2026-11-04T00:00:00+00:00\"}"), "{text}");
    assert_eq!(common::hmac_hex(common::FIXTURE_KEY, &payload), f.anchor.hmac);
}
