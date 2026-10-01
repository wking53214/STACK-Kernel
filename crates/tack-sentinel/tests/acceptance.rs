//! Named attacks, each with its verdict, reason, CNS outcome and resolution;
//! the Python semantics this crate keeps on purpose; the caps; and the CLI.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use tack_sentinel::attest::{verify_signature, AttestationStatus};
use tack_sentinel::canonical::{canonical_form, content_prehash};
use tack_sentinel::pyjson::{Object, Value};
use tack_sentinel::verify::GENESIS;
use tack_sentinel::{
    deep_verify_row, parse_export, verify_rows, Finding, GateOutcome, KeySet, LedgerRow, Reason, Report, Resolution,
    Verdict, Verifier, VerifierConfig, VerifyError,
};

const PRE: &str = "ledger_export_pre_receipts.json";
const POST: &str = "differential/base_post_receipts.json";

fn base(rel: &str) -> (Value, Vec<Object>) {
    (common::columns(rel), common::base_rows(rel))
}

fn check(rows: &[Object], anchor_rows: &[Object], keys: &[&[u8]]) -> Report {
    let cols = common::columns(POST);
    let anchor = common::anchor_bytes(anchor_rows, anchor_rows.len(), common::FIXTURE_KEY);
    common::verifier(keys)
        .verify_export(&common::export_bytes(&cols, rows), Some(&anchor))
        .unwrap()
}

/// Every run of hex digits of length 16 or more in a detail is either a
/// 16-hex key fingerprint (the Python wire format) or a full 64-hex hash.
fn assert_no_truncated_hash(f: &Finding) {
    let mut run = 0usize;
    for c in f.detail.chars().chain(std::iter::once(' ')) {
        if c.is_ascii_hexdigit() {
            run += 1;
        } else {
            assert!(run <= 16 || run == 64, "hex run of {run} in {:?}", f.detail);
            run = 0;
        }
    }
}

fn first(report: &Report) -> &Finding {
    let f = report.finding.as_ref().unwrap();
    assert_no_truncated_hash(f);
    if let Some(a) = &report.also {
        assert_no_truncated_hash(a);
    }
    f
}

fn idx(rows: &[Object], kind: &str, nth: usize) -> usize {
    rows.iter()
        .enumerate()
        .filter(|(_, r)| r["record_kind"].as_str() == Some(kind))
        .nth(nth)
        .unwrap()
        .0
}

#[test]
fn acceptance_f_the_pre_receipts_fixture_verifies() {
    let (cols, rows) = base(PRE);
    let anchor = common::anchor_bytes(&rows, rows.len(), common::FIXTURE_KEY);
    let report = common::verifier(&[common::FIXTURE_KEY])
        .verify_export(&common::export_bytes(&cols, &rows), Some(&anchor))
        .unwrap();
    assert_eq!(report.verdict(), Verdict::Verified);
    assert_eq!(report.gate_outcome(), GateOutcome::Pass);
    assert_eq!(report.resolution(), None);
    assert_eq!(report.render(), "VERIFIED");
    assert_eq!(report.rows_checked, 11);
    assert_eq!(report.export_sha256.len(), 64);
}

#[test]
fn the_fixture_abv2_signature_checks_under_its_key_and_only_its_key() {
    let (_, rows) = base(PRE);
    let signed = &rows[10];
    let prehash = content_prehash(&canonical_form(signed).unwrap());
    let good = KeySet::new(None, vec![common::key(common::FIXTURE_KEY)], vec![]);
    let other = KeySet::new(None, vec![common::key(common::OTHER_KEY)], vec![]);
    assert_eq!(verify_signature(signed, &good, &prehash).status, AttestationStatus::Ok);
    assert_eq!(verify_signature(signed, &other, &prehash).status, AttestationStatus::UnknownKey);
}

#[test]
fn acceptance_a_editing_input_data_is_tampered_and_quarantined() {
    let (_, base_rows) = base(POST);
    let mut rows = base_rows.clone();
    let d = idx(&rows, "governance_decision", 1);
    let Value::Object(mut input) = rows[d]["input_data"].clone() else { panic!() };
    input.insert("score".into(), Value::Str("0.99".into()));
    rows[d].insert("input_data".into(), Value::Object(input));
    let report = check(&rows, &base_rows, &[common::FIXTURE_KEY]);
    let f = first(&report);
    assert_eq!((f.verdict(), f.reason), (Verdict::Tampered, Reason::HashMismatch));
    assert_eq!(f.row_id, Some(rows[d]["id"].as_int()));
    assert_eq!(report.gate_outcome(), GateOutcome::TerminalBreach);
    assert_eq!(report.resolution(), Some(Resolution::Quarantine));
    assert!(report.render().starts_with(&format!("TAMPERED row={} hash mismatch", f.row_id.unwrap())));
}

#[test]
fn acceptance_b_a_copied_subject_digest_is_transplanted_even_after_rechaining() {
    let (_, base_rows) = base(POST);
    let mut rows = base_rows.clone();
    let (a, b) = (idx(&rows, "governance_decision", 0), idx(&rows, "governance_decision", 1));
    let stolen = rows[a]["subject_digest"].clone();
    rows[b].insert("subject_digest".into(), stolen);
    common::rechain(&mut rows, b);
    let report = check(&rows, &base_rows, &[common::FIXTURE_KEY]);
    let f = first(&report);
    assert_eq!((f.verdict(), f.reason), (Verdict::Transplanted, Reason::SubjectDigestMismatch));
    assert_eq!(report.also.as_ref().unwrap().reason, Reason::HeadMismatch);
    assert!(report.render().contains("\n  also: anchor mismatch as well: "));
    assert_eq!(report.gate_outcome(), GateOutcome::TerminalBreach);
}

#[test]
fn content_cns_cannot_encode_is_transplanted() {
    let (_, base_rows) = base(POST);
    let mut rows = base_rows.clone();
    let d = idx(&rows, "governance_decision", 1);
    let Value::Object(mut input) = rows[d]["input_data"].clone() else { panic!() };
    input.insert("score".into(), Value::Float(f64::NAN));
    rows[d].insert("input_data".into(), Value::Object(input));
    common::rechain(&mut rows, d);
    let f = first(&check(&rows, &base_rows, &[common::FIXTURE_KEY])).clone();
    assert_eq!((f.verdict(), f.reason), (Verdict::Transplanted, Reason::SubjectNotEncodable));
}

#[test]
fn acceptance_c_a_seed_the_server_would_not_derive_is_seed_forged() {
    let (_, base_rows) = base(POST);
    let mut rows = base_rows.clone();
    let d = idx(&rows, "governance_decision", 0);
    rows[d].insert("shuffle_seed".into(), Value::Str("0".repeat(64)));
    common::rechain(&mut rows, d);
    let report = check(&rows, &base_rows, &[common::FIXTURE_KEY]);
    let f = first(&report);
    // The row is abv3-signed, so the forged seed also breaks its signature;
    // the seed check runs first so the verdict names the attack.
    assert_eq!((f.verdict(), f.reason), (Verdict::SeedForged, Reason::SeedNotDerived));
    assert_eq!(report.gate_outcome(), GateOutcome::TerminalBreach);
}

#[test]
fn acceptance_d_a_signature_nulled_after_the_marker_is_unattested() {
    let (_, base_rows) = base(POST);
    let mut rows = base_rows.clone();
    let d = idx(&rows, "governance_decision", 0);
    rows[d].insert("authorized_by_sig".into(), Value::Null);
    common::rechain(&mut rows, d);
    let report = check(&rows, &base_rows, &[common::FIXTURE_KEY]);
    let f = first(&report);
    assert_eq!((f.verdict(), f.reason), (Verdict::Unattested, Reason::UnsignedAfterPolicy));
    assert!(!f.detail.contains("harness:production"), "the claim itself must not be echoed");
    assert_eq!(report.gate_outcome(), GateOutcome::TerminalBreach);
}

#[test]
fn before_the_marker_an_unsigned_claim_is_not_judged() {
    // The pre-receipts fixture carries unsigned accountable claims and no
    // marker, and verifies.
    let (_, rows) = base(PRE);
    let ledger: Vec<LedgerRow> = rows
        .iter()
        .map(|r| LedgerRow {
            id: r["id"].as_int(),
            columns: r.clone(),
        })
        .collect();
    assert!(rows.iter().any(|r| r["authorized_by"].is_truthy() && !r["authorized_by_sig"].is_truthy()));
    assert_eq!(verify_rows(&ledger, &common::verifier_keys()).finding, None);
}

#[test]
fn acceptance_e_deleting_the_last_three_rows_is_truncated() {
    let (_, base_rows) = base(POST);
    let rows = base_rows[..base_rows.len() - 3].to_vec();
    let report = check(&rows, &base_rows, &[common::FIXTURE_KEY]);
    let f = first(&report);
    assert_eq!((f.verdict(), f.reason), (Verdict::Truncated, Reason::TailMissing));
    assert_eq!(f.row_id, Some(rows.last().unwrap()["id"].as_int()));
    assert!(f.detail.contains("missing from the tail"));
}

#[test]
fn a_key_the_auditor_does_not_trust_is_unattested_and_retryable() {
    let (_, base_rows) = base(POST);
    let report = check(&base_rows, &base_rows, &[common::OTHER_KEY]);
    let f = first(&report);
    assert_eq!((f.verdict(), f.reason), (Verdict::Unattested, Reason::SignatureUnknownKey));
    assert_eq!(report.also.as_ref().unwrap().reason, Reason::AnchorUnknownKey);
    assert_eq!(report.gate_outcome(), GateOutcome::Retry);
    assert_eq!(report.resolution(), Some(Resolution::Reject));
}

#[test]
fn a_missing_or_unreadable_anchor_is_truncated_before_any_row_is_read() {
    let (cols, rows) = base(POST);
    let v = common::verifier(&[common::FIXTURE_KEY]);
    let export = common::export_bytes(&cols, &rows);
    let missing = v.verify_export(&export, None).unwrap();
    assert_eq!(first(&missing).reason, Reason::AnchorMissing);
    assert_eq!(missing.rows_checked, 0);
    assert_eq!(missing.render(), "TRUNCATED row=- no head anchor was supplied");
    let garbage = v.verify_export(&export, Some(b"{\"v\": 1}")).unwrap();
    assert_eq!(first(&garbage).reason, Reason::AnchorUnreadable);
    assert_eq!(garbage.gate_outcome(), GateOutcome::Retry);
}

#[test]
fn an_altered_anchor_is_a_terminal_truncation() {
    let (cols, rows) = base(POST);
    let anchor = String::from_utf8(common::anchor_bytes(&rows, rows.len(), common::FIXTURE_KEY)).unwrap();
    let altered = anchor.replace("\"entries\": 16", "\"entries\": 15");
    assert_ne!(anchor, altered);
    let report = common::verifier(&[common::FIXTURE_KEY])
        .verify_export(&common::export_bytes(&cols, &rows), Some(altered.as_bytes()))
        .unwrap();
    assert_eq!(first(&report).reason, Reason::AnchorInvalid);
    assert_eq!(report.gate_outcome(), GateOutcome::TerminalBreach);
}

#[test]
fn retired_keys_behave_as_the_python_does() {
    // Python: a signature valid under a retired key passes deep_verify_row,
    // a seed that re-derives only under a retired key is SEED_FORGED, and an
    // anchor under a retired key is accepted.
    // A key set must now hold a trusted key, and accepting retired keys is
    // no longer the default, so this runs the Python-compatible config with
    // an unrelated trusted key beside the retired fixture key.
    let (cols, rows) = base(POST);
    let keys = KeySet::new(None, vec![common::key(common::OTHER_KEY)], vec![common::key(common::FIXTURE_KEY)]);
    let v = Verifier::new(VerifierConfig::python_compatible(), keys).unwrap();
    let anchor = common::anchor_bytes(&rows, rows.len(), common::FIXTURE_KEY);
    let report = v.verify_export(&common::export_bytes(&cols, &rows), Some(&anchor)).unwrap();
    let f = first(&report);
    assert_eq!((f.verdict(), f.reason), (Verdict::SeedForged, Reason::SeedRetiredKey));
    assert_eq!(f.row_id, Some(rows[idx(&rows, "governance_decision", 2)]["id"].as_int()));
    assert_eq!(report.also, None, "an anchor under a retired key is accepted");
}

#[test]
fn with_no_key_seeds_and_signatures_are_unverifiable() {
    let (_, rows) = base(POST);
    let empty = KeySet::default();
    let seeded = &rows[idx(&rows, "governance_decision", 2)];
    let row = LedgerRow {
        id: seeded["id"].as_int(),
        columns: seeded.clone(),
    };
    assert_eq!(deep_verify_row(&row, &empty).unwrap_err().0, Reason::SeedUnverifiable);
    let signed = &rows[idx(&rows, "governance_decision", 0)];
    let row = LedgerRow {
        id: signed["id"].as_int(),
        columns: signed.clone(),
    };
    assert_eq!(deep_verify_row(&row, &empty).unwrap_err().0, Reason::SignatureUnverifiable);
    assert_eq!(Reason::SeedUnverifiable.gate_outcome(), GateOutcome::Retry);
}

#[test]
fn the_first_row_must_link_to_genesis() {
    let (_, base_rows) = base(POST);
    let mut rows = base_rows.clone();
    rows[0].insert("previous_hash".into(), Value::Str("0".repeat(64)));
    common::rechain(&mut rows, 0);
    let f = first(&check(&rows, &base_rows, &[common::FIXTURE_KEY])).clone();
    assert_eq!((f.reason, f.row_id), (Reason::ChainBroken, Some(1)));
    assert!(f.detail.contains(GENESIS));
}

#[test]
fn a_non_hash_stored_value_is_described_not_echoed() {
    let (_, base_rows) = base(POST);
    let mut rows = base_rows.clone();
    rows[4].insert("current_hash".into(), Value::Str("<script>alert(1)</script>".into()));
    let f = first(&check(&rows, &base_rows, &[common::FIXTURE_KEY])).clone();
    assert_eq!(f.reason, Reason::HashMismatch);
    assert!(!f.detail.contains("script"));
    assert!(f.detail.contains("a str of 25 bytes with sha256 "));
}

#[test]
fn caps_refuse_over_budget_input_without_a_verdict() {
    let (cols, rows) = base(POST);
    let export = common::export_bytes(&cols, &rows);
    let tight = VerifierConfig {
        max_rows: 3,
        max_anchor_bytes: 10,
        ..VerifierConfig::default()
    };
    let v = Verifier::new(tight, common::verifier_keys()).unwrap();
    let err = v.verify_export(&export, None).unwrap_err();
    assert_eq!(err, VerifyError::TooManyRows { len: 16, max: 3 });
    assert_eq!((err.gate_outcome(), err.resolution()), (GateOutcome::Retry, Resolution::Reject));

    let roomy = VerifierConfig {
        max_anchor_bytes: 10,
        ..VerifierConfig::default()
    };
    let v = Verifier::new(roomy, common::verifier_keys()).unwrap();
    let anchor = common::anchor_bytes(&rows, rows.len(), common::FIXTURE_KEY);
    assert_eq!(first(&v.verify_export(&export, Some(&anchor)).unwrap()).reason, Reason::AnchorUnreadable);

    let deep = format!(
        "{{\"format\": \"sentinel_os.ledger_export.v1\", \"rows\": [], \"x\": {}{}}}",
        "[".repeat(300),
        "]".repeat(300)
    );
    assert!(matches!(
        v.verify_export(deep.as_bytes(), None),
        Err(VerifyError::ExportNotJson(tack_sentinel::pyjson::JsonError::TooDeep(256)))
    ));
}

#[test]
fn malformed_exports_are_refused_not_judged() {
    let cfg = VerifierConfig::default();
    let fmt = "\"format\": \"sentinel_os.ledger_export.v1\"";
    for (text, want) in [
        (format!("{{{fmt}, \"rows\": {{}}}}"), "rows_missing"),
        (format!("{{{fmt}, \"rows\": [1]}}"), "row_not_an_object"),
        (format!("{{{fmt}, \"rows\": [{{\"id\": \"1\"}}]}}"), "row_id_invalid"),
        (format!("{{{fmt}, \"rows\": [{{\"id\": 99999999999999999999}}]}}"), "row_id_invalid"),
        (format!("{{{fmt}, \"rows\": [], \"rows\": []}}"), "export_not_json"),
        ("[]".to_owned(), "not_an_export"),
    ] {
        let err = parse_export(text.as_bytes(), &cfg).unwrap_err();
        assert_eq!(err.label(), want, "{text}");
    }
}

#[test]
fn rows_are_verified_in_id_order_whatever_the_file_order() {
    let (_, base_rows) = base(POST);
    let mut rows = base_rows.clone();
    rows.reverse();
    let report = check(&rows, &base_rows, &[common::FIXTURE_KEY]);
    assert_eq!(report.verdict(), Verdict::Verified);
}

// ---------------------------------------------------------------------------
// the command-line tool
// ---------------------------------------------------------------------------

fn cli(export: &[u8], anchor: Option<&[u8]>, keys: &str, fps: &str) -> (i32, String, String) {
    let dir = std::env::temp_dir().join(format!(
        "tack-sentinel-cli-{}-{}",
        std::process::id(),
        tack_sentinel::canonical::sha256_hex(format!("{keys}{fps}{}", export.len()).as_bytes())
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let export_path = dir.join("export.json");
    let anchor_path = dir.join("ledger.anchor");
    let key_path = dir.join("keys.txt");
    std::fs::write(&export_path, export).unwrap();
    let _ = std::fs::remove_file(&anchor_path);
    if let Some(a) = anchor {
        std::fs::write(&anchor_path, a).unwrap();
    }
    std::fs::write(&key_path, keys).unwrap();
    let out = std::process::Command::new(env!("CARGO_BIN_EXE_tack-sentinel-verify"))
        .args(["--export", export_path.to_str().unwrap()])
        .args(["--anchor", anchor_path.to_str().unwrap()])
        .args(["--trusted-fingerprints", fps])
        .args(["--key-file", key_path.to_str().unwrap()])
        .output()
        .unwrap();
    let _ = std::fs::remove_dir_all(&dir);
    (
        out.status.code().unwrap(),
        String::from_utf8(out.stdout).unwrap(),
        String::from_utf8(out.stderr).unwrap(),
    )
}

#[test]
fn the_cli_prints_what_the_python_tool_prints_and_exits_the_same_way() {
    let (cols, rows) = base(PRE);
    let export = common::export_bytes(&cols, &rows);
    let anchor = common::anchor_bytes(&rows, rows.len(), common::FIXTURE_KEY);
    let key_line = format!("{}\n", std::str::from_utf8(common::FIXTURE_KEY).unwrap());
    let fp = tack_sentinel::key_fingerprint(common::FIXTURE_KEY);

    let (code, out, _) = cli(&export, Some(&anchor), &key_line, &fp);
    assert_eq!((code, out.as_str()), (0, "VERIFIED\n"));

    let mut tampered = rows.clone();
    tampered[3].insert("reason".into(), Value::Str("edited".into()));
    let (code, out, _) = cli(&common::export_bytes(&cols, &tampered), Some(&anchor), &key_line, &fp);
    assert_eq!(code, 1);
    assert!(out.starts_with("TAMPERED row=4 "), "{out}");

    let (code, out, _) = cli(&export, None, &key_line, &fp);
    assert_eq!(code, 1);
    assert!(out.starts_with("TRUNCATED row=- "), "{out}");

    let other_fp = tack_sentinel::key_fingerprint(common::OTHER_KEY);
    let (code, out, err) = cli(&export, Some(&anchor), &key_line, &other_fp);
    assert_eq!((code, out.as_str()), (2, ""));
    assert!(err.contains("no trusted key material"));
}

trait AsInt {
    fn as_int(&self) -> i64;
}

impl AsInt for Value {
    fn as_int(&self) -> i64 {
        match self {
            Value::Int(i) => i.to_i64().unwrap(),
            _ => panic!("not an int"),
        }
    }
}

#[test]
fn an_ordinary_export_of_several_mib_is_not_refused_by_the_parse_budget() {
    // The allocation budget must leave room for ordinary rows: at 8 bytes of
    // tree per byte of text a 16 MiB export of these rows was refused.
    let (cols, base_rows) = base(POST);
    let mut rows = Vec::new();
    let mut id = 1i64;
    while rows.len() < 4800 {
        for r in &base_rows {
            let mut r = r.clone();
            r.insert("id".into(), Value::Int(tack_sentinel::pyjson::PyInt::from_i64(id)));
            id += 1;
            rows.push(r);
        }
    }
    let export = common::export_bytes(&cols, &rows);
    assert!(export.len() > 4 * 1024 * 1024, "{}", export.len());
    let parsed = parse_export(&export, &VerifierConfig::default()).unwrap();
    assert_eq!(parsed.len(), rows.len());
}
