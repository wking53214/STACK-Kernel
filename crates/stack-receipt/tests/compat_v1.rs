//! Receipt format compatibility (D1-C). A log written before the receipt gained
//! its supervisor-observed facts (format version 1, tag `stack-receipt/1`) must
//! keep verifying, unchanged, under the current verifier, and the facts a v1
//! receipt cannot show must come out as limitations, never as failures.
//!
//! `fixtures/v1_log.bin` was written by the v1 writer, before the version 2
//! encoding existed, from `honest_events()` under the `kernel-1` test key. The
//! first test proves the current writer still produces those exact bytes for
//! v1 events (so v1 is not silently changed), the others read the file as a
//! verifier would.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use common::*;
use stack_receipt::{
    decode_record, verify_log_bytes, Expectations, Limitation, OutcomeKind, State, DOMAIN_TAG,
};

const V1_LOG: &[u8] = include_bytes!("fixtures/v1_log.bin");

fn write_current_log(path: &std::path::Path) {
    let _ = std::fs::remove_file(path);
    let mut log = stack_receipt::FileReceiptLog::open(path, "kernel-1", &[fixture_public_key("kernel-1")]).unwrap();
    for s in sign_chain(honest_events()) {
        stack_receipt::ReceiptLog::append(&mut log, &s).unwrap();
    }
}

/// Maintenance only: `STACK_RECEIPT_WRITE_V1_FIXTURE=1 cargo test -p stack-receipt --test compat_v1`
/// rewrites the fixture. The committed file was produced this way on the
/// pre-version-2 writer and must not be regenerated casually.
#[test]
fn the_v1_fixture_matches_what_the_writer_produces_for_v1_events() {
    let dir = std::env::temp_dir().join(format!("stack-receipt-compat-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("current.log");
    write_current_log(&path);
    let now = std::fs::read(&path).unwrap();
    if std::env::var_os("STACK_RECEIPT_WRITE_V1_FIXTURE").is_some() {
        std::fs::write(concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/v1_log.bin"), &now).unwrap();
    }
    assert_eq!(now, V1_LOG, "the writer changed the bytes of a v1 log");
}

#[test]
fn a_v1_log_still_verifies_and_names_the_facts_it_cannot_show() {
    let v = verify_log_bytes(V1_LOG, &baseline_trust(), &Expectations::default());
    assert_eq!(v.state, State::VerifiedWithLimitations, "{}", v.to_json());
    assert!(v.findings.is_empty(), "a v1 receipt is not a failure: {:?}", v.findings);
    let e = &v.executions[0];
    assert_eq!(e.execution.outcome, Some(OutcomeKind::Completed));
    assert!(
        e.scope.not_checked.contains(&Limitation::SupervisorObservedFactsNotRecorded),
        "{:?}",
        e.scope.not_checked
    );
    assert!(v.scope.not_checked.contains(&Limitation::SupervisorObservedFactsNotRecorded));
}

#[test]
fn every_record_of_the_v1_log_carries_the_v1_tag_and_decodes() {
    let parsed = stack_receipt::parse_log(V1_LOG).unwrap();
    assert_eq!(parsed.records.len(), 4);
    for s in &parsed.records {
        assert!(s.canonical().starts_with(DOMAIN_TAG));
        let r = decode_record(s.canonical()).unwrap();
        assert_eq!(&r, s.record());
    }
}
