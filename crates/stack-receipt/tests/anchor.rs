//! The auditor's anchor: a `Head` saved somewhere the log's writer cannot
//! reach. With it the verifier catches a log that was cut short, rolled back
//! below the anchor, or replaced; without it the same files verify, which is
//! the limitation `LogRollbackNotDetectableWithoutAnchor` states. These tests
//! use the real file log and the real verifier, with fixture keys.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use std::path::PathBuf;

use common::*;
use stack_receipt::{
    verify_log, verify_log_bytes, Check, Expectations, FileReceiptLog, FindingCode, Head, LogError, Outcome, ReceiptLog,
    State,
};

fn temp(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("stack-receipt-anchor-{}-{name}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("receipts.log");
    let _ = std::fs::remove_file(&path);
    path
}

fn open(path: &PathBuf) -> Result<FileReceiptLog, LogError> {
    FileReceiptLog::open(path, "kernel-1", &[fixture_public_key("kernel-1")])
}

/// Appends `events` (signed as one chain) to a fresh log at `path`, and returns
/// the file bytes and the head after the last append.
fn write_log(path: &PathBuf, events: Vec<stack_receipt::Event>) -> (Vec<u8>, Head) {
    let mut log = open(path).unwrap();
    for s in sign_chain(events) {
        log.append(&s).unwrap();
    }
    let head = log.head().unwrap();
    drop(log);
    (std::fs::read(path).unwrap(), head)
}

fn codes(v: &stack_receipt::LogVerification) -> Vec<FindingCode> {
    v.findings.iter().map(|f| f.code.clone()).collect()
}

#[test]
fn an_anchor_still_held_after_the_log_grew_is_accepted() {
    let path = temp("grew");
    let chain = sign_chain(honest_events());
    let mut log = open(&path).unwrap();
    for s in &chain[..2] {
        log.append(s).unwrap();
    }
    let anchor = log.head().unwrap();
    for s in &chain[2..] {
        log.append(s).unwrap();
    }
    drop(log);
    let bytes = std::fs::read(&path).unwrap();
    let exp = Expectations {
        anchor: Some(&anchor),
        ..Expectations::default()
    };
    let v = verify_log_bytes(&bytes, &baseline_trust(), &exp);
    assert!(!codes(&v).contains(&FindingCode::LogDoesNotReachAnchor), "{:?}", v.findings);
    assert!(!codes(&v).contains(&FindingCode::AnchorMismatch), "{:?}", v.findings);
    assert_eq!(v.state, State::VerifiedWithLimitations);
    assert!(v.scope.checked.contains(&Check::AnchorHeld));
}

#[test]
fn a_log_rolled_back_below_the_anchor_is_rejected_and_without_the_anchor_it_is_not() {
    let path = temp("rollback");
    let chain = sign_chain(honest_events());
    let mut log = open(&path).unwrap();
    for s in &chain[..3] {
        log.append(s).unwrap();
    }
    drop(log);
    let three = std::fs::read(&path).unwrap();
    let mut log = open(&path).unwrap();
    log.append(&chain[3]).unwrap();
    let anchored = log.head().unwrap();
    drop(log);
    assert_eq!(anchored.sequence, 4);

    // An attacker puts the older, genuine, three-record file back.
    let with_anchor = Expectations {
        anchor: Some(&anchored),
        ..Expectations::default()
    };
    let v = verify_log_bytes(&three, &baseline_trust(), &with_anchor);
    assert_eq!(v.state, State::Rejected, "{:?}", v.findings);
    assert!(codes(&v).contains(&FindingCode::LogDoesNotReachAnchor), "{:?}", v.findings);

    // Control: the same bytes without the anchor are only incomplete. This is
    // the documented limitation, and it shows the anchor is what catches it.
    let v = verify_log_bytes(&three, &baseline_trust(), &Expectations::default());
    assert_eq!(v.state, State::Incomplete, "{:?}", v.findings);
    assert!(!codes(&v).contains(&FindingCode::LogDoesNotReachAnchor));
    assert!(!v.scope.checked.contains(&Check::AnchorHeld));
}

#[test]
fn a_log_whose_history_was_replaced_is_rejected_by_the_anchor() {
    let (_a_bytes, a_head) = write_log(&temp("replaced-a"), honest_events());
    let mut other = honest_events();
    other.pop();
    other.push(terminal(Outcome::Terminated { signal: 9 }));
    let (b_bytes, b_head) = write_log(&temp("replaced-b"), other);
    assert_eq!(a_head.sequence, b_head.sequence, "same length, different last record");
    assert_ne!(a_head.hash, b_head.hash);

    let exp = Expectations {
        anchor: Some(&a_head),
        ..Expectations::default()
    };
    let v = verify_log_bytes(&b_bytes, &baseline_trust(), &exp);
    assert_eq!(v.state, State::Rejected, "{:?}", v.findings);
    assert!(codes(&v).contains(&FindingCode::AnchorMismatch), "{:?}", v.findings);
}

#[test]
fn an_anchor_on_an_empty_log_is_rejected_and_the_genesis_anchor_is_vacuous() {
    let real = Head {
        sequence: 5,
        hash: [7u8; 32],
    };
    let exp = Expectations {
        anchor: Some(&real),
        ..Expectations::default()
    };
    let v = verify_log(&[], &baseline_trust(), &exp);
    assert!(codes(&v).contains(&FindingCode::LogDoesNotReachAnchor), "{:?}", v.findings);
    assert_eq!(v.state, State::Rejected);

    let genesis = Head::genesis();
    let exp = Expectations {
        anchor: Some(&genesis),
        ..Expectations::default()
    };
    let v = verify_log(&[], &baseline_trust(), &exp);
    assert!(!codes(&v).contains(&FindingCode::LogDoesNotReachAnchor), "{:?}", v.findings);
}
