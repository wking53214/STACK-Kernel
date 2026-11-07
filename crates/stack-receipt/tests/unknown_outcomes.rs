//! The verifier's headline for executions whose outcome nobody knows.
//!
//! A restart closes a crashed execution with a `Recovered` record, and the log then
//! verifies `VERIFIED_WITH_LIMITATIONS`, the same state string as a log of completed
//! runs. `unknown_outcomes` lists the executions whose outcome is unknown, so a consumer
//! that cannot read every execution still has one field to check. These tests use the
//! real file log, recorder and verifier, with fixture keys.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use std::path::PathBuf;

use common::*;
use stack_receipt::{
    verify_log_bytes, ActualAction, Authorized, Event, Expectations, FileReceiptLog, ManualClock, Outcome, Proposed,
    Recorder, State, Terminal,
};

fn temp(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("stack-receipt-unknown-{}-{name}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("receipts.log");
    let _ = std::fs::remove_file(&path);
    path
}

fn recorder(path: &PathBuf) -> Recorder {
    let log = FileReceiptLog::open(path, "kernel-1", &[fixture_public_key("kernel-1")]).unwrap();
    Recorder::new(
        Box::new(log),
        fixture_signer("kernel-1"),
        provenance(),
        Box::new(ManualClock::new(T0)),
    )
    .unwrap()
}

fn id(n: u8) -> stack_receipt::ExecutionId {
    stack_receipt::ExecutionId::from_bytes([n; 16])
}

fn proposed_body() -> Proposed {
    match proposed() {
        Event::Proposed(p) => p,
        other => panic!("{other:?}"),
    }
}

fn authorized_body() -> Authorized {
    match authorized() {
        Event::Authorized(a) => a,
        other => panic!("{other:?}"),
    }
}

fn actual() -> ActualAction {
    ActualAction {
        operation: "read".into(),
        resource: "/data/a".into(),
        argument_digest: d(0xbb),
    }
}

fn terminal_body(outcome: Outcome) -> Terminal {
    match terminal(outcome) {
        Event::Terminal(t) => t,
        other => panic!("{other:?}"),
    }
}

fn verify(path: &PathBuf) -> stack_receipt::LogVerification {
    verify_log_bytes(&std::fs::read(path).unwrap(), &baseline_trust(), &Expectations::default())
}

/// Runs execution `n` to a terminal with `outcome`.
fn run_to_terminal(rec: &Recorder, n: u8, outcome: Outcome) {
    rec.propose(id(n), proposed_body())
        .unwrap()
        .authorize_with(authorized_body())
        .unwrap()
        .attempt(actual(), T0)
        .unwrap()
        .finish(terminal_body(outcome))
        .unwrap();
}

#[test]
fn a_log_of_completed_runs_lists_no_unknown_outcome() {
    let path = temp("completed");
    let rec = recorder(&path);
    run_to_terminal(&rec, 1, completed());
    run_to_terminal(&rec, 2, Outcome::TimedOut);
    drop(rec);
    let v = verify(&path);
    assert_eq!(v.state, State::VerifiedWithLimitations, "{:?}", v.findings);
    assert!(v.unknown_outcomes.is_empty(), "{:?}", v.unknown_outcomes);
}

#[test]
fn an_attempt_with_no_terminal_is_listed_and_the_log_is_incomplete() {
    let path = temp("open");
    let rec = recorder(&path);
    let _open = rec
        .propose(id(7), proposed_body())
        .unwrap()
        .authorize_with(authorized_body())
        .unwrap()
        .attempt(actual(), T0)
        .unwrap();
    let v = verify(&path);
    assert_eq!(v.state, State::Incomplete);
    assert_eq!(v.unknown_outcomes, vec![id(7)]);
}

#[test]
fn a_recovered_attempt_is_listed_although_the_state_looks_fine() {
    let path = temp("recovered");
    let rec = recorder(&path);
    run_to_terminal(&rec, 1, completed());
    let _open = rec
        .propose(id(2), proposed_body())
        .unwrap()
        .authorize_with(authorized_body())
        .unwrap()
        .attempt(actual(), T0)
        .unwrap();
    drop(_open);
    drop(rec);
    let rec = recorder(&path);
    assert_eq!(rec.recover_open_executions().unwrap(), vec![id(2)]);
    drop(rec);

    let v = verify(&path);
    // The footgun: this is the state a log of completed runs has.
    assert_eq!(v.state, State::VerifiedWithLimitations, "{:?}", v.findings);
    // The headline that tells them apart.
    assert_eq!(v.unknown_outcomes, vec![id(2)]);
    let json = v.to_json();
    assert!(
        json.contains(&format!("\"unknown_outcomes\":[\"{}\"]", id(2).to_hex())),
        "{json}"
    );
}

#[test]
fn recovered_before_an_attempt_and_an_observed_unknown_terminal_are_told_apart() {
    let path = temp("mixed");
    let rec = recorder(&path);
    // 1: completed. 2: the kernel could not observe the end (a recorded Unknown terminal).
    run_to_terminal(&rec, 1, completed());
    run_to_terminal(&rec, 2, Outcome::Unknown { reason: "executor failed".into() });
    // 3: proposed only. 4: authorized only. 5: attempted. These three are left open.
    let _a = rec.propose(id(3), proposed_body()).unwrap();
    let _b = rec.propose(id(4), proposed_body()).unwrap().authorize_with(authorized_body()).unwrap();
    let _c = rec
        .propose(id(5), proposed_body())
        .unwrap()
        .authorize_with(authorized_body())
        .unwrap()
        .attempt(actual(), T0)
        .unwrap();
    drop((_a, _b, _c));
    drop(rec);
    let rec = recorder(&path);
    assert_eq!(rec.recover_open_executions().unwrap().len(), 3);
    drop(rec);

    let v = verify(&path);
    // Only executions whose payload may have run and whose end nobody knows, in log order. Executions
    // 3 and 4 never ran, so they have no outcome to be unknown.
    assert_eq!(v.unknown_outcomes, vec![id(2), id(5)]);
}

#[test]
fn a_log_that_does_not_parse_lists_nothing_and_is_rejected() {
    let v = verify_log_bytes(b"not a log", &baseline_trust(), &Expectations::default());
    assert_eq!(v.state, State::Rejected);
    assert!(v.unknown_outcomes.is_empty());
}
