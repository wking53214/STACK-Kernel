//! Crash recovery at the kernel: a restarted kernel closes the executions an
//! earlier run left open, in the log, before it accepts any work, and it
//! refuses to start if it cannot.
//!
//! An open execution is made by the real failure the existing tests use: a
//! terminal (or an attempt) that the log would not take. The restart is a
//! second kernel over the same directory, the real file log, the real
//! stores and the real supervised worker. Every claim about the log is made by
//! `stack_receipt::verify_log_bytes`. Keys are TEST FIXTURES.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use std::time::{Duration, Instant};

use common::*;
use stack_admission::{AdmissionResult, BuildError};
use stack_receipt::{
    FileReceiptLog, FindingCode, Limitation, LogError, OutcomeKind, RecordError, Stage as ReceiptStage, State,
};
use stack_trident::{StartError, StoreError};

/// A kernel whose terminal record cannot be written: the run completes and the
/// execution stays open at `Attempted`. Returns the execution id.
fn leave_one_attempt_open(dir: &TempDir) -> stack_receipt::ExecutionId {
    let h = Builder::new(dir.path())
        .receipt_log(Box::new(FailingFileLog::open(dir.path(), &[4])))
        .start();
    match h.process(honest_payload(&all_pass(), "echo")) {
        AdmissionResult::TerminalLost(lost) => lost.execution_id,
        other => panic!("expected TerminalLost, got {other:?}"),
    }
}

fn restart(dir: &TempDir) -> Harness {
    Builder::restarting(dir.path(), started_now()).start_after_release()
}

/// Starts a kernel over `dir` whose log fails on the given append calls, and
/// returns the error it stopped with. Retries only while a lock from the
/// previous kernel is still held by a forked worker.
fn restart_expecting_failure(dir: &TempDir, fail_on: &[usize]) -> BuildError {
    let give_up = Instant::now() + Duration::from_secs(10);
    loop {
        let inner = match FileReceiptLog::open(receipts_path(dir.path()), KERNEL, &[receipt_public_key(KERNEL)]) {
            Ok(l) => l,
            Err(LogError::Locked { .. }) if Instant::now() < give_up => {
                std::thread::sleep(Duration::from_millis(20));
                continue;
            }
            Err(e) => panic!("{e}"),
        };
        let log = FailingFileLog {
            inner,
            fail_on: fail_on.to_vec(),
            calls: 0,
        };
        match Builder::restarting(dir.path(), started_now()).receipt_log(Box::new(log)).build() {
            Err(BuildError::Trident(StartError::Store(StoreError::Locked { .. })) | BuildError::UseStoreNotDurable)
                if Instant::now() < give_up =>
            {
                std::thread::sleep(Duration::from_millis(20));
            }
            Err(e) => return e,
            Ok(_) => panic!("the kernel started although it could not write its recovery records"),
        }
    }
}

#[test]
fn a_restarted_kernel_closes_the_open_execution_before_it_takes_any_work() {
    let dir = TempDir::new("recovery-attempted");
    let open = leave_one_attempt_open(&dir);

    // Control: without a restart the log is incomplete, as it always was.
    let before = verify_bytes_full(&std::fs::read(receipts_path(dir.path())).unwrap(), &all_pass(), None);
    assert_eq!(before.state, State::Incomplete, "{}", before.to_json());

    let h = restart(&dir);
    assert_eq!(h.admission.recovered_executions(), [open]);

    // Before any new request: closed, outcome unknown, limitation named.
    let case = all_pass();
    let v = h.verify_full(&case, None);
    assert_eq!(v.state, State::VerifiedWithLimitations, "{}", v.to_json());
    assert_eq!(v.executions.len(), 1);
    let e = &v.executions[0];
    assert_eq!(e.execution.execution_id, open);
    assert_eq!(e.execution.stage_reached, Some(ReceiptStage::Attempted));
    assert_eq!(e.execution.outcome, Some(OutcomeKind::Unknown), "recovery does not claim the run did not happen");
    assert_eq!(e.execution.sequences, vec![1, 2, 3, 4]);
    assert!(e.findings.iter().any(|f| f.code == FindingCode::RecoveredAfterRestart), "{}", e.to_json());
    assert!(!e.findings.iter().any(|f| f.code == FindingCode::TerminalMissing), "{}", e.to_json());
    assert!(v.scope.not_checked.contains(&Limitation::ExecutionRecoveredOutcomeUnknown));
    // The headline for a consumer that reads only the state: the recovered execution is listed.
    assert_eq!(v.unknown_outcomes, vec![open]);

    // New work goes after the recovery record, and the log stays verifiable.
    h.set_next_seq(2);
    let fresh = h.process(honest_payload(&case, "echo"));
    assert!(fresh.is_success(), "{fresh:?}");
    let v = h.verify_full(&case, None);
    assert_eq!(v.state, State::VerifiedWithLimitations, "{}", v.to_json());
    assert_eq!(v.executions.len(), 2);
    assert_eq!(v.executions[0].execution.outcome, Some(OutcomeKind::Unknown));
    assert_eq!(v.executions[1].execution.outcome, Some(OutcomeKind::Completed));
    assert_eq!(v.executions[1].execution.sequences[0], 5, "the new execution starts after the Recovered record");
}

#[test]
fn recovery_does_not_repeat_on_the_next_restart() {
    let dir = TempDir::new("recovery-once");
    let open = leave_one_attempt_open(&dir);
    let first = restart(&dir);
    assert_eq!(first.admission.recovered_executions(), [open]);
    let head = first.admission.receipt_head().unwrap();
    drop(first);

    let second = restart(&dir);
    assert!(second.admission.recovered_executions().is_empty());
    assert_eq!(second.admission.receipt_head().unwrap(), head, "a second restart wrote nothing");
}

#[test]
fn a_kernel_that_shut_down_cleanly_recovers_nothing_and_writes_nothing() {
    let dir = TempDir::new("recovery-clean");
    let h = Builder::new(dir.path()).start();
    assert!(h.process(honest_payload(&all_pass(), "echo")).is_success());
    let head = h.admission.receipt_head().unwrap();
    drop(h);

    let h = restart(&dir);
    assert!(h.admission.recovered_executions().is_empty());
    assert_eq!(h.admission.receipt_head().unwrap(), head);
}

#[test]
fn an_authorized_but_never_attempted_execution_is_closed_without_an_unknown_outcome() {
    let dir = TempDir::new("recovery-authorized");
    // Append calls: 1 proposed, 2 authorized, 3 attempted (fails).
    let open = {
        let h = Builder::new(dir.path())
            .receipt_log(Box::new(FailingFileLog::open(dir.path(), &[3])))
            .start();
        let AdmissionResult::Refused(r) = h.process(honest_payload(&all_pass(), "echo")) else {
            panic!("expected a refusal");
        };
        assert_eq!(h.runs(), 0, "nothing ran");
        r.execution_id.expect("the proposal was recorded")
    };

    let h = restart(&dir);
    assert_eq!(h.admission.recovered_executions(), [open]);
    let v = h.verify_full(&all_pass(), None);
    assert_eq!(v.state, State::VerifiedWithLimitations, "{}", v.to_json());
    let e = &v.executions[0];
    assert_eq!(e.execution.stage_reached, Some(ReceiptStage::Authorized));
    assert_eq!(e.execution.outcome, None, "nothing was attempted, so there is no outcome to be unknown");
    assert!(e.findings.iter().any(|f| f.code == FindingCode::RecoveredAfterRestart));
    assert!(!v.scope.not_checked.contains(&Limitation::ExecutionRecoveredOutcomeUnknown));
}

#[test]
fn a_kernel_that_cannot_write_its_recovery_records_does_not_start() {
    let dir = TempDir::new("recovery-fails");
    let open = leave_one_attempt_open(&dir);
    let bytes_before = std::fs::read(receipts_path(dir.path())).unwrap();

    // The first append after the restart is the Recovered record. It fails.
    let err = restart_expecting_failure(&dir, &[1]);
    assert!(matches!(err, BuildError::Recorder(RecordError::Log(LogError::Poisoned))), "{err:?}");
    assert_eq!(
        std::fs::read(receipts_path(dir.path())).unwrap(),
        bytes_before,
        "a failed recovery wrote nothing"
    );

    // Nothing is lost: the next start recovers the same execution.
    let h = restart(&dir);
    assert_eq!(h.admission.recovered_executions(), [open]);
}
