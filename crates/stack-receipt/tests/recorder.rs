//! The recorder: write-ahead order by construction, and what each failure
//! leaves in the log.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use std::sync::{Arc, Mutex};

use common::*;
use stack_receipt::{
    AttemptUnrecorded, Event, Head, LogError, ManualClock, MemoryReceiptLog, Outcome, ReceiptLog, RecordError,
    Recorder, SignedRecord, Stage, Terminal, TerminalUnrecorded,
};

/// A log that shares its records with the test and fails every append
/// once `fail_after` records are in.
#[derive(Debug)]
struct FailingLog {
    inner: MemoryReceiptLog,
    seen: Arc<Mutex<Vec<SignedRecord>>>,
    fail_after: usize,
}

impl ReceiptLog for FailingLog {
    fn kernel_id(&self) -> &str {
        self.inner.kernel_id()
    }
    fn head(&self) -> Result<Head, LogError> {
        self.inner.head()
    }
    fn append(&mut self, record: &SignedRecord) -> Result<(), LogError> {
        if self.inner.records().len() >= self.fail_after {
            return Err(LogError::Io {
                op: "write record",
                kind: std::io::ErrorKind::Other,
                message: "disk full (simulated)".into(),
            });
        }
        self.inner.append(record)?;
        self.seen.lock().unwrap().push(record.clone());
        Ok(())
    }
    fn is_durable(&self) -> bool {
        false
    }
}

fn recorder(fail_after: usize) -> (Recorder, Arc<Mutex<Vec<SignedRecord>>>) {
    let seen = Arc::new(Mutex::new(Vec::new()));
    let log = FailingLog {
        inner: MemoryReceiptLog::new("kernel-1").unwrap(),
        seen: Arc::clone(&seen),
        fail_after,
    };
    let r = Recorder::new(
        Box::new(log),
        fixture_signer("kernel-1"),
        provenance(),
        Box::new(ManualClock::new(T0)),
    )
    .unwrap();
    (r, seen)
}

fn parts() -> (stack_receipt::Proposed, stack_receipt::Authorized, stack_receipt::Attempted) {
    let Event::Proposed(p) = proposed() else { panic!() };
    let Event::Authorized(a) = authorized() else { panic!() };
    let Event::Attempted(at) = attempted() else { panic!() };
    (p, a, at)
}

#[test]
fn the_honest_path_writes_four_chained_signed_records_in_order() {
    let (r, seen) = recorder(usize::MAX);
    let (p, a, at) = parts();
    let exec = r.propose(exec_id(), p).unwrap();
    let exec = exec.authorize_with(a).unwrap();
    let exec = exec.attempt(at.action, at.started_at_ms).unwrap();
    let closed = exec
        .finish(Terminal {
            outcome: completed(),
            completed_at_ms: T0 + 4,
            elapsed_ns: 7,
        })
        .unwrap();
    assert_eq!(closed.id, exec_id());
    assert_eq!(closed.terminal_sequence, 4);
    let records = seen.lock().unwrap().clone();
    let stages: Vec<Stage> = records.iter().map(|s| s.record().stage()).collect();
    assert_eq!(stages, [Stage::Proposed, Stage::Authorized, Stage::Attempted, Stage::Terminal]);
    let mut prev = stack_receipt::genesis_hash();
    for (i, s) in records.iter().enumerate() {
        assert_eq!(s.record().sequence as usize, i + 1);
        assert_eq!(s.record().prev_hash, prev);
        assert_eq!(s.record().kernel_id, "kernel-1");
        assert_eq!(s.record().key_id, *fixture_signer("kernel-1").key_id());
        assert_eq!(s.record().recorded_at_ms, T0);
        assert_eq!(s.record().provenance, provenance());
        assert!(s.verify(fixture_signer("kernel-1").public_key()).is_ok());
        prev = *s.hash();
    }
    assert_eq!(r.head().unwrap(), Head { sequence: 4, hash: prev });
    assert!(!r.is_durable().unwrap());
}

#[test]
fn rejection_is_terminal_from_proposed_and_from_authorized() {
    let (r, seen) = recorder(usize::MAX);
    let (p, a, _) = parts();
    let closed = r.propose(exec_id(), p.clone()).unwrap().reject("not for us").unwrap();
    assert_eq!(closed.terminal_sequence, 2);
    let closed = r
        .propose(exec_id(), p)
        .unwrap()
        .authorize_with(a)
        .unwrap()
        .reject("kernel policy")
        .unwrap();
    assert_eq!(closed.terminal_sequence, 5);
    let stages: Vec<Stage> = seen.lock().unwrap().iter().map(|s| s.record().stage()).collect();
    assert_eq!(
        stages,
        [Stage::Proposed, Stage::Rejected, Stage::Proposed, Stage::Authorized, Stage::Rejected]
    );
}

#[test]
fn a_failed_attempt_record_means_do_not_execute_and_leaves_the_execution_at_authorized() {
    let (r, seen) = recorder(2);
    let (p, a, at) = parts();
    let exec = r.propose(exec_id(), p).unwrap().authorize_with(a).unwrap();
    let err = exec.attempt(at.action, at.started_at_ms).unwrap_err();
    assert!(matches!(err, AttemptUnrecorded(RecordError::Log(LogError::Io { .. }))));
    let stages: Vec<Stage> = seen.lock().unwrap().iter().map(|s| s.record().stage()).collect();
    assert_eq!(stages, [Stage::Proposed, Stage::Authorized]);
}

#[test]
fn a_failed_terminal_record_hands_back_the_observed_outcome_and_leaves_the_attempt_open() {
    let (r, seen) = recorder(3);
    let (p, a, at) = parts();
    let running = r
        .propose(exec_id(), p)
        .unwrap()
        .authorize_with(a)
        .unwrap()
        .attempt(at.action, at.started_at_ms)
        .unwrap();
    let err = running
        .finish(Terminal {
            outcome: completed(),
            completed_at_ms: T0 + 4,
            elapsed_ns: 7,
        })
        .unwrap_err();
    assert!(matches!(
        err,
        TerminalUnrecorded {
            observed_outcome: Outcome::Completed { .. },
            error: RecordError::Log(LogError::Io { .. })
        }
    ));
    assert!(err.to_string().contains("completed"));
    let stages: Vec<Stage> = seen.lock().unwrap().iter().map(|s| s.record().stage()).collect();
    assert_eq!(stages, [Stage::Proposed, Stage::Authorized, Stage::Attempted]);
}

#[test]
fn a_failed_proposal_or_authorization_writes_nothing_further() {
    let (r, seen) = recorder(0);
    let (p, _, _) = parts();
    assert!(matches!(r.propose(exec_id(), p), Err(RecordError::Log(LogError::Io { .. }))));
    assert!(seen.lock().unwrap().is_empty());
    let (r, seen) = recorder(1);
    let (p, a, _) = parts();
    let exec = r.propose(exec_id(), p).unwrap();
    assert!(matches!(exec.authorize_with(a), Err(RecordError::Log(LogError::Io { .. }))));
    assert_eq!(seen.lock().unwrap().len(), 1);
}

#[test]
fn concurrent_executions_interleave_in_one_chain() {
    let (r, seen) = recorder(usize::MAX);
    let handles: Vec<_> = (0..8u8)
        .map(|i| {
            let r = r.clone();
            std::thread::spawn(move || {
                let (p, a, at) = parts();
                let id = stack_receipt::ExecutionId::from_bytes([i; 16]);
                let exec = r.propose(id, p).unwrap().authorize_with(a).unwrap();
                let exec = exec.attempt(at.action, at.started_at_ms).unwrap();
                exec.finish(Terminal {
                    outcome: Outcome::TimedOut,
                    completed_at_ms: T0,
                    elapsed_ns: 1,
                })
                .unwrap()
            })
        })
        .collect();
    for h in handles {
        h.join().unwrap();
    }
    let records = seen.lock().unwrap().clone();
    assert_eq!(records.len(), 32);
    let mut prev = stack_receipt::genesis_hash();
    for (i, s) in records.iter().enumerate() {
        assert_eq!(s.record().sequence as usize, i + 1);
        assert_eq!(s.record().prev_hash, prev);
        prev = *s.hash();
    }
    for i in 0..8u8 {
        let id = stack_receipt::ExecutionId::from_bytes([i; 16]);
        let stages: Vec<Stage> = records
            .iter()
            .filter(|s| s.record().execution_id == id)
            .map(|s| s.record().stage())
            .collect();
        assert_eq!(stages, [Stage::Proposed, Stage::Authorized, Stage::Attempted, Stage::Terminal]);
    }
}

#[test]
fn the_recorder_refuses_invalid_provenance_and_the_signer_key_is_stamped() {
    let mut bad = provenance();
    bad.component = String::new();
    assert!(matches!(
        Recorder::new(
            Box::new(MemoryReceiptLog::new("kernel-1").unwrap()),
            fixture_signer("kernel-1"),
            bad,
            Box::new(ManualClock::new(T0)),
        ),
        Err(RecordError::Invalid(_))
    ));
}
