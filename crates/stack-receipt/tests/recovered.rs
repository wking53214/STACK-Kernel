//! Crash recovery: a restarted kernel closes the executions a crash left open
//! with a `Recovered` record (format version 3), and the verifier reads that
//! record without claiming to know how the run ended.
//!
//! Most tests use the real file log, the real recorder and the real verifier,
//! with fixture keys. The control tests state what the same log looks like
//! without the recovery step, so the tests that follow show what it changes.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use std::path::PathBuf;

use common::*;
use stack_receipt::{
    canonical_bytes, decode_record, genesis_hash, verify_log_bytes, ActualAction, Authorized, Check, DecodeError,
    Event, Expectations, FileReceiptLog, FindingCode, LastStage, Limitation, LogError, ManualClock, MemoryReceiptLog,
    OutcomeKind, Proposed, ReceiptLog, Recorder, Recovered, Stage, State, DOMAIN_TAG, DOMAIN_TAG_V2, DOMAIN_TAG_V3,
};

fn temp(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("stack-receipt-recovered-{}-{name}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("receipts.log");
    let _ = std::fs::remove_file(&path);
    path
}

fn recorder_over_file(path: &PathBuf) -> Recorder {
    let log = FileReceiptLog::open(path, "kernel-1", &[fixture_public_key("kernel-1")]).unwrap();
    Recorder::new(
        Box::new(log),
        fixture_signer("kernel-1"),
        provenance(),
        Box::new(ManualClock::new(T0)),
    )
    .unwrap()
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

fn id(n: u8) -> stack_receipt::ExecutionId {
    stack_receipt::ExecutionId::from_bytes([n; 16])
}

/// Three executions left open at each stage, one closed with a terminal, one
/// closed with a rejection. Returns the ids: (proposed, authorized, attempted).
fn crashed_log(path: &PathBuf) -> (stack_receipt::ExecutionId, stack_receipt::ExecutionId, stack_receipt::ExecutionId) {
    let rec = recorder_over_file(path);
    // Closed ones, so recovery has something it must leave alone.
    let done = rec
        .propose(id(1), proposed_body())
        .unwrap()
        .authorize_with(authorized_body())
        .unwrap()
        .attempt(actual(), T0)
        .unwrap();
    done.finish(match terminal(completed()) {
        Event::Terminal(t) => t,
        other => panic!("{other:?}"),
    })
    .unwrap();
    rec.propose(id(2), proposed_body()).unwrap().reject("not allowed").unwrap();
    // Open ones. The handles are dropped, as a crash would drop them.
    let _p = rec.propose(id(3), proposed_body()).unwrap();
    let _a = rec.propose(id(4), proposed_body()).unwrap().authorize_with(authorized_body()).unwrap();
    let _t = rec
        .propose(id(5), proposed_body())
        .unwrap()
        .authorize_with(authorized_body())
        .unwrap()
        .attempt(actual(), T0)
        .unwrap();
    (id(3), id(4), id(5))
}

fn verify_file(path: &PathBuf) -> stack_receipt::LogVerification {
    verify_log_bytes(&std::fs::read(path).unwrap(), &baseline_trust(), &Expectations::default())
}

fn summary(v: &stack_receipt::LogVerification, e: stack_receipt::ExecutionId) -> &stack_receipt::ExecutionSummary {
    &v.executions.iter().find(|s| s.execution.execution_id == e).unwrap().execution
}

/// Chain-level and per-execution finding codes together.
fn codes(v: &stack_receipt::LogVerification) -> Vec<FindingCode> {
    let mut out: Vec<FindingCode> = v.findings.iter().map(|f| f.code.clone()).collect();
    for e in &v.executions {
        out.extend(e.findings.iter().map(|f| f.code.clone()));
    }
    out
}

// ---------------------------------------------------------------------------
// Control: without the recovery step
// ---------------------------------------------------------------------------

#[test]
fn control_a_log_with_open_executions_stays_incomplete_until_it_is_recovered() {
    let path = temp("control");
    let (p, a, t) = crashed_log(&path);
    let v = verify_file(&path);
    assert_eq!(v.state, State::Incomplete, "{:?}", v.findings);
    for e in [p, a, t] {
        assert!(summary(&v, e).stage_reached.is_some());
    }
    assert!(codes(&v).contains(&FindingCode::TerminalMissing));
    assert!(codes(&v).contains(&FindingCode::NotAttempted));
    assert!(codes(&v).contains(&FindingCode::NotAuthorized));
}

// ---------------------------------------------------------------------------
// Recovery
// ---------------------------------------------------------------------------

#[test]
fn recovery_closes_every_open_execution_and_only_those() {
    let path = temp("closes");
    let (p, a, t) = crashed_log(&path);
    let before = FileReceiptLog::read_file(&path).unwrap().records.len();

    let rec = recorder_over_file(&path);
    let recovered = rec.recover_open_executions().unwrap();
    assert_eq!(recovered, vec![p, a, t], "first-seen order, closed executions left alone");
    drop(rec);

    let after = FileReceiptLog::read_file(&path).unwrap().records;
    assert_eq!(after.len(), before + 3);
    let last_stages: Vec<_> = after[before..]
        .iter()
        .map(|s| match &s.record().event {
            Event::Recovered(r) => r.last_stage,
            other => panic!("{other:?}"),
        })
        .collect();
    assert_eq!(last_stages, vec![LastStage::Proposed, LastStage::Authorized, LastStage::Attempted]);
    assert!(after[before..].iter().all(|s| s.record().stage() == Stage::Recovered));
}

#[test]
fn a_recovered_log_verifies_with_limitations_and_names_the_unknown_outcome() {
    let path = temp("verifies");
    let (p, a, t) = crashed_log(&path);
    let rec = recorder_over_file(&path);
    rec.recover_open_executions().unwrap();
    drop(rec);

    let v = verify_file(&path);
    assert_eq!(v.state, State::VerifiedWithLimitations, "{:?}", v.findings);
    let c = codes(&v);
    assert!(!c.contains(&FindingCode::TerminalMissing), "{:?}", v.findings);
    assert!(!c.contains(&FindingCode::NotAttempted));
    assert!(!c.contains(&FindingCode::NotAuthorized));
    assert_eq!(c.iter().filter(|x| **x == FindingCode::RecoveredAfterRestart).count(), 3);
    assert!(v.scope.checked.contains(&Check::RecoveryClaimMatchesChain));

    // Only the execution whose payload may have run has an unknown outcome.
    assert_eq!(summary(&v, t).outcome, Some(OutcomeKind::Unknown));
    assert_eq!(summary(&v, t).stage_reached, Some(Stage::Attempted));
    assert_eq!(summary(&v, p).outcome, None);
    assert_eq!(summary(&v, a).outcome, None);
    assert!(v.scope.not_checked.contains(&Limitation::ExecutionRecoveredOutcomeUnknown));
}

#[test]
fn the_unknown_outcome_limitation_appears_only_when_a_run_may_have_happened() {
    let path = temp("limitation-only-when-needed");
    let rec = recorder_over_file(&path);
    let _p = rec.propose(id(3), proposed_body()).unwrap();
    let _a = rec.propose(id(4), proposed_body()).unwrap().authorize_with(authorized_body()).unwrap();
    // The handles share the recorder's log, so the crash is both going away.
    drop(_p);
    drop(_a);
    drop(rec);
    let rec = recorder_over_file(&path);
    assert_eq!(rec.recover_open_executions().unwrap().len(), 2);
    drop(rec);
    let v = verify_file(&path);
    assert_eq!(v.state, State::VerifiedWithLimitations, "{:?}", v.findings);
    assert!(!v.scope.not_checked.contains(&Limitation::ExecutionRecoveredOutcomeUnknown));
}

#[test]
fn recovery_twice_writes_nothing_the_second_time() {
    let path = temp("idempotent");
    let _ids = crashed_log(&path);
    let rec = recorder_over_file(&path);
    assert_eq!(rec.recover_open_executions().unwrap().len(), 3);
    let head = rec.head().unwrap();
    assert!(rec.recover_open_executions().unwrap().is_empty());
    assert_eq!(rec.head().unwrap(), head, "the log did not grow");
    drop(rec);
    // And again after a further restart.
    let rec = recorder_over_file(&path);
    assert!(rec.recover_open_executions().unwrap().is_empty());
}

#[test]
fn recovery_on_a_clean_or_empty_log_writes_nothing() {
    let path = temp("clean");
    let rec = recorder_over_file(&path);
    assert!(rec.recover_open_executions().unwrap().is_empty());
    assert_eq!(rec.head().unwrap(), stack_receipt::Head::genesis());
}

#[test]
fn recovery_reads_the_log_the_kernel_holds_not_whatever_is_at_the_path() {
    // The kernel opens and locks one file. If another file is put at the path before recovery
    // runs, recovery must still look at the file it holds and will append to.
    let path = temp("swapped-held");
    let rec = recorder_over_file(&path); // holds and locks the (empty) log at `path`

    let other = temp("swapped-other");
    let _ids = crashed_log(&other); // a different log with three open executions
    let moved = path.with_file_name("moved.log");
    let _ = std::fs::remove_file(&moved);
    std::fs::rename(&path, &moved).unwrap(); // the held file keeps its inode
    std::fs::rename(&other, &path).unwrap(); // a stranger's log now sits at the path

    let recovered = rec.recover_open_executions().unwrap();
    assert!(recovered.is_empty(), "recovered executions from a log the kernel does not hold: {recovered:?}");
    drop(rec);
    // The file the kernel held is untouched: no Recovered record was written into it.
    let held = FileReceiptLog::read_file(&moved).unwrap();
    assert!(held.records.is_empty(), "{} records were written into the held log", held.records.len());
}

// ---------------------------------------------------------------------------
// The verifier does not take the record's word for it
// ---------------------------------------------------------------------------

fn chain_with_recovered(last: LastStage, before: Vec<Event>) -> Vec<u8> {
    // Bytes of a file log holding `before` then a Recovered record for the
    // same execution.
    let path = temp(&format!("forged-{}-{}", last.as_str(), before.len()));
    let mut events = before;
    events.push(Event::Recovered(Recovered { last_stage: last }));
    let mut log = FileReceiptLog::open(&path, "kernel-1", &[fixture_public_key("kernel-1")]).unwrap();
    for s in sign_chain(events) {
        log.append(&s).unwrap();
    }
    drop(log);
    std::fs::read(&path).unwrap()
}

#[test]
fn a_recovered_record_that_names_the_wrong_stage_is_rejected() {
    // The execution reached Attempted, but the record says Authorized: it
    // would hide that a payload may have run.
    let bytes = chain_with_recovered(LastStage::Authorized, vec![proposed(), authorized(), attempted()]);
    let v = verify_log_bytes(&bytes, &baseline_trust(), &Expectations::default());
    assert_eq!(v.state, State::Rejected, "{:?}", v.findings);
    assert!(codes(&v).contains(&FindingCode::RecoveredStageMismatch));

    // The same chain with the honest claim is not rejected.
    let bytes = chain_with_recovered(LastStage::Attempted, vec![proposed(), authorized(), attempted()]);
    let v = verify_log_bytes(&bytes, &baseline_trust(), &Expectations::default());
    assert_eq!(v.state, State::VerifiedWithLimitations, "{:?}", v.findings);
}

#[test]
fn a_recovered_record_with_nothing_before_it_is_rejected() {
    let bytes = chain_with_recovered(LastStage::Attempted, vec![]);
    let v = verify_log_bytes(&bytes, &baseline_trust(), &Expectations::default());
    assert_eq!(v.state, State::Rejected, "{:?}", v.findings);
    assert!(codes(&v).contains(&FindingCode::MissingProposed));
    assert!(codes(&v).contains(&FindingCode::RecoveredStageMismatch));
}

#[test]
fn a_terminal_after_a_recovered_record_is_rejected_as_a_second_close() {
    let bytes = {
        let path = temp("terminal-after");
        let events = vec![
            proposed(),
            authorized(),
            attempted(),
            Event::Recovered(Recovered {
                last_stage: LastStage::Attempted,
            }),
            terminal(completed()),
        ];
        let mut log = FileReceiptLog::open(&path, "kernel-1", &[fixture_public_key("kernel-1")]).unwrap();
        for s in sign_chain(events) {
            log.append(&s).unwrap();
        }
        drop(log);
        std::fs::read(&path).unwrap()
    };
    let v = verify_log_bytes(&bytes, &baseline_trust(), &Expectations::default());
    assert_eq!(v.state, State::Rejected, "{:?}", v.findings);
    assert!(codes(&v).contains(&FindingCode::DuplicateTerminal));
}

#[test]
fn a_recovered_record_after_a_terminal_is_rejected() {
    let bytes = {
        let path = temp("recovered-after-terminal");
        let mut events = honest_events();
        events.push(Event::Recovered(Recovered {
            last_stage: LastStage::Attempted,
        }));
        let mut log = FileReceiptLog::open(&path, "kernel-1", &[fixture_public_key("kernel-1")]).unwrap();
        for s in sign_chain(events) {
            log.append(&s).unwrap();
        }
        drop(log);
        std::fs::read(&path).unwrap()
    };
    let v = verify_log_bytes(&bytes, &baseline_trust(), &Expectations::default());
    assert_eq!(v.state, State::Rejected, "{:?}", v.findings);
    assert!(codes(&v).contains(&FindingCode::DuplicateTerminal));
}

// ---------------------------------------------------------------------------
// Format version 3: exactly one encoding
// ---------------------------------------------------------------------------

fn recovered_record(last: LastStage) -> stack_receipt::Record {
    record(1, genesis_hash(), Event::Recovered(Recovered { last_stage: last }))
}

#[test]
fn a_recovered_record_round_trips_under_the_version_3_tag() {
    for last in [LastStage::Proposed, LastStage::Authorized, LastStage::Attempted] {
        let r = recovered_record(last);
        let bytes = canonical_bytes(&r).unwrap();
        assert!(bytes.starts_with(DOMAIN_TAG_V3), "{last:?}");
        assert_eq!(decode_record(&bytes).unwrap(), r);
    }
}

#[test]
fn the_version_and_the_event_must_agree_for_version_3() {
    let v3 = canonical_bytes(&recovered_record(LastStage::Attempted)).unwrap();
    // A version 3 body under the version 1 or 2 tag is refused.
    for tag in [DOMAIN_TAG, DOMAIN_TAG_V2] {
        let mut m = v3.clone();
        m[..tag.len()].copy_from_slice(tag);
        assert_eq!(decode_record(&m), Err(DecodeError::BadTagByte("event", 9)));
    }
    // A version 1 body and a version 2 body under the version 3 tag are refused.
    let v1 = canonical_bytes(&record(1, genesis_hash(), proposed())).unwrap();
    let v2 = canonical_bytes(&record(4, genesis_hash(), terminal_observed_fixture())).unwrap();
    for bytes in [v1, v2] {
        let mut m = bytes.clone();
        m[..DOMAIN_TAG_V3.len()].copy_from_slice(DOMAIN_TAG_V3);
        assert!(matches!(decode_record(&m), Err(DecodeError::BadTagByte("event", _))));
    }
    // A later version is not guessed at.
    let mut v4 = v3.clone();
    v4[14] = b'4';
    assert_eq!(decode_record(&v4), Err(DecodeError::BadTag));
}

fn terminal_observed_fixture() -> Event {
    Event::TerminalObserved(stack_receipt::TerminalObserved {
        terminal: match terminal(completed()) {
            Event::Terminal(t) => t,
            other => panic!("{other:?}"),
        },
        observed: stack_receipt::Observed {
            exit: stack_receipt::ExitObserved::Exited { code: 0 },
            frame: stack_receipt::FrameStatus::Valid,
        },
    })
}

#[test]
fn an_unknown_last_stage_and_a_cut_or_extended_record_are_refused() {
    let v3 = canonical_bytes(&recovered_record(LastStage::Attempted)).unwrap();
    let n = v3.len();
    for bad in [0u8, 4, 99] {
        let mut m = v3.clone();
        m[n - 1] = bad;
        assert_eq!(decode_record(&m), Err(DecodeError::BadTagByte("recovered.last_stage", bad)));
    }
    assert!(matches!(decode_record(&v3[..n - 1]), Err(DecodeError::Truncated(_))));
    let mut longer = v3.clone();
    longer.push(0);
    assert!(matches!(decode_record(&longer), Err(DecodeError::TrailingBytes(_))));
}

#[test]
fn every_single_byte_flip_of_a_recovered_record_is_visible() {
    let r = recovered_record(LastStage::Attempted);
    let bytes = canonical_bytes(&r).unwrap();
    for i in 0..bytes.len() {
        for bit in 0..8 {
            let mut m = bytes.clone();
            m[i] ^= 1 << bit;
            if let Ok(other) = decode_record(&m) {
                assert_ne!(other, r, "byte {i} bit {bit}: flip not visible");
                assert_eq!(canonical_bytes(&other).unwrap(), m, "byte {i} bit {bit}: not canonical");
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Logs that cannot be listed
// ---------------------------------------------------------------------------

/// A log that appends but cannot list its records: the trait's default.
#[derive(Debug)]
struct WriteOnlyLog(MemoryReceiptLog);

impl ReceiptLog for WriteOnlyLog {
    fn kernel_id(&self) -> &str {
        self.0.kernel_id()
    }
    fn head(&self) -> Result<stack_receipt::Head, LogError> {
        self.0.head()
    }
    fn append(&mut self, record: &stack_receipt::SignedRecord) -> Result<(), LogError> {
        self.0.append(record)
    }
    fn is_durable(&self) -> bool {
        false
    }
}

#[test]
fn a_log_that_cannot_list_its_records_makes_recovery_fail_instead_of_skipping() {
    let rec = Recorder::new(
        Box::new(WriteOnlyLog(MemoryReceiptLog::new("kernel-1").unwrap())),
        fixture_signer("kernel-1"),
        provenance(),
        Box::new(ManualClock::new(T0)),
    )
    .unwrap();
    let err = rec.recover_open_executions().unwrap_err();
    assert!(matches!(err, stack_receipt::RecordError::Log(LogError::BadConfig(_))), "{err:?}");
}

#[test]
fn a_write_failure_during_recovery_is_reported_and_the_records_already_written_stay() {
    // Two open executions; the memory log lets exactly one Recovered record in.
    #[derive(Debug)]
    struct FailAfter {
        inner: MemoryReceiptLog,
        allowed: usize,
    }
    impl ReceiptLog for FailAfter {
        fn kernel_id(&self) -> &str {
            self.inner.kernel_id()
        }
        fn head(&self) -> Result<stack_receipt::Head, LogError> {
            self.inner.head()
        }
        fn append(&mut self, record: &stack_receipt::SignedRecord) -> Result<(), LogError> {
            if self.inner.records().len() >= self.allowed {
                return Err(LogError::Io {
                    op: "write record",
                    kind: std::io::ErrorKind::Other,
                    message: "disk full (simulated)".into(),
                });
            }
            self.inner.append(record)
        }
        fn is_durable(&self) -> bool {
            false
        }
        fn acknowledged_records(&self) -> Result<Vec<stack_receipt::SignedRecord>, LogError> {
            self.inner.acknowledged_records()
        }
    }
    let rec = Recorder::new(
        Box::new(FailAfter {
            inner: MemoryReceiptLog::new("kernel-1").unwrap(),
            allowed: 3,
        }),
        fixture_signer("kernel-1"),
        provenance(),
        Box::new(ManualClock::new(T0)),
    )
    .unwrap();
    let _a = rec.propose(id(3), proposed_body()).unwrap();
    let _b = rec.propose(id(4), proposed_body()).unwrap();
    // Three records fit: two Proposed and one Recovered. The second Recovered fails.
    let err = rec.recover_open_executions().unwrap_err();
    assert!(matches!(err, stack_receipt::RecordError::Log(LogError::Io { .. })), "{err:?}");
    assert_eq!(rec.head().unwrap().sequence, 3, "the first Recovered record was written");
}
