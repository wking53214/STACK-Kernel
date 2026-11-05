//! R-8 (G-6) for the receipt log (`FileReceiptLog`): the attempt record
//! written and the writer gone (in process and as a real process), a
//! duplicate frame, rollback with the external head, and two real
//! processes opening one log. Each scenario runs on the real file log.
//! A failing append mid-run is covered by
//! `recorder::a_failed_attempt_record_means_do_not_execute_and_leaves_the_execution_at_authorized`
//! and the admission test `execution.rs` (log failures at calls 2, 3, 4).
//!
//! Every key is a TEST FIXTURE (tests/common/mod.rs).

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::{Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant};

use common::*;
use stack_receipt::{
    parse_log, Expectations, FileReceiptLog, FindingCode, Head, LogError, ManualClock, OutcomeKind, ReceiptLog, Recorder,
    Stage, State,
};

/// One test at a time: a child spawned by one test holds a copy of every
/// descriptor open in the process between fork and exec, which keeps
/// another test's advisory lock alive briefly after its log is dropped.
fn serial() -> MutexGuard<'static, ()> {
    static SERIAL: Mutex<()> = Mutex::new(());
    SERIAL.lock().unwrap_or_else(PoisonError::into_inner)
}

fn temp(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("stack-receipt-r8-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir.join("receipts.log")
}

fn open(path: &Path) -> Result<FileReceiptLog, LogError> {
    FileReceiptLog::open(path, "kernel-1", &[fixture_public_key("kernel-1")])
}

fn verify(path: &Path) -> stack_receipt::LogVerification {
    stack_receipt::verify_log_bytes(&std::fs::read(path).unwrap(), &baseline_trust(), &Expectations::default())
}

/// Writes Proposed, Authorized and Attempted through a real recorder and
/// leaves the execution running (returns the open handle).
fn attempt(path: &Path) -> stack_receipt::Execution<stack_receipt::AttemptedStage> {
    let recorder = Recorder::new(
        Box::new(open(path).unwrap()),
        fixture_signer("kernel-1"),
        provenance(),
        Box::new(ManualClock::new(T0)),
    )
    .unwrap();
    let stack_receipt::Event::Proposed(p) = proposed() else { panic!() };
    let stack_receipt::Event::Authorized(a) = authorized() else { panic!() };
    let stack_receipt::Event::Attempted(at) = attempted() else { panic!() };
    let exec = recorder.propose(exec_id(), p).unwrap().authorize_with(a).unwrap();
    exec.attempt(at.action, at.started_at_ms).unwrap()
}

fn assert_incomplete_with_unknown_outcome(path: &Path) {
    let v = verify(path);
    assert_eq!(v.state, State::Incomplete, "{}", v.to_json());
    assert_eq!(v.executions.len(), 1);
    assert_eq!(v.executions[0].execution.outcome, Some(OutcomeKind::Unknown));
    assert_eq!(v.executions[0].execution.stage_reached, Some(Stage::Attempted));
    assert_eq!(v.executions[0].findings[0].code, FindingCode::TerminalMissing);
}

// ---------------------------------------------------------------------------
// Child processes
// ---------------------------------------------------------------------------

const ROLE: &str = "STACK_RECEIPT_R8_ROLE";
const DIR: &str = "STACK_RECEIPT_R8_DIR";
const ID: &str = "STACK_RECEIPT_R8_ID";

fn child_env() -> Option<(String, PathBuf, String)> {
    let role = std::env::var(ROLE).ok()?;
    Some((role, PathBuf::from(std::env::var(DIR).ok()?), std::env::var(ID).unwrap_or_default()))
}

fn spawn_child(test: &str, role: &str, dir: &Path, id: &str) -> std::process::Child {
    Command::new(std::env::current_exe().unwrap())
        .args(["--exact", test, "--test-threads=1", "--nocapture"])
        .env(ROLE, role)
        .env(DIR, dir)
        .env(ID, id)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap()
}

fn rendezvous(dir: &Path, id: &str) {
    std::fs::write(dir.join(format!("ready-{id}")), b"1").unwrap();
    let begun = Instant::now();
    while !(dir.join("ready-a").exists() && dir.join("ready-b").exists()) {
        assert!(begun.elapsed() < Duration::from_secs(30), "the other child never arrived");
        std::thread::sleep(Duration::from_millis(2));
    }
}

// ---------------------------------------------------------------------------
// (1) The attempt is written and the writer never closes it
// ---------------------------------------------------------------------------

#[test]
fn attempt_written_and_the_handle_dropped_is_incomplete_never_success() {
    let _serial = serial();
    let path = temp("dropped");
    drop(attempt(&path)); // the caller loses the handle without finishing
    assert_eq!(open(&path).unwrap().records(), 3);
    assert_incomplete_with_unknown_outcome(&path);
}

#[test]
fn attempt_written_and_the_process_aborts_is_incomplete_never_success() {
    let _serial = serial();
    const TEST: &str = "attempt_written_and_the_process_aborts_is_incomplete_never_success";
    if let Some((role, dir, _)) = child_env() {
        assert_eq!(role, "attempt_then_abort");
        let _running = attempt(&dir.join("receipts.log"));
        std::process::abort();
    }
    let path = temp("abort");
    let dir = path.parent().unwrap().to_path_buf();
    let status = spawn_child(TEST, "attempt_then_abort", &dir, "x").wait().unwrap();
    assert!(!status.success(), "the child must have died: {status}");
    assert_eq!(open(&path).unwrap().records(), 3);
    assert_incomplete_with_unknown_outcome(&path);
}

// ---------------------------------------------------------------------------
// (2) Duplicate record
// ---------------------------------------------------------------------------

fn honest_bytes(path: &Path) -> Vec<u8> {
    let mut log = open(path).unwrap();
    for s in sign_chain(honest_events()) {
        log.append(&s).unwrap();
    }
    drop(log);
    std::fs::read(path).unwrap()
}

/// Byte offsets of the end of the header and of each of the four honest
/// frames, from a reference log written the same way.
fn frame_offsets(tag: &str) -> Vec<usize> {
    let mut log = open(&temp(tag)).unwrap();
    let mut offsets = vec![usize::try_from(log.committed_len()).unwrap()];
    for s in &sign_chain(honest_events()) {
        log.append(s).unwrap();
        offsets.push(usize::try_from(log.committed_len()).unwrap());
    }
    offsets
}

#[test]
fn a_frame_appended_twice_byte_for_byte_fails_closed_on_open() {
    let _serial = serial();
    let path = temp("dup-append");
    let bytes = honest_bytes(&path);
    let offsets = frame_offsets("dup-ref");
    assert_eq!(offsets[4], bytes.len());
    let mut dup = bytes.clone();
    dup.extend_from_slice(&bytes[offsets[3]..offsets[4]]);
    std::fs::write(&path, &dup).unwrap();
    assert!(matches!(open(&path), Err(LogError::Corrupt { .. })), "{:?}", open(&path).err());
    assert!(matches!(parse_log(&dup), Err(LogError::Corrupt { .. })));
    // The intact file still opens with exactly the four records.
    std::fs::write(&path, &bytes).unwrap();
    assert_eq!(open(&path).unwrap().records(), 4);
}

#[test]
fn a_frame_inserted_twice_inside_the_committed_chain_fails_closed_on_open() {
    let _serial = serial();
    let path = temp("dup-insert");
    let bytes = honest_bytes(&path);
    let offsets = frame_offsets("dup-ref2");
    // Frames 0, 1, 1 again, 2, 3.
    let mut dup = bytes[..offsets[2]].to_vec();
    dup.extend_from_slice(&bytes[offsets[1]..offsets[2]]);
    dup.extend_from_slice(&bytes[offsets[2]..]);
    assert_ne!(dup, bytes);
    std::fs::write(&path, &dup).unwrap();
    assert!(open(&path).is_err());
    assert!(parse_log(&dup).is_err());
}

// ---------------------------------------------------------------------------
// (3) Rollback to a prior valid state
// ---------------------------------------------------------------------------

#[test]
fn rollback_to_an_earlier_state_reads_as_a_crash_and_is_detected_only_against_an_external_head() {
    let _serial = serial();
    let path = temp("rollback-r8");
    let chain = sign_chain(honest_events());
    let mut log = open(&path).unwrap();
    for s in &chain[..3] {
        log.append(s).unwrap();
    }
    drop(log);
    let backup = std::fs::read(&path).unwrap(); // taken while the execution was only Attempted
    let mut log = open(&path).unwrap();
    log.append(&chain[3]).unwrap(); // the terminal record
    let anchored: Head = log.head().unwrap(); // recorded elsewhere by the operator
    drop(log);
    assert_eq!(verify(&path).state, State::VerifiedWithLimitations);

    std::fs::write(&path, &backup).unwrap(); // the restore

    // NOT detected from the file: it opens, and the verifier cannot tell it
    // from a crash. The Completed outcome has been hidden, and the
    // verifier says INCOMPLETE and names the limitation.
    let log = open(&path).unwrap();
    assert_eq!(log.records(), 3);
    drop(log);
    let v = verify(&path);
    assert_eq!(v.state, State::Incomplete, "{}", v.to_json());
    assert!(
        v.scope.not_checked.iter().any(|l| l.as_str() == "log_rollback_not_detectable_without_anchor"),
        "{}",
        v.to_json()
    );
    // Detected against the external head: the reopened log is behind it.
    let reopened = open(&path).unwrap();
    let head = reopened.head().unwrap();
    assert_ne!(head, anchored);
    assert!(head.sequence < anchored.sequence, "behind the anchor: {} < {}", head.sequence, anchored.sequence);
}

// ---------------------------------------------------------------------------
// (4) Storage unavailable
// ---------------------------------------------------------------------------

#[test]
fn real_unavailable_storage_at_open_fails_closed() {
    let _serial = serial();
    let path = temp("unavailable");
    let dir = path.parent().unwrap();
    assert!(matches!(open(dir), Err(LogError::Io { .. })), "a directory is not a log");
    assert!(matches!(open(&dir.join("gone/receipts.log")), Err(LogError::Io { .. })));
}

// ---------------------------------------------------------------------------
// (5) Two real processes, one log
// ---------------------------------------------------------------------------

#[test]
fn two_processes_open_one_log_exactly_one_holds_it() {
    let _serial = serial();
    const TEST: &str = "two_processes_open_one_log_exactly_one_holds_it";
    if let Some((role, dir, id)) = child_env() {
        assert_eq!(role, "race");
        rendezvous(&dir, &id);
        let word = match open(&dir.join("receipts.log")) {
            Err(LogError::Locked { .. }) => "locked".to_owned(),
            Err(e) => format!("other:{e:?}"),
            Ok(mut log) => {
                // Append the first record of the fixture chain, then hold the log.
                log.append(&sign_chain(honest_events())[0]).unwrap();
                std::thread::sleep(Duration::from_millis(1500));
                "opened".to_owned()
            }
        };
        std::fs::write(dir.join(format!("result-{id}")), word).unwrap();
        return;
    }
    let path = temp("race2");
    let dir = path.parent().unwrap().to_path_buf();
    let mut a = spawn_child(TEST, "race", &dir, "a");
    let mut b = spawn_child(TEST, "race", &dir, "b");
    assert!(a.wait().unwrap().success());
    assert!(b.wait().unwrap().success());
    let mut words: Vec<String> = ["a", "b"]
        .iter()
        .map(|id| std::fs::read_to_string(dir.join(format!("result-{id}"))).unwrap())
        .collect();
    words.sort();
    assert_eq!(words, ["locked", "opened"], "exactly one process may hold the log");
    let log = open(&path).unwrap();
    assert!(log.records() >= 1);
    drop(log);
    assert!(parse_log(&std::fs::read(&path).unwrap()).is_ok());
}
