//! Adversarial execution: deadlines, a kernel that dies mid-run, and every
//! way a request can be presented twice. Each test asserts the observable
//! result AND, for refusals, that no worker ran (the executor run count).
//!
//! Every key is a TEST FIXTURE (tests/common/mod.rs).

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use std::path::PathBuf;
use std::time::{Duration, Instant};

use common::*;
use stack_admission::{AdmissionResult, BuildError, ExecutionLimits, RefusalReason, Stage};
use stack_authority::AuthzError;
use stack_receipt::{FindingCode, OutcomeKind, State};
use stack_trident::{ReasonCode, StartError, StoreError};

/// Slack over the deadline for a killed worker: the kill, the reap and the
/// scheduler. Stated here, asserted below, and the measured value is printed.
const SLACK: Duration = Duration::from_secs(2);

fn policy_with_deadline(ns: u64) -> stack_admission::KernelPolicy {
    let mut p = policy();
    p.limits = ExecutionLimits::with_deadline_ns(ns);
    p
}

// ---------------------------------------------------------------------------
// Deadlines
// ---------------------------------------------------------------------------

#[test]
fn an_execution_timeout_is_a_timed_out_receipt_and_not_success() {
    let dir = TempDir::new("timeout");
    let h = Builder::new(dir.path()).start();
    let case = all_pass();
    let r = h.process(honest_payload(&case, "block"));
    let AdmissionResult::Unsuccessful(u) = &r else {
        panic!("expected Unsuccessful, got {r:?}");
    };
    assert!(!r.is_success());
    assert_eq!(u.outcome.kind(), OutcomeKind::TimedOut);
    assert!(u.elapsed_ns >= DEADLINE_NS, "killed early: {}", u.elapsed_ns);
    assert_eq!(h.runs(), 1);
    let v = h.verify_full(&case, None);
    // The receipt is honest: it verifies, and says the run timed out.
    assert_eq!(v.state, State::VerifiedWithLimitations, "{}", v.to_json());
    assert_eq!(v.executions[0].execution.outcome, Some(OutcomeKind::TimedOut));
    assert_ne!(v.executions[0].execution.outcome, Some(OutcomeKind::Completed));
}

#[test]
fn a_non_returning_payload_is_terminated_within_a_measured_bound() {
    let dir = TempDir::new("bound");
    let h = Builder::new(dir.path()).start();
    let case = all_pass();
    let deadline = Duration::from_nanos(DEADLINE_NS);
    let mut worst = Duration::ZERO;
    for (op, label) in [("spin", "SpinForever"), ("block", "BlockForever")] {
        for round in 0..3 {
            let started = Instant::now();
            let r = h.process(honest_payload(&case, op));
            let wall = started.elapsed();
            let AdmissionResult::Unsuccessful(u) = &r else {
                panic!("{label}: expected Unsuccessful, got {r:?}");
            };
            assert_eq!(u.outcome.kind(), OutcomeKind::TimedOut, "{label}");
            let supervisor = Duration::from_nanos(u.elapsed_ns);
            println!(
                "measured: {label} round {round}: supervisor {:?}, whole pipeline {:?} (deadline {:?}, slack {:?})",
                supervisor, wall, deadline, SLACK
            );
            assert!(supervisor >= deadline, "{label}: killed before the deadline: {supervisor:?}");
            assert!(supervisor < deadline + SLACK, "{label}: supervisor took {supervisor:?}");
            assert!(wall < deadline + SLACK, "{label}: the pipeline took {wall:?}");
            worst = worst.max(wall);
        }
    }
    println!("measured: worst whole-pipeline time for a non-returning payload: {worst:?} (bound {:?})", deadline + SLACK);
    // Six receipts, all TimedOut, all verifying.
    let v = h.verify_full(&case, None);
    assert_eq!(v.state, State::VerifiedWithLimitations, "{}", v.to_json());
    assert_eq!(v.executions.len(), 6);
    assert!(v.executions.iter().all(|e| e.execution.outcome == Some(OutcomeKind::TimedOut)));
    assert_eq!(h.runs(), 6);
}

// ---------------------------------------------------------------------------
// The kernel dies during execution
// ---------------------------------------------------------------------------

const CHILD_ENV: &str = "STACK_ADMISSION_RESTART_CHILD_DIR";
const RESTART_TEST: &str = "a_kernel_killed_during_execution_leaves_an_incomplete_unknown_execution";

/// `(pid, ppid, state)` of every process, from /proc.
fn process_table() -> Vec<(u32, u32, char)> {
    let mut out = Vec::new();
    let Ok(entries) = std::fs::read_dir("/proc") else {
        return out;
    };
    for entry in entries.flatten() {
        let Some(pid) = entry.file_name().to_str().and_then(|n| n.parse::<u32>().ok()) else {
            continue;
        };
        let Ok(stat) = std::fs::read_to_string(entry.path().join("stat")) else {
            continue;
        };
        // "pid (comm) state ppid ...": comm may hold spaces and parens.
        let Some(rest) = stat.rsplit_once(')').map(|(_, r)| r) else {
            continue;
        };
        let f: Vec<&str> = rest.split_whitespace().collect();
        let (Some(state), Some(ppid)) = (
            f.first().and_then(|s| s.chars().next()),
            f.get(1).and_then(|s| s.parse::<u32>().ok()),
        ) else {
            continue;
        };
        out.push((pid, ppid, state));
    }
    out
}

/// Live (not zombie) direct children of `pid`.
fn children_of(pid: u32) -> Vec<u32> {
    process_table().into_iter().filter(|&(_, ppid, st)| ppid == pid && st != 'Z').map(|(p, _, _)| p).collect()
}

/// Whether `pid` is a live, non-zombie process.
fn alive(pid: u32) -> bool {
    process_table().into_iter().any(|(p, _, st)| p == pid && st != 'Z')
}

/// Kills the kernel under test and every worker it started when dropped,
/// so a failing assertion cannot leave a blocked worker behind. A worker
/// is its own process group leader (the supervisor makes it one), so the
/// kernel's group does not reach it: the worker pids are tracked.
struct Cleanup {
    kernel: u32,
    workers: std::sync::Mutex<Vec<u32>>,
}

impl Cleanup {
    fn kill_all(&self) {
        let mut pids = vec![self.kernel];
        if let Ok(w) = self.workers.lock() {
            pids.extend(w.iter().copied());
        }
        pids.extend(children_of(self.kernel));
        for pid in pids {
            let _ = std::process::Command::new("kill")
                .args(["-KILL", &pid.to_string()])
                .stderr(std::process::Stdio::null())
                .status();
        }
    }
}

impl Drop for Cleanup {
    fn drop(&mut self) {
        self.kill_all();
    }
}

fn attempted_in(path: &std::path::Path) -> bool {
    std::fs::read(path)
        .ok()
        .and_then(|b| stack_receipt::parse_log(&b).ok())
        .is_some_and(|p| p.records.iter().any(|r| r.record().stage() == stack_receipt::Stage::Attempted))
}

#[test]
fn a_kernel_killed_during_execution_leaves_an_incomplete_unknown_execution() {
    if let Some(dir) = std::env::var_os(CHILD_ENV) {
        // The kernel under test: a child copy of this test binary. It admits
        // a request whose worker blocks for two minutes and is SIGKILLed
        // by the parent while the worker runs.
        let dir = PathBuf::from(dir);
        let h = Builder::new(&dir).policy(policy_with_deadline(120_000_000_000)).start();
        let _ = h.process(honest_payload(&all_pass(), "block"));
        std::process::exit(17); // the parent did not kill this kernel
    }

    use std::os::unix::process::CommandExt;
    let dir = TempDir::new("restart");
    let exe = std::env::current_exe().unwrap();
    let mut child = std::process::Command::new(exe)
        .args(["--exact", RESTART_TEST, "--test-threads=1", "--nocapture"])
        .env(CHILD_ENV, dir.path())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .process_group(0)
        .spawn()
        .unwrap();
    let kernel = child.id();
    let cleanup = Cleanup {
        kernel,
        workers: std::sync::Mutex::new(Vec::new()),
    };

    // Wait until the attempt is durable AND a worker process exists below
    // the kernel: the kernel is mid-execution.
    let receipts = receipts_path(dir.path());
    let give_up = Instant::now() + Duration::from_secs(120);
    let workers = loop {
        if let Some(status) = child.try_wait().unwrap() {
            panic!("the kernel exited before it was killed: {status}");
        }
        let workers = children_of(kernel);
        if attempted_in(&receipts) && !workers.is_empty() {
            break workers;
        }
        assert!(Instant::now() < give_up, "the kernel never reached execution");
        std::thread::sleep(Duration::from_millis(20));
    };
    *cleanup.workers.lock().unwrap() = workers.clone();
    std::thread::sleep(Duration::from_millis(300)); // genuinely mid-run
    child.kill().unwrap(); // SIGKILL
    let status = child.wait().unwrap();
    assert!(!status.success());

    // The worker must not outlive its killed supervisor: the C++ executor
    // sets PR_SET_PDEATHSIG = SIGKILL in the child (stack_supervised_exec.hpp).
    // Polled, because the signal is delivered by the kernel after the
    // supervisor's exit.
    let t = Instant::now();
    let limit = t + Duration::from_secs(5);
    while workers.iter().any(|&w| alive(w)) && Instant::now() < limit {
        std::thread::sleep(Duration::from_millis(10));
    }
    let survivors = workers.iter().filter(|&&w| alive(w)).count();
    println!("measured: worker gone {:?} after the kernel was SIGKILLed (survivors: {survivors} of {})", t.elapsed(), workers.len());
    cleanup.kill_all();
    assert_eq!(survivors, 0, "a blocked worker outlived its killed supervisor");

    // A restarted kernel reopens the log. The execution that was running
    // has an attempt and no terminal event: INCOMPLETE, outcome unknown,
    // never success.
    let case = all_pass();
    let v = verify_bytes_full(&std::fs::read(&receipts).unwrap(), &case, None);
    assert_eq!(v.state, State::Incomplete, "{}", v.to_json());
    assert_eq!(v.executions.len(), 1);
    let e = &v.executions[0];
    assert_eq!(e.execution.stage_reached, Some(stack_receipt::Stage::Attempted));
    assert_eq!(e.execution.outcome, Some(OutcomeKind::Unknown));
    assert!(e.findings.iter().any(|f| f.code == FindingCode::TerminalMissing), "{}", e.to_json());
    assert_eq!(e.execution.sequences, vec![1, 2, 3]);

    // The restarted kernel works, refuses the dead kernel's envelope as a
    // replay, and does not rewrite history: the old execution stays open.
    let h = Builder::restarting(dir.path(), started_now()).start_after_release();
    h.set_next_seq(2);
    // (The dead kernel's envelope is sequence 1; present sequence 1 again.)
    let old = h.envelope_for_seq(honest_payload(&case, "echo"), 1);
    match h.admission.process(&old) {
        AdmissionResult::Refused(r) => {
            assert_eq!(r.stage, Stage::Handoff);
            assert!(matches!(&r.reason, RefusalReason::Handoff(f) if f.has(ReasonCode::Replay) || f.has(ReasonCode::SequenceNotIncreasing)), "{r:?}");
        }
        other => panic!("{other:?}"),
    }
    assert_eq!(h.runs(), 0);
    let fresh = h.process(honest_payload(&case, "echo"));
    assert!(fresh.is_success(), "{fresh:?}");
    let v = h.verify_full(&case, None);
    assert_eq!(v.state, State::Incomplete, "the log is as incomplete as its worst execution: {}", v.to_json());
    assert_eq!(v.executions.len(), 2);
    assert_eq!(v.executions[0].execution.outcome, Some(OutcomeKind::Unknown));
    assert_eq!(v.executions[1].execution.outcome, Some(OutcomeKind::Completed));
    drop(cleanup);
}

// ---------------------------------------------------------------------------
// Replay, every way the same authority can be presented twice
// ---------------------------------------------------------------------------

#[test]
fn an_accepted_envelope_replayed_is_refused_and_does_not_run_again() {
    let dir = TempDir::new("replay-envelope");
    let h = Builder::new(dir.path()).start();
    let case = all_pass();
    let bytes = h.envelope(honest_payload(&case, "echo"));
    assert!(h.admission.process(&bytes).is_success());
    assert_eq!(h.runs(), 1);
    let again = h.admission.process(&bytes);
    let AdmissionResult::Refused(r) = &again else {
        panic!("expected a refusal, got {again:?}");
    };
    assert_eq!(r.stage, Stage::Handoff);
    assert!(matches!(&r.reason, RefusalReason::Handoff(f) if f.has(ReasonCode::Replay)), "{r:?}");
    assert_eq!(h.runs(), 1, "the replay ran nothing");
    assert_eq!(h.verify_full(&case, None).executions.len(), 1, "and left no execution record");
}

#[test]
fn an_accepted_envelope_replayed_after_a_restart_is_refused() {
    let dir = TempDir::new("replay-restart");
    let case = all_pass();
    let (bytes, cap) = {
        let h = Builder::new(dir.path()).start();
        let cap = CapSpec::for_case(&case, "echo", RESOURCE).issue();
        let bytes = h.envelope(payload_with(&case, &cap, "echo", RESOURCE));
        assert!(h.admission.process(&bytes).is_success());
        (bytes, cap)
    }; // the kernel is dropped: locks released, files closed
    let h = Builder::restarting(dir.path(), started_now()).start_after_release();
    let again = h.admission.process(&bytes);
    let AdmissionResult::Refused(r) = &again else {
        panic!("expected a refusal, got {again:?}");
    };
    assert_eq!(r.stage, Stage::Handoff);
    assert!(matches!(&r.reason, RefusalReason::Handoff(f) if f.has(ReasonCode::Replay)), "{r:?}");
    assert_eq!(h.runs(), 0);

    // The same one-time capability in a FRESH envelope after the restart:
    // the use store is durable too.
    h.set_next_seq(2);
    let fresh = h.process(payload_with(&case, &cap, "echo", RESOURCE));
    let AdmissionResult::Refused(r) = &fresh else {
        panic!("expected a refusal, got {fresh:?}");
    };
    assert_eq!(r.stage, Stage::Authorization);
    assert_eq!(r.reason, RefusalReason::Authorization(AuthzError::Replay));
    assert_eq!(h.runs(), 0);
    // Both executions' history is in one verified chain: one success, one
    // rejection.
    let v = h.verify_full(&case, None);
    assert_eq!(v.state, State::VerifiedWithLimitations, "{}", v.to_json());
    assert_eq!(v.executions.len(), 2);
}

#[test]
fn a_one_time_capability_presented_again_in_a_fresh_envelope_is_refused_after_it_ran() {
    let dir = TempDir::new("replay-capability");
    let h = Builder::new(dir.path()).start();
    let case = all_pass();
    let cap = CapSpec::for_case(&case, "echo", RESOURCE).issue();
    assert!(h.process(payload_with(&case, &cap, "echo", RESOURCE)).is_success());
    let again = h.process(payload_with(&case, &cap, "echo", RESOURCE));
    let AdmissionResult::Refused(r) = &again else {
        panic!("expected a refusal, got {again:?}");
    };
    assert_eq!(r.reason, RefusalReason::Authorization(AuthzError::Replay));
    assert_eq!(h.runs(), 1);
}

#[test]
fn a_second_verifier_on_the_same_stores_cannot_start_it_is_locked_not_reconciled() {
    // Design: every durable store takes an exclusive advisory lock, so two
    // kernels sharing one store do not race, the second one does not start.
    // This is "locked", not "conflict resolved": a shared store reachable
    // from two hosts needs a check-and-commit trait that does not exist
    // here (multi-host is BLOCKED, see the README).
    let first_dir = TempDir::new("locked-first");
    let second_dir = TempDir::new("locked-second");
    let first = Builder::new(first_dir.path()).start();

    // Same replay store, everything else distinct.
    let r = Builder::new(second_dir.path()).replay_file(replay_path(first_dir.path())).build();
    match r {
        Err(BuildError::Trident(StartError::Store(StoreError::Locked { .. }))) => {}
        other => panic!("a second verifier on the replay store must be locked out: {other:?}"),
    }
    // Same use store: it cannot be opened while the first kernel holds it
    // (UseError::Unavailable also covers other failures; the takeover
    // below shows the lock is the cause).
    assert!(stack_authority::FileUseStore::open(uses_path(first_dir.path()), 1024).is_err());
    // Same receipt log: the log's lock.
    let r = Builder::new(first_dir.path()).build();
    assert!(r.is_err(), "a second writer on one receipt log must not start");

    // The first kernel is unaffected, and once it is gone the second can
    // take over, and then it refuses the first one's envelope.
    let case = all_pass();
    let bytes = first.envelope(honest_payload(&case, "echo"));
    assert!(first.admission.process(&bytes).is_success());
    drop(first);
    let takeover = Builder::restarting(first_dir.path(), started_now()).start_after_release();
    assert!(!takeover.admission.process(&bytes).is_success());
    assert_eq!(takeover.runs(), 0);
}

#[test]
fn concurrent_presentations_of_one_envelope_or_one_capability_execute_once() {
    let dir = TempDir::new("concurrent");
    let h = Builder::new(dir.path()).start();
    let case = all_pass();

    // One envelope, eight threads.
    let bytes = h.envelope(honest_payload(&case, "echo"));
    let results: Vec<AdmissionResult> =
        std::thread::scope(|s| (0..8).map(|_| s.spawn(|| h.admission.process(&bytes))).collect::<Vec<_>>().into_iter().map(|t| t.join().unwrap()).collect());
    let ok = results.iter().filter(|r| r.is_success()).count();
    assert_eq!(ok, 1, "{results:?}");
    assert_eq!(h.runs(), 1);

    // One capability in eight different fresh envelopes. The Trident's
    // strictly increasing sender sequence already refuses most of them
    // depending on arrival order; the property asserted is the safety one:
    // exactly one execution, however the threads interleave.
    let cap = CapSpec::for_case(&case, "echo", RESOURCE).issue();
    let envelopes: Vec<Vec<u8>> = (0..8).map(|_| h.envelope(payload_with(&case, &cap, "echo", RESOURCE))).collect();
    let results: Vec<AdmissionResult> = std::thread::scope(|s| {
        envelopes
            .iter()
            .map(|e| s.spawn(|| h.admission.process(e)))
            .collect::<Vec<_>>()
            .into_iter()
            .map(|t| t.join().unwrap())
            .collect()
    });
    let ok = results.iter().filter(|r| r.is_success()).count();
    assert_eq!(ok, 1, "{results:?}");
    assert_eq!(h.runs(), 2);
    let v = h.verify_full(&case, None);
    assert!(
        matches!(v.state, State::VerifiedWithLimitations),
        "concurrent refusals and runs interleave but the chain verifies: {}",
        v.to_json()
    );
}
