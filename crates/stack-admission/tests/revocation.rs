//! R-5: a signed capability revoked after it was authorized. The re-check
//! immediately before spawn, and the request to stop a run in flight.
//!
//! Every key is a TEST FIXTURE (tests/common/mod.rs). Claims about the
//! receipt are made by `stack_receipt::verify_log_bytes` with fresh trusted
//! keys. The executor here is a test double: it counts runs, blocks until
//! released or cancelled, and honours the cancel token the way a real
//! executor must. None of these tests claim anything about `SupervisedExecutor`;
//! the real worker is stopped and tested in `revocation_real_worker.rs`.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, OnceLock, Weak};
use std::time::{Duration, Instant};

use common::*;
use stack_admission::admission::{CancelToken, CancellableExecutor};
use stack_admission::{
    Admission, AdmissionResult, Executor, ExecutorError, ExecutionLimits, RunOutcome, RunReport, WorkerKind,
    RETURN_BYTES_RESULT,
};
use stack_receipt::{
    Expectations, FileReceiptLog, LogError, LogVerification, OutcomeKind, ReceiptLog, SignedRecord, Stage as ReceiptStage,
};

// ---------------------------------------------------------------------------
// Test doubles
// ---------------------------------------------------------------------------

/// Counts runs, signals when a run starts, and holds each run until it is
/// released or cancelled.
#[derive(Debug, Default)]
struct HeldExecutor {
    runs: AtomicUsize,
    cancelled_runs: AtomicUsize,
    state: Mutex<HeldState>,
}

#[derive(Debug, Default)]
struct HeldState {
    released: bool,
}

impl HeldExecutor {
    fn runs(&self) -> usize {
        self.runs.load(Ordering::SeqCst)
    }
    fn release(&self) {
        self.state.lock().unwrap().released = true;
    }
    fn wait_for_runs(&self, n: usize) {
        let begun = Instant::now();
        while self.runs() < n {
            assert!(begun.elapsed() < Duration::from_secs(10), "executor never reached {n} runs");
            std::thread::sleep(Duration::from_millis(2));
        }
    }
}

/// The shared handle the kernel owns while the test keeps the other end.
#[derive(Debug)]
struct Shared(Arc<HeldExecutor>);

fn completed() -> RunReport {
    RunReport {
        outcome: RunOutcome::Completed {
            exit_code: 0,
            result: RETURN_BYTES_RESULT.to_vec(),
        },
        elapsed_ns: 1,
        deadline_fired: false,
    }
}

impl Executor for Shared {
    fn run(&self, _: WorkerKind, _: &ExecutionLimits, _: &[u8]) -> Result<RunReport, ExecutorError> {
        self.0.runs.fetch_add(1, Ordering::SeqCst);
        Ok(completed())
    }
}

impl CancellableExecutor for Shared {
    fn run_cancellable(
        &self,
        _: WorkerKind,
        _: &ExecutionLimits,
        _: &[u8],
        cancel: &CancelToken,
    ) -> Result<RunReport, ExecutorError> {
        let this = &self.0;
        this.runs.fetch_add(1, Ordering::SeqCst);
        let begun = Instant::now();
        loop {
            if cancel.is_cancelled() {
                this.cancelled_runs.fetch_add(1, Ordering::SeqCst);
                return Ok(RunReport {
                    outcome: RunOutcome::Terminated { signal: 15 },
                    elapsed_ns: 1,
                    deadline_fired: false,
                });
            }
            if this.state.lock().unwrap().released {
                return Ok(completed());
            }
            if begun.elapsed() > Duration::from_secs(20) {
                return Err(ExecutorError::Call("test executor timed out".into()));
            }
            cancel.wait_cancelled(Duration::from_millis(2));
        }
    }
}

/// A durable log that, right after the `call`-th append reached the file
/// (1 proposed, 2 authorized, 3 attempted), runs `then`: the moment
/// between the write-ahead attempt record and the spawn.
struct HookedLog {
    inner: FileReceiptLog,
    call: usize,
    calls: usize,
    then: Box<dyn Fn() + Send>,
}

impl std::fmt::Debug for HookedLog {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("HookedLog")
    }
}

impl HookedLog {
    fn open(dir: &Path, call: usize, then: impl Fn() + Send + 'static) -> Self {
        Self {
            inner: FileReceiptLog::open(receipts_path(dir), KERNEL, &[receipt_public_key(KERNEL)]).unwrap(),
            call,
            calls: 0,
            then: Box::new(then),
        }
    }
}

impl ReceiptLog for HookedLog {
    fn kernel_id(&self) -> &str {
        self.inner.kernel_id()
    }
    fn head(&self) -> Result<stack_receipt::Head, LogError> {
        self.inner.head()
    }
    fn append(&mut self, record: &SignedRecord) -> Result<(), LogError> {
        self.calls += 1;
        self.inner.append(record)?;
        if self.calls == self.call {
            (self.then)();
        }
        Ok(())
    }
    fn is_durable(&self) -> bool {
        self.inner.is_durable()
    }
    fn acknowledged_records(&self) -> Result<Vec<SignedRecord>, LogError> {
        self.inner.acknowledged_records()
    }
}

type Hook = Box<dyn Fn(&Admission) + Send>;

/// A kernel plus the envelopes (and their capability ids) to feed it.
struct Rig {
    admission: Arc<Admission>,
    dir: PathBuf,
    envelopes: Vec<Vec<u8>>,
    cap_ids: Vec<String>,
}

/// Builds a kernel running `exec` through the cancellable seam, with
/// `requests` honest, distinct, one-time requests ready. When `at_attempt`
/// is given the receipt log runs it right after the attempt record is
/// durable, handing it the admission.
fn rig(dir: &Path, exec: &Arc<HeldExecutor>, requests: usize, at_attempt: Option<Hook>) -> Rig {
    let slot: Arc<OnceLock<Weak<Admission>>> = Arc::new(OnceLock::new());
    let mut builder = Builder::new(dir).executor(Box::new(Shared(Arc::clone(exec))));
    if let Some(f) = at_attempt {
        let slot = Arc::clone(&slot);
        builder = builder.receipt_log(Box::new(HookedLog::open(dir, 3, move || {
            if let Some(a) = slot.get().and_then(Weak::upgrade) {
                f(&a);
            }
        })));
    }
    let h = builder.start();
    let case = all_pass();
    let mut envelopes = Vec::new();
    let mut cap_ids = Vec::new();
    for _ in 0..requests {
        let spec = CapSpec::for_case(&case, "echo", RESOURCE);
        cap_ids.push(spec.cap_id.clone());
        envelopes.push(h.envelope(payload_with(&case, &spec.issue(), "echo", RESOURCE)));
    }
    let admission = Arc::new(h.admission.with_cancellable_executor(Box::new(Shared(Arc::clone(exec)))));
    slot.set(Arc::downgrade(&admission)).unwrap();
    Rig {
        admission,
        dir: h.dir,
        envelopes,
        cap_ids,
    }
}

impl Rig {
    fn verify(&self) -> LogVerification {
        let exp = Expectations {
            kernel_id: Some(KERNEL),
            audience: Some(KERNEL),
            ..Expectations::default()
        };
        stack_receipt::verify_log_bytes(&std::fs::read(receipts_path(&self.dir)).unwrap(), &receipt_trust(), &exp)
    }

    /// The outcome and stage the independent verifier reads for the one
    /// execution in the log.
    fn the_execution(&self, id: stack_receipt::ExecutionId) -> (Option<ReceiptStage>, Option<OutcomeKind>) {
        let v = self.verify();
        let e = v
            .executions
            .iter()
            .find(|e| e.execution.execution_id == id)
            .unwrap_or_else(|| panic!("execution {id} not in the log: {}", v.to_json()));
        (e.execution.stage_reached, e.execution.outcome)
    }

    fn process_in_thread(&self, n: usize) -> std::thread::JoinHandle<AdmissionResult> {
        let (a, env) = (Arc::clone(&self.admission), self.envelopes[n].clone());
        std::thread::spawn(move || a.process(&env))
    }
}

fn revoke_id(a: &Admission, id: &str) {
    a.authority().with_revocations(|r| r.revoke_id(id).unwrap()).unwrap();
}

fn unsuccessful(r: AdmissionResult) -> stack_admission::Unsuccessful {
    match r {
        AdmissionResult::Unsuccessful(u) => u,
        other => panic!("expected an unsuccessful run, got {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// (a) between authorize and spawn
// ---------------------------------------------------------------------------

#[test]
fn revoked_between_authorize_and_spawn_never_runs_and_the_receipt_is_non_success() {
    let dir = TempDir::new("rev-prespawn");
    let exec = Arc::new(HeldExecutor::default());
    let ids: Arc<Mutex<Option<String>>> = Arc::new(Mutex::new(None));
    let ids2 = Arc::clone(&ids);
    let r = rig(
        dir.path(),
        &exec,
        1,
        Some(Box::new(move |a| {
            // The attempt record is on disk; the worker has not been spawned.
            let id = ids2.lock().unwrap().clone().unwrap();
            revoke_id(a, &id);
        })),
    );
    *ids.lock().unwrap() = Some(r.cap_ids[0].clone());

    let u = unsuccessful(r.admission.process(&r.envelopes[0]));
    assert_eq!(exec.runs(), 0, "the executor must not be asked to run");
    assert!(
        matches!(&u.outcome, stack_receipt::Outcome::Interrupted { reason } if reason.contains("before spawn")),
        "{:?}",
        u.outcome
    );
    let (stage, outcome) = r.the_execution(u.execution_id);
    assert_eq!(stage, Some(ReceiptStage::Terminal), "attempted is closed by a terminal");
    assert_eq!(outcome, Some(OutcomeKind::Interrupted));
    assert_eq!(r.admission.in_flight(), 0);
}

#[test]
fn issuer_key_revoked_between_authorize_and_spawn_never_runs() {
    let dir = TempDir::new("rev-prespawn-key");
    let exec = Arc::new(HeldExecutor::default());
    let r = rig(
        dir.path(),
        &exec,
        1,
        Some(Box::new(|a| {
            let id = issuer_public_key(ISSUER).key_id();
            a.authority().with_trust(|t| assert!(t.revoke(&id))).unwrap();
        })),
    );
    let u = unsuccessful(r.admission.process(&r.envelopes[0]));
    assert_eq!(exec.runs(), 0);
    assert_eq!(r.the_execution(u.execution_id).1, Some(OutcomeKind::Interrupted));
}

#[test]
fn revocation_list_poisoned_between_authorize_and_spawn_fails_closed() {
    let dir = TempDir::new("rev-prespawn-poison");
    let exec = Arc::new(HeldExecutor::default());
    let r = rig(
        dir.path(),
        &exec,
        1,
        Some(Box::new(poison_revocations)),
    );
    let u = unsuccessful(r.admission.process(&r.envelopes[0]));
    assert_eq!(exec.runs(), 0, "an unreadable revocation list is not a pass");
    assert_eq!(r.the_execution(u.execution_id).1, Some(OutcomeKind::Interrupted));
}

#[test]
fn revocation_list_poisoned_before_authorize_refuses_at_authorization() {
    let dir = TempDir::new("rev-poison-early");
    let exec = Arc::new(HeldExecutor::default());
    let r = rig(dir.path(), &exec, 1, None);
    poison_revocations(&r.admission);
    match r.admission.process(&r.envelopes[0]) {
        AdmissionResult::Refused(f) => {
            assert_eq!(f.stage, stack_admission::Stage::Authorization);
            assert_eq!(
                f.reason,
                stack_admission::RefusalReason::Authorization(stack_authority::AuthzError::TrustUnavailable)
            );
        }
        other => panic!("expected a refusal, got {other:?}"),
    }
    assert_eq!(exec.runs(), 0);
}

fn poison_revocations(a: &Admission) {
    // A panic inside the closure poisons the lock, as a crashed writer would.
    let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _ = a.authority().with_revocations(|_| panic!("poison the revocation list"));
    }));
    assert!(r.is_err());
}

// ---------------------------------------------------------------------------
// (b) while running
// ---------------------------------------------------------------------------

#[test]
fn revoked_while_running_requests_termination_and_the_run_is_non_success() {
    let dir = TempDir::new("rev-running");
    let exec = Arc::new(HeldExecutor::default());
    let r = rig(dir.path(), &exec, 1, None);
    let run = r.process_in_thread(0);
    exec.wait_for_runs(1);
    assert_eq!(r.admission.in_flight(), 1);
    assert_eq!(r.admission.authority().revocation_epoch(), 0);

    revoke_id(&r.admission, &r.cap_ids[0]);
    assert_eq!(r.admission.authority().revocation_epoch(), 1);

    let u = unsuccessful(run.join().unwrap());
    assert_eq!(u.outcome, stack_receipt::Outcome::Terminated { signal: 15 });
    assert_eq!(exec.cancelled_runs.load(Ordering::SeqCst), 1);
    assert_eq!(r.the_execution(u.execution_id), (Some(ReceiptStage::Terminal), Some(OutcomeKind::Terminated)));
    assert_eq!(r.admission.in_flight(), 0);
}

#[test]
fn issuer_key_revoked_while_running_requests_termination() {
    let dir = TempDir::new("rev-running-key");
    let exec = Arc::new(HeldExecutor::default());
    let r = rig(dir.path(), &exec, 1, None);
    let run = r.process_in_thread(0);
    exec.wait_for_runs(1);
    let id = issuer_public_key(ISSUER).key_id();
    r.admission.authority().with_trust(|t| assert!(t.revoke(&id))).unwrap();
    let u = unsuccessful(run.join().unwrap());
    assert!(matches!(u.outcome, stack_receipt::Outcome::Terminated { .. }));
}

#[test]
fn only_the_affected_capability_is_stopped_an_unrelated_run_completes() {
    let dir = TempDir::new("rev-unrelated");
    let exec = Arc::new(HeldExecutor::default());
    let r = rig(dir.path(), &exec, 2, None);
    // Started in sender-sequence order: the Trident refuses an older sequence.
    let victim = r.process_in_thread(0);
    exec.wait_for_runs(1);
    let bystander = r.process_in_thread(1);
    exec.wait_for_runs(2);
    assert_eq!(r.admission.in_flight(), 2);

    // An id nobody holds: nothing may stop.
    revoke_id(&r.admission, "cap-nobody-holds");
    std::thread::sleep(Duration::from_millis(50));
    assert_eq!(exec.cancelled_runs.load(Ordering::SeqCst), 0);

    revoke_id(&r.admission, &r.cap_ids[0]);
    let u = unsuccessful(victim.join().unwrap());
    assert!(matches!(u.outcome, stack_receipt::Outcome::Terminated { .. }));

    // The other run is still held, and it finishes normally when released.
    assert_eq!(r.admission.in_flight(), 1);
    exec.release();
    match bystander.join().unwrap() {
        AdmissionResult::Success(s) => assert_eq!(s.exit_code, 0),
        other => panic!("the unrelated run must complete, got {other:?}"),
    }
    assert_eq!(exec.cancelled_runs.load(Ordering::SeqCst), 1);
}

#[test]
fn an_unreadable_revocation_list_while_running_stops_the_run_on_enforce() {
    let dir = TempDir::new("rev-running-poison");
    let exec = Arc::new(HeldExecutor::default());
    let r = rig(dir.path(), &exec, 1, None);
    let run = r.process_in_thread(0);
    exec.wait_for_runs(1);
    // A panicking writer never reaches the change hook, so nothing stops by itself.
    poison_revocations(&r.admission);
    std::thread::sleep(Duration::from_millis(30));
    assert_eq!(exec.cancelled_runs.load(Ordering::SeqCst), 0);
    // The explicit re-check fails closed.
    assert_eq!(r.admission.enforce_revocations(), 1);
    let u = unsuccessful(run.join().unwrap());
    assert!(matches!(u.outcome, stack_receipt::Outcome::Terminated { .. }));
}

#[test]
fn an_executor_without_the_hook_runs_to_its_real_outcome() {
    // The documented limitation: the default hook ignores the token, so a
    // revocation mid-run cannot stop such a run, and its real outcome is
    // what the receipt says.
    #[derive(Debug)]
    struct NoHook(Arc<HeldExecutor>);
    impl Executor for NoHook {
        fn run(&self, k: WorkerKind, l: &ExecutionLimits, a: &[u8]) -> Result<RunReport, ExecutorError> {
            self.0.runs.fetch_add(1, Ordering::SeqCst);
            while !self.0.state.lock().unwrap().released {
                std::thread::sleep(Duration::from_millis(2));
            }
            let _ = (k, l, a);
            Ok(completed())
        }
    }
    impl CancellableExecutor for NoHook {}

    let dir = TempDir::new("rev-nohook");
    let exec = Arc::new(HeldExecutor::default());
    let mut r = rig(dir.path(), &exec, 1, None);
    // Swap in the executor that keeps the default hook.
    let admission = Arc::try_unwrap(r.admission).expect("sole owner");
    r.admission = Arc::new(admission.with_cancellable_executor(Box::new(NoHook(Arc::clone(&exec)))));
    let run = r.process_in_thread(0);
    exec.wait_for_runs(1);
    revoke_id(&r.admission, &r.cap_ids[0]);
    std::thread::sleep(Duration::from_millis(30));
    exec.release();
    assert!(run.join().unwrap().is_success(), "documented limitation: the worker was not stopped");
}

#[test]
fn a_unrevoked_run_is_unaffected_and_succeeds() {
    let dir = TempDir::new("rev-control");
    let exec = Arc::new(HeldExecutor::default());
    let r = rig(dir.path(), &exec, 1, None);
    let run = r.process_in_thread(0);
    exec.wait_for_runs(1);
    exec.release();
    assert!(run.join().unwrap().is_success());
}
