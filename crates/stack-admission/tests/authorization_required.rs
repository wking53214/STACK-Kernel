//! D2-A (Step 3) at the admission seam: the real executor runs a worker only on
//! behalf of an `AuthorizedAction`. The methods that name none are refused and
//! the host's worker spawn counter does not move; the authorized method runs the
//! intended worker and moves it by exactly one. Through the pipeline, every
//! refusal before the executor leaves the counter untouched.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use common::*;
use stack_admission::{AdmissionResult, ExecutionLimits, Executor, ExecutorError, RunOutcome, WorkerKind};

/// The host's spawn counter is process global: the tests here take turns.
fn serial() -> std::sync::MutexGuard<'static, ()> {
    static LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
    LOCK.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
}

fn limits() -> ExecutionLimits {
    ExecutionLimits::with_deadline_ns(DEADLINE_NS)
}

#[test]
fn the_real_executor_refuses_every_method_that_names_no_authorization_and_runs_nothing() {
    let _g = serial();
    let executor = test_executor();
    let before = stack_ffi::host_worker_spawn_count();
    for kind in WorkerKind::ALL {
        assert!(matches!(executor.run(kind, &limits(), b""), Err(ExecutorError::Refused(m)) if m.contains("AuthorizedAction")), "{kind}");
        assert!(matches!(executor.run_observed(kind, &limits(), b""), Err(ExecutorError::Refused(_))), "{kind}");
    }
    assert_eq!(stack_ffi::host_worker_spawn_count(), before, "no worker was spawned by any refusal");
}

#[test]
fn a_legitimate_authorization_runs_the_intended_worker_through_the_executor() {
    let _g = serial();
    let executor = test_executor();
    let auth = authorization();
    let before = stack_ffi::host_worker_spawn_count();
    let observed = executor
        .run_observed_authorized(&auth, WorkerKind::ReturnBytes, &limits(), b"")
        .unwrap();
    assert_eq!(
        observed.report.outcome,
        RunOutcome::Completed {
            exit_code: 0,
            result: stack_admission::RETURN_BYTES_RESULT.to_vec()
        }
    );
    assert!(observed.observed.is_some());
    assert_eq!(stack_ffi::host_worker_spawn_count(), before + 1);
}

#[test]
fn a_pipeline_refusal_before_the_executor_spawns_nothing_and_a_valid_request_spawns_one() {
    let _g = serial();
    let dir = TempDir::new("authz-pipeline");
    let h = Builder::new(dir.path()).start();
    let case = all_pass();
    // Not the first test in this binary to spawn: compare the host counter, which counts real spawns.
    let before = stack_ffi::host_worker_spawn_count();
    // A payload naming an unknown operation is refused at authorization: the executor is never reached.
    let refused = h.refusal(honest_payload(&case, "no-such-operation"));
    assert_eq!(refused.stage, stack_admission::Stage::Authorization);
    assert_eq!(h.runs(), 0, "the executor run counter");
    assert_eq!(stack_ffi::host_worker_spawn_count(), before, "the host spawn counter");
    // A legitimate request runs exactly once.
    let r = h.process(honest_payload(&case, "echo"));
    assert!(matches!(r, AdmissionResult::Success(_)), "{r:?}");
    assert_eq!(h.runs(), 1);
    assert_eq!(stack_ffi::host_worker_spawn_count(), before + 1);
}
