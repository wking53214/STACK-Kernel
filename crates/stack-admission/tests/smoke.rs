//! Step 1 smoke: the real supervised executor runs a legitimate worker
//! through the `Executor` seam, and the seam reports the other endings
//! distinctly.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::path::PathBuf;

use stack_admission::{ExecutionLimits, Executor, RunOutcome, SupervisedExecutor, WorkerConfig, WorkerKind};

/// The real executor on this build's worker program, with the capability
/// granted once for the process.
fn executor() -> SupervisedExecutor {
    static GRANT: std::sync::Once = std::sync::Once::new();
    let executor = SupervisedExecutor::new(WorkerConfig {
        worker_path: PathBuf::from(stack_ffi::WORKER_BUILD_PATH),
        worker_sha256: Some(
            stack_ffi::worker_image_sha256(&std::ffi::CString::new(stack_ffi::WORKER_BUILD_PATH).expect("no NUL"))
                .expect("hash the worker build"),
        ),
        context_id: 0,
        required_capabilities: 0x01,
        tokens_per_run: 1,
        reap_timeout_ns: 0,
    })
    .expect("the test worker is usable");
    GRANT.call_once(|| stack_ffi::host_set_capabilities(0x01, 0, 0, 0).expect("grant the test capability"));
    executor
}

const DEADLINE_NS: u64 = 300_000_000;
/// Slack over the deadline for a killed worker: kill, reap, scheduling.
const SLACK_NS: u64 = 2_000_000_000;

#[test]
fn a_legitimate_worker_runs_to_completion_with_its_bytes() {
    let report = executor()
        .run(WorkerKind::ReturnBytes, &ExecutionLimits::with_deadline_ns(DEADLINE_NS), b"")
        .expect("report");
    match &report.outcome {
        RunOutcome::Completed { exit_code, result } => {
            assert_eq!(*exit_code, 0);
            assert_eq!(result.as_slice(), stack_admission::RETURN_BYTES_RESULT);
        }
        other => panic!("expected Completed, got {other:?}"),
    }
    assert!(!report.deadline_fired);
    assert!(report.elapsed_ns < DEADLINE_NS + SLACK_NS);
}

#[test]
fn a_non_returning_worker_is_timed_out_not_completed() {
    let report = executor()
        .run(WorkerKind::SpinForever, &ExecutionLimits::with_deadline_ns(DEADLINE_NS), b"")
        .expect("report");
    assert_eq!(report.outcome, RunOutcome::TimedOut);
    assert!(report.deadline_fired);
    assert!(report.elapsed_ns >= DEADLINE_NS);
    assert!(report.elapsed_ns <= DEADLINE_NS + SLACK_NS, "{}", report.elapsed_ns);
}

#[test]
fn every_other_ending_is_reported_as_itself() {
    let limits = ExecutionLimits::with_deadline_ns(DEADLINE_NS);
    let run = |k| executor().run(k, &limits, b"").expect("report").outcome;
    assert_eq!(run(WorkerKind::Crash), RunOutcome::Crashed { signal: 11 });
    assert_eq!(run(WorkerKind::Abort), RunOutcome::Crashed { signal: 6 });
    assert_eq!(run(WorkerKind::ExitNonZero), RunOutcome::ExitedNonZero { exit_code: 3 });
    assert_eq!(run(WorkerKind::ForbiddenSyscall), RunOutcome::SeccompViolation { signal: 31 });
    // Limits the supervisor refuses never become a completion.
    let mut zero = limits;
    zero.wall_clock_deadline_ns = 0;
    // (Step 3: a zero deadline is now refused by the host before anything is
    // spawned, so it is an Err from the executor, which the pipeline records
    // as Unknown, rather than an Ok report with an Unknown outcome.)
    assert!(matches!(
        executor().run(WorkerKind::ReturnBytes, &zero, b""),
        Err(stack_admission::ExecutorError::Refused(_))
    ));
}
