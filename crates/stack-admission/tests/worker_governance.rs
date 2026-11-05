//! The real executor is fail-closed (decision A, RACE-02): it cannot be built
//! without a usable worker program, and every run is checked by the host's
//! capability mask and rate limit before anything is spawned.
//!
//! The host is process global and its capability mask is part of this test's
//! subject, so everything runs in one test, in order, in this binary alone.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;

use stack_admission::{
    ExecutionLimits, Executor, ExecutorError, RunOutcome, SupervisedExecutor, WorkerConfig, WorkerKind,
    RETURN_BYTES_RESULT,
};

fn config(path: PathBuf) -> WorkerConfig {
    WorkerConfig {
        worker_path: path,
        context_id: 0,
        required_capabilities: 0x01,
        tokens_per_run: 1,
        reap_timeout_ns: 0,
    }
}

fn worker() -> PathBuf {
    PathBuf::from(stack_ffi::WORKER_BUILD_PATH)
}

fn limits() -> ExecutionLimits {
    ExecutionLimits::with_deadline_ns(2_000_000_000)
}

#[test]
fn the_executor_is_fail_closed_and_governed_before_spawn() {
    // Unset, relative, missing, not executable, world-writable: no executor.
    for bad in ["", "stack_worker", "/nonexistent/stack_worker", "/etc/hostname", "/tmp"] {
        assert!(
            matches!(SupervisedExecutor::new(config(PathBuf::from(bad))), Err(ExecutorError::WorkerUnavailable(_))),
            "{bad:?}"
        );
    }
    let dir = std::env::temp_dir().join(format!("stack_worker_ww_{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let world_writable = dir.join("worker");
    std::fs::copy(worker(), &world_writable).unwrap();
    std::fs::set_permissions(&world_writable, std::fs::Permissions::from_mode(0o777)).unwrap();
    assert!(matches!(
        SupervisedExecutor::new(config(world_writable.clone())),
        Err(ExecutorError::WorkerUnavailable(_))
    ));
    std::fs::remove_dir_all(&dir).unwrap();
    // A request that names no capability, and a cost of zero or above 100.
    let mut cfg = config(worker());
    cfg.required_capabilities = 0;
    assert!(matches!(SupervisedExecutor::new(cfg), Err(ExecutorError::WorkerUnavailable(_))));
    for tokens in [0, 101] {
        let mut cfg = config(worker());
        cfg.tokens_per_run = tokens;
        assert!(matches!(SupervisedExecutor::new(cfg), Err(ExecutorError::WorkerUnavailable(_))));
    }

    let executor = SupervisedExecutor::new(config(worker())).expect("the build's worker is usable");

    // The host's mask has never been set: the capability is not granted and
    // nothing runs.
    assert!(matches!(
        executor.run(WorkerKind::ReturnBytes, &limits(), b""),
        Err(ExecutorError::Refused(m)) if m.contains("CapabilityDenied")
    ));

    // Granted: the run completes, and its bytes are what the worker said.
    stack_ffi::host_set_capabilities(0x01, 0, 0, 0).expect("grant");
    let report = executor.run(WorkerKind::ReturnBytes, &limits(), b"").expect("report");
    match report.outcome {
        RunOutcome::Completed { exit_code: 0, ref result } => assert_eq!(result.as_slice(), RETURN_BYTES_RESULT),
        ref other => panic!("expected Completed, got {other:?}"),
    }

    // Revoked: refused again, with the worker not even looked at.
    stack_ffi::host_set_capabilities(0x04, 0, 0, 0).expect("revoke");
    assert!(matches!(
        executor.run(WorkerKind::ReturnBytes, &limits(), b""),
        Err(ExecutorError::Refused(m)) if m.contains("CapabilityDenied")
    ));
    stack_ffi::host_set_capabilities(0x01, 0, 0, 0).expect("grant again");

    // Tokens: a domain of its own at 100 per run serves 9 and then refuses.
    let mut cfg = config(worker());
    cfg.context_id = 1;
    cfg.tokens_per_run = 100;
    let pricey = SupervisedExecutor::new(cfg).expect("executor");
    let t0 = std::time::Instant::now();
    let mut served = 0u32;
    loop {
        match pricey.run(WorkerKind::ReturnBytes, &limits(), b"") {
            Ok(r) => {
                assert!(matches!(r.outcome, RunOutcome::Completed { .. }));
                served += 1;
                assert!(served < 40, "never rate limited");
            }
            Err(ExecutorError::Refused(m)) => {
                assert!(m.contains("RateLimited"), "{m}");
                break;
            }
            Err(e) => panic!("unexpected {e:?}"),
        }
    }
    let allowance = (t0.elapsed().as_millis() / 100) as u32 + 1;
    assert!((9..=9 + allowance).contains(&served), "served {served}");

    // A timeout is a timeout, not a completion and not an error.
    let mut quick = ExecutionLimits::with_deadline_ns(150_000_000);
    quick.max_output_bytes = 64;
    let report = executor.run(WorkerKind::SpinForever, &quick, b"").expect("report");
    assert_eq!(report.outcome, RunOutcome::TimedOut);
    assert!(report.elapsed_ns >= 150_000_000 && report.elapsed_ns <= 150_000_000 + 1_000_000_000);
    assert_eq!(stack_ffi::supervised_unconfirmed_count(), 0);
}
