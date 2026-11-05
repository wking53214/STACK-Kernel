//! R-5 remainder (Step 4): a signed capability revoked while a REAL worker runs
//! kills that worker. `SupervisedExecutor` implements the stop hook: the cancel
//! token reaches the host by run id and the worker is SIGKILLed through its
//! pidfd, the same kill a capability-mask revocation uses.
//!
//! The worker is the shipped `stack_worker` spinning for its whole 3 s deadline.
//! Every claim about the receipt is made by `stack_receipt::verify_log_bytes`
//! with fresh trusted keys. Every key is a TEST FIXTURE (tests/common/mod.rs).

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use std::sync::Arc;
use std::time::{Duration, Instant};

use common::*;
use stack_admission::{Admission, AdmissionResult, ExecutionLimits};
use stack_receipt::{Event, ExitObserved, OutcomeKind, State};

/// The deadline the spinning worker would run to if nothing stopped it.
const SPIN_DEADLINE_NS: u64 = 3_000_000_000;
/// The stated bound from revocation to the worker being dead and the run recorded.
const KILL_BOUND: Duration = Duration::from_secs(1);

struct Rig {
    admission: Arc<Admission>,
    dir: std::path::PathBuf,
    envelopes: Vec<Vec<u8>>,
    cap_ids: Vec<String>,
    // keeps the temp dir alive
    _tmp: TempDir,
}

fn rig(label: &str, requests: usize, operation: &str) -> Rig {
    let tmp = TempDir::new(label);
    let mut policy = policy();
    policy.limits = ExecutionLimits::with_deadline_ns(SPIN_DEADLINE_NS);
    let h = Builder::new(tmp.path()).policy(policy).start();
    let case = all_pass();
    let (mut envelopes, mut cap_ids) = (Vec::new(), Vec::new());
    for _ in 0..requests {
        let spec = CapSpec::for_case(&case, operation, RESOURCE);
        cap_ids.push(spec.cap_id.clone());
        envelopes.push(h.envelope(payload_with(&case, &spec.issue(), operation, RESOURCE)));
    }
    // The REAL executor behind the cancellable seam.
    let admission = Arc::new(h.admission.with_cancellable_executor(Box::new(test_executor())));
    Rig {
        admission,
        dir: h.dir,
        envelopes,
        cap_ids,
        _tmp: tmp,
    }
}

impl Rig {
    fn start(&self, n: usize) -> std::thread::JoinHandle<AdmissionResult> {
        let (a, env) = (Arc::clone(&self.admission), self.envelopes[n].clone());
        std::thread::spawn(move || a.process(&env))
    }

    fn revoke(&self, n: usize) {
        self.admission
            .authority()
            .with_revocations(|r| r.revoke_id(&self.cap_ids[n]).unwrap())
            .unwrap();
    }

    fn verify(&self) -> stack_receipt::LogVerification {
        let exp = stack_receipt::Expectations {
            kernel_id: Some(KERNEL),
            audience: Some(KERNEL),
            ..stack_receipt::Expectations::default()
        };
        stack_receipt::verify_log_bytes(&std::fs::read(receipts_path(&self.dir)).unwrap(), &receipt_trust(), &exp)
    }

    fn terminal_of(&self, id: stack_receipt::ExecutionId) -> Event {
        let parsed = stack_receipt::parse_log(&std::fs::read(receipts_path(&self.dir)).unwrap()).unwrap();
        parsed
            .records
            .iter()
            .rev()
            .find(|r| r.record().execution_id == id)
            .unwrap()
            .record()
            .event
            .clone()
    }
}

fn wait_until(what: &str, mut cond: impl FnMut() -> bool) {
    let begun = Instant::now();
    while !cond() {
        assert!(begun.elapsed() < Duration::from_secs(5), "timed out waiting for {what}");
        std::thread::sleep(Duration::from_millis(5));
    }
}

/// The host's spawn counter is process global: these tests take turns.
fn serial() -> std::sync::MutexGuard<'static, ()> {
    static LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
    LOCK.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
}

#[test]
fn revoking_the_signed_capability_kills_the_real_worker_within_the_bound_and_the_receipt_says_terminated() {
    let _g = serial();
    let r = rig("rev-real", 1, "spin");
    let run = r.start(0);
    wait_until("the worker to be spawned", || stack_ffi::supervised_in_flight_count() >= 1);
    std::thread::sleep(Duration::from_millis(150)); // it is really spinning now

    let revoked_at = Instant::now();
    r.revoke(0);
    let result = run.join().unwrap();
    let to_dead = revoked_at.elapsed();
    println!("revocation to a recorded, dead worker: {to_dead:?} (bound {KILL_BOUND:?})");
    assert!(to_dead < KILL_BOUND, "revocation to a recorded, dead worker took {to_dead:?}");
    assert!(
        to_dead < Duration::from_millis(2500),
        "and far inside the 3 s deadline the worker would have run to"
    );

    let AdmissionResult::Unsuccessful(u) = &result else {
        panic!("a killed run is not a success: {result:?}");
    };
    assert!(!result.is_success());
    assert!(matches!(u.outcome, stack_receipt::Outcome::Terminated { signal: 9 }), "{:?}", u.outcome);

    // The receipt: a v2 terminal, outcome Terminated, killed by the supervisor, and it verifies.
    let Event::TerminalObserved(t) = r.terminal_of(u.execution_id) else {
        panic!("expected a version 2 terminal");
    };
    assert_eq!(t.terminal.outcome.kind(), OutcomeKind::Terminated);
    assert_eq!(t.observed.exit, ExitObserved::KilledBySupervisor { signal: 9 });
    let v = r.verify();
    assert_eq!(v.state, State::VerifiedWithLimitations, "{}", v.to_json());
    assert!(v.findings.is_empty(), "{}", v.to_json());
    assert_eq!(r.admission.in_flight(), 0);
    // And the worker is gone: nothing is left unconfirmed.
    assert_eq!(stack_ffi::supervised_unconfirmed_count(), 0);
}

#[test]
fn an_unrelated_real_run_is_unaffected_by_the_revocation_of_another() {
    let _g = serial();
    let r = rig("rev-real-bystander", 2, "spin");
    // One after the other: the Trident wants envelope sequences in order.
    let victim = r.start(0);
    wait_until("the first worker to be spawned", || stack_ffi::supervised_in_flight_count() >= 1);
    let bystander = r.start(1);
    wait_until("both workers to be spawned", || stack_ffi::supervised_in_flight_count() >= 2);
    std::thread::sleep(Duration::from_millis(100));

    r.revoke(0);
    let v = victim.join().unwrap();
    let AdmissionResult::Unsuccessful(vu) = &v else { panic!("{v:?}") };
    assert!(matches!(vu.outcome, stack_receipt::Outcome::Terminated { .. }), "{:?}", vu.outcome);

    // The other worker was not touched: it runs to its own 3 s deadline and is timed out, not terminated.
    let begun = Instant::now();
    let b = bystander.join().unwrap();
    let AdmissionResult::Unsuccessful(bu) = &b else { panic!("{b:?}") };
    assert_eq!(bu.outcome.kind(), OutcomeKind::TimedOut, "{:?}", bu.outcome);
    assert!(begun.elapsed() > Duration::from_millis(1000), "it ran on after the other was killed");
    let log = r.verify();
    assert!(log.findings.is_empty(), "{}", log.to_json());
}

#[test]
fn revoking_a_capability_whose_run_already_finished_changes_nothing() {
    let _g = serial();
    let r = rig("rev-real-finished", 1, "echo");
    let result = r.start(0).join().unwrap();
    assert!(result.is_success(), "{result:?}");
    let spawns = stack_ffi::host_worker_spawn_count();
    r.revoke(0);
    std::thread::sleep(Duration::from_millis(50));
    assert_eq!(stack_ffi::host_worker_spawn_count(), spawns, "nothing was spawned or stopped");
    assert_eq!(r.admission.in_flight(), 0);
    let log = r.verify();
    assert!(log.findings.is_empty(), "{}", log.to_json());
    assert_eq!(log.executions[0].execution.outcome, Some(OutcomeKind::Completed));
}
