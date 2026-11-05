//! Step 1 (R3-K-01): a real admission run records the supervisor-observed
//! facts (`exit_observed`, `frame_status`) in a version 2 terminal event, and
//! a run whose executor observes nothing still records a version 1 terminal
//! that the verifier reports with the old limitation.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use common::*;
use stack_admission::{AdmissionResult, RunOutcome, RunReport};
use stack_receipt::{Event, ExitObserved, FrameStatus, OutcomeKind, State};

fn terminal_event(h: &Harness) -> Event {
    let parsed = stack_receipt::parse_log(&h.receipt_bytes()).unwrap();
    parsed.records.last().unwrap().record().event.clone()
}

fn limitations(v: &stack_receipt::LogVerification) -> Vec<&'static str> {
    not_checked(v)
}

#[test]
fn a_real_admission_run_writes_a_v2_terminal_with_exit_and_frame() {
    let dir = TempDir::new("obs-real");
    let h = Builder::new(dir.path()).start();
    let case = all_pass();
    let r = h.process(honest_payload(&case, "echo"));
    assert!(r.is_success(), "{r:?}");
    match terminal_event(&h) {
        Event::TerminalObserved(t) => {
            assert_eq!(t.observed.exit, ExitObserved::Exited { code: 0 });
            assert_eq!(t.observed.frame, FrameStatus::Valid);
        }
        other => panic!("expected a version 2 terminal, got {other:?}"),
    }
    let v = h.verify_full(&case, Some(stack_admission::RETURN_BYTES_RESULT));
    assert_eq!(v.state, State::VerifiedWithLimitations, "{}", v.to_json());
    assert!(v.findings.is_empty(), "{}", v.to_json());
    assert!(
        !limitations(&v).contains(&"supervisor_observed_facts_not_recorded"),
        "{}",
        v.to_json()
    );
    let checked: Vec<&str> = v.scope.checked.iter().map(|c| c.as_str()).collect();
    assert!(checked.contains(&"observed_facts_consistent_with_outcome"), "{checked:?}");
}

#[test]
fn every_real_ending_records_the_facts_the_supervisor_saw() {
    let dir = TempDir::new("obs-endings");
    let h = Builder::new(dir.path()).start();
    let case = all_pass();
    // (operation, expected outcome, expected exit observation)
    let table = [
        ("exit", OutcomeKind::ExitedNonZero, ExitObserved::Exited { code: 3 }),
        ("crash", OutcomeKind::Crashed, ExitObserved::Signaled { signal: 11 }),
    ];
    for (op, kind, exit) in table {
        let r = h.process(honest_payload(&case, op));
        let AdmissionResult::Unsuccessful(u) = &r else {
            panic!("{op}: {r:?}");
        };
        assert_eq!(u.outcome.kind(), kind, "{op}");
        match terminal_event(&h) {
            Event::TerminalObserved(t) => assert_eq!(t.observed.exit, exit, "{op}"),
            other => panic!("{op}: expected a version 2 terminal, got {other:?}"),
        }
        let v = h.verify_full(&case, None);
        assert_eq!(v.state, State::VerifiedWithLimitations, "{op}: {}", v.to_json());
        assert!(v.findings.is_empty(), "{op}: {}", v.to_json());
    }
}

#[test]
fn an_executor_that_observes_nothing_still_writes_v1_and_the_old_limitation_stands() {
    let dir = TempDir::new("obs-v1");
    let report = RunReport {
        outcome: RunOutcome::Completed {
            exit_code: 0,
            result: b"ok".to_vec(),
        },
        elapsed_ns: 1,
        deadline_fired: false,
    };
    let h = Builder::new(dir.path())
        .executor(Box::new(ScriptedExecutor(Ok(report))))
        .start();
    let case = all_pass();
    let r = h.process(honest_payload(&case, "echo"));
    assert!(r.is_success(), "{r:?}");
    assert!(matches!(terminal_event(&h), Event::Terminal(_)), "a v1 terminal");
    let v = h.verify_full(&case, Some(b"ok"));
    assert_eq!(v.state, State::VerifiedWithLimitations, "{}", v.to_json());
    assert!(
        limitations(&v).contains(&"supervisor_observed_facts_not_recorded"),
        "{}",
        v.to_json()
    );
}
