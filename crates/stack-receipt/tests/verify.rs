//! The verifier on honest receipts: the five states, what the scope
//! lists, and what a consumer must read.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use common::*;
use stack_receipt::{
    verify_log, verify_log_bytes, verify_receipt_chain, Check, Event, ExecutionId, Expectations, FindingCode,
    Limitation, Outcome, OutcomeKind, RosterPolicy, Stage, State, TrustedReceiptKeys,
};

fn policy() -> RosterPolicy {
    RosterPolicy {
        required_seats: vec!["Governance_Gateway:door".into(), "DIT:judge".into()],
    }
}

/// Every expectation the auditor can supply for the fixture execution.
fn full<'a>(content: &'a stack_receipt::CnsValue, policy: &'a RosterPolicy) -> Expectations<'a> {
    Expectations {
        subject_content: Some(content),
        roster_policy: Some(policy),
        audience: Some("kernel-1"),
        kernel_id: Some("kernel-1"),
        result_bytes: Some(result_bytes()),
    }
}

#[test]
fn an_honest_completed_execution_with_every_expectation_is_verified_with_limitations_only() {
    let chain = sign_chain(honest_events());
    let content = subject_content();
    let policy = policy();
    let v = verify_receipt_chain(&chain, exec_id(), &baseline_trust(), &full(&content, &policy));
    assert_eq!(v.state, State::VerifiedWithLimitations, "{}", v.to_json());
    assert!(v.findings.is_empty(), "{:?}", v.findings);
    assert_eq!(v.execution.stage_reached, Some(Stage::Terminal));
    assert_eq!(v.execution.outcome, Some(OutcomeKind::Completed));
    assert_eq!(v.execution.sequences, [1, 2, 3, 4]);
    let mut checked = v.scope.checked.clone();
    checked.sort();
    let mut want = vec![
        Check::HashChain,
        Check::SequenceMonotonic,
        Check::KernelIdConsistent,
        Check::Signatures,
        Check::StageOrder,
        Check::DecisionRootRecomputed,
        Check::SubjectDigestRecomputed,
        Check::RosterComplete,
        Check::RosterPolicy,
        Check::CapabilityBindingConsistent,
        Check::ActionConsistent,
        Check::Audience,
        Check::OutcomeConsistentWithStageOrder,
        Check::ResultDigestRecomputed,
    ];
    want.sort();
    assert_eq!(checked, want, "every check the verifier has was performed");
    // The irreducible limitations: what no receipt can establish, plus
    // what this fixture carries that is not rechecked here.
    let mut limits = v.scope.not_checked.clone();
    limits.sort();
    let mut want = vec![
        Limitation::ActionLegitimacyNotEstablished,
        Limitation::CapabilitySignatureNotRechecked,
        Limitation::DecisionProofNotCheckableHmacIsProcessLocal,
        Limitation::NativeComponentNotVerified,
        Limitation::HandoffProvenanceNotRechecked,
        Limitation::TimestampsAreWriterClaims,
        Limitation::LogRollbackNotDetectableWithoutAnchor,
    ];
    want.sort();
    assert_eq!(limits, want);
}

#[test]
fn verified_is_strictly_every_check_passed_and_nothing_unchecked() {
    // By construction some limitation always applies, so VERIFIED is
    // never produced; this pins the definition rather than the hope.
    let chain = sign_chain(honest_events());
    let content = subject_content();
    let policy = policy();
    for exp in [Expectations::default(), full(&content, &policy)] {
        let v = verify_receipt_chain(&chain, exec_id(), &baseline_trust(), &exp);
        assert_ne!(v.state, State::Verified);
        assert!(!v.scope.not_checked.is_empty());
        assert!(v.scope.not_checked.contains(&Limitation::ActionLegitimacyNotEstablished));
        if v.state == State::Verified {
            assert!(v.scope.not_checked.is_empty());
        }
    }
}

#[test]
fn without_expectations_each_absence_is_a_named_limitation_not_a_pass() {
    let chain = sign_chain(honest_events());
    let v = verify_receipt_chain(&chain, exec_id(), &baseline_trust(), &Expectations::default());
    assert_eq!(v.state, State::VerifiedWithLimitations);
    for l in [
        Limitation::SubjectContentNotSupplied,
        Limitation::RosterPolicyNotSupplied,
        Limitation::AudienceNotSupplied,
        Limitation::ResultBytesNotSupplied,
    ] {
        assert!(v.scope.not_checked.contains(&l), "{l:?}");
    }
    for c in [
        Check::SubjectDigestRecomputed,
        Check::RosterPolicy,
        Check::Audience,
        Check::ResultDigestRecomputed,
    ] {
        assert!(!v.scope.checked.contains(&c), "{c:?} was not performed");
    }
    assert!(v.scope.checked.contains(&Check::RosterComplete), "non-empty, complete, all PASS needs no policy");
}

#[test]
fn honest_non_success_outcomes_verify_and_the_outcome_says_what_happened() {
    for outcome in every_outcome().into_iter().skip(1) {
        let kind = outcome.kind();
        let chain = sign_chain(vec![proposed(), authorized(), attempted(), terminal(outcome)]);
        let v = verify_receipt_chain(&chain, exec_id(), &baseline_trust(), &Expectations::default());
        assert_eq!(v.state, State::VerifiedWithLimitations, "{kind:?}");
        assert_eq!(v.execution.outcome, Some(kind));
        assert!(
            !v.scope.not_checked.contains(&Limitation::ResultBytesNotSupplied),
            "{kind:?}: no result to check"
        );
    }
}

#[test]
fn an_honest_rejection_verifies_with_stage_rejected_and_no_outcome() {
    for events in [vec![proposed(), rejected()], vec![proposed(), authorized(), rejected()]] {
        let chain = sign_chain(events);
        let v = verify_receipt_chain(&chain, exec_id(), &baseline_trust(), &Expectations::default());
        assert_eq!(v.state, State::VerifiedWithLimitations, "{:?}", v.findings);
        assert_eq!(v.execution.stage_reached, Some(Stage::Rejected));
        assert_eq!(v.execution.outcome, None);
    }
}

#[test]
fn an_open_attempt_is_incomplete_with_outcome_unknown_never_success() {
    let chain = sign_chain(vec![proposed(), authorized(), attempted()]);
    let v = verify_receipt_chain(&chain, exec_id(), &baseline_trust(), &Expectations::default());
    assert_eq!(v.state, State::Incomplete);
    assert_eq!(v.execution.outcome, Some(OutcomeKind::Unknown));
    assert_eq!(v.execution.stage_reached, Some(Stage::Attempted));
    assert_eq!(v.findings.len(), 1);
    assert_eq!(v.findings[0].code, FindingCode::TerminalMissing);
}

#[test]
fn an_execution_that_never_reached_an_attempt_is_incomplete_with_no_outcome() {
    let chain = sign_chain(vec![proposed(), authorized()]);
    let v = verify_receipt_chain(&chain, exec_id(), &baseline_trust(), &Expectations::default());
    assert_eq!(v.state, State::Incomplete);
    assert_eq!(v.execution.outcome, None);
    assert_eq!(v.findings[0].code, FindingCode::NotAttempted);
    let chain = sign_chain(vec![proposed()]);
    let v = verify_receipt_chain(&chain, exec_id(), &baseline_trust(), &Expectations::default());
    assert_eq!(v.state, State::Incomplete);
    assert_eq!(v.findings[0].code, FindingCode::NotAuthorized);
}

#[test]
fn an_unknown_execution_id_and_an_empty_log_are_unknown() {
    let chain = sign_chain(honest_events());
    let other = ExecutionId::from_bytes([0xee; 16]);
    let v = verify_receipt_chain(&chain, other, &baseline_trust(), &Expectations::default());
    assert_eq!(v.state, State::Unknown);
    assert_eq!(v.findings[0].code, FindingCode::ExecutionNotFound);
    assert_eq!(v.execution.stage_reached, None);
    let v = verify_log(&[], &baseline_trust(), &Expectations::default());
    assert_eq!(v.state, State::Unknown);
    assert_eq!(v.findings[0].code, FindingCode::EmptyLog);
    assert!(v.executions.is_empty());
}

#[test]
fn verify_log_judges_every_execution_and_takes_the_worst_state() {
    let (p, a, at) = (proposed(), authorized(), attempted());
    let mut events = Vec::new();
    // Execution A: complete. Execution B: open attempt. Interleaved.
    events.push((exec_id(), p.clone()));
    let b = ExecutionId::from_bytes([0xbb; 16]);
    events.push((b, p));
    events.push((exec_id(), a.clone()));
    events.push((b, a));
    events.push((exec_id(), at.clone()));
    events.push((b, at));
    events.push((exec_id(), terminal(completed())));
    let signer = fixture_signer("kernel-1");
    let records: Vec<_> = events
        .into_iter()
        .enumerate()
        .map(|(i, (id, e))| {
            let mut r = record(u64::try_from(i).unwrap() + 1, [0; 32], e);
            r.execution_id = id;
            r
        })
        .collect();
    let chain = resign_chain(&signer, records);
    let v = verify_log(&chain, &baseline_trust(), &Expectations::default());
    assert_eq!(v.state, State::Incomplete);
    assert_eq!(v.executions.len(), 2);
    assert_eq!(v.executions[0].execution.execution_id, exec_id());
    assert_eq!(v.executions[0].state, State::VerifiedWithLimitations);
    assert_eq!(v.executions[0].execution.sequences, [1, 3, 5, 7]);
    assert_eq!(v.executions[1].state, State::Incomplete);
    assert_eq!(v.executions[1].execution.outcome, Some(OutcomeKind::Unknown));
    assert!(v.findings.is_empty(), "no chain-level finding");
    let json = v.to_json();
    assert!(json.starts_with("{\"state\":\"INCOMPLETE\""));
    assert!(json.contains("\"outcome\":\"unknown\""));
    assert!(json.contains("\"code\":\"terminal_missing\""));
    assert!(json.contains("\"not_checked\":["));
    assert!(json.contains("\"action_legitimacy_not_established\""));
}

#[test]
fn verify_log_bytes_reads_a_real_file_and_reports_a_torn_tail_as_a_limitation() {
    let dir = std::env::temp_dir().join(format!("stack-receipt-verify-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("receipts.log");
    let _ = std::fs::remove_file(&path);
    let mut log = stack_receipt::FileReceiptLog::open(&path, "kernel-1", &[fixture_public_key("kernel-1")]).unwrap();
    let chain = sign_chain(honest_events());
    for s in &chain[..3] {
        stack_receipt::ReceiptLog::append(&mut log, s).unwrap();
    }
    drop(log);
    let mut bytes = std::fs::read(&path).unwrap();
    let v = verify_log_bytes(&bytes, &baseline_trust(), &Expectations::default());
    assert_eq!(v.state, State::Incomplete);
    // Half of the terminal frame: a crash mid-write.
    let frame = chain[3].to_frame();
    bytes.extend_from_slice(&frame[..frame.len() / 2]);
    let v = verify_log_bytes(&bytes, &baseline_trust(), &Expectations::default());
    assert_eq!(v.state, State::Incomplete, "the torn terminal is not a terminal");
    assert!(v.findings.iter().any(|f| f.code == FindingCode::TornTailDiscarded));
    assert!(v.scope.not_checked.contains(&Limitation::TornTailIgnored));
    assert!(v.executions[0].scope.not_checked.contains(&Limitation::TornTailIgnored));
    // The whole frame, unacknowledged: adopted, and the execution completes.
    let mut bytes = std::fs::read(&path).unwrap();
    bytes.extend_from_slice(&frame);
    let v = verify_log_bytes(&bytes, &baseline_trust(), &Expectations::default());
    assert_eq!(v.state, State::VerifiedWithLimitations);
    assert!(v.findings.iter().any(|f| f.code == FindingCode::TrailingFrameAdopted));
    // Garbage is rejected.
    let v = verify_log_bytes(b"not a log", &baseline_trust(), &Expectations::default());
    assert_eq!(v.state, State::Rejected);
    assert_eq!(v.findings[0].code, FindingCode::LogCorrupt);
}

#[test]
fn an_empty_trust_set_rejects_every_record() {
    let chain = sign_chain(honest_events());
    let v = verify_receipt_chain(&chain, exec_id(), &TrustedReceiptKeys::new(4), &Expectations::default());
    assert_eq!(v.state, State::Rejected);
    assert_eq!(v.findings.iter().filter(|f| f.code == FindingCode::ReceiptKeyUntrusted).count(), 4);
}

#[test]
fn a_receipt_never_reports_success_because_a_request_was_accepted() {
    // Proposed and Authorized alone: the request was accepted, nothing ran.
    let chain = sign_chain(vec![proposed(), authorized()]);
    let v = verify_receipt_chain(&chain, exec_id(), &baseline_trust(), &Expectations::default());
    assert_ne!(v.state, State::VerifiedWithLimitations);
    assert_ne!(v.execution.outcome, Some(OutcomeKind::Completed));
    // A Completed outcome with a non-zero exit code is still Completed as
    // recorded; the verifier does not reinterpret outcomes.
    let chain = sign_chain(vec![
        proposed(),
        authorized(),
        attempted(),
        Event::Terminal(stack_receipt::Terminal {
            outcome: Outcome::Completed {
                exit_code: 0,
                result_digest: result_digest(),
            },
            completed_at_ms: T0,
            elapsed_ns: 1,
        }),
    ]);
    let v = verify_receipt_chain(&chain, exec_id(), &baseline_trust(), &Expectations::default());
    assert_eq!(v.execution.outcome, Some(OutcomeKind::Completed));
}
