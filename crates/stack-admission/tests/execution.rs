//! Stages 5 to 8: write-ahead, execution through the real supervised
//! executor, the terminal record, the success path, and independent
//! verification of the log it leaves.
//!
//! Every key is a TEST FIXTURE (tests/common/mod.rs). Every claim about a
//! receipt is made by `stack_receipt::verify_log_bytes` with fresh trusted
//! keys and the auditor's own expectations, never by the producer.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use common::*;
use stack_admission::{AdmissionResult, ExecutorError, RefusalReason, RunOutcome, RunReport, Stage};
use stack_receipt::{
    Digest32, Expectations, FindingCode, Outcome, OutcomeKind, SignedRecord, Stage as ReceiptStage, State,
};

const RESULT: &[u8] = stack_admission::RETURN_BYTES_RESULT;

fn success(r: AdmissionResult) -> stack_admission::Success {
    match r {
        AdmissionResult::Success(s) => s,
        other => panic!("expected success, got {other:?}"),
    }
}

fn sorted(mut v: Vec<&'static str>) -> Vec<&'static str> {
    v.sort_unstable();
    v
}

// ---------------------------------------------------------------------------
// The success path
// ---------------------------------------------------------------------------

#[test]
fn a_valid_authorized_request_runs_and_verifies_with_stated_limitations() {
    let dir = TempDir::new("e2e");
    let h = Builder::new(dir.path()).start();
    let case = all_pass();
    let s = success(h.process(honest_payload(&case, "echo")));
    assert_eq!(s.exit_code, 0);
    assert_eq!(s.result, RESULT, "the worker's own bytes, as it sent them");
    assert_eq!(s.terminal_sequence, 4);
    assert_eq!(h.runs(), 1);

    // The auditor supplies the subject content, the roster, the audience,
    // the kernel and the result bytes. Everything it can check passes; it
    // still does not say the action was legitimate.
    let v = h.verify_full(&case, Some(RESULT));
    assert_eq!(v.state, State::VerifiedWithLimitations, "{}", v.to_json());
    assert_ne!(v.state, State::Verified, "VERIFIED is never produced: legitimacy is not established");
    assert!(v.findings.is_empty(), "{}", v.to_json());
    assert_eq!(v.executions.len(), 1);
    let e = &v.executions[0];
    assert_eq!(e.state, State::VerifiedWithLimitations);
    assert_eq!(e.execution.execution_id, s.execution_id);
    assert_eq!(e.execution.outcome, Some(OutcomeKind::Completed));
    assert_eq!(e.execution.stage_reached, Some(ReceiptStage::Terminal));
    assert_eq!(e.execution.sequences, vec![1, 2, 3, 4]);
    assert_eq!(
        sorted(not_checked(&v)),
        sorted(vec![
            "action_legitimacy_not_established",
            "capability_signature_not_rechecked",
            "decision_proof_not_checkable_hmac_is_process_local",
            "handoff_provenance_not_rechecked",
            "result_is_self_reported",
            "timestamps_are_writer_claims",
            "log_rollback_not_detectable_without_anchor",
        ]),
        "{}",
        v.to_json()
    );
    // What the verifier did check, by name.
    let checked: Vec<&str> = v.scope.checked.iter().map(|c| c.as_str()).collect();
    for c in [
        "hash_chain",
        "signatures",
        "stage_order",
        "decision_root_recomputed",
        "subject_digest_recomputed",
        "roster_complete",
        "roster_policy",
        "capability_binding_consistent",
        "action_consistent",
        "audience",
        "result_digest_recomputed",
    ] {
        assert!(checked.contains(&c), "{c} missing from {checked:?}");
    }
    // The recorded result digest is the digest of the bytes the worker sent.
    let parsed = stack_receipt::parse_log(&h.receipt_bytes()).unwrap();
    let digest = Digest32::from_bytes(sha2_digest(RESULT));
    assert_eq!(digest, s.result_digest);
    let terminal = parsed.records.last().unwrap();
    match &terminal.record().event {
        stack_receipt::Event::TerminalObserved(t) => assert_eq!(
            t.terminal.outcome,
            Outcome::Completed {
                exit_code: 0,
                result_digest: digest
            }
        ),
        other => panic!("{other:?}"),
    }
}

fn sha2_digest(bytes: &[u8]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    Sha256::digest(bytes).into()
}

#[test]
fn authorization_precedes_the_attempt_and_the_attempt_precedes_execution() {
    let dir = TempDir::new("order");
    let h = Builder::new(dir.path()).start();
    let case = all_pass();
    let s = success(h.process(honest_payload(&case, "echo")));

    // From the log: proposed < authorized < attempted < terminal, in
    // sequence and in time.
    let parsed = stack_receipt::parse_log(&h.receipt_bytes()).unwrap();
    let stages: Vec<ReceiptStage> = parsed.records.iter().map(|r| r.record().stage()).collect();
    assert_eq!(
        stages,
        [ReceiptStage::Proposed, ReceiptStage::Authorized, ReceiptStage::Attempted, ReceiptStage::Terminal]
    );
    let seqs: Vec<u64> = parsed.records.iter().map(|r| r.record().sequence).collect();
    assert_eq!(seqs, [1, 2, 3, 4]);
    let times: Vec<u64> = parsed.records.iter().map(|r| r.record().recorded_at_ms).collect();
    assert!(times.windows(2).all(|w| w[0] <= w[1]), "{times:?}");

    // From the executor: at the instant the worker was started, the
    // proposed, authorized and attempted records were already in the file
    // on disk, and the terminal was not.
    let seen = h.seen.lock().unwrap().clone();
    assert_eq!(seen.len(), 1);
    assert_eq!(
        seen[0],
        [ReceiptStage::Proposed, ReceiptStage::Authorized, ReceiptStage::Attempted],
        "the attempt must be durable before the worker starts"
    );
    // The attempted record names exactly what ran.
    match &parsed.records[2].record().event {
        stack_receipt::Event::Attempted(a) => {
            assert_eq!(a.action.operation, "echo");
            assert_eq!(a.action.resource, RESOURCE);
            assert_eq!(a.started_at_ms, h.now());
        }
        other => panic!("{other:?}"),
    }
    assert_eq!(s.terminal_sequence, 4);
}

#[test]
fn the_verifier_lists_every_item_it_did_not_check() {
    let dir = TempDir::new("scope");
    let h = Builder::new(dir.path()).start();
    let case = all_pass();
    let _ = success(h.process(honest_payload(&case, "echo")));

    // An auditor that supplies nothing is told, item by item, what it did
    // not check.
    let bare = h.verify_log(Expectations::default());
    assert_eq!(bare.state, State::VerifiedWithLimitations);
    assert_eq!(
        sorted(not_checked(&bare)),
        sorted(vec![
            "action_legitimacy_not_established",
            "capability_signature_not_rechecked",
            "decision_proof_not_checkable_hmac_is_process_local",
            "handoff_provenance_not_rechecked",
            "result_is_self_reported",
            "timestamps_are_writer_claims",
            "log_rollback_not_detectable_without_anchor",
            "subject_content_not_supplied",
            "roster_policy_not_supplied",
            "result_bytes_not_supplied",
            // Step 2: the Attempted record now binds the worker image and limits, and an
            // auditor that supplies no expectation is told so.
            "worker_expectation_not_supplied",
        ]),
        "{}",
        bare.to_json()
    );
    // The same items are in the machine-readable output a consumer gets.
    let json = bare.to_json();
    for item in not_checked(&bare) {
        assert!(json.contains(&format!("\"{item}\"")), "{item} missing from {json}");
    }
    // A completed result is never reported as anything but self-reported,
    // even when the bytes match.
    let with_bytes = h.verify_log(Expectations {
        result_bytes: Some(RESULT),
        ..Expectations::default()
    });
    assert!(not_checked(&with_bytes).contains(&"result_is_self_reported"));
    assert!(!not_checked(&with_bytes).contains(&"result_bytes_not_supplied"));
}

// ---------------------------------------------------------------------------
// Independent verification: an auditor that disagrees is believed
// ---------------------------------------------------------------------------

#[test]
fn an_auditor_with_other_expectations_rejects_the_same_log() {
    let dir = TempDir::new("audit");
    let h = Builder::new(dir.path()).start();
    let case = all_pass();
    let _ = success(h.process(honest_payload(&case, "echo")));
    let bytes = h.receipt_bytes();
    let reject = |v: stack_receipt::LogVerification, code: FindingCode| {
        assert_eq!(v.state, State::Rejected, "{}", v.to_json());
        assert!(
            v.executions.iter().flat_map(|e| &e.findings).any(|f| f.code == code),
            "{code:?} not found in {}",
            v.to_json()
        );
    };

    // A different subject than the one the log is about.
    let other = common::case("other_subject_all_pass");
    reject(verify_bytes_full(&bytes, &other, Some(RESULT)), FindingCode::SubjectDigestMismatch);
    // A stricter roster than the kernel's: the log does not contain it.
    let stricter = stack_receipt::RosterPolicy {
        required_seats: vec![
            "Governance_Gateway:door".into(),
            "DIT:judge".into(),
            "HERALD:confidence".into(),
        ],
        ..stack_receipt::RosterPolicy::default()
    };
    let content = stack_admission::cns_value(&case["subject"]).unwrap();
    let v = stack_receipt::verify_log_bytes(
        &bytes,
        &receipt_trust(),
        &Expectations {
            subject_content: Some(&content),
            roster_policy: Some(&stricter),
            audience: Some(KERNEL),
            kernel_id: Some(KERNEL),
            result_bytes: Some(RESULT),
            ..Expectations::default()
        },
    );
    reject(v, FindingCode::Decision(stack_receipt::DecisionFinding::RequiredSeatMissing("HERALD:confidence".into())));
    // Another audience, another kernel, other result bytes.
    let v = stack_receipt::verify_log_bytes(
        &bytes,
        &receipt_trust(),
        &Expectations {
            audience: Some("kernel-b"),
            ..Expectations::default()
        },
    );
    reject(v, FindingCode::AudienceMismatch);
    let v = stack_receipt::verify_log_bytes(
        &bytes,
        &receipt_trust(),
        &Expectations {
            kernel_id: Some("kernel-b"),
            ..Expectations::default()
        },
    );
    assert_eq!(v.state, State::Rejected, "{}", v.to_json());
    reject(
        stack_receipt::verify_log_bytes(
            &bytes,
            &receipt_trust(),
            &Expectations {
                result_bytes: Some(b"some other bytes"),
                ..Expectations::default()
            },
        ),
        FindingCode::ResultDigestMismatch,
    );
    // A trust set that does not hold the kernel's key trusts nothing.
    let empty = stack_receipt::TrustedReceiptKeys::new(4);
    let v = stack_receipt::verify_log_bytes(&bytes, &empty, &Expectations::default());
    assert_eq!(v.state, State::Rejected, "{}", v.to_json());
}

fn terminal_with_flipped_result_digest(chain: &[SignedRecord]) -> Vec<SignedRecord> {
    let s = chain.last().unwrap();
    let mut canonical = s.canonical().to_vec();
    // The result digest is the last 32 bytes before completed_at (8) and
    // elapsed (8). An attacker without the key can fix the hash, not the
    // signature.
    let i = canonical.len() - 16 - 1;
    canonical[i] ^= 0xff;
    let hash = stack_receipt::record_hash(&canonical);
    let forged = SignedRecord::from_parts(canonical, *s.signature(), hash).unwrap();
    let mut tampered = chain.to_vec();
    let last = tampered.len() - 1;
    tampered[last] = forged;
    tampered
}

#[test]
fn a_tampered_result_digest_is_rejected() {
    let dir = TempDir::new("tamper-digest");
    let h = Builder::new(dir.path()).start();
    let case = all_pass();
    let _ = success(h.process(honest_payload(&case, "echo")));
    let parsed = stack_receipt::parse_log(&h.receipt_bytes()).unwrap();
    let tampered = terminal_with_flipped_result_digest(&parsed.records);
    let content = stack_admission::cns_value(&case["subject"]).unwrap();
    let v = stack_receipt::verify_log(
        &tampered,
        &receipt_trust(),
        &Expectations {
            subject_content: Some(&content),
            result_bytes: Some(RESULT),
            kernel_id: Some(KERNEL),
            audience: Some(KERNEL),
            ..Expectations::default()
        },
    );
    assert_eq!(v.state, State::Rejected, "{}", v.to_json());
    assert!(
        v.executions[0].findings.iter().any(|f| f.code == FindingCode::BadSignature),
        "{}",
        v.to_json()
    );
    // Without the key it cannot be re-signed: the untampered chain is the
    // only one that verifies.
    assert_eq!(h.verify_full(&case, Some(RESULT)).state, State::VerifiedWithLimitations);
}

#[test]
fn every_byte_flip_of_the_receipt_file_is_rejected_or_changes_nothing() {
    let dir = TempDir::new("flip");
    let h = Builder::new(dir.path()).start();
    let case = all_pass();
    let _ = success(h.process(honest_payload(&case, "echo")));
    let original = h.receipt_bytes();
    let baseline = stack_receipt::parse_log(&original).unwrap();
    let mut rejected = 0usize;
    let mut unchanged = 0usize;
    for i in 0..original.len() {
        let mut bytes = original.clone();
        bytes[i] ^= 0x01;
        let v = verify_bytes_full(&bytes, &case, Some(RESULT));
        if v.state == State::Rejected {
            rejected += 1;
            continue;
        }
        // The only flips that may verify are in the redundant, older
        // header slot or in bytes the format does not use; they must then
        // yield exactly the same records.
        let parsed = stack_receipt::parse_log(&bytes).unwrap_or_else(|e| panic!("byte {i} verifies yet does not parse: {e}"));
        assert_eq!(parsed.records, baseline.records, "byte {i} changed the records yet verified: {}", v.to_json());
        assert_eq!(v.state, State::VerifiedWithLimitations, "byte {i}: {}", v.to_json());
        unchanged += 1;
    }
    println!("byte flips: {} total, {rejected} rejected, {unchanged} identical records", original.len());
    assert_eq!(rejected + unchanged, original.len());
    assert!(rejected > original.len() * 9 / 10, "rejected {rejected} of {}", original.len());
}

#[test]
fn a_receipt_cut_short_is_incomplete_or_rejected_never_verified() {
    let dir = TempDir::new("truncate");
    let h = Builder::new(dir.path()).start();
    let case = all_pass();
    let _ = success(h.process(honest_payload(&case, "echo")));
    let parsed = stack_receipt::parse_log(&h.receipt_bytes()).unwrap();

    // Record level: the log without its last record(s). An attacker (or a
    // crash) removes the terminal event.
    for keep in 1..parsed.records.len() {
        let v = stack_receipt::verify_log(&parsed.records[..keep], &receipt_trust(), &Expectations::default());
        assert_eq!(v.state, State::Incomplete, "keep {keep}: {}", v.to_json());
        let e = &v.executions[0];
        assert_ne!(e.execution.outcome, Some(OutcomeKind::Completed), "keep {keep}");
        if keep == 3 {
            // Attempted, no terminal: the outcome is unknown, not success.
            assert_eq!(e.execution.outcome, Some(OutcomeKind::Unknown));
            assert!(e.findings.iter().any(|f| f.code == FindingCode::TerminalMissing));
        }
    }
    // File level: every proper prefix of the file is refused outright or
    // shows less than the whole, and none verifies as the completed run.
    let bytes = h.receipt_bytes();
    for cut in 0..bytes.len() {
        let v = verify_bytes_full(&bytes[..cut], &case, Some(RESULT));
        let completed = v.executions.iter().any(|e| e.execution.outcome == Some(OutcomeKind::Completed));
        assert!(!completed, "a log cut to {cut} bytes still shows Completed: {}", v.to_json());
        assert_ne!(v.state, State::Verified, "cut {cut}");
    }
}

// ---------------------------------------------------------------------------
// Every ending that is not a completion
// ---------------------------------------------------------------------------

#[test]
fn every_ending_other_than_a_completion_is_recorded_as_itself_and_is_not_success() {
    let dir = TempDir::new("endings");
    let h = Builder::new(dir.path()).start();
    let case = all_pass();
    let table = [
        ("crash", OutcomeKind::Crashed),
        ("abort", OutcomeKind::Crashed),
        ("exit", OutcomeKind::ExitedNonZero),
        ("forbidden", OutcomeKind::SeccompViolation),
    ];
    for (op, expected) in table {
        let r = h.process(honest_payload(&case, op));
        let AdmissionResult::Unsuccessful(u) = &r else {
            panic!("{op}: expected Unsuccessful, got {r:?}");
        };
        assert!(!r.is_success(), "{op}");
        assert_eq!(u.outcome.kind(), expected, "{op}");
        let v = h.verify_full(&case, None);
        let e = v.executions.iter().find(|e| e.execution.execution_id == u.execution_id).unwrap();
        // The receipt is honest about what happened: it verifies, and the
        // outcome says the run was not a completion.
        assert_eq!(e.state, State::VerifiedWithLimitations, "{op}: {}", e.to_json());
        assert_eq!(e.execution.outcome, Some(expected), "{op}");
        assert_eq!(e.execution.sequences.len(), 4);
    }
    assert_eq!(h.runs(), 4);
    assert_eq!(h.verify_full(&case, None).state, State::VerifiedWithLimitations);
}

// ---------------------------------------------------------------------------
// Receipt failures around the run
// ---------------------------------------------------------------------------

#[test]
fn an_attempt_that_cannot_be_recorded_does_not_run() {
    let dir = TempDir::new("attempt-fail");
    // Append calls: 1 proposed, 2 authorized, 3 attempted.
    let h = Builder::new(dir.path())
        .receipt_log(Box::new(FailingFileLog::open(dir.path(), &[3])))
        .start();
    let case = all_pass();
    let cap = CapSpec::for_case(&case, "echo", RESOURCE).issue();
    let r = h.process(payload_with(&case, &cap, "echo", RESOURCE));
    let AdmissionResult::Refused(refused) = &r else {
        panic!("expected a refusal, got {r:?}");
    };
    assert_eq!(refused.stage, Stage::Attempt);
    assert!(matches!(refused.reason, RefusalReason::Receipt(_)));
    assert!(!refused.recorded);
    assert!(refused.record_error.is_some());
    assert!(!r.is_success());
    assert_eq!(h.runs(), 0, "no attempt record, no execution");
    // The log shows authorization and nothing after it.
    let v = h.verify_full(&case, None);
    assert_eq!(v.state, State::Incomplete, "{}", v.to_json());
    let e = &v.executions[0];
    assert_eq!(e.execution.stage_reached, Some(ReceiptStage::Authorized));
    assert_eq!(e.execution.outcome, None, "nothing was attempted");
    assert!(e.findings.iter().any(|f| f.code == FindingCode::NotAttempted));
    // The one-time capability was consumed by the authorization and stays
    // consumed: the failure is fail-closed, and the same capability in a
    // fresh envelope is a replay, not a second chance.
    let again = h.process(payload_with(&case, &cap, "echo", RESOURCE));
    let AdmissionResult::Refused(second) = &again else {
        panic!("expected a refusal, got {again:?}");
    };
    assert_eq!(second.stage, Stage::Authorization);
    assert_eq!(second.reason, RefusalReason::Authorization(stack_authority::AuthzError::Replay));
    assert_eq!(h.runs(), 0);
}

#[test]
fn a_terminal_that_cannot_be_recorded_is_a_typed_non_success_and_leaves_the_attempt_open() {
    let dir = TempDir::new("terminal-fail");
    // Append calls: 1 proposed, 2 authorized, 3 attempted, 4 terminal.
    let h = Builder::new(dir.path())
        .receipt_log(Box::new(FailingFileLog::open(dir.path(), &[4])))
        .start();
    let case = all_pass();
    let r = h.process(honest_payload(&case, "echo"));
    let AdmissionResult::TerminalLost(lost) = &r else {
        panic!("expected TerminalLost, got {r:?}");
    };
    assert!(!r.is_success(), "a completion whose terminal is not recorded is not success");
    assert_eq!(lost.observed.kind(), OutcomeKind::Completed, "the kernel saw a completion and could not record it");
    assert_eq!(h.runs(), 1);
    let v = h.verify_full(&case, Some(RESULT));
    assert_eq!(v.state, State::Incomplete, "{}", v.to_json());
    let e = &v.executions[0];
    assert_eq!(e.execution.execution_id, lost.execution_id);
    assert_eq!(e.execution.stage_reached, Some(ReceiptStage::Attempted));
    assert_eq!(e.execution.outcome, Some(OutcomeKind::Unknown), "the log cannot say it completed");
    assert_ne!(e.execution.outcome, Some(OutcomeKind::Completed));
    assert!(e.findings.iter().any(|f| f.code == FindingCode::TerminalMissing));
}

// ---------------------------------------------------------------------------
// An executor is not believed past what it can show
// ---------------------------------------------------------------------------

fn report(outcome: RunOutcome, deadline_fired: bool) -> Result<RunReport, ExecutorError> {
    Ok(RunReport {
        outcome,
        elapsed_ns: 1,
        deadline_fired,
    })
}

#[test]
fn an_executor_failure_or_a_contradictory_report_is_unknown_never_completed() {
    let case = all_pass();
    let completed = |result: Vec<u8>| RunOutcome::Completed { exit_code: 0, result };
    let scripts: Vec<(&str, Result<RunReport, ExecutorError>)> = vec![
        ("executor error", Err(ExecutorError::Call("pipe failed".into()))),
        ("completion after the deadline fired", report(completed(RESULT.to_vec()), true)),
        ("result longer than the cap", report(completed(vec![7; 5000]), false)),
        ("unknown", report(RunOutcome::Unknown { reason: "spawn failed (errno 11)".into() }, false)),
    ];
    for (label, script) in scripts {
        let dir = TempDir::new("scripted");
        let h = Builder::new(dir.path())
            .executor(Box::new(ScriptedExecutor(script)))
            .start();
        let r = h.process(honest_payload(&case, "echo"));
        let AdmissionResult::Unsuccessful(u) = &r else {
            panic!("{label}: expected Unsuccessful, got {r:?}");
        };
        assert_eq!(u.outcome.kind(), OutcomeKind::Unknown, "{label}");
        let v = h.verify_full(&case, None);
        assert_eq!(v.executions[0].execution.outcome, Some(OutcomeKind::Unknown), "{label}");
        assert_eq!(v.state, State::VerifiedWithLimitations, "{label}: {}", v.to_json());
    }
    // And a believable completion through the same seam is a success.
    let dir = TempDir::new("scripted-ok");
    let h = Builder::new(dir.path())
        .executor(Box::new(ScriptedExecutor(report(completed(b"ok".to_vec()), false))))
        .start();
    assert!(h.process(honest_payload(&case, "echo")).is_success());
}

// ---------------------------------------------------------------------------
// P2 review findings 6 and 10
// ---------------------------------------------------------------------------

#[test]
fn an_executor_that_lies_about_a_nonzero_exit_is_never_completed() {
    // Finding 6: Completed means exit 0. A plug-in executor that reports
    // Completed with another code is contradicting its own definition.
    let case = all_pass();
    for code in [1, 3, -1] {
        let dir = TempDir::new("lying-exit");
        let lie = RunOutcome::Completed {
            exit_code: code,
            result: RESULT.to_vec(),
        };
        let h = Builder::new(dir.path())
            .executor(Box::new(ScriptedExecutor(report(lie, false))))
            .start();
        let r = h.process(honest_payload(&case, "echo"));
        let AdmissionResult::Unsuccessful(u) = &r else {
            panic!("exit {code}: expected Unsuccessful, got {r:?}");
        };
        assert!(!r.is_success(), "exit {code}");
        assert_ne!(u.outcome.kind(), OutcomeKind::Completed, "exit {code}");
        let v = h.verify_full(&case, None);
        assert_ne!(v.executions[0].execution.outcome, Some(OutcomeKind::Completed), "exit {code}");
    }
}

#[test]
fn an_authorized_record_that_cannot_be_written_carries_its_error() {
    // Finding 10. Append calls: 1 proposed, 2 authorized.
    let dir = TempDir::new("authorized-fail");
    let h = Builder::new(dir.path())
        .receipt_log(Box::new(FailingFileLog::open(dir.path(), &[2])))
        .start();
    let r = h.process(honest_payload(&all_pass(), "echo"));
    let AdmissionResult::Refused(refused) = &r else {
        panic!("expected a refusal, got {r:?}");
    };
    assert_eq!(refused.stage, Stage::Authorization);
    let RefusalReason::Receipt(e) = &refused.reason else {
        panic!("expected a receipt reason, got {:?}", refused.reason);
    };
    assert!(!refused.recorded);
    assert_eq!(refused.record_error.as_ref(), Some(e), "the error must not be dropped");
    assert_eq!(h.runs(), 0);
}
