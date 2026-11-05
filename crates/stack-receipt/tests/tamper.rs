//! The tamper matrix. Each scenario names the attacker's edit, whether
//! the attacker holds the receipt key (an insider re-signs; an outsider
//! cannot), what the auditor supplied, and the state and finding the
//! verifier must return. Nothing here may verify as success.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use common::*;
use stack_receipt::{
    verify_log, verify_log_bytes, verify_receipt_chain, DecisionFinding, Digest32, Event, Expectations, FindingCode,
    GateOutcome, Limitation, LogError, MemoryReceiptLog, Outcome, OutcomeKind, ReceiptKeyAnchor, ReceiptLog, Record,
    RosterPolicy, SignedRecord, State, Terminal, TrustedReceiptKeys, Verification,
};

fn policy() -> RosterPolicy {
    RosterPolicy {
        required_seats: vec!["Governance_Gateway:door".into(), "DIT:judge".into()],
        ..RosterPolicy::default()
    }
}

/// The four honest records, unsigned, for an insider to edit.
fn honest_records() -> Vec<Record> {
    honest_events()
        .into_iter()
        .enumerate()
        .map(|(i, e)| record(u64::try_from(i).unwrap() + 1, [0; 32], e))
        .collect()
}

/// An insider edits one record and re-signs the whole chain.
fn insider(edit: impl FnOnce(&mut Vec<Record>)) -> Vec<SignedRecord> {
    let mut records = honest_records();
    edit(&mut records);
    resign_chain(&fixture_signer("kernel-1"), records)
}

fn verify(chain: &[SignedRecord]) -> Verification {
    verify_receipt_chain(chain, exec_id(), &baseline_trust(), &Expectations::default())
}

fn verify_full(chain: &[SignedRecord]) -> Verification {
    let content = subject_content();
    let policy = policy();
    verify_receipt_chain(
        chain,
        exec_id(),
        &baseline_trust(),
        &Expectations {
            subject_content: Some(&content),
            roster_policy: Some(&policy),
            audience: Some("kernel-1"),
            kernel_id: Some("kernel-1"),
            result_bytes: Some(result_bytes()),
        },
    )
}

fn has(v: &Verification, code: &FindingCode) -> bool {
    v.findings.iter().any(|f| &f.code == code)
}

fn assert_rejected(v: &Verification, code: &FindingCode) {
    assert_eq!(v.state, State::Rejected, "{}", v.to_json());
    assert!(has(v, code), "expected {code:?} in {}", v.to_json());
}

fn edit_proposed(records: &mut [Record], f: impl FnOnce(&mut stack_receipt::Proposed)) {
    if let Event::Proposed(p) = &mut records[0].event {
        f(p);
    } else {
        panic!("record 0 is not Proposed");
    }
}

fn edit_authorized(records: &mut [Record], f: impl FnOnce(&mut stack_receipt::Authorized)) {
    if let Event::Authorized(a) = &mut records[1].event {
        f(a);
    } else {
        panic!("record 1 is not Authorized");
    }
}

// ---------------------------------------------------------------------------
// Outsider edits: no key. Every edit to the bytes is caught by hash or
// signature.
// ---------------------------------------------------------------------------

#[test]
fn tampered_result_digest_without_the_key_is_rejected() {
    let chain = sign_chain(honest_events());
    let s = &chain[3];
    let mut canonical = s.canonical().to_vec();
    // The result digest is the last 32 bytes before completed_at and
    // elapsed (8 + 8): flip one of them and recompute the hash as an
    // attacker without the key would have to.
    let i = canonical.len() - 16 - 1;
    canonical[i] ^= 0xff;
    let hash = stack_receipt::record_hash(&canonical);
    let forged = SignedRecord::from_parts(canonical, *s.signature(), hash).unwrap();
    let mut tampered = chain.clone();
    tampered[3] = forged;
    let v = verify(&tampered);
    assert_rejected(&v, &FindingCode::BadSignature);
}

#[test]
fn every_byte_of_every_record_flipped_and_rehashed_is_rejected() {
    // The attacker recomputes the record hash (anyone can) but cannot
    // re-sign. Every flip is caught by the signature, by the decoder, or
    // by the chain.
    let chain = sign_chain(honest_events());
    let mut flips = 0;
    for (idx, s) in chain.iter().enumerate() {
        for i in 0..s.canonical().len() {
            let mut canonical = s.canonical().to_vec();
            canonical[i] ^= 0x01;
            let hash = stack_receipt::record_hash(&canonical);
            let Ok(forged) = SignedRecord::from_parts(canonical, *s.signature(), hash) else {
                // Does not decode: an outsider cannot even present it.
                flips += 1;
                continue;
            };
            let mut tampered = chain.clone();
            tampered[idx] = forged;
            let v = verify(&tampered);
            assert_eq!(v.state, State::Rejected, "record {idx} byte {i}: {}", v.to_json());
            // A flip in the kernel id, key id or recorded time is caught
            // before the signature (the key no longer resolves); any
            // other flip by the signature or the chain.
            assert!(
                has(&v, &FindingCode::BadSignature)
                    || has(&v, &FindingCode::PrevHashMismatch)
                    || has(&v, &FindingCode::SequenceGap)
                    || has(&v, &FindingCode::KernelIdMismatch)
                    || has(&v, &FindingCode::ReceiptKeyUntrusted)
                    || has(&v, &FindingCode::ReceiptKeyOutsideWindow),
                "record {idx} byte {i}: {}",
                v.to_json()
            );
            flips += 1;
        }
    }
    assert!(flips > 1000);
}

#[test]
fn every_byte_of_a_log_file_flipped_is_rejected_or_identical() {
    // Over the real file format, including the header: a flip in the
    // newest header slot makes the older slot win and the last frame be
    // adopted (identical records, same verdict); every other flip rejects.
    let dir = std::env::temp_dir().join(format!("stack-receipt-tamper-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("receipts.log");
    let _ = std::fs::remove_file(&path);
    let mut log = stack_receipt::FileReceiptLog::open(&path, "kernel-1", &[fixture_public_key("kernel-1")]).unwrap();
    for s in sign_chain(honest_events()) {
        log.append(&s).unwrap();
    }
    drop(log);
    let clean = std::fs::read(&path).unwrap();
    let honest = verify_log_bytes(&clean, &baseline_trust(), &Expectations::default());
    assert_eq!(honest.state, State::VerifiedWithLimitations);
    let newest_slot = 32..(32 + stack_receipt::SLOT_LEN) as usize;
    let (mut rejected, mut identical) = (0, 0);
    for i in 0..clean.len() {
        let mut bytes = clean.clone();
        bytes[i] ^= 0x01;
        let v = verify_log_bytes(&bytes, &baseline_trust(), &Expectations::default());
        if v.state == State::Rejected {
            rejected += 1;
        } else {
            assert!(newest_slot.contains(&i), "byte {i}: {}", v.to_json());
            assert_eq!(v.state, State::VerifiedWithLimitations);
            assert_eq!(v.executions, honest.executions);
            identical += 1;
        }
    }
    assert_eq!(rejected + identical, clean.len());
    assert!(identical > 0 && identical <= stack_receipt::SLOT_LEN as usize);
}

#[test]
fn a_record_removed_reordered_or_duplicated_is_rejected() {
    let chain = sign_chain(honest_events());
    let mut removed = chain.clone();
    removed.remove(2);
    let v = verify(&removed);
    assert_eq!(v.state, State::Rejected);
    assert!(has(&v, &FindingCode::SequenceGap) && has(&v, &FindingCode::PrevHashMismatch));

    let mut removed_last = chain.clone();
    removed_last.pop();
    let v = verify(&removed_last);
    assert_eq!(v.state, State::Incomplete, "dropping the last record is the rollback case: never success");
    assert_eq!(v.execution.outcome, Some(OutcomeKind::Unknown));

    let mut reordered = chain.clone();
    reordered.swap(1, 2);
    let v = verify(&reordered);
    assert_rejected(&v, &FindingCode::SequenceGap);
    assert!(has(&v, &FindingCode::PrevHashMismatch));

    let mut duplicated = chain.clone();
    duplicated.insert(3, chain[2].clone());
    let v = verify(&duplicated);
    assert_rejected(&v, &FindingCode::SequenceGap);
}

#[test]
fn a_swapped_signature_is_rejected() {
    let chain = sign_chain(honest_events());
    let swapped = SignedRecord::from_parts(chain[3].canonical().to_vec(), *chain[2].signature(), *chain[3].hash()).unwrap();
    let mut tampered = chain.clone();
    tampered[3] = swapped;
    assert_rejected(&verify(&tampered), &FindingCode::BadSignature);
}

// ---------------------------------------------------------------------------
// Key trust.
// ---------------------------------------------------------------------------

#[test]
fn a_wrong_receipt_key_is_rejected_even_when_trusted_for_another_kernel() {
    let chain = sign_chain_with(&fixture_signer("kernel-2"), honest_events());
    let v = verify(&chain);
    assert_rejected(&v, &FindingCode::ReceiptKeyUntrusted);
    let mut trust = baseline_trust();
    trust.insert(fixture_anchor("kernel-2", "kernel-2")).unwrap();
    let v = verify_receipt_chain(&chain, exec_id(), &trust, &Expectations::default());
    assert_rejected(&v, &FindingCode::ReceiptKeyUntrusted);
}

#[test]
fn an_expired_not_yet_valid_or_revoked_receipt_key_is_rejected() {
    let chain = sign_chain(honest_events());
    let mut expired = TrustedReceiptKeys::new(4);
    expired
        .insert(ReceiptKeyAnchor::new("kernel-1", fixture_public_key("kernel-1"), T0 - DAY, T0 - 1).unwrap())
        .unwrap();
    assert_rejected(
        &verify_receipt_chain(&chain, exec_id(), &expired, &Expectations::default()),
        &FindingCode::ReceiptKeyOutsideWindow,
    );
    let mut future = TrustedReceiptKeys::new(4);
    future
        .insert(ReceiptKeyAnchor::new("kernel-1", fixture_public_key("kernel-1"), T0 + DAY, T0 + 2 * DAY).unwrap())
        .unwrap();
    assert_rejected(
        &verify_receipt_chain(&chain, exec_id(), &future, &Expectations::default()),
        &FindingCode::ReceiptKeyOutsideWindow,
    );
    let mut revoked = baseline_trust();
    assert!(revoked.revoke(&fixture_public_key("kernel-1").key_id()));
    assert_rejected(
        &verify_receipt_chain(&chain, exec_id(), &revoked, &Expectations::default()),
        &FindingCode::ReceiptKeyRevoked,
    );
    // A record whose claimed time is inside the window verifies; one the
    // insider back-dates to before the window does not.
    let backdated = insider(|r| r[0].recorded_at_ms = T0 - DAY - 1);
    assert_rejected(&verify(&backdated), &FindingCode::ReceiptKeyOutsideWindow);
}

// ---------------------------------------------------------------------------
// Insider edits: the attacker holds the receipt key and re-signs.
// ---------------------------------------------------------------------------

#[test]
fn an_insider_tampered_result_digest_is_caught_only_with_the_result_bytes() {
    let chain = insider(|r| {
        r[3].event = terminal(Outcome::Completed {
            exit_code: 0,
            result_digest: d(0xdd),
        })
    });
    assert_rejected(&verify_full(&chain), &FindingCode::ResultDigestMismatch);
    let v = verify(&chain);
    assert_eq!(v.state, State::VerifiedWithLimitations, "without the bytes the digest is a claim");
    assert!(v.scope.not_checked.contains(&Limitation::ResultBytesNotSupplied));
}

#[test]
fn a_transplanted_subject_digest_is_caught_only_with_the_content() {
    // The insider moves the whole execution onto other content: the
    // proposal's subject digest and the capability's agree with each
    // other but not with the content the auditor has.
    let other = Digest32::from_bytes([0x5a; 32]);
    let chain = insider(|r| {
        edit_proposed(r, |p| p.subject.digest = other);
        edit_authorized(r, |a| a.capability.subject_digest = other);
    });
    assert_rejected(&verify_full(&chain), &FindingCode::SubjectDigestMismatch);
    let v = verify(&chain);
    assert_eq!(v.state, State::VerifiedWithLimitations);
    assert!(v.scope.not_checked.contains(&Limitation::SubjectContentNotSupplied));
}

#[test]
fn a_subject_changed_after_the_decision_is_rejected_without_any_content() {
    let chain = insider(|r| edit_proposed(r, |p| p.subject.digest = d(0x5a)));
    assert_rejected(&verify(&chain), &FindingCode::CapabilitySubjectMismatch);
}

#[test]
fn a_decision_changed_after_authorization_is_rejected() {
    // Verdict edited, root left as recorded: the root no longer recomputes.
    let chain = insider(|r| edit_proposed(r, |p| p.decision.verdicts[1].subject = "other".into()));
    assert_rejected(&verify(&chain), &FindingCode::DecisionRootMismatch);
    // Verdict edited and the root recomputed by the insider: the
    // capability was issued under the old root.
    let chain = insider(|r| {
        edit_proposed(r, |p| {
            p.decision.verdicts[1].subject = "other".into();
            p.decision.root = p.decision.recomputed_root();
        })
    });
    assert_rejected(&verify(&chain), &FindingCode::CapabilityDecisionRootMismatch);
    // Capability root edited to match: the capability binding itself is
    // then a different capability, which this verifier cannot recheck,
    // and says so.
    let chain = insider(|r| {
        let mut root = d(0);
        edit_proposed(r, |p| {
            p.decision.verdicts[1].subject = "other".into();
            p.decision.root = p.decision.recomputed_root();
            root = p.decision.root;
        });
        edit_authorized(r, |a| a.capability.decision_root = root);
    });
    let v = verify(&chain);
    assert_eq!(v.state, State::VerifiedWithLimitations);
    assert!(v.scope.not_checked.contains(&Limitation::CapabilitySignatureNotRechecked));
}

#[test]
fn an_empty_roster_is_rejected() {
    let chain = insider(|r| {
        edit_proposed(r, |p| {
            p.decision.seats.clear();
            p.decision.verdicts.clear();
            p.decision.root = p.decision.recomputed_root();
        });
        let root = decision_root_of(&r[0]);
        edit_authorized(r, |a| a.capability.decision_root = root);
    });
    assert_rejected(&verify(&chain), &FindingCode::Decision(DecisionFinding::EmptyRoster));
}

fn decision_root_of(r: &Record) -> Digest32 {
    match &r.event {
        Event::Proposed(p) => p.decision.root,
        _ => panic!(),
    }
}

#[test]
fn a_missing_policy_required_seat_is_rejected_only_when_the_policy_is_supplied() {
    let chain = insider(|r| {
        edit_proposed(r, |p| {
            p.decision.seats.remove(1);
            p.decision.verdicts.remove(1);
            p.decision.root = p.decision.recomputed_root();
        });
        let root = decision_root_of(&r[0]);
        edit_authorized(r, |a| a.capability.decision_root = root);
    });
    assert_rejected(
        &verify_full(&chain),
        &FindingCode::Decision(DecisionFinding::RequiredSeatMissing("DIT:judge".into())),
    );
    let v = verify(&chain);
    assert_eq!(v.state, State::VerifiedWithLimitations, "a one-seat roster is complete without a policy");
    assert!(v.scope.not_checked.contains(&Limitation::RosterPolicyNotSupplied));
}

#[test]
fn a_retry_or_terminal_breach_verdict_under_an_authorized_execution_is_rejected() {
    for outcome in [GateOutcome::Retry, GateOutcome::TerminalBreach] {
        let chain = insider(|r| {
            edit_proposed(r, |p| {
                p.decision.verdicts[1].outcome = outcome;
                p.decision.root = p.decision.recomputed_root();
            });
            let root = decision_root_of(&r[0]);
            edit_authorized(r, |a| a.capability.decision_root = root);
        });
        let v = verify(&chain);
        assert_rejected(
            &v,
            &FindingCode::Decision(DecisionFinding::VerdictNotPass {
                gate: "judge".into(),
                outcome,
            }),
        );
    }
    // The same roster under a Rejected execution is honest evidence of a
    // refusal and verifies.
    let chain = insider(|r| {
        edit_proposed(r, |p| {
            p.decision.verdicts[1].outcome = GateOutcome::Retry;
            p.decision.root = p.decision.recomputed_root();
        });
        r.truncate(1);
        r.push(record(2, [0; 32], rejected()));
    });
    assert_eq!(verify(&chain).state, State::VerifiedWithLimitations);
}

#[test]
fn an_unbound_pass_and_an_unseated_verdict_are_rejected() {
    let chain = insider(|r| {
        edit_proposed(r, |p| {
            p.decision.verdicts[0].subject = String::new();
            p.decision.verdicts[0].digest = String::new();
            p.decision.root = p.decision.recomputed_root();
        });
        let root = decision_root_of(&r[0]);
        edit_authorized(r, |a| a.capability.decision_root = root);
    });
    assert_rejected(
        &verify(&chain),
        &FindingCode::Decision(DecisionFinding::VerdictUnbound("door".into())),
    );
    let chain = insider(|r| {
        edit_proposed(r, |p| {
            let mut v = p.decision.verdicts[0].clone();
            v.gate = "extra".into();
            p.decision.verdicts.push(v);
            p.decision.root = p.decision.recomputed_root();
        });
        let root = decision_root_of(&r[0]);
        edit_authorized(r, |a| a.capability.decision_root = root);
    });
    let v = verify(&chain);
    assert_rejected(
        &v,
        &FindingCode::Decision(DecisionFinding::VerdictForUnseatedGate("extra".into())),
    );
    assert!(has(
        &v,
        &FindingCode::Decision(DecisionFinding::VerdictCountMismatch { seats: 2, verdicts: 3 })
    ));
}

#[test]
fn completed_without_attempted_or_without_authorized_is_rejected() {
    let chain = insider(|r| {
        r.remove(2);
    });
    assert_rejected(&verify(&chain), &FindingCode::TerminalWithoutAttempted);
    let chain = insider(|r| {
        r.remove(1);
    });
    assert_rejected(&verify(&chain), &FindingCode::AttemptedWithoutAuthorized);
    let chain = insider(|r| {
        r.remove(1);
        r.remove(1);
    });
    assert_rejected(&verify(&chain), &FindingCode::TerminalWithoutAttempted);
    let chain = insider(|r| {
        r.remove(0);
    });
    assert_rejected(&verify(&chain), &FindingCode::MissingProposed);
}

#[test]
fn an_actual_action_that_differs_from_the_authorized_one_is_rejected() {
    for (op, res) in [("write", "/data/a"), ("read", "/data/b"), ("read", "/data/a/b")] {
        let chain = insider(|r| {
            if let Event::Attempted(a) = &mut r[2].event {
                a.action.operation = op.into();
                a.action.resource = res.into();
            }
        });
        assert_rejected(&verify(&chain), &FindingCode::ActualActionDiffersFromAuthorized);
    }
    // And an authorized action that is not the proposed one.
    let chain = insider(|r| edit_authorized(r, |a| a.action.resource = "/data/b".into()));
    let v = verify(&chain);
    assert_rejected(&v, &FindingCode::AuthorizedActionDiffersFromProposed);
    assert!(has(&v, &FindingCode::ActualActionDiffersFromAuthorized));
}

#[test]
fn completed_after_a_timeout_or_any_second_terminal_is_rejected() {
    let chain = insider(|r| {
        r[3].event = terminal(Outcome::TimedOut);
        r.push(record(5, [0; 32], terminal(completed())));
    });
    let v = verify(&chain);
    assert_rejected(&v, &FindingCode::DuplicateTerminal);
    assert_eq!(v.execution.outcome, Some(OutcomeKind::TimedOut), "the first terminal stands in the summary");
    let chain = insider(|r| {
        r.push(record(5, [0; 32], attempted()));
    });
    assert_rejected(&verify(&chain), &FindingCode::EventAfterTerminal);
    let chain = insider(|r| {
        r.push(record(5, [0; 32], rejected()));
    });
    assert_rejected(&verify(&chain), &FindingCode::DuplicateTerminal);
    let chain = insider(|r| {
        r.truncate(2);
        r.push(record(3, [0; 32], rejected()));
        r.push(record(4, [0; 32], attempted()));
    });
    assert_rejected(&verify(&chain), &FindingCode::EventAfterTerminal);
}

#[test]
fn a_second_proposed_or_authorized_or_attempted_is_rejected() {
    let chain = insider(|r| r.insert(1, record(0, [0; 32], proposed())));
    assert_rejected(&verify(&chain), &FindingCode::DuplicateProposed);
    let chain = insider(|r| r.insert(2, record(0, [0; 32], authorized())));
    assert_rejected(&verify(&chain), &FindingCode::StageOrderViolation);
    let chain = insider(|r| r.insert(3, record(0, [0; 32], attempted())));
    assert_rejected(&verify(&chain), &FindingCode::StageOrderViolation);
}

#[test]
fn a_wrong_audience_or_kernel_is_rejected_when_expected() {
    let chain = insider(|r| edit_authorized(r, |a| a.capability.audience = "kernel-9".into()));
    assert_rejected(&verify_full(&chain), &FindingCode::AudienceMismatch);
    let v = verify(&chain);
    assert_eq!(v.state, State::VerifiedWithLimitations);
    assert!(v.scope.not_checked.contains(&Limitation::AudienceNotSupplied));

    let chain = sign_chain(honest_events());
    let v = verify_receipt_chain(
        &chain,
        exec_id(),
        &baseline_trust(),
        &Expectations {
            kernel_id: Some("kernel-9"),
            ..Expectations::default()
        },
    );
    assert_rejected(&v, &FindingCode::KernelIdMismatch);
    // A record of another kernel spliced in (its key is trusted for it).
    let mut trust = baseline_trust();
    trust.insert(fixture_anchor("kernel-2", "kernel-2")).unwrap();
    let mut mixed = honest_records();
    mixed[2].kernel_id = "kernel-2".into();
    let signer1 = fixture_signer("kernel-1");
    let signer2 = fixture_signer("kernel-2");
    let mut prev = stack_receipt::genesis_hash();
    let chain: Vec<SignedRecord> = mixed
        .into_iter()
        .map(|mut r| {
            r.prev_hash = prev;
            let signer = if r.kernel_id == "kernel-2" { &signer2 } else { &signer1 };
            r.key_id = *signer.key_id();
            let s = signer.sign(r).unwrap();
            prev = *s.hash();
            s
        })
        .collect();
    let v = verify_receipt_chain(&chain, exec_id(), &trust, &Expectations::default());
    assert_rejected(&v, &FindingCode::KernelIdMismatch);
}

#[test]
fn the_terminal_event_missing_is_incomplete_and_unknown_from_records_and_from_a_real_crash() {
    let chain = sign_chain(vec![proposed(), authorized(), attempted()]);
    let v = verify(&chain);
    assert_eq!(v.state, State::Incomplete);
    assert_eq!(v.execution.outcome, Some(OutcomeKind::Unknown));
    // The real crash is tests/log.rs: a_process_killed_between_attempted_and_terminal_leaves_the_attempt_open.
}

/// A log whose append fails after `fail_after` records: receipt
/// generation breaks between Attempted and the terminal event.
#[derive(Debug)]
struct FailingLog {
    inner: MemoryReceiptLog,
    fail_after: usize,
}

impl ReceiptLog for FailingLog {
    fn kernel_id(&self) -> &str {
        self.inner.kernel_id()
    }
    fn head(&self) -> Result<stack_receipt::Head, LogError> {
        self.inner.head()
    }
    fn append(&mut self, record: &SignedRecord) -> Result<(), LogError> {
        if self.inner.records().len() >= self.fail_after {
            return Err(LogError::Poisoned);
        }
        self.inner.append(record)
    }
    fn is_durable(&self) -> bool {
        false
    }
}

#[test]
fn a_receipt_generation_failure_leaves_an_incomplete_unknown_execution() {
    use std::sync::{Arc, Mutex};
    // The wrapper shares its memory log through a second handle so the
    // test can read what was written after the recorder is dropped.
    #[derive(Debug)]
    struct Shared(Arc<Mutex<FailingLog>>);
    impl ReceiptLog for Shared {
        fn kernel_id(&self) -> &str {
            "kernel-1"
        }
        fn head(&self) -> Result<stack_receipt::Head, LogError> {
            self.0.lock().map_err(|_| LogError::Poisoned)?.head()
        }
        fn append(&mut self, record: &SignedRecord) -> Result<(), LogError> {
            self.0.lock().map_err(|_| LogError::Poisoned)?.append(record)
        }
        fn is_durable(&self) -> bool {
            false
        }
    }
    let shared = Arc::new(Mutex::new(FailingLog {
        inner: MemoryReceiptLog::new("kernel-1").unwrap(),
        fail_after: 3,
    }));
    let recorder = stack_receipt::Recorder::new(
        Box::new(Shared(Arc::clone(&shared))),
        fixture_signer("kernel-1"),
        provenance(),
        Box::new(stack_receipt::ManualClock::new(T0)),
    )
    .unwrap();
    let Event::Proposed(p) = proposed() else { panic!() };
    let Event::Authorized(a) = authorized() else { panic!() };
    let Event::Attempted(at) = attempted() else { panic!() };
    let running = recorder
        .propose(exec_id(), p)
        .unwrap()
        .authorize_with(a)
        .unwrap()
        .attempt(at.action, at.started_at_ms)
        .unwrap();
    let err = running
        .finish(Terminal {
            outcome: completed(),
            completed_at_ms: T0,
            elapsed_ns: 1,
        })
        .unwrap_err();
    assert_eq!(err.observed_outcome.kind(), OutcomeKind::Completed);
    let records = shared.lock().unwrap().inner.records().to_vec();
    let v = verify_log(&records, &baseline_trust(), &Expectations::default());
    assert_eq!(v.state, State::Incomplete);
    assert_eq!(v.executions[0].execution.outcome, Some(OutcomeKind::Unknown));
    assert_ne!(v.executions[0].execution.outcome, Some(OutcomeKind::Completed));
}
