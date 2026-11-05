//! Step 2 (R-7, G-5, G-4/R-6) through the real pipeline: a real admission run
//! binds the worker image the supervisor pinned and the limits it was given
//! (in `Attempted`), binds the use store's evidence (in `Authorized`), and
//! keeps the sender's native digest in its own field beside the CNS subject
//! digest. Every claim is checked by `stack_receipt::verify_log_bytes` with the
//! auditor's own expectations.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use common::*;
use serde_json::json;
use stack_admission::{AdmissionResult, PayloadError, RefusalReason, Stage};
use stack_receipt::{Check, Digest32, Event, Expectations, FindingCode, NativeDigest, State, UseEvidence};

fn events(h: &Harness) -> Vec<Event> {
    stack_receipt::parse_log(&h.receipt_bytes())
        .unwrap()
        .records
        .iter()
        .map(|r| r.record().event.clone())
        .collect()
}

#[test]
fn a_real_run_binds_the_pinned_worker_image_and_the_limits_it_was_given() {
    let dir = TempDir::new("worker-bind");
    let h = Builder::new(dir.path()).start();
    let case = all_pass();
    assert!(h.process(honest_payload(&case, "echo")).is_success());
    let Event::Attempted(a) = &events(&h)[2] else { panic!() };
    let w = a.worker.expect("a real run records the worker binding");
    assert_eq!(w.image_sha256, expected_worker_image(), "the digest the supervisor pinned and verified");
    assert_eq!(w.limits, expected_worker_limits());
    assert_eq!(w.limits.wall_clock_deadline_ns, DEADLINE_NS);
    assert_eq!(w.limits.wall_clock_deadline_ms(), 300);

    // The auditor states the image and limits it expects: both check out.
    let content = stack_admission::cns_value(&case["subject"]).unwrap();
    let image = expected_worker_image();
    let limits = expected_worker_limits();
    let exp = Expectations {
        subject_content: Some(&content),
        worker_image_sha256: Some(&image),
        worker_limits: Some(&limits),
        ..Expectations::default()
    };
    let v = h.verify_log(exp);
    assert!(v.findings.is_empty(), "{}", v.to_json());
    for c in [Check::WorkerImageMatchesExpected, Check::WorkerLimitsMatchExpected] {
        assert!(v.scope.checked.contains(&c), "{c:?}");
    }

    // A different image or a different deadline is a finding, not a limitation.
    let other = Digest32::from_bytes([0x5a; 32]);
    let v = h.verify_log(Expectations {
        worker_image_sha256: Some(&other),
        ..Expectations::default()
    });
    assert_eq!(v.state, State::Rejected, "{}", v.to_json());
    assert!(v.executions[0].findings.iter().any(|f| f.code == FindingCode::WorkerImageMismatch));
    let mut shorter = limits;
    shorter.wall_clock_deadline_ns -= 1;
    let v = h.verify_log(Expectations {
        worker_limits: Some(&shorter),
        ..Expectations::default()
    });
    assert!(v.executions[0].findings.iter().any(|f| f.code == FindingCode::WorkerLimitsMismatch), "{}", v.to_json());
}

#[test]
fn a_real_run_binds_the_durable_use_record_and_each_run_gets_its_own_position() {
    let dir = TempDir::new("use-bind");
    let h = Builder::new(dir.path()).start();
    let case = all_pass();
    assert!(h.process(honest_payload(&case, "echo")).is_success());
    let first = match &events(&h)[1] {
        Event::Authorized(a) => a.use_evidence.expect("a real run records the use evidence"),
        other => panic!("{other:?}"),
    };
    let UseEvidence::Durable { record_hash, position, head } = first else {
        panic!("a FileUseStore gives durable evidence, got {first:?}");
    };
    assert_eq!(position, 1);
    assert_eq!(record_hash, head);
    // A second, distinct capability (the harness mints a fresh nonce per payload).
    assert!(h.process(honest_payload(&case, "echo")).is_success());
    let second = match &events(&h)[5] {
        Event::Authorized(a) => a.use_evidence.unwrap(),
        other => panic!("{other:?}"),
    };
    let UseEvidence::Durable { position: p2, record_hash: h2, .. } = second else { panic!() };
    assert_eq!(p2, 2);
    assert_ne!(h2, record_hash);
    let v = h.verify_full(&case, None);
    assert!(v.findings.is_empty(), "{}", v.to_json());
    assert!(!v.scope.not_checked.iter().any(|l| l.as_str().starts_with("use_evidence")), "{}", v.to_json());
}

fn with_native(mut payload: serde_json::Value, label: &str, digest_hex: &str) -> serde_json::Value {
    payload["native_digest"] = json!({"label": label, "digest": digest_hex});
    payload
}

#[test]
fn the_native_digest_is_its_own_field_and_each_digest_is_checked_by_its_own_expectation() {
    let dir = TempDir::new("native");
    let h = Builder::new(dir.path()).start();
    let case = all_pass();
    let native_hex = "ab".repeat(32);
    let r = h.process(with_native(honest_payload(&case, "echo"), "sentinel-row-hash", &native_hex));
    assert!(r.is_success(), "{r:?}");
    let Event::Proposed(p) = &events(&h)[0] else { panic!() };
    let n = p.native_digest.clone().expect("the native digest is recorded");
    assert_eq!(n.label, "sentinel-row-hash");
    assert_eq!(n.digest.to_hex(), native_hex);
    assert_ne!(n.digest, p.subject.digest, "two fields, two digests");
    assert_eq!(p.subject.digest, case_subject_digest(&case), "the CNS digest is the kernel's own recomputation");

    let content = stack_admission::cns_value(&case["subject"]).unwrap();
    let right = NativeDigest {
        label: "sentinel-row-hash".into(),
        digest: Digest32::from_hex(&native_hex).unwrap(),
    };
    let wrong = NativeDigest {
        digest: Digest32::from_bytes([0x11; 32]),
        ..right.clone()
    };
    let v = h.verify_log(Expectations {
        subject_content: Some(&content),
        native_digest: Some(&right),
        ..Expectations::default()
    });
    assert!(v.findings.is_empty(), "{}", v.to_json());
    assert!(v.scope.checked.contains(&Check::NativeDigestMatchesExpected));
    // Wrong native expectation: only the native finding. Wrong subject content: only the CNS finding.
    let v = h.verify_log(Expectations {
        subject_content: Some(&content),
        native_digest: Some(&wrong),
        ..Expectations::default()
    });
    let codes: Vec<_> = v.executions[0].findings.iter().map(|f| f.code.clone()).collect();
    assert_eq!(codes, vec![FindingCode::NativeDigestMismatch], "{}", v.to_json());
    let other_content = stack_admission::cns_value(&json!({"doc": "someone else"})).unwrap();
    let v = h.verify_log(Expectations {
        subject_content: Some(&other_content),
        native_digest: Some(&right),
        ..Expectations::default()
    });
    let codes: Vec<_> = v.executions[0].findings.iter().map(|f| f.code.clone()).collect();
    assert_eq!(codes, vec![FindingCode::SubjectDigestMismatch], "{}", v.to_json());
}

#[test]
fn a_malformed_native_digest_is_refused_before_anything_is_recorded() {
    let dir = TempDir::new("native-bad");
    let h = Builder::new(dir.path()).start();
    let case = all_pass();
    for (label, hex) in [("sentinel", "AB".repeat(32)), ("sentinel", "ab".repeat(31)), ("", "ab".repeat(32))] {
        let r = h.process(with_native(honest_payload(&case, "echo"), label, &hex));
        let AdmissionResult::Refused(refused) = r else { panic!("{r:?}") };
        assert_eq!(refused.stage, Stage::Payload);
        assert!(matches!(
            refused.reason,
            RefusalReason::Payload(PayloadError::BadNativeDigest | PayloadError::Text(_))
        ));
        assert_eq!(refused.execution_id, None);
    }
    assert_eq!(h.runs(), 0);
}
