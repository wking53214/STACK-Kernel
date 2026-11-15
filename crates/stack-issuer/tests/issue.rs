//! The issuer: what it derives itself, what it refuses, and what it leaves
//! behind. The verifier in these tests is the real `stack_authority::Authority`
//! and the CNS decision is a case the real SuperGate produced. Keys are TEST
//! FIXTURES.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use std::collections::BTreeSet;

use common::*;
use serde_json::{json, Value};
use stack_admission::{execution_binding, BindingFinding, WorkerKind};
use stack_authority::{
    ActionRequest, AuthzError, Digest32, ManualClock, ResourceScope, ScopeKind, SignedCapability,
};
use stack_issuer::{IssuanceRequest, IssueError};
use stack_trident::canonical::to_canonical_bytes;

fn request(case: &Value) -> IssuanceRequest {
    IssuanceRequest {
        requester: "requester-1".into(),
        subject: case["subject"].clone(),
        decision: decision_of(case),
        operation: "echo".into(),
        resources: vec![ResourceScope::new(ScopeKind::Exact, "/data/a").unwrap()],
        args: json!({"target": "a"}),
        lifetime_ms: 60_000,
    }
}

fn kernel_view(case: &Value, args: &Value, kind: WorkerKind) -> ActionRequest {
    let canonical = to_canonical_bytes(args, &canonical_limits()).unwrap();
    let policy = kernel_policy();
    ActionRequest {
        subject_digest: Digest32::from_hex(case["subject_digest"].as_str().unwrap()).unwrap(),
        decision_root: Digest32::from_hex(case["root"].as_str().unwrap()).unwrap(),
        operation: "echo".into(),
        resource: "/data/a".into(),
        execution: Some(execution_binding(&canonical, kind, &policy.limits)),
    }
}

#[test]
fn an_issued_capability_is_accepted_by_the_real_authority_exactly_once() {
    let case = case("all_pass");
    let log = SharedLog::default();
    let issued = honest_issuer(&log).issue(&request(&case)).unwrap();
    let (authority, store) = verifier();
    let clock = ManualClock::new(T0 + 1_000);
    let view = kernel_view(&case, &json!({"target": "a"}), WorkerKind::ReturnBytes);
    let action = authority.authorize(&issued.wire, &view, &clock, &store).unwrap();
    assert_eq!(action.operation(), "echo");
    // One-time: a second use of the same capability is a replay.
    assert_eq!(authority.authorize(&issued.wire, &view, &clock, &store).unwrap_err(), AuthzError::Replay);
}

#[test]
fn every_bound_field_is_the_one_the_issuer_derived_not_one_the_requester_sent() {
    let case = case("all_pass");
    let log = SharedLog::default();
    let issued = honest_issuer(&log).issue(&request(&case)).unwrap();
    let cap = SignedCapability::parse(&issued.wire, 16 * 1024).unwrap();
    let cap = cap.capability();
    let policy = kernel_policy();
    assert_eq!(cap.audience, policy.audience);
    assert_eq!(cap.issuer_id, ISSUER);
    assert_eq!(cap.policy_ref, POLICY_REF);
    assert_eq!(cap.subject_digest, Digest32::from_hex(case["subject_digest"].as_str().unwrap()).unwrap());
    assert_eq!(cap.decision_root, Digest32::from_hex(case["root"].as_str().unwrap()).unwrap());
    assert_eq!(cap.operations, vec!["echo".to_owned()]);
    let canonical = to_canonical_bytes(&json!({"target": "a"}), &canonical_limits()).unwrap();
    assert_eq!(cap.binding, Some(execution_binding(&canonical, WorkerKind::ReturnBytes, &policy.limits)));
    assert!(cap.one_time, "the issuer never issues a reusable capability");
}

#[test]
fn the_worker_comes_from_the_kernel_policy_not_from_the_requester() {
    let case = case("all_pass");
    let log = SharedLog::default();
    let mut req = request(&case);
    req.operation = "spin".into();
    let issued = honest_issuer(&log).issue(&req).unwrap();
    let cap = SignedCapability::parse(&issued.wire, 16 * 1024).unwrap();
    assert_eq!(cap.capability().binding.as_ref().unwrap().worker, WorkerKind::SpinForever.as_str());
}

#[test]
fn the_window_starts_now_and_lasts_the_requested_lifetime() {
    let case = case("all_pass");
    let log = SharedLog::default();
    let issued = honest_issuer(&log).issue(&request(&case)).unwrap();
    let cap = SignedCapability::parse(&issued.wire, 16 * 1024).unwrap();
    assert_eq!(cap.capability().not_before_ms, T0);
    assert_eq!(cap.capability().expires_at_ms, T0 + 60_000);
}

#[test]
fn a_lifetime_over_the_configured_maximum_or_zero_is_refused_and_the_maximum_itself_is_allowed() {
    let case = case("all_pass");
    let log = SharedLog::default();
    let issuer = honest_issuer(&log);
    for bad in [0, MAX_LIFETIME_MS + 1, u64::MAX] {
        let mut req = request(&case);
        req.lifetime_ms = bad;
        assert!(matches!(issuer.issue(&req), Err(IssueError::Lifetime { .. })), "lifetime {bad}");
    }
    let mut req = request(&case);
    req.lifetime_ms = MAX_LIFETIME_MS;
    assert!(issuer.issue(&req).is_ok());
    assert_eq!(log.count(), 1, "only the issued one was logged");
}

#[test]
fn a_decision_that_lost_a_seat_and_kept_its_old_root_is_refused_and_nothing_is_logged() {
    let case = case("all_pass");
    let log = SharedLog::default();
    let mut req = request(&case);
    req.decision.verdicts.pop();
    req.decision.seats.pop();
    // This one is refused because the old root no longer matches. The tests in
    // `tests/hardening.rs` recompute the root, so the seat check itself is what refuses.
    let err = honest_issuer(&log).issue(&req).unwrap_err();
    assert!(matches!(err, IssueError::DecisionRefused(ref f) if !f.is_empty()), "{err:?}");
    assert_eq!(log.count(), 0);
}

#[test]
fn a_forged_root_is_refused_with_a_root_mismatch() {
    let case = case("all_pass");
    let log = SharedLog::default();
    let mut req = request(&case);
    req.decision.root = Digest32::from_bytes([0xAB; 32]);
    match honest_issuer(&log).issue(&req).unwrap_err() {
        IssueError::DecisionRefused(findings) => assert!(findings.contains(&BindingFinding::RootMismatch), "{findings:?}"),
        other => panic!("{other:?}"),
    }
    assert_eq!(log.count(), 0);
}

#[test]
fn a_decision_about_other_content_is_refused_because_the_issuer_recomputes_the_subject() {
    let case = case("all_pass");
    let log = SharedLog::default();
    let mut req = request(&case);
    req.subject = json!({"some": "other content"});
    match honest_issuer(&log).issue(&req).unwrap_err() {
        IssueError::DecisionRefused(findings) => {
            assert!(findings.iter().any(|f| matches!(f, BindingFinding::VerdictNotBoundToSubject { .. })), "{findings:?}");
        }
        other => panic!("{other:?}"),
    }
    assert_eq!(log.count(), 0);
}

#[test]
fn an_operation_the_kernel_does_not_run_is_refused() {
    let case = case("all_pass");
    let log = SharedLog::default();
    let mut req = request(&case);
    req.operation = "delete-everything".into();
    assert!(matches!(honest_issuer(&log).issue(&req), Err(IssueError::UnknownOperation(_))));
    assert_eq!(log.count(), 0);
}

#[test]
fn a_wildcard_resource_scope_is_refused_and_a_narrow_prefix_is_not() {
    let case = case("all_pass");
    let log = SharedLog::default();
    let issuer = honest_issuer(&log);
    let mut wide = request(&case);
    wide.resources = vec![ResourceScope::new(ScopeKind::Prefix, "/").unwrap()];
    assert!(matches!(issuer.issue(&wide), Err(IssueError::WildcardScope)));
    let mut none = request(&case);
    none.resources = vec![];
    assert!(matches!(issuer.issue(&none), Err(IssueError::NoResources)));
    let mut narrow = request(&case);
    narrow.resources = vec![ResourceScope::new(ScopeKind::Prefix, "/data/tree").unwrap()];
    assert!(issuer.issue(&narrow).is_ok());
}

#[test]
fn a_signer_that_is_offline_issues_nothing_and_logs_nothing() {
    let case = case("all_pass");
    let log = SharedLog::default();
    let issuer = issuer_with(FixtureSigner::failing(ISSUER), CounterEntropy::default(), &log, T0);
    assert!(matches!(issuer.issue(&request(&case)), Err(IssueError::Signer(_))));
    assert_eq!(log.count(), 0);
}

#[test]
fn a_signer_whose_signature_does_not_verify_under_its_own_key_is_caught_before_anything_leaves() {
    let case = case("all_pass");
    let log = SharedLog::default();
    let issuer = issuer_with(FixtureSigner::pretend(ISSUER, "some-other-key"), CounterEntropy::default(), &log, T0);
    assert!(matches!(issuer.issue(&request(&case)), Err(IssueError::SignerMisbehaved)));
    assert_eq!(log.count(), 0);
}

#[test]
fn if_the_issuance_cannot_be_logged_no_capability_is_returned() {
    let case = case("all_pass");
    let log = SharedLog::default();
    log.set_failing(true);
    let err = honest_issuer(&log).issue(&request(&case)).unwrap_err();
    assert!(matches!(err, IssueError::Log(_)), "{err:?}");
    // And recovers when the log does; nothing was half-issued.
    log.set_failing(false);
    assert!(honest_issuer(&log).issue(&request(&case)).is_ok());
    assert_eq!(log.count(), 1);
}

#[test]
fn entropy_that_fails_issues_nothing() {
    let case = case("all_pass");
    let log = SharedLog::default();
    let issuer = issuer_with(
        FixtureSigner::honest(ISSUER),
        CounterEntropy { fail: true, ..CounterEntropy::default() },
        &log,
        T0,
    );
    assert!(matches!(issuer.issue(&request(&case)), Err(IssueError::Entropy(_))));
    assert_eq!(log.count(), 0);
}

#[test]
fn ids_and_nonces_are_unique_across_issuances() {
    let case = case("all_pass");
    let log = SharedLog::default();
    let issuer = honest_issuer(&log);
    let mut ids = BTreeSet::new();
    let mut nonces = BTreeSet::new();
    for _ in 0..50 {
        let issued = issuer.issue(&request(&case)).unwrap();
        let cap = SignedCapability::parse(&issued.wire, 16 * 1024).unwrap();
        assert!(ids.insert(cap.capability().cap_id.clone()));
        assert!(nonces.insert(cap.capability().nonce));
    }
}

#[test]
fn the_log_record_describes_what_was_issued_and_its_digest_is_the_wires() {
    let case = case("all_pass");
    let log = SharedLog::default();
    let issued = honest_issuer(&log).issue(&request(&case)).unwrap();
    let records = log.records.lock().unwrap();
    assert_eq!(records.len(), 1);
    let r = &records[0];
    assert_eq!(r.cap_id, issued.cap_id);
    assert_eq!(r.capability_digest, issued.digest.to_hex());
    assert_eq!(r.requester, "requester-1");
    assert_eq!(r.subject_digest, case["subject_digest"].as_str().unwrap());
    assert_eq!(r.decision_root, case["root"].as_str().unwrap());
    assert_eq!(r.operation, "echo");
    assert_eq!(r.resources, vec!["exact:/data/a".to_owned()]);
    assert_eq!((r.not_before_ms, r.expires_at_ms, r.issued_at_ms), (T0, T0 + 60_000, T0));
    assert!(r.one_time);
}

#[test]
fn the_file_log_appends_one_line_per_issuance_and_never_rewrites() {
    use stack_issuer::FileIssuanceLog;
    let dir = std::env::temp_dir().join(format!("stack-issuer-log-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("issuance.jsonl");
    let _ = std::fs::remove_file(&path);
    let case = case("all_pass");
    let make = || {
        stack_issuer::Issuer::new(
            issuer_config(),
            Box::new(FixtureSigner::honest(ISSUER)),
            Box::new(CounterEntropy::default()),
            Box::new(FileIssuanceLog::open(&path).unwrap()),
            Box::new(ManualClock::new(T0)),
        )
        .unwrap()
    };
    let first = make().issue(&request(&case)).unwrap();
    let after_one = std::fs::read_to_string(&path).unwrap();
    assert_eq!(after_one.lines().count(), 1);
    // A new process opening the same file adds to it; the first line is unchanged.
    let _second = make().issue(&request(&case)).unwrap();
    let after_two = std::fs::read_to_string(&path).unwrap();
    assert_eq!(after_two.lines().count(), 2);
    assert!(after_two.starts_with(&after_one), "the earlier record was rewritten");
    let line: Value = serde_json::from_str(after_two.lines().next().unwrap()).unwrap();
    assert_eq!(line["cap_id"].as_str(), Some(first.cap_id.as_str()));
    assert_eq!(line["capability_digest"].as_str(), Some(first.digest.to_hex().as_str()));
}

#[test]
fn the_config_refuses_a_lifetime_ceiling_beyond_what_a_verifier_accepts() {
    use stack_issuer::{ConfigError, IssuerConfig};
    let p = kernel_policy();
    for bad in [0, 24 * HOUR + 1] {
        let r = IssuerConfig::from_kernel_policy(&p, ISSUER, POLICY_REF, canonical_limits(), bad, ROOTS);
        assert!(matches!(r, Err(ConfigError::MaxLifetime)), "{bad}");
    }
    assert!(IssuerConfig::from_kernel_policy(&p, ISSUER, POLICY_REF, canonical_limits(), 24 * HOUR, ROOTS).is_ok());
}
