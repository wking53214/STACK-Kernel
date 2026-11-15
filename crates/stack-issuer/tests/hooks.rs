//! The two required hooks, the per-decision cap and the file log behind it. Hooks and
//! keys are TEST FIXTURES: the crate ships no hook that allows anything.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use std::sync::atomic::Ordering;
use std::sync::Arc;

use common::*;
use serde_json::{json, Value};
use stack_admission::execution_binding;
use stack_authority::{ManualClock, ResourceScope, ScopeKind};
use stack_issuer::{
    ConfigError, DenyAllRequests, FileIssuanceLog, IssuanceLog, IssuanceRecord, IssuanceRequest, IssueError, Issuer,
    IssuerConfig, RefuseAllDecisions, MAX_RECORD_LINE_BYTES,
};
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

fn with_hooks(
    log: impl IssuanceLog + 'static,
    verifier: FixtureAllowAllVerifier,
    authorizer: FixtureAuthorizer,
    config: IssuerConfig,
) -> Issuer {
    with_signer(FixtureSigner::honest(ISSUER), log, verifier, authorizer, config)
}

fn with_signer(
    signer: FixtureSigner,
    log: impl IssuanceLog + 'static,
    verifier: FixtureAllowAllVerifier,
    authorizer: FixtureAuthorizer,
    config: IssuerConfig,
) -> Issuer {
    Issuer::new(
        config,
        Box::new(signer),
        Box::new(CounterEntropy::default()),
        Box::new(log),
        Box::new(ManualClock::new(T0)),
        Box::new(verifier),
        Box::new(authorizer),
    )
    .unwrap()
}

fn record_for(root: &str) -> IssuanceRecord {
    IssuanceRecord {
        cap_id: "cap-x".into(),
        capability_digest: "00".repeat(32),
        issuer_id: ISSUER.into(),
        key_id: "00".repeat(32),
        requester: "r".into(),
        subject_digest: "00".repeat(32),
        decision_root: root.into(),
        operation: "echo".into(),
        args_digest: "00".repeat(32),
        worker: "return_bytes".into(),
        limits_digest: "00".repeat(32),
        resources: vec!["exact:/data/a".into()],
        not_before_ms: 1,
        expires_at_ms: 2,
        issued_at_ms: 1,
        one_time: true,
        policy_ref: POLICY_REF.into(),
    }
}

// ---- the decision verifier -----------------------------------------------------

#[test]
fn a_verifier_that_refuses_means_no_capability_no_record_and_its_reason_is_kept() {
    let case = case("all_pass");
    let log = SharedLog::default();
    let v = FixtureAllowAllVerifier { refuse: true, ..Default::default() };
    let issuer = with_hooks(log.clone(), v, FixtureAuthorizer::default(), issuer_config());
    let err = issuer.issue(&request(&case)).unwrap_err();
    assert!(matches!(err, IssueError::DecisionNotVerified(ref r) if r == "fixture verifier refuses"), "{err:?}");
    assert_eq!(log.count(), 0);
}

#[test]
fn the_verifier_is_given_the_subject_digest_root_and_decision_the_issuer_checked() {
    let case = case("all_pass");
    let log = SharedLog::default();
    let v = FixtureAllowAllVerifier::default();
    let (calls, decisions) = (v.calls.clone(), v.decisions.clone());
    let issuer = with_hooks(log, v, FixtureAuthorizer::default(), issuer_config());
    let req = request(&case);
    issuer.issue(&req).unwrap();
    let calls = calls.lock().unwrap();
    assert_eq!(calls.len(), 1);
    assert_eq!(calls[0].0, case["subject_digest"].as_str().unwrap());
    assert_eq!(calls[0].1, case["root"].as_str().unwrap());
    let decisions = decisions.lock().unwrap();
    assert_eq!(decisions[0], (req.decision.seats.clone(), req.decision.verdicts.len(), req.decision.root.to_hex()));
    assert!(!decisions[0].0.is_empty() && decisions[0].1 > 0, "the claim was not emptied");
}

#[test]
fn a_decision_that_fails_the_structural_checks_reaches_neither_hook() {
    let case = case("all_pass");
    let log = SharedLog::default();
    let v = FixtureAllowAllVerifier::default();
    let a = FixtureAuthorizer::default();
    let (calls, seen) = (v.calls.clone(), a.seen.clone());
    let issuer = with_hooks(log, v, a, issuer_config());
    let mut req = request(&case);
    req.decision.root = stack_authority::Digest32::from_bytes([9; 32]);
    assert!(issuer.issue(&req).is_err());
    assert!(calls.lock().unwrap().is_empty());
    assert!(seen.lock().unwrap().is_empty());
}

#[test]
fn the_placeholder_verifier_refuses_every_decision() {
    let case = case("all_pass");
    let log = SharedLog::default();
    let issuer = Issuer::new(
        issuer_config(),
        Box::new(FixtureSigner::honest(ISSUER)),
        Box::new(CounterEntropy::default()),
        Box::new(log.clone()),
        Box::new(ManualClock::new(T0)),
        Box::new(RefuseAllDecisions),
        Box::new(FixtureAuthorizer::default()),
    )
    .unwrap();
    assert!(matches!(issuer.issue(&request(&case)), Err(IssueError::DecisionNotVerified(_))));
    assert_eq!(log.count(), 0);
}

// ---- the authorizer ---------------------------------------------------------------

#[test]
fn the_authorizer_sees_everything_that_will_be_bound() {
    let case = case("all_pass");
    let a = FixtureAuthorizer::default();
    let seen = a.seen.clone();
    let issuer = with_hooks(SharedLog::default(), FixtureAllowAllVerifier::default(), a, issuer_config());
    let mut req = request(&case);
    req.resources = vec![
        ResourceScope::new(ScopeKind::Exact, "/data/a").unwrap(),
        ResourceScope::new(ScopeKind::Prefix, "/data/tree").unwrap(),
        ResourceScope::new(ScopeKind::Exact, "/data/z").unwrap(),
    ];
    issuer.issue(&req).unwrap();
    let seen = seen.lock().unwrap();
    assert_eq!(seen.len(), 1);
    let canonical = to_canonical_bytes(&json!({"target": "a"}), &canonical_limits()).unwrap();
    let expected = execution_binding(&canonical, stack_admission::WorkerKind::ReturnBytes, &kernel_policy().limits);
    assert_eq!(seen[0].requester, "requester-1");
    assert_eq!(seen[0].operation, "echo");
    assert_eq!(seen[0].resources, vec!["/data/a", "/data/tree", "/data/z"], "every scope, in the order requested");
    assert_eq!(seen[0].lifetime_ms, 60_000);
    assert_eq!(seen[0].args_digest, expected.args_digest.to_hex());
    assert_eq!(seen[0].subject_digest, case["subject_digest"].as_str().unwrap());
    assert_eq!(seen[0].decision_root, case["root"].as_str().unwrap());
}

#[test]
fn an_authorizer_that_denies_means_no_capability_and_no_record() {
    let case = case("all_pass");
    let log = SharedLog::default();
    let a = FixtureAuthorizer { allow: Some(vec![("requester-1".into(), "echo".into())]), ..Default::default() };
    let issuer = with_hooks(log.clone(), FixtureAllowAllVerifier::default(), a, issuer_config());
    assert!(issuer.issue(&request(&case)).is_ok());
    let mut other_requester = request(&case);
    other_requester.requester = "requester-2".into();
    let err = issuer.issue(&other_requester).unwrap_err();
    assert!(matches!(err, IssueError::NotAuthorized(ref r) if r == "fixture authorizer denies"), "{err:?}");
    let mut other_operation = request(&case);
    other_operation.operation = "spin".into();
    assert!(matches!(issuer.issue(&other_operation), Err(IssueError::NotAuthorized(_))));
    assert_eq!(log.count(), 1, "only the allowed one was logged");
}

#[test]
fn the_verifier_is_not_asked_when_the_authorizer_has_already_denied() {
    let case = case("all_pass");
    let v = FixtureAllowAllVerifier::default();
    let calls = v.calls.clone();
    let a = FixtureAuthorizer { allow: Some(vec![]), ..Default::default() };
    let issuer = with_hooks(SharedLog::default(), v, a, issuer_config());
    assert!(matches!(issuer.issue(&request(&case)), Err(IssueError::NotAuthorized(_))));
    assert!(calls.lock().unwrap().is_empty(), "a requester the policy refuses costs no lookup");
}

#[test]
fn the_placeholder_authorizer_denies_every_request() {
    let case = case("all_pass");
    let log = SharedLog::default();
    let issuer = Issuer::new(
        issuer_config(),
        Box::new(FixtureSigner::honest(ISSUER)),
        Box::new(CounterEntropy::default()),
        Box::new(log.clone()),
        Box::new(ManualClock::new(T0)),
        Box::new(FixtureAllowAllVerifier::default()),
        Box::new(DenyAllRequests),
    )
    .unwrap();
    assert!(matches!(issuer.issue(&request(&case)), Err(IssueError::NotAuthorized(_))));
    assert_eq!(log.count(), 0);
}

#[test]
fn a_refusal_from_either_hook_never_reaches_the_signer() {
    let case = case("all_pass");
    for (refuse_verifier, deny) in [(true, false), (false, true)] {
        let signer = FixtureSigner::honest(ISSUER);
        let signs = signer.signs.clone();
        let v = FixtureAllowAllVerifier { refuse: refuse_verifier, ..Default::default() };
        let a = FixtureAuthorizer { allow: if deny { Some(vec![]) } else { None }, ..Default::default() };
        let issuer = with_signer(signer, SharedLog::default(), v, a, issuer_config());
        assert!(issuer.issue(&request(&case)).is_err());
        assert_eq!(signs.load(Ordering::SeqCst), 0, "verifier refuses: {refuse_verifier}, authorizer denies: {deny}");
    }
}

// ---- the per-decision cap ---------------------------------------------------------

#[test]
fn one_decision_produces_at_most_the_configured_number_of_capabilities() {
    let first = case("all_pass");
    let other = case("other_subject_all_pass");
    let log = SharedLog::default();
    let issuer = with_hooks(log.clone(), FixtureAllowAllVerifier::default(), FixtureAuthorizer::default(), config_with_limit(2));
    assert!(issuer.issue(&request(&first)).is_ok());
    assert!(issuer.issue(&request(&first)).is_ok());
    assert!(matches!(issuer.issue(&request(&first)), Err(IssueError::DecisionLimit)));
    assert!(issuer.issue(&request(&other)).is_ok(), "a different decision has its own count");
    assert_eq!(log.count(), 3);
}

#[test]
fn an_exhausted_decision_costs_no_signature() {
    let case = case("all_pass");
    let signer = FixtureSigner::honest(ISSUER);
    let signs = signer.signs.clone();
    let issuer = with_signer(signer, SharedLog::default(), FixtureAllowAllVerifier::default(), FixtureAuthorizer::default(), config_with_limit(1));
    assert!(issuer.issue(&request(&case)).is_ok());
    assert_eq!(signs.load(Ordering::SeqCst), 1);
    for _ in 0..5 {
        assert!(matches!(issuer.issue(&request(&case)), Err(IssueError::DecisionLimit)));
    }
    assert_eq!(signs.load(Ordering::SeqCst), 1, "the refusals did not reach the signer");
}

#[test]
fn a_refusal_does_not_use_up_a_decisions_allowance() {
    let case = case("all_pass");
    let a = FixtureAuthorizer { allow: Some(vec![("requester-1".into(), "echo".into())]), ..Default::default() };
    let issuer = with_hooks(SharedLog::default(), FixtureAllowAllVerifier::default(), a, config_with_limit(1));
    let mut denied = request(&case);
    denied.requester = "intruder".into();
    for _ in 0..5 {
        assert!(issuer.issue(&denied).is_err());
    }
    assert!(issuer.issue(&request(&case)).is_ok(), "the denied attempts took no slot");
}

#[test]
fn a_limit_of_zero_is_a_configuration_error() {
    let r = IssuerConfig::from_kernel_policy(&kernel_policy(), ISSUER, POLICY_REF, canonical_limits(), MAX_LIFETIME_MS, ROOTS, 0);
    assert!(matches!(r, Err(ConfigError::DecisionLimit)));
}

// ---- the file log: counts per decision, restart, rotation, locking, limits ----------

#[test]
fn the_file_log_counts_each_decision_separately_and_remembers_them_across_a_restart() {
    let dir = TempDir::new("restart");
    let path = dir.file("issuance.jsonl");
    let (first, other) = (case("all_pass"), case("other_subject_all_pass"));
    let make = || {
        with_hooks(
            FileIssuanceLog::open(&path).unwrap(),
            FixtureAllowAllVerifier::default(),
            FixtureAuthorizer::default(),
            config_with_limit(2),
        )
    };
    {
        let issuer = make();
        assert!(issuer.issue(&request(&first)).is_ok());
        assert!(issuer.issue(&request(&first)).is_ok());
        assert!(matches!(issuer.issue(&request(&first)), Err(IssueError::DecisionLimit)));
        assert!(issuer.issue(&request(&other)).is_ok(), "the other decision is not limited by the first");
    }
    let issuer = make();
    assert!(matches!(issuer.issue(&request(&first)), Err(IssueError::DecisionLimit)), "the first is still spent");
    assert!(issuer.issue(&request(&other)).is_ok(), "the other has one left");
    assert!(matches!(issuer.issue(&request(&other)), Err(IssueError::DecisionLimit)));
}

#[test]
fn rotating_the_log_resets_the_counts_unless_the_history_is_carried() {
    let dir = TempDir::new("rotate");
    let (old, new) = (dir.file("issuance.1.jsonl"), dir.file("issuance.2.jsonl"));
    let case = case("all_pass");
    {
        let issuer = with_hooks(FileIssuanceLog::open(&old).unwrap(), FixtureAllowAllVerifier::default(), FixtureAuthorizer::default(), config_with_limit(1));
        assert!(issuer.issue(&request(&case)).is_ok());
    }
    // Without history the fresh file knows nothing: the spent decision is issued again.
    {
        let issuer = with_hooks(FileIssuanceLog::open(&new).unwrap(), FixtureAllowAllVerifier::default(), FixtureAuthorizer::default(), config_with_limit(1));
        assert!(issuer.issue(&request(&case)).is_ok(), "rotation without history re-arms the decision");
    }
    std::fs::remove_file(&new).unwrap();
    // With the old segment carried, it stays spent.
    let issuer = with_hooks(
        FileIssuanceLog::open_with_history(&new, &[old.as_path()]).unwrap(),
        FixtureAllowAllVerifier::default(),
        FixtureAuthorizer::default(),
        config_with_limit(1),
    );
    assert!(matches!(issuer.issue(&request(&case)), Err(IssueError::DecisionLimit)));
}

#[test]
fn a_history_segment_that_is_damaged_is_refused() {
    let dir = TempDir::new("history");
    let (old, new) = (dir.file("old.jsonl"), dir.file("new.jsonl"));
    std::fs::write(&old, b"garbage\n").unwrap();
    assert!(FileIssuanceLog::open_with_history(&new, &[old.as_path()]).is_err());
    assert!(FileIssuanceLog::open_with_history(&new, &[dir.file("missing.jsonl").as_path()]).is_err());
}

#[test]
fn a_second_handle_on_the_same_file_is_refused_until_the_first_is_dropped() {
    let dir = TempDir::new("lock");
    let path = dir.file("issuance.jsonl");
    let first = FileIssuanceLog::open(&path).unwrap();
    let e = FileIssuanceLog::open(&path).unwrap_err().to_string();
    assert!(e.contains("in use"), "{e}");
    drop(first);
    assert!(FileIssuanceLog::open(&path).is_ok());
}

#[test]
fn the_limit_is_exact_under_concurrent_appends_to_the_real_file_log() {
    let root = "ab".repeat(32);
    for round in 0..40 {
        let dir = TempDir::new(&format!("race{round}"));
        let log = Arc::new(FileIssuanceLog::open(&dir.file("issuance.jsonl")).unwrap());
        let barrier = Arc::new(std::sync::Barrier::new(8));
        let handles: Vec<_> = (0..8)
            .map(|_| {
                let (log, barrier, root) = (log.clone(), barrier.clone(), root.clone());
                std::thread::spawn(move || {
                    barrier.wait();
                    log.append(&record_for(&root), 3).is_ok()
                })
            })
            .collect();
        let ok = handles.into_iter().map(|h| h.join().unwrap()).filter(|b| *b).count();
        assert_eq!(ok, 3, "round {round}");
        assert_eq!(std::fs::read_to_string(dir.file("issuance.jsonl")).unwrap().lines().count(), 3);
    }
}

#[test]
fn the_limit_is_exact_under_concurrent_issuance_through_the_real_file_log() {
    let dir = TempDir::new("conc");
    let case = case("all_pass");
    let issuer = Arc::new(with_hooks(
        FileIssuanceLog::open(&dir.file("issuance.jsonl")).unwrap(),
        FixtureAllowAllVerifier::default(),
        FixtureAuthorizer::default(),
        config_with_limit(5),
    ));
    let req = request(&case);
    let handles: Vec<_> = (0..8)
        .map(|_| {
            let (issuer, req) = (Arc::clone(&issuer), req.clone());
            std::thread::spawn(move || (0..10).filter(|_| issuer.issue(&req).is_ok()).count())
        })
        .collect();
    let ok: usize = handles.into_iter().map(|h| h.join().unwrap()).sum();
    assert_eq!(ok, 5);
    assert_eq!(std::fs::read_to_string(dir.file("issuance.jsonl")).unwrap().lines().count(), 5);
}

#[test]
fn a_log_line_is_accepted_up_to_the_line_limit_and_refused_one_byte_past_it() {
    let dir = TempDir::new("linelimit");
    let path = dir.file("issuance.jsonl");
    let head = format!("{{\"cap_id\":\"c\",\"decision_root\":\"{}\",\"pad\":\"", "ab".repeat(32));
    let tail = "\"}";
    let make = |len: usize| {
        let pad = len - head.len() - tail.len();
        format!("{head}{}{tail}\n", "x".repeat(pad))
    };
    std::fs::write(&path, make(MAX_RECORD_LINE_BYTES)).unwrap();
    assert!(FileIssuanceLog::open(&path).is_ok(), "a line of exactly the limit opens");
    std::fs::write(&path, make(MAX_RECORD_LINE_BYTES + 1)).unwrap();
    let e = FileIssuanceLog::open(&path).unwrap_err().to_string();
    assert!(e.contains("longer than"), "{e}");
}

#[test]
fn a_log_far_larger_than_one_line_opens_by_streaming() {
    let dir = TempDir::new("stream");
    let path = dir.file("issuance.jsonl");
    // 3000 records of one decision, about 270 KiB: many reads, one count.
    let mut body = String::new();
    for _ in 0..3000 {
        body.push_str(&record_line(7));
    }
    std::fs::write(&path, body).unwrap();
    let log = FileIssuanceLog::open(&path).unwrap();
    assert_eq!(log.issued_for_decision(&hex::encode([7u8; 32])).unwrap(), 3000);
    assert_eq!(log.issued_for_decision(&hex::encode([8u8; 32])).unwrap(), 0);
}
