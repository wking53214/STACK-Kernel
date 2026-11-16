//! The per-subject cap, the bound on distinct decisions, the logged operator reset, and the
//! policy digest in `policy_ref`. Hooks, keys and the in-memory log are TEST FIXTURES; the file
//! log is the real one.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use std::collections::BTreeMap;
use std::sync::atomic::Ordering;

use common::*;
use serde_json::{json, Value};
use stack_admission::{ExecutionLimits, KernelPolicy, WorkerKind};
use stack_authority::{ManualClock, ResourceScope, ScopeKind};
use stack_issuer::{
    ConfigError, FileIssuanceLog, IssuanceCaps, IssuanceLog, IssuanceRequest, IssueError, Issuer, IssuerConfig,
};
use stack_receipt::{decision_root, GatePosition};

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

fn caps(per_decision: u32, per_subject: u32, distinct: u32) -> IssuanceCaps {
    IssuanceCaps { per_decision, per_subject, distinct_decisions: distinct }
}

fn issuer_with_log(log: impl IssuanceLog + 'static, caps: IssuanceCaps) -> Issuer {
    new_issuer(config_with_caps(caps), FixtureSigner::honest(ISSUER), CounterEntropy::default(), log, ManualClock::new(T0)).unwrap()
}

fn relabelled(case: &Value, label: &str) -> IssuanceRequest {
    let mut r = request(case);
    for v in &mut r.decision.verdicts {
        v.subject = label.to_owned();
    }
    r.decision.root = decision_root(&r.decision.seats, &r.decision.verdicts);
    r
}

fn reordered(case: &Value) -> IssuanceRequest {
    let mut r = request(case);
    r.decision.seats.reverse();
    r.decision.root = decision_root(&r.decision.seats, &r.decision.verdicts);
    r
}

// ---- the per-subject cap -----------------------------------------------------------------------

#[test]
fn a_second_decision_about_the_same_subject_shares_the_subject_allowance() {
    let (a, b, other) = (case("all_pass"), case("three_seats_all_pass"), case("other_subject_all_pass"));
    assert_eq!(a["subject_digest"], b["subject_digest"], "the fixture's two decisions are about one subject");
    assert_ne!(a["root"], b["root"]);
    let log = SharedLog::default();
    let issuer = issuer_with_log(log.clone(), caps(5, 2, 100));
    assert!(issuer.issue(&request(&a)).is_ok());
    assert!(issuer.issue(&request(&b)).is_ok());
    assert!(matches!(issuer.issue(&request(&a)), Err(IssueError::SubjectLimit)));
    assert!(matches!(issuer.issue(&request(&b)), Err(IssueError::SubjectLimit)), "a different root, same subject");
    assert!(issuer.issue(&request(&other)).is_ok(), "another subject has its own allowance");
    assert_eq!(log.count(), 3);
}

#[test]
fn relabelling_or_reordering_a_decision_does_not_dodge_the_subject_cap() {
    let case = case("all_pass");
    let issuer = issuer_with_log(SharedLog::default(), caps(1, 1, 100));
    assert!(issuer.issue(&request(&case)).is_ok());
    assert!(matches!(issuer.issue(&request(&case)), Err(IssueError::DecisionLimit)), "the same root");
    // Each of these is a new decision root that passes every structural check.
    let relabel = relabelled(&case, "another-label");
    assert_ne!(relabel.decision.root, request(&case).decision.root);
    assert!(matches!(issuer.issue(&relabel), Err(IssueError::SubjectLimit)), "relabelled");
    let reorder = reordered(&case);
    assert_ne!(reorder.decision.root, request(&case).decision.root);
    assert!(matches!(issuer.issue(&reorder), Err(IssueError::SubjectLimit)), "reordered");
}

#[test]
fn an_exhausted_subject_costs_no_signature() {
    let case = case("all_pass");
    let signer = FixtureSigner::honest(ISSUER);
    let signs = signer.signs.clone();
    let issuer = new_issuer(config_with_caps(caps(5, 1, 100)), signer, CounterEntropy::default(), SharedLog::default(), ManualClock::new(T0)).unwrap();
    assert!(issuer.issue(&request(&case)).is_ok());
    for _ in 0..3 {
        assert!(matches!(issuer.issue(&relabelled(&case, "x")), Err(IssueError::SubjectLimit)));
    }
    assert_eq!(signs.load(Ordering::SeqCst), 1);
}

#[test]
fn the_subject_count_survives_a_restart_on_the_real_file_log() {
    let dir = TempDir::new("subject");
    let path = dir.file("issuance.jsonl");
    let case = case("all_pass");
    let make = || issuer_with_log(FileIssuanceLog::open(&path).unwrap(), caps(5, 2, 100));
    {
        let issuer = make();
        assert!(issuer.issue(&request(&case)).is_ok());
        assert!(issuer.issue(&relabelled(&case, "label-1")).is_ok());
    }
    let issuer = make();
    assert!(matches!(issuer.issue(&relabelled(&case, "label-2")), Err(IssueError::SubjectLimit)));
}

#[test]
fn the_caps_must_all_be_stated_and_at_least_one() {
    let p = kernel_policy();
    let make = |c: IssuanceCaps| IssuerConfig::from_kernel_policy(&p, ISSUER, POLICY_REF, canonical_limits(), MAX_LIFETIME_MS, ROOTS, c);
    assert!(matches!(make(caps(0, 1, 1)), Err(ConfigError::DecisionLimit)));
    assert!(matches!(make(caps(1, 0, 1)), Err(ConfigError::DecisionLimit)));
    assert!(matches!(make(caps(1, 1, 0)), Err(ConfigError::DecisionLimit)));
    assert!(make(caps(1, 1, 1)).is_ok());
}

// ---- the bound on distinct decisions ---------------------------------------------------------------

#[test]
fn a_new_decision_is_refused_once_the_log_holds_the_most_distinct_decisions() {
    let (a, b, other) = (case("all_pass"), case("three_seats_all_pass"), case("other_subject_all_pass"));
    let signer = FixtureSigner::honest(ISSUER);
    let signs = signer.signs.clone();
    let log = SharedLog::default();
    let issuer = new_issuer(config_with_caps(caps(5, 100, 2)), signer, CounterEntropy::default(), log.clone(), ManualClock::new(T0)).unwrap();
    assert!(issuer.issue(&request(&a)).is_ok());
    assert!(issuer.issue(&request(&other)).is_ok());
    let signed = signs.load(Ordering::SeqCst);
    assert!(matches!(issuer.issue(&request(&b)), Err(IssueError::DistinctDecisionsLimit)), "a third root");
    assert!(matches!(issuer.issue(&relabelled(&a, "mint-1")), Err(IssueError::DistinctDecisionsLimit)));
    assert_eq!(signs.load(Ordering::SeqCst), signed, "the refusals cost no signature");
    assert!(issuer.issue(&request(&a)).is_ok(), "a decision already in the log is still served");
    assert_eq!(log.count(), 3);
}

#[test]
fn the_distinct_decision_bound_is_exact_and_survives_a_restart_on_the_real_file_log() {
    let dir = TempDir::new("distinct");
    let path = dir.file("issuance.jsonl");
    let (a, other, b) = (case("all_pass"), case("other_subject_all_pass"), case("three_seats_all_pass"));
    let make = || issuer_with_log(FileIssuanceLog::open(&path).unwrap(), caps(5, 100, 2));
    {
        let issuer = make();
        assert!(issuer.issue(&request(&a)).is_ok());
        assert!(issuer.issue(&request(&other)).is_ok());
    }
    let issuer = make();
    assert!(matches!(issuer.issue(&request(&b)), Err(IssueError::DistinctDecisionsLimit)));
    assert!(issuer.issue(&request(&a)).is_ok());
}

#[test]
fn a_reset_decision_still_counts_as_a_distinct_decision() {
    let dir = TempDir::new("resetdistinct");
    let path = dir.file("issuance.jsonl");
    let (a, b) = (case("all_pass"), case("other_subject_all_pass"));
    let issuer = issuer_with_log(FileIssuanceLog::open(&path).unwrap(), caps(1, 100, 1));
    assert!(issuer.issue(&request(&a)).is_ok());
    issuer.reset_decision(a["root"].as_str().unwrap(), "op", "why").unwrap();
    assert!(matches!(issuer.issue(&request(&b)), Err(IssueError::DistinctDecisionsLimit)), "the reset root is still in the log");
}

// ---- the operator reset -------------------------------------------------------------------------------

#[test]
fn a_reset_gives_a_spent_decision_a_fresh_allowance_and_gives_back_its_subject_slots() {
    let case = case("all_pass");
    let root = case["root"].as_str().unwrap().to_owned();
    let issuer = issuer_with_log(SharedLog::default(), caps(2, 2, 100));
    assert!(issuer.issue(&request(&case)).is_ok());
    assert!(issuer.issue(&request(&case)).is_ok());
    assert!(matches!(issuer.issue(&request(&case)), Err(IssueError::DecisionLimit)));
    assert_eq!(issuer.reset_decision(&root, "op-1", "approved by ticket 4711").unwrap(), 2);
    assert!(issuer.issue(&request(&case)).is_ok(), "re-allowed");
    assert!(issuer.issue(&request(&case)).is_ok());
    assert!(matches!(issuer.issue(&request(&case)), Err(IssueError::DecisionLimit)), "and the cap applies again");
}

#[test]
fn a_reset_is_written_to_the_log_and_survives_a_restart() {
    let dir = TempDir::new("resetfile");
    let path = dir.file("issuance.jsonl");
    let case = case("all_pass");
    let root = case["root"].as_str().unwrap().to_owned();
    let make = || issuer_with_log(FileIssuanceLog::open(&path).unwrap(), caps(1, 1, 100));
    {
        let issuer = make();
        assert!(issuer.issue(&request(&case)).is_ok());
        assert!(matches!(issuer.issue(&request(&case)), Err(IssueError::DecisionLimit)));
        assert_eq!(issuer.reset_decision(&root, "op-1", "approved").unwrap(), 1);
    }
    let text = std::fs::read_to_string(&path).unwrap();
    let last: Value = serde_json::from_str(text.lines().last().unwrap()).unwrap();
    assert_eq!(last["reset"], true);
    assert_eq!(last["decision_root"], root);
    assert_eq!(last["operator"], "op-1");
    assert_eq!(last["reason"], "approved");
    assert_eq!(last["reset_at_ms"], T0);
    assert_eq!(text.lines().count(), 2, "one issuance, one reset");
    let issuer = make();
    assert!(issuer.issue(&request(&case)).is_ok(), "the reset was read back");
    assert!(matches!(issuer.issue(&request(&case)), Err(IssueError::DecisionLimit)));
}

#[test]
fn nothing_to_reset_and_malformed_resets_are_refused_and_write_nothing() {
    let dir = TempDir::new("resetbad");
    let path = dir.file("issuance.jsonl");
    let case = case("all_pass");
    let root = case["root"].as_str().unwrap().to_owned();
    let issuer = issuer_with_log(FileIssuanceLog::open(&path).unwrap(), caps(3, 3, 100));
    assert!(matches!(issuer.reset_decision(&root, "op", "why"), Err(IssueError::NothingToReset)), "unknown root");
    issuer.issue(&request(&case)).unwrap();
    for (r, o, why) in [
        ("ab", "op", "why"),
        (root.as_str(), "", "why"),
        (root.as_str(), "op", ""),
        (root.as_str(), "o\np", "why"),
        (root.as_str(), "op", "w\ny"),
    ] {
        assert!(matches!(issuer.reset_decision(r, o, why), Err(IssueError::BadReset)), "{r:?} {o:?} {why:?}");
    }
    assert!(matches!(issuer.reset_decision(&root, &"o".repeat(129), "why"), Err(IssueError::BadReset)));
    assert!(matches!(issuer.reset_decision(&root, "op", &"w".repeat(513)), Err(IssueError::BadReset)));
    assert_eq!(std::fs::read_to_string(&path).unwrap().lines().count(), 1, "only the issuance");
    assert_eq!(issuer.reset_decision(&root, &"o".repeat(128), &"w".repeat(512)).unwrap(), 1, "the exact maxima are accepted");
    assert!(matches!(issuer.reset_decision(&root, "op", "why"), Err(IssueError::NothingToReset)), "a second reset");
    // A refused reset writes nothing, so the log still opens: a line that resets nothing would not.
    assert_eq!(std::fs::read_to_string(&path).unwrap().lines().count(), 2, "one issuance, one reset");
    drop(issuer);
    assert!(FileIssuanceLog::open(&path).is_ok());
}

#[test]
fn a_reset_in_a_later_segment_applies_to_earlier_ones_and_the_order_matters() {
    let dir = TempDir::new("resethist");
    let (old, live) = (dir.file("old.jsonl"), dir.file("live.jsonl"));
    let case = case("all_pass");
    let root = case["root"].as_str().unwrap().to_owned();
    {
        let issuer = issuer_with_log(FileIssuanceLog::open(&old).unwrap(), caps(1, 1, 100));
        issuer.issue(&request(&case)).unwrap();
    }
    {
        let log = FileIssuanceLog::open_with_history(&live, &[old.as_path()]).unwrap();
        let issuer = issuer_with_log(log, caps(1, 1, 100));
        assert!(matches!(issuer.issue(&request(&case)), Err(IssueError::DecisionLimit)), "the history counts");
        issuer.reset_decision(&root, "op", "why").unwrap();
    }
    // Oldest first: the reset in `live` finds the issuance in `old`, and the decision is free.
    let issuer = issuer_with_log(FileIssuanceLog::open_with_history(&dir.file("next.jsonl"), &[old.as_path(), live.as_path()]).unwrap(), caps(1, 1, 100));
    assert!(issuer.issue(&request(&case)).is_ok());
    drop(issuer);
    // Newest first: the reset comes before the records it resets, which is refused.
    let e = FileIssuanceLog::open_with_history(&dir.file("other.jsonl"), &[live.as_path(), old.as_path()]).unwrap_err().to_string();
    assert!(e.contains("resets a decision that has no issuances"), "{e}");
}

#[test]
fn a_reset_line_that_is_not_well_formed_is_refused_at_open() {
    let dir = TempDir::new("resetline");
    let path = dir.file("issuance.jsonl");
    let root = hex::encode([7u8; 32]);
    let record = record_line(7);
    let cases = [
        ("reset false", format!("{record}{{\"reset\":false,\"decision_root\":\"{root}\",\"operator\":\"o\",\"reason\":\"r\",\"reset_at_ms\":1}}\n")),
        ("no operator", format!("{record}{{\"reset\":true,\"decision_root\":\"{root}\",\"reason\":\"r\",\"reset_at_ms\":1}}\n")),
        ("no reason", format!("{record}{{\"reset\":true,\"decision_root\":\"{root}\",\"operator\":\"o\",\"reset_at_ms\":1}}\n")),
        ("no time", format!("{record}{{\"reset\":true,\"decision_root\":\"{root}\",\"operator\":\"o\",\"reason\":\"r\"}}\n")),
        ("bad root", format!("{record}{{\"reset\":true,\"decision_root\":\"ab\",\"operator\":\"o\",\"reason\":\"r\",\"reset_at_ms\":1}}\n")),
        ("nothing to reset", format!("{{\"reset\":true,\"decision_root\":\"{root}\",\"operator\":\"o\",\"reason\":\"r\",\"reset_at_ms\":1}}\n")),
    ];
    for (what, text) in cases {
        std::fs::write(&path, text).unwrap();
        assert!(FileIssuanceLog::open(&path).is_err(), "{what}");
    }
    let good = format!("{record}{{\"reset\":true,\"decision_root\":\"{root}\",\"operator\":\"o\",\"reason\":\"r\",\"reset_at_ms\":1}}\n");
    std::fs::write(&path, good).unwrap();
    assert!(FileIssuanceLog::open(&path).is_ok());
}

#[test]
fn an_issuance_record_must_carry_a_subject_digest() {
    let dir = TempDir::new("nosubject");
    let path = dir.file("issuance.jsonl");
    let root = hex::encode([7u8; 32]);
    std::fs::write(&path, format!("{{\"cap_id\":\"c\",\"decision_root\":\"{root}\"}}\n")).unwrap();
    assert!(FileIssuanceLog::open(&path).is_err());
}

// ---- the policy digest in policy_ref -------------------------------------------------------------------

fn config_for(p: &KernelPolicy) -> IssuerConfig {
    IssuerConfig::from_kernel_policy(p, ISSUER, POLICY_REF, canonical_limits(), MAX_LIFETIME_MS, ROOTS, default_caps()).unwrap()
}

#[test]
fn policy_ref_ends_with_the_digest_of_the_kernel_policy_and_it_matches_an_independent_computation() {
    let config = config_for(&kernel_policy());
    // Computed in Python (hashlib) from the documented layout, not by this crate.
    let expected = "8b4ef0a641e82de947ce369448f9f3777f1f019e35d7d65fe83b5ada34698e2c";
    assert_eq!(config.policy_digest().to_hex(), expected);
    assert_eq!(config.policy_ref(), format!("{POLICY_REF}@sha256:{expected}"));
}

#[test]
fn every_kernel_policy_field_the_issuer_uses_changes_the_digest_and_the_seat_order_does_not() {
    let base = config_for(&kernel_policy()).policy_digest();
    let digest = |p: KernelPolicy| config_for(&p).policy_digest();
    let changed: Vec<(&str, KernelPolicy)> = vec![
        ("audience", KernelPolicy { audience: "kernel-b".into(), ..kernel_policy() }),
        ("a required seat renamed", {
            let mut p = kernel_policy();
            p.required_seats[0] = "Governance_Gateway:door2".into();
            p.seat_positions = BTreeMap::from([
                ("Governance_Gateway:door2".to_owned(), GatePosition::Alpha),
                ("DIT:judge".to_owned(), GatePosition::Omega),
            ]);
            p
        }),
        ("a seat position", {
            let mut p = kernel_policy();
            p.seat_positions.insert("DIT:judge".into(), GatePosition::Alpha);
            p
        }),
        ("an operation added", {
            let mut p = kernel_policy();
            p.operations.insert("block".into(), WorkerKind::BlockForever);
            p
        }),
        ("an operation's worker", {
            let mut p = kernel_policy();
            p.operations.insert("echo".into(), WorkerKind::Crash);
            p
        }),
        ("the limits", KernelPolicy { limits: ExecutionLimits::with_deadline_ns(301_000_000), ..kernel_policy() }),
        ("refuse_arguments", KernelPolicy { refuse_arguments: true, ..kernel_policy() }),
        ("require_execution_binding", KernelPolicy { refuse_arguments: true, require_execution_binding: false, ..kernel_policy() }),
        ("require_one_time_capabilities", KernelPolicy { require_one_time_capabilities: false, ..kernel_policy() }),
    ];
    let mut seen = vec![base];
    for (what, p) in changed {
        let d = digest(p);
        assert!(!seen.contains(&d), "{what} did not change the digest (or collided with another change)");
        seen.push(d);
    }
    let mut reordered = kernel_policy();
    reordered.required_seats.reverse();
    assert_eq!(digest(reordered), base, "the order of the required seats is not part of the policy");
}

#[test]
fn the_capability_and_the_log_carry_the_policy_ref_with_its_digest() {
    let case = case("all_pass");
    let log = SharedLog::default();
    let issued = honest_issuer(&log).issue(&request(&case)).unwrap();
    let cap = stack_authority::SignedCapability::parse(&issued.wire, 16 * 1024).unwrap();
    assert!(cap.capability().policy_ref.starts_with(&format!("{POLICY_REF}@sha256:")));
    assert_eq!(cap.capability().policy_ref.len(), POLICY_REF.len() + "@sha256:".len() + 64);
    assert_eq!(log.records.lock().unwrap()[0].policy_ref, cap.capability().policy_ref);
}

// ---- the limits are exact under concurrency on the real file log ----------------------------------------

fn record_with(root_byte: u8, subject_byte: u8) -> stack_issuer::IssuanceRecord {
    stack_issuer::IssuanceRecord {
        cap_id: format!("cap-{root_byte}"),
        capability_digest: "00".repeat(32),
        issuer_id: ISSUER.into(),
        key_id: "00".repeat(32),
        requester: "r".into(),
        subject_digest: hex::encode([subject_byte; 32]),
        decision_root: hex::encode([root_byte; 32]),
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

fn race(limits: stack_issuer::AppendLimits, records: Vec<stack_issuer::IssuanceRecord>) -> Vec<Result<(), stack_issuer::LogError>> {
    let dir = TempDir::new("race");
    let log = std::sync::Arc::new(FileIssuanceLog::open(&dir.file("issuance.jsonl")).unwrap());
    let barrier = std::sync::Arc::new(std::sync::Barrier::new(records.len()));
    let handles: Vec<_> = records
        .into_iter()
        .map(|r| {
            let (log, barrier) = (log.clone(), barrier.clone());
            std::thread::spawn(move || {
                barrier.wait();
                log.append(&r, &limits)
            })
        })
        .collect();
    handles.into_iter().map(|h| h.join().unwrap()).collect()
}

#[test]
fn the_subject_limit_is_exact_under_concurrent_appends_with_different_decision_roots() {
    for _ in 0..30 {
        let limits = stack_issuer::AppendLimits { per_decision: 100, per_subject: 3, distinct_decisions: 100 };
        let results = race(limits, (0..8u8).map(|i| record_with(i + 1, 9)).collect());
        assert_eq!(results.iter().filter(|r| r.is_ok()).count(), 3);
        assert!(results.iter().filter_map(|r| r.as_ref().err()).all(|e| *e == stack_issuer::LogError::SubjectLimit));
    }
}

#[test]
fn the_distinct_decision_limit_is_exact_under_concurrent_appends_with_different_subjects() {
    for _ in 0..30 {
        let limits = stack_issuer::AppendLimits { per_decision: 100, per_subject: 100, distinct_decisions: 3 };
        let results = race(limits, (0..8u8).map(|i| record_with(i + 1, i + 1)).collect());
        assert_eq!(results.iter().filter(|r| r.is_ok()).count(), 3);
        assert!(results.iter().filter_map(|r| r.as_ref().err()).all(|e| *e == stack_issuer::LogError::DistinctDecisionsLimit));
    }
}

// ---- the limit errors the log reports at append time ------------------------------------------------------

/// A log that reports nothing used, so the issuer's own look at the counts passes and the limit is
/// found only by the atomic append: what two racing callers would see.
#[derive(Debug, Clone, Default)]
struct BlindUsage(SharedLog);

impl IssuanceLog for BlindUsage {
    fn is_durable(&self) -> bool {
        true
    }
    fn usage(&self, _: &str, _: &str) -> Result<stack_issuer::Usage, stack_issuer::LogError> {
        Ok(stack_issuer::Usage { decision: 0, decision_known: false, subject: 0, distinct_decisions: 0 })
    }
    fn append(&self, r: &stack_issuer::IssuanceRecord, l: &stack_issuer::AppendLimits) -> Result<(), stack_issuer::LogError> {
        self.0.append(r, l)
    }
    fn reset_decision(&self, r: &stack_issuer::ResetRecord) -> Result<u32, stack_issuer::LogError> {
        self.0.reset_decision(r)
    }
}

#[test]
fn each_limit_the_log_finds_at_append_time_reaches_the_caller_as_itself() {
    let (a, other) = (case("all_pass"), case("other_subject_all_pass"));
    // decision
    let issuer = issuer_with_log(BlindUsage::default(), caps(1, 100, 100));
    issuer.issue(&request(&a)).unwrap();
    assert!(matches!(issuer.issue(&request(&a)), Err(IssueError::DecisionLimit)));
    // subject
    let issuer = issuer_with_log(BlindUsage::default(), caps(100, 1, 100));
    issuer.issue(&request(&a)).unwrap();
    assert!(matches!(issuer.issue(&relabelled(&a, "x")), Err(IssueError::SubjectLimit)));
    // distinct decisions
    let issuer = issuer_with_log(BlindUsage::default(), caps(100, 100, 1));
    issuer.issue(&request(&a)).unwrap();
    assert!(matches!(issuer.issue(&request(&other)), Err(IssueError::DistinctDecisionsLimit)));
}
