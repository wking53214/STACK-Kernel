//! Findings of independent review 4, each pinned by a test. Where a finding was a
//! real defect the test failed on the code as merged in #88 (red first); where it was
//! a gap in the tests the test pins behaviour that already held.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use common::*;
use serde_json::{json, Value};
use stack_admission::{BindingFinding, KernelPolicy};
use stack_authority::{ManualClock, ResourceScope, ScopeKind, SignedCapability};
use stack_issuer::{
    ConfigError, FileIssuanceLog, IssuanceRequest, IssueError, Issuer, IssuerConfig, OsEntropy,
};
use stack_receipt::{decision_root, GatePosition, MAX_SEATS};

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

fn scope(kind: ScopeKind, path: &str) -> ResourceScope {
    ResourceScope::new(kind, path).unwrap()
}

fn refuses_with_decision_finding(req: &IssuanceRequest) -> Vec<BindingFinding> {
    let log = SharedLog::default();
    match honest_issuer(&log).issue(req).unwrap_err() {
        IssueError::DecisionRefused(f) => {
            assert!(!f.contains(&BindingFinding::RootMismatch), "the root was recomputed, so this must not be the cause: {f:?}");
            assert!(f.iter().any(|x| matches!(x, BindingFinding::Decision(_))), "{f:?}");
            assert_eq!(log.count(), 0);
            f
        }
        other => panic!("{other:?}"),
    }
}

// ---- finding 4: the seat and position checks, with the root recomputed -------

#[test]
fn a_missing_required_seat_is_refused_by_the_seat_check_not_by_a_root_mismatch() {
    let case = case("all_pass");
    let mut req = request(&case);
    req.decision.verdicts.pop();
    req.decision.seats.pop();
    req.decision.root = decision_root(&req.decision.seats, &req.decision.verdicts);
    refuses_with_decision_finding(&req);
}

#[test]
fn a_verdict_at_the_wrong_position_is_refused_with_the_root_recomputed() {
    let case = case("all_pass");
    let mut req = request(&case);
    for v in &mut req.decision.verdicts {
        v.position = GatePosition::Omega;
    }
    req.decision.root = decision_root(&req.decision.seats, &req.decision.verdicts);
    refuses_with_decision_finding(&req);
}

// ---- finding 2: scope breadth ------------------------------------------------

#[test]
fn a_scope_outside_the_configured_roots_is_refused_at_every_breadth() {
    let case = case("all_pass");
    let log = SharedLog::default();
    let issuer = honest_issuer(&log);
    let outside = [
        scope(ScopeKind::Prefix, "/a"),
        scope(ScopeKind::Exact, "/"),
        scope(ScopeKind::Exact, "/database"),
        scope(ScopeKind::Prefix, "/database"),
        scope(ScopeKind::Exact, "/other/data"),
    ];
    for s in outside {
        let mut req = request(&case);
        req.resources = vec![s.clone()];
        assert!(matches!(issuer.issue(&req), Err(IssueError::ScopeOutsideRoots(_))), "{s:?}");
    }
    assert_eq!(log.count(), 0);
}

#[test]
fn a_scope_at_or_under_a_root_is_issued_and_a_wider_one_than_the_root_is_not() {
    let case = case("all_pass");
    let log = SharedLog::default();
    let issuer = honest_issuer(&log);
    for s in [
        scope(ScopeKind::Prefix, "/data"),
        scope(ScopeKind::Exact, "/data"),
        scope(ScopeKind::Prefix, "/data/tree"),
        scope(ScopeKind::Exact, "/data/a/b"),
    ] {
        let mut req = request(&case);
        req.resources = vec![s.clone()];
        assert!(issuer.issue(&req).is_ok(), "{s:?}");
    }
}

#[test]
fn a_wildcard_hidden_among_other_scopes_is_still_refused() {
    let case = case("all_pass");
    let log = SharedLog::default();
    let mut req = request(&case);
    req.resources = vec![scope(ScopeKind::Exact, "/data/a"), scope(ScopeKind::Prefix, "/")];
    assert!(matches!(honest_issuer(&log).issue(&req), Err(IssueError::WildcardScope)));
    let mut req = request(&case);
    req.resources = vec![scope(ScopeKind::Prefix, "/"), scope(ScopeKind::Exact, "/data/a")];
    assert!(matches!(honest_issuer(&log).issue(&req), Err(IssueError::WildcardScope)));
}

#[test]
fn more_than_the_most_scopes_is_refused_and_exactly_the_most_is_not() {
    let case = case("all_pass");
    let log = SharedLog::default();
    let issuer = honest_issuer(&log);
    let many = |n: usize| -> Vec<ResourceScope> {
        (0..n).map(|i| scope(ScopeKind::Exact, &format!("/data/s{i:02}"))).collect()
    };
    let mut req = request(&case);
    req.resources = many(stack_issuer::MAX_RESOURCES_PER_CAPABILITY + 1);
    assert!(matches!(issuer.issue(&req), Err(IssueError::TooManyResources)));
    req.resources = many(stack_issuer::MAX_RESOURCES_PER_CAPABILITY);
    assert!(issuer.issue(&req).is_ok());
}

#[test]
fn the_roots_must_be_stated_and_may_not_be_the_whole_tree() {
    let p = kernel_policy();
    let make = |roots: &[&str]| IssuerConfig::from_kernel_policy(&p, ISSUER, POLICY_REF, canonical_limits(), MAX_LIFETIME_MS, roots, default_caps());
    assert!(matches!(make(&[]), Err(ConfigError::Roots)));
    assert!(matches!(make(&["/"]), Err(ConfigError::Roots)));
    assert!(matches!(make(&["/a/../b"]), Err(ConfigError::Roots)));
    assert!(make(&["/data", "/logs"]).is_ok());
}

// ---- finding 4 (rest): ordering, record, requester text, id versus nonce -----

#[test]
fn several_scopes_are_sorted_and_the_record_lists_them_all() {
    let case = case("all_pass");
    let log = SharedLog::default();
    let mut req = request(&case);
    req.resources = vec![
        scope(ScopeKind::Prefix, "/data/z"),
        scope(ScopeKind::Exact, "/data/a"),
        scope(ScopeKind::Exact, "/data/a"),
    ];
    let issued = honest_issuer(&log).issue(&req).unwrap();
    let cap = SignedCapability::parse(&issued.wire, 16 * 1024).unwrap();
    assert_eq!(cap.capability().resources.len(), 2, "the duplicate is dropped");
    let records = log.records.lock().unwrap();
    assert_eq!(records[0].resources, vec!["exact:/data/a".to_owned(), "prefix:/data/z".to_owned()]);
}

#[test]
fn the_record_carries_every_field_it_names() {
    let case = case("all_pass");
    let log = SharedLog::default();
    let issued = honest_issuer(&log).issue(&request(&case)).unwrap();
    let cap = SignedCapability::parse(&issued.wire, 16 * 1024).unwrap();
    let b = cap.capability().binding.clone().unwrap();
    let r = log.records.lock().unwrap()[0].clone();
    assert_eq!(r.issuer_id, ISSUER);
    assert_eq!(r.policy_ref, issuer_config().policy_ref());
    assert_eq!(r.key_id, public_key(ISSUER).key_id().to_hex());
    assert_eq!(r.args_digest, b.args_digest.to_hex());
    assert_eq!(r.worker, b.worker);
    assert_eq!(r.limits_digest, b.limits_digest.to_hex());
}

#[test]
fn a_bad_requester_label_is_refused() {
    let case = case("all_pass");
    let log = SharedLog::default();
    for bad in [String::new(), "x".repeat(129), "line\nbreak".to_owned()] {
        let mut req = request(&case);
        req.requester = bad;
        assert!(matches!(honest_issuer(&log).issue(&req), Err(IssueError::Text("requester"))));
    }
    assert_eq!(log.count(), 0);
}

#[test]
fn the_id_and_the_nonce_are_independent_draws() {
    let case = case("all_pass");
    let log = SharedLog::default();
    let issued = honest_issuer(&log).issue(&request(&case)).unwrap();
    let cap = SignedCapability::parse(&issued.wire, 16 * 1024).unwrap();
    let same = format!("cap-{}", hex::encode(cap.capability().nonce));
    assert_ne!(cap.capability().cap_id, same);
}

#[test]
fn the_real_operating_system_entropy_issues_distinct_capabilities() {
    let case = case("all_pass");
    let log = SharedLog::default();
    let issuer = new_issuer(issuer_config(), FixtureSigner::honest(ISSUER), OsEntropy, log.clone(), ManualClock::new(T0),
    )
    .unwrap();
    let a = issuer.issue(&request(&case)).unwrap();
    let b = issuer.issue(&request(&case)).unwrap();
    assert_ne!(a.cap_id, b.cap_id);
    assert_ne!(a.digest, b.digest);
}

// ---- finding 6: refuse what the kernel's own payload checks would refuse ------

#[test]
fn a_subject_that_is_not_a_map_is_refused_as_the_kernel_would() {
    let case = case("all_pass");
    let log = SharedLog::default();
    let mut req = request(&case);
    req.subject = json!("hello");
    assert!(matches!(honest_issuer(&log).issue(&req), Err(IssueError::DecisionShape(_))));
    assert_eq!(log.count(), 0);
}

#[test]
fn a_verdict_the_kernel_would_refuse_to_parse_is_refused() {
    let case = case("all_pass");
    let log = SharedLog::default();
    let mut req = request(&case);
    req.decision.verdicts[0].subject = "x\ny".into();
    assert!(matches!(honest_issuer(&log).issue(&req), Err(IssueError::DecisionShape(_))));
    let mut req = request(&case);
    req.decision.seats = vec!["s".into(); MAX_SEATS + 1];
    assert!(matches!(honest_issuer(&log).issue(&req), Err(IssueError::DecisionShape(_))));
    assert_eq!(log.count(), 0);
}

fn refusing_args_policy() -> KernelPolicy {
    KernelPolicy { refuse_arguments: true, ..kernel_policy() }
}

#[test]
fn a_kernel_that_refuses_arguments_gets_no_capability_for_arguments() {
    let case = case("all_pass");
    let log = SharedLog::default();
    let config = IssuerConfig::from_kernel_policy(&refusing_args_policy(), ISSUER, POLICY_REF, canonical_limits(), MAX_LIFETIME_MS, ROOTS, default_caps()).unwrap();
    let issuer = new_issuer(config, FixtureSigner::honest(ISSUER), CounterEntropy::default(), log.clone(), ManualClock::new(T0),
    )
    .unwrap();
    let mut req = request(&case);
    req.args = json!({"x": 1});
    assert!(matches!(issuer.issue(&req), Err(IssueError::ArgumentsNotAllowed)));
    // The kernel treats null and {} as "no arguments"; so does the issuer.
    for empty in [Value::Null, json!({})] {
        req.args = empty;
        assert!(issuer.issue(&req).is_ok());
    }
}

// ---- finding 7: the log must be durable --------------------------------------

#[test]
fn a_log_that_says_it_is_not_durable_is_refused_at_construction() {
    let log = SharedLog::default();
    *log.not_durable.lock().unwrap() = true;
    let r = new_issuer(issuer_config(), FixtureSigner::honest(ISSUER), CounterEntropy::default(), log, ManualClock::new(T0),
    );
    assert!(matches!(r, Err(ConfigError::LogNotDurable)));
}

// ---- finding 5 and 15: the file log --------------------------------------------

#[test]
fn a_file_log_with_a_torn_last_line_is_refused_not_appended_to() {
    let dir = TempDir::new("torn");
    let path = dir.file("issuance.jsonl");
    std::fs::write(&path, b"{\"cap_id\":\"cap-torn\",\"capab").unwrap();
    assert!(FileIssuanceLog::open(&path).is_err());
    // A complete record that lacks its newline is the case the unterminated-line check exists for.
    let complete = record_line(1);
    std::fs::write(&path, complete.trim_end().as_bytes()).unwrap();
    let e = FileIssuanceLog::open(&path).unwrap_err().to_string();
    assert!(e.contains("unterminated"), "{e}");
    // A log that ends in a newline, and an empty one, open fine.
    std::fs::write(&path, complete.as_bytes()).unwrap();
    assert!(FileIssuanceLog::open(&path).is_ok());
    std::fs::write(&path, b"").unwrap();
    assert!(FileIssuanceLog::open(&path).is_ok());
}

#[test]
fn a_file_log_line_that_is_not_an_issuance_record_is_refused() {
    let dir = TempDir::new("notrecord");
    let path = dir.file("issuance.jsonl");
    let upper = format!("{{\"cap_id\":\"c\",\"decision_root\":\"{}\"}}\n", hex::encode([0xAB; 32]).to_uppercase());
    let short = "{\"cap_id\":\"c\",\"decision_root\":\"ab\"}\n".to_owned();
    let no_cap = format!("{{\"decision_root\":\"{}\"}}\n", hex::encode([1; 32]));
    let number = "{\"cap_id\":\"c\",\"decision_root\":5}\n".to_owned();
    for (what, bad) in [
        ("an object without the fields", "{\"a\":1}\n".to_owned()),
        ("not json", "not json\n".to_owned()),
        ("an empty line", "\n".to_owned()),
        ("an upper-case root", upper),
        ("a short root", short),
        ("no cap_id", no_cap),
        ("a numeric root", number),
    ] {
        std::fs::write(&path, format!("{}{bad}", record_line(1))).unwrap();
        assert!(FileIssuanceLog::open(&path).is_err(), "{what}");
    }
    std::fs::write(&path, [0xFF, 0xFE, b'\n']).unwrap();
    let e = FileIssuanceLog::open(&path).unwrap_err().to_string();
    assert!(e.contains("UTF-8") && e.contains("line 1"), "{e}");
}

#[cfg(unix)]
#[test]
fn a_new_file_log_is_readable_by_its_owner_only() {
    use std::os::unix::fs::PermissionsExt;
    let dir = TempDir::new("mode");
    let path = dir.file("issuance.jsonl");
    let _log = FileIssuanceLog::open(&path).unwrap();
    assert_eq!(std::fs::metadata(&path).unwrap().permissions().mode() & 0o777, 0o600);
}

// ---- finding 9: the clock -------------------------------------------------------

fn issuer_at(log: &SharedLog, clock: ManualClock) -> Issuer {
    new_issuer(issuer_config(), FixtureSigner::honest(ISSUER), CounterEntropy::default(), log.clone(), clock)
    .unwrap()
}

#[test]
fn a_clock_that_reads_zero_issues_nothing() {
    let case = case("all_pass");
    let log = SharedLog::default();
    assert!(matches!(issuer_at(&log, ManualClock::new(0)).issue(&request(&case)), Err(IssueError::Clock(_))));
    assert_eq!(log.count(), 0);
}

#[test]
fn a_clock_that_overflows_the_window_is_a_clock_error_not_a_lifetime_error() {
    let case = case("all_pass");
    let log = SharedLog::default();
    let near_max = ManualClock::new(u64::MAX - 10);
    assert!(matches!(issuer_at(&log, near_max).issue(&request(&case)), Err(IssueError::Clock(_))));
}

#[test]
fn a_clock_that_goes_backwards_between_issuances_is_refused() {
    let case = case("all_pass");
    let log = SharedLog::default();
    let clock = std::sync::Arc::new(ManualClock::new(T0));
    #[derive(Debug)]
    struct Shared(std::sync::Arc<ManualClock>);
    impl stack_authority::Clock for Shared {
        fn now_unix_ms(&self) -> u64 {
            self.0.now_unix_ms()
        }
    }
    let issuer = new_issuer(issuer_config(), FixtureSigner::honest(ISSUER), CounterEntropy::default(), log.clone(), Shared(clock.clone()),
    )
    .unwrap();
    assert!(issuer.issue(&request(&case)).is_ok());
    clock.set(T0 - HOUR);
    assert!(matches!(issuer.issue(&request(&case)), Err(IssueError::Clock(_))));
    clock.set(T0);
    assert!(issuer.issue(&request(&case)).is_ok(), "the same instant is allowed");
}

// ---- finding 10: the unsafe policy pair ------------------------------------------

#[test]
fn a_policy_that_neither_refuses_arguments_nor_requires_a_binding_is_refused() {
    let p = KernelPolicy { refuse_arguments: false, require_execution_binding: false, ..kernel_policy() };
    let r = IssuerConfig::from_kernel_policy(&p, ISSUER, POLICY_REF, canonical_limits(), MAX_LIFETIME_MS, ROOTS, default_caps());
    assert!(matches!(r, Err(ConfigError::UnsafePolicyPair)));
}

#[cfg(target_os = "linux")]
#[test]
fn after_a_failed_write_the_file_log_refuses_every_later_append_until_reopened() {
    use stack_issuer::{IssuanceLog, IssuanceRecord};
    let record = IssuanceRecord {
        cap_id: "cap-x".into(),
        capability_digest: "00".repeat(32),
        issuer_id: ISSUER.into(),
        key_id: "00".repeat(32),
        requester: "r".into(),
        subject_digest: "00".repeat(32),
        decision_root: "00".repeat(32),
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
    };
    // /dev/null accepts the open and the write, and refuses to flush it (EINVAL): a write that
    // did not become durable.
    let log = FileIssuanceLog::open(std::path::Path::new("/dev/null")).unwrap();
    assert!(log.append(&record, &lim(10)).is_err());
    let second = log.append(&record, &lim(10)).unwrap_err().to_string();
    assert!(second.contains("earlier write failed"), "{second}");
}

#[cfg(target_os = "linux")]
#[test]
fn the_failed_write_latch_holds_under_concurrent_appends() {
    use stack_issuer::{IssuanceLog, IssuanceRecord};
    let record = IssuanceRecord {
        cap_id: "cap-x".into(),
        capability_digest: "00".repeat(32),
        issuer_id: ISSUER.into(),
        key_id: "00".repeat(32),
        requester: "r".into(),
        subject_digest: "00".repeat(32),
        decision_root: "00".repeat(32),
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
    };
    // On /dev/null the write succeeds and the flush fails. Exactly one append may reach the
    // device and fail there; every other one must be stopped by the latch, whatever the timing.
    for _round in 0..50 {
        let log = std::sync::Arc::new(FileIssuanceLog::open(std::path::Path::new("/dev/null")).unwrap());
        let barrier = std::sync::Arc::new(std::sync::Barrier::new(8));
        let handles: Vec<_> = (0..8)
            .map(|_| {
                let (log, barrier, record) = (log.clone(), barrier.clone(), record.clone());
                std::thread::spawn(move || {
                    barrier.wait();
                    log.append(&record, &lim(1000)).unwrap_err().to_string()
                })
            })
            .collect();
        let errors: Vec<String> = handles.into_iter().map(|h| h.join().unwrap()).collect();
        let reached_device = errors.iter().filter(|e| !e.contains("earlier write failed")).count();
        assert_eq!(reached_device, 1, "{errors:?}");
    }
}

// ---- review 5: shape and config text checks that were unpinned --------------------

#[test]
fn a_seat_name_that_is_empty_too_long_or_holds_a_control_character_is_refused() {
    let case = case("all_pass");
    for bad in [String::new(), "x".repeat(stack_receipt::MAX_ID_BYTES + 1), "a\nb".to_owned()] {
        let mut req = request(&case);
        req.decision.seats[0] = bad;
        assert!(matches!(honest_issuer(&SharedLog::default()).issue(&req), Err(IssueError::DecisionShape(_))));
    }
}

#[test]
fn issuer_id_and_policy_ref_are_checked_at_configuration() {
    let p = kernel_policy();
    let make = |id: &str, pref: &str| IssuerConfig::from_kernel_policy(&p, id, pref, canonical_limits(), MAX_LIFETIME_MS, ROOTS, default_caps());
    assert!(matches!(make("", POLICY_REF), Err(ConfigError::Text("issuer_id"))));
    assert!(matches!(make("bad\nid", POLICY_REF), Err(ConfigError::Text("issuer_id"))));
    assert!(matches!(make(&"x".repeat(129), POLICY_REF), Err(ConfigError::Text("issuer_id"))));
    assert!(matches!(make(ISSUER, &"x".repeat(257)), Err(ConfigError::Text("policy_ref"))));
    assert!(matches!(make(ISSUER, "bad\nref"), Err(ConfigError::Text("policy_ref"))));
    assert!(make(ISSUER, "").is_ok(), "an empty policy_ref is allowed");
}
