//! Findings of independent review 6, each pinned. Where the finding was a real defect
//! the test failed on the code as merged in #91; where it was an unpinned behaviour the
//! test passes on that code and fails on a named mutation.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use std::sync::atomic::Ordering;
use std::sync::Arc;

use common::*;
use serde_json::{json, Value};
use stack_authority::{ManualClock, ResourceScope, ScopeKind};
use stack_issuer::{
    ConfigError, FileIssuanceLog, IssuanceLog, IssuanceRecord, IssuanceRequest, IssueError, Issuer, IssuerConfig,
    MAX_RECORD_LINE_BYTES,
};
use stack_receipt::MAX_SEATS;

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

fn file_issuer(path: &std::path::Path, limit: u32) -> Issuer {
    new_issuer(
        config_with_limit(limit),
        FixtureSigner::honest(ISSUER),
        CounterEntropy::default(),
        FileIssuanceLog::open(path).unwrap(),
        ManualClock::new(T0),
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

// ---- F1: the lock belongs to the inode, so the handle checks the path still names it ----

#[cfg(unix)]
#[test]
fn a_log_renamed_while_open_stops_accepting_appends() {
    let dir = TempDir::new("rename");
    let (path, moved) = (dir.file("issuance.jsonl"), dir.file("moved.jsonl"));
    let log = FileIssuanceLog::open(&path).unwrap();
    let root = "ab".repeat(32);
    log.append(&record_for(&root), 5).unwrap();
    std::fs::rename(&path, &moved).unwrap();
    let e = log.append(&record_for(&root), 5).unwrap_err().to_string();
    assert!(e.contains("renamed, replaced or removed"), "{e}");
    // The handle stays latched, even if the path comes back.
    std::fs::copy(&moved, &path).unwrap();
    assert!(log.append(&record_for(&root), 5).is_err());
}

#[cfg(unix)]
#[test]
fn a_log_removed_or_replaced_while_open_stops_accepting_appends() {
    let dir = TempDir::new("unlink");
    let path = dir.file("issuance.jsonl");
    let log = FileIssuanceLog::open(&path).unwrap();
    std::fs::remove_file(&path).unwrap();
    assert!(log.append(&record_for(&"ab".repeat(32)), 5).is_err(), "removed");
    let dir2 = TempDir::new("replace");
    let path2 = dir2.file("issuance.jsonl");
    let log2 = FileIssuanceLog::open(&path2).unwrap();
    std::fs::remove_file(&path2).unwrap();
    std::fs::write(&path2, b"").unwrap();
    assert!(log2.append(&record_for(&"cd".repeat(32)), 5).is_err(), "replaced by another file");
}

// ---- F2: history segments are read under a shared lock and checked ----------------

#[test]
fn a_history_segment_held_by_a_running_issuer_makes_the_open_fail_until_it_stops() {
    let dir = TempDir::new("histlock");
    let (old, new) = (dir.file("old.jsonl"), dir.file("new.jsonl"));
    let running = FileIssuanceLog::open(&old).unwrap();
    let e = FileIssuanceLog::open_with_history(&new, &[old.as_path()]).unwrap_err().to_string();
    assert!(e.contains("in use"), "{e}");
    drop(running);
    assert!(FileIssuanceLog::open_with_history(&new, &[old.as_path()]).is_ok());
}

#[test]
fn history_listed_twice_the_live_file_listed_and_a_device_are_all_refused() {
    let dir = TempDir::new("histbad");
    let (old, new) = (dir.file("old.jsonl"), dir.file("new.jsonl"));
    std::fs::write(&old, record_line(1)).unwrap();
    assert!(FileIssuanceLog::open_with_history(&new, &[old.as_path(), old.as_path()]).is_err(), "twice");
    std::fs::write(&new, record_line(2)).unwrap();
    assert!(FileIssuanceLog::open_with_history(&new, &[new.as_path()]).is_err(), "the live file as its own history");
    #[cfg(target_os = "linux")]
    assert!(FileIssuanceLog::open_with_history(&new, &[std::path::Path::new("/dev/null")]).is_err(), "a device");
}

#[test]
fn a_bad_history_segment_does_not_create_the_live_file() {
    let dir = TempDir::new("historder");
    let new = dir.file("new.jsonl");
    assert!(FileIssuanceLog::open_with_history(&new, &[dir.file("missing.jsonl").as_path()]).is_err());
    assert!(!new.exists(), "the live file was created before the history was validated");
}

#[test]
fn several_history_segments_and_the_live_file_all_count() {
    let dir = TempDir::new("histsum");
    let (a, b, live) = (dir.file("a.jsonl"), dir.file("b.jsonl"), dir.file("live.jsonl"));
    std::fs::write(&a, record_line(7)).unwrap();
    std::fs::write(&b, format!("{}{}", record_line(7), record_line(8))).unwrap();
    std::fs::write(&live, record_line(7)).unwrap();
    let log = FileIssuanceLog::open_with_history(&live, &[a.as_path(), b.as_path()]).unwrap();
    assert_eq!(log.issued_for_decision(&hex::encode([7u8; 32])).unwrap(), 3, "a + b + live");
    assert_eq!(log.issued_for_decision(&hex::encode([8u8; 32])).unwrap(), 1);
}

// ---- F3: a handle used by another process is latched (unit test in log.rs) ---------

// ---- F4: the clock guard ------------------------------------------------------------

#[test]
fn a_failed_request_with_a_wild_clock_reading_does_not_block_the_issuer_afterwards() {
    let case = case("all_pass");
    #[derive(Debug)]
    struct Shared(Arc<ManualClock>);
    impl stack_authority::Clock for Shared {
        fn now_unix_ms(&self) -> u64 {
            self.0.now_unix_ms()
        }
    }
    let clock = Arc::new(ManualClock::new(T0 + 10 * 365 * 24 * HOUR));
    let signer = FixtureSigner::failing(ISSUER);
    let fail_flag = signer.signs.clone();
    let log = SharedLog::default();
    // First: a reading ten years ahead, and a signer that fails.
    let bad = new_issuer(issuer_config(), signer, CounterEntropy::default(), log.clone(), Shared(clock.clone())).unwrap();
    assert!(matches!(bad.issue(&request(&case)), Err(IssueError::Signer(_))));
    assert_eq!(fail_flag.load(Ordering::SeqCst), 1);
    // The same issuer value cannot swap its signer, so use one with a working signer and the
    // same clock behaviour: a wild reading that fails later must not poison the guard.
    let good = new_issuer(issuer_config(), FixtureSigner::honest(ISSUER), CounterEntropy::default(), log.clone(), Shared(clock.clone())).unwrap();
    let mut over = request(&case);
    over.lifetime_ms = 60_000;
    clock.set(u64::MAX - 10);
    assert!(matches!(good.issue(&over), Err(IssueError::Clock(_))), "the window would overflow");
    clock.set(T0);
    assert!(good.issue(&over).is_ok(), "an overflowing reading did not poison the guard");
    assert_eq!(log.count(), 1);
}

#[test]
fn two_threads_reading_the_clock_are_ordered_and_neither_is_refused() {
    let case = case("all_pass");
    #[derive(Debug)]
    struct Staggered(std::sync::atomic::AtomicU64);
    impl stack_authority::Clock for Staggered {
        fn now_unix_ms(&self) -> u64 {
            let n = self.0.fetch_add(1, Ordering::SeqCst);
            if n == 0 {
                std::thread::sleep(std::time::Duration::from_millis(300));
            }
            T0 + n * 10
        }
    }
    let log = SharedLog::default();
    let issuer = Arc::new(
        new_issuer(issuer_config(), FixtureSigner::honest(ISSUER), CounterEntropy::default(), log.clone(), Staggered(Default::default())).unwrap(),
    );
    let handles: Vec<_> = (0..2)
        .map(|_| {
            let (issuer, req) = (issuer.clone(), request(&case));
            std::thread::spawn(move || issuer.issue(&req).is_ok())
        })
        .collect();
    let ok = handles.into_iter().map(|h| h.join().unwrap()).filter(|b| *b).count();
    assert_eq!(ok, 2, "a thread that read an earlier time was refused as if the clock had gone backwards");
}

// ---- F5, F6: what append writes and what open accepts ----------------------------------

#[test]
fn a_record_the_log_could_not_read_back_is_refused_before_it_is_written() {
    let dir = TempDir::new("unreadable");
    let path = dir.file("issuance.jsonl");
    let log = FileIssuanceLog::open(&path).unwrap();
    assert!(log.append(&record_for(&"AB".repeat(32)), 5).is_err(), "upper-case root");
    assert!(log.append(&record_for("ab"), 5).is_err(), "short root");
    let mut huge = record_for(&"ab".repeat(32));
    huge.requester = "x".repeat(MAX_RECORD_LINE_BYTES);
    assert!(log.append(&huge, 5).is_err(), "over the line limit");
    assert_eq!(std::fs::read_to_string(&path).unwrap(), "", "nothing was written");
    log.append(&record_for(&"ab".repeat(32)), 5).unwrap();
    drop(log);
    assert!(FileIssuanceLog::open(&path).is_ok(), "and the log reopens");
}

#[test]
fn a_symlink_and_a_fifo_are_refused_as_a_log_path() {
    let dir = TempDir::new("special");
    let target = dir.file("real.jsonl");
    let link = dir.file("link.jsonl");
    std::fs::write(&target, b"").unwrap();
    #[cfg(unix)]
    {
        std::os::unix::fs::symlink(&target, &link).unwrap();
        assert!(FileIssuanceLog::open(&link).is_err(), "symlink");
        let fifo = dir.file("fifo");
        if std::process::Command::new("mkfifo").arg(&fifo).status().is_ok_and(|s| s.success()) {
            // Opening a FIFO blocks, so do it on a thread and fail the test instead of hanging it.
            let (tx, rx) = std::sync::mpsc::channel();
            std::thread::spawn(move || {
                let _ = tx.send(FileIssuanceLog::open(&fifo).is_err());
            });
            let refused = rx.recv_timeout(std::time::Duration::from_secs(5)).expect("open blocked on a FIFO");
            assert!(refused, "fifo");
        }
    }
    assert!(FileIssuanceLog::open(&target).is_ok());
}

#[cfg(target_os = "linux")]
#[test]
fn a_log_on_a_device_is_not_durable_and_the_issuer_refuses_it() {
    let log = FileIssuanceLog::open(std::path::Path::new("/dev/null")).unwrap();
    assert!(!log.is_durable());
    let r = Issuer::new(
        issuer_config(),
        Box::new(FixtureSigner::honest(ISSUER)),
        Box::new(CounterEntropy::default()),
        Box::new(log),
        Box::new(ManualClock::new(T0)),
        Box::new(FixtureAllowAllVerifier::default()),
        Box::new(FixtureAuthorizer::default()),
    );
    assert!(matches!(r, Err(ConfigError::LogNotDurable)));
    let dir = TempDir::new("regular");
    assert!(FileIssuanceLog::open(&dir.file("a.jsonl")).unwrap().is_durable());
}

// ---- F8, F9: error text and Debug -------------------------------------------------------

#[test]
fn error_text_is_neutral_and_the_detail_is_for_the_operator() {
    let case = case("all_pass");
    let log = SharedLog::default();
    let mut req = request(&case);
    req.decision.verdicts.pop();
    req.decision.seats.pop();
    req.decision.root = stack_receipt::decision_root(&req.decision.seats, &req.decision.verdicts);
    let e = honest_issuer(&log).issue(&req).unwrap_err();
    assert_eq!(e.to_string(), "decision refused");
    assert!(e.detail().unwrap().contains("RequiredSeatMissing"));

    let a = FixtureAuthorizer { allow: Some(vec![]), ..Default::default() };
    let issuer = new_issuer_with(a, FixtureAllowAllVerifier::default());
    let e = issuer.issue(&request(&case)).unwrap_err();
    assert_eq!(e.to_string(), "not authorized");
    assert_eq!(e.detail().as_deref(), Some("fixture authorizer denies"));
    assert!(IssueError::WildcardScope.detail().is_none());
}

fn new_issuer_with(a: FixtureAuthorizer, v: FixtureAllowAllVerifier) -> Issuer {
    Issuer::new(
        issuer_config(),
        Box::new(FixtureSigner::honest(ISSUER)),
        Box::new(CounterEntropy::default()),
        Box::new(SharedLog::default()),
        Box::new(ManualClock::new(T0)),
        Box::new(v),
        Box::new(a),
    )
    .unwrap()
}

#[test]
fn debug_output_does_not_print_the_capability_or_the_request_content() {
    let case = case("all_pass");
    let issued = honest_issuer(&SharedLog::default()).issue(&request(&case)).unwrap();
    let shown = format!("{issued:?}");
    assert!(shown.contains(&issued.cap_id) && shown.len() < 300, "{shown}");
    assert!(!shown.contains("115, 116, 97, 99, 107"), "the wire bytes are printed");
    let mut req = request(&case);
    req.args = json!({"secret-argument": "hunter2"});
    let shown = format!("{req:?}");
    assert!(!shown.contains("hunter2") && !shown.contains("secret-argument"), "{shown}");
}

#[test]
fn the_authorizer_is_given_the_arguments_as_requested() {
    let case = case("all_pass");
    let a = FixtureAuthorizer::default();
    let seen = a.seen.clone();
    let issuer = new_issuer_with(a, FixtureAllowAllVerifier::default());
    issuer.issue(&request(&case)).unwrap();
    assert_eq!(seen.lock().unwrap()[0].args, json!({"target": "a"}).to_string());
}

// ---- F10: pins for what survived ------------------------------------------------------------

#[test]
fn the_file_log_writes_every_field_of_the_record_to_disk() {
    let dir = TempDir::new("keys");
    let path = dir.file("issuance.jsonl");
    let case = case("all_pass");
    let issued = file_issuer(&path, 5).issue(&request(&case)).unwrap();
    let line: Value = serde_json::from_str(std::fs::read_to_string(&path).unwrap().lines().next().unwrap()).unwrap();
    let want = json!({
        "cap_id": issued.cap_id,
        "capability_digest": issued.digest.to_hex(),
        "issuer_id": ISSUER,
        "key_id": public_key(ISSUER).key_id().to_hex(),
        "requester": "requester-1",
        "subject_digest": case["subject_digest"],
        "decision_root": case["root"],
        "operation": "echo",
        "resources": ["exact:/data/a"],
        "not_before_ms": T0,
        "expires_at_ms": T0 + 60_000,
        "issued_at_ms": T0,
        "one_time": true,
        "policy_ref": POLICY_REF,
    });
    for (k, v) in want.as_object().unwrap() {
        assert_eq!(&line[k], v, "{k}");
    }
    for k in ["args_digest", "limits_digest"] {
        assert_eq!(line[k].as_str().unwrap().len(), 64, "{k}");
    }
    assert_eq!(line["worker"], "return_bytes");
    assert_eq!(line.as_object().unwrap().len(), 17, "no key added or dropped");
}

#[cfg(unix)]
#[test]
fn an_external_truncation_does_not_leave_a_hole_before_the_next_record() {
    let dir = TempDir::new("append");
    let path = dir.file("issuance.jsonl");
    let log = FileIssuanceLog::open(&path).unwrap();
    log.append(&record_for(&"ab".repeat(32)), 9).unwrap();
    std::fs::OpenOptions::new().write(true).open(&path).unwrap().set_len(0).unwrap();
    log.append(&record_for(&"cd".repeat(32)), 9).unwrap();
    let text = std::fs::read_to_string(&path).unwrap();
    assert!(!text.contains('\0'), "the record was written at the old offset");
    assert_eq!(text.lines().count(), 1);
}

#[test]
fn exact_length_limits_are_accepted_and_one_more_is_refused() {
    let case = case("all_pass");
    let log = SharedLog::default();
    let issuer = honest_issuer(&log);
    let mut req = request(&case);
    req.requester = "r".repeat(128);
    assert!(issuer.issue(&req).is_ok(), "a 128-byte requester");
    req.requester = "r".repeat(129);
    assert!(matches!(issuer.issue(&req), Err(IssueError::Text("requester"))));
    // seats: the shape check, not the roster, decides these
    let shape = |n: usize, len: usize| {
        let mut r = request(&case);
        r.decision.seats = (0..n).map(|i| format!("{i:0>len$}")).collect();
        matches!(honest_issuer(&SharedLog::default()).issue(&r), Err(IssueError::DecisionShape(_)))
    };
    assert!(!shape(MAX_SEATS, 4), "exactly the most seats passes the shape check");
    assert!(shape(MAX_SEATS + 1, 4));
    assert!(!shape(2, stack_receipt::MAX_ID_BYTES), "a seat name of exactly the most bytes");
    assert!(shape(2, stack_receipt::MAX_ID_BYTES + 1));
    // too many verdicts alone is a shape error, not a roster finding
    let mut r = request(&case);
    let v = r.decision.verdicts[0].clone();
    r.decision.verdicts = vec![v; MAX_SEATS + 1];
    assert!(matches!(honest_issuer(&SharedLog::default()).issue(&r), Err(IssueError::DecisionShape(_))));
}

#[test]
fn issuer_id_and_policy_ref_accept_their_exact_maximum() {
    let p = kernel_policy();
    let make = |id: &str, pref: &str| IssuerConfig::from_kernel_policy(&p, id, pref, canonical_limits(), MAX_LIFETIME_MS, ROOTS, MAX_PER_DECISION);
    assert!(make(&"i".repeat(128), POLICY_REF).is_ok());
    assert!(make(ISSUER, &"p".repeat(256)).is_ok());
}

#[test]
fn an_invalid_kernel_policy_is_refused_at_configuration() {
    let p = stack_admission::KernelPolicy { required_seats: vec![], ..kernel_policy() };
    let r = IssuerConfig::from_kernel_policy(&p, ISSUER, POLICY_REF, canonical_limits(), MAX_LIFETIME_MS, ROOTS, MAX_PER_DECISION);
    assert!(matches!(r, Err(ConfigError::Policy(_))));
}

#[test]
fn a_capability_over_the_default_verifier_size_cap_is_refused_and_not_logged() {
    let case = case("all_pass");
    let log = SharedLog::default();
    let mut req = request(&case);
    req.resources = (0..16)
        .map(|i| ResourceScope::new(ScopeKind::Exact, &format!("/data/{i:02}{}", "a".repeat(990))).unwrap())
        .collect();
    let err = honest_issuer(&log).issue(&req).unwrap_err();
    assert!(matches!(err, IssueError::Encode(_)), "{err:?}");
    assert_eq!(log.count(), 0);
}

#[test]
fn both_hooks_run_before_entropy_and_before_the_clock_is_read() {
    let case = case("all_pass");
    for (refuse_verifier, deny) in [(true, false), (false, true)] {
        let entropy = CounterEntropy::default();
        let fills = entropy.fills.clone();
        let reads = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let v = FixtureAllowAllVerifier { refuse: refuse_verifier, ..Default::default() };
        let a = FixtureAuthorizer { allow: if deny { Some(vec![]) } else { None }, ..Default::default() };
        let issuer = Issuer::new(
            issuer_config(),
            Box::new(FixtureSigner::honest(ISSUER)),
            Box::new(entropy),
            Box::new(SharedLog::default()),
            Box::new(CountingClock { reads: reads.clone(), now: T0 }),
            Box::new(v),
            Box::new(a),
        )
        .unwrap();
        assert!(issuer.issue(&request(&case)).is_err());
        assert_eq!(fills.load(Ordering::SeqCst), 0, "entropy was drawn before a hook refused");
        assert_eq!(reads.load(Ordering::SeqCst), 0, "the clock was read before a hook refused");
    }
}

#[test]
fn a_root_of_the_wrong_length_is_not_a_record() {
    let dir = TempDir::new("rootlen");
    let path = dir.file("issuance.jsonl");
    for len in [62usize, 66] {
        let line = format!("{{\"cap_id\":\"c\",\"decision_root\":\"{}\"}}\n", "a".repeat(len));
        std::fs::write(&path, line).unwrap();
        assert!(FileIssuanceLog::open(&path).is_err(), "{len}");
    }
}
