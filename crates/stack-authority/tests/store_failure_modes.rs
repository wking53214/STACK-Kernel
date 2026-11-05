//! R-8 (G-6) for the one-time-use store: lost acknowledgment, duplicate
//! record, rollback and its consequence, unavailable storage, and
//! concurrent one-time use from two real processes. Each scenario is
//! reproduced on `FileUseStore`, not described.
//!
//! The two-process tests re-run this test binary as children (the role is
//! passed in the environment), so they need no extra fixture programs.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use common::{
    authority_with, baseline_capability, baseline_request, fixture_nonce, issue, production_config, TempDir, T0,
};
use stack_authority::{
    AuthzError, Capability, CapabilityDigest, FileUseStore, ManualClock, UseError, UseKey, UseStore, LOG_HEADER,
    RECORD_BYTES,
};

/// Tests in this file run one at a time. A child spawned by one test holds
/// a copy of every descriptor open in the process for the instant between
/// fork and exec, which keeps another test's advisory lock alive a few
/// milliseconds past its store being dropped.
fn serial() -> std::sync::MutexGuard<'static, ()> {
    static SERIAL: std::sync::Mutex<()> = std::sync::Mutex::new(());
    SERIAL.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
}

fn one_time_wire(id: &str, nonce: &str) -> Vec<u8> {
    let mut cap: Capability = baseline_capability();
    cap.cap_id = id.into();
    cap.one_time = true;
    cap.nonce = fixture_nonce(nonce);
    issue(&cap, "issuer-1")
}

fn clock() -> ManualClock {
    ManualClock::new(T0 + 1_000)
}

fn try_authorize(path: &Path, wire: &[u8]) -> Result<(), AuthzError> {
    let store = FileUseStore::open(path, 64).map_err(|_| AuthzError::StoreUnavailable)?;
    authority_with(production_config())
        .authorize(wire, &baseline_request(), &clock(), &store)
        .map(|_| ())
}

// ---------------------------------------------------------------------------
// Child processes
// ---------------------------------------------------------------------------

const ROLE: &str = "STACK_AUTHORITY_R8_ROLE";
const DIR: &str = "STACK_AUTHORITY_R8_DIR";
const ID: &str = "STACK_AUTHORITY_R8_ID";

fn child_env() -> Option<(String, PathBuf, String)> {
    let role = std::env::var(ROLE).ok()?;
    Some((role, PathBuf::from(std::env::var(DIR).ok()?), std::env::var(ID).unwrap_or_default()))
}

fn spawn_child(test: &str, role: &str, dir: &Path, id: &str) -> std::process::Child {
    Command::new(std::env::current_exe().unwrap())
        .args(["--exact", test, "--test-threads=1", "--nocapture"])
        .env(ROLE, role)
        .env(DIR, dir)
        .env(ID, id)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap()
}

/// Both children write `ready-<id>` and wait until both files exist.
fn rendezvous(dir: &Path, id: &str) {
    std::fs::write(dir.join(format!("ready-{id}")), b"1").unwrap();
    let begun = Instant::now();
    while !(dir.join("ready-a").exists() && dir.join("ready-b").exists()) {
        assert!(begun.elapsed() < Duration::from_secs(30), "the other child never arrived");
        std::thread::sleep(Duration::from_millis(2));
    }
}

fn outcome_word(r: &Result<(), AuthzError>) -> String {
    match r {
        Ok(()) => "authorized".into(),
        Err(AuthzError::Replay) => "replay".into(),
        Err(AuthzError::StoreUnavailable) => "unavailable".into(),
        Err(e) => format!("other:{e:?}"),
    }
}

// ---------------------------------------------------------------------------
// (1) Lost acknowledgment
// ---------------------------------------------------------------------------

#[test]
fn lost_ack_in_process_the_use_is_committed_and_the_retry_is_a_replay() {
    let _serial = serial();
    let dir = TempDir::new("lostack-inproc");
    let path = dir.file("uses.log");
    let wire = one_time_wire("cap-lost", "n1");
    let executions = AtomicUsize::new(0);
    {
        let store = FileUseStore::open(&path, 64).unwrap();
        // The caller asks, the store commits, and the caller never looks:
        // the result is dropped as if the caller died right after the call.
        let granted = authority_with(production_config()).authorize(&wire, &baseline_request(), &clock(), &store);
        drop(granted);
    }
    // The retry (a new process life: the store is reopened from disk).
    match try_authorize(&path, &wire) {
        Ok(()) => {
            executions.fetch_add(1, Ordering::SeqCst);
        }
        Err(e) => assert_eq!(e, AuthzError::Replay),
    }
    assert_eq!(executions.load(Ordering::SeqCst), 0, "a lost acknowledgment must never allow a second execution");
    assert_eq!(try_authorize(&path, &wire), Err(AuthzError::Replay));
    assert_eq!(FileUseStore::open(&path, 64).unwrap().records(), Some(1));
}

#[test]
fn lost_ack_real_process_aborts_after_the_commit_and_the_retry_is_a_replay() {
    let _serial = serial();
    const TEST: &str = "lost_ack_real_process_aborts_after_the_commit_and_the_retry_is_a_replay";
    let wire = one_time_wire("cap-crash", "n1");
    if let Some((role, dir, _)) = child_env() {
        assert_eq!(role, "consume_then_abort");
        let granted = try_authorize(&dir.join("uses.log"), &wire);
        assert!(granted.is_ok());
        // The ack is lost: the process dies before it can do anything with it.
        std::process::abort();
    }
    let dir = TempDir::new("lostack-proc");
    let status = spawn_child(TEST, "consume_then_abort", dir.path(), "x").wait().unwrap();
    assert!(!status.success(), "the child must have died: {status}");
    let path = dir.file("uses.log");
    assert_eq!(try_authorize(&path, &wire), Err(AuthzError::Replay));
    assert_eq!(FileUseStore::open(&path, 64).unwrap().records(), Some(1));
}

// ---------------------------------------------------------------------------
// (2) Duplicate record
// ---------------------------------------------------------------------------

fn log_with_two_records(path: &Path) -> Vec<u8> {
    let store = FileUseStore::open(path, 16).unwrap();
    for id in ["one", "two"] {
        store
            .record_use(&UseKey { cap_id: id, digest: &CapabilityDigest::of_wire(id.as_bytes()) }, true, T0 + 10, T0)
            .unwrap();
    }
    drop(store);
    std::fs::read(path).unwrap()
}

#[test]
fn a_record_appended_twice_byte_for_byte_fails_closed_on_open() {
    let _serial = serial();
    let dir = TempDir::new("dup-append");
    let path = dir.file("uses.log");
    let bytes = log_with_two_records(&path);
    let last = &bytes[bytes.len() - RECORD_BYTES..];
    let mut dup = bytes.clone();
    dup.extend_from_slice(last);
    std::fs::write(&path, &dup).unwrap();
    assert_eq!(FileUseStore::open(&path, 16).map(|_| ()).unwrap_err(), UseError::Unavailable);
}

#[test]
fn a_record_replacing_its_neighbour_byte_for_byte_fails_closed_on_open() {
    let _serial = serial();
    let dir = TempDir::new("dup-replace");
    let path = dir.file("uses.log");
    let bytes = log_with_two_records(&path);
    let first = LOG_HEADER.len();
    let mut dup = bytes.clone();
    let (a, b) = (first, first + RECORD_BYTES);
    let copy: Vec<u8> = dup[a..a + RECORD_BYTES].to_vec();
    dup[b..b + RECORD_BYTES].copy_from_slice(&copy);
    assert_ne!(dup, bytes);
    std::fs::write(&path, &dup).unwrap();
    assert_eq!(FileUseStore::open(&path, 16).map(|_| ()).unwrap_err(), UseError::Unavailable);
    // The intact file still opens.
    std::fs::write(&path, &bytes).unwrap();
    assert_eq!(FileUseStore::open(&path, 16).unwrap().records(), Some(2));
}

// ---------------------------------------------------------------------------
// (3) Rollback to a prior valid state
// ---------------------------------------------------------------------------

#[test]
fn rollback_to_a_prior_state_is_not_detected_from_the_file_and_is_detected_against_an_external_head() {
    let _serial = serial();
    let dir = TempDir::new("rollback-r8");
    let path = dir.file("uses.log");
    let (cap1, cap2) = (CapabilityDigest::of_wire(b"one"), CapabilityDigest::of_wire(b"two"));
    let (older_bytes, anchored_head);
    {
        let store = FileUseStore::open(&path, 16).unwrap();
        store.record_use(&UseKey { cap_id: "one", digest: &cap1 }, true, T0 + 10, T0).unwrap();
        older_bytes = std::fs::read(&path).unwrap(); // a backup taken after use one
        store.record_use(&UseKey { cap_id: "two", digest: &cap2 }, true, T0 + 10, T0).unwrap();
        anchored_head = store.head().unwrap(); // what the operator recorded elsewhere
    }
    std::fs::write(&path, &older_bytes).unwrap(); // the restore

    // NOT detected from the file alone: it opens cleanly as a valid log,
    let store = FileUseStore::open(&path, 16).unwrap();
    assert_eq!(store.records(), Some(1));
    // and the forgotten use can be consumed again. This is the cost of the limitation.
    assert_eq!(store.record_use(&UseKey { cap_id: "two", digest: &cap2 }, true, T0 + 10, T0), Ok(()));
    // The use that survived the rollback is still refused.
    assert_eq!(
        store.record_use(&UseKey { cap_id: "one", digest: &cap1 }, true, T0 + 10, T0),
        Err(UseError::AlreadyUsed)
    );
    drop(store);

    // Detected against an external anchor: the operator compares the
    // head it recorded with the head the reopened store reports, before
    // trusting the store. FileUseStore has no built-in high-water option;
    // `head()` is the anchor it provides.
    std::fs::write(&path, &older_bytes).unwrap();
    let reopened = FileUseStore::open(&path, 16).unwrap();
    assert_ne!(reopened.head().unwrap(), anchored_head, "the external head exposes the rollback");
    assert_eq!(reopened.records(), Some(1));
    // Control: an unrolled-back store matches its anchor.
    let intact_dir = TempDir::new("rollback-r8-intact");
    let p2 = intact_dir.file("uses.log");
    let s2 = FileUseStore::open(&p2, 16).unwrap();
    s2.record_use(&UseKey { cap_id: "one", digest: &cap1 }, true, T0 + 10, T0).unwrap();
    let h = s2.head().unwrap();
    drop(s2);
    assert_eq!(FileUseStore::open(&p2, 16).unwrap().head().unwrap(), h);
}

// ---------------------------------------------------------------------------
// (4) Storage becomes unavailable
// ---------------------------------------------------------------------------

/// Delegates to a real `FileUseStore` until told to fail, then answers
/// `Unavailable` without touching the file: storage lost mid-run.
#[derive(Debug)]
struct LosesStorage {
    inner: FileUseStore,
    lost: AtomicBool,
}

impl UseStore for LosesStorage {
    fn record_use(&self, key: &UseKey<'_>, one_time: bool, expires_at_ms: u64, now_ms: u64) -> Result<(), UseError> {
        if self.lost.load(Ordering::SeqCst) {
            return Err(UseError::Unavailable);
        }
        self.inner.record_use(key, one_time, expires_at_ms, now_ms)
    }
    fn is_durable(&self) -> bool {
        true
    }
}

#[test]
fn storage_lost_mid_run_denies_and_the_failed_attempt_consumes_nothing() {
    let _serial = serial();
    let dir = TempDir::new("storage-lost");
    let path = dir.file("uses.log");
    let store = LosesStorage {
        inner: FileUseStore::open(&path, 16).unwrap(),
        lost: AtomicBool::new(false),
    };
    let auth = authority_with(production_config());
    let (first, second) = (one_time_wire("cap-first", "n1"), one_time_wire("cap-second", "n2"));
    assert!(auth.authorize(&first, &baseline_request(), &clock(), &store).is_ok());
    store.lost.store(true, Ordering::SeqCst);
    assert_eq!(auth.authorize(&second, &baseline_request(), &clock(), &store), Err(AuthzError::StoreUnavailable));
    assert_eq!(
        auth.authorize(&first, &baseline_request(), &clock(), &store),
        Err(AuthzError::StoreUnavailable),
        "an already-consumed capability is denied for the right reason or a safe one, never allowed"
    );
    // Storage returns: the capability whose attempt failed was never consumed.
    store.lost.store(false, Ordering::SeqCst);
    assert!(auth.authorize(&second, &baseline_request(), &clock(), &store).is_ok());
    assert_eq!(auth.authorize(&first, &baseline_request(), &clock(), &store), Err(AuthzError::Replay));
}

#[test]
fn real_unavailable_storage_at_open_fails_closed() {
    let _serial = serial();
    let dir = TempDir::new("storage-open");
    // A directory where the file should be.
    assert_eq!(FileUseStore::open(dir.path(), 16).map(|_| ()).unwrap_err(), UseError::Unavailable);
    // A parent that does not exist.
    assert_eq!(
        FileUseStore::open(dir.file("gone/uses.log"), 16).map(|_| ()).unwrap_err(),
        UseError::Unavailable
    );
}

// ---------------------------------------------------------------------------
// (5) Concurrent one-time use from two processes
// ---------------------------------------------------------------------------

#[test]
fn two_processes_race_one_one_time_capability_exactly_one_is_authorized() {
    let _serial = serial();
    const TEST: &str = "two_processes_race_one_one_time_capability_exactly_one_is_authorized";
    let wire = one_time_wire("cap-race2", "n1");
    if let Some((role, dir, id)) = child_env() {
        assert_eq!(role, "race");
        rendezvous(&dir, &id);
        let word = match FileUseStore::open(dir.join("uses.log"), 64) {
            // The other process holds the exclusive lock: this one has no
            // store, so it denies.
            Err(_) => "locked".to_owned(),
            Ok(store) => {
                let r = authority_with(production_config())
                    .authorize(&wire, &baseline_request(), &clock(), &store)
                    .map(|_| ());
                // Hold the store (and its lock) long enough for the other
                // process to find it locked.
                std::thread::sleep(Duration::from_millis(700));
                outcome_word(&r)
            }
        };
        std::fs::write(dir.join(format!("result-{id}")), word).unwrap();
        return;
    }
    let dir = TempDir::new("race2");
    let mut a = spawn_child(TEST, "race", dir.path(), "a");
    let mut b = spawn_child(TEST, "race", dir.path(), "b");
    assert!(a.wait().unwrap().success());
    assert!(b.wait().unwrap().success());
    let mut words: Vec<String> = ["a", "b"]
        .iter()
        .map(|id| std::fs::read_to_string(dir.file(&format!("result-{id}"))).unwrap())
        .collect();
    words.sort();
    assert!(
        words == ["authorized", "locked"] || words == ["authorized", "replay"],
        "exactly one process may be authorized, the other denied: {words:?}"
    );
    // After both exit, a third life of the store still refuses.
    assert_eq!(try_authorize(&dir.file("uses.log"), &wire), Err(AuthzError::Replay));
    assert_eq!(FileUseStore::open(dir.file("uses.log"), 64).unwrap().records(), Some(1));
}
