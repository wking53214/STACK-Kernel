//! R-8 (G-6) for the Trident replay store (`FileStore`): lost
//! acknowledgment (including a real process that dies after the commit),
//! duplicate record, rollback and the external high-water mark, and two
//! real processes racing one envelope. Each scenario runs on the real file
//! store. Storage failing mid-run is covered by
//! `replay_durable::a_storage_write_failure_refuses_and_leaves_state_unchanged_so_a_later_retry_is_accepted_once`
//! and `unavailable_storage_at_startup_fails_closed`.
//!
//! Every key is a TEST FIXTURE (tests/common/mod.rs).

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant};

use common::*;
use stack_trident::store::{ACCEPT_RECORD_LEN, HEADER_LEN};
use stack_trident::{
    seal, Clock, EnvelopeDraft, FileStore, GateOutcome, GatePosition, HandoffEnvelope, KeyRing, ManualClock, ReasonCode,
    ReplayStore, StartError, StoreError, Trident, TridentConfig, Verdict,
};

/// One test at a time: a child spawned by one test holds a copy of every
/// descriptor open in the process between fork and exec, which keeps
/// another test's advisory lock alive briefly after its store is dropped.
fn serial() -> MutexGuard<'static, ()> {
    static SERIAL: Mutex<()> = Mutex::new(());
    SERIAL.lock().unwrap_or_else(PoisonError::into_inner)
}

fn scratch(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("stack-trident-r8-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn ring() -> KeyRing {
    let mut ring = KeyRing::new(16);
    ring.insert(fixture_key("a")).unwrap();
    ring.insert(fixture_key("b")).unwrap();
    ring
}

fn cfg() -> TridentConfig {
    TridentConfig::unbound_audience()
}

fn open_with(path: &Path, clock: &Arc<ManualClock>, cfg: TridentConfig) -> Result<Trident, StartError> {
    let store = FileStore::open(path)?;
    Trident::new_with_store(cfg, ring(), Arc::clone(clock) as Arc<dyn Clock>, Box::new(store))
}

fn open(path: &Path, clock: &Arc<ManualClock>) -> Result<Trident, StartError> {
    open_with(path, clock, cfg())
}

fn boot(path: &Path) -> (Arc<ManualClock>, Trident) {
    let clock = Arc::new(ManualClock::new(T0));
    let trident = open(path, &clock).unwrap();
    clock.advance(cfg().max_future_skew_ms + 1);
    (clock, trident)
}

fn sealed_at(seq: u64, at: u64) -> HandoffEnvelope {
    seal(
        EnvelopeDraft {
            sequence: seq,
            issued_at_unix_ms: at,
            nonce: nonce_for(seq),
            gate_position: GatePosition::Alpha,
            gate_outcome: GateOutcome::Pass,
            payload: payload_for(seq),
        },
        &fixture_key("a"),
        &cfg().limits(),
    )
    .unwrap()
}

fn replayed(v: &Verdict) -> bool {
    v.refusal().is_some_and(|r| r.has(ReasonCode::Replay))
}

/// The instant a freshly booted verifier's clock reads once it can accept.
fn accepting_now() -> u64 {
    T0 + cfg().max_future_skew_ms + 1
}

// ---------------------------------------------------------------------------
// Child processes
// ---------------------------------------------------------------------------

const ROLE: &str = "STACK_TRIDENT_R8_ROLE";
const DIR: &str = "STACK_TRIDENT_R8_DIR";
const ID: &str = "STACK_TRIDENT_R8_ID";

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

fn rendezvous(dir: &Path, id: &str) {
    std::fs::write(dir.join(format!("ready-{id}")), b"1").unwrap();
    let begun = Instant::now();
    while !(dir.join("ready-a").exists() && dir.join("ready-b").exists()) {
        assert!(begun.elapsed() < Duration::from_secs(30), "the other child never arrived");
        std::thread::sleep(Duration::from_millis(2));
    }
}

// ---------------------------------------------------------------------------
// (1) Lost acknowledgment
// ---------------------------------------------------------------------------

#[test]
fn lost_ack_in_process_the_commit_stands_and_the_replay_is_refused_after_reopen() {
    let _serial = serial();
    let dir = scratch("lostack-inproc");
    let path = dir.join("replay.log");
    let (clock, trident) = boot(&path);
    let env = sealed_at(1, clock.now_unix_ms());
    // The caller gets the verdict and loses it before acting on it.
    drop(trident.verify(&env));
    drop(trident);

    clock.advance(1_000);
    let restarted = open(&path, &clock).unwrap();
    let v = restarted.verify(&env);
    assert!(replayed(&v), "the acceptance was committed; the retry must be a replay: {v:?}");
    assert!(!v.is_accepted());
}

#[test]
fn lost_ack_real_process_aborts_after_the_commit_and_the_replay_is_refused() {
    let _serial = serial();
    const TEST: &str = "lost_ack_real_process_aborts_after_the_commit_and_the_replay_is_refused";
    if let Some((role, dir, _)) = child_env() {
        assert_eq!(role, "accept_then_abort");
        let (clock, trident) = boot(&dir.join("replay.log"));
        let accepted = trident.verify(&sealed_at(1, clock.now_unix_ms())).is_accepted();
        assert!(accepted);
        // The caller dies before it can use the verdict.
        std::process::abort();
    }
    let dir = scratch("lostack-proc");
    let status = spawn_child(TEST, "accept_then_abort", &dir, "x").wait().unwrap();
    assert!(!status.success(), "the child must have died: {status}");

    let clock = Arc::new(ManualClock::new(accepting_now() + 1_000));
    let restarted = open(&dir.join("replay.log"), &clock).unwrap();
    let v = restarted.verify(&sealed_at(1, accepting_now()));
    assert!(replayed(&v), "{v:?}");
}

// ---------------------------------------------------------------------------
// (2) Duplicate record
// ---------------------------------------------------------------------------

fn populated(name: &str) -> (PathBuf, Arc<ManualClock>, Vec<u8>) {
    let dir = scratch(name);
    let path = dir.join("replay.log");
    let (clock, trident) = boot(&path);
    for seq in 1..=3 {
        assert!(trident.verify(&sealed_at(seq, clock.now_unix_ms())).is_accepted());
        clock.advance(100);
    }
    drop(trident);
    let bytes = std::fs::read(&path).unwrap();
    assert_eq!(bytes.len(), HEADER_LEN as usize + 3 * ACCEPT_RECORD_LEN);
    (path, clock, bytes)
}

fn record_start(i: usize) -> usize {
    HEADER_LEN as usize + i * ACCEPT_RECORD_LEN
}

#[test]
fn a_record_overwriting_its_neighbour_byte_for_byte_fails_closed_at_startup() {
    let _serial = serial();
    let (path, clock, bytes) = populated("dup-replace");
    let mut dup = bytes.clone();
    let copy = dup[record_start(1)..record_start(2)].to_vec();
    dup[record_start(2)..record_start(3)].copy_from_slice(&copy);
    assert_ne!(dup, bytes);
    std::fs::write(&path, &dup).unwrap();
    match open(&path, &clock) {
        Err(StartError::Store(StoreError::Corrupt { .. })) => {}
        other => panic!("a duplicated record must fail closed as Corrupt: {other:?}"),
    }
}

#[test]
fn a_record_appended_twice_past_the_committed_length_is_never_counted() {
    let _serial = serial();
    let (path, clock, bytes) = populated("dup-append");
    let mut dup = bytes.clone();
    dup.extend_from_slice(&bytes[record_start(2)..record_start(3)]);
    std::fs::write(&path, &dup).unwrap();
    // The header commits three records; the extra bytes were never
    // acknowledged. Pinned: the store opens, and its state is the three
    // acknowledged records, no more.
    let mut store = FileStore::open(&path).unwrap();
    let restored = store.load().unwrap();
    assert_eq!(restored.nonces.len(), 3, "the duplicate must not count as a fourth acceptance");
    assert_eq!(store.committed_len(), bytes.len() as u64);
    drop(store);
    let restarted = open(&path, &clock).unwrap();
    assert!(replayed(&restarted.verify(&sealed_at(3, accepting_now() + 200))));
}

// ---------------------------------------------------------------------------
// (3) Rollback to a prior valid state
// ---------------------------------------------------------------------------

#[test]
fn rollback_is_not_detected_from_the_file_and_the_external_mark_boundary_is_exact() {
    let _serial = serial();
    let dir = scratch("rollback-r8");
    let path = dir.join("replay.log");
    let (clock, trident) = boot(&path);
    for seq in 1..=2 {
        assert!(trident.verify(&sealed_at(seq, clock.now_unix_ms())).is_accepted());
        clock.advance(100);
    }
    let older = std::fs::read(&path).unwrap(); // the backup
    let older_high_water = trident.high_water_ms().unwrap();
    for seq in 3..=4 {
        assert!(trident.verify(&sealed_at(seq, clock.now_unix_ms())).is_accepted());
        clock.advance(100);
    }
    let true_high_water = trident.high_water_ms().unwrap();
    drop(trident);
    assert!(older_high_water < true_high_water);

    // Restore the backup.
    std::fs::write(&path, &older).unwrap();

    // NOT detected from the file alone (no mark): it starts.
    assert!(open(&path, &clock).is_ok());
    // Detected with an external mark equal to the true high-water: refused.
    let marked = TridentConfig {
        restored_high_water_ms: true_high_water,
        ..cfg()
    };
    match open_with(&path, &clock, marked) {
        Err(StartError::StoreBehindExternalMark { store_ms, external_ms }) => {
            assert_eq!(store_ms, older_high_water);
            assert_eq!(external_ms, true_high_water);
        }
        other => panic!("the rolled-back store must be refused against the mark: {other:?}"),
    }
    // A mark that the restored store itself reached does not refuse it.
    let at_store = TridentConfig {
        restored_high_water_ms: older_high_water,
        ..cfg()
    };
    assert!(open_with(&path, &clock, at_store).is_ok());
}

// ---------------------------------------------------------------------------
// (5) Two real processes, one envelope
// ---------------------------------------------------------------------------

#[test]
fn two_processes_race_one_envelope_exactly_one_accepts() {
    let _serial = serial();
    const TEST: &str = "two_processes_race_one_envelope_exactly_one_accepts";
    if let Some((role, dir, id)) = child_env() {
        assert_eq!(role, "race");
        rendezvous(&dir, &id);
        let clock = Arc::new(ManualClock::new(T0));
        let word = match open(&dir.join("replay.log"), &clock) {
            // The other process holds the exclusive lock: no store, no verifier, deny.
            Err(StartError::Store(StoreError::Locked { .. })) => "locked".to_owned(),
            Err(e) => format!("other:{e:?}"),
            Ok(trident) => {
                clock.advance(cfg().max_future_skew_ms + 1);
                let v = trident.verify(&sealed_at(1, accepting_now()));
                let word = if v.is_accepted() { "accepted" } else if replayed(&v) { "replay" } else { "other" };
                std::thread::sleep(Duration::from_millis(700));
                word.to_owned()
            }
        };
        std::fs::write(dir.join(format!("result-{id}")), word).unwrap();
        return;
    }
    let dir = scratch("race2");
    let mut a = spawn_child(TEST, "race", &dir, "a");
    let mut b = spawn_child(TEST, "race", &dir, "b");
    assert!(a.wait().unwrap().success());
    assert!(b.wait().unwrap().success());
    let mut words: Vec<String> = ["a", "b"]
        .iter()
        .map(|id| std::fs::read_to_string(dir.join(format!("result-{id}"))).unwrap())
        .collect();
    words.sort();
    assert!(
        words == ["accepted", "locked"] || words == ["accepted", "replay"],
        "exactly one process may accept, the other must deny: {words:?}"
    );
    // After both exit, a later life still refuses it.
    let clock = Arc::new(ManualClock::new(accepting_now() + 1_000));
    let restarted = open(&dir.join("replay.log"), &clock).unwrap();
    assert!(replayed(&restarted.verify(&sealed_at(1, accepting_now()))));
}
