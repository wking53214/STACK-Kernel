//! Behaviour tests for durable replay state (`FileStore`): replay across a
//! restart, across a clock regression, across a second verifier on the
//! same file; concurrency; storage failure; corruption, truncation,
//! unavailability and torn tails at start; and a fuzz loop over random
//! damage to the store file.
//!
//! Every key is a TEST FIXTURE derived from a public label (see
//! tests/common/mod.rs) and must never be used outside tests.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use std::collections::BTreeSet;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use common::*;
use stack_trident::store::{ACCEPT_RECORD_LEN, HEADER_LEN};
use stack_trident::{
    seal, AcceptRecord, Clock, EnvelopeDraft, FileStore, FileStoreOptions, Fingerprint, GateOutcome, GatePosition,
    HandoffEnvelope, KeyRing, ManualClock, ReasonCode, ReplayStore, Resolution, RestoredState, SecretKey,
    StartError, StoreError, Trident, TridentConfig, Verdict,
};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// A fresh directory for one test, under the system temp dir.
fn scratch(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("stack-trident-replay-{}-{name}", std::process::id()));
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

/// Opens a Trident at `T0` on a fresh store and steps the clock past the
/// start-up epoch floor.
fn boot_with(path: &Path, cfg: TridentConfig) -> (Arc<ManualClock>, Trident) {
    let clock = Arc::new(ManualClock::new(T0));
    let trident = open_with(path, &clock, cfg.clone()).unwrap();
    clock.advance(cfg.max_future_skew_ms + 1);
    (clock, trident)
}

fn boot(path: &Path) -> (Arc<ManualClock>, Trident) {
    boot_with(path, cfg())
}

fn sealed_at(key: &SecretKey, seq: u64, at: u64) -> HandoffEnvelope {
    seal(
        EnvelopeDraft {
            sequence: seq,
            issued_at_unix_ms: at,
            nonce: nonce_for(seq),
            gate_position: GatePosition::Alpha,
            gate_outcome: GateOutcome::Pass,
            payload: payload_for(seq),
        },
        key,
        &cfg().limits(),
    )
    .unwrap()
}

fn sealed(seq: u64, clock: &ManualClock) -> HandoffEnvelope {
    sealed_at(&fixture_key("a"), seq, clock.now_unix_ms())
}

fn refused_with(v: &Verdict, reason: ReasonCode) -> bool {
    v.refusal().is_some_and(|r| r.has(reason))
}

/// Accepts `n` envelopes (sequence 1..=n), advancing the clock `step_ms`
/// between them. Returns the envelopes.
fn accept_n(trident: &Trident, clock: &ManualClock, n: u64, step_ms: u64) -> Vec<HandoffEnvelope> {
    (1..=n)
        .map(|seq| {
            let e = sealed(seq, clock);
            assert!(trident.verify(&e).is_accepted(), "seq {seq}");
            clock.advance(step_ms);
            e
        })
        .collect()
}

/// A store that fails `commit` while `fail` is set, otherwise delegates.
#[derive(Debug)]
struct Flaky {
    inner: Box<dyn ReplayStore>,
    fail: Arc<AtomicBool>,
    commits: Arc<AtomicUsize>,
}

impl ReplayStore for Flaky {
    fn load(&mut self) -> Result<RestoredState, StoreError> {
        self.inner.load()
    }
    fn commit(&mut self, record: &AcceptRecord) -> Result<(), StoreError> {
        if self.fail.load(Ordering::SeqCst) {
            return Err(StoreError::Io {
                op: "write record",
                kind: io::ErrorKind::Other,
                message: "injected storage failure".into(),
            });
        }
        self.commits.fetch_add(1, Ordering::SeqCst);
        self.inner.commit(record)
    }
    fn is_durable(&self) -> bool {
        self.inner.is_durable()
    }
    fn record_quarantine(&mut self, sender: &Fingerprint, since_unix_ms: u64) -> Result<(), StoreError> {
        self.inner.record_quarantine(sender, since_unix_ms)
    }
    fn record_release(&mut self, sender: &Fingerprint) -> Result<(), StoreError> {
        self.inner.record_release(sender)
    }
}

// ---------------------------------------------------------------------------
// Replay across a restart
// ---------------------------------------------------------------------------

#[test]
fn replay_after_restart_is_refused() {
    let dir = scratch("restart");
    let path = dir.join("replay.log");
    let (clock, trident) = boot(&path);
    let env = sealed(1, &clock);
    assert!(trident.verify(&env).is_accepted());
    assert!(trident.verify(&env).refusal().unwrap().has(ReasonCode::Replay));
    drop(trident);

    // Restart one second later: a fresh process, nothing in memory.
    clock.advance(1_000);
    let restarted = open(&path, &clock).unwrap();
    let v = restarted.verify(&env);
    assert!(refused_with(&v, ReasonCode::Replay), "replayed after restart: {v:?}");
    assert!(refused_with(&v, ReasonCode::SequenceNotIncreasing), "{v:?}");
    assert_eq!(v.outcome(), GateOutcome::TerminalBreach);
    // Same bytes on the wire path.
    let wire = env.to_wire_bytes(&cfg().limits()).unwrap();
    assert!(refused_with(&restarted.verify_wire(&wire), ReasonCode::Replay));
    // New work is still accepted once the start-up floor has passed.
    clock.advance(cfg().max_future_skew_ms + 1);
    assert!(restarted.verify(&sealed(2, &clock)).is_accepted());
}

#[test]
fn replay_after_restart_with_the_clock_moved_back_hours_is_refused() {
    let dir = scratch("clock-back");
    let path = dir.join("replay.log");
    let (clock, trident) = boot(&path);
    let env = sealed(1, &clock);
    let accepted_at = clock.now_unix_ms();
    assert!(trident.verify(&env).is_accepted());
    drop(trident);

    // The clock is three hours behind what it was at acceptance.
    clock.set(accepted_at - 3 * 3_600_000);
    match open(&path, &clock) {
        Err(StartError::ClockBehindStore { high_water_ms, now_ms }) => {
            assert_eq!(high_water_ms, accepted_at);
            assert_eq!(now_ms, clock.now_unix_ms());
        }
        other => panic!("a clock behind the store must refuse to start: {other:?}"),
    }
    // With the dangerous override the verifier starts, and still refuses
    // the replay, now and once the clock has caught up.
    let override_cfg = TridentConfig {
        dangerously_allow_clock_behind_store: true,
        ..cfg()
    };
    let restarted = open_with(&path, &clock, override_cfg).unwrap();
    let v = restarted.verify(&env);
    assert!(!v.is_accepted(), "replayed into a clock-rolled-back restart: {v:?}");
    assert!(refused_with(&v, ReasonCode::Replay), "{v:?}");
    clock.set(accepted_at + 1_000);
    let v = restarted.verify(&env);
    assert!(!v.is_accepted(), "replayed once the clock caught up: {v:?}");
    assert!(refused_with(&v, ReasonCode::Replay) && refused_with(&v, ReasonCode::IssuedBeforeEpoch), "{v:?}");
}

#[test]
fn sequence_rollback_after_restart_is_refused() {
    let dir = scratch("seq-rollback");
    let path = dir.join("replay.log");
    let (clock, trident) = boot(&path);
    assert!(trident.verify(&sealed(5, &clock)).is_accepted());
    drop(trident);
    clock.advance(1_000);
    let restarted = open(&path, &clock).unwrap();
    // Fresh nonce, fresh time, lower sequence: only the sequence catches it.
    clock.advance(cfg().max_future_skew_ms + 1);
    let v = restarted.verify(&sealed(4, &clock));
    assert_eq!(v.reasons(), &[ReasonCode::SequenceNotIncreasing], "{v:?}");
    // Equal is not greater either (its nonce was also seen, so both show).
    let v = restarted.verify(&sealed(5, &clock));
    assert!(refused_with(&v, ReasonCode::SequenceNotIncreasing), "{v:?}");
    assert!(restarted.verify(&sealed(6, &clock)).is_accepted());
}

#[test]
fn duplicate_nonce_with_a_new_sequence_after_restart_is_refused() {
    let dir = scratch("dup-nonce");
    let path = dir.join("replay.log");
    let (clock, trident) = boot(&path);
    assert!(trident.verify(&sealed(1, &clock)).is_accepted());
    drop(trident);
    clock.advance(1_000);
    let restarted = open(&path, &clock).unwrap();
    clock.advance(cfg().max_future_skew_ms + 1);
    let mut again = sealed(2, &clock);
    again.nonce = nonce_for(1).to_hex();
    remac(&mut again, "a");
    let v = restarted.verify(&again);
    assert_eq!(v.reasons(), &[ReasonCode::Replay], "{v:?}");
}

#[test]
fn a_quarantine_survives_a_restart() {
    let dir = scratch("quarantine");
    let path = dir.join("replay.log");
    let cfg = TridentConfig {
        breaker_threshold: 1,
        ..cfg()
    };
    let (clock, trident) = boot_with(&path, cfg.clone());
    let mut transplanted = sealed(1, &clock);
    transplanted.payload = serde_json::json!({"moved": true});
    remac(&mut transplanted, "a");
    assert_eq!(trident.verify(&transplanted).refusal().unwrap().resolution, Resolution::Quarantine);
    let fp_a = fixture_key("a").fingerprint();
    assert_eq!(trident.quarantined().unwrap(), vec![fp_a]);
    drop(trident);
    let restarted = open_with(&path, &clock, cfg.clone()).unwrap();
    assert_eq!(restarted.quarantined().unwrap(), vec![fp_a], "quarantine lost on restart");
    clock.advance(cfg.max_future_skew_ms + 1);
    assert!(refused_with(&restarted.verify(&sealed(2, &clock)), ReasonCode::Quarantined));
    assert!(restarted.release(&fp_a).unwrap());
    drop(restarted);
    let again = open_with(&path, &clock, cfg).unwrap();
    assert!(again.quarantined().unwrap().is_empty(), "release lost on restart");
}

// ---------------------------------------------------------------------------
// One active verifier per store
// ---------------------------------------------------------------------------

#[test]
fn a_second_verifier_on_the_same_store_fails_to_start_and_sees_all_prior_accepts_after_the_first_is_dropped() {
    let dir = scratch("two-verifiers");
    let path = dir.join("replay.log");
    let (clock, first) = boot(&path);
    let envs = accept_n(&first, &clock, 3, 10);

    // The file is locked: a second verifier, in this process or another,
    // cannot open it.
    match FileStore::open(&path) {
        Err(StoreError::Locked { path: p }) => assert_eq!(p, path),
        other => panic!("second open must fail with Locked: {other:?}"),
    }
    assert!(matches!(open(&path, &clock), Err(StartError::Store(StoreError::Locked { .. }))));
    // The first keeps working meanwhile.
    assert!(first.verify(&sealed(4, &clock)).is_accepted());
    drop(first);

    clock.advance(1_000);
    let second = open(&path, &clock).unwrap();
    for e in &envs {
        let v = second.verify(e);
        assert!(refused_with(&v, ReasonCode::Replay), "seq {}: {v:?}", e.sequence);
    }
    clock.advance(cfg().max_future_skew_ms + 1);
    // Sequence 4 was accepted by the first verifier after the lock test.
    let v = second.verify(&sealed(4, &clock));
    assert!(refused_with(&v, ReasonCode::SequenceNotIncreasing), "{v:?}");
    assert!(second.verify(&sealed(5, &clock)).is_accepted());
}

// ---------------------------------------------------------------------------
// Concurrency
// ---------------------------------------------------------------------------

#[test]
fn concurrent_acceptance_of_the_same_envelope_is_accepted_exactly_once_across_the_store() {
    let dir = scratch("concurrent");
    let path = dir.join("replay.log");
    let (clock, trident) = boot(&path);
    let trident = Arc::new(trident);
    let env = Arc::new(sealed(1, &clock));
    let accepted = Arc::new(Mutex::new(Vec::new()));
    let handles: Vec<_> = (0..16)
        .map(|_| {
            let (tr, env, accepted) = (Arc::clone(&trident), Arc::clone(&env), Arc::clone(&accepted));
            std::thread::spawn(move || {
                if let Verdict::Accepted(h) = tr.verify(&env) {
                    accepted.lock().unwrap().push(h.nonce);
                }
            })
        })
        .collect();
    for h in handles {
        h.join().unwrap();
    }
    assert_eq!(accepted.lock().unwrap().len(), 1);
    drop(trident);

    // Exactly one acceptance record reached the store.
    let mut store = FileStore::open(&path).unwrap();
    let restored = store.load().unwrap();
    assert_eq!(restored.nonces.len(), 1);
    assert_eq!(store.committed_len(), HEADER_LEN + ACCEPT_RECORD_LEN as u64);
    drop(store);
    let restarted = open(&path, &clock).unwrap();
    assert!(refused_with(&restarted.verify(&env), ReasonCode::Replay));
}

// ---------------------------------------------------------------------------
// Storage failure
// ---------------------------------------------------------------------------

#[test]
fn a_storage_write_failure_refuses_and_leaves_state_unchanged_so_a_later_retry_is_accepted_once() {
    let dir = scratch("flaky");
    let path = dir.join("replay.log");
    let clock = Arc::new(ManualClock::new(T0));
    let fail = Arc::new(AtomicBool::new(true));
    let commits = Arc::new(AtomicUsize::new(0));
    let store = Flaky {
        inner: Box::new(FileStore::open(&path).unwrap()),
        fail: Arc::clone(&fail),
        commits: Arc::clone(&commits),
    };
    let trident = Trident::new_with_store(cfg(), ring(), Arc::clone(&clock) as Arc<dyn Clock>, Box::new(store)).unwrap();
    clock.advance(cfg().max_future_skew_ms + 1);
    let env = sealed(1, &clock);
    for _ in 0..3 {
        let v = trident.verify(&env);
        let r = v.refusal().expect("a refused commit must refuse the envelope");
        assert_eq!(r.reasons, vec![ReasonCode::StateUnavailable], "{v:?}");
        assert_eq!(r.outcome, GateOutcome::Retry);
        assert_eq!(r.resolution, Resolution::Reject);
        assert_eq!(trident.high_water_ms().unwrap(), 0, "high-water moved on a failed commit");
    }
    assert!(!trident.is_halted());
    assert!(trident.quarantined().unwrap().is_empty());

    fail.store(false, Ordering::SeqCst);
    assert!(trident.verify(&env).is_accepted(), "the retry after recovery must be accepted");
    assert_eq!(commits.load(Ordering::SeqCst), 1);
    assert_eq!(trident.high_water_ms().unwrap(), env.issued_at_unix_ms);
    let v = trident.verify(&env);
    assert!(refused_with(&v, ReasonCode::Replay), "accepted twice: {v:?}");
    drop(trident);

    // The one acceptance is durable.
    let restarted = open(&path, &clock).unwrap();
    assert!(refused_with(&restarted.verify(&env), ReasonCode::Replay));
}

// ---------------------------------------------------------------------------
// Damage to the store file at start: fail closed
// ---------------------------------------------------------------------------

/// A store with five acceptances 100 ms apart, closed cleanly. Returns the
/// path, the envelopes, the clock (at the last acceptance plus 100 ms) and
/// the file bytes.
fn populated(name: &str) -> (PathBuf, Vec<HandoffEnvelope>, Arc<ManualClock>, Vec<u8>) {
    let dir = scratch(name);
    let path = dir.join("replay.log");
    let (clock, trident) = boot(&path);
    let envs = accept_n(&trident, &clock, 5, 100);
    drop(trident);
    let bytes = std::fs::read(&path).unwrap();
    assert_eq!(bytes.len(), HEADER_LEN as usize + 5 * ACCEPT_RECORD_LEN);
    (path, envs, clock, bytes)
}

fn record_start(i: usize) -> usize {
    HEADER_LEN as usize + i * ACCEPT_RECORD_LEN
}

fn expect_corrupt(path: &Path, clock: &Arc<ManualClock>, what: &str) {
    match open(path, clock) {
        Err(StartError::Store(StoreError::Corrupt { .. })) => {}
        other => panic!("{what}: must fail closed as Corrupt, got {other:?}"),
    }
}

#[test]
fn a_flipped_byte_in_the_middle_fails_closed_at_startup() {
    let (path, _, clock, mut bytes) = populated("flip");
    // Inside the body of the third record.
    bytes[record_start(2) + 20] ^= 0x01;
    std::fs::write(&path, &bytes).unwrap();
    expect_corrupt(&path, &clock, "flipped byte");
}

#[test]
fn a_truncation_in_the_middle_fails_closed_at_startup() {
    let (path, _, clock, bytes) = populated("truncate");
    // Cut inside the third record.
    std::fs::write(&path, &bytes[..record_start(2) + 50]).unwrap();
    match open(&path, &clock) {
        Err(StartError::Store(StoreError::Truncated { committed_len, actual_len })) => {
            assert_eq!(committed_len, bytes.len() as u64);
            assert_eq!(actual_len, (record_start(2) + 50) as u64);
        }
        other => panic!("truncation must fail closed as Truncated: {other:?}"),
    }
    // Cut exactly at a record boundary: the header still commits more.
    std::fs::write(&path, &bytes[..record_start(3)]).unwrap();
    assert!(matches!(
        open(&path, &clock),
        Err(StartError::Store(StoreError::Truncated { .. }))
    ));
    // Cut inside the header.
    std::fs::write(&path, &bytes[..HEADER_LEN as usize - 1]).unwrap();
    expect_corrupt(&path, &clock, "cut inside the header");
}

#[test]
fn swapped_records_fail_closed_at_startup() {
    let (path, _, clock, mut bytes) = populated("swap");
    let (a, b) = (record_start(1), record_start(3));
    let first: Vec<u8> = bytes[a..a + ACCEPT_RECORD_LEN].to_vec();
    let second: Vec<u8> = bytes[b..b + ACCEPT_RECORD_LEN].to_vec();
    bytes[a..a + ACCEPT_RECORD_LEN].copy_from_slice(&second);
    bytes[b..b + ACCEPT_RECORD_LEN].copy_from_slice(&first);
    std::fs::write(&path, &bytes).unwrap();
    expect_corrupt(&path, &clock, "swapped records");
}

#[test]
fn an_older_copy_of_the_store_is_refused_when_an_external_mark_is_supplied() {
    let dir = scratch("older-copy");
    let path = dir.join("replay.log");
    let (clock, trident) = boot(&path);
    let _first_two = accept_n(&trident, &clock, 2, 100);
    // A backup taken now (the lock is advisory; reading is not stopped).
    let older = std::fs::read(&path).unwrap();
    let later = accept_n_from(&trident, &clock, 3, 5, 100);
    let high_water = trident.high_water_ms().unwrap();
    drop(trident);

    // Restore the backup. Its chain is consistent: from the file alone
    // this is undetectable, which the external mark exists for.
    std::fs::write(&path, &older).unwrap();
    let with_mark = TridentConfig {
        restored_high_water_ms: high_water,
        ..cfg()
    };
    match open_with(&path, &clock, with_mark) {
        Err(StartError::StoreBehindExternalMark { store_ms, external_ms }) => {
            assert_eq!(external_ms, high_water);
            assert!(store_ms < external_ms);
        }
        other => panic!("an older store than the external mark must be refused: {other:?}"),
    }
    // Without the mark the older copy starts (documented limit) and the
    // later acceptances are what it has forgotten: they are refused here
    // only by the epoch floor, because the clock has not moved past them.
    let restarted = open(&path, &clock).unwrap();
    for e in &later {
        assert!(!restarted.verify(e).is_accepted());
    }
}

fn accept_n_from(trident: &Trident, clock: &ManualClock, from: u64, to: u64, step_ms: u64) -> Vec<HandoffEnvelope> {
    (from..=to)
        .map(|seq| {
            let e = sealed(seq, clock);
            assert!(trident.verify(&e).is_accepted(), "seq {seq}");
            clock.advance(step_ms);
            e
        })
        .collect()
}

#[test]
fn a_torn_tail_is_tolerated_and_cut_off_by_the_next_commit() {
    let (path, envs, clock, bytes) = populated("torn-tail");
    // A crash in the middle of writing the sixth record: a partial record
    // past the committed length, never acknowledged.
    let mut torn = bytes.clone();
    torn.extend_from_slice(&[0x5a; ACCEPT_RECORD_LEN / 2]);
    std::fs::write(&path, &torn).unwrap();
    let restarted = open(&path, &clock).unwrap();
    for e in &envs {
        assert!(refused_with(&restarted.verify(e), ReasonCode::Replay), "seq {}", e.sequence);
    }
    clock.advance(cfg().max_future_skew_ms + 1);
    assert!(restarted.verify(&sealed(6, &clock)).is_accepted());
    drop(restarted);
    let after = std::fs::read(&path).unwrap();
    assert_eq!(after.len(), bytes.len() + ACCEPT_RECORD_LEN, "the torn tail was not cut off");
    // The records are untouched; only the header slots moved on.
    assert_eq!(&after[HEADER_LEN as usize..bytes.len()], &bytes[HEADER_LEN as usize..]);
}

#[test]
fn a_torn_header_slot_write_does_not_forget_the_last_acceptance() {
    let (path, envs, clock, mut bytes) = populated("torn-slot");
    // A crash while writing the header slot for the fifth record: the slot
    // is garbage, the record itself was synced before it.
    // Generation 5 lives in slot B (odd generations).
    let slot_b = 32 + 80;
    for b in &mut bytes[slot_b..slot_b + 80] {
        *b ^= 0xff;
    }
    std::fs::write(&path, &bytes).unwrap();
    let restarted = open(&path, &clock).unwrap();
    let last = envs.last().unwrap();
    let v = restarted.verify(last);
    assert!(
        refused_with(&v, ReasonCode::Replay),
        "the last acceptance was forgotten after a torn slot write: {v:?}"
    );
    // The same slot damage with the last record damaged too cannot come
    // from one crash: refused.
    bytes[record_start(4) + 30] ^= 0x01;
    std::fs::write(&path, &bytes).unwrap();
    drop(restarted);
    expect_corrupt(&path, &clock, "unreadable slot with a damaged tail");
}

#[test]
fn unavailable_storage_at_startup_fails_closed() {
    let dir = scratch("unavailable");
    let clock = Arc::new(ManualClock::new(T0));
    // A directory where the file should be.
    match FileStore::open(&dir) {
        Err(StoreError::Io { op: "open", .. }) => {}
        other => panic!("a directory must not open as a store: {other:?}"),
    }
    assert!(matches!(open(&dir, &clock), Err(StartError::Store(StoreError::Io { .. }))));
    // A path whose parent does not exist.
    let missing = dir.join("no-such-dir").join("replay.log");
    assert!(matches!(open(&missing, &clock), Err(StartError::Store(StoreError::Io { .. }))));
    // A file that is not a store.
    let junk = dir.join("junk.log");
    std::fs::write(&junk, b"this is not a replay log, it is just long enough to look like one. ".repeat(4)).unwrap();
    expect_corrupt(&junk, &clock, "not a store");
}

#[test]
fn compaction_keeps_sequences_live_nonces_and_quarantines() {
    let dir = scratch("compaction");
    let path = dir.join("replay.log");
    let clock = Arc::new(ManualClock::new(T0));
    let cfg = TridentConfig {
        breaker_threshold: 1,
        ..cfg()
    };
    let retention = cfg.replay_retention_ms();
    let options = FileStoreOptions {
        compact_after_bytes: HEADER_LEN + 4 * ACCEPT_RECORD_LEN as u64,
    };
    let store = FileStore::open_with(&path, options).unwrap();
    let trident = Trident::new_with_store(cfg.clone(), ring(), Arc::clone(&clock) as Arc<dyn Clock>, Box::new(store)).unwrap();
    clock.advance(cfg.max_future_skew_ms + 1);
    // Three old acceptances, then a quarantine of B, then time passes so
    // the old nonces expire, then two fresh ones.
    let old = accept_n(&trident, &clock, 3, 10);
    let mut transplanted = sealed_at(&fixture_key("b"), 1, clock.now_unix_ms());
    transplanted.payload = serde_json::json!({"moved": true});
    remac(&mut transplanted, "b");
    assert_eq!(trident.verify(&transplanted).refusal().unwrap().resolution, Resolution::Quarantine);
    clock.advance(retention + 1);
    let fresh = accept_n_from(&trident, &clock, 4, 5, 10);
    drop(trident);
    let len = std::fs::metadata(&path).unwrap().len();
    assert!(
        len < HEADER_LEN + 5 * ACCEPT_RECORD_LEN as u64,
        "the log was not compacted: {len} bytes"
    );

    let store = FileStore::open_with(&path, options).unwrap();
    let restarted = Trident::new_with_store(cfg.clone(), ring(), Arc::clone(&clock) as Arc<dyn Clock>, Box::new(store)).unwrap();
    assert_eq!(restarted.quarantined().unwrap(), vec![fixture_key("b").fingerprint()]);
    for e in &fresh {
        assert!(refused_with(&restarted.verify(e), ReasonCode::Replay), "seq {}", e.sequence);
    }
    clock.advance(cfg.max_future_skew_ms + 1);
    // The old nonces are gone from the log, but their sequences are not.
    for e in &old {
        let mut again = sealed(e.sequence, &clock);
        again.nonce = e.nonce.clone();
        remac(&mut again, "a");
        let v = restarted.verify(&again);
        assert!(refused_with(&v, ReasonCode::SequenceNotIncreasing), "seq {}: {v:?}", e.sequence);
    }
    assert!(restarted.verify(&sealed(6, &clock)).is_accepted());
}

// ---------------------------------------------------------------------------
// Fuzz: random damage never yields a verifier that re-accepts
// ---------------------------------------------------------------------------

/// Tiny deterministic PRNG (xorshift64*).
struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545_f491_4f6c_dd1d)
    }
    fn below(&mut self, n: usize) -> usize {
        (self.next() % (n as u64)) as usize
    }
}

/// One to three random edits (byte flips anywhere, a truncation, a swap of
/// two whole records, random bytes appended) to a clean five-record store.
/// After each, the verifier either refuses to start or refuses every one
/// of the five envelopes, with the clock still inside the skew window of
/// the last acceptance. Deliberately consistent rewrites of the file (an
/// older copy restored in full) are not random damage; they are covered
/// above and need the external mark.
#[test]
fn random_damage_to_the_store_never_yields_a_trident_that_accepts_an_accepted_envelope() {
    let (path, envs, clock, clean) = populated("fuzz");
    let mut rng = Rng(0x9e37_79b9_7f4a_7c15);
    let mut outcomes: BTreeSet<&'static str> = BTreeSet::new();
    for round in 0..400 {
        let mut bytes = clean.clone();
        let edits = 1 + rng.below(3);
        for _ in 0..edits {
            match rng.below(4) {
                0 => {
                    let i = rng.below(bytes.len());
                    bytes[i] ^= 1 << rng.below(8);
                }
                1 => {
                    let keep = rng.below(bytes.len());
                    bytes.truncate(keep);
                }
                2 => {
                    let (i, j) = (rng.below(5), rng.below(5));
                    let (a, b) = (record_start(i), record_start(j));
                    if i != j && b + ACCEPT_RECORD_LEN <= bytes.len() && a + ACCEPT_RECORD_LEN <= bytes.len() {
                        let first: Vec<u8> = bytes[a..a + ACCEPT_RECORD_LEN].to_vec();
                        let second: Vec<u8> = bytes[b..b + ACCEPT_RECORD_LEN].to_vec();
                        bytes[a..a + ACCEPT_RECORD_LEN].copy_from_slice(&second);
                        bytes[b..b + ACCEPT_RECORD_LEN].copy_from_slice(&first);
                    }
                }
                _ => {
                    let n = rng.below(2 * ACCEPT_RECORD_LEN);
                    for _ in 0..n {
                        bytes.push(rng.next() as u8);
                    }
                }
            }
        }
        if bytes == clean {
            continue;
        }
        std::fs::write(&path, &bytes).unwrap();
        match open(&path, &clock) {
            Err(e) => {
                outcomes.insert(match e {
                    StartError::Store(StoreError::Corrupt { .. }) => "corrupt",
                    StartError::Store(StoreError::Truncated { .. }) => "truncated",
                    _ => "other",
                });
            }
            Ok(t) => {
                outcomes.insert("started");
                for e in &envs {
                    let v = t.verify(e);
                    assert!(
                        !v.is_accepted(),
                        "round {round}: seq {} accepted again after random damage ({edits} edits)",
                        e.sequence
                    );
                }
            }
        }
    }
    assert!(outcomes.contains("corrupt"), "{outcomes:?}");
    assert!(outcomes.contains("truncated"), "{outcomes:?}");
    assert!(outcomes.contains("started"), "no damaged store ever started: {outcomes:?}");
}
