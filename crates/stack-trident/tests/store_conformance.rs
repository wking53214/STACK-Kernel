//! The `ReplayStore` check-and-commit conformance suite
//! (tests/common/conformance.rs) run against the crate's own stores, plus
//! the file store's fault cases that the trait alone cannot express: a
//! torn tail, a torn header slot write, a restart, and compaction.
//!
//! TRAIT SEMANTICS in one process. Not a multi-host test.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};

use common::conformance::replay_store_conformance;
use stack_trident::store::{ACCEPT_RECORD_LEN, HEADER_LEN};
use stack_trident::{AcceptRecord, FileStore, Fingerprint, MemoryStore, Nonce, ReplayStore, StoreError};

fn scratch(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("stack-trident-conformance-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

const AT: u64 = 1_800_000_000_000;

fn rec(seq: u64, n: u8, at: u64) -> AcceptRecord {
    AcceptRecord {
        sender: Fingerprint::from_bytes([1; 32]),
        sequence: seq,
        nonce: Nonce::from_bytes([n; 16]),
        issued_at_unix_ms: at,
        accepted_at_unix_ms: at,
        nonce_expires_at_unix_ms: at + 60_000,
    }
}

fn is_conflict(r: Result<(), StoreError>) -> bool {
    matches!(r, Err(StoreError::Conflict { .. }))
}

fn reopen(path: &PathBuf) -> FileStore {
    let mut s = FileStore::open(path).unwrap();
    s.load().unwrap();
    s
}

#[test]
fn memory_store_conforms() {
    replay_store_conformance(|| Box::new(MemoryStore::new()));
}

#[test]
fn file_store_conforms() {
    let dir = scratch("file");
    let n = AtomicUsize::new(0);
    replay_store_conformance(|| {
        let path = dir.join(format!("replay-{}.log", n.fetch_add(1, Ordering::SeqCst)));
        Box::new(FileStore::open(path).unwrap())
    });
}

#[test]
fn file_store_conflicts_survive_a_restart_and_a_compaction() {
    let dir = scratch("restart");
    let path = dir.join("replay.log");
    let mut s = reopen(&path);
    s.commit(&rec(5, 1, AT)).unwrap();
    s.raise_epoch_floor(AT + 100).unwrap();
    drop(s);
    let mut s = reopen(&path);
    assert!(is_conflict(s.commit(&rec(6, 1, AT + 100))), "nonce forgotten on restart");
    assert!(is_conflict(s.commit(&rec(5, 2, AT + 100))), "sequence forgotten on restart");
    assert!(is_conflict(s.commit(&rec(6, 2, AT + 99))), "epoch floor forgotten on restart");
    s.compact(AT + 1).unwrap();
    drop(s);
    let mut s = reopen(&path);
    assert_eq!(s.load().unwrap().epoch_floor_ms, AT + 100, "compaction dropped the floor");
    assert!(is_conflict(s.commit(&rec(6, 1, AT + 100))), "compaction dropped a live nonce");
    assert!(is_conflict(s.commit(&rec(5, 2, AT + 100))), "compaction dropped a sequence");
    s.commit(&rec(6, 2, AT + 100)).unwrap();
}

/// A crash in the middle of writing a record leaves part of it past the
/// committed length. It was never acknowledged, so it is discarded and
/// what it claimed is NOT consumed; what was acknowledged still is.
#[test]
fn file_store_torn_tail_record_is_not_consumed() {
    let dir = scratch("torn-tail");
    let path = dir.join("replay.log");
    let mut s = reopen(&path);
    s.commit(&rec(1, 1, AT)).unwrap();
    drop(s);
    let after_one = std::fs::read(&path).unwrap();
    let mut s = reopen(&path);
    s.commit(&rec(2, 2, AT + 1)).unwrap();
    drop(s);
    let after_two = std::fs::read(&path).unwrap();
    assert_eq!(after_two.len(), HEADER_LEN as usize + 2 * ACCEPT_RECORD_LEN);
    // The header of the first state, with half of the second record past it.
    let mut torn = after_one.clone();
    torn.extend_from_slice(&after_two[after_one.len()..after_one.len() + ACCEPT_RECORD_LEN / 2]);
    std::fs::write(&path, &torn).unwrap();
    let mut s = reopen(&path);
    assert!(is_conflict(s.commit(&rec(2, 1, AT + 2))), "acknowledged nonce lost");
    assert!(is_conflict(s.commit(&rec(1, 3, AT + 2))), "acknowledged sequence lost");
    s.commit(&rec(2, 2, AT + 1)).expect("a torn, unacknowledged record must not be consumed");
}

/// A crash between syncing a record and writing its header slot leaves a
/// complete record past the committed length. It may have been
/// acknowledged, so it is adopted and what it claimed IS consumed.
#[test]
fn file_store_torn_header_slot_record_is_consumed() {
    let dir = scratch("torn-slot");
    let path = dir.join("replay.log");
    let mut s = reopen(&path);
    s.commit(&rec(1, 1, AT)).unwrap();
    drop(s);
    let mut bytes = std::fs::read(&path).unwrap();
    // Generation 1 lives in slot B (odd generations).
    let slot_b = 32 + 80;
    for b in &mut bytes[slot_b..slot_b + 80] {
        *b ^= 0xff;
    }
    std::fs::write(&path, &bytes).unwrap();
    let mut s = reopen(&path);
    assert!(is_conflict(s.commit(&rec(2, 1, AT + 1))), "adopted record's nonce not consumed");
    assert!(is_conflict(s.commit(&rec(1, 2, AT + 1))), "adopted record's sequence not consumed");
    s.commit(&rec(2, 2, AT + 1)).unwrap();
}
