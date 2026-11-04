//! Step 4: the durable file store. Uses survive a restart, a reusable
//! capability is recorded once, the lock is exclusive, a torn tail is
//! tolerated, corruption fails closed, concurrent consumption accepts
//! exactly once, and an unavailable store denies.

#![allow(clippy::unwrap_used)]

mod common;

use std::sync::Arc;

use common::{
    authority_with, baseline_capability, baseline_request, fixture_nonce, issue, memory_store, production_config,
    TempDir, T0,
};
use stack_authority::{
    AuthzError, Capability, CapabilityDigest, FileUseStore, ManualClock, UseError, UseKey, UseStore, LOG_HEADER,
};

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

#[test]
fn open_creates_the_header_and_records_survive_reopen() {
    let dir = TempDir::new("reopen");
    let path = dir.file("uses.log");
    let auth = authority_with(production_config());
    let wire = one_time_wire("cap-once", "n1");
    let reusable = common::baseline_wire();
    {
        let store = FileUseStore::open(&path, 16).unwrap();
        assert!(store.is_durable());
        assert_eq!(store.records(), Some(0));
        assert_eq!(store.is_empty(), Some(true));
        assert_eq!(std::fs::read(&path).unwrap(), LOG_HEADER);
        assert!(auth.authorize(&wire, &baseline_request(), &clock(), &store).is_ok());
        assert_eq!(auth.authorize(&wire, &baseline_request(), &clock(), &store), Err(AuthzError::Replay));
        // A reusable capability is written once, then accepted without a
        // write.
        assert!(auth.authorize(&reusable, &baseline_request(), &clock(), &store).is_ok());
        let len = std::fs::metadata(&path).unwrap().len();
        assert!(auth.authorize(&reusable, &baseline_request(), &clock(), &store).is_ok());
        assert_eq!(std::fs::metadata(&path).unwrap().len(), len);
        assert_eq!(store.records(), Some(2));
        assert_eq!(store.len(), Some(2));
        assert_eq!(store.path(), path.as_path());
    }
    // Restart: the one-time use is remembered, the reusable one still
    // works, and the chain head is the same.
    let store = FileUseStore::open(&path, 16).unwrap();
    assert_eq!(store.records(), Some(2));
    assert_eq!(auth.authorize(&wire, &baseline_request(), &clock(), &store), Err(AuthzError::Replay));
    assert!(auth.authorize(&reusable, &baseline_request(), &clock(), &store).is_ok());
    let head = store.head().unwrap();
    drop(store);
    let again = FileUseStore::open(&path, 16).unwrap();
    assert_eq!(again.head(), Some(head));
}

#[test]
fn id_reuse_with_different_content_is_refused_across_restart() {
    let dir = TempDir::new("id-reuse");
    let path = dir.file("uses.log");
    let auth = authority_with(production_config());
    let first = one_time_wire("cap-x", "n1");
    let second = one_time_wire("cap-x", "n2");
    {
        let store = FileUseStore::open(&path, 16).unwrap();
        assert!(auth.authorize(&first, &baseline_request(), &clock(), &store).is_ok());
    }
    let store = FileUseStore::open(&path, 16).unwrap();
    assert_eq!(
        auth.authorize(&second, &baseline_request(), &clock(), &store),
        Err(AuthzError::CapabilityIdReused)
    );
}

#[test]
fn the_lock_is_exclusive_while_held() {
    let dir = TempDir::new("lock");
    let path = dir.file("uses.log");
    let first = FileUseStore::open(&path, 16).unwrap();
    assert_eq!(FileUseStore::open(&path, 16).map(|_| ()).unwrap_err(), UseError::Unavailable);
    drop(first);
    assert!(FileUseStore::open(&path, 16).is_ok());
}

#[test]
fn a_torn_tail_is_tolerated_and_cut_off_at_the_next_write() {
    let dir = TempDir::new("torn");
    let path = dir.file("uses.log");
    let d1 = CapabilityDigest::of_wire(b"one");
    let d2 = CapabilityDigest::of_wire(b"two");
    let after_one;
    {
        let store = FileUseStore::open(&path, 16).unwrap();
        store.record_use(&UseKey { cap_id: "one", digest: &d1 }, true, T0 + 10, T0).unwrap();
        after_one = std::fs::metadata(&path).unwrap().len();
        store.record_use(&UseKey { cap_id: "two", digest: &d2 }, true, T0 + 10, T0).unwrap();
    }
    let full = std::fs::read(&path).unwrap();
    // Every proper prefix of the second record is a torn tail: the first
    // record stays, the second was never reported as recorded.
    for cut in after_one..full.len() as u64 {
        std::fs::write(&path, &full[..cut as usize]).unwrap();
        let store = FileUseStore::open(&path, 16).unwrap();
        assert_eq!(store.records(), Some(1), "cut at {cut}");
        assert_eq!(
            store.record_use(&UseKey { cap_id: "one", digest: &d1 }, true, T0 + 10, T0),
            Err(UseError::AlreadyUsed)
        );
        // The torn bytes are cut off and a new record appended on top.
        store.record_use(&UseKey { cap_id: "two", digest: &d2 }, true, T0 + 10, T0).unwrap();
        assert_eq!(std::fs::metadata(&path).unwrap().len(), full.len() as u64);
        drop(store);
        let reopened = FileUseStore::open(&path, 16).unwrap();
        assert_eq!(reopened.records(), Some(2));
    }
    // A torn header is also tolerated.
    std::fs::write(&path, &LOG_HEADER[..5]).unwrap();
    let store = FileUseStore::open(&path, 16).unwrap();
    assert_eq!(store.records(), Some(0));
    assert_eq!(std::fs::read(&path).unwrap(), LOG_HEADER);
}

#[test]
fn corruption_fails_closed_on_open() {
    let dir = TempDir::new("corrupt");
    let path = dir.file("uses.log");
    let d1 = CapabilityDigest::of_wire(b"one");
    {
        let store = FileUseStore::open(&path, 16).unwrap();
        store.record_use(&UseKey { cap_id: "one", digest: &d1 }, true, T0 + 10, T0).unwrap();
        store
            .record_use(&UseKey { cap_id: "two", digest: &CapabilityDigest::of_wire(b"two") }, false, T0 + 10, T0)
            .unwrap();
    }
    let good = std::fs::read(&path).unwrap();
    // Every single byte of the file matters: flipping any one of them
    // is corruption, not a torn tail, because the record it lands in is
    // complete.
    for i in 0..good.len() {
        let mut bad = good.clone();
        bad[i] ^= 0x01;
        std::fs::write(&path, &bad).unwrap();
        assert_eq!(
            FileUseStore::open(&path, 16).map(|_| ()).unwrap_err(),
            UseError::Unavailable,
            "byte {i}"
        );
    }
    // Bytes after the last record that are not a prefix of a record
    // chained to the head: corruption.
    let mut junk = good.clone();
    junk.extend_from_slice(&[0xff; 40]);
    std::fs::write(&path, &junk).unwrap();
    assert_eq!(FileUseStore::open(&path, 16).map(|_| ()).unwrap_err(), UseError::Unavailable);
    // A record with the right prev hash but an id length out of bounds.
    let mut bad_len = good.clone();
    let head = {
        std::fs::write(&path, &good).unwrap();
        let s = FileUseStore::open(&path, 16).unwrap();
        s.head().unwrap()
    };
    bad_len.extend_from_slice(&head);
    bad_len.extend_from_slice(&[0xff, 0xff]);
    std::fs::write(&path, &bad_len).unwrap();
    assert_eq!(FileUseStore::open(&path, 16).map(|_| ()).unwrap_err(), UseError::Unavailable);
    // A wrong header.
    let mut wrong_header = good.clone();
    wrong_header[0] = b'S';
    std::fs::write(&path, &wrong_header).unwrap();
    assert_eq!(FileUseStore::open(&path, 16).map(|_| ()).unwrap_err(), UseError::Unavailable);
    // Records swapped: the chain breaks.
    std::fs::write(&path, &good).unwrap();
    let store = FileUseStore::open(&path, 16).unwrap();
    drop(store);
    let header_len = LOG_HEADER.len();
    let rec1_end = header_len + (32 + 2 + 3 + 32 + 1 + 8 + 8 + 32);
    let mut swapped = good[..header_len].to_vec();
    swapped.extend_from_slice(&good[rec1_end..]);
    swapped.extend_from_slice(&good[header_len..rec1_end]);
    std::fs::write(&path, &swapped).unwrap();
    assert_eq!(FileUseStore::open(&path, 16).map(|_| ()).unwrap_err(), UseError::Unavailable);
    // The intact file still opens.
    std::fs::write(&path, &good).unwrap();
    assert!(FileUseStore::open(&path, 16).is_ok());
}

#[test]
fn rollback_to_a_record_boundary_is_not_detected_by_the_file_alone() {
    // Documented limitation, pinned: the chain has no external anchor,
    // so dropping the last complete record reopens cleanly. The head
    // exposed by the store is what an operator anchors elsewhere.
    let dir = TempDir::new("rollback");
    let path = dir.file("uses.log");
    let d1 = CapabilityDigest::of_wire(b"one");
    let (head_after_one, len_after_one, head_after_two);
    {
        let store = FileUseStore::open(&path, 16).unwrap();
        store.record_use(&UseKey { cap_id: "one", digest: &d1 }, true, T0 + 10, T0).unwrap();
        head_after_one = store.head().unwrap();
        len_after_one = std::fs::metadata(&path).unwrap().len();
        store
            .record_use(&UseKey { cap_id: "two", digest: &CapabilityDigest::of_wire(b"two") }, true, T0 + 10, T0)
            .unwrap();
        head_after_two = store.head().unwrap();
    }
    let full = std::fs::read(&path).unwrap();
    std::fs::write(&path, &full[..len_after_one as usize]).unwrap();
    let store = FileUseStore::open(&path, 16).unwrap();
    assert_eq!(store.records(), Some(1));
    assert_eq!(store.head(), Some(head_after_one));
    assert_ne!(head_after_one, head_after_two, "the anchored head tells the rollback apart");
}

#[test]
fn expired_entries_are_pruned_from_the_index_and_capacity_is_enforced() {
    let dir = TempDir::new("capacity");
    let path = dir.file("uses.log");
    let store = FileUseStore::open(&path, 2).unwrap();
    let d = |s: &str| CapabilityDigest::of_wire(s.as_bytes());
    store.record_use(&UseKey { cap_id: "a", digest: &d("a") }, true, 100, 0).unwrap();
    store.record_use(&UseKey { cap_id: "b", digest: &d("b") }, true, 200, 0).unwrap();
    assert_eq!(
        store.record_use(&UseKey { cap_id: "c", digest: &d("c") }, true, 300, 0),
        Err(UseError::Unavailable)
    );
    // Once "a" has expired there is room; the log keeps every record.
    store.record_use(&UseKey { cap_id: "c", digest: &d("c") }, true, 300, 100).unwrap();
    assert_eq!(store.len(), Some(2));
    assert_eq!(store.records(), Some(3));
}

#[test]
fn concurrent_consumption_is_accepted_exactly_once() {
    let dir = TempDir::new("concurrent");
    let path = dir.file("uses.log");
    let store = Arc::new(FileUseStore::open(&path, 64).unwrap());
    let auth = Arc::new(authority_with(production_config()));
    let wire = Arc::new(one_time_wire("cap-race", "n1"));
    let threads = 16;
    let barrier = Arc::new(std::sync::Barrier::new(threads));
    let handles: Vec<_> = (0..threads)
        .map(|_| {
            let (store, auth, wire, barrier) = (store.clone(), auth.clone(), wire.clone(), barrier.clone());
            std::thread::spawn(move || {
                barrier.wait();
                auth.authorize(&wire, &baseline_request(), &clock(), store.as_ref())
                    .map(|_| ())
            })
        })
        .collect();
    let results: Vec<_> = handles.into_iter().map(|h| h.join().unwrap()).collect();
    assert_eq!(results.iter().filter(|r| r.is_ok()).count(), 1);
    assert_eq!(results.iter().filter(|r| **r == Err(AuthzError::Replay)).count(), threads - 1);
    assert_eq!(store.records(), Some(1));

    // The same holds for the in-memory store.
    let mem = Arc::new(memory_store());
    let auth = Arc::new(authority_with(common::memory_store_config()));
    let barrier = Arc::new(std::sync::Barrier::new(threads));
    let handles: Vec<_> = (0..threads)
        .map(|_| {
            let (mem, auth, wire, barrier) = (mem.clone(), auth.clone(), wire.clone(), barrier.clone());
            std::thread::spawn(move || {
                barrier.wait();
                auth.authorize(&wire, &baseline_request(), &clock(), mem.as_ref())
                    .map(|_| ())
            })
        })
        .collect();
    let results: Vec<_> = handles.into_iter().map(|h| h.join().unwrap()).collect();
    assert_eq!(results.iter().filter(|r| r.is_ok()).count(), 1);
}

/// A durable store that cannot answer.
#[derive(Debug)]
struct BrokenStore;

impl UseStore for BrokenStore {
    fn record_use(&self, _: &UseKey<'_>, _: bool, _: u64, _: u64) -> Result<(), UseError> {
        Err(UseError::Unavailable)
    }

    fn is_durable(&self) -> bool {
        true
    }
}

#[test]
fn an_unavailable_store_denies_even_a_valid_capability() {
    let auth = authority_with(production_config());
    assert_eq!(
        auth.authorize(&common::baseline_wire(), &baseline_request(), &clock(), &BrokenStore),
        Err(AuthzError::StoreUnavailable)
    );
    assert_eq!(
        auth.authorize(&one_time_wire("cap-once", "n1"), &baseline_request(), &clock(), &BrokenStore),
        Err(AuthzError::StoreUnavailable)
    );
}

#[test]
fn a_corrupted_log_cannot_be_opened_so_the_verifier_denies() {
    let dir = TempDir::new("corrupt-deny");
    let path = dir.file("uses.log");
    {
        let store = FileUseStore::open(&path, 16).unwrap();
        store
            .record_use(&UseKey { cap_id: "one", digest: &CapabilityDigest::of_wire(b"one") }, true, T0 + 10, T0)
            .unwrap();
    }
    let mut bytes = std::fs::read(&path).unwrap();
    let last = bytes.len() - 1;
    bytes[last] ^= 0x80;
    std::fs::write(&path, &bytes).unwrap();
    // There is no store to hand the verifier; the only honest answer is
    // to deny, which a caller does by not running without one.
    assert_eq!(FileUseStore::open(&path, 16).map(|_| ()).unwrap_err(), UseError::Unavailable);
}
