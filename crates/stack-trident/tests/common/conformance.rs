//! Reusable conformance suite for the `ReplayStore` check-and-commit
//! contract (decision D, R2-E-04). Any store, including a future shared
//! one, runs [`replay_store_conformance`]; a store whose state can be
//! reached through more than one handle also runs
//! [`replay_store_shared_conformance`].
//!
//! What this suite proves is TRAIT SEMANTICS inside one process. It is not
//! a multi-host test and says nothing about a store shared across hosts.
//!
//! Store-specific fault cases (a torn tail, an I/O failure) cannot be
//! expressed through the trait alone; the file store's are in
//! tests/store_conformance.rs.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::sync::{Arc, Barrier, Mutex};

use stack_trident::{AcceptRecord, Fingerprint, Nonce, ReplayStore, StoreError};

/// Receiver clock used by the suite (Unix ms).
const AT: u64 = 1_800_000_000_000;
/// Nonce retention used by the suite.
const KEEP: u64 = 60_000;

fn fp(b: u8) -> Fingerprint {
    Fingerprint::from_bytes([b; 32])
}

fn nonce(b: u8) -> Nonce {
    Nonce::from_bytes([b; 16])
}

/// A record from sender `s` with `seq` and nonce `n`, issued and accepted
/// at `at`.
fn rec(s: u8, seq: u64, n: u8, at: u64) -> AcceptRecord {
    AcceptRecord {
        sender: fp(s),
        sequence: seq,
        nonce: nonce(n),
        issued_at_unix_ms: at,
        accepted_at_unix_ms: at,
        nonce_expires_at_unix_ms: at + KEEP,
    }
}

fn loaded(make: &impl Fn() -> Box<dyn ReplayStore>) -> Box<dyn ReplayStore> {
    let mut s = make();
    s.load().expect("a fresh store must load");
    s
}

fn conflict(r: Result<(), StoreError>) -> (bool, Option<u64>, Option<u64>) {
    match r {
        Err(StoreError::Conflict {
            nonce_consumed,
            stored_sequence,
            epoch_floor_ms,
        }) => (nonce_consumed, stored_sequence, epoch_floor_ms),
        other => panic!("expected a Conflict, got {other:?}"),
    }
}

/// Runs every generic case against fresh stores from `make`. Each case
/// gets its own store. Panics with the case name on the first violation.
pub fn replay_store_conformance(make: impl Fn() -> Box<dyn ReplayStore>) {
    // Duplicate nonce, with a higher sequence: refused, nonce named.
    let mut s = loaded(&make);
    s.commit(&rec(1, 1, 7, AT)).expect("first commit");
    assert_eq!(conflict(s.commit(&rec(1, 2, 7, AT + 1))), (true, None, None), "duplicate nonce");
    // The same nonce from another sender is a different pair.
    s.commit(&rec(2, 1, 7, AT + 1)).expect("same nonce, other sender");

    // Sequence equal and lower, with fresh nonces: refused, stored named.
    let mut s = loaded(&make);
    s.commit(&rec(1, 5, 1, AT)).expect("first commit");
    assert_eq!(conflict(s.commit(&rec(1, 5, 2, AT + 1))), (false, Some(5), None), "equal sequence");
    assert_eq!(conflict(s.commit(&rec(1, 4, 3, AT + 2))), (false, Some(5), None), "lower sequence");
    assert_eq!(conflict(s.commit(&rec(1, 0, 4, AT + 3))), (false, Some(5), None), "sequence zero");
    // Both at once: both named.
    assert_eq!(conflict(s.commit(&rec(1, 5, 1, AT + 4))), (true, Some(5), None), "both");
    // Higher: accepted.
    s.commit(&rec(1, 6, 5, AT + 5)).expect("higher sequence must commit");
    s.commit(&rec(1, u64::MAX, 6, AT + 6)).expect("u64::MAX sequence must commit");
    assert_eq!(conflict(s.commit(&rec(1, u64::MAX, 7, AT + 7))).1, Some(u64::MAX), "no wrap at MAX");

    // Epoch floor: refused below, accepted at, never lowered.
    let mut s = loaded(&make);
    s.raise_epoch_floor(AT).expect("raise floor");
    assert_eq!(conflict(s.commit(&rec(1, 1, 1, AT - 1))), (false, None, Some(AT)), "below floor");
    s.raise_epoch_floor(AT - 10_000).expect("a lower floor is not an error");
    assert_eq!(conflict(s.commit(&rec(1, 1, 1, AT - 1))).2, Some(AT), "floor was lowered");
    s.commit(&rec(1, 1, 1, AT)).expect("at the floor must commit");
    assert_eq!(s.load().expect("reload").epoch_floor_ms, AT, "floor not in the view");

    // High-water mark: the maximum issued_at, never regressing.
    let mut s = loaded(&make);
    s.commit(&rec(1, 1, 1, AT + 100)).expect("commit");
    s.commit(&rec(2, 1, 2, AT + 50)).expect("an older issued_at from another sender is not a conflict");
    assert_eq!(s.load().expect("reload").high_water_ms, AT + 100, "high-water regressed");

    // Commit after failure: a refused record leaves no trace.
    let mut s = loaded(&make);
    s.commit(&rec(1, 10, 1, AT)).expect("commit");
    let mut huge = rec(1, 20, 1, AT + 1);
    huge.issued_at_unix_ms = AT + 1_000_000;
    let _ = conflict(s.commit(&huge));
    // Sequence 20 was not recorded: 15 still commits.
    s.commit(&rec(1, 15, 2, AT + 2)).expect("a refused sequence was recorded");
    // Nonce 3 offered with a stale sequence was not recorded.
    let _ = conflict(s.commit(&rec(1, 5, 3, AT + 3)));
    s.commit(&rec(1, 16, 3, AT + 4)).expect("a refused nonce was recorded");
    let view = s.load().expect("reload");
    assert_eq!(view.high_water_ms, AT + 4, "a refused record moved the high-water mark");
    let a = view.senders.iter().find(|x| x.sender == fp(1)).expect("sender in view");
    assert_eq!(a.last_sequence, 16);
    // The store still works after any number of conflicts.
    for _ in 0..50 {
        let _ = conflict(s.commit(&rec(1, 16, 3, AT + 5)));
    }
    s.commit(&rec(1, 17, 4, AT + 6)).expect("commit after repeated conflicts");

    // Retention: a nonce whose retention has ended may be reused (with a
    // higher sequence); one still inside it may not.
    let mut s = loaded(&make);
    s.commit(&rec(1, 1, 9, AT)).expect("commit");
    assert!(conflict(s.commit(&rec(1, 2, 9, AT + KEEP - 1))).0, "nonce forgotten early");
    s.commit(&rec(1, 3, 9, AT + KEEP)).expect("nonce kept past its retention");

    // Concurrent commits of one record through one store: exactly one wins.
    let s = Arc::new(Mutex::new(loaded(&make)));
    let handles: Vec<_> = (0..16).map(|_| Arc::clone(&s)).collect();
    let wins = race(handles, |h, r| h.lock().unwrap().commit(r));
    assert_eq!(wins, 1, "concurrent commits of one record: {wins} won");
}

/// For a store whose state more than one handle reaches (a shared store):
/// `make_handles(n)` returns `n` handles to ONE fresh state. Each thread
/// commits through its OWN handle, with no lock outside the store, so the
/// store's own atomicity is all that stands between two acceptances.
pub fn replay_store_shared_conformance(make_handles: impl Fn(usize) -> Vec<Box<dyn ReplayStore>>) {
    // Sequential: what one handle committed, the other refuses.
    let mut pair = make_handles(2);
    for h in &mut pair {
        h.load().expect("load");
    }
    let (a, b) = pair.split_at_mut(1);
    let (a, b) = (&mut a[0], &mut b[0]);
    a.commit(&rec(1, 1, 1, AT)).expect("a commits");
    assert_eq!(conflict(b.commit(&rec(1, 1, 1, AT))), (true, Some(1), None), "b re-accepted a's record");
    assert_eq!(conflict(b.commit(&rec(1, 1, 2, AT))).1, Some(1), "b accepted a duplicate sequence");
    assert!(conflict(b.commit(&rec(1, 2, 1, AT))).0, "b accepted a duplicate nonce");
    a.raise_epoch_floor(AT + 10).expect("a raises the floor");
    assert_eq!(conflict(b.commit(&rec(1, 9, 9, AT + 9))).2, Some(AT + 10), "b ignored a's floor");
    b.commit(&rec(1, 2, 2, AT + 10)).expect("b commits fresh work");
    assert_eq!(conflict(a.commit(&rec(1, 2, 3, AT + 11))).1, Some(2), "a missed b's commit");

    // Concurrent: 8 rounds of 16 threads, one handle each.
    for round in 0..8 {
        let mut handles = make_handles(16);
        for h in &mut handles {
            h.load().expect("load");
        }
        let wins = race(handles, |h, r| h.commit(r));
        assert_eq!(wins, 1, "round {round}: {wins} handles committed the same record");
    }
}

/// Starts one thread per handle at a barrier; each commits one identical
/// record through its own handle. Returns how many succeeded, and checks
/// every loser saw a Conflict (not some other error).
fn race<H: Send + 'static>(handles: Vec<H>, commit: fn(&mut H, &AcceptRecord) -> Result<(), StoreError>) -> usize {
    let barrier = Arc::new(Barrier::new(handles.len()));
    let record = rec(3, 1, 1, AT);
    let threads: Vec<_> = handles
        .into_iter()
        .map(|mut h| {
            let barrier = Arc::clone(&barrier);
            std::thread::spawn(move || {
                barrier.wait();
                commit(&mut h, &record)
            })
        })
        .collect();
    let mut wins = 0;
    for t in threads {
        match t.join().expect("thread") {
            Ok(()) => wins += 1,
            Err(StoreError::Conflict { .. }) => {}
            Err(other) => panic!("a losing concurrent commit must be a Conflict, got {other:?}"),
        }
    }
    wins
}
