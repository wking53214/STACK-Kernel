//! R-8 (4) at the admission boundary: storage that becomes unavailable
//! while the kernel is running denies, and nothing executes. Each wrapper
//! delegates to the real file store until told to fail, so the stores
//! behind it are the real durable ones.
//!
//! Every key is a TEST FIXTURE (tests/common/mod.rs).

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use common::*;
use stack_admission::{AdmissionResult, RefusalReason, Stage};
use stack_authority::{AuthzError, FileUseStore, UseError, UseKey, UseStore};
use stack_trident::{
    AcceptRecord, FileStore, Fingerprint, ReasonCode, ReplayStore, RestoredState, StoreError,
};

#[derive(Debug)]
struct LosesUseStore {
    inner: FileUseStore,
    lost: Arc<AtomicBool>,
}

impl UseStore for LosesUseStore {
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

#[derive(Debug)]
struct LosesReplayStore {
    inner: FileStore,
    lost: Arc<AtomicBool>,
}

impl ReplayStore for LosesReplayStore {
    fn load(&mut self) -> Result<RestoredState, StoreError> {
        self.inner.load()
    }
    fn commit(&mut self, record: &AcceptRecord) -> Result<(), StoreError> {
        if self.lost.load(Ordering::SeqCst) {
            return Err(StoreError::Io {
                op: "write",
                kind: std::io::ErrorKind::Other,
                message: "storage lost (test)".into(),
            });
        }
        self.inner.commit(record)
    }
    fn is_durable(&self) -> bool {
        true
    }
    fn record_quarantine(&mut self, sender: &Fingerprint, since_unix_ms: u64) -> Result<(), StoreError> {
        self.inner.record_quarantine(sender, since_unix_ms)
    }
    fn record_release(&mut self, sender: &Fingerprint) -> Result<(), StoreError> {
        self.inner.record_release(sender)
    }
    fn raise_epoch_floor(&mut self, floor_ms: u64) -> Result<(), StoreError> {
        self.inner.raise_epoch_floor(floor_ms)
    }
}

#[test]
fn the_use_store_lost_mid_run_denies_executes_nothing_and_consumes_nothing() {
    let dir = TempDir::new("use-lost");
    let lost = Arc::new(AtomicBool::new(false));
    let h = Builder::new(dir.path())
        .use_store(Box::new(LosesUseStore {
            inner: FileUseStore::open(uses_path(dir.path()), 1024).unwrap(),
            lost: Arc::clone(&lost),
        }))
        .start();
    let case = all_pass();
    let payload = honest_payload(&case, "echo");

    assert!(h.process(payload.clone()).is_success());
    assert_eq!(h.runs(), 1);

    // A second honest request while storage is gone.
    let second = honest_payload(&case, "echo");
    lost.store(true, Ordering::SeqCst);
    match h.process(second.clone()) {
        AdmissionResult::Refused(r) => {
            assert_eq!(r.stage, Stage::Authorization);
            assert_eq!(r.reason, RefusalReason::Authorization(AuthzError::StoreUnavailable));
            h.assert_rejected_recorded(&r);
        }
        other => panic!("expected a refusal, got {other:?}"),
    }
    assert_eq!(h.runs(), 1, "nothing may execute while the use store is unavailable");

    // The first capability, replayed while storage is gone, is denied too.
    assert!(matches!(h.process(payload), AdmissionResult::Refused(_)));
    assert_eq!(h.runs(), 1);

    // Storage returns: the capability whose attempt failed was never consumed.
    lost.store(false, Ordering::SeqCst);
    assert!(h.process(second).is_success());
    assert_eq!(h.runs(), 2);
}

#[test]
fn the_replay_store_lost_mid_run_denies_at_the_handoff_and_executes_nothing() {
    let dir = TempDir::new("replay-lost");
    let lost = Arc::new(AtomicBool::new(false));
    let h = Builder::new(dir.path())
        .replay_store(Box::new(LosesReplayStore {
            inner: FileStore::open(replay_path(dir.path())).unwrap(),
            lost: Arc::clone(&lost),
        }))
        .start();
    let case = all_pass();
    assert!(h.process(honest_payload(&case, "echo")).is_success());
    assert_eq!(h.runs(), 1);

    lost.store(true, Ordering::SeqCst);
    match h.process(honest_payload(&case, "echo")) {
        AdmissionResult::Refused(r) => {
            assert_eq!(r.stage, Stage::Handoff);
            match &r.reason {
                RefusalReason::Handoff(refusal) => assert!(refusal.has(ReasonCode::StateUnavailable), "{refusal:?}"),
                other => panic!("expected a handoff refusal, got {other:?}"),
            }
            h.assert_unrecorded(&r);
        }
        other => panic!("expected a refusal, got {other:?}"),
    }
    assert_eq!(h.runs(), 1);
}
