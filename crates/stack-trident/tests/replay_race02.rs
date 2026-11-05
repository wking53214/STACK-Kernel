//! RACE-02 replay list (I-09 Step 3): cases the Phase Zero baseline found
//! uncovered. Replay after a key rotation plus a restart on the same
//! FileStore (R2-E-05); a quarantine or release mark the store fails to
//! persist (R2-E-05 / D-24); and audience binding in Production after the
//! check-and-commit change.
//!
//! Single host, one process, one clock. Not a multi-host test.
//!
//! Every key is a TEST FIXTURE derived from a public label (see
//! tests/common/mod.rs) and must never be used outside tests.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use std::io;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use common::*;
use hmac::{Hmac, Mac};
use metrics_util::debugging::{DebugValue, DebuggingRecorder};
use metrics_util::MetricKind;
use sha2::Sha256;
use stack_trident::canonical::{to_canonical_bytes, to_hex};
use stack_trident::telemetry as t;
use stack_trident::{
    seal, seal_for, AcceptRecord, Clock, EnvelopeDraft, FileStore, Fingerprint, GateOutcome, GatePosition,
    HandoffEnvelope, KeyMeta, KeyPurpose, KeyRing, KeyStatus, ManualClock, ReasonCode, ReplayStore, Resolution,
    RestoredState, StoreError, Trident, TridentConfig, MAC_AUDIENCE_DOMAIN,
};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

const AUD: &str = "rx-1";

fn scratch(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("stack-trident-race02-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn meta(status: KeyStatus) -> KeyMeta {
    KeyMeta::new("issuer:test-fixture", KeyPurpose::Handoff, 0, None)
        .unwrap()
        .with_status(status)
}

/// A metadata ring: each label with its status.
fn ring(keys: &[(&str, KeyStatus)]) -> KeyRing {
    let mut ring = KeyRing::new(16);
    for (label, status) in keys {
        ring.insert_with_meta(fixture_key(label), meta(*status)).unwrap();
    }
    ring
}

fn start(path: &Path, cfg: TridentConfig, ring: KeyRing, clock: &Arc<ManualClock>) -> Trident {
    let store = FileStore::open(path).unwrap();
    Trident::new_with_store(cfg, ring, Arc::clone(clock) as Arc<dyn Clock>, Box::new(store)).unwrap()
}

fn draft(seq: u64, at: u64) -> EnvelopeDraft {
    EnvelopeDraft {
        sequence: seq,
        issued_at_unix_ms: at,
        nonce: nonce_for(seq),
        gate_position: GatePosition::Alpha,
        gate_outcome: GateOutcome::Pass,
        payload: payload_for(seq),
    }
}

fn sealed(label: &str, seq: u64, clock: &ManualClock) -> HandoffEnvelope {
    let limits = TridentConfig::production(AUD).limits();
    seal_for(draft(seq, clock.now_unix_ms()), &fixture_key(label), AUD, &limits).unwrap()
}

/// Recomputes the audience-bound MAC independently of the crate's writer,
/// for envelopes a key holder signed on purpose with a payload that does
/// not match its subject digest (an authenticated terminal breach).
fn remac_for(env: &mut HandoffEnvelope, label: &str, audience: &str) {
    use sha2::Digest;
    let key = Sha256::digest(format!("stack-trident TEST FIXTURE key: {label}").as_bytes());
    let mut v = to_value(env);
    v.as_object_mut().unwrap().remove("mac");
    let lim = TridentConfig::production(audience).limits();
    let mut input = MAC_AUDIENCE_DOMAIN.to_vec();
    input.extend_from_slice(audience.len().to_string().as_bytes());
    input.push(b':');
    input.extend_from_slice(audience.as_bytes());
    input.push(b'\n');
    input.extend(to_canonical_bytes(&v, &lim).unwrap());
    let mut m = <Hmac<Sha256> as Mac>::new_from_slice(&key).unwrap();
    m.update(&input);
    env.mac = to_hex(&m.finalize().into_bytes());
}

fn transplanted(label: &str, seq: u64, clock: &ManualClock) -> HandoffEnvelope {
    let mut env = sealed(label, seq, clock);
    env.payload = serde_json::json!({"moved": seq});
    remac_for(&mut env, label, AUD);
    env
}

/// A FileStore whose quarantine and release marks fail while `fail` is set.
#[derive(Debug)]
struct MarksFail {
    inner: FileStore,
    fail: Arc<AtomicBool>,
}

impl MarksFail {
    fn injected() -> StoreError {
        StoreError::Io {
            op: "write record",
            kind: io::ErrorKind::Other,
            message: "injected mark failure".into(),
        }
    }
}

impl ReplayStore for MarksFail {
    fn load(&mut self) -> Result<RestoredState, StoreError> {
        self.inner.load()
    }
    fn commit(&mut self, record: &AcceptRecord) -> Result<(), StoreError> {
        self.inner.commit(record)
    }
    fn is_durable(&self) -> bool {
        self.inner.is_durable()
    }
    fn record_quarantine(&mut self, sender: &Fingerprint, since_unix_ms: u64) -> Result<(), StoreError> {
        if self.fail.load(Ordering::SeqCst) {
            return Err(Self::injected());
        }
        self.inner.record_quarantine(sender, since_unix_ms)
    }
    fn record_release(&mut self, sender: &Fingerprint) -> Result<(), StoreError> {
        if self.fail.load(Ordering::SeqCst) {
            return Err(Self::injected());
        }
        self.inner.record_release(sender)
    }
    fn raise_epoch_floor(&mut self, floor_ms: u64) -> Result<(), StoreError> {
        self.inner.raise_epoch_floor(floor_ms)
    }
}

fn start_marks_fail(path: &Path, cfg: TridentConfig, clock: &Arc<ManualClock>, fail: &Arc<AtomicBool>) -> Trident {
    let store = MarksFail {
        inner: FileStore::open(path).unwrap(),
        fail: Arc::clone(fail),
    };
    let ring = ring(&[("a", KeyStatus::Active), ("b", KeyStatus::Active)]);
    Trident::new_with_store(cfg, ring, Arc::clone(clock) as Arc<dyn Clock>, Box::new(store)).unwrap()
}

fn counter_of<F: FnOnce()>(name: &str, labels: &[(&str, &str)], f: F) -> u64 {
    let recorder = DebuggingRecorder::new();
    let snapshotter = recorder.snapshotter();
    metrics::with_local_recorder(&recorder, f);
    let want: Vec<(String, String)> = labels.iter().map(|(k, v)| ((*k).to_owned(), (*v).to_owned())).collect();
    snapshotter
        .snapshot()
        .into_vec()
        .into_iter()
        .filter_map(|(ck, _, _, value)| {
            let (kind, key) = ck.into_parts();
            let got: Vec<(String, String)> = key
                .labels()
                .map(|l| (l.key().to_owned(), l.value().to_owned()))
                .collect();
            match (kind, value) {
                (MetricKind::Counter, DebugValue::Counter(n)) if key.name() == name && got == want => Some(n),
                _ => None,
            }
        })
        .sum()
}

// ---------------------------------------------------------------------------
// Replay after key rotation plus restart (R2-E-05)
// ---------------------------------------------------------------------------

/// Accepted under K1. The ring becomes K2 active plus K1 retired; the
/// process restarts on the same FileStore with that ring. The envelope is
/// refused before and after the restart, and still refused (as a replay)
/// even if an operator mistakenly reactivates K1: replay protection rests
/// on the store, not on the key's status.
#[test]
fn replay_after_key_rotation_and_restart_is_refused() {
    let dir = scratch("rotation");
    let path = dir.join("replay.log");
    let clock = Arc::new(ManualClock::new(T0));
    let cfg = TridentConfig::production(AUD);
    let first = start(&path, cfg.clone(), ring(&[("k1", KeyStatus::Active)]), &clock);
    clock.advance(cfg.max_future_skew_ms + 1);
    let env = sealed("k1", 1, &clock);
    assert!(first.verify(&env).is_accepted());

    // Rotation in place.
    first
        .replace_keyring(ring(&[("k2", KeyStatus::Active), ("k1", KeyStatus::Retired)]))
        .unwrap();
    let v = first.verify(&env);
    assert_eq!(v.reasons(), &[ReasonCode::KeyRetired], "{v:?}");
    clock.advance(100);
    assert!(first.verify(&sealed("k2", 1, &clock)).is_accepted(), "K2 must work after rotation");
    drop(first);

    // Restart with the rotated ring, inside the skew window of the
    // acceptance, so only state can refuse it.
    clock.advance(100);
    let rotated = start(&path, cfg.clone(), ring(&[("k2", KeyStatus::Active), ("k1", KeyStatus::Retired)]), &clock);
    let v = rotated.verify(&env);
    assert!(!v.is_accepted(), "replayed after rotation and restart: {v:?}");
    assert!(v.refusal().unwrap().has(ReasonCode::KeyRetired), "{v:?}");
    // K2's acceptance is also remembered across the restart.
    clock.advance(cfg.max_future_skew_ms + 1);
    let v = rotated.verify(&sealed("k2", 1, &clock));
    assert!(v.refusal().unwrap().has(ReasonCode::SequenceNotIncreasing), "{v:?}");
    drop(rotated);

    // Operator mistake: K1 active again after another restart, with the
    // clock back inside the original envelope's skew window by override.
    let back = TridentConfig {
        dangerously_allow_clock_behind_store: true,
        ..cfg
    };
    clock.set(env.issued_at_unix_ms + 10);
    let reactivated = start(&path, back, ring(&[("k1", KeyStatus::Active), ("k2", KeyStatus::Active)]), &clock);
    let v = reactivated.verify(&env);
    assert!(!v.is_accepted(), "replayed after K1 was reactivated: {v:?}");
    assert!(v.refusal().unwrap().has(ReasonCode::Replay), "{v:?}");
}

// ---------------------------------------------------------------------------
// Quarantine and release mark persistence failure (R2-E-05 / D-24)
// ---------------------------------------------------------------------------

/// Production: a quarantine the store fails to persist halts the
/// verifier (fail closed), is counted, and an operator reset does not
/// resume until the mark is persisted.
#[test]
fn production_fails_closed_when_a_quarantine_mark_cannot_be_persisted() {
    let dir = scratch("q-fail-prod");
    let path = dir.join("replay.log");
    let clock = Arc::new(ManualClock::new(T0));
    let fail = Arc::new(AtomicBool::new(true));
    let cfg = TridentConfig {
        breaker_threshold: 1,
        ..TridentConfig::production(AUD)
    };
    let trident = start_marks_fail(&path, cfg.clone(), &clock, &fail);
    clock.advance(cfg.max_future_skew_ms + 1);

    let mut verdict = None;
    let failures = counter_of(t::STORE_FAILURES_TOTAL, &[], || {
        verdict = Some(trident.verify(&transplanted("a", 1, &clock)));
    });
    assert_eq!(verdict.unwrap().refusal().unwrap().resolution, Resolution::Quarantine);
    assert_eq!(failures, 1, "the failed quarantine mark was not counted");
    assert!(trident.is_halted(), "Production continued with an unpersisted quarantine");
    // Every sender is refused while halted, not only the quarantined one.
    let v = trident.verify(&sealed("b", 1, &clock));
    assert_eq!(v.reasons(), &[ReasonCode::Halted], "{v:?}");

    // A reset while the store still fails does not resume.
    let halts = counter_of(t::HALTS_TOTAL, &[("cause", "store_failure")], || trident.operator_reset());
    assert!(trident.is_halted(), "reset resumed with the quarantine still unpersisted");
    assert_eq!(halts, 0, "staying halted is not a new halt");

    // Once the store recovers, a reset persists the mark and resumes.
    fail.store(false, Ordering::SeqCst);
    trident.operator_reset();
    assert!(!trident.is_halted());
    clock.advance(cfg.max_future_skew_ms + 1);
    assert!(trident.verify(&sealed("b", 2, &clock)).is_accepted());
    assert!(trident.verify(&sealed("a", 2, &clock)).refusal().unwrap().has(ReasonCode::Quarantined));
    drop(trident);

    // The quarantine survived to disk.
    let restarted = start(&path, cfg, ring(&[("a", KeyStatus::Active), ("b", KeyStatus::Active)]), &clock);
    assert_eq!(restarted.quarantined().unwrap(), vec![fixture_key("a").fingerprint()]);
}

/// The halt itself is counted with its own cause.
#[test]
fn a_store_failure_halt_is_counted_with_its_cause() {
    let dir = scratch("q-fail-count");
    let path = dir.join("replay.log");
    let clock = Arc::new(ManualClock::new(T0));
    let fail = Arc::new(AtomicBool::new(true));
    let cfg = TridentConfig {
        breaker_threshold: 1,
        ..TridentConfig::production(AUD)
    };
    let trident = start_marks_fail(&path, cfg.clone(), &clock, &fail);
    clock.advance(cfg.max_future_skew_ms + 1);
    let halts = counter_of(t::HALTS_TOTAL, &[("cause", "store_failure")], || {
        trident.verify(&transplanted("a", 1, &clock));
    });
    assert_eq!(halts, 1);
}

/// Development keeps the documented best-effort posture: the quarantine
/// stands in memory, the failure is counted, the verifier keeps working,
/// and the lost mark is what a restart forgets.
#[test]
fn development_counts_a_failed_quarantine_mark_and_keeps_the_in_memory_quarantine() {
    let dir = scratch("q-fail-dev");
    let path = dir.join("replay.log");
    let clock = Arc::new(ManualClock::new(T0));
    let fail = Arc::new(AtomicBool::new(true));
    let cfg = TridentConfig {
        breaker_threshold: 1,
        audience: AUD.into(),
        ..TridentConfig::default()
    };
    let trident = start_marks_fail(&path, cfg.clone(), &clock, &fail);
    clock.advance(cfg.max_future_skew_ms + 1);
    let failures = counter_of(t::STORE_FAILURES_TOTAL, &[], || {
        trident.verify(&transplanted("a", 1, &clock));
    });
    assert_eq!(failures, 1);
    assert!(!trident.is_halted());
    assert_eq!(trident.quarantined().unwrap(), vec![fixture_key("a").fingerprint()]);
    assert!(trident.verify(&sealed("b", 1, &clock)).is_accepted());
}

/// A release mark that fails is counted; the quarantine comes back on
/// restart, which is the restrictive outcome, in every profile.
#[test]
fn a_failed_release_mark_is_counted_and_the_quarantine_returns_on_restart() {
    let dir = scratch("r-fail");
    let path = dir.join("replay.log");
    let clock = Arc::new(ManualClock::new(T0));
    let fail = Arc::new(AtomicBool::new(false));
    let cfg = TridentConfig {
        breaker_threshold: 1,
        ..TridentConfig::production(AUD)
    };
    let trident = start_marks_fail(&path, cfg.clone(), &clock, &fail);
    clock.advance(cfg.max_future_skew_ms + 1);
    trident.verify(&transplanted("a", 1, &clock));
    let fp_a = fixture_key("a").fingerprint();
    assert_eq!(trident.quarantined().unwrap(), vec![fp_a]);
    fail.store(true, Ordering::SeqCst);
    let failures = counter_of(t::STORE_FAILURES_TOTAL, &[], || {
        assert!(trident.release(&fp_a).unwrap());
    });
    assert_eq!(failures, 1);
    assert!(!trident.is_halted(), "a lost release is restrictive and does not halt");
    drop(trident);
    let restarted = start(&path, cfg, ring(&[("a", KeyStatus::Active), ("b", KeyStatus::Active)]), &clock);
    assert_eq!(restarted.quarantined().unwrap(), vec![fp_a], "a release that was never stored took effect");
}

// ---------------------------------------------------------------------------
// Audience binding in Production, after check-and-commit
// ---------------------------------------------------------------------------

#[test]
fn production_still_refuses_missing_and_wrong_audience() {
    let dir = scratch("audience");
    let path = dir.join("replay.log");
    let clock = Arc::new(ManualClock::new(T0));
    let cfg = TridentConfig::production(AUD);
    let trident = start(&path, cfg.clone(), ring(&[("a", KeyStatus::Active)]), &clock);
    clock.advance(cfg.max_future_skew_ms + 1);
    let key = fixture_key("a");
    let limits = cfg.limits();
    let missing = seal(draft(1, clock.now_unix_ms()), &key, &limits).unwrap();
    assert_eq!(trident.verify(&missing).reasons(), &[ReasonCode::MacMismatch]);
    let wrong = seal_for(draft(2, clock.now_unix_ms()), &key, "rx-2", &limits).unwrap();
    assert_eq!(trident.verify(&wrong).reasons(), &[ReasonCode::MacMismatch]);
    // Neither refusal reached the store: sequence 1 and 2 are still free.
    let mine1 = seal_for(draft(1, clock.now_unix_ms()), &key, AUD, &limits).unwrap();
    assert!(trident.verify(&mine1).is_accepted());
    let mine2 = seal_for(draft(2, clock.now_unix_ms()), &key, AUD, &limits).unwrap();
    assert!(trident.verify(&mine2).is_accepted());
    // And the accepted one is not accepted again for another audience's
    // receiver on the same store after a restart (rebinding is a MAC
    // mismatch, and the store still holds the nonce).
    drop(trident);
    let other = start(&path, TridentConfig::production("rx-2"), ring(&[("a", KeyStatus::Active)]), &clock);
    let v = other.verify(&mine1);
    assert!(!v.is_accepted() && v.refusal().unwrap().has(ReasonCode::MacMismatch), "{v:?}");
}
