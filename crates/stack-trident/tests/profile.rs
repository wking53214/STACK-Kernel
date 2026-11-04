//! Behaviour tests for the deployment profiles (D-16) and the key
//! lifecycle (D-10): what a Production Trident refuses at start, how an
//! acceptance is marked, audience binding between receivers, and keys
//! that are not yet valid, expired, retired or revoked.
//!
//! Every key is a TEST FIXTURE derived from a public label (see
//! tests/common/mod.rs) and must never be used outside tests.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use std::path::{Path, PathBuf};
use std::sync::Arc;

use common::*;
use stack_trident::{
    seal, seal_for, Assurance, Clock, DeploymentProfile, DevelopmentAssurance, EnvelopeDraft, FileStore, GateOutcome,
    GatePosition, HandoffEnvelope, KeyMeta, KeyPurpose, KeyRing, KeyStatus, ManualClock, MemoryStore, ReasonCode,
    ReplaceKeyringError, SecretKey, StartError, Trident, TridentConfig,
};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn scratch(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("stack-trident-profile-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// Active, no planned end, issued by a test issuer.
fn active_meta() -> KeyMeta {
    KeyMeta::new("issuer:test-fixture", KeyPurpose::Handoff, 0, None).unwrap()
}

fn meta_ring(labels: &[&str]) -> KeyRing {
    let mut ring = KeyRing::new(16);
    for l in labels {
        ring.insert_with_meta(fixture_key(l), active_meta()).unwrap();
    }
    ring
}

fn legacy_ring(labels: &[&str]) -> KeyRing {
    let mut ring = KeyRing::new(16);
    for l in labels {
        ring.insert(fixture_key(l)).unwrap();
    }
    ring
}

fn production_cfg(audience: &str) -> TridentConfig {
    TridentConfig::production(audience)
}

fn start(path: &Path, cfg: TridentConfig, ring: KeyRing, clock: &Arc<ManualClock>) -> Result<Trident, StartError> {
    let store = FileStore::open(path)?;
    Trident::new_with_store(cfg, ring, Arc::clone(clock) as Arc<dyn Clock>, Box::new(store))
}

/// A Production Trident bound to `audience` on a fresh store, with the
/// clock stepped past the start-up floor.
fn production(path: &Path, audience: &str, ring: KeyRing) -> (Arc<ManualClock>, Trident) {
    let clock = Arc::new(ManualClock::new(T0));
    let cfg = production_cfg(audience);
    let trident = start(path, cfg.clone(), ring, &clock).unwrap();
    clock.advance(cfg.max_future_skew_ms + 1);
    (clock, trident)
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

fn sealed_for_audience(key: &SecretKey, seq: u64, clock: &ManualClock, audience: &str) -> HandoffEnvelope {
    seal_for(draft(seq, clock.now_unix_ms()), key, audience, &TridentConfig::default().limits()).unwrap()
}

fn config_field(result: Result<Trident, StartError>) -> &'static str {
    match result {
        Err(StartError::Config(e)) => e.field,
        other => panic!("expected a typed config error, got {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// Production refusals, each at start on a real durable store
// ---------------------------------------------------------------------------

#[test]
fn production_refuses_no_audience_the_unbound_opt_out_epoch_off_and_wide_skew_at_startup() {
    let dir = scratch("refusals");
    let clock = Arc::new(ManualClock::new(T0));
    let go = |name: &str, cfg: TridentConfig| config_field(start(&dir.join(name), cfg, meta_ring(&["a"]), &clock));

    let no_audience = TridentConfig {
        profile: DeploymentProfile::Production,
        ..TridentConfig::default()
    };
    assert_eq!(go("no-audience", no_audience), "audience");

    // The opt-out is refused even when an audience is also set: it has no
    // place in a production config.
    let opt_out = TridentConfig {
        profile: DeploymentProfile::Production,
        ..TridentConfig::unbound_audience()
    };
    assert_eq!(go("opt-out", opt_out), "allow_unbound_audience");
    let opt_out_with_audience = TridentConfig {
        allow_unbound_audience: true,
        ..production_cfg("rx-1")
    };
    assert_eq!(go("opt-out-audience", opt_out_with_audience), "allow_unbound_audience");

    let epoch_off = TridentConfig {
        enforce_startup_epoch: false,
        ..production_cfg("rx-1")
    };
    assert_eq!(go("epoch-off", epoch_off), "enforce_startup_epoch");

    let wide_past = TridentConfig {
        max_past_skew_ms: stack_trident::config::PRODUCTION_PAST_SKEW_CAP_MS + 1,
        ..production_cfg("rx-1")
    };
    assert_eq!(go("wide-past", wide_past), "max_past_skew_ms");
    let wide_future = TridentConfig {
        max_future_skew_ms: stack_trident::config::PRODUCTION_FUTURE_SKEW_CAP_MS + 1,
        ..production_cfg("rx-1")
    };
    assert_eq!(go("wide-future", wide_future), "max_future_skew_ms");

    // The same settings are accepted under Development, so it is the
    // profile that refuses them.
    for cfg in [
        TridentConfig::unbound_audience(),
        TridentConfig {
            enforce_startup_epoch: false,
            ..TridentConfig::unbound_audience()
        },
    ] {
        assert!(start(&dir.join("dev"), cfg, meta_ring(&["a"]), &clock).is_ok());
    }
    // And a Production config with none of them starts.
    assert!(start(&dir.join("ok"), production_cfg("rx-1"), meta_ring(&["a"]), &clock).is_ok());
}

#[test]
fn production_refuses_a_memory_store() {
    let clock = Arc::new(ManualClock::new(T0));
    let err = Trident::new(production_cfg("rx-1"), meta_ring(&["a"]), clock.clone()).unwrap_err();
    assert_eq!(err.field, "replay_store");
    let via_store = Trident::new_with_store(
        production_cfg("rx-1"),
        meta_ring(&["a"]),
        clock.clone(),
        Box::new(MemoryStore::new()),
    );
    assert_eq!(config_field(via_store), "replay_store");
    // Development on the same store is fine.
    assert!(Trident::new(TridentConfig::unbound_audience(), meta_ring(&["a"]), clock).is_ok());
}

#[test]
fn production_refuses_legacy_keys_at_start_and_on_ring_replacement() {
    let dir = scratch("legacy");
    let clock = Arc::new(ManualClock::new(T0));
    assert_eq!(
        config_field(start(&dir.join("legacy.log"), production_cfg("rx-1"), legacy_ring(&["a", "b"]), &clock)),
        "keyring.legacy_keys"
    );
    let mut mixed = meta_ring(&["a"]);
    mixed.insert(fixture_key("b")).unwrap();
    assert_eq!(
        config_field(start(&dir.join("mixed.log"), production_cfg("rx-1"), mixed, &clock)),
        "keyring.legacy_keys"
    );

    let (clock, trident) = production(&dir.join("ok.log"), "rx-1", meta_ring(&["a"]));
    let key_a = fixture_key("a");
    assert!(trident.verify(&sealed_for_audience(&key_a, 1, &clock, "rx-1")).is_accepted());
    // A legacy ring is refused and the ring in force is unchanged.
    assert_eq!(
        trident.replace_keyring(legacy_ring(&["a", "b"])),
        Err(ReplaceKeyringError::LegacyKeysInProduction { legacy: 2 })
    );
    assert!(trident.verify(&sealed_for_audience(&key_a, 2, &clock, "rx-1")).is_accepted());
    // A metadata ring without A revokes A.
    trident.replace_keyring(meta_ring(&["b"])).unwrap();
    let v = trident.verify(&sealed_for_audience(&key_a, 3, &clock, "rx-1"));
    assert_eq!(v.reasons(), &[ReasonCode::UnknownSender]);
}

// ---------------------------------------------------------------------------
// Assurance marking
// ---------------------------------------------------------------------------

#[test]
fn production_marks_handoffs_production_and_development_marks_them_development() {
    let dir = scratch("assurance");
    let (clock, prod) = production(&dir.join("prod.log"), "rx-1", meta_ring(&["a"]));
    assert_eq!(prod.profile(), DeploymentProfile::Production);
    let v = prod.verify(&sealed_for_audience(&fixture_key("a"), 1, &clock, "rx-1"));
    let h = v.accepted().expect("accepted");
    assert_eq!(h.assurance, Assurance::Production);
    assert!(h.is_production());
    assert!(h.require_production().is_ok());

    let fx = setup();
    assert_eq!(fx.trident.profile(), DeploymentProfile::Development);
    let v = fx.trident.verify(&fx.sealed(1));
    let h = v.accepted().expect("accepted");
    assert_eq!(h.assurance, Assurance::Development);
    assert!(!h.is_production());
    assert_eq!(h.require_production().map(|_| ()), Err(DevelopmentAssurance));
}

// ---------------------------------------------------------------------------
// Audience binding between receivers
// ---------------------------------------------------------------------------

#[test]
fn cross_receiver_redirection_with_the_same_key_between_two_production_receivers_is_refused() {
    let dir = scratch("redirect");
    let (clock1, rx1) = production(&dir.join("rx1.log"), "rx-1", meta_ring(&["a", "b"]));
    let (clock2, rx2) = production(&dir.join("rx2.log"), "rx-2", meta_ring(&["a", "b"]));
    clock2.set(clock1.now_unix_ms());
    let key_a = fixture_key("a");
    let for_rx1 = sealed_for_audience(&key_a, 1, &clock1, "rx-1");
    let for_rx2 = sealed_for_audience(&key_a, 1, &clock2, "rx-2");
    let wire = |e: &HandoffEnvelope| e.to_wire_bytes(&TridentConfig::default().limits()).unwrap();

    // Redirected before the intended receiver has seen it: it is the
    // audience, not replay state, that refuses it.
    let v = rx2.verify_wire(&wire(&for_rx1));
    assert_eq!(v.reasons(), &[ReasonCode::MacMismatch], "rx-2 took rx-1's envelope: {v:?}");
    let v = rx1.verify_wire(&wire(&for_rx2));
    assert_eq!(v.reasons(), &[ReasonCode::MacMismatch], "rx-1 took rx-2's envelope: {v:?}");
    // Each receiver accepts its own, once.
    assert!(rx1.verify_wire(&wire(&for_rx1)).is_accepted());
    assert!(rx2.verify_wire(&wire(&for_rx2)).is_accepted());
    // And still refuses the other's after that.
    assert!(!rx2.verify_wire(&wire(&for_rx1)).is_accepted());
    assert!(!rx1.verify_wire(&wire(&for_rx2)).is_accepted());
}

#[test]
fn an_envelope_sealed_with_an_audience_sent_to_an_unbound_receiver_is_refused() {
    // The unbound receiver is a Development one; Production cannot be unbound.
    let fx = setup();
    let bound = seal_for(draft(1, fx.now()), &fx.key_a, "rx-1", &fx.cfg.limits()).unwrap();
    let v = fx.trident.verify(&bound);
    assert_eq!(v.reasons(), &[ReasonCode::MacMismatch], "{v:?}");
    assert_eq!(v.outcome(), GateOutcome::TerminalBreach);
}

#[test]
fn an_unbound_envelope_sent_to_an_audienced_receiver_is_refused() {
    let dir = scratch("unbound-to-bound");
    let (clock, rx) = production(&dir.join("rx.log"), "rx-1", meta_ring(&["a"]));
    let unbound = seal(draft(1, clock.now_unix_ms()), &fixture_key("a"), &TridentConfig::default().limits()).unwrap();
    let v = rx.verify(&unbound);
    assert_eq!(v.reasons(), &[ReasonCode::MacMismatch], "{v:?}");
    // Same on the Development side with an audience set.
    let fx = setup_with(TridentConfig {
        audience: "rx-1".into(),
        ..TridentConfig::default()
    });
    let v = fx.trident.verify(&fx.sealed(1));
    assert_eq!(v.reasons(), &[ReasonCode::MacMismatch], "{v:?}");
}

// ---------------------------------------------------------------------------
// Key lifecycle
// ---------------------------------------------------------------------------

#[test]
fn keys_not_yet_valid_expired_retired_and_revoked_are_refused_with_distinct_reasons() {
    let dir = scratch("lifecycle");
    let window = 60_000;
    let mut ring = KeyRing::new(16);
    // a: valid from T0 + window. b: valid until T0 + window. c: retired. d: revoked.
    ring.insert_with_meta(
        fixture_key("a"),
        KeyMeta::new("issuer:test-fixture", KeyPurpose::Handoff, T0 + window, None).unwrap(),
    )
    .unwrap();
    ring.insert_with_meta(
        fixture_key("b"),
        KeyMeta::new("issuer:test-fixture", KeyPurpose::Handoff, 0, Some(T0 + window)).unwrap(),
    )
    .unwrap();
    ring.insert_with_meta(fixture_key("c"), active_meta().with_status(KeyStatus::Retired)).unwrap();
    ring.insert_with_meta(fixture_key("d"), active_meta().with_status(KeyStatus::Revoked)).unwrap();
    let (clock, rx) = production(&dir.join("rx.log"), "rx-1", ring);
    let env = |label: &str, seq: u64| sealed_for_audience(&fixture_key(label), seq, &clock, "rx-1");

    let v = rx.verify(&env("a", 1));
    assert_eq!(v.reasons(), &[ReasonCode::KeyNotYetValid], "{v:?}");
    assert_eq!(v.outcome(), GateOutcome::Retry);
    assert_eq!(v.refusal().unwrap().failed_prongs(), vec![1]);
    assert!(rx.verify(&env("b", 1)).is_accepted());
    let v = rx.verify(&env("c", 1));
    assert_eq!(v.reasons(), &[ReasonCode::KeyRetired], "{v:?}");
    assert_eq!(v.outcome(), GateOutcome::TerminalBreach);
    let v = rx.verify(&env("d", 1));
    assert_eq!(v.reasons(), &[ReasonCode::KeyRevoked], "{v:?}");
    assert_eq!(v.outcome(), GateOutcome::TerminalBreach);
    // A forgery under a revoked key reports both facts.
    let mut forged = env("d", 2);
    forged.mac = "11".repeat(32);
    let v = rx.verify(&forged);
    assert_eq!(v.reasons(), &[ReasonCode::MacMismatch, ReasonCode::KeyRevoked], "{v:?}");
    // No refused key counts toward the breaker or reveals freshness state.
    assert!(rx.quarantined().unwrap().is_empty());

    // Time passes: a becomes valid, b expires.
    clock.advance(window);
    assert!(rx.verify(&env("a", 2)).is_accepted());
    let v = rx.verify(&env("b", 2));
    assert_eq!(v.reasons(), &[ReasonCode::KeyExpired], "{v:?}");
    assert_eq!(v.outcome(), GateOutcome::TerminalBreach);

    // Retiring a key by ring replacement refuses it from the next envelope.
    let mut retired = KeyRing::new(16);
    retired
        .insert_with_meta(
            fixture_key("a"),
            KeyMeta::new("issuer:test-fixture", KeyPurpose::Handoff, T0 + window, None)
                .unwrap()
                .with_status(KeyStatus::Retired),
        )
        .unwrap();
    rx.replace_keyring(retired).unwrap();
    assert_eq!(rx.verify(&env("a", 3)).reasons(), &[ReasonCode::KeyRetired]);
}

#[test]
fn a_rotation_overlap_is_expressed_with_validity_windows() {
    let dir = scratch("rotation");
    let overlap = 10_000;
    let old_ends = T0 + 30_000;
    let mut ring = KeyRing::new(16);
    ring.insert_with_meta(
        fixture_key("old"),
        KeyMeta::new("issuer:test-fixture", KeyPurpose::Handoff, 0, Some(old_ends)).unwrap(),
    )
    .unwrap();
    ring.insert_with_meta(
        fixture_key("new"),
        KeyMeta::new("issuer:test-fixture", KeyPurpose::Handoff, old_ends - overlap, None).unwrap(),
    )
    .unwrap();
    let (clock, rx) = production(&dir.join("rx.log"), "rx-1", ring);
    let env = |label: &str, seq: u64| sealed_for_audience(&fixture_key(label), seq, &clock, "rx-1");
    // Before the overlap: only the old key.
    assert!(rx.verify(&env("old", 1)).is_accepted());
    assert_eq!(rx.verify(&env("new", 1)).reasons(), &[ReasonCode::KeyNotYetValid]);
    // During the overlap: both.
    clock.set(old_ends - overlap / 2);
    assert!(rx.verify(&env("old", 2)).is_accepted());
    assert!(rx.verify(&env("new", 2)).is_accepted());
    // After: only the new key.
    clock.set(old_ends);
    assert_eq!(rx.verify(&env("old", 3)).reasons(), &[ReasonCode::KeyExpired]);
    assert!(rx.verify(&env("new", 3)).is_accepted());
}
