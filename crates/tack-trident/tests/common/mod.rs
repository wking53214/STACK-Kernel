//! Shared test fixtures. Every key here is a TEST FIXTURE, derived from a
//! public label, and must never be used outside tests.

#![allow(dead_code)]
// Test-only fixture helpers: a failed unwrap here is a failed test.
#![allow(clippy::unwrap_used)]

use std::sync::Arc;

use hmac::{Hmac, Mac};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use tack_trident::canonical::{to_canonical_bytes, to_hex};
use tack_trident::{
    seal, EnvelopeDraft, Fingerprint, GateOutcome, GatePosition, HandoffEnvelope, KeyRing, ManualClock,
    Nonce, SecretKey, Trident, TridentConfig, MAC_DOMAIN,
};

/// Start of test time (a fixed Unix ms value).
pub const T0: u64 = 1_800_000_000_000;

/// TEST FIXTURE KEY: SHA-256 of a public label. Not a secret.
pub fn fixture_key(label: &str) -> SecretKey {
    let bytes = Sha256::digest(format!("tack-trident TEST FIXTURE key: {label}").as_bytes()).to_vec();
    SecretKey::from_bytes(bytes).unwrap()
}

pub struct Fx {
    pub clock: Arc<ManualClock>,
    pub trident: Trident,
    pub cfg: TridentConfig,
    /// Sender A, in the ring.
    pub key_a: SecretKey,
    pub fp_a: Fingerprint,
    /// Sender B, in the ring.
    pub key_b: SecretKey,
    pub fp_b: Fingerprint,
    /// Not in the ring.
    pub key_x: SecretKey,
}

pub fn setup() -> Fx {
    setup_with(TridentConfig::default())
}

pub fn setup_with(cfg: TridentConfig) -> Fx {
    let clock = Arc::new(ManualClock::new(T0));
    let mut ring = KeyRing::new(16);
    let fp_a = ring.insert(fixture_key("a")).unwrap();
    let fp_b = ring.insert(fixture_key("b")).unwrap();
    let trident = Trident::new(cfg.clone(), ring, clock.clone()).unwrap();
    // Step past the start-up epoch floor.
    clock.advance(cfg.max_future_skew_ms + 1);
    Fx {
        clock,
        trident,
        cfg,
        key_a: fixture_key("a"),
        fp_a,
        key_b: fixture_key("b"),
        fp_b,
        key_x: fixture_key("x"),
    }
}

pub fn nonce_for(seq: u64) -> Nonce {
    let mut b = [0u8; 16];
    b[..8].copy_from_slice(&seq.to_be_bytes());
    b[8] = 0xa5;
    Nonce::from_bytes(b)
}

pub fn payload_for(seq: u64) -> Value {
    json!({"task": "handoff", "seq": seq, "items": [1, 2, {"deep": ["x", null, true]}], "note": "é\n"})
}

impl Fx {
    pub fn now(&self) -> u64 {
        use tack_trident::Clock;
        self.clock.now_unix_ms()
    }

    pub fn sealed_by(&self, key: &SecretKey, seq: u64) -> HandoffEnvelope {
        seal(
            EnvelopeDraft {
                sequence: seq,
                issued_at_unix_ms: self.now(),
                nonce: nonce_for(seq),
                gate_position: GatePosition::Alpha,
                gate_outcome: GateOutcome::Pass,
                payload: payload_for(seq),
            },
            key,
            &self.cfg.limits(),
        )
        .unwrap()
    }

    pub fn sealed(&self, seq: u64) -> HandoffEnvelope {
        self.sealed_by(&self.key_a, seq)
    }

    pub fn wire(&self, env: &HandoffEnvelope) -> Vec<u8> {
        env.to_wire_bytes(&self.cfg.limits()).unwrap()
    }
}

/// The envelope as a generic JSON object (all ten fields).
pub fn to_value(env: &HandoffEnvelope) -> Value {
    json!({
        "version": env.version, "sender": env.sender, "sequence": env.sequence,
        "issued_at_unix_ms": env.issued_at_unix_ms, "nonce": env.nonce,
        "gate_position": env.gate_position, "gate_outcome": env.gate_outcome,
        "subject_digest": env.subject_digest, "payload": env.payload, "mac": env.mac,
    })
}

/// Recomputes the MAC independently of the crate's own writer: generic
/// canonical encoding of the object without `mac`, behind the domain
/// separator. Used to build envelopes a key holder signed on purpose.
pub fn remac(env: &mut HandoffEnvelope, key_bytes_label: &str) {
    let key = Sha256::digest(format!("tack-trident TEST FIXTURE key: {key_bytes_label}").as_bytes());
    let mut v = to_value(env);
    v.as_object_mut().unwrap().remove("mac");
    let lim = TridentConfig::default().limits();
    let mut input = MAC_DOMAIN.to_vec();
    input.extend(to_canonical_bytes(&v, &lim).unwrap());
    let mut m = <Hmac<Sha256> as Mac>::new_from_slice(&key).unwrap();
    m.update(&input);
    env.mac = to_hex(&m.finalize().into_bytes());
}
