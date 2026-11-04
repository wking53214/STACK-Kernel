//! Shared test fixtures. Every key here is a TEST FIXTURE, derived from a
//! public label, and must never be used outside tests. This module holds
//! the only signing path in the crate: issuing lives outside the kernel,
//! and tests stand in for the issuer.

#![allow(dead_code)]
// Test-only fixture helpers: a failed unwrap here is a failed test.
#![allow(clippy::unwrap_used)]

use ed25519_dalek::{Signer, SigningKey};
use sha2::{Digest, Sha256};
use stack_authority::{
    ActionRequest, Authority, AuthorityConfig, Capability, Digest32, KeyId, MemoryUseStore, PublicKey, Purpose,
    ResourceScope, RevocationList, ScopeKind, TrustAnchor, TrustSet, KEY_ID_BYTES, NONCE_BYTES,
};

/// Start of test time (a fixed Unix ms value).
pub const T0: u64 = 1_800_000_000_000;
/// One hour in milliseconds.
pub const HOUR: u64 = 3_600_000;
/// One day in milliseconds.
pub const DAY: u64 = 24 * HOUR;

/// TEST FIXTURE SIGNING KEY: seed is SHA-256 of a public label. Not a
/// secret, not an issuer anyone deploys.
pub fn fixture_signing_key(label: &str) -> SigningKey {
    let seed: [u8; 32] = Sha256::digest(format!("stack-authority TEST FIXTURE issuer: {label}").as_bytes()).into();
    SigningKey::from_bytes(&seed)
}

/// The public half of the fixture key for `label`.
pub fn fixture_public_key(label: &str) -> PublicKey {
    PublicKey::from_bytes(fixture_signing_key(label).verifying_key().to_bytes()).unwrap()
}

/// The key id of the fixture key for `label`.
pub fn fixture_key_id(label: &str) -> KeyId {
    fixture_public_key(label).key_id()
}

/// An active issuer anchor for the fixture key `key_label`, speaking for
/// `issuer_id`, valid from `T0 - DAY` to `T0 + DAY`.
pub fn fixture_anchor(issuer_id: &str, key_label: &str) -> TrustAnchor {
    fixture_anchor_window(issuer_id, key_label, T0 - DAY, T0 + DAY)
}

/// An active issuer anchor with an explicit window.
pub fn fixture_anchor_window(issuer_id: &str, key_label: &str, not_before: u64, not_after: u64) -> TrustAnchor {
    TrustAnchor::new(
        issuer_id,
        fixture_public_key(key_label),
        Purpose::CapabilityIssuer,
        not_before,
        not_after,
    )
    .unwrap()
}

/// A trust set holding one anchor: `issuer-1` under key `issuer-1`.
pub fn baseline_trust_set() -> TrustSet {
    let mut ts = TrustSet::new(16);
    ts.insert(fixture_anchor("issuer-1", "issuer-1")).unwrap();
    ts
}

/// Encodes and signs `cap` with the fixture key for `key_label`, under
/// that key's real key id. The honest issuing path.
pub fn issue(cap: &Capability, key_label: &str) -> Vec<u8> {
    issue_with_key_id(cap, fixture_key_id(key_label).as_bytes(), &fixture_signing_key(key_label))
}

/// The baseline capability signed by `issuer-1`.
pub fn baseline_wire() -> Vec<u8> {
    issue(&baseline_capability(), "issuer-1")
}

/// A request that the baseline capability grants: `read` on `/data/a`
/// about the fixture subject under the fixture decision.
pub fn baseline_request() -> ActionRequest {
    ActionRequest {
        subject_digest: fixture_digest("subject"),
        decision_root: fixture_digest("decision"),
        operation: "read".into(),
        resource: "/data/a".into(),
    }
}

/// Production configuration for the `kernel-a` verifier.
pub fn production_config() -> AuthorityConfig {
    AuthorityConfig::new("kernel-a")
}

/// The `kernel-a` configuration with the durable-store requirement
/// switched off, for tests that use [`MemoryUseStore`].
pub fn memory_store_config() -> AuthorityConfig {
    AuthorityConfig {
        require_durable_use_store: false,
        ..production_config()
    }
}

/// A verifier for `kernel-a` trusting `issuer-1`, with no revocations.
pub fn authority_with(config: AuthorityConfig) -> Authority {
    Authority::new(config, baseline_trust_set(), RevocationList::new(1024)).unwrap()
}

/// [`authority_with`] under [`memory_store_config`].
pub fn memory_authority() -> Authority {
    authority_with(memory_store_config())
}

/// A fresh in-memory use store.
pub fn memory_store() -> MemoryUseStore {
    MemoryUseStore::new(1024)
}

/// A deterministic 32-byte value from a label, for digests and ids.
pub fn fixture_bytes32(label: &str) -> [u8; 32] {
    Sha256::digest(format!("stack-authority TEST FIXTURE bytes: {label}").as_bytes()).into()
}

/// A deterministic digest from a label.
pub fn fixture_digest(label: &str) -> Digest32 {
    Digest32::from_bytes(fixture_bytes32(label))
}

/// A deterministic nonce from a label.
pub fn fixture_nonce(label: &str) -> [u8; NONCE_BYTES] {
    let mut n = [0u8; NONCE_BYTES];
    n.copy_from_slice(&fixture_bytes32(label)[..NONCE_BYTES]);
    n
}

/// A well-formed capability with every field set to a fixture value,
/// valid from `T0` for one hour, for the `kernel-a` audience, issued by
/// `issuer-1`, covering `read` and `write` on exact `/data/a` and prefix
/// `/data/tree`.
pub fn baseline_capability() -> Capability {
    let mut cap = Capability {
        cap_id: "cap-0001".into(),
        issuer_id: "issuer-1".into(),
        audience: "kernel-a".into(),
        subject_digest: fixture_digest("subject"),
        decision_root: fixture_digest("decision"),
        operations: vec!["write".into(), "read".into()],
        resources: vec![
            ResourceScope::prefix("/data/tree").unwrap(),
            ResourceScope::exact("/data/a").unwrap(),
        ],
        not_before_ms: T0,
        expires_at_ms: T0 + 3_600_000,
        one_time: false,
        policy_ref: "policy/baseline".into(),
        nonce: fixture_nonce("nonce-1"),
    };
    cap.normalise();
    cap
}

/// Signs `signed_region` with `key` and returns the full wire form.
pub fn sign_region(signed_region: &[u8], key: &SigningKey) -> Vec<u8> {
    let sig = key.sign(signed_region);
    let mut wire = signed_region.to_vec();
    wire.extend_from_slice(&sig.to_bytes());
    wire
}

/// Encodes `cap` through the crate's validating encoder, under `key_id`,
/// and signs it with `key`.
pub fn issue_with_key_id(cap: &Capability, key_id: &[u8; KEY_ID_BYTES], key: &SigningKey) -> Vec<u8> {
    let region = cap.encode_signed_region(key_id).unwrap();
    sign_region(&region, key)
}

/// An independent, non-validating writer of the signed region, so tests
/// can put onto the wire what the crate's encoder refuses (unsorted sets,
/// bad booleans, oversize fields). `one_time` is written as the raw byte
/// given. Kept byte-for-byte in step with the format documented in
/// `capability.rs`; a test asserts it agrees with the crate's encoder on
/// valid input.
pub struct RawFields {
    pub cap_id: Vec<u8>,
    pub issuer_id: Vec<u8>,
    pub audience: Vec<u8>,
    pub subject_digest: [u8; 32],
    pub decision_root: [u8; 32],
    pub operations: Vec<Vec<u8>>,
    pub resources: Vec<(u8, Vec<u8>)>,
    pub not_before_ms: u64,
    pub expires_at_ms: u64,
    pub one_time: u8,
    pub policy_ref: Vec<u8>,
    pub nonce: [u8; NONCE_BYTES],
    pub key_id: [u8; KEY_ID_BYTES],
}

impl RawFields {
    pub fn from_capability(cap: &Capability, key_id: &[u8; KEY_ID_BYTES]) -> Self {
        Self {
            cap_id: cap.cap_id.as_bytes().to_vec(),
            issuer_id: cap.issuer_id.as_bytes().to_vec(),
            audience: cap.audience.as_bytes().to_vec(),
            subject_digest: *cap.subject_digest.as_bytes(),
            decision_root: *cap.decision_root.as_bytes(),
            operations: cap.operations.iter().map(|o| o.as_bytes().to_vec()).collect(),
            resources: cap
                .resources
                .iter()
                .map(|r| (r.kind().to_wire(), r.path().as_bytes().to_vec()))
                .collect(),
            not_before_ms: cap.not_before_ms,
            expires_at_ms: cap.expires_at_ms,
            one_time: u8::from(cap.one_time),
            policy_ref: cap.policy_ref.as_bytes().to_vec(),
            nonce: cap.nonce,
            key_id: *key_id,
        }
    }

    pub fn encode(&self) -> Vec<u8> {
        fn put(out: &mut Vec<u8>, s: &[u8]) {
            out.extend_from_slice(&u16::try_from(s.len()).unwrap().to_be_bytes());
            out.extend_from_slice(s);
        }
        let mut out = b"stack-capability/1\n".to_vec();
        put(&mut out, &self.cap_id);
        put(&mut out, &self.issuer_id);
        put(&mut out, &self.audience);
        out.extend_from_slice(&self.subject_digest);
        out.extend_from_slice(&self.decision_root);
        out.extend_from_slice(&u16::try_from(self.operations.len()).unwrap().to_be_bytes());
        for op in &self.operations {
            put(&mut out, op);
        }
        out.extend_from_slice(&u16::try_from(self.resources.len()).unwrap().to_be_bytes());
        for (kind, path) in &self.resources {
            out.push(*kind);
            put(&mut out, path);
        }
        out.extend_from_slice(&self.not_before_ms.to_be_bytes());
        out.extend_from_slice(&self.expires_at_ms.to_be_bytes());
        out.push(self.one_time);
        put(&mut out, &self.policy_ref);
        out.extend_from_slice(&self.nonce);
        out.extend_from_slice(&self.key_id);
        out
    }
}

/// Scope kinds by wire byte, for raw writers.
pub const EXACT: u8 = ScopeKind::Exact.to_wire();
pub const PREFIX: u8 = ScopeKind::Prefix.to_wire();
