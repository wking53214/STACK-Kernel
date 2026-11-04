//! Trust: the public keys the kernel accepts capabilities from, with their
//! issuer identity, purpose, validity window and status; the revocation
//! list for capabilities; and strict Ed25519 signature verification.
//!
//! Nothing here can sign. A [`PublicKey`] holds a verifying key only;
//! there is no secret key type in this crate outside its tests.
//!
//! # Trust model
//!
//! A [`TrustAnchor`] says: the operator of this kernel trusts the holder
//! of `public_key` to issue capabilities as `issuer_id`, from
//! `not_before_ms` until `not_after_ms`, unless the anchor is revoked. A
//! [`TrustSet`] holds anchors keyed by [`KeyId`], the full SHA-256
//! fingerprint of the public key under a domain tag; one key id appears at
//! most once, under one issuer, so a capability's `(issuer_id, key_id)`
//! resolves to at most one anchor.
//!
//! * **Rotation**: add a second anchor for the same issuer with a window
//!   that overlaps the first. During the overlap both keys verify; after
//!   the old window ends only the new one does. No swap, no gap.
//! * **Issuer revocation**: [`TrustSet::revoke`] marks an anchor
//!   `Revoked`. It stays in the set so a capability under that key is
//!   refused as `IssuerRevoked`, which is a different fact from an
//!   untrusted key, and so a later re-insert of the same key is refused
//!   as a duplicate rather than silently restoring trust.
//! * **Capability revocation**: a [`RevocationList`] of `cap_id` values
//!   and, for capabilities whose id the issuer may reuse, of capability
//!   digests. Distributing it to every verifier is the operator's job;
//!   this crate only consults the copy it is given.
//!
//! A valid signature under an anchor's key proves that the holder of that
//! key signed exactly those bytes. It proves nothing about any person,
//! and nothing about whether the capability is still within its window,
//! unrevoked or addressed to this verifier; those are separate checks in
//! `authority`.

use std::collections::{HashMap, HashSet};
use std::fmt;

use ed25519_dalek::{Signature, VerifyingKey};
use sha2::{Digest, Sha256};

use crate::capability::{CapabilityDigest, Field, ParseError, SignedCapability, KEY_ID_BYTES, MAX_ID_BYTES, SIGNATURE_BYTES};
use crate::digest::decode_hex_lower;
use crate::scope::is_control;

/// Domain separator hashed in front of a public key to make its id, so a
/// key id can never be confused with a SHA-256 of the key used elsewhere.
pub const KEY_ID_DOMAIN: &[u8] = b"stack-authority/key-id/1\n";

/// Why a trust anchor, trust set or revocation list operation was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum TrustError {
    /// The bytes are not a valid Ed25519 public key, or decode to a point
    /// of small order, which could verify signatures nobody made.
    #[error("public key is invalid or of small order")]
    WeakKey,
    /// The issuer id breaks the identifier rules (1 to 128 bytes, no
    /// control character), so no capability could ever name it.
    #[error("issuer id refused: {0}")]
    BadIssuerId(ParseError),
    /// `not_after_ms` is not after `not_before_ms`.
    #[error("not_after_ms is not after not_before_ms")]
    WindowInverted,
    /// An anchor with this key id is already in the set.
    #[error("an anchor with this key id is already in the set")]
    Duplicate,
    /// The set or list already holds its maximum number of entries.
    #[error("full ({max} entries)")]
    Full {
        /// The cap.
        max: usize,
    },
}

/// A verifying key, validated on construction.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct PublicKey {
    bytes: [u8; 32],
    key: VerifyingKey,
}

impl PublicKey {
    /// Wraps a compressed Edwards point after checking that it decodes and
    /// is not of small order.
    pub fn from_bytes(bytes: [u8; 32]) -> Result<Self, TrustError> {
        let key = VerifyingKey::from_bytes(&bytes).map_err(|_| TrustError::WeakKey)?;
        if key.is_weak() {
            return Err(TrustError::WeakKey);
        }
        Ok(Self { bytes, key })
    }

    /// The compressed point.
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.bytes
    }

    /// This key's id.
    pub fn key_id(&self) -> KeyId {
        KeyId::of(self)
    }

    /// Strict Ed25519 verification of `signature` over `message`: refuses
    /// non-canonical scalars and small-order `R` or `A`, so a signature
    /// has one accepted encoding and a weak key cannot verify a forgery.
    pub fn verify_strict(&self, message: &[u8], signature: &[u8; SIGNATURE_BYTES]) -> Result<(), BadSignature> {
        let sig = Signature::from_bytes(signature);
        self.key.verify_strict(message, &sig).map_err(|_| BadSignature)
    }
}

impl fmt::Debug for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "PublicKey({})", hex::encode(self.bytes))
    }
}

/// The signature did not verify under the key it was checked against.
/// One variant on purpose: the reason (wrong key, altered bytes, altered
/// signature, non-canonical encoding) is not reported.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("signature does not verify")]
pub struct BadSignature;

/// A public key's identity: SHA-256 over [`KEY_ID_DOMAIN`] and the key
/// bytes. Written as 64 lowercase hex characters, never shortened. It is
/// a label for lookup, not a MAC and not a secret.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct KeyId([u8; KEY_ID_BYTES]);

impl KeyId {
    /// The id of `key`.
    pub fn of(key: &PublicKey) -> Self {
        let mut h = Sha256::new();
        h.update(KEY_ID_DOMAIN);
        h.update(key.as_bytes());
        Self(h.finalize().into())
    }

    /// Wraps raw bytes, as read from a capability.
    pub const fn from_bytes(bytes: [u8; KEY_ID_BYTES]) -> Self {
        Self(bytes)
    }

    /// Parses exactly 64 lowercase hex characters.
    pub fn from_hex(s: &str) -> Option<Self> {
        decode_hex_lower::<KEY_ID_BYTES>(s).map(Self)
    }

    /// The 64-character lowercase hex form.
    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }

    /// The raw bytes.
    pub const fn as_bytes(&self) -> &[u8; KEY_ID_BYTES] {
        &self.0
    }
}

impl fmt::Debug for KeyId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "KeyId({})", self.to_hex())
    }
}

impl fmt::Display for KeyId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_hex())
    }
}

/// What an anchor's key is trusted to do. Only one purpose exists today;
/// the field is in the anchor so that a key trusted for something else
/// later can never be mistaken for an issuer key.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Purpose {
    /// Signs capabilities this crate verifies.
    CapabilityIssuer,
}

/// Whether an anchor is still trusted.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AnchorStatus {
    /// Trusted inside its window.
    Active,
    /// No longer trusted, at any time.
    Revoked,
}

/// One trusted issuer key with its identity, purpose, window and status.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrustAnchor {
    issuer_id: String,
    key_id: KeyId,
    public_key: PublicKey,
    purpose: Purpose,
    not_before_ms: u64,
    not_after_ms: u64,
    status: AnchorStatus,
}

impl TrustAnchor {
    /// An active anchor. The key id is derived from the key, never
    /// supplied. The window is `not_before_ms <= now < not_after_ms`.
    pub fn new(
        issuer_id: &str,
        public_key: PublicKey,
        purpose: Purpose,
        not_before_ms: u64,
        not_after_ms: u64,
    ) -> Result<Self, TrustError> {
        if issuer_id.is_empty() || issuer_id.len() > MAX_ID_BYTES {
            return Err(TrustError::BadIssuerId(ParseError::LengthOutOfBounds(Field::IssuerId)));
        }
        if issuer_id.chars().any(is_control) {
            return Err(TrustError::BadIssuerId(ParseError::ControlCharacter(Field::IssuerId)));
        }
        if not_after_ms <= not_before_ms {
            return Err(TrustError::WindowInverted);
        }
        Ok(Self {
            issuer_id: issuer_id.to_owned(),
            key_id: public_key.key_id(),
            public_key,
            purpose,
            not_before_ms,
            not_after_ms,
            status: AnchorStatus::Active,
        })
    }

    /// The issuer this key is trusted to speak for.
    pub fn issuer_id(&self) -> &str {
        &self.issuer_id
    }

    /// The key id.
    pub const fn key_id(&self) -> &KeyId {
        &self.key_id
    }

    /// The key.
    pub const fn public_key(&self) -> &PublicKey {
        &self.public_key
    }

    /// The purpose.
    pub const fn purpose(&self) -> Purpose {
        self.purpose
    }

    /// Start of the window, inclusive.
    pub const fn not_before_ms(&self) -> u64 {
        self.not_before_ms
    }

    /// End of the window, exclusive.
    pub const fn not_after_ms(&self) -> u64 {
        self.not_after_ms
    }

    /// The status.
    pub const fn status(&self) -> AnchorStatus {
        self.status
    }

    /// Verifies a parsed capability's signature under this anchor's key.
    /// The capability's claimed key id must be this anchor's; a mismatch
    /// is reported as a bad signature, because that is what it would be.
    pub fn verify(&self, signed: &SignedCapability) -> Result<(), BadSignature> {
        if signed.key_id() != self.key_id.as_bytes() {
            return Err(BadSignature);
        }
        self.public_key.verify_strict(signed.signed_region(), signed.signature())
    }
}

/// Why `(issuer_id, key_id)` did not resolve to a usable anchor. Every
/// variant is a fact about the verifier's own trust set, which is public
/// configuration, and none depends on the signature.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ResolveError {
    /// No anchor names this issuer.
    #[error("no trust anchor names this issuer")]
    UnknownIssuer,
    /// The issuer is known but no anchor of it has this key id and the
    /// issuer purpose.
    #[error("key is not a trusted issuer key for this issuer")]
    UntrustedKey,
    /// The anchor is revoked.
    #[error("issuer key is revoked")]
    IssuerRevoked,
    /// Now is before the anchor's window.
    #[error("issuer key is not yet valid")]
    IssuerKeyNotYetValid,
    /// Now is at or after the end of the anchor's window.
    #[error("issuer key has expired")]
    IssuerKeyExpired,
}

/// The anchors a verifier trusts, bounded, keyed by key id.
#[derive(Debug, Clone)]
pub struct TrustSet {
    anchors: HashMap<KeyId, TrustAnchor>,
    issuers: HashMap<String, usize>,
    max_anchors: usize,
}

impl TrustSet {
    /// Default cap on the number of anchors.
    pub const DEFAULT_MAX_ANCHORS: usize = 1024;

    /// An empty set that will hold at most `max_anchors` anchors. An
    /// empty set trusts nothing.
    pub fn new(max_anchors: usize) -> Self {
        Self {
            anchors: HashMap::new(),
            issuers: HashMap::new(),
            max_anchors,
        }
    }

    /// Adds an anchor and returns its key id.
    pub fn insert(&mut self, anchor: TrustAnchor) -> Result<KeyId, TrustError> {
        let id = *anchor.key_id();
        if self.anchors.contains_key(&id) {
            return Err(TrustError::Duplicate);
        }
        if self.anchors.len() >= self.max_anchors {
            return Err(TrustError::Full { max: self.max_anchors });
        }
        *self.issuers.entry(anchor.issuer_id.clone()).or_insert(0) += 1;
        self.anchors.insert(id, anchor);
        Ok(id)
    }

    /// Marks the anchor revoked. Returns whether an active anchor was
    /// there to revoke.
    pub fn revoke(&mut self, key_id: &KeyId) -> bool {
        match self.anchors.get_mut(key_id) {
            Some(a) if a.status == AnchorStatus::Active => {
                a.status = AnchorStatus::Revoked;
                true
            }
            _ => false,
        }
    }

    /// Removes an anchor entirely. Prefer [`TrustSet::revoke`], which keeps
    /// the record. Returns whether one was there.
    pub fn remove(&mut self, key_id: &KeyId) -> bool {
        match self.anchors.remove(key_id) {
            Some(a) => {
                let gone = match self.issuers.get_mut(&a.issuer_id) {
                    Some(n) => {
                        *n = n.saturating_sub(1);
                        *n == 0
                    }
                    None => false,
                };
                if gone {
                    self.issuers.remove(&a.issuer_id);
                }
                true
            }
            None => false,
        }
    }

    /// The anchor with this key id, whatever its status.
    pub fn get(&self, key_id: &KeyId) -> Option<&TrustAnchor> {
        self.anchors.get(key_id)
    }

    /// Whether any anchor, of any status, names this issuer.
    pub fn knows_issuer(&self, issuer_id: &str) -> bool {
        self.issuers.contains_key(issuer_id)
    }

    /// Number of anchors held.
    pub fn len(&self) -> usize {
        self.anchors.len()
    }

    /// Whether the set holds no anchors.
    pub fn is_empty(&self) -> bool {
        self.anchors.is_empty()
    }

    /// The cap.
    pub const fn max_anchors(&self) -> usize {
        self.max_anchors
    }

    /// The one anchor for `(issuer_id, key_id)` that is an issuer key,
    /// active and in its window at `now`, or why there is none. Checked
    /// in that order: identity, then status, then window.
    pub fn resolve(&self, issuer_id: &str, key_id: &KeyId, now: u64) -> Result<&TrustAnchor, ResolveError> {
        if !self.knows_issuer(issuer_id) {
            return Err(ResolveError::UnknownIssuer);
        }
        let anchor = self.anchors.get(key_id).ok_or(ResolveError::UntrustedKey)?;
        if anchor.issuer_id != issuer_id || anchor.purpose != Purpose::CapabilityIssuer {
            return Err(ResolveError::UntrustedKey);
        }
        if anchor.status == AnchorStatus::Revoked {
            return Err(ResolveError::IssuerRevoked);
        }
        if now < anchor.not_before_ms {
            return Err(ResolveError::IssuerKeyNotYetValid);
        }
        if now >= anchor.not_after_ms {
            return Err(ResolveError::IssuerKeyExpired);
        }
        Ok(anchor)
    }
}

/// Capabilities the operator has withdrawn, by id and by digest. Bounded.
///
/// When the list is full, a revocation fails with [`TrustError::Full`].
/// The operator must treat that as an incident: a revocation that could
/// not be recorded is a capability still in force.
#[derive(Debug, Clone)]
pub struct RevocationList {
    ids: HashSet<String>,
    digests: HashSet<CapabilityDigest>,
    max_entries: usize,
}

impl RevocationList {
    /// Default cap on the number of entries, ids and digests together.
    pub const DEFAULT_MAX_ENTRIES: usize = 1 << 20;

    /// An empty list that will hold at most `max_entries` entries.
    pub fn new(max_entries: usize) -> Self {
        Self {
            ids: HashSet::new(),
            digests: HashSet::new(),
            max_entries,
        }
    }

    fn room(&self) -> Result<(), TrustError> {
        if self.ids.len().saturating_add(self.digests.len()) >= self.max_entries {
            Err(TrustError::Full {
                max: self.max_entries,
            })
        } else {
            Ok(())
        }
    }

    /// Revokes every capability with this id. Returns whether the entry
    /// is new.
    pub fn revoke_id(&mut self, cap_id: &str) -> Result<bool, TrustError> {
        if self.ids.contains(cap_id) {
            return Ok(false);
        }
        self.room()?;
        Ok(self.ids.insert(cap_id.to_owned()))
    }

    /// Revokes the one capability with this digest. Returns whether the
    /// entry is new.
    pub fn revoke_digest(&mut self, digest: CapabilityDigest) -> Result<bool, TrustError> {
        if self.digests.contains(&digest) {
            return Ok(false);
        }
        self.room()?;
        Ok(self.digests.insert(digest))
    }

    /// Whether a capability with this id and digest is revoked.
    pub fn is_revoked(&self, cap_id: &str, digest: &CapabilityDigest) -> bool {
        self.ids.contains(cap_id) || self.digests.contains(digest)
    }

    /// Number of entries held.
    pub fn len(&self) -> usize {
        self.ids.len().saturating_add(self.digests.len())
    }

    /// Whether the list holds no entries.
    pub fn is_empty(&self) -> bool {
        self.ids.is_empty() && self.digests.is_empty()
    }
}
