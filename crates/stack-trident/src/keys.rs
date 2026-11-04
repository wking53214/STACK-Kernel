//! Sender keys, their fingerprints, and the caller-supplied key ring.
//!
//! There is no built-in key, no default key and no way to construct a
//! [`KeyRing`] that holds a key the caller did not hand it. A fresh ring is
//! empty, and an empty ring authenticates nothing.
//!
//! ## What a key proves
//!
//! HMAC keys are shared secrets. A MAC that verifies proves that whoever
//! sealed the envelope held the key, nothing more: not which person or
//! service that was (any holder, including every receiver that verifies
//! under the key, can seal), and not that what the envelope asks for is
//! legitimate. [`KeyMeta::issuer_id`] records who handed the key out so
//! that an acceptance can be traced to an issuance decision; it is a
//! label the ring operator asserts, not something the MAC proves.
//!
//! ## Key lifecycle
//!
//! A key carries [`KeyMeta`]: an issuer, a purpose, a validity window and
//! a [`KeyStatus`]. At verification the receiver refuses, under the same
//! lock as the commit, a key that is not yet valid (`KeyNotYetValid`),
//! past `not_after_ms` (`KeyExpired`), [`KeyStatus::Retired`]
//! (`KeyRetired`) or [`KeyStatus::Revoked`] (`KeyRevoked`). A key added
//! with [`KeyRing::insert`] has no metadata (a legacy entry: no issuer,
//! no window, always active) and is refused by the Production profile.
//!
//! ## Rotation
//!
//! Overlap is expressed with validity windows, never by accepting retired
//! keys:
//!
//! 1. Issue the new key with `not_before_ms` at or before the moment the
//!    sender starts using it, and add it to every receiver's ring
//!    (`replace_keyring`) before that moment.
//! 2. Give the old key a `not_after_ms` at the end of the overlap and
//!    swap that ring in. Both keys authenticate during the overlap.
//! 3. When the overlap ends the old key refuses itself (`KeyExpired`).
//!    Mark it [`KeyStatus::Retired`] or remove it at the next ring swap.
//! 4. A key that may have leaked is marked [`KeyStatus::Revoked`] (or
//!    removed) and the ring swapped in at once; `replace_keyring` takes
//!    the state lock, so no verification already under way can commit
//!    under the old ring after the call returns.
//!
//! Retired and revoked both refuse new envelopes. They differ only in
//! what the operator records: retired is a planned end, revoked is a
//! suspected compromise.
//!
//! ## What the reasons reveal
//!
//! `KeyNotYetValid`, `KeyExpired`, `KeyRetired` and `KeyRevoked` tell a
//! caller that the fingerprint names a key in the ring and what state it
//! is in, as `MacMismatch` versus `UnknownSender` already tells whether
//! it is in the ring at all. Fingerprints are public identifiers and the
//! state of a key is something its holder already knows, so this is
//! accepted; no new oracle on the key bytes is added. A deployment that
//! must hide ring membership collapses these reasons at its own
//! boundary.

use std::collections::HashMap;
use std::fmt;

use sha2::{Digest, Sha256};

use crate::canonical::{decode_hex_lower, to_hex};

/// Shortest accepted key, in bytes. HMAC-SHA256 gains nothing from keys
/// longer than its 64-byte block, and a key shorter than the 32-byte output
/// weakens it.
pub const MIN_KEY_BYTES: usize = 32;
/// Longest accepted key, in bytes.
pub const MAX_KEY_BYTES: usize = 128;
/// Domain separator hashed in front of a key to make its fingerprint, so a
/// fingerprint can never be confused with a SHA-256 of the key used
/// elsewhere.
pub const FINGERPRINT_DOMAIN: &[u8] = b"stack-trident/fingerprint/v1\n";
/// Longest accepted [`KeyMeta::issuer_id`], in bytes.
pub const MAX_ISSUER_ID_BYTES: usize = 128;

/// What a key may be used for. Only handoff envelopes exist today; the
/// enum is closed so that a key issued for one purpose can never be
/// accepted for another added later.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum KeyPurpose {
    /// Sealing and verifying [`crate::HandoffEnvelope`]s.
    Handoff,
}

/// Where a key is in its life. Both non-active states refuse new
/// envelopes; see the module docs on rotation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum KeyStatus {
    /// In use, subject to the validity window.
    Active,
    /// Planned end of life. Refused for new envelopes.
    Retired,
    /// Suspected compromise. Refused for new envelopes.
    Revoked,
}

/// Issuance metadata for one key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyMeta {
    /// Who issued the key: a non-empty label of at most
    /// [`MAX_ISSUER_ID_BYTES`] bytes, asserted by the ring operator. Not
    /// proven by the MAC.
    pub issuer_id: String,
    /// What the key is for.
    pub purpose: KeyPurpose,
    /// Earliest receiver clock (Unix ms) at which the key verifies.
    pub not_before_ms: u64,
    /// Receiver clock (Unix ms) at and after which the key no longer
    /// verifies. `None` means no planned end.
    pub not_after_ms: Option<u64>,
    /// Lifecycle state.
    pub status: KeyStatus,
}

impl KeyMeta {
    /// Metadata for an active key. Refuses an empty or over-long issuer
    /// and a window that ends before it starts.
    pub fn new(
        issuer_id: impl Into<String>,
        purpose: KeyPurpose,
        not_before_ms: u64,
        not_after_ms: Option<u64>,
    ) -> Result<Self, KeyError> {
        let issuer_id = issuer_id.into();
        if issuer_id.is_empty() {
            return Err(KeyError::EmptyIssuer);
        }
        if issuer_id.len() > MAX_ISSUER_ID_BYTES {
            return Err(KeyError::IssuerTooLong { len: issuer_id.len() });
        }
        if not_after_ms.is_some_and(|after| after <= not_before_ms) {
            return Err(KeyError::InvalidWindow {
                not_before_ms,
                not_after_ms,
            });
        }
        Ok(Self {
            issuer_id,
            purpose,
            not_before_ms,
            not_after_ms,
            status: KeyStatus::Active,
        })
    }

    /// The same metadata with `status`.
    pub fn with_status(mut self, status: KeyStatus) -> Self {
        self.status = status;
        self
    }

    /// Whether the key may verify an envelope at receiver time `now_ms`.
    pub fn check(&self, now_ms: u64) -> KeyCheck {
        match self.status {
            KeyStatus::Revoked => KeyCheck::Revoked,
            KeyStatus::Retired => KeyCheck::Retired,
            KeyStatus::Active => {
                if now_ms < self.not_before_ms {
                    KeyCheck::NotYetValid
                } else if self.not_after_ms.is_some_and(|after| now_ms >= after) {
                    KeyCheck::Expired
                } else {
                    KeyCheck::Usable
                }
            }
        }
    }
}

/// The result of checking a key that is in the ring against the clock.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum KeyCheck {
    /// May verify envelopes now.
    Usable,
    /// `now < not_before_ms`.
    NotYetValid,
    /// `now >= not_after_ms`.
    Expired,
    /// [`KeyStatus::Retired`].
    Retired,
    /// [`KeyStatus::Revoked`].
    Revoked,
}

/// Why a key or key-ring operation was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum KeyError {
    /// Key shorter than [`MIN_KEY_BYTES`].
    #[error("key is {len} bytes; at least {MIN_KEY_BYTES} are required")]
    TooShort {
        /// Offered length.
        len: usize,
    },
    /// Key longer than [`MAX_KEY_BYTES`].
    #[error("key is {len} bytes; at most {MAX_KEY_BYTES} are accepted")]
    TooLong {
        /// Offered length.
        len: usize,
    },
    /// Every byte is zero, which is what an uninitialised buffer looks like.
    #[error("key is all zero bytes")]
    AllZero,
    /// The ring already holds its maximum number of keys.
    #[error("key ring is full ({max} keys)")]
    RingFull {
        /// The ring's cap.
        max: usize,
    },
    /// A key with this fingerprint is already in the ring.
    #[error("key is already in the ring")]
    Duplicate,
    /// `KeyMeta::issuer_id` is empty.
    #[error("key issuer_id is empty")]
    EmptyIssuer,
    /// `KeyMeta::issuer_id` is over [`MAX_ISSUER_ID_BYTES`].
    #[error("key issuer_id is {len} bytes; at most {MAX_ISSUER_ID_BYTES} are accepted")]
    IssuerTooLong {
        /// Offered length.
        len: usize,
    },
    /// `not_after_ms` is at or before `not_before_ms`.
    #[error("key validity window ends ({not_after_ms:?}) at or before it starts ({not_before_ms})")]
    InvalidWindow {
        /// Offered start.
        not_before_ms: u64,
        /// Offered end.
        not_after_ms: Option<u64>,
    },
}

/// A sender's HMAC key. Its `Debug` output never shows the bytes.
///
/// On drop the bytes are overwritten with zeros. This is best effort: the
/// write is not volatile (the workspace denies `unsafe`), so the compiler is
/// allowed to remove it, and copies made by the allocator are not reached.
pub struct SecretKey(Vec<u8>);

impl SecretKey {
    /// Wraps caller-provided key bytes after checking length and that they
    /// are not all zero.
    pub fn from_bytes(bytes: Vec<u8>) -> Result<Self, KeyError> {
        let len = bytes.len();
        if len < MIN_KEY_BYTES {
            return Err(KeyError::TooShort { len });
        }
        if len > MAX_KEY_BYTES {
            return Err(KeyError::TooLong { len });
        }
        if bytes.iter().all(|b| *b == 0) {
            return Err(KeyError::AllZero);
        }
        Ok(Self(bytes))
    }

    pub(crate) fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// This key's fingerprint.
    pub fn fingerprint(&self) -> Fingerprint {
        Fingerprint::of(self)
    }
}

impl fmt::Debug for SecretKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SecretKey(<redacted>, {} bytes)", self.0.len())
    }
}

impl Drop for SecretKey {
    fn drop(&mut self) {
        for b in self.0.iter_mut() {
            *b = 0;
        }
    }
}

/// A key's public identity: SHA-256 over [`FINGERPRINT_DOMAIN`] followed by
/// the key bytes. Written on the wire as 64 lowercase hex characters, never
/// shortened.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Fingerprint([u8; 32]);

impl Fingerprint {
    /// The fingerprint of `key`.
    pub fn of(key: &SecretKey) -> Self {
        let mut h = Sha256::new();
        h.update(FINGERPRINT_DOMAIN);
        h.update(key.as_bytes());
        Self(h.finalize().into())
    }

    /// Parses exactly 64 lowercase hex characters.
    pub fn from_hex(s: &str) -> Option<Self> {
        decode_hex_lower::<32>(s).map(Self)
    }

    /// Wraps the raw 32 bytes (as read back from a store).
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// The 64-character lowercase hex form.
    pub fn to_hex(&self) -> String {
        to_hex(&self.0)
    }

    /// The raw 32 bytes.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Debug for Fingerprint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Fingerprint({})", self.to_hex())
    }
}

impl fmt::Display for Fingerprint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_hex())
    }
}

/// One ring entry: the key and, unless it is a legacy entry, its metadata.
struct Entry {
    key: SecretKey,
    meta: Option<KeyMeta>,
}

/// The set of sender keys a receiver trusts, looked up by fingerprint.
///
/// Built and filled by the caller. Bounded by `max_keys`.
pub struct KeyRing {
    keys: HashMap<Fingerprint, Entry>,
    max_keys: usize,
}

impl KeyRing {
    /// Default cap on the number of keys.
    pub const DEFAULT_MAX_KEYS: usize = 1024;

    /// An empty ring that will hold at most `max_keys` keys.
    pub fn new(max_keys: usize) -> Self {
        Self {
            keys: HashMap::new(),
            max_keys,
        }
    }

    /// Adds `key` as a legacy entry (no issuer, no validity window, always
    /// active) and returns its fingerprint, which is the value a sender
    /// puts in the envelope's `sender` field. Development only: the
    /// Production profile refuses a ring with any legacy entry. Prefer
    /// [`KeyRing::insert_with_meta`].
    pub fn insert(&mut self, key: SecretKey) -> Result<Fingerprint, KeyError> {
        self.insert_entry(key, None)
    }

    /// Adds `key` with its issuance metadata and returns its fingerprint.
    pub fn insert_with_meta(&mut self, key: SecretKey, meta: KeyMeta) -> Result<Fingerprint, KeyError> {
        self.insert_entry(key, Some(meta))
    }

    fn insert_entry(&mut self, key: SecretKey, meta: Option<KeyMeta>) -> Result<Fingerprint, KeyError> {
        let fp = key.fingerprint();
        if self.keys.contains_key(&fp) {
            return Err(KeyError::Duplicate);
        }
        if self.keys.len() >= self.max_keys {
            return Err(KeyError::RingFull { max: self.max_keys });
        }
        self.keys.insert(fp, Entry { key, meta });
        Ok(fp)
    }

    /// The metadata of the key with this fingerprint. `None` when the key
    /// is absent or is a legacy entry.
    pub fn meta(&self, fp: &Fingerprint) -> Option<&KeyMeta> {
        self.keys.get(fp).and_then(|e| e.meta.as_ref())
    }

    /// Sets the status of the key with this fingerprint. Returns `false`
    /// when the key is absent or a legacy entry (which has no status to
    /// set; remove it instead).
    pub fn set_status(&mut self, fp: &Fingerprint, status: KeyStatus) -> bool {
        match self.keys.get_mut(fp).and_then(|e| e.meta.as_mut()) {
            Some(m) => {
                m.status = status;
                true
            }
            None => false,
        }
    }

    /// Number of legacy entries (keys without metadata).
    pub fn legacy_count(&self) -> usize {
        self.keys.values().filter(|e| e.meta.is_none()).count()
    }

    /// Whether the key with this fingerprint may verify an envelope at
    /// receiver time `now_ms`. `None` when it is not in the ring. A legacy
    /// entry is always [`KeyCheck::Usable`].
    pub fn check(&self, fp: &Fingerprint, now_ms: u64) -> Option<KeyCheck> {
        self.keys
            .get(fp)
            .map(|e| e.meta.as_ref().map_or(KeyCheck::Usable, |m| m.check(now_ms)))
    }

    /// Removes the key with this fingerprint. Returns whether one was there.
    pub fn remove(&mut self, fp: &Fingerprint) -> bool {
        self.keys.remove(fp).is_some()
    }

    /// Whether a key with this fingerprint is in the ring.
    pub fn contains(&self, fp: &Fingerprint) -> bool {
        self.keys.contains_key(fp)
    }

    /// Number of keys held.
    pub fn len(&self) -> usize {
        self.keys.len()
    }

    /// Whether the ring holds no keys.
    pub fn is_empty(&self) -> bool {
        self.keys.is_empty()
    }

    /// The ring's cap.
    pub fn max_keys(&self) -> usize {
        self.max_keys
    }

    pub(crate) fn get(&self, fp: &Fingerprint) -> Option<&SecretKey> {
        self.keys.get(fp).map(|e| &e.key)
    }
}

impl fmt::Debug for KeyRing {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut fps: Vec<&Fingerprint> = self.keys.keys().collect();
        fps.sort();
        f.debug_struct("KeyRing")
            .field("fingerprints", &fps)
            .field("max_keys", &self.max_keys)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // TEST FIXTURE ONLY. Not a key for any deployment.
    fn fixture(tag: u8) -> SecretKey {
        SecretKey::from_bytes(vec![tag; 32]).unwrap()
    }

    #[test]
    fn keys_are_checked() {
        assert_eq!(SecretKey::from_bytes(vec![1; 31]).unwrap_err(), KeyError::TooShort { len: 31 });
        assert_eq!(SecretKey::from_bytes(vec![1; 129]).unwrap_err(), KeyError::TooLong { len: 129 });
        assert_eq!(SecretKey::from_bytes(vec![0; 32]).unwrap_err(), KeyError::AllZero);
    }

    #[test]
    fn debug_never_shows_key_bytes() {
        let k = SecretKey::from_bytes(vec![0xab; 32]).unwrap();
        let s = format!("{k:?}");
        assert!(!s.contains("ab"), "{s}");
        let mut ring = KeyRing::new(4);
        ring.insert(k).unwrap();
        assert!(!format!("{ring:?}").contains("abab"));
    }

    #[test]
    fn ring_is_bounded_and_rejects_duplicates() {
        let mut ring = KeyRing::new(2);
        assert!(ring.is_empty());
        let a = ring.insert(fixture(1)).unwrap();
        assert_eq!(ring.insert(fixture(1)).unwrap_err(), KeyError::Duplicate);
        ring.insert(fixture(2)).unwrap();
        assert_eq!(ring.insert(fixture(3)).unwrap_err(), KeyError::RingFull { max: 2 });
        assert!(ring.contains(&a));
        assert!(ring.remove(&a));
        assert!(!ring.remove(&a));
        assert_eq!(ring.len(), 1);
    }

    #[test]
    fn metadata_is_checked_and_decides_usability() {
        assert_eq!(
            KeyMeta::new("", KeyPurpose::Handoff, 0, None).unwrap_err(),
            KeyError::EmptyIssuer
        );
        assert_eq!(
            KeyMeta::new("i".repeat(MAX_ISSUER_ID_BYTES + 1), KeyPurpose::Handoff, 0, None).unwrap_err(),
            KeyError::IssuerTooLong { len: MAX_ISSUER_ID_BYTES + 1 }
        );
        assert_eq!(
            KeyMeta::new("issuer", KeyPurpose::Handoff, 10, Some(10)).unwrap_err(),
            KeyError::InvalidWindow {
                not_before_ms: 10,
                not_after_ms: Some(10)
            }
        );
        let meta = KeyMeta::new("issuer", KeyPurpose::Handoff, 10, Some(20)).unwrap();
        assert_eq!(meta.check(9), KeyCheck::NotYetValid);
        assert_eq!(meta.check(10), KeyCheck::Usable);
        assert_eq!(meta.check(19), KeyCheck::Usable);
        assert_eq!(meta.check(20), KeyCheck::Expired);
        assert_eq!(meta.clone().with_status(KeyStatus::Retired).check(15), KeyCheck::Retired);
        assert_eq!(meta.clone().with_status(KeyStatus::Revoked).check(15), KeyCheck::Revoked);

        let mut ring = KeyRing::new(4);
        let legacy = ring.insert(fixture(1)).unwrap();
        let managed = ring.insert_with_meta(fixture(2), meta).unwrap();
        assert_eq!(ring.legacy_count(), 1);
        assert_eq!(ring.check(&legacy, 0), Some(KeyCheck::Usable));
        assert_eq!(ring.check(&managed, 0), Some(KeyCheck::NotYetValid));
        assert_eq!(ring.check(&fixture(3).fingerprint(), 0), None);
        assert!(!ring.set_status(&legacy, KeyStatus::Revoked));
        assert!(ring.set_status(&managed, KeyStatus::Revoked));
        assert_eq!(ring.check(&managed, 15), Some(KeyCheck::Revoked));
        assert_eq!(ring.meta(&managed).map(|m| m.issuer_id.as_str()), Some("issuer"));
    }

    #[test]
    fn fingerprint_is_domain_separated_full_length_hex() {
        let k = fixture(7);
        let fp = k.fingerprint();
        let plain: [u8; 32] = Sha256::digest(k.as_bytes()).into();
        assert_ne!(fp.as_bytes(), &plain);
        assert_eq!(fp.to_hex().len(), 64);
        assert_eq!(Fingerprint::from_hex(&fp.to_hex()), Some(fp));
        assert_eq!(Fingerprint::from_hex(&fp.to_hex().to_uppercase()), None);
    }
}
