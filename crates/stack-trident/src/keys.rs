//! Sender keys, their fingerprints, and the caller-supplied key ring.
//!
//! There is no built-in key, no default key and no way to construct a
//! [`KeyRing`] that holds a key the caller did not hand it. A fresh ring is
//! empty, and an empty ring authenticates nothing.

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

/// The set of sender keys a receiver trusts, looked up by fingerprint.
///
/// Built and filled by the caller. Bounded by `max_keys`.
pub struct KeyRing {
    keys: HashMap<Fingerprint, SecretKey>,
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

    /// Adds `key` and returns its fingerprint, which is the value a sender
    /// puts in the envelope's `sender` field.
    pub fn insert(&mut self, key: SecretKey) -> Result<Fingerprint, KeyError> {
        let fp = key.fingerprint();
        if self.keys.contains_key(&fp) {
            return Err(KeyError::Duplicate);
        }
        if self.keys.len() >= self.max_keys {
            return Err(KeyError::RingFull { max: self.max_keys });
        }
        self.keys.insert(fp, key);
        Ok(fp)
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
        self.keys.get(fp)
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
