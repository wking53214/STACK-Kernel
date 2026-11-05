//! The use store: what the verifier remembers about capabilities it has
//! accepted, so that a one-time capability authorizes once and a
//! capability id names one capability.
//!
//! [`Authority::authorize`](crate::Authority::authorize) consults the
//! store last, after every other check has passed, so a request that
//! fails for any other reason never burns a one-time capability. The
//! store's `record_use` is one atomic check-and-record: two concurrent
//! presentations of one one-time capability get exactly one `Ok`.
//!
//! A store that cannot answer (lock poisoned, disk error, full) reports
//! [`UseError::Unavailable`], and the verifier denies. Nothing is ever
//! allowed because the store could not be asked.
//!
//! [`MemoryUseStore`] forgets everything on restart and says so through
//! [`UseStore::is_durable`]; the verifier refuses it unless its
//! configuration allows a non-durable store. The durable, hash-chained
//! store is [`crate::FileUseStore`].

use std::collections::HashMap;
use std::fmt;
use std::sync::Mutex;

use crate::capability::CapabilityDigest;
use crate::digest::Digest32;

/// What a use is recorded under: the capability's id and its digest.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UseKey<'a> {
    /// The issuer-chosen id.
    pub cap_id: &'a str,
    /// The digest of the exact signed bytes.
    pub digest: &'a CapabilityDigest,
}

/// Why a use could not be recorded.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum UseError {
    /// A one-time capability with this digest has already been used.
    #[error("one-time capability already used")]
    AlreadyUsed,
    /// A capability with this id but a different digest has been seen.
    #[error("capability id already names a different capability")]
    IdConflict,
    /// The store cannot answer. The verifier must deny.
    #[error("use store unavailable")]
    Unavailable,
}

/// What the use store returned when it recorded a use: the evidence an
/// auditor can hold the store to later. Carried in the receipt's
/// `Authorized` record. It is evidence of what the store REPORTED, not proof
/// that the store is honest; a durable store's head can be anchored elsewhere
/// by an operator, a non-durable one proves nothing across a restart.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UseEvidence {
    /// The store returned none (a store written before this API, or a test
    /// double). Nothing can be said about where the use was recorded.
    NotProvided,
    /// [`MemoryUseStore`]: the use was recorded in memory only. A clearly
    /// labeled non-durable marker, never a durable position.
    NonDurableMemory,
    /// A durable store appended a new use record.
    Durable {
        /// Hash of the new use record (chained to its predecessor).
        record_hash: Digest32,
        /// Position of the record in the store, counting from 1.
        position: u64,
        /// The store head after the append (equal to `record_hash` for a
        /// hash-chained log).
        head: Digest32,
    },
    /// A durable store already held this reusable capability, so it wrote
    /// nothing; this is its head and record count at that moment.
    NoNewRecord {
        /// Number of records in the store.
        position: u64,
        /// The store head.
        head: Digest32,
    },
}

/// Atomic check-and-record of capability uses.
pub trait UseStore: Send + Sync + fmt::Debug {
    /// Records a use of the capability `key` at `now_ms`. The entry may be
    /// forgotten once `now_ms` reaches `expires_at_ms`, because the
    /// capability can no longer pass the verifier's expiry check.
    ///
    /// Must be atomic: if `one_time` and the digest is already recorded,
    /// `AlreadyUsed`; if the id is recorded under another digest,
    /// `IdConflict`; otherwise the use is recorded (for a reusable
    /// capability, recorded once and accepted thereafter) and the call
    /// returns `Ok`. A recorded use must be visible to every later call,
    /// on every thread, and, for a durable store, after a restart.
    fn record_use(&self, key: &UseKey<'_>, one_time: bool, expires_at_ms: u64, now_ms: u64)
        -> Result<(), UseError>;

    /// [`Self::record_use`], returning the evidence of where the use was
    /// recorded. The default calls `record_use` and reports
    /// [`UseEvidence::NotProvided`], so a store written before this method
    /// keeps working unchanged and is never credited with a position it did
    /// not give.
    fn record_use_evidenced(
        &self,
        key: &UseKey<'_>,
        one_time: bool,
        expires_at_ms: u64,
        now_ms: u64,
    ) -> Result<UseEvidence, UseError> {
        self.record_use(key, one_time, expires_at_ms, now_ms)?;
        Ok(UseEvidence::NotProvided)
    }

    /// Whether recorded uses survive a restart of the process.
    fn is_durable(&self) -> bool;
}

/// Shared check-and-record logic over an id-keyed map, used by every
/// store in this crate.
pub(crate) fn check_and_record(
    map: &mut HashMap<String, (CapabilityDigest, u64)>,
    capacity: usize,
    key: &UseKey<'_>,
    one_time: bool,
    expires_at_ms: u64,
    now_ms: u64,
) -> Result<bool, UseError> {
    map.retain(|_, (_, exp)| *exp > now_ms);
    if let Some((digest, _)) = map.get(key.cap_id) {
        if digest != key.digest {
            return Err(UseError::IdConflict);
        }
        if one_time {
            return Err(UseError::AlreadyUsed);
        }
        return Ok(false);
    }
    if map.len() >= capacity {
        return Err(UseError::Unavailable);
    }
    map.insert(key.cap_id.to_owned(), (*key.digest, expires_at_ms));
    Ok(true)
}

/// An in-memory store. NOT DURABLE: a restart forgets every use, so a
/// one-time capability could be presented again. Fit for tests, single
/// process simulations, and nothing that must hold across a restart.
#[derive(Debug)]
pub struct MemoryUseStore {
    inner: Mutex<HashMap<String, (CapabilityDigest, u64)>>,
    capacity: usize,
}

impl MemoryUseStore {
    /// Default cap on entries held.
    pub const DEFAULT_CAPACITY: usize = 1 << 16;

    /// An empty store holding at most `capacity` entries. When full after
    /// expiry pruning, it reports `Unavailable` rather than forgetting.
    pub fn new(capacity: usize) -> Self {
        Self {
            inner: Mutex::new(HashMap::new()),
            capacity,
        }
    }

    /// Number of entries held, or `None` if the lock is poisoned.
    pub fn len(&self) -> Option<usize> {
        self.inner.lock().ok().map(|m| m.len())
    }

    /// Whether the store holds no entries, or `None` if the lock is
    /// poisoned.
    pub fn is_empty(&self) -> Option<bool> {
        self.len().map(|n| n == 0)
    }
}

impl UseStore for MemoryUseStore {
    fn record_use(
        &self,
        key: &UseKey<'_>,
        one_time: bool,
        expires_at_ms: u64,
        now_ms: u64,
    ) -> Result<(), UseError> {
        let mut map = self.inner.lock().map_err(|_| UseError::Unavailable)?;
        check_and_record(&mut map, self.capacity, key, one_time, expires_at_ms, now_ms).map(|_| ())
    }

    fn record_use_evidenced(
        &self,
        key: &UseKey<'_>,
        one_time: bool,
        expires_at_ms: u64,
        now_ms: u64,
    ) -> Result<UseEvidence, UseError> {
        self.record_use(key, one_time, expires_at_ms, now_ms)?;
        Ok(UseEvidence::NonDurableMemory)
    }

    fn is_durable(&self) -> bool {
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn d(b: u8) -> CapabilityDigest {
        CapabilityDigest::of_wire(&[b])
    }

    #[test]
    fn memory_store_is_atomic_bounded_and_prunes_expired() {
        let s = MemoryUseStore::new(2);
        assert!(!s.is_durable());
        let (a, b, c) = (d(1), d(2), d(3));
        let ka = UseKey { cap_id: "a", digest: &a };
        assert_eq!(s.record_use(&ka, true, 100, 0), Ok(()));
        assert_eq!(s.record_use(&ka, true, 100, 0), Err(UseError::AlreadyUsed));
        let ka2 = UseKey { cap_id: "a", digest: &b };
        assert_eq!(s.record_use(&ka2, false, 100, 0), Err(UseError::IdConflict));
        let kb = UseKey { cap_id: "b", digest: &b };
        assert_eq!(s.record_use(&kb, false, 100, 0), Ok(()));
        assert_eq!(s.record_use(&kb, false, 100, 0), Ok(()), "reusable: accepted again");
        let kc = UseKey { cap_id: "c", digest: &c };
        assert_eq!(s.record_use(&kc, true, 100, 0), Err(UseError::Unavailable), "full");
        assert_eq!(s.len(), Some(2));
        // At expiry the entries are forgotten and there is room again.
        assert_eq!(s.record_use(&kc, true, 200, 100), Ok(()));
        assert_eq!(s.len(), Some(1));
        assert_eq!(s.is_empty(), Some(false));
    }
}
