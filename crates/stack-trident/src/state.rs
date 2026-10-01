//! Receiver-side state: the replay cache and the per-sender table (last
//! sequence, breaker history, quarantine). Both are bounded.

use std::collections::{HashMap, HashSet, VecDeque};

use crate::envelope::Nonce;
use crate::keys::{Fingerprint, KeyRing};

/// One sender's remembered nonces, in acceptance order.
#[derive(Debug, Default)]
struct SenderNonces {
    seen: HashSet<Nonce>,
    order: VecDeque<(Nonce, u64)>,
}

impl SenderNonces {
    /// Drops entries whose retention ended at or before `now`. Returns how
    /// many were dropped.
    fn expire(&mut self, now: u64) -> usize {
        let mut dropped = 0;
        while let Some((nonce, expires_at)) = self.order.front() {
            if *expires_at > now {
                break;
            }
            self.seen.remove(nonce);
            self.order.pop_front();
            dropped += 1;
        }
        dropped
    }

    fn pop_oldest(&mut self) -> bool {
        match self.order.pop_front() {
            Some((nonce, _)) => {
                self.seen.remove(&nonce);
                true
            }
            None => false,
        }
    }
}

/// Remembers accepted (sender, nonce) pairs until they could no longer pass
/// the skew check on their own. Bounded by `capacity` entries in total.
///
/// Each sender's entries are expired in acceptance order: a sender's
/// entries are expired whenever that sender is looked up, and every
/// sender's are swept when the cache is full. If the wall clock steps
/// backwards, expiry is delayed, never brought forward, so the cache errs
/// toward remembering too long. [`ReplayCache::len`] counts entries not yet
/// swept, which is what they cost in memory.
///
/// When full, the caller may evict the oldest entry of the sender holding
/// the most ([`ReplayCache::evict_from_largest`]). That is safe only
/// because the evicted envelope's sequence is at or below its sender's
/// retained high-water mark; see `TridentConfig::replay_cache_capacity`.
#[derive(Debug)]
pub(crate) struct ReplayCache {
    senders: HashMap<Fingerprint, SenderNonces>,
    len: usize,
    capacity: usize,
}

impl ReplayCache {
    pub(crate) fn new(capacity: usize) -> Self {
        Self {
            senders: HashMap::new(),
            len: 0,
            capacity,
        }
    }

    /// Expires `fp`'s entries whose retention ended at or before `now`.
    pub(crate) fn expire_sender(&mut self, fp: &Fingerprint, now: u64) {
        let emptied = match self.senders.get_mut(fp) {
            Some(n) => {
                let dropped = n.expire(now);
                self.len = self.len.saturating_sub(dropped);
                n.order.is_empty()
            }
            None => false,
        };
        if emptied {
            self.senders.remove(fp);
        }
    }

    /// Expires every sender's entries whose retention ended at or before
    /// `now`. Cost: one front check per sender with entries, plus one step
    /// per dropped entry.
    pub(crate) fn sweep(&mut self, now: u64) {
        let mut dropped = 0usize;
        self.senders.retain(|_, n| {
            dropped = dropped.saturating_add(n.expire(now));
            !n.order.is_empty()
        });
        self.len = self.len.saturating_sub(dropped);
    }

    pub(crate) fn contains(&self, fp: &Fingerprint, nonce: &Nonce) -> bool {
        self.senders.get(fp).is_some_and(|n| n.seen.contains(nonce))
    }

    /// Entries held for `fp`.
    pub(crate) fn count(&self, fp: &Fingerprint) -> usize {
        self.senders.get(fp).map_or(0, |n| n.seen.len())
    }

    pub(crate) fn is_full(&self) -> bool {
        self.len >= self.capacity
    }

    /// Drops the oldest entry of the sender holding the most entries.
    /// Returns whether an entry was dropped.
    pub(crate) fn evict_from_largest(&mut self) -> bool {
        let victim = self
            .senders
            .iter()
            .max_by_key(|(_, n)| n.seen.len())
            .map(|(fp, _)| *fp);
        let Some(fp) = victim else {
            return false;
        };
        let (popped, emptied) = match self.senders.get_mut(&fp) {
            Some(n) => (n.pop_oldest(), n.order.is_empty()),
            None => (false, false),
        };
        if popped {
            self.len = self.len.saturating_sub(1);
        }
        if emptied {
            self.senders.remove(&fp);
        }
        popped
    }

    /// Records a pair. The caller has checked `is_full` and `contains`.
    pub(crate) fn insert(&mut self, fp: Fingerprint, nonce: Nonce, expires_at: u64) {
        let n = self.senders.entry(fp).or_default();
        if n.seen.insert(nonce) {
            n.order.push_back((nonce, expires_at));
            self.len = self.len.saturating_add(1);
        }
    }

    pub(crate) fn len(&self) -> usize {
        self.len
    }

    pub(crate) fn clear(&mut self) {
        self.senders.clear();
        self.len = 0;
    }
}

/// Everything the receiver remembers about one sender.
#[derive(Debug, Default)]
pub(crate) struct SenderState {
    pub(crate) last_sequence: Option<u64>,
    /// Receiver clock at the last acceptance from this sender.
    pub(crate) last_accepted_at: Option<u64>,
    /// Times of counted terminal breaches inside the breaker window. Never
    /// longer than the breaker threshold.
    pub(crate) breaches: VecDeque<u64>,
    pub(crate) quarantined_since: Option<u64>,
}

impl SenderState {
    /// Records one counted breach at `now` and reports whether the sender
    /// has now reached `threshold` breaches inside `window_ms`.
    pub(crate) fn record_breach(&mut self, now: u64, window_ms: u64, threshold: u32) -> bool {
        let cutoff = now.saturating_sub(window_ms);
        while self.breaches.front().is_some_and(|t| *t < cutoff) {
            self.breaches.pop_front();
        }
        self.breaches.push_back(now);
        let cap = usize::try_from(threshold).unwrap_or(usize::MAX);
        while self.breaches.len() > cap {
            self.breaches.pop_front();
        }
        self.breaches.len() >= cap
    }

    /// Whether forgetting this entry at `now` loses nothing that matters:
    /// not quarantined, no acceptance within `retention_ms` (so every
    /// envelope it had accepted is stale and its sequence no longer guards
    /// a replay) and no counted breach within `window_ms`.
    pub(crate) fn is_idle(&self, now: u64, retention_ms: u64, window_ms: u64) -> bool {
        self.quarantined_since.is_none()
            && self
                .last_accepted_at
                .map_or(true, |t| now >= t.saturating_add(retention_ms))
            && self
                .breaches
                .back()
                .map_or(true, |t| *t < now.saturating_sub(window_ms))
    }
}

/// Per-sender state, bounded. Only senders that were in the key ring when
/// they were accepted or counted by the breaker are ever added, so an
/// attacker cannot grow it by inventing fingerprints. Entries for senders
/// later removed from the ring stay (as tombstones) until idle, so a ring
/// reload that drops and restores a sender cannot reset its sequence.
#[derive(Debug)]
pub(crate) struct SenderTable {
    map: HashMap<Fingerprint, SenderState>,
    capacity: usize,
    retention_ms: u64,
    window_ms: u64,
}

impl SenderTable {
    pub(crate) fn new(capacity: usize, retention_ms: u64, window_ms: u64) -> Self {
        Self {
            map: HashMap::new(),
            capacity,
            retention_ms,
            window_ms,
        }
    }

    pub(crate) fn get(&self, fp: &Fingerprint) -> Option<&SenderState> {
        self.map.get(fp)
    }

    /// Whether `fp` has, or could be given without eviction, an entry.
    pub(crate) fn can_track(&self, fp: &Fingerprint) -> bool {
        self.map.contains_key(fp) || self.map.len() < self.capacity
    }

    /// The entry for `fp`, created if there is room. When the table is
    /// full, one idle entry (see [`SenderState::is_idle`]) is evicted to
    /// make room; the scan runs only then and is bounded by the capacity.
    /// `None` when full and nothing is idle.
    pub(crate) fn get_or_insert(&mut self, fp: Fingerprint, now: u64) -> Option<&mut SenderState> {
        if !self.can_track(&fp) {
            let (retention, window) = (self.retention_ms, self.window_ms);
            let idle = self
                .map
                .iter()
                .find(|(_, s)| s.is_idle(now, retention, window))
                .map(|(k, _)| *k);
            self.map.remove(&idle?);
        }
        Some(self.map.entry(fp).or_default())
    }

    pub(crate) fn is_quarantined(&self, fp: &Fingerprint) -> bool {
        self.map.get(fp).is_some_and(|s| s.quarantined_since.is_some())
    }

    pub(crate) fn quarantined(&self) -> Vec<Fingerprint> {
        let mut v: Vec<Fingerprint> = self
            .map
            .iter()
            .filter(|(_, s)| s.quarantined_since.is_some())
            .map(|(fp, _)| *fp)
            .collect();
        v.sort();
        v
    }

    pub(crate) fn quarantined_count(&self) -> usize {
        self.map.values().filter(|s| s.quarantined_since.is_some()).count()
    }

    /// Lifts a quarantine and forgets the breach history that caused it.
    pub(crate) fn release(&mut self, fp: &Fingerprint) -> bool {
        match self.map.get_mut(fp) {
            Some(s) if s.quarantined_since.is_some() => {
                s.quarantined_since = None;
                s.breaches.clear();
                true
            }
            _ => false,
        }
    }

    /// Drops state for senders no longer in `ring`, except entries that
    /// are not idle at `now`: quarantines (lifted only by an operator) and
    /// recent sequence and breach history, kept as tombstones so that a
    /// sender removed and later restored resumes from its old high-water
    /// mark instead of from nothing.
    pub(crate) fn retain_for(&mut self, ring: &KeyRing, now: u64) {
        let (retention, window) = (self.retention_ms, self.window_ms);
        self.map
            .retain(|fp, s| ring.contains(fp) || !s.is_idle(now, retention, window));
    }

    /// Forgets sequences and breach history, keeping quarantines.
    pub(crate) fn reset_keep_quarantine(&mut self) {
        self.map.retain(|_, s| s.quarantined_since.is_some());
        for s in self.map.values_mut() {
            s.last_sequence = None;
            s.last_accepted_at = None;
            s.breaches.clear();
        }
    }
}

/// All mutable receiver state, behind one mutex so that checking freshness
/// and committing it happen in one critical section.
#[derive(Debug)]
pub(crate) struct State {
    pub(crate) replay: ReplayCache,
    pub(crate) senders: SenderTable,
    /// Envelopes issued before this instant are refused. Never lowered.
    pub(crate) epoch_floor_ms: u64,
    /// Highest `issued_at_unix_ms` ever accepted (or restored from config).
    /// Survives operator resets, which raise the floor above it.
    pub(crate) high_water_ms: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fp(b: u8) -> Fingerprint {
        Fingerprint::from_hex(&format!("{b:02x}").repeat(32)).unwrap()
    }

    #[test]
    fn replay_cache_expires_in_order_and_refuses_when_full() {
        let mut c = ReplayCache::new(2);
        let (a, b) = (Nonce::from_bytes([1; 16]), Nonce::from_bytes([2; 16]));
        c.insert(fp(1), a, 100);
        c.insert(fp(1), b, 200);
        assert!(c.is_full());
        c.expire_sender(&fp(1), 99);
        assert!(c.contains(&fp(1), &a));
        c.expire_sender(&fp(1), 100);
        assert!(!c.contains(&fp(1), &a) && c.contains(&fp(1), &b));
        assert!(!c.is_full());
        assert_eq!(c.len(), 1);
        c.sweep(200);
        assert_eq!(c.len(), 0);
    }

    #[test]
    fn replay_cache_evicts_from_the_largest_holder() {
        let mut c = ReplayCache::new(3);
        c.insert(fp(1), Nonce::from_bytes([1; 16]), 100);
        c.insert(fp(1), Nonce::from_bytes([2; 16]), 100);
        c.insert(fp(2), Nonce::from_bytes([3; 16]), 100);
        assert!(c.is_full());
        assert!(c.evict_from_largest());
        assert!(!c.contains(&fp(1), &Nonce::from_bytes([1; 16])));
        assert_eq!((c.count(&fp(1)), c.count(&fp(2)), c.len()), (1, 1, 2));
    }

    #[test]
    fn breaker_counts_inside_window_only() {
        let mut s = SenderState::default();
        assert!(!s.record_breach(1_000, 100, 3));
        assert!(!s.record_breach(1_050, 100, 3));
        // The first breach has left the window by now.
        assert!(!s.record_breach(1_200, 100, 3));
        assert!(!s.record_breach(1_250, 100, 3));
        assert!(s.record_breach(1_260, 100, 3));
        assert!(s.breaches.len() <= 3);
    }

    #[test]
    fn sender_table_is_bounded() {
        let mut t = SenderTable::new(1, 100, 50);
        t.get_or_insert(fp(1), 0).unwrap().last_accepted_at = Some(0);
        assert!(t.get_or_insert(fp(1), 0).is_some());
        assert!(t.get_or_insert(fp(2), 99).is_none());
        assert!(!t.can_track(&fp(2)));
        // Idle for the whole retention window: evicted to make room.
        assert!(t.get_or_insert(fp(2), 100).is_some());
        assert!(t.get(&fp(1)).is_none());
    }

    #[test]
    fn quarantined_and_recent_entries_are_never_idle() {
        let mut s = SenderState::default();
        assert!(s.is_idle(0, 100, 50));
        s.breaches.push_back(10);
        assert!(!s.is_idle(60, 100, 50));
        assert!(s.is_idle(61, 100, 50));
        s.quarantined_since = Some(10);
        assert!(!s.is_idle(u64::MAX, 100, 50));
    }
}
