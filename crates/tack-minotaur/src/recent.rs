//! A bounded table of recently seen untracked states, with exact visit
//! counts, for the degraded mode.
//!
//! Brent's detector (see `brent.rs`) only ever compares against one saved
//! state, and the steps at which it moves that state are fixed. A walker who
//! controls which step first overflows the exact set can line those steps up
//! so the saved state always lands on a fresh filler state and never on the
//! state being repeated (for example `A, n1, A, n2, A, n3, ...` with a new
//! nonce `n` each time). This table closes that gap by counting the repeated
//! state directly.
//!
//! It holds at most `cap` states. Each entry keeps the same two numbers the
//! exact set keeps (visit count and the step of the latest visit), and the
//! loop rule is the same: more than `allowance` revisits is a loop. When the
//! table is full, a new state evicts an old one chosen by the CLOCK rule: a
//! hand sweeps the slots, sparing (and clearing the mark of) any entry
//! revisited since the hand last passed it, and evicts the first unmarked
//! entry.
//!
//! Guarantee: a state whose successive visits are fewer than `cap` table
//! operations apart is never evicted between them, so its revisits are
//! counted exactly. (For the hand to evict it, it must pass the state once,
//! which clears the mark, and then travel all `cap` slots again. Every slot
//! the hand moves over in that second lap costs one table operation: an
//! eviction or a mark set by a revisit.) Counts are never overestimated, so
//! the table has no false positives: a walk of all-distinct states never
//! trips it.
//!
//! Memory: `cap` slots and a hash index of `cap` entries, allocated once.
//! The index uses the standard library's randomly keyed SipHash, so chosen
//! fingerprints cannot force slow collisions. Work per operation is
//! amortized constant; one eviction can sweep up to `cap` slots.

use std::collections::HashMap;

use crate::fingerprint::Fingerprint;

#[derive(Debug, Clone, Copy)]
struct Slot {
    fp: Fingerprint,
    /// Visits while resident, including the first.
    count: u32,
    /// Step number of the most recent visit.
    last_step: u64,
    /// Revisited since the CLOCK hand last passed this slot.
    marked: bool,
}

#[derive(Debug)]
pub(crate) struct Recent {
    index: HashMap<Fingerprint, usize>,
    slots: Vec<Slot>,
    hand: usize,
    cap: usize,
}

impl Recent {
    /// `cap` is clamped to at least 1.
    pub(crate) fn new(cap: usize) -> Self {
        let cap = cap.max(1);
        Self {
            index: HashMap::with_capacity(cap),
            slots: Vec::with_capacity(cap),
            hand: 0,
            cap,
        }
    }

    pub(crate) fn reset(&mut self) {
        self.index.clear();
        self.slots.clear();
        self.hand = 0;
    }

    /// Slots this table holds at most.
    pub(crate) const fn capacity(&self) -> usize {
        self.cap
    }

    /// Record one visit to an untracked state at `step`. Returns the gap
    /// since its previous visit when it has now been revisited more than
    /// `allowance` times while resident.
    pub(crate) fn observe(&mut self, x: Fingerprint, step: u64, allowance: u32) -> Option<u64> {
        if let Some(&i) = self.index.get(&x) {
            let s = self.slots.get_mut(i)?;
            s.count = s.count.saturating_add(1);
            let gap = step.saturating_sub(s.last_step);
            s.last_step = step;
            s.marked = true;
            return (s.count.saturating_sub(1) > allowance).then_some(gap);
        }
        let fresh = Slot {
            fp: x,
            count: 1,
            last_step: step,
            marked: false,
        };
        if self.slots.len() < self.cap {
            self.index.insert(x, self.slots.len());
            self.slots.push(fresh);
            return None;
        }
        // CLOCK sweep. After one full lap every mark is clear, so at most
        // `cap + 1` iterations run before an unmarked slot is found.
        for _ in 0..=self.cap {
            match self.slots.get_mut(self.hand) {
                Some(s) if s.marked => {
                    s.marked = false;
                    self.hand = (self.hand + 1) % self.cap;
                }
                _ => break,
            }
        }
        if let Some(victim) = self.slots.get_mut(self.hand) {
            self.index.remove(&victim.fp);
            *victim = fresh;
            self.index.insert(x, self.hand);
        }
        self.hand = (self.hand + 1) % self.cap;
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fp(n: u64) -> Fingerprint {
        Fingerprint::of_bytes(&n.to_le_bytes())
    }

    #[test]
    fn counts_a_state_interleaved_with_fresh_nonces() {
        let mut r = Recent::new(8);
        let a = fp(u64::MAX);
        let mut step = 0;
        let mut found = None;
        for i in 0..1_000u64 {
            step += 1;
            if let Some(p) = r.observe(a, step, 3) {
                found = Some((i, p));
                break;
            }
            step += 1;
            assert_eq!(r.observe(fp(i), step, 3), None);
        }
        // Fifth visit of `a` (fourth revisit, allowance 3), gap 2.
        assert_eq!(found, Some((4, 2)));
    }

    #[test]
    fn distinct_states_never_trip_and_memory_is_fixed() {
        let mut r = Recent::new(16);
        for n in 0..10_000u64 {
            assert_eq!(r.observe(fp(n), n, 0), None);
            assert!(r.slots.len() <= 16 && r.index.len() <= 16);
        }
    }

    #[test]
    fn resident_while_gap_is_below_capacity() {
        // Gap cap - 1 (cap - 2 fresh states in between) is always caught.
        let cap = 32usize;
        let mut r = Recent::new(cap);
        let a = fp(u64::MAX);
        let mut step = 0u64;
        let mut hits = 0;
        for round in 0..10u64 {
            step += 1;
            if r.observe(a, step, 3).is_some() {
                hits += 1;
                break;
            }
            for k in 0..(cap as u64 - 2) {
                step += 1;
                r.observe(fp(round * 1_000 + k), step, 3);
            }
        }
        assert_eq!(hits, 1);
    }

    #[test]
    fn capacity_one_holds_a_single_state() {
        let mut r = Recent::new(0);
        assert_eq!(r.capacity(), 1);
        for i in 0..100u64 {
            assert_eq!(r.observe(fp(i % 2), i, 0), None);
        }
    }
}
