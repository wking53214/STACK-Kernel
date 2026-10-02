//! A non-blocking counting semaphore for concurrent padded requests (the
//! same design as strategy 1, `stack-anc-ceiling`).
//!
//! Admission never waits for a slot: a queue would let a flood hold
//! requests for an unbounded time and would make admission time depend on
//! queue position. Either a slot is free now, or the request is shed.

use std::sync::atomic::{AtomicUsize, Ordering};

#[derive(Debug)]
pub(crate) struct Slots {
    cap: usize,
    in_use: AtomicUsize,
}

/// A held slot. Dropping it frees the slot.
#[derive(Debug)]
pub(crate) struct Permit<'a> {
    slots: &'a Slots,
}

impl Slots {
    pub(crate) fn new(cap: usize) -> Self {
        Self {
            cap,
            in_use: AtomicUsize::new(0),
        }
    }

    /// Take a slot if one is free. The compare-exchange loop retries only
    /// while other threads change the counter and the cap is not reached,
    /// so it is bounded by contention, and the counter never exceeds `cap`.
    pub(crate) fn try_acquire(&self) -> Option<Permit<'_>> {
        let mut cur = self.in_use.load(Ordering::Relaxed);
        loop {
            if cur >= self.cap {
                return None;
            }
            match self.in_use.compare_exchange_weak(
                cur,
                cur + 1,
                Ordering::Acquire,
                Ordering::Relaxed,
            ) {
                Ok(_) => return Some(Permit { slots: self }),
                Err(actual) => cur = actual,
            }
        }
    }

    pub(crate) fn in_use(&self) -> usize {
        self.in_use.load(Ordering::Relaxed)
    }
}

impl Drop for Permit<'_> {
    fn drop(&mut self) {
        self.slots.in_use.fetch_sub(1, Ordering::Release);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn caps_and_releases() {
        let s = Slots::new(2);
        let a = s.try_acquire();
        let b = s.try_acquire();
        assert!(a.is_some() && b.is_some());
        assert!(s.try_acquire().is_none());
        assert_eq!(s.in_use(), 2);
        drop(a);
        assert_eq!(s.in_use(), 1);
        assert!(s.try_acquire().is_some());
        drop(b);
        assert_eq!(s.in_use(), 0);
    }

    #[test]
    fn never_exceeds_cap_under_threads() {
        let s = Slots::new(3);
        let max_seen = AtomicUsize::new(0);
        std::thread::scope(|scope| {
            for _ in 0..8 {
                scope.spawn(|| {
                    for _ in 0..10_000 {
                        if let Some(p) = s.try_acquire() {
                            max_seen.fetch_max(s.in_use(), Ordering::Relaxed);
                            drop(p);
                        }
                    }
                });
            }
        });
        assert!(max_seen.load(Ordering::Relaxed) <= 3);
        assert_eq!(s.in_use(), 0);
    }
}
