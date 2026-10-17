//! A non-blocking counting semaphore for concurrent padded requests (the same design as strategy 1, `stack-anc-ceiling`).
//!
//! Admission never waits for a slot: a queue would let a flood hold
//! requests for an unbounded time and would make admission time depend on
//! queue position. Either a slot is free now, or the request is shed.
//!
//! # Why a slot is held for a fixed time
//!
//! If a slot were held until its request finished, a third party probing
//! admission would learn how long a victim's request took: "slots full"
//! while a slow victim is still inside, "free" after a fast one has left.
//! That is the victim's secret-dependent work time, leaked to someone who
//! cannot see the victim's own reply.
//!
//! So a slot is held for one fixed time, `hold`, counted from admission,
//! whatever the request does. Whether the next request is admitted is then
//! a function of arrival times alone. A request that runs past `hold` is
//! over the limit the pad promises to cover; its slot is already free.
//!
//! The cost is capacity: each slot admits one request per `hold`, not per
//! request time. Raise `max_concurrent` to compensate; waiting requests use
//! almost no CPU in Sleep mode.
//!
//! # The backstop
//!
//! Freeing slots on a clock means a request stuck past `hold` no longer
//! blocks a slot. A second, larger limit on requests actually still inside
//! the pad (4 times `max_concurrent`) keeps a flood of stuck
//! requests from piling up without bound. Requests within the limit never
//! reach it, because each is both running and held, so it can only be hit
//! by requests that are already over the limit.

use std::cmp::Reverse;
use std::collections::BinaryHeap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Mutex, MutexGuard};
use std::time::{Duration, Instant};

/// How many times `max_concurrent` requests may be inside the pad at once,
/// counting those past their hold time. See the module docs.
pub(crate) const BACKSTOP_FACTOR: usize = 4;

#[derive(Debug)]
pub(crate) struct Slots {
    cap: usize,
    backstop: usize,
    hold: Duration,
    /// Requests admitted and not yet returned. Raised only under the lock.
    running: AtomicUsize,
    /// Expiry instants (`start + hold`) of admitted requests, soonest first.
    held: Mutex<BinaryHeap<Reverse<Instant>>>,
}

/// A request inside the pad. Dropping it counts the request out of the
/// backstop. It does not free the slot: the slot frees itself at `hold`.
#[derive(Debug)]
pub(crate) struct Permit<'a> {
    slots: &'a Slots,
}

impl Slots {
    pub(crate) fn new(cap: usize, hold: Duration) -> Self {
        Self {
            cap,
            backstop: cap.saturating_mul(BACKSTOP_FACTOR),
            hold,
            running: AtomicUsize::new(0),
            held: Mutex::new(BinaryHeap::new()),
        }
    }

    fn lock(&self) -> MutexGuard<'_, BinaryHeap<Reverse<Instant>>> {
        // Nothing here panics while holding the lock, so a poisoned lock
        // still holds consistent data.
        self.held.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Admit a request that started at `start`, or return `None` to shed
    /// it. The decision uses only earlier admission instants and the
    /// backstop count, never how long any request took.
    pub(crate) fn try_acquire(&self, start: Instant) -> Option<Permit<'_>> {
        let expiry = start.checked_add(self.hold)?;
        let mut held = self.lock();
        while held.peek().is_some_and(|Reverse(t)| *t <= start) {
            held.pop();
        }
        if held.len() >= self.cap || self.running.load(Ordering::Acquire) >= self.backstop {
            return None;
        }
        held.push(Reverse(expiry));
        self.running.fetch_add(1, Ordering::AcqRel);
        Some(Permit { slots: self })
    }

    /// Requests admitted and not yet returned.
    pub(crate) fn in_use(&self) -> usize {
        self.running.load(Ordering::Relaxed)
    }
}

impl Drop for Permit<'_> {
    fn drop(&mut self) {
        self.slots.running.fetch_sub(1, Ordering::Release);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ms(n: u64) -> Duration {
        Duration::from_millis(n)
    }

    #[test]
    fn a_slot_is_held_for_the_fixed_time_even_if_the_request_returns_at_once() {
        let slots = Slots::new(1, ms(100));
        let t0 = Instant::now();
        drop(slots.try_acquire(t0).expect("first admitted"));
        assert!(slots.try_acquire(t0 + ms(99)).is_none(), "still held at 99 ms");
        assert!(slots.try_acquire(t0 + ms(100)).is_some(), "free at the hold time");
    }

    #[test]
    fn a_request_still_running_past_the_hold_time_does_not_hold_the_slot() {
        let slots = Slots::new(1, ms(100));
        let t0 = Instant::now();
        let _slow = slots.try_acquire(t0).expect("admitted");
        let second = slots.try_acquire(t0 + ms(150));
        assert!(second.is_some(), "free after the hold time");
        assert_eq!(slots.in_use(), 2);
    }

    #[test]
    fn the_backstop_bounds_requests_that_are_stuck() {
        let slots = Slots::new(1, ms(10));
        let t0 = Instant::now();
        let mut stuck = Vec::new();
        for i in 0..BACKSTOP_FACTOR {
            stuck.push(slots.try_acquire(t0 + ms(20 * i as u64)).expect("under the backstop"));
        }
        assert!(slots.try_acquire(t0 + ms(20 * BACKSTOP_FACTOR as u64)).is_none());
        drop(stuck.pop());
        assert!(slots.try_acquire(t0 + ms(20 * BACKSTOP_FACTOR as u64)).is_some());
    }

    #[test]
    fn the_verdict_does_not_depend_on_whether_earlier_requests_have_returned() {
        let t0 = Instant::now();
        let verdicts: Vec<bool> = [true, false]
            .into_iter()
            .map(|victim_returned| {
                let slots = Slots::new(1, ms(40));
                let victim = slots.try_acquire(t0).expect("admitted");
                if victim_returned {
                    drop(victim);
                    slots.try_acquire(t0 + ms(34)).is_some()
                } else {
                    let probe = slots.try_acquire(t0 + ms(34)).is_some();
                    drop(victim);
                    probe
                }
            })
            .collect();
        assert_eq!(verdicts[0], verdicts[1]);
    }
}
