//! A non-blocking counting semaphore for concurrent padded requests (the same design as strategy 1, `stack-anc-ceiling`).
//!
//! Admission never waits for a slot in the queue sense: a queue would let a
//! flood hold requests for an unbounded time and would make admission time
//! depend on queue position. Either a slot is free now, the request waits
//! in the small fixed-wait spillway (if one is configured), or it is shed.
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
//! request time. The two features below buy part of it back.
//!
//! # Extra slots that open on backlog
//!
//! Like a store opening more registers when the line grows, the number of
//! open slots can rise from `max_concurrent` up to `max_slots`. The rule
//! looks only at public counts: whether any arrival found every open slot
//! taken during a window of `reaction_delay`. A window with such an arrival
//! opens `step` more slots; `cooldown_windows` quiet windows in a row close
//! `step` again, never below `max_concurrent`. The count never looks at how
//! long any request took, and changes at most once per window, so it cannot
//! be steered one request at a time. The slots-taken test uses the held
//! times, which are arrival times plus a constant. The backstop below is
//! deliberately not counted, because it depends on when requests returned.
//!
//! # The spillway
//!
//! An arrival that finds every slot taken may wait in a small area of
//! `spillway_size` places for exactly `spillway_wait`, then tries once more.
//! The wait is the same for every request, so it says nothing about the
//! work. Occupancy of the area is counted on the same arrival-time rule as
//! the slots. A full area sheds at once.
//!
//! # The backstop
//!
//! Freeing slots on a clock means a request stuck past `hold` no longer
//! blocks a slot. A second, larger limit on requests actually still inside
//! the pad (4 times the most slots that can open) keeps a flood of
//! stuck requests from piling up without bound. Requests within the limit
//! never reach it, because each is both running and held, so it can only be
//! hit by requests that are already over the limit.

use crate::config::SlotScaling;
use std::cmp::Reverse;
use std::collections::BinaryHeap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Mutex, MutexGuard};
use std::time::{Duration, Instant};

/// How many times the most slots that can open may be inside the pad at
/// once, counting those past their hold time. See the module docs.
pub(crate) const BACKSTOP_FACTOR: usize = 4;

type Expiries = BinaryHeap<Reverse<Instant>>;

#[derive(Debug)]
struct State {
    held: Expiries,
    spill: Expiries,
    /// Slots open right now: `base ..= max_slots`.
    open: usize,
    window_end: Instant,
    /// An arrival found every open slot held during this window.
    pressure: bool,
    /// Windows in a row without pressure.
    quiet: u32,
}

#[derive(Debug)]
pub(crate) struct Slots {
    base: usize,
    max_slots: usize,
    backstop: usize,
    hold: Duration,
    step: usize,
    reaction: Duration,
    cooldown: u32,
    spill_size: usize,
    spill_wait: Duration,
    /// Requests admitted and not yet returned. Raised only under the lock.
    running: AtomicUsize,
    state: Mutex<State>,
}

/// What an arrival found.
#[derive(Debug)]
pub(crate) enum Step<'a> {
    In(Permit<'a>),
    /// Every slot is held but the spillway has room: wait `spillway_wait`,
    /// then call [`Slots::retry`].
    Spill,
    Shed,
}

/// A request inside the pad. Dropping it counts the request out of the
/// backstop. It does not free the slot: the slot frees itself at `hold`.
#[derive(Debug)]
pub(crate) struct Permit<'a> {
    slots: &'a Slots,
}

impl Slots {
    /// `base` slots open at the start; `scaling` is already validated.
    pub(crate) fn new(base: usize, hold: Duration, scaling: &SlotScaling, now: Instant) -> Self {
        let max_slots = scaling.effective_max(base);
        Self {
            base,
            max_slots,
            backstop: max_slots.saturating_mul(BACKSTOP_FACTOR),
            hold,
            step: scaling.step.max(1),
            reaction: scaling.reaction_delay,
            cooldown: scaling.cooldown_windows.max(1),
            spill_size: scaling.spillway_size,
            spill_wait: scaling.spillway_wait,
            running: AtomicUsize::new(0),
            state: Mutex::new(State {
                held: BinaryHeap::new(),
                spill: BinaryHeap::new(),
                open: base,
                window_end: now.checked_add(scaling.reaction_delay).unwrap_or(now),
                pressure: false,
                quiet: 0,
            }),
        }
    }

    fn lock(&self) -> MutexGuard<'_, State> {
        // Nothing here panics while holding the lock, so a poisoned lock
        // still holds consistent data.
        self.state.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Close finished windows: open or close slots from the public counts.
    fn roll(&self, st: &mut State, now: Instant) {
        if self.max_slots == self.base || now < st.window_end {
            return;
        }
        let r = self.reaction.as_nanos().max(1);
        let idle = now.duration_since(st.window_end).as_nanos() / r;
        let idle = u32::try_from(idle).unwrap_or(u32::MAX);
        if st.pressure {
            st.open = st.open.saturating_add(self.step).min(self.max_slots);
            st.quiet = 0;
        } else {
            st.quiet = st.quiet.saturating_add(1);
        }
        st.quiet = st.quiet.saturating_add(idle);
        st.pressure = false;
        if st.quiet >= self.cooldown {
            let closes = (st.quiet / self.cooldown) as usize;
            st.open = st.open.saturating_sub(closes.saturating_mul(self.step)).max(self.base);
            st.quiet %= self.cooldown;
        }
        st.window_end = self
            .reaction
            .checked_mul(idle.saturating_add(1))
            .and_then(|d| st.window_end.checked_add(d))
            .or_else(|| now.checked_add(self.reaction))
            .unwrap_or(now);
    }

    fn free_expired(heap: &mut Expiries, now: Instant) {
        while heap.peek().is_some_and(|Reverse(t)| *t <= now) {
            heap.pop();
        }
    }

    /// An arrival at `now`. The verdict uses only earlier arrival instants,
    /// the fixed hold, and the backstop count, never how long any request
    /// took.
    pub(crate) fn enter(&self, now: Instant) -> Step<'_> {
        let Some(expiry) = now.checked_add(self.hold) else {
            return Step::Shed;
        };
        let mut st = self.lock();
        self.roll(&mut st, now);
        Self::free_expired(&mut st.held, now);
        if self.running.load(Ordering::Acquire) >= self.backstop {
            return Step::Shed;
        }
        if st.held.len() < st.open {
            st.held.push(Reverse(expiry));
            self.running.fetch_add(1, Ordering::AcqRel);
            return Step::In(Permit { slots: self });
        }
        st.pressure = true;
        Self::free_expired(&mut st.spill, now);
        match now.checked_add(self.spill_wait) {
            Some(leaves) if st.spill.len() < self.spill_size => {
                st.spill.push(Reverse(leaves));
                Step::Spill
            }
            _ => Step::Shed,
        }
    }

    /// The one new try after the spillway wait.
    pub(crate) fn retry(&self, now: Instant) -> Option<Permit<'_>> {
        let expiry = now.checked_add(self.hold)?;
        let mut st = self.lock();
        self.roll(&mut st, now);
        Self::free_expired(&mut st.held, now);
        if st.held.len() >= st.open || self.running.load(Ordering::Acquire) >= self.backstop {
            return None;
        }
        st.held.push(Reverse(expiry));
        self.running.fetch_add(1, Ordering::AcqRel);
        Some(Permit { slots: self })
    }

    /// Slots open right now (as of the last arrival).
    pub(crate) fn open(&self) -> usize {
        self.lock().open
    }

    /// The fixed spillway wait.
    pub(crate) fn spill_wait(&self) -> Duration {
        self.spill_wait
    }

    /// Requests admitted and not yet returned.
    pub(crate) fn in_use(&self) -> usize {
        self.running.load(Ordering::Relaxed)
    }

    #[cfg(test)]
    fn try_acquire(&self, now: Instant) -> Option<Permit<'_>> {
        match self.enter(now) {
            Step::In(p) => Some(p),
            _ => None,
        }
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

    fn plain(cap: usize, hold: Duration, t0: Instant) -> Slots {
        Slots::new(cap, hold, &SlotScaling::default(), t0)
    }

    fn scaled(base: usize, max: usize, t0: Instant) -> Slots {
        let sc = SlotScaling {
            max_slots: max,
            step: 1,
            reaction_delay: ms(10),
            cooldown_windows: 2,
            ..SlotScaling::default()
        };
        Slots::new(base, ms(100), &sc, t0)
    }

    #[test]
    fn a_slot_is_held_for_the_fixed_time_even_if_the_request_returns_at_once() {
        let t0 = Instant::now();
        let slots = plain(1, ms(100), t0);
        drop(slots.try_acquire(t0).expect("first admitted"));
        assert!(slots.try_acquire(t0 + ms(99)).is_none(), "still held at 99 ms");
        assert!(slots.try_acquire(t0 + ms(100)).is_some(), "free at the hold time");
    }

    #[test]
    fn a_request_still_running_past_the_hold_time_does_not_hold_the_slot() {
        let t0 = Instant::now();
        let slots = plain(1, ms(100), t0);
        let _slow = slots.try_acquire(t0).expect("admitted");
        let second = slots.try_acquire(t0 + ms(150));
        assert!(second.is_some(), "free after the hold time");
        assert_eq!(slots.in_use(), 2);
    }

    #[test]
    fn the_backstop_bounds_requests_that_are_stuck() {
        let t0 = Instant::now();
        let slots = plain(1, ms(10), t0);
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
                let slots = plain(1, ms(40), t0);
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

    #[test]
    fn a_window_with_a_turned_away_arrival_opens_one_more_slot() {
        let t0 = Instant::now();
        let slots = scaled(1, 3, t0);
        let _a = slots.try_acquire(t0 + ms(1)).expect("first");
        assert!(slots.try_acquire(t0 + ms(2)).is_none(), "second is turned away");
        assert_eq!(slots.open(), 1, "the count changes only at the window end");
        let _b = slots.try_acquire(t0 + ms(11)).expect("second slot opened");
        assert_eq!(slots.open(), 2);
    }

    #[test]
    fn slots_never_open_past_the_maximum() {
        let t0 = Instant::now();
        let slots = scaled(1, 3, t0);
        let mut held = Vec::new();
        for w in 0..20u64 {
            for k in 0..6u64 {
                if let Some(p) = slots.try_acquire(t0 + ms(w * 10 + k)) {
                    held.push(p);
                }
            }
        }
        assert_eq!(slots.open(), 3);
    }

    #[test]
    fn quiet_windows_close_slots_back_to_the_base() {
        let t0 = Instant::now();
        let slots = scaled(1, 3, t0);
        let mut held = Vec::new();
        for w in 0..6u64 {
            for k in 0..4u64 {
                if let Some(p) = slots.try_acquire(t0 + ms(w * 10 + k)) {
                    held.push(p);
                }
            }
        }
        assert_eq!(slots.open(), 3);
        // Nothing arrives for a long time, then one request.
        let _late = slots.try_acquire(t0 + ms(5_000)).expect("admitted");
        assert_eq!(slots.open(), 1);
    }

    #[test]
    fn the_backstop_does_not_count_as_backlog() {
        let t0 = Instant::now();
        let sc = SlotScaling {
            max_slots: 2,
            reaction_delay: ms(10),
            ..SlotScaling::default()
        };
        let slots = Slots::new(1, ms(1), &sc, t0);
        // Fill the backstop (4 x 2) with requests that are past their hold.
        let mut stuck = Vec::new();
        for i in 0..8u64 {
            stuck.push(slots.try_acquire(t0 + ms(2 * i)).expect("under backstop"));
        }
        assert!(slots.try_acquire(t0 + ms(40)).is_none(), "backstop sheds");
        let _p = slots.try_acquire(t0 + ms(60));
        assert_eq!(slots.open(), 1, "a backstop shed must not open slots");
    }

    #[test]
    fn the_spillway_takes_a_fixed_number_and_each_waits_the_same_time() {
        let t0 = Instant::now();
        let sc = SlotScaling {
            spillway_size: 1,
            spillway_wait: ms(20),
            ..SlotScaling::default()
        };
        let slots = Slots::new(1, ms(100), &sc, t0);
        let _a = slots.try_acquire(t0).expect("in");
        assert!(matches!(slots.enter(t0 + ms(1)), Step::Spill));
        assert!(matches!(slots.enter(t0 + ms(2)), Step::Shed), "spillway full");
        assert_eq!(slots.spill_wait(), ms(20));
        assert!(slots.retry(t0 + ms(21)).is_none(), "slot still held");
        // After the wait the place has left the spillway.
        assert!(matches!(slots.enter(t0 + ms(22)), Step::Spill));
        assert!(slots.retry(t0 + ms(101)).is_some(), "slot free after its hold");
    }
}
