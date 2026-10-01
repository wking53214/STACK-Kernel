//! Release-time arithmetic and the three ways of waiting for it.
//!
//! Every loop here is bounded in iterations and, for a clock that stops or
//! slows, in wall time:
//! * The spin loop has an iteration cap derived from the remaining time,
//!   and a wall-time watchdog on `std::time::Instant`: if more than twice
//!   the remaining time plus [`SPIN_WALL_SLACK`] passes in real time and
//!   the clock still has not reached the target, it is a clock failure.
//!   The watchdog re-reads the clock before failing, so with the default
//!   [`crate::MonotonicClock`] (the same clock) preemption can never cause
//!   a false failure.
//! * The sleep loop runs at most [`MAX_SLEEP_ROUNDS`] rounds, and a round
//!   that slept but saw the clock not move at all is a clock failure at
//!   once (a real sleep always takes at least a microsecond).
//!
//! So a frozen clock trips after about one ceiling (Sleep, Hybrid) or about
//! two ceilings plus 1 ms (Spin), not after many. The pad treats every
//! such failure as [`crate::Trip::ClockFailure`] and halts.

use crate::clock::Clock;
use crate::config::WaitMode;
use std::time::{Duration, Instant};

/// Most sleep calls in one wait. `std::thread::sleep` already loops on
/// early wake-ups internally and the tokio timer never fires early, so
/// with the default clock one round always suffices.
pub const MAX_SLEEP_ROUNDS: u32 = 4;

/// Extra spin iterations allowed beyond one per remaining nanosecond.
const SPIN_ITER_SLACK: u64 = 1_000_000;

/// Wall-time slack of the spin watchdog, beyond twice the remaining time.
pub const SPIN_WALL_SLACK: Duration = Duration::from_millis(1);

/// The spin loop reads the watchdog clock once per this many iterations.
const SPIN_WATCHDOG_EVERY: u64 = 64;

/// The clock did not behave like a monotonic clock.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ClockFault;

/// The release bucket for an operation that took `elapsed`: the smallest
/// `k >= 1` with `k * ceiling >= elapsed`. On time is `k = 1`. A zero
/// ceiling is treated as 1 ns (config validation forbids it anyway).
pub fn release_bucket(elapsed: Duration, ceiling: Duration) -> u64 {
    let c = ceiling.as_nanos().max(1);
    let k = elapsed.as_nanos().div_ceil(c).max(1);
    u64::try_from(k).unwrap_or(u64::MAX)
}

/// `ceiling * k` as a `Duration`, or `None` on overflow.
pub fn bucket_offset(ceiling: Duration, k: u64) -> Option<Duration> {
    let ns = ceiling.as_nanos().checked_mul(u128::from(k))?;
    let secs = u64::try_from(ns / 1_000_000_000).ok()?;
    let sub = u32::try_from(ns % 1_000_000_000).ok()?;
    Some(Duration::new(secs, sub))
}

/// Busy-wait until `clock.now() >= target`.
#[inline]
pub(crate) fn spin_until<C: Clock + ?Sized>(clock: &C, target: Instant) -> Result<(), ClockFault> {
    let remaining = target.saturating_duration_since(clock.now());
    let cap = u64::try_from(remaining.as_nanos())
        .unwrap_or(u64::MAX)
        .saturating_add(SPIN_ITER_SLACK);
    // Wall-time watchdog. `None` (overflow) leaves only the iteration cap.
    let wall_deadline = remaining
        .checked_mul(2)
        .and_then(|d| d.checked_add(SPIN_WALL_SLACK))
        .and_then(|d| Instant::now().checked_add(d));
    for i in 0..cap {
        if clock.now() >= target {
            return Ok(());
        }
        if i % SPIN_WATCHDOG_EVERY == SPIN_WATCHDOG_EVERY - 1
            && wall_deadline.is_some_and(|w| Instant::now() >= w)
        {
            // Re-read the clock after the watchdog read, so a preemption
            // between the two reads cannot fail a working clock.
            return if clock.now() >= target {
                Ok(())
            } else {
                Err(ClockFault)
            };
        }
        std::hint::spin_loop();
    }
    Err(ClockFault)
}

/// One sleep round's check: the clock must have moved forward across a
/// real sleep.
#[inline]
fn advanced(before: Instant, after: Instant) -> Result<(), ClockFault> {
    if after > before {
        Ok(())
    } else {
        Err(ClockFault)
    }
}

/// Sleep until `clock.now() >= target`.
pub(crate) fn sleep_until<C: Clock + ?Sized>(clock: &C, target: Instant) -> Result<(), ClockFault> {
    let mut now = clock.now();
    for _ in 0..MAX_SLEEP_ROUNDS {
        if now >= target {
            return Ok(());
        }
        std::thread::sleep(target.saturating_duration_since(now));
        let after = clock.now();
        advanced(now, after)?;
        now = after;
    }
    if clock.now() >= target {
        Ok(())
    } else {
        Err(ClockFault)
    }
}

/// Blocking wait in `mode`. For Hybrid, sleeps until `target - tail`, then
/// spins. If the sleep phase wakes after `target`, the release is late
/// (the precision tradeoff documented on [`WaitMode::Hybrid`]).
pub(crate) fn wait_blocking<C: Clock + ?Sized>(
    clock: &C,
    target: Instant,
    mode: WaitMode,
    tail: Duration,
) -> Result<(), ClockFault> {
    match mode {
        WaitMode::Sleep => sleep_until(clock, target),
        WaitMode::Spin => spin_until(clock, target),
        WaitMode::Hybrid => {
            if let Some(wake) = target.checked_sub(tail) {
                sleep_until(clock, wake)?;
            }
            spin_until(clock, target)
        }
    }
}

/// Async sleep until `clock.now() >= target`, on the tokio timer. Tokio
/// rounds deadlines up to its 1 ms tick, so this wakes up to about 1 ms
/// late; it never wakes early.
pub(crate) async fn sleep_until_async<C: Clock + ?Sized>(
    clock: &C,
    target: Instant,
) -> Result<(), ClockFault> {
    let mut now = clock.now();
    for _ in 0..MAX_SLEEP_ROUNDS {
        if now >= target {
            return Ok(());
        }
        tokio::time::sleep_until(tokio::time::Instant::from_std(target)).await;
        let after = clock.now();
        advanced(now, after)?;
        now = after;
    }
    if clock.now() >= target {
        Ok(())
    } else {
        Err(ClockFault)
    }
}

/// Async wait in `mode`. Spin and the Hybrid tail busy-wait on the
/// executor thread: they block that worker for the spin time.
pub(crate) async fn wait_async<C: Clock + ?Sized>(
    clock: &C,
    target: Instant,
    mode: WaitMode,
    tail: Duration,
) -> Result<(), ClockFault> {
    match mode {
        WaitMode::Sleep => sleep_until_async(clock, target).await,
        WaitMode::Spin => spin_until(clock, target),
        WaitMode::Hybrid => {
            if let Some(wake) = target.checked_sub(tail) {
                sleep_until_async(clock, wake).await?;
            }
            spin_until(clock, target)
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn bucket_examples() {
        let c = Duration::from_millis(2);
        assert_eq!(release_bucket(Duration::ZERO, c), 1);
        assert_eq!(release_bucket(Duration::from_micros(1_999), c), 1);
        assert_eq!(release_bucket(c, c), 1);
        assert_eq!(release_bucket(c + Duration::from_nanos(1), c), 2);
        assert_eq!(release_bucket(Duration::from_micros(4_500), c), 3);
        assert_eq!(bucket_offset(c, 3), Some(Duration::from_millis(6)));
        assert_eq!(bucket_offset(Duration::MAX, 2), None);
    }

    proptest! {
        #[test]
        fn bucket_is_smallest_cover(e_ns in 0u64..10_000_000_000, c_ns in 1u64..1_000_000_000) {
            let e = Duration::from_nanos(e_ns);
            let c = Duration::from_nanos(c_ns);
            let k = release_bucket(e, c);
            prop_assert!(k >= 1);
            let off = bucket_offset(c, k).unwrap();
            prop_assert!(off >= e, "release before completion");
            if k > 1 {
                let prev = bucket_offset(c, k - 1).unwrap();
                prop_assert!(prev < e, "not the smallest bucket");
            }
            // Release offsets are always whole multiples of the ceiling.
            prop_assert_eq!(off.as_nanos() % c.as_nanos(), 0);
        }
    }

    #[test]
    fn spin_and_sleep_reach_target_never_early() {
        let clock = crate::clock::MonotonicClock;
        for mode in [WaitMode::Sleep, WaitMode::Spin, WaitMode::Hybrid] {
            let target = Instant::now() + Duration::from_micros(500);
            wait_blocking(&clock, target, mode, Duration::from_micros(200)).unwrap();
            assert!(Instant::now() >= target, "{mode:?} released early");
        }
    }

    #[derive(Debug)]
    struct Frozen(Instant);
    impl Clock for Frozen {
        fn now(&self) -> Instant {
            self.0
        }
    }

    #[test]
    fn frozen_clock_is_a_fault_not_a_hang() {
        let t = Instant::now();
        let clock = Frozen(t);
        let target = t + Duration::from_micros(10);
        assert_eq!(spin_until(&clock, target), Err(ClockFault));
        assert_eq!(sleep_until(&clock, target), Err(ClockFault));
    }

    #[test]
    fn frozen_clock_trips_quickly() {
        let t = Instant::now();
        let clock = Frozen(t);
        let ceiling = Duration::from_millis(5);
        for mode in [WaitMode::Sleep, WaitMode::Spin, WaitMode::Hybrid] {
            let t0 = Instant::now();
            let r = wait_blocking(&clock, t + ceiling, mode, Duration::from_micros(250));
            assert_eq!(r, Err(ClockFault), "{mode:?}");
            assert!(
                t0.elapsed() < ceiling * 3 + Duration::from_millis(20),
                "{mode:?}"
            );
        }
    }
}
