//! Waiting for the release time. Every loop is bounded: the spin loop by an
//! iteration cap derived from the remaining time (each iteration reads the
//! clock, which costs well over one nanosecond, so a working clock always
//! reaches the target first), the sleep loop by [`MAX_SLEEP_ROUNDS`].
//! Hitting either cap means the clock is not advancing, which the pad
//! treats as a clock failure.

use crate::clock::Clock;
use crate::config::WaitMode;
use std::time::{Duration, Instant};

/// Most sleep calls in one wait. `std::thread::sleep` already loops on early
/// wake-ups internally, so more than one round is rare.
pub const MAX_SLEEP_ROUNDS: u32 = 64;

/// Extra spin iterations allowed beyond one per remaining nanosecond.
const SPIN_ITER_SLACK: u64 = 1_000_000;

/// The clock did not behave like a monotonic clock.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ClockFault;

/// Busy-wait until `clock.now() >= target`.
pub(crate) fn spin_until<C: Clock + ?Sized>(clock: &C, target: Instant) -> Result<(), ClockFault> {
    let remaining = target.saturating_duration_since(clock.now());
    let cap = u64::try_from(remaining.as_nanos())
        .unwrap_or(u64::MAX)
        .saturating_add(SPIN_ITER_SLACK);
    for _ in 0..cap {
        if clock.now() >= target {
            return Ok(());
        }
        std::hint::spin_loop();
    }
    Err(ClockFault)
}

/// Sleep until `clock.now() >= target`.
pub(crate) fn sleep_until<C: Clock + ?Sized>(clock: &C, target: Instant) -> Result<(), ClockFault> {
    for _ in 0..MAX_SLEEP_ROUNDS {
        let now = clock.now();
        if now >= target {
            return Ok(());
        }
        std::thread::sleep(target.saturating_duration_since(now));
    }
    if clock.now() >= target {
        Ok(())
    } else {
        Err(ClockFault)
    }
}

/// Wait in `mode`. Hybrid sleeps until `target - tail`, then spins; if the
/// sleep wakes after `target`, the release is late by the wake-up delay.
pub(crate) fn wait<C: Clock + ?Sized>(
    clock: &C,
    target: Instant,
    mode: WaitMode,
    tail: Duration,
) -> Result<(), ClockFault> {
    match mode {
        WaitMode::Sleep => sleep_until(clock, target),
        WaitMode::Hybrid => {
            if let Some(wake) = target.checked_sub(tail) {
                sleep_until(clock, wake)?;
            }
            spin_until(clock, target)
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;
    use crate::clock::MonotonicClock;

    #[test]
    fn never_early() {
        for mode in [WaitMode::Sleep, WaitMode::Hybrid] {
            let target = Instant::now() + Duration::from_micros(500);
            wait(&MonotonicClock, target, mode, Duration::from_micros(200)).unwrap();
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
        let target = t + Duration::from_micros(10);
        assert_eq!(spin_until(&Frozen(t), target), Err(ClockFault));
    }
}
