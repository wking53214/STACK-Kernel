//! The public ladder of targets: `min(floor * 2^i, cap)` for
//! `i` in `0 ..= top_level`. Pure arithmetic in `u128` nanoseconds; every
//! loop is bounded by 64 iterations.

use std::time::Duration;

/// Hard bound on level indices. `floor * 2^63` exceeds any `Duration` the
/// config accepts, so real ladders stop far earlier (at most 24 levels for
/// a 1 us floor and a 10 s cap).
pub(crate) const MAX_LEVEL: u32 = 63;

fn ns(d: Duration) -> u128 {
    d.as_nanos()
}

fn from_ns(n: u128) -> Duration {
    let secs = u64::try_from(n / 1_000_000_000).unwrap_or(u64::MAX);
    // The remainder is below 1e9, so it always fits in u32.
    let sub = u32::try_from(n % 1_000_000_000).unwrap_or(0);
    Duration::new(secs, sub)
}

/// Smallest `i` with `floor * 2^i >= cap`, at most [`MAX_LEVEL`]. A zero
/// floor (rejected by config validation) yields `MAX_LEVEL`.
pub(crate) fn top_level(floor: Duration, cap: Duration) -> u32 {
    let f = ns(floor);
    let c = ns(cap);
    let mut i = 0u32;
    while i < MAX_LEVEL && (f << i) < c {
        i += 1;
    }
    i
}

/// `min(floor * 2^i, cap)`.
pub(crate) fn level_target(floor: Duration, cap: Duration, i: u32) -> Duration {
    let i = i.min(MAX_LEVEL);
    from_ns((ns(floor) << i).min(ns(cap)))
}

/// Smallest level `i >= from` whose target is at least `work`, or `None`
/// when `work` exceeds the cap.
pub(crate) fn covering_level(
    floor: Duration,
    cap: Duration,
    from: u32,
    work: Duration,
) -> Option<u32> {
    if work > cap {
        return None;
    }
    let top = top_level(floor, cap);
    (from.min(top)..=top).find(|&i| level_target(floor, cap, i) >= work)
}

/// The next whole multiple of `cap` at or after `work` (at least one cap).
/// Saturates at `Duration::MAX` (a release that far away makes the pad's
/// deadline arithmetic fail, which it treats as a clock failure).
pub(crate) fn cap_grid(cap: Duration, work: Duration) -> Duration {
    let c = ns(cap).max(1);
    let k = ns(work).div_ceil(c).max(1);
    match k.checked_mul(c) {
        Some(n) => from_ns(n),
        None => Duration::MAX,
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn examples() {
        let us = Duration::from_micros;
        assert_eq!(top_level(us(10), us(10)), 0);
        assert_eq!(top_level(us(10), us(80)), 3);
        assert_eq!(top_level(us(10), us(100)), 4); // 10,20,40,80,100
        assert_eq!(level_target(us(10), us(100), 3), us(80));
        assert_eq!(level_target(us(10), us(100), 4), us(100));
        assert_eq!(level_target(us(10), us(100), 60), us(100));
        assert_eq!(covering_level(us(10), us(100), 0, us(35)), Some(2));
        assert_eq!(covering_level(us(10), us(100), 3, us(35)), Some(3));
        assert_eq!(covering_level(us(10), us(100), 0, us(101)), None);
        assert_eq!(cap_grid(us(100), us(101)), us(200));
        assert_eq!(cap_grid(us(100), us(0)), us(100));
        assert_eq!(
            top_level(Duration::from_micros(1), Duration::from_secs(10)),
            24
        );
    }

    proptest! {
        #[test]
        fn ladder_is_monotone_and_bounded(f in 1u64..10_000_000, c_mult in 1u64..5_000, i in 0u32..70) {
            let floor = Duration::from_nanos(f);
            let cap = Duration::from_nanos(f.saturating_mul(c_mult));
            let top = top_level(floor, cap);
            prop_assert!(level_target(floor, cap, 0) == floor);
            prop_assert!(level_target(floor, cap, top) == cap);
            let t = level_target(floor, cap, i);
            prop_assert!(t >= floor && t <= cap);
            prop_assert!(level_target(floor, cap, i + 1) >= t);
        }

        #[test]
        fn covering_is_smallest(f in 1u64..1_000_000, c_mult in 1u64..1_000, w in 0u64..2_000_000_000) {
            let floor = Duration::from_nanos(f);
            let cap = Duration::from_nanos(f.saturating_mul(c_mult));
            let work = Duration::from_nanos(w);
            match covering_level(floor, cap, 0, work) {
                None => prop_assert!(work > cap),
                Some(i) => {
                    prop_assert!(level_target(floor, cap, i) >= work);
                    if i > 0 {
                        prop_assert!(level_target(floor, cap, i - 1) < work);
                    }
                }
            }
            let g = cap_grid(cap, work);
            prop_assert!(g >= work && g >= cap);
            prop_assert_eq!(g.as_nanos() % cap.as_nanos(), 0);
        }
    }
}
