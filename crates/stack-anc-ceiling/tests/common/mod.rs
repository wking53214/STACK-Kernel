//! Shared test helpers.
#![allow(dead_code, clippy::unwrap_used)]

use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};
use sstack_anc_ceiling::Clock;

/// Real monotonic time, except that call number `trip_at` (0-based)
/// returns a time one second in the past: a clock that went backwards.
#[derive(Debug)]
pub struct BackwardsOnce {
    pub calls: AtomicUsize,
    pub trip_at: usize,
}

impl BackwardsOnce {
    pub fn new(trip_at: usize) -> Self {
        Self {
            calls: AtomicUsize::new(0),
            trip_at,
        }
    }
}

impl Clock for BackwardsOnce {
    fn now(&self) -> Instant {
        let n = self.calls.fetch_add(1, Ordering::SeqCst);
        let t = Instant::now();
        if n == self.trip_at {
            t.checked_sub(Duration::from_secs(1)).unwrap()
        } else {
            t
        }
    }
}

/// Median of a slice (sorts a copy).
pub fn median(xs: &[Duration]) -> Duration {
    let mut v = xs.to_vec();
    v.sort();
    v[v.len() / 2]
}

/// Poll `cond` every 100 us, at most `max_polls` times.
pub fn wait_for(mut cond: impl FnMut() -> bool, max_polls: u32) -> bool {
    for _ in 0..max_polls {
        if cond() {
            return true;
        }
        std::thread::sleep(Duration::from_micros(100));
    }
    cond()
}
