//! Shared test helpers.
#![allow(dead_code, clippy::unwrap_used)]

use metrics_util::debugging::DebugValue;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};
use sstack_anc_adaptive::Clock;

pub fn us(n: u64) -> Duration {
    Duration::from_micros(n)
}

pub fn ms(n: u64) -> Duration {
    Duration::from_millis(n)
}

/// Busy-wait for `d` (a stand-in for CPU-bound secret-dependent work).
pub fn spin_for(d: Duration) {
    let end = Instant::now() + d;
    while Instant::now() < end {
        std::hint::spin_loop();
    }
}

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

pub type Snap = Vec<(
    metrics_util::CompositeKey,
    Option<metrics::Unit>,
    Option<metrics::SharedString>,
    DebugValue,
)>;

/// The value of the metric `name` whose labels include all of `labels`.
pub fn find<'s>(snap: &'s Snap, name: &str, labels: &[(&str, &str)]) -> Option<&'s DebugValue> {
    snap.iter()
        .find(|(k, _, _, _)| {
            let key = k.key();
            key.name() == name
                && labels
                    .iter()
                    .all(|(lk, lv)| key.labels().any(|l| l.key() == *lk && l.value() == *lv))
        })
        .map(|(_, _, _, v)| v)
}

pub fn counter(snap: &Snap, name: &str, labels: &[(&str, &str)]) -> u64 {
    match find(snap, name, labels) {
        Some(DebugValue::Counter(n)) => *n,
        _ => 0,
    }
}

pub fn gauge(snap: &Snap, name: &str, labels: &[(&str, &str)]) -> Option<f64> {
    match find(snap, name, labels) {
        Some(DebugValue::Gauge(g)) => Some(g.into_inner()),
        _ => None,
    }
}
