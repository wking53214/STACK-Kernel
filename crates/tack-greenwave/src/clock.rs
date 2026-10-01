//! Time, injected.
//!
//! The scheduling core never reads the system clock and never sleeps. It asks
//! a [`Clock`] what time it is, so tests can drive it with a
//! [`ManualClock`] and get the same answer every run. The tokio driver in
//! [`crate::driver`] supplies a real clock.
//!
//! Time is a plain count of nanoseconds since the clock's own origin
//! ([`Nanos`]). Epoch and phase boundaries are multiples of their lengths
//! measured from that origin, so two schedulers built on the same clock agree
//! on where every boundary is.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

/// Nanoseconds since the clock origin. Used for both instants and lengths.
///
/// A `u64` of nanoseconds covers about 584 years, so overflow only happens
/// with a broken or hostile clock; every sum in this crate is checked anyway.
pub type Nanos = u64;

/// A source of monotonic time.
///
/// Implementations must never go backwards. The scheduler checks this on
/// every call and halts if it sees time regress, because every fairness and
/// release guarantee is stated in terms of a monotonic clock.
pub trait Clock {
    /// Nanoseconds since this clock's origin.
    fn now(&self) -> Nanos;
}

/// A clock that only moves when told to. For tests and simulation.
///
/// Clones share one underlying time value, so a test can keep a clone and
/// advance the clock the scheduler is reading.
#[derive(Debug, Clone, Default)]
pub struct ManualClock {
    now: Arc<AtomicU64>,
}

impl ManualClock {
    /// A clock that reads `start`.
    #[must_use]
    pub fn new(start: Nanos) -> Self {
        Self {
            now: Arc::new(AtomicU64::new(start)),
        }
    }

    /// Set the time. Setting it backwards is allowed so tests can exercise
    /// the scheduler's clock-regression halt.
    pub fn set(&self, t: Nanos) {
        self.now.store(t, Ordering::SeqCst);
    }

    /// Move the time forward by `d`, saturating at `u64::MAX`.
    pub fn advance(&self, d: Nanos) {
        let cur = self.now.load(Ordering::SeqCst);
        self.now.store(cur.saturating_add(d), Ordering::SeqCst);
    }
}

impl Clock for ManualClock {
    fn now(&self) -> Nanos {
        self.now.load(Ordering::SeqCst)
    }
}
