//! The monotonic clock the pad reads, behind a trait so tests can inject
//! a failing clock.

use std::fmt::Debug;
use std::time::Instant;

/// A monotonic clock. Implementations must be cheap and must not block:
/// the pad reads it at admission, at completion, and in its spin loop.
pub trait Clock: Send + Sync + Debug {
    /// The current instant.
    fn now(&self) -> Instant;
}

/// `std::time::Instant::now()`, which on Linux is
/// `clock_gettime(CLOCK_MONOTONIC)` through the vDSO.
#[derive(Debug, Clone, Copy, Default)]
pub struct MonotonicClock;

impl Clock for MonotonicClock {
    #[inline(always)]
    fn now(&self) -> Instant {
        Instant::now()
    }
}
