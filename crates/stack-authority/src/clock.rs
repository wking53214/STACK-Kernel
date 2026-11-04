//! Wall-clock time in Unix milliseconds, injectable for tests. Same shape
//! as `stack_trident::Clock`, so one adapter can serve both crates at the
//! integration step; this crate does not depend on stack-trident.
//!
//! The verifier trusts the clock it is given. Every window check (issuer
//! key, capability) and the use store's expiry pruning read it, so a
//! clock that can be moved by an attacker moves the boundary.

use std::fmt;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

/// A source of Unix time in milliseconds.
pub trait Clock: Send + Sync + fmt::Debug {
    /// Milliseconds since the Unix epoch.
    fn now_unix_ms(&self) -> u64;
}

/// The system wall clock.
///
/// A clock set before 1970 reads as 0, which is before every window:
/// everything is then not yet valid, so the boundary fails closed.
#[derive(Debug, Clone, Copy, Default)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now_unix_ms(&self) -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
            .unwrap_or(0)
    }
}

/// A clock that only moves when told to. For tests and simulations.
#[derive(Debug, Default)]
pub struct ManualClock(AtomicU64);

impl ManualClock {
    /// A clock reading `ms`.
    pub fn new(ms: u64) -> Self {
        Self(AtomicU64::new(ms))
    }

    /// Sets the reading.
    pub fn set(&self, ms: u64) {
        self.0.store(ms, Ordering::SeqCst);
    }

    /// Moves the reading forward by `ms`, saturating.
    pub fn advance(&self, ms: u64) {
        let _ = self
            .0
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |v| Some(v.saturating_add(ms)));
    }
}

impl Clock for ManualClock {
    fn now_unix_ms(&self) -> u64 {
        self.0.load(Ordering::SeqCst)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn manual_clock_moves_only_when_told() {
        let c = ManualClock::new(10);
        assert_eq!(c.now_unix_ms(), 10);
        c.advance(5);
        assert_eq!(c.now_unix_ms(), 15);
        c.set(3);
        assert_eq!(c.now_unix_ms(), 3);
        c.advance(u64::MAX);
        assert_eq!(c.now_unix_ms(), u64::MAX);
        assert!(SystemClock.now_unix_ms() > 1_600_000_000_000);
    }
}
