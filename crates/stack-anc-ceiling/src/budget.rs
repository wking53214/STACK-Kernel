//! The spin CPU budget: a token bucket of spin nanoseconds.
//!
//! One bucket is shared by every request of a pad. A request reserves a
//! fixed charge at admission; if the bucket holds less than that, the
//! request falls back to Sleep. See [`crate::SpinBudgetConfig`] for why the
//! charge is fixed and never refunded.

use crate::config::SpinBudgetConfig;
use std::sync::Mutex;
use std::time::{Duration, Instant};

const NANOS_PER_SEC: u128 = 1_000_000_000;

#[derive(Debug)]
struct Bucket {
    tokens_ns: u64,
    last: Instant,
}

/// Shared spin budget.
#[derive(Debug)]
pub(crate) struct SpinBudget {
    /// `None` for [`SpinBudgetConfig::Unlimited`].
    limited: Option<Limits>,
    bucket: Mutex<Bucket>,
}

#[derive(Debug, Clone, Copy)]
struct Limits {
    rate_ns_per_sec: u64,
    capacity_ns: u64,
}

fn nanos_u64(d: Duration) -> u64 {
    u64::try_from(d.as_nanos()).unwrap_or(u64::MAX)
}

impl SpinBudget {
    /// A bucket that starts full.
    pub(crate) fn new(config: SpinBudgetConfig, now: Instant) -> Self {
        let limited = match config {
            SpinBudgetConfig::Limited {
                cpu_per_second,
                burst,
            } => Some(Limits {
                rate_ns_per_sec: nanos_u64(cpu_per_second),
                capacity_ns: nanos_u64(burst),
            }),
            SpinBudgetConfig::Unlimited => None,
        };
        let tokens_ns = limited.map_or(0, |l| l.capacity_ns);
        Self {
            limited,
            bucket: Mutex::new(Bucket {
                tokens_ns,
                last: now,
            }),
        }
    }

    /// Try to take `charge` from the bucket at time `now`. Returns true if
    /// granted. A zero charge is always granted. Unlimited always grants.
    ///
    /// The lock is held for a few arithmetic operations only. Under a flood
    /// the wait for it grows with the number of concurrent admissions,
    /// which is public load, not a secret.
    pub(crate) fn try_reserve(&self, charge: Duration, now: Instant) -> bool {
        let Some(limits) = self.limited else {
            return true;
        };
        let charge_ns = nanos_u64(charge);
        if charge_ns == 0 {
            return true;
        }
        // A poisoned lock only means another thread panicked while holding
        // it; the two integers inside are still consistent (every update is
        // a plain assignment), so keep going rather than fail every request.
        let mut b = self.bucket.lock().unwrap_or_else(|e| e.into_inner());
        // Refill. `saturating_duration_since` treats a clock that moved
        // backwards as zero elapsed, which only ever under-fills.
        let elapsed = now.saturating_duration_since(b.last);
        if now > b.last {
            b.last = now;
        }
        let add = elapsed
            .as_nanos()
            .saturating_mul(u128::from(limits.rate_ns_per_sec))
            / NANOS_PER_SEC;
        let add = u64::try_from(add).unwrap_or(u64::MAX);
        b.tokens_ns = b.tokens_ns.saturating_add(add).min(limits.capacity_ns);
        if b.tokens_ns >= charge_ns {
            b.tokens_ns -= charge_ns;
            true
        } else {
            false
        }
    }

    /// Tokens currently in the bucket, without refilling. `None` when
    /// unlimited. For tests and diagnostics.
    pub(crate) fn tokens(&self) -> Option<Duration> {
        self.limited?;
        let b = self.bucket.lock().unwrap_or_else(|e| e.into_inner());
        Some(Duration::from_nanos(b.tokens_ns))
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    fn limited(rate_ms: u64, burst_ms: u64) -> SpinBudgetConfig {
        SpinBudgetConfig::Limited {
            cpu_per_second: Duration::from_millis(rate_ms),
            burst: Duration::from_millis(burst_ms),
        }
    }

    #[test]
    fn drains_then_refuses_then_refills() {
        let t0 = Instant::now();
        let b = SpinBudget::new(limited(100, 10), t0);
        let c = Duration::from_millis(4);
        assert!(b.try_reserve(c, t0));
        assert!(b.try_reserve(c, t0));
        assert!(!b.try_reserve(c, t0)); // 2 ms left
        assert_eq!(b.tokens(), Some(Duration::from_millis(2)));
        // 20 ms of wall time at 100 ms/s refills 2 ms: 4 ms total.
        let t1 = t0 + Duration::from_millis(20);
        assert!(b.try_reserve(c, t1));
        assert_eq!(b.tokens(), Some(Duration::ZERO));
        // Refill is capped at the burst.
        let t2 = t1 + Duration::from_secs(100);
        assert!(b.try_reserve(Duration::ZERO, t2));
        assert!(b.try_reserve(c, t2));
        assert_eq!(b.tokens(), Some(Duration::from_millis(6)));
    }

    #[test]
    fn backwards_clock_does_not_refill() {
        let t0 = Instant::now() + Duration::from_secs(1);
        let b = SpinBudget::new(limited(1_000, 5), t0);
        assert!(b.try_reserve(Duration::from_millis(5), t0));
        let earlier = t0 - Duration::from_millis(500);
        assert!(!b.try_reserve(Duration::from_millis(1), earlier));
    }

    #[test]
    fn unlimited_always_grants() {
        let b = SpinBudget::new(SpinBudgetConfig::Unlimited, Instant::now());
        for _ in 0..1_000 {
            assert!(b.try_reserve(Duration::from_secs(1), Instant::now()));
        }
        assert_eq!(b.tokens(), None);
    }
}
