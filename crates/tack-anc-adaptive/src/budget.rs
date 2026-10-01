//! The spin CPU budget: a token bucket of spin nanoseconds (the same design
//! as strategy 1, `tack-anc-ceiling`).
//!
//! One bucket is shared by every request of a pad. A Hybrid request
//! reserves a fixed charge (the spin tail) at admission; if the bucket
//! holds less than that, the request sleeps instead. See
//! [`crate::SpinBudgetConfig`] for why the charge is fixed and never
//! refunded.

use crate::config::SpinBudgetConfig;
use std::sync::Mutex;
use std::time::{Duration, Instant};

const NANOS_PER_SEC: u128 = 1_000_000_000;

#[derive(Debug)]
struct Bucket {
    tokens_ns: u64,
    last: Instant,
}

#[derive(Debug, Clone, Copy)]
struct Limits {
    rate_ns_per_sec: u64,
    capacity_ns: u64,
}

/// Shared spin budget.
#[derive(Debug)]
pub(crate) struct SpinBudget {
    /// `None` for [`SpinBudgetConfig::Unlimited`].
    limited: Option<Limits>,
    bucket: Mutex<Bucket>,
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

    /// Try to take `charge` from the bucket at time `now`. A zero charge and
    /// an unlimited budget always grant. The lock is held for a few
    /// arithmetic operations; under a flood the wait for it grows with the
    /// number of concurrent admissions, which is public load.
    pub(crate) fn try_reserve(&self, charge: Duration, now: Instant) -> bool {
        let Some(limits) = self.limited else {
            return true;
        };
        let charge_ns = nanos_u64(charge);
        if charge_ns == 0 {
            return true;
        }
        // A poisoned lock only means another thread panicked while holding
        // it; the two fields are updated by plain assignments, so they are
        // still consistent.
        let mut b = self.bucket.lock().unwrap_or_else(|e| e.into_inner());
        // A clock that moved backwards counts as zero elapsed time, which
        // only ever under-fills.
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

    /// Tokens in the bucket, without refilling. `None` when unlimited.
    pub(crate) fn tokens(&self) -> Option<Duration> {
        self.limited?;
        let b = self.bucket.lock().unwrap_or_else(|e| e.into_inner());
        Some(Duration::from_nanos(b.tokens_ns))
    }
}

#[cfg(test)]
mod tests {
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
        assert!(!b.try_reserve(c, t0));
        assert_eq!(b.tokens(), Some(Duration::from_millis(2)));
        // 20 ms at 100 ms/s refills 2 ms: 4 ms in the bucket.
        let t1 = t0 + Duration::from_millis(20);
        assert!(b.try_reserve(c, t1));
        assert_eq!(b.tokens(), Some(Duration::ZERO));
        let t2 = t1 + Duration::from_secs(100);
        assert!(b.try_reserve(c, t2));
        assert_eq!(b.tokens(), Some(Duration::from_millis(6)));
    }

    #[test]
    fn unlimited_always_grants() {
        let b = SpinBudget::new(SpinBudgetConfig::Unlimited, Instant::now());
        assert!(b.try_reserve(Duration::from_secs(1), Instant::now()));
        assert_eq!(b.tokens(), None);
    }
}
