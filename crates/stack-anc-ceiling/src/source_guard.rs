//! A per-source admission guard: a cap on requests in flight, and a cap on
//! failed checks per second, both keyed by a caller-supplied source key.
//!
//! The guard runs before the padded operation and never sees the candidate
//! value, so its decision depends only on the source key, the clock and the
//! counts. A refused request must still be padded to the same ceiling by the
//! caller, or the refusal itself becomes a timing signal.
//!
//! Sources share a fixed table of buckets, hashed with a random per-guard key
//! so an attacker cannot choose colliding sources. A collision can throttle an
//! innocent source that shares a bucket; `buckets` sets how often that happens.
//! Refused requests do not extend a cooldown, so spamming a source cannot keep
//! it locked out.

use std::collections::hash_map::RandomState;
use std::hash::{BuildHasher, Hasher};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};

use crate::clock::Clock;

/// Limits applied per source bucket.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct GuardConfig {
    /// Most requests from one bucket in flight at once.
    pub max_in_flight: u32,
    /// Failed checks a bucket may make in a burst, and the bucket's capacity.
    pub failure_burst: f64,
    /// Failed checks regained per second.
    pub failures_per_second: f64,
    /// How long a bucket is refused after it runs out of failed checks.
    pub cooldown: Duration,
    /// Number of buckets in the table.
    pub buckets: usize,
}

/// A configuration the guard cannot use.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GuardConfigError(pub &'static str);

#[derive(Debug, Clone, Copy, Default)]
struct Bucket {
    in_flight: u32,
    tokens: f64,
    last: Option<Instant>,
    cooling_until: Option<Instant>,
}

/// The outcome of [`SourceGuard::admit`].
#[must_use]
#[derive(Debug)]
pub enum Decision<'a> {
    /// The request may proceed. Dropping the permit frees its slot.
    Admit(Permit<'a>),
    /// The request is refused before any secret-dependent work.
    Refuse,
}

/// A slot held by one admitted request.
#[must_use]
#[derive(Debug)]
pub struct Permit<'a> {
    guard: &'a SourceGuard,
    idx: usize,
}

impl Drop for Permit<'_> {
    fn drop(&mut self) {
        let mut table = self.guard.lock();
        if let Some(b) = table.get_mut(self.idx) {
            b.in_flight = b.in_flight.saturating_sub(1);
        }
    }
}

/// The guard. Shareable across threads.
#[derive(Debug)]
pub struct SourceGuard {
    config: GuardConfig,
    clock: Arc<dyn Clock>,
    hasher: RandomState,
    table: Mutex<Vec<Bucket>>,
}

impl SourceGuard {
    /// Build a guard, refusing configurations that could never admit anything.
    pub fn new(config: GuardConfig, clock: Arc<dyn Clock>) -> Result<Self, GuardConfigError> {
        if config.max_in_flight == 0 {
            return Err(GuardConfigError("max_in_flight must be at least 1"));
        }
        if !(config.failure_burst >= 1.0 && config.failure_burst.is_finite()) {
            return Err(GuardConfigError("failure_burst must be at least 1"));
        }
        if !(config.failures_per_second > 0.0 && config.failures_per_second.is_finite()) {
            return Err(GuardConfigError("failures_per_second must be positive"));
        }
        if config.buckets == 0 {
            return Err(GuardConfigError("buckets must be at least 1"));
        }
        Ok(Self {
            config,
            clock,
            hasher: RandomState::new(),
            table: Mutex::new(vec![Bucket::default(); config.buckets]),
        })
    }

    fn lock(&self) -> MutexGuard<'_, Vec<Bucket>> {
        self.table.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn index(&self, source: &[u8]) -> usize {
        let mut h = self.hasher.build_hasher();
        h.write(source);
        (h.finish() % self.config.buckets as u64) as usize
    }

    /// Top up a bucket's failed-check tokens for the time since it was last touched.
    fn refill(&self, b: &mut Bucket, now: Instant) {
        match b.last {
            None => b.tokens = self.config.failure_burst,
            Some(last) => {
                let elapsed = now.saturating_duration_since(last).as_secs_f64();
                b.tokens = (b.tokens + elapsed * self.config.failures_per_second).min(self.config.failure_burst);
            }
        }
        b.last = Some(now);
    }

    /// Ask to admit a request from `source`. Refusals change nothing.
    pub fn admit(&self, source: &[u8]) -> Decision<'_> {
        let idx = self.index(source);
        let now = self.clock.now();
        let mut table = self.lock();
        let Some(b) = table.get_mut(idx) else {
            return Decision::Refuse;
        };
        if let Some(until) = b.cooling_until {
            if now < until {
                return Decision::Refuse;
            }
            b.cooling_until = None;
        }
        if b.in_flight >= self.config.max_in_flight {
            return Decision::Refuse;
        }
        b.in_flight += 1;
        Decision::Admit(Permit { guard: self, idx })
    }

    /// Record one failed check from `source`. When the source has no failed
    /// checks left, it enters cooldown and its tokens are reset for afterwards.
    pub fn record_failure(&self, source: &[u8]) {
        let idx = self.index(source);
        let now = self.clock.now();
        let mut table = self.lock();
        let Some(b) = table.get_mut(idx) else {
            return;
        };
        self.refill(b, now);
        if b.tokens >= 1.0 {
            b.tokens -= 1.0;
        } else {
            b.cooling_until = Some(now + self.config.cooldown);
            b.tokens = self.config.failure_burst;
        }
    }
}
