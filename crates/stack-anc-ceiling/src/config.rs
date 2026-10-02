//! Configuration: the ceiling, the wait mode, and every cap.
//!
//! Every field has a hard bound checked by [`CeilingConfig::validate`].
//! Out-of-bound values are rejected with [`ConfigError`], never clamped, so
//! a typo in a deployment file fails loudly at startup instead of quietly
//! weakening the padding.
//!
//! The ceiling itself has no default. A default ceiling that is too short
//! for the real operation would overrun on every request and leak through
//! the overrun buckets, so the operator must choose it for the operation
//! being protected. Everything else has a documented default.

use std::time::Duration;
use thiserror::Error;

/// Smallest accepted ceiling. Below this the clock read itself (about 20 to
/// 50 ns through the vDSO) is a large fraction of the window.
pub const MIN_CEILING: Duration = Duration::from_micros(1);
/// Largest accepted ceiling. Longer windows hold a concurrency slot for too
/// long to be a sensible request timeout.
pub const MAX_CEILING: Duration = Duration::from_secs(10);
/// Largest accepted spin tail (blocking or async).
pub const MAX_SPIN_TAIL: Duration = MAX_CEILING;
/// Largest accepted concurrency cap.
pub const MAX_CONCURRENT_LIMIT: usize = 65_536;
/// Largest accepted hard-ceiling multiple.
pub const MAX_HARD_CEILING_BUCKETS: u32 = 1_024;
/// Largest accepted [`CeilingConfig::retry_release_factor`].
pub const MAX_RETRY_RELEASE_FACTOR: u32 = 64;
/// Largest accepted spin budget rate or burst: 64 CPU seconds.
pub const MAX_SPIN_BUDGET: Duration = Duration::from_secs(64);
/// Largest accepted `max_input_len`: 64 MiB.
pub const MAX_INPUT_LEN_LIMIT: usize = 64 << 20;

/// Default spin tail for the blocking Hybrid mode. The tail must cover the
/// time `std::thread::sleep` wakes late, or Hybrid releases late. Measured
/// on the development machine (see [`WaitMode`]), blocking sleep was late
/// by p99 182 us to 295 us, so 250 us covers about the p99.
pub const DEFAULT_SPIN_TAIL: Duration = Duration::from_micros(250);
/// Default spin tail for the async Hybrid mode. Tokio's timer wheel has
/// millisecond resolution and rounds deadlines up, so the async tail must
/// be longer than one tick.
pub const DEFAULT_ASYNC_SPIN_TAIL: Duration = Duration::from_micros(2_500);
/// Default concurrency cap.
pub const DEFAULT_MAX_CONCURRENT: usize = 64;
/// Default hard-ceiling multiple: a response may be released at up to four
/// ceilings; beyond that the result is discarded and RETRY is returned.
pub const DEFAULT_HARD_CEILING_BUCKETS: u32 = 4;
/// Default retry release factor: a hard-overrun RETRY leaves at sixteen
/// hard ceilings after admission (see
/// [`CeilingConfig::retry_release_factor`]), so with the default
/// [`DEFAULT_HARD_CEILING_BUCKETS`] an overrunning request holds its slot
/// for 64 ceilings. Chosen so that work plus a drop of up to 16 hard
/// ceilings, including scheduler delays under CPU oversubscription, maps to
/// one release time. Lower it to trade that margin for capacity.
pub const DEFAULT_RETRY_RELEASE_FACTOR: u32 = 16;
/// Async API only: the earliest a hard-overrun RETRY may leave is the hard
/// ceiling plus this slack. Tokio's timer rounds deadlines up to a 1 ms
/// tick and polls the operation before the timer, so the moment the
/// operation is cancelled (or finishes late) can fall anywhere in about
/// 1 to 2 ms after the hard ceiling. Releasing no earlier than this covers
/// that spread, so it cannot pick the release window.
pub const ASYNC_TIMER_SLACK: Duration = Duration::from_millis(2);
/// Default spin budget rate: a quarter of one core.
pub const DEFAULT_SPIN_CPU_PER_SECOND: Duration = Duration::from_millis(250);
/// Default spin budget burst.
pub const DEFAULT_SPIN_BURST: Duration = Duration::from_millis(50);
/// Default input length cap for [`crate::CeilingPad::pad_input`]: 64 KiB.
pub const DEFAULT_MAX_INPUT_LEN: usize = 64 << 10;

/// How the pad waits from operation completion until the release time.
///
/// Precision and cost figures below were measured with
/// `cargo run --release -p stack-anc-ceiling --example verify` (defaults)
/// on the development machine: 4 vCPU Intel Xeon @ 2.80GHz VM, Linux, load
/// average 0.4 to 1.4 during the run, other builds possibly sharing the
/// host. They describe that machine only; rerun the example on the target
/// host before choosing a mode. "Late" is the observed release offset
/// minus the ceiling, over 2000 idle requests (500 for async). The pad
/// never releases early; lateness is the only error.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum WaitMode {
    /// Sleep until the release time (`std::thread::sleep`, or
    /// `tokio::time::sleep_until` in the async API).
    ///
    /// Cost: no CPU while waiting; measured 29 us of CPU per request at a
    /// 300 us ceiling (the wake-up and bookkeeping). Precision: inherits
    /// the scheduler's wake-up granularity. Measured, blocking, ceiling
    /// 300 us: late by p50 87 us, p99 182 us, p99.9 465 us. Async (tokio
    /// timer, 1 ms tick, rounds up), ceiling 5 ms: late by p50 1.14 ms,
    /// p99 1.99 ms. Side channel: the wake-up delay can be shifted by what
    /// the secret-dependent work left in caches and CPU frequency state;
    /// the verify example tests for that (not detected at 100000 per
    /// class).
    Sleep,
    /// Busy-wait on `Instant::now()` until the release time.
    ///
    /// Cost: one core at 100 percent for the whole remaining window;
    /// measured 300 us of CPU per request at a 300 us ceiling. Precision:
    /// the clock read, while the thread is not preempted. Measured,
    /// blocking, idle, ceiling 300 us: late by p50 0.08 us, p99 31 us,
    /// p99.9 319 us (the tail is preemption). Under CPU oversubscription
    /// preemption dominates: in the flood (8 threads, 4 CPUs) served Spin
    /// responses were late by p99 850 us, p99.9 4.0 ms. In the async API it
    /// blocks the executor worker thread.
    Spin,
    /// Sleep until the release time minus a spin tail, then spin the tail.
    ///
    /// Cost: at most the tail in spin CPU per request, plus the sleep
    /// overhead. Measured 101 us of CPU per request at a 300 us ceiling
    /// with a 150 us tail. Precision: as Spin when the sleep wakes before
    /// the tail starts, as Sleep otherwise. Measured, blocking, ceiling
    /// 300 us, tail 150 us: late by p50 0.11 us, p99 23 us, p99.9 89 us.
    /// Ceiling 1 ms with [`DEFAULT_SPIN_TAIL`]: p50 0.16 us, p99 126 us,
    /// p99.9 1.5 ms. Async, ceiling 5 ms, [`DEFAULT_ASYNC_SPIN_TAIL`]:
    /// p50 0.18 us, p99 479 us, p99.9 3.6 ms (tokio wake-ups that miss
    /// the tail).
    Hybrid,
}

impl WaitMode {
    /// Closed-set metric label.
    pub const fn label(self) -> &'static str {
        match self {
            WaitMode::Sleep => "sleep",
            WaitMode::Spin => "spin",
            WaitMode::Hybrid => "hybrid",
        }
    }
}

/// Limit on total spin CPU time across all requests.
///
/// Spin and Hybrid waits burn a core. Without a limit, a flood of cheap
/// requests turns the padding into a CPU denial of service. The budget is a
/// token bucket of spin nanoseconds: it refills at `cpu_per_second` and
/// holds at most `burst`. Each request reserves a FIXED charge at admission
/// (the ceiling for Spin, the tail for Hybrid), before any secret-dependent
/// work. If the bucket cannot cover the charge, the request waits in Sleep
/// mode instead. The charge never depends on how long the operation took,
/// and unused spin is never refunded, so the switch to Sleep depends only on
/// public load (how many requests arrived), never on a secret.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SpinBudgetConfig {
    /// A token bucket. Both fields must be positive and at most
    /// [`MAX_SPIN_BUDGET`].
    Limited {
        /// Refill rate: spin CPU time allowed per second of wall time.
        /// `250 ms` means a quarter of one core. Default
        /// [`DEFAULT_SPIN_CPU_PER_SECOND`].
        cpu_per_second: Duration,
        /// Bucket capacity: the largest burst of spin CPU time. Must be at
        /// least one request's charge, or spin is never granted. Default
        /// [`DEFAULT_SPIN_BURST`].
        burst: Duration,
    },
    /// No limit. Every Spin or Hybrid request spins. Only for experiments
    /// (the verify example uses it to show the cost). Do not use in a
    /// production profile: a flood then costs up to `max_concurrent` cores.
    Unlimited,
}

impl Default for SpinBudgetConfig {
    fn default() -> Self {
        SpinBudgetConfig::Limited {
            cpu_per_second: DEFAULT_SPIN_CPU_PER_SECOND,
            burst: DEFAULT_SPIN_BURST,
        }
    }
}

/// Full configuration of a [`crate::CeilingPad`].
///
/// Build with [`CeilingConfig::new`] (which fills every default) and
/// override fields with struct update syntax. No field can be influenced by
/// a request: the pad reads this struct only.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CeilingConfig {
    /// The release offset: every on-time response leaves exactly this long
    /// after admission. No default (see module docs). Bounds:
    /// [`MIN_CEILING`] ..= [`MAX_CEILING`].
    pub ceiling: Duration,
    /// How to wait. Default [`WaitMode::Hybrid`].
    pub mode: WaitMode,
    /// Hybrid spin tail for the blocking API. Default
    /// [`DEFAULT_SPIN_TAIL`]. Bounds: 0 ..= [`MAX_SPIN_TAIL`]. A tail longer
    /// than the ceiling acts as the ceiling (the whole window spins).
    pub spin_tail: Duration,
    /// Hybrid spin tail for the async API. Default
    /// [`DEFAULT_ASYNC_SPIN_TAIL`]. Same bounds.
    pub async_spin_tail: Duration,
    /// Spin CPU budget. Default [`SpinBudgetConfig::Limited`] with the
    /// defaults above.
    pub spin_budget: SpinBudgetConfig,
    /// Most requests padded at once. Beyond it, requests are shed at
    /// admission with RETRY. Default [`DEFAULT_MAX_CONCURRENT`]. Bounds:
    /// 1 ..= [`MAX_CONCURRENT_LIMIT`].
    pub max_concurrent: usize,
    /// Hard ceiling as a multiple of `ceiling`. A result that completes
    /// after `ceiling * k` for `k` up to this value is released at the next
    /// multiple of the ceiling (and counted as an overrun). Beyond it the
    /// result is discarded and RETRY is returned. Default
    /// [`DEFAULT_HARD_CEILING_BUCKETS`]. Bounds: 1 ..=
    /// [`MAX_HARD_CEILING_BUCKETS`]. `1` means every overrun is a RETRY.
    pub hard_ceiling_buckets: u32,
    /// Where a hard-overrun RETRY is released, as a multiple of the hard
    /// ceiling. The retry window is `W = hard_ceiling * retry_release_factor`.
    /// The discarded value (or cancelled future) is dropped first, then the
    /// RETRY leaves at the first whole multiple of `W` after admission that
    /// is at or after that drop finished (async API: and at or after the
    /// hard ceiling plus [`ASYNC_TIMER_SLACK`]). Any work plus drop that
    /// ends inside the first window therefore gets one release time. The
    /// cost: an overrunning request holds its slot and thread (blocking)
    /// or task (async) until `W`. Default [`DEFAULT_RETRY_RELEASE_FACTOR`].
    /// Bounds: 1 ..= [`MAX_RETRY_RELEASE_FACTOR`].
    pub retry_release_factor: u32,
    /// Largest input accepted by [`crate::CeilingPad::pad_input`]. Longer
    /// inputs are rejected before admission. Default
    /// [`DEFAULT_MAX_INPUT_LEN`]. Bounds: 0 ..= [`MAX_INPUT_LEN_LIMIT`].
    pub max_input_len: usize,
}

impl CeilingConfig {
    /// Every default, with the given ceiling.
    pub fn new(ceiling: Duration) -> Self {
        Self {
            ceiling,
            mode: WaitMode::Hybrid,
            spin_tail: DEFAULT_SPIN_TAIL,
            async_spin_tail: DEFAULT_ASYNC_SPIN_TAIL,
            spin_budget: SpinBudgetConfig::default(),
            max_concurrent: DEFAULT_MAX_CONCURRENT,
            hard_ceiling_buckets: DEFAULT_HARD_CEILING_BUCKETS,
            retry_release_factor: DEFAULT_RETRY_RELEASE_FACTOR,
            max_input_len: DEFAULT_MAX_INPUT_LEN,
        }
    }

    /// The fixed spin charge one request reserves from the budget in the
    /// blocking API: the ceiling for Spin, the tail (at most the ceiling)
    /// for Hybrid, zero for Sleep.
    pub fn spin_charge(&self) -> Duration {
        charge(self.mode, self.ceiling, self.spin_tail)
    }

    /// The same for the async API (uses `async_spin_tail`).
    pub fn async_spin_charge(&self) -> Duration {
        charge(self.mode, self.ceiling, self.async_spin_tail)
    }

    /// The hard ceiling: `ceiling * hard_ceiling_buckets`, or `None` if
    /// that does not fit in a `Duration` (rejected by `validate`).
    pub fn hard_ceiling(&self) -> Option<Duration> {
        self.ceiling.checked_mul(self.hard_ceiling_buckets)
    }

    /// The retry window: `hard_ceiling * retry_release_factor`, or `None`
    /// on overflow (rejected by `validate`).
    pub fn retry_window(&self) -> Option<Duration> {
        self.hard_ceiling()?.checked_mul(self.retry_release_factor)
    }

    /// Check every bound. Called by [`crate::CeilingPad::new`].
    pub fn validate(&self) -> Result<(), ConfigError> {
        let bad = |field, reason| Err(ConfigError { field, reason });
        if self.ceiling < MIN_CEILING {
            return bad("ceiling", "below MIN_CEILING");
        }
        if self.ceiling > MAX_CEILING {
            return bad("ceiling", "above MAX_CEILING");
        }
        if self.spin_tail > MAX_SPIN_TAIL {
            return bad("spin_tail", "above MAX_SPIN_TAIL");
        }
        if self.async_spin_tail > MAX_SPIN_TAIL {
            return bad("async_spin_tail", "above MAX_SPIN_TAIL");
        }
        if self.max_concurrent == 0 {
            return bad("max_concurrent", "must be at least 1");
        }
        if self.max_concurrent > MAX_CONCURRENT_LIMIT {
            return bad("max_concurrent", "above MAX_CONCURRENT_LIMIT");
        }
        if self.hard_ceiling_buckets == 0 {
            return bad("hard_ceiling_buckets", "must be at least 1");
        }
        if self.hard_ceiling_buckets > MAX_HARD_CEILING_BUCKETS {
            return bad("hard_ceiling_buckets", "above MAX_HARD_CEILING_BUCKETS");
        }
        if self.hard_ceiling().is_none() {
            return bad("hard_ceiling_buckets", "ceiling times buckets overflows");
        }
        if self.retry_release_factor == 0 {
            return bad("retry_release_factor", "must be at least 1");
        }
        if self.retry_release_factor > MAX_RETRY_RELEASE_FACTOR {
            return bad("retry_release_factor", "above MAX_RETRY_RELEASE_FACTOR");
        }
        if self.retry_window().is_none() {
            return bad(
                "retry_release_factor",
                "hard ceiling times factor overflows",
            );
        }
        if self.max_input_len > MAX_INPUT_LEN_LIMIT {
            return bad("max_input_len", "above MAX_INPUT_LEN_LIMIT");
        }
        if let SpinBudgetConfig::Limited {
            cpu_per_second,
            burst,
        } = self.spin_budget
        {
            if cpu_per_second.is_zero() || burst.is_zero() {
                return bad(
                    "spin_budget",
                    "rate and burst must be positive; use WaitMode::Sleep for no spin",
                );
            }
            if cpu_per_second > MAX_SPIN_BUDGET || burst > MAX_SPIN_BUDGET {
                return bad("spin_budget", "above MAX_SPIN_BUDGET");
            }
            let largest_charge = self.spin_charge().max(self.async_spin_charge());
            if burst < largest_charge {
                return bad(
                    "spin_budget",
                    "burst is smaller than one request's spin charge, so spin would never be granted",
                );
            }
        }
        Ok(())
    }
}

fn charge(mode: WaitMode, ceiling: Duration, tail: Duration) -> Duration {
    match mode {
        WaitMode::Sleep => Duration::ZERO,
        WaitMode::Spin => ceiling,
        WaitMode::Hybrid => tail.min(ceiling),
    }
}

/// A configuration field out of bounds. Raised once at construction, never
/// per request.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
#[error("invalid ceiling config: {field}: {reason}")]
pub struct ConfigError {
    /// The offending field.
    pub field: &'static str,
    /// Why it was rejected.
    pub reason: &'static str,
}
