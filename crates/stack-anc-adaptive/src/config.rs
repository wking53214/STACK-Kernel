//! Configuration: the padding mechanics shared by both controllers, and one
//! config struct per controller.
//!
//! Every field has a hard bound checked by a `validate` method.
//! Out-of-bound values are rejected with [`ConfigError`], never clamped, so
//! a typo in a deployment file fails loudly at startup instead of quietly
//! weakening the padding.
//!
//! The target cap has no default. A cap that is too low for the real
//! operation would make every request overrun, and a cap that is too high
//! turns a slow flood into a latency denial of service, so the operator
//! must choose it for the operation being protected. Everything else has a
//! documented default.

use std::time::Duration;
use thiserror::Error;

/// Smallest accepted target, floor or cap. Below this the clock read itself
/// (about 20 to 50 ns through the vDSO) is a large fraction of the window.
pub const MIN_TARGET: Duration = Duration::from_micros(1);
/// Largest accepted target cap. Longer windows hold a concurrency slot for
/// too long to be a sensible request timeout.
pub const MAX_TARGET: Duration = Duration::from_secs(10);
/// Largest accepted Hybrid spin tail.
pub const MAX_SPIN_TAIL: Duration = MAX_TARGET;
/// Largest accepted concurrency cap.
pub const MAX_CONCURRENT_LIMIT: usize = 65_536;
/// Largest accepted spin budget rate or burst: 64 CPU seconds.
pub const MAX_SPIN_BUDGET: Duration = Duration::from_secs(64);
/// Largest accepted `max_input_len`: 64 MiB.
pub const MAX_INPUT_LEN_LIMIT: usize = 64 << 20;
/// Largest accepted naive window, in samples. The window ring and its
/// sorted copy are allocated once at construction: at most
/// 2 * 65_536 * 8 bytes = 1 MiB. Each observation updates the sorted copy
/// with two binary searches and two in-place moves (at most 512 KiB of
/// memmove at this size), never a full sort.
pub const MAX_WINDOW: usize = 65_536;
/// Shortest accepted epoch or leak-accounting window.
pub const MIN_EPOCH: Duration = Duration::from_millis(1);
/// Longest accepted epoch.
pub const MAX_EPOCH: Duration = Duration::from_secs(3_600);
/// Longest accepted leak-accounting window.
pub const MAX_LEAK_WINDOW: Duration = Duration::from_secs(86_400);
/// Largest accepted leak budget, in bits per window.
pub const MAX_LEAK_BUDGET_BITS: f64 = 1.0e6;
/// Largest accepted lifetime budget, in whole window budgets.
pub const MAX_LEAK_LIFETIME_WINDOWS: u32 = 1_000_000;

/// Default Hybrid spin tail. Chosen from the sleep overshoot measured for
/// strategy 1 on the development machine (p99.9 about 114 us): the tail must
/// cover the time `std::thread::sleep` wakes late, or Hybrid releases late.
pub const DEFAULT_SPIN_TAIL: Duration = Duration::from_micros(250);
/// Default concurrency cap.
pub const DEFAULT_MAX_CONCURRENT: usize = 64;
/// Default spin budget rate: a quarter of one core.
pub const DEFAULT_SPIN_CPU_PER_SECOND: Duration = Duration::from_millis(250);
/// Default spin budget burst.
pub const DEFAULT_SPIN_BURST: Duration = Duration::from_millis(50);
/// Default input length cap for [`crate::AdaptivePad::pad_input`]: 64 KiB.
pub const DEFAULT_MAX_INPUT_LEN: usize = 64 << 10;
/// Default naive window: the last 256 operation times.
pub const DEFAULT_WINDOW: usize = 256;
/// Default naive percentile: p99 (990 per mille).
pub const DEFAULT_PERCENTILE_PERMILLE: u16 = 990;
/// Default naive margin added to the window statistic.
pub const DEFAULT_MARGIN: Duration = Duration::from_micros(10);
/// Default epoch length: one second of wall time.
pub const DEFAULT_EPOCH: Duration = Duration::from_secs(1);
/// Default leak budget: 128 bits per accounting window.
pub const DEFAULT_LEAK_BUDGET_BITS: f64 = 128.0;
/// Default leak-accounting window: 60 seconds of wall time.
pub const DEFAULT_LEAK_WINDOW: Duration = Duration::from_secs(60);
/// Default lifetime budget, in whole window budgets: with the defaults,
/// 8 * 128 = 1024 bits between operator resets.
pub const DEFAULT_LEAK_LIFETIME_WINDOWS: u32 = 8;

/// How the pad waits from operation completion until the release time.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum WaitMode {
    /// Sleep until the release time (`std::thread::sleep`). The default.
    ///
    /// Cost: no CPU while waiting. Precision: the scheduler's wake-up
    /// granularity (on Linux the default timer slack is 50 us, so wake-ups
    /// are typically tens of microseconds late). Side channel: the wake-up
    /// delay can be shifted slightly by cache and frequency state that the
    /// secret-dependent work left behind; the verify example measures it.
    #[default]
    Sleep,
    /// Sleep until the release time minus the spin tail, then busy-wait the
    /// tail. Each request reserves the tail from the shared spin budget at
    /// admission; when the budget is empty the request sleeps instead.
    ///
    /// Cost: at most the tail in CPU per request, and at most the budget
    /// rate across all requests. Precision: tens of nanoseconds when the
    /// sleep wakes before the tail starts. The tail must exceed the host's
    /// sleep overshoot, or releases are late by the difference.
    ///
    /// A Hybrid request is planned as if its work took `work + spin_tail`,
    /// so the target must leave room for the tail: every released request
    /// finishes its work before `release - spin_tail`, sleeps, then spins.
    /// Without that rule, a request whose work ends inside the tail window
    /// skips the sleep; whether it slept then depends on the secret, and a
    /// sleep leaves the post-release path measurably slower (about 0.9 us,
    /// KS D 0.69 between classes, on the development host).
    Hybrid,
}

impl WaitMode {
    /// Closed-set metric label.
    pub const fn label(self) -> &'static str {
        match self {
            WaitMode::Sleep => "sleep",
            WaitMode::Hybrid => "hybrid",
        }
    }
}

/// Limit on total spin CPU time across all requests of one pad.
///
/// A token bucket of spin nanoseconds: it refills at `cpu_per_second` and
/// holds at most `burst`. Each Hybrid request reserves a FIXED charge (the
/// spin tail) at admission, before any secret-dependent work. If the bucket
/// cannot cover it, the request sleeps instead. The charge never depends on
/// how long the operation took and is never refunded, so the switch to
/// Sleep depends only on public load (how many requests arrived).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SpinBudgetConfig {
    /// A token bucket. Both fields must be positive and at most
    /// [`MAX_SPIN_BUDGET`].
    Limited {
        /// Refill rate: spin CPU time allowed per second of wall time.
        /// Default [`DEFAULT_SPIN_CPU_PER_SECOND`].
        cpu_per_second: Duration,
        /// Bucket capacity: the largest burst of spin CPU time. Must be at
        /// least one request's charge. Default [`DEFAULT_SPIN_BURST`].
        burst: Duration,
    },
    /// No limit. Only for experiments; never in a production profile, where
    /// a flood would then cost up to `max_concurrent` cores.
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

/// Shortest accepted slot-scaling window.
pub const MIN_REACTION_DELAY: Duration = Duration::from_millis(1);
/// Longest accepted slot-scaling window.
pub const MAX_REACTION_DELAY: Duration = Duration::from_secs(3_600);
/// Longest accepted spillway wait.
pub const MAX_SPILLWAY_WAIT: Duration = Duration::from_secs(10);
/// Default slot-scaling window.
pub const DEFAULT_REACTION_DELAY: Duration = Duration::from_secs(1);
/// Default quiet windows in a row before slots close again.
pub const DEFAULT_COOLDOWN_WINDOWS: u32 = 10;

/// Extra slots that open on backlog, and a small waiting area.
///
/// Both are off by default, so a pad behaves as before until an operator
/// turns them on. Neither looks at how long any request took: they use only
/// when requests arrived, which the sender already controls and sees.
///
/// * **More slots.** With `max_slots` above `max_concurrent`, the pad opens
///   `step` more slots after any window of `reaction_delay` in which an
///   arrival found every open slot held, and closes `step` after
///   `cooldown_windows` quiet windows in a row. It never goes below
///   `max_concurrent` or above `max_slots`.
/// * **Spillway.** With `spillway_size` above zero, up to that many
///   arrivals that find every slot held wait exactly `spillway_wait` and
///   try once more. The wait is the same for every request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SlotScaling {
    /// Most slots that may be open. `0` means the same as
    /// `max_concurrent`: no scaling. Otherwise at least `max_concurrent`
    /// and at most [`MAX_CONCURRENT_LIMIT`].
    pub max_slots: usize,
    /// Slots opened or closed at a time. Default 1. Bounds: 1 ..=
    /// [`MAX_CONCURRENT_LIMIT`].
    pub step: usize,
    /// Window length, and so the shortest time between changes. Default
    /// [`DEFAULT_REACTION_DELAY`]. Bounds: [`MIN_REACTION_DELAY`] ..=
    /// [`MAX_REACTION_DELAY`].
    pub reaction_delay: Duration,
    /// Quiet windows in a row before `step` slots close. Default
    /// [`DEFAULT_COOLDOWN_WINDOWS`]. At least 1.
    pub cooldown_windows: u32,
    /// Places in the waiting area. Default 0 (no spillway). Bounds: 0 ..=
    /// [`MAX_CONCURRENT_LIMIT`].
    pub spillway_size: usize,
    /// The fixed wait. Default zero. Required positive, and at most
    /// [`MAX_SPILLWAY_WAIT`], when `spillway_size` is above zero.
    pub spillway_wait: Duration,
}

impl Default for SlotScaling {
    fn default() -> Self {
        Self {
            max_slots: 0,
            step: 1,
            reaction_delay: DEFAULT_REACTION_DELAY,
            cooldown_windows: DEFAULT_COOLDOWN_WINDOWS,
            spillway_size: 0,
            spillway_wait: Duration::ZERO,
        }
    }
}

impl SlotScaling {
    /// The most slots that can be open for a pad with `base` slots.
    pub fn effective_max(&self, base: usize) -> usize {
        if self.max_slots == 0 {
            base
        } else {
            self.max_slots
        }
    }

    /// Check every bound against the pad's `max_concurrent`.
    pub fn validate(&self, base: usize) -> Result<(), ConfigError> {
        let err = |field, reason| Err(ConfigError { field, reason });
        if self.max_slots != 0 {
            if self.max_slots < base {
                return err("scaling.max_slots", "below max_concurrent");
            }
            if self.max_slots > MAX_CONCURRENT_LIMIT {
                return err("scaling.max_slots", "above MAX_CONCURRENT_LIMIT");
            }
            if self.step == 0 || self.step > MAX_CONCURRENT_LIMIT {
                return err("scaling.step", "must be 1 ..= MAX_CONCURRENT_LIMIT");
            }
            if self.reaction_delay < MIN_REACTION_DELAY {
                return err("scaling.reaction_delay", "below MIN_REACTION_DELAY");
            }
            if self.reaction_delay > MAX_REACTION_DELAY {
                return err("scaling.reaction_delay", "above MAX_REACTION_DELAY");
            }
            if self.cooldown_windows == 0 {
                return err("scaling.cooldown_windows", "must be at least 1");
            }
        }
        if self.spillway_size > MAX_CONCURRENT_LIMIT {
            return err("scaling.spillway_size", "above MAX_CONCURRENT_LIMIT");
        }
        if self.spillway_size > 0 {
            if self.spillway_wait.is_zero() {
                return err("scaling.spillway_wait", "must be positive with a spillway");
            }
            if self.spillway_wait > MAX_SPILLWAY_WAIT {
                return err("scaling.spillway_wait", "above MAX_SPILLWAY_WAIT");
            }
        }
        Ok(())
    }
}

/// Padding mechanics shared by both controllers: how to wait, and the
/// admission limits. No field can be influenced by a request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PadConfig {
    /// How to wait. Default [`WaitMode::Sleep`].
    pub mode: WaitMode,
    /// Hybrid spin tail. Default [`DEFAULT_SPIN_TAIL`]. Bounds:
    /// 0 ..= [`MAX_SPIN_TAIL`], and in Hybrid mode strictly below the
    /// controller's cap (checked when the pad is built: a Hybrid request is
    /// planned as `work + spin_tail`, so a tail at or above the cap would
    /// turn every spin-granted request into an overrun RETRY). A tail at or
    /// above the epoch floor is accepted with a warning: every spin-granted
    /// request then escalates until the level covers the tail.
    pub spin_tail: Duration,
    /// Spin CPU budget. Default [`SpinBudgetConfig::Limited`] with the
    /// defaults above.
    pub spin_budget: SpinBudgetConfig,
    /// Most requests padded at once. Beyond it, requests are shed at
    /// admission with RETRY, before any secret-dependent work. Default
    /// [`DEFAULT_MAX_CONCURRENT`]. Bounds: 1 ..= [`MAX_CONCURRENT_LIMIT`].
    pub max_concurrent: usize,
    /// Largest input accepted by [`crate::AdaptivePad::pad_input`]. Default
    /// [`DEFAULT_MAX_INPUT_LEN`]. Bounds: 0 ..= [`MAX_INPUT_LEN_LIMIT`].
    pub max_input_len: usize,
    /// Allow [`crate::AdaptivePad::naive`]. Default `false`. The naive
    /// controller releases a slow request at completion, so its response
    /// time is the raw, secret-dependent work time. It exists to measure that
    /// leak, never for deployment, so building one is refused unless this is
    /// set on purpose.
    pub allow_naive_controller: bool,
    /// Extra slots that open on backlog, and the spillway. Default: both
    /// off. See [`SlotScaling`].
    pub scaling: SlotScaling,
}

impl Default for PadConfig {
    fn default() -> Self {
        Self {
            mode: WaitMode::Sleep,
            spin_tail: DEFAULT_SPIN_TAIL,
            spin_budget: SpinBudgetConfig::default(),
            max_concurrent: DEFAULT_MAX_CONCURRENT,
            max_input_len: DEFAULT_MAX_INPUT_LEN,
            allow_naive_controller: false,
            scaling: SlotScaling::default(),
        }
    }
}

impl PadConfig {
    /// The fixed spin charge one request reserves at admission: the tail in
    /// Hybrid mode, zero in Sleep mode.
    pub fn spin_charge(&self) -> Duration {
        match self.mode {
            WaitMode::Sleep => Duration::ZERO,
            WaitMode::Hybrid => self.spin_tail,
        }
    }

    /// Check every bound.
    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.spin_tail > MAX_SPIN_TAIL {
            return bad("spin_tail", "above MAX_SPIN_TAIL");
        }
        if self.max_concurrent == 0 {
            return bad("max_concurrent", "must be at least 1");
        }
        if self.max_concurrent > MAX_CONCURRENT_LIMIT {
            return bad("max_concurrent", "above MAX_CONCURRENT_LIMIT");
        }
        if self.max_input_len > MAX_INPUT_LEN_LIMIT {
            return bad("max_input_len", "above MAX_INPUT_LEN_LIMIT");
        }
        self.scaling.validate(self.max_concurrent)?;
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
            if burst < self.spin_charge() {
                return bad(
                    "spin_budget",
                    "burst is smaller than one request's spin charge, so spin would never be granted",
                );
            }
        }
        Ok(())
    }
}

/// Which window statistic the naive controller tracks.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum WindowStatistic {
    /// Arithmetic mean of the window.
    Mean,
    /// Nearest-rank percentile of the window, in per mille (990 is p99).
    /// Bounds: 1 ..= 1000.
    Percentile {
        /// Per mille rank: 500 median, 990 p99, 1000 maximum.
        permille: u16,
    },
}

/// Configuration of [`crate::NaiveRollingTarget`], the brief's design.
///
/// Kept so its leaks can be measured. Do not deploy it: see the crate docs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NaiveConfig {
    /// The window statistic. Default p99
    /// ([`DEFAULT_PERCENTILE_PERMILLE`]).
    pub statistic: WindowStatistic,
    /// Samples in the trailing window. Default [`DEFAULT_WINDOW`]. Bounds:
    /// 1 ..= [`MAX_WINDOW`].
    pub window: usize,
    /// Added to the statistic. Default [`DEFAULT_MARGIN`]. Bounds:
    /// 0 ..= [`MAX_TARGET`].
    pub margin: Duration,
    /// Lowest target. Default [`MIN_TARGET`]. Bounds: [`MIN_TARGET`] ..=
    /// `cap`.
    pub floor: Duration,
    /// Highest target (anti-DoS ceiling). No default. Bounds: `floor` ..=
    /// [`MAX_TARGET`].
    pub cap: Duration,
    /// Target before the first observation. Default `cap`. Bounds: `floor`
    /// ..= `cap`.
    pub initial_target: Duration,
}

impl NaiveConfig {
    /// Every default, with the given cap.
    pub fn new(cap: Duration) -> Self {
        Self {
            statistic: WindowStatistic::Percentile {
                permille: DEFAULT_PERCENTILE_PERMILLE,
            },
            window: DEFAULT_WINDOW,
            margin: DEFAULT_MARGIN,
            floor: MIN_TARGET,
            cap,
            initial_target: cap,
        }
    }

    /// Check every bound.
    pub fn validate(&self) -> Result<(), ConfigError> {
        check_floor_cap(self.floor, self.cap)?;
        if self.initial_target < self.floor || self.initial_target > self.cap {
            return bad("initial_target", "outside floor ..= cap");
        }
        if self.window == 0 {
            return bad("window", "must be at least 1");
        }
        if self.window > MAX_WINDOW {
            return bad("window", "above MAX_WINDOW");
        }
        if self.margin > MAX_TARGET {
            return bad("margin", "above MAX_TARGET");
        }
        if let WindowStatistic::Percentile { permille } = self.statistic {
            if permille == 0 || permille > 1_000 {
                return bad("statistic", "percentile must be 1 ..= 1000 per mille");
            }
        }
        Ok(())
    }
}

/// The per-window leak budget of the epoch controller: at most `bits` of
/// timing information per `window` of wall time, by the bound in
/// [`crate::epoch_bound_bits`].
///
/// This is a RATE (bits per window). On its own it renews every window and
/// so bounds nothing in total; the total is bounded by
/// [`EpochConfig::leak_lifetime_windows`]. When one window's charged bound
/// reaches `bits`, the controller rolls back to the cap and stops adapting
/// for the rest of that window; it adapts again from the next window
/// boundary.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct LeakBudgetConfig {
    /// Bits allowed per window. Default [`DEFAULT_LEAK_BUDGET_BITS`].
    /// Bounds: finite, above 0, at most [`MAX_LEAK_BUDGET_BITS`].
    pub bits: f64,
    /// Accounting window, on a wall-clock grid anchored at construction.
    /// Default [`DEFAULT_LEAK_WINDOW`]. Bounds: [`MIN_EPOCH`] ..=
    /// [`MAX_LEAK_WINDOW`].
    pub window: Duration,
}

impl Default for LeakBudgetConfig {
    fn default() -> Self {
        Self {
            bits: DEFAULT_LEAK_BUDGET_BITS,
            window: DEFAULT_LEAK_WINDOW,
        }
    }
}

/// Configuration of [`crate::EpochQuantizedTarget`].
///
/// The target is always one of the public levels
/// `min(floor * 2^i, cap)` for `i` in `0 ..= top_level()`.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct EpochConfig {
    /// Lowest level. Set it at or above the worst-case work time at nominal
    /// load, so the controller adapts to load only (see the crate docs on
    /// trajectories). Bounds: [`MIN_TARGET`] ..= `cap`.
    pub floor: Duration,
    /// Highest level, and the public maximum the controller rolls back to
    /// when the leak budget is spent. No default. Bounds: `floor` ..=
    /// [`MAX_TARGET`].
    pub cap: Duration,
    /// Starting level index (0 is `floor`). Default `top_level()`, which is
    /// the cap: the controller starts at the public maximum and steps down.
    pub initial_level: u32,
    /// Epoch length on a wall-clock grid anchored at construction. The
    /// target may step down only at these boundaries. Default
    /// [`DEFAULT_EPOCH`]. Bounds: [`MIN_EPOCH`] ..= [`MAX_EPOCH`].
    pub epoch: Duration,
    /// Per-window leak budget (a rate). Default
    /// [`LeakBudgetConfig::default`].
    pub leak_budget: LeakBudgetConfig,
    /// Lifetime leak budget, as a whole number of window budgets. The
    /// controller sums every window's charged bound since construction or
    /// the last operator reset; when the sum reaches
    /// `leak_budget.bits * leak_lifetime_windows` it rolls back to the cap
    /// and stops adapting until an operator reset (waiting does not lift
    /// it). This is the total the budget guarantees. Default
    /// [`DEFAULT_LEAK_LIFETIME_WINDOWS`]. Bounds: 1 ..=
    /// [`MAX_LEAK_LIFETIME_WINDOWS`].
    pub leak_lifetime_windows: u32,
}

impl EpochConfig {
    /// Every default, with the given floor and cap. The initial level is
    /// the top level (the cap). If `floor > cap` the result fails
    /// `validate`.
    pub fn new(floor: Duration, cap: Duration) -> Self {
        let mut c = Self {
            floor,
            cap,
            initial_level: 0,
            epoch: DEFAULT_EPOCH,
            leak_budget: LeakBudgetConfig::default(),
            leak_lifetime_windows: DEFAULT_LEAK_LIFETIME_WINDOWS,
        };
        c.initial_level = c.top_level();
        c
    }

    /// Index of the top level: the smallest `i` with `floor * 2^i >= cap`.
    /// At most 63 (in practice at most 24 within the target bounds).
    pub fn top_level(&self) -> u32 {
        crate::controller::ladder::top_level(self.floor, self.cap)
    }

    /// Number of distinct public levels (`K` in the ladder bound).
    pub fn levels(&self) -> u32 {
        self.top_level().saturating_add(1)
    }

    /// The target at level `i`: `min(floor * 2^i, cap)`.
    pub fn level_target(&self, i: u32) -> Duration {
        crate::controller::ladder::level_target(self.floor, self.cap, i)
    }

    /// The lifetime budget in bits: `leak_budget.bits *
    /// leak_lifetime_windows`.
    pub fn leak_lifetime_bits(&self) -> f64 {
        self.leak_budget.bits * f64::from(self.leak_lifetime_windows)
    }

    /// Check every bound.
    ///
    /// Sizing note (not checkable here, because it depends on traffic): one
    /// full escalation cycle (a single request just under the cap, then the
    /// steps back down) costs up to `2 * top_level()` charged changes, each
    /// `log2(2 * (R + 1))` bits for `R` requests in the window. If
    /// `2 * top_level() * log2(2 * (R + 1))` is at or above
    /// `leak_budget.bits` at the expected request rate, one slow request
    /// freezes the controller at the cap for the rest of that window. The
    /// descent from the starting level is not charged (see
    /// [`crate::EpochQuantizedTarget`]), so honest warm-up does not spend
    /// the budget.
    pub fn validate(&self) -> Result<(), ConfigError> {
        check_floor_cap(self.floor, self.cap)?;
        if self.initial_level > self.top_level() {
            return bad("initial_level", "above top_level()");
        }
        if self.epoch < MIN_EPOCH || self.epoch > MAX_EPOCH {
            return bad("epoch", "outside MIN_EPOCH ..= MAX_EPOCH");
        }
        let b = self.leak_budget;
        if !b.bits.is_finite() || b.bits <= 0.0 || b.bits > MAX_LEAK_BUDGET_BITS {
            return bad(
                "leak_budget.bits",
                "must be finite, above 0 and at most MAX_LEAK_BUDGET_BITS",
            );
        }
        if b.window < MIN_EPOCH || b.window > MAX_LEAK_WINDOW {
            return bad(
                "leak_budget.window",
                "outside MIN_EPOCH ..= MAX_LEAK_WINDOW",
            );
        }
        if self.leak_lifetime_windows == 0 || self.leak_lifetime_windows > MAX_LEAK_LIFETIME_WINDOWS {
            return bad(
                "leak_lifetime_windows",
                "outside 1 ..= MAX_LEAK_LIFETIME_WINDOWS",
            );
        }
        Ok(())
    }
}

fn check_floor_cap(floor: Duration, cap: Duration) -> Result<(), ConfigError> {
    if floor < MIN_TARGET {
        return bad("floor", "below MIN_TARGET");
    }
    if cap > MAX_TARGET {
        return bad("cap", "above MAX_TARGET");
    }
    if floor > cap {
        return bad("floor", "above cap");
    }
    Ok(())
}

fn bad(field: &'static str, reason: &'static str) -> Result<(), ConfigError> {
    Err(ConfigError { field, reason })
}

/// A configuration field out of bounds. Raised once at construction, never
/// per request.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
#[error("invalid adaptive pad config: {field}: {reason}")]
pub struct ConfigError {
    /// The offending field.
    pub field: &'static str,
    /// Why it was rejected.
    pub reason: &'static str,
}
