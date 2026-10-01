//! The pad itself: admission, the operation, the wait, the release.
//!
//! Order of events for one request (both APIs):
//! 1. Read the clock: this is the admission time `start`. Nothing
//!    secret-dependent has happened yet.
//! 2. Admission checks, all on public facts: halted flag, input length,
//!    a free concurrency slot, then the spin budget reservation (a fixed
//!    charge). A failure here returns at once with a fixed-shape trip.
//! 3. Run the operation (the secret-dependent part).
//! 4. Read the clock: `completion`. Compute the release bucket `k`, the
//!    smallest whole multiple of the ceiling at or after completion.
//! 5. If `k <= hard_ceiling_buckets`: wait until `start + k * ceiling` in
//!    the chosen mode. Otherwise (hard overrun): drop the value (async:
//!    the cancelled or late future) NOW, read the clock, and wait until the
//!    first whole multiple of the retry window
//!    (`hard ceiling * retry_release_factor`) at or after that reading
//!    (async: and at or after the hard ceiling plus `ASYNC_TIMER_SLACK`).
//!    The drop cost is spent inside the padded time, so it cannot shift
//!    the reply unless it runs past the window boundary. The retry wait
//!    never spins more than the request's reserved charge: Spin waits as
//!    Hybrid with a one-ceiling tail.
//! 6. Read the clock: `release`. Then free the slot, emit metrics and
//!    logs, return. The slot release and the telemetry still run before
//!    the caller gets the reply; their cost does not depend on the secret
//!    (the telemetry differs by outcome only, by nanoseconds).

use crate::budget::SpinBudget;
use crate::clock::{Clock, MonotonicClock};
use crate::config::{CeilingConfig, ConfigError, WaitMode, ASYNC_TIMER_SLACK};
use crate::outcome::{GateOutcome, PadResult, Padded, ReleaseInfo, Trip};
use crate::slots::{Permit, Slots};
use crate::telemetry::{self, Event};
use crate::wait::{self, bucket_offset, release_bucket, ClockFault};
use std::future::Future;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};
use tracing::field::Empty;
use tracing::Instrument;

/// Deterministic ceiling padding (ANC strategy 1).
///
/// Share one pad per protected operation (wrap it in an `Arc` to share it
/// across threads or tasks). All state is internal and bounded: a slot
/// counter, a spin budget, and a halted flag.
#[derive(Debug)]
pub struct CeilingPad<C: Clock = MonotonicClock> {
    config: CeilingConfig,
    clock: C,
    slots: Slots,
    budget: SpinBudget,
    halted: AtomicBool,
}

struct Admitted<'a> {
    _permit: Permit<'a>,
    mode: WaitMode,
    reserved: Duration,
    fallback_from: Option<WaitMode>,
}

/// Outcome of planning and waiting: the bucket, and whether it was within
/// the hard ceiling.
type Waited = Result<(u64, bool), ClockFault>;

impl CeilingPad<MonotonicClock> {
    /// A pad on the system monotonic clock. Fails if any config bound is
    /// violated.
    pub fn new(config: CeilingConfig) -> Result<Self, ConfigError> {
        Self::with_clock(config, MonotonicClock)
    }

    /// Check, from inside the runtime that will call the async API, that it
    /// is a tokio runtime with the time driver enabled. Run it once at
    /// startup. `Err(Trip::TimerUnavailable)` means every `pad_async` call
    /// on this runtime would return that trip.
    ///
    /// Tokio has no public non-panicking check for the time driver, so this
    /// (and each async request) creates a timer inside `catch_unwind`. On a
    /// misconfigured runtime the panic hook still runs (it prints a line to
    /// stderr by default), and in a `panic = "abort"` build the process
    /// aborts instead: run this check in a test of the deployment profile.
    pub fn check_async_runtime() -> Result<(), Trip> {
        if timer_available() {
            Ok(())
        } else {
            Err(Trip::TimerUnavailable)
        }
    }
}

/// True inside a tokio runtime whose time driver is enabled.
fn timer_available() -> bool {
    if tokio::runtime::Handle::try_current().is_err() {
        return false;
    }
    // Creating a `Sleep` panics at once when the time driver is disabled;
    // it registers nothing until polled, so the probe is cheap.
    std::panic::catch_unwind(|| drop(tokio::time::sleep(Duration::ZERO))).is_ok()
}

/// Counts an admitted async request whose future is dropped before
/// release (a client disconnect). Disarmed just before `conclude`.
struct CancelGuard {
    reserved: Duration,
    armed: bool,
}

impl Drop for CancelGuard {
    fn drop(&mut self) {
        if self.armed {
            telemetry::emit_cancelled(self.reserved);
        }
    }
}

impl<C: Clock> CeilingPad<C> {
    /// A pad on a caller-supplied clock (tests use this to inject a
    /// failing clock).
    pub fn with_clock(config: CeilingConfig, clock: C) -> Result<Self, ConfigError> {
        config.validate()?;
        let now = clock.now();
        Ok(Self {
            slots: Slots::new(config.max_concurrent),
            budget: SpinBudget::new(config.spin_budget, now),
            halted: AtomicBool::new(false),
            config,
            clock,
        })
    }

    /// The configuration in force.
    pub fn config(&self) -> &CeilingConfig {
        &self.config
    }

    /// Requests currently holding a concurrency slot.
    pub fn in_flight(&self) -> usize {
        self.slots.in_use()
    }

    /// True after a clock failure, until [`CeilingPad::reset`].
    pub fn is_halted(&self) -> bool {
        self.halted.load(Ordering::Acquire)
    }

    /// Spin budget left in the bucket (without refilling), or `None` when
    /// the budget is unlimited.
    pub fn spin_budget_remaining(&self) -> Option<Duration> {
        self.budget.tokens()
    }

    /// Operator reset after a halt: the pad accepts work again. Counted in
    /// `tack_anc_resets_total`; if this pad was halted, the halted-pads
    /// gauge `tack_anc_halted` drops by one (a reset of a pad that is not
    /// halted leaves it alone). Call it only after the clock problem is
    /// understood.
    pub fn reset(&self) {
        let _span = tracing::info_span!("tack.anc.ceiling_reset").entered();
        let was = self.halted.swap(false, Ordering::AcqRel);
        telemetry::emit_reset(was);
        tracing::warn!(was_halted = was, "ceiling pad reset by operator");
    }

    /// Run `op` and release its result at admission time plus the ceiling
    /// (or the next multiple of it on overrun, up to the hard ceiling; past
    /// that, a RETRY at a multiple of the retry window). Blocks the calling
    /// thread.
    ///
    /// Returns [`Padded`] on success, or a [`Trip`]; never panics itself
    /// (a panic inside `op` propagates to the caller, as with any closure).
    pub fn pad<T, F>(&self, op: F) -> PadResult<T>
    where
        F: FnOnce() -> T,
    {
        let span = pad_span(false);
        let (result, ev) = span.in_scope(|| self.run_blocking(None, op));
        self.after_release(&span, &result, &ev, None);
        result
    }

    /// As [`CeilingPad::pad`], for an operation on a request input. The
    /// input length is checked against `max_input_len` before admission
    /// (oversized input: [`Trip::InputTooLarge`], returned at once, `op`
    /// not called). After release, the input is logged at debug level as
    /// its length and full SHA-256 hex, never raw.
    pub fn pad_input<T, F>(&self, input: &[u8], op: F) -> PadResult<T>
    where
        F: FnOnce(&[u8]) -> T,
    {
        let span = pad_span(false);
        let (result, ev) = span.in_scope(|| self.run_blocking(Some(input.len()), || op(input)));
        self.after_release(&span, &result, &ev, Some(input));
        result
    }

    /// Async variant of [`CeilingPad::pad`] for a tokio runtime with the
    /// time driver enabled (`enable_time` or `enable_all`). On any other
    /// runtime it returns [`Trip::TimerUnavailable`] before admission
    /// instead of panicking (see [`CeilingPad::check_async_runtime`] for
    /// the caveats).
    ///
    /// Differences from the blocking API:
    /// * Sleep waits use `tokio::time::sleep_until`, which rounds up to a
    ///   1 ms tick. Hybrid uses `async_spin_tail`.
    /// * Spin waits busy-wait on the executor worker thread.
    /// * The operation future is cancelled at the hard ceiling
    ///   (`tokio::time::timeout_at`, as precise as the 1 ms tokio tick). A
    ///   cancelled future, and one that finished after the hard ceiling
    ///   before the timer fired, are both treated as a hard overrun: the
    ///   future or value is dropped at once, and the RETRY is released at
    ///   the first multiple of the retry window at or after both that drop
    ///   and the hard ceiling plus `ASYNC_TIMER_SLACK`. So the RETRY time
    ///   does not depend on the work time, or on a drop cost that ends
    ///   inside that window. A future that never yields cannot be
    ///   cancelled; it behaves as in the blocking API.
    /// * If the returned future is itself dropped before release (client
    ///   disconnect), the slot is freed and the request is counted as
    ///   `tack_anc_requests_total{outcome="cancelled"}`.
    pub async fn pad_async<T, F, Fut>(&self, op: F) -> PadResult<T>
    where
        F: FnOnce() -> Fut,
        Fut: Future<Output = T>,
    {
        let span = pad_span(true);
        let (result, ev) = self.run_async(None, op).instrument(span.clone()).await;
        self.after_release(&span, &result, &ev, None);
        result
    }

    /// Async variant of [`CeilingPad::pad_input`].
    pub async fn pad_input_async<'i, T, F, Fut>(&self, input: &'i [u8], op: F) -> PadResult<T>
    where
        F: FnOnce(&'i [u8]) -> Fut,
        Fut: Future<Output = T>,
    {
        let span = pad_span(true);
        let (result, ev) = self
            .run_async(Some(input.len()), || op(input))
            .instrument(span.clone())
            .await;
        self.after_release(&span, &result, &ev, Some(input));
        result
    }

    /// Step 2 of the module docs. `start` is already taken.
    fn admit(
        &self,
        start: Instant,
        input_len: Option<usize>,
        async_api: bool,
    ) -> Result<Admitted<'_>, Trip> {
        if self.is_halted() {
            return Err(Trip::Halted);
        }
        if input_len.is_some_and(|n| n > self.config.max_input_len) {
            return Err(Trip::InputTooLarge);
        }
        let permit = self.slots.try_acquire().ok_or(Trip::SlotsFull)?;
        let charge = if async_api {
            self.config.async_spin_charge()
        } else {
            self.config.spin_charge()
        };
        let (mode, reserved, fallback_from) = if self.budget.try_reserve(charge, start) {
            (self.config.mode, charge, None)
        } else {
            (WaitMode::Sleep, Duration::ZERO, Some(self.config.mode))
        };
        Ok(Admitted {
            _permit: permit,
            mode,
            reserved,
            fallback_from,
        })
    }

    /// Step 4: the release target, its bucket, and whether it is within
    /// the hard ceiling.
    fn plan(
        &self,
        start: Instant,
        completion: Instant,
    ) -> Result<(Instant, u64, bool), ClockFault> {
        let elapsed = completion.checked_duration_since(start).ok_or(ClockFault)?;
        let k = release_bucket(elapsed, self.config.ceiling);
        let offset = bucket_offset(self.config.ceiling, k).ok_or(ClockFault)?;
        let target = start.checked_add(offset).ok_or(ClockFault)?;
        Ok((target, k, k <= u64::from(self.config.hard_ceiling_buckets)))
    }

    fn early(&self, start: Instant, trip: Trip) -> Event {
        Event::early(trip, self.clock.now().saturating_duration_since(start))
    }

    fn run_blocking<T>(
        &self,
        input_len: Option<usize>,
        op: impl FnOnce() -> T,
    ) -> (PadResult<T>, Event) {
        let start = self.clock.now();
        let adm = match self.admit(start, input_len, false) {
            Ok(a) => a,
            Err(trip) => return (Err(trip), self.early(start, trip)),
        };
        let value = op();
        let completion = self.clock.now();
        let tail = self.config.spin_tail;
        let (value, waited) = match self.plan(start, completion) {
            Ok((target, k, true)) => {
                let w = wait::wait_blocking(&self.clock, target, adm.mode, tail);
                (Some(value), w.map(|()| (k, true)))
            }
            Ok((_, _, false)) => {
                // Hard overrun: drop the discarded value inside the padded
                // time, then release on the retry window.
                drop(value);
                let (mode, tail) = self.retry_wait(adm.mode, tail);
                let w = self
                    .retry_target(start, self.clock.now())
                    .and_then(|(target, k)| {
                        wait::wait_blocking(&self.clock, target, mode, tail).map(|()| (k, false))
                    });
                (None, w)
            }
            Err(e) => (Some(value), Err(e)),
        };
        self.conclude(start, adm, value, waited)
    }

    /// The release target for a hard-overrun RETRY: the first whole
    /// multiple of the retry window, after `start`, at or after
    /// `not_before`. Returns the target and its offset in ceilings.
    fn retry_target(
        &self,
        start: Instant,
        not_before: Instant,
    ) -> Result<(Instant, u64), ClockFault> {
        let window = self.config.retry_window().ok_or(ClockFault)?;
        let elapsed = not_before.checked_duration_since(start).ok_or(ClockFault)?;
        let m = release_bucket(elapsed, window);
        let offset = bucket_offset(window, m).ok_or(ClockFault)?;
        let target = start.checked_add(offset).ok_or(ClockFault)?;
        let per_window = u64::from(self.config.hard_ceiling_buckets)
            .saturating_mul(u64::from(self.config.retry_release_factor));
        Ok((target, m.saturating_mul(per_window)))
    }

    /// How to wait for a RETRY release. The wait can be much longer than
    /// one ceiling, so it never spins more than the charge reserved at
    /// admission: Spin waits as Hybrid with a one-ceiling tail, Hybrid
    /// keeps its tail (capped at the ceiling), Sleep sleeps.
    fn retry_wait(&self, mode: WaitMode, tail: Duration) -> (WaitMode, Duration) {
        let c = self.config.ceiling;
        match mode {
            WaitMode::Sleep => (WaitMode::Sleep, Duration::ZERO),
            WaitMode::Spin => (WaitMode::Hybrid, c),
            WaitMode::Hybrid => (WaitMode::Hybrid, tail.min(c)),
        }
    }

    /// Async retry wait: the drop already happened; release on the retry
    /// window, never before `floor` (hard ceiling plus timer slack).
    async fn wait_retry_async(
        &self,
        start: Instant,
        floor: Instant,
        mode: WaitMode,
        tail: Duration,
    ) -> Waited {
        let not_before = self.clock.now().max(floor);
        let (target, k) = self.retry_target(start, not_before)?;
        let (mode, tail) = self.retry_wait(mode, tail);
        wait::wait_async(&self.clock, target, mode, tail).await?;
        Ok((k, false))
    }

    async fn run_async<T, F, Fut>(&self, input_len: Option<usize>, op: F) -> (PadResult<T>, Event)
    where
        F: FnOnce() -> Fut,
        Fut: Future<Output = T>,
    {
        let start = self.clock.now();
        if !timer_available() {
            let trip = Trip::TimerUnavailable;
            return (Err(trip), self.early(start, trip));
        }
        let adm = match self.admit(start, input_len, true) {
            Ok(a) => a,
            Err(trip) => return (Err(trip), self.early(start, trip)),
        };
        let mut guard = CancelGuard {
            reserved: adm.reserved,
            armed: true,
        };
        let tail = self.config.async_spin_tail;
        let deadlines = self
            .config
            .hard_ceiling()
            .and_then(|h| start.checked_add(h))
            .and_then(|hard| Some((hard, hard.checked_add(ASYNC_TIMER_SLACK)?)));
        let Some((hard_deadline, floor)) = deadlines else {
            guard.armed = false;
            return self.conclude::<T>(start, adm, None, Err(ClockFault));
        };
        // Awaiting the timeout future by value drops it, and with it a
        // cancelled operation future, at the end of this statement: inside
        // the padded time, before the retry wait below.
        let out =
            tokio::time::timeout_at(tokio::time::Instant::from_std(hard_deadline), op()).await;
        let completion = self.clock.now();
        let (value, waited) = match out {
            Ok(value) => match self.plan(start, completion) {
                Ok((target, k, true)) => {
                    let w = wait::wait_async(&self.clock, target, adm.mode, tail).await;
                    (Some(value), w.map(|()| (k, true)))
                }
                Ok((_, _, false)) => {
                    // Finished after the hard ceiling but before the timer
                    // fired: the same as a cancellation.
                    drop(value);
                    let w = self.wait_retry_async(start, floor, adm.mode, tail).await;
                    (None, w)
                }
                Err(e) => (Some(value), Err(e)),
            },
            Err(_elapsed) => {
                let w = self.wait_retry_async(start, floor, adm.mode, tail).await;
                (None, w)
            }
        };
        guard.armed = false;
        self.conclude(start, adm, value, waited)
    }

    /// Step 6. Everything here happens after the release time.
    fn conclude<T>(
        &self,
        start: Instant,
        adm: Admitted<'_>,
        value: Option<T>,
        waited: Waited,
    ) -> (PadResult<T>, Event) {
        let observed = self.clock.now().saturating_duration_since(start);
        let mut ev = Event {
            outcome: GateOutcome::Pass,
            trip: None,
            overrun_released: None,
            fallback_from: adm.fallback_from,
            reserved_spin: adm.reserved,
            observed,
            newly_halted: false,
        };
        let result = match (waited, value) {
            (Ok((k, true)), Some(value)) => {
                if k > 1 {
                    ev.overrun_released = Some(true);
                }
                Ok(Padded {
                    value,
                    release: ReleaseInfo {
                        buckets: k,
                        mode: adm.mode,
                        observed,
                    },
                })
            }
            (Ok(_), _) => {
                ev.outcome = GateOutcome::Retry;
                ev.trip = Some(Trip::Overrun);
                ev.overrun_released = Some(false);
                Err(Trip::Overrun)
            }
            (Err(ClockFault), _) => {
                ev.newly_halted = !self.halted.swap(true, Ordering::AcqRel);
                ev.outcome = GateOutcome::TerminalBreach;
                ev.trip = Some(Trip::ClockFailure);
                Err(Trip::ClockFailure)
            }
        };
        // `adm` (the slot) drops here, after the release time was read. A
        // hard-overrun value was already dropped before the retry wait; a
        // value is dropped here only on a clock failure (no padding then).
        (result, ev)
    }

    fn after_release<T>(
        &self,
        span: &tracing::Span,
        result: &PadResult<T>,
        ev: &Event,
        input: Option<&[u8]>,
    ) {
        telemetry::emit(ev);
        span.record("outcome", ev.outcome.as_str());
        span.record("trip", ev.trip.map_or("none", Trip::label));
        if let Ok(p) = result {
            span.record("buckets", p.release.buckets);
            span.record("mode", p.release.mode.label());
        }
        if let Some(input) = input {
            telemetry::log_input(input, self.config.max_input_len, ev);
        }
        match ev.trip {
            Some(Trip::ClockFailure) => {
                let _g = span.enter();
                tracing::error!("monotonic clock failure: ceiling pad halted until operator reset");
            }
            Some(Trip::Overrun) => {
                let _g = span.enter();
                tracing::debug!(
                    "hard ceiling overrun: result discarded, RETRY released on the retry window"
                );
            }
            _ => {}
        }
    }
}

fn pad_span(async_api: bool) -> tracing::Span {
    // `tracing` span names must be literals, hence two calls.
    if async_api {
        tracing::debug_span!(
            "tack.anc.ceiling_pad_async",
            outcome = Empty,
            trip = Empty,
            buckets = Empty,
            mode = Empty
        )
    } else {
        tracing::debug_span!(
            "tack.anc.ceiling_pad",
            outcome = Empty,
            trip = Empty,
            buckets = Empty,
            mode = Empty
        )
    }
}
