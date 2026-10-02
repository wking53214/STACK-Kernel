//! The pad: admission, the operation, the controller, the wait, the release.
//!
//! Order of events for one request:
//! 1. Read the clock: the admission time `start`. Nothing secret-dependent
//!    has happened yet.
//! 2. Admission checks, all on public facts: halted flag, input length, a
//!    free concurrency slot, then the spin budget reservation (a fixed
//!    charge). A failure returns at once with a fixed-shape trip.
//! 3. Ask the controller for this request's target (a [`Snapshot`]). This
//!    applies any update due at a public time (an epoch boundary).
//! 4. Run the operation (the secret-dependent part) under
//!    `catch_unwind`. A panic ends the work at the time of the panic; the
//!    request then follows the same steps and returns
//!    [`Trip::OperationPanicked`] after its release.
//! 5. Read the clock: `completion`. Plan the release from the snapshot and
//!    the work time (pure arithmetic), then let the controller record the
//!    work time. Both happen inside the padded window, so their cost is
//!    hidden when the request is on time. In Hybrid mode (spin granted) the
//!    "work time" used for both is the work plus the spin tail, so that
//!    every released request sleeps first and then spins: the wait path
//!    never depends on how long the secret-dependent work took.
//! 6. Wait until `start + release` in the chosen mode.
//! 7. Read the clock: `release`. Only now: free the slot, emit metrics and
//!    logs, return.

use crate::budget::SpinBudget;
use crate::clock::{Clock, MonotonicClock};
use crate::config::{ConfigError, EpochConfig, NaiveConfig, PadConfig, WaitMode};
use crate::controller::epoch::EpochQuantizedTarget;
use crate::controller::naive::NaiveRollingTarget;
use crate::controller::{ControllerKind, ControllerStatus, Plan, TargetController};
use crate::outcome::{
    ControllerTrip, Disposition, GateOutcome, PadResult, Padded, ReleaseInfo, Trip,
};
use crate::slots::{Permit, Slots};
use crate::telemetry::{self, Event, OverrunKind};
use crate::wait::{self, ClockFault};
use std::any::Any;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Mutex, MutexGuard};
use std::time::{Duration, Instant};
use tracing::field::Empty;

/// Adaptive padding (ANC strategy 2) around a [`TargetController`].
///
/// Share one pad per protected operation (wrap it in an `Arc` to share it
/// across threads). All state is internal and bounded: a slot counter, a
/// spin budget, the controller (behind a mutex held only for a few
/// arithmetic steps, or one sort of the naive window), and a halted flag.
#[derive(Debug)]
pub struct AdaptivePad<K: TargetController, C: Clock = MonotonicClock> {
    config: PadConfig,
    clock: C,
    slots: Slots,
    budget: SpinBudget,
    controller: Mutex<K>,
    kind: ControllerKind,
    halted: AtomicBool,
}

struct Admitted<'a> {
    _permit: Permit<'a>,
    mode: WaitMode,
    reserved: Duration,
    fallback: bool,
}

impl AdaptivePad<NaiveRollingTarget, MonotonicClock> {
    /// A pad running the naive rolling-average controller (the brief's
    /// design; kept to measure its leaks, not for deployment).
    ///
    /// Leaky by design: a request slower than the target is released at
    /// completion, so its response time is its raw, secret-dependent work
    /// time. Never select it in a deployment profile; use
    /// [`AdaptivePad::epoch`].
    pub fn naive(pad: PadConfig, naive: NaiveConfig) -> Result<Self, ConfigError> {
        Self::with_parts(pad, NaiveRollingTarget::new(naive)?, MonotonicClock)
    }
}

impl AdaptivePad<EpochQuantizedTarget, MonotonicClock> {
    /// A pad running the epoch-quantized controller, its epoch grid
    /// anchored at construction time.
    ///
    /// Fails if any bound is violated, including a Hybrid `spin_tail` at or
    /// above the cap. Logs a warning when a Hybrid tail is at or above the
    /// floor (every spin-granted request then escalates until the level
    /// covers the tail).
    pub fn epoch(pad: PadConfig, epoch: EpochConfig) -> Result<Self, ConfigError> {
        if pad.mode == WaitMode::Hybrid && pad.spin_tail >= epoch.floor && pad.spin_tail < epoch.cap
        {
            tracing::warn!(
                "hybrid spin_tail is at or above the epoch floor: every spin-granted request escalates until the level covers the tail"
            );
        }
        let origin = MonotonicClock.now();
        Self::with_parts(
            pad,
            EpochQuantizedTarget::new(epoch, origin)?,
            MonotonicClock,
        )
    }
}

impl<K: TargetController, C: Clock> AdaptivePad<K, C> {
    /// A pad from a controller and a clock (tests use this to inject a
    /// failing clock). Fails if any pad config bound is violated, or if
    /// the mode is Hybrid and `spin_tail` is at or above the controller's
    /// cap (every spin-granted request would then be an overrun RETRY).
    pub fn with_parts(config: PadConfig, controller: K, clock: C) -> Result<Self, ConfigError> {
        config.validate()?;
        let status = controller.status();
        if config.mode == WaitMode::Hybrid && config.spin_tail >= status.cap {
            return Err(ConfigError {
                field: "spin_tail",
                reason: "in Hybrid mode the spin tail must be below the controller cap",
            });
        }
        let now = clock.now();
        let kind = controller.kind();
        telemetry::emit_status(&status);
        Ok(Self {
            slots: Slots::new(config.max_concurrent),
            budget: SpinBudget::new(config.spin_budget, now),
            controller: Mutex::new(controller),
            kind,
            halted: AtomicBool::new(false),
            config,
            clock,
        })
    }

    /// The pad configuration in force.
    pub fn config(&self) -> &PadConfig {
        &self.config
    }

    /// Which controller this pad runs.
    pub fn kind(&self) -> ControllerKind {
        self.kind
    }

    /// Requests currently holding a concurrency slot.
    pub fn in_flight(&self) -> usize {
        self.slots.in_use()
    }

    /// True after a clock failure, until [`AdaptivePad::reset`].
    pub fn is_halted(&self) -> bool {
        self.halted.load(Ordering::Acquire)
    }

    /// Spin budget left in the bucket (without refilling), or `None` when
    /// the budget is unlimited.
    pub fn spin_budget_remaining(&self) -> Option<Duration> {
        self.budget.tokens()
    }

    /// The controller's current state.
    pub fn status(&self) -> ControllerStatus {
        self.lock().status()
    }

    /// Read the controller under its lock (for tests and diagnostics).
    pub fn inspect<R>(&self, f: impl FnOnce(&K) -> R) -> R {
        f(&self.lock())
    }

    /// Operator reset after a halt: the pad accepts work again. Counted in
    /// `stack_anc_resets_total{scope="pad"}`; sets `stack_anc_halted` to 0.
    pub fn reset(&self) {
        let _span = tracing::info_span!("tack.anc.adaptive_reset", controller = self.kind.label())
            .entered();
        let was = self.halted.swap(false, Ordering::AcqRel);
        telemetry::emit_reset(self.kind, "pad");
        tracing::warn!(was_halted = was, "adaptive pad reset by operator");
    }

    /// Operator reset of the controller: lifts a leak-budget freeze
    /// (including a lifetime freeze), clears the lifetime sum and starts a
    /// fresh accounting window. Counted in
    /// `stack_anc_resets_total{scope="controller"}`.
    pub fn reset_controller(&self) {
        let _span = tracing::info_span!(
            "tack.anc.adaptive_controller_reset",
            controller = self.kind.label()
        )
        .entered();
        let now = self.clock.now();
        let (ch, status) = {
            let mut g = self.lock();
            let ch = g.operator_reset(now);
            (ch, g.status())
        };
        telemetry::emit_reset(self.kind, "controller");
        telemetry::emit_changes(self.kind, &ch);
        telemetry::emit_status(&status);
        tracing::warn!(
            frozen = status.frozen,
            "adaptive controller reset by operator"
        );
    }

    /// Run `op` and release its result at admission time plus the target
    /// (see the module docs for the order of events). Blocks the calling
    /// thread. Returns [`Padded`] or a [`Trip`] and never panics: a panic
    /// inside `op` is caught, the reply is still released on schedule and
    /// counted, and the result is [`Trip::OperationPanicked`]. The panic
    /// hook (by default a message on stderr) still runs at the moment of
    /// the panic, inside the padded window; install a quiet hook if that
    /// output is observable. With `panic = "abort"` there is nothing to
    /// catch and the process aborts.
    pub fn pad<T, F>(&self, op: F) -> PadResult<T>
    where
        F: FnOnce() -> T,
    {
        let span = pad_span(self.kind);
        let (result, ev) = span.in_scope(|| self.run(None, op));
        self.after_release(&span, &result, &ev, None);
        result
    }

    /// As [`AdaptivePad::pad`], for an operation on a request input. The
    /// input length is checked against `max_input_len` before admission
    /// (oversized: [`Trip::InputTooLarge`] at once, `op` not called). After
    /// release, the input is logged at debug level as its length and full
    /// SHA-256 hex, never raw.
    pub fn pad_input<T, F>(&self, input: &[u8], op: F) -> PadResult<T>
    where
        F: FnOnce(&[u8]) -> T,
    {
        let span = pad_span(self.kind);
        let (result, ev) = span.in_scope(|| self.run(Some(input.len()), || op(input)));
        self.after_release(&span, &result, &ev, Some(input));
        result
    }

    fn lock(&self) -> MutexGuard<'_, K> {
        // The controller never panics while holding the lock (its methods
        // are total), so a poisoned lock can only come from a panic in a
        // caller's `inspect` closure; the state is still consistent.
        self.controller.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn admit(&self, start: Instant, input_len: Option<usize>) -> Result<Admitted<'_>, Trip> {
        if self.is_halted() {
            return Err(Trip::Halted);
        }
        if input_len.is_some_and(|n| n > self.config.max_input_len) {
            return Err(Trip::InputTooLarge);
        }
        let permit = self.slots.try_acquire().ok_or(Trip::SlotsFull)?;
        let charge = self.config.spin_charge();
        let (mode, reserved, fallback) = if self.budget.try_reserve(charge, start) {
            (self.config.mode, charge, false)
        } else {
            (WaitMode::Sleep, Duration::ZERO, true)
        };
        Ok(Admitted {
            _permit: permit,
            mode,
            reserved,
            fallback,
        })
    }

    fn run<T>(&self, input_len: Option<usize>, op: impl FnOnce() -> T) -> (PadResult<T>, Event) {
        let start = self.clock.now();
        let adm = match self.admit(start, input_len) {
            Ok(a) => a,
            Err(trip) => {
                let observed = self.clock.now().saturating_duration_since(start);
                return (Err(trip), Event::early(self.kind, trip, observed));
            }
        };
        let (snap, admit_changes) = self.lock().admit(start);
        // Kernel convention 1: no panic crosses the request boundary. The
        // controller lock is not held here, so a panic cannot poison it.
        let value = catch_unwind(AssertUnwindSafe(op));
        let completion = self.clock.now();
        let mut ev = Event {
            kind: self.kind,
            outcome: GateOutcome::Pass,
            trip: None,
            overrun: None,
            fallback: adm.fallback,
            reserved_spin: adm.reserved,
            observed: Duration::ZERO,
            changes: admit_changes,
            status: None,
        };
        let Some(work) = completion.checked_duration_since(start) else {
            return self.clock_failure(start, ev);
        };
        // In Hybrid mode the request needs `spin_tail` of spin after it
        // finishes, so it is planned and recorded as `work + spin_tail`.
        // Then every on-time or escalated Hybrid release finishes its work
        // before `release - spin_tail` and takes the same path: sleep, then
        // spin. Without this, work that ends after that point skips the
        // sleep, and whether a request slept depends on the secret (measured
        // on the development host: about 0.9 us of extra post-release time
        // after a sleep, KS D 0.69 between classes at one level).
        let tail_need = match adm.mode {
            WaitMode::Hybrid => self.config.spin_tail,
            WaitMode::Sleep => Duration::ZERO,
        };
        let need = work.saturating_add(tail_need);
        let plan = snap.plan(need);
        {
            let mut g = self.lock();
            let rec = g.record(&snap, need, completion);
            ev.changes = ev.changes.merge(rec);
            ev.status = Some(g.status());
        }
        let waited = start
            .checked_add(plan.release())
            .ok_or(ClockFault)
            .and_then(|target| wait::wait(&self.clock, target, adm.mode, self.config.spin_tail));
        if waited.is_err() {
            return self.clock_failure(start, ev);
        }
        let observed = self.clock.now().saturating_duration_since(start);
        ev.observed = observed;
        let release = |disposition| ReleaseInfo {
            target: snap.target,
            release: plan.release(),
            disposition,
            mode: adm.mode,
            observed,
        };
        let value = match value {
            Ok(v) => v,
            Err(payload) => {
                if let Some(o) = plan_overrun(&plan) {
                    ev.overrun = Some(o);
                }
                ev.outcome = GateOutcome::TerminalBreach;
                ev.trip = Some(Trip::OperationPanicked);
                drop_quietly(payload);
                return (Err(Trip::OperationPanicked), ev);
            }
        };
        let result = match plan {
            Plan::OnTime { .. } => Ok(Padded {
                value,
                release: release(Disposition::OnTime),
            }),
            Plan::Late { .. } => {
                ev.overrun = Some(OverrunKind::Late);
                Ok(Padded {
                    value,
                    release: release(Disposition::Late),
                })
            }
            Plan::Escalated { steps, .. } => {
                ev.overrun = Some(OverrunKind::Escalated);
                Ok(Padded {
                    value,
                    release: release(Disposition::Escalated { steps }),
                })
            }
            Plan::HardOverrun { .. } => {
                ev.overrun = Some(OverrunKind::Retry);
                ev.outcome = GateOutcome::Retry;
                ev.trip = Some(Trip::Overrun);
                Err(Trip::Overrun)
            }
        };
        // `adm` (the slot) and any discarded value drop here, after release.
        (result, ev)
    }

    fn clock_failure<T>(&self, start: Instant, mut ev: Event) -> (PadResult<T>, Event) {
        self.halted.store(true, Ordering::Release);
        ev.outcome = GateOutcome::TerminalBreach;
        ev.trip = Some(Trip::ClockFailure);
        ev.observed = self.clock.now().saturating_duration_since(start);
        (Err(Trip::ClockFailure), ev)
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
            span.record("disposition", p.release.disposition.label());
            span.record("mode", p.release.mode.label());
        }
        if let Some(input) = input {
            telemetry::log_input(input, self.config.max_input_len, ev);
        }
        let _g = span.enter();
        if ev.changes.lifetime_exhausted {
            let t = ControllerTrip::LeakLifetimeSpent;
            tracing::error!(
                outcome = t.gate_outcome().as_str(),
                reason = t.label(),
                rolled_back = ev.changes.rollback,
                "adaptive lifetime leak budget spent: target at the cap, adaptation stopped until operator reset"
            );
        } else if ev.changes.exhausted {
            let t = ControllerTrip::LeakBudgetSpent;
            tracing::warn!(
                outcome = t.gate_outcome().as_str(),
                reason = t.label(),
                rolled_back = ev.changes.rollback,
                "adaptive leak budget spent for this window: target rolled back to the cap until the next window boundary"
            );
        }
        match ev.trip {
            Some(Trip::ClockFailure) => {
                tracing::error!(
                    "monotonic clock failure: adaptive pad halted until operator reset"
                );
            }
            Some(Trip::Overrun) => {
                tracing::debug!("target cap overrun: result discarded, RETRY released");
            }
            Some(Trip::OperationPanicked) => {
                tracing::error!(
                    "operation panicked inside the adaptive pad: released on schedule, quarantine the input"
                );
            }
            _ => {}
        }
    }
}

/// The overrun counter a plan bumps, if any.
fn plan_overrun(plan: &Plan) -> Option<OverrunKind> {
    match plan {
        Plan::OnTime { .. } => None,
        Plan::Late { .. } => Some(OverrunKind::Late),
        Plan::Escalated { .. } => Some(OverrunKind::Escalated),
        Plan::HardOverrun { .. } => Some(OverrunKind::Retry),
    }
}

/// Drop a caught panic payload after release. A payload whose own `Drop`
/// panics is caught too, so nothing unwinds out of the pad.
fn drop_quietly(payload: Box<dyn Any + Send>) {
    let _ = catch_unwind(AssertUnwindSafe(move || drop(payload)));
}

fn pad_span(kind: ControllerKind) -> tracing::Span {
    tracing::debug_span!(
        "tack.anc.adaptive_pad",
        controller = kind.label(),
        outcome = Empty,
        trip = Empty,
        disposition = Empty,
        mode = Empty
    )
}
