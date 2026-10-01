//! The gearbox itself: [`Transmission`], [`DriveGuard`] and the shift
//! protocol.
//!
//! # State
//!
//! All mutable state sits in one `State` struct behind one `std::sync::Mutex`:
//! the engaged gear (`Arc<Gear<G>>`), the in-flight count, the clutch flag,
//! whether a `shift()` call owns the gearbox, the number of parked `engage()`
//! callers, the halt cause, a halt generation counter, and the end of the
//! post-rollback cooldown. Two condition variables share that mutex:
//! `drained` (the shifter waits on it for the in-flight count to reach zero)
//! and `released` (parked `engage()` callers wait on it for the clutch to
//! come up, and a shifter waits on it for the cooldown to end).
//!
//! The halt generation goes up by one on every transition into the halted
//! state. A call that waits (a shifter draining or cooling down, an engager
//! parked on the clutch) records it before waiting and gives up with
//! `halted` if it changed, whatever `halted` says when the call wakes. So an
//! operator who halts to stop a shift and resets at once still stops it.
//!
//! # Lock order
//!
//! 1. `Inner::state`, the only lock this crate owns.
//! 2. The internal locks of the installed `metrics` recorder and `tracing`
//!    subscriber. They are taken under (1) only for gauge updates, halt
//!    counters and the rare halt log event.
//!
//! Never the reverse: nothing here calls back into a transmission from inside
//! telemetry. Nothing blocks while holding (1) except `Condvar` waits, which
//! release it while parked. The caller's configuration type `G` is never
//! dropped under (1): a replaced gear is dropped after the lock is released,
//! and a guard's `Arc` is dropped after its `Drop` body has unlocked. So a
//! slow or panicking `G::drop` cannot stall or poison the transmission.
//! `shift()` drops the replaced gear only after its verdict is recorded and
//! contains a panic from it (counted in `tack_transmission_gear_drop_panics_total`).
//! A guard that drops the last `Arc` of an old gear runs `G::drop` in the
//! caller's thread and does not contain it, so `G::drop` must not panic.
//!
//! The API is blocking and uses `std::sync` only. From async code call
//! `engage()` and `shift()` through a blocking-task executor; never call them
//! directly on an async worker thread. A [`DriveGuard`] is not a lock and may
//! be held across an `.await`, but for that whole time it keeps the in-flight
//! count above zero and so holds off every shift.
//!
//! # Poisoning
//!
//! A `std` mutex is poisoned when a thread panics while holding it. This
//! crate's own code never panics under the lock, so poisoning means a bug or
//! a panic in a telemetry backend (gauges are written under the lock).
//!
//! Such a panic can land between a state change and its counterpart: after
//! the clutch is pressed, after the in-flight count or the parked-caller
//! count goes up. Each of those changes is covered by an `UnwindRepair`
//! declared before the lock is taken. On unwind the `MutexGuard` drops first
//! (poisoning the mutex) and the repair runs after it: it retakes the lock,
//! undoes every change still marked pending (clutch up, counts back down,
//! gearbox ownership released), wakes the waiters, and leaves the poison in
//! place. It emits no telemetry, so a broken backend cannot panic a second
//! time during the unwind and abort the process. The backend's panic itself
//! still reaches the caller: the crate does not hide a broken backend.
//!
//! When any call then finds the lock poisoned it takes the state, clears the
//! poison, counts it, and halts the transmission with cause `poisoned`. The
//! state it finds is consistent, so after [`Transmission::operator_reset`]
//! the gearbox works normally. Until then the in-flight count keeps being
//! maintained (guards still decrement), but no new work is admitted and no
//! shift runs. Nothing ever propagates the poison as a panic.
//!
//! Limit: a backend that panics while a thread is already unwinding (for
//! example in a guard dropped during a worker's panic) makes Rust abort the
//! process. That is the language's double-panic rule and cannot be caught.

use std::fmt;
use std::ops::Deref;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::{Arc, Condvar, Mutex, MutexGuard};
use std::time::{Duration, Instant};

use crate::config::{ConfigError, TransmissionConfig, SHIFT_COOLDOWN_FACTOR};
use crate::gear::Gear;
use crate::telemetry;
use crate::vocab::{GateOutcome, HaltCause, Operation, Reason, Trip};

/// The gearbox. Cheap to clone: clones share one gearbox.
///
/// See the crate documentation for the protocol.
pub struct Transmission<G> {
    inner: Arc<Inner<G>>,
}

struct Inner<G> {
    config: TransmissionConfig,
    state: Mutex<State<G>>,
    /// Signalled when the in-flight count reaches zero while the clutch is
    /// pressed, and on halt. The shifter waits on it.
    drained: Condvar,
    /// Signalled when the clutch is released, and on halt. Parked `engage()`
    /// callers wait on it, and so does a shifter waiting out the cooldown.
    released: Condvar,
}

struct State<G> {
    gear: Arc<Gear<G>>,
    in_flight: usize,
    clutch: bool,
    /// A `shift()` call owns the gearbox, from the moment it passes its
    /// entry checks (including a cooldown wait) until it releases the
    /// clutch. At most one call owns it, so at most one thread ever waits
    /// out a cooldown.
    shifter: bool,
    waiting_engagers: usize,
    halted: Option<HaltCause>,
    /// Transitions into the halted state so far. Wraps; only compared for
    /// equality.
    halt_gen: u64,
    /// Set by a `drain_timeout` rollback. The next shift waits with the
    /// clutch up until this instant before pressing it.
    cooldown_until: Option<Instant>,
}

/// Undoes a half-made state change if the thread unwinds. See "Poisoning"
/// in the module documentation. Declare it before taking the lock, set a
/// flag right after each change, and clear the flag once the change is
/// complete. On a normal return every flag is clear and `drop` does nothing.
struct UnwindRepair<'a, G> {
    inner: &'a Inner<G>,
    in_flight: bool,
    waiting: bool,
    clutch: bool,
    shifter: bool,
}

impl<'a, G> UnwindRepair<'a, G> {
    fn new(inner: &'a Inner<G>) -> Self {
        Self {
            inner,
            in_flight: false,
            waiting: false,
            clutch: false,
            shifter: false,
        }
    }

    fn armed(&self) -> bool {
        self.in_flight || self.waiting || self.clutch || self.shifter
    }
}

impl<G> Drop for UnwindRepair<'_, G> {
    fn drop(&mut self) {
        if !self.armed() {
            return;
        }
        // Reached only during an unwind that started while the lock was
        // held, so the mutex is poisoned. Take the state without clearing
        // the poison: the next caller recovers and halts as usual. No
        // telemetry here, so nothing can panic a second time.
        let mut st = match self.inner.state.lock() {
            Ok(st) => st,
            Err(poisoned) => poisoned.into_inner(),
        };
        if self.in_flight {
            st.in_flight = st.in_flight.saturating_sub(1);
        }
        if self.waiting {
            st.waiting_engagers = st.waiting_engagers.saturating_sub(1);
        }
        if self.clutch {
            st.clutch = false;
        }
        if self.shifter {
            st.shifter = false;
        }
        drop(st);
        self.inner.drained.notify_all();
        self.inner.released.notify_all();
    }
}

/// A point-in-time copy of the transmission's state, for operators and
/// tests. It is stale as soon as it is returned.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TransmissionStatus {
    /// Epoch of the engaged gear.
    pub epoch: u64,
    /// Drive guards currently out.
    pub in_flight: usize,
    /// `engage()` callers parked on the clutch.
    pub waiting_engagers: usize,
    /// Whether a shift holds the clutch.
    pub clutch_pressed: bool,
    /// Why the transmission is halted, if it is.
    pub halted: Option<HaltCause>,
}

/// A completed shift.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ShiftReport {
    /// Epoch of the gear that was replaced.
    pub from_epoch: u64,
    /// Epoch of the gear now engaged. Always `from_epoch + 1`.
    pub to_epoch: u64,
    /// How long the clutch was pressed (admission paused).
    pub clutch_held: Duration,
}

/// A refused shift. Hands the unused configuration back so the caller can
/// resubmit it after a RETRY without rebuilding it.
pub struct ShiftRefused<G> {
    trip: Trip,
    config: G,
}

impl<G> ShiftRefused<G> {
    /// The verdict.
    pub fn trip(&self) -> Trip {
        self.trip
    }

    /// Takes back the configuration that was not engaged.
    pub fn into_config(self) -> G {
        self.config
    }
}

/// Prints the verdict only, never the configuration.
impl<G> fmt::Debug for ShiftRefused<G> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ShiftRefused")
            .field("trip", &self.trip)
            .finish_non_exhaustive()
    }
}

impl<G> fmt::Display for ShiftRefused<G> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.trip, f)
    }
}

impl<G> std::error::Error for ShiftRefused<G> {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.trip)
    }
}

/// Proof of admission for one request. Holds the gear that was engaged when
/// it was issued, for as long as it lives, and counts as in-flight work.
///
/// Dropping it (including during a panic unwind) decrements the in-flight
/// count. Keep one guard per request and drop it when the request is done.
/// Do not call `engage()` or `shift()` from a thread that already holds a
/// guard: a shift would then wait on that thread's own guard until its
/// timeout and roll back.
pub struct DriveGuard<G> {
    gear: Arc<Gear<G>>,
    inner: Arc<Inner<G>>,
}

impl<G> DriveGuard<G> {
    /// The gear this request runs on.
    pub fn gear(&self) -> &Gear<G> {
        &self.gear
    }

    /// Shorthand for `self.gear().epoch()`.
    pub fn epoch(&self) -> u64 {
        self.gear.epoch()
    }

    /// Shorthand for `self.gear().config()`.
    pub fn config(&self) -> &G {
        self.gear.config()
    }
}

impl<G> Deref for DriveGuard<G> {
    type Target = G;

    fn deref(&self) -> &G {
        self.gear.config()
    }
}

impl<G> Drop for DriveGuard<G> {
    fn drop(&mut self) {
        let panicking = std::thread::panicking();
        let mut st = self.inner.lock();
        match st.in_flight.checked_sub(1) {
            Some(n) => st.in_flight = n,
            None => {
                self.inner.halt_locked(&mut st, HaltCause::Invariant);
            }
        }
        telemetry::set_in_flight(st.in_flight);
        let wake_shifter = st.in_flight == 0 && st.clutch;
        drop(st);
        if wake_shifter {
            self.inner.drained.notify_all();
        }
        if panicking {
            telemetry::guard_panicked();
            tracing::warn!(
                epoch = self.gear.epoch(),
                "drive guard released during a panic; in-flight count decremented"
            );
        }
        // `self.gear` is dropped after this body returns, outside the lock.
    }
}

impl<G> fmt::Debug for DriveGuard<G> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DriveGuard")
            .field("epoch", &self.gear.epoch())
            .finish_non_exhaustive()
    }
}

impl<G> Clone for Transmission<G> {
    fn clone(&self) -> Self {
        Self {
            inner: Arc::clone(&self.inner),
        }
    }
}

impl<G> fmt::Debug for Transmission<G> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Transmission")
            .field("config", &self.inner.config)
            .finish_non_exhaustive()
    }
}

impl<G> Inner<G> {
    /// Takes the state lock, recovering it if poisoned.
    fn lock(&self) -> MutexGuard<'_, State<G>> {
        match self.state.lock() {
            Ok(st) => st,
            Err(poisoned) => {
                let mut st = poisoned.into_inner();
                self.recover_locked(&mut st);
                st
            }
        }
    }

    /// Waits on `cv` for at most `dur`, recovering the lock if poisoned.
    fn wait<'a>(
        &self,
        cv: &Condvar,
        st: MutexGuard<'a, State<G>>,
        dur: Duration,
    ) -> MutexGuard<'a, State<G>> {
        match cv.wait_timeout(st, dur) {
            Ok((st, _)) => st,
            Err(poisoned) => {
                let (mut st, _) = poisoned.into_inner();
                self.recover_locked(&mut st);
                st
            }
        }
    }

    /// Clears the poison and halts. The state itself was already put right
    /// by the `UnwindRepair` of the thread that panicked.
    fn recover_locked(&self, st: &mut State<G>) {
        self.state.clear_poison();
        telemetry::poison_recovered();
        self.halt_locked(st, HaltCause::Poisoned);
    }

    /// Halts if not already halted. The first cause is kept. Bumps the halt
    /// generation so waiters give up even if a reset lands before they wake.
    /// Wakes every waiter so it sees the halt now rather than at its
    /// deadline.
    fn halt_locked(&self, st: &mut State<G>, cause: HaltCause) -> bool {
        if st.halted.is_some() {
            return false;
        }
        st.halted = Some(cause);
        st.halt_gen = st.halt_gen.wrapping_add(1);
        telemetry::halt(cause);
        tracing::error!(
            cause = cause.as_str(),
            epoch = st.gear.epoch(),
            "transmission halted; new work refused until operator reset"
        );
        self.drained.notify_all();
        self.released.notify_all();
        true
    }
}

fn millis(d: Duration) -> u64 {
    u64::try_from(d.as_millis()).unwrap_or(u64::MAX)
}

/// Time left before `deadline`, or `None` if it has passed.
fn remaining(deadline: Instant) -> Option<Duration> {
    deadline
        .checked_duration_since(Instant::now())
        .filter(|d| !d.is_zero())
}

impl<G> Transmission<G> {
    /// Builds a transmission with `initial` engaged as epoch 0.
    ///
    /// Fails closed on an invalid config. Registers the gauges without
    /// writing a value, so it never clears what another instance in the
    /// same process is showing (for example its halt).
    pub fn new(initial: G, config: TransmissionConfig) -> Result<Self, ConfigError> {
        config.validate()?;
        telemetry::register_gauges();
        Ok(Self {
            inner: Arc::new(Inner {
                config,
                state: Mutex::new(State {
                    gear: Arc::new(Gear::new(0, initial)),
                    in_flight: 0,
                    clutch: false,
                    shifter: false,
                    waiting_engagers: 0,
                    halted: None,
                    halt_gen: 0,
                    cooldown_until: None,
                }),
                drained: Condvar::new(),
                released: Condvar::new(),
            }),
        })
    }

    /// The caps this transmission runs with.
    pub fn config(&self) -> &TransmissionConfig {
        &self.inner.config
    }

    /// Admits one request on the engaged gear.
    ///
    /// If the clutch is up, this returns at once. If a shift holds the
    /// clutch, the caller parks for up to `timeout` and, if the shift
    /// finishes in time, is admitted on the new gear. Refusals:
    ///
    /// | reason | outcome | resolution |
    /// |---|---|---|
    /// | `engage_timeout_over_budget` (`timeout` above `max_engage_wait`) | RETRY | reject |
    /// | `wait_queue_full` (`max_waiting_engagers` already parked) | RETRY | reject |
    /// | `clutch_wait_timeout` (the clutch stayed down) | RETRY | reject |
    /// | `in_flight_capacity` (`max_in_flight` guards out) | RETRY | reject |
    /// | `halted` (halted now, or a halt happened while parked) | TERMINAL_BREACH | halt |
    ///
    /// A refusal changes nothing: no guard is issued and no count moves.
    pub fn engage(&self, timeout: Duration) -> Result<DriveGuard<G>, Trip> {
        let span = tracing::debug_span!(
            telemetry::SPAN_ENGAGE,
            timeout_ms = millis(timeout),
            epoch = tracing::field::Empty,
            outcome = tracing::field::Empty,
            reason = tracing::field::Empty,
        );
        let _entered = span.enter();
        let start = Instant::now();
        let result = self.engage_inner(timeout, start);
        telemetry::finish(
            Operation::Engage,
            result.as_ref().map(|_| ()).map_err(|r| *r),
            start.elapsed(),
        );
        match result {
            Ok(guard) => {
                span.record("epoch", guard.epoch());
                span.record("outcome", GateOutcome::Pass.as_str());
                Ok(guard)
            }
            Err(reason) => {
                span.record("outcome", reason.outcome().as_str());
                span.record("reason", reason.as_str());
                tracing::debug!(reason = reason.as_str(), "engage refused");
                Err(Trip::new(Operation::Engage, reason))
            }
        }
    }

    fn engage_inner(&self, timeout: Duration, start: Instant) -> Result<DriveGuard<G>, Reason> {
        let inner = &self.inner;
        let cfg = &inner.config;
        if timeout > cfg.max_engage_wait {
            return Err(Reason::EngageTimeoutOverBudget);
        }
        // Cannot fail once the timeout is capped; fail closed if it does.
        let deadline = start
            .checked_add(timeout)
            .ok_or(Reason::EngageTimeoutOverBudget)?;

        // Declared before the lock so that, on unwind, it runs after the
        // guard has dropped. See "Poisoning".
        let mut repair = UnwindRepair::new(inner);
        let mut st = inner.lock();
        if st.halted.is_some() {
            return Err(Reason::Halted);
        }
        if st.clutch {
            if st.waiting_engagers >= cfg.max_waiting_engagers {
                return Err(Reason::WaitQueueFull);
            }
            let halt_gen = st.halt_gen;
            st.waiting_engagers += 1;
            repair.waiting = true;
            telemetry::set_waiting(st.waiting_engagers);
            let waited = loop {
                if st.halted.is_some() || st.halt_gen != halt_gen {
                    break Err(Reason::Halted);
                }
                if !st.clutch {
                    break Ok(());
                }
                let Some(left) = remaining(deadline) else {
                    break Err(Reason::ClutchWaitTimeout);
                };
                st = inner.wait(&inner.released, st, left);
            };
            st.waiting_engagers = st.waiting_engagers.saturating_sub(1);
            repair.waiting = false;
            telemetry::set_waiting(st.waiting_engagers);
            waited?;
        }
        if st.in_flight >= cfg.max_in_flight {
            return Err(Reason::InFlightCapacity);
        }
        st.in_flight += 1;
        repair.in_flight = true;
        telemetry::set_in_flight(st.in_flight);
        // The count now belongs to the guard built below; nothing between
        // here and its construction can unwind.
        repair.in_flight = false;
        let gear = Arc::clone(&st.gear);
        drop(st);
        Ok(DriveGuard {
            gear,
            inner: Arc::clone(&self.inner),
        })
    }

    /// Changes gear. Presses the clutch (no new admissions), waits up to
    /// `timeout` for in-flight work to reach zero, swaps the gear in one
    /// step, and releases the clutch. The new gear gets epoch
    /// `current + 1`.
    ///
    /// If the drain does not finish in time, the shift is rolled back: the
    /// clutch is released, the old gear stays engaged, and `new_config`
    /// comes back inside the [`ShiftRefused`]. A gear is never half-shifted.
    ///
    /// After a rollback, the next shift first waits with the clutch up for
    /// [`SHIFT_COOLDOWN_FACTOR`] times as long as the rolled-back shift held
    /// the clutch, so a controller that resubmits at once after every RETRY
    /// cannot keep admission paused nearly all the time. That wait comes
    /// before, and does not count against, `timeout`.
    ///
    /// | reason | outcome | resolution |
    /// |---|---|---|
    /// | `shift_timeout_over_budget` (`timeout` above `max_shift_timeout`) | RETRY | reject |
    /// | `shift_in_progress` (another shift holds the clutch or is cooling down) | RETRY | reject |
    /// | `epoch_mismatch` ([`Self::shift_from`] only) | RETRY | reject |
    /// | `drain_timeout` | RETRY | rollback |
    /// | `epoch_exhausted` (epoch is `u64::MAX`) | TERMINAL_BREACH | reject |
    /// | `halted` (before or during the cooldown or drain, even if reset since) | TERMINAL_BREACH | halt |
    ///
    /// Only one shift runs at a time; a second one gets `shift_in_progress`
    /// at once rather than queueing, so shifts cannot pile up.
    ///
    /// This is last-writer-wins: it does not know which epoch the caller
    /// prepared `new_config` against, so a stale or replayed configuration
    /// is accepted and numbered as the newest gear. When more than one
    /// controller can shift, use [`Self::shift_from`].
    pub fn shift(&self, new_config: G, timeout: Duration) -> Result<ShiftReport, ShiftRefused<G>> {
        self.shift_checked(None, new_config, timeout)
    }

    /// Like [`Self::shift`], but only if the engaged epoch is still
    /// `expected_epoch` (compare and swap). Otherwise it refuses at once
    /// with RETRY `epoch_mismatch` (reject: nothing changed, the clutch is
    /// never pressed) and hands `new_config` back. The caller re-reads the
    /// current gear, rebuilds its configuration against it, and resubmits.
    ///
    /// The check is made under the state lock after this call has taken
    /// ownership of the gearbox, and only the owning shift can change the
    /// epoch, so the epoch is still `expected_epoch` when the swap happens.
    pub fn shift_from(
        &self,
        expected_epoch: u64,
        new_config: G,
        timeout: Duration,
    ) -> Result<ShiftReport, ShiftRefused<G>> {
        self.shift_checked(Some(expected_epoch), new_config, timeout)
    }

    fn shift_checked(
        &self,
        expected_epoch: Option<u64>,
        new_config: G,
        timeout: Duration,
    ) -> Result<ShiftReport, ShiftRefused<G>> {
        let span = tracing::info_span!(
            telemetry::SPAN_SHIFT,
            timeout_ms = millis(timeout),
            from_epoch = tracing::field::Empty,
            to_epoch = tracing::field::Empty,
            clutch_held_ms = tracing::field::Empty,
            cooldown_wait_ms = tracing::field::Empty,
            outcome = tracing::field::Empty,
            reason = tracing::field::Empty,
        );
        let _entered = span.enter();
        let start = Instant::now();
        let ShiftAttempt {
            result,
            from_epoch,
            clutch_held,
            cooldown_wait,
            retired,
        } = self.shift_inner(expected_epoch, new_config, timeout);
        let outcome = match &result {
            Ok(_) => GateOutcome::Pass,
            Err((reason, _)) => reason.outcome(),
        };
        if let Some(from) = from_epoch {
            span.record("from_epoch", from);
        }
        if let Some(waited) = cooldown_wait {
            span.record("cooldown_wait_ms", millis(waited));
        }
        if let Some(held) = clutch_held {
            span.record("clutch_held_ms", millis(held));
            telemetry::shift_drain(outcome, held);
        }
        telemetry::finish(
            Operation::Shift,
            result.as_ref().map(|_| ()).map_err(|(r, _)| *r),
            start.elapsed(),
        );
        span.record("outcome", outcome.as_str());
        let verdict = match result {
            Ok(report) => {
                span.record("to_epoch", report.to_epoch);
                tracing::info!(
                    from_epoch = report.from_epoch,
                    to_epoch = report.to_epoch,
                    "gear shifted"
                );
                Ok(report)
            }
            Err((reason, config)) => {
                span.record("reason", reason.as_str());
                if reason == Reason::DrainTimeout {
                    tracing::warn!("shift rolled back: in-flight work did not drain in time");
                } else {
                    tracing::debug!(reason = reason.as_str(), "shift refused");
                }
                Err(ShiftRefused {
                    trip: Trip::new(Operation::Shift, reason),
                    config,
                })
            }
        };
        // The replaced gear is dropped last, after the verdict is recorded,
        // and a panic from the caller's `G::drop` is contained here rather
        // than escaping across the request boundary.
        if let Some(old) = retired {
            if catch_unwind(AssertUnwindSafe(move || drop(old))).is_err() {
                telemetry::gear_drop_panicked();
                tracing::error!("dropping the replaced gear panicked; the panic was contained");
            }
        }
        verdict
    }

    fn shift_inner(
        &self,
        expected_epoch: Option<u64>,
        new_config: G,
        timeout: Duration,
    ) -> ShiftAttempt<G> {
        let inner = &self.inner;
        let refuse = |reason, config, from_epoch, cooldown_wait| ShiftAttempt {
            result: Err((reason, config)),
            from_epoch,
            clutch_held: None,
            cooldown_wait,
            retired: None,
        };
        if timeout > inner.config.max_shift_timeout {
            return refuse(Reason::ShiftTimeoutOverBudget, new_config, None, None);
        }

        // Both declared before the lock, so on unwind they drop after the
        // guard: the repair runs outside the poisoned critical section, and
        // a replaced gear is never dropped under the lock. See "Poisoning".
        let mut repair = UnwindRepair::new(inner);
        let mut retired: Option<Arc<Gear<G>>> = None;
        let mut st = inner.lock();
        let from_epoch = st.gear.epoch();
        if st.halted.is_some() {
            return refuse(Reason::Halted, new_config, Some(from_epoch), None);
        }
        if st.clutch || st.shifter {
            return refuse(Reason::ShiftInProgress, new_config, Some(from_epoch), None);
        }
        if expected_epoch.is_some_and(|e| e != from_epoch) {
            return refuse(Reason::EpochMismatch, new_config, Some(from_epoch), None);
        }
        let Some(to_epoch) = from_epoch.checked_add(1) else {
            return refuse(Reason::EpochExhausted, new_config, Some(from_epoch), None);
        };
        let halt_gen = st.halt_gen;

        // Own the gearbox. From here until release no other shift runs, so
        // the epoch cannot move under this call.
        st.shifter = true;
        repair.shifter = true;

        // Wait out the post-rollback cooldown with the clutch up.
        let mut cooldown_wait = None;
        if let Some(until) = st.cooldown_until {
            let waiting_since = Instant::now();
            while let Some(left) = remaining(until) {
                st = inner.wait(&inner.released, st, left);
                if st.halted.is_some() || st.halt_gen != halt_gen {
                    st.shifter = false;
                    repair.shifter = false;
                    let waited = Some(waiting_since.elapsed());
                    return refuse(Reason::Halted, new_config, Some(from_epoch), waited);
                }
            }
            st.cooldown_until = None;
            cooldown_wait = Some(waiting_since.elapsed());
        }

        let pressed_at = Instant::now();
        let Some(deadline) = pressed_at.checked_add(timeout) else {
            st.shifter = false;
            repair.shifter = false;
            return refuse(
                Reason::ShiftTimeoutOverBudget,
                new_config,
                Some(from_epoch),
                cooldown_wait,
            );
        };

        // Press the clutch. From here until release, engage() parks.
        st.clutch = true;
        repair.clutch = true;
        telemetry::set_clutch(true);

        let drained = loop {
            if st.halted.is_some() || st.halt_gen != halt_gen {
                break Err(Reason::Halted);
            }
            if st.in_flight == 0 {
                break Ok(());
            }
            let Some(left) = remaining(deadline) else {
                break Err(Reason::DrainTimeout);
            };
            st = inner.wait(&inner.drained, st, left);
        };

        // Swap (or not) and release, all under the one lock acquisition, so
        // no engage() can observe the clutch up with the old gear after a
        // successful drain, or the new gear before it.
        let swapped = match drained {
            Ok(()) => {
                let old = std::mem::replace(&mut st.gear, Arc::new(Gear::new(to_epoch, new_config)));
                // Handed out of the lock; dropped by `shift_checked` after
                // the verdict is recorded (or by whoever still holds an Arc).
                retired = Some(old);
                telemetry::set_epoch(to_epoch);
                Ok(())
            }
            Err(reason) => {
                if reason == Reason::DrainTimeout {
                    let held = pressed_at.elapsed().min(inner.config.max_shift_timeout);
                    st.cooldown_until = Instant::now()
                        .checked_add(held.saturating_mul(SHIFT_COOLDOWN_FACTOR));
                }
                Err((reason, new_config))
            }
        };
        st.clutch = false;
        st.shifter = false;
        repair.clutch = false;
        repair.shifter = false;
        telemetry::set_clutch(false);
        let clutch_held = pressed_at.elapsed();
        drop(st);
        inner.released.notify_all();

        let result = swapped.map(|()| ShiftReport {
            from_epoch,
            to_epoch,
            clutch_held,
        });
        ShiftAttempt {
            result,
            from_epoch: Some(from_epoch),
            clutch_held: Some(clutch_held),
            cooldown_wait,
            retired,
        }
    }

    /// Epoch of the engaged gear right now.
    pub fn current_epoch(&self) -> u64 {
        self.inner.lock().gear.epoch()
    }

    /// A copy of the current state.
    pub fn status(&self) -> TransmissionStatus {
        let st = self.inner.lock();
        TransmissionStatus {
            epoch: st.gear.epoch(),
            in_flight: st.in_flight,
            waiting_engagers: st.waiting_engagers,
            clutch_pressed: st.clutch,
            halted: st.halted,
        }
    }

    /// Stops the transmission: every later `engage()` and `shift()` gets
    /// TERMINAL_BREACH `halted`, a shift that is draining (or cooling down)
    /// rolls back, and callers parked on the clutch are refused. This holds
    /// even if [`Self::operator_reset`] follows before they wake.
    /// Guards already issued keep running on their gear. Returns `true` if
    /// this call caused the halt, `false` if it was already halted.
    pub fn operator_halt(&self) -> bool {
        let _entered = tracing::info_span!(telemetry::SPAN_OPERATOR_HALT).entered();
        let mut st = self.inner.lock();
        self.inner.halt_locked(&mut st, HaltCause::Operator)
    }

    /// Clears a halt so work is admitted again. Returns `true` if a halt was
    /// cleared. The engaged gear and in-flight count are untouched. A shift
    /// or parked `engage()` that was waiting when the halt happened is
    /// still refused; the reset only affects calls made after the halt.
    pub fn operator_reset(&self) -> bool {
        let _entered = tracing::info_span!(telemetry::SPAN_OPERATOR_RESET).entered();
        let mut st = self.inner.lock();
        let Some(cause) = st.halted.take() else {
            return false;
        };
        telemetry::set_halted(false);
        drop(st);
        telemetry::operator_reset();
        tracing::warn!(previous_cause = cause.as_str(), "transmission reset by operator");
        true
    }
}

/// Everything `shift()` needs to report, whatever happened.
struct ShiftAttempt<G> {
    result: Result<ShiftReport, (Reason, G)>,
    from_epoch: Option<u64>,
    clutch_held: Option<Duration>,
    /// How long the call waited out a post-rollback cooldown, if it did.
    cooldown_wait: Option<Duration>,
    /// The replaced gear after a successful swap, dropped by the caller of
    /// `shift_inner` once the verdict is recorded.
    retired: Option<Arc<Gear<G>>>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use metrics_util::debugging::{DebugValue, DebuggingRecorder};

    const SHORT: Duration = Duration::from_millis(20);

    fn tx() -> Transmission<u32> {
        Transmission::new(0, TransmissionConfig::default()).unwrap()
    }

    /// Poisons the state mutex the only way std allows: a thread panics
    /// while holding it.
    fn poison(t: &Transmission<u32>) {
        let inner = Arc::clone(&t.inner);
        let joined = std::thread::spawn(move || {
            let _held = inner.state.lock();
            panic!("test fixture: poison the transmission lock");
        })
        .join();
        assert!(joined.is_err());
        assert!(t.inner.state.is_poisoned());
    }

    fn counter(snap: &[(metrics_util::CompositeKey, DebugValue)], name: &str) -> u64 {
        snap.iter()
            .filter(|(k, _)| k.key().name() == name)
            .map(|(_, v)| match v {
                DebugValue::Counter(c) => *c,
                _ => 0,
            })
            .sum()
    }

    #[test]
    fn poisoned_lock_is_recovered_and_halts() {
        let recorder = DebuggingRecorder::new();
        let snapshotter = recorder.snapshotter();
        let t = tx();
        let guard = t.engage(SHORT).unwrap();
        poison(&t);

        metrics::with_local_recorder(&recorder, || {
            // The first call after poisoning recovers and halts.
            let trip = t.engage(SHORT).unwrap_err();
            assert_eq!(trip.reason, Reason::Halted);
            assert_eq!(trip.outcome(), GateOutcome::TerminalBreach);
            assert!(!t.inner.state.is_poisoned());
            assert_eq!(t.status().halted, Some(HaltCause::Poisoned));

            // A guard issued before the poison still decrements.
            drop(guard);
            assert_eq!(t.status().in_flight, 0);

            let refused = t.shift(1, SHORT).unwrap_err();
            assert_eq!(refused.trip().reason, Reason::Halted);
            assert_eq!(refused.into_config(), 1);

            assert!(t.operator_reset());
            assert!(t.engage(SHORT).is_ok());
            assert_eq!(t.shift(2, SHORT).unwrap().to_epoch, 1);
        });

        let snap: Vec<_> = snapshotter
            .snapshot()
            .into_vec()
            .into_iter()
            .map(|(k, _, _, v)| (k, v))
            .collect();
        assert_eq!(counter(&snap, telemetry::LOCK_POISON_RECOVERIES_TOTAL), 1);
        assert_eq!(counter(&snap, telemetry::HALTS_TOTAL), 1);
        assert_eq!(counter(&snap, telemetry::OPERATOR_RESETS_TOTAL), 1);
        let poisoned = snap.iter().any(|(k, _)| {
            k.key().name() == telemetry::HALTS_TOTAL
                && k.key().labels().any(|l| l.key() == "cause" && l.value() == "poisoned")
        });
        assert!(poisoned);
    }

    #[test]
    fn poison_during_drain_rolls_the_shift_back_under_halt() {
        let t = Transmission::new(0u32, TransmissionConfig::default()).unwrap();
        let guard = t.engage(SHORT).unwrap();
        let t2 = t.clone();
        let shifter = std::thread::spawn(move || t2.shift(1, Duration::from_secs(5)));
        while !t.status().clutch_pressed {
            std::thread::yield_now();
        }
        poison(&t);
        // Wake the parked shifter without taking the lock, so it is the one
        // that finds the poison (the Condvar::wait_timeout error path).
        t.inner.drained.notify_all();
        let refused = shifter.join().unwrap();
        let refused = refused.unwrap_err();
        assert_eq!(refused.trip().reason, Reason::Halted);
        assert_eq!(refused.into_config(), 1);
        drop(guard);
        let s = t.status();
        assert_eq!(s.halted, Some(HaltCause::Poisoned));
        assert_eq!(s.epoch, 0);
        assert!(!s.clutch_pressed);
        assert_eq!(s.in_flight, 0);
    }

    #[test]
    fn epoch_exhaustion_is_terminal_and_changes_nothing() {
        let t = tx();
        t.inner.lock().gear = Arc::new(Gear::new(u64::MAX, 9));
        let refused = t.shift(1, SHORT).unwrap_err();
        assert_eq!(refused.trip().reason, Reason::EpochExhausted);
        assert_eq!(refused.trip().outcome(), GateOutcome::TerminalBreach);
        let s = t.status();
        assert_eq!(s.epoch, u64::MAX);
        assert!(!s.clutch_pressed);
        assert_eq!(*t.engage(SHORT).unwrap(), 9);
    }

    #[test]
    fn rollback_starts_a_cooldown_that_the_next_shift_waits_out() {
        let t = tx();
        let g = t.engage(SHORT).unwrap();
        let held = t.shift(1, SHORT).unwrap_err();
        assert_eq!(held.trip().reason, Reason::DrainTimeout);
        drop(g);
        let started = Instant::now();
        let r = t.shift(1, SHORT).unwrap();
        assert_eq!(r.to_epoch, 1);
        // Held for at least SHORT, so the cooldown is at least 2 * SHORT.
        assert!(started.elapsed() >= SHORT * SHIFT_COOLDOWN_FACTOR);
        assert!(t.inner.lock().cooldown_until.is_none());
    }

    #[test]
    fn halt_during_cooldown_refuses_the_waiting_shift_even_after_reset() {
        let t = tx();
        let g = t.engage(SHORT).unwrap();
        let _ = t.shift(1, Duration::from_millis(200)).unwrap_err();
        drop(g);
        let t2 = t.clone();
        let shifter = std::thread::spawn(move || t2.shift(1, SHORT));
        while !t.inner.lock().shifter {
            std::thread::yield_now();
        }
        // A second shifter is refused while the first one cools down.
        let refused = t.shift(2, SHORT).unwrap_err();
        assert_eq!(refused.trip().reason, Reason::ShiftInProgress);
        assert!(t.operator_halt());
        assert!(t.operator_reset());
        let refused = shifter.join().unwrap().unwrap_err();
        assert_eq!(refused.trip().reason, Reason::Halted);
        let st = t.inner.lock();
        assert!(!st.shifter && !st.clutch);
        assert_eq!(st.gear.epoch(), 0);
    }

    #[test]
    fn shift_from_the_current_epoch_succeeds() {
        let t = tx();
        assert_eq!(t.shift_from(0, 1, SHORT).unwrap().to_epoch, 1);
        let refused = t.shift_from(0, 2, SHORT).unwrap_err();
        assert_eq!(refused.trip().reason, Reason::EpochMismatch);
        assert_eq!(refused.into_config(), 2);
        assert_eq!(t.shift_from(1, 3, SHORT).unwrap().to_epoch, 2);
    }

    struct TestFixtureDropBomb;
    impl Drop for TestFixtureDropBomb {
        fn drop(&mut self) {
            if !std::thread::panicking() {
                panic!("test fixture: G::drop panics");
            }
        }
    }

    #[test]
    fn panicking_gear_drop_is_contained_and_counted() {
        let recorder = DebuggingRecorder::new();
        let snapshotter = recorder.snapshotter();
        let t = Transmission::new(Some(TestFixtureDropBomb), TransmissionConfig::default()).unwrap();
        metrics::with_local_recorder(&recorder, || {
            assert_eq!(t.shift(None, SHORT).unwrap().to_epoch, 1);
        });
        let snap: Vec<_> = snapshotter
            .snapshot()
            .into_vec()
            .into_iter()
            .map(|(k, _, _, v)| (k, v))
            .collect();
        assert_eq!(counter(&snap, telemetry::GEAR_DROP_PANICS_TOTAL), 1);
        assert_eq!(counter(&snap, telemetry::SHIFT_TOTAL), 1);
    }

    #[test]
    fn invariant_breach_halts_instead_of_underflowing() {
        let t = tx();
        let g = t.engage(SHORT).unwrap();
        t.inner.lock().in_flight = 0;
        drop(g);
        let s = t.status();
        assert_eq!(s.in_flight, 0);
        assert_eq!(s.halted, Some(HaltCause::Invariant));
    }
}
