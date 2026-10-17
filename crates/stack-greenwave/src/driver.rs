//! A small tokio wrapper that drives the pure core with real time.
//!
//! The core never sleeps. This module supplies the two things it needs from
//! the outside world: a real monotonic clock ([`TokioClock`]) and a loop that
//! polls once at start and then at every phase start, calling
//! [`TrafficCop::poll`]. It also holds
//! completed results until their quantized release time with `sleep_until`.
//!
//! ## Waking on the phase grid, off the async runtime
//!
//! [`GreenWaveDriver::run_phases`] runs its loop on a thread of tokio's
//! blocking pool (`spawn_blocking`), not as an async task. There it sleeps
//! with the operating system's timer (`std::thread::sleep`) until shortly
//! before each phase start ([`DRIVER_EARLY_WAKE_NS`]), busy-waits through the
//! boundary, and polls. Two measured problems with an async loop motivated
//! this:
//!
//! - tokio's timer has 1 ms resolution and rounds deadlines up, so an async
//!   `sleep_until(phase start)` often woke in the next 1 ms phase and missed
//!   the one it aimed at, even on an idle runtime;
//! - a timer-woken task still has to be scheduled, and with thousands of
//!   runnable tasks (for example a flood of refused admits on one lane) the
//!   dispatch task woke hundreds of milliseconds late, delaying every other
//!   lane's turn.
//!
//! A dedicated thread is scheduled by the OS, so neither the timer wheel nor
//! the async run queue sits between the phase start and the poll. The costs
//! are one blocking-pool thread per running `run_phases` call and the
//! busy-wait (a fifth of a core for 1 ms phases). [`GreenWaveDriver::new`]
//! refuses phases shorter than [`DRIVER_MIN_PHASE_LEN_NS`] (1 ms): below
//! that, OS wake-up jitter is a large share of a phase.
//!
//! Known limit: when every CPU is busy, the kernel decides when the thread
//! runs. On the 4 vCPU, HZ=250, `PREEMPT_NONE` test machine, with all four
//! vCPUs held by other runnable threads, the thread was measured waking up
//! to about 4 ms (one scheduler tick) late, busy-wait or not. A 1 ms grid
//! then loses phases; a 5 ms grid mostly does not. Lost phases are counted
//! in `tack_greenwave_phases_missed_total`, and the fairness bound holds only
//! when no phase is lost. Raising the thread's scheduling priority would
//! need `unsafe` system calls and privileges and is not done here.
//!
//! ## Why a flood on one lane cannot hold up the poll
//!
//! Three measures, each found necessary by measurement:
//!
//! 1. **Full lanes refuse without the lock.** The driver keeps a lock-free
//!    copy of each lane's queue depth, the halt flag and the clock
//!    watermark, updated under the lock after every operation. An `admit`
//!    to a lane whose copy says full is refused right there with the same
//!    verdict the core would give (`QueueFull`, RETRY, reject, `retry_after`
//!    the lane's next phase start, from the same immutable phase table), and
//!    is counted the same way. So a flood of refused admits never touches
//!    the shared lock, and the poll never waits for a flooding thread that
//!    the OS descheduled while holding it (measured at 3 to 8 ms per stall on
//!    a busy machine). Anything the copy cannot settle (room in the queue, a
//!    halt, a possible clock regression, an unknown lane) takes the lock and
//!    gets the core's verdict. The copy can only be stale towards "full" for
//!    the instant between a poll draining a queue and the copy's update, so
//!    the worst a stale copy does is one spurious RETRY; it never admits.
//! 2. **A synchronous lock.** The cop sits behind a `std::sync::Mutex`, not
//!    an async one. Every critical section is a few microseconds of pure
//!    computation and the lock is never held across an `.await`, so the poll
//!    never queues behind other *tasks*. (With the earlier FIFO async mutex
//!    the poll queued behind every waiting admit.)
//! 3. **The poll goes first.** `std::sync::Mutex` is not fair. While the
//!    dispatch loop waits for the lock, async callers yield before taking it
//!    (at most [`DRIVER_MAX_GIVE_WAY_YIELDS`] times), and the loop takes the
//!    lock once per phase.
//!
//! ## No request is taken out of a queue that cannot be handed on
//!
//! Before each poll the driver reserves room in the sink, and the poll
//! dispatches at most as many requests as it holds room for. A slow consumer
//! delays the poll (and the phase may be missed and counted); a closed sink
//! stops the loop before anything is dequeued. Dispatched payloads are never
//! dropped by the driver.
//!
//! Timing note: tokio timers fire at or after their deadline, never before,
//! so a released result leaves at the epoch boundary plus scheduler jitter.
//! That jitter is noise from the runtime, not a function of the request, but
//! it is not zero; the ANC components are what bound it further.
//!
//! Metrics note: the dispatch loop runs on its own thread, so its metrics go
//! to the process-global recorder, not to a thread-local one installed with
//! `metrics::with_local_recorder` on the caller's thread.

use std::fmt;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::Duration;

use tokio::runtime::Handle;
use tokio::sync::mpsc;
use tokio::time::{sleep_until, Instant};
use tracing::Instrument;

use crate::clock::{Clock, Nanos};
use crate::config::{
    GreenWaveConfig, DRIVER_EARLY_WAKE_NS, DRIVER_MAX_GIVE_WAY_YIELDS, DRIVER_MAX_SPIN_ITERS,
    DRIVER_MIN_PHASE_LEN_NS,
};
use crate::cop::{Admitted, DispatchTicket, Dispatched, Refused, Release, TrafficCop};
use crate::error::{ConfigError, Op, Trip, TripReason};
use crate::table::PhaseTable;
use crate::telemetry;
use crate::timing::Timing;
use crate::LaneId;

/// A monotonic clock on tokio's `Instant`, counting from its creation.
#[derive(Debug, Clone, Copy)]
pub struct TokioClock {
    origin: Instant,
}

impl TokioClock {
    /// A clock whose origin is now.
    #[must_use]
    pub fn new() -> Self {
        Self {
            origin: Instant::now(),
        }
    }

    /// The tokio instant for clock time `t`, or `None` if it does not fit.
    #[must_use]
    pub fn instant_at(&self, t: Nanos) -> Option<Instant> {
        self.origin.checked_add(Duration::from_nanos(t))
    }
}

impl Default for TokioClock {
    fn default() -> Self {
        Self::new()
    }
}

impl Clock for TokioClock {
    fn now(&self) -> Nanos {
        // Saturates after 584 years of uptime rather than wrapping.
        u64::try_from(self.origin.elapsed().as_nanos()).unwrap_or(u64::MAX)
    }
}

/// Sets the flag when dropped, so a dropped `run_phases` future stops its
/// blocking-pool loop.
struct StopOnDrop(Arc<AtomicBool>);

impl Drop for StopOnDrop {
    fn drop(&mut self) {
        self.0.store(true, Ordering::Relaxed);
    }
}

/// One lane's lock-free depth copy.
struct LaneMirror {
    cap: usize,
    depth: AtomicUsize,
}

/// State shared by every clone of a driver.
struct Shared<T> {
    cop: Mutex<TrafficCop<T, TokioClock>>,
    /// Dispatch loops currently waiting for the lock. While non-zero, async
    /// callers give way before taking the lock.
    pollers_waiting: AtomicUsize,
    /// Copies of core state for refusing full lanes without the lock. Written
    /// only under the lock, read without it.
    lanes: Vec<LaneMirror>,
    halted: AtomicBool,
    watermark: AtomicU64,
    /// Immutable copies of the core's grid and table, for `retry_after`.
    timing: Timing,
    table: PhaseTable,
}

impl<T> Shared<T> {
    /// Refresh the lock-free copies from the locked core. At most
    /// [`crate::config::MAX_LANES`] stores.
    fn sync(&self, cop: &TrafficCop<T, TokioClock>) {
        for (i, m) in self.lanes.iter().enumerate() {
            let depth = LaneId::from_index(i)
                .and_then(|l| cop.lane_depth(l))
                .unwrap_or(0);
            m.depth.store(depth, Ordering::Release);
        }
        self.halted.store(cop.is_halted(), Ordering::Release);
        self.watermark.store(cop.watermark(), Ordering::Release);
    }
}

/// Shared handle to a cop driven by real time. Cloning shares the cop.
pub struct GreenWaveDriver<T> {
    shared: Arc<Shared<T>>,
    clock: TokioClock,
    early_wake: Nanos,
    max_dispatch: u32,
}

impl<T> Clone for GreenWaveDriver<T> {
    fn clone(&self) -> Self {
        Self {
            shared: Arc::clone(&self.shared),
            clock: self.clock,
            early_wake: self.early_wake,
            max_dispatch: self.max_dispatch,
        }
    }
}

impl<T> fmt::Debug for GreenWaveDriver<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("GreenWaveDriver")
            .field("clock", &self.clock)
            .finish_non_exhaustive()
    }
}

impl<T: Send + 'static> GreenWaveDriver<T> {
    /// Build a cop on a fresh [`TokioClock`].
    ///
    /// # Errors
    /// Any [`ConfigError`] from [`TrafficCop::new`], or
    /// [`ConfigError::PhaseTooShortForDriver`] if `phase_len_ns` is below
    /// [`DRIVER_MIN_PHASE_LEN_NS`]. Both are counted in
    /// `tack_greenwave_config_rejected_total`.
    pub fn new(config: &GreenWaveConfig) -> Result<Self, ConfigError> {
        if config.phase_len_ns < DRIVER_MIN_PHASE_LEN_NS {
            let err = ConfigError::PhaseTooShortForDriver {
                phase_len_ns: config.phase_len_ns,
                min: DRIVER_MIN_PHASE_LEN_NS,
            };
            telemetry::record_config_rejected(&err);
            tracing::warn!(reason = err.as_str(), "configuration refused by the driver");
            return Err(err);
        }
        let clock = TokioClock::new();
        let cop = TrafficCop::new(config, clock)?;
        let lanes = config
            .lanes
            .iter()
            .map(|l| LaneMirror {
                cap: l.queue_cap as usize,
                depth: AtomicUsize::new(0),
            })
            .collect();
        let shared = Shared {
            pollers_waiting: AtomicUsize::new(0),
            lanes,
            halted: AtomicBool::new(false),
            watermark: AtomicU64::new(cop.watermark()),
            timing: *cop.timing(),
            table: cop.phase_table().clone(),
            cop: Mutex::new(cop),
        };
        Ok(Self {
            shared: Arc::new(shared),
            clock,
            early_wake: DRIVER_EARLY_WAKE_NS.min(config.phase_len_ns / 2),
            max_dispatch: config.max_dispatch_per_phase,
        })
    }

    /// Lock the cop. The lock is only ever held for synchronous calls into
    /// the core, never across an `.await`. No core method panics, so a
    /// poisoned lock can only come from a panic in a caller's `with_cop`
    /// closure; the core's state is still consistent then, so the guard is
    /// recovered rather than turned into a panic here.
    fn lock(&self) -> MutexGuard<'_, TrafficCop<T, TokioClock>> {
        self.shared.cop.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Lock for the dispatch loop: announce the wait so async callers give
    /// way (see [`GreenWaveDriver::lock_async`]).
    fn lock_for_poll(&self) -> MutexGuard<'_, TrafficCop<T, TokioClock>> {
        self.shared.pollers_waiting.fetch_add(1, Ordering::SeqCst);
        let guard = self.lock();
        self.shared.pollers_waiting.fetch_sub(1, Ordering::SeqCst);
        guard
    }

    /// Lock for async callers: first yield while a dispatch loop is waiting
    /// for the lock, at most [`DRIVER_MAX_GIVE_WAY_YIELDS`] times, then take
    /// it. The guard is never held across an `.await`.
    async fn lock_async(&self) -> MutexGuard<'_, TrafficCop<T, TokioClock>> {
        let mut yields: u32 = 0;
        while self.shared.pollers_waiting.load(Ordering::SeqCst) > 0 && yields < DRIVER_MAX_GIVE_WAY_YIELDS {
            tokio::task::yield_now().await;
            yields = yields.saturating_add(1);
        }
        self.lock()
    }

    /// The lock-free refusal for a full lane, or `None` when only the core
    /// can decide. Gives exactly the core's verdict for a full lane: the core
    /// checks halt and clock regression first, then the lane, then the
    /// depth, and each of those cases falls through to the core here.
    fn refuse_full_lane(&self, lane: LaneId) -> Option<Trip> {
        let s = &self.shared;
        let m = s.lanes.get(lane.index())?;
        if s.halted.load(Ordering::Acquire) || m.depth.load(Ordering::Acquire) < m.cap {
            return None;
        }
        let now = self.clock.now();
        if now < s.watermark.load(Ordering::Acquire) {
            return None; // possible regression: let the core halt
        }
        let abs = s.table.next_phase_after(lane, s.timing.abs_phase(now))?;
        let retry_after = s.timing.phase_start(abs)?;
        let trip = Trip::new(Op::Admit, TripReason::QueueFull, Some(retry_after));
        telemetry::record_trip(&trip);
        telemetry::record_op(Op::Admit, trip.outcome());
        Some(trip)
    }

    /// The driver's clock, for converting grid times to instants.
    #[must_use]
    pub const fn clock(&self) -> &TokioClock {
        &self.clock
    }

    /// Admit a request. See [`TrafficCop::admit`]. A lane that is already
    /// full is refused without taking the lock (see the module
    /// documentation); the verdict is the same.
    ///
    /// # Errors
    /// As [`TrafficCop::admit`].
    pub async fn admit(&self, lane: LaneId, payload: T) -> Result<Admitted, Refused<T>> {
        {
            let _guard = tracing::debug_span!("tack.greenwave.admit", lane = lane.index()).entered();
            if let Some(trip) = self.refuse_full_lane(lane) {
                return Err(Refused { trip, payload });
            }
        }
        let mut cop = self.lock_async().await;
        let result = cop.admit(lane, payload);
        self.shared.sync(&cop);
        result
    }

    /// Run the cop with a closure over the locked core, for inspection or an
    /// operator [`TrafficCop::reset`]. The closure runs under a synchronous
    /// lock that the dispatch loop also needs, so it must be short and must
    /// not block.
    pub async fn with_cop<R>(&self, f: impl FnOnce(&mut TrafficCop<T, TokioClock>) -> R) -> R {
        let mut cop = self.lock_async().await;
        let out = f(&mut cop);
        self.shared.sync(&cop);
        out
    }

    /// Bring this OS thread to clock time `deadline`: sleep until
    /// `early_wake` before it, then busy-wait on the CPU until it arrives.
    /// A sleeping thread can wake late by a scheduler time slice when every
    /// CPU is busy; waking early absorbs that lateness, so the poll runs at
    /// the phase start. The busy-wait ends at the deadline or after
    /// [`DRIVER_MAX_SPIN_ITERS`] iterations.
    fn sleep_until_blocking(&self, deadline: Nanos) {
        let wake = deadline.saturating_sub(self.early_wake);
        let now = self.clock.now();
        if now < wake {
            std::thread::sleep(Duration::from_nanos(wake - now));
        }
        let mut iters: u32 = 0;
        while self.clock.now() < deadline && iters < DRIVER_MAX_SPIN_ITERS {
            std::hint::spin_loop();
            iters = iters.saturating_add(1);
        }
    }

    /// Reserve room in `sink` for the next poll: as many slots as are free
    /// now, up to `cap`, and at least one (waiting for it if the sink is
    /// full). `None` if the sink is closed.
    fn reserve<'a>(
        handle: &Handle,
        sink: &'a mpsc::Sender<Dispatched<T>>,
        cap: usize,
    ) -> Option<mpsc::PermitIterator<'a, Dispatched<T>>> {
        let free = sink.capacity().min(cap);
        if free > 0 {
            if let Ok(permits) = sink.try_reserve_many(free) {
                return Some(permits);
            }
        }
        handle.block_on(sink.reserve_many(1)).ok()
    }

    /// The dispatch loop, on a blocking-pool thread. See
    /// [`GreenWaveDriver::run_phases`]. Takes the lock once per phase.
    fn drive_blocking(
        &self,
        handle: &Handle,
        sink: &mpsc::Sender<Dispatched<T>>,
        max_phases: u64,
        stop: &AtomicBool,
    ) -> Result<u64, Trip> {
        let cap = usize::try_from(self.max_dispatch)
            .unwrap_or(usize::MAX)
            .min(sink.max_capacity());
        let mut sent: u64 = 0;
        // The first poll runs at once, in the current phase: any poll inside
        // a phase serves it, and waiting for the next phase start would cost
        // the current phase's owner its turn.
        let mut next = Some(self.clock.now());
        for _ in 0..max_phases {
            if sink.is_closed() || stop.load(Ordering::Relaxed) {
                break;
            }
            let deadline = next.ok_or_else(|| Trip::new(Op::Poll, TripReason::Overflow, None))?;
            // Waits for room (backpressure). A closed sink ends the loop
            // before anything is dequeued.
            let Some(permits) = Self::reserve(handle, sink, cap) else {
                break;
            };
            self.sleep_until_blocking(deadline);
            let limit = u32::try_from(permits.len()).unwrap_or(u32::MAX);
            let batch = {
                let mut cop = self.lock_for_poll();
                let batch = cop.poll_limited(limit);
                next = cop.next_phase_start();
                self.shared.sync(&cop);
                batch
            }?;
            // batch.len() <= limit == permits.len(), so every item has a
            // permit; unused permits are released when dropped.
            for (item, permit) in batch.into_iter().zip(permits) {
                permit.send(item);
                sent = sent.saturating_add(1);
            }
        }
        Ok(sent)
    }

    /// Poll once at once, in the current phase, then at each following phase
    /// start, `max_phases` polls in all, and send every dispatched request to
    /// `sink`. Returns the number of requests
    /// sent. Stops early, with `Ok`, if `sink` is closed; nothing is taken
    /// out of a queue once the sink is closed.
    ///
    /// The loop runs on a blocking-pool thread (see the module
    /// documentation); this future only waits for it. If this future is
    /// dropped, the loop stops at its next phase (or, if it is waiting for
    /// room in `sink`, once room appears or the sink closes).
    ///
    /// Before each poll the loop reserves room in `sink` (the free slots, up
    /// to the per-phase budget, and at least one), and the poll dispatches no
    /// more than that. Waiting for room is backpressure on the consumer;
    /// while it waits the next phase may be missed (and counted as missed by
    /// the cop). A sink with less free room than the per-phase budget caps
    /// dispatch per poll at its free room.
    ///
    /// # Errors
    /// Any [`Trip`] from `poll` (a halted cop); [`TripReason::Overflow`] if
    /// the next phase start does not fit in `u64`; or
    /// [`TripReason::DriverStopped`] if the runtime would not run the loop.
    pub async fn run_phases(&self, sink: &mpsc::Sender<Dispatched<T>>, max_phases: u64) -> Result<u64, Trip> {
        let span = tracing::info_span!("tack.greenwave.drive", max_phases);
        let handle = Handle::current();
        let stop = Arc::new(AtomicBool::new(false));
        let _stop_on_drop = StopOnDrop(Arc::clone(&stop));
        let this = self.clone();
        let sink = sink.clone();
        let join = tokio::task::spawn_blocking(move || {
            let result = span.in_scope(|| this.drive_blocking(&handle, &sink, max_phases, &stop));
            // Release this sender before reporting, so a caller that drops
            // its own sender after we return sees the channel close.
            drop(sink);
            result
        });
        match join.await {
            Ok(result) => result,
            Err(_) => {
                let trip = Trip::new(Op::Poll, TripReason::DriverStopped, None);
                telemetry::record_trip(&trip);
                Err(trip)
            }
        }
    }

    /// Run until `sink` is closed or the cop halts. A service loop; its
    /// lifetime bound is the consumer's.
    ///
    /// # Errors
    /// As [`GreenWaveDriver::run_phases`].
    pub async fn run(&self, sink: &mpsc::Sender<Dispatched<T>>) -> Result<u64, Trip> {
        let mut total: u64 = 0;
        while !sink.is_closed() {
            total = total.saturating_add(self.run_phases(sink, u64::from(u32::MAX)).await?);
        }
        Ok(total)
    }

    /// Record completion now, then sleep until the quantized release time.
    /// Returns the release once it is due.
    ///
    /// # Errors
    /// Any [`Trip`] from [`TrafficCop::complete`], or
    /// [`TripReason::Overflow`] if the release time does not fit in a tokio
    /// `Instant`.
    pub async fn release(&self, ticket: &DispatchTicket) -> Result<Release, Trip> {
        let release = {
            let mut cop = self.lock_async().await;
            let r = cop.complete(ticket);
            self.shared.sync(&cop);
            r
        }?;
        let at = self
            .clock
            .instant_at(release.release_at)
            .ok_or_else(|| Trip::new(Op::Complete, TripReason::Overflow, None))?;
        // TRACE, like `complete`: the span opens at the completion instant.
        sleep_until(at)
            .instrument(tracing::trace_span!("tack.greenwave.release_wait", seq = ticket.id().get()))
            .await;
        Ok(release)
    }
}
