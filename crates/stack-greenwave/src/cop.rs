//! The traffic cop: bounded per-lane queues, phase-gated dispatch, green wave
//! stage checks and release quantization, all on an injected clock.
//!
//! The cop is generic over the payload type `T` and places no trait bound on
//! it, so it cannot read request content even by accident. Every decision it
//! makes (admit, shed, dispatch, retry-after, release time) is a function of
//! the lane, the queue depth, and the clock: public information only.
//!
//! Tickets are bound to the cop that issued them. Each cop takes a
//! process-unique issuer number when it is built and stamps it on every
//! ticket, and each lane keeps a bounded set of its live (dispatched, not yet
//! completed) tickets. `stage_check` and `complete` accept only a live ticket
//! of this cop, and `complete` retires it, so a ticket from another cop, a
//! replayed completion, or a stage check after completion is refused.

use std::collections::{BTreeMap, VecDeque};
use std::fmt;
use std::sync::atomic::{AtomicU64, Ordering};

use crate::clock::{Clock, Nanos};
use crate::config::{live_ticket_cap, GreenWaveConfig};
use crate::error::{ConfigError, Op, Trip, TripReason};
use crate::outcome::GateOutcome;
use crate::table::PhaseTable;
use crate::telemetry;
use crate::timing::Timing;
use crate::wave::{GreenWave, StageSlot};
use crate::LaneId;

/// Identifier the cop assigns to each admitted request: its lane and its
/// sequence number in that lane's admission order.
///
/// Sequence numbers are per lane, not global, so the ids a tenant sees on its
/// own requests reveal nothing about how many requests other lanes admitted
/// in between. The pair is unique within one cop.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct RequestId {
    lane: LaneId,
    seq: u64,
}

impl RequestId {
    /// The sequence number within the request's lane, counting from 0.
    /// Unique only together with [`RequestId::lane`].
    #[must_use]
    pub const fn get(self) -> u64 {
        self.seq
    }

    /// The lane whose sequence this id belongs to.
    #[must_use]
    pub const fn lane(self) -> LaneId {
        self.lane
    }
}

/// Source of process-unique issuer numbers, one per cop.
static NEXT_ISSUER: AtomicU64 = AtomicU64::new(1);

/// Receipt for an admitted request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Admitted {
    /// The id the dispatched ticket will carry.
    pub id: RequestId,
    /// The lane it waits in.
    pub lane: LaneId,
    /// Clock time of admission.
    pub arrived_at: Nanos,
    /// Requests ahead of it in its lane at admission.
    pub position: u32,
}

/// Proof of dispatch. Only the cop constructs one, so its times are on the
/// cop's clock and its phase is on the cop's grid. It carries the issuing
/// cop's number, and the cop accepts it only while it is live (see the
/// module documentation).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DispatchTicket {
    issuer: u64,
    id: RequestId,
    lane: LaneId,
    arrived_at: Nanos,
    dispatched_at: Nanos,
    dispatch_phase: u64,
}

impl DispatchTicket {
    /// The request id.
    #[must_use]
    pub const fn id(&self) -> RequestId {
        self.id
    }
    /// The lane it was dispatched from.
    #[must_use]
    pub const fn lane(&self) -> LaneId {
        self.lane
    }
    /// Clock time of admission.
    #[must_use]
    pub const fn arrived_at(&self) -> Nanos {
        self.arrived_at
    }
    /// Clock time of dispatch.
    #[must_use]
    pub const fn dispatched_at(&self) -> Nanos {
        self.dispatched_at
    }
    /// Absolute phase of dispatch. Always owned by `lane`.
    #[must_use]
    pub const fn dispatch_phase(&self) -> u64 {
        self.dispatch_phase
    }
    /// Time spent queued.
    #[must_use]
    pub const fn queue_wait(&self) -> Nanos {
        self.dispatched_at.saturating_sub(self.arrived_at)
    }
}

/// A dispatched request: its ticket and its untouched payload.
pub struct Dispatched<T> {
    /// Proof of dispatch.
    pub ticket: DispatchTicket,
    /// The payload exactly as admitted.
    pub payload: T,
}

impl<T> fmt::Debug for Dispatched<T> {
    // The payload is request content and is never printed.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Dispatched")
            .field("ticket", &self.ticket)
            .finish_non_exhaustive()
    }
}

/// An admission refusal. The payload is handed back so the caller can retry
/// without having to keep a copy.
pub struct Refused<T> {
    /// Why.
    pub trip: Trip,
    /// The payload exactly as submitted.
    pub payload: T,
}

impl<T> fmt::Debug for Refused<T> {
    // The payload is request content and is never printed.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Refused")
            .field("trip", &self.trip)
            .finish_non_exhaustive()
    }
}

/// A stage's light is green for this request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StageClearance {
    /// The stage's slot in the wave.
    pub slot: StageSlot,
    /// True when the stage's phase had already ended: the request fell
    /// behind the wave. Still a PASS; release quantization absorbs lateness
    /// up to the epoch, and refusing late work would only add delay.
    pub late: bool,
}

/// When a completed result may leave.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Release {
    /// The request id.
    pub id: RequestId,
    /// Its lane.
    pub lane: LaneId,
    /// The first epoch boundary strictly after completion.
    pub release_at: Nanos,
    /// Index of the epoch that starts at `release_at`.
    pub release_epoch: u64,
}

struct Queued<T> {
    id: RequestId,
    arrived_at: Nanos,
    payload: T,
}

struct LaneQueue<T> {
    cap: usize,
    items: VecDeque<Queued<T>>,
    /// Next per-lane sequence number.
    next_seq: u64,
    /// Live tickets by sequence number, at most `live_cap` of them.
    live: BTreeMap<u64, DispatchTicket>,
    live_cap: usize,
}

/// The scheduler. See the crate documentation for the design.
pub struct TrafficCop<T, C: Clock> {
    timing: Timing,
    table: PhaseTable,
    wave: GreenWave,
    max_dispatch: u32,
    lanes: Vec<LaneQueue<T>>,
    clock: C,
    issuer: u64,
    last_now: Nanos,
    halted: bool,
    /// The absolute phase last accounted for: the phase of the latest poll,
    /// or of build or reset before any poll.
    current_phase: u64,
    dispatched_in_phase: u32,
    total_queued: usize,
}

impl<T, C: Clock> fmt::Debug for TrafficCop<T, C> {
    // Payloads are never printed; only depths.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let depths: Vec<usize> = self.lanes.iter().map(|l| l.items.len()).collect();
        f.debug_struct("TrafficCop")
            .field("timing", &self.timing)
            .field("owners", &self.table.owners())
            .field("stage_offsets", &self.wave.offsets())
            .field("lane_depths", &depths)
            .field("halted", &self.halted)
            .finish_non_exhaustive()
    }
}

impl<T, C: Clock> TrafficCop<T, C> {
    /// Validate `config`, build the phase table and green wave, and allocate
    /// empty queues. Nothing is sized from anything but the validated config.
    ///
    /// # Errors
    /// Any [`ConfigError`]. Counted in `tack_greenwave_config_rejected_total`.
    pub fn new(config: &GreenWaveConfig, clock: C) -> Result<Self, ConfigError> {
        let span = tracing::info_span!(
            "tack.greenwave.build",
            lanes = config.lanes.len(),
            phases = config.phases_per_epoch,
            stages = config.stage_offsets.len()
        );
        let _guard = span.entered();
        match Self::build(config, clock) {
            Ok(cop) => {
                // Shared gauges are sums over every cop: register, never set.
                telemetry::register_gauges();
                tracing::info!(owners = ?cop.table.owners(), "phase table built");
                Ok(cop)
            }
            Err(err) => {
                telemetry::record_config_rejected(&err);
                tracing::warn!(reason = err.as_str(), "configuration refused");
                Err(err)
            }
        }
    }

    fn build(config: &GreenWaveConfig, clock: C) -> Result<Self, ConfigError> {
        config.validate()?;
        let epoch_len = config
            .epoch_len_ns()
            .ok_or(ConfigError::EpochTooLong {
                max: crate::config::MAX_EPOCH_NS,
            })?;
        let timing = Timing::new(config.phase_len_ns, config.phases_per_epoch, epoch_len);
        let weights: Vec<u32> = config.lanes.iter().map(|l| l.weight).collect();
        let table = PhaseTable::build(&weights, config.phases_per_epoch)?;
        let wave = GreenWave::new(config.stage_offsets.clone(), timing);
        let lanes = config
            .lanes
            .iter()
            .map(|l| LaneQueue {
                cap: l.queue_cap as usize,
                items: VecDeque::new(),
                next_seq: 0,
                live: BTreeMap::new(),
                live_cap: live_ticket_cap(l, config.max_dispatch_per_phase),
            })
            .collect();
        let last_now = clock.now();
        // Wrapping after 2^64 builds in one process is not a practical
        // concern; the counter never panics.
        let issuer = NEXT_ISSUER.fetch_add(1, Ordering::Relaxed);
        Ok(Self {
            timing,
            table,
            wave,
            max_dispatch: config.max_dispatch_per_phase,
            lanes,
            clock,
            issuer,
            last_now,
            halted: false,
            // The build phase counts as accounted for, so a driver whose first
            // poll is in the next phase misses nothing, while every later
            // phase that passes before the first poll is counted as missed.
            current_phase: timing.abs_phase(last_now),
            dispatched_in_phase: 0,
            total_queued: 0,
        })
    }

    /// The phase and epoch grid.
    #[must_use]
    pub const fn timing(&self) -> &Timing {
        &self.timing
    }

    /// The weighted round-robin table.
    #[must_use]
    pub const fn phase_table(&self) -> &PhaseTable {
        &self.table
    }

    /// The green wave offset table.
    #[must_use]
    pub const fn green_wave(&self) -> &GreenWave {
        &self.wave
    }

    /// The injected clock.
    #[must_use]
    pub const fn clock(&self) -> &C {
        &self.clock
    }

    /// Requests waiting in `lane`, or `None` for an unknown lane.
    #[must_use]
    pub fn lane_depth(&self, lane: LaneId) -> Option<usize> {
        self.lanes.get(lane.index()).map(|l| l.items.len())
    }

    /// The queue cap of `lane`, or `None` for an unknown lane.
    #[must_use]
    pub fn lane_cap(&self, lane: LaneId) -> Option<usize> {
        self.lanes.get(lane.index()).map(|l| l.cap)
    }

    /// Requests waiting across all lanes.
    #[must_use]
    pub const fn total_queued(&self) -> usize {
        self.total_queued
    }

    /// The clock watermark: the latest clock reading any operation has
    /// accepted. A reading below it is a regression.
    #[must_use]
    pub const fn watermark(&self) -> Nanos {
        self.last_now
    }

    /// True after a clock fault, until [`TrafficCop::reset`].
    #[must_use]
    pub const fn is_halted(&self) -> bool {
        self.halted
    }

    /// The lane that owns the phase containing time `t`.
    #[must_use]
    pub fn owner_at(&self, t: Nanos) -> Option<LaneId> {
        self.table
            .owner(self.timing.phase_in_epoch(self.timing.abs_phase(t)))
    }

    /// Start of the first phase owned by `lane` strictly after the phase
    /// containing `t`. This is the `retry_after` a full queue returns.
    #[must_use]
    pub fn next_lane_phase_start(&self, lane: LaneId, t: Nanos) -> Option<Nanos> {
        let abs = self.table.next_phase_after(lane, self.timing.abs_phase(t))?;
        self.timing.phase_start(abs)
    }

    /// Start of the phase after the one containing the clock's current time.
    /// The tokio driver sleeps until this. Read-only: it does not run the
    /// clock-regression check.
    #[must_use]
    pub fn next_phase_start(&self) -> Option<Nanos> {
        let abs = self.timing.abs_phase(self.clock.now()).checked_add(1)?;
        self.timing.phase_start(abs)
    }

    /// The whole green wave for a dispatched request, in stage order.
    ///
    /// # Errors
    /// [`TripReason::Overflow`] (as a [`Op::StageCheck`] trip) if a due time
    /// does not fit.
    pub fn wave_schedule(&self, ticket: &DispatchTicket) -> Result<Vec<StageSlot>, Trip> {
        self.wave
            .schedule(ticket.dispatch_phase)
            .map_err(|reason| self.trip(Op::StageCheck, reason, None))
    }

    /// Admit a request into `lane`'s queue.
    ///
    /// Reads only the lane, the lane's queue depth and the clock. The payload
    /// is moved in untouched, or handed back in [`Refused`].
    ///
    /// # Errors
    /// - [`TripReason::QueueFull`]: RETRY, reject, `retry_after` is the start
    ///   of the lane's next phase.
    /// - [`TripReason::UnknownLane`]: TERMINAL_BREACH, reject.
    /// - [`TripReason::ClockRegressed`], [`TripReason::Halted`]:
    ///   TERMINAL_BREACH, halt.
    /// - [`TripReason::Overflow`]: TERMINAL_BREACH, reject.
    pub fn admit(&mut self, lane: LaneId, payload: T) -> Result<Admitted, Refused<T>> {
        let _guard = tracing::debug_span!("tack.greenwave.admit", lane = lane.index()).entered();
        match self.try_admit(lane) {
            Ok((now, id, position)) => {
                if let Some(q) = self.lanes.get_mut(lane.index()) {
                    q.items.push_back(Queued {
                        id,
                        arrived_at: now,
                        payload,
                    });
                }
                self.total_queued = self.total_queued.saturating_add(1);
                telemetry::queue_depth_add(1);
                telemetry::record_op(Op::Admit, GateOutcome::Pass);
                tracing::debug!(seq = id.seq, position, arrived_at = now, "admitted");
                Ok(Admitted {
                    id,
                    lane,
                    arrived_at: now,
                    position,
                })
            }
            Err(trip) => {
                telemetry::record_op(Op::Admit, trip.outcome());
                Err(Refused { trip, payload })
            }
        }
    }

    /// Every check in `admit`, with no mutation except the lane's sequence
    /// counter and the clock watermark. Returns the admission time, id and
    /// position.
    fn try_admit(&mut self, lane: LaneId) -> Result<(Nanos, RequestId, u32), Trip> {
        let now = self.observe(Op::Admit)?;
        let Some(q) = self.lanes.get(lane.index()) else {
            return Err(self.trip(Op::Admit, TripReason::UnknownLane, None));
        };
        let depth = q.items.len();
        if depth >= q.cap {
            return Err(match self.next_lane_phase_start(lane, now) {
                Some(t) => self.trip(Op::Admit, TripReason::QueueFull, Some(t)),
                None => self.trip(Op::Admit, TripReason::Overflow, None),
            });
        }
        // depth < cap <= MAX_QUEUE_CAP, so it fits in u32.
        let Ok(position) = u32::try_from(depth) else {
            return Err(self.trip(Op::Admit, TripReason::Overflow, None));
        };
        let seq = q.next_seq;
        let Some(next) = seq.checked_add(1) else {
            return Err(self.trip(Op::Admit, TripReason::Overflow, None));
        };
        if let Some(q) = self.lanes.get_mut(lane.index()) {
            q.next_seq = next;
        }
        Ok((now, RequestId { lane, seq }, position))
    }

    /// Dispatch from the lane that owns the current phase, oldest first, up
    /// to the per-phase budget. Returns an empty batch when the owner's queue
    /// is empty or its budget for this phase is spent. Never dispatches from
    /// a lane outside its own phase.
    ///
    /// The driver must call this at least once per phase. A phase with no
    /// call is lost to its lane (it is not made up later, because making it
    /// up would move that lane's work into another lane's phase) and is
    /// counted in `tack_greenwave_phases_missed_total`. Phases that pass
    /// between building (or resetting) the cop and its first poll count too.
    ///
    /// Each dispatched ticket becomes live in its lane. If the lane is at its
    /// live-ticket cap, its oldest live ticket expires (counted in
    /// `tack_greenwave_tickets_expired_total`).
    ///
    /// # Errors
    /// [`TripReason::ClockRegressed`] or [`TripReason::Halted`]:
    /// TERMINAL_BREACH, halt. Nothing is dispatched.
    pub fn poll(&mut self) -> Result<Vec<Dispatched<T>>, Trip> {
        self.poll_limited(self.max_dispatch)
    }

    /// [`TrafficCop::poll`], dispatching at most `limit` requests. The
    /// driver passes the number of sink slots it holds, so it never takes a
    /// request out of a queue that it cannot hand on. Requests left behind
    /// stay queued; the unspent budget remains usable by another poll in the
    /// same phase.
    ///
    /// # Errors
    /// As [`TrafficCop::poll`].
    pub(crate) fn poll_limited(&mut self, limit: u32) -> Result<Vec<Dispatched<T>>, Trip> {
        let _guard = tracing::debug_span!("tack.greenwave.poll").entered();
        let now = match self.observe(Op::Poll) {
            Ok(n) => n,
            Err(trip) => {
                telemetry::record_op(Op::Poll, trip.outcome());
                return Err(trip);
            }
        };
        let abs = self.timing.abs_phase(now);
        let cur = self.current_phase;
        let missed = abs.saturating_sub(cur).saturating_sub(1);
        if missed > 0 {
            telemetry::record_phases_missed(missed);
            tracing::warn!(missed, from_phase = cur, to_phase = abs, "phases passed without a poll");
        }
        if abs != cur {
            self.current_phase = abs;
            self.dispatched_in_phase = 0;
        }
        let Some(owner) = self.table.owner(self.timing.phase_in_epoch(abs)) else {
            // Unreachable: phase_in_epoch is below the table length.
            telemetry::record_op(Op::Poll, GateOutcome::Pass);
            return Ok(Vec::new());
        };
        let budget = self.max_dispatch.saturating_sub(self.dispatched_in_phase).min(limit) as usize;
        let issuer = self.issuer;
        let Some(q) = self.lanes.get_mut(owner.index()) else {
            telemetry::record_op(Op::Poll, GateOutcome::Pass);
            return Ok(Vec::new());
        };
        let n = budget.min(q.items.len());
        let mut out = Vec::with_capacity(n);
        let mut expired: u64 = 0;
        for _ in 0..n {
            let Some(item) = q.items.pop_front() else { break };
            let ticket = DispatchTicket {
                issuer,
                id: item.id,
                lane: owner,
                arrived_at: item.arrived_at,
                dispatched_at: now,
                dispatch_phase: abs,
            };
            // Bounded: at most live_cap entries per lane. Expiring the oldest
            // touches only this lane's tickets.
            while q.live.len() >= q.live_cap {
                if q.live.pop_first().is_none() {
                    break;
                }
                expired = expired.saturating_add(1);
            }
            q.live.insert(item.id.seq, ticket);
            telemetry::record_queue_wait(ticket.queue_wait());
            out.push(Dispatched {
                ticket,
                payload: item.payload,
            });
        }
        let count = out.len();
        // count <= budget <= MAX_DISPATCH_PER_PHASE, so it fits in u32.
        self.dispatched_in_phase = self
            .dispatched_in_phase
            .saturating_add(u32::try_from(count).unwrap_or(u32::MAX));
        self.total_queued = self.total_queued.saturating_sub(count);
        telemetry::queue_depth_sub(count);
        telemetry::record_dispatched(count as u64);
        if expired > 0 {
            telemetry::record_tickets_expired(expired);
            tracing::warn!(lane = owner.index(), expired, "live tickets expired at the lane cap");
        }
        telemetry::record_op(Op::Poll, GateOutcome::Pass);
        if count > 0 {
            tracing::debug!(lane = owner.index(), phase = abs, count, "dispatched");
        }
        Ok(out)
    }

    /// May `stage` run for this request now?
    ///
    /// PASS once the stage's due phase has started. The clearance says
    /// whether the request is late (its due phase has ended). The ticket
    /// must be a live ticket of this cop.
    ///
    /// The span and events of this call are at TRACE level: their timestamps
    /// would show per-stage progress to a trace reader (see [`telemetry`]).
    ///
    /// # Errors
    /// - [`TripReason::NotYetDue`]: RETRY, reject, `retry_after` is the due
    ///   time. Running early would break the wave for the requests behind it.
    /// - [`TripReason::ForeignTicket`], [`TripReason::TicketNotLive`],
    ///   [`TripReason::UnknownStage`], [`TripReason::Overflow`]:
    ///   TERMINAL_BREACH, reject.
    /// - [`TripReason::ClockRegressed`], [`TripReason::Halted`]:
    ///   TERMINAL_BREACH, halt.
    pub fn stage_check(&mut self, ticket: &DispatchTicket, stage: usize) -> Result<StageClearance, Trip> {
        let _guard =
            tracing::trace_span!("tack.greenwave.stage_check", seq = ticket.id.seq, stage).entered();
        let result = self.try_stage_check(ticket, stage);
        match &result {
            Ok(c) => {
                telemetry::record_op(Op::StageCheck, GateOutcome::Pass);
                if c.late {
                    telemetry::record_stage_late();
                    tracing::trace!(due_at = c.slot.due_at, "stage ran behind the wave");
                }
            }
            Err(trip) => telemetry::record_op(Op::StageCheck, trip.outcome()),
        }
        result
    }

    fn try_stage_check(&mut self, ticket: &DispatchTicket, stage: usize) -> Result<StageClearance, Trip> {
        let now = self.observe(Op::StageCheck)?;
        self.check_live(Op::StageCheck, ticket)?;
        let slot = self
            .wave
            .slot(ticket.dispatch_phase, stage)
            .map_err(|reason| self.trip(Op::StageCheck, reason, None))?;
        if now < slot.due_at {
            return Err(self.trip(Op::StageCheck, TripReason::NotYetDue, Some(slot.due_at)));
        }
        let late = now >= slot.due_at.saturating_add(self.timing.phase_len());
        Ok(StageClearance { slot, late })
    }

    /// Record completion now and return the quantized release time: the
    /// first epoch boundary strictly after the clock's current time. The
    /// ticket must be a live ticket of this cop; a successful completion
    /// retires it, so it cannot be completed or stage-checked again.
    ///
    /// The completion time itself is not logged or put in a metric, and the
    /// span and events of this call are at TRACE level, because any
    /// subscriber stamps them with the completion instant (see
    /// [`telemetry`]).
    ///
    /// # Errors
    /// - [`TripReason::CompletionBeforeDispatch`],
    ///   [`TripReason::ForeignTicket`], [`TripReason::TicketNotLive`],
    ///   [`TripReason::Overflow`]: TERMINAL_BREACH, reject.
    /// - [`TripReason::ClockRegressed`], [`TripReason::Halted`]:
    ///   TERMINAL_BREACH, halt.
    pub fn complete(&mut self, ticket: &DispatchTicket) -> Result<Release, Trip> {
        let _guard = tracing::trace_span!("tack.greenwave.complete", seq = ticket.id.seq).entered();
        let result = self.try_complete(ticket);
        match &result {
            Ok(r) => {
                telemetry::record_op(Op::Complete, GateOutcome::Pass);
                tracing::trace!(release_epoch = r.release_epoch, "release scheduled");
            }
            Err(trip) => telemetry::record_op(Op::Complete, trip.outcome()),
        }
        result
    }

    fn try_complete(&mut self, ticket: &DispatchTicket) -> Result<Release, Trip> {
        let now = self.observe(Op::Complete)?;
        if now < ticket.dispatched_at {
            return Err(self.trip(Op::Complete, TripReason::CompletionBeforeDispatch, None));
        }
        self.check_live(Op::Complete, ticket)?;
        let Some(release_at) = self.timing.release_at(now) else {
            return Err(self.trip(Op::Complete, TripReason::Overflow, None));
        };
        if let Some(q) = self.lanes.get_mut(ticket.lane.index()) {
            q.live.remove(&ticket.id.seq);
        }
        Ok(Release {
            id: ticket.id,
            lane: ticket.lane,
            release_at,
            release_epoch: self.timing.epoch_index(release_at),
        })
    }

    /// Refuse a ticket this cop did not issue, or one that is no longer live.
    fn check_live(&self, op: Op, ticket: &DispatchTicket) -> Result<(), Trip> {
        if ticket.issuer != self.issuer {
            return Err(self.trip(op, TripReason::ForeignTicket, None));
        }
        let live = self
            .lanes
            .get(ticket.lane.index())
            .and_then(|q| q.live.get(&ticket.id.seq));
        if live != Some(ticket) {
            return Err(self.trip(op, TripReason::TicketNotLive, None));
        }
        Ok(())
    }

    /// Operator reset.
    ///
    /// - Halted: clears the halt, takes the clock's current reading as the
    ///   new watermark, and restarts phase accounting from the current phase
    ///   with a fresh budget (time went backwards, so the old counters mean
    ///   nothing). Queued requests stay queued and live tickets stay live;
    ///   tickets issued before the regression may now fail `complete` with
    ///   `CompletionBeforeDispatch`, which is the safe direction.
    /// - Not halted, and the clock has gone backwards since the last
    ///   operation: the reset does not absorb the regression. It trips
    ///   `ClockRegressed` (op `reset`), counts it and halts, exactly as the
    ///   next operation would have. A second reset then clears the halt.
    ///   Check [`TrafficCop::is_halted`] after a reset.
    /// - Not halted, clock fine: nothing changes. In particular the phase
    ///   counters are kept, so a reset cannot refresh a phase's dispatch
    ///   budget.
    pub fn reset(&mut self) {
        let _guard = tracing::info_span!("tack.greenwave.reset", was_halted = self.halted).entered();
        let now = self.clock.now();
        if !self.halted {
            if now < self.last_now {
                // observe() halts, counts the trip and logs it.
                let _ = self.observe(Op::Reset);
                return;
            }
            telemetry::record_reset();
            tracing::info!("reset while not halted: nothing to clear");
            return;
        }
        self.halted = false;
        telemetry::halted_leave();
        self.last_now = now;
        self.current_phase = self.timing.abs_phase(now);
        self.dispatched_in_phase = 0;
        telemetry::record_reset();
        tracing::info!("scheduler reset by operator");
    }

    /// Read the clock, refusing if halted and halting if time went backwards.
    fn observe(&mut self, op: Op) -> Result<Nanos, Trip> {
        if self.halted {
            return Err(self.trip(op, TripReason::Halted, None));
        }
        let now = self.clock.now();
        if now < self.last_now {
            self.halted = true;
            telemetry::halted_enter();
            tracing::error!(
                previous = self.last_now,
                observed = now,
                "clock went backwards; halting until operator reset"
            );
            return Err(self.trip(op, TripReason::ClockRegressed, None));
        }
        self.last_now = now;
        Ok(now)
    }

    /// Build a trip, count it and log it. The one place trips are made.
    /// Trips from `stage_check` and `complete` are logged at TRACE for the
    /// same timestamp reason as their spans.
    fn trip(&self, op: Op, reason: TripReason, retry_after: Option<Nanos>) -> Trip {
        let trip = Trip::new(op, reason, retry_after);
        telemetry::record_trip(&trip);
        match op {
            Op::StageCheck | Op::Complete => tracing::trace!(
                op = op.as_str(),
                reason = reason.as_str(),
                outcome = trip.outcome().as_str(),
                resolution = trip.resolution().as_str(),
                retry_after = ?retry_after,
                "refused"
            ),
            Op::Admit | Op::Poll | Op::Reset => tracing::debug!(
                op = op.as_str(),
                reason = reason.as_str(),
                outcome = trip.outcome().as_str(),
                resolution = trip.resolution().as_str(),
                retry_after = ?retry_after,
                "refused"
            ),
        }
        trip
    }
}

impl<T, C: Clock> Drop for TrafficCop<T, C> {
    /// Take this cop's waiting requests out of the shared queue-depth gauge.
    /// A halted cop is deliberately not taken out of the halted gauge: only
    /// an operator reset clears a halt, so dropping a halted cop leaves the
    /// alert raised until the process restarts.
    fn drop(&mut self) {
        if self.total_queued > 0 {
            telemetry::queue_depth_sub(self.total_queued);
        }
    }
}
