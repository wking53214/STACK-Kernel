//! # stack-greenwave: Traffic Cop and Green Wave Routing
//!
//! **Status: new design.** This component does not exist in any TACK
//! repository today. Of the seven TACK components only the Sentinel
//! Hash-Chain exists (in `sentinel_os`). This crate is a reference
//! implementation of a design, not a port of running code.
//!
//! ## The metaphor
//!
//! A traffic cop at a busy crossing gives each direction its turn. No matter
//! how many cars pile up on one road, the cross street still gets waved
//! through on its turn. A *green wave* is the other half: consecutive lights
//! along an avenue are timed so a car moving at the design speed meets green
//! at every one and never stops.
//!
//! Here the "directions" are **lanes** (tenants or priority classes), the
//! "turns" are **phases** of a fixed-length **epoch**, and the "lights along
//! the avenue" are the kernel's processing **stages**.
//!
//! ## The goal
//!
//! Schedule work from many lanes through the kernel's stages so that the
//! schedule is:
//!
//! - **deterministic**: the same configuration and the same arrivals on the
//!   same clock give the same dispatch order and times, every run;
//! - **fair**: a lane that floods the system cannot starve another lane. A
//!   request that arrives at an empty lane queue is dispatched within one
//!   epoch plus the driver's poll latency, whatever every other lane is
//!   doing, as long as no phase is missed;
//! - **auditable**: every refusal is a typed verdict with a reason, counted
//!   in metrics, and every decision is a function of public inputs;
//! - **quieter in time**: results are released only on epoch boundaries, so
//!   the time a response leaves says which epoch the work finished in, not
//!   when inside that epoch. This is the bridge to ANC (Active Timing
//!   Cancellation), which works on the residue.
//!
//! ## The design, in pieces
//!
//! 1. **Grid** ([`Timing`]). Time is cut into phases of `phase_len_ns`;
//!    `phases_per_epoch` phases make an epoch. Boundaries are multiples of the
//!    lengths, measured from the clock's origin.
//! 2. **Phase table** ([`PhaseTable`]). Each phase of the epoch is owned by
//!    exactly one lane. A lane of weight `w` owns `w` phases, spread out by
//!    smooth weighted round-robin. The table is computed once, when the
//!    scheduler is built, and checked: every lane has at least one phase and
//!    the weights sum to the phases per epoch. It never changes afterwards.
//! 3. **Traffic cop** ([`TrafficCop`]). Admission puts a request into its
//!    lane's bounded FIFO queue. `poll` dispatches only from the lane that
//!    owns the current phase, oldest first, up to a per-phase budget. A full
//!    queue refuses at admission with RETRY and a `retry_after` equal to the
//!    start of that lane's next phase. Each dispatch issues a ticket bound to
//!    this cop and kept in a bounded per-lane live set until `complete`
//!    retires it.
//! 4. **Green wave** ([`GreenWave`]). Stage `i` has an offset in phases. A
//!    request dispatched in absolute phase `p` is due at stage `i` in phase
//!    `p + offset_i` (position `(p + offset_i) % phases_per_epoch` in its
//!    epoch). A stage asks [`TrafficCop::stage_check`] before running; too
//!    early is RETRY with the due time.
//! 5. **Release quantization** ([`Timing::release_at`],
//!    [`TrafficCop::complete`]). A completed result is released at the first
//!    epoch boundary strictly after completion.
//! 6. **Clock** ([`Clock`], [`ManualClock`]). The core never reads the system
//!    clock and never sleeps. Tests drive it by hand. The tokio wrapper in
//!    [`driver`] supplies real time, a dispatch loop on its own thread, and
//!    `sleep_until` for releases.
//!
//! ## Why the fairness bound holds
//!
//! Lane `L` of weight `w` owns `w` phase starts in every window of one epoch
//! length, wherever the window starts. If the driver polls in every phase,
//! each of those phases dispatches up to `max_dispatch_per_phase` (`M`)
//! requests from `L`'s queue and nothing from any other lane's queue. So a
//! request with `k` requests ahead of it in its own lane is dispatched at
//! most `ceil((floor(k / M) + 1) / w)` epochs after arrival, plus the
//! driver's poll latency (how long after a phase start the poll actually
//! runs). With `k = 0` that is at most one epoch plus poll latency. The
//! bound is not strict: a request that arrives in its lane's own phase just
//! after that phase's poll waits exactly one epoch on a perfect clock. No
//! term in the bound depends on any other lane, which is why flooding one
//! lane cannot delay another. The tokio driver keeps this true in practice
//! too: a full lane is refused without the shared lock, so a flood does not
//! delay the poll (see [`driver`]). The bound assumes no phase is missed;
//! missed phases are counted, and the driver misses them when the machine
//! has no free CPU (see the known limit in [`driver`]).
//!
//! ## Tradeoffs, stated plainly
//!
//! - **Not work-conserving.** A phase whose owner has nothing queued goes
//!   idle even if other lanes are full. That idle time is the price of the
//!   isolation above: if idle phases were lent out, one lane's load would
//!   change another's timing again, which is both a fairness leak and a
//!   timing side channel between tenants.
//! - **Latency floor.** Quantization adds up to one epoch to every response.
//!   A short epoch cuts that cost but hides less.
//! - **Missed phases are lost.** If the driver misses a phase (the process
//!   was descheduled), that lane's turn is not made up later, because making
//!   it up would move its work into another lane's phase. Missed phases are
//!   counted so an operator can see the bound was not guaranteed.
//! - **Live tickets expire.** Each lane keeps at most
//!   `queue_cap + 4 * weight * max_dispatch_per_phase` live tickets (see
//!   [`config::live_ticket_cap`]). Work that takes longer than that many of
//!   its own lane's newer dispatches loses its ticket and its completion is
//!   refused (`TicketNotLive`, counted in
//!   `tack_greenwave_tickets_expired_total`). The cap keeps memory bounded
//!   without letting one lane's backlog touch another lane's tickets.
//! - **Coarse information remains.** Quantization hides where inside an
//!   epoch work finished, not how many epochs it took. A request that takes
//!   several epochs still reveals that count.
//!
//! ## Verdicts and failure modes
//!
//! Every check returns a typed verdict and never panics. The vocabulary
//! mirrors CNS `GateOutcome` ([`GateOutcome`]). Each trip ([`TripReason`])
//! has exactly one outcome and one state resolution ([`Resolution`]):
//!
//! | Trip | Outcome | Resolution | Why |
//! |---|---|---|---|
//! | `QueueFull` | RETRY | reject | Load, not misbehaviour. `retry_after` is the lane's next phase start. |
//! | `NotYetDue` | RETRY | reject | Stage asked before its green. `retry_after` is the due time. |
//! | `UnknownLane` | TERMINAL_BREACH | reject | Lane identity comes from upstream; no correction by the caller is legitimate. |
//! | `UnknownStage` | TERMINAL_BREACH | reject | Stage index outside the wave table. |
//! | `CompletionBeforeDispatch` | TERMINAL_BREACH | reject | Ticket is not on this scheduler's timeline. |
//! | `ForeignTicket` | TERMINAL_BREACH | reject | Ticket was issued by another scheduler instance. |
//! | `TicketNotLive` | TERMINAL_BREACH | reject | Ticket already completed (replay) or expired at its lane's live-ticket cap. |
//! | `Overflow` | TERMINAL_BREACH | reject | A time or id sum would overflow `u64`. |
//! | `ClockRegressed` | TERMINAL_BREACH | halt | Every guarantee assumes monotonic time. |
//! | `Halted` | TERMINAL_BREACH | halt | Refusing while halted; an operator must `reset`. |
//! | `DriverStopped` | TERMINAL_BREACH | reject | The tokio runtime would not run the dispatch loop (shutting down). Nothing was dequeued. |
//! | [`ConfigError`] (build) | TERMINAL_BREACH | halt | The scheduler is never constructed. This includes `PhaseTooShortForDriver` from [`GreenWaveDriver::new`]. |
//!
//! The crate never quarantines: it has no sender identity beyond the lane,
//! and a busy lane is already contained by its own queue and phases. It
//! never rolls back: a refusal changes nothing, so there is nothing to
//! restore. `reject` is the right resolution for every request-level trip.
//!
//! ## Public information only
//!
//! [`TrafficCop`] is generic over the payload type and places no bound on
//! it, so it cannot inspect request content. Admission, shedding,
//! `retry_after`, dispatch order and release time depend only on the lane,
//! queue depth and clock. A shed decision therefore leaks nothing about any
//! secret the request carries. Request ids are per-lane sequence numbers
//! ([`RequestId`]), so the ids a tenant sees reveal nothing about how much
//! other lanes admitted.
//!
//! ## Telemetry
//!
//! Metric names, label sets and span names are listed in [`telemetry`].
//! Labels come only from closed enums in this crate.
//!
//! ## Where a timing or size side channel could appear
//!
//! - The refusal path and the admit path do different amounts of work, so
//!   admission latency reveals whether the queue was full. Queue depth is
//!   public information in this design, so this reveals nothing secret.
//! - Emitting per-request service time or hold time in metrics or logs would
//!   undo quantization for anyone who can read them. This crate emits
//!   neither; `complete` does not log the completion time.
//! - Tracing timestamps: any subscriber stamps spans and events with the
//!   wall clock at creation, so a span opened inside `complete` records the
//!   completion instant, and one inside `stage_check` records per-stage
//!   progress, even with no time field. Those spans and events (and the
//!   driver's `release_wait` span) are at TRACE level for that reason.
//!   Enabling TRACE for this crate where trace readers are less trusted than
//!   the scheduler reopens this channel.
//! - The driver refuses a full lane faster (without the lock) than it admits
//!   to a lane with room. Like the refusal path above, this reveals queue
//!   fullness, which is public here.
//! - Real timers and threads wake late by a runtime- and load-dependent
//!   amount (see [`driver`]).

pub mod clock;
pub mod config;
pub mod cop;
pub mod driver;
pub mod error;
pub mod outcome;
pub mod table;
pub mod telemetry;
pub mod timing;
pub mod wave;

pub use clock::{Clock, ManualClock, Nanos};
pub use config::{GreenWaveConfig, LaneSpec};
pub use cop::{
    Admitted, DispatchTicket, Dispatched, Refused, Release, RequestId, StageClearance, TrafficCop,
};
pub use driver::{GreenWaveDriver, TokioClock};
pub use error::{ConfigError, Op, Trip, TripReason};
pub use outcome::{GateOutcome, GatePosition, Resolution};
pub use table::PhaseTable;
pub use timing::Timing;
pub use wave::{GreenWave, StageSlot};

/// A lane: a tenant or priority class. An index into
/// [`GreenWaveConfig::lanes`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct LaneId(u16);

impl LaneId {
    /// Lane number `n`. Whether it exists is checked at admission.
    #[must_use]
    pub const fn new(n: u16) -> Self {
        Self(n)
    }

    /// Lane for index `i`, or `None` if it does not fit in `u16`.
    #[must_use]
    pub fn from_index(i: usize) -> Option<Self> {
        u16::try_from(i).ok().map(Self)
    }

    /// The index into the lane list.
    #[must_use]
    pub const fn index(self) -> usize {
        self.0 as usize
    }
}
