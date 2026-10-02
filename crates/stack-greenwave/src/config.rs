//! Configuration, defaults and hard caps.
//!
//! Every buffer the scheduler owns is sized from this struct, and every value
//! here is checked against a compile-time cap before anything is allocated.
//! Nothing is ever sized from a number a request supplies.

use crate::clock::Nanos;
use crate::error::ConfigError;

/// Default phase length: 1 ms.
pub const DEFAULT_PHASE_LEN_NS: Nanos = 1_000_000;
/// Default phases per epoch: 8, so the default epoch is 8 ms.
pub const DEFAULT_PHASES_PER_EPOCH: u32 = 8;
/// Default number of lanes in [`GreenWaveConfig::default`].
pub const DEFAULT_LANES: usize = 4;
/// Default lane weight in [`GreenWaveConfig::default`] (4 lanes x 2 = 8 phases).
pub const DEFAULT_LANE_WEIGHT: u32 = 2;
/// Default per-lane queue cap.
pub const DEFAULT_QUEUE_CAP: u32 = 64;
/// Default number of requests dispatched from the owning lane per phase.
pub const DEFAULT_MAX_DISPATCH_PER_PHASE: u32 = 4;
/// Default green wave offsets: four stages, one phase apart.
pub const DEFAULT_STAGE_OFFSETS: [u32; 4] = [0, 1, 2, 3];

/// Shortest phase the pure core accepts: 1 microsecond. This is a floor for
/// the arithmetic and for simulation on a [`crate::ManualClock`], not a
/// promise that any real timer can keep such a grid. The tokio driver has its
/// own, higher floor, [`DRIVER_MIN_PHASE_LEN_NS`], and refuses shorter phases.
pub const MIN_PHASE_LEN_NS: Nanos = 1_000;
/// Shortest phase [`crate::GreenWaveDriver`] accepts: 1 millisecond.
///
/// The driver sleeps to each phase start on a dedicated OS thread with
/// `std::thread::sleep`, which on Linux typically wakes tens of
/// microseconds late, and a whole scheduler time slice late (milliseconds)
/// when every CPU is busy. Below 1 ms that jitter is a large share of a phase
/// and most phases would be missed, so the driver refuses such
/// configurations with [`ConfigError::PhaseTooShortForDriver`]. (tokio's own
/// timer is coarser still: 1 ms resolution, deadlines rounded up.) A 1 ms
/// grid still misses phases when the thread waits a whole phase for a CPU;
/// those are counted in `tack_greenwave_phases_missed_total`.
pub const DRIVER_MIN_PHASE_LEN_NS: Nanos = 1_000_000;
/// How early the driver's thread wakes before a phase start: 200
/// microseconds (never more than half a phase). It then busy-waits on the
/// CPU until the phase starts, which absorbs ordinary wake-up lateness
/// (`std::thread::sleep` overshoots by tens of microseconds) at the cost of
/// a fifth of a CPU core for 1 ms phases (a twenty-fifth for 5 ms phases)
/// while the driver runs. It does not absorb the multi-millisecond delays of
/// a machine whose CPUs are all busy; see the driver module documentation.
pub const DRIVER_EARLY_WAKE_NS: Nanos = 200_000;
/// Most iterations of the driver's busy-wait before a phase start. The wait
/// normally ends when the phase starts, within [`DRIVER_EARLY_WAKE_NS`] on a
/// monotonic clock; the cap only bounds it if the clock stalls. Polling
/// early is harmless: the poll runs in the phase already served and
/// dispatches at most that phase's unspent budget.
pub const DRIVER_MAX_SPIN_ITERS: u32 = 50_000_000;
/// Most times an async caller of the driver (`admit`, `with_cop`,
/// `release`) yields to a dispatch loop that is waiting for the lock before
/// it takes the lock anyway. A waiting poll gets the lock within
/// microseconds once callers give way, so the cap is rarely reached; it
/// keeps the give-way loop bounded.
pub const DRIVER_MAX_GIVE_WAY_YIELDS: u32 = 1_024;
/// A dispatched ticket stays live (accepted by `stage_check` and `complete`)
/// until its lane has dispatched `queue_cap + LIVE_TICKET_EPOCHS * weight *
/// max_dispatch_per_phase` newer requests, that is, at least this many epochs
/// of that lane's full-rate dispatch plus one full queue. Past that the
/// oldest live ticket of the lane expires. See [`live_ticket_cap`].
pub const LIVE_TICKET_EPOCHS: u64 = 4;
/// Longest allowed epoch: 60 seconds. Release quantization holds every
/// response up to one epoch, so a longer epoch is a latency fault.
pub const MAX_EPOCH_NS: Nanos = 60_000_000_000;
/// Most lanes one scheduler serves.
pub const MAX_LANES: usize = 64;
/// Most phases in one epoch. Bounds the phase table.
pub const MAX_PHASES_PER_EPOCH: u32 = 1024;
/// Largest per-lane queue.
pub const MAX_QUEUE_CAP: u32 = 65_536;
/// Largest total of all lane queues.
pub const MAX_TOTAL_QUEUED: u64 = 1_048_576;
/// Largest per-phase dispatch budget. Also bounds the `Vec` one poll returns.
pub const MAX_DISPATCH_PER_PHASE: u32 = 1024;
/// Most stages in the green wave.
pub const MAX_STAGES: usize = 32;

/// One lane: a tenant or a priority class.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LaneSpec {
    /// Phases this lane owns per epoch. At least 1.
    pub weight: u32,
    /// Most requests that may wait in this lane's queue. 1..=[`MAX_QUEUE_CAP`].
    pub queue_cap: u32,
}

impl LaneSpec {
    /// A lane with `weight` phases per epoch and the default queue cap.
    #[must_use]
    pub const fn with_weight(weight: u32) -> Self {
        Self {
            weight,
            queue_cap: DEFAULT_QUEUE_CAP,
        }
    }
}

/// Most live (dispatched, not yet completed) tickets one lane keeps:
/// `min(queue_cap + LIVE_TICKET_EPOCHS * weight * max_dispatch_per_phase,
/// MAX_TOTAL_QUEUED)`. Sized only from validated configuration. When a lane is
/// at this cap, dispatching one more request from that lane expires the
/// lane's oldest live ticket, so one lane's slow or abandoned work never
/// affects another lane's tickets. Expiries are counted in
/// `tack_greenwave_tickets_expired_total`.
#[must_use]
pub fn live_ticket_cap(spec: &LaneSpec, max_dispatch_per_phase: u32) -> usize {
    let per_epoch = u64::from(spec.weight).saturating_mul(u64::from(max_dispatch_per_phase));
    let cap = u64::from(spec.queue_cap)
        .saturating_add(LIVE_TICKET_EPOCHS.saturating_mul(per_epoch))
        .min(MAX_TOTAL_QUEUED);
    usize::try_from(cap).unwrap_or(usize::MAX)
}

/// Scheduler configuration.
///
/// Invariants checked by [`GreenWaveConfig::validate`]:
/// - 1..=[`MAX_LANES`] lanes, each with weight at least 1;
/// - the weights sum exactly to `phases_per_epoch`, which is in
///   1..=[`MAX_PHASES_PER_EPOCH`];
/// - `phase_len_ns` is at least [`MIN_PHASE_LEN_NS`] and the epoch
///   (`phase_len_ns * phases_per_epoch`) is at most [`MAX_EPOCH_NS`];
/// - every queue cap is in 1..=[`MAX_QUEUE_CAP`] and their sum is at most
///   [`MAX_TOTAL_QUEUED`];
/// - `max_dispatch_per_phase` is in 1..=[`MAX_DISPATCH_PER_PHASE`];
/// - 1..=[`MAX_STAGES`] stage offsets, non-decreasing, each below
///   `phases_per_epoch`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GreenWaveConfig {
    /// Length of one phase in nanoseconds.
    pub phase_len_ns: Nanos,
    /// Phases in one epoch. Must equal the sum of lane weights.
    pub phases_per_epoch: u32,
    /// The lanes, indexed by [`crate::LaneId`].
    pub lanes: Vec<LaneSpec>,
    /// Green wave offsets: stage `i` is due `stage_offsets[i]` phases after
    /// the dispatch phase.
    pub stage_offsets: Vec<u32>,
    /// Requests dispatched from the owning lane in one phase.
    pub max_dispatch_per_phase: u32,
}

impl Default for GreenWaveConfig {
    /// 1 ms phases, 8 phases per epoch (8 ms epoch), 4 lanes of weight 2 with
    /// queue cap 64, 4 dispatches per phase, stage offsets `[0, 1, 2, 3]`.
    /// 1 ms is [`DRIVER_MIN_PHASE_LEN_NS`], the shortest phase the tokio
    /// driver accepts.
    fn default() -> Self {
        Self {
            phase_len_ns: DEFAULT_PHASE_LEN_NS,
            phases_per_epoch: DEFAULT_PHASES_PER_EPOCH,
            lanes: vec![LaneSpec::with_weight(DEFAULT_LANE_WEIGHT); DEFAULT_LANES],
            stage_offsets: DEFAULT_STAGE_OFFSETS.to_vec(),
            max_dispatch_per_phase: DEFAULT_MAX_DISPATCH_PER_PHASE,
        }
    }
}

impl GreenWaveConfig {
    /// Epoch length, if it does not overflow.
    #[must_use]
    pub fn epoch_len_ns(&self) -> Option<Nanos> {
        self.phase_len_ns
            .checked_mul(u64::from(self.phases_per_epoch))
    }

    /// Check every invariant listed on the struct. Cheap: at most
    /// [`MAX_LANES`] + [`MAX_STAGES`] steps before it can fail on a count.
    ///
    /// # Errors
    /// The first invariant that does not hold.
    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.lanes.is_empty() {
            return Err(ConfigError::NoLanes);
        }
        if self.lanes.len() > MAX_LANES {
            return Err(ConfigError::TooManyLanes {
                count: self.lanes.len(),
                max: MAX_LANES,
            });
        }
        if self.phases_per_epoch == 0 || self.phases_per_epoch > MAX_PHASES_PER_EPOCH {
            return Err(ConfigError::PhasesOutOfRange {
                phases: self.phases_per_epoch,
                max: MAX_PHASES_PER_EPOCH,
            });
        }
        if self.phase_len_ns < MIN_PHASE_LEN_NS {
            return Err(ConfigError::PhaseTooShort {
                phase_len_ns: self.phase_len_ns,
                min: MIN_PHASE_LEN_NS,
            });
        }
        match self.epoch_len_ns() {
            Some(e) if e <= MAX_EPOCH_NS => {}
            _ => return Err(ConfigError::EpochTooLong { max: MAX_EPOCH_NS }),
        }
        let mut weight_sum: u64 = 0;
        let mut queue_sum: u64 = 0;
        for (lane, spec) in self.lanes.iter().enumerate() {
            if spec.weight == 0 {
                return Err(ConfigError::ZeroWeight { lane });
            }
            if spec.queue_cap == 0 || spec.queue_cap > MAX_QUEUE_CAP {
                return Err(ConfigError::QueueCapOutOfRange {
                    lane,
                    cap: spec.queue_cap,
                    max: MAX_QUEUE_CAP,
                });
            }
            // At most 64 lanes of u32 each: cannot overflow u64.
            weight_sum = weight_sum.saturating_add(u64::from(spec.weight));
            queue_sum = queue_sum.saturating_add(u64::from(spec.queue_cap));
        }
        if weight_sum != u64::from(self.phases_per_epoch) {
            return Err(ConfigError::WeightSumMismatch {
                sum: weight_sum,
                phases: self.phases_per_epoch,
            });
        }
        if queue_sum > MAX_TOTAL_QUEUED {
            return Err(ConfigError::TotalQueueTooLarge {
                total: queue_sum,
                max: MAX_TOTAL_QUEUED,
            });
        }
        if self.max_dispatch_per_phase == 0 || self.max_dispatch_per_phase > MAX_DISPATCH_PER_PHASE {
            return Err(ConfigError::DispatchBudgetOutOfRange {
                value: self.max_dispatch_per_phase,
                max: MAX_DISPATCH_PER_PHASE,
            });
        }
        if self.stage_offsets.is_empty() {
            return Err(ConfigError::NoStages);
        }
        if self.stage_offsets.len() > MAX_STAGES {
            return Err(ConfigError::TooManyStages {
                count: self.stage_offsets.len(),
                max: MAX_STAGES,
            });
        }
        let mut previous = 0u32;
        for (stage, &offset) in self.stage_offsets.iter().enumerate() {
            if offset >= self.phases_per_epoch {
                return Err(ConfigError::OffsetOutOfRange {
                    stage,
                    offset,
                    phases: self.phases_per_epoch,
                });
            }
            if offset < previous {
                return Err(ConfigError::OffsetsNotMonotonic {
                    stage,
                    offset,
                    previous,
                });
            }
            previous = offset;
        }
        Ok(())
    }
}
