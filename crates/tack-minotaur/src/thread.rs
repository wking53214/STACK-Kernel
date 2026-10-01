//! The Thread (the string) and its depth guard.

use std::collections::{HashMap, VecDeque};
use std::ops::Deref;
use std::time::Instant;

use crate::brent::Brent;
use crate::config::{ConfigError, MinotaurConfig};
use crate::fingerprint::Fingerprint;
use crate::recent::Recent;
use crate::telemetry::{self, spans, WalkEnd, WalkStats};
use crate::trip::{Detector, GateOutcome, Resolution, Trip, TripKind};

/// Per-state entry in the exact revisit set.
#[derive(Debug, Clone, Copy)]
struct Visit {
    /// Total visits in this walk, including the first.
    count: u32,
    /// Step number of the most recent visit.
    last_step: u64,
}

/// Ariadne's string: tied at the anchor (depth 0, step 0) and paid out as
/// the walk goes deeper and moves from state to state.
///
/// One Thread guards one walk at a time. It holds no copy of the caller's
/// state; see the crate docs for the rollback contract. Keep the Thread with
/// the orchestrator and hand the constrained work guards or `&mut dyn Walk`:
/// [`Thread::rewind`] and [`Thread::operator_reset`] need `&mut Thread`. It uses no
/// thread-locals and no interior mutability, so it is `Send + Sync` and can
/// be moved into an async task or held across `.await` points.
#[derive(Debug)]
pub struct Thread {
    cfg: MinotaurConfig,
    depth: u32,
    max_depth_seen: u32,
    steps: u64,
    /// Incremented on every rewind. A guard issued in an earlier epoch is
    /// stale: it refuses `descend` and `record`, and dropping it does not pay
    /// depth back, so the outer scopes still unwinding after a trip can
    /// neither go deeper nor drive depth below 0.
    epoch: u64,
    visits: HashMap<Fingerprint, Visit>,
    breadcrumbs: VecDeque<Fingerprint>,
    brent: Brent,
    recent: Recent,
    degraded: bool,
    untracked: u64,
    trips: u32,
    halted: bool,
    /// Transitions accepted since construction or the last operator reset,
    /// across all walks. Only `operator_reset` clears it.
    lifetime_steps: u64,
    walk_started: Instant,
}

impl Thread {
    /// Tie a new string at the anchor.
    ///
    /// The exact set, the recent-state table and the breadcrumb ring are
    /// allocated here, once, at their configured caps, and never grow
    /// afterwards.
    ///
    /// # Errors
    /// [`ConfigError`] when a cap is outside its accepted range.
    pub fn new(cfg: MinotaurConfig) -> Result<Self, ConfigError> {
        cfg.validate()?;
        Ok(Self {
            visits: HashMap::with_capacity(cfg.max_distinct_states),
            breadcrumbs: VecDeque::with_capacity(cfg.breadcrumb_len),
            brent: Brent::new(cfg.max_cycle_period),
            recent: Recent::new(recent_capacity(&cfg)),
            cfg,
            depth: 0,
            max_depth_seen: 0,
            steps: 0,
            epoch: 0,
            degraded: false,
            untracked: 0,
            trips: 0,
            halted: false,
            lifetime_steps: 0,
            walk_started: Instant::now(),
        })
    }

    /// Go one level deeper. The returned guard pays the level back when it
    /// is dropped, on every exit path: normal return, early return, `?`, or
    /// a panic unwinding through the scope.
    ///
    /// The guard mutably borrows this Thread, so all further work in the
    /// deeper scope goes through the guard's own [`DepthGuard::descend`] and
    /// [`DepthGuard::record`]. The guard dereferences to the Thread only
    /// read-only, so no code holding a guard can reach [`Thread::rewind`],
    /// [`Thread::operator_reset`] or replace the Thread: those need a real
    /// `&mut Thread`, which the borrow checker denies while any guard is
    /// alive. There is no method that takes a guard, so a guard cannot be
    /// used with a different Thread, and guards are released strictly in
    /// reverse order.
    ///
    /// # Errors
    /// A [`Trip`] of kind [`TripKind::DepthExceeded`] if the descent would
    /// exceed `max_depth` (the Thread rewinds to the anchor), or
    /// [`TripKind::Halted`] if the Thread is halted (nothing changes).
    pub fn descend(&mut self) -> Result<DepthGuard<'_>, Trip> {
        let _span = tracing::trace_span!(spans::DESCEND).entered();
        if self.halted {
            return Err(self.halted_trip());
        }
        if self.depth >= self.cfg.max_depth {
            return Err(self.trip(TripKind::DepthExceeded {
                limit: self.cfg.max_depth,
            }));
        }
        self.depth += 1;
        self.max_depth_seen = self.max_depth_seen.max(self.depth);
        let epoch = self.epoch;
        Ok(DepthGuard {
            thread: self,
            epoch,
        })
    }

    /// Record one transition into the state with this fingerprint.
    ///
    /// Checks, in order: halted, step budget, lifetime budget, revisit
    /// allowance (exact set), state-space budget (once the set is full),
    /// Brent's detection (once the set is full), then the recent-state table
    /// (for states the full set cannot hold). Constant memory: a state is
    /// added to the exact set only while it has room.
    ///
    /// # Errors
    /// A [`Trip`]; every kind except [`TripKind::Halted`] rewinds the Thread
    /// to the anchor first.
    pub fn record(&mut self, state: Fingerprint) -> Result<(), Trip> {
        let _span = tracing::trace_span!(spans::RECORD).entered();
        if self.halted {
            return Err(self.halted_trip());
        }

        if self.breadcrumbs.len() >= self.cfg.breadcrumb_len {
            self.breadcrumbs.pop_front();
        }
        self.breadcrumbs.push_back(state);

        self.steps = self.steps.saturating_add(1);
        let step = self.steps;
        if step > self.cfg.max_steps {
            return Err(self.trip(TripKind::StepBudgetExhausted {
                limit: self.cfg.max_steps,
            }));
        }
        let lifetime_limit = self.lifetime_step_limit();
        if self.lifetime_steps >= lifetime_limit {
            return Err(self.trip_and_halt(TripKind::LifetimeBudgetExhausted {
                limit: lifetime_limit,
            }));
        }

        let allowance = self.cfg.revisit_allowance;
        let mut exact_loop = None;
        let mut recent_loop = None;
        if let Some(v) = self.visits.get_mut(&state) {
            v.count = v.count.saturating_add(1);
            let gap = step.saturating_sub(v.last_step);
            v.last_step = step;
            if v.count.saturating_sub(1) > allowance {
                exact_loop = Some(gap);
            }
        } else if self.visits.len() < self.cfg.max_distinct_states {
            self.visits.insert(
                state,
                Visit {
                    count: 1,
                    last_step: step,
                },
            );
        } else {
            if !self.degraded {
                self.degraded = true;
                telemetry::degraded(self.visits.len(), step);
            }
            self.untracked = self.untracked.saturating_add(1);
            if self.untracked > self.cfg.max_untracked_transitions {
                return Err(self.trip(TripKind::StateSpaceExhausted {
                    tracked: self.visits.len(),
                    limit: self.cfg.max_untracked_transitions,
                }));
            }
            recent_loop = self.recent.observe(state, step, allowance);
        }
        if let Some(period) = exact_loop {
            return Err(self.trip(TripKind::LoopDetected {
                period,
                detector: Detector::Exact,
            }));
        }

        if self.degraded {
            if let Some(period) = self.brent.observe(state, allowance) {
                return Err(self.trip(TripKind::LoopDetected {
                    period,
                    detector: Detector::Brent,
                }));
            }
        }
        if let Some(period) = recent_loop {
            return Err(self.trip(TripKind::LoopDetected {
                period,
                detector: Detector::Recent,
            }));
        }
        self.lifetime_steps = self.lifetime_steps.saturating_add(1);
        Ok(())
    }

    /// Wind the string back to the anchor after a walk finished cleanly.
    ///
    /// Clears depth, steps, the exact set (keeping its allocation), the
    /// breadcrumbs and the degraded state, and starts a new walk. It takes
    /// `&mut Thread`, so it cannot be called while any guard is alive, and a
    /// [`DepthGuard`] never hands one out. The trip count and the lifetime
    /// step count are kept, so rewinding does not forgive a Thread that
    /// keeps tripping, and replaying walks with a rewind just before each
    /// per-walk cap still runs into the lifetime budget. Emits the walk
    /// histograms with `end="rewind"`.
    ///
    /// Only the orchestrator that owns the Thread should rewind it; the
    /// constrained agent should only ever receive guards.
    pub fn rewind(&mut self) {
        let _span = tracing::debug_span!(spans::REWIND).entered();
        let stats = self.walk_stats();
        self.rewind_to_anchor();
        telemetry::walk_ended(WalkEnd::Rewind, stats);
    }

    /// Clear a halt, the trip count and the lifetime step count, and rewind
    /// to the anchor.
    ///
    /// This is the operator action convention 1 requires before a halted
    /// component accepts work again. Whoever holds `&mut Thread` can call
    /// it, so in an agent runtime the Thread must be owned by the
    /// orchestrator, never by the agent it constrains. A [`DepthGuard`]
    /// dereferences to the Thread only read-only, so code handed a guard
    /// cannot call it.
    pub fn operator_reset(&mut self) {
        let _span = tracing::info_span!(spans::OPERATOR_RESET).entered();
        let was_halted = self.halted;
        let trips = self.trips;
        let stats = self.walk_stats();
        self.rewind_to_anchor();
        self.trips = 0;
        self.halted = false;
        self.lifetime_steps = 0;
        telemetry::walk_ended(WalkEnd::OperatorReset, stats);
        telemetry::operator_reset(was_halted, trips);
    }

    /// Current depth (0 at the anchor).
    #[must_use]
    pub const fn depth(&self) -> u32 {
        self.depth
    }

    /// Transitions recorded since the anchor.
    #[must_use]
    pub const fn steps(&self) -> u64 {
        self.steps
    }

    /// States held in the exact revisit set. Never exceeds
    /// `max_distinct_states`.
    #[must_use]
    pub fn tracked_states(&self) -> usize {
        self.visits.len()
    }

    /// Allocated slots in the exact revisit set. Set once at construction;
    /// a walk never makes it grow.
    #[must_use]
    pub fn tracked_capacity(&self) -> usize {
        self.visits.capacity()
    }

    /// Whether this walk filled the exact set and switched to Brent's
    /// detection.
    #[must_use]
    pub const fn is_degraded(&self) -> bool {
        self.degraded
    }

    /// Transitions onto states the full exact set could not hold, this walk.
    #[must_use]
    pub const fn untracked_transitions(&self) -> u64 {
        self.untracked
    }

    /// Whether the Thread is halted and refusing work.
    #[must_use]
    pub const fn is_halted(&self) -> bool {
        self.halted
    }

    /// Trips since construction or the last [`Thread::operator_reset`].
    #[must_use]
    pub const fn trips(&self) -> u32 {
        self.trips
    }

    /// The breadcrumb trail, oldest first (at most `breadcrumb_len`).
    pub fn breadcrumbs(&self) -> impl ExactSizeIterator<Item = &Fingerprint> + '_ {
        self.breadcrumbs.iter()
    }

    /// The caps in force.
    #[must_use]
    pub const fn config(&self) -> &MinotaurConfig {
        &self.cfg
    }

    /// Transitions accepted since construction or the last
    /// [`Thread::operator_reset`], across all walks.
    #[must_use]
    pub const fn lifetime_steps(&self) -> u64 {
        self.lifetime_steps
    }

    /// The lifetime budget: `max_steps * max_trips_before_halt` accepted
    /// transitions between operator resets. The transition after that trips
    /// [`TripKind::LifetimeBudgetExhausted`], which halts. It is derived from
    /// the two caps so a caller gets as much total work from replaying walks
    /// as from tripping them.
    #[must_use]
    pub fn lifetime_step_limit(&self) -> u64 {
        self.cfg
            .max_steps
            .saturating_mul(u64::from(self.cfg.max_trips_before_halt))
    }

    /// Slots in the degraded mode's recent-state table:
    /// `min(max_cycle_period, max_distinct_states)`. An untracked state
    /// whose visits are fewer than this many untracked transitions apart has
    /// its revisits counted exactly.
    #[must_use]
    pub const fn recent_capacity(&self) -> usize {
        self.recent.capacity()
    }

    fn walk_stats(&self) -> WalkStats {
        WalkStats {
            steps: self.steps,
            max_depth: self.max_depth_seen,
            distinct: self.visits.len(),
            elapsed: self.walk_started.elapsed(),
        }
    }

    fn rewind_to_anchor(&mut self) {
        self.depth = 0;
        self.max_depth_seen = 0;
        self.steps = 0;
        self.epoch = self.epoch.wrapping_add(1);
        self.visits.clear();
        self.breadcrumbs.clear();
        self.brent.reset();
        self.recent.reset();
        self.degraded = false;
        self.untracked = 0;
        self.walk_started = Instant::now();
    }

    /// Build the trip, rewind, count it, and halt if this was the last one
    /// allowed.
    fn trip(&mut self, kind: TripKind) -> Trip {
        self.trip_inner(kind, false)
    }

    /// As [`Thread::trip`], but always halts.
    fn trip_and_halt(&mut self, kind: TripKind) -> Trip {
        self.trip_inner(kind, true)
    }

    /// The work here does not depend on the walk length or the log level:
    /// the path buffer is always `breadcrumb_len` slots written, and the
    /// digest always covers `breadcrumb_len` slots (see
    /// [`telemetry::path_digest`]).
    fn trip_inner(&mut self, kind: TripKind, force_halt: bool) -> Trip {
        let _span = tracing::info_span!(spans::TRIP).entered();
        self.trips = self.trips.saturating_add(1);
        let halted_now = force_halt || self.trips >= self.cfg.max_trips_before_halt;
        let (outcome, resolution) = if halted_now {
            (GateOutcome::TerminalBreach, Resolution::Halt)
        } else {
            (GateOutcome::Retry, Resolution::Rollback)
        };
        let k = self.cfg.breadcrumb_len;
        let len = self.breadcrumbs.len();
        // Write all K slots (the path, then zero padding), then cut to the
        // path length; the truncation is free for a `Copy` type.
        let mut path = Vec::with_capacity(k);
        path.extend(self.breadcrumbs.iter().copied());
        path.resize(k, Fingerprint::ZERO);
        let digest = telemetry::path_digest(&path);
        path.truncate(len);
        let t = Trip {
            kind,
            path,
            outcome,
            resolution,
            depth: self.depth,
            steps: self.steps,
        };
        let stats = self.walk_stats();
        self.rewind_to_anchor();
        if halted_now {
            self.halted = true;
        }
        telemetry::walk_ended(WalkEnd::Trip, stats);
        telemetry::trip(&t, halted_now, Some(&digest));
        t
    }

    /// Refusal while halted. Changes nothing.
    fn halted_trip(&self) -> Trip {
        let t = Trip {
            kind: TripKind::Halted,
            path: Vec::new(),
            outcome: GateOutcome::TerminalBreach,
            resolution: Resolution::Halt,
            depth: self.depth,
            steps: self.steps,
        };
        telemetry::trip(&t, false, None);
        t
    }

    /// Refusal of a call through a stale guard. Changes nothing.
    fn stale_trip(&self) -> Trip {
        let t = Trip {
            kind: TripKind::StaleGuard,
            path: Vec::new(),
            outcome: GateOutcome::Retry,
            resolution: Resolution::Reject,
            depth: self.depth,
            steps: self.steps,
        };
        telemetry::trip(&t, false, None);
        t
    }
}

/// `min(max_cycle_period, max_distinct_states)`: the recent-state table is
/// never larger than the exact set the operator already accepted, and never
/// larger than the longest period the degraded mode promises to find.
fn recent_capacity(cfg: &MinotaurConfig) -> usize {
    let period = usize::try_from(cfg.max_cycle_period).unwrap_or(usize::MAX);
    period.min(cfg.max_distinct_states)
}

/// Something a walk can go deeper through and record transitions on: the
/// root [`Thread`] or a [`DepthGuard`].
///
/// Recursive code takes `&mut dyn Walk` (or `&mut impl Walk`) so the same
/// function runs at the root and inside a guarded scope. The trait has no
/// `rewind` and no `operator_reset`, and [`Walk::thread`] is read-only:
/// those stay with whoever owns the Thread.
pub trait Walk {
    /// Go one level deeper. See [`Thread::descend`] and
    /// [`DepthGuard::descend`].
    ///
    /// # Errors
    /// A [`Trip`].
    fn descend(&mut self) -> Result<DepthGuard<'_>, Trip>;

    /// Record one transition. See [`Thread::record`] and
    /// [`DepthGuard::record`].
    ///
    /// # Errors
    /// A [`Trip`].
    fn record(&mut self, state: Fingerprint) -> Result<(), Trip>;

    /// Read-only view of the Thread, for its accessors.
    fn thread(&self) -> &Thread;
}

impl Walk for Thread {
    fn descend(&mut self) -> Result<DepthGuard<'_>, Trip> {
        Self::descend(self)
    }

    fn record(&mut self, state: Fingerprint) -> Result<(), Trip> {
        Self::record(self, state)
    }

    fn thread(&self) -> &Thread {
        self
    }
}

impl Walk for DepthGuard<'_> {
    fn descend(&mut self) -> Result<DepthGuard<'_>, Trip> {
        DepthGuard::descend(self)
    }

    fn record(&mut self, state: Fingerprint) -> Result<(), Trip> {
        DepthGuard::record(self, state)
    }

    fn thread(&self) -> &Thread {
        self.thread
    }
}

/// One level of depth, paid back to its [`Thread`] on drop.
///
/// Nested work uses the guard's own methods: `guard.descend()` and
/// `guard.record(fp)`. The guard dereferences to the Thread read-only, so
/// accessors work (`guard.depth()`, `guard.is_halted()`), but nothing that
/// needs `&mut Thread` does: code handed a guard cannot rewind the Thread,
/// reset it, or replace it.
///
/// If the Thread rewound while this guard was alive (a trip deeper in the
/// walk), the guard is stale. `descend` and `record` through it return a
/// [`TripKind::StaleGuard`] trip (`RETRY`, reject) and do not touch the
/// Thread, so the caller has to unwind to the root holder, as the rollback
/// contract requires. Dropping a stale guard does nothing: the depth it
/// accounted for was already cleared. `std::mem::forget` on a guard leaks
/// one level of depth until the next rewind; that errs toward tripping
/// `DepthExceeded`, never toward allowing more depth.
#[derive(Debug)]
#[must_use = "dropping the guard immediately pays the depth back"]
pub struct DepthGuard<'t> {
    thread: &'t mut Thread,
    epoch: u64,
}

impl Deref for DepthGuard<'_> {
    type Target = Thread;

    fn deref(&self) -> &Thread {
        self.thread
    }
}

impl DepthGuard<'_> {
    /// Whether the Thread has rewound since this guard was issued.
    #[must_use]
    pub const fn is_stale(&self) -> bool {
        self.thread.epoch != self.epoch
    }

    /// Refuse the call if the Thread is halted or this guard is stale.
    fn check_current(&self) -> Result<(), Trip> {
        if self.thread.halted {
            return Err(self.thread.halted_trip());
        }
        if self.is_stale() {
            return Err(self.thread.stale_trip());
        }
        Ok(())
    }

    /// Go one level deeper from this scope; see [`Thread::descend`].
    ///
    /// # Errors
    /// [`TripKind::Halted`] if the Thread is halted, [`TripKind::StaleGuard`]
    /// if the Thread rewound since this guard was issued (nothing changes in
    /// either case), otherwise as [`Thread::descend`].
    pub fn descend(&mut self) -> Result<DepthGuard<'_>, Trip> {
        self.check_current()?;
        self.thread.descend()
    }

    /// Record one transition from this scope; see [`Thread::record`].
    ///
    /// # Errors
    /// [`TripKind::Halted`] if the Thread is halted, [`TripKind::StaleGuard`]
    /// if the Thread rewound since this guard was issued (nothing changes in
    /// either case), otherwise as [`Thread::record`].
    pub fn record(&mut self, state: Fingerprint) -> Result<(), Trip> {
        self.check_current()?;
        self.thread.record(state)
    }
}

impl Drop for DepthGuard<'_> {
    fn drop(&mut self) {
        if self.thread.epoch == self.epoch {
            self.thread.depth = self.thread.depth.saturating_sub(1);
        }
    }
}
