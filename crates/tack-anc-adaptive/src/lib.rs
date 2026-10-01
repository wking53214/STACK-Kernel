//! tack-anc-adaptive: ANC (Active Timing Cancellation) strategy 2, adaptive
//! padding target.
//!
//! Status: new design. This is a reference implementation, compiled and
//! tested in this workspace; it is not deployed anywhere. Of the seven TACK
//! components only the Sentinel Hash-Chain (in `sentinel_os`) exists today.
//!
//! # The metaphor
//!
//! A bus timetable. Strategy 1 (`tack-anc-ceiling`) prints one timetable
//! and never changes it: every bus leaves on the printed minute, so the
//! platform clock says nothing about who was slow to board, but the
//! timetable must be written for the slowest day. Strategy 2 lets the
//! timetable follow how long boarding has been taking, so it is fast on
//! quiet days and slower on busy ones. The danger is that the timetable
//! itself becomes a record of who boarded. This crate holds two versions:
//!
//! * [`NaiveRollingTarget`], the brief's design: the timetable is rewritten
//!   after every bus from the average (or p99) of recent boarding times.
//!   It leaks, and it is kept so the leaks can be measured. Never select
//!   it (or [`AdaptivePad::naive`]) in a deployment profile.
//! * [`EpochQuantizedTarget`], the fix (predictive mitigation after
//!   Askarov, Zhang and Myers, CCS 2010 and CCS 2011): the timetable only
//!   uses a few printed intervals (powers of two), is only loosened when a
//!   bus actually misses its slot (the interval doubles), is only tightened
//!   on a public calendar (epoch boundaries), and every reprint is counted
//!   against a budget.
//!
//! # The goal
//!
//! An attacker who sends chosen requests and times the responses should not
//! be able to tell which path the secret-dependent work took (for example,
//! how many leading bytes of a guessed token were right), while the pad
//! still tracks load so that responses are not held to a worst-case
//! ceiling all the time.
//!
//! # The design, in plain words
//!
//! [`AdaptivePad`] does the padding; a [`TargetController`] decides the
//! target. For each request:
//! 1. At admission, before any secret work, check public facts (halted,
//!    input length, a free concurrency slot, the spin budget). A failure
//!    returns at once with a fixed-shape [`Trip`].
//! 2. Take the target from the controller (a [`Snapshot`]).
//! 3. Run the operation. Plan the release: on time means
//!    `admission + target`. In Hybrid mode the work is counted as
//!    `work + spin_tail`, so the target leaves room for the spin.
//! 4. Wait until the release time, then return.
//!
//! The two controllers differ in what happens when the work is slower than
//! the target, and in how the target moves.
//!
//! ## Naive: `clamp(stat(window) + margin, floor, cap)`
//!
//! The target is the mean or a percentile of the last `window` work times
//! plus a margin. Three leaks, each demonstrated in the tests and measured
//! by `examples/verify.rs`:
//! 1. **Late release.** A request slower than the target is released at
//!    completion ([`Disposition::Late`]), so its response time is its raw,
//!    secret-dependent work time.
//! 2. **Target poisoning.** The attacker controls part of the window. A
//!    flood of fast requests lowers the target below the slow path; the
//!    next probe on the slow path is then released late and stands out. A
//!    flood of slow requests raises the target (the cap bounds how far).
//! 3. **The target is a record of secret history.** The target is a
//!    statistic of recent work times, and every response time reveals it.
//!    If other users' requests take the slow path, the target rises, and
//!    the attacker sees that in their own responses. It changes on almost
//!    every request, so its leakage bound grows without limit.
//!
//! ## Epoch-quantized: the fix
//!
//! * The target is always a public level `min(floor * 2^i, cap)`.
//! * On a misprediction (work ran past the target), the level doubles until
//!   it covers the work, the response is released at that level
//!   ([`Disposition::Escalated`]), and the decrease clock restarts. The
//!   release time is still a public level, never the raw work time.
//! * The level steps down by exactly one only at epoch boundaries on a
//!   wall-clock grid (public times), and only if the epoch that ended had
//!   requests, no misprediction, and a largest work time the lower level
//!   would also have covered.
//! * Work past the cap is a RETRY released at the next whole multiple of
//!   the cap ([`Trip::Overrun`]).
//!
//! What the attacker can still learn is the sequence of target changes,
//! which requests were released above their admission target, and the cap
//! multiple of each overrun. The controller charges each of these as a
//! change and charges
//! [`epoch_bound_bits`]`(N, R) = N * log2(2 * (R + 1))` bits for `N` charged
//! changes among `R` requests in an accounting window (the theorist's epoch
//! form `N * log2(R + 1)`, plus one bit per change for its direction). The
//! ladder form `U * log2(K)` would be tighter but does not apply, because
//! doublings happen at request times, not only at public times. Charged:
//! every doubling; every miss that raised nothing (the level was already
//! raised by a concurrent request, or the controller was frozen), one
//! change; every overrun, `ceil(log2(k))` changes for its cap multiple
//! `k`; every decrease after warm-up. Not charged: the warm-up descent, a
//! run of one-step decreases from a public starting level (the initial
//! level, or the cap after a reset or a thaw); only its end (the first
//! hold above the floor) is charged, once.
//!
//! Two budgets. The window budget (`leak_budget`, default 128 bits per
//! 60 s) is a RATE: when one window's bound reaches it, the target rolls
//! back to the cap and adaptation stops for the rest of that window
//! ([`ControllerTrip::LeakBudgetSpent`], RETRY), then resumes from the cap
//! at the next window boundary. On its own a rate bounds nothing in total,
//! so every window's bound is also added to a lifetime sum; when the sum
//! reaches `leak_budget.bits * leak_lifetime_windows` (default 1024 bits)
//! adaptation stops until an operator reset
//! ([`ControllerTrip::LeakLifetimeSpent`], TERMINAL_BREACH). That lifetime
//! figure is the total the controller promises between operator resets.
//! While frozen the level does not move, but overruns and misses still
//! leak their release, and they are still charged (so a frozen controller
//! can still reach the lifetime budget); the leakage after a freeze is not
//! zero.
//!
//! **Trajectories.** The epoch target converges to the lowest level that
//! covers the slowest work in the traffic mix. If the two secret classes'
//! work times fall into different levels, the trajectory depends on which
//! class dominates the traffic, and that dependence is exactly what the
//! change count bounds. Set `floor` at or above the worst-case work time at
//! nominal load: then both classes share the floor level, the trajectory
//! is the same whichever class dominates, and the controller adapts to
//! load only. The tests show both cases.
//!
//! # Anti-DoS
//!
//! * The cap bounds the target: a flood of slow requests cannot drive the
//!   pad above it (naive or epoch).
//! * A concurrency cap (`max_concurrent`), a non-blocking semaphore as in
//!   strategy 1. Beyond it requests are shed at admission with RETRY,
//!   before any secret work.
//! * Sleep-mode padding by default ([`WaitMode::Sleep`]: no CPU while
//!   waiting). [`WaitMode::Hybrid`] spins only the last `spin_tail` of the
//!   window, and only when the shared spin budget ([`SpinBudgetConfig`])
//!   covers a fixed per-request charge; otherwise the request sleeps.
//! * The leak budget never halts the pad: a flood that forces
//!   mispredictions could otherwise force a halt.
//! * Availability tradeoff (known limitation): a decrease needs the whole
//!   epoch's largest work time to fit the lower level, so one request per
//!   epoch whose work an attacker can make slow (near the cap) holds every
//!   request at the cap. The cap bounds the cost. Per-sender quotas at the
//!   inlet limit one sender's share of the epoch maximum.
//! * One slow request (just under the cap) costs one full escalation cycle,
//!   up to `2 * top_level()` charged changes. Size the window budget so
//!   that `2 * top_level() * log2(2 * (R + 1))` stays below it at the
//!   expected requests per window `R`; otherwise that one request freezes
//!   the controller at the cap for the rest of the window (it thaws at the
//!   next one). Alert on `tack_anc_leak_budget_exhausted_total`.
//!
//! # CNS mapping (kernel convention 1)
//!
//! | Trip | Outcome | Resolution | Why |
//! |---|---|---|---|
//! | [`Trip::SlotsFull`] | RETRY | reject | load; resubmit later |
//! | [`Trip::InputTooLarge`] | RETRY | reject | resubmit a shorter input |
//! | [`Trip::Overrun`] | RETRY | reject | work passed the cap; value discarded |
//! | [`Trip::ClockFailure`] | TERMINAL_BREACH | halt | no trustworthy clock, no padding |
//! | [`Trip::Halted`] | TERMINAL_BREACH | halt | until operator [`AdaptivePad::reset`] |
//! | [`Trip::OperationPanicked`] | TERMINAL_BREACH | quarantine | the op panicked; caught, released on schedule, counted; a halt would let one request stop the pad |
//! | [`ControllerTrip::LeakBudgetSpent`] | RETRY (controller) | rollback | target back to the cap for the rest of the window; requests still served |
//! | [`ControllerTrip::LeakLifetimeSpent`] | TERMINAL_BREACH (controller) | rollback | target at the cap until operator [`AdaptivePad::reset_controller`]; requests still served |
//!
//! A late (naive) or escalated (epoch) release is not a trip: the value is
//! returned and the event is counted in `tack_anc_overrun_total`. An empty
//! spin budget is not a trip either: the request sleeps and is counted in
//! `tack_anc_spin_fallback_total`.
//!
//! # Threat model and its limits
//!
//! The attacker sends any number of chosen requests, sees only each
//! response and its arrival time, and can flood. The attacker cannot read
//! the metrics endpoint: this crate exports no pre-padding work time, but
//! the overrun, target-change and leak-budget metrics are derived from
//! work times and must stay private. Co-resident cache or SMT attackers are
//! out of scope.
//!
//! Residual channels (kernel convention 6):
//! * Target changes: each change of the epoch target is visible in later
//!   response times. That is the leakage the budget bounds.
//! * Escalations: an escalated response (released at a higher level) says
//!   "this request's work was slow". It is charged: as the doublings it
//!   causes, or as one change when the level was already raised by a
//!   concurrent request (its release is then the level covering its own
//!   work, below the current level). Keep `floor` above the nominal worst
//!   case so escalations come from load, not from the secret.
//! * Overruns: the release on the cap grid tells `ceil(work / cap)`; each
//!   overrun is charged `ceil(log2(k))` changes for its multiple `k`, even
//!   when frozen. The multiple itself is not capped, because the
//!   operation cannot be stopped early (a blocking API); a pre-emptible,
//!   deadline-aware API is the real fix.
//! * Slot occupancy (known limitation): a request holds its concurrency
//!   slot until its release. On-time requests hold it for the public
//!   target, but an escalated or overrunning request holds it until its
//!   later release, so a third party probing admission at a fixed offset
//!   can see SlotsFull and learn that a victim was slow. It carries the
//!   same information as the escalation and overrun releases above (which
//!   are charged), but to a different observer. Admission itself checks
//!   public facts only (halted, length, slots, spin budget).
//! * Panics: a panicking operation is caught and released on schedule,
//!   but the process panic hook runs at the moment of the panic, inside
//!   the padded window; its output (stderr by default) must not be
//!   observable by the attacker.
//! * Contention: a fast-fail flood slows every request, so it can force
//!   mispredictions and target changes (and so spend the budget). The
//!   verify example measures how many.
//! * Trip replies are different content (RETRY vs a value). Every trip is
//!   counted. The overrun RETRY is secret-influenced like an escalation;
//!   shed, input and halt replies reflect load or configuration only.
//! * Sleep wake-up jitter can be shifted a little by cache and frequency
//!   state that the secret work left behind. Hybrid reduces it at bounded
//!   CPU. A flood can force Sleep (by draining the spin budget), so Sleep
//!   must itself pass the leak test.
//! * The wait path. Found while measuring this crate: in Hybrid mode, a
//!   request whose work ended inside the spin-tail window skipped the
//!   sleep, and whether it slept depended on the secret; after a sleep the
//!   post-release path ran about 0.9 us slower (KS D 0.69 between classes
//!   at one target level on the development host). The pad now plans and
//!   records a Hybrid request as `work + spin_tail`, so every released
//!   request sleeps, then spins. In Sleep mode every on-time request
//!   sleeps already.
//! * The controller update runs inside the padded window and is hidden when
//!   the request is on time. Telemetry runs after the release timestamp but
//!   before `pad` returns; its cost depends only on the outcome and the
//!   disposition, which the release time already shows.
//!
//! # Measured (development host only)
//!
//! `cargo run --release -p tack-anc-adaptive --example verify`, defaults,
//! 100_000 samples per class, 4 vCPU Intel Xeon @ 2.80GHz VM, load average
//! 0.5 to 1.3, wall 511 s. These are facts about that host and run, not
//! guarantees. Calibration passed (leaky max |t| 858; ct raw |t| 0.58,
//! though its p50-cropped t was 10.8, so crops carry a false-alarm floor
//! near the line of 10 for nanosecond-scale input effects).
//!
//! | Run | max abs t | KS p | late / escalated | p50 added (A) |
//! |---|---|---|---|---|
//! | unprotected | 1015 | 0 | n/a | 0 |
//! | naive mean | 33.5 | 6e-53 | 20132 late | 100 us |
//! | naive p99, honest traffic | 3.9 | 0.52 | 1527 late | 147 us |
//! | naive p99, fast-flood poisoning (10_000 probes per class) | 17.2 | 1e-13 | 988 late | n/a |
//! | epoch, Sleep | 1.3 | 0.64 | 404 escalated | 310 us |
//! | epoch, Hybrid (250 us tail) | 1.2 | 0.87 | 364 escalated | 488 us |
//! | epoch under the same poisoning attack | 2.8 | 0.21 | 32 escalated | n/a |
//!
//! Host noise (millisecond scheduling tails) drove most epoch target
//! changes: 1309 changes in 202_000 requests (Sleep run). With the
//! production default budget (128 bits per 60 s) the controller froze at
//! the cap after 3454 requests (0.9 s, warm-up included) and then served
//! every request at the 2048 us cap, still undetected (max |t| 2.6). That
//! run predates the current accounting (warm-up descent was then charged,
//! uncounted misses and overrun multiples were not, and a freeze lasted
//! until an operator reset); it has not been re-measured. A
//! fast-fail flood at 10 x `max_concurrent` threads forced 18 (Hybrid) and
//! 56 (Sleep) target changes in 3 s; spin stayed within budget (0.300 s
//! reserved against a 0.311 s bound). The epoch trajectory under 90 percent
//! class A versus 90 percent class B traffic was not identical on this host
//! (noise-driven changes differ run to run); the deterministic tests show
//! it is identical when the floor covers both classes.
//!
//! # Quick use
//!
//! ```
//! use std::time::Duration;
//! use tack_anc_adaptive::{AdaptivePad, EpochConfig, PadConfig};
//!
//! let us = Duration::from_micros;
//! let pad = AdaptivePad::epoch(PadConfig::default(), EpochConfig::new(us(100), us(1_600)))?;
//! // Test fixture, not a real token.
//! let secret = [7u8; 32];
//! let guess = [0u8; 32];
//! match pad.pad(|| secret == guess) {
//!     Ok(p) => assert!(!p.value && p.release.observed >= p.release.target),
//!     Err(trip) => println!("{} {:?}", trip.gate_outcome().as_str(), trip.resolution()),
//! }
//! println!("target changes so far: {}", pad.status().changes_total);
//! # Ok::<(), tack_anc_adaptive::ConfigError>(())
//! ```

pub mod clock;
pub mod config;
pub mod controller;
pub mod outcome;
pub mod telemetry;

mod budget;
mod pad;
mod slots;
mod wait;

pub use clock::{Clock, MonotonicClock};
pub use config::{
    ConfigError, EpochConfig, LeakBudgetConfig, NaiveConfig, PadConfig, SpinBudgetConfig, WaitMode,
    WindowStatistic,
};
pub use controller::epoch::EpochQuantizedTarget;
pub use controller::naive::NaiveRollingTarget;
pub use controller::{
    epoch_bound_bits, ladder_bound_bits, Changes, ControllerKind, ControllerStatus, MissRule, Plan,
    Snapshot, TargetController,
};
pub use outcome::{
    ControllerTrip, Disposition, GateOutcome, PadResult, Padded, ReleaseInfo, Resolution, Trip,
};
pub use pad::AdaptivePad;
pub use wait::MAX_SLEEP_ROUNDS;
