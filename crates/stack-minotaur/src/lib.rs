//! # stack-minotaur: the Minotaur String
//!
//! **Status: new design.** Of the seven components of the STACK governance
//! kernel, only the Sentinel Hash-Chain exists today (in `sentinel_os`). The
//! Minotaur String did not exist in any STACK repository before this crate;
//! this is its first reference implementation, and nothing in `sentinel_os`,
//! CNS, observe-perceive, ghost_tools or Resume_OS calls it yet.
//!
//! ## The metaphor
//!
//! In the myth, Ariadne gives Theseus a ball of string before he enters the
//! Minotaur's labyrinth. He ties one end at the entrance and pays the string
//! out as he walks. At any moment the string tells him three things: how far
//! in he is, whether he is crossing his own path (walking in circles), and
//! how to get back out.
//!
//! This crate gives a program the same string. A [`Thread`] is tied at the
//! entrance, called the anchor (depth 0, no steps taken). Each time the
//! program goes one level deeper (a recursive call, a sub-agent, a nested
//! plan) it calls [`Thread::descend`]; each time it moves to a new state (a
//! tool call, a search node) it calls [`Thread::record`] with that state's
//! [`Fingerprint`].
//!
//! ## The goal
//!
//! Stop three failure patterns before they consume the machine:
//!
//! * **Runaway recursion**: depth grows without bound. Caught by
//!   `max_depth`.
//! * **Agent tool-call loops**: an agent calls the same tools with the same
//!   arguments over and over. Caught by the revisit allowance: a walk that
//!   returns to the same state more than `revisit_allowance` times is a
//!   loop, not legitimate iteration.
//! * **State-space explosions**: a search keeps finding new states forever.
//!   Caught by `max_steps` (total transitions) and by
//!   `max_untracked_transitions` (new states after the exact set is full).
//! * **Replay**: the orchestrator keeps rewinding and resubmitting a walk
//!   just before each per-walk cap. Caught by the lifetime budget,
//!   `max_steps * max_trips_before_halt` accepted transitions between
//!   operator resets.
//!
//! And in every case, always be able to unwind to the anchor.
//!
//! ## The design, in plain words
//!
//! **Depth is counted by guards.** [`Thread::descend`] returns a
//! [`DepthGuard`], a value whose only job is to subtract one from the depth
//! when it goes out of scope. Rust runs that "drop" code on every exit path,
//! including early returns, `?` error propagation and a panic unwinding the
//! stack, so the depth can never be left too high by a forgotten decrement.
//! The guard borrows the Thread exclusively, so deeper work must go through
//! the guard's own `descend` and `record`. The guard gives read-only access
//! to the Thread and nothing more. The compiler checks four things: a guard
//! cannot be used with a different Thread (no method accepts one), guards
//! are released strictly in reverse order, and code holding a guard can
//! neither call [`Thread::rewind`] or [`Thread::operator_reset`] nor replace
//! the Thread, because all three need a real `&mut Thread`. The [`Walk`]
//! trait lets one recursive function take either the root Thread or a
//! guard.
//!
//! **A trip makes every live guard stale.** After a trip the Thread is back
//! at the anchor, but the outer scopes are still on the stack. Each guard
//! remembers the walk it was issued in; through a guard from an earlier
//! walk, `descend` and `record` are refused with a [`TripKind::StaleGuard`]
//! trip (`RETRY`, reject) that changes nothing. So real nesting (live
//! guards) can never exceed `max_depth`: the caller has to unwind to the
//! root before it can go deeper again.
//!
//! **Revisits are counted exactly, up to a memory cap.** A hash map from
//! fingerprint to visit count holds up to `max_distinct_states` entries. It
//! is allocated at full size once, when the Thread is built, and never
//! grows. The map uses the standard library's randomly keyed SipHash, so an
//! attacker who chooses fingerprints cannot force slow collisions.
//!
//! **When the map is full, the Thread degrades instead of growing.** New
//! states are no longer all remembered. Two bounded detectors take over:
//!
//! * A streaming form of Brent's cycle detection sees every transition. It
//!   keeps one saved state and a few counters and finds any strictly
//!   periodic cycle up to `max_cycle_period` steps long.
//! * A recent-state table of `min(max_cycle_period, max_distinct_states)`
//!   slots counts visits to states the map could not hold, exactly, with
//!   the same rule as the map. It evicts by the CLOCK rule, which never
//!   evicts a state whose visits are fewer than the table size apart. This
//!   catches a repeated state with fresh filler states between its visits
//!   (`A, n1, A, n2, ...`), which Brent alone can miss when the walker lines
//!   up its saved state with the fillers. The table never overcounts, so it
//!   has no false positives.
//!
//! Memory stays constant. The cost is precision: a state revisited at gaps
//! longer than the table size, or a cycle longer than `max_cycle_period`,
//! among states the map could not hold, is not seen as a loop, and is
//! caught later by the untracked-transition budget or the step budget
//! instead.
//!
//! **A breadcrumb trail travels with every trip.** The last `breadcrumb_len`
//! fingerprints are kept in a fixed-size ring and copied into the [`Trip`],
//! so the caller can see where the walk was going when it was stopped.
//!
//! ## Outcomes (kernel convention 1)
//!
//! Every check returns `Result<_, Trip>`; nothing panics across the API.
//!
//! | Trip | CNS outcome | Resolution | Why |
//! |---|---|---|---|
//! | `DepthExceeded` | `RETRY` | rollback | A flatter decomposition of the same task can succeed. |
//! | `StepBudgetExhausted` | `RETRY` | rollback | Splitting the task into smaller walks can succeed. |
//! | `LoopDetected` | `RETRY` | rollback | The walk is not making progress; a different next step or plan can. |
//! | `StateSpaceExhausted` | `RETRY` | rollback | A narrower search can succeed. |
//! | the trip that reaches `max_trips_before_halt` (any kind) | `TERMINAL_BREACH` | halt (after rolling back) | A caller that keeps tripping is itself looping; resubmitting will not fix it. |
//! | `LifetimeBudgetExhausted` | `TERMINAL_BREACH` | halt (after rolling back) | The caller has used as much total work as `max_trips_before_halt` full walks; replaying more will not fix it. |
//! | `Halted` (any call while halted) | `TERMINAL_BREACH` | halt | Nothing changes until [`Thread::operator_reset`]. |
//! | `StaleGuard` (a call through a guard from before the last rewind) | `RETRY` | reject | Nothing changed; the caller must unwind to the root and resubmit from there. |
//!
//! Only `StaleGuard` is resolved by reject: every other trip fires after the
//! walk had already changed state. No trip is resolved by quarantine (the
//! Thread has no identity for the walker; the caller may quarantine its
//! agent using the trip as the signal). `StaleGuard` refusals do not count
//! toward `max_trips_before_halt`, because they do not touch the Thread.
//!
//! ## The rollback contract
//!
//! The Thread holds no copy of the caller's state, only counters and
//! fingerprints. Rollback is therefore split in two:
//!
//! 1. **The Thread's half.** When it returns a trip (other than `Halted` or
//!    `StaleGuard`) it has already rewound itself to the anchor: depth 0,
//!    step count 0, revisit map empty, degraded mode off. Guards still alive
//!    from before the trip become stale: they refuse further work, and
//!    dropping them does not drive the depth below zero.
//! 2. **The caller's half.** Before starting a walk, the caller takes a
//!    snapshot of whatever the walk may change. On a trip it discards all
//!    work since that snapshot and restores it, then decides whether to
//!    resubmit (on `RETRY`) or stop (on `TERMINAL_BREACH`). A trip must
//!    never be treated as a partial success. [`rollback_on_trip`] does this
//!    for any `Clone` state.
//!
//! On a clean finish the owner of the Thread calls [`Thread::rewind`] to
//! start the next walk from the anchor. Rewinding needs `&mut Thread`, so it
//! is an orchestrator action: hand the constrained agent guards (or
//! `&mut dyn Walk`), never the Thread itself. Per-walk budgets do not bound
//! a caller that can rewind; the lifetime budget does, and only
//! [`Thread::operator_reset`] clears it.
//!
//! ## Async use
//!
//! The Thread uses no thread-locals and no interior mutability. It is
//! `Send + Sync`, a [`DepthGuard`] is `Send`, and both may be held across
//! `.await`. One Thread guards one walk; concurrent walks each need their
//! own Thread.
//!
//! ## Telemetry (kernel convention 4)
//!
//! See [`telemetry`] for the metric and span names. No metric is emitted
//! per step. Labels are closed enums only. Log events carry the breadcrumb
//! path's length and full SHA-256 digest, never fingerprints. A refusal
//! through a stale guard is counted as
//! `tack_minotaur_trips_total{reason="stale_guard",outcome="retry"}`; a
//! steady rate of it means a caller is ignoring the rollback contract.
//!
//! ## Timing (kernel convention 6)
//!
//! `record` does not take constant time: a revisit is a map update, a new
//! state is a map insert, and degraded mode adds a Brent step and a
//! recent-table update (an eviction can sweep up to the table size). So the
//! latency of a step can reveal whether a state was new, whether the walk
//! was degraded, and whether it tripped. When a Thread sits on a request
//! path whose latency is protected by ANC (Active Timing Cancellation), the
//! ANC wrapper must enclose the Minotaur calls, not the other way round.
//!
//! A trip's own work is made independent of the walk length and of the log
//! level: it always writes `breadcrumb_len` path slots (the path, then zero
//! padding) and always hashes all `breadcrumb_len` slots, whether or not a
//! log event is emitted. What remains, for the ANC wrapper to cover:
//!
//! * The copy of the path out of the ring and the padding fill are both
//!   done, but at slightly different speeds, so a trip after `n < K` steps
//!   differs from one after `K` steps by a small memory-speed term.
//! * Whether a log event is formatted and written depends on the log level;
//!   that cost does not depend on the walk, but it does make trips slower
//!   than refusals under verbose logging.
//! * `Trip::path.len()` and the `path_len` log field reveal `min(steps, K)`
//!   to whoever receives the trip; the capacity of `Trip::path` does not.
//! * A trip costs a SHA-256 over `32 * breadcrumb_len` bytes (128 KiB at
//!   the ceiling), which makes a trip measurably slower than a passing step.
//!
//! ## Example
//!
//! ```
//! use tack_minotaur::{Fingerprint, MinotaurConfig, Thread, TripKind};
//!
//! let mut thread = Thread::new(MinotaurConfig { revisit_allowance: 1, ..Default::default() })?;
//! let a = Fingerprint::of_bytes(b"tool:search q=cats");
//! let b = Fingerprint::of_bytes(b"tool:open url=cats.example");
//!
//! let mut guard = thread.descend()?;
//! assert_eq!(guard.depth(), 1);
//! guard.record(a)?;
//! guard.record(b)?;
//! guard.record(a)?; // one revisit of each state is allowed
//! guard.record(b)?;
//! let trip = guard.record(a).unwrap_err(); // a second revisit is a loop
//! assert_eq!(trip.kind, TripKind::LoopDetected { period: 2, detector: tack_minotaur::Detector::Exact });
//! assert_eq!(guard.depth(), 0); // rewound to the anchor
//! // The guard is stale now: it refuses work until the caller unwinds.
//! assert_eq!(guard.record(b).unwrap_err().kind, TripKind::StaleGuard);
//! drop(guard);
//! assert_eq!(thread.depth(), 0);
//! thread.rewind(); // the owner starts the next walk
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```
//!
//! One recursive function can serve the root and every nested scope:
//!
//! ```
//! use tack_minotaur::{Fingerprint, MinotaurConfig, Thread, Trip, Walk};
//!
//! fn plan(w: &mut dyn Walk, depth_left: u32) -> Result<(), Trip> {
//!     w.record(Fingerprint::of_bytes(&depth_left.to_le_bytes()))?;
//!     if depth_left == 0 {
//!         return Ok(());
//!     }
//!     let mut child = w.descend()?;
//!     plan(&mut child, depth_left - 1)
//! }
//!
//! let mut thread = Thread::new(MinotaurConfig::default())?;
//! plan(&mut thread, 5)?;
//! assert_eq!(thread.depth(), 0);
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```
//!
//! Work in a deeper scope goes through the guard; the Thread itself is
//! borrowed until the guard is dropped:
//!
//! ```compile_fail,E0499
//! use tack_minotaur::{MinotaurConfig, Thread};
//! let mut thread = Thread::new(MinotaurConfig::default()).unwrap();
//! let guard = thread.descend().unwrap();
//! thread.descend().unwrap(); // error: `thread` is already borrowed by `guard`
//! drop(guard);
//! ```
//!
//! Code holding a guard cannot rewind the Thread (which would reset depth
//! while the outer guards are still live):
//!
//! ```compile_fail,E0596
//! use tack_minotaur::{MinotaurConfig, Thread};
//! let mut thread = Thread::new(MinotaurConfig::default()).unwrap();
//! let mut guard = thread.descend().unwrap();
//! guard.rewind(); // error: cannot borrow data in dereference of `DepthGuard` as mutable
//! ```
//!
//! nor clear a halt:
//!
//! ```compile_fail,E0596
//! use tack_minotaur::{MinotaurConfig, Thread};
//! let mut thread = Thread::new(MinotaurConfig::default()).unwrap();
//! let mut guard = thread.descend().unwrap();
//! guard.operator_reset(); // error: cannot borrow data in dereference of `DepthGuard` as mutable
//! ```
//!
//! nor swap in a fresh, unhalted Thread with a looser config:
//!
//! ```compile_fail,E0596
//! use tack_minotaur::{MinotaurConfig, Thread};
//! let mut thread = Thread::new(MinotaurConfig::default()).unwrap();
//! let mut guard = thread.descend().unwrap();
//! let fresh = Thread::new(MinotaurConfig::default()).unwrap();
//! let _old = std::mem::replace(&mut *guard, fresh); // error: DepthGuard is not DerefMut
//! ```

mod brent;
pub mod config;
mod fingerprint;
mod recent;
pub mod telemetry;
mod thread;
mod trip;

pub use config::{ConfigError, MinotaurConfig};
pub use fingerprint::Fingerprint;
pub use thread::{DepthGuard, Thread, Walk};
pub use trip::{Detector, GateOutcome, Reason, Resolution, Trip, TripKind, GATE_NAME};

/// Run `f` against `state`, and if it returns a [`Trip`], put `state` back
/// the way it was before `f` ran.
///
/// This is the caller's half of the rollback contract for any state that
/// can be cloned. `f` usually also captures the [`Thread`] (or a guard) and
/// records its transitions there. If `f` panics, `state` is not restored;
/// the panic propagates.
///
/// # Errors
/// The trip `f` returned, after `state` is restored.
pub fn rollback_on_trip<S: Clone, T>(
    state: &mut S,
    f: impl FnOnce(&mut S) -> Result<T, Trip>,
) -> Result<T, Trip> {
    let snapshot = state.clone();
    match f(state) {
        Ok(v) => Ok(v),
        Err(t) => {
            *state = snapshot;
            Err(t)
        }
    }
}
