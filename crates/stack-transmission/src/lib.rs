//! # tack-transmission: the Tractor Transmission
//!
//! **Status: new design.** This crate is a reference implementation written
//! for the TACK Governance Kernel manual. Of the kernel's seven components
//! only the Sentinel Hash-Chain exists today (in `sentinel_os`). The Tractor
//! Transmission does not exist anywhere in the TACK repositories yet; this
//! crate is its first implementation.
//!
//! ## The metaphor
//!
//! An old tractor gearbox has no synchromesh. To change gear you stop,
//! press the clutch, move the lever, and let the clutch out. Try to shift
//! while the tractor is moving and the gears grind.
//!
//! ## The goal
//!
//! A governed service has operating modes: which policy version is in force,
//! which signing key is current, which configuration is loaded, whether
//! enforcement is on. Changing one of these while requests are running
//! risks a request that starts under the old mode and finishes under the new
//! one: checked against policy v7 and logged as v8, or signed with one key
//! and verified with another. The transmission makes every mode change
//! happen only while the machine is stopped, so no request ever sees half of
//! one configuration and half of another.
//!
//! ## The design
//!
//! * A **gear** ([`Gear`]) is one immutable configuration of the caller's
//!   own type `G`, numbered with an **epoch**. The engaged gear lives behind
//!   an `Arc`.
//! * A worker calls [`Transmission::engage`] and gets a **drive guard**
//!   ([`DriveGuard`]). The guard holds its own `Arc` to the gear that was
//!   engaged at that moment, for the whole request, and counts as one unit of
//!   in-flight work. Dropping the guard (including during a panic) lowers the
//!   count.
//! * [`Transmission::shift`] **presses the clutch**: new `engage()` calls
//!   park (each up to its own timeout, then RETRY). The shift waits for the
//!   in-flight count to reach zero, swaps the gear in one step, bumps the
//!   epoch by one, and **releases the clutch**. Parked callers then proceed
//!   on the new gear.
//! * If in-flight work does not drain before the shift's timeout, the shift
//!   **rolls back**: the clutch is released, the old gear stays, and the new
//!   configuration is handed back to the caller. The gear is never
//!   half-shifted.
//! * Only one shift runs at a time. A second concurrent shift gets RETRY at
//!   once.
//! * After a rollback, the next shift waits with the clutch up for twice as
//!   long as the rolled-back shift held it ([`SHIFT_COOLDOWN_FACTOR`]), so a
//!   controller that retries at once cannot keep admission paused almost all
//!   the time.
//! * [`Transmission::shift_from`] is a compare and swap on the epoch: it
//!   refuses with RETRY `epoch_mismatch` if another shift got in first, so
//!   racing controllers do not silently lose updates and a replayed old
//!   shift is not numbered as the newest gear.
//!
//! In CNS terms (`/home/user/CNS/cns/gate.py`) `engage()` and `shift()` are
//! ALPHA-position gates: preconditions checked before any work runs.
//!
//! ### What this guarantees, and what it does not
//!
//! Guaranteed: between a guard's creation and its drop, the engaged epoch
//! does not change. So a worker that checks `current_epoch()` at the start
//! and end of its work sees the same number as its guard. That is what the
//! tests check with real threads.
//!
//! Not guaranteed: that a new configuration is valid. `G` is opaque to the
//! gearbox; parse and validate it before calling `shift()`. Plain `shift()`
//! is last-writer-wins; only `shift_from` refuses a stale configuration.
//! Also not guaranteed: fairness between a steady stream of successful
//! shifts and parked workers. The cooldown applies only after a rollback, so
//! a worker parked through several back-to-back successful shifts can time
//! out (RETRY) even though each shift is short.
//!
//! ### Tradeoff
//!
//! A shift pauses admission for up to the drain time. Long requests make
//! shifts slow or make them roll back. That is the price of never mixing
//! gears; the alternative (letting old requests finish on the old gear while
//! new ones start on the new gear) is cheaper but means two modes are live
//! at once, which is exactly what this component exists to prevent.
//!
//! ## Verdicts
//!
//! Every refusal is a typed [`Trip`] naming the [`Operation`], the
//! [`Reason`], the CNS [`GateOutcome`] (RETRY or TERMINAL_BREACH, never
//! PASS) and the [`Resolution`] (reject, rollback or halt; this component
//! never quarantines because it has no sender or agent to isolate). The
//! crate's own code does not panic, and `shift()` contains a panic from the
//! caller's `G::drop` of the replaced gear. Two panics can still reach a
//! caller, both from outside the crate: one raised by the installed metrics
//! recorder or tracing subscriber (the state is repaired and the
//! transmission halts with cause `poisoned`; see [`transmission`]), and one
//! from `G::drop` when a [`DriveGuard`] drops the last reference to an old
//! gear. `G::drop` must not panic. See [`Transmission::engage`] and
//! [`Transmission::shift`] for the full tables.
//!
//! ## Bounds
//!
//! [`TransmissionConfig`] caps guards in flight, callers parked on the
//! clutch, and both kinds of timeout. Nothing is sized by caller input.
//!
//! ## Concurrency
//!
//! `std::sync` only: one `Mutex` and two `Condvar`s. The lock order and the
//! poisoning policy are documented in [`transmission`].
//! A poisoned lock is recovered, counted, and turns into a halt that an
//! operator clears with [`Transmission::operator_reset`]; it is never
//! propagated as a panic.
//!
//! ## Telemetry
//!
//! Metric, span and alert names are in [`telemetry`]. Labels come only from
//! closed enums. The gear configuration may contain key material, so it is
//! never printed, logged or used as a label; `Debug` for [`Gear`],
//! [`DriveGuard`] and [`ShiftRefused`] shows epochs and verdicts only.
//!
//! ## Timing side channels (ANC)
//!
//! Where this component could undo Active Timing Cancellation:
//!
//! * **The clutch window is visible.** While a shift drains, `engage()`
//!   blocks. An outside observer timing requests can see that a mode change
//!   (for example a key rotation) is happening right now. ANC padding at the
//!   request boundary has to cover the longest clutch wait
//!   (`max_engage_wait`), or treat a RETRY as a response to be padded like
//!   any other.
//! * **Refusals are fast.** Over-budget, queue-full, capacity and halted
//!   refusals return without waiting, so they are quicker than a successful
//!   request. They depend only on caller-supplied timeouts and global load,
//!   not on secrets, but they do reveal load and halt state to a timer.
//! * **Shift latency shows rollbacks.** After a rollback the next `shift()`
//!   waits out a cooldown. This is visible to the controller calling
//!   `shift()`, not to request traffic, whose view is only the clutch window
//!   above.
//! * **Configuration content does not affect timing here.** The gearbox
//!   never reads, hashes or formats `G`, and telemetry work per call is the
//!   same whatever the gear holds.

pub mod config;
pub mod gear;
pub mod telemetry;
pub mod transmission;
pub mod vocab;

pub use config::{ConfigError, TransmissionConfig, MAX_CONFIGURABLE_WAIT, SHIFT_COOLDOWN_FACTOR};
pub use gear::Gear;
pub use transmission::{DriveGuard, ShiftRefused, ShiftReport, Transmission, TransmissionStatus};
pub use vocab::{GateOutcome, HaltCause, Operation, Reason, Resolution, Trip};
