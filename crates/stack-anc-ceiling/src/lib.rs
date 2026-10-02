//! stack-anc-ceiling: ANC (Active Timing Cancellation) strategy 1,
//! deterministic ceiling padding.
//!
//! Status: new design. This is a reference implementation, compiled and
//! tested in this workspace; it is not deployed anywhere. Of the seven TACK
//! components only the Sentinel Hash-Chain (in `sentinel_os`) exists today.
//!
//! # The metaphor
//!
//! A train that leaves on the timetable, not when the last passenger
//! boards. However long boarding took, the doors close at the scheduled
//! minute, so someone watching the platform clock learns nothing about who
//! was slow to board. Here the "boarding" is secret-dependent work (for
//! example comparing a guessed token against the real one), and the
//! "timetable" is a fixed ceiling after the request was admitted.
//!
//! # The goal
//!
//! An attacker who can send chosen requests and time the responses should
//! not be able to tell which code path the secret-dependent work took. A
//! token check that stops at the first wrong byte finishes sooner for a
//! guess that is wrong at byte 0 than for one that is wrong at byte 31;
//! timing that difference reveals the token one byte at a time. With the
//! pad, both responses leave at exactly `admission + ceiling`.
//!
//! # The design, in plain words
//!
//! 1. At admission, before anything secret happens, read the monotonic
//!    clock (`start`).
//! 2. Check public facts only: is the pad halted, is the input too long,
//!    is a concurrency slot free, is there spin budget. A failure returns
//!    at once with a fixed-shape [`Trip`] (RETRY or TERMINAL_BREACH). These
//!    fast replies depend on load, never on the secret.
//! 3. Run the operation.
//! 4. Wait until `start + ceiling`, then return. How to wait is the
//!    [`WaitMode`]: Sleep (no CPU, scheduler-grade precision), Spin
//!    (nanosecond-grade precision, burns a core), or Hybrid (sleep, then
//!    spin a short tail).
//! 5. If the operation ran past the ceiling (an overrun), release at the
//!    next whole multiple of the ceiling instead, never at the raw
//!    completion time, and count it. Past the hard ceiling
//!    (`ceiling * hard_ceiling_buckets`) the result is discarded: it is
//!    dropped at once (so its destructor runs inside the padded time), and
//!    a RETRY is released at the first whole multiple of the retry window
//!    (`hard ceiling * retry_release_factor`, default 16) at or after the
//!    drop finished. The async API cancels the operation at the hard
//!    ceiling and does the same, never releasing before the hard ceiling
//!    plus `ASYNC_TIMER_SLACK`.
//!
//! # Anti-DoS
//!
//! Padding holds each request for the whole ceiling, and spinning burns a
//! core while it does. Three limits stop that being turned against the
//! host:
//! * a spin budget ([`SpinBudgetConfig`]), a token bucket of spin CPU time
//!   per second across all requests. Each request reserves a fixed charge
//!   at admission; when the bucket is empty the request sleeps instead of
//!   spinning. The switch depends only on how many requests arrived;
//! * a concurrency cap (`max_concurrent`). Beyond it requests are shed at
//!   admission with RETRY, before any secret-dependent work;
//! * the ceiling is configuration only. No request field can change it.
//!
//! Tradeoff: a hard overrun holds its slot until the retry window `W`
//! (64 ceilings with the defaults), so a sender who can make the work slow
//! holds slots longer per request than one who cannot. The overrun alert
//! fires on it, and `retry_release_factor` trades that hold time against
//! the margin described under residual channels.
//!
//! # CNS mapping (kernel convention 1)
//!
//! | Trip | Outcome | Resolution | Why |
//! |---|---|---|---|
//! | [`Trip::SlotsFull`] | RETRY | reject | load; resubmit later |
//! | [`Trip::InputTooLarge`] | RETRY | reject | resubmit a shorter input |
//! | [`Trip::Overrun`] | RETRY | reject | work too slow this time; value discarded |
//! | [`Trip::ClockFailure`] | TERMINAL_BREACH | halt | no trustworthy clock, no padding |
//! | [`Trip::Halted`] | TERMINAL_BREACH | halt | until operator [`CeilingPad::reset`] |
//! | [`Trip::TimerUnavailable`] | TERMINAL_BREACH | reject | async API on a runtime without the tokio time driver; deployment error, the pad is not halted |
//!
//! An empty spin budget is not a trip: the request is served in Sleep mode
//! and counted in `stack_anc_spin_fallback_total`.
//!
//! # Threat model and its limits
//!
//! The attacker sends any number of chosen requests, sees each response and
//! its arrival time, and can flood. The attacker cannot read the metrics
//! endpoint: this crate exports no pre-padding work time, but the overrun
//! counter and the spin fallback counter are load facts an operator should
//! still keep private. Co-resident cache or SMT attackers are out of scope.
//!
//! Residual channels (kernel convention 6):
//! * Overrun buckets: a response released at `2 * ceiling` instead of
//!   `ceiling` says "the work was slow". If slowness depends on the secret,
//!   each overrun leaks up to `log2(hard_ceiling_buckets + 1)` bits: the
//!   `H` on-time or late buckets plus one RETRY time. That bound holds
//!   while the work plus the drop of a discarded value ends inside the
//!   first retry window `W = hard ceiling * retry_release_factor`. In the
//!   blocking API, which cannot stop the work, each further `W` of work
//!   (or of destructor time) adds one more RETRY time, so the leak there
//!   is `log2(H + ceil(t / W))` bits for work time `t`. The async API
//!   cancels at the hard ceiling, so only a future that never yields, or
//!   a cancelled future whose drop runs past `W`, can exceed it. Set the
//!   ceiling above the worst-case work time so the overrun rate is near
//!   zero, and alert on any overrun. For secret-heavy operations use
//!   `hard_ceiling_buckets = 1` and the async API.
//! * Overruns are visible to third parties: an overrunning request holds
//!   its concurrency slot until its later release, so another client's
//!   request that arrives meanwhile can be shed with RETRY where it would
//!   otherwise have been served. The shed check reads only public facts,
//!   but the slot hold time carries the overrun bit to whoever probes the
//!   cap. Known limitation; the mitigations are the same (ceiling above
//!   the worst case, `hard_ceiling_buckets = 1`, the overrun alert). Holding
//!   every slot to one fixed time would close it at a large capacity cost
//!   and is not implemented.
//! * Trip replies are different content (RETRY vs a value). Every trip is
//!   counted. Overrun RETRY is secret-influenced in the same way as the
//!   bucket; shed, input and halt replies are not.
//! * Sleep wake-up jitter can be shifted a little by cache and frequency
//!   state the secret-dependent work left behind. Hybrid reduces it at a
//!   bounded CPU cost. A flood can force Sleep (by draining the spin
//!   budget), so the Sleep mode must itself pass the leak test.
//! * Telemetry and logs are emitted after the release time is read, but
//!   still before the call returns to the caller, so their cost is inside
//!   the response time the caller sees. That cost differs by outcome only
//!   (a few extra counter updates on a trip), by nanoseconds, and never by
//!   the work time or the input contents beyond the length the sender
//!   already knows (the debug-level input digest is computed only when
//!   debug logging is on).
//!
//! # Quick use
//!
//! ```
//! use std::time::Duration;
//! use sstack_anc_ceiling::{CeilingConfig, CeilingPad, WaitMode};
//!
//! let pad = CeilingPad::new(CeilingConfig {
//!     mode: WaitMode::Hybrid,
//!     ..CeilingConfig::new(Duration::from_micros(500))
//! })?;
//! // Test fixture, not a real token.
//! let secret = [7u8; 32];
//! let guess = [0u8; 32];
//! let reply = pad.pad(|| secret == guess);
//! match reply {
//!     Ok(p) => assert!(!p.value && p.release.observed >= Duration::from_micros(500)),
//!     Err(trip) => println!("{} {:?}", trip.gate_outcome().as_str(), trip.resolution()),
//! }
//! # Ok::<(), stack_anc_ceiling::ConfigError>(())
//! ```

pub mod clock;
pub mod config;
pub mod outcome;
pub mod telemetry;
pub mod wait;

mod budget;
mod pad;
mod slots;

pub use clock::{Clock, MonotonicClock};
pub use config::{CeilingConfig, ConfigError, SpinBudgetConfig, WaitMode};
pub use outcome::{GateOutcome, PadResult, Padded, ReleaseInfo, Resolution, Trip};
pub use pad::CeilingPad;
pub use wait::{bucket_offset, release_bucket};
