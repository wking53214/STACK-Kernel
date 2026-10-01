//! tack-anc-pipeline: ANC (Active Timing Cancellation) strategy 3,
//! instruction-level pipeline padding.
//!
//! Status: new design. This is a reference implementation, compiled and
//! tested in this workspace; it is not deployed anywhere. Of the seven TACK
//! components only the Sentinel Hash-Chain (in `sentinel_os`) exists today.
//!
//! # The metaphor
//!
//! Two runners leave a checkpoint by different routes. Strategies 1 and 2
//! (`tack-anc-ceiling`, `tack-anc-adaptive`) make every runner wait at the
//! finish line until a fixed clock time, whichever route they took: they
//! pad up. Strategy 3 tries to make the routes themselves the same.
//! [`balanced_dummy`] makes the short route as many steps long as the long
//! one by adding laps on a side track; [`constant_time`] removes the fork,
//! so there is only one route. The lesson this crate measures is that equal
//! step counts are not equal time: the side track has different ground.
//!
//! # The goal
//!
//! An attacker who sends chosen token guesses and times the replies should
//! learn nothing about how many leading bytes of a guess were right. With
//! an early-exit compare, a guess wrong at byte 0 is answered sooner than a
//! guess wrong at byte 31, and that difference, repeated, recovers the
//! token one byte at a time.
//!
//! # The design, in plain words
//!
//! Three validators of a 32-byte token, all giving the same answers
//! (proved by a property test), measured side by side:
//!
//! * (a) [`early_exit`]: the leaky baseline. Stops at the first wrong byte.
//! * (b) [`balanced_dummy`]: the brief's design. Stops at the first wrong
//!   byte, then runs a dummy arithmetic block so every path performs 32
//!   steps. `core::hint::black_box` keeps the compiler from deleting the
//!   block; [`naive::balanced_dummy_no_black_box`] shows what happens
//!   without it (the block is deleted and the leak is back).
//! * (c) [`constant_time`]: no secret-dependent branch, no early exit, no
//!   secret-dependent memory index. It always visits all 32 byte pairs,
//!   ORs the differences together, and decides once at the end through
//!   `subtle::ConstantTimeEq`, returning a `subtle::Choice`.
//!
//! In front of the validator sits a [`PipelineGate`]: it rejects any input
//! that is not exactly 32 bytes from its length alone (before reading a
//! byte), caps the number of checks in flight, runs the validator, and
//! emits telemetry. The default and only production-allowed validator is
//! `constant_time`; the other two need `allow_leaky_validators = true`.
//!
//! Why equal instruction counts are not equal time (branch prediction,
//! caches and TLB, data-dependent latency, frequency scaling and SMT) is
//! explained in the [`validators`] module docs.
//!
//! # Threat model
//!
//! The attacker sends any number of chosen requests, sees only each
//! response and its arrival time, and can flood. The attacker cannot read
//! the metrics endpoint: this is an assumption, and it matters, because
//! `tack_anc_response_seconds` for a leaky validator is a histogram of the
//! leak. Co-resident attackers (same core through SMT, or same cache) are
//! out of scope.
//!
//! # Denial of service
//!
//! Constant-time code always pays the worst case, so the only defence is to
//! keep the worst case small and bounded: the input length is capped at
//! admission (32 bytes, rejected by length before any work), and the per
//! request cost is fixed (32 byte-pair steps plus a fixed admission and
//! telemetry overhead; see [`gate`] for the itemised bound and
//! `examples/verify.rs` for the measured nanoseconds). There is no padding
//! loop, so there is nothing an attacker can stretch. `balanced_dummy`, in
//! contrast, adds up to [`MAX_DUMMY_STEPS`] (31) steps of attacker-triggered
//! work to every fast-fail; the example measures that cost.
//!
//! # Outcomes (CNS vocabulary)
//!
//! | trip                         | outcome | resolution | why |
//! |------------------------------|---------|------------|-----|
//! | [`Trip::InputTooLarge`]      | RETRY   | reject     | length is public; a shorter resubmission may pass |
//! | [`Trip::Malformed`]          | RETRY   | reject     | same, for inputs shorter than 32 bytes |
//! | [`Trip::SlotsFull`]          | RETRY   | reject     | load only; retry later |
//! | [`Trip::Mismatch`]           | RETRY   | reject     | the caller may resubmit the right token |
//!
//! Nothing here halts, rolls back or quarantines: the gate keeps no state
//! except an in-flight counter that each request restores. There is no
//! clock-dependent decision (the clock feeds only a histogram) and no
//! adaptive target, so the ANC trips "clock unavailable" and "leakage
//! budget spent" do not arise in this strategy.
//!
//! # Measured (one release run, 4-CPU Xeon VM at 2.8 GHz, Rust 1.94)
//!
//! Command: `cargo run --release -p tack-anc-pipeline --example verify`,
//! 100,000 samples per class, classes A = wrong at byte 0 and B = wrong at
//! byte 31, timed around `PipelineGate::check`. The run is valid:
//! calibration passed (harness leaky victim max |t| 1221, constant-time
//! victim 2.0). Smallest detectable shift at this n: about 14 to 17 ns
//! through the gate, about 3 ns for the bare validators.
//!
//! | validator (through the gate) | raw t | 2nd-order t | max cropped t | KS D  | KS p  | verdict |
//! |------------------------------|-------|-------------|---------------|-------|-------|---------|
//! | early_exit                   | -7.07 | 1.15        | 684           | 0.806 | 0     | leak    |
//! | balanced_dummy               | -0.20 | -0.95       | 32.4          | 0.125 | 0     | leak    |
//! | constant_time                | 0.65  | 0.85        | 1.21          | 0.002 | 0.957 | none detected |
//!
//! * balanced_dummy was detected in every one of the five runs made with
//!   the final code (four seeds; max cropped t from 15 to 207 through the
//!   gate, KS p = 0). Its raw t is often below
//!   4.5; the difference shows in the shape of the distribution, which is
//!   why the cropped tests and KS matter. Bare medians were 50 ns versus
//!   49 ns (47 versus 50 in another run): close, not equal.
//! * constant_time passed every pair in the same five runs (primary, fixed
//!   versus random, bare, and with a metrics recorder doing real work on
//!   the path): max |t| at most 2.5, KS p at least 0.22.
//! * Without `black_box`, the filler was deleted: the counterexample has
//!   the same address as `early_exit` in the release binary (the linker
//!   merged the identical code), and it leaks like it (max |t| 1419).
//! * The release `constant_time` has no conditional branch at all: two
//!   16-byte vector compares, a mask, one `sete`, and a tail call into
//!   `subtle`'s `black_box`.
//! * Cost: about 190 to 270 ns of CPU per request through the gate for
//!   every validator (clock reads, span and metric keys dominate; the
//!   compare itself is 23 ns bare for constant_time, with no recorder
//!   installed). balanced_dummy adds 17 to
//!   29 ns of bare median time to each byte-0 fast-fail (two runs).
//! * Flood: 20 fast-fail threads against `max_in_flight = 2` for 2 s per
//!   validator: about 1.0 to 1.1 million requests per second, every shed
//!   counted in `tack_anc_shed_total`, no legitimate request exhausted its
//!   retries (mean attempts at most 1.002), in-flight back to 0. No spin CPU
//!   exists in this strategy.
//!
//! These are statistical results at one n on one machine: "not detected"
//! means not detected here, not proven constant time.
//!
//! # What is and is not proven
//!
//! The evidence is statistical (dudect-style Welch t, second-order t, KS,
//! through `tack-anc-harness`) plus a disassembly inspection of the release
//! build. Formal constant-time verification (ct-verif, binsec/rel) is the
//! only route to proof and is not available under this workspace's
//! dependency rules, so none was done. A compiler upgrade can reintroduce a
//! branch; rerun `examples/verify.rs` after one.

pub mod error;
pub mod gate;
pub mod naive;
pub mod outcome;
pub mod telemetry;
pub mod validators;

pub use error::ConfigError;
pub use gate::{PipelineConfig, PipelineGate, TokenSecret, DEFAULT_MAX_IN_FLIGHT, MAX_IN_FLIGHT};
pub use outcome::{Accepted, CheckResult, GateOutcome, Resolution, Trip};
pub use validators::{
    balanced_dummy, constant_time, early_exit, Validator, MAX_DUMMY_STEPS, TOKEN_LEN,
};
