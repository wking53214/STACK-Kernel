//! # tack-bumpers: Elastic Bumpers for the TACK governance kernel
//!
//! **Status: new design.** Of the seven TACK kernel components, only the
//! Sentinel Hash-Chain exists today (in `sentinel_os`). Elastic Bumpers is
//! one of the six new designs. This crate is its reference implementation;
//! it is not yet wired into any of the Python repositories.
//!
//! ## The metaphor
//!
//! A loading dock has rubber bumpers on its edge. A truck that backs in a
//! little off line hits the rubber, the rubber gives, and the truck ends up
//! where it should be. A truck that hits at speed still stops at the
//! concrete behind the rubber. The bumper is for small honest mistakes, not
//! for crashes.
//!
//! ## The goal
//!
//! Callers drift. One sends `"High"` where the spec says `"high"`, one sends
//! `" high "` with stray spaces, one sends a timeout of `1500` milliseconds
//! to a parameter declared in seconds, one sends `1.02` where the soft limit
//! is `1.0`. Refusing all of these makes the system brittle. Silently
//! accepting anything makes it unsafe. The bumper sits between:
//!
//! 1. It **normalizes** small drift into the canonical form.
//! 2. It **counts** every change as a [`Correction`] and returns the list.
//! 3. It **refuses** anything outside the elastic band, with a typed verdict.
//!
//! ## The design, in plain words
//!
//! Each parameter has a declarative [`ParamSpec`], written by the operator:
//!
//! * [`NumericSpec`]: four numbers, `hard_min <= soft_min <= soft_max <=
//!   hard_max`. Inside the soft band a value passes as is. Between the soft
//!   and hard edges it is clamped to the nearest soft edge (the rubber).
//!   Past a hard edge it is refused as TERMINAL_BREACH (the concrete).
//!   A numeric spec may declare units; a value tagged with an alternate
//!   unit is converted to the canonical unit.
//! * [`EnumSpec`]: canonical variant names plus aliases. Input is trimmed,
//!   ASCII case folded and alias resolved.
//! * [`StringSpec`]: a byte length range (`min_len`, default 1, to
//!   `max_len`), a [`TrimPolicy`] and a [`CharPolicy`]. The default
//!   `min_len` means an empty or whitespace-only value never satisfies a
//!   string parameter. `TrimPolicy::Reject` specs refuse control and
//!   format characters by default.
//!
//! A [`Bumper`] holds the specs and a [`BumperConfig`]. Its one operation,
//! [`Bumper::normalize`], takes the whole parameter map and returns either a
//! [`Normalized`] result (PASS, with values and corrections) or a
//! [`Rejection`] (RETRY or TERMINAL_BREACH, with every trip found).
//!
//! | What happened                                  | Outcome         |
//! |------------------------------------------------|-----------------|
//! | Everything in band, corrections within budget  | PASS            |
//! | More corrections than the budget (default 3)   | RETRY           |
//! | Unknown parameter (fail closed)                | RETRY           |
//! | Missing required parameter                     | RETRY           |
//! | Wrong value type, unknown variant, unknown unit| RETRY           |
//! | String too long or too short (empty)           | RETRY           |
//! | Whitespace, or a control or format character,  | RETRY           |
//! | on a strict (`Reject`) string                  |                 |
//! | Number outside the hard band                   | TERMINAL_BREACH |
//! | NaN or infinity, under any key, declared or not| TERMINAL_BREACH |
//! | Request over the global size caps, including a | TERMINAL_BREACH |
//! | text value or unit under an unknown key        |                 |
//!
//! Every refusal resolves as [`Resolution::Reject`]: nothing changed. The
//! bumper is a pure function with no state, so there is nothing to roll
//! back, no sender identity to quarantine, and no reason to halt.
//!
//! ### Why NaN is never clamped
//!
//! Rust's `f64::clamp(NaN, lo, hi)` returns NaN. A "clamp everything into
//! range" step built on it lets NaN straight through while looking safe,
//! and NaN then poisons every comparison downstream (every `<` and `>` with
//! NaN is false). This crate refuses NaN and both infinities before any
//! arithmetic and writes its band test so that NaN would fail it anyway.
//!
//! ### Monotone and idempotent
//!
//! For accepted values, normalization is monotone (`x <= y` implies
//! `n(x) <= n(y)`: clamping never reorders values) and idempotent
//! (`n(n(x)) == n(x)`, and the second pass makes no corrections). Both are
//! checked with property tests in `tests/properties.rs`.
//!
//! ### Dropping versus clamping
//!
//! The nearest existing analog is `sanitize_context` in
//! `observe-perceive/observe_consolidated.py`. It **drops** a context value
//! that is non-numeric, non-finite or out of its physical range, and the
//! engine then treats that signal as absent. It records a free-text note for
//! each drop. Its one production call site (observe_consolidated.py, line
//! 1435 as read on 2026-09-30) binds those notes to `_context_notes` and
//! never reads them; only its tests do.
//!
//! Dropping and clamping answer different questions:
//!
//! * Dropping says "this value is not trustworthy, act as if it was never
//!   sent". It is right when the consumer already handles absence well, as
//!   the observe-perceive engine does. It loses information: a reading of
//!   101 against a limit of 100 becomes no reading at all.
//! * Clamping says "this value is close enough to mean the limit". It keeps
//!   the signal, but it changes a value the caller sent, so it is only safe
//!   inside a declared elastic band, and only when every change is visible.
//!
//! The bumper clamps inside the soft-to-hard margin and refuses (it does
//! not drop) past the hard edge. It never drops silently, because a missing
//! parameter changes what a request means just as much as a wrong one.
//!
//! ### Why the kernel counts corrections
//!
//! A correction is the system changing what a caller asked for. Uncounted,
//! a steady stream of small changes is invisible, and "small drift" can be
//! how an attacker walks a parameter to its limit one nudge at a time, or
//! how a broken client hides behind the bumper for months. Counting makes
//! drift a measured quantity: per request (the budget turns too much drift
//! into RETRY so the caller must fix its inputs) and over time (the
//! `tack_bumpers_corrections_total` counter shows which kinds of drift are
//! rising). `sanitize_context` produces notes that production never reads;
//! here every correction is returned to the caller and counted in metrics.
//!
//! ## Facts and assumptions
//!
//! * Fact: the verdict vocabulary (`pass`, `retry`, `terminal_breach`,
//!   `alpha`, `omega`) matches `cns/gate.py`. See [`GateOutcome`].
//! * Assumption: the caller has already parsed its wire format into a
//!   `BTreeMap<String, ParamValue>`. Duplicate keys, if the wire format
//!   allows them, must be refused by that parser; a map cannot hold them.
//! * Assumption: unit names on a [`ParamValue::Quantity`] come from the
//!   caller explicitly. The bumper never infers a unit from magnitude.
//!
//! ## Telemetry
//!
//! Metrics (via the `metrics` facade, labels from closed enums only):
//!
//! * `tack_bumpers_requests_total{outcome}` counter, one per call.
//! * `tack_bumpers_trips_total{reason,outcome}` counter, one per trip.
//! * `tack_bumpers_corrections_total{kind}` counter, one per applied
//!   correction (passing requests only; a refused request applies nothing).
//! * `tack_bumpers_corrections_per_request` histogram, passing requests.
//! * `tack_bumpers_normalize_duration_seconds{outcome}` histogram.
//!
//! Spans: `tack.bumpers.normalize` and `tack.bumpers.build`. Trip events
//! are at DEBUG and carry the spec name, reason and outcome, and for caller
//! text only its byte length and full SHA-256 hex digest (`input_len`,
//! `input_sha256`). Text over `max_input_bytes` is logged by length only,
//! with `input_over_cap=true`, and is never hashed. A TERMINAL_BREACH request
//! writes exactly one WARN line, `bumper terminal breach`, with trip counts
//! by reason, so log volume at WARN is one line per request, not one per
//! entry.
//!
//! ## Timing (ANC)
//!
//! The bumper is not constant time and does not try to be; Active Timing
//! Cancellation must wrap the whole request boundary. Known variations:
//! refused requests do more work than passing ones (one extra counter per
//! trip, the SHA-256 of each unknown key within the cap, and a WARN summary
//! for a TERMINAL_BREACH); an enum lookup is a map search whose cost depends
//! on the input; a `Reject` string is scanned for control and format
//! characters; digests of declared values in DEBUG trip lines are computed
//! only when a subscriber enables DEBUG, so the log level changes timing;
//! and a unit conversion that divides a subnormal value can be slower on
//! some CPUs. Refusal work for text over `max_input_bytes` is bounded by the
//! cap, not by the size the caller sent: such text is measured, never
//! hashed. A request over `max_params` returns before reading any entry,
//! which is observably faster; that is deliberate, since the cap is public.
//!
//! ## Example
//!
//! ```
//! use std::collections::BTreeMap;
//! use tack_bumpers::{Bumper, BumperConfig, EnumSpec, NumericSpec, ParamSpec,
//!     ParamValue, UnitScale, VariantSpec};
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! let bumper = Bumper::new(BumperConfig::default(), [
//!     ParamSpec::required("timeout",
//!         NumericSpec::new(0.0, 0.5, 30.0, 300.0)?
//!             .with_units("s", &[("ms", UnitScale::Divide(1000.0))])?),
//!     ParamSpec::required("priority",
//!         EnumSpec::new([VariantSpec::new("low"), VariantSpec::new("high").alias("hi")])?),
//! ])?;
//!
//! let mut req = BTreeMap::new();
//! req.insert("timeout".to_owned(), ParamValue::Quantity { value: 1500.0, unit: "ms".into() });
//! req.insert("priority".to_owned(), ParamValue::Text("High".into()));
//!
//! let ok = bumper.normalize(&req)?;
//! assert_eq!(ok.get("timeout").and_then(|v| v.as_f64()), Some(1.5));
//! assert_eq!(ok.get("priority").and_then(|v| v.as_str()), Some("high"));
//! assert_eq!(ok.corrections().len(), 2); // unit converted, case folded
//! # Ok(())
//! # }
//! ```

mod bumper;
mod config;
mod error;
mod outcome;
mod spec;
pub mod telemetry;
mod value;

pub use bumper::{Bumper, Normalized};
pub use config::BumperConfig;
pub use error::{Rejection, SpecError, Trip, TripParam, TripReason};
pub use outcome::{GateOutcome, GatePosition, Resolution};
pub use spec::{
    CharPolicy, EnumSpec, NumericSpec, ParamSpec, Presence, SpecKind, StringSpec, TrimPolicy, UnitScale, VariantSpec,
};
pub use value::{Correction, CorrectionKind, NormalizedValue, ParamValue, SoftEdge};
