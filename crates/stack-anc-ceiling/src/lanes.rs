//! A standard lane and a fast lane, each with its own booths.
//!
//! Think of a toll plaza with a regular gate and a "fast pass" gate. A car
//! does not pick its gate by telling the booth what it is carrying. The
//! plaza's own layout decides: each entrance (route, listener, endpoint) is
//! wired to one gate when the server starts, and a handler holds only that
//! gate. So the sender cannot choose a lane, and a request cannot move
//! itself to the fast one.
//!
//! # What the fast lane is for
//!
//! Operations whose cost is a fixed, known constant and which never touch
//! a secret: a health check, a static lookup, a counter read. They get a
//! much shorter fixed time than the standard lane, so they do not wait
//! behind the standard ceiling. Because their cost does not vary with any
//! secret, an observer who watches this lane learns nothing; the lane may
//! be watched freely. What matters is that every request on it takes the
//! same time, which each lane's own timing test checks.
//!
//! # What keeps a mislabeled operation from hurting
//!
//! * The fast lane has **no input method**. An operation on it cannot be
//!   handed sender-chosen bytes through the pad.
//! * Its **hard ceiling is one ceiling**: an operation that runs longer is
//!   discarded and answered with a RETRY on the retry window, never
//!   released late at some multiple. A fast-lane operation is therefore
//!   either on time or a RETRY, and the RETRY says only "this was not a
//!   fixed-cost operation".
//! * Every such overrun is **counted** ([`LanedPad::fast_overruns`]) and
//!   the first one is logged at warn level. In a correct deployment the
//!   count stays at zero; a nonzero count is a wiring bug to fix, not
//!   traffic to tolerate.
//! * The fast ceiling must be **shorter than the standard ceiling**, so
//!   the fast gate cannot be used to buy a longer window.
//! * The two lanes have **separate slots**, spin budgets, scaling and
//!   spillway, so a flood on one lane cannot shed requests on the other.
//!
//! # What this does not do
//!
//! The pad cannot prove an operation is fixed-cost. Choosing which
//! entrances use the fast gate is a code-review decision, recorded where
//! the routes are wired. Only operations that never read a secret
//! belong on it.

//! ```compile_fail
//! // The fast gate has no input method.
//! use std::time::Duration;
//! use stack_anc_ceiling::{CeilingConfig, LanedPad};
//! let lanes = LanedPad::new(
//!     CeilingConfig::new(Duration::from_millis(10)),
//!     CeilingConfig { hard_ceiling_buckets: 1, ..CeilingConfig::new(Duration::from_millis(1)) },
//! ).unwrap();
//! let _ = lanes.fast().pad_input(b"sender bytes", |_| ());
//! ```

use crate::clock::MonotonicClock;
use crate::config::{CeilingConfig, ConfigError};
use crate::outcome::{PadResult, Trip};
use crate::pad::CeilingPad;
use std::future::Future;
use std::sync::atomic::{AtomicU64, Ordering};

/// Two lanes, each its own [`CeilingPad`].
///
/// Hand [`LanedPad::standard`] or [`LanedPad::fast`] to a route when the
/// server starts. Do not choose between them per request.
#[derive(Debug)]
pub struct LanedPad {
    standard: CeilingPad<MonotonicClock>,
    fast: CeilingPad<MonotonicClock>,
    fast_overruns: AtomicU64,
}

/// The fast gate. It can run an operation and nothing else: no input, no
/// way to reach the standard lane.
#[derive(Debug, Clone, Copy)]
pub struct FastLane<'a> {
    pad: &'a CeilingPad<MonotonicClock>,
    overruns: &'a AtomicU64,
}

impl LanedPad {
    /// Build both lanes.
    ///
    /// `fast` must have `hard_ceiling_buckets == 1` and a ceiling strictly
    /// shorter than `standard`'s. Each config is also checked as usual.
    pub fn new(standard: CeilingConfig, fast: CeilingConfig) -> Result<Self, ConfigError> {
        standard.validate()?;
        fast.validate()?;
        if fast.hard_ceiling_buckets != 1 {
            return Err(ConfigError {
                field: "fast.hard_ceiling_buckets",
                reason: "the fast lane must have a hard ceiling of exactly one ceiling",
            });
        }
        if fast.ceiling >= standard.ceiling {
            return Err(ConfigError {
                field: "fast.ceiling",
                reason: "the fast lane ceiling must be shorter than the standard ceiling",
            });
        }
        Ok(Self {
            standard: CeilingPad::new(standard)?,
            fast: CeilingPad::new(fast)?,
            fast_overruns: AtomicU64::new(0),
        })
    }

    /// The standard lane: the full pad, for anything that touches a secret.
    pub fn standard(&self) -> &CeilingPad<MonotonicClock> {
        &self.standard
    }

    /// The fast lane, for fixed-cost operations that never touch a secret.
    pub fn fast(&self) -> FastLane<'_> {
        FastLane {
            pad: &self.fast,
            overruns: &self.fast_overruns,
        }
    }

    /// Fast-lane operations that ran past the fast ceiling. Should stay
    /// zero: a nonzero value means something on the fast gate is not a
    /// fixed-cost operation.
    pub fn fast_overruns(&self) -> u64 {
        self.fast_overruns.load(Ordering::Relaxed)
    }

    /// Slots open in the fast lane right now.
    pub fn fast_slots_open(&self) -> usize {
        self.fast.slots_open()
    }

    /// True if either lane was halted by a clock failure.
    pub fn is_halted(&self) -> bool {
        self.standard.is_halted() || self.fast.is_halted()
    }

    /// Operator reset of both lanes after a halt.
    pub fn reset(&self) {
        self.standard.reset();
        self.fast.reset();
    }
}

impl FastLane<'_> {
    /// Run `op` on the fast lane, blocking the calling thread. See
    /// [`CeilingPad::pad`].
    pub fn pad<T, F>(&self, op: F) -> PadResult<T>
    where
        F: FnOnce() -> T,
    {
        self.note(self.pad.pad(op))
    }

    /// Async form of [`FastLane::pad`]. See [`CeilingPad::pad_async`].
    pub async fn pad_async<T, F, Fut>(&self, op: F) -> PadResult<T>
    where
        F: FnOnce() -> Fut,
        Fut: Future<Output = T>,
    {
        self.note(self.pad.pad_async(op).await)
    }

    /// Slots open in this lane right now.
    pub fn slots_open(&self) -> usize {
        self.pad.slots_open()
    }

    fn note<T>(&self, result: PadResult<T>) -> PadResult<T> {
        if matches!(result, Err(Trip::Overrun)) && self.overruns.fetch_add(1, Ordering::Relaxed) == 0 {
            tracing::warn!(
                "fast lane operation ran past its ceiling: it is not a fixed-cost operation and belongs on the standard lane"
            );
        }
        result
    }
}
