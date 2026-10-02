//! Caps for a [`crate::Thread`], with documented defaults and hard ceilings.
//!
//! Every number that bounds memory or work lives here. The operator sets
//! these; nothing a walker submits can change them, and no allocation in
//! this crate is sized by anything other than a validated field of this
//! struct.

use thiserror::Error;

/// Largest accepted [`MinotaurConfig::max_depth`].
pub const MAX_DEPTH_CEILING: u32 = 1 << 16;
/// Largest accepted [`MinotaurConfig::max_steps`].
pub const MAX_STEPS_CEILING: u64 = 1 << 40;
/// Largest accepted [`MinotaurConfig::max_distinct_states`]. The exact set is
/// preallocated to this many entries, so this is also the memory ceiling:
/// about 2^20 entries of roughly 48 bytes plus hash table overhead.
pub const MAX_DISTINCT_STATES_CEILING: usize = 1 << 20;
/// Largest accepted [`MinotaurConfig::revisit_allowance`].
pub const REVISIT_ALLOWANCE_CEILING: u32 = 1 << 16;
/// Largest accepted [`MinotaurConfig::breadcrumb_len`]. The breadcrumb ring is
/// preallocated to this many 32-byte fingerprints.
pub const BREADCRUMB_LEN_CEILING: usize = 4096;
/// Largest accepted [`MinotaurConfig::max_cycle_period`].
pub const MAX_CYCLE_PERIOD_CEILING: u64 = 1 << 24;
/// Largest accepted [`MinotaurConfig::max_untracked_transitions`].
pub const MAX_UNTRACKED_TRANSITIONS_CEILING: u64 = 1 << 40;
/// Largest accepted [`MinotaurConfig::max_trips_before_halt`].
pub const MAX_TRIPS_BEFORE_HALT_CEILING: u32 = 1 << 16;

/// The caps one [`crate::Thread`] enforces.
///
/// | Field | Default | Bounds |
/// |---|---|---|
/// | `max_depth` | 64 | 1 ..= 65 536 |
/// | `max_steps` | 100 000 | 1 ..= 2^40 |
/// | `max_distinct_states` | 4 096 | 1 ..= 2^20 |
/// | `revisit_allowance` | 3 | 0 ..= 65 536 |
/// | `breadcrumb_len` | 32 | 1 ..= 4 096 |
/// | `max_cycle_period` | 256 | 1 ..= 2^24 |
/// | `max_untracked_transitions` | 16 384 | 0 ..= 2^40 |
/// | `max_trips_before_halt` | 8 | 1 ..= 65 536 |
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MinotaurConfig {
    /// Deepest nesting allowed. Depth `max_depth` is legal; the descent that
    /// would go one level deeper trips `DepthExceeded`.
    pub max_depth: u32,
    /// Total transitions (calls to `record`) allowed in one walk. The
    /// transition that would be number `max_steps + 1` trips
    /// `StepBudgetExhausted`.
    pub max_steps: u64,
    /// Size of the exact revisit set. When it is full, new states are not
    /// added; the Thread degrades to Brent's cycle detection plus a
    /// recent-state table of `min(max_cycle_period, max_distinct_states)`
    /// slots instead.
    pub max_distinct_states: usize,
    /// How many times a state may be revisited (visits beyond the first)
    /// before the walk counts as a loop. `0` means any revisit is a loop.
    pub revisit_allowance: u32,
    /// K, the number of most recent fingerprints kept as the breadcrumb path
    /// returned in a `Trip`.
    pub breadcrumb_len: usize,
    /// Longest cycle the degraded (Brent) detector is guaranteed to find.
    /// Also caps the recent-state table, which holds
    /// `min(max_cycle_period, max_distinct_states)` untracked states and
    /// counts exactly the revisits of any state whose visits are fewer than
    /// that many untracked transitions apart. Longer cycles and longer gaps
    /// among untracked states are caught by `max_untracked_transitions` or
    /// `max_steps` instead.
    pub max_cycle_period: u64,
    /// Transitions onto states the full exact set could not hold that one walk
    /// may make before it trips `StateSpaceExhausted`. This is the
    /// state-space explosion guard: a walk that keeps discovering new states
    /// after the set is full is exploring without bound. `0` trips on the
    /// first state the set cannot hold.
    pub max_untracked_transitions: u64,
    /// Trips (since construction or the last `operator_reset`) after which
    /// the Thread halts. The trip that reaches this count is reported as
    /// `TERMINAL_BREACH` with resolution halt, and every later call is
    /// refused until an operator resets the Thread.
    ///
    /// Also sets the lifetime budget: `max_steps * max_trips_before_halt`
    /// accepted transitions between operator resets, across all walks. The
    /// next transition trips `LifetimeBudgetExhausted`, which halts. A
    /// long-lived Thread that serves many legitimate walks will reach it
    /// and needs a periodic operator reset (or one Thread per task).
    pub max_trips_before_halt: u32,
}

impl Default for MinotaurConfig {
    fn default() -> Self {
        Self {
            max_depth: 64,
            max_steps: 100_000,
            max_distinct_states: 4_096,
            revisit_allowance: 3,
            breadcrumb_len: 32,
            max_cycle_period: 256,
            max_untracked_transitions: 16_384,
            max_trips_before_halt: 8,
        }
    }
}

/// A config field outside its accepted range.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum ConfigError {
    /// A field that must be at least 1 was 0.
    #[error("config field `{field}` must be at least 1")]
    Zero {
        /// The field name.
        field: &'static str,
    },
    /// A field exceeded its hard ceiling.
    #[error("config field `{field}` exceeds its ceiling of {ceiling}")]
    AboveCeiling {
        /// The field name.
        field: &'static str,
        /// The largest accepted value.
        ceiling: u64,
    },
}

fn check(field: &'static str, value: u64, min: u64, ceiling: u64) -> Result<(), ConfigError> {
    if value < min {
        return Err(ConfigError::Zero { field });
    }
    if value > ceiling {
        return Err(ConfigError::AboveCeiling { field, ceiling });
    }
    Ok(())
}

impl MinotaurConfig {
    /// Check every field against its bounds. [`crate::Thread::new`] calls
    /// this, so an invalid config never produces a Thread.
    ///
    /// # Errors
    /// The first field found outside its range.
    pub fn validate(&self) -> Result<(), ConfigError> {
        check(
            "max_depth",
            u64::from(self.max_depth),
            1,
            u64::from(MAX_DEPTH_CEILING),
        )?;
        check("max_steps", self.max_steps, 1, MAX_STEPS_CEILING)?;
        check(
            "max_distinct_states",
            usize_to_u64(self.max_distinct_states),
            1,
            usize_to_u64(MAX_DISTINCT_STATES_CEILING),
        )?;
        check(
            "revisit_allowance",
            u64::from(self.revisit_allowance),
            0,
            u64::from(REVISIT_ALLOWANCE_CEILING),
        )?;
        check(
            "breadcrumb_len",
            usize_to_u64(self.breadcrumb_len),
            1,
            usize_to_u64(BREADCRUMB_LEN_CEILING),
        )?;
        check(
            "max_cycle_period",
            self.max_cycle_period,
            1,
            MAX_CYCLE_PERIOD_CEILING,
        )?;
        check(
            "max_untracked_transitions",
            self.max_untracked_transitions,
            0,
            MAX_UNTRACKED_TRANSITIONS_CEILING,
        )?;
        check(
            "max_trips_before_halt",
            u64::from(self.max_trips_before_halt),
            1,
            u64::from(MAX_TRIPS_BEFORE_HALT_CEILING),
        )?;
        Ok(())
    }
}

/// Lossless on every supported target; saturates rather than panics if a
/// future target had a wider `usize`.
pub(crate) fn usize_to_u64(v: usize) -> u64 {
    u64::try_from(v).unwrap_or(u64::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_is_valid() {
        assert_eq!(MinotaurConfig::default().validate(), Ok(()));
    }

    #[test]
    fn zero_depth_rejected() {
        let c = MinotaurConfig {
            max_depth: 0,
            ..MinotaurConfig::default()
        };
        assert_eq!(c.validate(), Err(ConfigError::Zero { field: "max_depth" }));
    }

    #[test]
    fn oversized_set_rejected() {
        let c = MinotaurConfig {
            max_distinct_states: MAX_DISTINCT_STATES_CEILING + 1,
            ..MinotaurConfig::default()
        };
        assert!(matches!(
            c.validate(),
            Err(ConfigError::AboveCeiling {
                field: "max_distinct_states",
                ..
            })
        ));
    }

    #[test]
    fn zero_allowance_and_untracked_budget_are_legal() {
        let c = MinotaurConfig {
            revisit_allowance: 0,
            max_untracked_transitions: 0,
            ..MinotaurConfig::default()
        };
        assert_eq!(c.validate(), Ok(()));
    }
}
