//! The green wave: when each stage should see a dispatched request.
//!
//! A request dispatched in absolute phase `p` is due at stage `i` in absolute
//! phase `p + offset[i]`. Inside the epoch that is position
//! `(p + offset[i]) % phases_per_epoch`, which is what "modulo the phase
//! count" means in the design. Offsets are non-decreasing and each is below
//! the phase count, so the whole wave fits inside one epoch after dispatch
//! and the modulo map from stage to position is unambiguous.
//!
//! Like lights timed for the design speed, a stage that runs on schedule
//! finds its input waiting and never idles on it, and a request never waits
//! at a stage longer than the gap between its offsets.

use crate::clock::Nanos;
use crate::error::TripReason;
use crate::timing::Timing;

/// When one stage is due for one request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StageSlot {
    /// Stage index.
    pub stage: usize,
    /// The stage's configured offset in phases.
    pub offset: u32,
    /// Absolute phase in which the stage is due.
    pub abs_phase: u64,
    /// That phase's position inside its epoch.
    pub phase_in_epoch: u32,
    /// Start time of that phase: the moment the stage's light turns green.
    pub due_at: Nanos,
}

/// The offset table.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GreenWave {
    offsets: Vec<u32>,
    timing: Timing,
}

impl GreenWave {
    /// `offsets` must already have passed validation.
    pub(crate) fn new(offsets: Vec<u32>, timing: Timing) -> Self {
        Self { offsets, timing }
    }

    /// The configured offsets, by stage.
    #[must_use]
    pub fn offsets(&self) -> &[u32] {
        &self.offsets
    }

    /// Number of stages.
    #[must_use]
    pub fn stage_count(&self) -> usize {
        self.offsets.len()
    }

    /// The slot for `stage` of a request dispatched in absolute phase
    /// `dispatch_phase`.
    ///
    /// # Errors
    /// [`TripReason::UnknownStage`] if `stage` is past the table,
    /// [`TripReason::Overflow`] if the due time does not fit in `u64`.
    pub fn slot(&self, dispatch_phase: u64, stage: usize) -> Result<StageSlot, TripReason> {
        let offset = *self.offsets.get(stage).ok_or(TripReason::UnknownStage)?;
        let abs_phase = dispatch_phase
            .checked_add(u64::from(offset))
            .ok_or(TripReason::Overflow)?;
        let due_at = self
            .timing
            .phase_start(abs_phase)
            .ok_or(TripReason::Overflow)?;
        Ok(StageSlot {
            stage,
            offset,
            abs_phase,
            phase_in_epoch: self.timing.phase_in_epoch(abs_phase),
            due_at,
        })
    }

    /// Every stage's slot for a request dispatched in `dispatch_phase`, in
    /// stage order. At most [`crate::config::MAX_STAGES`] entries.
    ///
    /// # Errors
    /// [`TripReason::Overflow`] if any due time does not fit in `u64`.
    pub fn schedule(&self, dispatch_phase: u64) -> Result<Vec<StageSlot>, TripReason> {
        (0..self.offsets.len())
            .map(|stage| self.slot(dispatch_phase, stage))
            .collect()
    }
}
