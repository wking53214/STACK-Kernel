//! The weighted round-robin phase table: who owns each phase of an epoch.
//!
//! Built once, when the scheduler is built, and never changed. The table is
//! a pure function of the lane weights, so every scheduler built from the
//! same configuration owns phases in the same order.
//!
//! The order comes from smooth weighted round-robin (the method nginx uses
//! for upstream selection). Each lane keeps a running credit. For each phase,
//! every lane's credit grows by its weight, the lane with the most credit
//! (lowest index on a tie) takes the phase, and that lane's credit drops by
//! the total weight. The effect is that a lane with weight 3 out of 8 gets
//! three phases spread through the epoch rather than three in a row, which
//! keeps its worst-case wait short. After exactly `total weight` phases the
//! credits return to zero, so one epoch is one full cycle.

use crate::config::{MAX_LANES, MAX_PHASES_PER_EPOCH};
use crate::error::ConfigError;
use crate::LaneId;

/// The owner of every phase in an epoch, plus each lane's phases in order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PhaseTable {
    owners: Vec<LaneId>,
    lane_phases: Vec<Vec<u32>>,
}

impl PhaseTable {
    /// Build and self-check the table.
    ///
    /// The same caps as [`crate::GreenWaveConfig::validate`] are checked here
    /// first, before anything is allocated, because this function is public
    /// and its cost (memory in `phases`, work in `lanes * phases`) is sized by
    /// its arguments: 1..=[`MAX_LANES`] lanes, every weight at least 1,
    /// `phases` in 1..=[`MAX_PHASES_PER_EPOCH`], weights summing to `phases`.
    ///
    /// # Errors
    /// The first cap that does not hold, as the matching [`ConfigError`]; or
    /// [`ConfigError::TableMismatch`] if a lane did not get exactly `weight`
    /// phases, which is unreachable for input that passed the caps and is
    /// kept so a bug fails closed.
    pub fn build(weights: &[u32], phases: u32) -> Result<Self, ConfigError> {
        if weights.is_empty() {
            return Err(ConfigError::NoLanes);
        }
        if weights.len() > MAX_LANES {
            return Err(ConfigError::TooManyLanes {
                count: weights.len(),
                max: MAX_LANES,
            });
        }
        if phases == 0 || phases > MAX_PHASES_PER_EPOCH {
            return Err(ConfigError::PhasesOutOfRange {
                phases,
                max: MAX_PHASES_PER_EPOCH,
            });
        }
        if let Some(lane) = weights.iter().position(|&w| w == 0) {
            return Err(ConfigError::ZeroWeight { lane });
        }
        // At most MAX_LANES weights of u32 each: cannot overflow u64.
        let sum: u64 = weights.iter().map(|&w| u64::from(w)).sum();
        if sum != u64::from(phases) {
            return Err(ConfigError::WeightSumMismatch { sum, phases });
        }
        let total: i64 = weights.iter().map(|&w| i64::from(w)).sum();
        let mut credit = vec![0i64; weights.len()];
        let mut owners = Vec::with_capacity(phases as usize);
        let mut lane_phases: Vec<Vec<u32>> = weights
            .iter()
            .map(|&w| Vec::with_capacity(w as usize))
            .collect();

        for slot in 0..phases {
            let mut best: Option<(usize, i64)> = None;
            for (lane, (c, &w)) in credit.iter_mut().zip(weights).enumerate() {
                *c += i64::from(w);
                match best {
                    Some((_, b)) if *c <= b => {}
                    _ => best = Some((lane, *c)),
                }
            }
            let Some((lane, _)) = best else {
                return Err(ConfigError::NoLanes);
            };
            if let Some(c) = credit.get_mut(lane) {
                *c -= total;
            }
            let id = LaneId::from_index(lane).ok_or(ConfigError::TooManyLanes {
                count: weights.len(),
                max: MAX_LANES,
            })?;
            owners.push(id);
            if let Some(list) = lane_phases.get_mut(lane) {
                list.push(slot);
            }
        }

        for (lane, (list, &w)) in lane_phases.iter().zip(weights).enumerate() {
            if list.is_empty() || list.len() != w as usize {
                return Err(ConfigError::TableMismatch {
                    lane,
                    got: list.len(),
                    expected: w,
                });
            }
        }
        Ok(Self {
            owners,
            lane_phases,
        })
    }

    /// Phases per epoch.
    #[must_use]
    pub fn len(&self) -> usize {
        self.owners.len()
    }

    /// Always false for a built table; present for API symmetry with `len`.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.owners.is_empty()
    }

    /// Number of lanes.
    #[must_use]
    pub fn lane_count(&self) -> usize {
        self.lane_phases.len()
    }

    /// Owner of each phase, in epoch order.
    #[must_use]
    pub fn owners(&self) -> &[LaneId] {
        &self.owners
    }

    /// The lane that owns phase `phase_in_epoch`, or `None` if out of range.
    #[must_use]
    pub fn owner(&self, phase_in_epoch: u32) -> Option<LaneId> {
        self.owners.get(phase_in_epoch as usize).copied()
    }

    /// The phases (positions within an epoch) that `lane` owns, ascending.
    #[must_use]
    pub fn phases_of(&self, lane: LaneId) -> Option<&[u32]> {
        self.lane_phases.get(lane.index()).map(Vec::as_slice)
    }

    /// The first absolute phase strictly after `abs` that `lane` owns, or
    /// `None` if the lane is unknown or the result overflows. At most one
    /// binary search over the lane's phases: constant work per call up to the
    /// table size, independent of any request.
    #[must_use]
    pub fn next_phase_after(&self, lane: LaneId, abs: u64) -> Option<u64> {
        let list = self.lane_phases.get(lane.index())?;
        let phases = u64::try_from(self.owners.len()).ok()?;
        if phases == 0 {
            return None;
        }
        let pos = abs % phases;
        let base = abs - pos;
        let i = list.partition_point(|&ph| u64::from(ph) <= pos);
        match list.get(i) {
            Some(&ph) => base.checked_add(u64::from(ph)),
            None => {
                let first = u64::from(*list.first()?);
                base.checked_add(phases)?.checked_add(first)
            }
        }
    }
}
