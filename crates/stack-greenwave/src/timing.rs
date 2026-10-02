//! The phase and epoch grid, and release quantization.
//!
//! Time is cut into phases of equal length, and `phases_per_epoch`
//! consecutive phases make an epoch. Phase `n` (the "absolute phase") covers
//! `[n * phase_len, (n + 1) * phase_len)`. Its position inside its epoch is
//! `n % phases_per_epoch`. Epoch boundaries are the multiples of the epoch
//! length. All arithmetic is checked; an overflow is reported as `None`.

use crate::clock::Nanos;

/// The grid. Built only from a validated configuration, so `phase_len` and
/// `phases` are non-zero and `epoch_len = phase_len * phases` fits.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Timing {
    phase_len: Nanos,
    phases: u32,
    epoch_len: Nanos,
}

impl Timing {
    /// Callers pass validated values; `epoch_len` was checked to fit.
    pub(crate) const fn new(phase_len: Nanos, phases: u32, epoch_len: Nanos) -> Self {
        Self {
            phase_len,
            phases,
            epoch_len,
        }
    }

    /// Phase length in nanoseconds.
    #[must_use]
    pub const fn phase_len(&self) -> Nanos {
        self.phase_len
    }

    /// Phases per epoch.
    #[must_use]
    pub const fn phases_per_epoch(&self) -> u32 {
        self.phases
    }

    /// Epoch length in nanoseconds.
    #[must_use]
    pub const fn epoch_len(&self) -> Nanos {
        self.epoch_len
    }

    /// The absolute phase containing time `t`.
    #[must_use]
    pub const fn abs_phase(&self, t: Nanos) -> u64 {
        // phase_len is non-zero by construction.
        t / self.phase_len
    }

    /// The position of absolute phase `abs` inside its epoch.
    #[must_use]
    pub fn phase_in_epoch(&self, abs: u64) -> u32 {
        // The remainder is below `phases`, which is a u32, so this cannot
        // fail; the fallback keeps the function total without a panic path.
        u32::try_from(abs % u64::from(self.phases)).unwrap_or(0)
    }

    /// The epoch index containing time `t`.
    #[must_use]
    pub const fn epoch_index(&self, t: Nanos) -> u64 {
        t / self.epoch_len
    }

    /// Start time of absolute phase `abs`, or `None` on overflow.
    #[must_use]
    pub const fn phase_start(&self, abs: u64) -> Option<Nanos> {
        abs.checked_mul(self.phase_len)
    }

    /// True when `t` is exactly on an epoch boundary.
    #[must_use]
    pub const fn is_epoch_boundary(&self, t: Nanos) -> bool {
        t % self.epoch_len == 0
    }

    /// Release quantization: the first epoch boundary strictly after
    /// `completed_at`, or `None` on overflow.
    ///
    /// "Strictly after" is the literal reading of the design: a result that
    /// completes exactly on a boundary waits for the next one. Either way the
    /// release time is a function of the epoch the completion fell in, not of
    /// where inside that epoch it fell, which is the property ANC needs.
    #[must_use]
    pub fn release_at(&self, completed_at: Nanos) -> Option<Nanos> {
        self.epoch_index(completed_at)
            .checked_add(1)?
            .checked_mul(self.epoch_len)
    }
}
