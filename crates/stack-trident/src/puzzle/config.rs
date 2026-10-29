//! Every cap the puzzle gate enforces, with documented defaults and hard
//! ceilings that validation will not let a caller exceed.

use crate::config::ConfigError;

/// Hard ceiling on `max_pieces`.
pub const MAX_PIECES_CEILING: u32 = 1_024;
/// Hard ceiling on `max_piece_bytes`: 1 MiB.
pub const MAX_PIECE_BYTES_CEILING: usize = 1024 * 1024;
/// Hard ceiling on `max_pieces * max_piece_bytes`: 16 MiB.
pub const MAX_WHOLE_BYTES_CEILING: usize = 16 * 1024 * 1024;
/// Hard ceiling on either lifetime setting: one hour.
pub const LIFETIME_CEILING_MS: u64 = 3_600_000;
/// Hard ceiling on `max_open_per_sender`.
pub const OPEN_PER_SENDER_CEILING: usize = 1_024;
/// Hard ceiling on `max_open_total`.
pub const OPEN_TOTAL_CEILING: usize = 1_048_576;
/// Hard ceiling on `max_held_bytes`: 1 GiB.
pub const HELD_BYTES_CEILING: usize = 1024 * 1024 * 1024;
/// Hard ceiling on `lookback_wholes`.
pub const LOOKBACK_CEILING: usize = 16;
/// Hard ceiling on `history_tail_bytes`: 1 MiB.
pub const TAIL_BYTES_CEILING: usize = 1024 * 1024;
/// Hard ceiling on `memory_capacity`.
pub const MEMORY_CAPACITY_CEILING: usize = 4_194_304;
/// Hard ceiling on `breaker_free` and `breaker_threshold`.
pub const BREAKER_COUNT_CEILING: u32 = 1_024;
/// Hard ceiling on `breaker_window_ms` and `quarantine_ms`: one day.
pub const BREAKER_TIME_CEILING_MS: u64 = 86_400_000;
/// Hard ceiling on `max_tracked_senders`.
pub const TRACKED_SENDERS_CEILING: usize = 65_536;

/// All caps and windows. Every field has a default and a hard ceiling.
///
/// The defaults come from a synthetic simulation (see the design note) and
/// should be re-measured against real traffic.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PuzzleConfig {
    /// Most pieces one puzzle may declare. Default 64. Ceiling 1,024.
    pub max_pieces: u32,
    /// Largest accepted piece, in decoded bytes. The envelope size cap of the
    /// owning Trident applies as well (a piece travels as hex, twice this
    /// size). Default 4,096. Ceiling 1 MiB.
    pub max_piece_bytes: usize,
    /// How long a puzzle may sit without a new piece before it explodes.
    /// Default 3,000 ms. Range 1 ms to one hour.
    pub idle_ms: u64,
    /// The longest a puzzle may live from its first piece, however steadily
    /// pieces arrive. At least `idle_ms`. Default 30,000 ms. Ceiling one hour.
    pub max_lifetime_ms: u64,
    /// Open puzzles one sender may hold. More is answered "busy" with no
    /// breach. Default 16. Ceiling 1,024.
    pub max_open_per_sender: usize,
    /// Open puzzles in the whole gate. Default 4,096. Ceiling 1,048,576.
    pub max_open_total: usize,
    /// Bytes of pieces held in the whole gate. Must be at least
    /// `max_pieces * max_piece_bytes` so one puzzle always fits. Default
    /// 16 MiB. Ceiling 1 GiB.
    pub max_held_bytes: usize,
    /// How many earlier released wholes the inspector sees the end of.
    /// 0 turns look-back off. Default 3. Ceiling 16.
    pub lookback_wholes: usize,
    /// How many trailing bytes of each released whole are kept for
    /// look-back. A pattern longer than this cannot be seen across a join.
    /// Default 4,096. Ceiling 1 MiB.
    pub history_tail_bytes: usize,
    /// A whole with the same root from the same sender is refused for this
    /// long after it was released. 0 turns the memory off. Default 60,000 ms.
    pub replay_window_ms: u64,
    /// Capacity of each of the two bounded memories: released roots and
    /// recently closed puzzles. Default 65,536. Ceiling 4,194,304.
    pub memory_capacity: usize,
    /// Breaches a sender may take inside `breaker_window_ms` with no
    /// consequence. Default 3. Ceiling 1,024.
    pub breaker_free: u32,
    /// Breaches beyond the free allowance that quarantine the sender.
    /// Default 3. Range 1 to 1,024.
    pub breaker_threshold: u32,
    /// The window breaches are counted in. Default 30,000 ms. Ceiling one day.
    pub breaker_window_ms: u64,
    /// How long a quarantine lasts. It ends by itself. Default 60,000 ms.
    /// Ceiling one day.
    pub quarantine_ms: u64,
    /// Senders with gate-side state. Default 1,024. Ceiling 65,536.
    pub max_tracked_senders: usize,
}

impl Default for PuzzleConfig {
    fn default() -> Self {
        Self {
            max_pieces: 64,
            max_piece_bytes: 4_096,
            idle_ms: 3_000,
            max_lifetime_ms: 30_000,
            max_open_per_sender: 16,
            max_open_total: 4_096,
            max_held_bytes: 16 * 1024 * 1024,
            lookback_wholes: 3,
            history_tail_bytes: 4_096,
            replay_window_ms: 60_000,
            memory_capacity: 65_536,
            breaker_free: 3,
            breaker_threshold: 3,
            breaker_window_ms: 30_000,
            quarantine_ms: 60_000,
            max_tracked_senders: 1_024,
        }
    }
}

fn check(field: &'static str, value: u64, min: u64, max: u64) -> Result<(), ConfigError> {
    if (min..=max).contains(&value) {
        Ok(())
    } else {
        Err(ConfigError { field, value, min, max })
    }
}

fn widen(n: usize) -> u64 {
    u64::try_from(n).unwrap_or(u64::MAX)
}

impl PuzzleConfig {
    /// Refuses any value outside its documented range.
    pub fn validate(&self) -> Result<(), ConfigError> {
        check("max_pieces", u64::from(self.max_pieces), 1, u64::from(MAX_PIECES_CEILING))?;
        check("max_piece_bytes", widen(self.max_piece_bytes), 1, widen(MAX_PIECE_BYTES_CEILING))?;
        let whole = u64::from(self.max_pieces).saturating_mul(widen(self.max_piece_bytes));
        check("max_pieces * max_piece_bytes", whole, 1, widen(MAX_WHOLE_BYTES_CEILING))?;
        check("idle_ms", self.idle_ms, 1, LIFETIME_CEILING_MS)?;
        check("max_lifetime_ms", self.max_lifetime_ms, self.idle_ms, LIFETIME_CEILING_MS)?;
        check("max_open_per_sender", widen(self.max_open_per_sender), 1, widen(OPEN_PER_SENDER_CEILING))?;
        check("max_open_total", widen(self.max_open_total), 1, widen(OPEN_TOTAL_CEILING))?;
        check("max_held_bytes", widen(self.max_held_bytes), whole.max(1), widen(HELD_BYTES_CEILING))?;
        check("lookback_wholes", widen(self.lookback_wholes), 0, widen(LOOKBACK_CEILING))?;
        check("history_tail_bytes", widen(self.history_tail_bytes), 1, widen(TAIL_BYTES_CEILING))?;
        check("replay_window_ms", self.replay_window_ms, 0, LIFETIME_CEILING_MS)?;
        check("memory_capacity", widen(self.memory_capacity), 1, widen(MEMORY_CAPACITY_CEILING))?;
        check("breaker_free", u64::from(self.breaker_free), 0, u64::from(BREAKER_COUNT_CEILING))?;
        check("breaker_threshold", u64::from(self.breaker_threshold), 1, u64::from(BREAKER_COUNT_CEILING))?;
        check("breaker_window_ms", self.breaker_window_ms, 1, BREAKER_TIME_CEILING_MS)?;
        check("quarantine_ms", self.quarantine_ms, 1, BREAKER_TIME_CEILING_MS)?;
        check("max_tracked_senders", widen(self.max_tracked_senders), 1, widen(TRACKED_SENDERS_CEILING))?;
        Ok(())
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn defaults_validate() {
        PuzzleConfig::default().validate().unwrap();
    }

    #[test]
    fn every_ceiling_and_floor_is_enforced() {
        type Edit = (&'static str, fn(&mut PuzzleConfig));
        let bad: Vec<Edit> = vec![
            ("max_pieces", |c| c.max_pieces = 0),
            ("max_pieces", |c| c.max_pieces = MAX_PIECES_CEILING + 1),
            ("max_piece_bytes", |c| c.max_piece_bytes = 0),
            ("max_piece_bytes", |c| c.max_piece_bytes = MAX_PIECE_BYTES_CEILING + 1),
            ("max_pieces * max_piece_bytes", |c| {
                c.max_pieces = 1_024;
                c.max_piece_bytes = 32 * 1024;
            }),
            ("idle_ms", |c| c.idle_ms = 0),
            ("idle_ms", |c| c.idle_ms = LIFETIME_CEILING_MS + 1),
            ("max_lifetime_ms", |c| c.max_lifetime_ms = c.idle_ms - 1),
            ("max_open_per_sender", |c| c.max_open_per_sender = 0),
            ("max_open_total", |c| c.max_open_total = OPEN_TOTAL_CEILING + 1),
            ("max_held_bytes", |c| c.max_held_bytes = 1),
            ("lookback_wholes", |c| c.lookback_wholes = LOOKBACK_CEILING + 1),
            ("history_tail_bytes", |c| c.history_tail_bytes = 0),
            ("replay_window_ms", |c| c.replay_window_ms = LIFETIME_CEILING_MS + 1),
            ("memory_capacity", |c| c.memory_capacity = 0),
            ("breaker_free", |c| c.breaker_free = BREAKER_COUNT_CEILING + 1),
            ("breaker_threshold", |c| c.breaker_threshold = 0),
            ("breaker_window_ms", |c| c.breaker_window_ms = 0),
            ("quarantine_ms", |c| c.quarantine_ms = BREAKER_TIME_CEILING_MS + 1),
            ("max_tracked_senders", |c| c.max_tracked_senders = 0),
        ];
        for (field, edit) in bad {
            let mut c = PuzzleConfig::default();
            edit(&mut c);
            let err = c.validate().unwrap_err();
            assert_eq!(err.field, field, "edit for {field} tripped {err}");
        }
    }

    #[test]
    fn zero_lookback_and_zero_replay_window_are_allowed_switches() {
        let c = PuzzleConfig { lookback_wholes: 0, replay_window_ms: 0, breaker_free: 0, ..PuzzleConfig::default() };
        c.validate().unwrap();
    }
}
