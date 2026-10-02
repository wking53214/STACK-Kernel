//! Caps for the transmission. Every wait and every counter that callers can
//! grow has a ceiling here, with a documented default.

use std::time::Duration;

/// The largest wait any cap may allow. A cap above this is refused by
/// [`TransmissionConfig::validate`], so deadline arithmetic
/// (`Instant + Duration`) can never overflow.
pub const MAX_CONFIGURABLE_WAIT: Duration = Duration::from_secs(24 * 60 * 60);

/// After a shift is rolled back with `drain_timeout`, the next shift waits
/// with the clutch up for this many times as long as the rolled-back shift
/// held it (capped at `max_shift_timeout` held), before it presses the
/// clutch again. So a controller that resubmits at once after every RETRY
/// can keep admission paused for at most `1 / (1 + 2)` of the time, not
/// almost all of it. The wait happens inside `shift()` before the drain
/// timeout starts, so one `shift()` call can block for up to
/// `(1 + SHIFT_COOLDOWN_FACTOR) * max_shift_timeout`. It is a constant, not a
/// field, so that adding it did not break code that builds a
/// [`TransmissionConfig`] with all four fields named.
pub const SHIFT_COOLDOWN_FACTOR: u32 = 2;

/// Caps for one [`crate::Transmission`].
///
/// All four fields must be nonzero; the waits must also be at most
/// [`MAX_CONFIGURABLE_WAIT`]. Build one with `Default` and change the fields
/// you need, then pass it to [`crate::Transmission::new`], which validates it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TransmissionConfig {
    /// Most drive guards that may be out at once. An `engage()` beyond this
    /// gets RETRY with reason `in_flight_capacity` instead of waiting.
    /// Default 4096.
    pub max_in_flight: usize,
    /// Most `engage()` callers that may be parked waiting for the clutch at
    /// once. The next one gets RETRY with reason `wait_queue_full` at once,
    /// so a shift cannot turn into an unbounded pile of blocked threads.
    /// Default 1024.
    pub max_waiting_engagers: usize,
    /// Longest timeout an `engage()` caller may ask for. A larger request is
    /// RETRY with reason `engage_timeout_over_budget`. Default 5 s.
    pub max_engage_wait: Duration,
    /// Longest drain timeout a `shift()` caller may ask for. A larger request
    /// is RETRY with reason `shift_timeout_over_budget`. This also bounds how
    /// long the clutch can stay pressed, and so how long admission can be
    /// paused by one shift. After a rollback the next shift first waits out
    /// a cooldown of up to [`SHIFT_COOLDOWN_FACTOR`] times this. Default
    /// 30 s.
    pub max_shift_timeout: Duration,
}

impl Default for TransmissionConfig {
    fn default() -> Self {
        Self {
            max_in_flight: 4096,
            max_waiting_engagers: 1024,
            max_engage_wait: Duration::from_secs(5),
            max_shift_timeout: Duration::from_secs(30),
        }
    }
}

/// Why a [`TransmissionConfig`] was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ConfigError {
    /// A count cap was zero, which would refuse every request.
    #[error("config field `{0}` must be greater than zero")]
    Zero(&'static str),
    /// A wait cap was zero or above [`MAX_CONFIGURABLE_WAIT`].
    #[error("config field `{0}` must be between 1 ns and 24 h")]
    WaitOutOfRange(&'static str),
}

impl TransmissionConfig {
    /// Checks every cap. Fails closed: a zero or out-of-range value is an
    /// error, never silently replaced by a default.
    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.max_in_flight == 0 {
            return Err(ConfigError::Zero("max_in_flight"));
        }
        if self.max_waiting_engagers == 0 {
            return Err(ConfigError::Zero("max_waiting_engagers"));
        }
        for (name, wait) in [
            ("max_engage_wait", self.max_engage_wait),
            ("max_shift_timeout", self.max_shift_timeout),
        ] {
            if wait.is_zero() || wait > MAX_CONFIGURABLE_WAIT {
                return Err(ConfigError::WaitOutOfRange(name));
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_is_valid() {
        assert_eq!(TransmissionConfig::default().validate(), Ok(()));
    }

    #[test]
    fn zero_and_oversized_caps_are_refused() {
        let base = TransmissionConfig::default();
        let cases = [
            (
                TransmissionConfig { max_in_flight: 0, ..base },
                ConfigError::Zero("max_in_flight"),
            ),
            (
                TransmissionConfig { max_waiting_engagers: 0, ..base },
                ConfigError::Zero("max_waiting_engagers"),
            ),
            (
                TransmissionConfig { max_engage_wait: Duration::ZERO, ..base },
                ConfigError::WaitOutOfRange("max_engage_wait"),
            ),
            (
                TransmissionConfig {
                    max_shift_timeout: MAX_CONFIGURABLE_WAIT + Duration::from_nanos(1),
                    ..base
                },
                ConfigError::WaitOutOfRange("max_shift_timeout"),
            ),
        ];
        for (cfg, want) in cases {
            assert_eq!(cfg.validate(), Err(want));
        }
    }
}
