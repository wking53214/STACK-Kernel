//! Metric and span names. Every label value comes from a closed enum in
//! [`crate::vocab`] or from the fixed strings below; nothing an envelope
//! contains ever becomes a label.

/// Counter. One per verification. Labels: `outcome` (pass, retry,
/// terminal_breach), `resolution` (accept, reject, quarantine, halt).
/// `outcome` is the Trident's own result ([`crate::Verdict::check_outcome`]),
/// so an accepted envelope is `pass` here even when the sender's gate claim
/// makes [`crate::Verdict::outcome`] RETRY or TERMINAL_BREACH.
pub const VERIFICATIONS_TOTAL: &str = "tack_trident_verifications_total";
/// Counter. One per reported reason. Labels: `check` (admission, custody,
/// authenticity, binding, freshness, capacity), `reason` (a
/// [`crate::ReasonCode`] spelling).
pub const CHECK_FAILURES_TOTAL: &str = "tack_trident_check_failures_total";
/// Histogram, seconds. Wall time of one verification. Label: `outcome`.
pub const VERIFY_DURATION_SECONDS: &str = "tack_trident_verify_duration_seconds";
/// Counter. Bytes fed to the prong 1 HMAC plus bytes fed to the prong 2
/// SHA-256. Does not count the log digest of the raw input. No labels.
pub const HASHED_BYTES_TOTAL: &str = "tack_trident_hashed_bytes_total";
/// Counter. Senders quarantined by the breaker. No labels.
pub const QUARANTINE_TRIPS_TOTAL: &str = "tack_trident_quarantine_trips_total";
/// Counter. Quarantines lifted by an operator. No labels.
pub const QUARANTINE_RELEASES_TOTAL: &str = "tack_trident_quarantine_releases_total";
/// Gauge. Senders currently quarantined. No labels.
pub const QUARANTINED_SENDERS: &str = "tack_trident_quarantined_senders";
/// Gauge. Entries in the replay cache. No labels.
pub const REPLAY_CACHE_ENTRIES: &str = "tack_trident_replay_cache_entries";
/// Counter. Transitions into the halted state. Label: `cause` (poisoned,
/// operator).
pub const HALTS_TOTAL: &str = "tack_trident_halts_total";
/// Counter. Operator resets. No labels.
pub const OPERATOR_RESETS_TOTAL: &str = "tack_trident_operator_resets_total";
/// Counter. Replay-cache entries evicted because the cache was full and a
/// sender under its fair share needed room. A sustained rate means one or
/// more key holders are sending at or above the cache's design rate; alert
/// on it, for example
/// `rate(tack_trident_replay_evictions_total[5m]) > 0` together with
/// `rate(tack_trident_check_failures_total{reason="replay_cache_full"}[5m]) > 0`.
/// No labels.
pub const REPLAY_EVICTIONS_TOTAL: &str = "tack_trident_replay_evictions_total";
/// Counter. Counted breaches that could not be recorded because the sender
/// table was full. No labels.
pub const BREAKER_UNTRACKED_TOTAL: &str = "tack_trident_breaker_untracked_total";

/// Span around one verification.
pub const SPAN_VERIFY: &str = "stack.trident.verify";
/// Span around sealing on the producer side.
pub const SPAN_SEAL: &str = "stack.trident.seal";
/// Span around an operator releasing a quarantined sender.
pub const SPAN_RELEASE: &str = "stack.trident.release";
/// Span around an operator reset.
pub const SPAN_RESET: &str = "stack.trident.reset";
/// Span around an operator halt.
pub const SPAN_HALT: &str = "stack.trident.halt";
/// Span around replacing the key ring.
pub const SPAN_REPLACE_KEYRING: &str = "stack.trident.replace_keyring";

/// Why the Trident halted. Closed; used as the `cause` label.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum HaltCause {
    /// A lock was poisoned by a panic in another thread.
    Poisoned,
    /// An operator called `operator_halt`.
    Operator,
}

impl HaltCause {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::Poisoned => "poisoned",
            Self::Operator => "operator",
        }
    }
}

/// Converts a count to a gauge value.
pub(crate) fn gauge_value(n: usize) -> f64 {
    // Counts here are bounded by config ceilings far below 2^53, so the
    // conversion is exact.
    u32::try_from(n).map(f64::from).unwrap_or(f64::MAX)
}
