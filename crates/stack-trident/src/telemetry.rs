//! Metric and span names. Every label value comes from a closed enum in
//! [`crate::vocab`] or from the fixed strings below; nothing an envelope
//! contains ever becomes a label.

/// Counter. One per verification. Labels: `outcome` (pass, retry,
/// terminal_breach), `resolution` (accept, reject, quarantine, halt).
/// `outcome` is the Trident's own result ([`crate::Verdict::check_outcome`]),
/// so an accepted envelope is `pass` here even when the sender's gate claim
/// makes [`crate::Verdict::outcome`] RETRY or TERMINAL_BREACH.
pub const VERIFICATIONS_TOTAL: &str = "stack_trident_verifications_total";
/// Counter. One per reported reason. Labels: `check` (admission, custody,
/// authenticity, binding, freshness, capacity), `reason` (a
/// [`crate::ReasonCode`] spelling).
pub const CHECK_FAILURES_TOTAL: &str = "stack_trident_check_failures_total";
/// Histogram, seconds. Wall time of one verification. Label: `outcome`.
pub const VERIFY_DURATION_SECONDS: &str = "stack_trident_verify_duration_seconds";
/// Counter. Bytes fed to the prong 1 HMAC plus bytes fed to the prong 2
/// SHA-256. Does not count the log digest of the raw input. No labels.
pub const HASHED_BYTES_TOTAL: &str = "stack_trident_hashed_bytes_total";
/// Counter. Senders quarantined by the breaker. No labels.
pub const QUARANTINE_TRIPS_TOTAL: &str = "stack_trident_quarantine_trips_total";
/// Counter. Quarantines lifted by an operator. No labels.
pub const QUARANTINE_RELEASES_TOTAL: &str = "stack_trident_quarantine_releases_total";
/// Gauge. Senders currently quarantined. No labels.
pub const QUARANTINED_SENDERS: &str = "stack_trident_quarantined_senders";
/// Gauge. Entries in the replay cache. No labels.
pub const REPLAY_CACHE_ENTRIES: &str = "stack_trident_replay_cache_entries";
/// Counter. Transitions into the halted state. Label: `cause` (poisoned,
/// operator, store_failure).
pub const HALTS_TOTAL: &str = "stack_trident_halts_total";
/// Counter. Operator resets. No labels.
pub const OPERATOR_RESETS_TOTAL: &str = "stack_trident_operator_resets_total";
/// Counter. Replay-cache entries evicted because the cache was full and a
/// sender under its fair share needed room. A sustained rate means one or
/// more key holders are sending at or above the cache's design rate; alert
/// on it, for example
/// `rate(stack_trident_replay_evictions_total[5m]) > 0` together with
/// `rate(stack_trident_check_failures_total{reason="replay_cache_full"}[5m]) > 0`.
/// No labels.
pub const REPLAY_EVICTIONS_TOTAL: &str = "stack_trident_replay_evictions_total";
/// Counter. Counted breaches that could not be recorded because the sender
/// table was full. No labels.
pub const BREAKER_UNTRACKED_TOTAL: &str = "stack_trident_breaker_untracked_total";
/// Counter. Writes to the durable replay store that failed. A failed
/// acceptance commit refuses the envelope (`state_unavailable`); a failed
/// quarantine or release mark is logged and leaves the in-memory state in
/// force. Any non-zero rate means the verifier is refusing valid work or
/// will lose quarantines on restart; alert on it. No labels.
pub const STORE_FAILURES_TOTAL: &str = "stack_trident_store_failures_total";
/// Counter. Acceptance commits the replay store refused as already
/// consumed (check-and-commit conflict: nonce, sequence or epoch floor).
/// Each one refused an envelope with `replay`, `sequence_not_increasing`
/// or `issued_before_epoch`. On a store shared by several verifiers a
/// non-zero rate is a replay caught by the store. No labels.
pub const STORE_CONFLICTS_TOTAL: &str = "stack_trident_store_conflicts_total";

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
    /// Under the Production profile, a quarantine mark the durable store
    /// failed to persist.
    StoreFailure,
}

impl HaltCause {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::Poisoned => "poisoned",
            Self::Operator => "operator",
            Self::StoreFailure => "store_failure",
        }
    }
}

/// Converts a count to a gauge value.
pub(crate) fn gauge_value(n: usize) -> f64 {
    // Counts here are bounded by config ceilings far below 2^53, so the
    // conversion is exact.
    u32::try_from(n).map(f64::from).unwrap_or(f64::MAX)
}
