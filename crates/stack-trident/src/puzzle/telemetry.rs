//! Metric and span names for the puzzle gate. Every label value comes from a
//! closed set below; nothing a sender, a puzzle, an envelope or an inspector
//! returns ever becomes a label, so an attacker cannot grow the number of
//! metric series. An inspector's own reason text is logged, never labelled.

/// Counter. One per message offered to the gate. Label: `outcome` (see
/// [`OUTCOMES`]).
pub const MESSAGES_TOTAL: &str = "stack_trident_puzzle_messages_total";
/// Counter. One per message the gate refused. Label: `reason` (see
/// [`REFUSAL_REASONS`]).
pub const REFUSALS_TOTAL: &str = "stack_trident_puzzle_refusals_total";
/// Counter. One per puzzle that stopped being open. Label: `reason` (see
/// [`CLOSE_REASONS`]).
pub const CLOSED_TOTAL: &str = "stack_trident_puzzle_closed_total";
/// Counter. Breaches counted against senders. No labels.
pub const BREACHES_TOTAL: &str = "stack_trident_puzzle_breaches_total";
/// Counter. Senders quarantined by the gate's breaker. No labels.
pub const QUARANTINE_TRIPS_TOTAL: &str = "stack_trident_puzzle_quarantine_trips_total";
/// Gauge. Puzzles currently open. No labels.
pub const OPEN_PUZZLES: &str = "stack_trident_puzzle_open_puzzles";
/// Gauge. Bytes currently held in open puzzles. No labels.
pub const HELD_BYTES: &str = "stack_trident_puzzle_held_bytes";
/// Histogram, seconds. Wall time of one inspection, which runs while the gate
/// holds its lock. Label: `finding` (see [`FINDINGS`]).
pub const INSPECT_DURATION_SECONDS: &str = "stack_trident_puzzle_inspect_duration_seconds";

/// Span around one message offered to the gate.
pub const SPAN_OFFER: &str = "stack.trident.puzzle.offer";
/// Span around an operator-driven sweep.
pub const SPAN_SWEEP: &str = "stack.trident.puzzle.sweep";

/// The `outcome` label values.
pub const OUTCOMES: [&str; 5] = ["held", "released", "aborted", "refused", "rejected"];
/// The `reason` label values on [`REFUSALS_TOTAL`].
pub const REFUSAL_REASONS: [&str; 14] = [
    "halted",
    "sender_gate_not_pass",
    "quarantined",
    "busy_too_many_open",
    "busy_holding_area_full",
    "busy_too_many_senders",
    "malformed",
    "unknown_puzzle",
    "already_closed",
    "conflict",
    "replayed_whole",
    "root_mismatch",
    "content_blocked",
    "content_suspicious",
];
/// The `reason` label values on [`CLOSED_TOTAL`].
pub const CLOSE_REASONS: [&str; 9] = [
    "released",
    "aborted",
    "exploded",
    "evicted",
    "conflict",
    "root_mismatch",
    "hostile",
    "suspicious",
    "quarantined",
];
/// The `finding` label values on [`INSPECT_DURATION_SECONDS`].
pub const FINDINGS: [&str; 3] = ["pass", "suspicious", "hostile"];

/// Converts a count to a gauge value.
pub(crate) fn gauge_value(n: usize) -> f64 {
    // Counts here are bounded by config ceilings far below 2^53, so the
    // conversion is exact.
    u32::try_from(n).map(f64::from).unwrap_or(f64::MAX)
}
