//! Metrics and log events.
//!
//! Every metric name starts `tack_inlet_`. Labels come only from closed enums
//! ([`crate::GateOutcome`] and [`crate::Reason`]); nothing derived from input
//! content is ever a label, because a free-form label is a cardinality
//! attack (each new value creates a new time series in the metrics store).
//!
//! Log events never carry input bytes, and they do not carry the plain
//! SHA-256 of the input either. For short or low-entropy input (a PIN, a
//! yes or no answer) an unkeyed digest in a log is the input by another
//! name: anyone with log access hashes the candidates and compares. So a log
//! event carries the length and, when the body was read and the deployment
//! supplied a [`LogKey`], `input_hmac`: the full 64-character hex
//! HMAC-SHA256, under that key, of the input's SHA-256. Without a key the
//! field reads `unkeyed` and no digest is logged. The plain SHA-256 stays in
//! the [`Verdict`] for binding the verdict to its subject. This deviates from
//! kernel convention 4 as written ("log its full SHA-256"); the deviation is
//! deliberate and should be raised as a kernel-wide convention change.
//!
//! Numbers that could reveal where a violation sits (`first_offset` and
//! `count`) are written zero-padded to 8 digits, which covers every value up
//! to the 16 MiB ceiling, so the size of a log record does not depend on the
//! position of the first bad byte (kernel convention 6). Formatting an
//! 8-digit number still costs a few nanoseconds more for larger values; that
//! is far below the noise of a 64 KiB scan.
//!
//! # Alerts
//!
//! Prometheus rule expressions over these metrics:
//!
//! ```text
//! # TackInletTerminalBreach: any quarantine in the last 5 minutes.
//! increase(tack_inlet_quarantined_total[5m]) > 0
//! # TackInletRetryFlood: more than 10 refusals a second, sustained.
//! sum(rate(tack_inlet_verdicts_total{outcome="retry"}[5m])) > 10
//! # TackInletAbandonedRefusals: streams dropped with a refusal pending.
//! increase(tack_inlet_streams_abandoned_total{outcome!="pass"}[5m]) > 0
//! # TackInletChunkLimit: senders hitting the chunk cap.
//! increase(tack_inlet_verdicts_total{reason="chunk_limit"}[5m]) > 0
//! ```

use core::fmt;
use std::time::Duration;

use hmac::{Hmac, Mac};
use metrics::{counter, describe_counter, describe_histogram, histogram, Unit};
use sha2::Sha256;

use crate::config::ConfigError;
use crate::verdict::{GateOutcome, Sha256Hex, Verdict};

/// Counter, labels `outcome` and `reason`: one per verdict issued. `reason` is
/// the first violation's reason, or `none` on a pass.
pub const VERDICTS_TOTAL: &str = "tack_inlet_verdicts_total";
/// Counter, no labels: total violations found (a verdict's `count`).
pub const VIOLATIONS_TOTAL: &str = "tack_inlet_violations_total";
/// Counter, label `reason`: once per verdict per distinct reason present.
pub const REASON_SEEN_TOTAL: &str = "tack_inlet_reason_seen_total";
/// Counter, no labels: verdicts whose resolution is quarantine.
pub const QUARANTINED_TOTAL: &str = "tack_inlet_quarantined_total";
/// Histogram, no labels: input length in bytes, as [`Verdict::len`] reports
/// it. An oversize refusal records the cap plus one, never the declared
/// length, so one request declaring `u64::MAX` cannot ruin the histogram's
/// sum.
pub const INPUT_BYTES: &str = "tack_inlet_input_bytes";
/// Histogram, label `outcome`: wall time to reach a verdict, in seconds.
pub const SCAN_DURATION_SECONDS: &str = "tack_inlet_scan_duration_seconds";
/// Counter, label `outcome`: streams dropped without
/// [`crate::Scanner::finish`], by the outcome of what had been fed so far. A
/// stream abandoned with a refusal pending also records its verdict in every
/// other metric, so a Trojan Source probe whose connection closes still
/// reaches [`QUARANTINED_TOTAL`]. A stream abandoned while clean is counted
/// here only, because nothing was admitted.
pub const STREAMS_ABANDONED_TOTAL: &str = "tack_inlet_streams_abandoned_total";

/// Span names.
pub mod spans {
    /// One-shot check of an in-memory input.
    pub const WINNOW: &str = "tack.inlet.winnow";
    /// Check of a declared length before the body is read.
    pub const PRECHECK: &str = "tack.inlet.precheck";
    /// A streaming scan, from `Inlet::scanner` to `Scanner::finish` (or to
    /// the drop of an abandoned scanner). The span is entered only when the
    /// verdict is reached, not on every chunk, and records the number of
    /// chunks fed as the field `chunks`.
    pub const STREAM: &str = "tack.inlet.stream";
}

/// Register descriptions and units with the installed recorder. Optional;
/// call once at start-up if the exporter shows descriptions.
pub fn describe_metrics() {
    describe_counter!(
        VERDICTS_TOTAL,
        "Inlet verdicts issued, by outcome and first reason"
    );
    describe_counter!(VIOLATIONS_TOTAL, "Violations found by the inlet");
    describe_counter!(REASON_SEEN_TOTAL, "Verdicts in which each reason appeared");
    describe_counter!(QUARANTINED_TOTAL, "Inlet verdicts resolved as quarantine");
    describe_histogram!(INPUT_BYTES, Unit::Bytes, "Input length seen by the inlet");
    describe_histogram!(
        SCAN_DURATION_SECONDS,
        Unit::Seconds,
        "Time for the inlet to reach a verdict"
    );
    describe_counter!(
        STREAMS_ABANDONED_TOTAL,
        "Inlet streams dropped without finish, by outcome so far"
    );
}

/// A deployment-supplied key for the digest written to logs.
///
/// There is no default and no constructor without key bytes. A key must be at
/// least [`LogKey::MIN_LEN`] bytes and not all one value. Load it from the
/// deployment's secret store; never hard-code it. Without a key the inlet
/// logs no digest at all, so a missing key fails closed on privacy.
#[derive(Clone)]
pub struct LogKey {
    mac: Hmac<Sha256>,
}

impl LogKey {
    /// Minimum key length in bytes: 32, the SHA-256 output size.
    pub const MIN_LEN: usize = 32;

    /// Domain separation for the log tag, so the tag cannot be confused with
    /// any other HMAC made under the same key.
    const DOMAIN: &'static [u8] = b"tack.inlet.log.v1\0";

    /// Build a key from secret bytes.
    ///
    /// # Errors
    ///
    /// [`ConfigError::LogKeyTooShort`] below [`LogKey::MIN_LEN`] bytes, and
    /// [`ConfigError::LogKeyPlaceholder`] when every byte is the same.
    pub fn new(key: &[u8]) -> Result<Self, ConfigError> {
        let too_short = ConfigError::LogKeyTooShort {
            len: key.len(),
            min: Self::MIN_LEN,
        };
        let Some(&first) = key.first() else {
            return Err(too_short);
        };
        if key.len() < Self::MIN_LEN {
            return Err(too_short);
        }
        if key.iter().all(|&b| b == first) {
            return Err(ConfigError::LogKeyPlaceholder);
        }
        let mac = Hmac::<Sha256>::new_from_slice(key).map_err(|_| too_short)?;
        Ok(Self { mac })
    }

    /// The tag logged as `input_hmac` for an input whose SHA-256 is
    /// `sha256`: HMAC-SHA256 under this key of a fixed domain string followed
    /// by the digest, full length. An operator holding the key computes this
    /// from a known input's digest (for example [`Verdict::sha256`]) to find
    /// its log lines.
    #[must_use]
    pub fn log_tag(&self, sha256: &[u8; 32]) -> [u8; 32] {
        let mut m = self.mac.clone();
        m.update(Self::DOMAIN);
        m.update(sha256);
        m.finalize().into_bytes().into()
    }
}

impl fmt::Debug for LogKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("LogKey(<redacted>)")
    }
}

/// Writes a number zero-padded to 8 digits, so its length does not depend
/// on its value for anything up to the 16 MiB ceiling.
struct Pad8(usize);

impl fmt::Display for Pad8 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:08}", self.0)
    }
}

/// The logged digest: the keyed tag, or `unkeyed` when there is no key.
struct LogTag(Option<[u8; 32]>);

impl fmt::Display for LogTag {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.0 {
            Some(t) => Sha256Hex(t).fmt(f),
            None => f.write_str("unkeyed"),
        }
    }
}

/// Record metrics and one log event for a verdict. Called exactly once per
/// verdict, inside the operation's span.
pub(crate) fn emit(v: &Verdict, elapsed: Duration, key: Option<&LogKey>) {
    emit_inner(v, elapsed, key, false);
}

/// Record a stream dropped without `finish`. `v` is the verdict on what had
/// been fed so far. A refusal is recorded in full (so alerts fire); a clean
/// partial stream is only counted, because nothing was admitted.
pub(crate) fn emit_abandoned(v: &Verdict, elapsed: Duration, key: Option<&LogKey>) {
    counter!(STREAMS_ABANDONED_TOTAL, "outcome" => v.outcome().as_str()).increment(1);
    if v.is_pass() {
        tracing::debug!(len = v.len(), "inlet stream abandoned while clean");
    } else {
        emit_inner(v, elapsed, key, true);
    }
}

fn emit_inner(v: &Verdict, elapsed: Duration, key: Option<&LogKey>, abandoned: bool) {
    let outcome = v.outcome().as_str();
    let reason = v.reason().map_or("none", |r| r.as_str());

    counter!(VERDICTS_TOTAL, "outcome" => outcome, "reason" => reason).increment(1);
    counter!(VIOLATIONS_TOTAL).increment(u64::try_from(v.count()).unwrap_or(u64::MAX));
    for r in v.reasons().iter() {
        counter!(REASON_SEEN_TOTAL, "reason" => r.as_str()).increment(1);
    }
    if v.outcome() == GateOutcome::TerminalBreach {
        counter!(QUARANTINED_TOTAL).increment(1);
    }
    histogram!(INPUT_BYTES).record(v.len() as f64);
    histogram!(SCAN_DURATION_SECONDS, "outcome" => outcome).record(elapsed.as_secs_f64());

    let resolution = v.resolution().map_or("none", |r| r.as_str());
    let first_offset = Pad8(v.first_offset().unwrap_or(0));
    let count = Pad8(v.count());
    match (v.outcome(), v.sha256()) {
        (GateOutcome::Pass, Some(d)) => tracing::debug!(
            outcome,
            len = v.len(),
            input_hmac = %LogTag(key.map(|k| k.log_tag(d))),
            "inlet admitted input"
        ),
        (_, Some(d)) => tracing::warn!(
            outcome,
            reason,
            resolution,
            first_offset = %first_offset,
            count = %count,
            len = v.len(),
            scanned = v.scanned(),
            abandoned,
            input_hmac = %LogTag(key.map(|k| k.log_tag(d))),
            "inlet refused input"
        ),
        (_, None) => tracing::warn!(
            outcome,
            reason,
            resolution,
            len = v.len(),
            scanned = v.scanned(),
            abandoned,
            body_read = false,
            "inlet refused input on length or chunk count"
        ),
    }
}
