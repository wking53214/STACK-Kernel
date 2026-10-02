//! Closed vocabularies: gate position and outcome (mirroring CNS), state
//! resolutions, the checks the Trident runs, and every reason code.
//!
//! Every string here is `'static` and comes from a fixed list. That is what
//! makes them safe as metric labels: an attacker cannot mint a new label
//! value, so they cannot grow the metric series count.

use std::fmt;

/// Which end of a decision the sender's gate ran at. Mirrors
/// `cns.gate.GatePosition` in `/home/user/CNS/cns/gate.py`.
///
/// `Alpha` runs before execution (a precondition). `Omega` runs on the
/// produced result (an outcome check).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum GatePosition {
    /// Before execution.
    Alpha,
    /// On the result.
    Omega,
}

impl GatePosition {
    /// The wire spelling, identical to the CNS enum value.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Alpha => "alpha",
            Self::Omega => "omega",
        }
    }

    /// Parses the exact wire spelling. Anything else is `None`: no case
    /// folding, no trimming, no aliases.
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "alpha" => Some(Self::Alpha),
            "omega" => Some(Self::Omega),
            _ => None,
        }
    }
}

/// A verdict in increasing order of finality. Mirrors `cns.gate.GateOutcome`.
///
/// Used twice in this crate, for two different things:
/// 1. the `gate_outcome` field of an envelope, which is the verdict the
///    *sender's* gate reached upstream (a claim the Trident authenticates
///    but does not re-judge), and
/// 2. the outcome of the Trident's own verification of the envelope.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum GateOutcome {
    /// Nothing objected.
    Pass,
    /// Repairable: the caller may resubmit with a correction.
    Retry,
    /// Abort: no correction repairs it.
    TerminalBreach,
}

impl GateOutcome {
    /// The wire spelling, identical to the CNS enum value.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Pass => "pass",
            Self::Retry => "retry",
            Self::TerminalBreach => "terminal_breach",
        }
    }

    /// Parses the exact wire spelling.
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "pass" => Some(Self::Pass),
            "retry" => Some(Self::Retry),
            "terminal_breach" => Some(Self::TerminalBreach),
            _ => None,
        }
    }

    /// CNS `resolve` precedence: any terminal breach wins, then any retry,
    /// and pass only when nothing objected.
    pub fn resolve<I: IntoIterator<Item = GateOutcome>>(outcomes: I) -> GateOutcome {
        outcomes.into_iter().max().unwrap_or(GateOutcome::Pass)
    }
}

/// What happened to receiver state when an envelope was refused.
///
/// The kernel vocabulary has four resolutions: reject, quarantine,
/// rollback and halt. This crate never produces rollback, because it never
/// has partial state to undo: the only state it changes on a verdict (the
/// sender's sequence number and the replay cache) is changed in one
/// critical section, and only after every check has passed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Resolution {
    /// Nothing changed. The envelope is dropped.
    Reject,
    /// The sender is isolated: every envelope it sends is refused until an
    /// operator calls [`crate::Trident::release`].
    Quarantine,
    /// The Trident stops accepting work until an operator calls
    /// [`crate::Trident::operator_reset`].
    Halt,
}

impl Resolution {
    /// Metric label spelling.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Reject => "reject",
            Self::Quarantine => "quarantine",
            Self::Halt => "halt",
        }
    }
}

/// The group a reason code belongs to. Three of these are the prongs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Check {
    /// Cheap public checks run before any cryptographic work: size, depth,
    /// node count, strict JSON, envelope shape. Failing here returns early.
    Admission,
    /// Receiver-wide or sender-wide isolation: halt and quarantine. Also
    /// returns early, because the state it reads is not secret.
    Custody,
    /// Prong 1: HMAC-SHA256 under the sender's key.
    Authenticity,
    /// Prong 2: the payload digest and the closed vocabularies.
    Binding,
    /// Prong 3: clock skew, replay cache, sequence order.
    Freshness,
    /// The receiver ran out of a bounded resource. Not the sender's fault.
    Capacity,
}

impl Check {
    /// Metric label spelling.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Admission => "admission",
            Self::Custody => "custody",
            Self::Authenticity => "authenticity",
            Self::Binding => "binding",
            Self::Freshness => "freshness",
            Self::Capacity => "capacity",
        }
    }

    /// The prong number (1, 2 or 3) if this check is a prong.
    pub const fn prong(self) -> Option<u8> {
        match self {
            Self::Authenticity => Some(1),
            Self::Binding => Some(2),
            Self::Freshness => Some(3),
            Self::Admission | Self::Custody | Self::Capacity => None,
        }
    }
}

/// Every reason the Trident can refuse an envelope. Each maps to exactly one
/// [`Check`] and one [`GateOutcome`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum ReasonCode {
    // Admission (early return, before any hashing of the envelope).
    /// Raw input or canonical encoding is over `max_envelope_bytes`.
    EnvelopeTooLarge,
    /// Nesting is deeper than `max_depth`.
    TooDeep,
    /// More JSON values than `max_nodes`.
    TooManyNodes,
    /// Not well-formed UTF-8 JSON under the strict grammar.
    MalformedJson,
    /// A number with a fraction or exponent.
    NonIntegerNumber,
    /// `NaN`, `Infinity` or `-Infinity` (Python's `json` emits these).
    NonFiniteNumber,
    /// An integer outside plus or minus 2^53 - 1.
    IntegerOutOfRange,
    /// An object with the same key twice.
    DuplicateKey,
    /// Not an object with exactly the ten envelope fields of the right types.
    MalformedEnvelope,

    // Custody (early return).
    /// The Trident is halted.
    Halted,
    /// The claimed sender is quarantined.
    Quarantined,

    // Prong 1: authenticity.
    /// `sender` is not 64 lowercase hex characters.
    MalformedSender,
    /// `sender` is not in the caller's key ring.
    UnknownSender,
    /// `mac` is not 64 lowercase hex characters.
    MalformedMac,
    /// The MAC does not verify under the sender's key.
    MacMismatch,

    // Prong 2: binding.
    /// `version` is not a version this build understands.
    UnsupportedVersion,
    /// `gate_position` is not `alpha` or `omega`.
    UnknownGatePosition,
    /// `gate_outcome` is not `pass`, `retry` or `terminal_breach`.
    UnknownGateOutcome,
    /// `subject_digest` is not 64 lowercase hex characters.
    MalformedDigest,
    /// The recomputed payload digest differs from `subject_digest`. This is
    /// the TRANSPLANTED check from sentinel_os.
    SubjectDigestMismatch,

    // Prong 3: freshness.
    /// `issued_at_unix_ms` is older than the past skew allows.
    Stale,
    /// `issued_at_unix_ms` is further ahead than the future skew allows.
    FromFuture,
    /// `issued_at_unix_ms` is before the epoch floor set at start-up or at
    /// the last operator reset.
    IssuedBeforeEpoch,
    /// `nonce` is not 32 lowercase hex characters.
    MalformedNonce,
    /// This (sender, nonce) pair was already accepted.
    Replay,
    /// `sequence` is not greater than the last accepted sequence.
    SequenceNotIncreasing,

    // Capacity.
    /// The replay cache is full of unexpired entries.
    ReplayCacheFull,
    /// The per-sender state table is full.
    SenderTableFull,
}

impl ReasonCode {
    /// Every reason code, in declaration order.
    pub const ALL: [ReasonCode; 28] = [
        Self::EnvelopeTooLarge,
        Self::TooDeep,
        Self::TooManyNodes,
        Self::MalformedJson,
        Self::NonIntegerNumber,
        Self::NonFiniteNumber,
        Self::IntegerOutOfRange,
        Self::DuplicateKey,
        Self::MalformedEnvelope,
        Self::Halted,
        Self::Quarantined,
        Self::MalformedSender,
        Self::UnknownSender,
        Self::MalformedMac,
        Self::MacMismatch,
        Self::UnsupportedVersion,
        Self::UnknownGatePosition,
        Self::UnknownGateOutcome,
        Self::MalformedDigest,
        Self::SubjectDigestMismatch,
        Self::Stale,
        Self::FromFuture,
        Self::IssuedBeforeEpoch,
        Self::MalformedNonce,
        Self::Replay,
        Self::SequenceNotIncreasing,
        Self::ReplayCacheFull,
        Self::SenderTableFull,
    ];

    /// Metric label and log spelling.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::EnvelopeTooLarge => "envelope_too_large",
            Self::TooDeep => "too_deep",
            Self::TooManyNodes => "too_many_nodes",
            Self::MalformedJson => "malformed_json",
            Self::NonIntegerNumber => "non_integer_number",
            Self::NonFiniteNumber => "non_finite_number",
            Self::IntegerOutOfRange => "integer_out_of_range",
            Self::DuplicateKey => "duplicate_key",
            Self::MalformedEnvelope => "malformed_envelope",
            Self::Halted => "halted",
            Self::Quarantined => "quarantined",
            Self::MalformedSender => "malformed_sender",
            Self::UnknownSender => "unknown_sender",
            Self::MalformedMac => "malformed_mac",
            Self::MacMismatch => "mac_mismatch",
            Self::UnsupportedVersion => "unsupported_version",
            Self::UnknownGatePosition => "unknown_gate_position",
            Self::UnknownGateOutcome => "unknown_gate_outcome",
            Self::MalformedDigest => "malformed_digest",
            Self::SubjectDigestMismatch => "subject_digest_mismatch",
            Self::Stale => "stale",
            Self::FromFuture => "from_future",
            Self::IssuedBeforeEpoch => "issued_before_epoch",
            Self::MalformedNonce => "malformed_nonce",
            Self::Replay => "replay",
            Self::SequenceNotIncreasing => "sequence_not_increasing",
            Self::ReplayCacheFull => "replay_cache_full",
            Self::SenderTableFull => "sender_table_full",
        }
    }

    /// Which check this reason belongs to.
    pub const fn check(self) -> Check {
        match self {
            Self::EnvelopeTooLarge
            | Self::TooDeep
            | Self::TooManyNodes
            | Self::MalformedJson
            | Self::NonIntegerNumber
            | Self::NonFiniteNumber
            | Self::IntegerOutOfRange
            | Self::DuplicateKey
            | Self::MalformedEnvelope => Check::Admission,
            Self::Halted | Self::Quarantined => Check::Custody,
            Self::MalformedSender | Self::UnknownSender | Self::MalformedMac | Self::MacMismatch => {
                Check::Authenticity
            }
            Self::UnsupportedVersion
            | Self::UnknownGatePosition
            | Self::UnknownGateOutcome
            | Self::MalformedDigest
            | Self::SubjectDigestMismatch => Check::Binding,
            Self::Stale
            | Self::FromFuture
            | Self::IssuedBeforeEpoch
            | Self::MalformedNonce
            | Self::Replay
            | Self::SequenceNotIncreasing => Check::Freshness,
            Self::ReplayCacheFull | Self::SenderTableFull => Check::Capacity,
        }
    }

    /// The CNS outcome this reason maps to.
    ///
    /// The rule: TERMINAL_BREACH when the envelope proves an integrity
    /// failure or a hostile act that no resubmission from an honest sender
    /// would ever need (a bad MAC, an unknown sender, a transplanted
    /// digest, a replay, a duplicate key, a quarantined sender). RETRY when
    /// an honest sender could plausibly produce it and fix it (an encoding
    /// bug, clock drift, out-of-order sends, an over-size payload, a
    /// receiver that is busy or halted).
    pub const fn outcome(self) -> GateOutcome {
        match self {
            Self::DuplicateKey
            | Self::Quarantined
            | Self::UnknownSender
            | Self::MacMismatch
            | Self::SubjectDigestMismatch
            | Self::Replay => GateOutcome::TerminalBreach,
            Self::EnvelopeTooLarge
            | Self::TooDeep
            | Self::TooManyNodes
            | Self::MalformedJson
            | Self::NonIntegerNumber
            | Self::NonFiniteNumber
            | Self::IntegerOutOfRange
            | Self::MalformedEnvelope
            | Self::Halted
            | Self::MalformedSender
            | Self::MalformedMac
            | Self::UnsupportedVersion
            | Self::UnknownGatePosition
            | Self::UnknownGateOutcome
            | Self::MalformedDigest
            | Self::Stale
            | Self::FromFuture
            | Self::IssuedBeforeEpoch
            | Self::MalformedNonce
            | Self::SequenceNotIncreasing
            | Self::ReplayCacheFull
            | Self::SenderTableFull => GateOutcome::Retry,
        }
    }
}

impl fmt::Display for ReasonCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reason_spellings_are_unique_and_snake_case() {
        let mut seen = std::collections::BTreeSet::new();
        for r in ReasonCode::ALL {
            let s = r.as_str();
            assert!(s.bytes().all(|b| b.is_ascii_lowercase() || b == b'_'), "{s}");
            assert!(seen.insert(s), "duplicate spelling {s}");
        }
    }

    #[test]
    fn resolve_follows_cns_precedence() {
        use GateOutcome::*;
        assert_eq!(GateOutcome::resolve([]), Pass);
        assert_eq!(GateOutcome::resolve([Pass, Retry]), Retry);
        assert_eq!(GateOutcome::resolve([Retry, TerminalBreach, Pass]), TerminalBreach);
    }

    #[test]
    fn vocabularies_round_trip_and_are_closed() {
        for p in [GatePosition::Alpha, GatePosition::Omega] {
            assert_eq!(GatePosition::parse(p.as_str()), Some(p));
        }
        for o in [GateOutcome::Pass, GateOutcome::Retry, GateOutcome::TerminalBreach] {
            assert_eq!(GateOutcome::parse(o.as_str()), Some(o));
        }
        assert_eq!(GatePosition::parse("ALPHA"), None);
        assert_eq!(GatePosition::parse(" alpha"), None);
        assert_eq!(GateOutcome::parse("terminal-breach"), None);
    }
}
