//! Verdicts, reasons, and their mapping onto the kernel vocabulary.
//!
//! The six verdict names are the words `tools/verify_receipts.py` prints.
//! Each non-`VERIFIED` verdict carries a [`Reason`], a closed enum that says
//! which check tripped. The reason, not the verdict, decides the CNS
//! [`GateOutcome`] and the [`Resolution`], by one rule:
//!
//! * **`RETRY`** when the finding depends on what the auditor supplied (the
//!   anchor file or the keys) rather than on the export alone. Supplying the
//!   missing anchor or the key that signed can change the answer. The
//!   resolution is **reject**: the verifier changed nothing and holds
//!   nothing, and the caller may resubmit with the correction.
//! * **`TERMINAL_BREACH`** when the export itself is inconsistent: a hash, a
//!   link, a signature, a subject binding or a seed does not hold, or the
//!   anchored head is not in the chain. No correction by the submitter
//!   repairs a broken seal. The resolution is **quarantine**: the export is
//!   not accepted as evidence, the finding is counted in
//!   `stack_sentinel_trips_total`, and the report names the first failing row
//!   for an operator to review.
//!
//! Two key findings are TERMINAL_BREACH although they involve keys, because
//! the auditor cannot repair them by supplying something:
//!
//! * a signature by a retired key (`signature_retired_key`): the operator
//!   has declared that key untrusted, which is what `sentinel_os`'s
//!   `verify_chain` does under enforcement;
//! * a signature naming a key fingerprint the verifier does not hold, on a
//!   row after an `attestation_policy` marker whose enforced key the verifier
//!   does hold (`signature_unknown_key_after_policy`): the fingerprint is text
//!   the writer of the row chose, and the auditor already holds the one key
//!   the policy enforces, so "supply the key and resubmit" would ask for a
//!   key that need not exist. Before a marker, or when the verifier does not
//!   hold the enforced key, an unknown key stays RETRY
//!   (`signature_unknown_key`).
//!
//! A report's outcome is the most severe across all its findings (the first
//! finding, the anchor finding in `also`, and the `escalation` finding), so a
//! RETRY finding can never hide a TERMINAL_BREACH one. The verdict word and
//! the printed lines still come from the first finding only, as the Python
//! tool prints them.
//!
//! The verifier never uses **rollback** or **halt**. It is read-only and
//! holds no state across calls, so there is nothing of its own to restore,
//! and restoring the ledger is the ledger operator's decision, made with the
//! report in hand. Halting would let one bad export stop the verification of
//! every other export, which helps an attacker and protects nothing.

use std::fmt;

/// The six words the Python offline verifier prints.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Verdict {
    /// Every row and the anchor hold.
    Verified,
    /// A row's bytes are not what was hashed, the chain is broken, or a
    /// signature does not match what it covers.
    Tampered,
    /// A verdict was moved onto content it was not issued for.
    Transplanted,
    /// The agent, not the server, chose the gate order.
    SeedForged,
    /// The chain is shorter than, or diverges from, its anchor.
    Truncated,
    /// An accountable claim with no signature after enforcement began, or a
    /// signature by a key the auditor does not trust.
    Unattested,
}

impl Verdict {
    /// The exact word the Python tool prints.
    pub fn as_str(self) -> &'static str {
        match self {
            Verdict::Verified => "VERIFIED",
            Verdict::Tampered => "TAMPERED",
            Verdict::Transplanted => "TRANSPLANTED",
            Verdict::SeedForged => "SEED_FORGED",
            Verdict::Truncated => "TRUNCATED",
            Verdict::Unattested => "UNATTESTED",
        }
    }

    /// Lowercase metric label.
    pub fn label(self) -> &'static str {
        match self {
            Verdict::Verified => "verified",
            Verdict::Tampered => "tampered",
            Verdict::Transplanted => "transplanted",
            Verdict::SeedForged => "seed_forged",
            Verdict::Truncated => "truncated",
            Verdict::Unattested => "unattested",
        }
    }

    /// Parse the printed word.
    pub fn from_word(word: &str) -> Option<Self> {
        Some(match word {
            "VERIFIED" => Verdict::Verified,
            "TAMPERED" => Verdict::Tampered,
            "TRANSPLANTED" => Verdict::Transplanted,
            "SEED_FORGED" => Verdict::SeedForged,
            "TRUNCATED" => Verdict::Truncated,
            "UNATTESTED" => Verdict::Unattested,
            _ => return None,
        })
    }
}

impl fmt::Display for Verdict {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// The CNS `GateOutcome` vocabulary (`cns/gate.py`). Ordered by severity:
/// `Pass < Retry < TerminalBreach`.
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
    /// The CNS row value: `pass`, `retry`, `terminal_breach`.
    pub fn as_str(self) -> &'static str {
        match self {
            GateOutcome::Pass => "pass",
            GateOutcome::Retry => "retry",
            GateOutcome::TerminalBreach => "terminal_breach",
        }
    }
}

/// The kernel's four state resolutions. This component uses only
/// [`Resolution::Reject`] and [`Resolution::Quarantine`]; see the module
/// documentation for why.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Resolution {
    /// Nothing changed; the caller may resubmit.
    Reject,
    /// The export is isolated from evidence use, counted, and left for review.
    Quarantine,
    /// State restored to the last good snapshot. Not used here.
    Rollback,
    /// The component stops accepting work until reset. Not used here.
    Halt,
}

impl Resolution {
    /// Lowercase label.
    pub fn as_str(self) -> &'static str {
        match self {
            Resolution::Reject => "reject",
            Resolution::Quarantine => "quarantine",
            Resolution::Rollback => "rollback",
            Resolution::Halt => "halt",
        }
    }
}

/// Which check tripped. A closed set, safe as a metric label.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Reason {
    /// `previous_hash` does not equal the prior row's `current_hash`
    /// (`"genesis"` for the first row).
    ChainBroken,
    /// The recomputed hash differs from `current_hash`.
    HashMismatch,
    /// The canonical form could not be rebuilt (a required column missing,
    /// or a column of the wrong shape).
    RecomputeFailed,
    /// A signature does not match under the key it names or any held key.
    SignatureInvalid,
    /// `subject_digest` is not the CNS digest of the row's `input_data`.
    SubjectDigestMismatch,
    /// `input_data` holds NaN or an infinity, which CNS refuses to digest.
    SubjectNotEncodable,
    /// `shuffle_seed` does not re-derive under any held key.
    SeedNotDerived,
    /// `shuffle_seed` re-derives only under a retired key.
    SeedRetiredKey,
    /// `shuffle_seed` is present but no key is held to re-derive it.
    SeedUnverifiable,
    /// An `authorized_by` claim with no signature after the chain's first
    /// `attestation_policy` marker.
    UnsignedAfterPolicy,
    /// A signature names a key fingerprint the verifier does not hold.
    SignatureUnknownKey,
    /// As [`Reason::SignatureUnknownKey`], on a row after an
    /// `attestation_policy` marker whose enforced key the verifier holds.
    SignatureUnknownKeyAfterPolicy,
    /// A signature is valid only under a retired key (refused unless
    /// `VerifierConfig::accept_retired_key_signatures`).
    SignatureRetiredKey,
    /// A signature is present but no key is held.
    SignatureUnverifiable,
    /// No anchor was supplied.
    AnchorMissing,
    /// The anchor is not a readable v1 head anchor, or is over budget.
    AnchorUnreadable,
    /// The anchor HMAC does not verify: the anchor was altered.
    AnchorInvalid,
    /// The anchor names a key the verifier does not hold.
    AnchorUnknownKey,
    /// No key is held to check the anchor.
    AnchorUnverifiable,
    /// The anchor is sealed with a retired key (refused unless
    /// `VerifierConfig::accept_retired_key_anchor`).
    AnchorRetiredKey,
    /// A genuine anchor seals fewer rows than
    /// `VerifierConfig::min_anchor_entries` (by default: zero rows) for a
    /// non-empty chain, so it vouches for nothing.
    AnchorMakesNoClaim,
    /// The chain has fewer rows than the anchor sealed.
    TailMissing,
    /// The row at the anchored position does not carry the anchored head.
    HeadMismatch,
}

impl Reason {
    /// The verdict word this reason is reported under.
    pub fn verdict(self) -> Verdict {
        use Reason::*;
        match self {
            ChainBroken | HashMismatch | RecomputeFailed | SignatureInvalid => Verdict::Tampered,
            SubjectDigestMismatch | SubjectNotEncodable => Verdict::Transplanted,
            SeedNotDerived | SeedRetiredKey | SeedUnverifiable => Verdict::SeedForged,
            UnsignedAfterPolicy
            | SignatureUnknownKey
            | SignatureUnknownKeyAfterPolicy
            | SignatureRetiredKey
            | SignatureUnverifiable => Verdict::Unattested,
            AnchorMissing | AnchorUnreadable | AnchorInvalid | AnchorUnknownKey | AnchorUnverifiable
            | AnchorRetiredKey | AnchorMakesNoClaim | TailMissing | HeadMismatch => Verdict::Truncated,
        }
    }

    /// The CNS outcome, by the rule in the module documentation.
    pub fn gate_outcome(self) -> GateOutcome {
        use Reason::*;
        match self {
            AnchorMissing | AnchorUnreadable | AnchorUnknownKey | AnchorUnverifiable | AnchorRetiredKey
            | AnchorMakesNoClaim | SignatureUnknownKey | SignatureUnverifiable | SeedUnverifiable => {
                GateOutcome::Retry
            }
            _ => GateOutcome::TerminalBreach,
        }
    }

    /// The state resolution: reject for RETRY, quarantine for TERMINAL_BREACH.
    pub fn resolution(self) -> Resolution {
        match self.gate_outcome() {
            GateOutcome::Retry => Resolution::Reject,
            _ => Resolution::Quarantine,
        }
    }

    /// Lowercase metric label.
    pub fn label(self) -> &'static str {
        use Reason::*;
        match self {
            ChainBroken => "chain_broken",
            HashMismatch => "hash_mismatch",
            RecomputeFailed => "recompute_failed",
            SignatureInvalid => "signature_invalid",
            SubjectDigestMismatch => "subject_digest_mismatch",
            SubjectNotEncodable => "subject_not_encodable",
            SeedNotDerived => "seed_not_derived",
            SeedRetiredKey => "seed_retired_key",
            SeedUnverifiable => "seed_unverifiable",
            UnsignedAfterPolicy => "unsigned_after_policy",
            SignatureUnknownKey => "signature_unknown_key",
            SignatureUnknownKeyAfterPolicy => "signature_unknown_key_after_policy",
            SignatureRetiredKey => "signature_retired_key",
            SignatureUnverifiable => "signature_unverifiable",
            AnchorMissing => "anchor_missing",
            AnchorUnreadable => "anchor_unreadable",
            AnchorInvalid => "anchor_invalid",
            AnchorUnknownKey => "anchor_unknown_key",
            AnchorUnverifiable => "anchor_unverifiable",
            AnchorRetiredKey => "anchor_retired_key",
            AnchorMakesNoClaim => "anchor_makes_no_claim",
            TailMissing => "tail_missing",
            HeadMismatch => "head_mismatch",
        }
    }

    /// Every reason, for exhaustive tests and dashboards.
    pub const ALL: [Reason; 23] = [
        Reason::ChainBroken,
        Reason::HashMismatch,
        Reason::RecomputeFailed,
        Reason::SignatureInvalid,
        Reason::SubjectDigestMismatch,
        Reason::SubjectNotEncodable,
        Reason::SeedNotDerived,
        Reason::SeedRetiredKey,
        Reason::SeedUnverifiable,
        Reason::UnsignedAfterPolicy,
        Reason::SignatureUnknownKey,
        Reason::SignatureUnknownKeyAfterPolicy,
        Reason::SignatureRetiredKey,
        Reason::SignatureUnverifiable,
        Reason::AnchorMissing,
        Reason::AnchorUnreadable,
        Reason::AnchorInvalid,
        Reason::AnchorUnknownKey,
        Reason::AnchorUnverifiable,
        Reason::AnchorRetiredKey,
        Reason::AnchorMakesNoClaim,
        Reason::TailMissing,
        Reason::HeadMismatch,
    ];
}

/// One failed check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Finding {
    /// Which check tripped.
    pub reason: Reason,
    /// The `id` of the row it tripped on, when there is one. The Python
    /// prints `row=-` when there is none.
    pub row_id: Option<i64>,
    /// Zero-based position of that row in id order.
    pub row_position: Option<usize>,
    /// A plain-words explanation. It never contains raw row content: stored
    /// values appear only as a full 64-hex hash when they are one, and
    /// otherwise as their type, length and full SHA-256.
    pub detail: String,
}

impl Finding {
    /// The verdict word for this finding.
    pub fn verdict(&self) -> Verdict {
        self.reason.verdict()
    }
}

/// Which anchor vouched for (or failed to vouch for) the chain, so an
/// auditor can see how old it is. A replayed, older anchor still verifies a
/// chain cut back to its count; these fields are how that is noticed.
///
/// Every field is safe to log: `entries` is decimal digits, and
/// `sealed_at` and `key_fingerprint` are shown as stored only when they have
/// the writer's shape (an ISO-8601 timestamp of at most 64 characters, a
/// 16-hex fingerprint), otherwise as their length and full SHA-256.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AnchorSummary {
    /// How many rows the anchor sealed.
    pub entries: String,
    /// When it says it was sealed.
    pub sealed_at: String,
    /// The fingerprint of the key it names.
    pub key_fingerprint: String,
    /// Whether its HMAC verified under a key the verifier accepts for
    /// anchors (a trusted key, or a retired one when that is allowed).
    pub vouched: bool,
}

/// The outcome of verifying one export.
///
/// `VERIFIED` covers only the columns each row's record kind hashes (see
/// [`crate::canonical::hashed_columns`]). Columns outside the canonical form,
/// such as `id`, `timestamp`, `call_sid` and `cassette_snapshot`, can change
/// without changing the verdict; [`Report::unhashed_columns`] lists the ones
/// this export carried.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Report {
    /// The first finding, or `None` for `VERIFIED`.
    pub finding: Option<Finding>,
    /// A second finding worth printing beside the first: the anchor, when a
    /// row failed first (`verify_receipts.verify`'s `note`).
    pub also: Option<Finding>,
    /// A TERMINAL_BREACH finding on a later row, when the first finding was
    /// only RETRY. The Python walk stops at the first failing row; this one
    /// keeps checking after a RETRY finding so that a repairable finding on
    /// an early row cannot hide tampering further down. The link, hash,
    /// subject-binding and unsigned-claim checks always count; seed and
    /// signature checks count only after a policy marker whose enforced key
    /// the verifier holds (see [`crate::verify::verify_rows_with`]). Not printed by
    /// [`Report::render`], which keeps the Python output; it does raise
    /// [`Report::gate_outcome`] and is counted in `trips_total`.
    pub escalation: Option<Finding>,
    /// How many rows the chain walk examined.
    pub rows_checked: usize,
    /// Rows in the export.
    pub rows_total: usize,
    /// Full SHA-256 hex of the export bytes.
    pub export_sha256: String,
    /// The anchor that was checked, when one was supplied and readable.
    pub anchor: Option<AnchorSummary>,
    /// Columns from [`crate::canonical::SHIPPED_COLUMNS`] that at least one
    /// row carried outside its hashed form, in that list's order. `VERIFIED`
    /// says nothing about their values.
    pub unhashed_columns: Vec<&'static str>,
    /// Whether some row carried a column that is not in
    /// [`crate::canonical::SHIPPED_COLUMNS`] at all (never hashed). Its name
    /// is attacker-chosen text, so it is not reported.
    pub other_unhashed_columns: bool,
}

impl Report {
    /// The verdict word, from the first finding, as the Python tool prints
    /// it. It covers the hashed columns only (see the type documentation).
    pub fn verdict(&self) -> Verdict {
        self.finding.as_ref().map_or(Verdict::Verified, Finding::verdict)
    }

    /// Every finding in the report: the first, the anchor note, and the
    /// escalation.
    pub fn findings(&self) -> impl Iterator<Item = &Finding> {
        self.finding.iter().chain(self.also.iter()).chain(self.escalation.iter())
    }

    /// The CNS outcome: the most severe across every finding, so a RETRY
    /// first finding never hides a TERMINAL_BREACH anchor or later-row one.
    pub fn gate_outcome(&self) -> GateOutcome {
        self.findings()
            .map(|f| f.reason.gate_outcome())
            .max()
            .unwrap_or(GateOutcome::Pass)
    }

    /// The state resolution of [`Report::gate_outcome`]: reject for RETRY,
    /// quarantine for TERMINAL_BREACH, `None` for PASS.
    pub fn resolution(&self) -> Option<Resolution> {
        match self.gate_outcome() {
            GateOutcome::Pass => None,
            GateOutcome::Retry => Some(Resolution::Reject),
            GateOutcome::TerminalBreach => Some(Resolution::Quarantine),
        }
    }

    /// The lines `tools/verify_receipts.py` prints for the same result:
    /// `VERIFIED`, or `<VERDICT> row=<id or -> <reason>` followed, when the
    /// anchor also failed, by `  also: anchor mismatch as well: <detail>`.
    pub fn render(&self) -> String {
        match &self.finding {
            None => "VERIFIED".to_owned(),
            Some(f) => {
                let row = f.row_id.map_or_else(|| "-".to_owned(), |id| id.to_string());
                let mut out = format!("{} row={} {}", f.verdict(), row, f.detail);
                if let Some(a) = &self.also {
                    out.push_str("\n  also: anchor mismatch as well: ");
                    out.push_str(&a.detail);
                }
                out
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_reason_maps_to_a_blocking_outcome_and_a_used_resolution() {
        for r in Reason::ALL {
            assert_ne!(r.gate_outcome(), GateOutcome::Pass, "{r:?}");
            assert_ne!(r.verdict(), Verdict::Verified, "{r:?}");
            assert!(matches!(r.resolution(), Resolution::Reject | Resolution::Quarantine));
            assert_eq!(r.resolution() == Resolution::Reject, r.gate_outcome() == GateOutcome::Retry);
        }
    }

    #[test]
    fn report_outcome_is_the_most_severe_finding() {
        let f = |reason| Finding {
            reason,
            row_id: None,
            row_position: None,
            detail: String::new(),
        };
        let mut r = Report {
            finding: Some(f(Reason::SignatureUnknownKey)),
            also: None,
            escalation: None,
            rows_checked: 0,
            rows_total: 0,
            export_sha256: String::new(),
            anchor: None,
            unhashed_columns: Vec::new(),
            other_unhashed_columns: false,
        };
        assert_eq!(r.gate_outcome(), GateOutcome::Retry);
        r.also = Some(f(Reason::TailMissing));
        assert_eq!(r.gate_outcome(), GateOutcome::TerminalBreach);
        assert_eq!(r.resolution(), Some(Resolution::Quarantine));
        r.also = None;
        r.escalation = Some(f(Reason::HashMismatch));
        assert_eq!(r.gate_outcome(), GateOutcome::TerminalBreach);
        assert_eq!(r.verdict(), Verdict::Unattested, "the verdict word stays the first finding's");
    }

    #[test]
    fn verdict_words_round_trip() {
        for v in [
            Verdict::Verified,
            Verdict::Tampered,
            Verdict::Transplanted,
            Verdict::SeedForged,
            Verdict::Truncated,
            Verdict::Unattested,
        ] {
            assert_eq!(Verdict::from_word(v.as_str()), Some(v));
        }
    }
}
