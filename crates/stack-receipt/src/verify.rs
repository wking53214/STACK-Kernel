//! The independent verifier: given a log (bytes or records), the receipt
//! keys the auditor trusts, and whatever the auditor can supply to
//! recompute against, it says what it checked, what it could not check,
//! what it found, and one of five states.
//!
//! # The five states
//!
//! | state | meaning |
//! |---|---|
//! | `VERIFIED` | every check this verifier can perform passed, and `scope.not_checked` is empty |
//! | `VERIFIED_WITH_LIMITATIONS` | every check performed passed; `scope.not_checked` lists what was not performed |
//! | `REJECTED` | at least one check failed; the receipt is not evidence of what it claims |
//! | `INCOMPLETE` | the chain is intact but the execution has no terminal event, or never reached an attempt |
//! | `UNKNOWN` | nothing to judge: no records for the execution, or an empty log |
//!
//! `VERIFIED` is defined strictly. Some limitation always applies
//! (`action_legitimacy_not_established`: no receipt can show that an
//! action should have happened, only that these records say it did), so
//! in practice an intact receipt is `VERIFIED_WITH_LIMITATIONS` and a
//! consumer must read `scope.not_checked` before relying on it. A
//! consumer must also read `execution.outcome`: a `TimedOut` or
//! `Rejected` execution verifies as well as a `Completed` one, because
//! the receipt is honest about what happened. The state is about the
//! evidence; the outcome is about the action.
//!
//! An attempt with no terminal event is `INCOMPLETE` with outcome
//! `Unknown`: this is the kernel-died-during-execution case and is never
//! reported as success.

use std::collections::BTreeMap;
use std::fmt;

use sha2::{Digest, Sha256};
use stack_authority::{Digest32, UseEvidence};

use crate::cns::{subject_digest, CnsValue};
use crate::decision::{check_authorized_decision, DecisionFinding, RosterPolicy};
use crate::encode::genesis_hash;
use crate::log::{parse_log, Head, LogError};
use crate::record::{Event, ExecutionId, LastStage, Observed, Outcome, OutcomeKind, Recovered, Stage};
use crate::sign::{ResolveError, SignedRecord, TrustedReceiptKeys};

/// The verdict on a receipt as evidence. See the module documentation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum State {
    /// Every check passed and nothing was left unchecked.
    Verified,
    /// Every check performed passed; some were not performed.
    VerifiedWithLimitations,
    /// A check failed.
    Rejected,
    /// Intact but not finished.
    Incomplete,
    /// Nothing to judge.
    Unknown,
}

impl State {
    /// The spelling consumers match on.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Verified => "VERIFIED",
            Self::VerifiedWithLimitations => "VERIFIED_WITH_LIMITATIONS",
            Self::Rejected => "REJECTED",
            Self::Incomplete => "INCOMPLETE",
            Self::Unknown => "UNKNOWN",
        }
    }
}

impl fmt::Display for State {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A check the verifier performed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Check {
    /// Every record's hash chains to the previous one from genesis.
    HashChain,
    /// Sequences run 1, 2, 3, ... with no gap or repeat.
    SequenceMonotonic,
    /// Every record names one kernel, and the expected one if given.
    KernelIdConsistent,
    /// Every signature verifies under a trusted, active, in-window key.
    Signatures,
    /// Proposed, then Authorized or Rejected, then Attempted, then one terminal.
    StageOrder,
    /// The decision root recomputes from the seats and verdicts.
    DecisionRootRecomputed,
    /// The subject digest recomputes from the supplied content.
    SubjectDigestRecomputed,
    /// The roster is non-empty, complete, all PASS and bound.
    RosterComplete,
    /// Policy-required seats are present and PASS.
    RosterPolicy,
    /// The capability's subject digest and decision root are the proposal's.
    CapabilityBindingConsistent,
    /// Proposed, authorized and actual operation and resource agree.
    ActionConsistent,
    /// The capability's audience is the expected one.
    Audience,
    /// The terminal outcome is consistent with the stages before it.
    OutcomeConsistentWithStageOrder,
    /// The result digest is the digest of the supplied result bytes.
    ResultDigestRecomputed,
    /// The supervisor-observed facts of a version 2 terminal agree with its
    /// outcome (Completed only on a clean exit 0 with one valid frame).
    ObservedFactsConsistentWithOutcome,
    /// The recorded worker image digest is the one the auditor expects.
    WorkerImageMatchesExpected,
    /// The recorded worker limits are the ones the auditor expects.
    WorkerLimitsMatchExpected,
    /// The recorded native component digest is the one the auditor expects.
    NativeDigestMatchesExpected,
    /// A durable use record's position and hashes are well formed.
    UseEvidenceWellFormed,
    /// The log still holds the record the auditor anchored.
    AnchorHeld,
    /// A `Recovered` record names the stage the chain shows the execution at.
    RecoveryClaimMatchesChain,
}

impl Check {
    /// Machine-readable spelling.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::HashChain => "hash_chain",
            Self::SequenceMonotonic => "sequence_monotonic",
            Self::KernelIdConsistent => "kernel_id_consistent",
            Self::Signatures => "signatures",
            Self::StageOrder => "stage_order",
            Self::DecisionRootRecomputed => "decision_root_recomputed",
            Self::SubjectDigestRecomputed => "subject_digest_recomputed",
            Self::RosterComplete => "roster_complete",
            Self::RosterPolicy => "roster_policy",
            Self::CapabilityBindingConsistent => "capability_binding_consistent",
            Self::ActionConsistent => "action_consistent",
            Self::Audience => "audience",
            Self::OutcomeConsistentWithStageOrder => "outcome_consistent_with_stage_order",
            Self::ResultDigestRecomputed => "result_digest_recomputed",
            Self::ObservedFactsConsistentWithOutcome => "observed_facts_consistent_with_outcome",
            Self::WorkerImageMatchesExpected => "worker_image_matches_expected",
            Self::WorkerLimitsMatchExpected => "worker_limits_match_expected",
            Self::NativeDigestMatchesExpected => "native_digest_matches_expected",
            Self::UseEvidenceWellFormed => "use_evidence_well_formed",
            Self::AnchorHeld => "anchor_held",
            Self::RecoveryClaimMatchesChain => "recovery_claim_matches_chain",
        }
    }
}

/// Something the verifier did not check, and why a consumer must know.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Limitation {
    /// No receipt can show that the action should have happened.
    ActionLegitimacyNotEstablished,
    /// The capability's issuer signature is not re-verified here; the
    /// receipt carries the binding `stack-authority` recorded.
    CapabilitySignatureNotRechecked,
    /// The CNS decision proof is an HMAC under a process-local key.
    DecisionProofNotCheckableHmacIsProcessLocal,
    /// The producer's native digest is carried, not verified.
    NativeComponentNotVerified,
    /// No subject content was supplied, so the subject digest stands
    /// unrecomputed.
    SubjectContentNotSupplied,
    /// No roster policy was supplied, so no seat was required.
    RosterPolicyNotSupplied,
    /// No expected audience was supplied.
    AudienceNotSupplied,
    /// No result bytes were supplied for a Completed outcome.
    ResultBytesNotSupplied,
    /// The result of a Completed outcome is the worker's own claim: a
    /// hostile worker can forge a well-formed result, and a matching
    /// digest proves only that these are the bytes the worker sent.
    ResultIsSelfReported,
    /// The Trident handoff MAC is not re-verified here.
    HandoffProvenanceNotRechecked,
    /// Every timestamp and elapsed time is the writer's claim.
    TimestampsAreWriterClaims,
    /// A rollback to an earlier chain head is undetectable without an
    /// external anchor of `head()`.
    LogRollbackNotDetectableWithoutAnchor,
    /// Bytes past the committed length were a torn frame and were ignored.
    TornTailIgnored,
    /// A terminal event of receipt format version 1 does not carry the
    /// supervisor-observed exit and frame facts, so they cannot be checked
    /// against the outcome. A limitation of the old receipt, not a failure.
    SupervisorObservedFactsNotRecorded,
    /// An `Attempted` record of receipt format version 1 does not bind the
    /// worker image digest or the limits the supervisor applied, so the
    /// receipt cannot say which program ran or under which limits. A
    /// limitation of the old receipt, not a failure.
    WorkerIdentityNotRecorded,
    /// The worker image digest and limits are recorded but the auditor
    /// supplied no expectation to compare them with.
    WorkerExpectationNotSupplied,
    /// An `Authorized` record of receipt format version 1 does not bind the
    /// use store's evidence. A limitation of the old receipt, not a failure.
    UseEvidenceNotRecorded,
    /// The use store returned no evidence (a store that predates the API), so
    /// the receipt cannot show where the one-time use was recorded.
    UseEvidenceNotProvidedByStore,
    /// The use was recorded by a non-durable store: it proves nothing about
    /// the use across a restart.
    UseEvidenceNonDurable,
    /// A restarted kernel closed this execution without knowing how it ended:
    /// its last record was `Attempted`, so the payload may have completed, may
    /// have been cut off, or may never have started. The outcome is unknown.
    ExecutionRecoveredOutcomeUnknown,
}

impl Limitation {
    /// Machine-readable spelling.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ActionLegitimacyNotEstablished => "action_legitimacy_not_established",
            Self::CapabilitySignatureNotRechecked => "capability_signature_not_rechecked",
            Self::DecisionProofNotCheckableHmacIsProcessLocal => "decision_proof_not_checkable_hmac_is_process_local",
            Self::NativeComponentNotVerified => "native_component_not_verified",
            Self::SubjectContentNotSupplied => "subject_content_not_supplied",
            Self::RosterPolicyNotSupplied => "roster_policy_not_supplied",
            Self::AudienceNotSupplied => "audience_not_supplied",
            Self::ResultBytesNotSupplied => "result_bytes_not_supplied",
            Self::ResultIsSelfReported => "result_is_self_reported",
            Self::HandoffProvenanceNotRechecked => "handoff_provenance_not_rechecked",
            Self::TimestampsAreWriterClaims => "timestamps_are_writer_claims",
            Self::LogRollbackNotDetectableWithoutAnchor => "log_rollback_not_detectable_without_anchor",
            Self::TornTailIgnored => "torn_tail_ignored",
            Self::SupervisorObservedFactsNotRecorded => "supervisor_observed_facts_not_recorded",
            Self::WorkerIdentityNotRecorded => "worker_identity_not_recorded",
            Self::WorkerExpectationNotSupplied => "worker_expectation_not_supplied",
            Self::UseEvidenceNotRecorded => "use_evidence_not_recorded",
            Self::UseEvidenceNotProvidedByStore => "use_evidence_not_provided_by_store",
            Self::UseEvidenceNonDurable => "use_evidence_non_durable",
            Self::ExecutionRecoveredOutcomeUnknown => "execution_recovered_outcome_unknown",
        }
    }
}

/// What was checked and what was not.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Scope {
    /// Checks performed, each of which passed unless a finding says
    /// otherwise.
    pub checked: Vec<Check>,
    /// Checks not performed. A consumer reads this before relying on
    /// the state.
    pub not_checked: Vec<Limitation>,
}

impl Scope {
    fn check(&mut self, c: Check) {
        if !self.checked.contains(&c) {
            self.checked.push(c);
        }
    }
    fn limit(&mut self, l: Limitation) {
        if !self.not_checked.contains(&l) {
            self.not_checked.push(l);
        }
    }
    fn merge(&mut self, other: &Scope) {
        for c in &other.checked {
            self.check(*c);
        }
        for l in &other.not_checked {
            self.limit(*l);
        }
    }
}

/// What a finding means for the state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Severity {
    /// The receipt is rejected.
    Reject,
    /// The receipt is incomplete.
    Incomplete,
    /// Recorded for the consumer; no effect on the state.
    Info,
}

/// A typed finding code.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FindingCode {
    /// The log bytes do not parse as a receipt log.
    LogCorrupt,
    /// The log holds no records.
    EmptyLog,
    /// A sequence is not the previous one plus one.
    SequenceGap,
    /// A record's `prev_hash` is not the previous record's hash.
    PrevHashMismatch,
    /// A record names a kernel other than the first record's, or the
    /// expected one.
    KernelIdMismatch,
    /// The record's key is not in the trusted set for its kernel.
    ReceiptKeyUntrusted,
    /// The record's key is revoked.
    ReceiptKeyRevoked,
    /// The record's claimed time is outside its key's window.
    ReceiptKeyOutsideWindow,
    /// The signature does not verify under the resolved key.
    BadSignature,
    /// No record carries the execution id.
    ExecutionNotFound,
    /// The execution's first record is not Proposed.
    MissingProposed,
    /// A second Proposed for the same execution.
    DuplicateProposed,
    /// Attempted recorded with no Authorized before it.
    AttemptedWithoutAuthorized,
    /// A terminal outcome recorded with no Attempted before it.
    TerminalWithoutAttempted,
    /// A second terminal event.
    DuplicateTerminal,
    /// Any event after a terminal one.
    EventAfterTerminal,
    /// An event out of order not covered above.
    StageOrderViolation,
    /// The recorded root is not the root of the recorded seats and verdicts.
    DecisionRootMismatch,
    /// A roster or verdict problem (see [`DecisionFinding`]).
    Decision(DecisionFinding),
    /// The capability's decision root is not the proposal's.
    CapabilityDecisionRootMismatch,
    /// The capability's subject digest is not the proposal's.
    CapabilitySubjectMismatch,
    /// The authorized operation or resource is not the proposed one.
    AuthorizedActionDiffersFromProposed,
    /// The attempted operation or resource is not the authorized one.
    ActualActionDiffersFromAuthorized,
    /// The capability's audience is not the expected one.
    AudienceMismatch,
    /// The supplied content does not digest to the recorded subject digest.
    SubjectDigestMismatch,
    /// The supplied result bytes do not digest to the recorded result digest.
    ResultDigestMismatch,
    /// Attempted with no terminal event.
    TerminalMissing,
    /// Authorized with no Attempted and no Rejected.
    NotAttempted,
    /// Proposed with nothing after it.
    NotAuthorized,
    /// The terminal outcome is `TerminationUnconfirmed`: the kernel could
    /// not confirm the worker dead, so the action may still be in
    /// progress (informational; the outcome already says so).
    WorkerMayStillBeRunning,
    /// A version 2 terminal event records a Completed outcome whose observed
    /// facts are not a clean exit 0 with one valid frame, or an observed fact
    /// that the outcome contradicts (Unreaped without TerminationUnconfirmed,
    /// a valid frame under ResultMissing).
    ObservedFactsContradictOutcome,
    /// The recorded worker image digest is not the one the auditor expects.
    WorkerImageMismatch,
    /// The recorded worker limits are not the ones the auditor expects.
    WorkerLimitsMismatch,
    /// The recorded native component digest (or its label) is not the one the
    /// auditor expects. Independent of the CNS subject digest.
    NativeDigestMismatch,
    /// A durable use record claims position 0.
    UseEvidenceMalformed,
    /// A torn frame was discarded (informational).
    TornTailDiscarded,
    /// A complete unacknowledged frame was adopted (informational).
    TrailingFrameAdopted,
    /// The auditor's anchor names a sequence the log does not reach: the log
    /// was cut short or rolled back.
    LogDoesNotReachAnchor,
    /// The record at the anchored sequence is not the anchored record: the
    /// history was replaced.
    AnchorMismatch,
    /// A restarted kernel found this execution open and closed it with a
    /// `Recovered` record (informational; the limitation says what is unknown).
    RecoveredAfterRestart,
    /// A `Recovered` record names a last stage the chain does not show.
    RecoveredStageMismatch,
}

impl FindingCode {
    /// What the finding means for the state.
    pub const fn severity(&self) -> Severity {
        match self {
            Self::TerminalMissing | Self::NotAttempted | Self::NotAuthorized => Severity::Incomplete,
            Self::EmptyLog
            | Self::ExecutionNotFound
            | Self::TornTailDiscarded
            | Self::TrailingFrameAdopted
            | Self::WorkerMayStillBeRunning
            | Self::RecoveredAfterRestart => Severity::Info,
            _ => Severity::Reject,
        }
    }

    /// Machine-readable spelling.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::LogCorrupt => "log_corrupt",
            Self::EmptyLog => "empty_log",
            Self::SequenceGap => "sequence_gap",
            Self::PrevHashMismatch => "prev_hash_mismatch",
            Self::KernelIdMismatch => "kernel_id_mismatch",
            Self::ReceiptKeyUntrusted => "receipt_key_untrusted",
            Self::ReceiptKeyRevoked => "receipt_key_revoked",
            Self::ReceiptKeyOutsideWindow => "receipt_key_outside_window",
            Self::BadSignature => "bad_signature",
            Self::ExecutionNotFound => "execution_not_found",
            Self::MissingProposed => "missing_proposed",
            Self::DuplicateProposed => "duplicate_proposed",
            Self::AttemptedWithoutAuthorized => "attempted_without_authorized",
            Self::TerminalWithoutAttempted => "terminal_without_attempted",
            Self::DuplicateTerminal => "duplicate_terminal",
            Self::EventAfterTerminal => "event_after_terminal",
            Self::StageOrderViolation => "stage_order_violation",
            Self::DecisionRootMismatch => "decision_root_mismatch",
            Self::Decision(d) => match d {
                DecisionFinding::EmptyRoster => "empty_roster",
                DecisionFinding::DuplicateSeat(_) => "duplicate_seat",
                DecisionFinding::RequiredSeatMissing(_) => "required_seat_missing",
                DecisionFinding::RequiredSeatNotPassed(_) => "required_seat_not_passed",
                DecisionFinding::VerdictNotPass { .. } => "verdict_not_pass",
                DecisionFinding::VerdictUnbound(_) => "verdict_unbound",
                DecisionFinding::VerdictForUnseatedGate(_) => "verdict_for_unseated_gate",
                DecisionFinding::VerdictCountMismatch { .. } => "verdict_count_mismatch",
                DecisionFinding::OmegaBeforeAlpha => "omega_before_alpha",
                DecisionFinding::DuplicateVerdict(_) => "duplicate_verdict",
                DecisionFinding::SeatNotJudged(_) => "seat_not_judged",
                DecisionFinding::DuplicateGateName(_) => "duplicate_gate_name",
                DecisionFinding::RequiredSeatWrongPosition { .. } => "required_seat_wrong_position",
            },
            Self::CapabilityDecisionRootMismatch => "capability_decision_root_mismatch",
            Self::CapabilitySubjectMismatch => "capability_subject_mismatch",
            Self::AuthorizedActionDiffersFromProposed => "authorized_action_differs_from_proposed",
            Self::ActualActionDiffersFromAuthorized => "actual_action_differs_from_authorized",
            Self::AudienceMismatch => "audience_mismatch",
            Self::SubjectDigestMismatch => "subject_digest_mismatch",
            Self::ResultDigestMismatch => "result_digest_mismatch",
            Self::TerminalMissing => "terminal_missing",
            Self::NotAttempted => "not_attempted",
            Self::NotAuthorized => "not_authorized",
            Self::WorkerMayStillBeRunning => "worker_may_still_be_running",
            Self::ObservedFactsContradictOutcome => "observed_facts_contradict_outcome",
            Self::WorkerImageMismatch => "worker_image_mismatch",
            Self::WorkerLimitsMismatch => "worker_limits_mismatch",
            Self::NativeDigestMismatch => "native_digest_mismatch",
            Self::UseEvidenceMalformed => "use_evidence_malformed",
            Self::TornTailDiscarded => "torn_tail_discarded",
            Self::TrailingFrameAdopted => "trailing_frame_adopted",
            Self::LogDoesNotReachAnchor => "log_does_not_reach_anchor",
            Self::AnchorMismatch => "anchor_mismatch",
            Self::RecoveredAfterRestart => "recovered_after_restart",
            Self::RecoveredStageMismatch => "recovered_stage_mismatch",
        }
    }
}

/// One finding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Finding {
    /// The code.
    pub code: FindingCode,
    /// The record it concerns, when one.
    pub sequence: Option<u64>,
    /// Detail for a reader; never input content.
    pub detail: String,
}

impl Finding {
    fn new(code: FindingCode, sequence: Option<u64>, detail: impl Into<String>) -> Self {
        Self {
            code,
            sequence,
            detail: detail.into(),
        }
    }
}

/// What the verifier can be given to recompute against. Everything is
/// optional; each absence becomes a [`Limitation`].
#[derive(Debug, Clone, Copy, Default)]
pub struct Expectations<'a> {
    /// The content the execution was about, to recompute the subject digest.
    pub subject_content: Option<&'a CnsValue>,
    /// The verifier's own required roster.
    pub roster_policy: Option<&'a RosterPolicy>,
    /// The audience the capability must name.
    pub audience: Option<&'a str>,
    /// The kernel the log must belong to.
    pub kernel_id: Option<&'a str>,
    /// The result bytes, to recompute a Completed outcome's digest.
    pub result_bytes: Option<&'a [u8]>,
    /// The SHA-256 of the worker image the auditor expects the supervisor to
    /// have run (from the release record).
    pub worker_image_sha256: Option<&'a Digest32>,
    /// The limits the auditor expects the supervisor to have applied.
    pub worker_limits: Option<&'a crate::record::AppliedLimits>,
    /// The native component digest the auditor expects (for example a
    /// Sentinel ledger row hash it holds). Compared with the record's
    /// `native_digest`, never with the CNS subject digest.
    pub native_digest: Option<&'a crate::record::NativeDigest>,
    /// A [`Head`] the auditor saved earlier somewhere the log's writer cannot
    /// reach (for example the `head()` of the log, written down off the
    /// machine). The log must still hold the record at that sequence with
    /// that hash. This catches a log cut short or rolled back below the
    /// anchor, and a log whose history was replaced. It cannot catch a
    /// rollback to a point at or after the anchor, so the limitation
    /// [`Limitation::LogRollbackNotDetectableWithoutAnchor`] is still listed.
    pub anchor: Option<&'a Head>,
}

/// What the execution's records say happened.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecutionSummary {
    /// The execution.
    pub execution_id: ExecutionId,
    /// The furthest stage with a record, in stage order.
    pub stage_reached: Option<Stage>,
    /// The terminal outcome; `Unknown` for an attempt with no terminal
    /// event; `None` when nothing was attempted (including a rejection).
    pub outcome: Option<OutcomeKind>,
    /// Sequences of the execution's records, in order.
    pub sequences: Vec<u64>,
}

/// The verdict on one execution.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Verification {
    /// The state.
    pub state: State,
    /// What the records say happened.
    pub execution: ExecutionSummary,
    /// What was checked and what was not.
    pub scope: Scope,
    /// Every finding, chain-level ones first.
    pub findings: Vec<Finding>,
}

/// The verdict on a whole log.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LogVerification {
    /// The state: the worst across the chain and every execution.
    pub state: State,
    /// Chain-level findings.
    pub findings: Vec<Finding>,
    /// The union of every scope.
    pub scope: Scope,
    /// One verdict per execution, in order of first appearance.
    pub executions: Vec<Verification>,
}

fn state_from(findings: &[Finding], scope: &Scope, has_records: bool) -> State {
    if findings.iter().any(|f| f.code.severity() == Severity::Reject) {
        return State::Rejected;
    }
    if !has_records {
        return State::Unknown;
    }
    if findings.iter().any(|f| f.code.severity() == Severity::Incomplete) {
        return State::Incomplete;
    }
    if scope.not_checked.is_empty() {
        State::Verified
    } else {
        State::VerifiedWithLimitations
    }
}

/// Chain-level checks over every record: sequence, hashes, kernel id,
/// signatures under the trust set.
fn verify_chain(records: &[SignedRecord], trusted: &TrustedReceiptKeys, exp: &Expectations<'_>) -> (Vec<Finding>, Scope) {
    let mut findings = Vec::new();
    let mut scope = Scope::default();
    scope.check(Check::SequenceMonotonic);
    scope.check(Check::HashChain);
    scope.check(Check::KernelIdConsistent);
    scope.check(Check::Signatures);
    scope.limit(Limitation::LogRollbackNotDetectableWithoutAnchor);
    scope.limit(Limitation::TimestampsAreWriterClaims);
    if exp.anchor.is_some() {
        scope.check(Check::AnchorHeld);
    }
    if records.is_empty() {
        findings.push(Finding::new(FindingCode::EmptyLog, None, "no records"));
        if let Some(anchor) = exp.anchor {
            check_anchor(records, anchor, &mut findings);
        }
        return (findings, scope);
    }
    let kernel_id = exp
        .kernel_id
        .map_or_else(|| records.first().map(|r| r.record().kernel_id.clone()).unwrap_or_default(), str::to_owned);
    let mut expected_seq = 1u64;
    let mut prev = genesis_hash();
    for s in records {
        let r = s.record();
        let seq = Some(r.sequence);
        if r.sequence != expected_seq {
            findings.push(Finding::new(
                FindingCode::SequenceGap,
                seq,
                format!("expected sequence {expected_seq}"),
            ));
            expected_seq = r.sequence;
        }
        expected_seq = expected_seq.saturating_add(1);
        if r.prev_hash != prev {
            findings.push(Finding::new(
                FindingCode::PrevHashMismatch,
                seq,
                "prev_hash is not the previous record's hash",
            ));
        }
        prev = *s.hash();
        if r.kernel_id != kernel_id {
            findings.push(Finding::new(FindingCode::KernelIdMismatch, seq, "record names another kernel"));
        }
        match trusted.resolve(&r.kernel_id, &r.key_id, r.recorded_at_ms) {
            Ok(anchor) => {
                if s.verify(anchor.public_key()).is_err() {
                    findings.push(Finding::new(FindingCode::BadSignature, seq, "signature does not verify"));
                }
            }
            Err(ResolveError::UntrustedKey) => {
                findings.push(Finding::new(FindingCode::ReceiptKeyUntrusted, seq, "key not trusted for this kernel"));
            }
            Err(ResolveError::Revoked) => {
                findings.push(Finding::new(FindingCode::ReceiptKeyRevoked, seq, "key revoked"));
            }
            Err(ResolveError::NotYetValid | ResolveError::Expired) => {
                findings.push(Finding::new(
                    FindingCode::ReceiptKeyOutsideWindow,
                    seq,
                    "recorded_at_ms outside the key's window",
                ));
            }
        }
    }
    if let Some(anchor) = exp.anchor {
        check_anchor(records, anchor, &mut findings);
    }
    (findings, scope)
}

/// The anchor check: the log must still hold the anchored record. An anchor
/// at sequence 0 is the head of an empty log, which every log extends.
fn check_anchor(records: &[SignedRecord], anchor: &Head, findings: &mut Vec<Finding>) {
    if anchor.sequence == 0 {
        return;
    }
    match records.iter().find(|s| s.record().sequence == anchor.sequence) {
        None => findings.push(Finding::new(
            FindingCode::LogDoesNotReachAnchor,
            Some(anchor.sequence),
            "the log has no record at the anchored sequence; it was cut short or rolled back",
        )),
        Some(s) if *s.hash() != anchor.hash => findings.push(Finding::new(
            FindingCode::AnchorMismatch,
            Some(anchor.sequence),
            "the record at the anchored sequence is not the anchored record; the history was replaced",
        )),
        Some(_) => {}
    }
}

/// The order of stages for "furthest stage reached".
const fn stage_rank(s: Stage) -> u8 {
    match s {
        Stage::Proposed => 0,
        Stage::Authorized => 1,
        Stage::Attempted => 2,
        Stage::Rejected | Stage::Terminal | Stage::Recovered => 3,
    }
}

/// Why the observed facts of a version 2 terminal cannot go with its outcome,
/// or `None` when they can. `Completed` is exactly: the supervisor saw the
/// worker exit 0 and held one well-formed frame. The converse is checked where
/// it is unambiguous: an unreaped worker is `TerminationUnconfirmed`, and
/// `ResultMissing` is an exit 0 whose frame was not valid.
fn observed_contradiction(outcome: &Outcome, o: &Observed) -> Option<&'static str> {
    use crate::record::{ExitObserved, FrameStatus};
    match outcome {
        Outcome::Completed { exit_code, .. } => {
            if !o.supports_completed() || *exit_code != 0 {
                Some("Completed, but the supervisor did not observe an exit 0 with one valid frame")
            } else {
                None
            }
        }
        Outcome::ResultMissing { .. } => {
            if matches!(o.exit, ExitObserved::Exited { code: 0 }) && o.frame != FrameStatus::Valid {
                None
            } else {
                Some("ResultMissing, but the supervisor did not observe an exit 0 with a frame that was not valid")
            }
        }
        Outcome::TerminationUnconfirmed { .. } => {
            if o.exit == ExitObserved::Unreaped {
                None
            } else {
                Some("TerminationUnconfirmed, but the supervisor did not observe an unreaped worker")
            }
        }
        _ if o.exit == ExitObserved::Unreaped => Some("an unreaped worker under an outcome other than TerminationUnconfirmed"),
        _ => None,
    }
}

/// Execution-level checks over one execution's records, in order.
fn verify_execution(
    execution_id: ExecutionId,
    records: &[&SignedRecord],
    exp: &Expectations<'_>,
) -> (ExecutionSummary, Vec<Finding>, Scope) {
    let mut findings = Vec::new();
    let mut scope = Scope::default();
    let mut summary = ExecutionSummary {
        execution_id,
        stage_reached: None,
        outcome: None,
        sequences: records.iter().map(|s| s.record().sequence).collect(),
    };
    scope.limit(Limitation::ActionLegitimacyNotEstablished);
    if records.is_empty() {
        findings.push(Finding::new(FindingCode::ExecutionNotFound, None, "no record carries this execution id"));
        return (summary, findings, scope);
    }
    scope.check(Check::StageOrder);
    scope.check(Check::OutcomeConsistentWithStageOrder);

    // Stage order, as a small state machine.
    #[derive(PartialEq, Eq, Clone, Copy)]
    enum At {
        Start,
        Proposed,
        Authorized,
        Attempted,
        Closed,
    }
    let mut at = At::Start;
    let (mut proposed, mut authorized, mut attempted, mut terminal) = (None, None, None, None);
    let mut observed: Option<&Observed> = None;
    let mut recovered: Option<&Recovered> = None;
    for s in records {
        let r = s.record();
        let seq = Some(r.sequence);
        let stage = r.stage();
        // `Recovered` closes an execution without being a stage it reached, so
        // the furthest stage stays what the run actually got to.
        if stage != Stage::Recovered && summary.stage_reached.is_none_or(|prev| stage_rank(stage) > stage_rank(prev)) {
            summary.stage_reached = Some(stage);
        }
        match (&r.event, at) {
            (Event::Proposed(p), At::Start) => {
                proposed = Some(p);
                at = At::Proposed;
            }
            (Event::Proposed(_), _) => {
                findings.push(Finding::new(FindingCode::DuplicateProposed, seq, "a second Proposed"));
            }
            (_, At::Start) => {
                findings.push(Finding::new(
                    FindingCode::MissingProposed,
                    seq,
                    "the first record is not Proposed",
                ));
                // Keep walking as if proposed, to report what follows.
                at = At::Proposed;
                match &r.event {
                    Event::Authorized(a) => {
                        authorized = Some(a);
                        at = At::Authorized;
                    }
                    Event::Rejected(_) => at = At::Closed,
                    Event::Recovered(rec) => {
                        recovered = Some(rec);
                        findings.push(Finding::new(
                            FindingCode::RecoveredStageMismatch,
                            seq,
                            "Recovered names a last stage, but the execution has no record before it",
                        ));
                        at = At::Closed;
                    }
                    Event::Attempted(a) => {
                        findings.push(Finding::new(FindingCode::AttemptedWithoutAuthorized, seq, "no Authorized"));
                        attempted = Some(a);
                        at = At::Attempted;
                    }
                    Event::Terminal(_) | Event::TerminalObserved(_) => {
                        findings.push(Finding::new(FindingCode::TerminalWithoutAttempted, seq, "no Attempted"));
                        if let Some((t, o)) = r.event.terminal_parts() {
                            terminal = Some(t);
                            observed = o;
                        }
                        at = At::Closed;
                    }
                    Event::Proposed(_) => {}
                }
            }
            (_, At::Closed) => {
                let code = if matches!(
                    r.event,
                    Event::Terminal(_) | Event::TerminalObserved(_) | Event::Rejected(_) | Event::Recovered(_)
                ) {
                    FindingCode::DuplicateTerminal
                } else {
                    FindingCode::EventAfterTerminal
                };
                findings.push(Finding::new(code, seq, "after a terminal event"));
            }
            (Event::Authorized(a), At::Proposed) => {
                authorized = Some(a);
                at = At::Authorized;
            }
            (Event::Rejected(_), At::Proposed | At::Authorized) => {
                at = At::Closed;
            }
            (Event::Recovered(rec), At::Proposed | At::Authorized | At::Attempted) => {
                scope.check(Check::RecoveryClaimMatchesChain);
                let actual = match at {
                    At::Authorized => LastStage::Authorized,
                    At::Attempted => LastStage::Attempted,
                    _ => LastStage::Proposed,
                };
                if rec.last_stage != actual {
                    findings.push(Finding::new(
                        FindingCode::RecoveredStageMismatch,
                        seq,
                        format!(
                            "Recovered says the execution was last at {}, but the chain shows {}",
                            rec.last_stage.as_str(),
                            actual.as_str()
                        ),
                    ));
                }
                findings.push(Finding::new(
                    FindingCode::RecoveredAfterRestart,
                    seq,
                    format!("a restart found this execution open after {} and closed it", actual.as_str()),
                ));
                recovered = Some(rec);
                at = At::Closed;
            }
            (Event::Attempted(a), At::Authorized) => {
                attempted = Some(a);
                at = At::Attempted;
            }
            (Event::Attempted(a), At::Proposed) => {
                findings.push(Finding::new(FindingCode::AttemptedWithoutAuthorized, seq, "no Authorized"));
                attempted = Some(a);
                at = At::Attempted;
            }
            (Event::Terminal(_) | Event::TerminalObserved(_), At::Attempted) => {
                if let Some((t, o)) = r.event.terminal_parts() {
                    terminal = Some(t);
                    observed = o;
                }
                at = At::Closed;
            }
            (Event::Terminal(_) | Event::TerminalObserved(_), At::Proposed | At::Authorized) => {
                findings.push(Finding::new(FindingCode::TerminalWithoutAttempted, seq, "no Attempted"));
                if let Some((t, o)) = r.event.terminal_parts() {
                    terminal = Some(t);
                    observed = o;
                }
                at = At::Closed;
            }
            (Event::Authorized(_) | Event::Rejected(_), At::Authorized | At::Attempted) => {
                findings.push(Finding::new(FindingCode::StageOrderViolation, seq, "out of order"));
            }
            (Event::Attempted(_), At::Attempted) => {
                findings.push(Finding::new(FindingCode::StageOrderViolation, seq, "a second Attempted"));
            }
        }
    }

    // Outcome and completeness.
    match (at, terminal) {
        (At::Closed, Some(t)) => summary.outcome = Some(t.outcome.kind()),
        (At::Closed, None) => {
            summary.outcome = match recovered {
                Some(rec) if rec.last_stage == LastStage::Attempted => {
                    scope.limit(Limitation::ExecutionRecoveredOutcomeUnknown);
                    Some(OutcomeKind::Unknown)
                }
                _ => None,
            };
        }
        (At::Attempted, _) => {
            summary.outcome = Some(OutcomeKind::Unknown);
            findings.push(Finding::new(
                FindingCode::TerminalMissing,
                None,
                "Attempted with no terminal event: the outcome is unknown",
            ));
        }
        (At::Authorized, _) => {
            findings.push(Finding::new(FindingCode::NotAttempted, None, "Authorized with nothing after it"));
        }
        (At::Proposed, _) => {
            findings.push(Finding::new(FindingCode::NotAuthorized, None, "Proposed with nothing after it"));
        }
        (At::Start, _) => {}
    }

    // Decision evidence.
    if let Some(p) = proposed {
        scope.check(Check::DecisionRootRecomputed);
        if !p.decision.root_matches() {
            findings.push(Finding::new(
                FindingCode::DecisionRootMismatch,
                None,
                "recorded root is not the root of the recorded seats and verdicts",
            ));
        }
        scope.limit(Limitation::DecisionProofNotCheckableHmacIsProcessLocal);
        match exp.subject_content {
            Some(content) => {
                scope.check(Check::SubjectDigestRecomputed);
                if !subject_digest(content).ct_eq(&p.subject.digest) {
                    findings.push(Finding::new(
                        FindingCode::SubjectDigestMismatch,
                        None,
                        "supplied content does not digest to the recorded subject digest",
                    ));
                }
            }
            None => scope.limit(Limitation::SubjectContentNotSupplied),
        }
        if p.handoff.is_some() {
            scope.limit(Limitation::HandoffProvenanceNotRechecked);
        }
        if let Some(n) = &p.native_digest {
            match exp.native_digest {
                Some(want) => {
                    scope.check(Check::NativeDigestMatchesExpected);
                    if want.label != n.label || !want.digest.ct_eq(&n.digest) {
                        findings.push(Finding::new(
                            FindingCode::NativeDigestMismatch,
                            None,
                            "recorded native component digest is not the expected one",
                        ));
                    }
                }
                None => scope.limit(Limitation::NativeComponentNotVerified),
            }
        }
    }

    // Authorization.
    if let Some(a) = authorized {
        scope.limit(Limitation::CapabilitySignatureNotRechecked);
        match &a.use_evidence {
            None => scope.limit(Limitation::UseEvidenceNotRecorded),
            Some(UseEvidence::NotProvided) => scope.limit(Limitation::UseEvidenceNotProvidedByStore),
            Some(UseEvidence::NonDurableMemory) => scope.limit(Limitation::UseEvidenceNonDurable),
            Some(UseEvidence::Durable { position, .. } | UseEvidence::NoNewRecord { position, .. }) => {
                scope.check(Check::UseEvidenceWellFormed);
                if *position == 0 && matches!(a.use_evidence, Some(UseEvidence::Durable { .. })) {
                    findings.push(Finding::new(
                        FindingCode::UseEvidenceMalformed,
                        None,
                        "a durable use record cannot be at position 0",
                    ));
                }
            }
        }
        if let Some(p) = proposed {
            scope.check(Check::RosterComplete);
            match exp.roster_policy {
                Some(_) => scope.check(Check::RosterPolicy),
                None => scope.limit(Limitation::RosterPolicyNotSupplied),
            }
            for f in check_authorized_decision(&p.decision, exp.roster_policy) {
                findings.push(Finding::new(FindingCode::Decision(f), None, "decision relied on by Authorized"));
            }
            scope.check(Check::CapabilityBindingConsistent);
            if !a.capability.decision_root.ct_eq(&p.decision.root) {
                findings.push(Finding::new(
                    FindingCode::CapabilityDecisionRootMismatch,
                    None,
                    "capability decision root is not the proposal's",
                ));
            }
            if !a.capability.subject_digest.ct_eq(&p.subject.digest) {
                findings.push(Finding::new(
                    FindingCode::CapabilitySubjectMismatch,
                    None,
                    "capability subject digest is not the proposal's",
                ));
            }
            scope.check(Check::ActionConsistent);
            if a.action != p.action {
                findings.push(Finding::new(
                    FindingCode::AuthorizedActionDiffersFromProposed,
                    None,
                    "authorized operation or resource is not the proposed one",
                ));
            }
        }
        match exp.audience {
            Some(aud) => {
                scope.check(Check::Audience);
                if a.capability.audience != aud {
                    findings.push(Finding::new(
                        FindingCode::AudienceMismatch,
                        None,
                        "capability audience is not the expected one",
                    ));
                }
            }
            None => scope.limit(Limitation::AudienceNotSupplied),
        }
    }

    // The attempt.
    if let Some(at_) = attempted {
        match &at_.worker {
            None => scope.limit(Limitation::WorkerIdentityNotRecorded),
            Some(w) => {
                if exp.worker_image_sha256.is_none() && exp.worker_limits.is_none() {
                    scope.limit(Limitation::WorkerExpectationNotSupplied);
                }
                if let Some(want) = exp.worker_image_sha256 {
                    scope.check(Check::WorkerImageMatchesExpected);
                    if !want.ct_eq(&w.image_sha256) {
                        findings.push(Finding::new(
                            FindingCode::WorkerImageMismatch,
                            None,
                            "recorded worker image digest is not the expected one",
                        ));
                    }
                }
                if let Some(want) = exp.worker_limits {
                    scope.check(Check::WorkerLimitsMatchExpected);
                    if *want != w.limits {
                        findings.push(Finding::new(
                            FindingCode::WorkerLimitsMismatch,
                            None,
                            "recorded worker limits are not the expected ones",
                        ));
                    }
                }
            }
        }
        scope.check(Check::ActionConsistent);
        if let Some(a) = authorized {
            if at_.action.as_action() != a.action {
                findings.push(Finding::new(
                    FindingCode::ActualActionDiffersFromAuthorized,
                    None,
                    "attempted operation or resource is not the authorized one",
                ));
            }
        }
    }

    // The result.
    if let Some(t) = terminal {
        if matches!(t.outcome, Outcome::TerminationUnconfirmed { .. }) {
            findings.push(Finding::new(
                FindingCode::WorkerMayStillBeRunning,
                None,
                "termination was not confirmed; the worker may still be acting",
            ));
        }
        // The supervisor-observed facts (receipt format version 2). A version 1
        // terminal cannot show them: that is a limitation of the old receipt.
        match observed {
            None => scope.limit(Limitation::SupervisorObservedFactsNotRecorded),
            Some(o) => {
                scope.check(Check::ObservedFactsConsistentWithOutcome);
                if let Some(why) = observed_contradiction(&t.outcome, o) {
                    findings.push(Finding::new(FindingCode::ObservedFactsContradictOutcome, None, why));
                }
            }
        }
        if let Outcome::Completed { result_digest, .. } = &t.outcome {
            scope.limit(Limitation::ResultIsSelfReported);
            match exp.result_bytes {
                Some(bytes) => {
                    scope.check(Check::ResultDigestRecomputed);
                    let got = Digest32::from_bytes(Sha256::digest(bytes).into());
                    if !got.ct_eq(result_digest) {
                        findings.push(Finding::new(
                            FindingCode::ResultDigestMismatch,
                            None,
                            "supplied result bytes do not digest to the recorded result digest",
                        ));
                    }
                }
                None => scope.limit(Limitation::ResultBytesNotSupplied),
            }
        }
    }

    (summary, findings, scope)
}

/// Verifies the whole chain and judges one execution in it.
pub fn verify_receipt_chain(
    records: &[SignedRecord],
    execution_id: ExecutionId,
    trusted: &TrustedReceiptKeys,
    expectations: &Expectations<'_>,
) -> Verification {
    let (chain_findings, chain_scope) = verify_chain(records, trusted, expectations);
    let own: Vec<&SignedRecord> = records
        .iter()
        .filter(|s| s.record().execution_id == execution_id)
        .collect();
    let (summary, mut findings, mut scope) = verify_execution(execution_id, &own, expectations);
    scope.merge(&chain_scope);
    let mut all = chain_findings;
    all.append(&mut findings);
    let state = state_from(&all, &scope, !own.is_empty());
    Verification {
        state,
        execution: summary,
        scope,
        findings: all,
    }
}

/// Verifies the whole chain and every execution in it.
pub fn verify_log(records: &[SignedRecord], trusted: &TrustedReceiptKeys, expectations: &Expectations<'_>) -> LogVerification {
    let (chain_findings, mut scope) = verify_chain(records, trusted, expectations);
    let mut by_id: BTreeMap<ExecutionId, Vec<&SignedRecord>> = BTreeMap::new();
    let mut order = Vec::new();
    for s in records {
        let id = s.record().execution_id;
        if !by_id.contains_key(&id) {
            order.push(id);
        }
        by_id.entry(id).or_default().push(s);
    }
    let mut executions = Vec::with_capacity(order.len());
    let mut worst = state_from(&chain_findings, &scope, !records.is_empty());
    for id in order {
        let own = by_id.get(&id).map(Vec::as_slice).unwrap_or(&[]);
        let (summary, findings, exec_scope) = verify_execution(id, own, expectations);
        let mut full_scope = exec_scope.clone();
        full_scope.merge(&scope);
        let mut all = chain_findings.clone();
        all.extend(findings.iter().cloned());
        let state = state_from(&all, &full_scope, true);
        scope.merge(&exec_scope);
        worst = worse(worst, state);
        executions.push(Verification {
            state,
            execution: summary,
            scope: full_scope,
            findings: all,
        });
    }
    LogVerification {
        state: worst,
        findings: chain_findings,
        scope,
        executions,
    }
}

/// Parses log bytes and verifies them. A log that does not parse is
/// REJECTED; a torn tail is ignored and reported.
pub fn verify_log_bytes(bytes: &[u8], trusted: &TrustedReceiptKeys, expectations: &Expectations<'_>) -> LogVerification {
    match parse_log(bytes) {
        Ok(parsed) => {
            let mut v = verify_log(&parsed.records, trusted, expectations);
            if parsed.discarded_tail_bytes > 0 {
                v.findings.push(Finding::new(
                    FindingCode::TornTailDiscarded,
                    None,
                    format!("{} unacknowledged bytes ignored", parsed.discarded_tail_bytes),
                ));
                v.scope.limit(Limitation::TornTailIgnored);
                for e in &mut v.executions {
                    e.scope.limit(Limitation::TornTailIgnored);
                }
            }
            if parsed.adopted_tail {
                v.findings.push(Finding::new(
                    FindingCode::TrailingFrameAdopted,
                    None,
                    "a complete unacknowledged frame was adopted",
                ));
            }
            v
        }
        Err(e) => {
            let detail = match &e {
                LogError::Corrupt { detail, .. } => (*detail).to_owned(),
                other => other.to_string(),
            };
            let findings = vec![Finding::new(FindingCode::LogCorrupt, None, detail)];
            LogVerification {
                state: State::Rejected,
                findings,
                scope: Scope::default(),
                executions: Vec::new(),
            }
        }
    }
}

const fn rank(s: State) -> u8 {
    match s {
        State::Verified => 0,
        State::VerifiedWithLimitations => 1,
        State::Unknown => 2,
        State::Incomplete => 3,
        State::Rejected => 4,
    }
}

const fn worse(a: State, b: State) -> State {
    if rank(a) >= rank(b) {
        a
    } else {
        b
    }
}

// ---------------------------------------------------------------------------
// JSON rendering, so a consumer gets structure and not a bare word.
// ---------------------------------------------------------------------------

fn json_str(out: &mut String, s: &str) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => {
                out.push_str(&format!("\\u{:04x}", c as u32));
            }
            c => out.push(c),
        }
    }
    out.push('"');
}

fn json_findings(out: &mut String, findings: &[Finding]) {
    out.push('[');
    for (i, f) in findings.iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        out.push_str("{\"code\":");
        json_str(out, f.code.as_str());
        out.push_str(",\"severity\":");
        json_str(
            out,
            match f.code.severity() {
                Severity::Reject => "reject",
                Severity::Incomplete => "incomplete",
                Severity::Info => "info",
            },
        );
        out.push_str(",\"sequence\":");
        match f.sequence {
            Some(s) => out.push_str(&s.to_string()),
            None => out.push_str("null"),
        }
        out.push_str(",\"detail\":");
        json_str(out, &f.detail);
        out.push('}');
    }
    out.push(']');
}

fn json_scope(out: &mut String, scope: &Scope) {
    out.push_str("{\"checked\":[");
    for (i, c) in scope.checked.iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        json_str(out, c.as_str());
    }
    out.push_str("],\"not_checked\":[");
    for (i, l) in scope.not_checked.iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        json_str(out, l.as_str());
    }
    out.push_str("]}");
}

impl Verification {
    /// A JSON object: `state`, `execution` (`execution_id`,
    /// `stage_reached`, `outcome`, `sequences`), `scope` (`checked`,
    /// `not_checked`), `findings` (`code`, `severity`, `sequence`, `detail`).
    pub fn to_json(&self) -> String {
        let mut out = String::new();
        self.write_json(&mut out);
        out
    }

    fn write_json(&self, out: &mut String) {
        out.push_str("{\"state\":");
        json_str(out, self.state.as_str());
        out.push_str(",\"execution\":{\"execution_id\":");
        json_str(out, &self.execution.execution_id.to_hex());
        out.push_str(",\"stage_reached\":");
        match self.execution.stage_reached {
            Some(s) => json_str(out, s.as_str()),
            None => out.push_str("null"),
        }
        out.push_str(",\"outcome\":");
        match self.execution.outcome {
            Some(o) => json_str(out, o.as_str()),
            None => out.push_str("null"),
        }
        out.push_str(",\"sequences\":[");
        for (i, s) in self.execution.sequences.iter().enumerate() {
            if i > 0 {
                out.push(',');
            }
            out.push_str(&s.to_string());
        }
        out.push_str("]},\"scope\":");
        json_scope(out, &self.scope);
        out.push_str(",\"findings\":");
        json_findings(out, &self.findings);
        out.push('}');
    }
}

impl LogVerification {
    /// A JSON object: `state`, `scope`, `findings`, `executions` (each as
    /// [`Verification::to_json`]).
    pub fn to_json(&self) -> String {
        let mut out = String::from("{\"state\":");
        json_str(&mut out, self.state.as_str());
        out.push_str(",\"scope\":");
        json_scope(&mut out, &self.scope);
        out.push_str(",\"findings\":");
        json_findings(&mut out, &self.findings);
        out.push_str(",\"executions\":[");
        for (i, e) in self.executions.iter().enumerate() {
            if i > 0 {
                out.push(',');
            }
            e.write_json(&mut out);
        }
        out.push_str("]}");
        out
    }
}
