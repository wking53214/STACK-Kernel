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
use stack_authority::Digest32;

use crate::cns::{subject_digest, CnsValue};
use crate::decision::{check_authorized_decision, DecisionFinding, RosterPolicy};
use crate::encode::genesis_hash;
use crate::log::{parse_log, LogError};
use crate::record::{Event, ExecutionId, Outcome, OutcomeKind, Stage};
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
    /// A torn frame was discarded (informational).
    TornTailDiscarded,
    /// A complete unacknowledged frame was adopted (informational).
    TrailingFrameAdopted,
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
            | Self::WorkerMayStillBeRunning => Severity::Info,
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
            Self::TornTailDiscarded => "torn_tail_discarded",
            Self::TrailingFrameAdopted => "trailing_frame_adopted",
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
    if records.is_empty() {
        findings.push(Finding::new(FindingCode::EmptyLog, None, "no records"));
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
    (findings, scope)
}

/// The order of stages for "furthest stage reached".
const fn stage_rank(s: Stage) -> u8 {
    match s {
        Stage::Proposed => 0,
        Stage::Authorized => 1,
        Stage::Attempted => 2,
        Stage::Rejected | Stage::Terminal => 3,
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
    for s in records {
        let r = s.record();
        let seq = Some(r.sequence);
        let stage = r.stage();
        if summary.stage_reached.is_none_or(|prev| stage_rank(stage) > stage_rank(prev)) {
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
                    Event::Attempted(a) => {
                        findings.push(Finding::new(FindingCode::AttemptedWithoutAuthorized, seq, "no Authorized"));
                        attempted = Some(a);
                        at = At::Attempted;
                    }
                    Event::Terminal(t) => {
                        findings.push(Finding::new(FindingCode::TerminalWithoutAttempted, seq, "no Attempted"));
                        terminal = Some(t);
                        at = At::Closed;
                    }
                    Event::Proposed(_) => {}
                }
            }
            (_, At::Closed) => {
                let code = if matches!(r.event, Event::Terminal(_) | Event::Rejected(_)) {
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
            (Event::Attempted(a), At::Authorized) => {
                attempted = Some(a);
                at = At::Attempted;
            }
            (Event::Attempted(a), At::Proposed) => {
                findings.push(Finding::new(FindingCode::AttemptedWithoutAuthorized, seq, "no Authorized"));
                attempted = Some(a);
                at = At::Attempted;
            }
            (Event::Terminal(t), At::Attempted) => {
                terminal = Some(t);
                at = At::Closed;
            }
            (Event::Terminal(t), At::Proposed | At::Authorized) => {
                findings.push(Finding::new(FindingCode::TerminalWithoutAttempted, seq, "no Attempted"));
                terminal = Some(t);
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
        (At::Closed, None) => summary.outcome = None,
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
        if p.native_digest.is_some() {
            scope.limit(Limitation::NativeComponentNotVerified);
        }
    }

    // Authorization.
    if let Some(a) = authorized {
        scope.limit(Limitation::CapabilitySignatureNotRechecked);
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
