//! The receipt record: one event in the life of one execution, with every
//! field a verifier needs to judge the evidence later.
//!
//! A record is evidence, never authority. It says what the kernel observed
//! and what it believed authorized the action; it grants nothing, and a
//! consumer that treats a `Completed` record as permission has misread it.
//!
//! Every field is public and every record is constructible by anyone: the
//! verifier defends against hostile records, and the typestate recorder
//! (`recorder`) exists so the honest kernel cannot write them in the wrong
//! order. The validation here bounds every string and count so that the
//! canonical encoding is total on a valid record and a decoder can refuse
//! anything else.

use std::fmt;

use stack_authority::{AuthorizedAction, Digest32, UseEvidence};

/// Longest identifier (kernel, issuer, capability, audience, component,
/// version, host, seat, gate), in bytes.
pub const MAX_ID_BYTES: usize = 128;
/// Longest free text (reason, resource, subject identity, verdict subject
/// or digest, policy reference, native digest label), in bytes.
pub const MAX_TEXT_BYTES: usize = 1024;
/// Longest operation name, in bytes. Matches `stack-authority`.
pub const MAX_OPERATION_BYTES: usize = 64;
/// Most seats on a roster, and most verdicts in a decision.
pub const MAX_SEATS: usize = 64;
/// Bytes of an execution id.
pub const EXECUTION_ID_BYTES: usize = 16;

/// Which field a validation refused.
pub type FieldName = &'static str;

/// Why a field was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum Problem {
    /// A required field is empty.
    #[error("empty")]
    Empty,
    /// Longer than the bound for its kind.
    #[error("longer than {max} bytes")]
    TooLong {
        /// The bound.
        max: usize,
    },
    /// Holds a character below U+0020 or U+007F.
    #[error("control character")]
    ControlCharacter,
    /// A list holds more entries than its bound.
    #[error("more than {max} entries")]
    TooMany {
        /// The bound.
        max: usize,
    },
}

/// A record field that breaks the rules in this module.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("{field}: {problem}")]
pub struct ValidationError {
    /// The field.
    pub field: FieldName,
    /// What is wrong with it.
    pub problem: Problem,
}

/// Whether `c` is a control character under the identifier rules.
pub fn is_control(c: char) -> bool {
    c < '\u{20}' || c == '\u{7f}'
}

/// Checks a string field: `min` (0 or 1) to `max` bytes, no control
/// character.
pub fn check_text(field: FieldName, s: &str, min: usize, max: usize) -> Result<(), ValidationError> {
    if s.len() < min {
        return Err(ValidationError {
            field,
            problem: Problem::Empty,
        });
    }
    if s.len() > max {
        return Err(ValidationError {
            field,
            problem: Problem::TooLong { max },
        });
    }
    if s.chars().any(is_control) {
        return Err(ValidationError {
            field,
            problem: Problem::ControlCharacter,
        });
    }
    Ok(())
}

fn check_id(field: FieldName, s: &str) -> Result<(), ValidationError> {
    check_text(field, s, 1, MAX_ID_BYTES)
}

/// The identity of one execution: 16 bytes chosen by the kernel, written
/// as 32 lowercase hex characters. A label, never a secret.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ExecutionId([u8; EXECUTION_ID_BYTES]);

impl ExecutionId {
    /// Wraps raw bytes.
    pub const fn from_bytes(bytes: [u8; EXECUTION_ID_BYTES]) -> Self {
        Self(bytes)
    }

    /// Parses exactly 32 lowercase hex characters.
    pub fn from_hex(s: &str) -> Option<Self> {
        stack_authority::digest::decode_hex_lower::<EXECUTION_ID_BYTES>(s).map(Self)
    }

    /// The 32-character lowercase hex form.
    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }

    /// The raw bytes.
    pub const fn as_bytes(&self) -> &[u8; EXECUTION_ID_BYTES] {
        &self.0
    }
}

impl fmt::Debug for ExecutionId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ExecutionId({})", self.to_hex())
    }
}

impl fmt::Display for ExecutionId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_hex())
    }
}

/// The id of the receipt key that signed a record: the full SHA-256 of
/// the public key under a domain tag (`sign::RECEIPT_KEY_ID_DOMAIN`). A
/// label for lookup in the trusted set, not a MAC and not a secret.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ReceiptKeyId([u8; 32]);

impl ReceiptKeyId {
    /// Wraps raw bytes, as read from a record.
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Parses exactly 64 lowercase hex characters.
    pub fn from_hex(s: &str) -> Option<Self> {
        Digest32::from_hex(s).map(|d| Self(*d.as_bytes()))
    }

    /// The 64-character lowercase hex form.
    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }

    /// The raw bytes.
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Debug for ReceiptKeyId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ReceiptKeyId({})", self.to_hex())
    }
}

impl fmt::Display for ReceiptKeyId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_hex())
    }
}

/// Who produced the evidence: the component, its version and the host.
/// Claims by the writer; a verifier cannot check them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Provenance {
    /// Component name, such as `stack-kernel`.
    pub component: String,
    /// Component version.
    pub version: String,
    /// Host identifier.
    pub host_id: String,
}

impl Provenance {
    /// Checks the three identifiers.
    pub fn validate(&self) -> Result<(), ValidationError> {
        check_id("provenance.component", &self.component)?;
        check_id("provenance.version", &self.version)?;
        check_id("provenance.host_id", &self.host_id)
    }
}

/// What a decision was about: the CNS subject identity and digest, as the
/// enforcement boundary recomputed them from the content.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Subject {
    /// Which document, in the producer's own naming.
    pub identity: String,
    /// `cns.gate.subject_digest` of the content.
    pub digest: Digest32,
}

impl Subject {
    /// Checks the identity.
    pub fn validate(&self) -> Result<(), ValidationError> {
        check_text("subject.identity", &self.identity, 1, MAX_TEXT_BYTES)
    }
}

/// A CNS gate position, spelled as CNS spells it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum GatePosition {
    /// Runs before execution; a failure means the work never starts.
    Alpha,
    /// Runs on the produced result.
    Omega,
}

impl GatePosition {
    /// The CNS spelling, which the decision root renders.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Alpha => "alpha",
            Self::Omega => "omega",
        }
    }

    /// Parses the CNS spelling.
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "alpha" => Some(Self::Alpha),
            "omega" => Some(Self::Omega),
            _ => None,
        }
    }
}

/// A CNS gate outcome, spelled as CNS spells it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum GateOutcome {
    /// The gate passed.
    Pass,
    /// The gate asks for a corrected resubmission.
    Retry,
    /// The gate refused and nothing may proceed.
    TerminalBreach,
}

impl GateOutcome {
    /// The CNS spelling, which the decision root renders.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Pass => "pass",
            Self::Retry => "retry",
            Self::TerminalBreach => "terminal_breach",
        }
    }

    /// Parses the CNS spelling.
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "pass" => Some(Self::Pass),
            "retry" => Some(Self::Retry),
            "terminal_breach" => Some(Self::TerminalBreach),
            _ => None,
        }
    }
}

/// One gate's verdict, exactly as CNS renders it into the decision root
/// (`cns_composition.super_gate._verdict`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Verdict {
    /// The gate's name (without its repository).
    pub gate: String,
    /// The gate's end.
    pub position: GatePosition,
    /// What it said.
    pub outcome: GateOutcome,
    /// What it judged, or empty for an unbound verdict.
    pub subject: String,
    /// The digest of what it judged, or empty for an unbound verdict.
    pub digest: String,
}

impl Verdict {
    /// Checks the strings.
    pub fn validate(&self) -> Result<(), ValidationError> {
        check_id("verdict.gate", &self.gate)?;
        check_text("verdict.subject", &self.subject, 0, MAX_TEXT_BYTES)?;
        check_text("verdict.digest", &self.digest, 0, MAX_TEXT_BYTES)
    }

    /// Whether the verdict records what it judged (`GateResult.bound`).
    pub fn is_bound(&self) -> bool {
        !self.subject.is_empty() && !self.digest.is_empty()
    }
}

/// The governing CNS decision: its root and everything the root is
/// computed from, so a verifier recomputes it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecisionEvidence {
    /// `Decision.root` as CNS computed it.
    pub root: Digest32,
    /// `Decision.seats`, in order, as `repository:gate`.
    pub seats: Vec<String>,
    /// `Decision.run.results`, in order.
    pub verdicts: Vec<Verdict>,
}

impl DecisionEvidence {
    /// Checks counts and strings. An empty roster is valid here and is a
    /// verifier finding, because the record must be able to carry what a
    /// hostile producer wrote.
    pub fn validate(&self) -> Result<(), ValidationError> {
        if self.seats.len() > MAX_SEATS {
            return Err(ValidationError {
                field: "decision.seats",
                problem: Problem::TooMany { max: MAX_SEATS },
            });
        }
        if self.verdicts.len() > MAX_SEATS {
            return Err(ValidationError {
                field: "decision.verdicts",
                problem: Problem::TooMany { max: MAX_SEATS },
            });
        }
        for seat in &self.seats {
            check_id("decision.seat", seat)?;
        }
        for v in &self.verdicts {
            v.validate()?;
        }
        Ok(())
    }
}

/// An operation on a resource, as proposed or as authorized.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Action {
    /// The operation, by exact name.
    pub operation: String,
    /// The resource path.
    pub resource: String,
}

impl Action {
    /// Checks both strings.
    pub fn validate(&self, field: FieldName) -> Result<(), ValidationError> {
        check_text(field, &self.operation, 1, MAX_OPERATION_BYTES)?;
        check_text(field, &self.resource, 1, MAX_TEXT_BYTES)
    }
}

/// The action the kernel intends to run: operation, resource and the digest
/// of the argument bytes it intends to pass. Intent, not delivery: today's
/// executor hands neither the resource nor the arguments to the worker
/// (R2-X-02).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ActualAction {
    /// The operation run.
    pub operation: String,
    /// The resource acted on.
    pub resource: String,
    /// SHA-256 of the argument bytes the producer says it intended to pass.
    /// Whether the executor delivered them to the worker is NOT established
    /// by this field: the supervised executor in this repository does not
    /// deliver arguments today (defect R2-X-02), so a consumer must not read
    /// this as proof of what the worker received.
    pub argument_digest: Digest32,
}

impl ActualAction {
    /// Checks the strings.
    pub fn validate(&self) -> Result<(), ValidationError> {
        check_text("attempted.action", &self.operation, 1, MAX_OPERATION_BYTES)?;
        check_text("attempted.action", &self.resource, 1, MAX_TEXT_BYTES)
    }

    /// The operation and resource, for comparison with an [`Action`].
    pub fn as_action(&self) -> Action {
        Action {
            operation: self.operation.clone(),
            resource: self.resource.clone(),
        }
    }
}

/// The Trident profile that accepted the handoff. Mirrors
/// `stack_trident::Assurance` without depending on that crate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Assurance {
    /// Accepted by a development-profile Trident.
    Development,
    /// Accepted by a production-profile Trident.
    Production,
}

impl Assurance {
    /// Log spelling.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Development => "development",
            Self::Production => "production",
        }
    }
}

/// Where the request came from: the Trident handoff that admitted it.
/// Copied from the verified handoff; a verifier cannot recheck the MAC.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Handoff {
    /// Authenticated sender key fingerprint.
    pub sender_fingerprint: [u8; 32],
    /// The audience the envelope named.
    pub audience: String,
    /// The envelope's sequence.
    pub sequence: u64,
    /// The envelope's nonce.
    pub nonce: [u8; 16],
    /// The accepting Trident's profile.
    pub assurance: Assurance,
}

impl Handoff {
    /// Checks the audience.
    pub fn validate(&self) -> Result<(), ValidationError> {
        check_id("handoff.audience", &self.audience)
    }
}

/// An opaque digest from the producer's own component, such as a Sentinel
/// ledger row hash. Carried beside the CNS digest, never in place of it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NativeDigest {
    /// What the digest is, in the producer's words.
    pub label: String,
    /// The digest.
    pub digest: Digest32,
}

impl NativeDigest {
    /// Checks the label.
    pub fn validate(&self) -> Result<(), ValidationError> {
        check_text("native_digest.label", &self.label, 1, MAX_TEXT_BYTES)
    }
}

/// Everything `stack-authority` established when it authorized the action.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CapabilityBinding {
    /// Digest of the capability that authorized the action.
    pub cap_digest: Digest32,
    /// The capability's id.
    pub cap_id: String,
    /// The issuer that signed it.
    pub issuer_id: String,
    /// The issuer key id it was signed under (`stack-authority` key id).
    pub issuer_key_id: Digest32,
    /// The policy reference the capability carried.
    pub policy_ref: String,
    /// The verifier that authorized the action.
    pub audience: String,
    /// The content the capability was issued about.
    pub subject_digest: Digest32,
    /// The decision the capability was issued under.
    pub decision_root: Digest32,
    /// Whether the capability was consumed by this authorization.
    pub one_time: bool,
    /// The verifier's clock when it authorized.
    pub authorized_at_ms: u64,
}

impl CapabilityBinding {
    /// Checks the strings.
    pub fn validate(&self) -> Result<(), ValidationError> {
        check_id("capability.cap_id", &self.cap_id)?;
        check_id("capability.issuer_id", &self.issuer_id)?;
        check_text("capability.policy_ref", &self.policy_ref, 0, MAX_TEXT_BYTES)?;
        check_id("capability.audience", &self.audience)
    }
}

impl From<&AuthorizedAction> for CapabilityBinding {
    fn from(a: &AuthorizedAction) -> Self {
        Self {
            cap_digest: Digest32::from_bytes(*a.cap_digest().as_bytes()),
            cap_id: a.cap_id().to_owned(),
            issuer_id: a.issuer_id().to_owned(),
            issuer_key_id: Digest32::from_bytes(*a.key_id().as_bytes()),
            policy_ref: a.policy_ref().to_owned(),
            audience: a.audience().to_owned(),
            subject_digest: *a.subject_digest(),
            decision_root: *a.decision_root(),
            one_time: a.one_time(),
            authorized_at_ms: a.authorized_at_ms(),
        }
    }
}

/// How a run ended. One variant per outcome the supervised executor
/// reports (`stack_ffi::SupervisedOutcome`), plus `Terminated` and
/// `TerminationUnconfirmed` for a worker the kernel itself killed,
/// `Interrupted` for a run the kernel stopped before any kill, and
/// `Unknown` for a run whose end the kernel could not observe. Nothing
/// here is success except `Completed`, and `Completed` is a claim the
/// verifier checks against the surrounding events, not a grant.
///
/// `Completed` means exactly: the worker exited 0 within the deadline
/// and sent a well-formed result frame. The result bytes are the
/// worker's own claim: a hostile worker can forge a well-formed result,
/// and nothing in the receipt can tell a forged result from a genuine
/// one. `result_digest` is therefore recorded as SELF-REPORTED, and the
/// verifier lists it as such even when the auditor supplies the bytes
/// and they match.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    /// Exit 0 within the deadline with a well-formed result frame. The
    /// result is self-reported by the worker; see the enum documentation.
    Completed {
        /// The exit status.
        exit_code: i32,
        /// SHA-256 of the result bytes the worker sent (self-reported).
        result_digest: Digest32,
    },
    /// The kernel sent the worker a termination signal and confirmed it
    /// dead (reaped).
    Terminated {
        /// The signal sent.
        signal: i32,
    },
    /// The kernel sent the worker a termination signal and could NOT
    /// confirm it dead. The worker may still be running and acting; a
    /// consumer must treat the action as possibly still in progress.
    TerminationUnconfirmed {
        /// What the kernel knows.
        reason: String,
    },
    /// The wall-clock deadline passed; the child was killed.
    TimedOut,
    /// Ended by a signal other than SIGSYS, SIGXCPU or SIGXFSZ.
    Crashed {
        /// The signal.
        signal: i32,
    },
    /// Ended by SIGSYS: the seccomp filter killed it.
    SeccompViolation {
        /// The signal.
        signal: i32,
    },
    /// Ended by SIGXCPU or SIGXFSZ.
    ResourceLimit {
        /// The signal.
        signal: i32,
    },
    /// Exit 0 but no complete, valid result frame.
    ResultMissing {
        /// The exit status.
        exit_code: i32,
    },
    /// Exited with a non-zero status.
    ExitedNonZero {
        /// The exit status.
        exit_code: i32,
    },
    /// The result frame announced more than the cap.
    ResultOversized,
    /// The kernel stopped the run deliberately (shutdown, operator).
    Interrupted {
        /// Why.
        reason: String,
    },
    /// The kernel cannot say how the run ended (supervisor error, spawn
    /// failure, limits refused after the attempt was recorded).
    Unknown {
        /// What the kernel does know.
        reason: String,
    },
}

/// The kind of an [`Outcome`], without its fields.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum OutcomeKind {
    /// See [`Outcome::Completed`].
    Completed,
    /// See [`Outcome::Terminated`].
    Terminated,
    /// See [`Outcome::TerminationUnconfirmed`].
    TerminationUnconfirmed,
    /// See [`Outcome::TimedOut`].
    TimedOut,
    /// See [`Outcome::Crashed`].
    Crashed,
    /// See [`Outcome::SeccompViolation`].
    SeccompViolation,
    /// See [`Outcome::ResourceLimit`].
    ResourceLimit,
    /// See [`Outcome::ResultMissing`].
    ResultMissing,
    /// See [`Outcome::ExitedNonZero`].
    ExitedNonZero,
    /// See [`Outcome::ResultOversized`].
    ResultOversized,
    /// See [`Outcome::Interrupted`].
    Interrupted,
    /// See [`Outcome::Unknown`].
    Unknown,
}

impl OutcomeKind {
    /// Machine-readable spelling.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Completed => "completed",
            Self::Terminated => "terminated",
            Self::TerminationUnconfirmed => "termination_unconfirmed",
            Self::TimedOut => "timed_out",
            Self::Crashed => "crashed",
            Self::SeccompViolation => "seccomp_violation",
            Self::ResourceLimit => "resource_limit",
            Self::ResultMissing => "result_missing",
            Self::ExitedNonZero => "exited_non_zero",
            Self::ResultOversized => "result_oversized",
            Self::Interrupted => "interrupted",
            Self::Unknown => "unknown",
        }
    }
}

impl OutcomeKind {
    /// The campaign vocabulary name (D1-C). Additive: no existing name changes
    /// (`as_str` is untouched). Several existing outcomes share a campaign
    /// name, and `RUNNING`, `PROPOSED`, `AUTHORIZED`, `REJECTED` and `ATTEMPTED`
    /// are stages or in-memory states, not terminal outcomes (RECEIPT.md).
    pub const fn campaign_name(self) -> &'static str {
        match self {
            Self::Completed => "COMPLETED",
            Self::Terminated => "TERMINATED",
            Self::TerminationUnconfirmed => "TERMINATION_UNCONFIRMED",
            Self::TimedOut => "TIMED_OUT",
            Self::Crashed | Self::SeccompViolation | Self::ResourceLimit | Self::ExitedNonZero => "CRASHED",
            Self::ResultMissing | Self::ResultOversized => "RESULT_INVALID",
            Self::Interrupted => "INTERRUPTED",
            Self::Unknown => "UNKNOWN",
        }
    }
}

impl Outcome {
    /// The kind.
    pub const fn kind(&self) -> OutcomeKind {
        match self {
            Self::Completed { .. } => OutcomeKind::Completed,
            Self::Terminated { .. } => OutcomeKind::Terminated,
            Self::TerminationUnconfirmed { .. } => OutcomeKind::TerminationUnconfirmed,
            Self::TimedOut => OutcomeKind::TimedOut,
            Self::Crashed { .. } => OutcomeKind::Crashed,
            Self::SeccompViolation { .. } => OutcomeKind::SeccompViolation,
            Self::ResourceLimit { .. } => OutcomeKind::ResourceLimit,
            Self::ResultMissing { .. } => OutcomeKind::ResultMissing,
            Self::ExitedNonZero { .. } => OutcomeKind::ExitedNonZero,
            Self::ResultOversized => OutcomeKind::ResultOversized,
            Self::Interrupted { .. } => OutcomeKind::Interrupted,
            Self::Unknown { .. } => OutcomeKind::Unknown,
        }
    }

    /// Checks the reason strings.
    pub fn validate(&self) -> Result<(), ValidationError> {
        match self {
            Self::Interrupted { reason } | Self::Unknown { reason } | Self::TerminationUnconfirmed { reason } => {
                check_text("terminal.reason", reason, 1, MAX_TEXT_BYTES)
            }
            _ => Ok(()),
        }
    }
}

/// The request as it arrived, before any authorization.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Proposed {
    /// What it is about.
    pub subject: Subject,
    /// The decision it arrived under.
    pub decision: DecisionEvidence,
    /// What it asks to do.
    pub action: Action,
    /// Where it came from, when it came through a Trident.
    pub handoff: Option<Handoff>,
    /// The producer's own digest of its record, when it has one.
    pub native_digest: Option<NativeDigest>,
}

/// The authorization `stack-authority` granted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Authorized {
    /// What authorized it.
    pub capability: CapabilityBinding,
    /// The operation and resource authorized.
    pub action: Action,
    /// What the use store returned when it recorded the capability's use
    /// (receipt format version 2). `None` is a version 1 record, which cannot
    /// show it; the verifier lists that as a limitation. Present means the
    /// record is written under the version 2 tag.
    pub use_evidence: Option<UseEvidence>,
}

/// The kernel refused to execute. Terminal.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rejected {
    /// Why, in the kernel's words.
    pub reason: String,
}

/// Written before the payload starts: the kernel intends to run this. It
/// is not proof of what the worker was given (R2-X-02).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Attempted {
    /// What the kernel intends to run.
    pub action: ActualAction,
    /// Wall clock at the start.
    pub started_at_ms: u64,
    /// The worker image and the limits the supervisor was given (receipt
    /// format version 2). `None` is a version 1 record, which cannot show
    /// them. Present means the record is written under the version 2 tag.
    pub worker: Option<WorkerBinding>,
}

/// The limits the kernel handed the supervisor for one run, recorded
/// explicitly so a verifier can state under which limits the worker ran. A
/// zero `cpu_seconds` or `nofile` means the supervisor derived the value; the
/// derived value is not reported back and is not in the record.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AppliedLimits {
    /// Wall-clock deadline in nanoseconds (exact, not rounded).
    pub wall_clock_deadline_ns: u64,
    /// `RLIMIT_CPU` seconds; 0 means derived by the supervisor.
    pub cpu_seconds: u64,
    /// `RLIMIT_AS` bytes.
    pub address_space_bytes: u64,
    /// Largest accepted result in bytes.
    pub max_output_bytes: u64,
    /// `RLIMIT_FSIZE` bytes; 0 forbids regular-file writes.
    pub file_size_bytes: u64,
    /// `RLIMIT_NOFILE`; 0 means the supervisor's derived floor.
    pub nofile: u32,
}

impl AppliedLimits {
    /// The deadline in whole milliseconds, rounded up.
    pub const fn wall_clock_deadline_ms(&self) -> u64 {
        self.wall_clock_deadline_ns.div_ceil(1_000_000)
    }
}

/// Which worker program ran and under which limits: the SHA-256 the
/// supervisor pinned and verified before exec, and the limits it was given.
/// Kept apart from every other digest in the record.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WorkerBinding {
    /// SHA-256 of the worker image, the digest the supervisor pinned and
    /// verified against the file it executed.
    pub image_sha256: Digest32,
    /// The limits the supervisor was given.
    pub limits: AppliedLimits,
}

/// How the run ended. Terminal.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Terminal {
    /// The outcome.
    pub outcome: Outcome,
    /// Wall clock at the end.
    pub completed_at_ms: u64,
    /// Monotonic elapsed time of the run.
    pub elapsed_ns: u64,
}

/// How the supervisor saw the worker process end (receipt format version 2).
/// Observed from the wait status and from the supervisor's own kill; no byte
/// the worker wrote can set it. The values mirror `stack_ffi::ExitObserved`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExitObserved {
    /// No process was started, or its end was not observed.
    NotObserved,
    /// The worker called exit with this status.
    Exited {
        /// The exit status.
        code: i32,
    },
    /// The worker was ended by this signal and the supervisor did not send it.
    Signaled {
        /// The signal.
        signal: i32,
    },
    /// The supervisor sent SIGKILL (deadline, oversized result, cancel) and
    /// the worker ended by it.
    KilledBySupervisor {
        /// The signal, 9.
        signal: i32,
    },
    /// SIGKILL was sent and the worker was not reaped in time.
    Unreaped,
}

/// What the supervisor made of the worker's result pipe (receipt format
/// version 2). Well-formedness only; the result bytes are never interpreted.
/// `Valid` says one well-formed frame arrived, not that the run succeeded and
/// not that the result is true.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FrameStatus {
    /// The pipe was not evaluated.
    NotRead,
    /// Exactly one complete, well-formed frame and nothing after it.
    Valid,
    /// No byte arrived.
    Missing,
    /// Bytes arrived but no complete well-formed frame.
    Malformed,
    /// The header announced more than the result cap.
    Oversized,
    /// One good frame, then bytes that are not a second complete frame.
    Trailing,
    /// Two or more complete frames.
    Conflicting,
}

/// The two supervisor-observed facts a version 2 terminal event carries.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Observed {
    /// How the process ended, as the supervisor saw it.
    pub exit: ExitObserved,
    /// What the supervisor made of the result pipe.
    pub frame: FrameStatus,
}

impl Observed {
    /// True exactly when these facts are the ones `Completed` requires: the
    /// supervisor saw the worker exit 0 and held one well-formed frame.
    pub const fn supports_completed(&self) -> bool {
        matches!(self.exit, ExitObserved::Exited { code: 0 }) && matches!(self.frame, FrameStatus::Valid)
    }
}

/// A terminal event with the supervisor-observed facts (receipt format
/// version 2, record tag `stack-receipt/2`). A terminal event without them is
/// [`Event::Terminal`], format version 1, and stays byte-for-byte what it was.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TerminalObserved {
    /// The terminal event, exactly as in version 1.
    pub terminal: Terminal,
    /// What the supervisor observed.
    pub observed: Observed,
}

/// The last stage an execution reached before a restart found it open. Only
/// the three stages an open execution can be at.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LastStage {
    /// The request was recorded; nothing was decided.
    Proposed,
    /// The authorization was recorded; nothing ran.
    Authorized,
    /// The attempt was recorded; the payload may have started.
    Attempted,
}

impl LastStage {
    /// Machine-readable spelling.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Proposed => "proposed",
            Self::Authorized => "authorized",
            Self::Attempted => "attempted",
        }
    }
}

/// A restarted kernel's statement that it found this execution open and
/// closed it in the log without knowing how it ended. It claims nothing about
/// the run: if the last stage was `Attempted`, the payload may have run to
/// completion, may have been cut off, or may never have started, and the
/// outcome stays unknown. Format version 3. Written by the kernel's recovery
/// step before it accepts new work, never by the verifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Recovered {
    /// The last record of the execution that the restart found.
    pub last_stage: LastStage,
}

/// One event in an execution's life.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Event {
    /// See [`Proposed`].
    Proposed(Proposed),
    /// See [`Authorized`].
    Authorized(Authorized),
    /// See [`Rejected`].
    Rejected(Rejected),
    /// See [`Attempted`].
    Attempted(Attempted),
    /// See [`Terminal`]. Format version 1.
    Terminal(Terminal),
    /// See [`TerminalObserved`]. Format version 2; stage [`Stage::Terminal`].
    TerminalObserved(TerminalObserved),
    /// See [`Recovered`]. Format version 3.
    Recovered(Recovered),
}

impl Event {
    /// The terminal event and, for format version 2, the observed facts.
    pub const fn terminal_parts(&self) -> Option<(&Terminal, Option<&Observed>)> {
        match self {
            Self::Terminal(t) => Some((t, None)),
            Self::TerminalObserved(t) => Some((&t.terminal, Some(&t.observed))),
            _ => None,
        }
    }
}

/// The stage an event belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Stage {
    /// See [`Proposed`].
    Proposed,
    /// See [`Authorized`].
    Authorized,
    /// See [`Rejected`].
    Rejected,
    /// See [`Attempted`].
    Attempted,
    /// See [`Terminal`].
    Terminal,
    /// See [`Recovered`].
    Recovered,
}

impl Stage {
    /// Machine-readable spelling.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Proposed => "proposed",
            Self::Authorized => "authorized",
            Self::Rejected => "rejected",
            Self::Attempted => "attempted",
            Self::Terminal => "terminal",
            Self::Recovered => "recovered",
        }
    }
}

impl Event {
    /// Whether this event is written under the version 2 tag: the observed
    /// terminal, an `Authorized` that carries use evidence, and an
    /// `Attempted` that carries a worker binding. Every other event, and these
    /// without their additions, are version 1 and encode as they always did.
    pub const fn is_v2(&self) -> bool {
        match self {
            Self::TerminalObserved(_) => true,
            Self::Recovered(_) => false,
            Self::Authorized(a) => a.use_evidence.is_some(),
            Self::Attempted(a) => a.worker.is_some(),
            _ => false,
        }
    }

    /// The stage.
    pub const fn stage(&self) -> Stage {
        match self {
            Self::Proposed(_) => Stage::Proposed,
            Self::Authorized(_) => Stage::Authorized,
            Self::Rejected(_) => Stage::Rejected,
            Self::Attempted(_) => Stage::Attempted,
            Self::Terminal(_) | Self::TerminalObserved(_) => Stage::Terminal,
            Self::Recovered(_) => Stage::Recovered,
        }
    }

    /// Checks every string and count in the event.
    pub fn validate(&self) -> Result<(), ValidationError> {
        match self {
            Self::Proposed(p) => {
                p.subject.validate()?;
                p.decision.validate()?;
                p.action.validate("proposed.action")?;
                if let Some(h) = &p.handoff {
                    h.validate()?;
                }
                if let Some(n) = &p.native_digest {
                    n.validate()?;
                }
                Ok(())
            }
            Self::Authorized(a) => {
                a.capability.validate()?;
                a.action.validate("authorized.action")
            }
            Self::Rejected(r) => check_text("rejected.reason", &r.reason, 1, MAX_TEXT_BYTES),
            Self::Attempted(a) => a.action.validate(),
            Self::Terminal(t) => t.outcome.validate(),
            Self::TerminalObserved(t) => t.terminal.outcome.validate(),
            Self::Recovered(_) => Ok(()),
        }
    }
}

/// One record of the log: the chain header, the execution it belongs to,
/// the signing key's id and the event.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Record {
    /// The kernel whose log this is.
    pub kernel_id: String,
    /// Position in the log, from 1, strictly increasing by one.
    pub sequence: u64,
    /// Hash of the previous record, or [`crate::encode::genesis_hash`].
    pub prev_hash: [u8; 32],
    /// The execution this event belongs to.
    pub execution_id: ExecutionId,
    /// Wall clock when the record was made, by the writer's clock.
    pub recorded_at_ms: u64,
    /// The receipt key that signed it, inside the hashed region.
    pub key_id: ReceiptKeyId,
    /// Who produced it.
    pub provenance: Provenance,
    /// What happened.
    pub event: Event,
}

impl Record {
    /// The stage of the event.
    pub const fn stage(&self) -> Stage {
        self.event.stage()
    }

    /// Checks every bounded field.
    pub fn validate(&self) -> Result<(), ValidationError> {
        check_id("kernel_id", &self.kernel_id)?;
        self.provenance.validate()?;
        self.event.validate()
    }
}
