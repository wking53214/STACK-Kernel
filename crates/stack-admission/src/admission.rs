//! The pipeline. `Admission::admit` runs stages 1 to 4 and returns an
//! [`Admitted`] request or a typed [`Refused`]; nothing executes here.
//!
//! Every boundary is built by the kernel from its own policy inside
//! [`Admission::new`]: the Trident from the operator's config, key ring
//! and durable replay store; the authority from the operator's trust set
//! and revocation list, named for the policy's audience; the recorder
//! from the operator's receipt log and receipt key. The one clock they all
//! read is [`crate::KernelClock`].
//!
//! Where the recorder is reachable, a refusal is recorded: once the
//! payload has parsed, the request is `proposed` and every later refusal
//! closes it with a `rejected` record. Before that (a Trident refusal, an
//! unparseable payload) there is nothing a receipt could truthfully say
//! about a subject, so nothing is written and `Refused::recorded` is
//! false.

use std::fmt;
use std::sync::Arc;

use sha2::{Digest, Sha256};
use stack_authority::{
    ActionRequest, Authority, AuthorityConfig, AuthorizedAction, AuthzError, Clock, Digest32, RevocationList,
    TrustSet, UseStore,
};
use stack_receipt::{
    Action, ActualAction, Assurance, AuthorizedStage, Execution, ExecutionId, Handoff, Head, Outcome, Proposed,
    ProposedStage, ReceiptLog, ReceiptSigner, RecordError, Recorder, Subject, Terminal, TerminalUnrecorded,
    MAX_TEXT_BYTES,
};
use stack_trident::canonical::{to_canonical_bytes, CanonicalError, Limits};
use stack_trident::{
    DeploymentProfile, GateOutcome, KeyRing, Nonce, Refusal, ReplayStore, StartError, Trident, TridentConfig,
    Verdict as TridentVerdict,
};

use crate::binding::{self, BindingFinding};
use crate::clock::KernelClock;
use crate::config::{ConfigError, KernelPolicy};
use crate::executor::{Executor, RunOutcome, WorkerKind};
use crate::payload::{self, PayloadError};

/// What the operator hands the kernel to build its boundaries from. Every
/// part is the operator's; none comes from a request.
#[derive(Debug)]
pub struct Parts {
    /// The Trident's config. Must be the Production profile and name the
    /// policy's audience.
    pub trident: TridentConfig,
    /// The sender keys the Trident trusts, each with issuer metadata.
    pub keyring: KeyRing,
    /// The durable replay store.
    pub replay_store: Box<dyn ReplayStore>,
    /// The capability issuer keys the kernel trusts.
    pub trust: TrustSet,
    /// Withdrawn capabilities.
    pub revocations: RevocationList,
    /// The durable one-time-use store.
    pub use_store: Box<dyn UseStore>,
    /// The durable receipt log for the policy's kernel id.
    pub receipt_log: Box<dyn ReceiptLog>,
    /// The kernel's receipt key.
    pub receipt_signer: ReceiptSigner,
    /// What runs workers.
    pub executor: Box<dyn Executor>,
    /// The one clock.
    pub clock: Arc<dyn Clock>,
}

/// Why the kernel refused to start. Every variant is fail-closed.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum BuildError {
    /// The policy is invalid.
    #[error("policy refused: {0}")]
    Policy(#[from] ConfigError),
    /// The Trident config is not the Production profile.
    #[error("trident profile is {0:?}; the admission pipeline runs only behind a Production Trident")]
    TridentNotProduction(DeploymentProfile),
    /// The Trident's audience is not the policy's.
    #[error("trident audience differs from the policy audience")]
    TridentAudienceMismatch,
    /// The Trident refused to start.
    #[error("trident refused to start: {0}")]
    Trident(#[from] StartError),
    /// The authority refused its configuration.
    #[error("authority refused: {0}")]
    Authority(stack_authority::ConfigError),
    /// The use store does not survive a restart.
    #[error("the use store is not durable")]
    UseStoreNotDurable,
    /// The receipt log does not survive a restart.
    #[error("the receipt log is not durable")]
    ReceiptLogNotDurable,
    /// The receipt log belongs to another kernel.
    #[error("the receipt log is for kernel {log:?}, the policy names another")]
    ReceiptLogKernelMismatch {
        /// The log's kernel id.
        log: String,
    },
    /// The recorder refused its provenance or log.
    #[error("recorder refused: {0}")]
    Recorder(#[from] RecordError),
}

/// Where in the pipeline a request stopped.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Stage {
    /// Stage 1: Trident verification.
    Handoff,
    /// Stage 2: payload parse.
    Payload,
    /// Stage 3: CNS binding and kernel policy.
    Binding,
    /// Stage 4: operation map and capability authorization.
    Authorization,
    /// Stage 5: the write-ahead attempt record.
    Attempt,
    /// Stage 6: execution.
    Execution,
    /// Stage 7: the terminal record.
    Terminal,
}

impl Stage {
    /// Machine-readable spelling.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Handoff => "handoff",
            Self::Payload => "payload",
            Self::Binding => "binding",
            Self::Authorization => "authorization",
            Self::Attempt => "attempt",
            Self::Execution => "execution",
            Self::Terminal => "terminal",
        }
    }
}

/// Why a request was refused. Every variant denies.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RefusalReason {
    /// The Trident refused the envelope.
    Handoff(Refusal),
    /// The Trident accepted it with Development assurance. Unreachable
    /// behind the Production Trident [`Admission::new`] builds, and
    /// checked anyway.
    DevelopmentAssurance,
    /// The sender's own gate outcome, authenticated by the Trident, was
    /// not PASS.
    HandoffOutcomeNotPass(GateOutcome),
    /// The payload is not a well-formed request.
    Payload(PayloadError),
    /// The subject or the arguments cannot be canonically encoded in the
    /// restricted domain.
    Canonical(CanonicalError),
    /// No execution id could be drawn from the operating system.
    ExecutionIdUnavailable,
    /// The decision is not bound to this subject under the kernel's policy.
    Binding(Vec<BindingFinding>),
    /// The operation is not in the kernel's map. Refused before the
    /// capability is examined, so nothing is consumed.
    UnknownOperation(String),
    /// `stack-authority` refused.
    Authorization(AuthzError),
    /// A receipt record that must precede execution could not be written.
    Receipt(RecordError),
}

impl fmt::Display for RefusalReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Handoff(r) => write!(f, "trident refused: {:?}", r.reasons),
            Self::DevelopmentAssurance => f.write_str("handoff accepted with development assurance"),
            Self::HandoffOutcomeNotPass(o) => write!(f, "handoff gate outcome is {}", o.as_str()),
            Self::Payload(e) => write!(f, "payload: {e}"),
            Self::Canonical(e) => write!(f, "canonical encoding: {e}"),
            Self::ExecutionIdUnavailable => f.write_str("no execution id could be drawn"),
            Self::Binding(findings) => write!(f, "cns binding: {findings:?}"),
            Self::UnknownOperation(op) => write!(f, "operation {op:?} is not in the kernel's map"),
            Self::Authorization(e) => write!(f, "authorization: {e}"),
            Self::Receipt(e) => write!(f, "receipt: {e}"),
        }
    }
}

/// A refused request: where, why, and what the receipt log says about it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Refused {
    /// The stage that refused.
    pub stage: Stage,
    /// Why.
    pub reason: RefusalReason,
    /// The execution id, once one was drawn and proposed.
    pub execution_id: Option<ExecutionId>,
    /// Whether a `rejected` record closes the execution in the log.
    pub recorded: bool,
    /// Why the `rejected` record could not be written, when it could not.
    pub record_error: Option<RecordError>,
}

/// A request that passed every admission check. It carries the one
/// permission that exists, the [`AuthorizedAction`], and the open receipt
/// handle. Nothing has run. Dropping it leaves the execution `authorized`
/// with nothing after it, which the verifier reports as INCOMPLETE.
#[must_use = "an admitted request that is dropped was authorized and never attempted"]
pub struct Admitted {
    pub(crate) execution_id: ExecutionId,
    pub(crate) action: AuthorizedAction,
    pub(crate) kind: WorkerKind,
    pub(crate) args: Vec<u8>,
    pub(crate) exec: Execution<AuthorizedStage>,
}

impl fmt::Debug for Admitted {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Admitted")
            .field("execution_id", &self.execution_id)
            .field("operation", &self.action.operation())
            .field("resource", &self.action.resource())
            .field("kind", &self.kind)
            .finish_non_exhaustive()
    }
}

impl Admitted {
    /// The execution id.
    pub const fn execution_id(&self) -> &ExecutionId {
        &self.execution_id
    }

    /// The permission `stack-authority` minted.
    pub const fn action(&self) -> &AuthorizedAction {
        &self.action
    }

    /// The worker the operation maps to.
    pub const fn worker(&self) -> WorkerKind {
        self.kind
    }

    /// The canonical argument bytes the worker is handed.
    pub fn args(&self) -> &[u8] {
        &self.args
    }
}

/// What a successful admission carries. Success means exactly one thing:
/// the worker exited 0 within the deadline with a well-formed result frame
/// AND the terminal record is durable. It does not mean the action was
/// legitimate, and the result bytes are the worker's own claim.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Success {
    /// The execution id, for the independent verifier.
    pub execution_id: ExecutionId,
    /// The worker's exit status (0).
    pub exit_code: i32,
    /// The bytes the worker sent. Self-reported: a hostile worker can
    /// forge a well-formed result.
    pub result: Vec<u8>,
    /// SHA-256 of `result`, as recorded in the terminal record.
    pub result_digest: Digest32,
    /// Monotonic time of the run as the executor measured it.
    pub elapsed_ns: u64,
    /// The sequence of the terminal record.
    pub terminal_sequence: u64,
}

/// A run that ended in anything but a recorded `Completed`, with its
/// terminal record durable. The receipt is honest about what happened;
/// the outcome is not success.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Unsuccessful {
    /// The execution id.
    pub execution_id: ExecutionId,
    /// How the run ended.
    pub outcome: Outcome,
    /// Monotonic time of the run as the executor measured it.
    pub elapsed_ns: u64,
    /// The sequence of the terminal record.
    pub terminal_sequence: u64,
}

/// A run whose terminal record could not be made durable. The attempt
/// stays open in the log; an auditor reads the execution as INCOMPLETE
/// with outcome `unknown`, whatever was observed. Never success, even if
/// the observed outcome was `Completed`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TerminalLost {
    /// The execution id.
    pub execution_id: ExecutionId,
    /// What the kernel observed and could not record.
    pub observed: Outcome,
    /// Why the terminal record failed.
    pub error: RecordError,
}

/// What [`Admission::process`] returns. Only [`AdmissionResult::Success`]
/// is success.
#[derive(Debug, Clone, PartialEq, Eq)]
#[must_use = "an admission result that is dropped hides a refusal or a failure"]
pub enum AdmissionResult {
    /// Completed, and the terminal record is durable.
    Success(Success),
    /// Refused at stages 1 to 5. Nothing ran.
    Refused(Refused),
    /// Ran (or may have) and did not complete; the terminal is recorded.
    Unsuccessful(Unsuccessful),
    /// Ran (or may have); the terminal could not be recorded.
    TerminalLost(TerminalLost),
}

impl AdmissionResult {
    /// Whether this is a recorded `Completed`. The only success.
    pub const fn is_success(&self) -> bool {
        matches!(self, Self::Success(_))
    }

    /// The execution id, when one was drawn.
    pub const fn execution_id(&self) -> Option<ExecutionId> {
        match self {
            Self::Success(s) => Some(s.execution_id),
            Self::Refused(r) => r.execution_id,
            Self::Unsuccessful(u) => Some(u.execution_id),
            Self::TerminalLost(t) => Some(t.execution_id),
        }
    }
}

/// The kernel's admission boundary.
#[derive(Debug)]
pub struct Admission {
    policy: KernelPolicy,
    limits: Limits,
    trident: Trident,
    authority: Authority,
    use_store: Box<dyn UseStore>,
    recorder: Recorder,
    executor: Box<dyn Executor>,
    clock: Arc<dyn Clock>,
}

/// Text a receipt record can carry: at most [`MAX_TEXT_BYTES`], cut at a
/// character boundary, control characters replaced.
fn clean_text(text: &str) -> String {
    let full: String = text
        .chars()
        .map(|c| if c < '\u{20}' || c == '\u{7f}' { ' ' } else { c })
        .collect();
    let mut end = full.len().min(MAX_TEXT_BYTES);
    while end > 0 && !full.is_char_boundary(end) {
        end = end.saturating_sub(1);
    }
    full.get(..end).unwrap_or("refused").to_owned()
}

/// A reason string a `rejected` record can carry.
fn reason_text(stage: Stage, reason: &RefusalReason) -> String {
    clean_text(&format!("{}: {reason}", stage.as_str()))
}

impl Admission {
    /// Builds the kernel's boundaries from `policy` and `parts`. Refuses a
    /// non-Production Trident, an audience that differs anywhere, a
    /// non-durable store or log, a log for another kernel.
    pub fn new(policy: KernelPolicy, parts: Parts) -> Result<Self, BuildError> {
        policy.validate()?;
        if parts.trident.profile != DeploymentProfile::Production {
            return Err(BuildError::TridentNotProduction(parts.trident.profile));
        }
        if parts.trident.audience != policy.audience {
            return Err(BuildError::TridentAudienceMismatch);
        }
        if !parts.use_store.is_durable() {
            return Err(BuildError::UseStoreNotDurable);
        }
        if !parts.receipt_log.is_durable() {
            return Err(BuildError::ReceiptLogNotDurable);
        }
        if parts.receipt_log.kernel_id() != policy.kernel_id {
            return Err(BuildError::ReceiptLogKernelMismatch {
                log: parts.receipt_log.kernel_id().to_owned(),
            });
        }
        let clock = parts.clock;
        let limits = parts.trident.limits();
        let trident = Trident::new_with_store(
            parts.trident,
            parts.keyring,
            Arc::new(KernelClock::new(Arc::clone(&clock))),
            parts.replay_store,
        )?;
        let authority = Authority::new(AuthorityConfig::new(&policy.audience), parts.trust, parts.revocations)
            .map_err(BuildError::Authority)?;
        let recorder = Recorder::new(
            parts.receipt_log,
            parts.receipt_signer,
            policy.provenance.clone(),
            Box::new(KernelClock::new(Arc::clone(&clock))),
        )?;
        Ok(Self {
            policy,
            limits,
            trident,
            authority,
            use_store: parts.use_store,
            recorder,
            executor: parts.executor,
            clock,
        })
    }

    /// The policy.
    pub const fn policy(&self) -> &KernelPolicy {
        &self.policy
    }

    /// The authority, for the operator to rotate trust or revoke while
    /// the kernel runs.
    pub const fn authority(&self) -> &Authority {
        &self.authority
    }

    /// The Trident, for operator controls.
    pub const fn trident(&self) -> &Trident {
        &self.trident
    }

    /// The receipt chain head, for an operator to anchor elsewhere.
    pub fn receipt_head(&self) -> Result<Head, RecordError> {
        self.recorder.head()
    }

    /// Refuses before anything was proposed.
    fn unrecorded(stage: Stage, reason: RefusalReason) -> Refused {
        Refused {
            stage,
            reason,
            execution_id: None,
            recorded: false,
            record_error: None,
        }
    }

    /// Refuses after `proposed` was written, closing the execution.
    fn rejected(exec: Execution<ProposedStage>, stage: Stage, reason: RefusalReason) -> Refused {
        let id = *exec.id();
        let text = reason_text(stage, &reason);
        let (recorded, record_error) = match exec.reject(&text) {
            Ok(_) => (true, None),
            Err(e) => (false, Some(e)),
        };
        Refused {
            stage,
            reason,
            execution_id: Some(id),
            recorded,
            record_error,
        }
    }

    /// Stages 1 to 4. See the module documentation.
    pub fn admit(&self, envelope_bytes: &[u8]) -> Result<Admitted, Refused> {
        // ---- 1. The handoff. The Trident re-derives every claim in the
        // envelope; what comes back is authenticated under a shared key,
        // which proves possession of the key and nothing about a person.
        let verdict = self.trident.verify_wire(envelope_bytes);
        let outcome = verdict.outcome();
        let handoff = match verdict {
            TridentVerdict::Accepted(h) => h,
            TridentVerdict::Refused(r) => return Err(Self::unrecorded(Stage::Handoff, RefusalReason::Handoff(r))),
        };
        if handoff.require_production().is_err() {
            return Err(Self::unrecorded(Stage::Handoff, RefusalReason::DevelopmentAssurance));
        }
        if outcome != GateOutcome::Pass {
            return Err(Self::unrecorded(Stage::Handoff, RefusalReason::HandoffOutcomeNotPass(outcome)));
        }

        // ---- 2. The payload, strictly.
        let request = payload::parse(&handoff.payload)
            .map_err(|e| Self::unrecorded(Stage::Payload, RefusalReason::Payload(e)))?;
        let args = to_canonical_bytes(&request.args, &self.limits)
            .map_err(|e| Self::unrecorded(Stage::Payload, RefusalReason::Canonical(e)))?;

        // ---- 3. The kernel's own digest of the subject, then the proposal
        // record, then the binding checks against that digest and the
        // kernel's policy. The proposal carries the claimed seats and
        // verdicts under the root the kernel recomputed from them.
        let subject_digest = binding::subject_digest(&request.subject, &self.limits)
            .map_err(|e| Self::unrecorded(Stage::Binding, RefusalReason::Canonical(e)))?;
        let execution_id = Nonce::from_os_random()
            .map(|n| ExecutionId::from_bytes(*n.as_bytes()))
            .map_err(|_| Self::unrecorded(Stage::Binding, RefusalReason::ExecutionIdUnavailable))?;
        let proposed = Proposed {
            subject: Subject {
                identity: binding::identity(&request.decision),
                digest: subject_digest,
            },
            decision: binding::evidence(&request.decision, binding::recomputed_root(&request.decision)),
            action: Action {
                operation: request.operation.clone(),
                resource: request.resource.clone(),
            },
            handoff: Some(Handoff {
                sender_fingerprint: *handoff.sender.as_bytes(),
                audience: self.policy.audience.clone(),
                sequence: handoff.sequence,
                nonce: *handoff.nonce.as_bytes(),
                assurance: Assurance::Production,
            }),
            native_digest: None,
        };
        let exec = self
            .recorder
            .propose(execution_id, proposed)
            .map_err(|e| Self::unrecorded(Stage::Binding, RefusalReason::Receipt(e)))?;
        let (findings, decision_root) = binding::check(&request.decision, &subject_digest, &self.policy.roster_policy());
        if !findings.is_empty() {
            return Err(Self::rejected(exec, Stage::Binding, RefusalReason::Binding(findings)));
        }

        // ---- 4. The operation must exist before any capability is read,
        // so an unknown operation consumes nothing. Then the authority,
        // with a request the kernel built from its own recomputed values.
        let Some(kind) = self.policy.worker_for(&request.operation) else {
            return Err(Self::rejected(
                exec,
                Stage::Authorization,
                RefusalReason::UnknownOperation(request.operation),
            ));
        };
        let action_request = ActionRequest {
            subject_digest,
            decision_root,
            operation: request.operation,
            resource: request.resource,
        };
        let action = match self.authority.authorize(
            &request.capability,
            &action_request,
            self.clock.as_ref(),
            self.use_store.as_ref(),
        ) {
            Ok(a) => a,
            Err(e) => return Err(Self::rejected(exec, Stage::Authorization, RefusalReason::Authorization(e))),
        };
        // The permission exists. Record it; without the record nothing runs.
        let exec = exec.authorize(&action).map_err(|e| Refused {
            stage: Stage::Authorization,
            reason: RefusalReason::Receipt(e),
            execution_id: Some(execution_id),
            recorded: false,
            record_error: None,
        })?;
        Ok(Admitted {
            execution_id,
            action,
            kind,
            args,
            exec,
        })
    }

    /// The whole pipeline: stages 1 to 4 ([`Admission::admit`]), then
    /// [`Admission::execute`]. Every failure is a typed variant;
    /// `Success` only for a recorded `Completed`.
    pub fn process(&self, envelope_bytes: &[u8]) -> AdmissionResult {
        match self.admit(envelope_bytes) {
            Ok(admitted) => self.execute(admitted),
            Err(refused) => AdmissionResult::Refused(refused),
        }
    }

    /// Stages 5 to 8 for a request that was admitted. The permission to
    /// call this is the [`Admitted`] value, which only [`Admission::admit`]
    /// can make.
    pub fn execute(&self, admitted: Admitted) -> AdmissionResult {
        let Admitted {
            execution_id,
            action,
            kind,
            args,
            exec,
        } = admitted;

        // ---- 5. Write-ahead: the attempt is durable before anything runs.
        // If it is not, nothing runs. The one-time capability was consumed
        // by stage 4 and stays consumed; the log holds `authorized` with no
        // attempt, which an auditor reads as INCOMPLETE and not attempted.
        let actual = ActualAction {
            operation: action.operation().to_owned(),
            resource: action.resource().to_owned(),
            argument_digest: Digest32::from_bytes(Sha256::digest(&args).into()),
        };
        let running = match exec.attempt(actual, self.clock.now_unix_ms()) {
            Ok(r) => r,
            Err(stack_receipt::AttemptUnrecorded(e)) => {
                return AdmissionResult::Refused(Refused {
                    stage: Stage::Attempt,
                    reason: RefusalReason::Receipt(e.clone()),
                    execution_id: Some(execution_id),
                    recorded: false,
                    record_error: Some(e),
                });
            }
        };

        // ---- 6. Execution through the seam, under the kernel's limits.
        let wall = std::time::Instant::now();
        let report = self.executor.run(kind, &self.policy.limits, &args);
        let measured_ns = u64::try_from(wall.elapsed().as_nanos()).unwrap_or(u64::MAX);

        // ---- 7. The terminal event from what was observed. Anything the
        // executor could not report is Unknown; an executor that claims a
        // completion after its own deadline fired, or a result longer than
        // the cap, is not believed.
        let (outcome, result, elapsed_ns) = match report {
            Ok(report) => {
                let elapsed = report.elapsed_ns;
                let (outcome, result) = self.observed(report.outcome, report.deadline_fired);
                (outcome, result, elapsed)
            }
            Err(e) => (
                Outcome::Unknown {
                    reason: clean_text(&format!("executor failed: {e}")),
                },
                None,
                measured_ns,
            ),
        };
        let terminal = Terminal {
            outcome: outcome.clone(),
            completed_at_ms: self.clock.now_unix_ms(),
            elapsed_ns,
        };
        match running.finish(terminal) {
            Ok(closed) => match (&outcome, result) {
                (Outcome::Completed { exit_code, result_digest }, Some(result)) => {
                    // ---- 8. Success: a recorded Completed.
                    AdmissionResult::Success(Success {
                        execution_id,
                        exit_code: *exit_code,
                        result,
                        result_digest: *result_digest,
                        elapsed_ns,
                        terminal_sequence: closed.terminal_sequence,
                    })
                }
                _ => AdmissionResult::Unsuccessful(Unsuccessful {
                    execution_id,
                    outcome,
                    elapsed_ns,
                    terminal_sequence: closed.terminal_sequence,
                }),
            },
            Err(TerminalUnrecorded { observed_outcome, error }) => AdmissionResult::TerminalLost(TerminalLost {
                execution_id,
                observed: observed_outcome,
                error,
            }),
        }
    }

    /// The receipt outcome for an executor's observation, and the result
    /// bytes when (and only when) it is a believable completion.
    fn observed(&self, outcome: RunOutcome, deadline_fired: bool) -> (Outcome, Option<Vec<u8>>) {
        match outcome {
            RunOutcome::Completed { exit_code, result } => {
                let too_long = u64::try_from(result.len()).map_or(true, |n| n > self.policy.limits.max_output_bytes);
                if deadline_fired || too_long {
                    (
                        Outcome::Unknown {
                            reason: "executor reported a completion that contradicts its own report".to_owned(),
                        },
                        None,
                    )
                } else {
                    (
                        Outcome::Completed {
                            exit_code,
                            result_digest: Digest32::from_bytes(Sha256::digest(&result).into()),
                        },
                        Some(result),
                    )
                }
            }
            RunOutcome::TimedOut => (Outcome::TimedOut, None),
            RunOutcome::Terminated { signal } => (Outcome::Terminated { signal }, None),
            RunOutcome::TerminationUnconfirmed { reason } => (
                Outcome::TerminationUnconfirmed {
                    reason: clean_text(&reason),
                },
                None,
            ),
            RunOutcome::Crashed { signal } => (Outcome::Crashed { signal }, None),
            RunOutcome::SeccompViolation { signal } => (Outcome::SeccompViolation { signal }, None),
            RunOutcome::ResourceLimit { signal } => (Outcome::ResourceLimit { signal }, None),
            RunOutcome::ResultMissing { exit_code } => (Outcome::ResultMissing { exit_code }, None),
            RunOutcome::ExitedNonZero { exit_code } => (Outcome::ExitedNonZero { exit_code }, None),
            RunOutcome::ResultOversized => (Outcome::ResultOversized, None),
            RunOutcome::Unknown { reason } => (
                Outcome::Unknown {
                    reason: clean_text(&reason),
                },
                None,
            ),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reason_text_is_bounded_and_free_of_control_characters() {
        let long = RefusalReason::UnknownOperation("x\n".repeat(2000));
        let text = reason_text(Stage::Authorization, &long);
        assert!(text.len() <= MAX_TEXT_BYTES);
        assert!(text.starts_with("authorization: operation"));
        assert!(!text.chars().any(|c| c < '\u{20}' || c == '\u{7f}'));
        let multi = RefusalReason::UnknownOperation("\u{1F600}".repeat(600));
        let text = reason_text(Stage::Authorization, &multi);
        assert!(text.len() <= MAX_TEXT_BYTES);
        assert!(text.is_char_boundary(text.len()));
        assert_eq!(Stage::Handoff.as_str(), "handoff");
    }
}
