//! Issuing one capability.

use std::fmt;
use std::sync::Mutex;

use serde_json::Value;
use stack_admission::{binding, execution_binding, BindingFinding, DecisionClaim};
use stack_authority::{
    Capability, CapabilityDigest, Clock, ParseError, ResourceScope, ScopeKind, SignedCapability, NONCE_BYTES,
};
use stack_receipt::{MAX_ID_BYTES, MAX_SEATS};
use stack_trident::canonical::to_canonical_bytes;

use crate::config::{ConfigError, IssuerConfig};
use crate::entropy::{Entropy, EntropyError};
use crate::hooks::{AuthorizationRequest, Authorizer, DecisionVerifier};
use crate::log::{AppendLimits, IssuanceLog, IssuanceRecord, LogError, ResetRecord};
use crate::signer::{SignError, Signer};

/// The most scopes one capability may carry. A small number on purpose: the
/// requirement is the minimum needed (R-6).
pub const MAX_RESOURCES_PER_CAPABILITY: usize = 16;

/// The size a default verifier accepts (`AuthorityConfig` default).
const VERIFIER_DEFAULT_MAX_BYTES: usize = 16 * 1024;

/// What a requester may say. There is no field for a digest, an audience, a
/// worker or a limit: the issuer derives those, so the requester cannot supply
/// one that differs from the truth.
#[derive(Clone)]
pub struct IssuanceRequest {
    /// Who is asking, as the caller authenticated them. 1 to 128 bytes.
    pub requester: String,
    /// The CNS content the decision is about.
    pub subject: Value,
    /// The claimed CNS decision. The issuer checks it as the kernel does.
    pub decision: DecisionClaim,
    /// One operation, by the name the kernel's policy maps to a worker.
    pub operation: String,
    /// The scopes wanted. At least one, no wildcard.
    pub resources: Vec<ResourceScope>,
    /// The arguments the operation will run with. Their canonical digest is
    /// bound. `null` and `{}` are different values with different digests.
    pub args: Value,
    /// How long the capability should live, from now, in milliseconds.
    pub lifetime_ms: u64,
}

/// What a successful issuance returns.
#[derive(Clone)]
pub struct Issued {
    /// The signed capability, ready to hex-encode into a payload.
    pub wire: Vec<u8>,
    /// Its id.
    pub cap_id: String,
    /// Its digest over the whole wire form.
    pub digest: CapabilityDigest,
}

impl fmt::Debug for IssuanceRequest {
    /// Names the request without printing the subject, the decision or the arguments.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("IssuanceRequest")
            .field("requester", &self.requester)
            .field("operation", &self.operation)
            .field("resources", &self.resources.len())
            .field("lifetime_ms", &self.lifetime_ms)
            .finish_non_exhaustive()
    }
}

impl fmt::Debug for Issued {
    /// Names the capability without printing it: the wire form is a bearer credential.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Issued").field("cap_id", &self.cap_id).field("digest", &self.digest.to_hex()).finish_non_exhaustive()
    }
}

/// Why nothing was issued. Every variant means no capability exists.
#[derive(Debug, thiserror::Error)]
pub enum IssueError {
    /// A text field is empty, too long, or holds a control character.
    #[error("{0} is empty, too long, or holds a control character")]
    Text(&'static str),
    /// The subject lies outside the canonical domain.
    #[error("subject: {0}")]
    Subject(String),
    /// The arguments lie outside the canonical domain.
    #[error("arguments: {0}")]
    Arguments(String),
    /// The decision is not a bound, policy-complete decision about this subject.
    #[error("decision refused")]
    DecisionRefused(Vec<BindingFinding>),
    /// The decision or subject is malformed in a way the kernel's payload parser refuses.
    #[error("decision shape: {0}")]
    DecisionShape(&'static str),
    /// The kernel refuses arguments and these are not empty.
    #[error("the kernel policy refuses arguments")]
    ArgumentsNotAllowed,
    /// A scope lies outside every configured resource root.
    #[error("scope {0:?} is outside the configured resource roots")]
    ScopeOutsideRoots(String),
    /// The issuer's clock is unusable: zero, running backwards, or too close to the end of time.
    #[error("issuer clock: {0}")]
    Clock(&'static str),
    /// The deployment's decision verifier refused.
    #[error("decision not verified")]
    DecisionNotVerified(String),
    /// The deployment's authorizer refused.
    #[error("not authorized")]
    NotAuthorized(String),
    /// This decision has already produced the most capabilities allowed.
    #[error("this decision has reached its issuance limit")]
    DecisionLimit,
    /// This subject has already produced the most capabilities allowed.
    #[error("this subject has reached its issuance limit")]
    SubjectLimit,
    /// The log holds the most distinct decisions allowed and this one is new.
    #[error("the log holds the most distinct decisions allowed")]
    DistinctDecisionsLimit,
    /// The decision named in a reset has nothing to reset.
    #[error("the decision has no issuances to reset")]
    NothingToReset,
    /// A reset was not well formed.
    #[error("the reset is not well formed")]
    BadReset,
    /// The kernel's policy has no such operation.
    #[error("unknown operation {0:?}")]
    UnknownOperation(String),
    /// No scope was requested.
    #[error("no resource scope requested")]
    NoResources,
    /// More scopes than [`MAX_RESOURCES_PER_CAPABILITY`].
    #[error("too many resource scopes")]
    TooManyResources,
    /// A prefix scope on the root.
    #[error("a wildcard resource scope is refused")]
    WildcardScope,
    /// The lifetime is zero or above the configured ceiling.
    #[error("lifetime {requested} ms is outside 1..={max} ms")]
    Lifetime {
        /// What was asked.
        requested: u64,
        /// The ceiling.
        max: u64,
    },
    /// No secure randomness.
    #[error(transparent)]
    Entropy(#[from] EntropyError),
    /// The capability did not encode.
    #[error("capability did not encode: {0:?}")]
    Encode(ParseError),
    /// The signer did not sign.
    #[error(transparent)]
    Signer(SignError),
    /// The signer returned a signature that does not verify under its own key.
    #[error("the signer's signature does not verify under its own public key")]
    SignerMisbehaved,
    /// The issuance could not be logged, so no capability was released.
    #[error(transparent)]
    Log(LogError),
}

impl IssueError {
    /// Detail for the operator's log, never for the requester. `Display` is neutral on
    /// purpose: a refused decision names the roster seats, a hook's reason can name
    /// internal policy.
    pub fn detail(&self) -> Option<String> {
        match self {
            Self::DecisionRefused(findings) => Some(format!("{findings:?}")),
            Self::DecisionNotVerified(reason) | Self::NotAuthorized(reason) => Some(reason.clone()),
            _ => None,
        }
    }
}

/// The issuer.
#[derive(Debug)]
pub struct Issuer {
    config: IssuerConfig,
    signer: Box<dyn Signer>,
    entropy: Box<dyn Entropy>,
    log: Box<dyn IssuanceLog>,
    clock: Box<dyn Clock>,
    verifier: Box<dyn DecisionVerifier>,
    authorizer: Box<dyn Authorizer>,
    /// The latest clock reading of a completed issuance. Only a completed issuance moves it.
    last_ms: Mutex<u64>,
}

fn args_are_empty(args: &Value) -> bool {
    match args {
        Value::Null => true,
        Value::Object(map) => map.is_empty(),
        _ => false,
    }
}

fn under(path: &str, root: &str) -> bool {
    path == root || path.strip_prefix(root).is_some_and(|rest| rest.starts_with('/'))
}

fn text_ok(s: &str, max: usize) -> bool {
    !s.is_empty() && s.len() <= max && !s.chars().any(char::is_control)
}

fn kind_label(kind: ScopeKind) -> &'static str {
    match kind {
        ScopeKind::Exact => "exact",
        ScopeKind::Prefix => "prefix",
    }
}

impl Issuer {
    /// An issuer over its policy, its signer, its entropy, its log, its clock, and the
    /// two hooks every deployment must supply. Refuses a log that does not say it is
    /// durable.
    pub fn new(
        config: IssuerConfig,
        signer: Box<dyn Signer>,
        entropy: Box<dyn Entropy>,
        log: Box<dyn IssuanceLog>,
        clock: Box<dyn Clock>,
        verifier: Box<dyn DecisionVerifier>,
        authorizer: Box<dyn Authorizer>,
    ) -> Result<Self, ConfigError> {
        if !log.is_durable() {
            return Err(ConfigError::LogNotDurable);
        }
        Ok(Self { config, signer, entropy, log, clock, verifier, authorizer, last_ms: Mutex::new(0) })
    }

    /// Re-allows one decision root: a deliberate, logged operator action. The reset is written
    /// into the issuance log (so it survives a restart and is auditable), the root's count goes
    /// back to zero, and what it had is taken off its subject's count. Returns the count it had.
    ///
    /// **Who may call this is the caller's job**: the issuer does not authenticate `operator`,
    /// it only records it. A reset undoes a cap, so treat the ability to call it as you treat the
    /// signing key.
    pub fn reset_decision(&self, decision_root_hex: &str, operator: &str, reason: &str) -> Result<u32, IssueError> {
        let reset = ResetRecord {
            decision_root: decision_root_hex.to_owned(),
            operator: operator.to_owned(),
            reason: reason.to_owned(),
            reset_at_ms: self.clock.now_unix_ms(),
        };
        self.log.reset_decision(&reset).map_err(|e| match e {
            LogError::NothingToReset => IssueError::NothingToReset,
            LogError::BadReset => IssueError::BadReset,
            other => IssueError::Log(other),
        })
    }

    /// Issues one capability, or none. Order: refuse what must be refused (shape, scope,
    /// operation, lifetime, the kernel's own decision check), ask the authorizer, ask the
    /// verifier, refuse an exhausted decision, take randomness, read the clock, sign and
    /// check the signature, write the log (which checks the cap again, atomically), and
    /// only then return the capability.
    pub fn issue(&self, req: &IssuanceRequest) -> Result<Issued, IssueError> {
        self.issue_with_receipt(req, None)
    }

    /// [`Self::issue`], with the CNS decision receipt the requester supplied, handed to the
    /// verifier unread. Whether a missing, malformed or expired receipt is refused is the
    /// verifier's rule (see [`CnsReceiptVerifier`](crate::CnsReceiptVerifier)); the receipt is
    /// not an input to anything else the issuer derives, and it is not part of the log record.
    pub fn issue_with_receipt(&self, req: &IssuanceRequest, receipt: Option<&[u8]>) -> Result<Issued, IssueError> {
        if req.requester.is_empty() || req.requester.len() > 128 || req.requester.chars().any(char::is_control) {
            return Err(IssueError::Text("requester"));
        }
        if req.resources.is_empty() {
            return Err(IssueError::NoResources);
        }
        if req.resources.len() > MAX_RESOURCES_PER_CAPABILITY {
            return Err(IssueError::TooManyResources);
        }
        if req.resources.iter().any(|r| r.kind() == ScopeKind::Prefix && r.path() == "/") {
            return Err(IssueError::WildcardScope);
        }
        for r in &req.resources {
            if !self.config.roots.iter().any(|root| under(r.path(), root)) {
                return Err(IssueError::ScopeOutsideRoots(r.path().to_owned()));
            }
        }
        let kind = *self
            .config
            .operations
            .get(&req.operation)
            .ok_or_else(|| IssueError::UnknownOperation(req.operation.clone()))?;
        if req.lifetime_ms == 0 || req.lifetime_ms > self.config.max_lifetime_ms {
            return Err(IssueError::Lifetime { requested: req.lifetime_ms, max: self.config.max_lifetime_ms });
        }

        // The shape checks the kernel's payload parser makes, so the issuer does not
        // sign what the kernel always refuses.
        if !req.subject.is_object() {
            return Err(IssueError::DecisionShape("the subject is not a map"));
        }
        if req.decision.seats.len() > MAX_SEATS || req.decision.verdicts.len() > MAX_SEATS {
            return Err(IssueError::DecisionShape("too many seats or verdicts"));
        }
        if req.decision.seats.iter().any(|s| !text_ok(s, MAX_ID_BYTES)) {
            return Err(IssueError::DecisionShape("a seat name is empty, too long or holds a control character"));
        }
        if req.decision.verdicts.iter().any(|v| v.validate().is_err()) {
            return Err(IssueError::DecisionShape("a verdict does not validate"));
        }
        if self.config.refuse_arguments && !args_are_empty(&req.args) {
            return Err(IssueError::ArgumentsNotAllowed);
        }

        // Everything bound is recomputed here, never copied from the request.
        let subject_digest = binding::subject_digest(&req.subject, &self.config.canonical)
            .map_err(|e| IssueError::Subject(format!("{e:?}")))?;
        let (findings, decision_root) = binding::check(&req.decision, &subject_digest, &self.config.roster);
        if !findings.is_empty() {
            return Err(IssueError::DecisionRefused(findings));
        }
        let canonical_args = to_canonical_bytes(&req.args, &self.config.canonical)
            .map_err(|e| IssueError::Arguments(format!("{e:?}")))?;
        let execution = execution_binding(&canonical_args, kind, &self.config.limits);
        let binding_for_record = execution.clone();
        // The cheap local policy first, then the verifier, which is probably a call to CNS.
        self.authorizer
            .authorize(&AuthorizationRequest {
                requester: &req.requester,
                operation: &req.operation,
                resources: &req.resources,
                lifetime_ms: req.lifetime_ms,
                args: &req.args,
                args_digest: &execution.args_digest,
                subject_digest: &subject_digest,
                decision_root: &decision_root,
            })
            .map_err(|r| IssueError::NotAuthorized(r.0))?;
        self.verifier
            .verify_with_receipt(&subject_digest, &req.decision, &decision_root, receipt)
            .map_err(|r| IssueError::DecisionNotVerified(r.0))?;
        // A non-binding look at the counts, so an exhausted request does not cost a signature.
        // The binding check is the log's `append`.
        let root_hex = decision_root.to_hex();
        let subject_hex = subject_digest.to_hex();
        let used = self.log.usage(&root_hex, &subject_hex).map_err(IssueError::Log)?;
        if used.decision >= self.config.caps.per_decision {
            return Err(IssueError::DecisionLimit);
        }
        if used.subject >= self.config.caps.per_subject {
            return Err(IssueError::SubjectLimit);
        }
        if !used.decision_known && used.distinct_decisions >= self.config.caps.distinct_decisions {
            return Err(IssueError::DistinctDecisionsLimit);
        }

        let mut nonce = [0u8; NONCE_BYTES];
        self.entropy.fill(&mut nonce)?;
        let mut id_bytes = [0u8; 16];
        self.entropy.fill(&mut id_bytes)?;
        let cap_id = format!("cap-{}", hex::encode(id_bytes));

        // Read and compare under one lock so concurrent readers are ordered, but only a
        // completed issuance advances the guard: a refused or failed request, or one wild
        // reading, must not block the issuer afterwards.
        let now = {
            let last = self.last_ms.lock().map_err(|_| IssueError::Clock("the clock guard is poisoned"))?;
            let now = self.clock.now_unix_ms();
            if now == 0 {
                return Err(IssueError::Clock("the clock reads zero"));
            }
            if now < *last {
                return Err(IssueError::Clock("the clock went backwards since the last issuance"));
            }
            now
        };
        let expires = now.checked_add(req.lifetime_ms).ok_or(IssueError::Clock("the window would overflow"))?;

        let mut cap = Capability {
            cap_id: cap_id.clone(),
            issuer_id: self.config.issuer_id.clone(),
            audience: self.config.audience.clone(),
            subject_digest,
            decision_root,
            operations: vec![req.operation.clone()],
            resources: req.resources.clone(),
            not_before_ms: now,
            expires_at_ms: expires,
            one_time: true,
            policy_ref: self.config.policy_ref.clone(),
            nonce,
            binding: Some(execution),
        };
        cap.normalise();

        let public = self.signer.public_key();
        let key_id = public.key_id();
        let region = cap.encode_signed_region(key_id.as_bytes()).map_err(IssueError::Encode)?;
        let signature = self.signer.sign(&region).map_err(IssueError::Signer)?;
        public.verify_strict(&region, &signature).map_err(|_| IssueError::SignerMisbehaved)?;
        let mut wire = region;
        wire.extend_from_slice(&signature);
        // The wire must parse as the verifier will read it, and fit the verifier's default size.
        SignedCapability::parse(&wire, VERIFIER_DEFAULT_MAX_BYTES).map_err(IssueError::Encode)?;
        let digest = CapabilityDigest::of_wire(&wire);

        let record = IssuanceRecord {
            cap_id: cap_id.clone(),
            capability_digest: digest.to_hex(),
            issuer_id: self.config.issuer_id.clone(),
            key_id: key_id.to_hex(),
            requester: req.requester.clone(),
            subject_digest: subject_digest.to_hex(),
            decision_root: decision_root.to_hex(),
            operation: req.operation.clone(),
            args_digest: binding_for_record.args_digest.to_hex(),
            worker: binding_for_record.worker.clone(),
            limits_digest: binding_for_record.limits_digest.to_hex(),
            resources: cap.resources.iter().map(|r| format!("{}:{}", kind_label(r.kind()), r.path())).collect(),
            not_before_ms: now,
            expires_at_ms: expires,
            issued_at_ms: now,
            one_time: true,
            policy_ref: self.config.policy_ref.clone(),
        };
        let limits = AppendLimits {
            per_decision: self.config.caps.per_decision,
            per_subject: self.config.caps.per_subject,
            distinct_decisions: self.config.caps.distinct_decisions,
        };
        self.log.append(&record, &limits).map_err(|e| match e {
            LogError::DecisionLimit => IssueError::DecisionLimit,
            LogError::SubjectLimit => IssueError::SubjectLimit,
            LogError::DistinctDecisionsLimit => IssueError::DistinctDecisionsLimit,
            other => IssueError::Log(other),
        })?;
        if let Ok(mut last) = self.last_ms.lock() {
            if now > *last {
                *last = now;
            }
        }
        Ok(Issued { wire, cap_id, digest })
    }
}
