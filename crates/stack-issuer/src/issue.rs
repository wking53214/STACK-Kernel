//! Issuing one capability.

use serde_json::Value;
use stack_admission::{binding, execution_binding, BindingFinding, DecisionClaim};
use stack_authority::{
    Capability, CapabilityDigest, Clock, ParseError, ResourceScope, ScopeKind, SignedCapability, NONCE_BYTES,
};
use stack_trident::canonical::to_canonical_bytes;

use crate::config::IssuerConfig;
use crate::entropy::{Entropy, EntropyError};
use crate::log::{IssuanceLog, IssuanceRecord, LogError};
use crate::signer::{SignError, Signer};

/// The most scopes one capability may carry. A small number on purpose: the
/// requirement is the minimum needed (R-6).
pub const MAX_RESOURCES_PER_CAPABILITY: usize = 16;

/// The size a default verifier accepts (`AuthorityConfig` default).
const VERIFIER_DEFAULT_MAX_BYTES: usize = 16 * 1024;

/// What a requester may say. There is no field for a digest, an audience, a
/// worker or a limit: the issuer derives those, so the requester cannot supply
/// one that differs from the truth.
#[derive(Debug, Clone)]
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
#[derive(Debug, Clone)]
pub struct Issued {
    /// The signed capability, ready to hex-encode into a payload.
    pub wire: Vec<u8>,
    /// Its id.
    pub cap_id: String,
    /// Its digest over the whole wire form.
    pub digest: CapabilityDigest,
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
    #[error("decision refused: {0:?}")]
    DecisionRefused(Vec<BindingFinding>),
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

/// The issuer.
#[derive(Debug)]
pub struct Issuer {
    config: IssuerConfig,
    signer: Box<dyn Signer>,
    entropy: Box<dyn Entropy>,
    log: Box<dyn IssuanceLog>,
    clock: Box<dyn Clock>,
}

fn kind_label(kind: ScopeKind) -> &'static str {
    match kind {
        ScopeKind::Exact => "exact",
        ScopeKind::Prefix => "prefix",
    }
}

impl Issuer {
    /// An issuer over its policy, its signer, its entropy, its log and its clock.
    pub fn new(
        config: IssuerConfig,
        signer: Box<dyn Signer>,
        entropy: Box<dyn Entropy>,
        log: Box<dyn IssuanceLog>,
        clock: Box<dyn Clock>,
    ) -> Self {
        Self { config, signer, entropy, log, clock }
    }

    /// Issues one capability, or none. Order: refuse what must be refused, take
    /// randomness, sign and check the signature, write the log, and only then
    /// return the capability.
    pub fn issue(&self, req: &IssuanceRequest) -> Result<Issued, IssueError> {
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
        let kind = *self
            .config
            .operations
            .get(&req.operation)
            .ok_or_else(|| IssueError::UnknownOperation(req.operation.clone()))?;
        if req.lifetime_ms == 0 || req.lifetime_ms > self.config.max_lifetime_ms {
            return Err(IssueError::Lifetime { requested: req.lifetime_ms, max: self.config.max_lifetime_ms });
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

        let mut nonce = [0u8; NONCE_BYTES];
        self.entropy.fill(&mut nonce)?;
        let mut id_bytes = [0u8; 16];
        self.entropy.fill(&mut id_bytes)?;
        let cap_id = format!("cap-{}", hex::encode(id_bytes));

        let now = self.clock.now_unix_ms();
        let expires = now
            .checked_add(req.lifetime_ms)
            .ok_or(IssueError::Lifetime { requested: req.lifetime_ms, max: self.config.max_lifetime_ms })?;

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
            resources: cap.resources.iter().map(|r| format!("{}:{}", kind_label(r.kind()), r.path())).collect(),
            not_before_ms: now,
            expires_at_ms: expires,
            issued_at_ms: now,
            one_time: true,
            policy_ref: self.config.policy_ref.clone(),
        };
        self.log.append(&record).map_err(IssueError::Log)?;
        Ok(Issued { wire, cap_id, digest })
    }
}
