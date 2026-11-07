//! The authorization decision: every check, in a fixed order, then one
//! atomic use record, then an [`AuthorizedAction`] that only this module
//! can mint.
//!
//! # Order of checks, and what each refusal reveals
//!
//! 1. The use store must be durable, unless configuration allows
//!    otherwise. A verifier that could forget a one-time use refuses to
//!    run at all.
//! 2. Size and strict parse. Reveals facts about the bytes presented.
//! 3. Trust resolution of `(issuer_id, key_id)` at `now`: unknown issuer,
//!    untrusted key, revoked, not yet valid, expired. Reveals facts about
//!    the verifier's own trust set, which is public configuration.
//! 4. Signature, strict. Reveals one bit: whether the holder of the
//!    anchor's key signed exactly these bytes. Nothing after this point
//!    is reached for bytes a trusted issuer did not sign, so every later
//!    refusal describes a genuine capability, which its holder already
//!    has in full.
//! 5. Revocation by id or digest.
//! 6. Lifetime cap: `expires_at_ms - not_before_ms` at most the
//!    configured maximum. A static property, checked before the clock so
//!    an over-long capability is refused at every instant.
//! 7. Window: `not_before_ms <= now < expires_at_ms`.
//! 8. Audience equals the verifier's configured identity. The identity
//!    is configuration, never request data: a caller cannot pick who it
//!    is talking to.
//! 9. Subject digest equals the request's.
//! 10. Decision root equals the request's.
//! 11. Operation is a member of the capability's set, byte for byte.
//! 12. Some resource scope covers the request's resource, under the
//!     rules in `scope`.
//!     (12a.) Execution binding: a version 2 capability's arguments digest,
//!     worker label and limits digest equal what the request says will run,
//!     each refused for its own reason; a bound capability with no
//!     description of the execution is refused; with
//!     `require_execution_binding` a version 1 capability is refused.
//! 13. The use store records the use. For a one-time capability this is
//!     the atomic step that makes it one-time; it runs last so a request
//!     refused for any other reason does not consume anything.
//!
//! A request descriptor is data about what the caller wants to do. It
//! authorizes nothing: every field in it is compared against a field the
//! issuer signed, and the two must agree.

use std::fmt;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::RwLock;

use crate::capability::{ExecutionBinding, Field, ParseError, SignedCapability, MAX_ID_BYTES, MAX_WIRE_BYTES, MIN_WIRE_BYTES};
use crate::clock::Clock;
use crate::digest::Digest32;
use crate::scope::is_control;
use crate::store::{UseError, UseEvidence, UseKey, UseStore};
use crate::trust::{KeyId, ResolveError, RevocationList, TrustSet};
use crate::CapabilityDigest;

/// Why a configuration was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ConfigError {
    /// The audience breaks the identifier rules, so no capability could
    /// ever name it.
    #[error("audience refused: {0}")]
    BadAudience(ParseError),
    /// `max_lifetime_ms` is zero.
    #[error("max_lifetime_ms is zero")]
    ZeroLifetime,
    /// `max_capability_bytes` is below the smallest valid wire form or
    /// above the largest.
    #[error("max_capability_bytes must be between {MIN_WIRE_BYTES} and {MAX_WIRE_BYTES}")]
    CapabilityCapOutOfRange,
}

/// What a verifier is, and what it accepts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorityConfig {
    /// This verifier's identity. A capability must name it exactly.
    pub audience: String,
    /// Longest `expires_at_ms - not_before_ms` accepted.
    pub max_lifetime_ms: u64,
    /// Longest capability wire form accepted, in bytes.
    pub max_capability_bytes: usize,
    /// Whether a use store that is not durable is refused. True in every
    /// deployment; false only for tests and simulations.
    pub require_durable_use_store: bool,
    /// Whether a capability without an execution binding (version 1) is
    /// refused. False by default, so existing issuers keep working; a
    /// deployment that has moved its issuer to version 2 sets it.
    pub require_execution_binding: bool,
}

impl AuthorityConfig {
    /// Default lifetime cap: one day.
    pub const DEFAULT_MAX_LIFETIME_MS: u64 = 24 * 60 * 60 * 1000;
    /// Default size cap: 16 KiB.
    pub const DEFAULT_MAX_CAPABILITY_BYTES: usize = 16 * 1024;

    /// Production defaults for the verifier named `audience`.
    pub fn new(audience: &str) -> Self {
        Self {
            audience: audience.to_owned(),
            max_lifetime_ms: Self::DEFAULT_MAX_LIFETIME_MS,
            max_capability_bytes: Self::DEFAULT_MAX_CAPABILITY_BYTES,
            require_durable_use_store: true,
            require_execution_binding: false,
        }
    }

    /// Checks the configuration.
    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.audience.is_empty() || self.audience.len() > MAX_ID_BYTES {
            return Err(ConfigError::BadAudience(ParseError::LengthOutOfBounds(Field::Audience)));
        }
        if self.audience.chars().any(is_control) {
            return Err(ConfigError::BadAudience(ParseError::ControlCharacter(Field::Audience)));
        }
        if self.max_lifetime_ms == 0 {
            return Err(ConfigError::ZeroLifetime);
        }
        if self.max_capability_bytes < MIN_WIRE_BYTES || self.max_capability_bytes > MAX_WIRE_BYTES {
            return Err(ConfigError::CapabilityCapOutOfRange);
        }
        Ok(())
    }
}

/// What the enforcement boundary wants to do, as data. Authorizes
/// nothing by itself.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ActionRequest {
    /// CNS subject digest of the content the action is about, recomputed
    /// by the boundary from the content, never copied from the caller.
    pub subject_digest: Digest32,
    /// CNS decision root of the governing decision.
    pub decision_root: Digest32,
    /// The operation, by exact name.
    pub operation: String,
    /// The resource, as a path under the rules in `scope`.
    pub resource: String,
    /// What the boundary will run: the digest of the arguments, the worker
    /// kind and the digest of the limits, computed by the boundary itself.
    /// A version 2 capability is checked against it. `None` says the
    /// boundary does not describe the execution, which a bound capability
    /// refuses.
    pub execution: Option<ExecutionBinding>,
}

/// Why a request was not authorized. Every variant denies; there is no
/// partial outcome.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum AuthzError {
    /// The verifier's use store cannot be relied on, so nothing is
    /// authorized.
    #[error("use store unavailable")]
    StoreUnavailable,
    /// The verifier's trust state is unreadable (a lock was poisoned).
    #[error("trust state unavailable")]
    TrustUnavailable,
    /// Longer than the configured cap.
    #[error("capability exceeds the byte cap")]
    TooLarge,
    /// Not a well-formed capability.
    #[error("capability malformed: {0}")]
    Malformed(ParseError),
    /// A `stack-capability/` version this verifier does not speak.
    #[error("unsupported capability version")]
    UnsupportedVersion,
    /// An empty operations or resources set.
    #[error("capability {0} set is empty")]
    EmptyScope(Field),
    /// No anchor names the issuer.
    #[error("unknown issuer")]
    UnknownIssuer,
    /// The issuer is known but not under this key.
    #[error("untrusted issuer key")]
    UntrustedKey,
    /// The issuer key is revoked.
    #[error("issuer key revoked")]
    IssuerRevoked,
    /// The issuer key's window has not started.
    #[error("issuer key not yet valid")]
    IssuerKeyNotYetValid,
    /// The issuer key's window has ended.
    #[error("issuer key expired")]
    IssuerKeyExpired,
    /// The signature does not verify under the resolved key.
    #[error("bad signature")]
    BadSignature,
    /// The capability is on the revocation list.
    #[error("capability revoked")]
    Revoked,
    /// `now` is before `not_before_ms`.
    #[error("capability not yet valid")]
    NotYetValid,
    /// `now` is at or after `expires_at_ms`.
    #[error("capability expired")]
    Expired,
    /// The capability's lifetime exceeds the verifier's cap.
    #[error("capability lifetime {lifetime_ms} ms exceeds the cap of {max_ms} ms")]
    LifetimeTooLong {
        /// `expires_at_ms - not_before_ms`.
        lifetime_ms: u64,
        /// The configured cap.
        max_ms: u64,
    },
    /// The capability names another verifier.
    #[error("capability is for another audience")]
    AudienceMismatch,
    /// The verifier requires an execution binding and the capability has none.
    #[error("capability has no execution binding")]
    ExecutionBindingRequired,
    /// The capability is bound but the request does not say what will run.
    #[error("request does not describe the execution the capability binds")]
    ExecutionNotDescribed,
    /// The capability binds other arguments.
    #[error("arguments digest mismatch")]
    ArgsMismatch,
    /// The capability binds another worker kind.
    #[error("worker kind mismatch")]
    WorkerMismatch,
    /// The capability binds other execution limits.
    #[error("limits digest mismatch")]
    LimitsMismatch,
    /// The capability is about other content.
    #[error("subject digest mismatch")]
    SubjectMismatch,
    /// The capability is governed by another decision.
    #[error("decision root mismatch")]
    DecisionMismatch,
    /// The operation is not in the capability's set.
    #[error("operation not granted")]
    OperationDenied,
    /// No scope covers the resource.
    #[error("resource not granted")]
    ResourceDenied,
    /// A one-time capability was already used.
    #[error("one-time capability already used")]
    Replay,
    /// The capability id already names a different capability.
    #[error("capability id reused for different content")]
    CapabilityIdReused,
}

impl From<ParseError> for AuthzError {
    fn from(e: ParseError) -> Self {
        match e {
            ParseError::TooLarge => Self::TooLarge,
            ParseError::UnsupportedVersion => Self::UnsupportedVersion,
            ParseError::EmptyScope(f) => Self::EmptyScope(f),
            other => Self::Malformed(other),
        }
    }
}

impl From<ResolveError> for AuthzError {
    fn from(e: ResolveError) -> Self {
        match e {
            ResolveError::UnknownIssuer => Self::UnknownIssuer,
            ResolveError::UntrustedKey => Self::UntrustedKey,
            ResolveError::IssuerRevoked => Self::IssuerRevoked,
            ResolveError::IssuerKeyNotYetValid => Self::IssuerKeyNotYetValid,
            ResolveError::IssuerKeyExpired => Self::IssuerKeyExpired,
        }
    }
}

impl From<UseError> for AuthzError {
    fn from(e: UseError) -> Self {
        match e {
            UseError::AlreadyUsed => Self::Replay,
            UseError::IdConflict => Self::CapabilityIdReused,
            UseError::Unavailable => Self::StoreUnavailable,
        }
    }
}

/// Proof that [`Authority::authorize`] passed every check for one
/// action. Only that function can construct it. The rest of the kernel
/// demands one before executing, and a receipt records what it carries.
#[derive(Debug, Clone, PartialEq, Eq)]
#[must_use = "an AuthorizedAction is the permission; dropping it unused authorizes nothing"]
pub struct AuthorizedAction {
    cap_digest: CapabilityDigest,
    cap_id: String,
    issuer_id: String,
    key_id: KeyId,
    policy_ref: String,
    audience: String,
    operation: String,
    resource: String,
    subject_digest: Digest32,
    decision_root: Digest32,
    one_time: bool,
    authorized_at_ms: u64,
    use_evidence: UseEvidence,
}

impl AuthorizedAction {
    /// Digest of the capability that authorized this action.
    pub const fn cap_digest(&self) -> &CapabilityDigest {
        &self.cap_digest
    }

    /// The capability's id.
    pub fn cap_id(&self) -> &str {
        &self.cap_id
    }

    /// The issuer that signed the capability.
    pub fn issuer_id(&self) -> &str {
        &self.issuer_id
    }

    /// The key it was signed under.
    pub const fn key_id(&self) -> &KeyId {
        &self.key_id
    }

    /// The policy reference carried by the capability.
    pub fn policy_ref(&self) -> &str {
        &self.policy_ref
    }

    /// The verifier that authorized the action.
    pub fn audience(&self) -> &str {
        &self.audience
    }

    /// The authorized operation.
    pub fn operation(&self) -> &str {
        &self.operation
    }

    /// The authorized resource.
    pub fn resource(&self) -> &str {
        &self.resource
    }

    /// The content the action is about.
    pub const fn subject_digest(&self) -> &Digest32 {
        &self.subject_digest
    }

    /// The governing decision.
    pub const fn decision_root(&self) -> &Digest32 {
        &self.decision_root
    }

    /// Whether the capability was consumed by this authorization.
    pub const fn one_time(&self) -> bool {
        self.one_time
    }

    /// The verifier's clock when it authorized.
    pub const fn authorized_at_ms(&self) -> u64 {
        self.authorized_at_ms
    }

    /// What the use store returned when it recorded this use: a durable
    /// record hash and position, a labeled non-durable marker, or nothing.
    pub const fn use_evidence(&self) -> &UseEvidence {
        &self.use_evidence
    }
}

/// Callback run after the revocation list or trust set was handed out
/// for writing. It receives the authority so it can re-check holders of
/// earlier permissions.
type ChangeHook = Box<dyn Fn(&Authority) + Send + Sync>;

struct ChangeHookCell(std::sync::OnceLock<ChangeHook>);

impl fmt::Debug for ChangeHookCell {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(if self.0.get().is_some() { "ChangeHook(set)" } else { "ChangeHook(unset)" })
    }
}

/// The verifier. Holds the trust set and the revocation list; never a
/// secret.
#[derive(Debug)]
pub struct Authority {
    config: AuthorityConfig,
    trust: RwLock<TrustSet>,
    revocations: RwLock<RevocationList>,
    epoch: AtomicU64,
    hook: ChangeHookCell,
}

impl Authority {
    /// A verifier with this configuration, trust set and revocation list.
    pub fn new(config: AuthorityConfig, trust: TrustSet, revocations: RevocationList) -> Result<Self, ConfigError> {
        config.validate()?;
        Ok(Self {
            config,
            trust: RwLock::new(trust),
            revocations: RwLock::new(revocations),
            epoch: AtomicU64::new(0),
            hook: ChangeHookCell(std::sync::OnceLock::new()),
        })
    }

    /// The revocation epoch: a monotonic counter, 0 at construction, that
    /// goes up each time the revocation list or the trust set is handed out
    /// for writing ([`Authority::with_revocations`], [`Authority::with_trust`]).
    /// It counts write accesses, not proven changes: a closure that changed
    /// nothing still advances it, which can only cause an extra re-check,
    /// never a missed one. A holder of an older [`AuthorizedAction`] that
    /// sees the epoch move calls [`Authority::recheck`].
    pub fn revocation_epoch(&self) -> u64 {
        self.epoch.load(Ordering::SeqCst)
    }

    /// Registers the one callback run after every write access to the
    /// revocation list or trust set, once the lock is released and the
    /// epoch has advanced. Returns false if a callback was already set (the
    /// first stays). The callback must not call `with_trust` or
    /// `with_revocations`.
    pub fn set_change_hook(&self, hook: impl Fn(&Authority) + Send + Sync + 'static) -> bool {
        self.hook.0.set(Box::new(hook)).is_ok()
    }

    fn run_hook(&self) {
        if let Some(hook) = self.hook.0.get() {
            hook(self);
        }
    }

    /// Re-checks, now, whether an earlier permission still stands: its
    /// capability is not revoked (by id or digest) and its issuer key is
    /// still in the trust set and not revoked. The key's validity window
    /// is deliberately not re-applied: a window that closes does not
    /// withdraw an already-minted permission. An unreadable (poisoned)
    /// state is an error, never a pass.
    pub fn recheck(&self, action: &AuthorizedAction) -> Result<(), AuthzError> {
        {
            let revocations = self.revocations.read().map_err(|_| AuthzError::TrustUnavailable)?;
            if revocations.is_revoked(action.cap_id(), action.cap_digest()) {
                return Err(AuthzError::Revoked);
            }
        }
        let trust = self.trust.read().map_err(|_| AuthzError::TrustUnavailable)?;
        match trust.resolve(action.issuer_id(), action.key_id(), action.authorized_at_ms()) {
            Ok(_) | Err(ResolveError::IssuerKeyNotYetValid | ResolveError::IssuerKeyExpired) => Ok(()),
            Err(e) => Err(e.into()),
        }
    }

    /// The configuration.
    pub const fn config(&self) -> &AuthorityConfig {
        &self.config
    }

    /// Runs `f` on the trust set under its write lock, so an operator can
    /// add, revoke or remove anchors while the verifier runs.
    pub fn with_trust<R>(&self, f: impl FnOnce(&mut TrustSet) -> R) -> Result<R, AuthzError> {
        let mut guard = self.trust.write().map_err(|_| AuthzError::TrustUnavailable)?;
        let r = f(&mut guard);
        self.epoch.fetch_add(1, Ordering::SeqCst);
        drop(guard);
        self.run_hook();
        Ok(r)
    }

    /// Runs `f` on the revocation list under its write lock.
    pub fn with_revocations<R>(&self, f: impl FnOnce(&mut RevocationList) -> R) -> Result<R, AuthzError> {
        let mut guard = self.revocations.write().map_err(|_| AuthzError::TrustUnavailable)?;
        let r = f(&mut guard);
        self.epoch.fetch_add(1, Ordering::SeqCst);
        drop(guard);
        self.run_hook();
        Ok(r)
    }

    /// Decides whether `capability_bytes` authorizes `request` now. See
    /// the module documentation for the order of checks.
    pub fn authorize(
        &self,
        capability_bytes: &[u8],
        request: &ActionRequest,
        clock: &dyn Clock,
        store: &dyn UseStore,
    ) -> Result<AuthorizedAction, AuthzError> {
        // 1. A verifier that could forget a use does not run.
        if self.config.require_durable_use_store && !store.is_durable() {
            return Err(AuthzError::StoreUnavailable);
        }
        // 2. Bytes.
        let signed = SignedCapability::parse(capability_bytes, self.config.max_capability_bytes)?;
        let cap = signed.capability();
        let now = clock.now_unix_ms();
        // 3 and 4. Who signed, and did they.
        let key_id = KeyId::from_bytes(*signed.key_id());
        {
            let trust = self.trust.read().map_err(|_| AuthzError::TrustUnavailable)?;
            let anchor = trust.resolve(&cap.issuer_id, &key_id, now)?;
            anchor.verify(&signed).map_err(|_| AuthzError::BadSignature)?;
        }
        // From here on, a trusted issuer signed exactly these bytes.
        // 5. Revocation.
        {
            let revocations = self.revocations.read().map_err(|_| AuthzError::TrustUnavailable)?;
            if revocations.is_revoked(&cap.cap_id, signed.digest()) {
                return Err(AuthzError::Revoked);
            }
        }
        // 6 and 7. Lifetime, then window.
        let lifetime_ms = cap.expires_at_ms.saturating_sub(cap.not_before_ms);
        if lifetime_ms > self.config.max_lifetime_ms {
            return Err(AuthzError::LifetimeTooLong {
                lifetime_ms,
                max_ms: self.config.max_lifetime_ms,
            });
        }
        if now < cap.not_before_ms {
            return Err(AuthzError::NotYetValid);
        }
        if now >= cap.expires_at_ms {
            return Err(AuthzError::Expired);
        }
        // 8. Who it is for.
        if cap.audience != self.config.audience {
            return Err(AuthzError::AudienceMismatch);
        }
        // 9 and 10. What it is about, and under which decision.
        if !cap.subject_digest.ct_eq(&request.subject_digest) {
            return Err(AuthzError::SubjectMismatch);
        }
        if !cap.decision_root.ct_eq(&request.decision_root) {
            return Err(AuthzError::DecisionMismatch);
        }
        // 11 and 12. What it permits.
        if cap
            .operations
            .binary_search_by(|op| op.as_bytes().cmp(request.operation.as_bytes()))
            .is_err()
        {
            return Err(AuthzError::OperationDenied);
        }
        if !cap.resources.iter().any(|scope| scope.covers(&request.resource)) {
            return Err(AuthzError::ResourceDenied);
        }
        // 12a. What it will run, if the capability says. Before the use is
        // recorded, so a refusal here consumes nothing.
        match (&cap.binding, &request.execution) {
            (Some(bound), Some(want)) => {
                if !bound.args_digest.ct_eq(&want.args_digest) {
                    return Err(AuthzError::ArgsMismatch);
                }
                if bound.worker != want.worker {
                    return Err(AuthzError::WorkerMismatch);
                }
                if !bound.limits_digest.ct_eq(&want.limits_digest) {
                    return Err(AuthzError::LimitsMismatch);
                }
            }
            (Some(_), None) => return Err(AuthzError::ExecutionNotDescribed),
            (None, _) if self.config.require_execution_binding => return Err(AuthzError::ExecutionBindingRequired),
            (None, _) => {}
        }
        // 13. Record the use, last.
        let use_evidence = store.record_use_evidenced(
            &UseKey {
                cap_id: &cap.cap_id,
                digest: signed.digest(),
            },
            cap.one_time,
            cap.expires_at_ms,
            now,
        )?;
        Ok(AuthorizedAction {
            cap_digest: *signed.digest(),
            cap_id: cap.cap_id.clone(),
            issuer_id: cap.issuer_id.clone(),
            key_id,
            policy_ref: cap.policy_ref.clone(),
            audience: cap.audience.clone(),
            operation: request.operation.clone(),
            resource: request.resource.clone(),
            subject_digest: cap.subject_digest,
            decision_root: cap.decision_root,
            one_time: cap.one_time,
            authorized_at_ms: now,
            use_evidence,
        })
    }
}
