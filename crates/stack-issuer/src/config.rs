//! The issuer's policy, derived from the kernel's so the two cannot drift (R-5).

use std::collections::BTreeMap;

use stack_admission::{ExecutionLimits, KernelPolicy, WorkerKind};
use sha2::{Digest, Sha256};
use stack_authority::{validate_path, Digest32};
use stack_receipt::RosterPolicy;
use stack_trident::canonical::Limits;

/// The largest lifetime ceiling accepted: the verifier's own default cap. A
/// ceiling above it would issue capabilities a default verifier refuses.
pub const MAX_LIFETIME_CEILING_MS: u64 = 24 * 60 * 60 * 1000;

/// Why a configuration was refused.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ConfigError {
    /// The kernel policy does not validate.
    #[error("kernel policy: {0}")]
    Policy(String),
    /// The ceiling is zero or above [`MAX_LIFETIME_CEILING_MS`].
    #[error("max lifetime must be between 1 ms and 24 hours")]
    MaxLifetime,
    /// A text field is empty, too long, or holds a control character.
    #[error("{0} is empty, too long, or holds a control character")]
    Text(&'static str),
    /// The resource roots are missing, the whole tree, or not valid paths.
    #[error("resource roots must be one or more valid paths other than \"/\"")]
    Roots,
    /// The kernel policy neither refuses arguments nor requires an execution
    /// binding, so a capability would cover arguments nothing binds (R-10).
    #[error("policy accepts arguments that no capability binds: set refuse_arguments or require_execution_binding")]
    UnsafePolicyPair,
    /// A cap is zero.
    #[error("every issuance cap must be at least 1")]
    DecisionLimit,
    /// The issuance log says it is not durable.
    #[error("the issuance log is not durable")]
    LogNotDurable,
}

/// How many capabilities the issuer allows, counted in the issuance log so the counts survive
/// a restart. All three are required and at least 1.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IssuanceCaps {
    /// The most capabilities one decision root may produce.
    pub per_decision: u32,
    /// The most capabilities one subject digest may produce across all of its decision
    /// roots. This is what stops a requester relabelling or reordering a decision to get a
    /// new root: the subject digest does not change. The price is that one piece of content
    /// can never be re-decided and re-issued beyond this number without an operator reset.
    pub per_subject: u32,
    /// The most distinct decision roots the log may hold. Past it the issuer refuses a
    /// decision it has not seen before, until the log is rotated with history. It bounds the
    /// log's memory and open time against a requester who mints roots.
    pub distinct_decisions: u32,
}

/// What the issuer needs to know, taken from one kernel policy. There is no
/// `Default`: every field is stated.
#[derive(Debug, Clone)]
pub struct IssuerConfig {
    pub(crate) issuer_id: String,
    pub(crate) audience: String,
    pub(crate) policy_ref: String,
    pub(crate) roster: RosterPolicy,
    pub(crate) operations: BTreeMap<String, WorkerKind>,
    pub(crate) limits: ExecutionLimits,
    pub(crate) canonical: Limits,
    pub(crate) max_lifetime_ms: u64,
    pub(crate) refuse_arguments: bool,
    pub(crate) roots: Vec<String>,
    pub(crate) caps: IssuanceCaps,
    pub(crate) policy_digest: Digest32,
}

fn text(name: &'static str, s: &str) -> Result<(), ConfigError> {
    if s.is_empty() || s.len() > 128 || s.chars().any(char::is_control) {
        return Err(ConfigError::Text(name));
    }
    Ok(())
}

impl IssuerConfig {
    /// Builds the issuer's policy from the kernel's.
    ///
    /// * `issuer_id` is the name the kernel's trust set knows this issuer by.
    /// * `policy_ref` is written into every capability.
    /// * `canonical` must be the Trident limits the kernel canonicalizes
    ///   arguments under (`TridentConfig::limits`), or the argument digests
    ///   will not agree.
    /// * `max_lifetime_ms` is the ceiling on any capability's lifetime. State
    ///   minutes, not hours (R-8).
    /// * `resource_roots` are the only trees a capability may cover (R-6): every
    ///   requested scope must equal a root or lie under one, on a path-segment
    ///   boundary, so a prefix wider than a root is refused. There is no
    ///   default, and `/` is refused as a root.
    ///
    /// * `caps` are the three issuance caps (see [`IssuanceCaps`]). They cover the records
    ///   the log knows about: rotating the log without carrying its history resets them
    ///   (see `FileIssuanceLog::open_with_history`). A requester can change the decision
    ///   root by altering the decision (see `DecisionVerifier`); the per-subject cap does
    ///   not depend on the root. There is no default.
    ///
    /// The `policy_ref` written into every capability is `{policy_ref}@sha256:{digest}`, where
    /// the digest covers the kernel policy this issuer was built from (see
    /// [`IssuerConfig::policy_digest`]), so drift from the kernel's policy shows in the audit
    /// log. `policy_ref` may be at most 184 bytes.
    ///
    /// The policy is copied when this is called. If the kernel's policy changes
    /// later, this one does not follow; the kernel then refuses what no longer
    /// matches (a worker, limits or roster mismatch), it does not accept it.
    pub fn from_kernel_policy(
        policy: &KernelPolicy,
        issuer_id: &str,
        policy_ref: &str,
        canonical: Limits,
        max_lifetime_ms: u64,
        resource_roots: &[&str],
        caps: IssuanceCaps,
    ) -> Result<Self, ConfigError> {
        policy.validate().map_err(|e| ConfigError::Policy(e.to_string()))?;
        if !policy.refuse_arguments && !policy.require_execution_binding {
            return Err(ConfigError::UnsafePolicyPair);
        }
        if caps.per_decision == 0 || caps.per_subject == 0 || caps.distinct_decisions == 0 {
            return Err(ConfigError::DecisionLimit);
        }
        if resource_roots.is_empty() || resource_roots.iter().any(|r| *r == "/" || validate_path(r).is_err()) {
            return Err(ConfigError::Roots);
        }
        text("issuer_id", issuer_id)?;
        if policy_ref.len() > 184 || policy_ref.chars().any(char::is_control) {
            return Err(ConfigError::Text("policy_ref"));
        }
        if max_lifetime_ms == 0 || max_lifetime_ms > MAX_LIFETIME_CEILING_MS {
            return Err(ConfigError::MaxLifetime);
        }
        Ok(Self {
            issuer_id: issuer_id.to_owned(),
            audience: policy.audience.clone(),
            policy_ref: format!("{policy_ref}@sha256:{}", policy_digest(policy).to_hex()),
            roster: policy.roster_policy(),
            operations: policy.operations.clone(),
            limits: policy.limits,
            canonical,
            max_lifetime_ms,
            refuse_arguments: policy.refuse_arguments,
            roots: resource_roots.iter().map(|r| (*r).to_owned()).collect(),
            caps,
            policy_digest: policy_digest(policy),
        })
    }
}

fn put(h: &mut Sha256, s: &str) {
    h.update(u32::try_from(s.len()).unwrap_or(u32::MAX).to_be_bytes());
    h.update(s.as_bytes());
}

/// SHA-256 over the kernel policy fields the issuer uses, with a domain tag and length-prefixed
/// fields in a fixed order: the audience; the required seats, sorted; the seat positions and the
/// operation map in key order; the execution limits' own binding digest; and three flags
/// (`refuse_arguments`, `require_execution_binding`, `require_one_time_capabilities`).
fn policy_digest(policy: &KernelPolicy) -> Digest32 {
    let mut h = Sha256::new();
    h.update(b"stack-issuer/policy/1\n");
    put(&mut h, &policy.audience);
    let mut seats: Vec<&String> = policy.required_seats.iter().collect();
    seats.sort();
    h.update(u32::try_from(seats.len()).unwrap_or(u32::MAX).to_be_bytes());
    for seat in seats {
        put(&mut h, seat);
    }
    h.update(u32::try_from(policy.seat_positions.len()).unwrap_or(u32::MAX).to_be_bytes());
    for (seat, position) in &policy.seat_positions {
        put(&mut h, seat);
        put(&mut h, position.as_str());
    }
    h.update(u32::try_from(policy.operations.len()).unwrap_or(u32::MAX).to_be_bytes());
    for (name, kind) in &policy.operations {
        put(&mut h, name);
        put(&mut h, kind.as_str());
    }
    h.update(policy.limits.binding_digest().as_bytes());
    h.update([
        u8::from(policy.refuse_arguments),
        u8::from(policy.require_execution_binding),
        u8::from(policy.require_one_time_capabilities),
    ]);
    Digest32::from_bytes(h.finalize().into())
}

impl IssuerConfig {
    /// The `policy_ref` written into every capability: the caller's text, then `@sha256:` and
    /// the policy digest.
    pub fn policy_ref(&self) -> &str {
        &self.policy_ref
    }

    /// The digest of the kernel policy this issuer was built from, as written into every
    /// capability's `policy_ref`.
    pub fn policy_digest(&self) -> Digest32 {
        self.policy_digest
    }
}
