//! The issuer's policy, derived from the kernel's so the two cannot drift (R-5).

use std::collections::BTreeMap;

use stack_admission::{ExecutionLimits, KernelPolicy, WorkerKind};
use stack_authority::validate_path;
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
    /// The issuance log says it is not durable.
    #[error("the issuance log is not durable")]
    LogNotDurable,
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
    ) -> Result<Self, ConfigError> {
        policy.validate().map_err(|e| ConfigError::Policy(e.to_string()))?;
        if !policy.refuse_arguments && !policy.require_execution_binding {
            return Err(ConfigError::UnsafePolicyPair);
        }
        if resource_roots.is_empty() || resource_roots.iter().any(|r| *r == "/" || validate_path(r).is_err()) {
            return Err(ConfigError::Roots);
        }
        text("issuer_id", issuer_id)?;
        if policy_ref.len() > 256 || policy_ref.chars().any(char::is_control) {
            return Err(ConfigError::Text("policy_ref"));
        }
        if max_lifetime_ms == 0 || max_lifetime_ms > MAX_LIFETIME_CEILING_MS {
            return Err(ConfigError::MaxLifetime);
        }
        Ok(Self {
            issuer_id: issuer_id.to_owned(),
            audience: policy.audience.clone(),
            policy_ref: policy_ref.to_owned(),
            roster: policy.roster_policy(),
            operations: policy.operations.clone(),
            limits: policy.limits,
            canonical,
            max_lifetime_ms,
            refuse_arguments: policy.refuse_arguments,
            roots: resource_roots.iter().map(|r| (*r).to_owned()).collect(),
        })
    }
}
