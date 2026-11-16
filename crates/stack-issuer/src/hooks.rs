//! The two hooks a deployment must supply. Neither has a default, and this crate
//! ships no implementation that allows anything.
//!
//! * [`DecisionVerifier`] answers the question the issuer cannot: is this decision
//!   real, that is, did CNS produce it? The CNS proof is an HMAC under a key local
//!   to the CNS process, so the check needs a channel to CNS that does not exist in
//!   this repository.
//! * [`Authorizer`] answers who may be issued what. The CNS decision is about a
//!   subject, not about an operation or a scope, so a passing decision says nothing
//!   about the requester.
//!
//! The issuer calls them after its own structural checks and before it takes entropy,
//! reads the clock or asks the signer for anything: the authorizer first (local policy),
//! then the verifier (probably a call to CNS), so a requester the policy refuses does not
//! cost a lookup. A refusal from either means no capability and no log record.
//!
//! Contract for both traits:
//! * They are called concurrently from any thread (`Send + Sync`) and may be called for a
//!   request that is then refused later (by the verifier, the cap, the signer or the
//!   log). A hook with side effects, such as a quota or a one-time ticket, must expect that.
//! * There is no timeout. A hook that hangs hangs `issue`; bound your own calls.
//! * `Refusal` is the only failure shape: an outage and a forged decision look the same to
//!   the caller. Do not forward the text to a requester. It can name roster seats and
//!   internal policy.
//! * Both require `Debug`, and `Issuer` derives `Debug`. A hook that holds a key must not
//!   derive `Debug` over it.

use std::fmt;

use stack_admission::DecisionClaim;
use stack_authority::{Digest32, ResourceScope};

/// Why a hook said no. The text is for the operator's log, not for the requester.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{0}")]
pub struct Refusal(pub String);

/// Checks that a CNS decision is genuine.
///
/// The cap on capabilities per decision is counted per decision *root*. A requester who
/// holds one genuine decision can change a verdict's identity label or add a PASS verdict
/// for an extra seat and recompute the root, and the result still passes the structural
/// checks. Only a verifier that accepts exactly the roots CNS produced makes the cap mean
/// anything; this trait receives no CNS proof, so such a verifier must look the root up
/// out of band.
pub trait DecisionVerifier: Send + Sync + fmt::Debug {
    /// `subject_digest` and `decision_root` are the values the issuer recomputed,
    /// never the requester's claims. `decision` is the claim as received.
    fn verify(&self, subject_digest: &Digest32, decision: &DecisionClaim, decision_root: &Digest32) -> Result<(), Refusal>;
}

/// What the issuer is about to grant, for the authorizer to judge.
#[derive(Debug, Clone, Copy)]
pub struct AuthorizationRequest<'a> {
    /// Who asked, as the caller named them. Authenticating them is the caller's job.
    pub requester: &'a str,
    /// The operation.
    pub operation: &'a str,
    /// The scopes, as requested (already inside the configured roots).
    pub resources: &'a [ResourceScope],
    /// How long the capability will live, in milliseconds from issue.
    pub lifetime_ms: u64,
    /// The digest of the canonical arguments that will be bound.
    pub args_digest: &'a Digest32,
    /// The recomputed subject digest.
    pub subject_digest: &'a Digest32,
    /// The recomputed decision root.
    pub decision_root: &'a Digest32,
}

/// Decides whether this requester may be issued this capability.
pub trait Authorizer: Send + Sync + fmt::Debug {
    /// `Ok` allows; `Err` refuses and nothing is issued.
    fn authorize(&self, request: &AuthorizationRequest<'_>) -> Result<(), Refusal>;
}

/// A verifier for a deployment that has no channel to CNS yet: it refuses every
/// decision, so nothing is issued. Use it to run the issuer until a real verifier
/// exists, or write your own and own the consequence.
#[derive(Debug, Clone, Copy, Default)]
pub struct RefuseAllDecisions;

impl DecisionVerifier for RefuseAllDecisions {
    fn verify(&self, _: &Digest32, _: &DecisionClaim, _: &Digest32) -> Result<(), Refusal> {
        Err(Refusal("no verification channel to CNS is configured".into()))
    }
}

/// An authorizer that refuses every request.
#[derive(Debug, Clone, Copy, Default)]
pub struct DenyAllRequests;

impl Authorizer for DenyAllRequests {
    fn authorize(&self, _: &AuthorizationRequest<'_>) -> Result<(), Refusal> {
        Err(Refusal("no authorization policy is configured".into()))
    }
}
