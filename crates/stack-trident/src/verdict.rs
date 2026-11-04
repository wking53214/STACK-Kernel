//! What the Trident returns: an accepted handoff with typed, re-derived
//! fields, or a refusal naming every failed check.

use serde_json::Value;

use crate::config::DeploymentProfile;
use crate::envelope::Nonce;
use crate::keys::Fingerprint;
use crate::vocab::{Check, GateOutcome, GatePosition, ReasonCode, Resolution};

/// How much an acceptance may be relied on, decided by the profile of
/// the Trident that made it. The checks are the same under both; what
/// differs is what the deployment was allowed to assume (audience
/// binding, durable replay state, key metadata). A consumer that must
/// not act on a development acceptance calls
/// [`VerifiedHandoff::require_production`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Assurance {
    /// Made by a [`DeploymentProfile::Development`] Trident.
    Development,
    /// Made by a [`DeploymentProfile::Production`] Trident: audience
    /// bound, durable replay store, epoch floor on, every key carrying
    /// issuer metadata.
    Production,
}

impl Assurance {
    /// The assurance a Trident with this profile gives.
    pub const fn of(profile: DeploymentProfile) -> Self {
        match profile {
            DeploymentProfile::Development => Self::Development,
            DeploymentProfile::Production => Self::Production,
        }
    }

    /// Log and label spelling.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Development => "development",
            Self::Production => "production",
        }
    }
}

/// Returned by [`VerifiedHandoff::require_production`] for an acceptance
/// made under the Development profile.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("handoff was accepted with development assurance; production assurance is required")]
pub struct DevelopmentAssurance;

/// An envelope that passed all three prongs. Every field here was either
/// re-derived by the receiver or authenticated under the sender's key.
///
/// What this proves: the envelope was sealed by a holder of the key with
/// fingerprint `sender`, binds `payload`, and was not seen before by this
/// receiver. A valid HMAC proves possession of a shared key, not who the
/// holder is and not that the action was legitimate; both belong to the
/// layer that issued the key and the layer that judges the payload.
#[derive(Debug, Clone, PartialEq)]
pub struct VerifiedHandoff {
    /// Profile of the Trident that accepted it. See [`Assurance`].
    pub assurance: Assurance,
    /// Authenticated sender.
    pub sender: Fingerprint,
    /// Accepted sequence number (now the sender's high-water mark).
    pub sequence: u64,
    /// Issue time, within the skew window.
    pub issued_at_unix_ms: u64,
    /// The nonce, now in the replay cache.
    pub nonce: Nonce,
    /// The sender's gate position.
    pub gate_position: GatePosition,
    /// The sender's gate verdict, carried as an authenticated claim. The
    /// Trident does not re-judge it; a `terminal_breach` here means the
    /// sender's own gate refused its subject. It is folded into
    /// [`Verdict::outcome`], so a consumer that acts on the outcome never
    /// reads it as PASS.
    pub gate_outcome: GateOutcome,
    /// SHA-256 of the canonical payload, as recomputed by the receiver.
    pub subject_digest: String,
    /// The payload.
    pub payload: Value,
}

impl VerifiedHandoff {
    /// Whether this acceptance carries [`Assurance::Production`].
    pub fn is_production(&self) -> bool {
        self.assurance == Assurance::Production
    }

    /// Refuses a development-assurance acceptance. Admission code that
    /// acts on handoffs calls this before acting, so a Trident that was
    /// allowed to assume things (no audience, no durable state) can never
    /// authorise anything downstream.
    pub fn require_production(&self) -> Result<&Self, DevelopmentAssurance> {
        if self.is_production() {
            Ok(self)
        } else {
            Err(DevelopmentAssurance)
        }
    }
}

/// Why an envelope was refused and what happened to receiver state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Refusal {
    /// CNS resolution of `reasons`: any terminal breach wins, then retry.
    pub outcome: GateOutcome,
    /// What changed on the receiver.
    pub resolution: Resolution,
    /// Every reported failure, in check order. For envelopes that got past
    /// admission and custody, this holds the failures of all three prongs,
    /// not just the first. At most one entry per [`ReasonCode`].
    pub reasons: Vec<ReasonCode>,
}

impl Refusal {
    /// The distinct checks that failed, in order.
    pub fn failed_checks(&self) -> Vec<Check> {
        let mut v: Vec<Check> = self.reasons.iter().map(|r| r.check()).collect();
        v.sort();
        v.dedup();
        v
    }

    /// The distinct prong numbers (1, 2, 3) that failed.
    pub fn failed_prongs(&self) -> Vec<u8> {
        self.failed_checks().into_iter().filter_map(Check::prong).collect()
    }

    /// Whether `reason` is among the reported failures.
    pub fn has(&self, reason: ReasonCode) -> bool {
        self.reasons.contains(&reason)
    }
}

/// The Trident's decision on one envelope.
#[derive(Debug, Clone, PartialEq)]
pub enum Verdict {
    /// All three prongs passed and the sender's freshness state advanced.
    Accepted(Box<VerifiedHandoff>),
    /// Refused. See [`Refusal`].
    Refused(Refusal),
}

impl Verdict {
    /// The decision value: PASS, RETRY or TERMINAL_BREACH. This is what a
    /// consumer acts on. For a refusal it is the refusal's outcome. For an
    /// accepted envelope it is the CNS resolution of the Trident's PASS and
    /// the sender's authenticated `gate_outcome`, so an envelope whose
    /// sender gate said TERMINAL_BREACH (or RETRY) is accepted as authentic
    /// and fresh but still yields TERMINAL_BREACH (or RETRY) here.
    pub fn outcome(&self) -> GateOutcome {
        match self {
            Self::Accepted(h) => GateOutcome::resolve([GateOutcome::Pass, h.gate_outcome]),
            Self::Refused(r) => r.outcome,
        }
    }

    /// The Trident's own result, ignoring the sender's gate claim: PASS
    /// for every accepted envelope. Used for telemetry labels. Do not use
    /// it to decide whether to act on a handoff; use [`Verdict::outcome`].
    pub fn check_outcome(&self) -> GateOutcome {
        match self {
            Self::Accepted(_) => GateOutcome::Pass,
            Self::Refused(r) => r.outcome,
        }
    }

    /// Whether the envelope was accepted.
    pub fn is_accepted(&self) -> bool {
        matches!(self, Self::Accepted(_))
    }

    /// The refusal, if refused.
    pub fn refusal(&self) -> Option<&Refusal> {
        match self {
            Self::Accepted(_) => None,
            Self::Refused(r) => Some(r),
        }
    }

    /// The accepted handoff, if accepted.
    pub fn accepted(&self) -> Option<&VerifiedHandoff> {
        match self {
            Self::Accepted(h) => Some(h),
            Self::Refused(_) => None,
        }
    }

    /// Reported reasons (empty when accepted).
    pub fn reasons(&self) -> &[ReasonCode] {
        match self {
            Self::Accepted(_) => &[],
            Self::Refused(r) => &r.reasons,
        }
    }

    pub(crate) fn refuse(reasons: Vec<ReasonCode>, resolution: Resolution) -> Self {
        let outcome = GateOutcome::resolve(reasons.iter().map(|r| r.outcome()));
        // Fail closed: a refusal with no reasons would resolve to PASS.
        let outcome = if outcome == GateOutcome::Pass {
            GateOutcome::Retry
        } else {
            outcome
        };
        Self::Refused(Refusal {
            outcome,
            resolution,
            reasons,
        })
    }
}
