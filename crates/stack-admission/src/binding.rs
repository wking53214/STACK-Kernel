//! CNS binding: the kernel recomputes what CNS bound and checks it
//! against its own policy. Nothing claimed by the payload is compared
//! with anything else claimed by the payload; every comparison has the
//! kernel's own recomputation on one side.
//!
//! * The subject digest is `cns.gate.subject_digest(subject)`, recomputed
//!   with `stack_trident::cns_digest` over the restricted domain.
//! * Every verdict must bind to that digest: its `digest` field equals the
//!   recomputed digest, and its `subject` names the same identity as every
//!   other verdict. A verdict bound to other content, or to nothing, is a
//!   verdict for something else.
//! * The decision root is `subject_digest({"seats", "verdicts"})`,
//!   recomputed with `stack_receipt::decision_root` (held to roots the real
//!   CNS SuperGate produced) and compared with the claimed root.
//! * The roster is checked against the kernel's required seats with
//!   `stack_receipt::check_authorized_decision`: non-empty, no duplicate,
//!   one bound PASS per seat, every required seat present and passed,
//!   alpha before omega, no verdict for an unseated gate.
//!
//! A decision that passes every check here still authorizes nothing. It
//! is one input the capability must agree with.

use serde_json::Value;
use stack_authority::Digest32;
use stack_receipt::{check_authorized_decision, decision_root, CnsValue, DecisionEvidence, DecisionFinding, RosterPolicy};
use stack_trident::canonical::{CanonicalError, Limits};
use stack_trident::cns_digest::subject_digest_raw;

use crate::payload::DecisionClaim;

/// One reason a decision is not bound to this subject under this policy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BindingFinding {
    /// The claimed root is not the root of the claimed seats and verdicts.
    RootMismatch,
    /// A verdict's `digest` is not the recomputed subject digest.
    VerdictNotBoundToSubject {
        /// The gate.
        gate: String,
    },
    /// The verdicts do not all name one subject identity.
    IdentityDisagreement,
    /// A roster or verdict problem under the kernel's policy.
    Decision(DecisionFinding),
}

/// The CNS subject digest of `subject`, recomputed over the restricted
/// domain. `None` when the content lies outside it (which the Trident's
/// grammar already refuses).
pub fn subject_digest(subject: &Value, limits: &Limits) -> Result<Digest32, CanonicalError> {
    subject_digest_raw(subject, limits).map(Digest32::from_bytes)
}

/// The one identity every bound verdict names, for the receipt's
/// `Subject.identity`. Falls back to a fixed label when no verdict is
/// bound; the binding check then refuses the decision anyway.
pub fn identity(claim: &DecisionClaim) -> String {
    claim
        .verdicts
        .iter()
        .find(|v| !v.subject.is_empty())
        .map_or_else(|| "unbound".to_owned(), |v| v.subject.clone())
}

/// The root of the claimed seats and verdicts, as the kernel computes it.
pub fn recomputed_root(claim: &DecisionClaim) -> Digest32 {
    decision_root(&claim.seats, &claim.verdicts)
}

/// The decision as receipt evidence: the claimed seats and verdicts with
/// the root the kernel recomputed from them, so a verifier recomputing
/// the root agrees and a refused request leaves a log that verifies. A
/// claimed root that differs is a binding finding
/// ([`BindingFinding::RootMismatch`]), recorded in the rejection reason;
/// writing the false root itself into the log would make the kernel's
/// honest record of a refusal read as a tampered log.
pub fn evidence(claim: &DecisionClaim, root: Digest32) -> DecisionEvidence {
    DecisionEvidence {
        root,
        seats: claim.seats.clone(),
        verdicts: claim.verdicts.clone(),
    }
}

/// Every reason `claim` is not a bound, policy-complete decision about
/// the content whose recomputed digest is `subject_digest`. Empty means
/// bound and complete. The recomputed root is the second value, for the
/// `ActionRequest`; it equals the claim's root whenever the findings are
/// empty.
pub fn check(claim: &DecisionClaim, subject_digest: &Digest32, policy: &RosterPolicy) -> (Vec<BindingFinding>, Digest32) {
    let mut out = Vec::new();
    let recomputed = recomputed_root(claim);
    if !recomputed.ct_eq(&claim.root) {
        out.push(BindingFinding::RootMismatch);
    }
    let expected_hex = subject_digest.to_hex();
    for v in &claim.verdicts {
        if v.digest != expected_hex {
            out.push(BindingFinding::VerdictNotBoundToSubject { gate: v.gate.clone() });
        }
    }
    let identities: Vec<&str> = claim.verdicts.iter().map(|v| v.subject.as_str()).collect();
    if identities.windows(2).any(|w| w[0] != w[1]) {
        out.push(BindingFinding::IdentityDisagreement);
    }
    out.extend(
        check_authorized_decision(&evidence(claim, recomputed), Some(policy))
            .into_iter()
            .map(BindingFinding::Decision),
    );
    (out, recomputed)
}

/// Converts restricted-domain JSON into the receipt verifier's CNS value,
/// so an auditor can hand the subject content to `Expectations`. `None`
/// for a float or an integer outside `i64`, which the restricted domain
/// never carries.
pub fn cns_value(v: &Value) -> Option<CnsValue> {
    Some(match v {
        Value::Null => CnsValue::Null,
        Value::Bool(b) => CnsValue::Bool(*b),
        Value::Number(n) => CnsValue::Int(n.as_i64()?),
        Value::String(s) => CnsValue::Str(s.clone()),
        Value::Array(items) => CnsValue::List(items.iter().map(cns_value).collect::<Option<Vec<_>>>()?),
        Value::Object(map) => CnsValue::Map(
            map.iter()
                .map(|(k, v)| cns_value(v).map(|v| (k.clone(), v)))
                .collect::<Option<_>>()?,
        ),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use stack_receipt::{GateOutcome, GatePosition, Verdict};

    fn limits() -> Limits {
        stack_trident::TridentConfig::default().limits()
    }

    #[test]
    fn the_two_digest_implementations_agree_on_restricted_content() {
        let v = json!({"doc": "x", "n": [1, -2, {"deep": [null, true, "é"]}], "z": {}});
        let trident = subject_digest(&v, &limits()).unwrap_or_else(|e| panic!("{e}"));
        let receipt = stack_receipt::subject_digest(&cns_value(&v).unwrap_or(CnsValue::Null));
        assert_eq!(trident, receipt);
        assert!(cns_value(&json!(1.5)).is_none());
    }

    #[test]
    fn a_bound_complete_decision_has_no_finding_and_everything_else_does() {
        let subject = json!({"doc": "x"});
        let digest = subject_digest(&subject, &limits()).unwrap_or_else(|e| panic!("{e}"));
        let verdict = |gate: &str, position, outcome| Verdict {
            gate: gate.into(),
            position,
            outcome,
            subject: "x".into(),
            digest: digest.to_hex(),
        };
        let seats = vec!["Governance_Gateway:door".to_owned(), "DIT:judge".to_owned()];
        let verdicts = vec![
            verdict("door", GatePosition::Alpha, GateOutcome::Pass),
            verdict("judge", GatePosition::Omega, GateOutcome::Pass),
        ];
        let claim = DecisionClaim {
            root: decision_root(&seats, &verdicts),
            seats,
            verdicts,
        };
        let policy = RosterPolicy {
            required_seats: vec!["Governance_Gateway:door".into(), "DIT:judge".into()],
        };
        let (findings, root) = check(&claim, &digest, &policy);
        assert!(findings.is_empty(), "{findings:?}");
        assert_eq!(root, claim.root);
        assert_eq!(identity(&claim), "x");

        let mut bad_root = claim.clone();
        bad_root.root = Digest32::from_bytes([0; 32]);
        assert_eq!(check(&bad_root, &digest, &policy).0, vec![BindingFinding::RootMismatch]);

        let other = Digest32::from_bytes([1; 32]);
        let (f, _) = check(&claim, &other, &policy);
        assert_eq!(
            f,
            vec![
                BindingFinding::VerdictNotBoundToSubject { gate: "door".into() },
                BindingFinding::VerdictNotBoundToSubject { gate: "judge".into() },
            ]
        );

        let mut split = claim.clone();
        split.verdicts[1].subject = "y".into();
        split.root = decision_root(&split.seats, &split.verdicts);
        assert_eq!(check(&split, &digest, &policy).0, vec![BindingFinding::IdentityDisagreement]);

        let stricter = RosterPolicy {
            required_seats: vec!["HERALD:confidence".into()],
        };
        assert_eq!(
            check(&claim, &digest, &stricter).0,
            vec![BindingFinding::Decision(DecisionFinding::RequiredSeatMissing("HERALD:confidence".into()))]
        );

        let empty = DecisionClaim {
            seats: vec![],
            verdicts: vec![],
            root: decision_root(&[], &[]),
        };
        let (f, _) = check(&empty, &digest, &policy);
        assert_eq!(f[0], BindingFinding::Decision(DecisionFinding::EmptyRoster));
        assert_eq!(identity(&empty), "unbound");
    }
}
