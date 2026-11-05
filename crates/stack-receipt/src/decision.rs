//! The governing decision as evidence: recomputing the CNS decision root
//! from the roster and the verdicts, and checking the roster against the
//! verifier's own policy.
//!
//! `cns_composition.super_gate._root` is
//! `subject_digest({"seats": [...], "verdicts": [{"gate", "position",
//! "outcome", "subject", "digest"}, ...]})`. A root that recomputes
//! proves that these seats and these verdicts are what the root names.
//! It does not prove that `SuperGate.decide` issued the decision: that
//! proof is an HMAC under a process-local key in CNS, unverifiable here,
//! and the verifier says so.
//!
//! A CNS root does not commit to the *required* roster (register D-11):
//! `required` is enforced only in the process that built the `SuperGate`.
//! So the verifier takes its own [`RosterPolicy`] and checks the recorded
//! roster against it, rather than trusting the record to say which seats
//! were required.

use crate::cns::{subject_digest, CnsValue};
use crate::record::{DecisionEvidence, GateOutcome, GatePosition, Verdict};
use stack_authority::Digest32;

/// The CNS value whose digest is the decision root.
pub fn root_content(seats: &[String], verdicts: &[Verdict]) -> CnsValue {
    let mut map = std::collections::BTreeMap::new();
    map.insert("seats".to_owned(), CnsValue::texts(seats.iter().map(String::as_str)));
    let verdicts: Vec<CnsValue> = verdicts
        .iter()
        .map(|v| {
            let mut m = std::collections::BTreeMap::new();
            m.insert("gate".to_owned(), CnsValue::text(&v.gate));
            m.insert("position".to_owned(), CnsValue::text(v.position.as_str()));
            m.insert("outcome".to_owned(), CnsValue::text(v.outcome.as_str()));
            m.insert("subject".to_owned(), CnsValue::text(&v.subject));
            m.insert("digest".to_owned(), CnsValue::text(&v.digest));
            CnsValue::Map(m)
        })
        .collect();
    map.insert("verdicts".to_owned(), CnsValue::List(verdicts));
    CnsValue::Map(map)
}

/// `super_gate._root(seats, results)`.
pub fn decision_root(seats: &[String], verdicts: &[Verdict]) -> Digest32 {
    subject_digest(&root_content(seats, verdicts))
}

impl DecisionEvidence {
    /// The root these seats and verdicts give.
    pub fn recomputed_root(&self) -> Digest32 {
        decision_root(&self.seats, &self.verdicts)
    }

    /// Whether the recorded root is the recomputed one.
    pub fn root_matches(&self) -> bool {
        self.root.ct_eq(&self.recomputed_root())
    }
}

/// The verifier's own roster policy: the seats that must be on the
/// roster and must have passed, as `repository:gate`.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct RosterPolicy {
    /// Required seats.
    pub required_seats: Vec<String>,
    /// The position each listed required seat must hold. A required seat
    /// that is not listed has its position left unchecked, so a verifier
    /// that wants the position enforced lists every seat.
    pub seat_positions: std::collections::BTreeMap<String, GatePosition>,
}

impl RosterPolicy {
    /// A policy requiring these seats, with no position constraint.
    pub fn new<I, S>(required_seats: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        Self {
            required_seats: required_seats.into_iter().map(Into::into).collect(),
            seat_positions: std::collections::BTreeMap::new(),
        }
    }

    /// This policy with `seat` required to hold `position`.
    #[must_use]
    pub fn with_position(mut self, seat: &str, position: GatePosition) -> Self {
        self.seat_positions.insert(seat.to_owned(), position);
        self
    }
}

/// One thing wrong with a decision that an `Authorized` execution relied
/// on. Every variant is a reason to reject the receipt as evidence of an
/// authorized action.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DecisionFinding {
    /// No seats at all.
    EmptyRoster,
    /// A seat appears twice.
    DuplicateSeat(String),
    /// A policy-required seat is not on the roster.
    RequiredSeatMissing(String),
    /// A policy-required seat has no PASS verdict.
    RequiredSeatNotPassed(String),
    /// A verdict other than PASS.
    VerdictNotPass {
        /// The gate.
        gate: String,
        /// What it said.
        outcome: GateOutcome,
    },
    /// A PASS verdict that does not record what it judged.
    VerdictUnbound(String),
    /// A verdict for a gate that holds no seat.
    VerdictForUnseatedGate(String),
    /// Fewer or more verdicts than seats: the run was not complete, or
    /// something was added.
    VerdictCountMismatch {
        /// Seats on the roster.
        seats: usize,
        /// Verdicts recorded.
        verdicts: usize,
    },
    /// An omega verdict precedes an alpha one; CNS runs every alpha gate
    /// first.
    OmegaBeforeAlpha,
    /// Two verdicts name the same gate: one seat cannot be judged twice,
    /// and a second verdict can stand in for another seat's.
    DuplicateVerdict(String),
    /// A roster seat has no verdict (reported when the counts agree, so a
    /// repeated verdict cannot hide it; a short run is a
    /// [`Self::VerdictCountMismatch`]).
    SeatNotJudged(String),
    /// Two different seats share one gate name, so a verdict cannot say
    /// which of them it judged.
    DuplicateGateName(String),
    /// A policy-required seat's verdict is at another position than the
    /// policy expects.
    RequiredSeatWrongPosition {
        /// The seat.
        seat: String,
        /// The position the policy expects.
        expected: GatePosition,
        /// The position the verdict recorded.
        found: GatePosition,
    },
}

/// The gate name of a seat written as `repository:gate`.
pub fn seat_gate(seat: &str) -> &str {
    seat.split_once(':').map_or(seat, |(_, gate)| gate)
}

/// Checks a decision an `Authorized` execution relied on: non-empty
/// roster without duplicate seats or shared gate names, exactly one
/// verdict per seat (never two for one gate) and none for an unseated
/// gate, every verdict PASS and bound, alpha before omega, and
/// every policy-required seat present with a PASS verdict at the position
/// the policy states for it. Returns every
/// finding, in a fixed order.
pub fn check_authorized_decision(d: &DecisionEvidence, policy: Option<&RosterPolicy>) -> Vec<DecisionFinding> {
    let mut out = Vec::new();
    if d.seats.is_empty() {
        out.push(DecisionFinding::EmptyRoster);
    }
    for (i, seat) in d.seats.iter().enumerate() {
        if d.seats.iter().take(i).any(|s| s == seat) {
            out.push(DecisionFinding::DuplicateSeat(seat.clone()));
        }
    }
    for (i, seat) in d.seats.iter().enumerate() {
        let gate = seat_gate(seat);
        let clash = d.seats.iter().take(i).any(|s| s != seat && seat_gate(s) == gate);
        if clash && !out.contains(&DecisionFinding::DuplicateGateName(gate.to_owned())) {
            out.push(DecisionFinding::DuplicateGateName(gate.to_owned()));
        }
    }
    for (i, v) in d.verdicts.iter().enumerate() {
        let repeated = d.verdicts.iter().take(i).any(|w| w.gate == v.gate);
        if repeated && !out.contains(&DecisionFinding::DuplicateVerdict(v.gate.clone())) {
            out.push(DecisionFinding::DuplicateVerdict(v.gate.clone()));
        }
    }
    if d.seats.len() != d.verdicts.len() {
        out.push(DecisionFinding::VerdictCountMismatch {
            seats: d.seats.len(),
            verdicts: d.verdicts.len(),
        });
    } else {
        for seat in &d.seats {
            if !d.verdicts.iter().any(|v| v.gate == seat_gate(seat)) {
                out.push(DecisionFinding::SeatNotJudged(seat.clone()));
            }
        }
    }
    let mut seen_omega = false;
    for v in &d.verdicts {
        match v.position {
            GatePosition::Omega => seen_omega = true,
            GatePosition::Alpha => {
                if seen_omega && !out.contains(&DecisionFinding::OmegaBeforeAlpha) {
                    out.push(DecisionFinding::OmegaBeforeAlpha);
                }
            }
        }
        if v.outcome != GateOutcome::Pass {
            out.push(DecisionFinding::VerdictNotPass {
                gate: v.gate.clone(),
                outcome: v.outcome,
            });
        } else if !v.is_bound() {
            out.push(DecisionFinding::VerdictUnbound(v.gate.clone()));
        }
        if !d.seats.iter().any(|s| seat_gate(s) == v.gate) {
            out.push(DecisionFinding::VerdictForUnseatedGate(v.gate.clone()));
        }
    }
    if let Some(policy) = policy {
        for required in &policy.required_seats {
            if !d.seats.iter().any(|s| s == required) {
                out.push(DecisionFinding::RequiredSeatMissing(required.clone()));
                continue;
            }
            let gate = seat_gate(required);
            let passed = d
                .verdicts
                .iter()
                .any(|v| v.gate == gate && v.outcome == GateOutcome::Pass && v.is_bound());
            if !passed {
                out.push(DecisionFinding::RequiredSeatNotPassed(required.clone()));
            }
            if let Some(expected) = policy.seat_positions.get(required) {
                if let Some(v) = d.verdicts.iter().find(|v| v.gate == gate && v.position != *expected) {
                    out.push(DecisionFinding::RequiredSeatWrongPosition {
                        seat: required.clone(),
                        expected: *expected,
                        found: v.position,
                    });
                }
            }
        }
    }
    out
}
