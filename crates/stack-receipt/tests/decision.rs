//! Decision root recomputation against roots the real CNS SuperGate
//! produced, and the roster policy checks.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use common::*;
use serde_json::Value;
use stack_receipt::{
    canonical_rendering, check_authorized_decision, decision_root, root_content, seat_gate, DecisionEvidence,
    DecisionFinding, Digest32, GateOutcome, GatePosition, RosterPolicy, Verdict,
};

fn load_cases() -> Vec<Value> {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/cns-decision-roots.json");
    let file: Value = serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
    assert_eq!(file["schema"].as_str(), Some("stack-receipt-cns-decision-roots/1"));
    assert_eq!(
        file["cns_commit"].as_str(),
        Some("4acd8f958a091900d43f553eba7fe83f7d33c4d6"),
        "the fixture names the CNS commit it was produced at"
    );
    file["cases"].as_array().unwrap().clone()
}

fn evidence(case: &Value) -> DecisionEvidence {
    DecisionEvidence {
        root: Digest32::from_hex(case["root"].as_str().unwrap()).unwrap(),
        seats: case["seats"]
            .as_array()
            .unwrap()
            .iter()
            .map(|s| s.as_str().unwrap().to_owned())
            .collect(),
        verdicts: case["verdicts"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| Verdict {
                gate: v["gate"].as_str().unwrap().to_owned(),
                position: GatePosition::parse(v["position"].as_str().unwrap()).unwrap(),
                outcome: GateOutcome::parse(v["outcome"].as_str().unwrap()).unwrap(),
                subject: v["subject"].as_str().unwrap().to_owned(),
                digest: v["digest"].as_str().unwrap().to_owned(),
            })
            .collect(),
    }
}

const CASE_COUNT: usize = 7;

#[test]
fn every_real_cns_root_is_recomputed_exactly() {
    let cases = load_cases();
    assert_eq!(cases.len(), CASE_COUNT);
    let mut roots = std::collections::BTreeSet::new();
    for case in &cases {
        let name = case["name"].as_str().unwrap();
        let d = evidence(case);
        assert_eq!(d.recomputed_root(), d.root, "{name}");
        assert!(d.root_matches(), "{name}");
        assert_eq!(decision_root(&d.seats, &d.verdicts), d.root, "{name}");
        assert!(roots.insert(d.root), "{name}: roots are distinct");
    }
}

#[test]
fn the_root_content_is_the_cns_map_of_seats_and_verdicts() {
    let d = evidence(&load_cases()[0]);
    let rendering = canonical_rendering(&root_content(&d.seats, &d.verdicts));
    assert!(rendering.starts_with("d:2:s:5:seatsl:2:s:23:Governance_Gateway:doors:9:DIT:judges:8:verdictsl:2:d:5:"));
    assert!(rendering.contains("s:6:digests:64:"));
    assert!(rendering.contains("s:4:gates:4:door"));
    assert!(rendering.contains("s:7:outcomes:4:pass"));
    assert!(rendering.contains("s:8:positions:5:alpha"));
    assert!(rendering.contains("s:7:subjects:4:door"));
}

#[test]
fn any_change_to_seats_or_verdicts_changes_the_root() {
    let d = evidence(&load_cases()[0]);
    let mut variants: Vec<DecisionEvidence> = Vec::new();
    let mut v = d.clone();
    v.seats.reverse();
    variants.push(v);
    let mut v = d.clone();
    v.seats.push("CNS:same_subject".into());
    variants.push(v);
    let mut v = d.clone();
    v.verdicts.reverse();
    variants.push(v);
    let mut v = d.clone();
    v.verdicts[1].outcome = GateOutcome::Retry;
    variants.push(v);
    let mut v = d.clone();
    v.verdicts[1].outcome = GateOutcome::TerminalBreach;
    variants.push(v);
    let mut v = d.clone();
    v.verdicts[0].position = GatePosition::Omega;
    variants.push(v);
    let mut v = d.clone();
    v.verdicts[0].subject = String::new();
    variants.push(v);
    let mut v = d.clone();
    v.verdicts[0].digest = String::new();
    variants.push(v);
    let mut v = d.clone();
    v.verdicts[0].gate = "doo".into();
    variants.push(v);
    let mut v = d.clone();
    v.verdicts.pop();
    variants.push(v);
    for (i, v) in variants.iter().enumerate() {
        assert!(!v.root_matches(), "variant {i}");
        assert_ne!(v.recomputed_root(), d.root, "variant {i}");
    }
}

fn policy(seats: &[&str]) -> RosterPolicy {
    RosterPolicy {
        required_seats: seats.iter().map(|s| (*s).to_owned()).collect(),
        ..RosterPolicy::default()
    }
}

#[test]
fn real_decisions_are_judged_as_cns_judged_them() {
    let cases = load_cases();
    let by_name = |n: &str| {
        cases
            .iter()
            .find(|c| c["name"].as_str() == Some(n))
            .unwrap_or_else(|| panic!("{n}"))
    };
    let full = policy(&["Governance_Gateway:door", "DIT:judge"]);

    let c = by_name("two_seats_all_pass");
    assert_eq!(c["allowed"].as_bool(), Some(true));
    assert_eq!(check_authorized_decision(&evidence(c), Some(&full)), vec![]);
    assert_eq!(check_authorized_decision(&evidence(c), None), vec![]);

    let c = by_name("three_seats_with_same_subject");
    assert_eq!(c["allowed"].as_bool(), Some(true));
    let three = policy(&["Governance_Gateway:door", "DIT:judge", "CNS:same_subject"]);
    assert_eq!(check_authorized_decision(&evidence(c), Some(&three)), vec![]);
    assert_eq!(
        evidence(c).seats,
        ["CNS:same_subject", "Governance_Gateway:door", "DIT:judge"],
        "the super gate seats same_subject first"
    );

    let c = by_name("omega_retry");
    assert_eq!(c["allowed"].as_bool(), Some(false));
    assert_eq!(
        check_authorized_decision(&evidence(c), Some(&full)),
        vec![
            DecisionFinding::VerdictNotPass {
                gate: "judge".into(),
                outcome: GateOutcome::Retry
            },
            DecisionFinding::RequiredSeatNotPassed("DIT:judge".into()),
        ]
    );

    let c = by_name("alpha_breach_omega_not_run");
    assert_eq!(c["allowed"].as_bool(), Some(false));
    let e = evidence(c);
    assert_eq!(e.verdicts.len(), 1, "CNS does not run omega after an alpha breach");
    assert_eq!(
        check_authorized_decision(&e, Some(&full)),
        vec![
            DecisionFinding::VerdictCountMismatch { seats: 2, verdicts: 1 },
            DecisionFinding::VerdictNotPass {
                gate: "door".into(),
                outcome: GateOutcome::TerminalBreach
            },
            DecisionFinding::RequiredSeatNotPassed("Governance_Gateway:door".into()),
            DecisionFinding::RequiredSeatNotPassed("DIT:judge".into()),
        ]
    );

    let c = by_name("unbound_pass");
    assert_eq!(c["allowed"].as_bool(), Some(false), "CNS: a pass that binds to nothing is not a go");
    assert_eq!(
        check_authorized_decision(&evidence(c), Some(&full)),
        vec![
            DecisionFinding::VerdictUnbound("door".into()),
            DecisionFinding::RequiredSeatNotPassed("Governance_Gateway:door".into()),
        ]
    );

    let c = by_name("seat_order_differs_from_run_order");
    assert_eq!(c["allowed"].as_bool(), Some(true));
    let e = evidence(c);
    assert_eq!(e.seats, ["DIT:judge", "HERALD:source", "HERALD:confidence"]);
    assert_eq!(
        e.verdicts.iter().map(|v| v.position).collect::<Vec<_>>(),
        [GatePosition::Alpha, GatePosition::Omega, GatePosition::Omega],
        "CNS runs alpha first whatever the seat order"
    );
    let herald = policy(&["HERALD:source", "HERALD:confidence", "DIT:judge"]);
    assert_eq!(check_authorized_decision(&e, Some(&herald)), vec![]);

    let c = by_name("unicode_candidate");
    assert_eq!(check_authorized_decision(&evidence(c), Some(&full)), vec![]);
}

#[test]
fn synthetic_rosters_are_refused_for_each_named_reason() {
    let base = evidence(&load_cases()[0]);
    let full = policy(&["Governance_Gateway:door", "DIT:judge"]);

    let mut empty = base.clone();
    empty.seats.clear();
    let f = check_authorized_decision(&empty, Some(&full));
    assert_eq!(f[0], DecisionFinding::EmptyRoster);
    assert!(f.contains(&DecisionFinding::VerdictCountMismatch { seats: 0, verdicts: 2 }));
    assert!(f.contains(&DecisionFinding::VerdictForUnseatedGate("door".into())));
    assert!(f.contains(&DecisionFinding::RequiredSeatMissing("Governance_Gateway:door".into())));

    let mut missing = base.clone();
    missing.seats.remove(1);
    missing.verdicts.remove(1);
    assert_eq!(
        check_authorized_decision(&missing, Some(&full)),
        vec![DecisionFinding::RequiredSeatMissing("DIT:judge".into())]
    );
    assert_eq!(check_authorized_decision(&missing, None), vec![], "no policy, no requirement");

    let mut dup = base.clone();
    dup.seats.push("DIT:judge".into());
    let f = check_authorized_decision(&dup, Some(&full));
    assert!(f.contains(&DecisionFinding::DuplicateSeat("DIT:judge".into())));
    assert!(f.contains(&DecisionFinding::VerdictCountMismatch { seats: 3, verdicts: 2 }));

    let mut reordered = base.clone();
    reordered.verdicts.reverse();
    assert_eq!(
        check_authorized_decision(&reordered, Some(&full)),
        vec![DecisionFinding::OmegaBeforeAlpha]
    );

    let mut extra = base.clone();
    extra.verdicts.push(Verdict {
        gate: "unchanged".into(),
        position: GatePosition::Omega,
        outcome: GateOutcome::TerminalBreach,
        subject: String::new(),
        digest: String::new(),
    });
    let f = check_authorized_decision(&extra, Some(&full));
    assert!(f.contains(&DecisionFinding::VerdictCountMismatch { seats: 2, verdicts: 3 }));
    assert!(f.contains(&DecisionFinding::VerdictNotPass {
        gate: "unchanged".into(),
        outcome: GateOutcome::TerminalBreach
    }));
    assert!(f.contains(&DecisionFinding::VerdictForUnseatedGate("unchanged".into())));

    let other_repo = policy(&["DGK:door"]);
    assert_eq!(
        check_authorized_decision(&base, Some(&other_repo)),
        vec![DecisionFinding::RequiredSeatMissing("DGK:door".into())],
        "a seat is repository and gate, not the gate name alone"
    );
    assert_eq!(seat_gate("DGK:door"), "door");
    assert_eq!(seat_gate("door"), "door");
    assert_eq!(seat_gate("a:b:c"), "b:c");
}

#[test]
fn the_shared_fixture_decision_recomputes_and_differs_from_every_real_root() {
    let d = decision();
    assert!(d.root_matches());
    for case in load_cases() {
        assert_ne!(evidence(&case).root, d.root);
    }
}

// ---------------------------------------------------------------------------
// Roster shape: one bound verdict per seat, gate names unique, positions
// ---------------------------------------------------------------------------

fn verdict(gate: &str, position: GatePosition) -> Verdict {
    Verdict {
        gate: gate.into(),
        position,
        outcome: GateOutcome::Pass,
        subject: "x".into(),
        digest: "d".into(),
    }
}

fn roster(seats: &[&str], verdicts: Vec<Verdict>) -> DecisionEvidence {
    let seats: Vec<String> = seats.iter().map(|s| (*s).to_owned()).collect();
    DecisionEvidence {
        root: decision_root(&seats, &verdicts),
        seats,
        verdicts,
    }
}

fn positioned() -> RosterPolicy {
    RosterPolicy::new(["Governance_Gateway:door", "DIT:judge"])
        .with_position("Governance_Gateway:door", GatePosition::Alpha)
        .with_position("DIT:judge", GatePosition::Omega)
}

#[test]
fn a_benign_positioned_roster_has_no_finding() {
    let d = roster(
        &["Governance_Gateway:door", "DIT:judge"],
        vec![verdict("door", GatePosition::Alpha), verdict("judge", GatePosition::Omega)],
    );
    assert_eq!(check_authorized_decision(&d, Some(&positioned())), vec![]);
    assert_eq!(check_authorized_decision(&d, None), vec![]);
}

#[test]
fn two_verdicts_for_one_gate_do_not_stand_in_for_two_seats() {
    // P2 finding 1: the counts agree (2 and 2), so the old check saw nothing
    // and DIT:judge was never judged.
    let d = roster(
        &["Governance_Gateway:door", "DIT:judge"],
        vec![verdict("door", GatePosition::Alpha), verdict("door", GatePosition::Alpha)],
    );
    let f = check_authorized_decision(&d, None);
    assert!(f.contains(&DecisionFinding::DuplicateVerdict("door".into())), "{f:?}");
    assert!(f.contains(&DecisionFinding::SeatNotJudged("DIT:judge".into())), "{f:?}");
    let f = check_authorized_decision(&d, Some(&positioned()));
    assert!(f.contains(&DecisionFinding::DuplicateVerdict("door".into())), "{f:?}");
}

#[test]
fn two_seats_that_share_a_gate_name_are_refused() {
    // P2 finding 2: DIT:judge was counted as passed by Evil's verdict.
    let d = roster(
        &["DIT:judge", "Evil:judge"],
        vec![verdict("judge", GatePosition::Omega), verdict("judge", GatePosition::Omega)],
    );
    let f = check_authorized_decision(&d, Some(&RosterPolicy::new(["DIT:judge"])));
    assert!(f.contains(&DecisionFinding::DuplicateGateName("judge".into())), "{f:?}");
    assert!(f.contains(&DecisionFinding::DuplicateVerdict("judge".into())), "{f:?}");
    // And with distinct verdict counts the roster alone is still refused.
    let d = roster(&["DIT:judge", "Evil:judge"], vec![verdict("judge", GatePosition::Omega)]);
    let f = check_authorized_decision(&d, None);
    assert!(f.contains(&DecisionFinding::DuplicateGateName("judge".into())), "{f:?}");
}

#[test]
fn a_required_seat_at_the_wrong_position_is_refused() {
    // P2 finding 3: a single door verdict at omega was accepted.
    let d = roster(&["Governance_Gateway:door"], vec![verdict("door", GatePosition::Omega)]);
    let policy = RosterPolicy::new(["Governance_Gateway:door"]).with_position("Governance_Gateway:door", GatePosition::Alpha);
    let f = check_authorized_decision(&d, Some(&policy));
    assert_eq!(
        f,
        vec![DecisionFinding::RequiredSeatWrongPosition {
            seat: "Governance_Gateway:door".into(),
            expected: GatePosition::Alpha,
            found: GatePosition::Omega,
        }]
    );
    // A policy that names no position leaves the position unchecked.
    let loose = RosterPolicy::new(["Governance_Gateway:door"]);
    assert_eq!(check_authorized_decision(&d, Some(&loose)), vec![]);
}
