//! Stages 1 to 4: every refusal is typed, recorded where the recorder is
//! reachable, and nothing runs. The witness is the executor run count,
//! which every test here asserts is zero.
//!
//! Every key is a TEST FIXTURE (tests/common/mod.rs).

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use common::*;
use serde_json::{json, Value};
use stack_admission::{BindingFinding, BuildError, PayloadError, RefusalReason, Refused, Stage};
use stack_authority::{AuthzError, Digest32, ResourceScope};
use stack_receipt::{decision_root, DecisionFinding, Expectations, GateOutcome as ReceiptOutcome};
use stack_trident::{DeploymentProfile, GateOutcome, ReasonCode, StartError, TridentConfig};

fn authz(r: &Refused) -> AuthzError {
    match (&r.stage, &r.reason) {
        (Stage::Authorization, RefusalReason::Authorization(e)) => *e,
        other => panic!("expected an authorization refusal, got {other:?}"),
    }
}

fn binding(r: &Refused) -> Vec<BindingFinding> {
    match (&r.stage, &r.reason) {
        (Stage::Binding, RefusalReason::Binding(f)) => f.clone(),
        other => panic!("expected a binding refusal, got {other:?}"),
    }
}

/// Hostile producers can compute roots too: re-roots an edited decision so
/// only the kernel's binding and policy checks can catch it.
fn reroot(case: &mut Value) {
    let seats: Vec<String> = case["seats"]
        .as_array()
        .unwrap()
        .iter()
        .map(|s| s.as_str().unwrap().to_owned())
        .collect();
    let verdicts: Vec<stack_receipt::Verdict> = case["verdicts"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| stack_receipt::Verdict {
            gate: v["gate"].as_str().unwrap().to_owned(),
            position: stack_receipt::GatePosition::parse(v["position"].as_str().unwrap()).unwrap(),
            outcome: ReceiptOutcome::parse(v["outcome"].as_str().unwrap()).unwrap(),
            subject: v["subject"].as_str().unwrap().to_owned(),
            digest: v["digest"].as_str().unwrap().to_owned(),
        })
        .collect();
    case["root"] = json!(decision_root(&seats, &verdicts).to_hex());
}

// ---------------------------------------------------------------------------
// The fixtures themselves
// ---------------------------------------------------------------------------

#[test]
fn the_kernel_recomputes_what_cns_bound_exactly() {
    let limits = TridentConfig::production(KERNEL).limits();
    for case in load_cases() {
        let name = case["name"].as_str().unwrap();
        let recomputed = stack_admission::binding::subject_digest(&case["subject"], &limits).unwrap();
        assert_eq!(recomputed, case_subject_digest(&case), "{name}: subject digest");
        for v in case["verdicts"].as_array().unwrap() {
            // CNS:same_subject binds its own object, not the content (R2-X-05).
            if !v["digest"].as_str().unwrap().is_empty() && v["gate"] != "same_subject" {
                assert_eq!(v["digest"].as_str().unwrap(), recomputed.to_hex(), "{name}: verdict binds the subject");
            }
        }
        let mut rerooted = case.clone();
        reroot(&mut rerooted);
        assert_eq!(rerooted["root"], case["root"], "{name}: the root recomputes");
    }
    assert_eq!(load_cases().len(), 8);
}

// ---------------------------------------------------------------------------
// Build-time refusals: the Trident must be Production and bound to this kernel
// ---------------------------------------------------------------------------

#[test]
fn a_development_trident_or_a_missing_or_foreign_audience_is_refused_at_build() {
    let dir = TempDir::new("build");
    let dev = Builder::new(dir.path()).trident(TridentConfig::unbound_audience()).build();
    assert!(matches!(dev, Err(BuildError::TridentNotProduction(DeploymentProfile::Development))), "{dev:?}");
    let dev_with_audience = Builder::new(dir.path())
        .trident(TridentConfig {
            audience: KERNEL.into(),
            ..TridentConfig::default()
        })
        .build();
    assert!(matches!(dev_with_audience, Err(BuildError::TridentNotProduction(_))));

    // Production with no audience: the Trident itself refuses (field audience).
    let no_audience = Builder::new(dir.path()).trident(TridentConfig::production("")).build();
    match no_audience {
        Err(BuildError::TridentAudienceMismatch) => {}
        other => panic!("{other:?}"),
    }
    let mut policy_no_audience = policy();
    policy_no_audience.audience = String::new();
    let both_empty = Builder::new(dir.path())
        .policy(policy_no_audience)
        .trident(TridentConfig::production(""))
        .build();
    assert!(matches!(both_empty, Err(BuildError::Policy(_))), "{both_empty:?}");

    // Production bound to another receiver than the policy names.
    let foreign = Builder::new(dir.path()).trident(TridentConfig::production("kernel-b")).build();
    assert!(matches!(foreign, Err(BuildError::TridentAudienceMismatch)), "{foreign:?}");

    // And a correct one starts; a second on the same files is locked out.
    let h = Builder::new(dir.path()).start();
    let second = Builder::new(dir.path()).build();
    match second {
        Err(BuildError::Trident(StartError::Store(stack_trident::StoreError::Locked { .. })))
        | Err(BuildError::Recorder(_))
        | Err(BuildError::UseStoreNotDurable) => {}
        other => panic!("a second kernel on the same store must not start: {other:?}"),
    }
    drop(h);
}

#[test]
fn the_production_trident_refuses_an_unbound_opt_out_even_with_an_audience() {
    let dir = TempDir::new("optout");
    let r = Builder::new(dir.path())
        .trident(TridentConfig {
            allow_unbound_audience: true,
            ..TridentConfig::production(KERNEL)
        })
        .build();
    match r {
        Err(BuildError::Trident(StartError::Config(e))) => assert_eq!(e.field, "allow_unbound_audience"),
        other => panic!("{other:?}"),
    }
}

// ---------------------------------------------------------------------------
// The honest path admits; everything below must not
// ---------------------------------------------------------------------------

#[test]
fn an_honest_request_is_admitted_with_the_kernels_own_values_and_nothing_runs_yet() {
    let dir = TempDir::new("honest");
    let h = Builder::new(dir.path()).start();
    let case = all_pass();
    let admitted = h.admission.admit(&h.envelope(honest_payload(&case, "echo"))).unwrap();
    assert_eq!(*admitted.action().subject_digest(), case_subject_digest(&case));
    assert_eq!(*admitted.action().decision_root(), case_root(&case));
    assert_eq!(admitted.action().operation(), "echo");
    assert_eq!(admitted.action().resource(), RESOURCE);
    assert_eq!(admitted.action().audience(), KERNEL);
    assert_eq!(admitted.action().issuer_id(), ISSUER);
    assert!(admitted.action().one_time());
    assert_eq!(admitted.worker(), stack_admission::WorkerKind::ReturnBytes);
    assert_eq!(h.runs(), 0, "admission never executes");
    // The log holds proposed then authorized and no attempt.
    let v = h.verify_log(Expectations::default());
    assert_eq!(v.executions.len(), 1);
    assert_eq!(v.executions[0].state, stack_receipt::State::Incomplete);
    assert_eq!(v.executions[0].execution.stage_reached, Some(stack_receipt::Stage::Authorized));
    drop(admitted);
}

// ---------------------------------------------------------------------------
// Stage 1: the handoff
// ---------------------------------------------------------------------------

#[test]
fn an_envelope_sealed_for_another_receiver_is_refused_by_the_trident() {
    let dir = TempDir::new("env-audience");
    let h = Builder::new(dir.path()).start();
    let bytes = h.envelope_for(honest_payload(&all_pass(), "echo"), "kernel-b", GateOutcome::Pass);
    let r = h.admission.admit(&bytes).unwrap_err();
    assert_eq!(r.stage, Stage::Handoff);
    match &r.reason {
        RefusalReason::Handoff(refusal) => assert_eq!(refusal.reasons, vec![ReasonCode::MacMismatch]),
        other => panic!("{other:?}"),
    }
    h.assert_unrecorded(&r);
    assert_eq!(h.runs(), 0);
}

#[test]
fn a_replayed_envelope_is_refused_by_the_trident() {
    let dir = TempDir::new("env-replay");
    let h = Builder::new(dir.path()).start();
    let bytes = h.envelope(honest_payload(&all_pass(), "echo"));
    let first = h.admission.admit(&bytes).unwrap();
    let r = h.admission.admit(&bytes).unwrap_err();
    assert_eq!(r.stage, Stage::Handoff);
    match &r.reason {
        RefusalReason::Handoff(refusal) => {
            assert!(refusal.has(ReasonCode::Replay), "{refusal:?}");
            assert!(refusal.has(ReasonCode::SequenceNotIncreasing), "{refusal:?}");
        }
        other => panic!("{other:?}"),
    }
    h.assert_unrecorded(&r);
    assert_eq!(h.runs(), 0);
    drop(first);
}

#[test]
fn a_sender_gate_claim_other_than_pass_is_refused_even_when_authentic() {
    let dir = TempDir::new("env-outcome");
    let h = Builder::new(dir.path()).start();
    for (outcome, expected) in [
        (GateOutcome::Retry, GateOutcome::Retry),
        (GateOutcome::TerminalBreach, GateOutcome::TerminalBreach),
    ] {
        let bytes = h.envelope_for(honest_payload(&all_pass(), "echo"), KERNEL, outcome);
        let r = h.admission.admit(&bytes).unwrap_err();
        assert_eq!(r.stage, Stage::Handoff);
        assert_eq!(r.reason, RefusalReason::HandoffOutcomeNotPass(expected));
        h.assert_unrecorded(&r);
    }
    let garbage = h.admission.admit(b"not an envelope").unwrap_err();
    assert_eq!(garbage.stage, Stage::Handoff);
    assert_eq!(h.runs(), 0);
}

// ---------------------------------------------------------------------------
// Stage 2: the payload
// ---------------------------------------------------------------------------

#[test]
fn a_malformed_payload_is_refused_before_anything_is_recorded() {
    let dir = TempDir::new("payload");
    let h = Builder::new(dir.path()).start();
    let case = all_pass();
    let good = honest_payload(&case, "echo");

    let mut no_cap = good.clone();
    no_cap.as_object_mut().unwrap().remove("capability");
    let r = h.refusal(no_cap);
    assert_eq!(r.stage, Stage::Payload);
    assert_eq!(r.reason, RefusalReason::Payload(PayloadError::MissingField("capability")));
    h.assert_unrecorded(&r);

    let mut extra = good.clone();
    extra["grant"] = json!(true);
    assert_eq!(
        h.refusal(extra).reason,
        RefusalReason::Payload(PayloadError::UnexpectedField("grant".into()))
    );

    let mut not_map = good.clone();
    not_map["subject"] = json!("invoice-42");
    assert_eq!(h.refusal(not_map).reason, RefusalReason::Payload(PayloadError::SubjectNotAMap));

    let mut bad_root = good.clone();
    bad_root["decision"]["root"] = json!(case["root"].as_str().unwrap().to_uppercase());
    assert_eq!(h.refusal(bad_root).reason, RefusalReason::Payload(PayloadError::BadRoot));

    let mut bad_outcome = good.clone();
    bad_outcome["decision"]["verdicts"][0]["outcome"] = json!("approved");
    assert_eq!(h.refusal(bad_outcome).reason, RefusalReason::Payload(PayloadError::UnknownOutcome));

    let mut bad_resource = good.clone();
    bad_resource["resource"] = json!("/data/../a");
    assert!(matches!(
        h.refusal(bad_resource).reason,
        RefusalReason::Payload(PayloadError::Resource(_))
    ));

    let mut upper_cap = good;
    upper_cap["capability"] = json!("ABCD");
    assert_eq!(h.refusal(upper_cap).reason, RefusalReason::Payload(PayloadError::BadCapabilityHex));

    assert_eq!(h.runs(), 0);
    let v = h.verify_log(Expectations::default());
    assert!(v.executions.is_empty(), "nothing was proposed: {}", v.to_json());
}

// ---------------------------------------------------------------------------
// Stage 3: CNS binding against the kernel's recomputation and policy
// ---------------------------------------------------------------------------

#[test]
fn a_transplanted_subject_digest_is_refused_because_the_kernel_recomputes_it() {
    // The decision and the capability are for invoice-42; the subject in
    // the payload is invoice-43. Every verdict digest fails to bind.
    let dir = TempDir::new("transplant");
    let h = Builder::new(dir.path()).start();
    let mut p = honest_payload(&all_pass(), "echo");
    p["subject"] = case("other_subject_all_pass")["subject"].clone();
    let r = h.refusal(p);
    assert_eq!(
        binding(&r),
        vec![
            BindingFinding::VerdictNotBoundToSubject { gate: "door".into() },
            BindingFinding::VerdictNotBoundToSubject { gate: "judge".into() },
        ]
    );
    h.assert_rejected_recorded(&r);
    assert_eq!(h.runs(), 0);
}

#[test]
fn a_subject_changed_after_the_decision_is_refused() {
    let dir = TempDir::new("changed-subject");
    let h = Builder::new(dir.path()).start();
    let mut p = honest_payload(&all_pass(), "echo");
    p["subject"]["amount"] = json!(1201);
    let r = h.refusal(p);
    assert!(binding(&r)
        .iter()
        .all(|f| matches!(f, BindingFinding::VerdictNotBoundToSubject { .. })));
    h.assert_rejected_recorded(&r);
    assert_eq!(h.runs(), 0);
}

#[test]
fn a_decision_changed_after_authorization_is_refused_by_root_or_by_the_capability() {
    let dir = TempDir::new("changed-decision");
    let h = Builder::new(dir.path()).start();
    let case = all_pass();
    let cap = CapSpec::for_case(&case, "echo", RESOURCE).issue();

    // Shape 1: a verdict edited, root left as issued: the root no longer
    // recomputes.
    let mut edited = case.clone();
    edited["verdicts"][1]["subject"] = json!("invoice-42 (amended)");
    let r = h.refusal(payload_with(&edited, &cap, "echo", RESOURCE));
    let f = binding(&r);
    assert_eq!(f[0], BindingFinding::RootMismatch);
    assert!(f.contains(&BindingFinding::IdentityDisagreement));
    h.assert_rejected_recorded(&r);

    // Shape 2: a different real decision (three seats, all PASS, same
    // subject) re-rooted by CNS itself; the capability names the two-seat
    // root, so the authority refuses the decision.
    let three = common::case("three_seats_all_pass");
    let r = h.refusal(payload_with(&three, &cap, "echo", RESOURCE));
    assert_eq!(authz(&r), AuthzError::DecisionMismatch);
    h.assert_rejected_recorded(&r);

    // Shape 3: an edit re-rooted by the attacker, so only the binding
    // check catches it: a verdict rebound to other content.
    let mut rebound = case.clone();
    rebound["verdicts"][0]["digest"] = common::case("other_subject_all_pass")["subject_digest"].clone();
    reroot(&mut rebound);
    let r = h.refusal(payload_with(&rebound, &cap, "echo", RESOURCE));
    assert_eq!(binding(&r), vec![BindingFinding::VerdictNotBoundToSubject { gate: "door".into() }]);
    h.assert_rejected_recorded(&r);
    assert_eq!(h.runs(), 0);
}

#[test]
fn a_missing_required_gate_is_refused_whatever_the_capability_says() {
    let dir = TempDir::new("missing-gate");
    let h = Builder::new(dir.path()).start();
    let case = case("missing_required_seat");
    assert_eq!(case["allowed"], json!(true), "CNS allowed it: its roster never required the judge");
    let r = h.refusal(honest_payload(&case, "echo"));
    assert_eq!(
        binding(&r),
        vec![BindingFinding::Decision(DecisionFinding::RequiredSeatMissing("DIT:judge".into()))]
    );
    h.assert_rejected_recorded(&r);
    assert_eq!(h.runs(), 0);
}

#[test]
fn retry_terminal_breach_unbound_and_empty_decisions_are_refused() {
    let dir = TempDir::new("verdicts");
    let h = Builder::new(dir.path()).start();

    let retry = case("omega_retry");
    let r = h.refusal(honest_payload(&retry, "echo"));
    assert!(binding(&r).contains(&BindingFinding::Decision(DecisionFinding::VerdictNotPass {
        gate: "judge".into(),
        outcome: ReceiptOutcome::Retry,
    })));
    h.assert_rejected_recorded(&r);

    let breach = case("alpha_breach_omega_not_run");
    let r = h.refusal(honest_payload(&breach, "echo"));
    let f = binding(&r);
    assert!(f.contains(&BindingFinding::Decision(DecisionFinding::VerdictNotPass {
        gate: "door".into(),
        outcome: ReceiptOutcome::TerminalBreach,
    })));
    assert!(f.contains(&BindingFinding::Decision(DecisionFinding::VerdictCountMismatch {
        seats: 2,
        verdicts: 1,
    })));
    h.assert_rejected_recorded(&r);

    let unbound = case("unbound_pass");
    let r = h.refusal(honest_payload(&unbound, "echo"));
    let f = binding(&r);
    assert!(f.contains(&BindingFinding::VerdictNotBoundToSubject { gate: "door".into() }));
    assert!(f.contains(&BindingFinding::Decision(DecisionFinding::VerdictUnbound("door".into()))));
    h.assert_rejected_recorded(&r);

    // Empty roster and decision, with the root an attacker would compute
    // for it, and a capability bound to that root.
    let empty_root = decision_root(&[], &[]);
    let cap = CapSpec::for_digests(case_subject_digest(&all_pass()), empty_root, "echo", RESOURCE).issue();
    let mut p = payload_with(&all_pass(), &cap, "echo", RESOURCE);
    p["decision"] = json!({"seats": [], "verdicts": [], "root": empty_root.to_hex()});
    let r = h.refusal(p);
    let f = binding(&r);
    assert_eq!(f[0], BindingFinding::Decision(DecisionFinding::EmptyRoster));
    assert!(f.contains(&BindingFinding::Decision(DecisionFinding::RequiredSeatMissing(
        "Governance_Gateway:door".into()
    ))));
    h.assert_rejected_recorded(&r);
    assert_eq!(h.runs(), 0);
}

// ---------------------------------------------------------------------------
// Stage 4: authorization. A valid PASS decision with matching digests and a
// valid handoff is never enough.
// ---------------------------------------------------------------------------

#[test]
fn a_valid_pass_decision_with_no_capability_does_not_execute() {
    let dir = TempDir::new("no-cap");
    let h = Builder::new(dir.path()).start();
    let case = all_pass();
    let r = h.refusal(payload_with(&case, b"", "echo", RESOURCE));
    assert!(matches!(authz(&r), AuthzError::Malformed(_)), "{r:?}");
    h.assert_rejected_recorded(&r);
    assert_eq!(h.runs(), 0);
}

#[test]
fn a_capability_from_an_untrusted_or_unauthorized_issuer_does_not_execute() {
    let dir = TempDir::new("issuer");
    let h = Builder::new(dir.path()).start();
    let case = all_pass();

    let mut unknown = CapSpec::for_case(&case, "echo", RESOURCE);
    unknown.issuer_id = "issuer-9".into();
    unknown.key_label = "issuer-9".into();
    let r = h.refusal(payload_with(&case, &unknown.issue(), "echo", RESOURCE));
    assert_eq!(authz(&r), AuthzError::UnknownIssuer);
    h.assert_rejected_recorded(&r);

    // The issuer id is known, the key is not the one the kernel trusts.
    let mut rogue = CapSpec::for_case(&case, "echo", RESOURCE);
    rogue.key_label = "issuer-1-rogue".into();
    let r = h.refusal(payload_with(&case, &rogue.issue(), "echo", RESOURCE));
    assert_eq!(authz(&r), AuthzError::UntrustedKey);
    h.assert_rejected_recorded(&r);
    assert_eq!(h.runs(), 0);
}

#[test]
fn an_invalid_capability_signature_does_not_execute() {
    let dir = TempDir::new("sig");
    let h = Builder::new(dir.path()).start();
    let case = all_pass();
    let mut cap = CapSpec::for_case(&case, "echo", RESOURCE).issue();
    let last = cap.len() - 1;
    cap[last] ^= 0x01;
    let r = h.refusal(payload_with(&case, &cap, "echo", RESOURCE));
    assert_eq!(authz(&r), AuthzError::BadSignature);
    h.assert_rejected_recorded(&r);
    // A flip inside the signed region: still only a bad signature, never a
    // later refusal that would describe a capability nobody issued.
    let mut cap = CapSpec::for_case(&case, "echo", RESOURCE).issue();
    cap[40] ^= 0x01;
    let r = h.refusal(payload_with(&case, &cap, "echo", RESOURCE));
    assert!(matches!(authz(&r), AuthzError::BadSignature | AuthzError::Malformed(_)), "{r:?}");
    assert_eq!(h.runs(), 0);
}

#[test]
fn a_capability_for_another_subject_decision_operation_resource_or_audience_does_not_execute() {
    let dir = TempDir::new("scope");
    let h = Builder::new(dir.path()).start();
    let case = all_pass();

    let other_subject = CapSpec::for_case(&common::case("other_subject_all_pass"), "echo", RESOURCE).issue();
    let r = h.refusal(payload_with(&case, &other_subject, "echo", RESOURCE));
    assert_eq!(authz(&r), AuthzError::SubjectMismatch);
    h.assert_rejected_recorded(&r);

    let other_decision =
        CapSpec::for_digests(case_subject_digest(&case), Digest32::from_bytes([7; 32]), "echo", RESOURCE).issue();
    let r = h.refusal(payload_with(&case, &other_decision, "echo", RESOURCE));
    assert_eq!(authz(&r), AuthzError::DecisionMismatch);

    let other_op = CapSpec::for_case(&case, "exit", RESOURCE).issue();
    let r = h.refusal(payload_with(&case, &other_op, "echo", RESOURCE));
    assert_eq!(authz(&r), AuthzError::OperationDenied);

    let other_resource = CapSpec::for_case(&case, "echo", "/data/b").issue();
    let r = h.refusal(payload_with(&case, &other_resource, "echo", RESOURCE));
    assert_eq!(authz(&r), AuthzError::ResourceDenied);
    // A prefix scope one segment short, and a sibling that shares a byte prefix.
    let mut prefix = CapSpec::for_case(&case, "echo", "/data");
    prefix.resources = vec![ResourceScope::prefix("/dat").unwrap()];
    let r = h.refusal(payload_with(&case, &prefix.issue(), "echo", RESOURCE));
    assert_eq!(authz(&r), AuthzError::ResourceDenied);

    let mut other_audience = CapSpec::for_case(&case, "echo", RESOURCE);
    other_audience.audience = "kernel-b".into();
    let r = h.refusal(payload_with(&case, &other_audience.issue(), "echo", RESOURCE));
    assert_eq!(authz(&r), AuthzError::AudienceMismatch);
    h.assert_rejected_recorded(&r);
    assert_eq!(h.runs(), 0);
}

#[test]
fn a_revoked_or_expired_or_not_yet_valid_capability_does_not_execute() {
    let dir = TempDir::new("window");
    let h = Builder::new(dir.path()).start();
    let case = all_pass();

    let revoked = CapSpec::for_case(&case, "echo", RESOURCE);
    let wire = revoked.issue();
    h.admission
        .authority()
        .with_revocations(|r| r.revoke_id(&revoked.cap_id))
        .unwrap()
        .unwrap();
    let r = h.refusal(payload_with(&case, &wire, "echo", RESOURCE));
    assert_eq!(authz(&r), AuthzError::Revoked);
    h.assert_rejected_recorded(&r);

    let mut future = CapSpec::for_case(&case, "echo", RESOURCE);
    future.not_before_ms = h.now() + HOUR;
    future.expires_at_ms = h.now() + 2 * HOUR;
    let r = h.refusal(payload_with(&case, &future.issue(), "echo", RESOURCE));
    assert_eq!(authz(&r), AuthzError::NotYetValid);

    // Time passes beyond the capability's hour; the envelope is fresh.
    let cap = CapSpec::for_case(&case, "echo", RESOURCE).issue();
    h.clock.advance(HOUR + 1);
    let r = h.refusal(payload_with(&case, &cap, "echo", RESOURCE));
    assert_eq!(authz(&r), AuthzError::Expired);
    h.assert_rejected_recorded(&r);
    assert_eq!(h.runs(), 0);
}

#[test]
fn an_operation_outside_the_kernels_map_is_refused_before_the_capability_is_consumed() {
    let dir = TempDir::new("unknown-op");
    let h = Builder::new(dir.path()).start();
    let case = all_pass();
    // A capability that grants both names; the kernel maps only one.
    let mut spec = CapSpec::for_case(&case, "echo", RESOURCE);
    spec.operations = vec!["echo".into(), "launch".into()];
    let cap = spec.issue();
    let r = h.refusal(payload_with(&case, &cap, "launch", RESOURCE));
    assert_eq!(r.stage, Stage::Authorization);
    assert_eq!(r.reason, RefusalReason::UnknownOperation("launch".into()));
    h.assert_rejected_recorded(&r);
    // The one-time capability was not consumed: it still admits the mapped
    // operation.
    let admitted = h.admission.admit(&h.envelope(payload_with(&case, &cap, "echo", RESOURCE))).unwrap();
    assert_eq!(admitted.action().operation(), "echo");
    assert_eq!(h.runs(), 0);
    drop(admitted);
}

#[test]
fn a_one_time_capability_presented_in_a_fresh_envelope_is_refused_as_replay() {
    let dir = TempDir::new("cap-replay");
    let h = Builder::new(dir.path()).start();
    let case = all_pass();
    let cap = CapSpec::for_case(&case, "echo", RESOURCE).issue();
    let first = h.admission.admit(&h.envelope(payload_with(&case, &cap, "echo", RESOURCE))).unwrap();
    let r = h.refusal(payload_with(&case, &cap, "echo", RESOURCE));
    assert_eq!(authz(&r), AuthzError::Replay);
    h.assert_rejected_recorded(&r);
    assert_eq!(h.runs(), 0);
    drop(first);
}

#[test]
fn every_rejection_is_in_the_receipt_log_with_its_stage() {
    let dir = TempDir::new("log");
    let h = Builder::new(dir.path()).start();
    let case = all_pass();
    let r1 = h.refusal(honest_payload(&common::case("omega_retry"), "echo"));
    let r2 = h.refusal(payload_with(&case, b"", "echo", RESOURCE));
    let v = h.verify_log(Expectations::default());
    assert_eq!(v.state, stack_receipt::State::VerifiedWithLimitations, "{}", v.to_json());
    assert_eq!(v.executions.len(), 2);
    let ids: Vec<_> = v.executions.iter().map(|e| e.execution.execution_id).collect();
    assert_eq!(ids, vec![r1.execution_id.unwrap(), r2.execution_id.unwrap()]);
    // The rejection reasons name the stage; read back from the log.
    let parsed = stack_receipt::parse_log(&h.receipt_bytes()).unwrap();
    let reasons: Vec<String> = parsed
        .records
        .iter()
        .filter_map(|s| match &s.record().event {
            stack_receipt::Event::Rejected(r) => Some(r.reason.clone()),
            _ => None,
        })
        .collect();
    assert_eq!(reasons.len(), 2);
    assert!(reasons[0].starts_with("binding: cns binding:"), "{}", reasons[0]);
    assert!(reasons[1].starts_with("authorization: authorization:"), "{}", reasons[1]);
    assert_eq!(h.runs(), 0);
}

// ---------------------------------------------------------------------------
// A recorded gap, as an assertion
// ---------------------------------------------------------------------------

/// R2-X-05. A real SuperGate roster that asks CNS to check "every seat
/// judged one document" carries a pseudo seat, `CNS:same_subject`, whose
/// verdict binds to its own object (`{"identity", "digest", "seats"}`) and
/// names itself as its subject. The kernel requires every verdict to bind
/// to the recomputed subject digest and to name one identity, so it refuses
/// such a decision, with or without the pseudo seat in its required seats.
/// Refusal is the safe direction; this test pins it so that a change which
/// starts admitting these decisions has to change this test on purpose.
#[test]
fn a_real_decision_that_carries_the_same_subject_seat_is_refused_today() {
    let case = common::case("same_subject_all_pass");
    assert_eq!(case["allowed"], json!(true), "CNS passed it");
    for required in [
        vec!["Governance_Gateway:door", "DIT:judge"],
        vec!["CNS:same_subject", "Governance_Gateway:door", "DIT:judge"],
    ] {
        let mut p = policy();
        p.required_seats = required.iter().map(|s| (*s).to_owned()).collect();
        let dir = TempDir::new("same-subject");
        let h = Builder::new(dir.path()).policy(p).start();
        let r = h.refusal(honest_payload(&case, "echo"));
        let f = binding(&r);
        assert!(f.contains(&BindingFinding::VerdictNotBoundToSubject { gate: "same_subject".into() }), "{f:?}");
        assert!(f.contains(&BindingFinding::IdentityDisagreement), "{f:?}");
        h.assert_rejected_recorded(&r);
        assert_eq!(h.runs(), 0);
        drop(h);
    }
}
