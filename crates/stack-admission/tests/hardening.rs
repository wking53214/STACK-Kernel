//! Two policy switches that close gaps found in the RACE review: a reusable
//! capability can start the same action again, and arguments are neither
//! delivered to the worker nor covered by the capability.
//!
//! The first two tests are controls. They state today's behaviour when the
//! switches are off, so the others show what the switches change. All tests
//! use the real pipeline, the real stores and the real worker, with fixture
//! keys and committed CNS fixtures.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use common::*;
use serde_json::{json, Value};
use stack_admission::{RefusalReason, Stage};

fn reusable_cap(case: &Value) -> Vec<u8> {
    let mut spec = CapSpec::for_case(case, "echo", RESOURCE);
    spec.one_time = false;
    spec.issue()
}

fn strict_policy() -> stack_admission::KernelPolicy {
    let mut p = policy();
    p.require_one_time_capabilities = true;
    p.refuse_arguments = true;
    p
}

#[test]
fn control_a_reusable_capability_starts_the_same_action_twice_when_the_policy_allows_it() {
    let dir = TempDir::new("hardening-reusable-control");
    let h = Builder::new(dir.path()).start();
    let case = all_pass();
    let cap = reusable_cap(&case);
    let first = h.process(payload_with(&case, &cap, "echo", RESOURCE));
    let second = h.process(payload_with(&case, &cap, "echo", RESOURCE));
    assert!(first.is_success() && second.is_success(), "{first:?} / {second:?}");
    assert_eq!(h.runs(), 2, "one capability, two fresh envelopes, two runs");
}

#[test]
fn control_one_capability_covers_requests_that_differ_only_in_their_arguments() {
    let dir = TempDir::new("hardening-args-control");
    let h = Builder::new(dir.path()).start();
    let case = all_pass();
    let cap = reusable_cap(&case);
    let mut one = payload_with(&case, &cap, "echo", RESOURCE);
    one["args"] = json!({"target": "a"});
    let mut two = payload_with(&case, &cap, "echo", RESOURCE);
    two["args"] = json!({"target": "b"});
    assert!(h.process(one).is_success());
    assert!(h.process(two).is_success());
    assert_eq!(h.runs(), 2, "the capability does not bind the arguments");
}

#[test]
fn a_reusable_capability_is_refused_when_the_policy_requires_one_time() {
    let dir = TempDir::new("hardening-reusable-refused");
    let h = Builder::new(dir.path()).policy(strict_policy()).start();
    let case = all_pass();
    let cap = reusable_cap(&case);
    let mut payload = payload_with(&case, &cap, "echo", RESOURCE);
    payload["args"] = Value::Null;
    let r = h.refusal(payload);
    assert_eq!(r.stage, Stage::Authorization);
    assert_eq!(r.reason, RefusalReason::ReusableCapabilityNotAllowed);
    h.assert_rejected_recorded(&r);
    assert_eq!(h.runs(), 0, "nothing ran");
}

#[test]
fn a_one_time_capability_still_runs_under_the_strict_policy() {
    let dir = TempDir::new("hardening-onetime-runs");
    let h = Builder::new(dir.path()).policy(strict_policy()).start();
    let case = all_pass();
    let mut payload = honest_payload(&case, "echo");
    payload["args"] = Value::Null;
    let r = h.process(payload);
    assert!(r.is_success(), "{r:?}");
    assert_eq!(h.runs(), 1);
}

#[test]
fn arguments_are_refused_before_anything_is_recorded_when_the_policy_says_so() {
    let dir = TempDir::new("hardening-args-refused");
    let h = Builder::new(dir.path()).policy(strict_policy()).start();
    let case = all_pass();
    for args in [json!({"k": 1}), json!([]), json!([1]), json!("x"), json!(0), json!(false)] {
        let mut payload = honest_payload(&case, "echo");
        payload["args"] = args.clone();
        let r = h.refusal(payload);
        assert_eq!(r.stage, Stage::Payload, "{args}");
        assert_eq!(r.reason, RefusalReason::ArgumentsNotAllowed, "{args}");
        h.assert_unrecorded(&r);
    }
    assert_eq!(h.runs(), 0, "nothing ran");
}

#[test]
fn null_and_empty_object_are_the_two_ways_to_send_no_arguments() {
    let dir = TempDir::new("hardening-args-empty");
    let h = Builder::new(dir.path()).policy(strict_policy()).start();
    let case = all_pass();
    for args in [Value::Null, json!({})] {
        let mut payload = honest_payload(&case, "echo");
        payload["args"] = args.clone();
        let r = h.process(payload);
        assert!(r.is_success(), "{args}: {r:?}");
    }
    assert_eq!(h.runs(), 2);
}
