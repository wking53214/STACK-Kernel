//! Capability format version 2 at the kernel: a capability that commits to the
//! arguments, the worker kind and the limits, and a kernel that refuses a request
//! that would run anything else.
//!
//! These tests use the real pipeline, the real stores and the real worker, with
//! fixture keys. They replace the gap the earlier control test pinned: one
//! capability used to cover requests that differed only in their arguments.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use common::*;
use serde_json::{json, Value};
use stack_admission::{execution_binding, ExecutionLimits, KernelPolicy, RefusalReason, Stage, WorkerKind};
use stack_authority::AuthzError;
use stack_trident::canonical::to_canonical_bytes;
use stack_trident::TridentConfig;

fn bound_policy() -> KernelPolicy {
    let mut p = policy();
    p.require_one_time_capabilities = true;
    p.refuse_arguments = false; // the capability now covers the arguments
    p.require_execution_binding = true;
    p
}

/// A capability for `echo` bound to `args`, the worker kind and the limits given.
fn bound_cap(case: &Value, args: &Value, kind: WorkerKind, limits: &ExecutionLimits) -> Vec<u8> {
    let canonical = to_canonical_bytes(args, &TridentConfig::production(KERNEL).limits()).unwrap();
    let mut spec = CapSpec::for_case(case, "echo", RESOURCE);
    spec.binding = Some(execution_binding(&canonical, kind, limits));
    spec.issue()
}

fn with_args(case: &Value, cap: &[u8], args: Value) -> Value {
    let mut payload = payload_with(case, cap, "echo", RESOURCE);
    payload["args"] = args;
    payload
}

#[test]
fn the_limits_digest_has_a_fixed_layout_known_answer() {
    // SHA-256 of "stack-admission/limits/1\n" then the six limits big-endian: five u64 and a u32, in
    // declaration order. The expected value was computed independently (Python hashlib). If this
    // changes, every capability already issued for these limits stops matching.
    let limits = ExecutionLimits {
        wall_clock_deadline_ns: 300_000_000,
        cpu_seconds: 0,
        address_space_bytes: 4 << 30,
        max_output_bytes: 4096,
        file_size_bytes: 0,
        nofile: 0,
    };
    assert_eq!(
        limits.binding_digest().to_hex(),
        "d900e0da0bd947058ff6ade2338ba7b90586aa7ccf85c2038463d0ca1e536309"
    );
}

#[test]
fn a_bound_capability_runs_the_arguments_it_names() {
    let dir = TempDir::new("bind-runs");
    let p = bound_policy();
    let h = Builder::new(dir.path()).policy(p.clone()).start();
    let case = all_pass();
    let args = json!({"target": "a"});
    let cap = bound_cap(&case, &args, WorkerKind::ReturnBytes, &p.limits);
    let r = h.process(with_args(&case, &cap, args));
    assert!(r.is_success(), "{r:?}");
    assert_eq!(h.runs(), 1);
}

#[test]
fn one_capability_no_longer_covers_requests_that_differ_in_their_arguments() {
    let dir = TempDir::new("bind-args");
    let p = bound_policy();
    let h = Builder::new(dir.path()).policy(p.clone()).start();
    let case = all_pass();
    let cap = bound_cap(&case, &json!({"target": "a"}), WorkerKind::ReturnBytes, &p.limits);
    let r = h.refusal(with_args(&case, &cap, json!({"target": "b"})));
    assert_eq!(r.stage, Stage::Authorization);
    assert_eq!(r.reason, RefusalReason::Authorization(AuthzError::ArgsMismatch));
    h.assert_rejected_recorded(&r);
    assert_eq!(h.runs(), 0, "nothing ran");
}

#[test]
fn a_capability_bound_to_another_worker_kind_is_refused() {
    let dir = TempDir::new("bind-worker");
    let p = bound_policy();
    let h = Builder::new(dir.path()).policy(p.clone()).start();
    let case = all_pass();
    // `echo` runs ReturnBytes under this policy; the capability was issued for a worker that never returns.
    let cap = bound_cap(&case, &Value::Null, WorkerKind::SpinForever, &p.limits);
    let r = h.refusal(with_args(&case, &cap, Value::Null));
    assert_eq!(r.stage, Stage::Authorization);
    assert_eq!(r.reason, RefusalReason::Authorization(AuthzError::WorkerMismatch));
    h.assert_rejected_recorded(&r);
    assert_eq!(h.runs(), 0);
}

#[test]
fn a_capability_bound_to_other_limits_is_refused() {
    let dir = TempDir::new("bind-limits");
    let p = bound_policy();
    let h = Builder::new(dir.path()).policy(p.clone()).start();
    let case = all_pass();
    // Issued for a one-hour deadline; the kernel runs under its own, much shorter one.
    let other = ExecutionLimits::with_deadline_ns(3_600_000_000_000);
    assert_ne!(other.binding_digest(), p.limits.binding_digest());
    let cap = bound_cap(&case, &Value::Null, WorkerKind::ReturnBytes, &other);
    let r = h.refusal(with_args(&case, &cap, Value::Null));
    assert_eq!(r.stage, Stage::Authorization);
    assert_eq!(r.reason, RefusalReason::Authorization(AuthzError::LimitsMismatch));
    h.assert_rejected_recorded(&r);
    assert_eq!(h.runs(), 0);
}

#[test]
fn an_unbound_capability_is_refused_when_the_policy_requires_a_binding() {
    let dir = TempDir::new("bind-required");
    let h = Builder::new(dir.path()).policy(bound_policy()).start();
    let case = all_pass();
    let mut payload = honest_payload(&case, "echo");
    payload["args"] = Value::Null;
    let r = h.refusal(payload);
    assert_eq!(r.stage, Stage::Authorization);
    assert_eq!(r.reason, RefusalReason::Authorization(AuthzError::ExecutionBindingRequired));
    h.assert_rejected_recorded(&r);
    assert_eq!(h.runs(), 0);
}

#[test]
fn control_an_unbound_capability_still_runs_when_the_policy_does_not_require_a_binding() {
    let dir = TempDir::new("bind-control");
    let mut p = bound_policy();
    p.require_execution_binding = false;
    let h = Builder::new(dir.path()).policy(p).start();
    let case = all_pass();
    let mut payload = honest_payload(&case, "echo");
    payload["args"] = Value::Null;
    let r = h.process(payload);
    assert!(r.is_success(), "{r:?}");
    assert_eq!(h.runs(), 1);
}

#[test]
fn a_refused_binding_leaves_a_one_time_capability_unspent() {
    let dir = TempDir::new("bind-unspent");
    let p = bound_policy();
    let h = Builder::new(dir.path()).policy(p.clone()).start();
    let case = all_pass();
    let args = json!({"target": "a"});
    let cap = bound_cap(&case, &args, WorkerKind::ReturnBytes, &p.limits);
    let refused = h.refusal(with_args(&case, &cap, json!({"target": "b"})));
    assert_eq!(refused.reason, RefusalReason::Authorization(AuthzError::ArgsMismatch));
    // The mismatch was found before the use was recorded: the same capability, with the arguments it
    // names, in a fresh envelope, still works.
    let r = h.process(with_args(&case, &cap, args));
    assert!(r.is_success(), "{r:?}");
    assert_eq!(h.runs(), 1);
}
