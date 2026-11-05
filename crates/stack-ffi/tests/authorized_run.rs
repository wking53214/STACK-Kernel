//! D2-A (Step 3): the safe governed entry points of `stack-ffi` run only on
//! behalf of an `AuthorizedAction`, and the C++ host records and enforces what
//! it can.
//!
//! The scenarios:
//!  - no authorization cannot be constructed from safe code (doc tests on
//!    `execute_governed_transaction`, `supervised_run_governed` and the
//!    unauthorized variants; `tests/api_surface.rs` pins the source shape);
//!  - an all-zero digest is refused at the C layer (`cpp/tests/ffi_authorized_caller.c`,
//!    ctest STACKFfiAuthorizedCaller), where a made-up non-zero digest IS accepted,
//!    which is pinned there as the documented non-guarantee;
//!  - here: a legitimate `AuthorizedAction` runs the intended worker end to end,
//!    the host's audit trail carries a label derived from its digest, and the
//!    host's own governance (capability mask, tokens) still applies afterwards.
//!
//! Every key is a TEST FIXTURE. The host is process global, so every test takes
//! one lock and uses its own rate-limit domain.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::ffi::CString;
use std::sync::{Mutex, MutexGuard, Once};

use ed25519_dalek::{Signer, SigningKey};
use sha2::{Digest, Sha256};
use stack_authority::{
    ActionRequest, Authority, AuthorityConfig, AuthorizedAction, Capability, Digest32, ManualClock, MemoryUseStore,
    PublicKey, Purpose, ResourceScope, RevocationList, TrustAnchor, TrustSet, NONCE_BYTES,
};
use stack_ffi::{
    capability_label, host_audit_read_slot, host_initialize, host_set_capabilities, host_worker_spawn_count,
    supervised_run_governed, worker_image_sha256, GovernedSupervisedError, GovernedSupervisedRequest, HostAuditEvent,
    PayloadKind, SupervisedLimits, SupervisedOutcome, WORKER_BUILD_PATH,
};

const T0: u64 = 1_800_000_000_000;
const KERNEL: &str = "kernel-ffi";

fn serial() -> MutexGuard<'static, ()> {
    static LOCK: Mutex<()> = Mutex::new(());
    static INIT: Once = Once::new();
    let guard = LOCK.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    INIT.call_once(|| {
        host_initialize().expect("initialize the host");
        host_set_capabilities(0x01, 0, 0, 0).expect("grant the test capability");
    });
    guard
}

fn fixture32(label: &str) -> [u8; 32] {
    Sha256::digest(format!("stack-ffi TEST FIXTURE: {label}").as_bytes()).into()
}

/// A real `AuthorizedAction`, minted by `Authority::authorize` from a capability
/// the fixture issuer signed. This is the only way to obtain one.
fn authorization(id: &str) -> AuthorizedAction {
    let key = SigningKey::from_bytes(&fixture32("issuer"));
    let public = PublicKey::from_bytes(key.verifying_key().to_bytes()).unwrap();
    let mut trust = TrustSet::new(4);
    trust
        .insert(TrustAnchor::new("issuer-ffi", public, Purpose::CapabilityIssuer, T0 - 1000, T0 + 1_000_000).unwrap())
        .unwrap();
    let subject = Digest32::from_bytes(fixture32("subject"));
    let root = Digest32::from_bytes(fixture32("root"));
    let mut cap = Capability {
        cap_id: id.to_owned(),
        issuer_id: "issuer-ffi".into(),
        audience: KERNEL.into(),
        subject_digest: subject,
        decision_root: root,
        operations: vec!["echo".into()],
        resources: vec![ResourceScope::exact("/data/a").unwrap()],
        not_before_ms: T0,
        expires_at_ms: T0 + 3_600_000,
        one_time: true,
        policy_ref: "policy/test-fixture".into(),
        nonce: [0; NONCE_BYTES],
    };
    cap.nonce.copy_from_slice(&fixture32(id)[..NONCE_BYTES]);
    cap.normalise();
    let region = cap.encode_signed_region(public.key_id().as_bytes()).unwrap();
    let mut wire = region.clone();
    wire.extend_from_slice(&key.sign(&region).to_bytes());
    let config = AuthorityConfig {
        require_durable_use_store: false,
        ..AuthorityConfig::new(KERNEL)
    };
    Authority::new(config, trust, RevocationList::new(4))
        .unwrap()
        .authorize(
            &wire,
            &ActionRequest {
                subject_digest: subject,
                decision_root: root,
                operation: "echo".into(),
                resource: "/data/a".into(),
            },
            &ManualClock::new(T0 + 1),
            &MemoryUseStore::new(4),
        )
        .unwrap()
}

fn worker_path() -> CString {
    CString::new(WORKER_BUILD_PATH).unwrap()
}

fn request<'a>(path: &'a std::ffi::CStr, domain: u64, caps: u64, tokens: u32, kind: PayloadKind) -> GovernedSupervisedRequest<'a> {
    GovernedSupervisedRequest {
        context_id: domain,
        required_capability_m0: caps,
        required_tokens: tokens,
        kind,
        worker_path: path,
        worker_sha256: Some(worker_image_sha256(path).unwrap()),
        reap_timeout_ns: 0,
    }
}

fn limits() -> SupervisedLimits {
    SupervisedLimits {
        wall_clock_deadline_ns: 2_000_000_000,
        cpu_seconds: 0,
        address_space_bytes: 1 << 30,
        max_output_bytes: 64,
        file_size_bytes: 0,
        nofile: 0,
    }
}

fn bound_events(label: u64) -> usize {
    (0..8192u64)
        .filter_map(host_audit_read_slot)
        .filter(|r| r.event == HostAuditEvent::AuthorizationBound && r.context_id == label)
        .count()
}

#[test]
fn a_legitimate_authorization_runs_the_intended_worker_end_to_end() {
    let _g = serial();
    let auth = authorization("cap-ffi-run");
    let path = worker_path();
    let mut out = [0u8; 64];
    let spawns = host_worker_spawn_count();
    let report = supervised_run_governed(&auth, &request(&path, 1, 0x01, 1, PayloadKind::ReturnBytes), &limits(), &mut out).unwrap();
    assert_eq!(report.outcome, SupervisedOutcome::Completed);
    assert_eq!(&out[..report.result_length as usize], stack_ffi::SUPERVISED_PAYLOAD_BYTES);
    assert!(report.result_self_reported, "the bytes are still the worker's own claim");
    assert_eq!(host_worker_spawn_count(), spawns + 1, "exactly one worker was spawned");

    // The audit trail carries a LABEL derived from the digest, not the digest.
    let label = capability_label(auth.cap_digest().as_bytes());
    assert_eq!(label, u64::from_be_bytes(auth.cap_digest().as_bytes()[..8].try_into().unwrap()));
    assert_eq!(bound_events(label), 1);
}

#[test]
fn a_different_kind_runs_as_itself_under_the_same_authorization() {
    let _g = serial();
    let auth = authorization("cap-ffi-kinds");
    let path = worker_path();
    let mut out = [0u8; 64];
    let report = supervised_run_governed(&auth, &request(&path, 2, 0x01, 1, PayloadKind::ExitNonZero), &limits(), &mut out).unwrap();
    assert_eq!(report.outcome, SupervisedOutcome::ExitedNonZero);
    assert_eq!(report.exit_code, 3);
}

#[test]
fn governance_is_still_enforced_after_authorization_and_the_worker_never_runs() {
    let _g = serial();
    let auth = authorization("cap-ffi-governance");
    let path = worker_path();
    let mut out = [0u8; 64];

    // A capability bit the operator did not grant: refused, nothing spawned.
    let spawns = host_worker_spawn_count();
    let err = supervised_run_governed(&auth, &request(&path, 3, 0x02, 1, PayloadKind::ReturnBytes), &limits(), &mut out).unwrap_err();
    assert_eq!(err, GovernedSupervisedError::CapabilityDenied);
    assert_eq!(host_worker_spawn_count(), spawns, "run counter unchanged");

    // A request naming no capability: refused.
    let err = supervised_run_governed(&auth, &request(&path, 3, 0, 1, PayloadKind::ReturnBytes), &limits(), &mut out).unwrap_err();
    assert_eq!(err, GovernedSupervisedError::CapabilityDenied);
    assert_eq!(host_worker_spawn_count(), spawns);

    // Tokens: a domain spends its burst and is then rate limited, spawning nothing.
    let mut served = 0u64;
    let mut last = Ok(());
    for _ in 0..40 {
        match supervised_run_governed(&auth, &request(&path, 14, 0x01, 100, PayloadKind::ReturnBytes), &limits(), &mut out) {
            Ok(_) => served += 1,
            Err(e) => {
                last = Err(e);
                break;
            }
        }
    }
    assert_eq!(last, Err(GovernedSupervisedError::RateLimited));
    assert!((1..=12).contains(&served), "served {served}");
    assert_eq!(host_worker_spawn_count(), spawns + served, "the refused request spawned nothing");

    // Pinned worker image: a wrong digest is refused, spawning nothing.
    let mut wrong = request(&path, 3, 0x01, 1, PayloadKind::ReturnBytes);
    wrong.worker_sha256 = Some([0x5a; 32]);
    let before = host_worker_spawn_count();
    assert_eq!(
        supervised_run_governed(&auth, &wrong, &limits(), &mut out).unwrap_err(),
        GovernedSupervisedError::WorkerDigestMismatch
    );
    assert_eq!(host_worker_spawn_count(), before);
}

#[test]
fn the_audit_label_is_not_the_digest_and_two_authorizations_have_two_labels() {
    let _g = serial();
    let a = authorization("cap-ffi-label-a");
    let b = authorization("cap-ffi-label-b");
    assert_ne!(a.cap_digest(), b.cap_digest());
    let (la, lb) = (capability_label(a.cap_digest().as_bytes()), capability_label(b.cap_digest().as_bytes()));
    assert_ne!(la, lb);
    // 64 bits of a 256-bit digest: a label, which says nothing about integrity.
    assert_eq!(std::mem::size_of_val(&la) * 8, 64);
    assert_eq!(a.cap_digest().as_bytes().len() * 8, 256);
}
