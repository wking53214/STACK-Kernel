//! Step 3: the authorization decision. The happy path mints an
//! AuthorizedAction carrying every field a receipt needs; every check in
//! the documented order denies with its typed reason; resource scope
//! semantics; the request descriptor authorizes nothing.

#![allow(clippy::unwrap_used)]

mod common;

use common::{
    authority_with, baseline_capability, baseline_request, baseline_wire, fixture_anchor, fixture_anchor_window,
    fixture_digest, fixture_key_id, issue, issue_with_key_id, fixture_signing_key, memory_authority,
    memory_store, memory_store_config, production_config, DAY, HOUR, T0,
};
use stack_authority::{
    ActionRequest, Authority, AuthorityConfig, AuthzError, Capability, CapabilityDigest, ConfigError, Field,
    ManualClock, ParseError, ResourceScope, RevocationList, TrustSet, MAX_WIRE_BYTES, MIN_WIRE_BYTES,
};

fn clock() -> ManualClock {
    ManualClock::new(T0 + 1_000)
}

fn authorize(auth: &Authority, wire: &[u8], req: &ActionRequest) -> Result<(), AuthzError> {
    auth.authorize(wire, req, &clock(), &memory_store()).map(|_| ())
}

fn with(f: impl FnOnce(&mut Capability)) -> Vec<u8> {
    let mut cap = baseline_capability();
    f(&mut cap);
    cap.normalise();
    issue(&cap, "issuer-1")
}

#[test]
fn config_is_validated() {
    assert_eq!(
        AuthorityConfig::new("").validate().unwrap_err(),
        ConfigError::BadAudience(ParseError::LengthOutOfBounds(Field::Audience))
    );
    assert_eq!(
        AuthorityConfig::new("k\u{7f}").validate().unwrap_err(),
        ConfigError::BadAudience(ParseError::ControlCharacter(Field::Audience))
    );
    let zero = AuthorityConfig {
        max_lifetime_ms: 0,
        ..production_config()
    };
    assert_eq!(zero.validate().unwrap_err(), ConfigError::ZeroLifetime);
    let small = AuthorityConfig {
        max_capability_bytes: MIN_WIRE_BYTES - 1,
        ..production_config()
    };
    assert_eq!(small.validate().unwrap_err(), ConfigError::CapabilityCapOutOfRange);
    let big = AuthorityConfig {
        max_capability_bytes: MAX_WIRE_BYTES + 1,
        ..production_config()
    };
    assert_eq!(big.validate().unwrap_err(), ConfigError::CapabilityCapOutOfRange);
    assert_eq!(
        Authority::new(zero, TrustSet::new(1), RevocationList::new(1)).unwrap_err(),
        ConfigError::ZeroLifetime
    );
    let auth = memory_authority();
    assert_eq!(auth.config().audience, "kernel-a");
    assert!(auth.config().max_lifetime_ms > 0);
}

#[test]
fn happy_path_mints_an_authorized_action_with_every_receipt_field() {
    let auth = memory_authority();
    let wire = baseline_wire();
    let c = clock();
    let action = auth.authorize(&wire, &baseline_request(), &c, &memory_store()).unwrap();
    assert_eq!(action.cap_digest(), &CapabilityDigest::of_wire(&wire));
    assert_eq!(action.cap_id(), "cap-0001");
    assert_eq!(action.issuer_id(), "issuer-1");
    assert_eq!(action.key_id(), &fixture_key_id("issuer-1"));
    assert_eq!(action.policy_ref(), "policy/baseline");
    assert_eq!(action.audience(), "kernel-a");
    assert_eq!(action.operation(), "read");
    assert_eq!(action.resource(), "/data/a");
    assert_eq!(action.subject_digest(), &fixture_digest("subject"));
    assert_eq!(action.decision_root(), &fixture_digest("decision"));
    assert!(!action.one_time());
    assert_eq!(action.authorized_at_ms(), T0 + 1_000);
    // A reusable capability authorizes again.
    assert!(auth.authorize(&wire, &baseline_request(), &c, &memory_store()).is_ok());
}

#[test]
fn production_config_refuses_a_non_durable_store_before_anything_else() {
    let auth = authority_with(production_config());
    // Even garbage is refused with StoreUnavailable: the store check is
    // first, so no parse result leaks past an unusable verifier.
    assert_eq!(authorize(&auth, b"garbage", &baseline_request()), Err(AuthzError::StoreUnavailable));
    assert_eq!(authorize(&auth, &baseline_wire(), &baseline_request()), Err(AuthzError::StoreUnavailable));
}

#[test]
fn malformed_oversize_and_unsupported_input_is_typed() {
    let auth = memory_authority();
    let req = baseline_request();
    assert_eq!(authorize(&auth, b"", &req), Err(AuthzError::Malformed(ParseError::BadDomainTag)));
    let mut v3 = baseline_wire();
    v3[17] = b'3';
    assert_eq!(authorize(&auth, &v3, &req), Err(AuthzError::UnsupportedVersion));
    let wire = baseline_wire();
    assert_eq!(authorize(&auth, &wire[..wire.len() - 1], &req), Err(AuthzError::Malformed(ParseError::Truncated)));
    let small = authority_with(AuthorityConfig {
        max_capability_bytes: MIN_WIRE_BYTES,
        ..memory_store_config()
    });
    assert_eq!(authorize(&small, &wire, &req), Err(AuthzError::TooLarge));
    // EmptyScope is reported from the parser as its own class.
    assert_eq!(AuthzError::from(ParseError::EmptyScope(Field::Operations)), AuthzError::EmptyScope(Field::Operations));
}

#[test]
fn trust_resolution_failures_are_typed_and_precede_the_signature() {
    let req = baseline_request();
    let auth = memory_authority();
    assert_eq!(
        authorize(&auth, &with(|c| c.issuer_id = "issuer-9".into()), &req),
        Err(AuthzError::UnknownIssuer)
    );
    assert_eq!(authorize(&auth, &issue(&baseline_capability(), "other"), &req), Err(AuthzError::UntrustedKey));
    auth.with_trust(|t| t.revoke(&fixture_key_id("issuer-1"))).unwrap();
    assert_eq!(authorize(&auth, &baseline_wire(), &req), Err(AuthzError::IssuerRevoked));

    let mut ts = TrustSet::new(4);
    ts.insert(fixture_anchor_window("issuer-1", "issuer-1", T0 + HOUR, T0 + DAY)).unwrap();
    let future = Authority::new(memory_store_config(), ts, RevocationList::new(4)).unwrap();
    assert_eq!(authorize(&future, &baseline_wire(), &req), Err(AuthzError::IssuerKeyNotYetValid));
    let mut ts = TrustSet::new(4);
    ts.insert(fixture_anchor_window("issuer-1", "issuer-1", T0 - DAY, T0)).unwrap();
    let past = Authority::new(memory_store_config(), ts, RevocationList::new(4)).unwrap();
    assert_eq!(authorize(&past, &baseline_wire(), &req), Err(AuthzError::IssuerKeyExpired));
}

#[test]
fn bad_signature_is_one_class() {
    let auth = memory_authority();
    let req = baseline_request();
    let mut wire = baseline_wire();
    let n = wire.len();
    wire[n - 1] ^= 1;
    assert_eq!(authorize(&auth, &wire, &req), Err(AuthzError::BadSignature));
    let forged = issue_with_key_id(
        &baseline_capability(),
        fixture_key_id("issuer-1").as_bytes(),
        &fixture_signing_key("attacker"),
    );
    assert_eq!(authorize(&auth, &forged, &req), Err(AuthzError::BadSignature));
}

#[test]
fn revocation_by_id_or_digest_denies_after_the_signature() {
    let auth = memory_authority();
    let req = baseline_request();
    let wire = baseline_wire();
    auth.with_revocations(|r| r.revoke_id("cap-0001").unwrap()).unwrap();
    assert_eq!(authorize(&auth, &wire, &req), Err(AuthzError::Revoked));
    let auth = memory_authority();
    auth.with_revocations(|r| r.revoke_digest(CapabilityDigest::of_wire(&wire)).unwrap())
        .unwrap();
    assert_eq!(authorize(&auth, &wire, &req), Err(AuthzError::Revoked));
    // Revoking an unrelated id or digest changes nothing.
    let auth = memory_authority();
    auth.with_revocations(|r| r.revoke_id("cap-9999").unwrap()).unwrap();
    assert!(authorize(&auth, &wire, &req).is_ok());
}

#[test]
fn lifetime_and_window_checks() {
    let auth = memory_authority();
    let req = baseline_request();
    let max = auth.config().max_lifetime_ms;
    let too_long = with(|c| c.expires_at_ms = c.not_before_ms + max + 1);
    assert_eq!(
        authorize(&auth, &too_long, &req),
        Err(AuthzError::LifetimeTooLong {
            lifetime_ms: max + 1,
            max_ms: max
        })
    );
    let exactly = with(|c| c.expires_at_ms = c.not_before_ms + max);
    assert!(authorize(&auth, &exactly, &req).is_ok());
    let wire = baseline_wire();
    let c = ManualClock::new(T0 - 1);
    assert_eq!(
        auth.authorize(&wire, &req, &c, &memory_store()).unwrap_err(),
        AuthzError::NotYetValid
    );
    c.set(T0);
    assert!(auth.authorize(&wire, &req, &c, &memory_store()).is_ok());
    c.set(T0 + HOUR - 1);
    assert!(auth.authorize(&wire, &req, &c, &memory_store()).is_ok());
    c.set(T0 + HOUR);
    assert_eq!(auth.authorize(&wire, &req, &c, &memory_store()).unwrap_err(), AuthzError::Expired);
}

#[test]
fn audience_is_configuration_not_request_data() {
    let auth = memory_authority();
    let req = baseline_request();
    assert_eq!(
        authorize(&auth, &with(|c| c.audience = "kernel-b".into()), &req),
        Err(AuthzError::AudienceMismatch)
    );
    assert_eq!(
        authorize(&auth, &with(|c| c.audience = "Kernel-a".into()), &req),
        Err(AuthzError::AudienceMismatch)
    );
    // The same bytes are accepted by the verifier they name.
    let b = Authority::new(
        AuthorityConfig {
            audience: "kernel-b".into(),
            ..memory_store_config()
        },
        common::baseline_trust_set(),
        RevocationList::new(4),
    )
    .unwrap();
    assert!(authorize(&b, &with(|c| c.audience = "kernel-b".into()), &req).is_ok());
}

#[test]
fn subject_and_decision_must_match_the_request() {
    let auth = memory_authority();
    let wire = baseline_wire();
    let mut req = baseline_request();
    req.subject_digest = fixture_digest("other-subject");
    assert_eq!(authorize(&auth, &wire, &req), Err(AuthzError::SubjectMismatch));
    let mut req = baseline_request();
    req.decision_root = fixture_digest("other-decision");
    assert_eq!(authorize(&auth, &wire, &req), Err(AuthzError::DecisionMismatch));
    // Subject is checked before decision.
    let mut req = baseline_request();
    req.subject_digest = fixture_digest("other-subject");
    req.decision_root = fixture_digest("other-decision");
    assert_eq!(authorize(&auth, &wire, &req), Err(AuthzError::SubjectMismatch));
}

#[test]
fn operations_match_exactly() {
    let auth = memory_authority();
    let wire = baseline_wire();
    for op in ["Read", "READ", "read ", " read", "rea", "reads", "delete", "", "read\0"] {
        let mut req = baseline_request();
        req.operation = op.into();
        assert_eq!(authorize(&auth, &wire, &req), Err(AuthzError::OperationDenied), "{op:?}");
    }
    let mut req = baseline_request();
    req.operation = "write".into();
    assert!(authorize(&auth, &wire, &req).is_ok());
}

#[test]
fn resource_scopes_are_exact_or_segment_prefix() {
    let auth = memory_authority();
    // exact /data/a, prefix /data/tree
    let wire = baseline_wire();
    let ok = |r: &str| {
        let mut req = baseline_request();
        req.resource = r.into();
        authorize(&auth, &wire, &req)
    };
    assert!(ok("/data/a").is_ok());
    assert!(ok("/data/tree").is_ok());
    assert!(ok("/data/tree/x").is_ok());
    assert!(ok("/data/tree/x/y/z").is_ok());
    for denied in [
        "/data/a/b",      // exact scope does not extend
        "/data/ab",       // exact
        "/data/treeing",  // prefix confusion
        "/data/tree2",    // prefix confusion
        "/data/tre",      // shorter
        "/data/Tree",     // case
        "/data/A",        // case
        "/data/tree/",    // trailing slash: not a valid path
        "/data/tree//x",  // empty segment
        "/data/tree/../a", // traversal
        "/data/tree/./x", // dot segment
        "data/a",         // relative
        "/data",          // parent
        "/",              // root
        "",               // empty
        "/data/a\0",      // control
        "/data/a%2F",     // no decoding
    ] {
        assert_eq!(ok(denied), Err(AuthzError::ResourceDenied), "{denied:?}");
    }
}

#[test]
fn root_prefix_covers_every_valid_path_and_nothing_invalid() {
    let auth = memory_authority();
    let wire = with(|c| c.resources = vec![ResourceScope::prefix("/").unwrap()]);
    let ok = |r: &str| {
        let mut req = baseline_request();
        req.resource = r.into();
        authorize(&auth, &wire, &req)
    };
    assert!(ok("/").is_ok());
    assert!(ok("/anything/at/all").is_ok());
    assert_eq!(ok("//"), Err(AuthzError::ResourceDenied));
    assert_eq!(ok("/.."), Err(AuthzError::ResourceDenied));
    assert_eq!(ok("x"), Err(AuthzError::ResourceDenied));
    let exact_root = with(|c| c.resources = vec![ResourceScope::exact("/").unwrap()]);
    let mut req = baseline_request();
    req.resource = "/".into();
    assert!(authorize(&auth, &exact_root, &req).is_ok());
    req.resource = "/x".into();
    assert_eq!(authorize(&auth, &exact_root, &req), Err(AuthzError::ResourceDenied));
}

#[test]
fn one_time_capability_is_consumed_last_and_only_on_success() {
    let auth = memory_authority();
    let store = memory_store();
    let c = clock();
    let wire = with(|c| c.one_time = true);
    // A refused request does not consume it.
    let mut wrong = baseline_request();
    wrong.operation = "delete".into();
    assert_eq!(auth.authorize(&wire, &wrong, &c, &store), Err(AuthzError::OperationDenied));
    assert_eq!(store.len(), Some(0));
    let action = auth.authorize(&wire, &baseline_request(), &c, &store).unwrap();
    assert!(action.one_time());
    assert_eq!(store.len(), Some(1));
    assert_eq!(auth.authorize(&wire, &baseline_request(), &c, &store), Err(AuthzError::Replay));
    // A different one-time capability with the same id is a reuse of the
    // id, not a replay.
    let same_id = with(|c| {
        c.one_time = true;
        c.nonce = common::fixture_nonce("nonce-2");
    });
    assert_eq!(
        auth.authorize(&same_id, &baseline_request(), &c, &store),
        Err(AuthzError::CapabilityIdReused)
    );
}

#[test]
fn a_hostile_request_descriptor_with_a_self_made_capability_is_denied() {
    let auth = memory_authority();
    // The attacker builds a capability that grants everything to itself,
    // signs it with its own key, and names the real issuer.
    let mut cap = baseline_capability();
    cap.operations = vec!["admin".into()];
    cap.resources = vec![ResourceScope::prefix("/").unwrap()];
    cap.normalise();
    let wire = issue_with_key_id(&cap, fixture_key_id("attacker").as_bytes(), &fixture_signing_key("attacker"));
    let mut req = baseline_request();
    req.operation = "admin".into();
    req.resource = "/etc/anything".into();
    assert_eq!(authorize(&auth, &wire, &req), Err(AuthzError::UntrustedKey));
    // Claiming the trusted key id does not help.
    let wire = issue_with_key_id(&cap, fixture_key_id("issuer-1").as_bytes(), &fixture_signing_key("attacker"));
    assert_eq!(authorize(&auth, &wire, &req), Err(AuthzError::BadSignature));
}

#[test]
fn trust_set_lives_in_the_authority_and_can_rotate_while_running() {
    let auth = memory_authority();
    let req = baseline_request();
    let under_new = issue(&baseline_capability(), "issuer-1-new");
    assert_eq!(authorize(&auth, &under_new, &req), Err(AuthzError::UntrustedKey));
    auth.with_trust(|t| t.insert(fixture_anchor("issuer-1", "issuer-1-new")).unwrap())
        .unwrap();
    assert!(authorize(&auth, &under_new, &req).is_ok());
    assert!(authorize(&auth, &baseline_wire(), &req).is_ok());
    auth.with_trust(|t| t.revoke(&fixture_key_id("issuer-1"))).unwrap();
    assert_eq!(authorize(&auth, &baseline_wire(), &req), Err(AuthzError::IssuerRevoked));
    assert!(authorize(&auth, &under_new, &req).is_ok());
}
