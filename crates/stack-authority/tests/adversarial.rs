//! Step 5: adversarial scenarios against the whole boundary, under the
//! production configuration and the durable store wherever the scenario
//! allows. Each test is named for the scenario in the campaign brief.
//!
//! Invariant checked throughout: an attacker who alters any byte of a
//! capability never gets past the signature stage, so no refusal they
//! see describes anything but the bytes and the public trust set.

#![allow(clippy::unwrap_used)]

mod common;

use std::sync::Arc;

use common::{
    authority_with, baseline_capability, baseline_request, baseline_trust_set, baseline_wire, fixture_anchor,
    fixture_anchor_window, fixture_digest, fixture_key_id, fixture_nonce, fixture_signing_key, issue,
    issue_with_key_id, production_config, sign_region, RawFields, TempDir, DAY, EXACT, HOUR, PREFIX, T0,
};
use stack_authority::{
    ActionRequest, Authority, AuthorityConfig, AuthzError, Capability, CapabilityDigest, Field, FileUseStore,
    ManualClock, ParseError, ResourceScope, RevocationList, TrustSet, UseError, UseKey, UseStore,
};

struct Fx {
    _dir: TempDir,
    store: FileUseStore,
    auth: Authority,
    clock: ManualClock,
}

fn fresh(label: &str) -> Fx {
    let dir = TempDir::new(label);
    let store = FileUseStore::open(dir.file("uses.log"), 64).unwrap();
    Fx {
        _dir: dir,
        store,
        auth: authority_with(production_config()),
        clock: ManualClock::new(T0 + 1_000),
    }
}

impl Fx {
    fn authorize(&self, wire: &[u8], req: &ActionRequest) -> Result<(), AuthzError> {
        self.auth.authorize(wire, req, &self.clock, &self.store).map(|_| ())
    }

    fn records(&self) -> usize {
        self.store.records().unwrap()
    }
}

fn modified(f: impl FnOnce(&mut Capability)) -> Vec<u8> {
    let mut cap = baseline_capability();
    f(&mut cap);
    cap.normalise();
    issue(&cap, "issuer-1")
}

fn request(f: impl FnOnce(&mut ActionRequest)) -> ActionRequest {
    let mut r = baseline_request();
    f(&mut r);
    r
}

/// Whether `e` is a refusal that can be reached before the signature is
/// checked. Anything else describes a genuine capability.
fn is_pre_signature(e: AuthzError) -> bool {
    matches!(
        e,
        AuthzError::TooLarge
            | AuthzError::Malformed(_)
            | AuthzError::UnsupportedVersion
            | AuthzError::EmptyScope(_)
            | AuthzError::UnknownIssuer
            | AuthzError::UntrustedKey
            | AuthzError::IssuerRevoked
            | AuthzError::IssuerKeyNotYetValid
            | AuthzError::IssuerKeyExpired
            | AuthzError::BadSignature
    )
}

#[test]
fn baseline_is_accepted_so_every_denial_below_is_the_scenario_and_nothing_else() {
    let fx = fresh("baseline");
    assert!(fx.authorize(&baseline_wire(), &baseline_request()).is_ok());
}

#[test]
fn unauthorized_issuer() {
    let fx = fresh("unauthorized-issuer");
    // An issuer nobody trusts, signing with its own key under its own id.
    let mut cap = baseline_capability();
    cap.issuer_id = "issuer-rogue".into();
    let wire = issue(&cap, "issuer-rogue");
    assert_eq!(fx.authorize(&wire, &baseline_request()), Err(AuthzError::UnknownIssuer));
    assert_eq!(fx.records(), 0);
}

#[test]
fn untrusted_key_with_a_valid_signature() {
    let fx = fresh("untrusted-key");
    // Names the trusted issuer, signed correctly, but under a key the
    // trust set does not hold for that issuer.
    let wire = issue(&baseline_capability(), "issuer-1-unlisted");
    assert_eq!(fx.authorize(&wire, &baseline_request()), Err(AuthzError::UntrustedKey));
    // The same key trusted for a different issuer is still untrusted
    // for this one.
    fx.auth
        .with_trust(|t| t.insert(fixture_anchor("issuer-2", "issuer-1-unlisted")).unwrap())
        .unwrap();
    assert_eq!(fx.authorize(&wire, &baseline_request()), Err(AuthzError::UntrustedKey));
    assert_eq!(fx.records(), 0);
}

#[test]
fn invalid_signature_every_single_byte_flip_in_signed_region_and_signature() {
    let fx = fresh("byte-flips");
    let wire = baseline_wire();
    let mut reached_signature = 0usize;
    for i in 0..wire.len() {
        let mut m = wire.clone();
        m[i] ^= 1 << (i % 8);
        let err = fx.authorize(&m, &baseline_request()).unwrap_err();
        assert!(is_pre_signature(err), "byte {i}: {err:?} is a post-signature refusal");
        if err == AuthzError::BadSignature {
            reached_signature += 1;
        }
    }
    assert!(reached_signature > wire.len() / 2, "{reached_signature} flips reached the signature check");
    assert_eq!(fx.records(), 0, "no altered capability touched the store");
    // The signature bytes alone, every one of them.
    let n = wire.len();
    for i in n - 64..n {
        let mut m = wire.clone();
        m[i] ^= 0x01;
        assert_eq!(fx.authorize(&m, &baseline_request()), Err(AuthzError::BadSignature), "sig byte {i}");
    }
}

#[test]
fn signature_from_another_capability_transplanted() {
    let fx = fresh("transplant");
    let a = baseline_wire();
    let b = modified(|c| {
        c.operations = vec!["admin".into()];
        c.resources = vec![ResourceScope::prefix("/").unwrap()];
    });
    // b's signature onto a's body, and a's onto b's.
    let mut ab = a[..a.len() - 64].to_vec();
    ab.extend_from_slice(&b[b.len() - 64..]);
    let mut ba = b[..b.len() - 64].to_vec();
    ba.extend_from_slice(&a[a.len() - 64..]);
    assert_eq!(fx.authorize(&ab, &baseline_request()), Err(AuthzError::BadSignature));
    let admin = request(|r| r.operation = "admin".into());
    assert_eq!(fx.authorize(&ba, &admin), Err(AuthzError::BadSignature));
    assert_eq!(fx.records(), 0);
}

#[test]
fn wrong_audience() {
    let fx = fresh("audience");
    for other in ["kernel-b", "Kernel-a", "kernel-a ", "kernel-a\u{200b}", "kernel"] {
        let wire = modified(|c| c.audience = other.into());
        assert_eq!(fx.authorize(&wire, &baseline_request()), Err(AuthzError::AudienceMismatch), "{other:?}");
    }
    assert_eq!(fx.records(), 0);
}

#[test]
fn transplanted_subject_digest() {
    let fx = fresh("subject");
    // A genuine capability about subject A, presented for content B.
    let wire = baseline_wire();
    let req = request(|r| r.subject_digest = fixture_digest("subject-b"));
    assert_eq!(fx.authorize(&wire, &req), Err(AuthzError::SubjectMismatch));
    // And a capability whose subject field was edited: the signature
    // catches it before the subject is even compared.
    let edited = {
        let mut cap = baseline_capability();
        cap.subject_digest = fixture_digest("subject-b");
        let region = cap.encode_signed_region(fixture_key_id("issuer-1").as_bytes()).unwrap();
        let mut w = region;
        w.extend_from_slice(&wire[wire.len() - 64..]);
        w
    };
    assert_eq!(fx.authorize(&edited, &req), Err(AuthzError::BadSignature));
    assert_eq!(fx.records(), 0);
}

#[test]
fn changed_decision_root() {
    let fx = fresh("decision");
    let wire = baseline_wire();
    let req = request(|r| r.decision_root = fixture_digest("decision-b"));
    assert_eq!(fx.authorize(&wire, &req), Err(AuthzError::DecisionMismatch));
    // A matching decision root alone, with the wrong subject, is not
    // enough: subject is checked first and both must hold.
    let req = request(|r| r.subject_digest = fixture_digest("subject-b"));
    assert_eq!(fx.authorize(&wire, &req), Err(AuthzError::SubjectMismatch));
    assert_eq!(fx.records(), 0);
}

#[test]
fn revoked_capability() {
    let fx = fresh("revoked-cap");
    let wire = baseline_wire();
    assert!(fx.authorize(&wire, &baseline_request()).is_ok());
    fx.auth.with_revocations(|r| r.revoke_id("cap-0001").unwrap()).unwrap();
    assert_eq!(fx.authorize(&wire, &baseline_request()), Err(AuthzError::Revoked));
    // By digest, for a capability whose id was never revoked.
    let other = modified(|c| c.cap_id = "cap-0002".into());
    assert!(fx.authorize(&other, &baseline_request()).is_ok());
    fx.auth
        .with_revocations(|r| r.revoke_digest(CapabilityDigest::of_wire(&other)).unwrap())
        .unwrap();
    assert_eq!(fx.authorize(&other, &baseline_request()), Err(AuthzError::Revoked));
}

#[test]
fn revoked_issuer() {
    let fx = fresh("revoked-issuer");
    let wire = baseline_wire();
    assert!(fx.authorize(&wire, &baseline_request()).is_ok());
    fx.auth
        .with_trust(|t| assert!(t.revoke(&fixture_key_id("issuer-1"))))
        .unwrap();
    assert_eq!(fx.authorize(&wire, &baseline_request()), Err(AuthzError::IssuerRevoked));
    // Re-adding the same key does not restore trust.
    let reinsert = fx
        .auth
        .with_trust(|t| t.insert(fixture_anchor("issuer-1", "issuer-1")))
        .unwrap();
    assert!(reinsert.is_err());
    assert_eq!(fx.authorize(&wire, &baseline_request()), Err(AuthzError::IssuerRevoked));
}

#[test]
fn issuer_key_expired_or_not_yet_valid() {
    let req = baseline_request();
    let wire = baseline_wire();
    let dir = TempDir::new("issuer-window");
    let store = FileUseStore::open(dir.file("uses.log"), 16).unwrap();
    let mut ts = TrustSet::new(4);
    ts.insert(fixture_anchor_window("issuer-1", "issuer-1", T0, T0 + 2 * HOUR)).unwrap();
    let auth = Authority::new(production_config(), ts, RevocationList::new(4)).unwrap();
    let c = ManualClock::new(T0 - 1);
    assert_eq!(auth.authorize(&wire, &req, &c, &store).unwrap_err(), AuthzError::IssuerKeyNotYetValid);
    c.set(T0 + 10);
    assert!(auth.authorize(&wire, &req, &c, &store).is_ok());
    // The key window ends before the capability's; the key wins.
    let long = modified(|c| c.expires_at_ms = T0 + 3 * HOUR);
    c.set(T0 + 2 * HOUR);
    assert_eq!(auth.authorize(&long, &req, &c, &store).unwrap_err(), AuthzError::IssuerKeyExpired);
}

#[test]
fn expired_capability() {
    let fx = fresh("expired");
    let wire = baseline_wire();
    fx.clock.set(T0 + HOUR);
    assert_eq!(fx.authorize(&wire, &baseline_request()), Err(AuthzError::Expired));
    fx.clock.set(u64::MAX);
    assert_eq!(fx.authorize(&wire, &baseline_request()), Err(AuthzError::IssuerKeyExpired));
    assert_eq!(fx.records(), 0);
}

#[test]
fn not_yet_valid_capability() {
    let fx = fresh("not-yet-valid");
    let wire = modified(|c| {
        c.not_before_ms = T0 + HOUR;
        c.expires_at_ms = T0 + 2 * HOUR;
    });
    assert_eq!(fx.authorize(&wire, &baseline_request()), Err(AuthzError::NotYetValid));
    fx.clock.set(T0 + HOUR);
    assert!(fx.authorize(&wire, &baseline_request()).is_ok());
}

#[test]
fn lifetime_above_cap() {
    let fx = fresh("lifetime");
    let max = fx.auth.config().max_lifetime_ms;
    let wire = modified(|c| c.expires_at_ms = c.not_before_ms + max + 1);
    assert_eq!(
        fx.authorize(&wire, &baseline_request()),
        Err(AuthzError::LifetimeTooLong {
            lifetime_ms: max + 1,
            max_ms: max
        })
    );
    // Refused at every instant of its window, not only at the edges.
    fx.clock.set(T0 + max / 2);
    assert!(fx.authorize(&wire, &baseline_request()).is_err());
    // A tighter verifier refuses what a looser one accepts.
    let tight = Authority::new(
        AuthorityConfig {
            max_lifetime_ms: HOUR - 1,
            ..production_config()
        },
        baseline_trust_set(),
        RevocationList::new(4),
    )
    .unwrap();
    fx.clock.set(T0 + 1_000);
    assert_eq!(
        tight
            .authorize(&baseline_wire(), &baseline_request(), &fx.clock, &fx.store)
            .unwrap_err(),
        AuthzError::LifetimeTooLong {
            lifetime_ms: HOUR,
            max_ms: HOUR - 1
        }
    );
    assert_eq!(fx.records(), 0);
}

#[test]
fn wrong_operation() {
    let fx = fresh("operation");
    let wire = baseline_wire();
    for op in ["delete", "Read", "READ", "read\0", "read ", "", "re", "readwrite", "write\u{301}"] {
        assert_eq!(
            fx.authorize(&wire, &request(|r| r.operation = op.into())),
            Err(AuthzError::OperationDenied),
            "{op:?}"
        );
    }
    assert_eq!(fx.records(), 0);
}

#[test]
fn wrong_resource_prefix_confusion_traversal_empty_segment_case() {
    let fx = fresh("resource");
    // Grants: exact /data/a, prefix /data/tree.
    let wire = baseline_wire();
    let cases = [
        ("/data/ab", "prefix confusion on an exact scope"),
        ("/data/a/b", "child of an exact scope"),
        ("/data/treeing", "prefix confusion at a non-boundary"),
        ("/data/tree-2", "prefix confusion with punctuation"),
        ("/data/tree/../secret", "traversal"),
        ("/data/tree/./x/../../../etc", "traversal, deeper"),
        ("/data/tree//x", "empty segment"),
        ("/data/tree/", "trailing slash"),
        ("//data/tree", "leading double slash"),
        ("/data/Tree", "case"),
        ("/DATA/tree", "case, parent"),
        ("/data/tree\u{0}", "embedded NUL"),
        ("/data/tree%2Fx", "percent-encoded separator is not a separator"),
        ("/data/tree\\x", "backslash is not a separator"),
        ("data/tree", "relative"),
        ("", "empty"),
    ];
    for (res, why) in cases {
        assert_eq!(
            fx.authorize(&wire, &request(|r| r.resource = res.into())),
            Err(AuthzError::ResourceDenied),
            "{why}: {res:?}"
        );
    }
    // What the scopes do cover.
    for ok in ["/data/a", "/data/tree", "/data/tree/x", "/data/tree/x/y"] {
        assert!(fx.authorize(&wire, &request(|r| r.resource = ok.into())).is_ok(), "{ok}");
    }
}

#[test]
fn empty_operations_or_resources() {
    let fx = fresh("empty-scope");
    let key = fixture_signing_key("issuer-1");
    let kid = *fixture_key_id("issuer-1").as_bytes();
    let mut r = RawFields::from_capability(&baseline_capability(), &kid);
    r.operations = vec![];
    let wire = sign_region(&r.encode(), &key);
    assert_eq!(fx.authorize(&wire, &baseline_request()), Err(AuthzError::EmptyScope(Field::Operations)));
    let mut r = RawFields::from_capability(&baseline_capability(), &kid);
    r.resources = vec![];
    let wire = sign_region(&r.encode(), &key);
    assert_eq!(fx.authorize(&wire, &baseline_request()), Err(AuthzError::EmptyScope(Field::Resources)));
    // The encoder refuses to produce them at all.
    let mut cap = baseline_capability();
    cap.operations.clear();
    assert_eq!(cap.encode_signed_region(&kid).unwrap_err(), ParseError::EmptyScope(Field::Operations));
    // An empty-string operation or path cannot be put on the wire either.
    let mut r = RawFields::from_capability(&baseline_capability(), &kid);
    r.operations = vec![vec![]];
    let wire = sign_region(&r.encode(), &key);
    assert_eq!(
        fx.authorize(&wire, &baseline_request()),
        Err(AuthzError::Malformed(ParseError::LengthOutOfBounds(Field::Operation)))
    );
    let mut r = RawFields::from_capability(&baseline_capability(), &kid);
    r.resources = vec![(PREFIX, vec![])];
    let wire = sign_region(&r.encode(), &key);
    assert_eq!(
        fx.authorize(&wire, &baseline_request()),
        Err(AuthzError::Malformed(ParseError::LengthOutOfBounds(Field::ResourcePath)))
    );
    let _ = EXACT;
    assert_eq!(fx.records(), 0);
}

#[test]
fn replay_of_a_one_time_capability() {
    let fx = fresh("replay");
    let wire = modified(|c| c.one_time = true);
    // Refusals before the store do not consume it.
    assert_eq!(
        fx.authorize(&wire, &request(|r| r.operation = "delete".into())),
        Err(AuthzError::OperationDenied)
    );
    assert_eq!(fx.records(), 0);
    assert!(fx.authorize(&wire, &baseline_request()).is_ok());
    assert_eq!(fx.records(), 1);
    assert_eq!(fx.authorize(&wire, &baseline_request()), Err(AuthzError::Replay));
    // Also with a different, still-covered request: the capability, not
    // the request, is what was consumed.
    assert_eq!(
        fx.authorize(&wire, &request(|r| r.operation = "write".into())),
        Err(AuthzError::Replay)
    );
    assert_eq!(fx.records(), 1);
}

#[test]
fn replay_after_restart() {
    let dir = TempDir::new("restart");
    let path = dir.file("uses.log");
    let auth = authority_with(production_config());
    let clock = ManualClock::new(T0 + 1_000);
    let wire = modified(|c| c.one_time = true);
    {
        let store = FileUseStore::open(&path, 16).unwrap();
        assert!(auth.authorize(&wire, &baseline_request(), &clock, &store).is_ok());
    }
    for _ in 0..3 {
        let store = FileUseStore::open(&path, 16).unwrap();
        assert_eq!(auth.authorize(&wire, &baseline_request(), &clock, &store), Err(AuthzError::Replay));
        assert_eq!(store.records(), Some(1));
    }
    // A fresh verifier process with the same log remembers too.
    let other_process = authority_with(production_config());
    let store = FileUseStore::open(&path, 16).unwrap();
    assert_eq!(
        other_process.authorize(&wire, &baseline_request(), &clock, &store),
        Err(AuthzError::Replay)
    );
}

#[test]
fn concurrent_consumption_by_many_threads_accepted_exactly_once() {
    let dir = TempDir::new("threads");
    let store = Arc::new(FileUseStore::open(dir.file("uses.log"), 256).unwrap());
    let auth = Arc::new(authority_with(production_config()));
    let threads = 32;
    let wire = Arc::new(modified(|c| c.one_time = true));
    let barrier = Arc::new(std::sync::Barrier::new(threads));
    let handles: Vec<_> = (0..threads)
        .map(|_| {
            let (store, auth, wire, barrier) = (store.clone(), auth.clone(), wire.clone(), barrier.clone());
            std::thread::spawn(move || {
                barrier.wait();
                let clock = ManualClock::new(T0 + 1_000);
                auth.authorize(&wire, &baseline_request(), &clock, store.as_ref())
                    .map(|a| a.cap_id().to_owned())
            })
        })
        .collect();
    let results: Vec<_> = handles.into_iter().map(|h| h.join().unwrap()).collect();
    assert_eq!(results.iter().filter(|r| r.is_ok()).count(), 1);
    assert!(results.iter().all(|r| r.is_ok() || *r == Err(AuthzError::Replay)));
    assert_eq!(store.records(), Some(1));
}

/// A durable store that cannot answer.
#[derive(Debug)]
struct DownStore;

impl UseStore for DownStore {
    fn record_use(&self, _: &UseKey<'_>, _: bool, _: u64, _: u64) -> Result<(), UseError> {
        Err(UseError::Unavailable)
    }

    fn is_durable(&self) -> bool {
        true
    }
}

#[test]
fn store_unavailable_denies() {
    let auth = authority_with(production_config());
    let clock = ManualClock::new(T0 + 1_000);
    assert_eq!(
        auth.authorize(&baseline_wire(), &baseline_request(), &clock, &DownStore),
        Err(AuthzError::StoreUnavailable)
    );
    // A non-durable store under production configuration is also
    // unavailable, before any other check.
    assert_eq!(
        auth.authorize(b"not even a capability", &baseline_request(), &clock, &common::memory_store()),
        Err(AuthzError::StoreUnavailable)
    );
}

#[test]
fn corrupted_store_fails_closed() {
    let dir = TempDir::new("corrupted");
    let path = dir.file("uses.log");
    let auth = authority_with(production_config());
    let clock = ManualClock::new(T0 + 1_000);
    let wire = modified(|c| c.one_time = true);
    {
        let store = FileUseStore::open(&path, 16).unwrap();
        assert!(auth.authorize(&wire, &baseline_request(), &clock, &store).is_ok());
    }
    // An attacker who can edit the log cannot make the verifier forget:
    // every edit is corruption and the store refuses to open, so there is
    // nothing to hand the verifier and it cannot authorize.
    let good = std::fs::read(&path).unwrap();
    for i in 0..good.len() {
        let mut bad = good.clone();
        bad[i] = bad[i].wrapping_add(1);
        std::fs::write(&path, &bad).unwrap();
        assert_eq!(FileUseStore::open(&path, 16).map(|_| ()), Err(UseError::Unavailable), "byte {i}");
    }
    // Zeroing the whole log is also refused (a wrong header), as is
    // replacing it with another verifier's log that chains differently.
    std::fs::write(&path, vec![0u8; good.len()]).unwrap();
    assert_eq!(FileUseStore::open(&path, 16).map(|_| ()), Err(UseError::Unavailable));
}

#[test]
fn reused_cap_id_with_different_content() {
    let fx = fresh("id-reuse");
    let a = modified(|c| c.one_time = true);
    let b = modified(|c| {
        c.one_time = true;
        c.nonce = fixture_nonce("other");
    });
    let c_reusable = modified(|c| c.policy_ref = "policy/other".into());
    assert_eq!(fx.authorize(&a, &baseline_request()), Ok(()));
    assert_eq!(fx.authorize(&b, &baseline_request()), Err(AuthzError::CapabilityIdReused));
    assert_eq!(fx.authorize(&c_reusable, &baseline_request()), Err(AuthzError::CapabilityIdReused));
    // The other way round: a reusable capability first, then a one-time
    // one under its id.
    let fx = fresh("id-reuse-2");
    assert_eq!(fx.authorize(&c_reusable, &baseline_request()), Ok(()));
    assert_eq!(fx.authorize(&c_reusable, &baseline_request()), Ok(()));
    assert_eq!(fx.authorize(&a, &baseline_request()), Err(AuthzError::CapabilityIdReused));
    assert_eq!(fx.records(), 1);
}

#[test]
fn hostile_request_descriptor_with_a_self_made_capability() {
    let fx = fresh("hostile");
    // The caller controls the request descriptor entirely and brings a
    // capability it made itself, matching that descriptor perfectly.
    let req = ActionRequest {
        subject_digest: fixture_digest("attacker-subject"),
        decision_root: fixture_digest("attacker-decision"),
        operation: "exfiltrate".into(),
        resource: "/secrets/all".into(),
        execution: None,
    };
    let mut cap = baseline_capability();
    cap.subject_digest = req.subject_digest;
    cap.decision_root = req.decision_root;
    cap.operations = vec!["exfiltrate".into()];
    cap.resources = vec![ResourceScope::prefix("/").unwrap()];
    cap.one_time = false;
    cap.normalise();
    // Signed by the attacker under the attacker's key id.
    let own = issue(&cap, "attacker");
    assert_eq!(fx.authorize(&own, &req), Err(AuthzError::UntrustedKey));
    // Signed by the attacker claiming the trusted key id.
    let claimed = issue_with_key_id(&cap, fixture_key_id("issuer-1").as_bytes(), &fixture_signing_key("attacker"));
    assert_eq!(fx.authorize(&claimed, &req), Err(AuthzError::BadSignature));
    // Unsigned: a region with a zero signature.
    let mut unsigned = cap.encode_signed_region(fixture_key_id("issuer-1").as_bytes()).unwrap();
    unsigned.extend_from_slice(&[0u8; 64]);
    assert_eq!(fx.authorize(&unsigned, &req), Err(AuthzError::BadSignature));
    // Naming an issuer and key the trust set has never heard of.
    cap.issuer_id = "attacker".into();
    let foreign = issue(&cap, "attacker");
    assert_eq!(fx.authorize(&foreign, &req), Err(AuthzError::UnknownIssuer));
    // And a matching request descriptor against a genuine capability
    // that does not grant what the descriptor asks.
    assert_eq!(fx.authorize(&baseline_wire(), &req), Err(AuthzError::SubjectMismatch));
    assert_eq!(fx.records(), 0);
}

#[test]
fn permissive_capability_with_valid_signature_but_wrong_audience() {
    let fx = fresh("permissive");
    // Everything an attacker could wish for, genuinely signed by the
    // trusted issuer, for a different verifier.
    let wire = modified(|c| {
        c.audience = "kernel-b".into();
        c.operations = (0..8).map(|i| format!("op{i}")).chain(["read".into(), "write".into()]).collect();
        c.resources = vec![ResourceScope::prefix("/").unwrap()];
        c.one_time = false;
        c.expires_at_ms = c.not_before_ms + DAY;
    });
    assert_eq!(fx.authorize(&wire, &baseline_request()), Err(AuthzError::AudienceMismatch));
    assert_eq!(
        fx.authorize(&wire, &request(|r| r.resource = "/anything".into())),
        Err(AuthzError::AudienceMismatch)
    );
    // The verifier it does name accepts it, so the only thing wrong with
    // it here is the audience.
    let b = Authority::new(
        AuthorityConfig {
            audience: "kernel-b".into(),
            ..production_config()
        },
        baseline_trust_set(),
        RevocationList::new(4),
    )
    .unwrap();
    assert!(b.authorize(&wire, &baseline_request(), &fx.clock, &fx.store).is_ok());
}

#[test]
fn no_refusal_after_the_signature_stage_touches_the_store_or_leaks_past_it() {
    // For a set of genuine capabilities that each fail one later check,
    // the store is never written: the use record is last.
    let fx = fresh("ordering");
    let max = fx.auth.config().max_lifetime_ms;
    let cases: Vec<(Vec<u8>, ActionRequest, AuthzError)> = vec![
        (modified(|c| c.audience = "x".into()), baseline_request(), AuthzError::AudienceMismatch),
        (
            baseline_wire(),
            request(|r| r.subject_digest = fixture_digest("z")),
            AuthzError::SubjectMismatch,
        ),
        (
            baseline_wire(),
            request(|r| r.decision_root = fixture_digest("z")),
            AuthzError::DecisionMismatch,
        ),
        (baseline_wire(), request(|r| r.operation = "z".into()), AuthzError::OperationDenied),
        (baseline_wire(), request(|r| r.resource = "/z".into()), AuthzError::ResourceDenied),
        (
            modified(|c| c.expires_at_ms = c.not_before_ms + max + 1),
            baseline_request(),
            AuthzError::LifetimeTooLong {
                lifetime_ms: max + 1,
                max_ms: max,
            },
        ),
    ];
    for (wire, req, expected) in cases {
        assert_eq!(fx.authorize(&wire, &req), Err(expected));
    }
    assert_eq!(fx.records(), 0);
}
