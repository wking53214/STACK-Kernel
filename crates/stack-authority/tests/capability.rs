//! Step 1: the wire encoding round-trips, and every malformed input is
//! refused with the typed reason.

#![allow(clippy::unwrap_used)]

mod common;

use common::{
    baseline_capability, fixture_bytes32, fixture_signing_key, issue_with_key_id, sign_region, RawFields, EXACT,
    PREFIX, T0,
};
use stack_authority::{
    CapabilityDigest, Field, ParseError, ResourceScope, SignedCapability, DOMAIN_TAG, MAX_ID_BYTES,
    MAX_OPERATIONS, MAX_OPERATION_BYTES, MAX_PATH_BYTES, MAX_POLICY_REF_BYTES, MAX_RESOURCES, MAX_WIRE_BYTES,
};

const CAP: usize = MAX_WIRE_BYTES;

fn key_id() -> [u8; 32] {
    fixture_bytes32("key-id")
}

fn wire() -> Vec<u8> {
    issue_with_key_id(&baseline_capability(), &key_id(), &fixture_signing_key("issuer-1"))
}

fn parse(bytes: &[u8]) -> Result<SignedCapability, ParseError> {
    SignedCapability::parse(bytes, CAP)
}

fn raw() -> RawFields {
    RawFields::from_capability(&baseline_capability(), &key_id())
}

fn parse_raw(r: &RawFields) -> Result<SignedCapability, ParseError> {
    parse(&sign_region(&r.encode(), &fixture_signing_key("issuer-1")))
}

#[test]
fn round_trip_preserves_every_field_and_the_bytes() {
    let cap = baseline_capability();
    let w = wire();
    let parsed = parse(&w).unwrap();
    assert_eq!(parsed.capability(), &cap);
    assert_eq!(parsed.key_id(), &key_id());
    assert_eq!(parsed.wire(), &w[..]);
    assert_eq!(parsed.signed_region(), &w[..w.len() - 64]);
    assert_eq!(parsed.signature(), &w[w.len() - 64..]);
    assert_eq!(parsed.digest(), &CapabilityDigest::of_wire(&w));
    // Re-encoding what was parsed gives the same signed region.
    assert_eq!(
        parsed.capability().encode_signed_region(parsed.key_id()).unwrap(),
        parsed.signed_region()
    );
}

#[test]
fn independent_raw_writer_agrees_with_the_encoder() {
    let cap = baseline_capability();
    assert_eq!(raw().encode(), cap.encode_signed_region(&key_id()).unwrap());
}

#[test]
fn digest_is_domain_separated_full_sha256_and_covers_the_signature() {
    use sha2::{Digest, Sha256};
    let w = wire();
    let d = CapabilityDigest::of_wire(&w);
    let plain: [u8; 32] = Sha256::digest(&w).into();
    assert_ne!(d.as_bytes(), &plain);
    assert_eq!(d.to_hex().len(), 64);
    assert_eq!(CapabilityDigest::from_hex(&d.to_hex()), Some(d));
    assert_eq!(CapabilityDigest::from_hex(&d.to_hex().to_uppercase()), None);
    let mut other = w.clone();
    let last = other.len() - 1;
    other[last] ^= 1;
    assert_ne!(CapabilityDigest::of_wire(&other), d);
}

#[test]
fn normalise_sorts_by_bytes_and_dedups() {
    let mut cap = baseline_capability();
    cap.operations = vec!["b".into(), "a".into(), "B".into(), "a".into()];
    cap.resources = vec![
        ResourceScope::prefix("/a").unwrap(),
        ResourceScope::exact("/a").unwrap(),
        ResourceScope::exact("/a").unwrap(),
    ];
    cap.normalise();
    assert_eq!(cap.operations, vec!["B", "a", "b"]);
    assert_eq!(
        cap.resources,
        vec![ResourceScope::exact("/a").unwrap(), ResourceScope::prefix("/a").unwrap()]
    );
}

#[test]
fn truncation_at_every_length_is_refused() {
    let w = wire();
    for n in 0..w.len() {
        let err = parse(&w[..n]).unwrap_err();
        assert!(
            matches!(
                err,
                ParseError::Truncated | ParseError::BadDomainTag | ParseError::UnsupportedVersion
            ),
            "len {n}: {err:?}"
        );
    }
}

#[test]
fn trailing_bytes_are_refused() {
    let mut w = wire();
    w.push(0);
    assert_eq!(parse(&w).unwrap_err(), ParseError::TrailingBytes);
}

#[test]
fn oversize_input_is_refused_before_reading() {
    let w = wire();
    assert_eq!(SignedCapability::parse(&w, w.len() - 1).unwrap_err(), ParseError::TooLarge);
    assert!(SignedCapability::parse(&w, w.len()).is_ok());
    let huge = vec![0u8; MAX_WIRE_BYTES + 1];
    assert_eq!(SignedCapability::parse(&huge, usize::MAX).unwrap_err(), ParseError::TooLarge);
}

#[test]
fn wrong_domain_tag_or_version_is_refused() {
    let w = wire();
    let mut other = w.clone();
    other[0] ^= 0x20;
    assert_eq!(parse(&other).unwrap_err(), ParseError::BadDomainTag);
    let mut v3 = w.clone();
    let pos = DOMAIN_TAG.len() - 2;
    assert_eq!(v3[pos], b'1');
    v3[pos] = b'3';
    assert_eq!(parse(&v3).unwrap_err(), ParseError::UnsupportedVersion);
    let mut no_newline = w;
    no_newline[DOMAIN_TAG.len() - 1] = b' ';
    assert_eq!(parse(&no_newline).unwrap_err(), ParseError::UnsupportedVersion);
    assert_eq!(parse(b"").unwrap_err(), ParseError::BadDomainTag);
    assert_eq!(parse(b"stack-capability/").unwrap_err(), ParseError::UnsupportedVersion);
}

#[test]
fn unsorted_and_duplicate_sets_are_refused() {
    let mut r = raw();
    r.operations = vec![b"write".to_vec(), b"read".to_vec()];
    assert_eq!(parse_raw(&r).unwrap_err(), ParseError::UnsortedSet(Field::Operations));
    let mut r = raw();
    r.operations = vec![b"read".to_vec(), b"read".to_vec()];
    assert_eq!(parse_raw(&r).unwrap_err(), ParseError::DuplicateMember(Field::Operations));
    let mut r = raw();
    r.resources = vec![(PREFIX, b"/b".to_vec()), (EXACT, b"/a".to_vec())];
    assert_eq!(parse_raw(&r).unwrap_err(), ParseError::UnsortedSet(Field::Resources));
    let mut r = raw();
    r.resources = vec![(PREFIX, b"/a".to_vec()), (EXACT, b"/a".to_vec())];
    assert_eq!(parse_raw(&r).unwrap_err(), ParseError::UnsortedSet(Field::Resources));
    let mut r = raw();
    r.resources = vec![(EXACT, b"/a".to_vec()), (EXACT, b"/a".to_vec())];
    assert_eq!(parse_raw(&r).unwrap_err(), ParseError::DuplicateMember(Field::Resources));
    // Same path, different kind, in order: two distinct members.
    let mut r = raw();
    r.resources = vec![(EXACT, b"/a".to_vec()), (PREFIX, b"/a".to_vec())];
    assert!(parse_raw(&r).is_ok());
}

#[test]
fn empty_sets_are_refused_as_empty_scope() {
    let mut r = raw();
    r.operations = vec![];
    assert_eq!(parse_raw(&r).unwrap_err(), ParseError::EmptyScope(Field::Operations));
    let mut r = raw();
    r.resources = vec![];
    assert_eq!(parse_raw(&r).unwrap_err(), ParseError::EmptyScope(Field::Resources));
    let mut cap = baseline_capability();
    cap.operations.clear();
    assert_eq!(
        cap.encode_signed_region(&key_id()).unwrap_err(),
        ParseError::EmptyScope(Field::Operations)
    );
    let mut cap = baseline_capability();
    cap.resources.clear();
    assert_eq!(
        cap.encode_signed_region(&key_id()).unwrap_err(),
        ParseError::EmptyScope(Field::Resources)
    );
}

#[test]
fn length_bounds_are_enforced_on_both_paths() {
    let mut r = raw();
    r.cap_id = vec![b'x'; MAX_ID_BYTES + 1];
    assert_eq!(parse_raw(&r).unwrap_err(), ParseError::LengthOutOfBounds(Field::CapId));
    let mut r = raw();
    r.cap_id = vec![];
    assert_eq!(parse_raw(&r).unwrap_err(), ParseError::LengthOutOfBounds(Field::CapId));
    let mut r = raw();
    r.issuer_id = vec![];
    assert_eq!(parse_raw(&r).unwrap_err(), ParseError::LengthOutOfBounds(Field::IssuerId));
    let mut r = raw();
    r.audience = vec![b'a'; MAX_ID_BYTES + 1];
    assert_eq!(parse_raw(&r).unwrap_err(), ParseError::LengthOutOfBounds(Field::Audience));
    let mut r = raw();
    r.operations = vec![vec![b'o'; MAX_OPERATION_BYTES + 1]];
    assert_eq!(parse_raw(&r).unwrap_err(), ParseError::LengthOutOfBounds(Field::Operation));
    let mut r = raw();
    r.operations = (0..=MAX_OPERATIONS).map(|i| format!("op{i:03}").into_bytes()).collect();
    assert_eq!(parse_raw(&r).unwrap_err(), ParseError::LengthOutOfBounds(Field::Operations));
    let mut r = raw();
    r.resources = (0..=MAX_RESOURCES).map(|i| (EXACT, format!("/r{i:03}").into_bytes())).collect();
    assert_eq!(parse_raw(&r).unwrap_err(), ParseError::LengthOutOfBounds(Field::Resources));
    let mut r = raw();
    r.resources = vec![(EXACT, vec![])];
    assert_eq!(parse_raw(&r).unwrap_err(), ParseError::LengthOutOfBounds(Field::ResourcePath));
    let mut r = raw();
    let mut long = b"/".to_vec();
    long.extend(vec![b'p'; MAX_PATH_BYTES]);
    r.resources = vec![(EXACT, long)];
    assert_eq!(parse_raw(&r).unwrap_err(), ParseError::LengthOutOfBounds(Field::ResourcePath));
    let mut r = raw();
    r.policy_ref = vec![b'p'; MAX_POLICY_REF_BYTES + 1];
    assert_eq!(parse_raw(&r).unwrap_err(), ParseError::LengthOutOfBounds(Field::PolicyRef));
    let mut r = raw();
    r.policy_ref = vec![];
    assert!(parse_raw(&r).is_ok(), "policy_ref may be empty");

    // The encoder refuses the same things.
    let mut cap = baseline_capability();
    cap.cap_id = "x".repeat(MAX_ID_BYTES + 1);
    assert_eq!(
        cap.encode_signed_region(&key_id()).unwrap_err(),
        ParseError::LengthOutOfBounds(Field::CapId)
    );
    let mut cap = baseline_capability();
    cap.operations = vec!["b".into(), "a".into()];
    assert_eq!(
        cap.encode_signed_region(&key_id()).unwrap_err(),
        ParseError::UnsortedSet(Field::Operations)
    );
    let mut cap = baseline_capability();
    cap.operations = vec!["a".into(), "a".into()];
    assert_eq!(
        cap.encode_signed_region(&key_id()).unwrap_err(),
        ParseError::DuplicateMember(Field::Operations)
    );
    let mut cap = baseline_capability();
    cap.resources = vec![ResourceScope::exact("/b").unwrap(), ResourceScope::exact("/a").unwrap()];
    assert_eq!(
        cap.encode_signed_region(&key_id()).unwrap_err(),
        ParseError::UnsortedSet(Field::Resources)
    );
    let mut cap = baseline_capability();
    cap.resources = vec![ResourceScope::exact("/a").unwrap(), ResourceScope::exact("/a").unwrap()];
    assert_eq!(
        cap.encode_signed_region(&key_id()).unwrap_err(),
        ParseError::DuplicateMember(Field::Resources)
    );
}

#[test]
fn bad_utf8_and_control_characters_are_refused() {
    type Setter = fn(&mut RawFields, Vec<u8>);
    let cases: [(Field, Setter); 5] = [
        (Field::CapId, |r, v| r.cap_id = v),
        (Field::IssuerId, |r, v| r.issuer_id = v),
        (Field::Audience, |r, v| r.audience = v),
        (Field::Operation, |r, v| r.operations = vec![v]),
        (Field::PolicyRef, |r, v| r.policy_ref = v),
    ];
    for (field, set) in cases {
        let mut r = raw();
        set(&mut r, vec![0xff, 0xfe]);
        assert_eq!(parse_raw(&r).unwrap_err(), ParseError::InvalidUtf8(field), "{field}");
        let mut r = raw();
        set(&mut r, b"a\nb".to_vec());
        assert_eq!(parse_raw(&r).unwrap_err(), ParseError::ControlCharacter(field), "{field}");
        let mut r = raw();
        set(&mut r, b"a\x7fb".to_vec());
        assert_eq!(parse_raw(&r).unwrap_err(), ParseError::ControlCharacter(field), "{field}");
        let mut r = raw();
        set(&mut r, "ünïcode".as_bytes().to_vec());
        assert!(parse_raw(&r).is_ok(), "{field}: non-ASCII UTF-8 is fine");
    }
    let mut r = raw();
    r.resources = vec![(EXACT, vec![b'/', 0xff])];
    assert_eq!(parse_raw(&r).unwrap_err(), ParseError::InvalidUtf8(Field::ResourcePath));
    let mut cap = baseline_capability();
    cap.audience = "k\u{1}".into();
    assert_eq!(
        cap.encode_signed_region(&key_id()).unwrap_err(),
        ParseError::ControlCharacter(Field::Audience)
    );
}

#[test]
fn bad_paths_scope_kinds_bools_and_windows_are_refused() {
    use stack_authority::PathError;
    let mut r = raw();
    r.resources = vec![(EXACT, b"data/a".to_vec())];
    assert_eq!(parse_raw(&r).unwrap_err(), ParseError::BadPath(PathError::NotAbsolute));
    let mut r = raw();
    r.resources = vec![(EXACT, b"/data/../a".to_vec())];
    assert_eq!(parse_raw(&r).unwrap_err(), ParseError::BadPath(PathError::DotSegment));
    let mut r = raw();
    r.resources = vec![(EXACT, b"/data//a".to_vec())];
    assert_eq!(parse_raw(&r).unwrap_err(), ParseError::BadPath(PathError::EmptySegment));
    let mut r = raw();
    r.resources = vec![(EXACT, b"/data/a\n".to_vec())];
    // The string rule fires before the path rule; both refuse.
    assert_eq!(parse_raw(&r).unwrap_err(), ParseError::ControlCharacter(Field::ResourcePath));
    let mut r = raw();
    r.resources = vec![(2, b"/data/a".to_vec())];
    assert_eq!(parse_raw(&r).unwrap_err(), ParseError::BadScopeKind);
    let mut r = raw();
    r.one_time = 2;
    assert_eq!(parse_raw(&r).unwrap_err(), ParseError::BadBool);
    let mut r = raw();
    r.one_time = 1;
    assert!(parse_raw(&r).unwrap().capability().one_time);
    let mut r = raw();
    r.expires_at_ms = r.not_before_ms;
    assert_eq!(parse_raw(&r).unwrap_err(), ParseError::WindowInverted);
    let mut r = raw();
    r.expires_at_ms = T0 - 1;
    assert_eq!(parse_raw(&r).unwrap_err(), ParseError::WindowInverted);
    let mut cap = baseline_capability();
    cap.expires_at_ms = cap.not_before_ms;
    assert_eq!(cap.encode_signed_region(&key_id()).unwrap_err(), ParseError::WindowInverted);
}

#[test]
fn parsing_never_panics_on_random_mutations() {
    // A cheap deterministic fuzz: xor one byte at a time with every bit
    // pattern and parse. Any outcome but a panic is acceptable here; the
    // signature tests in later steps assert that none of these verify.
    let w = wire();
    for i in 0..w.len() {
        for bit in 0..8 {
            let mut m = w.clone();
            m[i] ^= 1 << bit;
            let _ = parse(&m);
        }
    }
}
