//! Step 2: key ids, public key validation, the trust set (insert, revoke,
//! rotation, resolution order), the revocation list and strict signature
//! verification.

#![allow(clippy::unwrap_used)]

mod common;

use common::{
    baseline_capability, baseline_trust_set, baseline_wire, fixture_anchor, fixture_anchor_window, fixture_key_id,
    fixture_public_key, fixture_signing_key, issue, issue_with_key_id, DAY, HOUR, T0,
};
use sha2::{Digest, Sha256};
use stack_authority::{
    AnchorStatus, BadSignature, CapabilityDigest, Field, KeyId, ParseError, PublicKey, Purpose, ResolveError,
    RevocationList, SignedCapability, TrustAnchor, TrustError, TrustSet, MAX_WIRE_BYTES,
};

fn parse(bytes: &[u8]) -> SignedCapability {
    SignedCapability::parse(bytes, MAX_WIRE_BYTES).unwrap()
}

#[test]
fn key_id_is_domain_separated_full_sha256_with_one_spelling() {
    let pk = fixture_public_key("issuer-1");
    let id = pk.key_id();
    let plain: [u8; 32] = Sha256::digest(pk.as_bytes()).into();
    assert_ne!(id.as_bytes(), &plain);
    assert_eq!(id.to_hex().len(), 64);
    assert_eq!(KeyId::from_hex(&id.to_hex()), Some(id));
    assert_eq!(KeyId::from_hex(&id.to_hex().to_uppercase()), None);
    assert_eq!(KeyId::from_bytes(*id.as_bytes()), id);
    assert_ne!(fixture_key_id("issuer-2"), id);
    assert!(format!("{pk:?}").starts_with("PublicKey("));
}

#[test]
fn weak_or_invalid_public_keys_are_refused() {
    // The identity point and a point of order four.
    assert_eq!(PublicKey::from_bytes([1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]).unwrap_err(), TrustError::WeakKey);
    assert_eq!(PublicKey::from_bytes([0; 32]).unwrap_err(), TrustError::WeakKey);
    // About half of all y values have no x on the curve and do not
    // decode; at least one of the first 64 must be refused.
    let undecodable = (2u8..66)
        .filter(|y| {
            let mut b = [0u8; 32];
            b[0] = *y;
            PublicKey::from_bytes(b) == Err(TrustError::WeakKey)
        })
        .count();
    assert!(undecodable > 0);
    assert!(PublicKey::from_bytes(fixture_signing_key("ok").verifying_key().to_bytes()).is_ok());
}

#[test]
fn anchors_validate_issuer_id_and_window() {
    let pk = fixture_public_key("issuer-1");
    assert_eq!(
        TrustAnchor::new("", pk, Purpose::CapabilityIssuer, 0, 1).unwrap_err(),
        TrustError::BadIssuerId(ParseError::LengthOutOfBounds(Field::IssuerId))
    );
    assert_eq!(
        TrustAnchor::new(&"i".repeat(129), pk, Purpose::CapabilityIssuer, 0, 1).unwrap_err(),
        TrustError::BadIssuerId(ParseError::LengthOutOfBounds(Field::IssuerId))
    );
    assert_eq!(
        TrustAnchor::new("i\n", pk, Purpose::CapabilityIssuer, 0, 1).unwrap_err(),
        TrustError::BadIssuerId(ParseError::ControlCharacter(Field::IssuerId))
    );
    assert_eq!(
        TrustAnchor::new("issuer-1", pk, Purpose::CapabilityIssuer, 5, 5).unwrap_err(),
        TrustError::WindowInverted
    );
    assert_eq!(
        TrustAnchor::new("issuer-1", pk, Purpose::CapabilityIssuer, 6, 5).unwrap_err(),
        TrustError::WindowInverted
    );
    let a = TrustAnchor::new("issuer-1", pk, Purpose::CapabilityIssuer, 5, 6).unwrap();
    assert_eq!(a.issuer_id(), "issuer-1");
    assert_eq!(a.key_id(), &pk.key_id());
    assert_eq!(a.public_key(), &pk);
    assert_eq!(a.purpose(), Purpose::CapabilityIssuer);
    assert_eq!((a.not_before_ms(), a.not_after_ms()), (5, 6));
    assert_eq!(a.status(), AnchorStatus::Active);
}

#[test]
fn trust_set_is_bounded_and_one_key_appears_once() {
    let mut ts = TrustSet::new(2);
    assert!(ts.is_empty());
    assert_eq!(ts.max_anchors(), 2);
    let id = ts.insert(fixture_anchor("issuer-1", "issuer-1")).unwrap();
    assert_eq!(id, fixture_key_id("issuer-1"));
    // Same key under another issuer: still a duplicate.
    assert_eq!(
        ts.insert(fixture_anchor("issuer-2", "issuer-1")).unwrap_err(),
        TrustError::Duplicate
    );
    ts.insert(fixture_anchor("issuer-2", "issuer-2")).unwrap();
    assert_eq!(
        ts.insert(fixture_anchor("issuer-3", "issuer-3")).unwrap_err(),
        TrustError::Full { max: 2 }
    );
    assert_eq!(ts.len(), 2);
    assert!(ts.knows_issuer("issuer-1") && ts.knows_issuer("issuer-2") && !ts.knows_issuer("issuer-3"));
    assert!(ts.get(&id).is_some());
    assert!(ts.remove(&id));
    assert!(!ts.remove(&id));
    assert!(!ts.knows_issuer("issuer-1"));
    assert_eq!(ts.len(), 1);
}

#[test]
fn resolution_checks_identity_then_status_then_window() {
    let mut ts = baseline_trust_set();
    let id = fixture_key_id("issuer-1");
    assert!(ts.resolve("issuer-1", &id, T0).is_ok());
    assert_eq!(ts.resolve("issuer-9", &id, T0).unwrap_err(), ResolveError::UnknownIssuer);
    assert_eq!(
        ts.resolve("issuer-1", &fixture_key_id("other"), T0).unwrap_err(),
        ResolveError::UntrustedKey
    );
    // A key trusted for another issuer is untrusted for this one.
    ts.insert(fixture_anchor("issuer-2", "issuer-2")).unwrap();
    assert_eq!(
        ts.resolve("issuer-1", &fixture_key_id("issuer-2"), T0).unwrap_err(),
        ResolveError::UntrustedKey
    );
    // Window edges: start inclusive, end exclusive.
    assert_eq!(
        ts.resolve("issuer-1", &id, T0 - DAY - 1).unwrap_err(),
        ResolveError::IssuerKeyNotYetValid
    );
    assert!(ts.resolve("issuer-1", &id, T0 - DAY).is_ok());
    assert!(ts.resolve("issuer-1", &id, T0 + DAY - 1).is_ok());
    assert_eq!(
        ts.resolve("issuer-1", &id, T0 + DAY).unwrap_err(),
        ResolveError::IssuerKeyExpired
    );
    // Revocation wins over the window and keeps the record.
    assert!(ts.revoke(&id));
    assert!(!ts.revoke(&id));
    assert_eq!(ts.resolve("issuer-1", &id, T0).unwrap_err(), ResolveError::IssuerRevoked);
    assert_eq!(
        ts.resolve("issuer-1", &id, T0 + DAY).unwrap_err(),
        ResolveError::IssuerRevoked
    );
    assert_eq!(ts.get(&id).unwrap().status(), AnchorStatus::Revoked);
    assert_eq!(
        ts.insert(fixture_anchor("issuer-1", "issuer-1")).unwrap_err(),
        TrustError::Duplicate
    );
    assert!(!ts.revoke(&fixture_key_id("nobody")));
}

#[test]
fn rotation_is_two_overlapping_anchors() {
    let mut ts = TrustSet::new(8);
    let old = ts
        .insert(fixture_anchor_window("issuer-1", "issuer-1-old", T0 - DAY, T0 + HOUR))
        .unwrap();
    let new = ts
        .insert(fixture_anchor_window("issuer-1", "issuer-1-new", T0, T0 + DAY))
        .unwrap();
    // Before the overlap: only the old key.
    assert!(ts.resolve("issuer-1", &old, T0 - 1).is_ok());
    assert_eq!(
        ts.resolve("issuer-1", &new, T0 - 1).unwrap_err(),
        ResolveError::IssuerKeyNotYetValid
    );
    // In the overlap: both.
    assert!(ts.resolve("issuer-1", &old, T0 + HOUR - 1).is_ok());
    assert!(ts.resolve("issuer-1", &new, T0 + HOUR - 1).is_ok());
    // After: only the new key.
    assert_eq!(
        ts.resolve("issuer-1", &old, T0 + HOUR).unwrap_err(),
        ResolveError::IssuerKeyExpired
    );
    assert!(ts.resolve("issuer-1", &new, T0 + HOUR).is_ok());
    // Capabilities signed under each key verify under their own anchor
    // only.
    let cap = baseline_capability();
    let under_old = parse(&issue(&cap, "issuer-1-old"));
    let under_new = parse(&issue(&cap, "issuer-1-new"));
    assert!(ts.get(&old).unwrap().verify(&under_old).is_ok());
    assert!(ts.get(&new).unwrap().verify(&under_new).is_ok());
    assert_eq!(ts.get(&new).unwrap().verify(&under_old), Err(BadSignature));
    assert_eq!(ts.get(&old).unwrap().verify(&under_new), Err(BadSignature));
}

#[test]
fn revocation_list_is_bounded_and_matches_by_id_or_digest() {
    let mut rl = RevocationList::new(2);
    assert!(rl.is_empty());
    let signed = parse(&baseline_wire());
    let other = CapabilityDigest::of_wire(b"other");
    assert!(!rl.is_revoked("cap-0001", signed.digest()));
    assert!(rl.revoke_id("cap-0001").unwrap());
    assert!(!rl.revoke_id("cap-0001").unwrap());
    assert!(rl.is_revoked("cap-0001", &other));
    assert!(!rl.is_revoked("cap-0002", signed.digest()));
    assert!(rl.revoke_digest(*signed.digest()).unwrap());
    assert!(!rl.revoke_digest(*signed.digest()).unwrap());
    assert!(rl.is_revoked("cap-0002", signed.digest()));
    assert_eq!(rl.len(), 2);
    assert_eq!(rl.revoke_id("cap-0003").unwrap_err(), TrustError::Full { max: 2 });
    assert_eq!(rl.revoke_digest(other).unwrap_err(), TrustError::Full { max: 2 });
}

#[test]
fn honest_signature_verifies_under_its_anchor() {
    let ts = baseline_trust_set();
    let signed = parse(&baseline_wire());
    let anchor = ts
        .resolve(&signed.capability().issuer_id, &KeyId::from_bytes(*signed.key_id()), T0)
        .unwrap();
    assert_eq!(anchor.verify(&signed), Ok(()));
    assert_eq!(
        anchor
            .public_key()
            .verify_strict(signed.signed_region(), signed.signature()),
        Ok(())
    );
}

#[test]
fn every_single_byte_flip_in_the_wire_fails_to_verify() {
    let ts = baseline_trust_set();
    let anchor = ts.get(&fixture_key_id("issuer-1")).unwrap().clone();
    let wire = baseline_wire();
    let mut parsed_ok = 0usize;
    for i in 0..wire.len() {
        // One flipped bit per byte, the bit position varying with the
        // offset, so every byte of the signed region and the signature is
        // altered once.
        let mut m = wire.clone();
        m[i] ^= 1 << (i % 8);
        if let Ok(signed) = SignedCapability::parse(&m, MAX_WIRE_BYTES) {
            parsed_ok += 1;
            assert_eq!(anchor.verify(&signed), Err(BadSignature), "byte {i}");
        }
    }
    // Most flips still parse (digests, nonce, timestamps, signature
    // bytes), so the signature check is what refuses them.
    assert!(parsed_ok > wire.len() / 2, "{parsed_ok} mutations parsed");
}

#[test]
fn transplanted_signature_and_wrong_key_id_fail() {
    let ts = baseline_trust_set();
    let anchor = ts.get(&fixture_key_id("issuer-1")).unwrap();
    let a = baseline_wire();
    let mut other = baseline_capability();
    other.cap_id = "cap-0002".into();
    let b = issue(&other, "issuer-1");
    // Signature of b under a's body.
    let mut transplanted = a[..a.len() - 64].to_vec();
    transplanted.extend_from_slice(&b[b.len() - 64..]);
    assert_eq!(anchor.verify(&parse(&transplanted)), Err(BadSignature));
    // Signed by an untrusted key but claiming the trusted key id.
    let forged = issue_with_key_id(
        &baseline_capability(),
        fixture_key_id("issuer-1").as_bytes(),
        &fixture_signing_key("attacker"),
    );
    assert_eq!(anchor.verify(&parse(&forged)), Err(BadSignature));
    // Signed by the trusted key but naming another key id: the anchor's
    // id does not match, so it is a bad signature here too.
    let misnamed = issue_with_key_id(
        &baseline_capability(),
        fixture_key_id("other").as_bytes(),
        &fixture_signing_key("issuer-1"),
    );
    assert_eq!(anchor.verify(&parse(&misnamed)), Err(BadSignature));
}

#[test]
fn non_canonical_signature_scalar_is_refused() {
    // Ed25519 group order L. Adding L to S gives a scalar that a lax
    // verifier reduces to the same value; strict verification refuses it.
    const L: [u8; 32] = [
        0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10,
    ];
    let ts = baseline_trust_set();
    let anchor = ts.get(&fixture_key_id("issuer-1")).unwrap();
    let mut wire = baseline_wire();
    let n = wire.len();
    let s = &mut wire[n - 32..];
    let mut carry = 0u16;
    for (byte, l) in s.iter_mut().zip(L.iter()) {
        let sum = u16::from(*byte) + u16::from(*l) + carry;
        *byte = (sum & 0xff) as u8;
        carry = sum >> 8;
    }
    assert_eq!(carry, 0, "S + L fits in 32 bytes");
    assert_eq!(anchor.verify(&parse(&wire)), Err(BadSignature));
}
