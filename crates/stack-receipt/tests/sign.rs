//! Signing, verification, frames and the trusted receipt key set.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use common::*;
use ed25519_dalek::{Signer, SigningKey};
use sha2::{Digest, Sha256};
use stack_receipt::{
    genesis_hash, record_hash, signed_message, BadSignature, FrameError, ReceiptKeyAnchor, ReceiptKeyId,
    ReceiptKeyStatus, ReceiptPublicKey, ResolveError, SignError, SignedRecord, TrustError, TrustedReceiptKeys,
    WeakKey, FRAME_OVERHEAD, RECEIPT_KEY_ID_DOMAIN, SIGNATURE_DOMAIN,
};

#[test]
fn a_signed_record_verifies_under_its_key_and_under_no_other() {
    let signer = fixture_signer("kernel-1");
    let mut r = record(1, genesis_hash(), proposed());
    r.key_id = *signer.key_id();
    let s = signer.sign(r.clone()).unwrap();
    assert_eq!(s.record(), &r);
    assert_eq!(*s.hash(), record_hash(s.canonical()));
    assert_eq!(s.verify(signer.public_key()), Ok(()));
    assert_eq!(s.verify(&fixture_public_key("kernel-2")), Err(BadSignature));
}

#[test]
fn the_signature_covers_the_domain_and_the_record_hash_and_nothing_else() {
    let signer = fixture_signer("kernel-1");
    let mut r = record(1, genesis_hash(), attempted());
    r.key_id = *signer.key_id();
    let s = signer.sign(r).unwrap();
    // Recompute with the raw library over the documented message.
    let secret: [u8; 32] = Sha256::digest(b"stack-receipt TEST FIXTURE key: kernel-1").into();
    let raw = SigningKey::from_bytes(&secret);
    let mut msg = SIGNATURE_DOMAIN.to_vec();
    msg.extend_from_slice(s.hash());
    assert_eq!(signed_message(s.hash()), msg);
    assert_eq!(raw.sign(&msg).to_bytes(), *s.signature());
    // A signature over the bare hash, or over the canonical bytes, is not
    // a receipt signature.
    let bare = raw.sign(s.hash()).to_bytes();
    assert_eq!(
        SignedRecord::from_parts(s.canonical().to_vec(), bare, *s.hash())
            .unwrap()
            .verify(signer.public_key()),
        Err(BadSignature)
    );
    let over_bytes = raw.sign(s.canonical()).to_bytes();
    assert_eq!(
        SignedRecord::from_parts(s.canonical().to_vec(), over_bytes, *s.hash())
            .unwrap()
            .verify(signer.public_key()),
        Err(BadSignature)
    );
}

#[test]
fn key_id_is_domain_separated_full_sha256_of_the_public_key() {
    let pk = fixture_public_key("kernel-1");
    let mut h = Sha256::new();
    h.update(RECEIPT_KEY_ID_DOMAIN);
    h.update(pk.as_bytes());
    assert_eq!(pk.key_id(), ReceiptKeyId::from_bytes(h.finalize().into()));
    assert_eq!(pk.key_id().to_hex().len(), 64);
    assert_eq!(ReceiptKeyId::from_hex(&pk.key_id().to_hex()), Some(pk.key_id()));
    assert_ne!(
        *pk.key_id().as_bytes(),
        <[u8; 32]>::from(Sha256::digest(pk.as_bytes())),
        "no bare sha256"
    );
}

#[test]
fn a_signer_refuses_a_record_that_names_another_key() {
    let signer = fixture_signer("kernel-1");
    let r = record(1, genesis_hash(), proposed());
    assert_ne!(r.key_id, *signer.key_id());
    assert_eq!(signer.sign(r).unwrap_err(), SignError::KeyIdMismatch);
    let mut bad = record(1, genesis_hash(), proposed());
    bad.key_id = *signer.key_id();
    bad.kernel_id = String::new();
    assert!(matches!(signer.sign(bad), Err(SignError::Invalid(_))));
}

#[test]
fn every_byte_flip_of_the_signature_or_the_record_is_refused() {
    let signer = fixture_signer("kernel-1");
    let s = sign_chain(vec![rejected()]).remove(0);
    for i in 0..64 {
        let mut sig = *s.signature();
        sig[i] ^= 1;
        let m = SignedRecord::from_parts(s.canonical().to_vec(), sig, *s.hash()).unwrap();
        assert_eq!(m.verify(signer.public_key()), Err(BadSignature), "sig byte {i}");
    }
    for i in 0..s.canonical().len() {
        let mut c = s.canonical().to_vec();
        c[i] ^= 1;
        match SignedRecord::from_parts(c.clone(), *s.signature(), *s.hash()) {
            Err(FrameError::HashMismatch | FrameError::Decode(_)) => {}
            other => panic!("record byte {i}: {other:?}"),
        }
        // Even with the hash recomputed, the old signature does not cover it.
        if let Ok(m) = SignedRecord::from_parts(c.clone(), *s.signature(), record_hash(&c)) {
            assert_eq!(m.verify(signer.public_key()), Err(BadSignature), "record byte {i}");
        }
    }
}

#[test]
fn weak_and_undecodable_public_keys_are_refused() {
    // y = 0 decodes to a point of order 4.
    assert_eq!(ReceiptPublicKey::from_bytes([0; 32]).unwrap_err(), WeakKey);
    // About half of all y values have no x on the curve and do not
    // decode; at least one of the first 64 must be refused.
    let undecodable = (2u8..66)
        .filter(|y| {
            let mut b = [0u8; 32];
            b[0] = *y;
            ReceiptPublicKey::from_bytes(b) == Err(WeakKey)
        })
        .count();
    assert!(undecodable > 0);
    // The identity point, order 1.
    let mut identity = [0u8; 32];
    identity[0] = 1;
    assert_eq!(ReceiptPublicKey::from_bytes(identity).unwrap_err(), WeakKey);
    assert!(ReceiptPublicKey::from_bytes(*fixture_public_key("kernel-1").as_bytes()).is_ok());
}

#[test]
fn frames_round_trip_and_every_truncation_is_refused() {
    let chain = sign_chain(honest_events());
    for s in &chain {
        let frame = s.to_frame();
        assert_eq!(frame.len(), s.canonical().len() + FRAME_OVERHEAD);
        let (back, used) = SignedRecord::parse_frame(&frame).unwrap();
        assert_eq!(used, frame.len());
        assert_eq!(&back, s);
        for n in 0..frame.len() {
            assert!(
                matches!(SignedRecord::parse_frame(&frame[..n]), Err(FrameError::Truncated { .. })),
                "len {n}"
            );
        }
        let mut two = frame.clone();
        two.extend_from_slice(&frame);
        let (_, used) = SignedRecord::parse_frame(&two).unwrap();
        assert_eq!(used, frame.len(), "parses one frame and reports where the next begins");
    }
}

#[test]
fn a_frame_with_a_bad_length_or_stored_hash_is_refused() {
    let s = sign_chain(vec![proposed()]).remove(0);
    let frame = s.to_frame();
    let mut zero = frame.clone();
    zero[..4].copy_from_slice(&0u32.to_be_bytes());
    assert_eq!(SignedRecord::parse_frame(&zero), Err(FrameError::LengthOutOfRange(0)));
    let mut huge = frame.clone();
    huge[..4].copy_from_slice(&u32::MAX.to_be_bytes());
    assert!(matches!(SignedRecord::parse_frame(&huge), Err(FrameError::LengthOutOfRange(_))));
    let last = frame.len() - 1;
    let mut hash_flipped = frame.clone();
    hash_flipped[last] ^= 1;
    assert_eq!(SignedRecord::parse_frame(&hash_flipped), Err(FrameError::HashMismatch));
}

#[test]
fn trust_resolution_checks_identity_then_status_then_window() {
    let mut t = TrustedReceiptKeys::new(4);
    assert!(t.is_empty());
    let id = t.insert(fixture_anchor("kernel-1", "kernel-1")).unwrap();
    assert_eq!(t.len(), 1);
    assert_eq!(t.get(&id).unwrap().status(), ReceiptKeyStatus::Active);
    assert!(t.resolve("kernel-1", &id, T0).is_ok());
    let other = fixture_public_key("kernel-2").key_id();
    assert_eq!(t.resolve("kernel-1", &other, T0), Err(ResolveError::UntrustedKey));
    assert_eq!(t.resolve("kernel-2", &id, T0), Err(ResolveError::UntrustedKey), "wrong kernel");
    assert_eq!(t.resolve("kernel-1", &id, T0 - DAY - 1), Err(ResolveError::NotYetValid));
    assert_eq!(t.resolve("kernel-1", &id, T0 - DAY), Ok(t.get(&id).unwrap()), "inclusive start");
    assert_eq!(t.resolve("kernel-1", &id, T0 + DAY), Err(ResolveError::Expired), "exclusive end");
    assert!(t.revoke(&id));
    assert!(!t.revoke(&id), "already revoked");
    assert_eq!(t.resolve("kernel-1", &id, T0), Err(ResolveError::Revoked));
    assert_eq!(
        t.resolve("kernel-1", &id, T0 + DAY),
        Err(ResolveError::Revoked),
        "status before window"
    );
    assert_eq!(
        t.insert(fixture_anchor("kernel-1", "kernel-1")).unwrap_err(),
        TrustError::Duplicate,
        "a revoked key cannot be re-inserted"
    );
}

#[test]
fn the_set_is_bounded_and_anchors_are_validated() {
    let mut t = TrustedReceiptKeys::new(1);
    t.insert(fixture_anchor("kernel-1", "kernel-1")).unwrap();
    assert_eq!(
        t.insert(fixture_anchor("kernel-1", "kernel-2")).unwrap_err(),
        TrustError::Full { max: 1 }
    );
    assert!(matches!(
        ReceiptKeyAnchor::new("", fixture_public_key("kernel-1"), 0, 1),
        Err(TrustError::BadKernelId(_))
    ));
    assert_eq!(
        ReceiptKeyAnchor::new("k", fixture_public_key("kernel-1"), 5, 5).unwrap_err(),
        TrustError::WindowInverted
    );
}

#[test]
fn rotation_is_two_overlapping_anchors_and_each_record_verifies_only_under_its_own() {
    let mut t = TrustedReceiptKeys::new(4);
    let old = ReceiptKeyAnchor::new("kernel-1", fixture_public_key("old"), T0, T0 + 2 * DAY).unwrap();
    let new = ReceiptKeyAnchor::new("kernel-1", fixture_public_key("new"), T0 + DAY, T0 + 3 * DAY).unwrap();
    let old_id = t.insert(old).unwrap();
    let new_id = t.insert(new).unwrap();
    assert!(t.resolve("kernel-1", &old_id, T0 + DAY / 2).is_ok());
    assert_eq!(t.resolve("kernel-1", &new_id, T0 + DAY / 2), Err(ResolveError::NotYetValid));
    assert!(t.resolve("kernel-1", &old_id, T0 + DAY + DAY / 2).is_ok());
    assert!(t.resolve("kernel-1", &new_id, T0 + DAY + DAY / 2).is_ok());
    assert_eq!(t.resolve("kernel-1", &old_id, T0 + 2 * DAY), Err(ResolveError::Expired));
    assert!(t.resolve("kernel-1", &new_id, T0 + 2 * DAY).is_ok());
    let under_old = sign_chain_with(&fixture_signer("old"), vec![proposed()]).remove(0);
    assert!(under_old.verify(t.get(&old_id).unwrap().public_key()).is_ok());
    assert_eq!(
        under_old.verify(t.get(&new_id).unwrap().public_key()),
        Err(BadSignature)
    );
}

#[test]
fn a_chain_of_signed_records_links_hashes_and_sequences() {
    let chain = sign_chain(honest_events());
    let mut prev = genesis_hash();
    for (i, s) in chain.iter().enumerate() {
        assert_eq!(s.record().sequence, u64::try_from(i).unwrap() + 1);
        assert_eq!(s.record().prev_hash, prev);
        prev = *s.hash();
    }
}

#[test]
fn debug_output_never_shows_the_secret() {
    let signer = fixture_signer("kernel-1");
    let secret: [u8; 32] = Sha256::digest(b"stack-receipt TEST FIXTURE key: kernel-1").into();
    let shown = format!("{signer:?}");
    assert!(shown.contains(&signer.key_id().to_hex()));
    assert!(!shown.contains(&hex::encode(secret)));
}
