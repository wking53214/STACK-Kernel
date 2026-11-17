//! The CNS decision receipt: a signed statement that CNS made a decision about a
//! subject, checked by the issuer before it signs a capability. Keys are TEST
//! FIXTURES derived from public labels. The known-answer receipt was produced by an
//! independent Python script (see `KAT_*`), not by this crate.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use common::*;
use ed25519_dalek::Signer as _;
use serde_json::{json, Value};
use stack_admission::DecisionClaim;
use stack_authority::{Digest32, ManualClock, ResourceScope, ScopeKind, KEY_ID_BYTES, SIGNATURE_BYTES};
use stack_issuer::{
    AttesterKey, CnsReceiptVerifier, DecisionVerifier, IssuanceRequest, IssueError, Issuer, ReceiptConfigError,
    ReceiptError, ReceiptFields, RECEIPT_DOMAIN, RECEIPT_LEN, RECEIPT_VERSION,
};

const MAX_VALIDITY: u64 = 5 * 60 * 1000;
const SKEW: u64 = 5_000;
const NONCE: [u8; 16] = [7; 16];

/// Independently computed (Python, `cryptography`): the signed region and the wire form of a
/// receipt for the `all_pass` case, key label `cns-attester`, issued at T0, valid 300 seconds,
/// nonce 0..16.
const KAT_SIGNED: &str = "737461636b2d6973737565722f636e732d6465636973696f6e2d726563656970742f310a01e1926fdb585b6b817292a081e3ad2f65e6237a91705e66151d1578c77506b6cb32b57492907675867f122c85ae6c2eee02d9eb6f63c3452eeb3c9bca0576ae2e08efae276351fd848c7e16be2d907c72d54b5ba1bf65723891e706c5a5c641be000001a3185c5000000001a31860e3e0000102030405060708090a0b0c0d0e0f";
const KAT_WIRE: &str = "01e1926fdb585b6b817292a081e3ad2f65e6237a91705e66151d1578c77506b6cb32b57492907675867f122c85ae6c2eee02d9eb6f63c3452eeb3c9bca0576ae2e08efae276351fd848c7e16be2d907c72d54b5ba1bf65723891e706c5a5c641be000001a3185c5000000001a31860e3e0000102030405060708090a0b0c0d0e0f15d056903724a6335100e7dac83087052231937d5b9dc027b6b80494b9fb538dee4ec62f0ce4c79deedd17a9c590850a182b9850542996ac10a68d2460f7010c";

fn attester(label: &str, from: u64, to: u64) -> AttesterKey {
    AttesterKey { key: public_key(label), not_before_ms: from, not_after_ms: to }
}

fn default_keys() -> Vec<AttesterKey> {
    vec![attester("cns-attester", T0 - HOUR, T0 + DAY)]
}

fn verifier_at(keys: Vec<AttesterKey>, now: u64) -> CnsReceiptVerifier {
    CnsReceiptVerifier::new(keys, MAX_VALIDITY, SKEW, Box::new(ManualClock::new(now))).unwrap()
}

fn digest(case: &Value, field: &str) -> Digest32 {
    Digest32::from_hex(case[field].as_str().unwrap()).unwrap()
}

fn fields_for(case: &Value, label: &str, issued: u64, expires: u64) -> ReceiptFields {
    ReceiptFields {
        key_id: public_key(label).key_id(),
        subject_digest: digest(case, "subject_digest"),
        decision_root: digest(case, "root"),
        issued_at_ms: issued,
        expires_at_ms: expires,
        nonce: NONCE,
    }
}

fn sign(label: &str, f: &ReceiptFields) -> Vec<u8> {
    let sig = signing_key(label).sign(&f.signed_bytes());
    f.encode(&sig.to_bytes())
}

fn good(case: &Value) -> Vec<u8> {
    sign("cns-attester", &fields_for(case, "cns-attester", T0, T0 + 60_000))
}

fn check(v: &CnsReceiptVerifier, case: &Value, receipt: &[u8]) -> Result<(), ReceiptError> {
    v.check(&digest(case, "subject_digest"), &digest(case, "root"), receipt)
}

fn request(case: &Value) -> IssuanceRequest {
    IssuanceRequest {
        requester: "requester-1".into(),
        subject: case["subject"].clone(),
        decision: decision_of(case),
        operation: "echo".into(),
        resources: vec![ResourceScope::new(ScopeKind::Exact, "/data/a").unwrap()],
        args: json!({"target": "a"}),
        lifetime_ms: 60_000,
    }
}

fn issuer_with_verifier(v: CnsReceiptVerifier, log: &SharedLog) -> Issuer {
    Issuer::new(
        issuer_config(),
        Box::new(FixtureSigner::honest(ISSUER)),
        Box::new(CounterEntropy::default()),
        Box::new(log.clone()),
        Box::new(ManualClock::new(T0)),
        Box::new(v),
        Box::new(FixtureAuthorizer::default()),
    )
    .unwrap()
}

// ---- the wire format ------------------------------------------------------

#[test]
fn the_format_constants_are_what_the_design_says() {
    assert_eq!(RECEIPT_VERSION, 1);
    assert_eq!(RECEIPT_DOMAIN, b"stack-issuer/cns-decision-receipt/1\n");
    assert_eq!(RECEIPT_LEN, 1 + KEY_ID_BYTES + 32 + 32 + 8 + 8 + 16 + SIGNATURE_BYTES);
    assert_eq!(RECEIPT_LEN, 193);
}

#[test]
fn a_receipt_computed_independently_in_python_has_these_bytes_and_verifies() {
    let case = case("all_pass");
    let nonce: [u8; 16] = std::array::from_fn(|i| i as u8);
    let f = ReceiptFields { nonce, ..fields_for(&case, "cns-attester", T0, T0 + 300_000) };
    assert_eq!(hex::encode(f.signed_bytes()), KAT_SIGNED, "the signed region is the one the Python script built");
    let wire = hex::decode(KAT_WIRE).unwrap();
    assert_eq!(wire.len(), RECEIPT_LEN);
    // The Rust fixture key signs the same bytes to the same signature (Ed25519 is deterministic).
    assert_eq!(sign("cns-attester", &f), wire);
    // And the verifier accepts the Python-made receipt.
    let v = CnsReceiptVerifier::new(default_keys(), 300_000, SKEW, Box::new(ManualClock::new(T0 + 1))).unwrap();
    check(&v, &case, &wire).unwrap();
}

// ---- what a genuine receipt does ------------------------------------------

#[test]
fn a_genuine_receipt_lets_the_issuer_sign_and_the_log_records_it() {
    let case = case("all_pass");
    let log = SharedLog::default();
    let issuer = issuer_with_verifier(verifier_at(default_keys(), T0), &log);
    let issued = issuer.issue_with_receipt(&request(&case), Some(&good(&case))).unwrap();
    assert!(!issued.wire.is_empty());
    assert_eq!(log.count(), 1);
}

#[test]
fn without_a_receipt_this_verifier_refuses_and_nothing_is_logged() {
    let case = case("all_pass");
    let log = SharedLog::default();
    let issuer = issuer_with_verifier(verifier_at(default_keys(), T0), &log);
    assert!(matches!(issuer.issue(&request(&case)), Err(IssueError::DecisionNotVerified(_))));
    assert!(matches!(issuer.issue_with_receipt(&request(&case), None), Err(IssueError::DecisionNotVerified(_))));
    assert_eq!(log.count(), 0);
}

#[test]
fn a_bad_receipt_leaves_no_capability_and_no_log_record() {
    let case = case("all_pass");
    let log = SharedLog::default();
    let issuer = issuer_with_verifier(verifier_at(default_keys(), T0), &log);
    let mut bad = good(&case);
    bad[RECEIPT_LEN - 1] ^= 1;
    assert!(matches!(issuer.issue_with_receipt(&request(&case), Some(&bad)), Err(IssueError::DecisionNotVerified(_))));
    assert_eq!(log.count(), 0);
}

// ---- tampering ------------------------------------------------------------

#[test]
fn flipping_any_single_bit_of_a_receipt_makes_it_fail() {
    let case = case("all_pass");
    let v = verifier_at(default_keys(), T0);
    let wire = good(&case);
    check(&v, &case, &wire).unwrap();
    for byte in 0..wire.len() {
        for bit in 0..8 {
            let mut t = wire.clone();
            t[byte] ^= 1 << bit;
            assert!(check(&v, &case, &t).is_err(), "byte {byte} bit {bit} changed and the receipt still verified");
        }
    }
}

#[test]
fn a_receipt_of_the_wrong_length_or_version_is_refused_before_anything_else() {
    let case = case("all_pass");
    let v = verifier_at(default_keys(), T0);
    let wire = good(&case);
    assert_eq!(check(&v, &case, &[]), Err(ReceiptError::BadLength));
    assert_eq!(check(&v, &case, &wire[..RECEIPT_LEN - 1]), Err(ReceiptError::BadLength));
    let mut longer = wire.clone();
    longer.push(0);
    assert_eq!(check(&v, &case, &longer), Err(ReceiptError::BadLength));
    let mut other_version = wire;
    other_version[0] = 2;
    assert_eq!(check(&v, &case, &other_version), Err(ReceiptError::BadVersion));
}

#[test]
fn nothing_inside_a_receipt_is_believed_until_the_signature_verifies() {
    // Every other field is wrong too (subject, root, life, time, key window), but the signature is
    // what fails first: a forger learns nothing about the contents from the refusal.
    let case = case("all_pass");
    let v = verifier_at(vec![attester("cns-attester", T0 + 5 * DAY, T0 + 6 * DAY)], T0);
    let mut f = fields_for(&case, "cns-attester", T0 + 10 * DAY, T0 + 9 * DAY);
    f.subject_digest = Digest32::from_bytes([1; 32]);
    f.decision_root = Digest32::from_bytes([2; 32]);
    let sig = signing_key("someone-else").sign(&f.signed_bytes());
    assert_eq!(check(&v, &case, &f.encode(&sig.to_bytes())), Err(ReceiptError::BadSignature));
}

#[test]
fn a_key_that_is_not_pinned_is_refused_even_with_a_valid_signature() {
    let case = case("all_pass");
    let v = verifier_at(default_keys(), T0);
    let stranger = sign("someone-else", &fields_for(&case, "someone-else", T0, T0 + 60_000));
    assert_eq!(check(&v, &case, &stranger), Err(ReceiptError::UnknownKey));
}

#[test]
fn naming_a_pinned_key_but_signing_with_another_is_a_bad_signature() {
    let case = case("all_pass");
    let v = verifier_at(default_keys(), T0);
    let f = fields_for(&case, "cns-attester", T0, T0 + 60_000);
    let sig = signing_key("someone-else").sign(&f.signed_bytes());
    assert_eq!(check(&v, &case, &f.encode(&sig.to_bytes())), Err(ReceiptError::BadSignature));
}

#[test]
fn a_signature_that_skips_the_domain_label_does_not_verify() {
    let case = case("all_pass");
    let v = verifier_at(default_keys(), T0);
    let f = fields_for(&case, "cns-attester", T0, T0 + 60_000);
    let region = f.signed_bytes();
    let without_domain = &region[RECEIPT_DOMAIN.len()..];
    let sig = signing_key("cns-attester").sign(without_domain);
    assert_eq!(check(&v, &case, &f.encode(&sig.to_bytes())), Err(ReceiptError::BadSignature));
    let mut other_domain = b"stack-issuer/some-other-statement/1\n".to_vec();
    other_domain.extend_from_slice(without_domain);
    let sig = signing_key("cns-attester").sign(&other_domain);
    assert_eq!(check(&v, &case, &f.encode(&sig.to_bytes())), Err(ReceiptError::BadSignature));
}

// ---- binding to this decision ---------------------------------------------

#[test]
fn a_genuine_receipt_for_another_subject_or_root_is_refused() {
    let case = case("all_pass");
    let v = verifier_at(default_keys(), T0);
    let mut other_subject = fields_for(&case, "cns-attester", T0, T0 + 60_000);
    other_subject.subject_digest = Digest32::from_bytes([9; 32]);
    assert_eq!(check(&v, &case, &sign("cns-attester", &other_subject)), Err(ReceiptError::SubjectMismatch));
    let mut other_root = fields_for(&case, "cns-attester", T0, T0 + 60_000);
    other_root.decision_root = Digest32::from_bytes([9; 32]);
    assert_eq!(check(&v, &case, &sign("cns-attester", &other_root)), Err(ReceiptError::RootMismatch));
}

#[test]
fn a_receipt_for_one_decision_does_not_cover_a_relabelled_one() {
    // The issuer recomputes the root from the claim it was given. A claim with a changed
    // verdict label has a different root, so the receipt for the original does not match it.
    let case = case("all_pass");
    let log = SharedLog::default();
    let issuer = issuer_with_verifier(verifier_at(default_keys(), T0), &log);
    let receipt = good(&case);
    let mut relabelled = request(&case);
    let DecisionClaim { seats, mut verdicts, .. } = relabelled.decision.clone();
    verdicts[0].subject = format!("{}-relabelled", verdicts[0].subject);
    let root = stack_receipt::decision_root(&seats, &verdicts);
    relabelled.decision = DecisionClaim { seats, verdicts, root };
    assert!(issuer.issue_with_receipt(&relabelled, Some(&receipt)).is_err());
    assert_eq!(log.count(), 0);
}

// ---- time -----------------------------------------------------------------

#[test]
fn a_receipt_is_good_until_its_expiry_and_not_after() {
    let case = case("all_pass");
    let wire = good(&case); // T0 .. T0 + 60_000
    check(&verifier_at(default_keys(), T0 + 59_999), &case, &wire).unwrap();
    assert_eq!(check(&verifier_at(default_keys(), T0 + 60_000), &case, &wire), Err(ReceiptError::Expired));
    assert_eq!(check(&verifier_at(default_keys(), T0 + 3_600_000), &case, &wire), Err(ReceiptError::Expired));
}

#[test]
fn a_receipt_from_the_future_is_refused_beyond_the_skew() {
    let case = case("all_pass");
    let wire = sign("cns-attester", &fields_for(&case, "cns-attester", T0 + SKEW, T0 + SKEW + 60_000));
    check(&verifier_at(default_keys(), T0), &case, &wire).unwrap();
    let later = sign("cns-attester", &fields_for(&case, "cns-attester", T0 + SKEW + 1, T0 + SKEW + 60_000));
    assert_eq!(check(&verifier_at(default_keys(), T0), &case, &later), Err(ReceiptError::NotYetValid));
}

#[test]
fn a_receipt_may_not_claim_a_longer_life_than_the_verifier_allows() {
    let case = case("all_pass");
    let v = verifier_at(default_keys(), T0);
    let at_limit = sign("cns-attester", &fields_for(&case, "cns-attester", T0, T0 + MAX_VALIDITY));
    check(&v, &case, &at_limit).unwrap();
    let over = sign("cns-attester", &fields_for(&case, "cns-attester", T0, T0 + MAX_VALIDITY + 1));
    assert_eq!(check(&v, &case, &over), Err(ReceiptError::TooLong));
    let inverted = sign("cns-attester", &fields_for(&case, "cns-attester", T0 + 10, T0));
    assert_eq!(check(&v, &case, &inverted), Err(ReceiptError::TooLong));
    let empty = sign("cns-attester", &fields_for(&case, "cns-attester", T0, T0));
    assert_eq!(check(&v, &case, &empty), Err(ReceiptError::TooLong));
}

#[test]
fn a_clock_that_reads_zero_refuses_everything() {
    let case = case("all_pass");
    assert!(check(&verifier_at(default_keys(), 0), &case, &good(&case)).is_err());
}

// ---- keys and rotation ----------------------------------------------------

#[test]
fn a_key_is_trusted_only_inside_its_window() {
    let case = case("all_pass");
    let wire = good(&case);
    let early = vec![attester("cns-attester", T0 + 1, T0 + DAY)];
    assert_eq!(check(&verifier_at(early, T0), &case, &wire), Err(ReceiptError::KeyNotInWindow));
    let retired = vec![attester("cns-attester", T0 - HOUR, T0 - 1)];
    assert_eq!(check(&verifier_at(retired, T0), &case, &wire), Err(ReceiptError::KeyNotInWindow));
    // A receipt stamped before the key's window opened is refused even if the key is current now.
    let late_key = vec![attester("cns-attester", T0 - 10, T0 + DAY)];
    let stale = sign("cns-attester", &fields_for(&case, "cns-attester", T0 - 20, T0 + 60_000));
    assert_eq!(check(&verifier_at(late_key, T0), &case, &stale), Err(ReceiptError::KeyNotInWindow));
}

#[test]
fn a_keys_window_includes_both_of_its_end_times() {
    let case = case("all_pass");
    let wire = good(&case); // issued at T0, expires T0 + 60_000
    let ends_now = vec![attester("cns-attester", T0 - HOUR, T0)];
    check(&verifier_at(ends_now, T0), &case, &wire).unwrap();
    let starts_now = vec![attester("cns-attester", T0, T0 + DAY)];
    check(&verifier_at(starts_now, T0), &case, &wire).unwrap();
    let ended = vec![attester("cns-attester", T0 - HOUR, T0 - 1)];
    assert_eq!(check(&verifier_at(ended, T0), &case, &wire), Err(ReceiptError::KeyNotInWindow));
}

#[test]
fn the_plain_verify_call_never_accepts_because_it_carries_no_receipt() {
    // `verify` is the trait's required method. Anything that reaches the receipt verifier through it
    // has no receipt to check, so it must refuse, whatever the decision looks like.
    let case = case("all_pass");
    let v = verifier_at(default_keys(), T0);
    let subject = digest(&case, "subject_digest");
    let root = digest(&case, "root");
    let refusal = v.verify(&subject, &decision_of(&case), &root).unwrap_err();
    assert!(refusal.0.contains("receipt is required"), "{}", refusal.0);
    assert!(v.verify_with_receipt(&subject, &decision_of(&case), &root, None).is_err());
}

#[test]
fn rotation_with_overlapping_windows_never_leaves_a_gap_and_a_retired_key_stops() {
    let case = case("all_pass");
    let old = attester("cns-attester-old", T0 - DAY, T0 + 2 * HOUR);
    let new = attester("cns-attester-new", T0 - HOUR, T0 + DAY);
    let from_old = sign("cns-attester-old", &fields_for(&case, "cns-attester-old", T0, T0 + 60_000));
    let from_new = sign("cns-attester-new", &fields_for(&case, "cns-attester-new", T0, T0 + 60_000));
    // During the overlap, both are accepted.
    let v = verifier_at(vec![old, new], T0);
    check(&v, &case, &from_old).unwrap();
    check(&v, &case, &from_new).unwrap();
    // After the old key's window closes, only the new one is.
    let later = T0 + 2 * HOUR + 1;
    let old = attester("cns-attester-old", T0 - DAY, T0 + 2 * HOUR);
    let new = attester("cns-attester-new", T0 - HOUR, T0 + DAY);
    let v = verifier_at(vec![old, new], later);
    let old_late = sign("cns-attester-old", &fields_for(&case, "cns-attester-old", later, later + 60_000));
    let new_late = sign("cns-attester-new", &fields_for(&case, "cns-attester-new", later, later + 60_000));
    assert_eq!(check(&v, &case, &old_late), Err(ReceiptError::KeyNotInWindow));
    check(&v, &case, &new_late).unwrap();
}

#[test]
fn the_verifier_refuses_a_configuration_that_could_not_work() {
    let clock = || Box::new(ManualClock::new(T0));
    assert_eq!(CnsReceiptVerifier::new(vec![], MAX_VALIDITY, SKEW, clock()).unwrap_err(), ReceiptConfigError::NoKeys);
    assert_eq!(
        CnsReceiptVerifier::new(vec![attester("a", T0, T0)], MAX_VALIDITY, SKEW, clock()).unwrap_err(),
        ReceiptConfigError::WindowInverted
    );
    assert_eq!(
        CnsReceiptVerifier::new(vec![attester("a", 1, 2), attester("a", 3, 4)], MAX_VALIDITY, SKEW, clock()).unwrap_err(),
        ReceiptConfigError::DuplicateKey
    );
    assert_eq!(CnsReceiptVerifier::new(default_keys(), 0, SKEW, clock()).unwrap_err(), ReceiptConfigError::Validity);
    assert_eq!(CnsReceiptVerifier::new(default_keys(), DAY + 1, SKEW, clock()).unwrap_err(), ReceiptConfigError::Validity);
    assert_eq!(CnsReceiptVerifier::new(default_keys(), MAX_VALIDITY, 5 * 60 * 1000 + 1, clock()).unwrap_err(), ReceiptConfigError::Skew);
}

// ---- compatibility --------------------------------------------------------

#[test]
fn a_verifier_that_knows_nothing_of_receipts_behaves_as_before() {
    // The trait's default `verify_with_receipt` ignores the receipt and calls `verify`, so a
    // verifier written before receipts existed is called exactly as it was.
    let case = case("all_pass");
    let verifier = FixtureAllowAllVerifier::default();
    let subject = digest(&case, "subject_digest");
    let root = digest(&case, "root");
    verifier.verify_with_receipt(&subject, &decision_of(&case), &root, Some(b"garbage")).unwrap();
    verifier.verify_with_receipt(&subject, &decision_of(&case), &root, None).unwrap();
    assert_eq!(verifier.calls.lock().unwrap().len(), 2);
    let refusing = FixtureAllowAllVerifier { refuse: true, ..FixtureAllowAllVerifier::default() };
    assert!(refusing.verify_with_receipt(&subject, &decision_of(&case), &root, Some(b"garbage")).is_err());
}
