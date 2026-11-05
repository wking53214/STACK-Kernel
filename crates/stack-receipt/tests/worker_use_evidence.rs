//! Step 2 (R-7, G-5, G-4/R-6): the two receipt gaps the field audit found,
//! closed additively under receipt format version 2, and the native digest
//! kept apart from the CNS subject digest.
//!
//! (a) WORKER IDENTITY: `Attempted` binds the worker image SHA-256 and the
//! limits the supervisor was given.
//! (b) USE EVIDENCE: `Authorized` binds what the use store returned.
//! Version 1 logs stay byte-compatible (`compat_v1.rs` pins the bytes) and are
//! read here as limitations, never failures.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use common::*;
use stack_receipt::{
    canonical_bytes, decode_record, genesis_hash, verify_log_bytes, verify_receipt_chain, Check, DecodeError, Event,
    Expectations, FindingCode, Limitation, NativeDigest, Record, SignedRecord, State, UseEvidence, Verification,
    DOMAIN_TAG, DOMAIN_TAG_V2,
};

const V1_LOG: &[u8] = include_bytes!("fixtures/v1_log.bin");

fn v2_events(evidence: UseEvidence) -> Vec<Event> {
    vec![
        proposed(),
        authorized_with_evidence(evidence),
        attempted_with_worker(),
        terminal(completed()),
    ]
}

fn durable() -> UseEvidence {
    UseEvidence::Durable {
        record_hash: d(0x51),
        position: 7,
        head: d(0x51),
    }
}

fn verify_with(chain: &[SignedRecord], exp: &Expectations<'_>) -> Verification {
    verify_receipt_chain(chain, exec_id(), &baseline_trust(), exp)
}

fn has(v: &Verification, code: &FindingCode) -> bool {
    v.findings.iter().any(|f| &f.code == code)
}

fn limitations(v: &Verification) -> Vec<&'static str> {
    v.scope.not_checked.iter().map(|l| l.as_str()).collect()
}

fn insider(edit: impl FnOnce(&mut Vec<Record>)) -> Vec<SignedRecord> {
    let mut records: Vec<Record> = v2_events(durable())
        .into_iter()
        .enumerate()
        .map(|(i, e)| record(u64::try_from(i).unwrap() + 1, [0; 32], e))
        .collect();
    edit(&mut records);
    resign_chain(&fixture_signer("kernel-1"), records)
}

// ---------------------------------------------------------------------------
// Encoding and compatibility
// ---------------------------------------------------------------------------

#[test]
fn the_additions_round_trip_under_the_v2_tag_and_without_them_the_bytes_are_v1() {
    for ev in [
        UseEvidence::NotProvided,
        UseEvidence::NonDurableMemory,
        durable(),
        UseEvidence::NoNewRecord { position: 3, head: d(0x52) },
    ] {
        let r = record(2, genesis_hash(), authorized_with_evidence(ev));
        let bytes = canonical_bytes(&r).unwrap();
        assert!(bytes.starts_with(DOMAIN_TAG_V2), "{ev:?}");
        assert_eq!(decode_record(&bytes).unwrap(), r, "{ev:?}");
    }
    let r = record(3, genesis_hash(), attempted_with_worker());
    let bytes = canonical_bytes(&r).unwrap();
    assert!(bytes.starts_with(DOMAIN_TAG_V2));
    assert_eq!(decode_record(&bytes).unwrap(), r);
    // The same events without the additions are v1 and carry the v1 tag.
    for e in [authorized(), attempted()] {
        let b = canonical_bytes(&record(2, genesis_hash(), e)).unwrap();
        assert!(b.starts_with(DOMAIN_TAG));
    }
}

#[test]
fn a_record_has_one_encoding_so_the_version_and_the_event_must_agree() {
    let v2 = canonical_bytes(&record(2, genesis_hash(), authorized_with_evidence(durable()))).unwrap();
    let mut as_v1 = v2.clone();
    as_v1.splice(..DOMAIN_TAG.len(), DOMAIN_TAG.iter().copied());
    assert!(matches!(decode_record(&as_v1), Err(DecodeError::BadTagByte("event", 7))));
    let v1 = canonical_bytes(&record(2, genesis_hash(), authorized())).unwrap();
    let mut as_v2 = v1.clone();
    as_v2.splice(..DOMAIN_TAG_V2.len(), DOMAIN_TAG_V2.iter().copied());
    assert!(matches!(decode_record(&as_v2), Err(DecodeError::BadTagByte("event", 2))));
    // Truncating the addition is refused, not read as a v1 record.
    let cut = &v2[..v2.len() - 1];
    assert!(decode_record(cut).is_err());
}

#[test]
fn a_v1_log_still_verifies_and_names_both_gaps_as_limitations() {
    let v = verify_log_bytes(V1_LOG, &baseline_trust(), &Expectations::default());
    assert_eq!(v.state, State::VerifiedWithLimitations, "{}", v.to_json());
    assert!(v.findings.is_empty(), "a v1 receipt is not a failure: {:?}", v.findings);
    for l in [Limitation::WorkerIdentityNotRecorded, Limitation::UseEvidenceNotRecorded] {
        assert!(v.scope.not_checked.contains(&l), "{l:?} in {:?}", v.scope.not_checked);
    }
    // And an expectation about the worker cannot fail a log that never claimed one.
    let image = d(0xff);
    let exp = Expectations {
        worker_image_sha256: Some(&image),
        ..Expectations::default()
    };
    let v = verify_log_bytes(V1_LOG, &baseline_trust(), &exp);
    assert!(v.findings.is_empty(), "{}", v.to_json());
    assert!(!v.scope.checked.contains(&Check::WorkerImageMatchesExpected));
}

// ---------------------------------------------------------------------------
// Worker identity
// ---------------------------------------------------------------------------

#[test]
fn the_expected_worker_image_and_limits_verify_and_are_listed_as_checked() {
    let chain = sign_chain(v2_events(durable()));
    let w = worker_binding();
    let exp = Expectations {
        worker_image_sha256: Some(&w.image_sha256),
        worker_limits: Some(&w.limits),
        ..Expectations::default()
    };
    let v = verify_with(&chain, &exp);
    assert!(v.findings.is_empty(), "{}", v.to_json());
    for c in [Check::WorkerImageMatchesExpected, Check::WorkerLimitsMatchExpected, Check::UseEvidenceWellFormed] {
        assert!(v.scope.checked.contains(&c), "{c:?}");
    }
    let lim = limitations(&v);
    assert!(!lim.contains(&"worker_identity_not_recorded"));
    assert!(!lim.contains(&"use_evidence_not_recorded"));
    assert!(!lim.contains(&"worker_expectation_not_supplied"));
}

#[test]
fn a_worker_image_that_differs_from_the_expectation_is_a_finding() {
    let chain = sign_chain(v2_events(durable()));
    let other = d(0xee);
    let v = verify_with(
        &chain,
        &Expectations {
            worker_image_sha256: Some(&other),
            ..Expectations::default()
        },
    );
    assert_eq!(v.state, State::Rejected, "{}", v.to_json());
    assert!(has(&v, &FindingCode::WorkerImageMismatch));
    assert!(!has(&v, &FindingCode::WorkerLimitsMismatch));
}

#[test]
fn limits_that_differ_from_the_expectation_are_a_finding_and_each_field_counts() {
    let chain = sign_chain(v2_events(durable()));
    let base = worker_binding().limits;
    let edits: [&dyn Fn(&mut stack_receipt::AppliedLimits); 6] = [
        &|l| l.wall_clock_deadline_ns += 1,
        &|l| l.cpu_seconds += 1,
        &|l| l.address_space_bytes += 1,
        &|l| l.max_output_bytes += 1,
        &|l| l.file_size_bytes += 1,
        &|l| l.nofile += 1,
    ];
    for (i, edit) in edits.iter().enumerate() {
        let mut want = base;
        edit(&mut want);
        let v = verify_with(
            &chain,
            &Expectations {
                worker_limits: Some(&want),
                ..Expectations::default()
            },
        );
        assert!(has(&v, &FindingCode::WorkerLimitsMismatch), "field {i}");
    }
    assert_eq!(base.wall_clock_deadline_ms(), 2000);
}

#[test]
fn no_expectation_is_a_limitation_and_an_insider_edit_of_the_image_is_caught_by_one() {
    let honest = sign_chain(v2_events(durable()));
    let v = verify_with(&honest, &Expectations::default());
    assert!(limitations(&v).contains(&"worker_expectation_not_supplied"), "{}", v.to_json());
    // An insider who holds the receipt key swaps the image digest and re-signs:
    // the chain verifies, so only the auditor's own expectation can notice.
    let forged = insider(|rs| {
        let Event::Attempted(a) = &mut rs[2].event else { panic!() };
        a.worker.as_mut().unwrap().image_sha256 = d(0xdd);
    });
    let w = worker_binding();
    let exp = Expectations {
        worker_image_sha256: Some(&w.image_sha256),
        ..Expectations::default()
    };
    assert!(verify_with(&forged, &Expectations::default()).findings.is_empty());
    assert!(has(&verify_with(&forged, &exp), &FindingCode::WorkerImageMismatch));
}

// ---------------------------------------------------------------------------
// Use evidence
// ---------------------------------------------------------------------------

#[test]
fn use_evidence_that_is_absent_unprovided_or_non_durable_is_a_limitation_not_a_finding() {
    let cases = [
        (UseEvidence::NotProvided, "use_evidence_not_provided_by_store"),
        (UseEvidence::NonDurableMemory, "use_evidence_non_durable"),
    ];
    for (ev, name) in cases {
        let v = verify_with(&sign_chain(v2_events(ev)), &Expectations::default());
        assert!(v.findings.is_empty(), "{ev:?}: {}", v.to_json());
        assert!(limitations(&v).contains(&name), "{ev:?}: {:?}", limitations(&v));
        assert!(!limitations(&v).contains(&"use_evidence_not_recorded"));
    }
    let v1 = verify_with(&sign_chain(vec![proposed(), authorized(), attempted(), terminal(completed())]), &Expectations::default());
    assert!(limitations(&v1).contains(&"use_evidence_not_recorded"));
}

#[test]
fn a_durable_use_record_at_position_zero_is_a_finding() {
    let bad = UseEvidence::Durable {
        record_hash: d(1),
        position: 0,
        head: d(1),
    };
    let v = verify_with(&sign_chain(v2_events(bad)), &Expectations::default());
    assert_eq!(v.state, State::Rejected, "{}", v.to_json());
    assert!(has(&v, &FindingCode::UseEvidenceMalformed));
}

#[test]
fn flipping_a_bit_in_the_use_evidence_or_the_worker_binding_breaks_the_signature() {
    let chain = sign_chain(v2_events(durable()));
    for idx in [1usize, 2] {
        let mut recs: Vec<SignedRecord> = chain.clone();
        let mut flipped = recs[idx].canonical().to_vec();
        let last = flipped.len() - 1;
        flipped[last] ^= 1;
        let hash = stack_receipt::record_hash(&flipped);
        recs[idx] = SignedRecord::from_parts(flipped, *recs[idx].signature(), hash).unwrap();
        let v = verify_with(&recs, &Expectations::default());
        assert_ne!(v.state, State::VerifiedWithLimitations, "record {idx}");
    }
}

// ---------------------------------------------------------------------------
// Native integrity (G-4, R-6): the native digest and the CNS subject digest
// are separate fields, and tampering either is caught independently.
// ---------------------------------------------------------------------------

#[test]
fn tampering_the_native_digest_is_caught_and_the_subject_digest_still_checks_out() {
    let content = subject_content();
    let want = NativeDigest {
        label: "sentinel-row-hash".into(),
        digest: d(0xaa),
    };
    let exp = Expectations {
        subject_content: Some(&content),
        native_digest: Some(&want),
        ..Expectations::default()
    };
    let honest = insider(|_| {});
    let v = verify_with(&honest, &exp);
    assert!(!has(&v, &FindingCode::NativeDigestMismatch) && !has(&v, &FindingCode::SubjectDigestMismatch), "{}", v.to_json());
    assert!(!limitations(&v).contains(&"native_component_not_verified"), "checked, so no longer a limitation");

    let tampered = insider(|rs| {
        let Event::Proposed(p) = &mut rs[0].event else { panic!() };
        p.native_digest.as_mut().unwrap().digest = d(0xab);
    });
    let v = verify_with(&tampered, &exp);
    assert!(has(&v, &FindingCode::NativeDigestMismatch), "{}", v.to_json());
    assert!(!has(&v, &FindingCode::SubjectDigestMismatch), "the CNS digest is a different field");
}

#[test]
fn tampering_the_cns_subject_digest_is_caught_and_the_native_digest_still_checks_out() {
    let content = subject_content();
    let want = NativeDigest {
        label: "sentinel-row-hash".into(),
        digest: d(0xaa),
    };
    let exp = Expectations {
        subject_content: Some(&content),
        native_digest: Some(&want),
        ..Expectations::default()
    };
    let tampered = insider(|rs| {
        let Event::Proposed(p) = &mut rs[0].event else { panic!() };
        p.subject.digest = d(0x01);
    });
    let v = verify_with(&tampered, &exp);
    assert!(has(&v, &FindingCode::SubjectDigestMismatch), "{}", v.to_json());
    assert!(!has(&v, &FindingCode::NativeDigestMismatch), "the native digest is a different field");
}

#[test]
fn a_native_label_that_differs_is_also_a_mismatch_and_without_an_expectation_it_stays_a_limitation() {
    let want = NativeDigest {
        label: "trident-mac-verified".into(),
        digest: d(0xaa),
    };
    let v = verify_with(
        &insider(|_| {}),
        &Expectations {
            native_digest: Some(&want),
            ..Expectations::default()
        },
    );
    assert!(has(&v, &FindingCode::NativeDigestMismatch));
    let v = verify_with(&insider(|_| {}), &Expectations::default());
    assert!(limitations(&v).contains(&"native_component_not_verified"));
}
