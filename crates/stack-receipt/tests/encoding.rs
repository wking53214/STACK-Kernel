//! The canonical encoding: deterministic, reversible, and sensitive to
//! every field.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use common::*;
use stack_receipt::encode::{prefix_consistent, FIXED_PREFIX_BYTES};
use stack_receipt::{
    canonical_bytes, decode_record, genesis_hash, record_hash, Assurance, DecodeError, Event, ExecutionId,
    GateOutcome, GatePosition, Outcome, Problem, ReceiptKeyId, Record, ValidationError, DOMAIN_TAG, MAX_ID_BYTES,
    MAX_RECORD_BYTES, MAX_SEATS, MAX_TEXT_BYTES,
};

fn hash_of(r: &Record) -> [u8; 32] {
    record_hash(&canonical_bytes(r).unwrap())
}

#[test]
fn encoding_is_deterministic_and_starts_with_the_tag() {
    for event in honest_events() {
        let r = record(1, genesis_hash(), event);
        let a = canonical_bytes(&r).unwrap();
        let b = canonical_bytes(&r.clone()).unwrap();
        assert_eq!(a, b);
        assert_eq!(&a[..16], DOMAIN_TAG);
        assert_eq!(record_hash(&a), record_hash(&b));
        assert!(a.len() < MAX_RECORD_BYTES);
    }
}

#[test]
fn every_event_and_outcome_round_trips_exactly() {
    let mut events = honest_events();
    events.push(rejected());
    for o in every_outcome() {
        events.push(terminal(o));
    }
    // Proposed without the optional fields, too.
    if let Event::Proposed(mut p) = proposed() {
        p.handoff = None;
        p.native_digest = None;
        events.push(Event::Proposed(p));
    }
    for (i, event) in events.into_iter().enumerate() {
        let r = record(u64::try_from(i).unwrap() + 1, [u8::try_from(i).unwrap(); 32], event);
        let bytes = canonical_bytes(&r).unwrap();
        let back = decode_record(&bytes).unwrap();
        assert_eq!(back, r);
        assert_eq!(canonical_bytes(&back).unwrap(), bytes);
    }
}

#[test]
fn genesis_and_record_hashes_are_domain_separated_full_sha256() {
    use sha2::{Digest, Sha256};
    let g = genesis_hash();
    assert_eq!(g, <[u8; 32]>::from(Sha256::digest(b"stack-receipt/genesis/1\n")));
    let bytes = canonical_bytes(&record(1, g, proposed())).unwrap();
    let mut h = Sha256::new();
    h.update(b"stack-receipt/record-hash/1\n");
    h.update(&bytes);
    assert_eq!(record_hash(&bytes), <[u8; 32]>::from(h.finalize()));
    assert_ne!(record_hash(&bytes), <[u8; 32]>::from(Sha256::digest(&bytes)), "no bare sha256");
}

/// One mutation per field of the four honest records. Every mutation must
/// change the record hash, and every pair of mutations must differ.
fn mutations() -> Vec<(&'static str, Record)> {
    let base = record(1, genesis_hash(), proposed());
    let mut out: Vec<(&'static str, Record)> = Vec::new();
    let mut push = |name: &'static str, f: &dyn Fn(&mut Record)| {
        let mut r = base.clone();
        f(&mut r);
        out.push((name, r));
    };
    push("kernel_id", &|r| r.kernel_id = "kernel-2".into());
    push("sequence", &|r| r.sequence = 2);
    push("prev_hash", &|r| r.prev_hash = [1; 32]);
    push("execution_id", &|r| r.execution_id = ExecutionId::from_bytes([0x12; 16]));
    push("recorded_at_ms", &|r| r.recorded_at_ms += 1);
    push("key_id", &|r| r.key_id = ReceiptKeyId::from_bytes([0x78; 32]));
    push("provenance.component", &|r| r.provenance.component = "other".into());
    push("provenance.version", &|r| r.provenance.version = "0.2.0".into());
    push("provenance.host_id", &|r| r.provenance.host_id = "host-2".into());
    push("event.stage", &|r| r.event = authorized());
    let prop = |r: &mut Record, f: &dyn Fn(&mut stack_receipt::Proposed)| {
        if let Event::Proposed(p) = &mut r.event {
            f(p);
        } else {
            panic!("not proposed");
        }
    };
    push("subject.identity", &|r| prop(r, &|p| p.subject.identity = "invoice-43".into()));
    push("subject.digest", &|r| prop(r, &|p| p.subject.digest = d(0x23)));
    push("decision.root", &|r| prop(r, &|p| p.decision.root = d(0x44)));
    push("decision.seats.order", &|r| prop(r, &|p| p.decision.seats.reverse()));
    push("decision.seats.name", &|r| prop(r, &|p| p.decision.seats[0] = "DGK:door".into()));
    push("decision.seats.removed", &|r| prop(r, &|p| {
        p.decision.seats.pop();
    }));
    push("decision.seats.added", &|r| prop(r, &|p| p.decision.seats.push("CNS:same_subject".into())));
    push("decision.verdicts.order", &|r| prop(r, &|p| p.decision.verdicts.reverse()));
    push("decision.verdicts.removed", &|r| prop(r, &|p| {
        p.decision.verdicts.pop();
    }));
    push("decision.verdicts.added", &|r| prop(r, &|p| {
        let v = p.decision.verdicts[0].clone();
        p.decision.verdicts.push(v);
    }));
    push("verdict.gate", &|r| prop(r, &|p| p.decision.verdicts[0].gate = "gate".into()));
    push("verdict.position", &|r| prop(r, &|p| p.decision.verdicts[0].position = GatePosition::Omega));
    push("verdict.outcome.retry", &|r| prop(r, &|p| p.decision.verdicts[0].outcome = GateOutcome::Retry));
    push("verdict.outcome.breach", &|r| prop(r, &|p| p.decision.verdicts[0].outcome = GateOutcome::TerminalBreach));
    push("verdict.subject", &|r| prop(r, &|p| p.decision.verdicts[0].subject = "x".into()));
    push("verdict.subject.empty", &|r| prop(r, &|p| p.decision.verdicts[0].subject = String::new()));
    push("verdict.digest", &|r| prop(r, &|p| p.decision.verdicts[0].digest = d(0x34).to_hex()));
    push("verdict.digest.empty", &|r| prop(r, &|p| p.decision.verdicts[0].digest = String::new()));
    push("proposed.action.operation", &|r| prop(r, &|p| p.action.operation = "write".into()));
    push("proposed.action.resource", &|r| prop(r, &|p| p.action.resource = "/data/b".into()));
    push("handoff.absent", &|r| prop(r, &|p| p.handoff = None));
    push("handoff.sender", &|r| prop(r, &|p| p.handoff.as_mut().unwrap().sender_fingerprint = [0x89; 32]));
    push("handoff.audience", &|r| prop(r, &|p| p.handoff.as_mut().unwrap().audience = "kernel-2".into()));
    push("handoff.sequence", &|r| prop(r, &|p| p.handoff.as_mut().unwrap().sequence = 10));
    push("handoff.nonce", &|r| prop(r, &|p| p.handoff.as_mut().unwrap().nonce = [0x9a; 16]));
    push("handoff.assurance", &|r| prop(r, &|p| p.handoff.as_mut().unwrap().assurance = Assurance::Development));
    push("native.absent", &|r| prop(r, &|p| p.native_digest = None));
    push("native.label", &|r| prop(r, &|p| p.native_digest.as_mut().unwrap().label = "other".into()));
    push("native.digest", &|r| prop(r, &|p| p.native_digest.as_mut().unwrap().digest = d(0xab)));
    out
}

fn authorized_mutations() -> Vec<(&'static str, Record)> {
    let base = record(2, [1; 32], authorized());
    let mut out: Vec<(&'static str, Record)> = Vec::new();
    let mut push = |name: &'static str, f: &dyn Fn(&mut stack_receipt::Authorized)| {
        let mut r = base.clone();
        if let Event::Authorized(a) = &mut r.event {
            f(a);
        }
        out.push((name, r));
    };
    push("cap_digest", &|a| a.capability.cap_digest = d(0x56));
    push("cap_id", &|a| a.capability.cap_id = "cap-2".into());
    push("issuer_id", &|a| a.capability.issuer_id = "issuer-2".into());
    push("issuer_key_id", &|a| a.capability.issuer_key_id = d(0x67));
    push("policy_ref", &|a| a.capability.policy_ref = "policy/2".into());
    push("policy_ref.empty", &|a| a.capability.policy_ref = String::new());
    push("audience", &|a| a.capability.audience = "kernel-2".into());
    push("subject_digest", &|a| a.capability.subject_digest = d(0x23));
    push("decision_root", &|a| a.capability.decision_root = d(0x44));
    push("one_time", &|a| a.capability.one_time = false);
    push("authorized_at_ms", &|a| a.capability.authorized_at_ms += 1);
    push("action.operation", &|a| a.action.operation = "write".into());
    push("action.resource", &|a| a.action.resource = "/data/b".into());
    out
}

fn attempted_and_terminal_mutations() -> Vec<(&'static str, Record)> {
    let mut out: Vec<(&'static str, Record)> = Vec::new();
    let base = record(3, [2; 32], attempted());
    let mut push = |name: &'static str, f: &dyn Fn(&mut stack_receipt::Attempted)| {
        let mut r = base.clone();
        if let Event::Attempted(a) = &mut r.event {
            f(a);
        }
        out.push((name, r));
    };
    push("actual.operation", &|a| a.action.operation = "write".into());
    push("actual.resource", &|a| a.action.resource = "/data/b".into());
    push("actual.argument_digest", &|a| a.action.argument_digest = d(0xbc));
    push("started_at_ms", &|a| a.started_at_ms += 1);
    let base = record(4, [3; 32], terminal(completed()));
    let mut push = |name: &'static str, f: &dyn Fn(&mut stack_receipt::Terminal)| {
        let mut r = base.clone();
        if let Event::Terminal(t) = &mut r.event {
            f(t);
        }
        out.push((name, r));
    };
    push("completed.exit_code", &|t| {
        t.outcome = Outcome::Completed {
            exit_code: 1,
            result_digest: result_digest(),
        }
    });
    push("completed.result_digest", &|t| {
        t.outcome = Outcome::Completed {
            exit_code: 0,
            result_digest: d(0xcd),
        }
    });
    push("completed_at_ms", &|t| t.completed_at_ms += 1);
    push("elapsed_ns", &|t| t.elapsed_ns += 1);
    let outcome_names = [
        "outcome.timed_out",
        "outcome.crashed",
        "outcome.seccomp",
        "outcome.resource",
        "outcome.result_missing",
        "outcome.exited_non_zero",
        "outcome.result_oversized",
        "outcome.interrupted",
        "outcome.unknown",
        "outcome.terminated",
        "outcome.termination_unconfirmed",
    ];
    for (name, o) in outcome_names.into_iter().zip(every_outcome().into_iter().skip(1)) {
        push(name, &|t| t.outcome = o.clone());
    }
    let mut r = base.clone();
    r.event = rejected();
    out.push(("rejected", r));
    out
}

#[test]
fn changing_any_field_changes_the_hash_and_no_two_changes_collide() {
    let mut all = mutations();
    all.extend(authorized_mutations());
    all.extend(attempted_and_terminal_mutations());
    assert_eq!(all.len(), 72, "one mutation per field; update this count when a field is added");
    let bases = [
        hash_of(&record(1, genesis_hash(), proposed())),
        hash_of(&record(2, [1; 32], authorized())),
        hash_of(&record(3, [2; 32], attempted())),
        hash_of(&record(4, [3; 32], terminal(completed()))),
    ];
    let mut seen = std::collections::HashSet::new();
    for (name, r) in &all {
        let h = hash_of(r);
        assert!(!bases.contains(&h), "{name}: hash unchanged");
        assert!(seen.insert(h), "{name}: collides with an earlier mutation");
    }
}

#[test]
fn signal_and_exit_code_sign_bits_are_encoded() {
    let a = record(4, [3; 32], terminal(Outcome::Crashed { signal: 1 }));
    let b = record(4, [3; 32], terminal(Outcome::Crashed { signal: -1 }));
    assert_ne!(hash_of(&a), hash_of(&b));
    assert_eq!(decode_record(&canonical_bytes(&b).unwrap()).unwrap(), b);
}

#[test]
fn truncation_at_every_length_and_a_trailing_byte_are_refused() {
    for event in honest_events() {
        let bytes = canonical_bytes(&record(1, genesis_hash(), event)).unwrap();
        for n in 0..bytes.len() {
            let e = decode_record(&bytes[..n]).unwrap_err();
            assert!(
                matches!(e, DecodeError::Truncated(_) | DecodeError::BadTag),
                "len {n}: {e:?}"
            );
        }
        let mut longer = bytes.clone();
        longer.push(0);
        assert!(matches!(decode_record(&longer), Err(DecodeError::TrailingBytes(_))));
    }
}

#[test]
fn a_wrong_tag_an_unknown_variant_and_an_over_cap_record_are_refused() {
    let bytes = canonical_bytes(&record(1, genesis_hash(), proposed())).unwrap();
    let mut wrong = bytes.clone();
    wrong[0] ^= 1;
    assert_eq!(decode_record(&wrong), Err(DecodeError::BadTag));
    let mut v2 = bytes.clone();
    v2[14] = b'2';
    assert_eq!(decode_record(&v2), Err(DecodeError::BadTag));
    // The event tag sits right after the fixed header, kernel_id,
    // execution id, recorded_at, key id and provenance.
    let event_tag = FIXED_PREFIX_BYTES + 2 + 8 + 16 + 8 + 32 + (2 + 12) + (2 + 10) + (2 + 9);
    assert_eq!(bytes[event_tag], 1);
    let mut bad = bytes.clone();
    bad[event_tag] = 9;
    assert_eq!(decode_record(&bad), Err(DecodeError::BadTagByte("event", 9)));
    assert_eq!(decode_record(&vec![0; MAX_RECORD_BYTES + 1]), Err(DecodeError::TooLarge));
}

#[test]
fn every_single_byte_flip_either_fails_to_decode_or_decodes_to_a_different_record() {
    for event in honest_events() {
        let r = record(1, genesis_hash(), event);
        let bytes = canonical_bytes(&r).unwrap();
        for i in 0..bytes.len() {
            for bit in 0..8 {
                let mut m = bytes.clone();
                m[i] ^= 1 << bit;
                if let Ok(other) = decode_record(&m) {
                    assert_ne!(other, r, "byte {i} bit {bit}: flip not visible");
                    assert_eq!(canonical_bytes(&other).unwrap(), m, "byte {i} bit {bit}: not canonical");
                }
            }
        }
    }
}

#[test]
fn validation_bounds_are_enforced_on_encode_and_decode() {
    let mut r = record(1, genesis_hash(), proposed());
    r.kernel_id = "a\u{1}b".into();
    assert_eq!(
        canonical_bytes(&r),
        Err(ValidationError {
            field: "kernel_id",
            problem: Problem::ControlCharacter
        })
    );
    r.kernel_id = "x".repeat(MAX_ID_BYTES + 1);
    assert_eq!(
        canonical_bytes(&r),
        Err(ValidationError {
            field: "kernel_id",
            problem: Problem::TooLong { max: MAX_ID_BYTES }
        })
    );
    r.kernel_id = String::new();
    assert_eq!(
        canonical_bytes(&r),
        Err(ValidationError {
            field: "kernel_id",
            problem: Problem::Empty
        })
    );
    r.kernel_id = "x".repeat(MAX_ID_BYTES);
    assert!(canonical_bytes(&r).is_ok());
    if let Event::Proposed(p) = &mut r.event {
        p.decision.seats = vec!["s".into(); MAX_SEATS + 1];
    }
    assert_eq!(
        canonical_bytes(&r),
        Err(ValidationError {
            field: "decision.seats",
            problem: Problem::TooMany { max: MAX_SEATS }
        })
    );
    if let Event::Proposed(p) = &mut r.event {
        p.decision.seats = vec!["s".into(); MAX_SEATS];
        p.subject.identity = "y".repeat(MAX_TEXT_BYTES + 1);
    }
    assert!(matches!(
        canonical_bytes(&r),
        Err(ValidationError {
            field: "subject.identity",
            problem: Problem::TooLong { .. }
        })
    ));
    // A decoder refuses a control character even though the length is fine.
    let ok = canonical_bytes(&record(1, genesis_hash(), rejected())).unwrap();
    let mut bad = ok.clone();
    let last = bad.len() - 1;
    bad[last] = 0x7f;
    assert_eq!(
        decode_record(&bad),
        Err(DecodeError::Invalid(ValidationError {
            field: "rejected.reason",
            problem: Problem::ControlCharacter
        }))
    );
    // A decoder refuses invalid UTF-8 inside a string.
    bad[last] = 0xff;
    assert_eq!(decode_record(&bad), Err(DecodeError::BadUtf8("rejected.reason")));
}

#[test]
fn a_torn_prefix_is_judged_by_what_the_writer_would_have_put_there() {
    let bytes = canonical_bytes(&record(7, [5; 32], attempted())).unwrap();
    for n in 0..=FIXED_PREFIX_BYTES + 4 {
        assert!(prefix_consistent(&bytes[..n], 7, &[5; 32]), "len {n}");
    }
    assert!(!prefix_consistent(&bytes[..FIXED_PREFIX_BYTES], 8, &[5; 32]));
    assert!(!prefix_consistent(&bytes[..FIXED_PREFIX_BYTES], 7, &[6; 32]));
    assert!(!prefix_consistent(&bytes[..24], 8, &[5; 32]), "sequence visible");
    assert!(prefix_consistent(&bytes[..24], 7, &[6; 32]), "prev not yet visible");
    assert!(prefix_consistent(&bytes[..20], 8, &[5; 32]), "low sequence byte not yet visible");
    assert!(!prefix_consistent(b"garbage", 7, &[5; 32]));
}
