//! Receipt format version 2 (D1-C): a terminal event that carries the two
//! facts the supervisor observed, `exit_observed` and `frame_status`, under
//! the record tag `stack-receipt/2`. Version 1 is covered by `compat_v1.rs`.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use common::*;
use stack_receipt::{
    canonical_bytes, decode_record, genesis_hash, verify_log_bytes, verify_receipt_chain, Check, DecodeError, Event,
    Expectations, ExitObserved, FindingCode, FrameStatus, Limitation, Observed, Outcome, OutcomeKind, State,
    Terminal, TerminalObserved, DOMAIN_TAG, DOMAIN_TAG_V2,
};

fn observed_terminal(outcome: Outcome, exit: ExitObserved, frame: FrameStatus) -> Event {
    Event::TerminalObserved(TerminalObserved {
        terminal: Terminal {
            outcome,
            completed_at_ms: T0 + 4,
            elapsed_ns: 1_000_000,
        },
        observed: Observed { exit, frame },
    })
}

fn clean() -> Event {
    observed_terminal(completed(), ExitObserved::Exited { code: 0 }, FrameStatus::Valid)
}

fn chain_with(terminal: Event) -> Vec<stack_receipt::SignedRecord> {
    sign_chain(vec![proposed(), authorized(), attempted(), terminal])
}

fn verify(terminal: Event) -> stack_receipt::Verification {
    verify_receipt_chain(&chain_with(terminal), exec_id(), &baseline_trust(), &Expectations::default())
}

#[test]
fn a_version_2_terminal_round_trips_under_its_own_tag_and_nothing_else_uses_it() {
    for event in honest_events() {
        let bytes = canonical_bytes(&record(1, genesis_hash(), event)).unwrap();
        assert!(bytes.starts_with(DOMAIN_TAG), "version 1 events keep the version 1 tag");
    }
    let exits = [
        ExitObserved::NotObserved,
        ExitObserved::Exited { code: 0 },
        ExitObserved::Exited { code: 3 },
        ExitObserved::Signaled { signal: 11 },
        ExitObserved::KilledBySupervisor { signal: 9 },
        ExitObserved::Unreaped,
    ];
    let frames = [
        FrameStatus::NotRead,
        FrameStatus::Valid,
        FrameStatus::Missing,
        FrameStatus::Malformed,
        FrameStatus::Oversized,
        FrameStatus::Trailing,
        FrameStatus::Conflicting,
    ];
    for outcome in every_outcome() {
        for (i, exit) in exits.into_iter().enumerate() {
            let frame = frames[i % frames.len()];
            let r = record(4, genesis_hash(), observed_terminal(outcome.clone(), exit, frame));
            let bytes = canonical_bytes(&r).unwrap();
            assert!(bytes.starts_with(DOMAIN_TAG_V2));
            assert_eq!(decode_record(&bytes).unwrap(), r);
        }
    }
    for frame in frames {
        let r = record(4, genesis_hash(), observed_terminal(completed(), ExitObserved::Exited { code: 0 }, frame));
        assert_eq!(decode_record(&canonical_bytes(&r).unwrap()).unwrap(), r);
    }
}

#[test]
fn a_record_has_one_encoding_so_the_version_and_the_event_must_agree() {
    let v2 = canonical_bytes(&record(4, genesis_hash(), clean())).unwrap();
    // A version 2 body under the version 1 tag is refused.
    let mut as_v1 = v2.clone();
    as_v1[..DOMAIN_TAG.len()].copy_from_slice(DOMAIN_TAG);
    assert_eq!(decode_record(&as_v1), Err(DecodeError::BadTagByte("event", 6)));
    // A version 1 body under the version 2 tag is refused.
    let v1 = canonical_bytes(&record(1, genesis_hash(), proposed())).unwrap();
    let mut as_v2 = v1.clone();
    as_v2[..DOMAIN_TAG_V2.len()].copy_from_slice(DOMAIN_TAG_V2);
    assert_eq!(decode_record(&as_v2), Err(DecodeError::BadTagByte("event", 1)));
    // A later version is not guessed at.
    let mut v3 = v2.clone();
    v3[14] = b'3';
    assert_eq!(decode_record(&v3), Err(DecodeError::BadTag));
    // Unknown exit and frame codes are refused, not collapsed.
    let n = v2.len();
    let mut bad_frame = v2.clone();
    bad_frame[n - 1] = 99;
    assert_eq!(decode_record(&bad_frame), Err(DecodeError::BadTagByte("terminal.frame_status", 99)));
    // Layout: ..., exit tag u8, exit code i32, frame u8 for Exited.
    let mut bad_exit = v2.clone();
    bad_exit[n - 6] = 99;
    assert_eq!(decode_record(&bad_exit), Err(DecodeError::BadTagByte("terminal.exit_observed", 99)));
    // Cut short and extended.
    assert!(matches!(decode_record(&v2[..n - 1]), Err(DecodeError::Truncated(_))));
    let mut longer = v2.clone();
    longer.push(0);
    assert!(matches!(decode_record(&longer), Err(DecodeError::TrailingBytes(_))));
}

#[test]
fn every_single_byte_flip_of_a_version_2_record_is_visible() {
    let r = record(4, genesis_hash(), clean());
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

#[test]
fn a_clean_version_2_completion_verifies_and_the_facts_are_checked_not_limited() {
    let v = verify(clean());
    assert_eq!(v.state, State::VerifiedWithLimitations, "{}", v.to_json());
    assert!(v.findings.is_empty(), "{:?}", v.findings);
    assert_eq!(v.execution.outcome, Some(OutcomeKind::Completed));
    assert!(v.scope.checked.contains(&Check::ObservedFactsConsistentWithOutcome));
    assert!(!v.scope.not_checked.contains(&Limitation::SupervisorObservedFactsNotRecorded));
    // The result is still the worker's own claim, version 2 or not.
    assert!(v.scope.not_checked.contains(&Limitation::ResultIsSelfReported));
}

#[test]
fn a_version_1_log_may_gain_version_2_terminals_in_the_same_log() {
    // Two executions on one chain: the first closed by a version 1 terminal, the second by version 2.
    let mut events = honest_events();
    events.extend([proposed(), authorized(), attempted(), clean()]);
    let chain = sign_chain(events);
    let dir = std::env::temp_dir().join(format!("stack-receipt-v2-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("mixed.log");
    let _ = std::fs::remove_file(&path);
    let mut log = stack_receipt::FileReceiptLog::open(&path, "kernel-1", &[fixture_public_key("kernel-1")]).unwrap();
    for s in &chain {
        stack_receipt::ReceiptLog::append(&mut log, s).unwrap();
    }
    drop(log);
    let bytes = std::fs::read(&path).unwrap();
    let v = verify_log_bytes(&bytes, &baseline_trust(), &Expectations::default());
    // The same execution id is reused by the fixture helper, so judge the chain as a log: no
    // hash, signature or sequence finding, and the terminal kinds are what was written.
    assert!(
        !v.findings.iter().any(|f| matches!(
            f.code,
            FindingCode::BadSignature | FindingCode::PrevHashMismatch | FindingCode::SequenceGap | FindingCode::LogCorrupt
        )),
        "{:?}",
        v.findings
    );
    let kinds: Vec<_> = chain.iter().map(|s| (s.record().sequence, s.canonical().starts_with(DOMAIN_TAG_V2))).collect();
    assert_eq!(kinds, [(1, false), (2, false), (3, false), (4, false), (5, false), (6, false), (7, false), (8, true)]);
}

#[test]
fn a_torn_version_2_terminal_is_discarded_like_a_torn_version_1_terminal() {
    let chain = chain_with(clean());
    let dir = std::env::temp_dir().join(format!("stack-receipt-v2-torn-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("torn.log");
    let _ = std::fs::remove_file(&path);
    let mut log = stack_receipt::FileReceiptLog::open(&path, "kernel-1", &[fixture_public_key("kernel-1")]).unwrap();
    for s in &chain[..3] {
        stack_receipt::ReceiptLog::append(&mut log, s).unwrap();
    }
    drop(log);
    let mut bytes = std::fs::read(&path).unwrap();
    let frame = chain[3].to_frame();
    bytes.extend_from_slice(&frame[..frame.len() / 2]);
    let v = verify_log_bytes(&bytes, &baseline_trust(), &Expectations::default());
    assert_eq!(v.state, State::Incomplete, "a torn terminal is not a terminal");
    assert!(v.findings.iter().any(|f| f.code == FindingCode::TornTailDiscarded));
    let mut whole = std::fs::read(&path).unwrap();
    whole.extend_from_slice(&frame);
    let v = verify_log_bytes(&whole, &baseline_trust(), &Expectations::default());
    assert_eq!(v.state, State::VerifiedWithLimitations, "{}", v.to_json());
}

#[test]
fn a_completed_outcome_without_a_clean_exit_and_one_valid_frame_is_rejected() {
    let cases = [
        (ExitObserved::Exited { code: 3 }, FrameStatus::Valid, "non-zero exit"),
        (ExitObserved::Exited { code: 0 }, FrameStatus::Missing, "no frame"),
        (ExitObserved::Exited { code: 0 }, FrameStatus::Malformed, "malformed frame"),
        (ExitObserved::Exited { code: 0 }, FrameStatus::Oversized, "oversized frame"),
        (ExitObserved::Exited { code: 0 }, FrameStatus::Trailing, "trailing bytes"),
        (ExitObserved::Exited { code: 0 }, FrameStatus::Conflicting, "two frames"),
        (ExitObserved::Exited { code: 0 }, FrameStatus::NotRead, "pipe not read"),
        (ExitObserved::Signaled { signal: 11 }, FrameStatus::Valid, "signal death"),
        (ExitObserved::KilledBySupervisor { signal: 9 }, FrameStatus::Valid, "killed at the deadline"),
        (ExitObserved::Unreaped, FrameStatus::Valid, "unreaped"),
        (ExitObserved::NotObserved, FrameStatus::Valid, "nothing observed"),
    ];
    for (exit, frame, why) in cases {
        let v = verify(observed_terminal(completed(), exit, frame));
        assert_eq!(v.state, State::Rejected, "{why}: {}", v.to_json());
        assert!(
            v.findings.iter().any(|f| f.code == FindingCode::ObservedFactsContradictOutcome),
            "{why}: {:?}",
            v.findings
        );
    }
}

#[test]
fn the_other_facts_the_outcome_contradicts_are_rejected_too() {
    // ResultMissing is an exit 0 whose frame was not valid.
    let ok = verify(observed_terminal(
        Outcome::ResultMissing { exit_code: 0 },
        ExitObserved::Exited { code: 0 },
        FrameStatus::Malformed,
    ));
    assert_eq!(ok.state, State::VerifiedWithLimitations, "{}", ok.to_json());
    for (exit, frame) in [
        (ExitObserved::Exited { code: 0 }, FrameStatus::Valid),
        (ExitObserved::Exited { code: 3 }, FrameStatus::Missing),
    ] {
        let v = verify(observed_terminal(Outcome::ResultMissing { exit_code: 0 }, exit, frame));
        assert_eq!(v.state, State::Rejected, "{exit:?} {frame:?}");
    }
    // TerminationUnconfirmed is the one outcome with an unreaped worker, and the only one.
    let unconfirmed = Outcome::TerminationUnconfirmed { reason: "not reaped".into() };
    let ok = verify(observed_terminal(unconfirmed.clone(), ExitObserved::Unreaped, FrameStatus::NotRead));
    assert_ne!(ok.state, State::Rejected, "{}", ok.to_json());
    assert_eq!(
        verify(observed_terminal(unconfirmed, ExitObserved::KilledBySupervisor { signal: 9 }, FrameStatus::NotRead)).state,
        State::Rejected
    );
    assert_eq!(
        verify(observed_terminal(Outcome::TimedOut, ExitObserved::Unreaped, FrameStatus::NotRead)).state,
        State::Rejected
    );
    // A valid frame beside a timeout is allowed: the frame is a fact about the pipe, not about success.
    let v = verify(observed_terminal(
        Outcome::TimedOut,
        ExitObserved::KilledBySupervisor { signal: 9 },
        FrameStatus::Valid,
    ));
    assert_ne!(v.state, State::Rejected, "{}", v.to_json());
}

#[test]
fn campaign_vocabulary_maps_each_existing_outcome_once() {
    let want = [
        (OutcomeKind::Completed, "COMPLETED"),
        (OutcomeKind::TimedOut, "TIMED_OUT"),
        (OutcomeKind::Terminated, "TERMINATED"),
        (OutcomeKind::TerminationUnconfirmed, "TERMINATION_UNCONFIRMED"),
        (OutcomeKind::Crashed, "CRASHED"),
        (OutcomeKind::SeccompViolation, "CRASHED"),
        (OutcomeKind::ResourceLimit, "CRASHED"),
        (OutcomeKind::ExitedNonZero, "CRASHED"),
        (OutcomeKind::ResultMissing, "RESULT_INVALID"),
        (OutcomeKind::ResultOversized, "RESULT_INVALID"),
        (OutcomeKind::Interrupted, "INTERRUPTED"),
        (OutcomeKind::Unknown, "UNKNOWN"),
    ];
    for o in every_outcome() {
        let name = want.iter().find(|(k, _)| *k == o.kind()).unwrap().1;
        assert_eq!(o.kind().campaign_name(), name);
        // Only Completed is COMPLETED, and no existing spelling changed.
        assert_eq!(name == "COMPLETED", o.kind() == OutcomeKind::Completed);
    }
    assert_eq!(want.len(), 12);
    assert_eq!(OutcomeKind::ResultMissing.as_str(), "result_missing");
    assert_eq!(OutcomeKind::ExitedNonZero.as_str(), "exited_non_zero");
}
