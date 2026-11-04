//! Shared test fixtures. Every key here is a TEST FIXTURE derived from a
//! public label and must never be used outside tests.

#![allow(dead_code)]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use stack_receipt::{
    Action, ActualAction, Assurance, Attempted, Authorized, CapabilityBinding, DecisionEvidence, Digest32, Event,
    ExecutionId, GateOutcome, GatePosition, Handoff, NativeDigest, Outcome, Proposed, Provenance, ReceiptKeyId,
    Record, Rejected, Subject, Terminal, Verdict,
};

/// Start of test time (a fixed Unix ms value).
pub const T0: u64 = 1_800_000_000_000;

/// A digest filled with one byte.
pub fn d(b: u8) -> Digest32 {
    Digest32::from_bytes([b; 32])
}

/// The fixture execution id.
pub fn exec_id() -> ExecutionId {
    ExecutionId::from_bytes([0x11; 16])
}

/// The fixture provenance.
pub fn provenance() -> Provenance {
    Provenance {
        component: "stack-kernel".into(),
        version: "0.1.0-test".into(),
        host_id: "test-host".into(),
    }
}

/// A verdict as CNS would write it.
pub fn verdict(gate: &str, position: GatePosition, outcome: GateOutcome) -> Verdict {
    Verdict {
        gate: gate.into(),
        position,
        outcome,
        subject: gate.into(),
        digest: d(0x33).to_hex(),
    }
}

/// A two-seat, all-PASS decision. Its root is a placeholder here; the
/// decision tests recompute real roots.
pub fn decision() -> DecisionEvidence {
    DecisionEvidence {
        root: d(0x44),
        seats: vec!["Governance_Gateway:door".into(), "DIT:judge".into()],
        verdicts: vec![
            verdict("door", GatePosition::Alpha, GateOutcome::Pass),
            verdict("judge", GatePosition::Omega, GateOutcome::Pass),
        ],
    }
}

/// The fixture action.
pub fn action() -> Action {
    Action {
        operation: "read".into(),
        resource: "/data/a".into(),
    }
}

/// The fixture capability binding.
pub fn capability() -> CapabilityBinding {
    CapabilityBinding {
        cap_digest: d(0x55),
        cap_id: "cap-1".into(),
        issuer_id: "issuer-1".into(),
        issuer_key_id: d(0x66),
        policy_ref: "policy/1".into(),
        audience: "kernel-1".into(),
        subject_digest: d(0x22),
        decision_root: d(0x44),
        one_time: true,
        authorized_at_ms: T0 + 1,
    }
}

/// A bare record with `event`, at `sequence`, chained to `prev`.
pub fn record(sequence: u64, prev: [u8; 32], event: Event) -> Record {
    Record {
        kernel_id: "kernel-1".into(),
        sequence,
        prev_hash: prev,
        execution_id: exec_id(),
        recorded_at_ms: T0 + sequence,
        key_id: ReceiptKeyId::from_bytes([0x77; 32]),
        provenance: provenance(),
        event,
    }
}

/// The fixture Proposed event, with a handoff and a native digest.
pub fn proposed() -> Event {
    Event::Proposed(Proposed {
        subject: Subject {
            identity: "invoice-42".into(),
            digest: d(0x22),
        },
        decision: decision(),
        action: action(),
        handoff: Some(Handoff {
            sender_fingerprint: [0x88; 32],
            audience: "kernel-1".into(),
            sequence: 9,
            nonce: [0x99; 16],
            assurance: Assurance::Production,
        }),
        native_digest: Some(NativeDigest {
            label: "sentinel-row-hash".into(),
            digest: d(0xaa),
        }),
    })
}

/// The fixture Authorized event.
pub fn authorized() -> Event {
    Event::Authorized(Authorized {
        capability: capability(),
        action: action(),
    })
}

/// The fixture Rejected event.
pub fn rejected() -> Event {
    Event::Rejected(Rejected {
        reason: "capability expired".into(),
    })
}

/// The fixture Attempted event.
pub fn attempted() -> Event {
    Event::Attempted(Attempted {
        action: ActualAction {
            operation: "read".into(),
            resource: "/data/a".into(),
            argument_digest: d(0xbb),
        },
        started_at_ms: T0 + 3,
    })
}

/// A terminal event with `outcome`.
pub fn terminal(outcome: Outcome) -> Event {
    Event::Terminal(Terminal {
        outcome,
        completed_at_ms: T0 + 4,
        elapsed_ns: 1_000_000,
    })
}

/// The fixture Completed outcome.
pub fn completed() -> Outcome {
    Outcome::Completed {
        exit_code: 0,
        result_digest: d(0xcc),
    }
}

/// Every outcome variant once.
pub fn every_outcome() -> Vec<Outcome> {
    vec![
        completed(),
        Outcome::TimedOut,
        Outcome::Crashed { signal: 11 },
        Outcome::SeccompViolation { signal: 31 },
        Outcome::ResourceLimit { signal: 24 },
        Outcome::ResultMissing { exit_code: 0 },
        Outcome::ExitedNonZero { exit_code: 3 },
        Outcome::ResultOversized,
        Outcome::Interrupted {
            reason: "shutdown".into(),
        },
        Outcome::Unknown {
            reason: "supervisor error".into(),
        },
    ]
}

/// The four fixture events of one honest Completed execution, in order,
/// without chain hashes (sequence 1 to 4, prev_hash zero).
pub fn honest_events() -> Vec<Event> {
    vec![proposed(), authorized(), attempted(), terminal(completed())]
}
