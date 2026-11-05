//! Shared test fixtures. Every key here is a TEST FIXTURE derived from a
//! public label and must never be used outside tests.

#![allow(dead_code)]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::collections::BTreeMap;

use sha2::{Digest, Sha256};
use stack_receipt::{
    decision_root, genesis_hash, subject_digest, Action, ActualAction, Assurance, Attempted, Authorized,
    CapabilityBinding, CnsValue, DecisionEvidence, Digest32, Event, ExecutionId, GateOutcome, GatePosition, Handoff,
    NativeDigest, Outcome, Proposed, Provenance, ReceiptKeyAnchor, ReceiptKeyId, ReceiptPublicKey, ReceiptSigner,
    Record, Rejected, SignedRecord, Subject, Terminal, TrustedReceiptKeys, Verdict,
};

/// The content the fixture execution is about.
pub fn subject_content() -> CnsValue {
    let mut m = BTreeMap::new();
    m.insert("doc".to_owned(), CnsValue::text("invoice-42"));
    m.insert("amount".to_owned(), CnsValue::Int(1200));
    CnsValue::Map(m)
}

/// The CNS digest of [`subject_content`].
pub fn subject_digest_of_content() -> Digest32 {
    subject_digest(&subject_content())
}

/// The result bytes the fixture Completed outcome digests.
pub fn result_bytes() -> &'static [u8] {
    b"stack-receipt fixture result bytes"
}

/// SHA-256 of [`result_bytes`].
pub fn result_digest() -> Digest32 {
    Digest32::from_bytes(Sha256::digest(result_bytes()).into())
}

/// Start of test time (a fixed Unix ms value).
pub const T0: u64 = 1_800_000_000_000;
/// One day in milliseconds.
pub const DAY: u64 = 24 * 3_600_000;

/// TEST FIXTURE RECEIPT KEY: the secret is SHA-256 of a public label.
/// Not a secret, not a key anyone deploys.
pub fn fixture_signer(label: &str) -> ReceiptSigner {
    let secret: [u8; 32] = Sha256::digest(format!("stack-receipt TEST FIXTURE key: {label}").as_bytes()).into();
    ReceiptSigner::from_secret_bytes(&secret).unwrap()
}

/// The public half of the fixture key for `label`.
pub fn fixture_public_key(label: &str) -> ReceiptPublicKey {
    *fixture_signer(label).public_key()
}

/// An active anchor for the fixture key `label` under `kernel_id`, valid
/// from `T0 - DAY` to `T0 + DAY`.
pub fn fixture_anchor(kernel_id: &str, label: &str) -> ReceiptKeyAnchor {
    ReceiptKeyAnchor::new(kernel_id, fixture_public_key(label), T0 - DAY, T0 + DAY).unwrap()
}

/// A trust set holding the `kernel-1` key for kernel `kernel-1`.
pub fn baseline_trust() -> TrustedReceiptKeys {
    let mut t = TrustedReceiptKeys::new(16);
    t.insert(fixture_anchor("kernel-1", "kernel-1")).unwrap();
    t
}

/// Signs `events` in order as one chain under the `kernel-1` fixture key:
/// sequence 1.., prev hashes linked from genesis.
pub fn sign_chain(events: Vec<Event>) -> Vec<SignedRecord> {
    sign_chain_with(&fixture_signer("kernel-1"), events)
}

/// [`sign_chain`] under an explicit signer.
pub fn sign_chain_with(signer: &ReceiptSigner, events: Vec<Event>) -> Vec<SignedRecord> {
    let mut prev = genesis_hash();
    let mut out = Vec::new();
    for (i, event) in events.into_iter().enumerate() {
        let mut r = record(u64::try_from(i).unwrap() + 1, prev, event);
        r.key_id = *signer.key_id();
        let s = signer.sign(r).unwrap();
        prev = *s.hash();
        out.push(s);
    }
    out
}

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

/// A two-seat, all-PASS decision with a real (recomputable) root.
pub fn decision() -> DecisionEvidence {
    let seats = vec!["Governance_Gateway:door".to_owned(), "DIT:judge".to_owned()];
    let verdicts = vec![
        verdict("door", GatePosition::Alpha, GateOutcome::Pass),
        verdict("judge", GatePosition::Omega, GateOutcome::Pass),
    ];
    DecisionEvidence {
        root: decision_root(&seats, &verdicts),
        seats,
        verdicts,
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
        subject_digest: subject_digest_of_content(),
        decision_root: decision().root,
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
            digest: subject_digest_of_content(),
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
        use_evidence: None,
    })
}

/// The fixture Authorized event under format version 2: it carries the use
/// store's evidence.
pub fn authorized_with_evidence(evidence: stack_receipt::UseEvidence) -> Event {
    Event::Authorized(Authorized {
        capability: capability(),
        action: action(),
        use_evidence: Some(evidence),
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
        worker: None,
    })
}

/// The fixture worker binding.
pub fn worker_binding() -> stack_receipt::WorkerBinding {
    stack_receipt::WorkerBinding {
        image_sha256: d(0xc1),
        limits: stack_receipt::AppliedLimits {
            wall_clock_deadline_ns: 2_000_000_000,
            cpu_seconds: 0,
            address_space_bytes: 4 << 30,
            max_output_bytes: 4096,
            file_size_bytes: 0,
            nofile: 0,
        },
    }
}

/// The fixture Attempted event under format version 2: it binds the worker.
pub fn attempted_with_worker() -> Event {
    let Event::Attempted(a) = attempted() else {
        unreachable!()
    };
    Event::Attempted(stack_receipt::Attempted {
        worker: Some(worker_binding()),
        ..a
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
        result_digest: result_digest(),
    }
}

/// Re-signs `records` as one chain under `signer`, rewriting sequence,
/// prev hash and key id. What an insider holding the receipt key can
/// produce from any list of records.
pub fn resign_chain(signer: &ReceiptSigner, records: Vec<Record>) -> Vec<SignedRecord> {
    let mut prev = genesis_hash();
    let mut out = Vec::new();
    for (i, mut r) in records.into_iter().enumerate() {
        r.sequence = u64::try_from(i).unwrap() + 1;
        r.prev_hash = prev;
        r.key_id = *signer.key_id();
        let s = signer.sign(r).unwrap();
        prev = *s.hash();
        out.push(s);
    }
    out
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
        Outcome::Terminated { signal: 9 },
        Outcome::TerminationUnconfirmed {
            reason: "waitpid did not return before the kernel gave up".into(),
        },
    ]
}

/// The four fixture events of one honest Completed execution, in order,
/// without chain hashes (sequence 1 to 4, prev_hash zero).
pub fn honest_events() -> Vec<Event> {
    vec![proposed(), authorized(), attempted(), terminal(completed())]
}
