//! # stack-receipt: execution receipts and their verifier
//!
//! An execution receipt is the durable record of what the kernel did: the
//! request it saw, the decision and capability it believed authorized the
//! action, the action it actually ran, and how the run ended. It is
//! **evidence**, never **authority**. Nothing in this crate grants
//! anything; a receipt that says `Completed` is a claim the verifier
//! checks against the events around it and against the keys the auditor
//! trusts, and even a fully verified receipt proves only that the holder
//! of the receipt key signed these records in this order. It does not
//! prove the action was legitimate, that a human stood behind any key, or
//! that the log was not rolled back to an earlier head.
//!
//! ## Shape
//!
//! One log per kernel, append-only, hash-chained, every record signed by
//! the kernel's receipt key. One execution has events in a fixed order:
//! `Proposed`, then `Authorized` or `Rejected`, then `Attempted` (written
//! before the payload starts), then exactly one terminal event.
//!
//! | module | what it holds |
//! |---|---|
//! | [`record`] | the record and event types, their bounds and validation |
//! | [`encode`] | the one canonical encoding, the record hash, the genesis hash |
//! | [`sign`] | the receipt signer, signed records and frames, the trusted receipt key set |
//!
//! Later steps add the CNS decision root and roster policy, the durable
//! file log and the write-ahead recorder, and the verifier.

#![forbid(unsafe_code)]

pub mod encode;
pub mod record;
pub mod sign;

pub use sign::{
    signed_message, BadSignature, FrameError, ReceiptKeyAnchor, ReceiptKeyStatus, ReceiptPublicKey, ReceiptSigner,
    ResolveError, SignError, SignedRecord, TrustError, TrustedReceiptKeys, WeakKey, FRAME_OVERHEAD,
    RECEIPT_KEY_ID_DOMAIN, SIGNATURE_BYTES, SIGNATURE_DOMAIN,
};
pub use encode::{
    canonical_bytes, decode_record, genesis_hash, record_hash, DecodeError, DOMAIN_TAG, GENESIS_DOMAIN,
    MAX_RECORD_BYTES, RECORD_HASH_DOMAIN,
};
pub use record::{
    Action, ActualAction, Assurance, Attempted, Authorized, CapabilityBinding, DecisionEvidence, Event, ExecutionId,
    GateOutcome, GatePosition, Handoff, NativeDigest, Outcome, OutcomeKind, Problem, Proposed, Provenance,
    ReceiptKeyId, Record, Rejected, Stage, Subject, Terminal, ValidationError, Verdict, EXECUTION_ID_BYTES,
    MAX_ID_BYTES, MAX_OPERATION_BYTES, MAX_SEATS, MAX_TEXT_BYTES,
};
pub use stack_authority::Digest32;
