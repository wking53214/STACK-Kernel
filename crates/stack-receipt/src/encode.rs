//! The one canonical encoding of a [`Record`], and the record hash.
//!
//! The encoding is a deterministic length-prefixed binary form, not the
//! CNS text rendering: a record carries raw 32-byte digests, signed and
//! unsigned integers and nested optional structures, which the CNS
//! rendering (a map of text, integers, lists and maps) would have to
//! spell out as hex and flags, and the receipt's only consumers are this
//! crate's own verifier and whatever reads its log. The CNS rendering is
//! still used where it is normative: the decision root (see `cns`).
//!
//! Rules: big-endian integers; `u16`-length-prefixed UTF-8 strings with
//! no control character; `u16`-counted lists; one tag byte per enum
//! variant and per optional field (0 absent, 1 present); fixed-size
//! digests raw. Every string and count is bounded (see `record`), so a
//! valid record has exactly one encoding and a decoder never allocates
//! for a declared length before the bytes are present.
//!
//! ```text
//! canonical record
//!   "stack-receipt/1\n"   16 bytes, domain and version tag
//!   sequence              u64
//!   prev_hash             32 bytes
//!   kernel_id             str
//!   execution_id          16 bytes
//!   recorded_at_ms        u64
//!   key_id                32 bytes, receipt key id
//!   provenance            component str, version str, host_id str
//!   event                 tag u8, then the event's fields (see `encode_event`)
//! record_hash = SHA-256("stack-receipt/record-hash/1\n" || canonical record)
//! ```
//!
//! The fixed fields come first so that a torn write of a record (a crash
//! part way through) leaves a prefix whose readable bytes a reader can
//! compare with what the writer would have put there.

use sha2::{Digest, Sha256};
use stack_authority::Digest32;

use crate::record::{
    check_text, Action, ActualAction, Assurance, Attempted, Authorized, CapabilityBinding, DecisionEvidence, Event,
    ExecutionId, ExitObserved, FieldName, FrameStatus, GateOutcome, GatePosition, Handoff, NativeDigest, Observed,
    Outcome, Proposed, Provenance, ReceiptKeyId, Record, Rejected, Subject, Terminal, TerminalObserved,
    ValidationError, Verdict, MAX_ID_BYTES, MAX_OPERATION_BYTES, MAX_SEATS, MAX_TEXT_BYTES,
};

/// The domain and version tag every canonical record starts with (format
/// version 1). Every event except [`Event::TerminalObserved`] is written with it.
pub const DOMAIN_TAG: &[u8; 16] = b"stack-receipt/1\n";
/// The tag of format version 2: a terminal event that carries the
/// supervisor-observed facts. Only that event is written or accepted under it,
/// so a record still has exactly one encoding.
pub const DOMAIN_TAG_V2: &[u8; 16] = b"stack-receipt/2\n";
/// Domain separator for record hashes.
pub const RECORD_HASH_DOMAIN: &[u8] = b"stack-receipt/record-hash/1\n";
/// Domain separator for the genesis hash.
pub const GENESIS_DOMAIN: &[u8] = b"stack-receipt/genesis/1\n";
/// Longest canonical record accepted, in bytes.
pub const MAX_RECORD_BYTES: usize = 64 * 1024;
/// Byte length of the fixed prefix (tag, sequence, prev_hash).
pub const FIXED_PREFIX_BYTES: usize = 16 + 8 + 32;

const TAG_PROPOSED: u8 = 1;
const TAG_AUTHORIZED: u8 = 2;
const TAG_REJECTED: u8 = 3;
const TAG_ATTEMPTED: u8 = 4;
const TAG_TERMINAL: u8 = 5;
const TAG_TERMINAL_OBSERVED: u8 = 6;

const EXIT_NOT_OBSERVED: u8 = 0;
const EXIT_EXITED: u8 = 1;
const EXIT_SIGNALED: u8 = 2;
const EXIT_KILLED_BY_SUPERVISOR: u8 = 3;
const EXIT_UNREAPED: u8 = 4;

const FRAME_NOT_READ: u8 = 0;
const FRAME_VALID: u8 = 1;
const FRAME_MISSING: u8 = 2;
const FRAME_MALFORMED: u8 = 3;
const FRAME_OVERSIZED: u8 = 4;
const FRAME_TRAILING: u8 = 5;
const FRAME_CONFLICTING: u8 = 6;

const OUT_COMPLETED: u8 = 1;
const OUT_TIMED_OUT: u8 = 2;
const OUT_CRASHED: u8 = 3;
const OUT_SECCOMP: u8 = 4;
const OUT_RESOURCE: u8 = 5;
const OUT_RESULT_MISSING: u8 = 6;
const OUT_EXITED_NON_ZERO: u8 = 7;
const OUT_RESULT_OVERSIZED: u8 = 8;
const OUT_INTERRUPTED: u8 = 9;
const OUT_UNKNOWN: u8 = 10;
const OUT_TERMINATED: u8 = 11;
const OUT_TERMINATION_UNCONFIRMED: u8 = 12;

/// The hash a log's first record chains to.
pub fn genesis_hash() -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(GENESIS_DOMAIN);
    h.finalize().into()
}

/// SHA-256 over [`RECORD_HASH_DOMAIN`] and the canonical bytes.
pub fn record_hash(canonical: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(RECORD_HASH_DOMAIN);
    h.update(canonical);
    h.finalize().into()
}

/// Why bytes are not a canonical record.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum DecodeError {
    /// Longer than [`MAX_RECORD_BYTES`].
    #[error("record exceeds {MAX_RECORD_BYTES} bytes")]
    TooLarge,
    /// Does not start with [`DOMAIN_TAG`].
    #[error("not a stack-receipt/1 record")]
    BadTag,
    /// Ended inside a field.
    #[error("record cut off at byte {0}")]
    Truncated(usize),
    /// Bytes after the last field.
    #[error("trailing bytes at {0}")]
    TrailingBytes(usize),
    /// A string field is not UTF-8.
    #[error("{0}: not UTF-8")]
    BadUtf8(FieldName),
    /// A tag or flag byte names no variant.
    #[error("{0}: unknown tag {1}")]
    BadTagByte(FieldName, u8),
    /// A field breaks the record rules.
    #[error("{0}")]
    Invalid(#[from] ValidationError),
}

struct Encoder {
    buf: Vec<u8>,
}

impl Encoder {
    fn u8(&mut self, v: u8) {
        self.buf.push(v);
    }
    fn u16(&mut self, v: u16) {
        self.buf.extend_from_slice(&v.to_be_bytes());
    }
    fn u64(&mut self, v: u64) {
        self.buf.extend_from_slice(&v.to_be_bytes());
    }
    fn i32(&mut self, v: i32) {
        self.buf.extend_from_slice(&v.to_be_bytes());
    }
    fn raw(&mut self, v: &[u8]) {
        self.buf.extend_from_slice(v);
    }
    fn digest(&mut self, d: &Digest32) {
        self.raw(d.as_bytes());
    }
    fn text(&mut self, field: FieldName, s: &str, min: usize, max: usize) -> Result<(), ValidationError> {
        check_text(field, s, min, max)?;
        // max is at most MAX_TEXT_BYTES, which fits in u16.
        self.u16(u16::try_from(s.len()).unwrap_or(u16::MAX));
        self.raw(s.as_bytes());
        Ok(())
    }
    fn id(&mut self, field: FieldName, s: &str) -> Result<(), ValidationError> {
        self.text(field, s, 1, MAX_ID_BYTES)
    }
    fn count(&mut self, field: FieldName, n: usize, max: usize) -> Result<(), ValidationError> {
        if n > max {
            return Err(ValidationError {
                field,
                problem: crate::record::Problem::TooMany { max },
            });
        }
        self.u16(u16::try_from(n).unwrap_or(u16::MAX));
        Ok(())
    }
    fn flag(&mut self, present: bool) {
        self.u8(u8::from(present));
    }
}

/// The canonical bytes of `record`, or why it cannot be encoded.
pub fn canonical_bytes(record: &Record) -> Result<Vec<u8>, ValidationError> {
    let mut e = Encoder {
        buf: Vec::with_capacity(512),
    };
    e.raw(if matches!(record.event, Event::TerminalObserved(_)) {
        DOMAIN_TAG_V2
    } else {
        DOMAIN_TAG
    });
    e.u64(record.sequence);
    e.raw(&record.prev_hash);
    e.id("kernel_id", &record.kernel_id)?;
    e.raw(record.execution_id.as_bytes());
    e.u64(record.recorded_at_ms);
    e.raw(record.key_id.as_bytes());
    encode_provenance(&mut e, &record.provenance)?;
    encode_event(&mut e, &record.event)?;
    Ok(e.buf)
}

fn encode_provenance(e: &mut Encoder, p: &Provenance) -> Result<(), ValidationError> {
    e.id("provenance.component", &p.component)?;
    e.id("provenance.version", &p.version)?;
    e.id("provenance.host_id", &p.host_id)
}

fn encode_action(e: &mut Encoder, field: FieldName, a: &Action) -> Result<(), ValidationError> {
    e.text(field, &a.operation, 1, MAX_OPERATION_BYTES)?;
    e.text(field, &a.resource, 1, MAX_TEXT_BYTES)
}

fn encode_decision(e: &mut Encoder, d: &DecisionEvidence) -> Result<(), ValidationError> {
    e.digest(&d.root);
    e.count("decision.seats", d.seats.len(), MAX_SEATS)?;
    for seat in &d.seats {
        e.id("decision.seat", seat)?;
    }
    e.count("decision.verdicts", d.verdicts.len(), MAX_SEATS)?;
    for v in &d.verdicts {
        e.id("verdict.gate", &v.gate)?;
        e.u8(match v.position {
            GatePosition::Alpha => 1,
            GatePosition::Omega => 2,
        });
        e.u8(match v.outcome {
            GateOutcome::Pass => 1,
            GateOutcome::Retry => 2,
            GateOutcome::TerminalBreach => 3,
        });
        e.text("verdict.subject", &v.subject, 0, MAX_TEXT_BYTES)?;
        e.text("verdict.digest", &v.digest, 0, MAX_TEXT_BYTES)?;
    }
    Ok(())
}

fn encode_event(e: &mut Encoder, event: &Event) -> Result<(), ValidationError> {
    match event {
        Event::Proposed(p) => {
            e.u8(TAG_PROPOSED);
            e.text("subject.identity", &p.subject.identity, 1, MAX_TEXT_BYTES)?;
            e.digest(&p.subject.digest);
            encode_decision(e, &p.decision)?;
            encode_action(e, "proposed.action", &p.action)?;
            e.flag(p.handoff.is_some());
            if let Some(h) = &p.handoff {
                e.raw(&h.sender_fingerprint);
                e.id("handoff.audience", &h.audience)?;
                e.u64(h.sequence);
                e.raw(&h.nonce);
                e.u8(match h.assurance {
                    Assurance::Development => 1,
                    Assurance::Production => 2,
                });
            }
            e.flag(p.native_digest.is_some());
            if let Some(n) = &p.native_digest {
                e.text("native_digest.label", &n.label, 1, MAX_TEXT_BYTES)?;
                e.digest(&n.digest);
            }
        }
        Event::Authorized(a) => {
            e.u8(TAG_AUTHORIZED);
            let c = &a.capability;
            e.digest(&c.cap_digest);
            e.id("capability.cap_id", &c.cap_id)?;
            e.id("capability.issuer_id", &c.issuer_id)?;
            e.digest(&c.issuer_key_id);
            e.text("capability.policy_ref", &c.policy_ref, 0, MAX_TEXT_BYTES)?;
            e.id("capability.audience", &c.audience)?;
            e.digest(&c.subject_digest);
            e.digest(&c.decision_root);
            e.flag(c.one_time);
            e.u64(c.authorized_at_ms);
            encode_action(e, "authorized.action", &a.action)?;
        }
        Event::Rejected(r) => {
            e.u8(TAG_REJECTED);
            e.text("rejected.reason", &r.reason, 1, MAX_TEXT_BYTES)?;
        }
        Event::Attempted(a) => {
            e.u8(TAG_ATTEMPTED);
            e.text("attempted.action", &a.action.operation, 1, MAX_OPERATION_BYTES)?;
            e.text("attempted.action", &a.action.resource, 1, MAX_TEXT_BYTES)?;
            e.digest(&a.action.argument_digest);
            e.u64(a.started_at_ms);
        }
        Event::Terminal(_) | Event::TerminalObserved(_) => {
            let Some((t, observed)) = event.terminal_parts() else {
                return Ok(());
            };
            e.u8(if observed.is_some() { TAG_TERMINAL_OBSERVED } else { TAG_TERMINAL });
            match &t.outcome {
                Outcome::Completed {
                    exit_code,
                    result_digest,
                } => {
                    e.u8(OUT_COMPLETED);
                    e.i32(*exit_code);
                    e.digest(result_digest);
                }
                Outcome::TimedOut => e.u8(OUT_TIMED_OUT),
                Outcome::Crashed { signal } => {
                    e.u8(OUT_CRASHED);
                    e.i32(*signal);
                }
                Outcome::SeccompViolation { signal } => {
                    e.u8(OUT_SECCOMP);
                    e.i32(*signal);
                }
                Outcome::ResourceLimit { signal } => {
                    e.u8(OUT_RESOURCE);
                    e.i32(*signal);
                }
                Outcome::ResultMissing { exit_code } => {
                    e.u8(OUT_RESULT_MISSING);
                    e.i32(*exit_code);
                }
                Outcome::ExitedNonZero { exit_code } => {
                    e.u8(OUT_EXITED_NON_ZERO);
                    e.i32(*exit_code);
                }
                Outcome::ResultOversized => e.u8(OUT_RESULT_OVERSIZED),
                Outcome::Interrupted { reason } => {
                    e.u8(OUT_INTERRUPTED);
                    e.text("terminal.reason", reason, 1, MAX_TEXT_BYTES)?;
                }
                Outcome::Unknown { reason } => {
                    e.u8(OUT_UNKNOWN);
                    e.text("terminal.reason", reason, 1, MAX_TEXT_BYTES)?;
                }
                Outcome::Terminated { signal } => {
                    e.u8(OUT_TERMINATED);
                    e.i32(*signal);
                }
                Outcome::TerminationUnconfirmed { reason } => {
                    e.u8(OUT_TERMINATION_UNCONFIRMED);
                    e.text("terminal.reason", reason, 1, MAX_TEXT_BYTES)?;
                }
            }
            e.u64(t.completed_at_ms);
            e.u64(t.elapsed_ns);
            if let Some(o) = observed {
                match o.exit {
                    ExitObserved::NotObserved => e.u8(EXIT_NOT_OBSERVED),
                    ExitObserved::Exited { code } => {
                        e.u8(EXIT_EXITED);
                        e.i32(code);
                    }
                    ExitObserved::Signaled { signal } => {
                        e.u8(EXIT_SIGNALED);
                        e.i32(signal);
                    }
                    ExitObserved::KilledBySupervisor { signal } => {
                        e.u8(EXIT_KILLED_BY_SUPERVISOR);
                        e.i32(signal);
                    }
                    ExitObserved::Unreaped => e.u8(EXIT_UNREAPED),
                }
                e.u8(match o.frame {
                    FrameStatus::NotRead => FRAME_NOT_READ,
                    FrameStatus::Valid => FRAME_VALID,
                    FrameStatus::Missing => FRAME_MISSING,
                    FrameStatus::Malformed => FRAME_MALFORMED,
                    FrameStatus::Oversized => FRAME_OVERSIZED,
                    FrameStatus::Trailing => FRAME_TRAILING,
                    FrameStatus::Conflicting => FRAME_CONFLICTING,
                });
            }
        }
    }
    Ok(())
}

struct Decoder<'a> {
    b: &'a [u8],
    pos: usize,
}

impl<'a> Decoder<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], DecodeError> {
        let end = self.pos.checked_add(n).ok_or(DecodeError::Truncated(self.pos))?;
        let s = self.b.get(self.pos..end).ok_or(DecodeError::Truncated(self.pos))?;
        self.pos = end;
        Ok(s)
    }
    fn u8(&mut self) -> Result<u8, DecodeError> {
        self.take(1)?.first().copied().ok_or(DecodeError::Truncated(self.pos))
    }
    fn u16(&mut self) -> Result<u16, DecodeError> {
        let s = self.take(2)?;
        Ok(u16::from_be_bytes(<[u8; 2]>::try_from(s).map_err(|_| DecodeError::Truncated(self.pos))?))
    }
    fn u64(&mut self) -> Result<u64, DecodeError> {
        let s = self.take(8)?;
        Ok(u64::from_be_bytes(<[u8; 8]>::try_from(s).map_err(|_| DecodeError::Truncated(self.pos))?))
    }
    fn i32(&mut self) -> Result<i32, DecodeError> {
        let s = self.take(4)?;
        Ok(i32::from_be_bytes(<[u8; 4]>::try_from(s).map_err(|_| DecodeError::Truncated(self.pos))?))
    }
    fn arr32(&mut self) -> Result<[u8; 32], DecodeError> {
        let s = self.take(32)?;
        <[u8; 32]>::try_from(s).map_err(|_| DecodeError::Truncated(self.pos))
    }
    fn arr16(&mut self) -> Result<[u8; 16], DecodeError> {
        let s = self.take(16)?;
        <[u8; 16]>::try_from(s).map_err(|_| DecodeError::Truncated(self.pos))
    }
    fn digest(&mut self) -> Result<Digest32, DecodeError> {
        Ok(Digest32::from_bytes(self.arr32()?))
    }
    fn text(&mut self, field: FieldName, min: usize, max: usize) -> Result<String, DecodeError> {
        let len = usize::from(self.u16()?);
        if len > max {
            return Err(DecodeError::Invalid(ValidationError {
                field,
                problem: crate::record::Problem::TooLong { max },
            }));
        }
        let raw = self.take(len)?;
        let s = std::str::from_utf8(raw).map_err(|_| DecodeError::BadUtf8(field))?;
        check_text(field, s, min, max)?;
        Ok(s.to_owned())
    }
    fn id(&mut self, field: FieldName) -> Result<String, DecodeError> {
        self.text(field, 1, MAX_ID_BYTES)
    }
    fn count(&mut self, field: FieldName, max: usize) -> Result<usize, DecodeError> {
        let n = usize::from(self.u16()?);
        if n > max {
            return Err(DecodeError::Invalid(ValidationError {
                field,
                problem: crate::record::Problem::TooMany { max },
            }));
        }
        Ok(n)
    }
    fn flag(&mut self, field: FieldName) -> Result<bool, DecodeError> {
        match self.u8()? {
            0 => Ok(false),
            1 => Ok(true),
            other => Err(DecodeError::BadTagByte(field, other)),
        }
    }
}

/// Parses canonical bytes back into a [`Record`]. Refuses truncation,
/// trailing bytes, a wrong tag, out-of-bounds lengths and counts, invalid
/// UTF-8, control characters and unknown tag bytes.
pub fn decode_record(bytes: &[u8]) -> Result<Record, DecodeError> {
    if bytes.len() > MAX_RECORD_BYTES {
        return Err(DecodeError::TooLarge);
    }
    let mut d = Decoder { b: bytes, pos: 0 };
    let tag = d.take(DOMAIN_TAG.len())?;
    let v2 = if tag == DOMAIN_TAG {
        false
    } else if tag == DOMAIN_TAG_V2 {
        true
    } else {
        return Err(DecodeError::BadTag);
    };
    let sequence = d.u64()?;
    let prev_hash = d.arr32()?;
    let kernel_id = d.id("kernel_id")?;
    let execution_id = ExecutionId::from_bytes(d.arr16()?);
    let recorded_at_ms = d.u64()?;
    let key_id = ReceiptKeyId::from_bytes(d.arr32()?);
    let provenance = Provenance {
        component: d.id("provenance.component")?,
        version: d.id("provenance.version")?,
        host_id: d.id("provenance.host_id")?,
    };
    let event = decode_event(&mut d, v2)?;
    if d.pos != bytes.len() {
        return Err(DecodeError::TrailingBytes(d.pos));
    }
    let record = Record {
        kernel_id,
        sequence,
        prev_hash,
        execution_id,
        recorded_at_ms,
        key_id,
        provenance,
        event,
    };
    record.validate()?;
    Ok(record)
}

fn decode_action(d: &mut Decoder<'_>, field: FieldName) -> Result<Action, DecodeError> {
    Ok(Action {
        operation: d.text(field, 1, MAX_OPERATION_BYTES)?,
        resource: d.text(field, 1, MAX_TEXT_BYTES)?,
    })
}

fn decode_decision(d: &mut Decoder<'_>) -> Result<DecisionEvidence, DecodeError> {
    let root = d.digest()?;
    let n = d.count("decision.seats", MAX_SEATS)?;
    let mut seats = Vec::with_capacity(n);
    for _ in 0..n {
        seats.push(d.id("decision.seat")?);
    }
    let n = d.count("decision.verdicts", MAX_SEATS)?;
    let mut verdicts = Vec::with_capacity(n);
    for _ in 0..n {
        let gate = d.id("verdict.gate")?;
        let position = match d.u8()? {
            1 => GatePosition::Alpha,
            2 => GatePosition::Omega,
            other => return Err(DecodeError::BadTagByte("verdict.position", other)),
        };
        let outcome = match d.u8()? {
            1 => GateOutcome::Pass,
            2 => GateOutcome::Retry,
            3 => GateOutcome::TerminalBreach,
            other => return Err(DecodeError::BadTagByte("verdict.outcome", other)),
        };
        verdicts.push(Verdict {
            gate,
            position,
            outcome,
            subject: d.text("verdict.subject", 0, MAX_TEXT_BYTES)?,
            digest: d.text("verdict.digest", 0, MAX_TEXT_BYTES)?,
        });
    }
    Ok(DecisionEvidence { root, seats, verdicts })
}

fn decode_event(d: &mut Decoder<'_>, v2: bool) -> Result<Event, DecodeError> {
    let tag = d.u8()?;
    // A record has exactly one encoding: format version 2 holds only the
    // observed terminal event, and version 1 never holds it.
    if v2 != (tag == TAG_TERMINAL_OBSERVED) {
        return Err(DecodeError::BadTagByte("event", tag));
    }
    match tag {
        TAG_PROPOSED => {
            let subject = Subject {
                identity: d.text("subject.identity", 1, MAX_TEXT_BYTES)?,
                digest: d.digest()?,
            };
            let decision = decode_decision(d)?;
            let action = decode_action(d, "proposed.action")?;
            let handoff = if d.flag("proposed.handoff")? {
                Some(Handoff {
                    sender_fingerprint: d.arr32()?,
                    audience: d.id("handoff.audience")?,
                    sequence: d.u64()?,
                    nonce: d.arr16()?,
                    assurance: match d.u8()? {
                        1 => Assurance::Development,
                        2 => Assurance::Production,
                        other => return Err(DecodeError::BadTagByte("handoff.assurance", other)),
                    },
                })
            } else {
                None
            };
            let native_digest = if d.flag("proposed.native_digest")? {
                Some(NativeDigest {
                    label: d.text("native_digest.label", 1, MAX_TEXT_BYTES)?,
                    digest: d.digest()?,
                })
            } else {
                None
            };
            Ok(Event::Proposed(Proposed {
                subject,
                decision,
                action,
                handoff,
                native_digest,
            }))
        }
        TAG_AUTHORIZED => {
            let capability = CapabilityBinding {
                cap_digest: d.digest()?,
                cap_id: d.id("capability.cap_id")?,
                issuer_id: d.id("capability.issuer_id")?,
                issuer_key_id: d.digest()?,
                policy_ref: d.text("capability.policy_ref", 0, MAX_TEXT_BYTES)?,
                audience: d.id("capability.audience")?,
                subject_digest: d.digest()?,
                decision_root: d.digest()?,
                one_time: d.flag("capability.one_time")?,
                authorized_at_ms: d.u64()?,
            };
            let action = decode_action(d, "authorized.action")?;
            Ok(Event::Authorized(Authorized { capability, action }))
        }
        TAG_REJECTED => Ok(Event::Rejected(Rejected {
            reason: d.text("rejected.reason", 1, MAX_TEXT_BYTES)?,
        })),
        TAG_ATTEMPTED => {
            let action = ActualAction {
                operation: d.text("attempted.action", 1, MAX_OPERATION_BYTES)?,
                resource: d.text("attempted.action", 1, MAX_TEXT_BYTES)?,
                argument_digest: d.digest()?,
            };
            Ok(Event::Attempted(Attempted {
                action,
                started_at_ms: d.u64()?,
            }))
        }
        TAG_TERMINAL | TAG_TERMINAL_OBSERVED => {
            let outcome = match d.u8()? {
                OUT_COMPLETED => Outcome::Completed {
                    exit_code: d.i32()?,
                    result_digest: d.digest()?,
                },
                OUT_TIMED_OUT => Outcome::TimedOut,
                OUT_CRASHED => Outcome::Crashed { signal: d.i32()? },
                OUT_SECCOMP => Outcome::SeccompViolation { signal: d.i32()? },
                OUT_RESOURCE => Outcome::ResourceLimit { signal: d.i32()? },
                OUT_RESULT_MISSING => Outcome::ResultMissing { exit_code: d.i32()? },
                OUT_EXITED_NON_ZERO => Outcome::ExitedNonZero { exit_code: d.i32()? },
                OUT_RESULT_OVERSIZED => Outcome::ResultOversized,
                OUT_INTERRUPTED => Outcome::Interrupted {
                    reason: d.text("terminal.reason", 1, MAX_TEXT_BYTES)?,
                },
                OUT_UNKNOWN => Outcome::Unknown {
                    reason: d.text("terminal.reason", 1, MAX_TEXT_BYTES)?,
                },
                OUT_TERMINATED => Outcome::Terminated { signal: d.i32()? },
                OUT_TERMINATION_UNCONFIRMED => Outcome::TerminationUnconfirmed {
                    reason: d.text("terminal.reason", 1, MAX_TEXT_BYTES)?,
                },
                other => return Err(DecodeError::BadTagByte("terminal.outcome", other)),
            };
            let terminal = Terminal {
                outcome,
                completed_at_ms: d.u64()?,
                elapsed_ns: d.u64()?,
            };
            if !v2 {
                return Ok(Event::Terminal(terminal));
            }
            let exit = match d.u8()? {
                EXIT_NOT_OBSERVED => ExitObserved::NotObserved,
                EXIT_EXITED => ExitObserved::Exited { code: d.i32()? },
                EXIT_SIGNALED => ExitObserved::Signaled { signal: d.i32()? },
                EXIT_KILLED_BY_SUPERVISOR => ExitObserved::KilledBySupervisor { signal: d.i32()? },
                EXIT_UNREAPED => ExitObserved::Unreaped,
                other => return Err(DecodeError::BadTagByte("terminal.exit_observed", other)),
            };
            let frame = match d.u8()? {
                FRAME_NOT_READ => FrameStatus::NotRead,
                FRAME_VALID => FrameStatus::Valid,
                FRAME_MISSING => FrameStatus::Missing,
                FRAME_MALFORMED => FrameStatus::Malformed,
                FRAME_OVERSIZED => FrameStatus::Oversized,
                FRAME_TRAILING => FrameStatus::Trailing,
                FRAME_CONFLICTING => FrameStatus::Conflicting,
                other => return Err(DecodeError::BadTagByte("terminal.frame_status", other)),
            };
            Ok(Event::TerminalObserved(TerminalObserved {
                terminal,
                observed: Observed { exit, frame },
            }))
        }
        other => Err(DecodeError::BadTagByte("event", other)),
    }
}

/// Reads the fixed prefix of a canonical record: the tag, sequence and
/// previous hash. For judging a torn tail: returns `None` when the bytes
/// present disagree with what a writer at `sequence` after `prev` would
/// have written, and `Some(bytes present)` otherwise.
pub fn prefix_consistent(bytes: &[u8], sequence: u64, prev: &[u8; 32]) -> bool {
    // Either format version's tag may start the record being written.
    [DOMAIN_TAG, DOMAIN_TAG_V2].into_iter().any(|tag| {
        let mut expected = Vec::with_capacity(FIXED_PREFIX_BYTES);
        expected.extend_from_slice(tag);
        expected.extend_from_slice(&sequence.to_be_bytes());
        expected.extend_from_slice(prev);
        let n = bytes.len().min(FIXED_PREFIX_BYTES);
        bytes.get(..n) == expected.get(..n)
    })
}
