//! The handoff envelope: its fields, its canonical byte forms, and sealing
//! on the producer side.
//!
//! Two byte forms exist:
//!
//! * the **wire form**: the canonical JSON object with all ten fields, and
//! * the **MAC input**: a domain separator, then the canonical JSON object
//!   with every field except `mac`. With no audience the separator is
//!   [`MAC_DOMAIN`]. With an audience (the receiver's identifier, see
//!   [`seal_for`]) it is [`MAC_AUDIENCE_DOMAIN`], the audience's byte length
//!   in decimal, `:`, the audience bytes and `\n`. The audience is not a
//!   wire field: the receiver supplies its own configured audience, so an
//!   envelope sealed for one receiver fails prong 1 at any other.
//!
//! The subject digest is SHA-256 over the canonical JSON of the payload
//! alone.

use std::fmt;
use std::io::Read;

use hmac::{Hmac, Mac};
use serde_json::{Map, Value};
use sha2::Sha256;

use crate::canonical::{
    decode_hex_lower, encode_value_counted, escaped_len, sha256_hex, to_hex, write_str, write_u64,
    CanonicalError, Limits, MAX_SAFE_INTEGER,
};
use crate::keys::SecretKey;
use crate::vocab::{GateOutcome, GatePosition};

/// The only envelope version this build understands.
pub const ENVELOPE_VERSION: u64 = 1;

/// Domain separator prefixed to the MAC input, so an HMAC made for a
/// Trident envelope can never be valid for any other message format that
/// happens to share a key.
pub const MAC_DOMAIN: &[u8] = b"tack-trident/mac/v1\n";

/// Domain separator used instead of [`MAC_DOMAIN`] when the envelope is
/// bound to an audience. It differs from [`MAC_DOMAIN`] at byte 19, so the
/// two MAC input forms can never collide.
pub const MAC_AUDIENCE_DOMAIN: &[u8] = b"tack-trident/mac/v1/audience\n";

/// Longest accepted audience, in bytes.
pub const MAX_AUDIENCE_BYTES: usize = 256;

/// JSON values the wire parser counts for the envelope itself before it
/// reaches the payload: the envelope object and its nine scalar fields.
pub const ENVELOPE_OWN_NODES: usize = 10;

/// The ten wire field names, in canonical (sorted) order.
pub const FIELD_NAMES: [&str; 10] = [
    "gate_outcome",
    "gate_position",
    "issued_at_unix_ms",
    "mac",
    "nonce",
    "payload",
    "sender",
    "sequence",
    "subject_digest",
    "version",
];

/// 16 bytes chosen by the sender, unique per envelope. Written on the wire as
/// 32 lowercase hex characters.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct Nonce([u8; 16]);

impl Nonce {
    /// Wraps caller-supplied bytes. The caller is responsible for them being
    /// random; reuse under one sender key is refused by the receiver as a
    /// replay.
    pub const fn from_bytes(bytes: [u8; 16]) -> Self {
        Self(bytes)
    }

    /// 16 bytes from the operating system's random device (`/dev/urandom`).
    /// Returns an error on platforms without one; there is no fallback.
    pub fn from_os_random() -> std::io::Result<Self> {
        let mut buf = [0u8; 16];
        std::fs::File::open("/dev/urandom")?.read_exact(&mut buf)?;
        Ok(Self(buf))
    }

    /// Parses exactly 32 lowercase hex characters.
    pub fn from_hex(s: &str) -> Option<Self> {
        decode_hex_lower::<16>(s).map(Self)
    }

    /// The 32-character lowercase hex form.
    pub fn to_hex(&self) -> String {
        to_hex(&self.0)
    }

    /// The raw bytes.
    pub fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }
}

impl fmt::Debug for Nonce {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Nonce({})", self.to_hex())
    }
}

/// An envelope as it travels between repositories or agents.
///
/// Every field is kept in its raw wire type (strings stay strings) so that
/// the receiver can check the closed vocabularies itself instead of the
/// type system silently refusing to represent a bad value. Nothing in here
/// is trusted until [`crate::Trident`] has re-derived it.
#[derive(Debug, Clone, PartialEq)]
pub struct HandoffEnvelope {
    /// Envelope format version. Must be [`ENVELOPE_VERSION`].
    pub version: u64,
    /// The sender's key fingerprint, 64 lowercase hex characters.
    pub sender: String,
    /// Per-sender counter; must strictly increase.
    pub sequence: u64,
    /// When the sender issued it, Unix milliseconds.
    pub issued_at_unix_ms: u64,
    /// 16 random bytes as 32 lowercase hex characters.
    pub nonce: String,
    /// `alpha` or `omega`.
    pub gate_position: String,
    /// `pass`, `retry` or `terminal_breach`.
    pub gate_outcome: String,
    /// SHA-256 of the canonical payload, 64 lowercase hex characters.
    pub subject_digest: String,
    /// What the sender's gate judged.
    pub payload: Value,
    /// HMAC-SHA256 over the MAC input, 64 lowercase hex characters.
    pub mac: String,
}

/// What a sender fills in before sealing. The sealer supplies `version`,
/// `sender`, `subject_digest` and `mac`.
#[derive(Debug, Clone, PartialEq)]
pub struct EnvelopeDraft {
    /// Per-sender counter; the sender must increase it for every envelope.
    pub sequence: u64,
    /// Issue time, Unix milliseconds.
    pub issued_at_unix_ms: u64,
    /// Fresh random nonce.
    pub nonce: Nonce,
    /// Which end of the decision the sender's gate ran at.
    pub gate_position: GatePosition,
    /// The sender's gate verdict.
    pub gate_outcome: GateOutcome,
    /// The judged content.
    pub payload: Value,
}

/// Why sealing failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum SealError {
    /// The draft cannot be canonically encoded within the limits.
    #[error("draft cannot be canonically encoded: {0}")]
    Encoding(#[from] CanonicalError),
    /// The HMAC could not be keyed. Unreachable for HMAC-SHA256, which
    /// accepts any key length, but reported rather than assumed.
    #[error("HMAC could not be keyed")]
    Mac,
}

/// Seals a draft under `key` with no audience binding: computes the
/// subject digest over the canonical payload and the MAC over every other
/// field. Only a receiver whose configured audience is empty accepts it.
/// Same as [`seal_for`] with an empty audience.
///
/// `limits` is applied to the payload alone (its bytes, depth and values).
/// A receiver with the same limits also counts the envelope object and its
/// nine scalar fields ([`ENVELOPE_OWN_NODES`]) against `max_nodes` and the
/// whole wire form against `max_bytes`, so a payload right at the cap can
/// seal and still be refused.
pub fn seal(draft: EnvelopeDraft, key: &SecretKey, limits: &Limits) -> Result<HandoffEnvelope, SealError> {
    seal_for(draft, key, "", limits)
}

/// Seals a draft under `key` for one receiver, named by `audience` (the
/// receiver's `TridentConfig::audience`). The audience goes into the MAC
/// input, so any other receiver refuses the envelope at prong 1, even one
/// that trusts the same sender key.
pub fn seal_for(
    draft: EnvelopeDraft,
    key: &SecretKey,
    audience: &str,
    limits: &Limits,
) -> Result<HandoffEnvelope, SealError> {
    let _span = tracing::debug_span!("tack.trident.seal").entered();
    if audience.len() > MAX_AUDIENCE_BYTES {
        return Err(SealError::Encoding(CanonicalError::TooLarge));
    }
    let payload_bytes = encode_payload(&draft.payload, limits)?;
    let mut env = HandoffEnvelope {
        version: ENVELOPE_VERSION,
        sender: key.fingerprint().to_hex(),
        sequence: draft.sequence,
        issued_at_unix_ms: draft.issued_at_unix_ms,
        nonce: draft.nonce.to_hex(),
        gate_position: draft.gate_position.as_str().to_owned(),
        gate_outcome: draft.gate_outcome.as_str().to_owned(),
        subject_digest: sha256_hex(&payload_bytes),
        payload: draft.payload,
        mac: String::new(),
    };
    let input = env.mac_input(&payload_bytes, audience, limits)?;
    let tag = hmac_sha256(key.as_bytes(), &input).ok_or(SealError::Mac)?;
    env.mac = to_hex(&tag);
    Ok(env)
}

/// HMAC-SHA256. `None` only if the key is refused, which HMAC never does.
pub(crate) fn hmac_sha256(key: &[u8], msg: &[u8]) -> Option<[u8; 32]> {
    let mut m = <Hmac<Sha256> as Mac>::new_from_slice(key).ok()?;
    m.update(msg);
    Some(m.finalize().into_bytes().into())
}

/// Canonical bytes of a payload as it sits inside the envelope (level 1),
/// counting only the payload's own values against `max_nodes`.
pub(crate) fn encode_payload(payload: &Value, limits: &Limits) -> Result<Vec<u8>, CanonicalError> {
    encode_payload_counted(payload, limits, 0)
}

/// [`encode_payload`] with `start_nodes` already counted. The receiver
/// passes [`ENVELOPE_OWN_NODES`] so its count matches the wire parser's.
pub(crate) fn encode_payload_counted(
    payload: &Value,
    limits: &Limits,
    start_nodes: usize,
) -> Result<Vec<u8>, CanonicalError> {
    let mut out = Vec::new();
    encode_value_counted(payload, limits, 1, start_nodes, &mut out)?;
    Ok(out)
}

/// Decimal digit count of `n`.
fn digits(n: u64) -> usize {
    let mut d = 1;
    let mut v = n;
    while v >= 10 {
        v /= 10;
        d += 1;
    }
    d
}

impl HandoffEnvelope {
    /// The canonical wire form: all ten fields, sorted keys, no whitespace.
    pub fn to_wire_bytes(&self, limits: &Limits) -> Result<Vec<u8>, CanonicalError> {
        let payload_bytes = encode_payload(&self.payload, limits)?;
        let mut out = Vec::new();
        self.write_object(&payload_bytes, true, limits, &mut out)?;
        Ok(out)
    }

    /// The domain separator (see the module docs) followed by the canonical
    /// object without `mac`. `payload_bytes` must be the canonical encoding
    /// of `self.payload`. The caller keeps `audience` within
    /// [`MAX_AUDIENCE_BYTES`].
    pub(crate) fn mac_input(
        &self,
        payload_bytes: &[u8],
        audience: &str,
        limits: &Limits,
    ) -> Result<Vec<u8>, CanonicalError> {
        let mut out = Vec::new();
        if audience.is_empty() {
            out.extend_from_slice(MAC_DOMAIN);
        } else {
            out.extend_from_slice(MAC_AUDIENCE_DOMAIN);
            out.extend_from_slice(audience.len().to_string().as_bytes());
            out.push(b':');
            out.extend_from_slice(audience.as_bytes());
            out.push(b'\n');
        }
        self.write_object(payload_bytes, false, limits, &mut out)?;
        Ok(out)
    }

    /// Exact length of the canonical object (with or without `mac`) for a
    /// payload whose canonical encoding is `payload_len` bytes, or the
    /// error writing it would give. Refuses in O(1) when the raw parts
    /// alone are over budget, so an in-process envelope with a huge string
    /// field is never scanned or copied.
    pub(crate) fn canonical_len(
        &self,
        payload_len: usize,
        include_mac: bool,
        limits: &Limits,
    ) -> Result<usize, CanonicalError> {
        let strings: [&str; 6] = [
            &self.gate_outcome,
            &self.gate_position,
            &self.nonce,
            &self.sender,
            &self.subject_digest,
            if include_mac { &self.mac } else { "" },
        ];
        let raw = strings
            .iter()
            .map(|s| s.len())
            .fold(payload_len, |acc, n| acc.saturating_add(n));
        if raw > limits.max_bytes {
            return Err(CanonicalError::TooLarge);
        }
        for n in [self.issued_at_unix_ms, self.sequence, self.version] {
            if n > MAX_SAFE_INTEGER {
                return Err(CanonicalError::IntegerOutOfRange);
            }
        }
        // Keys, quotes, colons, commas and braces of the fixed layout in
        // `write_object`, without the `,"mac":` member.
        const FIXED: usize = r#"{"gate_outcome":,"gate_position":,"issued_at_unix_ms":,"nonce":,"payload":,"sender":,"sequence":,"subject_digest":,"version":}"#.len();
        let mut total = FIXED
            .saturating_add(payload_len)
            .saturating_add(digits(self.issued_at_unix_ms))
            .saturating_add(digits(self.sequence))
            .saturating_add(digits(self.version));
        for s in &strings[..5] {
            total = total.saturating_add(escaped_len(s));
        }
        if include_mac {
            total = total
                .saturating_add(r#","mac":"#.len())
                .saturating_add(escaped_len(&self.mac));
        }
        Ok(total)
    }

    fn write_object(
        &self,
        payload_bytes: &[u8],
        include_mac: bool,
        limits: &Limits,
        out: &mut Vec<u8>,
    ) -> Result<(), CanonicalError> {
        // Refuse before writing anything when the exact size is over budget,
        // so nothing is ever written past the byte cap.
        let len = self.canonical_len(payload_bytes.len(), include_mac, limits)?;
        if len > limits.max_bytes {
            return Err(CanonicalError::TooLarge);
        }
        out.reserve(len);
        let start = out.len();
        out.extend_from_slice(b"{\"gate_outcome\":");
        write_str(&self.gate_outcome, out);
        out.extend_from_slice(b",\"gate_position\":");
        write_str(&self.gate_position, out);
        out.extend_from_slice(b",\"issued_at_unix_ms\":");
        write_u64(self.issued_at_unix_ms, out)?;
        if include_mac {
            out.extend_from_slice(b",\"mac\":");
            write_str(&self.mac, out);
        }
        out.extend_from_slice(b",\"nonce\":");
        write_str(&self.nonce, out);
        out.extend_from_slice(b",\"payload\":");
        out.extend_from_slice(payload_bytes);
        out.extend_from_slice(b",\"sender\":");
        write_str(&self.sender, out);
        out.extend_from_slice(b",\"sequence\":");
        write_u64(self.sequence, out)?;
        out.extend_from_slice(b",\"subject_digest\":");
        write_str(&self.subject_digest, out);
        out.extend_from_slice(b",\"version\":");
        write_u64(self.version, out)?;
        out.push(b'}');
        debug_assert_eq!(out.len().saturating_sub(start), len);
        Ok(())
    }

    /// Builds an envelope from a strictly parsed JSON value. The value must
    /// be an object with exactly the ten fields: integers (non-negative) for
    /// `version`, `sequence` and `issued_at_unix_ms`, strings for the other
    /// scalars, anything for `payload`. Contents are not checked here; that
    /// is the prongs' job.
    pub fn from_value(v: Value) -> Option<Self> {
        let Value::Object(mut map) = v else {
            return None;
        };
        if map.len() != FIELD_NAMES.len() || !FIELD_NAMES.iter().all(|k| map.contains_key(*k)) {
            return None;
        }
        Some(Self {
            version: take_u64(&mut map, "version")?,
            sender: take_string(&mut map, "sender")?,
            sequence: take_u64(&mut map, "sequence")?,
            issued_at_unix_ms: take_u64(&mut map, "issued_at_unix_ms")?,
            nonce: take_string(&mut map, "nonce")?,
            gate_position: take_string(&mut map, "gate_position")?,
            gate_outcome: take_string(&mut map, "gate_outcome")?,
            subject_digest: take_string(&mut map, "subject_digest")?,
            payload: map.remove("payload")?,
            mac: take_string(&mut map, "mac")?,
        })
    }
}

fn take_u64(map: &mut Map<String, Value>, key: &str) -> Option<u64> {
    match map.remove(key)? {
        Value::Number(n) => n.as_u64(),
        _ => None,
    }
}

fn take_string(map: &mut Map<String, Value>, key: &str) -> Option<String> {
    match map.remove(key)? {
        Value::String(s) => Some(s),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::canonical::{parse_strict, to_canonical_bytes};
    use serde_json::json;

    fn limits() -> Limits {
        crate::TridentConfig::default().limits()
    }

    #[test]
    fn field_names_are_in_canonical_order() {
        let mut sorted = FIELD_NAMES;
        sorted.sort_by(|a, b| a.encode_utf16().cmp(b.encode_utf16()));
        assert_eq!(sorted, FIELD_NAMES);
    }

    #[test]
    fn hand_written_object_matches_generic_encoder() {
        // TEST FIXTURE KEY. Not for any deployment.
        let key = SecretKey::from_bytes(vec![0x5a; 32]).unwrap();
        let env = seal(
            EnvelopeDraft {
                sequence: 3,
                issued_at_unix_ms: 1_700_000_000_000,
                nonce: Nonce::from_bytes([7; 16]),
                gate_position: GatePosition::Omega,
                gate_outcome: GateOutcome::Retry,
                payload: json!({"z": [1, -2], "a": "\u{1F600}\n"}),
            },
            &key,
            &limits(),
        )
        .unwrap();
        let wire = env.to_wire_bytes(&limits()).unwrap();
        let generic = json!({
            "version": env.version, "sender": env.sender, "sequence": env.sequence,
            "issued_at_unix_ms": env.issued_at_unix_ms, "nonce": env.nonce,
            "gate_position": env.gate_position, "gate_outcome": env.gate_outcome,
            "subject_digest": env.subject_digest, "payload": env.payload, "mac": env.mac,
        });
        assert_eq!(wire, to_canonical_bytes(&generic, &limits()).unwrap());
        let back = HandoffEnvelope::from_value(parse_strict(&wire, &limits()).unwrap()).unwrap();
        assert_eq!(back, env);
    }

    #[test]
    fn shape_is_exact() {
        let ok = json!({
            "version": 1, "sender": "s", "sequence": 1, "issued_at_unix_ms": 1, "nonce": "n",
            "gate_position": "alpha", "gate_outcome": "pass", "subject_digest": "d",
            "payload": null, "mac": "m",
        });
        assert!(HandoffEnvelope::from_value(ok.clone()).is_some());
        let mut extra = ok.clone();
        extra.as_object_mut().unwrap().insert("x".into(), json!(1));
        assert!(HandoffEnvelope::from_value(extra).is_none());
        let mut missing = ok.clone();
        missing.as_object_mut().unwrap().remove("mac");
        assert!(HandoffEnvelope::from_value(missing).is_none());
        let mut wrong_type = ok.clone();
        wrong_type["sequence"] = json!("1");
        assert!(HandoffEnvelope::from_value(wrong_type).is_none());
        let mut negative = ok;
        negative["version"] = json!(-1);
        assert!(HandoffEnvelope::from_value(negative).is_none());
        assert!(HandoffEnvelope::from_value(json!([])).is_none());
    }

    #[test]
    fn os_nonces_differ() {
        let a = Nonce::from_os_random().unwrap();
        let b = Nonce::from_os_random().unwrap();
        assert_ne!(a, b);
    }
}
