//! The verified payload, parsed strictly into a request. Nothing here is
//! trusted: every field is a claim the later stages check or refuse.
//!
//! ```text
//! {
//!   "subject":    { ... CNS content, a map with text keys ... },
//!   "decision":   { "seats": [ "repo:gate", ... ],
//!                   "verdicts": [ { "gate", "position", "outcome", "subject", "digest" }, ... ],
//!                   "root": "<64 lowercase hex>" },
//!   "capability": "<lowercase hex of the stack-capability/1 or /2 wire bytes>",
//!   "operation":  "<name>",
//!   "resource":   "/path",
//!   "args":       <any JSON inside the Trident restricted domain>
//! }
//! ```
//!
//! Exactly these six fields, plus one optional seventh, `native_digest`
//! (`{ "label": "...", "digest": "<64 lowercase hex>" }`): the sender's own
//! digest of its native record, such as a Sentinel ledger row hash. It is
//! authenticated by the Trident MAC with the rest of the payload, is recorded
//! beside the CNS subject digest and never in place of it, and the kernel does
//! not recompute it. Each field is of the right shape, within the bounds a
//! receipt record can carry (`stack_receipt::record`) and a capability
//! can express (`stack_authority`). The Trident has already refused
//! floats, out-of-range integers, duplicate keys and excess depth, so a
//! payload that reaches here is inside the restricted CNS digest domain.

use serde_json::{Map, Value};
use stack_authority::{validate_path, Digest32, PathError, MAX_WIRE_BYTES};
use stack_receipt::record::check_text;
use stack_receipt::{GateOutcome, GatePosition, NativeDigest, ValidationError, Verdict, MAX_ID_BYTES, MAX_OPERATION_BYTES, MAX_SEATS, MAX_TEXT_BYTES};

/// Why the payload was not accepted as a request. Every variant is a
/// refusal before anything is recorded or authorized.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PayloadError {
    /// The payload, `decision` or a verdict is not a JSON object.
    #[error("{0} is not an object")]
    NotAnObject(&'static str),
    /// A field the format does not define.
    #[error("unexpected field {0:?}")]
    UnexpectedField(String),
    /// A required field is absent.
    #[error("missing field {0}")]
    MissingField(&'static str),
    /// A field has the wrong JSON type.
    #[error("field {0} has the wrong type")]
    WrongType(&'static str),
    /// `subject` is not a map, so it is not CNS content.
    #[error("subject is not a map with text keys")]
    SubjectNotAMap,
    /// `decision.root` is not 64 lowercase hex characters.
    #[error("decision.root is not a 64-character lowercase hex digest")]
    BadRoot,
    /// More seats or verdicts than a decision record can carry.
    #[error("decision holds more than {MAX_SEATS} seats or verdicts")]
    TooManySeats,
    /// A seat, gate, subject, digest, operation or resource string breaks
    /// the record rules.
    #[error("{0}")]
    Text(ValidationError),
    /// A verdict position outside the CNS vocabulary.
    #[error("verdict position outside the CNS vocabulary")]
    UnknownPosition,
    /// A verdict outcome outside the CNS vocabulary.
    #[error("verdict outcome outside the CNS vocabulary")]
    UnknownOutcome,
    /// `capability` is not lowercase hex of an even length, or decodes to
    /// more bytes than any capability can be.
    #[error("capability is not lowercase hex of a capability-sized byte string")]
    BadCapabilityHex,
    /// `native_digest.digest` is not 64 lowercase hex characters.
    #[error("native_digest.digest is not a 64-character lowercase hex digest")]
    BadNativeDigest,
    /// `resource` breaks the resource path rules.
    #[error("resource refused: {0}")]
    Resource(PathError),
}

impl From<ValidationError> for PayloadError {
    fn from(e: ValidationError) -> Self {
        Self::Text(e)
    }
}

/// The decision as the payload claims it: roster, verdicts and root, all
/// unchecked. `root` is the sender's claim; the kernel recomputes it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecisionClaim {
    /// `Decision.seats`, as `repository:gate`.
    pub seats: Vec<String>,
    /// `Decision.run.results`, in order.
    pub verdicts: Vec<Verdict>,
    /// `Decision.root` as claimed.
    pub root: Digest32,
}

/// A parsed request. Well-formed, not yet bound, not yet authorized.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Request {
    /// The CNS content the decision is about.
    pub subject: Value,
    /// The claimed decision.
    pub decision: DecisionClaim,
    /// The capability wire bytes, as presented.
    pub capability: Vec<u8>,
    /// The requested operation.
    pub operation: String,
    /// The requested resource.
    pub resource: String,
    /// The argument value for the worker.
    pub args: Value,
    /// The sender's native digest, when it sent one. Recorded as given.
    pub native_digest: Option<NativeDigest>,
}

const FIELDS: [&str; 6] = ["args", "capability", "decision", "operation", "resource", "subject"];
const DECISION_FIELDS: [&str; 3] = ["root", "seats", "verdicts"];
const VERDICT_FIELDS: [&str; 5] = ["digest", "gate", "outcome", "position", "subject"];
const NATIVE_FIELDS: [&str; 2] = ["digest", "label"];

fn object<'a>(v: &'a Value, what: &'static str, fields: &[&'static str]) -> Result<&'a Map<String, Value>, PayloadError> {
    object_with(v, what, fields, &[])
}

/// As [`object`], also allowing the `optional` fields to be absent.
fn object_with<'a>(
    v: &'a Value,
    what: &'static str,
    fields: &[&'static str],
    optional: &[&'static str],
) -> Result<&'a Map<String, Value>, PayloadError> {
    let map = v.as_object().ok_or(PayloadError::NotAnObject(what))?;
    if let Some(extra) = map
        .keys()
        .find(|k| !fields.contains(&k.as_str()) && !optional.contains(&k.as_str()))
    {
        return Err(PayloadError::UnexpectedField(extra.clone()));
    }
    for f in fields {
        if !map.contains_key(*f) {
            return Err(PayloadError::MissingField(f));
        }
    }
    Ok(map)
}

fn string<'a>(map: &'a Map<String, Value>, field: &'static str) -> Result<&'a str, PayloadError> {
    map.get(field)
        .ok_or(PayloadError::MissingField(field))?
        .as_str()
        .ok_or(PayloadError::WrongType(field))
}

fn array<'a>(map: &'a Map<String, Value>, field: &'static str) -> Result<&'a [Value], PayloadError> {
    map.get(field)
        .ok_or(PayloadError::MissingField(field))?
        .as_array()
        .map(Vec::as_slice)
        .ok_or(PayloadError::WrongType(field))
}

fn is_lower_hex(s: &str) -> bool {
    s.len().is_multiple_of(2) && s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

fn verdict(v: &Value) -> Result<Verdict, PayloadError> {
    let m = object(v, "verdict", &VERDICT_FIELDS)?;
    let verdict = Verdict {
        gate: string(m, "gate")?.to_owned(),
        position: GatePosition::parse(string(m, "position")?).ok_or(PayloadError::UnknownPosition)?,
        outcome: GateOutcome::parse(string(m, "outcome")?).ok_or(PayloadError::UnknownOutcome)?,
        subject: string(m, "subject")?.to_owned(),
        digest: string(m, "digest")?.to_owned(),
    };
    verdict.validate()?;
    Ok(verdict)
}

/// Parses a verified Trident payload into a [`Request`].
pub fn parse(payload: &Value) -> Result<Request, PayloadError> {
    let map = object_with(payload, "payload", &FIELDS, &["native_digest"])?;

    let subject = map.get("subject").ok_or(PayloadError::MissingField("subject"))?;
    if !subject.is_object() {
        return Err(PayloadError::SubjectNotAMap);
    }

    let d = object(map.get("decision").ok_or(PayloadError::MissingField("decision"))?, "decision", &DECISION_FIELDS)?;
    // `Digest32::from_hex` accepts upper case; this format does not.
    let root_hex = string(d, "root")?;
    if root_hex.len() != 64 || !is_lower_hex(root_hex) {
        return Err(PayloadError::BadRoot);
    }
    let root = Digest32::from_hex(root_hex).ok_or(PayloadError::BadRoot)?;
    let seat_values = array(d, "seats")?;
    let verdict_values = array(d, "verdicts")?;
    if seat_values.len() > MAX_SEATS || verdict_values.len() > MAX_SEATS {
        return Err(PayloadError::TooManySeats);
    }
    let mut seats = Vec::with_capacity(seat_values.len());
    for s in seat_values {
        let seat = s.as_str().ok_or(PayloadError::WrongType("decision.seats"))?;
        check_text("decision.seat", seat, 1, MAX_ID_BYTES)?;
        seats.push(seat.to_owned());
    }
    let verdicts = verdict_values.iter().map(verdict).collect::<Result<Vec<_>, _>>()?;

    let cap_hex = string(map, "capability")?;
    if !is_lower_hex(cap_hex) || cap_hex.len() > MAX_WIRE_BYTES.saturating_mul(2) {
        return Err(PayloadError::BadCapabilityHex);
    }
    let capability = hex::decode(cap_hex).map_err(|_| PayloadError::BadCapabilityHex)?;

    let operation = string(map, "operation")?;
    check_text("operation", operation, 1, MAX_OPERATION_BYTES)?;
    let resource = string(map, "resource")?;
    check_text("resource", resource, 1, MAX_TEXT_BYTES)?;
    validate_path(resource).map_err(PayloadError::Resource)?;

    let args = map.get("args").ok_or(PayloadError::MissingField("args"))?.clone();

    let native_digest = match map.get("native_digest") {
        None => None,
        Some(v) => {
            let m = object(v, "native_digest", &NATIVE_FIELDS)?;
            let hex_digest = string(m, "digest")?;
            if hex_digest.len() != 64 || !is_lower_hex(hex_digest) {
                return Err(PayloadError::BadNativeDigest);
            }
            let native = NativeDigest {
                label: string(m, "label")?.to_owned(),
                digest: Digest32::from_hex(hex_digest).ok_or(PayloadError::BadNativeDigest)?,
            };
            native.validate()?;
            Some(native)
        }
    };

    Ok(Request {
        subject: subject.clone(),
        decision: DecisionClaim { seats, verdicts, root },
        capability,
        operation: operation.to_owned(),
        resource: resource.to_owned(),
        args,
        native_digest,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn good() -> Value {
        json!({
            "subject": {"doc": "x", "n": 1},
            "decision": {
                "seats": ["Governance_Gateway:door"],
                "verdicts": [{"gate": "door", "position": "alpha", "outcome": "pass", "subject": "x", "digest": "ab"}],
                "root": "00".repeat(32),
            },
            "capability": "0a0b",
            "operation": "echo",
            "resource": "/data/a",
            "args": {"k": 1},
        })
    }

    #[test]
    fn a_well_formed_payload_parses() {
        let r = parse(&good()).unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(r.capability, vec![0x0a, 0x0b]);
        assert_eq!(r.decision.seats, ["Governance_Gateway:door"]);
        assert_eq!(r.decision.verdicts[0].position, GatePosition::Alpha);
        assert_eq!(r.operation, "echo");
    }

    #[test]
    fn every_shape_violation_is_refused() {
        let cases: Vec<(Value, PayloadError)> = vec![
            (json!([]), PayloadError::NotAnObject("payload")),
            (
                {
                    let mut v = good();
                    v["extra"] = json!(1);
                    v
                },
                PayloadError::UnexpectedField("extra".into()),
            ),
            (
                {
                    let mut v = good();
                    if let Some(m) = v.as_object_mut() {
                        m.remove("capability");
                    }
                    v
                },
                PayloadError::MissingField("capability"),
            ),
            (
                {
                    let mut v = good();
                    v["subject"] = json!([1]);
                    v
                },
                PayloadError::SubjectNotAMap,
            ),
            (
                {
                    let mut v = good();
                    v["decision"]["root"] = json!("ab".repeat(32).to_uppercase());
                    v
                },
                PayloadError::BadRoot,
            ),
            (
                {
                    let mut v = good();
                    v["decision"]["verdicts"][0]["position"] = json!("middle");
                    v
                },
                PayloadError::UnknownPosition,
            ),
            (
                {
                    let mut v = good();
                    v["decision"]["verdicts"][0]["outcome"] = json!("PASS");
                    v
                },
                PayloadError::UnknownOutcome,
            ),
            (
                {
                    let mut v = good();
                    v["capability"] = json!("0A0B");
                    v
                },
                PayloadError::BadCapabilityHex,
            ),
            (
                {
                    let mut v = good();
                    v["capability"] = json!("abc");
                    v
                },
                PayloadError::BadCapabilityHex,
            ),
            (
                {
                    let mut v = good();
                    v["resource"] = json!("data/a");
                    v
                },
                PayloadError::Resource(PathError::NotAbsolute),
            ),
            (
                {
                    let mut v = good();
                    v["operation"] = json!(7);
                    v
                },
                PayloadError::WrongType("operation"),
            ),
            (
                {
                    let mut v = good();
                    v["decision"]["seats"] = Value::Array(vec![json!("x"); MAX_SEATS + 1]);
                    v
                },
                PayloadError::TooManySeats,
            ),
        ];
        for (i, (payload, expected)) in cases.into_iter().enumerate() {
            assert_eq!(parse(&payload), Err(expected), "case {i}");
        }
        let mut v = good();
        v["decision"]["seats"] = json!([""]);
        assert!(matches!(parse(&v), Err(PayloadError::Text(_))));
        let mut v = good();
        v["operation"] = json!("a\nb");
        assert!(matches!(parse(&v), Err(PayloadError::Text(_))));
    }
}
