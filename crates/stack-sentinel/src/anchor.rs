//! The external head anchor (`twin_custody.py`, TACK Layer 5 step 2.6).
//!
//! A hash chain checked link by link catches an edited or deleted middle
//! row, but a chain cut at the tail and rebuilt from there is internally
//! perfect. The anchor is the record of what the head was: the head hash,
//! the row count, the time it was sealed and the signing key's fingerprint,
//! with an HMAC over those four, kept where the database writer cannot
//! reach it.
//!
//! Reproduces `head_anchor_payload`, `read_head_anchor`,
//! `verify_head_anchor` and `check_head_anchor`.
//!
//! An anchor may carry an optional `name`, a label the Python writer signs
//! with the other four fields (`twin_custody.py:633-639`: the name joins the
//! signed payload only when present and truthy, so an unnamed anchor signs
//! exactly as before). [`read_anchor_file`] keeps the name and
//! [`check_anchor_file_with`] verifies it; [`parse_head_anchor`] and
//! [`check_head_anchor_with`] read and check the four fields only, as they
//! always did, so they fail a named anchor's HMAC.

use crate::attest::{digest_matches, AttestationStatus, KeySet};
use crate::config::VerifierConfig;
use crate::pyjson::{dumps, parse, JsonError, Object, ParseLimits, PyInt, Separators, Value};
use crate::verdict::{AnchorSummary, Finding, Reason};
use crate::verify::{describe, describe_str, LedgerRow};

/// `_ANCHOR_DOMAIN`.
pub const ANCHOR_DOMAIN: &[u8] = b"sentinel_os.head_anchor.v1";
/// `HEAD_ANCHOR_VERSION`.
pub const HEAD_ANCHOR_VERSION: i64 = 1;

/// A parsed v1 head anchor.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HeadAnchor {
    /// The `current_hash` of the row at position `entries`.
    pub head: String,
    /// How many rows the chain held when sealed.
    pub entries: PyInt,
    /// When it was sealed (ISO-8601 text; not interpreted).
    pub sealed_at: String,
    /// Wire fingerprint of the signing key.
    pub key_fingerprint: String,
    /// HMAC-SHA256 hex over [`anchor_payload`].
    pub hmac: String,
}

/// Why an anchor could not be read. `read_head_anchor` raises
/// `CustodyError` for these and the Python tool prints `TRUNCATED row=-`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum AnchorError {
    /// Larger than the configured cap.
    #[error("anchor is {len} bytes, over the {max} byte cap")]
    TooLarge {
        /// Size of the anchor.
        len: usize,
        /// The cap.
        max: usize,
    },
    /// Not readable JSON.
    #[error("anchor is not readable JSON: {0}")]
    Json(JsonError),
    /// Not a v1 head anchor: not an object, wrong version, or a field
    /// missing or of the wrong type.
    #[error("anchor is not a v1 head anchor: field {0} is missing or has the wrong type")]
    NotAnAnchor(&'static str),
}

fn field_str(o: &Object, name: &'static str) -> Result<String, AnchorError> {
    match o.get(name) {
        Some(Value::Str(s)) => Ok(s.clone()),
        _ => Err(AnchorError::NotAnAnchor(name)),
    }
}

/// `read_head_anchor`, on bytes already read. Stricter than Python in one
/// way: each field must have the type the writer gives it (`v` and
/// `entries` integers, the rest strings). Python would coerce with `str()`
/// and `int()` and then, for any value a real writer could not have made,
/// fail the HMAC; both paths end in `TRUNCATED`. An optional `name` is not
/// kept; use [`read_anchor_file`] for an anchor that may be named.
pub fn parse_head_anchor(bytes: &[u8], max_bytes: usize, limits: ParseLimits) -> Result<HeadAnchor, AnchorError> {
    parse_inner(bytes, max_bytes, limits).map(|(a, _)| a)
}

/// An anchor as read from its file: the v1 fields and the optional name the
/// writer signed with them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AnchorFile {
    /// The four signed fields, the version and the HMAC.
    pub anchor: HeadAnchor,
    /// `None` when the file has no `name` member. `Some("")` when it has one
    /// that is null or empty (or any other falsy JSON value), which nothing
    /// signed: such an anchor never verifies (`twin_custody.py:702-703`).
    pub name: Option<String>,
}

/// [`parse_head_anchor`], keeping the optional `name`. A `name` that is a
/// string is kept as it is; any other falsy value (null, `0`, `false`, an
/// empty list or mapping) is kept as `Some("")`, so it fails the HMAC as it
/// does in Python; a truthy value that is not a string, which the Python
/// writer refuses to produce (`_check_anchor_name`), is
/// [`AnchorError::NotAnAnchor`] (Python would sign its JSON form; both end
/// in `TRUNCATED`).
pub fn read_anchor_file(bytes: &[u8], max_bytes: usize, limits: ParseLimits) -> Result<AnchorFile, AnchorError> {
    let (anchor, o) = parse_inner(bytes, max_bytes, limits)?;
    let name = match o.get("name") {
        None => None,
        Some(Value::Str(s)) => Some(s.clone()),
        Some(v) if !v.is_truthy() => Some(String::new()),
        Some(_) => return Err(AnchorError::NotAnAnchor("name")),
    };
    Ok(AnchorFile { anchor, name })
}

fn parse_inner(bytes: &[u8], max_bytes: usize, limits: ParseLimits) -> Result<(HeadAnchor, Object), AnchorError> {
    if bytes.len() > max_bytes {
        return Err(AnchorError::TooLarge {
            len: bytes.len(),
            max: max_bytes,
        });
    }
    let v = parse(bytes, limits).map_err(AnchorError::Json)?;
    let Value::Object(o) = v else {
        return Err(AnchorError::NotAnAnchor("v"));
    };
    match o.get("v") {
        Some(Value::Int(i)) if i.to_i64() == Some(HEAD_ANCHOR_VERSION) => {}
        _ => return Err(AnchorError::NotAnAnchor("v")),
    }
    let entries = match o.get("entries") {
        Some(Value::Int(i)) => i.clone(),
        _ => return Err(AnchorError::NotAnAnchor("entries")),
    };
    let a = HeadAnchor {
        head: field_str(&o, "head")?,
        entries,
        sealed_at: field_str(&o, "sealed_at")?,
        key_fingerprint: field_str(&o, "key_fingerprint")?,
        hmac: field_str(&o, "hmac")?,
    };
    Ok((a, o))
}

/// `head_anchor_payload` of an unnamed anchor: domain, a zero byte, then
/// the compact sorted JSON of `entries`, `head`, `key_fingerprint` and
/// `sealed_at`.
pub fn anchor_payload(a: &HeadAnchor) -> Vec<u8> {
    anchor_payload_named(a, None)
}

/// `head_anchor_payload(head, entries, sealed_at, key_fingerprint, name)`
/// (`twin_custody.py:633-639`): as [`anchor_payload`], with `"name"` added
/// to the sorted JSON only when `name` is present and non-empty (Python's
/// `if name:`). `None` and `Some("")` give exactly the unnamed payload. The
/// JSON is `canonical_json` (`twin_custody.py:117-119`): compact separators,
/// sorted keys, `ensure_ascii`, which the compact writer reproduces.
pub fn anchor_payload_named(a: &HeadAnchor, name: Option<&str>) -> Vec<u8> {
    let mut body = Object::new();
    body.insert("entries".into(), Value::Int(a.entries.clone()));
    body.insert("head".into(), Value::Str(a.head.clone()));
    body.insert("key_fingerprint".into(), Value::Str(a.key_fingerprint.clone()));
    body.insert("sealed_at".into(), Value::Str(a.sealed_at.clone()));
    if let Some(n) = name.filter(|n| !n.is_empty()) {
        body.insert("name".into(), Value::Str(n.to_owned()));
    }
    let mut out = ANCHOR_DOMAIN.to_vec();
    out.push(0);
    out.extend_from_slice(dumps(&Value::Object(body), Separators::Compact).as_bytes());
    out
}

/// `verify_head_anchor` of an unnamed anchor: its HMAC under the key it
/// names.
pub fn verify_head_anchor(a: &HeadAnchor, keys: &KeySet) -> AttestationStatus {
    if keys.is_empty() {
        return AttestationStatus::Unverifiable;
    }
    verify_payload(a, keys, anchor_payload(a))
}

/// `verify_head_anchor` (`twin_custody.py:694-719`) of an anchor as read
/// from its file, name included. A `name` member that is present but empty
/// is `Invalid`: nothing signed it.
pub fn verify_anchor_file(f: &AnchorFile, keys: &KeySet) -> AttestationStatus {
    if keys.is_empty() {
        return AttestationStatus::Unverifiable;
    }
    if f.name.as_deref() == Some("") {
        return AttestationStatus::Invalid;
    }
    verify_payload(&f.anchor, keys, anchor_payload_named(&f.anchor, f.name.as_deref()))
}

fn verify_payload(a: &HeadAnchor, keys: &KeySet, payload: Vec<u8>) -> AttestationStatus {
    if let Some(k) = keys.trusted_key(&a.key_fingerprint) {
        return if digest_matches(k, &payload, &a.hmac) {
            AttestationStatus::Ok
        } else {
            AttestationStatus::Invalid
        };
    }
    if let Some(k) = keys.retired_key(&a.key_fingerprint) {
        return if digest_matches(k, &payload, &a.hmac) {
            AttestationStatus::RetiredKey
        } else {
            AttestationStatus::Invalid
        };
    }
    AttestationStatus::UnknownKey
}

/// Whether `s` looks like the ISO-8601 text `datetime.isoformat()` writes:
/// at most 64 characters of digits and `-:.+TZ`.
fn is_timestamp_shaped(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 64
        && s.bytes().all(|b| b.is_ascii_digit() || matches!(b, b'-' | b':' | b'.' | b'+' | b'T' | b'Z'))
}

/// What a report shows about an anchor (see [`AnchorSummary`]).
pub fn anchor_summary(a: &HeadAnchor, vouched: bool) -> AnchorSummary {
    AnchorSummary {
        entries: a.entries.to_string(),
        sealed_at: if is_timestamp_shaped(&a.sealed_at) {
            a.sealed_at.clone()
        } else {
            describe_str(&a.sealed_at)
        },
        key_fingerprint: describe_str(&a.key_fingerprint),
        vouched,
    }
}

/// `check_head_anchor` with the default [`VerifierConfig`]: a retired-key
/// anchor and a zero-entry anchor are findings (see
/// [`check_head_anchor_with`]).
pub fn check_head_anchor(rows: &[LedgerRow], a: &HeadAnchor, keys: &KeySet) -> Option<Finding> {
    check_head_anchor_with(rows, a, keys, &VerifierConfig::default())
}

/// `check_head_anchor`: `None` when the anchored head is a prefix of the
/// chain (rows appended after sealing are expected), else a `TRUNCATED`
/// finding. An anchor that does not verify vouches for nothing and fails
/// closed.
///
/// Two departures from Python, each controlled by `config`:
///
/// * an anchor sealed with a retired key is `anchor_retired_key` (RETRY)
///   unless `accept_retired_key_anchor` is set; Python accepts it;
/// * a genuine anchor sealing fewer than `min_anchor_entries` rows (by
///   default: zero or fewer) for a non-empty chain is
///   `anchor_makes_no_claim` (RETRY); Python treats a zero-entry anchor as
///   making no claim and passes the chain.
pub fn check_head_anchor_with(rows: &[LedgerRow], a: &HeadAnchor, keys: &KeySet, config: &VerifierConfig) -> Option<Finding> {
    check_status(rows, a, verify_head_anchor(a, keys), config)
}

/// [`check_head_anchor_with`] for an anchor as read from its file, its
/// optional signed `name` included (see [`verify_anchor_file`]). For an
/// unnamed anchor the answer is exactly that of [`check_head_anchor_with`].
pub fn check_anchor_file_with(
    rows: &[LedgerRow],
    f: &AnchorFile,
    keys: &KeySet,
    config: &VerifierConfig,
) -> Option<Finding> {
    check_status(rows, &f.anchor, verify_anchor_file(f, keys), config)
}

fn check_status(rows: &[LedgerRow], a: &HeadAnchor, status: AttestationStatus, config: &VerifierConfig) -> Option<Finding> {
    let fp = describe(Some(&Value::Str(a.key_fingerprint.clone())));
    let untrusted = |reason, detail: String| {
        Some(Finding {
            reason,
            row_id: None,
            row_position: None,
            detail: format!("anchor cannot be trusted: {detail}"),
        })
    };
    match status {
        AttestationStatus::Ok => {}
        AttestationStatus::RetiredKey if config.accept_retired_key_anchor => {}
        AttestationStatus::RetiredKey => {
            return untrusted(
                Reason::AnchorRetiredKey,
                format!("anchor sealed with key {fp}, which the auditor has retired; obtain an anchor sealed with a current key"),
            )
        }
        AttestationStatus::Unverifiable => {
            return untrusted(Reason::AnchorUnverifiable, "no key held to check the anchor".into())
        }
        AttestationStatus::UnknownKey => {
            return untrusted(
                Reason::AnchorUnknownKey,
                format!("anchor signed by key {fp}, which this verifier does not hold"),
            )
        }
        _ => {
            return untrusted(
                Reason::AnchorInvalid,
                format!("anchor HMAC does not verify under key {fp}: the anchor was altered"),
            )
        }
    }
    let below_minimum = a.entries.is_negative()
        || a.entries.magnitude_u64().is_some_and(|e| e < config.min_anchor_entries);
    if !rows.is_empty() && below_minimum {
        return Some(Finding {
            reason: Reason::AnchorMakesNoClaim,
            row_id: None,
            row_position: None,
            detail: format!(
                "the anchor seals {} row(s), fewer than the {} required, so it vouches for none of the {} row(s) in the chain",
                a.entries,
                config.min_anchor_entries,
                rows.len()
            ),
        });
    }
    if a.entries.is_negative() || a.entries.is_zero() {
        return None;
    }
    // An anchored count too large for u64 is larger than any export.
    let entries = a.entries.magnitude_u64().and_then(|e| usize::try_from(e).ok());
    let enough = entries.filter(|e| *e <= rows.len());
    let Some(entries) = enough else {
        let sealed = a.entries.to_string();
        let missing = entries.map_or_else(|| "an unrepresentable number of".to_owned(), |e| (e - rows.len()).to_string());
        return Some(Finding {
            reason: Reason::TailMissing,
            row_id: rows.last().map(|r| r.id),
            row_position: rows.len().checked_sub(1),
            detail: format!(
                "the chain holds {} row(s) but the anchor sealed {sealed}; {missing} row(s) are missing from the tail",
                rows.len()
            ),
        });
    };
    let pos = entries - 1;
    let at = rows.get(pos)?;
    let stored = at.columns.get("current_hash");
    if stored != Some(&Value::Str(a.head.clone())) {
        return Some(Finding {
            reason: Reason::HeadMismatch,
            row_id: Some(at.id),
            row_position: Some(pos),
            detail: format!(
                "the anchored head {} is not the hash at row {entries} ({}): the chain was rebuilt after it was sealed",
                describe(Some(&Value::Str(a.head.clone()))),
                describe(stored)
            ),
        });
    }
    None
}
