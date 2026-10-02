//! The canonical form of one ledger row, and the hash of it.
//!
//! This is a line-by-line reproduction of
//! `sentinel_os/twin_custody.py::canonical_form`, which itself mirrors the
//! writer in `governance/ledger_postgres.py`, with the shared lists from
//! `sentinel_os/canonical_fields.py` copied here as constants. The row's
//! `current_hash` is `sha256(json.dumps(canonical_form(row), sort_keys=True,
//! default=str).encode())` (`twin_custody.recompute_current_hash`).
//!
//! Python distinguishes a missing column from a `null` one: `row["x"]` raises
//! `KeyError` for a missing key and the witness reports `TAMPERED`, while
//! `row.get("x")` reads a missing key as `None`. Each column below is read
//! the same way the Python reads it.
//!
//! ## What the hash covers, and what it does not
//!
//! Each record kind hashes a fixed set of columns, listed by
//! [`hashed_columns`], and only those. Every other column the export ships
//! (`id`, `timestamp`, `call_sid`, `cassette_snapshot`, `record_kind` on a
//! base row, any column the export adds) can change without changing the
//! row's hash, so `VERIFIED` says nothing about them. For several kinds only
//! named keys of the `data` mapping are hashed. This is the `sentinel_os`
//! ledger design, reproduced as it is; the verifier reports which unhashed
//! columns an export carried (`Report::unhashed_columns`).
//!
//! Internally the canonical form borrows the row's values instead of
//! copying them, and the hash is computed by streaming the serialization
//! into SHA-256, so a large column costs no second copy.

use std::borrow::Cow;
use std::collections::BTreeMap;

use sha2::{Digest, Sha256};

use crate::pyjson::{write_entries, Object, Separators, Sink, Value};

/// `canonical_fields.OPTIONAL_HASHED_FIELDS`, in its fixed order. Each joins
/// the canonical form only when present and truthy on the row.
pub const OPTIONAL_HASHED_FIELDS: [&str; 13] = [
    "cassette_hash",
    "cassette_code_hash",
    "model_identity",
    "authorized_by",
    "supersedes_hash",
    "outcome_obligation",
    "replaces_hash",
    "ai_cost",
    "shadow_run_hash",
    "decision_hash",
    "authorized_by_sig",
    "subject_digest",
    "shuffle_seed",
];

/// `canonical_fields.CONTRACT_CANONICAL_FIELDS`: the four contract record
/// kinds and the fields each hashes, read from the row's `data` mapping.
pub const CONTRACT_CANONICAL_FIELDS: [(&str, &[&str]); 4] = [
    (
        "contract_ingest",
        &["counterparty", "ingest_id", "data_scope", "received_at"],
    ),
    (
        "contract_egress",
        &[
            "counterparty",
            "decision",
            "data_scope",
            "recipient",
            "recipient_class",
            "purpose",
            "approval_reference",
            "occurred_at",
        ],
    ),
    (
        "contract_approval",
        &[
            "counterparty",
            "approval_id",
            "state",
            "recipient",
            "recipient_class",
            "scope",
            "granted_at",
            "expires_at",
            "revoked_at",
        ],
    ),
    (
        "contract_deletion",
        &[
            "counterparty",
            "ingest_id",
            "deleted_at",
            "scope",
            "method",
            "stamp",
        ],
    ),
];

/// `canonical_fields.CONTRACT_KINDS_WITH_FINDING`.
pub const CONTRACT_KINDS_WITH_FINDING: [&str; 1] = ["contract_egress"];

/// `canonical_fields.OBSERVED_EVENT_CANONICAL_FIELDS`, read from `input_data`.
pub const OBSERVED_EVENT_CANONICAL_FIELDS: [&str; 13] = [
    "episode_id",
    "event_id",
    "domain",
    "kind",
    "occurred_at",
    "observed_at",
    "source",
    "provenance",
    "method",
    "fields",
    "detail",
    "schema_version",
    "reducer_version",
];

/// `canonical_fields.ATTESTATION_POLICY_RECORD_KIND`.
pub const ATTESTATION_POLICY_RECORD_KIND: &str = "attestation_policy";

/// `canonical_fields.ATTESTATION_POLICY_CANONICAL_FIELDS`, read from `data`.
pub const ATTESTATION_POLICY_CANONICAL_FIELDS: [&str; 2] = ["key_fingerprint", "enforced_at"];

/// `authorized_by_attestation.SIGNATURE_FIELD`: the column and canonical key
/// of the keyed attestation.
pub const SIGNATURE_FIELD: &str = "authorized_by_sig";

/// Why a canonical form could not be rebuilt. The witness reports every one
/// of these as `TAMPERED` (`recompute-failed`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum RecomputeError {
    /// A column the Python reads with `row[...]` is absent (`KeyError`).
    #[error("column {0} is missing from the row")]
    MissingColumn(&'static str),
    /// A column read as a mapping (`(row.get(c) or {}).get(...)`) holds a
    /// truthy value that is not a mapping. Python raises `AttributeError`
    /// there, which the witness does not catch; this crate reports it as
    /// the row failing to recompute instead of stopping.
    #[error("column {0} is truthy but not a mapping")]
    NotAMapping(&'static str),
    /// `record_kind` is a list or a mapping. Python raises `TypeError` when
    /// it tests membership in the contract-kinds dict.
    #[error("record_kind is a list or mapping and cannot be looked up")]
    UnhashableRecordKind,
}

/// A canonical form that borrows the row's values. Keys are the fixed
/// canonical names, so they are `&'static str`, and `BTreeMap` keeps them in
/// the order `sort_keys=True` writes them.
pub(crate) type CanonRef<'a> = BTreeMap<&'static str, Cow<'a, Value>>;

const NULL: Value = Value::Null;

fn req<'a>(row: &'a Object, col: &'static str) -> Result<Cow<'a, Value>, RecomputeError> {
    row.get(col).map(Cow::Borrowed).ok_or(RecomputeError::MissingColumn(col))
}

fn opt<'a>(row: &'a Object, col: &str) -> Cow<'a, Value> {
    Cow::Borrowed(row.get(col).unwrap_or(&NULL))
}

/// `(row.get(col) or {})` followed by `.get(...)`: falsy reads as empty.
fn mapping<'a>(row: &'a Object, col: &'static str) -> Result<Option<&'a Object>, RecomputeError> {
    match row.get(col) {
        None => Ok(None),
        Some(v) if !v.is_truthy() => Ok(None),
        Some(Value::Object(o)) => Ok(Some(o)),
        Some(_) => Err(RecomputeError::NotAMapping(col)),
    }
}

fn mget<'a>(m: Option<&'a Object>, key: &str) -> Cow<'a, Value> {
    Cow::Borrowed(m.and_then(|o| o.get(key)).unwrap_or(&NULL))
}

fn s(v: &str) -> Cow<'static, Value> {
    Cow::Owned(Value::Str(v.to_owned()))
}

/// `canonical_fields.apply_optional_hashed_fields`.
pub fn apply_optional_hashed_fields(canonical: &mut Object, row: &Object) {
    for field in OPTIONAL_HASHED_FIELDS {
        if let Some(v) = row.get(field) {
            if v.is_truthy() {
                canonical.insert(field.to_owned(), v.clone());
            }
        }
    }
}

fn apply_optional_ref<'a>(canonical: &mut CanonRef<'a>, row: &'a Object) {
    for field in OPTIONAL_HASHED_FIELDS {
        if let Some(v) = row.get(field) {
            if v.is_truthy() {
                canonical.insert(field, Cow::Borrowed(v));
            }
        }
    }
}

/// `twin_custody.canonical_form(row)`, kind by kind. This returns an owned
/// copy; the verifier itself uses a borrowing form and copies nothing.
pub fn canonical_form(row: &Object) -> Result<Object, RecomputeError> {
    Ok(canonical_form_ref(row)?
        .into_iter()
        .map(|(k, v)| (k.to_owned(), v.into_owned()))
        .collect())
}

/// [`canonical_form`], borrowing the row's values.
pub(crate) fn canonical_form_ref(row: &Object) -> Result<CanonRef<'_>, RecomputeError> {
    let kind_value = row.get("record_kind");
    let kind: Option<&str> = kind_value.and_then(Value::as_str);
    let mut c = CanonRef::new();
    match kind {
        Some("governance_decision") => {
            let data = mapping(row, "data")?;
            c.insert("record_kind", s("governance_decision"));
            c.insert("action_type", req(row, "action_type")?);
            c.insert("node", req(row, "node")?);
            c.insert("cassette_version", req(row, "cassette_version")?);
            c.insert("input_data", req(row, "input_data")?);
            c.insert("policy_parameters", req(row, "policy_parameters")?);
            c.insert("reasoning", req(row, "reason")?);
            c.insert("output", req(row, "decision_output")?);
            c.insert("previous_value", req(row, "previous_value")?);
            c.insert("applied_value", req(row, "applied_value")?);
            c.insert(
                "parameter_changed",
                Cow::Owned(Value::Bool(mget(data, "parameter_changed").is_truthy())),
            );
            c.insert("previous_hash", req(row, "previous_hash")?);
            apply_optional_ref(&mut c, row);
        }
        Some("cassette_binding") => {
            c.insert("record_kind", s("cassette_binding"));
            c.insert("cassette_version", req(row, "cassette_version")?);
            c.insert("previous_hash", req(row, "previous_hash")?);
            apply_optional_ref(&mut c, row);
        }
        Some(k @ ("regulatory_cassette_inserted" | "regulatory_cassette_removed")) => {
            let d = mapping(row, "data")?;
            c.insert("record_kind", s(k));
            c.insert("cassette_version", req(row, "cassette_version")?);
            c.insert("mode", mget(d, "mode"));
            c.insert("regulation", mget(d, "regulation"));
            c.insert("previous_hash", req(row, "previous_hash")?);
            apply_optional_ref(&mut c, row);
        }
        Some("regulatory_disclosure") => {
            let d = mapping(row, "data")?;
            c.insert("record_kind", s("regulatory_disclosure"));
            c.insert("cassette_version", req(row, "cassette_version")?);
            for key in ["regulation", "check", "action", "subject"] {
                c.insert(key, mget(d, key));
            }
            c.insert("finding", req(row, "decision_output")?);
            c.insert("previous_hash", req(row, "previous_hash")?);
            apply_optional_ref(&mut c, row);
        }
        Some("outcome_harm_event") => {
            let d = mapping(row, "data")?;
            c.insert("record_kind", s("outcome_harm_event"));
            c.insert("cassette_version", req(row, "cassette_version")?);
            for key in ["harmed_decision", "harm_kind", "subject", "discovered_at"] {
                c.insert(key, mget(d, key));
            }
            c.insert("finding", req(row, "decision_output")?);
            c.insert("previous_hash", req(row, "previous_hash")?);
            apply_optional_ref(&mut c, row);
        }
        _ => {
            if matches!(kind_value, Some(Value::Array(_) | Value::Object(_))) {
                return Err(RecomputeError::UnhashableRecordKind);
            }
            if let Some((k, fields)) = kind.and_then(|k| {
                CONTRACT_CANONICAL_FIELDS
                    .iter()
                    .find(|(name, _)| *name == k)
                    .copied()
            }) {
                let d = mapping(row, "data")?;
                c.insert("record_kind", s(k));
                c.insert("cassette_version", req(row, "cassette_version")?);
                for key in fields {
                    c.insert(key, mget(d, key));
                }
                if CONTRACT_KINDS_WITH_FINDING.contains(&k) {
                    c.insert("finding", req(row, "decision_output")?);
                }
                c.insert("previous_hash", req(row, "previous_hash")?);
                apply_optional_ref(&mut c, row);
            } else {
                canonical_form_rest(row, kind, &mut c)?;
            }
        }
    }
    Ok(c)
}

fn canonical_form_rest<'a>(row: &'a Object, kind: Option<&str>, c: &mut CanonRef<'a>) -> Result<(), RecomputeError> {
    match kind {
        Some("decision_supersession") => {
            c.insert("record_kind", s("decision_supersession"));
            c.insert("supersedes_id", req(row, "supersedes_id")?);
            c.insert("cassette_version", req(row, "cassette_version")?);
            c.insert("authority", req(row, "authorized_by")?);
            c.insert("reason", req(row, "reason")?);
            c.insert("corrected_output", req(row, "decision_output")?);
            c.insert("previous_hash", req(row, "previous_hash")?);
            apply_optional_ref(c, row);
        }
        Some("recommendation_shadow_run") => {
            let d = mapping(row, "data")?;
            c.insert("record_kind", s("recommendation_shadow_run"));
            c.insert("cassette_version", req(row, "cassette_version")?);
            c.insert("recommendation_kind", mget(d, "recommendation_kind"));
            c.insert("subject", mget(d, "subject"));
            c.insert("inputs", req(row, "input_data")?);
            c.insert("recommendation", req(row, "decision_output")?);
            c.insert("previous_hash", req(row, "previous_hash")?);
            apply_optional_ref(c, row);
        }
        Some("recommendation_shadow_score") => {
            c.insert("record_kind", s("recommendation_shadow_score"));
            c.insert("actual", req(row, "input_data")?);
            c.insert("score", req(row, "decision_output")?);
            c.insert("previous_hash", req(row, "previous_hash")?);
            apply_optional_ref(c, row);
        }
        Some("human_selection") => {
            let d = mapping(row, "data")?;
            c.insert("record_kind", s("human_selection"));
            c.insert("cassette_version", req(row, "cassette_version")?);
            c.insert("human_selection", mget(d, "human_selection"));
            c.insert("rationale", mget(d, "rationale"));
            c.insert("recommendation_shown", req(row, "decision_output")?);
            c.insert("previous_hash", req(row, "previous_hash")?);
            apply_optional_ref(c, row);
        }
        Some("observed_event") => {
            // Fixed form, no optional fields (canonical_fields.observed_event_canonical).
            let previous_hash = req(row, "previous_hash")?;
            let body = mapping(row, "input_data")?;
            c.insert("record_kind", s("observed_event"));
            for key in OBSERVED_EVENT_CANONICAL_FIELDS {
                c.insert(key, mget(body, key));
            }
            c.insert("previous_hash", previous_hash);
        }
        Some(ATTESTATION_POLICY_RECORD_KIND) => {
            // Fixed form (canonical_fields.attestation_policy_canonical).
            let body = mapping(row, "data")?;
            let previous_hash = req(row, "previous_hash")?;
            c.insert("record_kind", s(ATTESTATION_POLICY_RECORD_KIND));
            for key in ATTESTATION_POLICY_CANONICAL_FIELDS {
                c.insert(key, mget(body, key));
            }
            c.insert("reason", opt(row, "reason"));
            c.insert("previous_hash", previous_hash);
        }
        _ => {
            // Base rows from ledger_postgres.append(): no record-kind key,
            // no optional fields.
            for col in [
                "action_type",
                "node",
                "previous_value",
                "applied_value",
                "reason",
                "data",
                "previous_hash",
            ] {
                c.insert(col, req(row, col)?);
            }
        }
    }
    Ok(())
}

/// SHA-256 over whatever is written to it, keeping only the hash state.
#[derive(Debug, Clone, Default)]
pub(crate) struct Sha256Sink {
    pub(crate) hasher: Sha256,
    pub(crate) len: usize,
}

impl Sink for Sha256Sink {
    fn put(&mut self, s: &str) {
        self.hasher.update(s.as_bytes());
        self.len = self.len.saturating_add(s.len());
    }
}

impl Sha256Sink {
    pub(crate) fn hex(self) -> String {
        hex::encode(self.hasher.finalize())
    }
}

fn hash_canon(c: &CanonRef<'_>, skip: Option<&str>) -> String {
    let mut sink = Sha256Sink::default();
    write_entries(
        &mut sink,
        c.iter().filter(|(k, _)| skip != Some(**k)).map(|(k, v)| (*k, v.as_ref())),
        Separators::Python,
    );
    sink.hex()
}

/// The row hash of a borrowed canonical form, streamed into SHA-256.
pub(crate) fn ledger_hash_ref(c: &CanonRef<'_>) -> String {
    hash_canon(c, None)
}

/// [`content_prehash`] of a borrowed canonical form.
pub(crate) fn content_prehash_ref(c: &CanonRef<'_>) -> String {
    hash_canon(c, Some(SIGNATURE_FIELD))
}

/// The bytes the ledger hashes: `json.dumps(obj, sort_keys=True, default=str).encode()`.
pub fn ledger_bytes(canonical: &Object) -> Vec<u8> {
    crate::pyjson::dumps_object(canonical, Separators::Python, None).into_bytes()
}

/// Full SHA-256 hex of `bytes`.
pub fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

/// `twin_custody.recompute_current_hash(row)`.
pub fn recompute_current_hash(row: &Object) -> Result<String, RecomputeError> {
    Ok(ledger_hash_ref(&canonical_form_ref(row)?))
}

/// `authorized_by_attestation.content_prehash(canonical)`: the hash of the
/// canonical form with the signature field removed, which an `abv3`
/// signature covers.
pub fn content_prehash(canonical: &Object) -> String {
    let mut sink = Sha256Sink::default();
    write_entries(
        &mut sink,
        canonical
            .iter()
            .filter(|(k, _)| k.as_str() != SIGNATURE_FIELD)
            .map(|(k, v)| (k.as_str(), v)),
        Separators::Python,
    );
    sink.hex()
}

/// Every column `twin_custody.SHIPPED_COLUMNS` lists, in its order: the
/// closed set of names [`hashed_columns`] and the report draw from.
pub const SHIPPED_COLUMNS: [&str; 31] = [
    "id",
    "timestamp",
    "action_type",
    "node",
    "previous_value",
    "applied_value",
    "reason",
    "previous_hash",
    "current_hash",
    "data",
    "record_kind",
    "cassette_version",
    "input_data",
    "policy_parameters",
    "decision_output",
    "cassette_snapshot",
    "cassette_hash",
    "call_sid",
    "cassette_code_hash",
    "model_identity",
    "authorized_by",
    "supersedes_id",
    "supersedes_hash",
    "replaces_hash",
    "outcome_obligation",
    "ai_cost",
    "shadow_run_hash",
    "decision_hash",
    "authorized_by_sig",
    "subject_digest",
    "shuffle_seed",
];

const BASE_COLUMNS: &[&str] = &[
    "action_type",
    "node",
    "previous_value",
    "applied_value",
    "reason",
    "data",
    "previous_hash",
];

/// The row columns a row's canonical form reads, by its record kind, and
/// whether `OPTIONAL_HASHED_FIELDS` join it when present and truthy. A
/// column read as a mapping (`data`, and `input_data` for an observed
/// event) counts as read even when only some of its keys are hashed.
/// `current_hash` is the hash itself and is never in the list.
pub fn hashed_columns(row: &Object) -> (&'static [&'static str], bool) {
    match row.get("record_kind").and_then(Value::as_str) {
        Some("governance_decision") => (
            &[
                "record_kind",
                "data",
                "action_type",
                "node",
                "cassette_version",
                "input_data",
                "policy_parameters",
                "reason",
                "decision_output",
                "previous_value",
                "applied_value",
                "previous_hash",
            ],
            true,
        ),
        Some("cassette_binding") => (&["record_kind", "cassette_version", "previous_hash"], true),
        Some("regulatory_cassette_inserted" | "regulatory_cassette_removed") => {
            (&["record_kind", "data", "cassette_version", "previous_hash"], true)
        }
        Some("regulatory_disclosure" | "outcome_harm_event" | "human_selection" | "contract_egress") => (
            &["record_kind", "data", "cassette_version", "decision_output", "previous_hash"],
            true,
        ),
        Some("contract_ingest" | "contract_approval" | "contract_deletion") => {
            (&["record_kind", "data", "cassette_version", "previous_hash"], true)
        }
        Some("decision_supersession") => (
            &[
                "record_kind",
                "supersedes_id",
                "cassette_version",
                "authorized_by",
                "reason",
                "decision_output",
                "previous_hash",
            ],
            true,
        ),
        Some("recommendation_shadow_run") => (
            &[
                "record_kind",
                "data",
                "cassette_version",
                "input_data",
                "decision_output",
                "previous_hash",
            ],
            true,
        ),
        Some("recommendation_shadow_score") => {
            (&["record_kind", "input_data", "decision_output", "previous_hash"], true)
        }
        Some("observed_event") => (&["record_kind", "input_data", "previous_hash"], false),
        Some(ATTESTATION_POLICY_RECORD_KIND) => (&["record_kind", "data", "reason", "previous_hash"], false),
        _ => (BASE_COLUMNS, false),
    }
}

/// Whether `col` on `row` enters the row's hash: read by its kind's
/// canonical form, or an optional hashed field present with a truthy value.
/// An optional field that is present but falsy (null, empty) counts as
/// covered, because the hash treats it exactly like an absent one.
pub fn column_is_hashed(row: &Object, col: &str) -> bool {
    if col == "current_hash" {
        return true;
    }
    let (read, optional) = hashed_columns(row);
    if read.contains(&col) {
        return true;
    }
    if OPTIONAL_HASHED_FIELDS.contains(&col) {
        let truthy = row.get(col).is_some_and(Value::is_truthy);
        return optional || !truthy;
    }
    false
}
