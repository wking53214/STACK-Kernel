//! The chain walk and the offline verifier.
//!
//! Reproduces `twin_custody.deep_verify_row`, `twin_custody.verify_rows`
//! and `tools/verify_receipts.py` (`load_export`, `verify`, `main`).

use std::time::Instant;

use crate::anchor::{anchor_summary, check_head_anchor_with, parse_head_anchor, HeadAnchor};
use crate::attest::{keyed_work_bytes, verify_seed, verify_signature, AttestationStatus, KeySet};
use crate::canonical::{
    canonical_form_ref, content_prehash_ref, hashed_columns, ledger_hash_ref, sha256_hex, Sha256Sink,
    ATTESTATION_POLICY_RECORD_KIND, OPTIONAL_HASHED_FIELDS, SHIPPED_COLUMNS, SIGNATURE_FIELD,
};
use crate::cns::subject_digest;
use crate::config::VerifierConfig;
use crate::error::VerifyError;
use crate::pyjson::{parse_object_keeping, write_value, Object, Separators, Value};
use crate::telemetry;
use crate::verdict::{Finding, GateOutcome, Reason, Report};

/// `verify_receipts.EXPORT_FORMAT`.
pub const EXPORT_FORMAT: &str = "sentinel_os.ledger_export.v1";

/// The literal `previous_hash` of the first row.
pub const GENESIS: &str = "genesis";

/// One exported row: its integer `id` and every shipped column.
#[derive(Debug, Clone, PartialEq)]
pub struct LedgerRow {
    /// The row's `id` column.
    pub id: i64,
    /// Every column in the export, `id` included.
    pub columns: Object,
}

fn is_hex64(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

fn is_hex16(s: &str) -> bool {
    s.len() == 16 && s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

/// A stored value, described for a report or a log without copying raw
/// input: a full 64-hex hash, a 16-hex key fingerprint and the literal
/// `genesis` are shown as they are (none can carry anything else); any
/// other value is shown as its type, length and full SHA-256. The hash is
/// computed by streaming, so describing a large value copies nothing.
pub fn describe(v: Option<&Value>) -> String {
    match v {
        None => "an absent value".to_owned(),
        Some(Value::Null) => "null".to_owned(),
        Some(Value::Str(s)) => describe_str(s),
        Some(other) => {
            let mut sink = Sha256Sink::default();
            write_value(&mut sink, other, Separators::Python);
            let len = sink.len;
            format!("a {} of {} bytes with sha256 {}", other.type_name(), len, sink.hex())
        }
    }
}

/// [`describe`] of a string.
pub fn describe_str(s: &str) -> String {
    if is_hex64(s) || is_hex16(s) || s == GENESIS {
        s.to_owned()
    } else {
        format!("a str of {} bytes with sha256 {}", s.len(), sha256_hex(s.as_bytes()))
    }
}

const NULL: Value = Value::Null;

fn get<'a>(row: &'a Object, col: &str) -> &'a Value {
    row.get(col).unwrap_or(&NULL)
}

/// `twin_custody.deep_verify_row(row, keys)` with the default
/// [`VerifierConfig`] (see [`deep_verify_row_with`]).
pub fn deep_verify_row(row: &LedgerRow, keys: &KeySet) -> Result<(), (Reason, String)> {
    deep_verify_row_with(row, keys, &VerifierConfig::default())
}

/// `twin_custody.deep_verify_row(row, keys)`: `Ok` when the row's hash, its
/// subject binding, any seed and any signature hold. Checks run in the
/// Python order, so the finding names the attack rather than its
/// consequence: hash, then subject binding, then seed, then signature.
///
/// One departure from `twin_custody`: a signature valid only under a
/// retired key is `signature_retired_key` unless
/// `config.accept_retired_key_signatures` is set (see [`VerifierConfig`]).
pub fn deep_verify_row_with(row: &LedgerRow, keys: &KeySet, config: &VerifierConfig) -> Result<(), (Reason, String)> {
    let canonical = verify_row_content(row)?;
    verify_row_keyed(row, &canonical, keys, config)
}

/// The checks of [`deep_verify_row_with`] that need no key: the canonical
/// form, the row hash and the subject binding. Their answer depends on the
/// export alone.
fn verify_row_content(row: &LedgerRow) -> Result<crate::canonical::CanonRef<'_>, (Reason, String)> {
    let cols = &row.columns;
    let canonical = canonical_form_ref(cols).map_err(|e| (Reason::RecomputeFailed, format!("recompute failed: {e}")))?;
    let recomputed = ledger_hash_ref(&canonical);
    let stored = cols.get("current_hash");
    if stored.and_then(Value::as_str) != Some(recomputed.as_str()) {
        return Err((
            Reason::HashMismatch,
            format!(
                "hash mismatch: recomputed {recomputed} but the row stores {}",
                describe(stored)
            ),
        ));
    }

    let stored_digest = cols.get("subject_digest");
    if stored_digest.is_some_and(Value::is_truthy) {
        let empty = Value::Object(Object::new());
        let input = cols.get("input_data").filter(|v| v.is_truthy()).unwrap_or(&empty);
        match subject_digest(input) {
            Err(e) => {
                return Err((
                    Reason::SubjectNotEncodable,
                    format!("stored input_data is not canonically encodable ({e})"),
                ))
            }
            Ok(expected) => {
                if stored_digest.and_then(Value::as_str) != Some(expected.as_str()) {
                    return Err((
                        Reason::SubjectDigestMismatch,
                        format!(
                            "subject_digest {} was not issued for this row's input_data (recomputed {expected})",
                            describe(stored_digest)
                        ),
                    ));
                }
            }
        }
    }
    Ok(canonical)
}

/// The keyed checks of [`deep_verify_row_with`]: the seed, then the
/// signature.
fn verify_row_keyed(
    row: &LedgerRow,
    canonical: &crate::canonical::CanonRef<'_>,
    keys: &KeySet,
    config: &VerifierConfig,
) -> Result<(), (Reason, String)> {
    let cols = &row.columns;
    match verify_seed(cols, keys) {
        AttestationStatus::Absent | AttestationStatus::Ok => {}
        AttestationStatus::RetiredKey => {
            return Err((
                Reason::SeedRetiredKey,
                "shuffle_seed re-derives only under a retired key".to_owned(),
            ))
        }
        AttestationStatus::Unverifiable => {
            return Err((
                Reason::SeedUnverifiable,
                "the row carries a shuffle_seed but no attestation key is held to re-derive it".to_owned(),
            ))
        }
        _ => {
            return Err((
                Reason::SeedNotDerived,
                "shuffle_seed does not re-derive from the previous hash and record kind under any held key: \
                 the order was not fixed by the server"
                    .to_owned(),
            ))
        }
    }

    if cols.get(SIGNATURE_FIELD).is_some_and(Value::is_truthy) {
        let check = verify_signature(cols, keys, &content_prehash_ref(canonical));
        let named = check.named_fingerprint;
        match check.status {
            AttestationStatus::Invalid => {
                let under = named.map_or_else(|| "any held key".to_owned(), |fp| format!("key {fp}"));
                return Err((
                    Reason::SignatureInvalid,
                    format!("attestation invalid: signature does not match a fresh HMAC under {under}"),
                ));
            }
            AttestationStatus::UnknownKey => {
                let fp = named.unwrap_or_else(|| "an unnamed key".to_owned());
                return Err((
                    Reason::SignatureUnknownKey,
                    format!("signed by key {fp}, which this verifier holds as neither a trusted nor a retired key"),
                ));
            }
            AttestationStatus::RetiredKey if !config.accept_retired_key_signatures => {
                let under = named.map_or_else(|| "a held key".to_owned(), |fp| format!("key {fp}"));
                return Err((
                    Reason::SignatureRetiredKey,
                    format!("signature is valid only under {under}, which the auditor has retired"),
                ));
            }
            AttestationStatus::Unverifiable => {
                return Err((
                    Reason::SignatureUnverifiable,
                    "signature present but no key is held to check it".to_owned(),
                ))
            }
            _ => {}
        }
    }
    Ok(())
}

/// Result of walking a chain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChainWalk {
    /// The first failing row, or `None` when every row holds.
    pub finding: Option<Finding>,
    /// When the first finding is only RETRY, the first later row that fails
    /// with TERMINAL_BREACH, if any (see [`Report::escalation`]).
    pub escalation: Option<Finding>,
    /// Rows examined, including the failing ones.
    pub rows_checked: usize,
}

/// The first attestation_policy marker passed so far: its row id and the
/// key fingerprint it enforces.
struct Policy<'a> {
    since: i64,
    key_fingerprint: Option<&'a str>,
}

impl Policy<'_> {
    /// Whether the verifier holds, as trusted, the key this policy enforces.
    fn enforced_key_held(&self, keys: &KeySet) -> bool {
        self.key_fingerprint.is_some_and(|fp| keys.trusted_key(fp).is_some())
    }
}

/// How much of a row [`check_row`] judges.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Checks {
    /// Every check, in the Python order.
    All,
    /// Only the checks whose answer depends on the export alone: the link,
    /// the hash, the subject binding and an unsigned claim after the policy
    /// marker. Used after a RETRY finding when the verifier does not hold
    /// the enforced key, because then a seed or legacy signature that fails
    /// under the held keys may only mean the auditor holds the wrong key.
    ExportOnly,
}

fn check_row(
    row: &LedgerRow,
    prev: &Value,
    policy: Option<&Policy<'_>>,
    keys: &KeySet,
    config: &VerifierConfig,
    checks: Checks,
) -> Option<(Reason, String)> {
    let cols = &row.columns;
    let link = get(cols, "previous_hash");
    if link != prev {
        return Some((
            Reason::ChainBroken,
            format!(
                "chain broken: previous_hash {} does not link to {}",
                describe(Some(link)),
                describe(Some(prev))
            ),
        ));
    }
    let verified = verify_row_content(row).and_then(|canonical| match checks {
        Checks::All => verify_row_keyed(row, &canonical, keys, config),
        Checks::ExportOnly => Ok(()),
    });
    if let Err((reason, detail)) = verified {
        // A fingerprint is text the row's writer chose. When the auditor
        // already holds the key the policy enforces, a signature naming any
        // other key cannot be repaired by supplying a key.
        let enforced_key_held = policy.is_some_and(|p| p.enforced_key_held(keys));
        if reason == Reason::SignatureUnknownKey && enforced_key_held {
            return Some((
                Reason::SignatureUnknownKeyAfterPolicy,
                format!("{detail}; attestation is enforced under a key this verifier holds"),
            ));
        }
        return Some((reason, detail));
    }
    if let Some(p) = policy {
        let claim = get(cols, "authorized_by");
        if claim.is_truthy() && !get(cols, SIGNATURE_FIELD).is_truthy() {
            return Some((
                Reason::UnsignedAfterPolicy,
                format!(
                    "authorized_by claim ({}) carries no signature; attestation has been enforced since row {}",
                    describe(Some(claim)),
                    p.since
                ),
            ));
        }
    }
    None
}

/// `twin_custody.verify_rows(rows, keys)` with the default
/// [`VerifierConfig`] (see [`verify_rows_with`]).
pub fn verify_rows(rows: &[LedgerRow], keys: &KeySet) -> ChainWalk {
    verify_rows_with(rows, keys, &VerifierConfig::default())
}

/// `twin_custody.verify_rows(rows, keys)` over rows already in id order.
///
/// Per row: the link to the previous row (`TAMPERED`), then
/// [`deep_verify_row_with`], then, once an `attestation_policy` marker has
/// been passed, an `authorized_by` claim with no signature (`UNATTESTED`).
/// Rows before the first marker are not judged for missing signatures.
///
/// The Python walk stops at the first failing row. This one stops there
/// only when that finding is TERMINAL_BREACH. After a RETRY finding it keeps
/// checking every later row, all of them bounded by `max_rows`, and reports
/// the first TERMINAL_BREACH it finds as [`ChainWalk::escalation`], so a
/// repairable finding on an early row cannot hide tampering further down.
///
/// Which later checks can escalate depends on the keys. The link, the hash,
/// the subject binding and an unsigned claim after the policy marker depend
/// on the export alone and always count. The seed and signature checks count
/// only on rows after an `attestation_policy` marker whose enforced key the
/// verifier holds as trusted: without that key, a seed that does not
/// re-derive may only mean the auditor supplied the wrong key, which is the
/// RETRY the first finding already reports.
pub fn verify_rows_with(rows: &[LedgerRow], keys: &KeySet, config: &VerifierConfig) -> ChainWalk {
    let _span = tracing::info_span!("tack.sentinel.verify_rows", rows = rows.len()).entered();
    let genesis = Value::Str(GENESIS.to_owned());
    let mut prev: &Value = &genesis;
    let mut policy: Option<Policy<'_>> = None;
    let mut first: Option<Finding> = None;
    let mut escalation: Option<Finding> = None;
    let mut rows_checked = 0;
    for (pos, row) in rows.iter().enumerate() {
        rows_checked = pos + 1;
        let checks = match (&first, &policy) {
            (None, _) => Checks::All,
            (Some(_), Some(p)) if p.enforced_key_held(keys) => Checks::All,
            (Some(_), _) => Checks::ExportOnly,
        };
        if let Some((reason, detail)) = check_row(row, prev, policy.as_ref(), keys, config, checks) {
            let terminal = reason.gate_outcome() == GateOutcome::TerminalBreach;
            let finding = Finding {
                reason,
                row_id: Some(row.id),
                row_position: Some(pos),
                detail,
            };
            if first.is_none() {
                first = Some(finding);
                if terminal {
                    break;
                }
            } else if terminal {
                escalation = Some(finding);
                break;
            }
        }
        let cols = &row.columns;
        if policy.is_none() && cols.get("record_kind").and_then(Value::as_str) == Some(ATTESTATION_POLICY_RECORD_KIND) {
            policy = Some(Policy {
                since: row.id,
                key_fingerprint: cols
                    .get("data")
                    .and_then(Value::as_object)
                    .and_then(|d| d.get("key_fingerprint"))
                    .and_then(Value::as_str),
            });
        }
        prev = get(cols, "current_hash");
    }
    ChainWalk {
        finding: first,
        escalation,
        rows_checked,
    }
}

/// Which [`SHIPPED_COLUMNS`] some row carried outside its hashed form, and
/// whether some row carried a column outside that list altogether.
fn unhashed_columns(rows: &[LedgerRow]) -> (Vec<&'static str>, bool) {
    let mut seen = [false; SHIPPED_COLUMNS.len()];
    let mut other = false;
    for row in rows {
        let (read, optional) = hashed_columns(&row.columns);
        for (col, v) in &row.columns {
            let col = col.as_str();
            if col == "current_hash" || read.contains(&col) {
                continue;
            }
            // A falsy optional field is hashed exactly like an absent one.
            if OPTIONAL_HASHED_FIELDS.contains(&col) && (optional || !v.is_truthy()) {
                continue;
            }
            match SHIPPED_COLUMNS.iter().position(|c| *c == col) {
                Some(i) => seen[i] = true,
                None => other = true,
            }
        }
    }
    let names = SHIPPED_COLUMNS
        .iter()
        .zip(seen)
        .filter(|(_, s)| *s)
        .map(|(c, _)| *c)
        .collect();
    (names, other)
}

/// `verify_receipts.load_export`: parse, check the format, and return the
/// rows sorted by `id` (a stable sort, as Python's `sorted` is). Reordering
/// the rows array therefore changes nothing; changing ids does.
///
/// Only the `format` and `rows` members are built; every other top-level
/// member (`columns`, and anything an attacker adds) is checked for syntax
/// and then discarded without being built, so it costs no memory. The
/// parse runs under the allocation budget in `config.json`.
pub fn parse_export(bytes: &[u8], config: &VerifierConfig) -> Result<Vec<LedgerRow>, VerifyError> {
    let _span = tracing::info_span!("tack.sentinel.parse_export", export_len = bytes.len()).entered();
    if bytes.len() > config.max_export_bytes {
        return Err(VerifyError::ExportTooLarge {
            len: bytes.len(),
            max: config.max_export_bytes,
        });
    }
    let root = parse_object_keeping(bytes, config.json, &["format", "rows"]).map_err(VerifyError::ExportNotJson)?;
    let Some(mut top) = root else {
        return Err(VerifyError::NotAnExport);
    };
    if top.get("format").and_then(Value::as_str) != Some(EXPORT_FORMAT) {
        return Err(VerifyError::NotAnExport);
    }
    let Some(Value::Array(raw_rows)) = top.remove("rows") else {
        return Err(VerifyError::RowsMissing);
    };
    if raw_rows.len() > config.max_rows {
        return Err(VerifyError::TooManyRows {
            len: raw_rows.len(),
            max: config.max_rows,
        });
    }
    let mut rows = Vec::with_capacity(raw_rows.len());
    for (position, raw) in raw_rows.into_iter().enumerate() {
        let Value::Object(columns) = raw else {
            return Err(VerifyError::RowNotAnObject { position });
        };
        let id = match columns.get("id") {
            Some(Value::Int(i)) => i.to_i64().ok_or(VerifyError::RowIdInvalid { position })?,
            _ => return Err(VerifyError::RowIdInvalid { position }),
        };
        rows.push(LedgerRow { id, columns });
    }
    rows.sort_by_key(|r| r.id);
    Ok(rows)
}

/// The offline verifier: a key set the auditor trusts and the caps.
#[derive(Debug, Clone)]
pub struct Verifier {
    config: VerifierConfig,
    keys: KeySet,
}

impl Verifier {
    /// A verifier over `keys`. Refuses a key set with no trusted key (one
    /// that holds only retired keys included), as the Python tool refuses to
    /// run with no trusted key material: every signature and the anchor are
    /// HMACs, and a verdict it could not check is not printed.
    pub fn new(config: VerifierConfig, keys: KeySet) -> Result<Self, VerifyError> {
        if keys.trusted_len() == 0 {
            let err = VerifyError::NoTrustedKeyMaterial;
            telemetry::record_rejected(&err, None);
            tracing::warn!(reason = err.label(), "tack.sentinel refused to build a verifier with no trusted key");
            return Err(err);
        }
        Ok(Verifier { config, keys })
    }

    /// The caps in force.
    pub fn config(&self) -> &VerifierConfig {
        &self.config
    }

    /// Verify one export against its anchor, as `verify_receipts.py` does.
    ///
    /// `anchor` is the anchor file's bytes, or `None` when there is none;
    /// a missing or unreadable anchor is `TRUNCATED` with no row checked,
    /// exactly as the Python prints `TRUNCATED row=-` when
    /// `read_head_anchor` fails. `Err` means no verdict could be reached
    /// (see [`VerifyError`]). An export over `max_export_bytes` is refused
    /// by its length alone: it is not hashed, and its span and log record
    /// only its length.
    pub fn verify_export(&self, export: &[u8], anchor: Option<&[u8]>) -> Result<Report, VerifyError> {
        let started = Instant::now();
        let span = tracing::info_span!(
            "tack.sentinel.verify_export",
            export_len = export.len(),
            export_sha256 = tracing::field::Empty,
            anchor_len = anchor.map(<[u8]>::len),
            anchor_entries = tracing::field::Empty,
            anchor_sealed_at = tracing::field::Empty,
            anchor_key_fingerprint = tracing::field::Empty,
            verdict = tracing::field::Empty,
            outcome = tracing::field::Empty,
        );
        let _entered = span.enter();
        let result = if export.len() > self.config.max_export_bytes {
            Err(VerifyError::ExportTooLarge {
                len: export.len(),
                max: self.config.max_export_bytes,
            })
        } else {
            let export_sha256 = sha256_hex(export);
            span.record("export_sha256", export_sha256.as_str());
            self.verify_inner(export, anchor, export_sha256)
        };
        match &result {
            Ok(report) => {
                span.record("verdict", report.verdict().as_str());
                span.record("outcome", report.gate_outcome().as_str());
                if let Some(a) = &report.anchor {
                    span.record("anchor_entries", a.entries.as_str());
                    span.record("anchor_sealed_at", a.sealed_at.as_str());
                    span.record("anchor_key_fingerprint", a.key_fingerprint.as_str());
                }
                let roles = [
                    ("first", &report.finding),
                    ("also", &report.also),
                    ("escalation", &report.escalation),
                ];
                for (role, found) in roles {
                    if let Some(f) = found {
                        tracing::warn!(
                            finding = role,
                            verdict = f.verdict().as_str(),
                            reason = f.reason.label(),
                            outcome = f.reason.gate_outcome().as_str(),
                            resolution = f.reason.resolution().as_str(),
                            row_id = f.row_id,
                            row_position = f.row_position,
                            "tack.sentinel export failed verification"
                        );
                    }
                }
                telemetry::record_report(report, started.elapsed());
            }
            Err(err) => {
                span.record("outcome", err.gate_outcome().as_str());
                tracing::warn!(reason = err.label(), outcome = err.gate_outcome().as_str(), "tack.sentinel export refused");
                telemetry::record_rejected(err, Some(started.elapsed()));
            }
        }
        result
    }

    fn verify_inner(&self, export: &[u8], anchor: Option<&[u8]>, export_sha256: String) -> Result<Report, VerifyError> {
        let rows = parse_export(export, &self.config)?;
        let rows_total = rows.len();
        let (unhashed, other_unhashed) = unhashed_columns(&rows);
        let report = |finding, also, escalation, rows_checked, anchor| Report {
            finding,
            also,
            escalation,
            rows_checked,
            rows_total,
            export_sha256: export_sha256.clone(),
            anchor,
            unhashed_columns: unhashed.clone(),
            other_unhashed_columns: other_unhashed,
        };
        let early = |reason, detail: String| {
            let f = Finding {
                reason,
                row_id: None,
                row_position: None,
                detail,
            };
            report(Some(f), None, None, 0, None)
        };
        let parsed: HeadAnchor = match anchor {
            None => return Ok(early(Reason::AnchorMissing, "no head anchor was supplied".to_owned())),
            Some(bytes) => {
                let s = tracing::info_span!(
                    "tack.sentinel.parse_anchor",
                    anchor_len = bytes.len(),
                    anchor_sha256 = tracing::field::Empty
                )
                .entered();
                // An anchor over the cap is refused by its length alone; it
                // is hashed for the log only once it is known to be small.
                if bytes.len() <= self.config.max_anchor_bytes {
                    s.record("anchor_sha256", sha256_hex(bytes).as_str());
                }
                match parse_head_anchor(bytes, self.config.max_anchor_bytes, self.config.json) {
                    Ok(a) => a,
                    Err(e) => return Ok(early(Reason::AnchorUnreadable, format!("anchor cannot be read: {e}"))),
                }
            }
        };
        let needed = rows
            .iter()
            .fold(0usize, |acc, r| acc.saturating_add(keyed_work_bytes(&r.columns, &self.keys)));
        if needed > self.config.max_keyed_bytes {
            return Err(VerifyError::KeyedWorkOverBudget {
                needed,
                max: self.config.max_keyed_bytes,
            });
        }
        let walk = verify_rows_with(&rows, &self.keys, &self.config);
        let anchored = {
            let _s = tracing::info_span!("tack.sentinel.check_anchor").entered();
            check_head_anchor_with(&rows, &parsed, &self.keys, &self.config)
        };
        let vouched = !anchored.as_ref().is_some_and(|f| {
            matches!(
                f.reason,
                Reason::AnchorInvalid | Reason::AnchorUnknownKey | Reason::AnchorUnverifiable | Reason::AnchorRetiredKey
            )
        });
        let summary = Some(anchor_summary(&parsed, vouched));
        let (finding, also) = match (walk.finding, anchored) {
            (Some(row), anchor_finding) => (Some(row), anchor_finding),
            (None, anchor_finding) => (anchor_finding, None),
        };
        Ok(report(finding, also, walk.escalation, walk.rows_checked, summary))
    }
}
