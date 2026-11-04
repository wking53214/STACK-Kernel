//! What a verdict covers, as a stable, machine-readable record.
//!
//! A bare `VERIFIED` is easy to over-read. It means the hashed columns of
//! every checked row chain correctly from `"genesis"`, and that whatever
//! anchor and signature checks ran passed. It does not mean every stored
//! column is intact (unhashed columns can change freely), it does not mean
//! the original action was legitimate, and it says nothing about whether
//! anything was executed. [`ScopedReport::to_json`] states that scope next to
//! the verdict, schema `sentinel-scope/1`, so a consumer can act on it.
//!
//! Every string in the record comes from a closed set in this crate or is a
//! value already safe to log in a [`Report`] (a full hash, a 16-hex key
//! fingerprint, an ISO-8601 time, decimal digits, or a described value). No
//! raw export content and no attacker-chosen column name is ever written.
//! See `SCOPE.md` beside this crate for the schema and how to consume it.

use std::collections::BTreeSet;

use crate::canonical::{
    hashed_columns, hashed_mapping_keys, record_kind_label, OPTIONAL_HASHED_FIELDS, RECORD_KIND_LABELS, SHIPPED_COLUMNS,
};
use crate::pyjson::{dumps, Object, PyInt, Separators, Value};
use crate::verdict::{Finding, Report};
use crate::verify::LedgerRow;

/// The schema identifier written in every scope record.
pub const SCOPE_SCHEMA: &str = "sentinel-scope/1";

/// The one integrity claim a verdict makes, written in every scope record.
pub const INTEGRITY_CLAIM: &str = "hash chain over hashed columns only";

/// A stable code for something a verdict does not establish. Computed from
/// the export, the anchor and the result; a consumer must handle every code
/// it receives and treat an unknown code as a reason not to rely on the
/// verdict.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Limitation {
    /// Some row carried a column (or part of one) outside its hashed form;
    /// its value is not covered by any verdict.
    UnhashedColumnsPresent,
    /// Some rows lie beyond what a vouched anchor seals (or no anchor
    /// vouched at all). Those rows are covered only by the unkeyed chain,
    /// which anyone able to write the file can recompute.
    RowsAfterLastAnchorUnkeyed,
    /// An anchor vouched. The verifier cannot tell whether it is the latest
    /// anchor: an older genuine anchor verifies a chain cut back to its count.
    AnchorStalePossible,
    /// No anchor vouched: it was missing, unreadable, or its HMAC did not
    /// verify under a key the verifier accepts.
    AnchorNotVerified,
    /// The walk stopped before the last row.
    PartialRowsChecked,
    /// The ledger records decisions, not their execution. Nothing in the
    /// export shows that any decision was carried out. Always present.
    NoExecutionRecord,
}

impl Limitation {
    /// The stable code.
    pub fn as_str(self) -> &'static str {
        match self {
            Limitation::UnhashedColumnsPresent => "unhashed_columns_present",
            Limitation::RowsAfterLastAnchorUnkeyed => "rows_after_last_anchor_unkeyed",
            Limitation::AnchorStalePossible => "anchor_stale_possible",
            Limitation::AnchorNotVerified => "anchor_not_verified",
            Limitation::PartialRowsChecked => "partial_rows_checked",
            Limitation::NoExecutionRecord => "no_execution_record",
        }
    }

    /// Every code, in the order a record lists them.
    pub const ALL: [Limitation; 6] = [
        Limitation::UnhashedColumnsPresent,
        Limitation::RowsAfterLastAnchorUnkeyed,
        Limitation::AnchorStalePossible,
        Limitation::AnchorNotVerified,
        Limitation::PartialRowsChecked,
        Limitation::NoExecutionRecord,
    ];
}

/// The hashed and unhashed columns of the rows of one record kind.
///
/// A column path is a [`SHIPPED_COLUMNS`] name (the whole value is or is
/// not hashed), `<column>.<key>` for a named key of a mapping column that
/// the kind hashes (see [`crate::canonical::hashed_mapping_keys`]), or
/// `<column>.*` in the unhashed list for "keys of this mapping other than
/// the hashed ones". Key names in paths come from this crate's constants,
/// never from the export.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KindScope {
    /// A [`RECORD_KIND_LABELS`] entry (`base` for rows hashed by the base form).
    pub kind: &'static str,
    /// How many rows of the export have this kind.
    pub rows: usize,
    /// Column paths that enter these rows' hash, in [`SHIPPED_COLUMNS`]
    /// order, keys sorted within a column. A path is listed when the kind
    /// reads it, whether or not a row carries a value for it (an absent
    /// value hashes as null); an optional hashed field is listed when a row
    /// of the kind carries it.
    pub hashed: Vec<String>,
    /// Column paths some row of this kind carried outside its hash.
    pub unhashed: Vec<&'static str>,
}

/// What the verdict of one export covers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Scope {
    /// The union over every kind of [`KindScope::hashed`].
    pub hashed_columns: Vec<String>,
    /// The union over every kind of [`KindScope::unhashed`] (the same list
    /// as [`Report::unhashed_columns`]). A name can appear in both lists when
    /// different record kinds treat it differently; [`Scope::by_record_kind`]
    /// says which.
    pub unhashed_columns: Vec<&'static str>,
    /// Whether some row carried a column outside [`SHIPPED_COLUMNS`]. Its
    /// name is attacker-chosen text, so it is not reported.
    pub other_unhashed_columns: bool,
    /// Per record kind present in the export, in [`RECORD_KIND_LABELS`] order.
    pub by_record_kind: Vec<KindScope>,
    /// What the verdict does not establish, in [`Limitation::ALL`] order.
    pub limitations: Vec<Limitation>,
}

/// A [`Report`] with its [`Scope`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScopedReport {
    /// The report, exactly as [`crate::Verifier::verify_export`] returns it.
    pub report: Report,
    /// What its verdict covers.
    pub scope: Scope,
}

/// A column path: an index into [`SHIPPED_COLUMNS`] and a key (`""` for
/// the whole column, `"*"` for the unhashed remainder of a mapping).
type Path = (usize, &'static str);

/// The column paths of one record kind, accumulated over its rows.
#[derive(Default)]
struct Paths {
    rows: usize,
    hashed: BTreeSet<Path>,
    unhashed: BTreeSet<Path>,
}

fn path_string(p: &Path) -> String {
    let col = SHIPPED_COLUMNS[p.0];
    if p.1.is_empty() {
        col.to_owned()
    } else {
        format!("{col}.{}", p.1)
    }
}

fn unhashed_name(p: &Path) -> &'static str {
    match (SHIPPED_COLUMNS[p.0], p.1) {
        (col, "") => col,
        ("data", _) => "data.*",
        ("input_data", _) => "input_data.*",
        // Only data and input_data are ever read by key.
        _ => "other.*",
    }
}

/// Add one row's paths to `acc`. Returns whether it carried a column outside
/// [`SHIPPED_COLUMNS`].
fn add_row(acc: &mut Paths, row: &crate::pyjson::Object) -> bool {
    acc.rows += 1;
    let (read, optional) = hashed_columns(row);
    let partial = hashed_mapping_keys(row);
    for (i, col) in SHIPPED_COLUMNS.iter().enumerate() {
        let value = row.get(*col);
        if *col == "current_hash" {
            continue;
        }
        if let Some((pcol, keys)) = partial.filter(|(c, _)| c == col) {
            acc.hashed.extend(keys.iter().map(|k| (i, *k)));
            let extra = match value {
                Some(Value::Object(m)) => m.keys().any(|k| !keys.contains(&k.as_str())),
                Some(v) => v.is_truthy(),
                None => false,
            };
            if extra {
                debug_assert!(pcol == "data" || pcol == "input_data");
                acc.unhashed.insert((i, "*"));
            }
            continue;
        }
        if read.contains(col) {
            acc.hashed.insert((i, ""));
            continue;
        }
        if value.is_none() {
            continue;
        }
        if optional && OPTIONAL_HASHED_FIELDS.contains(col) {
            acc.hashed.insert((i, ""));
        } else {
            acc.unhashed.insert((i, ""));
        }
    }
    row.keys().any(|k| !SHIPPED_COLUMNS.contains(&k.as_str()))
}

/// The column scope of an export: every field of [`Scope`] but the
/// limitations.
pub(crate) fn column_scope(rows: &[LedgerRow]) -> Scope {
    let mut per_kind: Vec<Paths> = RECORD_KIND_LABELS.iter().map(|_| Paths::default()).collect();
    let mut other = false;
    for row in rows {
        let label = record_kind_label(&row.columns);
        let at = RECORD_KIND_LABELS.iter().position(|k| *k == label).unwrap_or(RECORD_KIND_LABELS.len() - 1);
        if let Some(acc) = per_kind.get_mut(at) {
            other |= add_row(acc, &row.columns);
        }
    }
    let mut hashed: BTreeSet<Path> = BTreeSet::new();
    let mut unhashed: BTreeSet<Path> = BTreeSet::new();
    let mut by_record_kind = Vec::new();
    for (kind, p) in RECORD_KIND_LABELS.iter().zip(per_kind) {
        if p.rows == 0 {
            continue;
        }
        hashed.extend(p.hashed.iter().copied());
        unhashed.extend(p.unhashed.iter().copied());
        by_record_kind.push(KindScope {
            kind,
            rows: p.rows,
            hashed: p.hashed.iter().map(path_string).collect(),
            unhashed: p.unhashed.iter().map(unhashed_name).collect(),
        });
    }
    Scope {
        hashed_columns: hashed.iter().map(path_string).collect(),
        unhashed_columns: unhashed.iter().map(unhashed_name).collect(),
        other_unhashed_columns: other,
        by_record_kind,
        limitations: Vec::new(),
    }
}

/// How many leading rows a vouched anchor seals, capped at `rows_total`.
fn anchored_rows(report: &Report) -> usize {
    match &report.anchor {
        Some(a) if a.vouched => {
            if a.entries.starts_with('-') {
                0
            } else {
                // Digits too many for usize seal more rows than any export holds.
                a.entries.parse::<usize>().unwrap_or(usize::MAX).min(report.rows_total)
            }
        }
        _ => 0,
    }
}

/// The limitation codes for `report`, computed from its data.
pub(crate) fn limitations(report: &Report, unhashed_present: bool) -> Vec<Limitation> {
    let vouched = report.anchor.as_ref().is_some_and(|a| a.vouched);
    Limitation::ALL
        .into_iter()
        .filter(|l| match l {
            Limitation::UnhashedColumnsPresent => unhashed_present,
            Limitation::RowsAfterLastAnchorUnkeyed => anchored_rows(report) < report.rows_total,
            Limitation::AnchorStalePossible => vouched,
            Limitation::AnchorNotVerified => !vouched,
            Limitation::PartialRowsChecked => report.rows_checked < report.rows_total,
            Limitation::NoExecutionRecord => true,
        })
        .collect()
}

fn int(n: usize) -> Value {
    Value::Int(PyInt::from_i64(i64::try_from(n).unwrap_or(i64::MAX)))
}

fn s(v: &str) -> Value {
    Value::Str(v.to_owned())
}

fn row(id: Option<i64>) -> Value {
    id.map_or(Value::Null, |i| Value::Int(PyInt::from_i64(i)))
}

fn finding(f: Option<&Finding>) -> Value {
    f.map_or(Value::Null, |f| {
        let mut o = Object::new();
        o.insert("reason".into(), s(f.reason.label()));
        o.insert("row".into(), row(f.row_id));
        o.insert("verdict".into(), s(f.verdict().as_str()));
        Value::Object(o)
    })
}

impl ScopedReport {
    /// The scope record as one line of JSON: compact separators, keys
    /// sorted, non-ASCII escaped. The same report always gives the same
    /// bytes. Field meanings are in `SCOPE.md`.
    pub fn to_json(&self) -> String {
        let r = &self.report;
        let sc = &self.scope;
        let mut o = Object::new();
        o.insert("schema".into(), s(SCOPE_SCHEMA));
        o.insert("verdict".into(), s(r.verdict().as_str()));
        o.insert(
            "reason".into(),
            r.finding.as_ref().map_or(Value::Null, |f| s(f.reason.label())),
        );
        o.insert("row".into(), row(r.finding.as_ref().and_then(|f| f.row_id)));
        o.insert("gate_outcome".into(), s(r.gate_outcome().as_str()));
        o.insert("integrity_claim".into(), s(INTEGRITY_CLAIM));
        o.insert("rows_checked".into(), int(r.rows_checked));
        o.insert("rows_total".into(), int(r.rows_total));
        o.insert("export_sha256".into(), s(&r.export_sha256));
        o.insert(
            "hashed_columns".into(),
            Value::Array(sc.hashed_columns.iter().map(|c| s(c)).collect()),
        );
        o.insert(
            "unhashed_columns".into(),
            Value::Array(sc.unhashed_columns.iter().map(|c| s(c)).collect()),
        );
        o.insert("other_unhashed_columns".into(), Value::Bool(sc.other_unhashed_columns));
        o.insert(
            "by_record_kind".into(),
            Value::Array(
                sc.by_record_kind
                    .iter()
                    .map(|k| {
                        let mut m = Object::new();
                        m.insert("kind".into(), s(k.kind));
                        m.insert("rows".into(), int(k.rows));
                        m.insert("hashed".into(), Value::Array(k.hashed.iter().map(|c| s(c)).collect()));
                        m.insert("unhashed".into(), Value::Array(k.unhashed.iter().map(|c| s(c)).collect()));
                        Value::Object(m)
                    })
                    .collect(),
            ),
        );
        o.insert(
            "anchor".into(),
            r.anchor.as_ref().map_or(Value::Null, |a| {
                let mut m = Object::new();
                m.insert("entries".into(), s(&a.entries));
                m.insert("sealed_at".into(), s(&a.sealed_at));
                m.insert("key_fingerprint".into(), s(&a.key_fingerprint));
                m.insert("vouched".into(), Value::Bool(a.vouched));
                Value::Object(m)
            }),
        );
        o.insert("also".into(), finding(r.also.as_ref()));
        o.insert("escalation".into(), finding(r.escalation.as_ref()));
        o.insert(
            "limitations".into(),
            Value::Array(sc.limitations.iter().map(|l| s(l.as_str())).collect()),
        );
        dumps(&Value::Object(o), Separators::Compact)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn limitation_codes_are_distinct_snake_case() {
        let mut seen = std::collections::BTreeSet::new();
        for l in Limitation::ALL {
            assert!(l.as_str().bytes().all(|b| b.is_ascii_lowercase() || b == b'_'));
            assert!(seen.insert(l.as_str()));
        }
    }
}
