//! The scope record (`sentinel-scope/1`): what a verdict covers and what it
//! does not, as stable JSON, and the CLI's `--json` flag.
//!
//! Golden files live in `tests/fixtures/scope/`. To regenerate one after an
//! intended change, run this suite with `SENTINEL_SCOPE_BLESS=1` and review
//! the diff.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use stack_sentinel::pyjson::{parse, Object, ParseLimits, Value};
use stack_sentinel::{Limitation, ScopedReport, Verdict};

const PRE: &str = "ledger_export_pre_receipts.json";
const POST: &str = "differential/base_post_receipts.json";

fn scoped(rel: &str, rows: &[Object], anchor_rows: &[Object]) -> ScopedReport {
    let cols = common::columns(rel);
    let anchor = common::anchor_bytes(anchor_rows, anchor_rows.len(), common::FIXTURE_KEY);
    common::verifier(&[common::FIXTURE_KEY])
        .verify_export_scoped(&common::export_bytes(&cols, rows), Some(&anchor))
        .unwrap()
}

fn json(s: &ScopedReport) -> Object {
    let text = s.to_json();
    assert!(!text.contains('\n'), "one line: {text}");
    match parse(text.as_bytes(), ParseLimits::default()).unwrap() {
        Value::Object(o) => o,
        _ => panic!("not an object: {text}"),
    }
}

fn strings(v: &Value) -> Vec<String> {
    match v {
        Value::Array(a) => a.iter().map(|x| x.as_str().unwrap().to_owned()).collect(),
        _ => panic!("not a list: {v:?}"),
    }
}

fn golden(name: &str, actual: &str) {
    let path = common::fixtures().join("scope").join(name);
    if std::env::var_os("SENTINEL_SCOPE_BLESS").is_some() {
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, format!("{actual}\n")).unwrap();
    }
    let expected = std::fs::read_to_string(&path).unwrap();
    assert_eq!(actual, expected.trim_end_matches('\n'), "golden {name} differs");
}

#[test]
fn golden_scope_for_the_pre_receipts_acceptance_fixture() {
    let rows = common::base_rows(PRE);
    let s = scoped(PRE, &rows, &rows);
    assert_eq!(s.report.verdict(), Verdict::Verified);
    let text = s.to_json();
    golden("pre_receipts_verified.json", &text);
    assert_eq!(s.to_json(), text, "the same report renders to the same bytes");
}

#[test]
fn scope_record_carries_the_schema_claim_and_counts() {
    let rows = common::base_rows(POST);
    let s = scoped(POST, &rows, &rows);
    let o = json(&s);
    assert_eq!(o["schema"].as_str(), Some("sentinel-scope/1"));
    assert_eq!(o["verdict"].as_str(), Some("VERIFIED"));
    assert_eq!(o["reason"], Value::Null);
    assert_eq!(o["row"], Value::Null);
    assert_eq!(o["integrity_claim"].as_str(), Some("hash chain over hashed columns only"));
    assert_eq!(o["export_sha256"].as_str(), Some(s.report.export_sha256.as_str()));
    let anchor = o["anchor"].as_object().unwrap();
    assert_eq!(anchor["entries"].as_str(), Some("16"));
    assert_eq!(anchor["vouched"], Value::Bool(true));
    let lim = strings(&o["limitations"]);
    assert!(lim.contains(&"no_execution_record".to_owned()));
    assert!(lim.contains(&"anchor_stale_possible".to_owned()));
    assert!(lim.contains(&"unhashed_columns_present".to_owned()));
    assert!(!lim.contains(&"rows_after_last_anchor_unkeyed".to_owned()), "{lim:?}");
    assert!(!lim.contains(&"partial_rows_checked".to_owned()), "{lim:?}");
    assert!(!lim.contains(&"anchor_not_verified".to_owned()), "{lim:?}");
}

#[test]
fn scope_record_names_the_failing_row_and_the_partial_walk() {
    let mut rows = common::base_rows(POST);
    let base = rows.clone();
    rows[3].insert("reason".into(), Value::Str("edited".into()));
    let s = scoped(POST, &rows, &base);
    let o = json(&s);
    assert_eq!(o["verdict"].as_str(), Some("TAMPERED"));
    assert_eq!(o["reason"].as_str(), Some("hash_mismatch"));
    assert_eq!(o["row"], Value::Int(stack_sentinel::pyjson::PyInt::from_i64(4)));
    assert_eq!(o["gate_outcome"].as_str(), Some("terminal_breach"));
    assert!(strings(&o["limitations"]).contains(&"partial_rows_checked".to_owned()));
}

#[test]
fn an_anchor_over_a_prefix_leaves_later_rows_unkeyed() {
    let rows = common::base_rows(POST);
    let s = scoped(POST, &rows, &rows[..6]);
    assert_eq!(s.report.verdict(), Verdict::Verified);
    assert!(s.scope.limitations.contains(&Limitation::RowsAfterLastAnchorUnkeyed));
}

#[test]
fn a_missing_anchor_is_reported_as_not_verified() {
    let rows = common::base_rows(POST);
    let cols = common::columns(POST);
    let s = common::verifier(&[common::FIXTURE_KEY])
        .verify_export_scoped(&common::export_bytes(&cols, &rows), None)
        .unwrap();
    let o = json(&s);
    assert_eq!(o["verdict"].as_str(), Some("TRUNCATED"));
    assert_eq!(o["reason"].as_str(), Some("anchor_missing"));
    assert_eq!(o["anchor"], Value::Null);
    let lim = strings(&o["limitations"]);
    assert!(lim.contains(&"anchor_not_verified".to_owned()));
    assert!(lim.contains(&"rows_after_last_anchor_unkeyed".to_owned()));
}

#[test]
fn verify_export_and_the_scoped_report_agree() {
    let rows = common::base_rows(POST);
    let cols = common::columns(POST);
    let export = common::export_bytes(&cols, &rows);
    let anchor = common::anchor_bytes(&rows, rows.len(), common::FIXTURE_KEY);
    let v = common::verifier(&[common::FIXTURE_KEY]);
    let plain = v.verify_export(&export, Some(&anchor)).unwrap();
    let scoped = v.verify_export_scoped(&export, Some(&anchor)).unwrap();
    assert_eq!(plain, scoped.report);
    assert_eq!(scoped.scope.unhashed_columns, plain.unhashed_columns);
}

// ---------------------------------------------------------------------------
// the command-line tool
// ---------------------------------------------------------------------------

fn cli(export: &[u8], anchor: &[u8], extra: &[&str]) -> (i32, String) {
    let dir = std::env::temp_dir().join(format!(
        "stack-sentinel-scope-cli-{}-{}",
        std::process::id(),
        stack_sentinel::canonical::sha256_hex(format!("{}{extra:?}", export.len()).as_bytes())
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let export_path = dir.join("export.json");
    let anchor_path = dir.join("ledger.anchor");
    let key_path = dir.join("keys.txt");
    std::fs::write(&export_path, export).unwrap();
    std::fs::write(&anchor_path, anchor).unwrap();
    std::fs::write(&key_path, format!("{}\n", std::str::from_utf8(common::FIXTURE_KEY).unwrap())).unwrap();
    let fp = stack_sentinel::key_fingerprint(common::FIXTURE_KEY);
    let out = std::process::Command::new(env!("CARGO_BIN_EXE_stack-sentinel-verify"))
        .args(["--export", export_path.to_str().unwrap()])
        .args(["--anchor", anchor_path.to_str().unwrap()])
        .args(["--trusted-fingerprints", fp.as_str()])
        .args(["--key-file", key_path.to_str().unwrap()])
        .args(extra)
        .output()
        .unwrap();
    let _ = std::fs::remove_dir_all(&dir);
    (out.status.code().unwrap(), String::from_utf8(out.stdout).unwrap())
}

#[test]
fn the_cli_json_flag_prints_the_scope_line_with_the_same_exit_codes() {
    let rows = common::base_rows(PRE);
    let cols = common::columns(PRE);
    let export = common::export_bytes(&cols, &rows);
    let anchor = common::anchor_bytes(&rows, rows.len(), common::FIXTURE_KEY);

    let (code, out) = cli(&export, &anchor, &[]);
    assert_eq!((code, out.as_str()), (0, "VERIFIED\n"), "default output is unchanged");

    let (code, out) = cli(&export, &anchor, &["--json"]);
    let expected = scoped(PRE, &rows, &rows).to_json();
    assert_eq!((code, out.as_str()), (0, format!("{expected}\n").as_str()));

    let mut tampered = rows.clone();
    tampered[3].insert("reason".into(), Value::Str("edited".into()));
    let bad = common::export_bytes(&cols, &tampered);
    let (code, plain) = cli(&bad, &anchor, &[]);
    assert_eq!(code, 1);
    assert!(plain.starts_with("TAMPERED row=4 "), "{plain}");
    let (code, out) = cli(&bad, &anchor, &["--json"]);
    assert_eq!(code, 1, "exit code unchanged under --json");
    assert_eq!(out.lines().count(), 1);
    assert!(out.contains("\"verdict\":\"TAMPERED\""), "{out}");
}

// ---------------------------------------------------------------------------
// Step 2 (D-08): the hashed and unhashed lists are exact, per record kind
// ---------------------------------------------------------------------------

/// A row of `kind` carrying every shipped column, so every canonical form
/// can be rebuilt; `data` and `input_data` are empty mappings.
fn synthetic_row(kind: &str) -> Object {
    let mut row = Object::new();
    for col in stack_sentinel::canonical::SHIPPED_COLUMNS {
        row.insert(col.into(), Value::Null);
    }
    row.insert("data".into(), Value::Object(Object::new()));
    row.insert("input_data".into(), Value::Object(Object::new()));
    if kind != "base" {
        row.insert("record_kind".into(), Value::Str(kind.into()));
    }
    row
}

fn hash(row: &Object) -> String {
    stack_sentinel::recompute_current_hash(row).unwrap()
}

/// The key lists the scope reports are checked against the hash itself, for
/// every record kind: each listed key moves the hash, any other key does
/// not; each whole column the kind reads moves it, every other shipped
/// column does not (optional hashed fields only on kinds that apply them).
#[test]
fn the_reported_hashed_paths_are_exactly_what_moves_the_hash() {
    use stack_sentinel::canonical::{
        column_is_hashed, hashed_columns, hashed_mapping_keys, OPTIONAL_HASHED_FIELDS, RECORD_KIND_LABELS,
        SHIPPED_COLUMNS,
    };
    for kind in RECORD_KIND_LABELS {
        let row = synthetic_row(kind);
        let before = hash(&row);
        let partial = hashed_mapping_keys(&row);
        if let Some((col, keys)) = partial {
            for key in keys {
                let mut r = row.clone();
                let mut m = Object::new();
                m.insert((*key).into(), Value::Str("moved".into()));
                r.insert(col.into(), Value::Object(m));
                assert_ne!(hash(&r), before, "{kind}: {col}.{key} is listed as hashed but does not move the hash");
            }
            let mut r = row.clone();
            let mut m = Object::new();
            m.insert("zz_not_a_canonical_key".into(), Value::Str("moved".into()));
            r.insert(col.into(), Value::Object(m));
            assert_eq!(hash(&r), before, "{kind}: an extra {col} key moved the hash");
        }
        let (read, optional) = hashed_columns(&row);
        for col in SHIPPED_COLUMNS {
            if col == "current_hash" || partial.is_some_and(|(c, _)| c == col) {
                continue;
            }
            let mut r = row.clone();
            r.insert(col.into(), Value::Str("moved".into()));
            let Ok(after) = stack_sentinel::recompute_current_hash(&r) else {
                // Making a mapping column a string fails the recompute: covered.
                assert!(read.contains(&col), "{kind}: {col}");
                continue;
            };
            let moves = after != before;
            let listed = read.contains(&col) || (optional && OPTIONAL_HASHED_FIELDS.contains(&col));
            assert_eq!(moves, listed, "{kind}: column {col} moves={moves} listed={listed}");
            assert_eq!(column_is_hashed(&row, col), listed, "{kind}: column_is_hashed({col})");
        }
    }
}

struct Gap {
    what: &'static str,
    row: usize,
    edit: fn(&mut Object),
    kind: &'static str,
    token: &'static str,
}

fn set(row: &mut Object, col: &str, v: Value) {
    row.insert(col.into(), v);
}

fn data_mut(row: &mut Object, col: &str) -> Object {
    match row.get(col) {
        Some(Value::Object(m)) => m.clone(),
        _ => Object::new(),
    }
}

/// Each known unhashed column, edited on the post-receipts fixture under a
/// full anchor: the verdict stays VERIFIED (the known gap, as
/// redteam_unhashed_columns_change_under_verified records for timestamp),
/// and the scope record lists the column as unhashed for that row's kind,
/// and not as hashed for it, so a consumer can see the gap.
#[test]
fn every_known_unhashed_column_changes_under_verified_and_is_listed() {
    let gaps = [
        Gap {
            what: "timestamp on a decision (obligation horizon)",
            row: 7,
            edit: |r| set(r, "timestamp", Value::Str("1999-01-01T00:00:00+00:00".into())),
            kind: "governance_decision",
            token: "timestamp",
        },
        Gap {
            what: "call_sid on a decision (idempotency)",
            row: 2,
            edit: |r| set(r, "call_sid", Value::Str("CA-replayed".into())),
            kind: "governance_decision",
            token: "call_sid",
        },
        Gap {
            what: "cassette_snapshot on a decision",
            row: 2,
            edit: |r| set(r, "cassette_snapshot", Value::Str("{\"limit\": 999}".into())),
            kind: "governance_decision",
            token: "cassette_snapshot",
        },
        Gap {
            what: "reason on a typed non-decision row",
            row: 10,
            edit: |r| set(r, "reason", Value::Str("rewritten".into())),
            kind: "cassette_binding",
            token: "reason",
        },
        Gap {
            what: "node on a typed non-decision row",
            row: 10,
            edit: |r| set(r, "node", Value::Str("elsewhere".into())),
            kind: "cassette_binding",
            token: "node",
        },
        Gap {
            what: "an extra data key on a decision",
            row: 2,
            edit: |r| {
                let mut d = data_mut(r, "data");
                d.insert("note".into(), Value::Str("rewritten".into()));
                set(r, "data", Value::Object(d));
            },
            kind: "governance_decision",
            token: "data.*",
        },
        Gap {
            what: "an extra input_data key on an observed event",
            row: 4,
            edit: |r| {
                let mut d = data_mut(r, "input_data");
                d.insert("injected".into(), Value::Str("rewritten".into()));
                set(r, "input_data", Value::Object(d));
            },
            kind: "observed_event",
            token: "input_data.*",
        },
        Gap {
            what: "record_kind on a legacy row",
            row: 0,
            edit: |r| set(r, "record_kind", Value::Str("legacy-rewritten".into())),
            kind: "base",
            token: "record_kind",
        },
        Gap {
            what: "authorized_by (null) on a legacy row, which applies no optional field",
            row: 0,
            edit: |r| set(r, "authorized_by", Value::Str("mallory".into())),
            kind: "base",
            token: "authorized_by",
        },
    ];
    let base = common::base_rows(POST);
    for g in gaps {
        let mut rows = base.clone();
        (g.edit)(&mut rows[g.row]);
        let s = scoped(POST, &rows, &base);
        assert_eq!(s.report.verdict(), Verdict::Verified, "{}: {}", g.what, s.report.render());
        assert!(s.report.unhashed_columns.contains(&g.token), "{}: {:?}", g.what, s.report.unhashed_columns);
        let o = json(&s);
        assert!(strings(&o["unhashed_columns"]).contains(&g.token.to_owned()), "{}", g.what);
        let Value::Array(kinds) = &o["by_record_kind"] else { panic!() };
        let k = kinds
            .iter()
            .map(|k| k.as_object().unwrap())
            .find(|k| k["kind"].as_str() == Some(g.kind))
            .unwrap_or_else(|| panic!("{}: kind {} missing", g.what, g.kind));
        assert!(strings(&k["unhashed"]).contains(&g.token.to_owned()), "{}: {:?}", g.what, k["unhashed"]);
        assert!(!strings(&k["hashed"]).contains(&g.token.to_owned()), "{}: {:?}", g.what, k["hashed"]);
        assert!(strings(&o["limitations"]).contains(&"unhashed_columns_present".to_owned()));
    }
}

/// `data` is no longer reported as hashed for the kinds that hash only named
/// keys of it: the record names the keys instead.
#[test]
fn a_decision_reports_its_hashed_data_keys_not_data() {
    let rows = common::base_rows(POST);
    let s = scoped(POST, &rows, &rows);
    let d = s.scope.by_record_kind.iter().find(|k| k.kind == "governance_decision").unwrap();
    assert!(d.hashed.contains(&"data.parameter_changed".to_owned()), "{:?}", d.hashed);
    assert!(!d.hashed.contains(&"data".to_owned()), "{:?}", d.hashed);
    assert!(d.unhashed.contains(&"data.*"), "the fixture decisions carry data.note: {:?}", d.unhashed);
    let base = s.scope.by_record_kind.iter().find(|k| k.kind == "base").unwrap();
    assert!(base.hashed.contains(&"data".to_owned()), "a base row hashes all of data: {:?}", base.hashed);
}
