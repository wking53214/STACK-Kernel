//! The metrics named in `tack_sentinel::telemetry` fire, with closed labels.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use metrics_util::debugging::{DebugValue, DebuggingRecorder};
use metrics_util::CompositeKey;
use tack_sentinel::telemetry::{
    describe_metrics, INPUT_REJECTED_TOTAL, ROWS_CHECKED_TOTAL, TRIPS_TOTAL, VERIFICATIONS_TOTAL,
    VERIFY_DURATION_SECONDS,
};
use tack_sentinel::{KeySet, Reason, Verifier, VerifierConfig, VerifyError};

type Entry = (CompositeKey, DebugValue);

fn run<F: FnOnce()>(f: F) -> Vec<Entry> {
    let recorder = DebuggingRecorder::new();
    let snapshotter = recorder.snapshotter();
    metrics::with_local_recorder(&recorder, f);
    snapshotter
        .snapshot()
        .into_vec()
        .into_iter()
        .map(|(k, _, _, v)| (k, v))
        .collect()
}

fn labels(k: &CompositeKey) -> Vec<(String, String)> {
    let mut l: Vec<(String, String)> = k
        .key()
        .labels()
        .map(|l| (l.key().to_owned(), l.value().to_owned()))
        .collect();
    l.sort();
    l
}

fn counter(entries: &[Entry], name: &str, want: &[(&str, &str)]) -> u64 {
    let mut want: Vec<(String, String)> = want.iter().map(|(a, b)| ((*a).to_owned(), (*b).to_owned())).collect();
    want.sort();
    entries
        .iter()
        .filter(|(k, _)| k.key().name() == name && labels(k) == want)
        .map(|(_, v)| match v {
            DebugValue::Counter(c) => *c,
            _ => 0,
        })
        .sum()
}

fn histogram_count(entries: &[Entry], name: &str, outcome: &str) -> usize {
    entries
        .iter()
        .filter(|(k, _)| k.key().name() == name && labels(k) == vec![("outcome".to_owned(), outcome.to_owned())])
        .map(|(_, v)| match v {
            DebugValue::Histogram(h) => h.len(),
            _ => 0,
        })
        .sum()
}

fn pre() -> (tack_sentinel::pyjson::Value, Vec<tack_sentinel::pyjson::Object>) {
    let rel = "ledger_export_pre_receipts.json";
    (common::columns(rel), common::base_rows(rel))
}

#[test]
fn a_clean_export_counts_one_verified_pass_and_its_rows() {
    let (cols, rows) = pre();
    let anchor = common::anchor_bytes(&rows, rows.len(), common::FIXTURE_KEY);
    let export = common::export_bytes(&cols, &rows);
    let entries = run(|| {
        describe_metrics();
        let report = common::verifier(&[common::FIXTURE_KEY])
            .verify_export(&export, Some(&anchor))
            .unwrap();
        assert_eq!(report.verdict().as_str(), "VERIFIED");
    });
    assert_eq!(
        counter(&entries, VERIFICATIONS_TOTAL, &[("verdict", "verified"), ("outcome", "pass")]),
        1
    );
    assert_eq!(counter(&entries, ROWS_CHECKED_TOTAL, &[]), rows.len() as u64);
    assert_eq!(histogram_count(&entries, VERIFY_DURATION_SECONDS, "pass"), 1);
    assert!(entries.iter().all(|(k, _)| k.key().name() != TRIPS_TOTAL));
}

#[test]
fn a_tampered_export_counts_a_terminal_breach_trip_and_the_anchor_note() {
    let (cols, mut rows) = pre();
    let anchor = common::anchor_bytes(&rows, rows.len(), common::FIXTURE_KEY);
    rows[0].insert("reason".into(), tack_sentinel::pyjson::Value::Str("edited".into()));
    common::rechain(&mut rows, 0);
    let export = common::export_bytes(&cols, &rows);
    let entries = run(|| {
        let report = common::verifier(&[common::FIXTURE_KEY])
            .verify_export(&export, Some(&anchor))
            .unwrap();
        assert_eq!(report.finding.as_ref().unwrap().reason, Reason::SignatureInvalid);
        assert_eq!(report.also.as_ref().unwrap().reason, Reason::HeadMismatch);
    });
    assert_eq!(
        counter(&entries, VERIFICATIONS_TOTAL, &[("verdict", "tampered"), ("outcome", "terminal_breach")]),
        1
    );
    assert_eq!(
        counter(
            &entries,
            TRIPS_TOTAL,
            &[
                ("verdict", "tampered"),
                ("reason", "signature_invalid"),
                ("outcome", "terminal_breach"),
                ("resolution", "quarantine")
            ]
        ),
        1
    );
    assert_eq!(
        counter(
            &entries,
            TRIPS_TOTAL,
            &[
                ("verdict", "truncated"),
                ("reason", "head_mismatch"),
                ("outcome", "terminal_breach"),
                ("resolution", "quarantine")
            ]
        ),
        1
    );
    assert_eq!(histogram_count(&entries, VERIFY_DURATION_SECONDS, "terminal_breach"), 1);
}

#[test]
fn a_missing_anchor_counts_a_retry_trip_resolved_by_reject() {
    let (cols, rows) = pre();
    let export = common::export_bytes(&cols, &rows);
    let entries = run(|| {
        let report = common::verifier(&[common::FIXTURE_KEY]).verify_export(&export, None).unwrap();
        assert_eq!(report.verdict().as_str(), "TRUNCATED");
    });
    assert_eq!(
        counter(
            &entries,
            TRIPS_TOTAL,
            &[
                ("verdict", "truncated"),
                ("reason", "anchor_missing"),
                ("outcome", "retry"),
                ("resolution", "reject")
            ]
        ),
        1
    );
    assert_eq!(
        counter(&entries, VERIFICATIONS_TOTAL, &[("verdict", "truncated"), ("outcome", "retry")]),
        1
    );
}

#[test]
fn refused_inputs_count_by_closed_reason() {
    let entries = run(|| {
        let err = Verifier::new(VerifierConfig::default(), KeySet::default()).unwrap_err();
        assert_eq!(err, VerifyError::NoTrustedKeyMaterial);
        let v = common::verifier(&[common::FIXTURE_KEY]);
        assert!(matches!(v.verify_export(b"{not json", None), Err(VerifyError::ExportNotJson(_))));
        assert!(matches!(v.verify_export(br#"{"format": "other"}"#, None), Err(VerifyError::NotAnExport)));
        let tiny = VerifierConfig {
            max_export_bytes: 4,
            ..VerifierConfig::default()
        };
        let small = Verifier::new(tiny, common::verifier_keys()).unwrap();
        assert!(matches!(small.verify_export(b"[1, 2, 3]", None), Err(VerifyError::ExportTooLarge { .. })));
    });
    for reason in ["no_trusted_key_material", "export_not_json", "not_an_export", "export_too_large"] {
        assert_eq!(
            counter(&entries, INPUT_REJECTED_TOTAL, &[("reason", reason), ("outcome", "retry")]),
            1,
            "{reason}"
        );
    }
    // three of the four happened inside verify_export and were timed
    assert_eq!(histogram_count(&entries, VERIFY_DURATION_SECONDS, "retry"), 3);
}

#[test]
fn no_label_value_is_taken_from_the_export() {
    // An export whose every string is attacker-chosen must not appear in any
    // label: labels come only from the crate's closed enums.
    let (cols, mut rows) = pre();
    let marker = "ATTACKER-CONTROLLED-LABEL-VALUE";
    rows[3].insert("node".into(), tack_sentinel::pyjson::Value::Str(marker.into()));
    let anchor = common::anchor_bytes(&rows, rows.len(), common::FIXTURE_KEY);
    let export = common::export_bytes(&cols, &rows);
    let entries = run(|| {
        let report = common::verifier(&[common::FIXTURE_KEY])
            .verify_export(&export, Some(&anchor))
            .unwrap();
        assert!(!report.render().contains(marker), "raw input leaked into the report");
    });
    for (k, _) in &entries {
        for (_, v) in labels(k) {
            assert!(!v.contains(marker));
        }
    }
    assert!(!entries.is_empty());
}
