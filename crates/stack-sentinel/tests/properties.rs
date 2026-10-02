//! Property tests: the reader and writer agree with each other, nothing
//! panics on arbitrary input, and the chain properties hold for every row.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use proptest::prelude::*;
use stack_sentinel::pyjson::{dumps, float_repr, parse, Object, ParseLimits, PyInt, Separators, Value};
use stack_sentinel::{Reason, Verdict};

const POST: &str = "differential/base_post_receipts.json";

fn arb_value() -> impl Strategy<Value = Value> {
    let leaf = prop_oneof![
        Just(Value::Null),
        any::<bool>().prop_map(Value::Bool),
        any::<i64>().prop_map(|i| Value::Int(PyInt::from_i64(i))),
        "-?[1-9][0-9]{0,60}".prop_map(|s| parse(s.as_bytes(), ParseLimits::default()).unwrap()),
        any::<u64>()
            .prop_map(f64::from_bits)
            .prop_filter("finite", |f| f.is_finite())
            .prop_map(Value::Float),
        any::<String>().prop_map(Value::Str),
    ];
    leaf.prop_recursive(4, 48, 6, |inner| {
        prop_oneof![
            prop::collection::vec(inner.clone(), 0..6).prop_map(Value::Array),
            prop::collection::btree_map(any::<String>(), inner, 0..6).prop_map(Value::Object),
        ]
    })
}

fn post() -> (Value, Vec<Object>) {
    (common::columns(POST), common::base_rows(POST))
}

fn verify(rows: &[Object], anchor_rows: &[Object]) -> tack_sentinel::Report {
    let cols = common::columns(POST);
    let anchor = common::anchor_bytes(anchor_rows, anchor_rows.len(), common::FIXTURE_KEY);
    common::verifier(&[common::FIXTURE_KEY])
        .verify_export(&common::export_bytes(&cols, rows), Some(&anchor))
        .unwrap()
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 256, .. ProptestConfig::default() })]

    #[test]
    fn written_json_reads_back_to_the_same_bytes(v in arb_value()) {
        for seps in [Separators::Python, Separators::Compact] {
            let text = dumps(&v, seps);
            prop_assert!(text.is_ascii(), "ensure_ascii output must be ASCII");
            let back = parse(text.as_bytes(), ParseLimits::default()).unwrap();
            prop_assert_eq!(dumps(&back, seps), text);
        }
    }

    #[test]
    fn float_repr_round_trips_every_finite_double(bits in any::<u64>()) {
        let f = f64::from_bits(bits);
        prop_assume!(f.is_finite());
        let text = float_repr(f);
        prop_assert_eq!(text.parse::<f64>().unwrap().to_bits(), f.to_bits());
    }

    #[test]
    fn the_reader_never_panics(bytes in prop::collection::vec(any::<u8>(), 0..256)) {
        let _ = parse(&bytes, ParseLimits::default());
    }

    #[test]
    fn the_verifier_never_panics_and_never_passes_noise(bytes in prop::collection::vec(any::<u8>(), 0..256)) {
        let v = common::verifier(&[common::FIXTURE_KEY]);
        if let Ok(report) = v.verify_export(&bytes, Some(&bytes)) {
            prop_assert_ne!(report.verdict(), Verdict::Verified);
        }
    }
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 48, .. ProptestConfig::default() })]

    #[test]
    fn any_reordering_of_the_rows_array_verifies(seed in any::<u64>()) {
        let (_, base) = post();
        let mut rows = base.clone();
        // Fisher-Yates driven by the seed
        let mut s = seed;
        for i in (1..rows.len()).rev() {
            s = s.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
            let j = (s >> 33) as usize % (i + 1);
            rows.swap(i, j);
        }
        prop_assert_eq!(verify(&rows, &base).verdict(), Verdict::Verified);
    }

    #[test]
    fn cutting_any_tail_is_truncated(keep in 1usize..16) {
        let (_, base) = post();
        let rows = base[..keep].to_vec();
        let report = verify(&rows, &base);
        let f = report.finding.unwrap();
        prop_assert_eq!(f.reason, Reason::TailMissing);
        prop_assert_eq!(f.row_position, Some(keep - 1));
    }

    #[test]
    fn deleting_any_row_but_the_last_breaks_the_chain(drop in 0usize..15) {
        let (_, base) = post();
        let mut rows = base.clone();
        rows.remove(drop);
        let report = verify(&rows, &base);
        let f = report.finding.unwrap();
        prop_assert_eq!(f.reason, Reason::ChainBroken);
        prop_assert_eq!(f.row_position, Some(drop));
    }

    #[test]
    fn flipping_any_hash_character_is_never_verified(row in 0usize..16, at in 0usize..64, prev in any::<bool>()) {
        let (_, base) = post();
        let mut rows = base.clone();
        let col = if prev && row > 0 { "previous_hash" } else { "current_hash" };
        let mut h: Vec<u8> = rows[row][col].as_str().unwrap().as_bytes().to_vec();
        h[at] = if h[at] == b'0' { b'1' } else { b'0' };
        rows[row].insert(col.into(), Value::Str(String::from_utf8(h).unwrap()));
        let report = verify(&rows, &base);
        prop_assert_ne!(report.verdict(), Verdict::Verified);
    }

    #[test]
    fn editing_any_hashed_decision_field_and_rechaining_never_verifies(which in 0usize..4, field in 0usize..6) {
        let (_, base) = post();
        let mut rows = base.clone();
        let decisions: Vec<usize> = rows
            .iter()
            .enumerate()
            .filter(|(_, r)| r["record_kind"].as_str() == Some("governance_decision"))
            .map(|(i, _)| i)
            .collect();
        let d = decisions[which % decisions.len()];
        let col = ["action_type", "node", "reason", "decision_output", "policy_parameters", "applied_value"][field];
        rows[d].insert(col.into(), Value::Str("edited".into()));
        common::rechain(&mut rows, d);
        let report = verify(&rows, &base);
        prop_assert_ne!(report.verdict(), Verdict::Verified);
    }
}
