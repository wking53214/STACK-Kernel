//! Each correction kind, the budget, and every RETRY path.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use common::{fixture, fixture_with, num, qty, req, text};
use stack_bumpers::{
    BumperConfig, CorrectionKind, GateOutcome, NormalizedValue, Resolution, SoftEdge, TripParam, TripReason,
    UnitScale,
};

fn kinds(n: &tack_bumpers::Normalized) -> Vec<&'static str> {
    n.corrections().iter().map(|c| c.kind.label()).collect()
}

#[test]
fn clean_request_passes_with_no_corrections() {
    let n = fixture().normalize(&req(&[])).unwrap();
    assert_eq!(n.outcome(), GateOutcome::Pass);
    assert!(n.corrections().is_empty());
    assert_eq!(n.get("timeout"), Some(&NormalizedValue::Number(5.0)));
    assert_eq!(n.get("priority"), Some(&NormalizedValue::Variant("low".into())));
}

#[test]
fn clamp_below_soft_band_moves_to_soft_min() {
    let n = fixture().normalize(&req(&[("timeout", num(0.1))])).unwrap();
    assert_eq!(n.get("timeout").unwrap().as_f64(), Some(0.5));
    assert_eq!(
        n.corrections()[0].kind,
        CorrectionKind::Clamped {
            from: 0.1,
            to: 0.5,
            edge: SoftEdge::Min
        }
    );
    assert_eq!(n.corrections()[0].param, "timeout");
}

#[test]
fn clamp_above_soft_band_moves_to_soft_max() {
    let n = fixture().normalize(&req(&[("timeout", num(299.0))])).unwrap();
    assert_eq!(n.get("timeout").unwrap().as_f64(), Some(30.0));
    assert_eq!(
        n.corrections()[0].kind,
        CorrectionKind::Clamped {
            from: 299.0,
            to: 30.0,
            edge: SoftEdge::Max
        }
    );
}

#[test]
fn soft_edges_and_hard_edges_are_inclusive() {
    let b = fixture();
    for (x, want, corrected) in [(0.5, 0.5, false), (30.0, 30.0, false), (0.0, 0.5, true), (300.0, 30.0, true)] {
        let n = b.normalize(&req(&[("timeout", num(x))])).unwrap();
        assert_eq!(n.get("timeout").unwrap().as_f64(), Some(want), "x={x}");
        assert_eq!(!n.corrections().is_empty(), corrected, "x={x}");
    }
}

#[test]
fn unit_conversion_milliseconds_to_seconds() {
    let n = fixture().normalize(&req(&[("timeout", qty(1500.0, "ms"))])).unwrap();
    assert_eq!(n.get("timeout").unwrap().as_f64(), Some(1.5));
    assert_eq!(
        n.corrections()[0].kind,
        CorrectionKind::UnitConverted {
            from_unit: "ms".into(),
            scale: UnitScale::Divide(1000.0)
        }
    );
}

#[test]
fn canonical_unit_is_not_a_correction() {
    let n = fixture().normalize(&req(&[("timeout", qty(2.0, "s"))])).unwrap();
    assert_eq!(n.get("timeout").unwrap().as_f64(), Some(2.0));
    assert!(n.corrections().is_empty());
}

#[test]
fn unit_conversion_then_clamp_counts_two() {
    // 2 min = 120 s, over soft_max 30, under hard_max 300.
    let n = fixture().normalize(&req(&[("timeout", qty(2.0, "min"))])).unwrap();
    assert_eq!(n.get("timeout").unwrap().as_f64(), Some(30.0));
    assert_eq!(kinds(&n), ["unit_converted", "clamped"]);
}

#[test]
fn unit_conversion_past_hard_band_is_terminal() {
    // 10 min = 600 s, past hard_max 300.
    let r = fixture().normalize(&req(&[("timeout", qty(10.0, "min"))])).unwrap_err();
    assert_eq!(r.outcome, GateOutcome::TerminalBreach);
    assert!(r.has(TripReason::OutsideHardBand));
}

#[test]
fn unit_conversion_overflow_is_terminal_not_nan() {
    let r = fixture().normalize(&req(&[("timeout", qty(f64::MAX, "min"))])).unwrap_err();
    assert_eq!(r.outcome, GateOutcome::TerminalBreach);
    assert!(r.has(TripReason::OutsideHardBand));
}

#[test]
fn units_match_exactly_no_case_folding() {
    for unit in ["MS", "Ms", " ms", "msec", ""] {
        let r = fixture().normalize(&req(&[("timeout", qty(1500.0, unit))])).unwrap_err();
        assert_eq!(r.outcome, GateOutcome::Retry, "unit {unit:?}");
        assert!(r.has(TripReason::UnknownUnit));
    }
}

#[test]
fn quantity_on_unitless_param_is_unknown_unit() {
    let r = fixture().normalize(&req(&[("ratio", qty(0.1, "s"))])).unwrap_err();
    assert!(r.has(TripReason::UnknownUnit));
}

#[test]
fn enum_case_fold() {
    let n = fixture().normalize(&req(&[("priority", text("High"))])).unwrap();
    assert_eq!(n.get("priority"), Some(&NormalizedValue::Variant("high".into())));
    assert_eq!(n.corrections()[0].kind, CorrectionKind::CaseFolded);
}

#[test]
fn enum_trim() {
    let n = fixture().normalize(&req(&[("priority", text("  high\t"))])).unwrap();
    assert_eq!(n.get("priority").unwrap().as_str(), Some("high"));
    assert_eq!(n.corrections()[0].kind, CorrectionKind::Trimmed { removed_bytes: 3 });
}

#[test]
fn enum_alias() {
    let n = fixture().normalize(&req(&[("priority", text("hi"))])).unwrap();
    assert_eq!(n.get("priority").unwrap().as_str(), Some("high"));
    assert_eq!(
        n.corrections()[0].kind,
        CorrectionKind::AliasResolved {
            alias: "hi".into(),
            canonical: "high".into()
        }
    );
}

#[test]
fn enum_trim_fold_and_alias_each_count() {
    let n = fixture().normalize(&req(&[("priority", text(" HI "))])).unwrap();
    assert_eq!(n.get("priority").unwrap().as_str(), Some("high"));
    assert_eq!(kinds(&n), ["trimmed", "case_folded", "alias_resolved"]);
}

#[test]
fn enum_non_ascii_is_not_folded() {
    let b = tack_bumpers::Bumper::new(
        BumperConfig::default(),
        [tack_bumpers::ParamSpec::required(
            "mode",
            tack_bumpers::EnumSpec::new([tack_bumpers::VariantSpec::new("\u{e9}t\u{e9}")]).unwrap(),
        )],
    )
    .unwrap();
    let mut m = std::collections::BTreeMap::new();
    m.insert("mode".to_owned(), text("\u{c9}T\u{c9}"));
    let r = b.normalize(&m).unwrap_err();
    assert!(r.has(TripReason::UnknownVariant));
    // ASCII letters around a non-ASCII one still fold.
    m.insert("mode".to_owned(), text("\u{e9}T\u{e9}"));
    let n = b.normalize(&m).unwrap();
    assert_eq!(n.corrections()[0].kind, CorrectionKind::CaseFolded);
}

#[test]
fn enum_unknown_variant_is_retry() {
    for s in ["urgent", "", "   ", "highest", "h i"] {
        let r = fixture().normalize(&req(&[("priority", text(s))])).unwrap_err();
        assert_eq!(r.outcome, GateOutcome::Retry, "{s:?}");
        assert!(r.has(TripReason::UnknownVariant), "{s:?}");
    }
}

#[test]
fn enum_oversized_input_is_refused_before_folding() {
    let long = "h".repeat(1000);
    let r = fixture().normalize(&req(&[("priority", text(&long))])).unwrap_err();
    assert!(r.has(TripReason::UnknownVariant));
}

#[test]
fn string_trim_policy() {
    let n = fixture().normalize(&req(&[("label", text("  hello  "))])).unwrap();
    assert_eq!(n.get("label"), Some(&NormalizedValue::Text("hello".into())));
    assert_eq!(n.corrections()[0].kind, CorrectionKind::Trimmed { removed_bytes: 4 });
}

#[test]
fn string_trim_then_length_check() {
    // 16 bytes after trimming fits, even though the raw value is longer.
    let n = fixture()
        .normalize(&req(&[("label", text("   0123456789abcdef   "))]))
        .unwrap();
    assert_eq!(n.get("label").unwrap().as_str(), Some("0123456789abcdef"));
    let r = fixture()
        .normalize(&req(&[("label", text("0123456789abcdefg"))]))
        .unwrap_err();
    assert_eq!(r.outcome, GateOutcome::Retry);
    assert!(r.has(TripReason::TooLong));
}

#[test]
fn string_reject_policy() {
    let r = fixture().normalize(&req(&[("tenant", text(" acme"))])).unwrap_err();
    assert_eq!(r.outcome, GateOutcome::Retry);
    assert!(r.has(TripReason::WhitespaceRejected));
    let n = fixture().normalize(&req(&[("tenant", text("acme"))])).unwrap();
    assert!(n.corrections().is_empty());
}

#[test]
fn string_is_never_truncated() {
    let r = fixture().normalize(&req(&[("tenant", text("abcdefghi"))])).unwrap_err();
    assert!(r.has(TripReason::TooLong));
}

#[test]
fn budget_of_three_passes_at_three() {
    // unit converted + clamped + case folded = 3.
    let n = fixture()
        .normalize(&req(&[("timeout", qty(2.0, "min")), ("priority", text("LOW"))]))
        .unwrap();
    assert_eq!(n.corrections().len(), 3);
}

#[test]
fn budget_exhaustion_is_retry() {
    // 2 (timeout) + 3 (priority) = 5 > 3.
    let r = fixture()
        .normalize(&req(&[("timeout", qty(2.0, "min")), ("priority", text(" HI "))]))
        .unwrap_err();
    assert_eq!(r.outcome, GateOutcome::Retry);
    assert_eq!(r.resolution, Resolution::Reject);
    assert_eq!(r.trips.len(), 1);
    assert_eq!(r.trips[0].param, TripParam::Request);
    assert_eq!(r.trips[0].reason, TripReason::CorrectionBudgetExceeded);
}

#[test]
fn zero_budget_makes_any_drift_retry() {
    let b = fixture_with(BumperConfig {
        correction_budget: 0,
        ..BumperConfig::default()
    });
    assert!(b.normalize(&req(&[])).is_ok());
    let r = b.normalize(&req(&[("priority", text("Low"))])).unwrap_err();
    assert!(r.has(TripReason::CorrectionBudgetExceeded));
}

#[test]
fn unknown_param_is_rejected_and_not_echoed() {
    let r = fixture().normalize(&req(&[("timeuot", num(1.0))])).unwrap_err();
    assert_eq!(r.outcome, GateOutcome::Retry);
    assert_eq!(r.trips.len(), 1);
    match &r.trips[0].param {
        TripParam::Unknown { len, sha256 } => {
            assert_eq!(*len, 7);
            assert_eq!(sha256.len(), 64);
            assert_eq!(sha256, &tack_bumpers::telemetry::sha256_hex(b"timeuot"));
        }
        other => panic!("unexpected {other:?}"),
    }
    assert!(!format!("{r:?}").contains("timeuot"));
}

#[test]
fn param_names_match_exactly() {
    let r = fixture().normalize(&req(&[("Timeout", num(1.0))])).unwrap_err();
    assert!(r.has(TripReason::UnknownParam));
}

#[test]
fn missing_required_is_retry() {
    let mut m = req(&[]);
    m.remove("priority");
    let r = fixture().normalize(&m).unwrap_err();
    assert_eq!(r.outcome, GateOutcome::Retry);
    assert_eq!(r.trips[0].param, TripParam::Named("priority".into()));
    assert_eq!(r.trips[0].reason, TripReason::MissingRequired);
}

#[test]
fn optional_absent_is_absent_not_defaulted() {
    let n = fixture().normalize(&req(&[])).unwrap();
    assert!(n.get("label").is_none());
    assert!(n.get("ratio").is_none());
}

#[test]
fn type_mismatch_is_retry() {
    for (k, v) in [("timeout", text("5")), ("priority", num(1.0)), ("label", num(1.0))] {
        let r = fixture().normalize(&req(&[(k, v)])).unwrap_err();
        assert_eq!(r.outcome, GateOutcome::Retry);
        assert!(r.has(TripReason::TypeMismatch), "{k}");
    }
}

#[test]
fn every_problem_is_reported_and_terminal_wins() {
    let mut m = req(&[("timeout", num(f64::NAN)), ("bogus", num(1.0))]);
    m.remove("priority");
    let r = fixture().normalize(&m).unwrap_err();
    assert_eq!(r.outcome, GateOutcome::TerminalBreach);
    let reasons: Vec<_> = r.trips.iter().map(|t| t.reason).collect();
    assert!(reasons.contains(&TripReason::NonFinite));
    assert!(reasons.contains(&TripReason::UnknownParam));
    assert!(reasons.contains(&TripReason::MissingRequired));
}

#[test]
fn corrections_of_a_tripped_param_do_not_count() {
    // " urgent " would be trimmed, but then matches nothing: only the trip
    // is reported, and the trim does not count toward the budget.
    let r = fixture().normalize(&req(&[("priority", text(" urgent "))])).unwrap_err();
    assert_eq!(r.trips.len(), 1);
    assert_eq!(r.trips[0].reason, TripReason::UnknownVariant);
}

#[test]
fn too_many_params_is_terminal_and_bounded() {
    let b = fixture_with(BumperConfig {
        max_params: 5,
        ..BumperConfig::default()
    });
    let mut m = req(&[]);
    for i in 0..10 {
        m.insert(format!("k{i}"), num(0.0));
    }
    let r = b.normalize(&m).unwrap_err();
    assert_eq!(r.outcome, GateOutcome::TerminalBreach);
    assert_eq!(r.trips.len(), 1, "no entry is read past the cap");
    assert_eq!(r.trips[0].reason, TripReason::TooManyParams);
}

#[test]
fn oversized_text_is_terminal() {
    let big = "a".repeat(4097);
    for (k, v) in [
        ("label", text(&big)),
        ("priority", text(&big)),
        ("timeout", qty(1.0, &big)),
    ] {
        let r = fixture().normalize(&req(&[(k, v)])).unwrap_err();
        assert_eq!(r.outcome, GateOutcome::TerminalBreach, "{k}");
        assert!(r.has(TripReason::InputTooLarge), "{k}");
    }
    let mut m = req(&[]);
    m.insert(big, num(1.0));
    let r = fixture().normalize(&m).unwrap_err();
    assert!(r.has(TripReason::InputTooLarge));
}

#[test]
fn rejection_display_has_no_raw_input() {
    let r = fixture().normalize(&req(&[("secret-key-xyz", num(1.0))])).unwrap_err();
    let shown = r.to_string();
    assert!(shown.contains("retry"));
    assert!(!shown.contains("secret-key-xyz"));
}

#[test]
fn string_min_len_is_checked_after_trim() {
    // Whitespace-only text under Trim is too short, not an empty PASS.
    let r = fixture().normalize(&req(&[("label", text("   "))])).unwrap_err();
    assert_eq!(r.outcome, GateOutcome::Retry);
    assert!(r.has(TripReason::TooShort));
    // An explicit min_len of 0 allows the empty string.
    let b = tack_bumpers::Bumper::new(
        BumperConfig::default(),
        [tack_bumpers::ParamSpec::required(
            "s",
            tack_bumpers::StringSpec::new(4, tack_bumpers::TrimPolicy::Trim)
                .unwrap()
                .with_min_len(0)
                .unwrap(),
        )],
    )
    .unwrap();
    let mut m = std::collections::BTreeMap::new();
    m.insert("s".to_owned(), text(""));
    assert_eq!(b.normalize(&m).unwrap().get("s").unwrap().as_str(), Some(""));
}

#[test]
fn reject_string_refuses_control_and_format_chars() {
    for id in ["ac\u{200D}me", "acme\u{7}", "\u{2066}acme"] {
        let r = fixture().normalize(&req(&[("tenant", text(id))])).unwrap_err();
        assert_eq!(r.outcome, GateOutcome::Retry);
        assert!(r.has(TripReason::DisallowedChar), "{}", id.escape_unicode());
    }
    // A Trim string keeps CharPolicy::Any by default.
    assert!(fixture().normalize(&req(&[("label", text("a\u{200B}b"))])).is_ok());
}

#[test]
fn non_finite_is_terminal_on_any_shape_and_unknown_key() {
    for (k, v) in [("priority", num(f64::NAN)), ("label", qty(f64::INFINITY, "s")), ("nope", num(f64::NAN))] {
        let r = fixture().normalize(&req(&[(k, v)])).unwrap_err();
        assert_eq!(r.outcome, GateOutcome::TerminalBreach, "{k}");
        assert!(r.has(TripReason::NonFinite), "{k}");
    }
}

#[test]
fn oversized_unknown_key_records_length_only() {
    let big = "k".repeat(4097);
    let mut m = req(&[]);
    m.insert(big, num(1.0));
    let r = fixture().normalize(&m).unwrap_err();
    assert_eq!(r.trips[0].param, TripParam::UnknownOverCap { len: 4097 });
    assert_eq!(r.trips[0].reason, TripReason::InputTooLarge);
    // An oversized value under a short unknown key keeps the key digest.
    let r = fixture().normalize(&req(&[("x", text(&"v".repeat(4097)))])).unwrap_err();
    assert_eq!(r.outcome, GateOutcome::TerminalBreach);
    assert!(matches!(&r.trips[0].param, TripParam::Unknown { len: 1, .. }));
}
