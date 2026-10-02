//! Property tests: idempotence, monotonicity, soft band containment,
//! and fail-closed handling of every f64.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use std::collections::BTreeMap;

use proptest::prelude::*;
use stack_bumpers::{
    Bumper, BumperConfig, EnumSpec, GateOutcome, NumericSpec, ParamSpec, ParamValue, StringSpec, TrimPolicy,
    TripReason, UnitScale, VariantSpec,
};

/// Four sorted finite bounds.
fn bands() -> impl Strategy<Value = [f64; 4]> {
    prop::array::uniform4(-1.0e9f64..1.0e9).prop_map(|mut a| {
        a.sort_by(f64::total_cmp);
        a
    })
}

fn numeric_bumper(b: [f64; 4], budget: u32) -> Bumper {
    let spec = NumericSpec::new(b[0], b[1], b[2], b[3])
        .unwrap()
        .with_units("s", &[("ms", UnitScale::Divide(1000.0))])
        .unwrap();
    Bumper::new(
        BumperConfig {
            correction_budget: budget,
            ..BumperConfig::default()
        },
        [ParamSpec::required("x", spec)],
    )
    .unwrap()
}

fn one(v: ParamValue) -> BTreeMap<String, ParamValue> {
    let mut m = BTreeMap::new();
    m.insert("x".to_owned(), v);
    m
}

fn out(b: &Bumper, v: ParamValue) -> Result<f64, tack_bumpers::Rejection> {
    b.normalize(&one(v)).map(|n| n.get("x").unwrap().as_f64().unwrap())
}

/// Any f64 at all, weighted toward the awkward classes.
fn any_f64() -> impl Strategy<Value = f64> {
    prop_oneof![
        any::<f64>(),
        Just(f64::NAN),
        Just(-f64::NAN),
        Just(f64::INFINITY),
        Just(f64::NEG_INFINITY),
        Just(-0.0),
        Just(0.0),
        proptest::num::f64::SUBNORMAL | proptest::num::f64::POSITIVE | proptest::num::f64::NEGATIVE,
        -2.0e9f64..2.0e9,
    ]
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(2048))]

    /// normalize(normalize(x)) == normalize(x), bit for bit, and the second
    /// pass makes no corrections.
    #[test]
    fn numeric_idempotent(b in bands(), x in any_f64(), as_ms in any::<bool>()) {
        let bumper = numeric_bumper(b, 3);
        let v = if as_ms { ParamValue::Quantity { value: x, unit: "ms".into() } } else { ParamValue::Number(x) };
        if let Ok(first) = bumper.normalize(&one(v)) {
            let second = bumper.normalize(&first.to_input()).unwrap();
            let a = first.get("x").unwrap().as_f64().unwrap();
            let c = second.get("x").unwrap().as_f64().unwrap();
            prop_assert_eq!(a.to_bits(), c.to_bits());
            prop_assert!(second.corrections().is_empty());
        }
    }

    /// x <= y implies n(x) <= n(y) for every accepted pair.
    #[test]
    fn numeric_monotone(b in bands(), t1 in 0.0f64..=1.0, t2 in 0.0f64..=1.0) {
        let bumper = numeric_bumper(b, 3);
        // Points inside the hard band, so both are accepted.
        let lerp = |t: f64| (b[0] + t * (b[3] - b[0])).clamp(b[0], b[3]);
        let (x, y) = { let (p, q) = (lerp(t1), lerp(t2)); if p <= q { (p, q) } else { (q, p) } };
        let nx = out(&bumper, ParamValue::Number(x)).unwrap();
        let ny = out(&bumper, ParamValue::Number(y)).unwrap();
        prop_assert!(nx <= ny, "x={x} y={y} nx={nx} ny={ny}");
    }

    /// Monotonicity over arbitrary f64 pairs, where either may be refused.
    #[test]
    fn numeric_monotone_any(b in bands(), x in any_f64(), y in any_f64()) {
        let bumper = numeric_bumper(b, 3);
        if let (Ok(nx), Ok(ny)) = (out(&bumper, ParamValue::Number(x)), out(&bumper, ParamValue::Number(y))) {
            if x <= y { prop_assert!(nx <= ny); }
            if y <= x { prop_assert!(ny <= nx); }
        }
    }

    /// Every accepted value lies in the soft band. A correction never moves
    /// a value outside it. Every refused value is RETRY or TERMINAL_BREACH.
    #[test]
    fn accepted_values_lie_in_soft_band(b in bands(), x in any_f64(), as_ms in any::<bool>()) {
        let bumper = numeric_bumper(b, 3);
        let v = if as_ms { ParamValue::Quantity { value: x, unit: "ms".into() } } else { ParamValue::Number(x) };
        match bumper.normalize(&one(v)) {
            Ok(n) => {
                let o = n.get("x").unwrap().as_f64().unwrap();
                prop_assert!(o.is_finite());
                prop_assert!(o >= b[1] && o <= b[2], "out={o} soft=[{}, {}]", b[1], b[2]);
                prop_assert!(!(o == 0.0 && o.is_sign_negative()));
            }
            Err(r) => prop_assert_ne!(r.outcome, GateOutcome::Pass),
        }
    }

    /// NaN and infinities are never accepted, whatever the band.
    #[test]
    fn non_finite_is_always_terminal(b in bands(), neg in any::<bool>(), which in 0u8..3) {
        let bumper = numeric_bumper(b, 3);
        let x = match which { 0 => f64::NAN, 1 => f64::INFINITY, _ => f64::from_bits(0x7ff4_0000_0000_0000) };
        let x = if neg { -x } else { x };
        let r = out(&bumper, ParamValue::Number(x)).unwrap_err();
        prop_assert_eq!(r.outcome, GateOutcome::TerminalBreach);
        prop_assert!(r.has(TripReason::NonFinite));
    }

    /// Values inside the soft band pass untouched. Values between the soft
    /// and hard edges clamp to exactly the nearer soft edge. Values past the
    /// hard edges are TERMINAL_BREACH.
    #[test]
    fn band_regions(b in bands(), x in -2.0e9f64..2.0e9) {
        let bumper = numeric_bumper(b, 3);
        let r = out(&bumper, ParamValue::Number(x));
        if x < b[0] || x > b[3] {
            prop_assert_eq!(r.unwrap_err().outcome, GateOutcome::TerminalBreach);
        } else if x < b[1] {
            prop_assert_eq!(r.unwrap(), b[1]);
        } else if x > b[2] {
            prop_assert_eq!(r.unwrap(), b[2]);
        } else {
            prop_assert_eq!(r.unwrap().to_bits(), (x + 0.0).to_bits());
        }
    }

    /// Enum normalization is idempotent over messy inputs built from the
    /// declared names with random case and whitespace.
    #[test]
    fn enum_idempotent(pick in 0usize..5, upper in prop::collection::vec(any::<bool>(), 0..8),
                       lead in "[ \t]{0,3}", trail in "[ \t]{0,3}", junk in "[a-zA-Z ]{0,6}", use_junk in any::<bool>()) {
        let names = ["low", "medium", "med", "high", "hi"];
        let bumper = Bumper::new(BumperConfig { correction_budget: 10, ..BumperConfig::default() }, [
            ParamSpec::required("x", EnumSpec::new([
                VariantSpec::new("low"),
                VariantSpec::new("medium").alias("med"),
                VariantSpec::new("high").alias("hi"),
            ]).unwrap()),
        ]).unwrap();
        let core: String = if use_junk { junk } else {
            names[pick].chars().enumerate()
                .map(|(i, c)| if upper.get(i).copied().unwrap_or(false) { c.to_ascii_uppercase() } else { c })
                .collect()
        };
        let input = format!("{lead}{core}{trail}");
        if let Ok(first) = bumper.normalize(&one(ParamValue::Text(input))) {
            let second = bumper.normalize(&first.to_input()).unwrap();
            prop_assert_eq!(first.values(), second.values());
            prop_assert!(second.corrections().is_empty());
            let v = first.get("x").unwrap().as_str().unwrap();
            prop_assert!(["low", "medium", "high"].contains(&v));
        }
    }

    /// String trim normalization is idempotent and never exceeds max_len.
    #[test]
    fn string_idempotent(s in "\\PC{0,40}", policy in 0u8..3) {
        let trim = match policy { 0 => TrimPolicy::Preserve, 1 => TrimPolicy::Trim, _ => TrimPolicy::Reject };
        let bumper = Bumper::new(BumperConfig::default(), [
            ParamSpec::required("x", StringSpec::new(24, trim).unwrap()),
        ]).unwrap();
        if let Ok(first) = bumper.normalize(&one(ParamValue::Text(s))) {
            let v = first.get("x").unwrap().as_str().unwrap();
            prop_assert!(v.len() <= 24);
            let second = bumper.normalize(&first.to_input()).unwrap();
            prop_assert_eq!(first.values(), second.values());
            prop_assert!(second.corrections().is_empty());
        }
    }

    /// The budget is exact: a request passes if and only if its corrections
    /// do not exceed the budget.
    #[test]
    fn budget_is_exact(budget in 0u32..4, clamps in 0usize..6) {
        let specs = (0..6).map(|i| ParamSpec::required(format!("p{i}"), NumericSpec::new(-10.0, 0.0, 1.0, 10.0).unwrap()));
        let bumper = Bumper::new(BumperConfig { correction_budget: budget, ..BumperConfig::default() }, specs).unwrap();
        let m: BTreeMap<String, ParamValue> = (0..6)
            .map(|i| (format!("p{i}"), ParamValue::Number(if i < clamps { 5.0 } else { 0.5 })))
            .collect();
        let r = bumper.normalize(&m);
        if clamps <= budget as usize {
            prop_assert_eq!(r.unwrap().corrections().len(), clamps);
        } else {
            let e = r.unwrap_err();
            prop_assert_eq!(e.outcome, GateOutcome::Retry);
            prop_assert!(e.has(TripReason::CorrectionBudgetExceeded));
        }
    }
}
