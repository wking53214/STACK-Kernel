//! NaN, infinities, negative zero and subnormal values.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use common::{fixture, num, qty, req};
use tack_bumpers::{
    Bumper, BumperConfig, CorrectionKind, GateOutcome, NumericSpec, ParamSpec, ParamValue, SoftEdge, TripReason,
};

fn nans() -> Vec<f64> {
    // NaN produced by arithmetic at run time, as it would be upstream.
    let (zero_a, zero_b) = (std::hint::black_box(0.0f64), std::hint::black_box(0.0f64));
    let (inf_a, inf_b) = (std::hint::black_box(f64::INFINITY), std::hint::black_box(f64::INFINITY));
    vec![
        f64::NAN,
        -f64::NAN,
        f64::from_bits(0x7ff0_0000_0000_0001), // signalling NaN pattern
        f64::from_bits(0xfff8_dead_beef_0001), // negative NaN with payload
        zero_a / zero_b,
        inf_a - inf_b,
    ]
}

#[test]
fn every_nan_is_terminal_and_never_clamped() {
    for x in nans() {
        assert!(x.is_nan());
        for key in ["timeout", "ratio"] {
            let r = fixture().normalize(&req(&[(key, num(x))])).unwrap_err();
            assert_eq!(r.outcome, GateOutcome::TerminalBreach, "{key} {x:?}");
            assert!(r.has(TripReason::NonFinite));
        }
    }
}

#[test]
fn nan_quantity_is_terminal_even_with_a_valid_unit() {
    let r = fixture().normalize(&req(&[("timeout", qty(f64::NAN, "ms"))])).unwrap_err();
    assert_eq!(r.outcome, GateOutcome::TerminalBreach);
    assert!(r.has(TripReason::NonFinite));
}

#[test]
fn nan_quantity_with_unknown_unit_is_still_terminal() {
    let r = fixture().normalize(&req(&[("timeout", qty(f64::NAN, "furlongs"))])).unwrap_err();
    assert_eq!(r.outcome, GateOutcome::TerminalBreach);
    assert!(r.has(TripReason::NonFinite));
}

#[test]
fn infinities_are_terminal() {
    for x in [f64::INFINITY, f64::NEG_INFINITY] {
        let r = fixture().normalize(&req(&[("timeout", num(x))])).unwrap_err();
        assert_eq!(r.outcome, GateOutcome::TerminalBreach);
        assert!(r.has(TripReason::NonFinite));
        let r = fixture().normalize(&req(&[("timeout", qty(x, "ms"))])).unwrap_err();
        assert!(r.has(TripReason::NonFinite));
    }
}

#[test]
fn negative_zero_is_canonicalized_without_a_correction() {
    // ratio: hard [-1, 1], soft [-0.5, 0.5]. -0.0 == 0.0 is inside.
    let n = fixture().normalize(&req(&[("ratio", num(-0.0))])).unwrap();
    let v = n.get("ratio").unwrap().as_f64().unwrap();
    assert_eq!(v, 0.0);
    assert!(v.is_sign_positive(), "output must be +0.0");
    assert!(n.corrections().is_empty(), "-0.0 to +0.0 is not a value change");
}

#[test]
fn negative_zero_below_a_positive_soft_min_is_clamped() {
    // timeout: hard [0, 300], soft [0.5, 30]. -0.0 equals hard_min 0.0.
    let n = fixture().normalize(&req(&[("timeout", num(-0.0))])).unwrap();
    assert_eq!(n.get("timeout").unwrap().as_f64(), Some(0.5));
    assert_eq!(
        n.corrections()[0].kind,
        CorrectionKind::Clamped {
            from: 0.0,
            to: 0.5,
            edge: SoftEdge::Min
        }
    );
}

#[test]
fn negative_zero_is_idempotent_bitwise() {
    let b = fixture();
    let once = b.normalize(&req(&[("ratio", num(-0.0))])).unwrap();
    let twice = b.normalize(&once.to_input()).unwrap();
    let a = once.get("ratio").unwrap().as_f64().unwrap();
    let c = twice.get("ratio").unwrap().as_f64().unwrap();
    assert_eq!(a.to_bits(), c.to_bits());
}

#[test]
fn subnormals_inside_the_band_pass_unchanged() {
    for x in [f64::from_bits(1), -f64::from_bits(1), f64::MIN_POSITIVE / 2.0] {
        assert!(x.is_subnormal());
        let n = fixture().normalize(&req(&[("ratio", num(x))])).unwrap();
        assert_eq!(n.get("ratio").unwrap().as_f64().unwrap().to_bits(), x.to_bits());
        assert!(n.corrections().is_empty());
    }
}

#[test]
fn subnormal_below_soft_min_is_clamped_not_flushed() {
    // timeout soft_min is 0.5; a subnormal is inside the hard band [0, 300].
    let x = f64::from_bits(1);
    let n = fixture().normalize(&req(&[("timeout", num(x))])).unwrap();
    assert_eq!(n.get("timeout").unwrap().as_f64(), Some(0.5));
}

#[test]
fn negative_subnormal_below_hard_min_zero_is_terminal() {
    let x = -f64::from_bits(1);
    let r = fixture().normalize(&req(&[("timeout", num(x))])).unwrap_err();
    assert_eq!(r.outcome, GateOutcome::TerminalBreach);
    assert!(r.has(TripReason::OutsideHardBand));
}

#[test]
fn subnormal_bounds_are_honored() {
    let tiny = f64::from_bits(10);
    let spec = NumericSpec::new(0.0, tiny, tiny * 2.0, 1.0).unwrap();
    let b = Bumper::new(BumperConfig::default(), [ParamSpec::required("x", spec)]).unwrap();
    let mut m = std::collections::BTreeMap::new();
    m.insert("x".to_owned(), ParamValue::Number(f64::from_bits(1)));
    let n = b.normalize(&m).unwrap();
    assert_eq!(n.get("x").unwrap().as_f64(), Some(tiny));
}

#[test]
fn unit_conversion_into_subnormal_range_is_accepted() {
    // 1e-310 ms is a subnormal number of seconds once divided; timeout
    // hard_min is 0 so it is inside the hard band and clamps to 0.5.
    let n = fixture().normalize(&req(&[("timeout", qty(1e-310, "ms"))])).unwrap();
    assert_eq!(n.get("timeout").unwrap().as_f64(), Some(0.5));
}

#[test]
fn extreme_finite_values_outside_hard_band_are_terminal() {
    for x in [f64::MAX, f64::MIN, 300.000_000_000_1, -1e-300] {
        let r = fixture().normalize(&req(&[("timeout", num(x))])).unwrap_err();
        assert_eq!(r.outcome, GateOutcome::TerminalBreach, "{x:e}");
        assert!(r.has(TripReason::OutsideHardBand));
    }
}
