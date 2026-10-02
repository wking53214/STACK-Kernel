//! Spec and bumper construction: alias collisions, bands, caps.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use stack_bumpers::{
    Bumper, BumperConfig, EnumSpec, NumericSpec, ParamSpec, SpecError, StringSpec, TrimPolicy, UnitScale,
    VariantSpec,
};

#[test]
fn alias_colliding_with_another_canonical_is_rejected() {
    let e = EnumSpec::new([VariantSpec::new("high"), VariantSpec::new("low").alias("high")]).unwrap_err();
    assert_eq!(
        e,
        SpecError::AliasCollision {
            first: "high".into(),
            second: "high".into()
        }
    );
}

#[test]
fn alias_colliding_under_case_folding_is_rejected() {
    let e = EnumSpec::new([VariantSpec::new("high").alias("H"), VariantSpec::new("hot").alias("h")]).unwrap_err();
    assert_eq!(
        e,
        SpecError::AliasCollision {
            first: "H".into(),
            second: "h".into()
        }
    );
}

#[test]
fn two_canonicals_differing_only_in_case_are_rejected() {
    let e = EnumSpec::new([VariantSpec::new("High"), VariantSpec::new("HIGH")]).unwrap_err();
    assert!(matches!(e, SpecError::AliasCollision { .. }));
}

#[test]
fn alias_duplicating_its_own_canonical_is_rejected() {
    let e = EnumSpec::new([VariantSpec::new("high").alias("HIGH")]).unwrap_err();
    assert!(matches!(e, SpecError::AliasCollision { .. }));
}

#[test]
fn same_alias_on_two_variants_is_rejected() {
    let e = EnumSpec::new([VariantSpec::new("a").alias("x"), VariantSpec::new("b").alias("x")]).unwrap_err();
    assert!(matches!(e, SpecError::AliasCollision { .. }));
}

#[test]
fn non_ascii_names_that_differ_only_in_unicode_case_do_not_collide() {
    // Only ASCII is folded, so these are distinct names and both are legal.
    assert!(EnumSpec::new([VariantSpec::new("\u{e9}"), VariantSpec::new("\u{c9}")]).is_ok());
}

#[test]
fn empty_and_untrimmed_names_are_rejected() {
    assert_eq!(EnumSpec::new([]).unwrap_err(), SpecError::EmptyEnum);
    assert_eq!(EnumSpec::new([VariantSpec::new("")]).unwrap_err(), SpecError::EmptyName);
    assert!(matches!(
        EnumSpec::new([VariantSpec::new("a").alias(" b")]).unwrap_err(),
        SpecError::UntrimmedName { .. }
    ));
}

#[test]
fn numeric_band_order_and_finiteness() {
    assert!(NumericSpec::new(0.0, 0.0, 0.0, 0.0).is_ok());
    assert_eq!(NumericSpec::new(0.0, -1.0, 1.0, 2.0).unwrap_err(), SpecError::BandOrder);
    assert_eq!(NumericSpec::new(0.0, 2.0, 1.0, 3.0).unwrap_err(), SpecError::BandOrder);
    assert_eq!(NumericSpec::new(0.0, 1.0, 2.0, 1.5).unwrap_err(), SpecError::BandOrder);
    for bad in [f64::NAN, f64::INFINITY, f64::NEG_INFINITY] {
        assert_eq!(NumericSpec::new(bad, 0.0, 1.0, 2.0).unwrap_err(), SpecError::NonFiniteBound);
        assert_eq!(NumericSpec::new(-1.0, 0.0, 1.0, bad).unwrap_err(), SpecError::NonFiniteBound);
    }
}

#[test]
fn unit_table_validation() {
    let base = || NumericSpec::new(0.0, 0.0, 1.0, 1.0).unwrap();
    assert!(matches!(
        base().with_units("s", &[("s", UnitScale::Divide(1.0))]).unwrap_err(),
        SpecError::DuplicateUnit { .. }
    ));
    assert!(matches!(
        base()
            .with_units("s", &[("ms", UnitScale::Divide(1e3)), ("ms", UnitScale::Divide(1e3))])
            .unwrap_err(),
        SpecError::DuplicateUnit { .. }
    ));
    for bad in [0.0, -1.0, f64::NAN, f64::INFINITY, f64::from_bits(1)] {
        assert!(matches!(
            base().with_units("s", &[("x", UnitScale::Multiply(bad))]).unwrap_err(),
            SpecError::InvalidUnitScale { .. }
        ));
    }
    assert_eq!(base().with_units("", &[]).unwrap_err(), SpecError::EmptyName);
}

#[test]
fn string_zero_max_len_is_rejected() {
    assert_eq!(StringSpec::new(0, TrimPolicy::Trim).unwrap_err(), SpecError::ZeroMaxLen);
}

#[test]
fn bumper_rejects_duplicate_params() {
    let s = || StringSpec::new(4, TrimPolicy::Preserve).unwrap();
    let e = Bumper::new(BumperConfig::default(), [ParamSpec::required("a", s()), ParamSpec::optional("a", s())]).unwrap_err();
    assert_eq!(e, SpecError::DuplicateParam { name: "a".into() });
}

#[test]
fn bumper_enforces_caps_on_specs() {
    let cfg = BumperConfig {
        max_params: 1,
        max_name_bytes: 4,
        max_enum_names: 2,
        max_units: 1,
        max_input_bytes: 8,
        ..BumperConfig::default()
    };
    let s = || StringSpec::new(4, TrimPolicy::Preserve).unwrap();
    assert_eq!(
        Bumper::new(cfg, [ParamSpec::required("a", s()), ParamSpec::required("b", s())]).unwrap_err(),
        SpecError::TooManyParams { max: 1 }
    );
    assert!(matches!(
        Bumper::new(cfg, [ParamSpec::required("abcde", s())]).unwrap_err(),
        SpecError::NameTooLong { len: 5, max: 4 }
    ));
    assert!(matches!(
        Bumper::new(
            cfg,
            [ParamSpec::required("e", EnumSpec::new([VariantSpec::new("a").alias("b").alias("c")]).unwrap())]
        )
        .unwrap_err(),
        SpecError::TooManyEnumNames { count: 3, .. }
    ));
    assert!(matches!(
        Bumper::new(
            cfg,
            [ParamSpec::required("e", EnumSpec::new([VariantSpec::new("abcdefg")]).unwrap())]
        )
        .unwrap_err(),
        SpecError::NameTooLong { .. }
    ));
    assert!(matches!(
        Bumper::new(
            cfg,
            [ParamSpec::required(
                "n",
                NumericSpec::new(0.0, 0.0, 1.0, 1.0)
                    .unwrap()
                    .with_units("s", &[("ms", UnitScale::Divide(1e3))])
                    .unwrap()
            )]
        )
        .unwrap_err(),
        SpecError::TooManyUnits { count: 2, .. }
    ));
    assert!(matches!(
        Bumper::new(cfg, [ParamSpec::required("t", StringSpec::new(9, TrimPolicy::Trim).unwrap())]).unwrap_err(),
        SpecError::StringCapAboveInputCap { .. }
    ));
    assert!(matches!(
        Bumper::new(cfg, [ParamSpec::required(" t", s())]).unwrap_err(),
        SpecError::UntrimmedName { .. }
    ));
}

#[test]
fn bumper_rejects_invalid_config() {
    let cfg = BumperConfig {
        max_params: 0,
        ..BumperConfig::default()
    };
    assert!(matches!(Bumper::new(cfg, []).unwrap_err(), SpecError::InvalidConfig(_)));
}

#[test]
fn bumper_position_is_alpha() {
    assert_eq!(Bumper::POSITION, tack_bumpers::GatePosition::Alpha);
}
