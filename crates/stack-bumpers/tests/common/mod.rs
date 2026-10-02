//! Shared test fixtures. Not every test file uses every helper.
#![allow(dead_code, clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::collections::BTreeMap;

use stack_bumpers::{
    Bumper, BumperConfig, EnumSpec, NumericSpec, ParamSpec, ParamValue, StringSpec, TrimPolicy, UnitScale,
    VariantSpec,
};

/// A bumper with one parameter of each shape:
/// - `timeout`: seconds, hard [0, 300], soft [0.5, 30], alternates ms and min.
/// - `priority`: low, medium (alias "med"), high (alias "hi").
/// - `label`: optional, trimmed, max 16 bytes.
/// - `tenant`: optional, whitespace rejected, max 8 bytes.
/// - `ratio`: optional, hard [-1, 1], soft [-0.5, 0.5].
pub fn fixture() -> Bumper {
    fixture_with(BumperConfig::default())
}

pub fn fixture_with(config: BumperConfig) -> Bumper {
    Bumper::new(
        config,
        [
            ParamSpec::required(
                "timeout",
                NumericSpec::new(0.0, 0.5, 30.0, 300.0)
                    .unwrap()
                    .with_units(
                        "s",
                        &[("ms", UnitScale::Divide(1000.0)), ("min", UnitScale::Multiply(60.0))],
                    )
                    .unwrap(),
            ),
            ParamSpec::required(
                "priority",
                EnumSpec::new([
                    VariantSpec::new("low"),
                    VariantSpec::new("medium").alias("med"),
                    VariantSpec::new("high").alias("hi"),
                ])
                .unwrap(),
            ),
            ParamSpec::optional("label", StringSpec::new(16, TrimPolicy::Trim).unwrap()),
            ParamSpec::optional("tenant", StringSpec::new(8, TrimPolicy::Reject).unwrap()),
            ParamSpec::optional("ratio", NumericSpec::new(-1.0, -0.5, 0.5, 1.0).unwrap()),
        ],
    )
    .unwrap()
}

pub fn num(x: f64) -> ParamValue {
    ParamValue::Number(x)
}

pub fn qty(x: f64, unit: &str) -> ParamValue {
    ParamValue::Quantity {
        value: x,
        unit: unit.to_owned(),
    }
}

pub fn text(s: &str) -> ParamValue {
    ParamValue::Text(s.to_owned())
}

/// A request that passes with no corrections, then overridden by `extra`.
pub fn req(extra: &[(&str, ParamValue)]) -> BTreeMap<String, ParamValue> {
    let mut m = BTreeMap::new();
    m.insert("timeout".to_owned(), num(5.0));
    m.insert("priority".to_owned(), text("low"));
    for (k, v) in extra {
        m.insert((*k).to_owned(), v.clone());
    }
    m
}
