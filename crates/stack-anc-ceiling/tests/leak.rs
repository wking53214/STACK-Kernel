//! Statistical check, small n, debug build: the ceiling-padded leaky
//! validator is not distinguishable, and the same harness at the same n
//! does flag the unpadded one (calibration). Debug-mode timings are not
//! evidence; the reported numbers come from `examples/verify.rs` in release
//! mode. This test only guards against regressions.
//!
//! Classes (theorist's primary pair): A = candidate differs from the secret
//! at byte 0 (fastest early exit), B = equal in bytes 0..30, differs at
//! byte 31 (slowest wrong path).
#![allow(clippy::unwrap_used)]

use std::time::Duration;
use sstack_anc_ceiling::{CeilingConfig, CeilingPad, SpinBudgetConfig, WaitMode};
use sstack_anc_harness::victim::{ct_validate, leaky_validate, TOKEN_LEN};
use sstack_anc_harness::{measure_pair, Class, MeasureConfig, Report, T_THRESHOLD};

/// Samples per class.
const N_PER_CLASS: usize = 20_000;
/// Crop line (dudect uses 10 for the many cropped tests).
const CROP_LINE: f64 = 10.0;

fn fixture() -> ([u8; TOKEN_LEN], [u8; TOKEN_LEN], [u8; TOKEN_LEN]) {
    // Test fixture token, not a key.
    let secret: [u8; TOKEN_LEN] = core::array::from_fn(|i| (i as u8).wrapping_mul(37) ^ 0x5a);
    let mut a = secret;
    a[0] ^= 0xff;
    let mut b = secret;
    b[TOKEN_LEN - 1] ^= 0xff;
    (secret, a, b)
}

fn cfg() -> MeasureConfig {
    MeasureConfig {
        warmup: 2_000,
        seed: 0x00ce_111e_0001,
        ..MeasureConfig::with_samples(2 * N_PER_CLASS)
    }
}

fn max_first_order(r: &Report) -> f64 {
    let mut m = r.t_raw.map_or(0.0, f64::abs);
    for c in &r.cropped {
        if let Some(t) = c.t {
            m = m.max(t.abs());
        }
    }
    m
}

#[test]
fn calibrated_spin_padding_hides_the_early_exit() {
    let (secret, a, b) = fixture();
    let prepare = |c: Class, _: &mut stack_anc_harness::SplitMix64| match c {
        Class::A => a,
        Class::B => b,
    };

    // Calibration at the same n.
    let leaky = measure_pair(&cfg(), prepare, |cand| leaky_validate(&secret, cand)).unwrap();
    assert!(
        max_first_order(&leaky) > T_THRESHOLD,
        "calibration failed: unpadded leaky not flagged: {leaky:?}"
    );
    let ct = measure_pair(&cfg(), prepare, |cand| ct_validate(&secret, cand)).unwrap();
    assert!(
        ct.max_abs_t < CROP_LINE && ct.t_raw.unwrap().abs() < T_THRESHOLD,
        "calibration failed: constant-time control flagged: {ct:?}"
    );

    let pad = CeilingPad::new(CeilingConfig {
        mode: WaitMode::Spin,
        spin_budget: SpinBudgetConfig::Unlimited,
        ..CeilingConfig::new(Duration::from_micros(50))
    })
    .unwrap();
    let padded = measure_pair(&cfg(), prepare, |cand| {
        pad.pad(|| leaky_validate(&secret, cand)).map(|p| p.value)
    })
    .unwrap();
    let t_raw = padded.t_raw.unwrap().abs();
    let t2 = padded.t_second_order.unwrap().abs();
    let crop_max = padded
        .cropped
        .iter()
        .filter_map(|c| c.t)
        .fold(0.0f64, |m, t| m.max(t.abs()));
    assert!(t_raw < T_THRESHOLD, "first-order leak: {padded:?}");
    assert!(t2 < T_THRESHOLD, "second-order leak: {padded:?}");
    assert!(crop_max < CROP_LINE, "cropped leak: {padded:?}");
    assert!(padded.a.median.unwrap() >= 50_000.0);
}
