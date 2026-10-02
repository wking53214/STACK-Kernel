//! Fast statistical smoke test, calibrated at the same n.
//!
//! This runs in whatever profile `cargo test` uses (normally debug), so its
//! timings are NOT evidence; `examples/verify.rs` in release mode is. What
//! this test checks is that the measurement setup works at this n: the
//! known-leaky harness victim is flagged, the known-good one is not, the
//! early-exit gate is flagged, and the constant-time gate is not.
//!
//! Classes: A = wrong at byte 0 (fastest early exit), B = wrong at byte 31
//! (slowest wrong path). Timed: the whole `PipelineGate::check`, admission
//! to decision, which is what the attacker sees.

#![allow(clippy::unwrap_used, clippy::panic)] // test code: failures should abort the test

use sstack_anc_harness::victim::{ct_validate, leaky_validate};
use sstack_anc_harness::{measure_pair, Class, MeasureConfig, Report, SplitMix64, T_THRESHOLD};
use sstack_anc_pipeline::{PipelineConfig, PipelineGate, TokenSecret, Validator, TOKEN_LEN};

const PER_CLASS: usize = 20_000;

// Test fixture, not a key.
const SECRET: [u8; TOKEN_LEN] = [0x42; TOKEN_LEN];

fn candidate(class: Class, rng: &mut SplitMix64) -> [u8; TOKEN_LEN] {
    let mut c = SECRET;
    let flip = (rng.next_u64() as u8) | 1; // never zero
    match class {
        Class::A => c[0] ^= flip,
        Class::B => c[TOKEN_LEN - 1] ^= flip,
    }
    c
}

fn run(op: impl FnMut(&[u8; TOKEN_LEN]) -> bool) -> Report {
    let cfg = MeasureConfig::with_samples(2 * PER_CLASS);
    let mut op = op;
    measure_pair(&cfg, candidate, |c| op(c)).unwrap()
}

fn gate(validator: Validator) -> PipelineGate {
    let cfg = PipelineConfig {
        validator,
        allow_leaky_validators: true,
        ..PipelineConfig::default()
    };
    PipelineGate::new(TokenSecret::from_bytes(&SECRET).unwrap(), cfg).unwrap()
}

#[test]
fn calibrated_leak_check() {
    let leaky = run(|c| leaky_validate(&SECRET, c));
    let ct = run(|c| ct_validate(&SECRET, c));
    let lv = leaky.verdict(T_THRESHOLD);
    let cv = ct.verdict(T_THRESHOLD);
    assert!(
        lv.is_leak(),
        "calibration failed: leaky victim not flagged {lv:?}"
    );
    assert!(cv.is_pass(), "calibration failed: ct victim flagged {cv:?}");

    let early = gate(Validator::EarlyExit);
    let r_early = run(|c| early.check(c).is_ok());
    let v_early = r_early.verdict(T_THRESHOLD);
    assert!(
        v_early.is_leak(),
        "early_exit gate should leak: {v_early:?}"
    );

    let ctg = gate(Validator::ConstantTime);
    let r_ct = run(|c| ctg.check(c).is_ok());
    let v_ct = r_ct.verdict(T_THRESHOLD);
    assert!(
        v_ct.is_pass(),
        "constant_time gate flagged: {v_ct:?} t_raw={:?} t2={:?} crops={:?}",
        r_ct.t_raw,
        r_ct.t_second_order,
        r_ct.cropped
    );

    // balanced_dummy is reported, not asserted: in a debug build the
    // result says little about release behaviour.
    let bd = gate(Validator::BalancedDummy);
    let r_bd = run(|c| bd.check(c).is_ok());
    eprintln!(
        "debug-build smoke at n={PER_CLASS}/class: leaky max|t|={:.1} ct={:.2} \
         early_exit={:.1} constant_time={:.2} balanced_dummy={:.2}",
        leaky.max_abs_t, ct.max_abs_t, r_early.max_abs_t, r_ct.max_abs_t, r_bd.max_abs_t
    );
}
