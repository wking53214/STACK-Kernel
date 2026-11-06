#![allow(clippy::unwrap_used)]
use std::hint::black_box;
use std::time::{Duration, Instant};
use stack_anc_ceiling::{CeilingConfig, CeilingPad, SpinBudgetConfig, WaitMode};
use stack_anc_harness::victim::{ct_validate, leaky_validate, TOKEN_LEN};
use stack_anc_harness::{measure_pair, Class, MeasureConfig};

fn cfg() -> MeasureConfig {
    MeasureConfig { warmup: 2_000, seed: 0x00ce_111e_0001, ..MeasureConfig::with_samples(40_000) }
}

#[test]
fn diag_ci_cropped() {
    let mut minstep = u128::MAX;
    let mut last = Instant::now();
    for _ in 0..200_000 {
        let n = Instant::now();
        let d = n.duration_since(last).as_nanos();
        if d > 0 && d < minstep { minstep = d; }
        last = n;
    }
    let secret: [u8; TOKEN_LEN] = core::array::from_fn(|i| (i as u8).wrapping_mul(37) ^ 0x5a);
    let mut a = secret; a[0] ^= 0xff;
    let mut b = secret; b[TOKEN_LEN - 1] ^= 0xff;
    let prepare = |c: Class, _: &mut stack_anc_harness::SplitMix64| match c { Class::A => a, Class::B => b };
    let _cal1 = measure_pair(&cfg(), prepare, |cand| leaky_validate(&secret, cand)).unwrap();
    let _cal2 = measure_pair(&cfg(), prepare, |cand| ct_validate(&secret, cand)).unwrap();
    let pad = CeilingPad::new(CeilingConfig {
        mode: WaitMode::Spin,
        spin_budget: SpinBudgetConfig::Unlimited,
        ..CeilingConfig::new(Duration::from_micros(50))
    }).unwrap();
    let leaky = measure_pair(&cfg(), prepare, |cand| pad.pad(|| leaky_validate(&secret, cand)).map(|p| p.value)).unwrap();
    let noop = measure_pair(&cfg(), prepare, |cand| pad.pad(|| black_box(cand[0])).map(|p| p.value)).unwrap();
    panic!("DIAG clock_min_step_ns={minstep}\nDIAG LEAKY {leaky:?}\nDIAG NOOP {noop:?}");
}
