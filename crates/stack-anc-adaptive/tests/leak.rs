//! Statistical check at small n (fast enough for `cargo test`): the harness
//! is calibrated at this n, the naive controller leaks, the epoch
//! controller does not at this n. The reported numbers come from
//! `examples/verify.rs` in release mode, not from here.
#![allow(clippy::unwrap_used, clippy::panic)] // test code: failures should abort the test

mod common;

use common::{ms, spin_for, us};
use sstack_anc_adaptive::{
    AdaptivePad, EpochConfig, NaiveConfig, PadConfig, SpinBudgetConfig, WaitMode, WindowStatistic,
};
use sstack_anc_harness::victim::{ct_validate, leaky_validate, TOKEN_LEN};
use sstack_anc_harness::{measure_pair, Class, MeasureConfig, Report, T_THRESHOLD};

/// Samples per class. Calibration below is checked at this same n.
const N_PER_CLASS: usize = 2_000;

type Token = [u8; TOKEN_LEN];

/// Test fixtures, not keys: the secret, a guess wrong at byte 0 (class A,
/// fastest early exit) and a guess wrong only at byte 31 (class B, slowest
/// wrong path).
fn tokens() -> (Token, Token, Token) {
    let secret = [0x5au8; TOKEN_LEN];
    let mut a = secret;
    a[0] ^= 0xff;
    let mut b = secret;
    b[TOKEN_LEN - 1] ^= 0xff;
    (secret, a, b)
}

fn cfg() -> MeasureConfig {
    MeasureConfig {
        warmup: 200,
        ..MeasureConfig::with_samples(2 * N_PER_CLASS)
    }
}

fn run(op: impl FnMut(&Token) -> bool) -> Report {
    let (_, a, b) = tokens();
    measure_pair(
        &cfg(),
        |class, _| match class {
            Class::A => a,
            Class::B => b,
        },
        op,
    )
    .unwrap()
}

/// The secret-dependent victim for the padded runs: `leaky_validate`, then
/// work proportional to the matched prefix (4 us per matching byte on top
/// of 40 us), so class A takes about 40 us and class B about 164 us. The
/// amplification keeps the test fast and robust in a debug build.
fn amplified(secret: &Token, cand: &Token) -> bool {
    let ok = leaky_validate(secret, cand);
    let prefix = secret.iter().zip(cand).take_while(|(x, y)| x == y).count() as u64;
    spin_for(us(40 + 4 * prefix));
    ok
}

#[test]
fn calibrated_naive_leaks_epoch_does_not() {
    let (secret, _, _) = tokens();

    // Calibration at this n: the leaky victim must be flagged, the
    // constant-time one must not. Otherwise the run proves nothing.
    let leaky = run(|c| leaky_validate(&secret, c));
    assert!(
        leaky.verdict(T_THRESHOLD).is_leak(),
        "calibration failed: {leaky:?}"
    );
    let ct = run(|c| ct_validate(&secret, c));
    assert!(
        !ct.verdict(T_THRESHOLD).is_leak(),
        "calibration failed: {ct:?}"
    );

    // Naive, mean of a mixed window plus 20 us: about 122 us, below class
    // B's 164 us, so class B is released late (leak 1).
    let naive = AdaptivePad::naive(
        PadConfig::default(),
        NaiveConfig {
            statistic: WindowStatistic::Mean,
            window: 64,
            margin: us(20),
            ..NaiveConfig::new(ms(2))
        },
    )
    .unwrap();
    let r = run(|c| {
        naive
            .pad(|| amplified(&secret, c))
            .map(|p| p.value)
            .unwrap_or(false)
    });
    let v = r.verdict(T_THRESHOLD);
    assert!(v.is_leak(), "naive should leak: {v:?} {r:?}");

    // Epoch, Hybrid with a 150 us tail (unlimited budget: a test-only
    // setting). A Hybrid request needs work + tail, at most 314 us here, so
    // the 512 us floor covers both classes and both sleep, then spin.
    let epoch = AdaptivePad::epoch(
        PadConfig {
            mode: WaitMode::Hybrid,
            spin_tail: us(150),
            spin_budget: SpinBudgetConfig::Unlimited,
            ..PadConfig::default()
        },
        EpochConfig {
            initial_level: 0,
            ..EpochConfig::new(us(512), ms(8))
        },
    )
    .unwrap();
    let r = run(|c| {
        epoch
            .pad(|| amplified(&secret, c))
            .map(|p| p.value)
            .unwrap_or(false)
    });
    let v = r.verdict(T_THRESHOLD);
    assert!(
        v.is_pass(),
        "epoch should not be detected at this n: {v:?} {r:?}"
    );
}
