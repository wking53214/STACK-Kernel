//! Measured comparison: a violation at offset 0 versus at the end of a
//! 64 KiB input. Reports ratios; asserts only deterministic facts, because a
//! wall-clock bound would flake on a shared machine.
//!
//! Run with `cargo test -p tack-inlet --release --test timing -- --nocapture`
//! to see the numbers from an optimised build.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::hint::black_box;
use std::time::{Duration, Instant};

use stack_inlet::{Inlet, InletConfig, Reason};

const LEN: usize = 64 * 1024;
const ROUNDS: usize = 61;
const PER_ROUND: usize = 4;

fn median(mut v: Vec<Duration>) -> Duration {
    v.sort_unstable();
    v[v.len() / 2]
}

fn time(inlet: &Inlet, input: &[u8]) -> Duration {
    let t = Instant::now();
    for _ in 0..PER_ROUND {
        black_box(inlet.winnow(black_box(input)));
    }
    t.elapsed() / PER_ROUND as u32
}

#[test]
fn rejection_time_depends_on_length_not_position() {
    let inlet = Inlet::new(InletConfig::default()).unwrap();
    let mut early = vec![b'a'; LEN];
    early[0] = 0x01;
    let mut late = vec![b'a'; LEN];
    late[LEN - 1] = 0x01;
    let clean = vec![b'a'; LEN];

    // Deterministic facts: same verdict shape, and every byte scanned in both.
    let ve = inlet.winnow(&early);
    let vl = inlet.winnow(&late);
    assert_eq!(ve.reason(), Some(Reason::C0Control));
    assert_eq!(vl.reason(), Some(Reason::C0Control));
    assert_eq!(ve.first_offset(), Some(0));
    assert_eq!(vl.first_offset(), Some(LEN - 1));
    assert_eq!(ve.scanned(), LEN);
    assert_eq!(vl.scanned(), LEN);

    // Warm up, then interleave so drift hits all inputs equally.
    for _ in 0..8 {
        black_box(inlet.winnow(&early));
        black_box(inlet.winnow(&late));
        black_box(inlet.winnow(&clean));
    }
    let (mut te, mut tl, mut tc, mut tx) = (Vec::new(), Vec::new(), Vec::new(), Vec::new());
    for _ in 0..ROUNDS {
        te.push(time(&inlet, &early));
        tl.push(time(&inlet, &late));
        tc.push(time(&inlet, &clean));
        // Counterfactual: what early exit would cost, i.e. stopping right
        // after the offending byte at offset 0.
        tx.push(time(&inlet, &early[..1]));
    }
    let (me, ml, mc, mx) = (median(te), median(tl), median(tc), median(tx));
    let ratio = me.as_secs_f64() / ml.as_secs_f64();
    let early_exit_ratio = mx.as_secs_f64() / ml.as_secs_f64();
    println!(
        "stack-inlet timing ({} build, {LEN} bytes, median of {ROUNDS} rounds x {PER_ROUND}):",
        if cfg!(debug_assertions) {
            "debug"
        } else {
            "release"
        }
    );
    println!("  violation at offset 0:        {me:?}");
    println!("  violation at offset {}:    {ml:?}", LEN - 1);
    println!("  no violation:                 {mc:?}");
    println!("  ratio offset0 / end:          {ratio:.3}");
    println!("  early-exit counterfactual:    {mx:?} (ratio to end {early_exit_ratio:.5})");
    println!(
        "  throughput (winnow incl. SHA-256): {:.1} MiB/s",
        LEN as f64 / ml.as_secs_f64() / (1024.0 * 1024.0)
    );
    assert!(ratio.is_finite());
}
