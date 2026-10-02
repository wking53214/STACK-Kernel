//! End-to-end timing: a deliberately leaky closure must be detected.
#![allow(clippy::unwrap_used, clippy::panic)] // test code: failures should abort the test

use std::time::{Duration, Instant};
use sstack_anc_harness::victim::{ct_validate, leaky_validate, TOKEN_LEN};
use sstack_anc_harness::{measure_pair, Class, MeasureConfig, Timer, T_THRESHOLD};

fn spin(d: Duration) {
    let start = Instant::now();
    while start.elapsed() < d {
        std::hint::spin_loop();
    }
}

fn leaky_spin_run(timer: Timer) {
    let cfg = MeasureConfig {
        warmup: 100,
        timer,
        ..MeasureConfig::with_samples(2_000)
    };
    let report = measure_pair(
        &cfg,
        |class, _rng| class,
        |class: &Class| {
            if *class == Class::B {
                spin(Duration::from_micros(20));
            }
        },
    )
    .unwrap();
    assert_eq!(report.n_a + report.n_b, 2_000);
    assert!(report.n_a > 800 && report.n_b > 800);
    assert!(report.max_abs_t > T_THRESHOLD, "{report:?}");
    assert!(
        report.t_raw.unwrap() < -T_THRESHOLD,
        "B is slower: {report:?}"
    );
    let v = report.verdict(T_THRESHOLD);
    assert!(v.is_leak(), "{v:?}");
    let run = report.run.as_ref().unwrap();
    assert_eq!(run.timer, timer);
    assert!(run.wall_seconds > 0.0);
}

#[test]
fn spin_20us_detected_with_instant() {
    leaky_spin_run(Timer::Instant);
}

#[cfg(target_arch = "x86_64")]
#[test]
fn spin_20us_detected_with_rdtsc() {
    leaky_spin_run(Timer::Rdtsc);
}

#[test]
fn victims_agree_on_answers() {
    // Test fixture token, not a real secret.
    let expected = [0x5au8; TOKEN_LEN];
    let mut wrong_last = expected;
    wrong_last[TOKEN_LEN - 1] ^= 1;
    let mut wrong_first = expected;
    wrong_first[0] ^= 0x80;
    for cand in [expected, wrong_last, wrong_first, [0u8; TOKEN_LEN]] {
        assert_eq!(
            leaky_validate(&expected, &cand),
            ct_validate(&expected, &cand)
        );
    }
    assert!(leaky_validate(&expected, &expected));
    assert!(!ct_validate(&expected, &wrong_last));
}

#[test]
fn reproducible_class_schedule() {
    let cfg = MeasureConfig {
        warmup: 0,
        ..MeasureConfig::with_samples(1_000)
    };
    let a = measure_pair(&cfg, |c, _| c, |_c: &Class| ()).unwrap();
    let b = measure_pair(&cfg, |c, _| c, |_c: &Class| ()).unwrap();
    assert_eq!((a.n_a, a.n_b), (b.n_a, b.n_b));
}
