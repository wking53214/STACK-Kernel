//! `analyze` and `Report::verdict` on synthetic, deterministic samples.
#![allow(clippy::unwrap_used, clippy::panic)] // test code: failures should abort the test

use sstack_anc_harness::{
    analyze, Class, GateOutcome, HarnessError, InconclusiveReason, MeasureConfig, SplitMix64,
    Statistic, TimeUnit, Verdict, DEFAULT_CROP_PERCENTILES, MAX_CROP_PERCENTILES, MAX_SAMPLES,
    T_THRESHOLD,
};

/// Uniform noise in [0, 100) plus `shift` for class B.
fn synth(n: usize, shift_b: f64, seed: u64) -> (Vec<Class>, Vec<f64>) {
    let mut rng = SplitMix64::new(seed);
    let mut classes = Vec::with_capacity(n);
    let mut samples = Vec::with_capacity(n);
    for _ in 0..n {
        let c = rng.next_class();
        let noise = (rng.next_u64() >> 11) as f64 / (1u64 << 53) as f64 * 100.0;
        classes.push(c);
        samples.push(noise + if c == Class::B { shift_b } else { 0.0 });
    }
    (classes, samples)
}

#[test]
fn shifted_classes_leak() {
    let (c, s) = synth(20_000, 5.0, 1);
    let r = analyze(&c, &s, TimeUnit::Other, &DEFAULT_CROP_PERCENTILES, 1_000).unwrap();
    assert_eq!(r.n_a + r.n_b, 20_000);
    assert_eq!(r.cropped.len(), DEFAULT_CROP_PERCENTILES.len());
    assert!(r.t_raw.unwrap() < -4.5, "B slower gives negative t");
    let v = r.verdict(T_THRESHOLD);
    assert!(v.is_leak(), "{v:?}");
    assert_eq!(v.gate_outcome(), GateOutcome::TerminalBreach);
    assert_eq!(v.gate_outcome().as_str(), "TERMINAL_BREACH");
    assert!(r.ks_p.unwrap() < 1e-6);
}

#[test]
fn identical_classes_pass() {
    let (c, s) = synth(20_000, 0.0, 2);
    let r = analyze(&c, &s, TimeUnit::Other, &DEFAULT_CROP_PERCENTILES, 1_000).unwrap();
    let v = r.verdict(T_THRESHOLD);
    assert!(v.is_pass(), "{v:?} {r:?}");
    assert_eq!(v.gate_outcome(), GateOutcome::Pass);
    assert!(r.max_abs_t < T_THRESHOLD);
    assert!(r.max_source.is_some());
}

#[test]
fn variance_only_difference_is_caught_by_second_order() {
    // Same mean (50), class B spread 3x wider.
    let mut rng = SplitMix64::new(3);
    let (mut c, mut s) = (Vec::new(), Vec::new());
    for _ in 0..20_000 {
        let class = rng.next_class();
        let u = (rng.next_u64() >> 11) as f64 / (1u64 << 53) as f64 - 0.5;
        let width = if class == Class::B { 60.0 } else { 20.0 };
        c.push(class);
        s.push(50.0 + u * width);
    }
    let r = analyze(&c, &s, TimeUnit::Other, &[], 100).unwrap();
    assert!(r.t_raw.unwrap().abs() < T_THRESHOLD);
    assert_eq!(r.max_source, Some(Statistic::SecondOrder));
    assert!(r.verdict(T_THRESHOLD).is_leak());
}

#[test]
fn verdict_fails_closed() {
    let (c, s) = synth(1_000, 0.0, 4);
    let r = analyze(&c, &s, TimeUnit::Other, &[0.9], 10_000).unwrap();
    assert_eq!(
        r.verdict(T_THRESHOLD),
        Verdict::Inconclusive {
            reason: InconclusiveReason::TooFewSamples
        }
    );
    assert_eq!(r.verdict(T_THRESHOLD).gate_outcome(), GateOutcome::Retry);
    let r = analyze(&c, &s, TimeUnit::Other, &[0.9], 2).unwrap();
    for bad in [f64::NAN, 0.0, -1.0, f64::INFINITY] {
        assert_eq!(
            r.verdict(bad),
            Verdict::Inconclusive {
                reason: InconclusiveReason::InvalidThreshold
            }
        );
    }
    // Only one sample per class: nothing computable.
    let r = analyze(&[Class::A, Class::B], &[1.0, 2.0], TimeUnit::Other, &[], 1).unwrap();
    assert_eq!(
        r.verdict(T_THRESHOLD),
        Verdict::Inconclusive {
            reason: InconclusiveReason::NoStatistic
        }
    );
}

#[test]
fn analyze_rejects_bad_input() {
    assert_eq!(
        analyze(&[Class::A], &[], TimeUnit::Other, &[], 2).unwrap_err(),
        HarnessError::LengthMismatch
    );
    assert!(matches!(
        analyze(
            &[Class::A, Class::B],
            &[1.0, f64::NAN],
            TimeUnit::Other,
            &[],
            2
        ),
        Err(HarnessError::InvalidConfig {
            field: "samples",
            ..
        })
    ));
    for ps in [
        vec![0.0],
        vec![1.0],
        vec![f64::NAN],
        vec![0.5; MAX_CROP_PERCENTILES + 1],
    ] {
        assert!(matches!(
            analyze(&[Class::A, Class::B], &[1.0, 2.0], TimeUnit::Other, &ps, 2),
            Err(HarnessError::InvalidConfig {
                field: "crop_percentiles",
                ..
            })
        ));
    }
}

#[test]
fn config_bounds() {
    assert!(MeasureConfig::default().validate().is_ok());
    assert!(MeasureConfig::with_samples(4).validate().is_ok());
    let field = |cfg: MeasureConfig| match cfg.validate() {
        Err(HarnessError::InvalidConfig { field, .. }) => field,
        other => panic!("expected InvalidConfig, got {other:?}"),
    };
    assert_eq!(
        field(MeasureConfig {
            samples: 3,
            ..Default::default()
        }),
        "samples"
    );
    assert_eq!(
        field(MeasureConfig {
            samples: MAX_SAMPLES + 1,
            ..Default::default()
        }),
        "samples"
    );
    assert_eq!(
        field(MeasureConfig {
            warmup: usize::MAX,
            ..Default::default()
        }),
        "warmup"
    );
    assert_eq!(
        field(MeasureConfig {
            min_per_class: 1,
            ..Default::default()
        }),
        "min_per_class"
    );
    assert_eq!(
        field(MeasureConfig {
            samples: 10,
            min_per_class: 11,
            ..Default::default()
        }),
        "min_per_class"
    );
    assert_eq!(
        field(MeasureConfig {
            batch: 0,
            ..Default::default()
        }),
        "batch"
    );
    assert_eq!(
        field(MeasureConfig {
            batch: stack_anc_harness::MAX_BATCH + 1,
            ..Default::default()
        }),
        "batch"
    );
}

#[test]
fn splitmix64_reference_values() {
    // Reference outputs of splitmix64 seeded with 0 (Vigna's C code).
    let mut r = SplitMix64::new(0);
    assert_eq!(r.next_u64(), 0xe220_a839_7b1d_cdaf);
    assert_eq!(r.next_u64(), 0x6e78_9e6a_a1b9_65f4);
    let mut buf = [0u8; 11];
    SplitMix64::new(0).fill_bytes(&mut buf);
    assert_eq!(&buf[..8], &0xe220_a839_7b1d_cdafu64.to_le_bytes());
}
