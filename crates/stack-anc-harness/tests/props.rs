//! Property tests for the stats module.
#![allow(clippy::unwrap_used, clippy::panic)] // test code: failures should abort the test

use proptest::prelude::*;
use sstack_anc_harness::stats::{ks_two_sample, percentile, welch_slices, Welford};

fn finite_vec() -> impl Strategy<Value = Vec<f64>> {
    prop::collection::vec(-1.0e6..1.0e6_f64, 2..200)
}

proptest! {
    #[test]
    fn welford_matches_two_pass(xs in finite_vec()) {
        let w = Welford::from_slice(&xs);
        let n = xs.len() as f64;
        let mean = xs.iter().sum::<f64>() / n;
        let var = xs.iter().map(|x| (x - mean).powi(2)).sum::<f64>() / (n - 1.0);
        prop_assert!((w.mean().unwrap() - mean).abs() <= 1e-6 * (1.0 + mean.abs()));
        prop_assert!((w.variance().unwrap() - var).abs() <= 1e-6 * (1.0 + var));
    }

    #[test]
    fn welch_is_antisymmetric(a in finite_vec(), b in finite_vec()) {
        let x = welch_slices(&a, &b).unwrap();
        let y = welch_slices(&b, &a).unwrap();
        if x.t.is_finite() {
            prop_assert!((x.t + y.t).abs() <= 1e-9 * (1.0 + x.t.abs()));
            prop_assert!(x.df > 0.0);
        }
    }

    #[test]
    fn ks_is_bounded_and_symmetric(a in finite_vec(), b in finite_vec()) {
        let x = ks_two_sample(&a, &b).unwrap();
        let y = ks_two_sample(&b, &a).unwrap();
        prop_assert!((0.0..=1.0).contains(&x.d));
        prop_assert!((0.0..=1.0).contains(&x.p));
        prop_assert!((x.d - y.d).abs() < 1e-12);
        prop_assert_eq!(ks_two_sample(&a, &a).unwrap().d, 0.0);
    }

    #[test]
    fn percentile_is_within_range(xs in finite_vec(), q in 0.0..=1.0_f64) {
        let p = percentile(&xs, q).unwrap();
        let lo = xs.iter().copied().fold(f64::INFINITY, f64::min);
        let hi = xs.iter().copied().fold(f64::NEG_INFINITY, f64::max);
        prop_assert!(p >= lo && p <= hi);
    }
}
