//! Stats functions against hand-computed values.
#![allow(clippy::unwrap_used, clippy::panic)] // test code: failures should abort the test

use sstack_anc_harness::stats::{
    crop_upper, kolmogorov_q, ks_two_sample, percentile, percentile_sorted, second_order_welch,
    welch, welch_slices, Welford,
};

fn close(a: f64, b: f64, tol: f64) -> bool {
    (a - b).abs() <= tol
}

#[test]
fn welford_mean_and_sample_variance() {
    let w = Welford::from_slice(&[2.0, 4.0, 4.0, 4.0, 5.0, 5.0, 7.0, 9.0]);
    assert_eq!(w.count(), 8);
    assert!(close(w.mean().unwrap(), 5.0, 1e-12));
    // sum of squared deviations = 32, n - 1 = 7
    assert!(close(w.variance().unwrap(), 32.0 / 7.0, 1e-12));
    assert_eq!(Welford::new().mean(), None);
    assert_eq!(Welford::from_slice(&[1.0]).variance(), None);
}

#[test]
fn welch_hand_computed() {
    // a: mean 2.5, var 5/3. b: mean 5, var 20/3. n = 4 each.
    // se^2 = 5/12 + 5/3 = 25/12, t = -2.5 / sqrt(25/12) = -sqrt(3).
    // df = (25/12)^2 / ((5/12)^2/3 + (5/3)^2/3) = 1875/425.
    let w = welch_slices(&[1.0, 2.0, 3.0, 4.0], &[2.0, 4.0, 6.0, 8.0]).unwrap();
    assert!(close(w.t, -(3.0_f64).sqrt(), 1e-12), "t = {}", w.t);
    assert!(close(w.df, 1875.0 / 425.0, 1e-12), "df = {}", w.df);
    // Antisymmetric in the classes.
    let r = welch_slices(&[2.0, 4.0, 6.0, 8.0], &[1.0, 2.0, 3.0, 4.0]).unwrap();
    assert!(close(r.t, (3.0_f64).sqrt(), 1e-12));
}

#[test]
fn welch_edge_cases() {
    assert!(welch_slices(&[1.0], &[1.0, 2.0]).is_none());
    assert!(welch_slices(&[], &[]).is_none());
    let same = welch_slices(&[3.0, 3.0], &[3.0, 3.0]).unwrap();
    assert_eq!(same.t, 0.0);
    let apart = welch_slices(&[3.0, 3.0], &[1.0, 1.0]).unwrap();
    assert!(apart.t.is_infinite() && apart.t > 0.0);
    let w = welch(
        &Welford::from_slice(&[1.0, 2.0]),
        &Welford::from_slice(&[1.0, 2.0]),
    )
    .unwrap();
    assert_eq!(w.t, 0.0);
}

#[test]
fn second_order_hand_computed() {
    // Centered squares: a -> [2.25, .25, .25, 2.25] (mean 1.25, var 4/3),
    // b -> [9, 1, 1, 9] (mean 5, var 64/3). t = -3.75 / sqrt(17/3).
    let w = second_order_welch(&[1.0, 2.0, 3.0, 4.0], &[2.0, 4.0, 6.0, 8.0]).unwrap();
    let expected = -3.75 / (17.0_f64 / 3.0).sqrt();
    assert!(close(w.t, expected, 1e-12), "t = {}", w.t);
    // Same spread, different means: second order sees nothing.
    let w = second_order_welch(&[1.0, 2.0, 3.0, 4.0], &[11.0, 12.0, 13.0, 14.0]).unwrap();
    assert!(close(w.t, 0.0, 1e-12));
}

#[test]
fn kolmogorov_q_known_values() {
    assert!(close(kolmogorov_q(1.0), 0.269_999_67, 1e-7));
    assert!(close(kolmogorov_q(1.36), 0.049_485_88, 1e-7));
    assert_eq!(kolmogorov_q(0.0), 1.0);
    assert_eq!(kolmogorov_q(0.01), 1.0);
    assert_eq!(kolmogorov_q(f64::INFINITY), 0.0);
    assert!(kolmogorov_q(5.0) < 1e-20);
}

#[test]
fn ks_known_samples() {
    // Fully separated: D = 1. lambda = (sqrt(2.5) + 0.12 + 0.11/sqrt(2.5)) = 1.770709,
    // Q(lambda) = 0.0037813541.
    let ks = ks_two_sample(&[1.0, 2.0, 3.0, 4.0, 5.0], &[6.0, 7.0, 8.0, 9.0, 10.0]).unwrap();
    assert_eq!(ks.d, 1.0);
    assert!(close(ks.p, 0.003_781_354_1, 1e-9), "p = {}", ks.p);

    // Identical: D = 0, p = 1.
    let ks = ks_two_sample(&[1.0, 2.0, 3.0], &[3.0, 2.0, 1.0]).unwrap();
    assert_eq!(ks.d, 0.0);
    assert_eq!(ks.p, 1.0);

    // Interleaved: D = 1/3.
    let ks = ks_two_sample(&[1.0, 2.0, 3.0], &[1.5, 2.5, 3.5]).unwrap();
    assert!(close(ks.d, 1.0 / 3.0, 1e-12));

    // Ties: at x = 1, F_a = 2/3 and F_b = 1/3; at x = 2 both are 1. D = 1/3.
    let ks = ks_two_sample(&[1.0, 1.0, 2.0], &[1.0, 2.0, 2.0]).unwrap();
    assert!(close(ks.d, 1.0 / 3.0, 1e-12));

    // Unequal sizes: a = {1, 2}, b = {1, 2, 3, 4}. At 2: 1 - 1/2 = 1/2.
    let ks = ks_two_sample(&[2.0, 1.0], &[4.0, 3.0, 2.0, 1.0]).unwrap();
    assert!(close(ks.d, 0.5, 1e-12));

    assert!(ks_two_sample(&[], &[1.0]).is_none());
}

#[test]
fn percentiles_and_crop() {
    let s = [1.0, 2.0, 3.0, 4.0];
    assert_eq!(percentile_sorted(&s, 0.0), Some(1.0));
    assert_eq!(percentile_sorted(&s, 1.0), Some(4.0));
    assert_eq!(percentile_sorted(&s, 0.5), Some(2.5));
    assert!(close(percentile_sorted(&s, 0.9).unwrap(), 3.7, 1e-12));
    assert_eq!(percentile(&[4.0, 1.0, 3.0, 2.0], 0.5), Some(2.5));
    assert_eq!(percentile_sorted(&[], 0.5), None);
    assert_eq!(percentile_sorted(&s, 1.5), None);
    assert_eq!(percentile_sorted(&s, f64::NAN), None);
    assert_eq!(percentile_sorted(&[7.0], 0.3), Some(7.0));
    assert_eq!(crop_upper(&[5.0, 1.0, 9.0, 3.0], 5.0), vec![5.0, 1.0, 3.0]);
}
