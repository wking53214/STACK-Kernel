//! Pure statistics used by the harness. No timing, no I/O, no telemetry.
//!
//! Everything here is deterministic and is tested against hand-computed
//! values in `tests/stats_known.rs`.
//!
//! Conventions:
//! * Variance is the unbiased sample variance (divide by `n - 1`).
//! * The Welch t statistic is `(mean_a - mean_b) / sqrt(var_a/n_a + var_b/n_b)`,
//!   so a positive t means class A was slower on average.
//! * Functions that cannot produce a meaningful number (too few samples)
//!   return `None` instead of a made-up value.

use serde::Serialize;

/// Welford's online mean and variance accumulator.
///
/// Numerically stable single-pass algorithm. Memory is constant no matter
/// how many samples are pushed.
#[derive(Debug, Clone, Copy, Default, PartialEq, Serialize)]
pub struct Welford {
    n: u64,
    mean: f64,
    m2: f64,
}

impl Welford {
    /// An empty accumulator.
    pub const fn new() -> Self {
        Self {
            n: 0,
            mean: 0.0,
            m2: 0.0,
        }
    }

    /// Add one sample.
    pub fn push(&mut self, x: f64) {
        self.n = self.n.saturating_add(1);
        let delta = x - self.mean;
        self.mean += delta / self.n as f64;
        let delta2 = x - self.mean;
        self.m2 += delta * delta2;
    }

    /// Number of samples pushed.
    pub const fn count(&self) -> u64 {
        self.n
    }

    /// Mean, or `None` when empty.
    pub fn mean(&self) -> Option<f64> {
        (self.n > 0).then_some(self.mean)
    }

    /// Unbiased sample variance (divide by `n - 1`), or `None` when `n < 2`.
    pub fn variance(&self) -> Option<f64> {
        (self.n > 1).then(|| self.m2 / (self.n - 1) as f64)
    }

    /// Build an accumulator from a slice.
    pub fn from_slice(xs: &[f64]) -> Self {
        let mut w = Self::new();
        for &x in xs {
            w.push(x);
        }
        w
    }
}

/// Result of Welch's unequal-variance t test.
#[derive(Debug, Clone, Copy, PartialEq, Serialize)]
pub struct Welch {
    /// The t statistic, `(mean_a - mean_b) / standard_error`.
    /// Can be `+inf` or `-inf` when both variances are zero and the means
    /// differ (a perfectly separated, noise-free difference).
    pub t: f64,
    /// Welch-Satterthwaite degrees of freedom. `inf` when both variances are
    /// zero.
    pub df: f64,
}

/// Welch t statistic and Welch-Satterthwaite degrees of freedom.
///
/// Returns `None` when either side has fewer than 2 samples. When both
/// variances are zero it returns `t = 0` if the means are equal and
/// `t = +/-inf` otherwise.
pub fn welch(a: &Welford, b: &Welford) -> Option<Welch> {
    let (ma, mb) = (a.mean()?, b.mean()?);
    let (va, vb) = (a.variance()?, b.variance()?);
    let (na, nb) = (a.count() as f64, b.count() as f64);
    let sa = va / na;
    let sb = vb / nb;
    let se2 = sa + sb;
    let diff = ma - mb;
    if se2 <= 0.0 {
        let t = if diff == 0.0 {
            0.0
        } else {
            diff.signum() * f64::INFINITY
        };
        return Some(Welch {
            t,
            df: f64::INFINITY,
        });
    }
    let t = diff / se2.sqrt();
    let denom = sa * sa / (na - 1.0) + sb * sb / (nb - 1.0);
    let df = if denom > 0.0 {
        se2 * se2 / denom
    } else {
        f64::INFINITY
    };
    Some(Welch { t, df })
}

/// Welch test straight from two slices.
pub fn welch_slices(a: &[f64], b: &[f64]) -> Option<Welch> {
    welch(&Welford::from_slice(a), &Welford::from_slice(b))
}

/// Second-order (variance) test, as dudect does it.
///
/// Each sample is centered on its own class mean and squared, then a Welch
/// t test is run on the two squared series. A large |t| means the classes
/// differ in spread even if their means match. Two passes over the data.
pub fn second_order_welch(a: &[f64], b: &[f64]) -> Option<Welch> {
    let ma = Welford::from_slice(a).mean()?;
    let mb = Welford::from_slice(b).mean()?;
    let mut wa = Welford::new();
    let mut wb = Welford::new();
    for &x in a {
        let c = x - ma;
        wa.push(c * c);
    }
    for &x in b {
        let c = x - mb;
        wb.push(c * c);
    }
    welch(&wa, &wb)
}

/// Result of the two-sample Kolmogorov-Smirnov test.
#[derive(Debug, Clone, Copy, PartialEq, Serialize)]
pub struct Ks {
    /// Largest vertical distance between the two empirical CDFs, in [0, 1].
    pub d: f64,
    /// Asymptotic p-value (Kolmogorov distribution with the Stephens small
    /// sample correction), in [0, 1]. Small p means the distributions differ.
    pub p: f64,
}

/// Upper cap on series terms in [`kolmogorov_q`]. The series converges in a
/// handful of terms for every lambda that matters.
const KS_MAX_TERMS: u32 = 100;

/// Complementary Kolmogorov distribution `Q(lambda) = P(K > lambda)`,
/// `2 * sum_{j>=1} (-1)^(j-1) exp(-2 j^2 lambda^2)`.
///
/// Known values: `Q(1.0) = 0.26999967`, `Q(1.358) = 0.05` (approximately).
/// Returns 1.0 for small lambda where the alternating series does not
/// converge in [`KS_MAX_TERMS`] terms (the true value is 1 there to working
/// precision).
pub fn kolmogorov_q(lambda: f64) -> f64 {
    if !lambda.is_finite() {
        return if lambda > 0.0 { 0.0 } else { 1.0 };
    }
    if lambda <= 0.0 {
        return 1.0;
    }
    const EPS1: f64 = 1e-6;
    const EPS2: f64 = 1e-16;
    let a2 = -2.0 * lambda * lambda;
    let mut fac = 2.0;
    let mut sum = 0.0;
    let mut termbf = 0.0_f64;
    for j in 1..=KS_MAX_TERMS {
        let jf = f64::from(j);
        let term = fac * (a2 * jf * jf).exp();
        sum += term;
        if term.abs() <= EPS1 * termbf || term.abs() <= EPS2 * sum {
            return sum.clamp(0.0, 1.0);
        }
        fac = -fac;
        termbf = term.abs();
    }
    1.0
}

/// Two-sample Kolmogorov-Smirnov D and asymptotic p-value.
///
/// Ties are handled correctly (both empirical CDFs step past a shared value
/// together). Sorts copies of the inputs, so it costs O((n + m) log(n + m))
/// time and O(n + m) memory. Returns `None` when either side is empty.
pub fn ks_two_sample(a: &[f64], b: &[f64]) -> Option<Ks> {
    if a.is_empty() || b.is_empty() {
        return None;
    }
    let mut sa = a.to_vec();
    let mut sb = b.to_vec();
    sa.sort_by(f64::total_cmp);
    sb.sort_by(f64::total_cmp);
    let d = ks_d_sorted(&sa, &sb);
    let (n, m) = (sa.len() as f64, sb.len() as f64);
    let en = (n * m / (n + m)).sqrt();
    let lambda = (en + 0.12 + 0.11 / en) * d;
    Some(Ks {
        d,
        p: kolmogorov_q(lambda),
    })
}

/// KS D for two already sorted slices (ascending, by `total_cmp`).
fn ks_d_sorted(a: &[f64], b: &[f64]) -> f64 {
    let (n, m) = (a.len(), b.len());
    let (nf, mf) = (n as f64, m as f64);
    let (mut i, mut j) = (0usize, 0usize);
    let mut d = 0.0_f64;
    while i < n && j < m {
        let x = if a[i].total_cmp(&b[j]).is_le() {
            a[i]
        } else {
            b[j]
        };
        while i < n && a[i].total_cmp(&x).is_le() {
            i += 1;
        }
        while j < m && b[j].total_cmp(&x).is_le() {
            j += 1;
        }
        let gap = (i as f64 / nf - j as f64 / mf).abs();
        if gap > d {
            d = gap;
        }
    }
    d
}

/// Percentile of an ascending sorted slice, by linear interpolation between
/// closest ranks (the "type 7" rule used by NumPy and R by default).
///
/// `q` is a fraction in [0, 1]: 0.5 is the median. Returns `None` for an
/// empty slice or a `q` outside [0, 1] or NaN.
pub fn percentile_sorted(sorted: &[f64], q: f64) -> Option<f64> {
    if sorted.is_empty() || !(0.0..=1.0).contains(&q) {
        return None;
    }
    let last = sorted.len() - 1;
    let pos = q * last as f64;
    let lo = pos.floor();
    // lo is in [0, last] because q is in [0, 1]; the cast is exact for any
    // slice length that fits in memory.
    let lo_i = (lo as usize).min(last);
    let hi_i = (lo_i + 1).min(last);
    let frac = pos - lo;
    Some(sorted[lo_i] + (sorted[hi_i] - sorted[lo_i]) * frac)
}

/// Percentile of an unsorted slice (sorts a copy).
pub fn percentile(xs: &[f64], q: f64) -> Option<f64> {
    let mut v = xs.to_vec();
    v.sort_by(f64::total_cmp);
    percentile_sorted(&v, q)
}

/// Keep only the samples at or below `threshold` (upper cropping).
///
/// Timing distributions have a long right tail from interrupts and
/// preemption. dudect crops that tail at several percentiles of the pooled
/// data and tests each cropped set, because a small leak can hide under the
/// tail noise. The threshold must come from pooled data (both classes), so
/// the crop does not itself depend on the class.
pub fn crop_upper(xs: &[f64], threshold: f64) -> Vec<f64> {
    xs.iter().copied().filter(|&x| x <= threshold).collect()
}
