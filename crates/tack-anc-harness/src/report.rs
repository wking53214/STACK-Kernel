//! Turning raw samples into a [`Report`], and a [`Report`] into a [`Verdict`].

use crate::env::Env;
use crate::error::HarnessError;
use crate::measure::{validate_crop_percentiles, Class, TimeUnit, Timer, MAX_SAMPLES};
use crate::stats::{self, Welford};
use serde::Serialize;

/// Welch t on one upper-cropped subset.
#[derive(Debug, Clone, Copy, PartialEq, Serialize)]
pub struct CroppedT {
    /// Crop percentile of the pooled samples, as a fraction (0.9 = p90).
    pub percentile: f64,
    /// Sample value at that percentile; samples above it were dropped.
    pub threshold: f64,
    /// Class A samples kept.
    pub n_a: u64,
    /// Class B samples kept.
    pub n_b: u64,
    /// Welch t on the kept samples. `None` when either class kept fewer
    /// than 2 samples (which itself usually means the classes are far
    /// apart; the raw t will show it).
    pub t: Option<f64>,
}

/// Which statistic produced `max_abs_t`.
#[derive(Debug, Clone, Copy, PartialEq, Serialize)]
pub enum Statistic {
    /// Welch t on all samples.
    Raw,
    /// Welch t on samples at or below this pooled percentile.
    Cropped {
        /// The crop percentile, as a fraction.
        percentile: f64,
    },
    /// Welch t on centered squared samples (difference in spread).
    SecondOrder,
}

/// Summary of one class's samples.
#[derive(Debug, Clone, Copy, PartialEq, Serialize)]
pub struct ClassSummary {
    /// Sample count.
    pub n: u64,
    /// Mean, `None` if empty.
    pub mean: Option<f64>,
    /// Unbiased sample variance, `None` if fewer than 2 samples.
    pub variance: Option<f64>,
    /// Median, `None` if empty.
    pub median: Option<f64>,
    /// 99th percentile, `None` if empty.
    pub p99: Option<f64>,
}

/// Context of a run made by `measure_pair` (absent when the caller used
/// `analyze` directly).
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct RunInfo {
    /// Clock used.
    pub timer: Timer,
    /// Seed used.
    pub seed: u64,
    /// Warm-up iterations run.
    pub warmup: usize,
    /// Wall time of the timed loop, seconds.
    pub wall_seconds: f64,
    /// CPU time of the measuring thread during the timed loop, seconds.
    pub thread_cpu_seconds: Option<f64>,
    /// CPU time of the whole process during the timed loop, seconds.
    pub process_cpu_seconds: Option<f64>,
    /// `thread_cpu_seconds / wall_seconds`. Near 1.0 means the thread ran
    /// uninterrupted; well below 1.0 means it was descheduled and the
    /// samples are noisier than usual.
    pub thread_cpu_utilization: Option<f64>,
    /// Machine conditions just before the run.
    pub env: Env,
}

/// Everything the harness computed about one pair of sample sets.
///
/// Sign convention: every t is `(mean_A - mean_B) / standard_error`, so a
/// positive t means class A was slower.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Report {
    /// Unit of every time value in this report.
    pub unit: TimeUnit,
    /// Class A sample count (same as `a.n`).
    pub n_a: u64,
    /// Class B sample count (same as `b.n`).
    pub n_b: u64,
    /// Class A summary.
    pub a: ClassSummary,
    /// Class B summary.
    pub b: ClassSummary,
    /// Welch t on all samples.
    pub t_raw: Option<f64>,
    /// Welch-Satterthwaite degrees of freedom for `t_raw`.
    pub df_raw: Option<f64>,
    /// Welch t after upper cropping at each configured percentile, in the
    /// order given.
    pub cropped: Vec<CroppedT>,
    /// Second-order t (difference in variance), dudect style.
    pub t_second_order: Option<f64>,
    /// Two-sample Kolmogorov-Smirnov D on all samples.
    pub ks_d: Option<f64>,
    /// Asymptotic KS p-value. Informational: not part of the verdict,
    /// because at large n it flags differences far too small to exploit.
    pub ks_p: Option<f64>,
    /// Largest |t| over `t_raw`, every `cropped[i].t` and
    /// `t_second_order`. 0.0 when none could be computed. May be `inf`.
    pub max_abs_t: f64,
    /// Which statistic produced `max_abs_t`; `None` when none could be
    /// computed.
    pub max_source: Option<Statistic>,
    /// Per-class minimum below which `verdict` is `Inconclusive`.
    pub min_per_class: u64,
    /// Run context, filled in by `measure_pair`.
    pub run: Option<RunInfo>,
}

/// Mirror of the CNS `GateOutcome` vocabulary (`cns/gate.py`), so strategy
/// crates can map a verdict without depending on anything else.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum GateOutcome {
    /// No leak detected at the threshold.
    Pass,
    /// Not enough evidence either way; rerun with more samples.
    Retry,
    /// Leak detected: the strategy under test fails, and no resubmission
    /// of the same build can repair that.
    TerminalBreach,
}

/// Why a verdict could not be reached.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum InconclusiveReason {
    /// A class has fewer than `min_per_class` samples.
    TooFewSamples,
    /// No t statistic could be computed.
    NoStatistic,
    /// The threshold passed to `verdict` was not finite and positive.
    InvalidThreshold,
}

impl GateOutcome {
    /// The CNS spelling: `PASS`, `RETRY` or `TERMINAL_BREACH`.
    pub const fn as_str(self) -> &'static str {
        match self {
            GateOutcome::Pass => "PASS",
            GateOutcome::Retry => "RETRY",
            GateOutcome::TerminalBreach => "TERMINAL_BREACH",
        }
    }
}

impl InconclusiveReason {
    const fn label(self) -> &'static str {
        match self {
            InconclusiveReason::TooFewSamples => "too_few_samples",
            InconclusiveReason::NoStatistic => "no_statistic",
            InconclusiveReason::InvalidThreshold => "invalid_threshold",
        }
    }
}

/// The pass or fail answer for one report at one threshold.
#[derive(Debug, Clone, Copy, PartialEq, Serialize)]
pub enum Verdict {
    /// `max_abs_t <= threshold`. Maps to [`GateOutcome::Pass`].
    NoLeakDetected {
        /// The largest |t| seen.
        max_abs_t: f64,
    },
    /// `max_abs_t > threshold`. Maps to [`GateOutcome::TerminalBreach`].
    LeakDetected {
        /// The largest |t| seen.
        max_abs_t: f64,
        /// Which statistic crossed the threshold.
        source: Statistic,
    },
    /// No decision. Maps to [`GateOutcome::Retry`] (fail closed: never Pass).
    Inconclusive {
        /// Why.
        reason: InconclusiveReason,
    },
}

impl Verdict {
    /// CNS outcome for this verdict.
    pub const fn gate_outcome(&self) -> GateOutcome {
        match self {
            Verdict::NoLeakDetected { .. } => GateOutcome::Pass,
            Verdict::LeakDetected { .. } => GateOutcome::TerminalBreach,
            Verdict::Inconclusive { .. } => GateOutcome::Retry,
        }
    }

    /// True only for `LeakDetected`.
    pub const fn is_leak(&self) -> bool {
        matches!(self, Verdict::LeakDetected { .. })
    }

    /// True only for `NoLeakDetected`.
    pub const fn is_pass(&self) -> bool {
        matches!(self, Verdict::NoLeakDetected { .. })
    }

    const fn label(&self) -> &'static str {
        match self {
            Verdict::NoLeakDetected { .. } => "no_leak",
            Verdict::LeakDetected { .. } => "leak",
            Verdict::Inconclusive { .. } => "inconclusive",
        }
    }
}

impl Report {
    /// Decide at `threshold` (use [`crate::T_THRESHOLD`], 4.5, unless you
    /// have a reason not to). Fails closed: too few samples, no computable
    /// statistic, or a bad threshold give `Inconclusive`, never a pass.
    ///
    /// Each call increments `tack_anc_harness_verdicts_total{verdict,reason}`
    /// once, so call it once per report you actually decide on.
    pub fn verdict(&self, threshold: f64) -> Verdict {
        let v = self.decide(threshold);
        let reason = match v {
            Verdict::Inconclusive { reason } => reason.label(),
            _ => "none",
        };
        metrics::counter!(
            "tack_anc_harness_verdicts_total",
            "verdict" => v.label(),
            "reason" => reason
        )
        .increment(1);
        v
    }

    fn decide(&self, threshold: f64) -> Verdict {
        if !(threshold.is_finite() && threshold > 0.0) {
            return Verdict::Inconclusive {
                reason: InconclusiveReason::InvalidThreshold,
            };
        }
        if self.n_a < self.min_per_class || self.n_b < self.min_per_class {
            return Verdict::Inconclusive {
                reason: InconclusiveReason::TooFewSamples,
            };
        }
        let Some(source) = self.max_source else {
            return Verdict::Inconclusive {
                reason: InconclusiveReason::NoStatistic,
            };
        };
        if self.max_abs_t > threshold {
            Verdict::LeakDetected {
                max_abs_t: self.max_abs_t,
                source,
            }
        } else {
            Verdict::NoLeakDetected {
                max_abs_t: self.max_abs_t,
            }
        }
    }
}

fn summarize(sorted: &[f64]) -> ClassSummary {
    let w = Welford::from_slice(sorted);
    ClassSummary {
        n: w.count(),
        mean: w.mean(),
        variance: w.variance(),
        median: stats::percentile_sorted(sorted, 0.5),
        p99: stats::percentile_sorted(sorted, 0.99),
    }
}

/// Analyse samples collected by any means.
///
/// `classes[i]` is the class of `samples[i]`. Use this directly when
/// `measure_pair` does not fit (for example, timing an async pipeline end
/// to end); keep the classes interleaved at random in time when you collect.
///
/// * `unit`: recorded in the report; use `TimeUnit::Other` for anything
///   that is not nanoseconds or cycles.
/// * `crop_percentiles`: fractions strictly between 0 and 1, at most
///   `MAX_CROP_PERCENTILES`.
/// * `min_per_class`: per-class count below which `verdict` is
///   `Inconclusive`.
///
/// Errors: length mismatch, more than `MAX_SAMPLES` samples, a non-finite
/// sample, or bad crop percentiles. Cost: O(n log n) time, about 3n `f64`
/// of extra memory.
pub fn analyze(
    classes: &[Class],
    samples: &[f64],
    unit: TimeUnit,
    crop_percentiles: &[f64],
    min_per_class: u64,
) -> Result<Report, HarnessError> {
    let _guard = tracing::debug_span!("tack.anc_harness.analyze", n = samples.len()).entered();
    if classes.len() != samples.len() {
        return Err(HarnessError::LengthMismatch);
    }
    if samples.len() > MAX_SAMPLES {
        return Err(HarnessError::InvalidConfig {
            field: "samples",
            reason: "exceeds MAX_SAMPLES",
        });
    }
    if samples.iter().any(|x| !x.is_finite()) {
        return Err(HarnessError::InvalidConfig {
            field: "samples",
            reason: "contains a non-finite value",
        });
    }
    validate_crop_percentiles(crop_percentiles)?;

    let mut a: Vec<f64> = Vec::with_capacity(samples.len() / 2 + 1);
    let mut b: Vec<f64> = Vec::with_capacity(samples.len() / 2 + 1);
    for (&c, &x) in classes.iter().zip(samples) {
        match c {
            Class::A => a.push(x),
            Class::B => b.push(x),
        }
    }

    // First-order and second-order tests on the raw samples.
    let raw = stats::welch_slices(&a, &b);
    let second = stats::second_order_welch(&a, &b);

    // Cropped tests. Thresholds come from the pooled distribution so the
    // crop does not depend on the class.
    let mut pooled = samples.to_vec();
    pooled.sort_by(f64::total_cmp);
    let mut cropped = Vec::with_capacity(crop_percentiles.len());
    for &p in crop_percentiles {
        let Some(threshold) = stats::percentile_sorted(&pooled, p) else {
            continue;
        };
        let mut wa = Welford::new();
        let mut wb = Welford::new();
        for &x in a.iter().filter(|&&x| x <= threshold) {
            wa.push(x);
        }
        for &x in b.iter().filter(|&&x| x <= threshold) {
            wb.push(x);
        }
        cropped.push(CroppedT {
            percentile: p,
            threshold,
            n_a: wa.count(),
            n_b: wb.count(),
            t: stats::welch(&wa, &wb).map(|w| w.t),
        });
    }
    drop(pooled);

    a.sort_by(f64::total_cmp);
    b.sort_by(f64::total_cmp);
    let ks = stats::ks_two_sample(&a, &b);
    let sa = summarize(&a);
    let sb = summarize(&b);

    let mut max_abs_t = 0.0_f64;
    let mut max_source = None;
    let mut consider = |t: Option<f64>, s: Statistic| {
        if let Some(t) = t {
            let at = t.abs();
            if max_source.is_none() || at > max_abs_t {
                max_abs_t = at;
                max_source = Some(s);
            }
        }
    };
    consider(raw.map(|w| w.t), Statistic::Raw);
    for c in &cropped {
        consider(
            c.t,
            Statistic::Cropped {
                percentile: c.percentile,
            },
        );
    }
    consider(second.map(|w| w.t), Statistic::SecondOrder);

    metrics::gauge!("tack_anc_harness_max_abs_t").set(max_abs_t);

    Ok(Report {
        unit,
        n_a: sa.n,
        n_b: sb.n,
        a: sa,
        b: sb,
        t_raw: raw.map(|w| w.t),
        df_raw: raw.map(|w| w.df),
        cropped,
        t_second_order: second.map(|w| w.t),
        ks_d: ks.map(|k| k.d),
        ks_p: ks.map(|k| k.p),
        max_abs_t,
        max_source,
        min_per_class,
        run: None,
    })
}
