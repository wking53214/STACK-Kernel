//! Calibrate the harness on this machine and print the result as JSON.
//!
//! Three checks:
//! 1. A/A: the same function and the same input distribution for both
//!    classes, repeated with different seeds. Any run whose max |t| exceeds
//!    the threshold is a false positive; the fraction estimates the false
//!    positive rate of the verdict on this machine.
//! 2. The leaky victim (early-exit compare): must be detected with a max |t|
//!    far above 4.5.
//! 3. The constant-time victim (`subtle`): should not be detected.
//!
//! Plus one control that shows why inputs are prepared in batches: the
//! constant-time victim again with `batch = 1` (each input built right
//! before it is timed). On the development machine this reported a large
//! false leak caused by the input generator's residue, not by the victim.
//!
//! Usage: `cargo run --release -p stack-anc-harness --example calibrate
//! [samples] [aa_runs]`. Defaults: 200000 samples per run, 20 A/A runs.
//! Both arguments are bounded (samples by MAX_SAMPLES, runs by 1000).

use serde_json::{json, Value};
use tack_anc_harness::victim::{ct_validate, leaky_validate, TOKEN_LEN};
use tack_anc_harness::{
    env, measure_pair, Class, MeasureConfig, Report, Timer, DEFAULT_SEED, MAX_SAMPLES, T_THRESHOLD,
};

const MAX_AA_RUNS: usize = 1_000;

fn summary(r: &Report) -> Value {
    let v = r.verdict(T_THRESHOLD);
    json!({
        "unit": r.unit,
        "n_a": r.n_a,
        "n_b": r.n_b,
        "mean_a": r.a.mean,
        "mean_b": r.b.mean,
        "median_a": r.a.median,
        "median_b": r.b.median,
        "t_raw": r.t_raw,
        "t_cropped": r.cropped.iter().map(|c| json!({"p": c.percentile, "t": c.t})).collect::<Vec<_>>(),
        "t_second_order": r.t_second_order,
        "ks_d": r.ks_d,
        "ks_p": r.ks_p,
        "max_abs_t": r.max_abs_t,
        "max_source": r.max_source,
        "verdict": v,
        "gate_outcome": v.gate_outcome(),
        "wall_seconds": r.run.as_ref().map(|x| x.wall_seconds),
        "thread_cpu_utilization": r.run.as_ref().and_then(|x| x.thread_cpu_utilization),
    })
}

fn parse_arg(i: usize, default: usize, max: usize) -> Result<usize, String> {
    match std::env::args().nth(i) {
        None => Ok(default),
        Some(s) => match s.parse::<usize>() {
            Ok(n) if n <= max => Ok(n),
            _ => Err(format!("argument {i} must be an integer at most {max}")),
        },
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let samples = parse_arg(1, 200_000, MAX_SAMPLES)?;
    let aa_runs = parse_arg(2, 20, MAX_AA_RUNS)?;
    let env_before = env::snapshot();

    // Test fixture token, not a real secret or key.
    let secret: [u8; TOKEN_LEN] = [0xa5; TOKEN_LEN];
    let fixed_vs_random = move |class: Class, rng: &mut tack_anc_harness::SplitMix64| match class {
        Class::A => secret,
        Class::B => rng.bytes::<TOKEN_LEN>(),
    };

    // 1. A/A.
    let mut aa_max = Vec::with_capacity(aa_runs);
    let mut aa_raw = Vec::with_capacity(aa_runs);
    let mut aa_fp = 0usize;
    let mut aa_fp_raw = 0usize;
    for i in 0..aa_runs {
        let cfg = MeasureConfig {
            seed: DEFAULT_SEED.wrapping_add(i as u64),
            ..MeasureConfig::with_samples(samples)
        };
        // Both classes: a fresh random candidate, same function.
        let r = measure_pair(
            &cfg,
            |_class, rng| rng.bytes::<TOKEN_LEN>(),
            |c| ct_validate(&secret, c),
        )?;
        if r.max_abs_t > T_THRESHOLD {
            aa_fp += 1;
        }
        let raw = r.t_raw.unwrap_or(0.0);
        if raw.abs() > T_THRESHOLD {
            aa_fp_raw += 1;
        }
        aa_max.push(r.max_abs_t);
        aa_raw.push(raw);
    }
    let rate = |k: usize| {
        if aa_runs == 0 {
            None
        } else {
            Some(k as f64 / aa_runs as f64)
        }
    };

    // 2 and 3, with each timer this machine supports.
    let mut victims = Vec::new();
    for timer in [Timer::Instant, Timer::Rdtsc] {
        if !timer.is_supported() {
            continue;
        }
        let cfg = MeasureConfig {
            timer,
            ..MeasureConfig::with_samples(samples)
        };
        let leaky = measure_pair(&cfg, fixed_vs_random, |c| leaky_validate(&secret, c))?;
        let ct = measure_pair(&cfg, fixed_vs_random, |c| ct_validate(&secret, c))?;
        victims.push(json!({
            "timer": timer,
            "leaky": summary(&leaky),
            "ct": summary(&ct),
        }));
    }

    let ct_batch1 = measure_pair(
        &MeasureConfig {
            batch: 1,
            ..MeasureConfig::with_samples(samples)
        },
        fixed_vs_random,
        |c| ct_validate(&secret, c),
    )?;

    let out = json!({
        "threshold": T_THRESHOLD,
        "samples_per_run": samples,
        "env_before": env_before,
        "aa": {
            "runs": aa_runs,
            "timer": Timer::Instant,
            "false_positives_max_abs_t": aa_fp,
            "false_positive_rate_max_abs_t": rate(aa_fp),
            "false_positives_raw_t": aa_fp_raw,
            "false_positive_rate_raw_t": rate(aa_fp_raw),
            "max_abs_t_per_run": aa_max,
            "t_raw_per_run": aa_raw,
        },
        "victims": victims,
        "control_ct_batch1_instant": summary(&ct_batch1),
        "env_after": env::snapshot(),
    });
    println!("{}", serde_json::to_string_pretty(&out)?);
    Ok(())
}
