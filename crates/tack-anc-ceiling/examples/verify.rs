//! Measure ceiling padding against the harness victims and under a flood.
//! Prints one JSON document on stdout.
//!
//! Run in release mode (debug timings are not evidence):
//!
//! ```text
//! cargo run --release -p tack-anc-ceiling --example verify > verify.json
//! ```
//!
//! Sections:
//! 1. `calibration`: unpadded `leaky_validate` must be flagged (max
//!    first-order |t| above 4.5) and unpadded `ct_validate` must not (raw
//!    |t| below 4.5). If this fails, nothing else in the run proves
//!    anything, and `calibration.passed` is false.
//! 2. `padded`: `leaky_validate` inside a `CeilingPad` in Sleep, Spin and
//!    Hybrid modes, timed from the call (admission) to the return
//!    (release), which is what a client sees.
//! 3. `precision`: release lateness (observed offset minus ceiling) and
//!    CPU per request of each mode, blocking and async, idle.
//! 4. `flood`: N = 2 x CPU count threads send fast-fail requests for a
//!    fixed wall time, for Spin without a budget, Hybrid with a budget, and
//!    Sleep; plus one legitimate client sending a correct token every 5 ms
//!    (retrying on RETRY up to 200 attempts). A shed flood worker sleeps
//!    200 us before its next request (a stand-in for a network round trip).
//!    `process_cpu_seconds` includes that in-process attacker loop;
//!    `cpu_inside_pad_seconds` counts only thread CPU inside `pad` calls.
//!
//! Classes (primary pair): A = candidate differs from the secret at byte 0
//! (fastest early exit); B = equal in bytes 0..30, differs at byte 31
//! (slowest wrong path). The class of each sample is drawn at random from
//! a recorded seed and interleaved; inputs are prepared in batches of 1024
//! outside the timed region (the harness's method, reproduced here so the
//! raw samples are available for percentiles).
//!
//! Environment variables (all optional; out-of-range values are an error):
//! * `TACK_VERIFY_N_PER_CLASS`: samples per class, default 100000, bounds
//!   10000 ..= 5000000.
//! * `TACK_VERIFY_CEILING_US`: ceiling for the padded runs, default 300,
//!   bounds 20 ..= 100000.
//! * `TACK_VERIFY_TAIL_US`: blocking Hybrid spin tail, default 150, bounds
//!   0 ..= 100000.
//! * `TACK_VERIFY_PRECISION_N`: requests per mode in `precision`, default
//!   2000 blocking (async uses a quarter), bounds 100 ..= 1000000.
//! * `TACK_VERIFY_FLOOD_SECS`: wall seconds per flood config, default 3,
//!   bounds 1 ..= 60.
//! * `TACK_VERIFY_FLOOD_CEILING_US`: ceiling in the flood, default 1000,
//!   bounds 20 ..= 100000.
//! * `TACK_VERIFY_FLOOD_CAP`: `max_concurrent` in the flood, default
//!   max(1, CPU count / 2), bounds 1 ..= 4096.
//! * `TACK_VERIFY_SEED`: class schedule seed, default 0x7ac4ce11. Not a key.
//!
//! With the defaults the whole run takes about 4 minutes on 4 CPUs.

use serde_json::{json, Value};
use std::cell::Cell;
use std::hint::black_box;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tack_anc_ceiling::{CeilingConfig, CeilingPad, SpinBudgetConfig, Trip, WaitMode};
use tack_anc_harness::cpu::{process_cpu_time, thread_cpu_time};
use tack_anc_harness::stats::percentile_sorted;
use tack_anc_harness::victim::{ct_validate, leaky_validate, TOKEN_LEN};
use tack_anc_harness::{
    analyze, env, Class, Report, SplitMix64, TimeUnit, DEFAULT_CROP_PERCENTILES, T_THRESHOLD,
};

const BATCH: usize = 1_024;
const WARMUP: usize = 2_000;
const CROP_LINE: f64 = 10.0;
const MAX_LATE_SAMPLES_PER_THREAD: usize = 100_000;
const LEGIT_MAX_ATTEMPTS: u32 = 200;

type Token = [u8; TOKEN_LEN];

fn env_u64(name: &str, default: u64, lo: u64, hi: u64) -> Result<u64, String> {
    match std::env::var(name) {
        Err(_) => Ok(default),
        Ok(s) => {
            let s = s.trim();
            let v = if let Some(h) = s.strip_prefix("0x") {
                u64::from_str_radix(h, 16)
            } else {
                s.parse::<u64>()
            }
            .map_err(|_| format!("{name} must be an integer"))?;
            if v < lo || v > hi {
                return Err(format!("{name} must be in {lo} ..= {hi}"));
            }
            Ok(v)
        }
    }
}

fn to_usize(v: u64) -> Result<usize, String> {
    usize::try_from(v).map_err(|_| "value does not fit usize".to_string())
}

/// Time `op` on inputs from `prepare`, dudect style: classes drawn up front
/// from `seed`, inputs prepared a batch at a time outside the timed region.
fn collect<O>(
    n_total: usize,
    seed: u64,
    mut prepare: impl FnMut(Class) -> Token,
    mut op: impl FnMut(&Token) -> O,
) -> (Vec<Class>, Vec<f64>) {
    let mut rng = SplitMix64::new(seed);
    let classes: Vec<Class> = (0..n_total).map(|_| rng.next_class()).collect();
    let mut wrng = SplitMix64::new(seed ^ 0xd1b5_4a32_d192_ed03);
    for _ in 0..WARMUP {
        let input = prepare(wrng.next_class());
        black_box(op(black_box(&input)));
    }
    let mut samples = Vec::with_capacity(n_total);
    let mut batch: Vec<Token> = Vec::with_capacity(BATCH);
    for chunk in classes.chunks(BATCH) {
        batch.clear();
        batch.extend(chunk.iter().map(|&c| prepare(c)));
        for input in &batch {
            let t0 = Instant::now();
            let out = black_box(op(black_box(input)));
            let t1 = Instant::now();
            drop(out);
            samples.push(t1.duration_since(t0).as_nanos() as f64);
        }
    }
    (classes, samples)
}

struct ClassPct {
    p50: f64,
    p99: f64,
    p999: f64,
}

fn class_pct(classes: &[Class], samples: &[f64], want: Class) -> Option<ClassPct> {
    let mut v: Vec<f64> = classes
        .iter()
        .zip(samples)
        .filter(|(c, _)| **c == want)
        .map(|(_, s)| *s)
        .collect();
    v.sort_by(f64::total_cmp);
    Some(ClassPct {
        p50: percentile_sorted(&v, 0.5)?,
        p99: percentile_sorted(&v, 0.99)?,
        p999: percentile_sorted(&v, 0.999)?,
    })
}

fn pct_json(p: &Option<ClassPct>) -> Value {
    match p {
        Some(p) => json!({"p50_ns": p.p50, "p99_ns": p.p99, "p999_ns": p.p999}),
        None => Value::Null,
    }
}

fn added_json(padded: &Option<ClassPct>, base: &Option<ClassPct>) -> Value {
    match (padded, base) {
        (Some(p), Some(b)) => json!({
            "p50_ns": p.p50 - b.p50,
            "p99_ns": p.p99 - b.p99,
            "p999_ns": p.p999 - b.p999,
        }),
        _ => Value::Null,
    }
}

/// The detectability measures the theorist requires, on one report.
fn detect_json(r: &Report) -> Value {
    let na = r.n_a as f64;
    let nb = r.n_b as f64;
    let delta_min = match (r.a.variance, r.b.variance) {
        (Some(va), Some(vb)) if na > 0.0 && nb > 0.0 => {
            Some(T_THRESHOLD * (va / na + vb / nb).sqrt())
        }
        _ => None,
    };
    let pooled_sd = match (r.a.variance, r.b.variance) {
        (Some(va), Some(vb)) => Some(((va + vb) / 2.0).sqrt()),
        _ => None,
    };
    let ks_crit = if na > 0.0 && nb > 0.0 {
        Some(1.95 * ((na + nb) / (na * nb)).sqrt())
    } else {
        None
    };
    let crop_max = r
        .cropped
        .iter()
        .filter_map(|c| c.t)
        .fold(0.0f64, |m, t| m.max(t.abs()));
    let first_order_max = r.t_raw.map_or(0.0, f64::abs).max(crop_max);
    let t_raw_ok = r.t_raw.is_some_and(|t| t.abs() < T_THRESHOLD);
    let t2_ok = r.t_second_order.is_some_and(|t| t.abs() < T_THRESHOLD);
    let ks_ok = r.ks_p.is_some_and(|p| p >= 0.001);
    let crops_ok = crop_max < CROP_LINE;
    let verdict = r.verdict(T_THRESHOLD);
    json!({
        "n_a": r.n_a,
        "n_b": r.n_b,
        "mean_a_ns": r.a.mean,
        "mean_b_ns": r.b.mean,
        "median_a_ns": r.a.median,
        "median_b_ns": r.b.median,
        "t_raw": r.t_raw,
        "t_second_order": r.t_second_order,
        "t_cropped": r.cropped.iter().map(|c| json!({"p": c.percentile, "t": c.t, "n_a": c.n_a, "n_b": c.n_b})).collect::<Vec<_>>(),
        "max_abs_cropped_t": crop_max,
        "max_abs_first_order_t": first_order_max,
        "ks_d": r.ks_d,
        "ks_p": r.ks_p,
        "ks_d_critical_p001": ks_crit,
        "delta_min_ns": delta_min,
        "delta_min_sd": delta_min.zip(pooled_sd).map(|(d, s)| if s > 0.0 { d / s } else { f64::NAN }),
        "criteria": {
            "t_raw_below_4_5": t_raw_ok,
            "t_second_order_below_4_5": t2_ok,
            "ks_p_at_least_0_001": ks_ok,
            "cropped_below_10": crops_ok,
            "all": t_raw_ok && t2_ok && ks_ok && crops_ok,
        },
        "harness_max_abs_t": r.max_abs_t,
        "harness_max_source": r.max_source,
        "harness_verdict": verdict,
        "harness_gate_outcome": verdict.gate_outcome(),
    })
}

fn tokens() -> (Token, Token, Token) {
    // Test fixture token, not a real secret or key.
    let secret: Token = core::array::from_fn(|i| (i as u8).wrapping_mul(37) ^ 0x5a);
    let mut a = secret;
    a[0] ^= 0xff;
    let mut b = secret;
    b[TOKEN_LEN - 1] ^= 0xff;
    (secret, a, b)
}

struct Run {
    classes: Vec<Class>,
    samples: Vec<f64>,
    thread_cpu_s: Option<f64>,
    wall_s: f64,
}

fn timed_run<O>(
    n_total: usize,
    seed: u64,
    prepare: impl FnMut(Class) -> Token,
    op: impl FnMut(&Token) -> O,
) -> Run {
    let cpu0 = thread_cpu_time().ok();
    let w0 = Instant::now();
    let (classes, samples) = collect(n_total, seed, prepare, op);
    let wall_s = w0.elapsed().as_secs_f64();
    let thread_cpu_s = cpu0
        .zip(thread_cpu_time().ok())
        .map(|(b, a)| a.since(&b).total().as_secs_f64());
    Run {
        classes,
        samples,
        thread_cpu_s,
        wall_s,
    }
}

fn late_stats(mut late_ns: Vec<f64>) -> Value {
    late_ns.sort_by(f64::total_cmp);
    json!({
        "n": late_ns.len(),
        "p50_us": percentile_sorted(&late_ns, 0.5).map(|x| x / 1e3),
        "p99_us": percentile_sorted(&late_ns, 0.99).map(|x| x / 1e3),
        "p999_us": percentile_sorted(&late_ns, 0.999).map(|x| x / 1e3),
        "max_us": late_ns.last().map(|x| x / 1e3),
        "min_us": late_ns.first().map(|x| x / 1e3),
    })
}

fn precision_blocking(mode: WaitMode, ceiling: Duration, tail: Duration, n: usize) -> Value {
    let pad = match CeilingPad::new(CeilingConfig {
        mode,
        spin_tail: tail,
        spin_budget: SpinBudgetConfig::Unlimited,
        ..CeilingConfig::new(ceiling)
    }) {
        Ok(p) => p,
        Err(e) => return json!({"error": e.to_string()}),
    };
    let mut late = Vec::with_capacity(n);
    let mut other = 0u64;
    let cpu0 = thread_cpu_time().ok();
    for i in 0..n {
        match pad.pad(|| black_box(i)) {
            Ok(p) => late.push((p.release.observed.saturating_sub(ceiling)).as_nanos() as f64),
            Err(_) => other += 1,
        }
    }
    let cpu = cpu0
        .zip(thread_cpu_time().ok())
        .map(|(b, a)| a.since(&b).total().as_secs_f64());
    json!({
        "mode": mode.label(),
        "ceiling_us": ceiling.as_secs_f64() * 1e6,
        "tail_us": tail.as_secs_f64() * 1e6,
        "late": late_stats(late),
        "not_served": other,
        "cpu_seconds_per_request": cpu.map(|c| c / n as f64),
        "cpu_fraction_of_ceiling": cpu.map(|c| c / n as f64 / ceiling.as_secs_f64()),
    })
}

fn precision_async(mode: WaitMode, ceiling: Duration, tail: Duration, n: usize) -> Value {
    let rt = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(rt) => rt,
        Err(e) => return json!({"error": e.to_string()}),
    };
    let pad = match CeilingPad::new(CeilingConfig {
        mode,
        async_spin_tail: tail,
        spin_budget: SpinBudgetConfig::Unlimited,
        ..CeilingConfig::new(ceiling)
    }) {
        Ok(p) => p,
        Err(e) => return json!({"error": e.to_string()}),
    };
    let cpu0 = thread_cpu_time().ok();
    let (late, other) = rt.block_on(async {
        let mut late = Vec::with_capacity(n);
        let mut other = 0u64;
        for i in 0..n {
            match pad.pad_async(|| async move { black_box(i) }).await {
                Ok(p) => late.push((p.release.observed.saturating_sub(ceiling)).as_nanos() as f64),
                Err(_) => other += 1,
            }
        }
        (late, other)
    });
    let cpu = cpu0
        .zip(thread_cpu_time().ok())
        .map(|(b, a)| a.since(&b).total().as_secs_f64());
    json!({
        "mode": mode.label(),
        "ceiling_us": ceiling.as_secs_f64() * 1e6,
        "async_tail_us": tail.as_secs_f64() * 1e6,
        "late": late_stats(late),
        "not_served": other,
        "cpu_seconds_per_request": cpu.map(|c| c / n as f64),
    })
}

struct FloodParams {
    secs: u64,
    ceiling: Duration,
    cap: usize,
    threads: usize,
    backoff: Duration,
}

fn flood(
    name: &str,
    cfg: CeilingConfig,
    fp: &FloodParams,
    secret: Token,
    fast_fail: Token,
) -> Value {
    let requested = cfg.mode;
    let charge = cfg.spin_charge();
    let budget = cfg.spin_budget;
    let pad = match CeilingPad::new(cfg) {
        Ok(p) => Arc::new(p),
        Err(e) => return json!({"name": name, "error": e.to_string()}),
    };
    let stop = Arc::new(AtomicBool::new(false));
    let served = Arc::new(AtomicU64::new(0));
    let shed = Arc::new(AtomicU64::new(0));
    let other = Arc::new(AtomicU64::new(0));
    // Thread CPU nanoseconds spent inside `pad` calls (admission, operation,
    // wait), summed over flood workers: the server-side cost, separated from
    // the in-process attacker loop (its shed backoff sleeps and bookkeeping).
    let cpu_in_pad_ns = Arc::new(AtomicU64::new(0));
    let overruns = Arc::new(AtomicU64::new(0));
    let spun = Arc::new(AtomicU64::new(0));
    let cpu0 = process_cpu_time().ok();
    let w0 = Instant::now();
    let mut late_all: Vec<f64> = Vec::new();
    let mut legit = json!(null);
    std::thread::scope(|s| {
        let mut handles = Vec::new();
        for _ in 0..fp.threads {
            let cpu_in_pad_ns = Arc::clone(&cpu_in_pad_ns);
            let (pad, stop, served, shed, other, overruns, spun) = (
                Arc::clone(&pad),
                Arc::clone(&stop),
                Arc::clone(&served),
                Arc::clone(&shed),
                Arc::clone(&other),
                Arc::clone(&overruns),
                Arc::clone(&spun),
            );
            let backoff = fp.backoff;
            let ceiling = fp.ceiling;
            handles.push(s.spawn(move || {
                let mut late = Vec::new();
                while !stop.load(Ordering::Relaxed) {
                    let c0 = thread_cpu_time().ok();
                    let r = pad.pad(|| leaky_validate(&secret, &fast_fail));
                    if let Some(d) = c0
                        .zip(thread_cpu_time().ok())
                        .map(|(b, a)| a.since(&b).total())
                    {
                        let ns = u64::try_from(d.as_nanos()).unwrap_or(u64::MAX);
                        cpu_in_pad_ns.fetch_add(ns, Ordering::Relaxed);
                    }
                    match r {
                        Ok(p) => {
                            served.fetch_add(1, Ordering::Relaxed);
                            if p.release.buckets > 1 {
                                overruns.fetch_add(1, Ordering::Relaxed);
                            }
                            if p.release.mode != WaitMode::Sleep {
                                spun.fetch_add(1, Ordering::Relaxed);
                            }
                            if late.len() < MAX_LATE_SAMPLES_PER_THREAD {
                                let bucket =
                                    ceiling * u32::try_from(p.release.buckets).unwrap_or(u32::MAX);
                                late.push(
                                    p.release.observed.saturating_sub(bucket).as_nanos() as f64
                                );
                            }
                        }
                        Err(Trip::SlotsFull) => {
                            shed.fetch_add(1, Ordering::Relaxed);
                            std::thread::sleep(backoff);
                        }
                        Err(Trip::Overrun) => {
                            overruns.fetch_add(1, Ordering::Relaxed);
                            other.fetch_add(1, Ordering::Relaxed);
                        }
                        Err(_) => {
                            other.fetch_add(1, Ordering::Relaxed);
                        }
                    }
                }
                late
            }));
        }
        let legit_handle = {
            let (pad, stop) = (Arc::clone(&pad), Arc::clone(&stop));
            let backoff = fp.backoff;
            s.spawn(move || {
                // One logical request every 5 ms. On RETRY (shed) the client
                // retries with the same backoff as the flood, up to
                // LEGIT_MAX_ATTEMPTS attempts.
                let (mut logical, mut first_try, mut completed, mut correct) =
                    (0u64, 0u64, 0u64, 0u64);
                let (mut attempts, mut gave_up) = (0u64, 0u64);
                while !stop.load(Ordering::Relaxed) {
                    logical += 1;
                    let mut done = false;
                    for attempt in 0..LEGIT_MAX_ATTEMPTS {
                        attempts += 1;
                        match pad.pad(|| leaky_validate(&secret, &secret)) {
                            Ok(p) => {
                                completed += 1;
                                if attempt == 0 {
                                    first_try += 1;
                                }
                                if p.value {
                                    correct += 1;
                                }
                                done = true;
                                break;
                            }
                            Err(Trip::SlotsFull) => std::thread::sleep(backoff),
                            Err(_) => break,
                        }
                    }
                    if !done {
                        gave_up += 1;
                    }
                    std::thread::sleep(Duration::from_millis(5));
                }
                json!({
                    "logical_requests": logical,
                    "completed": completed,
                    "completed_first_try": first_try,
                    "completed_correct": correct,
                    "gave_up": gave_up,
                    "attempts": attempts,
                    "max_attempts": LEGIT_MAX_ATTEMPTS,
                })
            })
        };
        std::thread::sleep(Duration::from_secs(fp.secs));
        stop.store(true, Ordering::Relaxed);
        for h in handles {
            if let Ok(mut v) = h.join() {
                late_all.append(&mut v);
            }
        }
        legit = legit_handle.join().unwrap_or(Value::Null);
    });
    let wall = w0.elapsed().as_secs_f64();
    let cpu = cpu0
        .zip(process_cpu_time().ok())
        .map(|(b, a)| a.since(&b).total().as_secs_f64());
    let served = served.load(Ordering::Relaxed);
    let shed = shed.load(Ordering::Relaxed);
    let spun = spun.load(Ordering::Relaxed);
    let reserved_spin_s = spun as f64 * charge.as_secs_f64();
    let (budget_json, bound) = match budget {
        SpinBudgetConfig::Limited {
            cpu_per_second,
            burst,
        } => {
            let bound = cpu_per_second.as_secs_f64() * wall + burst.as_secs_f64();
            (
                json!({"cpu_per_second_s": cpu_per_second.as_secs_f64(), "burst_s": burst.as_secs_f64()}),
                Some(bound),
            )
        }
        SpinBudgetConfig::Unlimited => (json!("unlimited"), None),
    };
    let capacity = fp.cap as f64 / fp.ceiling.as_secs_f64();
    let offered = (served + shed) as f64 / wall;
    json!({
        "name": name,
        "mode": requested.label(),
        "spin_budget": budget_json,
        "threads": fp.threads,
        "max_concurrent": fp.cap,
        "ceiling_us": fp.ceiling.as_secs_f64() * 1e6,
        "shed_backoff_us": fp.backoff.as_secs_f64() * 1e6,
        "wall_seconds": wall,
        "process_cpu_seconds": cpu,
        "cpu_utilization_cores": cpu.map(|c| c / wall),
        "requests_served": served,
        "requests_shed": shed,
        "requests_other": other.load(Ordering::Relaxed),
        "overruns": overruns.load(Ordering::Relaxed),
        "served_with_spin": spun,
        "served_with_sleep_fallback": served.saturating_sub(spun),
        "cpu_inside_pad_seconds": cpu_in_pad_ns.load(Ordering::Relaxed) as f64 / 1e9,
        "cpu_inside_pad_cores": cpu_in_pad_ns.load(Ordering::Relaxed) as f64 / 1e9 / wall,
        "spin_reserved_seconds": reserved_spin_s,
        "spin_budget_bound_seconds": bound,
        "spin_within_budget": bound.map(|b| reserved_spin_s <= b),
        "admission_capacity_per_second": capacity,
        "offered_per_second": offered,
        "offered_over_capacity": offered / capacity,
        "release_late_vs_bucket": late_stats(late_all),
        "legitimate_client": legit,
    })
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let n_per_class = to_usize(env_u64(
        "TACK_VERIFY_N_PER_CLASS",
        100_000,
        10_000,
        5_000_000,
    )?)?;
    let ceiling = Duration::from_micros(env_u64("TACK_VERIFY_CEILING_US", 300, 20, 100_000)?);
    let tail = Duration::from_micros(env_u64("TACK_VERIFY_TAIL_US", 150, 0, 100_000)?);
    let prec_n = to_usize(env_u64("TACK_VERIFY_PRECISION_N", 2_000, 100, 1_000_000)?)?;
    let flood_secs = env_u64("TACK_VERIFY_FLOOD_SECS", 3, 1, 60)?;
    let flood_ceiling =
        Duration::from_micros(env_u64("TACK_VERIFY_FLOOD_CEILING_US", 1_000, 20, 100_000)?);
    let cpus = env::cpu_count().unwrap_or(1);
    let default_cap = u64::try_from((cpus / 2).max(1)).unwrap_or(1);
    let flood_cap = to_usize(env_u64("TACK_VERIFY_FLOOD_CAP", default_cap, 1, 4_096)?)?;
    let seed = env_u64("TACK_VERIFY_SEED", 0x7ac4_ce11, 0, u64::MAX)?;
    let n_total = n_per_class * 2;
    let started = Instant::now();
    let env_before = env::snapshot();

    let (secret, a, b) = tokens();
    let prepare = move |c: Class| match c {
        Class::A => a,
        Class::B => b,
    };
    let crops = DEFAULT_CROP_PERCENTILES;
    let analyze_run =
        |r: &Run| analyze(&r.classes, &r.samples, TimeUnit::Nanoseconds, &crops, 1_000);

    // 1. Calibration.
    let leaky_run = timed_run(n_total, seed, prepare, |c| leaky_validate(&secret, c));
    let leaky_env = env::snapshot();
    let ct_run = timed_run(n_total, seed, prepare, |c| ct_validate(&secret, c));
    let ct_env = env::snapshot();
    let leaky_rep = analyze_run(&leaky_run)?;
    let ct_rep = analyze_run(&ct_run)?;
    let leaky_first = leaky_rep
        .cropped
        .iter()
        .filter_map(|c| c.t)
        .fold(leaky_rep.t_raw.map_or(0.0, f64::abs), |m, t| m.max(t.abs()));
    let ct_raw_ok = ct_rep.t_raw.is_some_and(|t| t.abs() < T_THRESHOLD);
    let calibration_passed = leaky_first > T_THRESHOLD && ct_raw_ok;
    let base_a = class_pct(&leaky_run.classes, &leaky_run.samples, Class::A);
    let base_b = class_pct(&leaky_run.classes, &leaky_run.samples, Class::B);

    // 2. Padded runs.
    let mut padded = serde_json::Map::new();
    for mode in [WaitMode::Sleep, WaitMode::Spin, WaitMode::Hybrid] {
        let pad = CeilingPad::new(CeilingConfig {
            mode,
            spin_tail: tail,
            // One measuring thread: the budget would only turn Spin into
            // Sleep here and blur the per-mode result. Its CPU cost is
            // reported below; the flood section tests the budget.
            spin_budget: SpinBudgetConfig::Unlimited,
            ..CeilingConfig::new(ceiling)
        })?;
        let overrun_released = Cell::new(0u64);
        let overrun_retry = Cell::new(0u64);
        let other = Cell::new(0u64);
        let run = timed_run(n_total, seed, prepare, |c| {
            let r = pad.pad(|| leaky_validate(&secret, c));
            match &r {
                Ok(p) if p.release.buckets > 1 => overrun_released.set(overrun_released.get() + 1),
                Ok(_) => {}
                Err(Trip::Overrun) => overrun_retry.set(overrun_retry.get() + 1),
                Err(_) => other.set(other.get() + 1),
            }
            r.map(|p| p.value)
        });
        let run_env = env::snapshot();
        let rep = analyze_run(&run)?;
        let pa = class_pct(&run.classes, &run.samples, Class::A);
        let pb = class_pct(&run.classes, &run.samples, Class::B);
        let total_overrun = overrun_released.get() + overrun_retry.get();
        padded.insert(
            mode.label().to_string(),
            json!({
                "mode": mode.label(),
                "ceiling_us": ceiling.as_secs_f64() * 1e6,
                "spin_tail_us": if mode == WaitMode::Hybrid { Some(tail.as_secs_f64() * 1e6) } else { None },
                "seed": seed,
                "detect": detect_json(&rep),
                "percentiles": {"a": pct_json(&pa), "b": pct_json(&pb)},
                "added_latency_vs_unpadded": {"a": added_json(&pa, &base_a), "b": added_json(&pb, &base_b)},
                "overrun_released": overrun_released.get(),
                "overrun_retry": overrun_retry.get(),
                "overrun_rate": total_overrun as f64 / n_total as f64,
                "not_served_other": other.get(),
                "thread_cpu_seconds": run.thread_cpu_s,
                "thread_cpu_seconds_per_request": run.thread_cpu_s.map(|c| c / n_total as f64),
                "wall_seconds": run.wall_s,
                "env": run_env,
            }),
        );
    }

    // 3. Precision, idle.
    let async_ceiling = Duration::from_millis(5);
    let async_tail = tack_anc_ceiling::config::DEFAULT_ASYNC_SPIN_TAIL;
    let async_n = (prec_n / 4).max(25);
    let blocking: Vec<Value> = [WaitMode::Sleep, WaitMode::Spin, WaitMode::Hybrid]
        .into_iter()
        .map(|m| precision_blocking(m, ceiling, tail, prec_n))
        .collect();
    let default_tail = tack_anc_ceiling::config::DEFAULT_SPIN_TAIL;
    let blocking_1ms: Vec<Value> = [WaitMode::Sleep, WaitMode::Hybrid]
        .into_iter()
        .map(|m| precision_blocking(m, Duration::from_millis(1), default_tail, prec_n))
        .collect();
    let asyncs: Vec<Value> = [WaitMode::Sleep, WaitMode::Spin, WaitMode::Hybrid]
        .into_iter()
        .map(|m| precision_async(m, async_ceiling, async_tail, async_n))
        .collect();
    let precision = json!({
        "blocking": blocking,
        "blocking_1ms_default_tail": blocking_1ms,
        "async": asyncs,
    });

    // 4. Flood.
    let fp = FloodParams {
        secs: flood_secs,
        ceiling: flood_ceiling,
        cap: flood_cap,
        threads: 2 * cpus,
        backoff: Duration::from_micros(200),
    };
    let base = CeilingConfig {
        max_concurrent: flood_cap,
        ..CeilingConfig::new(flood_ceiling)
    };
    let flood_json = json!([
        flood(
            "spin_no_budget",
            CeilingConfig {
                mode: WaitMode::Spin,
                spin_budget: SpinBudgetConfig::Unlimited,
                ..base.clone()
            },
            &fp,
            secret,
            a
        ),
        flood(
            "hybrid_with_budget",
            CeilingConfig {
                mode: WaitMode::Hybrid,
                spin_tail: Duration::from_micros(250),
                spin_budget: SpinBudgetConfig::Limited {
                    cpu_per_second: Duration::from_millis(250),
                    burst: Duration::from_millis(25),
                },
                ..base.clone()
            },
            &fp,
            secret,
            a
        ),
        flood(
            "sleep",
            CeilingConfig {
                mode: WaitMode::Sleep,
                ..base.clone()
            },
            &fp,
            secret,
            a
        ),
    ]);

    let out = json!({
        "tool": "tack-anc-ceiling examples/verify.rs",
        "build": if cfg!(debug_assertions) { "debug (timings are not evidence)" } else { "release" },
        "threshold": T_THRESHOLD,
        "crop_line": CROP_LINE,
        "n_per_class_target": n_per_class,
        "seed": seed,
        "classes": "A: differs at byte 0; B: equal in bytes 0..30, differs at byte 31",
        "env_before": env_before,
        "calibration": {
            "passed": calibration_passed,
            "rule": "unpadded leaky max first-order |t| > 4.5 and unpadded ct raw |t| < 4.5 at the same n",
            "leaky": {"detect": detect_json(&leaky_rep), "percentiles": {"a": pct_json(&base_a), "b": pct_json(&base_b)}, "wall_seconds": leaky_run.wall_s, "env": leaky_env},
            "ct": {"detect": detect_json(&ct_rep), "wall_seconds": ct_run.wall_s, "env": ct_env},
        },
        "padded": padded,
        "precision": precision,
        "flood": flood_json,
        "env_after": env::snapshot(),
        "total_wall_seconds": started.elapsed().as_secs_f64(),
    });
    println!("{}", serde_json::to_string_pretty(&out)?);
    Ok(())
}
