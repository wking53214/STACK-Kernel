//! Measure adaptive padding (strategy 2): unprotected, the naive rolling
//! target, and the epoch-quantized target, on a victim whose run time
//! depends on the secret AND drifts with load. Prints one JSON document on
//! stdout.
//!
//! Run in release mode (debug timings are not evidence):
//!
//! ```text
//! cargo run --release -p tack-anc-adaptive --example verify > verify.json
//! ```
//!
//! Sections:
//! 1. `calibration`: unpadded `leaky_validate` must be flagged (max
//!    first-order |t|, raw or cropped, above 4.5) and unpadded
//!    `ct_validate` must not (raw |t| below 4.5). If this fails,
//!    `calibration.passed` is false and nothing else in the run proves
//!    anything.
//! 2. `runs`: the drifting victim unprotected, then inside a naive pad
//!    (mean and p99) and an epoch pad (Sleep, the default, and Hybrid).
//!    Every run has a background load phase over its middle third: the
//!    victim's base work is multiplied by `LOAD_MULT` and `LOAD_THREADS`
//!    threads stream through memory. Timed from the call (admission) to
//!    the return (release), which is what a client sees.
//! 3. `poisoning`: leak 2. An attacker floods fast requests (a guess wrong
//!    at byte 0) to pull the naive p99 target down, then probes with a
//!    random-class request; the probes' times are tested. The same attack
//!    is run against the epoch pad. Also a slow flood against the naive
//!    pad, to show the cap bounds it.
//! 4. `trajectory`: leak 3. The same pads under traffic that is 90 percent
//!    class A, then 90 percent class B. For the naive pad the target (and
//!    so every response) follows the mix; for the epoch pad the sequence of
//!    target levels is compared between the two mixes.
//! 5. `flood`: 10 x `max_concurrent` threads send fast-fail requests for a
//!    fixed wall time, against the epoch pad in Hybrid with a spin budget
//!    and in Sleep, plus one legitimate client every 5 ms (retrying on
//!    RETRY up to 200 attempts). A shed flood worker sleeps 200 us before
//!    its next request (a stand-in for a network round trip). Reports
//!    sheds, the spin budget bound, CPU, legitimate completions, and how
//!    many target changes the flood forced.
//! 6. `budget_default`: the epoch pad with the production default leak
//!    budget (`LeakBudgetConfig::default()`) on the drifting victim, to
//!    show how fast host noise and the load phase spend it and what the
//!    pad does after (target rolled back to the cap, requests served).
//!
//! The victim: `leaky_validate` (early-exit compare) called `ROUNDS` times,
//! then `BASE_ITERS * load_multiplier` iterations of a multiply-add loop.
//! Classes: A = candidate differs from the secret at byte 0 (fastest early
//! exit); B = equal in bytes 0..30, differs at byte 31 (slowest wrong
//! path). The class of each sample is drawn at random from a recorded seed
//! and interleaved, so drift and load hit both classes equally. Inputs are
//! two fixed arrays chosen by class, so no input generation happens next
//! to the timed region.
//!
//! Environment variables (all optional; out-of-range values are an error):
//! * `TACK_ADAPTIVE_N_PER_CLASS`: samples per class in `calibration` and
//!   `runs`, default 100000, bounds 10000 ..= 5000000.
//! * `TACK_ADAPTIVE_POISON_PROBES`: probes per class in `poisoning`,
//!   default 10000, bounds 10000 ..= 1000000.
//! * `TACK_ADAPTIVE_TRAJ_N`: samples per run in `trajectory`, default
//!   40000, bounds 1000 ..= 1000000.
//! * `TACK_ADAPTIVE_ROUNDS`: `leaky_validate` calls per victim call,
//!   default 256, bounds 1 ..= 100000.
//! * `TACK_ADAPTIVE_BASE_ITERS`: base work iterations, default 10000,
//!   bounds 0 ..= 100000000.
//! * `TACK_ADAPTIVE_LOAD_MULT`: base work multiplier in the load phase,
//!   default 4, bounds 1 ..= 1000.
//! * `TACK_ADAPTIVE_LOAD_THREADS`: memory-streaming threads in the load
//!   phase, default 2, bounds 0 ..= 64.
//! * `TACK_ADAPTIVE_FLOOR_US`, `TACK_ADAPTIVE_CAP_US`: epoch ladder floor
//!   and cap (also the naive cap), defaults 64 and 2048.
//! * `TACK_ADAPTIVE_EPOCH_MS`: epoch length, default 50.
//! * `TACK_ADAPTIVE_BUDGET_BITS`: epoch leak budget per 60 s window in
//!   `runs`, `poisoning`, `trajectory` and `flood`, default 1000000. This
//!   is a measurement setting, not a production value: it keeps the
//!   controller adapting so its behaviour can be measured, and every run
//!   reports the bits it would have spent. Section 6 runs the production
//!   default budget (128 bits per 60 s) to show when it is spent.
//! * `TACK_ADAPTIVE_FLOOD_SECS`: wall seconds per flood config, default 3,
//!   bounds 1 ..= 60.
//! * `TACK_ADAPTIVE_FLOOD_CAP`: `max_concurrent` in the flood, default
//!   max(1, CPU count / 2).
//! * `TACK_ADAPTIVE_SEED`: class schedule seed, default 0x7ac4ada9. Not a
//!   key.
//!
//! With the defaults the whole run took 511 s on the development host (4
//! vCPU Xeon VM); the `meta.wall_seconds` field records it.

use serde_json::{json, Value};
use std::hint::black_box;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tack_anc_adaptive::{
    epoch_bound_bits, ladder_bound_bits, AdaptivePad, ControllerStatus, Disposition, EpochConfig,
    EpochQuantizedTarget, LeakBudgetConfig, NaiveConfig, NaiveRollingTarget, PadConfig, PadResult,
    SpinBudgetConfig, Trip, WaitMode, WindowStatistic,
};
use tack_anc_harness::cpu::{process_cpu_time, thread_cpu_time};
use tack_anc_harness::stats::percentile_sorted;
use tack_anc_harness::victim::{ct_validate, leaky_validate, TOKEN_LEN};
use tack_anc_harness::{
    analyze, env, Class, Report, SplitMix64, TimeUnit, DEFAULT_CROP_PERCENTILES, T_THRESHOLD,
};

const WARMUP: usize = 2_000;
const CROP_LINE: f64 = 10.0;
const MIN_PER_CLASS: u64 = 1_000;
const MAX_TRAJECTORY_POINTS: usize = 256;
const LEGIT_MAX_ATTEMPTS: u32 = 200;
const LOAD_BUFFER_WORDS: usize = 2 << 20; // 16 MiB of u64 per load thread
const POISON_WINDOW: usize = 16;
const MAX_OCCUPANCY_KEYS: usize = 64;

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

/// Test fixtures, not keys.
fn tokens() -> (Token, Token, Token) {
    let secret = [0x5au8; TOKEN_LEN];
    let mut a = secret;
    a[0] ^= 0xff;
    let mut b = secret;
    b[TOKEN_LEN - 1] ^= 0xff;
    (secret, a, b)
}

fn busy(iters: u64) -> u64 {
    let mut x = 1u64;
    for i in 0..iters {
        x = black_box(x.wrapping_mul(6_364_136_223_846_793_005).wrapping_add(i));
    }
    x
}

/// The secret-dependent, load-drifting victim.
struct Workload {
    secret: Token,
    rounds: u32,
    base_iters: u64,
    load_mult: u64,
    /// Current base multiplier: 1 idle, `load_mult` in the load phase.
    mult: AtomicU64,
    /// True while the background threads stream memory.
    loaded: AtomicBool,
}

impl Workload {
    fn run(&self, cand: &Token) -> bool {
        let mut ok = true;
        for _ in 0..self.rounds {
            ok &= leaky_validate(&self.secret, black_box(cand));
        }
        let m = self.mult.load(Ordering::Relaxed);
        black_box(busy(self.base_iters.saturating_mul(m)));
        ok
    }

    fn set_load(&self, on: bool) {
        self.mult
            .store(if on { self.load_mult } else { 1 }, Ordering::Relaxed);
        self.loaded.store(on, Ordering::Relaxed);
    }
}

/// Background memory streaming while `wl.loaded` is set, until `stop`.
fn load_thread(wl: &Workload, stop: &AtomicBool) {
    let mut buf = vec![1u64; LOAD_BUFFER_WORDS];
    let mut acc = 0u64;
    while !stop.load(Ordering::Relaxed) {
        if wl.loaded.load(Ordering::Relaxed) {
            for (i, w) in buf.iter_mut().enumerate().step_by(8) {
                *w = w.wrapping_add(i as u64);
                acc = acc.wrapping_add(*w);
            }
            black_box(acc);
        } else {
            std::thread::sleep(Duration::from_millis(1));
        }
    }
}

/// What one padded (or unpadded) call reported.
#[derive(Clone, Copy)]
enum Obs {
    Unpadded,
    Served {
        target: Duration,
        disposition: Disposition,
    },
    Tripped(Trip),
}

fn obs<T>(r: &PadResult<T>) -> Obs {
    match r {
        Ok(p) => Obs::Served {
            target: p.release.target,
            disposition: p.release.disposition,
        },
        Err(t) => Obs::Tripped(*t),
    }
}

#[derive(Default)]
struct Tally {
    on_time: u64,
    late: u64,
    escalated: u64,
    overrun_retry: u64,
    other_trip: u64,
    target_points: Vec<(usize, f64)>,
    target_moves: u64,
    target_sum_us: f64,
    last_target: Option<Duration>,
    /// Served samples per target, in microseconds. At most one entry per
    /// ladder level (epoch) or per distinct target (naive: capped).
    occupancy: std::collections::BTreeMap<u64, u64>,
}

impl Tally {
    fn add(&mut self, i: usize, o: Obs) {
        match o {
            Obs::Unpadded => {}
            Obs::Served {
                target,
                disposition,
            } => {
                match disposition {
                    Disposition::OnTime => self.on_time += 1,
                    Disposition::Late => self.late += 1,
                    Disposition::Escalated { .. } => self.escalated += 1,
                }
                self.target_sum_us += target.as_secs_f64() * 1e6;
                let key = u64::try_from(target.as_micros()).unwrap_or(u64::MAX);
                if self.occupancy.len() < MAX_OCCUPANCY_KEYS || self.occupancy.contains_key(&key) {
                    *self.occupancy.entry(key).or_insert(0) += 1;
                }
                if self.last_target != Some(target) {
                    self.target_moves += 1;
                    if self.target_points.len() < MAX_TRAJECTORY_POINTS {
                        self.target_points.push((i, target.as_secs_f64() * 1e6));
                    }
                    self.last_target = Some(target);
                }
            }
            Obs::Tripped(Trip::Overrun) => self.overrun_retry += 1,
            Obs::Tripped(_) => self.other_trip += 1,
        }
    }

    fn json(&self, n: usize) -> Value {
        let served = self.on_time + self.late + self.escalated;
        json!({
            "on_time": self.on_time,
            "late": self.late,
            "escalated": self.escalated,
            "overrun_retry": self.overrun_retry,
            "other_trip": self.other_trip,
            "overrun_rate": (self.late + self.escalated + self.overrun_retry) as f64 / n.max(1) as f64,
            "mean_target_us": if served > 0 { Some(self.target_sum_us / served as f64) } else { None },
            "distinct_target_runs": self.target_moves,
            "samples_per_target_us": self.occupancy.iter().map(|(k, v)| json!([k, v])).collect::<Vec<_>>(),
            "target_points_first_256": self.target_points.iter().map(|(i, t)| json!([i, t])).collect::<Vec<_>>(),
        })
    }
}

struct Run {
    classes: Vec<Class>,
    samples: Vec<f64>,
    tally: Tally,
    wall_s: f64,
    thread_cpu_s: Option<f64>,
}

fn schedule(n_total: usize, seed: u64, share_b_permille: Option<u64>) -> Vec<Class> {
    let mut rng = SplitMix64::new(seed);
    (0..n_total)
        .map(|_| match share_b_permille {
            None => rng.next_class(),
            Some(p) => {
                if rng.next_u64() % 1_000 < p {
                    Class::B
                } else {
                    Class::A
                }
            }
        })
        .collect()
}

/// Time `op` over `classes`, with the load phase over the middle third.
fn collect(
    classes: Vec<Class>,
    (a, b): (&Token, &Token),
    wl: &Workload,
    load_threads: usize,
    mut op: impl FnMut(&Token) -> Obs,
) -> Run {
    let n = classes.len();
    let stop = AtomicBool::new(false);
    wl.set_load(false);
    let mut run = Run {
        classes,
        samples: Vec::with_capacity(n),
        tally: Tally::default(),
        wall_s: 0.0,
        thread_cpu_s: None,
    };
    std::thread::scope(|s| {
        for _ in 0..load_threads {
            s.spawn(|| load_thread(wl, &stop));
        }
        for i in 0..WARMUP {
            black_box(op(if i % 2 == 0 { a } else { b }));
        }
        let cpu0 = thread_cpu_time().ok();
        let w0 = Instant::now();
        for (i, &c) in run.classes.iter().enumerate() {
            if i == n / 3 {
                wl.set_load(true);
            } else if i == 2 * n / 3 {
                wl.set_load(false);
            }
            let input = match c {
                Class::A => a,
                Class::B => b,
            };
            let t0 = Instant::now();
            let o = black_box(op(black_box(input)));
            let t1 = Instant::now();
            run.samples.push(t1.duration_since(t0).as_nanos() as f64);
            run.tally.add(i, o);
        }
        run.wall_s = w0.elapsed().as_secs_f64();
        run.thread_cpu_s = cpu0
            .zip(thread_cpu_time().ok())
            .map(|(b, a)| a.since(&b).total().as_secs_f64());
        wl.set_load(false);
        stop.store(true, Ordering::Relaxed);
    });
    run
}

fn detect_json(r: &Report) -> Value {
    let na = r.n_a as f64;
    let nb = r.n_b as f64;
    let ks_crit = if na > 0.0 && nb > 0.0 {
        Some(1.95 * ((na + nb) / (na * nb)).sqrt())
    } else {
        None
    };
    let delta_min = match (r.a.variance, r.b.variance) {
        (Some(va), Some(vb)) if na > 0.0 && nb > 0.0 => {
            Some(T_THRESHOLD * (va / na + vb / nb).sqrt())
        }
        _ => None,
    };
    let max_crop = r
        .cropped
        .iter()
        .filter_map(|c| c.t)
        .fold(0.0f64, |m, t| m.max(t.abs()));
    let first = r.t_raw.map(|t| t.abs() < T_THRESHOLD);
    let second = r.t_second_order.map(|t| t.abs() < T_THRESHOLD);
    let ks = r.ks_p.map(|p| p >= 0.001);
    let crops = max_crop < CROP_LINE;
    let all = first == Some(true) && second == Some(true) && ks == Some(true) && crops;
    json!({
        "n_a": r.n_a,
        "n_b": r.n_b,
        "mean_a_ns": r.a.mean,
        "mean_b_ns": r.b.mean,
        "t_first_order": r.t_raw,
        "t_second_order": r.t_second_order,
        "t_cropped": r.cropped.iter().map(|c| json!({"p": c.percentile, "t": c.t})).collect::<Vec<_>>(),
        "max_abs_t": r.max_abs_t,
        "max_source": format!("{:?}", r.max_source),
        "ks_d": r.ks_d,
        "ks_p": r.ks_p,
        "ks_d_critical_p001": ks_crit,
        "delta_min_ns": delta_min,
        "pass_first_order": first,
        "pass_second_order": second,
        "pass_ks": ks,
        "pass_crops_line_10": crops,
        "pass_all": all,
        "harness_verdict": format!("{:?}", r.verdict(T_THRESHOLD)),
    })
}

fn class_pct(classes: &[Class], samples: &[f64], want: Class) -> Option<[f64; 3]> {
    let mut v: Vec<f64> = classes
        .iter()
        .zip(samples)
        .filter(|(c, _)| **c == want)
        .map(|(_, s)| *s)
        .collect();
    v.sort_by(f64::total_cmp);
    Some([
        percentile_sorted(&v, 0.5)?,
        percentile_sorted(&v, 0.99)?,
        percentile_sorted(&v, 0.999)?,
    ])
}

fn pct_json(p: Option<[f64; 3]>) -> Value {
    p.map_or(
        Value::Null,
        |p| json!({"p50_ns": p[0], "p99_ns": p[1], "p999_ns": p[2]}),
    )
}

fn added_json(p: Option<[f64; 3]>, base: Option<[f64; 3]>) -> Value {
    match (p, base) {
        (Some(p), Some(b)) => {
            json!({"p50_ns": p[0] - b[0], "p99_ns": p[1] - b[1], "p999_ns": p[2] - b[2]})
        }
        _ => Value::Null,
    }
}

fn leak_json(s: &ControllerStatus, levels: Option<u32>, boundaries: Option<u64>) -> Value {
    let n = s.changes_total;
    let r = s.requests_total;
    json!({
        "target_changes": n,
        "increases": s.increases_total,
        "decreases": s.decreases_total,
        "rollbacks": s.rollbacks_total,
        "requests": r,
        "bound_bits_theorist_n_log2_r_plus_1": if n == 0 { 0.0 } else { n as f64 * ((r as f64) + 1.0).log2() },
        "bound_bits_crate_n_log2_2r_plus_2": epoch_bound_bits(n, r),
        "ladder_bits_boundaries_only": levels.zip(boundaries).map(|(k, u)| ladder_bound_bits(u, k)),
        "window_leak_bits": s.leak_bits,
        "window_budget_bits": s.leak_budget_bits,
        "frozen": s.frozen,
        "final_target_us": s.target.as_secs_f64() * 1e6,
    })
}

struct Params {
    n_total: usize,
    seed: u64,
    load_threads: usize,
    floor: Duration,
    cap: Duration,
    epoch: Duration,
    budget_bits: f64,
}

fn epoch_cfg(p: &Params) -> EpochConfig {
    EpochConfig {
        initial_level: 0,
        epoch: p.epoch,
        leak_budget: LeakBudgetConfig {
            bits: p.budget_bits,
            window: Duration::from_secs(60),
        },
        ..EpochConfig::new(p.floor, p.cap)
    }
}

fn naive_cfg(p: &Params, statistic: WindowStatistic) -> NaiveConfig {
    NaiveConfig {
        statistic,
        initial_target: p.floor,
        floor: tack_anc_adaptive::config::MIN_TARGET,
        ..NaiveConfig::new(p.cap)
    }
}

fn run_json(name: &str, cfg: Value, run: &Run, rep: &Report, base: &Run, leak: Value) -> Value {
    let pa = class_pct(&run.classes, &run.samples, Class::A);
    let pb = class_pct(&run.classes, &run.samples, Class::B);
    let ba = class_pct(&base.classes, &base.samples, Class::A);
    let bb = class_pct(&base.classes, &base.samples, Class::B);
    let n = run.samples.len();
    json!({
        "name": name,
        "config": cfg,
        "detect": detect_json(rep),
        "percentiles": {"a": pct_json(pa), "b": pct_json(pb)},
        "added_latency_vs_unprotected": {"a": added_json(pa, ba), "b": added_json(pb, bb)},
        "releases": run.tally.json(n),
        "leakage": leak,
        "wall_seconds": run.wall_s,
        "thread_cpu_seconds": run.thread_cpu_s,
        "thread_cpu_seconds_per_request": run.thread_cpu_s.map(|c| c / n.max(1) as f64),
        "env_after": env::snapshot(),
    })
}

fn analyze_run(r: &Run) -> Result<Report, tack_anc_harness::HarnessError> {
    analyze(
        &r.classes,
        &r.samples,
        TimeUnit::Nanoseconds,
        &DEFAULT_CROP_PERCENTILES,
        MIN_PER_CLASS,
    )
}

fn epoch_leak(pad: &AdaptivePad<EpochQuantizedTarget>) -> Value {
    let (levels, boundaries) = pad.inspect(|c| (c.config().levels(), c.boundaries_total()));
    leak_json(&pad.status(), Some(levels), Some(boundaries))
}

/// Leak 2: flood fast requests, then probe; probe times only are tested.
fn poisoning(
    p: &Params,
    probes_per_class: usize,
    wl: &Workload,
    (a, b): (&Token, &Token),
) -> Result<Value, Box<dyn std::error::Error>> {
    let n_probes = probes_per_class * 2;
    let classes = schedule(n_probes, p.seed ^ 0x9e37_79b9, None);

    // Naive p99 over a short window: the attacker refills it with fast
    // requests before every probe.
    let naive = AdaptivePad::naive(
        PadConfig::default(),
        NaiveConfig {
            window: POISON_WINDOW,
            ..naive_cfg(p, WindowStatistic::Percentile { permille: 990 })
        },
    )?;
    let mut naive_run = Run {
        classes: classes.clone(),
        samples: Vec::with_capacity(n_probes),
        tally: Tally::default(),
        wall_s: 0.0,
        thread_cpu_s: None,
    };
    let w0 = Instant::now();
    for (i, &c) in classes.iter().enumerate() {
        for _ in 0..POISON_WINDOW {
            black_box(naive.pad(|| wl.run(a)).is_ok());
        }
        let input = if c == Class::A { a } else { b };
        let t0 = Instant::now();
        let r = naive.pad(|| wl.run(black_box(input)));
        let t1 = Instant::now();
        naive_run
            .samples
            .push(t1.duration_since(t0).as_nanos() as f64);
        naive_run.tally.add(i, obs(&r));
    }
    naive_run.wall_s = w0.elapsed().as_secs_f64();
    let naive_rep = analyze_run(&naive_run)?;

    // Epoch: the attacker floods fast requests for 3 epochs (as low as the
    // target can be pushed is the floor), then alternates probe and fast
    // request.
    let epoch = AdaptivePad::epoch(PadConfig::default(), epoch_cfg(p))?;
    let flood_until = Instant::now() + p.epoch * 3;
    while Instant::now() < flood_until {
        black_box(epoch.pad(|| wl.run(a)).is_ok());
    }
    let mut epoch_run = Run {
        classes: classes.clone(),
        samples: Vec::with_capacity(n_probes),
        tally: Tally::default(),
        wall_s: 0.0,
        thread_cpu_s: None,
    };
    let w0 = Instant::now();
    for (i, &c) in classes.iter().enumerate() {
        black_box(epoch.pad(|| wl.run(a)).is_ok());
        let input = if c == Class::A { a } else { b };
        let t0 = Instant::now();
        let r = epoch.pad(|| wl.run(black_box(input)));
        let t1 = Instant::now();
        epoch_run
            .samples
            .push(t1.duration_since(t0).as_nanos() as f64);
        epoch_run.tally.add(i, obs(&r));
    }
    epoch_run.wall_s = w0.elapsed().as_secs_f64();
    let epoch_rep = analyze_run(&epoch_run)?;

    // Slow flood against the naive pad: the target rises to the cap and
    // no further.
    let slow_pad = AdaptivePad::naive(
        PadConfig::default(),
        naive_cfg(p, WindowStatistic::Percentile { permille: 990 }),
    )?;
    for _ in 0..64 {
        black_box(slow_pad.pad(|| wl.run(a)).is_ok());
    }
    let before = slow_pad.status().target;
    let slow_work = p.cap * 2;
    let mut slow_retry = 0u64;
    for _ in 0..tack_anc_adaptive::config::DEFAULT_WINDOW {
        if slow_pad.pad(|| std::thread::sleep(slow_work)) == Err(Trip::Overrun) {
            slow_retry += 1;
        }
    }
    let after = slow_pad.status().target;
    let mut recover = 0u64;
    while slow_pad.status().target > before * 2 && recover < 10_000 {
        black_box(slow_pad.pad(|| wl.run(a)).is_ok());
        recover += 1;
    }

    Ok(json!({
        "probes_per_class": probes_per_class,
        "naive_p99": {
            "window": POISON_WINDOW,
            "fast_requests_before_each_probe": POISON_WINDOW,
            "detect": detect_json(&naive_rep),
            "percentiles": {
                "a": pct_json(class_pct(&naive_run.classes, &naive_run.samples, Class::A)),
                "b": pct_json(class_pct(&naive_run.classes, &naive_run.samples, Class::B)),
            },
            "releases": naive_run.tally.json(n_probes),
            "wall_seconds": naive_run.wall_s,
        },
        "epoch": {
            "fast_flood_epochs_before_probing": 3,
            "fast_requests_between_probes": 1,
            "detect": detect_json(&epoch_rep),
            "percentiles": {
                "a": pct_json(class_pct(&epoch_run.classes, &epoch_run.samples, Class::A)),
                "b": pct_json(class_pct(&epoch_run.classes, &epoch_run.samples, Class::B)),
            },
            "releases": epoch_run.tally.json(n_probes),
            "leakage": epoch_leak(&epoch),
            "wall_seconds": epoch_run.wall_s,
        },
        "naive_slow_flood": {
            "slow_requests": tack_anc_adaptive::config::DEFAULT_WINDOW,
            "slow_work_us": slow_work.as_secs_f64() * 1e6,
            "cap_us": p.cap.as_secs_f64() * 1e6,
            "target_before_us": before.as_secs_f64() * 1e6,
            "target_after_us": after.as_secs_f64() * 1e6,
            "target_within_cap": after <= p.cap,
            "slow_requests_retry": slow_retry,
            "fast_requests_until_target_below_2x_before": recover,
        },
    }))
}

/// Leak 3 and the trajectory check: the same pad under A-heavy and B-heavy
/// traffic.
fn trajectory(
    p: &Params,
    n: usize,
    wl: &Workload,
    toks: (&Token, &Token),
) -> Result<Value, Box<dyn std::error::Error>> {
    let mut out = serde_json::Map::new();
    for (name, is_epoch) in [("naive_mean", false), ("epoch", true)] {
        let mut per_mix = serde_json::Map::new();
        let mut level_seqs: Vec<Vec<u64>> = Vec::new();
        for (mix, share_b) in [("mostly_a", 100u64), ("mostly_b", 900u64)] {
            let classes = schedule(n, p.seed ^ 0x51ed, Some(share_b));
            let (run, leak) = if is_epoch {
                let pad = AdaptivePad::epoch(PadConfig::default(), epoch_cfg(p))?;
                let run = collect(classes, toks, wl, p.load_threads, |c| {
                    obs(&pad.pad(|| wl.run(c)))
                });
                (run, epoch_leak(&pad))
            } else {
                let pad =
                    AdaptivePad::naive(PadConfig::default(), naive_cfg(p, WindowStatistic::Mean))?;
                let run = collect(classes, toks, wl, p.load_threads, |c| {
                    obs(&pad.pad(|| wl.run(c)))
                });
                (run, leak_json(&pad.status(), None, None))
            };
            // Level sequence with consecutive repeats removed.
            let mut seq: Vec<u64> = Vec::new();
            for (_, t) in &run.tally.target_points {
                let t = *t as u64;
                if seq.last() != Some(&t) {
                    seq.push(t);
                }
            }
            level_seqs.push(seq);
            // What an attacker learns from their own fast (class A)
            // requests: their response time follows the target.
            let a_times: Vec<f64> = run
                .classes
                .iter()
                .zip(&run.samples)
                .filter(|(c, _)| **c == Class::A)
                .map(|(_, s)| *s)
                .collect();
            let a_mean = a_times.iter().sum::<f64>() / a_times.len().max(1) as f64;
            per_mix.insert(
                mix.to_string(),
                json!({
                    "share_b_permille": share_b,
                    "samples": n,
                    "class_a_response_mean_ns": a_mean,
                    "releases": run.tally.json(n),
                    "leakage": leak,
                }),
            );
        }
        let same = level_seqs.first() == level_seqs.get(1);
        per_mix.insert("level_sequence_identical".to_string(), json!(same));
        per_mix.insert(
            "level_sequences_first_64_us".to_string(),
            json!(level_seqs
                .iter()
                .map(|s| s.iter().take(64).collect::<Vec<_>>())
                .collect::<Vec<_>>()),
        );
        out.insert(name.to_string(), Value::Object(per_mix));
    }
    Ok(Value::Object(out))
}

/// The production default leak budget on the drifting victim.
fn budget_default(
    p: &Params,
    n: usize,
    wl: &Workload,
    toks: (&Token, &Token),
) -> Result<Value, Box<dyn std::error::Error>> {
    let cfg = EpochConfig {
        leak_budget: LeakBudgetConfig::default(),
        ..epoch_cfg(p)
    };
    let pad = AdaptivePad::epoch(PadConfig::default(), cfg)?;
    let t0 = Instant::now();
    let calls = std::cell::Cell::new(0u64);
    let frozen_at = std::cell::Cell::new(None::<(u64, f64)>);
    let run = collect(
        schedule(n, p.seed ^ 0xb0d6, None),
        toks,
        wl,
        p.load_threads,
        |c| {
            let o = obs(&pad.pad(|| wl.run(c)));
            calls.set(calls.get() + 1);
            if frozen_at.get().is_none() && pad.status().frozen {
                frozen_at.set(Some((calls.get(), t0.elapsed().as_secs_f64())));
            }
            o
        },
    );
    let rep = analyze_run(&run)?;
    Ok(json!({
        "leak_budget_bits_per_window": cfg.leak_budget.bits,
        "window_seconds": cfg.leak_budget.window.as_secs_f64(),
        "samples": n,
        "warmup_requests_included_in_counts": WARMUP,
        "frozen": frozen_at.get().is_some(),
        "requests_until_frozen": frozen_at.get().map(|f| f.0),
        "seconds_until_frozen": frozen_at.get().map(|f| f.1),
        "detect": detect_json(&rep),
        "releases": run.tally.json(n),
        "leakage": epoch_leak(&pad),
        "wall_seconds": run.wall_s,
    }))
}

struct FloodParams {
    secs: u64,
    cap: usize,
    threads: usize,
    backoff: Duration,
}

fn flood(
    name: &str,
    pad_cfg: PadConfig,
    p: &Params,
    fp: &FloodParams,
    wl: &Workload,
    (secret, fast_fail): (&Token, &Token),
) -> Value {
    let charge = pad_cfg.spin_charge();
    let budget = pad_cfg.spin_budget;
    let mode = pad_cfg.mode;
    let pad = match AdaptivePad::epoch(pad_cfg, epoch_cfg(p)) {
        Ok(pad) => Arc::new(pad),
        Err(e) => return json!({"name": name, "error": e.to_string()}),
    };
    // Settle the controller on idle legitimate traffic first.
    for _ in 0..2_000 {
        black_box(pad.pad(|| wl.run(secret)).is_ok());
    }
    let before = pad.status();
    let stop = AtomicBool::new(false);
    let (served, shed, spun, other, escalated) = (
        AtomicU64::new(0),
        AtomicU64::new(0),
        AtomicU64::new(0),
        AtomicU64::new(0),
        AtomicU64::new(0),
    );
    let cpu_in_pad_ns = AtomicU64::new(0);
    let cpu0 = process_cpu_time().ok();
    let w0 = Instant::now();
    let mut legit = Value::Null;
    std::thread::scope(|s| {
        for _ in 0..fp.threads {
            s.spawn(|| {
                while !stop.load(Ordering::Relaxed) {
                    let c0 = thread_cpu_time().ok();
                    let r = pad.pad(|| wl.run(fast_fail));
                    if let Some(d) = c0
                        .zip(thread_cpu_time().ok())
                        .map(|(b, a)| a.since(&b).total())
                    {
                        let ns = u64::try_from(d.as_nanos()).unwrap_or(u64::MAX);
                        cpu_in_pad_ns.fetch_add(ns, Ordering::Relaxed);
                    }
                    match r {
                        Ok(pd) => {
                            served.fetch_add(1, Ordering::Relaxed);
                            if pd.release.mode == WaitMode::Hybrid {
                                spun.fetch_add(1, Ordering::Relaxed);
                            }
                            if matches!(pd.release.disposition, Disposition::Escalated { .. }) {
                                escalated.fetch_add(1, Ordering::Relaxed);
                            }
                        }
                        Err(Trip::SlotsFull) => {
                            shed.fetch_add(1, Ordering::Relaxed);
                            std::thread::sleep(fp.backoff);
                        }
                        Err(_) => {
                            other.fetch_add(1, Ordering::Relaxed);
                        }
                    }
                }
            });
        }
        let legit_handle = s.spawn(|| {
            let (mut logical, mut first_try, mut completed, mut correct) = (0u64, 0u64, 0u64, 0u64);
            let (mut attempts, mut gave_up) = (0u64, 0u64);
            while !stop.load(Ordering::Relaxed) {
                logical += 1;
                let mut done = false;
                for attempt in 0..LEGIT_MAX_ATTEMPTS {
                    attempts += 1;
                    match pad.pad(|| wl.run(secret)) {
                        Ok(pd) => {
                            completed += 1;
                            if attempt == 0 {
                                first_try += 1;
                            }
                            if pd.value {
                                correct += 1;
                            }
                            if pd.release.mode == WaitMode::Hybrid {
                                spun.fetch_add(1, Ordering::Relaxed);
                            }
                            done = true;
                            break;
                        }
                        Err(Trip::SlotsFull) => std::thread::sleep(fp.backoff),
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
        });
        std::thread::sleep(Duration::from_secs(fp.secs));
        stop.store(true, Ordering::Relaxed);
        legit = legit_handle.join().unwrap_or(Value::Null);
    });
    let wall = w0.elapsed().as_secs_f64();
    let cpu = cpu0
        .zip(process_cpu_time().ok())
        .map(|(b, a)| a.since(&b).total().as_secs_f64());
    let after = pad.status();
    let served = served.load(Ordering::Relaxed);
    let shed = shed.load(Ordering::Relaxed);
    let spun = spun.load(Ordering::Relaxed);
    let reserved = spun as f64 * charge.as_secs_f64();
    let bound = match budget {
        SpinBudgetConfig::Limited {
            cpu_per_second,
            burst,
        } => Some(cpu_per_second.as_secs_f64() * wall + burst.as_secs_f64()),
        SpinBudgetConfig::Unlimited => None,
    };
    let offered = (served + shed) as f64 / wall;
    let capacity = fp.cap as f64 / before.target.as_secs_f64().max(1e-9);
    json!({
        "name": name,
        "mode": mode.label(),
        "threads": fp.threads,
        "max_concurrent": fp.cap,
        "threads_over_cap": fp.threads as f64 / fp.cap as f64,
        "shed_backoff_us": fp.backoff.as_secs_f64() * 1e6,
        "wall_seconds": wall,
        "process_cpu_seconds": cpu,
        "cpu_utilization_cores": cpu.map(|c| c / wall),
        "cpu_inside_pad_seconds_flood": cpu_in_pad_ns.load(Ordering::Relaxed) as f64 / 1e9,
        "cpu_inside_pad_seconds_per_served_flood_request":
            cpu_in_pad_ns.load(Ordering::Relaxed) as f64 / 1e9 / served.max(1) as f64,
        "requests_served": served,
        "requests_shed": shed,
        "requests_other_trip": other.load(Ordering::Relaxed),
        "flood_requests_escalated": escalated.load(Ordering::Relaxed),
        "served_with_spin": spun,
        "spin_reserved_seconds": reserved,
        "spin_budget_bound_seconds": bound,
        "spin_within_budget": bound.map(|b| reserved <= b),
        "admission_capacity_per_second_at_start_target": capacity,
        "offered_per_second": offered,
        "offered_over_capacity": offered / capacity,
        "target_changes_forced_by_flood": after.changes_total.saturating_sub(before.changes_total),
        "increases_during_flood": after.increases_total.saturating_sub(before.increases_total),
        "target_before_us": before.target.as_secs_f64() * 1e6,
        "target_after_us": after.target.as_secs_f64() * 1e6,
        "leak_bits_window_after": after.leak_bits,
        "frozen_after": after.frozen,
        "legitimate_client": legit,
    })
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let n_per_class = to_usize(env_u64(
        "TACK_ADAPTIVE_N_PER_CLASS",
        100_000,
        10_000,
        5_000_000,
    )?)?;
    let probes = to_usize(env_u64(
        "TACK_ADAPTIVE_POISON_PROBES",
        10_000,
        10_000,
        1_000_000,
    )?)?;
    let traj_n = to_usize(env_u64("TACK_ADAPTIVE_TRAJ_N", 40_000, 1_000, 1_000_000)?)?;
    let rounds = u32::try_from(env_u64("TACK_ADAPTIVE_ROUNDS", 256, 1, 100_000)?)?;
    let base_iters = env_u64("TACK_ADAPTIVE_BASE_ITERS", 10_000, 0, 100_000_000)?;
    let load_mult = env_u64("TACK_ADAPTIVE_LOAD_MULT", 4, 1, 1_000)?;
    let load_threads = to_usize(env_u64("TACK_ADAPTIVE_LOAD_THREADS", 2, 0, 64)?)?;
    let floor = Duration::from_micros(env_u64("TACK_ADAPTIVE_FLOOR_US", 64, 1, 1_000_000)?);
    let cap = Duration::from_micros(env_u64("TACK_ADAPTIVE_CAP_US", 2_048, 1, 10_000_000)?);
    let epoch = Duration::from_millis(env_u64("TACK_ADAPTIVE_EPOCH_MS", 50, 1, 3_600_000)?);
    let budget_bits = env_u64("TACK_ADAPTIVE_BUDGET_BITS", 1_000_000, 1, 1_000_000)? as f64;
    let flood_secs = env_u64("TACK_ADAPTIVE_FLOOD_SECS", 3, 1, 60)?;
    let cpus = env::cpu_count().unwrap_or(1);
    let default_cap = u64::try_from((cpus / 2).max(1)).unwrap_or(1);
    let flood_cap = to_usize(env_u64("TACK_ADAPTIVE_FLOOD_CAP", default_cap, 1, 4_096)?)?;
    let seed = env_u64("TACK_ADAPTIVE_SEED", 0x7ac4_ada9, 0, u64::MAX)?;
    let started = Instant::now();
    let env_before = env::snapshot();

    let (secret, a, b) = tokens();
    let toks = (&a, &b);
    let p = Params {
        n_total: n_per_class * 2,
        seed,
        load_threads,
        floor,
        cap,
        epoch,
        budget_bits,
    };
    let wl = Workload {
        secret,
        rounds,
        base_iters,
        load_mult,
        mult: AtomicU64::new(1),
        loaded: AtomicBool::new(false),
    };
    // Validate the pad configs before any long run.
    epoch_cfg(&p).validate()?;
    naive_cfg(&p, WindowStatistic::Mean).validate()?;

    // 1. Calibration: the harness victims, unpadded, same n and schedule.
    let cal = |f: &dyn Fn(&Token) -> bool| {
        let quiet = Workload {
            secret,
            rounds: 0,
            base_iters: 0,
            load_mult: 1,
            mult: AtomicU64::new(1),
            loaded: AtomicBool::new(false),
        };
        collect(schedule(p.n_total, seed, None), toks, &quiet, 0, |c| {
            black_box(f(c));
            Obs::Unpadded
        })
    };
    let leaky_run = cal(&|c| leaky_validate(&secret, c));
    let ct_run = cal(&|c| ct_validate(&secret, c));
    let leaky_rep = analyze_run(&leaky_run)?;
    let ct_rep = analyze_run(&ct_run)?;
    let leaky_first = leaky_rep
        .cropped
        .iter()
        .filter_map(|c| c.t)
        .fold(leaky_rep.t_raw.map_or(0.0, f64::abs), |m, t| m.max(t.abs()));
    let ct_raw_ok = ct_rep.t_raw.is_some_and(|t| t.abs() < T_THRESHOLD);
    let calibration_passed = leaky_first > T_THRESHOLD && ct_raw_ok;

    // 2. Runs on the drifting victim.
    let mut runs = Vec::new();
    let base = collect(
        schedule(p.n_total, seed, None),
        toks,
        &wl,
        load_threads,
        |c| {
            black_box(wl.run(c));
            Obs::Unpadded
        },
    );
    let base_rep = analyze_run(&base)?;
    runs.push(run_json(
        "unprotected",
        json!({}),
        &base,
        &base_rep,
        &base,
        Value::Null,
    ));

    for (name, stat) in [
        ("naive_mean", WindowStatistic::Mean),
        ("naive_p99", WindowStatistic::Percentile { permille: 990 }),
    ] {
        let cfg = naive_cfg(&p, stat);
        let pad: AdaptivePad<NaiveRollingTarget> = AdaptivePad::naive(PadConfig::default(), cfg)?;
        let run = collect(
            schedule(p.n_total, seed, None),
            toks,
            &wl,
            load_threads,
            |c| obs(&pad.pad(|| wl.run(c))),
        );
        let rep = analyze_run(&run)?;
        let cfg_json = json!({
            "statistic": format!("{:?}", cfg.statistic),
            "window": cfg.window,
            "margin_us": cfg.margin.as_secs_f64() * 1e6,
            "cap_us": cfg.cap.as_secs_f64() * 1e6,
            "mode": "sleep",
        });
        runs.push(run_json(
            name,
            cfg_json,
            &run,
            &rep,
            &base,
            leak_json(&pad.status(), None, None),
        ));
    }

    let hybrid_tail = tack_anc_adaptive::config::DEFAULT_SPIN_TAIL;
    for (name, pad_cfg) in [
        ("epoch_sleep", PadConfig::default()),
        (
            "epoch_hybrid",
            PadConfig {
                mode: WaitMode::Hybrid,
                spin_tail: hybrid_tail,
                // One CPU-second per second: enough for one measuring
                // thread, so the mode is not blurred by fallbacks here. The
                // flood section tests a tight budget.
                spin_budget: SpinBudgetConfig::Limited {
                    cpu_per_second: Duration::from_secs(1),
                    burst: Duration::from_millis(100),
                },
                ..PadConfig::default()
            },
        ),
    ] {
        let mode = pad_cfg.mode;
        let pad = AdaptivePad::epoch(pad_cfg, epoch_cfg(&p))?;
        let run = collect(
            schedule(p.n_total, seed, None),
            toks,
            &wl,
            load_threads,
            |c| obs(&pad.pad(|| wl.run(c))),
        );
        let rep = analyze_run(&run)?;
        let cfg_json = json!({
            "floor_us": floor.as_secs_f64() * 1e6,
            "cap_us": cap.as_secs_f64() * 1e6,
            "levels": epoch_cfg(&p).levels(),
            "epoch_ms": epoch.as_secs_f64() * 1e3,
            "leak_budget_bits_per_60s": budget_bits,
            "mode": mode.label(),
            "spin_tail_us": if mode == WaitMode::Hybrid { Some(hybrid_tail.as_secs_f64() * 1e6) } else { None },
        });
        runs.push(run_json(
            name,
            cfg_json,
            &run,
            &rep,
            &base,
            epoch_leak(&pad),
        ));
    }

    // 3. Poisoning.
    let poison = poisoning(&p, probes, &wl, toks)?;

    // 4. Trajectory.
    let traj = trajectory(&p, traj_n, &wl, toks)?;

    // 5. Flood.
    let fp = FloodParams {
        secs: flood_secs,
        cap: flood_cap,
        threads: 10 * flood_cap,
        backoff: Duration::from_micros(200),
    };
    let flood_json = json!([
        flood(
            "hybrid_limited_budget",
            PadConfig {
                mode: WaitMode::Hybrid,
                spin_tail: hybrid_tail,
                spin_budget: SpinBudgetConfig::Limited {
                    cpu_per_second: Duration::from_millis(100),
                    burst: Duration::from_millis(10),
                },
                max_concurrent: flood_cap,
                ..PadConfig::default()
            },
            &p,
            &fp,
            &wl,
            (&secret, &a),
        ),
        flood(
            "sleep_default",
            PadConfig {
                max_concurrent: flood_cap,
                ..PadConfig::default()
            },
            &p,
            &fp,
            &wl,
            (&secret, &a),
        ),
    ]);

    // 6. The production default budget.
    let budget = budget_default(&p, traj_n, &wl, toks)?;

    let out = json!({
        "meta": {
            "status": "new design; reference implementation measured on this host only",
            "n_per_class": n_per_class,
            "seed": seed,
            "victim": {
                "rounds_of_leaky_validate": rounds,
                "base_iters": base_iters,
                "load_mult": load_mult,
                "load_threads": load_threads,
                "load_phase": "middle third of every run",
            },
            "threshold": T_THRESHOLD,
            "crop_line": CROP_LINE,
            "env_before": env_before,
            "env_after": env::snapshot(),
            "wall_seconds": started.elapsed().as_secs_f64(),
        },
        "calibration": {
            "passed": calibration_passed,
            "leaky_max_first_order_abs_t": leaky_first,
            "leaky": detect_json(&leaky_rep),
            "ct": detect_json(&ct_rep),
        },
        "runs": runs,
        "poisoning": poison,
        "trajectory": traj,
        "flood": flood_json,
        "budget_default": budget,
    });
    println!("{}", serde_json::to_string_pretty(&out)?);
    Ok(())
}
