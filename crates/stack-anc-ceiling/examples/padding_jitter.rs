//! Randomized padding experiment (measurement only). Does adding random
//! jitter to the padded release time hide a class-dependent timing leak,
//! and at what latency cost? Prints nothing on stdout; writes one JSON file.
//!
//! Run in release mode, one launch per (mode, block):
//!
//! ```text
//! STACK_JITTER_MODE=spin STACK_JITTER_BLOCK=0 STACK_JITTER_OUT=out.json \
//!   taskset -c 3 cargo run --release -p stack-anc-ceiling --example padding_jitter
//! ```
//!
//! The ceiling pad itself is not modified. Policies are built from the
//! shipped `CeilingPad`:
//! * `fixed`: one pad at the ceiling C (the baseline).
//! * `replace`: the release target is C plus a random extra drawn from
//!   `K` equally likely levels `J*(l+1)/K`, by choosing one of `K` pads
//!   whose ceilings are `C + extra(l)`. The random total replaces C.
//! * `add`: the fixed pad at C, then a second pad around nothing whose
//!   ceiling is the random extra. The random delay is appended.
//!
//! Six classes are drawn uniformly per sample from a seeded schedule, so
//! every comparison shares the same machine noise:
//! * `A`: token differs at byte 0 (fast early exit).
//! * `A2`: identical to `A` (NEGATIVE control: no leak exists).
//! * `B`: token differs at byte 31 (the natural leak, tens of ns).
//! * `D1`, `D2`, `D3`: the `A` input, then a known extra delay of 200 ns,
//!   1 us and 50 us spun after release (POSITIVE controls: a leak of known
//!   size that passes through the pad, because it is added after release).
//!
//! The jitter draw is independent of the class and recorded per sample, so
//! independence is tested from the output (class by level counts), and the
//! "attacker knows the draw" case is analysed by subtracting the nominal
//! extra.
//!
//! The PRNG here is `SplitMix64`: reproducible, NOT cryptographic. A real
//! deployment of random padding needs an unpredictable source, because a
//! predictable draw can be subtracted out (see `adjusted` in the output).
//!
//! Environment variables (all optional; out-of-range values are an error):
//! * `STACK_JITTER_MODE`: `sleep`, `spin` or `hybrid` (default `spin`).
//! * `STACK_JITTER_BLOCK`: block number, recorded and mixed into seeds.
//! * `STACK_JITTER_SEED`: master seed, default 0x5eed_0a9c.
//! * `STACK_JITTER_N_TOTAL`: samples per cell (all classes), default 60000.
//! * `STACK_JITTER_CEILING_US`: ceiling C, default 300.
//! * `STACK_JITTER_TAIL_US`: Hybrid spin tail, default 150.
//! * `STACK_JITTER_PERMS`: permutations per pair, default 2000.
//! * `STACK_JITTER_BOOTS`: bootstrap resamples per pair, default 1000.
//! * `STACK_JITTER_OUT`: output path (default `padding_jitter.json`).

use serde_json::{json, Value};
use stack_anc_ceiling::{CeilingConfig, CeilingPad, SpinBudgetConfig, Trip, WaitMode};
use stack_anc_harness::cpu::thread_cpu_time;
use stack_anc_harness::stats::{percentile_sorted, welch_slices, Welford};
use stack_anc_harness::victim::{leaky_validate, TOKEN_LEN};
use stack_anc_harness::{analyze, env, Class, SplitMix64, TimeUnit, DEFAULT_CROP_PERCENTILES, T_THRESHOLD};
use std::hint::black_box;
use std::time::{Duration, Instant};

type Token = [u8; TOKEN_LEN];
type BoxErr = Box<dyn std::error::Error>;

const WARMUP: usize = 3_000;
const BATCH: usize = 1_024;
/// The shipped default hard-ceiling multiple, kept for the fixed and
/// replace pads so the baseline is the shipped configuration.
const DEFAULT_HARD_CEILING_BUCKETS: u32 = stack_anc_ceiling::config::DEFAULT_HARD_CEILING_BUCKETS;
/// The shipped default concurrency cap.
const DEFAULT_MAX_CONCURRENT: usize = stack_anc_ceiling::config::DEFAULT_MAX_CONCURRENT;
/// The `add` policy's extra pads have ceilings of a few microseconds, so a
/// short preemption would exceed the default 4x hard ceiling and the pad
/// would refuse the request, dropping slow samples. A large multiple keeps
/// every sample (an overrun then releases at the next whole multiple). A
/// slot is held for the hard ceiling, so the cap is raised with it, or one
/// thread issuing back-to-back requests would fill the slots and be shed.
const EXTRA_HARD_CEILING_BUCKETS: u32 = 1_024;
const EXTRA_MAX_CONCURRENT: usize = 65_536;
/// Equally likely jitter levels.
const LEVELS: usize = 8;
/// Class names and the known extra delay (ns) spun after release.
const CLASSES: [(&str, u64); 6] = [
    ("A", 0),
    ("A2", 0),
    ("B", 0),
    ("D1_200ns", 200),
    ("D2_1us", 1_000),
    ("D3_50us", 50_000),
];
/// Pairs analysed, each against class A (index 0).
const PAIRS: [usize; 5] = [1, 2, 3, 4, 5];
const PERCENTILES: [f64; 10] = [0.0, 0.01, 0.05, 0.25, 0.5, 0.75, 0.95, 0.99, 0.999, 1.0];

#[derive(Clone, Copy, PartialEq, Eq)]
enum Policy {
    Fixed,
    Replace,
    Add,
}

impl Policy {
    fn label(self) -> &'static str {
        match self {
            Policy::Fixed => "fixed",
            Policy::Replace => "replace",
            Policy::Add => "add",
        }
    }
}

#[derive(Clone, Copy)]
struct Cell {
    policy: Policy,
    /// Jitter width J as a percent of the ceiling (0 for `fixed`).
    width_pct: u64,
}

struct Pads {
    fixed: CeilingPad,
    /// `replace`: one pad per level. `add`: one extra pad per level.
    levels: Vec<CeilingPad>,
}

fn env_u64(name: &str, default: u64, lo: u64, hi: u64) -> Result<u64, String> {
    match std::env::var(name) {
        Err(_) => Ok(default),
        Ok(s) => {
            let s = s.trim();
            let v = if let Some(h) = s.strip_prefix("0x") {
                u64::from_str_radix(&h.replace('_', ""), 16)
            } else {
                s.replace('_', "").parse::<u64>()
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

fn mode_from_env() -> Result<WaitMode, String> {
    match std::env::var("STACK_JITTER_MODE").unwrap_or_else(|_| "spin".into()).as_str() {
        "sleep" => Ok(WaitMode::Sleep),
        "spin" => Ok(WaitMode::Spin),
        "hybrid" => Ok(WaitMode::Hybrid),
        other => Err(format!("STACK_JITTER_MODE must be sleep, spin or hybrid; got {other}")),
    }
}

fn pad_with(
    mode: WaitMode,
    ceiling: Duration,
    tail: Duration,
    hard_buckets: u32,
    max_concurrent: usize,
) -> Result<CeilingPad, BoxErr> {
    Ok(CeilingPad::new(CeilingConfig {
        mode,
        spin_tail: tail,
        spin_budget: SpinBudgetConfig::Unlimited,
        hard_ceiling_buckets: hard_buckets,
        max_concurrent,
        ..CeilingConfig::new(ceiling)
    })?)
}

/// Nominal extra for a level, in nanoseconds: `J * (l + 1) / LEVELS`.
fn extra_ns(width_ns: u64, level: usize) -> u64 {
    width_ns * (level as u64 + 1) / LEVELS as u64
}

fn build_pads(cell: Cell, mode: WaitMode, ceiling: Duration, tail: Duration) -> Result<Pads, BoxErr> {
    let fixed = pad_with(mode, ceiling, tail, DEFAULT_HARD_CEILING_BUCKETS, DEFAULT_MAX_CONCURRENT)?;
    let width_ns = u64::try_from(ceiling.as_nanos())? * cell.width_pct / 100;
    let mut levels = Vec::new();
    match cell.policy {
        Policy::Fixed => {}
        Policy::Replace => {
            for l in 0..LEVELS {
                levels.push(pad_with(
                    mode,
                    ceiling + Duration::from_nanos(extra_ns(width_ns, l)),
                    tail,
                    DEFAULT_HARD_CEILING_BUCKETS,
                    DEFAULT_MAX_CONCURRENT,
                )?);
            }
        }
        Policy::Add => {
            for l in 0..LEVELS {
                levels.push(pad_with(
                    mode,
                    Duration::from_nanos(extra_ns(width_ns, l)),
                    tail,
                    EXTRA_HARD_CEILING_BUCKETS,
                    EXTRA_MAX_CONCURRENT,
                )?);
            }
        }
    }
    Ok(Pads { fixed, levels })
}

/// Spin for `delta_ns` (or read the clock once for 0, so every class runs
/// about the same code).
#[inline]
fn spin_ns(delta_ns: u64) {
    let t = Instant::now();
    if delta_ns == 0 {
        black_box(t);
        return;
    }
    let d = Duration::from_nanos(delta_ns);
    while t.elapsed() < d {
        std::hint::spin_loop();
    }
}

/// One timed request. `Err` carries the trip when the pad refused it.
#[inline]
fn run_one(cell: Cell, pads: &Pads, secret: &Token, tok: &Token, level: usize, delta_ns: u64) -> Result<(), Trip> {
    let ok = match cell.policy {
        Policy::Fixed => pads.fixed.pad(|| leaky_validate(secret, black_box(tok))).map(|_| ()),
        Policy::Replace => pads.levels[level].pad(|| leaky_validate(secret, black_box(tok))).map(|_| ()),
        Policy::Add => pads
            .fixed
            .pad(|| leaky_validate(secret, black_box(tok)))
            .and_then(|_| pads.levels[level].pad(|| black_box(0u8)))
            .map(|_| ()),
    };
    spin_ns(delta_ns);
    ok
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

fn draw_below(rng: &mut SplitMix64, n: usize) -> usize {
    ((u128::from(rng.next_u64()) * n as u128) >> 64) as usize
}

struct Collected {
    class: Vec<u8>,
    level: Vec<u8>,
    ns: Vec<f64>,
    not_served: u64,
    trips: std::collections::BTreeMap<String, u64>,
    wall_s: f64,
    thread_cpu_s: Option<f64>,
}

fn collect(cell: Cell, pads: &Pads, n_total: usize, seed: u64) -> Collected {
    let (secret, a, b) = tokens();
    let mut crng = SplitMix64::new(seed);
    let mut jrng = SplitMix64::new(seed ^ 0x9e37_79b9_7f4a_7c15);
    let classes: Vec<u8> = (0..n_total).map(|_| draw_below(&mut crng, CLASSES.len()) as u8).collect();
    let levels: Vec<u8> = (0..n_total).map(|_| draw_below(&mut jrng, LEVELS) as u8).collect();
    let token_for = |c: u8| if c == 2 { b } else { a };

    let mut wrng = SplitMix64::new(seed ^ 0xd1b5_4a32_d192_ed03);
    for _ in 0..WARMUP {
        let c = draw_below(&mut wrng, CLASSES.len());
        let l = draw_below(&mut wrng, LEVELS);
        let _ = black_box(run_one(cell, pads, &secret, &token_for(c as u8), l, CLASSES[c].1));
    }

    let mut out = Collected {
        class: Vec::with_capacity(n_total),
        level: Vec::with_capacity(n_total),
        ns: Vec::with_capacity(n_total),
        not_served: 0,
        trips: std::collections::BTreeMap::new(),
        wall_s: 0.0,
        thread_cpu_s: None,
    };
    let cpu0 = thread_cpu_time().ok();
    let w0 = Instant::now();
    let mut batch: Vec<Token> = Vec::with_capacity(BATCH);
    let mut idx = 0usize;
    for chunk in classes.chunks(BATCH) {
        batch.clear();
        batch.extend(chunk.iter().map(|&c| token_for(c)));
        for (k, tok) in batch.iter().enumerate() {
            let c = chunk[k];
            let l = levels[idx + k];
            let delta = CLASSES[usize::from(c)].1;
            let t0 = Instant::now();
            let ok = run_one(cell, pads, &secret, tok, usize::from(l), delta);
            let t1 = Instant::now();
            match ok {
                Ok(()) => {
                    out.class.push(c);
                    out.level.push(l);
                    out.ns.push(t1.duration_since(t0).as_nanos() as f64);
                }
                Err(trip) => {
                    out.not_served += 1;
                    *out.trips.entry(format!("{trip:?}")).or_insert(0) += 1;
                }
            }
        }
        idx += chunk.len();
    }
    out.wall_s = w0.elapsed().as_secs_f64();
    out.thread_cpu_s = cpu0
        .zip(thread_cpu_time().ok())
        .map(|(b0, a1)| a1.since(&b0).total().as_secs_f64());
    out
}

fn sorted_pcts(xs: &[f64]) -> Value {
    let mut v = xs.to_vec();
    v.sort_by(f64::total_cmp);
    let pairs: Vec<Value> = PERCENTILES
        .iter()
        .map(|&q| json!([q, percentile_sorted(&v, q)]))
        .collect();
    Value::Array(pairs)
}

fn permutation_p(pooled: &mut [f64], n_a: usize, rng: &mut SplitMix64, perms: usize, observed: f64) -> f64 {
    let n = pooled.len();
    let n_x = n - n_a;
    if n_a == 0 || n_x == 0 {
        return f64::NAN;
    }
    let total: f64 = pooled.iter().sum();
    let mut at_least = 0usize;
    for _ in 0..perms {
        let mut s = 0.0;
        for i in 0..n_a {
            let j = i + draw_below(rng, n - i);
            pooled.swap(i, j);
            s += pooled[i];
        }
        let d = (total - s) / n_x as f64 - s / n_a as f64;
        if d.abs() >= observed.abs() {
            at_least += 1;
        }
    }
    (1.0 + at_least as f64) / (perms as f64 + 1.0)
}

fn bootstrap_ci(a: &[f64], x: &[f64], rng: &mut SplitMix64, boots: usize) -> (Option<f64>, Option<f64>, Option<f64>, Option<f64>) {
    if a.is_empty() || x.is_empty() {
        return (None, None, None, None);
    }
    let mut diffs = Vec::with_capacity(boots);
    for _ in 0..boots {
        let mut sa = 0.0;
        for _ in 0..a.len() {
            sa += a[draw_below(rng, a.len())];
        }
        let mut sx = 0.0;
        for _ in 0..x.len() {
            sx += x[draw_below(rng, x.len())];
        }
        diffs.push(sx / x.len() as f64 - sa / a.len() as f64);
    }
    diffs.sort_by(f64::total_cmp);
    (
        percentile_sorted(&diffs, 0.025),
        percentile_sorted(&diffs, 0.975),
        percentile_sorted(&diffs, 0.005),
        percentile_sorted(&diffs, 0.995),
    )
}

/// The crate's cropped Welch tests, with the cropped mean difference and its
/// standard error at each crop, for the pair `a` (class A) against `x`.
fn cropped_list(a: &[f64], x: &[f64], rep: &stack_anc_harness::Report) -> Vec<Value> {
    rep.cropped
        .iter()
        .map(|c| {
            let ka: Vec<f64> = a.iter().copied().filter(|v| *v <= c.threshold).collect();
            let kx: Vec<f64> = x.iter().copied().filter(|v| *v <= c.threshold).collect();
            let (wa, wx) = (Welford::from_slice(&ka), Welford::from_slice(&kx));
            let d = wa.mean().zip(wx.mean()).map(|(p, q)| q - p);
            let se = wa
                .variance()
                .zip(wx.variance())
                .map(|(p, q)| (p / ka.len() as f64 + q / kx.len() as f64).sqrt());
            json!({
                "p": c.percentile,
                "threshold_ns": c.threshold,
                "t": c.t,
                "n_a": c.n_a,
                "n_x": c.n_b,
                "diff_ns": d,
                "se_ns": se,
            })
        })
        .collect()
}

fn pair_json(
    col: &Collected,
    x_class: usize,
    nominal: &dyn Fn(u8) -> f64,
    perms: usize,
    boots: usize,
    rng: &mut SplitMix64,
) -> Result<Value, BoxErr> {
    let mut a = Vec::new();
    let mut x = Vec::new();
    let mut a_adj = Vec::new();
    let mut x_adj = Vec::new();
    for i in 0..col.ns.len() {
        let c = usize::from(col.class[i]);
        if c == 0 {
            a.push(col.ns[i]);
            a_adj.push(col.ns[i] - nominal(col.level[i]));
        } else if c == x_class {
            x.push(col.ns[i]);
            x_adj.push(col.ns[i] - nominal(col.level[i]));
        }
    }
    // The crate's own statistic (sign: positive t means A slower).
    let mut classes = vec![Class::A; a.len()];
    classes.extend(std::iter::repeat_n(Class::B, x.len()));
    let mut both = a.clone();
    both.extend_from_slice(&x);
    let rep = analyze(&classes, &both, TimeUnit::Nanoseconds, &DEFAULT_CROP_PERCENTILES, 1_000)?;
    let wa = Welford::from_slice(&a);
    let wx = Welford::from_slice(&x);
    let (ma, mx) = (wa.mean(), wx.mean());
    let (va, vx) = (wa.variance(), wx.variance());
    let diff = ma.zip(mx).map(|(p, q)| q - p);
    let se = va.zip(vx).map(|(p, q)| (p / a.len() as f64 + q / x.len() as f64).sqrt());
    let mut median_diff = None;
    {
        let mut sa = a.clone();
        let mut sx = x.clone();
        sa.sort_by(f64::total_cmp);
        sx.sort_by(f64::total_cmp);
        if let (Some(p), Some(q)) = (percentile_sorted(&sa, 0.5), percentile_sorted(&sx, 0.5)) {
            median_diff = Some(q - p);
        }
    }
    let p_perm = diff.map(|d| permutation_p(&mut both, a.len(), rng, perms, d));
    let (lo95, hi95, lo99, hi99) = bootstrap_ci(&a, &x, rng, boots);
    let adj_t = welch_slices(&a_adj, &x_adj).map(|w| w.t);
    let mut adj_both = a_adj.clone();
    adj_both.extend_from_slice(&x_adj);
    let adj_rep = analyze(&classes, &adj_both, TimeUnit::Nanoseconds, &DEFAULT_CROP_PERCENTILES, 1_000)?;
    let adj_diff = Welford::from_slice(&a_adj)
        .mean()
        .zip(Welford::from_slice(&x_adj).mean())
        .map(|(p, q)| q - p);
    let crop_max = rep
        .cropped
        .iter()
        .filter_map(|c| c.t)
        .fold(0.0f64, |m, t| m.max(t.abs()));
    Ok(json!({
        "x_class": CLASSES[x_class].0,
        "known_delta_ns": CLASSES[x_class].1,
        "n_a": a.len(),
        "n_x": x.len(),
        "mean_a_ns": ma,
        "mean_x_ns": mx,
        "var_a": va,
        "var_x": vx,
        "diff_ns": diff,
        "se_ns": se,
        "median_diff_ns": median_diff,
        "t_raw": rep.t_raw,
        "t_second_order": rep.t_second_order,
        "max_abs_cropped_t": crop_max,
        "crate_max_abs_t": rep.max_abs_t,
        "crate_max_source": rep.max_source,
        "t_cropped": cropped_list(&a, &x, &rep),
        "crate_leak": rep.max_abs_t > T_THRESHOLD,
        "ks_p": rep.ks_p,
        "perm_p": p_perm,
        "boot_ci95_ns": [lo95, hi95],
        "boot_ci99_ns": [lo99, hi99],
        "adjusted": {
            "t": adj_t,
            "diff_ns": adj_diff,
            "crate_max_abs_t": adj_rep.max_abs_t,
            "t_cropped": cropped_list(&a_adj, &x_adj, &adj_rep),
        },
    }))
}

fn class_json(col: &Collected, c: usize) -> Value {
    let xs: Vec<f64> = (0..col.ns.len())
        .filter(|&i| usize::from(col.class[i]) == c)
        .map(|i| col.ns[i])
        .collect();
    let w = Welford::from_slice(&xs);
    json!({
        "class": CLASSES[c].0,
        "n": xs.len(),
        "mean_ns": w.mean(),
        "var": w.variance(),
        "percentiles_ns": sorted_pcts(&xs),
    })
}

fn load_snapshot() -> Value {
    json!({"load_avg": env::load_avg()})
}

fn cpus_allowed() -> Option<String> {
    let s = std::fs::read_to_string("/proc/self/status").ok()?;
    s.lines()
        .find(|l| l.starts_with("Cpus_allowed_list"))
        .and_then(|l| l.split_once(':'))
        .map(|(_, v)| v.trim().to_owned())
}

fn main() -> Result<(), BoxErr> {
    let mode = mode_from_env()?;
    let block = env_u64("STACK_JITTER_BLOCK", 0, 0, 1_000_000)?;
    let master = env_u64("STACK_JITTER_SEED", 0x5eed_0a9c, 0, u64::MAX)?;
    let n_total = to_usize(env_u64("STACK_JITTER_N_TOTAL", 60_000, 6_000, 5_000_000)?)?;
    let ceiling = Duration::from_micros(env_u64("STACK_JITTER_CEILING_US", 300, 20, 100_000)?);
    let tail = Duration::from_micros(env_u64("STACK_JITTER_TAIL_US", 150, 0, 100_000)?);
    let perms = to_usize(env_u64("STACK_JITTER_PERMS", 2_000, 100, 100_000)?)?;
    let boots = to_usize(env_u64("STACK_JITTER_BOOTS", 1_000, 100, 100_000)?)?;
    let out_path = std::env::var("STACK_JITTER_OUT").unwrap_or_else(|_| "padding_jitter.json".into());
    let mode_id = match mode {
        WaitMode::Sleep => 1u64,
        WaitMode::Spin => 2,
        WaitMode::Hybrid => 3,
    };
    let launch_seed = master ^ block.wrapping_mul(0xa076_1d64_78bd_642f) ^ mode_id.wrapping_mul(0xe703_7ed1_a0b4_28db);

    let mut cells = vec![Cell { policy: Policy::Fixed, width_pct: 0 }];
    for policy in [Policy::Replace, Policy::Add] {
        for width_pct in [5, 20, 100] {
            cells.push(Cell { policy, width_pct });
        }
    }
    // Shuffle the cell order per launch so drift is not confounded with a cell.
    let mut orng = SplitMix64::new(launch_seed ^ 0x1234_5678_9abc_def0);
    for i in (1..cells.len()).rev() {
        let j = draw_below(&mut orng, i + 1);
        cells.swap(i, j);
    }

    let started = Instant::now();
    let env_before = env::snapshot();
    let mut cell_out = Vec::new();
    for (ci, cell) in cells.iter().enumerate() {
        let seed = launch_seed ^ (ci as u64 + 1).wrapping_mul(0x8cb9_2ba7_2f3d_8dd7);
        let pads = build_pads(*cell, mode, ceiling, tail)?;
        let width_ns = u64::try_from(ceiling.as_nanos())? * cell.width_pct / 100;
        let load_before = load_snapshot();
        let col = collect(*cell, &pads, n_total, seed);
        let load_after = load_snapshot();
        let nominal = |l: u8| -> f64 {
            match cell.policy {
                Policy::Fixed => 0.0,
                _ => extra_ns(width_ns, usize::from(l)) as f64,
            }
        };
        let mut prng = SplitMix64::new(seed ^ 0xfeed_beef_0bad_f00d);
        let mut pairs = Vec::new();
        for &x in &PAIRS {
            pairs.push(pair_json(&col, x, &nominal, perms, boots, &mut prng)?);
        }
        // Independence of the jitter draw from the class: counts class x level.
        let mut table = vec![vec![0u64; LEVELS]; CLASSES.len()];
        for i in 0..col.ns.len() {
            table[usize::from(col.class[i])][usize::from(col.level[i])] += 1;
        }
        // Latency of the un-delayed classes (A, A2, B pooled).
        let base: Vec<f64> = (0..col.ns.len())
            .filter(|&i| col.class[i] <= 2)
            .map(|i| col.ns[i])
            .collect();
        let bw = Welford::from_slice(&base);
        let classes: Vec<Value> = (0..CLASSES.len()).map(|c| class_json(&col, c)).collect();
        eprintln!(
            "block {block} {} {} {}%: n={} not_served={} wall={:.1}s",
            mode.label(),
            cell.policy.label(),
            cell.width_pct,
            col.ns.len(),
            col.not_served,
            col.wall_s
        );
        cell_out.push(json!({
            "policy": cell.policy.label(),
            "width_pct": cell.width_pct,
            "width_ns": width_ns,
            "levels": LEVELS,
            "cell_seed": seed,
            "n_kept": col.ns.len(),
            "not_served": col.not_served,
            "not_served_by_trip": col.trips,
            "wall_seconds": col.wall_s,
            "thread_cpu_seconds": col.thread_cpu_s,
            "thread_cpu_utilization": col.thread_cpu_s.map(|c| c / col.wall_s),
            "load_before": load_before,
            "load_after": load_after,
            "latency_undelayed": {
                "n": base.len(),
                "mean_ns": bw.mean(),
                "var": bw.variance(),
                "percentiles_ns": sorted_pcts(&base),
            },
            "classes": classes,
            "level_class_counts": table,
            "pairs": pairs,
        }));
    }

    let doc = json!({
        "tool": "stack-anc-ceiling examples/padding_jitter.rs",
        "build": if cfg!(debug_assertions) { "debug (timings are not evidence)" } else { "release" },
        "mode": mode.label(),
        "block": block,
        "master_seed": master,
        "launch_seed": launch_seed,
        "n_total_per_cell": n_total,
        "ceiling_ns": u64::try_from(ceiling.as_nanos())?,
        "tail_ns": u64::try_from(tail.as_nanos())?,
        "threshold": T_THRESHOLD,
        "perms": perms,
        "boots": boots,
        "classes": CLASSES.iter().map(|(n, d)| json!({"name": n, "known_delta_ns": d})).collect::<Vec<_>>(),
        "cpus_allowed": cpus_allowed(),
        "env_before": env_before,
        "env_after": env::snapshot(),
        "total_wall_seconds": started.elapsed().as_secs_f64(),
        "cells": cell_out,
    });
    std::fs::write(&out_path, serde_json::to_string_pretty(&doc)?)?;
    Ok(())
}
