//! Release-mode evidence for ANC strategy 3. Prints one JSON document.
//!
//! Run from the workspace root:
//!
//! ```text
//! cargo run --release -p stack-anc-pipeline --example verify > verify.json
//! ```
//!
//! Debug-mode timings are not evidence; the program refuses to run without
//! optimizations unless `TACK_ANC_PIPELINE_ALLOW_DEBUG=1`.
//!
//! Environment variables (all optional):
//!
//! | variable                        | default              | bounds               | meaning |
//! |---------------------------------|----------------------|----------------------|---------|
//! | `TACK_ANC_PIPELINE_N`           | 100000               | 10000 ..= 5000000    | samples PER CLASS in every timing run |
//! | `TACK_ANC_PIPELINE_SEED`        | 0x7ac4a1c05eed0003   | any u64              | class schedule and input seed (not a key) |
//! | `TACK_ANC_PIPELINE_CPU_REQS`    | 1000000              | 10000 ..= 50000000   | requests per CPU-cost loop |
//! | `TACK_ANC_PIPELINE_FLOOD_MS`    | 2000                 | 100 ..= 60000        | flood duration per validator |
//! | `TACK_ANC_PIPELINE_FLOOD_CAP`   | 2                    | 1 ..= 64             | `max_in_flight` during the flood |
//!
//! With the defaults this took about 9 seconds of wall time on a 4-CPU VM
//! (6 of them in the three 2-second floods).
//!
//! What is timed: `PipelineGate::check`, from admission to the returned
//! decision, including admission checks and telemetry (a global
//! `DebuggingRecorder` is installed so the metric calls do real work).
//! That is what the attacker sees, minus the network.
//!
//! Classes (primary pair): A = candidate wrong at byte 0, B = wrong at
//! byte 31. Secondary pair (dudect style): A = one fixed candidate (wrong
//! at byte 31), B = a fresh random candidate. Classes are shuffled with a
//! seeded generator (exactly N of each) and inputs are prepared in batches
//! of 1024 outside the timed region.

use metrics_util::debugging::{DebugValue, DebuggingRecorder, Snapshotter};
use serde_json::{json, Value};
use std::hint::black_box;
use std::io::{BufRead, BufReader};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tack_anc_harness::cpu::{process_cpu_time, thread_cpu_time};
use tack_anc_harness::stats::percentile_sorted;
use tack_anc_harness::victim::{ct_validate, leaky_validate};
use tack_anc_harness::{
    analyze, env, Class, Report, SplitMix64, TimeUnit, DEFAULT_CROP_PERCENTILES, T_THRESHOLD,
};
use tack_anc_pipeline::naive::balanced_dummy_no_black_box;
use tack_anc_pipeline::telemetry::names;
use tack_anc_pipeline::{
    balanced_dummy, constant_time, early_exit, PipelineConfig, PipelineGate, TokenSecret, Trip,
    Validator, MAX_DUMMY_STEPS, TOKEN_LEN,
};

const BATCH: usize = 1_024;
const WARMUP: usize = 5_000;
const CROP_LINE: f64 = 10.0;
const KS_P_MIN: f64 = 0.001;
const LEGIT_MAX_ATTEMPTS: u32 = 100_000;
const MAX_DISASM_LINES_PER_FN: usize = 400;
const CPU_RING: usize = 1_024;

type Token = [u8; TOKEN_LEN];
/// One counter from a snapshot: name, labels, value.
type CounterRow = (String, Vec<(String, String)>, u64);
/// A named validator under test.
type NamedOp = (&'static str, fn(&Token, &Token) -> bool);

/// Test fixture, not a key.
const SECRET: Token = *b"verify-fixture-not-a-key-000001!";

struct Settings {
    per_class: usize,
    seed: u64,
    cpu_reqs: usize,
    flood: Duration,
    flood_cap: usize,
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

impl Settings {
    fn from_env() -> Result<Self, String> {
        Ok(Self {
            per_class: to_usize(env_u64("TACK_ANC_PIPELINE_N", 100_000, 10_000, 5_000_000)?)?,
            seed: env_u64("TACK_ANC_PIPELINE_SEED", 0x7ac4_a1c0_5eed_0003, 0, u64::MAX)?,
            cpu_reqs: to_usize(env_u64(
                "TACK_ANC_PIPELINE_CPU_REQS",
                1_000_000,
                10_000,
                50_000_000,
            )?)?,
            flood: Duration::from_millis(env_u64(
                "TACK_ANC_PIPELINE_FLOOD_MS",
                2_000,
                100,
                60_000,
            )?),
            flood_cap: to_usize(env_u64("TACK_ANC_PIPELINE_FLOOD_CAP", 2, 1, 64)?)?,
        })
    }
}

// ---------------------------------------------------------------- inputs

fn primary(class: Class, rng: &mut SplitMix64) -> Token {
    let mut c = SECRET;
    let flip = (rng.next_u64() as u8) | 1; // never zero, so always wrong
    match class {
        Class::A => c[0] ^= flip,
        Class::B => c[TOKEN_LEN - 1] ^= flip,
    }
    c
}

fn secondary(class: Class, rng: &mut SplitMix64) -> Token {
    match class {
        Class::A => {
            let mut c = SECRET;
            c[TOKEN_LEN - 1] ^= 0x01;
            c
        }
        Class::B => {
            let mut c: Token = rng.bytes();
            if c == SECRET {
                c[0] ^= 1; // probability 2^-256; keeps both classes "wrong"
            }
            c
        }
    }
}

/// Exactly `per_class` of each class, shuffled (Fisher-Yates) with `seed`.
fn schedule(per_class: usize, seed: u64) -> Vec<Class> {
    let mut v: Vec<Class> = Vec::with_capacity(2 * per_class);
    v.resize(per_class, Class::A);
    v.resize(2 * per_class, Class::B);
    let mut rng = SplitMix64::new(seed);
    for i in (1..v.len()).rev() {
        let j = (rng.next_u64() % (i as u64 + 1)) as usize;
        v.swap(i, j);
    }
    v
}

// ---------------------------------------------------------------- timing

struct Run {
    samples: Vec<f64>,
    wall_seconds: f64,
    thread_cpu_seconds: Option<f64>,
}

/// Time `op` once per scheduled class. Inputs for a batch are prepared
/// before any of that batch is timed; only the `op` call is inside the
/// timed region; outputs are dropped after the end timestamp.
fn collect<R>(
    classes: &[Class],
    seed: u64,
    mut prepare: impl FnMut(Class, &mut SplitMix64) -> Token,
    mut op: impl FnMut(&Token) -> R,
) -> Run {
    let mut wrng = SplitMix64::new(seed ^ 0xd1b5_4a32_d192_ed03);
    for _ in 0..WARMUP {
        let c = wrng.next_class();
        let input = prepare(c, &mut wrng);
        black_box(op(black_box(&input)));
    }
    let mut rng = SplitMix64::new(seed ^ 0x9e37_79b9_7f4a_7c15);
    let cpu0 = thread_cpu_time().ok();
    let t0 = Instant::now();
    let mut samples = Vec::with_capacity(classes.len());
    let mut batch: Vec<Token> = Vec::with_capacity(BATCH);
    for chunk in classes.chunks(BATCH) {
        batch.clear();
        batch.extend(chunk.iter().map(|&c| prepare(c, &mut rng)));
        for input in &batch {
            let s = Instant::now();
            let out = black_box(op(black_box(input)));
            let e = Instant::now();
            drop(out);
            samples.push(e.duration_since(s).as_nanos() as f64);
        }
    }
    let wall_seconds = t0.elapsed().as_secs_f64();
    let thread_cpu_seconds = match (cpu0, thread_cpu_time().ok()) {
        (Some(a), Some(b)) => Some(b.since(&a).total().as_secs_f64()),
        _ => None,
    };
    Run {
        samples,
        wall_seconds,
        thread_cpu_seconds,
    }
}

#[derive(Clone, Copy)]
struct Pct {
    p50: f64,
    p99: f64,
    p999: f64,
}

fn class_pct(classes: &[Class], samples: &[f64], want: Class) -> Option<Pct> {
    let mut v: Vec<f64> = classes
        .iter()
        .zip(samples)
        .filter(|(c, _)| **c == want)
        .map(|(_, s)| *s)
        .collect();
    v.sort_by(f64::total_cmp);
    Some(Pct {
        p50: percentile_sorted(&v, 0.5)?,
        p99: percentile_sorted(&v, 0.99)?,
        p999: percentile_sorted(&v, 0.999)?,
    })
}

fn pct_json(p: Option<Pct>) -> Value {
    p.map_or(
        Value::Null,
        |p| json!({"p50_ns": p.p50, "p99_ns": p.p99, "p999_ns": p.p999}),
    )
}

fn added_json(x: Option<Pct>, base: Option<Pct>) -> Value {
    match (x, base) {
        (Some(p), Some(b)) => json!({
            "p50_ns": p.p50 - b.p50,
            "p99_ns": p.p99 - b.p99,
            "p999_ns": p.p999 - b.p999,
        }),
        _ => Value::Null,
    }
}

struct Measured {
    report: Report,
    pa: Option<Pct>,
    pb: Option<Pct>,
    json: Value,
}

/// Analyze one run and build every measure the theorist asked for.
fn measure<R>(
    label: &str,
    s: &Settings,
    pair: &str,
    seed_offset: u64,
    prepare: impl FnMut(Class, &mut SplitMix64) -> Token,
    op: impl FnMut(&Token) -> R,
) -> Result<Measured, String> {
    let seed = s.seed.wrapping_add(seed_offset);
    let classes = schedule(s.per_class, seed);
    eprintln!(
        "measuring {label} ({pair}), {} samples per class",
        s.per_class
    );
    let run = collect(&classes, seed, prepare, op);
    let min_per_class = u64::try_from(s.per_class).map_err(|e| e.to_string())?;
    let report = analyze(
        &classes,
        &run.samples,
        TimeUnit::Nanoseconds,
        &DEFAULT_CROP_PERCENTILES,
        min_per_class,
    )
    .map_err(|e| format!("{label}: {e}"))?;
    let verdict = report.verdict(T_THRESHOLD);
    let pa = class_pct(&classes, &run.samples, Class::A);
    let pb = class_pct(&classes, &run.samples, Class::B);

    let (na, nb) = (report.n_a as f64, report.n_b as f64);
    let va = report.a.variance.unwrap_or(f64::NAN);
    let vb = report.b.variance.unwrap_or(f64::NAN);
    let delta_min_ns = T_THRESHOLD * (va / na + vb / nb).sqrt();
    let pooled_sd = ((va + vb) / 2.0).sqrt();
    let ks_d_limit = 1.95 * ((na + nb) / (na * nb)).sqrt();
    let crop_ts: Vec<Value> = report
        .cropped
        .iter()
        .map(|c| json!({"percentile": c.percentile, "t": c.t, "n_a": c.n_a, "n_b": c.n_b}))
        .collect();
    let max_crop = report
        .cropped
        .iter()
        .filter_map(|c| c.t)
        .fold(0.0f64, |m, t| m.max(t.abs()));
    let t_raw = report.t_raw.unwrap_or(f64::NAN);
    let t2 = report.t_second_order.unwrap_or(f64::NAN);
    let ks_p = report.ks_p.unwrap_or(f64::NAN);
    let theorist_pass = t_raw.abs() < T_THRESHOLD
        && t2.abs() < T_THRESHOLD
        && ks_p >= KS_P_MIN
        && max_crop < CROP_LINE;

    let json = json!({
        "label": label,
        "pair": pair,
        "seed": seed,
        "n_a": report.n_a,
        "n_b": report.n_b,
        "mean_a_ns": report.a.mean,
        "mean_b_ns": report.b.mean,
        "var_a": report.a.variance,
        "var_b": report.b.variance,
        "median_a_ns": report.a.median,
        "median_b_ns": report.b.median,
        "t_raw": report.t_raw,
        "t_second_order": report.t_second_order,
        "t_cropped": crop_ts,
        "max_abs_cropped_t": max_crop,
        "ks_d": report.ks_d,
        "ks_p": report.ks_p,
        "ks_d_limit_p001": ks_d_limit,
        "delta_min_ns": delta_min_ns,
        "delta_min_pooled_sd": delta_min_ns / pooled_sd,
        "harness_max_abs_t": report.max_abs_t,
        "harness_max_source": report.max_source,
        "harness_verdict": verdict,
        "harness_gate_outcome": verdict.gate_outcome().as_str(),
        "theorist_pass": theorist_pass,
        "theorist_rule": "|t_raw|<4.5 and |t_second_order|<4.5 and ks_p>=0.001 and every |cropped t|<10",
        "class_a": pct_json(pa),
        "class_b": pct_json(pb),
        "wall_seconds": run.wall_seconds,
        "thread_cpu_utilization": run.thread_cpu_seconds.map(|c| c / run.wall_seconds),
        "env": env::snapshot(),
    });
    Ok(Measured {
        report,
        pa,
        pb,
        json,
    })
}

fn with_added(mut m: Measured, base: (Option<Pct>, Option<Pct>)) -> Value {
    if let Value::Object(ref mut o) = m.json {
        o.insert(
            "added_vs_early_exit".into(),
            json!({
                "class_a": added_json(m.pa, base.0),
                "class_b": added_json(m.pb, base.1),
            }),
        );
    }
    m.json
}

fn verdict_of(runs: &[Value], label: &str) -> Value {
    runs.iter()
        .find(|r| r.get("label").and_then(Value::as_str) == Some(label))
        .map_or(Value::Null, |r| {
            json!({
                "theorist_pass": r.get("theorist_pass"),
                "harness_gate_outcome": r.get("harness_gate_outcome"),
                "harness_max_abs_t": r.get("harness_max_abs_t"),
                "t_raw": r.get("t_raw"),
                "t_second_order": r.get("t_second_order"),
                "max_abs_cropped_t": r.get("max_abs_cropped_t"),
                "ks_p": r.get("ks_p"),
                "delta_min_ns": r.get("delta_min_ns"),
            })
        })
}

fn median_of(runs: &[Value], label: &str, class: &str) -> Option<f64> {
    runs.iter()
        .find(|r| r.get("label").and_then(Value::as_str) == Some(label))
        .and_then(|r| r.get(class))
        .and_then(|c| c.get("p50_ns"))
        .and_then(Value::as_f64)
}

// ---------------------------------------------------------------- gates

fn gate(validator: Validator, max_in_flight: usize, record: bool) -> Result<PipelineGate, String> {
    let cfg = PipelineConfig {
        validator,
        allow_leaky_validators: true,
        max_in_flight,
        record_response_time: record,
    };
    let secret = TokenSecret::from_bytes(&SECRET).map_err(|e| e.to_string())?;
    PipelineGate::new(secret, cfg).map_err(|e| e.to_string())
}

// ---------------------------------------------------------------- cpu

fn cpu_cost(g: &PipelineGate, class: Class, reqs: usize, seed: u64) -> Value {
    let mut rng = SplitMix64::new(seed);
    let ring: Vec<Token> = (0..CPU_RING).map(|_| primary(class, &mut rng)).collect();
    let cpu0 = thread_cpu_time().ok();
    let t0 = Instant::now();
    for i in 0..reqs {
        black_box(g.check(black_box(&ring[i % CPU_RING])).is_ok());
    }
    let wall = t0.elapsed().as_secs_f64();
    let cpu = match (cpu0, thread_cpu_time().ok()) {
        (Some(a), Some(b)) => Some(b.since(&a).total().as_secs_f64()),
        _ => None,
    };
    json!({
        "requests": reqs,
        "cpu_seconds_per_request": cpu.map(|c| c / reqs as f64),
        "cpu_ns_per_request": cpu.map(|c| c * 1e9 / reqs as f64),
        "wall_ns_per_request": wall * 1e9 / reqs as f64,
    })
}

// ---------------------------------------------------------------- flood

#[derive(Default, Clone, Copy)]
struct Tally {
    ok: u64,
    mismatch: u64,
    shed: u64,
    other: u64,
}

impl Tally {
    fn add(&mut self, r: Result<tack_anc_pipeline::Accepted, Trip>) {
        match r {
            Ok(_) => self.ok += 1,
            Err(Trip::Mismatch) => self.mismatch += 1,
            Err(Trip::SlotsFull) => self.shed += 1,
            Err(_) => self.other += 1,
        }
    }
    fn merge(&mut self, o: Tally) {
        self.ok += o.ok;
        self.mismatch += o.mismatch;
        self.shed += o.shed;
        self.other += o.other;
    }
    fn total(&self) -> u64 {
        self.ok + self.mismatch + self.shed + self.other
    }
}

fn counter_sum(snap: &[CounterRow], name: &str, want: &[(&str, &str)]) -> u64 {
    snap.iter()
        .filter(|(n, l, _)| {
            n == name
                && want
                    .iter()
                    .all(|(k, v)| l.iter().any(|(lk, lv)| lk == k && lv == v))
        })
        .map(|(_, _, c)| *c)
        .sum()
}

fn counters(s: &Snapshotter) -> Vec<CounterRow> {
    s.snapshot()
        .into_vec()
        .into_iter()
        .filter_map(|(ck, _, _, v)| match v {
            DebugValue::Counter(c) => Some((
                ck.key().name().to_string(),
                ck.key()
                    .labels()
                    .map(|l| (l.key().to_string(), l.value().to_string()))
                    .collect(),
                c,
            )),
            _ => None,
        })
        .collect()
}

fn flood(validator: Validator, s: &Settings, snap: &Snapshotter) -> Result<Value, String> {
    let threads = 10 * s.flood_cap;
    eprintln!(
        "flood {}: {threads} fast-fail threads against max_in_flight={} for {:?}",
        validator.label(),
        s.flood_cap,
        s.flood
    );
    let _ = snap.snapshot(); // drain counters and histograms
                             // Response histogram off: a multi-second flood would store tens of
                             // millions of values in the debugging recorder.
    let g = Arc::new(gate(validator, s.flood_cap, false)?);
    let stop = Arc::new(AtomicBool::new(false));
    let mut fast_fail = SECRET;
    fast_fail[0] ^= 0xff;
    let cpu0 = process_cpu_time().map_err(|e| e.to_string())?;
    let t0 = Instant::now();
    let flooders: Vec<_> = (0..threads)
        .map(|_| {
            let g = Arc::clone(&g);
            let stop = Arc::clone(&stop);
            std::thread::spawn(move || {
                let mut t = Tally::default();
                while !stop.load(Ordering::Relaxed) {
                    t.add(g.check(black_box(&fast_fail)));
                }
                t
            })
        })
        .collect();
    let legit = {
        let g = Arc::clone(&g);
        let stop = Arc::clone(&stop);
        std::thread::spawn(move || {
            let mut t = Tally::default();
            let (mut completed, mut failed, mut attempts_sum) = (0u64, 0u64, 0u64);
            let mut lat: Vec<f64> = Vec::new();
            while !stop.load(Ordering::Relaxed) {
                let start = Instant::now();
                let mut done = false;
                for attempt in 1..=LEGIT_MAX_ATTEMPTS {
                    let r = g.check(black_box(&SECRET));
                    t.add(r);
                    if r.is_ok() {
                        attempts_sum += u64::from(attempt);
                        done = true;
                        break;
                    }
                    std::thread::yield_now();
                }
                if done {
                    completed += 1;
                    if lat.len() < 1_000_000 {
                        lat.push(start.elapsed().as_nanos() as f64);
                    }
                } else {
                    failed += 1;
                }
            }
            lat.sort_by(f64::total_cmp);
            (t, completed, failed, attempts_sum, lat)
        })
    };
    std::thread::sleep(s.flood);
    stop.store(true, Ordering::Relaxed);
    let mut ft = Tally::default();
    for h in flooders {
        ft.merge(h.join().map_err(|_| "flood thread panicked".to_string())?);
    }
    let (lt, completed, failed, attempts_sum, lat) = legit
        .join()
        .map_err(|_| "legit thread panicked".to_string())?;
    let wall = t0.elapsed().as_secs_f64();
    let cpu = process_cpu_time()
        .map_err(|e| e.to_string())?
        .since(&cpu0)
        .total()
        .as_secs_f64();
    let c = counters(snap);
    let mut all = ft;
    all.merge(lt);
    let metric_sheds = counter_sum(&c, names::SHED_TOTAL, &[("reason", "slots_full")]);
    let metric_requests = counter_sum(
        &c,
        names::REQUESTS_TOTAL,
        &[("validator", validator.label())],
    );
    Ok(json!({
        "validator": validator.label(),
        "max_in_flight": s.flood_cap,
        "flood_threads": threads,
        "legit_threads": 1,
        "duration_seconds": wall,
        "requests": all.total(),
        "requests_per_second": all.total() as f64 / wall,
        "flood_mismatches": ft.mismatch,
        "sheds_observed": all.shed,
        "sheds_in_metrics": metric_sheds,
        "sheds_counted": metric_sheds == all.shed,
        "requests_in_metrics": metric_requests,
        "requests_counted": metric_requests == all.total(),
        "shed_fraction": all.shed as f64 / all.total().max(1) as f64,
        "unexpected_outcomes": all.other + ft.ok + lt.mismatch,
        "process_cpu_seconds": cpu,
        "cpu_seconds_per_request": cpu / all.total().max(1) as f64,
        "cpu_ns_per_request": cpu * 1e9 / all.total().max(1) as f64,
        "spin_cpu_seconds": 0.0,
        "spin_note": "strategy 3 has no spin loop and no spin budget; per-request work is fixed",
        "legit_completed": completed,
        "legit_failed_after_max_attempts": failed,
        "legit_mean_attempts": attempts_sum as f64 / completed.max(1) as f64,
        "legit_latency_p50_ns": percentile_sorted(&lat, 0.5),
        "legit_latency_p99_ns": percentile_sorted(&lat, 0.99),
        "in_flight_after": g.in_flight(),
    }))
}

// ---------------------------------------------------------------- disassembly

const FUNCS: [&str; 4] = [
    "tack_anc_pipeline::validators::early_exit",
    "tack_anc_pipeline::validators::balanced_dummy",
    "tack_anc_pipeline::validators::constant_time",
    "tack_anc_pipeline::naive::balanced_dummy_no_black_box",
];

struct Insn {
    addr: u64,
    mnemonic: String,
    operands: String,
}

fn parse_insn(line: &str) -> Option<Insn> {
    let (addr, rest) = line.trim_start().split_once(':')?;
    let addr = u64::from_str_radix(addr.trim(), 16).ok()?;
    let rest = rest.trim();
    let (mnemonic, operands) = match rest.split_once(char::is_whitespace) {
        Some((m, o)) => (m.to_string(), o.trim().to_string()),
        None => (rest.to_string(), String::new()),
    };
    if mnemonic.is_empty() {
        return None;
    }
    Some(Insn {
        addr,
        mnemonic,
        operands,
    })
}

fn analyze_fn(lines: &[String], lo: u64, hi: u64) -> Value {
    let insns: Vec<Insn> = lines
        .iter()
        .filter_map(|l| parse_insn(l))
        .filter(|i| i.mnemonic != "int3")
        .collect();
    let is_nop = |i: &Insn| i.mnemonic.starts_with("nop") || i.mnemonic == "data16";
    let real: Vec<&Insn> = insns.iter().filter(|i| !is_nop(i)).collect();
    let cond: Vec<&&Insn> = real
        .iter()
        .filter(|i| i.mnemonic.starts_with('j') && i.mnemonic != "jmp")
        .collect();
    let mut loops = Vec::new();
    for b in &cond {
        let target = b
            .operands
            .split_whitespace()
            .next()
            .and_then(|t| u64::from_str_radix(t, 16).ok());
        if let Some(t) = target {
            if t <= b.addr && t >= lo && t < hi {
                let body = real
                    .iter()
                    .filter(|i| i.addr >= t && i.addr <= b.addr)
                    .count();
                loops.push(json!({"head": format!("{t:x}"), "back_edge": format!("{:x}", b.addr), "instructions_per_iteration": body}));
            }
        }
    }
    let muldiv = real
        .iter()
        .filter(|i| i.mnemonic.contains("mul") || i.mnemonic.contains("div"))
        .count();
    let indirect = real
        .iter()
        .filter(|i| {
            (i.mnemonic.starts_with("jmp") || i.mnemonic.starts_with("call"))
                && i.operands.contains('*')
        })
        .count();
    json!({
        "instructions": real.len(),
        "conditional_branches": cond.len(),
        "loops": loops,
        "multiply_or_divide": muldiv,
        "indirect_jumps_or_calls": indirect,
    })
}

fn disassembly() -> Value {
    let exe = match std::env::current_exe() {
        Ok(p) => p,
        Err(e) => return json!({"available": false, "reason": format!("current_exe: {e}")}),
    };
    let syms = match Command::new("objdump")
        .arg("-t")
        .arg("-C")
        .arg(&exe)
        .output()
    {
        Ok(o) if o.status.success() => String::from_utf8_lossy(&o.stdout).into_owned(),
        Ok(o) => {
            return json!({"available": false, "reason": format!("objdump -t exit {:?}", o.status.code())})
        }
        Err(e) => {
            return json!({"available": false, "reason": format!("objdump not runnable: {e}")})
        }
    };
    // name -> (address, size)
    let mut table: Vec<(&str, u64, u64)> = Vec::new();
    for line in syms.lines() {
        for name in FUNCS {
            if line.trim_end().ends_with(name) {
                let toks: Vec<&str> = line.split_whitespace().collect();
                let addr = toks.first().and_then(|t| u64::from_str_radix(t, 16).ok());
                let size = toks
                    .iter()
                    .position(|t| *t == ".text")
                    .and_then(|p| toks.get(p + 1))
                    .and_then(|t| u64::from_str_radix(t, 16).ok());
                if let (Some(a), Some(s)) = (addr, size) {
                    table.push((name, a, s));
                }
            }
        }
    }
    let child = Command::new("objdump")
        .args(["-d", "-C", "--no-show-raw-insn"])
        .arg(&exe)
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn();
    let mut child = match child {
        Ok(c) => c,
        Err(e) => return json!({"available": false, "reason": format!("objdump -d: {e}")}),
    };
    let mut blocks: Vec<(u64, Vec<String>)> = Vec::new();
    if let Some(out) = child.stdout.take() {
        let mut current: Option<(u64, Vec<String>)> = None;
        for line in BufReader::new(out).lines().map_while(Result::ok) {
            if line.ends_with(">:") {
                if let Some(b) = current.take() {
                    blocks.push(b);
                }
                let addr = line
                    .split_whitespace()
                    .next()
                    .and_then(|t| u64::from_str_radix(t, 16).ok());
                if let Some(a) = addr {
                    if table.iter().any(|(_, ta, _)| *ta == a) {
                        current = Some((a, Vec::new()));
                    }
                }
            } else if line.trim().is_empty() {
                if let Some(b) = current.take() {
                    blocks.push(b);
                }
            } else if let Some((_, ref mut v)) = current {
                if v.len() < MAX_DISASM_LINES_PER_FN {
                    v.push(line);
                }
            }
        }
        if let Some(b) = current.take() {
            blocks.push(b);
        }
    }
    let _ = child.wait();

    let addr_of = |n: &str| table.iter().find(|(tn, _, _)| *tn == n).map(|(_, a, _)| *a);
    let mut fns = serde_json::Map::new();
    for name in FUNCS {
        let Some((_, a, sz)) = table.iter().find(|(tn, _, _)| *tn == name) else {
            fns.insert(name.into(), json!({"found": false}));
            continue;
        };
        let aliases: Vec<&str> = table
            .iter()
            .filter(|(tn, ta, _)| *ta == *a && *tn != name)
            .map(|(tn, _, _)| *tn)
            .collect();
        let body = blocks
            .iter()
            .find(|(ba, _)| *ba == *a)
            .map(|(_, l)| l.clone());
        let mut entry = json!({
            "found": true,
            "address": format!("{a:x}"),
            "size_bytes": sz,
            "same_address_as": aliases,
        });
        if let (Some(lines), Value::Object(ref mut o)) = (body.as_ref(), &mut entry) {
            if let Value::Object(stats) = analyze_fn(lines, *a, a + sz) {
                o.extend(stats);
            }
            if name.ends_with("constant_time") || name.ends_with("::balanced_dummy") {
                let listing: Vec<String> = lines
                    .iter()
                    .filter(|l| !l.contains("int3"))
                    .map(|l| l.trim().replace('\t', " "))
                    .collect();
                o.insert("listing".into(), json!(listing));
            }
        }
        fns.insert(name.into(), entry);
    }
    let naive_folded = match (addr_of(FUNCS[3]), addr_of(FUNCS[0])) {
        (Some(n), Some(e)) => Some(n == e),
        _ => None,
    };
    let ct_branches = fns
        .get(FUNCS[2])
        .and_then(|v| v.get("conditional_branches"))
        .and_then(Value::as_u64);
    json!({
        "available": true,
        "tool": "objdump -d -C --no-show-raw-insn (and objdump -t for symbol addresses)",
        "functions": fns,
        "naive_filler_deleted_and_merged_with_early_exit": naive_folded,
        "constant_time_conditional_branches": ct_branches,
        "note": "Counts are static, from this binary only. Zero conditional branches in constant_time means no branch at all, so none on secret data. The one indirect jump in constant_time is the tail call into subtle's black_box for Choice. A different compiler version or target can change all of this.",
    })
}

// ---------------------------------------------------------------- main

fn main() -> Result<(), Box<dyn std::error::Error>> {
    if cfg!(debug_assertions) && std::env::var("TACK_ANC_PIPELINE_ALLOW_DEBUG").is_err() {
        return Err("debug build: timings are not evidence; use --release (or set TACK_ANC_PIPELINE_ALLOW_DEBUG=1)".into());
    }
    let s = Settings::from_env()?;
    let env_before = env::snapshot();
    let t_start = Instant::now();

    // Sections 1 to 5 run with no metrics recorder installed: the metric
    // macros still build their keys and call the (no-op) recorder, so the
    // request path is the production one minus the exporter's own cost.
    // Section 2b repeats the key runs with a DebuggingRecorder on the path.

    // 1. Calibration: unpadded harness victims, primary classes.
    let leaky = measure(
        "harness leaky_validate (unpadded)",
        &s,
        "primary",
        1,
        primary,
        |c| leaky_validate(&SECRET, c),
    )?;
    let ctv = measure(
        "harness ct_validate (unpadded)",
        &s,
        "primary",
        2,
        primary,
        |c| ct_validate(&SECRET, c),
    )?;
    let calibration_passed =
        leaky.report.verdict(T_THRESHOLD).is_leak() && ctv.report.verdict(T_THRESHOLD).is_pass();

    // 2. Primary pair through the gate (what the attacker sees).
    let mut prim = Vec::new();
    for (k, v) in Validator::ALL.into_iter().enumerate() {
        let g = gate(v, 64, true)?;
        prim.push(measure(
            v.label(),
            &s,
            "primary",
            10 + k as u64,
            primary,
            |c| g.check(c).is_ok(),
        )?);
    }
    let base = (prim[0].pa, prim[0].pb);
    let primary_runs: Vec<Value> = prim.into_iter().map(|m| with_added(m, base)).collect();

    // 2b. Same, with a DebuggingRecorder doing real work on every metric
    // call (it takes a mutex per call, so it is slower and noisier than a
    // production exporter).
    let mut with_recorder = Vec::new();
    for (k, v) in [Validator::EarlyExit, Validator::ConstantTime]
        .into_iter()
        .enumerate()
    {
        let rec = DebuggingRecorder::new();
        let g = gate(v, 64, true)?;
        let m = metrics::with_local_recorder(&rec, || {
            measure(
                v.label(),
                &s,
                "primary_with_debugging_recorder",
                15 + k as u64,
                primary,
                |c| g.check(c).is_ok(),
            )
        })?;
        with_recorder.push(m.json);
    }

    // 3. Secondary pair (fixed vs random) through the gate.
    let mut secondary_runs = Vec::new();
    for (k, v) in Validator::ALL.into_iter().enumerate() {
        let g = gate(v, 64, true)?;
        let m = measure(
            v.label(),
            &s,
            "secondary_fixed_vs_random",
            20 + k as u64,
            secondary,
            |c| g.check(c).is_ok(),
        )?;
        secondary_runs.push(m.json);
    }

    // 4. Bare validators, including the counterexample without black_box.
    let mut bare = Vec::new();
    let ops: [NamedOp; 4] = [
        ("early_exit", early_exit),
        ("balanced_dummy", balanced_dummy),
        ("balanced_dummy_no_black_box", balanced_dummy_no_black_box),
        ("constant_time", |a, b| bool::from(constant_time(a, b))),
    ];
    for (k, (name, f)) in ops.into_iter().enumerate() {
        let m = measure(
            name,
            &s,
            "primary_bare_validator",
            30 + k as u64,
            primary,
            |c| f(&SECRET, c),
        )?;
        bare.push(m.json);
    }

    // 5. CPU cost per request, idle (one thread, no contention).
    let mut cpu_idle = serde_json::Map::new();
    for (k, v) in Validator::ALL.into_iter().enumerate() {
        let g = gate(v, 64, true)?;
        let a = cpu_cost(&g, Class::A, s.cpu_reqs, s.seed ^ (40 + k as u64));
        let b = cpu_cost(&g, Class::B, s.cpu_reqs, s.seed ^ (50 + k as u64));
        cpu_idle.insert(
            v.label().into(),
            json!({"class_a_wrong_at_0": a, "class_b_wrong_at_31": b}),
        );
    }
    let cpu_ns = |v: &str, c: &str| {
        cpu_idle
            .get(v)
            .and_then(|x| x.get(c))
            .and_then(|x| x.get("cpu_ns_per_request"))
            .and_then(Value::as_f64)
    };
    let dummy_cost = json!({
        "max_dummy_steps_per_request": MAX_DUMMY_STEPS,
        "bare_median_ns_balanced_dummy_minus_early_exit_class_a": match (
            median_of(&bare, "balanced_dummy", "class_a"),
            median_of(&bare, "early_exit", "class_a"),
        ) {
            (Some(x), Some(y)) => Some(x - y),
            _ => None,
        },
        "gate_cpu_ns_balanced_dummy_minus_early_exit_class_a": match (
            cpu_ns("balanced_dummy", "class_a_wrong_at_0"),
            cpu_ns("early_exit", "class_a_wrong_at_0"),
        ) {
            (Some(x), Some(y)) => Some(x - y),
            _ => None,
        },
        "gate_cpu_ns_constant_time_class_a": cpu_ns("constant_time", "class_a_wrong_at_0"),
        "gate_cpu_ns_constant_time_class_b": cpu_ns("constant_time", "class_b_wrong_at_31"),
    });

    // 6. Flood, with a global recorder so sheds can be checked against
    // the metrics.
    let rec = DebuggingRecorder::new();
    let snap = rec.snapshotter();
    rec.install()
        .map_err(|_| "could not install metrics recorder")?;
    let mut floods = Vec::new();
    for v in Validator::ALL {
        floods.push(flood(v, &s, &snap)?);
    }

    // 7. Disassembly.
    eprintln!("disassembling {}", std::env::current_exe()?.display());
    let disasm = disassembly();

    let summary = json!({
        "calibration_passed": calibration_passed,
        "evidence_valid": calibration_passed,
        "calibration_leaky": verdict_of(std::slice::from_ref(&leaky.json), "harness leaky_validate (unpadded)"),
        "calibration_ct": verdict_of(std::slice::from_ref(&ctv.json), "harness ct_validate (unpadded)"),
        "primary_gate": {
            "early_exit": verdict_of(&primary_runs, "early_exit"),
            "balanced_dummy": verdict_of(&primary_runs, "balanced_dummy"),
            "constant_time": verdict_of(&primary_runs, "constant_time"),
        },
        "primary_gate_with_debugging_recorder": {
            "early_exit": verdict_of(&with_recorder, "early_exit"),
            "constant_time": verdict_of(&with_recorder, "constant_time"),
        },
        "secondary_gate": {
            "early_exit": verdict_of(&secondary_runs, "early_exit"),
            "balanced_dummy": verdict_of(&secondary_runs, "balanced_dummy"),
            "constant_time": verdict_of(&secondary_runs, "constant_time"),
        },
        "bare": {
            "early_exit": verdict_of(&bare, "early_exit"),
            "balanced_dummy": verdict_of(&bare, "balanced_dummy"),
            "balanced_dummy_no_black_box": verdict_of(&bare, "balanced_dummy_no_black_box"),
            "constant_time": verdict_of(&bare, "constant_time"),
        },
        "balanced_dummy_cost": dummy_cost,
        "naive_filler_deleted": disasm.get("naive_filler_deleted_and_merged_with_early_exit"),
        "constant_time_conditional_branches": disasm.get("constant_time_conditional_branches"),
    });

    let out = json!({
        "crate": "stack-anc-pipeline",
        "strategy": 3,
        "profile": if cfg!(debug_assertions) { "debug (NOT evidence)" } else { "release" },
        "timer": "Instant (ns)",
        "settings": {
            "per_class": s.per_class,
            "seed": s.seed,
            "cpu_reqs": s.cpu_reqs,
            "flood_ms": s.flood.as_millis() as u64,
            "flood_cap": s.flood_cap,
            "batch": BATCH,
            "warmup": WARMUP,
            "threshold": T_THRESHOLD,
            "crop_line": CROP_LINE,
            "ks_p_min": KS_P_MIN,
        },
        "env_before": env_before,
        "summary": summary,
        "calibration": {"leaky": leaky.json, "ct": ctv.json},
        "primary_gate": primary_runs,
        "primary_gate_with_debugging_recorder": with_recorder,
        "secondary_gate": secondary_runs,
        "bare_validators": bare,
        "cpu_idle": cpu_idle,
        "flood": floods,
        "disassembly": disasm,
        "env_after": env::snapshot(),
        "total_wall_seconds": t_start.elapsed().as_secs_f64(),
    });
    println!("{}", serde_json::to_string_pretty(&out)?);
    Ok(())
}
