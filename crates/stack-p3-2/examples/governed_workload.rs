// One slice of a workload against the real P3.2 kernel.
//
// Tasks come from a seeded generator (--profile) or from a trace file (--csv). Durations, tokens and
// memory are SIMULATED. Real: the kernel creates each transaction and its deadline trap, and every
// limit is read over HTTP from the governance service through the governed-limits client.
// Token and memory limits are NOT enforced by the kernel yet, so their trap events are built here in
// the P3.2 schema and marked "kernel_made": false.
//
// Output, one JSON object per line: {"trap": <TrapEvent>, "expected_load": bool, "kernel_made": bool},
// then {"summary": {...}}.
//
// usage: governed_workload --agent NAME --round N --tasks N --default-ns N
//          ( --profile healthy|runaway|slowed|regressed --seed N | --csv FILE )
//          [--tokens-cap N --memory-cap N] [--ttl-s N] ( --port P [--token T] | --static )

use stack_p3_2::governed_limits::HttpSource;
use stack_p3_2::{ContextLocal, GovernedLimits, HardPreemptionKernel, LimitKind, P32Config, TrapEvent};
use std::collections::HashMap;
use std::time::Duration;

struct Rng(u64);
impl Rng {
    fn next(&mut self) -> f64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        ((self.0.wrapping_mul(0x2545F4914F6CDD1D) >> 11) as f64) / ((1u64 << 53) as f64)
    }
    fn normal(&mut self) -> f64 {
        let (u, v) = (self.next().max(1e-12), self.next());
        (-2.0 * u.ln()).sqrt() * (2.0 * std::f64::consts::PI * v).cos()
    }
}

struct Task {
    dur_ns: u64,
    tokens: u64,
    memory: u64,
    expected: bool,
    bad: bool,
}

fn csv_tasks(path: &str, agent: &str, lo: u64, hi: u64) -> Vec<Task> {
    let text = std::fs::read_to_string(path).unwrap_or_else(|e| panic!("cannot read {path}: {e}"));
    let mut lines = text.lines();
    let header: Vec<&str> = lines.next().expect("empty csv").split(',').collect();
    let col = |n: &str| header.iter().position(|h| *h == n).unwrap_or_else(|| panic!("csv lacks column {n}"));
    let (ca, cs, cd, ct, cm, ce, cb) = (
        col("agent_id"), col("seq"), col("duration_ns"), col("tokens_requested"),
        col("memory_requested_bytes"), col("expected_load"), col("is_bad"),
    );
    let mut out = Vec::new();
    for line in lines {
        let f: Vec<&str> = line.split(',').collect();
        if f.len() != header.len() || f[ca] != agent {
            continue;
        }
        let seq: u64 = f[cs].parse().expect("bad seq");
        if seq < lo || seq >= hi {
            continue;
        }
        out.push(Task {
            dur_ns: f[cd].parse().expect("bad duration"),
            tokens: f[ct].parse().expect("bad tokens"),
            memory: f[cm].parse().expect("bad memory"),
            expected: f[ce] == "1",
            bad: f[cb] == "1",
        });
    }
    out
}

fn generated_tasks(profile: &str, agent: &str, round: u64, n: u64, seed: u64) -> Vec<Task> {
    let agent_hash = agent.bytes().fold(1469598103934665603u64, |h, b| (h ^ b as u64).wrapping_mul(1099511628211));
    let mut rng = Rng(seed ^ agent_hash ^ round.wrapping_mul(0x9E3779B97F4A7C15) | 1);
    for _ in 0..8 { rng.next(); }
    let (median_ms, runaway_p) = match profile {
        "healthy" => (20.0, 0.0),
        "runaway" => (20.0, 0.05),
        "slowed" => (60.0, 0.0),
        // healthy for the first 20 rounds, then a regression makes every task 3x slower
        "regressed" => (if round < 20 { 20.0 } else { 60.0 }, 0.0),
        other => panic!("unknown profile {other}"),
    };
    (0..n).map(|_| {
        let bad = rng.next() < runaway_p;
        let dur_ns = if bad { 500_000_000 } else { (median_ms * (0.5 * rng.normal()).exp() * 1e6) as u64 };
        Task { dur_ns, tokens: 800, memory: 100 << 20, expected: false, bad }
    }).collect()
}

fn synthetic_trap(kernel_trap: &TrapEvent, reason: &str, tokens_deficit: Option<u64>, memory: Option<u64>) -> TrapEvent {
    let mut t = kernel_trap.clone();
    t.trap_id = uuid::Uuid::new_v4();
    t.trap_reason = reason.to_string();
    t.boundary_layer = stack_p3_2::BoundaryLayer::RateLimiting as u8;
    t.nanoseconds_since_deadline = None;
    t.tokens_deficit = tokens_deficit;
    t.memory_requested_bytes = memory;
    t
}

fn main() {
    let a: Vec<String> = std::env::args().collect();
    let mut m: HashMap<String, String> = HashMap::new();
    let mut i = 1;
    while i < a.len() {
        let k = a[i].trim_start_matches("--").to_owned();
        if k == "static" { m.insert(k, "1".into()); i += 1; } else { m.insert(k, a[i + 1].clone()); i += 2; }
    }
    let get = |k: &str| m.get(k).cloned().unwrap_or_else(|| panic!("missing --{k}"));
    let num = |k: &str, d: u64| m.get(k).map(|v| v.parse::<u64>().unwrap()).unwrap_or(d);
    let agent = get("agent");
    let n = num("tasks", 0);
    let round = num("round", 0);
    let (default_ns, tokens_cap, memory_cap) = (num("default-ns", 100_000_000), num("tokens-cap", 4000), num("memory-cap", 512 << 20));
    let ttl = Duration::from_secs(num("ttl-s", 0));

    let tasks = match m.get("csv") {
        Some(path) => csv_tasks(path, &agent, round * n, (round + 1) * n),
        None => generated_tasks(&get("profile"), &agent, round, n, num("seed", 1)),
    };

    let kernel = HardPreemptionKernel::new(P32Config::default()).unwrap();
    let limits = if m.contains_key("static") {
        None
    } else {
        let src = HttpSource {
            host: "127.0.0.1".into(), port: get("port").parse().unwrap(),
            token: m.get("token").cloned(), timeout: Duration::from_secs(2),
        };
        Some(GovernedLimits::new(src, ttl))
    };
    let eff = |kind: LimitKind, default: u64| match &limits {
        Some(l) => l.effective(&agent, kind, default),
        None => default,
    };

    let (mut legit, mut legit_failed, mut bad, mut bad_caught, mut expected_trapped) = (0u64, 0u64, 0u64, 0u64, 0u64);
    let (mut deadline_traps, mut token_traps, mut memory_traps) = (0u64, 0u64, 0u64);
    let (mut total_ns, mut bad_ns) = (0u128, 0u128);
    let (mut budget_last, mut tokens_last, mut memory_last) = (default_ns, tokens_cap, memory_cap);
    let mut completed: Vec<u64> = Vec::new();
    let digest = [0u8; 32];
    for t in &tasks {
        let budget = eff(LimitKind::DeadlineNs, default_ns);
        let tok_budget = eff(LimitKind::TokensCapacity, tokens_cap);
        let mem_budget = eff(LimitKind::MemoryCapacityBytes, memory_cap);
        (budget_last, tokens_last, memory_last) = (budget, tok_budget, mem_budget);
        let now_ns = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos() as u64;
        let deadline_abs = now_ns + budget;
        let tx = kernel.begin_transaction(agent.clone(), digest, deadline_abs).unwrap();
        let ctx = ContextLocal::new(agent.clone(), digest, deadline_abs);
        let mut trapped = false;
        if t.dur_ns > budget {
            trapped = true;
            deadline_traps += 1;
            if let Err(trap) = kernel.check_preemption_boundary(tx, &ctx, true) {
                println!("{}", serde_json::json!({ "trap": trap, "expected_load": t.expected, "kernel_made": true }));
                // keep a kernel-made trap around as the template for the synthetic ones
                let _ = &trap;
            }
        } else if t.tokens > tok_budget || t.memory > mem_budget {
            trapped = true;
            // Build the event from a kernel-made template (the kernel cannot produce these reasons yet).
            let template = kernel.check_preemption_boundary(tx, &ctx, true).unwrap_err();
            let trap = if t.tokens > tok_budget {
                token_traps += 1;
                synthetic_trap(&template, "token_exhausted", Some(t.tokens - tok_budget), None)
            } else {
                memory_traps += 1;
                synthetic_trap(&template, "memory_exceeded", None, Some(t.memory))
            };
            println!("{}", serde_json::json!({ "trap": trap, "expected_load": t.expected, "kernel_made": false }));
        }
        if !trapped { completed.push(t.dur_ns); }
        let cost = t.dur_ns.min(budget) as u128;
        total_ns += cost;
        if t.bad {
            bad += 1; bad_ns += cost;
            if trapped { bad_caught += 1; }
        } else {
            legit += 1;
            if trapped { if t.expected { expected_trapped += 1; } else { legit_failed += 1; } }
        }
    }
    completed.sort_unstable();
    let completed_median = completed.get(completed.len() / 2).copied().unwrap_or(0);
    // Quantiles of completed durations: p50 p75 p90 p95 p99 (0 if nothing completed).
    let q: Vec<u64> = [0.50, 0.75, 0.90, 0.95, 0.99].iter()
        .map(|p| if completed.is_empty() { 0 } else { completed[((completed.len() as f64 - 1.0) * p).round() as usize] })
        .collect();
    println!("{}", serde_json::json!({ "summary": {
        "agent": agent, "round": round, "tasks": tasks.len(), "legit": legit, "legit_failed": legit_failed,
        "expected_trapped": expected_trapped, "bad": bad, "bad_caught": bad_caught,
        "deadline_traps": deadline_traps, "token_traps": token_traps, "memory_traps": memory_traps,
        "completed_median_ns": completed_median, "completed_q": q, "total_ns": total_ns.to_string(), "bad_ns": bad_ns.to_string(),
        "budget_last_ns": budget_last, "tokens_last": tokens_last, "memory_last": memory_last } }));
}
