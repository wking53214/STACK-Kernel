// One round of a simulated agent workload against the real P3.2 kernel.
//
// Task durations are SIMULATED (virtual time, seeded). What is real: the kernel creates the
// transaction and the trap event, and the time budget for each task is read over HTTP from the
// governance service through the governed-limits client.
//
// Output, one JSON object per line: {"trap": <TrapEvent>} for each trap, then {"summary": {...}}.
//
// usage: governed_workload --agent NAME --profile healthy|runaway|slowed --round N --tasks N
//        --default-ns N --seed N [--port P --token T | --static]

use stack_p3_2::governed_limits::HttpSource;
use stack_p3_2::{ContextLocal, GovernedLimits, HardPreemptionKernel, LimitKind, P32Config};
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

fn main() {
    let a: Vec<String> = std::env::args().collect();
    let mut m: HashMap<&str, String> = HashMap::new();
    let mut i = 1;
    while i < a.len() {
        if a[i] == "--static" {
            m.insert("static", "1".into());
            i += 1;
        } else {
            m.insert(a[i].trim_start_matches("--").to_owned().leak(), a[i + 1].clone());
            i += 2;
        }
    }
    let get = |k: &str| m.get(k).cloned().unwrap_or_else(|| panic!("missing --{k}"));
    let agent = get("agent");
    let profile = get("profile");
    let tasks: u64 = get("tasks").parse().unwrap();
    let default_ns: u64 = get("default-ns").parse().unwrap();
    let round: u64 = get("round").parse().unwrap();
    let seed: u64 = get("seed").parse().unwrap();
    let is_static = m.contains_key("static");

    // Same seed => same task durations with and without governance, so runs are paired.
    let agent_hash = agent.bytes().fold(1469598103934665603u64, |h, b| (h ^ b as u64).wrapping_mul(1099511628211));
    let mut rng = Rng(seed ^ agent_hash ^ round.wrapping_mul(0x9E3779B97F4A7C15) | 1);
    for _ in 0..8 { rng.next(); }

    let kernel = HardPreemptionKernel::new(P32Config::default()).unwrap();
    let limits = if is_static {
        None
    } else {
        let src = HttpSource {
            host: "127.0.0.1".into(),
            port: get("port").parse().unwrap(),
            token: m.get("token").cloned(),
            timeout: Duration::from_secs(2),
        };
        Some(GovernedLimits::new(src, Duration::ZERO))
    };

    let (median_ms, runaway_p) = match profile.as_str() {
        "healthy" => (20.0, 0.0),
        "runaway" => (20.0, 0.05),
        "slowed" => (60.0, 0.0),
        other => panic!("unknown profile {other}"),
    };

    let (mut legit, mut legit_failed, mut bad, mut bad_caught) = (0u64, 0u64, 0u64, 0u64);
    let (mut total_ns, mut bad_ns, mut budget_last) = (0u128, 0u128, default_ns);
    let digest = [0u8; 32];
    for _ in 0..tasks {
        let is_bad = rng.next() < runaway_p;
        let dur_ns = if is_bad {
            500_000_000u64
        } else {
            (median_ms * (0.5 * rng.normal()).exp() * 1e6) as u64
        };
        let budget = match &limits {
            Some(l) => l.effective(&agent, LimitKind::DeadlineNs, default_ns),
            None => default_ns,
        };
        budget_last = budget;
        let now_ns = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos() as u64;
        let deadline_abs = now_ns + budget;
        let tx = kernel.begin_transaction(agent.clone(), digest, deadline_abs).unwrap();
        let ctx = ContextLocal::new(agent.clone(), digest, deadline_abs);
        let preempted = dur_ns > budget;
        if preempted {
            if let Err(trap) = kernel.check_preemption_boundary(tx, &ctx, true) {
                println!("{}", serde_json::json!({ "trap": trap }));
            }
        }
        let cost = dur_ns.min(budget) as u128;
        total_ns += cost;
        if is_bad {
            bad += 1;
            bad_ns += cost;
            if preempted { bad_caught += 1; }
        } else {
            legit += 1;
            if preempted { legit_failed += 1; }
        }
    }
    println!("{}", serde_json::json!({ "summary": {
        "agent": agent, "round": round, "tasks": tasks, "legit": legit, "legit_failed": legit_failed,
        "bad": bad, "bad_caught": bad_caught, "total_ns": total_ns.to_string(), "bad_ns": bad_ns.to_string(),
        "budget_last_ns": budget_last } }));
}
