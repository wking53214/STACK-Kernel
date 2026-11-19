// Round 23 replay harness. Reads JSONL runs (class limits per slice, then the calls of that slice) and prints, for each run, the kernel's
// per-call kill decision made with GovernedLimits::effective_for_class, including the kernel's own floor and ceiling.
//   cargo run --release --example class_replay -- runs.jsonl > decisions.jsonl
use serde_json::{json, Value};
use stack_p3_2::governed_limits::*;
use std::collections::HashMap;
use std::io::{BufRead, BufReader, Write};
use std::time::Duration;

struct Snap(HashMap<String, Value>);
impl LimitSource for Snap {
    fn fetch(&self, id: &str) -> Result<Option<Value>, String> {
        Ok(self.0.get(id).cloned())
    }
}

fn main() {
    let path = std::env::args().nth(1).expect("runs.jsonl");
    let out = std::io::stdout();
    let mut out = out.lock();
    for line in BufReader::new(std::fs::File::open(path).unwrap()).lines() {
        let run: Value = serde_json::from_str(&line.unwrap()).unwrap();
        let default = run["default_ns"].as_u64().unwrap();
        let mut kills = String::new();
        let mut floor_hits = 0u64;
        let (mut burn_gov, mut burn_static) = (0f64, 0f64);
        for sl in run["slices"].as_array().unwrap() {
            let mut m = HashMap::new();
            for (c, v) in sl["limits"].as_object().unwrap() {
                m.insert(class_boundary_id("a", c), v.clone());
            }
            let g = GovernedLimits::new(Snap(m), Duration::ZERO);
            for call in sl["calls"].as_array().unwrap() {
                let class = call[0].as_str().unwrap();
                let dur = call[1].as_u64().unwrap();
                let dl = g.effective_for_class("a", Some(class), default);
                kills.push(if dur > dl { '1' } else { '0' });
                if call[2].as_u64() == Some(1) {
                    burn_gov += dur.min(dl) as f64;
                    burn_static += dur.min(default) as f64;
                }
            }
            floor_hits += g.stats().below_floor;
        }
        writeln!(out, "{}", json!({"id": run["id"], "kills": kills, "below_floor": floor_hits, "burn_gov": burn_gov, "burn_static": burn_static})).unwrap();
    }
}
