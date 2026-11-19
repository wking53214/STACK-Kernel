// Round 23 (experimental repo, docs/TRACE_TEST_PLAN.md): class-aware governed deadlines and the kernel's own floor.
use serde_json::{json, Value};
use stack_p3_2::governed_limits::*;
use std::collections::HashMap;
use std::sync::Mutex;
use std::time::Duration;

const D: u64 = 60_000_000_000;
const FLOOR: u64 = 15_000_000_000; // 0.25 x D

struct MapSource {
    map: Mutex<HashMap<String, Value>>,
    fail: bool,
}
impl MapSource {
    fn new(items: &[(&str, Value)]) -> Self {
        Self { map: Mutex::new(items.iter().map(|(k, v)| (k.to_string(), v.clone())).collect()), fail: false }
    }
    fn failing() -> Self {
        Self { map: Mutex::new(HashMap::new()), fail: true }
    }
}
impl LimitSource for MapSource {
    fn fetch(&self, id: &str) -> Result<Option<Value>, String> {
        if self.fail {
            return Err("down".into());
        }
        Ok(self.map.lock().unwrap().get(id).cloned())
    }
}
fn gl(src: MapSource) -> GovernedLimits<MapSource> {
    GovernedLimits::new(src, Duration::ZERO)
}
fn aid(a: &str) -> String { boundary_id(a, LimitKind::DeadlineNs) }
fn cid(a: &str, c: &str) -> String { class_boundary_id(a, c) }

#[test]
fn ids_agree_with_the_python_side_on_shared_vectors() {
    // Reference values computed with integrations/stack_traps.py::_agent_key.
    let v = [
        ("agent-1", "agent-1"), ("a b", "h-c8687a08aa5d6ed2044328fa"), ("a/b", "h-c14cddc033f64b9dea80ea67"),
        ("h-abc", "h-e594a58dec61ff58fa16aa26"), ("h-", "h-3d8c0d8ccdf38a6d9103dbda"), ("../x y", "h-46c740c677b096f58d923616"),
        ("café", "h-850f7dc43910ff890f8879c0"), ("tool.read_file", "tool.read_file"), ("UPPER_case-1", "UPPER_case-1"),
    ];
    for (raw, want) in v {
        assert_eq!(agent_key(raw), want, "agent_key({raw})");
        assert_eq!(class_key(raw), want, "class_key({raw})");
    }
    assert_eq!(agent_key(&"x".repeat(65)), "h-9537c5fdf120482f7d58d25e");
    assert_eq!(agent_key(&"x".repeat(64)), "x".repeat(64));
    assert!(agent_key("").starts_with("h-")); // Python refuses an empty id; Rust hashes it
}

#[test]
fn class_id_has_no_path_or_separator_surprises() {
    let id = cid("a", "../../etc/x y");
    assert!(id.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'_' || b == b'-'));
    assert!(id.starts_with("stack.agent.a.class.h-") && id.ends_with(".deadline_ns"));
}

#[test]
fn lowest_of_class_agent_and_default_wins() {
    let g = gl(MapSource::new(&[(&aid("a"), json!(40_000_000_000u64)), (&cid("a", "read"), json!(20_000_000_000u64)),
                                (&cid("a", "write"), json!(50_000_000_000u64))]));
    assert_eq!(g.effective_for_class("a", Some("read"), D), 20_000_000_000);
    assert_eq!(g.effective_for_class("a", Some("write"), D), 40_000_000_000); // agent limit is lower
    assert_eq!(g.effective_for_class("a", Some("other"), D), 40_000_000_000); // no class limit: agent result
    assert_eq!(g.effective_for_class("b", Some("read"), D), D);               // nothing governed
}

#[test]
fn the_kernel_raises_a_too_low_class_limit_to_its_floor() {
    let g = gl(MapSource::new(&[(&cid("a", "read"), json!(1))]));
    assert_eq!(g.effective_for_class("a", Some("read"), D), FLOOR);
    assert_eq!(g.stats().below_floor, 1);
}

#[test]
fn no_class_or_empty_class_is_exactly_the_agent_result() {
    let g = gl(MapSource::new(&[(&aid("a"), json!(33_000_000_000u64)), (&cid("a", "read"), json!(16_000_000_000u64))]));
    assert_eq!(g.effective_for_class("a", None, D), g.effective("a", LimitKind::DeadlineNs, D));
    assert_eq!(g.effective_for_class("a", Some(""), D), 33_000_000_000);
}

#[test]
fn unusable_class_values_leave_the_agent_result() {
    for bad in [json!("20"), json!(null), json!(-5), json!(0), json!(0.5), json!(true), json!([1]), json!({"a": 1}), json!("NaN")] {
        let g = gl(MapSource::new(&[(&aid("a"), json!(45_000_000_000u64)), (&cid("a", "read"), bad.clone())]));
        assert_eq!(g.effective_for_class("a", Some("read"), D), 45_000_000_000, "class value {bad}");
    }
}

fn lcg(state: &mut u64) -> u64 {
    *state = state.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
    *state >> 11
}
fn fuzz_value(s: &mut u64) -> Value {
    match lcg(s) % 9 {
        0 => json!(0), 1 => json!(1), 2 => json!(-(lcg(s) as i64)), 3 => json!(lcg(s) % (2 * D)),
        4 => json!((lcg(s) % (2 * D)) as f64 + 0.5), 5 => json!(u64::MAX), 6 => json!("x"), 7 => json!(null),
        _ => json!(lcg(s) % D),
    }
}

#[test]
fn fuzzed_service_values_never_leave_the_floor_and_ceiling() {
    let mut s = 12345u64;
    for _ in 0..10_000 {
        let g = gl(MapSource::new(&[(&cid("a", "read"), fuzz_value(&mut s)), (&aid("a"), fuzz_value(&mut s))]));
        let got = g.effective_for_class("a", Some("read"), D);
        assert!(got <= D, "above ceiling: {got}");
        // the agent limit may be lower than the floor (floor on the agent path is opt-in); the class path alone never is
        let agent = g.effective("a", LimitKind::DeadlineNs, D);
        assert!(got >= FLOOR.min(agent), "below floor: {got}");
    }
}

/// The pre-change rule, copied here as a reference: ceiling only, whole floats floored, junk ignored.
fn reference(v: Option<&Value>, default: u64) -> u64 {
    let n = v.and_then(|v| {
        if let Some(u) = v.as_u64() { return if u > 0 { Some(u) } else { None }; }
        let f = v.as_f64()?;
        if f.is_finite() && (1.0..1.8446744073709552e19).contains(&f) { Some(f.floor() as u64) } else { None }
    });
    match n { Some(x) if x > default => default, Some(x) => x, None => default }
}

#[test]
fn without_a_class_or_a_floor_the_result_is_the_old_result() {
    let mut s = 777u64;
    for i in 0..10_000 {
        let v = fuzz_value(&mut s);
        let kind = if i % 2 == 0 { LimitKind::DeadlineNs } else { LimitKind::TokensCapacity };
        let g = gl(MapSource::new(&[(&boundary_id("a", kind), v.clone())]));
        assert_eq!(g.effective("a", kind, D), reference(Some(&v), D), "value {v}");
        if kind == LimitKind::DeadlineNs {
            assert_eq!(g.effective_for_class("a", None, D), reference(Some(&v), D));
        }
    }
}

#[test]
fn the_whole_agent_floor_is_opt_in() {
    let src = || MapSource::new(&[(&aid("a"), json!(1))]);
    assert_eq!(gl(src()).effective("a", LimitKind::DeadlineNs, D), 1); // existing behavior, finding F2
    assert_eq!(gl(src()).with_deadline_floor(0.25).effective("a", LimitKind::DeadlineNs, D), FLOOR);
    assert_eq!(gl(src()).with_deadline_floor(f64::NAN).effective("a", LimitKind::DeadlineNs, D), 1); // invalid ratio ignored
    assert_eq!(gl(src()).with_deadline_floor(0.25).effective("a", LimitKind::TokensCapacity, 1000), 1000); // other kinds untouched
}

#[test]
fn a_restarted_kernel_with_the_service_down_uses_the_default() {
    // Documents limit F3 (not fixed in this change): the cache is in memory.
    let up = gl(MapSource::new(&[(&cid("a", "read"), json!(20_000_000_000u64))]));
    assert_eq!(up.effective_for_class("a", Some("read"), D), 20_000_000_000);
    let restarted = gl(MapSource::failing());
    assert_eq!(restarted.effective_for_class("a", Some("read"), D), D);
}

#[test]
fn a_flood_of_class_names_is_capped() {
    let g = gl(MapSource::new(&[]));
    for i in 0..(CLASS_CACHE_LIMIT + 50) {
        assert_eq!(g.effective_for_class("a", Some(&format!("c{i}")), D), D);
    }
    assert!(g.stats().class_cache_full >= 40);
}

struct Flaky {
    up: std::sync::atomic::AtomicBool,
}
impl LimitSource for Flaky {
    fn fetch(&self, _id: &str) -> Result<Option<Value>, String> {
        if self.up.load(std::sync::atomic::Ordering::SeqCst) { Ok(Some(json!(20_000_000_000u64))) } else { Err("down".into()) }
    }
}

#[test]
fn a_service_error_keeps_the_last_good_class_value() {
    let g = GovernedLimits::new(Flaky { up: std::sync::atomic::AtomicBool::new(true) }, Duration::ZERO);
    assert_eq!(g.effective_for_class("a", Some("read"), D), 20_000_000_000);
    g.source_for_test().up.store(false, std::sync::atomic::Ordering::SeqCst);
    assert_eq!(g.effective_for_class("a", Some("read"), D), 20_000_000_000);
    assert!(g.stats().source_errors >= 1);
}
