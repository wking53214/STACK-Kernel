#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use stack_anc_ceiling::source_guard::{Decision, GuardConfig, SourceGuard};
use stack_anc_ceiling::Clock;

#[derive(Debug)]
struct ManualClock(Mutex<Instant>);

impl ManualClock {
    fn new() -> Arc<Self> {
        Arc::new(Self(Mutex::new(Instant::now())))
    }
    fn advance(&self, d: Duration) {
        *self.0.lock().unwrap() += d;
    }
}

impl Clock for ManualClock {
    fn now(&self) -> Instant {
        *self.0.lock().unwrap()
    }
}

fn cfg() -> GuardConfig {
    GuardConfig {
        max_in_flight: 2,
        failure_burst: 3.0,
        failures_per_second: 1.0,
        cooldown: Duration::from_secs(10),
        buckets: 1024,
    }
}

/// Borrowing check: the decision (and any permit it holds) stays alive.
fn is_admit(d: &Decision<'_>) -> bool {
    matches!(d, Decision::Admit(_))
}

#[test]
fn rejects_bad_configuration() {
    let clock = ManualClock::new();
    let mut c = cfg();
    c.max_in_flight = 0;
    assert!(SourceGuard::new(c, clock.clone()).is_err());
    let mut c = cfg();
    c.failure_burst = 0.5;
    assert!(SourceGuard::new(c, clock.clone()).is_err());
    let mut c = cfg();
    c.failures_per_second = 0.0;
    assert!(SourceGuard::new(c, clock.clone()).is_err());
    let mut c = cfg();
    c.buckets = 0;
    assert!(SourceGuard::new(c, clock.clone()).is_err());
    assert!(SourceGuard::new(cfg(), clock).is_ok());
}

#[test]
fn concurrency_cap_per_source_and_slots_free_on_drop() {
    let g = SourceGuard::new(cfg(), ManualClock::new()).unwrap();
    let p1 = g.admit(b"src-a");
    let p2 = g.admit(b"src-a");
    assert!(is_admit(&p1));
    assert!(is_admit(&p2));
    let third = g.admit(b"src-a");
    assert!(!is_admit(&third), "third request in flight is refused");
    drop(p2);
    let fourth = g.admit(b"src-a");
    assert!(is_admit(&fourth), "a freed slot admits again");
}

#[test]
fn failure_burst_then_cooldown_then_recovery() {
    let clock = ManualClock::new();
    let g = SourceGuard::new(cfg(), clock.clone()).unwrap();
    for _ in 0..3 {
        g.record_failure(b"attacker");
    }
    assert!(is_admit(&g.admit(b"attacker")), "three failures are within the burst");
    g.record_failure(b"attacker");
    assert!(!is_admit(&g.admit(b"attacker")), "the fourth failure trips the cooldown");
    clock.advance(Duration::from_secs(9));
    assert!(!is_admit(&g.admit(b"attacker")), "still cooling at nine seconds");
    clock.advance(Duration::from_secs(2));
    assert!(is_admit(&g.admit(b"attacker")), "cooldown over at eleven seconds");
}

#[test]
fn refusals_do_not_extend_the_cooldown() {
    let clock = ManualClock::new();
    let g = SourceGuard::new(cfg(), clock.clone()).unwrap();
    for _ in 0..4 {
        g.record_failure(b"victim");
    }
    for _ in 0..50 {
        clock.advance(Duration::from_millis(100));
        assert!(!is_admit(&g.admit(b"victim")));
    }
    // 50 refusals over 5 s, then 5.1 s more: 10.1 s after the trip, past the 10 s cooldown.
    clock.advance(Duration::from_millis(5_100));
    assert!(is_admit(&g.admit(b"victim")), "cooldown ended on schedule despite refusals");
}

#[test]
fn tokens_refill_with_time() {
    let clock = ManualClock::new();
    let mut c = cfg();
    c.failure_burst = 2.0;
    c.failures_per_second = 10.0;
    let g = SourceGuard::new(c, clock.clone()).unwrap();
    g.record_failure(b"s");
    g.record_failure(b"s");
    clock.advance(Duration::from_millis(100));
    g.record_failure(b"s");
    assert!(is_admit(&g.admit(b"s")), "one token regained in 100 ms, so no trip yet");
    g.record_failure(b"s");
    assert!(!is_admit(&g.admit(b"s")), "no tokens left, so the next failure trips");
}

#[test]
fn one_source_tripping_does_not_refuse_others() {
    let clock = ManualClock::new();
    let mut c = cfg();
    c.failure_burst = 1.0;
    let g = SourceGuard::new(c, clock).unwrap();
    // The hash is random per guard, so other keys land in other buckets with
    // overwhelming probability. Check that at least one of 100 keys is unaffected.
    g.record_failure(b"alpha");
    g.record_failure(b"alpha");
    assert!(!is_admit(&g.admit(b"alpha")));
    let unaffected = (0..100u32).any(|i| {
        let key = format!("other-{i}");
        is_admit(&g.admit(key.as_bytes()))
    });
    assert!(unaffected, "other sources keep their own limits");
}
