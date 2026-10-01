//! Flood: fast-fail requests from ten times as many threads as there are
//! admission slots. Sheds must be counted in the metrics, legitimate
//! requests must still complete, and the in-flight counter must return to
//! zero. This strategy has no spin loop and no spin budget, so there is no
//! spin CPU to bound; the per-request work is fixed.
//!
//! This file is its own test binary so it can install a global metrics
//! recorder (flood threads do not see a thread-local one).

#![allow(clippy::unwrap_used, clippy::panic)] // test code: failures should abort the test

use metrics_util::debugging::{DebugValue, DebuggingRecorder};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tack_anc_harness::cpu::process_cpu_time;
use tack_anc_pipeline::telemetry::names;
use tack_anc_pipeline::{
    Accepted, PipelineConfig, PipelineGate, TokenSecret, Trip, Validator, TOKEN_LEN,
};

const CAP: usize = 1;
const FLOOD_THREADS: usize = 10 * CAP;
const FLOOD_FOR: Duration = Duration::from_millis(300);
const LEGIT_MAX_ATTEMPTS: u32 = 100_000;

#[derive(Default, Debug, Clone, Copy)]
struct Tally {
    ok: u64,
    mismatch: u64,
    shed: u64,
    other: u64,
}

fn tally(r: Result<Accepted, Trip>, t: &mut Tally) {
    match r {
        Ok(_) => t.ok += 1,
        Err(Trip::Mismatch) => t.mismatch += 1,
        Err(Trip::SlotsFull) => t.shed += 1,
        Err(_) => t.other += 1,
    }
}

#[test]
fn flood_sheds_are_counted_and_legit_requests_complete() {
    let rec = DebuggingRecorder::new();
    let snapshotter = rec.snapshotter();
    rec.install().unwrap();

    // Test fixture, not a key.
    let secret = [0x42u8; TOKEN_LEN];
    let mut fast_fail = secret;
    fast_fail[0] ^= 0xff;

    for validator in Validator::ALL {
        let _ = snapshotter.snapshot(); // drain
        let cfg = PipelineConfig {
            validator,
            allow_leaky_validators: true,
            max_in_flight: CAP,
            record_response_time: false,
        };
        let gate =
            Arc::new(PipelineGate::new(TokenSecret::from_bytes(&secret).unwrap(), cfg).unwrap());
        let stop = Arc::new(AtomicBool::new(false));
        let cpu0 = process_cpu_time().unwrap();

        let flooders: Vec<_> = (0..FLOOD_THREADS)
            .map(|_| {
                let g = Arc::clone(&gate);
                let s = Arc::clone(&stop);
                std::thread::spawn(move || {
                    let mut t = Tally::default();
                    while !s.load(Ordering::Relaxed) {
                        tally(g.check(&fast_fail), &mut t);
                    }
                    t
                })
            })
            .collect();

        let legit = {
            let g = Arc::clone(&gate);
            let s = Arc::clone(&stop);
            std::thread::spawn(move || {
                let mut t = Tally::default();
                let (mut completed, mut failed) = (0u64, 0u64);
                while !s.load(Ordering::Relaxed) {
                    let mut done = false;
                    for _ in 0..LEGIT_MAX_ATTEMPTS {
                        let r = g.check(&secret);
                        tally(r, &mut t);
                        if r.is_ok() {
                            done = true;
                            break;
                        }
                        std::thread::yield_now();
                    }
                    if done {
                        completed += 1;
                    } else {
                        failed += 1;
                    }
                }
                (t, completed, failed)
            })
        };

        let t0 = Instant::now();
        std::thread::sleep(FLOOD_FOR);
        stop.store(true, Ordering::Relaxed);
        let mut total = Tally::default();
        for h in flooders {
            let t = h.join().unwrap();
            total.ok += t.ok;
            total.mismatch += t.mismatch;
            total.shed += t.shed;
            total.other += t.other;
        }
        let (lt, completed, failed) = legit.join().unwrap();
        let wall = t0.elapsed();
        let cpu = process_cpu_time().unwrap().since(&cpu0).total();

        let snap = snapshotter.snapshot().into_vec();
        let count = |name: &str, want: &[(&str, &str)]| -> u64 {
            snap.iter()
                .filter(|(ck, _, _, _)| {
                    ck.key().name() == name
                        && want.iter().all(|(k, v)| {
                            ck.key().labels().any(|l| l.key() == *k && l.value() == *v)
                        })
                })
                .map(|(_, _, _, v)| match v {
                    DebugValue::Counter(c) => *c,
                    _ => 0,
                })
                .sum()
        };
        let sheds = total.shed + lt.shed;
        let requests = total.ok
            + total.mismatch
            + total.shed
            + total.other
            + lt.ok
            + lt.mismatch
            + lt.shed
            + lt.other;
        let label = validator.label();

        assert_eq!(total.ok, 0, "{label}: flood never matches");
        assert_eq!(total.other + lt.other, 0, "{label}");
        assert_eq!(lt.mismatch, 0, "{label}: legit token never mismatches");
        assert!(sheds > 0, "{label}: 10x oversubscription must shed");
        assert_eq!(
            count(
                names::SHED_TOTAL,
                &[("strategy", "pipeline"), ("reason", "slots_full")]
            ),
            sheds,
            "{label}: every shed is counted"
        );
        assert_eq!(
            count(names::REQUESTS_TOTAL, &[("validator", label)]),
            requests,
            "{label}: every request is counted"
        );
        assert_eq!(
            count(names::TOKEN_MISMATCH_TOTAL, &[("validator", label)]),
            total.mismatch,
            "{label}"
        );
        assert!(
            completed > 0,
            "{label}: legit requests complete under flood"
        );
        assert_eq!(
            failed, 0,
            "{label}: no legit request exhausted its attempts"
        );
        assert_eq!(gate.in_flight(), 0, "{label}: slots all returned");
        eprintln!(
            "{label}: requests={requests} sheds={sheds} legit_completed={completed} \
             wall={wall:?} cpu={cpu:?} cpu_ns_per_request={:.1}",
            cpu.as_nanos() as f64 / requests.max(1) as f64
        );
    }
}
