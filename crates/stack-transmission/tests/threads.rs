//! Real-thread tests of the shift protocol.

// Test crate: helpers outside #[test] functions may unwrap and panic.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use std::collections::HashSet;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{mpsc, Arc, Barrier, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use common::{tx, wait_until, Mode};
use stack_transmission::{GateOutcome, Reason, Resolution, Transmission, TransmissionConfig};

const LONG: Duration = Duration::from_secs(5);

/// Work that takes a little while and reads the whole config more than once.
fn do_work(m: &Mode) -> u64 {
    let mut acc = 0u64;
    for i in 0..50u64 {
        assert!(m.is_consistent());
        acc = acc.wrapping_add(m.policy_version ^ i);
        if i % 16 == 0 {
            thread::yield_now();
        }
    }
    acc
}

#[test]
fn workers_never_observe_a_mixed_gear_across_repeated_shifts() {
    let t = tx(TransmissionConfig::default());
    let stop = Arc::new(AtomicBool::new(false));
    let checks = Arc::new(AtomicU64::new(0));
    let workers: Vec<_> = (0..8)
        .map(|_| {
            let t = t.clone();
            let stop = Arc::clone(&stop);
            let checks = Arc::clone(&checks);
            thread::spawn(move || {
                let mut epochs = HashSet::new();
                while !stop.load(Ordering::Relaxed) {
                    let g = match t.engage(LONG) {
                        Ok(g) => g,
                        Err(trip) => {
                            assert_eq!(trip.outcome(), GateOutcome::Retry);
                            continue;
                        }
                    };
                    let e = g.epoch();
                    assert_eq!(t.current_epoch(), e, "epoch moved before work started");
                    assert_eq!(g.config().tag, e, "gear config does not match its epoch");
                    do_work(g.config());
                    assert_eq!(t.current_epoch(), e, "epoch moved while work was in flight");
                    drop(g);
                    epochs.insert(e);
                    checks.fetch_add(1, Ordering::Relaxed);
                }
                epochs
            })
        })
        .collect();

    let mut shifted = 0u64;
    let started = Instant::now();
    while shifted < 50 && started.elapsed() < Duration::from_secs(20) {
        let next = t.current_epoch() + 1;
        match t.shift(Mode::for_epoch(next), LONG) {
            Ok(r) => {
                assert_eq!(r.from_epoch + 1, r.to_epoch);
                assert_eq!(r.to_epoch, next);
                shifted += 1;
            }
            Err(e) => assert_eq!(e.trip().reason, Reason::DrainTimeout),
        }
        thread::sleep(Duration::from_millis(2));
    }
    stop.store(true, Ordering::Relaxed);
    let mut seen = HashSet::new();
    for w in workers {
        seen.extend(w.join().unwrap());
    }
    assert_eq!(shifted, 50);
    assert!(seen.len() > 10, "workers saw only {} epochs", seen.len());
    assert!(checks.load(Ordering::Relaxed) > 100);
    let s = t.status();
    assert_eq!((s.epoch, s.in_flight, s.clutch_pressed), (50, 0, false));
}

#[test]
fn drain_timeout_rolls_back_and_parked_engager_stays_on_old_gear() {
    let t = tx(TransmissionConfig::default());
    let held = t.engage(LONG).unwrap();

    let t2 = t.clone();
    let shifter = thread::spawn(move || t2.shift(Mode::for_epoch(1), Duration::from_millis(200)));
    wait_until("clutch pressed", || t.status().clutch_pressed);

    let t3 = t.clone();
    let engager = thread::spawn(move || t3.engage(LONG).map(|g| g.epoch()));
    wait_until("engager parked", || t.status().waiting_engagers == 1);

    let refused = shifter.join().unwrap().unwrap_err();
    let trip = refused.trip();
    assert_eq!(trip.reason, Reason::DrainTimeout);
    assert_eq!(trip.outcome(), GateOutcome::Retry);
    assert_eq!(trip.resolution(), Resolution::Rollback);
    assert_eq!(refused.into_config(), Mode::for_epoch(1));

    // The parked engager proceeds, on the old gear.
    assert_eq!(engager.join().unwrap().unwrap(), 0);
    let s = t.status();
    assert_eq!((s.epoch, s.clutch_pressed, s.in_flight), (0, false, 1));
    assert_eq!(held.epoch(), 0);
    assert_eq!(t.current_epoch(), 0);

    // Once the work drains, the same config shifts cleanly.
    drop(held);
    let r = t.shift(Mode::for_epoch(1), LONG).unwrap();
    assert_eq!((r.from_epoch, r.to_epoch), (0, 1));
}

#[test]
fn engage_during_clutch_waits_then_runs_on_the_new_gear() {
    let t = tx(TransmissionConfig::default());
    let held = t.engage(LONG).unwrap();

    let t2 = t.clone();
    let shifter = thread::spawn(move || t2.shift(Mode::for_epoch(1), LONG));
    wait_until("clutch pressed", || t.status().clutch_pressed);

    let t3 = t.clone();
    let engager = thread::spawn(move || {
        let g = t3.engage(LONG).unwrap();
        (g.epoch(), g.config().clone())
    });
    wait_until("engager parked", || t.status().waiting_engagers == 1);
    // Still parked: the old gear is engaged and the clutch is down.
    assert_eq!(t.current_epoch(), 0);

    drop(held);
    let report = shifter.join().unwrap().unwrap();
    assert_eq!(report.to_epoch, 1);
    let (epoch, mode) = engager.join().unwrap();
    assert_eq!(epoch, 1);
    assert_eq!(mode, Mode::for_epoch(1));
    assert_eq!(t.status().waiting_engagers, 0);
}

#[test]
fn engage_that_outlasts_its_timeout_gets_retry() {
    let t = tx(TransmissionConfig::default());
    let held = t.engage(LONG).unwrap();
    let t2 = t.clone();
    let shifter = thread::spawn(move || t2.shift(Mode::for_epoch(1), LONG));
    wait_until("clutch pressed", || t.status().clutch_pressed);

    let trip = t.engage(Duration::from_millis(30)).unwrap_err();
    assert_eq!(trip.reason, Reason::ClutchWaitTimeout);
    assert_eq!(trip.outcome(), GateOutcome::Retry);
    assert_eq!(trip.resolution(), Resolution::Reject);
    assert_eq!(t.status().in_flight, 1);

    drop(held);
    assert!(shifter.join().unwrap().is_ok());
}

#[test]
fn wait_queue_is_bounded() {
    let cfg = TransmissionConfig {
        max_waiting_engagers: 1,
        ..TransmissionConfig::default()
    };
    let t = tx(cfg);
    let held = t.engage(LONG).unwrap();
    let t2 = t.clone();
    let shifter = thread::spawn(move || t2.shift(Mode::for_epoch(1), LONG));
    wait_until("clutch pressed", || t.status().clutch_pressed);
    let t3 = t.clone();
    let parked = thread::spawn(move || t3.engage(LONG).map(|g| g.epoch()));
    wait_until("engager parked", || t.status().waiting_engagers == 1);

    let trip = t.engage(LONG).unwrap_err();
    assert_eq!(trip.reason, Reason::WaitQueueFull);
    assert_eq!(trip.outcome(), GateOutcome::Retry);

    drop(held);
    assert!(shifter.join().unwrap().is_ok());
    assert_eq!(parked.join().unwrap().unwrap(), 1);
}

#[test]
fn panicking_worker_does_not_wedge_the_transmission() {
    let t = tx(TransmissionConfig::default());
    let (go_tx, go_rx) = mpsc::channel::<()>();
    let (held_tx, held_rx) = mpsc::channel::<()>();

    let tw = t.clone();
    let worker = thread::spawn(move || {
        let _g = tw.engage(LONG).unwrap();
        held_tx.send(()).unwrap();
        go_rx.recv().unwrap();
        panic!("test fixture: worker fails while holding a drive guard");
    });
    held_rx.recv().unwrap();
    assert_eq!(t.status().in_flight, 1);

    let ts = t.clone();
    let shift_timeout = Duration::from_secs(10);
    let shifter = thread::spawn(move || {
        let started = Instant::now();
        (ts.shift(Mode::for_epoch(1), shift_timeout), started.elapsed())
    });
    wait_until("clutch pressed", || t.status().clutch_pressed);

    go_tx.send(()).unwrap();
    assert!(worker.join().is_err(), "worker should have panicked");

    let (result, took) = shifter.join().unwrap();
    assert_eq!(result.unwrap().to_epoch, 1);
    assert!(took < shift_timeout, "shift waited for its full timeout");
    let s = t.status();
    assert_eq!((s.in_flight, s.clutch_pressed, s.halted), (0, false, None));
    assert_eq!(t.engage(LONG).unwrap().epoch(), 1);
}

#[test]
fn second_concurrent_shift_gets_retry_and_first_completes() {
    let t = tx(TransmissionConfig::default());
    let held = t.engage(LONG).unwrap();
    let t2 = t.clone();
    let first = thread::spawn(move || t2.shift(Mode::for_epoch(1), LONG));
    wait_until("clutch pressed", || t.status().clutch_pressed);

    let refused = t.shift(Mode::for_epoch(99), LONG).unwrap_err();
    assert_eq!(refused.trip().reason, Reason::ShiftInProgress);
    assert_eq!(refused.trip().outcome(), GateOutcome::Retry);
    assert_eq!(refused.trip().resolution(), Resolution::Reject);
    assert_eq!(refused.into_config().tag, 99);

    drop(held);
    assert_eq!(first.join().unwrap().unwrap().to_epoch, 1);
    assert_eq!(t.current_epoch(), 1);
    assert_eq!(t.engage(LONG).unwrap().config().tag, 1);
}

#[test]
fn concurrent_shifters_serialize_with_no_lost_or_duplicate_epochs() {
    const THREADS: u64 = 8;
    const PER_THREAD: u64 = 50;
    let t = Transmission::new(0u64, TransmissionConfig::default()).unwrap();
    let barrier = Arc::new(Barrier::new(THREADS as usize));
    let reports = Arc::new(Mutex::new(Vec::new()));
    let handles: Vec<_> = (0..THREADS)
        .map(|id| {
            let t = t.clone();
            let barrier = Arc::clone(&barrier);
            let reports = Arc::clone(&reports);
            thread::spawn(move || {
                barrier.wait();
                let mut done = 0;
                let mut retries = 0u64;
                let mut cfg = id;
                while done < PER_THREAD {
                    match t.shift(cfg, LONG) {
                        Ok(r) => {
                            reports.lock().unwrap().push(r);
                            done += 1;
                            cfg = id;
                        }
                        Err(e) => {
                            assert_eq!(e.trip().reason, Reason::ShiftInProgress);
                            cfg = e.into_config();
                            retries += 1;
                            thread::yield_now();
                        }
                    }
                }
                retries
            })
        })
        .collect();
    for h in handles {
        h.join().unwrap();
    }
    let reports = reports.lock().unwrap();
    assert_eq!(reports.len() as u64, THREADS * PER_THREAD);
    let mut to: Vec<u64> = reports.iter().map(|r| r.to_epoch).collect();
    to.sort_unstable();
    let want: Vec<u64> = (1..=THREADS * PER_THREAD).collect();
    assert_eq!(to, want, "every epoch assigned exactly once");
    assert!(reports.iter().all(|r| r.from_epoch + 1 == r.to_epoch));
    assert_eq!(t.current_epoch(), THREADS * PER_THREAD);
}


#[test]
fn stress_ten_thousand_plus_operations() {
    const WORKERS: usize = 8;
    const ENGAGES_PER_WORKER: u64 = 1_500;
    // Small caps so the capacity and wait-queue refusals are exercised too.
    let cfg = TransmissionConfig {
        max_in_flight: 4,
        max_waiting_engagers: 3,
        ..TransmissionConfig::default()
    };
    let t = tx(cfg);
    let ops = Arc::new(AtomicU64::new(0));
    let retries = Arc::new(AtomicU64::new(0));
    let done = Arc::new(AtomicBool::new(false));

    let workers: Vec<_> = (0..WORKERS)
        .map(|_| {
            let (t, ops, retries) = (t.clone(), Arc::clone(&ops), Arc::clone(&retries));
            thread::spawn(move || {
                let mut ok = 0;
                while ok < ENGAGES_PER_WORKER {
                    ops.fetch_add(1, Ordering::Relaxed);
                    match t.engage(Duration::from_millis(500)) {
                        Ok(g) => {
                            let e = g.epoch();
                            assert_eq!(t.current_epoch(), e);
                            do_work(g.config());
                            assert_eq!(t.current_epoch(), e);
                            ok += 1;
                        }
                        Err(trip) => {
                            assert_eq!(trip.outcome(), GateOutcome::Retry, "{trip}");
                            retries.fetch_add(1, Ordering::Relaxed);
                            thread::yield_now();
                        }
                    }
                }
            })
        })
        .collect();

    // Two shifters race each other and the workers. Tags are unique per
    // attempt rather than equal to the epoch, because a shifter cannot know
    // which epoch it will get while the other one is also shifting.
    let successes = Arc::new(AtomicU64::new(0));
    let shifters: Vec<_> = (0..2u64)
        .map(|id| {
            let (t, ops, done, successes) =
                (t.clone(), Arc::clone(&ops), Arc::clone(&done), Arc::clone(&successes));
            thread::spawn(move || {
                let mut n = 0u64;
                while !done.load(Ordering::Relaxed) {
                    ops.fetch_add(1, Ordering::Relaxed);
                    n += 1;
                    let tag = (id << 32) | n;
                    match t.shift(Mode::for_epoch(tag), Duration::from_millis(200)) {
                        Ok(r) => {
                            assert_eq!(r.from_epoch + 1, r.to_epoch);
                            successes.fetch_add(1, Ordering::Relaxed);
                        }
                        Err(e) => assert_eq!(e.trip().outcome(), GateOutcome::Retry),
                    }
                    thread::sleep(Duration::from_micros(200));
                }
            })
        })
        .collect();

    for w in workers {
        w.join().unwrap();
    }
    done.store(true, Ordering::Relaxed);
    for s in shifters {
        s.join().unwrap();
    }
    let total = ops.load(Ordering::Relaxed);
    assert!(total >= 10_000, "only {total} operations");
    let s = t.status();
    assert_eq!(s.in_flight, 0);
    assert_eq!(s.waiting_engagers, 0);
    assert!(!s.clutch_pressed);
    assert_eq!(s.epoch, successes.load(Ordering::Relaxed));
    assert!(s.epoch > 0, "no shift ever completed");
    eprintln!(
        "stress: {total} operations, {} engage retries, {} shifts",
        retries.load(Ordering::Relaxed),
        s.epoch
    );
}
