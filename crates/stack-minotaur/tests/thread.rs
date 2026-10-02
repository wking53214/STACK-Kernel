//! Behaviour of the Thread and its guards.

// Test code: unwrapping and panicking on an unexpected result is the assertion.
#![allow(clippy::unwrap_used, clippy::panic)]

use std::panic::{catch_unwind, AssertUnwindSafe};

use stack_minotaur::{
    rollback_on_trip, Detector, Fingerprint, GateOutcome, MinotaurConfig, Resolution, Thread, Trip,
    TripKind, Walk,
};

fn fp(n: u64) -> Fingerprint {
    Fingerprint::of_bytes(&n.to_le_bytes())
}

fn thread(cfg: MinotaurConfig) -> Thread {
    Thread::new(cfg).unwrap()
}

#[test]
fn depth_counts_across_nested_guards() {
    let mut t = thread(MinotaurConfig::default());
    assert_eq!(t.depth(), 0);
    {
        let mut g1 = t.descend().unwrap();
        assert_eq!(g1.depth(), 1);
        {
            let mut g2 = g1.descend().unwrap();
            assert_eq!(g2.depth(), 2);
            {
                let g3 = g2.descend().unwrap();
                assert_eq!(g3.depth(), 3);
            }
            assert_eq!(g2.depth(), 2);
        }
        assert_eq!(g1.depth(), 1);
    }
    assert_eq!(t.depth(), 0);
}

fn recurse_with_early_return(
    t: &mut dyn Walk,
    n: u32,
    bail_at: u32,
) -> Result<u32, &'static str> {
    let mut g = t.descend().map_err(|_| "tripped")?;
    let here = g.depth();
    if n == bail_at {
        return Err("early");
    }
    if n == 0 {
        return Ok(here);
    }
    recurse_with_early_return(&mut g, n - 1, bail_at)
}

#[test]
fn depth_restored_after_early_returns() {
    let mut t = thread(MinotaurConfig::default());
    assert_eq!(recurse_with_early_return(&mut t, 10, 99), Ok(11));
    assert_eq!(t.depth(), 0);
    assert_eq!(recurse_with_early_return(&mut t, 10, 4), Err("early"));
    assert_eq!(t.depth(), 0);
}

#[test]
fn panic_inside_guarded_scope_restores_depth() {
    let mut t = thread(MinotaurConfig::default());
    let result = catch_unwind(AssertUnwindSafe(|| {
        let mut g1 = t.descend().unwrap();
        let g2 = g1.descend().unwrap();
        assert_eq!(g2.depth(), 2);
        panic!("boom inside a guarded scope");
    }));
    assert!(result.is_err());
    assert_eq!(t.depth(), 0);
    // The Thread is still usable afterwards.
    let g = t.descend().unwrap();
    assert_eq!(g.depth(), 1);
}

#[test]
fn two_state_ping_pong_is_a_loop_of_period_2() {
    let mut t = thread(MinotaurConfig {
        revisit_allowance: 3,
        ..Default::default()
    });
    let (a, b) = (fp(1), fp(2));
    let mut trip = None;
    for i in 0..100 {
        let s = if i % 2 == 0 { a } else { b };
        if let Err(e) = t.record(s) {
            trip = Some((i, e));
            break;
        }
    }
    let (i, trip) = trip.unwrap();
    // a is visited at steps 0, 2, 4, 6, 8: the fifth visit is the fourth
    // revisit, one more than the allowance of 3.
    assert_eq!(i, 8);
    assert_eq!(
        trip.kind,
        TripKind::LoopDetected {
            period: 2,
            detector: Detector::Exact
        }
    );
    assert_eq!(trip.period(), Some(2));
    assert_eq!(trip.outcome, GateOutcome::Retry);
    assert_eq!(trip.resolution, Resolution::Rollback);
    assert_eq!(trip.steps, 9);
    assert_eq!(trip.path.last(), Some(&a));
    // Rewound to the anchor.
    assert_eq!(t.steps(), 0);
    assert_eq!(t.tracked_states(), 0);
}

#[test]
fn ping_pong_found_by_brent_once_the_set_is_full() {
    let cfg = MinotaurConfig {
        max_distinct_states: 16,
        revisit_allowance: 2,
        ..Default::default()
    };
    let mut t = thread(cfg);
    for n in 0..16 {
        t.record(fp(n)).unwrap();
    }
    assert_eq!(t.tracked_states(), 16);
    // Two states the full set cannot hold, alternating.
    let (a, b) = (fp(1_000), fp(1_001));
    let mut trip = None;
    for i in 0..1_000 {
        let s = if i % 2 == 0 { a } else { b };
        if let Err(e) = t.record(s) {
            trip = Some(e);
            break;
        }
        assert!(t.is_degraded());
    }
    let trip = trip.unwrap();
    // The recent-state table (16 slots here) counts `a` exactly and finds
    // the loop one step before Brent's saved state would.
    assert_eq!(
        trip.kind,
        TripKind::LoopDetected {
            period: 2,
            detector: Detector::Recent
        }
    );
}

#[test]
fn long_non_repeating_walk_under_caps_passes() {
    let cfg = MinotaurConfig {
        max_depth: 8,
        max_steps: 50_000,
        max_distinct_states: 50_000,
        revisit_allowance: 0,
        ..Default::default()
    };
    let mut t = thread(cfg);
    let mut g = t.descend().unwrap();
    let mut g2 = g.descend().unwrap();
    for n in 0..50_000 {
        g2.record(fp(n)).unwrap();
    }
    assert_eq!(g2.steps(), 50_000);
    assert_eq!(g2.tracked_states(), 50_000);
    assert!(!g2.is_degraded());
    assert_eq!(g2.trips(), 0);
    drop(g2);
    drop(g);
    t.rewind();
    assert_eq!(t.steps(), 0);
}

#[test]
fn long_non_repeating_walk_in_degraded_mode_passes() {
    let cfg = MinotaurConfig {
        max_steps: 20_000,
        max_distinct_states: 64,
        revisit_allowance: 0,
        max_untracked_transitions: 20_000,
        ..Default::default()
    };
    let mut t = thread(cfg);
    for n in 0..20_000 {
        t.record(fp(n)).unwrap();
    }
    assert!(t.is_degraded());
    assert_eq!(t.untracked_transitions(), 20_000 - 64);
}

#[test]
fn memory_stays_bounded_when_distinct_state_cap_is_hit() {
    let cfg = MinotaurConfig {
        max_steps: 1_000_000,
        max_distinct_states: 128,
        max_untracked_transitions: 1_000_000,
        breadcrumb_len: 16,
        ..Default::default()
    };
    let mut t = thread(cfg);
    let cap_before = t.tracked_capacity();
    assert!(cap_before >= 128);
    for n in 0..100_000 {
        t.record(fp(n)).unwrap();
        assert!(t.tracked_states() <= 128);
    }
    assert_eq!(t.tracked_states(), 128);
    assert_eq!(
        t.tracked_capacity(),
        cap_before,
        "the exact set must not grow"
    );
    assert_eq!(t.breadcrumbs().len(), 16);
    assert!(t.is_degraded());
}

#[test]
fn state_space_explosion_trips() {
    let cfg = MinotaurConfig {
        max_distinct_states: 10,
        max_untracked_transitions: 5,
        ..Default::default()
    };
    let mut t = thread(cfg);
    let mut trip = None;
    for n in 0..100 {
        if let Err(e) = t.record(fp(n)) {
            trip = Some((n, e));
            break;
        }
    }
    let (n, trip) = trip.unwrap();
    assert_eq!(n, 15);
    assert_eq!(
        trip.kind,
        TripKind::StateSpaceExhausted {
            tracked: 10,
            limit: 5
        }
    );
    assert_eq!(trip.outcome, GateOutcome::Retry);
    assert!(!t.is_degraded());
    assert_eq!(t.tracked_states(), 0);
}

#[test]
fn zero_untracked_budget_trips_on_first_overflow() {
    let cfg = MinotaurConfig {
        max_distinct_states: 3,
        max_untracked_transitions: 0,
        ..Default::default()
    };
    let mut t = thread(cfg);
    for n in 0..3 {
        t.record(fp(n)).unwrap();
    }
    let e = t.record(fp(3)).unwrap_err();
    assert_eq!(
        e.kind,
        TripKind::StateSpaceExhausted {
            tracked: 3,
            limit: 0
        }
    );
}

#[test]
fn step_budget_trips() {
    let mut t = thread(MinotaurConfig {
        max_steps: 5,
        ..Default::default()
    });
    for n in 0..5 {
        t.record(fp(n)).unwrap();
    }
    let e = t.record(fp(5)).unwrap_err();
    assert_eq!(e.kind, TripKind::StepBudgetExhausted { limit: 5 });
    assert_eq!(e.steps, 6);
    assert_eq!(t.steps(), 0);
}

#[test]
fn depth_exceeded_rewinds_and_stale_guards_refuse_work() {
    let mut t = thread(MinotaurConfig {
        max_depth: 3,
        ..Default::default()
    });
    {
        let mut g1 = t.descend().unwrap();
        let mut g2 = g1.descend().unwrap();
        let mut g3 = g2.descend().unwrap();
        g3.record(fp(1)).unwrap();
        let e = g3.descend().unwrap_err();
        assert_eq!(e.kind, TripKind::DepthExceeded { limit: 3 });
        assert_eq!(e.depth, 3);
        assert_eq!(e.path, vec![fp(1)]);
        assert_eq!(
            g3.depth(),
            0,
            "rewound to the anchor while guards are alive"
        );
        // Every guard alive from before the trip is stale and refuses work
        // without touching the Thread: the caller has to unwind to the root.
        let e = g3.descend().unwrap_err();
        assert_eq!(e.kind, TripKind::StaleGuard);
        assert_eq!(e.outcome, GateOutcome::Retry);
        assert_eq!(e.resolution, Resolution::Reject);
        assert!(e.path.is_empty());
        assert_eq!(g3.record(fp(2)).unwrap_err().kind, TripKind::StaleGuard);
        assert!(g3.is_stale());
        drop(g3);
        assert_eq!(g2.descend().unwrap_err().kind, TripKind::StaleGuard);
        assert_eq!(g2.depth(), 0);
        assert_eq!(g2.steps(), 0);
        assert_eq!(g2.trips(), 1, "stale refusals are not counted as trips");
    }
    // Stale guards dropped without driving depth below zero.
    assert_eq!(t.depth(), 0);
    let g = t.descend().unwrap();
    assert_eq!(g.depth(), 1);
}

#[test]
fn breadcrumb_path_is_bounded_and_ordered() {
    let mut t = thread(MinotaurConfig {
        breadcrumb_len: 4,
        max_steps: 10,
        ..Default::default()
    });
    for n in 0..10 {
        t.record(fp(n)).unwrap();
    }
    let e = t.record(fp(10)).unwrap_err();
    assert_eq!(e.path, vec![fp(7), fp(8), fp(9), fp(10)]);
}

#[test]
fn repeated_trips_halt_until_operator_reset() {
    let mut t = thread(MinotaurConfig {
        max_steps: 2,
        max_trips_before_halt: 3,
        ..Default::default()
    });
    let mut trips: Vec<Trip> = Vec::new();
    for _ in 0..3 {
        let mut n = 0;
        loop {
            n += 1;
            if let Err(e) = t.record(fp(n)) {
                trips.push(e);
                break;
            }
        }
    }
    assert_eq!(trips[0].outcome, GateOutcome::Retry);
    assert_eq!(trips[1].outcome, GateOutcome::Retry);
    assert_eq!(trips[2].outcome, GateOutcome::TerminalBreach);
    assert_eq!(trips[2].resolution, Resolution::Halt);
    assert_eq!(trips[2].kind, TripKind::StepBudgetExhausted { limit: 2 });
    assert!(t.is_halted());

    // Fail closed: everything is refused, and nothing changes.
    let e = t.record(fp(99)).unwrap_err();
    assert_eq!(e.kind, TripKind::Halted);
    assert_eq!(e.outcome, GateOutcome::TerminalBreach);
    assert!(e.path.is_empty());
    assert_eq!(t.steps(), 0);
    assert_eq!(t.descend().unwrap_err().kind, TripKind::Halted);
    assert_eq!(t.trips(), 3);

    t.operator_reset();
    assert!(!t.is_halted());
    assert_eq!(t.trips(), 0);
    t.record(fp(1)).unwrap();
}

#[test]
fn rewind_does_not_forgive_trips() {
    let mut t = thread(MinotaurConfig {
        max_steps: 1,
        ..Default::default()
    });
    t.record(fp(1)).unwrap();
    t.record(fp(2)).unwrap_err();
    t.rewind();
    assert_eq!(t.trips(), 1);
}

#[test]
fn zero_allowance_trips_on_first_revisit() {
    let mut t = thread(MinotaurConfig {
        revisit_allowance: 0,
        ..Default::default()
    });
    t.record(fp(1)).unwrap();
    t.record(fp(2)).unwrap();
    t.record(fp(3)).unwrap();
    let e = t.record(fp(1)).unwrap_err();
    assert_eq!(
        e.kind,
        TripKind::LoopDetected {
            period: 3,
            detector: Detector::Exact
        }
    );
}

#[test]
fn legitimate_revisits_within_allowance_pass() {
    let mut t = thread(MinotaurConfig {
        revisit_allowance: 2,
        ..Default::default()
    });
    // Each state is visited three times (two revisits), interleaved with
    // fresh states.
    let mut fresh = 1_000;
    for _ in 0..3 {
        for s in 0..10 {
            t.record(fp(s)).unwrap();
            t.record(fp(fresh)).unwrap();
            fresh += 1;
        }
    }
    assert_eq!(t.trips(), 0);
}

#[test]
fn rollback_on_trip_restores_caller_state() {
    let mut t = thread(MinotaurConfig {
        revisit_allowance: 0,
        ..Default::default()
    });
    let mut ledger: Vec<u64> = vec![1, 2, 3];

    let ok = rollback_on_trip(&mut ledger, |l| {
        l.push(4);
        t.record(fp(4))?;
        Ok(l.len())
    });
    assert_eq!(ok.unwrap(), 4);
    assert_eq!(ledger, vec![1, 2, 3, 4]);

    let err = rollback_on_trip(&mut ledger, |l| {
        l.push(5);
        t.record(fp(5))?;
        l.push(4);
        t.record(fp(4))?; // revisit with allowance 0: loop
        Ok(l.len())
    });
    assert!(matches!(
        err.unwrap_err().kind,
        TripKind::LoopDetected { .. }
    ));
    assert_eq!(
        ledger,
        vec![1, 2, 3, 4],
        "caller state restored to the snapshot"
    );
    assert_eq!(t.steps(), 0, "thread rewound to the anchor");
}

#[test]
fn invalid_config_is_refused() {
    let r = Thread::new(MinotaurConfig {
        breadcrumb_len: 0,
        ..Default::default()
    });
    assert!(r.is_err());
}

#[test]
fn thread_and_guard_are_send_and_sync() {
    fn send<T: Send>() {}
    fn sync<T: Sync>() {}
    send::<Thread>();
    sync::<Thread>();
    send::<tack_minotaur::DepthGuard<'static>>();
    send::<Trip>();
}
