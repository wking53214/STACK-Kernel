//! Scheduling behaviour on the manual clock.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use tack_greenwave::{
    ConfigError, GateOutcome, GatePosition, GreenWaveConfig, LaneId, LaneSpec, ManualClock, Op,
    Resolution, TrafficCop, TripReason,
};

const PHASE: u64 = 1_000;

fn config(weights: &[u32], cap: u32, per_phase: u32, offsets: &[u32]) -> GreenWaveConfig {
    GreenWaveConfig {
        phase_len_ns: PHASE,
        phases_per_epoch: weights.iter().sum(),
        lanes: weights
            .iter()
            .map(|&weight| LaneSpec {
                weight,
                queue_cap: cap,
            })
            .collect(),
        stage_offsets: offsets.to_vec(),
        max_dispatch_per_phase: per_phase,
    }
}

fn cop(cfg: &GreenWaveConfig) -> (TrafficCop<u32, ManualClock>, ManualClock) {
    let clock = ManualClock::new(0);
    (TrafficCop::new(cfg, clock.clone()).unwrap(), clock)
}

#[test]
fn phase_assignment_is_deterministic() {
    let cfg = config(&[5, 1, 1], 8, 1, &[0]);
    let (a, _) = cop(&cfg);
    let (b, _) = cop(&cfg);
    assert_eq!(a.phase_table(), b.phase_table());
    // Smooth weighted round-robin, lowest index wins ties. For weights
    // {a: 5, b: 1, c: 1} this is the sequence nginx documents: a a b a c a a.
    let owners: Vec<usize> = a.phase_table().owners().iter().map(|l| l.index()).collect();
    assert_eq!(owners, vec![0, 0, 1, 0, 2, 0, 0]);
    assert_eq!(a.phase_table().phases_of(LaneId::new(0)).unwrap(), &[0, 1, 3, 5, 6]);

    // Same arrivals on the same clock give the same dispatch sequence.
    let run = || {
        let (mut c, clock) = cop(&config(&[2, 1, 3], 4, 2, &[0, 1]));
        let mut out = Vec::new();
        for step in 0..60u64 {
            clock.set(step * PHASE + 3);
            let lane = LaneId::new(u16::try_from(step % 3).unwrap());
            let _ = c.admit(lane, u32::try_from(step).unwrap());
            clock.set((step + 1) * PHASE);
            for d in c.poll().unwrap() {
                out.push((d.ticket.id().get(), d.ticket.lane().index(), d.ticket.dispatched_at(), d.payload));
            }
        }
        out
    };
    let first = run();
    assert!(!first.is_empty());
    assert_eq!(first, run());
}

#[test]
fn every_lane_owns_at_least_one_phase_and_weights_are_honoured() {
    let weights = [1u32, 7, 3, 1, 4];
    let (c, _) = cop(&config(&weights, 4, 1, &[0]));
    let t = c.phase_table();
    assert_eq!(t.len(), 16);
    for (i, &w) in weights.iter().enumerate() {
        let phases = t.phases_of(LaneId::from_index(i).unwrap()).unwrap();
        assert_eq!(phases.len(), w as usize);
        assert!(!phases.is_empty());
    }
}

#[test]
fn table_validation_fails_closed() {
    let mut cfg = config(&[1, 1], 4, 1, &[0]);
    cfg.lanes[1].weight = 0;
    cfg.phases_per_epoch = 1;
    let err = TrafficCop::<u32, _>::new(&cfg, ManualClock::new(0)).unwrap_err();
    assert_eq!(err, ConfigError::ZeroWeight { lane: 1 });
    assert_eq!(err.outcome(), GateOutcome::TerminalBreach);
    assert_eq!(err.resolution(), Resolution::Halt);

    let mut cfg = config(&[2, 2], 4, 1, &[0]);
    cfg.phases_per_epoch = 5;
    assert_eq!(
        TrafficCop::<u32, _>::new(&cfg, ManualClock::new(0)).unwrap_err(),
        ConfigError::WeightSumMismatch { sum: 4, phases: 5 }
    );

    let cases: Vec<(GreenWaveConfig, &str)> = vec![
        (config(&[], 4, 1, &[0]), "no_lanes"),
        (config(&[1; 65], 4, 1, &[0]), "too_many_lanes"),
        (config(&[1, 1], 0, 1, &[0]), "queue_cap_out_of_range"),
        (config(&[1, 1], 65_537, 1, &[0]), "queue_cap_out_of_range"),
        (config(&[1, 1], 4, 0, &[0]), "dispatch_budget_out_of_range"),
        (config(&[1, 1], 4, 1, &[]), "no_stages"),
        (config(&[1, 1], 4, 1, &[0; 33]), "too_many_stages"),
        (config(&[1, 1], 4, 1, &[0, 2]), "offset_out_of_range"),
        (config(&[2, 2], 4, 1, &[1, 0]), "offsets_not_monotonic"),
        (
            GreenWaveConfig {
                phase_len_ns: 999,
                ..config(&[1], 4, 1, &[0])
            },
            "phase_too_short",
        ),
        (
            GreenWaveConfig {
                phase_len_ns: 60_000_000_000,
                ..config(&[1, 1], 4, 1, &[0])
            },
            "epoch_too_long",
        ),
        (
            GreenWaveConfig {
                phases_per_epoch: 0,
                ..config(&[1], 4, 1, &[0])
            },
            "phases_out_of_range",
        ),
        (config(&[1; 64], 65_536, 1, &[0]), "total_queue_too_large"),
    ];
    for (cfg, want) in cases {
        let err = TrafficCop::<u32, _>::new(&cfg, ManualClock::new(0)).unwrap_err();
        assert_eq!(err.as_str(), want, "{err}");
    }
    assert!(GreenWaveConfig::default().validate().is_ok());
}

#[test]
fn dispatch_happens_only_in_the_owning_lanes_phase() {
    // Owners: [0, 1, 0] for weights [2, 1].
    let (mut c, clock) = cop(&config(&[2, 1], 8, 4, &[0]));
    let owners: Vec<usize> = c.phase_table().owners().iter().map(|l| l.index()).collect();
    assert_eq!(owners, vec![0, 1, 0]);
    for _ in 0..3 {
        c.admit(LaneId::new(1), 1).unwrap();
    }
    // Phase 0 belongs to lane 0: nothing leaves lane 1.
    assert!(c.poll().unwrap().is_empty());
    clock.set(PHASE - 1);
    assert!(c.poll().unwrap().is_empty());
    // Phase 1 belongs to lane 1.
    clock.set(PHASE);
    let out = c.poll().unwrap();
    assert_eq!(out.len(), 3);
    for d in &out {
        assert_eq!(d.ticket.lane(), LaneId::new(1));
        assert_eq!(c.owner_at(d.ticket.dispatched_at()), Some(LaneId::new(1)));
        assert_eq!(d.ticket.dispatch_phase(), 1);
    }
    // FIFO order.
    let ids: Vec<u64> = out.iter().map(|d| d.ticket.id().get()).collect();
    assert_eq!(ids, vec![0, 1, 2]);
}

#[test]
fn per_phase_budget_is_enforced_across_repeated_polls() {
    let (mut c, clock) = cop(&config(&[1, 1], 16, 3, &[0]));
    for i in 0..10 {
        c.admit(LaneId::new(0), i).unwrap();
    }
    assert_eq!(c.poll().unwrap().len(), 3);
    clock.set(PHASE / 2);
    assert_eq!(c.poll().unwrap().len(), 0, "budget for this phase is spent");
    clock.set(2 * PHASE);
    assert_eq!(c.poll().unwrap().len(), 3);
}

#[test]
fn flooding_lane_cannot_delay_another_lane_by_more_than_one_epoch() {
    let cfg = config(&[6, 1, 1], 32, 2, &[0]);
    let (mut c, clock) = cop(&cfg);
    let epoch = c.timing().epoch_len();
    let flood = LaneId::new(0);
    let victims = [LaneId::new(1), LaneId::new(2)];
    let mut victim_arrivals = std::collections::HashMap::new();
    let mut worst = 0u64;
    let mut t = 0u64;
    for phase in 0..400u64 {
        // The flooder submits many requests at several instants in every phase.
        for k in 0..4 {
            t = phase * PHASE + k * (PHASE / 4);
            clock.set(t);
            for _ in 0..16 {
                let _ = c.admit(flood, 0);
            }
            // A victim arrives now and then, at arbitrary offsets.
            if (phase * 4 + k) % 7 == 3 {
                let v = victims[usize::try_from((phase + k) % 2).unwrap()];
                if c.lane_depth(v) == Some(0) {
                    let a = c.admit(v, 1).unwrap();
                    assert_eq!(a.position, 0);
                    victim_arrivals.insert(a.id, a.arrived_at);
                }
            }
            if k == 0 {
                for d in c.poll().unwrap() {
                    if let Some(arr) = victim_arrivals.remove(&d.ticket.id()) {
                        let wait = d.ticket.dispatched_at() - arr;
                        assert!(wait < epoch, "victim waited {wait} ns, epoch is {epoch} ns");
                        worst = worst.max(wait);
                    }
                }
            }
        }
    }
    assert!(t > 0);
    assert!(worst > 0, "victims did wait for their phase");
    // Anything still waiting arrived less than one epoch before the last poll.
    let last_poll = 399 * PHASE;
    for arr in victim_arrivals.values() {
        assert!(last_poll.saturating_sub(*arr) < epoch);
    }
}

#[test]
fn queues_never_exceed_caps_and_full_queue_is_retry_with_next_phase_start() {
    let (mut c, clock) = cop(&config(&[2, 1, 1], 5, 1, &[0]));
    let lane = LaneId::new(2);
    for step in 0..50u64 {
        let now = step * 337;
        clock.set(now);
        for i in 0..9u32 {
            match c.admit(lane, i) {
                Ok(_) => {}
                Err(refused) => {
                    assert_eq!(refused.payload, i, "payload handed back untouched");
                    let trip = refused.trip;
                    assert_eq!(trip.reason(), TripReason::QueueFull);
                    assert_eq!(trip.outcome(), GateOutcome::Retry);
                    assert_eq!(trip.resolution(), Resolution::Reject);
                    assert_eq!(trip.op(), Op::Admit);
                    assert_eq!(trip.position(), GatePosition::Alpha);
                    let ra = trip.retry_after().unwrap();
                    assert!(ra > now);
                    assert_eq!(ra % PHASE, 0, "retry_after is a phase start");
                    assert_eq!(c.owner_at(ra), Some(lane), "retry_after is the lane's phase");
                    // And it is the first such phase after the current one.
                    let mut p = now / PHASE + 1;
                    while c.owner_at(p * PHASE) != Some(lane) {
                        p += 1;
                    }
                    assert_eq!(ra, p * PHASE);
                }
            }
            assert!(c.lane_depth(lane).unwrap() <= c.lane_cap(lane).unwrap());
            assert!(c.total_queued() <= 5 * 3);
        }
        let _ = c.poll().unwrap();
    }
}

#[test]
fn release_times_always_land_on_epoch_boundaries() {
    let (mut c, clock) = cop(&config(&[1, 2, 1], 64, 64, &[0, 1]));
    let epoch = c.timing().epoch_len();
    assert_eq!(epoch, 4 * PHASE);
    // Pure function, including completions exactly on a boundary.
    for completed in (0..20 * epoch).step_by(97).chain([0, epoch, 2 * epoch, 2 * epoch - 1]) {
        let r = c.timing().release_at(completed).unwrap();
        assert!(c.timing().is_epoch_boundary(r));
        assert!(r > completed && r - completed <= epoch);
    }
    assert_eq!(c.timing().release_at(u64::MAX), None);

    // Through the cop.
    let mut tickets = Vec::new();
    for step in 0..40u64 {
        clock.set(step * 250);
        let lane = LaneId::from_index(usize::try_from(step % 3).unwrap()).unwrap();
        c.admit(lane, 0).unwrap();
        tickets.extend(c.poll().unwrap().into_iter().map(|d| d.ticket));
    }
    assert!(tickets.len() > 10);
    let base = clock.now_for_test();
    for (i, t) in tickets.iter().enumerate() {
        clock.set(base + u64::try_from(i).unwrap() * 131);
        let r = c.complete(t).unwrap();
        assert_eq!(r.release_at % epoch, 0);
        assert!(r.release_at > clock.now_for_test());
        assert_eq!(r.release_epoch * epoch, r.release_at);
        assert_eq!(r.id, t.id());
    }
}

/// Small extension so the tests can read the manual clock without importing
/// the trait everywhere.
trait NowForTest {
    fn now_for_test(&self) -> u64;
}
impl NowForTest for ManualClock {
    fn now_for_test(&self) -> u64 {
        tack_greenwave::Clock::now(self)
    }
}

#[test]
fn green_wave_schedule_is_consistent_across_stages() {
    let offsets = [0u32, 1, 1, 3, 6];
    let (mut c, clock) = cop(&config(&[3, 2, 2], 16, 4, &offsets));
    let p = u64::from(c.timing().phases_per_epoch());
    let mut checked = 0;
    for step in 0..70u64 {
        clock.set(step * PHASE + 11);
        let lane = LaneId::from_index(usize::try_from(step % 3).unwrap()).unwrap();
        c.admit(lane, 0).unwrap();
        for d in c.poll().unwrap() {
            let ticket = d.ticket;
            let sched = c.wave_schedule(&ticket).unwrap();
            assert_eq!(sched.len(), offsets.len());
            let dp = ticket.dispatch_phase();
            let dispatch_phase_start = dp * PHASE;
            assert!(ticket.dispatched_at() >= dispatch_phase_start);
            for (i, slot) in sched.iter().enumerate() {
                assert_eq!(slot.stage, i);
                assert_eq!(slot.abs_phase, dp + u64::from(offsets[i]));
                assert_eq!(u64::from(slot.phase_in_epoch), (dp % p + u64::from(offsets[i])) % p);
                assert_eq!(slot.due_at - dispatch_phase_start, u64::from(offsets[i]) * PHASE);
                assert_eq!(*slot, c.green_wave().slot(dp, i).unwrap());
                if i > 0 {
                    let prev = sched[i - 1];
                    assert!(slot.due_at >= prev.due_at);
                    assert_eq!(
                        slot.due_at - prev.due_at,
                        u64::from(offsets[i] - offsets[i - 1]) * PHASE
                    );
                }
            }
            // Whole wave fits in one epoch after dispatch.
            assert!(sched.last().unwrap().due_at < dispatch_phase_start + c.timing().epoch_len());
            checked += 1;
        }
    }
    assert!(checked > 20);
}

#[test]
fn stage_check_early_on_time_late_and_unknown() {
    let (mut c, clock) = cop(&config(&[1, 1], 4, 1, &[0, 1]));
    c.admit(LaneId::new(0), 7).unwrap();
    let d = c.poll().unwrap().pop().unwrap();
    let t = d.ticket;

    // Stage 0 is due at the dispatch phase start (time 0).
    let ok = c.stage_check(&t, 0).unwrap();
    assert!(!ok.late);
    // Stage 1 is due one phase later.
    let early = c.stage_check(&t, 1).unwrap_err();
    assert_eq!(early.reason(), TripReason::NotYetDue);
    assert_eq!(early.outcome(), GateOutcome::Retry);
    assert_eq!(early.retry_after(), Some(PHASE));
    clock.set(PHASE);
    assert!(!c.stage_check(&t, 1).unwrap().late);
    clock.set(2 * PHASE);
    assert!(c.stage_check(&t, 1).unwrap().late);

    let unknown = c.stage_check(&t, 2).unwrap_err();
    assert_eq!(unknown.reason(), TripReason::UnknownStage);
    assert_eq!(unknown.outcome(), GateOutcome::TerminalBreach);
    assert_eq!(unknown.resolution(), Resolution::Reject);
    assert_eq!(unknown.retry_after(), None);
}

#[test]
fn unknown_lane_is_terminal_and_changes_nothing() {
    let (mut c, _) = cop(&config(&[1, 1], 4, 1, &[0]));
    let refused = c.admit(LaneId::new(2), 99).unwrap_err();
    assert_eq!(refused.payload, 99);
    assert_eq!(refused.trip.reason(), TripReason::UnknownLane);
    assert_eq!(refused.trip.outcome(), GateOutcome::TerminalBreach);
    assert_eq!(refused.trip.resolution(), Resolution::Reject);
    assert_eq!(c.total_queued(), 0);
    // The id counter did not move: the next admission gets id 0.
    assert_eq!(c.admit(LaneId::new(0), 1).unwrap().id.get(), 0);
}

#[test]
fn clock_regression_halts_until_reset() {
    let (mut c, clock) = cop(&config(&[1, 1], 4, 1, &[0]));
    clock.set(10 * PHASE);
    c.admit(LaneId::new(0), 1).unwrap();
    clock.set(5 * PHASE);
    let trip = c.poll().unwrap_err();
    assert_eq!(trip.reason(), TripReason::ClockRegressed);
    assert_eq!(trip.outcome(), GateOutcome::TerminalBreach);
    assert_eq!(trip.resolution(), Resolution::Halt);
    assert!(c.is_halted());
    // Even with time moving forward again, everything refuses until reset.
    clock.set(20 * PHASE);
    let r = c.admit(LaneId::new(1), 2).unwrap_err();
    assert_eq!(r.trip.reason(), TripReason::Halted);
    assert_eq!(r.trip.resolution(), Resolution::Halt);
    assert_eq!(c.poll().unwrap_err().reason(), TripReason::Halted);
    assert_eq!(c.total_queued(), 1, "halt changed no queue state");
    c.reset();
    assert!(!c.is_halted());
    assert_eq!(c.poll().unwrap().len(), 1);
}

#[test]
fn completion_before_dispatch_is_terminal() {
    let cfg = config(&[1, 1], 4, 1, &[0]);
    let (mut a, clock_a) = cop(&cfg);
    clock_a.set(50 * PHASE);
    a.admit(LaneId::new(0), 1).unwrap();
    let ticket = a.poll().unwrap().pop().unwrap().ticket;
    let (mut b, _) = cop(&cfg);
    let trip = b.complete(&ticket).unwrap_err();
    assert_eq!(trip.reason(), TripReason::CompletionBeforeDispatch);
    assert_eq!(trip.outcome(), GateOutcome::TerminalBreach);
    assert_eq!(trip.position(), GatePosition::Omega);
}

#[test]
fn missed_phases_are_not_made_up() {
    // Lane 1 owns phase 1 only. If nobody polls during phase 1, its work
    // waits for the next epoch rather than leaking into lane 0's phase.
    let (mut c, clock) = cop(&config(&[1, 1], 4, 4, &[0]));
    c.admit(LaneId::new(1), 1).unwrap();
    c.poll().unwrap();
    clock.set(2 * PHASE);
    assert!(c.poll().unwrap().is_empty());
    clock.set(3 * PHASE);
    assert_eq!(c.poll().unwrap().len(), 1);
}

#[test]
fn trip_display_names_op_reason_outcome_and_resolution() {
    let (mut c, _) = cop(&config(&[1], 1, 1, &[0]));
    c.admit(LaneId::new(0), 1).unwrap();
    let r = c.admit(LaneId::new(0), 2).unwrap_err();
    let text = r.trip.to_string();
    assert_eq!(text, "tack-greenwave admit refused: queue_full (retry, reject)");
    // Debug of a refusal does not print the payload.
    let dbg = format!("{r:?}");
    assert!(!dbg.contains("payload"));
}
