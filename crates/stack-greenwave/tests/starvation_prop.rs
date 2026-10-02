//! Property test: the no-starvation bound over random arrival patterns.
//!
//! For a request with `k` requests ahead of it in its own lane, a lane weight
//! `w` and per-phase budget `M`, dispatch happens less than
//! `ceil((floor(k / M) + 1) / w)` epochs after arrival, as long as the driver
//! polls at every phase start. With `k = 0` the bound is one epoch, whatever
//! the other lanes do.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::collections::HashMap;

use proptest::prelude::*;
use stack_greenwave::{
    Clock, GreenWaveConfig, LaneId, LaneSpec, ManualClock, RequestId, TrafficCop, TripReason,
};

const PHASE: u64 = 1_000;

#[derive(Debug, Clone)]
struct Scenario {
    weights: Vec<u32>,
    caps: Vec<u32>,
    per_phase: u32,
    /// (lane, arrival time)
    arrivals: Vec<(usize, u64)>,
}

fn scenario() -> impl Strategy<Value = Scenario> {
    (1usize..=5)
        .prop_flat_map(|lanes| {
            (
                proptest::collection::vec(1u32..=4, lanes),
                proptest::collection::vec(1u32..=6, lanes),
                1u32..=3,
                proptest::collection::vec((0..lanes, 0u64..60 * PHASE), 0..300),
            )
        })
        .prop_map(|(weights, caps, per_phase, arrivals)| Scenario {
            weights,
            caps,
            per_phase,
            arrivals,
        })
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    #[test]
    fn no_lane_starves(s in scenario()) {
        let cfg = GreenWaveConfig {
            phase_len_ns: PHASE,
            phases_per_epoch: s.weights.iter().sum(),
            lanes: s.weights.iter().zip(&s.caps).map(|(&weight, &queue_cap)| LaneSpec { weight, queue_cap }).collect(),
            stage_offsets: vec![0],
            max_dispatch_per_phase: s.per_phase,
        };
        let clock = ManualClock::new(0);
        let mut cop: TrafficCop<(), _> = TrafficCop::new(&cfg, clock.clone()).unwrap();
        let epoch = cop.timing().epoch_len();

        let mut arrivals = s.arrivals.clone();
        arrivals.sort_by_key(|&(_, t)| t);
        let mut next = 0usize;
        // id -> (lane, arrived_at, position)
        let mut waiting: HashMap<RequestId, (usize, u64, u32)> = HashMap::new();
        let mut admitted = 0usize;
        let mut dispatched = 0usize;

        // Enough phases to drain every queue after the last arrival.
        let max_cap = u64::from(*s.caps.iter().max().unwrap());
        let drain_epochs = max_cap + 2;
        let last_phase = 60 + drain_epochs * u64::from(cfg.phases_per_epoch);

        for phase in 0..=last_phase {
            let start = phase * PHASE;
            // Arrivals up to and including this phase start, in time order.
            while let Some(&(lane, t)) = arrivals.get(next) {
                if t > start { break; }
                clock.set(t);
                let lane_id = LaneId::from_index(lane).unwrap();
                match cop.admit(lane_id, ()) {
                    Ok(a) => {
                        prop_assert_eq!(a.arrived_at, t);
                        waiting.insert(a.id, (lane, t, a.position));
                        admitted += 1;
                    }
                    Err(r) => {
                        prop_assert_eq!(r.trip.reason(), TripReason::QueueFull);
                        let ra = r.trip.retry_after().unwrap();
                        prop_assert!(ra > t);
                        prop_assert_eq!(cop.owner_at(ra), Some(lane_id));
                    }
                }
                let depth = cop.lane_depth(lane_id).unwrap();
                prop_assert!(depth <= s.caps[lane] as usize, "queue over cap");
                next += 1;
            }
            clock.set(start);
            let batch = cop.poll().unwrap();
            prop_assert!(batch.len() <= s.per_phase as usize);
            for d in batch {
                let (lane, arrived, position) = waiting.remove(&d.ticket.id()).unwrap();
                prop_assert_eq!(d.ticket.lane().index(), lane);
                prop_assert_eq!(cop.owner_at(d.ticket.dispatched_at()), Some(d.ticket.lane()));
                let w = u64::from(s.weights[lane]);
                let m = u64::from(s.per_phase);
                let slots_needed = u64::from(position) / m + 1;
                let epochs = slots_needed.div_ceil(w);
                let wait = d.ticket.dispatched_at() - arrived;
                prop_assert!(
                    wait < epochs * epoch,
                    "lane {} position {} waited {} ns, bound {} epochs of {} ns",
                    lane, position, wait, epochs, epoch
                );
                if position == 0 {
                    prop_assert!(wait < epoch, "head-of-line request waited more than one epoch");
                }
                dispatched += 1;
            }
        }
        prop_assert_eq!(next, arrivals.len());
        prop_assert!(waiting.is_empty(), "requests left undispatched: {}", waiting.len());
        prop_assert_eq!(admitted, dispatched);
        prop_assert_eq!(cop.total_queued(), 0);
        prop_assert!(clock.now() >= arrivals.last().map_or(0, |a| a.1));
    }

    #[test]
    fn release_is_always_an_epoch_boundary(phases in 1u32..=64, phase_len in 1_000u64..=1_000_000, completed in any::<u64>()) {
        let cfg = GreenWaveConfig {
            phase_len_ns: phase_len,
            phases_per_epoch: phases,
            lanes: vec![LaneSpec { weight: phases, queue_cap: 1 }],
            stage_offsets: vec![0],
            max_dispatch_per_phase: 1,
        };
        let cop: TrafficCop<(), _> = TrafficCop::new(&cfg, ManualClock::new(0)).unwrap();
        let t = cop.timing();
        match t.release_at(completed) {
            Some(r) => {
                prop_assert!(t.is_epoch_boundary(r));
                prop_assert!(r > completed);
                prop_assert!(r - completed <= t.epoch_len());
            }
            None => prop_assert!(completed / t.epoch_len() + 1 > u64::MAX / t.epoch_len()),
        }
    }
}
