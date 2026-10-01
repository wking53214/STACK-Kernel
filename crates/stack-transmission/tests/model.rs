//! Property test: single-threaded operation sequences against a simple
//! model. A shift succeeds exactly when nothing is in flight, the epoch goes
//! up by one per successful shift, and the in-flight count equals the guards
//! the test holds.

// Test crate: helpers outside #[test] functions may unwrap and panic.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::time::Duration;

use proptest::prelude::*;
use tack_transmission::{Reason, Resolution, Transmission, TransmissionConfig};

#[derive(Debug, Clone)]
enum Op {
    Engage,
    DropOne(usize),
    Shift(u32),
}

fn op() -> impl Strategy<Value = Op> {
    prop_oneof![
        3 => Just(Op::Engage),
        2 => any::<usize>().prop_map(Op::DropOne),
        2 => any::<u32>().prop_map(Op::Shift),
    ]
}

const CAP: usize = 5;

proptest! {
    #[test]
    fn matches_the_model(ops in proptest::collection::vec(op(), 1..200)) {
        let cfg = TransmissionConfig { max_in_flight: CAP, ..TransmissionConfig::default() };
        let t = Transmission::new(0u32, cfg).unwrap();
        let mut held = Vec::new();
        let mut epoch = 0u64;
        let mut current = 0u32;
        for op in ops {
            match op {
                Op::Engage => match t.engage(Duration::ZERO) {
                    Ok(g) => {
                        prop_assert!(held.len() < CAP);
                        prop_assert_eq!(g.epoch(), epoch);
                        prop_assert_eq!(*g, current);
                        held.push(g);
                    }
                    Err(trip) => {
                        prop_assert_eq!(held.len(), CAP);
                        prop_assert_eq!(trip.reason, Reason::InFlightCapacity);
                    }
                },
                Op::DropOne(i) => {
                    if !held.is_empty() {
                        let g = held.swap_remove(i % held.len());
                        drop(g);
                    }
                }
                Op::Shift(cfg) => match t.shift(cfg, Duration::ZERO) {
                    Ok(r) => {
                        prop_assert!(held.is_empty());
                        prop_assert_eq!(r.from_epoch, epoch);
                        epoch += 1;
                        current = cfg;
                        prop_assert_eq!(r.to_epoch, epoch);
                    }
                    Err(e) => {
                        prop_assert!(!held.is_empty());
                        prop_assert_eq!(e.trip().reason, Reason::DrainTimeout);
                        prop_assert_eq!(e.trip().resolution(), Resolution::Rollback);
                        prop_assert_eq!(e.into_config(), cfg);
                    }
                },
            }
            let s = t.status();
            prop_assert_eq!(s.in_flight, held.len());
            prop_assert_eq!(s.epoch, epoch);
            prop_assert!(!s.clutch_pressed);
            prop_assert_eq!(s.waiting_engagers, 0);
            for g in &held {
                prop_assert_eq!(g.epoch(), epoch);
            }
        }
    }
}
