//! Property tests: depth returns to the anchor after any random walk.

// Test code: unwrapping and panicking on an unexpected result is the assertion.
#![allow(clippy::unwrap_used, clippy::panic)]

use proptest::prelude::*;
use stack_minotaur::{Fingerprint, MinotaurConfig, Thread, Walk};

#[derive(Debug, Clone)]
enum Op {
    /// Open a nested guarded scope.
    Descend,
    /// Leave the current scope normally.
    Ascend,
    /// Leave the current scope early, as a `?` would.
    Bail,
    /// Record a transition into state n (small range, so revisits happen).
    Record(u8),
    /// Rewind to the anchor. Only the root holder of the Thread can rewind,
    /// so this unwinds every scope and the driver rewinds.
    Rewind,
}

fn op() -> impl Strategy<Value = Op> {
    prop_oneof![
        4 => Just(Op::Descend),
        3 => Just(Op::Ascend),
        1 => Just(Op::Bail),
        6 => (0u8..24).prop_map(Op::Record),
        1 => Just(Op::Rewind),
    ]
}

#[derive(Debug, PartialEq, Eq)]
enum Exit {
    /// Left the scope early, as a `?` would.
    Early,
    /// Unwinding to the root so the driver can rewind.
    Rewind,
}

/// Walk the ops; each Descend recurses into a new scope holding a guard.
/// Checks that depth equals the number of live guards issued since the last
/// rewind or trip, and that a stale guard (one issued before a trip) refuses
/// work without changing the depth.
fn walk(
    t: &mut dyn Walk,
    ops: &mut std::slice::Iter<'_, Op>,
    live_since_rewind: u32,
) -> Result<(), Exit> {
    let mut live = live_since_rewind;
    while let Some(op) = ops.next() {
        match op {
            Op::Descend => {
                let mut exit = None;
                match t.descend() {
                    Ok(mut g) => {
                        assert_eq!(g.depth(), live + 1);
                        exit = walk(&mut g, ops, live + 1).err();
                        // A trip inside the scope makes this guard stale
                        // and leaves depth at 0.
                        if g.is_stale() {
                            live = 0;
                        }
                    }
                    Err(_) => live = 0,
                }
                assert_eq!(t.thread().depth(), live);
                if let Some(e) = exit {
                    return Err(e);
                }
            }
            Op::Ascend => return Ok(()),
            Op::Bail => return Err(Exit::Early),
            Op::Record(n) => {
                if t.record(Fingerprint::of_bytes(&[*n])).is_err() {
                    live = 0;
                }
                assert_eq!(t.thread().depth(), live);
            }
            Op::Rewind => return Err(Exit::Rewind),
        }
    }
    Ok(())
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(512))]

    #[test]
    fn depth_returns_to_zero_after_all_guards_drop(
        ops in proptest::collection::vec(op(), 0..400),
        max_depth in 1u32..12,
        max_steps in 1u64..200,
        max_distinct in 1usize..16,
        allowance in 0u32..4,
    ) {
        let cfg = MinotaurConfig {
            max_depth,
            max_steps,
            max_distinct_states: max_distinct,
            revisit_allowance: allowance,
            max_untracked_transitions: 50,
            max_cycle_period: 8,
            breadcrumb_len: 8,
            max_trips_before_halt: 1_000,
        };
        let mut t = Thread::new(cfg).unwrap();
        let mut it = ops.iter();
        // Keep re-entering at the anchor until every op is consumed.
        while it.len() > 0 {
            if walk(&mut t, &mut it, 0) == Err(Exit::Rewind) {
                t.rewind();
            }
            prop_assert_eq!(t.depth(), 0);
        }
        prop_assert_eq!(t.depth(), 0);
        prop_assert!(t.tracked_states() <= max_distinct);
        prop_assert!(t.breadcrumbs().len() <= 8);
    }

    #[test]
    fn periodic_walk_is_always_caught_with_its_period(
        period in 2u64..40,
        tail in 0u64..200,
        max_distinct in 1usize..64,
        allowance in 0u32..4,
    ) {
        let cfg = MinotaurConfig {
            max_steps: 1_000_000,
            max_distinct_states: max_distinct,
            revisit_allowance: allowance,
            max_untracked_transitions: 1_000_000,
            max_cycle_period: 64,
            ..Default::default()
        };
        let mut t = Thread::new(cfg).unwrap();
        let seq = (0..tail).map(|i| 1_000_000 + i).chain((0..100_000u64).map(|i| i % period));
        let mut found = None;
        for s in seq {
            if let Err(e) = t.record(Fingerprint::of_bytes(&s.to_le_bytes())) {
                found = Some(e);
                break;
            }
        }
        let trip = found.unwrap();
        prop_assert_eq!(trip.period(), Some(period));
    }
}
