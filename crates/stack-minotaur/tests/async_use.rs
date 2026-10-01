//! The Thread and its guards work across `.await` in a spawned task.

// Test code: unwrapping and panicking on an unexpected result is the assertion.
#![allow(clippy::unwrap_used, clippy::panic)]

use tack_minotaur::{Fingerprint, MinotaurConfig, Thread, Trip, TripKind};

async fn tool_call_loop(t: &mut Thread, calls: u64) -> Result<(), Trip> {
    let mut g = t.descend()?;
    for n in 0..calls {
        tokio::task::yield_now().await;
        g.record(Fingerprint::of_bytes(&(n % 2).to_le_bytes()))?;
    }
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn guard_held_across_await_in_spawned_task() {
    let t = Thread::new(MinotaurConfig {
        revisit_allowance: 2,
        ..Default::default()
    })
    .unwrap();
    let (t, r) = tokio::spawn(async move {
        let mut t = t;
        let r = tool_call_loop(&mut t, 100).await;
        (t, r)
    })
    .await
    .unwrap();
    let trip = r.unwrap_err();
    assert_eq!(
        trip.kind,
        TripKind::LoopDetected {
            period: 2,
            detector: tack_minotaur::Detector::Exact
        }
    );
    assert_eq!(t.depth(), 0);
}
