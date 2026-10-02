//! The tokio wrapper, on real time. Short phases keep the test fast.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use stack_greenwave::{Clock, GreenWaveConfig, GreenWaveDriver, LaneId, LaneSpec, TripReason};
use tokio::sync::mpsc;

#[tokio::test]
async fn driver_dispatches_in_phase_and_releases_on_epoch_boundaries() {
    let cfg = GreenWaveConfig {
        phase_len_ns: 2_000_000, // 2 ms
        phases_per_epoch: 3,
        lanes: vec![
            LaneSpec { weight: 2, queue_cap: 8 },
            LaneSpec { weight: 1, queue_cap: 8 },
        ],
        stage_offsets: vec![0, 1],
        max_dispatch_per_phase: 8,
    };
    let driver: GreenWaveDriver<u32> = GreenWaveDriver::new(&cfg).unwrap();
    for i in 0..4 {
        driver.admit(LaneId::new(0), i).await.unwrap();
        driver.admit(LaneId::new(1), 100 + i).await.unwrap();
    }
    let (tx, mut rx) = mpsc::channel(16);
    // Two epochs of phases is enough to drain both lanes.
    let sent = driver.run_phases(&tx, 7).await.unwrap();
    assert_eq!(sent, 8);
    drop(tx);

    let epoch = driver.with_cop(|c| c.timing().epoch_len()).await;
    let mut got = Vec::new();
    while let Some(d) = rx.recv().await {
        let owner = driver.with_cop(|c| c.owner_at(d.ticket.dispatched_at())).await;
        assert_eq!(owner, Some(d.ticket.lane()), "dispatched only in the lane's own phase");
        got.push(d);
    }
    assert_eq!(got.len(), 8);

    // Release one result and check it waited for an epoch boundary.
    let first = got[0].ticket;
    let release = driver.release(&first).await.unwrap();
    assert_eq!(release.release_at % epoch, 0);
    assert!(driver.clock().now() >= release.release_at, "sleep_until did not return early");
}

#[tokio::test]
async fn driver_stops_on_halt_and_when_sink_closes() {
    let cfg = GreenWaveConfig {
        phase_len_ns: 1_000_000,
        phases_per_epoch: 1,
        lanes: vec![LaneSpec { weight: 1, queue_cap: 1 }],
        stage_offsets: vec![0],
        max_dispatch_per_phase: 1,
    };
    let driver: GreenWaveDriver<()> = GreenWaveDriver::new(&cfg).unwrap();

    // Closed sink: returns immediately with nothing sent.
    let (tx, rx) = mpsc::channel(1);
    drop(rx);
    assert_eq!(driver.run(&tx).await.unwrap(), 0);

    // Full queue refuses with RETRY on the real clock too.
    driver.admit(LaneId::new(0), ()).await.unwrap();
    let refused = driver.admit(LaneId::new(0), ()).await.unwrap_err();
    assert_eq!(refused.trip.reason(), TripReason::QueueFull);

    // An operator can inspect and reset through with_cop.
    driver.with_cop(|c| c.reset()).await;
    assert!(!driver.with_cop(|c| c.is_halted()).await);
}
