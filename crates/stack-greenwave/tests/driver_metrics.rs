//! Driver metrics seen through a process-global recorder.
//!
//! `GreenWaveDriver::run_phases` polls on a blocking-pool thread, so a
//! thread-local recorder (`metrics::with_local_recorder`) on the test thread
//! does not see its metrics. This binary installs a global
//! `DebuggingRecorder` instead, and holds exactly one test so no other test
//! adds to the global counters.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use metrics_util::debugging::{DebugValue, DebuggingRecorder};
use metrics_util::MetricKind;
use tack_greenwave::telemetry as t;
use tack_greenwave::{GreenWaveConfig, GreenWaveDriver, LaneId};
use tokio::sync::mpsc;

#[test]
fn driver_keeps_default_grid_and_counts_polls_globally() {
    let recorder = DebuggingRecorder::new();
    let snapshotter = recorder.snapshotter();
    recorder.install().unwrap();

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_time()
        .build()
        .unwrap();
    let (served, worst) = rt.block_on(async {
        let cfg = GreenWaveConfig::default();
        let driver = GreenWaveDriver::<u32>::new(&cfg).unwrap();
        for l in 0..4u16 {
            driver.admit(LaneId::new(l), u32::from(l)).await.unwrap();
        }
        let (tx, mut rx) = mpsc::channel(64);
        driver.run_phases(&tx, 60).await.unwrap();
        drop(tx);
        let mut served = [0usize; 4];
        let mut worst = 0u64;
        while let Some(d) = rx.recv().await {
            served[d.ticket.lane().index()] += 1;
            worst = worst.max(d.ticket.queue_wait());
        }
        (served, worst)
    });

    let mut polls = 0u64;
    let mut missed = 0u64;
    for (ck, _, _, v) in snapshotter.snapshot().into_vec() {
        if let (MetricKind::Counter, DebugValue::Counter(c)) = (ck.kind(), v) {
            if ck.key().name() == t::POLLS_TOTAL {
                polls += c;
            }
            if ck.key().name() == t::PHASES_MISSED_TOTAL {
                missed += c;
            }
        }
    }
    eprintln!("default config, 60 phases: polls {polls}, phases missed {missed}, served {served:?}, worst wait {worst} ns");
    assert_eq!(served, [1, 1, 1, 1]);
    assert_eq!(polls, 60, "the driver's polls were not seen by the global recorder");
    // A loaded CI machine can deschedule the driver thread for a whole 1 ms
    // phase; allow a small number, far below the 70 the async timer lost.
    assert!(missed <= 3, "the driver missed {missed} of 60 phases on an idle runtime");
    assert!(worst <= 8_000_000, "a request waited {worst} ns, past one epoch");
}
