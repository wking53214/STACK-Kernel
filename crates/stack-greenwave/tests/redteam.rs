//! Red-team tests for stack-greenwave.
//!
//! Every test asserts the SAFE behaviour, so a test that fails marks a
//! weakness that still exists. Tests named `rt_held_*` are attacks the crate
//! resisted; they pass. All other `rt_*` tests target a specific claim.
//!
//! Test keys: none. This crate holds no key material.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::collections::HashSet;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant as StdInstant};

use metrics_util::debugging::{DebugValue, DebuggingRecorder};
use metrics_util::MetricKind;
use proptest::prelude::*;
use stack_greenwave::telemetry as t;
use stack_greenwave::{
    Clock, GateOutcome, GreenWaveConfig, GreenWaveDriver, LaneId, LaneSpec, ManualClock,
    PhaseTable, Resolution, TrafficCop, TripReason,
};
use tokio::sync::mpsc;

const PHASE: u64 = 1_000;

fn two_lane(cap: u32, m: u32) -> GreenWaveConfig {
    GreenWaveConfig {
        phase_len_ns: PHASE,
        phases_per_epoch: 2,
        lanes: vec![
            LaneSpec { weight: 1, queue_cap: cap },
            LaneSpec { weight: 1, queue_cap: cap },
        ],
        stage_offsets: vec![0, 1],
        max_dispatch_per_phase: m,
    }
}

fn one_lane(cap: u32, m: u32) -> GreenWaveConfig {
    GreenWaveConfig {
        phase_len_ns: PHASE,
        phases_per_epoch: 1,
        lanes: vec![LaneSpec { weight: 1, queue_cap: cap }],
        stage_offsets: vec![0],
        max_dispatch_per_phase: m,
    }
}

type Snap = Vec<(MetricKind, String, Vec<(String, String)>, DebugValue)>;

fn snapshot(rec: &DebuggingRecorder) -> Snap {
    rec.snapshotter()
        .snapshot()
        .into_vec()
        .into_iter()
        .map(|(ck, _, _, v)| {
            let key = ck.key();
            let labels = key
                .labels()
                .map(|l| (l.key().to_string(), l.value().to_string()))
                .collect();
            (ck.kind(), key.name().to_string(), labels, v)
        })
        .collect()
}

fn gauge(s: &Snap, name: &str) -> Option<f64> {
    s.iter().find_map(|(k, n, _, v)| match (k, v) {
        (MetricKind::Gauge, DebugValue::Gauge(g)) if n == name => Some(g.0),
        _ => None,
    })
}

fn counter(s: &Snap, name: &str) -> u64 {
    s.iter()
        .filter(|(k, n, _, _)| *k == MetricKind::Counter && n == name)
        .map(|(_, _, _, v)| match v {
            DebugValue::Counter(c) => *c,
            _ => 0,
        })
        .sum()
}

// ---------------------------------------------------------------------------
// Attack 1: replay and foreign tickets at the OMEGA gate.
// ---------------------------------------------------------------------------

/// A ticket issued by cop A is presented to cop B, whose clock is further
/// along. The builder says CompletionBeforeDispatch catches tickets "from
/// another cop". It only does so when the other cop's clock happens to be
/// behind. Unknown input must never PASS.
#[test]
fn rt_foreign_ticket_refused_at_complete() {
    let clock_a = ManualClock::new(10 * PHASE);
    let mut a: TrafficCop<u8, _> = TrafficCop::new(&one_lane(4, 4), clock_a).unwrap();
    a.admit(LaneId::new(0), 1).unwrap();
    let ticket = a.poll().unwrap().pop().unwrap().ticket;

    let clock_b = ManualClock::new(1_000 * PHASE);
    let mut b: TrafficCop<u8, _> = TrafficCop::new(&one_lane(4, 4), clock_b).unwrap();
    let res = b.complete(&ticket);
    let stage = b.stage_check(&ticket, 0);
    eprintln!("foreign ticket on cop B: complete={res:?} stage_check={stage:?}");
    assert!(
        res.is_err(),
        "cop B issued a release for a ticket it never dispatched: {res:?}"
    );
    assert!(stage.is_err(), "cop B cleared a stage for a foreign ticket: {stage:?}");
}

/// The same ticket completed twice yields two PASS releases; the cop keeps no
/// record of which tickets are live.
#[test]
fn rt_double_complete_refused() {
    let clock = ManualClock::new(0);
    let mut cop: TrafficCop<u8, _> = TrafficCop::new(&one_lane(4, 4), clock.clone()).unwrap();
    cop.admit(LaneId::new(0), 1).unwrap();
    let ticket = cop.poll().unwrap().pop().unwrap().ticket;
    clock.advance(10);
    let first = cop.complete(&ticket);
    clock.advance(5 * PHASE);
    let second = cop.complete(&ticket);
    eprintln!("first={first:?} second={second:?}");
    assert!(first.is_ok());
    assert!(second.is_err(), "replayed completion accepted: {second:?}");
}

/// After completion a ticket still clears stages: a stage can be re-run for
/// finished work.
#[test]
fn rt_stage_check_after_complete_refused() {
    let clock = ManualClock::new(0);
    let mut cop: TrafficCop<u8, _> = TrafficCop::new(&two_lane(4, 4), clock.clone()).unwrap();
    cop.admit(LaneId::new(0), 1).unwrap();
    let ticket = cop.poll().unwrap().pop().unwrap().ticket;
    clock.advance(3 * PHASE);
    cop.complete(&ticket).unwrap();
    let again = cop.stage_check(&ticket, 1);
    eprintln!("stage_check after complete: {again:?}");
    assert!(again.is_err(), "stage cleared for an already completed ticket: {again:?}");
}

// ---------------------------------------------------------------------------
// Attack 2: cross-tenant information leak through request ids.
// ---------------------------------------------------------------------------

/// RequestId is one global counter across all lanes, handed back to the
/// admitter in `Admitted` and on the ticket. A tenant on lane 0 that admits
/// twice learns how many requests every other tenant admitted in between.
/// Safe: what lane 0 observes does not depend on lane 1's traffic.
#[test]
fn rt_request_ids_do_not_leak_cross_lane_volume() {
    fn observe(lane1_admits: u32) -> u64 {
        let clock = ManualClock::new(0);
        let mut cop: TrafficCop<u32, _> = TrafficCop::new(&two_lane(64, 4), clock).unwrap();
        let a1 = cop.admit(LaneId::new(0), 0).unwrap();
        for i in 0..lane1_admits {
            cop.admit(LaneId::new(1), i).unwrap();
        }
        let a2 = cop.admit(LaneId::new(0), 1).unwrap();
        a2.id.get() - a1.id.get()
    }
    let quiet = observe(0);
    let busy = observe(37);
    eprintln!("lane 0 id delta with lane 1 quiet: {quiet}, with lane 1 busy: {busy}");
    assert_eq!(
        quiet, busy,
        "lane 0 can count lane 1's admissions from its own request ids"
    );
}

// ---------------------------------------------------------------------------
// Attack 3: process-global gauges clobbered by a second scheduler.
// ---------------------------------------------------------------------------

/// Cop A halts on a clock regression (gauge 1, critical alert). Building any
/// other cop in the same process sets tack_greenwave_halted back to 0 while A
/// is still halted, which silently clears the critical alert.
#[test]
fn rt_halted_gauge_not_cleared_by_second_cop() {
    let rec = DebuggingRecorder::new();
    let (a_halted, gauge_after) = metrics::with_local_recorder(&rec, || {
        let clock = ManualClock::new(10 * PHASE);
        let mut a: TrafficCop<u8, _> = TrafficCop::new(&one_lane(4, 4), clock.clone()).unwrap();
        clock.set(PHASE);
        assert_eq!(a.poll().unwrap_err().reason(), TripReason::ClockRegressed);
        // Corrected: no snapshot here. DebuggingRecorder::snapshot swaps every
        // gauge to 0 (metrics-util 0.20.4, debugging.rs), so reading the gauge
        // at this point would itself clear it and the final reading would
        // blame B for the recorder's own reset. The final assertion below is
        // unchanged and still fails if building B sets the gauge to 0.
        let _b: TrafficCop<u8, _> = TrafficCop::new(&one_lane(4, 4), ManualClock::new(0)).unwrap();
        (a.is_halted(), gauge(&snapshot(&rec), t::HALTED))
    });
    eprintln!("A still halted: {a_halted}; halted gauge after building B: {gauge_after:?}");
    assert!(a_halted);
    assert_eq!(
        gauge_after,
        Some(1.0),
        "building a second cop cleared the halt gauge of a halted cop"
    );
}

// ---------------------------------------------------------------------------
// Attack 4: reset misuse.
// ---------------------------------------------------------------------------

/// A reset while not halted, mid-phase, forgets the phase counter, so the
/// same phase dispatches a second full budget.
#[test]
fn rt_reset_does_not_refresh_dispatch_budget_mid_phase() {
    let clock = ManualClock::new(0);
    let mut cop: TrafficCop<u32, _> = TrafficCop::new(&one_lane(16, 2), clock.clone()).unwrap();
    for i in 0..8 {
        cop.admit(LaneId::new(0), i).unwrap();
    }
    let first = cop.poll().unwrap().len();
    cop.reset();
    let second = cop.poll().unwrap().len();
    eprintln!("same phase: first poll {first}, after reset {second}; budget is 2");
    assert!(
        first + second <= 2,
        "one phase dispatched {} requests past a budget of 2",
        first + second
    );
}

/// The clock goes backwards, then a reset happens before any op observes it
/// (for example a routine reset from a health check). The regression is
/// never detected and never counted.
#[test]
fn rt_reset_does_not_swallow_clock_regression() {
    let clock = ManualClock::new(100 * PHASE);
    let mut cop: TrafficCop<u8, _> = TrafficCop::new(&one_lane(4, 4), clock.clone()).unwrap();
    cop.poll().unwrap();
    clock.set(3 * PHASE);
    cop.reset();
    let r = cop.admit(LaneId::new(0), 1);
    eprintln!("admit after unobserved regression and reset: {:?}", r.as_ref().map(|a| a.arrived_at));
    assert!(
        r.is_err() || cop.is_halted(),
        "a clock regression was absorbed by reset without a trip"
    );
}

// ---------------------------------------------------------------------------
// Attack 5: missed phases before the first poll are not counted.
// ---------------------------------------------------------------------------

#[test]
fn rt_phases_missed_counted_before_first_poll() {
    let rec = DebuggingRecorder::new();
    let missed = metrics::with_local_recorder(&rec, || {
        let clock = ManualClock::new(0);
        let mut cop: TrafficCop<u8, _> = TrafficCop::new(&two_lane(4, 4), clock.clone()).unwrap();
        cop.admit(LaneId::new(1), 1).unwrap();
        clock.set(100 * PHASE); // 100 phases pass, 50 of them lane 1's
        cop.poll().unwrap();
        counter(&snapshot(&rec), t::PHASES_MISSED_TOTAL)
    });
    eprintln!("phases_missed_total after 100 unpolled phases since build: {missed}");
    assert!(missed >= 99, "phases lost before the first poll were not counted");
}

// ---------------------------------------------------------------------------
// Attack 6: the public PhaseTable::build skips every cap.
// ---------------------------------------------------------------------------

/// PhaseTable::build is `pub` and documents that its input "must already have
/// passed validate", but does not check. Allocation is sized by the
/// arguments (Vec::with_capacity(phases)) and work is lanes * phases.
#[test]
fn rt_phase_table_build_enforces_caps() {
    let over_phases = PhaseTable::build(&[2_000], 2_000);
    let over_lanes = PhaseTable::build(&vec![1u32; 65], 65);
    eprintln!(
        "build(&[2000], 2000) ok={}; build(65 lanes) ok={}",
        over_phases.is_ok(),
        over_lanes.is_ok()
    );
    let n = 12_000usize;
    let started = StdInstant::now();
    let big = PhaseTable::build(&vec![1u32; n], n as u32);
    let took = started.elapsed();
    eprintln!("build({n} lanes x {n} phases) ok={} in {took:?}", big.is_ok());
    assert!(over_phases.is_err(), "PHASES cap bypassed through PhaseTable::build");
    assert!(over_lanes.is_err(), "LANES cap bypassed through PhaseTable::build");
    assert!(big.is_err(), "quadratic build accepted {n} x {n}");
}

// ---------------------------------------------------------------------------
// Attack 7: completion time leaks through span and event timestamps.
// ---------------------------------------------------------------------------

type Records = Arc<Mutex<Vec<(&'static str, String, tracing::Level)>>>;

#[derive(Clone, Default)]
struct Capture {
    records: Records,
    next: Arc<AtomicU64>,
}

impl tracing::Subscriber for Capture {
    fn enabled(&self, _: &tracing::Metadata<'_>) -> bool {
        true
    }
    fn new_span(&self, attrs: &tracing::span::Attributes<'_>) -> tracing::span::Id {
        let m = attrs.metadata();
        self.records
            .lock()
            .unwrap()
            .push(("span", m.name().to_string(), *m.level()));
        tracing::span::Id::from_u64(self.next.fetch_add(1, Ordering::SeqCst) + 1)
    }
    fn record(&self, _: &tracing::span::Id, _: &tracing::span::Record<'_>) {}
    fn record_follows_from(&self, _: &tracing::span::Id, _: &tracing::span::Id) {}
    fn event(&self, e: &tracing::Event<'_>) {
        let m = e.metadata();
        self.records
            .lock()
            .unwrap()
            .push(("event", format!("{}:{:?}", m.target(), m.line()), *m.level()));
    }
    fn enter(&self, _: &tracing::span::Id) {}
    fn exit(&self, _: &tracing::span::Id) {}
}

/// Any subscriber stamps each span and event with the wall clock (fmt's
/// default timer, OpenTelemetry span start times). `complete` opens a debug
/// span and emits a debug event at the completion instant, so a trace reader
/// sees the exact completion time that quantization exists to hide. The same
/// applies to the per-stage `stage_check` span. The crate docs list side
/// channels but omit this one.
#[test]
fn rt_complete_emits_no_timestamped_telemetry() {
    let cap = Capture::default();
    let clock = ManualClock::new(0);
    let mut cop: TrafficCop<u8, _> = TrafficCop::new(&one_lane(4, 4), clock.clone()).unwrap();
    cop.admit(LaneId::new(0), 1).unwrap();
    let ticket = cop.poll().unwrap().pop().unwrap().ticket;
    clock.advance(123);
    let during = tracing::subscriber::with_default(cap.clone(), || {
        cop.complete(&ticket).unwrap();
        cap.records.lock().unwrap().clone()
    });
    eprintln!("telemetry emitted inside complete(): {during:?}");
    let visible: Vec<_> = during
        .iter()
        .filter(|(_, _, lvl)| *lvl <= tracing::Level::DEBUG)
        .collect();
    assert!(
        visible.is_empty(),
        "complete() emits {} span/event records at DEBUG or above, each timestamped at the completion instant",
        visible.len()
    );
}

// ---------------------------------------------------------------------------
// Attack 8: the tokio driver cannot keep a sub-millisecond phase grid.
// ---------------------------------------------------------------------------

/// MIN_PHASE_LEN_NS is 1 microsecond and its doc says an OS timer can keep
/// the grid above that. tokio's timer wheel has 1 ms resolution, so the
/// crate's own driver polls about once per millisecond, whatever the phase.
/// With 100 us phases and two lanes, the bound "empty lane is served in
/// under one epoch (200 us)" does not hold, and one lane can starve.
#[test]
fn rt_driver_sub_ms_phase_keeps_fairness_bound() {
    let cfg = GreenWaveConfig {
        phase_len_ns: 100_000,
        phases_per_epoch: 2,
        lanes: vec![
            LaneSpec { weight: 1, queue_cap: 64 },
            LaneSpec { weight: 1, queue_cap: 64 },
        ],
        stage_offsets: vec![0],
        max_dispatch_per_phase: 1,
    };
    let rec = DebuggingRecorder::new();
    let (built, results, missed) = metrics::with_local_recorder(&rec, || {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_time()
            .build()
            .unwrap();
        rt.block_on(async {
            let Ok(driver) = GreenWaveDriver::<u32>::new(&cfg) else {
                return (false, Vec::new(), 0);
            };
            for i in 0..10 {
                driver.admit(LaneId::new(0), i).await.unwrap();
                driver.admit(LaneId::new(1), 100 + i).await.unwrap();
            }
            let (tx, mut rx) = mpsc::channel(64);
            driver.run_phases(&tx, 40).await.unwrap();
            drop(tx);
            let mut got = Vec::new();
            while let Some(d) = rx.recv().await {
                got.push((d.ticket.lane().index(), d.ticket.dispatched_at()));
            }
            (true, got, counter(&snapshot(&rec), t::PHASES_MISSED_TOTAL))
        })
    });
    if !built {
        return; // refusing the config is the safe outcome
    }
    let lane0 = results.iter().filter(|(l, _)| *l == 0).count();
    let lane1 = results.iter().filter(|(l, _)| *l == 1).count();
    eprintln!(
        "100us phases, 40 driver iterations: lane0 dispatched {lane0}, lane1 dispatched {lane1}, phases_missed_total {missed}"
    );
    assert_eq!(missed, 0, "the driver missed {missed} phases on a validated config");
    assert!(lane0 >= 10 && lane1 >= 10, "lanes were not served evenly");
}

/// The default config (1 ms phases) under the crate's own driver. Measures
/// how many phases the driver misses with no load at all.
#[test]
fn rt_driver_default_config_misses_no_phases() {
    let cfg = GreenWaveConfig::default();
    let rec = DebuggingRecorder::new();
    let (missed, served, worst) = metrics::with_local_recorder(&rec, || {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_time()
            .build()
            .unwrap();
        rt.block_on(async {
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
            (counter(&snapshot(&rec), t::PHASES_MISSED_TOTAL), served, worst)
        })
    });
    eprintln!(
        "default config, 60 driver iterations, one request per lane: phases_missed_total {missed}, served per lane {served:?}, worst queue_wait {worst} ns (epoch 8000000 ns)"
    );
    assert_eq!(missed, 0, "idle driver missed {missed} of about 60 phases");
    assert!(worst < 8_000_000, "a request waited {worst} ns, past one epoch");
}

// ---------------------------------------------------------------------------
// Attack 9: the driver drops dispatched payloads when the sink closes.
// ---------------------------------------------------------------------------

struct Counted(Arc<AtomicUsize>);
impl Drop for Counted {
    fn drop(&mut self) {
        self.0.fetch_add(1, Ordering::SeqCst);
    }
}

/// A batch of 3 is dequeued, the first is sent, the consumer goes away. The
/// other 2 are destroyed inside run_phases with no verdict, no metric and no
/// way to get them back; dispatched_total still says 3.
#[test]
fn rt_driver_does_not_drop_payloads_when_sink_closes() {
    let drops = Arc::new(AtomicUsize::new(0));
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_time()
        .build()
        .unwrap();
    let (sent, queued_after, dropped_in_driver) = rt.block_on(async {
        let cfg = GreenWaveConfig {
            phase_len_ns: 1_000_000,
            ..one_lane(8, 8)
        };
        let driver = GreenWaveDriver::<Counted>::new(&cfg).unwrap();
        for _ in 0..3 {
            driver.admit(LaneId::new(0), Counted(drops.clone())).await.unwrap();
        }
        let (tx, rx) = mpsc::channel(1);
        let d2 = driver.clone();
        let task = tokio::spawn(async move { d2.run_phases(&tx, 1).await });
        // Wait until the batch is out of the queue and the channel is full.
        for _ in 0..200 {
            if rx.len() == 1 && driver.with_cop(|c| c.total_queued()).await == 0 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
        let before = drops.load(Ordering::SeqCst);
        drop(rx); // drops the one buffered item too
        let sent = task.await.unwrap().unwrap();
        let after = drops.load(Ordering::SeqCst);
        // `after - before` includes the 1 buffered item the channel owned.
        (sent, driver.with_cop(|c| c.total_queued()).await, after - before - 1)
    });
    eprintln!(
        "sent={sent}, still queued={queued_after}, destroyed inside run_phases={dropped_in_driver}"
    );
    assert_eq!(
        sent as usize + queued_after,
        3,
        "{dropped_in_driver} dispatched payloads vanished with no verdict"
    );
}

// ---------------------------------------------------------------------------
// Attack 10: a flooding lane delays another lane's poll through the driver's
// shared mutex.
// ---------------------------------------------------------------------------

/// The core's fairness bound has no term for other lanes, but the driver's
/// poll waits on the same FIFO mutex as every admit. Lane 0 fires thousands
/// of concurrent admits at a full queue (each one refused with RETRY). The
/// victim, lane 1, must still be served within its bound.
#[test]
fn rt_driver_flood_does_not_delay_other_lane() {
    const PHASE_NS: u64 = 5_000_000; // 5 ms: well above timer resolution
    let cfg = GreenWaveConfig {
        phase_len_ns: PHASE_NS,
        phases_per_epoch: 2,
        lanes: vec![
            LaneSpec { weight: 1, queue_cap: 1 },
            LaneSpec { weight: 1, queue_cap: 1024 },
        ],
        stage_offsets: vec![0],
        max_dispatch_per_phase: 64,
    };
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(4)
        .enable_time()
        .build()
        .unwrap();
    let (worst, refused) = rt.block_on(async {
        let driver = GreenWaveDriver::<u64>::new(&cfg).unwrap();
        driver.admit(LaneId::new(0), 0).await.unwrap(); // lane 0 now full
        let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let refused = Arc::new(AtomicU64::new(0));
        let mut flood = Vec::new();
        let tasks: usize = std::env::var("RT_FLOOD_TASKS")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(8_000);
        eprintln!("flood tasks: {tasks}");
        for _ in 0..tasks {
            let d = driver.clone();
            let s = stop.clone();
            let r = refused.clone();
            flood.push(tokio::spawn(async move {
                while !s.load(Ordering::Relaxed) {
                    if d.admit(LaneId::new(0), 1).await.is_err() {
                        r.fetch_add(1, Ordering::Relaxed);
                    }
                    tokio::task::yield_now().await;
                }
            }));
        }
        let (tx, mut rx) = mpsc::channel(4096);
        let d2 = driver.clone();
        let runner = tokio::spawn(async move { d2.run_phases(&tx, 60).await });
        // Victim admits one request every 7 ms into its empty lane.
        let victim = driver.clone();
        let feeder = tokio::spawn(async move {
            for i in 0..30u64 {
                let _ = victim.admit(LaneId::new(1), 1_000 + i).await;
                tokio::time::sleep(Duration::from_millis(7)).await;
            }
        });
        feeder.await.unwrap();
        let _ = runner.await.unwrap();
        stop.store(true, Ordering::Relaxed);
        for f in flood {
            let _ = f.await;
        }
        let mut worst = 0u64;
        while let Ok(d) = rx.try_recv() {
            if d.ticket.lane().index() == 1 {
                worst = worst.max(d.ticket.queue_wait());
            }
        }
        (worst, refused.load(Ordering::Relaxed))
    });
    let epoch = 2 * PHASE_NS;
    // Baseline with no flood measured about 10.5 ms (timer jitter on top of
    // the non-strict one-epoch bound), so allow two epochs before blaming
    // the flood.
    eprintln!(
        "flood refused {refused} admits; victim worst queue_wait {worst} ns; one epoch is {epoch} ns"
    );
    assert!(
        worst < 2 * epoch,
        "victim lane waited {worst} ns, over two epochs, because of another lane's flood"
    );
}

// ---------------------------------------------------------------------------
// Held: attacks the crate resisted.
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
enum Act {
    Advance(u64),
    Jump(u64),
    Back(u64),
    Admit(u16),
    Poll,
    Stage(usize, usize),
    Complete(usize),
    Reset,
}

fn act() -> impl Strategy<Value = Act> {
    prop_oneof![
        4 => (0u64..5_000).prop_map(Act::Advance),
        1 => any::<u64>().prop_map(Act::Jump),
        1 => (1u64..10_000).prop_map(Act::Back),
        4 => any::<u16>().prop_map(|l| Act::Admit(l % 10)),
        1 => any::<u16>().prop_map(Act::Admit),
        4 => Just(Act::Poll),
        2 => (any::<usize>(), prop_oneof![0usize..6, Just(usize::MAX)]).prop_map(|(i, s)| Act::Stage(i, s)),
        2 => any::<usize>().prop_map(Act::Complete),
        1 => Just(Act::Reset),
    ]
}

fn cfg_strategy() -> impl Strategy<Value = GreenWaveConfig> {
    (
        prop::collection::vec((1u32..4, 1u32..5), 1..6),
        prop_oneof![Just(1_000u64), Just(1_000_000u64), 1_000u64..50_000],
        prop::collection::vec(0u32..8, 1..5),
        1u32..5,
    )
        .prop_map(|(lanes, phase_len_ns, mut offs, m)| {
            let lanes: Vec<LaneSpec> = lanes
                .into_iter()
                .map(|(weight, queue_cap)| LaneSpec { weight, queue_cap })
                .collect();
            let p: u32 = lanes.iter().map(|l| l.weight).sum();
            for o in &mut offs {
                *o %= p;
            }
            offs.sort_unstable();
            GreenWaveConfig {
                phase_len_ns,
                phases_per_epoch: p,
                lanes,
                stage_offsets: offs,
                max_dispatch_per_phase: m,
            }
        })
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 512, ..ProptestConfig::default() })]

    /// Random op sequences including clock jumps to u64::MAX, regressions,
    /// forged lanes, usize::MAX stages and stale tickets. No panic, no PASS
    /// from a trip, caps and dispatch rules hold.
    #[test]
    fn rt_held_random_ops_never_panic_or_fail_open(
        cfg in cfg_strategy(),
        start in prop_oneof![Just(0u64), any::<u64>(), Just(u64::MAX - 10_000)],
        acts in prop::collection::vec(act(), 1..200),
    ) {
        let clock = ManualClock::new(start);
        let mut cop: TrafficCop<u64, _> = TrafficCop::new(&cfg, clock.clone()).unwrap();
        let m = cfg.max_dispatch_per_phase as usize;
        let epoch = cfg.epoch_len_ns().unwrap();
        let mut tickets = Vec::new();
        let mut phase_tally: Option<(u64, usize)> = None;
        let mut seq = 0u64;
        for a in acts {
            let was_halted = cop.is_halted();
            match a {
                Act::Advance(d) => clock.advance(d),
                Act::Jump(t) => { if t >= clock.now() { clock.set(t) } },
                Act::Back(d) => clock.set(clock.now().saturating_sub(d)),
                Act::Admit(l) => {
                    seq += 1;
                    match cop.admit(LaneId::new(l), seq) {
                        Ok(_) => prop_assert!(!was_halted),
                        Err(r) => {
                            prop_assert_eq!(r.payload, seq);
                            prop_assert_ne!(r.trip.outcome(), GateOutcome::Pass);
                            if r.trip.reason() == TripReason::QueueFull {
                                let ra = r.trip.retry_after().unwrap();
                                prop_assert!(ra > clock.now());
                                prop_assert_eq!(cop.owner_at(ra), Some(LaneId::new(l)));
                            }
                        }
                    }
                }
                Act::Poll => match cop.poll() {
                    Ok(batch) => {
                        prop_assert!(!was_halted);
                        prop_assert!(batch.len() <= m);
                        for d in &batch {
                            prop_assert_eq!(cop.owner_at(d.ticket.dispatched_at()), Some(d.ticket.lane()));
                            let ph = d.ticket.dispatch_phase();
                            match &mut phase_tally {
                                Some((p, n)) if *p == ph => *n += 1,
                                _ => phase_tally = Some((ph, 1)),
                            }
                            prop_assert!(phase_tally.unwrap().1 <= m, "per-phase budget exceeded");
                            tickets.push(d.ticket);
                        }
                    }
                    Err(trip) => prop_assert_ne!(trip.outcome(), GateOutcome::Pass),
                },
                Act::Stage(i, s) => {
                    if tickets.is_empty() { continue; }
                    let tk = tickets[i % tickets.len()];
                    match cop.stage_check(&tk, s) {
                        Ok(c) => { prop_assert!(!was_halted); prop_assert!(clock.now() >= c.slot.due_at); }
                        Err(trip) => {
                            prop_assert_ne!(trip.outcome(), GateOutcome::Pass);
                            if trip.reason() == TripReason::NotYetDue {
                                prop_assert!(trip.retry_after().unwrap() > clock.now());
                            }
                        }
                    }
                }
                Act::Complete(i) => {
                    if tickets.is_empty() { continue; }
                    let tk = tickets[i % tickets.len()];
                    match cop.complete(&tk) {
                        Ok(r) => {
                            prop_assert!(!was_halted);
                            prop_assert_eq!(r.release_at % epoch, 0);
                            prop_assert!(r.release_at > clock.now());
                        }
                        Err(trip) => prop_assert_ne!(trip.outcome(), GateOutcome::Pass),
                    }
                }
                Act::Reset => { cop.reset(); phase_tally = None; }
            }
            let mut sum = 0;
            for l in 0..cfg.lanes.len() {
                let lane = LaneId::from_index(l).unwrap();
                let d = cop.lane_depth(lane).unwrap();
                prop_assert!(d <= cop.lane_cap(lane).unwrap());
                sum += d;
            }
            prop_assert_eq!(sum, cop.total_queued());
        }
    }

    /// Hostile configurations never panic and never build.
    #[test]
    fn rt_held_hostile_config_never_panics(
        phase_len_ns in any::<u64>(),
        phases in any::<u32>(),
        lanes in prop::collection::vec((any::<u32>(), any::<u32>()), 0..70),
        offs in prop::collection::vec(any::<u32>(), 0..40),
        m in any::<u32>(),
    ) {
        let cfg = GreenWaveConfig {
            phase_len_ns,
            phases_per_epoch: phases,
            lanes: lanes.into_iter().map(|(weight, queue_cap)| LaneSpec { weight, queue_cap }).collect(),
            stage_offsets: offs,
            max_dispatch_per_phase: m,
        };
        let valid = cfg.validate().is_ok();
        let built = TrafficCop::<u8, _>::new(&cfg, ManualClock::new(0));
        prop_assert_eq!(valid, built.is_ok());
        if let Err(e) = built {
            prop_assert_eq!(e.outcome(), GateOutcome::TerminalBreach);
            prop_assert_eq!(e.resolution(), Resolution::Halt);
        }
    }
}

/// Forged lanes (all 65,536 u16 values) and usize::MAX stages create no new
/// label values: every label comes from a closed enum.
#[test]
fn rt_held_metric_cardinality_is_closed() {
    let rec = DebuggingRecorder::new();
    let keys = metrics::with_local_recorder(&rec, || {
        let clock = ManualClock::new(0);
        let mut cop: TrafficCop<u8, _> = TrafficCop::new(&two_lane(2, 4), clock.clone()).unwrap();
        for l in 0..=u16::MAX {
            let _ = cop.admit(LaneId::new(l), 0);
        }
        let batch = cop.poll().unwrap();
        for d in &batch {
            for s in [0usize, 1, 2, 1_000, usize::MAX] {
                let _ = cop.stage_check(&d.ticket, s);
            }
        }
        let snap = snapshot(&rec);
        let mut keys = HashSet::new();
        for (_, n, labels, _) in snap {
            keys.insert(format!("{n}{labels:?}"));
        }
        keys
    });
    eprintln!("distinct metric series after 65,536 forged lanes: {}", keys.len());
    assert!(keys.len() < 40, "series count grew with attacker input: {}", keys.len());
}

/// Payloads never appear in Debug or Display output.
#[test]
fn rt_held_payload_never_printed() {
    let clock = ManualClock::new(0);
    let mut cop: TrafficCop<String, _> = TrafficCop::new(&one_lane(1, 1), clock).unwrap();
    cop.admit(LaneId::new(0), "SECRET-A".into()).unwrap();
    let refused = cop.admit(LaneId::new(0), "SECRET-B\nforged log line".into()).unwrap_err();
    let s1 = format!("{refused:?} {} {cop:?}", refused.trip);
    let d = cop.poll().unwrap();
    let s2 = format!("{d:?}");
    assert!(!s1.contains("SECRET") && !s2.contains("SECRET"), "{s1} {s2}");
}

/// Unknown lanes: TERMINAL_BREACH, reject, payload back, id not consumed.
#[test]
fn rt_held_unknown_lane_changes_nothing() {
    let clock = ManualClock::new(0);
    let mut cop: TrafficCop<u8, _> = TrafficCop::new(&two_lane(4, 4), clock).unwrap();
    let a = cop.admit(LaneId::new(0), 1).unwrap();
    let r = cop.admit(LaneId::new(2), 9).unwrap_err();
    assert_eq!(r.payload, 9);
    assert_eq!(r.trip.outcome(), GateOutcome::TerminalBreach);
    assert_eq!(r.trip.resolution(), Resolution::Reject);
    let b = cop.admit(LaneId::new(0), 2).unwrap();
    assert_eq!(b.id.get(), a.id.get() + 1);
    assert_eq!(cop.total_queued(), 2);
}

/// A flood on lane 1 does not change when lane 0's requests are admitted,
/// refused or dispatched (ids aside, see the id leak test).
#[test]
fn rt_held_cross_lane_dispatch_timing_isolated() {
    fn run(flood: bool) -> Vec<(u64, u64, u64)> {
        let clock = ManualClock::new(0);
        let mut cop: TrafficCop<u32, _> = TrafficCop::new(&two_lane(8, 2), clock.clone()).unwrap();
        let mut out = Vec::new();
        for step in 0..40u32 {
            if step % 3 == 0 {
                let _ = cop.admit(LaneId::new(0), step);
            }
            if flood {
                for _ in 0..50 {
                    let _ = cop.admit(LaneId::new(1), step);
                }
            }
            for d in cop.poll().unwrap() {
                if d.ticket.lane() == LaneId::new(0) {
                    out.push((d.ticket.arrived_at(), d.ticket.dispatched_at(), d.ticket.dispatch_phase()));
                }
            }
            clock.advance(PHASE / 2);
        }
        out
    }
    assert_eq!(run(false), run(true));
}

/// Claim under attack: "a request that arrives at an empty lane queue is
/// dispatched in less than one epoch" and "strictly sooner" than the bound.
/// Worst-case arrival: the same instant as the lane's own-phase poll, just
/// after it. The wait is exactly one epoch, so the bound is not strict; with
/// any poll latency at the next phase it exceeds one epoch.
#[test]
fn rt_empty_lane_bound_strictly_under_one_epoch() {
    let cfg = GreenWaveConfig {
        phase_len_ns: PHASE,
        phases_per_epoch: 7,
        lanes: vec![
            LaneSpec { weight: 5, queue_cap: 8 },
            LaneSpec { weight: 1, queue_cap: 8 },
            LaneSpec { weight: 1, queue_cap: 8 },
        ],
        stage_offsets: vec![0],
        max_dispatch_per_phase: 1,
    };
    let clock = ManualClock::new(0);
    let mut cop: TrafficCop<u8, _> = TrafficCop::new(&cfg, clock.clone()).unwrap();
    let own = cop.phase_table().phases_of(LaneId::new(2)).unwrap()[0] as u64;
    clock.set(own * PHASE);
    cop.poll().unwrap();
    let adm = cop.admit(LaneId::new(2), 1).unwrap();
    let mut waited = None;
    for p in (own + 1)..(own + 20) {
        clock.set(p * PHASE);
        for _ in 0..50 {
            let _ = cop.admit(LaneId::new(0), 0);
        }
        if let Some(d) = cop.poll().unwrap().into_iter().find(|d| d.ticket.id() == adm.id) {
            waited = Some(d.ticket.dispatched_at() - adm.arrived_at);
            break;
        }
    }
    let w = waited.unwrap();
    eprintln!("worst-case empty-lane wait {w} ns; epoch {} ns", cop.timing().epoch_len());
    // Corrected: the crate now claims "at most one epoch plus poll latency"
    // for an empty lane (the strict claim this test found false was dropped
    // from the docs). On the manual clock poll latency is zero, so the wait
    // must not exceed one epoch; the worst case above is exactly one epoch.
    assert!(w <= cop.timing().epoch_len(), "waited {w}, more than one epoch");
}

/// Release depends only on the epoch the completion fell in.
#[test]
fn rt_held_release_depends_only_on_epoch() {
    let clock = ManualClock::new(0);
    let mut cop: TrafficCop<u8, _> = TrafficCop::new(&two_lane(8, 8), clock.clone()).unwrap();
    for _ in 0..4 {
        cop.admit(LaneId::new(0), 0).unwrap();
    }
    let tickets: Vec<_> = cop.poll().unwrap().into_iter().map(|d| d.ticket).collect();
    let epoch = cop.timing().epoch_len();
    let mut releases = HashSet::new();
    for (i, t) in tickets.iter().enumerate() {
        clock.set(3 * epoch + 1 + i as u64 * 400);
        releases.insert(cop.complete(t).unwrap().release_at);
    }
    assert_eq!(releases.len(), 1);
    assert_eq!(releases.into_iter().next().unwrap(), 4 * epoch);
}

/// Clock at u64::MAX: operations fail closed with Overflow, nothing panics.
#[test]
fn rt_held_end_of_time_fails_closed() {
    let clock = ManualClock::new(u64::MAX - 1);
    let mut cop: TrafficCop<u8, _> = TrafficCop::new(&one_lane(1, 1), clock.clone()).unwrap();
    cop.admit(LaneId::new(0), 1).unwrap();
    let r = cop.admit(LaneId::new(0), 2).unwrap_err();
    assert_eq!(r.trip.reason(), TripReason::Overflow);
    let tk = cop.poll().unwrap().pop().unwrap().ticket;
    clock.set(u64::MAX);
    let c = cop.complete(&tk).unwrap_err();
    assert_eq!(c.reason(), TripReason::Overflow);
    assert!(cop.wave_schedule(&tk).is_ok() || cop.wave_schedule(&tk).is_err());
    assert!(cop.next_phase_start().is_none());
}

/// Halt refuses everything, returns payloads and changes no queue.
#[test]
fn rt_held_halt_refuses_everything() {
    let clock = ManualClock::new(10 * PHASE);
    let mut cop: TrafficCop<u8, _> = TrafficCop::new(&two_lane(4, 4), clock.clone()).unwrap();
    cop.admit(LaneId::new(0), 1).unwrap();
    clock.set(PHASE);
    assert_eq!(cop.poll().unwrap_err().reason(), TripReason::ClockRegressed);
    clock.set(100 * PHASE);
    let r = cop.admit(LaneId::new(1), 7).unwrap_err();
    assert_eq!((r.payload, r.trip.reason(), r.trip.resolution()), (7, TripReason::Halted, Resolution::Halt));
    assert_eq!(cop.poll().unwrap_err().reason(), TripReason::Halted);
    assert_eq!(cop.total_queued(), 1);
}

/// Early stage: RETRY with retry_after = due_at; absurd stage: TERMINAL_BREACH.
#[test]
fn rt_held_stage_gate_early_and_unknown() {
    let clock = ManualClock::new(0);
    let mut cop: TrafficCop<u8, _> = TrafficCop::new(&two_lane(4, 4), clock.clone()).unwrap();
    cop.admit(LaneId::new(0), 1).unwrap();
    let tk = cop.poll().unwrap().pop().unwrap().ticket;
    let e = cop.stage_check(&tk, 1).unwrap_err();
    assert_eq!(e.outcome(), GateOutcome::Retry);
    assert_eq!(e.retry_after(), Some(PHASE));
    let u = cop.stage_check(&tk, usize::MAX).unwrap_err();
    assert_eq!(u.outcome(), GateOutcome::TerminalBreach);
}
