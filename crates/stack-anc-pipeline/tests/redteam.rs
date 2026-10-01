//! Red-team tests for stack-anc-pipeline (ANC strategy 3).
//!
//! Each test asserts the SAFE behaviour, so a test FAILS while the weakness
//! it probes exists. Tests are serialized with one process-wide lock:
//! several install a scoped `tracing` subscriber, and `tracing` caches
//! callsite interest process-wide (see tests/logs.rs for the same issue).
//!
//! Timing tests run in whatever profile `cargo test` uses (normally debug),
//! so they are smoke tests, each calibrated against the harness victims at
//! the same n. They are not evidence of release behaviour.

#![allow(clippy::unwrap_used, clippy::panic)] // test code: failures should abort the test

use metrics_util::debugging::{DebugValue, DebuggingRecorder, Snapshotter};
use proptest::prelude::*;
use std::collections::BTreeSet;
use std::io::Write;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};
use tack_anc_harness::victim::{ct_validate, leaky_validate};
use tack_anc_harness::{measure_pair, Class, MeasureConfig, Report, SplitMix64, T_THRESHOLD};
use tack_anc_pipeline::telemetry::{names, sha256_hex};
use tack_anc_pipeline::{
    Accepted, GateOutcome, PipelineConfig, PipelineGate, TokenSecret, Trip, Validator, TOKEN_LEN,
};

// Test fixture, not a key. Printable so a raw leak into a log is easy to spot.
const FIXTURE: &[u8; TOKEN_LEN] = b"REDTEAM-FIXTURE-not-a-key-012345";

static LOCK: Mutex<()> = Mutex::new(());

fn serial() -> MutexGuard<'static, ()> {
    LOCK.lock().unwrap_or_else(|e| e.into_inner())
}

fn gate_with(validator: Validator, max_in_flight: usize, record: bool) -> PipelineGate {
    let cfg = PipelineConfig {
        validator,
        allow_leaky_validators: validator.is_leaky(),
        max_in_flight,
        record_response_time: record,
    };
    PipelineGate::new(TokenSecret::from_bytes(FIXTURE).unwrap(), cfg).unwrap()
}

fn gate(validator: Validator) -> PipelineGate {
    gate_with(validator, 64, true)
}

fn wrong_at(pos: usize) -> [u8; TOKEN_LEN] {
    let mut c = *FIXTURE;
    c[pos] ^= 0x01;
    c
}

type Entry = (String, Vec<(String, String)>, DebugValue);

fn snapshot(s: &Snapshotter) -> Vec<Entry> {
    s.snapshot()
        .into_vec()
        .into_iter()
        .map(|(ck, _, _, v)| {
            let key = ck.key();
            let mut labels: Vec<(String, String)> = key
                .labels()
                .map(|l| (l.key().to_string(), l.value().to_string()))
                .collect();
            labels.sort();
            (key.name().to_string(), labels, v)
        })
        .collect()
}

fn counter_sum(snap: &[Entry], name: &str) -> u64 {
    snap.iter()
        .filter(|(n, _, _)| n == name)
        .map(|(_, _, v)| match v {
            DebugValue::Counter(c) => *c,
            _ => 0,
        })
        .sum()
}

#[derive(Clone, Default)]
struct Buf(Arc<Mutex<Vec<u8>>>);

impl Write for Buf {
    fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(b);
        Ok(b.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

fn capture_debug_logs(f: impl FnOnce()) -> String {
    let buf = Buf::default();
    let writer = buf.clone();
    let subscriber = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::DEBUG)
        .with_ansi(false)
        .with_writer(move || writer.clone())
        .finish();
    tracing::subscriber::with_default(subscriber, f);
    let bytes = buf.0.lock().unwrap().clone();
    String::from_utf8_lossy(&bytes).into_owned()
}

// ---------------------------------------------------------------------
// Bypass and fail-open
// ---------------------------------------------------------------------

/// Attack: pad the correct token with extra bytes, or truncate it, hoping
/// a validator reads only a prefix.
#[test]
fn bypass_prefix_suffix_and_truncation_never_pass() {
    let _l = serial();
    for v in Validator::ALL {
        let g = gate(v);
        let mut long = FIXTURE.to_vec();
        long.push(0);
        assert_eq!(g.check(&long), Err(Trip::InputTooLarge), "{v:?}");
        let mut doubled = FIXTURE.to_vec();
        doubled.extend_from_slice(FIXTURE);
        assert_eq!(g.check(&doubled), Err(Trip::InputTooLarge), "{v:?}");
        assert_eq!(g.check(&FIXTURE[..31]), Err(Trip::Malformed), "{v:?}");
        assert_eq!(g.check(&[]), Err(Trip::Malformed), "{v:?}");
        assert_eq!(g.check(FIXTURE), Ok(Accepted), "{v:?}");
        for pos in 0..TOKEN_LEN {
            for bit in 0..8 {
                let mut c = *FIXTURE;
                c[pos] ^= 1 << bit;
                assert_eq!(
                    g.check(&c),
                    Err(Trip::Mismatch),
                    "{v:?} pos {pos} bit {bit}"
                );
            }
        }
        assert_eq!(g.in_flight(), 0);
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(2000))]

    /// Attack: arbitrary bytes of arbitrary length (0..=80), including the
    /// secret as a prefix. Only the exact secret passes; every other input
    /// maps to a non-PASS outcome; nothing panics; the slot is returned.
    #[test]
    fn fuzz_only_exact_secret_passes(
        body in proptest::collection::vec(any::<u8>(), 0..=80),
        prefix_secret in any::<bool>(),
        vi in 0usize..3,
    ) {
        let _l = serial();
        let v = Validator::ALL[vi];
        let g = gate_with(v, 1, true);
        let mut input = body.clone();
        if prefix_secret {
            input = FIXTURE.to_vec();
            input.extend_from_slice(&body);
        }
        let r = g.check(&input);
        let is_secret = input.as_slice() == FIXTURE.as_slice();
        match r {
            Ok(a) => {
                prop_assert!(is_secret, "{:?} passed a non-secret input of len {}", v, input.len());
                prop_assert_eq!(a.gate_outcome(), GateOutcome::Pass);
            }
            Err(t) => {
                prop_assert!(!is_secret);
                prop_assert_ne!(t.gate_outcome(), GateOutcome::Pass);
                let expected = if input.len() > TOKEN_LEN {
                    Trip::InputTooLarge
                } else if input.len() < TOKEN_LEN {
                    Trip::Malformed
                } else {
                    Trip::Mismatch
                };
                prop_assert_eq!(t, expected);
            }
        }
        prop_assert_eq!(g.in_flight(), 0);
    }
}

/// Attack: pick a leaky validator without the opt-in flag, or with an
/// out-of-bound cap. Construction must fail closed.
#[test]
fn fail_open_config_is_refused() {
    let _l = serial();
    for v in [Validator::EarlyExit, Validator::BalancedDummy] {
        let cfg = PipelineConfig {
            validator: v,
            ..PipelineConfig::default()
        };
        assert!(PipelineGate::new(TokenSecret::from_bytes(FIXTURE).unwrap(), cfg).is_err());
    }
    for cap in [0usize, 65_537, usize::MAX] {
        let cfg = PipelineConfig {
            max_in_flight: cap,
            ..PipelineConfig::default()
        };
        assert!(
            PipelineGate::new(TokenSecret::from_bytes(FIXTURE).unwrap(), cfg).is_err(),
            "cap {cap}"
        );
    }
    assert!(TokenSecret::from_bytes(&[0u8; TOKEN_LEN]).is_err());
    assert!(TokenSecret::from_bytes(&[]).is_err());
    assert!(TokenSecret::from_bytes(&[7u8; 1 << 20]).is_err());
}

/// Attack (keys): the all-zero secret is refused as "the usual shape of an
/// unset default", but the other common unset shape, all 0xFF (erased
/// flash, or `!0` filler), is accepted as a production key.
#[test]
fn key_all_ff_unset_shape_is_refused() {
    let _l = serial();
    assert!(
        TokenSecret::from_bytes(&[0xFFu8; TOKEN_LEN]).is_err(),
        "TokenSecret accepted the all-0xFF token, a common unset-key shape"
    );
}

// ---------------------------------------------------------------------
// Panics and unbounded resources, amplification
// ---------------------------------------------------------------------

/// Attack: a 64 MiB input must cost one length compare, even with debug
/// logging on (it must not be hashed or copied).
#[test]
fn dos_huge_input_is_rejected_in_constant_work() {
    let _l = serial();
    let huge = vec![0x41u8; 64 << 20];
    let g = gate(Validator::ConstantTime);
    let mut worst = Duration::ZERO;
    let logs = capture_debug_logs(|| {
        for _ in 0..20 {
            let t = Instant::now();
            assert_eq!(g.check(&huge), Err(Trip::InputTooLarge));
            worst = worst.max(t.elapsed());
        }
    });
    // SHA-256 of 64 MiB in debug takes seconds; one compare plus one log
    // line takes well under 50 ms.
    assert!(worst < Duration::from_millis(50), "worst {worst:?}");
    assert!(logs.contains("input_len=67108864"), "{logs}");
    assert!(!logs.contains("AAAA"), "raw input in log");
}

/// Attack: the in-flight counter is shared state. Hammer it from many
/// threads with a tiny cap; the cap must never be exceeded, every call
/// must get a sane outcome, and the counter must return to zero.
#[test]
fn concurrency_slot_counter_holds_under_contention() {
    let _l = serial();
    let g = Arc::new(gate_with(Validator::ConstantTime, 2, false));
    let stop = Arc::new(AtomicBool::new(false));
    let max_seen = Arc::new(AtomicUsize::new(0));
    let watcher = {
        let (g, stop, max_seen) = (g.clone(), stop.clone(), max_seen.clone());
        std::thread::spawn(move || {
            while !stop.load(Ordering::Relaxed) {
                max_seen.fetch_max(g.in_flight(), Ordering::Relaxed);
            }
        })
    };
    let wrong_pass = Arc::new(AtomicUsize::new(0));
    let right_mismatch = Arc::new(AtomicUsize::new(0));
    let sheds = Arc::new(AtomicUsize::new(0));
    let mut hs = Vec::new();
    for t in 0..8 {
        let (g, wp, rm, sh) = (
            g.clone(),
            wrong_pass.clone(),
            right_mismatch.clone(),
            sheds.clone(),
        );
        hs.push(std::thread::spawn(move || {
            let wrong = wrong_at(t % TOKEN_LEN);
            for i in 0..20_000 {
                let good = i % 2 == 0;
                let c: &[u8; TOKEN_LEN] = if good { FIXTURE } else { &wrong };
                match g.check(c) {
                    Ok(_) if !good => {
                        wp.fetch_add(1, Ordering::Relaxed);
                    }
                    Err(Trip::Mismatch) if good => {
                        rm.fetch_add(1, Ordering::Relaxed);
                    }
                    Err(Trip::SlotsFull) => {
                        sh.fetch_add(1, Ordering::Relaxed);
                    }
                    Err(Trip::InputTooLarge | Trip::Malformed) => panic!("bad trip"),
                    _ => {}
                }
            }
        }));
    }
    for h in hs {
        h.join().unwrap();
    }
    stop.store(true, Ordering::Relaxed);
    watcher.join().unwrap();
    eprintln!(
        "contention: max in_flight seen {}, sheds {}",
        max_seen.load(Ordering::Relaxed),
        sheds.load(Ordering::Relaxed)
    );
    assert!(max_seen.load(Ordering::Relaxed) <= 2);
    assert_eq!(wrong_pass.load(Ordering::Relaxed), 0);
    assert_eq!(right_mismatch.load(Ordering::Relaxed), 0);
    assert_eq!(g.in_flight(), 0);
}

// ---------------------------------------------------------------------
// Telemetry abuse
// ---------------------------------------------------------------------

/// Attack: drive label cardinality with 5000 random inputs of random
/// lengths and contents. The metric key set must stay inside the closed
/// set, whatever the input.
#[test]
fn telemetry_label_cardinality_is_closed() {
    let _l = serial();
    let rec = DebuggingRecorder::new();
    let snap = rec.snapshotter();
    let mut rng = SplitMix64::new(0x5eed_0bad);
    metrics::with_local_recorder(&rec, || {
        for v in Validator::ALL {
            let g = gate(v);
            for _ in 0..5000 {
                let len = (rng.next_u64() % 65) as usize;
                let mut buf = vec![0u8; len];
                rng.fill_bytes(&mut buf);
                let _ = g.check(&buf);
            }
            let _ = g.check(FIXTURE);
        }
    });
    let s = snapshot(&snap);
    let allowed_values: BTreeSet<&str> = [
        "pipeline",
        "early_exit",
        "balanced_dummy",
        "constant_time",
        "pass",
        "retry",
        "slots_full",
        "input_too_large",
        "malformed",
    ]
    .into_iter()
    .collect();
    for (n, labels, _) in &s {
        assert!(n.starts_with("tack_anc_"), "{n}");
        for (k, val) in labels {
            assert!(
                ["strategy", "validator", "outcome", "reason"].contains(&k.as_str()),
                "label key {k}"
            );
            assert!(allowed_values.contains(val.as_str()), "label value {val}");
        }
    }
    // 3 validators x (2 requests + 2 histogram + 1 mismatch + 1 gauge for
    // the two leaky ones) + 3 shed reasons at most.
    assert!(s.len() <= 3 * 5 + 2 + 3, "{} keys: {s:?}", s.len());
}

/// Attack (unit confusion): the histogram named `_seconds` must hold
/// seconds, not nanoseconds or microseconds.
#[test]
fn telemetry_response_histogram_is_in_seconds() {
    let _l = serial();
    let rec = DebuggingRecorder::new();
    let snap = rec.snapshotter();
    metrics::with_local_recorder(&rec, || {
        let g = gate(Validator::ConstantTime);
        for _ in 0..100 {
            let _ = g.check(&wrong_at(3));
        }
    });
    let s = snapshot(&snap);
    let vals: Vec<f64> = s
        .iter()
        .filter(|(n, _, _)| n == names::RESPONSE_SECONDS)
        .flat_map(|(_, _, v)| match v {
            DebugValue::Histogram(h) => h.iter().map(|x| x.into_inner()).collect(),
            _ => Vec::new(),
        })
        .collect();
    assert_eq!(vals.len(), 100);
    assert!(vals.iter().all(|x| *x > 0.0 && *x < 0.5), "{vals:?}");
}

/// Attack (log injection): a 32-byte candidate full of newlines, ANSI
/// escapes and a forged key=value must never reach the log as text.
#[test]
fn telemetry_log_injection_is_impossible() {
    let _l = serial();
    let evil: &[u8; TOKEN_LEN] = b"\n\x1b[31mXY outcome=PASS reason=ok\n";
    let g = gate(Validator::ConstantTime);
    let logs = capture_debug_logs(|| {
        assert_eq!(g.check(evil), Err(Trip::Mismatch));
    });
    assert!(!logs.contains("outcome=PASS reason=ok"), "{logs}");
    assert!(!logs.contains('\x1b'), "{logs}");
    assert!(logs.contains(&sha256_hex(evil)), "{logs}");
}

/// Attack (credential-derived verifier in logs): every accepted request
/// logs `input_sha256` next to `outcome="PASS"`, i.e. the unkeyed SHA-256
/// of the server's secret. Anyone with log access can then test guesses
/// offline, with no rate limit, no metric and no alert, and a low-entropy
/// secret (TokenSecret accepts any non-zero 32 bytes, including ASCII)
/// falls to a dictionary. The safe behaviour: no log line carries an
/// unkeyed digest of the secret.
#[test]
fn telemetry_logs_do_not_carry_unkeyed_digest_of_the_secret() {
    let _l = serial();
    let g = gate(Validator::ConstantTime);
    let logs = capture_debug_logs(|| {
        assert_eq!(g.check(FIXTURE), Ok(Accepted));
    });
    let secret_digest = sha256_hex(FIXTURE);
    assert!(
        !logs.contains(&secret_digest),
        "debug log carries SHA-256(secret) on PASS: {}",
        logs.lines()
            .find(|l| l.contains(&secret_digest))
            .unwrap_or("")
    );
}

/// Attack (detective-control ordering): the leaky-validator gauge is set
/// once, inside `PipelineGate::new`. If the gate is built before the
/// metrics recorder is installed (a common start-up order: parse config,
/// build components, then start the exporter), the gauge is never
/// emitted and `TackAncPipelineLeakyValidatorActive` never fires, even
/// though every request afterwards runs the leaky validator.
#[test]
fn telemetry_leaky_gauge_survives_recorder_installed_after_build() {
    let _l = serial();
    let g = gate(Validator::BalancedDummy); // no recorder yet
    let rec = DebuggingRecorder::new();
    let snap = rec.snapshotter();
    metrics::with_local_recorder(&rec, || {
        for _ in 0..10 {
            let _ = g.check(&wrong_at(0));
        }
    });
    let s = snapshot(&snap);
    assert!(
        counter_sum(&s, names::REQUESTS_TOTAL) == 10,
        "recorder is live: {s:?}"
    );
    let gauge = s.iter().any(|(n, labels, v)| {
        n == names::LEAKY_VALIDATOR_ACTIVE
            && labels.contains(&("validator".into(), "balanced_dummy".into()))
            && matches!(v, DebugValue::Gauge(x) if x.into_inner() > 0.0)
    });
    assert!(
        gauge,
        "10 requests ran on balanced_dummy, yet tack_anc_leaky_validator_active \
         was never emitted to the live recorder: {s:?}"
    );
}

/// Attack (stale alert): the gauge is never reset. After the leaky gate is
/// dropped and replaced by a constant_time gate in the same process, the
/// critical alert keeps firing, which trains operators to silence it.
#[test]
fn telemetry_leaky_gauge_clears_when_leaky_gate_is_dropped() {
    let _l = serial();
    let rec = DebuggingRecorder::new();
    let snap = rec.snapshotter();
    metrics::with_local_recorder(&rec, || {
        let leaky = gate(Validator::EarlyExit);
        let _ = leaky.check(FIXTURE);
        drop(leaky);
        let ct = gate(Validator::ConstantTime);
        let _ = ct.check(FIXTURE);
    });
    let s = snapshot(&snap);
    let still_on = s.iter().any(|(n, _, v)| {
        n == names::LEAKY_VALIDATOR_ACTIVE
            && matches!(v, DebugValue::Gauge(x) if x.into_inner() > 0.0)
    });
    assert!(
        !still_on,
        "no leaky gate exists, yet tack_anc_leaky_validator_active is still 1: {s:?}"
    );
}

/// Attack (alert evasion by dilution): `TackAncPipelineGuessing` divides
/// mismatches by ALL requests, sheds included. A guessing campaign in
/// which every well-formed token is wrong hides under the 0.5 threshold by
/// sending two cheap wrong-length requests per guess, which cost the
/// server one compare each. The safe denominator counts only requests
/// that reached the validator.
#[test]
fn alert_guessing_ratio_cannot_be_diluted_by_cheap_malformed_requests() {
    let _l = serial();
    let rec = DebuggingRecorder::new();
    let snap = rec.snapshotter();
    metrics::with_local_recorder(&rec, || {
        let g = gate(Validator::ConstantTime);
        for i in 0..100 {
            assert_eq!(g.check(&wrong_at(i % TOKEN_LEN)), Err(Trip::Mismatch));
            assert_eq!(g.check(&[0u8; 1]), Err(Trip::Malformed));
            assert_eq!(g.check(&[0u8; 1]), Err(Trip::Malformed));
        }
    });
    let s = snapshot(&snap);
    let mismatch = counter_sum(&s, names::TOKEN_MISMATCH_TOTAL) as f64;
    let requests = counter_sum(&s, names::REQUESTS_TOTAL) as f64;
    // The documented alert expression, evaluated on the same counters.
    let ratio = mismatch / requests.max(1e-9);
    eprintln!("guessing alert ratio {ratio:.3} (mismatch {mismatch}, requests {requests})");
    assert!(
        ratio > 0.5,
        "100% of well-formed tokens were wrong, yet the guessing alert ratio is {ratio:.3}"
    );
}

// ---------------------------------------------------------------------
// Timing side channels (debug-profile smoke, calibrated)
// ---------------------------------------------------------------------

const PER_CLASS: usize = 20_000;

fn run_pair(
    mut prep: impl FnMut(Class, &mut SplitMix64) -> [u8; TOKEN_LEN],
    op: impl FnMut(&[u8; TOKEN_LEN]) -> bool,
) -> Report {
    let cfg = MeasureConfig::with_samples(2 * PER_CLASS);
    let mut op = op;
    measure_pair(&cfg, |c, r| prep(c, r), |c| op(c)).unwrap()
}

fn prefix_classes(class: Class, rng: &mut SplitMix64) -> [u8; TOKEN_LEN] {
    let mut c = *FIXTURE;
    let flip = (rng.next_u64() as u8) | 1;
    match class {
        Class::A => c[0] ^= flip,
        Class::B => c[TOKEN_LEN - 1] ^= flip,
    }
    c
}

fn calibrate() {
    let leaky = run_pair(prefix_classes, |c| leaky_validate(FIXTURE, c));
    let ct = run_pair(prefix_classes, |c| ct_validate(FIXTURE, c));
    assert!(leaky.verdict(T_THRESHOLD).is_leak(), "calibration: leaky");
    assert!(ct.verdict(T_THRESHOLD).is_pass(), "calibration: ct");
}

/// Attack (Hamming weight): the XOR/OR accumulator ends as 0xFF when every
/// bit differs and 0x01 when one bit differs. Any value-dependent step in
/// the final decision would separate these classes.
#[test]
fn timing_constant_time_gate_ignores_hamming_weight_of_difference() {
    let _l = serial();
    calibrate();
    let g = gate(Validator::ConstantTime);
    let r = run_pair(
        |class, _| match class {
            Class::A => {
                let mut c = *FIXTURE;
                for b in &mut c {
                    *b = !*b;
                }
                c
            }
            Class::B => {
                let mut c = *FIXTURE;
                c[TOKEN_LEN - 1] ^= 0x01;
                c
            }
        },
        |c| g.check(c).is_ok(),
    );
    let v = r.verdict(T_THRESHOLD);
    eprintln!("hamming: max|t|={:.2} ks_p={:?}", r.max_abs_t, r.ks_p);
    assert!(
        v.is_pass(),
        "{v:?} t_raw={:?} crops={:?}",
        r.t_raw,
        r.cropped
    );
}

/// Attack (telemetry on the path): with debug logging on, every
/// well-formed request hashes the candidate and formats a log line inside
/// the attacker-observed window. That work must not separate a guess wrong
/// at byte 0 from one wrong at byte 31.
#[test]
fn timing_constant_time_gate_with_debug_logging_and_recorder() {
    let _l = serial();
    calibrate();
    let g = gate(Validator::ConstantTime);
    let subscriber = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::DEBUG)
        .with_ansi(false)
        .with_writer(std::io::sink)
        .finish();
    let rec = DebuggingRecorder::new();
    let r = tracing::subscriber::with_default(subscriber, || {
        metrics::with_local_recorder(&rec, || run_pair(prefix_classes, |c| g.check(c).is_ok()))
    });
    let v = r.verdict(T_THRESHOLD);
    eprintln!(
        "logging+recorder: max|t|={:.2} ks_p={:?}",
        r.max_abs_t, r.ks_p
    );
    assert!(
        v.is_pass(),
        "{v:?} t_raw={:?} crops={:?}",
        r.t_raw,
        r.cropped
    );
}

/// Shed-rate side channel: an "occupant" thread holds the single slot of a
/// max_in_flight = 1 gate with guesses whose class (A or B) is redrawn at
/// random for each block of 1024 requests, and publishes the block number
/// and class. A "probe" thread sends a fixed token and tallies its own
/// sheds per occupant block. If slot hold time depends on the secret, the
/// probe's shed rate differs by class: load shedding becomes a second
/// channel, visible from reply codes alone, that survives even if reply
/// times were padded upstream.
///
/// Statistic: Welch t over per-block shed rates, block by class. Sheds
/// arrive in scheduler-driven bursts, so a per-request binomial z is
/// overdispersed (an A/A run reached |z| = 8 and a constant_time run 20
/// during development); the block, whose class is randomized, is the
/// valid unit. Blocks the probe saw fewer than 32 times are dropped.
/// Returns t (positive means the probe was shed more while class A ran).
fn shed_channel_t(v: Validator) -> f64 {
    shed_channel_t_with(v, wrong_at(0), wrong_at(TOKEN_LEN - 1), v.label())
}

/// As [`shed_channel_t`], with explicit class A and class B tokens. Passing
/// the same token twice gives an A/A control for the statistic itself.
fn shed_channel_t_with(
    v: Validator,
    cand_a: [u8; TOKEN_LEN],
    cand_b: [u8; TOKEN_LEN],
    tag: &str,
) -> f64 {
    const BLOCK: usize = 1024;
    const PROBES: usize = 1_500_000;
    let g = Arc::new(gate_with(v, 1, false));
    // block number * 2 + class; usize::MAX until the first block starts.
    let now = Arc::new(AtomicUsize::new(usize::MAX));
    let done = Arc::new(AtomicBool::new(false));
    let occupant = {
        let (g, now, done) = (g.clone(), now.clone(), done.clone());
        std::thread::spawn(move || {
            let cands = [cand_a, cand_b];
            let mut rng = SplitMix64::new(0x0cc0_0bad);
            let mut block = 0usize;
            while !done.load(Ordering::Relaxed) {
                let c = (rng.next_u64() & 1) as usize;
                now.store(block * 2 + c, Ordering::Relaxed);
                for _ in 0..BLOCK {
                    let _ = g.check(&cands[c]);
                }
                block += 1;
            }
        })
    };
    let probe_cand = wrong_at(7);
    // (tag, sent, shed) per block, in order; bounded by PROBES entries.
    let mut blocks: Vec<(usize, usize, usize)> = Vec::new();
    let mut probes = 0usize;
    while probes < PROBES {
        let tag_now = now.load(Ordering::Relaxed);
        if tag_now == usize::MAX {
            std::thread::yield_now();
            continue;
        }
        probes += 1;
        let shed = usize::from(g.check(&probe_cand) == Err(Trip::SlotsFull));
        match blocks.last_mut() {
            Some((t, sent, sh)) if *t == tag_now => {
                *sent += 1;
                *sh += shed;
            }
            _ => blocks.push((tag_now, 1, shed)),
        }
    }
    done.store(true, Ordering::Relaxed);
    occupant.join().unwrap();
    assert_eq!(g.in_flight(), 0);
    let mut rates: [Vec<f64>; 2] = [Vec::new(), Vec::new()];
    for (t, sent, sh) in blocks {
        if sent >= 32 {
            rates[t & 1].push(sh as f64 / sent as f64);
        }
    }
    let w = tack_anc_harness::stats::welch_slices(&rates[0], &rates[1]).unwrap();
    let mean = |x: &[f64]| x.iter().sum::<f64>() / x.len().max(1) as f64;
    eprintln!(
        "shed channel {tag}: blocks A {} (mean shed rate {:.4}), blocks B {} ({:.4}), t = {:.2}",
        rates[0].len(),
        mean(&rates[0]),
        rates[1].len(),
        mean(&rates[1]),
        w.t
    );
    w.t
}

/// Attack (secret-dependent shedding): for constant_time, the probe's shed
/// rate must not depend on the class of the concurrent guesses
/// (|t| < T_THRESHOLD). Calibrated in the same run: an A/A control (both
/// classes the same token) must pass, and the known-leaky early_exit must
/// be detected, so a pass is not a blind method.
#[test]
fn shedding_outcome_is_independent_of_token_value() {
    let _l = serial();
    let t_aa = shed_channel_t_with(
        Validator::ConstantTime,
        wrong_at(0),
        wrong_at(0),
        "constant_time A/A control",
    );
    let t_early = shed_channel_t(Validator::EarlyExit);
    assert!(t_aa.abs() < T_THRESHOLD, "calibration: A/A t = {t_aa:.2}");
    assert!(
        t_early.abs() > T_THRESHOLD,
        "calibration: early_exit shed channel not detected, t = {t_early:.2}"
    );
    let t_ct = shed_channel_t(Validator::ConstantTime);
    assert!(
        t_ct.abs() < T_THRESHOLD,
        "constant_time shed rate depends on class: t = {t_ct:.2}"
    );
}

/// Attack (secret-dependent shedding, brief's design): the crate docs say
/// a SlotsFull reply "reflects load only". With balanced_dummy, slot hold
/// time still depends on where the guess goes wrong, so a probe that sees
/// only reply codes (no clock) learns the class of concurrent guesses from
/// its own shed rate. The safe behaviour is |t| < T_THRESHOLD, as for
/// constant_time.
#[test]
fn shedding_reflects_load_only_for_balanced_dummy() {
    let _l = serial();
    let t = shed_channel_t(Validator::BalancedDummy);
    assert!(
        t.abs() < T_THRESHOLD,
        "balanced_dummy: probe shed rate depends on the class of concurrent guesses: t = {t:.2}"
    );
}
