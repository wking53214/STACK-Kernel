//! Independent red-team tests for tack-bumpers.
//!
//! Every test asserts the SAFE behaviour, so a test FAILS while the weakness
//! it describes exists. Test names start with `redteam_`.
//!
//! One global tracing subscriber is installed for the whole binary (see
//! `init`), because tracing caches per-callsite interest globally and a mix
//! of scoped subscribers across parallel tests races that cache. It formats
//! every event at DEBUG and above into a shared buffer, and counts WARN
//! events per thread so a test can measure log volume for its own request.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use std::cell::Cell;
use std::collections::{BTreeMap, BTreeSet};
use std::io::Write;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

use common::{fixture, num, qty, req, text};
use metrics_util::debugging::DebuggingRecorder;
use proptest::prelude::*;
use tack_bumpers::telemetry;
use tack_bumpers::{
    Bumper, BumperConfig, CorrectionKind, GateOutcome, NormalizedValue, NumericSpec, ParamSpec, ParamValue,
    Resolution, StringSpec, TrimPolicy, TripReason, UnitScale,
};
use tracing_subscriber::layer::{Context, SubscriberExt};
use tracing_subscriber::Layer;

// ---------------------------------------------------------------------------
// Global log capture
// ---------------------------------------------------------------------------

#[derive(Clone, Default)]
struct Capture(Arc<Mutex<Vec<u8>>>);

impl Write for Capture {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for Capture {
    type Writer = Capture;
    fn make_writer(&'a self) -> Self::Writer {
        self.clone()
    }
}

thread_local! {
    static WARN_EVENTS: Cell<usize> = const { Cell::new(0) };
}

/// Counts WARN events emitted on the current thread.
struct WarnCounter;

impl<S: tracing::Subscriber> Layer<S> for WarnCounter {
    fn on_event(&self, event: &tracing::Event<'_>, _ctx: Context<'_, S>) {
        if *event.metadata().level() == tracing::Level::WARN {
            WARN_EVENTS.with(|c| c.set(c.get() + 1));
        }
    }
}

fn init() -> &'static Capture {
    static CAP: OnceLock<Capture> = OnceLock::new();
    CAP.get_or_init(|| {
        let cap = Capture::default();
        let fmt = tracing_subscriber::fmt::layer()
            .with_ansi(false)
            .with_writer(cap.clone())
            .with_span_events(tracing_subscriber::fmt::format::FmtSpan::CLOSE)
            .with_filter(tracing_subscriber::filter::LevelFilter::DEBUG);
        let subscriber = tracing_subscriber::registry().with(fmt).with(WarnCounter);
        tracing::subscriber::set_global_default(subscriber).unwrap();
        cap
    })
}

fn logs() -> String {
    String::from_utf8_lossy(&init().0.lock().unwrap()).into_owned()
}

fn warn_count() -> usize {
    WARN_EVENTS.with(Cell::get)
}

fn min_time<F: FnMut()>(runs: usize, mut f: F) -> Duration {
    (0..runs)
        .map(|_| {
            let t = Instant::now();
            f();
            t.elapsed()
        })
        .min()
        .unwrap()
}

// ---------------------------------------------------------------------------
// Attack: panics and fail-open under arbitrary input (fuzz)
// ---------------------------------------------------------------------------

fn arb_key() -> impl Strategy<Value = String> {
    prop_oneof![
        Just("timeout".to_owned()),
        Just("priority".to_owned()),
        Just("label".to_owned()),
        Just("tenant".to_owned()),
        Just("ratio".to_owned()),
        Just("Timeout".to_owned()),
        Just("timeout ".to_owned()),
        ".{0,12}",
    ]
}

fn arb_f64() -> impl Strategy<Value = f64> {
    prop_oneof![
        proptest::num::f64::ANY,
        Just(f64::NAN),
        Just(-f64::NAN),
        Just(f64::INFINITY),
        Just(f64::NEG_INFINITY),
        Just(-0.0),
        Just(f64::MAX),
        Just(f64::MIN),
        Just(f64::MIN_POSITIVE / 4.0),
        -400.0f64..400.0,
    ]
}

fn arb_text() -> impl Strategy<Value = String> {
    prop_oneof![
        Just(" HI ".to_owned()),
        Just("Med".to_owned()),
        Just("\u{3000}high\u{00A0}".to_owned()),
        Just(" ".repeat(5000)),
        "\\PC{0,24}",
        "[ \t\n\r\u{85}\u{a0}\u{2028}a-zA-Z]{0,20}",
    ]
}

fn arb_value() -> impl Strategy<Value = ParamValue> {
    prop_oneof![
        arb_f64().prop_map(ParamValue::Number),
        (arb_f64(), prop_oneof![Just("s"), Just("ms"), Just("min"), Just("MS"), Just("")])
            .prop_map(|(v, u)| ParamValue::Quantity {
                value: v,
                unit: u.to_owned()
            }),
        arb_text().prop_map(ParamValue::Text),
    ]
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(1024))]

    /// Arbitrary maps (including more than max_params entries, every float
    /// edge, Unicode whitespace) never panic, never fail open, and every
    /// PASS output satisfies the specs.
    #[test]
    fn redteam_fuzz_no_panic_no_fail_open(input in proptest::collection::btree_map(arb_key(), arb_value(), 0..70)) {
        init();
        let b = fixture();
        let nan_on_numeric = input.iter().any(|(k, v)| {
            (k == "timeout" || k == "ratio")
                && matches!(v, ParamValue::Number(x) | ParamValue::Quantity { value: x, .. } if !x.is_finite())
        });
        match b.normalize(&input) {
            Ok(n) => {
                prop_assert!(!nan_on_numeric, "non-finite numeric input passed");
                prop_assert!(input.len() <= 64);
                prop_assert!(n.corrections().len() <= 3);
                for (k, v) in n.values() {
                    prop_assert!(input.contains_key(k));
                    match (k.as_str(), v) {
                        ("timeout", NormalizedValue::Number(x)) => {
                            prop_assert!(x.is_finite() && *x >= 0.5 && *x <= 30.0);
                            prop_assert!(x.to_bits() != (-0.0f64).to_bits());
                        }
                        ("ratio", NormalizedValue::Number(x)) => {
                            prop_assert!(*x >= -0.5 && *x <= 0.5);
                            prop_assert!(x.to_bits() != (-0.0f64).to_bits(), "negative zero escaped");
                        }
                        ("priority", NormalizedValue::Variant(s)) => {
                            prop_assert!(["low", "medium", "high"].contains(&s.as_str()));
                        }
                        ("label", NormalizedValue::Text(s)) => prop_assert!(s.len() <= 16 && s.trim() == s),
                        ("tenant", NormalizedValue::Text(s)) => prop_assert!(s.len() <= 8 && s.trim() == s),
                        other => prop_assert!(false, "unexpected output {:?}", other),
                    }
                }
                prop_assert!(n.get("timeout").is_some() && n.get("priority").is_some());
            }
            Err(r) => {
                prop_assert_ne!(r.outcome, GateOutcome::Pass);
                prop_assert_eq!(r.resolution, Resolution::Reject);
                prop_assert!(!r.trips.is_empty());
                prop_assert!(r.trips.len() <= 64 + 5 + 1);
                let worst = r.trips.iter().map(|t| t.reason.outcome()).max().unwrap();
                prop_assert_eq!(worst, r.outcome);
                if nan_on_numeric && input.len() <= 64 {
                    prop_assert_eq!(r.outcome, GateOutcome::TerminalBreach);
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Attack: wrong outcome, NaN and infinity routed away from NON_FINITE
// ---------------------------------------------------------------------------

/// The failure-mode table claims "NaN in any form ... as a Number" is
/// TERMINAL_BREACH (non_finite), and the critical alert
/// TackBumpersNonFiniteInput keys on reason=non_finite. A NaN sent to an
/// enum or string parameter, or under an undeclared key, should not be
/// downgraded to a repairable RETRY that the alert never sees.
#[test]
fn redteam_nan_anywhere_is_terminal_non_finite() {
    init();
    let b = fixture();
    let cases: Vec<(&str, BTreeMap<String, ParamValue>)> = vec![
        ("NaN to enum param", req(&[("priority", num(f64::NAN))])),
        ("+inf to string param", req(&[("label", num(f64::INFINITY))])),
        (
            "NaN quantity to string param",
            req(&[("tenant", qty(f64::NAN, "s"))]),
        ),
        ("NaN under unknown key", req(&[("zz", num(f64::NAN))])),
    ];
    let mut failures = Vec::new();
    for (name, r) in &cases {
        match b.normalize(r) {
            Ok(_) => failures.push(format!("{name}: PASS")),
            Err(rej) => {
                if rej.outcome != GateOutcome::TerminalBreach || !rej.has(TripReason::NonFinite) {
                    failures.push(format!(
                        "{name}: outcome={} reasons={:?}",
                        rej.outcome.as_str(),
                        rej.trips.iter().map(|t| t.reason.as_str()).collect::<Vec<_>>()
                    ));
                }
            }
        }
    }
    assert!(failures.is_empty(), "non-finite input not TERMINAL non_finite: {failures:#?}");
}

// ---------------------------------------------------------------------------
// Attack: wrong outcome, oversized input hidden under an unknown key
// ---------------------------------------------------------------------------

/// The table claims "a text value, a Quantity unit name or an unknown key
/// longer than max_input_bytes" is TERMINAL_BREACH. Only the key is checked
/// on the unknown-key path, so an oversized value rides under a short
/// unknown key as a RETRY.
#[test]
fn redteam_oversized_value_under_unknown_key_is_terminal() {
    init();
    let b = fixture();
    let big = "A".repeat(1 << 20);
    let cases = [
        ("1 MiB text under unknown key", req(&[("x", text(&big))])),
        ("1 MiB unit under unknown key", req(&[("x", qty(1.0, &big))])),
    ];
    let mut failures = Vec::new();
    for (name, r) in &cases {
        let rej = b.normalize(r).unwrap_err();
        if rej.outcome != GateOutcome::TerminalBreach || !rej.has(TripReason::InputTooLarge) {
            failures.push(format!(
                "{name}: outcome={} reasons={:?}",
                rej.outcome.as_str(),
                rej.trips.iter().map(|t| t.reason.as_str()).collect::<Vec<_>>()
            ));
        }
    }
    assert!(failures.is_empty(), "oversized input not TERMINAL input_too_large: {failures:#?}");
}

// ---------------------------------------------------------------------------
// Attack: bypass of Required through whitespace-only text
// ---------------------------------------------------------------------------

/// A required TrimPolicy::Trim string sent as whitespace only passes as an
/// empty string: the parameter is "present" but carries nothing, which is
/// the silent drop the design says it never does.
#[test]
fn redteam_required_trim_string_cannot_be_satisfied_by_whitespace() {
    init();
    let b = Bumper::new(
        BumperConfig::default(),
        [ParamSpec::required("name", StringSpec::new(16, TrimPolicy::Trim).unwrap())],
    )
    .unwrap();
    let mut passed = Vec::new();
    for ws in ["   ", "\t\n", "\u{3000}\u{2028}\u{00A0}"] {
        let mut m = BTreeMap::new();
        m.insert("name".to_owned(), text(ws));
        if let Ok(n) = b.normalize(&m) {
            passed.push(format!("Trim {ws:?} -> {:?}", n.get("name")));
        }
    }
    // The literal empty string, under every policy.
    for policy in [TrimPolicy::Preserve, TrimPolicy::Trim, TrimPolicy::Reject] {
        let b = Bumper::new(
            BumperConfig::default(),
            [ParamSpec::required("name", StringSpec::new(16, policy).unwrap())],
        )
        .unwrap();
        let mut m = BTreeMap::new();
        m.insert("name".to_owned(), text(""));
        if let Ok(n) = b.normalize(&m) {
            passed.push(format!("{policy:?} \"\" -> {:?}", n.get("name")));
        }
    }
    assert!(passed.is_empty(), "empty value satisfied a required string: {passed:#?}");
}

// ---------------------------------------------------------------------------
// Attack: invisible and control characters in TrimPolicy::Reject identifiers
// ---------------------------------------------------------------------------

/// TrimPolicy::Reject exists "for identifiers, where a silent trim could
/// make two distinct keys look equal". Zero-width, BOM, bidi-override and
/// NUL characters are not whitespace to `str::trim`, so identifiers that
/// render identically to "admin" pass.
#[test]
fn redteam_reject_policy_refuses_invisible_and_control_chars() {
    init();
    let b = Bumper::new(
        BumperConfig::default(),
        [ParamSpec::required("tenant", StringSpec::new(16, TrimPolicy::Reject).unwrap())],
    )
    .unwrap();
    let mut passed = Vec::new();
    for id in [
        "adm\u{200B}in",
        "\u{FEFF}admin",
        "admin\u{0}",
        "\u{202E}nimda",
        "admin\u{1B}[2K",
    ] {
        let mut m = BTreeMap::new();
        m.insert("tenant".to_owned(), text(id));
        if b.normalize(&m).is_ok() {
            passed.push(id.escape_unicode().to_string());
        }
    }
    assert!(passed.is_empty(), "look-alike identifiers passed a Reject string: {passed:?}");
}

// ---------------------------------------------------------------------------
// Attack: raw input and log injection through every log path
// ---------------------------------------------------------------------------

#[test]
fn redteam_logs_never_carry_raw_input_or_injection() {
    init();
    let b = fixture();
    let m_key = "RTKEY\nWARN forged line\u{1B}[31m";
    let m_enum = "RTENUM\r\nERROR forged";
    let m_unit = "RTUNIT\n";
    let m_long = format!("RTLONG{}", "x".repeat(40));
    let m_ws = " RTWS ";
    let m_big = format!("RTBIG{}", "y".repeat(5000));
    let reqs = vec![
        req(&[(m_key, num(1.0))]),
        req(&[("priority", text(m_enum))]),
        req(&[("timeout", qty(1.0, m_unit))]),
        req(&[("label", text(&m_long))]),
        req(&[("tenant", text(m_ws))]),
        req(&[("label", text(&m_big))]),
        req(&[(m_big.as_str(), text(&m_big))]),
        req(&[("label", text(" RTPASS "))]),
    ];
    for r in &reqs {
        let _ = b.normalize(r);
    }
    let l = logs();
    let mut leaked = Vec::new();
    for marker in ["RTKEY", "RTENUM", "RTUNIT", "RTLONG", "RTWS", "RTBIG", "RTPASS", "forged"] {
        if l.contains(marker) {
            leaked.push(marker);
        }
    }
    assert!(leaked.is_empty(), "raw caller text reached logs: {leaked:?}");
    assert!(l.contains(&telemetry::sha256_hex(m_key.as_bytes())), "unknown key digest missing");
    assert!(l.contains(&telemetry::sha256_hex(m_enum.as_bytes())), "enum digest missing");
}

// ---------------------------------------------------------------------------
// Attack: metric label cardinality from hostile input
// ---------------------------------------------------------------------------

#[test]
fn redteam_metric_labels_stay_closed_under_hostile_input() {
    init();
    let recorder = DebuggingRecorder::new();
    let snap = recorder.snapshotter();
    metrics::with_local_recorder(&recorder, || {
        let b = fixture();
        for i in 0..300u32 {
            let k = format!("k{i}\"}}{{outcome=\"pass");
            let mut r = req(&[(k.as_str(), num(f64::from(i)))]);
            r.insert("priority".into(), text(&format!("v{i}")));
            r.insert("timeout".into(), qty(f64::from(i), &format!("u{i}")));
            let _ = b.normalize(&r);
            let _ = b.normalize(&req(&[("priority", text(" HI ")), ("label", text(&format!(" l{} ", i % 7)))]));
        }
    });
    let reasons: BTreeSet<&str> = TripReason::ALL.iter().map(|r| r.as_str()).collect();
    let mut series = BTreeSet::new();
    let mut bad = Vec::new();
    for (ck, _, _, _) in snap.snapshot().into_vec() {
        let key = ck.key();
        let name = key.name().to_owned();
        if !name.starts_with("tack_bumpers_") {
            bad.push(format!("name {name}"));
        }
        let mut ls = Vec::new();
        for l in key.labels() {
            let ok = match l.key() {
                "outcome" => ["pass", "retry", "terminal_breach"].contains(&l.value()),
                "reason" => reasons.contains(l.value()),
                "kind" => CorrectionKind::LABELS.contains(&l.value()),
                _ => false,
            };
            if !ok {
                bad.push(format!("{name} {}={}", l.key(), l.value()));
            }
            ls.push(format!("{}={}", l.key(), l.value()));
        }
        series.insert((name, ls));
    }
    assert!(bad.is_empty(), "open labels: {bad:?}");
    assert!(series.len() <= 3 + 3 + 12 + 5 + 1, "series grew to {}", series.len());
}

// ---------------------------------------------------------------------------
// Attack: log volume amplification (DoS on the log pipeline)
// ---------------------------------------------------------------------------

/// A ~1 KiB request of 64 NaNs produces one WARN line per entry. Nothing
/// rate limits it, so log volume scales with request rate times max_params.
/// Safe behaviour: at most one WARN line per request, with trip counts.
#[test]
fn redteam_one_warn_line_per_request() {
    init();
    let names: Vec<String> = (0..64).map(|i| format!("p{i:02}")).collect();
    let b = Bumper::new(
        BumperConfig::default(),
        names
            .iter()
            .map(|n| ParamSpec::optional(n.as_str(), NumericSpec::new(0.0, 0.0, 1.0, 1.0).unwrap())),
    )
    .unwrap();
    let input: BTreeMap<String, ParamValue> = names.iter().map(|n| (n.clone(), num(f64::NAN))).collect();
    let before = warn_count();
    let rej = b.normalize(&input).unwrap_err();
    let warns = warn_count() - before;
    assert_eq!(rej.outcome, GateOutcome::TerminalBreach);
    assert!(warns <= 1, "one request produced {warns} WARN log events");
}

// ---------------------------------------------------------------------------
// Attack: CPU amplification, oversized unknown keys hashed twice
// ---------------------------------------------------------------------------

/// An unknown key over max_input_bytes is hashed eagerly for the trip record
/// and again lazily by the WARN log line, over its full length. Safe: at
/// most one pass over attacker bytes past the cap (ratio near 1).
#[test]
fn redteam_oversized_unknown_keys_hashed_at_most_once() {
    init();
    let b = fixture();
    let keys: Vec<String> = (0..32).map(|i| format!("{i:02}{}", "k".repeat(4 << 20))).collect();
    let mut input = req(&[]);
    for k in &keys {
        input.insert(k.clone(), num(1.0));
    }
    let t_hash = min_time(3, || {
        for k in &keys {
            std::hint::black_box(telemetry::sha256_hex(k.as_bytes()));
        }
    });
    let t_norm = min_time(3, || {
        let r = b.normalize(std::hint::black_box(&input)).unwrap_err();
        assert!(r.has(TripReason::InputTooLarge));
    });
    let ratio = t_norm.as_secs_f64() / t_hash.as_secs_f64();
    eprintln!("hash-once {t_hash:?}, normalize {t_norm:?}, ratio {ratio:.2}");
    assert!(ratio <= 1.5, "normalize did {ratio:.2}x the work of hashing the keys once");
}

// ---------------------------------------------------------------------------
// Attack: work past the cap scales with attacker size
// ---------------------------------------------------------------------------

/// A known string parameter with text over max_input_bytes is refused, but
/// the WARN line hashes the whole value. Refusal work should be bounded by
/// the cap, not by the attacker's size.
#[test]
fn redteam_oversize_refusal_work_is_bounded_by_cap() {
    init();
    let b = fixture();
    let small = req(&[("label", text(&"z".repeat(4097)))]);
    let large = req(&[("label", text(&"z".repeat(64 << 20)))]);
    let t_small = min_time(5, || {
        let _ = b.normalize(std::hint::black_box(&small));
    });
    let t_large = min_time(3, || {
        let r = b.normalize(std::hint::black_box(&large)).unwrap_err();
        assert!(r.has(TripReason::InputTooLarge));
    });
    eprintln!("4097 B refusal {t_small:?}, 64 MiB refusal {t_large:?}");
    assert!(
        t_large <= t_small * 20 + Duration::from_millis(2),
        "refusal of 64 MiB took {t_large:?} vs {t_small:?} at the cap"
    );
}

// ---------------------------------------------------------------------------
// Attack: over max_params refusal is cheap (does not read entries)
// ---------------------------------------------------------------------------

#[test]
fn redteam_too_many_params_refused_before_reading_entries() {
    init();
    let b = fixture();
    let input: BTreeMap<String, ParamValue> = (0..65)
        .map(|i| (format!("{i:02}{}", "q".repeat(1 << 20)), text(&"v".repeat(1 << 16))))
        .collect();
    let t_hash = min_time(3, || {
        for k in input.keys() {
            std::hint::black_box(telemetry::sha256_hex(k.as_bytes()));
        }
    });
    let t_norm = min_time(3, || {
        let r = b.normalize(std::hint::black_box(&input)).unwrap_err();
        assert_eq!(r.outcome, GateOutcome::TerminalBreach);
        assert_eq!(r.trips.len(), 1);
        assert!(r.has(TripReason::TooManyParams));
    });
    eprintln!("hash {t_hash:?}, normalize {t_norm:?}");
    assert!(t_norm * 10 < t_hash, "over-cap refusal read the entries");
}

// ---------------------------------------------------------------------------
// Attack: unit confusion
// ---------------------------------------------------------------------------

#[test]
fn redteam_unit_confusion_is_refused_not_guessed() {
    init();
    let b = fixture();
    for u in ["MS", "Ms", " ms", "ms ", "ms\u{0}", "m\u{200B}s", "\u{FF4D}\u{FF53}", "", "S"] {
        let r = b.normalize(&req(&[("timeout", qty(1500.0, u))])).unwrap_err();
        assert_eq!(r.outcome, GateOutcome::Retry, "unit {u:?}");
        assert!(r.has(TripReason::UnknownUnit), "unit {u:?}");
    }
    // A unit on a parameter with no unit table.
    let r = b.normalize(&req(&[("ratio", qty(0.1, "s"))])).unwrap_err();
    assert!(r.has(TripReason::UnknownUnit));
    // A bare 1500 meant as ms is not reinterpreted by size: it is clamped
    // visibly, never silently rescaled to 1.5.
    let n = b.normalize(&req(&[("timeout", num(1500.0))]));
    assert!(n.is_err(), "1500 is past hard_max 300");
    let n = b.normalize(&req(&[("timeout", num(200.0))])).unwrap();
    assert_eq!(n.get("timeout").unwrap().as_f64(), Some(30.0));
    assert!(matches!(n.corrections()[0].kind, CorrectionKind::Clamped { .. }));
    // Conversion overflow is TERMINAL, never infinity passed on.
    let r = b.normalize(&req(&[("timeout", qty(f64::MAX, "min"))])).unwrap_err();
    assert_eq!(r.outcome, GateOutcome::TerminalBreach);
    assert!(r.has(TripReason::OutsideHardBand));
}

// ---------------------------------------------------------------------------
// Attack: negative zero through unit conversion underflow
// ---------------------------------------------------------------------------

#[test]
fn redteam_negative_zero_never_escapes_through_conversion() {
    init();
    let b = Bumper::new(
        BumperConfig {
            correction_budget: 0,
            ..BumperConfig::default()
        },
        [ParamSpec::required(
            "x",
            NumericSpec::new(-1.0, -1.0, 1.0, 1.0)
                .unwrap()
                .with_units(
                    "s",
                    &[("ms", UnitScale::Divide(1000.0)), ("tiny", UnitScale::Multiply(1e-300))],
                )
                .unwrap(),
        )],
    )
    .unwrap();
    for v in [qty(-1e-320, "ms"), qty(-1e-30, "tiny"), num(-0.0), qty(-0.0, "s")] {
        let budget_free = matches!(v, ParamValue::Number(_)) || matches!(&v, ParamValue::Quantity { unit, .. } if unit == "s");
        let mut m = BTreeMap::new();
        m.insert("x".to_owned(), v.clone());
        match b.normalize(&m) {
            Ok(n) => {
                let x = n.get("x").unwrap().as_f64().unwrap();
                assert_eq!(x.to_bits(), 0.0f64.to_bits(), "{v:?} produced {x:e} bits {:x}", x.to_bits());
            }
            Err(r) => {
                // Budget 0 refuses the unit conversion; that is allowed.
                assert!(!budget_free, "{v:?} refused: {r:?}");
                assert!(r.has(TripReason::CorrectionBudgetExceeded));
            }
        }
    }
    let loose = Bumper::new(
        BumperConfig::default(),
        [ParamSpec::required(
            "x",
            NumericSpec::new(-1.0, -1.0, 1.0, 1.0)
                .unwrap()
                .with_units("s", &[("ms", UnitScale::Divide(1000.0))])
                .unwrap(),
        )],
    )
    .unwrap();
    // -5e-324 (the smallest negative subnormal) divided by 1000 underflows
    // to exactly -0.0, which must come out as +0.0.
    let underflow = -5e-324f64 / std::hint::black_box(1000.0);
    assert_eq!(underflow.to_bits(), (-0.0f64).to_bits(), "fixture: division must underflow to -0.0");
    let mut m = BTreeMap::new();
    m.insert("x".to_owned(), qty(-5e-324, "ms"));
    let x = loose.normalize(&m).unwrap().get("x").unwrap().as_f64().unwrap();
    assert_eq!(x.to_bits(), 0.0f64.to_bits(), "negative zero escaped: bits {:x}", x.to_bits());
    // A negative subnormal that does NOT underflow is a real value and must
    // pass unchanged (subnormals are never flushed to zero).
    let mut m = BTreeMap::new();
    m.insert("x".to_owned(), qty(-1e-320, "ms"));
    let x = loose.normalize(&m).unwrap().get("x").unwrap().as_f64().unwrap();
    assert_eq!(x.to_bits(), (-1e-320f64 / 1000.0).to_bits());
}

// ---------------------------------------------------------------------------
// Attack: correction budget edge and stacking
// ---------------------------------------------------------------------------

#[test]
fn redteam_budget_cannot_be_exceeded_by_stacking() {
    init();
    let b = fixture();
    // 3 (trim, fold, alias) + 2 (unit, clamp) = 5 > 3.
    let r = b
        .normalize(&req(&[("priority", text(" HI ")), ("timeout", qty(200_000.0, "ms"))]))
        .unwrap_err();
    assert_eq!(r.outcome, GateOutcome::Retry);
    assert!(r.has(TripReason::CorrectionBudgetExceeded));
    // Exactly the budget passes.
    let n = b.normalize(&req(&[("priority", text(" HI "))])).unwrap();
    assert_eq!(n.corrections().len(), 3);
    // A NaN alongside budget exhaustion still wins as TERMINAL.
    let r = b
        .normalize(&req(&[("priority", text(" HI ")), ("label", text(" a ")), ("ratio", num(f64::NAN))]))
        .unwrap_err();
    assert_eq!(r.outcome, GateOutcome::TerminalBreach);
    assert!(r.has(TripReason::CorrectionBudgetExceeded) && r.has(TripReason::NonFinite));
}

// ---------------------------------------------------------------------------
// Attack: ordering, every entry evaluated, trips bounded
// ---------------------------------------------------------------------------

#[test]
fn redteam_every_entry_evaluated_regardless_of_order() {
    init();
    let b = fixture();
    // First key ("a...") and last key ("z...") both trip, plus middle ones.
    let mut m = req(&[
        ("aaa", num(1.0)),
        ("ratio", num(f64::INFINITY)),
        ("tenant", text(" x ")),
        ("zzz", num(1.0)),
    ]);
    m.remove("priority");
    let r = b.normalize(&m).unwrap_err();
    let reasons: Vec<&str> = r.trips.iter().map(|t| t.reason.as_str()).collect();
    assert_eq!(r.trips.len(), 5, "{reasons:?}");
    assert_eq!(r.outcome, GateOutcome::TerminalBreach);
    // 64 unknown keys plus both required missing: bounded by max_params + specs + 1.
    let m: BTreeMap<String, ParamValue> = (0..64).map(|i| (format!("u{i}"), num(1.0))).collect();
    let r = b.normalize(&m).unwrap_err();
    assert_eq!(r.trips.len(), 66);
}

// ---------------------------------------------------------------------------
// Attack: shared state under concurrency, and time of check to time of use
// ---------------------------------------------------------------------------

#[test]
fn redteam_shared_bumper_is_deterministic_across_threads() {
    init();
    let b = Arc::new(fixture());
    let inputs = Arc::new(vec![
        req(&[("priority", text(" HI "))]),
        req(&[("timeout", qty(1500.0, "ms"))]),
        req(&[("ratio", num(f64::NAN))]),
        req(&[("zz", num(1.0))]),
        req(&[("label", text("  ok  "))]),
    ]);
    let expected: Vec<_> = inputs.iter().map(|i| b.normalize(i)).collect();
    let handles: Vec<_> = (0..8)
        .map(|_| {
            let b = Arc::clone(&b);
            let inputs = Arc::clone(&inputs);
            std::thread::spawn(move || {
                let mut out = Vec::new();
                for _ in 0..200 {
                    for i in inputs.iter() {
                        out.push(b.normalize(i));
                    }
                }
                out
            })
        })
        .collect();
    for h in handles {
        let out = h.join().unwrap();
        for (i, got) in out.iter().enumerate() {
            assert_eq!(got, &expected[i % expected.len()]);
        }
    }
    // The verdict owns its values; mutating the input afterwards cannot
    // change what was approved.
    let mut input = req(&[("label", text("safe"))]);
    let n = b.normalize(&input).unwrap();
    input.insert("label".into(), text("evil"));
    assert_eq!(n.get("label").unwrap().as_str(), Some("safe"));
}

// ---------------------------------------------------------------------------
// Attack: raw input echoed through the returned Rejection (Display / Debug)
// ---------------------------------------------------------------------------

/// Callers commonly log `{err}` or `{err:?}`. Neither form may carry caller
/// text: unknown keys, bad enum text, bad units or oversized strings.
#[test]
fn redteam_rejection_never_echoes_raw_input() {
    init();
    let b = fixture();
    let secret_key = "RAWKEY-sk_live_0123456789";
    let secret_enum = "RAWENUM-hunter2";
    let secret_unit = "RAWUNIT-x";
    let r = b
        .normalize(&req(&[
            (secret_key, text("RAWVAL-under-unknown")),
            ("priority", text(secret_enum)),
            ("timeout", qty(1.0, secret_unit)),
            ("label", text(&format!("RAWLONG{}", "q".repeat(40)))),
        ]))
        .unwrap_err();
    let shown = format!("{r} || {r:?}");
    assert!(!shown.contains("RAW"), "rejection echoed raw input: {shown}");
    assert!(shown.contains(&telemetry::sha256_hex(secret_key.as_bytes())), "unknown key digest missing");
    assert_eq!(r.trips.len(), 4);
}

// ---------------------------------------------------------------------------
// Attack: telemetry gaps on the early-return path and on refused corrections
// ---------------------------------------------------------------------------

/// The over-max_params path returns before the per-entry loop. It must still
/// count the request and the trip. A refused request must not count its
/// discarded corrections, or corrections_total would be inflatable by an
/// attacker without anything being applied.
#[test]
fn redteam_metrics_fire_on_every_path() {
    init();
    let recorder = DebuggingRecorder::new();
    let snap = recorder.snapshotter();
    metrics::with_local_recorder(&recorder, || {
        let b = fixture();
        let over: BTreeMap<String, ParamValue> = (0..65).map(|i| (format!("k{i}"), num(1.0))).collect();
        let _ = b.normalize(&over).unwrap_err();
        // 5 corrections computed, refused on budget: nothing applied.
        let r = b
            .normalize(&req(&[("priority", text(" HI ")), ("timeout", qty(200_000.0, "ms"))]))
            .unwrap_err();
        assert!(r.has(TripReason::CorrectionBudgetExceeded));
    });
    let mut counters: BTreeMap<String, u64> = BTreeMap::new();
    for (ck, _, _, v) in snap.snapshot().into_vec() {
        let key = ck.key();
        let mut id = key.name().to_owned();
        let mut labels: Vec<String> = key.labels().map(|l| format!("{}={}", l.key(), l.value())).collect();
        labels.sort();
        id.push_str(&format!("{{{}}}", labels.join(",")));
        if let metrics_util::debugging::DebugValue::Counter(c) = v {
            counters.insert(id, c);
        }
    }
    assert_eq!(
        counters.get("tack_bumpers_requests_total{outcome=terminal_breach}"),
        Some(&1),
        "{counters:#?}"
    );
    assert_eq!(
        counters.get("tack_bumpers_trips_total{outcome=terminal_breach,reason=too_many_params}"),
        Some(&1),
        "{counters:#?}"
    );
    assert_eq!(counters.get("tack_bumpers_requests_total{outcome=retry}"), Some(&1), "{counters:#?}");
    assert!(
        !counters.keys().any(|k| k.starts_with("tack_bumpers_corrections_total")),
        "refused corrections were counted: {counters:#?}"
    );
}

// ---------------------------------------------------------------------------
// Attack: Unicode look-alikes slipping through ASCII case folding
// ---------------------------------------------------------------------------

/// Kelvin sign (U+212A) and Turkish dotted capital I (U+0130) lowercase to
/// ASCII `k` and `i` under full Unicode folding. ASCII-only folding must not
/// map them onto declared names, and full-width letters must not match.
#[test]
fn redteam_enum_fold_is_ascii_only() {
    init();
    let b = Bumper::new(
        BumperConfig::default(),
        [ParamSpec::required(
            "mode",
            tack_bumpers::EnumSpec::new([
                tack_bumpers::VariantSpec::new("kill"),
                tack_bumpers::VariantSpec::new("strasse"),
            ])
            .unwrap(),
        )],
    )
    .unwrap();
    for bad in ["\u{212A}ill", "K\u{0130}LL", "stra\u{00DF}e", "\u{FF4B}ill", "kil\u{0301}l", "kill\u{0}"] {
        let mut m = BTreeMap::new();
        m.insert("mode".to_owned(), text(bad));
        let r = b.normalize(&m).unwrap_err();
        assert!(r.has(TripReason::UnknownVariant), "{} was not unknown_variant", bad.escape_unicode());
    }
    let mut m = BTreeMap::new();
    m.insert("mode".to_owned(), text("KILL"));
    assert_eq!(b.normalize(&m).unwrap().get("mode").unwrap().as_str(), Some("kill"));
}

// ---------------------------------------------------------------------------
// Attack: extreme config values (integer confusion, overflow, panics)
// ---------------------------------------------------------------------------

/// Caps at their integer limits must not panic (overflow checks are on) or
/// allocate by cap, and budget u32::MAX must not wrap into a strict budget.
#[test]
fn redteam_extreme_config_values_do_not_panic() {
    init();
    let cfg = BumperConfig {
        correction_budget: u32::MAX,
        max_params: usize::MAX,
        max_input_bytes: usize::MAX,
        max_name_bytes: usize::MAX,
        max_enum_names: usize::MAX,
        max_units: usize::MAX,
    };
    let b = common::fixture_with(cfg);
    let n = b
        .normalize(&req(&[("priority", text(" HI ")), ("timeout", qty(200_000.0, "ms")), ("label", text(" a "))]))
        .unwrap();
    assert_eq!(n.corrections().len(), 6);
    let _ = b.normalize(&req(&[("zz", text(&"z".repeat(1 << 16)))])).unwrap_err();
}

// ---------------------------------------------------------------------------
// Attack: ambiguous specs accepted at build time
// ---------------------------------------------------------------------------

/// An alias of one variant equal (after ASCII folding) to another variant's
/// canonical name would let the attacker pick the meaning. Must be refused
/// when the spec is built, as must more specs than max_params.
#[test]
fn redteam_ambiguous_specs_refused_at_build() {
    init();
    use tack_bumpers::{EnumSpec, SpecError, VariantSpec};
    let e = EnumSpec::new([VariantSpec::new("allow"), VariantSpec::new("deny").alias("ALLOW")]);
    assert!(matches!(e, Err(SpecError::AliasCollision { .. })), "{e:?}");
    let e = EnumSpec::new([VariantSpec::new("allow").alias("Allow")]);
    assert!(matches!(e, Err(SpecError::AliasCollision { .. })), "{e:?}");
    let many = (0..3).map(|i| ParamSpec::optional(format!("p{i}"), NumericSpec::new(0.0, 0.0, 1.0, 1.0).unwrap()));
    let r = Bumper::new(
        BumperConfig {
            max_params: 2,
            ..BumperConfig::default()
        },
        many,
    );
    assert!(matches!(r, Err(SpecError::TooManyParams { .. })));
    let r = std::panic::catch_unwind(|| {
        common::fixture_with(BumperConfig {
            max_params: 1,
            ..BumperConfig::default()
        })
    });
    assert!(r.is_err(), "fixture with 5 specs built under max_params 1");
}
