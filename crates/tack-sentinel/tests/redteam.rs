//! Red-team attacks on tack-sentinel, written by an independent tester.
//!
//! Every test asserts the SAFE behaviour. A test that fails marks a weakness
//! that still exists; its failure message names the attack and what the
//! crate did instead. Heavy or crash-prone attacks (memory peaks, deep
//! nesting, span capture) run in a fresh copy of this test binary so a
//! stack overflow or a memory spike cannot disturb the other tests.
//!
//! Every key here is a TEST FIXTURE, never a real secret.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use std::collections::HashMap;
use std::fmt;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use metrics_util::debugging::DebuggingRecorder;
use proptest::prelude::*;
use tack_sentinel::anchor::{anchor_payload, HeadAnchor};
use tack_sentinel::attest::verify_signature;
use tack_sentinel::canonical::{canonical_form, content_prehash};
use tack_sentinel::pyjson::{dumps, Object, PyInt, Separators, Value};
use tack_sentinel::telemetry::{
    INPUT_REJECTED_TOTAL, ROWS_CHECKED_TOTAL, TRIPS_TOTAL, VERIFICATIONS_TOTAL, VERIFY_DURATION_SECONDS,
};
use tack_sentinel::{
    deep_verify_row, recompute_current_hash, subject_digest, GateOutcome, KeySet, LedgerRow, Reason, Report, Verdict,
    Verifier, VerifierConfig, VerifyError,
};

const PRE: &str = "ledger_export_pre_receipts.json";
const POST: &str = "differential/base_post_receipts.json";
/// Marker planted in attacker-controlled fields. It must never reach a
/// report line, a metric label or a tracing field.
const MARK: &str = "PWNED-MARKER";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn post() -> (Value, Vec<Object>) {
    (common::columns(POST), common::base_rows(POST))
}

fn fixture_verifier() -> Verifier {
    common::verifier(&[common::FIXTURE_KEY])
}

fn run(v: &Verifier, cols: &Value, rows: &[Object], anchor: &[u8]) -> Report {
    v.verify_export(&common::export_bytes(cols, rows), Some(anchor)).unwrap()
}

fn summary(r: &Report) -> String {
    format!(
        "verdict={} outcome={} resolution={:?} first={:?} also={:?} rows_checked={}/{}",
        r.verdict(),
        r.gate_outcome().as_str(),
        r.resolution(),
        r.finding.as_ref().map(|f| (f.reason, f.row_id)),
        r.also.as_ref().map(|f| (f.reason, f.row_id)),
        r.rows_checked,
        r.rows_total
    )
}

/// A signed v1 head anchor with any head and count (as a key holder makes it).
fn anchor_raw(head: &str, entries: PyInt, key: &[u8]) -> Vec<u8> {
    let mut a = HeadAnchor {
        head: head.to_owned(),
        entries,
        sealed_at: "2026-09-30T00:00:00+00:00".into(),
        key_fingerprint: tack_sentinel::key_fingerprint(key),
        hmac: String::new(),
    };
    a.hmac = common::hmac_hex(key, &anchor_payload(&a));
    let mut o = Object::new();
    o.insert("v".into(), Value::Int(PyInt::from_i64(1)));
    o.insert("head".into(), Value::Str(a.head));
    o.insert("entries".into(), Value::Int(a.entries));
    o.insert("sealed_at".into(), Value::Str(a.sealed_at));
    o.insert("key_fingerprint".into(), Value::Str(a.key_fingerprint));
    o.insert("hmac".into(), Value::Str(a.hmac));
    dumps(&Value::Object(o), Separators::Python).into_bytes()
}

/// Recompute one row's hash in place, as an attacker holding the file can.
fn rehash(row: &mut Object) {
    let h = recompute_current_hash(row).unwrap();
    row.insert("current_hash".into(), Value::Str(h));
}

const CHILD_ENV: &str = "TACK_SENTINEL_REDTEAM_CHILD";

/// Run `work` in a fresh copy of this test binary. Returns `None` inside the
/// child (after `work` ran) and `Some((success, stdout, stderr))` in the parent.
fn in_child(name: &str, work: impl FnOnce()) -> Option<(bool, String, String)> {
    if std::env::var(CHILD_ENV).as_deref() == Ok(name) {
        work();
        return None;
    }
    let out = std::process::Command::new(std::env::current_exe().unwrap())
        .args([name, "--exact", "--nocapture", "--test-threads=1"])
        .env(CHILD_ENV, name)
        .output()
        .unwrap();
    Some((
        out.status.success(),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    ))
}

fn status_kb(field: &str) -> u64 {
    let s = std::fs::read_to_string("/proc/self/status").unwrap();
    s.lines()
        .find(|l| l.starts_with(field))
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|v| v.parse().ok())
        .unwrap()
}

/// Peak resident memory added by `work`, in bytes (Linux only).
fn peak_delta(work: impl FnOnce()) -> u64 {
    // Reset the high-water mark to the current RSS (Linux 4.0 and later).
    std::fs::write("/proc/self/clear_refs", "5").unwrap();
    let base = status_kb("VmRSS:");
    work();
    let peak = status_kb("VmHWM:");
    peak.saturating_sub(base) * 1024
}

fn parse_kv(out: &str, key: &str) -> u64 {
    out.split_whitespace()
        .find_map(|w| w.strip_prefix(&format!("{key}=")))
        .and_then(|v| v.parse().ok())
        .unwrap_or_else(|| panic!("child printed no {key}: {out}"))
}

/// The documented bound (VerifierConfig::max_export_bytes docs): a parsed
/// export takes "roughly ten times" its text size, "so this also caps
/// memory near 640 MiB".
const DOCUMENTED_MEMORY_FACTOR: u64 = 10;

fn median(mut v: Vec<Duration>) -> Duration {
    v.sort();
    v[v.len() / 2]
}

fn time_it(f: impl Fn()) -> Duration {
    median(
        (0..3)
            .map(|_| {
                let t = Instant::now();
                f();
                t.elapsed()
            })
            .collect(),
    )
}

// ---------------------------------------------------------------------------
// 1. Outcome downgrade: a signature naming an unknown key is RETRY
// ---------------------------------------------------------------------------

/// A forged authorization appended after the last anchor, signed with a
/// fingerprint the attacker made up. sentinel_os's own verify_chain calls
/// UNKNOWN_KEY "a violation ALWAYS ... the one outcome that cannot be
/// configured away", and the chain's attestation_policy marker names the one
/// enforced key. The crate reports RETRY (reject): "supply the key and
/// resubmit", for a key that does not exist.
#[test]
fn redteam_forged_claim_with_made_up_fingerprint_is_not_retryable() {
    let (cols, base) = post();
    let mut rows = base.clone();
    let mut forged = rows[15].clone();
    forged.insert("id".into(), Value::Int(PyInt::from_i64(17)));
    forged.insert("previous_hash".into(), rows[15]["current_hash"].clone());
    forged.insert("authorized_by".into(), Value::Str("cfo@attacker.example".into()));
    forged.insert(
        "authorized_by_sig".into(),
        Value::Str(format!("abv3.0123456789abcdef.{}", "a".repeat(64))),
    );
    rehash(&mut forged);
    rows.push(forged);
    let anchor = common::anchor_bytes(&base, base.len(), common::FIXTURE_KEY);
    let r = run(&fixture_verifier(), &cols, &rows, &anchor);
    assert_ne!(r.verdict(), Verdict::Verified);
    assert_eq!(
        r.gate_outcome(),
        GateOutcome::TerminalBreach,
        "a forged claim naming a made-up key must not be repairable by resubmission: {}",
        summary(&r)
    );
}

/// The chain walk stops at the first failing row. When that row's finding is
/// RETRY, every later row goes unchecked. Two unhashed columns on the
/// legacy first row (authorized_by and a junk abv2 signature; neither is in
/// the base-row canonical form, so no rehash is needed) hide a real content
/// edit further down the chain. The anchor only compares the head string,
/// which the attacker left alone, so no TERMINAL finding appears at all and
/// the tamper-evidence alert never fires.
#[test]
fn redteam_unknown_key_on_first_row_masks_later_tampering() {
    let (cols, base) = post();
    let mut rows = base.clone();
    // The real attack: change the amount a decision judged, no rechain.
    let Value::Object(mut input) = rows[7]["input_data"].clone() else { panic!() };
    input.insert("amount".into(), Value::Int(PyInt::from_i64(999_999_999)));
    rows[7].insert("input_data".into(), Value::Object(input));
    // The mask: unhashed columns on the legacy row 1.
    rows[0].insert("authorized_by".into(), Value::Str("nobody".into()));
    rows[0].insert(
        "authorized_by_sig".into(),
        Value::Str(format!("abv2.fedcba9876543210.{}", "b".repeat(64))),
    );
    assert_eq!(recompute_current_hash(&rows[0]).unwrap(), base[0]["current_hash"].as_str().unwrap());
    let anchor = common::anchor_bytes(&base, base.len(), common::FIXTURE_KEY);

    let recorder = DebuggingRecorder::new();
    let snap = recorder.snapshotter();
    let r = metrics::with_local_recorder(&recorder, || run(&fixture_verifier(), &cols, &rows, &anchor));
    let breach_trips: u64 = snap
        .snapshot()
        .into_vec()
        .into_iter()
        .filter(|(k, ..)| {
            k.key().name() == TRIPS_TOTAL && k.key().labels().any(|l| l.key() == "outcome" && l.value() == "terminal_breach")
        })
        .map(|(.., v)| match v {
            metrics_util::debugging::DebugValue::Counter(c) => c,
            _ => 0,
        })
        .sum();
    assert_eq!(
        r.gate_outcome(),
        GateOutcome::TerminalBreach,
        "row 8 was edited (hash mismatch) but the report says RETRY: {}",
        summary(&r)
    );
    assert!(breach_trips > 0, "TackSentinelTamperEvidence would not fire");
}

/// Report::gate_outcome looks only at the first finding. A TERMINAL anchor
/// finding (tail cut after sealing) in `also` does not raise the report's
/// outcome, so a caller acting on gate_outcome() treats a truncated ledger
/// as repairable.
#[test]
fn redteam_terminal_anchor_finding_in_also_is_ignored_by_gate_outcome() {
    let (cols, base) = post();
    let mut rows = base.clone();
    rows.truncate(13); // cut the last three rows
    rows[0].insert("authorized_by".into(), Value::Str("nobody".into()));
    rows[0].insert(
        "authorized_by_sig".into(),
        Value::Str(format!("abv2.fedcba9876543210.{}", "b".repeat(64))),
    );
    let anchor = common::anchor_bytes(&base, base.len(), common::FIXTURE_KEY);
    let r = run(&fixture_verifier(), &cols, &rows, &anchor);
    let also_terminal = r.also.as_ref().map(|f| f.reason.gate_outcome()) == Some(GateOutcome::TerminalBreach);
    assert!(also_terminal, "precondition: the anchor finding is terminal: {}", summary(&r));
    assert_eq!(
        r.gate_outcome(),
        GateOutcome::TerminalBreach,
        "a truncated ledger is reported as repairable: {}",
        summary(&r)
    );
}

// ---------------------------------------------------------------------------
// 2. Retired keys and key sets with no trusted key
// ---------------------------------------------------------------------------

/// sentinel_os documents RETIRED as keys "the operator has deliberately
/// stopped trusting (a suspected compromise, a policy sunset)", and its
/// verify_chain treats a retired-key signature as a violation under
/// enforcement (on by default). The crate accepts it.
#[test]
fn redteam_signature_valid_only_under_retired_key_is_accepted() {
    let (_, rows) = post();
    let keys = KeySet::new(
        None,
        vec![common::key(common::OTHER_KEY)],
        vec![common::key(common::FIXTURE_KEY)],
    );
    let row = LedgerRow {
        id: 3,
        columns: rows[2].clone(),
    };
    let got = deep_verify_row(&row, &keys);
    assert!(
        got.is_err(),
        "an abv3 signature valid only under a distrusted (retired) key passed deep_verify_row"
    );
}

/// An attacker holding a compromised, since-retired key cuts the tail and
/// forges a fresh anchor for the shorter chain. The crate accepts an anchor
/// under a retired key, so truncation is VERIFIED.
#[test]
fn redteam_anchor_signed_by_retired_key_vouches_for_truncation() {
    let (cols, base) = post();
    let mut rows = base.clone();
    rows.truncate(13);
    let forged = common::anchor_bytes(&rows, rows.len(), common::OTHER_KEY);
    let keys = KeySet::new(
        None,
        vec![common::key(common::FIXTURE_KEY)],
        vec![common::key(common::OTHER_KEY)],
    );
    let v = Verifier::new(VerifierConfig::default(), keys).unwrap();
    let r = run(&v, &cols, &rows, &forged);
    assert_ne!(
        r.verdict(),
        Verdict::Verified,
        "a tail cut vouched for by a distrusted key verified: {}",
        summary(&r)
    );
}

/// Verifier::new "refuses to run with no trusted key", but only checks that
/// the key set is non-empty. A set holding only retired keys passes, and
/// then prints VERIFIED with zero trusted keys.
#[test]
fn redteam_verifier_with_only_retired_keys_is_refused() {
    let keys = KeySet::new(None, vec![], vec![common::key(common::FIXTURE_KEY)]);
    assert_eq!(keys.trusted_len(), 0);
    match Verifier::new(VerifierConfig::default(), keys) {
        Err(VerifyError::NoTrustedKeyMaterial) => {}
        Err(e) => panic!("refused, but for the wrong reason: {e}"),
        Ok(v) => {
            let cols = common::columns(PRE);
            let rows = common::base_rows(PRE);
            let anchor = common::anchor_bytes(&rows, rows.len(), common::FIXTURE_KEY);
            let r = run(&v, &cols, &rows, &anchor);
            panic!(
                "a verifier with zero trusted keys was built and printed: {}",
                summary(&r)
            );
        }
    }
}

// ---------------------------------------------------------------------------
// 3. Memory and CPU amplification
// ---------------------------------------------------------------------------

/// `[0,0,0,...]` in an unused top-level field: each two input bytes become a
/// 32-byte Value plus a separate heap allocation for the digit string.
#[test]
fn redteam_memory_amplification_small_ints() {
    let Some((ok, out, err)) = in_child("redteam_memory_amplification_small_ints", || {
        let n = 8 * 1024 * 1024;
        let mut s = Vec::with_capacity(2 * n + 128);
        s.extend_from_slice(br#"{"format": "sentinel_os.ledger_export.v1", "rows": [], "pad": ["#);
        for i in 0..n {
            if i > 0 {
                s.push(b',');
            }
            s.push(b'0');
        }
        s.extend_from_slice(b"]}");
        let v = fixture_verifier();
        let delta = peak_delta(|| {
            let r = v.verify_export(&s, None).unwrap();
            assert_eq!(r.finding.unwrap().reason, Reason::AnchorMissing);
        });
        println!("REDTEAM peak={delta} input={}", s.len());
    }) else {
        return;
    };
    assert!(ok, "child failed: {out}\n{err}");
    let (peak, input) = (parse_kv(&out, "peak"), parse_kv(&out, "input"));
    assert!(
        peak <= DOCUMENTED_MEMORY_FACTOR * input,
        "peak memory {peak} bytes for a {input} byte export is {:.1}x, over the documented {DOCUMENTED_MEMORY_FACTOR}x \
         (at the 64 MiB default cap that is about {} MiB)",
        peak as f64 / input as f64,
        (peak as f64 / input as f64 * 64.0) as u64
    );
}

/// A signature of 16 MiB of dots on a hashed column (the attacker rehashes
/// the row). verify_signature splits it into a Vec<&str> with one 16-byte
/// entry per dot, and clones the text first.
#[test]
fn redteam_memory_amplification_dotted_signature() {
    let Some((ok, out, err)) = in_child("redteam_memory_amplification_dotted_signature", || {
        let (cols, mut rows) = post();
        rows[15].insert("authorized_by_sig".into(), Value::Str(".".repeat(16 * 1024 * 1024)));
        rehash(&mut rows[15]);
        let anchor = common::anchor_bytes(&rows, rows.len(), common::FIXTURE_KEY);
        let export = common::export_bytes(&cols, &rows);
        drop(rows);
        let v = fixture_verifier();
        let delta = peak_delta(|| {
            let r = v.verify_export(&export, Some(&anchor)).unwrap();
            assert_eq!(r.finding.unwrap().reason, Reason::SignatureInvalid);
        });
        println!("REDTEAM peak={delta} input={}", export.len());
    }) else {
        return;
    };
    assert!(ok, "child failed: {out}\n{err}");
    let (peak, input) = (parse_kv(&out, "peak"), parse_kv(&out, "input"));
    assert!(
        peak <= DOCUMENTED_MEMORY_FACTOR * input,
        "peak memory {peak} bytes for a {input} byte export is {:.1}x, over the documented {DOCUMENTED_MEMORY_FACTOR}x",
        peak as f64 / input as f64
    );
}

/// The seed check HMACs a payload containing record_kind under every held
/// key. On a base-form row neither record_kind nor shuffle_seed is hashed,
/// so the attacker needs no rehash: a large record_kind plus any seed costs
/// one HMAC over the large value per held key (64 at the CLI cap).
#[test]
fn redteam_seed_check_cost_scales_with_key_count_times_attacker_size() {
    let (cols, base) = post();
    let mut keys: Vec<Vec<u8>> = vec![common::FIXTURE_KEY.to_vec()];
    for i in 1..64 {
        keys.push(format!("redteam-test-fixture-key-{i}-not-a-real-secret").into_bytes());
    }
    let key_refs: Vec<&[u8]> = keys.iter().map(Vec::as_slice).collect();
    let v = common::verifier(&key_refs);
    let anchor = common::anchor_bytes(&base, base.len(), common::FIXTURE_KEY);

    let mut plain = base.clone();
    plain[0].insert("record_kind".into(), Value::Str("L".repeat(512 * 1024)));
    let mut seeded = plain.clone();
    seeded[0].insert("shuffle_seed".into(), Value::Str("x".into()));
    let plain_bytes = common::export_bytes(&cols, &plain);
    let seeded_bytes = common::export_bytes(&cols, &seeded);

    let r_plain = v.verify_export(&plain_bytes, Some(&anchor)).unwrap();
    let r_seeded = v.verify_export(&seeded_bytes, Some(&anchor)).unwrap();
    assert_eq!(r_plain.verdict(), Verdict::Verified, "{}", summary(&r_plain));
    assert_eq!(r_seeded.verdict(), Verdict::SeedForged, "{}", summary(&r_seeded));

    let t_plain = time_it(|| {
        v.verify_export(&plain_bytes, Some(&anchor)).unwrap();
    });
    let t_seeded = time_it(|| {
        v.verify_export(&seeded_bytes, Some(&anchor)).unwrap();
    });
    let ratio = t_seeded.as_secs_f64() / t_plain.as_secs_f64();
    assert!(
        ratio <= 4.0,
        "a one-byte seed on the same {} byte export made verification {ratio:.1}x slower ({t_plain:?} to {t_seeded:?}) \
         with 64 keys held",
        seeded_bytes.len()
    );
}

/// verify_export hashes the whole export for telemetry before the size cap
/// is checked, so an over-budget input costs full-size work before refusal.
#[test]
fn redteam_oversized_export_is_hashed_before_the_cap() {
    let cfg = VerifierConfig {
        max_export_bytes: 1024,
        ..VerifierConfig::default()
    };
    let v = Verifier::new(cfg, common::verifier_keys()).unwrap();
    let huge = vec![b' '; 64 * 1024 * 1024];
    let t = Instant::now();
    let got = v.verify_export(&huge, None);
    let took = t.elapsed();
    assert!(matches!(got, Err(VerifyError::ExportTooLarge { .. })));
    assert!(
        took < Duration::from_millis(100),
        "refusing a 64 MiB export over a 1 KiB cap took {took:?}: it was processed before the cap"
    );
}

/// The anchor is hashed for the parse_anchor span field before its size
/// cap. Tracing evaluates span fields only when a subscriber is listening,
/// so this runs with one installed, as a deployed verifier would have.
#[test]
fn redteam_oversized_anchor_is_hashed_before_the_cap() {
    let Some((ok, out, err)) = in_child("redteam_oversized_anchor_is_hashed_before_the_cap", || {
        let sub = Collect {
            log: Arc::new(Mutex::new(Captured::default())),
            next: AtomicU64::new(0),
        };
        tracing::subscriber::with_default(sub, || {
            let cols = common::columns(PRE);
            let rows = common::base_rows(PRE);
            let export = common::export_bytes(&cols, &rows);
            let v = fixture_verifier();
            let huge = vec![b' '; 64 * 1024 * 1024];
            let small = vec![b' '; 70 * 1024];
            let t_small = time_it(|| {
                v.verify_export(&export, Some(&small)).unwrap();
            });
            let t = Instant::now();
            let r = v.verify_export(&export, Some(&huge)).unwrap();
            let took = t.elapsed();
            assert_eq!(r.finding.unwrap().reason, Reason::AnchorUnreadable);
            println!("REDTEAM huge_us={} small_us={}", took.as_micros(), t_small.as_micros());
        });
    }) else {
        return;
    };
    assert!(ok, "child failed: {out}\n{err}");
    let (huge, small) = (parse_kv(&out, "huge_us"), parse_kv(&out, "small_us"));
    assert!(
        huge < small + 100_000,
        "refusing a 64 MiB anchor over the 64 KiB cap took {huge} us (a 70 KiB one took {small} us)"
    );
}

// ---------------------------------------------------------------------------
// 4. Panics and crashes reachable from input
// ---------------------------------------------------------------------------

/// std::env::args() panics on an argument that is not valid Unicode. A file
/// name taken from an upload directory can be such a name.
#[test]
fn redteam_cli_non_utf8_argument_does_not_panic() {
    use std::ffi::OsStr;
    use std::os::unix::ffi::OsStrExt;
    let out = std::process::Command::new(env!("CARGO_BIN_EXE_tack-sentinel-verify"))
        .arg("--export")
        .arg(OsStr::from_bytes(b"export-\xff.json"))
        .args(["--anchor", "a", "--trusted-fingerprints", "0000000000000000"])
        .output()
        .unwrap();
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        out.status.code() == Some(2) && !stderr.contains("panicked"),
        "exit {:?}, stderr: {stderr}",
        out.status.code()
    );
}

fn nested(depth: usize) -> Value {
    let mut v = Value::Str("leaf".into());
    for i in 0..depth {
        v = if i % 2 == 0 {
            Value::Array(vec![v])
        } else {
            let mut o = Object::new();
            o.insert("k".into(), v);
            Value::Object(o)
        };
    }
    v
}

/// Nesting at the parse cap through every recursive path: parse, clone
/// (canonical_form), dumps (row hash, prehash), the CNS rendering, describe
/// (a deep previous_hash) and drop. Runs on a 1 MiB stack in a child
/// process, so an overflow shows as a failed child, not a dead test run.
#[test]
fn redteam_max_depth_nesting_survives_every_recursive_path() {
    let Some((ok, out, err)) = in_child("redteam_max_depth_nesting_survives_every_recursive_path", || {
        let h = std::thread::Builder::new()
            .stack_size(1 << 20)
            .spawn(|| {
                let (cols, mut rows) = post();
                // top object, rows list, row object: three levels already.
                let deep = nested(253);
                rows[3].insert("input_data".into(), deep.clone());
                rows[3].insert("subject_digest".into(), Value::Str(subject_digest(&deep).unwrap()));
                common::rechain(&mut rows, 3);
                let anchor = common::anchor_bytes(&rows, rows.len(), common::FIXTURE_KEY);
                let r = run(&fixture_verifier(), &cols, &rows, &anchor);
                // Rechaining from row 4 breaks the abv2 signature on row 6
                // (it covers previous_hash); the deep row 4 itself must have
                // passed hash, subject digest, seed and signature checks.
                let at = r.finding.as_ref().and_then(|f| f.row_position).unwrap_or(usize::MAX);
                assert!(at > 3, "deep row did not pass its own checks: {}", summary(&r));

                let (cols, mut rows) = post();
                rows[0].insert("previous_hash".into(), nested(253));
                let r = run(&fixture_verifier(), &cols, &rows, &anchor);
                assert_eq!(r.finding.unwrap().reason, Reason::ChainBroken);
            })
            .unwrap();
        h.join().unwrap();
        println!("REDTEAM depth=ok");
    }) else {
        return;
    };
    assert!(ok && out.contains("REDTEAM depth=ok"), "child failed: {out}\n{err}");
}

fn arb_value() -> impl Strategy<Value = Value> {
    let leaf = prop_oneof![
        Just(Value::Null),
        any::<bool>().prop_map(Value::Bool),
        any::<i64>().prop_map(|i| Value::Int(PyInt::from_i64(i))),
        prop_oneof![any::<f64>(), Just(f64::NAN), Just(f64::INFINITY), Just(-0.0)].prop_map(Value::Float),
        "\\PC{0,10}".prop_map(Value::Str),
        Just(Value::Str("genesis".into())),
        Just(Value::Str(format!("{MARK}\n\u{1b}[2J\rVERIFIED"))),
        Just(Value::Str("abv3.acdf8e81f938b3ca.00".into())),
    ];
    leaf.prop_recursive(3, 24, 4, |inner| {
        prop_oneof![
            prop::collection::vec(inner.clone(), 0..4).prop_map(Value::Array),
            prop::collection::btree_map("\\PC{0,6}", inner, 0..4).prop_map(Value::Object),
        ]
    })
}

const FUZZ_COLUMNS: &[&str] = &[
    "record_kind",
    "data",
    "input_data",
    "decision_output",
    "authorized_by",
    "authorized_by_sig",
    "subject_digest",
    "shuffle_seed",
    "current_hash",
    "previous_hash",
    "reason",
    "cassette_version",
    "timestamp",
];

proptest! {
    #![proptest_config(ProptestConfig { cases: 256, ..ProptestConfig::default() })]

    /// Any JSON value in any column of any row: no panic, and a row whose
    /// stored hash no longer matches its content never verifies.
    #[test]
    fn redteam_fuzz_column_values_never_panic_or_pass_a_broken_row(
        pos in 0usize..16,
        col in 0usize..FUZZ_COLUMNS.len(),
        value in arb_value(),
        drop_col in any::<bool>(),
    ) {
        let (cols, base) = post();
        let mut rows = base.clone();
        let name = FUZZ_COLUMNS[col];
        if drop_col {
            rows[pos].remove(name);
        } else {
            rows[pos].insert(name.into(), value);
        }
        let anchor = common::anchor_bytes(&base, base.len(), common::FIXTURE_KEY);
        let export = common::export_bytes(&cols, &rows);
        let v = fixture_verifier();
        let got = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| v.verify_export(&export, Some(&anchor))));
        prop_assert!(got.is_ok(), "panic on {name} at row {pos}");
        let stored = rows[pos].get("current_hash").and_then(Value::as_str);
        let row_holds = stored.is_some() && recompute_current_hash(&rows[pos]).ok().as_deref() == stored
            && rows[pos].get("previous_hash") == base[pos].get("previous_hash");
        if let Ok(Ok(r)) = got {
            if !row_holds {
                prop_assert_ne!(r.verdict(), Verdict::Verified);
            }
            prop_assert!(!r.render().contains(MARK));
        }
    }

    /// Random byte edits to the export text: no panic, no marker echo.
    #[test]
    fn redteam_fuzz_export_bytes_never_panic(
        edits in prop::collection::vec((any::<prop::sample::Index>(), any::<u8>()), 1..6),
    ) {
        let (cols, base) = post();
        let anchor = common::anchor_bytes(&base, base.len(), common::FIXTURE_KEY);
        let mut export = common::export_bytes(&cols, &base);
        for (i, b) in &edits {
            let at = i.index(export.len());
            export[at] = *b;
        }
        let v = fixture_verifier();
        let got = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| v.verify_export(&export, Some(&anchor))));
        prop_assert!(got.is_ok());
    }
}

// ---------------------------------------------------------------------------
// 5. Log injection, telemetry cardinality, raw input in spans
// ---------------------------------------------------------------------------

fn hostile_cases() -> Vec<(Vec<u8>, Vec<u8>)> {
    let (cols, base) = post();
    let payload = Value::Str(format!("{MARK}\n\u{1b}[2J\rVERIFIED row=1"));
    let good_anchor = common::anchor_bytes(&base, base.len(), common::FIXTURE_KEY);
    let mut out = Vec::new();
    let mut push = |rows: &[Object], anchor: &[u8]| out.push((common::export_bytes(&cols, rows), anchor.to_vec()));

    let mut r = base.clone();
    r[3].insert("previous_hash".into(), payload.clone());
    push(&r, &good_anchor);

    let mut r = base.clone();
    r[3].insert("current_hash".into(), payload.clone());
    push(&r, &good_anchor);

    let mut r = base.clone();
    r[2].insert(
        "authorized_by_sig".into(),
        Value::Str(format!("abv3.{MARK}\nVERIFIED.{}", "c".repeat(64))),
    );
    common::rechain(&mut r, 2);
    push(&r, &good_anchor);

    let mut r = base.clone();
    r[3].insert("subject_digest".into(), payload.clone());
    common::rechain(&mut r, 3);
    push(&r, &good_anchor);

    let mut r = base.clone();
    r[8].insert("authorized_by".into(), payload.clone());
    common::rechain(&mut r, 8);
    push(&r, &good_anchor);

    let mut r = base.clone();
    let mut kind = Object::new();
    kind.insert(MARK.into(), payload.clone());
    r[4].insert("record_kind".into(), Value::Object(kind));
    push(&r, &good_anchor);

    let mut a = String::from_utf8(good_anchor.clone()).unwrap();
    a = a.replace("acdf8e81f938b3ca", &format!("{MARK}\\n"));
    push(&base, a.as_bytes());

    push(&base, anchor_raw(&format!("{MARK}\n"), PyInt::from_i64(16), common::FIXTURE_KEY).as_slice());
    push(&base, format!("{{\"v\": 1, \"{MARK}\": \"\n\"}}").as_bytes());

    out.push((format!("{{\"format\": \"{MARK}\"}}").into_bytes(), good_anchor.clone()));
    out.push((format!("[\"{MARK}\"]").into_bytes(), good_anchor));
    out
}

/// Report lines never carry attacker bytes, control characters or extra
/// lines that could fake a second verdict in a log.
#[test]
fn redteam_report_text_never_echoes_attacker_bytes() {
    let v = fixture_verifier();
    for (i, (export, anchor)) in hostile_cases().iter().enumerate() {
        let Ok(r) = v.verify_export(export, Some(anchor)) else { continue };
        let text = r.render();
        assert!(!text.contains(MARK), "case {i} echoed attacker bytes: {text}");
        assert!(!text.chars().any(|c| c == '\r' || c == '\u{1b}'), "case {i}: control character in {text:?}");
        let lines: Vec<&str> = text.lines().collect();
        assert!(
            lines.len() == 1 || (lines.len() == 2 && lines[1].starts_with("  also: ")),
            "case {i}: forged extra line in {text:?}"
        );
    }
}

/// Every metric name and label value stays inside the closed sets whatever
/// the input.
#[test]
fn redteam_metric_labels_stay_closed_under_hostile_input() {
    let recorder = DebuggingRecorder::new();
    let snap = recorder.snapshotter();
    metrics::with_local_recorder(&recorder, || {
        let v = fixture_verifier();
        for (export, anchor) in hostile_cases() {
            let _ = v.verify_export(&export, Some(&anchor));
            let _ = v.verify_export(&export, None);
        }
        let _ = Verifier::new(VerifierConfig::default(), KeySet::default());
    });
    let names = [
        VERIFICATIONS_TOTAL,
        TRIPS_TOTAL,
        INPUT_REJECTED_TOTAL,
        ROWS_CHECKED_TOTAL,
        VERIFY_DURATION_SECONDS,
    ];
    let mut allowed: Vec<&str> = vec![
        "verified",
        "tampered",
        "transplanted",
        "seed_forged",
        "truncated",
        "unattested",
        "pass",
        "retry",
        "terminal_breach",
        "reject",
        "quarantine",
        "rollback",
        "halt",
        "export_too_large",
        "export_not_json",
        "not_an_export",
        "rows_missing",
        "row_not_an_object",
        "row_id_invalid",
        "too_many_rows",
        "no_trusted_key_material",
        "key_refused",
    ];
    allowed.extend(Reason::ALL.iter().map(|r| r.label()));
    let entries = snap.snapshot().into_vec();
    assert!(!entries.is_empty());
    for (k, ..) in entries {
        assert!(names.contains(&k.key().name()), "unexpected metric {}", k.key().name());
        for l in k.key().labels() {
            assert!(
                ["verdict", "reason", "outcome", "resolution"].contains(&l.key()),
                "unexpected label key {}",
                l.key()
            );
            assert!(allowed.contains(&l.value()), "open label value {:?}", l.value());
        }
    }
}

#[derive(Default)]
struct Captured {
    spans: HashMap<u64, String>,
    fields: Vec<(String, String, String)>,
}

struct Collect {
    log: Arc<Mutex<Captured>>,
    next: AtomicU64,
}

struct Vis<'a> {
    owner: String,
    out: &'a mut Vec<(String, String, String)>,
}

impl tracing::field::Visit for Vis<'_> {
    fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn fmt::Debug) {
        self.out.push((self.owner.clone(), field.name().to_owned(), format!("{value:?}")));
    }
    fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
        self.out.push((self.owner.clone(), field.name().to_owned(), value.to_owned()));
    }
}

impl tracing::Subscriber for Collect {
    fn enabled(&self, _: &tracing::Metadata<'_>) -> bool {
        true
    }
    fn new_span(&self, span: &tracing::span::Attributes<'_>) -> tracing::span::Id {
        let id = self.next.fetch_add(1, Ordering::Relaxed) + 1;
        let name = span.metadata().name().to_owned();
        let mut g = self.log.lock().unwrap();
        g.spans.insert(id, name.clone());
        let mut fields = Vec::new();
        span.record(&mut Vis { owner: name, out: &mut fields });
        g.fields.extend(fields);
        tracing::span::Id::from_u64(id)
    }
    fn record(&self, id: &tracing::span::Id, values: &tracing::span::Record<'_>) {
        let mut g = self.log.lock().unwrap();
        let name = g.spans.get(&id.into_u64()).cloned().unwrap_or_default();
        let mut fields = Vec::new();
        values.record(&mut Vis { owner: name, out: &mut fields });
        g.fields.extend(fields);
    }
    fn record_follows_from(&self, _: &tracing::span::Id, _: &tracing::span::Id) {}
    fn event(&self, event: &tracing::Event<'_>) {
        let mut fields = Vec::new();
        event.record(&mut Vis {
            owner: format!("event:{}", event.metadata().target()),
            out: &mut fields,
        });
        self.log.lock().unwrap().fields.extend(fields);
    }
    fn enter(&self, _: &tracing::span::Id) {}
    fn exit(&self, _: &tracing::span::Id) {}
}

/// No tracing span or event carries raw input, every span is named
/// tack.sentinel.*, and every sha256 field is a full 64-hex digest.
#[test]
fn redteam_spans_carry_no_raw_input_and_no_short_hash() {
    let Some((ok, out, err)) = in_child("redteam_spans_carry_no_raw_input_and_no_short_hash", || {
        let log = Arc::new(Mutex::new(Captured::default()));
        let sub = Collect {
            log: log.clone(),
            next: AtomicU64::new(0),
        };
        tracing::subscriber::with_default(sub, || {
            let v = fixture_verifier();
            for (export, anchor) in hostile_cases() {
                let _ = v.verify_export(&export, Some(&anchor));
            }
            let _ = Verifier::new(VerifierConfig::default(), KeySet::default());
        });
        let g = log.lock().unwrap();
        assert!(!g.spans.is_empty(), "no spans captured");
        for name in g.spans.values() {
            assert!(name.starts_with("tack.sentinel."), "span {name}");
        }
        for (owner, field, value) in &g.fields {
            assert!(!value.contains(MARK), "{owner}.{field} carries raw input: {value}");
            if field.contains("sha256") {
                assert!(
                    value.len() == 64 && value.bytes().all(|b| b.is_ascii_hexdigit()),
                    "{owner}.{field} is not a full hash: {value}"
                );
            }
        }
        println!("REDTEAM spans={} fields={}", g.spans.len(), g.fields.len());
    }) else {
        return;
    };
    assert!(ok, "child failed: {out}\n{err}");
}

// ---------------------------------------------------------------------------
// 6. Concurrency and timing
// ---------------------------------------------------------------------------

/// One Verifier shared by many threads gives the same answers as one thread.
#[test]
fn redteam_shared_verifier_is_consistent_across_threads() {
    let (cols, base) = post();
    let anchor = common::anchor_bytes(&base, base.len(), common::FIXTURE_KEY);
    let mut tampered = base.clone();
    tampered[5].insert("reason".into(), Value::Str("edited".into()));
    let mut cut = base.clone();
    cut.truncate(10);
    let exports: Arc<Vec<Vec<u8>>> = Arc::new(vec![
        common::export_bytes(&cols, &base),
        common::export_bytes(&cols, &tampered),
        common::export_bytes(&cols, &cut),
    ]);
    let v = Arc::new(fixture_verifier());
    let want: Vec<String> = exports.iter().map(|e| v.verify_export(e, Some(&anchor)).unwrap().render()).collect();
    let handles: Vec<_> = (0..8)
        .map(|t| {
            let (v, exports, anchor) = (v.clone(), exports.clone(), anchor.clone());
            std::thread::spawn(move || {
                (0..30)
                    .map(|i| {
                        let k = (t + i) % exports.len();
                        (k, v.verify_export(&exports[k], Some(&anchor)).unwrap().render())
                    })
                    .collect::<Vec<_>>()
            })
        })
        .collect();
    for h in handles {
        for (k, got) in h.join().unwrap() {
            assert_eq!(got, want[k]);
        }
    }
}

/// Signature comparison time does not depend on where a forged digest first
/// differs (subtle's constant-time compare). A smoke test with a wide bound:
/// the HMAC dominates, so only a gross early-exit leak would show.
#[test]
fn redteam_signature_check_time_does_not_track_matching_prefix() {
    let (_, rows) = post();
    let row = rows[5].clone();
    let good = row["authorized_by_sig"].as_str().unwrap().to_owned();
    let (head, digest) = good.rsplit_once('.').unwrap();
    let flip = |c: u8| if c == b'0' { b'1' } else { b'0' };
    let mut early = digest.as_bytes().to_vec();
    early[0] = flip(early[0]);
    let mut late = digest.as_bytes().to_vec();
    late[63] = flip(late[63]);
    let make = |d: Vec<u8>| {
        let mut r = row.clone();
        r.insert(
            "authorized_by_sig".into(),
            Value::Str(format!("{head}.{}", String::from_utf8(d).unwrap())),
        );
        r
    };
    let (r_early, r_late) = (make(early), make(late));
    let keys = common::verifier_keys();
    let pre_e = content_prehash(&canonical_form(&r_early).unwrap());
    let pre_l = content_prehash(&canonical_form(&r_late).unwrap());
    let mut te = Vec::new();
    let mut tl = Vec::new();
    for _ in 0..2000 {
        let t = Instant::now();
        std::hint::black_box(verify_signature(&r_early, &keys, &pre_e));
        te.push(t.elapsed());
        let t = Instant::now();
        std::hint::black_box(verify_signature(&r_late, &keys, &pre_l));
        tl.push(t.elapsed());
    }
    let (me, ml) = (median(te).as_secs_f64(), median(tl).as_secs_f64());
    let ratio = me / ml;
    assert!((0.67..=1.5).contains(&ratio), "early {me:e}s vs late {ml:e}s");
}

// ---------------------------------------------------------------------------
// 7. Anchor arithmetic, replay and coverage
// ---------------------------------------------------------------------------

/// Off-by-one and huge anchored counts, and extreme row ids, give the right
/// finding and never panic.
#[test]
fn redteam_anchor_counts_and_row_ids_at_the_edges() {
    let (cols, base) = post();
    let v = fixture_verifier();
    let last = base[15]["current_hash"].as_str().unwrap();
    // head of row 16 claimed at position 17
    let r = run(&v, &cols, &base, &anchor_raw(last, PyInt::from_i64(17), common::FIXTURE_KEY));
    assert_eq!(r.finding.unwrap().reason, Reason::TailMissing);
    // head of row 16 claimed at position 15
    let r = run(&v, &cols, &base, &anchor_raw(last, PyInt::from_i64(15), common::FIXTURE_KEY));
    assert_eq!(r.finding.unwrap().reason, Reason::HeadMismatch);
    // a count too large for any integer type
    let huge = tack_sentinel::pyjson::parse("9".repeat(4000).as_bytes(), Default::default()).unwrap();
    let Value::Int(huge) = huge else { panic!() };
    let r = run(&v, &cols, &base, &anchor_raw(last, huge, common::FIXTURE_KEY));
    assert_eq!(r.finding.unwrap().reason, Reason::TailMissing);
    // i64::MIN and i64::MAX ids keep order; 2**63 is refused
    let anchor = common::anchor_bytes(&base, base.len(), common::FIXTURE_KEY);
    let mut rows = base.clone();
    rows[0].insert("id".into(), Value::Int(PyInt::from_i64(i64::MIN)));
    rows[15].insert("id".into(), Value::Int(PyInt::from_i64(i64::MAX)));
    assert_eq!(run(&v, &cols, &rows, &anchor).verdict(), Verdict::Verified);
    let text = String::from_utf8(common::export_bytes(&cols, &rows))
        .unwrap()
        .replace("9223372036854775807", "9223372036854775808");
    assert!(matches!(
        v.verify_export(text.as_bytes(), Some(&anchor)),
        Err(VerifyError::RowIdInvalid { .. })
    ));
}

/// A genuine anchor sealed with zero rows (for example at ledger setup)
/// vouches for any chain. An attacker who can swap the anchor file for that
/// early one gets VERIFIED for a fully rebuilt ledger.
#[test]
fn redteam_zero_entry_anchor_vouches_for_nothing() {
    let (cols, base) = post();
    let mut rows = base.clone();
    rows.truncate(4);
    rows[3].insert("reason".into(), Value::Str("rewritten history".into()));
    common::rechain(&mut rows, 3);
    let zero = common::anchor_bytes(&rows, 0, common::FIXTURE_KEY);
    let r = run(&fixture_verifier(), &cols, &rows, &zero);
    assert_ne!(
        r.gate_outcome(),
        GateOutcome::Pass,
        "a zero-entry anchor passed a cut and rewritten chain: {}",
        summary(&r)
    );
}

/// A stale but genuine anchor verifies a chain cut back to its count, and
/// the Report does not say which anchor vouched (entries, sealed_at), so the
/// auditor cannot see that the anchor was old.
#[test]
fn redteam_report_does_not_show_which_anchor_vouched() {
    let (cols, base) = post();
    let stale = common::anchor_bytes(&base, 6, common::FIXTURE_KEY);
    let mut rows = base.clone();
    rows.truncate(6);
    let r = run(&fixture_verifier(), &cols, &rows, &stale);
    assert_eq!(r.verdict(), Verdict::Verified);
    let shown = format!("{r:?} {}", r.render());
    assert!(
        shown.contains("sealed_at") || shown.contains("2026-09-30T00:00:00"),
        "the report gives no anchor count or seal time: {shown}"
    );
}

/// Columns outside the canonical form (timestamp, id, record_kind on a base
/// row, call_sid, cassette_snapshot) change freely under VERIFIED. This is
/// sentinel_os's ledger design, but nothing in the crate or its report says
/// that VERIFIED covers only the hashed columns.
#[test]
fn redteam_unhashed_columns_change_under_verified() {
    let (cols, base) = post();
    let mut rows = base.clone();
    rows[7].insert("timestamp".into(), Value::Str("1999-01-01T00:00:00+00:00".into()));
    let anchor = common::anchor_bytes(&base, base.len(), common::FIXTURE_KEY);
    let r = run(&fixture_verifier(), &cols, &rows, &anchor);
    // timestamp is outside every canonical form by sentinel_os's design, so
    // the verdict stays VERIFIED (as the Python prints it). What must hold
    // is that the report says VERIFIED did not cover it.
    assert_eq!(r.verdict(), Verdict::Verified);
    assert!(
        r.unhashed_columns.contains(&"timestamp"),
        "a decision's timestamp was moved by 27 years and the report does not say timestamp is unhashed: {:?}",
        r.unhashed_columns
    );
}
