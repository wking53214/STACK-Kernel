//! Behaviour tests for the Trident: acceptance, tamper, replay, order,
//! keys, payload bombs, freshness, breaker, halt, capacity.

mod common;

use std::sync::Arc;

use common::*;
use serde_json::{json, Value};
use tack_trident::canonical::{sha256_hex, to_canonical_bytes};
use tack_trident::ReasonCode::*;
use tack_trident::{
    BreakerAttribution, Check, GateOutcome, GatePosition, KeyRing, ManualClock, ReasonCode, Resolution, Trident,
    TridentConfig, Verdict,
};

fn reasons(v: &Verdict) -> Vec<ReasonCode> {
    let mut r = v.reasons().to_vec();
    r.sort();
    r
}

fn sorted(mut r: Vec<ReasonCode>) -> Vec<ReasonCode> {
    r.sort();
    r
}

// ---------------------------------------------------------------------------
// Acceptance
// ---------------------------------------------------------------------------

#[test]
fn valid_envelope_passes_on_both_paths() {
    let fx = setup();
    let env = fx.sealed(1);
    let v = fx.trident.verify_wire(&fx.wire(&env));
    assert!(v.is_accepted(), "{v:?}");
    assert_eq!(v.outcome(), GateOutcome::Pass);
    let h = v.accepted().unwrap();
    assert_eq!(h.sender, fx.fp_a);
    assert_eq!(h.sequence, 1);
    assert_eq!(h.gate_position, GatePosition::Alpha);
    assert_eq!(h.gate_outcome, GateOutcome::Pass);
    assert_eq!(h.payload, payload_for(1));
    assert_eq!(h.subject_digest, env.subject_digest);

    let env2 = fx.sealed(2);
    assert!(fx.trident.verify(&env2).is_accepted());
}

#[test]
fn non_canonical_wire_spelling_of_the_same_values_passes() {
    let fx = setup();
    let env = fx.sealed(1);
    // Pretty-printed, different key order, escaped characters.
    let pretty = serde_json::to_string_pretty(&to_value(&env)).unwrap();
    let pretty = pretty.replace('é', "\\u00e9");
    assert!(fx.trident.verify_wire(pretty.as_bytes()).is_accepted());
}

#[test]
fn a_sender_terminal_breach_claim_is_carried_not_rejudged() {
    let fx = setup();
    let env = tack_trident::seal(
        tack_trident::EnvelopeDraft {
            sequence: 1,
            issued_at_unix_ms: fx.now(),
            nonce: nonce_for(1),
            gate_position: GatePosition::Omega,
            gate_outcome: GateOutcome::TerminalBreach,
            payload: json!({"refused": "yes"}),
        },
        &fx.key_a,
        &fx.cfg.limits(),
    )
    .unwrap();
    let v = fx.trident.verify(&env);
    assert_eq!(v.accepted().unwrap().gate_outcome, GateOutcome::TerminalBreach);
    assert_eq!(v.accepted().unwrap().gate_position, GatePosition::Omega);
}

// ---------------------------------------------------------------------------
// Single-field tampering
// ---------------------------------------------------------------------------

#[test]
fn every_single_field_tamper_fails_with_the_right_reason() {
    type Tamper = (&'static str, fn(&mut Value, &Fx), Vec<ReasonCode>);
    let cases: Vec<Tamper> = vec![
        ("version bumped", |v, _| v["version"] = json!(2), vec![MacMismatch, UnsupportedVersion]),
        (
            "sender swapped for another ring member",
            |v, fx| v["sender"] = json!(fx.fp_b.to_hex()),
            vec![MacMismatch],
        ),
        (
            "sender swapped for an unknown fingerprint",
            |v, _| v["sender"] = json!("ab".repeat(32)),
            vec![UnknownSender],
        ),
        ("sender not hex", |v, _| v["sender"] = json!("not-a-fingerprint"), vec![MalformedSender]),
        ("sequence bumped", |v, _| v["sequence"] = json!(99), vec![MacMismatch]),
        (
            "issued_at moved one ms",
            |v, _| v["issued_at_unix_ms"] = json!(v["issued_at_unix_ms"].as_u64().unwrap() - 1),
            vec![MacMismatch],
        ),
        ("nonce changed", |v, _| v["nonce"] = json!("00".repeat(16)), vec![MacMismatch]),
        ("nonce malformed", |v, _| v["nonce"] = json!("xyz"), vec![MacMismatch, MalformedNonce]),
        ("gate_position flipped", |v, _| v["gate_position"] = json!("omega"), vec![MacMismatch]),
        (
            "gate_position outside vocabulary",
            |v, _| v["gate_position"] = json!("gamma"),
            vec![MacMismatch, UnknownGatePosition],
        ),
        ("gate_outcome flipped", |v, _| v["gate_outcome"] = json!("retry"), vec![MacMismatch]),
        (
            "gate_outcome outside vocabulary",
            |v, _| v["gate_outcome"] = json!("PASS"),
            vec![MacMismatch, UnknownGateOutcome],
        ),
        (
            "subject_digest replaced",
            |v, _| v["subject_digest"] = json!(sha256_hex(b"other")),
            vec![MacMismatch, SubjectDigestMismatch],
        ),
        (
            "subject_digest uppercased",
            |v, _| v["subject_digest"] = json!(v["subject_digest"].as_str().unwrap().to_uppercase()),
            vec![MacMismatch, MalformedDigest],
        ),
        (
            "payload changed",
            |v, _| v["payload"]["task"] = json!("other"),
            vec![MacMismatch, SubjectDigestMismatch],
        ),
        (
            "mac changed",
            |v, _| {
                let m = v["mac"].as_str().unwrap();
                let flipped = if m.starts_with('0') { "1" } else { "0" };
                v["mac"] = json!(format!("{flipped}{}", &m[1..]));
            },
            vec![MacMismatch],
        ),
        ("mac truncated", |v, _| v["mac"] = json!(v["mac"].as_str().unwrap()[..32].to_owned()), vec![MalformedMac]),
    ];
    for (name, tamper, expected) in cases {
        let fx = setup();
        let env = fx.sealed(1);
        let mut v = to_value(&env);
        tamper(&mut v, &fx);
        let bytes = to_canonical_bytes(&v, &fx.cfg.limits()).unwrap();
        let verdict = fx.trident.verify_wire(&bytes);
        assert_eq!(reasons(&verdict), sorted(expected.clone()), "case: {name}");
        let expected_outcome = GateOutcome::resolve(expected.iter().map(|r| r.outcome()));
        assert_eq!(verdict.outcome(), expected_outcome, "case: {name}");
        assert_eq!(verdict.refusal().unwrap().resolution, Resolution::Reject, "case: {name}");
    }
}

#[test]
fn transplanted_digest_signed_by_the_key_holder_is_caught_by_binding_alone() {
    let fx = setup();
    let mut env = fx.sealed(1);
    env.payload = json!({"moved": "onto other content"});
    remac(&mut env, "a");
    let v = fx.trident.verify(&env);
    assert_eq!(reasons(&v), vec![SubjectDigestMismatch]);
    assert_eq!(v.outcome(), GateOutcome::TerminalBreach);
    assert_eq!(v.refusal().unwrap().failed_prongs(), vec![2]);
}

#[test]
fn all_three_prongs_are_evaluated_and_reported() {
    let fx = setup();
    let mut env = fx.sealed_by(&fx.key_x, 1); // prong 1: unknown sender
    env.subject_digest = sha256_hex(b"wrong"); // prong 2
    fx.clock.advance(fx.cfg.max_past_skew_ms + 1); // prong 3: stale
    let v = fx.trident.verify(&env);
    let r = v.refusal().unwrap();
    assert_eq!(r.failed_prongs(), vec![1, 2, 3]);
    assert_eq!(sorted(r.reasons.clone()), sorted(vec![UnknownSender, SubjectDigestMismatch, Stale]));
    assert_eq!(r.outcome, GateOutcome::TerminalBreach);
}

// ---------------------------------------------------------------------------
// Replay and ordering
// ---------------------------------------------------------------------------

#[test]
fn replay_fails() {
    let fx = setup();
    let bytes = fx.wire(&fx.sealed(1));
    assert!(fx.trident.verify_wire(&bytes).is_accepted());
    let v = fx.trident.verify_wire(&bytes);
    assert_eq!(reasons(&v), sorted(vec![Replay, SequenceNotIncreasing]));
    assert_eq!(v.outcome(), GateOutcome::TerminalBreach);
    assert_eq!(v.refusal().unwrap().failed_checks(), vec![Check::Freshness]);
}

#[test]
fn nonce_reuse_with_a_new_sequence_is_a_replay() {
    let fx = setup();
    assert!(fx.trident.verify(&fx.sealed(1)).is_accepted());
    let mut again = fx.sealed(2);
    again.nonce = nonce_for(1).to_hex();
    remac(&mut again, "a");
    assert_eq!(reasons(&fx.trident.verify(&again)), vec![Replay]);
}

#[test]
fn out_of_order_sequence_fails() {
    let fx = setup();
    assert!(fx.trident.verify(&fx.sealed(5)).is_accepted());
    let v = fx.trident.verify(&fx.sealed(4));
    assert_eq!(reasons(&v), vec![SequenceNotIncreasing]);
    assert_eq!(v.outcome(), GateOutcome::Retry);
    // Equal is not strictly greater either.
    let mut same = fx.sealed(5);
    same.nonce = nonce_for(500).to_hex();
    remac(&mut same, "a");
    assert_eq!(reasons(&fx.trident.verify(&same)), vec![SequenceNotIncreasing]);
    assert!(fx.trident.verify(&fx.sealed(6)).is_accepted());
    // Sequences are per sender.
    assert!(fx.trident.verify(&fx.sealed_by(&fx.key_b, 1)).is_accepted());
}

#[test]
fn stateful_freshness_is_masked_for_unauthenticated_envelopes() {
    let fx = setup();
    let good = fx.sealed(10);
    assert!(fx.trident.verify(&good).is_accepted());
    // A forger replays the nonce and a low sequence under A's name. The
    // reply must not reveal that the nonce was seen or the counter is 10.
    let mut forged = good.clone();
    forged.sequence = 3;
    forged.mac = "00".repeat(32);
    let v = fx.trident.verify(&forged);
    assert_eq!(reasons(&v), vec![MacMismatch]);
}

// ---------------------------------------------------------------------------
// Keys
// ---------------------------------------------------------------------------

#[test]
fn wrong_key_fails() {
    let fx = setup();
    let mut env = fx.sealed(1);
    // Signed with B's key but claiming to be A.
    remac(&mut env, "b");
    assert_eq!(env.sender, fx.fp_a.to_hex());
    let v = fx.trident.verify(&env);
    assert_eq!(reasons(&v), vec![MacMismatch]);
    assert_eq!(v.outcome(), GateOutcome::TerminalBreach);
}

#[test]
fn unknown_sender_fails() {
    let fx = setup();
    let env = fx.sealed_by(&fx.key_x, 1);
    let v = fx.trident.verify(&env);
    assert_eq!(reasons(&v), vec![UnknownSender]);
    assert_eq!(v.outcome(), GateOutcome::TerminalBreach);
}

#[test]
fn an_empty_ring_authenticates_nothing() {
    let clock = Arc::new(ManualClock::new(T0));
    let t = Trident::new(TridentConfig::default(), KeyRing::new(4), clock.clone()).unwrap();
    clock.advance(10_000);
    let fx = setup();
    fx.clock.set(T0 + 10_000);
    let v = t.verify(&fx.sealed(1));
    assert_eq!(reasons(&v), vec![UnknownSender]);
}

#[test]
fn removing_a_key_by_replacing_the_ring_revokes_the_sender() {
    let fx = setup();
    assert!(fx.trident.verify(&fx.sealed(1)).is_accepted());
    let mut ring = KeyRing::new(4);
    ring.insert(fixture_key("b")).unwrap();
    fx.trident.replace_keyring(ring).unwrap();
    assert_eq!(reasons(&fx.trident.verify(&fx.sealed(2))), vec![UnknownSender]);
    assert!(fx.trident.verify(&fx.sealed_by(&fx.key_b, 1)).is_accepted());
}

// ---------------------------------------------------------------------------
// Payload bombs and strict parsing
// ---------------------------------------------------------------------------

#[test]
fn depth_bomb_on_the_wire_is_refused_at_admission() {
    let fx = setup();
    let bomb = format!("{{\"payload\":{}{}}}", "[".repeat(20_000), "]".repeat(20_000));
    let v = fx.trident.verify_wire(bomb.as_bytes());
    assert_eq!(reasons(&v), vec![TooDeep]);
    assert_eq!(v.outcome(), GateOutcome::Retry);
    assert_eq!(v.refusal().unwrap().failed_checks(), vec![Check::Admission]);
}

#[test]
fn size_bomb_on_the_wire_is_refused_before_parsing() {
    let fx = setup();
    let bomb = vec![b' '; fx.cfg.max_envelope_bytes + 1];
    assert_eq!(reasons(&fx.trident.verify_wire(&bomb)), vec![EnvelopeTooLarge]);
}

#[test]
fn node_bomb_on_the_wire_is_refused() {
    let fx = setup();
    let bomb = format!("[{}]", vec!["0"; fx.cfg.max_nodes + 1].join(","));
    assert!(bomb.len() < fx.cfg.max_envelope_bytes);
    assert_eq!(reasons(&fx.trident.verify_wire(bomb.as_bytes())), vec![TooManyNodes]);
}

#[test]
fn in_process_bombs_hit_the_same_caps() {
    let fx = setup();
    let mut deep = json!(0);
    for _ in 0..200 {
        deep = json!([deep]);
    }
    let mut env = fx.sealed(1);
    env.payload = deep;
    assert_eq!(reasons(&fx.trident.verify(&env)), vec![TooDeep]);

    let mut env = fx.sealed(1);
    env.payload = Value::String("x".repeat(fx.cfg.max_envelope_bytes));
    assert_eq!(reasons(&fx.trident.verify(&env)), vec![EnvelopeTooLarge]);

    let mut env = fx.sealed(1);
    env.sender = "a".repeat(10 * fx.cfg.max_envelope_bytes);
    assert_eq!(reasons(&fx.trident.verify(&env)), vec![EnvelopeTooLarge]);

    let mut env = fx.sealed(1);
    env.sequence = tack_trident::MAX_SAFE_INTEGER + 1;
    assert_eq!(reasons(&fx.trident.verify(&env)), vec![IntegerOutOfRange]);

    let mut env = fx.sealed(1);
    env.payload = json!({"f": 0.5});
    assert_eq!(reasons(&fx.trident.verify(&env)), vec![NonIntegerNumber]);
}

#[test]
fn strict_parser_refusals_map_to_reasons() {
    let fx = setup();
    let env = fx.sealed(1);
    let wire = String::from_utf8(fx.wire(&env)).unwrap();
    let cases: Vec<(String, ReasonCode)> = vec![
        (wire.replace("\"sequence\":1", "\"sequence\":1.0"), NonIntegerNumber),
        (wire.replace("\"seq\":1", "\"seq\":NaN"), NonFiniteNumber),
        (wire.replace("\"seq\":1", "\"seq\":Infinity"), NonFiniteNumber),
        (wire.replace("\"seq\":1", "\"seq\":1,\"seq\":1"), DuplicateKey),
        (wire.replacen('{', "{\"version\":1,", 1), DuplicateKey),
        (wire.replace("\"seq\":1", "\"seq\":18446744073709551616"), IntegerOutOfRange),
        (wire[..wire.len() - 1].to_owned(), MalformedJson),
        (format!("{wire} x"), MalformedJson),
        ("[]".to_owned(), MalformedEnvelope),
        (wire.replace("\"sequence\":1", "\"sequence\":\"1\""), MalformedEnvelope),
        (wire.replace("\"sequence\":1", "\"sequence\":-1"), MalformedEnvelope),
        (wire.replace("\"sequence\":1", "\"sequence\":1,\"extra\":0"), MalformedEnvelope),
    ];
    for (input, expected) in cases {
        let v = fx.trident.verify_wire(input.as_bytes());
        assert_eq!(reasons(&v), vec![expected], "input: {input}");
        assert_eq!(v.outcome(), expected.outcome());
    }
}

// ---------------------------------------------------------------------------
// Freshness windows
// ---------------------------------------------------------------------------

#[test]
fn skew_window_and_epoch_floor() {
    let fx = setup();
    let env = fx.sealed(1);
    fx.clock.advance(fx.cfg.max_past_skew_ms + 1);
    assert_eq!(reasons(&fx.trident.verify(&env)), vec![Stale]);

    let fx = setup();
    let env = fx.sealed(1);
    fx.clock.set(env.issued_at_unix_ms - fx.cfg.max_future_skew_ms - 1);
    assert_eq!(reasons(&fx.trident.verify(&env)), vec![FromFuture]);

    // Before the start-up floor: issued at start time.
    let clock = Arc::new(ManualClock::new(T0));
    let mut ring = KeyRing::new(4);
    ring.insert(fixture_key("a")).unwrap();
    let t = Trident::new(TridentConfig::default(), ring, clock.clone()).unwrap();
    let fx = setup();
    fx.clock.set(T0);
    let env = fx.sealed(1);
    assert_eq!(reasons(&t.verify(&env)), vec![IssuedBeforeEpoch]);
    // With the floor disabled, the same envelope passes.
    let mut ring = KeyRing::new(4);
    ring.insert(fixture_key("a")).unwrap();
    let cfg = TridentConfig {
        enforce_startup_epoch: false,
        ..TridentConfig::default()
    };
    let t = Trident::new(cfg, ring, clock).unwrap();
    assert!(t.verify(&env).is_accepted());
}

// ---------------------------------------------------------------------------
// Circuit breaker
// ---------------------------------------------------------------------------

fn transplanted(fx: &Fx, seq: u64) -> tack_trident::HandoffEnvelope {
    let mut env = fx.sealed(seq);
    env.payload = json!({"transplanted": seq});
    remac(&mut env, "a");
    env
}

#[test]
fn quarantine_trips_at_k_and_releases_on_reset() {
    let fx = setup_with(TridentConfig {
        breaker_threshold: 3,
        ..TridentConfig::default()
    });
    for seq in 1..=2 {
        let v = fx.trident.verify(&transplanted(&fx, seq));
        assert_eq!(v.outcome(), GateOutcome::TerminalBreach);
        assert_eq!(v.refusal().unwrap().resolution, Resolution::Reject);
    }
    let v = fx.trident.verify(&transplanted(&fx, 3));
    assert_eq!(reasons(&v), vec![SubjectDigestMismatch]);
    assert_eq!(v.refusal().unwrap().resolution, Resolution::Quarantine);
    assert_eq!(fx.trident.quarantined().unwrap(), vec![fx.fp_a]);

    // Every envelope from A is now refused, even a valid one.
    let v = fx.trident.verify(&fx.sealed(10));
    assert_eq!(reasons(&v), vec![Quarantined]);
    assert_eq!(v.outcome(), GateOutcome::TerminalBreach);
    assert_eq!(v.refusal().unwrap().resolution, Resolution::Quarantine);
    // Other senders are unaffected.
    assert!(fx.trident.verify(&fx.sealed_by(&fx.key_b, 1)).is_accepted());

    assert!(fx.trident.release(&fx.fp_a).unwrap());
    assert!(!fx.trident.release(&fx.fp_a).unwrap());
    assert!(fx.trident.quarantined().unwrap().is_empty());
    assert!(fx.trident.verify(&fx.sealed(11)).is_accepted());
    // Released with a clean slate: K - 1 breaches do not trip again.
    for seq in 12..=13 {
        let v = fx.trident.verify(&transplanted(&fx, seq));
        assert_eq!(v.refusal().unwrap().resolution, Resolution::Reject);
    }
}

#[test]
fn quarantine_survives_an_operator_reset() {
    let fx = setup_with(TridentConfig {
        breaker_threshold: 1,
        ..TridentConfig::default()
    });
    let v = fx.trident.verify(&transplanted(&fx, 1));
    assert_eq!(v.refusal().unwrap().resolution, Resolution::Quarantine);
    fx.trident.operator_reset();
    assert_eq!(fx.trident.quarantined().unwrap(), vec![fx.fp_a]);
}

#[test]
fn breaches_outside_the_window_do_not_trip() {
    let fx = setup_with(TridentConfig {
        breaker_threshold: 2,
        breaker_window_ms: 1_000,
        ..TridentConfig::default()
    });
    fx.trident.verify(&transplanted(&fx, 1));
    fx.clock.advance(1_001);
    let v = fx.trident.verify(&transplanted(&fx, 2));
    assert_eq!(v.refusal().unwrap().resolution, Resolution::Reject);
    let v = fx.trident.verify(&transplanted(&fx, 3));
    assert_eq!(v.refusal().unwrap().resolution, Resolution::Quarantine);
}

#[test]
fn forgeries_and_replays_cannot_quarantine_a_sender_by_default() {
    let fx = setup_with(TridentConfig {
        breaker_threshold: 2,
        ..TridentConfig::default()
    });
    let good = fx.sealed(1);
    assert!(fx.trident.verify(&good).is_accepted());
    for _ in 0..5 {
        // Replays of a genuine envelope: authenticated, but anyone can do it.
        assert!(fx.trident.verify(&good).refusal().unwrap().has(Replay));
        // Forgeries under A's name: not authenticated.
        let mut forged = fx.sealed(50);
        forged.mac = "11".repeat(32);
        assert_eq!(fx.trident.verify(&forged).refusal().unwrap().resolution, Resolution::Reject);
    }
    assert!(fx.trident.quarantined().unwrap().is_empty());
}

#[test]
fn claimed_sender_attribution_counts_forgeries() {
    let fx = setup_with(TridentConfig {
        breaker_threshold: 2,
        breaker_attribution: BreakerAttribution::ClaimedSender,
        ..TridentConfig::default()
    });
    let mut forged = fx.sealed(1);
    forged.mac = "22".repeat(32);
    assert_eq!(fx.trident.verify(&forged).refusal().unwrap().resolution, Resolution::Reject);
    assert_eq!(fx.trident.verify(&forged).refusal().unwrap().resolution, Resolution::Quarantine);
    assert_eq!(fx.trident.quarantined().unwrap(), vec![fx.fp_a]);
}

// ---------------------------------------------------------------------------
// Halt, capacity
// ---------------------------------------------------------------------------

#[test]
fn operator_halt_stops_all_work_until_reset() {
    let fx = setup();
    fx.trident.operator_halt();
    assert!(fx.trident.is_halted());
    for v in [fx.trident.verify(&fx.sealed(1)), fx.trident.verify_wire(b"garbage")] {
        let r = v.refusal().unwrap();
        assert_eq!(r.reasons, vec![Halted]);
        assert_eq!(r.resolution, Resolution::Halt);
        assert_eq!(r.outcome, GateOutcome::Retry);
    }
    fx.trident.operator_reset();
    fx.clock.advance(fx.cfg.max_future_skew_ms + 1);
    assert!(fx.trident.verify(&fx.sealed(1)).is_accepted());
}

#[test]
fn replay_cache_full_is_retry_and_drains_with_time() {
    let fx = setup_with(TridentConfig {
        replay_cache_capacity: 2,
        ..TridentConfig::default()
    });
    assert!(fx.trident.verify(&fx.sealed(1)).is_accepted());
    assert!(fx.trident.verify(&fx.sealed(2)).is_accepted());
    let v = fx.trident.verify(&fx.sealed(3));
    assert_eq!(reasons(&v), vec![ReplayCacheFull]);
    assert_eq!(v.outcome(), GateOutcome::Retry);
    fx.clock.advance(fx.cfg.replay_retention_ms());
    assert!(fx.trident.verify(&fx.sealed(4)).is_accepted());
}

#[test]
fn sender_table_full_is_retry() {
    let fx = setup_with(TridentConfig {
        max_tracked_senders: 1,
        ..TridentConfig::default()
    });
    assert!(fx.trident.verify(&fx.sealed(1)).is_accepted());
    let v = fx.trident.verify(&fx.sealed_by(&fx.key_b, 1));
    assert_eq!(reasons(&v), vec![SenderTableFull]);
    assert_eq!(v.outcome(), GateOutcome::Retry);
}

#[test]
fn invalid_config_is_refused_at_construction() {
    let cfg = TridentConfig {
        max_depth: 1_000,
        ..TridentConfig::default()
    };
    let err = Trident::with_system_clock(cfg, KeyRing::new(1)).unwrap_err();
    assert_eq!(err.field, "max_depth");
}

#[test]
fn concurrent_duplicates_are_accepted_once() {
    let fx = Arc::new(setup());
    let bytes = Arc::new(fx.wire(&fx.sealed(1)));
    let handles: Vec<_> = (0..8)
        .map(|_| {
            let fx = Arc::clone(&fx);
            let bytes = Arc::clone(&bytes);
            std::thread::spawn(move || fx.trident.verify_wire(&bytes).is_accepted())
        })
        .collect();
    let accepted = handles.into_iter().map(|h| h.join().unwrap()).filter(|a| *a).count();
    assert_eq!(accepted, 1);
}

// ---------------------------------------------------------------------------
// Canonical encoding interop vector
// ---------------------------------------------------------------------------

/// Known-answer vector produced by CPython with
/// `json.dumps(p, sort_keys=True, separators=(",", ":"), ensure_ascii=False)`.
#[test]
fn canonical_payload_matches_python_json_dumps_for_bmp_keys() {
    let p = json!({
        "zeta": [1, -2, 9_007_199_254_740_991_i64, -9_007_199_254_740_991_i64, 0],
        "alpha": {"b": true, "a": null, "c": false},
        "text": "q\"b\\/\u{8}\u{c}\n\r\t\u{1}\u{1f}\u{7f}\u{e9}\u{4e2d}\u{20ac}",
        "Upper": "",
        "\u{e9}key": [],
        "\u{ff61}": {}
    });
    let bytes = to_canonical_bytes(&p, &TridentConfig::default().limits()).unwrap();
    assert_eq!(
        sha256_hex(&bytes),
        "1d37dbf5538e1f9517a8e6a702dafb71e33bc0fc157399c63ac45d36b6b3ed32"
    );
}
