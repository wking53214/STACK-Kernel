//! Property tests: flipping any byte of an encoded envelope is rejected,
//! valid envelopes are accepted, and canonical encoding is a fixed point.

mod common;

use common::*;
use proptest::prelude::*;
use serde_json::{Map, Value};
use tack_trident::canonical::{parse_strict, to_canonical_bytes};
use tack_trident::{seal, EnvelopeDraft, GateOutcome, GatePosition, Nonce, TridentConfig, MAX_SAFE_INTEGER};

fn json_value() -> impl Strategy<Value = Value> {
    let safe = MAX_SAFE_INTEGER as i64;
    let leaf = prop_oneof![
        Just(Value::Null),
        any::<bool>().prop_map(Value::Bool),
        (-safe..=safe).prop_map(|n| Value::Number(n.into())),
        ".{0,12}".prop_map(Value::String),
    ];
    leaf.prop_recursive(4, 32, 6, |inner| {
        prop_oneof![
            prop::collection::vec(inner.clone(), 0..6).prop_map(Value::Array),
            prop::collection::btree_map(".{0,8}", inner, 0..6)
                .prop_map(|m| Value::Object(m.into_iter().collect::<Map<String, Value>>())),
        ]
    })
}

fn draft() -> impl Strategy<Value = EnvelopeDraft> {
    (
        1u64..1_000_000,
        any::<[u8; 16]>(),
        prop::bool::ANY,
        0usize..3,
        json_value(),
    )
        .prop_map(|(sequence, nonce, alpha, outcome, payload)| EnvelopeDraft {
            sequence,
            issued_at_unix_ms: 0, // filled in against the fixture clock
            nonce: Nonce::from_bytes(nonce),
            gate_position: if alpha { GatePosition::Alpha } else { GatePosition::Omega },
            gate_outcome: [GateOutcome::Pass, GateOutcome::Retry, GateOutcome::TerminalBreach][outcome],
            payload,
        })
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(512))]

    #[test]
    fn flipping_any_byte_of_the_encoded_envelope_is_rejected(
        mut d in draft(),
        pos in any::<prop::sample::Index>(),
        mask in 1u8..=255,
    ) {
        let fx = setup();
        d.issued_at_unix_ms = fx.now();
        let env = seal(d, &fx.key_a, &fx.cfg.limits()).unwrap();
        let mut bytes = fx.wire(&env);
        let i = pos.index(bytes.len());
        bytes[i] ^= mask;
        let v = fx.trident.verify_wire(&bytes);
        prop_assert!(!v.is_accepted(), "flip at {} by {:#04x} was accepted", i, mask);
    }

    #[test]
    fn sealed_envelopes_are_accepted(mut d in draft()) {
        let fx = setup();
        d.issued_at_unix_ms = fx.now();
        let env = seal(d, &fx.key_a, &fx.cfg.limits()).unwrap();
        let v = fx.trident.verify_wire(&fx.wire(&env));
        prop_assert!(v.is_accepted(), "{:?}", v);
    }

    #[test]
    fn canonical_encoding_is_a_fixed_point(v in json_value()) {
        let lim = TridentConfig::default().limits();
        let once = to_canonical_bytes(&v, &lim).unwrap();
        let parsed = parse_strict(&once, &lim).unwrap();
        prop_assert_eq!(&parsed, &v);
        prop_assert_eq!(to_canonical_bytes(&parsed, &lim).unwrap(), once);
    }
}
