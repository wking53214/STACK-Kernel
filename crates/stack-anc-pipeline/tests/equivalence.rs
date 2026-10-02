//! The three validators (and the counterexample, and the harness victims)
//! give the same answer on every input.

#![allow(clippy::unwrap_used, clippy::panic)] // test code: failures should abort the test

use proptest::prelude::*;
use sstack_anc_harness::victim::{ct_validate, leaky_validate};
use sstack_anc_pipeline::naive::balanced_dummy_no_black_box;
use sstack_anc_pipeline::{
    balanced_dummy, constant_time, early_exit, Accepted, PipelineConfig, PipelineGate, TokenSecret,
    Trip, Validator, TOKEN_LEN,
};

type Token = [u8; TOKEN_LEN];

fn all_agree(secret: &Token, cand: &Token) -> bool {
    let want = secret == cand;
    let answers = [
        early_exit(secret, cand),
        balanced_dummy(secret, cand),
        bool::from(constant_time(secret, cand)),
        balanced_dummy_no_black_box(secret, cand),
        leaky_validate(secret, cand),
        ct_validate(secret, cand),
    ];
    answers.iter().all(|&a| a == want)
}

fn gates(secret: &Token) -> Vec<PipelineGate> {
    Validator::ALL
        .iter()
        .map(|&validator| {
            let cfg = PipelineConfig {
                validator,
                allow_leaky_validators: true,
                ..PipelineConfig::default()
            };
            PipelineGate::new(TokenSecret::from_bytes(secret).unwrap(), cfg).unwrap()
        })
        .collect()
}

fn nonzero_token() -> impl Strategy<Value = Token> {
    any::<Token>().prop_filter("secret must not be all zero", |t| t.iter().any(|&b| b != 0))
}

proptest! {
    #![proptest_config(ProptestConfig {
        cases: 512,
        failure_persistence: None,
        ..ProptestConfig::default()
    })]

    #[test]
    fn random_candidates(secret in any::<Token>(), cand in any::<Token>()) {
        prop_assert!(all_agree(&secret, &cand));
    }

    #[test]
    fn one_byte_off(secret in any::<Token>(), pos in 0..TOKEN_LEN, flip in 1u8..=255) {
        let mut cand = secret;
        cand[pos] ^= flip;
        prop_assert!(all_agree(&secret, &cand));
        prop_assert!(!early_exit(&secret, &cand));
    }

    #[test]
    fn equal_tokens(secret in any::<Token>()) {
        prop_assert!(all_agree(&secret, &secret));
        prop_assert!(bool::from(constant_time(&secret, &secret)));
    }

    #[test]
    fn gates_agree(secret in nonzero_token(), cand in any::<Token>(), pos in 0..TOKEN_LEN, pick in 0u8..3) {
        // pick 0: random candidate; 1: one byte off; 2: exact match.
        let cand = match pick {
            0 => cand,
            1 => { let mut c = secret; c[pos] ^= 0x5a; c }
            _ => secret,
        };
        let want = if cand == secret { Ok(Accepted) } else { Err(Trip::Mismatch) };
        for g in gates(&secret) {
            prop_assert_eq!(g.check(&cand), want);
            prop_assert_eq!(g.in_flight(), 0);
        }
    }

    #[test]
    fn any_wrong_length_is_rejected_by_length(secret in nonzero_token(), len in 0usize..200) {
        prop_assume!(len != TOKEN_LEN);
        let input = vec![0x42u8; len];
        let want = if len > TOKEN_LEN { Trip::InputTooLarge } else { Trip::Malformed };
        for g in gates(&secret) {
            prop_assert_eq!(g.check(&input), Err(want));
        }
    }
}
