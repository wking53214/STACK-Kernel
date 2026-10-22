//! The harness writes its gate outcome with exactly the strings CNS uses,
//! and every copy of the CNS `GateOutcome` vocabulary in the workspace agrees.
//!
//! The expected strings are the values of `GateOutcome` in CNS `cns/gate.py`:
//! `PASS = 'pass'`, `RETRY = 'retry'`, `TERMINAL_BREACH = 'terminal_breach'`.
#![allow(clippy::unwrap_used, clippy::panic)] // test code: failures should abort the test

use stack_anc_harness::{GateOutcome, InconclusiveReason, Statistic, Verdict};

/// CNS `cns/gate.py`, `class GateOutcome`, in the order pass, retry,
/// terminal breach.
const CNS: [&str; 3] = ["pass", "retry", "terminal_breach"];

const HARNESS: [GateOutcome; 3] = [
    GateOutcome::Pass,
    GateOutcome::Retry,
    GateOutcome::TerminalBreach,
];

#[test]
fn harness_outcome_serializes_to_the_cns_strings() {
    for (o, want) in HARNESS.into_iter().zip(CNS) {
        assert_eq!(
            serde_json::to_value(o).unwrap(),
            serde_json::json!(want),
            "{o:?}"
        );
        assert_eq!(o.as_str(), want, "{o:?}");
    }
}

#[test]
fn verdict_outcomes_serialize_to_the_cns_strings() {
    let cases = [
        (Verdict::NoLeakDetected { max_abs_t: 1.0 }, "pass"),
        (
            Verdict::Inconclusive {
                reason: InconclusiveReason::TooFewSamples,
            },
            "retry",
        ),
        (
            Verdict::LeakDetected {
                max_abs_t: 9.0,
                source: Statistic::Raw,
            },
            "terminal_breach",
        ),
    ];
    for (v, want) in cases {
        let json = serde_json::json!({ "gate_outcome": v.gate_outcome() });
        assert_eq!(json["gate_outcome"], want, "{v:?}");
    }
}

/// The eleven Rust copies of the vocabulary. Eight spell the wire value with
/// `as_str`. The three ANC strategy crates use `label` for it (their metric
/// label); their `as_str` is the upper-case name used in log fields.
#[test]
fn every_workspace_copy_spells_the_cns_strings() {
    let copies: [(&str, [&str; 3]); 11] = [
        ("stack-anc-harness", HARNESS.map(GateOutcome::as_str)),
        ("stack-anc-ceiling", {
            use stack_anc_ceiling::GateOutcome as G;
            [G::Pass, G::Retry, G::TerminalBreach].map(G::label)
        }),
        ("stack-anc-adaptive", {
            use stack_anc_adaptive::GateOutcome as G;
            [G::Pass, G::Retry, G::TerminalBreach].map(G::label)
        }),
        ("stack-anc-pipeline", {
            use stack_anc_pipeline::GateOutcome as G;
            [G::Pass, G::Retry, G::TerminalBreach].map(G::label)
        }),
        ("stack-bumpers", {
            use stack_bumpers::GateOutcome as G;
            [G::Pass, G::Retry, G::TerminalBreach].map(G::as_str)
        }),
        ("stack-greenwave", {
            use stack_greenwave::GateOutcome as G;
            [G::Pass, G::Retry, G::TerminalBreach].map(G::as_str)
        }),
        ("stack-inlet", {
            use stack_inlet::GateOutcome as G;
            [G::Pass, G::Retry, G::TerminalBreach].map(G::as_str)
        }),
        ("stack-minotaur", {
            use stack_minotaur::GateOutcome as G;
            [G::Pass, G::Retry, G::TerminalBreach].map(G::as_str)
        }),
        ("stack-sentinel", {
            use stack_sentinel::GateOutcome as G;
            [G::Pass, G::Retry, G::TerminalBreach].map(G::as_str)
        }),
        ("stack-transmission", {
            use stack_transmission::GateOutcome as G;
            [G::Pass, G::Retry, G::TerminalBreach].map(G::as_str)
        }),
        ("stack-trident", {
            use stack_trident::GateOutcome as G;
            [G::Pass, G::Retry, G::TerminalBreach].map(G::as_str)
        }),
    ];
    for (krate, spelled) in copies {
        assert_eq!(spelled, CNS, "{krate}");
    }
}
