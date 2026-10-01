# stack-kernel

Reference implementations of the STACK governance kernel, written in Rust and
purple-teamed. Each component was built, attacked by a separate red-team
agent, fixed, measured and documented. The manual that describes all of it is
in `manual/`.

**Private on purpose.** These crates are built around the CNS gate contract
(`cns/gate.py` in the CNS repository), which carries a confidentiality
notice. Several source comments point at that file by path. Do not make this
repository public without clearing that first.

## What is here

| Crate | Component |
|---|---|
| `stack-inlet` | 1. Inlet Winnowing Filter |
| `stack-trident` | 2. Inter-Agent Trident |
| `stack-bumpers` | 3. Elastic Bumpers |
| `stack-minotaur` | 4. Minotaur String |
| `stack-greenwave` | 5. Traffic Cop and Green Wave Routing |
| `stack-transmission` | 6. Tractor Transmission |
| `stack-sentinel` | 7. Sentinel Hash-Chain (Rust verifier; the ledger itself lives in sentinel_os) |
| `stack-anc-ceiling` | ANC strategy 1: deterministic ceiling padding |
| `stack-anc-adaptive` | ANC strategy 2: adaptive rolling-average blinding |
| `stack-anc-pipeline` | ANC strategy 3: instruction-level pipeline padding |
| `stack-anc-harness` | Timing measurement harness (Welch t-test), test tooling |
| `_warm` | Dependency warm-up crate, not part of the kernel |

`manual/sections/` holds the manual's sections as markdown. `manual/measurements/`
holds the raw timing runs the ANC sections quote. `manual/review/` holds the
final reviewer's findings, all of which were applied to the manual.

## Build and test

Rust 1.94 was used. Dependencies are limited to the workspace list in
`Cargo.toml`.

```
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace --all-targets --no-fail-fast
```

Timing measurements need release builds on a quiet machine:

```
cargo run --release -p stack-anc-ceiling --example verify
```

The Rust Sentinel verifier can also be checked against the real Python one. The
cross-check runs both programs as separate processes on the same 211 recorded
cases and fails on any difference that is not listed in the test, or when a
listed difference stops happening. It needs a `sentinel_os` checkout and a
Python with its dependencies, so it is ignored by default:

```
SENTINEL_OS_DIR=/path/to/sentinel_os PYTHON=/path/to/venv/bin/python \
    cargo test -p stack-sentinel --test crosscheck -- --ignored
```

It currently reports one understood difference (an anchor that seals zero rows:
Python says `VERIFIED`, Rust says `TRUNCATED`). The header of
`crates/stack-sentinel/tests/crosscheck.rs` explains the rest.

## Known state

- Ten red-team tests fail on purpose, all in the three ANC strategy crates (1 in Strategy 1, 3 in Strategy 2, 6 in Strategy 3).
  They record weaknesses that were found and not fixed, and the manual
  lists each one. A recorded gap stays a failing test, never a skipped one.
- Two timing-sensitive suites fail intermittently on a loaded host:
  Strategy 1's `rt04` and the Green Wave driver tests. Run them on an idle
  machine before trusting a red result.
- ANC cannot make a timing difference zero, and a t-test cannot prove a leak
  absent. The manual explains why in its ANC analysis section.
