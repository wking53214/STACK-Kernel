# ≡TACK Kernel

Reference implementation of the ≡TACK governance kernel, written in Rust and C++ with comprehensive red-team validation. Each component was built, attacked by a separate red-team agent, hardened, measured and documented. The complete manual is in `manual/`.

These crates are built around the CNS gate contract (`cns/gate.py` in [CNS](https://github.com/wking53214/CNS), Apache-2.0). Several source comments reference that contract.

`stack-sentinel` reproduces CNS's subject digest (`cns.gate.subject_digest`) in Rust, and it is held to CNS's own answer key: `crates/stack-sentinel/tests/fixtures/cns-digest-vectors.json` is a copy of CNS's `contracts/digest-vectors.json` (contents and the digest CNS gives each, chosen to catch near-misses), and `cargo test -p stack-sentinel --test cns_vectors` recomputes every one. CNS checks this copy against its own, so a stale one is reported there.

## What is here

| Crate | Component |
|---|---|
| `stack-inlet` | 1. Inlet Winnowing Filter (UTF-8 + Unicode validation) |
| `stack-trident` | 2. Inter-Agent Trident (zero-trust envelope verification) |
| `stack-minotaur` | 3. Minotaur String (recursion depth + cycle detection) |
| `stack-greenwave` | 4. Green Wave Routing (fair scheduling + deterministic dispatch) |
| `stack-transmission` | 5. Transmission Queue (worker pool coordination) |
| `stack-sentinel` | 6. Sentinel Hash-Chain (Rust verifier; ledger in sentinel_os) |
| `stack-p3-2` | P3.2 Hard Preemption (hybrid boundary model + trap logging) |
| `stack-anc-ceiling` | ANC strategy 1: deterministic ceiling padding |
| `stack-anc-adaptive` | ANC strategy 2: adaptive rolling-average blinding |
| `stack-anc-pipeline` | ANC strategy 3: instruction-level pipeline padding |
| `stack-anc-harness` | Timing measurement harness (Welch t-test), test tooling |
| `_warm` | Dependency warm-up crate, not part of the kernel |

C++ headers (kernel layers 1-6) in `cpp/include/`:
| File | Component |
|---|---|
| `stack_kernel.hpp` | Foundation: CNS compatibility layer |
| `posix_deadline_timer_hardened.hpp` | Layer 2: Deadline timer + preemption detection |
| `stack_kinetic_governor.hpp` | Layer 3: Rate limiting + token bucket |
| `stack_host_binding.hpp` | Layer 4: Orchestration + SECCOMP enforcement |
| `stack_audit.hpp` | Layer 5: Audit trail + subject binding |
| `stack_arena.hpp` | Layer 6: Memory isolation + arena allocation |

`manual/sections/` holds the manual's sections as markdown. `manual/measurements/`
holds the raw timing runs the ANC sections quote. `manual/review/` holds the
final reviewer's findings. Not all of them are applied to the manual yet.

## Build and test

Rust 1.95 or newer is required (`rust-version` in `Cargo.toml`); the original reference
build used 1.94. Dependencies are limited to the workspace list in
`Cargo.toml`.

```
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace --all-targets --no-fail-fast
```

Some timing tests can fail on a loaded machine, for example `rt_driver_default_config_misses_no_phases`. Rerun a failing test alone before treating it as a regression. One test fails every time because it records an open finding: `shedding_reflects_load_only_for_balanced_dummy`, in ANC Strategy 3. The Summary section lists the open ANC limits.

CI tests the four ANC crates in two jobs, both in release and one test at a
time. `anc` runs every test except the wall-clock ones and blocks a merge.
`anc-wall-clock` runs exactly the wall-clock ones, named with the reason for
each in `ANC_WALL_CLOCK_TESTS` in `.github/workflows/ci.yml`, on every push
and pull request. It is marked `continue-on-error` because a shared runner
can fail them with no code change, so read its result before merging ANC
changes.

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

A second test in the same file, `live_edge_cases_differ_only_as_documented`, feeds both programs twelve hand-built inputs. They agree on six. On the other six Rust is stricter by design: duplicate JSON keys, nesting deeper than 256, a key file over 1 MiB, more than 64 keys, and keys supplied only through the environment.

## Design Analogy: The Flywheel

≡TACK is built on a core principle: **enforcement is visibility**. Every time a boundary prevents execution—a deadline expires, a quota is exhausted, a capability is denied, memory is exceeded—that enforcement event is not logged and forgotten. Instead, it becomes the signal that tightens the next boundary.

### The River and Its Banks

Imagine a river system where banks are not static walls, but adaptive barriers. Water flows downstream with force. When it hits a bank, erosion patterns form. Over time, those patterns inform where to reinforce the banks. The banks reshape themselves in response to being tested by water. The water reshapes itself in response to the banks constraining it.

Neither the water nor the banks are static. They are in constant conversation.

### Applied to ≡TACK

1. **Payload executes** within the six-layer containment boundary
2. **Boundary enforces**: deadline fires, quota exhausted, capability revoked, memory exceeded
3. **Trap event is logged** with full execution context
4. **Sentinel observes** patterns in trap logs and asks: which boundaries catch most, why, in what states?
5. **Boundaries reorganize** based on patterns—tighter deadlines for chronic overruns, reduced quotas for quota-busters
6. **Next transaction** loads reorganized boundaries
7. The flywheel turns: **traps → learning → reorganization → tighter boundaries → new traps**

### Technical Realization

| Layer | Role |
|-------|------|
| 1: HardwareClock | Measurement foundation (CPU clock ticks) |
| 2: Preemption | Detects deadline breach (signal-based flag) |
| 3: RateLimiting | Enforces quota (token bucket) |
| 4: Orchestration | Composes layers 1-3, enforces 5-6 (six gates) |
| 5: Audit | Records all verdicts with subject binding |
| 6: Isolation | Memory boundary isolation (arena) |
| P3.2: Hard Preemption | Hybrid model: signal sets flag + context-local state → trap events logged for Sentinel |

Every enforcement event is a data point. Sentinel runs offline analysis (Q1-Q6 queries on trap_events table) to identify which boundaries trap most, which agents trigger most traps, what patterns emerge. Based on patterns, boundaries are reorganized for next execution.

**Anti-isolation principle**: The system cannot hide enforcement from itself. Enforcement is the primary input to governance learning.

---

## Accepted timing residual (ANC strategy 1)

Status: accepted, documented, not eliminated. The padded response still has a small, measurable difference between the two secret-dependent paths. This section is the current record. Where it conflicts with older numbers in `manual/sections/anc_ceiling.md`, this section wins.

### What the residual is

`stack-anc-ceiling` releases every response at admission plus a fixed ceiling (50 µs in the tests). The validator used for measurement is `leaky_validate`, which stops at the first wrong byte. Class A (wrong at byte 0) finishes earlier than class B (wrong at byte 31). After padding, a difference remains between the two classes. Measured values, all on one 4-core virtual machine:

| Setup | Gap, class A minus B | Noise | Result |
|---|---|---|---|
| In-process, padded, 20 runs of 20,000 per class | about -2.8 ns (mean) | run-to-run sd 1.0 ns | 19 of 20 runs negative |
| Loopback socket, 4 connections, one source, 10 runs of 3 s | -2.39 ns | standard error 0.22 ns | t = -10.8, 10 of 10 runs negative |
| Same, A vs A control (no difference expected) | -0.07 ns | standard error 0.33 ns | t = -0.2, valid |
| Loopback socket, 1 connection, 800,000 requests | -3.2 ns (middle 50%) | per request sd 1.28 µs | t = -0.8, not detectable at this sample size |

The sign has been negative in every run we measured on this machine except one early subagent run, which reported the opposite sign for the same seeds. We have not reproduced that run, and we don't know its cause.

### What an attacker needs (estimates, not measurements on a real network)

These use the standard detection rule (|t| of at least 4.5) and assume independent noise, which is the attacker's best case.

- **One connection, loopback:** about 6.6 million requests per class (about 13 million total). At about 83 µs per round trip, roughly 18 minutes of traffic.
- **Four connections, loopback:** about 70,000 requests per class (about 140,000 total), roughly 2 seconds at about 67,000 requests per second. The per-request noise drops under concurrency, probably because server threads stop sleeping between requests.
- **A network adds noise.** Real networks are noisier than loopback, which raises these numbers. We have not measured a real network, so the attack cost on one is unknown.

Loopback is the most favorable channel for an attacker. If a real deployment is slower to attack than these figures, that is a property of the network, not of the padding.

### What we tried and why it is not a fix

- **A memory barrier after the validator** (1,000 fences). In-process, it cut the gap to about -0.9 ns, but that result is not a fix. It added about 6 µs per request, and at 4 connections the overrun rate rose from 0.002% to 0.075% and errors from 2 to 34. The release-time check failed, so the barrier was not adopted.
- **Padding overshoot exists even without load.** The 99th percentile release lands 11 to 14 µs past the 50 µs ceiling at every connection count tested (1, 2, 4 and 8). The median overshoot is under 0.1 µs.
- **Overrun replies are a separate timing class.** Under 4 connections, 2 of about 200,000 padded operations finished after the hard ceiling and were answered with `Trip::Overrun`. Their release time differs from normal replies. The cause is probably the OS briefly descheduling a spinning thread (not measured). Overruns are counted, not hidden.
- **Eight connections** produced 2 client errors out of 8 clients. We have not identified the error type.

### What limits the damage

- **Per-source guard** (`stack-anc-ceiling::source_guard`, PR #54, merged). Caps requests in flight per source and failed checks per source, with a cooldown. In a 3-second test from one source with 4 connections, 11 requests were admitted and 200,757 were refused, and refused responses were released on the same schedule as admitted ones. The guard is a library module. It is **not yet wired into any service**, and its limits are not tuned, because the legitimate failure rate per source is unknown.
- **A source-spreading attacker** is slowed, not blocked. Each source has its own budget, so cost rises with the number of sources needed.

### What is not claimed

- That the two paths take the same time. They do not, by about 2 to 3 ns in our runs.
- That the residual is zero, or that the test `calibrated_spin_padding_hides_the_early_exit` proves it. That test checks for a measurable difference under its own rules. It is non-blocking in CI and fails under load.
- Attackers on the same physical core, through shared cache, or through a sibling hardware thread (SMT). These are outside the threat model.
- Any real network, any production load pattern, or any second machine.
- That the sign of the residual is fixed across all setups. It was negative in every run we kept, with one unexplained exception.

### How this was accepted

The residual is accepted as a known, bounded risk for this library. The bound depends on the attacker's channel and request budget, and the mitigation available now is the per-source guard, which is not yet deployed. Anyone deploying the library in front of an untrusted network must (1) wire in the guard, (2) set its limits from the legitimate failure rate for that deployment, (3) monitor overrun and refusal counts, and (4) decide whether the estimates above are acceptable for their threat model.

The loopback measurements came from scratch harnesses that are **not committed to this repository**, so they cannot be reproduced from the repo as it stands.

## Known state

- Defect-fixing phase COMPLETE (October 2, 2026)
  - All six layers + P3.2 hardened
  - 15 architectural defects identified and fixed
  - 6 red-team validation passes
  - All tests passing
  - See `manual/ELEGANT_COMPLETION_LOG.md` for details
- ANC timing-sensitive tests may fail under load
  - Run on idle machine for reliable results
  - Strategy 1 (`rt04`) and Green Wave driver tests affected
- ANC cannot make timing difference zero mathematically
  - See "Accepted timing residual" above for the measured residual and its limits
  - Manual's ANC section explains signal detection limits
