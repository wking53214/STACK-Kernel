# ≡STACK Kernel

Reference implementation of the ≡STACK governance kernel, written in Rust and C++ with comprehensive red-team validation. Each component was built, attacked by a separate red-team agent, hardened, measured and documented. The complete manual is in `manual/`.

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

Rust 1.94 was used. Dependencies are limited to the workspace list in
`Cargo.toml`.

```
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace --all-targets --no-fail-fast
```

The ANC red-team tests are timing-sensitive. On a loaded machine a run can fail one or two of them, for example `attack_one_slow_request_per_epoch_pins_cap`. Rerun before treating a failure as a regression. The Summary section lists the open ANC limits.

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

## Design Analogy: The Flywheel

≡STACK is built on a core principle: **enforcement is visibility**. Every time a boundary prevents execution—a deadline expires, a quota is exhausted, a capability is denied, memory is exceeded—that enforcement event is not logged and forgotten. Instead, it becomes the signal that tightens the next boundary.

### The River and Its Banks

Imagine a river system where banks are not static walls, but adaptive barriers. Water flows downstream with force. When it hits a bank, erosion patterns form. Over time, those patterns inform where to reinforce the banks. The banks reshape themselves in response to being tested by water. The water reshapes itself in response to the banks constraining it.

Neither the water nor the banks are static. They are in constant conversation.

### Applied to ≡STACK

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
  - Manual's ANC section explains signal detection limits
