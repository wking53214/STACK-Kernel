# ≡TACK Kernel

Reference implementation of the ≡TACK governance kernel: Rust crates and C++23 headers that run in user space. It is **not an operating-system kernel** and is not loaded into one. Repository name: STACK-Kernel. The manual is in `manual/`.

Status: experiment. Last checked 2026-11-19 at commit `4d2287d`. License: Apache-2.0 (`LICENSE`). Prerequisites: Linux (seccomp, POSIX timers and `pidfd` are used), Rust 1.95 or newer, and for the C++ layer CMake 3.22 or newer, a C++23 compiler (`-fno-exceptions -fno-rtti`, plus `-mavx2` on x86_64) and Catch2 3, which the C++ build requires (`find_package(Catch2 REQUIRED)`). The C++ build and test commands are in `cpp/README.md`. The C++ headers carry syscall tables for x86_64 and aarch64 (INSPECTED).

## Role Within ≡TACK

- **What it is.** The enforcement-side reference code: an admission chain (a CNS decision and a capability in, a signed receipt out), a verify-only authorization boundary, receipts with an independent verifier, and a supervised worker that runs a payload under limits.
- **What it owns.** Recomputing the subject digest and decision root, checking a capability against its own trust set, one-time use, write-ahead receipts, and running a worker (the supervised C++ path) under a deadline and a seccomp filter.
- **What it contributes.** The part of ≡TACK that decides whether a signed capability may run and records what happened.
- **What it does not own.** The gate vocabulary and digest definition (CNS); deciding that a human approved (HUMANITY's issuer, which signs before the kernel sees anything); a production issuer or signing key (none exists here: tests use fixture keys derived from public labels); custody of the long-term ledger (sentinel_os; this repo holds the Rust verifier); authentication of a person (a shared key proves possession, not a person).
- **Depends on.** The CNS gate contract (`cns/gate.py`), held to CNS's own digest vectors by `stack-sentinel`'s `cns_vectors` test.
- **Depended on by.** `HUMANITY/issuer` pins this repo's crates at commit `e2f2134` (INSPECTED in its `Cargo.toml`). Other consumers: UNKNOWN. `stack-admission`'s README says nothing outside that crate calls it.
- **Verified versus declared.** Verified by tests that ran in this check: see "Build and test". Declared only: the flywheel below (trap logs feeding tighter boundaries), the `trap_events` table and Q1 to Q6 analyses, and any production deployment.
- **Governance and control design.** The kernel does not trust a CNS PASS, a matching digest or a decision's HMAC as permission. Permission exists only as an `AuthorizedAction` made by `Authority::authorize`. Evaluation, authorization and enforcement are separate steps here; the issuer that signs is outside this repo.

## Security notes

- Isolation exists only in the supervised worker path (`SupervisedExecutor::RunWorker`, fork and exec of a separate program under rlimits, a strict seccomp filter and a SIGKILL deadline). The in-process path (`GovernedMinotaurHost`) uses a cooperative deadline that does not stop a payload. See `cpp/CONTAINMENT.md`.
- `stack_audit.hpp` is telemetry. Its "HMAC" is an XOR placeholder stated as such in the source. It is not a receipt. Receipts are in `stack-receipt`.
- `stack_arena.hpp` is a fixed-size arena with a generation counter. Its header says reuse is not isolation.
- Failure behavior: the admission stages refuse on failure and record where a log is reachable (`crates/stack-admission/README.md`, section 1). A kernel killed during execution leaves an incomplete record (tested).
- Out of model: a kernel bug in seccomp, side channels, and a payload that runs legitimately for the whole deadline.

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
| `stack-admission` | End-to-end admission chain: a CNS decision and capability in, a signed receipt out |
| `stack-authority` | Verify-only authorization boundary: capabilities, scope, revocation |
| `stack-receipt` | Execution receipts and their independent verifier |
| `stack-bumpers` | Elastic Bumpers: a new design, see the crate's own status note |
| `stack-issuer` | Capability issuer as a library. Holds no key, runs no service. See the crate's README. |
| `stack-ffi` | C++/Rust FFI bridge to the containment stack |
| `_warm` | Dependency warm-up crate, not part of the kernel |

Ten of these crates open their own source with a "Status: new design" note: `stack-inlet`, `stack-trident`, `stack-minotaur`, `stack-greenwave`, `stack-transmission`, `stack-bumpers` and the four `stack-anc-*` crates (INSPECTED 2026-11-15). The notes describe reference implementations of components that are not running in any other ≡TACK repository. Read a crate's note before treating its row above as a working part of a deployed system.

C++ headers (kernel layers 1-6) in `cpp/include/`:

| File | Component |
|---|---|
| `stack_kernel.hpp` | Foundation: CNS compatibility layer |
| `posix_deadline_timer_hardened.hpp` | Layer 2: deadline timer that sets a flag read after the payload returns. Does not stop a payload. |
| `stack_kinetic_governor.hpp` | Layer 3: Rate limiting + token bucket |
| `stack_host_binding.hpp` | Layer 4: capability-mask check, per-thread seccomp allowlist, cooperative deadline. Not isolation. |
| `stack_audit.hpp` | Layer 5: audit telemetry ring. The HMAC is an XOR placeholder. Not a receipt. |
| `stack_arena.hpp` | Layer 6: fixed-size arena with a generation counter. Not isolation (see its header). |

`cpp/include/` also holds `stack_run_cancel.hpp` (lets another thread stop a supervised worker in flight) and `stack_supervised_exec.hpp` (supervised execution in a child process). Neither is a numbered layer.

`manual/sections/` holds the manual's sections as markdown. `manual/measurements/`
holds the raw timing runs the ANC sections quote. `manual/review/` holds the
final reviewer's findings. Whether each finding is reflected in the manual has not been checked.

## Build and test

EXECUTED 2026-11-19 at `4d2287d` (Rust 1.97, one pass, Linux): `cargo test -p stack-admission -p stack-authority -p stack-receipt -p stack-sentinel` gave 491 passed, 0 failed, 2 ignored (the same as the 2026-11-15 run at `14b48a0`). Since then `stack-issuer` and `stack-p3-2` changed (receipt verifier and caps; class-aware deadlines and an opt-in restart snapshot); those two crates were not run in this check, and the statements above about the issuer (a library, no key, no service) and about the host layers were re-read against the new code (INSPECTED 2026-11-19; the C++ headers are unchanged since `14b48a0`). That is four crates, not the workspace. The other crates, the clippy job and the C++ build and `ctest` were not run (UNKNOWN). A passing test shows the tested behavior holds. It is not universal security.

Rust 1.95 or newer is required (`rust-version` in `Cargo.toml`). The CI clippy job pins
Rust 1.99.0; the other CI jobs use the stable toolchain. Most external dependencies come
from the workspace list in `Cargo.toml`. A few crates declare their own external crates in their `Cargo.toml` files:
`stack-p3-2` in its normal dependencies, and `stack-ffi` only in its test dependencies.

```
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace --all-targets --no-fail-fast
```

Some timing tests can fail on a loaded machine, for example `rt_driver_default_config_misses_no_phases`. Rerun a failing test alone before treating it as a regression. The test `shedding_reflects_load_only_for_balanced_dummy` (ANC Strategy 3) records an open finding. It is marked `#[ignore]` (run with `--ignored`) because it asserts a property the brief's design does not have. Measured November 6, 2026 on a 2-vCPU machine: class A was shed more in all 14 runs (sign positive), by about 0.5 to 1.2 percentage points. |t| reached 4.5 in 3 of 14 runs, at 1.5 million probes (6 runs) or 6 million (8 runs). The older notes (8 of 8 detections in the manual; 2 of 2 debug failures) were not reproduced here, and their setup is not recorded. The Summary section lists the open ANC limits.

CI tests the four ANC crates in two jobs, both in release and one test at a
time. `anc` runs every test except the wall-clock ones. It has no `continue-on-error`,
so a failure fails the job; whether that blocks a merge depends on branch protection,
which this review did not check.
`anc-wall-clock` runs exactly the wall-clock ones, named with the reason for
each in `ANC_WALL_CLOCK_TESTS` in `.github/workflows/ci.yml`, on pushes to `main`
and on every pull request. It is marked `continue-on-error` because a shared runner
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

## Design analogy: the flywheel (intended, not implemented as described)

≡TACK is built on a core principle: **enforcement is visibility**. Every time a boundary prevents execution (a deadline expires, a quota is exhausted, a capability is denied, memory is exceeded), that enforcement event is not logged and forgotten. Instead, it becomes the signal that tightens the next boundary.

### The River and Its Banks

Imagine a river system where banks are not static walls, but adaptive barriers. Water flows downstream with force. When it hits a bank, erosion patterns form. Over time, those patterns inform where to reinforce the banks. The banks reshape themselves in response to being tested by water. The water reshapes itself in response to the banks constraining it.

Neither the water nor the banks are static. They are in constant conversation.

### Applied to ≡TACK

1. **Payload executes** under the host layers (isolation only on the supervised worker path)
2. **Boundary enforces**: deadline fires, quota exhausted, capability revoked, memory exceeded
3. **Trap event is logged** with full execution context
4. **Sentinel observes** patterns in trap logs and asks: which boundaries catch most, why, in what states?
5. **Boundaries reorganize** based on patterns, such as tighter deadlines for chronic overruns, reduced quotas for quota-busters
6. **Next transaction** loads reorganized boundaries
7. The flywheel turns: **traps → learning → reorganization → tighter boundaries → new traps**

### Technical Realization

| Layer | Role |
|-------|------|
| 1: HardwareClock | Measurement foundation (CPU clock ticks) |
| 2: Preemption | Detects deadline breach (signal-based flag) |
| 3: RateLimiting | Enforces quota (token bucket) |
| 4: Orchestration | Composes layers 1 to 3 around a trusted payload (cooperative; not isolation) |
| 5: Audit | Telemetry ring (placeholder MAC) |
| 6: Arena | Fixed-size arena; the header says it is not isolation |
| P3.2: Hard Preemption | Hybrid model: signal sets flag + context-local state → trap events logged for Sentinel |

Every enforcement event is a data point. The intended design has Sentinel run offline analysis (Q1-Q6 queries on a `trap_events` table) to identify which boundaries trap most, which agents trigger most traps, and what patterns emerge. Based on patterns, boundaries would be reorganized for the next execution. This repository records `TrapEvent`s in `stack-p3-2`, but it does not implement the table or the Q1-Q6 analyses; those are specified in `manual/sections/p3.2_schema_design.md`.

**Anti-isolation principle**: The system cannot hide enforcement from itself. Enforcement is the primary input to governance learning.

---

## Timing residual (ANC strategy 1)

Open and documented, not eliminated. A caller who can time the padded function directly can detect a small difference between the two secret-dependent paths in minutes (measured November 2026). The per-source guard that limits the damage is a library module and is not wired into any service. Two cropped-percentile checks are recorded as open findings (the fast lane, and the padded leaky validator) and are ignored by default. The loopback harnesses used for the measurements are not committed, so those numbers cannot be reproduced from this repository. Anyone deploying `stack-anc-ceiling` in front of an untrusted network must wire in the guard, set its limits from the legitimate failure rate, and monitor overrun and refusal counts. Full record: [`docs/anc-ceiling-residual.md`](docs/anc-ceiling-residual.md). Where it conflicts with older numbers in `manual/sections/anc_ceiling.md`, the doc wins.

## Known state

- Defect-fixing phase recorded as complete on October 2, 2026 (historical)
  - All six layers + P3.2 hardened, per the completion log
  - 15 architectural defects and 6 red-team passes, per the completion log (counts not re-verified in November 2026)
  - Not every test passes on every run. The ANC wall-clock job is non-blocking and failed on the last runs checked. The ANC timing tests fail under load, and one fails in debug builds (see above)
  - See `manual/ELEGANT_COMPLETION_LOG.md` for details
- ANC timing-sensitive tests may fail under load
  - Run on idle machine for reliable results
  - Strategy 1 (`rt04`) and Green Wave driver tests affected
- ANC cannot make timing difference zero mathematically
  - See "Timing residual (ANC strategy 1)" above for the measured residual and its limits (open for direct callers)
  - Manual's ANC section explains signal detection limits

Maintainer: William N. King.
