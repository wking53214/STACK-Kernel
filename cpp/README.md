# C++23 Host Body Containment Stack

Header-only C++23 implementation of the TACK host boundary: the layer that
runs an untrusted payload (Minotaur, from the Rust crates) under a governor
and, since Phase 6, in a supervised child process. See `CONTAINMENT.md` for
what is and is not guaranteed; this file lists what exists.

## Headers and what they define

| Header | Defines |
|---|---|
| `stack_kernel.hpp` | `PriorityClass`, `HardwareClock` (tick counter with serialization fences) |
| `stack_kinetic_governor.hpp` | `GovernorError`, `BackpressureController`, `ExecutionDeadlineScope` (cooperative software deadline), `ComputeDebtTracker`, `PackedBucket64`, `VolumeCounter`, `KineticGovernor` (per-domain token buckets), `TransactionRollbackGuard` |
| `posix_deadline_timer_hardened.hpp` | `HardenedPosixPreemptionGuard`: a per-thread `CLOCK_THREAD_CPUTIME_ID` timer whose signal handler sets a flag read after the payload returns. It does not stop a payload. |
| `stack_host_binding.hpp` | `CapabilityMask256`, `SIMDCapabilityToken` (a caller-supplied request descriptor, not a credential; nothing authenticates `context_id`), `SeccompFilterEngine` (per-thread allowlist), `GovernedMinotaurHost` (`ExecuteGovernedTransaction`: capability check, tokens, cooperative deadline, debt, rollback). Cooperative deadline only; not isolation. |
| `stack_supervised_exec.hpp` | `stack::supervised::SupervisedExecutor`: runs a payload in a supervised child under rlimits and a strict seccomp filter, with a wall-clock deadline enforced by SIGKILL from the parent, a bounded reap (`TerminationUnconfirmed`) and a strict outcome classification. `Run` forks the caller (not for untrusted payloads); `RunWorker` fork+execs the separate program `worker/stack_worker.cpp` (decision A, RACE-02). |
| `stack_arena.hpp` | `StaticArenaBuffer` (fixed-size arena with a 64-bit generation counter) |
| `stack_audit.hpp` | `SeccompAuditRing` (seqlock ring), `AuditEventRecord`, `AuditEventType`, `HmacSha256`. The "HMAC" is an XOR placeholder, stated as such in the source; the ring is telemetry, not a receipt. |

There is no `CapabilityGuard`, `DelegationTable`, `BoundedRingBuffer`,
`KernelDispatcher`, `ExecutionContextSupervisor` or
`stack_kinetic_governor_tier2.hpp`; earlier versions of this file named
them. There is no capability issuer or authorization in this layer: the
mask check is caller-supplied request against a host-global active mask.

The seccomp allowlist in `stack_host_binding.hpp` carries one syscall-number
table per architecture (x86_64 and aarch64) and a `static_assert` against
each `__NR_*` value turns a wrong entry into a compile error. The filter
attaches to the thread that installs it; every thread that calls
`InitializeAndSeal` or `ExecuteGovernedTransaction` installs its own, once,
after creating its deadline timer (`timer_create` is not on the allowlist).
It is not applied process wide with `SECCOMP_FILTER_FLAG_TSYNC`: that would
also filter threads that never asked for it, such as a Rust caller's
allocator and runtime threads. The supervised executor builds its own,
stricter filter in the child at runtime.

## Tests

All of these are registered in `CMakeLists.txt` and run under `ctest`
(26 entries in this build). The C++ job in `.github/workflows/ci.yml` runs 25 of them; `STACKWorkerReapPidReuse` is root-only and is left out.

- `tests/tests_all_components.cpp` (Catch2, `stack_tests`): governor, timer,
  arena, audit, debt refund, the real BPF jump-offset check in a forked
  child, capability race cases, per-thread sealing, the D-01 hard-timeout
  expiry on a sealed thread, zero-timeout refusal and fail-closed arming.
  Its "Capability Mutation Race Fix" Test 2 was scheduling dependent until RACE-02 step 5b made it deterministic (two `layer2_redteam` tests were fixed the same way); see `CONTAINMENT.md`.
- `tests/worker_exec_tests.cpp`, `tests/worker_reap_tests.cpp`, `tests/ffi_supervised_tests.cpp`
  (Catch2; ctest `STACKWorkerExec`, `STACKWorkerReap`, `STACKFfiSupervised`): the clean worker path,
  bounded reap and governance before spawn; see `CONTAINMENT.md`, "The clean worker path".
- `tests/supervised_exec_tests.cpp` (Catch2, `stack_supervised_exec_tests`):
  the supervised executor, 15 cases (the waitpid fallback has its own program, `tests/supervised_fallback_tests.cpp`); every hostile payload runs in a child.
- `tests/tests_production_hardened.cpp` (Catch2): five checks in one case;
  its banner covers that case only.
- Red-team programs (plain `main`, exit non-zero on failure):
  `layer2_redteam`, `layer4_redteam`, `layer5_redteam`, `layer6_redteam`,
  `layer6_wraparound_redteam`, `layer8_redteam`,
  `p3_audit_trail_signing_redteam`, `p3_per_domain_rate_limiting_redteam`,
  `ffi_init_redteam` (built with `STACK_FFI_TESTING=1`, registered as `STACKRedteam_ffi_init`).

## Build

Requires a C++23 compiler (tested with g++ 13.3; older versions are untested), CMake 3.22 or later, Catch2 3
and Linux with seccomp and POSIX timers. The project flags are
`-fno-exceptions -fno-rtti -Wall -Wextra -Werror -mavx2`.

```bash
cmake -S cpp -B build/cpp
cmake --build build/cpp -j"$(nproc)"
ctest --test-dir build/cpp --output-on-failure -LE needs-root
```

The `-LE needs-root` option leaves out the root-only entry (`STACKWorkerReapPidReuse`), which fails at once without root by design. Only x86_64 has been built and run, and CI runs only x86_64. The aarch64 tables compile-check
against `__NR_*` by `static_assert`, but no aarch64 build has been done.

## Fixes recorded in the sources

Each of these is described at the place it applies, with the test that
pins it:

- Fix comments at the code they touch, for example the "LAYER 6 P1 FIX" on the arena's 64-bit generation counter.
- D-01, D-03 (`rt_sigreturn` on the allowlist; zero hard timeout refused;
  arm failure fails closed) in `stack_host_binding.hpp`.
- D-02 (payload cannot be stopped in process) by `stack_supervised_exec.hpp`.

## Rust side

`crates/stack-ffi` wraps `GovernedMinotaurHost` (in-process path, with
distinct failure codes) and `SupervisedExecutor` (`supervised_run`, over a
fixed set of built-in payloads). Its host instance is
`GovernedMinotaurHost<1000, 100, 100, 2100000, 16>`: capacity 1000 tokens, 100 reserved, 100 largest request, 2,100,000 ticks per token, 16 domains. The reserved floor plus the largest request fits inside the capacity (see the comment in `crates/stack-ffi/src/ffi_wrapper.cpp`). An earlier instance with capacity 64 and reserved 100 rate-limited every Standard-priority transaction; that was fixed as R2-K-01 and is covered by the `[I-01]` cases in `tests/tests_all_components.cpp`.
