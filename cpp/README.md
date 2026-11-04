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
| `stack_supervised_exec.hpp` | `stack::supervised::SupervisedExecutor`: runs a payload in a forked child under rlimits and a strict seccomp filter, with a wall-clock deadline enforced by SIGKILL from the parent and a strict outcome classification. |
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
(eleven entries). The C++ job in `.github/workflows/ci.yml` runs them.

- `tests/tests_all_components.cpp` (Catch2, `stack_tests`): governor, timer,
  arena, audit, debt refund, the real BPF jump-offset check in a forked
  child, capability race cases, per-thread sealing, the D-01 hard-timeout
  expiry on a sealed thread, zero-timeout refusal and fail-closed arming.
  One pre-existing case is scheduling dependent; see `CONTAINMENT.md`.
- `tests/supervised_exec_tests.cpp` (Catch2, `stack_supervised_exec_tests`):
  the supervised executor, 12 cases; every hostile payload runs in a child.
- `tests/tests_production_hardened.cpp` (Catch2): five checks in one case;
  its banner covers that case only.
- Red-team programs (plain `main`, exit non-zero on failure):
  `layer2_redteam`, `layer4_redteam`, `layer5_redteam`, `layer6_redteam`,
  `layer6_wraparound_redteam`, `layer8_redteam`,
  `p3_audit_trail_signing_redteam`, `p3_per_domain_rate_limiting_redteam`.

## Build

Requires a C++23 compiler (g++ 13 or later), CMake 3.22 or later, Catch2 3
and Linux with seccomp and POSIX timers. The project flags are
`-fno-exceptions -fno-rtti -Wall -Wextra -Werror -mavx2`.

```bash
cmake -S cpp -B build/cpp
cmake --build build/cpp -j"$(nproc)"
ctest --test-dir build/cpp --output-on-failure
```

Only x86_64 has been built and run. The aarch64 tables compile-check
against `__NR_*` by `static_assert`, but no aarch64 build has been done.

## Fixes recorded in the sources

Each of these is described at the place it applies, with the test that
pins it:

- RT-01 to RT-10 (governor refill wrap, rollback, counter wrap, fences,
  saturating debt, `sival_ptr` routing, signal-mask immutability, timer
  reuse, flag-only handler, idempotent timer init) in
  `stack_kinetic_governor.hpp` and `posix_deadline_timer_hardened.hpp`.
- D-01, D-03 (`rt_sigreturn` on the allowlist; zero hard timeout refused;
  arm failure fails closed) in `stack_host_binding.hpp`.
- D-02 (payload cannot be stopped in process) by `stack_supervised_exec.hpp`.

## Rust side

`crates/stack-ffi` wraps `GovernedMinotaurHost` (in-process path, with
distinct failure codes) and `SupervisedExecutor` (`supervised_run`, over a
fixed set of built-in payloads). Its host instance is
`GovernedMinotaurHost<64, 100, 1000, 100, 16>`, whose `Reserved` (100)
exceeds `MaxCapacity` (64); every Standard-priority transaction through it
is rate limited. This is recorded in the crate's tests and not changed in
Phase 6.
