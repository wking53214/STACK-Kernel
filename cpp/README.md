# C++23 Host Body Containment Stack

Production-locked implementation of the TACK Host Body — the system-level security boundary that contains and protects untrusted agent execution (Minotaur, from the Rust crates).

## Components (13/20 Completed)

| Component | Header | Purpose |
|---|---|---|
| 1-10 | stack_kernel.hpp | ≡TACK Kernel: StackArena, CapabilityGuard, DelegationTable, BoundedRingBuffer, KernelDispatcher, ExecutionContextSupervisor |
| 2-5 | stack_kinetic_governor.hpp + tier2 | Rate limiting, token bucket, reserved pool, dual-compensation rollbacks (RT-01-05 patches) |
| 6 | stack_kinetic_governor_tier2.hpp | ExecutionDeadlineScope (cooperative software deadline enforcement) |
| 7 | stack_kinetic_governor_tier2.hpp | BackpressureController (yield on high water mark) |
| 8-9 | stack_kinetic_governor_tier2.hpp | ComputeDebtTracker + deferred preemption hooks (RT-05: saturating CAS) |
| 10 | posix_deadline_timer_hardened.hpp | Persistent per-thread POSIX timer (≤220 cycles Arm), sival_ptr routing (RT-06, RT-08 fixes). The deadline timer only sets a flag that is read after the payload returns; a payload that never returns is not stopped. |
| 11 | stack_host_binding.hpp | SeccompFilterEngine: BPF-enforced signal mask immutability (RT-07 fix) |
| 12 | stack_host_binding.hpp | GovernedMinotaurHost: One-way security ratchet + boundary executor |
| 13 | stack_host_binding.hpp | SIMDCapabilityToken: 256-bit AVX2/NEON capability verification. The token is a caller-supplied request descriptor, not a credential: its context_id is caller-asserted and nothing authenticates it. |

The seccomp allowlist in `stack_host_binding.hpp` carries one syscall-number table per architecture (x86_64 and aarch64), and a `static_assert` against each `__NR_*` value turns a wrong entry into a compile error.

The filter attaches to the thread that installs it, and every thread that calls `InitializeAndSeal` or `ExecuteGovernedTransaction` installs its own, once, after creating its deadline timer (`timer_create` is not on the allowlist). It is not applied process wide with `SECCOMP_FILTER_FLAG_TSYNC`: that would also filter threads that never asked for it, such as a Rust caller's allocator and runtime threads, and would leave them unable to create a timer.

## Lock/Key Alignment with Rust Crates

- **stack-inlet** (Winnowing Filter) ← CapabilityGuard (boundary validation)
- **stack-minotaur** (Agent String / Recursion) ← HardenedPosixPreemptionGuard (preemption control)
- **stack-sentinel** (Audit Chain) ← BoundedRingBuffer (telemetry)
- **stack-trident** (Inter-Agent) ← DelegationTable (O(1) capability dispatch)
- **stack-greenwave** (Routing / Traffic) ← KineticGovernor (rate limiting)
- **stack-transmission** (Queue) ← ComputeDebtTracker + TransactionRollbackGuard

## Test Harnesses

- `test_stack_kernel.cpp` - 6 Catch2 suites, 10M ops chaos validation
- `test_kinetic_governor.cpp` (showstopper patches) - 3 suites validating RT-01-05 fixes
- `test_posix_deadline_timer_hardened.cpp` - 6 suites: signal registration, single/multi-thread preemption, TLS safety, cleanup
- `test_seccomp_policy_validator.cpp` - 2 suites: 4 evasion scenarios + whitelist compliance (fork/waitpid isolated)
- `test_host_binding.cpp` - Component 13 SIMD + Components 11&12 integration in isolated child

## Build

Requires C++23 compiler and Linux SECCOMP/POSIX timer support:

```bash
clang++ -std=c++23 -O3 -march=native cpp/tests/*.cpp -I cpp/include -o build/tests
./build/tests
```

## Vulnerability Fixes

- **RT-01**: 64-bit TSC multi-wrap refill via CAS-packed epoch|count
- **RT-02**: Transaction rollback window unrecord on abort
- **RT-03**: Counter-wrap protection for idle >2.86s
- **RT-04**: Instruction serialization fences (lfence/isb) preventing speculative leakage
- **RT-05**: Saturating CAS preventing compute debt overflow
- **RT-06**: sival_ptr routing eliminating __tls_get_addr deadlock in signal handler
- **RT-07**: SECCOMP-BPF blocking rt_sigprocmask preemption bypass
- **RT-08**: Persistent timer reuse (3500 → 220 cycles per Arm)
- **RT-09**: Signal handler only sets atomic flags, never pthread_exit
- **RT-10**: Idempotent per-thread timer initialization on recycled TID

## One-Way Security Ratchet

```
Phase 1: Bootstrap
  ↓ RegisterSignalHandler()
  ↓ InitializeThreadTimer()
  ↓
Phase 2: Irreversible Lockdown
  ↓ SeccompFilterEngine::InstallFilter()
  ↓
Phase 3: Governed Transaction
  → Token Consumption (Kinetic Governor)
  → Arm Hardened POSIX Timer
  → Execute Payload with Deadline Scope
  → Evaluate Preemption & Deadline Flags
  → Accrue Compute Debt
  → Commit (or Auto-Rollback)
```
