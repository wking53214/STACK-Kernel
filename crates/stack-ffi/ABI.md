# stack-ffi: C ABI, behaviour and what is tested

This is the contract of the exported C symbols in `src/ffi_wrapper.cpp` and
of the Rust wrappers in `src/lib.rs`, as changed by the RACE-02 steps 1 to 5.
Every statement carries one of four labels:

- **tested**: a test in this repository fails if the statement is false;
  the test is named.
- **implemented**: the code does it; no test proves it, or only part of it.
- **experimental**: it works in the cases tried and is not a guarantee.
- **planned**: not done.

Anything that could not be shown by a test is labelled **BLOCKED** with the
reason. Nothing here is a claim beyond the tests named.

The in-process path is a cooperative governor, not isolation. A payload that
must be stopped goes through `stack_supervised_run` (see `cpp/CONTAINMENT.md`).

## 1. ABI delta, base to HEAD

Base is `ccr-2a7ddb2d-fccloq`. Symbol names and signatures of every symbol
that existed before are unchanged. Additions and changes of meaning:

| Step | Symbol | Change |
|---|---|---|
| 1 | `uint64_t stack_host_payload_count(void)` | NEW. How many times the built-in governed payload has run. A completed transaction ran it once; a refused one did not. |
| 1 | `int stack_host_audit_read_slot(index, *event_type, *timestamp, *context_id, *tokens)` | NEW. Reads the host's own governance audit ring. 0 filled, -1 not initialized, null pointer or empty slot. |
| 1 | `stack_execute_governed_transaction` | Behaviour: a valid transaction now completes (it returned -5 for every request). A request above 100 tokens and a domain id of 16 or more are -5. The policy is in section 2. |
| 2 | `int stack_host_initialize(void)` | NEW. Process initialization only. 0 or -1 (failed, latched). |
| 2 | `int stack_host_seal_current_thread(void)` | NEW. Seals the calling thread. 0, -1 not initialized, -2 seal failed, -3 initialization failed. |
| 2 | `stack_host_initialize_and_seal` | Same name and signature. -1 now means "initialization failed (latched)"; -2 "this thread could not be sealed", unchanged. |
| 2 | `stack_host_set_capabilities` | NEW -3: initialization failed (latched). A mask is never applied to a host that did not finish initializing. |
| 2 | `stack_execute_governed_transaction` | NEW -11: calling thread not sealed (no implicit seal any more). NEW -12: initialization failed. |
| 3 | `stack_execute_governed_transaction` | Accounting: -6, -7 and -8 now keep the transaction's tokens and charge its ticks (section 4). Codes unchanged. |
| 4 | `stack_host_set_capabilities` | 0 now also means no transaction runs or will run with the old mask. -2 is narrower: the in-flight transactions did not drain within 500 ms, the mask was NOT applied and nothing is left pending. The call may now block for up to 500 ms. |
| 4 | `stack_execute_governed_transaction` | NEW -13: a capability change is pending; nothing ran, nothing was consumed; retry. |
| 5a | Rust `audit_read_slot` | Result flipped to what its documentation said: `Some` for a written slot, `None` for an empty one. The C symbol `stack_audit_read_slot` is unchanged. |

Test-only, present only when compiled with `-DSTACK_FFI_TESTING` (CMake
`ffi_init_redteam`; never defined by `build.rs`):
`uint64_t stack_ffi_testing_init_work_runs(void)` and
`uint64_t stack_ffi_testing_host_constructions(void)`.

Rust additions in `src/lib.rs`: `host_initialize`, `host_seal_current_thread`,
`host_payload_count`, `host_audit_read_slot`, `HostAuditEvent`,
`HostAuditRecord`, `SealError`, `HostError::SealFailed`,
`CapabilityError::InitializationFailed`,
`TransactionError::{ThreadNotSealed, InitializationFailed, CapabilityChangePending}`.

### Return codes

`stack_host_set_capabilities`

| Code | Meaning |
|---|---|
| 0 | Applied. No transaction runs or will run with the old mask. |
| -1 | Not initialized (not yet, or another thread is still initializing). |
| -2 | Not applied: in-flight transactions did not drain within 500 ms. Nothing is left pending. Retry or escalate. |
| -3 | Initialization failed (latched). |

`stack_execute_governed_transaction`

| Code | Meaning |
|---|---|
| 0 | Completed. |
| -1 | Host not initialized. |
| -3 | Setup failure (seccomp, signal handler or timer_create). |
| -4 | Capability validation failed. |
| -5 | Rate limited (also: request above 100 tokens, domain id 16 or more). |
| -6 | Hard (CPU-time) deadline fired. Payload ran. |
| -7 | Software tick budget exceeded. Payload ran. |
| -8 | Compute debt ceiling exceeded. Payload ran. |
| -9 | `hard_timeout_nanoseconds` was 0. Nothing ran. |
| -10 | The deadline timer could not be armed. Nothing ran. |
| -11 | Calling thread not sealed. Nothing ran; the thread is untouched. |
| -12 | Initialization failed (latched). Nothing ran. |
| -13 | A capability change is pending. Nothing ran, nothing consumed. |

## 2. Governance policy of the FFI host

`GovernedMinotaurHost<1000, 100, 100, 2'100'000, 16>` with the refill rate
measured at initialization: 1000 tokens per domain, a floor of 100 that a
standard request may not dip into, a largest single request of 100, 16
domains, a refill of 1000 tokens per second. A domain can burst 900 tokens and
then sustain 1000 per second in requests of at most 100.
`KineticGovernor` `static_assert`s `Reserved + MaxBurst <= MaxCapacity`, so
the pre-step-1 configuration (`Reserved` 100 in a bucket of 64, which rejected
every transaction) no longer compiles.

- tested: valid transaction completes and runs the payload; exhaustion is
  rate limited and refusals run no payload; a 300 ms refill restores two
  requests of 100; concurrent transactions consume exactly the tokens expected;
  oversize request and unknown domain are refused (`cpp/tests/ffi_host_tests.cpp`,
  the Rust tests through the FFI).
- implemented, not tested: the refill rate is calibrated once against
  `CLOCK_MONOTONIC` over 10 ms. Behaviour on a machine whose TSC frequency
  changes at run time is not tested.
- not done: R2-K-15 is closed only in the sense that `MaxBurst` is now
  enforced; the rate is still measured in raw ticks.

## 3. Initialization state machine

```
Uninitialized --CAS--> InProgress --> Ready
                                  \-> Failed   (latched for the process)
```

- One thread wins the compare and swap and does the one-time work: signal
  handler registration, then creation of its own deadline timer, then
  construction of the host (including the calibration). The others see the
  result at once or yield while it is in progress.
- The host pointer is written before the release store of `Ready` and read
  after an acquire load of `Ready`: no caller sees a partial host, and the host
  is constructed once.
- `Failed` is latched. Nothing is retried. There is no recovery in this
  process; the caller restarts. Every entry point reports it with its own code
  (initialize -1, seal -3, set_capabilities -3, execute -12).
- A failure before construction constructs no host.
- Initialization and sealing are separate. A transaction never seals its caller
  (decision B): an unsealed thread gets -11 and is left exactly as it was.
  Sealing is irreversible and per thread; the seccomp filter attaches to the
  thread that installs it.
- No `std::mutex`, no allocation and `-fno-exceptions` in the initialization
  path, so nothing can throw across the C ABI.

Tested: `cpp/tests/ffi_init_redteam.cpp` (ctest `STACKRedteam_ffi_init`):
before initialization every entry point says not initialized and seals nothing;
in a forked child with `timer_create` failing, 8 barrier-released first
callers all see -1, set_capabilities is -3, execute is -12, seal is -3, the
work ran once, no host was constructed and the failure stays latched after the
fault is removed; 64 barrier-released initializations all return 0, the work
ran once and one host was constructed; 16 initializers racing 4 setters and 4
sealed executors return only documented codes; a transaction on an unsealed
thread is -11, runs no payload and leaves the thread unfiltered; repeated
initialization and sealing are idempotent. Rust: an unsealed thread is refused
with `ThreadNotSealed` and can still open files while a sealed one cannot; 16
concurrent `host_initialize` calls agree.

Not tested: failure of the signal handler registration (only `timer_create`
failure is injected); initialization racing `fork`.

## 4. Accounting rules

Stated at the point they apply in `stack_host_binding.hpp`:

1. A transaction rejected before its payload ran costs nothing: zero hard
   timeout, capability denial, rate limit, oversized request, unknown domain,
   timer arm failure, failed re-validation, **a pending capability change**.
   Tokens it had consumed are refunded, no debt is charged.
2. Once the payload has run, its tokens are spent whatever the outcome
   (completed, -6, -7, -8) and its elapsed ticks are charged as debt. The
   charge is best effort against the ceiling: when it does not fit, the debt
   stays where it is and nothing is refunded. An overrun pays for its tokens
   and its ticks. At the ceiling nothing is refunded (R2-K-05, R2-K-06).

Tested (`tests_all_components.cpp`, tag `[I-03]`; `ffi_host_tests.cpp`; Rust):
at the ceiling the debt is unchanged and exactly 89 more requests of 10 run;
a software overrun and a hard preemption leave debt above zero and exactly 89
more requests of 10; ten capability denials, ten oversized requests and a
forged timer id leave debt zero and all 90 requests; through the FFI, an
overrun of 100 tokens is followed by 8 requests of 100, not 9. `DebtTracker()`
(`ComputeDebtTracker::Accrued`) is exposed so the rule can be read.

Not done: the audit ring records no event for a transaction refused as
pending (a new event type would change the audit enum).

## 5. Revocation semantics

`stack_host_set_capabilities` is the revocation call.

- Before step 4 the change was refused whenever any transaction was in flight
  anywhere, so under steady load a revocation never applied (R2-K-07; baseline
  probe: never within 2 s with 8 executors).
- Now: if nothing is in flight the mask applies at once. Otherwise the change
  becomes **pending** and waits, up to 500 ms (`kCapabilityDrainNs`), for the
  last in-flight transaction to leave. While a change is pending, **new
  transactions are refused with -13**: they do not wait, they fail closed
  before anything is consumed (nothing runs, no tokens, no debt, no audit
  record: tested for "payload did not run" and "debt is zero"; implemented, by
  the order of the checks, for the rest). The in-flight set can then only
  shrink, so the change applies as soon as it drains.
- 0 means the mask is applied and no transaction is running or will run with
  the old one. The change applies only with none in flight.
- -2 means the in-flight transactions did not drain in time (a payload that
  does not return holds them; the deadline is cooperative). The mask is NOT
  applied, nothing is left pending, and the host serves under the old mask
  again. The caller retries or escalates; a revocation that must happen
  cannot be assumed after -2.
- Several changes may wait at once; new transactions stay refused while any
  waits; one that times out leaves the others waiting (tested); each applies
  when it sees the host drained and the last to apply is the mask that stays
  (implemented, ordering not tested).
- Do not call it from inside a payload: the caller is itself in flight, so the
  wait runs to its bound.
- The C++ host also keeps `SetActiveCapabilities(mask)` (try once, can still
  be starved, unchanged) and adds `SetActiveCapabilitiesWithin(mask, max_wait)`,
  `PendingCapabilityChanges()` and `HostExecutionError::CapabilityChangePending`.
  The FFI uses the second form.

Tested:
- `ffi_host_tests.cpp` "a revocation applies under sustained transaction load
  (R2-K-07)" and the Rust `test_revocation_applies_under_sustained_load_through_the_ffi`:
  8 sealed executors in a tight loop on 8 domains; the revocation applies
  within a 1 s bound (in practice on the first call); every transaction that
  began after it returned is -4; the payload counter does not move from the
  moment the call returned to the end of the load; restoring applies at once
  and the host serves. Failed on the unchanged code (-2 for the full second,
  both languages).
- `tests_all_components.cpp`, tag `[I-04]`, with a payload parked on a latch:
  a pending change refuses a new transaction with `CapabilityChangePending`
  (payload not run, debt 0) and has not returned while the transaction is held;
  on release it applies and the revoked capability is refused; a 60 ms bound
  times out, applies nothing, leaves nothing pending, and the host serves under
  the old mask; one setter timing out leaves the other holding the host closed.

Not tested, and why:
- The FFI's 500 ms timeout path: the FFI payload is a fixed built-in that
  cannot park, so a transaction cannot be held in flight through the C ABI.
  The same logic is tested at the host level with a 60 ms bound. BLOCKED at
  the FFI level.
- A revocation racing a payload that is blocked past its deadline: not tried.

## 6. Thread safety and ThreadSanitizer

ctest builds ThreadSanitizer versions of three programs when the CMake option
`STACK_FFI_TSAN` is on (the default); the CI `cpp` job runs them:

| ctest | Program | Covers |
|---|---|---|
| `STACKTsan_ffi_init` | `ffi_init_redteam` | initialization, 64 concurrent first callers, setters racing executors |
| `STACKTsan_ffi_revocation` | `ffi_host_tests` `[I-04]` | the sustained-load revocation through the shipped wrapper |
| `STACKTsan_capability_change` | `tests_all_components` `[I-04]` | pending change, in-flight counter and condition variable |

Status: clean. 0 reports; `STACKTsan_ffi_init` before step 2 reported two data
races on `g_host` (that was the baseline). Each program exits 66 on any
report, which fails the test. The sanitizer can fail these tests: with the
mask write moved outside the lock in `SetActiveCapabilitiesWithin` (mutant,
not committed) `STACKTsan_ffi_revocation` reports a data race.

Limits (stated, not hidden): a thread under the real seccomp allowlist cannot
`mmap`, which the sanitizer runtime needs, so these builds link
`cpp/tests/ffi_no_seccomp_interpose.cpp`, which makes `PR_SET_SECCOMP` a no-op.
They check the synchronization, not the filter; their "thread is filtered"
checks are reported as skipped. The filter is covered by the unsanitized
builds of the same tests. No Rust test runs under the sanitizer.

## 7. Not covered by this contract

- No isolation on the in-process path. `-6` is detected after the payload
  returns; a payload that never returns, or blocks in a syscall, is not stopped.
  The deadline signal can also arrive late under CPU contention (R2-K-16, up to
  182 ms of CPU time into a 50 ms budget in the probe, four cores, six busy
  loops); see `cpp/CONTAINMENT.md`.
- The audit ring's seqlock is single-writer (R2-K-10); the host ring is written
  from many threads. Not changed here.
- aarch64: the wrapper includes `<x86intrin.h>` unconditionally (R2-E-10);
  only x86_64 is built and tested.
