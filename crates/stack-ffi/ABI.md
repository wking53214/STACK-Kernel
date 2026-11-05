# stack-ffi: C ABI, behaviour and what is tested

This is the contract of the exported C symbols in `src/ffi_wrapper.cpp` and
of the Rust wrappers in `src/lib.rs`, as changed by the RACE-02 steps 1 to 5
and by decision A (the clean supervised worker, section 8).
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
| A3 | `int stack_supervised_run_governed(context_id, required_capability_m0, required_tokens, payload_kind, worker_path, limits, reap_timeout_ns, out, out_capacity, report)` | NEW. Capability and rate-limit checks through the initialized host BEFORE a clean worker program is spawned. Codes in section 8. |
| R2-K-20 | `stack_execute_governed_transaction`, `stack_supervised_run_governed` | Behaviour: `required_tokens == 0` is now -5 (rate limited), audited as a rate-limit event, nothing consumed, nothing run or spawned. Before, a zero-token request passed the governor's floor check for free (`available >= Reserved + 0`) and was accepted without limit (2000 of 2000 governed runs at 0 tokens, against 9 of 30 at 100 tokens). A caller that passed 0 must pass at least 1. |
| R2-K-21 | `int stack_supervised_run_governed(context_id, required_capability_m0, required_tokens, payload_kind, worker_path, worker_sha256, limits, reap_timeout_ns, out, out_capacity, report)` | SIGNATURE CHANGE relative to the previous commit of this series (the symbol is NEW relative to the base, so no base caller breaks): `const uint8_t* worker_sha256` (32 bytes) inserted after `worker_path`. REQUIRED. NULL is -16 (fail closed); an image that does not hash to it is -17. New -14 causes: a symlink in the path, setuid, setgid or group-writable image. |
| R2-K-21 | `int stack_supervised_image_sha256(const char* path, uint8_t out[32])` | NEW. SHA-256 of a file, for provisioning and for tests. 0, a positive errno, or -3 for a null argument. No trust policy. |
| R2-K-24 | `stack_host_set_capabilities`, `stack_supervised_run_governed` | A pending change now TERMINATES governed supervised workers in flight instead of waiting for them; the run's `report->outcome` is NEW value 13 `Terminated`. Section 5. |
| R2-K-24 | host audit ring, `AuditEventType` | NEW value 9 `SupervisedTerminated`, appended. |
| A3 | `uint64_t stack_supervised_unconfirmed_count(void)`, `uint64_t stack_supervised_reap_unconfirmed(void)` | NEW. Workers sent SIGKILL and not confirmed reaped; re-kill and reap them. |
| A2 | `stack_supervised_report` | Same size and layout. `reserved[3]` became `result_self_reported` (u8) and `reserved[2]`. Old callers read it as before; it is 1 on `Completed`. |
| A2 | `stack_supervised_report.outcome` | NEW value 12 `TerminationUnconfirmed`. A caller that switched over the outcome and had a default arm now sees it there. |
| A3 | `stack_supervised_run` | Unchanged signature and behaviour. Now documented LEGACY: its child is a fork of the caller, it makes no capability or rate-limit check and writes no audit event. Not for untrusted payloads. Nothing in this repository calls it except its own tests. R2-K-22: the C symbol is kept unchanged for ABI compatibility; the Rust wrapper `supervised_run` is now `pub unsafe fn` (with a `# Safety` section), so safe Rust can no longer reach it. Tested: `tests/api_surface.rs` (source guard: no safe public function reaches the symbol; `supervised_run` is `unsafe`) and a `compile_fail,E0133` doc test on `supervised_run`. |
| A3 | host audit ring, `AuditEventType` | NEW values 5 `SupervisedCompleted`, 6 `SupervisedTimedOut`, 7 `SupervisedFailed`, 8 `SupervisedTerminationUnconfirmed`, appended so 0 to 4 keep their numbers. `stack_host_audit_read_slot` returns them. |

Test-only, present only when compiled with `-DSTACK_FFI_TESTING` (CMake
`ffi_init_redteam`; never defined by `build.rs`):
`uint64_t stack_ffi_testing_init_work_runs(void)` and
`uint64_t stack_ffi_testing_host_constructions(void)`.

`SupervisedOutcome::Terminated` and `HostAuditEvent::SupervisedTerminated` (R2-K-24) are new Rust variants.

Rust additions for decision A in `src/lib.rs`: `supervised_run_governed`,
`GovernedSupervisedRequest`, `GovernedSupervisedError`,
`supervised_unconfirmed_count`, `supervised_reap_unconfirmed`,
`SupervisedOutcome::TerminationUnconfirmed`,
`SupervisedReport::result_self_reported`, `HostAuditEvent::{SupervisedCompleted,
SupervisedTimedOut, SupervisedFailed, SupervisedTerminationUnconfirmed}`,
`WORKER_BUILD_PATH`, `TESTING_WORKER_PATH` (hidden). `supervised_run` is
documented legacy and an `unsafe fn` (R2-K-22). `stack-admission`: `SupervisedExecutor` is no longer a unit
struct; it is built by `SupervisedExecutor::new(WorkerConfig)`, which fails
closed (new `ExecutorError::{Refused, WorkerUnavailable}`).

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
| -5 | Rate limited (also: request above 100 tokens, a request for 0 tokens (R2-K-20), domain id 16 or more). |
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
- tested (R2-K-20): a request for 0 tokens is rate limited on both the transaction
  and the governed supervised path, runs and spawns nothing, is audited, and
  takes nothing from the bucket (`ffi_host_tests.cpp` "a zero-token transaction
  is rate limited", `ffi_supervised_tests.cpp` "a zero-token request is rate
  limited").
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

### Revocation terminates governed supervised workers (R2-K-24)

Decision (approved): a pending revocation terminates the governed supervised
workers in flight. Before, `stack_host_set_capabilities` waited for them: with
a 3 s spin worker in flight it returned -2 after 500 ms, three times in a row,
and the worker ran to its deadline with the revoked capability still in force.

- implemented, tested: while a change waits, every governed supervised run in
  flight is requested to stop (`CancelHandle`, `cpp/include/stack_run_cancel.hpp`).
  Its worker is sent SIGKILL through its pidfd, the run ends with outcome
  `Terminated` (13; Rust `SupervisedOutcome::Terminated`, admission
  `RunOutcome::Terminated { signal: 9 }`), never a success
  (`result_self_reported` 0, `deadline_fired` 0), is audited as
  `SupervisedTerminated` (event 9) with its tokens SPENT (not refunded), and the
  change applies once the worker is reaped.
- implemented, tested: new governed runs are refused while a change is pending
  (-13, as for transactions): nothing is consumed or spawned. A run that was
  registered but not yet forked when the request came is not spawned and is
  refused with -13, tokens refunded.
- tested: with two 3 s workers (a spinner and a blocked one) in flight the
  change applied after 0.5 to 0.6 ms (measured, development host, five runs;
  asserted below 1 s) with both workers dead and reaped when it returned, both
  outcomes `Terminated` with `elapsed_ns` below 1 s, a later run with the revoked
  capability -4 with nothing spawned, and the terminated run's 100 tokens still
  spent. Tests: `ffi_supervised_tests.cpp` "a pending revocation terminates
  in-flight workers within a bound", Rust
  `test_revocation_terminates_in_flight_supervised_workers`, admission
  `worker_governance.rs`. The pre-existing "a revocation waits for a run in flight
  and then refuses" asserted the old wait and was changed to assert termination.
- tested (through a test-only seam, `STACK_SUPERVISED_TESTING`, that suppresses
  the cancellation kill): if the worker is not killed, the change stays pending,
  new governed runs get -13 meanwhile, and the call returns -2 at 500 ms with the
  mask NOT applied and nothing left pending ("new governed runs are refused while
  a change is pending, and an unkillable run leaves it unapplied").
- not changed: in-process transactions (`stack_execute_governed_transaction`)
  cannot be stopped; a pending change still waits for them, up to 500 ms.
- not tested: a worker stuck in uninterruptible sleep that SIGKILL cannot end
  (the same limit as `TerminationUnconfirmed`); then the call is -2 as above and
  the caller escalates.
- Behaviour change for callers: a revocation now ends the runs it overlaps. A
  caller that granted a capability and revokes it mid-run sees `Terminated`, not
  `TimedOut` or `Completed`. A worker that exits 0 with a good frame before the
  kill takes effect is still `Completed`: it finished first.

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

## 7. Not covered by this contract (and see section 8)

- No isolation on the in-process path. `-6` is detected after the payload
  returns; a payload that never returns, or blocks in a syscall, is not stopped.
  The deadline signal can also arrive late under CPU contention (R2-K-16, up to
  182 ms of CPU time into a 50 ms budget in the probe, four cores, six busy
  loops); see `cpp/CONTAINMENT.md`.
- The audit ring's seqlock is single-writer (R2-K-10); the host ring is written
  from many threads. Not changed here.
- aarch64: the wrapper includes `<x86intrin.h>` unconditionally (R2-E-10);
  only x86_64 is built and tested.

## 8. Supervised execution in a clean worker (RACE-02, decision A)

Why: the supervised child used to be a fork of the caller. Probes on the
unchanged code (`race02/ffi/probes`): a payload returned the caller's memory
(`P12`, `Completed` with `PARENT-SECRET-KEY-0123456789`), and wrote its own
well-formed result frame then `exit_group(0)` (`P2`, `Completed` with
`FORGED-OK`). A frame checksum is not a MAC and no key held by an untrusted
worker could be one.

What is now done (each statement names its test):

- implemented, tested: `stack_supervised_run_governed` forks and, in the
  child before exec, sets its process group and `PR_SET_PDEATHSIG`, resets
  signals, closes every descriptor except 0 to 2 (`/dev/null`) and the result
  pipe (placed on fd 3), applies rlimits, then `execveat`s an image
  descriptor opened and checked before the fork from the ABSOLUTE path given
  by the caller, with an EMPTY environment. The helper program
  (`cpp/worker/stack_worker.cpp`) installs the strict seccomp filter with
  `NO_NEW_PRIVS` as its first action, before it reads argv, then runs one of
  the built-in kinds 0 to 6. Tests: `cpp/tests/worker_exec_tests.cpp` (ctest
  `STACKWorkerExec`): "the caller's memory is not in the worker" (the worker
  reading the address of a caller global or heap secret faults with SIGSEGV and
  returns nothing; the control case shows the fork path does expose it),
  "the environment is empty", "only descriptors 0, 1, 2 and the result pipe are
  inherited" (listed from inside the worker before its filter: `0,1,2,3,`),
  "network, exec, fork, ptrace, open and the x32 ABI are denied inside the
  helper", "the worker dies when its supervisor is killed", "the worker image
  is checked before anything is forked".
- implemented, tested: the worker path comes from the caller's configuration
  only. It must be absolute, a regular file with an exec bit, owned by root or
  the effective user, and none of setuid, setgid, group-writable or
  world-writable (checked on the opened file, not the path). It is opened with
  `openat2(RESOLVE_NO_SYMLINKS)`, so a symlink in ANY component is refused
  (`ELOOP`); on a kernel without `openat2` (or a filter that answers `EPERM` for
  it) the open falls back to `O_NOFOLLOW`, which refuses only a symlink as the
  final component. That fallback is implemented, not tested. Anything else is
  `-14` and nothing is spawned. Tests: `cpp/tests/worker_image_tests.cpp` (ctest
  `STACKWorkerImage`) "a symlink is refused, as the final component and as a
  directory component", "group-writable, world-writable, setuid and setgid
  images are refused"; `ffi_supervised_tests.cpp` "a symlink, a setuid, a setgid
  and a group-writable image are refused".
- implemented, tested: NO_NEW_PRIVS before exec (R2-K-21). The supervisor's
  child sets `PR_SET_NO_NEW_PRIVS` before `execveat`, so even an image run
  without a pinned digest cannot gain privilege through exec. Before this the
  flag was set only inside the worker, after exec. Test: "the worker is exec'd
  with NO_NEW_PRIVS already set" (a test-only image that installs no filter and
  reports the flag).
- implemented, tested: the worker image is pinned by SHA-256 (R2-K-21) and the
  governed path REQUIRES the pin (`-16` when unset). The supervisor reads the
  image through the descriptor it opened, hashes what it read, and executes a
  SEALED in-memory copy (`memfd`, sealed against write, grow and shrink) of
  exactly those bytes. A swap of the file after the check, in place or by
  rename, therefore changes nothing: the verified bytes run. A program that is
  not the pinned one never runs (`/usr/bin/touch`, an altered copy). Tests:
  "a pinned image swapped after the check still runs the verified bytes" (the
  file at the path is overwritten in place, and separately renamed over,
  between the check and the fork, through the `STACK_SUPERVISED_TESTING` seam),
  "a non-worker binary (touch) is not run when the worker's digest is pinned",
  "the worker image digest is required, and an image that is not the pinned one
  is refused", Rust `test_governed_supervised_requires_the_worker_digest_and_refuses_another_program`.
  SHA-256 is checked against the standard vectors and `sha256sum`.
  The digest is checked after governance, not before: hashing costs
  milliseconds, so a request refused for capability or rate limit does not make
  the host pay it. A kernel that cannot `memfd_create`, or one that forbids
  executing memfds (`vm.memfd_noexec=2`), fails closed (the run does not start).
  An image larger than 64 MiB is refused when pinned.
- not pinned, and labelled so: `RunWorker` called WITHOUT a digest (the C++
  API allows it; the FFI does not) executes the opened descriptor itself. A
  rename over the path afterwards changes nothing (the opened inode runs; test
  "the same swap with no digest pinned"), but a write into the same inode
  between the open and the exec would be executed. Such a caller has not pinned
  the worker and is outside the guarantee above. A non-worker program run that
  way has no seccomp filter (only the worker installs it).
  `stack-admission` fails closed when it is unset or unusable
  (`tests/worker_governance.rs`).
- implemented, tested: result semantics. `Completed` means the worker exited 0
  before the deadline AND sent a well-formed frame. The bytes are
  SELF-REPORTED by an untrusted worker and every report says so
  (`result_self_reported`, 1 on `Completed`, 0 otherwise). Nothing may be
  inferred from them beyond that. A forged frame then `exit_group(0)` is
  `Completed`, flagged, and holds no caller memory ("a forged frame then
  exit_group(0) is Completed but flagged self-reported"). A forged frame then a
  spin is `TimedOut`; a frame arriving after the deadline is ignored; a
  malformed, truncated, oversized or doubled frame, a frameless exit 0, and a
  self SIGKILL are never `Completed`. On any outcome other than `Completed` the
  bytes the frame parser had written into the caller's buffer are zeroed.
- implemented, tested: bounded reap (R2-K-12). After SIGKILL the supervisor
  waits at most `reap_timeout_ns` (default 2 s, at most 60 s; 0 in the C call
  means the default), re-sending SIGKILL every 100 ms. If the worker is not
  reaped it reports `TerminationUnconfirmed`, never a success, keeps the pid and
  pidfd in a table of 64, and every later run first re-kills and reaps them and
  refuses to spawn when the table is full (`SupervisorError`, errno `EBUSY`).
  R2-K-23: the slot is RESERVED before the fork, so a worker is never spawned
  that could not be tracked, and the check and the tracking can no longer
  race (four runs racing for one free slot: one spawns, three are refused
  `EBUSY` with nothing forked; before, all four forked and three were
  untracked). A reservation is held for the whole run and given back when the
  run ends, so at most 64 runs (in progress plus unconfirmed) exist at once; a
  65th concurrent run is refused `EBUSY`. Behaviour change: that is a cap on
  concurrent supervised runs per process that did not exist before.
  A worker is signaled and reaped only through its pidfd (`pidfd_send_signal`,
  `waitid(P_PIDFD)`): a worker reaped elsewhere (a SIGCHLD handler, a
  `waitpid(-1)`) answers ESRCH/ECHILD and is forgotten, and its pid number, which
  may by then belong to someone else, is never signaled or waited on. The
  process group is signaled only while the worker is checked alive and
  unreaped. On a kernel without pidfd (older than 5.3) the old by-number
  behaviour remains for a run in progress, and a tracked unconfirmed worker is
  reaped by number but not re-signaled; that path is tested only by the
  existing fallback test, not for reuse. Tests (real pid reuse, produced by
  setting `ns_last_pid`, which needs root): "a worker reaped elsewhere cannot
  make the supervisor kill or reap whoever now holds its pid", "a tracked
  unconfirmed worker reaped elsewhere is forgotten, not signaled by number", "the
  tracking slot is reserved before the fork", "a run that completes gives its
  reserved slot back" (`worker_reap_tests.cpp`, ctest `STACKWorkerReap`).
  The test seam that simulates an ineffective kill exists only when
  `-DSTACK_SUPERVISED_TESTING` is defined (CMake targets `stack_worker_reap_tests`
  and `ffi_supervised_tests`); it is in no shipped build. Tests: `STACKWorkerReap`
  and "an ineffective kill is TerminationUnconfirmed and audited".
- implemented, tested: governance before spawn (R2-K-13). Codes of
  `stack_supervised_run_governed`; nothing is spawned and nothing consumed
  unless 0:

| Code | Meaning |
|---|---|
| 0 | Governance passed. `report->outcome` says how the run ended (any `Outcome`). Tokens are spent when `child_pid != 0`, refunded when nothing was spawned. |
| -1 | Host not initialized. |
| -2 | Unknown payload kind (above 6). |
| -3 | A null pointer, or `out` null with a non-zero capacity. |
| -4 | Capability validation failed, including a request naming no capability bit. |
| -5 | Rate limited (also above 100 tokens, 0 tokens (R2-K-20), domain 16 or more). |
| -9 | `wall_clock_deadline_ns` was 0. |
| -12 | Initialization failed (latched). |
| -13 | A capability change is pending; retry. |
| -14 | `worker_path` unusable (also: a symlink in the path, a setuid, setgid or group-writable image, or a call from a sealed thread, which cannot `open`). |
| -15 | Other limits invalid (deadline above one hour, output above the buffer or 1 MiB, reap bound above a minute). |
| -16 | `worker_sha256` is NULL. The digest of the worker image is required. Nothing spawned, nothing consumed. |
| -17 | The image does not hash to `worker_sha256`. Nothing spawned; tokens taken for the call are refunded and one `SupervisedFailed` event with 0 tokens is written. |

  While a worker runs the call counts as in flight. A capability change that
  is waiting TERMINATES it (R2-K-24, below) instead of waiting for it.
  One audit event records the outcome in the host ring, timeouts included:
  `SupervisedCompleted`, `SupervisedTimedOut`, `SupervisedFailed` (also written
  with 0 tokens when nothing was spawned), `SupervisedTerminationUnconfirmed` or
  `SupervisedTerminated` (event 9, tokens spent).
  Tests: `cpp/tests/ffi_supervised_tests.cpp` (ctest `STACKFfiSupervised`) and the
  Rust tests `test_governed_supervised_*`.
- implemented, tested: SIGCHLD ignored is refused (`SigchldIgnored`, outcome 11)
  after governance and refunds the tokens ("a run that spawns nothing refunds").

Measured on the development host (four cores, otherwise idle): spin, CPU-bound
and blocked-syscall workers killed at 300.9 to 301.1 ms for a 300 ms deadline;
governed timeouts at 40 ms: worst 41.5 to 42.8 ms over 50 runs; at 150 ms: 151
ms; an ineffective kill reports `TerminationUnconfirmed` at 400.6 ms for a 100
ms deadline plus a 300 ms bound. These are observations, not guarantees.

Not done, and why:

- not done: no signature, only a digest. The digest comes from the operator's
  configuration; nothing here protects the configuration itself, and a digest
  taken from the file it is about to trust (`stack_supervised_image_sha256` on
  the live path) pins nothing.
- not done: compute debt is not charged on the supervised path (the host's
  tick-based debt is for the in-process path).
- not done: arguments are not delivered to the worker (`args` in the admission
  pipeline are digested and ignored; the kind is the whole request).
- not done: a worker that is a script is not supported (the image descriptor is
  close-on-exec, so an interpreter could not open it); workers are ELF programs.
- not defended (unchanged): a kernel bug in seccomp or an allowed syscall; the
  worker shares the caller's uid, filesystem view and network namespace, and only
  the filter keeps it from using them; no namespaces, cgroups or chroot.
- BLOCKED: nothing in decision A is unprovable here, with one exception: the
  uninterruptible-sleep case behind `TerminationUnconfirmed` cannot be produced
  without a kernel fault, so only the simulated ineffective kill is tested.
- aarch64: the helper and the filter compile for it by their `#if`s but only
  x86_64 was built and run; the x32 test exists for x86_64 only.
