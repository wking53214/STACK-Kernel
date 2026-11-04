# Execution containment in the C++ layer

This document says what the two execution paths under `cpp/include` do,
what the tests under `cpp/tests` prove about them, and what they do not do.
Nothing here is a claim beyond those tests.

## Two paths

| Path | Header | What stops a payload | Status |
|---|---|---|---|
| In-process, `GovernedMinotaurHost::ExecuteGovernedTransaction` | `stack_host_binding.hpp`, `posix_deadline_timer_hardened.hpp` | Nothing. A CPU-time timer sets a flag that is read after the payload returns. | Cooperative deadline only. Not isolation. |
| Supervised child, `stack::supervised::SupervisedExecutor::Run` | `stack_supervised_exec.hpp` | SIGKILL from the parent at a wall-clock deadline; a seccomp filter that kills the child on any unlisted syscall. | Isolation of the payload's syscalls and run time, within the limits in "What it does not do". |

A payload that must be stopped goes through the supervised executor. The
in-process path remains for callers that want the governor (tokens, debt,
capability mask) around a payload they already trust to return.

## Threat model for the supervised executor

The payload is arbitrary native code running in a copy of the host process
(a fork). It is assumed to try any of the following:

- never return (spin), or block in a syscall so no CPU time passes;
- change its signal dispositions or mask, or disarm timers;
- spawn processes, exec programs, open files, open sockets, trace processes;
- allocate without bound, write without bound, hold descriptors;
- crash, abort, or exit without producing a result;
- claim a result it did not produce, or an oversized one.

Outside the model (not defended): a kernel bug in seccomp or in an allowed
syscall; a payload that reads memory the parent left in the forked image;
side channels; a payload that is allowed to run legitimately for the full
deadline and burns that CPU time.

## What the executor guarantees, and the test that proves each

All tests are in `cpp/tests/supervised_exec_tests.cpp` (ctest
`STACKSupervisedExec`, 12 cases, 1094 assertions) unless noted. Run 20 times
in a row on the development host: 20 passes, 0 failures.

| Guarantee | Test |
|---|---|
| A spinning payload is killed at the wall-clock deadline and reported `TimedOut`, never `Completed`; elapsed time is within the deadline plus a stated slack. | "an infinite loop is killed at the deadline and is TimedOut" |
| A payload blocked in `read()` with no CPU time passing is killed the same way. | "a payload blocked in read() on an empty pipe is killed" |
| `signal(SIG_IGN)`, `sigaction` on SIGKILL and SIGXCPU, and a fully blocked mask do not evade the kill; `timer_settime` is unavailable. | "signal tricks cannot evade the deadline" |
| `fork`, `execve`, `socket`, `open` and `ptrace` end the child with SIGSYS, reported `SeccompViolation`. | "fork, execve, socket, open and ptrace are SeccompViolation" |
| SIGSEGV and `abort()` are `Crashed` with their signal; `_exit(0)` without a result is `ResultMissing`; `_exit(3)` is `ExitedNonZero` with the code. None is `Completed`. | "SIGSEGV, abort() and a frameless exit are never Completed" |
| A result the child announces beyond `max_output_bytes` is `ResultOversized`; the bytes are not delivered. | "an oversized result is rejected" |
| Allocation beyond `RLIMIT_AS` ends in `ResourceLimit` or `Crashed`, never `Completed`. | "allocating beyond RLIMIT_AS is ResourceLimit or Crashed" |
| A zero deadline, a deadline over one hour, an output cap over 1 MiB or over the caller's buffer, and a descriptor below 3 are `InvalidLimits` before anything is forked. | "zero or absurd limits are rejected before forking" |
| A completing payload's bytes arrive exactly, with `Completed`. | "a payload that returns bytes is Completed with the exact bytes" |
| 300 sequential runs leave no zombie (`waitpid(-1)` gives `ECHILD`) and no descriptor (`/proc/self/fd` count unchanged). | "300 sequential runs leave no zombies and no descriptors" |
| Concurrent runs from four threads each classify correctly and leak nothing. | "concurrent runs from several threads each classify correctly" |
| A 1 ms payload under a 5 s deadline returns in well under a second. | "a fast payload with a 5 s deadline returns promptly" |

Classification rule, as implemented: `Completed` requires all of (a) the
deadline had not passed when the exit was observed, (b) exit status 0,
(c) a complete frame with a matching checksum and nothing after it. A
deadline expiry is `TimedOut` even if the child exited in the same instant.
Ambiguity is never reported as success.

The FFI (`crates/stack-ffi`) exposes the same executor over a fixed set of
built-in payloads and its Rust tests repeat the spin, block, crash, abort,
exit, forbidden-syscall, return-bytes and invalid-limits cases.

## What the executor does not do

- **No namespace, cgroup, user or filesystem isolation.** The child is a
  fork: same uid, same mount and network namespaces, same view of the
  filesystem, and a copy of the parent's memory at the moment of the fork.
  The seccomp filter is what keeps the payload from using any of that; a
  payload can still read whatever the parent had in memory.
- **fork in a multithreaded parent.** Only the forking thread is copied.
  Any lock another thread held at that instant stays held in the child.
  glibc protects its own allocator; a payload that touches another lock can
  deadlock. The deadline is the backstop: the child is killed and reported
  `TimedOut`, never `Completed`.
- **Wall clock, not CPU.** The deadline is wall-clock time measured in the
  parent on `CLOCK_MONOTONIC`. `RLIMIT_CPU` is also set (derived from the
  deadline unless given) and ends in SIGXCPU, reported `ResourceLimit`, but
  the kill at the deadline is what is tested.
- **Resource limits are best effort.** `RLIMIT_AS` makes allocation fail
  inside the child; what happens next is the payload's business (usually
  `abort`, so `Crashed`). `RLIMIT_NPROC` is not enforced for a privileged
  uid; the filter's refusal of `clone` is what prevents spawning.
  `RLIMIT_FSIZE` does not apply to pipes.
- **The result is the payload's claim.** The frame checksum (FNV-1a 64)
  detects truncation and interleaving on the pipe. It is not a MAC and the
  payload itself can write to the result descriptor.
- **Kernel dependence.** `SECCOMP_RET_KILL_PROCESS` needs Linux 4.14,
  `pidfd_open` 5.3 (older kernels fall back to `waitpid` polling at 5 ms),
  `close_range` 5.9 (older kernels close descriptors one by one). A kernel
  bug in any allowed syscall is outside the model.
- **Architectures.** x86_64 and aarch64 only, by the architecture check in
  the filter and the `#error` for anything else. Only x86_64 has been built
  and run; aarch64 has not been compiled in this work (no cross compiler
  was available).
- **Exceptions.** The payload runs on its own stack; an exception that
  escapes it ends in `std::terminate`, `abort` and `Crashed`. It never
  unwinds into frames the child inherited from the parent.

## The in-process path: cooperative only

`ExecuteGovernedTransaction` runs the payload on the caller's thread after
sealing that thread with a seccomp allowlist. Its "hard timeout" is a
`CLOCK_THREAD_CPUTIME_ID` timer whose handler sets a flag; the host reads
the flag after the payload returns and reports `PreemptionTriggered`.

What this gives: a payload that returns is told, afterwards, that it ran
past its CPU budget, and the thread's syscalls are restricted to the
allowlist.

What it cannot give, and why it is not isolation:

- a payload that never returns is never stopped;
- a payload blocked in a syscall consumes no CPU time and never trips the
  timer;
- the allowlist carries `timer_settime` and `rt_sigaction` on the deadline
  signal because the host needs them, so the payload can disarm the timer
  or ignore its signal (the Phase 0 probe did both);
- the timer has scheduler-tick granularity: a tiny budget can expire after
  the payload already finished and the result is success.

Fixed in this phase on that path: the deadline signal handler can return
(`rt_sigreturn` was missing from the allowlist and the first expiry killed
the whole process with SIGSEGV; test "Hard-timeout expiry on a sealed
thread does not kill the process"); a zero `hard_timeout_nanoseconds` is
refused with `InvalidHardTimeout` instead of running the payload with no
deadline; a timer that cannot be armed fails closed with `TimerArmFailed`
and the payload does not run.

Known, unchanged: a POSIX timer created on a thread is not inherited by a
forked child while the thread-local "initialized" flag is. A transaction
on such a thread fails closed with `TimerArmFailed`; run transactions on a
fresh thread in a forked process.

## Known test-level issues

`layer2_redteam.cpp`, Test 3 "Repeated arm/disarm cycles": arms a 50 ms
CPU-time budget and burns for 60 ms of wall-clock time, then requires the
timer to have fired. Whenever the thread is descheduled for more than
10 ms during the burn, less than 50 ms of CPU time passes and the timer
correctly does not fire; the test counts that as "poison". On an
unchanged tree it failed 9 of 40 runs (2 of 40 here). The timer is
behaving as specified; the test assumes CPU time equals wall time. Not
edited (no step changes the behaviour it asserts); reported.

`tests_all_components.cpp`, case "Capability Mutation Race Fix", Test 2
("Snapshot consistency during validation"): the changer thread waits for
the payload to start and then asks for a capability change, expecting a
refusal because the transaction is in flight. The payload is a single
store, so the transaction often returns before the changer runs and the
change is applied; the assertion `capabilities_changed` then fails. On an
unchanged tree it failed 11 of 40 runs; an instrumented replica shows
that in 162 of 171 failing iterations the transaction had already
returned when the change was requested. The host behaves correctly: the
latch-based case "Capability change refused while a payload runs" tests
the same property deterministically and passes every run. The flaky case
is not edited here (no step changes the behaviour it asserts); it is
reported for a separate fix.
