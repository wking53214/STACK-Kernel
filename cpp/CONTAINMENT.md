# Execution containment in the C++ layer

This document says what the two execution paths under `cpp/include` do,
what the tests under `cpp/tests` prove about them, and what they do not do.
Nothing here is a claim beyond those tests.

## Two paths

| Path | Header | What stops a payload | Status |
|---|---|---|---|
| In-process, `GovernedMinotaurHost::ExecuteGovernedTransaction` | `stack_host_binding.hpp`, `posix_deadline_timer_hardened.hpp` | Nothing. A CPU-time timer sets a flag that is read after the payload returns. | Cooperative deadline only. Not isolation. |
| Supervised child, `stack::supervised::SupervisedExecutor::Run` (fork of the caller) | `stack_supervised_exec.hpp` | SIGKILL from the parent at a wall-clock deadline; a seccomp filter that kills the child on any unlisted syscall. | Isolation of the payload's syscalls and run time, within the limits in "What it does not do". **NOT for untrusted payloads**: the child is a copy of the caller (see "The clean worker path"). |
| Supervised worker program, `SupervisedExecutor::RunWorker` (fork + exec) | `stack_supervised_exec.hpp`, `cpp/worker/stack_worker.cpp` | The same kill and filter, from a separate program with none of the caller's memory. | Implemented and tested (decision A, RACE-02). The path for anything not fully trusted. |

A payload that must be stopped goes through the supervised executor, and a
payload that is not fully trusted goes through `RunWorker`. The
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
`STACKSupervisedExec`, 15 cases, 1116 assertions) unless noted. The first 12
cases ran 20 times in a row on the development host: 20 passes, 0 failures.

| Guarantee | Test |
|---|---|
| A spinning payload is killed at the wall-clock deadline and reported `TimedOut`, never `Completed`; elapsed time is within the deadline plus a stated slack. | "an infinite loop is killed at the deadline and is TimedOut" |
| A payload blocked in `read()` with no CPU time passing is killed the same way. | "a payload blocked in read() on an empty pipe is killed" |
| `signal(SIG_IGN)`, `sigaction` on SIGKILL and SIGXCPU, and a fully blocked mask do not evade the kill; `timer_settime` is unavailable. | "signal tricks cannot evade the deadline" |
| `fork`, `execve`, `socket`, `open` and `ptrace` end the child with SIGSYS, reported `SeccompViolation`. | "fork, execve, socket, open and ptrace are SeccompViolation" |
| SIGSEGV and `abort()` are `Crashed` with their signal; `_exit(0)` without a result is `ResultMissing`; `_exit(3)` is `ExitedNonZero` with the code. None is `Completed`. | "SIGSEGV, abort() and a frameless exit are never Completed" |
| A result the child announces beyond `max_output_bytes` is `ResultOversized`; the bytes are not delivered. | "an oversized result is rejected" |
| Allocation beyond `RLIMIT_AS` ends in `ResourceLimit` or `Crashed`, never `Completed`. | "allocating beyond RLIMIT_AS is ResourceLimit or Crashed" |
| With `SIGCHLD` ignored (`SIG_IGN` or `SA_NOCLDWAIT`) the executor refuses with `SigchldIgnored` before forking; it never reports a misleading outcome. | "a run is refused while SIGCHLD is ignored" |
| A default-constructed `Limits` bounds the address space at 4 GiB, so a runaway allocation is `Crashed` or `ResourceLimit`, never `Completed`. | "allocating beyond the default address-space limit is Crashed or ResourceLimit" |
| On the `waitpid` fallback (no pidfd) a child reaped at the deadline is not signaled by its freed pid; with a pidfd the child is signaled through it. Tested by interposing `kill`, `waitpid` and `syscall` in `cpp/tests/supervised_fallback_tests.cpp` (ctest `STACKSupervisedFallback`). | "no kill after reap" |
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
built-in payloads (the ungoverned fork-of-caller entry, `stack_supervised_run`, is
kept as a C symbol for ABI compatibility; its Rust wrapper is an `unsafe fn`
since R2-K-22, so safe Rust reaches only the governed worker entry; tested by
`crates/stack-ffi/tests/api_surface.rs`) and its Rust tests repeat the spin, block, crash, abort,
exit, forbidden-syscall, return-bytes and invalid-limits cases.

## The clean worker path (decision A, RACE-02)

`Run(callable)` is kept and works, but its child is a fork of the caller. Two
baseline probes on it: a payload that returns the caller's memory
(`Completed` with the caller's secret) and a payload that writes its own
well-formed frame then `exit_group(0)` (`Completed` with the forged bytes).
`RunWorker` closes the first and bounds the second. Labels: implemented and
tested unless stated; the tests are `cpp/tests/worker_exec_tests.cpp` (ctest
`STACKWorkerExec`, 19 cases) and `cpp/tests/worker_reap_tests.cpp` (`STACKWorkerReap`,
5 cases); the governed FFI path is `cpp/tests/ffi_supervised_tests.cpp`
(`STACKFfiSupervised`, 13 cases).

- The worker is a separate program, `stack_worker`, exec'd from an image
  descriptor opened before the fork from an absolute path given by kernel
  configuration, never from the payload or the environment. Its environment is
  empty and it holds only fds 0 to 2 (`/dev/null`) and the result pipe on fd 3.
  It installs the strict seccomp filter itself, with `NO_NEW_PRIVS`, before it
  reads argv. The supervisor still enforces the deadline, the rlimits and the
  exit status from outside and does not trust the filter to have been installed.
- `Completed` means: exited 0 within the deadline AND sent a well-formed frame.
  The frame bytes are SELF-REPORTED by an untrusted worker; the report carries
  `result_self_reported = true` and nothing more may be inferred. A forged frame
  cannot make a timeout, crash, seccomp kill, non-zero exit or missing frame
  `Completed`, and cannot expose the caller's memory (it is not mapped in the
  worker). What it can do is say whatever it likes in a run that really did exit
  0 in time; that is what "self-reported" means. The receipt layer records it so.
- The worker image is trusted before it runs (R2-K-21; implemented and tested in
  `cpp/tests/worker_image_tests.cpp`, ctest `STACKWorkerImage`, and through the FFI
  in `ffi_supervised_tests.cpp`). A symlink in the path is refused (`openat2` with
  `RESOLVE_NO_SYMLINKS`; where that call is missing only the final component is
  refused, via `O_NOFOLLOW`, and that fallback is not tested). Setuid, setgid,
  group-writable and world-writable images are refused, as are owners other than
  root or the effective user. The child sets `PR_SET_NO_NEW_PRIVS` before the
  exec (it used to be set only inside the worker). When the configuration pins
  a SHA-256 (`WorkerSpec::expected_sha256`; REQUIRED by the FFI) the supervisor
  hashes the bytes it reads through the opened descriptor and executes a sealed
  memfd copy of exactly those bytes, so a swap of the file after the check
  (in place or by rename) changes nothing and a program that is not the pinned
  one never runs. Without a pin the opened descriptor itself is executed: a write
  into the same inode between open and exec would run, and a non-worker program
  would run with no seccomp filter (the worker installs its own). That mode is
  for callers who accept it; it is not what the FFI offers.
- The wait after SIGKILL is bounded (`reap_timeout_ns`, default 2 s). A worker
  that is not reaped in time is `TerminationUnconfirmed`: never a success, still
  tracked (`UnconfirmedCount`, `ReapUnconfirmed`).
- Through the FFI the run is governed first: capability mask and rate limit are
  checked by the initialized host before anything is spawned, and one audit event
  records the outcome, timeouts included (`crates/stack-ffi/ABI.md`, section 8).
- Found while testing it, R2-K-19, fixed: the fork-path child never closed the
  descriptors above the highest one it kept (a signed comparison with -1 in
  `CloseRange`). The seccomp filter already stopped the payload from using one.
- Not done: no compute-debt charge; no argument delivery; ELF workers only. Still true: same uid, filesystem view and
  network namespace as the caller.

## What the executor does not do

- **No namespace, cgroup, user or filesystem isolation.** The child has the
  same uid, mount and network namespaces and view of the filesystem as the
  caller. On the fork path it is also a copy of the parent's memory at the
  moment of the fork, and a payload can read whatever the parent had in
  memory; the worker path (`RunWorker`) does not have that problem. The seccomp
  filter is what keeps the payload from using the rest.
- **fork in a multithreaded parent.** Only the forking thread is copied.
  Any lock another thread held at that instant stays held in the child.
  glibc protects its own allocator; a payload that touches another lock can
  deadlock. The deadline is the backstop: the child is killed and reported
  `TimedOut`, never `Completed`.
- **Wall clock, not CPU.** The deadline is wall-clock time measured in the
  parent on `CLOCK_MONOTONIC`. `RLIMIT_CPU` is also set (derived from the
  deadline unless given). A payload that leaves SIGXCPU alone ends in
  SIGXCPU and is reported `ResourceLimit`. A payload that ignores or
  catches SIGXCPU is not stopped by it: the hard limit one second later
  sends SIGKILL, and the run is reported `Crashed` with signal 9, not
  `ResourceLimit` (test "a payload that ignores SIGXCPU is Crashed with
  signal 9"). The kill at the deadline is what is tested for timing.
- **Resource limits are best effort.** `RLIMIT_AS` (4 GiB by default; 0 is
  an explicit opt-out that `stack-admission` refuses) makes allocation fail
  inside the child; what happens next is the payload's business (usually
  `abort`, so `Crashed`). `RLIMIT_NPROC` is not enforced for a privileged
  uid; the filter's refusal of `clone` is what prevents spawning.
  `RLIMIT_FSIZE` does not apply to pipes.
- **The result is the payload's claim.** The frame checksum (FNV-1a 64)
  detects truncation and interleaving on the pipe. It is not a MAC and the
  payload itself can write to the result descriptor; reports say so
  (`result_self_reported`).
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
  the payload already finished and the result is success; and under CPU
  contention its signal can arrive well after the budget (R2-K-16, measured:
  up to 182 ms of CPU time into a 50 ms budget with six busy loops on four
  cores).

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

## The FFI host (`crates/stack-ffi`)

The exported C symbols, their return codes, the initialization state machine,
the accounting rules, the revocation semantics, what each test proves and the
ThreadSanitizer status are in `crates/stack-ffi/ABI.md`, with every statement
labelled tested, implemented, experimental or planned. New exported symbols
(steps 1 and 2): `stack_host_payload_count`, `stack_host_audit_read_slot`,
`stack_host_initialize`, `stack_host_seal_current_thread`; new return codes:
`stack_host_set_capabilities` -3, `stack_execute_governed_transaction` -11,
-12, -13. In short, for the
in-process path that the FFI exposes:

- tested: the host can serve (it rejected every transaction until the
  governor policy was fixed); initialization happens once, a failure is latched
  and reported by every entry point, and a transaction never seals its caller;
  a transaction that ran keeps its tokens and is charged its ticks, one
  rejected before it ran costs nothing; a revocation applies under sustained
  load within a bound and no transaction that begins after it runs.
- tested (R2-K-20): a governed request consumes at least one token. A request
  for 0 tokens is refused as rate limited on the transaction path and on the
  governed supervised path, before anything runs or spawns, and is audited. It
  used to pass the governor's floor check for free and was accepted without
  limit.
- not isolation, still: the deadline stays cooperative (section above).
- the direct C++ call `GovernedMinotaurHost::ExecuteGovernedTransaction` still
  seals an unsealed calling thread, as before; only the FFI entry point stopped
  doing that (decision B).

## Test-level issues found, and how they were fixed

Both were scheduling-dependent tests whose host behaviour was correct. Neither
was weakened; each now makes the condition it needs hold instead of hoping
for it, the way PR #44 did for layer4.

`tests_all_components.cpp`, case "Capability Mutation Race Fix", Test 2
("Snapshot consistency during validation"): the changer asked for a
capability change after the payload started and expected a refusal because the
transaction was in flight, but nothing kept the transaction in flight. On an
unchanged tree it failed 14 of 100 runs. The payload now blocks on a condition
variable until the changer has made its attempt (bounded at 5 s), so the
attempt is made while the transaction is provably in flight. The assertions are
unchanged; the transaction's deadline budgets were widened to those of the
neighbouring latch test because a payload that waits would exceed the old
50 microseconds of CPU. After: 0 of 100 failed. With the in-flight check in
`SetActiveCapabilities` removed, the case fails.

`layer2_redteam.cpp`, Test 3 "Repeated arm/disarm cycles" (and Test 1, same
shape): a 50 ms CPU-time timer against a 60 ms burn of wall-clock time. When
the thread is descheduled the timer correctly does not fire. On an unchanged
tree Test 3 failed 9 of 100 runs idle, and under six competing busy loops on
four cores 48 of 50 runs failed. The tests now burn the thread's own CPU time
(`CLOCK_THREAD_CPUTIME_ID`, the clock the timer measures) for at least the
same margin over the budget, then keep burning until the timer's signal is
seen or 2000 ms of CPU time (forty times the budget) have passed. After: 0 of
100 failed idle, 0 of 50 under the busy loops. With the arm budget raised to
5 s the test fails.

What the second fix cost, stated plainly: the tests no longer require the
signal to have arrived by 60 ms of CPU time. They require that it arrives
within 2000 ms. The reason is a measurement, not a convenience: with six busy
loops on four cores the signal was first seen between 50 and 182 ms of CPU
time into a 50 ms budget (idle: 50 to 54 ms). R2-K-16: the cooperative
deadline is therefore a lower bound on how long a payload may run, not a tight
one. The cause inside the kernel's CPU-timer delivery was not investigated.
The supervised executor's wall-clock kill is the bounded path.
