#pragma once

/**
 * STACK KERNEL: Supervised execution in a child process.
 *
 * WHY THIS EXISTS
 *
 * The in-process path (GovernedMinotaurHost::ExecuteGovernedTransaction)
 * runs the payload on the caller's thread under a CPU-time timer whose
 * handler only sets a flag. It cannot stop a payload that never returns,
 * never notices a payload blocked in a syscall (no CPU time passes), and
 * its allowlist lets the payload disarm the timer. That path is a
 * cooperative deadline, not isolation (D-02).
 *
 * TWO PATHS, AND WHICH ONE TO USE
 *
 *   RunWorker(limits, WorkerSpec, ...)   fork + exec of a separate worker
 *       program (cpp/worker/stack_worker.cpp). The child has none of the
 *       caller's memory, an empty environment, and only fds 0-2 (/dev/null)
 *       and the result pipe. USE THIS for anything that is not fully trusted.
 *   Run(limits, callable, ...) / RunThunk   the payload runs in a fork of the
 *       caller. It can read and return the caller's memory and can write a
 *       result frame of its own. NOT FOR UNTRUSTED PAYLOADS (R2-K-08); it is
 *       kept for in-tree, trusted callables and for the existing tests.
 *
 * SupervisedExecutor runs the payload in a forked child process and
 * supervises it from the parent with a wall-clock deadline that ends in
 * SIGKILL. A payload cannot block, catch or ignore SIGKILL, so the
 * deadline holds for a spinning payload, a blocked payload, a payload that
 * changes its signal dispositions or mask, and a payload that deadlocks.
 *
 * WHAT THE CHILD IS GIVEN
 *
 *   - its own process group (setpgid), so the kill reaches anything the
 *     payload managed to spawn (it should not be able to: see the filter);
 *   - PR_SET_PDEATHSIG = SIGKILL, so it dies if the supervising thread dies;
 *   - default signal dispositions and an empty signal mask, so handlers
 *     inherited from the parent (a test framework's, for example) cannot
 *     run inside the sandbox;
 *   - stdin, stdout and stderr on /dev/null, the result pipe, and at most
 *     one caller-chosen read-only descriptor (Limits::inherit_fd); every
 *     other descriptor is closed;
 *   - rlimits: CORE 0, CPU (derived from the deadline unless given), AS
 *     (if given), FSIZE, NPROC 0, NOFILE just above the highest kept fd;
 *   - PR_SET_NO_NEW_PRIVS and a strict seccomp filter: architecture check,
 *     then an allowlist of what a computing payload needs (memory,
 *     clocks, futex, signal bookkeeping so abort() works, read on fd 0 and
 *     the inherited fd, write on fds 1, 2 and the result pipe, exit).
 *     Everything else is SECCOMP_RET_KILL_PROCESS, which ends the child
 *     with SIGSYS and is classified as SeccompViolation by the parent.
 *
 * WHAT THE PARENT GUARANTEES
 *
 *   - The deadline is measured on CLOCK_MONOTONIC from before the fork.
 *     When it passes, the child's process group and the child are sent
 *     SIGKILL and the result is TimedOut, even if the child exited in the
 *     same instant with a complete result.
 *   - Completed is reported only when all of the following hold: the
 *     deadline had not passed when the exit was observed, the child
 *     exited with status 0, and a complete, well-formed result frame with
 *     a matching checksum arrived with nothing after it. Any other
 *     combination is one of the failure outcomes; ambiguity never becomes
 *     success.
 *   - The result bytes of a Completed run are SELF-REPORTED: the worker is
 *     untrusted and wrote them itself, so ExecutionReport::result_self_reported
 *     is true and nothing beyond "a well-formed frame came from a process that
 *     exited 0 in time" may be inferred from them. A forged frame cannot turn
 *     a timeout, a crash, a seccomp kill, a non-zero exit or a missing frame
 *     into Completed, and (worker path) cannot expose the caller's memory. On
 *     every outcome other than Completed the bytes the frame parser had
 *     written into the caller's buffer are zeroed.
 *   - The wait for the child after SIGKILL is bounded (Limits::reap_timeout_ns,
 *     2 s by default). If the child is not reaped in time the run is
 *     TerminationUnconfirmed: not a success, the pid and pidfd stay tracked
 *     (UnconfirmedCount, ReapUnconfirmed) and the child may still be running.
 *   - The worker image is trusted before it runs (R2-K-21): a symlink in the path is
 *     refused (openat2 RESOLVE_NO_SYMLINKS; O_NOFOLLOW only where openat2 is missing), so are
 *     setuid, setgid, group-writable and world-writable images and owners other than root or
 *     the effective user, the child sets PR_SET_NO_NEW_PRIVS before the exec, and
 *     WorkerSpec::expected_sha256 pins the image: the bytes read through the opened
 *     descriptor are hashed and a sealed memfd copy of those bytes is what executes.
 *   - With a pidfd the child is signaled and reaped only through it (pidfd_send_signal,
 *     waitid(P_PIDFD)), never by a pid number another process may have reused; the
 *     tracking slot for an unconfirmed child is reserved before the fork (R2-K-23).
 *   - Otherwise the child is reaped and both parent-side descriptors are
 *     closed, on every path. There is no heap allocation in the parent; the
 *     result goes into the caller's buffer.
 *
 * WHAT IT DOES NOT DO (read cpp/CONTAINMENT.md)
 *
 *   - No namespaces, no cgroups, no user switch, no chroot: the child
 *     shares the parent's uid, its filesystem view and its network
 *     namespace; on the fork-of-caller path it also holds a copy of the
 *     parent's address space (the worker path does not). The seccomp
 *     filter is what keeps the payload from reaching them; a kernel
 *     bug in seccomp or in an allowed syscall is outside this model.
 *   - fork() in a multithreaded parent copies only the calling thread.
 *     Locks held by other threads at that instant stay held in the child
 *     forever. glibc protects malloc, but a payload that touches another
 *     lock can deadlock. The deadline is the backstop: a deadlocked
 *     child is killed and reported TimedOut, never Completed.
 *   - Resource limits are best effort: RLIMIT_AS (4 GiB unless set; 0 is an
 *     explicit opt-out) makes allocation fail inside the child (which
 *     usually ends in abort, so Crashed) and RLIMIT_CPU ends in SIGXCPU
 *     (ResourceLimit) for a payload that leaves SIGXCPU alone; a payload
 *     that ignores or catches it is killed with SIGKILL one second later
 *     and is Crashed with signal 9. Neither is observed by the parent as a
 *     limit event in its own right.
 *   - SIGCHLD must not be ignored in the calling process (SIG_IGN or
 *     SA_NOCLDWAIT): the kernel would reap the child before waitpid and
 *     the run could not be classified. Run refuses up front with
 *     Outcome::SigchldIgnored and forks nothing.
 *   - The payload runs on its own stack (makecontext) whose bottom frame
 *     ends the unwind chain. An exception that escapes the payload cannot
 *     reach the frames the child inherited from the parent (a test
 *     framework's handlers, for instance) and so cannot run parent code
 *     inside the sandbox; it ends in std::terminate, abort and Crashed.
 *   - The result frame checksum (FNV-1a 64) detects truncation and
 *     interleaving on the pipe. It is not a MAC: the payload itself
 *     writes to the result descriptor, so the bytes are the payload's
 *     claim, not an attestation.
 *   - x86_64 and aarch64 only. Linux 5.3+ for pidfd_open (older kernels
 *     fall back to waitpid polling at 5 ms granularity), 5.9+ for
 *     close_range (older kernels close descriptors one by one).
 */

#include <atomic>
#include <cerrno>
#include <csignal>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <ctime>
#include <type_traits>
#include <utility>

#include <fcntl.h>
#include <poll.h>
#include <ucontext.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>
#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/seccomp.h>

namespace stack::supervised {

enum class Outcome : uint8_t {
    Completed = 0,        // exit 0, complete valid frame, deadline not passed
    TimedOut = 1,         // wall-clock deadline passed; child killed
    Crashed = 2,          // child ended by a signal other than SIGSYS/SIGXCPU/SIGXFSZ
    SeccompViolation = 3, // child ended by SIGSYS (filter kill)
    ExitedNonZero = 4,    // child exited with a non-zero status
    ResultMissing = 5,    // exit 0 but no complete, valid result frame
    ResultOversized = 6,  // frame announced more bytes than max_output_bytes
    ResourceLimit = 7,    // child ended by SIGXCPU or SIGXFSZ
    SpawnFailed = 8,      // pipe/fork failed, or the child could not set up its sandbox
    SupervisorError = 9,  // poll/waitpid failure in the parent
    InvalidLimits = 10,   // Limits rejected before anything was spawned
    SigchldIgnored = 11,  // SIGCHLD is ignored in this process; refused before anything was spawned
    // The child was sent SIGKILL and was NOT reaped within Limits::reap_timeout_ns. It may still be
    // running. Never a success; the pid stays tracked (UnconfirmedCount / ReapUnconfirmed).
    TerminationUnconfirmed = 12
};

/** Upper bound on a deadline: one hour. Larger values are InvalidLimits. */
inline constexpr uint64_t kMaxWallClockDeadlineNs = 3'600'000'000'000ULL;
/** Upper bound on a result: 1 MiB. Larger max_output_bytes is InvalidLimits. */
inline constexpr std::size_t kMaxOutputBytes = 1u << 20;
/**
 * Default RLIMIT_AS for the child: 4 GiB. The limit counts the whole address
 * space, including the mappings the child inherits from the parent through
 * fork, so it must sit above what the parent already maps. 4 GiB leaves a
 * payload room to compute and still ends a runaway allocation in a crash or
 * a ResourceLimit instead of the host's memory.
 */
inline constexpr uint64_t kDefaultAddressSpaceBytes = 4ULL << 30;
/** The descriptor a worker program finds its result pipe on. 0, 1 and 2 are /dev/null. */
inline constexpr int kWorkerResultFd = 3;
/** Default bound on the wait for a killed child to be reaped: 2 s. */
inline constexpr uint64_t kDefaultReapTimeoutNs = 2'000'000'000ULL;
/** Upper bound on Limits::reap_timeout_ns: one minute. */
inline constexpr uint64_t kMaxReapTimeoutNs = 60'000'000'000ULL;
/** How many killed-but-unreaped children are tracked; at this many, new runs are refused. */
inline constexpr std::size_t kMaxUnconfirmedChildren = 64;
/** Longest worker path accepted (bytes, without the terminator). */
inline constexpr std::size_t kMaxWorkerPathBytes = 4095;
/** Largest worker image the supervisor will hash and copy (pinned mode): 64 MiB. */
inline constexpr std::size_t kMaxWorkerImageBytes = 64u << 20;

struct Limits {
    /** Required, 1 .. kMaxWallClockDeadlineNs. */
    uint64_t wall_clock_deadline_ns = 0;
    /** RLIMIT_CPU soft limit in seconds; 0 derives ceil(deadline) + 1. */
    uint64_t cpu_seconds = 0;
    /**
     * RLIMIT_AS in bytes. Defaults to kDefaultAddressSpaceBytes. 0 leaves
     * the inherited limit and is an explicit opt-out: the admission layer
     * (stack-admission) refuses it.
     */
    uint64_t address_space_bytes = kDefaultAddressSpaceBytes;
    /** Largest result accepted, <= kMaxOutputBytes and <= the caller's buffer. */
    uint64_t max_output_bytes = 4096;
    /** RLIMIT_FSIZE in bytes; 0 forbids writing to regular files. Pipes are unaffected. */
    uint64_t file_size_bytes = 0;
    /** RLIMIT_NOFILE; 0 derives (highest kept descriptor + 1), which is also the floor. */
    uint32_t nofile = 0;
    /** One descriptor (>= 3) kept open in the child for the payload to read, or -1. */
    int inherit_fd = -1;
    /**
     * How long to wait, after SIGKILL, for the child to be reaped: 1 ns ..
     * kMaxReapTimeoutNs, default kDefaultReapTimeoutNs. When it is not reaped in
     * time the run is TerminationUnconfirmed, never a success.
     */
    uint64_t reap_timeout_ns = kDefaultReapTimeoutNs;
};

struct ExecutionReport {
    Outcome outcome = Outcome::SupervisorError;
    /** Wall-clock time from before the fork to after the reap. */
    uint64_t elapsed_ns = 0;
    /** Exit status when the child exited; the setup code (120..127) on SpawnFailed from the child. */
    int exit_code = -1;
    /** Terminating signal when the child was signaled, else 0. */
    int signal_number = 0;
    /** errno of the failing parent-side call on SpawnFailed / SupervisorError, else 0. */
    int error_number = 0;
    /** 0 when nothing was forked. */
    pid_t child_pid = 0;
    /** True when the deadline passed before the exit was observed. */
    bool deadline_fired = false;
    /** Bytes placed in the caller's buffer; meaningful only on Completed. */
    uint64_t result_length = 0;
    /**
     * True whenever result bytes were delivered (Completed). The bytes are the
     * WORKER'S OWN CLAIM: an untrusted process wrote them, and the supervisor
     * establishes nothing about them beyond "a well-formed frame arrived from a
     * process that then exited 0 before the deadline". Never evidence that the
     * work was done or done correctly.
     */
    bool result_self_reported = false;
};

/**
 * A worker program for SupervisedExecutor::RunWorker. Everything here is
 * chosen by kernel configuration, never by the payload or the environment.
 */
struct WorkerSpec {
    /** ABSOLUTE path of the worker executable. The supervisor opens it once, before the fork,
     *  and executes that open descriptor, so a later swap of the path changes nothing. */
    const char* executable = nullptr;
    /** argv[1] as a decimal number: which built-in kind the worker runs. */
    uint32_t kind = 0;
    /** Optional argv[2]; used by test workers only. Null for none. */
    const char* argument = nullptr;
    /**
     * Optional (R2-K-21): the expected SHA-256 of the worker image, 32 bytes. When set the
     * supervisor reads the image through the descriptor it opened, hashes what it read, refuses
     * (SpawnFailed, error_number EKEYREJECTED, nothing forked) on a mismatch, and executes a
     * sealed in-memory copy of exactly the bytes it hashed, so nothing that happens to the
     * file after the check changes what runs. When null the opened descriptor itself is
     * executed (not pinned: a write into the same file between the open and the exec would be
     * executed). The governed FFI path requires the digest.
     */
    const uint8_t* expected_sha256 = nullptr;
};

/** Payload entry used by the child: writes up to capacity bytes to out and returns the count. */
using PayloadThunk = std::size_t (*)(void* context, uint8_t* out, std::size_t capacity);

class SupervisedExecutor {
public:
    /**
     * Runs payload(out, capacity) in a supervised child. payload may return
     * std::size_t (bytes written) or void (no result bytes). The result is
     * copied into result[0..result_capacity) and its length reported.
     */
    template <typename Payload>
    [[nodiscard]] static ExecutionReport Run(const Limits& limits, Payload&& payload,
                                             uint8_t* result, std::size_t result_capacity) noexcept {
        using P = std::remove_reference_t<Payload>;
        PayloadThunk thunk = [](void* context, uint8_t* out, std::size_t capacity) -> std::size_t {
            P& fn = *static_cast<P*>(context);
            if constexpr (std::is_void_v<decltype(fn(out, capacity))>) {
                fn(out, capacity);
                return 0;
            } else {
                return static_cast<std::size_t>(fn(out, capacity));
            }
        };
        return RunThunk(limits, thunk, static_cast<void*>(&payload), result, result_capacity);
    }

    /** Type-erased form for C callers (the FFI). */
    [[nodiscard]] static ExecutionReport RunThunk(const Limits& limits, PayloadThunk payload, void* context,
                                                  uint8_t* result, std::size_t result_capacity) noexcept {
        ExecutionReport report{};
        if (!LimitsAreValid(limits, result, result_capacity)) {
            report.outcome = Outcome::InvalidLimits;
            return report;
        }
        if (SigchldIsIgnored()) {
            // The kernel reaps an ignored SIGCHLD child itself, so waitpid
            // would fail with ECHILD and the real end of the run (a timeout
            // included) would be reported as a supervisor error. Fail
            // closed before forking instead.
            report.outcome = Outcome::SigchldIgnored;
            return report;
        }
        const uint64_t t0 = MonotonicNs();
        const uint64_t deadline = t0 + limits.wall_clock_deadline_ns;
        // A tracking slot is reserved BEFORE anything is forked (R2-K-23): a worker is
        // never spawned that could not be tracked if its death went unconfirmed. A full
        // table is a refusal, not a silent drop.
        (void)ReapUnconfirmed();
        SlotGuard slot{ReserveSlot()};
        if (slot.index < 0) {
            report.outcome = Outcome::SupervisorError;
            report.error_number = EBUSY;
            return report;
        }

        int pipe_fds[2] = {-1, -1};
        if (::pipe2(pipe_fds, O_CLOEXEC) != 0) {
            report.outcome = Outcome::SpawnFailed;
            report.error_number = errno;
            report.elapsed_ns = MonotonicNs() - t0;
            return report;
        }
        FdGuard pipe_r{pipe_fds[0]};
        FdGuard pipe_w{pipe_fds[1]};
        // The child puts /dev/null on 0, 1 and 2; the pipe must not sit there.
        if (!pipe_r.RaiseAbove(2) || !pipe_w.RaiseAbove(2)) {
            report.outcome = Outcome::SpawnFailed;
            report.error_number = errno;
            report.elapsed_ns = MonotonicNs() - t0;
            return report;
        }

        const pid_t parent_pid = ::getpid();
        const pid_t pid = ::fork();
        if (pid < 0) {
            report.outcome = Outcome::SpawnFailed;
            report.error_number = errno;
            report.elapsed_ns = MonotonicNs() - t0;
            return report;
        }
        if (pid == 0) {
            ::close(pipe_r.fd);
            ChildMain(limits, payload, context, pipe_w.fd, parent_pid);  // never returns
        }

        // Parent.
        report.child_pid = pid;
        pipe_w.Close();
        Supervise(report, limits, pid, pipe_r, t0, deadline, result, result_capacity, slot);
        return report;
    }

    /**
     * Runs a worker PROGRAM (fork, then exec of a separate executable) under
     * the same supervision as RunThunk. Unlike RunThunk the child is not a
     * copy of the caller: after the exec it has none of the caller's memory,
     * its environment is empty, and it holds only descriptors 0 to 2
     * (/dev/null) and the result pipe on kWorkerResultFd. The worker installs
     * the strict seccomp filter itself as its first action
     * (InstallWorkerFilter); the supervisor does not trust that and still
     * enforces the deadline, the rlimits and the exit status from outside.
     *
     * Completed means: the worker exited 0 before the deadline AND sent a
     * well-formed frame. The frame bytes are the worker's own claim.
     */
    [[nodiscard]] static ExecutionReport RunWorker(const Limits& limits, const WorkerSpec& spec, uint8_t* result,
                                                   std::size_t result_capacity) noexcept {
        ExecutionReport report{};
        if (!LimitsAreValid(limits, result, result_capacity) || limits.inherit_fd != -1) {
            report.outcome = Outcome::InvalidLimits;
            return report;
        }
        if (SigchldIsIgnored()) {
            report.outcome = Outcome::SigchldIgnored;
            return report;
        }
        const uint64_t t0 = MonotonicNs();
        const uint64_t deadline = t0 + limits.wall_clock_deadline_ns;
        // Reserve the tracking slot before the fork (see RunThunk).
        (void)ReapUnconfirmed();
        SlotGuard slot{ReserveSlot()};
        if (slot.index < 0) {
            report.outcome = Outcome::SupervisorError;
            report.error_number = EBUSY;
            return report;
        }

        // The image is opened and checked before anything is forked, and the
        // child executes this descriptor, not the path.
        FdGuard image{-1};
        {
            const int err = OpenWorkerImage(spec.executable, spec.expected_sha256, image.fd);
            if (err != 0) {
                report.outcome = Outcome::SpawnFailed;
                report.error_number = err;
                report.elapsed_ns = MonotonicNs() - t0;
                return report;
            }
        }
#ifdef STACK_SUPERVISED_TESTING
        if (image_checked_hook_ != nullptr) image_checked_hook_(spec.executable);
#endif
        // argv and envp are built here, on the stack: the child allocates nothing.
        char kind_text[16];
        FormatDecimal(spec.kind, kind_text);
        char* argv[4] = {const_cast<char*>(spec.executable), kind_text, const_cast<char*>(spec.argument), nullptr};
        char* envp[1] = {nullptr};

        int pipe_fds[2] = {-1, -1};
        if (::pipe2(pipe_fds, O_CLOEXEC) != 0) {
            report.outcome = Outcome::SpawnFailed;
            report.error_number = errno;
            report.elapsed_ns = MonotonicNs() - t0;
            return report;
        }
        FdGuard pipe_r{pipe_fds[0]};
        FdGuard pipe_w{pipe_fds[1]};
        if (!pipe_r.RaiseAbove(2) || !pipe_w.RaiseAbove(2) || !image.RaiseAbove(2)) {
            report.outcome = Outcome::SpawnFailed;
            report.error_number = errno;
            report.elapsed_ns = MonotonicNs() - t0;
            return report;
        }

        const pid_t parent_pid = ::getpid();
        const pid_t pid = ::fork();
        if (pid < 0) {
            report.outcome = Outcome::SpawnFailed;
            report.error_number = errno;
            report.elapsed_ns = MonotonicNs() - t0;
            return report;
        }
        if (pid == 0) {
            ::close(pipe_r.fd);
            WorkerChildMain(limits, image.fd, argv, envp, pipe_w.fd, parent_pid);  // never returns
        }

        report.child_pid = pid;
        pipe_w.Close();
        image.Close();
        Supervise(report, limits, pid, pipe_r, t0, deadline, result, result_capacity, slot);
        return report;
    }

    /**
     * Checks a worker path the way RunWorker does before it forks (absolute, no symlink in
     * the path where openat2 is available, opens, regular, executable, not setuid, setgid,
     * group-writable or world-writable, owned by root or the effective user and, when
     * `expected_sha256` is given, hashing to it) and closes it again. Returns 0 or an errno
     * (EKEYREJECTED for a digest mismatch). For a caller that wants to refuse a request before
     * it spends anything on it.
     */
    [[nodiscard]] static int CheckWorkerImage(const char* path, const uint8_t* expected_sha256 = nullptr) noexcept {
        int fd = -1;
        const int err = OpenWorkerImage(path, expected_sha256, fd);
        if (err == 0) ::close(fd);
        return err;
    }

    /** SHA-256 of `n` bytes at `data` (n may be 0). No allocation. */
    static void Sha256(const uint8_t* data, std::size_t n, uint8_t (&out)[32]) noexcept {
        Sha256State st;
        st.Update(data, n);
        st.Final(out);
    }

    /**
     * SHA-256 of the file at `path`, read through one descriptor (no policy check: it hashes any
     * regular file). Returns 0 or an errno. For provisioning and for tests, to obtain the digest
     * a configuration pins; a production deployment takes the digest from its release record,
     * not from the file it is about to trust.
     */
    [[nodiscard]] static int Sha256OfFile(const char* path, uint8_t (&out)[32]) noexcept {
        const int fd = ::open(path, O_RDONLY | O_CLOEXEC);
        if (fd < 0) return errno;
        const int err = HashDescriptor(fd, out, -1);
        ::close(fd);
        return err;
    }

    /**
     * For a worker program: installs the filter the fork path installs (x32
     * and foreign architectures killed; read only on fd 0; write only on 1,
     * 2 and the result pipe; anonymous non-executable mmap; no open, socket,
     * clone, execve, ptrace), with NO_NEW_PRIVS. Call it first, before the
     * worker reads anything. Irreversible.
     */
    [[nodiscard]] static bool InstallWorkerFilter(int result_fd) noexcept {
        return InstallFilter(result_fd, -1, ::getpid());
    }

    /** For a worker program: writes one result frame (magic, length, bytes, checksum) to fd. */
    [[nodiscard]] static bool WriteResultFrame(int fd, const uint8_t* body, std::size_t len) noexcept {
        return WriteFrame(fd, body, len);
    }

    [[nodiscard]] static bool LimitsAreValid(const Limits& limits, const uint8_t* result,
                                             std::size_t result_capacity) noexcept {
        if (limits.wall_clock_deadline_ns == 0 || limits.wall_clock_deadline_ns > kMaxWallClockDeadlineNs) return false;
        if (limits.max_output_bytes > kMaxOutputBytes) return false;
        if (limits.max_output_bytes > result_capacity) return false;
        if (result == nullptr && limits.max_output_bytes > 0) return false;
        if (limits.inherit_fd < -1 || (limits.inherit_fd >= 0 && limits.inherit_fd < 3)) return false;
        if (limits.reap_timeout_ns == 0 || limits.reap_timeout_ns > kMaxReapTimeoutNs) return false;
        return true;
    }

private:
    struct FdGuard;
    struct FrameParser;
    struct SlotGuard;

    // The parent half of a run, shared by the fork-of-caller path and the
    // worker path: watch the child until it exits or the deadline passes,
    // kill it, reap it, and classify what was seen. pipe_r is the read end of
    // the result pipe (the write end is already closed here).
    static void Supervise(ExecutionReport& report, const Limits& limits, pid_t pid, FdGuard& pipe_r, uint64_t t0,
                          uint64_t deadline, uint8_t* result, std::size_t result_capacity, SlotGuard& slot) noexcept {
        (void)::setpgid(pid, pid);  // the child does the same; whichever runs first wins
        (void)::fcntl(pipe_r.fd, F_SETFL, O_NONBLOCK);
        FdGuard pidfd{PidfdOpen(pid)};

        FrameParser parser{result, result_capacity, static_cast<std::size_t>(limits.max_output_bytes)};
        int status = 0;
        bool exited = false;
        bool reaped = false;
        bool pipe_eof = false;
        bool poll_failed = false;
        int poll_errno = 0;

        while (!exited) {
            const uint64_t now = MonotonicNs();
            if (now >= deadline) {
                report.deadline_fired = true;
                break;
            }
            const uint64_t remaining_ns = deadline - now;
            int timeout_ms = static_cast<int>((remaining_ns + 999'999ULL) / 1'000'000ULL);
            if (pidfd.fd < 0 && timeout_ms > 5) timeout_ms = 5;  // waitpid polling fallback
            if (timeout_ms < 1) timeout_ms = 1;

            pollfd fds[2];
            nfds_t n = 0;
            if (!pipe_eof) {
                fds[n].fd = pipe_r.fd;
                fds[n].events = POLLIN;
                fds[n].revents = 0;
                ++n;
            }
            if (pidfd.fd >= 0) {
                fds[n].fd = pidfd.fd;
                fds[n].events = POLLIN;
                fds[n].revents = 0;
                ++n;
            }
            const int pr = ::poll(fds, n, timeout_ms);
            if (pr < 0) {
                if (errno == EINTR) continue;
                poll_failed = true;
                poll_errno = errno;
                break;
            }
            for (nfds_t i = 0; i < n; ++i) {
                if (fds[i].revents == 0) continue;
                if (fds[i].fd == pipe_r.fd) {
                    if (!DrainPipe(pipe_r.fd, parser, pipe_eof)) {
                        poll_failed = true;
                        poll_errno = errno;
                    }
                    if (parser.state == FrameParser::State::Oversized) {
                        // Nothing more is accepted; stop the child now.
                        KillChild(pid, pidfd.fd);
                    }
                } else if (pidfd.fd >= 0 && fds[i].fd == pidfd.fd) {
                    exited = true;
                }
            }
            if (poll_failed) break;
            if (!exited && pidfd.fd < 0) {
                const pid_t w = ::waitpid(pid, &status, WNOHANG);
                if (w == pid) {
                    exited = true;
                    reaped = true;
                } else if (w < 0 && errno != EINTR) {
                    poll_failed = true;
                    poll_errno = errno;
                    break;
                }
            }
            if (exited && MonotonicNs() >= deadline) {
                // Exit observed only after the deadline: strict, never success.
                report.deadline_fired = true;
            }
        }

        // Once the waitpid fallback has reaped the child its pid is free to be
        // reused, so nothing may be signaled by that number any more.
        bool killed = false;
        if ((report.deadline_fired || poll_failed) && !reaped) {
            KillChild(pid, pidfd.fd);
            killed = true;
        }
        // Always reap, but never wait without a bound (R2-K-12). With the waitpid
        // fallback the child may be reaped already.
        if (!reaped) {
            const int rc = ReapBounded(pid, pidfd.fd, limits.reap_timeout_ns, status, killed);
            if (rc == 0) {
                // SIGKILL did not take effect in time. The child may still be
                // running: say so, keep tracking it, report no success.
                KillChild(pid, pidfd.fd);
                TrackUnconfirmed(slot, pid, pidfd);
                report.outcome = Outcome::TerminationUnconfirmed;
                report.error_number = ETIMEDOUT;
                report.elapsed_ns = MonotonicNs() - t0;
                ScrubResult(result, parser);
                return;
            }
            if (rc < 0) {
                report.outcome = Outcome::SupervisorError;
                report.error_number = errno;
                report.elapsed_ns = MonotonicNs() - t0;
                ScrubResult(result, parser);
                return;
            }
        }
        // Whatever the child wrote before dying is in the pipe; take it, bounded.
        if (!pipe_eof) DrainPipeAfterExit(pipe_r.fd, parser, pipe_eof);

        report.elapsed_ns = MonotonicNs() - t0;
        Classify(report, status, parser, poll_failed, poll_errno);
        // Bytes the caller's buffer received from a run that did not complete are
        // not a result; do not leave them there to be mistaken for one.
        if (report.outcome != Outcome::Completed) ScrubResult(result, parser);
    }

    static void ScrubResult(uint8_t* result, const FrameParser& parser) noexcept {
        if (result != nullptr && parser.body_n > 0) std::memset(result, 0, parser.body_n);
    }

    // ------------------------------------------------------------------
    // Bounded reap and the children that could not be confirmed dead.
    // ------------------------------------------------------------------

    // waitid(P_PIDFD) is called by number so no glibc newer than the kernel's is needed.
    static constexpr long kPidfdIdType = 3;  // P_PIDFD

    // Reaps the child if it has ended, without blocking. With a pidfd the wait is on THAT
    // process and no other (R2-K-23): a pid number that was reaped elsewhere and reused can
    // never be reaped here. Returns 1 reaped (status set), 0 still running, -1 error with
    // errno set (ECHILD: it is gone, reaped by someone else; its status is unknown). Without a
    // pidfd (kernel older than 5.3) it falls back to waitpid on the number, which is only
    // correct while nothing else reaps children of this process.
    [[nodiscard]] static int TryReap(pid_t pid, int pidfd, int& status) noexcept {
#ifdef __NR_waitid
        if (pidfd >= 0) {
            siginfo_t info{};
            const long r = ::syscall(__NR_waitid, kPidfdIdType, pidfd, &info, WEXITED | WNOHANG, nullptr);
            if (r < 0) return errno == EINTR ? 0 : -1;
            if (info.si_pid == 0) return 0;
            const int code = info.si_status;
            if (info.si_code == CLD_EXITED) status = (code & 0xff) << 8;
            else if (info.si_code == CLD_KILLED) status = code & 0x7f;
            else if (info.si_code == CLD_DUMPED) status = (code & 0x7f) | 0x80;
            else return 0;
            return 1;
        }
#endif
        const pid_t w = ::waitpid(pid, &status, WNOHANG);
        if (w == pid) return 1;
        if (w < 0 && errno != EINTR) return -1;
        return 0;
    }

    // Waits for the child to be reaped, at most bound_ns, re-sending SIGKILL every
    // 100 ms while it waits (when `resend`). Returns 1 reaped (status set),
    // 0 not reaped in time, -1 the wait failed (errno set; ECHILD means it was reaped
    // elsewhere).
    [[nodiscard]] static int ReapBounded(pid_t pid, int pidfd, uint64_t bound_ns, int& status, bool resend) noexcept {
        const uint64_t end = MonotonicNs() + bound_ns;
        uint64_t next_kill = MonotonicNs() + 100'000'000ULL;
        for (;;) {
            const int w = TryReap(pid, pidfd, status);
            if (w != 0) return w;
            const uint64_t now = MonotonicNs();
            if (now >= end) return 0;
            if (resend && now >= next_kill) {
                KillChild(pid, pidfd);
                next_kill = now + 100'000'000ULL;
            }
            uint64_t ms = (end - now + 999'999ULL) / 1'000'000ULL;
            if (ms > 10) ms = 10;
            if (ms < 1) ms = 1;
            if (pidfd >= 0) {
                pollfd p{pidfd, POLLIN, 0};
                (void)::poll(&p, 1, static_cast<int>(ms));
            } else {
                (void)::poll(nullptr, 0, 1);
            }
        }
    }

    // Slot states in unconfirmed_pid_: 0 free, > 0 a tracked pid (a worker whose death was not
    // confirmed), kSlotBusy being edited, kSlotReserved held by a run in progress (R2-K-23).
    static constexpr pid_t kSlotBusy = -2;
    static constexpr pid_t kSlotReserved = -3;
    static inline std::atomic<pid_t> unconfirmed_pid_[kMaxUnconfirmedChildren]{};
    static inline int unconfirmed_fd_[kMaxUnconfirmedChildren]{};

    // Reserves a free slot for a run about to fork. Returns its index, or -1 when every slot is
    // taken (tracked or reserved): the run is refused, it does not spawn untracked.
    [[nodiscard]] static int ReserveSlot() noexcept {
        for (std::size_t i = 0; i < kMaxUnconfirmedChildren; ++i) {
            pid_t expected = 0;
            if (unconfirmed_pid_[i].compare_exchange_strong(expected, kSlotReserved, std::memory_order_acq_rel)) {
                unconfirmed_fd_[i] = -1;
                return static_cast<int>(i);
            }
        }
        return -1;
    }

    // Holds a reservation for the life of a run; gives it back unless the run handed it to a
    // tracked pid.
    struct SlotGuard {
        int index;
        explicit SlotGuard(int i) noexcept : index(i) {}
        SlotGuard(const SlotGuard&) = delete;
        SlotGuard& operator=(const SlotGuard&) = delete;
        ~SlotGuard() noexcept {
            if (index >= 0) unconfirmed_pid_[static_cast<std::size_t>(index)].store(0, std::memory_order_release);
        }
    };

    // Moves the reserved slot to the tracked pid and takes over the pidfd (the guard no longer
    // closes it). Cannot fail: the slot was reserved before the fork.
    static void TrackUnconfirmed(SlotGuard& slot, pid_t pid, FdGuard& pidfd) noexcept {
        const std::size_t i = static_cast<std::size_t>(slot.index);
        unconfirmed_fd_[i] = pidfd.fd;
        pidfd.fd = -1;
        unconfirmed_pid_[i].store(pid, std::memory_order_release);
        slot.index = -1;
    }

public:
    /** Children that were sent SIGKILL and not yet confirmed reaped. */
    [[nodiscard]] static std::size_t UnconfirmedCount() noexcept {
        std::size_t n = 0;
        for (std::size_t i = 0; i < kMaxUnconfirmedChildren; ++i) {
            if (unconfirmed_pid_[i].load(std::memory_order_acquire) > 0) ++n;
        }
        return n;
    }

    /**
     * Re-sends SIGKILL to each tracked child that is still there and reaps the
     * ones that have gone. Returns how many remain unconfirmed. Called at the
     * start of every run; a monitor may call it too.
     *
     * A tracked child is reached only through its pidfd (R2-K-23): a child that was reaped
     * elsewhere (ECHILD, or ESRCH on the signal) is forgotten and its number is never signaled
     * or waited on, so a pid that has been reused cannot be hit. A tracked child with no pidfd
     * (kernel older than 5.3) is reaped by number but never re-signaled.
     */
    static std::size_t ReapUnconfirmed() noexcept {
        for (std::size_t i = 0; i < kMaxUnconfirmedChildren; ++i) {
            pid_t p = unconfirmed_pid_[i].load(std::memory_order_acquire);
            if (p <= 0) continue;
            if (!unconfirmed_pid_[i].compare_exchange_strong(p, kSlotBusy, std::memory_order_acq_rel)) continue;
            int status = 0;
            const int fd = unconfirmed_fd_[i];
            const int rc = TryReap(p, fd, status);
            if (rc == 1 || (rc < 0 && errno == ECHILD)) {
                if (fd >= 0) ::close(fd);
                unconfirmed_fd_[i] = -1;
                unconfirmed_pid_[i].store(0, std::memory_order_release);
            } else {
                if (fd >= 0) KillChild(p, fd);
                unconfirmed_pid_[i].store(p, std::memory_order_release);
            }
        }
        return UnconfirmedCount();
    }

#ifdef STACK_SUPERVISED_TESTING
    /**
     * Test seam, compiled only with -DSTACK_SUPERVISED_TESTING (never in a
     * shipped build): a function that replaces the kill. Return true to say
     * "handled" and suppress the real SIGKILL, which simulates a kill that
     * does not take effect. Pass nullptr to restore the real kill.
     */
    using KillHook = bool (*)(pid_t pid, int pidfd);
    static void SetKillHookForTesting(KillHook hook) noexcept { kill_hook_ = hook; }

    /**
     * Test seam (same define): a function RunWorker calls after the worker image was opened and
     * verified and before the fork, to let a test change the file at the path (R2-K-21). Pass
     * nullptr to remove it.
     */
    using ImageCheckedHook = void (*)(const char* path);
    static void SetImageCheckedHookForTesting(ImageCheckedHook hook) noexcept { image_checked_hook_ = hook; }
#endif

private:

    // ------------------------------------------------------------------
    // Result frame: magic "STKR", u32 length, bytes, u64 FNV-1a of bytes.
    // ------------------------------------------------------------------
    static constexpr uint32_t kFrameMagic = 0x524B5453u;  // "STKR" little-endian
    static constexpr uint64_t kFnvOffset = 0xcbf29ce484222325ULL;
    static constexpr uint64_t kFnvPrime = 0x100000001b3ULL;

    struct FrameParser {
        enum class State : uint8_t { Header, Body, Trailer, Done, Invalid, Oversized };
        uint8_t* out;
        std::size_t out_capacity;
        std::size_t max_len;
        State state = State::Header;
        uint8_t head[8]{};
        std::size_t head_n = 0;
        uint32_t body_len = 0;
        std::size_t body_n = 0;
        uint8_t trailer[8]{};
        std::size_t trailer_n = 0;
        uint64_t hash = kFnvOffset;

        void Feed(const uint8_t* p, std::size_t n) noexcept {
            while (n > 0) {
                switch (state) {
                case State::Header: {
                    head[head_n++] = *p++;
                    --n;
                    if (head_n == 8) {
                        uint32_t magic = 0;
                        std::memcpy(&magic, head, 4);
                        std::memcpy(&body_len, head + 4, 4);
                        if (magic != kFrameMagic) { state = State::Invalid; return; }
                        if (body_len > max_len || body_len > out_capacity) { state = State::Oversized; return; }
                        state = body_len == 0 ? State::Trailer : State::Body;
                    }
                    break;
                }
                case State::Body: {
                    std::size_t take = body_len - body_n;
                    if (take > n) take = n;
                    std::memcpy(out + body_n, p, take);
                    for (std::size_t i = 0; i < take; ++i) {
                        hash ^= p[i];
                        hash *= kFnvPrime;
                    }
                    body_n += take;
                    p += take;
                    n -= take;
                    if (body_n == body_len) state = State::Trailer;
                    break;
                }
                case State::Trailer: {
                    trailer[trailer_n++] = *p++;
                    --n;
                    if (trailer_n == 8) {
                        uint64_t claimed = 0;
                        std::memcpy(&claimed, trailer, 8);
                        state = claimed == hash ? State::Done : State::Invalid;
                    }
                    break;
                }
                case State::Done:
                    state = State::Invalid;  // trailing bytes: not a clean frame
                    return;
                case State::Invalid:
                case State::Oversized:
                    return;
                }
            }
        }
    };

    struct FdGuard {
        int fd;
        explicit FdGuard(int f) noexcept : fd(f) {}
        FdGuard(const FdGuard&) = delete;
        FdGuard& operator=(const FdGuard&) = delete;
        ~FdGuard() noexcept { Close(); }
        void Close() noexcept {
            if (fd >= 0) { ::close(fd); fd = -1; }
        }
        [[nodiscard]] bool RaiseAbove(int floor) noexcept {
            if (fd > floor) return true;
            const int moved = ::fcntl(fd, F_DUPFD_CLOEXEC, floor + 1);
            if (moved < 0) return false;
            ::close(fd);
            fd = moved;
            return true;
        }
    };

    // Child setup failures, reported to the parent as SpawnFailed with this exit code.
    enum ChildExit : int {
        kExitParentGone = 120,
        kExitSignalReset = 121,
        kExitDescriptors = 122,
        kExitRlimits = 123,
        kExitSeccomp = 124,
        kExitChildMemory = 125,     // output buffer or payload stack could not be mapped
        kExitResultOverflow = 126,  // payload claimed more than kMaxOutputBytes
        kExitResultWrite = 127,
        kExitExec = 128             // worker path: execveat of the opened image failed
    };

    [[nodiscard]] static uint64_t MonotonicNs() noexcept {
        timespec ts{};
        ::clock_gettime(CLOCK_MONOTONIC, &ts);
        return static_cast<uint64_t>(ts.tv_sec) * 1'000'000'000ULL + static_cast<uint64_t>(ts.tv_nsec);
    }

    [[nodiscard]] static int PidfdOpen(pid_t pid) noexcept {
#ifdef __NR_pidfd_open
        const long r = ::syscall(__NR_pidfd_open, pid, 0);
        return r < 0 ? -1 : static_cast<int>(r);
#else
        (void)pid;
        return -1;
#endif
    }

    // Sends SIGKILL to the child (R2-K-23).
    //
    // With a pidfd the signal goes ONLY through the descriptor, which names that process and
    // no other: if the process is gone (reaped elsewhere) the kernel answers ESRCH and nothing
    // is signaled. The child's process group is signaled by number only while the child is
    // checked alive and unreaped (waitid on the pidfd with WNOHANG|WNOWAIT answers "no state
    // change"); a child that has exited, or was reaped, gets no group signal, because a pid
    // number is reusable once reaped. The check and the group signal are two calls: the
    // window between them is the time another thread would need to reap the child AND have
    // its number reused, and the filter denies the worker any descendant, so the group signal
    // is defense in depth, not the kill.
    //
    // Without a pidfd (kernel older than 5.3) the child is signaled by number, as before: the
    // caller has not reaped it and nothing else is assumed to.
#ifdef STACK_SUPERVISED_TESTING
    static inline KillHook kill_hook_ = nullptr;
#endif
#ifdef STACK_SUPERVISED_TESTING
    static inline ImageCheckedHook image_checked_hook_ = nullptr;
#endif
    static void KillChild(pid_t pid, int pidfd) noexcept {
#ifdef STACK_SUPERVISED_TESTING
        if (kill_hook_ != nullptr && kill_hook_(pid, pidfd)) return;
#endif
        if (pidfd >= 0) {
            if (ChildIsAliveAndUnreaped(pidfd)) (void)::kill(-pid, SIGKILL);
            (void)PidfdSendKill(pidfd);  // ESRCH: already gone
            return;
        }
        (void)::kill(-pid, SIGKILL);
        (void)::kill(pid, SIGKILL);
    }

    // True when the process behind pidfd exists, has not exited and has not been reaped.
    [[nodiscard]] static bool ChildIsAliveAndUnreaped(int pidfd) noexcept {
#ifdef __NR_waitid
        siginfo_t info{};
        const long r = ::syscall(__NR_waitid, kPidfdIdType, pidfd, &info, WEXITED | WNOHANG | WNOWAIT, nullptr);
        return r == 0 && info.si_pid == 0;
#else
        (void)pidfd;
        return false;
#endif
    }

    [[nodiscard]] static bool PidfdSendKill(int pidfd) noexcept {
#ifdef __NR_pidfd_send_signal
        return ::syscall(__NR_pidfd_send_signal, pidfd, SIGKILL, nullptr, 0) == 0;
#else
        (void)pidfd;
        return false;
#endif
    }

    // True when the kernel would reap children on its own: SIGCHLD set to
    // SIG_IGN, or SA_NOCLDWAIT set.
    [[nodiscard]] static bool SigchldIsIgnored() noexcept {
        struct sigaction current{};
        if (::sigaction(SIGCHLD, nullptr, &current) != 0) return false;
        return current.sa_handler == SIG_IGN || (current.sa_flags & SA_NOCLDWAIT) != 0;
    }

    // Reads what is available now. Returns false on a hard read error.
    [[nodiscard]] static bool DrainPipe(int fd, FrameParser& parser, bool& eof) noexcept {
        uint8_t chunk[4096];
        for (;;) {
            const ssize_t r = ::read(fd, chunk, sizeof chunk);
            if (r > 0) {
                parser.Feed(chunk, static_cast<std::size_t>(r));
                continue;
            }
            if (r == 0) { eof = true; return true; }
            if (errno == EINTR) continue;
            if (errno == EAGAIN) return true;
            eof = true;
            return false;
        }
    }

    // After the child is gone its write end is closed by the kernel, so the
    // pipe drains to EOF. A sibling child forked concurrently by another
    // thread can hold a copy of the write end for the microseconds before
    // it closes its inherited descriptors, so the wait is bounded.
    static void DrainPipeAfterExit(int fd, FrameParser& parser, bool& eof) noexcept {
        for (int rounds = 0; rounds < 50 && !eof; ++rounds) {
            if (!DrainPipe(fd, parser, eof)) return;
            if (eof) return;
            pollfd p{fd, POLLIN, 0};
            const int pr = ::poll(&p, 1, 20);
            if (pr == 0) return;
            if (pr < 0 && errno != EINTR) return;
        }
    }

    static void Classify(ExecutionReport& report, int status, const FrameParser& parser,
                         bool poll_failed, int poll_errno) noexcept {
        if (WIFSIGNALED(status)) report.signal_number = WTERMSIG(status);
        if (WIFEXITED(status)) report.exit_code = WEXITSTATUS(status);

        if (report.deadline_fired) { report.outcome = Outcome::TimedOut; return; }
        if (poll_failed) {
            report.outcome = Outcome::SupervisorError;
            report.error_number = poll_errno;
            return;
        }
        if (parser.state == FrameParser::State::Oversized) { report.outcome = Outcome::ResultOversized; return; }
        if (WIFSIGNALED(status)) {
            const int sig = WTERMSIG(status);
            if (sig == SIGSYS) report.outcome = Outcome::SeccompViolation;
            else if (sig == SIGXCPU || sig == SIGXFSZ) report.outcome = Outcome::ResourceLimit;
            else report.outcome = Outcome::Crashed;
            return;
        }
        if (!WIFEXITED(status)) { report.outcome = Outcome::SupervisorError; return; }
        const int code = WEXITSTATUS(status);
        if (code >= kExitParentGone && code <= kExitExec) { report.outcome = Outcome::SpawnFailed; return; }
        if (code != 0) { report.outcome = Outcome::ExitedNonZero; return; }
        if (parser.state == FrameParser::State::Done) {
            report.outcome = Outcome::Completed;
            report.result_length = parser.body_len;
            report.result_self_reported = true;
            return;
        }
        report.outcome = Outcome::ResultMissing;
    }

    // ------------------------------------------------------------------
    // Child side. Only raw syscalls and the payload run here; no heap use
    // before the payload, no C++ teardown (every exit is _exit).
    // ------------------------------------------------------------------
    [[noreturn]] static void ChildMain(const Limits& limits, PayloadThunk payload, void* context,
                                       int result_fd, pid_t parent_pid) noexcept {
        (void)::setpgid(0, 0);
        (void)::prctl(PR_SET_PDEATHSIG, SIGKILL, 0, 0, 0);
        if (::getppid() != parent_pid) ::_exit(kExitParentGone);

        if (!ResetSignals()) ::_exit(kExitSignalReset);

        // Output buffer and payload stack before the address-space limit so
        // the limit cannot take them away. Lazily backed: unused pages cost
        // nothing. The stack has a guard page below it.
        const std::size_t out_bytes = kMaxOutputBytes;
        void* out_map = ::mmap(nullptr, out_bytes, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (out_map == MAP_FAILED) ::_exit(kExitChildMemory);
        auto* out = static_cast<uint8_t*>(out_map);
        void* stack_map = ::mmap(nullptr, kPayloadStackBytes + kGuardBytes, PROT_READ | PROT_WRITE,
                                 MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE | MAP_STACK, -1, 0);
        if (stack_map == MAP_FAILED) ::_exit(kExitChildMemory);
        if (::mprotect(stack_map, kGuardBytes, PROT_NONE) != 0) ::_exit(kExitChildMemory);

        ucontext_t main_context{};
        ucontext_t payload_context{};
        if (::getcontext(&payload_context) != 0) ::_exit(kExitChildMemory);
        payload_context.uc_stack.ss_sp = static_cast<uint8_t*>(stack_map) + kGuardBytes;
        payload_context.uc_stack.ss_size = kPayloadStackBytes;
        payload_context.uc_link = &main_context;
        ::makecontext(&payload_context, &PayloadTrampoline, 0);

        if (!SanitizeDescriptors(result_fd, limits.inherit_fd)) ::_exit(kExitDescriptors);
        if (!ApplyRlimits(limits, result_fd)) ::_exit(kExitRlimits);
        if (!InstallFilter(result_fd, limits.inherit_fd, ::getpid())) ::_exit(kExitSeccomp);

        // The child is a private copy, so these process-wide slots are ours.
        child_payload_ = payload;
        child_context_ = context;
        child_out_ = out;
        child_capacity_ = static_cast<std::size_t>(limits.max_output_bytes);
        child_len_ = 0;
        if (::swapcontext(&main_context, &payload_context) != 0) ::_exit(kExitChildMemory);

        const std::size_t len = child_len_;
        if (len > out_bytes) ::_exit(kExitResultOverflow);
        if (!WriteFrame(result_fd, out, len)) ::_exit(kExitResultWrite);
        ::_exit(0);
    }

    // ------------------------------------------------------------------
    // Worker path.
    // ------------------------------------------------------------------

    // Opens the worker image and checks the OPEN file, not the path. Returns 0 or an errno.
    //
    // Open: openat2 with RESOLVE_NO_SYMLINKS refuses a symlink in ANY component of the path
    // (ELOOP); where openat2 is unavailable (ENOSYS, or a filter that answers EPERM) the open
    // falls back to O_NOFOLLOW, which refuses only a symlink as the FINAL component. A
    // deployment names a canonical path.
    //
    // Checks on the open file: a regular file, an exec bit, none of setuid, setgid,
    // group-writable, world-writable, owned by root or by this process's effective user.
    //
    // Digest (expected_sha256 non-null): the file is read through this descriptor, hashed as it
    // is read and copied into a sealed memfd (no writes, no resize, sealed). A mismatch is
    // EKEYREJECTED. On success fd_out is the SEALED COPY, so the bytes that run are the bytes
    // that were hashed whatever happens to the file afterwards. A kernel without memfd_create,
    // or one that forbids executing memfds, fails closed here. Without a digest fd_out is the
    // opened file itself.
    //
    // The descriptor is close-on-exec, which is also why a script (shebang) worker cannot be
    // executed: the interpreter would not find the descriptor. Workers are ELF programs.
    [[nodiscard]] static int OpenWorkerImage(const char* path, const uint8_t* expected_sha256, int& fd_out) noexcept {
        fd_out = -1;
        if (path == nullptr || path[0] != '/') return EINVAL;
        std::size_t n = 0;
        while (path[n] != '\0') {
            if (++n > kMaxWorkerPathBytes) return ENAMETOOLONG;
        }
        int fd = OpenNoSymlinks(path);
        if (fd < 0) return errno;
        struct stat st{};
        if (::fstat(fd, &st) != 0) {
            const int e = errno;
            ::close(fd);
            return e;
        }
        int err = 0;
        if (!S_ISREG(st.st_mode)) err = EACCES;
        else if ((st.st_mode & (S_IXUSR | S_IXGRP | S_IXOTH)) == 0) err = EACCES;
        else if ((st.st_mode & (S_ISUID | S_ISGID | S_IWGRP | S_IWOTH)) != 0) err = EACCES;
        else if (st.st_uid != 0 && st.st_uid != ::geteuid()) err = EACCES;
        if (err != 0) {
            ::close(fd);
            return err;
        }
        if (expected_sha256 != nullptr) {
            int copy = -1;
            uint8_t actual[32];
            err = HashDescriptor(fd, actual, kSealedCopy, &copy);
            ::close(fd);
            if (err == 0 && !Equal32(actual, expected_sha256)) err = EKEYREJECTED;
            if (err != 0) {
                if (copy >= 0) ::close(copy);
                return err;
            }
            fd = copy;
        }
        fd_out = fd;
        return 0;
    }

    static constexpr int kSealedCopy = -2;  // HashDescriptor: also copy into a sealed memfd

    [[nodiscard]] static bool Equal32(const uint8_t* a, const uint8_t* b) noexcept {
        uint8_t diff = 0;
        for (int i = 0; i < 32; ++i) diff = static_cast<uint8_t>(diff | (a[i] ^ b[i]));
        return diff == 0;
    }

    // openat2 how struct, spelled here so no header newer than the kernel's is needed.
    struct OpenHow {
        uint64_t flags;
        uint64_t mode;
        uint64_t resolve;
    };
    static constexpr uint64_t kResolveNoMagicLinks = 0x02;
    static constexpr uint64_t kResolveNoSymlinks = 0x04;

    [[nodiscard]] static int OpenNoSymlinks(const char* path) noexcept {
#ifdef __NR_openat2
        OpenHow how{};
        how.flags = O_RDONLY | O_CLOEXEC | O_NOFOLLOW;
        how.resolve = kResolveNoMagicLinks | kResolveNoSymlinks;
        const long r = ::syscall(__NR_openat2, AT_FDCWD, path, &how, sizeof how);
        if (r >= 0) return static_cast<int>(r);
        if (errno != ENOSYS && errno != EPERM) return -1;
#endif
        return ::open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    }

    // Reads fd to its end with pread (the file offset is not used), hashing as it goes. With
    // `copy_mode == kSealedCopy` the bytes are also written to a new memfd, which is sealed and
    // returned in *copy_out. Returns 0 or an errno; on an error *copy_out is closed and -1.
    [[nodiscard]] static int HashDescriptor(int fd, uint8_t (&digest)[32], int copy_mode, int* copy_out = nullptr) noexcept {
        int copy = -1;
        if (copy_mode == kSealedCopy) {
            copy = CreateExecMemfd();
            if (copy < 0) return errno != 0 ? errno : ENOSYS;
        }
        Sha256State st;
        uint8_t buf[65536];
        std::size_t total = 0;
        int err = 0;
        for (;;) {
            const ssize_t r = ::pread(fd, buf, sizeof buf, static_cast<off_t>(total));
            if (r < 0) {
                if (errno == EINTR) continue;
                err = errno;
                break;
            }
            if (r == 0) break;
            const std::size_t got = static_cast<std::size_t>(r);
            if (total + got > kMaxWorkerImageBytes) { err = EFBIG; break; }
            st.Update(buf, got);
            if (copy >= 0 && !WriteAll(copy, buf, got)) { err = errno != 0 ? errno : EIO; break; }
            total += got;
        }
        if (err == 0 && copy >= 0) {
#if defined(F_ADD_SEALS)
            if (::fcntl(copy, F_ADD_SEALS, F_SEAL_SEAL | F_SEAL_SHRINK | F_SEAL_GROW | F_SEAL_WRITE) != 0) err = errno;
#else
            err = ENOSYS;
#endif
        }
        if (err != 0) {
            if (copy >= 0) ::close(copy);
            if (copy_out != nullptr) *copy_out = -1;
            return err;
        }
        st.Final(digest);
        if (copy_out != nullptr) *copy_out = copy;
        return 0;
    }

    [[nodiscard]] static int CreateExecMemfd() noexcept {
#if defined(__NR_memfd_create)
        constexpr unsigned kCloexec = 0x0001U, kAllowSealing = 0x0002U, kExec = 0x0010U;
        long r = ::syscall(__NR_memfd_create, "stack-worker-image", kCloexec | kAllowSealing | kExec);
        if (r < 0 && errno == EINVAL) r = ::syscall(__NR_memfd_create, "stack-worker-image", kCloexec | kAllowSealing);
        return r < 0 ? -1 : static_cast<int>(r);
#else
        errno = ENOSYS;
        return -1;
#endif
    }

    // SHA-256 (FIPS 180-4). No allocation; the whole state is on the stack.
    struct Sha256State {
        uint32_t h[8] = {0x6a09e667u, 0xbb67ae85u, 0x3c6ef372u, 0xa54ff53au,
                         0x510e527fu, 0x9b05688cu, 0x1f83d9abu, 0x5be0cd19u};
        uint8_t block[64]{};
        std::size_t fill = 0;
        uint64_t total = 0;

        static uint32_t Rotr(uint32_t x, unsigned n) noexcept { return (x >> n) | (x << (32 - n)); }

        void Compress(const uint8_t* p) noexcept {
            static constexpr uint32_t K[64] = {
                0x428a2f98u, 0x71374491u, 0xb5c0fbcfu, 0xe9b5dba5u, 0x3956c25bu, 0x59f111f1u, 0x923f82a4u, 0xab1c5ed5u,
                0xd807aa98u, 0x12835b01u, 0x243185beu, 0x550c7dc3u, 0x72be5d74u, 0x80deb1feu, 0x9bdc06a7u, 0xc19bf174u,
                0xe49b69c1u, 0xefbe4786u, 0x0fc19dc6u, 0x240ca1ccu, 0x2de92c6fu, 0x4a7484aau, 0x5cb0a9dcu, 0x76f988dau,
                0x983e5152u, 0xa831c66du, 0xb00327c8u, 0xbf597fc7u, 0xc6e00bf3u, 0xd5a79147u, 0x06ca6351u, 0x14292967u,
                0x27b70a85u, 0x2e1b2138u, 0x4d2c6dfcu, 0x53380d13u, 0x650a7354u, 0x766a0abbu, 0x81c2c92eu, 0x92722c85u,
                0xa2bfe8a1u, 0xa81a664bu, 0xc24b8b70u, 0xc76c51a3u, 0xd192e819u, 0xd6990624u, 0xf40e3585u, 0x106aa070u,
                0x19a4c116u, 0x1e376c08u, 0x2748774cu, 0x34b0bcb5u, 0x391c0cb3u, 0x4ed8aa4au, 0x5b9cca4fu, 0x682e6ff3u,
                0x748f82eeu, 0x78a5636fu, 0x84c87814u, 0x8cc70208u, 0x90befffau, 0xa4506cebu, 0xbef9a3f7u, 0xc67178f2u};
            uint32_t w[64];
            for (int i = 0; i < 16; ++i) {
                w[i] = (static_cast<uint32_t>(p[4 * i]) << 24) | (static_cast<uint32_t>(p[4 * i + 1]) << 16) |
                       (static_cast<uint32_t>(p[4 * i + 2]) << 8) | static_cast<uint32_t>(p[4 * i + 3]);
            }
            for (int i = 16; i < 64; ++i) {
                const uint32_t s0 = Rotr(w[i - 15], 7) ^ Rotr(w[i - 15], 18) ^ (w[i - 15] >> 3);
                const uint32_t s1 = Rotr(w[i - 2], 17) ^ Rotr(w[i - 2], 19) ^ (w[i - 2] >> 10);
                w[i] = w[i - 16] + s0 + w[i - 7] + s1;
            }
            uint32_t a = h[0], b = h[1], c = h[2], d = h[3], e = h[4], f = h[5], g = h[6], hh = h[7];
            for (int i = 0; i < 64; ++i) {
                const uint32_t s1 = Rotr(e, 6) ^ Rotr(e, 11) ^ Rotr(e, 25);
                const uint32_t ch = (e & f) ^ (~e & g);
                const uint32_t t1 = hh + s1 + ch + K[i] + w[i];
                const uint32_t s0 = Rotr(a, 2) ^ Rotr(a, 13) ^ Rotr(a, 22);
                const uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
                const uint32_t t2 = s0 + maj;
                hh = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2;
            }
            h[0] += a; h[1] += b; h[2] += c; h[3] += d; h[4] += e; h[5] += f; h[6] += g; h[7] += hh;
        }

        void Update(const uint8_t* p, std::size_t n) noexcept {
            total += n;
            while (n > 0) {
                std::size_t take = 64 - fill;
                if (take > n) take = n;
                std::memcpy(block + fill, p, take);
                fill += take;
                p += take;
                n -= take;
                if (fill == 64) { Compress(block); fill = 0; }
            }
        }

        void Final(uint8_t (&out)[32]) noexcept {
            const uint64_t bits = total * 8;
            const uint8_t one = 0x80;
            Update(&one, 1);
            const uint8_t zero = 0;
            while (fill != 56) Update(&zero, 1);
            uint8_t len[8];
            for (int i = 0; i < 8; ++i) len[i] = static_cast<uint8_t>(bits >> (56 - 8 * i));
            Update(len, 8);
            for (int i = 0; i < 8; ++i) {
                out[4 * i] = static_cast<uint8_t>(h[i] >> 24);
                out[4 * i + 1] = static_cast<uint8_t>(h[i] >> 16);
                out[4 * i + 2] = static_cast<uint8_t>(h[i] >> 8);
                out[4 * i + 3] = static_cast<uint8_t>(h[i]);
            }
        }
    };

    static void FormatDecimal(uint32_t v, char (&out)[16]) noexcept {
        char tmp[12];
        std::size_t n = 0;
        do {
            tmp[n++] = static_cast<char>('0' + (v % 10));
            v /= 10;
        } while (v != 0);
        std::size_t i = 0;
        while (n > 0) out[i++] = tmp[--n];
        out[i] = '\0';
    }

    // Child side of RunWorker. Raw syscalls only; every exit is _exit.
    [[noreturn]] static void WorkerChildMain(const Limits& limits, int image_fd, char* const argv[], char* const envp[],
                                             int result_fd, pid_t parent_pid) noexcept {
        (void)::setpgid(0, 0);
        (void)::prctl(PR_SET_PDEATHSIG, SIGKILL, 0, 0, 0);
        if (::getppid() != parent_pid) ::_exit(kExitParentGone);
        if (!ResetSignals()) ::_exit(kExitSignalReset);
        if (!WorkerDescriptors(result_fd, image_fd)) ::_exit(kExitDescriptors);
        if (!ApplyRlimits(limits, image_fd)) ::_exit(kExitRlimits);
        // Whatever image this is, exec may not grant it privilege (setuid, setgid, file
        // capabilities). The worker sets it again inside its own filter install (R2-K-21).
        if (::prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0) ::_exit(kExitSeccomp);
#ifdef __NR_execveat
        (void)::syscall(__NR_execveat, image_fd, "", argv, envp, AT_EMPTY_PATH);
#else
        (void)argv;
        (void)envp;
#endif
        ::_exit(kExitExec);
    }

    // Leaves exactly: 0, 1, 2 on /dev/null, the result pipe on kWorkerResultFd
    // (inheritable), and the image descriptor (close-on-exec, moved to 4 or
    // above). Everything else is closed. image_fd is updated if it moved.
    [[nodiscard]] static bool WorkerDescriptors(int result_fd, int& image_fd) noexcept {
        if (image_fd <= kWorkerResultFd) {
            const int moved = ::fcntl(image_fd, F_DUPFD_CLOEXEC, kWorkerResultFd + 1);
            if (moved < 0) return false;
            ::close(image_fd);
            image_fd = moved;
        }
        if (result_fd != kWorkerResultFd && ::dup2(result_fd, kWorkerResultFd) != kWorkerResultFd) return false;
        if (::fcntl(kWorkerResultFd, F_SETFD, 0) != 0) return false;
        const int devnull = ::open("/dev/null", O_RDWR);  // not close-on-exec: dup2 onto itself would keep that
        if (devnull < 0) return false;
        for (int fd = 0; fd <= 2; ++fd) {
            if (devnull != fd && ::dup2(devnull, fd) != fd) return false;
        }
        if (devnull > 2 && devnull != image_fd) ::close(devnull);
        CloseRange(kWorkerResultFd + 1, image_fd - 1);
        CloseRange(image_fd + 1, ~0);
        return true;
    }

    static constexpr std::size_t kPayloadStackBytes = 8u << 20;
    static constexpr std::size_t kGuardBytes = 1u << 16;

    static inline PayloadThunk child_payload_ = nullptr;
    static inline void* child_context_ = nullptr;
    static inline uint8_t* child_out_ = nullptr;
    static inline std::size_t child_capacity_ = 0;
    static inline std::size_t child_len_ = 0;

    // Runs on the payload stack. Returning resumes main_context via uc_link.
    static void PayloadTrampoline() noexcept {
        child_len_ = child_payload_(child_context_, child_out_, child_capacity_);
    }

    [[nodiscard]] static bool ResetSignals() noexcept {
        struct sigaction dfl{};
        dfl.sa_handler = SIG_DFL;
        ::sigemptyset(&dfl.sa_mask);
        for (int sig = 1; sig < NSIG; ++sig) {
            if (sig == SIGKILL || sig == SIGSTOP) continue;
            if (sig >= SIGRTMIN && sig <= SIGRTMAX) {
                // glibc reserves the lowest real-time signals; a failure there is not ours.
                (void)::sigaction(sig, &dfl, nullptr);
                continue;
            }
            if (::sigaction(sig, &dfl, nullptr) != 0 && errno != EINVAL) return false;
        }
        sigset_t none;
        ::sigemptyset(&none);
        return ::sigprocmask(SIG_SETMASK, &none, nullptr) == 0;
    }

    [[nodiscard]] static bool SanitizeDescriptors(int result_fd, int inherit_fd) noexcept {
        const int devnull = ::open("/dev/null", O_RDWR | O_CLOEXEC);
        if (devnull < 0) return false;
        for (int fd = 0; fd <= 2; ++fd) {
            if (::dup2(devnull, fd) != fd) return false;
        }
        if (devnull > 2) ::close(devnull);
        // Close everything except 0..2, result_fd and inherit_fd.
        int keep[2] = {result_fd, inherit_fd};
        if (keep[0] > keep[1]) { const int t = keep[0]; keep[0] = keep[1]; keep[1] = t; }
        int lo = 3;
        for (int k : keep) {
            if (k < 3) continue;
            if (k > lo) CloseRange(lo, k - 1);
            lo = k + 1;
        }
        CloseRange(lo, ~0);
        return true;
    }

    static void CloseRange(int first, int last) noexcept {
        // last == ~0 means "to the end": compare it as unsigned, not as -1 (R2-K-19).
        if (last != ~0 && first > last) return;
#ifdef __NR_close_range
        if (::syscall(__NR_close_range, static_cast<unsigned>(first), static_cast<unsigned>(last), 0) == 0) return;
#endif
        rlimit nofile{};
        long limit = 65536;
        if (::getrlimit(RLIMIT_NOFILE, &nofile) == 0 && nofile.rlim_cur != RLIM_INFINITY &&
            static_cast<long>(nofile.rlim_cur) < limit) {
            limit = static_cast<long>(nofile.rlim_cur);
        }
        const long stop = (last == ~0 || static_cast<long>(last) >= limit) ? limit - 1 : last;
        for (long fd = first; fd <= stop; ++fd) (void)::close(static_cast<int>(fd));
    }

    [[nodiscard]] static bool ApplyRlimits(const Limits& limits, int result_fd) noexcept {
        rlimit lim{};
        lim.rlim_cur = 0;
        lim.rlim_max = 0;
        if (::setrlimit(RLIMIT_CORE, &lim) != 0) return false;
        // NPROC is not enforced for a privileged uid; the filter denies clone anyway.
        (void)::setrlimit(RLIMIT_NPROC, &lim);

        uint64_t cpu = limits.cpu_seconds;
        if (cpu == 0) cpu = (limits.wall_clock_deadline_ns + 999'999'999ULL) / 1'000'000'000ULL + 1;
        lim.rlim_cur = cpu;
        lim.rlim_max = cpu + 1;
        if (::setrlimit(RLIMIT_CPU, &lim) != 0) return false;

        lim.rlim_cur = limits.file_size_bytes;
        lim.rlim_max = limits.file_size_bytes;
        if (::setrlimit(RLIMIT_FSIZE, &lim) != 0) return false;

        if (limits.address_space_bytes > 0) {
            lim.rlim_cur = limits.address_space_bytes;
            lim.rlim_max = limits.address_space_bytes;
            if (::setrlimit(RLIMIT_AS, &lim) != 0) return false;
        }

        int highest = result_fd > 2 ? result_fd : 2;
        if (limits.inherit_fd > highest) highest = limits.inherit_fd;
        uint64_t nofile = static_cast<uint64_t>(highest) + 1;
        if (limits.nofile > nofile) nofile = limits.nofile;
        lim.rlim_cur = nofile;
        lim.rlim_max = nofile;
        return ::setrlimit(RLIMIT_NOFILE, &lim) == 0;
    }

    // ------------------------------------------------------------------
    // Seccomp filter. Built at runtime because the result descriptor, the
    // inherited descriptor and the child's pid are only known then. Jump
    // targets are symbolic until Finish() appends the two return blocks.
    // ------------------------------------------------------------------
    struct FilterBuilder {
        static constexpr std::size_t kMaxInsns = 96;
        static constexpr uint8_t kToAllow = 0xFE;
        static constexpr uint8_t kToKill = 0xFD;
        sock_filter insns[kMaxInsns]{};
        std::size_t len = 0;
        bool overflow = false;

        void Stmt(uint16_t code, uint32_t k) noexcept {
            if (len >= kMaxInsns) { overflow = true; return; }
            insns[len++] = BPF_STMT(code, k);
        }
        void Jump(uint16_t code, uint32_t k, uint8_t jt, uint8_t jf) noexcept {
            if (len >= kMaxInsns) { overflow = true; return; }
            insns[len++] = BPF_JUMP(code, k, jt, jf);
        }
        void LoadNr() noexcept { Stmt(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr)); }
        void LoadArg(unsigned i) noexcept {
            Stmt(BPF_LD | BPF_W | BPF_ABS, static_cast<uint32_t>(offsetof(struct seccomp_data, args) + i * sizeof(uint64_t)));
        }
        void AllowNr(long nr) noexcept { Jump(BPF_JMP | BPF_JEQ | BPF_K, static_cast<uint32_t>(nr), kToAllow, 0); }

        // Resolves symbolic targets and appends: [len] kill, [len+1] allow.
        [[nodiscard]] bool Finish() noexcept {
            if (overflow || len + 2 > kMaxInsns) return false;
            const std::size_t kill_at = len;
            const std::size_t allow_at = len + 1;
            for (std::size_t i = 0; i < len; ++i) {
                if (BPF_CLASS(insns[i].code) != BPF_JMP) continue;
                if (!Resolve(insns[i].jt, i, kill_at, allow_at)) return false;
                if (!Resolve(insns[i].jf, i, kill_at, allow_at)) return false;
            }
            Stmt(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS);
            Stmt(BPF_RET | BPF_K, SECCOMP_RET_ALLOW);
            return !overflow;
        }
        [[nodiscard]] static bool Resolve(uint8_t& slot, std::size_t at, std::size_t kill_at, std::size_t allow_at) noexcept {
            std::size_t target = 0;
            if (slot == kToAllow) target = allow_at;
            else if (slot == kToKill) target = kill_at;
            else return true;
            const std::size_t distance = target - (at + 1);
            if (distance > 255) return false;
            slot = static_cast<uint8_t>(distance);
            return true;
        }
    };

    [[nodiscard]] static bool InstallFilter(int result_fd, int inherit_fd, pid_t self) noexcept {
        if (::prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0) return false;
#if defined(__x86_64__)
        constexpr uint32_t kArch = AUDIT_ARCH_X86_64;
#elif defined(__aarch64__)
        constexpr uint32_t kArch = AUDIT_ARCH_AARCH64;
#else
#error "SupervisedExecutor: no seccomp table for this architecture"
#endif
        FilterBuilder b;
        b.Stmt(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, arch));
        b.Jump(BPF_JMP | BPF_JEQ | BPF_K, kArch, 0, FilterBuilder::kToKill);
        b.LoadNr();
#if defined(__x86_64__)
        // The x32 ABI shares the table with bit 30 set; never allow it.
        b.Jump(BPF_JMP | BPF_JSET | BPF_K, 0x40000000u, FilterBuilder::kToKill, 0);
#endif
        // read: only fd 0 (/dev/null) and the inherited descriptor.
        {
            const uint8_t block = inherit_fd >= 0 ? 4 : 3;
            b.Jump(BPF_JMP | BPF_JEQ | BPF_K, __NR_read, 0, block);
            b.LoadArg(0);
            b.Jump(BPF_JMP | BPF_JEQ | BPF_K, 0, FilterBuilder::kToAllow, 0);
            if (inherit_fd >= 0) {
                b.Jump(BPF_JMP | BPF_JEQ | BPF_K, static_cast<uint32_t>(inherit_fd), FilterBuilder::kToAllow, 0);
            }
            b.Stmt(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS);
        }
        // write: fds 1 and 2 (/dev/null) and the result pipe.
        b.Jump(BPF_JMP | BPF_JEQ | BPF_K, __NR_write, 0, 5);
        b.LoadArg(0);
        b.Jump(BPF_JMP | BPF_JEQ | BPF_K, 1, FilterBuilder::kToAllow, 0);
        b.Jump(BPF_JMP | BPF_JEQ | BPF_K, 2, FilterBuilder::kToAllow, 0);
        b.Jump(BPF_JMP | BPF_JEQ | BPF_K, static_cast<uint32_t>(result_fd), FilterBuilder::kToAllow, 0);
        b.Stmt(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS);
        // tgkill: only at itself (abort() needs it).
        b.Jump(BPF_JMP | BPF_JEQ | BPF_K, __NR_tgkill, 0, 3);
        b.LoadArg(0);
        b.Jump(BPF_JMP | BPF_JEQ | BPF_K, static_cast<uint32_t>(self), FilterBuilder::kToAllow, 0);
        b.Stmt(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS);
        // mmap: anonymous, never executable.
        b.Jump(BPF_JMP | BPF_JEQ | BPF_K, __NR_mmap, 0, 5);
        b.LoadArg(2);
        b.Jump(BPF_JMP | BPF_JSET | BPF_K, PROT_EXEC, FilterBuilder::kToKill, 0);
        b.LoadArg(3);
        b.Jump(BPF_JMP | BPF_JSET | BPF_K, MAP_ANONYMOUS, FilterBuilder::kToAllow, 0);
        b.Stmt(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS);
        // mprotect: never executable.
        b.Jump(BPF_JMP | BPF_JEQ | BPF_K, __NR_mprotect, 0, 2);
        b.LoadArg(2);
        b.Jump(BPF_JMP | BPF_JSET | BPF_K, PROT_EXEC, FilterBuilder::kToKill, FilterBuilder::kToAllow);
        // Unconditional allows: what a computing payload needs.
        b.AllowNr(__NR_exit_group);
        b.AllowNr(__NR_exit);
        b.AllowNr(__NR_brk);
        b.AllowNr(__NR_munmap);
        b.AllowNr(__NR_mremap);
        b.AllowNr(__NR_madvise);
        b.AllowNr(__NR_futex);
        b.AllowNr(__NR_clock_gettime);
        b.AllowNr(__NR_clock_nanosleep);
#ifdef __NR_nanosleep
        b.AllowNr(__NR_nanosleep);
#endif
        b.AllowNr(__NR_sched_yield);
        b.AllowNr(__NR_getpid);
        b.AllowNr(__NR_gettid);
        b.AllowNr(__NR_getrandom);
        b.AllowNr(__NR_rt_sigaction);
        b.AllowNr(__NR_rt_sigprocmask);
        b.AllowNr(__NR_rt_sigreturn);
        if (!b.Finish()) return false;

        sock_fprog prog{};
        prog.len = static_cast<unsigned short>(b.len);
        prog.filter = b.insns;
        return ::prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog, 0, 0) == 0;
    }

    [[nodiscard]] static bool WriteAll(int fd, const uint8_t* p, std::size_t n) noexcept {
        while (n > 0) {
            const ssize_t w = ::write(fd, p, n);
            if (w < 0) {
                if (errno == EINTR) continue;
                return false;
            }
            p += w;
            n -= static_cast<std::size_t>(w);
        }
        return true;
    }

    [[nodiscard]] static bool WriteFrame(int fd, const uint8_t* body, std::size_t len) noexcept {
        uint8_t head[8];
        const uint32_t magic = kFrameMagic;
        const uint32_t len32 = static_cast<uint32_t>(len);
        std::memcpy(head, &magic, 4);
        std::memcpy(head + 4, &len32, 4);
        uint64_t hash = kFnvOffset;
        for (std::size_t i = 0; i < len; ++i) {
            hash ^= body[i];
            hash *= kFnvPrime;
        }
        uint8_t trailer[8];
        std::memcpy(trailer, &hash, 8);
        return WriteAll(fd, head, 8) && WriteAll(fd, body, len) && WriteAll(fd, trailer, 8);
    }
};

}  // namespace stack::supervised
