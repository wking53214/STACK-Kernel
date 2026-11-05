#pragma once

/**
 * ≡TACK KERNEL LAYER 4: Host Boundary Orchestration and SECCOMP Enforcement
 *
 * ───────────────────────────────────────────────────────────────────────────
 * ORCHESTRATION LAYER: Binding Execution to Governance
 *
 * This is where all prior layers converge into one boundary: the host.
 *
 * The GovernedMinotaurHost orchestrates five enforced gates:
 *   1. Capability verification (SIMD token validation)
 *   2. Rate limiting (KineticGovernor token consumption)
 *   3. Deadline detection (HardenedPosixPreemptionGuard signal handler)
 *   4. Software deadline tracking (ExecutionDeadlineScope)
 *   5. Debt accrual and ceiling enforcement (ComputeDebtTracker)
 *
 * Plus a kernel-level boundary:
 *   6. SECCOMP BPF filter (syscall restriction)
 *
 * Execution flow through ExecuteGovernedTransaction():
 *   Check capabilities → consume tokens → arm timer → run payload →
 *   commit tokens and accrue debt → check preemption → check deadline →
 *   check the debt ceiling
 *
 * If any gate rejects, execution halts and error returns to caller.
 * Accounting (I-03): a transaction rejected before its payload ran costs
 * nothing (its tokens are refunded, no debt); once the payload has run its
 * tokens are spent and its ticks charged whatever the outcome.
 *
 * ───────────────────────────────────────────────────────────────────────────
 * ARCHITECTURAL NOTE: Single-Responsibility Violation
 *
 * ExecuteGovernedTransaction() is doing too much in one method. It orchestrates
 * capability checking, rate limiting, deadline enforcement, debt tracking, and
 * transaction rollback all in a single call. This is architecturally correct for
 * correctness (all gates must complete) but tactically complex.
 *
 * A production implementation would likely split this into separate orchestration
 * phases, each checkpointable and recoverable independently. Current implementation
 * is intentionally unified to ensure atomic all-or-nothing execution.
 *
 * ───────────────────────────────────────────────────────────────────────────
 */

#include "stack_kernel.hpp"
#include "stack_kinetic_governor.hpp"
#include "posix_deadline_timer_hardened.hpp"
#include "stack_audit.hpp"

#include <array>
#include <atomic>
#include <cerrno>
#include <chrono>
#include <condition_variable>
#include <cstddef>
#include <cstdint>
#include <csignal>
#include <expected>
#include <mutex>
#include <utility>

#include <sys/prctl.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/seccomp.h>

#if defined(__x86_64__) || defined(_M_X64)
#include <immintrin.h>
#elif defined(__aarch64__)
#include <arm_neon.h>
#endif

namespace stack::host {

using namespace stack::governor;
using namespace stack::telemetry;

/**
 * CAPABILITY MASK: 256-bit Permission Vector
 *
 * Represents a set of capabilities as a 256-bit bitmask (four uint64_t values).
 * Each bit represents a capability the execution context can use.
 *
 * Used to verify that requested capabilities (in SIMDCapabilityToken) are a
 * subset of available capabilities (in CapabilityMask256).
 *
 * Validation uses SIMD: IsSubsetOf() tests (required AND NOT available) == 0.
 * SIMD implementations (AVX2 on x86_64, NEON on ARM64) check all 256 bits in
 * parallel. Fallback uses bitwise AND for unknown architectures.
 */
struct alignas(32) CapabilityMask256 {
    uint64_t data[4]{0, 0, 0, 0};

    constexpr CapabilityMask256() noexcept = default;
    constexpr CapabilityMask256(uint64_t m0, uint64_t m1, uint64_t m2, uint64_t m3) noexcept
        : data{m0, m1, m2, m3} {}

    // SIMD-Accelerated Bitwise Validation (Required <= Provided)
    [[nodiscard]] inline bool IsSubsetOf(const CapabilityMask256& provided) const noexcept {
#if defined(__AVX2__)
        __m256i req = _mm256_load_si256(reinterpret_cast<const __m256i*>(data));
        __m256i prov = _mm256_load_si256(reinterpret_cast<const __m256i*>(provided.data));
        
        // (req AND NOT prov) must yield 0
        __m256i test = _mm256_andnot_si256(prov, req);
        return _mm256_testz_si256(test, test) == 1;
#elif defined(__aarch64__)
        uint64x2_t req_lo = vld1q_u64(&data[0]);
        uint64x2_t req_hi = vld1q_u64(&data[2]);
        uint64x2_t prov_lo = vld1q_u64(&provided.data[0]);
        uint64x2_t prov_hi = vld1q_u64(&provided.data[2]);

        uint64x2_t test_lo = vbicq_u64(req_lo, prov_lo); // req AND NOT prov
        uint64x2_t test_hi = vbicq_u64(req_hi, prov_hi);

        uint64x2_t combined = vorrq_u64(test_lo, test_hi);
        return (vgetq_lane_u64(combined, 0) | vgetq_lane_u64(combined, 1)) == 0;
#else
        return ((data[0] & ~provided.data[0]) |
                (data[1] & ~provided.data[1]) |
                (data[2] & ~provided.data[2]) |
                (data[3] & ~provided.data[3])) == 0;
#endif
    }
};

/**
 * SIMD CAPABILITY TOKEN: the capabilities a transaction asks for.
 *
 * The token is a caller-supplied request descriptor, not a credential: the
 * host checks that the requested mask is a subset of the active mask, and
 * context_id is caller-asserted, used for rate limiting, debt and audit
 * attribution, with nothing here authenticating it.
 */
class SIMDCapabilityToken {
private:
    CapabilityMask256 required_capabilities_{};
    uint64_t context_id_{0};

public:
    constexpr SIMDCapabilityToken() noexcept = default;
    constexpr SIMDCapabilityToken(uint64_t context_id, const CapabilityMask256& required) noexcept
        : required_capabilities_(required), context_id_(context_id) {}

    [[nodiscard]] inline bool Validate(const CapabilityMask256& active_mask) const noexcept {
        return required_capabilities_.IsSubsetOf(active_mask);
    }

    [[nodiscard]] constexpr uint64_t GetContextId() const noexcept { return context_id_; }
};

/**
 * SECCOMP FILTER ENGINE: Kernel-Level Syscall Restriction Boundary
 *
 * LAYER 4 P1 CRITICAL FIX: Whitelist-based model (was blacklist).
 *
 * Installs a SECCOMP BPF filter (Berkeley Packet Filter) that runs in the
 * Linux kernel and restricts which syscalls Minotaur (the untrusted execution
 * engine) can invoke.
 *
 * DEFECT (Fixed): Previous filter was blacklist-based (allow all except specific
 * blocks). This is "too permissive" — it allows syscalls we don't need/want.
 *
 * NEW: Whitelist-based model. Explicitly allows ONLY these syscalls
 * (numbers shown are x86_64; the aarch64 table is in SeccompFilterEngine):
 *   - SYS_read (0): Read from file descriptors
 *   - SYS_write (1): Write to file descriptors
 *   - SYS_exit (60): Terminate the calling thread. A sealed thread must be
 *     able to exit; without this, glibc retries the denied call forever.
 *   - SYS_exit_group (231): Terminate execution
 *   - SYS_rt_sigaction (13): Register signal handlers (GOVERNOR_PREEMPT_SIG only)
 *   - SYS_clock_gettime (228): Query clock (for timing/metrics)
 *   - SYS_futex (202): Wait/wake (if payload uses atomics/mutexes)
 *   - SYS_timer_settime (223): Arm and disarm the thread's deadline timer. The
 *     timer is created before the filter is installed (timer_create is not
 *     allowed), but a sealed thread must still be able to arm it.
 *   - SYS_rt_sigreturn (15): Return from the deadline signal handler. The
 *     kernel issues this call from the signal trampoline when the handler
 *     returns; with it denied the return faults and the whole process dies
 *     with SIGSEGV on the first deadline expiry (D-01).
 *
 * NOT ISOLATION: this filter bounds what a payload on the sealed thread can
 * call; it does not bound how long the payload runs and it cannot stop it.
 * The deadline on this path is cooperative: its handler only sets a flag
 * that is read after the payload returns, and the allowlist above lets the
 * payload disarm that very deadline (timer_settime on the thread's timer) or
 * ignore its signal (rt_sigaction on GOVERNOR_PREEMPT_SIG). Both calls are
 * needed by the host itself and are not removed here. A payload that must be
 * stopped runs under stack::supervised::SupervisedExecutor
 * (stack_supervised_exec.hpp), which puts it in a child process the parent
 * can kill.
 *
 * All other syscalls return SECCOMP_RET_ERRNO (ENOSYS). This is safer:
 * if a payload tries ptrace, mmap, prctl, socket, etc., it gets ENOSYS
 * instead of succeeding. Minotaur is strictly contained to the arena and
 * I/O operations.
 *
 * Once installed, the filter cannot be removed or modified—only by the host
 * process with appropriate privileges. For Minotaur, once sealed, it is sealed.
 *
 * SCOPE: a filter attaches to the one thread that installs it (no
 * SECCOMP_FILTER_FLAG_TSYNC), so every thread that governs transactions
 * installs its own, exactly once. Applying it process wide was rejected: it
 * would also put this tiny allowlist on threads that never asked for it (an
 * allocator or runtime thread of a Rust caller needs mmap, openat and clone),
 * and it would not help the threads it reached, which could not call
 * timer_create to set up their deadline timers.
 */
enum class SeccompError : uint8_t {
    None = 0,
    SetNoNewPrivsFailed,
    FilterApplyFailed,
    UnsupportedArchitecture
};

class SeccompFilterEngine {
private:
    // LAYER 4 P1 FIX: Whitelist-based filter (explicit allow, default deny)
    // Syscall numbers are per architecture. x86_64 keeps its own table;
    // aarch64 uses the asm-generic table, where the x86_64 values name
    // io_setup, io_destroy, quotactl, munlockall, flistxattr, mlock and
    // accept instead. The static_asserts below hold every entry to the
    // libc's __NR_* value for the architecture being compiled, so a wrong
    // table is a compile error rather than ENOSYS on every read.
#if defined(__x86_64__) || defined(_M_X64)
    static constexpr long SYS_READ = 0;
    static constexpr long SYS_WRITE = 1;
    static constexpr long SYS_EXIT = 60;
    static constexpr long SYS_EXIT_GROUP = 231;
    static constexpr long SYS_RT_SIGACTION = 13;
    static constexpr long SYS_CLOCK_GETTIME = 228;
    static constexpr long SYS_FUTEX = 202;
    static constexpr long SYS_TIMER_SETTIME = 223;
    static constexpr long SYS_RT_SIGRETURN = 15;
#elif defined(__aarch64__)
    static constexpr long SYS_READ = 63;
    static constexpr long SYS_WRITE = 64;
    static constexpr long SYS_EXIT = 93;
    static constexpr long SYS_EXIT_GROUP = 94;
    static constexpr long SYS_RT_SIGACTION = 134;
    static constexpr long SYS_CLOCK_GETTIME = 113;
    static constexpr long SYS_FUTEX = 98;
    static constexpr long SYS_TIMER_SETTIME = 110;
    static constexpr long SYS_RT_SIGRETURN = 139;
#else
#error "SeccompFilterEngine: no syscall table for this architecture"
#endif
    static_assert(SYS_READ == __NR_read, "SYS_READ must equal __NR_read for this architecture");
    static_assert(SYS_WRITE == __NR_write, "SYS_WRITE must equal __NR_write for this architecture");
    static_assert(SYS_EXIT == __NR_exit, "SYS_EXIT must equal __NR_exit for this architecture");
    static_assert(SYS_EXIT_GROUP == __NR_exit_group, "SYS_EXIT_GROUP must equal __NR_exit_group for this architecture");
    static_assert(SYS_RT_SIGACTION == __NR_rt_sigaction, "SYS_RT_SIGACTION must equal __NR_rt_sigaction for this architecture");
    static_assert(SYS_CLOCK_GETTIME == __NR_clock_gettime, "SYS_CLOCK_GETTIME must equal __NR_clock_gettime for this architecture");
    static_assert(SYS_FUTEX == __NR_futex, "SYS_FUTEX must equal __NR_futex for this architecture");
    static_assert(SYS_TIMER_SETTIME == __NR_timer_settime, "SYS_TIMER_SETTIME must equal __NR_timer_settime for this architecture");
    static_assert(SYS_RT_SIGRETURN == __NR_rt_sigreturn, "SYS_RT_SIGRETURN must equal __NR_rt_sigreturn for this architecture");

    // Set only after the filter is installed on this thread. Per thread and not
    // per host: the filter is, and a second install would be denied by it.
    static inline thread_local bool installed_on_this_thread_ = false;

public:
    [[nodiscard]] static bool IsInstalledOnThisThread() noexcept {
        return installed_on_this_thread_;
    }

    [[nodiscard]] static std::expected<void, SeccompError> InstallFilter() noexcept {
        if (installed_on_this_thread_) [[unlikely]] {
            return {};
        }
        if (::prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0) [[unlikely]] {
            return std::unexpected(SeccompError::SetNoNewPrivsFailed);
        }

#if defined(__x86_64__) || defined(_M_X64)
        constexpr uint32_t NATIVE_AUDIT_ARCH = AUDIT_ARCH_X86_64;
#elif defined(__aarch64__)
        constexpr uint32_t NATIVE_AUDIT_ARCH = AUDIT_ARCH_AARCH64;
#else
        return std::unexpected(SeccompError::UnsupportedArchitecture);
#endif

        const struct sock_filter filter[] = {
            // [0-2] Validate Arch (deny if wrong architecture)
            BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, arch)),
            BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, NATIVE_AUDIT_ARCH, 1, 0),
            BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS),

            // [3] Load Syscall Number
            BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr)),

            // [4-12] Whitelist explicit allowed syscalls (jump-on-match to allow at [17])
            BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_READ, 12, 0),
            BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_WRITE, 11, 0),
            BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_EXIT_GROUP, 10, 0),
            BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_CLOCK_GETTIME, 9, 0),
            BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_FUTEX, 8, 0),
            BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_EXIT, 7, 0),
            BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_TIMER_SETTIME, 6, 0),
            BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_RT_SIGRETURN, 5, 0),
            BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_RT_SIGACTION, 1, 0),

            // [13] Default deny (not in whitelist)
            BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | (ENOSYS & SECCOMP_RET_DATA)),

            // [14] SYS_rt_sigaction special case (check for GOVERNOR_PREEMPT_SIG)
            BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, args[0])),
            BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, static_cast<uint32_t>(GOVERNOR_PREEMPT_SIG), 1, 0),

            // [16] SYS_rt_sigaction deny (not for GOVERNOR_PREEMPT_SIG)
            BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | (EPERM & SECCOMP_RET_DATA)),

            // [17] All whitelisted calls: allow
            BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
        };

        const struct sock_fprog prog = {
            .len = static_cast<unsigned short>(sizeof(filter) / sizeof(filter[0])),
            .filter = const_cast<struct sock_filter*>(filter),
        };

        if (::prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog, 0, 0) != 0) [[unlikely]] {
            return std::unexpected(SeccompError::FilterApplyFailed);
        }

        installed_on_this_thread_ = true;
        return {};
    }
};

// ============================================================================
// COMPONENT 12: GOVERNED MINOTAUR HOST BOUNDARY EXECUTOR
// ============================================================================
enum class HostExecutionError : uint8_t {
    None = 0,
    SeccompInitializationFailed,
    SignalHandlerRegistrationFailed,
    TimerInitializationFailed,
    RateLimitExceeded,
    PreemptionTriggered,
    DeadlineExceeded,
    CapabilityValidationFailed,
    DebtCeilingExceeded,
    // hard_timeout_nanoseconds was 0. A zero budget used to arm nothing and
    // run the payload with no deadline at all (D-03); it is now refused
    // before the thread is sealed and before any token is consumed.
    InvalidHardTimeout,
    // timer_settime failed on an already created timer. Distinct from
    // TimerInitializationFailed (timer_create). The payload does not run.
    TimerArmFailed,
    // A capability change (a revocation, typically) is waiting for the
    // transactions in flight to drain and new transactions are held out
    // until it has applied or given up (I-04, R2-K-07). Fail closed: nothing
    // ran, no token was consumed, nothing was charged. Retry.
    CapabilityChangePending
};

template <
    uint32_t MaxCapacity = 1000,
    uint32_t ReservedTokens = 100,
    uint32_t MaxBurstTokens = 100,
    uint64_t TicksPerToken = 10'000,
    std::size_t MaxDomains = 256
>
class GovernedMinotaurHost {
private:
    KineticGovernor<MaxCapacity, ReservedTokens, MaxBurstTokens, TicksPerToken, MaxDomains> governor_{};
    ComputeDebtTracker<MaxDomains> debt_tracker_{};
    CapabilityMask256 active_host_capabilities_{};
    std::atomic<uint32_t> transactions_in_flight_{0};  // Lifecycle guard
    // Capability changes waiting for the in-flight transactions to drain
    // (I-04). Written under capability_lock_; read lock free by the
    // transaction guard, which notifies only when it is not zero.
    std::atomic<uint32_t> pending_capability_changes_{0};
    std::condition_variable capability_drained_{};
    mutable std::mutex initialization_lock_{};  // Serializes InitializeAndSeal()
    mutable std::mutex capability_lock_{};  // Protects active_host_capabilities_
    SeccompAuditRing<8192> audit_ring_{};  // Layer 5: Governance audit trail (DEFECT #1 FIX)

public:
    GovernedMinotaurHost() noexcept = default;

    /**
     * Construct with a run-time refill rate for the governor, in HardwareClock
     * ticks per token (I-01). The tick counter's frequency is a run-time
     * property of the machine, so a host that wants "N tokens per second"
     * measures the counter against a wall clock and passes frequency / N here.
     */
    explicit GovernedMinotaurHost(uint64_t governor_ticks_per_token) noexcept
        : governor_(governor_ticks_per_token) {}

    /**
     * Read access to the governance audit trail, so a caller or a test can
     * check which events a transaction recorded (I-01: a failed transaction
     * must leave no TransactionCompleted record).
     */
    [[nodiscard]] const SeccompAuditRing<8192>& AuditRing() const noexcept { return audit_ring_; }

    /**
     * The per-domain compute debt (I-03). The non-const accessor is for an
     * administrator that forgives or preloads debt; transactions charge it
     * themselves through ExecuteGovernedTransaction.
     */
    [[nodiscard]] ComputeDebtTracker<MaxDomains>& DebtTracker() noexcept { return debt_tracker_; }
    [[nodiscard]] const ComputeDebtTracker<MaxDomains>& DebtTracker() const noexcept { return debt_tracker_; }

    /**
     * Set active capability mask. Guarded against mid-transaction changes.
     * Returns false if transaction is in flight, preventing capability mutation.
     *
     * Try once: this is the original behaviour and it is unchanged. Under a
     * steady stream of transactions some transaction is always in flight, so
     * a caller that retries this can wait forever (R2-K-07). A caller that
     * must make a change, a revocation above all, uses
     * SetActiveCapabilitiesWithin().
     *
     * Thread safety: Acquires capability_lock_ to ensure atomicity with
     * concurrent reads in ExecuteGovernedTransaction(). The in-flight check
     * runs under that lock, and ExecuteGovernedTransaction() raises the
     * counter under the same lock as its snapshot, so a transaction cannot
     * start between this check and the write.
     */
    [[nodiscard]] bool SetActiveCapabilities(const CapabilityMask256& mask) noexcept {
        std::lock_guard<std::mutex> lock(capability_lock_);
        if (transactions_in_flight_.load(std::memory_order_acquire) > 0) {
            return false;  // Transaction in flight; cannot change capabilities
        }
        active_host_capabilities_ = mask;
        return true;
    }

    /**
     * Set the active capability mask, waiting up to `max_wait` for the
     * transactions in flight to drain (I-04, R2-K-07).
     *
     * While this call waits, the change is pending and NEW transactions are
     * refused with CapabilityChangePending (fail closed: they do not wait,
     * nothing runs, nothing is charged). Only transactions that were already
     * in flight can still be running, so the set can only shrink and the
     * change applies as soon as the last of them returns. It applies only
     * with none in flight, so no transaction is ever running across it.
     *
     * Returns true when the mask was applied. After a true return, no
     * transaction runs with the old mask. Returns false when the in-flight
     * transactions did not drain within `max_wait` (a payload that does not
     * return holds them; the deadline is cooperative): the mask is NOT
     * applied, no change is left pending, and the host serves under the old
     * mask again. The caller owns the decision to retry or to escalate.
     * A `max_wait` of zero or less is try-once, the same as
     * SetActiveCapabilities(), and never holds new transactions out.
     *
     * Several waiting changes are allowed. New transactions stay refused
     * while any of them is waiting, and each applies when it sees the host
     * drained, in the order the lock is won, so the last to apply is the mask
     * that stays. A change that times out leaves the others waiting.
     *
     * Do not call this from inside a payload: the calling transaction is
     * itself in flight, so the wait cannot succeed and runs to its bound.
     */
    [[nodiscard]] bool SetActiveCapabilitiesWithin(const CapabilityMask256& mask,
                                                   std::chrono::nanoseconds max_wait) noexcept {
        std::unique_lock<std::mutex> lock(capability_lock_);
        if (transactions_in_flight_.load(std::memory_order_seq_cst) == 0) {
            active_host_capabilities_ = mask;
            return true;
        }
        if (max_wait <= std::chrono::nanoseconds::zero()) {
            return false;
        }
        pending_capability_changes_.fetch_add(1, std::memory_order_seq_cst);
        const bool drained = capability_drained_.wait_for(lock, max_wait, [this] {
            return transactions_in_flight_.load(std::memory_order_seq_cst) == 0;
        });
        pending_capability_changes_.fetch_sub(1, std::memory_order_seq_cst);
        if (drained) {
            active_host_capabilities_ = mask;
        }
        return drained;
    }

    /** Number of capability changes currently waiting for in-flight transactions to drain. */
    [[nodiscard]] uint32_t PendingCapabilityChanges() const noexcept {
        return pending_capability_changes_.load(std::memory_order_acquire);
    }

    [[nodiscard]] std::expected<void, HostExecutionError> InitializeAndSeal() noexcept {
        // Fast path: this thread already carries the filter. The state is per
        // thread, so another thread having sealed says nothing about this one.
        if (SeccompFilterEngine::IsInstalledOnThisThread()) [[likely]] {
            return {};
        }

        // Slow path: acquire lock for initialization
        std::lock_guard<std::mutex> lock(initialization_lock_);

        if (!HardenedPosixPreemptionGuard::RegisterSignalHandler().has_value()) [[unlikely]] {
            return std::unexpected(HostExecutionError::SignalHandlerRegistrationFailed);
        }

        if (!HardenedPosixPreemptionGuard::InitializeThreadTimer().has_value()) [[unlikely]] {
            return std::unexpected(HostExecutionError::TimerInitializationFailed);
        }

        // The timer above must exist first: timer_create is not on the allowlist.
        // A failed install returns an error and leaves this thread unsealed.
        if (!SeccompFilterEngine::InstallFilter().has_value()) [[unlikely]] {
            return std::unexpected(HostExecutionError::SeccompInitializationFailed);
        }

        return {};
    }

    template <typename ExecutionPayload>
    [[nodiscard]] std::expected<void, HostExecutionError> ExecuteGovernedTransaction(
        const SIMDCapabilityToken& token,
        uint32_t required_tokens,
        uint64_t deadline_budget_ticks,
        uint64_t hard_timeout_nanoseconds,
        ExecutionPayload&& payload) noexcept
    {
        // COOPERATIVE DEADLINE ONLY. The hard timeout below is a CPU-time
        // timer whose handler sets a flag that is read after the payload
        // returns. It does not stop the payload: a payload that never
        // returns is never stopped, a payload blocked in read() consumes no
        // CPU time and never trips it, and the sealed thread's allowlist
        // lets the payload disarm the timer (timer_settime) or ignore its
        // signal (rt_sigaction on GOVERNOR_PREEMPT_SIG). This path is not
        // isolation. Use stack::supervised::SupervisedExecutor for a payload
        // that must be stopped at a deadline.
        if (hard_timeout_nanoseconds == 0) [[unlikely]] {
            return std::unexpected(HostExecutionError::InvalidHardTimeout);
        }

        if (!SeccompFilterEngine::IsInstalledOnThisThread()) [[unlikely]] {
            auto init_res = InitializeAndSeal();
            if (!init_res.has_value()) return std::unexpected(init_res.error());
        }

        // Snapshot active capabilities to prevent torn reads during concurrent mutations.
        // Lifecycle guard: mark the transaction in flight under the same lock, so
        // SetActiveCapabilities() (which checks the counter under capability_lock_)
        // sees either the old counter and no snapshot yet, or the raised counter.
        //
        // A pending capability change (I-04) holds new transactions out here,
        // before anything is consumed: the in-flight set can then only shrink,
        // so the change is guaranteed to apply once it drains.
        CapabilityMask256 snapshot_capabilities{};
        {
            std::lock_guard<std::mutex> lock(capability_lock_);
            if (pending_capability_changes_.load(std::memory_order_seq_cst) > 0) [[unlikely]] {
                return std::unexpected(HostExecutionError::CapabilityChangePending);
            }
            snapshot_capabilities = active_host_capabilities_;
            transactions_in_flight_.fetch_add(1, std::memory_order_release);
        }

        // RAII cleanup: decrement on exit (pairs with the fetch_add above on every path)
        // When a capability change is waiting (I-04), wake it. The decrement
        // comes first and the waiter tests the counter under capability_lock_,
        // so taking that lock before notifying cannot lose the wake-up.
        struct TransactionGuard {
            std::atomic<uint32_t>& counter;
            const std::atomic<uint32_t>& pending;
            std::mutex& lock;
            std::condition_variable& drained;
            ~TransactionGuard() noexcept {
                counter.fetch_sub(1, std::memory_order_seq_cst);
                if (pending.load(std::memory_order_seq_cst) != 0) [[unlikely]] {
                    std::lock_guard<std::mutex> lk(lock);
                    drained.notify_all();
                }
            }
        } lifecycle_guard{transactions_in_flight_, pending_capability_changes_, capability_lock_,
                          capability_drained_};

        // Extract domain ID early for audit logging
        const uint64_t domain_id = token.GetContextId();

        // Component 13 Check: SIMD Capability Verification (against snapshot)
        if (!token.Validate(snapshot_capabilities)) [[unlikely]] {
            // LAYER 5 FIX: Record capability violation event
            audit_ring_.Push(AuditEventType::CapabilityViolation, domain_id, 0);
            return std::unexpected(HostExecutionError::CapabilityValidationFailed);
        }
        const uint64_t start_tick = HardwareClock::ReadTicks();

        // Component 2-5 Check: Kinetic Governor
        // LAYER 7 FIX: Consume now reads clock internally (removed caller-supplied time parameter)
        // P3.1 FIX: Consume now accepts domain_id for per-domain rate limiting
        // R2-K-20: a request must consume at least one token. A zero-token
        // request passes the governor's floor check for free ("available >=
        // Reserved + 0" is always true), so it would run without limit.
        if (required_tokens == 0) [[unlikely]] {
            audit_ring_.Push(AuditEventType::RateLimitTriggered, domain_id, 0);
            return std::unexpected(HostExecutionError::RateLimitExceeded);
        }
        auto consume_res = governor_.Consume(domain_id, required_tokens, PriorityClass::Standard);
        if (!consume_res.has_value()) [[unlikely]] {
            // LAYER 5 FIX: Record rate limit event
            audit_ring_.Push(AuditEventType::RateLimitTriggered, domain_id, required_tokens);
            return std::unexpected(HostExecutionError::RateLimitExceeded);
        }

        TransactionRollbackGuard guard(
            governor_, debt_tracker_, domain_id, start_tick, 0, required_tokens);

        // Component 10 Check: Persistent POSIX Timer. Fails closed: an arm
        // failure returns before the payload runs and the rollback guard
        // refunds the tokens. The guard's own reason tells timer_create
        // (resource_unavailable_try_again) from timer_settime (invalid_argument).
        HardenedPosixPreemptionGuard timer_guard;
        if (auto arm_res = timer_guard.Arm(hard_timeout_nanoseconds); !arm_res.has_value()) [[unlikely]] {
            return std::unexpected(arm_res.error() == std::errc::invalid_argument
                                       ? HostExecutionError::TimerArmFailed
                                       : HostExecutionError::TimerInitializationFailed);
        }

        // LAYER 8 FIX: Re-validate capabilities before payload execution
        // Between snapshot and execution, the host may have revoked capabilities.
        // Re-check under lock to ensure Minotaur still has required permissions.
        {
            std::lock_guard<std::mutex> lock(capability_lock_);
            if (!token.Validate(active_host_capabilities_)) [[unlikely]] {
                // LAYER 5 FIX: Record capability violation event
                audit_ring_.Push(AuditEventType::CapabilityViolation, domain_id, 0);
                return std::unexpected(HostExecutionError::CapabilityValidationFailed);
            }
        }

        // Component 6 Check: Software Deadline Scope
        bool software_overrun = false;
        {
            ExecutionDeadlineScope deadline_scope(deadline_budget_ticks, &software_overrun);
            payload();
        }

        const uint64_t elapsed_ticks = HardwareClock::ReadTicks() - start_tick;

        // ACCOUNTING RULE (I-03, R2-K-05/06). Everything above this line
        // that returned did so before the payload ran, and the rollback
        // guard refunded its tokens: a rejected transaction costs nothing.
        // From here on the payload has run, so its tokens are spent whatever
        // the outcome, and its CPU ticks are charged as debt, an overrun
        // included. The charge is best effort against the ceiling: when it
        // does not fit, the debt stays where it is and nothing is refunded.
        // Before this, an overrun or preempted payload was refunded in full,
        // and a payload that hit the ceiling had the ticks AccrueDebt had
        // just refused refunded through the guard, so the debt went down.
        guard.Commit();
        const bool debt_charged = debt_tracker_.AccrueDebt(domain_id, elapsed_ticks).has_value();

        if (timer_guard.WasPreempted()) [[unlikely]] {
            // LAYER 5 FIX: Record hardware timer preemption event
            audit_ring_.Push(AuditEventType::HardwareTimerPreempted, domain_id, required_tokens);
            return std::unexpected(HostExecutionError::PreemptionTriggered);
        }

        if (software_overrun) [[unlikely]] {
            // LAYER 5 FIX: Record software deadline exceeded event
            audit_ring_.Push(AuditEventType::SoftwareDeadlineExceeded, domain_id, required_tokens);
            return std::unexpected(HostExecutionError::DeadlineExceeded);
        }

        // Component 8-9 Check: Compute Debt
        if (!debt_charged) [[unlikely]] {
            // LAYER 5 FIX: Record debt ceiling exceeded event
            audit_ring_.Push(AuditEventType::RateLimitTriggered, domain_id, required_tokens);
            return std::unexpected(HostExecutionError::DebtCeilingExceeded);
        }

        // LAYER 5 FIX: Record successful transaction completion
        audit_ring_.Push(AuditEventType::TransactionCompleted, domain_id, required_tokens);
        return {};
    }

    /**
     * How a supervised run (see ExecuteGovernedSupervised) ended, as far as the
     * host's audit trail and accounting are concerned.
     */
    enum class SupervisedRunResult : uint8_t {
        Completed,               // worker exited 0 in time with a well-formed frame
        TimedOut,                // wall-clock deadline passed; worker killed
        Failed,                  // spawned, ended any other way
        TerminationUnconfirmed,  // killed, not reaped in time; may still be running
        NotSpawned               // refused or failed before any process existed
    };

    /**
     * Governance before spawn for a supervised worker run (RACE-02, R2-K-13).
     *
     * The same checks as ExecuteGovernedTransaction, in the same order, and
     * BEFORE `run` is called, so a refused request spawns nothing:
     *   1. wall_clock_deadline_ns == 0: InvalidHardTimeout (nothing consumed);
     *   2. a pending capability change: CapabilityChangePending (nothing consumed);
     *   3. the token's capabilities against the active mask: CapabilityValidationFailed
     *      (CapabilityViolation audit event, nothing consumed);
     *   4. the domain's token bucket: RateLimitExceeded (RateLimitTriggered audit event);
     *   5. the capabilities again under the lock, after the tokens were taken
     *      (a revocation in between refunds them).
     * While `run` executes the transaction counts as in flight, so a capability
     * change waits for it exactly as for a governed transaction.
     *
     * `run` spawns and supervises the worker and says how it ended. Tokens
     * are spent when something was spawned and refunded when it was not
     * (SupervisedRunResult::NotSpawned). One audit event records the outcome,
     * timeouts included. Compute debt is not charged on this path.
     *
     * No seal is needed and none may be present: a sealed thread's filter
     * forbids fork and exec, so `run` would fail to spawn (NotSpawned).
     */
    template <typename SupervisedRun>
    [[nodiscard]] std::expected<void, HostExecutionError> ExecuteGovernedSupervised(
        const SIMDCapabilityToken& token,
        uint32_t required_tokens,
        uint64_t wall_clock_deadline_ns,
        SupervisedRun&& run) noexcept
    {
        if (wall_clock_deadline_ns == 0) [[unlikely]] {
            return std::unexpected(HostExecutionError::InvalidHardTimeout);
        }

        CapabilityMask256 snapshot_capabilities{};
        {
            std::lock_guard<std::mutex> lock(capability_lock_);
            if (pending_capability_changes_.load(std::memory_order_seq_cst) > 0) [[unlikely]] {
                return std::unexpected(HostExecutionError::CapabilityChangePending);
            }
            snapshot_capabilities = active_host_capabilities_;
            transactions_in_flight_.fetch_add(1, std::memory_order_release);
        }
        struct TransactionGuard {
            std::atomic<uint32_t>& counter;
            const std::atomic<uint32_t>& pending;
            std::mutex& lock;
            std::condition_variable& drained;
            ~TransactionGuard() noexcept {
                counter.fetch_sub(1, std::memory_order_seq_cst);
                if (pending.load(std::memory_order_seq_cst) != 0) [[unlikely]] {
                    std::lock_guard<std::mutex> lk(lock);
                    drained.notify_all();
                }
            }
        } lifecycle_guard{transactions_in_flight_, pending_capability_changes_, capability_lock_,
                          capability_drained_};

        const uint64_t domain_id = token.GetContextId();
        if (!token.Validate(snapshot_capabilities)) [[unlikely]] {
            audit_ring_.Push(AuditEventType::CapabilityViolation, domain_id, 0);
            return std::unexpected(HostExecutionError::CapabilityValidationFailed);
        }
        // R2-K-20: a request must consume at least one token. A zero-token
        // request passes the governor's floor check for free ("available >=
        // Reserved + 0" is always true), so it would run without limit.
        if (required_tokens == 0) [[unlikely]] {
            audit_ring_.Push(AuditEventType::RateLimitTriggered, domain_id, 0);
            return std::unexpected(HostExecutionError::RateLimitExceeded);
        }
        auto consume_res = governor_.Consume(domain_id, required_tokens, PriorityClass::Standard);
        if (!consume_res.has_value()) [[unlikely]] {
            audit_ring_.Push(AuditEventType::RateLimitTriggered, domain_id, required_tokens);
            return std::unexpected(HostExecutionError::RateLimitExceeded);
        }
        TransactionRollbackGuard guard(governor_, debt_tracker_, domain_id, 0, 0, required_tokens);
        {
            std::lock_guard<std::mutex> lock(capability_lock_);
            if (!token.Validate(active_host_capabilities_)) [[unlikely]] {
                audit_ring_.Push(AuditEventType::CapabilityViolation, domain_id, 0);
                return std::unexpected(HostExecutionError::CapabilityValidationFailed);
            }
        }

        const SupervisedRunResult result = run();
        switch (result) {
        case SupervisedRunResult::NotSpawned:
            // Nothing existed to spend the tokens on: the guard refunds them.
            audit_ring_.Push(AuditEventType::SupervisedFailed, domain_id, 0);
            return {};
        case SupervisedRunResult::Completed:
            guard.Commit();
            audit_ring_.Push(AuditEventType::SupervisedCompleted, domain_id, required_tokens);
            return {};
        case SupervisedRunResult::TimedOut:
            guard.Commit();
            audit_ring_.Push(AuditEventType::SupervisedTimedOut, domain_id, required_tokens);
            return {};
        case SupervisedRunResult::TerminationUnconfirmed:
            guard.Commit();
            audit_ring_.Push(AuditEventType::SupervisedTerminationUnconfirmed, domain_id, required_tokens);
            return {};
        case SupervisedRunResult::Failed:
            break;
        }
        guard.Commit();
        audit_ring_.Push(AuditEventType::SupervisedFailed, domain_id, required_tokens);
        return {};
    }
};

} // namespace stack::host
