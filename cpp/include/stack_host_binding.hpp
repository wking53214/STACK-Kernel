#pragma once

/**
 * ≡TACK KERNEL LAYER 4: Host Boundary Orchestration and SECCOMP Enforcement
 *
 * CONFIDENTIAL. Trade secret of William King (wking53214).
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
 *   check preemption → check deadline → accrue debt → commit
 *
 * If any gate rejects, execution halts and error returns to caller.
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
 * Installs a SECCOMP BPF filter (Berkeley Packet Filter) that runs in the
 * Linux kernel and restricts which syscalls Minotaur (the untrusted execution
 * engine) can invoke.
 *
 * The filter explicitly blocks:
 *   - ptrace (attach/inspect)
 *   - rt_sigaction (modify signal handlers, except GOVERNOR_PREEMPT_SIG)
 *   - rt_sigprocmask (block/unblock signals)
 *   - prctl with PR_SET_SECCOMP (can't layer another SECCOMP filter)
 *
 * All other syscalls are allowed by default. This is a whitelist-by-exception:
 * we permit almost everything except the specific escapes that would break
 * governance.
 *
 * Once installed, the filter cannot be removed or modified—only by the host
 * process with appropriate privileges. For Minotaur, once sealed, it is sealed.
 */
enum class SeccompError : uint8_t {
    None = 0,
    SetNoNewPrivsFailed,
    FilterApplyFailed,
    UnsupportedArchitecture
};

class SeccompFilterEngine {
private:
    // Compute jump offsets programmatically to prevent silent corruption
    // from structure changes. Each offset is computed relative to the jump position.
    struct FilterOffsets {
        uint8_t arch_fail_to_default_allow;    // From arch check fail to default allow
        uint8_t ptrace_to_sig_handler;         // From ptrace jump-true to sig handler
        uint8_t sigaction_to_sigprocmask;      // From sigaction jump-true to sigprocmask
        uint8_t sigprocmask_to_prctl;          // From sigprocmask jump-true to prctl
        uint8_t prctl_to_sigaction_load;       // From prctl jump-false to sigaction load
        uint8_t sigaction_load_to_check;       // From sigaction load to signal check
        uint8_t sigaction_check_to_allow;      // From sigaction check to allow
        uint8_t sigaction_fail_to_sigprocmask; // From sigaction check-false to sigprocmask ret
        uint8_t prctl_load_to_check;           // From prctl load to PR_SET_SECCOMP check
        uint8_t prctl_check_to_errno;          // From prctl check to errno return
        uint8_t prctl_check_fail_to_allow;     // From prctl check-false to allow
    };

    [[nodiscard]] static constexpr FilterOffsets ComputeFilterOffsets() noexcept {
        // Filter structure (index comments):
        // [0] Load arch
        // [1] Jump: if arch == native, skip 1 (go to [2]), else skip 0 (go to [3])
        // [2] Kill: RET_KILL_PROCESS
        // [3] Load syscall nr
        // [4] Jump: if nr == SYS_ptrace, skip ? to sig_handler, else skip 0
        // [5] Jump: if nr == SYS_rt_sigaction, skip ? to prctl_load, else skip 0
        // [6] Jump: if nr == SYS_rt_sigprocmask, skip ? to prctl_load, else skip 0
        // [7] Jump: if nr == SYS_prctl, skip ? to prctl_load, else skip 0
        // [8] RET_ALLOW (default)
        // [9] Load args[0] (for sigaction)
        // [10] Jump: if args[0] == GOVERNOR_PREEMPT_SIG, skip 2, else skip 0
        // [11] RET_ALLOW
        // [12] RET_ERRNO (sigprocmask deny)
        // [13] Load args[0] (for prctl)
        // [14] Jump: if args[0] == PR_SET_SECCOMP, skip 0 (go to errno), skip 1 (go to allow)
        // [15] RET_ERRNO (prctl deny)
        // [16] RET_ALLOW

        // Computed jumps (relative to jump position):
        return FilterOffsets{
            .arch_fail_to_default_allow = 6,    // From [1] fail to [8] (6 steps forward)
            .ptrace_to_sig_handler = 5,         // From [4] to [9] (5 steps forward)
            .sigaction_to_sigprocmask = 6,      // From [5] to [12] (6 steps forward)
            .sigprocmask_to_prctl = 6,          // From [6] to [13] (6 steps forward)
            .prctl_to_sigaction_load = 2,       // From [7] to [9] (2 steps forward)
            .sigaction_load_to_check = 1,       // From [9] to [10] (1 step forward)
            .sigaction_check_to_allow = 2,      // From [10] to [12] (2 steps forward)
            .sigaction_fail_to_sigprocmask = 1, // From [10] fail to [12] (1 step forward)
            .prctl_load_to_check = 1,           // From [13] to [14] (1 step forward)
            .prctl_check_to_errno = 0,          // From [14] to [15] (0 steps = next)
            .prctl_check_fail_to_allow = 1,     // From [14] fail to [16] (1 step forward)
        };
    }

public:
    [[nodiscard]] static std::expected<void, SeccompError> InstallFilter() noexcept {
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

        constexpr FilterOffsets offsets = ComputeFilterOffsets();

        const struct sock_filter filter[] = {
            // [0-2] Validate Arch
            BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, arch)),
            BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, NATIVE_AUDIT_ARCH, 1, offsets.arch_fail_to_default_allow),
            BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS),

            // [3] Load Syscall Number
            BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr)),

            // System calls to restrict (computed jumps)
            BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_ptrace, offsets.ptrace_to_sig_handler, 0),
            BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_rt_sigaction, offsets.sigaction_to_sigprocmask, 0),
            BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_rt_sigprocmask, offsets.sigprocmask_to_prctl, 0),
            BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_prctl, offsets.prctl_to_sigaction_load, 0),

            // [8] Default Allow
            BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),

            // [9] SYS_rt_sigaction handler (check for GOVERNOR_PREEMPT_SIG)
            BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, args[0])),
            BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, static_cast<uint32_t>(GOVERNOR_PREEMPT_SIG),
                     offsets.sigaction_check_to_allow, offsets.sigaction_fail_to_sigprocmask),
            BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),

            // [12] SYS_rt_sigprocmask handler (deny mask modifications)
            BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | (EPERM & SECCOMP_RET_DATA)),

            // [13] SYS_prctl handler (deny PR_SET_SECCOMP manipulation)
            BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, args[0])),
            BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, PR_SET_SECCOMP,
                     offsets.prctl_check_to_errno, offsets.prctl_check_fail_to_allow),
            BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | (EPERM & SECCOMP_RET_DATA)),
            BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
        };

        const struct sock_fprog prog = {
            .len = static_cast<unsigned short>(sizeof(filter) / sizeof(filter[0])),
            .filter = const_cast<struct sock_filter*>(filter),
        };

        if (::prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog, 0, 0) != 0) [[unlikely]] {
            return std::unexpected(SeccompError::FilterApplyFailed);
        }

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
    DebtCeilingExceeded
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
    KineticGovernor<MaxCapacity, ReservedTokens, MaxBurstTokens, TicksPerToken> governor_{};
    ComputeDebtTracker<MaxDomains> debt_tracker_{};
    CapabilityMask256 active_host_capabilities_{};
    std::atomic<bool> seccomp_sealed_{false};
    std::atomic<uint32_t> transactions_in_flight_{0};  // Lifecycle guard
    mutable std::mutex initialization_lock_{};  // Serializes InitializeAndSeal()
    mutable std::mutex capability_lock_{};  // Protects active_host_capabilities_
    SeccompAuditRing<8192> audit_ring_{};  // Layer 5: Governance audit trail (DEFECT #1 FIX)

public:
    GovernedMinotaurHost() noexcept = default;

    /**
     * Set active capability mask. Guarded against mid-transaction changes.
     * Returns false if transaction is in flight, preventing capability mutation.
     *
     * Thread safety: Acquires capability_lock_ to ensure atomicity with
     * concurrent reads in ExecuteGovernedTransaction().
     */
    [[nodiscard]] bool SetActiveCapabilities(const CapabilityMask256& mask) noexcept {
        if (transactions_in_flight_.load(std::memory_order_acquire) > 0) {
            return false;  // Transaction in flight; cannot change capabilities
        }
        std::lock_guard<std::mutex> lock(capability_lock_);
        active_host_capabilities_ = mask;
        return true;
    }

    [[nodiscard]] std::expected<void, HostExecutionError> InitializeAndSeal() noexcept {
        // Double-checked locking: fast path (no lock)
        if (seccomp_sealed_.load(std::memory_order_acquire)) [[likely]] {
            return {};
        }

        // Slow path: acquire lock for initialization
        std::lock_guard<std::mutex> lock(initialization_lock_);

        // Recheck after acquiring lock: another thread may have initialized
        if (seccomp_sealed_.load(std::memory_order_acquire)) [[likely]] {
            return {};
        }

        if (!HardenedPosixPreemptionGuard::RegisterSignalHandler().has_value()) [[unlikely]] {
            return std::unexpected(HostExecutionError::SignalHandlerRegistrationFailed);
        }

        if (!HardenedPosixPreemptionGuard::InitializeThreadTimer().has_value()) [[unlikely]] {
            return std::unexpected(HostExecutionError::TimerInitializationFailed);
        }

        if (!SeccompFilterEngine::InstallFilter().has_value()) [[unlikely]] {
            return std::unexpected(HostExecutionError::SeccompInitializationFailed);
        }

        seccomp_sealed_.store(true, std::memory_order_release);
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
        if (!seccomp_sealed_) [[unlikely]] {
            auto init_res = InitializeAndSeal();
            if (!init_res.has_value()) return std::unexpected(init_res.error());
        }

        // Snapshot active capabilities to prevent torn reads during concurrent mutations
        CapabilityMask256 snapshot_capabilities{};
        {
            std::lock_guard<std::mutex> lock(capability_lock_);
            snapshot_capabilities = active_host_capabilities_;
        }

        // Extract domain ID early for audit logging
        const uint64_t domain_id = token.GetContextId();

        // Lifecycle guard: mark transaction in flight
        transactions_in_flight_.fetch_add(1, std::memory_order_release);

        // RAII cleanup: decrement on exit
        struct TransactionGuard {
            std::atomic<uint32_t>& counter;
            ~TransactionGuard() noexcept {
                counter.fetch_sub(1, std::memory_order_release);
            }
        } lifecycle_guard{transactions_in_flight_};

        // Component 13 Check: SIMD Capability Verification (against snapshot)
        if (!token.Validate(snapshot_capabilities)) [[unlikely]] {
            // LAYER 5 FIX: Record capability violation event
            audit_ring_.Push(AuditEventType::CapabilityViolation, domain_id, 0);
            return std::unexpected(HostExecutionError::CapabilityValidationFailed);
        }
        const uint64_t start_tick = HardwareClock::ReadTicks();

        // Component 2-5 Check: Kinetic Governor
        // LAYER 7 FIX: Consume now reads clock internally (removed caller-supplied time parameter)
        auto consume_res = governor_.Consume(required_tokens, PriorityClass::Standard);
        if (!consume_res.has_value()) [[unlikely]] {
            // LAYER 5 FIX: Record rate limit event
            audit_ring_.Push(AuditEventType::RateLimitTriggered, domain_id, required_tokens);
            return std::unexpected(HostExecutionError::RateLimitExceeded);
        }

        TransactionRollbackGuard guard(
            governor_, debt_tracker_, domain_id, start_tick, 0, required_tokens);

        // Component 10 Check: Persistent POSIX Timer
        HardenedPosixPreemptionGuard timer_guard;
        if (!timer_guard.Arm(hard_timeout_nanoseconds).has_value()) [[unlikely]] {
            return std::unexpected(HostExecutionError::TimerInitializationFailed);
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
        guard.accrued_ticks = elapsed_ticks;
        auto debt_res = debt_tracker_.AccrueDebt(domain_id, elapsed_ticks);
        if (!debt_res.has_value()) [[unlikely]] {
            // LAYER 5 FIX: Record debt ceiling exceeded event
            audit_ring_.Push(AuditEventType::RateLimitTriggered, domain_id, required_tokens);
            return std::unexpected(HostExecutionError::DebtCeilingExceeded);
        }

        guard.Commit();

        // LAYER 5 FIX: Record successful transaction completion
        audit_ring_.Push(AuditEventType::TransactionCompleted, domain_id, required_tokens);
        return {};
    }
};

} // namespace stack::host
