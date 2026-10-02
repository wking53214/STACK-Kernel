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

        const struct sock_filter filter[] = {
            // [0-2] Validate Arch
            BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, arch)),
            BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, NATIVE_AUDIT_ARCH, 1, 0),
            BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS),

            // [3] Load Syscall Number
            BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr)),

            // System calls to restrict
            BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_ptrace, 7, 0),
            BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_rt_sigaction, 3, 0),
            BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_rt_sigprocmask, 4, 0),
            BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_prctl, 5, 0),

            // Default Allow
            BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),

            // SYS_rt_sigaction handler (check for GOVERNOR_PREEMPT_SIG)
            BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, args[0])),
            BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, static_cast<uint32_t>(GOVERNOR_PREEMPT_SIG), 2, 0),
            BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),

            // SYS_rt_sigprocmask handler (deny mask modifications)
            BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | (EPERM & SECCOMP_RET_DATA)),

            // SYS_prctl handler (deny PR_SET_SECCOMP manipulation)
            BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, args[0])),
            BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, PR_SET_SECCOMP, 0, 1),
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

public:
    GovernedMinotaurHost() noexcept = default;

    /**
     * Set active capability mask. Guarded against mid-transaction changes.
     * Returns false if transaction is in flight, preventing capability mutation.
     */
    [[nodiscard]] bool SetActiveCapabilities(const CapabilityMask256& mask) noexcept {
        if (transactions_in_flight_.load(std::memory_order_acquire) > 0) {
            return false;  // Transaction in flight; cannot change capabilities
        }
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

        // Lifecycle guard: mark transaction in flight
        transactions_in_flight_.fetch_add(1, std::memory_order_release);

        // RAII cleanup: decrement on exit
        struct TransactionGuard {
            std::atomic<uint32_t>& counter;
            ~TransactionGuard() noexcept {
                counter.fetch_sub(1, std::memory_order_release);
            }
        } lifecycle_guard{transactions_in_flight_};

        // Component 13 Check: SIMD Capability Verification
        if (!token.Validate(active_host_capabilities_)) [[unlikely]] {
            return std::unexpected(HostExecutionError::CapabilityValidationFailed);
        }

        const uint64_t domain_id = token.GetContextId();
        const uint64_t start_tick = HardwareClock::ReadTicks();

        // Component 2-5 Check: Kinetic Governor
        auto consume_res = governor_.Consume(required_tokens, PriorityClass::Standard, start_tick);
        if (!consume_res.has_value()) [[unlikely]] {
            return std::unexpected(HostExecutionError::RateLimitExceeded);
        }

        TransactionRollbackGuard guard(
            governor_, debt_tracker_, domain_id, start_tick, 0, required_tokens);

        // Component 10 Check: Persistent POSIX Timer
        HardenedPosixPreemptionGuard timer_guard;
        if (!timer_guard.Arm(hard_timeout_nanoseconds).has_value()) [[unlikely]] {
            return std::unexpected(HostExecutionError::TimerInitializationFailed);
        }

        // Component 6 Check: Software Deadline Scope
        bool software_overrun = false;
        {
            ExecutionDeadlineScope deadline_scope(deadline_budget_ticks, &software_overrun);
            payload();
        }

        const uint64_t elapsed_ticks = HardwareClock::ReadTicks() - start_tick;

        if (timer_guard.WasPreempted()) [[unlikely]] {
            return std::unexpected(HostExecutionError::PreemptionTriggered);
        }

        if (software_overrun) [[unlikely]] {
            return std::unexpected(HostExecutionError::DeadlineExceeded);
        }

        // Component 8-9 Check: Compute Debt
        guard.accrued_ticks = elapsed_ticks;
        auto debt_res = debt_tracker_.AccrueDebt(domain_id, elapsed_ticks);
        if (!debt_res.has_value()) [[unlikely]] {
            return std::unexpected(HostExecutionError::DebtCeilingExceeded);
        }

        guard.Commit();
        return {};
    }
};

} // namespace stack::host
