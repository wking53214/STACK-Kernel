#pragma once

#include "tack_kernel.hpp"
#include <atomic>
#include <cstdint>
#include <expected>
#include <array>

#if defined(__x86_64__) || defined(_M_X64)
#include <emmintrin.h>
#endif

#include <algorithm>

namespace tack::governor {

enum class GovernorError : uint8_t { None = 0, RateLimited = 1, DebtCeilingExceeded = 2 };

// Component 7: Backpressure & Saturation Controller
struct BackpressureController {
    static inline void YieldCpu() noexcept {
#if defined(__x86_64__) || defined(_M_X64)
        _mm_pause();
#elif defined(__aarch64__)
        asm volatile("yield" ::: "memory");
#endif
    }
};

// Component 6: Execution Deadline Clocks
class ExecutionDeadlineScope {
private:
    uint64_t start_ticks_;
    uint64_t budget_ticks_;
    bool* overrun_flag_;
public:
    ExecutionDeadlineScope(uint64_t budget_ticks, bool* overrun_flag) noexcept
        : start_ticks_(HardwareClock::ReadTicks()), budget_ticks_(budget_ticks), overrun_flag_(overrun_flag) {}
    
    ~ExecutionDeadlineScope() noexcept {
        if (HardwareClock::ReadTicks() - start_ticks_ > budget_ticks_) {
            *overrun_flag_ = true;
        }
    }
};

// Component 8 & 9: Saturating Compute Debt Tracker & Decoupled Hooks
template <std::size_t MaxDomains = 256>
class alignas(64) ComputeDebtTracker {
private:
    struct alignas(64) DomainDebt { std::atomic<uint64_t> accrued_ticks{0}; };
    std::array<DomainDebt, MaxDomains> domains_{};

public:
    [[nodiscard]] std::expected<void, GovernorError> AccrueDebt(uint64_t domain_id, uint64_t ticks) noexcept {
        if (domain_id >= MaxDomains) return std::unexpected(GovernorError::DebtCeilingExceeded);
        
        auto& debt = domains_[domain_id].accrued_ticks;
        uint64_t current = debt.load(std::memory_order_relaxed);
        while (!debt.compare_exchange_weak(current, current + ticks, std::memory_order_release, std::memory_order_relaxed)) {
            BackpressureController::YieldCpu();
        }
        
        if (current + ticks > 100'000'000'000ULL) { // Decoupled hook threshold check
            return std::unexpected(GovernorError::DebtCeilingExceeded);
        }
        return {};
    }
};

// Component 2: Double-Word Atomic State (128-bit)
struct alignas(16) PackedBucket64 {
    uint64_t timestamp;
    uint64_t tokens;
};

// Component 4: Sliding Window Ring
template <std::size_t Capacity>
class alignas(64) SlidingWindowRing {
    static_assert((Capacity & (Capacity - 1)) == 0, "Capacity must be power of two");
private:
    std::atomic<uint64_t> volume_{0};
public:
    void Record(uint64_t amount) noexcept { volume_.fetch_add(amount, std::memory_order_relaxed); }
    void Unrecord(uint64_t amount) noexcept { volume_.fetch_sub(amount, std::memory_order_relaxed); }
};

template <uint32_t MaxCapacity = 1000, uint32_t Reserved = 100, uint32_t MaxBurst = 100, uint64_t TicksPerToken = 10000>
class alignas(64) KineticGovernor {
private:
    std::atomic<PackedBucket64> bucket_{};
    SlidingWindowRing<1024> window_{};

public:
    [[nodiscard]] std::expected<void, GovernorError> Consume(uint32_t amount, PriorityClass prio, uint64_t now) noexcept {
        PackedBucket64 current = bucket_.load(std::memory_order_acquire);
        PackedBucket64 next;
        do {
            uint64_t elapsed = (now > current.timestamp) ? (now - current.timestamp) : 0;
            uint64_t generated = elapsed / TicksPerToken;
            uint64_t available = std::min(static_cast<uint64_t>(MaxCapacity), current.tokens + generated);
            
            if (prio == PriorityClass::Standard && available < Reserved + amount) {
                return std::unexpected(GovernorError::RateLimited);
            }
            if (available < amount) return std::unexpected(GovernorError::RateLimited);
            
            next.tokens = available - amount;
            next.timestamp = now;
        } while (!bucket_.compare_exchange_weak(current, next, std::memory_order_release, std::memory_order_relaxed));
        
        window_.Record(amount);
        return {};
    }

    void Refund(uint32_t amount) noexcept {
        PackedBucket64 current = bucket_.load(std::memory_order_relaxed);
        PackedBucket64 next;
        do {
            next.tokens = std::min(static_cast<uint64_t>(MaxCapacity), current.tokens + amount);
            next.timestamp = current.timestamp;
        } while (!bucket_.compare_exchange_weak(current, next, std::memory_order_release, std::memory_order_relaxed));
        window_.Unrecord(amount);
    }
};

// Component 5: Dual-Compensation Transaction Rollback
template <uint32_t MaxCap, uint32_t Reserved, uint32_t MaxBurst, uint64_t TicksPerToken, std::size_t MaxDomains = 256>
class TransactionRollbackGuard {
    KineticGovernor<MaxCap, Reserved, MaxBurst, TicksPerToken>& gov_;
    ComputeDebtTracker<MaxDomains>& tracker_;
    uint64_t domain_id_;
    uint32_t tokens_;
    bool committed_{false};
public:
    uint64_t accrued_ticks{0};

    TransactionRollbackGuard(KineticGovernor<MaxCap, Reserved, MaxBurst, TicksPerToken>& gov, 
                             ComputeDebtTracker<MaxDomains>& tracker, 
                             uint64_t did, uint64_t /*start*/, uint64_t /*budget*/, uint32_t tokens)
        : gov_(gov), tracker_(tracker), domain_id_(did), tokens_(tokens) {}

    void Commit() noexcept { committed_ = true; }

    ~TransactionRollbackGuard() noexcept {
        if (!committed_) {
            gov_.Refund(tokens_); // Dual Token + Volume Unrecord
        }
    }
};

} // namespace tack::governor
