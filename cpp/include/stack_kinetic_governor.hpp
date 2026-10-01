#pragma once

/**
 * ≡TACK KERNEL LAYER 3: Rate Limiting, Debt Tracking, and Execution Deadlines
 *
 * CONFIDENTIAL. Trade secret of William King (wking53214).
 *
 * ───────────────────────────────────────────────────────────────────────────
 * LAYER 3 OVERVIEW
 *
 * This layer implements token-bucket rate limiting (KineticGovernor) and
 * per-domain execution debt accounting (ComputeDebtTracker). It enforces
 * quota and resource constraints on untrusted execution.
 *
 * Four major defects are visible in this implementation:
 *
 * 1. SlidingWindowRing is not a sliding window (just a counter)
 * 2. Debt ceiling check happens after the debt is already incremented
 * 3. ExecutionDeadlineScope is reactive (checks after completion)
 * 4. Unused budget parameters hint at incomplete rollback design
 *
 * All four are documented here because they are architectural limitations
 * that propagate upward and must be visible before fixes are attempted.
 *
 * ───────────────────────────────────────────────────────────────────────────
 */

#include "stack_kernel.hpp"
#include <atomic>
#include <cstdint>
#include <expected>
#include <array>

#if defined(__x86_64__) || defined(_M_X64)
#include <emmintrin.h>
#endif

#include <algorithm>

namespace stack::governor {

/**
 * GOVERNOR ERROR: Rate limiting and debt ceiling violations.
 *
 * None:                  Success (no error).
 * RateLimited:           Token bucket is empty; request denied at admission.
 * DebtCeilingExceeded:   Domain has accrued too much execution debt, or
 *                        domain ID is out of bounds.
 */
enum class GovernorError : uint8_t {
    None = 0,
    RateLimited = 1,
    DebtCeilingExceeded = 2
};

/**
 * BACKPRESSURE CONTROLLER: Spin-yield for lock contention.
 *
 * When a compare-exchange loop fails (CAS retry), yields CPU to other threads
 * instead of spinning uselessly. Uses platform-specific CPU pause instructions:
 *   x86_64:  _mm_pause() (PAUSE instruction, ~140 cycles)
 *   ARM64:   asm yield (YIELD instruction)
 *
 * This is correctly implemented and has no defects.
 */
struct BackpressureController {
    static inline void YieldCpu() noexcept {
#if defined(__x86_64__) || defined(_M_X64)
        _mm_pause();
#elif defined(__aarch64__)
        asm volatile("yield" ::: "memory");
#endif
    }
};

/**
 * EXECUTION DEADLINE SCOPE: Software-based deadline overrun detection.
 *
 * Measures elapsed ticks from construction to destruction and marks a flag
 * if the execution exceeded its budget.
 *
 * DEFECT #3 (REACTIVE DEADLINE DETECTION):
 *
 * This is NOT deadline enforcement. Like the preemption layer above it,
 * this is an after-the-fact check:
 *
 *   - Records start tick at construction
 *   - Payload executes completely
 *   - Destructor reads end tick
 *   - If elapsed > budget, sets flag
 *
 * If the payload runs forever, this check never runs (no destructor).
 * If the payload uses 150% of its budget, the flag is set, but the work
 * has already completed.
 *
 * The entire deadline enforcement model depends on layers below (preemption)
 * actually stopping execution, but they do not. This creates a cascade of
 * reactive checks instead of preventive enforcement.
 *
 * This is documented here because the name "Deadline*Scope*" suggests active
 * enforcement during execution, but the implementation is pure observation.
 */
class ExecutionDeadlineScope {
private:
    uint64_t start_ticks_;
    uint64_t budget_ticks_;
    bool* overrun_flag_;

public:
    /**
     * Construct: Record the current tick counter as the start point.
     *
     * Parameters:
     *   budget_ticks:   The tick budget for this execution scope.
     *   overrun_flag:   Pointer to bool. Set to true if deadline exceeded.
     */
    ExecutionDeadlineScope(uint64_t budget_ticks, bool* overrun_flag) noexcept
        : start_ticks_(HardwareClock::ReadTicks()),
          budget_ticks_(budget_ticks),
          overrun_flag_(overrun_flag) {}

    /**
     * Destruct: Check if execution exceeded the budget.
     *
     * Reads the current tick counter and compares against the start time.
     * If elapsed ticks > budget, sets the overrun flag to true.
     *
     * REACTIVE: This check happens AFTER the payload completes, not during.
     */
    ~ExecutionDeadlineScope() noexcept {
        if (HardwareClock::ReadTicks() - start_ticks_ > budget_ticks_) {
            *overrun_flag_ = true;
        }
    }
};

/**
 * COMPUTE DEBT TRACKER: Per-Domain Execution Debt Accounting
 *
 * Tracks accumulated tick debt per domain. Each domain (execution context) has
 * a debt counter. As execution completes, debt is accrued. If debt exceeds a
 * ceiling, future requests from that domain are denied.
 *
 * DEFECT #2 (DEBT CEILING CHECK AFTER INCREMENT):
 *
 * The ceiling check is deeply broken:
 *
 *   1. Load current debt value
 *   2. CAS loop: atomically set debt to (current + ticks)
 *   3. Check if (current + ticks > 100'000'000'000ULL)
 *   4. If yes, return error
 *
 * By step 3, the state has ALREADY been modified. The debt counter has
 * already been incremented beyond the ceiling. Returning an error does not
 * undo the CAS—the damage is done.
 *
 * This is either:
 *   a) A permanent safety latch (debt goes over the edge and stays there),
 *      intentionally left high-water-marked for forensics, or
 *   b) A state-accounting defect that allows debt to exceed the limit.
 *
 * The implementation does not say which. This is documented here to make the
 * ambiguity visible.
 *
 * Additionally, there is no TransactionRollbackGuard mechanism to refund debt
 * on rollback. The guard refunds governor tokens but not accrued debt. This
 * creates an asymmetry: tokens can be refunded, but debt cannot.
 */
template <std::size_t MaxDomains = 256>
class alignas(64) ComputeDebtTracker {
private:
    /**
     * Per-domain debt storage. One atomic counter per domain.
     * Cache-line aligned to prevent false-sharing across domains.
     */
    struct alignas(64) DomainDebt {
        std::atomic<uint64_t> accrued_ticks{0};
    };

    std::array<DomainDebt, MaxDomains> domains_{};

public:
    /**
     * Accrue execution debt for a domain.
     *
     * Atomically increments the domain's debt counter by the given ticks.
     * Fails if the domain ID is out of bounds or if the new debt exceeds
     * the ceiling.
     *
     * Parameters:
     *   domain_id:  Domain identifier (0 to MaxDomains-1).
     *   ticks:      Execution ticks to accrue.
     *
     * Returns:
     *   GovernorError::None if successful.
     *   GovernorError::DebtCeilingExceeded if domain_id >= MaxDomains or
     *                                       if (new_debt > ceiling).
     *
     * CRITICAL ISSUE: The ceiling check happens AFTER the CAS operation,
     * so state may exceed the ceiling before the error is returned.
     */
    [[nodiscard]] std::expected<void, GovernorError> AccrueDebt(uint64_t domain_id, uint64_t ticks) noexcept {
        if (domain_id >= MaxDomains) {
            return std::unexpected(GovernorError::DebtCeilingExceeded);
        }

        auto& debt = domains_[domain_id].accrued_ticks;
        uint64_t current = debt.load(std::memory_order_relaxed);

        // CAS loop: atomically update debt counter
        while (!debt.compare_exchange_weak(current, current + ticks,
                                           std::memory_order_release,
                                           std::memory_order_relaxed)) {
            BackpressureController::YieldCpu();
        }

        // DEFECT: Check happens after CAS. Debt has already been incremented.
        // See architectural notes above.
        if (current + ticks > 100'000'000'000ULL) {
            return std::unexpected(GovernorError::DebtCeilingExceeded);
        }

        return {};
    }
};

/**
 * PACKED BUCKET STATE: Token bucket snapshot (128-bit atomic).
 *
 * Used by KineticGovernor to track available tokens and the timestamp of
 * the last update. Both fields fit in 128 bits for atomic load/store.
 *
 * Members:
 *   timestamp:  Last time tokens were regenerated (from HardwareClock).
 *   tokens:     Current available token count (capped at MaxCapacity).
 */
struct alignas(16) PackedBucket64 {
    uint64_t timestamp;
    uint64_t tokens;
};

/**
 * SLIDING WINDOW RING: Volume accounting container
 *
 * DEFECT #1 (NOT ACTUALLY A SLIDING WINDOW):
 *
 * Name: "SlidingWindowRing" (implies time-windowed volume tracking)
 * Reality: Single atomic counter
 *
 * What the name promises:
 *   - Time-windowed request volume tracking
 *   - Buckets for different time slices
 *   - Expiration of old buckets
 *   - Ring buffer structure (circular)
 *
 * What the code actually does:
 *   - One atomic uint64_t counter (volume_)
 *   - Record() increments it
 *   - Unrecord() decrements it
 *   - No timestamps
 *   - No buckets
 *   - No window movement
 *   - No expiration
 *
 * This is a running total, not a windowed sum. The gap between the name
 * and the implementation is cosmetic but significant: a true sliding window
 * would give fresh perspective on volume trends; this counter accumulates
 * forever.
 *
 * The power-of-two capacity constraint (static_assert) suggests awareness
 * of ring-buffer properties, but the implementation never uses it.
 *
 * This defect is documented here to make the naming mismatch visible before
 * any attempt to fix or extend it.
 */
template <std::size_t Capacity>
class alignas(64) SlidingWindowRing {
    static_assert((Capacity & (Capacity - 1)) == 0, "Capacity must be power of two");

private:
    /**
     * CURRENT IMPLEMENTATION: Single atomic counter (not a window).
     *
     * Despite the class name and template capacity parameter, this is just
     * a counter. Record() adds, Unrecord() subtracts.
     */
    std::atomic<uint64_t> volume_{0};

public:
    /**
     * Record volume: increment the counter.
     *
     * LIMITATION: There is no time window. This is a running total that
     * never expires old requests.
     */
    void Record(uint64_t amount) noexcept {
        volume_.fetch_add(amount, std::memory_order_relaxed);
    }

    /**
     * Unrecord volume: decrement the counter.
     *
     * Used when a transaction is rolled back. Subtracts the amount from
     * the running total.
     */
    void Unrecord(uint64_t amount) noexcept {
        volume_.fetch_sub(amount, std::memory_order_relaxed);
    }
};

/**
 * KINETIC GOVERNOR: Token-Bucket Rate Limiter
 *
 * Implements a token-bucket algorithm with time-based token regeneration.
 * Each time unit (TicksPerToken ticks), tokens are regenerated up to MaxCapacity.
 * Admission requires sufficient tokens available.
 *
 * Priority tier support:
 *   Root:     Bypasses the Reserved token floor check.
 *   Standard: Cannot consume if available < (Reserved + amount requested).
 *
 * This correctly implements token-bucket rate limiting. No defects here.
 */
template <uint32_t MaxCapacity = 1000,
          uint32_t Reserved = 100,
          uint32_t MaxBurst = 100,
          uint64_t TicksPerToken = 10000>
class alignas(64) KineticGovernor {
private:
    std::atomic<PackedBucket64> bucket_{};
    SlidingWindowRing<1024> window_{};

public:
    /**
     * Consume tokens from the bucket.
     *
     * Atomically checks available tokens and deducts the requested amount.
     * Tokens are regenerated based on elapsed time since last update.
     *
     * Parameters:
     *   amount:   Number of tokens requested.
     *   prio:     Priority class (Root or Standard).
     *   now:      Current tick counter (from HardwareClock).
     *
     * Returns:
     *   GovernorError::None if tokens consumed.
     *   GovernorError::RateLimited if insufficient tokens.
     *
     * Thread-safe via CAS loop on atomic bucket state.
     */
    [[nodiscard]] std::expected<void, GovernorError> Consume(
        uint32_t amount,
        PriorityClass prio,
        uint64_t now) noexcept {

        PackedBucket64 current = bucket_.load(std::memory_order_acquire);
        PackedBucket64 next;

        do {
            uint64_t elapsed = (now > current.timestamp) ? (now - current.timestamp) : 0;
            uint64_t generated = elapsed / TicksPerToken;
            uint64_t available = std::min(static_cast<uint64_t>(MaxCapacity),
                                          current.tokens + generated);

            // Standard priority: must leave Reserved tokens for system use
            if (prio == PriorityClass::Standard && available < Reserved + amount) {
                return std::unexpected(GovernorError::RateLimited);
            }

            // Any priority: must have enough tokens to serve the request
            if (available < amount) {
                return std::unexpected(GovernorError::RateLimited);
            }

            next.tokens = available - amount;
            next.timestamp = now;

        } while (!bucket_.compare_exchange_weak(current, next,
                                                 std::memory_order_release,
                                                 std::memory_order_relaxed));

        window_.Record(amount);
        return {};
    }

    /**
     * Refund tokens to the bucket.
     *
     * Called when a transaction is rolled back or preempted. Adds tokens
     * back to the bucket (capped at MaxCapacity).
     *
     * Thread-safe via CAS loop.
     */
    void Refund(uint32_t amount) noexcept {
        PackedBucket64 current = bucket_.load(std::memory_order_relaxed);
        PackedBucket64 next;

        do {
            next.tokens = std::min(static_cast<uint64_t>(MaxCapacity),
                                    current.tokens + amount);
            next.timestamp = current.timestamp;

        } while (!bucket_.compare_exchange_weak(current, next,
                                                 std::memory_order_release,
                                                 std::memory_order_relaxed));

        window_.Unrecord(amount);
    }
};

/**
 * TRANSACTION ROLLBACK GUARD: Dual-Compensation on Abort
 *
 * RAII guard that refunds governor tokens if the transaction does not
 * explicitly commit. Compensation on destruction ensures tokens are restored
 * if the transaction is preempted or fails.
 *
 * DEFECT #4 (UNUSED BUDGET PARAMETERS):
 *
 * Constructor signature includes two unused parameters:
 *   - uint64_t start:   Intended to record transaction start time
 *   - uint64_t budget:  Intended to track deadline budget
 *
 * These parameters appear in the signature but are commented out and never
 * stored. This suggests incomplete rollback design:
 *
 *   - Full rollback should refund both tokens AND accrued debt
 *   - Budget tracking suggests intent to enforce timeout on rollback
 *   - Current implementation refunds only tokens
 *
 * The presence of unused parameters hints at architectural debt: the guard
 * was designed for more comprehensive rollback but was simplified before
 * completion. This is documented to make the incompleteness visible.
 */
template <uint32_t MaxCap,
          uint32_t Reserved,
          uint32_t MaxBurst,
          uint64_t TicksPerToken,
          std::size_t MaxDomains = 256>
class TransactionRollbackGuard {
private:
    KineticGovernor<MaxCap, Reserved, MaxBurst, TicksPerToken>& gov_;
    ComputeDebtTracker<MaxDomains>& tracker_;
    uint64_t domain_id_;
    uint32_t tokens_;
    bool committed_{false};

public:
    uint64_t accrued_ticks{0};

    /**
     * Construct: Register token amount for potential refund.
     *
     * Parameters:
     *   gov:       Reference to the token bucket governor.
     *   tracker:   Reference to the debt tracker.
     *   did:       Domain ID for this transaction.
     *   start:     [UNUSED] Transaction start tick (not stored).
     *   budget:    [UNUSED] Execution budget ticks (not stored).
     *   tokens:    Tokens consumed by this transaction.
     *
     * DEFECT: start and budget are unused. They appear in the signature but
     * are never stored or checked. This suggests incomplete design.
     */
    TransactionRollbackGuard(
        KineticGovernor<MaxCap, Reserved, MaxBurst, TicksPerToken>& gov,
        ComputeDebtTracker<MaxDomains>& tracker,
        uint64_t did,
        uint64_t /*start*/,  // Unused: transaction start time
        uint64_t /*budget*/, // Unused: execution deadline budget
        uint32_t tokens)
        : gov_(gov), tracker_(tracker), domain_id_(did), tokens_(tokens) {}

    /**
     * Commit: Mark this transaction as successful (no rollback on destruction).
     */
    void Commit() noexcept { committed_ = true; }

    /**
     * Destruct: Refund tokens if not committed.
     *
     * LIMITATION: Refunds only governor tokens. Does not refund or adjust
     * accrued debt in the tracker. This creates asymmetry: tokens are
     * reversible on abort, but debt is permanent.
     *
     * The unused budget parameter hints at an intent to implement timeout
     * checks on rollback, but this is not implemented.
     */
    ~TransactionRollbackGuard() noexcept {
        if (!committed_) {
            gov_.Refund(tokens_);  // Refund tokens only
            // Note: accrued_ticks is not refunded from tracker
        }
    }
};

} // namespace tack::governor
