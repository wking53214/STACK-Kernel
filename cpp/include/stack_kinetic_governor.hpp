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
 * DEFECT #3 (REACTIVE DEADLINE DETECTION - ARCHITECTURAL CONSTRAINT):
 *
 * This is NOT deadline enforcement. Like the preemption layer below it,
 * this is an after-the-fact check. The check happens in the destructor,
 * which means:
 *
 *   - Records start tick at construction
 *   - Payload executes to completion
 *   - Destructor runs (after payload returns)
 *   - Destructor reads end tick and checks if elapsed > budget
 *   - Sets flag if exceeded (but execution already completed)
 *
 * LIMITATIONS (Inherited from Layer 2):
 *
 *   - If payload runs forever, destructor never runs; check never happens
 *   - If payload exceeds budget by 50%, the flag is set, but work completed
 *   - Deadline enforcement is post-facto, not preventive
 *   - Useful only for detecting overruns, not preventing them
 *
 * ROOT CAUSE: The preemption layer (Layer 2) does not actually stop execution.
 * It only sets a flag when the timer fires. The signal handler does not
 * preempt the payload; execution continues to completion. Therefore, this
 * scope can only observe and report the overrun AFTER the work is done.
 *
 * FIX STRATEGY: This defect cannot be fixed in Layer 3. It requires Layer 2
 * to implement true execution preemption (e.g., setjmp/longjmp or signal-based
 * context unwinding), which is a major architectural change outside this layer's
 * scope.
 *
 * CONTRACT: Use this scope only for deadline-overrun reporting and forensics,
 * not for hard deadline enforcement. For enforcing hard limits, preemption
 * must be implemented in a lower layer.
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
     * REACTIVE: This check happens AFTER the payload completes. The flag is
     * a marker of overrun, not a preemption mechanism.
     *
     * Thread-safe: Each thread has its own start_ticks and budget_ticks.
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
     * Fails if the domain ID is out of bounds or if the new debt would exceed
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
     * FIX #2: Ceiling check now happens BEFORE the CAS operation (not after).
     * This prevents state from being modified beyond the ceiling.
     *
     * ALGORITHM:
     *   1. Load current debt value
     *   2. Check if (current + ticks > ceiling) BEFORE any modification
     *   3. If check fails, return error without modifying state
     *   4. Attempt CAS to apply the new debt atomically
     *   5. Retry if CAS fails (another thread won the race)
     */
    [[nodiscard]] std::expected<void, GovernorError> AccrueDebt(uint64_t domain_id, uint64_t ticks) noexcept {
        constexpr uint64_t DEBT_CEILING = 100'000'000'000ULL;

        if (domain_id >= MaxDomains) {
            return std::unexpected(GovernorError::DebtCeilingExceeded);
        }

        auto& debt = domains_[domain_id].accrued_ticks;
        uint64_t current = debt.load(std::memory_order_relaxed);

        // CAS loop: atomically update debt counter
        while (true) {
            // FIX: Check ceiling BEFORE attempting CAS, not after
            if (current + ticks > DEBT_CEILING) {
                return std::unexpected(GovernorError::DebtCeilingExceeded);
            }

            if (debt.compare_exchange_weak(current, current + ticks,
                                          std::memory_order_release,
                                          std::memory_order_relaxed)) {
                break;  // CAS succeeded, debt has been updated
            }

            // CAS failed; another thread modified the counter. Retry.
            BackpressureController::YieldCpu();
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
 * VOLUME COUNTER: Request volume tracking (not a sliding window)
 *
 * FIX #1: Renamed from "SlidingWindowRing" to "VolumeCounter" to correct the
 * architectural contract. The previous name promised time-windowed tracking but
 * the implementation is a simple running counter.
 *
 * WHAT THIS DOES:
 *   - Tracks cumulative volume: Record() increments, Unrecord() decrements
 *   - No time windows, no bucket expiration, no ring structure
 *   - Atomic counter for thread-safe updates
 *
 * ARCHITECTURAL CONSTRAINT:
 *   This is NOT a sliding window. Volume accumulates forever and is never reset
 *   by time passage. If windowed behavior is needed in the future, this class
 *   must be redesigned with timestamp-based buckets and ring rotation.
 *
 * The template Capacity parameter is retained for API compatibility but is
 * enforced as a power-of-two (static_assert) to prepare infrastructure for
 * future sliding-window implementation.
 *
 * CONTRACT: Callers must not assume time-based volume expiration. This counter
 * is suitable for transaction tracking but not for rate-limit windows that
 * should reset on time boundaries.
 */
template <std::size_t Capacity>
class alignas(64) VolumeCounter {
    static_assert((Capacity & (Capacity - 1)) == 0, "Capacity must be power of two");

private:
    /**
     * RUNNING TOTAL: Cumulative volume counter.
     *
     * Incremented on transaction admission, decremented on rollback.
     * Never reset by timer expiration.
     */
    std::atomic<uint64_t> volume_{0};

public:
    /**
     * Record volume: increment the counter.
     *
     * Called when a transaction consumes resources. Adds to the running total.
     */
    void Record(uint64_t amount) noexcept {
        volume_.fetch_add(amount, std::memory_order_relaxed);
    }

    /**
     * Unrecord volume: decrement the counter.
     *
     * Called when a transaction is rolled back. Subtracts from the total.
     *
     * NOTE: This does NOT refund based on transaction age. It is a simple
     * reversal of the Record() call. Time-based expiration is not implemented.
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
    VolumeCounter<1024> volume_{};

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

        volume_.Record(amount);
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

        volume_.Unrecord(amount);
    }
};

/**
 * TRANSACTION ROLLBACK GUARD: Compensation on Abort
 *
 * RAII guard that refunds governor tokens if the transaction does not
 * explicitly commit. Compensation on destruction ensures tokens are restored
 * if the transaction is preempted, fails, or is rolled back.
 *
 * DEFECT #4 (INCOMPLETE ROLLBACK DESIGN - UNUSED PARAMETERS):
 *
 * Constructor accepts but ignores two parameters:
 *   - uint64_t start:   Transaction start tick
 *   - uint64_t budget:  Execution deadline budget
 *
 * These parameters were intended for comprehensive rollback but are not stored
 * or used. This indicates the rollback design is incomplete:
 *
 * INTENDED DESIGN (not yet implemented):
 *   - On abort, refund both tokens AND accrued debt
 *   - Record budget parameter for timeout enforcement on rollback
 *   - Track transaction age for deadline-driven cleanup
 *
 * CURRENT IMPLEMENTATION (simplified):
 *   - On abort, refund tokens only
 *   - Accrued debt is permanent (cannot be refunded)
 *   - Budget parameter is accepted but ignored
 *
 * ASYMMETRY: This creates an imbalance: tokens are reversible on abort,
 * but debt is not. If a transaction is rolled back, its consumed tokens
 * return to the bucket, but its accrued ticks remain charged to the domain.
 *
 * FIX STRATEGY (Future): Implement debt refunding in the tracker:
 *   - Store the budget parameter (implies tracking rollback time)
 *   - On destruction (abort case), call tracker_.RefundDebt(domain_id_, accrued_ticks)
 *   - Ensure RefundDebt is atomic and thread-safe like AccrueDebt
 *
 * CURRENT CONTRACT: This guard refunds tokens only. The debt accrued during
 * transaction execution is permanent regardless of commit/rollback outcome.
 * Debt is NOT reversible; it accumulates until the domain hits the ceiling.
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
     *   start:     [STORED but UNUSED] Transaction start tick. Intended for
     *              future deadline-driven rollback, not currently used.
     *   budget:    [STORED but UNUSED] Execution deadline budget. Intended for
     *              future timeout enforcement on rollback, not currently used.
     *   tokens:    Tokens consumed by this transaction (refunded on abort).
     *
     * DESIGN NOTE: The start and budget parameters are intentionally accepted
     * and documented for future implementation of comprehensive rollback that
     * includes debt refunding. Current implementation ignores them.
     */
    TransactionRollbackGuard(
        KineticGovernor<MaxCap, Reserved, MaxBurst, TicksPerToken>& gov,
        ComputeDebtTracker<MaxDomains>& tracker,
        uint64_t did,
        uint64_t /*start*/,  // For future: transaction start time
        uint64_t /*budget*/, // For future: execution deadline budget
        uint32_t tokens)
        : gov_(gov), tracker_(tracker), domain_id_(did), tokens_(tokens) {}

    /**
     * Commit: Mark this transaction as successful (no rollback on destruction).
     */
    void Commit() noexcept { committed_ = true; }

    /**
     * Destruct: Refund tokens if not committed.
     *
     * CURRENT BEHAVIOR: Refunds only governor tokens on abort. Does not
     * modify debt accrued during transaction execution.
     *
     * LIMITATION: Tokens are reversible, but debt is permanent. This creates
     * asymmetry in rollback compensation.
     *
     * FUTURE BEHAVIOR: Once the rollback design is completed (see class doc),
     * this destructor will also refund accrued debt via tracker_.RefundDebt().
     */
    ~TransactionRollbackGuard() noexcept {
        if (!committed_) {
            gov_.Refund(tokens_);  // Refund tokens
            // TODO: Implement tracker_.RefundDebt(domain_id_, accrued_ticks)
            // when rollback compensation is complete (defect #4 fix phase 2)
        }
    }
};

} // namespace stack::governor
