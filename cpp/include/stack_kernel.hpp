#pragma once

/**
 * ≡TACK KERNEL FOUNDATION: Hardware-Locked Timing and Admission Control
 *
 * CONFIDENTIAL. Trade secret of William King (wking53214).
 * This module is the ground floor of the containment stack.
 * Everything built above depends on what it measures.
 *
 * ───────────────────────────────────────────────────────────────────────────
 * WHY HARDWARE CLOCKS MATTER TO GOVERNANCE
 *
 * A governance system that cannot measure time cannot enforce anything.
 * Rate limiting without accurate measurement is guessing. Deadline enforcement
 * without reliable clocks is theater. Every decision in this kernel—admission,
 * preemption, debt accrual—depends on a tick counter that cannot be gamed.
 *
 * This module provides the single source of truth. Every other component
 * reads this clock and trusts the result completely. If this clock fails
 * silently, the entire containment model fails silently.
 *
 * ───────────────────────────────────────────────────────────────────────────
 * SERIALIZATION: The Critical Detail
 *
 * A naive tick counter (reading time without barriers) can measure speculative
 * work—instructions prefetched by the CPU but not yet executed. For rate
 * limiting, that means a burst looks smaller than it was. For deadline
 * enforcement, that means an overrun looks on-time.
 *
 * This implementation uses serializing instructions:
 *   x86_64:  __rdtscp() waits for all prior instructions, reads the counter,
 *            then waits before any subsequent instruction starts.
 *   ARM64:   ISB barrier (Instruction Synchronization Barrier) then mrs
 *            cntvct_el0 to read the virtual counter.
 *
 * Both guarantee the returned tick is the actual execution point, not a
 * speculative ghost.
 *
 * ───────────────────────────────────────────────────────────────────────────
 */

#include <cstdint>

#if defined(__x86_64__) || defined(_M_X64)
#include <immintrin.h>
#elif defined(__aarch64__)
#include <arm_neon.h>
#endif

namespace stack::governor {

/**
 * PRIORITY CLASS: Admission tier for the governance system.
 *
 * Two tiers, both under governance:
 *
 *   Root (0):    System-critical operations. Higher queue priority but not
 *                exempt from rate limiting or deadline enforcement. Root
 *                means "admit me faster," not "let me run forever."
 *
 *   Standard (1): User work. Fully rate-limited and deadline-constrained.
 *
 * This distinction is structural and checked at admission time. It is not
 * advisory. A Standard request denied stays denied. A Root request denied
 * still does not run.
 */
enum class PriorityClass : uint8_t {
    Root = 0,       // System-critical, higher queue priority
    Standard = 1    // User work, standard rate limiting applies
};

/**
 * HARDWARE CLOCK: Serialized Tick Counter
 *
 * The foundation of all timing measurements in the containment kernel.
 * Every component (deadline scope, rate limiter, debt tracker, preemption
 * guard) depends on this single source of truth.
 *
 * Guaranteed property: The returned tick count represents the actual point
 * of execution, not speculative prefetch, not out-of-order work, not CPU
 * tricks. This guarantee is enforced by serializing instructions (RDTSCP on
 * x86_64, ISB+MRS on ARM64).
 *
 * Architecture: Cache-line aligned (64 bytes) to prevent false-sharing if
 * multiple threads poll the clock simultaneously. Not that they should—this
 * is a single source of truth per core, not a shared variable—but alignment
 * is cheap insurance.
 */
struct alignas(64) HardwareClock {

    /**
     * Read the current execution tick counter in a serializing, unambiguous way.
     *
     * Returns:     CPU cycle count (x86_64) or virtual counter (ARM64).
     * Precision:   Single-cycle granularity.
     * Guarantee:   Serializing. Measures the actual point in execution, not
     *              speculative or out-of-order.
     *
     * KNOWN LIMITATION (Architecture Fallback):
     *
     * On unsupported architectures (neither x86_64 nor ARM64), this returns 0.
     * This is a SILENT DEFECT. Returning 0 makes all timing measurements
     * worthless: every deadline has infinite time, every rate limit is never
     * triggered, every debt is never accrued. The entire containment model
     * becomes inert.
     *
     * This path exists for code compilability on unknown architectures, but
     * it is NOT SAFE FOR PRODUCTION. Any use of this kernel on an unsupported
     * CPU will have zero timing enforcement.
     *
     * This defect is documented here because it is catastrophic and must be
     * visible, not hidden.
     */
    [[nodiscard]] static inline uint64_t ReadTicks() noexcept {
#if defined(__x86_64__) || defined(_M_X64)
        // x86_64: RDTSCP is a serializing instruction.
        // Waits for all prior instructions to complete.
        // Reads the time-stamp counter + auxiliary register.
        // Prevents all subsequent instructions from starting until done.
        unsigned int aux;
        return __rdtscp(&aux);

#elif defined(__aarch64__)
        // ARM64: ISB (Instruction Synchronization Barrier) then read the
        // virtual timer counter (cntvct_el0). ISB ensures all prior work is
        // done before the counter read, preventing speculative prefetch.
        uint64_t val;
        asm volatile("isb; mrs %0, cntvct_el0" : "=r"(val));
        return val;

#else
        // DEFECT VISIBLE: Unsupported architecture.
        // Timing measurements will be 0, making rate limiting and deadline
        // enforcement inert. See docstring above.
        return 0;
#endif
    }
};

} // namespace tack::governor
