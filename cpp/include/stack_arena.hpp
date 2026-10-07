#pragma once

/**
 * ≡TACK KERNEL LAYER 6: Memory Isolation Arena (Bump Allocator)
 *
 * ───────────────────────────────────────────────────────────────────────────
 * ISOLATION LAYER: Linear Allocation Without Escape
 *
 * This layer provides a sealed, bounded memory region for untrusted execution.
 * Minotaur (the sandbox payload) allocates from this arena; it cannot
 * allocate outside it. The arena is statically sized, fixed at compile time.
 *
 * Uses a simple bump allocator: allocation increments an offset counter.
 * No freeing. No fragmentation. No escape to system heap.
 *
 * Once the arena is exhausted (OutOfMemory), all further allocations fail.
 * Minotaur cannot acquire more memory by any mechanism—SECCOMP blocks
 * mmap/brk, and the arena is the only allocation source available.
 *
 * Architectural property: Minotaur's heap is finite and known at boot time.
 *
 * ───────────────────────────────────────────────────────────────────────────
 * ARCHITECTURAL DEFECT: Reset() Allows Reuse (Not Isolation)
 *
 * Reset() rewinds the allocator, allowing memory to be reused. In true
 * isolation, each transaction should get a fresh arena and never see
 * previous allocations. Current implementation allows sequential transactions
 * to share arena state if Reset() is called between them.
 *
 * This is a policy defect: the mechanism (linear allocation) is correct,
 * but the lifecycle (when Reset() is called) determines isolation strength.
 * Calling Reset() between transactions preserves isolation. Reusing the
 * arena across transactions breaks it.
 *
 * ───────────────────────────────────────────────────────────────────────────
 */

#include <algorithm>
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <new>
#include <utility>

namespace stack::isolation {

/**
 * ARENA ERROR: Allocation failure classification.
 *
 *   None:                 No error (success)
 *   OutOfMemory:          Arena exhausted; cannot satisfy allocation
 *   InvalidAlignment:     Reserved for future use (not currently used)
 *   PointerOutOfBounds:   Reserved for future use (not currently used)
 */
enum class ArenaError : uint8_t {
    None = 0,
    OutOfMemory,
    InvalidAlignment,
    PointerOutOfBounds
};

/**
 * STATIC ARENA BUFFER: Sealed, Bounded Heap for Untrusted Code
 *
 * A linear (bump) allocator that provides a fixed-size memory region with
 * compile-time capacity. Minotaur receives this arena as its only heap.
 *
 * Allocation algorithm:
 *   1. Calculate aligned offset (align current offset to T's alignment)
 *   2. Check if allocation fits (offset + padding + sizeof(T) <= ArenaSize)
 *   3. Placement-new the object at the aligned address
 *   4. Increment offset by (padding + sizeof(T))
 *
 * Returns T* on success, std::unexpected(OutOfMemory) on failure.
 *
 * Properties:
 *   - No fragmentation (linear allocation)
 *   - O(1) allocation (no search, no tree)
 *   - Deterministic failure (clear exhaustion point)
 *   - No freeing (single-use memory, then reset)
 *
 * Template parameters:
 *   ArenaSize: Total capacity in bytes (default: 64 KiB). Set at compile time.
 *
 * Defect: Lifecycle management (Reset() reuse) is not isolation-enforced.
 * See architectural notes above.
 */
template <std::size_t ArenaSize = 64 * 1024>
class StaticArenaBuffer {
private:
    alignas(64) uint8_t storage_[ArenaSize]{};
    std::size_t offset_{0};
    std::atomic<uint32_t> allocations_in_flight_{0};  // Lifecycle guard
    std::atomic<uint64_t> generation_{0};  // LAYER 6 P1 FIX: uint64 to prevent wraparound over decades

public:
    constexpr StaticArenaBuffer() noexcept = default;

    // Increment allocations counter when allocating
    void IncAllocations() noexcept {
        allocations_in_flight_.fetch_add(1, std::memory_order_release);
    }

    // Decrement allocations counter when done
    void DecAllocations() noexcept {
        allocations_in_flight_.fetch_sub(1, std::memory_order_release);
    }

    /**
     * ALLOCATE: Reserve and construct one object in the arena.
     *
     * Advances the offset counter to account for the new allocation.
     * Honors alignment requirements.
     *
     * Parameters:
     *   args: Constructor arguments forwarded to T
     *
     * Returns: T* (pointer to constructed object) on success
     *          unexpected(OutOfMemory) if arena cannot fit the allocation
     *
     * Defect: No protection against reuse across transaction boundaries.
     * If Reset() is called between transactions, Minotaur can read data
     * from previous transactions if it finds the old pointer.
     */
    template <typename T, typename... Args>
    [[nodiscard]] std::expected<T*, ArenaError> Allocate(Args&&... args) noexcept {
        constexpr std::size_t alignment = alignof(T);
        constexpr std::size_t type_size = sizeof(T);
        const std::size_t current_ptr = reinterpret_cast<std::size_t>(storage_ + offset_);
        const std::size_t aligned_ptr = (current_ptr + (alignment - 1)) & ~(alignment - 1);
        const std::size_t padding = aligned_ptr - current_ptr;

        if (offset_ + padding + type_size > ArenaSize) [[unlikely]] {
            return std::unexpected(ArenaError::OutOfMemory);
        }
        offset_ += (padding + type_size);
        return ::new (reinterpret_cast<void*>(aligned_ptr)) T(std::forward<Args>(args)...);
    }

    /**
     * RESET: Rewind the allocator to the beginning. Guarded against mid-flight resets.
     *
     * Clears all allocations and allows the arena to be reused.
     * Destructors are NOT called on existing objects (no automatic cleanup).
     *
     * LAYER 6 FIX: Invalidate stale pointers by:
     * 1. Zeroing the entire arena (defensive memory scrub)
     * 2. Incrementing generation counter (makes old pointers logically invalid)
     *
     * Returns: true if reset succeeded, false if allocations are in flight
     * (prevents arena wipe during active transaction use).
     */
    [[nodiscard]] bool Reset() noexcept {
        if (allocations_in_flight_.load(std::memory_order_acquire) > 0) {
            return false;  // Allocations in flight; cannot reset
        }

        // LAYER 6 FIX: Zero memory to prevent leakage through stale pointer access
        std::fill(storage_, storage_ + ArenaSize, uint8_t{0});

        offset_ = 0;
        generation_.fetch_add(1, std::memory_order_release);  // Invalidate old pointers
        return true;
    }

    /**
     * CURRENT GENERATION: Logical epoch for isolation.
     * LAYER 6 P1 FIX: Returns uint64_t (extended from uint32_t) to match the
     * generation counter size. This prevents wraparound over decades of operation.
     * Allocations from generation N become stale after Reset() advances to N+1.
     */
    [[nodiscard]] uint64_t CurrentGeneration() const noexcept {
        return generation_.load(std::memory_order_acquire);
    }

    /**
     * BYTES ALLOCATED: Current high-water mark.
     * Returns the offset of the next allocation.
     */
    [[nodiscard]] std::size_t BytesAllocated() const noexcept { return offset_; }

    /**
     * BYTES REMAINING: Free space in the arena.
     * Returns how many bytes can still be allocated before exhaustion.
     */
    [[nodiscard]] std::size_t BytesRemaining() const noexcept { return ArenaSize - offset_; }
};

} // namespace stack::isolation
