#pragma once

/**
 * ≡TACK KERNEL LAYER 6: Memory Isolation Arena (Bump Allocator)
 *
 * CONFIDENTIAL. Trade secret of William King (wking53214).
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

public:
    constexpr StaticArenaBuffer() noexcept = default;

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
     * RESET: Rewind the allocator to the beginning.
     *
     * Clears all allocations and allows the arena to be reused.
     * Destructors are NOT called on existing objects (no automatic cleanup).
     *
     * Defect: No automatic memory zeroization. After reset, old data may
     * persist in the arena until it is overwritten by new allocations.
     * This is a policy defect: the mechanism is correct, but the lifecycle
     * is the user's responsibility.
     */
    void Reset() noexcept { offset_ = 0; }

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
