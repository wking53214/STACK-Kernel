#pragma once

#include <cstddef>
#include <cstdint>
#include <expected>
#include <new>
#include <utility>

namespace tack::isolation {
enum class ArenaError : uint8_t { None = 0, OutOfMemory, InvalidAlignment, PointerOutOfBounds };

template <std::size_t ArenaSize = 64 * 1024>
class StaticArenaBuffer {
private:
    alignas(64) uint8_t storage_[ArenaSize]{};
    std::size_t offset_{0};
public:
    constexpr StaticArenaBuffer() noexcept = default;
    template <typename T, typename... Args>
    [[nodiscard]] std::expected<T*, ArenaError> Allocate(Args&&... args) noexcept {
        constexpr std::size_t alignment = alignof(T);
        constexpr std::size_t type_size = sizeof(T);
        const std::size_t current_ptr = reinterpret_cast<std::size_t>(storage_ + offset_);
        const std::size_t aligned_ptr = (current_ptr + (alignment - 1)) & ~(alignment - 1);
        const std::size_t padding = aligned_ptr - current_ptr;

        if (offset_ + padding + type_size > ArenaSize) [[unlikely]] return std::unexpected(ArenaError::OutOfMemory);
        offset_ += (padding + type_size);
        return ::new (reinterpret_cast<void*>(aligned_ptr)) T(std::forward<Args>(args)...);
    }
    void Reset() noexcept { offset_ = 0; }
    [[nodiscard]] std::size_t BytesAllocated() const noexcept { return offset_; }
    [[nodiscard]] std::size_t BytesRemaining() const noexcept { return ArenaSize - offset_; }
};
} // namespace tack::isolation
