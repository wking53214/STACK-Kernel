#pragma once

#include <cstdint>

#if defined(__x86_64__) || defined(_M_X64)
#include <immintrin.h>
#elif defined(__aarch64__)
#include <arm_neon.h>
#endif

namespace tack::governor {

enum class PriorityClass : uint8_t { Root = 0, Standard = 1 };

// Component 1: Hardware-Locked Tick Sync
struct alignas(64) HardwareClock {
    [[nodiscard]] static inline uint64_t ReadTicks() noexcept {
#if defined(__x86_64__) || defined(_M_X64)
        unsigned int aux;
        return __rdtscp(&aux); // Serializing pipeline read
#elif defined(__aarch64__)
        uint64_t val;
        asm volatile("isb; mrs %0, cntvct_el0" : "=r"(val)); // Serializing barrier
        return val;
#else
        return 0; // Fallback
#endif
    }
};

} // namespace tack::governor
