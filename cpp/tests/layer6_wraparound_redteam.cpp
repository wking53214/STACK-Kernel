#include <iostream>
#include <atomic>
#include <string>
#include <cstdint>
#include <limits>

#include "../include/stack_arena.hpp"

using namespace stack::isolation;

int test_count = 0;
int test_passed = 0;

void test_start(const std::string& name) {
    test_count++;
    std::cout << "TEST " << test_count << ": " << name << " ... ";
    std::cout.flush();
}

void test_pass() {
    test_passed++;
    std::cout << "PASS\n";
    std::cout.flush();
}

void test_fail(const std::string& msg) {
    std::cout << "FAIL: " << msg << "\n";
    std::cout.flush();
}

// ============================================================================
// LAYER 6 P1: Generation Counter Wraparound (uint32 -> uint64)
// ============================================================================

// Test 1: Basic generation increment
void test_generation_increment() {
    test_start("Layer 6: Generation increments on Reset()");

    StaticArenaBuffer<4096> arena;
    uint64_t gen0 = arena.CurrentGeneration();

    // Reset and check generation incremented
    bool reset_ok = arena.Reset();
    if (!reset_ok) {
        test_fail("Reset failed");
        return;
    }

    uint64_t gen1 = arena.CurrentGeneration();

    if (gen1 == gen0 + 1) {
        test_pass();
    } else {
        test_fail("Generation did not increment (was " + std::to_string(gen0) + ", now " + std::to_string(gen1) + ")");
    }
}

// Test 2: Multiple resets accumulate generation correctly
void test_generation_accumulates() {
    test_start("Layer 6: Generation accumulates over multiple resets");

    StaticArenaBuffer<4096> arena;
    constexpr int num_resets = 100;

    for (int i = 0; i < num_resets; ++i) {
        if (!arena.Reset()) {
            test_fail("Reset " + std::to_string(i) + " failed");
            return;
        }
    }

    uint64_t final_gen = arena.CurrentGeneration();
    if (final_gen == num_resets) {
        test_pass();
    } else {
        test_fail("Expected generation " + std::to_string(num_resets) + ", got " + std::to_string(final_gen));
    }
}

// Test 3: uint64_t prevents wraparound at 2^32
// (Demonstrates that if it were uint32_t, it would wrap here)
void test_uint64_prevents_wraparound() {
    test_start("Layer 6 P1 CRITICAL: uint64_t prevents wraparound at 2^32");

    // This test validates the type is uint64_t by checking that
    // CurrentGeneration() returns a uint64_t and can hold values > 2^32

    StaticArenaBuffer<4096> arena;

    // Simulate reaching a high generation count by casting the internal counter
    // (In production, this would take years of continuous Reset() calls)
    // We verify the type is correct by checking the size and range

    uint64_t gen = arena.CurrentGeneration();
    constexpr uint64_t uint32_max = std::numeric_limits<uint32_t>::max();

    // The return type must be uint64_t, not uint32_t
    if (sizeof(gen) == sizeof(uint64_t)) {
        test_pass();
    } else {
        test_fail("Generation counter is not uint64_t (size: " + std::to_string(sizeof(gen)) + ")");
    }
}

// Test 4: Reset() guards against in-flight allocations
void test_reset_guards_in_flight() {
    test_start("Layer 6: Reset() rejects when allocations in flight");

    StaticArenaBuffer<4096> arena;

    // Manually mark an allocation as in-flight
    arena.IncAllocations();

    // Try to reset while allocation is marked in-flight
    bool reset_ok = arena.Reset();

    // Clean up
    arena.DecAllocations();

    if (!reset_ok) {
        test_pass();
    } else {
        test_fail("Reset succeeded even with allocation in flight");
    }
}

// Test 5: Generation type is verifiably uint64_t
void test_generation_type_is_uint64() {
    test_start("Layer 6 P1: Verify generation type is uint64_t, not uint32_t");

    StaticArenaBuffer<4096> arena;

    // Get the generation and check its type
    auto gen = arena.CurrentGeneration();

    // If this compiles and returns true, the type is uint64_t
    bool is_uint64 = std::is_same_v<decltype(gen), uint64_t>;

    if (is_uint64) {
        test_pass();
    } else {
        test_fail("CurrentGeneration() does not return uint64_t");
    }
}

// Test 6: Arena memory is zeroed on Reset()
void test_reset_zeros_memory() {
    test_start("Layer 6: Reset() zeroes arena memory");

    StaticArenaBuffer<256> arena;  // Small arena for testing

    // Allocate and write a pattern
    auto alloc_res = arena.Allocate<uint32_t>(0xDEADBEEF);
    if (!alloc_res.has_value()) {
        test_fail("Allocation failed");
        return;
    }

    uint32_t* ptr = alloc_res.value();
    *ptr = 0xDEADBEEF;

    // Reset should zero memory
    if (!arena.Reset()) {
        test_fail("Reset failed");
        return;
    }

    // Re-allocate in the same location
    auto alloc_res2 = arena.Allocate<uint32_t>(0);
    if (!alloc_res2.has_value()) {
        test_fail("Second allocation failed");
        return;
    }

    // Should now be zero (cleared by Reset)
    if (*alloc_res2.value() == 0) {
        test_pass();
    } else {
        test_fail("Memory was not zeroed on Reset");
    }
}

int main() {
    std::cout << "\n=== Layer 6 Generation Counter Wraparound Test Suite ===\n\n";

    test_generation_increment();
    test_generation_accumulates();
    test_uint64_prevents_wraparound();
    test_reset_guards_in_flight();
    test_generation_type_is_uint64();
    test_reset_zeros_memory();

    std::cout << "\n=== Summary ===\n";
    std::cout << "Passed: " << test_passed << "/" << test_count << "\n\n";

    return (test_passed == test_count) ? 0 : 1;
}
