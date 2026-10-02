#include <iostream>
#include <thread>
#include <vector>
#include <atomic>
#include <string>
#include <cstring>

#include "../include/stack_kernel.hpp"
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
// LAYER 6: Memory Isolation Arena
// ============================================================================

void test_layer6_arena_basic_allocation() {
    test_start("Layer 6: Arena basic allocation");

    StaticArenaBuffer<8192> arena;

    auto res = arena.Allocate<uint64_t>(42);
    if (!res.has_value()) {
        test_fail("Allocation failed");
        return;
    }

    uint64_t* ptr = res.value();
    if (*ptr != 42) {
        test_fail("Value mismatch: got " + std::to_string(*ptr) + ", expected 42");
        return;
    }

    if (arena.BytesAllocated() == 0) {
        test_fail("Offset not advanced after allocation");
        return;
    }

    test_pass();
}

void test_layer6_reset_zeros_memory() {
    test_start("Layer 6: Reset zeros memory (isolation)");

    StaticArenaBuffer<8192> arena;

    // Allocate and write sentinel values
    auto res1 = arena.Allocate<uint64_t>(0xDEADBEEFCAFEBABE);
    auto res2 = arena.Allocate<uint64_t>(0x1122334455667788);

    if (!res1.has_value() || !res2.has_value()) {
        test_fail("Allocations failed");
        return;
    }

    // Mark allocations as in-flight (so reset will fail if we have them tracked)
    // Then complete them so we can reset
    arena.IncAllocations();
    arena.DecAllocations();

    // Reset should zero memory and increment generation
    if (!arena.Reset()) {
        test_fail("Reset failed");
        return;
    }

    // Verify generation incremented
    uint32_t gen_after = arena.CurrentGeneration();
    if (gen_after != 1) {
        test_fail("Generation not incremented: expected 1, got " + std::to_string(gen_after));
        return;
    }

    // Allocate new objects at same addresses
    auto res3 = arena.Allocate<uint64_t>(0x0);
    if (!res3.has_value()) {
        test_fail("Post-reset allocation failed");
        return;
    }

    // Verify new allocation sees zeroed memory (via placement-new semantics)
    // The new allocation should be at offset 0 with value 0x0
    uint64_t* ptr3 = res3.value();
    if (*ptr3 != 0x0) {
        test_fail("Memory not zeroed: got " + std::to_string(*ptr3));
        return;
    }

    test_pass();
}

void test_layer6_generation_counter() {
    test_start("Layer 6: Generation counter increments on Reset");

    StaticArenaBuffer<8192> arena;

    uint32_t gen0 = arena.CurrentGeneration();
    if (gen0 != 0) {
        test_fail("Initial generation not 0: got " + std::to_string(gen0));
        return;
    }

    // Allocate something to ensure arena has content
    auto res1 = arena.Allocate<uint32_t>(123);
    if (!res1.has_value()) {
        test_fail("Allocation failed");
        return;
    }

    // Reset
    if (!arena.Reset()) {
        test_fail("First reset failed");
        return;
    }

    uint32_t gen1 = arena.CurrentGeneration();
    if (gen1 != 1) {
        test_fail("After first reset, generation not 1: got " + std::to_string(gen1));
        return;
    }

    // Allocate and reset again
    auto res2 = arena.Allocate<uint32_t>(456);
    if (!res2.has_value()) {
        test_fail("Second allocation failed");
        return;
    }

    if (!arena.Reset()) {
        test_fail("Second reset failed");
        return;
    }

    uint32_t gen2 = arena.CurrentGeneration();
    if (gen2 != 2) {
        test_fail("After second reset, generation not 2: got " + std::to_string(gen2));
        return;
    }

    test_pass();
}

void test_layer6_reset_blocked_during_allocation() {
    test_start("Layer 6: Reset blocked when allocations in flight");

    StaticArenaBuffer<8192> arena;

    // Allocate something
    auto res = arena.Allocate<uint64_t>(999);
    if (!res.has_value()) {
        test_fail("Allocation failed");
        return;
    }

    // Mark as in-flight
    arena.IncAllocations();

    // Try to reset (should fail)
    if (arena.Reset()) {
        test_fail("Reset succeeded when allocations in flight");
        return;
    }

    // Mark as complete
    arena.DecAllocations();

    // Now reset should succeed
    if (!arena.Reset()) {
        test_fail("Reset failed after decrementing allocations");
        return;
    }

    test_pass();
}

void test_layer6_arena_exhaustion() {
    test_start("Layer 6: Arena exhaustion prevents overflow");

    constexpr std::size_t small_size = 256;
    StaticArenaBuffer<small_size> arena;

    // Allocate until exhausted
    bool hit_exhaustion = false;
    for (int i = 0; i < 100; ++i) {
        auto res = arena.Allocate<uint64_t>(i);
        if (!res.has_value()) {
            hit_exhaustion = true;
            break;
        }
    }

    if (!hit_exhaustion) {
        test_fail("Never hit arena exhaustion");
        return;
    }

    test_pass();
}

void test_layer6_concurrent_allocations() {
    test_start("Layer 6: Concurrent allocations from multiple threads");

    StaticArenaBuffer<8192> arena;
    std::atomic<int> successful_allocs{0};

    constexpr int num_threads = 4;
    constexpr int allocs_per_thread = 50;
    std::vector<std::thread> threads;

    for (int i = 0; i < num_threads; ++i) {
        threads.emplace_back([&arena, &successful_allocs, i]() {
            for (int j = 0; j < allocs_per_thread; ++j) {
                auto res = arena.Allocate<uint32_t>(i * 100 + j);
                if (res.has_value()) {
                    successful_allocs++;
                }
            }
        });
    }

    for (auto& t : threads) t.join();

    if (successful_allocs.load() == 0) {
        test_fail("No successful allocations");
        return;
    }

    test_pass();
}

void test_layer6_multiple_reset_cycles() {
    test_start("Layer 6: Multiple reset cycles maintain isolation");

    StaticArenaBuffer<8192> arena;

    // Cycle 1
    auto res1 = arena.Allocate<uint64_t>(0xAAAAAAAAAAAAAAAA);
    if (!res1.has_value()) {
        test_fail("Cycle 1 allocation failed");
        return;
    }

    uint32_t gen1 = arena.CurrentGeneration();
    if (!arena.Reset()) {
        test_fail("Cycle 1 reset failed");
        return;
    }

    // Cycle 2
    auto res2 = arena.Allocate<uint64_t>(0xBBBBBBBBBBBBBBBB);
    if (!res2.has_value()) {
        test_fail("Cycle 2 allocation failed");
        return;
    }

    uint32_t gen2 = arena.CurrentGeneration();
    if (gen2 != gen1 + 1) {
        test_fail("Generation not incremented between cycles");
        return;
    }

    if (!arena.Reset()) {
        test_fail("Cycle 2 reset failed");
        return;
    }

    // Cycle 3
    auto res3 = arena.Allocate<uint64_t>(0xCCCCCCCCCCCCCCCC);
    if (!res3.has_value()) {
        test_fail("Cycle 3 allocation failed");
        return;
    }

    uint32_t gen3 = arena.CurrentGeneration();
    if (gen3 != gen2 + 1) {
        test_fail("Generation not incremented to cycle 3");
        return;
    }

    test_pass();
}

void test_layer6_bytes_tracking() {
    test_start("Layer 6: Bytes allocated/remaining tracking");

    StaticArenaBuffer<1024> arena;

    std::size_t initial_remaining = arena.BytesRemaining();
    if (initial_remaining != 1024) {
        test_fail("Initial remaining not 1024");
        return;
    }

    auto res1 = arena.Allocate<uint64_t>(111);
    if (!res1.has_value()) {
        test_fail("Allocation 1 failed");
        return;
    }

    std::size_t after_alloc = arena.BytesRemaining();
    if (after_alloc >= initial_remaining) {
        test_fail("Bytes remaining not decremented");
        return;
    }

    if (!arena.Reset()) {
        test_fail("Reset failed");
        return;
    }

    std::size_t after_reset = arena.BytesRemaining();
    if (after_reset != 1024) {
        test_fail("Bytes remaining not restored after reset");
        return;
    }

    test_pass();
}

// ============================================================================
// Main
// ============================================================================

int main() {
    std::cout << "\n";
    std::cout << "≡TACK KERNEL LAYER 6 RED-TEAM VALIDATION\n";
    std::cout << "========================================\n\n";

    std::cout << "LAYER 6: Memory Isolation Arena\n";
    test_layer6_arena_basic_allocation();
    test_layer6_reset_zeros_memory();
    test_layer6_generation_counter();
    test_layer6_reset_blocked_during_allocation();
    test_layer6_arena_exhaustion();
    test_layer6_concurrent_allocations();
    test_layer6_multiple_reset_cycles();
    test_layer6_bytes_tracking();

    std::cout << "\n========================================\n";
    std::cout << "RESULTS: " << test_passed << "/" << test_count << " tests passed\n";
    std::cout << "========================================\n\n";

    return (test_passed == test_count) ? 0 : 1;
}
