#include <iostream>
#include <thread>
#include <vector>
#include <atomic>
#include <string>
#include <chrono>
#include <cassert>

#include "../include/posix_deadline_timer_hardened.hpp"

using namespace stack::governor;

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
// LAYER 2 P1 CRITICAL: Signal Race During Disarm
// ============================================================================

// Test 1: Basic functionality — timer fires and sets flag
void test_signal_fire_basic() {
    test_start("Layer 2: Timer fires and sets preempted flag");

    auto sig_res = HardenedPosixPreemptionGuard::RegisterSignalHandler();
    if (!sig_res.has_value()) {
        test_fail("Failed to register signal handler");
        return;
    }

    auto timer_res = HardenedPosixPreemptionGuard::InitializeThreadTimer();
    if (!timer_res.has_value()) {
        test_fail("Failed to initialize thread timer");
        return;
    }

    HardenedPosixPreemptionGuard guard;
    constexpr uint64_t budget_ns = 10'000'000;  // 10ms
    auto arm_res = guard.Arm(budget_ns);
    if (!arm_res.has_value()) {
        test_fail("Failed to arm timer");
        return;
    }

    // Burn CPU for ~20ms (intentionally exceed the 10ms budget)
    auto start = std::chrono::high_resolution_clock::now();
    while (true) {
        auto now = std::chrono::high_resolution_clock::now();
        auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(now - start).count();
        if (elapsed > 20) break;
        // Busy loop to consume CPU time
        volatile int x = 0;
        for (int i = 0; i < 10000; ++i) x = i;
    }

    // Scope ends, destructor disarms
    bool was_preempted = guard.WasPreempted();

    if (was_preempted) {
        test_pass();
    } else {
        test_fail("Timer did not fire (deadline was not exceeded)");
    }
}

// Test 2: TOCTOU race — signal fires during disarm window (stale state poison)
void test_disarm_race_stale_state_poison() {
    test_start("Layer 2 P1 CRITICAL: Disarm TOCTOU race — stale state poison");

    auto sig_res = HardenedPosixPreemptionGuard::RegisterSignalHandler();
    if (!sig_res.has_value()) {
        test_fail("Failed to register signal handler");
        return;
    }

    auto timer_res = HardenedPosixPreemptionGuard::InitializeThreadTimer();
    if (!timer_res.has_value()) {
        test_fail("Failed to initialize thread timer");
        return;
    }

    bool transaction2_was_poisoned = false;

    // Transaction 1: Deliberately exceed deadline, let destructor disarm
    {
        HardenedPosixPreemptionGuard guard1;
        auto arm_res = guard1.Arm(5'000'000);  // 5ms budget
        if (!arm_res.has_value()) {
            test_fail("Failed to arm timer for transaction 1");
            return;
        }

        // Burn CPU to trigger the deadline
        auto start = std::chrono::high_resolution_clock::now();
        while (true) {
            auto now = std::chrono::high_resolution_clock::now();
            auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(now - start).count();
            if (elapsed > 10) break;
            volatile int x = 0;
            for (int i = 0; i < 10000; ++i) x = i;
        }
        // Destructor runs here, disarms timer, clears preempted flag
    }

    // Transaction 2: Immediately re-use the same guard with a tiny budget
    // If a signal fired during transaction 1's disarm and wasn't cleared,
    // WasPreempted() will report false positive (preempted even though
    // transaction 2 never had a deadline).
    {
        HardenedPosixPreemptionGuard guard2;
        auto arm_res = guard2.Arm(1'000'000'000);  // 1 second (huge budget)
        if (!arm_res.has_value()) {
            test_fail("Failed to arm timer for transaction 2");
            return;
        }

        // Run a quick, non-preemptive payload
        volatile int x = 0;
        for (int i = 0; i < 1000; ++i) x = i;

        // If preempted flag was poisoned from transaction 1's disarm race,
        // WasPreempted() will return true even though we never hit the deadline.
        transaction2_was_poisoned = guard2.WasPreempted();
        // Destructor runs here
    }

    if (!transaction2_was_poisoned) {
        test_pass();
    } else {
        test_fail("DEFECT PRESENT: Transaction 2 was poisoned by stale state from transaction 1's disarm race");
    }
}

// Test 3: Repeated disarm/rearm cycles don't accumulate stale state
void test_repeated_arm_disarm_cycles() {
    test_start("Layer 2: Repeated arm/disarm cycles (10 iterations)");

    auto sig_res = HardenedPosixPreemptionGuard::RegisterSignalHandler();
    if (!sig_res.has_value()) {
        test_fail("Failed to register signal handler");
        return;
    }

    auto timer_res = HardenedPosixPreemptionGuard::InitializeThreadTimer();
    if (!timer_res.has_value()) {
        test_fail("Failed to initialize thread timer");
        return;
    }

    constexpr int num_cycles = 10;
    int poison_count = 0;

    for (int cycle = 0; cycle < num_cycles; ++cycle) {
        HardenedPosixPreemptionGuard guard;
        auto arm_res = guard.Arm(50'000'000);  // 50ms budget
        if (!arm_res.has_value()) {
            test_fail("Failed to arm timer in cycle " + std::to_string(cycle));
            return;
        }

        // Burn CPU to exceed deadline
        auto start = std::chrono::high_resolution_clock::now();
        while (true) {
            auto now = std::chrono::high_resolution_clock::now();
            auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(now - start).count();
            if (elapsed > 60) break;
            volatile int x = 0;
            for (int i = 0; i < 10000; ++i) x = i;
        }

        bool was_preempted = guard.WasPreempted();
        if (!was_preempted) {
            poison_count++;
        }
    }

    if (poison_count == 0) {
        test_pass();
    } else {
        test_fail("Poison detected in " + std::to_string(poison_count) + "/" + std::to_string(num_cycles) + " cycles");
    }
}

// Test 4: Zero-budget transactions don't arm (WasPreempted always false)
void test_zero_budget_never_preempts() {
    test_start("Layer 2: Zero-budget transaction never preempts");

    auto sig_res = HardenedPosixPreemptionGuard::RegisterSignalHandler();
    if (!sig_res.has_value()) {
        test_fail("Failed to register signal handler");
        return;
    }

    auto timer_res = HardenedPosixPreemptionGuard::InitializeThreadTimer();
    if (!timer_res.has_value()) {
        test_fail("Failed to initialize thread timer");
        return;
    }

    HardenedPosixPreemptionGuard guard;
    auto arm_res = guard.Arm(0);  // Zero budget
    if (!arm_res.has_value()) {
        test_fail("Failed to arm with zero budget");
        return;
    }

    bool was_preempted = guard.WasPreempted();
    if (!was_preempted) {
        test_pass();
    } else {
        test_fail("Zero-budget transaction incorrectly reported preemption");
    }
}

// Test 5: Disarm before Arm doesn't crash (destructor guards on timer_initialized)
void test_disarm_before_arm() {
    test_start("Layer 2: Destructor safe before Arm (timer not initialized)");

    {
        HardenedPosixPreemptionGuard guard;
        // Never call Arm()
        // Destructor should check timer_initialized and do nothing
    }

    test_pass();
}

int main() {
    std::cout << "\n=== Layer 2 Red-Team Test Suite ===\n\n";

    test_signal_fire_basic();
    test_disarm_race_stale_state_poison();
    test_repeated_arm_disarm_cycles();
    test_zero_budget_never_preempts();
    test_disarm_before_arm();

    std::cout << "\n=== Summary ===\n";
    std::cout << "Passed: " << test_passed << "/" << test_count << "\n\n";

    return (test_passed == test_count) ? 0 : 1;
}
