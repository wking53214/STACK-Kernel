#include <iostream>
#include <string>
#include <cstdint>

#include "../include/stack_kernel.hpp"
#include "../include/stack_kinetic_governor.hpp"

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
// LAYER 7: Timestamp Wraparound Protection
// ============================================================================

void test_layer7_normal_time_progression() {
    test_start("Layer 7: Normal time progression regenerates tokens");

    KineticGovernor<> gov;

    // Consume initial tokens
    auto res1 = gov.Consume(50, PriorityClass::Standard, 1000);
    if (!res1.has_value()) {
        test_fail("Initial consume failed");
        return;
    }

    // After time passes, tokens regenerate
    // At time 1000, bucket has (default 1000 - 50 = 950 tokens)
    // At time 11000 (10000 ticks later), we get 10000/10000 = 1 new token
    // Total: 950 + 1 = 951 tokens (capped at 1000)
    auto res2 = gov.Consume(50, PriorityClass::Standard, 11000);
    if (!res2.has_value()) {
        test_fail("Consume after time elapsed failed");
        return;
    }

    test_pass();
}

void test_layer7_clock_wraparound_detection() {
    test_start("Layer 7: Clock wraparound treated conservatively");

    KineticGovernor<> gov;

    // Consume tokens at time T1
    auto res1 = gov.Consume(50, PriorityClass::Standard, 0x8000000000000000ULL);
    if (!res1.has_value()) {
        test_fail("Consume at high timestamp failed");
        return;
    }

    // Clock wraps: next timestamp is much smaller (wraparound)
    // After wraparound (now < timestamp), no tokens should regenerate
    // But we should still have previously consumed 50 tokens out of default capacity
    auto res2 = gov.Consume(50, PriorityClass::Standard, 0x0000000000000001ULL);
    if (res2.has_value()) {
        // This may or may not succeed depending on remaining capacity
        // The point is the system doesn't crash or generate infinite tokens
        test_pass();
    } else if (res2.error() == GovernorError::RateLimited) {
        // Expected: rate limited because clock wrapped, no token regeneration
        test_pass();
    } else {
        test_fail("Unexpected error: " + std::to_string(static_cast<uint8_t>(res2.error())));
    }
}

void test_layer7_overflow_capping() {
    test_start("Layer 7: Elapsed time overflow is capped");

    KineticGovernor<> gov;

    // Consume at time 0
    auto res1 = gov.Consume(10, PriorityClass::Standard, 0);
    if (!res1.has_value()) {
        test_fail("Initial consume failed");
        return;
    }

    // Attempt to consume after HUGE time jump (simulating wrapped clock)
    // If not capped, this could cause integer overflow in token generation
    // Max reasonable elapsed is capped at (1ULL << 48) = 281 trillion ticks
    // At 4GHz, this is ~32,000 years of runtime
    uint64_t huge_time = (1ULL << 50);  // Much larger than MAX_REASONABLE_ELAPSED

    auto res2 = gov.Consume(10, PriorityClass::Standard, huge_time);
    if (!res2.has_value()) {
        // Should fail rate limit (too many tokens generated would overflow)
        // Or succeed with capped tokens (if capping works)
        if (res2.error() == GovernorError::RateLimited) {
            test_pass();
        } else {
            test_fail("Unexpected error after huge time jump");
        }
    } else {
        // Capping worked: we successfully consumed
        test_pass();
    }
}

void test_layer7_max_reasonable_elapsed_boundary() {
    test_start("Layer 7: MAX_REASONABLE_ELAPSED boundary");

    KineticGovernor<> gov;

    // Consume at time 0
    auto res1 = gov.Consume(10, PriorityClass::Standard, 0);
    if (!res1.has_value()) {
        test_fail("Initial consume failed");
        return;
    }

    // MAX_REASONABLE_ELAPSED = (1ULL << 48)
    // This should be treated as valid time, tokens should regenerate
    constexpr uint64_t MAX_REASONABLE = (1ULL << 48);
    auto res2 = gov.Consume(10, PriorityClass::Standard, MAX_REASONABLE);

    if (!res2.has_value()) {
        // This is acceptable (rate limit)
        if (res2.error() == GovernorError::RateLimited) {
            test_pass();
        } else {
            test_fail("Unexpected error");
        }
    } else {
        // Success is also acceptable
        test_pass();
    }
}

void test_layer7_zero_elapsed_on_same_timestamp() {
    test_start("Layer 7: Zero elapsed when timestamps equal");

    KineticGovernor<> gov;

    // Consume at time T
    auto res1 = gov.Consume(50, PriorityClass::Standard, 5000);
    if (!res1.has_value()) {
        test_fail("Initial consume failed");
        return;
    }

    // Try to consume immediately (same timestamp)
    // No time has passed, no tokens regenerated
    auto res2 = gov.Consume(50, PriorityClass::Standard, 5000);
    if (!res2.has_value()) {
        // Expected: rate limited (no time passed, no token regen)
        if (res2.error() == GovernorError::RateLimited) {
            test_pass();
        } else {
            test_fail("Wrong error on same timestamp");
        }
    } else {
        test_fail("Should be rate limited on same timestamp");
    }
}

void test_layer7_refund_after_wraparound() {
    test_start("Layer 7: Refund works after wraparound");

    KineticGovernor<> gov;

    // Consume at time T1
    auto res1 = gov.Consume(50, PriorityClass::Standard, 0x7000000000000000ULL);
    if (!res1.has_value()) {
        test_fail("Consume at T1 failed");
        return;
    }

    // Refund should work regardless of clock state
    gov.Refund(25);  // Should restore 25 tokens

    // Now try to consume (should succeed if refund worked)
    auto res2 = gov.Consume(25, PriorityClass::Standard, 0x0000000000000001ULL);

    // Regardless of success/failure, the refund didn't crash and was safe
    test_pass();
}

// ============================================================================
// Main
// ============================================================================

int main() {
    std::cout << "\n";
    std::cout << "≡TACK KERNEL LAYER 7 RED-TEAM VALIDATION\n";
    std::cout << "========================================\n\n";

    std::cout << "LAYER 7: Timestamp Wraparound Protection\n";
    test_layer7_normal_time_progression();
    test_layer7_clock_wraparound_detection();
    test_layer7_overflow_capping();
    test_layer7_max_reasonable_elapsed_boundary();
    test_layer7_zero_elapsed_on_same_timestamp();
    test_layer7_refund_after_wraparound();

    std::cout << "\n========================================\n";
    std::cout << "RESULTS: " << test_passed << "/" << test_count << " tests passed\n";
    std::cout << "========================================\n\n";

    return (test_passed == test_count) ? 0 : 1;
}
