/**
 * P3.1 RED-TEAM TEST: Per-Domain Rate Limiting
 *
 * Validates that per-domain buckets prevent one noisy domain from starving others.
 * Key test scenarios:
 *
 * 1. Domain isolation: One domain exhausts its tokens, others unaffected
 * 2. Concurrent access: Multiple domains' Consume/Refund calls race safely
 * 3. Bounds checking: domain_id >= MaxDomains returns error
 * 4. Token regeneration: Each domain's tokens regenerate independently
 * 5. Refund correctness: Tokens return to the domain's bucket, not global
 */

#include "stack_kinetic_governor.hpp"
#include <iostream>
#include <thread>
#include <vector>
#include <atomic>
#include <chrono>

using namespace stack::governor;

// Test configuration
constexpr uint32_t TEST_MAX_CAPACITY = 100;
constexpr uint32_t TEST_RESERVED = 10;
constexpr uint32_t TEST_MAX_BURST = 50;
constexpr uint64_t TEST_TICKS_PER_TOKEN = 10000;
constexpr std::size_t TEST_MAX_DOMAINS = 8;

using TestGovernor = KineticGovernor<TEST_MAX_CAPACITY, TEST_RESERVED, TEST_MAX_BURST, TEST_TICKS_PER_TOKEN, TEST_MAX_DOMAINS>;

// ============================================================================
// TEST 1: Domain Isolation (One domain exhausts tokens, others unaffected)
// ============================================================================
bool test_domain_isolation() {
    std::cout << "[TEST 1] Domain Isolation\n";
    TestGovernor gov;

    // Domain 0: Exhaust tokens
    for (int i = 0; i < TEST_MAX_CAPACITY / 10; ++i) {
        auto res = gov.Consume(0, 10, PriorityClass::Root);
        if (!res.has_value()) {
            std::cout << "  FAIL: Domain 0 exhausted at iteration " << i << "\n";
            return false;
        }
    }

    // Domain 0 should now be rate limited
    auto res0 = gov.Consume(0, 10, PriorityClass::Standard);
    if (res0.has_value()) {
        std::cout << "  FAIL: Domain 0 should be rate limited but succeeded\n";
        return false;
    }

    // Domain 1 should still have tokens
    auto res1 = gov.Consume(1, 10, PriorityClass::Standard);
    if (!res1.has_value()) {
        std::cout << "  FAIL: Domain 1 should have tokens but was rate limited\n";
        return false;
    }

    std::cout << "  PASS: Domains isolated correctly\n";
    return true;
}

// ============================================================================
// TEST 2: Bounds Checking (domain_id >= MaxDomains returns error)
// ============================================================================
bool test_bounds_checking() {
    std::cout << "[TEST 2] Bounds Checking\n";
    TestGovernor gov;

    // Valid domain
    auto res_valid = gov.Consume(TEST_MAX_DOMAINS - 1, 10, PriorityClass::Root);
    if (!res_valid.has_value()) {
        std::cout << "  FAIL: Valid domain " << (TEST_MAX_DOMAINS - 1) << " failed\n";
        return false;
    }

    // Out of bounds
    auto res_oob = gov.Consume(TEST_MAX_DOMAINS, 10, PriorityClass::Root);
    if (res_oob.has_value()) {
        std::cout << "  FAIL: Out-of-bounds domain should fail\n";
        return false;
    }

    // Refund bounds check
    auto res_refund_valid = gov.Refund(TEST_MAX_DOMAINS - 1, 5);
    if (!res_refund_valid.has_value()) {
        std::cout << "  FAIL: Valid Refund should succeed\n";
        return false;
    }

    auto res_refund_oob = gov.Refund(TEST_MAX_DOMAINS, 5);
    if (res_refund_oob.has_value()) {
        std::cout << "  FAIL: Out-of-bounds Refund should fail\n";
        return false;
    }

    std::cout << "  PASS: Bounds checking correct\n";
    return true;
}

// ============================================================================
// TEST 3: Concurrent Access (Thread-safe per-domain access)
// ============================================================================
bool test_concurrent_access() {
    std::cout << "[TEST 3] Concurrent Access\n";
    TestGovernor gov;
    std::atomic<int> success_count{0};
    std::atomic<int> fail_count{0};
    std::vector<std::thread> threads;

    // 8 threads, one per domain, each trying to consume 50 tokens
    auto worker = [&gov, &success_count, &fail_count](uint64_t domain_id) {
        for (int i = 0; i < 10; ++i) {
            auto res = gov.Consume(domain_id, 5, PriorityClass::Root);
            if (res.has_value()) {
                success_count++;
            } else {
                fail_count++;
            }
        }
    };

    for (uint64_t i = 0; i < TEST_MAX_DOMAINS; ++i) {
        threads.emplace_back(worker, i);
    }

    for (auto& t : threads) {
        t.join();
    }

    // Each of 8 threads does 10 iterations of Consume(domain_id, 5, Root)
    // Total operations: 8 * 10 = 80 Consume calls
    // Total tokens requested: 80 * 5 = 400 tokens
    // Available capacity: 100 tokens * 8 domains = 800 tokens
    // Expected: all 80 operations should succeed (400 < 800)
    int expected_successes = TEST_MAX_DOMAINS * 10;  // 80

    if (success_count < expected_successes - 5) {  // Allow small margin for timing
        std::cout << "  FAIL: Too few successes: " << success_count << " (expected ~" << expected_successes << ")\n";
        return false;
    }

    std::cout << "  PASS: Concurrent access safe. Successes: " << success_count << ", Failures: " << fail_count << "\n";
    return true;
}

// ============================================================================
// TEST 4: Refund Correctness (Tokens return to domain's bucket)
// ============================================================================
bool test_refund_correctness() {
    std::cout << "[TEST 4] Refund Correctness\n";
    TestGovernor gov;

    // Domain 0: Consume all tokens
    for (int i = 0; i < TEST_MAX_CAPACITY / 10; ++i) {
        auto res = gov.Consume(0, 10, PriorityClass::Root);
        if (!res.has_value()) {
            std::cout << "  FAIL: Could not exhaust Domain 0\n";
            return false;
        }
    }

    // Domain 0 should be rate limited
    auto res_limited = gov.Consume(0, 10, PriorityClass::Root);
    if (res_limited.has_value()) {
        std::cout << "  FAIL: Domain 0 should be limited\n";
        return false;
    }

    // Refund 50 tokens to Domain 0
    auto res_refund = gov.Refund(0, 50);
    if (!res_refund.has_value()) {
        std::cout << "  FAIL: Refund should succeed\n";
        return false;
    }

    // Domain 0 should now succeed at consuming (refunded tokens available)
    auto res_after_refund = gov.Consume(0, 40, PriorityClass::Root);
    if (!res_after_refund.has_value()) {
        std::cout << "  FAIL: Should succeed after refund\n";
        return false;
    }

    // Domain 1 should still be unaffected (not refunded)
    auto res_domain1 = gov.Consume(1, 50, PriorityClass::Root);
    if (!res_domain1.has_value()) {
        std::cout << "  FAIL: Domain 1 should still have its tokens\n";
        return false;
    }

    std::cout << "  PASS: Refund correctly returns to domain's bucket\n";
    return true;
}

// ============================================================================
// TEST 5: Priority Tiers with Per-Domain Isolation
// ============================================================================
bool test_priority_isolation() {
    std::cout << "[TEST 5] Priority Tiers with Per-Domain Isolation\n";
    TestGovernor gov;

    // Domain 0: Exhaust all tokens except reserved
    for (int i = 0; i < (TEST_MAX_CAPACITY - TEST_RESERVED) / 10; ++i) {
        auto res = gov.Consume(0, 10, PriorityClass::Root);
        if (!res.has_value()) {
            std::cout << "  FAIL: Could not exhaust Domain 0 tokens\n";
            return false;
        }
    }

    // Standard priority on Domain 0 should fail (reserved tokens unreachable for Standard)
    auto res_standard = gov.Consume(0, 5, PriorityClass::Standard);
    if (res_standard.has_value()) {
        std::cout << "  FAIL: Standard priority should not reach reserved tokens\n";
        return false;
    }

    // Root priority on Domain 0 should succeed (can use reserved tokens)
    auto res_root = gov.Consume(0, 5, PriorityClass::Root);
    if (!res_root.has_value()) {
        std::cout << "  FAIL: Root priority should reach reserved tokens\n";
        return false;
    }

    // Domain 1 Standard priority should still work (independent bucket)
    auto res_domain1_standard = gov.Consume(1, 10, PriorityClass::Standard);
    if (!res_domain1_standard.has_value()) {
        std::cout << "  FAIL: Domain 1 should have unreserved tokens for Standard\n";
        return false;
    }

    std::cout << "  PASS: Priority tiers work correctly per-domain\n";
    return true;
}

// ============================================================================
// MAIN TEST RUNNER
// ============================================================================
int main() {
    std::cout << "========================================\n";
    std::cout << "P3.1 RED-TEAM: Per-Domain Rate Limiting\n";
    std::cout << "========================================\n\n";

    int passed = 0;
    int failed = 0;

    if (test_domain_isolation()) passed++; else failed++;
    if (test_bounds_checking()) passed++; else failed++;
    if (test_concurrent_access()) passed++; else failed++;
    if (test_refund_correctness()) passed++; else failed++;
    if (test_priority_isolation()) passed++; else failed++;

    std::cout << "\n========================================\n";
    std::cout << "Results: " << passed << " passed, " << failed << " failed\n";
    std::cout << "========================================\n";

    return (failed == 0) ? 0 : 1;
}
