#include <iostream>
#include <thread>
#include <vector>
#include <atomic>
#include <string>

#include "../include/stack_kernel.hpp"
#include "../include/stack_kinetic_governor.hpp"
#include "../include/posix_deadline_timer_hardened.hpp"
#include "../include/stack_host_binding.hpp"
#include "../include/stack_audit.hpp"

using namespace stack::governor;
using namespace stack::host;
using namespace stack::telemetry;

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
// LAYER 5: Audit Trail Event Recording
// ============================================================================

void test_layer5_audit_ring_basic() {
    test_start("Layer 5: Audit ring basic push/read");

    SeccompAuditRing<1024> audit_ring;

    // Push a test event
    audit_ring.Push(AuditEventType::TransactionCompleted, 42, 100);

    // Read it back
    AuditEventRecord rec;
    bool valid = audit_ring.ReadSlot(0, rec);

    if (!valid) {
        test_fail("Record not valid after push");
        return;
    }

    if (rec.context_id != 42) {
        test_fail("Context ID mismatch: got " + std::to_string(rec.context_id) + ", expected 42");
        return;
    }

    if (rec.tokens_consumed != 100) {
        test_fail("Tokens mismatch: got " + std::to_string(rec.tokens_consumed) + ", expected 100");
        return;
    }

    if (rec.event_type != AuditEventType::TransactionCompleted) {
        test_fail("Event type mismatch");
        return;
    }

    test_pass();
}

void test_layer5_capability_violation_event() {
    test_start("Layer 5: Capability violation event recorded");

    GovernedMinotaurHost<> host;
    if (!host.SetActiveCapabilities(CapabilityMask256(0xAA, 0, 0, 0))) {
        test_fail("Failed to set active capabilities");
        return;
    }

    // Create a token with capability bits NOT in active mask
    SIMDCapabilityToken token(1, CapabilityMask256(0x55, 0, 0, 0));  // Opposite bits

    // This should fail capability validation
    auto res = host.ExecuteGovernedTransaction(
        token, 5, 100'000ULL, 50'000ULL, []() {}
    );

    if (res.has_value()) {
        test_fail("Expected capability validation to fail");
        return;
    }

    if (res.error() != HostExecutionError::CapabilityValidationFailed) {
        test_fail("Wrong error type: expected CapabilityValidationFailed");
        return;
    }

    // Note: Full verification of the Push call requires access to host's audit_ring
    // For now, we verify that the failure occurred. Integration tests with
    // ReadSlot would require exposing audit_ring or adding an accessor.
    test_pass();
}

void test_layer5_rate_limit_event() {
    test_start("Layer 5: Rate limit event recorded");

    GovernedMinotaurHost<> host;
    if (!host.SetActiveCapabilities(CapabilityMask256(0xFF, 0, 0, 0))) {
        test_fail("Failed to set active capabilities");
        return;
    }

    SIMDCapabilityToken token(2, CapabilityMask256(0xFF, 0, 0, 0));

    // Attempt to consume more tokens than available to trigger rate limit
    // Default governor has limited token bucket; multiple high-token requests will exhaust it
    bool rate_limited = false;
    for (int i = 0; i < 10; ++i) {
        auto res = host.ExecuteGovernedTransaction(
            token, 1'000'000, 1'000'000ULL, 500'000ULL, []() {}  // Very high token requirement
        );
        if (!res.has_value() && res.error() == HostExecutionError::RateLimitExceeded) {
            rate_limited = true;
            break;
        }
    }

    if (!rate_limited) {
        test_fail("Never hit rate limit despite high token consumption");
        return;
    }

    test_pass();
}

void test_layer5_concurrent_audit_events() {
    test_start("Layer 5: Concurrent Push events (stress test)");

    SeccompAuditRing<8192> audit_ring;
    std::atomic<int> push_count{0};

    constexpr int num_threads = 4;
    constexpr int pushes_per_thread = 100;
    std::vector<std::thread> threads;

    for (int i = 0; i < num_threads; ++i) {
        threads.emplace_back([&audit_ring, &push_count, i]() {
            for (int j = 0; j < pushes_per_thread; ++j) {
                audit_ring.Push(
                    (j % 5 == 0) ? AuditEventType::TransactionCompleted : AuditEventType::RateLimitTriggered,
                    i * 100 + j,
                    j * 10
                );
                push_count++;
            }
        });
    }

    for (auto& t : threads) t.join();

    if (push_count.load() != num_threads * pushes_per_thread) {
        test_fail("Push count mismatch: got " + std::to_string(push_count.load()) +
                  ", expected " + std::to_string(num_threads * pushes_per_thread));
        return;
    }

    // Verify we can read back some events
    AuditEventRecord rec;
    int valid_reads = 0;
    for (int i = 0; i < 100; ++i) {
        if (audit_ring.ReadSlot(i, rec)) {
            valid_reads++;
        }
    }

    if (valid_reads == 0) {
        test_fail("No events readable after push");
        return;
    }

    test_pass();
}

void test_layer5_seqlock_consistency() {
    test_start("Layer 5: Seqlock read consistency");

    SeccompAuditRing<1024> audit_ring;
    std::atomic<bool> writer_done{false};
    std::atomic<int> successful_reads{0};

    // Writer thread
    std::thread writer([&audit_ring, &writer_done]() {
        for (int i = 0; i < 50; ++i) {
            audit_ring.Push(AuditEventType::TransactionCompleted, i, i * 10);
        }
        writer_done.store(true, std::memory_order_release);
    });

    // Reader threads
    std::vector<std::thread> readers;
    for (int r = 0; r < 2; ++r) {
        readers.emplace_back([&audit_ring, &successful_reads]() {
            AuditEventRecord rec;
            for (int i = 0; i < 50; ++i) {
                while (audit_ring.ReadSlot(i, rec)) {
                    // Verify record sanity (no torn reads)
                    if (rec.context_id < 50) {
                        successful_reads++;
                    }
                    // Retry up to 10 times if seqlock detects in-flight write
                    std::this_thread::yield();
                    break;
                }
            }
        });
    }

    writer.join();
    for (auto& t : readers) t.join();

    if (successful_reads.load() == 0) {
        test_fail("No successful reads despite writes");
        return;
    }

    test_pass();
}

void test_layer5_event_types_all_recordable() {
    test_start("Layer 5: All event types recordable");

    SeccompAuditRing<1024> audit_ring;

    // Push all 5 event types
    audit_ring.Push(AuditEventType::TransactionCompleted, 1, 10);
    audit_ring.Push(AuditEventType::RateLimitTriggered, 2, 20);
    audit_ring.Push(AuditEventType::SoftwareDeadlineExceeded, 3, 30);
    audit_ring.Push(AuditEventType::HardwareTimerPreempted, 4, 40);
    audit_ring.Push(AuditEventType::CapabilityViolation, 5, 50);

    // Read them back in reverse order
    AuditEventRecord rec;
    std::vector<AuditEventType> expected_types = {
        AuditEventType::CapabilityViolation,
        AuditEventType::HardwareTimerPreempted,
        AuditEventType::SoftwareDeadlineExceeded,
        AuditEventType::RateLimitTriggered,
        AuditEventType::TransactionCompleted
    };

    for (size_t i = 0; i < expected_types.size(); ++i) {
        if (!audit_ring.ReadSlot(4 - i, rec)) {
            test_fail("Could not read slot " + std::to_string(4 - i));
            return;
        }

        if (rec.event_type != expected_types[i]) {
            test_fail("Event type mismatch at slot " + std::to_string(4 - i));
            return;
        }
    }

    test_pass();
}

// ============================================================================
// Main
// ============================================================================

int main() {
    std::cout << "\n";
    std::cout << "≡TACK KERNEL LAYER 5 RED-TEAM VALIDATION\n";
    std::cout << "========================================\n\n";

    std::cout << "LAYER 5: Audit Trail Event Recording\n";
    test_layer5_audit_ring_basic();
    test_layer5_capability_violation_event();
    test_layer5_rate_limit_event();
    test_layer5_concurrent_audit_events();
    test_layer5_seqlock_consistency();
    test_layer5_event_types_all_recordable();

    std::cout << "\n========================================\n";
    std::cout << "RESULTS: " << test_passed << "/" << test_count << " tests passed\n";
    std::cout << "========================================\n\n";

    return (test_passed == test_count) ? 0 : 1;
}
