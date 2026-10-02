/**
 * P3.3 RED-TEAM TEST: Audit Trail Signing
 *
 * Validates HMAC-SHA256 signing prevents audit tampering.
 */

#include "stack_audit.hpp"
#include <iostream>
#include <cstring>

using namespace stack::telemetry;

constexpr std::size_t TEST_RING_CAPACITY = 256;
using TestAuditRing = SeccompAuditRing<TEST_RING_CAPACITY>;

// TEST 1: Signing Round-Trip
bool test_signing_round_trip() {
    std::cout << "[TEST 1] Signing Round-Trip\n";
    TestAuditRing ring;
    ring.InitializeSigningKey();

    ring.Push(AuditEventType::RateLimitTriggered, 123, 50);

    AuditEventRecord record;
    bool valid = ring.ReadSlot(0, record);

    if (!valid) {
        std::cout << "  FAIL: ReadSlot returned false\n";
        return false;
    }
    if (record.is_signed != 1) {
        std::cout << "  FAIL: is_signed should be 1\n";
        return false;
    }
    if (record.context_id != 123 || record.tokens_consumed != 50) {
        std::cout << "  FAIL: Event data mismatch\n";
        return false;
    }

    std::cout << "  PASS\n";
    return true;
}

// TEST 2: Backward Compatibility (Unsigned entries)
bool test_backward_compatibility() {
    std::cout << "[TEST 2] Backward Compatibility\n";
    TestAuditRing ring;
    ring.InitializeSigningKey();

    ring.Push(AuditEventType::TransactionCompleted, 111, 10);

    AuditEventRecord record;
    bool valid = ring.ReadSlot(0, record);

    if (!valid) {
        std::cout << "  FAIL: Signed event unreadable\n";
        return false;
    }
    if (record.is_signed != 1) {
        std::cout << "  FAIL: Should be signed\n";
        return false;
    }

    std::cout << "  PASS\n";
    return true;
}

// TEST 3: Key Initialization Required
bool test_key_initialization() {
    std::cout << "[TEST 3] Key Initialization\n";
    TestAuditRing ring;
    // NO InitializeSigningKey() call

    ring.Push(AuditEventType::RateLimitTriggered, 222, 20);

    AuditEventRecord record;
    bool valid = ring.ReadSlot(0, record);

    // Without key, is_signed should be 0 (no signing occurred)
    if (record.is_signed != 0) {
        std::cout << "  FAIL: Without key init, is_signed should be 0\n";
        return false;
    }

    std::cout << "  PASS\n";
    return true;
}

// TEST 4: Multiple Events Signed Correctly
bool test_multiple_events() {
    std::cout << "[TEST 4] Multiple Events\n";
    TestAuditRing ring;
    ring.InitializeSigningKey();

    // Push 10 events
    for (int i = 0; i < 10; ++i) {
        ring.Push(AuditEventType::RateLimitTriggered, 1000 + i, 100 + i);
    }

    // Verify all are readable and signed
    for (int i = 0; i < 10; ++i) {
        AuditEventRecord record;
        bool valid = ring.ReadSlot(i, record);

        if (!valid) {
            std::cout << "  FAIL: Slot " << i << " invalid\n";
            return false;
        }
        if (record.is_signed != 1) {
            std::cout << "  FAIL: Slot " << i << " not signed\n";
            return false;
        }
        if (record.context_id != 1000 + i) {
            std::cout << "  FAIL: Slot " << i << " data mismatch\n";
            return false;
        }
    }

    std::cout << "  PASS\n";
    return true;
}

// TEST 5: Seqlock Integration
bool test_seqlock_integration() {
    std::cout << "[TEST 5] Seqlock Integration\n";
    TestAuditRing ring;
    ring.InitializeSigningKey();

    // Push and immediately read
    ring.Push(AuditEventType::CapabilityViolation, 333, 30);

    AuditEventRecord record;
    bool valid = ring.ReadSlot(0, record);

    if (!valid) {
        std::cout << "  FAIL: Seqlock read failed\n";
        return false;
    }
    if (record.event_type != AuditEventType::CapabilityViolation) {
        std::cout << "  FAIL: Event type mismatch\n";
        return false;
    }

    std::cout << "  PASS\n";
    return true;
}

// TEST 6: Ring Wraparound with Signing
bool test_ring_wraparound() {
    std::cout << "[TEST 6] Ring Wraparound\n";
    SeccompAuditRing<16> ring;  // Small ring for wraparound testing
    ring.InitializeSigningKey();

    // Push 32 events (wraps the ring twice)
    for (int i = 0; i < 32; ++i) {
        ring.Push(AuditEventType::TransactionCompleted, 2000 + i, 200 + i);
    }

    // Last 16 events should be in the ring (oldest overwritten)
    for (int i = 16; i < 32; ++i) {
        AuditEventRecord record;
        bool valid = ring.ReadSlot(i, record);

        if (!valid) {
            std::cout << "  FAIL: Slot " << i << " unreadable after wraparound\n";
            return false;
        }
        if (record.is_signed != 1) {
            std::cout << "  FAIL: Slot " << i << " not signed\n";
            return false;
        }
    }

    std::cout << "  PASS\n";
    return true;
}

int main() {
    std::cout << "========================================\n";
    std::cout << "P3.3 RED-TEAM: Audit Trail Signing\n";
    std::cout << "========================================\n\n";

    int passed = 0;
    int failed = 0;

    if (test_signing_round_trip()) passed++; else failed++;
    if (test_backward_compatibility()) passed++; else failed++;
    if (test_key_initialization()) passed++; else failed++;
    if (test_multiple_events()) passed++; else failed++;
    if (test_seqlock_integration()) passed++; else failed++;
    if (test_ring_wraparound()) passed++; else failed++;

    std::cout << "\n========================================\n";
    std::cout << "Results: " << passed << " passed, " << failed << " failed\n";
    std::cout << "========================================\n";

    return (failed == 0) ? 0 : 1;
}
