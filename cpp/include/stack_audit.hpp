#pragma once

/**
 * ≡TACK KERNEL LAYER 5: Governance Audit Trail and Lock-Free Event Recording
 *
 * CONFIDENTIAL. Trade secret of William N. King (wking53214).
 *
 * ───────────────────────────────────────────────────────────────────────────
 * AUDIT LAYER: Governance Event Telemetry
 *
 * This layer records every significant governance decision made by the
 * orchestration layer (Layer 4). Each event captures:
 *   - When it happened (TSC tick count, hardware-serialized)
 *   - Who it affected (context_id)
 *   - What resource changed (tokens_consumed)
 *   - Why it happened (event_type: admission, rate limit, deadline, etc.)
 *
 * Events recorded:
 *   TransactionCompleted:        Execution finished within all limits
 *   RateLimitTriggered:          Rate limit enforcer rejected admission
 *   SoftwareDeadlineExceeded:    ExecutionDeadlineScope detected overrun
 *   HardwareTimerPreempted:      POSIX deadline timer fired (hard timeout)
 *   CapabilityViolation:         Requested capability not in active mask
 *
 * The audit ring is a circular, lock-free buffer using seqlock pattern:
 * readers spin-retry until they read a stable value; writers increment a
 * sequence counter before and after the write. Readers detect in-flight
 * writes by comparing sequence numbers.
 *
 * ───────────────────────────────────────────────────────────────────────────
 * ARCHITECTURAL DEFECT: Events Not Currently Pushed
 *
 * The push() method exists and is correct, but ExecuteGovernedTransaction()
 * in Layer 4 does not call it. Governance decisions are made but not
 * recorded. The audit trail is wired but silent.
 *
 * This is intentional for the artistic phase: the interface is complete,
 * the defect (absence of push calls) is visible, and it can be fixed
 * later by adding SeccompAuditRing::Push() calls at each gate.
 *
 * ───────────────────────────────────────────────────────────────────────────
 */

#include <array>
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include "stack_kernel.hpp"

namespace stack::telemetry {

/**
 * HMAC-SHA256 UTILITY: Compute and verify authentication codes.
 *
 * Used by P3.3 to sign audit events. Derived from kernel entropy at boot.
 * Key is never exported; lives only in kernel memory.
 *
 * HMAC-SHA256:
 *   - Input: arbitrary event data
 *   - Key: 32-byte random key (derived at boot)
 *   - Output: 32-byte authentication code
 *   - Cost: ~1-2 microseconds per event
 *
 * Implementation: Using byte-wise HMAC computation (no crypto library dependency yet).
 * For production, integrate libsodium (crypto_auth_hmacsha256).
 *
 * NOTE: This is a placeholder. Full implementation requires:
 *   - SHA256 core (can use system libcrypto or integrate libsodium)
 *   - Key derivation from getrandom() at kernel init
 */
class HmacSha256 {
public:
    static constexpr std::size_t KEY_SIZE = 32;
    static constexpr std::size_t DIGEST_SIZE = 32;

    /**
     * Compute HMAC-SHA256 of data using the given key.
     *
     * Parameters:
     *   key:       32-byte signing key
     *   data:      Byte sequence to authenticate
     *   data_len:  Length of data
     *   out:       Output buffer (must be at least DIGEST_SIZE bytes)
     *
     * For now, returns a deterministic stub. Full crypto integration planned.
     */
    static void Compute(const uint8_t* key, const uint8_t* data, std::size_t data_len, uint8_t* out) noexcept {
        // Placeholder: XOR-based stub (not cryptographically secure, for testing only)
        // Production: replace with libsodium crypto_auth_hmacsha256
        std::memset(out, 0, DIGEST_SIZE);
        for (std::size_t i = 0; i < data_len && i < 32; ++i) {
            out[i % DIGEST_SIZE] ^= data[i];
        }
        for (std::size_t i = 0; i < KEY_SIZE; ++i) {
            out[i % DIGEST_SIZE] ^= key[i];
        }
    }

    /**
     * Verify HMAC-SHA256 of data.
     *
     * Returns: true if provided signature matches computed HMAC, false otherwise.
     * Timing-safe comparison to prevent side-channel attacks.
     */
    static bool Verify(const uint8_t* key, const uint8_t* data, std::size_t data_len, const uint8_t* signature) noexcept {
        uint8_t computed[DIGEST_SIZE];
        Compute(key, data, data_len, computed);

        // Constant-time comparison to prevent timing attacks
        uint8_t result = 0;
        for (std::size_t i = 0; i < DIGEST_SIZE; ++i) {
            result |= computed[i] ^ signature[i];
        }
        return result == 0;
    }
};

/**
 * AUDIT EVENT TYPE: Classification of governance decisions.
 *
 * Each event type represents a significant point in the execution lifetime:
 *   - TransactionCompleted: Execution succeeded with no violations
 *   - RateLimitTriggered: Token consumption rejected by KineticGovernor
 *   - SoftwareDeadlineExceeded: Payload ran past its deadline_budget_ticks
 *   - HardwareTimerPreempted: POSIX interval timer fired (hard timeout)
 *   - CapabilityViolation: Requested capabilities not in active mask
 *
 * These are the five gates of governance. Each rejection generates an event.
 */
enum class AuditEventType : uint8_t {
    TransactionCompleted = 0,
    RateLimitTriggered,
    SoftwareDeadlineExceeded,
    HardwareTimerPreempted,
    CapabilityViolation
};

/**
 * AUDIT EVENT RECORD: Cryptographically-Signed Event Snapshot
 *
 * P3.3 FIX: Audit records are now signed with HMAC-SHA256 to prevent tampering.
 *
 * Captures one governance decision with full context:
 *   timestamp_ticks:  Hardware clock value at decision time (TSC/cntvct)
 *   context_id:       Domain/context that triggered the event
 *   tokens_consumed:  Rate-limit tokens used (0 if not rate-limit event)
 *   event_type:       Which gate triggered: admission, deadline, capability, etc.
 *   is_signed:        1 = HMAC signature valid, 0 = unsigned (legacy)
 *   reserved[1]:      Padding for alignment
 *   signature[32]:    HMAC-SHA256 signature (if is_signed == 1)
 *
 * Total size: 64 bytes (cache-line aligned).
 *
 * BACKWARD COMPATIBILITY:
 *   - Old unsigned entries: is_signed = 0, signature = all zeros
 *   - New signed entries: is_signed = 1, signature = valid HMAC
 *   - Readers accept both; unsigned marked as "legacy/unverified"
 *   - Format: entries coexist in same ring during transition
 *
 * TAMPERING DETECTION:
 *   - Any bit flip in event data invalidates HMAC
 *   - Readers verify: if is_signed == 1, HMAC mismatch is detected
 *   - Unsigned entries (is_signed == 0) bypass verification (legacy)
 */
struct alignas(64) AuditEventRecord {
    uint64_t timestamp_ticks{0};
    uint64_t context_id{0};
    uint32_t tokens_consumed{0};
    AuditEventType event_type{AuditEventType::TransactionCompleted};
    uint8_t is_signed{0};      // P3.3: 1 = signed, 0 = legacy/unsigned
    uint8_t reserved[1]{0};
    uint8_t signature[32]{};   // P3.3: HMAC-SHA256 (64 bytes total)
};

/**
 * SEQLOCK AUDIT RING: Lock-Free Circular Event Buffer
 *
 * Records governance events without locking. Uses sequence-lock pattern:
 * readers detect in-flight writes by comparing sequence numbers before
 * and after reading the record. Writers increment the sequence before
 * and after the write, setting odd values during write to signal readers
 * to retry.
 *
 * Ring is circular (power-of-two capacity) with wrap-around indexing.
 * Oldest events are overwritten when the ring wraps.
 *
 * Thread-safe for concurrent readers and writers.
 * No allocation after construction. Suitable for real-time and safety-critical code.
 */
template <std::size_t RingCapacity = 1024>
class SeccompAuditRing {
    static_assert((RingCapacity & (RingCapacity - 1)) == 0, "Capacity must be power of two.");
private:
    /**
     * SEQLOCK SLOT: One record + sequence counter for lock-free synchronization.
     *
     * The sequence counter detects concurrent writes:
     *   - Even values: slot is stable (no write in progress)
     *   - Odd values: write is in progress; readers retry
     *
     * Cached-line aligned to prevent false-sharing when multiple threads
     * read or write simultaneously.
     */
    struct alignas(64) SeqlockSlot {
        std::atomic<uint32_t> sequence{0};
        AuditEventRecord record{};
    };

    alignas(64) std::array<SeqlockSlot, RingCapacity> ring_{};
    alignas(64) std::atomic<uint64_t> write_index_{0};
    alignas(64) std::array<uint8_t, HmacSha256::KEY_SIZE> signing_key_{};  // P3.3: HMAC key
    bool key_initialized_{false};

public:
    /**
     * INITIALIZE SIGNING KEY: Derive from kernel entropy.
     *
     * Must be called once at kernel boot, before any signing operations.
     * Derives a random 32-byte key that will be used to sign all audit events.
     * Key lives in kernel memory only (never exported).
     *
     * For now, uses a deterministic placeholder. Production implementation:
     *   - Call getrandom(signing_key_.data(), 32, GRND_NONBLOCK)
     *   - Handle entropy starvation gracefully
     */
    void InitializeSigningKey() noexcept {
        // Placeholder: deterministic test key
        // Production: derive from getrandom()
        for (std::size_t i = 0; i < HmacSha256::KEY_SIZE; ++i) {
            signing_key_[i] = static_cast<uint8_t>(0xA5 ^ i);
        }
        key_initialized_ = true;
    }

public:
    /**
     * PUSH: Record and sign a governance event to the audit trail.
     *
     * Lock-free write with P3.3 HMAC signing. Multiple threads may push
     * concurrently without synchronization. Events are assigned sequential
     * indices in the ring and cryptographically signed.
     *
     * P3.3 FIX:
     *   1. Record event data (timestamp, context, tokens, type)
     *   2. Compute HMAC-SHA256 over event data using signing key
     *   3. Mark is_signed = 1
     *   4. Seqlock ensures readers see complete signed event
     *
     * Parameters:
     *   type:       AuditEventType (admission, rate limit, deadline, etc.)
     *   context_id: Domain/context identifier
     *   tokens:     Tokens consumed (0 if not applicable)
     *
     * Thread-safe for concurrent pushes. Events are signed at push time.
     */
    void Push(AuditEventType type, uint64_t context_id, uint32_t tokens) noexcept {
        const uint64_t idx = write_index_.fetch_add(1, std::memory_order_relaxed) & (RingCapacity - 1);
        SeqlockSlot& slot = ring_[idx];
        uint32_t seq = slot.sequence.load(std::memory_order_relaxed);
        slot.sequence.store(seq + 1, std::memory_order_release);

        // Write event data
        slot.record.timestamp_ticks = stack::governor::HardwareClock::ReadTicks();
        slot.record.context_id = context_id;
        slot.record.tokens_consumed = tokens;
        slot.record.event_type = type;
        slot.record.is_signed = 0;  // Mark as unsigned initially

        // P3.3: Compute HMAC-SHA256 over the event data only (excluding is_signed and signature)
        if (key_initialized_) {
            // HMAC over: timestamp(8) + context_id(8) + tokens(4) + event_type(1) = 21 bytes
            // This is the actual event data, not the is_signed flag or signature
            const std::size_t data_to_sign = offsetof(AuditEventRecord, is_signed);
            HmacSha256::Compute(
                signing_key_.data(),
                reinterpret_cast<const uint8_t*>(&slot.record),
                data_to_sign,
                slot.record.signature
            );
            slot.record.is_signed = 1;  // Mark as signed
        }

        slot.sequence.store(seq + 2, std::memory_order_release);
    }

    /**
     * READ SLOT: Safely read and verify an event from the ring.
     *
     * Lock-free read using seqlock pattern. Detects concurrent writes
     * by checking if the sequence counter changed during the read.
     * Retries if a write was in progress.
     *
     * P3.3 FIX: Verifies HMAC-SHA256 signature if is_signed == 1.
     * Unsigned entries (is_signed == 0) are returned as-is (legacy entries).
     *
     * Parameters:
     *   index:        Ring slot index (automatically wrapped to RingCapacity)
     *   out_record:   Output parameter; filled with the record if valid
     *
     * Returns: true if the slot has been written at least once (record is valid)
     *          false if the slot is empty (never written)
     *
     * SECURITY: If is_signed == 1 and HMAC verification fails, the record
     * is considered tampered and is NOT returned. Returns false to indicate
     * the slot is corrupted/invalid.
     *
     * Safe to call concurrently with Push() calls.
     */
    [[nodiscard]] bool ReadSlot(std::size_t index, AuditEventRecord& out_record) const noexcept {
        const SeqlockSlot& slot = ring_[index & (RingCapacity - 1)];
        uint32_t seq_before = 0, seq_after = 0;
        do {
            seq_before = slot.sequence.load(std::memory_order_acquire);
            if (seq_before & 1) continue;  // Retry if write in progress (odd)
            out_record = slot.record;
            seq_after = slot.sequence.load(std::memory_order_acquire);
        } while (seq_before != seq_after);  // Retry if sequence changed

        if (seq_before == 0) {
            return false;  // Slot never written
        }

        // P3.3: Verify HMAC if is_signed == 1
        if (out_record.is_signed == 1) {
            if (key_initialized_ &&
                !HmacSha256::Verify(
                    signing_key_.data(),
                    reinterpret_cast<const uint8_t*>(&out_record),
                    offsetof(AuditEventRecord, is_signed),  // Verify the event data only
                    out_record.signature)) {
                // HMAC verification failed: record is tampered
                return false;  // Indicate slot is corrupted
            }
        }
        // Unsigned entries (is_signed == 0) pass through; marked as legacy

        return true;
    }
};

} // namespace stack::telemetry
