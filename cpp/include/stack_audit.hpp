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
#include "stack_kernel.hpp"

namespace stack::telemetry {

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
 * AUDIT EVENT RECORD: Immutable event snapshot.
 *
 * Captures one governance decision with full context:
 *   timestamp_ticks:  Hardware clock value at decision time (TSC/cntvct)
 *   context_id:       Domain/context that triggered the event
 *   tokens_consumed:  Rate-limit tokens used (0 if not rate-limit event)
 *   event_type:       Which gate triggered: admission, deadline, capability, etc.
 *   reserved[3]:      Padding for alignment and future use
 *
 * Total size: 32 bytes (cache-line aligned). Fits exactly in one seqlock slot.
 */
struct alignas(32) AuditEventRecord {
    uint64_t timestamp_ticks{0};
    uint64_t context_id{0};
    uint32_t tokens_consumed{0};
    AuditEventType event_type{AuditEventType::TransactionCompleted};
    uint8_t reserved[3]{0, 0, 0};
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

public:
    /**
     * PUSH: Record a governance event to the audit trail.
     *
     * Lock-free write. Multiple threads may push concurrently without
     * synchronization. Events are assigned sequential indices in the ring.
     *
     * Parameters:
     *   type:       AuditEventType (admission, rate limit, deadline, etc.)
     *   context_id: Domain/context identifier
     *   tokens:     Tokens consumed (0 if not applicable)
     *
     * Defect: Layer 4 (ExecuteGovernedTransaction) does not call this.
     * Governance decisions are made but not recorded. The audit trail
     * interface is complete and correct, but it remains empty until
     * push() calls are wired into each governance gate.
     */
    void Push(AuditEventType type, uint64_t context_id, uint32_t tokens) noexcept {
        const uint64_t idx = write_index_.fetch_add(1, std::memory_order_relaxed) & (RingCapacity - 1);
        SeqlockSlot& slot = ring_[idx];
        uint32_t seq = slot.sequence.load(std::memory_order_relaxed);
        slot.sequence.store(seq + 1, std::memory_order_release);
        slot.record.timestamp_ticks = stack::governor::HardwareClock::ReadTicks();
        slot.record.context_id = context_id;
        slot.record.tokens_consumed = tokens;
        slot.record.event_type = type;
        slot.sequence.store(seq + 2, std::memory_order_release);
    }

    /**
     * READ SLOT: Safely read an event from the ring.
     *
     * Lock-free read using seqlock pattern. Detects concurrent writes
     * by checking if the sequence counter changed during the read.
     * Retries if a write was in progress.
     *
     * Parameters:
     *   index:        Ring slot index (automatically wrapped to RingCapacity)
     *   out_record:   Output parameter; filled with the record if valid
     *
     * Returns: true if the slot has been written at least once (record is valid)
     *          false if the slot is empty (never written)
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
        return seq_before != 0;
    }
};

} // namespace stack::telemetry
