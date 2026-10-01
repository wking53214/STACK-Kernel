#pragma once

#include <array>
#include <atomic>
#include <cstddef>
#include <cstdint>
#include "tack_kernel.hpp"

namespace tack::telemetry {
enum class AuditEventType : uint8_t { TransactionCompleted = 0, RateLimitTriggered, SoftwareDeadlineExceeded, HardwareTimerPreempted, CapabilityViolation };

struct alignas(32) AuditEventRecord {
    uint64_t timestamp_ticks{0};
    uint64_t context_id{0};
    uint32_t tokens_consumed{0};
    AuditEventType event_type{AuditEventType::TransactionCompleted};
    uint8_t reserved[3]{0, 0, 0};
};

template <std::size_t RingCapacity = 1024>
class SeccompAuditRing {
    static_assert((RingCapacity & (RingCapacity - 1)) == 0, "Capacity must be power of two.");
private:
    struct alignas(64) SeqlockSlot {
        std::atomic<uint32_t> sequence{0};
        AuditEventRecord record{};
    };
    alignas(64) std::array<SeqlockSlot, RingCapacity> ring_{};
    alignas(64) std::atomic<uint64_t> write_index_{0};
public:
    void Push(AuditEventType type, uint64_t context_id, uint32_t tokens) noexcept {
        const uint64_t idx = write_index_.fetch_add(1, std::memory_order_relaxed) & (RingCapacity - 1);
        SeqlockSlot& slot = ring_[idx];
        uint32_t seq = slot.sequence.load(std::memory_order_relaxed);
        slot.sequence.store(seq + 1, std::memory_order_release);
        slot.record.timestamp_ticks = tack::governor::HardwareClock::ReadTicks();
        slot.record.context_id = context_id;
        slot.record.tokens_consumed = tokens;
        slot.record.event_type = type;
        slot.sequence.store(seq + 2, std::memory_order_release);
    }
    [[nodiscard]] bool ReadSlot(std::size_t index, AuditEventRecord& out_record) const noexcept {
        const SeqlockSlot& slot = ring_[index & (RingCapacity - 1)];
        uint32_t seq_before = 0, seq_after = 0;
        do {
            seq_before = slot.sequence.load(std::memory_order_acquire);
            if (seq_before & 1) continue;
            out_record = slot.record;
            seq_after = slot.sequence.load(std::memory_order_acquire);
        } while (seq_before != seq_after);
        return seq_before != 0;
    }
};
} // namespace tack::telemetry
