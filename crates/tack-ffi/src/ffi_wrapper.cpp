#include <cstdint>
#include <atomic>
#include <x86intrin.h>

// Pull in the actual C++23 containment stack
#include "tack_kernel.hpp"
#include "tack_kinetic_governor.hpp"
#include "posix_deadline_timer_hardened.hpp"
#include "tack_host_binding.hpp"
#include "tack_arena.hpp"
#include "tack_audit.hpp"

using namespace tack;

// Global instances
static host::GovernedMinotaurHost<64, 100, 1000, 100, 16>* g_host = nullptr;
static std::atomic<bool> g_initialized(false);
static arena::StaticArenaBuffer<65536> g_arena;
static telemetry::SeccompAuditRing<1024> g_audit_ring;

extern "C" {

// Initialize host and seal with SECCOMP
int tack_host_initialize_and_seal() {
    if (g_initialized.load()) return 0;
    
    // Allocate host instance
    static host::GovernedMinotaurHost<64, 100, 1000, 100, 16> host_instance;
    g_host = &host_instance;
    
    // Initialize the hardened POSIX timer for this thread
    auto timer_result = governor::HardenedPosixPreemptionGuard::InitializeThreadTimer();
    if (!timer_result.has_value()) {
        return -1; // Timer initialization failed
    }
    
    // Initialize and seal with SECCOMP
    auto seal_result = g_host->InitializeAndSeal();
    if (!seal_result.has_value()) {
        return -2; // Sealing failed
    }
    
    g_initialized.store(true);
    return 0;
}

// Set active capabilities mask (256-bit SIMD)
void tack_host_set_capabilities(uint64_t m0, uint64_t m1, uint64_t m2, uint64_t m3) {
    if (!g_host) return;
    
    host::CapabilityMask256 caps;
    caps.bits[0] = m0;
    caps.bits[1] = m1;
    caps.bits[2] = m2;
    caps.bits[3] = m3;
    
    g_host->SetActiveCapabilities(caps);
}

// Execute governed transaction under deadline and token budget
int tack_execute_governed_transaction(
    uint64_t context_id,
    uint64_t required_capability_bits,
    uint32_t required_tokens,
    uint64_t deadline_budget_ticks,
    uint64_t hard_timeout_nanoseconds) 
{
    if (!g_host) return -1;
    if (!g_initialized.load()) return -1;
    
    // Build capability token with context
    host::CapabilityMask256 required_mask;
    required_mask.bits[0] = required_capability_bits;
    required_mask.bits[1] = 0;
    required_mask.bits[2] = 0;
    required_mask.bits[3] = 0;
    
    host::SIMDCapabilityToken token(context_id, required_mask);
    
    // Execute under governance
    auto result = g_host->ExecuteGovernedTransaction(
        token,
        context_id,
        deadline_budget_ticks,
        hard_timeout_nanoseconds,
        [](){ 
            // Minimal payload: just burn some cycles
            volatile uint64_t x = 0;
            for (int i = 0; i < 1000; i++) x += i;
        });
    
    return result.has_value() ? 0 : -3;
}

// Audit ring: push event
void tack_audit_push(uint8_t event_type, uint64_t context_id, uint32_t tokens) {
    telemetry::AuditEventRecord event{};
    event.timestamp_ticks = tack_read_ticks();
    event.context_id = context_id;
    event.tokens_consumed = tokens;
    event.event_type = static_cast<telemetry::AuditEventType>(event_type);
    
    g_audit_ring.Push(event);
}

// Audit ring: read record safely (seqlock-protected)
int tack_audit_read_slot(
    uint64_t index,
    uint64_t* out_timestamp,
    uint64_t* out_context_id,
    uint32_t* out_tokens) 
{
    if (!out_timestamp || !out_context_id || !out_tokens) return -1;
    
    auto event_opt = g_audit_ring.ReadSlot(index);
    if (!event_opt.has_value()) {
        *out_timestamp = 0;
        *out_context_id = 0;
        *out_tokens = 0;
        return -1;
    }
    
    *out_timestamp = event_opt->timestamp_ticks;
    *out_context_id = event_opt->context_id;
    *out_tokens = event_opt->tokens_consumed;
    return 0;
}

// Arena allocator
void* tack_arena_allocate(size_t size) {
    auto result = g_arena.Allocate(size);
    return result.has_value() ? result.value() : nullptr;
}

// Hardware tick counter
uint64_t tack_read_ticks() {
#ifdef __x86_64__
    unsigned int aux;
    return __rdtscp(&aux);
#elif defined(__aarch64__)
    uint64_t cntpct_el0;
    asm volatile("mrs %0, cntpct_el0" : "=r"(cntpct_el0));
    return cntpct_el0;
#else
    return 0;
#endif
}

}
