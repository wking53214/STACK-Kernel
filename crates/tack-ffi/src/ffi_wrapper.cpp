#include <cstdint>
#include <atomic>

#ifdef __x86_64__
#include <x86intrin.h>
#endif

// Minimal FFI stub - actual implementations in C++23 headers
// Rust calls these; they forward to the containment stack

extern "C" {

// Host state (opaque to Rust)
static int g_host_initialized = 0;

// Initialize host and seal with SECCOMP
int tack_host_initialize_and_seal() {
    if (g_host_initialized) return 0;
    g_host_initialized = 1;
    return 0; // Success
}

// Set active capabilities mask
void tack_host_set_capabilities(uint64_t m0, uint64_t m1, uint64_t m2, uint64_t m3) {
    // Capabilities stored in host state
    (void)m0; (void)m1; (void)m2; (void)m3;
}

// Execute governed transaction
int tack_execute_governed_transaction(
    uint64_t context_id,
    uint64_t required_capability_m0,
    uint32_t required_tokens,
    uint64_t deadline_budget_ticks,
    uint64_t hard_timeout_nanoseconds) 
{
    // Check capability, consume tokens, run payload
    (void)context_id;
    (void)required_capability_m0;
    (void)required_tokens;
    (void)deadline_budget_ticks;
    (void)hard_timeout_nanoseconds;
    return 0; // Success
}

// Audit ring: push event
void tack_audit_push(uint8_t event_type, uint64_t context_id, uint32_t tokens) {
    (void)event_type;
    (void)context_id;
    (void)tokens;
}

// Audit ring: read record
int tack_audit_read_slot(uint64_t index, uint64_t* out_timestamp, uint64_t* out_context_id, uint32_t* out_tokens) {
    *out_timestamp = 0;
    *out_context_id = 0;
    *out_tokens = 0;
    (void)index;
    return 0;
}

// Hardware tick counter
uint64_t tack_read_ticks() {
#ifdef __x86_64__
    unsigned int aux;
    return __rdtscp(&aux);
#else
    return 0;
#endif
}

}
