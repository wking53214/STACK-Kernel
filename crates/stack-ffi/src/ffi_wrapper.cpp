#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <atomic>
#include <x86intrin.h>
#include <fcntl.h>
#include <sys/syscall.h>
#include <unistd.h>

// Pull in the actual C++23 containment stack
#include "stack_kernel.hpp"
#include "stack_kinetic_governor.hpp"
#include "posix_deadline_timer_hardened.hpp"
#include "stack_host_binding.hpp"
#include "stack_arena.hpp"
#include "stack_audit.hpp"
#include "stack_supervised_exec.hpp"

using namespace stack;

// ---------------------------------------------------------------------------
// Governance policy of the FFI host (I-01, R2-K-01).
//
// The previous host was GovernedMinotaurHost<64, 100, 1000, 100, 16>: a
// Reserved floor of 100 in a bucket of 64, which no Standard request could
// clear, so every transaction was rate limited; and TicksPerToken 100, about
// 21 million tokens per second on this clock, which would have been no limit
// at all once the floor was fixed. KineticGovernor now static_asserts
// Reserved + MaxBurst <= MaxCapacity, so the first mistake cannot compile.
//
// Policy: a domain may hold 1000 tokens, a Standard request may not dip into
// the last 100, the largest single request is 100 tokens, and the bucket
// refills at kTokensPerSecond. So a domain can burst 900 tokens and then
// sustain 1000 tokens per second, in requests of at most 100.
//
// The refill rate is in HardwareClock ticks (RDTSCP on x86_64, the same
// counter stack_read_ticks returns). The TSC frequency is a property of the
// machine, not of the build, so it is measured once at initialization against
// CLOCK_MONOTONIC and handed to the host's constructor; kDefaultTicksPerToken
// is only the template default and is never used by this wrapper.
// ---------------------------------------------------------------------------
static constexpr uint32_t kMaxCapacity = 1000;
static constexpr uint32_t kReservedTokens = 100;
static constexpr uint32_t kMaxRequestTokens = 100;   // largest single request
static constexpr uint64_t kDefaultTicksPerToken = 2'100'000;  // 2.1 GHz at 1000 tokens/s
static constexpr std::size_t kMaxDomains = 16;
static constexpr uint64_t kTokensPerSecond = 1000;
static constexpr uint64_t kCalibrationSpanNs = 10'000'000;  // 10 ms

static_assert(static_cast<uint64_t>(kReservedTokens) + kMaxRequestTokens <= kMaxCapacity,
              "FFI host: Reserved + largest request must fit in the bucket (R2-K-01)");
static_assert(kTokensPerSecond >= 1 && kTokensPerSecond <= 1'000'000'000ULL,
              "FFI host: tokens per second must divide a second's nanoseconds");

using FfiHost = host::GovernedMinotaurHost<kMaxCapacity, kReservedTokens, kMaxRequestTokens,
                                           kDefaultTicksPerToken, kMaxDomains>;

// Measures the tick counter against CLOCK_MONOTONIC over kCalibrationSpanNs
// and returns the ticks per token for kTokensPerSecond. Runs once, on the
// initializing thread, before anything is sealed (clock_gettime is on the
// allowlist anyway). A counter that does not advance gives 1 tick per token,
// the governor's fastest expressible rate; it is clamped, not an error, since
// HardwareClock has no failure mode to report.
static uint64_t CalibrateTicksPerToken() noexcept {
    timespec start{};
    ::clock_gettime(CLOCK_MONOTONIC, &start);
    const uint64_t ticks_start = governor::HardwareClock::ReadTicks();
    uint64_t elapsed_ns = 0;
    do {
        timespec now{};
        ::clock_gettime(CLOCK_MONOTONIC, &now);
        elapsed_ns = static_cast<uint64_t>(now.tv_sec - start.tv_sec) * 1'000'000'000ULL
                   + static_cast<uint64_t>(now.tv_nsec - start.tv_nsec);
    } while (elapsed_ns < kCalibrationSpanNs);
    const uint64_t ticks = governor::HardwareClock::ReadTicks() - ticks_start;
    // ticks_per_token = (ticks / elapsed_s) / kTokensPerSecond
    //                 = ticks * (1e9 / kTokensPerSecond) / elapsed_ns
    // ticks over 10 ms is below 1e8 on any current clock, so the product fits.
    const uint64_t ns_per_token = 1'000'000'000ULL / kTokensPerSecond;
    const uint64_t ticks_per_token = (ticks * ns_per_token) / elapsed_ns;
    return ticks_per_token == 0 ? 1 : ticks_per_token;
}

// Global instances
static FfiHost* g_host = nullptr;
static std::atomic<bool> g_initialized(false);
static isolation::StaticArenaBuffer<65536> g_arena;
static telemetry::SeccompAuditRing<1024> g_audit_ring;
// Number of times the built-in governed payload has run (I-01: a completed
// transaction must have run it; a refused one must not have).
static std::atomic<uint64_t> g_payload_runs{0};

extern "C" {

// Initialize host and seal with SECCOMP
// The host is process wide but the seccomp filter is per thread, so every
// calling thread seals itself; a thread that is already sealed returns at once.
int stack_host_initialize_and_seal() {
    // Allocate host instance. The calibrated refill rate is measured once,
    // under the compiler's one-time initialization of this static.
    static FfiHost host_instance(CalibrateTicksPerToken());
    if (!g_initialized.load()) g_host = &host_instance;
    
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
// Returns 0 when the mask was applied, -1 when the host is not initialized, and
// -2 when the change was refused because a transaction is in flight (retry).
int stack_host_set_capabilities(uint64_t m0, uint64_t m1, uint64_t m2, uint64_t m3) {
    if (!g_host) return -1;

    host::CapabilityMask256 caps(m0, m1, m2, m3);
    return g_host->SetActiveCapabilities(caps) ? 0 : -2;
}

// Execute governed transaction under deadline and token budget.
//
// Return codes. The original three keep their meaning; the rest were added
// so a caller can tell a deadline from a denial (D-18):
//    0  completed
//   -1  host not initialized (unchanged)
//   -3  execution failed for a reason not listed below: seccomp, signal
//       handler or timer_create setup failed (unchanged meaning, narrower)
//   -4  capability validation failed
//   -5  rate limit exceeded
//   -6  hard (CPU-time) deadline fired: PreemptionTriggered
//   -7  software deadline (tick budget) exceeded
//   -8  compute debt ceiling exceeded
//   -9  hard_timeout_nanoseconds was 0 (refused, nothing ran)
//  -10  the deadline timer could not be armed (nothing ran)
// This is the in-process path: cooperative deadline, not isolation. A
// payload that must be stopped goes through stack_supervised_run.
int stack_execute_governed_transaction(
    uint64_t context_id,
    uint64_t required_capability_bits,
    uint32_t required_tokens,
    uint64_t deadline_budget_ticks,
    uint64_t hard_timeout_nanoseconds)
{
    if (!g_host) return -1;
    if (!g_initialized.load()) return -1;

    // Build capability token with context
    host::CapabilityMask256 required_mask(required_capability_bits, 0, 0, 0);
    host::SIMDCapabilityToken token(context_id, required_mask);

    // Execute under governance
    auto result = g_host->ExecuteGovernedTransaction(
        token,
        required_tokens,
        deadline_budget_ticks,
        hard_timeout_nanoseconds,
        [](){
            // Minimal payload: just burn some cycles
            volatile uint64_t x = 0;
            for (int i = 0; i < 1000; i++) x += i;
            g_payload_runs.fetch_add(1, std::memory_order_relaxed);
        });

    if (result.has_value()) return 0;
    switch (result.error()) {
        case host::HostExecutionError::CapabilityValidationFailed: return -4;
        case host::HostExecutionError::RateLimitExceeded: return -5;
        case host::HostExecutionError::PreemptionTriggered: return -6;
        case host::HostExecutionError::DeadlineExceeded: return -7;
        case host::HostExecutionError::DebtCeilingExceeded: return -8;
        case host::HostExecutionError::InvalidHardTimeout: return -9;
        case host::HostExecutionError::TimerArmFailed: return -10;
        case host::HostExecutionError::None:
        case host::HostExecutionError::SeccompInitializationFailed:
        case host::HostExecutionError::SignalHandlerRegistrationFailed:
        case host::HostExecutionError::TimerInitializationFailed:
            return -3;
    }
    return -3;
}

// ---------------------------------------------------------------------------
// Supervised execution (child process, wall-clock deadline ending in SIGKILL).
//
// The FFI cannot carry a closure, so the payload is chosen from a fixed,
// built-in set by number. These exist to exercise and verify the executor
// from Rust; a real integration adds its payload on the C++ side.
//   0  ReturnBytes       writes "stack-ffi-payload-v1" and completes
//   1  SpinForever       infinite loop
//   2  BlockForever      futex wait that is never woken
//   3  Crash             null store (SIGSEGV)
//   4  Abort             abort() (SIGABRT)
//   5  ExitNonZero       _exit(3)
//   6  ForbiddenSyscall  open(2), which the filter kills with SIGSYS
// ---------------------------------------------------------------------------

struct stack_supervised_limits {
    uint64_t wall_clock_deadline_ns;
    uint64_t cpu_seconds;
    uint64_t address_space_bytes;
    uint64_t max_output_bytes;
    uint64_t file_size_bytes;
    uint32_t nofile;
    uint32_t reserved;
};

struct stack_supervised_report {
    uint64_t elapsed_ns;
    uint64_t result_length;
    int32_t outcome;        // stack::supervised::Outcome as an integer
    int32_t exit_code;
    int32_t signal_number;
    int32_t error_number;
    int32_t child_pid;
    uint8_t deadline_fired;
    uint8_t reserved[3];
};

static const char kFfiPayloadBytes[] = "stack-ffi-payload-v1";

static std::size_t stack_ffi_builtin_payload(void* context, uint8_t* out, std::size_t capacity) {
    const uint32_t kind = *static_cast<const uint32_t*>(context);
    switch (kind) {
        case 0: {
            std::size_t n = sizeof(kFfiPayloadBytes) - 1;
            if (n > capacity) n = capacity;
            std::memcpy(out, kFfiPayloadBytes, n);
            return n;
        }
        case 1:
            for (;;) { asm volatile("" ::: "memory"); }
        case 2: {
            static uint32_t never_woken = 0;
            for (;;) {
                (void)::syscall(SYS_futex, &never_woken, 128 /* FUTEX_WAIT_PRIVATE */, 0, nullptr, nullptr, 0);
            }
        }
        case 3:
            *static_cast<volatile int*>(nullptr) = 1;
            return 0;
        case 4:
            std::abort();
        case 5:
            ::_exit(3);
        case 6:
            (void)::open("/etc/hostname", O_RDONLY);
            for (;;) { asm volatile("" ::: "memory"); }
        default:
            ::_exit(4);
    }
}

// Returns 0 with *report filled, -1 for a null argument, -2 for an unknown
// payload kind. The outcome, including InvalidLimits, is in report->outcome.
int stack_supervised_run(
    uint32_t payload_kind,
    const stack_supervised_limits* limits,
    uint8_t* out,
    size_t out_capacity,
    stack_supervised_report* report)
{
    if (!limits || !report) return -1;
    if (!out && out_capacity != 0) return -1;
    if (payload_kind > 6) return -2;

    supervised::Limits l;
    l.wall_clock_deadline_ns = limits->wall_clock_deadline_ns;
    l.cpu_seconds = limits->cpu_seconds;
    l.address_space_bytes = limits->address_space_bytes;
    l.max_output_bytes = limits->max_output_bytes;
    l.file_size_bytes = limits->file_size_bytes;
    l.nofile = limits->nofile;
    l.inherit_fd = -1;

    uint32_t kind = payload_kind;
    const supervised::ExecutionReport r =
        supervised::SupervisedExecutor::RunThunk(l, &stack_ffi_builtin_payload, &kind, out, out_capacity);

    report->elapsed_ns = r.elapsed_ns;
    report->result_length = r.result_length;
    report->outcome = static_cast<int32_t>(r.outcome);
    report->exit_code = r.exit_code;
    report->signal_number = r.signal_number;
    report->error_number = r.error_number;
    report->child_pid = static_cast<int32_t>(r.child_pid);
    report->deadline_fired = r.deadline_fired ? 1 : 0;
    report->reserved[0] = report->reserved[1] = report->reserved[2] = 0;
    return 0;
}

// Number of times the built-in governed payload has run in this process.
// Added in I-01 so a caller can tell that a completed transaction ran its
// payload and that a refused one did not.
uint64_t stack_host_payload_count() {
    return g_payload_runs.load(std::memory_order_acquire);
}

// The host's own governance audit trail (distinct from the free-standing ring
// behind stack_audit_push/stack_audit_read_slot). Slot `index` is filled and
// 0 returned when the slot holds a record; -1 when the host is not
// initialized, an output pointer is null, or the slot was never written.
// out_event_type is the AuditEventType value (0 TransactionCompleted,
// 1 RateLimitTriggered, 2 SoftwareDeadlineExceeded, 3 HardwareTimerPreempted,
// 4 CapabilityViolation). Added in I-01.
int stack_host_audit_read_slot(
    uint64_t index,
    uint8_t* out_event_type,
    uint64_t* out_timestamp,
    uint64_t* out_context_id,
    uint32_t* out_tokens)
{
    if (!out_event_type || !out_timestamp || !out_context_id || !out_tokens) return -1;
    if (!g_host) return -1;

    telemetry::AuditEventRecord event{};
    if (!g_host->AuditRing().ReadSlot(index, event)) return -1;

    *out_event_type = static_cast<uint8_t>(event.event_type);
    *out_timestamp = event.timestamp_ticks;
    *out_context_id = event.context_id;
    *out_tokens = event.tokens_consumed;
    return 0;
}

// Audit ring: push event
void stack_audit_push(uint8_t event_type, uint64_t context_id, uint32_t tokens) {
    g_audit_ring.Push(
        static_cast<telemetry::AuditEventType>(event_type),
        context_id,
        tokens);
}

// Audit ring: read record safely (seqlock-protected)
int stack_audit_read_slot(
    uint64_t index,
    uint64_t* out_timestamp,
    uint64_t* out_context_id,
    uint32_t* out_tokens)
{
    if (!out_timestamp || !out_context_id || !out_tokens) return -1;

    telemetry::AuditEventRecord event{};
    bool valid = g_audit_ring.ReadSlot(index, event);
    if (!valid) {
        *out_timestamp = 0;
        *out_context_id = 0;
        *out_tokens = 0;
        return -1;
    }

    *out_timestamp = event.timestamp_ticks;
    *out_context_id = event.context_id;
    *out_tokens = event.tokens_consumed;
    return 0;
}

// Arena allocator: allocate from the arena
// Note: StaticArenaBuffer is designed for typed object allocation, not raw bytes.
// This allocates an 8-byte block (uint64_t). Larger allocations require multiple calls.
void* stack_arena_allocate(size_t size) {
    if (size == 0) return nullptr;

    // For simplicity, allocate one uint64_t per call
    // A production wrapper would provide size-aware allocation
    auto result = g_arena.Allocate<uint64_t>();
    return result.has_value() ? reinterpret_cast<void*>(result.value()) : nullptr;
}

// Hardware tick counter
uint64_t stack_read_ticks() {
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
