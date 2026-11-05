#include <cerrno>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <atomic>
#include <chrono>
#include <thread>
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
// How long stack_host_set_capabilities waits for the transactions in flight
// to drain before giving up with -2 (I-04). A transaction is bounded by its
// caller's hard timeout, which is cooperative, so the wait is bounded too.
static constexpr uint64_t kCapabilityDrainNs = 500'000'000;  // 500 ms

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

// ---------------------------------------------------------------------------
// Process initialization (I-02, R2-K-02/03/04; decision B).
//
// Two things used to be one call: the process-wide host (one object, one
// signal handler, one calibration) and the per-thread seal (a deadline timer
// and a seccomp filter on the calling thread). They are now separate:
//
//   stack_host_initialize()           process initialization, once
//   stack_host_seal_current_thread()  this thread's timer and filter
//   stack_host_initialize_and_seal()  both, kept for existing callers
//
// Initialization is a state machine on g_init_state:
//
//   Uninitialized --CAS--> InProgress --> Ready
//                                     \-> Failed  (latched for the process)
//
// Exactly one thread wins the CAS and does the work; every other caller
// either sees Ready or Failed at once or waits (yielding) while the winner
// is in progress and then sees the winner's result. The host pointer is
// written by the winner before its release store of Ready and read after an
// acquire load of Ready, so no thread observes a partial host, and the host
// is constructed exactly once. The old code wrote g_host from every
// initializing thread with no ordering (two ThreadSanitizer data races).
//
// Failed is latched: once the one-time work has failed, every later call
// to any entry point reports it (initialize -1, set_capabilities -3,
// seal -3, execute -12) and nothing is retried. There is no recovery path
// in this process; the caller restarts. The work that can fail is the
// signal handler registration and the creation of the initializing
// thread's deadline timer, which doubles as the check that deadline timers
// can be created at all; the host construction (calibration) cannot fail.
//
// A transaction no longer seals its calling thread as a side effect
// (R2-K-04): a thread that has not called stack_host_seal_current_thread()
// (or stack_host_initialize_and_seal()) gets -11 and is left exactly as it
// was. Sealing is irreversible, so it has to be asked for.
//
// Nothing in this file throws: it is compiled with -fno-exceptions, uses
// no std::mutex (whose lock can report an error only by throwing) and no
// allocation, so no exception can reach the C ABI.
// ---------------------------------------------------------------------------
enum : int {
    kInitUninitialized = 0,
    kInitInProgress = 1,
    kInitReady = 2,
    kInitFailed = 3
};

static std::atomic<int> g_init_state{kInitUninitialized};

#if defined(STACK_FFI_TESTING)
// Test-only instrumentation for the initialization tests (cpp/tests/
// ffi_init_redteam.cpp). Never defined in the shipped build (build.rs does
// not define STACK_FFI_TESTING); the symbols below do not exist there.
static std::atomic<uint64_t> g_testing_init_work_runs{0};
static std::atomic<uint64_t> g_testing_host_constructions{0};
struct FfiHostInstance : FfiHost {
    explicit FfiHostInstance(uint64_t ticks_per_token) noexcept : FfiHost(ticks_per_token) {
        g_testing_host_constructions.fetch_add(1, std::memory_order_relaxed);
    }
};
#else
using FfiHostInstance = FfiHost;
#endif

// Global instances
static FfiHost* g_host = nullptr;
static isolation::StaticArenaBuffer<65536> g_arena;
static telemetry::SeccompAuditRing<1024> g_audit_ring;
// Number of times the built-in governed payload has run (I-01: a completed
// transaction must have run it; a refused one must not have).
static std::atomic<uint64_t> g_payload_runs{0};

// The one-time process work. Runs on exactly one thread, the one that moved
// the state to InProgress. The order matters: the two steps that can fail
// come first, so a failure constructs no host.
static bool RunProcessInitialization() noexcept {
#if defined(STACK_FFI_TESTING)
    g_testing_init_work_runs.fetch_add(1, std::memory_order_relaxed);
#endif
    if (!governor::HardenedPosixPreemptionGuard::RegisterSignalHandler().has_value()) return false;
    // The initializing thread's deadline timer. Besides serving this thread
    // later, it proves that timer_create works in this process.
    if (!governor::HardenedPosixPreemptionGuard::InitializeThreadTimer().has_value()) return false;
    // Constructed exactly once: only the winning thread reaches this line,
    // and only once per process. The calibration spins for 10 ms.
    static FfiHostInstance host_instance(CalibrateTicksPerToken());
    g_host = &host_instance;
    return true;
}

// Drives the state machine. Returns 0 when the process is Ready, -1 when
// initialization has failed (now or earlier).
static int EnsureProcessInitialized() noexcept {
    int state = g_init_state.load(std::memory_order_acquire);
    if (state == kInitReady) return 0;
    if (state == kInitFailed) return -1;

    int expected = kInitUninitialized;
    if (g_init_state.compare_exchange_strong(expected, kInitInProgress,
                                             std::memory_order_acq_rel,
                                             std::memory_order_acquire)) {
        const bool ok = RunProcessInitialization();
        g_init_state.store(ok ? kInitReady : kInitFailed, std::memory_order_release);
        return ok ? 0 : -1;
    }
    // Another thread won, or finished between the load and the CAS. Wait for
    // its result. No caller here is sealed (sealing needs Ready first), so
    // yielding is allowed.
    while ((state = g_init_state.load(std::memory_order_acquire)) == kInitInProgress) {
        std::this_thread::yield();
    }
    return state == kInitReady ? 0 : -1;
}

extern "C" {

// Process initialization only: constructs the host (once), registers the
// deadline signal handler and creates this thread's deadline timer. Does
// not seal the calling thread. Idempotent: every later call returns the
// latched outcome.
//    0  initialized (now or earlier)
//   -1  initialization failed (latched for the life of the process)
int stack_host_initialize() {
    return EnsureProcessInitialized();
}

// Seals the calling thread: creates its deadline timer and installs the
// seccomp allowlist on it. Irreversible. Idempotent for a sealed thread.
//    0  this thread is sealed (now or earlier)
//   -1  the host is not initialized (call stack_host_initialize first)
//   -2  this thread could not be sealed (timer or filter); it is left
//       unsealed and unchanged, and the host stays usable from other threads
//   -3  initialization failed (latched)
int stack_host_seal_current_thread() {
    const int state = g_init_state.load(std::memory_order_acquire);
    if (state == kInitFailed) return -3;
    if (state != kInitReady) return -1;
    if (host::SeccompFilterEngine::IsInstalledOnThisThread()) return 0;
    return g_host->InitializeAndSeal().has_value() ? 0 : -2;
}

// Initialize the process and seal the calling thread, in that order.
//    0  initialized and this thread sealed
//   -1  initialization failed (latched; was "timer initialization failed",
//       which is now part of initialization)
//   -2  initialized, but this thread could not be sealed (unchanged meaning)
int stack_host_initialize_and_seal() {
    if (EnsureProcessInitialized() != 0) return -1;
    return stack_host_seal_current_thread() == 0 ? 0 : -2;
}

// Set active capabilities mask (256-bit SIMD)
// Returns 0 when the mask was applied, -1 when the host is not initialized
// (not yet, or another thread is still initializing it), -2 when the change
// was NOT applied because the transactions in flight did not drain within
// kCapabilityDrainNs, and -3 when initialization has failed (latched): a mask
// is never applied to a host that did not finish initializing (R2-K-03).
//
// Revocation (I-04, R2-K-07). The change used to be refused whenever any
// transaction was in flight anywhere, so under steady load a revocation never
// applied. Now the call holds NEW transactions out (they return -13, nothing
// runs, nothing is consumed) while it waits for the ones already in flight,
// at most kCapabilityDrainNs. 0 means the mask is applied and no transaction
// is running or will run with the old one. -2 means it was not applied, no
// change is left pending and the host serves under the old mask again; the
// caller retries or escalates. Do not call it from a payload.
//
// R2-K-24: governed supervised workers in flight are TERMINATED by a pending
// change, not waited for: each is sent SIGKILL through its pidfd and its run
// ends with outcome Terminated (13), audited as SupervisedTerminated (9), with
// its tokens spent. The change then applies as soon as they are reaped (a few
// milliseconds), instead of after their deadline. In-process transactions
// cannot be stopped and are still waited for, up to kCapabilityDrainNs.
int stack_host_set_capabilities(uint64_t m0, uint64_t m1, uint64_t m2, uint64_t m3) {
    const int state = g_init_state.load(std::memory_order_acquire);
    if (state == kInitFailed) return -3;
    if (state != kInitReady) return -1;

    host::CapabilityMask256 caps(m0, m1, m2, m3);
    return g_host->SetActiveCapabilitiesWithin(caps, std::chrono::nanoseconds(kCapabilityDrainNs)) ? 0 : -2;
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
//   -5  rate limit exceeded (also: required_tokens == 0, R2-K-20)
//   -6  hard (CPU-time) deadline fired: PreemptionTriggered
//   -7  software deadline (tick budget) exceeded
//   -8  compute debt ceiling exceeded
//   -9  hard_timeout_nanoseconds was 0 (refused, nothing ran)
//  -10  the deadline timer could not be armed (nothing ran)
//  -11  the calling thread is not sealed (I-02, decision B): call
//       stack_host_seal_current_thread first. Nothing ran, nothing was
//       consumed, and the thread was not sealed as a side effect.
//  -12  initialization failed (latched); nothing ran
//  -13  a capability change is pending (I-04): it is waiting for the
//       transactions in flight to drain and holds new ones out. Nothing ran,
//       nothing was consumed. Retry.
// This is the in-process path: cooperative deadline, not isolation. A
// payload that must be stopped goes through stack_supervised_run.
int stack_execute_governed_transaction(
    uint64_t context_id,
    uint64_t required_capability_bits,
    uint32_t required_tokens,
    uint64_t deadline_budget_ticks,
    uint64_t hard_timeout_nanoseconds)
{
    const int state = g_init_state.load(std::memory_order_acquire);
    if (state == kInitFailed) return -12;
    if (state != kInitReady) return -1;
    // Decision B: no implicit seal. The host's own ExecuteGovernedTransaction
    // would seal an unsealed caller; it is never reached from here unsealed.
    if (!host::SeccompFilterEngine::IsInstalledOnThisThread()) return -11;

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
        case host::HostExecutionError::CapabilityChangePending: return -13;
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
    // 1 when result bytes were delivered (outcome Completed): they are the
    // worker's own claim and nothing more (RACE-02). Was reserved[0]; the
    // struct has the same size and layout, old callers read it as zero.
    uint8_t result_self_reported;
    uint8_t reserved[2];
};

static void FillReport(stack_supervised_report* report, const supervised::ExecutionReport& r) {
    report->elapsed_ns = r.elapsed_ns;
    report->result_length = r.result_length;
    report->outcome = static_cast<int32_t>(r.outcome);
    report->exit_code = r.exit_code;
    report->signal_number = r.signal_number;
    report->error_number = r.error_number;
    report->child_pid = static_cast<int32_t>(r.child_pid);
    report->deadline_fired = r.deadline_fired ? 1 : 0;
    report->result_self_reported = r.result_self_reported ? 1 : 0;
    report->reserved[0] = report->reserved[1] = 0;
}

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

    FillReport(report, r);
    return 0;
}

// ---------------------------------------------------------------------------
// Governed supervised run in a clean worker process (RACE-02, decision A).
//
// stack_supervised_run above is the LEGACY entry: its child is a fork of this
// process, it runs without any capability or rate-limit check, and it is kept
// only so existing callers keep linking. It is NOT for untrusted payloads and
// stack-admission no longer calls it.
//
// stack_supervised_run_governed takes the same context, capability and token
// arguments as stack_execute_governed_transaction, validates the capability
// mask and consumes rate-limit tokens through the initialized host BEFORE
// anything is spawned, and only then forks and execs the worker program at
// worker_path (an ABSOLUTE path chosen by kernel configuration, never by the
// payload or the environment). The worker runs one of the built-in kinds 0 to
// 6 inside its own seccomp filter. One audit event records the outcome in the
// host audit ring (see stack_host_audit_read_slot), timeouts included.
//
// Return codes. Nothing is spawned and nothing is consumed unless 0:
//    0  governance passed. The run's outcome is in report->outcome (any
//       Outcome, including TimedOut, TerminationUnconfirmed and Terminated).
//       Tokens are spent when child_pid != 0 and refunded when nothing was
//       spawned. Terminated (13): a capability change that was waiting killed
//       the worker (R2-K-24); never a success.
//   -1  host not initialized
//   -2  unknown payload kind (above 6)
//   -3  a null pointer argument, or out null with a non-zero capacity
//   -4  capability validation failed, including a request that names no
//       capability bit at all (required_capability_m0 == 0)
//   -5  rate limited (also: more than 100 tokens, 0 tokens (R2-K-20: a
//       governed request consumes at least one), domain id 16 or more)
//   -9  wall_clock_deadline_ns was 0
//  -12  initialization failed (latched)
//  -13  a capability change is pending; retry
//  -14  worker_path is unusable (null, relative, missing, a symlink anywhere
//       in the path, not a regular executable file, setuid, setgid,
//       group-writable, world-writable, or owned by someone else)
//  -15  the other limits are invalid (deadline above one hour, output above
//       the buffer or 1 MiB, reap_timeout_ns above one minute)
//  -16  worker_sha256 is null: the digest of the worker image is REQUIRED
//       (R2-K-21); nothing is spawned and nothing consumed
//  -17  the image at worker_path does not hash to worker_sha256 (R2-K-21).
//       Checked after governance: tokens taken for the call are refunded and
//       one SupervisedFailed event with 0 tokens is written
//
// worker_sha256 points to 32 bytes, the SHA-256 the configuration pins for
// the worker image. The image is read through the descriptor that is then
// executed, hashed, and a sealed in-memory copy of the hashed bytes is what
// runs, so a swap of the file after the check changes nothing (see
// cpp/include/stack_supervised_exec.hpp). stack_supervised_image_sha256
// computes the digest of a file for provisioning and for tests.
// reap_timeout_ns 0 means the default, 2 s. On a non-zero return the report is
// zeroed. Do not call from a sealed thread: the seal forbids open, fork and
// exec, so the worker image cannot be opened and the call is -14 with nothing
// spawned and nothing consumed.
// ---------------------------------------------------------------------------
int stack_supervised_run_governed(
    uint64_t context_id,
    uint64_t required_capability_m0,
    uint32_t required_tokens,
    uint32_t payload_kind,
    const char* worker_path,
    const uint8_t* worker_sha256,
    const stack_supervised_limits* limits,
    uint64_t reap_timeout_ns,
    uint8_t* out,
    size_t out_capacity,
    stack_supervised_report* report)
{
    if (!report) return -3;
    std::memset(report, 0, sizeof *report);
    const int state = g_init_state.load(std::memory_order_acquire);
    if (state == kInitFailed) return -12;
    if (state != kInitReady) return -1;
    if (!limits || (!out && out_capacity != 0)) return -3;
    if (payload_kind > 6) return -2;
    if (limits->wall_clock_deadline_ns == 0) return -9;

    supervised::Limits l;
    l.wall_clock_deadline_ns = limits->wall_clock_deadline_ns;
    l.cpu_seconds = limits->cpu_seconds;
    l.address_space_bytes = limits->address_space_bytes;
    l.max_output_bytes = limits->max_output_bytes;
    l.file_size_bytes = limits->file_size_bytes;
    l.nofile = limits->nofile;
    l.inherit_fd = -1;
    if (reap_timeout_ns != 0) l.reap_timeout_ns = reap_timeout_ns;
    if (!supervised::SupervisedExecutor::LimitsAreValid(l, out, out_capacity)) return -15;
    if (worker_sha256 == nullptr) return -16;  // fail closed: the image must be pinned
    // Cheap policy checks here, before governance. The digest itself is checked
    // by RunWorker on the descriptor it executes, after governance: hashing the
    // image costs milliseconds, and a refused request must not make the host
    // pay that.
    if (supervised::SupervisedExecutor::CheckWorkerImage(worker_path) != 0) return -14;

    supervised::WorkerSpec spec;
    spec.executable = worker_path;
    spec.kind = payload_kind;
    spec.expected_sha256 = worker_sha256;

    // A request that names no capability would pass any mask: refuse it.
    if (required_capability_m0 == 0) return -4;
    host::CapabilityMask256 required_mask(required_capability_m0, 0, 0, 0);
    host::SIMDCapabilityToken token(context_id, required_mask);

    supervised::ExecutionReport r{};
    auto governed = g_host->ExecuteGovernedSupervised(
        token, required_tokens, limits->wall_clock_deadline_ns,
        [&](supervised::CancelHandle& cancel) -> FfiHost::SupervisedRunResult {
            r = supervised::SupervisedExecutor::RunWorker(l, spec, out, out_capacity, &cancel);
            if (r.child_pid == 0) return FfiHost::SupervisedRunResult::NotSpawned;
            switch (r.outcome) {
                case supervised::Outcome::Completed: return FfiHost::SupervisedRunResult::Completed;
                case supervised::Outcome::TimedOut: return FfiHost::SupervisedRunResult::TimedOut;
                case supervised::Outcome::Terminated: return FfiHost::SupervisedRunResult::Terminated;
                case supervised::Outcome::TerminationUnconfirmed:
                    return FfiHost::SupervisedRunResult::TerminationUnconfirmed;
                default: return FfiHost::SupervisedRunResult::Failed;
            }
        });
    if (!governed.has_value()) {
        switch (governed.error()) {
            case host::HostExecutionError::CapabilityValidationFailed: return -4;
            case host::HostExecutionError::RateLimitExceeded: return -5;
            case host::HostExecutionError::InvalidHardTimeout: return -9;
            case host::HostExecutionError::CapabilityChangePending: return -13;
            default: return -3;
        }
    }
    // The image did not hash to the pinned digest: nothing was spawned, the
    // tokens were refunded and one SupervisedFailed event with 0 tokens records it.
    if (r.outcome == supervised::Outcome::SpawnFailed && r.child_pid == 0 && r.error_number == EKEYREJECTED) {
        std::memset(report, 0, sizeof *report);
        return -17;
    }
    FillReport(report, r);
    return 0;
}

// Computes the SHA-256 of the file at `path` into out[32], for provisioning
// and for tests (R2-K-21). It applies no trust policy: it hashes any readable
// regular file. A production deployment pins a digest from its release record,
// not one computed from the file it is about to trust. Returns 0, or an errno
// (a positive number) when the file cannot be read; -3 for a null argument.
int stack_supervised_image_sha256(const char* path, uint8_t* out) {
    if (path == nullptr || out == nullptr) return -3;
    uint8_t digest[32];
    const int err = supervised::SupervisedExecutor::Sha256OfFile(path, digest);
    if (err != 0) return err;
    std::memcpy(out, digest, sizeof digest);
    return 0;
}

// Supervised workers that were sent SIGKILL and not yet confirmed reaped
// (outcome TerminationUnconfirmed). They may still be running.
uint64_t stack_supervised_unconfirmed_count() {
    return supervised::SupervisedExecutor::UnconfirmedCount();
}

// Re-sends SIGKILL to each unconfirmed worker and reaps the ones that have
// gone. Returns how many remain unconfirmed.
uint64_t stack_supervised_reap_unconfirmed() {
    return supervised::SupervisedExecutor::ReapUnconfirmed();
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
    if (g_init_state.load(std::memory_order_acquire) != kInitReady) return -1;

    telemetry::AuditEventRecord event{};
    if (!g_host->AuditRing().ReadSlot(index, event)) return -1;

    *out_event_type = static_cast<uint8_t>(event.event_type);
    *out_timestamp = event.timestamp_ticks;
    *out_context_id = event.context_id;
    *out_tokens = event.tokens_consumed;
    return 0;
}

#if defined(STACK_FFI_TESTING)
// Test-only counters (see the STACK_FFI_TESTING note above). Absent from the
// shipped build.
uint64_t stack_ffi_testing_init_work_runs() {
    return g_testing_init_work_runs.load(std::memory_order_acquire);
}
uint64_t stack_ffi_testing_host_constructions() {
    return g_testing_host_constructions.load(std::memory_order_acquire);
}
#endif

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
