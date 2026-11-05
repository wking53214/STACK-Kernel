/* A C-language caller of the exported FFI ABI (R-1, D1-C).
 *
 * This file is compiled as C (gcc -std=c11, -Wall -Wextra -Werror) and linked
 * against the FFI wrapper built as a static library (crates/stack-ffi/src/
 * ffi_wrapper.cpp). It declares the ABI the way a C consumer would, from
 * crates/stack-ffi/ABI.md, and exercises it end to end:
 *
 *   init (and a repeated init), capabilities, a governed supervised run in a
 *   clean worker (success, and a refusal that spawns nothing), the supervisor's
 *   exit_observed / frame_status in the report struct, then on a sealed thread
 *   a governed transaction (success and a refusal), and finally the lifetime
 *   statement of ABI.md: there is no teardown, a repeated init is idempotent
 *   and keeps the state.
 *
 * Exit status 0 means every check held; any other value is the number of the
 * first check that did not. No test framework: a C caller has none.
 */
#include <pthread.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#ifndef STACK_WORKER_PATH
#error "STACK_WORKER_PATH must name the shipped worker program"
#endif

/* ---- the ABI, as ABI.md states it ------------------------------------- */
typedef struct {
    uint64_t wall_clock_deadline_ns;
    uint64_t cpu_seconds;
    uint64_t address_space_bytes;
    uint64_t max_output_bytes;
    uint64_t file_size_bytes;
    uint32_t nofile;
    uint32_t reserved;
} stack_supervised_limits;

typedef struct {
    uint64_t elapsed_ns;
    uint64_t result_length;
    int32_t outcome;
    int32_t exit_code;
    int32_t signal_number;
    int32_t error_number;
    int32_t child_pid;
    uint8_t deadline_fired;
    uint8_t result_self_reported;
    uint8_t exit_observed;
    uint8_t frame_status;
} stack_supervised_report;

_Static_assert(sizeof(stack_supervised_report) == 40, "the report keeps its ABI size");
_Static_assert(sizeof(stack_supervised_limits) == 48, "the limits keep their ABI size");

int stack_host_initialize(void);
int stack_host_initialize_and_seal(void);
int stack_host_set_capabilities(uint64_t m0, uint64_t m1, uint64_t m2, uint64_t m3);
int stack_execute_governed_transaction(uint64_t context_id, uint64_t required_capability_m0, uint32_t required_tokens,
                                       uint64_t deadline_budget_ticks, uint64_t hard_timeout_nanoseconds);
uint64_t stack_host_payload_count(void);
int stack_supervised_run_governed(uint64_t context_id, uint64_t required_capability_m0, uint32_t required_tokens,
                                  uint32_t payload_kind, const char* worker_path, const uint8_t* worker_sha256,
                                  const stack_supervised_limits* limits, uint64_t reap_timeout_ns, uint8_t* out,
                                  size_t out_capacity, stack_supervised_report* report);
int stack_supervised_image_sha256(const char* path, uint8_t* out);
uint64_t stack_supervised_unconfirmed_count(void);

/* ---- a tiny check harness --------------------------------------------- */
static int g_check = 0;
#define CHECK(cond)                                                               \
    do {                                                                          \
        ++g_check;                                                                \
        if (!(cond)) {                                                            \
            fprintf(stderr, "check %d failed at line %d: %s\n", g_check, __LINE__, #cond); \
            return g_check;                                                       \
        }                                                                         \
    } while (0)

/* Return codes (ABI.md). */
enum { kOk = 0, kCapabilityDenied = -4, kWorkerUnusable = -14 };
/* stack::supervised::Outcome values. */
enum { kCompleted = 0, kTimedOut = 1, kCrashed = 2 };
/* ExitKind and FrameStatus values (ABI.md). */
enum { kExited = 1, kSignaled = 2, kKilledBySupervisor = 3, kFrameValid = 1, kFrameMissing = 2 };

#define NO_DEADLINE (~(uint64_t)0)

static int run_governed(uint64_t ctx, uint64_t caps, uint32_t kind, uint64_t deadline_ns, const uint8_t* digest,
                        const char* path, uint8_t* out, size_t cap, stack_supervised_report* report) {
    stack_supervised_limits lim;
    memset(&lim, 0, sizeof lim);
    lim.wall_clock_deadline_ns = deadline_ns;
    lim.address_space_bytes = (uint64_t)1 << 30;
    lim.max_output_bytes = cap;
    return stack_supervised_run_governed(ctx, caps, 1, kind, path, digest, &lim, 0, out, cap, report);
}

static int g_sealed_thread_result = -1;

/* On a fresh thread: seal it (irreversible, per thread), then the in-process governed path. */
static void* sealed_thread(void* arg) {
    (void)arg;
    int step = 0;
    if (stack_host_initialize_and_seal() != 0) { g_sealed_thread_result = 1; return NULL; }
    step = 2;
    const uint64_t before = stack_host_payload_count();
    /* success: the granted capability, a valid request */
    if (stack_execute_governed_transaction(1, 0x01, 1, NO_DEADLINE, 1000000000ULL) != kOk) { g_sealed_thread_result = step; return NULL; }
    step = 3;
    if (stack_host_payload_count() != before + 1) { g_sealed_thread_result = step; return NULL; }
    step = 4;
    /* refusal: a capability that was not granted; nothing runs */
    if (stack_execute_governed_transaction(1, 0x02, 1, NO_DEADLINE, 1000000000ULL) != kCapabilityDenied) { g_sealed_thread_result = step; return NULL; }
    step = 5;
    if (stack_host_payload_count() != before + 1) { g_sealed_thread_result = step; return NULL; }
    g_sealed_thread_result = 0;
    return NULL;
}

int main(void) {
    /* init, twice: idempotent (ABI.md section 3). */
    CHECK(stack_host_initialize() == 0);
    CHECK(stack_host_initialize() == 0);
    CHECK(stack_host_set_capabilities(0x01, 0, 0, 0) == 0);

    /* provisioning: the governed supervised path requires the pinned image digest. */
    uint8_t digest[32];
    CHECK(stack_supervised_image_sha256(STACK_WORKER_PATH, digest) == 0);

    /* governed supervised run, success: the worker returns its bytes. */
    uint8_t out[64];
    stack_supervised_report r;
    memset(&r, 0xFF, sizeof r);
    CHECK(run_governed(2, 0x01, 0, 2000000000ULL, digest, STACK_WORKER_PATH, out, sizeof out, &r) == kOk);
    CHECK(r.outcome == kCompleted);
    CHECK(r.exit_observed == kExited && r.exit_code == 0);
    CHECK(r.frame_status == kFrameValid);
    CHECK(r.result_self_reported == 1);
    CHECK(r.result_length == 20 && memcmp(out, "stack-ffi-payload-v1", 20) == 0);
    CHECK(r.child_pid > 0);

    /* supervised run, the supervisor kills a spinner at the deadline and says so itself. */
    memset(&r, 0xFF, sizeof r);
    CHECK(run_governed(3, 0x01, 1, 150000000ULL, digest, STACK_WORKER_PATH, out, sizeof out, &r) == kOk);
    CHECK(r.outcome == kTimedOut && r.deadline_fired == 1);
    CHECK(r.exit_observed == kKilledBySupervisor && r.signal_number == 9);
    CHECK(r.frame_status == kFrameMissing);
    CHECK(r.result_self_reported == 0 && r.result_length == 0);

    /* supervised run, a crash is Signaled and never Completed. */
    memset(&r, 0xFF, sizeof r);
    CHECK(run_governed(4, 0x01, 3, 2000000000ULL, digest, STACK_WORKER_PATH, out, sizeof out, &r) == kOk);
    CHECK(r.outcome == kCrashed && r.exit_observed == kSignaled && r.signal_number == 11);
    CHECK(r.result_self_reported == 0);

    /* refusals: nothing is spawned, the report comes back zeroed. */
    memset(&r, 0xFF, sizeof r);
    CHECK(run_governed(5, 0x02, 0, 1000000000ULL, digest, STACK_WORKER_PATH, out, sizeof out, &r) == kCapabilityDenied);
    CHECK(r.child_pid == 0 && r.exit_observed == 0 && r.frame_status == 0);
    memset(&r, 0xFF, sizeof r);
    CHECK(run_governed(5, 0x01, 0, 1000000000ULL, digest, "/nonexistent/stack_worker", out, sizeof out, &r) == kWorkerUnusable);
    CHECK(r.child_pid == 0 && r.exit_observed == 0 && r.frame_status == 0);
    CHECK(stack_supervised_unconfirmed_count() == 0);

    /* governed transaction on a sealed thread: success and refusal. */
    pthread_t t;
    CHECK(pthread_create(&t, NULL, sealed_thread, NULL) == 0);
    CHECK(pthread_join(t, NULL) == 0);
    if (g_sealed_thread_result != 0) fprintf(stderr, "sealed thread stopped at step %d\n", g_sealed_thread_result);
    CHECK(g_sealed_thread_result == 0);

    /* lifetime (ABI.md section 3): the host lives for the process. A repeated init after use is
     * idempotent and does not reset anything: the granted capability still admits a run, and the
     * payload counter was not rewound. There is no teardown entry point to call. */
    const uint64_t runs = stack_host_payload_count();
    CHECK(runs >= 1);
    CHECK(stack_host_initialize() == 0);
    CHECK(stack_host_payload_count() == runs);
    memset(&r, 0xFF, sizeof r);
    CHECK(run_governed(6, 0x01, 0, 2000000000ULL, digest, STACK_WORKER_PATH, out, sizeof out, &r) == kOk);
    CHECK(r.outcome == kCompleted && r.exit_observed == kExited && r.frame_status == kFrameValid);

    printf("ffi_c_caller: %d checks passed\n", g_check);
    return 0;
}
