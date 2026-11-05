/* A C-language caller of the AUTHORIZED entry points (D2-A, Step 3).
 *
 * Compiled as C (-Wall -Wextra -Werror) against the FFI wrapper as a static
 * library, like ffi_c_caller.c. It calls the exported symbols
 * stack_supervised_run_authorized and stack_execute_governed_transaction_authorized
 * directly and pins four things:
 *
 *   1. A null or all-zero capability digest is refused with -18 and nothing
 *      runs: the worker spawn counter and the payload counter do not move.
 *   2. A legitimate non-zero digest runs the intended worker end to end and
 *      leaves an AuthorizationBound audit event whose label is derived from the
 *      digest (first 8 bytes, big endian).
 *   3. NON-GUARANTEE, pinned: a made-up non-zero digest is ACCEPTED. The host
 *      holds no trust set and cannot tell a real digest from garbage. The
 *      authorized entry points are an anti-misuse boundary for callers that go
 *      through the Rust API, not protection against code in this process.
 *   4. Governance is still enforced after authorization: an ungranted
 *      capability is -4 and an exhausted domain is -5, with nothing spawned.
 *
 * Exit status 0 means every check held; any other value is the number of the
 * first check that did not.
 */
#include <pthread.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#ifndef STACK_WORKER_PATH
#error "STACK_WORKER_PATH must name the shipped worker program"
#endif

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

int stack_host_initialize(void);
int stack_host_initialize_and_seal(void);
int stack_host_set_capabilities(uint64_t m0, uint64_t m1, uint64_t m2, uint64_t m3);
uint64_t stack_host_payload_count(void);
uint64_t stack_host_worker_spawn_count(void);
int stack_host_audit_read_slot(uint64_t index, uint8_t* out_event_type, uint64_t* out_timestamp,
                               uint64_t* out_context_id, uint32_t* out_tokens);
int stack_supervised_image_sha256(const char* path, uint8_t* out);
int stack_supervised_run_authorized(const uint8_t* capability_digest, uint64_t context_id,
                                    uint64_t required_capability_m0, uint32_t required_tokens, uint32_t payload_kind,
                                    const char* worker_path, const uint8_t* worker_sha256,
                                    const stack_supervised_limits* limits, uint64_t reap_timeout_ns, uint8_t* out,
                                    size_t out_capacity, stack_supervised_report* report);
int stack_supervised_run_authorized_cancellable(const uint8_t* capability_digest, uint64_t run_id, uint64_t context_id,
                                                uint64_t required_capability_m0, uint32_t required_tokens,
                                                uint32_t payload_kind, const char* worker_path,
                                                const uint8_t* worker_sha256, const stack_supervised_limits* limits,
                                                uint64_t reap_timeout_ns, uint8_t* out, size_t out_capacity,
                                                stack_supervised_report* report);
int stack_supervised_cancel(uint64_t run_id);
uint64_t stack_supervised_in_flight_count(void);
int stack_execute_governed_transaction_authorized(const uint8_t* capability_digest, uint64_t context_id,
                                                  uint64_t required_capability_m0, uint32_t required_tokens,
                                                  uint64_t deadline_budget_ticks, uint64_t hard_timeout_nanoseconds);

static int g_check = 0;
#define CHECK(cond)                                                                        \
    do {                                                                                   \
        ++g_check;                                                                         \
        if (!(cond)) {                                                                     \
            fprintf(stderr, "check %d failed at line %d: %s\n", g_check, __LINE__, #cond); \
            return g_check;                                                                \
        }                                                                                  \
    } while (0)

enum { kOk = 0, kCapabilityDenied = -4, kRateLimited = -5, kAuthorizationRequired = -18, kRunIdUnavailable = -19 };
enum { kTerminated = 13, kKilledBySupervisorKind = 3 };
enum { kCompleted = 0, kAuthorizationBoundEvent = 10 };
#define NO_DEADLINE (~(uint64_t)0)

static int run(const uint8_t* cap_digest, uint64_t ctx, uint64_t caps, uint32_t tokens, uint32_t kind,
               const uint8_t* worker_digest, uint8_t* out, size_t cap, stack_supervised_report* report) {
    stack_supervised_limits lim;
    memset(&lim, 0, sizeof lim);
    lim.wall_clock_deadline_ns = 2000000000ULL;
    lim.address_space_bytes = (uint64_t)1 << 30;
    lim.max_output_bytes = cap;
    return stack_supervised_run_authorized(cap_digest, ctx, caps, tokens, kind, STACK_WORKER_PATH, worker_digest,
                                           &lim, 0, out, cap, report);
}

/* How many AuthorizationBound events with this label the host's audit ring holds. */
static int bound_events(uint64_t label) {
    int n = 0;
    for (uint64_t i = 0; i < 8192; ++i) {
        uint8_t type = 0;
        uint64_t ts = 0, ctx = 0;
        uint32_t tokens = 0;
        if (stack_host_audit_read_slot(i, &type, &ts, &ctx, &tokens) == 0 && type == kAuthorizationBoundEvent &&
            ctx == label)
            ++n;
    }
    return n;
}

static uint64_t label_of(const uint8_t* d) {
    uint64_t l = 0;
    for (int i = 0; i < 8; ++i) l = (l << 8) | d[i];
    return l;
}

/* R-5: a spinning worker run by id on its own thread, stopped from the main thread. */
static int g_spin_rc = 12345;
static stack_supervised_report g_spin_report;
static uint8_t g_spin_digest[32];
static const uint8_t* g_worker_digest_for_thread;
static void* spin_thread(void* arg) {
    (void)arg;
    uint8_t out[64];
    stack_supervised_limits lim;
    memset(&lim, 0, sizeof lim);
    lim.wall_clock_deadline_ns = 3000000000ULL; /* it would run 3 s if nothing stopped it */
    lim.address_space_bytes = (uint64_t)1 << 30;
    lim.max_output_bytes = sizeof out;
    g_spin_rc = stack_supervised_run_authorized_cancellable(g_spin_digest, 777, 6, 0x01, 1, 1 /* SpinForever */,
                                                            STACK_WORKER_PATH, g_worker_digest_for_thread, &lim, 0,
                                                            out, sizeof out, &g_spin_report);
    return NULL;
}

static int g_sealed_result = -1;
static uint64_t g_payload_before = 0, g_payload_after_zero = 0, g_payload_after_ok = 0;
static int g_zero_rc = 0, g_null_rc = 0, g_ok_rc = 0, g_denied_rc = 0;

/* On a fresh thread: seal it, then the in-process authorized transaction. */
static void* sealed_thread(void* arg) {
    (void)arg;
    uint8_t zero[32];
    memset(zero, 0, sizeof zero);
    uint8_t legit[32];
    memset(legit, 0x7c, sizeof legit);
    if (stack_host_initialize_and_seal() != 0) { g_sealed_result = 1; return NULL; }
    g_payload_before = stack_host_payload_count();
    g_zero_rc = stack_execute_governed_transaction_authorized(zero, 1, 0x01, 1, NO_DEADLINE, 1000000000ULL);
    g_null_rc = stack_execute_governed_transaction_authorized(NULL, 1, 0x01, 1, NO_DEADLINE, 1000000000ULL);
    g_payload_after_zero = stack_host_payload_count();
    g_ok_rc = stack_execute_governed_transaction_authorized(legit, 1, 0x01, 1, NO_DEADLINE, 1000000000ULL);
    g_payload_after_ok = stack_host_payload_count();
    g_denied_rc = stack_execute_governed_transaction_authorized(legit, 1, 0x02, 1, NO_DEADLINE, 1000000000ULL);
    g_sealed_result = 0;
    return NULL;
}

int main(void) {
    CHECK(stack_host_initialize() == 0);
    CHECK(stack_host_set_capabilities(0x01, 0, 0, 0) == 0);
    uint8_t worker_digest[32];
    CHECK(stack_supervised_image_sha256(STACK_WORKER_PATH, worker_digest) == 0);

    uint8_t zero[32];
    memset(zero, 0, sizeof zero);
    uint8_t legit[32];
    for (int i = 0; i < 32; ++i) legit[i] = (uint8_t)(0xA0 + i);
    uint8_t garbage[32];
    memset(garbage, 0x01, sizeof garbage); /* not any capability's digest: the host cannot know */
    uint8_t out[64];
    stack_supervised_report r;

    /* 1. Refused: null and all-zero digest. Nothing spawned, report zeroed. */
    const uint64_t spawns0 = stack_host_worker_spawn_count();
    memset(&r, 0xFF, sizeof r);
    CHECK(run(zero, 2, 0x01, 1, 0, worker_digest, out, sizeof out, &r) == kAuthorizationRequired);
    CHECK(r.child_pid == 0 && r.outcome == 0 && r.exit_observed == 0 && r.frame_status == 0);
    memset(&r, 0xFF, sizeof r);
    CHECK(run(NULL, 2, 0x01, 1, 0, worker_digest, out, sizeof out, &r) == kAuthorizationRequired);
    CHECK(r.child_pid == 0);
    /* The refusal precedes every other check: even a request that is otherwise invalid says -18. */
    CHECK(run(zero, 2, 0x02, 1, 0, worker_digest, out, sizeof out, &r) == kAuthorizationRequired);
    CHECK(stack_host_worker_spawn_count() == spawns0);
    CHECK(bound_events(label_of(zero)) == 0);

    /* 2. A legitimate digest runs the intended worker end to end and is audited by label. */
    CHECK(bound_events(label_of(legit)) == 0);
    memset(&r, 0xFF, sizeof r);
    CHECK(run(legit, 3, 0x01, 1, 0, worker_digest, out, sizeof out, &r) == kOk);
    CHECK(r.outcome == kCompleted && r.exit_observed == 1 && r.exit_code == 0 && r.frame_status == 1);
    CHECK(r.result_length == 20 && memcmp(out, "stack-ffi-payload-v1", 20) == 0);
    CHECK(stack_host_worker_spawn_count() == spawns0 + 1);
    CHECK(bound_events(label_of(legit)) == 1);

    /* 3. NON-GUARANTEE (pinned): a made-up non-zero digest is accepted and runs the worker. */
    memset(&r, 0xFF, sizeof r);
    CHECK(run(garbage, 3, 0x01, 1, 0, worker_digest, out, sizeof out, &r) == kOk);
    CHECK(r.outcome == kCompleted && r.child_pid > 0);
    CHECK(stack_host_worker_spawn_count() == spawns0 + 2);
    CHECK(bound_events(label_of(garbage)) == 1);

    /* 4. Governance after authorization: an ungranted capability and an exhausted domain refuse, spawning nothing. */
    memset(&r, 0xFF, sizeof r);
    CHECK(run(legit, 4, 0x02, 1, 0, worker_digest, out, sizeof out, &r) == kCapabilityDenied);
    CHECK(r.child_pid == 0);
    CHECK(stack_host_worker_spawn_count() == spawns0 + 2);
    int served = 0, rc = 0;
    struct timespec s0, s1;
    clock_gettime(CLOCK_MONOTONIC, &s0);
    for (int i = 0; i < 40 && rc == 0; ++i) {
        rc = run(legit, 5, 0x01, 100, 0, worker_digest, out, sizeof out, &r);
        if (rc == 0) ++served;
    }
    clock_gettime(CLOCK_MONOTONIC, &s1);
    /* 9 from a full bucket, plus one per 100 ms of refill. */
    long ms = (s1.tv_sec - s0.tv_sec) * 1000 + (s1.tv_nsec - s0.tv_nsec) / 1000000;
    CHECK(rc == kRateLimited && served >= 9 && served <= 9 + (int)(ms / 100) + 1);
    CHECK(stack_host_worker_spawn_count() == spawns0 + 2 + (uint64_t)served);

    /* R-5: stop a run by id. Unknown ids are no-ops; an id in flight cannot be reused. */
    CHECK(stack_supervised_cancel(0) == 0);
    CHECK(stack_supervised_cancel(555555) == 0);
    memcpy(g_spin_digest, legit, sizeof legit);
    g_worker_digest_for_thread = worker_digest;
    memset(&g_spin_report, 0xFF, sizeof g_spin_report);
    pthread_t spin;
    CHECK(pthread_create(&spin, NULL, spin_thread, NULL) == 0);
    for (int i = 0; i < 2000 && stack_supervised_in_flight_count() < 1; ++i) {
        struct timespec ts = {0, 2000000};
        nanosleep(&ts, NULL);
    }
    CHECK(stack_supervised_in_flight_count() == 1);
    {
        struct timespec ts = {0, 100000000}; /* it is really spinning */
        nanosleep(&ts, NULL);
    }
    {
        stack_supervised_limits lim;
        memset(&lim, 0, sizeof lim);
        lim.wall_clock_deadline_ns = 1000000000ULL;
        lim.address_space_bytes = (uint64_t)1 << 30;
        lim.max_output_bytes = sizeof out;
        CHECK(stack_supervised_run_authorized_cancellable(legit, 777, 7, 0x01, 1, 0, STACK_WORKER_PATH, worker_digest,
                                                          &lim, 0, out, sizeof out, &r) == kRunIdUnavailable);
        CHECK(stack_supervised_run_authorized_cancellable(legit, 0, 7, 0x01, 1, 0, STACK_WORKER_PATH, worker_digest,
                                                          &lim, 0, out, sizeof out, &r) == kRunIdUnavailable);
    }
    struct timespec t0, t1;
    clock_gettime(CLOCK_MONOTONIC, &t0);
    CHECK(stack_supervised_cancel(777) == 1);
    CHECK(pthread_join(spin, NULL) == 0);
    clock_gettime(CLOCK_MONOTONIC, &t1);
    CHECK((t1.tv_sec - t0.tv_sec) * 1000 + (t1.tv_nsec - t0.tv_nsec) / 1000000 < 1000); /* killed in under a second */
    CHECK(g_spin_rc == kOk);
    CHECK(g_spin_report.outcome == kTerminated && g_spin_report.exit_observed == kKilledBySupervisorKind);
    CHECK(g_spin_report.signal_number == 9 && g_spin_report.deadline_fired == 0 && g_spin_report.result_self_reported == 0);
    CHECK(stack_supervised_cancel(777) == 0); /* finished: a no-op */
    CHECK(stack_supervised_in_flight_count() == 0);

    /* The in-process transaction, on a sealed thread. */
    pthread_t t;
    CHECK(pthread_create(&t, NULL, sealed_thread, NULL) == 0);
    CHECK(pthread_join(t, NULL) == 0);
    CHECK(g_sealed_result == 0);
    CHECK(g_zero_rc == kAuthorizationRequired && g_null_rc == kAuthorizationRequired);
    CHECK(g_payload_after_zero == g_payload_before);
    CHECK(g_ok_rc == kOk && g_payload_after_ok == g_payload_before + 1);
    CHECK(g_denied_rc == kCapabilityDenied);
    CHECK(stack_host_payload_count() == g_payload_before + 1);

    printf("ffi_authorized_caller: %d checks passed\n", g_check);
    return 0;
}
