// Governed supervised runs through the shipped FFI wrapper
// (crates/stack-ffi/src/ffi_wrapper.cpp, stack_supervised_run_governed).
//
// RACE-02, R2-K-13 and decision A: the supervised path takes the same
// context, capability and token arguments as the governed transaction and
// checks them through the initialized host BEFORE it spawns. A refused
// request spawns nothing and consumes nothing; a spawned run spends its
// tokens and leaves one audit event, timeouts included.
//
// "Nothing was spawned" is observed with a SIGCHLD counter: every child this
// process spawns ends in a SIGCHLD, so a refusal leaves the count unchanged.
// "Nothing was consumed" is observed by counting how many 100-token requests
// a fresh domain then serves (9 of the 1000-token bucket above its floor of
// 100), with an allowance of one extra request per 100 ms elapsed, since the
// bucket refills at 1000 tokens per second.
//
// Built with -DSTACK_SUPERVISED_TESTING so the ineffective-kill seam can be
// used; the seam does nothing until a test installs a hook.

#include <catch2/catch_test_macros.hpp>

#include <atomic>
#include <chrono>
#include <csignal>
#include <cstdint>
#include <cstring>
#include <thread>

#include <sys/wait.h>
#include <unistd.h>

#include "../include/stack_supervised_exec.hpp"

extern "C" {
int stack_host_initialize();
int stack_host_initialize_and_seal();
int stack_host_set_capabilities(uint64_t, uint64_t, uint64_t, uint64_t);
int stack_host_audit_read_slot(uint64_t, uint8_t*, uint64_t*, uint64_t*, uint32_t*);
uint64_t stack_supervised_unconfirmed_count();
uint64_t stack_supervised_reap_unconfirmed();

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
    int32_t outcome;
    int32_t exit_code;
    int32_t signal_number;
    int32_t error_number;
    int32_t child_pid;
    uint8_t deadline_fired;
    uint8_t result_self_reported;
    uint8_t reserved[2];
};
int stack_supervised_run_governed(uint64_t, uint64_t, uint32_t, uint32_t, const char*, const stack_supervised_limits*,
                                  uint64_t, uint8_t*, size_t, stack_supervised_report*);
}

#ifndef STACK_WORKER_PATH
#error "STACK_WORKER_PATH must name the shipped worker program"
#endif

namespace {

constexpr uint64_t kMs = 1'000'000ULL;
// Return codes (ffi_wrapper.cpp).
constexpr int kRan = 0, kNotInitialized = -1, kUnknownKind = -2, kNullArgument = -3, kCapabilityDenied = -4,
              kRateLimited = -5, kZeroDeadline = -9, kWorkerUnusable = -14, kLimitsInvalid = -15;
// Outcome values (stack::supervised::Outcome).
constexpr int kCompleted = 0, kTimedOut = 1, kSigchldIgnored = 11, kTerminationUnconfirmed = 12;
// AuditEventType values (stack_audit.hpp).
constexpr uint8_t kAuditRateLimited = 1, kAuditCapabilityViolation = 4, kAuditSupervisedCompleted = 5,
                  kAuditSupervisedTimedOut = 6, kAuditSupervisedFailed = 7, kAuditSupervisedUnconfirmed = 8;
constexpr uint64_t kHostAuditSlots = 8192;
constexpr uint64_t kCap = 0x01;  // the capability bit the tests grant
constexpr uint32_t kRequest = 100;

std::atomic<int> g_sigchld{0};
void OnSigchld(int) { g_sigchld.fetch_add(1, std::memory_order_relaxed); }

struct Result {
    int rc = 99;
    stack_supervised_report report{};
    uint8_t out[64]{};
};

Result Governed(uint64_t domain, uint64_t caps, uint32_t tokens, uint32_t kind, uint64_t deadline_ns = 2'000 * kMs,
                const char* path = STACK_WORKER_PATH, uint64_t reap_ns = 0) {
    Result r;
    stack_supervised_limits l{};
    l.wall_clock_deadline_ns = deadline_ns;
    l.address_space_bytes = 1ULL << 30;
    l.max_output_bytes = sizeof r.out;
    r.rc = stack_supervised_run_governed(domain, caps, tokens, kind, path, &l, reap_ns, r.out, sizeof r.out, &r.report);
    return r;
}

void Setup() {
    static const bool once = [] {
        struct sigaction sa{};
        sa.sa_handler = OnSigchld;
        sigemptyset(&sa.sa_mask);
        sa.sa_flags = SA_RESTART | SA_NOCLDSTOP;
        REQUIRE(::sigaction(SIGCHLD, &sa, nullptr) == 0);
        REQUIRE(stack_host_initialize() == 0);
        REQUIRE(stack_host_set_capabilities(kCap, 0, 0, 0) == 0);
        return true;
    }();
    (void)once;
}

// Waits (bounded) until the SIGCHLD count reaches at least `n`.
bool WaitForSigchld(int n) {
    for (int i = 0; i < 400; ++i) {
        if (g_sigchld.load() >= n) return true;
        ::usleep(5'000);
    }
    return false;
}

struct AuditView {
    int count = 0;
    uint32_t tokens = 0;  // of the last match
};

AuditView Audit(uint64_t domain, uint8_t type) {
    AuditView v;
    for (uint64_t i = 0; i < kHostAuditSlots; ++i) {
        uint8_t t = 0;
        uint64_t ts = 0, ctx = 0;
        uint32_t tok = 0;
        if (stack_host_audit_read_slot(i, &t, &ts, &ctx, &tok) != 0) continue;
        if (ctx == domain && t == type) {
            ++v.count;
            v.tokens = tok;
        }
    }
    return v;
}

// How many kRequest-token runs a fresh domain serves before RateLimited.
int ServedRequests(uint64_t domain, int already_spent = 0) {
    using Clock = std::chrono::steady_clock;
    const auto t0 = Clock::now();
    int ok = 0;
    for (int i = 0; i < 40; ++i) {
        const Result r = Governed(domain, kCap, kRequest, 0);
        if (r.rc != kRan) {
            REQUIRE(r.rc == kRateLimited);
            break;
        }
        ++ok;
    }
    const auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(Clock::now() - t0).count();
    // 9 from a full bucket; one more per 100 ms of refill.
    INFO("served " << ok << " in " << ms << " ms");
    REQUIRE(ok >= 9 - already_spent);
    REQUIRE(ok <= 9 - already_spent + static_cast<int>(ms / 100) + 1);
    return ok;
}

bool Alive(pid_t pid) { return ::kill(pid, 0) == 0; }

bool IneffectiveKill(pid_t, int) { return true; }

}  // namespace

TEST_CASE("Governed supervised: before the host is initialized nothing is spawned", "[governed]") {
    // Runs in a forked copy because the host is process global and the other
    // cases initialize it.
    const pid_t pid = ::fork();
    REQUIRE(pid >= 0);
    if (pid == 0) {
        const Result r = Governed(1, kCap, 1, 0);
        ::_exit(r.rc == kNotInitialized && r.report.child_pid == 0 ? 0 : 1);
    }
    int status = 0;
    REQUIRE(::waitpid(pid, &status, 0) == pid);
    REQUIRE(WIFEXITED(status));
    REQUIRE(WEXITSTATUS(status) == 0);
}

TEST_CASE("Governed supervised: a valid request runs the worker, spends its tokens and is audited", "[governed]") {
    Setup();
    const uint64_t domain = 2;
    const int before = g_sigchld.load();
    const Result r = Governed(domain, kCap, kRequest, 0);
    REQUIRE(r.rc == kRan);
    REQUIRE(r.report.outcome == kCompleted);
    REQUIRE(r.report.result_self_reported == 1);
    REQUIRE(std::string(reinterpret_cast<const char*>(r.out), r.report.result_length) == "stack-ffi-payload-v1");
    REQUIRE(r.report.child_pid > 0);
    REQUIRE(WaitForSigchld(before + 1));
    const AuditView a = Audit(domain, kAuditSupervisedCompleted);
    REQUIRE(a.count == 1);
    REQUIRE(a.tokens == kRequest);
    // 100 tokens were spent: 8 more requests, not 9.
    ServedRequests(domain, /*already_spent*/ 1);
}

TEST_CASE("Governed supervised: an invalid capability is refused with no spawn and no tokens consumed", "[governed]") {
    Setup();
    const uint64_t domain = 3;
    const int before = g_sigchld.load();
    for (const uint64_t caps : {uint64_t{0x02}, uint64_t{0xF0}, uint64_t{0}}) {
        const Result r = Governed(domain, caps, kRequest, 0);
        INFO("caps " << caps);
        REQUIRE(r.rc == kCapabilityDenied);
        REQUIRE(r.report.child_pid == 0);
    }
    ::usleep(100'000);
    REQUIRE(g_sigchld.load() == before);  // nothing spawned
    // Two of the three were audited as violations (a request naming no
    // capability is refused before the host sees it).
    REQUIRE(Audit(domain, kAuditCapabilityViolation).count == 2);
    REQUIRE(Audit(domain, kAuditSupervisedCompleted).count == 0);
    ServedRequests(domain);  // tokens untouched: the full 9
}

TEST_CASE("Governed supervised: exhausted tokens are refused with no spawn and the count does not move", "[governed]") {
    Setup();
    const uint64_t domain = 4;
    const int served = ServedRequests(domain);
    (void)served;
    const int before = g_sigchld.load();
    for (int i = 0; i < 5; ++i) {
        const Result r = Governed(domain, kCap, kRequest, 0);
        REQUIRE(r.rc == kRateLimited);
        REQUIRE(r.report.child_pid == 0);
    }
    ::usleep(100'000);
    REQUIRE(g_sigchld.load() == before + 0);
    REQUIRE(Audit(domain, kAuditRateLimited).count >= 5);
    // A request above the largest allowed one, and an unknown domain, are rate limited too.
    REQUIRE(Governed(5, kCap, 101, 0).rc == kRateLimited);
    REQUIRE(Governed(16, kCap, 1, 0).rc == kRateLimited);
}

TEST_CASE("Governed supervised: refusals before governance consume nothing", "[governed]") {
    Setup();
    const uint64_t domain = 6;
    const int before = g_sigchld.load();
    REQUIRE(Governed(domain, kCap, kRequest, 0, /*deadline*/ 0).rc == kZeroDeadline);
    REQUIRE(Governed(domain, kCap, kRequest, 7).rc == kUnknownKind);
    REQUIRE(Governed(domain, kCap, kRequest, 0, 2'000 * kMs, nullptr).rc == kWorkerUnusable);
    REQUIRE(Governed(domain, kCap, kRequest, 0, 2'000 * kMs, "stack_worker").rc == kWorkerUnusable);
    REQUIRE(Governed(domain, kCap, kRequest, 0, 2'000 * kMs, "/nonexistent/stack_worker").rc == kWorkerUnusable);
    REQUIRE(Governed(domain, kCap, kRequest, 0, 2'000 * kMs, "/etc/hostname").rc == kWorkerUnusable);
    REQUIRE(Governed(domain, kCap, kRequest, 0, 3'600'000 * kMs + 1).rc == kLimitsInvalid);
    REQUIRE(Governed(domain, kCap, kRequest, 0, 2'000 * kMs, STACK_WORKER_PATH, 61'000 * kMs).rc == kLimitsInvalid);
    {
        Result r;
        stack_supervised_limits l{};
        l.wall_clock_deadline_ns = 1'000 * kMs;
        l.max_output_bytes = 128;  // above the 64-byte buffer
        r.rc = stack_supervised_run_governed(domain, kCap, kRequest, 0, STACK_WORKER_PATH, &l, 0, r.out, sizeof r.out, &r.report);
        REQUIRE(r.rc == kLimitsInvalid);
        r.rc = stack_supervised_run_governed(domain, kCap, kRequest, 0, STACK_WORKER_PATH, nullptr, 0, r.out, sizeof r.out, &r.report);
        REQUIRE(r.rc == kNullArgument);
        r.rc = stack_supervised_run_governed(domain, kCap, kRequest, 0, STACK_WORKER_PATH, &l, 0, r.out, sizeof r.out, nullptr);
        REQUIRE(r.rc == kNullArgument);
    }
    ::usleep(100'000);
    REQUIRE(g_sigchld.load() == before);
    ServedRequests(domain);  // the full 9: not one token was taken
}

TEST_CASE("Governed supervised: a timeout is audited and still spends its tokens", "[governed]") {
    Setup();
    const uint64_t domain = 7;
    const Result r = Governed(domain, kCap, kRequest, 1 /* spin */, 150 * kMs);
    REQUIRE(r.rc == kRan);
    REQUIRE(r.report.outcome == kTimedOut);
    REQUIRE(r.report.result_self_reported == 0);
    REQUIRE(r.report.deadline_fired == 1);
    const AuditView a = Audit(domain, kAuditSupervisedTimedOut);
    REQUIRE(a.count == 1);
    REQUIRE(a.tokens == kRequest);
    REQUIRE(Audit(domain, kAuditSupervisedCompleted).count == 0);
    ServedRequests(domain, /*already_spent*/ 1);
}

TEST_CASE("Governed supervised: other ends are audited as failed, never as completed", "[governed]") {
    Setup();
    const uint64_t domain = 8;
    for (const uint32_t kind : {3u, 4u, 5u, 6u}) {  // crash, abort, exit 3, forbidden syscall
        const Result r = Governed(domain, kCap, 1, kind);
        INFO(kind);
        REQUIRE(r.rc == kRan);
        REQUIRE(r.report.outcome != kCompleted);
        REQUIRE(r.report.result_self_reported == 0);
    }
    REQUIRE(Audit(domain, kAuditSupervisedFailed).count == 4);
    REQUIRE(Audit(domain, kAuditSupervisedCompleted).count == 0);
}

TEST_CASE("Governed supervised: a run that spawns nothing refunds its tokens and is audited as failed", "[governed]") {
    Setup();
    // SIGCHLD ignored is refused by the supervisor after governance passed.
    // The disposition is process wide, so a forked copy does it; the copy
    // shares the host's state as of the fork.
    const uint64_t domain = 9;
    const pid_t pid = ::fork();
    REQUIRE(pid >= 0);
    if (pid == 0) {
        ::signal(SIGCHLD, SIG_IGN);
        const Result r = Governed(domain, kCap, kRequest, 0);
        ::signal(SIGCHLD, SIG_DFL);
        const bool refused = r.rc == kRan && r.report.outcome == kSigchldIgnored && r.report.child_pid == 0;
        const bool audited = Audit(domain, kAuditSupervisedFailed).count == 1 && Audit(domain, kAuditSupervisedFailed).tokens == 0;
        // Refunded: the domain still serves its full 9.
        int served = 0;
        ::sigaction(SIGCHLD, nullptr, nullptr);
        for (int i = 0; i < 12; ++i) {
            if (Governed(domain, kCap, kRequest, 0).rc != kRan) break;
            ++served;
        }
        ::_exit(refused && audited && served >= 9 ? 0 : (refused ? (audited ? 3 : 2) : 1));
    }
    int status = 0;
    REQUIRE(::waitpid(pid, &status, 0) == pid);
    REQUIRE(WIFEXITED(status));
    INFO("child exit " << WEXITSTATUS(status) << " (1 not refused, 2 not audited, 3 not refunded)");
    REQUIRE(WEXITSTATUS(status) == 0);
}

TEST_CASE("Governed supervised: a sealed thread cannot spawn: the worker image cannot be opened, nothing is consumed", "[governed]") {
    Setup();
    const uint64_t domain = 10;
    Result r;
    std::thread([&] {
        if (stack_host_initialize_and_seal() != 0) return;
        r = Governed(domain, kCap, kRequest, 0);
    }).join();
    // The seal forbids open(2), so the preflight check of the worker image
    // fails before governance: refused, nothing spawned, nothing consumed.
    REQUIRE(r.rc == kWorkerUnusable);
    REQUIRE(r.report.child_pid == 0);
    ServedRequests(domain);
}

TEST_CASE("Governed supervised: a revocation waits for a run in flight and then refuses", "[governed]") {
    Setup();
    const uint64_t domain = 11;
    Result running;
    std::thread runner([&] { running = Governed(domain, kCap, 1, 1 /* spin */, 250 * kMs); });
    ::usleep(60'000);  // the run is in flight
    const auto t0 = std::chrono::steady_clock::now();
    REQUIRE(stack_host_set_capabilities(0x04, 0, 0, 0) == 0);  // waits for the run, then applies
    const auto waited_ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
    runner.join();
    REQUIRE(running.report.outcome == kTimedOut);
    REQUIRE(waited_ms >= 100);  // it did wait for the run, bounded by the 500 ms drain limit
    // After the revocation the old capability is refused.
    const int before = g_sigchld.load();
    REQUIRE(Governed(domain, kCap, 1, 0).rc == kCapabilityDenied);
    ::usleep(50'000);
    REQUIRE(g_sigchld.load() == before);
    REQUIRE(stack_host_set_capabilities(kCap, 0, 0, 0) == 0);
    REQUIRE(Governed(domain, kCap, 1, 0).rc == kRan);
}

TEST_CASE("Governed supervised: an ineffective kill is TerminationUnconfirmed and audited", "[governed][reap]") {
    Setup();
    const uint64_t domain = 12;
    namespace sv = stack::supervised;
    sv::SupervisedExecutor::SetKillHookForTesting(&IneffectiveKill);
    const Result r = Governed(domain, kCap, kRequest, 1 /* spin */, 100 * kMs, STACK_WORKER_PATH, 200 * kMs);
    REQUIRE(r.rc == kRan);
    REQUIRE(r.report.outcome == kTerminationUnconfirmed);
    REQUIRE(r.report.outcome != kCompleted);
    REQUIRE(r.report.result_self_reported == 0);
    REQUIRE(r.report.elapsed_ns <= (100 + 200 + 1'000) * kMs);
    REQUIRE(Alive(r.report.child_pid));
    REQUIRE(stack_supervised_unconfirmed_count() == 1);
    const AuditView a = Audit(domain, kAuditSupervisedUnconfirmed);
    REQUIRE(a.count == 1);
    REQUIRE(a.tokens == kRequest);

    sv::SupervisedExecutor::SetKillHookForTesting(nullptr);
    for (int i = 0; i < 400 && stack_supervised_reap_unconfirmed() != 0; ++i) ::usleep(10'000);
    REQUIRE(stack_supervised_unconfirmed_count() == 0);
    REQUIRE_FALSE(Alive(r.report.child_pid));
}
