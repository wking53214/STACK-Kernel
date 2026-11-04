// FFI initialization red team (I-02, R2-K-02/03/04). Plain main(); exits
// non-zero on any failure. Built twice: as is (real seccomp filter) and under
// ThreadSanitizer with the prctl interposer (STACK_FFI_NO_SECCOMP), which
// makes the sanitized run a check of the wrapper's synchronization only.
//
// The wrapper is compiled with STACK_FFI_TESTING for the two counters used
// here. Every worker records into fixed arrays: a sealed thread cannot
// allocate.
//
// Scenarios, in order (each depends on the process state the one before
// leaves behind):
//   A  before initialization: every entry point says "not initialized",
//      and asking does not initialize or seal anything;
//   B  initialization failure, in a forked child so the latch does not
//      poison the rest: timer_create fails for the one-time work, every
//      concurrent first-time caller sees the failure, capability updates
//      and transactions are refused with their own codes, the failure is
//      latched, no host was constructed;
//   C  64 first-time initializations released by a barrier: all succeed,
//      the one-time work ran once, the host was constructed once;
//   D  concurrent initialization, capability updates and transaction
//      entry: only documented codes come back;
//   E  no implicit seal: a transaction on an unsealed thread is -11 and the
//      thread stays unfiltered; after sealing it runs;
//   F  repeated initialization and sealing are idempotent.
#include <atomic>
#include <cerrno>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <csignal>
#include <ctime>
#include <thread>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

extern "C" {
int stack_host_initialize();
int stack_host_seal_current_thread();
int stack_host_initialize_and_seal();
int stack_host_set_capabilities(uint64_t, uint64_t, uint64_t, uint64_t);
int stack_execute_governed_transaction(uint64_t, uint64_t, uint32_t, uint64_t, uint64_t);
uint64_t stack_host_payload_count();
uint64_t stack_ffi_testing_init_work_runs();
uint64_t stack_ffi_testing_host_constructions();
}

namespace {

int g_failures = 0;

void Check(bool ok, const char* what) {
    std::printf("  [%s] %s\n", ok ? "ok" : "FAIL", what);
    if (!ok) ++g_failures;
}

// getpid is not on the allowlist: a filtered thread gets ENOSYS.
bool ThisThreadIsFiltered() {
    errno = 0;
    const long rc = ::syscall(SYS_getpid);
    return rc == -1 && errno == ENOSYS;
}

// Under the interposer no thread is ever filtered; the checks that would
// prove a seal landed are not meaningful and are reported as skipped.
#if defined(STACK_FFI_NO_SECCOMP)
constexpr bool kSeccompActive = false;
#else
constexpr bool kSeccompActive = true;
#endif

void CheckFiltered(bool filtered, bool expected, const char* what) {
    if (!kSeccompActive) {
        std::printf("  [skip] %s (seccomp interposed in this build)\n", what);
        return;
    }
    Check(filtered == expected, what);
}

int Txn(uint64_t domain, uint32_t tokens) {
    return stack_execute_governed_transaction(domain, 0x01, tokens, ~0ULL, 1'000'000'000ULL);
}

// A spin barrier: every participant arrives, the main thread releases all.
struct Barrier {
    std::atomic<int> arrived{0};
    std::atomic<bool> go{false};
    void Arrive() {
        arrived.fetch_add(1, std::memory_order_acq_rel);
        while (!go.load(std::memory_order_acquire)) {}
    }
    void ReleaseWhen(int count) {
        while (arrived.load(std::memory_order_acquire) < count) {}
        go.store(true, std::memory_order_release);
    }
};

// Test-only failure injection: the test binary's timer_create wins over the
// libc one for every call in this process, so the wrapper's one-time work
// fails when g_fail_timer_create is set. The real syscall is used otherwise.
std::atomic<bool> g_fail_timer_create{false};

}  // namespace

extern "C" int timer_create(clockid_t clockid, struct sigevent* sevp, timer_t* timerid) {
    if (g_fail_timer_create.load(std::memory_order_acquire)) {
        errno = EAGAIN;
        return -1;
    }
    // What glibc does for a SIGEV_THREAD_ID event (the only kind the wrapper
    // creates): the kernel returns an int id, stored widened in the timer_t.
    int kernel_id = 0;
    const long rc = ::syscall(SYS_timer_create, clockid, sevp, &kernel_id);
    if (rc != 0) return -1;
    *timerid = reinterpret_cast<timer_t>(static_cast<intptr_t>(kernel_id));
    return 0;
}

namespace {

// A: nothing is initialized yet.
void ScenarioA() {
    std::printf("A. before initialization\n");
    Check(stack_host_set_capabilities(0xFF, 0, 0, 0) == -1, "set_capabilities is -1 (not initialized)");
    Check(stack_execute_governed_transaction(1, 1, 1, ~0ULL, 1'000'000'000ULL) == -1, "execute is -1 (not initialized)");
    int seal_rc = 99;
    bool filtered_after = true;
    std::thread([&] {
        seal_rc = stack_host_seal_current_thread();
        filtered_after = ThisThreadIsFiltered();
    }).join();
    Check(seal_rc == -1, "seal_current_thread is -1 (not initialized)");
    CheckFiltered(filtered_after, false, "a refused seal left the thread unfiltered");
    Check(stack_ffi_testing_init_work_runs() == 0, "the one-time work has not run");
    Check(stack_ffi_testing_host_constructions() == 0, "no host constructed");
}

// B: initialization failure, in a forked child. Returns the child's failure count.
int ScenarioBInChild() {
    int failures = 0;
    auto check = [&](bool ok, const char* what) {
        std::printf("  [%s] (child) %s\n", ok ? "ok" : "FAIL", what);
        if (!ok) ++failures;
    };
    g_fail_timer_create.store(true, std::memory_order_release);

    constexpr int kThreads = 8;
    int rc[kThreads];
    Barrier barrier;
    std::thread threads[kThreads];
    for (int i = 0; i < kThreads; ++i) {
        rc[i] = 99;
        threads[i] = std::thread([&, i] { barrier.Arrive(); rc[i] = stack_host_initialize_and_seal(); });
    }
    barrier.ReleaseWhen(kThreads);
    for (auto& t : threads) t.join();
    bool all_failed = true;
    for (int i = 0; i < kThreads; ++i) all_failed = all_failed && rc[i] == -1;
    check(all_failed, "8 concurrent first-time initialize_and_seal all return -1");
    check(stack_host_initialize() == -1, "stack_host_initialize is -1 afterwards (latched)");
    check(stack_host_set_capabilities(0xFF, 0, 0, 0) == -3, "set_capabilities is -3 (initialization failed), not applied");
    check(stack_execute_governed_transaction(1, 1, 1, ~0ULL, 1'000'000'000ULL) == -12, "execute is -12 (initialization failed)");
    int seal_rc = 99;
    std::thread([&] { seal_rc = stack_host_seal_current_thread(); }).join();
    check(seal_rc == -3, "seal_current_thread is -3 (initialization failed)");
    check(stack_ffi_testing_init_work_runs() == 1, "the one-time work ran exactly once");
    check(stack_ffi_testing_host_constructions() == 0, "no host was constructed");

    // Even with timers working again, the failure stays latched.
    g_fail_timer_create.store(false, std::memory_order_release);
    check(stack_host_initialize_and_seal() == -1, "initialize_and_seal stays -1 after the fault is gone");
    check(stack_host_initialize() == -1, "initialize stays -1 after the fault is gone");
    check(stack_ffi_testing_init_work_runs() == 1, "the one-time work was not retried");
    check(stack_host_payload_count() == 0, "no payload ran");
    return failures;
}

void ScenarioB() {
    std::printf("B. initialization failure (forked child)\n");
    std::fflush(stdout);
    const pid_t pid = ::fork();
    if (pid < 0) { Check(false, "fork"); return; }
    if (pid == 0) {
        const int failures = ScenarioBInChild();
        std::fflush(stdout);
        ::_exit(failures > 100 ? 100 : failures);
    }
    int status = 0;
    bool reaped = false;
    for (int waited_ms = 0; waited_ms < 60'000; waited_ms += 10) {
        if (::waitpid(pid, &status, WNOHANG) == pid) { reaped = true; break; }
        timespec nap{0, 10'000'000L};
        ::nanosleep(&nap, nullptr);
    }
    if (!reaped) { ::kill(pid, SIGKILL); ::waitpid(pid, &status, 0); }
    Check(reaped, "child finished within 60 s");
    Check(WIFEXITED(status) && WEXITSTATUS(status) == 0, "child reported no failures");
}

// C: 64 concurrent first-time initializations.
void ScenarioC() {
    std::printf("C. 64 concurrent first-time initializations\n");
    constexpr int kThreads = 64;
    int rc[kThreads];
    bool filtered[kThreads];
    Barrier barrier;
    std::thread threads[kThreads];
    for (int i = 0; i < kThreads; ++i) {
        rc[i] = 99;
        filtered[i] = false;
        threads[i] = std::thread([&, i] {
            barrier.Arrive();
            rc[i] = stack_host_initialize_and_seal();
            filtered[i] = ThisThreadIsFiltered();
        });
    }
    barrier.ReleaseWhen(kThreads);
    for (auto& t : threads) t.join();
    bool all_ok = true, all_filtered = true;
    for (int i = 0; i < kThreads; ++i) { all_ok = all_ok && rc[i] == 0; all_filtered = all_filtered && filtered[i]; }
    Check(all_ok, "all 64 return 0");
    CheckFiltered(all_filtered, true, "all 64 threads are filtered");
    Check(stack_ffi_testing_init_work_runs() == 1, "the one-time work ran exactly once");
    Check(stack_ffi_testing_host_constructions() == 1, "the host was constructed exactly once");
    Check(stack_host_initialize() == 0, "stack_host_initialize is 0 afterwards");
}

// D: initialization racing capability updates and transaction entry.
void ScenarioD() {
    std::printf("D. concurrent initialization, capability updates and transactions\n");
    constexpr int kInit = 16, kCaps = 4, kExec = 4, kIters = 200;
    int init_rc[kInit];
    int caps_hist[kCaps][16] = {};
    int exec_hist[kExec][16] = {};
    int exec_seal[kExec];
    Barrier barrier;
    std::thread threads[kInit + kCaps + kExec];
    int n = 0;
    for (int i = 0; i < kInit; ++i) {
        init_rc[i] = 99;
        threads[n++] = std::thread([&, i] { barrier.Arrive(); init_rc[i] = stack_host_initialize(); });
    }
    for (int i = 0; i < kCaps; ++i) {
        threads[n++] = std::thread([&, i] {
            barrier.Arrive();
            for (int k = 0; k < kIters; ++k) {
                const int r = stack_host_set_capabilities(0xFF, 0, 0, 0);
                caps_hist[i][(-r) & 15]++;
            }
        });
    }
    for (int i = 0; i < kExec; ++i) {
        exec_seal[i] = 99;
        threads[n++] = std::thread([&, i] {
            barrier.Arrive();
            exec_seal[i] = stack_host_initialize_and_seal();
            for (int k = 0; k < kIters; ++k) {
                const int r = Txn(8 + static_cast<uint64_t>(i), 1);  // 200 of 900 tokens per domain
                exec_hist[i][(-r) & 15]++;
            }
        });
    }
    barrier.ReleaseWhen(n);
    for (int i = 0; i < n; ++i) threads[i].join();

    bool init_ok = true;
    for (int i = 0; i < kInit; ++i) init_ok = init_ok && init_rc[i] == 0;
    Check(init_ok, "16 concurrent stack_host_initialize all return 0");
    // Capability updates: applied (0), not yet initialized (-1) or refused for
    // a transaction in flight (-2). Nothing else.
    bool caps_ok = true;
    int caps_applied = 0;
    for (int i = 0; i < kCaps; ++i) {
        for (int c = 0; c < 16; ++c) {
            if (caps_hist[i][c] == 0) continue;
            if (c == 0) caps_applied += caps_hist[i][c];
            else if (c != 1 && c != 2) { caps_ok = false; std::printf("    caps[%d]: unexpected rc=-%d x%d\n", i, c, caps_hist[i][c]); }
        }
    }
    Check(caps_ok, "capability updates returned only 0, -1 or -2");
    Check(caps_applied > 0, "at least one capability update was applied");
    // Transactions on a sealed thread after Ready: completed (0) or
    // CapabilityValidationFailed (-4, before any setter got in). Never
    // -1, -3, -11 or -12, and never RateLimited (200 tokens of 900).
    bool exec_ok = true;
    int completed = 0;
    for (int i = 0; i < kExec; ++i) {
        exec_ok = exec_ok && exec_seal[i] == 0;
        for (int c = 0; c < 16; ++c) {
            if (exec_hist[i][c] == 0) continue;
            if (c == 0) completed += exec_hist[i][c];
            else if (c != 4) { exec_ok = false; std::printf("    exec[%d]: unexpected rc=-%d x%d\n", i, c, exec_hist[i][c]); }
        }
    }
    Check(exec_ok, "sealed executors returned only 0 or -4");
    Check(completed > 0, "at least one transaction completed");
    Check(stack_ffi_testing_init_work_runs() == 1, "the one-time work still ran exactly once");
    Check(stack_ffi_testing_host_constructions() == 1, "the host is still one object");
}

// E: no implicit seal.
void ScenarioE() {
    std::printf("E. a transaction does not seal its caller\n");
    Check(stack_host_set_capabilities(0xFF, 0, 0, 0) == 0, "capabilities set (no transaction in flight)");
    int unsealed_rc = 99, seal_rc = 99, sealed_rc = 99;
    bool filtered_before = true, filtered_after_refusal = true, filtered_after_seal = false;
    uint64_t runs_before = 0, runs_after_refusal = 0, runs_after_completion = 0;
    std::thread([&] {
        filtered_before = ThisThreadIsFiltered();
        runs_before = stack_host_payload_count();
        unsealed_rc = Txn(12, 1);
        runs_after_refusal = stack_host_payload_count();
        filtered_after_refusal = ThisThreadIsFiltered();
        seal_rc = stack_host_seal_current_thread();
        sealed_rc = Txn(12, 1);
        runs_after_completion = stack_host_payload_count();
        filtered_after_seal = ThisThreadIsFiltered();
    }).join();
    CheckFiltered(filtered_before, false, "a fresh thread starts unfiltered");
    Check(unsealed_rc == -11, "execute on an unsealed thread is -11");
    CheckFiltered(filtered_after_refusal, false, "the refused thread is still unfiltered (no implicit seal)");
    Check(runs_after_refusal == runs_before, "the refused transaction ran no payload");
    Check(seal_rc == 0, "seal_current_thread is 0");
    Check(sealed_rc == 0, "execute on the sealed thread completes");
    CheckFiltered(filtered_after_seal, true, "the sealed thread is filtered");
    Check(runs_after_completion == runs_before + 1, "the completed transaction ran the payload once");
}

// F: idempotence.
void ScenarioF() {
    std::printf("F. repeated initialization and sealing\n");
    int init_rc = 0;
    for (int i = 0; i < 100; ++i) init_rc |= stack_host_initialize();
    Check(init_rc == 0, "100 repeated stack_host_initialize all return 0");
    int seal_rc = 0, txn_rc = 0;
    std::thread([&] {
        for (int i = 0; i < 100; ++i) seal_rc |= stack_host_initialize_and_seal();
        for (int i = 0; i < 100; ++i) seal_rc |= stack_host_seal_current_thread();
        txn_rc = Txn(13, 1);
    }).join();
    Check(seal_rc == 0, "100 repeated seals on one thread all return 0");
    Check(txn_rc == 0, "and the thread runs a transaction");
    Check(stack_ffi_testing_init_work_runs() == 1, "the one-time work ran exactly once in this process");
    Check(stack_ffi_testing_host_constructions() == 1, "one host in this process");
}

}  // namespace

int main() {
    std::printf("FFI initialization red team (%s)\n", kSeccompActive ? "real seccomp" : "seccomp interposed, synchronization only");
    ScenarioA();
    ScenarioB();
    ScenarioC();
    ScenarioD();
    ScenarioE();
    ScenarioF();
    std::printf("%s: %d failure(s)\n", g_failures == 0 ? "PASS" : "FAIL", g_failures);
    return g_failures == 0 ? 0 : 1;
}
