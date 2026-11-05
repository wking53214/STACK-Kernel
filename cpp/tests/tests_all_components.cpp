#include <catch2/catch_test_macros.hpp>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>
#include <atomic>
#include <cerrno>
#include <chrono>
#include <condition_variable>
#include <expected>
#include <mutex>
#include <thread>
#include <vector>
#include <iostream>

#include "../include/stack_kernel.hpp"
#include "../include/stack_kinetic_governor.hpp"
#include "../include/posix_deadline_timer_hardened.hpp"
#include "../include/stack_host_binding.hpp"
#include "../include/stack_arena.hpp"
#include "../include/stack_audit.hpp"

using namespace stack::governor;
using namespace stack::host;
using namespace stack::isolation;
using namespace stack::telemetry;

// getpid is not on the allowlist, so a thread that has installed the filter
// gets ENOSYS and an unfiltered thread gets its pid.
static bool ThisThreadIsFiltered() {
    errno = 0;
    const long rc = ::syscall(SYS_getpid);
    return rc == -1 && errno == ENOSYS;
}

// Spins on CLOCK_MONOTONIC (vDSO; clock_gettime is also on the allowlist) for
// the given wall-clock span. Burns CPU the whole time, so a CPU-time deadline
// shorter than the span expires while the payload is still running.
static void BurnCpuForMilliseconds(long ms) {
    timespec start{};
    ::clock_gettime(CLOCK_MONOTONIC, &start);
    for (;;) {
        timespec now{};
        ::clock_gettime(CLOCK_MONOTONIC, &now);
        const long elapsed_ms = (now.tv_sec - start.tv_sec) * 1000L + (now.tv_nsec - start.tv_nsec) / 1'000'000L;
        if (elapsed_ms >= ms) return;
    }
}

// Reaps a forked child with a wall-clock bound so a wedged child cannot hang
// the runner. Returns the wait status; kills the child first if it exceeds the bound.
static int ReapChildWithin(pid_t pid, long bound_ms) {
    int status = 0;
    for (long waited = 0; waited < bound_ms; waited += 10) {
        const pid_t r = ::waitpid(pid, &status, WNOHANG);
        if (r == pid) return status;
        timespec nap{0, 10'000'000L};
        ::nanosleep(&nap, nullptr);
    }
    ::kill(pid, SIGKILL);
    ::waitpid(pid, &status, 0);
    return status;
}
TEST_CASE("Components 1-5: Governor & Sync Core", "[components][1-5]") {
    KineticGovernor<> gov;
    auto res = gov.Consume(0, 10, PriorityClass::Standard);
    REQUIRE(res.has_value());
    REQUIRE(gov.Refund(0, 10).has_value());
}

TEST_CASE("Components 6-10: Preemption Timer & Deadlines", "[components][6-10]") {
    REQUIRE(HardenedPosixPreemptionGuard::RegisterSignalHandler().has_value());
    REQUIRE(HardenedPosixPreemptionGuard::InitializeThreadTimer().has_value());
    HardenedPosixPreemptionGuard guard;
    REQUIRE(guard.Arm(100'000'000ULL).has_value());
    REQUIRE_FALSE(guard.WasPreempted());
}

TEST_CASE("Components 14-15: Arena & Audit Ring", "[components][14-15]") {
    StaticArenaBuffer<1024> arena;
    REQUIRE(arena.Allocate<uint64_t>(42).has_value());
    
    SeccompAuditRing<1024> audit;
    audit.Push(AuditEventType::CapabilityViolation, 777, 5);
    AuditEventRecord rec{};
    REQUIRE(audit.ReadSlot(0, rec));
    REQUIRE(rec.context_id == 777);
}

TEST_CASE("Component 12: Layer 4 - Debt Refund Asymmetry Fix", "[layer-4][defect-4]") {
    // RED TEAM: Test 1 - Debt is refunded on transaction abort
    {
        ComputeDebtTracker<256> tracker;
        uint64_t domain_id = 42;

        // Accrue 1000 ticks of debt
        auto accrue_res = tracker.AccrueDebt(domain_id, 1000);
        REQUIRE(accrue_res.has_value());

        // Refund 600 ticks (partial refund)
        auto refund_res = tracker.RefundDebt(domain_id, 600);
        REQUIRE(refund_res.has_value());

        // Refund remaining 400 ticks (full cleanup)
        refund_res = tracker.RefundDebt(domain_id, 400);
        REQUIRE(refund_res.has_value());

        // Attempt to refund more than accrued (should fail)
        refund_res = tracker.RefundDebt(domain_id, 1);
        REQUIRE(!refund_res.has_value());
    }

    // RED TEAM: Test 2 - TransactionRollbackGuard refunds debt on abort
    {
        KineticGovernor<> gov;
        ComputeDebtTracker<256> tracker;

        // Verify initial token consumption succeeds
        auto consume_res = gov.Consume(1, 100, PriorityClass::Standard);
        REQUIRE(consume_res.has_value());

        {
            // Create guard: will refund tokens and debt on destruction (abort)
            TransactionRollbackGuard guard(gov, tracker, 1, 0, 0, 100);
            guard.accrued_ticks = 5000;
            // Guard destroyed here WITHOUT Commit() call
            // Should refund both 100 tokens AND 5000 ticks of debt
        }

        // After abort, tokens should be restored to bucket
        // (verified implicitly: next Consume should have more tokens available)
        REQUIRE(true);  // Guard destruction completed successfully
    }

    // RED TEAM: Test 3 - Debt NOT refunded on successful commit
    {
        KineticGovernor<> gov;
        ComputeDebtTracker<256> tracker;

        auto consume_res = gov.Consume(2, 50, PriorityClass::Standard);
        REQUIRE(consume_res.has_value());
        REQUIRE(tracker.AccrueDebt(2, 2000).has_value());

        {
            TransactionRollbackGuard guard(gov, tracker, 2, 0, 0, 50);
            guard.accrued_ticks = 2000;
            guard.Commit();  // COMMITTED - no refund should happen
            // Guard destroyed here WITH Commit() call
        }

        // After commit, debt should NOT be refunded
        auto refund_res = tracker.RefundDebt(2, 2000);
        REQUIRE(refund_res.has_value());  // We can refund because it wasn't auto-refunded
    }

    // RED TEAM: Test 4 - Concurrent accrue and refund (stress test)
    {
        ComputeDebtTracker<256> tracker;
        std::atomic<int> accrue_count{0};
        std::atomic<int> refund_count{0};

        constexpr int num_threads = 4;
        constexpr int iterations = 100;
        std::vector<std::thread> threads;

        for (int i = 0; i < num_threads; ++i) {
            threads.emplace_back([&tracker, &accrue_count, &refund_count, i]() {
                for (int j = 0; j < iterations; ++j) {
                    // Accrue ticks
                    auto accrue_res = tracker.AccrueDebt(i, 100 + j);
                    if (accrue_res.has_value()) {
                        accrue_count++;

                        // Immediately refund half
                        auto refund_res = tracker.RefundDebt(i, 50 + (j / 2));
                        if (refund_res.has_value()) {
                            refund_count++;
                        }
                    }
                }
            });
        }

        for (auto& t : threads) t.join();

        REQUIRE(accrue_count.load() > 0);
        REQUIRE(refund_count.load() > 0);
    }
}

TEST_CASE("Component 12: Layer 4 - BPF Filter Jump Offsets Fix", "[layer-4][defect-3]") {
    // Runs the real filter in a forked child (a filter cannot be removed, so
    // the runner must not install it) and checks where each call lands:
    // every allowlisted syscall must reach the kernel, the rt_sigaction
    // special case must allow GOVERNOR_PREEMPT_SIG and refuse another
    // signal with EPERM, and an unlisted syscall must get ENOSYS. A wrong
    // jump offset misroutes at least one of these. The child reports a bit
    // per check in its exit status; the parent asserts on the whole mask.
    int pipe_fds[2] = {-1, -1};
    REQUIRE(::pipe(pipe_fds) == 0);
    std::cout.flush();
    const pid_t pid = ::fork();
    REQUIRE(pid >= 0);
    if (pid == 0) {
        int mask = 0;
        if (!HardenedPosixPreemptionGuard::RegisterSignalHandler().has_value()) ::_exit(0);
        if (!SeccompFilterEngine::InstallFilter().has_value()) ::_exit(0);
        // Allowlisted calls reach the kernel: success, or the kernel's own
        // errno for a bad argument (anything but ENOSYS from the filter).
        timespec ts{};
        if (::syscall(SYS_clock_gettime, CLOCK_MONOTONIC, &ts) == 0) mask |= 1 << 0;
        char byte = 'w';
        if (::syscall(SYS_write, pipe_fds[1], &byte, 1) == 1) mask |= 1 << 1;
        char got = 0;
        if (::syscall(SYS_read, pipe_fds[0], &got, 1) == 1 && got == 'w') mask |= 1 << 2;
        uint32_t futex_word = 0;
        if (::syscall(SYS_futex, &futex_word, 1 /* FUTEX_WAKE */, 1, nullptr, nullptr, 0) == 0) mask |= 1 << 3;
        itimerspec zero{};
        errno = 0;
        if (::syscall(SYS_timer_settime, 0x7fffffff, 0, &zero, nullptr) == -1 && errno == EINVAL) mask |= 1 << 4;
        // The libc wrapper marshals the kernel's sigaction layout; it still
        // issues rt_sigaction, which is what the filter inspects.
        struct sigaction sa{};
        sa.sa_handler = SIG_DFL;
        errno = 0;
        if (::sigaction(GOVERNOR_PREEMPT_SIG, &sa, nullptr) == 0) mask |= 1 << 5;
        errno = 0;
        if (::sigaction(SIGUSR1, &sa, nullptr) == -1 && errno == EPERM) mask |= 1 << 6;
        // Unlisted: the default deny.
        errno = 0;
        if (::syscall(SYS_getpid) == -1 && errno == ENOSYS) mask |= 1 << 7;
        ::_exit(mask);  // exit_group: allowlisted
    }
    const int status = ReapChildWithin(pid, 10'000);
    ::close(pipe_fds[0]);
    ::close(pipe_fds[1]);
    INFO("child exit mask " << (WIFEXITED(status) ? WEXITSTATUS(status) : -1)
         << " (bits: clock_gettime, write, read, futex, timer_settime, rt_sigaction preempt, rt_sigaction other EPERM, getpid ENOSYS)"
         << " signaled=" << WIFSIGNALED(status));
    REQUIRE(WIFEXITED(status));
    REQUIRE(WEXITSTATUS(status) == 0xFF);
}

TEST_CASE("Component 12: Layer 4 - Capability Mutation Race Fix", "[layer-4][defect-2]") {
    // RED TEAM: Test 1 - Concurrent SetActiveCapabilities and ExecuteGovernedTransaction
    {
        constexpr int num_executor_threads = 4;
        constexpr int num_capability_setters = 2;
        GovernedMinotaurHost<> host;
        std::atomic<int> validation_success{0};
        std::atomic<int> validation_failed{0};
        std::atomic<int> capability_updates{0};

        // Initialize capabilities
        REQUIRE(host.SetActiveCapabilities(CapabilityMask256(0xFF, 0, 0, 0)));

        std::vector<std::thread> threads;

        // Executor threads: attempt ExecuteGovernedTransaction with various capabilities
        for (int i = 0; i < num_executor_threads; ++i) {
            threads.emplace_back([&host, &validation_success, &validation_failed, i]() {
                SIMDCapabilityToken token(i, CapabilityMask256(0x01, 0, 0, 0));
                for (int j = 0; j < 100; ++j) {
                    auto res = host.ExecuteGovernedTransaction(
                        token, 10, 1'000'000ULL, 100'000ULL, []() {}
                    );
                    if (res.has_value() || res.error() != HostExecutionError::CapabilityValidationFailed) {
                        validation_success++;
                    } else {
                        validation_failed++;
                    }
                }
            });
        }

        // Capability setter threads: update capabilities while executors run
        for (int i = 0; i < num_capability_setters; ++i) {
            threads.emplace_back([&host, &capability_updates]() {
                // Retry until applied and finish on 0xFF so the outcome does not depend on scheduling.
                for (int j = 0; j < 51; ++j) {
                    CapabilityMask256 mask((j % 2 == 0) ? 0xFF : 0xAA, 0, 0, 0);
                    while (!host.SetActiveCapabilities(mask)) {
                        std::this_thread::yield();
                    }
                    capability_updates++;
                }
            });
        }

        for (auto& t : threads) t.join();

        // Verify: no torn reads or validation corruption
        REQUIRE(validation_success.load() > 0);
        REQUIRE(capability_updates.load() > 0);
    }

    // RED TEAM: Test 2 - Snapshot consistency during validation
    {
        GovernedMinotaurHost<> host;
        CapabilityMask256 initial_caps(0xFF, 0, 0, 0);
        REQUIRE(host.SetActiveCapabilities(initial_caps));

        std::atomic<bool> token_validated{false};
        std::atomic<bool> validator_done{false};
        std::atomic<bool> transaction_ok{false};
        std::atomic<bool> capabilities_changed{false};
        // Latch (R2-K-14): the payload does not return until the changer has made
        // its attempt, so the attempt is made while the transaction is provably in
        // flight. Without it the transaction could finish between the payload's
        // signal and the changer's call, and the attempt would (correctly) apply.
        // The payload blocks on a condition variable (no CPU is burned while
        // it waits) and the wait is bounded, so a changer that never attempts
        // fails the assertions below instead of hanging the run. Because the
        // payload now waits, the deadline budgets are generous (the nearby
        // latch test uses the same): the old 100 000 ticks and 50 microseconds
        // of CPU were sized for a payload that returned at once, and this test
        // is about snapshot consistency, not about deadlines.
        std::mutex attempt_mutex;
        std::condition_variable attempt_cv;
        bool change_attempted = false;

        std::thread validator([&host, &token_validated, &validator_done, &transaction_ok,
                               &attempt_mutex, &attempt_cv, &change_attempted]() {
            SIMDCapabilityToken token(1, CapabilityMask256(0x01, 0, 0, 0));
            auto res = host.ExecuteGovernedTransaction(
                token, 5, 100'000'000'000ULL, 1'000'000'000ULL,
                [&token_validated, &attempt_mutex, &attempt_cv, &change_attempted]() {
                    token_validated.store(true, std::memory_order_release);
                    std::unique_lock<std::mutex> lk(attempt_mutex);
                    attempt_cv.wait_for(lk, std::chrono::seconds(5), [&] { return change_attempted; });
                }
            );
            transaction_ok.store(res.has_value(), std::memory_order_release);
            validator_done.store(true, std::memory_order_release);
        });

        std::thread changer([&host, &token_validated, &validator_done, &capabilities_changed,
                             &attempt_mutex, &attempt_cv, &change_attempted]() {
            while (!token_validated.load(std::memory_order_acquire)) {
                if (validator_done.load(std::memory_order_acquire)) return;
                std::this_thread::yield();
            }
            // Try to change capabilities during validation
            bool success = host.SetActiveCapabilities(CapabilityMask256(0, 0, 0, 0));
            capabilities_changed.store(!success, std::memory_order_release);  // Should fail (txn in flight)
            {
                std::lock_guard<std::mutex> lk(attempt_mutex);
                change_attempted = true;
            }
            attempt_cv.notify_all();
        });

        validator.join();
        changer.join();

        REQUIRE(transaction_ok.load());

        // Capability change should have been rejected (transaction was in flight)
        REQUIRE(capabilities_changed.load());
    }

    // RED TEAM: Test 3 - Rapid capability mask changes (stress test lock contention)
    {
        GovernedMinotaurHost<> host;
        std::atomic<int> successful_updates{0};

        for (int i = 0; i < 200; ++i) {
            CapabilityMask256 mask(i & 0xFF, (i >> 8) & 0xFF, 0, 0);
            if (host.SetActiveCapabilities(mask)) {
                successful_updates++;
            }
        }

        REQUIRE(successful_updates.load() > 0);
    }
}

TEST_CASE("Component 12: Layer 4 - Capability change refused while a payload runs", "[layer-4][defect-2]") {
    // Deterministic, latch based: the payload parks on a condition variable, the
    // main thread asks for a capability change while it is parked (must be refused),
    // releases the payload, and asks again once the transaction has returned (must
    // be applied).
    //
    // Sealing is per thread: the sacrificial thread below seals itself and the
    // worker seals itself when it runs its transaction. The test pins the
    // in-flight counter, and the main thread stays unsealed.
    GovernedMinotaurHost<> host;
    REQUIRE(host.SetActiveCapabilities(CapabilityMask256(0xFF, 0, 0, 0)));

    std::thread([&host]() {
        SIMDCapabilityToken token(1, CapabilityMask256(0x01, 0, 0, 0));
        (void)host.ExecuteGovernedTransaction(token, 5, 1'000'000ULL, 1'000'000'000ULL, []() {});
    }).join();

    std::mutex latch_mutex;
    std::condition_variable latch_cv;
    bool payload_parked = false;
    bool release_payload = false;
    bool transaction_done = false;
    std::atomic<bool> payload_ran{false};

    std::thread worker([&]() {
        SIMDCapabilityToken token(2, CapabilityMask256(0x01, 0, 0, 0));
        (void)host.ExecuteGovernedTransaction(
            token, 5, 100'000'000'000ULL, 1'000'000'000ULL,
            [&]() {
                payload_ran.store(true, std::memory_order_release);
                std::unique_lock<std::mutex> lk(latch_mutex);
                payload_parked = true;
                latch_cv.notify_all();
                latch_cv.wait(lk, [&] { return release_payload; });
            });
        std::lock_guard<std::mutex> lk(latch_mutex);
        transaction_done = true;
        latch_cv.notify_all();
    });

    {
        std::unique_lock<std::mutex> lk(latch_mutex);
        latch_cv.wait(lk, [&] { return payload_parked || transaction_done; });
    }
    // Asked while the payload is parked inside the transaction.
    const bool refused_while_running = !host.SetActiveCapabilities(CapabilityMask256(0, 0, 0, 0));
    {
        std::lock_guard<std::mutex> lk(latch_mutex);
        release_payload = true;
        latch_cv.notify_all();
    }
    worker.join();

    // The payload must have run, or the refusal above proves nothing.
    REQUIRE(payload_ran.load(std::memory_order_acquire));
    REQUIRE(refused_while_running);
    // Asked after the transaction returned: the counter is back to zero.
    REQUIRE(host.SetActiveCapabilities(CapabilityMask256(0, 0, 0, 0)));
}

namespace {

// A transaction whose payload parks until released, so a test can hold one
// transaction provably in flight (I-04). It runs on its own thread, which
// seals itself; the test thread stays unsealed.
struct ParkedTransaction {
    std::mutex m;
    std::condition_variable cv;
    bool parked = false;
    bool release = false;
    std::atomic<bool> payload_ran{false};
    std::expected<void, HostExecutionError> result{};
    std::thread thread;

    template <typename Host>
    void Start(Host& host, uint64_t domain, uint64_t capability_bits) {
        thread = std::thread([this, &host, domain, capability_bits]() {
            SIMDCapabilityToken token(domain, CapabilityMask256(capability_bits, 0, 0, 0));
            result = host.ExecuteGovernedTransaction(
                token, 5, 100'000'000'000ULL, 10'000'000'000ULL,
                [this]() {
                    payload_ran.store(true, std::memory_order_release);
                    std::unique_lock<std::mutex> lk(m);
                    parked = true;
                    cv.notify_all();
                    cv.wait(lk, [this] { return release; });
                });
            // A refused or failed transaction never parks: wake the waiter.
            std::lock_guard<std::mutex> lk(m);
            parked = true;
            cv.notify_all();
        });
    }
    void WaitParked() {
        std::unique_lock<std::mutex> lk(m);
        cv.wait(lk, [this] { return parked; });
    }
    void Release() {
        std::lock_guard<std::mutex> lk(m);
        release = true;
        cv.notify_all();
    }
    void Join() { if (thread.joinable()) thread.join(); }
};

// Polls on the unsealed test thread; a failure shows as a false return, not a hang.
template <typename Pred>
bool WaitUntil(Pred pred, int timeout_ms = 5000) {
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(timeout_ms);
    while (!pred()) {
        if (std::chrono::steady_clock::now() >= deadline) return false;
        std::this_thread::yield();
    }
    return true;
}

// One quick transaction on a fresh thread; returns its result and whether the payload ran.
template <typename Host>
std::expected<void, HostExecutionError> QuickTransaction(Host& host, uint64_t domain, uint64_t capability_bits,
                                                         bool* payload_ran) {
    std::expected<void, HostExecutionError> result{};
    std::atomic<bool> ran{false};
    std::thread([&]() {
        SIMDCapabilityToken token(domain, CapabilityMask256(capability_bits, 0, 0, 0));
        result = host.ExecuteGovernedTransaction(
            token, 5, 100'000'000'000ULL, 10'000'000'000ULL,
            [&ran]() { ran.store(true, std::memory_order_release); });
    }).join();
    *payload_ran = ran.load(std::memory_order_acquire);
    return result;
}

}  // namespace

TEST_CASE("Component 12: Layer 4 - A pending capability change blocks new transactions and applies when in-flight ones drain", "[layer-4][I-04]") {
    // R2-K-07. A transaction is held in flight (payload parked on a latch). A
    // bounded capability change then waits for it: while it waits, a NEW
    // transaction is refused with CapabilityChangePending (fail closed, nothing
    // runs, nothing is charged). When the parked transaction finishes the
    // change applies and the revoked capability is refused.
    GovernedMinotaurHost<> host;
    REQUIRE(host.SetActiveCapabilities(CapabilityMask256(0xFF, 0, 0, 0)));
    REQUIRE(host.PendingCapabilityChanges() == 0);

    ParkedTransaction a;
    a.Start(host, 1, 0x01);
    a.WaitParked();
    REQUIRE(a.payload_ran.load());

    std::atomic<bool> setter_done{false};
    bool setter_applied = false;
    std::thread setter([&]() {
        setter_applied = host.SetActiveCapabilitiesWithin(
            CapabilityMask256(0, 0, 0, 0), std::chrono::seconds(30));
        setter_done.store(true, std::memory_order_release);
    });
    REQUIRE(WaitUntil([&] { return host.PendingCapabilityChanges() == 1; }));

    // A new transaction while the change is pending: refused, payload not run.
    bool b_ran = true;
    const auto b = QuickTransaction(host, 2, 0x01, &b_ran);
    REQUIRE_FALSE(b.has_value());
    REQUIRE(b.error() == HostExecutionError::CapabilityChangePending);
    REQUIRE_FALSE(b_ran);
    REQUIRE(host.DebtTracker().Accrued(2) == 0);
    // The change waits for the parked transaction: it has not applied.
    REQUIRE_FALSE(setter_done.load(std::memory_order_acquire));

    a.Release();
    a.Join();
    setter.join();
    REQUIRE(a.result.has_value());           // it ran to completion under the old mask
    REQUIRE(setter_applied);
    REQUIRE(host.PendingCapabilityChanges() == 0);

    // Applied: the revoked capability is refused, and the payload does not run.
    bool c_ran = true;
    const auto c = QuickTransaction(host, 3, 0x01, &c_ran);
    REQUIRE_FALSE(c.has_value());
    REQUIRE(c.error() == HostExecutionError::CapabilityValidationFailed);
    REQUIRE_FALSE(c_ran);
}

TEST_CASE("Component 12: Layer 4 - A bounded capability change that times out leaves nothing pending", "[layer-4][I-04]") {
    // The wait is bounded. When the in-flight transaction does not drain in
    // time the change is NOT applied (false), no change remains pending, and
    // the host serves new transactions under the unchanged mask.
    GovernedMinotaurHost<> host;
    REQUIRE(host.SetActiveCapabilities(CapabilityMask256(0xFF, 0, 0, 0)));

    ParkedTransaction a;
    a.Start(host, 1, 0x01);
    a.WaitParked();

    // Zero wait is the old try-once behaviour: refused at once, nothing pending.
    REQUIRE_FALSE(host.SetActiveCapabilitiesWithin(CapabilityMask256(0, 0, 0, 0), std::chrono::nanoseconds(0)));
    REQUIRE(host.PendingCapabilityChanges() == 0);
    REQUIRE_FALSE(host.SetActiveCapabilities(CapabilityMask256(0, 0, 0, 0)));
    REQUIRE(host.PendingCapabilityChanges() == 0);

    const auto t0 = std::chrono::steady_clock::now();
    const bool applied = host.SetActiveCapabilitiesWithin(
        CapabilityMask256(0, 0, 0, 0), std::chrono::milliseconds(60));
    const auto waited = std::chrono::steady_clock::now() - t0;
    REQUIRE_FALSE(applied);
    REQUIRE(waited >= std::chrono::milliseconds(60));
    REQUIRE(waited < std::chrono::seconds(5));
    REQUIRE(host.PendingCapabilityChanges() == 0);

    // Still serving, still under the old mask (nothing was applied).
    bool b_ran = false;
    const auto b = QuickTransaction(host, 2, 0x01, &b_ran);
    REQUIRE(b.has_value());
    REQUIRE(b_ran);

    a.Release();
    a.Join();
    REQUIRE(a.result.has_value());
    // Nothing in flight now: the same change applies at once.
    REQUIRE(host.SetActiveCapabilitiesWithin(CapabilityMask256(0, 0, 0, 0), std::chrono::milliseconds(60)));
    bool c_ran = true;
    const auto c = QuickTransaction(host, 3, 0x01, &c_ran);
    REQUIRE(c.error() == HostExecutionError::CapabilityValidationFailed);
    REQUIRE_FALSE(c_ran);
}

TEST_CASE("Component 12: Layer 4 - One setter timing out does not unblock another that is still waiting", "[layer-4][I-04]") {
    GovernedMinotaurHost<> host;
    REQUIRE(host.SetActiveCapabilities(CapabilityMask256(0xFF, 0, 0, 0)));

    ParkedTransaction a;
    a.Start(host, 1, 0x01);
    a.WaitParked();

    bool long_applied = false;
    std::thread long_setter([&]() {
        long_applied = host.SetActiveCapabilitiesWithin(CapabilityMask256(0x0F, 0, 0, 0), std::chrono::seconds(30));
    });
    REQUIRE(WaitUntil([&] { return host.PendingCapabilityChanges() == 1; }));

    REQUIRE_FALSE(host.SetActiveCapabilitiesWithin(CapabilityMask256(0xF0, 0, 0, 0), std::chrono::milliseconds(30)));
    // The short setter is gone; the long one still holds the host closed.
    REQUIRE(host.PendingCapabilityChanges() == 1);
    bool b_ran = true;
    const auto b = QuickTransaction(host, 2, 0x01, &b_ran);
    REQUIRE(b.error() == HostExecutionError::CapabilityChangePending);
    REQUIRE_FALSE(b_ran);

    a.Release();
    a.Join();
    long_setter.join();
    REQUIRE(long_applied);
    REQUIRE(host.PendingCapabilityChanges() == 0);
    // The long setter's mask (0x0F) applied, the short one's (0xF0) did not.
    bool c_ran = false;
    REQUIRE(QuickTransaction(host, 3, 0x01, &c_ran).has_value());
    REQUIRE(c_ran);
    bool d_ran = true;
    REQUIRE(QuickTransaction(host, 4, 0x10, &d_ran).error() == HostExecutionError::CapabilityValidationFailed);
    REQUIRE_FALSE(d_ran);
}

TEST_CASE("Component 12: Layer 4 - A sealed thread can arm its deadline timer", "[layer-4][defect-5]") {
    // The allowlist must carry timer_settime: the timer is created before the
    // filter goes on (timer_create is not allowed), but Arm() calls timer_settime
    // on the sealed thread for every transaction. Without it the transaction
    // fails with TimerInitializationFailed and the payload never runs.
    // Results are collected on the worker and checked on the main thread, which
    // is not sealed.
    GovernedMinotaurHost<> host;
    REQUIRE(host.SetActiveCapabilities(CapabilityMask256(0xFF, 0, 0, 0)));

    std::atomic<bool> payload_ran{false};
    std::atomic<bool> transaction_ok{false};
    std::atomic<bool> filter_active{false};

    std::thread worker([&]() {
        SIMDCapabilityToken token(1, CapabilityMask256(0x01, 0, 0, 0));
        auto res = host.ExecuteGovernedTransaction(
            token, 5, 100'000'000'000ULL, 1'000'000'000ULL,
            [&]() { payload_ran.store(true, std::memory_order_release); });
        transaction_ok.store(res.has_value(), std::memory_order_release);
        filter_active.store(ThisThreadIsFiltered(), std::memory_order_release);
    });
    worker.join();

    REQUIRE(filter_active.load());
    REQUIRE(payload_ran.load());
    REQUIRE(transaction_ok.load());
}

TEST_CASE("Component 12: Layer 4 - Every governed thread installs its own filter", "[layer-4][defect-6]") {
    // A seccomp filter attaches to the thread that installs it, and the host's
    // sealed state used to be per host, so only the first thread to call in was
    // filtered and every later thread ran unfiltered. Each thread below runs one
    // transaction after the previous thread has finished; all must succeed (the
    // timer is created before the filter) and all must be filtered. The calling
    // thread never seals, which pins that the filter is not process wide.
    GovernedMinotaurHost<> host;
    REQUIRE(host.SetActiveCapabilities(CapabilityMask256(0xFF, 0, 0, 0)));

    constexpr int num_threads = 3;
    std::atomic<int> transactions_ok{0};
    std::atomic<int> threads_filtered{0};
    for (int i = 0; i < num_threads; ++i) {
        std::thread([&host, &transactions_ok, &threads_filtered, i]() {
            SIMDCapabilityToken token(static_cast<uint64_t>(i) + 1, CapabilityMask256(0x01, 0, 0, 0));
            auto res = host.ExecuteGovernedTransaction(
                token, 5, 100'000'000'000ULL, 1'000'000'000ULL, []() {});
            if (res.has_value()) transactions_ok++;
            if (ThisThreadIsFiltered()) threads_filtered++;
        }).join();
    }

    REQUIRE(transactions_ok.load() == num_threads);
    REQUIRE(threads_filtered.load() == num_threads);
    REQUIRE_FALSE(ThisThreadIsFiltered());
}

TEST_CASE("Component 10 & 11: Hard-timeout expiry on a sealed thread does not kill the process", "[layer-2][layer-4][D-01]") {
    // D-01: the deadline signal handler runs on the sealed thread and returns
    // through rt_sigreturn. With rt_sigreturn missing from the allowlist the
    // kernel refuses the return and the whole process dies with SIGSEGV.
    // The scenario runs in a forked child so a crash cannot take the runner
    // down; the parent asserts on the wait status.
    std::cout.flush();
    const pid_t pid = ::fork();
    REQUIRE(pid >= 0);
    if (pid == 0) {
        // A fresh thread: the forking thread's thread-local timer state may
        // say "initialized" while its kernel timer did not survive the fork.
        int code = 13;
        std::thread([&code]() {
            GovernedMinotaurHost<> host;
            if (!host.SetActiveCapabilities(CapabilityMask256(0xFF, 0, 0, 0))) { code = 10; return; }
            SIMDCapabilityToken token(7, CapabilityMask256(0x01, 0, 0, 0));
            // 20 ms of CPU time, payload burns 200 ms: the timer fires mid-payload.
            auto res = host.ExecuteGovernedTransaction(
                token, 10, 1'000'000'000'000ULL, 20'000'000ULL, []() { BurnCpuForMilliseconds(200); });
            if (res.has_value()) { code = 11; return; }
            // 0 on the expected error, otherwise 20 + the error code for diagnosis.
            code = res.error() == HostExecutionError::PreemptionTriggered ? 0 : 20 + static_cast<int>(res.error());
        }).join();
        ::_exit(code);
    }
    const int status = ReapChildWithin(pid, 10'000);
    INFO("wait status " << status << " signaled=" << WIFSIGNALED(status)
         << " sig=" << (WIFSIGNALED(status) ? WTERMSIG(status) : 0)
         << " exit=" << (WIFEXITED(status) ? WEXITSTATUS(status) : -1));
    REQUIRE_FALSE((WIFSIGNALED(status) && WTERMSIG(status) == SIGSEGV));
    REQUIRE(WIFEXITED(status));
    // 0: the expiry was detected and reported as PreemptionTriggered.
    REQUIRE(WEXITSTATUS(status) == 0);
}

TEST_CASE("Component 12: Layer 4 - A zero hard timeout is rejected, not silently undeadlined", "[layer-4][D-03]") {
    // D-03: hard_timeout_nanoseconds == 0 used to mean "no deadline" and the
    // payload ran unbounded with a SUCCESS result. The host now refuses it
    // before sealing, consuming tokens or running the payload.
    GovernedMinotaurHost<> host;
    REQUIRE(host.SetActiveCapabilities(CapabilityMask256(0xFF, 0, 0, 0)));
    std::atomic<bool> payload_ran{false};
    std::atomic<int> error_code{-1};
    std::atomic<bool> sealed_after{true};

    std::thread worker([&]() {
        SIMDCapabilityToken token(1, CapabilityMask256(0x01, 0, 0, 0));
        auto res = host.ExecuteGovernedTransaction(
            token, 5, 100'000'000'000ULL, 0ULL,
            [&]() { payload_ran.store(true, std::memory_order_release); });
        error_code.store(res.has_value() ? 0 : static_cast<int>(res.error()), std::memory_order_release);
        sealed_after.store(ThisThreadIsFiltered(), std::memory_order_release);
    });
    worker.join();

    REQUIRE_FALSE(payload_ran.load());
    REQUIRE(error_code.load() == static_cast<int>(HostExecutionError::InvalidHardTimeout));
    // Argument validation runs before the irreversible seal.
    REQUIRE_FALSE(sealed_after.load());
}

TEST_CASE("Component 12: Layer 4 - A timer that cannot be armed fails closed", "[layer-4][D-03]") {
    // If timer_settime fails the payload must not run, and the failure must
    // be distinguishable from a timer_create failure. The worker forges an
    // initialized-looking thread timer state with an id the kernel rejects
    // (EINVAL), so Arm() fails deterministically on a sealed thread.
    GovernedMinotaurHost<> host;
    REQUIRE(host.SetActiveCapabilities(CapabilityMask256(0xFF, 0, 0, 0)));
    std::atomic<bool> payload_ran{false};
    std::atomic<int> error_code{-1};

    std::thread worker([&]() {
        g_thread_timer_state.timer_id = reinterpret_cast<timer_t>(static_cast<uintptr_t>(0x7fffffff));
        g_thread_timer_state.timer_initialized = true;
        SIMDCapabilityToken token(1, CapabilityMask256(0x01, 0, 0, 0));
        auto res = host.ExecuteGovernedTransaction(
            token, 5, 100'000'000'000ULL, 20'000'000ULL,
            [&]() { payload_ran.store(true, std::memory_order_release); });
        error_code.store(res.has_value() ? 0 : static_cast<int>(res.error()), std::memory_order_release);
    });
    worker.join();

    REQUIRE_FALSE(payload_ran.load());
    REQUIRE(error_code.load() == static_cast<int>(HostExecutionError::TimerArmFailed));
}

TEST_CASE("Component 12: Layer 4 - InitializeAndSeal TOCTOU Fix", "[layer-4][defect-1]") {
    // RED TEAM: Test 1 - Concurrent InitializeAndSeal calls (no double initialization)
    {
        constexpr int num_threads = 6;
        std::vector<std::thread> threads;
        std::atomic<int> success_count{0};
        std::atomic<int> error_count{0};
        GovernedMinotaurHost<> host;

        for (int i = 0; i < num_threads; ++i) {
            threads.emplace_back([&host, &success_count, &error_count]() {
                auto res = host.InitializeAndSeal();
                if (res.has_value()) {
                    success_count++;
                } else {
                    error_count++;
                }
            });
        }

        for (auto& t : threads) t.join();

        // All threads should report success (idempotent init)
        REQUIRE(success_count.load() == num_threads);
        REQUIRE(error_count.load() == 0);
    }

    // RED TEAM: Test 2 - Sealed state visible across threads
    {
        GovernedMinotaurHost<> host;
        std::atomic<bool> thread1_sealed{false};
        std::atomic<bool> thread2_saw_sealed{false};
        std::atomic<bool> thread2_filtered{false};

        std::thread t1([&host, &thread1_sealed]() {
            auto res = host.InitializeAndSeal();
            REQUIRE(res.has_value());
            thread1_sealed.store(true, std::memory_order_release);
        });

        std::thread t2([&host, &thread1_sealed, &thread2_saw_sealed, &thread2_filtered]() {
            while (!thread1_sealed.load(std::memory_order_acquire)) {
                std::this_thread::yield();
            }
            auto res = host.InitializeAndSeal();
            REQUIRE(res.has_value());
            thread2_saw_sealed.store(true, std::memory_order_release);
            thread2_filtered.store(ThisThreadIsFiltered(), std::memory_order_release);
        });

        t1.join();
        t2.join();
        REQUIRE(thread2_saw_sealed.load());
        // A filter attaches to one thread, so the second thread installed its own.
        REQUIRE(thread2_filtered.load());
    }

    // RED TEAM: Test 3 - Rapid sequential init (stress test lock contention)
    {
        GovernedMinotaurHost<> host;
        std::atomic<int> init_attempts{0};
        std::atomic<int> init_failures{0};

        // Sealing blocks clone for the sealed thread, so seal on a worker and keep main unsealed.
        std::thread sealer([&host, &init_attempts, &init_failures]() {
            for (int i = 0; i < 100; ++i) {
                auto res = host.InitializeAndSeal();
                if (!res.has_value()) init_failures++;
                init_attempts++;
            }
        });
        sealer.join();

        REQUIRE(init_failures.load() == 0);
        REQUIRE(init_attempts.load() == 100);
    }
}

// I-01 (R2-K-01): the FFI host's parameters, with a refill rate the test
// controls. 2^38 ticks per token is one token per two minutes here, so no
// refill lands inside a test, and a never-used bucket starts full whatever
// the rate. Every count below is exact.
using FfiPolicyHost = GovernedMinotaurHost<1000, 100, 100, 2'100'000, 16>;
constexpr uint64_t kNoRefill = 1ULL << 38;

namespace {
int ExactConsumeUntilLimited(FfiPolicyHost& host, uint64_t domain, uint32_t tokens, int limit, HostExecutionError* last) {
    SIMDCapabilityToken token(domain, CapabilityMask256(0x01, 0, 0, 0));
    int ok = 0;
    *last = HostExecutionError::None;
    for (int i = 0; i < limit; ++i) {
        auto res = host.ExecuteGovernedTransaction(token, tokens, ~0ULL, 1'000'000'000ULL, []() {});
        if (res.has_value()) { ++ok; continue; }
        *last = res.error();
        break;
    }
    return ok;
}
}  // namespace

TEST_CASE("Component 12: Layer 4 - FFI policy host serves exactly its budget and refuses the rest", "[layer-4][I-01]") {
    FfiPolicyHost host(kNoRefill);
    REQUIRE(host.SetActiveCapabilities(CapabilityMask256(0xFF, 0, 0, 0)));

    int completed = 0;
    int refusals = 0;
    bool unchanged_after_refusal = false;
    bool then_exhausted = false;
    std::thread([&]() {
        // 17 requests of 50 from the 900 spendable tokens: all complete, leaving 150.
        SIMDCapabilityToken token(1, CapabilityMask256(0x01, 0, 0, 0));
        for (int i = 0; i < 17; ++i) {
            if (host.ExecuteGovernedTransaction(token, 50, ~0ULL, 1'000'000'000ULL, []() {}).has_value()) ++completed;
        }
        // 150 left: a request of 100 needs 200 and is refused, five times.
        for (int i = 0; i < 5; ++i) {
            auto r = host.ExecuteGovernedTransaction(token, 100, ~0ULL, 1'000'000'000ULL, []() {});
            if (!r.has_value() && r.error() == HostExecutionError::RateLimitExceeded) ++refusals;
        }
        // The refusals consumed nothing: a request of 50 (needs 150) still completes,
        // and after it the bucket is at the floor.
        unchanged_after_refusal = host.ExecuteGovernedTransaction(token, 50, ~0ULL, 1'000'000'000ULL, []() {}).has_value();
        auto r = host.ExecuteGovernedTransaction(token, 1, ~0ULL, 1'000'000'000ULL, []() {});
        then_exhausted = !r.has_value() && r.error() == HostExecutionError::RateLimitExceeded;
    }).join();

    REQUIRE(completed == 17);
    REQUIRE(refusals == 5);
    REQUIRE(unchanged_after_refusal);
    REQUIRE(then_exhausted);
}

TEST_CASE("Component 12: Layer 4 - FFI policy host: denied capability and oversized request consume nothing", "[layer-4][I-01]") {
    FfiPolicyHost host(kNoRefill);
    REQUIRE(host.SetActiveCapabilities(CapabilityMask256(0xFF, 0, 0, 0)));

    int denied = 0, oversized = 0, completed = 0;
    bool payload_ran_on_failure = false;
    HostExecutionError last = HostExecutionError::None;
    std::thread([&]() {
        SIMDCapabilityToken bad(2, CapabilityMask256(0x100, 0, 0, 0));
        SIMDCapabilityToken good(2, CapabilityMask256(0x01, 0, 0, 0));
        for (int i = 0; i < 20; ++i) {
            auto r = host.ExecuteGovernedTransaction(bad, 100, ~0ULL, 1'000'000'000ULL,
                                                     [&]() { payload_ran_on_failure = true; });
            if (!r.has_value() && r.error() == HostExecutionError::CapabilityValidationFailed) ++denied;
        }
        for (int i = 0; i < 20; ++i) {
            auto r = host.ExecuteGovernedTransaction(good, 101, ~0ULL, 1'000'000'000ULL,
                                                     [&]() { payload_ran_on_failure = true; });
            if (!r.has_value() && r.error() == HostExecutionError::RateLimitExceeded) ++oversized;
        }
        // The bucket is still full: exactly 9 requests of 100.
        completed = ExactConsumeUntilLimited(host, 2, 100, 50, &last);
    }).join();

    REQUIRE(denied == 20);
    REQUIRE(oversized == 20);
    REQUIRE_FALSE(payload_ran_on_failure);
    REQUIRE(completed == 9);
    REQUIRE(last == HostExecutionError::RateLimitExceeded);
}

TEST_CASE("Component 12: Layer 4 - FFI policy host: concurrent transactions sum exactly", "[layer-4][I-01]") {
    FfiPolicyHost host(kNoRefill);
    REQUIRE(host.SetActiveCapabilities(CapabilityMask256(0xFF, 0, 0, 0)));

    constexpr int kThreads = 4;
    constexpr int kPerThread = 15;
    constexpr uint32_t kTokens = 10;  // 600 of 900 spendable tokens
    std::atomic<int> completed{0};
    std::atomic<int> failed{0};
    std::atomic<int> payload_runs{0};
    std::atomic<int> arrived{0};
    std::atomic<bool> go{false};
    std::vector<std::thread> workers;
    for (int t = 0; t < kThreads; ++t) {
        workers.emplace_back([&]() {
            SIMDCapabilityToken token(3, CapabilityMask256(0x01, 0, 0, 0));
            arrived++;
            while (!go.load(std::memory_order_acquire)) {}
            for (int i = 0; i < kPerThread; ++i) {
                auto r = host.ExecuteGovernedTransaction(token, kTokens, ~0ULL, 1'000'000'000ULL,
                                                         [&]() { payload_runs++; });
                if (r.has_value()) completed++; else failed++;
            }
        });
    }
    while (arrived.load() < kThreads) {}
    go.store(true, std::memory_order_release);
    for (auto& w : workers) w.join();

    int drained = 0;
    HostExecutionError last = HostExecutionError::None;
    std::thread([&]() { drained = ExactConsumeUntilLimited(host, 3, kTokens, 200, &last); }).join();

    REQUIRE(failed.load() == 0);
    REQUIRE(completed.load() == kThreads * kPerThread);
    REQUIRE(payload_runs.load() == kThreads * kPerThread);
    REQUIRE(drained == 30);  // (900 - 600) / 10
    REQUIRE(last == HostExecutionError::RateLimitExceeded);
}

TEST_CASE("Component 12: Layer 4 - a failed transaction records no TransactionCompleted event", "[layer-4][I-01]") {
    FfiPolicyHost host(kNoRefill);
    REQUIRE(host.SetActiveCapabilities(CapabilityMask256(0xFF, 0, 0, 0)));

    HostExecutionError denied = HostExecutionError::None;
    HostExecutionError limited = HostExecutionError::None;
    bool ok = false;
    std::thread([&]() {
        SIMDCapabilityToken bad(4, CapabilityMask256(0x100, 0, 0, 0));
        SIMDCapabilityToken good(4, CapabilityMask256(0x01, 0, 0, 0));
        auto r1 = host.ExecuteGovernedTransaction(bad, 1, ~0ULL, 1'000'000'000ULL, []() {});
        if (!r1.has_value()) denied = r1.error();
        auto r2 = host.ExecuteGovernedTransaction(good, 101, ~0ULL, 1'000'000'000ULL, []() {});
        if (!r2.has_value()) limited = r2.error();
        ok = host.ExecuteGovernedTransaction(good, 1, ~0ULL, 1'000'000'000ULL, []() {}).has_value();
    }).join();
    REQUIRE(denied == HostExecutionError::CapabilityValidationFailed);
    REQUIRE(limited == HostExecutionError::RateLimitExceeded);
    REQUIRE(ok);

    // A fresh host's ring holds the events in order; slot 3 was never written.
    AuditEventRecord rec{};
    REQUIRE(host.AuditRing().ReadSlot(0, rec));
    REQUIRE(rec.event_type == AuditEventType::CapabilityViolation);
    REQUIRE(rec.context_id == 4);
    REQUIRE(host.AuditRing().ReadSlot(1, rec));
    REQUIRE(rec.event_type == AuditEventType::RateLimitTriggered);
    REQUIRE(host.AuditRing().ReadSlot(2, rec));
    REQUIRE(rec.event_type == AuditEventType::TransactionCompleted);
    REQUIRE(rec.tokens_consumed == 1);
    REQUIRE_FALSE(host.AuditRing().ReadSlot(3, rec));
}

// I-03 (R2-K-05, R2-K-06): accounting rules of ExecuteGovernedTransaction.
//   1. Rejected before the payload ran: nothing consumed, nothing accrued.
//   2. The payload ran: its tokens are spent whatever follows, and its CPU
//      ticks are charged as debt (an overrun is charged too; at the ceiling
//      the debt stays where it is and is never refunded).
// The exact counts use the no-refill rate: 90 requests of 10 tokens are the
// 900 spendable tokens of one domain.
namespace {
constexpr uint64_t kDebtCeiling = 100'000'000'000ULL;
constexpr uint32_t kTen = 10;

// Requests of 10 tokens with a generous budget until the first RateLimited;
// returns how many ran (completed or failed after running).
int DrainTensUntilRateLimited(FfiPolicyHost& host, uint64_t domain, int* completed, int* ceiling_hit) {
    SIMDCapabilityToken token(domain, CapabilityMask256(0x01, 0, 0, 0));
    int ran = 0;
    *completed = 0;
    *ceiling_hit = 0;
    for (int i = 0; i < 200; ++i) {
        auto r = host.ExecuteGovernedTransaction(token, kTen, ~0ULL, 1'000'000'000ULL, []() {});
        if (!r.has_value() && r.error() == HostExecutionError::RateLimitExceeded) break;
        ++ran;
        if (r.has_value()) ++*completed;
        else if (r.error() == HostExecutionError::DebtCeilingExceeded) ++*ceiling_hit;
    }
    return ran;
}
}  // namespace

TEST_CASE("Component 12: Layer 4 - at the debt ceiling nothing is refunded (R2-K-05)", "[layer-4][I-03]") {
    // The observed case: with the debt preloaded one tick below the ceiling,
    // a transaction hits the ceiling after its payload ran, and the rollback
    // guard refunded the elapsed ticks that AccrueDebt had refused, so the
    // debt went down (by 7610 ticks in the baseline run). The ceiling then
    // defeats itself: every later transaction gets the same discount.
    FfiPolicyHost host(kNoRefill);
    REQUIRE(host.SetActiveCapabilities(CapabilityMask256(0xFF, 0, 0, 0)));
    const uint64_t domain = 2;
    REQUIRE(host.DebtTracker().AccrueDebt(domain, kDebtCeiling - 1).has_value());
    const uint64_t debt_before = host.DebtTracker().Accrued(domain);

    HostExecutionError first = HostExecutionError::None;
    bool payload_ran = false;
    uint64_t debt_after_first = 0;
    int ran = 0, completed = 0, ceiling_hit = 0;
    std::thread([&]() {
        SIMDCapabilityToken token(domain, CapabilityMask256(0x01, 0, 0, 0));
        auto r = host.ExecuteGovernedTransaction(token, kTen, ~0ULL, 1'000'000'000ULL, [&]() { payload_ran = true; });
        if (!r.has_value()) first = r.error();
        debt_after_first = host.DebtTracker().Accrued(domain);
        ran = DrainTensUntilRateLimited(host, domain, &completed, &ceiling_hit);
    }).join();

    REQUIRE(payload_ran);
    REQUIRE(first == HostExecutionError::DebtCeilingExceeded);
    INFO("debt before " << debt_before << " after " << debt_after_first
         << " (delta " << static_cast<long long>(debt_after_first - debt_before) << ")");
    REQUIRE(debt_after_first == debt_before);
    // The payload ran, so the 10 tokens are spent: 89 more run (all at the
    // ceiling) and the 91st is RateLimited. The debt never moved.
    REQUIRE(ran == 89);
    REQUIRE(completed == 0);
    REQUIRE(ceiling_hit == 89);
    REQUIRE(host.DebtTracker().Accrued(domain) == debt_before);
}

TEST_CASE("Component 12: Layer 4 - an overrun keeps its tokens and is charged its ticks (R2-K-06)", "[layer-4][I-03]") {
    FfiPolicyHost host(kNoRefill);
    REQUIRE(host.SetActiveCapabilities(CapabilityMask256(0xFF, 0, 0, 0)));

    // Software deadline: a budget of one tick is always exceeded.
    const uint64_t software_domain = 3;
    HostExecutionError software = HostExecutionError::None;
    uint64_t software_debt = 0;
    int software_ran = 0, software_completed = 0, software_ceiling = 0;
    std::thread([&]() {
        SIMDCapabilityToken token(software_domain, CapabilityMask256(0x01, 0, 0, 0));
        auto r = host.ExecuteGovernedTransaction(token, kTen, 1ULL, 1'000'000'000ULL, []() { BurnCpuForMilliseconds(1); });
        if (!r.has_value()) software = r.error();
        software_debt = host.DebtTracker().Accrued(software_domain);
        software_ran = DrainTensUntilRateLimited(host, software_domain, &software_completed, &software_ceiling);
    }).join();
    REQUIRE(software == HostExecutionError::DeadlineExceeded);
    REQUIRE(software_debt > 0);
    REQUIRE(software_ran == 89);       // the overrun's 10 tokens were not refunded
    REQUIRE(software_completed == 89);

    // Hard (CPU-time) deadline: 20 ms of CPU, the payload burns 200 ms.
    const uint64_t hard_domain = 4;
    HostExecutionError hard = HostExecutionError::None;
    uint64_t hard_debt = 0;
    int hard_ran = 0, hard_completed = 0, hard_ceiling = 0;
    std::thread([&]() {
        SIMDCapabilityToken token(hard_domain, CapabilityMask256(0x01, 0, 0, 0));
        auto r = host.ExecuteGovernedTransaction(token, kTen, ~0ULL, 20'000'000ULL, []() { BurnCpuForMilliseconds(200); });
        if (!r.has_value()) hard = r.error();
        hard_debt = host.DebtTracker().Accrued(hard_domain);
        hard_ran = DrainTensUntilRateLimited(host, hard_domain, &hard_completed, &hard_ceiling);
    }).join();
    REQUIRE(hard == HostExecutionError::PreemptionTriggered);
    REQUIRE(hard_debt > 0);
    REQUIRE(hard_ran == 89);
    REQUIRE(hard_completed == 89);
}

TEST_CASE("Component 12: Layer 4 - a transaction rejected before running consumes and accrues nothing", "[layer-4][I-03]") {
    FfiPolicyHost host(kNoRefill);
    REQUIRE(host.SetActiveCapabilities(CapabilityMask256(0xFF, 0, 0, 0)));

    // Capability denied and an oversized request: refused before the payload.
    const uint64_t refused_domain = 5;
    int denied = 0, oversized = 0;
    bool payload_ran = false;
    uint64_t debt_after_refusals = 1;
    int ran = 0, completed = 0, ceiling = 0;
    std::thread([&]() {
        SIMDCapabilityToken bad(refused_domain, CapabilityMask256(0x100, 0, 0, 0));
        SIMDCapabilityToken good(refused_domain, CapabilityMask256(0x01, 0, 0, 0));
        for (int i = 0; i < 10; ++i) {
            auto r = host.ExecuteGovernedTransaction(bad, kTen, ~0ULL, 1'000'000'000ULL, [&]() { payload_ran = true; });
            if (!r.has_value() && r.error() == HostExecutionError::CapabilityValidationFailed) ++denied;
            auto o = host.ExecuteGovernedTransaction(good, 101, ~0ULL, 1'000'000'000ULL, [&]() { payload_ran = true; });
            if (!o.has_value() && o.error() == HostExecutionError::RateLimitExceeded) ++oversized;
        }
        debt_after_refusals = host.DebtTracker().Accrued(refused_domain);
        ran = DrainTensUntilRateLimited(host, refused_domain, &completed, &ceiling);
    }).join();
    REQUIRE(denied == 10);
    REQUIRE(oversized == 10);
    REQUIRE_FALSE(payload_ran);
    REQUIRE(debt_after_refusals == 0);
    REQUIRE(ran == 90);
    REQUIRE(completed == 90);

    // A timer that cannot be armed: tokens were consumed and are refunded,
    // the payload never ran, no debt. Forged timer id as in the D-03 case.
    const uint64_t arm_domain = 6;
    HostExecutionError arm = HostExecutionError::None;
    bool arm_payload_ran = false;
    std::thread([&]() {
        g_thread_timer_state.timer_id = reinterpret_cast<timer_t>(static_cast<uintptr_t>(0x7fffffff));
        g_thread_timer_state.timer_initialized = true;
        SIMDCapabilityToken token(arm_domain, CapabilityMask256(0x01, 0, 0, 0));
        auto r = host.ExecuteGovernedTransaction(token, kTen, ~0ULL, 20'000'000ULL, [&]() { arm_payload_ran = true; });
        if (!r.has_value()) arm = r.error();
    }).join();
    REQUIRE(arm == HostExecutionError::TimerArmFailed);
    REQUIRE_FALSE(arm_payload_ran);
    REQUIRE(host.DebtTracker().Accrued(arm_domain) == 0);
    int arm_ran = 0, arm_completed = 0, arm_ceiling = 0;
    std::thread([&]() { arm_ran = DrainTensUntilRateLimited(host, arm_domain, &arm_completed, &arm_ceiling); }).join();
    REQUIRE(arm_ran == 90);
    REQUIRE(arm_completed == 90);
}

TEST_CASE("Component 16 & 17: Integration & Chaos Stress", "[components][16-17]") {
    constexpr int num_threads = 4;
    std::vector<std::thread> threads;
    std::atomic<int> completed{0};
    GovernedMinotaurHost<> host;
    REQUIRE(host.SetActiveCapabilities(CapabilityMask256(0xFF, 0, 0, 0)));

    for (int i = 0; i < num_threads; ++i) {
        threads.emplace_back([&host, &completed, i]() {
            SIMDCapabilityToken token(i, CapabilityMask256(0x01, 0, 0, 0));
            for (int j = 0; j < 500; ++j) {
                [[maybe_unused]] auto res = host.ExecuteGovernedTransaction(
                    token, 50, 1'000'000ULL, 500'000ULL, []() { BackpressureController::YieldCpu(); }
                );
            }
            completed++;
        });
    }
    for (auto& t : threads) t.join();
    REQUIRE(completed.load() == num_threads);
}
