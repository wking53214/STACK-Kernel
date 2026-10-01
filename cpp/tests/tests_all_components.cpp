#include <catch2/catch_test_macros.hpp>
#include <sys/wait.h>
#include <thread>
#include <vector>

#include "../include/tack_kernel.hpp"
#include "../include/tack_kinetic_governor.hpp"
#include "../include/posix_deadline_timer_hardened.hpp"
#include "../include/tack_host_binding.hpp"
#include "../include/tack_arena.hpp"
#include "../include/tack_audit.hpp"

using namespace tack::governor;
using namespace tack::host;
using namespace tack::isolation;
using namespace tack::telemetry;

TEST_CASE("Components 1-5: Governor & Sync Core", "[components][1-5]") {
    KineticGovernor<> gov;
    auto res = gov.Consume(10, PriorityClass::Standard, HardwareClock::ReadTicks());
    REQUIRE(res.has_value());
    gov.Refund(10);
}

TEST_CASE("Components 6-10: Preemption Timer & Deadlines", "[components][6-10]") {
    REQUIRE(HardenedPosixPreemptionGuard::RegisterSignalHandler().has_value());
    REQUIRE(HardenedPosixPreemptionGuard::InitializeThreadTimer().has_value());
    HardenedPosixPreemptionGuard guard;
    REQUIRE(guard.Arm(100'000'000ULL).has_value());
    REQUIRE_FALSE(guard.WasPreempted());
}

TEST_CASE("Components 11-15: SECCOMP, Bindings, Arena, Audit", "[components][11-15]") {
    StaticArenaBuffer<1024> arena;
    REQUIRE(arena.Allocate<uint64_t>(42).has_value());
    
    SeccompAuditRing<1024> audit;
    audit.Push(AuditEventType::CapabilityViolation, 777, 5);
    AuditEventRecord rec{};
    REQUIRE(audit.ReadSlot(0, rec));
    REQUIRE(rec.context_id == 777);

    pid_t pid = ::fork();
    REQUIRE(pid >= 0);
    if (pid == 0) {
        GovernedMinotaurHost<> host;
        host.SetActiveCapabilities(CapabilityMask256(0xFF, 0, 0, 0));
        SIMDCapabilityToken token(777, CapabilityMask256(0x0F, 0, 0, 0));
        auto exec_res = host.ExecuteGovernedTransaction(token, 5, 100'000'000ULL, 1'000'000'000ULL, [](){});
        if (!exec_res.has_value()) ::_exit(1);
        ::_exit(0);
    }
    int status = 0;
    ::waitpid(pid, &status, 0);
    REQUIRE(WIFEXITED(status));
    REQUIRE(WEXITSTATUS(status) == 0);
}

TEST_CASE("Component 16 & 17: Master Integration & Chaos Stress", "[components][16-17]") {
    constexpr int num_threads = 4;
    std::vector<std::thread> threads;
    std::atomic<int> completed{0};
    GovernedMinotaurHost<> host;
    host.SetActiveCapabilities(CapabilityMask256(0xFF, 0, 0, 0));

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
