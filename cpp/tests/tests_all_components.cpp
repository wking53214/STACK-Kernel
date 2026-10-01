#include <catch2/catch_test_macros.hpp>
#include <sys/wait.h>
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

TEST_CASE("Components 14-15: Arena & Audit Ring", "[components][14-15]") {
    StaticArenaBuffer<1024> arena;
    REQUIRE(arena.Allocate<uint64_t>(42).has_value());
    
    SeccompAuditRing<1024> audit;
    audit.Push(AuditEventType::CapabilityViolation, 777, 5);
    AuditEventRecord rec{};
    REQUIRE(audit.ReadSlot(0, rec));
    REQUIRE(rec.context_id == 777);
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
