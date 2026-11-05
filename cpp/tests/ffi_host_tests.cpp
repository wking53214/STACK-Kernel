// Tests of the shipped FFI host (crates/stack-ffi/src/ffi_wrapper.cpp) through
// its C entry points. The wrapper is compiled into this binary, so these run
// the same host object, parameters and calibration a Rust caller gets.
//
// The host is process global and a sealed thread stays sealed, so every test
// case seals a fresh worker thread for its transactions and uses its own
// domain (context id); the main thread never seals. Catch2 assertions are
// made on the main thread only; workers record what they saw.
//
// The bucket refills at the calibrated rate (1000 tokens per second), so a
// count that depends on "no refill happened" is asserted with an allowance
// of one token per elapsed millisecond, measured around the sequence. On an
// idle machine the allowance is zero.
#include <catch2/catch_test_macros.hpp>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <thread>
#include <vector>

extern "C" {
int stack_host_initialize();
int stack_host_initialize_and_seal();
int stack_host_set_capabilities(uint64_t, uint64_t, uint64_t, uint64_t);
int stack_execute_governed_transaction(uint64_t, uint64_t, uint32_t, uint64_t, uint64_t);
uint64_t stack_host_payload_count();
int stack_host_audit_read_slot(uint64_t, uint8_t*, uint64_t*, uint64_t*, uint32_t*);
}

namespace {

constexpr uint64_t kNoSoftwareDeadline = ~0ULL;
constexpr uint64_t kOneSecondNs = 1'000'000'000ULL;

// Return codes of stack_execute_governed_transaction (see ffi_wrapper.cpp).
constexpr int kCompleted = 0;
constexpr int kCapabilityDenied = -4;
constexpr int kRateLimited = -5;
constexpr int kCapabilityChangePending = -13;  // I-04: a capability change is waiting to apply

// FFI governance policy (ffi_wrapper.cpp): bucket 1000, floor 100, largest
// request 100, 1000 tokens per second, 16 domains.
constexpr uint32_t kBucket = 1000;
constexpr uint32_t kFloor = 100;
constexpr uint32_t kLargestRequest = 100;
constexpr uint32_t kSpendable = kBucket - kFloor;  // 900

// AuditEventType values (stack_audit.hpp).
constexpr uint8_t kAuditTransactionCompleted = 0;
constexpr uint8_t kAuditRateLimitTriggered = 1;
constexpr uint8_t kAuditCapabilityViolation = 4;
constexpr uint64_t kHostAuditSlots = 8192;

using Clock = std::chrono::steady_clock;

long ElapsedMs(Clock::time_point since) {
    return std::chrono::duration_cast<std::chrono::milliseconds>(Clock::now() - since).count();
}

int Txn(uint64_t domain, uint64_t caps, uint32_t tokens) {
    return stack_execute_governed_transaction(domain, caps, tokens, kNoSoftwareDeadline, kOneSecondNs);
}

// Runs f on a fresh thread that seals itself first; returns the seal code.
template <typename F>
int OnSealedThread(F&& f) {
    int seal_rc = 99;
    std::thread([&] {
        seal_rc = stack_host_initialize_and_seal();
        if (seal_rc == 0) f();
    }).join();
    return seal_rc;
}

// Consumes `tokens` per transaction until the first RateLimited, at most
// `limit` attempts. Returns the number of completed transactions; `*last` is
// the final return code.
int ConsumeUntilRateLimited(uint64_t domain, uint32_t tokens, int limit, int* last) {
    int ok = 0;
    *last = 99;
    for (int i = 0; i < limit; ++i) {
        *last = Txn(domain, 0x01, tokens);
        if (*last != kCompleted) break;
        ++ok;
    }
    return ok;
}

// Counts the host audit records for `domain` by event type.
struct AuditCounts {
    int completed = 0;
    int rate_limited = 0;
    int capability_violation = 0;
    int other = 0;
};

AuditCounts CountHostAudit(uint64_t domain) {
    AuditCounts c;
    for (uint64_t i = 0; i < kHostAuditSlots; ++i) {
        uint8_t type = 0;
        uint64_t ts = 0, ctx = 0;
        uint32_t tok = 0;
        if (stack_host_audit_read_slot(i, &type, &ts, &ctx, &tok) != 0) continue;
        if (ctx != domain) continue;
        if (type == kAuditTransactionCompleted) ++c.completed;
        else if (type == kAuditRateLimitTriggered) ++c.rate_limited;
        else if (type == kAuditCapabilityViolation) ++c.capability_violation;
        else ++c.other;
    }
    return c;
}

}  // namespace

TEST_CASE("FFI host: a valid transaction with budget completes and runs the payload", "[ffi][I-01]") {
    // R2-K-01: the shipped host was GovernedMinotaurHost<64, 100, ...>, whose
    // Reserved (100) exceeded MaxCapacity (64), so every Standard request
    // failed `available < Reserved + amount` and the FFI never completed a
    // transaction. A valid capability with a full bucket must complete, and
    // completing means the payload ran.
    int caps_rc = 99;
    int rc = 99;
    uint64_t runs_before = 0, runs_after = 0;
    const int seal = OnSealedThread([&] {
        caps_rc = stack_host_set_capabilities(0xFF, 0, 0, 0);
        runs_before = stack_host_payload_count();
        rc = Txn(1, 0x01, 1);
        runs_after = stack_host_payload_count();
    });
    REQUIRE(seal == 0);
    REQUIRE(caps_rc == 0);
    INFO("transaction return code " << rc << " (" << kRateLimited << " is RateLimited)");
    REQUIRE(rc == kCompleted);
    REQUIRE(runs_after == runs_before + 1);
}

TEST_CASE("FFI host: an exhausted bucket is RateLimited, refusals consume nothing, refill restores service", "[ffi][I-01]") {
    const uint64_t domain = 2;
    int caps_rc = 99, last = 99, seal2 = 99;
    int completed = 0;
    int refusals = 0;
    uint64_t runs_before_refusals = 0, runs_after_refusals = 0;
    long elapsed_ms = -1;
    // Plain integers: a sealed thread cannot allocate (mmap and brk are not
    // on the allowlist), so nothing a worker touches may grow.
    int after_refill_first = 99, after_refill_second = 99;

    const int seal = OnSealedThread([&] {
        caps_rc = stack_host_set_capabilities(0xFF, 0, 0, 0);
        const auto t0 = Clock::now();
        completed = ConsumeUntilRateLimited(domain, kLargestRequest, 50, &last);
        elapsed_ms = ElapsedMs(t0);
        // The bucket is below the floor plus one request: every further
        // request of that size is refused and must not run the payload.
        runs_before_refusals = stack_host_payload_count();
        for (int i = 0; i < 5; ++i) {
            if (Txn(domain, 0x01, kLargestRequest) == kRateLimited) ++refusals;
        }
        runs_after_refusals = stack_host_payload_count();
    });
    REQUIRE(seal == 0);
    REQUIRE(caps_rc == 0);
    REQUIRE(last == kRateLimited);
    // 900 spendable tokens in requests of 100: 9, plus at most one per 100 ms of refill.
    INFO("completed " << completed << " in " << elapsed_ms << " ms");
    REQUIRE(completed >= static_cast<int>(kSpendable / kLargestRequest));
    REQUIRE(completed <= static_cast<int>(kSpendable / kLargestRequest) + elapsed_ms / 100 + 1);
    REQUIRE(refusals == 5);
    REQUIRE(runs_after_refusals == runs_before_refusals);

    // Refill: 300 ms at 1000 tokens per second is 300 tokens, enough for two
    // more requests of 100 above the floor. The main thread sleeps because a
    // sealed thread cannot (nanosleep is not on the allowlist).
    std::this_thread::sleep_for(std::chrono::milliseconds(300));
    uint64_t runs_before_refill = 0, runs_after_refill = 0;
    seal2 = OnSealedThread([&] {
        runs_before_refill = stack_host_payload_count();
        after_refill_first = Txn(domain, 0x01, kLargestRequest);
        after_refill_second = Txn(domain, 0x01, kLargestRequest);
        runs_after_refill = stack_host_payload_count();
    });
    REQUIRE(seal2 == 0);
    REQUIRE(after_refill_first == kCompleted);
    REQUIRE(after_refill_second == kCompleted);
    REQUIRE(runs_after_refill == runs_before_refill + 2);
}

TEST_CASE("FFI host: an invalid capability is CapabilityValidationFailed and consumes no tokens", "[ffi][I-01]") {
    const uint64_t domain = 3;
    int caps_rc = 99;
    int denied = 0;
    uint64_t runs_before = 0, runs_after = 0;
    int completed = 0, last = 99;
    long elapsed_ms = -1;
    const int seal = OnSealedThread([&] {
        caps_rc = stack_host_set_capabilities(0xFF, 0, 0, 0);
        runs_before = stack_host_payload_count();
        for (int i = 0; i < 20; ++i) {
            if (Txn(domain, 0x100, kLargestRequest) == kCapabilityDenied) ++denied;  // bit 8 is not in 0xFF
        }
        runs_after = stack_host_payload_count();
        // The bucket is still full: exactly the spendable budget is served.
        const auto t0 = Clock::now();
        completed = ConsumeUntilRateLimited(domain, kLargestRequest, 50, &last);
        elapsed_ms = ElapsedMs(t0);
    });
    REQUIRE(seal == 0);
    REQUIRE(caps_rc == 0);
    REQUIRE(denied == 20);
    REQUIRE(runs_after == runs_before);
    REQUIRE(last == kRateLimited);
    INFO("completed " << completed << " in " << elapsed_ms << " ms");
    REQUIRE(completed >= static_cast<int>(kSpendable / kLargestRequest));
    REQUIRE(completed <= static_cast<int>(kSpendable / kLargestRequest) + elapsed_ms / 100 + 1);
}

TEST_CASE("FFI host: repeated transactions leave no stale state", "[ffi][I-01]") {
    const uint64_t domain = 4;
    int caps_rc = 99;
    int completed = 0, denied = 0, other = 0;
    int caps_after = 99;
    const int seal = OnSealedThread([&] {
        caps_rc = stack_host_set_capabilities(0xFF, 0, 0, 0);
        for (int i = 0; i < 200; ++i) {
            const int valid = Txn(domain, 0x01, 1);
            const int invalid = Txn(domain, 0x100, 1);
            if (valid == kCompleted) ++completed; else ++other;
            if (invalid == kCapabilityDenied) ++denied; else ++other;
        }
        // The in-flight counter is back at zero after every outcome, so a
        // capability change is applied, not refused.
        caps_after = stack_host_set_capabilities(0xFF, 0, 0, 0);
    });
    REQUIRE(seal == 0);
    REQUIRE(caps_rc == 0);
    REQUIRE(completed == 200);  // 200 of 900 spendable tokens
    REQUIRE(denied == 200);
    REQUIRE(other == 0);
    REQUIRE(caps_after == 0);
}

TEST_CASE("FFI host: concurrent transactions consume exactly the tokens expected", "[ffi][I-01]") {
    // 4 threads x 15 transactions x 10 tokens = 600 of the 900 spendable
    // tokens on one domain: every one must complete. Draining the rest in
    // requests of 10 then gives exactly 30 more, plus the refill allowance.
    const uint64_t domain = 5;
    constexpr int kThreads = 4;
    constexpr int kPerThread = 15;
    constexpr uint32_t kTokens = 10;
    int caps_rc = 99;
    std::atomic<int> seal_failures{0};
    std::atomic<int> completed{0};
    std::atomic<int> failed{0};
    std::atomic<int> arrived{0};
    std::atomic<bool> go{false};
    uint64_t runs_before = stack_host_payload_count();

    // The main thread stays unsealed; this worker only sets the mask.
    const int seal0 = OnSealedThread([&] { caps_rc = stack_host_set_capabilities(0xFF, 0, 0, 0); });
    REQUIRE(seal0 == 0);
    REQUIRE(caps_rc == 0);

    const auto t0 = Clock::now();
    std::vector<std::thread> workers;
    for (int t = 0; t < kThreads; ++t) {
        workers.emplace_back([&] {
            if (stack_host_initialize_and_seal() != 0) { seal_failures++; arrived++; return; }
            arrived++;
            while (!go.load(std::memory_order_acquire)) {}
            for (int i = 0; i < kPerThread; ++i) {
                if (Txn(domain, 0x01, kTokens) == kCompleted) completed++; else failed++;
            }
        });
    }
    while (arrived.load() < kThreads) {}
    go.store(true, std::memory_order_release);
    for (auto& w : workers) w.join();

    int drained = 0, last = 99;
    const int seal1 = OnSealedThread([&] { drained = ConsumeUntilRateLimited(domain, kTokens, 200, &last); });
    const long elapsed_ms = ElapsedMs(t0);
    const uint64_t runs_after = stack_host_payload_count();

    REQUIRE(seal_failures.load() == 0);
    REQUIRE(seal1 == 0);
    REQUIRE(failed.load() == 0);
    REQUIRE(completed.load() == kThreads * kPerThread);
    REQUIRE(last == kRateLimited);
    const int expected_rest = static_cast<int>((kSpendable - kThreads * kPerThread * kTokens) / kTokens);  // 30
    INFO("drained " << drained << " more in " << elapsed_ms << " ms");
    REQUIRE(drained >= expected_rest);
    REQUIRE(drained <= expected_rest + static_cast<int>(elapsed_ms / kTokens) + 1);
    REQUIRE(runs_after == runs_before + static_cast<uint64_t>(completed.load() + drained));
}

TEST_CASE("FFI host: a request above the largest allowed request and an unknown domain are refused", "[ffi][I-01]") {
    const uint64_t domain = 6;
    int caps_rc = 99, too_big = 99, bad_domain = 99;
    int completed = 0, last = 99;
    long elapsed_ms = -1;
    const int seal = OnSealedThread([&] {
        caps_rc = stack_host_set_capabilities(0xFF, 0, 0, 0);
        too_big = Txn(domain, 0x01, kLargestRequest + 1);
        bad_domain = Txn(16, 0x01, 1);  // MaxDomains is 16
        // Neither refusal touched the bucket: the full spendable budget follows.
        const auto t0 = Clock::now();
        completed = ConsumeUntilRateLimited(domain, kLargestRequest, 50, &last);
        elapsed_ms = ElapsedMs(t0);
    });
    REQUIRE(seal == 0);
    REQUIRE(caps_rc == 0);
    REQUIRE(too_big == kRateLimited);
    REQUIRE(bad_domain == kRateLimited);
    REQUIRE(last == kRateLimited);
    REQUIRE(completed >= static_cast<int>(kSpendable / kLargestRequest));
    REQUIRE(completed <= static_cast<int>(kSpendable / kLargestRequest) + elapsed_ms / 100 + 1);
}

TEST_CASE("FFI host: an overrun transaction keeps its tokens", "[ffi][I-03]") {
    // A software budget of one tick is always exceeded. The payload ran, so
    // its 100 tokens are spent: 8 more requests of 100 follow, not 9.
    const uint64_t domain = 8;
    constexpr int kSoftwareDeadline = -7;
    int caps_rc = 99, overrun = 99, last = 99;
    int completed = 0;
    long elapsed_ms = -1;
    uint64_t runs_before = 0, runs_after = 0;
    const int seal = OnSealedThread([&] {
        caps_rc = stack_host_set_capabilities(0xFF, 0, 0, 0);
        const auto t0 = Clock::now();
        runs_before = stack_host_payload_count();
        overrun = stack_execute_governed_transaction(domain, 0x01, kLargestRequest, 1, kOneSecondNs);
        runs_after = stack_host_payload_count();
        completed = ConsumeUntilRateLimited(domain, kLargestRequest, 50, &last);
        elapsed_ms = ElapsedMs(t0);
    });
    REQUIRE(seal == 0);
    REQUIRE(caps_rc == 0);
    REQUIRE(overrun == kSoftwareDeadline);
    REQUIRE(runs_after == runs_before + 1);
    REQUIRE(last == kRateLimited);
    INFO("completed " << completed << " in " << elapsed_ms << " ms");
    REQUIRE(completed >= static_cast<int>(kSpendable / kLargestRequest) - 1);
    REQUIRE(completed <= static_cast<int>(kSpendable / kLargestRequest) - 1 + elapsed_ms / 100 + 1);
}

TEST_CASE("FFI host: a failed transaction produces no success audit record", "[ffi][I-01]") {
    const uint64_t domain = 7;
    int caps_rc = 99, denied = 99, limited = 99, ok = 99;
    const int seal = OnSealedThread([&] {
        caps_rc = stack_host_set_capabilities(0xFF, 0, 0, 0);
        denied = Txn(domain, 0x100, 1);                   // capability not in the mask
        limited = Txn(domain, 0x01, kLargestRequest + 1); // above the largest request
        ok = Txn(domain, 0x01, 1);
    });
    REQUIRE(seal == 0);
    REQUIRE(caps_rc == 0);
    REQUIRE(denied == kCapabilityDenied);
    REQUIRE(limited == kRateLimited);
    REQUIRE(ok == kCompleted);
    const AuditCounts c = CountHostAudit(domain);
    REQUIRE(c.capability_violation == 1);
    REQUIRE(c.rate_limited == 1);
    REQUIRE(c.completed == 1);  // only the transaction that completed
    REQUIRE(c.other == 0);
}

TEST_CASE("FFI host: a revocation applies under sustained transaction load (R2-K-07)", "[ffi][I-04]") {
    // Eight sealed executor threads run transactions back to back, each on its
    // own domain, so at every instant some transaction is in flight. They ask
    // for zero tokens: the bucket's rate limit (1000 tokens per second) would
    // otherwise end the load within milliseconds, and a rate limited
    // transaction leaves the host before the payload and the timer, which
    // leaves the setter gaps to slip through. A zero-token transaction takes
    // the whole path: capability check, floor check, timer arm, payload,
    // debt. The
    // capability change used to be refused whenever the global in-flight count
    // was above zero, so it never applied (334 attempts with one executor,
    // none in 2 s with eight). The change must now apply within a bound, a
    // transaction that starts after it returned must not run its payload, and
    // the host must serve again once the capability is restored.
    constexpr int kExecutors = 8;
    constexpr uint64_t kDomains[kExecutors] = {0, 9, 10, 11, 12, 13, 14, 15};
    constexpr long kBoundMs = 1000;

    REQUIRE(stack_host_initialize() == 0);
    REQUIRE(stack_host_set_capabilities(0xFF, 0, 0, 0) == 0);

    std::atomic<bool> stop{false};
    std::atomic<bool> revoked{false};       // set after the change returned applied
    std::atomic<int> sealed{0};
    std::atomic<int> seal_failures{0};
    std::atomic<uint64_t> attempts{0};
    std::atomic<uint64_t> started_after_revoke{0};
    std::atomic<uint64_t> completed_after_revoke{0};
    std::atomic<uint64_t> refused_after_revoke{0};
    std::vector<std::thread> executors;
    for (int t = 0; t < kExecutors; ++t) {
        executors.emplace_back([&, t] {
            if (stack_host_initialize_and_seal() != 0) { seal_failures++; sealed++; return; }
            sealed++;
            while (!stop.load(std::memory_order_relaxed)) {
                // Read before the call: a transaction that begins after the
                // change returned applied is the one that must be refused.
                const bool after = revoked.load(std::memory_order_acquire);
                const int rc = Txn(kDomains[t], 0x01, 0);
                attempts.fetch_add(1, std::memory_order_relaxed);
                if (after) {
                    started_after_revoke.fetch_add(1, std::memory_order_relaxed);
                    if (rc == kCompleted) completed_after_revoke.fetch_add(1, std::memory_order_relaxed);
                    if (rc == kCapabilityDenied) refused_after_revoke.fetch_add(1, std::memory_order_relaxed);
                }
            }
        });
    }
    const auto wait_started = Clock::now();
    while (sealed.load() < kExecutors && ElapsedMs(wait_started) < 5000) {}
    // Let the load run until payloads are demonstrably executing.
    const uint64_t payloads_at_start = stack_host_payload_count();
    while (stack_host_payload_count() < payloads_at_start + 100 && ElapsedMs(wait_started) < 5000) {}

    // The revocation, retried on -2 as the ABI documents, for at most the bound.
    const auto t0 = Clock::now();
    int rc = -2;
    long tries = 0;
    while (rc == -2 && ElapsedMs(t0) < kBoundMs) {
        rc = stack_host_set_capabilities(0, 0, 0, 0);
        ++tries;
    }
    const long applied_ms = ElapsedMs(t0);
    const uint64_t payloads_when_applied = stack_host_payload_count();
    revoked.store(true, std::memory_order_release);

    // Keep the load running after the change so a late payload would show.
    const auto after_start = Clock::now();
    while (started_after_revoke.load() < 1000 && ElapsedMs(after_start) < 2000) {}
    stop.store(true, std::memory_order_relaxed);
    for (auto& e : executors) e.join();
    const uint64_t payloads_at_end = stack_host_payload_count();

    REQUIRE(seal_failures.load() == 0);
    INFO("revocation returned " << rc << " after " << applied_ms << " ms and " << tries << " calls ("
         << attempts.load() << " transactions attempted)");
    REQUIRE(rc == 0);
    REQUIRE(applied_ms < kBoundMs);
    REQUIRE(payloads_when_applied > payloads_at_start);  // payloads were running under the load
    // Nothing that began after the change ran: not by return code, not by payload.
    REQUIRE(started_after_revoke.load() >= 1000);
    REQUIRE(completed_after_revoke.load() == 0);
    REQUIRE(refused_after_revoke.load() == started_after_revoke.load());
    REQUIRE(payloads_at_end == payloads_when_applied);

    // Restoring applies at once (no change is left pending) and the host serves.
    REQUIRE(stack_host_set_capabilities(0xFF, 0, 0, 0) == 0);
    int served = 99;
    REQUIRE(OnSealedThread([&] { served = Txn(1, 0x01, 1); }) == 0);
    REQUIRE(served != kCapabilityChangePending);
    REQUIRE(served == kCompleted);
}
