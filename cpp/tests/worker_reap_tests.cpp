// Bounded reap and TerminationUnconfirmed (RACE-02, R2-K-12).
//
// Built with -DSTACK_SUPERVISED_TESTING, which compiles in a seam that
// replaces the supervisor's SIGKILL. The seam does not exist in a shipped
// build. With the kill suppressed the child keeps running past its deadline,
// so the supervisor must NOT wait for it forever and must NOT report success:
// it reports TerminationUnconfirmed within the reap bound, keeps the pid
// tracked, and the test then restores the real kill to clean up.

#include <catch2/catch_test_macros.hpp>

#include <cerrno>
#include <csignal>
#include <atomic>
#include <cstdio>
#include <cstring>
#include <string>
#include <thread>
#include <vector>

#include <dirent.h>
#include <fcntl.h>
#include <sys/wait.h>
#include <unistd.h>

#include "../include/stack_supervised_exec.hpp"

using namespace stack::supervised;

#ifndef STACK_WORKER_PATH
#error "STACK_WORKER_PATH must name the shipped worker program"
#endif

namespace {

constexpr uint64_t kMs = 1'000'000ULL;

bool IneffectiveKill(pid_t, int) { return true; }  // "handled": nothing is sent

std::size_t OpenDescriptorCount() {
    DIR* d = ::opendir("/proc/self/fd");
    REQUIRE(d != nullptr);
    std::size_t n = 0;
    while (::readdir(d) != nullptr) ++n;
    ::closedir(d);
    return n - 1;
}

bool Alive(pid_t pid) { return ::kill(pid, 0) == 0; }

// Restores the real kill and waits (bounded) for every tracked child to go.
void CleanUp() {
    SupervisedExecutor::SetKillHookForTesting(nullptr);
    for (int i = 0; i < 400 && SupervisedExecutor::ReapUnconfirmed() != 0; ++i) ::usleep(10'000);
}

Limits QuickLimits(uint64_t deadline_ms, uint64_t reap_ms) {
    Limits l;
    l.wall_clock_deadline_ns = deadline_ms * kMs;
    l.reap_timeout_ns = reap_ms * kMs;
    l.max_output_bytes = 64;
    return l;
}

ExecutionReport RunSpinner(const Limits& l) {
    uint8_t out[64] = {};
    WorkerSpec spec;
    spec.executable = STACK_WORKER_PATH;
    spec.kind = 1;  // spin
    return SupervisedExecutor::RunWorker(l, spec, out, sizeof out);
}

}  // namespace

TEST_CASE("Reap: an ineffective kill is TerminationUnconfirmed within the bound, never a success", "[reap]") {
    REQUIRE(SupervisedExecutor::UnconfirmedCount() == 0);
    const std::size_t fds_before = OpenDescriptorCount();
    SupervisedExecutor::SetKillHookForTesting(&IneffectiveKill);
    const ExecutionReport r = RunSpinner(QuickLimits(100, 300));
    std::fprintf(stderr, "[measured] ineffective kill: elapsed %.1f ms (deadline 100 ms + reap bound 300 ms)\n",
                 static_cast<double>(r.elapsed_ns) / 1e6);

    REQUIRE(r.outcome == Outcome::TerminationUnconfirmed);
    REQUIRE(r.outcome != Outcome::Completed);
    REQUIRE(r.deadline_fired);
    REQUIRE(r.result_length == 0);
    REQUIRE_FALSE(r.result_self_reported);
    REQUIRE(r.error_number == ETIMEDOUT);
    REQUIRE(r.elapsed_ns >= 100 * kMs + 300 * kMs);
    REQUIRE(r.elapsed_ns <= 100 * kMs + 300 * kMs + 1'000 * kMs);

    // The child is still there, and still tracked with its descriptor.
    REQUIRE(r.child_pid > 0);
    REQUIRE(Alive(r.child_pid));
    REQUIRE(SupervisedExecutor::UnconfirmedCount() == 1);

    // Restore the real kill: the tracked child is killed and reaped, the
    // count returns to zero and the pidfd is closed.
    CleanUp();
    REQUIRE(SupervisedExecutor::UnconfirmedCount() == 0);
    REQUIRE_FALSE(Alive(r.child_pid));
    REQUIRE(OpenDescriptorCount() == fds_before);
}

TEST_CASE("Reap: the bound is configurable and also applies to the fork-of-caller path", "[reap]") {
    SupervisedExecutor::SetKillHookForTesting(&IneffectiveKill);
    uint8_t out[64] = {};
    const Limits l = QuickLimits(50, 80);
    const ExecutionReport r = SupervisedExecutor::Run(
        l, [](uint8_t*, std::size_t) { for (;;) asm volatile("" ::: "memory"); }, out, sizeof out);
    std::fprintf(stderr, "[measured] ineffective kill, fork path, 50+80 ms: elapsed %.1f ms\n",
                 static_cast<double>(r.elapsed_ns) / 1e6);
    REQUIRE(r.outcome == Outcome::TerminationUnconfirmed);
    REQUIRE(r.elapsed_ns >= 130 * kMs);
    REQUIRE(r.elapsed_ns <= 130 * kMs + 1'000 * kMs);
    REQUIRE(SupervisedExecutor::UnconfirmedCount() == 1);
    CleanUp();
    REQUIRE(SupervisedExecutor::UnconfirmedCount() == 0);
}

TEST_CASE("Reap: a run while a child is unconfirmed still works, and the unconfirmed one is cleaned up first", "[reap]") {
    SupervisedExecutor::SetKillHookForTesting(&IneffectiveKill);
    const ExecutionReport stuck = RunSpinner(QuickLimits(50, 50));
    REQUIRE(stuck.outcome == Outcome::TerminationUnconfirmed);
    REQUIRE(SupervisedExecutor::UnconfirmedCount() == 1);
    SupervisedExecutor::SetKillHookForTesting(nullptr);

    uint8_t out[64] = {};
    WorkerSpec spec;
    spec.executable = STACK_WORKER_PATH;
    spec.kind = 0;  // return bytes
    const ExecutionReport ok = SupervisedExecutor::RunWorker(QuickLimits(2'000, 2'000), spec, out, sizeof out);
    REQUIRE(ok.outcome == Outcome::Completed);
    REQUIRE(ok.result_self_reported);
    CleanUp();
    REQUIRE(SupervisedExecutor::UnconfirmedCount() == 0);
    REQUIRE_FALSE(Alive(stuck.child_pid));
}

TEST_CASE("Reap: with every tracking slot taken, no new child is spawned", "[reap]") {
    SupervisedExecutor::SetKillHookForTesting(&IneffectiveKill);
    for (std::size_t i = 0; i < kMaxUnconfirmedChildren; ++i) {
        const ExecutionReport r = RunSpinner(QuickLimits(10, 10));
        REQUIRE(r.outcome == Outcome::TerminationUnconfirmed);
    }
    REQUIRE(SupervisedExecutor::UnconfirmedCount() == kMaxUnconfirmedChildren);

    const ExecutionReport refused = RunSpinner(QuickLimits(10, 10));
    REQUIRE(refused.outcome == Outcome::SupervisorError);
    REQUIRE(refused.error_number == EBUSY);
    REQUIRE(refused.child_pid == 0);
    CleanUp();
    REQUIRE(SupervisedExecutor::UnconfirmedCount() == 0);
}

TEST_CASE("Reap: the reap bound is validated", "[reap]") {
    Limits l = QuickLimits(100, 100);
    uint8_t out[64];
    WorkerSpec spec;
    spec.executable = STACK_WORKER_PATH;
    l.reap_timeout_ns = 0;
    REQUIRE(SupervisedExecutor::RunWorker(l, spec, out, sizeof out).outcome == Outcome::InvalidLimits);
    l.reap_timeout_ns = kMaxReapTimeoutNs + 1;
    REQUIRE(SupervisedExecutor::RunWorker(l, spec, out, sizeof out).outcome == Outcome::InvalidLimits);
    l.reap_timeout_ns = kMaxReapTimeoutNs;
    spec.kind = 0;
    REQUIRE(SupervisedExecutor::RunWorker(l, spec, out, sizeof out).outcome == Outcome::Completed);
}

// ---------------------------------------------------------------------------
// R2-K-23: the supervisor signals and reaps a worker through its pidfd, never
// by a pid number that may have been reused, and a worker is never spawned
// without a tracking slot reserved for it.
// ---------------------------------------------------------------------------

namespace {

// Forks a process that gets exactly the pid `want` (by setting the pid
// namespace's next pid, which needs root), leads its own process group and
// sleeps. This is a real pid reuse, not a simulation of one. Returns -1 if
// the number could not be had.
// On failure g_victim_failure says why, with the path, the call and the errno.
std::string g_victim_failure;

void RecordVictimFailure(const char* what, int err) {
    char text[200];
    std::snprintf(text, sizeof text, "ForkVictimWithPid: %s on /proc/sys/kernel/ns_last_pid failed: errno %d (%s), euid %d",
                  what, err, std::strerror(err), static_cast<int>(::geteuid()));
    g_victim_failure = text;
}

pid_t ForkVictimWithPid(pid_t want) {
    g_victim_failure.clear();
    for (int attempt = 0; attempt < 50; ++attempt) {
        const int fd = ::open("/proc/sys/kernel/ns_last_pid", O_WRONLY | O_CLOEXEC);
        if (fd < 0) {
            RecordVictimFailure("open", errno);
            return -1;
        }
        char text[16];
        const int n = std::snprintf(text, sizeof text, "%d", static_cast<int>(want) - 1);
        const bool wrote = ::write(fd, text, static_cast<std::size_t>(n)) == n;
        if (wrote) {
            const pid_t pid = ::fork();
            if (pid == 0) {
                (void)::setpgid(0, 0);
                for (;;) ::pause();
            }
            ::close(fd);
            if (pid == want) {
                (void)::setpgid(pid, pid);  // do not depend on the child winning the race
                return pid;
            }
            if (pid > 0) {
                ::kill(pid, SIGKILL);
                ::waitpid(pid, nullptr, 0);
            }
        } else {
            RecordVictimFailure("write", errno);
            ::close(fd);
            return -1;
        }
    }
    g_victim_failure = "ForkVictimWithPid: 50 attempts never produced the wanted pid (it was taken each time)";
    return -1;
}

// Fails the test loudly, with the reason, when this process cannot set the pid
// namespace's next pid. The pid-reuse cases need to write
// /proc/sys/kernel/ns_last_pid, which requires CAP_SYS_ADMIN (in practice:
// root). They are never skipped; a CI job that runs them as an ordinary user
// is misconfigured and must fail here, not pass vacuously or fail with a bare
// "victim == -1". They are root-only and are not run in CI (ctest label "needs-root"); the blocking CI check of the same property is pid_reuse_interposed_tests.cpp.
void RequirePidReuseCapability() {
    const int fd = ::open("/proc/sys/kernel/ns_last_pid", O_RDWR | O_CLOEXEC);
    const int open_errno = errno;
    char text[16] = {0};
    bool ok = false;
    int err = open_errno;
    if (fd >= 0) {
        const ssize_t got = ::pread(fd, text, sizeof text - 1, 0);
        // Write back the value just read: a no-op for the pid namespace that
        // still proves the write permission.
        ok = got > 0 && ::write(fd, text, static_cast<std::size_t>(got)) == got;
        err = errno;
        ::close(fd);
    }
    INFO("euid " << ::geteuid() << ", errno " << err << " (" << std::strerror(err) << ")");
    if (!ok) {
        FAIL("the pid-reuse cases must write /proc/sys/kernel/ns_last_pid, which needs CAP_SYS_ADMIN "
             "(run as root, e.g. `sudo env PATH=$PATH ctest -L needs-root` from a build owned by root); this process cannot, "
             "so the pid reuse cannot be simulated. This case is never skipped.");
    }
}

bool StillRunningAndUnreaped(pid_t pid) {
    int status = 0;
    return ::waitpid(pid, &status, WNOHANG) == 0;
}

void DisposeOf(pid_t victim) {
    if (victim > 0) {
        ::kill(victim, SIGKILL);
        ::waitpid(victim, nullptr, 0);
    }
}

struct Reuse {
    std::atomic<bool> fired{false};
    pid_t victim = -1;
};
Reuse g_reuse;

// Kill hook: the first time the supervisor goes to kill, the worker has
// already been reaped "elsewhere" (a SIGCHLD handler, a waitpid(-1)) and an
// unrelated process holds its pid number and leads a process group of that
// number. The real kill then proceeds.
bool ReapElsewhereThenReuse(pid_t pid, int) {
    if (g_reuse.fired.exchange(true)) return false;
    ::kill(pid, SIGKILL);
    ::waitpid(pid, nullptr, 0);
    g_reuse.victim = ForkVictimWithPid(pid);
    return false;
}

}  // namespace

TEST_CASE("Reap: a worker reaped elsewhere cannot make the supervisor kill or reap whoever now holds its pid", "[reap][pid-reuse]") {
    RequirePidReuseCapability();
    g_reuse.fired = false;
    g_reuse.victim = -1;
    SupervisedExecutor::SetKillHookForTesting(&ReapElsewhereThenReuse);
    const ExecutionReport r = RunSpinner(QuickLimits(100, 300));
    SupervisedExecutor::SetKillHookForTesting(nullptr);
    const pid_t victim = g_reuse.victim;
    INFO(g_victim_failure);
    INFO("run outcome " << static_cast<int>(r.outcome) << " (8 is SpawnFailed: the kill hook, and so ForkVictimWithPid, never ran), error_number "
                        << r.error_number << ", child_pid " << r.child_pid);
    REQUIRE(victim > 0);          // the simulation worked: the number was reused
    REQUIRE(victim == r.child_pid);
    const bool victim_ok = StillRunningAndUnreaped(victim);        // not killed, not reaped by the supervisor
    const bool group_ok = ::kill(-victim, 0) == 0;                 // its group is intact
    DisposeOf(victim);
    CHECK(victim_ok);
    CHECK(group_ok);
    // The run cannot be a success, and it did not hang on the stranger.
    REQUIRE(r.outcome != Outcome::Completed);
    REQUIRE(r.outcome != Outcome::TimedOut);  // it could not confirm what happened to ITS child
    REQUIRE(r.elapsed_ns <= 100 * kMs + 1'000 * kMs);
    REQUIRE(SupervisedExecutor::UnconfirmedCount() == 0);
}

TEST_CASE("Reap: a tracked unconfirmed worker reaped elsewhere is forgotten, not signaled by number", "[reap][pid-reuse]") {
    RequirePidReuseCapability();
    SupervisedExecutor::SetKillHookForTesting(&IneffectiveKill);
    const ExecutionReport stuck = RunSpinner(QuickLimits(50, 50));
    SupervisedExecutor::SetKillHookForTesting(nullptr);
    INFO("run outcome " << static_cast<int>(stuck.outcome) << " (8 is SpawnFailed), error_number " << stuck.error_number);
    REQUIRE(stuck.outcome == Outcome::TerminationUnconfirmed);
    REQUIRE(SupervisedExecutor::UnconfirmedCount() == 1);
    // Reaped elsewhere, and its number now belongs to a stranger.
    ::kill(stuck.child_pid, SIGKILL);
    REQUIRE(::waitpid(stuck.child_pid, nullptr, 0) == stuck.child_pid);
    const pid_t victim = ForkVictimWithPid(stuck.child_pid);
    INFO(g_victim_failure);
    REQUIRE(victim == stuck.child_pid);

    const std::size_t remaining = SupervisedExecutor::ReapUnconfirmed();
    const bool victim_ok = StillRunningAndUnreaped(victim);
    const bool group_ok = ::kill(-victim, 0) == 0;
    DisposeOf(victim);
    CHECK(victim_ok);
    CHECK(group_ok);
    REQUIRE(remaining == 0);  // the dead entry was forgotten
    REQUIRE(SupervisedExecutor::UnconfirmedCount() == 0);
}

TEST_CASE("Reap: the tracking slot is reserved before the fork, so a racing run cannot spawn an untrackable worker", "[reap][slots]") {
    SupervisedExecutor::SetKillHookForTesting(&IneffectiveKill);
    // 63 of the 64 slots are taken by workers whose death was never confirmed.
    for (std::size_t i = 0; i + 1 < kMaxUnconfirmedChildren; ++i) {
        REQUIRE(RunSpinner(QuickLimits(10, 10)).outcome == Outcome::TerminationUnconfirmed);
    }
    REQUIRE(SupervisedExecutor::UnconfirmedCount() == kMaxUnconfirmedChildren - 1);

    // Four runs race for the one free slot. Before the reservation each of
    // them passed the "fewer than 64 tracked" test and forked; three of the
    // four children then had no slot and were dropped from tracking.
    constexpr int kRacers = 4;
    std::atomic<bool> go{false};
    ExecutionReport results[kRacers];
    std::vector<std::thread> threads;
    for (int i = 0; i < kRacers; ++i) {
        threads.emplace_back([&, i] {
            while (!go.load()) {}
            results[i] = RunSpinner(QuickLimits(10, 10));
        });
    }
    go.store(true);
    for (auto& t : threads) t.join();
    int spawned = 0, refused = 0;
    for (const auto& r : results) {
        if (r.child_pid != 0) {
            ++spawned;
            REQUIRE(r.outcome == Outcome::TerminationUnconfirmed);
        } else {
            ++refused;
            REQUIRE(r.outcome == Outcome::SupervisorError);
            REQUIRE(r.error_number == EBUSY);
        }
    }
    INFO("spawned " << spawned << ", refused " << refused);
    REQUIRE(spawned == 1);
    REQUIRE(refused == kRacers - 1);
    // Every worker that exists is tracked: the table is exactly full.
    REQUIRE(SupervisedExecutor::UnconfirmedCount() == kMaxUnconfirmedChildren);
    CleanUp();
    REQUIRE(SupervisedExecutor::UnconfirmedCount() == 0);
}

TEST_CASE("Reap: a run that completes gives its reserved slot back", "[reap][slots]") {
    // 70 completed runs in a row would exhaust a 64-slot table if completion
    // did not release the reservation.
    uint8_t out[64] = {};
    for (int i = 0; i < 70; ++i) {
        WorkerSpec spec;
        spec.executable = STACK_WORKER_PATH;
        spec.kind = 0;
        const ExecutionReport r = SupervisedExecutor::RunWorker(QuickLimits(2'000, 2'000), spec, out, sizeof out);
        REQUIRE(r.outcome == Outcome::Completed);
    }
    REQUIRE(SupervisedExecutor::UnconfirmedCount() == 0);
}
