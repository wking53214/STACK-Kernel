// Tests for stack::supervised::SupervisedExecutor (cpp/include/stack_supervised_exec.hpp).
//
// Every hostile payload here (infinite loops, blocking reads, fork and
// memory attempts) runs inside a supervised child under rlimits; the parent
// is this Catch2 process. Timing assertions use a stated slack over the
// deadline: the kill and reap take well under a millisecond, but a loaded
// host can delay the supervising thread's wake-up.

#include <catch2/catch_test_macros.hpp>

#include <atomic>
#include <cerrno>
#include <csignal>
#include <cstdlib>
#include <cstring>
#include <thread>
#include <vector>

#include <dirent.h>
#include <fcntl.h>
#include <sys/ptrace.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>

#include "../include/stack_supervised_exec.hpp"

using namespace stack::supervised;

namespace {

constexpr uint64_t kMs = 1'000'000ULL;
constexpr uint64_t kDeadlineNs = 200 * kMs;
// Slack over the deadline for a killed child: kill + reap + scheduling.
constexpr uint64_t kSlackNs = 1'000 * kMs;

// Fits the 64-byte buffers most cases use; the two large-output cases raise it.
Limits DefaultLimits() {
    Limits l;
    l.wall_clock_deadline_ns = kDeadlineNs;
    l.max_output_bytes = 64;
    return l;
}

std::size_t OpenDescriptorCount() {
    DIR* d = ::opendir("/proc/self/fd");
    REQUIRE(d != nullptr);
    std::size_t n = 0;
    while (::readdir(d) != nullptr) ++n;
    ::closedir(d);
    return n - 1;  // the directory stream's own descriptor
}

bool NoChildrenLeft() {
    int status = 0;
    const pid_t w = ::waitpid(-1, &status, WNOHANG);
    const int saved = errno;
    return w == -1 && saved == ECHILD;
}

[[noreturn]] void SpinForever() {
    for (;;) {
        asm volatile("" ::: "memory");
    }
}

}  // namespace

TEST_CASE("Supervised: a payload that returns bytes is Completed with the exact bytes", "[supervised]") {
    uint8_t out[4096];
    std::memset(out, 0, sizeof out);
    Limits limits = DefaultLimits();
    limits.max_output_bytes = sizeof out;
    const auto report = SupervisedExecutor::Run(
        limits,
        [](uint8_t* o, std::size_t cap) {
            for (std::size_t i = 0; i < 1000 && i < cap; ++i) o[i] = static_cast<uint8_t>((i * 7) & 0xFF);
            return std::size_t{1000};
        },
        out, sizeof out);
    REQUIRE(report.outcome == Outcome::Completed);
    REQUIRE(report.result_length == 1000);
    REQUIRE(report.exit_code == 0);
    REQUIRE_FALSE(report.deadline_fired);
    for (std::size_t i = 0; i < 1000; ++i) REQUIRE(out[i] == static_cast<uint8_t>((i * 7) & 0xFF));
    REQUIRE(NoChildrenLeft());
}

TEST_CASE("Supervised: an infinite loop is killed at the deadline and is TimedOut", "[supervised][D-02]") {
    uint8_t out[64];
    const auto report = SupervisedExecutor::Run(DefaultLimits(), [](uint8_t*, std::size_t) { SpinForever(); }, out, sizeof out);
    REQUIRE(report.outcome == Outcome::TimedOut);
    REQUIRE(report.outcome != Outcome::Completed);
    REQUIRE(report.deadline_fired);
    REQUIRE(report.signal_number == SIGKILL);
    REQUIRE(report.elapsed_ns >= kDeadlineNs);
    REQUIRE(report.elapsed_ns <= kDeadlineNs + kSlackNs);
    REQUIRE(NoChildrenLeft());
}

TEST_CASE("Supervised: a payload blocked in read() on an empty pipe is killed", "[supervised][D-02]") {
    int p[2] = {-1, -1};
    REQUIRE(::pipe2(p, O_CLOEXEC) == 0);
    Limits limits = DefaultLimits();
    limits.inherit_fd = p[0];
    uint8_t out[64];
    const int read_fd = p[0];
    const auto report = SupervisedExecutor::Run(
        limits,
        [read_fd](uint8_t*, std::size_t) {
            char c = 0;
            const ssize_t r = ::read(read_fd, &c, 1);  // blocks: nobody writes
            (void)r;
        },
        out, sizeof out);
    ::close(p[0]);
    ::close(p[1]);
    REQUIRE(report.outcome == Outcome::TimedOut);
    REQUIRE(report.deadline_fired);
    REQUIRE(report.elapsed_ns <= kDeadlineNs + kSlackNs);
    REQUIRE(NoChildrenLeft());
}

TEST_CASE("Supervised: signal tricks cannot evade the deadline", "[supervised][D-02]") {
    uint8_t out[64];
    SECTION("signal(SIG_IGN), sigaction and a blocked mask, then spin") {
        const auto report = SupervisedExecutor::Run(
            DefaultLimits(),
            [](uint8_t*, std::size_t) {
                (void)::signal(SIGTERM, SIG_IGN);
                (void)::signal(SIGKILL, SIG_IGN);
                struct sigaction sa{};
                sa.sa_handler = SIG_IGN;
                (void)::sigaction(SIGXCPU, &sa, nullptr);
                (void)::sigaction(SIGKILL, &sa, nullptr);
                sigset_t all;
                ::sigfillset(&all);
                (void)::sigprocmask(SIG_BLOCK, &all, nullptr);
                SpinForever();
            },
            out, sizeof out);
        REQUIRE(report.outcome != Outcome::Completed);
        REQUIRE(report.outcome == Outcome::TimedOut);
        REQUIRE(report.elapsed_ns <= kDeadlineNs + kSlackNs);
    }
    SECTION("timer_settime is not available in the child") {
        const auto report = SupervisedExecutor::Run(
            DefaultLimits(),
            [](uint8_t*, std::size_t) {
                itimerspec zero{};
                (void)::timer_settime(nullptr, 0, &zero, nullptr);
                SpinForever();
            },
            out, sizeof out);
        REQUIRE(report.outcome != Outcome::Completed);
        REQUIRE((report.outcome == Outcome::SeccompViolation || report.outcome == Outcome::TimedOut));
        REQUIRE(report.elapsed_ns <= kDeadlineNs + kSlackNs);
    }
    REQUIRE(NoChildrenLeft());
}

TEST_CASE("Supervised: fork, execve, socket, open and ptrace are SeccompViolation", "[supervised]") {
    uint8_t out[64];
    enum class Attempt { Fork, Execve, Socket, Open, Ptrace };
    const Attempt attempts[] = {Attempt::Fork, Attempt::Execve, Attempt::Socket, Attempt::Open, Attempt::Ptrace};
    for (const Attempt attempt : attempts) {
        const auto report = SupervisedExecutor::Run(
            DefaultLimits(),
            [attempt](uint8_t*, std::size_t) {
                switch (attempt) {
                case Attempt::Fork: (void)::fork(); break;
                case Attempt::Execve: {
                    char* const argv[] = {const_cast<char*>("/bin/true"), nullptr};
                    (void)::execve("/bin/true", argv, nullptr);
                    break;
                }
                case Attempt::Socket: (void)::socket(AF_INET, SOCK_STREAM, 0); break;
                case Attempt::Open: (void)::open("/etc/hostname", O_RDONLY); break;
                case Attempt::Ptrace: (void)::ptrace(PTRACE_TRACEME, 0, nullptr, nullptr); break;
                }
                // Reaching here means the call was not killed: make that visible.
                SpinForever();
            },
            out, sizeof out);
        INFO("attempt " << static_cast<int>(attempt));
        REQUIRE(report.outcome == Outcome::SeccompViolation);
        REQUIRE(report.signal_number == SIGSYS);
        REQUIRE_FALSE(report.deadline_fired);
    }
    REQUIRE(NoChildrenLeft());
}

TEST_CASE("Supervised: SIGSEGV, abort() and a frameless exit are never Completed", "[supervised]") {
    uint8_t out[64];
    SECTION("SIGSEGV is Crashed with the signal number") {
        const auto report = SupervisedExecutor::Run(
            DefaultLimits(), [](uint8_t*, std::size_t) { *static_cast<volatile int*>(nullptr) = 1; }, out, sizeof out);
        REQUIRE(report.outcome == Outcome::Crashed);
        REQUIRE(report.signal_number == SIGSEGV);
    }
    SECTION("abort() is Crashed with SIGABRT") {
        const auto report = SupervisedExecutor::Run(DefaultLimits(), [](uint8_t*, std::size_t) { std::abort(); }, out, sizeof out);
        REQUIRE(report.outcome == Outcome::Crashed);
        REQUIRE(report.signal_number == SIGABRT);
    }
    SECTION("_exit(0) without a result frame is ResultMissing") {
        const auto report = SupervisedExecutor::Run(DefaultLimits(), [](uint8_t*, std::size_t) { ::_exit(0); }, out, sizeof out);
        REQUIRE(report.outcome == Outcome::ResultMissing);
        REQUIRE(report.exit_code == 0);
    }
    SECTION("_exit(3) is ExitedNonZero with the code") {
        const auto report = SupervisedExecutor::Run(DefaultLimits(), [](uint8_t*, std::size_t) { ::_exit(3); }, out, sizeof out);
        REQUIRE(report.outcome == Outcome::ExitedNonZero);
        REQUIRE(report.exit_code == 3);
    }
    REQUIRE(NoChildrenLeft());
}

TEST_CASE("Supervised: allocating beyond RLIMIT_AS is ResourceLimit or Crashed", "[supervised]") {
    Limits limits = DefaultLimits();
    limits.wall_clock_deadline_ns = 5'000 * kMs;
    limits.address_space_bytes = 64u << 20;
    uint8_t out[64];
    const auto report = SupervisedExecutor::Run(
        limits,
        [](uint8_t*, std::size_t) {
            // Virtual size only: RLIMIT_AS trips on the mapping, not on use.
            for (;;) {
                volatile uint8_t* p = new uint8_t[1u << 20];
                p[0] = 1;
            }
        },
        out, sizeof out);
    INFO("outcome " << static_cast<int>(report.outcome) << " exit " << report.exit_code << " signal " << report.signal_number
                    << " errno " << report.error_number << " elapsed_ms " << report.elapsed_ns / kMs);
    REQUIRE(report.outcome != Outcome::Completed);
    REQUIRE((report.outcome == Outcome::ResourceLimit || report.outcome == Outcome::Crashed));
    REQUIRE_FALSE(report.deadline_fired);
    REQUIRE(NoChildrenLeft());
}

TEST_CASE("Supervised: an oversized result is rejected", "[supervised]") {
    Limits limits = DefaultLimits();
    limits.max_output_bytes = 16;
    uint8_t out[4096];
    const auto report = SupervisedExecutor::Run(
        limits,
        [](uint8_t* o, std::size_t) {
            std::memset(o, 'x', 64);
            return std::size_t{64};
        },
        out, sizeof out);
    REQUIRE(report.outcome == Outcome::ResultOversized);
    REQUIRE(report.outcome != Outcome::Completed);
    REQUIRE(report.result_length == 0);
    REQUIRE(NoChildrenLeft());
}

TEST_CASE("Supervised: zero or absurd limits are rejected before forking", "[supervised]") {
    uint8_t out[64];
    const std::size_t fds_before = OpenDescriptorCount();
    auto run = [&](Limits l) { return SupervisedExecutor::Run(l, [](uint8_t*, std::size_t) {}, out, sizeof out); };
    Limits zero = DefaultLimits();
    zero.wall_clock_deadline_ns = 0;
    Limits absurd = DefaultLimits();
    absurd.wall_clock_deadline_ns = kMaxWallClockDeadlineNs + 1;
    Limits big_output = DefaultLimits();
    big_output.max_output_bytes = kMaxOutputBytes + 1;
    Limits larger_than_buffer = DefaultLimits();
    larger_than_buffer.max_output_bytes = sizeof out + 1;
    Limits bad_fd = DefaultLimits();
    bad_fd.inherit_fd = 1;
    for (const Limits& l : {zero, absurd, big_output, larger_than_buffer, bad_fd}) {
        const auto report = run(l);
        REQUIRE(report.outcome == Outcome::InvalidLimits);
        REQUIRE(report.child_pid == 0);
        REQUIRE(report.elapsed_ns == 0);
    }
    REQUIRE(OpenDescriptorCount() == fds_before);
    REQUIRE(NoChildrenLeft());
}

TEST_CASE("Supervised: 300 sequential runs leave no zombies and no descriptors", "[supervised]") {
    const std::size_t fds_before = OpenDescriptorCount();
    uint8_t out[64];
    Limits limits = DefaultLimits();
    limits.wall_clock_deadline_ns = 2'000 * kMs;
    int completed = 0;
    for (int i = 0; i < 300; ++i) {
        const auto report = SupervisedExecutor::Run(
            limits,
            [i](uint8_t* o, std::size_t) {
                o[0] = static_cast<uint8_t>(i);
                return std::size_t{1};
            },
            out, sizeof out);
        if (report.outcome == Outcome::Completed && report.result_length == 1 && out[0] == static_cast<uint8_t>(i)) ++completed;
    }
    REQUIRE(completed == 300);
    REQUIRE(OpenDescriptorCount() == fds_before);
    REQUIRE(NoChildrenLeft());
}

TEST_CASE("Supervised: concurrent runs from several threads each classify correctly", "[supervised]") {
    const std::size_t fds_before = OpenDescriptorCount();
    constexpr int kThreads = 4;
    constexpr int kRounds = 3;
    std::atomic<int> correct{0};
    std::vector<std::thread> threads;
    for (int t = 0; t < kThreads; ++t) {
        threads.emplace_back([t, &correct]() {
            uint8_t out[64];
            for (int round = 0; round < kRounds; ++round) {
                const int kind = (t + round) % 3;
                const Limits limits = DefaultLimits();
                ExecutionReport report{};
                bool ok = false;
                if (kind == 0) {
                    report = SupervisedExecutor::Run(limits, [](uint8_t*, std::size_t) { SpinForever(); }, out, sizeof out);
                    ok = report.outcome == Outcome::TimedOut && report.elapsed_ns <= kDeadlineNs + kSlackNs;
                } else if (kind == 1) {
                    report = SupervisedExecutor::Run(
                        limits,
                        [t](uint8_t* o, std::size_t) {
                            o[0] = static_cast<uint8_t>(0x40 + t);
                            return std::size_t{1};
                        },
                        out, sizeof out);
                    ok = report.outcome == Outcome::Completed && report.result_length == 1 && out[0] == 0x40 + t;
                } else {
                    report = SupervisedExecutor::Run(limits, [](uint8_t*, std::size_t) { std::abort(); }, out, sizeof out);
                    ok = report.outcome == Outcome::Crashed && report.signal_number == SIGABRT;
                }
                if (ok) ++correct;
            }
        });
    }
    for (auto& th : threads) th.join();
    REQUIRE(correct.load() == kThreads * kRounds);
    REQUIRE(OpenDescriptorCount() == fds_before);
    REQUIRE(NoChildrenLeft());
}

TEST_CASE("Supervised: a fast payload with a 5 s deadline returns promptly", "[supervised]") {
    Limits limits = DefaultLimits();
    limits.wall_clock_deadline_ns = 5'000 * kMs;
    uint8_t out[64];
    const auto report = SupervisedExecutor::Run(
        limits,
        [](uint8_t* o, std::size_t) {
            timespec nap{0, 1'000'000L};
            (void)::nanosleep(&nap, nullptr);
            o[0] = 'k';
            return std::size_t{1};
        },
        out, sizeof out);
    REQUIRE(report.outcome == Outcome::Completed);
    REQUIRE(out[0] == 'k');
    REQUIRE(report.elapsed_ns < 1'000 * kMs);
    REQUIRE(NoChildrenLeft());
}
