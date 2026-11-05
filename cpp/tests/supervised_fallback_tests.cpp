// P2 finding 7: on the waitpid fallback path (no pidfd) the supervisor reaps
// the child inside its polling loop. If the deadline has passed by the time
// that exit is seen, the old code still called kill(-pid) and kill(pid) on
// the reaped, possibly reused, pid.
//
// This program forces the fallback and a late observation deterministically
// by interposing three libc entry points in the executable itself:
//   syscall   makes pidfd_open fail with ENOSYS when asked to, counts
//             pidfd_send_signal, and forwards everything else;
//   waitpid   after a WNOHANG call that reaped the child, sleeps past the
//             deadline when asked to;
//   kill      records every signal sent, then forwards.
// Plain main(): exits non-zero on the first failed check.

#include <atomic>
#include <cerrno>
#include <csignal>
#include <cstdarg>
#include <cstdio>
#include <cstdlib>
#include <ctime>

#include <dlfcn.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

#include "../include/stack_supervised_exec.hpp"

namespace {

std::atomic<bool> g_no_pidfd{false};
std::atomic<long> g_stall_after_reap_ms{0};
std::atomic<int> g_kill_calls{0};
std::atomic<int> g_kill_calls_positive_pid{0};
std::atomic<int> g_pidfd_signals{0};
std::atomic<pid_t> g_last_child{0};

template <typename Fn>
Fn Next(const char* name) {
    return reinterpret_cast<Fn>(::dlsym(RTLD_NEXT, name));
}

int g_failures = 0;
#define CHECK(cond)                                                                \
    do {                                                                           \
        if (!(cond)) {                                                             \
            std::fprintf(stderr, "FAILED %s:%d: %s\n", __FILE__, __LINE__, #cond); \
            ++g_failures;                                                          \
        }                                                                          \
    } while (0)

}  // namespace

extern "C" long syscall(long number, ...) {
    va_list ap;
    va_start(ap, number);
    long a[6];
    for (long& v : a) v = va_arg(ap, long);
    va_end(ap);
    if (number == __NR_pidfd_open && g_no_pidfd.load()) {
        errno = ENOSYS;
        return -1;
    }
    if (number == __NR_pidfd_send_signal) g_pidfd_signals.fetch_add(1);
    using Fn = long (*)(long, long, long, long, long, long, long);
    static Fn real = Next<Fn>("syscall");
    return real(number, a[0], a[1], a[2], a[3], a[4], a[5]);
}

extern "C" pid_t waitpid(pid_t pid, int* status, int options) {
    using Fn = pid_t (*)(pid_t, int*, int);
    static Fn real = Next<Fn>("waitpid");
    const pid_t r = real(pid, status, options);
    const long stall = g_stall_after_reap_ms.load();
    if (r > 0 && (options & WNOHANG) != 0 && stall > 0) {
        g_stall_after_reap_ms.store(0);
        timespec ts{stall / 1000, (stall % 1000) * 1'000'000L};
        (void)::nanosleep(&ts, nullptr);
    }
    return r;
}

extern "C" int kill(pid_t pid, int sig) {
    g_kill_calls.fetch_add(1);
    if (pid > 0) g_kill_calls_positive_pid.fetch_add(1);
    using Fn = int (*)(pid_t, int);
    static Fn real = Next<Fn>("kill");
    return real(pid, sig);
}

using namespace stack::supervised;

int main() {
    uint8_t out[64];
    Limits limits;
    limits.wall_clock_deadline_ns = 100'000'000ULL;
    limits.max_output_bytes = 64;

    {
        // Fallback path; the child exits at once and is reaped by the
        // WNOHANG poll, then the supervisor is held until the deadline has
        // passed. The strict rule makes the run TimedOut, and nothing may be
        // signaled: the child is already reaped.
        g_no_pidfd.store(true);
        g_stall_after_reap_ms.store(300);
        g_kill_calls.store(0);
        const auto report = SupervisedExecutor::Run(
            limits, [](uint8_t* o, std::size_t) { o[0] = 'k'; return std::size_t{1}; }, out, sizeof out);
        g_no_pidfd.store(false);
        CHECK(report.outcome == Outcome::TimedOut);
        CHECK(report.deadline_fired);
        CHECK(report.child_pid > 0);
        std::fprintf(stderr, "fallback: kill calls after reap = %d\n", g_kill_calls.load());
        CHECK(g_kill_calls.load() == 0);
    }
    {
        // Fallback path, a payload that really overruns: the child is not
        // reaped, so it is killed, by pid and group (no pidfd to use).
        g_no_pidfd.store(true);
        g_kill_calls.store(0);
        const auto report = SupervisedExecutor::Run(
            limits, [](uint8_t*, std::size_t) { for (;;) { asm volatile("" ::: "memory"); } }, out, sizeof out);
        g_no_pidfd.store(false);
        CHECK(report.outcome == Outcome::TimedOut);
        CHECK(g_kill_calls.load() >= 1);
    }
    {
        // With a pidfd the child itself is signaled through it, never by pid.
        int probe = static_cast<int>(::syscall(__NR_pidfd_open, ::getpid(), 0));
        if (probe < 0) {
            std::fprintf(stderr, "pidfd_open unavailable (errno %d): pidfd case not run on this kernel\n", errno);
        } else {
            ::close(probe);
            g_kill_calls_positive_pid.store(0);
            g_pidfd_signals.store(0);
            const auto report = SupervisedExecutor::Run(
                limits, [](uint8_t*, std::size_t) { for (;;) { asm volatile("" ::: "memory"); } }, out, sizeof out);
            CHECK(report.outcome == Outcome::TimedOut);
            std::fprintf(stderr, "pidfd: kill(pid>0) = %d, pidfd_send_signal = %d\n",
                         g_kill_calls_positive_pid.load(), g_pidfd_signals.load());
            CHECK(g_kill_calls_positive_pid.load() == 0);
            CHECK(g_pidfd_signals.load() >= 1);
        }
    }
    int status = 0;
    CHECK(::waitpid(-1, &status, WNOHANG) == -1 && errno == ECHILD);
    if (g_failures != 0) return 1;
    std::fprintf(stderr, "supervised fallback tests passed\n");
    return 0;
}
