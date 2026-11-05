// The pid-reuse safety property, verified WITHOUT root, by interposition.
//
// Property: after the supervisor's worker has been reaped elsewhere (a SIGCHLD
// handler, a waitpid(-1)) its pid number may belong to a stranger. From that
// point the supervisor must never kill(-pid), kill(pid) or wait on that number
// (it uses the pidfd, or forgets the entry), must not report success, and must
// not hang.
//
// The real-pid simulation (stack_worker_reap_tests [pid-reuse]) needs
// CAP_SYS_ADMIN to hand a number to a stranger. This program needs nothing: it
// wraps the libc entry points the supervisor can reach a process through
// (kill, waitpid, wait4, waitid and the raw syscalls kill, wait4, waitid,
// pidfd_send_signal) in the executable itself and records every call made
// after the kill hook reports "reaped elsewhere". A call that names the pid
// number or its negated group is a violation. A reused number would have been
// hit by exactly such a call, so zero such calls is the property.
//
// Not covered, by design: the waitpid fallback (kernel without pidfd). There
// the supervisor signals and waits by number, as documented in
// stack_supervised_exec.hpp, so the property is not claimed for it.
//
// Usage: pid_reuse_interposed_tests running | tracked. Plain main(): exits
// non-zero on the first failed check.

#include <atomic>
#include <cerrno>
#include <csignal>
#include <cstdarg>
#include <cstdio>
#include <cstdlib>
#include <cstring>

#include <dlfcn.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

#include "../include/stack_supervised_exec.hpp"

#ifndef STACK_WORKER_PATH
#error "STACK_WORKER_PATH must name the shipped worker program"
#endif

namespace {

enum class Call : int { Kill, Wait, WaitidByPid, PidfdSignal, WaitidByPidfd };

struct Record {
    Call call;
    long target;
};

constexpr int kMaxRecords = 512;
std::atomic<bool> g_recording{false};
std::atomic<int> g_n{0};
Record g_records[kMaxRecords];

void Note(Call call, long target) {
    if (!g_recording.load()) return;
    const int i = g_n.fetch_add(1);
    if (i < kMaxRecords) g_records[i] = Record{call, target};
}

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

extern "C" int kill(pid_t pid, int sig) {
    Note(Call::Kill, pid);
    using Fn = int (*)(pid_t, int);
    static Fn real = Next<Fn>("kill");
    return real(pid, sig);
}

extern "C" pid_t waitpid(pid_t pid, int* status, int options) {
    Note(Call::Wait, pid);
    using Fn = pid_t (*)(pid_t, int*, int);
    static Fn real = Next<Fn>("waitpid");
    return real(pid, status, options);
}

extern "C" pid_t wait4(pid_t pid, int* status, int options, struct rusage* ru) {
    Note(Call::Wait, pid);
    using Fn = pid_t (*)(pid_t, int*, int, struct rusage*);
    static Fn real = Next<Fn>("wait4");
    return real(pid, status, options, ru);
}

extern "C" int waitid(idtype_t idtype, id_t id, siginfo_t* info, int options) {
    Note(idtype == P_PIDFD ? Call::WaitidByPidfd : Call::WaitidByPid, static_cast<long>(id));
    using Fn = int (*)(idtype_t, id_t, siginfo_t*, int);
    static Fn real = Next<Fn>("waitid");
    return real(idtype, id, info, options);
}

extern "C" long syscall(long number, ...) {
    va_list ap;
    va_start(ap, number);
    long a[6];
    for (long& v : a) v = va_arg(ap, long);
    va_end(ap);
    if (number == __NR_kill) Note(Call::Kill, a[0]);
    else if (number == __NR_wait4) Note(Call::Wait, a[0]);
    else if (number == __NR_waitid) Note(a[0] == P_PIDFD ? Call::WaitidByPidfd : Call::WaitidByPid, a[1]);
    else if (number == __NR_pidfd_send_signal) Note(Call::PidfdSignal, a[0]);
    using Fn = long (*)(long, long, long, long, long, long, long);
    static Fn real = Next<Fn>("syscall");
    return real(number, a[0], a[1], a[2], a[3], a[4], a[5]);
}

using namespace stack::supervised;

namespace {

constexpr uint64_t kMs = 1'000'000ULL;

bool IneffectiveKill(pid_t, int) { return true; }

std::atomic<pid_t> g_hooked{0};
std::atomic<bool> g_fired{false};

// First kill: the worker is reaped "elsewhere" right now, then recording
// starts and the supervisor's real kill proceeds against a dead, reaped child.
bool ReapElsewhere(pid_t pid, int) {
    if (g_fired.exchange(true)) return false;
    if (pid <= 1) return false;  // never signal "everything" or init
    ::kill(pid, SIGKILL);
    int status = 0;
    CHECK(::waitpid(pid, &status, 0) == pid);
    g_hooked.store(pid);
    g_n.store(0);
    g_recording.store(true);
    return false;
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

bool PidfdAvailable() {
    const long fd = ::syscall(__NR_pidfd_open, ::getpid(), 0);
    if (fd < 0) return false;
    ::close(static_cast<int>(fd));
    return true;
}

// Stops recording and reports every recorded call that names `pid` or its
// negated group. Returns the violation count; pidfd_signals gets the number
// of pidfd_send_signal calls (proof the supervisor went through the pidfd).
int Violations(pid_t pid, int& pidfd_signals) {
    g_recording.store(false);
    const int n = g_n.load() < kMaxRecords ? g_n.load() : kMaxRecords;
    int bad = 0;
    pidfd_signals = 0;
    for (int i = 0; i < n; ++i) {
        const Record& r = g_records[i];
        if (r.call == Call::PidfdSignal) { ++pidfd_signals; continue; }
        if (r.call == Call::WaitidByPidfd) continue;
        if (r.target == pid || r.target == -static_cast<long>(pid)) {
            std::fprintf(stderr, "VIOLATION: call kind %d on target %ld (worker pid %d)\n",
                         static_cast<int>(r.call), r.target, static_cast<int>(pid));
            ++bad;
        }
    }
    std::fprintf(stderr, "recorded %d calls, %d violations, %d pidfd_send_signal\n", n, bad, pidfd_signals);
    return bad;
}

// A run whose worker is reaped elsewhere at the moment the supervisor kills it.
void Running() {
    SupervisedExecutor::SetKillHookForTesting(&ReapElsewhere);
    g_fired.store(false);
    const ExecutionReport r = RunSpinner(QuickLimits(100, 300));
    SupervisedExecutor::SetKillHookForTesting(nullptr);
    int pidfd_signals = 0;
    const int bad = Violations(g_hooked.load(), pidfd_signals);
    CHECK(g_fired.load());
    CHECK(r.child_pid > 0);
    CHECK(r.child_pid == g_hooked.load());                // the hook saw this run's worker
    CHECK(bad == 0);                                      // no kill/wait by number, group or pid
    CHECK(pidfd_signals >= 1);                            // it did try, through the pidfd
    CHECK(r.outcome != Outcome::Completed);
    CHECK(r.outcome != Outcome::TimedOut);                // it could not confirm what happened to ITS child
    CHECK(r.elapsed_ns <= 100 * kMs + 1'000 * kMs);       // bounded, no hang
    CHECK(SupervisedExecutor::UnconfirmedCount() == 0);
}

// A tracked, unconfirmed worker that is reaped elsewhere: forgotten, never
// signaled or waited on by number.
void Tracked() {
    SupervisedExecutor::SetKillHookForTesting(&IneffectiveKill);
    const ExecutionReport stuck = RunSpinner(QuickLimits(50, 50));
    SupervisedExecutor::SetKillHookForTesting(nullptr);
    CHECK(stuck.outcome == Outcome::TerminationUnconfirmed);
    CHECK(SupervisedExecutor::UnconfirmedCount() == 1);
    // Hard guard, not a CHECK: a failed spawn leaves child_pid at -1, and
    // kill(-1, SIGKILL) signals every process this user may signal, while
    // waitpid(-1) waits for any child. Never act on a pid that is not a real worker.
    if (stuck.child_pid <= 1) {
        std::fprintf(stderr, "no worker was spawned (child_pid %d, outcome %d, errno %d): "
                             "refusing to signal or wait on it\n",
                     static_cast<int>(stuck.child_pid), static_cast<int>(stuck.outcome),
                     static_cast<int>(stuck.error_number));
        CHECK(stuck.child_pid > 1);
        return;
    }

    ::kill(stuck.child_pid, SIGKILL);
    CHECK(::waitpid(stuck.child_pid, nullptr, 0) == stuck.child_pid);

    g_n.store(0);
    g_recording.store(true);
    const std::size_t remaining = SupervisedExecutor::ReapUnconfirmed();
    int pidfd_signals = 0;
    const int bad = Violations(stuck.child_pid, pidfd_signals);
    CHECK(bad == 0);
    CHECK(remaining == 0);  // the dead entry was forgotten
    CHECK(SupervisedExecutor::UnconfirmedCount() == 0);
}

}  // namespace

int main(int argc, char** argv) {
    if (argc != 2) {
        std::fprintf(stderr, "usage: %s running|tracked\n", argv[0]);
        return 2;
    }
    if (!PidfdAvailable()) {
        std::fprintf(stderr, "FAILED: pidfd_open is unavailable, the property under test needs a pidfd (Linux 5.3+)\n");
        return 1;
    }
    if (std::strcmp(argv[1], "running") == 0) Running();
    else if (std::strcmp(argv[1], "tracked") == 0) Tracked();
    else {
        std::fprintf(stderr, "unknown case %s\n", argv[1]);
        return 2;
    }
    int status = 0;
    CHECK(::waitpid(-1, &status, WNOHANG) == -1 && errno == ECHILD);  // nothing left behind
    if (g_failures != 0) return 1;
    std::fprintf(stderr, "pid reuse interposition case %s passed\n", argv[1]);
    return 0;
}
