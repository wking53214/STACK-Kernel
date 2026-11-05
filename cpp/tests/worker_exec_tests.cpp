// Tests for SupervisedExecutor::RunWorker (RACE-02 decision A): the payload
// runs in a separate PROGRAM (cpp/worker/stack_worker.cpp) that the
// supervisor fork+execs, not in a fork of the caller.
//
// Every hostile case runs in a worker process under a deadline and rlimits,
// and the whole binary runs under ctest's TIMEOUT. The worker programs are
// built beside this test: STACK_WORKER_PATH is the shipped worker (kinds 0
// to 6) and STACK_WORKER_TEST_PATH the test build, which adds kinds that
// misbehave on purpose.
//
// Timing assertions use a stated slack over the deadline; the measured
// values are printed so the bound can be read off a run.

#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <csignal>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>

#include <dirent.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#include "../include/stack_supervised_exec.hpp"

using namespace stack::supervised;

#ifndef STACK_WORKER_PATH
#error "STACK_WORKER_PATH must name the shipped worker program"
#endif
#ifndef STACK_WORKER_TEST_PATH
#error "STACK_WORKER_TEST_PATH must name the test worker program"
#endif

namespace {

constexpr uint64_t kMs = 1'000'000ULL;
constexpr uint64_t kDeadlineNs = 300 * kMs;
// Slack over the deadline for a killed worker: kill + reap + scheduling.
constexpr uint64_t kSlackNs = 1'000 * kMs;

// Worker kinds (cpp/worker/stack_worker.cpp).
enum : uint32_t {
    kReturnBytes = 0, kSpin = 1, kBlock = 2, kCrash = 3, kAbort = 4, kExitNonZero = 5, kForbiddenOpen = 6,
    kForgeThenExit0 = 32, kForgeThenSpin = 33, kTruncatedFrame = 34, kSelfSigkill = 35, kExitZeroNoFrame = 36,
    kMalformedFrame = 37, kOversizedFrame = 38, kTrailingBytes = 39, kDelayedResult = 40, kReadAddress = 41,
    kSocket = 43, kExecve = 44, kFork = 45, kPtrace = 46, kX32Syscall = 49, kCpuBound = 50, kEnvCount = 51,
    kListFds = 52,
};

Limits DefaultLimits() {
    Limits l;
    l.wall_clock_deadline_ns = kDeadlineNs;
    l.max_output_bytes = 256;
    return l;
}

struct Run {
    ExecutionReport report;
    uint8_t out[256];
    std::string Text() const {
        return std::string(reinterpret_cast<const char*>(out), report.outcome == Outcome::Completed ? report.result_length : 0);
    }
};

Run RunKind(const char* path, uint32_t kind, const Limits& limits, const char* argument = nullptr) {
    Run r;
    std::memset(r.out, 0, sizeof r.out);
    WorkerSpec spec;
    spec.executable = path;
    spec.kind = kind;
    spec.argument = argument;
    r.report = SupervisedExecutor::RunWorker(limits, spec, r.out, sizeof r.out);
    return r;
}

Run Shipped(uint32_t kind, const Limits& limits = DefaultLimits()) { return RunKind(STACK_WORKER_PATH, kind, limits); }
Run Hostile(uint32_t kind, const Limits& limits = DefaultLimits(), const char* argument = nullptr) {
    return RunKind(STACK_WORKER_TEST_PATH, kind, limits, argument);
}

void Measured(const char* what, const ExecutionReport& r) {
    std::fprintf(stderr, "[measured] %-44s elapsed %7.1f ms (deadline %llu ms)\n", what,
                 static_cast<double>(r.elapsed_ns) / 1e6, static_cast<unsigned long long>(kDeadlineNs / kMs));
}

bool NoChildrenLeft() {
    int status = 0;
    const pid_t w = ::waitpid(-1, &status, WNOHANG);
    const int saved = errno;
    return w == -1 && saved == ECHILD;
}

std::size_t OpenDescriptorCount() {
    DIR* d = ::opendir("/proc/self/fd");
    REQUIRE(d != nullptr);
    std::size_t n = 0;
    while (::readdir(d) != nullptr) ++n;
    ::closedir(d);
    return n - 1;
}

pid_t FindChildOf(pid_t parent) {
    DIR* d = ::opendir("/proc");
    if (d == nullptr) return -1;
    pid_t found = -1;
    while (dirent* e = ::readdir(d)) {
        if (e->d_name[0] < '0' || e->d_name[0] > '9') continue;
        char path[300];
        std::snprintf(path, sizeof path, "/proc/%s/stat", e->d_name);
        FILE* f = std::fopen(path, "r");
        if (f == nullptr) continue;
        char line[512] = {};
        const bool got = std::fgets(line, sizeof line, f) != nullptr;
        std::fclose(f);
        if (!got) continue;
        const char* rp = std::strrchr(line, ')');
        int ppid = 0;
        char state = 0;
        if (rp != nullptr && std::sscanf(rp + 2, "%c %d", &state, &ppid) == 2 && ppid == parent) {
            found = static_cast<pid_t>(std::atoi(e->d_name));
            break;
        }
    }
    ::closedir(d);
    return found;
}

// Not static, not const: the worker is asked to read this by address.
char g_caller_secret[] = "CALLER-SECRET-KEY-0123456789";

}  // namespace

TEST_CASE("Worker: the shipped worker returns its bytes and is Completed", "[worker]") {
    const Run r = Shipped(kReturnBytes);
    REQUIRE(r.report.outcome == Outcome::Completed);
    REQUIRE(r.report.exit_code == 0);
    REQUIRE(r.Text() == "stack-ffi-payload-v1");
    REQUIRE(r.report.child_pid > 0);
    REQUIRE(r.report.child_pid != ::getpid());
    REQUIRE_FALSE(r.report.deadline_fired);
    REQUIRE(NoChildrenLeft());
}

TEST_CASE("Worker: an infinite loop, a CPU-bound loop and a blocked syscall are killed at the deadline", "[worker]") {
    struct Case { const char* name; const char* path; uint32_t kind; };
    const Case cases[] = {
        {"empty infinite loop", STACK_WORKER_PATH, kSpin},
        {"CPU-bound loop", STACK_WORKER_TEST_PATH, kCpuBound},
        {"futex wait that is never woken", STACK_WORKER_PATH, kBlock},
    };
    for (const Case& c : cases) {
        const Run r = RunKind(c.path, c.kind, DefaultLimits());
        Measured(c.name, r.report);
        INFO(c.name);
        REQUIRE(r.report.outcome == Outcome::TimedOut);
        REQUIRE(r.report.deadline_fired);
        REQUIRE(r.report.elapsed_ns >= kDeadlineNs);
        REQUIRE(r.report.elapsed_ns <= kDeadlineNs + kSlackNs);
        REQUIRE(r.report.result_length == 0);
        REQUIRE(NoChildrenLeft());
    }
}

TEST_CASE("Worker: crash, abort, non-zero exit and a forbidden syscall are distinct and never Completed", "[worker]") {
    const Run segv = Shipped(kCrash);
    REQUIRE(segv.report.outcome == Outcome::Crashed);
    REQUIRE(segv.report.signal_number == SIGSEGV);
    const Run abrt = Shipped(kAbort);
    REQUIRE(abrt.report.outcome == Outcome::Crashed);
    REQUIRE(abrt.report.signal_number == SIGABRT);
    const Run nz = Shipped(kExitNonZero);
    REQUIRE(nz.report.outcome == Outcome::ExitedNonZero);
    REQUIRE(nz.report.exit_code == 3);
    const Run forbidden = Shipped(kForbiddenOpen);
    REQUIRE(forbidden.report.outcome == Outcome::SeccompViolation);
    REQUIRE(forbidden.report.signal_number == SIGSYS);
    REQUIRE_FALSE(forbidden.report.deadline_fired);
    REQUIRE(NoChildrenLeft());
}

TEST_CASE("Worker: an unknown kind exits non-zero", "[worker]") {
    const Run r = Shipped(31337);
    REQUIRE(r.report.outcome == Outcome::ExitedNonZero);
    REQUIRE(r.report.exit_code == 4);
}

TEST_CASE("Worker: network, exec, fork, ptrace, open and the x32 ABI are denied inside the helper", "[worker]") {
    struct Case { const char* name; uint32_t kind; };
    const Case cases[] = {
        {"socket", kSocket}, {"execve", kExecve}, {"fork", kFork},
        {"ptrace", kPtrace}, {"open", kForbiddenOpen},
#if defined(__x86_64__)
        {"x32 syscall bit", kX32Syscall},
#endif
    };
    for (const Case& c : cases) {
        const Run r = Hostile(c.kind);
        INFO(c.name);
        REQUIRE(r.report.outcome == Outcome::SeccompViolation);
        REQUIRE(r.report.signal_number == SIGSYS);
        REQUIRE_FALSE(r.report.deadline_fired);
    }
    REQUIRE(NoChildrenLeft());
}

// P2 (baseline probe): a payload writes its own well-formed frame and then
// exits. On the fork-of-caller path that is Completed with the forged bytes.
// The worker path cannot make that go away (a worker always writes its own
// frame): what it must do is keep the forged bytes the worker's own claim,
// keep a forgery from turning a timeout into success, and keep the caller's
// memory out of reach (next case).
TEST_CASE("Worker: a forged frame then a spin is TimedOut, never Completed", "[worker][forge]") {
    const Run r = Hostile(kForgeThenSpin);
    Measured("forged frame then spin", r.report);
    REQUIRE(r.report.outcome == Outcome::TimedOut);
    REQUIRE(r.report.deadline_fired);
    REQUIRE(r.report.result_length == 0);
    REQUIRE(NoChildrenLeft());
}

TEST_CASE("Worker: a frame that arrives after the deadline is ignored", "[worker][forge]") {
    Limits l = DefaultLimits();
    l.wall_clock_deadline_ns = 200 * kMs;  // the worker sleeps 600 ms, then sends a valid frame and exits 0
    const Run r = Hostile(kDelayedResult, l);
    REQUIRE(r.report.outcome == Outcome::TimedOut);
    REQUIRE(r.report.result_length == 0);
    REQUIRE(r.report.elapsed_ns < 600 * kMs);
    REQUIRE(NoChildrenLeft());
}

TEST_CASE("Worker: frames that are not clean are not Completed", "[worker][forge]") {
    SECTION("exit 0 with no frame") {
        REQUIRE(Hostile(kExitZeroNoFrame).report.outcome == Outcome::ResultMissing);
    }
    SECTION("bad magic and junk") {
        REQUIRE(Hostile(kMalformedFrame).report.outcome == Outcome::ResultMissing);
    }
    SECTION("a frame cut short") {
        REQUIRE(Hostile(kTruncatedFrame).report.outcome == Outcome::ResultMissing);
    }
    SECTION("a frame announcing far more than the cap") {
        REQUIRE(Hostile(kOversizedFrame).report.outcome == Outcome::ResultOversized);
    }
    SECTION("a valid frame followed by another") {
        const Run r = Hostile(kTrailingBytes);
        REQUIRE(r.report.outcome == Outcome::ResultMissing);
        REQUIRE(r.report.result_length == 0);
    }
    SECTION("the worker kills itself with SIGKILL") {
        const Run r = Hostile(kSelfSigkill);
        REQUIRE(r.report.outcome == Outcome::Crashed);
        REQUIRE(r.report.signal_number == SIGKILL);
    }
    REQUIRE(NoChildrenLeft());
}

// P12 (baseline probe): the payload returns the caller's memory. On the
// fork-of-caller path the secret comes back; the control case shows the
// probe works. In a worker program the address is not mapped.
TEST_CASE("Worker: the caller's memory is not in the worker", "[worker][memory]") {
    SECTION("control: the fork-of-caller path does expose it (why decision A exists)") {
        uint8_t out[64] = {};
        Limits l = DefaultLimits();
        l.max_output_bytes = sizeof out;
        const char* secret = g_caller_secret;
        const auto report = SupervisedExecutor::Run(
            l,
            [secret](uint8_t* o, std::size_t cap) {
                std::size_t n = std::strlen(secret);
                if (n > cap) n = cap;
                std::memcpy(o, secret, n);
                return n;
            },
            out, sizeof out);
        REQUIRE(report.outcome == Outcome::Completed);
        REQUIRE(std::string(reinterpret_cast<const char*>(out), report.result_length) == g_caller_secret);
    }
    SECTION("the worker reading that address by number faults and returns nothing") {
        char addr[32];
        std::snprintf(addr, sizeof addr, "%lx", reinterpret_cast<unsigned long>(&g_caller_secret[0]));
        const Run r = Hostile(kReadAddress, DefaultLimits(), addr);
        REQUIRE(r.report.outcome == Outcome::Crashed);
        REQUIRE(r.report.signal_number == SIGSEGV);
        REQUIRE(r.report.result_length == 0);
        const std::string all(reinterpret_cast<const char*>(r.out), sizeof r.out);
        REQUIRE(all.find("CALLER-SECRET") == std::string::npos);
    }
    SECTION("a heap secret too") {
        char* heap_secret = static_cast<char*>(std::malloc(64));
        std::strcpy(heap_secret, "HEAP-SECRET-KEY-0123456789");
        char addr[32];
        std::snprintf(addr, sizeof addr, "%lx", reinterpret_cast<unsigned long>(heap_secret));
        const Run r = Hostile(kReadAddress, DefaultLimits(), addr);
        std::free(heap_secret);
        REQUIRE(r.report.outcome == Outcome::Crashed);
        const std::string all(reinterpret_cast<const char*>(r.out), sizeof r.out);
        REQUIRE(all.find("HEAP-SECRET") == std::string::npos);
    }
    REQUIRE(NoChildrenLeft());
}

TEST_CASE("Worker: the environment is empty", "[worker][env]") {
    REQUIRE(::setenv("STACK_TEST_SECRET", "do-not-leak", 1) == 0);
    REQUIRE(::setenv("LD_PRELOAD", "/nonexistent.so", 1) == 0);
    const Run r = Hostile(kEnvCount);
    ::unsetenv("STACK_TEST_SECRET");
    ::unsetenv("LD_PRELOAD");
    REQUIRE(r.report.outcome == Outcome::Completed);
    REQUIRE(r.Text() == "env=0");
}

TEST_CASE("Worker: only descriptors 0, 1, 2 and the result pipe are inherited", "[worker][fd]") {
    // Leak descriptors on purpose: an inheritable file, an inheritable
    // duplicate placed high, and a close-on-exec one.
    const int leak_a = ::open("/etc/hostname", O_RDONLY);
    REQUIRE(leak_a >= 0);
    const int leak_b = ::fcntl(leak_a, F_DUPFD, 100);
    REQUIRE(leak_b >= 100);
    const int leak_c = ::open("/etc/hostname", O_RDONLY | O_CLOEXEC);
    REQUIRE(leak_c >= 0);
    const Run r = Hostile(kListFds);
    ::close(leak_a);
    ::close(leak_b);
    ::close(leak_c);
    REQUIRE(r.report.outcome == Outcome::Completed);
    REQUIRE(r.Text() == "0,1,2,3,");
}

TEST_CASE("Worker: the worker image is checked before anything is forked", "[worker][path]") {
    Limits l = DefaultLimits();
    SECTION("a null and a relative path") {
        WorkerSpec spec;
        uint8_t out[16];
        l.max_output_bytes = sizeof out;
        auto r = SupervisedExecutor::RunWorker(l, spec, out, sizeof out);
        REQUIRE(r.outcome == Outcome::SpawnFailed);
        REQUIRE(r.child_pid == 0);
        spec.executable = "stack_worker";
        r = SupervisedExecutor::RunWorker(l, spec, out, sizeof out);
        REQUIRE(r.outcome == Outcome::SpawnFailed);
        REQUIRE(r.error_number == EINVAL);
        REQUIRE(r.child_pid == 0);
    }
    SECTION("a missing file, a directory and a file that is not executable") {
        uint8_t out[16];
        l.max_output_bytes = sizeof out;
        for (const char* path : {"/nonexistent/stack_worker", "/tmp", "/etc/hostname"}) {
            WorkerSpec spec;
            spec.executable = path;
            const auto r = SupervisedExecutor::RunWorker(l, spec, out, sizeof out);
            INFO(path);
            REQUIRE(r.outcome == Outcome::SpawnFailed);
            REQUIRE(r.child_pid == 0);
        }
    }
    SECTION("a world-writable executable is refused") {
        char tmpl[] = "/tmp/stack_worker_ww_XXXXXX";
        const int fd = ::mkstemp(tmpl);
        REQUIRE(fd >= 0);
        ::close(fd);
        REQUIRE(::chmod(tmpl, 0777) == 0);
        uint8_t out[16];
        l.max_output_bytes = sizeof out;
        WorkerSpec spec;
        spec.executable = tmpl;
        const auto r = SupervisedExecutor::RunWorker(l, spec, out, sizeof out);
        ::unlink(tmpl);
        REQUIRE(r.outcome == Outcome::SpawnFailed);
        REQUIRE(r.error_number == EACCES);
        REQUIRE(r.child_pid == 0);
    }
    SECTION("an executable that is not a program ends in SpawnFailed from the child") {
        char tmpl[] = "/tmp/stack_worker_junk_XXXXXX";
        const int fd = ::mkstemp(tmpl);
        REQUIRE(fd >= 0);
        REQUIRE(::write(fd, "not an elf", 10) == 10);
        ::close(fd);
        REQUIRE(::chmod(tmpl, 0755) == 0);
        uint8_t out[16];
        l.max_output_bytes = sizeof out;
        WorkerSpec spec;
        spec.executable = tmpl;
        const auto r = SupervisedExecutor::RunWorker(l, spec, out, sizeof out);
        ::unlink(tmpl);
        REQUIRE(r.outcome == Outcome::SpawnFailed);
        REQUIRE(r.exit_code == 128);
    }
    SECTION("a limit the worker path does not support") {
        uint8_t out[16];
        l.max_output_bytes = sizeof out;
        l.inherit_fd = 5;
        WorkerSpec spec;
        spec.executable = STACK_WORKER_PATH;
        REQUIRE(SupervisedExecutor::RunWorker(l, spec, out, sizeof out).outcome == Outcome::InvalidLimits);
    }
    REQUIRE(NoChildrenLeft());
}

TEST_CASE("Worker: SIGCHLD ignored is refused before anything is spawned", "[worker][sigchld]") {
    const pid_t pid = ::fork();
    REQUIRE(pid >= 0);
    if (pid == 0) {
        ::signal(SIGCHLD, SIG_IGN);
        const Run r = Shipped(kReturnBytes);
        ::_exit(r.report.outcome == Outcome::SigchldIgnored && r.report.child_pid == 0 ? 0 : 1);
    }
    int status = 0;
    REQUIRE(::waitpid(pid, &status, 0) == pid);
    REQUIRE(WIFEXITED(status));
    REQUIRE(WEXITSTATUS(status) == 0);
}

TEST_CASE("Worker: the worker dies when its supervisor is killed", "[worker][pdeathsig]") {
    int announce[2];
    REQUIRE(::pipe(announce) == 0);
    const pid_t supervisor = ::fork();
    REQUIRE(supervisor >= 0);
    if (supervisor == 0) {
        ::close(announce[0]);
        Limits l = DefaultLimits();
        l.wall_clock_deadline_ns = 60'000 * kMs;
        // The supervisor tells the test it is about to run; the test then
        // finds the worker as its child.
        char b = 'x';
        if (::write(announce[1], &b, 1) != 1) ::_exit(2);
        (void)Shipped(kSpin, l);
        ::_exit(0);
    }
    ::close(announce[1]);
    char b = 0;
    REQUIRE(::read(announce[0], &b, 1) == 1);
    ::close(announce[0]);

    pid_t worker = -1;
    for (int i = 0; i < 400 && worker < 0; ++i) {
        worker = FindChildOf(supervisor);
        if (worker < 0) ::usleep(5'000);
    }
    REQUIRE(worker > 0);

    REQUIRE(::kill(supervisor, SIGKILL) == 0);
    int status = 0;
    REQUIRE(::waitpid(supervisor, &status, 0) == supervisor);

    // The worker is gone (or a zombie awaiting init) within a bound.
    bool gone = false;
    for (int i = 0; i < 400 && !gone; ++i) {
        char path[64];
        std::snprintf(path, sizeof path, "/proc/%d/stat", worker);
        FILE* f = std::fopen(path, "r");
        if (f == nullptr) {
            gone = true;
        } else {
            char line[512] = {};
            const bool got = std::fgets(line, sizeof line, f) != nullptr;
            std::fclose(f);
            const char* rp = got ? std::strrchr(line, ')') : nullptr;
            gone = rp == nullptr || rp[2] == 'Z' || rp[2] == 'X';
        }
        if (!gone) ::usleep(5'000);
    }
    REQUIRE(gone);
}

TEST_CASE("Worker: repeated timeouts leave no zombies and no leaked descriptors", "[worker][leak]") {
    const std::size_t before = OpenDescriptorCount();
    Limits l = DefaultLimits();
    l.wall_clock_deadline_ns = 40 * kMs;
    uint64_t worst = 0;
    for (int i = 0; i < 50; ++i) {
        const Run r = Shipped(i % 2 == 0 ? kSpin : kBlock, l);
        REQUIRE(r.report.outcome == Outcome::TimedOut);
        worst = std::max(worst, r.report.elapsed_ns);
    }
    std::fprintf(stderr, "[measured] 50 timeouts at 40 ms: worst elapsed %.1f ms\n", static_cast<double>(worst) / 1e6);
    REQUIRE(worst <= 40 * kMs + kSlackNs);
    REQUIRE(NoChildrenLeft());
    REQUIRE(OpenDescriptorCount() == before);
}

// R2-K-19 (found while testing the worker path): the fork-of-caller child
// closed the descriptors BELOW the highest one it keeps but never the ones
// above it, because CloseRange(lo, ~0) compared a signed -1 with `first` and
// returned at once. A caller descriptor above the result pipe stayed open in
// the payload's process. (The filter stops the payload using it, but it is
// still an open descriptor that was meant to be closed.)
TEST_CASE("Supervised: the fork-of-caller child holds no caller descriptor above the result pipe", "[supervised][fd]") {
    const int leak_a = ::open("/etc/hostname", O_RDONLY);
    REQUIRE(leak_a >= 0);
    const int leak_b = ::fcntl(leak_a, F_DUPFD, 100);
    REQUIRE(leak_b >= 100);
    int announce[2];
    REQUIRE(::pipe(announce) == 0);
    const pid_t supervisor = ::fork();
    REQUIRE(supervisor >= 0);
    if (supervisor == 0) {
        ::close(announce[0]);
        Limits l = DefaultLimits();
        l.wall_clock_deadline_ns = 3'000 * kMs;
        l.max_output_bytes = 0;
        char b = 'x';
        if (::write(announce[1], &b, 1) != 1) ::_exit(2);
        uint8_t out[8];
        (void)SupervisedExecutor::Run(l, [](uint8_t*, std::size_t) { for (;;) asm volatile("" ::: "memory"); }, out, 0);
        ::_exit(0);
    }
    ::close(announce[1]);
    char b = 0;
    REQUIRE(::read(announce[0], &b, 1) == 1);
    ::close(announce[0]);
    pid_t child = -1;
    for (int i = 0; i < 400 && child < 0; ++i) {
        child = FindChildOf(supervisor);
        if (child < 0) ::usleep(5'000);
    }
    REQUIRE(child > 0);
    // Give the child time to finish its descriptor clean-up before looking.
    ::usleep(200'000);
    bool has_100 = false;
    char dir[64];
    std::snprintf(dir, sizeof dir, "/proc/%d/fd", child);
    if (DIR* d = ::opendir(dir)) {
        while (dirent* e = ::readdir(d)) {
            if (std::atoi(e->d_name) >= 100) has_100 = true;
        }
        ::closedir(d);
    }
    ::kill(supervisor, SIGKILL);
    int status = 0;
    (void)::waitpid(supervisor, &status, 0);
    ::close(leak_a);
    ::close(leak_b);
    REQUIRE_FALSE(has_100);
}

// Decision A, result semantics: Completed means "exited 0 within the deadline
// AND sent a well-formed frame". The bytes are the worker's own claim and the
// report says so.
TEST_CASE("Worker: a forged frame then exit_group(0) is Completed but flagged self-reported, with no caller memory", "[worker][forge][semantics]") {
    const Run r = Hostile(kForgeThenExit0);
    REQUIRE(r.report.outcome == Outcome::Completed);
    REQUIRE(r.report.exit_code == 0);
    REQUIRE(r.report.result_self_reported);
    REQUIRE(r.Text() == "FORGED-OK");
    // The forgery is whatever the worker chose to write: it holds nothing of
    // the caller's.
    REQUIRE(r.Text().find("CALLER-SECRET") == std::string::npos);
    const std::string all(reinterpret_cast<const char*>(r.out), sizeof r.out);
    REQUIRE(all.find("CALLER-SECRET") == std::string::npos);
}

TEST_CASE("Worker: a result is self-reported when delivered and never otherwise", "[worker][semantics]") {
    REQUIRE(Shipped(kReturnBytes).report.result_self_reported);
    uint8_t out[64] = {};
    Limits l = DefaultLimits();
    l.max_output_bytes = sizeof out;
    const auto legacy = SupervisedExecutor::Run(l, [](uint8_t* o, std::size_t) { o[0] = 'x'; return std::size_t{1}; }, out, sizeof out);
    REQUIRE(legacy.outcome == Outcome::Completed);
    REQUIRE(legacy.result_self_reported);

    for (const uint32_t kind : {kSpin, kCrash, kExitNonZero, kForbiddenOpen}) {
        const Run r = Shipped(kind);
        INFO(kind);
        REQUIRE(r.report.outcome != Outcome::Completed);
        REQUIRE_FALSE(r.report.result_self_reported);
    }
    for (const uint32_t kind : {kForgeThenSpin, kExitZeroNoFrame, kMalformedFrame, kTruncatedFrame, kOversizedFrame, kTrailingBytes,
                                kSelfSigkill, kDelayedResult}) {
        const Run r = Hostile(kind);
        INFO(kind);
        REQUIRE(r.report.outcome != Outcome::Completed);
        REQUIRE_FALSE(r.report.result_self_reported);
    }
}

TEST_CASE("Worker: bytes of a run that did not complete are not left in the caller's buffer", "[worker][semantics]") {
    // kTrailingBytes and kForgeThenSpin both put a whole valid frame into the
    // buffer before the run is judged not Completed.
    struct Case { uint32_t kind; std::size_t written; };  // bytes the frame parser put in the buffer
    for (const Case c : {Case{kTrailingBytes, 5}, Case{kForgeThenSpin, 9}}) {
        const uint32_t kind = c.kind;
        Run r;
        std::memset(r.out, 0xAB, sizeof r.out);
        WorkerSpec spec;
        spec.executable = STACK_WORKER_TEST_PATH;
        spec.kind = kind;
        r.report = SupervisedExecutor::RunWorker(DefaultLimits(), spec, r.out, sizeof r.out);
        REQUIRE(r.report.outcome != Outcome::Completed);
        for (std::size_t i = 0; i < c.written; ++i) {
            INFO("kind " << kind << " byte " << i);
            REQUIRE(r.out[i] == 0);
        }
        REQUIRE(r.out[c.written] == 0xAB);  // only what the parser had written is cleared
    }
}
