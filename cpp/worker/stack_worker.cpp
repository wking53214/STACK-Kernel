// stack_worker: the helper program SupervisedExecutor::RunWorker executes.
//
// WHY A SEPARATE PROGRAM (RACE-02, R2-K-08). The fork-of-caller path runs the
// payload in a copy of the caller: the payload can read and return the
// caller's memory and can write a well-formed result frame of its own. This
// program is exec'd instead, so its image holds none of the caller's memory,
// its environment is empty and it has only descriptors 0 to 2 (/dev/null)
// and the result pipe on fd 3.
//
// WHAT IT DOES. main() installs the strict seccomp filter (with NO_NEW_PRIVS)
// as its FIRST action, before it reads argv or anything else, and only then
// runs the built-in kind named by argv[1]. The kinds are a closed set; an
// unknown kind exits 4. Nothing here parses a request, opens a file or
// allocates.
//
// The supervisor does not trust this program to behave: the deadline, the
// rlimits and the exit status are enforced from outside, and the result
// bytes are the worker's own claim (cpp/CONTAINMENT.md).
//
// TEST BUILD. Compiled with -DSTACK_WORKER_TEST_KINDS this program also
// carries kinds that misbehave on purpose (forged frames, self kill, reads
// at a caller-supplied address, every syscall the filter must deny...). They
// exist to prove the supervisor and the filter hold against a hostile worker.
// The shipped worker is built without them.
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>

#include <fcntl.h>
#include <signal.h>
#include <sys/mman.h>
#include <sys/ptrace.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <unistd.h>
#ifdef STACK_WORKER_TEST_KINDS
#include <dirent.h>
#include <time.h>
#endif

#include "../include/stack_supervised_exec.hpp"

using stack::supervised::kWorkerResultFd;
using stack::supervised::SupervisedExecutor;

namespace {

constexpr char kReturnBytesPayload[] = "stack-ffi-payload-v1";

[[noreturn]] void SpinForever() {
    for (;;) {
        asm volatile("" ::: "memory");
    }
}

[[noreturn]] void ExitGroup(int code) {
    for (;;) (void)::syscall(SYS_exit_group, code);
}

#ifdef STACK_WORKER_TEST_KINDS
void RawWrite(const void* p, std::size_t n) {
    if (::write(kWorkerResultFd, p, n) < 0) ExitGroup(127);
}
#endif

void SendFrame(const char* body, std::size_t len) {
    if (!SupervisedExecutor::WriteResultFrame(kWorkerResultFd, reinterpret_cast<const uint8_t*>(body), len)) {
        ExitGroup(127);
    }
}

bool ParseU32(const char* s, uint32_t& out) {
    if (s == nullptr || *s == '\0') return false;
    uint64_t v = 0;
    for (; *s != '\0'; ++s) {
        if (*s < '0' || *s > '9') return false;
        v = v * 10 + static_cast<uint64_t>(*s - '0');
        if (v > 0xFFFFFFFFULL) return false;
    }
    out = static_cast<uint32_t>(v);
    return true;
}

// Built-in kinds. 0 to 6 are the shipped set (stack_ffi::PayloadKind).
enum Kind : uint32_t {
    kReturnBytes = 0,
    kSpin = 1,
    kBlock = 2,
    kCrash = 3,
    kAbort = 4,
    kExitNonZero = 5,
    kForbiddenSyscall = 6,
#ifdef STACK_WORKER_TEST_KINDS
    kForgeThenExit0 = 32,
    kForgeThenSpin = 33,
    kTruncatedFrame = 34,
    kSelfSigkill = 35,
    kExitZeroNoFrame = 36,
    kMalformedFrame = 37,
    kOversizedFrame = 38,
    kTrailingBytes = 39,
    kDelayedResult = 40,
    kReadAddress = 41,
    kSocket = 43,
    kExecve = 44,
    kFork = 45,
    kPtrace = 46,
    kX32Syscall = 49,
    kCpuBound = 50,
    kEnvCount = 51,
    kListFds = 52,
    // D1-C adversarial matrix. 53 to 55 and 57 act BEFORE the filter exists: they model a
    // worker that does not follow the protocol, which the supervisor must not trust.
    kFrameThenExitNonZero = 53,   // case 2: a well-formed frame, then exit 3
    kProbeFds = 54,               // case 8: probes every descriptor it might reach, reports what it found
    kClobberResultFd = 55,        // case 8: replaces its own result descriptor, then "reports" and exits 0
    kCloseResultThenSpin = 56,    // case 6 (filtered): close(3) is not allowed and ends in SIGSYS
    kCloseUnfilteredThenSpin = 57,// case 6 (unfiltered): closes the result pipe early, then spins
    kPartialFrameThenBlock = 58,  // case 9: a header and part of the body, then blocks
    kForgeThenCrash = 59,         // case 12: a well-formed frame claiming success, then SIGSEGV
#endif
};

}  // namespace

int main(int argc, char** argv, char** envp) {
    (void)envp;
#ifdef STACK_WORKER_TEST_KINDS
    // Test instrumentation that must look at the process BEFORE the filter
    // exists (the filter forbids open): which descriptors did the supervisor
    // leave open. Never in the shipped worker.
    if (argc >= 2) {
        uint32_t early = 0;
        if (ParseU32(argv[1], early) && early == kProbeFds) {
            // Which descriptors does a hostile worker hold, and what can it do to them? The
            // supervisor's own descriptors (read end of the pipe, pidfd, image) must not be here.
            char text[256];
            std::size_t n = 0;
            DIR* d = ::opendir("/proc/self/fd");
            if (d == nullptr) ExitGroup(120);
            const int self_dir = ::dirfd(d);
            n += static_cast<std::size_t>(::snprintf(text + n, sizeof text - n, "fds="));
            while (dirent* e = ::readdir(d)) {
                if (e->d_name[0] < '0' || e->d_name[0] > '9') continue;
                const int fd = std::atoi(e->d_name);
                if (fd == self_dir) continue;
                n += static_cast<std::size_t>(::snprintf(text + n, sizeof text - n, "%d,", fd));
            }
            ::closedir(d);
            unsigned open_above = 0, wrote_above = 0, closed_above = 0, dup_above = 0;
            for (int fd = 4; fd < 1024; ++fd) {
                if (::fcntl(fd, F_GETFD) != -1) ++open_above;
                if (::write(fd, "x", 1) >= 0) ++wrote_above;
                if (::fcntl(fd, F_DUPFD, 4) >= 0) ++dup_above;
                if (::close(fd) == 0) ++closed_above;
            }
            char scratch;
            const bool read_result_end = ::read(kWorkerResultFd, &scratch, 1) >= 0;  // it holds the WRITE end only
            n += static_cast<std::size_t>(::snprintf(text + n, sizeof text - n, ";above3=%u,%u,%u,%u;read3=%d", open_above,
                                                     wrote_above, dup_above, closed_above, read_result_end ? 1 : 0));
            if (!SupervisedExecutor::InstallWorkerFilter(kWorkerResultFd)) ExitGroup(124);
            SendFrame(text, n);
            ExitGroup(0);
        }
        if (ParseU32(argv[1], early) && early == kClobberResultFd) {
            // Replace the result descriptor with /dev/null, then behave as if all were well.
            const int devnull = ::open("/dev/null", O_RDWR);
            if (devnull < 0 || ::dup2(devnull, kWorkerResultFd) != kWorkerResultFd) ExitGroup(120);
            SendFrame("I-REPORT-SUCCESS", 16);
            ExitGroup(0);
        }
        if (ParseU32(argv[1], early) && early == kCloseUnfilteredThenSpin) {
            (void)::close(kWorkerResultFd);
            SpinForever();
        }
        if (ParseU32(argv[1], early) && early == kListFds) {
            char text[512];
            std::size_t n = 0;
            DIR* d = ::opendir("/proc/self/fd");
            if (d == nullptr) ExitGroup(120);
            const int self_dir = ::dirfd(d);
            while (dirent* e = ::readdir(d)) {
                if (e->d_name[0] < '0' || e->d_name[0] > '9') continue;
                const int fd = std::atoi(e->d_name);
                if (fd == self_dir) continue;
                n += static_cast<std::size_t>(::snprintf(text + n, sizeof text - n, "%d,", fd));
            }
            ::closedir(d);
            if (!SupervisedExecutor::InstallWorkerFilter(kWorkerResultFd)) ExitGroup(124);
            SendFrame(text, n);
            ExitGroup(0);
        }
    }
#endif
    // FIRST ACTION: the filter, before argv is read.
    if (!SupervisedExecutor::InstallWorkerFilter(kWorkerResultFd)) ExitGroup(124);

    uint32_t kind = 0;
    if (argc < 2 || !ParseU32(argv[1], kind)) ExitGroup(4);

    switch (kind) {
    case kReturnBytes:
        SendFrame(kReturnBytesPayload, sizeof(kReturnBytesPayload) - 1);
        ExitGroup(0);
    case kSpin:
        SpinForever();
    case kBlock: {
        static uint32_t never_woken = 0;
        for (;;) {
            (void)::syscall(SYS_futex, &never_woken, 128 /* FUTEX_WAIT_PRIVATE */, 0, nullptr, nullptr, 0);
        }
    }
    case kCrash:
        *static_cast<volatile int*>(nullptr) = 1;
        ExitGroup(0);
    case kAbort:
        std::abort();
    case kExitNonZero:
        ExitGroup(3);
    case kForbiddenSyscall:
        (void)::open("/etc/hostname", O_RDONLY);
        SpinForever();
#ifdef STACK_WORKER_TEST_KINDS
    case kForgeThenExit0:
        SendFrame("FORGED-OK", 9);
        ExitGroup(0);
    case kForgeThenSpin:
        SendFrame("FORGED-OK", 9);
        SpinForever();
    case kTruncatedFrame: {
        // A valid header announcing 16 bytes, then 4 of them, then a clean exit.
        const uint8_t head[12] = {'S', 'T', 'K', 'R', 16, 0, 0, 0, 'a', 'b', 'c', 'd'};
        RawWrite(head, sizeof head);
        ExitGroup(0);
    }
    case kSelfSigkill:
        (void)::syscall(SYS_tgkill, ::getpid(), ::syscall(SYS_gettid), SIGKILL);
        SpinForever();
    case kExitZeroNoFrame:
        ExitGroup(0);
    case kMalformedFrame: {
        const char junk[16] = {'X', 'X', 'X', 'X', 'X', 'X', 'X', 'X', 'X', 'X', 'X', 'X', 'X', 'X', 'X', 'X'};
        RawWrite(junk, sizeof junk);
        ExitGroup(0);
    }
    case kOversizedFrame: {
        // Magic "STKR" and a length far above any cap.
        const uint8_t head[8] = {'S', 'T', 'K', 'R', 0xFF, 0xFF, 0xFF, 0x00};
        RawWrite(head, sizeof head);
        ExitGroup(0);
    }
    case kTrailingBytes:
        SendFrame("FIRST", 5);
        SendFrame("SECOND", 6);
        ExitGroup(0);
    case kDelayedResult: {
        timespec ts{0, 600'000'000};
        (void)::nanosleep(&ts, nullptr);
        SendFrame("LATE", 4);
        ExitGroup(0);
    }
    case kReadAddress: {
        // argv[2] is a hexadecimal address in the CALLER's address space.
        // In this image it is not mapped, so the read faults.
        if (argc < 3) ExitGroup(5);
        uint64_t addr = 0;
        for (const char* c = argv[2]; *c != '\0'; ++c) {
            const char ch = *c;
            const uint64_t digit = (ch >= '0' && ch <= '9') ? static_cast<uint64_t>(ch - '0')
                                 : (ch >= 'a' && ch <= 'f') ? static_cast<uint64_t>(ch - 'a' + 10)
                                                            : 0;
            addr = (addr << 4) | digit;
        }
        char copy[32];
        const volatile char* src = reinterpret_cast<const volatile char*>(addr);
        for (std::size_t i = 0; i < sizeof copy; ++i) copy[i] = src[i];
        SendFrame(copy, sizeof copy);
        ExitGroup(0);
    }
    case kSocket:
        (void)::socket(AF_INET, SOCK_STREAM, 0);
        SpinForever();
    case kExecve: {
        char* const av[] = {const_cast<char*>("/bin/true"), nullptr};
        (void)::execve("/bin/true", av, nullptr);
        SpinForever();
    }
    case kFork:
        (void)::fork();
        SpinForever();
    case kPtrace:
        (void)::ptrace(PTRACE_TRACEME, 0, nullptr, nullptr);
        SpinForever();
    case kX32Syscall:
#if defined(__x86_64__)
        {
            // getpid through the x32 ABI: syscall number with bit 30 set.
            long r = 0;
            asm volatile("syscall" : "=a"(r) : "a"(static_cast<long>(__NR_getpid) | 0x40000000L) : "rcx", "r11", "memory");
            (void)r;
        }
        SpinForever();
#else
        ExitGroup(77);
#endif
    case kCpuBound: {
        volatile uint64_t x = 1;
        for (;;) x = x * 6364136223846793005ULL + 1442695040888963407ULL;
    }
    case kFrameThenExitNonZero:
        SendFrame("FORGED-OK", 9);
        ExitGroup(3);
    case kCloseResultThenSpin:
        (void)::close(kWorkerResultFd);
        SpinForever();
    case kPartialFrameThenBlock: {
        // Header announcing 16 bytes, 4 of them, then no more: a hang during result delivery.
        const uint8_t head[12] = {'S', 'T', 'K', 'R', 16, 0, 0, 0, 'a', 'b', 'c', 'd'};
        RawWrite(head, sizeof head);
        SpinForever();
    }
    case kForgeThenCrash:
        SendFrame("FORGED-OK", 9);
        *static_cast<volatile int*>(nullptr) = 1;
        ExitGroup(0);
    case kEnvCount: {
        std::size_t n = 0;
        while (envp != nullptr && envp[n] != nullptr) ++n;
        char text[24];
        std::size_t len = 0;
        text[len++] = 'e';
        text[len++] = 'n';
        text[len++] = 'v';
        text[len++] = '=';
        text[len++] = static_cast<char>('0' + (n % 10));
        SendFrame(text, len);
        ExitGroup(0);
    }
#endif
    default:
        ExitGroup(4);
    }
}
