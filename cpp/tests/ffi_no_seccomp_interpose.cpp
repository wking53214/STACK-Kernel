// Link-time interposer for the ThreadSanitizer build of the FFI init
// program only. It turns prctl(PR_SET_SECCOMP, ...) into a no-op and passes
// every other prctl to the kernel, because a thread under the real
// allowlist cannot mmap or munmap and the sanitizer runtime needs both
// (observed in the RACE-02 baseline: "ThreadSanitizer failed to allocate").
//
// The sanitized run therefore checks the synchronization of the wrapper,
// not the seccomp filter; the plain build of the same program, and every
// other test, install the real filter. The program knows it is running
// this way through STACK_FFI_NO_SECCOMP and skips its "thread is filtered"
// checks.
#include <cstdarg>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <unistd.h>

extern "C" int prctl(int option, ...) {
    va_list ap;
    va_start(ap, option);
    const unsigned long a2 = va_arg(ap, unsigned long);
    const unsigned long a3 = va_arg(ap, unsigned long);
    const unsigned long a4 = va_arg(ap, unsigned long);
    const unsigned long a5 = va_arg(ap, unsigned long);
    va_end(ap);
    if (option == PR_SET_SECCOMP) return 0;
    return static_cast<int>(::syscall(SYS_prctl, option, a2, a3, a4, a5));
}
