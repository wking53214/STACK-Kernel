#pragma once

/**
 * STACK KERNEL: a handle that lets another thread terminate a supervised
 * worker that is in flight (R2-K-24).
 *
 * WHY. A capability revocation must not wait for a worker that may run for
 * an hour. The host (GovernedMinotaurHost) gives every governed supervised
 * run a CancelHandle and, while a capability change is pending, calls
 * Request() on every handle that is registered. The supervisor
 * (SupervisedExecutor::RunWorker) publishes the worker's pidfd in the handle
 * after the fork (Arm) and withdraws it before the pidfd is closed (Disarm).
 *
 * RACES. Request() and Arm() take the same spin lock and each looks at the
 * other's state under it, so a request made before the worker exists is seen
 * by Arm() (which kills at once) and a request made after is seen by
 * Request() (which kills through the armed pidfd). The pidfd is never used
 * after Disarm() returns, so a closed descriptor number cannot be signaled.
 * The kill is pidfd_send_signal(SIGKILL), which names that process and no
 * other.
 *
 * It does not allocate and does not throw.
 */

#include <atomic>
#include <csignal>

#include <sys/syscall.h>
#include <unistd.h>

namespace stack::supervised {

class CancelHandle {
public:
    CancelHandle() noexcept = default;
    CancelHandle(const CancelHandle&) = delete;
    CancelHandle& operator=(const CancelHandle&) = delete;

    /** Asks for the worker to be terminated. Idempotent. Callable from any thread. */
    void Request() noexcept {
        requested_.store(true, std::memory_order_seq_cst);
        Lock();
        if (pidfd_ >= 0) Kill(pidfd_);
        Unlock();
    }

    /** True once Request() has been called. */
    [[nodiscard]] bool Requested() const noexcept { return requested_.load(std::memory_order_seq_cst); }

    /** Supervisor: publishes the worker's pidfd. Kills at once if a request already came. */
    void Arm(int pidfd) noexcept {
        Lock();
        pidfd_ = pidfd;
        if (pidfd >= 0 && requested_.load(std::memory_order_seq_cst)) Kill(pidfd);
        Unlock();
    }

    /** Supervisor: withdraws the pidfd. Call before closing it. */
    void Disarm() noexcept {
        Lock();
        pidfd_ = -1;
        Unlock();
    }

    /** The host's list of handles of runs in flight; owned by the host under its lock. */
    CancelHandle* prev = nullptr;
    CancelHandle* next = nullptr;

#ifdef STACK_SUPERVISED_TESTING
    /**
     * Test seam (compiled only with -DSTACK_SUPERVISED_TESTING, in no shipped build): a function
     * that replaces the cancellation kill. Return true to say "handled" and suppress the real
     * SIGKILL, which keeps a worker in flight so a test can hold a capability change pending.
     */
    using KillHook = bool (*)(int pidfd);
    static void SetKillHookForTesting(KillHook hook) noexcept { kill_hook_ = hook; }
#endif

private:
    void Lock() noexcept {
        while (lock_.test_and_set(std::memory_order_acquire)) {
        }
    }
    void Unlock() noexcept { lock_.clear(std::memory_order_release); }

    static void Kill(int pidfd) noexcept {
#ifdef STACK_SUPERVISED_TESTING
        if (kill_hook_ != nullptr && kill_hook_(pidfd)) return;
#endif
#ifdef __NR_pidfd_send_signal
        (void)::syscall(__NR_pidfd_send_signal, pidfd, SIGKILL, nullptr, 0);
#else
        (void)pidfd;
#endif
    }

#ifdef STACK_SUPERVISED_TESTING
    static inline KillHook kill_hook_ = nullptr;
#endif
    std::atomic<bool> requested_{false};
    std::atomic_flag lock_ = ATOMIC_FLAG_INIT;
    int pidfd_ = -1;
};

}  // namespace stack::supervised
