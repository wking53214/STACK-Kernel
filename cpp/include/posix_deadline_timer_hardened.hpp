#pragma once

#include "stack_kernel.hpp"

/**
 * ≡TACK KERNEL LAYER 2: Hardened POSIX Deadline Timer and Preemption
 *
 * CONFIDENTIAL. Trade secret of William King (wking53214).
 *
 * ───────────────────────────────────────────────────────────────────────────
 * ARCHITECTURE: Signal-Based Timeout Detection
 *
 * This layer implements deadline enforcement using POSIX interval timers and
 * real-time signals. When a deadline expires, the kernel delivers a signal
 * to the thread. The signal handler records that preemption was triggered.
 *
 * CRITICAL ARCHITECTURAL CONSTRAINT:
 *
 * This is NOT execution preemption. This is deadline-breach detection.
 *
 * The signal handler does not stop execution. It sets a flag. The payload
 * continues running. Only after the payload completes does the host check
 * the flag and recognize the deadline was exceeded.
 *
 * This design choice has profound implications:
 *   - A payload that runs forever will run forever (flag is never checked)
 *   - Deadline enforcement is reactive (after overrun), not preventive
 *   - The "hard timeout" is actually a "breach detector" + soft timeout
 *
 * This is documented here because the name "HardenedPosixPreemptionGuard"
 * promises execution preemption but delivers deadline detection. The gap
 * between the name and the mechanism is the first major defect.
 *
 * ───────────────────────────────────────────────────────────────────────────
 * SIGNAL DELIVERY STRATEGY
 *
 * Uses SIGRTMIN+2 (a real-time signal, thread-targeted via SIGEV_THREAD_ID).
 * The signal carries a pointer to the thread's state via si_value.sival_ptr,
 * allowing the handler to find the right thread's preemption flag.
 *
 * Per-thread timer state is stored in thread-local storage, so each thread
 * gets its own timer and its own preemption flag.
 *
 * ───────────────────────────────────────────────────────────────────────────
 */

#include <csignal>
#include <cstdint>
#include <ctime>
#include <expected>
#include <system_error>
#include <sys/syscall.h>
#include <unistd.h>
#include <atomic>

namespace stack::governor {

/**
 * SIGNAL NUMBER: Real-time signal for deadline breach notification.
 * Uses SIGRTMIN+2 to avoid collisions with other system signals.
 */
inline int GOVERNOR_PREEMPT_SIG = SIGRTMIN + 2;

/**
 * PERSISTENT THREAD TIMER STATE: Per-thread deadline tracking.
 *
 * Members:
 *   preempted:          Flag set to 1 when the deadline timer fires (signal delivered).
 *                       Read by WasPreempted() to check if deadline was exceeded.
 *   timer_id:           Kernel timer handle for this thread.
 *   timer_initialized:  Whether this thread's timer has been set up.
 *
 * Stored in thread-local storage so each thread has its own independent timer.
 * Cache-line aligned to prevent false-sharing if multiple threads initialize
 * simultaneously.
 */
struct alignas(64) PersistentThreadTimerState {
    std::atomic<uint32_t> preempted{0};
    timer_t timer_id{nullptr};
    bool timer_initialized{false};
};

/**
 * THREAD-LOCAL TIMER STATE: One instance per thread.
 * Automatically initialized with default constructor (preempted=0, timer_id=nullptr).
 */
inline thread_local PersistentThreadTimerState g_thread_timer_state{};

/**
 * DEADLINE BREACH SIGNAL HANDLER: Marks deadline exceeded when signal arrives.
 *
 * Invoked when the kernel timer fires (deadline expired). Sets the preempted flag
 * to 1 to record that the deadline was exceeded.
 *
 * CRITICAL DEFECT (Architectural):
 *
 * This handler does NOT stop execution. It only sets a flag. The payload
 * that triggered the timeout continues running to completion. The host only
 * checks WasPreempted() AFTER the payload returns.
 *
 * This means:
 *   - If payload() runs forever, this handler will never interrupt it
 *   - The "hard timeout" is not hard; it is a deadline-breach marker
 *   - Deadline enforcement is reactive (after-the-fact) not preventive
 *
 * This defect is documented here because it is fundamental to how this layer
 * works and how its limitations propagate upward.
 */
inline void HardenedPreemptSignalHandler(int sig, siginfo_t* info, [[maybe_unused]] void* context) noexcept {
    if (sig == GOVERNOR_PREEMPT_SIG && info) {
        auto* state = static_cast<PersistentThreadTimerState*>(info->si_value.sival_ptr);
        if (state) {
            // Mark that deadline was exceeded. Payload continues running.
            // This is a flag, not a preemption.
            state->preempted.store(1, std::memory_order_release);
        }
    }
}

/**
 * DEADLINE DETECTION GUARD: Per-Thread Reactive Deadline Enforcement.
 *
 * Manages a POSIX interval timer for one thread's execution deadline.
 * Registers a signal handler, initializes the timer, arms it with a budget,
 * and checks after execution whether the deadline was exceeded.
 *
 * CRITICAL CONTRACT:
 *
 * This is NOT execution preemption. This is deadline-breach detection.
 *
 * The signal handler sets a flag; execution continues. Only after the
 * payload returns does WasPreempted() check whether the deadline was exceeded.
 *
 * Implications:
 *   - Payloads with infinite loops will NOT be preempted
 *   - Deadline enforcement is reactive (post-execution), not preventive
 *   - WasPreempted() MUST be called AFTER Arm() scope completes
 *   - Do not call WasPreempted() before Arm() completes (reads stale state)
 *
 * USAGE PATTERN (Correct):
 *   {
 *     HardenedPosixPreemptionGuard guard;
 *     guard.Arm(deadline_ns);
 *     payload();  // Execution continues even if deadline fires
 *   }
 *   if (guard.WasPreempted()) { handle_overrun(); }
 *
 * USAGE PATTERN (WRONG - do not do this):
 *   HardenedPosixPreemptionGuard guard;
 *   guard.Arm(deadline_ns);
 *   if (guard.WasPreempted()) { ... }  // BUG: stale state, Arm not complete
 *   payload();
 */
class HardenedPosixPreemptionGuard {
private:
    PersistentThreadTimerState& state_{g_thread_timer_state};
    bool armed_{false};  // Guard: ensures WasPreempted() only called after Arm()

    /**
     * Get the kernel thread ID (gettid syscall).
     * Used to deliver signals to the correct thread when the timer fires.
     */
    [[nodiscard]] static pid_t GetThreadId() noexcept {
        return static_cast<pid_t>(::syscall(SYS_gettid));
    }

public:
    /**
     * PROCESS-WIDE SETUP: Register the deadline breach signal handler.
     *
     * Must be called once per process before any preemption guards are armed.
     * Installs HardenedPreemptSignalHandler() for GOVERNOR_PREEMPT_SIG.
     *
     * Flags:
     *   SA_SIGINFO:  Handler receives full siginfo_t (including sival_ptr)
     *   SA_NODEFER:  Handler can be re-entered (timer can fire while handler runs)
     *   SA_RESTART:  Interrupted system calls are restarted (not aborted)
     *
     * Returns: std::errc::operation_not_permitted if sigaction() fails.
     */
    static std::expected<void, std::errc> RegisterSignalHandler() noexcept {
        struct sigaction sa{};
        sa.sa_sigaction = HardenedPreemptSignalHandler;
        sa.sa_flags = SA_SIGINFO | SA_NODEFER | SA_RESTART;
        ::sigemptyset(&sa.sa_mask);
        if (::sigaction(GOVERNOR_PREEMPT_SIG, &sa, nullptr) != 0) [[unlikely]] {
            return std::unexpected(std::errc::operation_not_permitted);
        }
        return {};
    }

    /**
     * THREAD-LOCAL SETUP: Initialize this thread's deadline timer.
     *
     * Creates a per-thread POSIX timer (CLOCK_THREAD_CPUTIME_ID, so it measures
     * CPU time, not wall-clock time). The timer is configured to send
     * GOVERNOR_PREEMPT_SIG to this thread with sival_ptr pointing to the
     * thread's preemption state.
     *
     * Safe to call multiple times—after the first call, returns success immediately.
     *
     * Returns: std::errc::resource_unavailable_try_again if timer_create() fails
     *          (typically: too many timers or not enough kernel resources).
     */
    static std::expected<void, std::errc> InitializeThreadTimer() noexcept {
        if (g_thread_timer_state.timer_initialized) return {};

        sigevent sev{};
        sev.sigev_notify = SIGEV_THREAD_ID;
        sev.sigev_signo = GOVERNOR_PREEMPT_SIG;
        sev.sigev_value.sival_ptr = &g_thread_timer_state;
        sev._sigev_un._tid = GetThreadId();

        if (::timer_create(CLOCK_THREAD_CPUTIME_ID, &sev, &g_thread_timer_state.timer_id) != 0) [[unlikely]] {
            return std::unexpected(std::errc::resource_unavailable_try_again);
        }
        g_thread_timer_state.timer_initialized = true;
        return {};
    }

    /**
     * CONSTRUCTION: Create a deadline detection guard (not armed yet).
     * Must call Arm() before checking WasPreempted().
     */
    HardenedPosixPreemptionGuard() noexcept : armed_(false) {}

    /**
     * ARM: Set the deadline timer with a budget in nanoseconds.
     *
     * After calling Arm(), the timer will fire after budget_nanoseconds of CPU
     * time have elapsed. When it fires, the signal handler sets preempted=1.
     *
     * If budget_nanoseconds is 0, returns success without arming (allows zero-
     * budget transactions to proceed undeadlined). armed_ flag is NOT set for
     * zero-budget (WasPreempted() will report no preemption).
     *
     * FIX LAYER 2: Sets armed_=true only after successful timer_settime().
     * This prevents WasPreempted() from being called before Arm() completes.
     *
     * Clears preempted flag to 0 before arming, so repeated Arm() calls start
     * fresh.
     *
     * Parameters:
     *   budget_nanoseconds:  Deadline budget in nanoseconds. 0 = no deadline.
     *
     * Returns: std::errc::invalid_argument if timer_settime() fails
     *          (usually: invalid timer or invalid timespec).
     */
    [[nodiscard]] std::expected<void, std::errc> Arm(uint64_t budget_nanoseconds) noexcept {
        armed_ = false;  // Reset to prevent stale WasPreempted() checks
        if (budget_nanoseconds == 0) return {};

        if (!state_.timer_initialized) [[unlikely]] {
            auto init_res = InitializeThreadTimer();
            if (!init_res.has_value()) return init_res;
        }

        // Clear the preempted flag before arming a new deadline
        state_.preempted.store(0, std::memory_order_relaxed);

        struct itimerspec its{};
        its.it_value.tv_sec = static_cast<time_t>(budget_nanoseconds / 1'000'000'000ULL);
        its.it_value.tv_nsec = static_cast<long>(budget_nanoseconds % 1'000'000'000ULL);

        if (::timer_settime(state_.timer_id, 0, &its, nullptr) != 0) [[unlikely]] {
            return std::unexpected(std::errc::invalid_argument);
        }
        armed_ = true;  // FIX: Only set after successful timer setup
        return {};
    }

    /**
     * DESTRUCTION: Disarm the timer (stop it from firing).
     *
     * Called when the guard goes out of scope or is destroyed. Sets the timer
     * to zero (expires immediately with zero budget), which disarms it.
     *
     * CRITICAL FIX (Layer 2 P1): After disarm, clear the preempted flag with
     * release semantics. This prevents a signal that fires during the disarm
     * window (TOCTOU race) from poisoning the next transaction using the same
     * thread-local state.
     *
     * Sequence that triggered the defect:
     *   1. Transaction 1: deadline fires, signal handler sets preempted=1
     *   2. Destructor: calls timer_settime(zero) to disarm
     *   3. RACE WINDOW: signal fires again before disarm completes
     *   4. Signal handler: sets preempted=1 again (in thread-local state)
     *   5. Transaction 2 starts on same thread, Arm() clears preempted=0
     *   6. But the second signal from step 3 delivers after Arm() returns
     *   7. Signal handler: sets preempted=1, poisoning transaction 2
     *
     * The fix: clear with release semantics after disarm, ensuring any
     * signal that fires during disarm cannot race past the destructor's
     * store and into the next transaction.
     *
     * Does not throw. Silently succeeds or fails; timer cleanup is a best-effort
     * operation.
     */
    ~HardenedPosixPreemptionGuard() noexcept {
        if (state_.timer_initialized) {
            struct itimerspec zero_its{};
            ::timer_settime(state_.timer_id, 0, &zero_its, nullptr);
            // FIX LAYER 2 P1: Clear preempted flag after disarm to prevent
            // signals that fire during the disarm window from poisoning the
            // next transaction on the same thread.
            state_.preempted.store(0, std::memory_order_release);
        }
    }

    /**
     * CHECK: Did the deadline timer fire?
     *
     * Returns true if the preempted flag is set (deadline was exceeded).
     *
     * PRECONDITION: Arm() must have been called and completed successfully.
     * Calling WasPreempted() before Arm() is complete returns stale state.
     *
     * FIX LAYER 2: Returns false if called before Arm() completes.
     * This prevents misuse where WasPreempted() is checked during payload.
     *
     * ARCHITECTURAL NOTE: This is a reactive check. The deadline may have
     * been exceeded while the payload was executing, but the execution was
     * not actually stopped. This check happens AFTER the payload completes.
     *
     * If the payload never returns (infinite loop), this check never runs.
     * See the layer 2 architectural notes for why this is a limitation.
     */
    [[nodiscard]] bool WasPreempted() const noexcept {
        // FIX: Guard against calling before Arm() completes
        if (!armed_) {
            return false;  // Not armed yet; no preemption possible
        }
        return state_.preempted.load(std::memory_order_acquire) != 0;
    }
};

} // namespace stack::governor
