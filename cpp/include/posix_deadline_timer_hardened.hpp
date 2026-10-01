#pragma once

#include <csignal>
#include <cstdint>
#include <ctime>
#include <expected>
#include <sys/syscall.h>
#include <unistd.h>
#include <atomic>

namespace tack::governor {

inline int GOVERNOR_PREEMPT_SIG = SIGRTMIN + 2;

struct alignas(64) PersistentThreadTimerState {
    std::atomic<uint32_t> preempted{0};
    timer_t timer_id{nullptr};
    bool timer_initialized{false};
};

inline thread_local PersistentThreadTimerState g_thread_timer_state{};

inline void HardenedPreemptSignalHandler(int sig, siginfo_t* info, [[maybe_unused]] void* context) noexcept {
    if (sig == GOVERNOR_PREEMPT_SIG && info) {
        auto* state = static_cast<PersistentThreadTimerState*>(info->si_value.sival_ptr);
        if (state) state->preempted.store(1, std::memory_order_release);
    }
}

class HardenedPosixPreemptionGuard {
private:
    PersistentThreadTimerState& state_{g_thread_timer_state};
    [[nodiscard]] static pid_t GetThreadId() noexcept { return static_cast<pid_t>(::syscall(SYS_gettid)); }

public:
    static std::expected<void, std::errc> RegisterSignalHandler() noexcept {
        struct sigaction sa{};
        sa.sa_sigaction = HardenedPreemptSignalHandler;
        sa.sa_flags = SA_SIGINFO | SA_NODEFER | SA_RESTART;
        ::sigemptyset(&sa.sa_mask);
        if (::sigaction(GOVERNOR_PREEMPT_SIG, &sa, nullptr) != 0) [[unlikely]] return std::unexpected(std::errc::operation_not_permitted);
        return {};
    }

    static std::expected<void, std::errc> InitializeThreadTimer() noexcept {
        if (g_thread_timer_state.timer_initialized) return {};
        sigevent sev{};
        sev.sigev_notify = SIGEV_THREAD_ID;
        sev.sigev_signo = GOVERNOR_PREEMPT_SIG;
        sev.sigev_value.sival_ptr = &g_thread_timer_state;
        sev._sigev_un._tid = GetThreadId();
        if (::timer_create(CLOCK_THREAD_CPUTIME_ID, &sev, &g_thread_timer_state.timer_id) != 0) [[unlikely]] return std::unexpected(std::errc::resource_unavailable_try_again);
        g_thread_timer_state.timer_initialized = true;
        return {};
    }

    HardenedPosixPreemptionGuard() noexcept = default;

    [[nodiscard]] std::expected<void, std::errc> Arm(uint64_t budget_nanoseconds) noexcept {
        if (budget_nanoseconds == 0) return {};
        
        if (!state_.timer_initialized) [[unlikely]] {
            auto init_res = InitializeThreadTimer();
            if (!init_res.has_value()) return init_res;
        }
        state_.preempted.store(0, std::memory_order_relaxed);
        struct itimerspec its{};
        its.it_value.tv_sec = static_cast<time_t>(budget_nanoseconds / 1'000'000'000ULL);
        its.it_value.tv_nsec = static_cast<long>(budget_nanoseconds % 1'000'000'000ULL);
        if (::timer_settime(state_.timer_id, 0, &its, nullptr) != 0) [[unlikely]] return std::unexpected(std::errc::invalid_argument);
        return {};
    }

    ~HardenedPosixPreemptionGuard() noexcept {
        if (state_.timer_initialized) {
            struct itimerspec zero_its{};
            ::timer_settime(state_.timer_id, 0, &zero_its, nullptr);
        }
    }

    [[nodiscard]] bool WasPreempted() const noexcept { return state_.preempted.load(std::memory_order_acquire) != 0; }
};

} // namespace tack::governor
