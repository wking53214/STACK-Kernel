//! ≡TACK C++/Rust FFI Bridge
//! 
//! Safe Rust bindings to the C++23 containment stack.
//! Compiles C++ directly via `cc` crate for hardened integration.

#![no_std]
#![allow(non_camel_case_types)]

extern "C" {
    pub fn stack_host_initialize_and_seal() -> i32;
    pub fn stack_host_set_capabilities(m0: u64, m1: u64, m2: u64, m3: u64) -> i32;
    pub fn stack_execute_governed_transaction(
        context_id: u64,
        required_capability_m0: u64,
        required_tokens: u32,
        deadline_budget_ticks: u64,
        hard_timeout_nanoseconds: u64,
    ) -> i32;
    pub fn stack_audit_push(event_type: u8, context_id: u64, tokens: u32);
    pub fn stack_audit_read_slot(
        index: u64,
        out_timestamp: *mut u64,
        out_context_id: *mut u64,
        out_tokens: *mut u32,
    ) -> i32;
    pub fn stack_arena_allocate(size: usize) -> *mut u8;
    pub fn stack_read_ticks() -> u64;
    pub fn stack_supervised_run(
        payload_kind: u32,
        limits: *const SupervisedLimitsFfi,
        out: *mut u8,
        out_capacity: usize,
        report: *mut SupervisedReportFfi,
    ) -> i32;
}

/// C layout of `stack_supervised_limits` in ffi_wrapper.cpp.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct SupervisedLimitsFfi {
    pub wall_clock_deadline_ns: u64,
    pub cpu_seconds: u64,
    pub address_space_bytes: u64,
    pub max_output_bytes: u64,
    pub file_size_bytes: u64,
    pub nofile: u32,
    pub reserved: u32,
}

/// C layout of `stack_supervised_report` in ffi_wrapper.cpp.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct SupervisedReportFfi {
    pub elapsed_ns: u64,
    pub result_length: u64,
    pub outcome: i32,
    pub exit_code: i32,
    pub signal_number: i32,
    pub error_number: i32,
    pub child_pid: i32,
    pub deadline_fired: u8,
    pub reserved: [u8; 3],
}

/// Safe wrapper for host initialization
pub fn host_initialize_and_seal() -> Result<(), HostError> {
    unsafe {
        match stack_host_initialize_and_seal() {
            0 => Ok(()),
            _ => Err(HostError::InitializationFailed),
        }
    }
}

/// Safe wrapper for setting active capabilities.
///
/// A change is refused while a transaction is in flight, so a caller that must
/// apply it retries on `TransactionInFlight`.
pub fn host_set_capabilities(m0: u64, m1: u64, m2: u64, m3: u64) -> Result<(), CapabilityError> {
    unsafe {
        match stack_host_set_capabilities(m0, m1, m2, m3) {
            0 => Ok(()),
            -2 => Err(CapabilityError::TransactionInFlight),
            _ => Err(CapabilityError::NotInitialized),
        }
    }
}

/// Safe wrapper for executing a governed transaction on the in-process path.
///
/// This path has a cooperative CPU-time deadline and is not isolation; see
/// `supervised_run` for a payload that must be stopped. The C codes -1 and
/// -3 keep their original meaning and still map to `ExecutionFailed`; the
/// codes added for D-18 map to the distinct variants below.
pub fn execute_governed_transaction(
    context_id: u64,
    required_capability_m0: u64,
    required_tokens: u32,
    deadline_budget_ticks: u64,
    hard_timeout_nanoseconds: u64,
) -> Result<(), TransactionError> {
    unsafe {
        match stack_execute_governed_transaction(
            context_id,
            required_capability_m0,
            required_tokens,
            deadline_budget_ticks,
            hard_timeout_nanoseconds,
        ) {
            0 => Ok(()),
            -4 => Err(TransactionError::CapabilityDenied),
            -5 => Err(TransactionError::RateLimited),
            -6 => Err(TransactionError::HardTimeout),
            -7 => Err(TransactionError::SoftwareDeadline),
            -8 => Err(TransactionError::DebtCeiling),
            -9 => Err(TransactionError::InvalidHardTimeout),
            -10 => Err(TransactionError::TimerArmFailed),
            _ => Err(TransactionError::ExecutionFailed),
        }
    }
}

/// The built-in payloads `supervised_run` can execute. The C ABI cannot
/// carry a closure, so the set is fixed; it exists to exercise and verify
/// the executor from Rust.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PayloadKind {
    /// Writes `SUPERVISED_PAYLOAD_BYTES` and completes.
    ReturnBytes,
    /// Infinite loop.
    SpinForever,
    /// A futex wait that is never woken.
    BlockForever,
    /// Null store (SIGSEGV).
    Crash,
    /// abort() (SIGABRT).
    Abort,
    /// _exit(3).
    ExitNonZero,
    /// open(2), which the filter kills with SIGSYS.
    ForbiddenSyscall,
}

impl PayloadKind {
    fn code(self) -> u32 {
        match self {
            PayloadKind::ReturnBytes => 0,
            PayloadKind::SpinForever => 1,
            PayloadKind::BlockForever => 2,
            PayloadKind::Crash => 3,
            PayloadKind::Abort => 4,
            PayloadKind::ExitNonZero => 5,
            PayloadKind::ForbiddenSyscall => 6,
        }
    }
}

/// What `PayloadKind::ReturnBytes` writes.
pub const SUPERVISED_PAYLOAD_BYTES: &[u8] = b"stack-ffi-payload-v1";

/// Limits for a supervised run; mirrors `stack::supervised::Limits` without
/// the inherited descriptor.
#[derive(Debug, Clone, Copy)]
pub struct SupervisedLimits {
    /// Required, 1 ns .. 1 hour.
    pub wall_clock_deadline_ns: u64,
    /// RLIMIT_CPU seconds; 0 derives ceil(deadline) + 1.
    pub cpu_seconds: u64,
    /// RLIMIT_AS bytes; 0 keeps the inherited limit.
    pub address_space_bytes: u64,
    /// Largest accepted result, at most 1 MiB and at most the buffer given.
    pub max_output_bytes: u64,
    /// RLIMIT_FSIZE bytes; 0 forbids regular-file writes.
    pub file_size_bytes: u64,
    /// RLIMIT_NOFILE; 0 derives the floor.
    pub nofile: u32,
}

/// Outcome of a supervised run, one variant per C++ `Outcome`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SupervisedOutcome {
    /// Exit 0, complete valid result, deadline not passed.
    Completed,
    /// The wall-clock deadline passed; the child was killed.
    TimedOut,
    /// Ended by a signal other than SIGSYS, SIGXCPU or SIGXFSZ.
    Crashed,
    /// Ended by SIGSYS: the seccomp filter killed it.
    SeccompViolation,
    /// Exited with a non-zero status.
    ExitedNonZero,
    /// Exit 0 but no complete, valid result frame.
    ResultMissing,
    /// The frame announced more than `max_output_bytes`.
    ResultOversized,
    /// Ended by SIGXCPU or SIGXFSZ.
    ResourceLimit,
    /// pipe/fork failed, or the child could not set up its sandbox.
    SpawnFailed,
    /// poll/waitpid failed in the parent.
    SupervisorError,
    /// The limits were rejected before anything was spawned.
    InvalidLimits,
    /// A code this crate does not know; carried rather than collapsed.
    Unrecognized(i32),
}

impl SupervisedOutcome {
    fn from_code(code: i32) -> Self {
        match code {
            0 => SupervisedOutcome::Completed,
            1 => SupervisedOutcome::TimedOut,
            2 => SupervisedOutcome::Crashed,
            3 => SupervisedOutcome::SeccompViolation,
            4 => SupervisedOutcome::ExitedNonZero,
            5 => SupervisedOutcome::ResultMissing,
            6 => SupervisedOutcome::ResultOversized,
            7 => SupervisedOutcome::ResourceLimit,
            8 => SupervisedOutcome::SpawnFailed,
            9 => SupervisedOutcome::SupervisorError,
            10 => SupervisedOutcome::InvalidLimits,
            other => SupervisedOutcome::Unrecognized(other),
        }
    }
}

/// Report of a supervised run.
#[derive(Debug, Clone, Copy)]
pub struct SupervisedReport {
    pub outcome: SupervisedOutcome,
    /// Wall-clock time from before the fork to after the reap.
    pub elapsed_ns: u64,
    /// Exit status when the child exited, else -1.
    pub exit_code: i32,
    /// Terminating signal when the child was signaled, else 0.
    pub signal_number: i32,
    /// errno on SpawnFailed / SupervisorError, else 0.
    pub error_number: i32,
    /// 0 when nothing was forked.
    pub child_pid: i32,
    /// True when the deadline passed before the exit was observed.
    pub deadline_fired: bool,
    /// Bytes placed at the start of the buffer; meaningful only on Completed.
    pub result_length: u64,
}

/// Why `supervised_run` could not even produce a report.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SupervisedCallError {
    /// The C side rejected a pointer argument.
    NullArgument,
    /// The C side does not know this payload kind.
    UnknownPayloadKind,
    /// A code this crate does not know.
    Unrecognized(i32),
}

/// Runs a built-in payload in a supervised child process (a fork of this
/// process) with a wall-clock deadline that ends in SIGKILL, and returns
/// the classified report. The result bytes land at the start of `out`.
///
/// Forking a multithreaded process copies only the calling thread; a child
/// that deadlocks on a lock another thread held is killed at the deadline
/// and reported `TimedOut`, never `Completed`.
pub fn supervised_run(
    kind: PayloadKind,
    limits: &SupervisedLimits,
    out: &mut [u8],
) -> Result<SupervisedReport, SupervisedCallError> {
    let ffi_limits = SupervisedLimitsFfi {
        wall_clock_deadline_ns: limits.wall_clock_deadline_ns,
        cpu_seconds: limits.cpu_seconds,
        address_space_bytes: limits.address_space_bytes,
        max_output_bytes: limits.max_output_bytes,
        file_size_bytes: limits.file_size_bytes,
        nofile: limits.nofile,
        reserved: 0,
    };
    let mut ffi_report = SupervisedReportFfi::default();
    let rc = unsafe {
        stack_supervised_run(
            kind.code(),
            &ffi_limits,
            out.as_mut_ptr(),
            out.len(),
            &mut ffi_report,
        )
    };
    match rc {
        0 => Ok(SupervisedReport {
            outcome: SupervisedOutcome::from_code(ffi_report.outcome),
            elapsed_ns: ffi_report.elapsed_ns,
            exit_code: ffi_report.exit_code,
            signal_number: ffi_report.signal_number,
            error_number: ffi_report.error_number,
            child_pid: ffi_report.child_pid,
            deadline_fired: ffi_report.deadline_fired != 0,
            result_length: ffi_report.result_length,
        }),
        -1 => Err(SupervisedCallError::NullArgument),
        -2 => Err(SupervisedCallError::UnknownPayloadKind),
        other => Err(SupervisedCallError::Unrecognized(other)),
    }
}

/// Safe wrapper for audit ring push
pub fn audit_push(event_type: u8, context_id: u64, tokens: u32) {
    unsafe {
        stack_audit_push(event_type, context_id, tokens);
    }
}

/// Safe wrapper for audit ring read
pub fn audit_read_slot(index: u64) -> Option<AuditRecord> {
    unsafe {
        let mut timestamp = 0u64;
        let mut context_id = 0u64;
        let mut tokens = 0u32;
        
        if stack_audit_read_slot(index, &mut timestamp, &mut context_id, &mut tokens) != 0 {
            Some(AuditRecord {
                timestamp_ticks: timestamp,
                context_id,
                tokens_consumed: tokens,
            })
        } else {
            None
        }
    }
}

/// Read hardware tick counter
pub fn read_ticks() -> u64 {
    unsafe { stack_read_ticks() }
}

#[derive(Debug, Clone, Copy)]
pub enum HostError {
    InitializationFailed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CapabilityError {
    /// The host has not been initialized yet.
    NotInitialized,
    /// A governed transaction is in flight; the mask was not changed.
    TransactionInFlight,
}

/// Failure of the in-process governed transaction. `ExecutionFailed` keeps
/// its original coverage of the C codes -1 (not initialized) and -3 (setup
/// failure); the other variants are the codes added for D-18.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransactionError {
    ExecutionFailed,
    /// The requested capabilities are not a subset of the active mask.
    CapabilityDenied,
    /// The domain's token bucket refused the request.
    RateLimited,
    /// The CPU-time hard timeout fired while the payload ran (detected after it returned).
    HardTimeout,
    /// The software tick budget was exceeded.
    SoftwareDeadline,
    /// The domain's compute debt ceiling was exceeded.
    DebtCeiling,
    /// hard_timeout_nanoseconds was 0; refused before anything ran.
    InvalidHardTimeout,
    /// The deadline timer could not be armed; nothing ran.
    TimerArmFailed,
}

#[derive(Debug, Clone, Copy)]
pub struct AuditRecord {
    pub timestamp_ticks: u64,
    pub context_id: u64,
    pub tokens_consumed: u32,
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;

    /// Sealing installs a seccomp filter that cannot be removed, so it runs in
    /// a child copy of this test binary. The parent only checks that the child
    /// seals and exits cleanly, within a deadline, so a hang fails fast.
    #[test]
    fn test_ffi_initialization() {
        const CHILD_ENV: &str = "STACK_FFI_SEAL_CHILD";
        if std::env::var_os(CHILD_ENV).is_some() {
            assert!(host_initialize_and_seal().is_ok());
            return;
        }
        let exe = std::env::current_exe().expect("test binary path");
        let mut child = std::process::Command::new(exe)
            .args(["--exact", "tests::test_ffi_initialization", "--test-threads=1"])
            .env(CHILD_ENV, "1")
            .spawn()
            .expect("spawn sealed child");
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(60);
        loop {
            if let Some(status) = child.try_wait().expect("poll child") {
                assert!(status.success(), "sealed child failed: {status}");
                return;
            }
            if std::time::Instant::now() >= deadline {
                let _ = child.kill();
                panic!("sealed child did not exit within 60 seconds");
            }
            std::thread::sleep(std::time::Duration::from_millis(50));
        }
    }

    /// A seccomp filter attaches to the thread that installs it. Every thread
    /// that seals must be filtered, and a thread that never seals must not be,
    /// so a Rust process that seals on one thread keeps working on the rest.
    /// Runs in a child copy of this test binary for the same reason as above.
    /// openat is not on the allowlist, so a filtered thread cannot open a file.
    #[test]
    fn test_each_thread_seals_itself_and_only_itself() {
        const CHILD_ENV: &str = "STACK_FFI_THREAD_SEAL_CHILD";
        const PROBE: &str = "/proc/self/stat";
        if std::env::var_os(CHILD_ENV).is_some() {
            assert!(std::fs::File::open(PROBE).is_ok(), "unsealed thread must open files");
            // The sealed closures do no allocation and no formatting; results come
            // back through join and are checked on this unsealed thread.
            let seal_and_probe = || {
                let sealed = host_initialize_and_seal().is_ok();
                let blocked = std::fs::File::open(PROBE).is_err();
                (sealed, blocked)
            };
            let first = std::thread::spawn(seal_and_probe).join().expect("first thread");
            let second = std::thread::spawn(seal_and_probe).join().expect("second thread");
            assert_eq!(first, (true, true), "first thread must be sealed and filtered");
            assert_eq!(second, (true, true), "second thread must be sealed and filtered");
            // Not process wide: this thread can still open files and spawn threads.
            assert!(std::fs::File::open(PROBE).is_ok(), "sealing must not reach other threads");
            let third = std::thread::spawn(|| std::fs::File::open(PROBE).is_ok())
                .join()
                .expect("third thread");
            assert!(third, "a thread that never sealed must stay unfiltered");
            return;
        }
        let exe = std::env::current_exe().expect("test binary path");
        let mut child = std::process::Command::new(exe)
            .args([
                "--exact",
                "tests::test_each_thread_seals_itself_and_only_itself",
                "--test-threads=1",
            ])
            .env(CHILD_ENV, "1")
            .spawn()
            .expect("spawn sealed child");
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(60);
        loop {
            if let Some(status) = child.try_wait().expect("poll child") {
                assert!(status.success(), "sealed child failed: {status}");
                return;
            }
            if std::time::Instant::now() >= deadline {
                let _ = child.kill();
                panic!("sealed child did not exit within 60 seconds");
            }
            std::thread::sleep(std::time::Duration::from_millis(50));
        }
    }

    #[test]
    fn test_capability_setting() {
        let _ = host_set_capabilities(0xFF, 0, 0, 0);
    }

    /// Distinct transaction codes: a zero hard timeout and a capability
    /// denial are told apart from each other and from success. Runs in a
    /// sealed child copy of this binary like the other sealing tests.
    #[test]
    fn test_transaction_failures_are_distinct() {
        const CHILD_ENV: &str = "STACK_FFI_TXN_CODES_CHILD";
        if std::env::var_os(CHILD_ENV).is_some() {
            assert!(host_initialize_and_seal().is_ok());
            assert_eq!(host_set_capabilities(0xFF, 0, 0, 0), Ok(()));
            assert_eq!(
                execute_governed_transaction(1, 0x01, 1, 1_000_000_000, 0),
                Err(TransactionError::InvalidHardTimeout)
            );
            assert_eq!(host_set_capabilities(0, 0, 0, 0), Ok(()));
            assert_eq!(
                execute_governed_transaction(1, 0x01, 1, 1_000_000_000, 1_000_000_000),
                Err(TransactionError::CapabilityDenied)
            );
            assert_eq!(host_set_capabilities(0xFF, 0, 0, 0), Ok(()));
            // Pre-existing: the FFI host is GovernedMinotaurHost<64, 100, ...>,
            // whose Reserved (100) exceeds MaxCapacity (64), so a Standard
            // priority request can never clear `available < Reserved + amount`
            // and every FFI transaction is rate limited. The old -3 collapse
            // hid this; the distinct code now shows it. When the parameters
            // are fixed this assertion becomes Ok(()).
            assert_eq!(
                execute_governed_transaction(1, 0x01, 1, 1_000_000_000, 1_000_000_000),
                Err(TransactionError::RateLimited)
            );
            return;
        }
        let exe = std::env::current_exe().expect("test binary path");
        let mut child = std::process::Command::new(exe)
            .args(["--exact", "tests::test_transaction_failures_are_distinct", "--test-threads=1"])
            .env(CHILD_ENV, "1")
            .spawn()
            .expect("spawn sealed child");
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(60);
        loop {
            if let Some(status) = child.try_wait().expect("poll child") {
                assert!(status.success(), "sealed child failed: {status}");
                return;
            }
            if std::time::Instant::now() >= deadline {
                let _ = child.kill();
                panic!("sealed child did not exit within 60 seconds");
            }
            std::thread::sleep(std::time::Duration::from_millis(50));
        }
    }

    const SUPERVISED_DEADLINE_NS: u64 = 300_000_000;
    // Slack over the deadline for a killed child: kill, reap, scheduling.
    const SUPERVISED_SLACK_NS: u64 = 2_000_000_000;

    fn supervised_limits() -> SupervisedLimits {
        SupervisedLimits {
            wall_clock_deadline_ns: SUPERVISED_DEADLINE_NS,
            cpu_seconds: 0,
            address_space_bytes: 0,
            max_output_bytes: 64,
            file_size_bytes: 0,
            nofile: 0,
        }
    }

    /// The supervised runs fork this test process; the harness is
    /// multithreaded, which is the documented caveat the deadline backstops.
    #[test]
    fn test_supervised_return_bytes_is_completed_with_exact_bytes() {
        let mut out = [0u8; 64];
        let report = supervised_run(PayloadKind::ReturnBytes, &supervised_limits(), &mut out)
            .expect("report");
        assert_eq!(report.outcome, SupervisedOutcome::Completed);
        assert_eq!(report.exit_code, 0);
        assert!(!report.deadline_fired);
        let n = usize::try_from(report.result_length).expect("length fits");
        assert_eq!(&out[..n], SUPERVISED_PAYLOAD_BYTES);
    }

    #[test]
    fn test_supervised_spin_forever_is_timed_out_at_the_deadline() {
        let mut out = [0u8; 64];
        let report = supervised_run(PayloadKind::SpinForever, &supervised_limits(), &mut out)
            .expect("report");
        assert_eq!(report.outcome, SupervisedOutcome::TimedOut);
        assert!(report.deadline_fired);
        assert!(report.elapsed_ns >= SUPERVISED_DEADLINE_NS);
        assert!(report.elapsed_ns <= SUPERVISED_DEADLINE_NS + SUPERVISED_SLACK_NS);
    }

    #[test]
    fn test_supervised_block_forever_is_timed_out() {
        let mut out = [0u8; 64];
        let report = supervised_run(PayloadKind::BlockForever, &supervised_limits(), &mut out)
            .expect("report");
        assert_eq!(report.outcome, SupervisedOutcome::TimedOut);
        assert!(report.elapsed_ns <= SUPERVISED_DEADLINE_NS + SUPERVISED_SLACK_NS);
    }

    #[test]
    fn test_supervised_crash_abort_exit_and_forbidden_syscall_are_distinct() {
        let mut out = [0u8; 64];
        let crash = supervised_run(PayloadKind::Crash, &supervised_limits(), &mut out).expect("report");
        assert_eq!(crash.outcome, SupervisedOutcome::Crashed);
        assert_eq!(crash.signal_number, 11);

        let abort = supervised_run(PayloadKind::Abort, &supervised_limits(), &mut out).expect("report");
        assert_eq!(abort.outcome, SupervisedOutcome::Crashed);
        assert_eq!(abort.signal_number, 6);

        let exit = supervised_run(PayloadKind::ExitNonZero, &supervised_limits(), &mut out).expect("report");
        assert_eq!(exit.outcome, SupervisedOutcome::ExitedNonZero);
        assert_eq!(exit.exit_code, 3);

        let forbidden =
            supervised_run(PayloadKind::ForbiddenSyscall, &supervised_limits(), &mut out).expect("report");
        assert_eq!(forbidden.outcome, SupervisedOutcome::SeccompViolation);
        assert_eq!(forbidden.signal_number, 31);
        assert!(!forbidden.deadline_fired);
    }

    #[test]
    fn test_supervised_invalid_limits_are_rejected_before_forking() {
        let mut out = [0u8; 64];
        let mut limits = supervised_limits();
        limits.wall_clock_deadline_ns = 0;
        let report = supervised_run(PayloadKind::ReturnBytes, &limits, &mut out).expect("report");
        assert_eq!(report.outcome, SupervisedOutcome::InvalidLimits);
        assert_eq!(report.child_pid, 0);

        let mut too_big = supervised_limits();
        too_big.max_output_bytes = 65;
        let report = supervised_run(PayloadKind::ReturnBytes, &too_big, &mut out).expect("report");
        assert_eq!(report.outcome, SupervisedOutcome::InvalidLimits);
    }

    #[test]
    fn test_tick_counter() {
        let t1 = read_ticks();
        let t2 = read_ticks();
        assert!(t2 >= t1);
    }

    /// Before the host exists, a change is reported as not initialized.
    /// No test in this process initializes the host (sealing runs in children).
    #[test]
    fn test_set_capabilities_before_init_is_reported() {
        assert_eq!(host_set_capabilities(0xFF, 0, 0, 0), Err(CapabilityError::NotInitialized));
    }

    /// After sealing, a change with no transaction in flight is applied and
    /// reported as such. Runs in a child copy of this test binary because
    /// sealing cannot be undone.
    #[test]
    fn test_set_capabilities_reports_applied_after_init() {
        const CHILD_ENV: &str = "STACK_FFI_SET_CAPS_CHILD";
        if std::env::var_os(CHILD_ENV).is_some() {
            assert!(host_initialize_and_seal().is_ok());
            assert_eq!(host_set_capabilities(0xFF, 0, 0, 0), Ok(()));
            assert_eq!(host_set_capabilities(0xAA, 0, 0, 0), Ok(()));
            return;
        }
        let exe = std::env::current_exe().expect("test binary path");
        let mut child = std::process::Command::new(exe)
            .args(["--exact", "tests::test_set_capabilities_reports_applied_after_init", "--test-threads=1"])
            .env(CHILD_ENV, "1")
            .spawn()
            .expect("spawn sealed child");
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(60);
        loop {
            if let Some(status) = child.try_wait().expect("poll child") {
                assert!(status.success(), "sealed child failed: {status}");
                return;
            }
            if std::time::Instant::now() >= deadline {
                let _ = child.kill();
                panic!("sealed child did not exit within 60 seconds");
            }
            std::thread::sleep(std::time::Duration::from_millis(50));
        }
    }
}
