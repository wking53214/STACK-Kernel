//! ≡TACK C++/Rust FFI Bridge
//! 
//! Safe Rust bindings to the C++23 containment stack.
//! Compiles C++ directly via `cc` crate for hardened integration.

#![no_std]
#![allow(non_camel_case_types)]

extern "C" {
    pub fn stack_host_initialize() -> i32;
    pub fn stack_host_seal_current_thread() -> i32;
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
    pub fn stack_host_payload_count() -> u64;
    pub fn stack_host_audit_read_slot(
        index: u64,
        out_event_type: *mut u8,
        out_timestamp: *mut u64,
        out_context_id: *mut u64,
        out_tokens: *mut u32,
    ) -> i32;
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

/// Process initialization only (I-02): constructs the host once, registers the
/// deadline signal handler and creates this thread's deadline timer. Does not
/// seal the calling thread. Idempotent; a failure is latched for the life of
/// the process and every later call reports it.
pub fn host_initialize() -> Result<(), HostError> {
    unsafe {
        match stack_host_initialize() {
            0 => Ok(()),
            _ => Err(HostError::InitializationFailed),
        }
    }
}

/// Seals the calling thread (I-02): its deadline timer and the seccomp
/// allowlist. Irreversible; idempotent for a sealed thread. A thread must be
/// sealed before it can run `execute_governed_transaction`.
pub fn host_seal_current_thread() -> Result<(), SealError> {
    unsafe {
        match stack_host_seal_current_thread() {
            0 => Ok(()),
            -1 => Err(SealError::NotInitialized),
            -2 => Err(SealError::SealFailed),
            _ => Err(SealError::InitializationFailed),
        }
    }
}

/// Initializes the process and seals the calling thread, in that order.
pub fn host_initialize_and_seal() -> Result<(), HostError> {
    unsafe {
        match stack_host_initialize_and_seal() {
            0 => Ok(()),
            -2 => Err(HostError::SealFailed),
            _ => Err(HostError::InitializationFailed),
        }
    }
}

/// Safe wrapper for setting active capabilities.
///
/// A change is refused while a transaction is in flight, so a caller that must
/// apply it retries on `TransactionInFlight`. It needs a completed
/// initialization: `NotInitialized` before (or during) it, and
/// `InitializationFailed` for good once it has failed.
pub fn host_set_capabilities(m0: u64, m1: u64, m2: u64, m3: u64) -> Result<(), CapabilityError> {
    unsafe {
        match stack_host_set_capabilities(m0, m1, m2, m3) {
            0 => Ok(()),
            -2 => Err(CapabilityError::TransactionInFlight),
            -3 => Err(CapabilityError::InitializationFailed),
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
            -11 => Err(TransactionError::ThreadNotSealed),
            -12 => Err(TransactionError::InitializationFailed),
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

/// How many times the built-in governed payload has run in this process. A
/// completed transaction has run it once; a refused one has not run it.
pub fn host_payload_count() -> u64 {
    unsafe { stack_host_payload_count() }
}

/// One event type of the host's governance audit trail (`AuditEventType`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HostAuditEvent {
    TransactionCompleted,
    RateLimitTriggered,
    SoftwareDeadlineExceeded,
    HardwareTimerPreempted,
    CapabilityViolation,
    /// A value this crate does not know; carried rather than collapsed.
    Unrecognized(u8),
}

impl HostAuditEvent {
    fn from_code(code: u8) -> Self {
        match code {
            0 => HostAuditEvent::TransactionCompleted,
            1 => HostAuditEvent::RateLimitTriggered,
            2 => HostAuditEvent::SoftwareDeadlineExceeded,
            3 => HostAuditEvent::HardwareTimerPreempted,
            4 => HostAuditEvent::CapabilityViolation,
            other => HostAuditEvent::Unrecognized(other),
        }
    }
}

/// One record of the host's governance audit trail.
#[derive(Debug, Clone, Copy)]
pub struct HostAuditRecord {
    pub event: HostAuditEvent,
    pub timestamp_ticks: u64,
    pub context_id: u64,
    pub tokens: u32,
}

/// Reads slot `index` of the host's own audit ring (8192 slots; the index
/// wraps). `None` when the host is not initialized or the slot was never
/// written. This is the ring `execute_governed_transaction` records into,
/// not the free-standing ring behind `audit_push`.
pub fn host_audit_read_slot(index: u64) -> Option<HostAuditRecord> {
    let mut event_type = 0u8;
    let mut timestamp = 0u64;
    let mut context_id = 0u64;
    let mut tokens = 0u32;
    let rc = unsafe {
        stack_host_audit_read_slot(index, &mut event_type, &mut timestamp, &mut context_id, &mut tokens)
    };
    if rc == 0 {
        Some(HostAuditRecord {
            event: HostAuditEvent::from_code(event_type),
            timestamp_ticks: timestamp,
            context_id,
            tokens,
        })
    } else {
        None
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HostError {
    /// The one-time process initialization failed; latched for this process.
    InitializationFailed,
    /// Initialization succeeded but this thread could not be sealed (I-02).
    SealFailed,
}

/// Failure of `host_seal_current_thread` (I-02).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SealError {
    /// `host_initialize` has not completed.
    NotInitialized,
    /// This thread's timer or filter could not be set up; it is unchanged.
    SealFailed,
    /// Initialization failed; latched for this process.
    InitializationFailed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CapabilityError {
    /// The host has not been initialized yet (or is still being initialized).
    NotInitialized,
    /// A governed transaction is in flight; the mask was not changed.
    TransactionInFlight,
    /// Initialization failed; latched. The mask was not changed (I-02).
    InitializationFailed,
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
    /// The calling thread is not sealed (I-02): call `host_seal_current_thread`
    /// first. Nothing ran and the thread was not sealed as a side effect.
    ThreadNotSealed,
    /// Initialization failed; latched for this process. Nothing ran.
    InitializationFailed,
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
            // R2-K-01 (I-01): the FFI host used to be GovernedMinotaurHost<64, 100, ...>,
            // whose Reserved (100) exceeded MaxCapacity (64), so every Standard
            // request was rate limited and this assertion had to be RateLimited.
            // With a bucket that can serve a request, a valid transaction completes.
            assert_eq!(
                execute_governed_transaction(1, 0x01, 1, 1_000_000_000, 1_000_000_000),
                Ok(())
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

    /// Runs the named test in a child copy of this binary with `env` set, and
    /// requires the child to exit cleanly within 60 seconds. Sealing cannot
    /// be undone, so each test that seals gets its own process.
    fn run_in_child(test: &str, env: &str) {
        let exe = std::env::current_exe().expect("test binary path");
        let mut child = std::process::Command::new(exe)
            .args(["--exact", test, "--test-threads=1"])
            .env(env, "1")
            .spawn()
            .expect("spawn child");
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(60);
        loop {
            if let Some(status) = child.try_wait().expect("poll child") {
                assert!(status.success(), "child failed: {status}");
                return;
            }
            if std::time::Instant::now() >= deadline {
                let _ = child.kill();
                panic!("child did not exit within 60 seconds");
            }
            std::thread::sleep(std::time::Duration::from_millis(50));
        }
    }

    const NO_SOFTWARE_DEADLINE: u64 = u64::MAX;
    const ONE_SECOND_NS: u64 = 1_000_000_000;
    // FFI governance policy (ffi_wrapper.cpp): bucket 1000, floor 100,
    // largest request 100, 1000 tokens per second; 900 spendable in a burst.
    const SPENDABLE: u32 = 900;
    const LARGEST_REQUEST: u32 = 100;

    fn txn(domain: u64, caps: u64, tokens: u32) -> Result<(), TransactionError> {
        execute_governed_transaction(domain, caps, tokens, NO_SOFTWARE_DEADLINE, ONE_SECOND_NS)
    }

    /// Runs `f` on a fresh thread that seals itself first; the result comes
    /// back through join and is asserted on the unsealed caller.
    fn on_sealed_thread<T: Send + 'static>(f: impl FnOnce() -> T + Send + 'static) -> T {
        std::thread::spawn(move || {
            assert!(host_initialize_and_seal().is_ok(), "seal");
            f()
        })
        .join()
        .expect("sealed thread")
    }

    /// Completed transactions of `tokens` each before the first RateLimited,
    /// with the last result.
    fn consume_until_rate_limited(domain: u64, tokens: u32, limit: usize) -> (usize, Result<(), TransactionError>) {
        let mut ok = 0;
        let mut last = Ok(());
        for _ in 0..limit {
            last = txn(domain, 0x01, tokens);
            if last.is_err() {
                break;
            }
            ok += 1;
        }
        (ok, last)
    }

    /// I-01: an exhausted bucket is RateLimited, refusals run no payload and
    /// consume nothing, and refill restores service.
    #[test]
    fn test_exhaustion_refusal_and_refill_through_the_ffi() {
        const CHILD_ENV: &str = "STACK_FFI_EXHAUST_CHILD";
        if std::env::var_os(CHILD_ENV).is_some() {
            let (completed, last, elapsed_ms, refusals, runs_delta) = on_sealed_thread(|| {
                assert_eq!(host_set_capabilities(0xFF, 0, 0, 0), Ok(()));
                let t0 = std::time::Instant::now();
                let (completed, last) = consume_until_rate_limited(1, LARGEST_REQUEST, 50);
                let elapsed_ms = t0.elapsed().as_millis() as usize;
                let before = host_payload_count();
                let refusals = (0..5)
                    .filter(|_| txn(1, 0x01, LARGEST_REQUEST) == Err(TransactionError::RateLimited))
                    .count();
                (completed, last, elapsed_ms, refusals, host_payload_count() - before)
            });
            assert_eq!(last, Err(TransactionError::RateLimited));
            let expected = (SPENDABLE / LARGEST_REQUEST) as usize; // 9
            assert!(completed >= expected, "completed {completed}");
            assert!(completed <= expected + elapsed_ms / 100 + 1, "completed {completed} in {elapsed_ms} ms");
            assert_eq!(refusals, 5);
            assert_eq!(runs_delta, 0, "a refused transaction must not run the payload");

            // 300 ms of refill at 1000 tokens per second: two more requests of 100.
            // The unsealed thread sleeps; a sealed one cannot.
            std::thread::sleep(std::time::Duration::from_millis(300));
            let (first, second, runs_delta) = on_sealed_thread(|| {
                let before = host_payload_count();
                let first = txn(1, 0x01, LARGEST_REQUEST);
                let second = txn(1, 0x01, LARGEST_REQUEST);
                (first, second, host_payload_count() - before)
            });
            assert_eq!(first, Ok(()));
            assert_eq!(second, Ok(()));
            assert_eq!(runs_delta, 2);
            return;
        }
        run_in_child("tests::test_exhaustion_refusal_and_refill_through_the_ffi", CHILD_ENV);
    }

    /// I-01: an invalid capability is CapabilityDenied, runs no payload and
    /// leaves the bucket full.
    #[test]
    fn test_invalid_capability_consumes_nothing_through_the_ffi() {
        const CHILD_ENV: &str = "STACK_FFI_BADCAP_CHILD";
        if std::env::var_os(CHILD_ENV).is_some() {
            let (denied, runs_delta, completed, last, elapsed_ms) = on_sealed_thread(|| {
                assert_eq!(host_set_capabilities(0xFF, 0, 0, 0), Ok(()));
                let before = host_payload_count();
                let denied = (0..20)
                    .filter(|_| txn(2, 0x100, LARGEST_REQUEST) == Err(TransactionError::CapabilityDenied))
                    .count();
                let runs_delta = host_payload_count() - before;
                let t0 = std::time::Instant::now();
                let (completed, last) = consume_until_rate_limited(2, LARGEST_REQUEST, 50);
                (denied, runs_delta, completed, last, t0.elapsed().as_millis() as usize)
            });
            assert_eq!(denied, 20);
            assert_eq!(runs_delta, 0);
            assert_eq!(last, Err(TransactionError::RateLimited));
            let expected = (SPENDABLE / LARGEST_REQUEST) as usize;
            assert!(completed >= expected, "completed {completed}");
            assert!(completed <= expected + elapsed_ms / 100 + 1, "completed {completed} in {elapsed_ms} ms");
            return;
        }
        run_in_child("tests::test_invalid_capability_consumes_nothing_through_the_ffi", CHILD_ENV);
    }

    /// I-01: repeated valid and invalid transactions leave no stale state: every
    /// valid one completes, every invalid one is denied, and the in-flight
    /// counter is back at zero so a capability change is applied.
    #[test]
    fn test_repeated_transactions_leave_no_stale_state_through_the_ffi() {
        const CHILD_ENV: &str = "STACK_FFI_REPEAT_CHILD";
        if std::env::var_os(CHILD_ENV).is_some() {
            let (completed, denied, caps_after) = on_sealed_thread(|| {
                assert_eq!(host_set_capabilities(0xFF, 0, 0, 0), Ok(()));
                let mut completed = 0;
                let mut denied = 0;
                for _ in 0..200 {
                    if txn(3, 0x01, 1) == Ok(()) {
                        completed += 1;
                    }
                    if txn(3, 0x100, 1) == Err(TransactionError::CapabilityDenied) {
                        denied += 1;
                    }
                }
                (completed, denied, host_set_capabilities(0xFF, 0, 0, 0))
            });
            assert_eq!(completed, 200);
            assert_eq!(denied, 200);
            assert_eq!(caps_after, Ok(()));
            return;
        }
        run_in_child("tests::test_repeated_transactions_leave_no_stale_state_through_the_ffi", CHILD_ENV);
    }

    /// I-01: 4 threads x 15 transactions x 10 tokens on one domain all
    /// complete (600 of 900 spendable), and draining the rest in tens gives
    /// exactly 30 more plus the refill allowance.
    #[test]
    fn test_concurrent_transactions_sum_exactly_through_the_ffi() {
        const CHILD_ENV: &str = "STACK_FFI_SUM_CHILD";
        if std::env::var_os(CHILD_ENV).is_some() {
            const THREADS: usize = 4;
            const PER_THREAD: usize = 15;
            const TOKENS: u32 = 10;
            on_sealed_thread(|| assert_eq!(host_set_capabilities(0xFF, 0, 0, 0), Ok(())));
            let runs_before = host_payload_count();
            let t0 = std::time::Instant::now();
            let go = std::sync::Arc::new(std::sync::Barrier::new(THREADS));
            let workers: std::vec::Vec<_> = (0..THREADS)
                .map(|_| {
                    let go = go.clone();
                    std::thread::spawn(move || {
                        assert!(host_initialize_and_seal().is_ok(), "seal");
                        go.wait();
                        (0..PER_THREAD).filter(|_| txn(4, 0x01, TOKENS) == Ok(())).count()
                    })
                })
                .collect();
            let completed: usize = workers.into_iter().map(|w| w.join().expect("worker")).sum();
            let (drained, last) = on_sealed_thread(|| consume_until_rate_limited(4, TOKENS, 200));
            let elapsed_ms = t0.elapsed().as_millis() as usize;
            assert_eq!(completed, THREADS * PER_THREAD);
            assert_eq!(last, Err(TransactionError::RateLimited));
            let expected_rest = ((SPENDABLE as usize) - THREADS * PER_THREAD * TOKENS as usize) / TOKENS as usize; // 30
            assert!(drained >= expected_rest, "drained {drained}");
            assert!(drained <= expected_rest + elapsed_ms / TOKENS as usize + 1, "drained {drained} in {elapsed_ms} ms");
            assert_eq!(host_payload_count() - runs_before, (completed + drained) as u64);
            return;
        }
        run_in_child("tests::test_concurrent_transactions_sum_exactly_through_the_ffi", CHILD_ENV);
    }

    /// I-01: a failed transaction leaves no TransactionCompleted record in the
    /// host's audit trail; only the completed one does.
    #[test]
    fn test_failed_transaction_leaves_no_success_audit_record_through_the_ffi() {
        const CHILD_ENV: &str = "STACK_FFI_AUDIT_CHILD";
        if std::env::var_os(CHILD_ENV).is_some() {
            const DOMAIN: u64 = 5;
            let (denied, limited, ok) = on_sealed_thread(|| {
                assert_eq!(host_set_capabilities(0xFF, 0, 0, 0), Ok(()));
                let denied = txn(DOMAIN, 0x100, 1);
                let limited = txn(DOMAIN, 0x01, LARGEST_REQUEST + 1);
                let ok = txn(DOMAIN, 0x01, 1);
                (denied, limited, ok)
            });
            assert_eq!(denied, Err(TransactionError::CapabilityDenied));
            assert_eq!(limited, Err(TransactionError::RateLimited));
            assert_eq!(ok, Ok(()));
            let mut completed = 0;
            let mut rate_limited = 0;
            let mut violations = 0;
            for index in 0..8192u64 {
                if let Some(rec) = host_audit_read_slot(index) {
                    if rec.context_id != DOMAIN {
                        continue;
                    }
                    match rec.event {
                        HostAuditEvent::TransactionCompleted => completed += 1,
                        HostAuditEvent::RateLimitTriggered => rate_limited += 1,
                        HostAuditEvent::CapabilityViolation => violations += 1,
                        other => panic!("unexpected event {other:?}"),
                    }
                }
            }
            assert_eq!((violations, rate_limited, completed), (1, 1, 1));
            return;
        }
        run_in_child("tests::test_failed_transaction_leaves_no_success_audit_record_through_the_ffi", CHILD_ENV);
    }

    /// I-02 (decision B): a transaction on a thread that has not sealed
    /// itself is refused with ThreadNotSealed and the thread is left as it
    /// was (it can still open files, which a sealed thread cannot). A
    /// capability update needs initialization, not a seal.
    #[test]
    fn test_unsealed_thread_is_refused_and_not_sealed_as_a_side_effect() {
        const CHILD_ENV: &str = "STACK_FFI_UNSEALED_CHILD";
        const PROBE: &str = "/proc/self/stat";
        if std::env::var_os(CHILD_ENV).is_some() {
            assert_eq!(host_initialize(), Ok(()));
            assert_eq!(host_set_capabilities(0xFF, 0, 0, 0), Ok(()));
            let runs_before = host_payload_count();
            assert_eq!(txn(1, 0x01, 1), Err(TransactionError::ThreadNotSealed));
            assert_eq!(host_payload_count(), runs_before, "a refused transaction runs no payload");
            assert!(std::fs::File::open(PROBE).is_ok(), "the refused thread must stay unsealed");
            // Sealing is explicit, per thread, and then the transaction runs.
            let (sealed, result, blocked) = std::thread::spawn(|| {
                let sealed = host_seal_current_thread();
                let result = txn(1, 0x01, 1);
                let blocked = std::fs::File::open(PROBE).is_err();
                (sealed, result, blocked)
            })
            .join()
            .expect("sealed thread");
            assert_eq!(sealed, Ok(()));
            assert_eq!(result, Ok(()));
            assert!(blocked, "the thread that asked to be sealed is filtered");
            assert_eq!(host_payload_count(), runs_before + 1);
            assert!(std::fs::File::open(PROBE).is_ok(), "sealing another thread does not reach this one");
            return;
        }
        run_in_child("tests::test_unsealed_thread_is_refused_and_not_sealed_as_a_side_effect", CHILD_ENV);
    }

    /// I-02: initialization is idempotent and safe to race; a seal is
    /// idempotent on its thread.
    #[test]
    fn test_initialization_is_idempotent_and_concurrent_callers_agree() {
        const CHILD_ENV: &str = "STACK_FFI_IDEMPOTENT_CHILD";
        if std::env::var_os(CHILD_ENV).is_some() {
            let barrier = std::sync::Arc::new(std::sync::Barrier::new(16));
            let workers: std::vec::Vec<_> = (0..16)
                .map(|_| {
                    let barrier = barrier.clone();
                    std::thread::spawn(move || {
                        barrier.wait();
                        host_initialize()
                    })
                })
                .collect();
            for w in workers {
                assert_eq!(w.join().expect("worker"), Ok(()));
            }
            for _ in 0..100 {
                assert_eq!(host_initialize(), Ok(()));
            }
            let seals = on_sealed_thread(|| {
                (0..100).filter(|_| host_seal_current_thread() == Ok(())).count()
                    + (0..100).filter(|_| host_initialize_and_seal() == Ok(())).count()
            });
            assert_eq!(seals, 200);
            return;
        }
        run_in_child("tests::test_initialization_is_idempotent_and_concurrent_callers_agree", CHILD_ENV);
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
