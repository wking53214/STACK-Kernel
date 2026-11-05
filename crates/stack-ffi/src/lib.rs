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
    pub fn stack_supervised_run_governed(
        context_id: u64,
        required_capability_m0: u64,
        required_tokens: u32,
        payload_kind: u32,
        worker_path: *const core::ffi::c_char,
        worker_sha256: *const u8,
        limits: *const SupervisedLimitsFfi,
        reap_timeout_ns: u64,
        out: *mut u8,
        out_capacity: usize,
        report: *mut SupervisedReportFfi,
    ) -> i32;
    pub fn stack_supervised_image_sha256(path: *const core::ffi::c_char, out: *mut u8) -> i32;
    pub fn stack_supervised_unconfirmed_count() -> u64;
    pub fn stack_supervised_reap_unconfirmed() -> u64;
}

/// Absolute path of the `stack_worker` program this build compiled (static,
/// built by `build.rs` from `cpp/worker/stack_worker.cpp`). For tests and
/// development. A production kernel names its own worker by absolute path in
/// its configuration; nothing here is read from the environment.
pub const WORKER_BUILD_PATH: &str = env!("STACK_WORKER_BUILD_PATH");

/// Absolute path of the test build of the worker, which carries kinds that
/// misbehave on purpose (forged frames, self kill, denied syscalls). Tests
/// only; never a production worker.
#[doc(hidden)]
pub const TESTING_WORKER_PATH: &str = env!("STACK_WORKER_TEST_BUILD_PATH");

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
    /// 1 when result bytes were delivered: the worker's own claim.
    pub result_self_reported: u8,
    pub reserved: [u8; 2],
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
/// Ok means the mask is applied and no transaction is running, or will run,
/// with the old one (I-04). The call holds new transactions out
/// (`TransactionError::CapabilityChangePending`) while it waits up to 500 ms
/// for the ones in flight to drain, so it applies under steady load. If they
/// do not drain in time it returns `TransactionInFlight`: the mask was NOT
/// applied, nothing is left pending, and the caller retries or escalates. Do
/// not call it from inside a payload. It needs a completed
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
            -13 => Err(TransactionError::CapabilityChangePending),
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
    /// SIGCHLD is ignored in this process (SIG_IGN or SA_NOCLDWAIT), so the
    /// run could not be supervised; refused before anything was spawned.
    SigchldIgnored,
    /// The worker was sent SIGKILL and was not reaped within the bound; it may
    /// still be running. Never a success. `supervised_unconfirmed_count`
    /// says how many such workers are tracked.
    TerminationUnconfirmed,
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
            11 => SupervisedOutcome::SigchldIgnored,
            12 => SupervisedOutcome::TerminationUnconfirmed,
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
    /// True when result bytes were delivered (`Completed`). They are the
    /// worker's own claim: an untrusted process wrote them, and nothing beyond
    /// "a well-formed frame came from a process that exited 0 in time" may be
    /// inferred from them.
    pub result_self_reported: bool,
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

/// LEGACY. Runs a built-in payload in a supervised child process that is a
/// fork of this process, with a wall-clock deadline that ends in SIGKILL, and
/// returns the classified report. The result bytes land at the start of `out`.
///
/// NOT for untrusted payloads and ungoverned: the child holds a copy of this
/// process's memory, and no capability or rate-limit check is made. Use
/// [`supervised_run_governed`], which runs a separate worker program after
/// those checks. Kept so existing callers keep linking.
///
/// Forking a multithreaded process copies only the calling thread; a child
/// that deadlocks on a lock another thread held is killed at the deadline
/// and reported `TimedOut`, never `Completed`.
///
/// This is an `unsafe fn` (R2-K-22) so that safe code cannot reach the
/// ungoverned path by accident. The C symbol `stack_supervised_run` keeps its
/// name and signature for ABI compatibility; nothing in this repository calls
/// it except this crate's own tests.
///
/// # Safety
///
/// The caller takes responsibility for everything the governed entry would
/// have checked: it is NOT checked against the capability mask or the rate
/// limit, it writes no audit event, and the payload runs in a fork of this
/// process with a copy of its memory. Call it only for a trusted, built-in
/// payload, from a process that can tolerate `fork`, and never for a payload
/// that came from outside. Use [`supervised_run_governed`] otherwise.
///
/// ```compile_fail,E0133
/// // R2-K-22: the ungoverned run is not callable from safe code.
/// let limits = stack_ffi::SupervisedLimits {
///     wall_clock_deadline_ns: 1_000_000_000,
///     cpu_seconds: 0,
///     address_space_bytes: 1 << 30,
///     max_output_bytes: 64,
///     file_size_bytes: 0,
///     nofile: 0,
/// };
/// let mut out = [0u8; 64];
/// let _ = stack_ffi::supervised_run(stack_ffi::PayloadKind::ReturnBytes, &limits, &mut out);
/// ```
pub unsafe fn supervised_run(
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
            result_self_reported: ffi_report.result_self_reported != 0,
        }),
        -1 => Err(SupervisedCallError::NullArgument),
        -2 => Err(SupervisedCallError::UnknownPayloadKind),
        other => Err(SupervisedCallError::Unrecognized(other)),
    }
}

/// A governed supervised run: the same context, capability and token
/// arguments as [`execute_governed_transaction`], plus the worker to run.
#[derive(Debug, Clone, Copy)]
pub struct GovernedSupervisedRequest<'a> {
    /// The rate-limit domain (0..16).
    pub context_id: u64,
    /// The capability bits the run requires. Must name at least one bit: a
    /// request that names none would pass any mask and is refused.
    pub required_capability_m0: u64,
    /// Tokens the run costs (at most 100). Spent when a worker was spawned.
    pub required_tokens: u32,
    /// Which built-in worker kind to run.
    pub kind: PayloadKind,
    /// ABSOLUTE path of the worker program, from kernel configuration. No
    /// symlink may be in the path (where the kernel has `openat2`).
    pub worker_path: &'a core::ffi::CStr,
    /// The SHA-256 the configuration pins for the worker image (R2-K-21).
    /// REQUIRED: `None` is refused ([`GovernedSupervisedError::WorkerDigestRequired`])
    /// and nothing is spawned. Take it from a release record; see
    /// [`worker_image_sha256`] for provisioning and tests.
    pub worker_sha256: Option<[u8; 32]>,
    /// Bound on the wait for a killed worker to be reaped; 0 means 2 s.
    pub reap_timeout_ns: u64,
}

/// Why a governed supervised run was refused. In every case nothing was
/// spawned and nothing was consumed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GovernedSupervisedError {
    /// The host is not initialized (call [`host_initialize`] first).
    NotInitialized,
    /// Initialization failed (latched).
    InitializationFailed,
    /// The C side does not know this payload kind.
    UnknownPayloadKind,
    /// A null pointer reached the C side.
    NullArgument,
    /// The capability mask does not cover the request, or it names no bit.
    CapabilityDenied,
    /// Rate limited, a request above 100 tokens, or an unknown domain.
    RateLimited,
    /// The wall-clock deadline was zero.
    InvalidDeadline,
    /// A capability change is pending; retry.
    CapabilityChangePending,
    /// The worker path is null, relative, missing, a symlink (anywhere in the
    /// path), not a regular executable file, setuid, setgid, group-writable,
    /// world-writable, or owned by someone else.
    WorkerUnavailable,
    /// The other limits are invalid (deadline above an hour, output above the
    /// buffer or 1 MiB, reap bound above a minute).
    InvalidLimits,
    /// No worker image digest was supplied. The governed path fails closed.
    WorkerDigestRequired,
    /// The image at the worker path does not hash to the pinned digest.
    WorkerDigestMismatch,
    /// A code this crate does not know.
    Unrecognized(i32),
}

/// SHA-256 of the file at `path`, for provisioning a configuration and for
/// tests. It applies no trust policy: it hashes any readable regular file. A
/// production deployment pins a digest from its release record, not one
/// computed from the file it is about to trust. `None` if the file cannot be
/// read.
pub fn worker_image_sha256(path: &core::ffi::CStr) -> Option<[u8; 32]> {
    let mut out = [0u8; 32];
    // SAFETY: `path` is NUL terminated and `out` is 32 writable bytes.
    let rc = unsafe { stack_supervised_image_sha256(path.as_ptr(), out.as_mut_ptr()) };
    (rc == 0).then_some(out)
}

/// Runs a built-in worker kind in a separate worker PROGRAM (fork then exec;
/// the worker has none of this process's memory, an empty environment, and
/// only descriptors 0 to 2 and its result pipe) after the capability and
/// rate-limit checks of the initialized host, with a wall-clock deadline that
/// ends in SIGKILL. `Err` means the request was refused before anything was
/// spawned. `Ok` carries the outcome, which may be any [`SupervisedOutcome`],
/// timeouts and `TerminationUnconfirmed` included; one audit event records it
/// (see [`host_audit_read_slot`]).
///
/// `Completed` means the worker exited 0 within the deadline and sent a
/// well-formed frame. The bytes are self-reported (`result_self_reported`).
/// Do not call this from a sealed thread (it fails with `WorkerUnavailable`).
pub fn supervised_run_governed(
    request: &GovernedSupervisedRequest<'_>,
    limits: &SupervisedLimits,
    out: &mut [u8],
) -> Result<SupervisedReport, GovernedSupervisedError> {
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
        stack_supervised_run_governed(
            request.context_id,
            request.required_capability_m0,
            request.required_tokens,
            request.kind.code(),
            request.worker_path.as_ptr(),
            request.worker_sha256.as_ref().map_or(core::ptr::null(), |d| d.as_ptr()),
            &ffi_limits,
            request.reap_timeout_ns,
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
            result_self_reported: ffi_report.result_self_reported != 0,
        }),
        -1 => Err(GovernedSupervisedError::NotInitialized),
        -2 => Err(GovernedSupervisedError::UnknownPayloadKind),
        -3 => Err(GovernedSupervisedError::NullArgument),
        -4 => Err(GovernedSupervisedError::CapabilityDenied),
        -5 => Err(GovernedSupervisedError::RateLimited),
        -9 => Err(GovernedSupervisedError::InvalidDeadline),
        -12 => Err(GovernedSupervisedError::InitializationFailed),
        -13 => Err(GovernedSupervisedError::CapabilityChangePending),
        -14 => Err(GovernedSupervisedError::WorkerUnavailable),
        -15 => Err(GovernedSupervisedError::InvalidLimits),
        -16 => Err(GovernedSupervisedError::WorkerDigestRequired),
        -17 => Err(GovernedSupervisedError::WorkerDigestMismatch),
        other => Err(GovernedSupervisedError::Unrecognized(other)),
    }
}

/// Supervised workers that were sent SIGKILL and not yet confirmed reaped
/// (outcome [`SupervisedOutcome::TerminationUnconfirmed`]). They may still be
/// running.
pub fn supervised_unconfirmed_count() -> u64 {
    unsafe { stack_supervised_unconfirmed_count() }
}

/// Re-sends SIGKILL to each unconfirmed worker and reaps the ones that have
/// gone. Returns how many remain unconfirmed.
pub fn supervised_reap_unconfirmed() -> u64 {
    unsafe { stack_supervised_reap_unconfirmed() }
}

/// Safe wrapper for audit ring push
pub fn audit_push(event_type: u8, context_id: u64, tokens: u32) {
    unsafe {
        stack_audit_push(event_type, context_id, tokens);
    }
}

/// Safe wrapper for audit ring read. `Some` for a slot that holds a record,
/// `None` for a slot that was never written (R2-K-09: this was inverted).
pub fn audit_read_slot(index: u64) -> Option<AuditRecord> {
    unsafe {
        let mut timestamp = 0u64;
        let mut context_id = 0u64;
        let mut tokens = 0u32;
        
        if stack_audit_read_slot(index, &mut timestamp, &mut context_id, &mut tokens) == 0 {
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
    /// A supervised worker run completed (exit 0 in time, well-formed frame).
    SupervisedCompleted,
    /// A supervised worker run passed its wall-clock deadline and was killed.
    SupervisedTimedOut,
    /// A supervised worker run ended any other way, or nothing was spawned.
    SupervisedFailed,
    /// A supervised worker was killed and not confirmed reaped in time.
    SupervisedTerminationUnconfirmed,
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
            5 => HostAuditEvent::SupervisedCompleted,
            6 => HostAuditEvent::SupervisedTimedOut,
            7 => HostAuditEvent::SupervisedFailed,
            8 => HostAuditEvent::SupervisedTerminationUnconfirmed,
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
    /// The transactions in flight did not drain within the bound (500 ms); the
    /// mask was not changed and nothing is left pending (I-04).
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
    /// A capability change (a revocation) is waiting for the transactions in
    /// flight to drain and holds new ones out (I-04). Nothing ran and nothing
    /// was consumed. Retry.
    CapabilityChangePending,
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

    /// I-03: a transaction whose payload ran but overran its software budget
    /// keeps its tokens: 8 more requests of 100 follow instead of 9.
    #[test]
    fn test_overrun_keeps_its_tokens_through_the_ffi() {
        const CHILD_ENV: &str = "STACK_FFI_OVERRUN_CHILD";
        if std::env::var_os(CHILD_ENV).is_some() {
            let (overrun, runs_delta, completed, last, elapsed_ms) = on_sealed_thread(|| {
                assert_eq!(host_set_capabilities(0xFF, 0, 0, 0), Ok(()));
                let t0 = std::time::Instant::now();
                let before = host_payload_count();
                let overrun = execute_governed_transaction(6, 0x01, LARGEST_REQUEST, 1, ONE_SECOND_NS);
                let runs_delta = host_payload_count() - before;
                let (completed, last) = consume_until_rate_limited(6, LARGEST_REQUEST, 50);
                (overrun, runs_delta, completed, last, t0.elapsed().as_millis() as usize)
            });
            assert_eq!(overrun, Err(TransactionError::SoftwareDeadline));
            assert_eq!(runs_delta, 1, "the overrun payload ran");
            assert_eq!(last, Err(TransactionError::RateLimited));
            let expected = (SPENDABLE / LARGEST_REQUEST) as usize - 1; // 8
            assert!(completed >= expected, "completed {completed}");
            assert!(completed <= expected + elapsed_ms / 100 + 1, "completed {completed} in {elapsed_ms} ms");
            return;
        }
        run_in_child("tests::test_overrun_keeps_its_tokens_through_the_ffi", CHILD_ENV);
    }

    /// I-04 (R2-K-07): a revocation applies under sustained load from eight
    /// sealed executor threads, within a bound, and no transaction that begins
    /// after it returned runs its payload. Executors ask for one token each (zero
    /// became a rate limit refusal in R2-K-20); a domain's first 900 requests
    /// are served at once.
    #[test]
    fn test_revocation_applies_under_sustained_load_through_the_ffi() {
        use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
        use std::sync::Arc;
        const CHILD_ENV: &str = "STACK_FFI_REVOKE_CHILD";
        if std::env::var_os(CHILD_ENV).is_some() {
            const DOMAINS: [u64; 8] = [0, 9, 10, 11, 12, 13, 14, 15];
            assert_eq!(host_initialize(), Ok(()));
            assert_eq!(host_set_capabilities(0xFF, 0, 0, 0), Ok(()));
            let stop = Arc::new(AtomicBool::new(false));
            let revoked = Arc::new(AtomicBool::new(false));
            let sealed = Arc::new(AtomicU64::new(0));
            let started_after = Arc::new(AtomicU64::new(0));
            let ran_after = Arc::new(AtomicU64::new(0));
            let refused_after = Arc::new(AtomicU64::new(0));
            let mut executors = std::vec::Vec::new();
            for domain in DOMAINS {
                let (stop, revoked, sealed) = (stop.clone(), revoked.clone(), sealed.clone());
                let (started_after, ran_after, refused_after) =
                    (started_after.clone(), ran_after.clone(), refused_after.clone());
                executors.push(std::thread::spawn(move || {
                    assert!(host_initialize_and_seal().is_ok(), "seal");
                    sealed.fetch_add(1, Ordering::SeqCst);
                    while !stop.load(Ordering::Relaxed) {
                        let after = revoked.load(Ordering::Acquire);
                        let r = txn(domain, 0x01, 1);
                        if after {
                            started_after.fetch_add(1, Ordering::Relaxed);
                            match r {
                                Ok(()) => {
                                    ran_after.fetch_add(1, Ordering::Relaxed);
                                }
                                Err(TransactionError::CapabilityDenied) => {
                                    refused_after.fetch_add(1, Ordering::Relaxed);
                                }
                                Err(_) => {}
                            }
                        }
                    }
                }));
            }
            let wait = std::time::Instant::now();
            while sealed.load(Ordering::SeqCst) < 8 && wait.elapsed().as_secs() < 5 {}
            let at_start = host_payload_count();
            while host_payload_count() < at_start + 100 && wait.elapsed().as_secs() < 5 {}

            let t0 = std::time::Instant::now();
            let mut r = Err(CapabilityError::TransactionInFlight);
            while r == Err(CapabilityError::TransactionInFlight) && t0.elapsed().as_millis() < 1000 {
                r = host_set_capabilities(0, 0, 0, 0);
            }
            let applied_ms = t0.elapsed().as_millis();
            let payloads_when_applied = host_payload_count();
            revoked.store(true, Ordering::Release);

            let after_start = std::time::Instant::now();
            while started_after.load(Ordering::Relaxed) < 1000 && after_start.elapsed().as_secs() < 2 {}
            stop.store(true, Ordering::Relaxed);
            for e in executors {
                e.join().expect("executor");
            }
            let payloads_at_end = host_payload_count();

            assert_eq!(r, Ok(()), "revocation not applied after {applied_ms} ms");
            assert!(applied_ms < 1000, "applied after {applied_ms} ms");
            assert!(payloads_when_applied > at_start, "payloads ran under the load");
            assert!(started_after.load(Ordering::Relaxed) >= 1000);
            assert_eq!(ran_after.load(Ordering::Relaxed), 0, "a transaction ran after the revocation");
            assert_eq!(refused_after.load(Ordering::Relaxed), started_after.load(Ordering::Relaxed));
            assert_eq!(payloads_at_end, payloads_when_applied, "a payload ran after the revocation");
            // Restoring applies at once and the host serves.
            assert_eq!(host_set_capabilities(0xFF, 0, 0, 0), Ok(()));
            assert_eq!(on_sealed_thread(|| txn(1, 0x01, 1)), Ok(()));
            return;
        }
        run_in_child("tests::test_revocation_applies_under_sustained_load_through_the_ffi", CHILD_ENV);
    }

    /// R2-K-09 (step 5): audit_read_slot reported the opposite of the C code.
    /// The C function returns 0 for a slot that holds a record, and the
    /// wrapper tested `!= 0`, so a written slot read as None and an empty
    /// slot as Some(zeros). Only this test pushes to the free-standing ring.
    #[test]
    fn test_audit_read_slot_returns_the_record_of_a_written_slot() {
        const CONTEXT: u64 = 0x00A1_1D17;
        const SLOTS: u64 = 1024; // SeccompAuditRing<1024> in ffi_wrapper.cpp
        // Nothing written yet: every slot is empty.
        let before = (0..SLOTS).filter(|&i| audit_read_slot(i).is_some()).count();
        assert_eq!(before, 0, "an empty slot must read as None");
        audit_push(0, CONTEXT, 5);
        let written: std::vec::Vec<AuditRecord> =
            (0..SLOTS).filter_map(audit_read_slot).collect();
        assert_eq!(written.len(), 1, "exactly the one written slot reads as Some");
        assert_eq!(written[0].context_id, CONTEXT);
        assert_eq!(written[0].tokens_consumed, 5);
        assert!(written[0].timestamp_ticks > 0);
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

    /// The legacy run is an `unsafe fn` (R2-K-22). These tests exercise the
    /// C++ fork path itself with built-in payloads, so they call it through
    /// this local wrapper, which shadows the glob import.
    fn supervised_run(
        kind: PayloadKind,
        limits: &SupervisedLimits,
        out: &mut [u8],
    ) -> Result<SupervisedReport, SupervisedCallError> {
        // SAFETY: built-in payloads only, in a test process.
        unsafe { super::supervised_run(kind, limits, out) }
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

    /// P2 finding 9: with SIGCHLD set to SIG_IGN the kernel reaps the child,
    /// waitpid fails with ECHILD, and even a real timeout came back as
    /// SupervisorError. The run is now refused up front with its own outcome.
    /// The disposition is process-wide, so this runs in a child copy of the
    /// test binary and cannot disturb the other tests' forks.
    #[test]
    fn test_supervised_run_is_refused_while_sigchld_is_ignored() {
        const CHILD_ENV: &str = "STACK_FFI_SIGCHLD_CHILD";
        extern "C" {
            fn signal(signum: i32, handler: usize) -> usize;
        }
        const SIGCHLD: i32 = 17;
        const SIG_IGN: usize = 1;
        if std::env::var_os(CHILD_ENV).is_some() {
            let mut out = [0u8; 64];
            let before = unsafe { signal(SIGCHLD, SIG_IGN) };
            let report = supervised_run(PayloadKind::BlockForever, &supervised_limits(), &mut out).expect("report");
            unsafe { signal(SIGCHLD, before) };
            assert_eq!(report.outcome, SupervisedOutcome::SigchldIgnored, "{report:?}");
            assert_eq!(report.child_pid, 0, "nothing may be forked");
            let after = supervised_run(PayloadKind::BlockForever, &supervised_limits(), &mut out).expect("report");
            assert_eq!(after.outcome, SupervisedOutcome::TimedOut, "the default disposition runs again");
            return;
        }
        run_in_child("tests::test_supervised_run_is_refused_while_sigchld_is_ignored", CHILD_ENV);
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

    // ----- Governed supervised runs in a clean worker (RACE-02, decision A) -----
    //
    // The host is process global and these tests set its capability mask, so
    // each runs in a child copy of the test binary (as the sealing tests do).

    fn worker_path() -> std::ffi::CString {
        std::ffi::CString::new(WORKER_BUILD_PATH).expect("worker path has no NUL")
    }

    /// The digest the configuration pins for the build's worker (R2-K-21).
    fn worker_digest() -> [u8; 32] {
        worker_image_sha256(&worker_path()).expect("hash the worker build")
    }

    fn governed_request<'a>(
        path: &'a std::ffi::CStr,
        domain: u64,
        caps: u64,
        kind: PayloadKind,
    ) -> GovernedSupervisedRequest<'a> {
        GovernedSupervisedRequest {
            context_id: domain,
            required_capability_m0: caps,
            required_tokens: LARGEST_REQUEST,
            kind,
            worker_path: path,
            worker_sha256: Some(worker_digest()),
            reap_timeout_ns: 0,
        }
    }

    /// R2-K-21: the governed call requires the digest of the worker image and
    /// refuses a program that is not the pinned one; nothing is spawned.
    #[test]
    fn test_governed_supervised_requires_the_worker_digest_and_refuses_another_program() {
        const CHILD_ENV: &str = "STACK_FFI_GOVERNED_DIGEST_CHILD";
        if std::env::var_os(CHILD_ENV).is_some() {
            let path = worker_path();
            host_initialize().expect("initialize");
            host_set_capabilities(0x01, 0, 0, 0).expect("capabilities");
            let lim = governed_limits(1_000_000_000);
            let mut out = [0u8; 64];
            let mut req = governed_request(&path, 4, 0x01, PayloadKind::ReturnBytes);
            // Unset: fail closed.
            req.worker_sha256 = None;
            assert_eq!(
                supervised_run_governed(&req, &lim, &mut out).unwrap_err(),
                GovernedSupervisedError::WorkerDigestRequired
            );
            // Wrong digest, and another program under the right digest.
            let mut wrong = worker_digest();
            wrong[0] ^= 0x80;
            req.worker_sha256 = Some(wrong);
            assert_eq!(
                supervised_run_governed(&req, &lim, &mut out).unwrap_err(),
                GovernedSupervisedError::WorkerDigestMismatch
            );
            let touch = std::ffi::CString::new("/usr/bin/touch").expect("no NUL");
            let other = governed_request(&touch, 4, 0x01, PayloadKind::ReturnBytes);
            assert_eq!(
                supervised_run_governed(&other, &lim, &mut out).unwrap_err(),
                GovernedSupervisedError::WorkerDigestMismatch
            );
            // The pinned image runs, and the tokens were not kept by the refusals.
            let (ok, ms) = served_runs(&path, 4);
            assert!(ok >= 9 && ok <= 9 + (ms / 100) as u32 + 1, "served {ok} in {ms} ms");
            return;
        }
        run_in_child("tests::test_governed_supervised_requires_the_worker_digest_and_refuses_another_program", CHILD_ENV);
    }

    #[test]
    fn test_worker_image_sha256_matches_sha256sum_and_fails_for_a_missing_file() {
        let digest = worker_digest();
        let hex: std::string::String = digest.iter().map(|b| std::format!("{b:02x}")).collect();
        let out = std::process::Command::new("sha256sum").arg(WORKER_BUILD_PATH).output().expect("sha256sum");
        let text = std::string::String::from_utf8(out.stdout).expect("utf8");
        assert_eq!(&text[..64], hex);
        let missing = std::ffi::CString::new("/nonexistent/stack_worker").expect("no NUL");
        assert_eq!(worker_image_sha256(&missing), None);
    }

    fn governed_limits(deadline_ns: u64) -> SupervisedLimits {
        SupervisedLimits {
            wall_clock_deadline_ns: deadline_ns,
            cpu_seconds: 0,
            address_space_bytes: 1 << 30,
            max_output_bytes: 64,
            file_size_bytes: 0,
            nofile: 0,
        }
    }

    /// How many 100-token governed supervised runs a domain serves before it
    /// is rate limited: 9 from a full bucket, plus one per 100 ms of refill.
    fn served_runs(path: &std::ffi::CStr, domain: u64) -> (u32, u128) {
        let t0 = std::time::Instant::now();
        let mut out = [0u8; 64];
        let mut ok = 0;
        for _ in 0..40 {
            match supervised_run_governed(
                &governed_request(path, domain, 0x01, PayloadKind::ReturnBytes),
                &governed_limits(2_000_000_000),
                &mut out,
            ) {
                Ok(r) => {
                    assert_eq!(r.outcome, SupervisedOutcome::Completed);
                    ok += 1;
                }
                Err(GovernedSupervisedError::RateLimited) => break,
                Err(e) => panic!("unexpected refusal {e:?}"),
            }
        }
        (ok, t0.elapsed().as_millis())
    }

    fn audit_count(domain: u64, event: HostAuditEvent) -> usize {
        (0..8192u64)
            .filter_map(host_audit_read_slot)
            .filter(|r| r.context_id == domain && r.event == event)
            .count()
    }

    /// The enum mapping, including the new code.
    #[test]
    fn test_supervised_outcome_codes_map_including_termination_unconfirmed() {
        assert_eq!(SupervisedOutcome::from_code(0), SupervisedOutcome::Completed);
        assert_eq!(SupervisedOutcome::from_code(11), SupervisedOutcome::SigchldIgnored);
        assert_eq!(SupervisedOutcome::from_code(12), SupervisedOutcome::TerminationUnconfirmed);
        assert_eq!(SupervisedOutcome::from_code(13), SupervisedOutcome::Unrecognized(13));
        assert_eq!(HostAuditEvent::from_code(5), HostAuditEvent::SupervisedCompleted);
        assert_eq!(HostAuditEvent::from_code(6), HostAuditEvent::SupervisedTimedOut);
        assert_eq!(HostAuditEvent::from_code(7), HostAuditEvent::SupervisedFailed);
        assert_eq!(HostAuditEvent::from_code(8), HostAuditEvent::SupervisedTerminationUnconfirmed);
        assert_eq!(HostAuditEvent::from_code(9), HostAuditEvent::Unrecognized(9));
    }

    #[test]
    fn test_governed_supervised_completes_self_reported_and_is_audited() {
        const CHILD_ENV: &str = "STACK_FFI_GOVERNED_OK_CHILD";
        if std::env::var_os(CHILD_ENV).is_some() {
            let path = worker_path();
            host_initialize().expect("initialize");
            host_set_capabilities(0x01, 0, 0, 0).expect("capabilities");
            let mut out = [0u8; 64];
            let r = supervised_run_governed(
                &governed_request(&path, 3, 0x01, PayloadKind::ReturnBytes),
                &governed_limits(2_000_000_000),
                &mut out,
            )
            .expect("governed run");
            assert_eq!(r.outcome, SupervisedOutcome::Completed);
            assert!(r.result_self_reported, "the result is the worker's own claim");
            assert!(r.child_pid > 0 && r.child_pid != std::process::id() as i32);
            let n = usize::try_from(r.result_length).expect("length");
            assert_eq!(&out[..n], SUPERVISED_PAYLOAD_BYTES);
            assert_eq!(audit_count(3, HostAuditEvent::SupervisedCompleted), 1);
            assert_eq!(supervised_unconfirmed_count(), 0);
            // 100 tokens were spent: at most 8 (plus refill) more.
            let (ok, ms) = served_runs(&path, 3);
            assert!(ok <= 8 + (ms / 100) as u32 + 1, "served {ok} in {ms} ms");
            return;
        }
        run_in_child("tests::test_governed_supervised_completes_self_reported_and_is_audited", CHILD_ENV);
    }

    #[test]
    fn test_governed_supervised_refusals_spawn_nothing_and_consume_nothing() {
        const CHILD_ENV: &str = "STACK_FFI_GOVERNED_REFUSE_CHILD";
        if std::env::var_os(CHILD_ENV).is_some() {
            let path = worker_path();
            let mut out = [0u8; 64];
            // Before initialization.
            assert_eq!(
                supervised_run_governed(
                    &governed_request(&path, 4, 0x01, PayloadKind::ReturnBytes),
                    &governed_limits(1_000_000_000),
                    &mut out
                )
                .unwrap_err(),
                GovernedSupervisedError::NotInitialized
            );
            host_initialize().expect("initialize");
            host_set_capabilities(0x01, 0, 0, 0).expect("capabilities");
            let lim = governed_limits(1_000_000_000);
            let req = |caps| governed_request(&path, 4, caps, PayloadKind::ReturnBytes);
            // Invalid capability, and a request that names none.
            assert_eq!(supervised_run_governed(&req(0x02), &lim, &mut out).unwrap_err(), GovernedSupervisedError::CapabilityDenied);
            assert_eq!(supervised_run_governed(&req(0), &lim, &mut out).unwrap_err(), GovernedSupervisedError::CapabilityDenied);
            assert!(audit_count(4, HostAuditEvent::CapabilityViolation) >= 1);
            // A zero deadline.
            assert_eq!(
                supervised_run_governed(&req(0x01), &governed_limits(0), &mut out).unwrap_err(),
                GovernedSupervisedError::InvalidDeadline
            );
            // Worker paths: relative, missing, not executable.
            for bad in ["stack_worker", "/nonexistent/stack_worker", "/etc/hostname"] {
                let p = std::ffi::CString::new(bad).expect("no NUL");
                assert_eq!(
                    supervised_run_governed(&governed_request(&p, 4, 0x01, PayloadKind::ReturnBytes), &lim, &mut out).unwrap_err(),
                    GovernedSupervisedError::WorkerUnavailable,
                    "{bad}"
                );
            }
            // Output cap above the buffer.
            let mut big = governed_limits(1_000_000_000);
            big.max_output_bytes = 65;
            assert_eq!(supervised_run_governed(&req(0x01), &big, &mut out).unwrap_err(), GovernedSupervisedError::InvalidLimits);
            // Nothing above spent a token: the domain still serves its full 9.
            let (ok, ms) = served_runs(&path, 4);
            assert!(ok >= 9 && ok <= 9 + (ms / 100) as u32 + 1, "served {ok} in {ms} ms");
            // Exhausted now: refused, and the audit ring says so.
            assert_eq!(
                supervised_run_governed(&req(0x01), &lim, &mut out).unwrap_err(),
                GovernedSupervisedError::RateLimited
            );
            assert!(audit_count(4, HostAuditEvent::RateLimitTriggered) >= 1);
            return;
        }
        run_in_child("tests::test_governed_supervised_refusals_spawn_nothing_and_consume_nothing", CHILD_ENV);
    }

    #[test]
    fn test_governed_supervised_timeouts_are_killed_audited_and_leave_nothing_behind() {
        const CHILD_ENV: &str = "STACK_FFI_GOVERNED_TIMEOUT_CHILD";
        if std::env::var_os(CHILD_ENV).is_some() {
            let path = worker_path();
            host_initialize().expect("initialize");
            host_set_capabilities(0x01, 0, 0, 0).expect("capabilities");
            let deadline = 150_000_000u64;
            let mut out = [0u8; 64];
            let mut worst = 0u64;
            for (i, kind) in [PayloadKind::SpinForever, PayloadKind::BlockForever].into_iter().enumerate() {
                let mut req = governed_request(&path, 5 + i as u64, 0x01, kind);
                req.required_tokens = 1;
                let r = supervised_run_governed(&req, &governed_limits(deadline), &mut out).expect("report");
                assert_eq!(r.outcome, SupervisedOutcome::TimedOut);
                assert!(r.deadline_fired && !r.result_self_reported);
                assert!(r.elapsed_ns >= deadline && r.elapsed_ns <= deadline + 1_000_000_000);
                worst = worst.max(r.elapsed_ns);
                assert_eq!(audit_count(5 + i as u64, HostAuditEvent::SupervisedTimedOut), 1);
                assert_eq!(audit_count(5 + i as u64, HostAuditEvent::SupervisedCompleted), 0);
            }
            std::eprintln!("[measured] rust governed timeouts at 150 ms: worst {} ms", worst / 1_000_000);
            // The other ways to end are never Completed.
            for kind in [PayloadKind::Crash, PayloadKind::Abort, PayloadKind::ExitNonZero, PayloadKind::ForbiddenSyscall] {
                let mut req = governed_request(&path, 7, 0x01, kind);
                req.required_tokens = 1;
                let r = supervised_run_governed(&req, &governed_limits(2_000_000_000), &mut out).expect("report");
                assert_ne!(r.outcome, SupervisedOutcome::Completed, "{kind:?}");
                assert!(!r.result_self_reported);
            }
            assert_eq!(audit_count(7, HostAuditEvent::SupervisedFailed), 4);
            assert_eq!(supervised_unconfirmed_count(), 0);
            return;
        }
        run_in_child("tests::test_governed_supervised_timeouts_are_killed_audited_and_leave_nothing_behind", CHILD_ENV);
    }

    #[test]
    fn test_governed_supervised_repeated_timeouts_leave_no_zombie_and_no_descriptor() {
        const CHILD_ENV: &str = "STACK_FFI_GOVERNED_LEAK_CHILD";
        if std::env::var_os(CHILD_ENV).is_some() {
            let fd_count = || std::fs::read_dir("/proc/self/fd").expect("fd dir").count();
            // Children of every thread of this process; a zombie still counts.
            let children = || {
                let mut n = 0;
                for task in std::fs::read_dir("/proc/self/task").expect("task dir").flatten() {
                    let text = std::fs::read_to_string(task.path().join("children")).unwrap_or_default();
                    n += text.split_whitespace().count();
                }
                n
            };
            let path = worker_path();
            host_initialize().expect("initialize");
            host_set_capabilities(0x01, 0, 0, 0).expect("capabilities");
            let mut out = [0u8; 64];
            // Warm up so lazily opened descriptors are not counted as leaks.
            let mut warm = governed_request(&path, 0, 0x01, PayloadKind::ReturnBytes);
            warm.required_tokens = 1;
            supervised_run_governed(&warm, &governed_limits(2_000_000_000), &mut out).expect("warm-up");
            let before = fd_count();
            let mut worst = 0u64;
            for i in 0..50u64 {
                let kind = if i % 2 == 0 { PayloadKind::SpinForever } else { PayloadKind::BlockForever };
                let mut req = governed_request(&path, i % 2, 0x01, kind);
                req.required_tokens = 1;
                let r = supervised_run_governed(&req, &governed_limits(40_000_000), &mut out).expect("report");
                assert_eq!(r.outcome, SupervisedOutcome::TimedOut);
                worst = worst.max(r.elapsed_ns);
            }
            std::eprintln!("[measured] rust 50 governed timeouts at 40 ms: worst {} ms", worst / 1_000_000);
            assert!(worst <= 40_000_000 + 1_000_000_000);
            assert_eq!(children(), 0, "no zombie and no child left");
            assert_eq!(supervised_unconfirmed_count(), 0);
            assert_eq!(fd_count(), before, "no descriptor leaked");
            return;
        }
        run_in_child("tests::test_governed_supervised_repeated_timeouts_leave_no_zombie_and_no_descriptor", CHILD_ENV);
    }
}
