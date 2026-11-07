//! The executor seam: the one place this crate touches `stack-ffi`.
//!
//! The pipeline runs a worker through the [`Executor`] trait and reads
//! back a [`RunReport`]. [`SupervisedExecutor`] is the one real
//! implementation: the C++ supervised executor reached through
//! `stack_ffi::supervised_run_governed`. It runs a separate worker PROGRAM
//! (fork then exec: the worker has none of this process's memory, an empty
//! environment and only its result pipe) under a wall-clock deadline that
//! ends in SIGKILL, a seccomp filter the worker installs first, and rlimits,
//! after the host's capability and rate-limit checks. The worker program's
//! absolute path is kernel configuration ([`WorkerConfig`]); with none, or
//! one that is not an executable regular file, the executor cannot be built
//! and no run can start. The FFI is expected to change (host, governor,
//! init); when it does, this file is the adaptation and nothing else in the
//! crate moves.
//!
//! What a report proves: what the supervisor observed. A `Completed`
//! outcome means the worker exited 0 within the deadline and sent a
//! well-formed result frame; the result bytes are the worker's own claim
//! (`cpp/CONTAINMENT.md`), and the receipt records their digest as
//! self-reported.

use std::ffi::CString;
use std::fmt;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::Duration;

use sha2::{Digest, Sha256};
use stack_authority::{AuthorizedAction, Digest32, ExecutionBinding};

use crate::admission::{CancelToken, CancellableExecutor};

/// Longest wall-clock deadline the supervisor accepts: one hour.
pub const MAX_DEADLINE_NS: u64 = 3_600_000_000_000;
/// Largest result the supervisor accepts: 1 MiB.
pub const MAX_OUTPUT_BYTES: u64 = 1 << 20;

/// What [`WorkerKind::ReturnBytes`] sends back, so no caller names the FFI
/// crate to know it.
pub const RETURN_BYTES_RESULT: &[u8] = stack_ffi::SUPERVISED_PAYLOAD_BYTES;

/// The workers a kernel can run. The supervised executor's payloads are a
/// fixed, built-in set chosen by number (the C ABI carries no closure),
/// so the kernel's operation map points at one of these. `ReturnBytes`
/// is the one legitimate worker; the others exist to prove that the
/// pipeline reports every way a run can end.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum WorkerKind {
    /// Writes a fixed byte string and exits 0.
    ReturnBytes,
    /// Never returns: an infinite loop.
    SpinForever,
    /// Never returns: blocks in a futex wait that is never woken.
    BlockForever,
    /// Null store (SIGSEGV).
    Crash,
    /// `abort()` (SIGABRT).
    Abort,
    /// `_exit(3)`.
    ExitNonZero,
    /// `open(2)`, which the seccomp filter kills with SIGSYS.
    ForbiddenSyscall,
}

impl WorkerKind {
    /// Every kind, for configuration listings.
    pub const ALL: [Self; 7] = [
        Self::ReturnBytes,
        Self::SpinForever,
        Self::BlockForever,
        Self::Crash,
        Self::Abort,
        Self::ExitNonZero,
        Self::ForbiddenSyscall,
    ];

    /// Configuration spelling.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ReturnBytes => "return_bytes",
            Self::SpinForever => "spin_forever",
            Self::BlockForever => "block_forever",
            Self::Crash => "crash",
            Self::Abort => "abort",
            Self::ExitNonZero => "exit_non_zero",
            Self::ForbiddenSyscall => "forbidden_syscall",
        }
    }

    /// Parses the configuration spelling.
    pub fn parse(s: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|k| k.as_str() == s)
    }
}

impl fmt::Display for WorkerKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Why execution limits were refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum LimitsError {
    /// Zero, or above [`MAX_DEADLINE_NS`].
    #[error("wall_clock_deadline_ns must be 1..={MAX_DEADLINE_NS}")]
    Deadline,
    /// Zero, or above [`MAX_OUTPUT_BYTES`].
    #[error("max_output_bytes must be 1..={MAX_OUTPUT_BYTES}")]
    Output,
    /// Zero: the worker would inherit the host's address-space limit.
    #[error("address_space_bytes must be above 0; 0 would leave RLIMIT_AS inherited")]
    AddressSpace,
}

/// Domain separator hashed in front of the limits to make [`ExecutionLimits::binding_digest`].
pub const LIMITS_DIGEST_DOMAIN: &[u8] = b"stack-admission/limits/1\n";

/// What a version 2 capability binds for a run: the digest of the canonical
/// argument bytes, the worker kind's label and the digest of the limits. The
/// kernel builds it from its own parsed request and policy; an issuer builds it
/// with this function so the two agree byte for byte.
pub fn execution_binding(canonical_args: &[u8], kind: WorkerKind, limits: &ExecutionLimits) -> ExecutionBinding {
    ExecutionBinding {
        args_digest: Digest32::from_bytes(Sha256::digest(canonical_args).into()),
        worker: kind.as_str().to_owned(),
        limits_digest: limits.binding_digest(),
    }
}

/// Limits every execution runs under. Mirrors the supervisor's limits.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExecutionLimits {
    /// Wall-clock deadline; the worker is killed when it passes. Required.
    pub wall_clock_deadline_ns: u64,
    /// `RLIMIT_CPU` seconds; 0 derives one from the deadline.
    pub cpu_seconds: u64,
    /// `RLIMIT_AS` bytes; must be above 0, because 0 would keep the
    /// inherited limit ([`LimitsError::AddressSpace`]).
    pub address_space_bytes: u64,
    /// Largest accepted result, at most [`MAX_OUTPUT_BYTES`].
    pub max_output_bytes: u64,
    /// `RLIMIT_FSIZE` bytes; 0 forbids regular-file writes.
    pub file_size_bytes: u64,
    /// `RLIMIT_NOFILE`; 0 derives the floor.
    pub nofile: u32,
}

impl ExecutionLimits {
    /// Default result cap: 4 KiB.
    pub const DEFAULT_MAX_OUTPUT_BYTES: u64 = 4096;

    /// Default `RLIMIT_AS`: 4 GiB, the supervisor's own default. The limit
    /// counts the whole address space the forked worker inherits, so it
    /// must sit above what the host already maps.
    pub const DEFAULT_ADDRESS_SPACE_BYTES: u64 = 4 << 30;

    /// Limits with this deadline and the defaults for everything else:
    /// derived CPU limit, [`Self::DEFAULT_ADDRESS_SPACE_BYTES`] of address
    /// space, 4 KiB of result, no file writes, derived descriptor floor.
    pub const fn with_deadline_ns(wall_clock_deadline_ns: u64) -> Self {
        Self {
            wall_clock_deadline_ns,
            cpu_seconds: 0,
            address_space_bytes: Self::DEFAULT_ADDRESS_SPACE_BYTES,
            max_output_bytes: Self::DEFAULT_MAX_OUTPUT_BYTES,
            file_size_bytes: 0,
            nofile: 0,
        }
    }

    /// SHA-256 over a fixed domain and the six limits, each big-endian, in
    /// declaration order. This is the `limits_digest` a version 2 capability
    /// binds: an issuer computes it with this function and the kernel computes
    /// it from its own policy, so a capability issued for other limits is refused.
    pub fn binding_digest(&self) -> Digest32 {
        let mut h = Sha256::new();
        h.update(LIMITS_DIGEST_DOMAIN);
        h.update(self.wall_clock_deadline_ns.to_be_bytes());
        h.update(self.cpu_seconds.to_be_bytes());
        h.update(self.address_space_bytes.to_be_bytes());
        h.update(self.max_output_bytes.to_be_bytes());
        h.update(self.file_size_bytes.to_be_bytes());
        h.update(self.nofile.to_be_bytes());
        Digest32::from_bytes(h.finalize().into())
    }

    /// Checks the deadline, the result cap and the address-space limit. The
    /// supervisor checks again before forking; this refuses a bad policy at
    /// build time.
    pub const fn validate(&self) -> Result<(), LimitsError> {
        if self.wall_clock_deadline_ns == 0 || self.wall_clock_deadline_ns > MAX_DEADLINE_NS {
            return Err(LimitsError::Deadline);
        }
        if self.max_output_bytes == 0 || self.max_output_bytes > MAX_OUTPUT_BYTES {
            return Err(LimitsError::Output);
        }
        if self.address_space_bytes == 0 {
            return Err(LimitsError::AddressSpace);
        }
        Ok(())
    }
}

/// How a run ended, as the executor observed it. Only `Completed` is
/// success, and its result is the worker's own claim.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RunOutcome {
    /// Exit 0 within the deadline with a well-formed result frame.
    Completed {
        /// The exit status.
        exit_code: i32,
        /// The bytes the worker sent. Self-reported.
        result: Vec<u8>,
    },
    /// The wall-clock deadline passed; the worker was killed.
    TimedOut,
    /// The executor sent a termination signal and confirmed the worker dead.
    Terminated {
        /// The signal sent.
        signal: i32,
    },
    /// The executor sent a termination signal and could not confirm the
    /// worker dead. It may still be acting.
    TerminationUnconfirmed {
        /// What the executor knows.
        reason: String,
    },
    /// Ended by a signal other than SIGSYS, SIGXCPU or SIGXFSZ.
    Crashed {
        /// The signal.
        signal: i32,
    },
    /// Ended by SIGSYS: the seccomp filter killed it.
    SeccompViolation {
        /// The signal.
        signal: i32,
    },
    /// Ended by SIGXCPU or SIGXFSZ.
    ResourceLimit {
        /// The signal.
        signal: i32,
    },
    /// Exit 0 but no complete, valid result frame.
    ResultMissing {
        /// The exit status.
        exit_code: i32,
    },
    /// Exited with a non-zero status.
    ExitedNonZero {
        /// The exit status.
        exit_code: i32,
    },
    /// The result frame announced more than the cap.
    ResultOversized,
    /// The executor cannot say how the run ended: spawn failure,
    /// supervisor error, limits refused, a code this crate does not know.
    Unknown {
        /// What the executor does know.
        reason: String,
    },
}

/// What an executor observed of one run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunReport {
    /// How it ended.
    pub outcome: RunOutcome,
    /// Monotonic time from before the spawn to after the reap.
    pub elapsed_ns: u64,
    /// Whether the deadline passed before the end was observed.
    pub deadline_fired: bool,
}

/// A [`RunReport`] with the facts the supervisor observed itself (D1-C):
/// how the process ended and what the result pipe held. `observed` is `None`
/// for an executor that does not observe them (a test double, or an older
/// supervisor); the receipt then records a version 1 terminal, and the
/// verifier lists the missing facts as a limitation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObservedRun {
    /// The report `run` returns.
    pub report: RunReport,
    /// What the supervisor observed, when it did.
    pub observed: Option<stack_receipt::Observed>,
}

/// Why an executor could not produce a report at all.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ExecutorError {
    /// The executor does not run this kind of worker.
    #[error("executor does not run {0}")]
    Unsupported(WorkerKind),
    /// The underlying call failed before anything was observed.
    #[error("executor call failed: {0}")]
    Call(String),
    /// The host refused the run before anything was spawned: capability not
    /// granted, rate limit, a capability change pending, bad limits. Nothing
    /// ran and no token was spent.
    #[error("refused before spawn: {0}")]
    Refused(String),
    /// The worker program is not configured or not usable: not absolute, not
    /// a regular executable file, world-writable, or the host would not
    /// initialize.
    #[error("worker program unusable: {0}")]
    WorkerUnavailable(String),
}

/// Runs one worker under limits and reports what it observed. The
/// pipeline treats an `Err` as an `Unknown` outcome: after the attempt was
/// recorded, nothing weaker than "unknown" may be claimed.
pub trait Executor: Send + Sync + fmt::Debug {
    /// Runs `kind` under `limits` with `args` as its argument bytes.
    fn run(&self, kind: WorkerKind, limits: &ExecutionLimits, args: &[u8]) -> Result<RunReport, ExecutorError>;

    /// [`Self::run`] plus the facts the supervisor observed (D1-C). The default
    /// observes nothing, so an executor written before D1-C keeps working
    /// unchanged; [`SupervisedExecutor`] overrides it.
    fn run_observed(&self, kind: WorkerKind, limits: &ExecutionLimits, args: &[u8]) -> Result<ObservedRun, ExecutorError> {
        Ok(ObservedRun {
            report: self.run(kind, limits, args)?,
            observed: None,
        })
    }

    /// The worker program and the limits this executor would run `kind` under,
    /// for the receipt's `Attempted` record (receipt format version 2). The
    /// default says nothing, so an executor that cannot name its worker
    /// (a test double) writes a version 1 `Attempted` and the verifier lists
    /// the missing identity as a limitation.
    fn worker_binding(&self, kind: WorkerKind, limits: &ExecutionLimits) -> Option<stack_receipt::WorkerBinding> {
        let _ = (kind, limits);
        None
    }

    /// [`Self::run`] on behalf of the authorization `stack-authority` granted
    /// (D2-A). The pipeline calls this and never `run`. The default ignores the
    /// authorization and calls `run`, which is right for a test double and
    /// wrong for an executor that reaches the host: [`SupervisedExecutor`]
    /// refuses `run` and passes the authorization's capability digest to the
    /// host here.
    fn run_authorized(
        &self,
        authorization: &AuthorizedAction,
        kind: WorkerKind,
        limits: &ExecutionLimits,
        args: &[u8],
    ) -> Result<RunReport, ExecutorError> {
        let _ = authorization;
        self.run(kind, limits, args)
    }

    /// [`Self::run_authorized`] plus the facts the supervisor observed (D1-C).
    /// The default is [`Self::run_observed`].
    fn run_observed_authorized(
        &self,
        authorization: &AuthorizedAction,
        kind: WorkerKind,
        limits: &ExecutionLimits,
        args: &[u8],
    ) -> Result<ObservedRun, ExecutorError> {
        let _ = authorization;
        self.run_observed(kind, limits, args)
    }
}

/// Everything the real executor needs from kernel configuration. None of it
/// comes from a request, a payload or the environment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkerConfig {
    /// ABSOLUTE path of the worker program (`stack_worker`).
    pub worker_path: PathBuf,
    /// The SHA-256 of the worker program, from the release record. REQUIRED:
    /// `None` makes [`SupervisedExecutor::new`] fail closed, and every run
    /// executes only an image that hashes to this value (R2-K-21).
    pub worker_sha256: Option<[u8; 32]>,
    /// The host rate-limit domain every run is charged to (0..16).
    pub context_id: u64,
    /// Capability bits every run requires of the host's active mask. Must
    /// name at least one bit; the operator grants them with
    /// `stack_ffi::host_set_capabilities` and may revoke them at any time.
    pub required_capabilities: u64,
    /// Tokens each run costs (1..=100).
    pub tokens_per_run: u32,
    /// Bound on the wait for a killed worker to be reaped, in nanoseconds;
    /// 0 means the supervisor's default of 2 s.
    pub reap_timeout_ns: u64,
}

/// The real executor: the C++ supervised worker behind `stack-ffi`.
///
/// Built from a [`WorkerConfig`]; [`SupervisedExecutor::new`] fails closed
/// when the worker path is not absolute or not an executable regular file, or
/// when the pinned image digest is unset or does not match.
/// Every run goes through the host's capability and rate-limit checks before
/// anything is spawned, so a refused run is `ExecutorError::Refused` and the
/// pipeline records it as unknown (nothing ran).
///
/// Argument bytes are accepted and ignored: the built-in worker kinds take no
/// arguments, and the FFI carries none. The pipeline still records the
/// digest of what it would have passed, so a later FFI that delivers
/// arguments changes only this file.
#[derive(Debug, Clone)]
pub struct SupervisedExecutor {
    worker: CString,
    worker_sha256: [u8; 32],
    context_id: u64,
    required_capabilities: u64,
    tokens_per_run: u32,
    reap_timeout_ns: u64,
}

impl SupervisedExecutor {
    /// Checks the configuration and initializes the host. Fails closed.
    pub fn new(config: WorkerConfig) -> Result<Self, ExecutorError> {
        let path = &config.worker_path;
        if !path.is_absolute() {
            return Err(ExecutorError::WorkerUnavailable(format!(
                "worker path {} is not absolute",
                path.display()
            )));
        }
        let meta = std::fs::metadata(path)
            .map_err(|e| ExecutorError::WorkerUnavailable(format!("worker path {}: {e}", path.display())))?;
        let mode = meta.permissions().mode();
        if !meta.is_file() || mode & 0o111 == 0 || mode & 0o002 != 0 {
            return Err(ExecutorError::WorkerUnavailable(format!(
                "worker path {} is not an executable regular file that is not world-writable",
                path.display()
            )));
        }
        let worker = CString::new(path.as_os_str().as_encoded_bytes())
            .map_err(|_| ExecutorError::WorkerUnavailable("worker path holds a NUL".to_owned()))?;
        let Some(worker_sha256) = config.worker_sha256 else {
            return Err(ExecutorError::WorkerUnavailable(
                "worker_sha256 is not set; the worker image must be pinned".to_owned(),
            ));
        };
        match stack_ffi::worker_image_sha256(&worker) {
            Some(actual) if actual == worker_sha256 => {}
            _ => {
                return Err(ExecutorError::WorkerUnavailable(format!(
                    "worker {} does not hash to the pinned digest",
                    path.display()
                )))
            }
        }
        if config.required_capabilities == 0 {
            return Err(ExecutorError::WorkerUnavailable(
                "required_capabilities names no bit; the host would pass any mask".to_owned(),
            ));
        }
        if config.tokens_per_run == 0 || config.tokens_per_run > 100 {
            return Err(ExecutorError::WorkerUnavailable("tokens_per_run must be 1..=100".to_owned()));
        }
        stack_ffi::host_initialize()
            .map_err(|e| ExecutorError::WorkerUnavailable(format!("host initialization failed: {e:?}")))?;
        Ok(Self {
            worker,
            worker_sha256,
            context_id: config.context_id,
            required_capabilities: config.required_capabilities,
            tokens_per_run: config.tokens_per_run,
            reap_timeout_ns: config.reap_timeout_ns,
        })
    }
}

impl WorkerKind {
    const fn ffi_kind(self) -> stack_ffi::PayloadKind {
        match self {
            Self::ReturnBytes => stack_ffi::PayloadKind::ReturnBytes,
            Self::SpinForever => stack_ffi::PayloadKind::SpinForever,
            Self::BlockForever => stack_ffi::PayloadKind::BlockForever,
            Self::Crash => stack_ffi::PayloadKind::Crash,
            Self::Abort => stack_ffi::PayloadKind::Abort,
            Self::ExitNonZero => stack_ffi::PayloadKind::ExitNonZero,
            Self::ForbiddenSyscall => stack_ffi::PayloadKind::ForbiddenSyscall,
        }
    }
}

/// The receipt's spelling of what the supervisor observed. A code this crate
/// does not know becomes "not observed" / "not read": the receipt cannot carry
/// a value it has no name for, and it never invents a success.
fn receipt_observed(report: &stack_ffi::SupervisedReport) -> stack_receipt::Observed {
    use stack_receipt::{ExitObserved as E, FrameStatus as F};
    let exit = match report.exit_observed {
        stack_ffi::ExitObserved::Exited(code) => E::Exited { code },
        stack_ffi::ExitObserved::Signaled(signal) => E::Signaled { signal },
        stack_ffi::ExitObserved::KilledBySupervisor(signal) => E::KilledBySupervisor { signal },
        stack_ffi::ExitObserved::Unreaped => E::Unreaped,
        stack_ffi::ExitObserved::None | stack_ffi::ExitObserved::Unrecognized(_) => E::NotObserved,
    };
    let frame = match report.frame_status {
        stack_ffi::FrameStatus::Valid => F::Valid,
        stack_ffi::FrameStatus::Missing => F::Missing,
        stack_ffi::FrameStatus::Malformed => F::Malformed,
        stack_ffi::FrameStatus::Oversized => F::Oversized,
        stack_ffi::FrameStatus::Trailing => F::Trailing,
        stack_ffi::FrameStatus::Conflicting => F::Conflicting,
        stack_ffi::FrameStatus::NotRead | stack_ffi::FrameStatus::Unrecognized(_) => F::NotRead,
    };
    stack_receipt::Observed { exit, frame }
}

/// True exactly when the supervisor's own observations are those `Completed`
/// requires: it saw the worker exit 0 before the deadline and held one
/// well-formed frame. A supervisor that says `Completed` without them is not
/// believed.
fn completed_conditions_hold(report: &stack_ffi::SupervisedReport) -> bool {
    !report.deadline_fired
        && report.exit_observed == stack_ffi::ExitObserved::Exited(0)
        && report.frame_status == stack_ffi::FrameStatus::Valid
}

impl Executor for SupervisedExecutor {
    fn worker_binding(&self, _kind: WorkerKind, limits: &ExecutionLimits) -> Option<stack_receipt::WorkerBinding> {
        Some(stack_receipt::WorkerBinding {
            // The digest this executor pinned at construction and that the
            // supervisor re-verifies against the image it executes on every run.
            image_sha256: stack_receipt::Digest32::from_bytes(self.worker_sha256),
            limits: stack_receipt::AppliedLimits {
                wall_clock_deadline_ns: limits.wall_clock_deadline_ns,
                cpu_seconds: limits.cpu_seconds,
                address_space_bytes: limits.address_space_bytes,
                max_output_bytes: limits.max_output_bytes,
                file_size_bytes: limits.file_size_bytes,
                nofile: limits.nofile,
            },
        })
    }

    /// Refused: the real executor runs only on behalf of an
    /// [`AuthorizedAction`] (D2-A). Use [`Executor::run_authorized`].
    fn run(&self, _kind: WorkerKind, _limits: &ExecutionLimits, _args: &[u8]) -> Result<RunReport, ExecutorError> {
        Err(ExecutorError::Refused(NO_AUTHORIZATION.to_owned()))
    }

    /// Refused, as [`Self::run`].
    fn run_observed(&self, _kind: WorkerKind, _limits: &ExecutionLimits, _args: &[u8]) -> Result<ObservedRun, ExecutorError> {
        Err(ExecutorError::Refused(NO_AUTHORIZATION.to_owned()))
    }

    fn run_authorized(
        &self,
        authorization: &AuthorizedAction,
        kind: WorkerKind,
        limits: &ExecutionLimits,
        args: &[u8],
    ) -> Result<RunReport, ExecutorError> {
        self.run_with_facts(authorization, kind, limits, args, None).map(|(report, _)| report)
    }

    fn run_observed_authorized(
        &self,
        authorization: &AuthorizedAction,
        kind: WorkerKind,
        limits: &ExecutionLimits,
        args: &[u8],
    ) -> Result<ObservedRun, ExecutorError> {
        self.run_with_facts(authorization, kind, limits, args, None)
            .map(|(report, observed)| ObservedRun {
                report,
                observed: Some(observed),
            })
    }
}

/// Run ids for the host's table of runs that can be stopped. Process wide, so two
/// executors in one process never name the same run.
static NEXT_RUN_ID: AtomicU64 = AtomicU64::new(1);

/// The stop hook for the real worker (R-5 remainder). A [`CancelToken`] that fires
/// while a run is in flight asks the host, by run id, to SIGKILL the worker through
/// its pidfd: the same kill a capability-mask revocation uses. The run then ends as
/// `Terminated`, which is never a success, and its receipt says so.
impl CancellableExecutor for SupervisedExecutor {
    fn run_cancellable_observed(
        &self,
        authorization: &AuthorizedAction,
        kind: WorkerKind,
        limits: &ExecutionLimits,
        args: &[u8],
        cancel: &CancelToken,
    ) -> Result<ObservedRun, ExecutorError> {
        let run_id = NEXT_RUN_ID.fetch_add(1, Ordering::SeqCst);
        let finished = AtomicBool::new(false);
        let result = std::thread::scope(|scope| {
            scope.spawn(|| {
                // Wake on the token (it notifies at once); the timeout only lets
                // this thread see that the run is over.
                while !finished.load(Ordering::Acquire) {
                    if cancel.wait_cancelled(Duration::from_millis(10)) {
                        // The host may not have registered the run yet (a cancel can
                        // beat the spawn): keep asking until it has, or the run ends.
                        while !finished.load(Ordering::Acquire) && !stack_ffi::supervised_cancel(run_id) {
                            std::thread::sleep(Duration::from_millis(1));
                        }
                        return;
                    }
                }
            });
            let r = self.run_with_facts(authorization, kind, limits, args, Some(run_id));
            finished.store(true, Ordering::Release);
            r
        });
        result.map(|(report, observed)| ObservedRun {
            report,
            observed: Some(observed),
        })
    }
}

/// Why [`SupervisedExecutor`] refuses the methods that name no authorization.
const NO_AUTHORIZATION: &str = "the supervised executor runs only on behalf of an AuthorizedAction (run_authorized)";

impl SupervisedExecutor {
    fn run_with_facts(
        &self,
        authorization: &AuthorizedAction,
        kind: WorkerKind,
        limits: &ExecutionLimits,
        _args: &[u8],
        run_id: Option<u64>,
    ) -> Result<(RunReport, stack_receipt::Observed), ExecutorError> {
        let capacity = usize::try_from(limits.max_output_bytes.min(MAX_OUTPUT_BYTES))
            .map_err(|_| ExecutorError::Call("result cap does not fit".to_owned()))?;
        let mut out = vec![0u8; capacity];
        let ffi_limits = stack_ffi::SupervisedLimits {
            wall_clock_deadline_ns: limits.wall_clock_deadline_ns,
            cpu_seconds: limits.cpu_seconds,
            address_space_bytes: limits.address_space_bytes,
            max_output_bytes: limits.max_output_bytes,
            file_size_bytes: limits.file_size_bytes,
            nofile: limits.nofile,
        };
        let request = stack_ffi::GovernedSupervisedRequest {
            context_id: self.context_id,
            required_capability_m0: self.required_capabilities,
            required_tokens: self.tokens_per_run,
            kind: kind.ffi_kind(),
            worker_path: &self.worker,
            worker_sha256: Some(self.worker_sha256),
            reap_timeout_ns: self.reap_timeout_ns,
        };
        let result = match run_id {
            Some(id) => stack_ffi::supervised_run_governed_cancellable(authorization, id, &request, &ffi_limits, &mut out),
            None => stack_ffi::supervised_run_governed(authorization, &request, &ffi_limits, &mut out),
        };
        let report = result.map_err(|e| ExecutorError::Refused(format!("{e:?}")))?;
        use stack_ffi::SupervisedOutcome as O;
        let outcome = match report.outcome {
            O::Completed if !completed_conditions_hold(&report) => RunOutcome::Unknown {
                reason: "supervisor reported a completion without an observed exit 0 and one valid frame".to_owned(),
            },
            O::Completed => match usize::try_from(report.result_length).ok().and_then(|n| out.get(..n)) {
                Some(bytes) => RunOutcome::Completed {
                    exit_code: report.exit_code,
                    result: bytes.to_vec(),
                },
                // A completion whose bytes cannot be read is not a completion.
                None => RunOutcome::Unknown {
                    reason: "supervisor reported a result longer than the buffer".to_owned(),
                },
            },
            O::TimedOut => RunOutcome::TimedOut,
            O::Crashed => RunOutcome::Crashed {
                signal: report.signal_number,
            },
            O::SeccompViolation => RunOutcome::SeccompViolation {
                signal: report.signal_number,
            },
            O::ExitedNonZero => RunOutcome::ExitedNonZero {
                exit_code: report.exit_code,
            },
            O::ResultMissing => RunOutcome::ResultMissing {
                exit_code: report.exit_code,
            },
            O::ResultOversized => RunOutcome::ResultOversized,
            O::ResourceLimit => RunOutcome::ResourceLimit {
                signal: report.signal_number,
            },
            O::SpawnFailed => RunOutcome::Unknown {
                reason: format!("spawn failed (errno {})", report.error_number),
            },
            O::SupervisorError => RunOutcome::Unknown {
                reason: format!("supervisor error (errno {})", report.error_number),
            },
            O::InvalidLimits => RunOutcome::Unknown {
                reason: "limits refused by the supervisor".to_owned(),
            },
            O::SigchldIgnored => RunOutcome::Unknown {
                reason: "SIGCHLD is ignored in this process; the supervisor refused to run".to_owned(),
            },
            // A pending capability revocation killed the worker (R2-K-24).
            O::Terminated => RunOutcome::Terminated {
                signal: report.signal_number,
            },
            O::TerminationUnconfirmed => RunOutcome::TerminationUnconfirmed {
                reason: format!(
                    "SIGKILL sent and the worker (pid {}) was not reaped within the bound; it may still be running",
                    report.child_pid
                ),
            },
            O::Unrecognized(code) => RunOutcome::Unknown {
                reason: format!("unrecognized supervisor outcome code {code}"),
            },
        };
        Ok((
            RunReport {
                outcome,
                elapsed_ns: report.elapsed_ns,
                deadline_fired: report.deadline_fired,
            },
            receipt_observed(&report),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ffi_report(outcome: stack_ffi::SupervisedOutcome, exit: stack_ffi::ExitObserved, frame: stack_ffi::FrameStatus) -> stack_ffi::SupervisedReport {
        stack_ffi::SupervisedReport {
            outcome,
            elapsed_ns: 1,
            exit_code: 0,
            signal_number: 0,
            error_number: 0,
            child_pid: 1,
            deadline_fired: false,
            result_length: 0,
            result_self_reported: true,
            exit_observed: exit,
            frame_status: frame,
        }
    }

    #[test]
    fn a_completion_is_believed_only_with_an_observed_clean_exit_and_one_valid_frame() {
        use stack_ffi::{ExitObserved as E, FrameStatus as F, SupervisedOutcome::Completed};
        assert!(completed_conditions_hold(&ffi_report(Completed, E::Exited(0), F::Valid)));
        for (exit, frame) in [
            (E::Exited(3), F::Valid),
            (E::Exited(0), F::Missing),
            (E::Exited(0), F::Conflicting),
            (E::Signaled(11), F::Valid),
            (E::KilledBySupervisor(9), F::Valid),
            (E::None, F::Valid),
            (E::Exited(0), F::NotRead),
        ] {
            assert!(!completed_conditions_hold(&ffi_report(Completed, exit, frame)), "{exit:?} {frame:?}");
        }
        let mut late = ffi_report(Completed, E::Exited(0), F::Valid);
        late.deadline_fired = true;
        assert!(!completed_conditions_hold(&late));
    }

    #[test]
    fn what_the_supervisor_observed_reaches_the_receipt_vocabulary_unchanged() {
        use stack_ffi::{ExitObserved as E, FrameStatus as F, SupervisedOutcome as O};
        use stack_receipt::{ExitObserved as RE, FrameStatus as RF};
        let o = receipt_observed(&ffi_report(O::TimedOut, E::KilledBySupervisor(9), F::Valid));
        assert_eq!((o.exit, o.frame), (RE::KilledBySupervisor { signal: 9 }, RF::Valid));
        let o = receipt_observed(&ffi_report(O::TerminationUnconfirmed, E::Unreaped, F::NotRead));
        assert_eq!((o.exit, o.frame), (RE::Unreaped, RF::NotRead));
        let o = receipt_observed(&ffi_report(O::Crashed, E::Signaled(11), F::Conflicting));
        assert_eq!((o.exit, o.frame), (RE::Signaled { signal: 11 }, RF::Conflicting));
        // A code this crate has no name for is never read as a success.
        let o = receipt_observed(&ffi_report(O::Completed, E::Unrecognized(99), F::Unrecognized(99)));
        assert_eq!((o.exit, o.frame), (RE::NotObserved, RF::NotRead));
        assert!(!o.supports_completed());
    }

    #[test]
    fn kinds_round_trip_through_their_spelling() {
        for k in WorkerKind::ALL {
            assert_eq!(WorkerKind::parse(k.as_str()), Some(k));
            assert_eq!(format!("{k}"), k.as_str());
        }
        assert_eq!(WorkerKind::parse("rm -rf"), None);
    }

    #[test]
    fn a_zero_address_space_is_refused_and_the_default_is_bounded() {
        let mut l = ExecutionLimits::with_deadline_ns(1);
        assert_eq!(l.address_space_bytes, ExecutionLimits::DEFAULT_ADDRESS_SPACE_BYTES);
        assert_eq!(ExecutionLimits::DEFAULT_ADDRESS_SPACE_BYTES, 4 << 30);
        assert_eq!(l.validate(), Ok(()));
        l.address_space_bytes = 0;
        assert_eq!(l.validate(), Err(LimitsError::AddressSpace));
        l.address_space_bytes = 1;
        assert_eq!(l.validate(), Ok(()));
    }

    #[test]
    fn limits_are_bounded() {
        assert_eq!(ExecutionLimits::with_deadline_ns(1).validate(), Ok(()));
        assert_eq!(ExecutionLimits::with_deadline_ns(0).validate(), Err(LimitsError::Deadline));
        assert_eq!(
            ExecutionLimits::with_deadline_ns(MAX_DEADLINE_NS + 1).validate(),
            Err(LimitsError::Deadline)
        );
        let mut l = ExecutionLimits::with_deadline_ns(1);
        l.max_output_bytes = 0;
        assert_eq!(l.validate(), Err(LimitsError::Output));
        l.max_output_bytes = MAX_OUTPUT_BYTES + 1;
        assert_eq!(l.validate(), Err(LimitsError::Output));
    }
}
