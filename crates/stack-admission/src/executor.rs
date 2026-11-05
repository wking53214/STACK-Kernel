//! The executor seam: the one place this crate touches `stack-ffi`.
//!
//! The pipeline runs a worker through the [`Executor`] trait and reads
//! back a [`RunReport`]. [`SupervisedExecutor`] is the one real
//! implementation: the C++ supervised executor (a forked child under a
//! wall-clock deadline that ends in SIGKILL, a seccomp allowlist and
//! rlimits) reached through `stack_ffi::supervised_run`. The FFI is
//! expected to change (host, governor, init); when it does, this file is
//! the adaptation and nothing else in the crate moves.
//!
//! What a report proves: what the supervisor observed. A `Completed`
//! outcome means the worker exited 0 within the deadline and sent a
//! well-formed result frame; the result bytes are the worker's own claim
//! (`cpp/CONTAINMENT.md`), and the receipt records their digest as
//! self-reported.

use std::fmt;

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

/// Why an executor could not produce a report at all.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ExecutorError {
    /// The executor does not run this kind of worker.
    #[error("executor does not run {0}")]
    Unsupported(WorkerKind),
    /// The underlying call failed before anything was observed.
    #[error("executor call failed: {0}")]
    Call(String),
}

/// Runs one worker under limits and reports what it observed. The
/// pipeline treats an `Err` as an `Unknown` outcome: after the attempt was
/// recorded, nothing weaker than "unknown" may be claimed.
pub trait Executor: Send + Sync + fmt::Debug {
    /// Runs `kind` under `limits` with `args` as its argument bytes.
    fn run(&self, kind: WorkerKind, limits: &ExecutionLimits, args: &[u8]) -> Result<RunReport, ExecutorError>;
}

/// The real executor: the C++ supervised child behind `stack-ffi`.
///
/// Argument bytes are accepted and ignored: the built-in payloads take no
/// arguments, and the FFI carries none. The pipeline still records the
/// digest of what it would have passed, so a later FFI that delivers
/// arguments changes only this file.
#[derive(Debug, Clone, Copy, Default)]
pub struct SupervisedExecutor;

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

impl Executor for SupervisedExecutor {
    fn run(&self, kind: WorkerKind, limits: &ExecutionLimits, _args: &[u8]) -> Result<RunReport, ExecutorError> {
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
        let report = stack_ffi::supervised_run(kind.ffi_kind(), &ffi_limits, &mut out)
            .map_err(|e| ExecutorError::Call(format!("{e:?}")))?;
        use stack_ffi::SupervisedOutcome as O;
        let outcome = match report.outcome {
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
            O::Unrecognized(code) => RunOutcome::Unknown {
                reason: format!("unrecognized supervisor outcome code {code}"),
            },
        };
        Ok(RunReport {
            outcome,
            elapsed_ns: report.elapsed_ns,
            deadline_fired: report.deadline_fired,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
