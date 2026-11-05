//! The recorder: the honest kernel's way of writing receipts, shaped so
//! the write-ahead order cannot be violated.
//!
//! An [`Execution`] handle moves through stages by consuming itself:
//! `propose` gives `Execution<Proposed>`; `authorize` gives
//! `Execution<Authorized>` and `reject` closes it; `attempt` writes the
//! `Attempted` record and gives `Execution<Attempted>`, and only that
//! handle can `finish`. The payload must not start until `attempt` has
//! returned `Ok`: a failure there is [`AttemptUnrecorded`], and the
//! caller has nothing to run with. A failure to record the terminal
//! event is [`TerminalUnrecorded`], which carries the outcome the kernel
//! observed so the caller can report it elsewhere; the log keeps the
//! `Attempted` record open, and the verifier reports that execution as
//! INCOMPLETE with an unknown outcome, never as success.
//!
//! Dropping an `Execution<Attempted>` without finishing it has the same
//! effect as a crash: the verifier sees an open attempt. The handle is
//! `must_use` for that reason.
//!
//! One recorder serves one log and may be shared between threads; records
//! of concurrent executions interleave in the log in the order they were
//! appended, each chained to the one before.

use std::marker::PhantomData;
use std::sync::{Arc, Mutex};

use stack_authority::{AuthorizedAction, Clock};

use crate::log::{Head, LogError, ReceiptLog};
use crate::record::{
    Action, ActualAction, Attempted, Authorized, CapabilityBinding, Event, ExecutionId, Outcome, Proposed,
    Provenance, Record, Rejected, Terminal, ValidationError,
};
use crate::sign::{ReceiptSigner, SignError, SignedRecord};

/// Why a record could not be made.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum RecordError {
    /// The log refused or failed.
    #[error("{0}")]
    Log(#[from] LogError),
    /// The record could not be signed (an invalid field).
    #[error("{0}")]
    Sign(#[from] SignError),
    /// The recorder's lock is poisoned by a panic elsewhere.
    #[error("recorder unavailable")]
    Unavailable,
    /// The provenance given at construction is invalid.
    #[error("{0}")]
    Invalid(#[from] ValidationError),
}

/// The `Attempted` record was not made durable. The caller must not run
/// the payload.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("attempt not recorded, do not execute: {0}")]
pub struct AttemptUnrecorded(#[source] pub RecordError);

/// The terminal record was not made durable. The log keeps the attempt
/// open; a verifier will report the execution as incomplete with an
/// unknown outcome. `observed_outcome` is what the kernel saw, for the
/// caller to report through another channel.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("terminal event not recorded; observed outcome {} stays unrecorded: {error}", observed_outcome.kind().as_str())]
pub struct TerminalUnrecorded {
    /// What the kernel observed.
    pub observed_outcome: Outcome,
    /// Why it could not be recorded.
    #[source]
    pub error: RecordError,
}

struct Inner {
    log: Box<dyn ReceiptLog>,
    signer: ReceiptSigner,
    provenance: Provenance,
    clock: Box<dyn Clock>,
}

impl Inner {
    fn append(&mut self, execution_id: ExecutionId, event: Event) -> Result<SignedRecord, RecordError> {
        let head = self.log.head()?;
        let record = Record {
            kernel_id: self.log.kernel_id().to_owned(),
            sequence: head.sequence.saturating_add(1),
            prev_hash: head.hash,
            execution_id,
            recorded_at_ms: self.clock.now_unix_ms(),
            key_id: *self.signer.key_id(),
            provenance: self.provenance.clone(),
            event,
        };
        let signed = self.signer.sign(record)?;
        self.log.append(&signed)?;
        Ok(signed)
    }
}

/// Writes receipts for one kernel into one log.
#[derive(Clone)]
pub struct Recorder {
    inner: Arc<Mutex<Inner>>,
}

impl std::fmt::Debug for Recorder {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.inner.lock() {
            Ok(i) => f
                .debug_struct("Recorder")
                .field("kernel_id", &i.log.kernel_id())
                .field("key_id", i.signer.key_id())
                .finish_non_exhaustive(),
            Err(_) => f.write_str("Recorder(poisoned)"),
        }
    }
}

impl Recorder {
    /// A recorder over `log`, signing with `signer`, stamping every
    /// record with `provenance` and the clock's time.
    pub fn new(
        log: Box<dyn ReceiptLog>,
        signer: ReceiptSigner,
        provenance: Provenance,
        clock: Box<dyn Clock>,
    ) -> Result<Self, RecordError> {
        provenance.validate()?;
        Ok(Self {
            inner: Arc::new(Mutex::new(Inner {
                log,
                signer,
                provenance,
                clock,
            })),
        })
    }

    /// The chain head, for an operator to anchor elsewhere.
    pub fn head(&self) -> Result<Head, RecordError> {
        let inner = self.inner.lock().map_err(|_| RecordError::Unavailable)?;
        Ok(inner.log.head()?)
    }

    /// Whether the log is durable.
    pub fn is_durable(&self) -> Result<bool, RecordError> {
        let inner = self.inner.lock().map_err(|_| RecordError::Unavailable)?;
        Ok(inner.log.is_durable())
    }

    /// Records that a request arrived. The first event of an execution.
    pub fn propose(&self, execution_id: ExecutionId, proposed: Proposed) -> Result<Execution<ProposedStage>, RecordError> {
        {
            let mut inner = self.inner.lock().map_err(|_| RecordError::Unavailable)?;
            inner.append(execution_id, Event::Proposed(proposed))?;
        }
        Ok(Execution {
            inner: Arc::clone(&self.inner),
            id: execution_id,
            _stage: PhantomData,
        })
    }
}

/// Marker: the execution has been proposed.
#[derive(Debug, Clone, Copy)]
pub struct ProposedStage;
/// Marker: the execution has been authorized.
#[derive(Debug, Clone, Copy)]
pub struct AuthorizedStage;
/// Marker: the attempt has been recorded; the payload may run.
#[derive(Debug, Clone, Copy)]
pub struct AttemptedStage;

/// One execution's handle at a stage. Consumed by every transition.
#[must_use = "an execution handle that is dropped leaves the execution open in the log"]
pub struct Execution<S> {
    inner: Arc<Mutex<Inner>>,
    id: ExecutionId,
    _stage: PhantomData<S>,
}

impl<S> std::fmt::Debug for Execution<S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Execution").field("id", &self.id).finish_non_exhaustive()
    }
}

impl<S> Execution<S> {
    /// The execution id.
    pub const fn id(&self) -> &ExecutionId {
        &self.id
    }

    fn append(&self, event: Event) -> Result<SignedRecord, RecordError> {
        let mut inner = self.inner.lock().map_err(|_| RecordError::Unavailable)?;
        inner.append(self.id, event)
    }

    fn advance<T>(self) -> Execution<T> {
        Execution {
            inner: self.inner,
            id: self.id,
            _stage: PhantomData,
        }
    }
}

/// An execution that has reached a terminal record. Nothing more can be
/// written for it through this handle.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Closed {
    /// The execution id.
    pub id: ExecutionId,
    /// The sequence of its terminal record.
    pub terminal_sequence: u64,
}

impl Execution<ProposedStage> {
    /// Records the authorization `stack-authority` granted.
    pub fn authorize(self, action: &AuthorizedAction) -> Result<Execution<AuthorizedStage>, RecordError> {
        self.authorize_with(Authorized {
            capability: CapabilityBinding::from(action),
            action: Action {
                operation: action.operation().to_owned(),
                resource: action.resource().to_owned(),
            },
        })
    }

    /// Records an authorization given as data (for a binding built
    /// elsewhere, or for tests).
    pub fn authorize_with(self, authorized: Authorized) -> Result<Execution<AuthorizedStage>, RecordError> {
        self.append(Event::Authorized(authorized))?;
        Ok(self.advance())
    }

    /// Records that the kernel refused the request. Terminal.
    pub fn reject(self, reason: &str) -> Result<Closed, RecordError> {
        let s = self.append(Event::Rejected(Rejected {
            reason: reason.to_owned(),
        }))?;
        Ok(Closed {
            id: self.id,
            terminal_sequence: s.record().sequence,
        })
    }
}

impl Execution<AuthorizedStage> {
    /// Records, before anything runs, the action the kernel is about to
    /// run: the operation it selects, the resource it was authorized for,
    /// and the digest of the argument bytes it intends to pass. The record
    /// is the kernel's intent, not proof of what the worker received: the
    /// supervised executor in this repository delivers neither the
    /// arguments nor the resource to its built-in workers (R2-X-02). The
    /// payload may start only once this returns `Ok`.
    pub fn attempt(self, action: ActualAction, started_at_ms: u64) -> Result<Execution<AttemptedStage>, AttemptUnrecorded> {
        self.append(Event::Attempted(Attempted { action, started_at_ms }))
            .map_err(AttemptUnrecorded)?;
        Ok(self.advance())
    }

    /// Records that the kernel refused after authorization (a policy of
    /// its own). Terminal.
    pub fn reject(self, reason: &str) -> Result<Closed, RecordError> {
        let s = self.append(Event::Rejected(Rejected {
            reason: reason.to_owned(),
        }))?;
        Ok(Closed {
            id: self.id,
            terminal_sequence: s.record().sequence,
        })
    }
}

impl Execution<AttemptedStage> {
    /// Records how the run ended. On failure the outcome is handed back
    /// in the error and the attempt stays open in the log.
    pub fn finish(self, terminal: Terminal) -> Result<Closed, TerminalUnrecorded> {
        let observed = terminal.outcome.clone();
        match self.append(Event::Terminal(terminal)) {
            Ok(s) => Ok(Closed {
                id: self.id,
                terminal_sequence: s.record().sequence,
            }),
            Err(error) => Err(TerminalUnrecorded {
                observed_outcome: observed,
                error,
            }),
        }
    }
}
