//! # stack-admission: the end-to-end chain from CNS decision to receipt
//!
//! One pipeline, `Admission::process(envelope_bytes)`, that takes a Trident
//! handoff carrying a CNS decision, a capability and a requested action,
//! and either refuses it with a typed reason or executes it under a
//! write-ahead receipt. Every stage fails closed.
//!
//! ## Trust placement (decision E)
//!
//! CNS defines and binds the contract: the subject digest, the gate
//! vocabulary and the decision root. The kernel independently validates
//! authority: permission exists only as a `stack_authority::AuthorizedAction`
//! minted by `Authority::authorize` from a capability an issuer outside the
//! kernel and outside CNS signed. In this repository that issuer exists only
//! as a test fixture. The kernel never treats a CNS PASS, a matching digest,
//! a Trident acceptance or a decision's HMAC as permission: an HMAC proves
//! possession of a shared key, not a human; a signed decision proves a
//! decision was signed, not that anything executed.
//!
//! ## Stages
//!
//! 1. Trident verification under the Production profile; a Development
//!    assurance is refused.
//! 2. Strict parse of the verified payload.
//! 3. CNS binding: the kernel recomputes the subject digest and the
//!    decision root itself and checks the roster against its own policy.
//! 4. Authorization through `stack-authority` with an `ActionRequest` the
//!    kernel built from its own recomputed values.
//! 5. Receipt write-ahead: `proposed`, `authorized`, `attempted` before
//!    anything runs; no attempt record, no execution.
//! 6. Execution through the [`Executor`] seam; the one real implementation
//!    is the supervised C++ executor behind `stack-ffi`.
//! 7. The terminal receipt from the observed outcome; a terminal that
//!    cannot be recorded is a typed non-success and the attempt stays open.
//! 8. An `AdmissionResult` that is success only for a recorded `Completed`.
//!
//! `README.md` at the crate root states what is implemented, tested,
//! independently verified and still planned. Nothing here claims more
//! than a named test proves.
//!
//! Step 1: the crate skeleton, the kernel policy types, the executor seam
//! and its supervised implementation. Step 2: stages 1 to 4,
//! [`Admission::new`] and [`Admission::admit`], the strict payload parse
//! ([`payload`]) and the CNS binding ([`binding`]).

#![forbid(unsafe_code)]

pub mod admission;
pub mod binding;
pub mod clock;
pub mod config;
pub mod executor;
pub mod payload;

pub use admission::{Admission, Admitted, BuildError, Parts, RefusalReason, Refused, Stage};
pub use binding::{cns_value, BindingFinding};
pub use clock::KernelClock;
pub use config::{ConfigError, KernelPolicy};
pub use payload::{DecisionClaim, PayloadError, Request};
pub use executor::{
    ExecutionLimits, Executor, ExecutorError, LimitsError, RunOutcome, RunReport, SupervisedExecutor, WorkerKind,
    MAX_DEADLINE_NS, MAX_OUTPUT_BYTES,
};
