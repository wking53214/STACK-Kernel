//! A capability issuer, as a library.
//!
//! The kernel verifies capabilities; it cannot make them. This crate is the
//! piece that does, under the rules in `docs/issuer-requirements.md`:
//!
//! * The requester names a subject, a claimed CNS decision, an operation, the
//!   resources, the arguments and a lifetime. It names **no digest and no
//!   audience**. The issuer derives the audience, the subject digest, the
//!   decision root, the worker kind and the three execution-binding values
//!   itself, with the kernel's own functions, from a policy built from the
//!   kernel's own [`KernelPolicy`](stack_admission::KernelPolicy).
//! * It refuses a decision the kernel would refuse (the kernel's own binding
//!   check, same roster, same positions), a wildcard scope, an unknown
//!   operation, and a lifetime over its ceiling. Every capability it issues is
//!   one-time and bound (`stack-capability/2`).
//! * It signs through the [`Signer`] trait. **No key lives here.** The
//!   production signer (an HSM or KMS adapter) is a deployment decision this
//!   crate does not make; tests use a fixture signer. It checks every signature
//!   against the signer's own public key before anything leaves.
//! * Two hooks have no default: a [`DecisionVerifier`] (is the CNS decision real?) and an
//!   [`Authorizer`] (may this requester be issued this?). The crate ships only refusing
//!   placeholders.
//! * Three caps, counted in the issuance log so they survive a restart: capabilities per decision
//!   root, per subject digest, and the number of distinct decision roots. They cover the records
//!   the log knows about: rotating the log without carrying its history resets them. An operator
//!   can re-allow one decision with a logged reset.
//! * It appends an [`IssuanceRecord`] to an [`IssuanceLog`] *before* it returns
//!   the capability. If the record cannot be written, no capability is returned.
//!
//! What this crate does not establish: that a real CNS decision exists. The CNS
//! proof is an HMAC under a key local to the CNS process, so the issuer can
//! check the decision's structure, roster, positions, subject binding and root,
//! exactly as the kernel does, but not who produced it. That needs a
//! verification channel to CNS which does not exist yet (see the README).
#![forbid(unsafe_code)]

mod config;
mod entropy;
mod hooks;
mod issue;
mod log;
mod signer;

pub use config::{ConfigError, IssuanceCaps, IssuerConfig, MAX_LIFETIME_CEILING_MS};
pub use entropy::{Entropy, EntropyError, OsEntropy};
pub use hooks::{AuthorizationRequest, Authorizer, DecisionVerifier, DenyAllRequests, RefuseAllDecisions, Refusal};
pub use issue::{IssuanceRequest, IssueError, Issued, Issuer, MAX_RESOURCES_PER_CAPABILITY};
pub use log::{
    AppendLimits, FileIssuanceLog, IssuanceLog, IssuanceRecord, LogError, ResetRecord, Usage, MAX_RECORD_LINE_BYTES,
};
pub use signer::{SignError, Signer};
