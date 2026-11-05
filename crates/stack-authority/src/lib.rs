//! # stack-authority: the verify-only authorization boundary
//!
//! This crate answers one question for the kernel: may this caller perform
//! this operation on this resource, under this governing decision, right
//! now? It answers by verifying a capability that an issuer outside the
//! kernel signed, against a trust set the kernel holds. It never issues.
//! There is no signing key, no signing code and no default key anywhere
//! in the non-test source, and a test checks that claim against the
//! source text.
//!
//! ## Concepts that stay separate
//!
//! | Concept | What it is here | What it proves |
//! |---|---|---|
//! | Content identity | SHA-256 of canonical bytes, elsewhere | the bytes are these bytes |
//! | CNS subject binding | `subject_digest`, an unkeyed CNS digest carried in the capability and recomputed by the enforcement boundary | the capability was issued about this content (tamper-evidence only; anyone can compute it) |
//! | Authentication | an Ed25519 signature that verifies under a public key | the holder of that key signed exactly these bytes; nothing about a person |
//! | Trusted issuer identity | that key resolving to exactly one active, in-window anchor for the named issuer in the kernel's trust set | the kernel's operator chose to trust that key for that issuer, for issuing capabilities, for that period |
//! | Authorization | this crate's [`Authority::authorize`]: every check in order, then one atomic use record | this capability permits this operation on this resource for this audience, under this decision, now |
//! | Enforcement | the caller's boundary, which must demand an [`AuthorizedAction`] before executing | out of scope here |
//! | Outcome, receipt | what happened and the durable record of it | out of scope here; the [`AuthorizedAction`] carries what a receipt needs |
//!
//! A CNS PASS, a decision root that matches, or a subject digest that
//! matches, never authorizes anything on its own. They are conditions the
//! capability must also satisfy, checked after the signature.
//!
//! ## Status
//!
//! Step 1: the capability type, its one wire encoding, the strict parser
//! and the digest. Step 2: the trust set, the revocation list and strict
//! signature verification. Step 3: the [`Authority`], its ordered checks
//! (see [`authority`]), the [`AuthorizedAction`] it alone can mint, the
//! [`UseStore`] trait and the non-durable [`MemoryUseStore`]. Step 4: the
//! durable, locked, hash-chained [`FileUseStore`] (see [`file_store`]).

#![forbid(unsafe_code)]

pub mod authority;
pub mod capability;
pub mod clock;
pub mod digest;
pub mod file_store;
pub mod scope;
pub mod store;
pub mod trust;

pub use authority::{ActionRequest, AuthorizedAction, Authority, AuthorityConfig, AuthzError, ConfigError};
pub use capability::{
    Capability, CapabilityDigest, Field, ParseError, SignedCapability, DIGEST_DOMAIN, DOMAIN_TAG, KEY_ID_BYTES,
    MAX_ID_BYTES, MAX_OPERATIONS, MAX_OPERATION_BYTES, MAX_POLICY_REF_BYTES, MAX_RESOURCES, MAX_WIRE_BYTES,
    MIN_WIRE_BYTES, NONCE_BYTES, SIGNATURE_BYTES,
};
pub use clock::{Clock, ManualClock, SystemClock};
pub use digest::Digest32;
pub use file_store::{FileUseStore, LOG_HEADER, MAX_LOG_BYTES, RECORD_BYTES, RECORD_DOMAIN};
pub use scope::{validate_path, PathError, ResourceScope, ScopeKind, MAX_PATH_BYTES};
pub use store::{MemoryUseStore, UseError, UseEvidence, UseKey, UseStore};
pub use trust::{
    AnchorStatus, BadSignature, KeyId, PublicKey, Purpose, ResolveError, RevocationList, TrustAnchor, TrustError,
    TrustSet, KEY_ID_DOMAIN,
};
