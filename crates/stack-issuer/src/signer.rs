//! The only way this crate signs. No key material in this repository.

use std::fmt;

use stack_authority::{PublicKey, SIGNATURE_BYTES};

/// Why a signer did not sign.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SignError {
    /// The device or service cannot be reached or refused.
    #[error("signer unavailable: {0}")]
    Unavailable(String),
}

/// A signing device: an HSM, a cloud KMS, or anything that does not export the
/// key. Implementations live outside this crate. The issuer never asks for the
/// private key, only for a signature over a message, and it checks that
/// signature against [`Signer::public_key`] before using it.
pub trait Signer: Send + Sync + fmt::Debug {
    /// The Ed25519 public key whose key id goes into every capability.
    fn public_key(&self) -> PublicKey;
    /// An Ed25519 signature over `message`.
    fn sign(&self, message: &[u8]) -> Result<[u8; SIGNATURE_BYTES], SignError>;
}
