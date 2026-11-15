//! Randomness for capability ids and nonces (R-9).

use std::fmt;
use std::io::Read;

/// Why entropy was not available.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum EntropyError {
    /// The source failed.
    #[error("entropy unavailable: {0}")]
    Unavailable(String),
}

/// A source of cryptographically secure random bytes.
pub trait Entropy: Send + Sync + fmt::Debug {
    /// Fills `buf` completely or fails. A partial fill is a failure.
    fn fill(&self, buf: &mut [u8]) -> Result<(), EntropyError>;
}

/// The operating system's random device (`/dev/urandom`), the same source the
/// Trident envelope uses. Linux only; another platform supplies its own.
#[derive(Debug, Clone, Copy, Default)]
pub struct OsEntropy;

impl Entropy for OsEntropy {
    fn fill(&self, buf: &mut [u8]) -> Result<(), EntropyError> {
        std::fs::File::open("/dev/urandom")
            .and_then(|mut f| f.read_exact(buf))
            .map_err(|e| EntropyError::Unavailable(e.to_string()))
    }
}
