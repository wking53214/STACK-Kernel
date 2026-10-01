//! State fingerprints: the knots on the string.

use core::fmt;

use sha2::{Digest, Sha256};

/// A 32-byte fingerprint of one state of the walk.
///
/// The caller decides what a "state" is (a tool name plus its canonical
/// arguments, a recursion frame's inputs, a planner node) and hands the
/// Thread its fingerprint. Two states are the same state exactly when their
/// fingerprints are equal, so the fingerprint must cover everything that
/// makes two steps different. [`Fingerprint::of_bytes`] computes the full
/// SHA-256 of a canonical encoding; [`Fingerprint::from_digest`] accepts a
/// 32-byte digest the caller already has.
///
/// Fingerprints are fixed-size, so hashing one into the exact set costs the
/// same for every state, and the set's memory per entry is fixed.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Fingerprint([u8; 32]);

impl Fingerprint {
    /// All-zero padding value for fixed-size buffers. Not a real state's
    /// fingerprint in practice (it would need a SHA-256 preimage of zero).
    pub(crate) const ZERO: Self = Self([0u8; 32]);

    /// Full SHA-256 of `canonical_state`. The caller is responsible for the
    /// encoding being canonical (the same state always encodes to the same
    /// bytes).
    #[must_use]
    pub fn of_bytes(canonical_state: &[u8]) -> Self {
        Self(Sha256::digest(canonical_state).into())
    }

    /// Wrap a 32-byte digest the caller already computed.
    #[must_use]
    pub const fn from_digest(digest: [u8; 32]) -> Self {
        Self(digest)
    }

    /// The raw 32 bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Full 64-character lowercase hex. Never truncated.
    #[must_use]
    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }
}

impl fmt::Debug for Fingerprint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Fingerprint({})", self.to_hex())
    }
}

impl fmt::Display for Fingerprint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_hex())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_is_full_length() {
        let fp = Fingerprint::of_bytes(b"abc");
        assert_eq!(fp.to_hex().len(), 64);
        assert_eq!(
            fp.to_hex(),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert_eq!(format!("{fp}"), fp.to_hex());
    }

    #[test]
    fn from_digest_round_trips() {
        let d = [7u8; 32];
        assert_eq!(Fingerprint::from_digest(d).as_bytes(), &d);
    }
}
