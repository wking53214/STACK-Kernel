//! Fixed-size 32-byte digests and their one accepted text spelling.
//!
//! A CNS `subject_digest` and a CNS decision root are both SHA-256 values
//! written as 64 lowercase hex characters. This module gives them one
//! type, [`Digest32`], whose text form is exactly that spelling: uppercase
//! or shortened input is refused, so every digest has one encoding and a
//! comparison by bytes is a comparison by value.

use std::fmt;

use subtle::ConstantTimeEq;

/// A 32-byte digest. Never truncated, never shown shortened.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Digest32([u8; 32]);

impl Digest32 {
    /// Wraps raw bytes.
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Parses exactly 64 lowercase hex characters. Anything else is `None`.
    pub fn from_hex(s: &str) -> Option<Self> {
        decode_hex_lower::<32>(s).map(Self)
    }

    /// The 64-character lowercase hex form.
    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }

    /// The raw bytes.
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Constant-time equality. Nothing compared here is secret; the
    /// constant-time form is used so that a future secret-bearing caller
    /// does not have to remember to switch.
    pub fn ct_eq(&self, other: &Self) -> bool {
        self.0.ct_eq(&other.0).into()
    }
}

impl fmt::Debug for Digest32 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Digest32({})", self.to_hex())
    }
}

impl fmt::Display for Digest32 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_hex())
    }
}

/// Decodes exactly `2 * N` lowercase hex characters. Uppercase is refused
/// so that every byte string has exactly one accepted spelling.
pub fn decode_hex_lower<const N: usize>(s: &str) -> Option<[u8; N]> {
    let bytes = s.as_bytes();
    if bytes.len() != N.checked_mul(2)? {
        return None;
    }
    if !bytes
        .iter()
        .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
    {
        return None;
    }
    let mut out = [0u8; N];
    hex::decode_to_slice(bytes, &mut out).ok()?;
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_round_trip_is_lowercase_and_full_length() {
        let d = Digest32::from_bytes([0xab; 32]);
        let h = d.to_hex();
        assert_eq!(h.len(), 64);
        assert_eq!(h, "ab".repeat(32));
        assert_eq!(Digest32::from_hex(&h), Some(d));
        assert_eq!(Digest32::from_hex(&h.to_uppercase()), None);
        assert_eq!(Digest32::from_hex(&h[..63]), None);
        assert_eq!(Digest32::from_hex(&format!("{h}0")), None);
        assert_eq!(Digest32::from_hex(&"zz".repeat(32)), None);
        assert!(d.ct_eq(&d));
        assert!(!d.ct_eq(&Digest32::from_bytes([0; 32])));
        assert_eq!(format!("{d}"), h);
        assert_eq!(format!("{d:?}"), format!("Digest32({h})"));
    }
}
