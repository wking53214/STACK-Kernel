//! Signing and verifying records with the kernel's receipt key, and the
//! set of receipt keys an auditor trusts.
//!
//! The receipt key is the kernel's attestation key. The caller supplies
//! it; nothing here generates, defaults or embeds one. A signature proves
//! that the holder of the receipt key signed exactly this record hash. It
//! proves nothing about any person and nothing about whether the recorded
//! action was legitimate.
//!
//! The signature is over `SIGNATURE_DOMAIN || record_hash`, not over the
//! canonical bytes: the record hash already commits to every byte of the
//! record, and the domain keeps a receipt signature from ever being a
//! valid signature on anything else signed with the same key. The key id
//! sits inside the hashed region (`Record::key_id`), so a record is bound
//! to one key and a rotation cannot make it ambiguous.

use std::collections::HashMap;
use std::fmt;

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use sha2::{Digest, Sha256};

use crate::encode::{canonical_bytes, decode_record, record_hash, DecodeError, MAX_RECORD_BYTES};
use crate::record::{check_text, Record, ReceiptKeyId, ValidationError, MAX_ID_BYTES};

/// Domain separator hashed in front of a public key to make its id.
pub const RECEIPT_KEY_ID_DOMAIN: &[u8] = b"stack-receipt/key-id/1\n";
/// Domain separator in front of the record hash in the signed message.
pub const SIGNATURE_DOMAIN: &[u8] = b"stack-receipt/signature/1\n";
/// Bytes of an Ed25519 signature.
pub const SIGNATURE_BYTES: usize = 64;
/// Bytes a frame adds around the canonical record: the length prefix, the
/// signature and the record hash.
pub const FRAME_OVERHEAD: usize = 4 + SIGNATURE_BYTES + 32;

/// A public key is unusable.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("receipt public key is invalid or of small order")]
pub struct WeakKey;

/// The signature did not verify. One variant on purpose.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("receipt signature does not verify")]
pub struct BadSignature;

/// A receipt verifying key, validated on construction.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct ReceiptPublicKey {
    bytes: [u8; 32],
    key: VerifyingKey,
}

impl ReceiptPublicKey {
    /// Wraps a compressed Edwards point after checking that it decodes and
    /// is not of small order.
    pub fn from_bytes(bytes: [u8; 32]) -> Result<Self, WeakKey> {
        let key = VerifyingKey::from_bytes(&bytes).map_err(|_| WeakKey)?;
        if key.is_weak() {
            return Err(WeakKey);
        }
        Ok(Self { bytes, key })
    }

    /// The compressed point.
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.bytes
    }

    /// This key's id: SHA-256 over [`RECEIPT_KEY_ID_DOMAIN`] and the key.
    pub fn key_id(&self) -> ReceiptKeyId {
        let mut h = Sha256::new();
        h.update(RECEIPT_KEY_ID_DOMAIN);
        h.update(self.bytes);
        ReceiptKeyId::from_bytes(h.finalize().into())
    }

    /// Strict verification of `signature` over the signed message for
    /// `hash` (see [`signed_message`]).
    pub fn verify_hash(&self, hash: &[u8; 32], signature: &[u8; SIGNATURE_BYTES]) -> Result<(), BadSignature> {
        let sig = Signature::from_bytes(signature);
        self.key
            .verify_strict(&signed_message(hash), &sig)
            .map_err(|_| BadSignature)
    }
}

impl fmt::Debug for ReceiptPublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ReceiptPublicKey({})", hex::encode(self.bytes))
    }
}

/// The bytes a receipt signature covers: [`SIGNATURE_DOMAIN`] then the
/// record hash.
pub fn signed_message(hash: &[u8; 32]) -> Vec<u8> {
    let mut m = Vec::with_capacity(SIGNATURE_DOMAIN.len() + 32);
    m.extend_from_slice(SIGNATURE_DOMAIN);
    m.extend_from_slice(hash);
    m
}

/// Why a record could not be signed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum SignError {
    /// The record names a key id other than the signer's.
    #[error("record key id is not the signer's key id")]
    KeyIdMismatch,
    /// The record cannot be encoded.
    #[error("{0}")]
    Invalid(#[from] ValidationError),
}

/// The kernel's receipt signing key. The only signing path in the crate.
/// Debug output never shows the secret.
pub struct ReceiptSigner {
    key: SigningKey,
    public: ReceiptPublicKey,
    key_id: ReceiptKeyId,
}

impl ReceiptSigner {
    /// A signer from a 32-byte Ed25519 secret the caller holds.
    pub fn from_secret_bytes(secret: &[u8; 32]) -> Result<Self, WeakKey> {
        let key = SigningKey::from_bytes(secret);
        let public = ReceiptPublicKey::from_bytes(key.verifying_key().to_bytes())?;
        let key_id = public.key_id();
        Ok(Self { key, public, key_id })
    }

    /// The verifying key.
    pub const fn public_key(&self) -> &ReceiptPublicKey {
        &self.public
    }

    /// The key id every record signed here must carry.
    pub const fn key_id(&self) -> &ReceiptKeyId {
        &self.key_id
    }

    /// Encodes, hashes and signs `record`, which must name this key.
    pub fn sign(&self, record: Record) -> Result<SignedRecord, SignError> {
        if record.key_id != self.key_id {
            return Err(SignError::KeyIdMismatch);
        }
        let canonical = canonical_bytes(&record)?;
        let hash = record_hash(&canonical);
        let signature = self.key.sign(&signed_message(&hash)).to_bytes();
        Ok(SignedRecord {
            record,
            canonical,
            hash,
            signature,
        })
    }
}

impl fmt::Debug for ReceiptSigner {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ReceiptSigner")
            .field("key_id", &self.key_id)
            .finish_non_exhaustive()
    }
}

/// Why bytes are not a frame.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum FrameError {
    /// Fewer bytes than the frame declares. `have` is what is present.
    #[error("frame cut off: declares {declared} record bytes, {have} bytes present")]
    Truncated {
        /// Length the prefix declares.
        declared: usize,
        /// Bytes present after the prefix.
        have: usize,
    },
    /// The length prefix is zero or above [`MAX_RECORD_BYTES`].
    #[error("frame length {0} out of range")]
    LengthOutOfRange(usize),
    /// The stored hash is not the hash of the canonical bytes.
    #[error("stored record hash does not match the record")]
    HashMismatch,
    /// The canonical bytes do not decode.
    #[error("{0}")]
    Decode(#[from] DecodeError),
}

/// A record with its canonical bytes, hash and signature. Built only by
/// [`ReceiptSigner::sign`] or by parsing a frame; the parts always agree.
#[derive(Clone, PartialEq, Eq)]
pub struct SignedRecord {
    record: Record,
    canonical: Vec<u8>,
    hash: [u8; 32],
    signature: [u8; SIGNATURE_BYTES],
}

impl SignedRecord {
    /// The record.
    pub const fn record(&self) -> &Record {
        &self.record
    }

    /// The canonical bytes the hash covers.
    pub fn canonical(&self) -> &[u8] {
        &self.canonical
    }

    /// The record hash.
    pub const fn hash(&self) -> &[u8; 32] {
        &self.hash
    }

    /// The signature.
    pub const fn signature(&self) -> &[u8; SIGNATURE_BYTES] {
        &self.signature
    }

    /// Strict verification under `key`. The key's id must be the one the
    /// record names; a mismatch is reported as a bad signature, because
    /// that is what it would be.
    pub fn verify(&self, key: &ReceiptPublicKey) -> Result<(), BadSignature> {
        if key.key_id() != self.record.key_id {
            return Err(BadSignature);
        }
        key.verify_hash(&self.hash, &self.signature)
    }

    /// Assembles a signed record from parts the caller holds, checking
    /// that the canonical bytes decode and that the hash is theirs. The
    /// signature is not checked here; [`SignedRecord::verify`] does that.
    pub fn from_parts(
        canonical: Vec<u8>,
        signature: [u8; SIGNATURE_BYTES],
        hash: [u8; 32],
    ) -> Result<Self, FrameError> {
        let record = decode_record(&canonical)?;
        if record_hash(&canonical) != hash {
            return Err(FrameError::HashMismatch);
        }
        Ok(Self {
            record,
            canonical,
            hash,
            signature,
        })
    }

    /// The on-disk frame: `u32` big-endian length of the canonical bytes,
    /// the canonical bytes, the signature, the record hash.
    pub fn to_frame(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(self.canonical.len() + FRAME_OVERHEAD);
        out.extend_from_slice(&u32::try_from(self.canonical.len()).unwrap_or(u32::MAX).to_be_bytes());
        out.extend_from_slice(&self.canonical);
        out.extend_from_slice(&self.signature);
        out.extend_from_slice(&self.hash);
        out
    }

    /// Parses one frame from the start of `bytes`. Returns the record and
    /// the number of bytes consumed.
    pub fn parse_frame(bytes: &[u8]) -> Result<(Self, usize), FrameError> {
        let len_bytes = bytes.get(..4).ok_or(FrameError::Truncated {
            declared: 0,
            have: bytes.len(),
        })?;
        let declared = usize::try_from(u32::from_be_bytes(<[u8; 4]>::try_from(len_bytes).unwrap_or([0; 4])))
            .unwrap_or(usize::MAX);
        if declared == 0 || declared > MAX_RECORD_BYTES {
            return Err(FrameError::LengthOutOfRange(declared));
        }
        let total = 4 + declared + SIGNATURE_BYTES + 32;
        let Some(frame) = bytes.get(..total) else {
            return Err(FrameError::Truncated {
                declared,
                have: bytes.len().saturating_sub(4),
            });
        };
        let (Some(canonical), Some(sig), Some(hash)) = (
            frame.get(4..4 + declared),
            frame.get(4 + declared..4 + declared + SIGNATURE_BYTES),
            frame.get(4 + declared + SIGNATURE_BYTES..total),
        ) else {
            return Err(FrameError::Truncated {
                declared,
                have: bytes.len().saturating_sub(4),
            });
        };
        let signature = <[u8; SIGNATURE_BYTES]>::try_from(sig).map_err(|_| FrameError::Truncated {
            declared,
            have: bytes.len().saturating_sub(4),
        })?;
        let hash = <[u8; 32]>::try_from(hash).map_err(|_| FrameError::Truncated {
            declared,
            have: bytes.len().saturating_sub(4),
        })?;
        let signed = Self::from_parts(canonical.to_vec(), signature, hash)?;
        Ok((signed, total))
    }
}

impl fmt::Debug for SignedRecord {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SignedRecord")
            .field("sequence", &self.record.sequence)
            .field("stage", &self.record.stage())
            .field("hash", &hex::encode(self.hash))
            .finish_non_exhaustive()
    }
}

// ---------------------------------------------------------------------------
// Trusted receipt keys
// ---------------------------------------------------------------------------

/// Whether an anchor is still trusted.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ReceiptKeyStatus {
    /// Trusted inside its window.
    Active,
    /// No longer trusted, at any time.
    Revoked,
}

/// Why a trust-set operation was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum TrustError {
    /// The kernel id breaks the identifier rules.
    #[error("kernel id refused: {0}")]
    BadKernelId(ValidationError),
    /// `not_after_ms` is not after `not_before_ms`.
    #[error("not_after_ms is not after not_before_ms")]
    WindowInverted,
    /// An anchor with this key id is already in the set.
    #[error("an anchor with this key id is already in the set")]
    Duplicate,
    /// The set holds its maximum number of anchors.
    #[error("full ({max} anchors)")]
    Full {
        /// The cap.
        max: usize,
    },
}

/// Why `(kernel_id, key_id)` did not resolve at a given instant. Every
/// variant is a fact about the auditor's own trust set.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ResolveError {
    /// No anchor has this key id under this kernel.
    #[error("key is not a trusted receipt key for this kernel")]
    UntrustedKey,
    /// The anchor is revoked.
    #[error("receipt key is revoked")]
    Revoked,
    /// The instant is before the anchor's window.
    #[error("receipt key is not yet valid at that time")]
    NotYetValid,
    /// The instant is at or after the end of the anchor's window.
    #[error("receipt key has expired at that time")]
    Expired,
}

/// One trusted receipt key: which kernel it speaks for, its window and
/// status. The key id is derived, never supplied.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReceiptKeyAnchor {
    kernel_id: String,
    key_id: ReceiptKeyId,
    public_key: ReceiptPublicKey,
    not_before_ms: u64,
    not_after_ms: u64,
    status: ReceiptKeyStatus,
}

impl ReceiptKeyAnchor {
    /// An active anchor for `kernel_id`. The window is
    /// `not_before_ms <= recorded_at < not_after_ms`, judged against the
    /// time a record claims it was made.
    pub fn new(
        kernel_id: &str,
        public_key: ReceiptPublicKey,
        not_before_ms: u64,
        not_after_ms: u64,
    ) -> Result<Self, TrustError> {
        check_text("kernel_id", kernel_id, 1, MAX_ID_BYTES).map_err(TrustError::BadKernelId)?;
        if not_after_ms <= not_before_ms {
            return Err(TrustError::WindowInverted);
        }
        Ok(Self {
            kernel_id: kernel_id.to_owned(),
            key_id: public_key.key_id(),
            public_key,
            not_before_ms,
            not_after_ms,
            status: ReceiptKeyStatus::Active,
        })
    }

    /// The kernel this key is trusted to sign for.
    pub fn kernel_id(&self) -> &str {
        &self.kernel_id
    }

    /// The key id.
    pub const fn key_id(&self) -> &ReceiptKeyId {
        &self.key_id
    }

    /// The key.
    pub const fn public_key(&self) -> &ReceiptPublicKey {
        &self.public_key
    }

    /// Start of the window, inclusive.
    pub const fn not_before_ms(&self) -> u64 {
        self.not_before_ms
    }

    /// End of the window, exclusive.
    pub const fn not_after_ms(&self) -> u64 {
        self.not_after_ms
    }

    /// The status.
    pub const fn status(&self) -> ReceiptKeyStatus {
        self.status
    }
}

/// The receipt keys an auditor trusts, bounded, keyed by key id.
#[derive(Debug, Clone)]
pub struct TrustedReceiptKeys {
    anchors: HashMap<ReceiptKeyId, ReceiptKeyAnchor>,
    max_anchors: usize,
}

impl TrustedReceiptKeys {
    /// Default cap on the number of anchors.
    pub const DEFAULT_MAX_ANCHORS: usize = 1024;

    /// An empty set that trusts nothing.
    pub fn new(max_anchors: usize) -> Self {
        Self {
            anchors: HashMap::new(),
            max_anchors,
        }
    }

    /// Adds an anchor and returns its key id.
    pub fn insert(&mut self, anchor: ReceiptKeyAnchor) -> Result<ReceiptKeyId, TrustError> {
        let id = *anchor.key_id();
        if self.anchors.contains_key(&id) {
            return Err(TrustError::Duplicate);
        }
        if self.anchors.len() >= self.max_anchors {
            return Err(TrustError::Full { max: self.max_anchors });
        }
        self.anchors.insert(id, anchor);
        Ok(id)
    }

    /// Marks the anchor revoked. It stays in the set so a record under it
    /// is refused as revoked and the key cannot be re-inserted.
    pub fn revoke(&mut self, key_id: &ReceiptKeyId) -> bool {
        match self.anchors.get_mut(key_id) {
            Some(a) if a.status == ReceiptKeyStatus::Active => {
                a.status = ReceiptKeyStatus::Revoked;
                true
            }
            _ => false,
        }
    }

    /// The anchor with this key id, whatever its status.
    pub fn get(&self, key_id: &ReceiptKeyId) -> Option<&ReceiptKeyAnchor> {
        self.anchors.get(key_id)
    }

    /// Number of anchors held.
    pub fn len(&self) -> usize {
        self.anchors.len()
    }

    /// Whether the set holds no anchors.
    pub fn is_empty(&self) -> bool {
        self.anchors.is_empty()
    }

    /// The anchor for `(kernel_id, key_id)` that is active and whose
    /// window contains `at_ms`, or why there is none. Checked in that
    /// order: identity, then status, then window.
    pub fn resolve(&self, kernel_id: &str, key_id: &ReceiptKeyId, at_ms: u64) -> Result<&ReceiptKeyAnchor, ResolveError> {
        let anchor = self.anchors.get(key_id).ok_or(ResolveError::UntrustedKey)?;
        if anchor.kernel_id != kernel_id {
            return Err(ResolveError::UntrustedKey);
        }
        if anchor.status == ReceiptKeyStatus::Revoked {
            return Err(ResolveError::Revoked);
        }
        if at_ms < anchor.not_before_ms {
            return Err(ResolveError::NotYetValid);
        }
        if at_ms >= anchor.not_after_ms {
            return Err(ResolveError::Expired);
        }
        Ok(anchor)
    }
}
