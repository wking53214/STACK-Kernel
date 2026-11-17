//! A CNS decision receipt: a signed statement that CNS made a decision about a subject.
//!
//! The issuer cannot tell a real CNS decision from a self-consistent forgery by looking at
//! the decision alone: CNS's own proof is an HMAC under a key that never leaves the CNS
//! process. A receipt closes that gap. CNS signs, with a key of its own, a short statement of
//! fact, "I decided this root about this subject, between these two times". The issuer holds
//! the matching public key and checks the statement before it signs a capability.
//!
//! This is evidence, not authority. A receipt says CNS decided; it does not say anything may
//! run. The issuer still applies its own policy and its own authorizer.
//!
//! # Wire form (version 1), 193 bytes, fixed length, nothing optional
//!
//! | bytes | field |
//! |---|---|
//! | 1 | version, `1` |
//! | 32 | key id of the CNS key (the id `stack-authority` gives every key) |
//! | 32 | subject digest |
//! | 32 | decision root |
//! | 8 | issued at, milliseconds since the Unix epoch, big endian |
//! | 8 | expires at, milliseconds since the Unix epoch, big endian |
//! | 16 | nonce, set by CNS; not checked here (the per-decision caps bound reuse) |
//! | 64 | Ed25519 signature |
//!
//! The signature is over [`RECEIPT_DOMAIN`] followed by every byte above except the
//! signature. The domain label keeps a signature made for something else from being read as a
//! receipt.
//!
//! # What the verifier checks, in this order
//!
//! length and version; the key id is one it pins; the signature (strict) verifies; only then
//! is anything inside the receipt believed: the key's window covers now and the issue time,
//! the subject and root equal the values the issuer recomputed itself, the life is positive
//! and no longer than the verifier allows, it is not from the future beyond the skew, and it
//! has not expired.
//!
//! # What it does not do
//!
//! A compromised CNS signing key signs anything. A receipt can be presented more than once
//! inside its life; the issuer's per-decision and per-subject caps are what bound that.

use std::fmt;

use stack_authority::{Clock, Digest32, KeyId, PublicKey, KEY_ID_BYTES, SIGNATURE_BYTES};

use crate::hooks::{DecisionVerifier, Refusal};

/// The label hashed into every receipt signature.
pub const RECEIPT_DOMAIN: &[u8] = b"stack-issuer/cns-decision-receipt/1\n";
/// The only version this crate reads.
pub const RECEIPT_VERSION: u8 = 1;
/// Bytes of nonce.
pub const RECEIPT_NONCE_BYTES: usize = 16;
/// Bytes of the part the signature covers (without the domain label).
const BODY_LEN: usize = 1 + KEY_ID_BYTES + 32 + 32 + 8 + 8 + RECEIPT_NONCE_BYTES;
/// Bytes of a receipt on the wire.
pub const RECEIPT_LEN: usize = BODY_LEN + SIGNATURE_BYTES;
/// Most keys a verifier will pin.
pub const MAX_ATTESTER_KEYS: usize = 8;
/// Longest life a verifier may be configured to allow.
pub const MAX_RECEIPT_VALIDITY_CEILING_MS: u64 = 24 * 60 * 60 * 1000;
/// Largest clock skew a verifier may be configured to tolerate.
pub const MAX_SKEW_CEILING_MS: u64 = 5 * 60 * 1000;

/// The fields of a receipt. CNS (or a test) builds one, signs [`ReceiptFields::signed_bytes`],
/// and calls [`ReceiptFields::encode`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReceiptFields {
    /// The id of the key that signs.
    pub key_id: KeyId,
    /// The subject digest the decision is about.
    pub subject_digest: Digest32,
    /// The decision root.
    pub decision_root: Digest32,
    /// When CNS made the statement.
    pub issued_at_ms: u64,
    /// When the statement stops being good.
    pub expires_at_ms: u64,
    /// A value CNS picks. Recorded, not checked here.
    pub nonce: [u8; RECEIPT_NONCE_BYTES],
}

impl ReceiptFields {
    fn body(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(BODY_LEN);
        out.push(RECEIPT_VERSION);
        out.extend_from_slice(self.key_id.as_bytes());
        out.extend_from_slice(self.subject_digest.as_bytes());
        out.extend_from_slice(self.decision_root.as_bytes());
        out.extend_from_slice(&self.issued_at_ms.to_be_bytes());
        out.extend_from_slice(&self.expires_at_ms.to_be_bytes());
        out.extend_from_slice(&self.nonce);
        out
    }

    /// The bytes the signature covers: the domain label, then the body.
    pub fn signed_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(RECEIPT_DOMAIN.len() + BODY_LEN);
        out.extend_from_slice(RECEIPT_DOMAIN);
        out.extend_from_slice(&self.body());
        out
    }

    /// The wire form: the body, then the signature over [`Self::signed_bytes`].
    pub fn encode(&self, signature: &[u8; SIGNATURE_BYTES]) -> Vec<u8> {
        let mut out = self.body();
        out.extend_from_slice(signature);
        out
    }
}

/// Why a receipt was refused. The text goes to the operator's log, never to the requester.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ReceiptError {
    /// Not exactly [`RECEIPT_LEN`] bytes.
    #[error("receipt has the wrong length")]
    BadLength,
    /// A version this crate does not read.
    #[error("receipt version is not supported")]
    BadVersion,
    /// The key id is not one the verifier pins.
    #[error("receipt names a key that is not pinned")]
    UnknownKey,
    /// The signature does not verify under the pinned key.
    #[error("receipt signature does not verify")]
    BadSignature,
    /// The key's window does not cover now and the time the receipt was issued.
    #[error("receipt key is outside its window")]
    KeyNotInWindow,
    /// The receipt is about another subject.
    #[error("receipt is about another subject")]
    SubjectMismatch,
    /// The receipt is about another decision.
    #[error("receipt is about another decision")]
    RootMismatch,
    /// Its life is not positive, or is longer than this verifier allows.
    #[error("receipt life is not positive or is too long")]
    TooLong,
    /// Issued later than now plus the skew.
    #[error("receipt is from the future")]
    NotYetValid,
    /// Past its expiry.
    #[error("receipt has expired")]
    Expired,
    /// No receipt was supplied, and this verifier requires one.
    #[error("a CNS decision receipt is required")]
    Missing,
}

/// Why a verifier could not be built.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ReceiptConfigError {
    /// No key pinned.
    #[error("no CNS key is pinned")]
    NoKeys,
    /// More than [`MAX_ATTESTER_KEYS`].
    #[error("too many pinned keys")]
    TooManyKeys,
    /// A key's `not_after_ms` is not after its `not_before_ms`.
    #[error("a key's window ends before it starts")]
    WindowInverted,
    /// The same key is pinned twice.
    #[error("a key is pinned twice")]
    DuplicateKey,
    /// The allowed receipt life is zero or over the ceiling.
    #[error("the allowed receipt life is zero or over the ceiling")]
    Validity,
    /// The allowed clock skew is over the ceiling.
    #[error("the allowed clock skew is over the ceiling")]
    Skew,
}

/// A pinned CNS public key and the window in which it is trusted.
#[derive(Debug, Clone, Copy)]
pub struct AttesterKey {
    /// The CNS public key.
    pub key: PublicKey,
    /// Trusted from this time (inclusive), milliseconds since the Unix epoch.
    pub not_before_ms: u64,
    /// Trusted until this time (inclusive).
    pub not_after_ms: u64,
}

/// Checks that a CNS decision is real by checking a receipt CNS signed for it.
///
/// Rotation: pin the new key before the old one retires, with overlapping windows. A key
/// outside its window refuses every receipt, even an unexpired one.
pub struct CnsReceiptVerifier {
    keys: Vec<AttesterKey>,
    max_validity_ms: u64,
    skew_ms: u64,
    clock: Box<dyn Clock>,
}

impl fmt::Debug for CnsReceiptVerifier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CnsReceiptVerifier")
            .field("keys", &self.keys.len())
            .field("max_validity_ms", &self.max_validity_ms)
            .field("skew_ms", &self.skew_ms)
            .finish_non_exhaustive()
    }
}

impl CnsReceiptVerifier {
    /// A verifier pinning `keys`, refusing receipts that claim a life over `max_validity_ms`,
    /// and tolerating `skew_ms` of difference between CNS's clock and this one.
    pub fn new(keys: Vec<AttesterKey>, max_validity_ms: u64, skew_ms: u64, clock: Box<dyn Clock>) -> Result<Self, ReceiptConfigError> {
        if keys.is_empty() {
            return Err(ReceiptConfigError::NoKeys);
        }
        if keys.len() > MAX_ATTESTER_KEYS {
            return Err(ReceiptConfigError::TooManyKeys);
        }
        if keys.iter().any(|k| k.not_after_ms <= k.not_before_ms) {
            return Err(ReceiptConfigError::WindowInverted);
        }
        for (i, a) in keys.iter().enumerate() {
            if keys.iter().skip(i + 1).any(|b| b.key.key_id() == a.key.key_id()) {
                return Err(ReceiptConfigError::DuplicateKey);
            }
        }
        if max_validity_ms == 0 || max_validity_ms > MAX_RECEIPT_VALIDITY_CEILING_MS {
            return Err(ReceiptConfigError::Validity);
        }
        if skew_ms > MAX_SKEW_CEILING_MS {
            return Err(ReceiptConfigError::Skew);
        }
        Ok(Self { keys, max_validity_ms, skew_ms, clock })
    }

    /// Checks `receipt` against the subject digest and decision root the issuer recomputed.
    pub fn check(&self, subject_digest: &Digest32, decision_root: &Digest32, receipt: &[u8]) -> Result<(), ReceiptError> {
        if receipt.len() != RECEIPT_LEN {
            return Err(ReceiptError::BadLength);
        }
        let (body, signature) = receipt.split_at(BODY_LEN);
        let (version, rest) = body.split_first().ok_or(ReceiptError::BadLength)?;
        if *version != RECEIPT_VERSION {
            return Err(ReceiptError::BadVersion);
        }
        let (key_id, rest) = rest.split_at(KEY_ID_BYTES);
        let (subject, rest) = rest.split_at(32);
        let (root, rest) = rest.split_at(32);
        let (issued, rest) = rest.split_at(8);
        let (expires, nonce) = rest.split_at(8);
        let issued_at_ms = u64::from_be_bytes(issued.try_into().map_err(|_| ReceiptError::BadLength)?);
        let expires_at_ms = u64::from_be_bytes(expires.try_into().map_err(|_| ReceiptError::BadLength)?);
        let nonce: [u8; RECEIPT_NONCE_BYTES] = nonce.try_into().map_err(|_| ReceiptError::BadLength)?;
        let key_id: [u8; KEY_ID_BYTES] = key_id.try_into().map_err(|_| ReceiptError::BadLength)?;
        let signature: [u8; SIGNATURE_BYTES] = signature.try_into().map_err(|_| ReceiptError::BadLength)?;
        let subject: [u8; 32] = subject.try_into().map_err(|_| ReceiptError::BadLength)?;
        let root: [u8; 32] = root.try_into().map_err(|_| ReceiptError::BadLength)?;

        let pinned = self.keys.iter().find(|k| k.key.key_id() == KeyId::from_bytes(key_id)).ok_or(ReceiptError::UnknownKey)?;
        let fields = ReceiptFields {
            key_id: KeyId::from_bytes(key_id),
            subject_digest: Digest32::from_bytes(subject),
            decision_root: Digest32::from_bytes(root),
            issued_at_ms,
            expires_at_ms,
            nonce,
        };
        // Nothing inside the receipt is believed until the signature verifies.
        pinned.key.verify_strict(&fields.signed_bytes(), &signature).map_err(|_| ReceiptError::BadSignature)?;

        let now = self.clock.now_unix_ms();
        if now < pinned.not_before_ms || now > pinned.not_after_ms || issued_at_ms < pinned.not_before_ms {
            return Err(ReceiptError::KeyNotInWindow);
        }
        if !fields.subject_digest.ct_eq(subject_digest) {
            return Err(ReceiptError::SubjectMismatch);
        }
        if !fields.decision_root.ct_eq(decision_root) {
            return Err(ReceiptError::RootMismatch);
        }
        match expires_at_ms.checked_sub(issued_at_ms) {
            Some(life) if life > 0 && life <= self.max_validity_ms => {}
            _ => return Err(ReceiptError::TooLong),
        }
        if issued_at_ms > now.saturating_add(self.skew_ms) {
            return Err(ReceiptError::NotYetValid);
        }
        if now >= expires_at_ms {
            return Err(ReceiptError::Expired);
        }
        Ok(())
    }
}

impl DecisionVerifier for CnsReceiptVerifier {
    /// Refuses: this verifier needs a receipt, which `verify` is not given. Use
    /// [`Issuer::issue_with_receipt`](crate::Issuer::issue_with_receipt).
    fn verify(&self, _: &Digest32, _: &stack_admission::DecisionClaim, _: &Digest32) -> Result<(), Refusal> {
        Err(Refusal(ReceiptError::Missing.to_string()))
    }

    fn verify_with_receipt(
        &self,
        subject_digest: &Digest32,
        _: &stack_admission::DecisionClaim,
        decision_root: &Digest32,
        receipt: Option<&[u8]>,
    ) -> Result<(), Refusal> {
        let receipt = receipt.ok_or_else(|| Refusal(ReceiptError::Missing.to_string()))?;
        self.check(subject_digest, decision_root, receipt).map_err(|e| Refusal(e.to_string()))
    }
}
