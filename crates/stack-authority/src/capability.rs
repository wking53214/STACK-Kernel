//! The capability: its fields, its one wire encoding, its strict parser
//! and its digest.
//!
//! # Wire format, `stack-capability/1`
//!
//! Every integer is big-endian. Every string is UTF-8, length-prefixed by
//! a `u16`, and may not contain a control character (below U+0020, or
//! U+007F). Sets are written in strictly increasing byte order with no
//! duplicate, so one set has one encoding.
//!
//! ```text
//! signed region
//!   "stack-capability/1\n"            19 bytes, the domain and version tag
//!   cap_id          u16 len, 1..=128 bytes
//!   issuer_id       u16 len, 1..=128 bytes
//!   audience        u16 len, 1..=128 bytes
//!   subject_digest  32 bytes (the CNS subject digest, raw)
//!   decision_root   32 bytes (the CNS decision root, raw)
//!   operations      u16 count, 1..=64, then each: u16 len, 1..=64 bytes;
//!                   strictly increasing by bytes
//!   resources       u16 count, 1..=64, then each: u8 kind (0 exact,
//!                   1 prefix), u16 len, 1..=1024 bytes of path (see
//!                   `scope`); strictly increasing by (path bytes, kind)
//!   not_before_ms   u64
//!   expires_at_ms   u64, strictly greater than not_before_ms
//!   one_time        u8, 0 or 1
//!   policy_ref      u16 len, 0..=256 bytes
//!   nonce           16 bytes
//!   key_id          32 bytes (full SHA-256 fingerprint of the issuer's
//!                   public key, see `trust`)
//! signature         64 bytes, Ed25519 over the signed region
//! ```
//!
//! Nothing may follow the signature. The parser reads every field under
//! the bounds above and refuses on the first violation; it never
//! allocates in proportion to a declared length before checking that the
//! bytes are present.
//!
//! # Digest
//!
//! The capability digest is SHA-256 over [`DIGEST_DOMAIN`] followed by the
//! whole wire form, signature included. Ed25519 signatures are
//! deterministic and the verifier uses strict verification, so one signed
//! capability has one digest. It is 32 bytes, written as 64 hex
//! characters, and is never truncated. It is the capability's name in
//! receipts and in the use store.

use std::fmt;

use sha2::{Digest, Sha256};

use crate::digest::Digest32;
use crate::scope::{is_control, validate_path, PathError, ResourceScope, ScopeKind, MAX_PATH_BYTES};

/// The domain and version tag that opens every encoding.
pub const DOMAIN_TAG: &[u8] = b"stack-capability/1\n";
/// The prefix shared by every version of the format, used to tell an
/// unsupported version from unrelated bytes.
const DOMAIN_PREFIX: &[u8] = b"stack-capability/";
/// Domain separator hashed in front of the wire form to make the digest.
pub const DIGEST_DOMAIN: &[u8] = b"stack-authority/capability-digest/1\n";

/// Longest `cap_id`, `issuer_id` or `audience`, in bytes.
pub const MAX_ID_BYTES: usize = 128;
/// Longest operation name, in bytes.
pub const MAX_OPERATION_BYTES: usize = 64;
/// Most operations in one capability.
pub const MAX_OPERATIONS: usize = 64;
/// Most resource scopes in one capability.
pub const MAX_RESOURCES: usize = 64;
/// Longest `policy_ref`, in bytes. May be empty.
pub const MAX_POLICY_REF_BYTES: usize = 256;
/// Nonce length, in bytes.
pub const NONCE_BYTES: usize = 16;
/// Key identifier length, in bytes (a full SHA-256).
pub const KEY_ID_BYTES: usize = 32;
/// Ed25519 signature length, in bytes.
pub const SIGNATURE_BYTES: usize = 64;

/// The longest wire form the format can express. Longer input is refused
/// before anything is read.
pub const MAX_WIRE_BYTES: usize = DOMAIN_TAG.len()
    + 3 * (2 + MAX_ID_BYTES)
    + 32
    + 32
    + 2
    + MAX_OPERATIONS * (2 + MAX_OPERATION_BYTES)
    + 2
    + MAX_RESOURCES * (1 + 2 + MAX_PATH_BYTES)
    + 8
    + 8
    + 1
    + 2
    + MAX_POLICY_REF_BYTES
    + NONCE_BYTES
    + KEY_ID_BYTES
    + SIGNATURE_BYTES;

/// The shortest wire form the format can express: one-byte identifiers,
/// one one-byte operation, one one-byte path, an empty policy reference.
pub const MIN_WIRE_BYTES: usize = DOMAIN_TAG.len()
    + 3 * (2 + 1)
    + 32
    + 32
    + 2
    + (2 + 1)
    + 2
    + (1 + 2 + 1)
    + 8
    + 8
    + 1
    + 2
    + NONCE_BYTES
    + KEY_ID_BYTES
    + SIGNATURE_BYTES;

/// Which field an error is about.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Field {
    /// `cap_id`.
    CapId,
    /// `issuer_id`.
    IssuerId,
    /// `audience`.
    Audience,
    /// The operations set as a whole.
    Operations,
    /// One operation name.
    Operation,
    /// The resources set as a whole.
    Resources,
    /// One resource path.
    ResourcePath,
    /// `policy_ref`.
    PolicyRef,
}

impl fmt::Display for Field {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::CapId => "cap_id",
            Self::IssuerId => "issuer_id",
            Self::Audience => "audience",
            Self::Operations => "operations",
            Self::Operation => "operation",
            Self::Resources => "resources",
            Self::ResourcePath => "resource path",
            Self::PolicyRef => "policy_ref",
        })
    }
}

/// Why bytes were not accepted as a capability, or why a [`Capability`]
/// could not be encoded.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ParseError {
    /// Longer than the caller's cap or than [`MAX_WIRE_BYTES`].
    #[error("input exceeds the byte cap")]
    TooLarge,
    /// The input ended inside a field.
    #[error("input ends inside a field")]
    Truncated,
    /// Bytes follow the signature.
    #[error("bytes follow the signature")]
    TrailingBytes,
    /// The input does not open with the `stack-capability/` prefix.
    #[error("input does not carry the stack-capability domain tag")]
    BadDomainTag,
    /// The input opens with the prefix but names a version other than 1.
    #[error("unsupported stack-capability version")]
    UnsupportedVersion,
    /// A string or set is outside its length bounds.
    #[error("{0} is outside its length bounds")]
    LengthOutOfBounds(Field),
    /// A string is not UTF-8.
    #[error("{0} is not valid UTF-8")]
    InvalidUtf8(Field),
    /// A string holds a control character.
    #[error("{0} holds a control character")]
    ControlCharacter(Field),
    /// A set is empty.
    #[error("{0} is empty")]
    EmptyScope(Field),
    /// A set's members are not in strictly increasing order.
    #[error("{0} members are not in canonical order")]
    UnsortedSet(Field),
    /// A set holds the same member twice.
    #[error("{0} holds a duplicate member")]
    DuplicateMember(Field),
    /// `one_time` is a byte other than 0 or 1.
    #[error("one_time is not 0 or 1")]
    BadBool,
    /// A scope kind byte is not 0 or 1.
    #[error("resource scope kind is not 0 or 1")]
    BadScopeKind,
    /// A resource path breaks the path rules.
    #[error("resource path refused: {0}")]
    BadPath(PathError),
    /// `expires_at_ms` is not after `not_before_ms`.
    #[error("expires_at_ms is not after not_before_ms")]
    WindowInverted,
}

/// A capability's fields. Public so that an issuer, or a test, can build
/// one; the encoder validates every field before writing it, and the
/// parser validates every field as it reads it, so an invalid
/// `Capability` can exist in memory but never on the wire.
///
/// `operations` and `resources` must be in strictly increasing order with
/// no duplicate (see [`Capability::normalise`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Capability {
    /// Unique identifier chosen by the issuer. 1 to 128 bytes.
    pub cap_id: String,
    /// The issuer's identity, resolved in the trust set. 1 to 128 bytes.
    pub issuer_id: String,
    /// The verifier this capability is addressed to. 1 to 128 bytes.
    pub audience: String,
    /// CNS subject digest of the content this capability is about.
    pub subject_digest: Digest32,
    /// CNS decision root of the decision that governs this capability.
    pub decision_root: Digest32,
    /// Exact operation names, sorted, unique, 1 to 64 of them.
    pub operations: Vec<String>,
    /// Resource scopes, sorted, unique, 1 to 64 of them.
    pub resources: Vec<ResourceScope>,
    /// Earliest instant this capability may be used, Unix milliseconds.
    pub not_before_ms: u64,
    /// Instant from which this capability is refused, Unix milliseconds.
    /// Strictly after `not_before_ms`.
    pub expires_at_ms: u64,
    /// Whether this capability may authorize at most one action.
    pub one_time: bool,
    /// Reference to the policy under which it was issued. 0 to 256 bytes.
    pub policy_ref: String,
    /// Issuer-chosen nonce, so two capabilities with equal fields differ.
    pub nonce: [u8; NONCE_BYTES],
}

impl Capability {
    /// Sorts and deduplicates `operations` and `resources`. The encoder
    /// does not do this for the caller, because a set that arrives
    /// unsorted on the wire is a parse error and the two paths should
    /// agree about what is canonical.
    pub fn normalise(&mut self) {
        self.operations.sort_unstable_by(|a, b| a.as_bytes().cmp(b.as_bytes()));
        self.operations.dedup();
        self.resources.sort_unstable();
        self.resources.dedup();
    }

    /// Encodes the signed region (everything before the signature) for
    /// `key_id`, validating every field. This is the exact byte string an
    /// issuer signs and the verifier checks the signature over.
    pub fn encode_signed_region(&self, key_id: &[u8; KEY_ID_BYTES]) -> Result<Vec<u8>, ParseError> {
        let mut out = Vec::with_capacity(512);
        out.extend_from_slice(DOMAIN_TAG);
        put_str(&mut out, Field::CapId, &self.cap_id, 1, MAX_ID_BYTES)?;
        put_str(&mut out, Field::IssuerId, &self.issuer_id, 1, MAX_ID_BYTES)?;
        put_str(&mut out, Field::Audience, &self.audience, 1, MAX_ID_BYTES)?;
        out.extend_from_slice(self.subject_digest.as_bytes());
        out.extend_from_slice(self.decision_root.as_bytes());

        if self.operations.is_empty() {
            return Err(ParseError::EmptyScope(Field::Operations));
        }
        if self.operations.len() > MAX_OPERATIONS {
            return Err(ParseError::LengthOutOfBounds(Field::Operations));
        }
        put_u16(&mut out, self.operations.len())?;
        for (i, op) in self.operations.iter().enumerate() {
            if let Some(prev) = i.checked_sub(1).and_then(|p| self.operations.get(p)) {
                check_order(Field::Operations, prev.as_bytes(), op.as_bytes())?;
            }
            put_str(&mut out, Field::Operation, op, 1, MAX_OPERATION_BYTES)?;
        }

        if self.resources.is_empty() {
            return Err(ParseError::EmptyScope(Field::Resources));
        }
        if self.resources.len() > MAX_RESOURCES {
            return Err(ParseError::LengthOutOfBounds(Field::Resources));
        }
        put_u16(&mut out, self.resources.len())?;
        for (i, scope) in self.resources.iter().enumerate() {
            if let Some(prev) = i.checked_sub(1).and_then(|p| self.resources.get(p)) {
                match prev.cmp(scope) {
                    std::cmp::Ordering::Less => {}
                    std::cmp::Ordering::Equal => return Err(ParseError::DuplicateMember(Field::Resources)),
                    std::cmp::Ordering::Greater => return Err(ParseError::UnsortedSet(Field::Resources)),
                }
            }
            validate_path(scope.path()).map_err(ParseError::BadPath)?;
            out.push(scope.kind().to_wire());
            put_str(&mut out, Field::ResourcePath, scope.path(), 1, MAX_PATH_BYTES)?;
        }

        if self.expires_at_ms <= self.not_before_ms {
            return Err(ParseError::WindowInverted);
        }
        out.extend_from_slice(&self.not_before_ms.to_be_bytes());
        out.extend_from_slice(&self.expires_at_ms.to_be_bytes());
        out.push(u8::from(self.one_time));
        put_str(&mut out, Field::PolicyRef, &self.policy_ref, 0, MAX_POLICY_REF_BYTES)?;
        out.extend_from_slice(&self.nonce);
        out.extend_from_slice(key_id);
        Ok(out)
    }
}

fn put_u16(out: &mut Vec<u8>, n: usize) -> Result<(), ParseError> {
    let n = u16::try_from(n).map_err(|_| ParseError::TooLarge)?;
    out.extend_from_slice(&n.to_be_bytes());
    Ok(())
}

fn check_str(field: Field, s: &str, min: usize, max: usize) -> Result<(), ParseError> {
    if s.len() < min || s.len() > max {
        return Err(ParseError::LengthOutOfBounds(field));
    }
    if s.chars().any(is_control) {
        return Err(ParseError::ControlCharacter(field));
    }
    Ok(())
}

fn put_str(out: &mut Vec<u8>, field: Field, s: &str, min: usize, max: usize) -> Result<(), ParseError> {
    check_str(field, s, min, max)?;
    put_u16(out, s.len())?;
    out.extend_from_slice(s.as_bytes());
    Ok(())
}

fn check_order(field: Field, prev: &[u8], next: &[u8]) -> Result<(), ParseError> {
    match prev.cmp(next) {
        std::cmp::Ordering::Less => Ok(()),
        std::cmp::Ordering::Equal => Err(ParseError::DuplicateMember(field)),
        std::cmp::Ordering::Greater => Err(ParseError::UnsortedSet(field)),
    }
}

/// The digest of a signed capability: SHA-256 over [`DIGEST_DOMAIN`] and
/// the whole wire form. Never truncated.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct CapabilityDigest(Digest32);

impl CapabilityDigest {
    /// The digest of `wire`.
    pub fn of_wire(wire: &[u8]) -> Self {
        let mut h = Sha256::new();
        h.update(DIGEST_DOMAIN);
        h.update(wire);
        Self(Digest32::from_bytes(h.finalize().into()))
    }

    /// Parses exactly 64 lowercase hex characters.
    pub fn from_hex(s: &str) -> Option<Self> {
        Digest32::from_hex(s).map(Self)
    }

    /// The 64-character lowercase hex form.
    pub fn to_hex(&self) -> String {
        self.0.to_hex()
    }

    /// The raw bytes.
    pub const fn as_bytes(&self) -> &[u8; 32] {
        self.0.as_bytes()
    }
}

impl fmt::Debug for CapabilityDigest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "CapabilityDigest({})", self.to_hex())
    }
}

impl fmt::Display for CapabilityDigest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_hex())
    }
}

/// A capability as parsed from the wire: the fields, the key id and the
/// signature, plus the exact bytes so the signature can be checked over
/// what was actually received. Parsing proves well-formedness only. It
/// proves nothing about who signed it; see `trust`.
#[derive(Debug, Clone)]
pub struct SignedCapability {
    capability: Capability,
    key_id: [u8; KEY_ID_BYTES],
    signature: [u8; SIGNATURE_BYTES],
    wire: Vec<u8>,
    signed_len: usize,
    digest: CapabilityDigest,
}

impl SignedCapability {
    /// Parses `bytes` strictly. `max_bytes` is the caller's cap; input
    /// longer than it, or than [`MAX_WIRE_BYTES`], is refused before any
    /// byte is read.
    pub fn parse(bytes: &[u8], max_bytes: usize) -> Result<Self, ParseError> {
        if bytes.len() > max_bytes || bytes.len() > MAX_WIRE_BYTES {
            return Err(ParseError::TooLarge);
        }
        let mut r = Reader { bytes, pos: 0 };
        r.domain_tag()?;
        let cap_id = r.string(Field::CapId, 1, MAX_ID_BYTES)?;
        let issuer_id = r.string(Field::IssuerId, 1, MAX_ID_BYTES)?;
        let audience = r.string(Field::Audience, 1, MAX_ID_BYTES)?;
        let subject_digest = Digest32::from_bytes(r.array::<32>()?);
        let decision_root = Digest32::from_bytes(r.array::<32>()?);

        let op_count = usize::from(r.u16()?);
        if op_count == 0 {
            return Err(ParseError::EmptyScope(Field::Operations));
        }
        if op_count > MAX_OPERATIONS {
            return Err(ParseError::LengthOutOfBounds(Field::Operations));
        }
        let mut operations: Vec<String> = Vec::with_capacity(op_count);
        for _ in 0..op_count {
            let op = r.string(Field::Operation, 1, MAX_OPERATION_BYTES)?;
            if let Some(prev) = operations.last() {
                check_order(Field::Operations, prev.as_bytes(), op.as_bytes())?;
            }
            operations.push(op);
        }

        let res_count = usize::from(r.u16()?);
        if res_count == 0 {
            return Err(ParseError::EmptyScope(Field::Resources));
        }
        if res_count > MAX_RESOURCES {
            return Err(ParseError::LengthOutOfBounds(Field::Resources));
        }
        let mut resources: Vec<ResourceScope> = Vec::with_capacity(res_count);
        for _ in 0..res_count {
            let kind = ScopeKind::from_wire(r.u8()?).ok_or(ParseError::BadScopeKind)?;
            let path = r.string(Field::ResourcePath, 1, MAX_PATH_BYTES)?;
            let scope = ResourceScope::new(kind, &path).map_err(ParseError::BadPath)?;
            if let Some(prev) = resources.last() {
                match prev.cmp(&scope) {
                    std::cmp::Ordering::Less => {}
                    std::cmp::Ordering::Equal => return Err(ParseError::DuplicateMember(Field::Resources)),
                    std::cmp::Ordering::Greater => return Err(ParseError::UnsortedSet(Field::Resources)),
                }
            }
            resources.push(scope);
        }

        let not_before_ms = r.u64()?;
        let expires_at_ms = r.u64()?;
        if expires_at_ms <= not_before_ms {
            return Err(ParseError::WindowInverted);
        }
        let one_time = match r.u8()? {
            0 => false,
            1 => true,
            _ => return Err(ParseError::BadBool),
        };
        let policy_ref = r.string(Field::PolicyRef, 0, MAX_POLICY_REF_BYTES)?;
        let nonce = r.array::<NONCE_BYTES>()?;
        let key_id = r.array::<KEY_ID_BYTES>()?;
        let signed_len = r.pos;
        let signature = r.array::<SIGNATURE_BYTES>()?;
        if r.pos != bytes.len() {
            return Err(ParseError::TrailingBytes);
        }
        Ok(Self {
            capability: Capability {
                cap_id,
                issuer_id,
                audience,
                subject_digest,
                decision_root,
                operations,
                resources,
                not_before_ms,
                expires_at_ms,
                one_time,
                policy_ref,
                nonce,
            },
            key_id,
            signature,
            wire: bytes.to_vec(),
            signed_len,
            digest: CapabilityDigest::of_wire(bytes),
        })
    }

    /// The parsed fields.
    pub fn capability(&self) -> &Capability {
        &self.capability
    }

    /// The key id the capability claims it was signed under. A claim,
    /// until the signature verifies under the key the trust set holds for
    /// it.
    pub const fn key_id(&self) -> &[u8; KEY_ID_BYTES] {
        &self.key_id
    }

    /// The signature bytes.
    pub const fn signature(&self) -> &[u8; SIGNATURE_BYTES] {
        &self.signature
    }

    /// The exact bytes the signature must cover.
    pub fn signed_region(&self) -> &[u8] {
        self.wire.get(..self.signed_len).unwrap_or(&[])
    }

    /// The whole wire form as received.
    pub fn wire(&self) -> &[u8] {
        &self.wire
    }

    /// The capability digest.
    pub const fn digest(&self) -> &CapabilityDigest {
        &self.digest
    }
}

struct Reader<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], ParseError> {
        let end = self.pos.checked_add(n).ok_or(ParseError::Truncated)?;
        let s = self.bytes.get(self.pos..end).ok_or(ParseError::Truncated)?;
        self.pos = end;
        Ok(s)
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N], ParseError> {
        let s = self.take(N)?;
        <[u8; N]>::try_from(s).map_err(|_| ParseError::Truncated)
    }

    fn u8(&mut self) -> Result<u8, ParseError> {
        Ok(self.array::<1>()?[0])
    }

    fn u16(&mut self) -> Result<u16, ParseError> {
        Ok(u16::from_be_bytes(self.array::<2>()?))
    }

    fn u64(&mut self) -> Result<u64, ParseError> {
        Ok(u64::from_be_bytes(self.array::<8>()?))
    }

    fn domain_tag(&mut self) -> Result<(), ParseError> {
        if self.bytes.starts_with(DOMAIN_TAG) {
            self.pos = DOMAIN_TAG.len();
            return Ok(());
        }
        if self.bytes.starts_with(DOMAIN_PREFIX) {
            return Err(ParseError::UnsupportedVersion);
        }
        Err(ParseError::BadDomainTag)
    }

    fn string(&mut self, field: Field, min: usize, max: usize) -> Result<String, ParseError> {
        let len = usize::from(self.u16()?);
        if len < min || len > max {
            return Err(ParseError::LengthOutOfBounds(field));
        }
        let raw = self.take(len)?;
        let s = std::str::from_utf8(raw).map_err(|_| ParseError::InvalidUtf8(field))?;
        check_str(field, s, min, max)?;
        Ok(s.to_owned())
    }
}
