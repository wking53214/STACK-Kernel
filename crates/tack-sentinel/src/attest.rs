//! Keys, key fingerprints, and the keyed checks: `authorized_by_sig`
//! signatures (legacy bare digest, `abv2`, `abv3`) and `shuffle_seed`.
//!
//! Reproduces `sentinel_os/governance/authorized_by_attestation.py`:
//! `key_fingerprint`, `KeySet`, `_payload`, `_payload_v3`,
//! `content_prehash`, `_split_envelope`, `verify_authorized_by_signature`,
//! `_seed_payload` and `verify_shuffle_seed`.
//!
//! Every attestation is HMAC-SHA256, so checking one needs the key itself,
//! not only its fingerprint. This crate never contains, generates or
//! defaults a key: the caller supplies every key, and a verifier with no
//! trusted key refuses to run ([`crate::VerifyError::NoTrustedKeyMaterial`]).
//!
//! Digest comparisons use `subtle::ConstantTimeEq`, the counterpart of
//! Python's `hmac.compare_digest`.
//!
//! ## Shape checks before any HMAC
//!
//! Every HMAC this module computes is over attacker-supplied bytes, under
//! every key the verifier holds when the input names no key. To keep that
//! work in proportion to honest input, a candidate that cannot possibly
//! match is refused as `Invalid` before any HMAC is computed:
//!
//! * a digest or seed that is not 64 lowercase hex characters (an HMAC-SHA256
//!   hex digest always is, so Python's `compare_digest` would fail too);
//! * a seed whose `record_kind` is neither absent, null nor a string of at
//!   most [`MAX_RECORD_KIND_BYTES`], or whose `previous_hash` is not a string
//!   of at most 64 bytes. No `sentinel_os` writer produces such a row; Python
//!   would HMAC it and, unless the attacker holds a key, also find it
//!   invalid. This is stricter than Python only for rows a key holder built
//!   by hand.
//!
//! A signature is split into its envelope by borrowing slices of the stored
//! text, never by copying it, so a signature of any length costs one scan.
//! What remains is bounded per export by
//! [`crate::VerifierConfig::max_keyed_bytes`] (see [`keyed_work_bytes`]).

use std::fmt;

use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

use crate::pyjson::{write_entries, CountingSink, Object, Separators, Sink, Value};

/// Domain tag of the `abv2` and legacy payload (`_DOMAIN_TAG`).
pub const DOMAIN_TAG_V1: &[u8] = b"sentinel_os.authorized_by.v1";
/// Domain tag of the `abv3` payload (`_DOMAIN_TAG_V3`).
pub const DOMAIN_TAG_V3: &[u8] = b"sentinel_os.authorized_by.v3";
/// Domain tag of the key fingerprint (`_KEYID_DOMAIN`).
pub const KEYID_DOMAIN: &[u8] = b"sentinel_os.authorized_by.keyid.v1";
/// Domain tag of the shuffle seed (`_SEED_DOMAIN_TAG`).
pub const SEED_DOMAIN_TAG: &[u8] = b"sentinel_os.shuffle_seed.v1";
/// Length, in hex characters, of the fingerprint the Python wire format
/// carries inside `abv2.<fp>.<digest>` and in the head anchor.
pub const WIRE_FINGERPRINT_LEN: usize = 16;

/// Full SHA-256 hex of `domain || 0x00 || key`: the key's identity digest.
/// Logs and `Debug` output use this full value.
pub fn key_id_digest(key: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(KEYID_DOMAIN);
    h.update([0u8]);
    h.update(key);
    hex::encode(h.finalize())
}

/// `authorized_by_attestation.key_fingerprint(key)`.
///
/// The Python wire format defines this identifier as the first 16 hex
/// characters of [`key_id_digest`]. It is a public key identifier that
/// signatures and anchors carry, not an integrity hash, and this crate
/// reproduces it only to match that format. Nothing in this crate truncates
/// a hash for any other purpose.
pub fn key_fingerprint(key: &[u8]) -> String {
    let mut full = key_id_digest(key);
    full.truncate(WIRE_FINGERPRINT_LEN);
    full
}

/// Why a key was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum KeyError {
    /// A zero-length key is not a key (`attestation_key` refuses it too).
    #[error("a zero-length key is not a key")]
    Empty,
    /// A key longer than the configured cap.
    #[error("key is {len} bytes, over the {max} byte cap")]
    TooLong {
        /// Length of the refused key.
        len: usize,
        /// The cap.
        max: usize,
    },
    /// More keys than the configured cap.
    #[error("{count} keys supplied, over the cap of {max}")]
    TooMany {
        /// Number of keys supplied.
        count: usize,
        /// The cap.
        max: usize,
    },
    /// A key file larger than the configured cap.
    #[error("key file is {len} bytes, over the {max} byte cap")]
    FileTooLarge {
        /// Length of the refused file.
        len: usize,
        /// The cap.
        max: usize,
    },
    /// A key file that is not UTF-8 (Python opens it as UTF-8 text).
    #[error("key file is not valid UTF-8")]
    FileNotUtf8,
}

/// Longest key accepted, in bytes. The Python guidance is 32 bytes of
/// CSPRNG output rendered as hex (64 bytes); this cap leaves room for other
/// encodings and nothing more.
pub const MAX_KEY_BYTES: usize = 4096;

/// One attestation key. Its bytes never appear in `Debug` output, logs or
/// errors; only its full identity digest does.
///
/// The bytes are held in an ordinary `Vec<u8>`. They are not locked in
/// memory or wiped on drop, because doing that reliably needs code this
/// crate does not carry; a caller that needs it holds keys elsewhere.
#[derive(Clone, PartialEq, Eq)]
pub struct SecretKey {
    bytes: Vec<u8>,
    fingerprint: String,
}

impl SecretKey {
    /// Wrap key bytes. Refuses an empty key and a key over [`MAX_KEY_BYTES`].
    pub fn new(bytes: Vec<u8>) -> Result<Self, KeyError> {
        if bytes.is_empty() {
            return Err(KeyError::Empty);
        }
        if bytes.len() > MAX_KEY_BYTES {
            return Err(KeyError::TooLong {
                len: bytes.len(),
                max: MAX_KEY_BYTES,
            });
        }
        let fingerprint = key_fingerprint(&bytes);
        Ok(SecretKey { bytes, fingerprint })
    }

    /// The Python wire fingerprint (see [`key_fingerprint`]).
    pub fn fingerprint(&self) -> &str {
        &self.fingerprint
    }

    /// The full identity digest (see [`key_id_digest`]).
    pub fn id_digest(&self) -> String {
        key_id_digest(&self.bytes)
    }

    fn bytes(&self) -> &[u8] {
        &self.bytes
    }
}

impl fmt::Debug for SecretKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SecretKey")
            .field("id_sha256", &self.id_digest())
            .field("len", &self.bytes.len())
            .finish()
    }
}

/// Python's `str.strip()` whitespace: Unicode `White_Space` plus the four
/// ASCII separators U+001C to U+001F, which Python also strips.
fn is_py_space(c: char) -> bool {
    c.is_whitespace() || ('\u{1c}'..='\u{1f}').contains(&c)
}

/// Keys from a key file, one per line, blank lines ignored, each line
/// stripped of surrounding whitespace (`verify_receipts.trusted_keys`).
/// Lines break on `\n`, `\r` and `\r\n`, as Python's text mode reads them.
pub fn parse_key_file(bytes: &[u8], max_file_bytes: usize, max_keys: usize) -> Result<Vec<SecretKey>, KeyError> {
    if bytes.len() > max_file_bytes {
        return Err(KeyError::FileTooLarge {
            len: bytes.len(),
            max: max_file_bytes,
        });
    }
    let text = std::str::from_utf8(bytes).map_err(|_| KeyError::FileNotUtf8)?;
    let mut keys = Vec::new();
    for line in text.split(['\n', '\r']) {
        let line = line.trim_matches(is_py_space);
        if line.is_empty() {
            continue;
        }
        if keys.len() >= max_keys {
            return Err(KeyError::TooMany {
                count: keys.len() + 1,
                max: max_keys,
            });
        }
        keys.push(SecretKey::new(line.as_bytes().to_vec())?);
    }
    Ok(keys)
}

/// `authorized_by_attestation.KeySet`: trusted keys (a match is OK) and
/// retired keys (a match is RETIRED_KEY). Duplicates collapse; a key in both
/// lists counts only as trusted.
#[derive(Clone, Default, PartialEq, Eq)]
pub struct KeySet {
    trusted: Vec<SecretKey>,
    retired: Vec<SecretKey>,
}

impl fmt::Debug for KeySet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("KeySet")
            .field("trusted", &self.trusted)
            .field("retired", &self.retired)
            .finish()
    }
}

impl KeySet {
    /// `KeySet(current, previous, retired)`.
    pub fn new(current: Option<SecretKey>, previous: Vec<SecretKey>, retired: Vec<SecretKey>) -> Self {
        let mut trusted: Vec<SecretKey> = Vec::new();
        for k in current.into_iter().chain(previous) {
            if !trusted.contains(&k) {
                trusted.push(k);
            }
        }
        let mut ret: Vec<SecretKey> = Vec::new();
        for k in retired {
            if !trusted.contains(&k) && !ret.contains(&k) {
                ret.push(k);
            }
        }
        KeySet { trusted, retired: ret }
    }

    /// `verify_receipts.trusted_keys`: every held key whose fingerprint the
    /// auditor lists, all as trusted, and no other key.
    pub fn from_trusted_fingerprints(held: Vec<SecretKey>, fingerprints: &[&str]) -> Self {
        let wanted: Vec<&str> = fingerprints
            .iter()
            .map(|f| f.trim_matches(is_py_space))
            .filter(|f| !f.is_empty())
            .collect();
        let chosen = held
            .into_iter()
            .filter(|k| wanted.contains(&k.fingerprint()))
            .collect();
        KeySet::new(None, chosen, Vec::new())
    }

    /// Whether no key at all is held.
    pub fn is_empty(&self) -> bool {
        self.trusted.is_empty() && self.retired.is_empty()
    }

    /// Number of trusted keys.
    pub fn trusted_len(&self) -> usize {
        self.trusted.len()
    }

    /// Number of retired keys.
    pub fn retired_len(&self) -> usize {
        self.retired.len()
    }

    /// `KeySet.trusted_key(fp)`. Python builds a dict, so a later key with
    /// the same fingerprint wins.
    pub(crate) fn trusted_key(&self, fp: &str) -> Option<&SecretKey> {
        self.trusted.iter().rev().find(|k| k.fingerprint() == fp)
    }

    /// `KeySet.retired_key(fp)`.
    pub(crate) fn retired_key(&self, fp: &str) -> Option<&SecretKey> {
        self.retired.iter().rev().find(|k| k.fingerprint() == fp)
    }

    pub(crate) fn trusted(&self) -> &[SecretKey] {
        &self.trusted
    }

    pub(crate) fn retired(&self) -> &[SecretKey] {
        &self.retired
    }
}

/// The status vocabulary of `verify_authorized_by_signature`,
/// `verify_shuffle_seed` and `verify_head_anchor`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AttestationStatus {
    /// Valid under a trusted key.
    Ok,
    /// Nothing to check (no claim, or no seed).
    Absent,
    /// A claim with no signature. Not a finding on its own.
    Unattested,
    /// Something to check, but no key is held.
    Unverifiable,
    /// The digest does not match.
    Invalid,
    /// Valid, but only under a retired key.
    RetiredKey,
    /// Names a key fingerprint this verifier does not hold.
    UnknownKey,
}

/// HMAC-SHA256 of `msg` under `key`, as lowercase hex.
pub(crate) fn hmac_hex(key: &SecretKey, msg: &[u8]) -> Option<String> {
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(key.bytes()).ok()?;
    mac.update(msg);
    Some(hex::encode(mac.finalize().into_bytes()))
}

/// Constant-time equality of an expected hex digest and a candidate string.
pub(crate) fn digest_matches(key: &SecretKey, msg: &[u8], candidate: &str) -> bool {
    match hmac_hex(key, msg) {
        Some(expected) => bool::from(expected.as_bytes().ct_eq(candidate.as_bytes())),
        None => false,
    }
}

struct MacSink(Hmac<Sha256>);

impl Sink for MacSink {
    fn put(&mut self, s: &str) {
        self.0.update(s.as_bytes());
    }
}

/// [`digest_matches`] over a payload written straight into the HMAC.
fn payload_matches(key: &SecretKey, payload: &Payload<'_>, candidate: &str) -> bool {
    let Ok(mac) = <Hmac<Sha256> as Mac>::new_from_slice(key.bytes()) else {
        return false;
    };
    let mut sink = MacSink(mac);
    payload.write(&mut sink);
    let expected = hex::encode(sink.0.finalize().into_bytes());
    bool::from(expected.as_bytes().ct_eq(candidate.as_bytes()))
}

const NULL: Value = Value::Null;

fn get<'a>(row: &'a Object, col: &str) -> &'a Value {
    row.get(col).unwrap_or(&NULL)
}

/// What a keyed attestation covers: a domain tag, a zero byte, then the
/// compact sorted JSON of a few borrowed values.
struct Payload<'a> {
    domain: &'static [u8],
    /// `(key, value)` pairs in sorted key order.
    body: Vec<(&'static str, &'a Value)>,
}

impl Payload<'_> {
    fn write<S: Sink + ?Sized>(&self, out: &mut S) {
        // Every domain tag is ASCII.
        out.put(std::str::from_utf8(self.domain).unwrap_or_default());
        out.put("\0");
        write_entries(out, self.body.iter().map(|(k, v)| (*k, *v)), Separators::Compact);
    }

    fn len(&self) -> usize {
        let mut c = CountingSink::default();
        self.write(&mut c);
        c.0
    }

    fn to_vec(&self) -> Vec<u8> {
        let mut out = String::new();
        self.write(&mut out);
        out.into_bytes()
    }
}

fn v2<'a>(authorized_by: &'a Value, previous_hash: &'a Value, record_kind: &'a Value) -> Payload<'a> {
    Payload {
        domain: DOMAIN_TAG_V1,
        body: vec![
            ("authorized_by", authorized_by),
            ("previous_hash", previous_hash),
            ("record_kind", record_kind),
        ],
    }
}

fn v3<'a>(authorized_by: &'a Value, previous_hash: &'a Value, record_kind: &'a Value, prehash: &'a Value) -> Payload<'a> {
    Payload {
        domain: DOMAIN_TAG_V3,
        body: vec![
            ("authorized_by", authorized_by),
            ("content_prehash", prehash),
            ("previous_hash", previous_hash),
            ("record_kind", record_kind),
        ],
    }
}

fn seed<'a>(previous_hash: &'a Value, record_kind: &'a Value) -> Payload<'a> {
    Payload {
        domain: SEED_DOMAIN_TAG,
        body: vec![("previous_hash", previous_hash), ("record_kind", record_kind)],
    }
}

/// `_payload`: what an `abv2` or legacy signature covers.
pub fn payload_v2(authorized_by: &Value, previous_hash: &Value, record_kind: &Value) -> Vec<u8> {
    v2(authorized_by, previous_hash, record_kind).to_vec()
}

/// `_payload_v3`: what an `abv3` signature covers.
pub fn payload_v3(authorized_by: &Value, previous_hash: &Value, record_kind: &Value, prehash: &str) -> Vec<u8> {
    let prehash = Value::Str(prehash.to_owned());
    v3(authorized_by, previous_hash, record_kind, &prehash).to_vec()
}

/// `_seed_payload`: what a shuffle seed is derived from.
pub fn seed_payload(previous_hash: &Value, record_kind: &Value) -> Vec<u8> {
    seed(previous_hash, record_kind).to_vec()
}

/// Longest `record_kind` a seed is checked for, in bytes. The longest kind
/// `sentinel_os` writes is 28 bytes.
pub const MAX_RECORD_KIND_BYTES: usize = 64;

fn is_hex64(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

/// Which envelope a signature used.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SigForm {
    /// A bare 64-hex digest with no key id.
    Legacy,
    /// `abv2.<fp>.<digest>`: covers the name and chain position.
    Abv2,
    /// `abv3.<fp>.<digest>`: also covers the row's content pre-hash.
    Abv3,
}

/// `_split_envelope(sig)`: `(form, keyfp, digest)`, all borrowed from
/// `sig`. Python splits on every `.` and takes the envelope only when there
/// are exactly three parts and the first is a known tag; this finds the
/// same answer without building a list of parts.
fn split_envelope(sig: &str) -> (SigForm, Option<&str>, &str) {
    let tagged = sig
        .strip_prefix("abv2.")
        .map(|rest| (SigForm::Abv2, rest))
        .or_else(|| sig.strip_prefix("abv3.").map(|rest| (SigForm::Abv3, rest)));
    if let Some((form, rest)) = tagged {
        if let Some((fp, digest)) = rest.split_once('.') {
            if !digest.contains('.') {
                return (form, Some(fp), digest);
            }
        }
    }
    (SigForm::Legacy, None, sig)
}

/// Result of a signature check: the status and, for a signature that names
/// its key, that fingerprint as a report may show it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignatureCheck {
    /// Python's status.
    pub status: AttestationStatus,
    /// The envelope form, when a signature was examined.
    pub form: Option<SigForm>,
    /// The fingerprint the envelope names, as [`crate::verify::describe`]
    /// shows a stored value: the text itself when it is 16 hex characters,
    /// otherwise its length and full SHA-256. Never the raw text otherwise.
    pub named_fingerprint: Option<String>,
}

/// `verify_authorized_by_signature(row, keys, content_prehash)`.
pub fn verify_signature(row: &Object, keys: &KeySet, content_prehash: &str) -> SignatureCheck {
    let authorized_by = get(row, "authorized_by");
    let sig = get(row, crate::canonical::SIGNATURE_FIELD);
    let done = |status| SignatureCheck {
        status,
        form: None,
        named_fingerprint: None,
    };
    if !authorized_by.is_truthy() {
        return done(AttestationStatus::Absent);
    }
    if !sig.is_truthy() {
        return done(AttestationStatus::Unattested);
    }
    if keys.is_empty() {
        return done(AttestationStatus::Unverifiable);
    }
    // Python works on str(sig). Only a str or an int can render as a hex
    // digest; for any other type no comparison can succeed, and the result
    // is the one Python reaches after trying every key: INVALID.
    let Some(sig_text) = sig.python_str_if_hexable() else {
        return SignatureCheck {
            status: AttestationStatus::Invalid,
            form: Some(SigForm::Legacy),
            named_fingerprint: None,
        };
    };
    let (form, keyfp, digest) = split_envelope(&sig_text);
    let result = |status| SignatureCheck {
        status,
        form: Some(form),
        named_fingerprint: keyfp.map(crate::verify::describe_str),
    };
    let previous_hash = get(row, "previous_hash");
    let record_kind = get(row, "record_kind");
    let prehash = Value::Str(content_prehash.to_owned());
    let payload = match form {
        SigForm::Abv3 => v3(authorized_by, previous_hash, record_kind, &prehash),
        _ => v2(authorized_by, previous_hash, record_kind),
    };
    // No HMAC hex digest can equal a candidate that is not 64 lowercase hex,
    // so such a digest is INVALID under every key without computing one.
    let shaped = is_hex64(digest);
    if let Some(fp) = keyfp {
        if let Some(k) = keys.trusted_key(fp) {
            return result(if shaped && payload_matches(k, &payload, digest) {
                AttestationStatus::Ok
            } else {
                AttestationStatus::Invalid
            });
        }
        if let Some(k) = keys.retired_key(fp) {
            return result(if shaped && payload_matches(k, &payload, digest) {
                AttestationStatus::RetiredKey
            } else {
                AttestationStatus::Invalid
            });
        }
        return result(AttestationStatus::UnknownKey);
    }
    if !shaped {
        return result(AttestationStatus::Invalid);
    }
    if keys.trusted().iter().any(|k| payload_matches(k, &payload, digest)) {
        return result(AttestationStatus::Ok);
    }
    if keys.retired().iter().any(|k| payload_matches(k, &payload, digest)) {
        return result(AttestationStatus::RetiredKey);
    }
    result(AttestationStatus::Invalid)
}

/// Whether a seed's payload has the shape a `sentinel_os` writer gives it.
fn seed_payload_shaped(previous_hash: &Value, record_kind: &Value) -> bool {
    let kind_ok = match record_kind {
        Value::Null => true,
        Value::Str(k) => k.len() <= MAX_RECORD_KIND_BYTES,
        _ => false,
    };
    let prev_ok = matches!(previous_hash, Value::Str(p) if p.len() <= 64);
    kind_ok && prev_ok
}

/// `verify_shuffle_seed(row["shuffle_seed"], row["previous_hash"], row["record_kind"], keys)`.
pub fn verify_seed(row: &Object, keys: &KeySet) -> AttestationStatus {
    let seed_value = get(row, "shuffle_seed");
    if !seed_value.is_truthy() {
        return AttestationStatus::Absent;
    }
    if keys.is_empty() {
        return AttestationStatus::Unverifiable;
    }
    let Some(seed_text) = seed_value.python_str_if_hexable() else {
        return AttestationStatus::Invalid;
    };
    let (previous_hash, record_kind) = (get(row, "previous_hash"), get(row, "record_kind"));
    if !is_hex64(&seed_text) || !seed_payload_shaped(previous_hash, record_kind) {
        return AttestationStatus::Invalid;
    }
    let payload = seed(previous_hash, record_kind);
    if keys.trusted().iter().any(|k| payload_matches(k, &payload, &seed_text)) {
        return AttestationStatus::Ok;
    }
    if keys.retired().iter().any(|k| payload_matches(k, &payload, &seed_text)) {
        return AttestationStatus::RetiredKey;
    }
    AttestationStatus::Invalid
}

/// An upper bound on the bytes [`verify_seed`] and [`verify_signature`]
/// would feed to HMAC-SHA256 for this row: each payload's length times the
/// number of keys it would be tried under. Counting writes nothing and
/// allocates nothing. The verifier sums this over an export and refuses one
/// that needs more than `VerifierConfig::max_keyed_bytes`.
pub fn keyed_work_bytes(row: &Object, keys: &KeySet) -> usize {
    if keys.is_empty() {
        return 0;
    }
    let held = keys.trusted().len() + keys.retired().len();
    let previous_hash = get(row, "previous_hash");
    let record_kind = get(row, "record_kind");
    let mut total = 0usize;

    let seed_value = get(row, "shuffle_seed");
    if seed_value.is_truthy() {
        let shaped = seed_value.python_str_if_hexable().is_some_and(|t| is_hex64(&t));
        if shaped && seed_payload_shaped(previous_hash, record_kind) {
            total = total.saturating_add(held.saturating_mul(seed(previous_hash, record_kind).len()));
        }
    }

    let authorized_by = get(row, "authorized_by");
    let sig = get(row, crate::canonical::SIGNATURE_FIELD);
    if authorized_by.is_truthy() && sig.is_truthy() {
        if let Some(text) = sig.python_str_if_hexable() {
            let (form, keyfp, digest) = split_envelope(&text);
            let tries = match keyfp {
                _ if !is_hex64(digest) => 0,
                Some(fp) if keys.trusted_key(fp).is_some() || keys.retired_key(fp).is_some() => 1,
                Some(_) => 0,
                None => held,
            };
            let prehash = Value::Str("0".repeat(64));
            let len = match form {
                SigForm::Abv3 => v3(authorized_by, previous_hash, record_kind, &prehash).len(),
                _ => v2(authorized_by, previous_hash, record_kind).len(),
            };
            total = total.saturating_add(tries.saturating_mul(len));
        }
    }
    total
}

#[cfg(test)]
mod tests {
    use super::*;

    // TEST FIXTURE ONLY: the key sentinel_os's own test suite labels as
    // "fixture-attestation-key-not-a-real-secret". Not a real key.
    const FIXTURE_KEY: &[u8] = b"fixture-attestation-key-not-a-real-secret";

    #[test]
    fn fingerprint_matches_the_fixture_signature() {
        // The fixture's abv2 signature names this fingerprint.
        assert_eq!(key_fingerprint(FIXTURE_KEY), "acdf8e81f938b3ca");
        assert_eq!(key_id_digest(FIXTURE_KEY).len(), 64);
    }

    #[test]
    fn debug_never_prints_key_bytes() {
        let k = SecretKey::new(FIXTURE_KEY.to_vec()).unwrap();
        let shown = format!("{k:?}");
        assert!(!shown.contains("fixture-attestation"));
        assert!(shown.contains(&key_id_digest(FIXTURE_KEY)));
    }

    #[test]
    fn key_file_lines_strip_like_python() {
        let keys = parse_key_file(b"  a \r\n\n\x1cb\x1f\rc", 1024, 8).unwrap();
        let fps: Vec<String> = keys.iter().map(|k| k.fingerprint().to_owned()).collect();
        assert_eq!(fps, vec![key_fingerprint(b"a"), key_fingerprint(b"b"), key_fingerprint(b"c")]);
        assert!(matches!(parse_key_file(b"a\nb\nc", 1024, 2), Err(KeyError::TooMany { .. })));
        assert!(matches!(parse_key_file(b"abc", 2, 8), Err(KeyError::FileTooLarge { .. })));
    }

    #[test]
    fn keyset_dedupes_and_prefers_trusted() {
        let a = SecretKey::new(b"a".to_vec()).unwrap();
        let b = SecretKey::new(b"b".to_vec()).unwrap();
        let ks = KeySet::new(Some(a.clone()), vec![a.clone(), b.clone()], vec![a, b.clone()]);
        assert_eq!(ks.trusted_len(), 2);
        assert_eq!(ks.retired_len(), 0);
        let only_b = KeySet::from_trusted_fingerprints(vec![b.clone()], &[" nope ", b.fingerprint()]);
        assert_eq!(only_b.trusted_len(), 1);
    }
}
