//! A durable use store: an append-only, hash-chained log in one file,
//! held under an exclusive lock, synced to disk before a use is reported
//! as recorded.
//!
//! # File format, `stack-authority/use-log/1`
//!
//! ```text
//! header   "stack-authority/use-log/1\n"          26 bytes
//! record   prev_hash        32 bytes  hash of the previous record, or the
//!                                     genesis hash for the first
//!          cap_id_len       u8, 1..=128
//!          cap_id           128 bytes, zero padded
//!          digest           32 bytes  capability digest
//!          one_time         u8, 0 or 1
//!          expires_at_ms    u64
//!          recorded_at_ms   u64
//!          record_hash      32 bytes  SHA-256 over RECORD_DOMAIN and every
//!                                     field above, prev_hash included
//! ```
//!
//! Every record is exactly [`RECORD_BYTES`] long. That is deliberate: a
//! record's extent must not depend on any byte an editor could change,
//! or altering a length field would turn the last complete record into
//! the "torn" prefix of a longer one and erase it on open.
//!
//! Each record is written with one `write_all` followed by `sync_data`,
//! and only then is the use reported as recorded. A crash in between can
//! leave a torn tail: fewer than [`RECORD_BYTES`] trailing bytes whose
//! readable fields are consistent (the right `prev_hash`, a length in
//! bounds). On open a torn tail is tolerated and cut off at the next
//! write; nothing before it is lost, and the use it would have recorded
//! was never reported.
//!
//! Anything else that does not verify, a wrong header, a record whose
//! `prev_hash` is not the chain head, a hash that does not match, a
//! length out of bounds, is corruption. Open fails and the store is
//! unusable: the verifier then denies every request. A store that could
//! have forgotten a use must not answer.
//!
//! # What the chain does and does not prove
//!
//! The chain detects alteration and reordering of records and any
//! truncation that does not land exactly on a record boundary. It does
//! not detect a rollback to an earlier record boundary (dropping the last
//! complete records), because the file carries no external anchor. An
//! operator who needs that keeps the chain head elsewhere; this crate
//! exposes it through [`FileUseStore::head`].
//!
//! The lock is advisory (`flock`): it keeps two cooperating opens apart,
//! in one process or in two. It does not stop a process that ignores it.
//!
//! The log is append-only and never compacted. Expired entries stay in
//! the file; only the in-memory index forgets them. Starting a fresh log
//! is safe only once every entry in the old one has expired.

use std::collections::HashMap;
use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use sha2::{Digest, Sha256};

use crate::capability::{CapabilityDigest, MAX_ID_BYTES};
use crate::digest::Digest32;
use crate::store::{check_and_record, UseError, UseKey, UseStore};

/// The header every log starts with.
pub const LOG_HEADER: &[u8] = b"stack-authority/use-log/1\n";
/// Domain separator for record hashes.
pub const RECORD_DOMAIN: &[u8] = b"stack-authority/use-record/1\n";
/// Largest log the store will read on open, in bytes.
pub const MAX_LOG_BYTES: u64 = 256 * 1024 * 1024;
/// Length of every record.
pub const RECORD_BYTES: usize = PREV_HASH_LEN + BODY_LEN + 32;

const PREV_HASH_LEN: usize = 32;
/// id_len, padded id, digest, one_time, expires_at_ms, recorded_at_ms.
const BODY_LEN: usize = 1 + MAX_ID_BYTES + 32 + 1 + 8 + 8;

fn genesis() -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(RECORD_DOMAIN);
    h.update(b"genesis");
    h.finalize().into()
}

fn record_hash(prev: &[u8; 32], body: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(RECORD_DOMAIN);
    h.update(prev);
    h.update(body);
    h.finalize().into()
}

#[derive(Debug)]
struct Inner {
    file: File,
    index: HashMap<String, (CapabilityDigest, u64)>,
    head: [u8; 32],
    /// Length of the verified prefix of the file. Anything past it is a
    /// torn tail, cut off before the next write.
    valid_len: u64,
    /// Set when a write or sync failed, so the on-disk state is unknown.
    /// Every later call is refused until the store is reopened.
    poisoned: bool,
    records: usize,
}

/// The durable, hash-chained, locked use store.
#[derive(Debug)]
pub struct FileUseStore {
    path: PathBuf,
    capacity: usize,
    inner: Mutex<Inner>,
}

/// What a parsed record tells the opener.
enum Parsed {
    Record {
        cap_id: String,
        digest: CapabilityDigest,
        expires_at_ms: u64,
        hash: [u8; 32],
        len: usize,
    },
    Torn,
    Corrupt,
}

fn id_len_ok(b: u8) -> bool {
    b >= 1 && usize::from(b) <= MAX_ID_BYTES
}

fn parse_record(bytes: &[u8], head: &[u8; 32]) -> Parsed {
    // A torn tail is a proper prefix of a record that would have been
    // well formed: its readable bytes must agree with what a writer
    // would have put there.
    let Some(record) = bytes.get(..RECORD_BYTES) else {
        let prefix_len = bytes.len().min(PREV_HASH_LEN);
        if bytes.get(..prefix_len) != head.get(..prefix_len) {
            return Parsed::Corrupt;
        }
        if bytes.get(PREV_HASH_LEN).is_some_and(|b| !id_len_ok(*b)) {
            return Parsed::Corrupt;
        }
        return Parsed::Torn;
    };
    let body_end = PREV_HASH_LEN + BODY_LEN;
    let (Some(prev), Some(body), Some(stored_hash)) = (
        record.get(..PREV_HASH_LEN),
        record.get(PREV_HASH_LEN..body_end),
        record.get(body_end..RECORD_BYTES),
    ) else {
        return Parsed::Corrupt;
    };
    if prev != head || record_hash(head, body) != stored_hash {
        return Parsed::Corrupt;
    }
    let (Some(id_len), Some(id_field), Some(rest)) = (body.first(), body.get(1..1 + MAX_ID_BYTES), body.get(1 + MAX_ID_BYTES..)) else {
        return Parsed::Corrupt;
    };
    if !id_len_ok(*id_len) {
        return Parsed::Corrupt;
    }
    let (Some(id_raw), Some(padding)) = (id_field.get(..usize::from(*id_len)), id_field.get(usize::from(*id_len)..)) else {
        return Parsed::Corrupt;
    };
    if padding.iter().any(|b| *b != 0) {
        return Parsed::Corrupt;
    }
    let Ok(cap_id) = std::str::from_utf8(id_raw) else {
        return Parsed::Corrupt;
    };
    let (Some(digest_raw), Some(one_time), Some(expires_raw)) = (rest.get(..32), rest.get(32), rest.get(33..41)) else {
        return Parsed::Corrupt;
    };
    if *one_time > 1 {
        return Parsed::Corrupt;
    }
    let (Ok(digest_arr), Ok(expires_arr)) = (<[u8; 32]>::try_from(digest_raw), <[u8; 8]>::try_from(expires_raw)) else {
        return Parsed::Corrupt;
    };
    let Ok(hash) = <[u8; 32]>::try_from(stored_hash) else {
        return Parsed::Corrupt;
    };
    Parsed::Record {
        cap_id: cap_id.to_owned(),
        digest: CapabilityDigest::from_digest32(Digest32::from_bytes(digest_arr)),
        expires_at_ms: u64::from_be_bytes(expires_arr),
        hash,
        len: RECORD_BYTES,
    }
}

impl FileUseStore {
    /// Default cap on live entries in the index.
    pub const DEFAULT_CAPACITY: usize = 1 << 20;

    /// Opens or creates the log at `path`, takes the exclusive lock,
    /// verifies the chain and loads the index. Any failure, including
    /// another holder of the lock, corruption, or a log over
    /// [`MAX_LOG_BYTES`], is [`UseError::Unavailable`].
    pub fn open(path: impl AsRef<Path>, capacity: usize) -> Result<Self, UseError> {
        let path = path.as_ref().to_path_buf();
        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(&path)
            .map_err(|_| UseError::Unavailable)?;
        file.try_lock().map_err(|_| UseError::Unavailable)?;
        let size = file.metadata().map_err(|_| UseError::Unavailable)?.len();
        if size > MAX_LOG_BYTES {
            return Err(UseError::Unavailable);
        }
        let mut bytes = Vec::with_capacity(usize::try_from(size).map_err(|_| UseError::Unavailable)?);
        file.read_to_end(&mut bytes).map_err(|_| UseError::Unavailable)?;

        let mut index = HashMap::new();
        let mut head = genesis();
        let mut records = 0usize;
        let valid_len = if bytes.len() < LOG_HEADER.len() {
            // Empty, or a torn header: start the log.
            if LOG_HEADER.get(..bytes.len()) != Some(bytes.as_slice()) {
                return Err(UseError::Unavailable);
            }
            file.set_len(0).map_err(|_| UseError::Unavailable)?;
            file.seek(SeekFrom::Start(0)).map_err(|_| UseError::Unavailable)?;
            file.write_all(LOG_HEADER).map_err(|_| UseError::Unavailable)?;
            file.sync_data().map_err(|_| UseError::Unavailable)?;
            LOG_HEADER.len()
        } else {
            if bytes.get(..LOG_HEADER.len()) != Some(LOG_HEADER) {
                return Err(UseError::Unavailable);
            }
            let mut pos = LOG_HEADER.len();
            loop {
                let Some(rest) = bytes.get(pos..) else {
                    return Err(UseError::Unavailable);
                };
                if rest.is_empty() {
                    break;
                }
                match parse_record(rest, &head) {
                    Parsed::Record {
                        cap_id,
                        digest,
                        expires_at_ms,
                        hash,
                        len,
                    } => {
                        // The log is the truth: a later record for the
                        // same id with another digest would itself have
                        // been refused at write time, so first wins.
                        index.entry(cap_id).or_insert((digest, expires_at_ms));
                        head = hash;
                        records = records.saturating_add(1);
                        pos = pos.saturating_add(len);
                    }
                    Parsed::Torn => break,
                    Parsed::Corrupt => return Err(UseError::Unavailable),
                }
            }
            pos
        };
        Ok(Self {
            path,
            capacity,
            inner: Mutex::new(Inner {
                file,
                index,
                head,
                valid_len: u64::try_from(valid_len).map_err(|_| UseError::Unavailable)?,
                poisoned: false,
                records,
            }),
        })
    }

    /// The log's path.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// The hash of the last record, or the genesis hash. An operator who
    /// anchors this elsewhere can detect a rollback the file cannot.
    pub fn head(&self) -> Option<[u8; 32]> {
        self.inner.lock().ok().map(|i| i.head)
    }

    /// Number of records in the verified log.
    pub fn records(&self) -> Option<usize> {
        self.inner.lock().ok().map(|i| i.records)
    }

    /// Number of live entries in the index (not yet pruned as expired).
    pub fn len(&self) -> Option<usize> {
        self.inner.lock().ok().map(|i| i.index.len())
    }

    /// Whether the index holds no live entries.
    pub fn is_empty(&self) -> Option<bool> {
        self.len().map(|n| n == 0)
    }

    fn append(inner: &mut Inner, key: &UseKey<'_>, one_time: bool, expires_at_ms: u64, now_ms: u64) -> std::io::Result<()> {
        let mut body = Vec::with_capacity(BODY_LEN);
        let id_len = u8::try_from(key.cap_id.len()).map_err(|_| std::io::Error::other("id length"))?;
        if !id_len_ok(id_len) {
            return Err(std::io::Error::other("id length"));
        }
        body.push(id_len);
        body.extend_from_slice(key.cap_id.as_bytes());
        body.resize(1 + MAX_ID_BYTES, 0);
        body.extend_from_slice(key.digest.as_bytes());
        body.push(u8::from(one_time));
        body.extend_from_slice(&expires_at_ms.to_be_bytes());
        body.extend_from_slice(&now_ms.to_be_bytes());
        if body.len() != BODY_LEN {
            return Err(std::io::Error::other("record length"));
        }
        let hash = record_hash(&inner.head, &body);
        let mut record = Vec::with_capacity(RECORD_BYTES);
        record.extend_from_slice(&inner.head);
        record.extend_from_slice(&body);
        record.extend_from_slice(&hash);
        // Cut off a torn tail before appending after the verified prefix.
        inner.file.set_len(inner.valid_len)?;
        inner.file.seek(SeekFrom::Start(inner.valid_len))?;
        inner.file.write_all(&record)?;
        inner.file.sync_data()?;
        inner.head = hash;
        inner.valid_len = inner
            .valid_len
            .checked_add(u64::try_from(record.len()).map_err(|_| std::io::Error::other("length"))?)
            .ok_or_else(|| std::io::Error::other("length"))?;
        inner.records = inner.records.saturating_add(1);
        Ok(())
    }
}

impl UseStore for FileUseStore {
    fn record_use(&self, key: &UseKey<'_>, one_time: bool, expires_at_ms: u64, now_ms: u64) -> Result<(), UseError> {
        let mut inner = self.inner.lock().map_err(|_| UseError::Unavailable)?;
        if inner.poisoned {
            return Err(UseError::Unavailable);
        }
        let inserted = check_and_record(&mut inner.index, self.capacity, key, one_time, expires_at_ms, now_ms)?;
        if !inserted {
            // A reusable capability already on record: nothing to write.
            return Ok(());
        }
        if Self::append(&mut inner, key, one_time, expires_at_ms, now_ms).is_err() {
            // The on-disk state is unknown. Deny this use and every
            // later one until an operator reopens the store.
            inner.poisoned = true;
            inner.index.remove(key.cap_id);
            return Err(UseError::Unavailable);
        }
        Ok(())
    }

    fn is_durable(&self) -> bool {
        true
    }
}
