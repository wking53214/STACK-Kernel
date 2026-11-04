//! Durable replay state: what a receiver must remember across a restart so
//! that nothing it accepted before can be accepted again.
//!
//! A [`ReplayStore`] holds, per sender, the last accepted sequence; every
//! accepted nonce with the instant it may be forgotten; the high-water
//! mark (the highest `issued_at_unix_ms` ever accepted); and quarantine
//! marks. The Trident calls [`ReplayStore::load`] once at start and
//! [`ReplayStore::commit`] for every acceptance, inside the same critical
//! section as the in-memory commit and BEFORE it. A commit that fails
//! refuses the envelope (`StateUnavailable`, RETRY) and leaves the
//! in-memory state untouched, so a later retry is accepted exactly once
//! when storage recovers.
//!
//! Two stores are provided. [`MemoryStore`] keeps nothing: it is the
//! behaviour the crate had before durable state existed and is for
//! development only (`is_durable() == false`). [`FileStore`] is an
//! append-only, hash-chained, fsynced log under an exclusive advisory lock.
//!
//! ## Supported topology
//!
//! ONE active verifier per store. The file lock refuses a second process
//! or a second `Trident` on the same file at open time. Multi-host
//! replication is not supported: two hosts cannot share a `FileStore`, and
//! this crate does not simulate it. A deployment that needs more than one
//! verifier gives each its own store and routes each sender to exactly one
//! of them (sender affinity).
//!
//! ## What the file store proves and what it cannot
//!
//! * A flipped byte, a swapped or reordered record, a record inserted in
//!   the middle, or a committed region shorter than the header says, is
//!   detected at load and refuses to start.
//! * A crash between writing a record and acknowledging it leaves bytes
//!   past the committed length. They were never acknowledged, so they are
//!   discarded, and the next append overwrites them.
//! * An attacker with write access to the file can rewrite the whole log
//!   consistently, or replace it with an older consistent copy. Neither is
//!   detectable from the file alone. The external mark
//!   (`TridentConfig::restored_high_water_ms`, kept somewhere the attacker
//!   cannot reach) catches an older copy: a durable store whose high-water
//!   mark is behind the external mark refuses to start.
//! * The hash chain is SHA-256 with no key. It proves consistency, not
//!   authorship.

use std::collections::HashMap;
use std::fmt;
use std::fs::{File, OpenOptions, TryLockError};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};

use crate::envelope::Nonce;
use crate::keys::Fingerprint;

/// One acceptance, as the Trident hands it to the store.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AcceptRecord {
    /// Authenticated sender.
    pub sender: Fingerprint,
    /// Accepted sequence (the sender's new high-water mark).
    pub sequence: u64,
    /// Accepted nonce.
    pub nonce: Nonce,
    /// The envelope's `issued_at_unix_ms`.
    pub issued_at_unix_ms: u64,
    /// Receiver clock at acceptance.
    pub accepted_at_unix_ms: u64,
    /// When the nonce may be forgotten (`accepted_at + replay retention`).
    pub nonce_expires_at_unix_ms: u64,
}

/// A sender's restored freshness state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RestoredSender {
    /// The sender.
    pub sender: Fingerprint,
    /// Last accepted sequence.
    pub last_sequence: u64,
    /// Receiver clock at the last acceptance.
    pub last_accepted_at_unix_ms: u64,
}

/// A restored (sender, nonce) pair.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RestoredNonce {
    /// The sender.
    pub sender: Fingerprint,
    /// The nonce.
    pub nonce: Nonce,
    /// When it may be forgotten.
    pub expires_at_unix_ms: u64,
}

/// Everything a store gives back at start.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RestoredState {
    /// One entry per sender ever accepted and still recorded.
    pub senders: Vec<RestoredSender>,
    /// Every recorded nonce, expired or not. The Trident keeps only those
    /// still inside their retention window.
    pub nonces: Vec<RestoredNonce>,
    /// Highest `issued_at_unix_ms` ever accepted. 0 when nothing was.
    pub high_water_ms: u64,
    /// Senders quarantined when the previous process stopped, with the
    /// receiver clock at which each quarantine began.
    pub quarantined: Vec<(Fingerprint, u64)>,
}

/// Why a store operation failed. Every variant is a reason to refuse: the
/// Trident never continues on a weaker posture because of one.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum StoreError {
    /// Another verifier holds the exclusive lock on this file.
    #[error("replay store {path} is locked by another verifier; one active verifier per store")]
    Locked {
        /// The store file.
        path: PathBuf,
    },
    /// An I/O operation failed. `kind` is the OS error kind.
    #[error("replay store {op} failed: {kind:?}: {message}")]
    Io {
        /// What was being done.
        op: &'static str,
        /// The OS error kind.
        kind: io::ErrorKind,
        /// The OS error text.
        message: String,
    },
    /// The committed region does not verify: the file is corrupt, or was
    /// edited, reordered or spliced.
    #[error("replay store is corrupt at byte {offset}: {detail}")]
    Corrupt {
        /// Byte offset of the first thing that did not verify.
        offset: u64,
        /// What did not verify.
        detail: &'static str,
    },
    /// The file is shorter than its acknowledged length: records that were
    /// acknowledged are gone.
    #[error("replay store was truncated: header commits {committed_len} bytes, file holds {actual_len}")]
    Truncated {
        /// Length the header acknowledges.
        committed_len: u64,
        /// Length on disk.
        actual_len: u64,
    },
    /// `commit` was called before `load`. The store refuses to append to
    /// a log it has not verified.
    #[error("replay store was not loaded before use")]
    NotLoaded,
}

impl StoreError {
    fn io(op: &'static str, e: &io::Error) -> Self {
        Self::Io {
            op,
            kind: e.kind(),
            message: e.to_string(),
        }
    }
}

/// Durable replay state. See the module docs for the contract.
///
/// Every method is called by the Trident while it holds its state lock,
/// so an implementation needs no locking of its own against the Trident.
/// It must still refuse a second process (see [`FileStore`]).
pub trait ReplayStore: Send + Sync + fmt::Debug {
    /// Reads and verifies the whole store. Called once, before any commit.
    /// An error here is fatal at start: the Trident does not build.
    fn load(&mut self) -> Result<RestoredState, StoreError>;

    /// Makes one acceptance durable. Returns only after the record would
    /// survive a crash, or with an error, in which case nothing may have
    /// been kept and the Trident refuses the envelope.
    fn commit(&mut self, record: &AcceptRecord) -> Result<(), StoreError>;

    /// Whether what `commit` returned `Ok` for survives a restart of the
    /// process. A `false` store is for development only.
    fn is_durable(&self) -> bool;

    /// Records that `sender` was quarantined at `since_unix_ms`. Best
    /// effort: the in-memory quarantine stands whether or not this
    /// succeeds. The default keeps nothing.
    fn record_quarantine(&mut self, sender: &Fingerprint, since_unix_ms: u64) -> Result<(), StoreError> {
        let _ = (sender, since_unix_ms);
        Ok(())
    }

    /// Records that an operator released `sender`. If this fails the
    /// quarantine comes back on restart, which is the restrictive outcome.
    /// The default keeps nothing.
    fn record_release(&mut self, sender: &Fingerprint) -> Result<(), StoreError> {
        let _ = sender;
        Ok(())
    }
}

/// A store that keeps nothing. Restart safety then rests on the clock and
/// on `TridentConfig::restored_high_water_ms`, exactly as before durable
/// state existed. Development only: `is_durable()` is `false`, and the
/// Production profile refuses it.
#[derive(Debug, Default)]
pub struct MemoryStore {
    loaded: bool,
}

impl MemoryStore {
    /// A store that keeps nothing.
    pub fn new() -> Self {
        Self::default()
    }
}

impl ReplayStore for MemoryStore {
    fn load(&mut self) -> Result<RestoredState, StoreError> {
        self.loaded = true;
        Ok(RestoredState::default())
    }

    fn commit(&mut self, _record: &AcceptRecord) -> Result<(), StoreError> {
        if self.loaded {
            Ok(())
        } else {
            Err(StoreError::NotLoaded)
        }
    }

    fn is_durable(&self) -> bool {
        false
    }
}

// ---------------------------------------------------------------------------
// File store
// ---------------------------------------------------------------------------

/// First 32 bytes of the file. The format name, newline, zero padding.
const MAGIC: &[u8; 32] = b"stack-trident/replay-log/v1\n\0\0\0\0";
const GENESIS_DOMAIN: &[u8] = b"stack-trident/replay-log/genesis/v1\n";
const RECORD_DOMAIN: &[u8] = b"stack-trident/replay-log/record/v1\n";
const SLOT_DOMAIN: &[u8] = b"stack-trident/replay-log/slot/v1\n";

/// Bytes of the header: the magic and two header slots.
pub const HEADER_LEN: u64 = 32 + 2 * SLOT_LEN;
/// Bytes of one header slot: generation, committed length, chain head and
/// the slot's own SHA-256.
const SLOT_LEN: u64 = 8 + 8 + 32 + 32;
const SLOT_A: u64 = 32;
const SLOT_B: u64 = 32 + SLOT_LEN;
/// Longest record body the reader accepts. Anything larger is corruption.
const MAX_BODY_LEN: usize = 256;
/// Bytes a record adds beyond its body: the length prefix, the previous
/// chain hash and this record's hash.
const RECORD_OVERHEAD: usize = 4 + 32 + 32;
/// Longest record on disk. One crash can leave at most this many
/// unacknowledged bytes past the committed length.
const MAX_RECORD_LEN: u64 = (RECORD_OVERHEAD + MAX_BODY_LEN) as u64;
/// Bytes of an acceptance record on disk, for tests that need to find
/// record boundaries.
pub const ACCEPT_RECORD_LEN: usize = RECORD_OVERHEAD + 1 + 32 + 8 + 16 + 8 + 8 + 8;

const TAG_ACCEPT: u8 = 1;
const TAG_QUARANTINE: u8 = 2;
const TAG_RELEASE: u8 = 3;
const TAG_SENDER: u8 = 4;
const TAG_HIGH_WATER: u8 = 5;

/// Tunables of a [`FileStore`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FileStoreOptions {
    /// Compact (rewrite without expired nonces) once the committed log is
    /// this long. Default 64 MiB. Compaction keeps every sender's
    /// sequence, the high-water mark, every quarantine and every nonce
    /// still inside its retention window.
    pub compact_after_bytes: u64,
}

impl Default for FileStoreOptions {
    fn default() -> Self {
        Self {
            compact_after_bytes: 64 * 1024 * 1024,
        }
    }
}

#[derive(Debug, Clone, Copy)]
struct Slot {
    generation: u64,
    committed_len: u64,
    head: [u8; 32],
}

impl Slot {
    fn hash(&self) -> [u8; 32] {
        let mut h = Sha256::new();
        h.update(SLOT_DOMAIN);
        h.update(self.generation.to_be_bytes());
        h.update(self.committed_len.to_be_bytes());
        h.update(self.head);
        h.finalize().into()
    }

    fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(SLOT_LEN as usize);
        out.extend_from_slice(&self.generation.to_be_bytes());
        out.extend_from_slice(&self.committed_len.to_be_bytes());
        out.extend_from_slice(&self.head);
        out.extend_from_slice(&self.hash());
        out
    }

    fn decode(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != SLOT_LEN as usize {
            return None;
        }
        let generation = u64::from_be_bytes(bytes.get(0..8)?.try_into().ok()?);
        let committed_len = u64::from_be_bytes(bytes.get(8..16)?.try_into().ok()?);
        let head: [u8; 32] = bytes.get(16..48)?.try_into().ok()?;
        let stored: [u8; 32] = bytes.get(48..80)?.try_into().ok()?;
        let slot = Self {
            generation,
            committed_len,
            head,
        };
        if slot.hash() == stored && committed_len >= HEADER_LEN {
            Some(slot)
        } else {
            None
        }
    }

    fn state(bytes: Option<&[u8]>) -> SlotState {
        match bytes {
            Some(b) if b.iter().all(|x| *x == 0) => SlotState::Empty,
            Some(b) => Self::decode(b).map_or(SlotState::Invalid, SlotState::Valid),
            None => SlotState::Invalid,
        }
    }
}

/// What a header slot holds. `Empty` (all zero) is legitimate only in the
/// genesis shape: the other slot valid at generation 0. Anywhere else an
/// empty slot is as suspect as an unreadable one.
#[derive(Debug, Clone, Copy)]
enum SlotState {
    Valid(Slot),
    Empty,
    Invalid,
}

fn genesis_head() -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(GENESIS_DOMAIN);
    h.update(MAGIC);
    h.finalize().into()
}

fn record_hash(body: &[u8], prev: &[u8; 32]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(RECORD_DOMAIN);
    h.update(u32::try_from(body.len()).unwrap_or(u32::MAX).to_be_bytes());
    h.update(body);
    h.update(prev);
    h.finalize().into()
}

/// One record's bytes: length, body, previous hash, this hash. Returns the
/// bytes and the new chain head.
fn encode_record(body: &[u8], prev: &[u8; 32]) -> (Vec<u8>, [u8; 32]) {
    let hash = record_hash(body, prev);
    let mut out = Vec::with_capacity(body.len() + RECORD_OVERHEAD);
    out.extend_from_slice(&u32::try_from(body.len()).unwrap_or(u32::MAX).to_be_bytes());
    out.extend_from_slice(body);
    out.extend_from_slice(prev);
    out.extend_from_slice(&hash);
    (out, hash)
}

enum Record {
    Accept(AcceptRecord),
    Quarantine(Fingerprint, u64),
    Release(Fingerprint),
    Sender(RestoredSender),
    HighWater(u64),
}

impl Record {
    fn encode(&self) -> Vec<u8> {
        let mut b = Vec::with_capacity(96);
        match self {
            Self::Accept(r) => {
                b.push(TAG_ACCEPT);
                b.extend_from_slice(r.sender.as_bytes());
                b.extend_from_slice(&r.sequence.to_be_bytes());
                b.extend_from_slice(r.nonce.as_bytes());
                b.extend_from_slice(&r.issued_at_unix_ms.to_be_bytes());
                b.extend_from_slice(&r.accepted_at_unix_ms.to_be_bytes());
                b.extend_from_slice(&r.nonce_expires_at_unix_ms.to_be_bytes());
            }
            Self::Quarantine(fp, since) => {
                b.push(TAG_QUARANTINE);
                b.extend_from_slice(fp.as_bytes());
                b.extend_from_slice(&since.to_be_bytes());
            }
            Self::Release(fp) => {
                b.push(TAG_RELEASE);
                b.extend_from_slice(fp.as_bytes());
            }
            Self::Sender(s) => {
                b.push(TAG_SENDER);
                b.extend_from_slice(s.sender.as_bytes());
                b.extend_from_slice(&s.last_sequence.to_be_bytes());
                b.extend_from_slice(&s.last_accepted_at_unix_ms.to_be_bytes());
            }
            Self::HighWater(hw) => {
                b.push(TAG_HIGH_WATER);
                b.extend_from_slice(&hw.to_be_bytes());
            }
        }
        b
    }

    fn decode(body: &[u8]) -> Option<Self> {
        let mut r = Reader(body, 0);
        let tag = r.u8()?;
        let rec = match tag {
            TAG_ACCEPT => Self::Accept(AcceptRecord {
                sender: r.fingerprint()?,
                sequence: r.u64()?,
                nonce: r.nonce()?,
                issued_at_unix_ms: r.u64()?,
                accepted_at_unix_ms: r.u64()?,
                nonce_expires_at_unix_ms: r.u64()?,
            }),
            TAG_QUARANTINE => Self::Quarantine(r.fingerprint()?, r.u64()?),
            TAG_RELEASE => Self::Release(r.fingerprint()?),
            TAG_SENDER => Self::Sender(RestoredSender {
                sender: r.fingerprint()?,
                last_sequence: r.u64()?,
                last_accepted_at_unix_ms: r.u64()?,
            }),
            TAG_HIGH_WATER => Self::HighWater(r.u64()?),
            _ => return None,
        };
        if r.1 == body.len() {
            Some(rec)
        } else {
            None
        }
    }
}

struct Reader<'a>(&'a [u8], usize);

impl Reader<'_> {
    fn take(&mut self, n: usize) -> Option<&[u8]> {
        let s = self.0.get(self.1..self.1.checked_add(n)?)?;
        self.1 += n;
        Some(s)
    }
    fn u8(&mut self) -> Option<u8> {
        self.take(1)?.first().copied()
    }
    fn u64(&mut self) -> Option<u64> {
        Some(u64::from_be_bytes(self.take(8)?.try_into().ok()?))
    }
    fn fingerprint(&mut self) -> Option<Fingerprint> {
        let b: [u8; 32] = self.take(32)?.try_into().ok()?;
        Some(Fingerprint::from_bytes(b))
    }
    fn nonce(&mut self) -> Option<Nonce> {
        let b: [u8; 16] = self.take(16)?.try_into().ok()?;
        Some(Nonce::from_bytes(b))
    }
}

/// Folds records into a [`RestoredState`].
#[derive(Default)]
struct Fold {
    senders: HashMap<Fingerprint, (u64, u64)>,
    nonces: HashMap<(Fingerprint, Nonce), u64>,
    high_water_ms: u64,
    quarantined: HashMap<Fingerprint, u64>,
}

impl Fold {
    fn sender(&mut self, fp: Fingerprint, seq: u64, at: u64) {
        let e = self.senders.entry(fp).or_insert((seq, at));
        e.0 = e.0.max(seq);
        e.1 = e.1.max(at);
    }

    fn apply(&mut self, r: Record) {
        match r {
            Record::Accept(a) => {
                self.sender(a.sender, a.sequence, a.accepted_at_unix_ms);
                let e = self.nonces.entry((a.sender, a.nonce)).or_insert(0);
                *e = (*e).max(a.nonce_expires_at_unix_ms);
                self.high_water_ms = self.high_water_ms.max(a.issued_at_unix_ms);
            }
            Record::Quarantine(fp, since) => {
                self.quarantined.insert(fp, since);
            }
            Record::Release(fp) => {
                self.quarantined.remove(&fp);
            }
            Record::Sender(s) => self.sender(s.sender, s.last_sequence, s.last_accepted_at_unix_ms),
            Record::HighWater(hw) => self.high_water_ms = self.high_water_ms.max(hw),
        }
    }

    fn finish(self) -> RestoredState {
        let mut senders: Vec<RestoredSender> = self
            .senders
            .into_iter()
            .map(|(sender, (last_sequence, last_accepted_at_unix_ms))| RestoredSender {
                sender,
                last_sequence,
                last_accepted_at_unix_ms,
            })
            .collect();
        senders.sort_by_key(|s| s.sender);
        let mut nonces: Vec<RestoredNonce> = self
            .nonces
            .into_iter()
            .map(|((sender, nonce), expires_at_unix_ms)| RestoredNonce {
                sender,
                nonce,
                expires_at_unix_ms,
            })
            .collect();
        nonces.sort_by_key(|n| (n.expires_at_unix_ms, n.sender, *n.nonce.as_bytes()));
        let mut quarantined: Vec<(Fingerprint, u64)> = self.quarantined.into_iter().collect();
        quarantined.sort();
        RestoredState {
            senders,
            nonces,
            high_water_ms: self.high_water_ms,
            quarantined,
        }
    }
}

/// An append-only, hash-chained, fsynced log file under an exclusive
/// advisory lock. See the module docs for the topology and the limits.
///
/// Layout: a 32-byte magic, then two 80-byte header slots (generation,
/// committed length, chain head, SHA-256 of those), then records. Each
/// record is a 4-byte big-endian body length, the body, the previous
/// chain head (32 bytes) and this record's SHA-256 over a domain
/// separator, the length, the body and the previous head. A commit
/// appends the record, calls `sync_data`, writes the next header slot
/// (alternating between the two) and calls `sync_data` again. Only then
/// is the acceptance acknowledged. At load the newest valid slot wins;
/// everything it commits is verified against the chain, and bytes past
/// it are discarded as never acknowledged.
pub struct FileStore {
    path: PathBuf,
    file: File,
    options: FileStoreOptions,
    loaded: bool,
    generation: u64,
    committed_len: u64,
    head: [u8; 32],
    high_water_ms: u64,
    /// Bytes past `committed_len` may exist on disk and must be cut off
    /// before the next append.
    dirty_tail: bool,
    /// Do not compact again until the log is this long.
    next_compact_at: u64,
}

impl fmt::Debug for FileStore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FileStore")
            .field("path", &self.path)
            .field("loaded", &self.loaded)
            .field("generation", &self.generation)
            .field("committed_len", &self.committed_len)
            .field("high_water_ms", &self.high_water_ms)
            .finish_non_exhaustive()
    }
}

impl FileStore {
    /// Opens (creating if absent) the store at `path` with default
    /// options and takes its exclusive lock. Fails with
    /// [`StoreError::Locked`] when another verifier holds it. Records are
    /// not read here; [`ReplayStore::load`] does that and is where
    /// corruption is reported.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, StoreError> {
        Self::open_with(path, FileStoreOptions::default())
    }

    /// [`FileStore::open`] with explicit options.
    pub fn open_with(path: impl AsRef<Path>, options: FileStoreOptions) -> Result<Self, StoreError> {
        let path = path.as_ref().to_path_buf();
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(&path)
            .map_err(|e| StoreError::io("open", &e))?;
        lock_exclusive(&file, &path)?;
        let len = file.metadata().map_err(|e| StoreError::io("stat", &e))?.len();
        let mut store = Self {
            path,
            file,
            options,
            loaded: false,
            generation: 0,
            committed_len: HEADER_LEN,
            head: genesis_head(),
            high_water_ms: 0,
            dirty_tail: false,
            next_compact_at: options.compact_after_bytes,
        };
        if len == 0 {
            store.write_genesis()?;
        }
        Ok(store)
    }

    /// The store file.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// The highest `issued_at_unix_ms` this store has recorded, as of the
    /// last load or commit.
    pub fn high_water_ms(&self) -> u64 {
        self.high_water_ms
    }

    /// Bytes of the log that are acknowledged.
    pub fn committed_len(&self) -> u64 {
        self.committed_len
    }

    fn write_genesis(&mut self) -> Result<(), StoreError> {
        let slot = Slot {
            generation: 0,
            committed_len: HEADER_LEN,
            head: genesis_head(),
        };
        let mut header = Vec::with_capacity(HEADER_LEN as usize);
        header.extend_from_slice(MAGIC);
        header.extend_from_slice(&slot.encode());
        header.extend_from_slice(&[0u8; SLOT_LEN as usize]);
        self.file.seek(SeekFrom::Start(0)).map_err(|e| StoreError::io("seek", &e))?;
        self.file.write_all(&header).map_err(|e| StoreError::io("write header", &e))?;
        self.file.sync_all().map_err(|e| StoreError::io("sync header", &e))?;
        sync_parent(&self.path)?;
        Ok(())
    }

    /// Reads the magic and both slots; returns the newest valid slot, the
    /// file length, and whether the pair of slots is one that a clean
    /// history leaves (both valid, or genesis: one valid at generation 0
    /// and the other empty). A pair that is not is explained only by a
    /// torn slot write, which leaves a complete record in the tail;
    /// `load` refuses it otherwise.
    fn read_header(file: &mut File) -> Result<(Slot, u64, bool), StoreError> {
        let len = file.metadata().map_err(|e| StoreError::io("stat", &e))?.len();
        if len < HEADER_LEN {
            return Err(StoreError::Corrupt {
                offset: len,
                detail: "file shorter than the header",
            });
        }
        let mut header = vec![0u8; HEADER_LEN as usize];
        file.seek(SeekFrom::Start(0)).map_err(|e| StoreError::io("seek", &e))?;
        file.read_exact(&mut header).map_err(|e| StoreError::io("read header", &e))?;
        if header.get(..32) != Some(&MAGIC[..]) {
            return Err(StoreError::Corrupt {
                offset: 0,
                detail: "not a stack-trident replay log",
            });
        }
        let a = Slot::state(header.get(SLOT_A as usize..SLOT_B as usize));
        let b = Slot::state(header.get(SLOT_B as usize..HEADER_LEN as usize));
        let (slot, clean) = match (a, b) {
            (SlotState::Valid(a), SlotState::Valid(b)) => {
                if a.generation >= b.generation {
                    (a, true)
                } else {
                    (b, true)
                }
            }
            (SlotState::Valid(a), SlotState::Empty) => (a, a.generation == 0),
            (SlotState::Empty, SlotState::Valid(b)) => (b, b.generation == 0),
            (SlotState::Valid(a), SlotState::Invalid) => (a, false),
            (SlotState::Invalid, SlotState::Valid(b)) => (b, false),
            _ => {
                return Err(StoreError::Corrupt {
                    offset: SLOT_A,
                    detail: "no valid header slot",
                })
            }
        };
        Ok((slot, len, clean))
    }

    /// Reads and verifies the chain from the end of the header to
    /// `committed_len`, whose head must be `expected_head`.
    fn read_chain(file: &mut File, committed_len: u64, expected_head: &[u8; 32]) -> Result<Vec<Record>, StoreError> {
        let body_len = usize::try_from(committed_len.saturating_sub(HEADER_LEN)).map_err(|_| StoreError::Corrupt {
            offset: HEADER_LEN,
            detail: "committed length does not fit in memory",
        })?;
        let mut bytes = vec![0u8; body_len];
        file.seek(SeekFrom::Start(HEADER_LEN)).map_err(|e| StoreError::io("seek", &e))?;
        file.read_exact(&mut bytes).map_err(|e| StoreError::io("read records", &e))?;
        let mut records = Vec::new();
        let mut running = genesis_head();
        let mut pos = 0usize;
        while pos < bytes.len() {
            let (record, hash, next) = Self::parse_record(&bytes, pos, &running, HEADER_LEN)?;
            records.push(record);
            running = hash;
            pos = next;
        }
        if &running != expected_head {
            return Err(StoreError::Corrupt {
                offset: committed_len,
                detail: "chain head does not match the header",
            });
        }
        Ok(records)
    }

    /// Parses and verifies the record at `pos` in `bytes`, which must chain
    /// to `running`. Returns the record, its hash (the new chain head) and
    /// the position after it. `base` is the file offset of `bytes[0]`, for
    /// error reporting.
    fn parse_record(
        bytes: &[u8],
        pos: usize,
        running: &[u8; 32],
        base: u64,
    ) -> Result<(Record, [u8; 32], usize), StoreError> {
        let at = base.saturating_add(u64::try_from(pos).unwrap_or(u64::MAX));
        let len_bytes = bytes.get(pos..pos.saturating_add(4)).ok_or(StoreError::Corrupt {
            offset: at,
            detail: "record length cut off",
        })?;
        let len = usize::try_from(u32::from_be_bytes(len_bytes.try_into().unwrap_or([0; 4]))).unwrap_or(usize::MAX);
        if len == 0 || len > MAX_BODY_LEN {
            return Err(StoreError::Corrupt {
                offset: at,
                detail: "record length out of range",
            });
        }
        let body_start = pos.saturating_add(4);
        let body_end = body_start.saturating_add(len);
        let hash_end = body_end.saturating_add(64);
        let (body, prev, stored) = match (
            bytes.get(body_start..body_end),
            bytes.get(body_end..body_end.saturating_add(32)),
            bytes.get(body_end.saturating_add(32)..hash_end),
        ) {
            (Some(b), Some(p), Some(h)) => (b, p, h),
            _ => {
                return Err(StoreError::Corrupt {
                    offset: at,
                    detail: "record cut off",
                })
            }
        };
        if prev != running {
            return Err(StoreError::Corrupt {
                offset: at,
                detail: "record does not chain to the previous one",
            });
        }
        let hash = record_hash(body, running);
        if stored != hash {
            return Err(StoreError::Corrupt {
                offset: at,
                detail: "record hash mismatch",
            });
        }
        let record = Record::decode(body).ok_or(StoreError::Corrupt {
            offset: at,
            detail: "record body does not decode",
        })?;
        Ok((record, hash, hash_end))
    }

    /// Judges the bytes past the committed length. A crash between the
    /// record sync and the header-slot write leaves exactly one complete,
    /// chain-valid record there: it is adopted, because refusing that
    /// envelope as a replay is the restrictive outcome and the previous
    /// process may have acknowledged it. Anything else that one crash can
    /// leave (a partial or garbled record) is discarded as never
    /// acknowledged. More bytes than one record can hold is not something a
    /// crash produces and is reported as corruption.
    fn judge_tail(
        file: &mut File,
        path: &Path,
        committed_len: u64,
        len: u64,
        head: &[u8; 32],
    ) -> Result<Option<(Record, [u8; 32], u64)>, StoreError> {
        let tail_len = len.saturating_sub(committed_len);
        if tail_len == 0 {
            return Ok(None);
        }
        if tail_len > MAX_RECORD_LEN {
            return Err(StoreError::Corrupt {
                offset: committed_len,
                detail: "more unacknowledged bytes than one record can hold",
            });
        }
        let mut tail = vec![0u8; usize::try_from(tail_len).unwrap_or(0)];
        file.seek(SeekFrom::Start(committed_len)).map_err(|e| StoreError::io("seek", &e))?;
        file.read_exact(&mut tail).map_err(|e| StoreError::io("read tail", &e))?;
        match Self::parse_record(&tail, 0, head, committed_len) {
            Ok((record, hash, next)) if next == tail.len() => {
                tracing::warn!(
                    path = %path.display(),
                    "stack.trident replay store has a complete but unacknowledged last record (torn header write); adopting it"
                );
                Ok(Some((record, hash, len)))
            }
            Ok(_) => Err(StoreError::Corrupt {
                offset: committed_len,
                detail: "bytes follow the unacknowledged last record",
            }),
            Err(_) => {
                tracing::warn!(
                    path = %path.display(),
                    unacknowledged_bytes = tail_len,
                    "stack.trident replay store has a torn last record (never acknowledged); discarding it"
                );
                Ok(None)
            }
        }
    }

    /// Appends one record and acknowledges it. On any error the in-memory
    /// view is unchanged and the next append starts by cutting the file
    /// back to the committed length.
    fn append(&mut self, record: &Record) -> Result<(), StoreError> {
        if !self.loaded {
            return Err(StoreError::NotLoaded);
        }
        let result = self.append_inner(record);
        if result.is_err() {
            self.dirty_tail = true;
        }
        result
    }

    fn append_inner(&mut self, record: &Record) -> Result<(), StoreError> {
        if self.dirty_tail {
            self.file
                .set_len(self.committed_len)
                .map_err(|e| StoreError::io("truncate unacknowledged tail", &e))?;
            self.dirty_tail = false;
        }
        let (bytes, head) = encode_record(&record.encode(), &self.head);
        self.file
            .seek(SeekFrom::Start(self.committed_len))
            .map_err(|e| StoreError::io("seek", &e))?;
        self.file.write_all(&bytes).map_err(|e| StoreError::io("write record", &e))?;
        self.file.sync_data().map_err(|e| StoreError::io("sync record", &e))?;
        let slot = Slot {
            generation: self.generation.saturating_add(1),
            committed_len: self.committed_len.saturating_add(u64::try_from(bytes.len()).unwrap_or(u64::MAX)),
            head,
        };
        let offset = if slot.generation.is_multiple_of(2) { SLOT_A } else { SLOT_B };
        self.file.seek(SeekFrom::Start(offset)).map_err(|e| StoreError::io("seek", &e))?;
        self.file.write_all(&slot.encode()).map_err(|e| StoreError::io("write header slot", &e))?;
        self.file.sync_data().map_err(|e| StoreError::io("sync header slot", &e))?;
        self.generation = slot.generation;
        self.committed_len = slot.committed_len;
        self.head = head;
        Ok(())
    }

    /// Rewrites the log without nonces whose retention ended at or before
    /// `now_unix_ms`. Every sender's sequence, the high-water mark and every
    /// quarantine are kept. The new file is written, synced and locked
    /// before it replaces the old one, so a failure leaves the old log in
    /// place and acknowledged.
    pub fn compact(&mut self, now_unix_ms: u64) -> Result<(), StoreError> {
        if !self.loaded {
            return Err(StoreError::NotLoaded);
        }
        let records = Self::read_chain(&mut self.file, self.committed_len, &self.head)?;
        let mut fold = Fold::default();
        for r in records {
            fold.apply(r);
        }
        let state = fold.finish();
        let mut out: Vec<Record> = Vec::with_capacity(state.senders.len() + state.nonces.len() + 2);
        out.push(Record::HighWater(state.high_water_ms));
        out.extend(state.senders.iter().copied().map(Record::Sender));
        out.extend(
            state
                .nonces
                .iter()
                .filter(|n| n.expires_at_unix_ms > now_unix_ms)
                .map(|n| {
                    Record::Accept(AcceptRecord {
                        sender: n.sender,
                        sequence: 0,
                        nonce: n.nonce,
                        issued_at_unix_ms: 0,
                        accepted_at_unix_ms: 0,
                        nonce_expires_at_unix_ms: n.expires_at_unix_ms,
                    })
                }),
        );
        out.extend(state.quarantined.iter().map(|(fp, since)| Record::Quarantine(*fp, *since)));

        let tmp_path = {
            let mut p = self.path.clone().into_os_string();
            p.push(".compacting");
            PathBuf::from(p)
        };
        let written = Self::write_fresh(&tmp_path, &out);
        let (file, generation, committed_len, head) = match written {
            Ok(v) => v,
            Err(e) => {
                let _ = std::fs::remove_file(&tmp_path);
                return Err(e);
            }
        };
        if let Err(e) = std::fs::rename(&tmp_path, &self.path) {
            let _ = std::fs::remove_file(&tmp_path);
            return Err(StoreError::io("rename compacted log", &e));
        }
        sync_parent(&self.path)?;
        self.file = file;
        self.generation = generation;
        self.committed_len = committed_len;
        self.head = head;
        self.dirty_tail = false;
        self.next_compact_at = self
            .options
            .compact_after_bytes
            .max(committed_len.saturating_mul(2));
        tracing::info!(
            path = %self.path.display(),
            committed_len,
            "stack.trident replay store compacted"
        );
        Ok(())
    }

    /// Writes a complete, locked, synced log holding `records` at `path`.
    fn write_fresh(path: &Path, records: &[Record]) -> Result<(File, u64, u64, [u8; 32]), StoreError> {
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(true)
            .open(path)
            .map_err(|e| StoreError::io("create compacted log", &e))?;
        lock_exclusive(&file, path)?;
        let mut bytes = Vec::new();
        bytes.extend_from_slice(MAGIC);
        bytes.extend_from_slice(&[0u8; 2 * SLOT_LEN as usize]);
        let mut head = genesis_head();
        for r in records {
            let (rec, new_head) = encode_record(&r.encode(), &head);
            bytes.extend_from_slice(&rec);
            head = new_head;
        }
        let committed_len = u64::try_from(bytes.len()).unwrap_or(u64::MAX);
        let generation = 1;
        let slot = Slot {
            generation,
            committed_len,
            head,
        };
        // Both slots carry the same generation so that the pair is clean.
        let slot_bytes = slot.encode();
        let slot_range = SLOT_A as usize..HEADER_LEN as usize;
        match bytes.get_mut(slot_range) {
            Some(dst) => {
                let (first, second) = dst.split_at_mut(SLOT_LEN as usize);
                first.copy_from_slice(&slot_bytes);
                second.copy_from_slice(&slot_bytes);
            }
            None => {
                return Err(StoreError::Corrupt {
                    offset: SLOT_A,
                    detail: "header buffer too short",
                })
            }
        }
        let mut f = &file;
        f.write_all(&bytes).map_err(|e| StoreError::io("write compacted log", &e))?;
        f.sync_all().map_err(|e| StoreError::io("sync compacted log", &e))?;
        Ok((file, generation, committed_len, head))
    }
}

impl ReplayStore for FileStore {
    fn load(&mut self) -> Result<RestoredState, StoreError> {
        let (slot, len, clean) = Self::read_header(&mut self.file)?;
        if slot.committed_len > len {
            return Err(StoreError::Truncated {
                committed_len: slot.committed_len,
                actual_len: len,
            });
        }
        let mut records = Self::read_chain(&mut self.file, slot.committed_len, &slot.head)?;
        let (mut committed_len, mut head) = (slot.committed_len, slot.head);
        let adopted = Self::judge_tail(&mut self.file, &self.path, committed_len, len, &head)?;
        if !clean && adopted.is_none() {
            // An unreadable slot with no complete trailing record to
            // explain it is not a torn slot write: it is damage, and
            // reading the older slot would silently forget acceptances.
            return Err(StoreError::Corrupt {
                offset: SLOT_A,
                detail: "a header slot is unreadable and no torn slot write explains it",
            });
        }
        if let Some((record, hash, new_len)) = adopted {
            records.push(record);
            committed_len = new_len;
            head = hash;
        }
        let mut fold = Fold::default();
        for r in records {
            fold.apply(r);
        }
        let state = fold.finish();
        self.generation = slot.generation;
        self.committed_len = committed_len;
        self.head = head;
        self.high_water_ms = state.high_water_ms;
        self.dirty_tail = len > committed_len;
        self.loaded = true;
        self.next_compact_at = self.options.compact_after_bytes;
        Ok(state)
    }

    fn commit(&mut self, record: &AcceptRecord) -> Result<(), StoreError> {
        self.append(&Record::Accept(*record))?;
        self.high_water_ms = self.high_water_ms.max(record.issued_at_unix_ms);
        if self.committed_len >= self.next_compact_at {
            if let Err(e) = self.compact(record.accepted_at_unix_ms) {
                // The acceptance is already durable; a failed compaction
                // only leaves the log longer than it needs to be.
                self.next_compact_at = self.committed_len.saturating_mul(2);
                tracing::error!(error = %e, "stack.trident replay store compaction failed; keeping the uncompacted log");
            }
        }
        Ok(())
    }

    fn is_durable(&self) -> bool {
        true
    }

    fn record_quarantine(&mut self, sender: &Fingerprint, since_unix_ms: u64) -> Result<(), StoreError> {
        self.append(&Record::Quarantine(*sender, since_unix_ms))
    }

    fn record_release(&mut self, sender: &Fingerprint) -> Result<(), StoreError> {
        self.append(&Record::Release(*sender))
    }
}

fn lock_exclusive(file: &File, path: &Path) -> Result<(), StoreError> {
    match file.try_lock() {
        Ok(()) => Ok(()),
        Err(TryLockError::WouldBlock) => Err(StoreError::Locked {
            path: path.to_path_buf(),
        }),
        Err(TryLockError::Error(e)) => Err(StoreError::io("lock", &e)),
    }
}

/// Makes a directory entry change (create, rename) durable.
fn sync_parent(path: &Path) -> Result<(), StoreError> {
    let parent = match path.parent() {
        Some(p) if !p.as_os_str().is_empty() => p.to_path_buf(),
        _ => PathBuf::from("."),
    };
    File::open(&parent)
        .and_then(|d| d.sync_all())
        .map_err(|e| StoreError::io("sync directory", &e))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fp(b: u8) -> Fingerprint {
        Fingerprint::from_bytes([b; 32])
    }

    fn accept(b: u8, seq: u64, at: u64) -> AcceptRecord {
        AcceptRecord {
            sender: fp(b),
            sequence: seq,
            nonce: Nonce::from_bytes([u8::try_from(seq).unwrap(); 16]),
            issued_at_unix_ms: at,
            accepted_at_unix_ms: at,
            nonce_expires_at_unix_ms: at + 100,
        }
    }

    fn temp(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("stack-trident-store-{}-{name}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        dir.join("replay.log")
    }

    #[test]
    fn records_round_trip_through_the_chain() {
        let path = temp("roundtrip");
        let _ = std::fs::remove_file(&path);
        let mut s = FileStore::open(&path).unwrap();
        assert!(s.commit(&accept(1, 1, 10)).is_err(), "commit before load must fail");
        assert_eq!(s.load().unwrap(), RestoredState::default());
        s.commit(&accept(1, 1, 10)).unwrap();
        s.commit(&accept(1, 2, 20)).unwrap();
        s.commit(&accept(2, 7, 15)).unwrap();
        s.record_quarantine(&fp(2), 16).unwrap();
        drop(s);
        let mut s = FileStore::open(&path).unwrap();
        let st = s.load().unwrap();
        assert_eq!(st.high_water_ms, 20);
        assert_eq!(st.senders.len(), 2);
        assert_eq!(st.nonces.len(), 3);
        assert_eq!(st.quarantined, vec![(fp(2), 16)]);
        s.record_release(&fp(2)).unwrap();
        s.compact(115).unwrap();
        let st = s.load().unwrap();
        assert_eq!(st.high_water_ms, 20);
        assert_eq!(st.senders.len(), 2);
        assert_eq!(st.nonces.len(), 1, "{:?}", st.nonces);
        assert!(st.quarantined.is_empty());
    }

    #[test]
    fn memory_store_is_not_durable_and_needs_load() {
        let mut m = MemoryStore::new();
        assert!(!m.is_durable());
        assert_eq!(m.commit(&accept(1, 1, 1)), Err(StoreError::NotLoaded));
        m.load().unwrap();
        m.commit(&accept(1, 1, 1)).unwrap();
    }
}
