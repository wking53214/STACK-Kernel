//! The receipt log: an append-only, hash-chained, signed, fsynced file
//! under an exclusive advisory lock, and the trait a recorder writes to.
//!
//! # File format, `stack-receipt/log/1`
//!
//! ```text
//! magic     32 bytes   "stack-receipt/log/1\n" then zero padding
//! slot A    80 bytes   generation u64, committed_len u64, head hash 32, SHA-256 of those 32
//! slot B    80 bytes   the same shape
//! frames    each: u32 length, canonical record, signature 64, record hash 32
//! ```
//!
//! An append writes the frame at `committed_len`, calls `sync_data`,
//! writes the next header slot (alternating between the two, generation
//! plus one, the new committed length and chain head), calls `sync_data`
//! again, and only then reports the record as recorded. The design is the
//! one `stack-trident`'s replay store uses, reimplemented here: the
//! committed length lives in a hashed header slot, so the extent of the
//! acknowledged log never depends on a byte an editor could change.
//!
//! On open the newest valid slot wins; every frame up to its committed
//! length must chain (sequence plus one, previous hash equal to the
//! running head, stored hash equal to the recomputed hash) and the
//! running head must equal the slot's. Bytes past the committed length are
//! what one crash can leave: exactly one complete, chain-valid frame (the
//! crash fell between the frame sync and the slot write) is adopted, since
//! the previous process may already have reported it; anything else is
//! discarded as never acknowledged. More bytes than one frame can hold,
//! an unreadable slot with no adopted frame to explain it, a frame that
//! does not chain, or a wrong magic is corruption: open fails and the log
//! is unusable. A log that could have forgotten a record must not answer.
//!
//! # What the chain proves and what it cannot
//!
//! Alteration, reordering, insertion and truncation inside the committed
//! region are detected at open. A rollback to an earlier committed state
//! by someone who can rewrite both header slots consistently is not
//! detectable from the file alone; [`FileReceiptLog::head`] exposes the
//! chain head for an operator to anchor elsewhere (the same class as
//! register D-09 and the stack-authority use log). The lock is advisory:
//! it keeps cooperating opens apart and does not stop a process that
//! ignores it. One active writer per log.

use std::fmt;
use std::fs::{File, OpenOptions, TryLockError};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};

use crate::encode::{genesis_hash, prefix_consistent, MAX_RECORD_BYTES};
use crate::record::{check_text, MAX_ID_BYTES};
use crate::sign::{FrameError, ReceiptPublicKey, SignedRecord, FRAME_OVERHEAD};

/// The first 32 bytes of a log file.
pub const MAGIC: &[u8; 32] = b"stack-receipt/log/1\n\0\0\0\0\0\0\0\0\0\0\0\0";
const SLOT_DOMAIN: &[u8] = b"stack-receipt/log-slot/1\n";
/// Bytes of one header slot.
pub const SLOT_LEN: u64 = 8 + 8 + 32 + 32;
const SLOT_A: u64 = 32;
const SLOT_B: u64 = 32 + SLOT_LEN;
/// Bytes of the header: magic and two slots.
pub const HEADER_LEN: u64 = 32 + 2 * SLOT_LEN;
/// Largest log the reader will load, in bytes.
pub const MAX_LOG_BYTES: u64 = 1 << 30;
/// Longest frame on disk.
pub const MAX_FRAME_BYTES: u64 = (MAX_RECORD_BYTES + FRAME_OVERHEAD) as u64;

/// The chain head: the sequence and hash of the last record, or `0` and
/// the genesis hash for an empty log. The next record must carry
/// `sequence + 1` and `prev_hash == hash`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Head {
    /// Sequence of the last record; 0 when empty.
    pub sequence: u64,
    /// Hash of the last record, or the genesis hash.
    pub hash: [u8; 32],
}

impl Head {
    /// The head of an empty log.
    pub fn genesis() -> Self {
        Self {
            sequence: 0,
            hash: genesis_hash(),
        }
    }
}

/// Why a log operation failed. Every variant is a reason not to execute:
/// a recorder never proceeds on a weaker posture because of one.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum LogError {
    /// Another writer holds the exclusive lock.
    #[error("receipt log {path} is locked by another writer; one active writer per log")]
    Locked {
        /// The log file.
        path: PathBuf,
    },
    /// An I/O operation failed.
    #[error("receipt log {op} failed: {kind:?}: {message}")]
    Io {
        /// What was being done.
        op: &'static str,
        /// The OS error kind.
        kind: io::ErrorKind,
        /// The OS error text.
        message: String,
    },
    /// The committed region does not verify.
    #[error("receipt log is corrupt at byte {offset}: {detail}")]
    Corrupt {
        /// Byte offset of the first thing that did not verify.
        offset: u64,
        /// What did not verify.
        detail: &'static str,
    },
    /// The file is shorter than its committed length.
    #[error("receipt log was truncated: header commits {committed_len} bytes, file holds {actual_len}")]
    Truncated {
        /// Length the header commits.
        committed_len: u64,
        /// Length on disk.
        actual_len: u64,
    },
    /// Longer than [`MAX_LOG_BYTES`].
    #[error("receipt log exceeds {MAX_LOG_BYTES} bytes")]
    TooLarge,
    /// A record does not chain to the head or names another kernel.
    #[error("record does not chain: {detail}")]
    DoesNotChain {
        /// What is wrong.
        detail: &'static str,
    },
    /// A record's signature does not verify under any key the log was
    /// opened with.
    #[error("record signature does not verify under the log's keys")]
    BadSignature,
    /// A write or sync failed earlier; the on-disk state is unknown and
    /// every later call is refused until the log is reopened.
    #[error("receipt log is poisoned by an earlier write failure")]
    Poisoned,
    /// The kernel id or key set given at open is unusable.
    #[error("bad configuration: {0}")]
    BadConfig(&'static str),
}

impl LogError {
    fn io(op: &'static str, e: &io::Error) -> Self {
        Self::Io {
            op,
            kind: e.kind(),
            message: e.to_string(),
        }
    }
}

/// Where a recorder appends. Every method is called under the recorder's
/// own lock; an implementation needs no locking against the recorder but
/// must still refuse a second process ([`FileReceiptLog`] does).
pub trait ReceiptLog: Send + fmt::Debug {
    /// The kernel whose log this is.
    fn kernel_id(&self) -> &str;

    /// The chain head.
    fn head(&self) -> Result<Head, LogError>;

    /// Makes one record durable. Returns only after the record would
    /// survive a crash, or with an error, in which case the record must
    /// be treated as unrecorded.
    fn append(&mut self, record: &SignedRecord) -> Result<(), LogError>;

    /// Whether what `append` returned `Ok` for survives a restart.
    fn is_durable(&self) -> bool;

    /// Every acknowledged record, in order. A restarted kernel reads this once,
    /// before it accepts work, to find executions a crash left open
    /// ([`crate::Recorder::recover_open_executions`]). A log that cannot list its
    /// records refuses, so a kernel over it cannot start: it fails closed
    /// rather than leaving open executions unexamined.
    fn acknowledged_records(&self) -> Result<Vec<SignedRecord>, LogError> {
        Err(LogError::BadConfig("this log cannot list its records"))
    }
}

/// A log that keeps records in memory only. For tests and simulations:
/// `is_durable()` is `false`.
#[derive(Debug)]
pub struct MemoryReceiptLog {
    kernel_id: String,
    records: Vec<SignedRecord>,
    head: Head,
}

impl MemoryReceiptLog {
    /// An empty in-memory log for `kernel_id`.
    pub fn new(kernel_id: &str) -> Result<Self, LogError> {
        check_text("kernel_id", kernel_id, 1, MAX_ID_BYTES).map_err(|_| LogError::BadConfig("kernel id"))?;
        Ok(Self {
            kernel_id: kernel_id.to_owned(),
            records: Vec::new(),
            head: Head::genesis(),
        })
    }

    /// The records, in order.
    pub fn records(&self) -> &[SignedRecord] {
        &self.records
    }
}

impl ReceiptLog for MemoryReceiptLog {
    fn kernel_id(&self) -> &str {
        &self.kernel_id
    }

    fn head(&self) -> Result<Head, LogError> {
        Ok(self.head)
    }

    fn append(&mut self, record: &SignedRecord) -> Result<(), LogError> {
        check_chains(record, &self.head, &self.kernel_id)?;
        self.head = Head {
            sequence: record.record().sequence,
            hash: *record.hash(),
        };
        self.records.push(record.clone());
        Ok(())
    }

    fn is_durable(&self) -> bool {
        false
    }

    fn acknowledged_records(&self) -> Result<Vec<SignedRecord>, LogError> {
        Ok(self.records.clone())
    }
}

/// Checks that `record` is the next record after `head` for `kernel_id`.
pub fn check_chains(record: &SignedRecord, head: &Head, kernel_id: &str) -> Result<(), LogError> {
    let r = record.record();
    if r.kernel_id != kernel_id {
        return Err(LogError::DoesNotChain {
            detail: "record names another kernel",
        });
    }
    if r.sequence != head.sequence.saturating_add(1) || head.sequence == u64::MAX {
        return Err(LogError::DoesNotChain {
            detail: "sequence is not the head sequence plus one",
        });
    }
    if r.prev_hash != head.hash {
        return Err(LogError::DoesNotChain {
            detail: "prev_hash is not the head hash",
        });
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Header slots
// ---------------------------------------------------------------------------

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

#[derive(Debug, Clone, Copy)]
enum SlotState {
    Valid(Slot),
    Empty,
    Invalid,
}

/// What a log's bytes hold, as the reader judged them.
#[derive(Debug, Clone)]
pub struct ParsedLog {
    /// Every acknowledged record, in order, plus an adopted trailing
    /// frame when one was found.
    pub records: Vec<SignedRecord>,
    /// The chain head after the last record.
    pub head: Head,
    /// Generation of the newest valid slot.
    pub generation: u64,
    /// The committed length, after adopting a complete trailing frame.
    pub committed_len: u64,
    /// Whether a complete, chain-valid frame past the committed length
    /// was adopted (a torn slot write).
    pub adopted_tail: bool,
    /// Bytes past the committed length that were discarded as never
    /// acknowledged (a torn frame write).
    pub discarded_tail_bytes: u64,
}

/// Reads the header and returns the newest valid slot and whether the
/// pair of slots is one a clean history leaves.
fn read_header(bytes: &[u8]) -> Result<(Slot, bool), LogError> {
    if (bytes.len() as u64) < HEADER_LEN {
        return Err(LogError::Corrupt {
            offset: bytes.len() as u64,
            detail: "file shorter than the header",
        });
    }
    if bytes.get(..32) != Some(&MAGIC[..]) {
        return Err(LogError::Corrupt {
            offset: 0,
            detail: "not a stack-receipt log",
        });
    }
    let a = Slot::state(bytes.get(SLOT_A as usize..SLOT_B as usize));
    let b = Slot::state(bytes.get(SLOT_B as usize..HEADER_LEN as usize));
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
            return Err(LogError::Corrupt {
                offset: SLOT_A,
                detail: "no valid header slot",
            })
        }
    };
    Ok((slot, clean))
}

/// Parses one frame at `pos`, which must chain to `head`. Returns the
/// record and the position after it.
fn parse_chained_frame(bytes: &[u8], pos: usize, head: &Head) -> Result<(SignedRecord, usize), LogError> {
    let at = pos as u64;
    let rest = bytes.get(pos..).ok_or(LogError::Corrupt {
        offset: at,
        detail: "frame offset past the end",
    })?;
    let (record, used) = match SignedRecord::parse_frame(rest) {
        Ok(v) => v,
        Err(FrameError::Truncated { .. }) => {
            return Err(LogError::Corrupt {
                offset: at,
                detail: "frame cut off inside the committed region",
            })
        }
        Err(FrameError::LengthOutOfRange(_)) => {
            return Err(LogError::Corrupt {
                offset: at,
                detail: "frame length out of range",
            })
        }
        Err(FrameError::HashMismatch) => {
            return Err(LogError::Corrupt {
                offset: at,
                detail: "record hash mismatch",
            })
        }
        Err(FrameError::Decode(_)) => {
            return Err(LogError::Corrupt {
                offset: at,
                detail: "record does not decode",
            })
        }
    };
    let r = record.record();
    if r.sequence != head.sequence.saturating_add(1) {
        return Err(LogError::Corrupt {
            offset: at,
            detail: "sequence is not the previous sequence plus one",
        });
    }
    if r.prev_hash != head.hash {
        return Err(LogError::Corrupt {
            offset: at,
            detail: "record does not chain to the previous one",
        });
    }
    Ok((record, pos.saturating_add(used)))
}

/// Parses a whole log file. Signatures are not checked here; the writer
/// checks them against its keys at open and the verifier against its
/// trust set with windows.
pub fn parse_log(bytes: &[u8]) -> Result<ParsedLog, LogError> {
    if bytes.len() as u64 > MAX_LOG_BYTES {
        return Err(LogError::TooLarge);
    }
    let (slot, clean) = read_header(bytes)?;
    let len = bytes.len() as u64;
    if slot.committed_len > len {
        return Err(LogError::Truncated {
            committed_len: slot.committed_len,
            actual_len: len,
        });
    }
    let committed = usize::try_from(slot.committed_len).map_err(|_| LogError::TooLarge)?;
    let mut records = Vec::new();
    let mut head = Head::genesis();
    let mut pos = HEADER_LEN as usize;
    while pos < committed {
        let (record, next) = parse_chained_frame(bytes, pos, &head)?;
        if next > committed {
            return Err(LogError::Corrupt {
                offset: pos as u64,
                detail: "frame crosses the committed length",
            });
        }
        head = Head {
            sequence: record.record().sequence,
            hash: *record.hash(),
        };
        records.push(record);
        pos = next;
    }
    if head.hash != slot.head {
        return Err(LogError::Corrupt {
            offset: slot.committed_len,
            detail: "chain head does not match the header",
        });
    }
    // The tail: what one crash can leave.
    let tail_len = len.saturating_sub(slot.committed_len);
    let mut committed_len = slot.committed_len;
    let mut adopted_tail = false;
    let mut discarded_tail_bytes = 0;
    if tail_len > 0 {
        if tail_len > MAX_FRAME_BYTES {
            return Err(LogError::Corrupt {
                offset: slot.committed_len,
                detail: "more unacknowledged bytes than one frame can hold",
            });
        }
        match parse_chained_frame(bytes, committed, &head) {
            Ok((record, next)) if next as u64 == len => {
                head = Head {
                    sequence: record.record().sequence,
                    hash: *record.hash(),
                };
                records.push(record);
                committed_len = len;
                adopted_tail = true;
            }
            Ok(_) => {
                return Err(LogError::Corrupt {
                    offset: slot.committed_len,
                    detail: "bytes follow the unacknowledged last frame",
                })
            }
            Err(_) => {
                // A torn frame write: the bytes present must be a prefix
                // of what the writer would have put there, else it is
                // damage and not a crash.
                let tail = bytes.get(committed..).unwrap_or(&[]);
                if !torn_tail_plausible(tail, &head) {
                    return Err(LogError::Corrupt {
                        offset: slot.committed_len,
                        detail: "unacknowledged bytes are not a torn frame",
                    });
                }
                discarded_tail_bytes = tail_len;
            }
        }
    }
    if !clean && !adopted_tail {
        return Err(LogError::Corrupt {
            offset: SLOT_A,
            detail: "a header slot is unreadable and no torn slot write explains it",
        });
    }
    Ok(ParsedLog {
        records,
        head,
        generation: slot.generation,
        committed_len,
        adopted_tail,
        discarded_tail_bytes,
    })
}

/// Whether `tail` could be the prefix of a frame a writer at `head` was
/// writing when it died: a length in range (when present) and a record
/// prefix consistent with the next sequence and the head hash.
fn torn_tail_plausible(tail: &[u8], head: &Head) -> bool {
    if tail.len() >= 4 {
        let declared = u32::from_be_bytes(tail.get(..4).and_then(|s| s.try_into().ok()).unwrap_or([0; 4]));
        if declared == 0 || declared as usize > MAX_RECORD_BYTES {
            return false;
        }
        let body = tail.get(4..).unwrap_or(&[]);
        let body = body.get(..body.len().min(declared as usize)).unwrap_or(&[]);
        return prefix_consistent(body, head.sequence.saturating_add(1), &head.hash);
    }
    true
}

// ---------------------------------------------------------------------------
// File log
// ---------------------------------------------------------------------------

/// The durable receipt log. See the module documentation.
pub struct FileReceiptLog {
    path: PathBuf,
    file: File,
    kernel_id: String,
    keys: Vec<ReceiptPublicKey>,
    generation: u64,
    committed_len: u64,
    head: Head,
    dirty_tail: bool,
    poisoned: bool,
    records: usize,
}

impl fmt::Debug for FileReceiptLog {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FileReceiptLog")
            .field("path", &self.path)
            .field("kernel_id", &self.kernel_id)
            .field("generation", &self.generation)
            .field("committed_len", &self.committed_len)
            .field("head", &self.head)
            .field("poisoned", &self.poisoned)
            .finish_non_exhaustive()
    }
}

impl FileReceiptLog {
    /// Opens or creates the log at `path` for `kernel_id`, takes the
    /// exclusive lock, verifies the chain and every record's signature
    /// under one of `keys` (the kernel's current receipt key, and its
    /// previous ones while their records remain in the log).
    pub fn open(path: impl AsRef<Path>, kernel_id: &str, keys: &[ReceiptPublicKey]) -> Result<Self, LogError> {
        check_text("kernel_id", kernel_id, 1, MAX_ID_BYTES).map_err(|_| LogError::BadConfig("kernel id"))?;
        if keys.is_empty() {
            return Err(LogError::BadConfig("no receipt key"));
        }
        let path = path.as_ref().to_path_buf();
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(&path)
            .map_err(|e| LogError::io("open", &e))?;
        match file.try_lock() {
            Ok(()) => {}
            Err(TryLockError::WouldBlock) => return Err(LogError::Locked { path }),
            Err(TryLockError::Error(e)) => return Err(LogError::io("lock", &e)),
        }
        let len = file.metadata().map_err(|e| LogError::io("stat", &e))?.len();
        if len > MAX_LOG_BYTES {
            return Err(LogError::TooLarge);
        }
        let mut log = Self {
            path,
            file,
            kernel_id: kernel_id.to_owned(),
            keys: keys.to_vec(),
            generation: 0,
            committed_len: HEADER_LEN,
            head: Head::genesis(),
            dirty_tail: false,
            poisoned: false,
            records: 0,
        };
        if len == 0 {
            log.write_genesis()?;
            return Ok(log);
        }
        let mut bytes = Vec::with_capacity(usize::try_from(len).map_err(|_| LogError::TooLarge)?);
        log.file
            .seek(SeekFrom::Start(0))
            .map_err(|e| LogError::io("seek", &e))?;
        log.file
            .read_to_end(&mut bytes)
            .map_err(|e| LogError::io("read", &e))?;
        let parsed = parse_log(&bytes)?;
        for record in &parsed.records {
            if record.record().kernel_id != kernel_id {
                return Err(LogError::Corrupt {
                    offset: HEADER_LEN,
                    detail: "a record names another kernel",
                });
            }
            if !log.keys.iter().any(|k| record.verify(k).is_ok()) {
                return Err(LogError::Corrupt {
                    offset: HEADER_LEN,
                    detail: "a record's signature does not verify under the log's keys",
                });
            }
        }
        log.generation = parsed.generation;
        log.committed_len = parsed.committed_len;
        log.head = parsed.head;
        log.records = parsed.records.len();
        log.dirty_tail = parsed.discarded_tail_bytes > 0;
        if parsed.adopted_tail {
            // Finish the interrupted commit so the file is clean.
            log.write_slot()?;
        }
        Ok(log)
    }

    /// The log file.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Bytes of the log that are acknowledged.
    pub const fn committed_len(&self) -> u64 {
        self.committed_len
    }

    /// Number of acknowledged records.
    pub const fn records(&self) -> usize {
        self.records
    }

    /// Reads and parses the whole file (for a verifier that holds the
    /// path but not the lock, or for tests). Does not take the lock.
    pub fn read_file(path: impl AsRef<Path>) -> Result<ParsedLog, LogError> {
        let bytes = std::fs::read(path).map_err(|e| LogError::io("read", &e))?;
        parse_log(&bytes)
    }

    fn write_genesis(&mut self) -> Result<(), LogError> {
        let slot = Slot {
            generation: 0,
            committed_len: HEADER_LEN,
            head: genesis_hash(),
        };
        let mut header = Vec::with_capacity(HEADER_LEN as usize);
        header.extend_from_slice(MAGIC);
        header.extend_from_slice(&slot.encode());
        header.extend_from_slice(&[0u8; SLOT_LEN as usize]);
        self.file.seek(SeekFrom::Start(0)).map_err(|e| LogError::io("seek", &e))?;
        self.file
            .write_all(&header)
            .map_err(|e| LogError::io("write header", &e))?;
        self.file.sync_all().map_err(|e| LogError::io("sync header", &e))?;
        sync_parent(&self.path)?;
        Ok(())
    }

    fn write_slot(&mut self) -> Result<(), LogError> {
        let slot = Slot {
            generation: self.generation.saturating_add(1),
            committed_len: self.committed_len,
            head: self.head.hash,
        };
        let offset = if slot.generation.is_multiple_of(2) { SLOT_A } else { SLOT_B };
        self.file
            .seek(SeekFrom::Start(offset))
            .map_err(|e| LogError::io("seek", &e))?;
        self.file
            .write_all(&slot.encode())
            .map_err(|e| LogError::io("write header slot", &e))?;
        self.file
            .sync_data()
            .map_err(|e| LogError::io("sync header slot", &e))?;
        self.generation = slot.generation;
        Ok(())
    }

    fn append_inner(&mut self, record: &SignedRecord) -> Result<(), LogError> {
        if self.dirty_tail {
            self.file
                .set_len(self.committed_len)
                .map_err(|e| LogError::io("truncate unacknowledged tail", &e))?;
            self.dirty_tail = false;
        }
        let frame = record.to_frame();
        self.file
            .seek(SeekFrom::Start(self.committed_len))
            .map_err(|e| LogError::io("seek", &e))?;
        self.file
            .write_all(&frame)
            .map_err(|e| LogError::io("write record", &e))?;
        self.file.sync_data().map_err(|e| LogError::io("sync record", &e))?;
        let new_len = self
            .committed_len
            .checked_add(frame.len() as u64)
            .ok_or(LogError::TooLarge)?;
        let (old_len, old_head) = (self.committed_len, self.head);
        self.committed_len = new_len;
        self.head = Head {
            sequence: record.record().sequence,
            hash: *record.hash(),
        };
        if let Err(e) = self.write_slot() {
            self.committed_len = old_len;
            self.head = old_head;
            return Err(e);
        }
        self.records = self.records.saturating_add(1);
        Ok(())
    }
}

impl ReceiptLog for FileReceiptLog {
    fn kernel_id(&self) -> &str {
        &self.kernel_id
    }

    fn head(&self) -> Result<Head, LogError> {
        if self.poisoned {
            return Err(LogError::Poisoned);
        }
        Ok(self.head)
    }

    fn append(&mut self, record: &SignedRecord) -> Result<(), LogError> {
        if self.poisoned {
            return Err(LogError::Poisoned);
        }
        check_chains(record, &self.head, &self.kernel_id)?;
        if !self.keys.iter().any(|k| record.verify(k).is_ok()) {
            return Err(LogError::BadSignature);
        }
        let result = self.append_inner(record);
        if result.is_err() {
            // The on-disk state is unknown: refuse everything until an
            // operator reopens the log, which re-verifies it.
            self.poisoned = true;
        }
        result
    }

    fn is_durable(&self) -> bool {
        true
    }

    fn acknowledged_records(&self) -> Result<Vec<SignedRecord>, LogError> {
        if self.poisoned {
            return Err(LogError::Poisoned);
        }
        Ok(Self::read_file(&self.path)?.records)
    }
}

/// Makes a directory entry change durable.
fn sync_parent(path: &Path) -> Result<(), LogError> {
    let parent = match path.parent() {
        Some(p) if !p.as_os_str().is_empty() => p.to_path_buf(),
        _ => PathBuf::from("."),
    };
    File::open(&parent)
        .and_then(|d| d.sync_all())
        .map_err(|e| LogError::io("sync directory", &e))
}
