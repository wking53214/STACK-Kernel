//! The issuance log (R-16): an append-only record of every capability issued,
//! separate from the kernel's receipt log.

use std::fmt;
use std::collections::{HashMap, HashSet};
use std::fs::{File, Metadata, OpenOptions, TryLockError};
use std::io::{BufRead, BufReader, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use serde_json::json;

/// Why a record was not written.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum LogError {
    /// The log cannot take the record.
    #[error("issuance log unavailable: {0}")]
    Unavailable(String),
    /// This decision root already has the most records allowed.
    #[error("decision issuance limit reached")]
    DecisionLimit,
}

/// What an issuance leaves behind. Enough to reconcile against the use store
/// and the kernel's receipt log (R-17): a capability that was used and has no
/// record here is a finding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IssuanceRecord {
    /// The capability id.
    pub cap_id: String,
    /// The capability digest, hex, over the whole wire form. Never truncated.
    pub capability_digest: String,
    /// The issuer's name in the kernel's trust set.
    pub issuer_id: String,
    /// The signing key's id, hex.
    pub key_id: String,
    /// Who asked, as the caller named them. Authenticating them is the
    /// caller's job.
    pub requester: String,
    /// The subject digest the issuer recomputed, hex.
    pub subject_digest: String,
    /// The decision root the issuer recomputed, hex.
    pub decision_root: String,
    /// The single operation granted.
    pub operation: String,
    /// The bound arguments digest, hex.
    pub args_digest: String,
    /// The bound worker label.
    pub worker: String,
    /// The bound limits digest, hex.
    pub limits_digest: String,
    /// The scopes granted, as `exact:<path>` or `prefix:<path>`.
    pub resources: Vec<String>,
    /// Start of the window.
    pub not_before_ms: u64,
    /// End of the window.
    pub expires_at_ms: u64,
    /// When it was issued, by the issuer's clock.
    pub issued_at_ms: u64,
    /// Always true for this issuer.
    pub one_time: bool,
    /// The policy reference written into the capability.
    pub policy_ref: String,
}

impl IssuanceRecord {
    /// One JSON object, one line.
    pub fn to_json_line(&self) -> String {
        json!({
            "cap_id": self.cap_id,
            "capability_digest": self.capability_digest,
            "issuer_id": self.issuer_id,
            "key_id": self.key_id,
            "requester": self.requester,
            "subject_digest": self.subject_digest,
            "decision_root": self.decision_root,
            "operation": self.operation,
            "args_digest": self.args_digest,
            "worker": self.worker,
            "limits_digest": self.limits_digest,
            "resources": self.resources,
            "not_before_ms": self.not_before_ms,
            "expires_at_ms": self.expires_at_ms,
            "issued_at_ms": self.issued_at_ms,
            "one_time": self.one_time,
            "policy_ref": self.policy_ref,
        })
        .to_string()
    }
}

/// Where issuance records go. The issuer calls `append` before it returns a
/// capability and returns none if `append` fails.
///
/// A record means "the issuer produced this capability", not "it was delivered":
/// the issuer returns the capability only after `append` succeeds, and the caller's
/// own later steps can still lose it. If the write reached the file but could not be
/// flushed, `append` reports an error, no capability is released, and the record may
/// still be counted after the log is next opened.
pub trait IssuanceLog: Send + Sync + fmt::Debug {
    /// Whether `append` is durable. The issuer refuses a log that says no, as
    /// the kernel refuses a store that is not durable.
    fn is_durable(&self) -> bool;
    /// How many records already carry this decision root. A non-binding read the
    /// issuer uses to refuse an exhausted decision before it asks the signer to
    /// sign; the binding check is `append`.
    fn issued_for_decision(&self, decision_root: &str) -> Result<u32, LogError>;
    /// Atomically: if fewer than `max_per_decision` records already carry this
    /// record's `decision_root`, durably records it; otherwise returns
    /// [`LogError::DecisionLimit`] and records nothing. Two concurrent calls on
    /// one log cannot both take the last slot. The guarantee covers the records
    /// this log knows about: a second log over the same storage, or records that
    /// were moved elsewhere, are not counted unless the implementation says so.
    fn append(&self, record: &IssuanceRecord, max_per_decision: u32) -> Result<(), LogError>;
}

/// The longest line `FileIssuanceLog` will read when it opens a file: 1 MiB. A record is
/// well under 10 KiB, so a longer line is damage or tampering. Opening streams the file
/// line by line, so memory is bounded by this and by the number of distinct decisions,
/// not by the size of the log.
pub const MAX_RECORD_LINE_BYTES: usize = 1 << 20;

/// A file of JSON lines, opened for append. Each record is flushed to stable storage
/// before `append` returns. A new file is created readable by its owner only (Unix;
/// an existing file keeps its mode).
///
/// * Opening takes an exclusive advisory lock (`File::try_lock`) held for the life of
///   the handle, so a second handle on the same file is refused. **The lock belongs to
///   the file, not to the path, and to the open file description, not to the process.**
///   Renaming, replacing or removing the file while it is open, or forking with the
///   handle open, defeats it; `append` therefore checks that the path still names the
///   file it holds and that the process is the one that opened it, and latches the
///   handle if not (Unix). The check is not atomic with the write. It does not help on
///   a network filesystem whose locks are client-local.
/// * Opening reads the file once, line by line. It refuses an unterminated last line
///   (a torn write: appending would fuse two records), an empty line, a line that is not
///   a record (a JSON object with a string `cap_id` and a 64-character lowercase hex
///   `decision_root`), invalid UTF-8, and a line over [`MAX_RECORD_LINE_BYTES`]. `append`
///   refuses to write a record that `open` would refuse.
/// * It refuses a symlink, a FIFO and a socket. `is_durable` is true only for a regular
///   file, so `Issuer::new` refuses a log on a device.
/// * The per-decision counts are rebuilt from the file. **Rotation resets them.** To
///   rotate without re-arming spent decisions, open the new file with
///   [`FileIssuanceLog::open_with_history`] and list every earlier segment. The old
///   issuer must be stopped first: history segments are read under a shared lock, so a
///   segment still held by a running issuer makes the open fail.
/// * Counts and open time grow with the number of distinct decision roots ever logged.
/// * After a failed write or flush the handle refuses every later append until it is
///   reopened after the log is repaired.
/// * It is not tamper-evident (no hash chain, no signature), and the directory entry is
///   not flushed.
pub struct FileIssuanceLog {
    inner: Mutex<FileInner>,
    durable: bool,
}

struct FileInner {
    file: File,
    path: PathBuf,
    pid: u32,
    ident: Option<(u64, u64)>,
    counts: HashMap<String, u32>,
    failed: bool,
}

impl fmt::Debug for FileIssuanceLog {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FileIssuanceLog").finish_non_exhaustive()
    }
}

fn is_lower_hex_64(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

/// The (device, inode) of a file, where the platform has them.
fn ident(meta: &Metadata) -> Option<(u64, u64)> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        Some((meta.dev(), meta.ino()))
    }
    #[cfg(not(unix))]
    {
        let _ = meta;
        None
    }
}

/// Counts the decisions in `reader`, line by line, adding to `counts`.
fn count_into(reader: impl Read, counts: &mut HashMap<String, u32>, name: &str) -> Result<(), LogError> {
    let bad = |msg: String| LogError::Unavailable(format!("{name}: {msg}"));
    let mut reader = BufReader::new(reader);
    let mut buf = Vec::new();
    let mut n = 0usize;
    loop {
        buf.clear();
        let got = reader
            .by_ref()
            .take(MAX_RECORD_LINE_BYTES as u64 + 1)
            .read_until(b'\n', &mut buf)
            .map_err(|e| bad(e.to_string()))?;
        if got == 0 {
            return Ok(());
        }
        n += 1;
        if buf.last() != Some(&b'\n') {
            return Err(if buf.len() > MAX_RECORD_LINE_BYTES {
                bad(format!("line {n} is longer than {MAX_RECORD_LINE_BYTES} bytes"))
            } else {
                bad(format!("line {n} is unterminated (torn write); repair the log first"))
            });
        }
        buf.pop();
        let line = std::str::from_utf8(&buf).map_err(|_| bad(format!("line {n} is not valid UTF-8")))?;
        let value: serde_json::Value =
            serde_json::from_str(line).map_err(|_| bad(format!("line {n} is not an issuance record")))?;
        let root = value
            .get("decision_root")
            .and_then(serde_json::Value::as_str)
            .filter(|r| is_lower_hex_64(r))
            .filter(|_| value.get("cap_id").is_some_and(serde_json::Value::is_string))
            .ok_or_else(|| bad(format!("line {n} is not an issuance record")))?;
        let c = counts.entry(root.to_owned()).or_insert(0);
        *c = c.saturating_add(1);
    }
}

fn unavailable(e: std::io::Error) -> LogError {
    LogError::Unavailable(e.to_string())
}

fn lock_error(e: TryLockError, what: &str) -> LogError {
    match e {
        TryLockError::WouldBlock => LogError::Unavailable(format!("{what} is in use by another handle or process")),
        TryLockError::Error(e) => unavailable(e),
    }
}

impl FileIssuanceLog {
    /// Opens or creates `path` for append, locks it, and counts what is in it.
    pub fn open(path: &Path) -> Result<Self, LogError> {
        Self::open_with_history(path, &[])
    }

    /// Like [`FileIssuanceLog::open`], and also counts the records in each earlier
    /// segment listed in `history`, so that rotating the log does not give a spent
    /// decision a fresh allowance. List every segment you have kept, once each. Every
    /// segment must be a regular file, must not be the live file, and must not be held
    /// by a running issuer (it is read under a shared lock). The segments are checked
    /// before the live file is created.
    pub fn open_with_history(path: &Path, history: &[&Path]) -> Result<Self, LogError> {
        let mut counts: HashMap<String, u32> = HashMap::new();
        let mut seen: HashSet<(u64, u64)> = HashSet::new();
        for segment in history {
            let name = segment.display().to_string();
            let f = File::open(segment).map_err(unavailable)?;
            let meta = f.metadata().map_err(unavailable)?;
            if !meta.is_file() {
                return Err(LogError::Unavailable(format!("{name}: a history segment must be a regular file")));
            }
            if let Some(id) = ident(&meta) {
                if !seen.insert(id) {
                    return Err(LogError::Unavailable(format!("{name}: listed twice (or the same file as another segment)")));
                }
            }
            f.try_lock_shared().map_err(|e| lock_error(e, &name))?;
            count_into(&f, &mut counts, &name)?;
        }

        if let Ok(meta) = std::fs::symlink_metadata(path) {
            #[cfg(unix)]
            let special = {
                use std::os::unix::fs::FileTypeExt;
                let t = meta.file_type();
                t.is_fifo() || t.is_socket()
            };
            #[cfg(not(unix))]
            let special = false;
            if meta.file_type().is_symlink() || special {
                return Err(LogError::Unavailable("the log path is a symlink, FIFO or socket".into()));
            }
        }
        let mut options = OpenOptions::new();
        options.create(true).append(true).read(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let file = options.open(path).map_err(unavailable)?;
        file.try_lock().map_err(|e| lock_error(e, "the log"))?;
        let meta = file.metadata().map_err(unavailable)?;
        let id = ident(&meta);
        if id.is_some_and(|id| seen.contains(&id)) {
            return Err(LogError::Unavailable("the live log is also listed as a history segment".into()));
        }
        // The same handle is read and then appended to, so the file counted is the file written.
        count_into(&file, &mut counts, &path.display().to_string())?;
        Ok(Self {
            inner: Mutex::new(FileInner {
                file,
                path: path.to_owned(),
                pid: std::process::id(),
                ident: id,
                counts,
                failed: false,
            }),
            durable: meta.is_file(),
        })
    }
}

impl IssuanceLog for FileIssuanceLog {
    fn is_durable(&self) -> bool {
        self.durable
    }

    fn issued_for_decision(&self, decision_root: &str) -> Result<u32, LogError> {
        let inner = self.inner.lock().map_err(|_| LogError::Unavailable("log lock poisoned".into()))?;
        Ok(inner.counts.get(decision_root).copied().unwrap_or(0))
    }

    fn append(&self, record: &IssuanceRecord, max_per_decision: u32) -> Result<(), LogError> {
        // Refuse a record `open` would refuse, before anything is written.
        let mut line = record.to_json_line();
        if !is_lower_hex_64(&record.decision_root) || line.len() > MAX_RECORD_LINE_BYTES {
            return Err(LogError::Unavailable("the record would not be readable when the log is reopened".into()));
        }
        line.push('\n');
        let mut inner = self.inner.lock().map_err(|_| LogError::Unavailable("log lock poisoned".into()))?;
        // Checked under the lock, so a thread that was waiting cannot write after another failed.
        if inner.failed {
            return Err(LogError::Unavailable("an earlier write failed; reopen after repairing the log".into()));
        }
        if inner.pid != std::process::id() {
            inner.failed = true;
            return Err(LogError::Unavailable("the log handle is being used by a forked process".into()));
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            let same = std::fs::metadata(&inner.path).is_ok_and(|m| ident(&m) == inner.ident && m.nlink() > 0);
            if !same {
                inner.failed = true;
                return Err(LogError::Unavailable("the log file was renamed, replaced or removed while open".into()));
            }
        }
        if inner.counts.get(&record.decision_root).copied().unwrap_or(0) >= max_per_decision {
            return Err(LogError::DecisionLimit);
        }
        if let Err(e) = inner.file.write_all(line.as_bytes()).and_then(|()| inner.file.sync_all()) {
            inner.failed = true;
            return Err(LogError::Unavailable(e.to_string()));
        }
        let c = inner.counts.entry(record.decision_root.clone()).or_insert(0);
        *c = c.saturating_add(1);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_handle_used_by_a_process_that_did_not_open_it_is_latched() {
        let dir = std::env::temp_dir().join(format!("stack-issuer-pid-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("issuance.jsonl");
        let _ = std::fs::remove_file(&path);
        let log = FileIssuanceLog::open(&path).unwrap();
        // Stand in for a forked child: the handle records the pid that opened it.
        log.inner.lock().unwrap().pid = std::process::id().wrapping_add(1);
        let record = IssuanceRecord {
            cap_id: "c".into(),
            capability_digest: String::new(),
            issuer_id: String::new(),
            key_id: String::new(),
            requester: String::new(),
            subject_digest: String::new(),
            decision_root: "ab".repeat(32),
            operation: String::new(),
            args_digest: String::new(),
            worker: String::new(),
            limits_digest: String::new(),
            resources: vec![],
            not_before_ms: 0,
            expires_at_ms: 0,
            issued_at_ms: 0,
            one_time: true,
            policy_ref: String::new(),
        };
        let e = log.append(&record, 5).unwrap_err().to_string();
        assert!(e.contains("forked"), "{e}");
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "");
        drop(log);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
