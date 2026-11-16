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
    /// This subject already has the most records allowed.
    #[error("subject issuance limit reached")]
    SubjectLimit,
    /// The log already holds the most distinct decision roots allowed, and this one is new.
    #[error("distinct decision limit reached")]
    DistinctDecisionsLimit,
    /// A reset was not well formed (bad root, operator or reason).
    #[error("the reset is not well formed")]
    BadReset,
    /// A reset named a decision that has nothing to reset.
    #[error("the decision has no issuances to reset")]
    NothingToReset,
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

/// The limits an append enforces, atomically with the write. All three are required.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AppendLimits {
    /// The most records one decision root may have.
    pub per_decision: u32,
    /// The most records one subject digest may have, across all its decision roots.
    pub per_subject: u32,
    /// The most distinct decision roots the log may hold.
    pub distinct_decisions: u32,
}

/// What the log already holds for a request, read before signing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Usage {
    /// Records counted against the decision root.
    pub decision: u32,
    /// Whether the decision root is already in the log (a reset root still is).
    pub decision_known: bool,
    /// Records counted against the subject digest.
    pub subject: u32,
    /// Distinct decision roots in the log.
    pub distinct_decisions: u32,
}

/// An operator's deliberate re-allowance of one decision root, written into the log.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResetRecord {
    /// The decision root to re-allow, 64 lowercase hex characters.
    pub decision_root: String,
    /// Who did it, as the caller named them. 1 to 128 bytes, no control character.
    pub operator: String,
    /// Why. 1 to 512 bytes, no control character.
    pub reason: String,
    /// When, by the issuer's clock.
    pub reset_at_ms: u64,
}

impl ResetRecord {
    fn valid(&self) -> bool {
        let text = |s: &str, max: usize| !s.is_empty() && s.len() <= max && !s.chars().any(char::is_control);
        is_lower_hex_64(&self.decision_root) && text(&self.operator, 128) && text(&self.reason, 512)
    }

    /// One JSON object, one line. The `reset` key tells it from an issuance record.
    pub fn to_json_line(&self) -> String {
        json!({
            "reset": true,
            "decision_root": self.decision_root,
            "operator": self.operator,
            "reason": self.reason,
            "reset_at_ms": self.reset_at_ms,
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
    /// What the log holds for this decision root and subject. A non-binding read the
    /// issuer uses to refuse an exhausted request before it asks the signer to sign; the
    /// binding check is `append`.
    fn usage(&self, decision_root: &str, subject_digest: &str) -> Result<Usage, LogError>;
    /// Atomically: check `limits` against the log, and if every one holds, durably record
    /// `record`; otherwise return the matching limit error and record nothing. Two
    /// concurrent calls on one log cannot both take the last slot. The guarantee covers the
    /// records this log knows about: a second log over the same storage, or records that
    /// were moved elsewhere, are not counted unless the implementation says so.
    fn append(&self, record: &IssuanceRecord, limits: &AppendLimits) -> Result<(), LogError>;
    /// Durably records a reset and sets the decision root's count back to zero, subtracting
    /// what it had from its subject's count. Returns the count it had. Fails with
    /// [`LogError::NothingToReset`] if the root is unknown or already at zero.
    fn reset_decision(&self, reset: &ResetRecord) -> Result<u32, LogError>;
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
///   (a torn write: appending would fuse two records), an empty line, a line that is neither
///   an issuance record (a JSON object with a string `cap_id` and 64-character lowercase hex
///   `decision_root` and `subject_digest`) nor a reset record, invalid UTF-8, a line over
///   [`MAX_RECORD_LINE_BYTES`], and a reset of a decision that has no issuances. `append`
///   refuses to write a record that `open` would refuse.
/// * It refuses a symlink, a FIFO and a socket. `is_durable` is true only for a regular
///   file, so `Issuer::new` refuses a log on a device.
/// * The counts are rebuilt from the file. **Rotation resets them.** To rotate without
///   re-arming spent decisions, open the new file with
///   [`FileIssuanceLog::open_with_history`] and list every earlier segment, **oldest
///   first** (a reset in a later segment applies to the records before it). The old
///   issuer must be stopped first: history segments are read under a shared lock, so a
///   segment still held by a running issuer makes the open fail.
/// * Memory and open time grow with the number of distinct decision roots, which the
///   `distinct_decisions` limit bounds for new roots.
/// * After a failed write or flush the handle refuses every later append until it is
///   reopened after the log is repaired.
/// * It is not tamper-evident (no hash chain, no signature), and the directory entry is
///   not flushed.
pub struct FileIssuanceLog {
    inner: Mutex<FileInner>,
    durable: bool,
}

#[derive(Default)]
struct Tally {
    /// Per decision root: how many records, and the subject they were issued for.
    roots: HashMap<String, (u32, String)>,
    /// Per subject: how many records, across its decision roots.
    subjects: HashMap<String, u32>,
}

impl Tally {
    fn issue(&mut self, root: &str, subject: &str) {
        let entry = self.roots.entry(root.to_owned()).or_insert_with(|| (0, subject.to_owned()));
        entry.0 = entry.0.saturating_add(1);
        let s = self.subjects.entry(subject.to_owned()).or_insert(0);
        *s = s.saturating_add(1);
    }

    /// The count a reset would clear, or `None` if there is nothing to reset.
    fn resettable(&self, root: &str) -> Option<u32> {
        self.roots.get(root).map(|(n, _)| *n).filter(|n| *n > 0)
    }

    fn reset(&mut self, root: &str) -> Option<u32> {
        let (n, subject) = self.roots.get_mut(root).map(|(n, s)| (std::mem::take(n), s.clone()))?;
        if n == 0 {
            return None;
        }
        if let Some(s) = self.subjects.get_mut(&subject) {
            *s = s.saturating_sub(n);
        }
        Some(n)
    }
}

struct FileInner {
    file: File,
    path: PathBuf,
    pid: u32,
    ident: Option<(u64, u64)>,
    tally: Tally,
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

/// Reads `reader` line by line into `tally`.
fn count_into(reader: impl Read, tally: &mut Tally, name: &str) -> Result<(), LogError> {
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
        let text = |key: &str| value.get(key).and_then(serde_json::Value::as_str);
        let hex64 = |key: &str| text(key).filter(|r| is_lower_hex_64(r));
        if value.get("reset").is_some() {
            let ok = value.get("reset") == Some(&serde_json::Value::Bool(true))
                && text("operator").is_some()
                && text("reason").is_some()
                && value.get("reset_at_ms").is_some_and(serde_json::Value::is_u64);
            let root = hex64("decision_root").filter(|_| ok).ok_or_else(|| bad(format!("line {n} is not a reset record")))?;
            tally.reset(root).ok_or_else(|| bad(format!("line {n} resets a decision that has no issuances")))?;
            continue;
        }
        let (root, subject) = hex64("decision_root")
            .zip(hex64("subject_digest"))
            .filter(|_| text("cap_id").is_some())
            .ok_or_else(|| bad(format!("line {n} is not an issuance record")))?;
        tally.issue(root, subject);
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
    /// decision a fresh allowance. List every segment you have kept, once each, **oldest
    /// first**. Every segment must be a regular file, must not be the live file, and must
    /// not be held by a running issuer (it is read under a shared lock). The segments are
    /// checked before the live file is created.
    pub fn open_with_history(path: &Path, history: &[&Path]) -> Result<Self, LogError> {
        let mut tally = Tally::default();
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
            count_into(&f, &mut tally, &name)?;
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
        count_into(&file, &mut tally, &path.display().to_string())?;
        Ok(Self {
            inner: Mutex::new(FileInner {
                file,
                path: path.to_owned(),
                pid: std::process::id(),
                ident: id,
                tally,
                failed: false,
            }),
            durable: meta.is_file(),
        })
    }
}

impl FileInner {
    /// The checks every write makes first: not latched, same process, same file.
    fn ready(&mut self) -> Result<(), LogError> {
        // Checked under the lock, so a thread that was waiting cannot write after another failed.
        if self.failed {
            return Err(LogError::Unavailable("an earlier write failed; reopen after repairing the log".into()));
        }
        if self.pid != std::process::id() {
            self.failed = true;
            return Err(LogError::Unavailable("the log handle is being used by a forked process".into()));
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            let same = std::fs::metadata(&self.path).is_ok_and(|m| ident(&m) == self.ident && m.nlink() > 0);
            if !same {
                self.failed = true;
                return Err(LogError::Unavailable("the log file was renamed, replaced or removed while open".into()));
            }
        }
        Ok(())
    }

    fn write_line(&mut self, mut line: String) -> Result<(), LogError> {
        line.push('\n');
        if let Err(e) = self.file.write_all(line.as_bytes()).and_then(|()| self.file.sync_all()) {
            self.failed = true;
            return Err(LogError::Unavailable(e.to_string()));
        }
        Ok(())
    }
}

impl IssuanceLog for FileIssuanceLog {
    fn is_durable(&self) -> bool {
        self.durable
    }

    fn usage(&self, decision_root: &str, subject_digest: &str) -> Result<Usage, LogError> {
        let inner = self.inner.lock().map_err(|_| LogError::Unavailable("log lock poisoned".into()))?;
        let known = inner.tally.roots.get(decision_root);
        Ok(Usage {
            decision: known.map_or(0, |(n, _)| *n),
            decision_known: known.is_some(),
            subject: inner.tally.subjects.get(subject_digest).copied().unwrap_or(0),
            distinct_decisions: u32::try_from(inner.tally.roots.len()).unwrap_or(u32::MAX),
        })
    }

    fn append(&self, record: &IssuanceRecord, limits: &AppendLimits) -> Result<(), LogError> {
        // Refuse a record `open` would refuse, before anything is written.
        let line = record.to_json_line();
        if !is_lower_hex_64(&record.decision_root) || !is_lower_hex_64(&record.subject_digest) || line.len() > MAX_RECORD_LINE_BYTES {
            return Err(LogError::Unavailable("the record would not be readable when the log is reopened".into()));
        }
        let mut inner = self.inner.lock().map_err(|_| LogError::Unavailable("log lock poisoned".into()))?;
        inner.ready()?;
        let known = inner.tally.roots.get(&record.decision_root).map(|(n, _)| *n);
        if known.unwrap_or(0) >= limits.per_decision {
            return Err(LogError::DecisionLimit);
        }
        if inner.tally.subjects.get(&record.subject_digest).copied().unwrap_or(0) >= limits.per_subject {
            return Err(LogError::SubjectLimit);
        }
        if known.is_none() && inner.tally.roots.len() >= limits.distinct_decisions as usize {
            return Err(LogError::DistinctDecisionsLimit);
        }
        inner.write_line(line)?;
        inner.tally.issue(&record.decision_root, &record.subject_digest);
        Ok(())
    }

    fn reset_decision(&self, reset: &ResetRecord) -> Result<u32, LogError> {
        if !reset.valid() {
            return Err(LogError::BadReset);
        }
        let mut inner = self.inner.lock().map_err(|_| LogError::Unavailable("log lock poisoned".into()))?;
        inner.ready()?;
        if inner.tally.resettable(&reset.decision_root).is_none() {
            return Err(LogError::NothingToReset);
        }
        inner.write_line(reset.to_json_line())?;
        inner.tally.reset(&reset.decision_root).ok_or(LogError::NothingToReset)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn limits(n: u32) -> AppendLimits {
        AppendLimits { per_decision: n, per_subject: 1000, distinct_decisions: 1000 }
    }

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
            subject_digest: "cd".repeat(32),
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
        let e = log.append(&record, &limits(5)).unwrap_err().to_string();
        assert!(e.contains("forked"), "{e}");
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "");
        drop(log);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
