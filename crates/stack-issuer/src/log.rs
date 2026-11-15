//! The issuance log (R-16): an append-only record of every capability issued,
//! separate from the kernel's receipt log.

use std::fmt;
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::Path;
use std::sync::Mutex;

use serde_json::json;

/// Why a record was not written.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum LogError {
    /// The log cannot take the record.
    #[error("issuance log unavailable: {0}")]
    Unavailable(String),
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
pub trait IssuanceLog: Send + Sync + fmt::Debug {
    /// Durably records `record`, or fails.
    fn append(&self, record: &IssuanceRecord) -> Result<(), LogError>;
}

/// A file of JSON lines, opened for append only. Each record is flushed to
/// stable storage before `append` returns. It is not tamper-evident (no hash
/// chain, no signature) and it takes no lock, so one issuer process per file.
#[derive(Debug)]
pub struct FileIssuanceLog {
    file: Mutex<File>,
}

impl FileIssuanceLog {
    /// Opens or creates `path` for append.
    pub fn open(path: &Path) -> Result<Self, LogError> {
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .map_err(|e| LogError::Unavailable(e.to_string()))?;
        Ok(Self { file: Mutex::new(file) })
    }
}

impl IssuanceLog for FileIssuanceLog {
    fn append(&self, record: &IssuanceRecord) -> Result<(), LogError> {
        let mut line = record.to_json_line();
        line.push('\n');
        let mut file = self.file.lock().map_err(|_| LogError::Unavailable("log lock poisoned".into()))?;
        file.write_all(line.as_bytes())
            .and_then(|()| file.sync_all())
            .map_err(|e| LogError::Unavailable(e.to_string()))
    }
}
