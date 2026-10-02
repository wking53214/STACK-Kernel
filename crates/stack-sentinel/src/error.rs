//! Inputs the verifier refuses before it can reach a verdict.

use crate::attest::KeyError;
use crate::pyjson::JsonError;
use crate::verdict::{GateOutcome, Resolution};

/// The export or the key material could not be used, so no verdict was
/// reached. The Python tool behaves the same way for these inputs: it exits
/// without printing a verdict (exit 1 for a bad export, exit 2 for no
/// trusted key).
///
/// Every variant is CNS `RETRY` with resolution **reject**: nothing was
/// read into any state, and a well-formed export or the right key file,
/// resubmitted, can be verified. None is ever `PASS`.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum VerifyError {
    /// The export is larger than `VerifierConfig::max_export_bytes`.
    #[error("export is {len} bytes, over the {max} byte cap")]
    ExportTooLarge {
        /// Size of the export.
        len: usize,
        /// The cap.
        max: usize,
    },
    /// The export is not JSON Python would read, or breaks a parse cap
    /// (nesting, integer length, or the allocation budget).
    #[error("export is not readable JSON: {0}")]
    ExportNotJson(JsonError),
    /// The export is not a `sentinel_os.ledger_export.v1` object.
    #[error("not a sentinel_os.ledger_export.v1 export")]
    NotAnExport,
    /// The export carries no `rows` list.
    #[error("export carries no rows list")]
    RowsMissing,
    /// A row is not a JSON object.
    #[error("row at position {position} is not an object")]
    RowNotAnObject {
        /// Position of the row in the file.
        position: usize,
    },
    /// A row's `id` is missing or not an integer that fits in 64 bits.
    #[error("row at position {position} has no integer id")]
    RowIdInvalid {
        /// Position of the row in the file.
        position: usize,
    },
    /// More rows than `VerifierConfig::max_rows`.
    #[error("export has {len} rows, over the cap of {max}")]
    TooManyRows {
        /// Number of rows.
        len: usize,
        /// The cap.
        max: usize,
    },
    /// No held key matches a trusted fingerprint. The Python tool refuses
    /// to print a verdict it could not have checked, and so does this one.
    #[error("no trusted key material: refusing to print a verdict that could not be checked")]
    NoTrustedKeyMaterial,
    /// A key or key file was refused.
    #[error("key material refused: {0}")]
    Key(KeyError),
    /// Checking every seed and signature would feed more bytes to
    /// HMAC-SHA256 than `VerifierConfig::max_keyed_bytes` allows. Refused
    /// before any row is checked.
    #[error("export needs {needed} bytes of keyed work, over the {max} byte budget")]
    KeyedWorkOverBudget {
        /// The upper bound on keyed bytes this export needs.
        needed: usize,
        /// The budget.
        max: usize,
    },
}

impl VerifyError {
    /// Closed metric label.
    pub fn label(&self) -> &'static str {
        match self {
            VerifyError::ExportTooLarge { .. } => "export_too_large",
            VerifyError::ExportNotJson(_) => "export_not_json",
            VerifyError::NotAnExport => "not_an_export",
            VerifyError::RowsMissing => "rows_missing",
            VerifyError::RowNotAnObject { .. } => "row_not_an_object",
            VerifyError::RowIdInvalid { .. } => "row_id_invalid",
            VerifyError::TooManyRows { .. } => "too_many_rows",
            VerifyError::NoTrustedKeyMaterial => "no_trusted_key_material",
            VerifyError::Key(_) => "key_refused",
            VerifyError::KeyedWorkOverBudget { .. } => "keyed_work_over_budget",
        }
    }

    /// Always `RETRY`.
    pub fn gate_outcome(&self) -> GateOutcome {
        GateOutcome::Retry
    }

    /// Always reject.
    pub fn resolution(&self) -> Resolution {
        Resolution::Reject
    }
}
