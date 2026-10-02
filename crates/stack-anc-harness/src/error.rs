//! Error type for the harness.

use thiserror::Error;

/// Everything that can go wrong in the harness. No variant carries caller
/// data, so an error message never echoes an input.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum HarnessError {
    /// A config field is outside its documented bounds. `field` names the
    /// field and `reason` says which bound it broke.
    #[error("invalid harness config: {field}: {reason}")]
    InvalidConfig {
        /// The offending field.
        field: &'static str,
        /// Which bound was broken.
        reason: &'static str,
    },
    /// The class and sample slices given to `analyze` differ in length.
    #[error("classes and samples differ in length")]
    LengthMismatch,
    /// The requested timer or OS facility is not available on this platform.
    #[error("unsupported on this platform: {0}")]
    Unsupported(&'static str),
    /// An OS call failed. Holds the raw errno.
    #[error("os call {call} failed with errno {errno}")]
    Os {
        /// The call that failed.
        call: &'static str,
        /// The raw OS error number.
        errno: i32,
    },
}
