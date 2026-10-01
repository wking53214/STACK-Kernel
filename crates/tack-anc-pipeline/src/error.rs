//! Configuration errors. These happen when a gate is built, never on the
//! request path.

use thiserror::Error;

/// Why a gate or secret could not be built.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum ConfigError {
    /// A config field is out of bounds.
    #[error("invalid config: {field} {reason}")]
    Invalid {
        /// The field.
        field: &'static str,
        /// What is wrong with it.
        reason: &'static str,
    },
    /// A leaky validator was chosen without `allow_leaky_validators`.
    #[error("leaky validator requires allow_leaky_validators")]
    LeakyValidator,
    /// The secret is not exactly `TOKEN_LEN` bytes.
    #[error("secret must be exactly TOKEN_LEN bytes")]
    SecretLength,
    /// The secret is all zeros, the usual shape of an unset default.
    #[error("secret is all zeros")]
    SecretAllZero,
}
