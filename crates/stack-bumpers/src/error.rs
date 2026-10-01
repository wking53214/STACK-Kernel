//! Typed failures: spec construction errors and request rejections.

use crate::outcome::{GateOutcome, Resolution};

/// A spec or configuration that cannot be built. These are operator errors
/// found at startup, never request-time verdicts.
#[derive(Debug, Clone, PartialEq, thiserror::Error)]
pub enum SpecError {
    /// A numeric bound is NaN or infinite.
    #[error("numeric bound is NaN or infinite")]
    NonFiniteBound,
    /// Bounds are not ordered `hard_min <= soft_min <= soft_max <= hard_max`.
    #[error("bounds must satisfy hard_min <= soft_min <= soft_max <= hard_max")]
    BandOrder,
    /// An enum spec with no variants.
    #[error("enum spec has no variants")]
    EmptyEnum,
    /// A declared name is empty.
    #[error("a declared name is empty")]
    EmptyName,
    /// A declared name has leading or trailing whitespace.
    #[error("declared name {name:?} has leading or trailing whitespace")]
    UntrimmedName {
        /// The offending name.
        name: String,
    },
    /// Two enum names are equal after ASCII case folding.
    #[error("enum names {first:?} and {second:?} collide under ASCII case folding")]
    AliasCollision {
        /// The name declared first.
        first: String,
        /// The name that collided with it.
        second: String,
    },
    /// A unit scale factor that is not finite, positive and normal.
    #[error("unit {unit:?} has a scale factor that is not finite, positive and normal")]
    InvalidUnitScale {
        /// The unit name.
        unit: String,
    },
    /// A unit name declared twice.
    #[error("unit {unit:?} is declared twice")]
    DuplicateUnit {
        /// The unit name.
        unit: String,
    },
    /// A string spec with `max_len == 0`.
    #[error("string max_len must be greater than zero")]
    ZeroMaxLen,
    /// A string spec whose `min_len` exceeds its `max_len`, so no value
    /// could ever pass.
    #[error("string min_len {min_len} exceeds max_len {max_len}")]
    MinLenAboveMaxLen {
        /// The requested minimum.
        min_len: usize,
        /// The spec's maximum.
        max_len: usize,
    },
    /// Two parameter specs share a name.
    #[error("parameter {name:?} is declared twice")]
    DuplicateParam {
        /// The parameter name.
        name: String,
    },
    /// A declared name longer than `BumperConfig::max_name_bytes`.
    #[error("declared name of {len} bytes exceeds max_name_bytes {max}")]
    NameTooLong {
        /// Its length in bytes.
        len: usize,
        /// The cap.
        max: usize,
    },
    /// More parameter specs than `BumperConfig::max_params`.
    #[error("more than max_params {max} parameter specs")]
    TooManyParams {
        /// The cap.
        max: usize,
    },
    /// An enum with more names than `BumperConfig::max_enum_names`.
    #[error("enum parameter {param:?} declares {count} names, over max_enum_names {max}")]
    TooManyEnumNames {
        /// The parameter name.
        param: String,
        /// Names declared.
        count: usize,
        /// The cap.
        max: usize,
    },
    /// A numeric spec with more units than `BumperConfig::max_units`.
    #[error("numeric parameter {param:?} declares {count} units, over max_units {max}")]
    TooManyUnits {
        /// The parameter name.
        param: String,
        /// Units declared.
        count: usize,
        /// The cap.
        max: usize,
    },
    /// A string spec whose `max_len` exceeds `BumperConfig::max_input_bytes`,
    /// which would make part of its declared range unreachable.
    #[error("string parameter {param:?} max_len {max_len} exceeds max_input_bytes {cap}")]
    StringCapAboveInputCap {
        /// The parameter name.
        param: String,
        /// The spec's cap.
        max_len: usize,
        /// The global input cap.
        cap: usize,
    },
    /// A configuration value outside its allowed range.
    #[error("invalid bumper config: {0}")]
    InvalidConfig(&'static str),
}

/// Why a request tripped. A closed set, so it is safe as a metric label.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum TripReason {
    /// A number was NaN or infinite. Never clamped. This is reported for a
    /// non-finite `Number` or `Quantity` value under any key, declared or
    /// not and whatever the parameter's shape, before any type check.
    NonFinite,
    /// A number was outside the hard band, after any unit conversion.
    OutsideHardBand,
    /// A text value, unit name or unknown key exceeded
    /// `BumperConfig::max_input_bytes`. This includes a text value or unit
    /// name carried under an unknown key.
    InputTooLarge,
    /// The request carried more than `BumperConfig::max_params` entries.
    TooManyParams,
    /// A key that no spec declares.
    UnknownParam,
    /// A required parameter was absent.
    MissingRequired,
    /// The value had the wrong shape (text for a number, and so on).
    TypeMismatch,
    /// Text that matches no variant or alias, even after trim and fold.
    UnknownVariant,
    /// A quantity whose unit the spec does not declare.
    UnknownUnit,
    /// Text longer than the spec's `max_len` after the trim policy.
    TooLong,
    /// Text shorter than the spec's `min_len` after the trim policy. With
    /// the default `min_len` of 1 this is an empty or whitespace-only value,
    /// which would otherwise satisfy a required parameter while carrying
    /// nothing.
    TooShort,
    /// Surrounding whitespace on a `TrimPolicy::Reject` parameter.
    WhitespaceRejected,
    /// A control, format, line separator or paragraph separator character
    /// (Unicode categories Cc, Cf, Zl, Zp) in a string whose
    /// `CharPolicy` refuses them.
    DisallowedChar,
    /// More corrections than `BumperConfig::correction_budget`.
    CorrectionBudgetExceeded,
}

impl TripReason {
    /// Every reason, for tests and for exporters that pre-register labels.
    pub const ALL: [Self; 14] = [
        Self::NonFinite,
        Self::OutsideHardBand,
        Self::InputTooLarge,
        Self::TooManyParams,
        Self::UnknownParam,
        Self::MissingRequired,
        Self::TypeMismatch,
        Self::UnknownVariant,
        Self::UnknownUnit,
        Self::TooLong,
        Self::TooShort,
        Self::WhitespaceRejected,
        Self::DisallowedChar,
        Self::CorrectionBudgetExceeded,
    ];

    /// The `reason` metric label.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::NonFinite => "non_finite",
            Self::OutsideHardBand => "outside_hard_band",
            Self::InputTooLarge => "input_too_large",
            Self::TooManyParams => "too_many_params",
            Self::UnknownParam => "unknown_param",
            Self::MissingRequired => "missing_required",
            Self::TypeMismatch => "type_mismatch",
            Self::UnknownVariant => "unknown_variant",
            Self::UnknownUnit => "unknown_unit",
            Self::TooLong => "too_long",
            Self::TooShort => "too_short",
            Self::WhitespaceRejected => "whitespace_rejected",
            Self::DisallowedChar => "disallowed_char",
            Self::CorrectionBudgetExceeded => "correction_budget_exceeded",
        }
    }

    /// The fixed CNS outcome for this reason.
    ///
    /// TERMINAL_BREACH is kept for inputs that no honest drift produces: a
    /// value that is not a number, a value past the physical limits the
    /// operator declared, or a request past the global size caps, which sit
    /// far above anything a spec allows. Everything else is RETRY because
    /// the caller can see what to change and change it.
    #[must_use]
    pub const fn outcome(self) -> GateOutcome {
        match self {
            Self::NonFinite | Self::OutsideHardBand | Self::InputTooLarge | Self::TooManyParams => {
                GateOutcome::TerminalBreach
            }
            Self::UnknownParam
            | Self::MissingRequired
            | Self::TypeMismatch
            | Self::UnknownVariant
            | Self::UnknownUnit
            | Self::TooLong
            | Self::TooShort
            | Self::WhitespaceRejected
            | Self::DisallowedChar
            | Self::CorrectionBudgetExceeded => GateOutcome::Retry,
        }
    }
}

/// Which parameter a trip is about.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TripParam {
    /// A declared parameter, by its spec name (operator-controlled text).
    Named(String),
    /// A key no spec declares, no longer than
    /// `BumperConfig::max_input_bytes`. The raw key is never echoed. Its
    /// byte length and full SHA-256 hex digest identify it for audit
    /// correlation.
    Unknown {
        /// Key length in bytes.
        len: usize,
        /// Full lowercase SHA-256 hex digest of the key bytes (64 chars).
        sha256: String,
    },
    /// A key no spec declares that is longer than
    /// `BumperConfig::max_input_bytes`. Only its length is recorded: hashing
    /// it would make refusal work grow with the attacker's size instead of
    /// staying bounded by the cap, and a digest of a prefix would be a
    /// digest of a different value.
    UnknownOverCap {
        /// Key length in bytes.
        len: usize,
    },
    /// The request as a whole (size caps, correction budget).
    Request,
}

/// One reason a request was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Trip {
    /// What the trip is about.
    pub param: TripParam,
    /// Why.
    pub reason: TripReason,
}

/// A refused request. Nothing was changed.
///
/// `trips` lists every problem found, not only the first, so a caller can
/// fix them all in one resubmission. Its length is bounded by
/// `max_params + number of specs + 1`.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("bumpers refused the request: {} with {} trip(s)", .outcome.as_str(), .trips.len())]
pub struct Rejection {
    /// RETRY or TERMINAL_BREACH, never PASS. The most severe trip decides.
    pub outcome: GateOutcome,
    /// Always [`Resolution::Reject`] for this component.
    pub resolution: Resolution,
    /// Every trip found, in request key order then spec order.
    pub trips: Vec<Trip>,
}

impl Rejection {
    /// True when any trip has the given reason.
    #[must_use]
    pub fn has(&self, reason: TripReason) -> bool {
        self.trips.iter().any(|t| t.reason == reason)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn labels_are_unique_snake_case() {
        let mut seen = std::collections::BTreeSet::new();
        for r in TripReason::ALL {
            let s = r.as_str();
            assert!(s.chars().all(|c| c.is_ascii_lowercase() || c == '_'));
            assert!(seen.insert(s), "duplicate label {s}");
        }
    }

    #[test]
    fn no_reason_maps_to_pass() {
        for r in TripReason::ALL {
            assert_ne!(r.outcome(), GateOutcome::Pass, "{r:?} fails open");
        }
    }
}
