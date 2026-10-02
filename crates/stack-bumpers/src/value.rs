//! Input values, normalized values and corrections.

use crate::spec::UnitScale;

/// A raw parameter value as the caller sent it.
#[derive(Debug, Clone, PartialEq)]
pub enum ParamValue {
    /// A bare number, taken to be in the canonical unit.
    Number(f64),
    /// A number tagged with a unit name, for parameters that declare units.
    /// This is how "1500 ms" reaches a parameter declared in seconds. The
    /// bumper never guesses a unit from the size of a bare number.
    Quantity {
        /// The magnitude.
        value: f64,
        /// The unit name, matched exactly.
        unit: String,
    },
    /// Text, for enum and string parameters.
    Text(String),
}

/// A value after normalization.
#[derive(Debug, Clone, PartialEq)]
pub enum NormalizedValue {
    /// A finite number in the canonical unit, inside the soft band, never
    /// negative zero.
    Number(f64),
    /// The canonical name of an enum variant.
    Variant(String),
    /// A string that satisfies its spec.
    Text(String),
}

impl NormalizedValue {
    /// Convert back into an input value. Feeding the result into the same
    /// bumper yields the same value with no corrections (idempotence).
    #[must_use]
    pub fn to_param_value(&self) -> ParamValue {
        match self {
            Self::Number(x) => ParamValue::Number(*x),
            Self::Variant(s) | Self::Text(s) => ParamValue::Text(s.clone()),
        }
    }

    /// The number, if this is a numeric value.
    #[must_use]
    pub fn as_f64(&self) -> Option<f64> {
        match self {
            Self::Number(x) => Some(*x),
            Self::Variant(_) | Self::Text(_) => None,
        }
    }

    /// The text, if this is an enum or string value.
    #[must_use]
    pub fn as_str(&self) -> Option<&str> {
        match self {
            Self::Number(_) => None,
            Self::Variant(s) | Self::Text(s) => Some(s),
        }
    }
}

/// Which soft edge a clamp moved a value to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SoftEdge {
    /// Raised to `soft_min`.
    Min,
    /// Lowered to `soft_max`.
    Max,
}

/// What the bumper changed. Every variant carries only operator-declared
/// text (spec names) or numbers, never raw caller text.
#[derive(Debug, Clone, PartialEq)]
pub enum CorrectionKind {
    /// A number inside the hard band but outside the soft band was moved to
    /// the nearest soft edge.
    Clamped {
        /// The value before clamping, in the canonical unit.
        from: f64,
        /// The soft edge it was moved to.
        to: f64,
        /// Which edge.
        edge: SoftEdge,
    },
    /// A quantity in an alternate unit was converted to the canonical unit.
    UnitConverted {
        /// The declared alternate unit name.
        from_unit: String,
        /// The conversion applied.
        scale: UnitScale,
    },
    /// Leading or trailing whitespace was removed.
    Trimmed {
        /// How many bytes were removed.
        removed_bytes: usize,
    },
    /// Text matched a declared name only after ASCII case folding.
    CaseFolded,
    /// An alias was replaced by its canonical variant.
    AliasResolved {
        /// The declared alias that matched.
        alias: String,
        /// The canonical variant it maps to.
        canonical: String,
    },
}

impl CorrectionKind {
    /// Every label, for tests and for exporters that pre-register labels.
    pub const LABELS: [&'static str; 5] = ["clamped", "unit_converted", "trimmed", "case_folded", "alias_resolved"];

    /// The `kind` metric label.
    #[must_use]
    pub const fn label(&self) -> &'static str {
        match self {
            Self::Clamped { .. } => "clamped",
            Self::UnitConverted { .. } => "unit_converted",
            Self::Trimmed { .. } => "trimmed",
            Self::CaseFolded => "case_folded",
            Self::AliasResolved { .. } => "alias_resolved",
        }
    }
}

/// One change the bumper made to one parameter. Each change is its own
/// correction and each counts once against the budget, so `" HI "` resolved
/// through the alias `hi` costs three: trimmed, case folded, alias resolved.
#[derive(Debug, Clone, PartialEq)]
pub struct Correction {
    /// The spec name of the parameter.
    pub param: String,
    /// What changed.
    pub kind: CorrectionKind,
}
