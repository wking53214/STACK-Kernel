//! Declarative parameter specifications.
//!
//! A [`ParamSpec`] says what one parameter may look like and how much drift
//! the bumper may absorb for it. Specs are written by the operator, not by
//! the caller, so they are trusted configuration. They are still checked
//! when they are built, because a spec with overlapping aliases or an
//! inverted band would make the bumper's behaviour ambiguous, and an
//! ambiguous rule is a rule an attacker gets to pick.

use std::collections::BTreeMap;

use crate::error::SpecError;

/// Whether a parameter must be present in every request.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Presence {
    /// Absence is RETRY with reason `missing_required`.
    Required,
    /// Absence is allowed. The bumper never invents a default: an absent
    /// optional parameter is absent from the output too.
    Optional,
}

/// The rule for one named parameter.
#[derive(Debug, Clone, PartialEq)]
pub struct ParamSpec {
    name: String,
    presence: Presence,
    kind: SpecKind,
}

impl ParamSpec {
    /// A parameter with an explicit presence rule.
    pub fn new(name: impl Into<String>, presence: Presence, kind: SpecKind) -> Self {
        Self {
            name: name.into(),
            presence,
            kind,
        }
    }

    /// A required parameter.
    pub fn required(name: impl Into<String>, kind: impl Into<SpecKind>) -> Self {
        Self::new(name, Presence::Required, kind.into())
    }

    /// An optional parameter.
    pub fn optional(name: impl Into<String>, kind: impl Into<SpecKind>) -> Self {
        Self::new(name, Presence::Optional, kind.into())
    }

    /// The parameter name. Request keys must match it exactly.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Whether the parameter is required.
    #[must_use]
    pub fn presence(&self) -> Presence {
        self.presence
    }

    /// The type-specific rule.
    #[must_use]
    pub fn kind(&self) -> &SpecKind {
        &self.kind
    }
}

/// The three parameter shapes the bumper understands.
#[derive(Debug, Clone, PartialEq)]
pub enum SpecKind {
    /// A floating point value with a soft band inside a hard band.
    Numeric(NumericSpec),
    /// One of a closed set of names, with accepted aliases.
    Enum(EnumSpec),
    /// Free text with a length cap and a whitespace policy.
    Text(StringSpec),
}

impl From<NumericSpec> for SpecKind {
    fn from(s: NumericSpec) -> Self {
        Self::Numeric(s)
    }
}

impl From<EnumSpec> for SpecKind {
    fn from(s: EnumSpec) -> Self {
        Self::Enum(s)
    }
}

impl From<StringSpec> for SpecKind {
    fn from(s: StringSpec) -> Self {
        Self::Text(s)
    }
}

// ---------------------------------------------------------------------------
// Numeric
// ---------------------------------------------------------------------------

/// How an alternate unit converts into the canonical unit.
///
/// Two forms exist so that the common cases convert without an extra
/// rounding step. Milliseconds to seconds is `Divide(1000.0)`, which gives
/// the correctly rounded quotient (1500 / 1000 is exactly 1.5).
/// `Multiply(0.001)` would multiply by a constant that is not exactly one
/// thousandth in binary and could land one unit in the last place away.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum UnitScale {
    /// canonical = value * factor
    Multiply(f64),
    /// canonical = value / divisor
    Divide(f64),
}

impl UnitScale {
    /// Convert a value in this unit into the canonical unit.
    ///
    /// The factor is checked at construction to be finite, positive and
    /// normal, so the result of a finite input is finite or an overflow to
    /// infinity, never NaN. The caller checks the result against the hard
    /// band, which catches the overflow.
    #[must_use]
    pub fn apply(self, value: f64) -> f64 {
        match self {
            Self::Multiply(f) => value * f,
            Self::Divide(d) => value / d,
        }
    }

    fn factor(self) -> f64 {
        match self {
            Self::Multiply(f) | Self::Divide(f) => f,
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
struct UnitTable {
    canonical: String,
    alternates: Vec<(String, UnitScale)>,
}

/// The outcome of looking up a unit name.
#[derive(Debug, Clone, Copy, PartialEq)]
pub(crate) enum UnitMatch<'a> {
    Canonical,
    Alternate(&'a str, UnitScale),
}

/// A numeric parameter: a soft band inside a hard band, optionally with
/// declared units.
///
/// ```text
///   hard_min      soft_min                 soft_max      hard_max
///      |-------------|========================|-------------|
///      ^ TERMINAL    ^ clamp up to here       ^ clamp down  ^ TERMINAL
///        below                                  to here       above
/// ```
///
/// A value inside the soft band passes unchanged. A value inside the hard
/// band but outside the soft band is clamped to the nearest soft edge and
/// the clamp is recorded as a correction. A value outside the hard band is
/// TERMINAL_BREACH: it is not drift, it is a truck hitting the concrete.
#[derive(Debug, Clone, PartialEq)]
pub struct NumericSpec {
    hard_min: f64,
    soft_min: f64,
    soft_max: f64,
    hard_max: f64,
    units: Option<UnitTable>,
}

/// Turn negative zero into positive zero and leave every other value alone.
///
/// `-0.0 == 0.0` in IEEE 754, so this never changes a value, only its bit
/// pattern. It makes output bits deterministic, which matters for anything
/// that hashes the normalized parameters.
#[must_use]
pub(crate) fn canonical_zero(x: f64) -> f64 {
    if x == 0.0 {
        0.0
    } else {
        x
    }
}

impl NumericSpec {
    /// Build a spec from its four bounds.
    ///
    /// # Errors
    ///
    /// [`SpecError::NonFiniteBound`] if any bound is NaN or infinite, and
    /// [`SpecError::BandOrder`] unless
    /// `hard_min <= soft_min <= soft_max <= hard_max`. Equal bounds are
    /// allowed: `soft_min == hard_min` means there is no elastic room below,
    /// and `soft_min == soft_max` pins the value.
    pub fn new(hard_min: f64, soft_min: f64, soft_max: f64, hard_max: f64) -> Result<Self, SpecError> {
        let bounds = [hard_min, soft_min, soft_max, hard_max];
        if bounds.iter().any(|b| !b.is_finite()) {
            return Err(SpecError::NonFiniteBound);
        }
        if !(hard_min <= soft_min && soft_min <= soft_max && soft_max <= hard_max) {
            return Err(SpecError::BandOrder);
        }
        Ok(Self {
            hard_min: canonical_zero(hard_min),
            soft_min: canonical_zero(soft_min),
            soft_max: canonical_zero(soft_max),
            hard_max: canonical_zero(hard_max),
            units: None,
        })
    }

    /// Declare the canonical unit and the alternate units the bumper may
    /// convert from. Bounds are always in the canonical unit.
    ///
    /// Unit names match exactly, with no case folding and no trimming,
    /// because in SI `ms` (millisecond) and `Ms` (megasecond) differ by a
    /// factor of a billion.
    ///
    /// # Errors
    ///
    /// [`SpecError::EmptyName`], [`SpecError::UntrimmedName`],
    /// [`SpecError::DuplicateUnit`] if a name repeats (including an
    /// alternate equal to the canonical name), and
    /// [`SpecError::InvalidUnitScale`] unless every factor is finite,
    /// positive and normal.
    pub fn with_units(mut self, canonical: &str, alternates: &[(&str, UnitScale)]) -> Result<Self, SpecError> {
        check_name(canonical)?;
        let mut seen: Vec<&str> = vec![canonical];
        let mut table = Vec::with_capacity(alternates.len());
        for (name, scale) in alternates {
            check_name(name)?;
            if seen.contains(name) {
                return Err(SpecError::DuplicateUnit {
                    unit: (*name).to_owned(),
                });
            }
            let f = scale.factor();
            if !(f.is_normal() && f > 0.0) {
                return Err(SpecError::InvalidUnitScale {
                    unit: (*name).to_owned(),
                });
            }
            seen.push(name);
            table.push(((*name).to_owned(), *scale));
        }
        self.units = Some(UnitTable {
            canonical: canonical.to_owned(),
            alternates: table,
        });
        Ok(self)
    }

    /// Lower edge of the hard band.
    #[must_use]
    pub fn hard_min(&self) -> f64 {
        self.hard_min
    }
    /// Lower edge of the soft band.
    #[must_use]
    pub fn soft_min(&self) -> f64 {
        self.soft_min
    }
    /// Upper edge of the soft band.
    #[must_use]
    pub fn soft_max(&self) -> f64 {
        self.soft_max
    }
    /// Upper edge of the hard band.
    #[must_use]
    pub fn hard_max(&self) -> f64 {
        self.hard_max
    }

    /// The canonical unit name, if units were declared.
    #[must_use]
    pub fn canonical_unit(&self) -> Option<&str> {
        self.units.as_ref().map(|u| u.canonical.as_str())
    }

    pub(crate) fn unit_count(&self) -> usize {
        self.units.as_ref().map_or(0, |u| 1 + u.alternates.len())
    }

    pub(crate) fn resolve_unit(&self, unit: &str) -> Option<UnitMatch<'_>> {
        let table = self.units.as_ref()?;
        if table.canonical == unit {
            return Some(UnitMatch::Canonical);
        }
        table
            .alternates
            .iter()
            .find(|(name, _)| name == unit)
            .map(|(name, scale)| UnitMatch::Alternate(name.as_str(), *scale))
    }

    pub(crate) fn names(&self) -> impl Iterator<Item = &str> {
        self.units.iter().flat_map(|u| {
            std::iter::once(u.canonical.as_str()).chain(u.alternates.iter().map(|(n, _)| n.as_str()))
        })
    }
}

// ---------------------------------------------------------------------------
// Enum
// ---------------------------------------------------------------------------

/// One canonical variant and the aliases that resolve to it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VariantSpec {
    canonical: String,
    aliases: Vec<String>,
}

impl VariantSpec {
    /// A variant with no aliases yet.
    pub fn new(canonical: impl Into<String>) -> Self {
        Self {
            canonical: canonical.into(),
            aliases: Vec::new(),
        }
    }

    /// Add an accepted alias.
    #[must_use]
    pub fn alias(mut self, alias: impl Into<String>) -> Self {
        self.aliases.push(alias.into());
        self
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct EnumEntry {
    /// The name exactly as declared.
    pub(crate) exact: String,
    /// True when this name is an alias, false when it is the canonical name.
    pub(crate) is_alias: bool,
    /// Index into `EnumSpec::variants`.
    pub(crate) variant: usize,
}

/// An enumerated parameter: a closed set of canonical variants plus aliases.
///
/// Matching trims surrounding whitespace, then folds ASCII case. Only ASCII
/// is folded: full Unicode case folding changes string lengths (German sharp
/// s folds to "ss") and depends on locale (Turkish dotted and dotless i), so
/// non-ASCII letters must match exactly.
///
/// Every name, canonical or alias, must have a distinct ASCII-folded form.
/// That rule is checked here, when the spec is built, so an input can never
/// match two entries and the bumper never has to pick one.
#[derive(Debug, Clone, PartialEq)]
pub struct EnumSpec {
    variants: Vec<String>,
    index: BTreeMap<String, EnumEntry>,
    longest: usize,
}

impl EnumSpec {
    /// Build an enum spec.
    ///
    /// # Errors
    ///
    /// [`SpecError::EmptyEnum`] with no variants, [`SpecError::EmptyName`]
    /// or [`SpecError::UntrimmedName`] for a bad name, and
    /// [`SpecError::AliasCollision`] when two names (canonical or alias,
    /// same variant or different) are equal after ASCII case folding.
    pub fn new(variants: impl IntoIterator<Item = VariantSpec>) -> Result<Self, SpecError> {
        let mut canon = Vec::new();
        let mut index: BTreeMap<String, EnumEntry> = BTreeMap::new();
        let mut longest = 0usize;
        for (i, v) in variants.into_iter().enumerate() {
            let names = std::iter::once((v.canonical.clone(), false)).chain(v.aliases.iter().map(|a| (a.clone(), true)));
            for (name, is_alias) in names {
                check_name(&name)?;
                let key = name.to_ascii_lowercase();
                if let Some(prev) = index.get(&key) {
                    return Err(SpecError::AliasCollision {
                        first: prev.exact.clone(),
                        second: name,
                    });
                }
                longest = longest.max(name.len());
                index.insert(
                    key,
                    EnumEntry {
                        exact: name,
                        is_alias,
                        variant: i,
                    },
                );
            }
            canon.push(v.canonical);
        }
        if canon.is_empty() {
            return Err(SpecError::EmptyEnum);
        }
        Ok(Self {
            variants: canon,
            index,
            longest,
        })
    }

    /// The canonical variants, in declaration order.
    #[must_use]
    pub fn variants(&self) -> &[String] {
        &self.variants
    }

    /// Total names declared, canonical plus aliases.
    pub(crate) fn name_count(&self) -> usize {
        self.index.len()
    }

    /// Byte length of the longest declared name. Inputs longer than this,
    /// after trimming, cannot match and are refused without folding them.
    pub(crate) fn longest(&self) -> usize {
        self.longest
    }

    pub(crate) fn lookup(&self, folded: &str) -> Option<&EnumEntry> {
        self.index.get(folded)
    }

    pub(crate) fn variant(&self, i: usize) -> Option<&str> {
        self.variants.get(i).map(String::as_str)
    }

    pub(crate) fn names(&self) -> impl Iterator<Item = &str> {
        self.index.values().map(|e| e.exact.as_str())
    }
}

// ---------------------------------------------------------------------------
// String
// ---------------------------------------------------------------------------

/// What to do with leading and trailing whitespace in a string parameter.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TrimPolicy {
    /// Keep the string byte for byte. Whitespace is data.
    Preserve,
    /// Remove leading and trailing Unicode whitespace and record a
    /// `trimmed` correction when anything was removed.
    Trim,
    /// Refuse surrounding whitespace with RETRY. For identifiers, where a
    /// silent trim could make two distinct keys look equal. A string spec
    /// with this policy also refuses control and format characters by
    /// default (see [`CharPolicy`]), because characters such as a zero-width
    /// space or a bidi override make two distinct keys look equal too.
    Reject,
}

/// Which characters a string parameter may contain, beyond its length and
/// whitespace rules.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CharPolicy {
    /// Any Unicode scalar value. Whitespace is still governed by the
    /// [`TrimPolicy`].
    Any,
    /// Refuse, with RETRY reason `disallowed_char`, any character in the
    /// Unicode general categories Cc (controls, including NUL and ESC), Cf
    /// (format characters: zero-width space and joiners, byte order mark,
    /// bidi embeddings, overrides and isolates, soft hyphen, tag
    /// characters), Zl (line separator) or Zp (paragraph separator).
    ///
    /// This does not catch every look-alike. Confusable letters from other
    /// scripts (Cyrillic `a` for Latin `a`), combining marks and visually
    /// blank letters such as the Hangul fillers are not in these
    /// categories. Refusing those needs a confusables table, which this
    /// crate does not carry.
    RefuseControlAndFormat,
}

/// A free text parameter.
///
/// The length bounds are in UTF-8 bytes, not characters, because bytes are
/// what memory and storage are sized by. Text that is too long is RETRY and
/// is never truncated: cutting a string changes its meaning, and a bumper
/// only makes changes that keep meaning.
///
/// Text shorter than `min_len` (default 1) after the trim policy is RETRY
/// with reason `too_short`. The default means an empty string, or a string
/// that the `Trim` policy reduces to nothing, never satisfies a parameter:
/// a present parameter that carries nothing is a silent drop by another
/// name. An operator who wants empty strings sets `min_len` to 0
/// explicitly with [`StringSpec::with_min_len`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StringSpec {
    min_len: usize,
    max_len: usize,
    trim: TrimPolicy,
    chars: CharPolicy,
}

impl StringSpec {
    /// Build a string spec with `min_len` 1. The character policy is
    /// [`CharPolicy::RefuseControlAndFormat`] for [`TrimPolicy::Reject`]
    /// and [`CharPolicy::Any`] otherwise.
    ///
    /// # Errors
    ///
    /// [`SpecError::ZeroMaxLen`] when `max_len` is zero.
    pub fn new(max_len: usize, trim: TrimPolicy) -> Result<Self, SpecError> {
        if max_len == 0 {
            return Err(SpecError::ZeroMaxLen);
        }
        let chars = match trim {
            TrimPolicy::Reject => CharPolicy::RefuseControlAndFormat,
            TrimPolicy::Preserve | TrimPolicy::Trim => CharPolicy::Any,
        };
        Ok(Self {
            min_len: 1,
            max_len,
            trim,
            chars,
        })
    }

    /// Set the minimum length in UTF-8 bytes, measured after the trim
    /// policy runs. Zero allows the empty string.
    ///
    /// # Errors
    ///
    /// [`SpecError::MinLenAboveMaxLen`] when `min_len > max_len`.
    pub fn with_min_len(mut self, min_len: usize) -> Result<Self, SpecError> {
        if min_len > self.max_len {
            return Err(SpecError::MinLenAboveMaxLen {
                min_len,
                max_len: self.max_len,
            });
        }
        self.min_len = min_len;
        Ok(self)
    }

    /// Set the character policy.
    #[must_use]
    pub fn with_char_policy(mut self, chars: CharPolicy) -> Self {
        self.chars = chars;
        self
    }

    /// Minimum length in UTF-8 bytes, measured after the trim policy runs.
    #[must_use]
    pub fn min_len(&self) -> usize {
        self.min_len
    }

    /// Maximum length in UTF-8 bytes, measured after the trim policy runs.
    #[must_use]
    pub fn max_len(&self) -> usize {
        self.max_len
    }

    /// The whitespace policy.
    #[must_use]
    pub fn trim(&self) -> TrimPolicy {
        self.trim
    }

    /// The character policy.
    #[must_use]
    pub fn char_policy(&self) -> CharPolicy {
        self.chars
    }
}

/// True for a character in Unicode general category Cc, Cf, Zl or Zp.
///
/// Cc is `char::is_control`. The Cf ranges are written out from the Unicode
/// 16.0 character database because the standard library has no category
/// lookup and this crate takes no Unicode table dependency. A code point
/// assigned to Cf in a later Unicode version is not caught until this table
/// is updated.
pub(crate) fn is_control_or_format(c: char) -> bool {
    if c.is_control() {
        return true;
    }
    matches!(
        c,
        '\u{00AD}'
            | '\u{0600}'..='\u{0605}'
            | '\u{061C}'
            | '\u{06DD}'
            | '\u{070F}'
            | '\u{0890}'..='\u{0891}'
            | '\u{08E2}'
            | '\u{180E}'
            | '\u{200B}'..='\u{200F}'
            | '\u{2028}'..='\u{202E}'
            | '\u{2060}'..='\u{2064}'
            | '\u{2066}'..='\u{206F}'
            | '\u{FEFF}'
            | '\u{FFF9}'..='\u{FFFB}'
            | '\u{110BD}'
            | '\u{110CD}'
            | '\u{13430}'..='\u{1343F}'
            | '\u{1BCA0}'..='\u{1BCA3}'
            | '\u{1D173}'..='\u{1D17A}'
            | '\u{E0001}'
            | '\u{E0020}'..='\u{E007F}'
    )
}

/// Every declared name (parameter, variant, alias, unit) must be non-empty
/// and carry no surrounding whitespace. A name with surrounding whitespace
/// could never be matched after the bumper trims its input.
pub(crate) fn check_name(name: &str) -> Result<(), SpecError> {
    if name.is_empty() {
        return Err(SpecError::EmptyName);
    }
    if name.trim() != name {
        return Err(SpecError::UntrimmedName { name: name.to_owned() });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn negative_zero_bounds_are_canonicalized() {
        let s = NumericSpec::new(-0.0, -0.0, 1.0, 2.0).unwrap();
        assert!(s.hard_min().is_sign_positive());
        assert!(s.soft_min().is_sign_positive());
    }

    #[test]
    fn unit_scale_divide_is_exact_for_milliseconds() {
        assert_eq!(UnitScale::Divide(1000.0).apply(1500.0), 1.5);
    }

    #[test]
    fn control_and_format_table() {
        for c in ['\u{0}', '\u{1B}', '\u{7F}', '\u{85}', '\u{AD}', '\u{200B}', '\u{200D}', '\u{2028}', '\u{2029}', '\u{202E}', '\u{2066}', '\u{FEFF}', '\u{E0041}'] {
            assert!(is_control_or_format(c), "{}", c.escape_unicode());
        }
        for c in ['a', ' ', '\u{A0}', '\u{3000}', '\u{E9}', '\u{212A}', '\u{2030}', '\u{2065}'] {
            assert!(!is_control_or_format(c), "{}", c.escape_unicode());
        }
    }

    #[test]
    fn string_spec_defaults_and_min_len() {
        let s = StringSpec::new(4, TrimPolicy::Trim).unwrap();
        assert_eq!(s.min_len(), 1);
        assert_eq!(s.char_policy(), CharPolicy::Any);
        assert_eq!(StringSpec::new(4, TrimPolicy::Reject).unwrap().char_policy(), CharPolicy::RefuseControlAndFormat);
        assert_eq!(s.clone().with_min_len(0).unwrap().min_len(), 0);
        assert_eq!(s.clone().with_min_len(4).unwrap().min_len(), 4);
        assert_eq!(
            s.with_min_len(5).unwrap_err(),
            SpecError::MinLenAboveMaxLen { min_len: 5, max_len: 4 }
        );
    }

    #[test]
    fn resolve_unit_is_exact_match_only() {
        let s = NumericSpec::new(0.0, 0.0, 10.0, 20.0)
            .unwrap()
            .with_units("s", &[("ms", UnitScale::Divide(1000.0))])
            .unwrap();
        assert_eq!(s.resolve_unit("s"), Some(UnitMatch::Canonical));
        assert!(matches!(s.resolve_unit("ms"), Some(UnitMatch::Alternate("ms", _))));
        assert_eq!(s.resolve_unit("MS"), None);
        assert_eq!(s.resolve_unit("Ms"), None);
        assert_eq!(s.resolve_unit(" ms"), None);
        assert_eq!(s.unit_count(), 2);
    }
}
