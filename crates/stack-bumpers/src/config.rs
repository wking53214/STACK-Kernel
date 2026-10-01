//! Caps and budgets. Every bound the bumper enforces lives here.

use crate::error::SpecError;

/// Bumper configuration. Every field is a cap with a documented default.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BumperConfig {
    /// Most corrections allowed in one request before the request is RETRY.
    /// Default 3. Zero makes the bumper strict: any drift is RETRY.
    pub correction_budget: u32,
    /// Most entries a request may carry, and most specs a bumper may hold.
    /// A request over this is TERMINAL_BREACH before any entry is read.
    /// Default 64.
    pub max_params: usize,
    /// Most bytes in any one text value, unit name or unknown key, including
    /// a text value or unit name under an unknown key. Over this is
    /// TERMINAL_BREACH, and the oversized text is measured but never hashed.
    /// It sits at or above every spec's `max_len` (checked at build time).
    /// Default 4096.
    pub max_input_bytes: usize,
    /// Most bytes in any declared name: parameter, variant, alias or unit.
    /// Default 64. Must not exceed `max_input_bytes`.
    pub max_name_bytes: usize,
    /// Most names (canonical plus aliases) one enum may declare. Default 64.
    pub max_enum_names: usize,
    /// Most units (canonical plus alternates) one numeric spec may declare.
    /// Default 8.
    pub max_units: usize,
}

impl Default for BumperConfig {
    fn default() -> Self {
        Self {
            correction_budget: 3,
            max_params: 64,
            max_input_bytes: 4096,
            max_name_bytes: 64,
            max_enum_names: 64,
            max_units: 8,
        }
    }
}

impl BumperConfig {
    /// Check the caps are usable.
    ///
    /// # Errors
    ///
    /// [`SpecError::InvalidConfig`] naming the first bad field.
    pub fn validate(&self) -> Result<(), SpecError> {
        if self.max_params == 0 {
            return Err(SpecError::InvalidConfig("max_params must be at least 1"));
        }
        if self.max_input_bytes == 0 {
            return Err(SpecError::InvalidConfig("max_input_bytes must be at least 1"));
        }
        if self.max_name_bytes == 0 {
            return Err(SpecError::InvalidConfig("max_name_bytes must be at least 1"));
        }
        if self.max_name_bytes > self.max_input_bytes {
            return Err(SpecError::InvalidConfig("max_name_bytes must not exceed max_input_bytes"));
        }
        if self.max_enum_names == 0 {
            return Err(SpecError::InvalidConfig("max_enum_names must be at least 1"));
        }
        if self.max_units == 0 {
            return Err(SpecError::InvalidConfig("max_units must be at least 1"));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_are_valid_and_documented_values() {
        let c = BumperConfig::default();
        assert_eq!(c.correction_budget, 3);
        assert_eq!(c.max_params, 64);
        assert_eq!(c.max_input_bytes, 4096);
        assert_eq!(c.max_name_bytes, 64);
        assert_eq!(c.max_enum_names, 64);
        assert_eq!(c.max_units, 8);
        assert!(c.validate().is_ok());
    }

    #[test]
    fn zero_caps_are_refused() {
        let base = BumperConfig::default();
        for bad in [
            BumperConfig { max_params: 0, ..base },
            BumperConfig { max_input_bytes: 0, ..base },
            BumperConfig { max_name_bytes: 0, ..base },
            BumperConfig { max_enum_names: 0, ..base },
            BumperConfig { max_units: 0, ..base },
            BumperConfig {
                max_name_bytes: 10,
                max_input_bytes: 5,
                ..base
            },
        ] {
            assert!(matches!(bad.validate(), Err(SpecError::InvalidConfig(_))));
        }
    }

    #[test]
    fn zero_budget_is_allowed() {
        let c = BumperConfig {
            correction_budget: 0,
            ..BumperConfig::default()
        };
        assert!(c.validate().is_ok());
    }
}
