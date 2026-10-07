// P3.2 configuration and validation

#[derive(Debug, Clone)]
pub struct P32Config {
    pub max_contexts: usize,
    pub max_traps: usize,
    pub trap_retention_seconds: u64,
}

impl P32Config {
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.max_contexts == 0 {
            return Err("max_contexts must be > 0");
        }
        if self.max_traps == 0 {
            return Err("max_traps must be > 0");
        }
        if self.trap_retention_seconds == 0 {
            return Err("trap_retention_seconds must be > 0");
        }
        Ok(())
    }
}

impl Default for P32Config {
    fn default() -> Self {
        Self {
            max_contexts: 10_000,
            max_traps: 100_000,
            trap_retention_seconds: 86400, // 24 hours
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config_valid() {
        let config = P32Config::default();
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_invalid_max_contexts() {
        let config = P32Config {
            max_contexts: 0,
            ..Default::default()
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_invalid_max_traps() {
        let config = P32Config {
            max_traps: 0,
            ..Default::default()
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_invalid_trap_retention() {
        let config = P32Config {
            trap_retention_seconds: 0,
            ..Default::default()
        };
        assert!(config.validate().is_err());
    }
}
