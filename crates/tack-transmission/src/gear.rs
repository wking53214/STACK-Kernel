//! A gear: one immutable operating configuration and the epoch number the
//! transmission gave it.

use std::fmt;

/// One operating configuration, frozen. The transmission keeps the engaged
/// gear behind an `Arc`, and every [`crate::DriveGuard`] holds a clone of
/// that `Arc` for the whole request, so a request reads one gear from start
/// to finish even if a shift happens right after it ends.
///
/// `G` is the caller's own type: policy version, key handles, parsed
/// configuration, an enforcement flag, or all of these together. The
/// transmission treats it as opaque. It never prints it, compares it or
/// validates it; parsing and validating a new configuration is the caller's
/// job and happens before `shift()` is called.
pub struct Gear<G> {
    epoch: u64,
    config: G,
}

impl<G> Gear<G> {
    pub(crate) fn new(epoch: u64, config: G) -> Self {
        Self { epoch, config }
    }

    /// The epoch. The first gear is epoch 0 and each successful shift adds
    /// exactly one. Epochs are never reused.
    pub fn epoch(&self) -> u64 {
        self.epoch
    }

    /// The configuration.
    pub fn config(&self) -> &G {
        &self.config
    }
}

/// Prints the epoch only. The configuration may contain key material, so it
/// is never formatted, whether or not `G` implements `Debug`.
impl<G> fmt::Debug for Gear<G> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Gear")
            .field("epoch", &self.epoch)
            .field("config", &format_args!("<not printed>"))
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn debug_never_prints_the_config() {
        let g = Gear::new(7, "TEST-FIXTURE-KEY-not-a-real-key");
        let s = format!("{g:?}");
        assert!(s.contains("epoch: 7"));
        assert!(!s.contains("TEST-FIXTURE"));
    }
}
