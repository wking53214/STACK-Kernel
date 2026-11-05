//! One clock for every boundary the kernel runs.
//!
//! `stack-trident`, `stack-authority` and `stack-receipt` each take a
//! `Clock` trait of the same shape. The kernel must read one clock for
//! all of them, or the Trident's freshness window, the capability window
//! and the receipt timestamps could disagree about "now". [`KernelClock`]
//! wraps one `stack_authority::Clock` (which `stack-receipt` re-exports)
//! and implements the Trident trait over it.
//!
//! The clock is trusted. Every window check reads it; a clock an attacker
//! can move moves every boundary.

use std::sync::Arc;

/// One clock, shared by the Trident, the authority and the recorder.
#[derive(Debug, Clone)]
pub struct KernelClock(Arc<dyn stack_authority::Clock>);

impl KernelClock {
    /// Wraps `clock`.
    pub fn new(clock: Arc<dyn stack_authority::Clock>) -> Self {
        Self(clock)
    }

    /// The system wall clock.
    pub fn system() -> Self {
        Self(Arc::new(stack_authority::SystemClock))
    }

    /// The wrapped clock.
    pub fn inner(&self) -> &Arc<dyn stack_authority::Clock> {
        &self.0
    }
}

impl stack_authority::Clock for KernelClock {
    fn now_unix_ms(&self) -> u64 {
        self.0.now_unix_ms()
    }
}

impl stack_trident::Clock for KernelClock {
    fn now_unix_ms(&self) -> u64 {
        self.0.now_unix_ms()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn both_traits_read_the_same_clock() {
        let manual = Arc::new(stack_authority::ManualClock::new(7));
        let clock = KernelClock::new(manual.clone());
        assert_eq!(stack_authority::Clock::now_unix_ms(&clock), 7);
        assert_eq!(stack_trident::Clock::now_unix_ms(&clock), 7);
        manual.advance(3);
        assert_eq!(stack_authority::Clock::now_unix_ms(&clock), 10);
        assert_eq!(stack_trident::Clock::now_unix_ms(&clock), 10);
        assert!(stack_trident::Clock::now_unix_ms(&KernelClock::system()) > 1_600_000_000_000);
    }
}
