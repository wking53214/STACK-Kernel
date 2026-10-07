// Preemption boundary: hybrid model with signal-safe enforcement

use crate::{ContextLocal, TrapOutcome};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

pub struct PreemptionBoundary {
    preemption_flag: Arc<AtomicBool>,
    halted: Arc<AtomicBool>,
}

impl PreemptionBoundary {
    pub fn new() -> Self {
        Self {
            preemption_flag: Arc::new(AtomicBool::new(false)),
            halted: Arc::new(AtomicBool::new(false)),
        }
    }

    /// Signal handler calls this (signal-safe)
    pub fn signal_preemption(&self) {
        self.preemption_flag.store(true, Ordering::Release);
    }

    /// Boundary checks before returning to payload
    pub fn check_preemption(&self, ctx: &ContextLocal) -> Result<(), TrapOutcome> {
        if self.halted.load(Ordering::Acquire) {
            return Err(TrapOutcome::Halt);
        }

        let preempted = self.preemption_flag.load(Ordering::Acquire);
        if preempted && ctx.deadline_ns > 0 {
            // Deadline was exceeded; unwind at safe point
            return Err(TrapOutcome::TerminalBreach);
        }

        Ok(())
    }

    /// Operator can halt the boundary
    pub fn operator_halt(&self) {
        self.halted.store(true, Ordering::Release);
    }

    /// Operator can reset preemption flag
    pub fn operator_reset(&self) {
        self.preemption_flag.store(false, Ordering::Release);
        self.halted.store(false, Ordering::Release);
    }

    pub fn is_preempted(&self) -> bool {
        self.preemption_flag.load(Ordering::Acquire)
    }

    pub fn is_halted(&self) -> bool {
        self.halted.load(Ordering::Acquire)
    }
}

impl Default for PreemptionBoundary {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_boundary_creation() {
        let boundary = PreemptionBoundary::new();
        assert!(!boundary.is_preempted());
        assert!(!boundary.is_halted());
    }

    #[test]
    fn test_signal_preemption() {
        let boundary = PreemptionBoundary::new();
        boundary.signal_preemption();
        assert!(boundary.is_preempted());
    }

    #[test]
    fn test_check_preemption_passes() {
        let boundary = PreemptionBoundary::new();
        let ctx = ContextLocal::new("test".to_string(), [0u8; 32], 1000000);
        let result = boundary.check_preemption(&ctx);
        assert!(result.is_ok());
    }

    #[test]
    fn test_check_preemption_traps() {
        let boundary = PreemptionBoundary::new();
        let ctx = ContextLocal::new("test".to_string(), [0u8; 32], 1000000)
            .with_preemption(true);

        boundary.signal_preemption();
        let result = boundary.check_preemption(&ctx);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), TrapOutcome::TerminalBreach);
    }

    #[test]
    fn test_operator_halt() {
        let boundary = PreemptionBoundary::new();
        boundary.operator_halt();

        let ctx = ContextLocal::default();
        let result = boundary.check_preemption(&ctx);
        assert_eq!(result.unwrap_err(), TrapOutcome::Halt);
    }

    #[test]
    fn test_operator_reset() {
        let boundary = PreemptionBoundary::new();
        boundary.signal_preemption();
        boundary.operator_halt();

        assert!(boundary.is_preempted());
        assert!(boundary.is_halted());

        boundary.operator_reset();

        assert!(!boundary.is_preempted());
        assert!(!boundary.is_halted());
    }
}
