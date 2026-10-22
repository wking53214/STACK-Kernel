// ≡TACK P3.2: Hard Preemption with Hybrid Boundary Model
//
// PURPOSE: Enforce deadline preemption via signal handler + context-local state,
// with full trap event logging for Sentinel analysis.
//
// HYBRID MODEL:
// - Signal handler sets preemption flag (signal-safe, no unwinding)
// - Preemption state travels with execution context (not broadcast flag mesh)
// - Boundaries are active observers: trap logs what was executing + why
// - Trap events → Sentinel learns which boundaries to tighten next

pub mod schema;
pub mod context;
pub mod trap;
pub mod boundary;
pub mod config;
pub mod governed_limits;

pub use schema::{ExecutionContext, TrapEvent, Transaction};
pub use context::ContextLocal;
pub use trap::{TrapReason, TrapOutcome};
pub use boundary::PreemptionBoundary;
pub use config::P32Config;
pub use governed_limits::{GovernedLimits, LimitKind, LimitSource};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BoundaryLayer {
    Clock = 1,
    Preemption = 2,
    RateLimiting = 3,
    Orchestration = 4,
    Audit = 5,
    Isolation = 6,
}

/// Main interface: Create and manage execution contexts with trap logging.
pub struct HardPreemptionKernel {
    config: P32Config,
    flywheel: Flywheel,
}

struct Flywheel {
    // Live execution contexts
    contexts: std::sync::Arc<std::sync::Mutex<Vec<ExecutionContext>>>,
    // Trap events log
    traps: std::sync::Arc<std::sync::Mutex<Vec<TrapEvent>>>,
}

impl HardPreemptionKernel {
    /// Create a new kernel with schema-aware trap logging.
    pub fn new(config: P32Config) -> Result<Self, &'static str> {
        config.validate()?;
        Ok(Self {
            config,
            flywheel: Flywheel {
                contexts: std::sync::Arc::new(std::sync::Mutex::new(Vec::new())),
                traps: std::sync::Arc::new(std::sync::Mutex::new(Vec::new())),
            },
        })
    }

    /// Begin a transaction: create root execution context.
    pub fn begin_transaction(
        &self,
        agent_id: String,
        subject_digest: [u8; 32],
        deadline_ns: u64,
    ) -> Result<uuid::Uuid, &'static str> {
        let tx_id = uuid::Uuid::new_v4();
        let ctx = ExecutionContext::root(tx_id, agent_id, subject_digest, deadline_ns);

        let mut contexts = self.flywheel.contexts.lock()
            .map_err(|_| "Failed to lock contexts")?;
        contexts.push(ctx.clone());

        Ok(tx_id)
    }

    /// Begin a transaction whose deadline is `now + budget`, where the budget is the governed
    /// time budget for this agent. `default_budget_ns` is the ceiling: the governance service
    /// can shorten the budget, never lengthen it, and an outage leaves the default in force.
    /// (`deadline_ns` in the schema is an absolute timestamp; the governed limit is a duration.)
    pub fn begin_transaction_governed<S: governed_limits::LimitSource>(
        &self,
        limits: &GovernedLimits<S>,
        agent_id: String,
        subject_digest: [u8; 32],
        default_budget_ns: u64,
    ) -> Result<uuid::Uuid, &'static str> {
        let budget = limits.effective(&agent_id, LimitKind::DeadlineNs, default_budget_ns);
        let now_ns = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|_| "clock before epoch")?
            .as_nanos() as u64;
        self.begin_transaction(agent_id, subject_digest, now_ns.saturating_add(budget))
    }

    /// Check preemption boundary: trap if preempted, log context + reason.
    pub fn check_preemption_boundary(
        &self,
        tx_id: uuid::Uuid,
        ctx_local: &ContextLocal,
        preemption_flag: bool,
    ) -> Result<(), TrapEvent> {
        if !preemption_flag {
            return Ok(());
        }

        // Preemption active: boundary traps and logs event
        let trap = TrapEvent::preemption_trap(tx_id, ctx_local, preemption_flag);

        let mut traps = self.flywheel.traps.lock()
            .map_err(|_| TrapEvent::system_error(tx_id))?;
        traps.push(trap.clone());

        Err(trap)
    }

    /// Query live contexts (for real-time boundary decisions)
    pub fn live_contexts(&self, tx_id: uuid::Uuid) -> Result<Vec<ExecutionContext>, &'static str> {
        let contexts = self.flywheel.contexts.lock()
            .map_err(|_| "Failed to lock contexts")?;
        Ok(contexts.iter()
            .filter(|c| c.transaction_id == tx_id)
            .cloned()
            .collect())
    }

    /// Query trap history (for Sentinel pattern analysis)
    pub fn trap_history(&self, agent_id: &str) -> Result<Vec<TrapEvent>, &'static str> {
        let traps = self.flywheel.traps.lock()
            .map_err(|_| "Failed to lock traps")?;
        Ok(traps.iter()
            .filter(|t| t.agent_id == agent_id)
            .cloned()
            .collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_kernel_creation() {
        let config = P32Config::default();
        let kernel = HardPreemptionKernel::new(config);
        assert!(kernel.is_ok());
    }

    #[test]
    fn test_transaction_begin() {
        let config = P32Config::default();
        let kernel = HardPreemptionKernel::new(config).unwrap();

        let agent_id = "test-agent".to_string();
        let subject_digest = [0u8; 32];
        let deadline_ns = 1000000;

        let tx_id = kernel.begin_transaction(agent_id, subject_digest, deadline_ns);
        assert!(tx_id.is_ok());
    }

    #[test]
    fn test_preemption_boundary_traps() {
        let config = P32Config::default();
        let kernel = HardPreemptionKernel::new(config).unwrap();

        let agent_id = "test-agent".to_string();
        let tx_id = kernel.begin_transaction(agent_id, [0u8; 32], 1000000).unwrap();

        let ctx_local = ContextLocal::default();

        // No preemption: boundary passes
        let result = kernel.check_preemption_boundary(tx_id, &ctx_local, false);
        assert!(result.is_ok());

        // Preemption active: boundary traps
        let result = kernel.check_preemption_boundary(tx_id, &ctx_local, true);
        assert!(result.is_err());
    }

    #[test]
    fn test_trap_logging() {
        let config = P32Config::default();
        let kernel = HardPreemptionKernel::new(config).unwrap();

        let agent_id = "test-agent".to_string();
        let tx_id = kernel.begin_transaction(agent_id.clone(), [0u8; 32], 1000000).unwrap();

        let ctx_local = ContextLocal::new(agent_id.clone(), [0u8; 32], 1000000);
        let _ = kernel.check_preemption_boundary(tx_id, &ctx_local, true);

        // Trap should be logged
        let history = kernel.trap_history(&agent_id).unwrap();
        assert!(!history.is_empty());
    }

    #[test]
    fn test_governed_budget_becomes_a_deadline_and_is_capped() {
        use std::time::Duration;
        let kernel = HardPreemptionKernel::new(P32Config::default()).unwrap();
        let dir = std::env::temp_dir().join(format!("gd-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("l.json");
        std::fs::write(&path, r#"{"stack.agent.a.deadline_ns": 2000000000, "stack.agent.b.deadline_ns": 99000000000}"#).unwrap();
        let limits = GovernedLimits::new(governed_limits::FileSource { path }, Duration::ZERO);
        let budget = |agent: &str| {
            let before = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos() as u64;
            let tx = kernel.begin_transaction_governed(&limits, agent.into(), [0u8; 32], 10_000_000_000).unwrap();
            let after = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos() as u64;
            let d = kernel.live_contexts(tx).unwrap()[0].deadline_ns;
            assert!(d >= before && d <= after + 10_000_000_000, "deadline is an absolute time");
            d - before
        };
        let slack = 1_000_000_000; // generous: clock reads happen around the call
        let near = |got: u64, want: u64| got >= want && got <= want + slack;
        assert!(near(budget("a"), 2_000_000_000)); // tightened
        assert!(near(budget("b"), 10_000_000_000)); // above the ceiling: default
        assert!(near(budget("c"), 10_000_000_000)); // nothing governed: default
    }
}
