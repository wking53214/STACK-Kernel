// ≡TACK P3.2 Schema: Relational model for execution contexts and trap events

use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};

/// Execution context: Full state snapshot when a boundary is checked.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutionContext {
    pub context_id: uuid::Uuid,
    pub transaction_id: uuid::Uuid,
    pub agent_id: String,
    pub subject_digest: [u8; 32],
    pub depth: u32,
    pub boundary_layer: u8,
    pub issued_at_unix_ns: u64,
    pub wall_clock_at_entry_ns: u64,
    pub hardware_ticks_at_entry: u64,
    pub preemption_flag_at_entry: bool,
    pub deadline_ns: u64,
    pub tokens_consumed: u64,
    pub tokens_capacity: u64,
    pub capabilities_mask: [u8; 32],
    pub memory_allocated_bytes: u64,
    pub memory_capacity_bytes: u64,
}

impl ExecutionContext {
    /// Create root context for a transaction.
    pub fn root(
        tx_id: uuid::Uuid,
        agent_id: String,
        subject_digest: [u8; 32],
        deadline_ns: u64,
    ) -> Self {
        let now_ns = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos() as u64;

        Self {
            context_id: uuid::Uuid::new_v4(),
            transaction_id: tx_id,
            agent_id,
            subject_digest,
            depth: 0,
            boundary_layer: 0,
            issued_at_unix_ns: now_ns,
            wall_clock_at_entry_ns: now_ns,
            hardware_ticks_at_entry: 0,
            preemption_flag_at_entry: false,
            deadline_ns,
            tokens_consumed: 0,
            tokens_capacity: 0,
            capabilities_mask: [0u8; 32],
            memory_allocated_bytes: 0,
            memory_capacity_bytes: 0,
        }
    }

    /// Create child context (called at boundary).
    pub fn at_boundary(
        parent: &ExecutionContext,
        boundary_layer: u8,
        hardware_ticks: u64,
        preemption_flag: bool,
        tokens_consumed: u64,
        capabilities_mask: [u8; 32],
        memory_allocated: u64,
    ) -> Self {
        let now_ns = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos() as u64;

        Self {
            context_id: uuid::Uuid::new_v4(),
            transaction_id: parent.transaction_id,
            agent_id: parent.agent_id.clone(),
            subject_digest: parent.subject_digest,
            depth: parent.depth + 1,
            boundary_layer,
            issued_at_unix_ns: now_ns,
            wall_clock_at_entry_ns: now_ns,
            hardware_ticks_at_entry: hardware_ticks,
            preemption_flag_at_entry: preemption_flag,
            deadline_ns: parent.deadline_ns,
            tokens_consumed,
            tokens_capacity: parent.tokens_capacity,
            capabilities_mask,
            memory_allocated_bytes: memory_allocated,
            memory_capacity_bytes: parent.memory_capacity_bytes,
        }
    }
}

/// Trap event: When a boundary enforces a rule.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrapEvent {
    pub trap_id: uuid::Uuid,
    pub context_id: uuid::Uuid,
    pub transaction_id: uuid::Uuid,
    pub agent_id: String,
    pub subject_digest: [u8; 32],
    pub boundary_layer: u8,
    pub trap_reason: String,
    pub trap_outcome: String, // "RETRY" | "TERMINAL_BREACH" | "HALT"
    pub preemption_active_at_trap: bool,
    pub hardware_ticks_at_trap: u64,
    pub nanoseconds_since_deadline: Option<i64>,
    pub tokens_deficit: Option<u64>,
    pub capability_mask_denied: Option<[u8; 32]>,
    pub memory_requested_bytes: Option<u64>,
    pub retry_after_ns: Option<u64>,
    pub created_at_ns: u64,
}

impl TrapEvent {
    /// Record a preemption boundary trap.
    pub fn preemption_trap(
        tx_id: uuid::Uuid,
        ctx_local: &crate::ContextLocal,
        preemption_flag: bool,
    ) -> Self {
        let now_ns = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos() as u64;

        let nanoseconds_since_deadline = if ctx_local.deadline_ns > 0 {
            Some(now_ns.saturating_sub(ctx_local.deadline_ns) as i64)
        } else {
            None
        };

        Self {
            trap_id: uuid::Uuid::new_v4(),
            context_id: uuid::Uuid::new_v4(),
            transaction_id: tx_id,
            agent_id: ctx_local.agent_id.clone(),
            subject_digest: ctx_local.subject_digest,
            boundary_layer: crate::BoundaryLayer::Preemption as u8,
            trap_reason: "deadline_exceeded".to_string(),
            trap_outcome: "TERMINAL_BREACH".to_string(),
            preemption_active_at_trap: preemption_flag,
            hardware_ticks_at_trap: ctx_local.hardware_ticks,
            nanoseconds_since_deadline,
            tokens_deficit: None,
            capability_mask_denied: None,
            memory_requested_bytes: None,
            retry_after_ns: None,
            created_at_ns: now_ns,
        }
    }

    /// System error trap (e.g., lock poisoned).
    pub fn system_error(tx_id: uuid::Uuid) -> Self {
        let now_ns = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos() as u64;

        Self {
            trap_id: uuid::Uuid::new_v4(),
            context_id: uuid::Uuid::new_v4(),
            transaction_id: tx_id,
            agent_id: "system".to_string(),
            subject_digest: [0u8; 32],
            boundary_layer: 0,
            trap_reason: "system_error".to_string(),
            trap_outcome: "HALT".to_string(),
            preemption_active_at_trap: false,
            hardware_ticks_at_trap: 0,
            nanoseconds_since_deadline: None,
            tokens_deficit: None,
            capability_mask_denied: None,
            memory_requested_bytes: None,
            retry_after_ns: None,
            created_at_ns: now_ns,
        }
    }
}

/// Transaction record: Groups contexts and traps into logical units.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Transaction {
    pub transaction_id: uuid::Uuid,
    pub agent_id: String,
    pub subject_digest: [u8; 32],
    pub started_at_ns: u64,
    pub deadline_ns: u64,
    pub outcome: Option<String>, // "PASS" | "RETRY" | "TERMINAL_BREACH" | "HALTED"
    pub completed_at_ns: Option<u64>,
    pub execution_ns: Option<u64>,
    pub trap_count: u32,
}

impl Transaction {
    pub fn new(
        agent_id: String,
        subject_digest: [u8; 32],
        deadline_ns: u64,
    ) -> Self {
        let now_ns = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos() as u64;

        Self {
            transaction_id: uuid::Uuid::new_v4(),
            agent_id,
            subject_digest,
            started_at_ns: now_ns,
            deadline_ns,
            outcome: None,
            completed_at_ns: None,
            execution_ns: None,
            trap_count: 0,
        }
    }

    pub fn complete(&mut self, outcome: String) {
        let now_ns = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos() as u64;

        self.outcome = Some(outcome);
        self.completed_at_ns = Some(now_ns);
        self.execution_ns = Some(now_ns.saturating_sub(self.started_at_ns));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_context_root_creation() {
        let agent_id = "test-agent".to_string();
        let subject_digest = [0u8; 32];
        let tx_id = uuid::Uuid::new_v4();

        let ctx = ExecutionContext::root(tx_id, agent_id.clone(), subject_digest, 1000000);
        assert_eq!(ctx.agent_id, agent_id);
        assert_eq!(ctx.depth, 0);
        assert_eq!(ctx.boundary_layer, 0);
    }

    #[test]
    fn test_context_child_creation() {
        let parent = ExecutionContext::root(
            uuid::Uuid::new_v4(),
            "test".to_string(),
            [0u8; 32],
            1000000,
        );

        let child = ExecutionContext::at_boundary(
            &parent,
            2,
            100,
            true,
            0,
            [0u8; 32],
            0,
        );

        assert_eq!(child.depth, 1);
        assert_eq!(child.boundary_layer, 2);
        assert_eq!(child.transaction_id, parent.transaction_id);
    }

    #[test]
    fn test_trap_event_serialization() {
        let ctx_local = crate::ContextLocal::default();
        let tx_id = uuid::Uuid::new_v4();
        let trap = TrapEvent::preemption_trap(tx_id, &ctx_local, true);

        let json = serde_json::to_string(&trap).unwrap();
        let parsed: TrapEvent = serde_json::from_str(&json).unwrap();

        assert_eq!(parsed.trap_id, trap.trap_id);
    }
}
