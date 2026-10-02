// Context-local preemption state (not broadcast flag mesh)

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ContextLocal {
    pub agent_id: String,
    pub subject_digest: [u8; 32],
    pub deadline_ns: u64,
    pub hardware_ticks: u64,
    pub preemption_flag: bool,
    pub tokens_consumed: u64,
}

impl ContextLocal {
    pub fn new(agent_id: String, subject_digest: [u8; 32], deadline_ns: u64) -> Self {
        Self {
            agent_id,
            subject_digest,
            deadline_ns,
            hardware_ticks: 0,
            preemption_flag: false,
            tokens_consumed: 0,
        }
    }

    pub fn with_preemption(mut self, flag: bool) -> Self {
        self.preemption_flag = flag;
        self
    }

    pub fn with_ticks(mut self, ticks: u64) -> Self {
        self.hardware_ticks = ticks;
        self
    }
}
