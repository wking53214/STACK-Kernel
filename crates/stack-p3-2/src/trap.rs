// Trap reason and outcome enums

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrapReason {
    DeadlineExceeded,
    TokenExhausted,
    CapabilityDenied,
    MemoryExceeded,
    SignalDelivered,
    SystemError,
}

impl TrapReason {
    pub fn as_str(&self) -> &'static str {
        match self {
            TrapReason::DeadlineExceeded => "deadline_exceeded",
            TrapReason::TokenExhausted => "token_exhausted",
            TrapReason::CapabilityDenied => "capability_denied",
            TrapReason::MemoryExceeded => "memory_exceeded",
            TrapReason::SignalDelivered => "signal_delivered",
            TrapReason::SystemError => "system_error",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrapOutcome {
    Retry,
    TerminalBreach,
    Halt,
}

impl TrapOutcome {
    pub fn as_str(&self) -> &'static str {
        match self {
            TrapOutcome::Retry => "RETRY",
            TrapOutcome::TerminalBreach => "TERMINAL_BREACH",
            TrapOutcome::Halt => "HALT",
        }
    }
}
