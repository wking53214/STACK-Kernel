//! ≡TACK C++/Rust FFI Bridge
//! 
//! Safe Rust bindings to the C++23 containment stack.
//! Compiles C++ directly via `cc` crate for hardened integration.

#![no_std]
#![allow(non_camel_case_types)]

extern "C" {
    pub fn tack_host_initialize_and_seal() -> i32;
    pub fn tack_host_set_capabilities(m0: u64, m1: u64, m2: u64, m3: u64);
    pub fn tack_execute_governed_transaction(
        context_id: u64,
        required_capability_m0: u64,
        required_tokens: u32,
        deadline_budget_ticks: u64,
        hard_timeout_nanoseconds: u64,
    ) -> i32;
    pub fn tack_audit_push(event_type: u8, context_id: u64, tokens: u32);
    pub fn tack_audit_read_slot(
        index: u64,
        out_timestamp: *mut u64,
        out_context_id: *mut u64,
        out_tokens: *mut u32,
    ) -> i32;
    pub fn tack_arena_allocate(size: usize) -> *mut u8;
    pub fn tack_read_ticks() -> u64;
}

/// Safe wrapper for host initialization
pub fn host_initialize_and_seal() -> Result<(), HostError> {
    unsafe {
        match tack_host_initialize_and_seal() {
            0 => Ok(()),
            _ => Err(HostError::InitializationFailed),
        }
    }
}

/// Safe wrapper for setting active capabilities
pub fn host_set_capabilities(m0: u64, m1: u64, m2: u64, m3: u64) {
    unsafe {
        tack_host_set_capabilities(m0, m1, m2, m3);
    }
}

/// Safe wrapper for executing governed transaction
pub fn execute_governed_transaction(
    context_id: u64,
    required_capability_m0: u64,
    required_tokens: u32,
    deadline_budget_ticks: u64,
    hard_timeout_nanoseconds: u64,
) -> Result<(), TransactionError> {
    unsafe {
        match tack_execute_governed_transaction(
            context_id,
            required_capability_m0,
            required_tokens,
            deadline_budget_ticks,
            hard_timeout_nanoseconds,
        ) {
            0 => Ok(()),
            _ => Err(TransactionError::ExecutionFailed),
        }
    }
}

/// Safe wrapper for audit ring push
pub fn audit_push(event_type: u8, context_id: u64, tokens: u32) {
    unsafe {
        tack_audit_push(event_type, context_id, tokens);
    }
}

/// Safe wrapper for audit ring read
pub fn audit_read_slot(index: u64) -> Option<AuditRecord> {
    unsafe {
        let mut timestamp = 0u64;
        let mut context_id = 0u64;
        let mut tokens = 0u32;
        
        if tack_audit_read_slot(index, &mut timestamp, &mut context_id, &mut tokens) != 0 {
            Some(AuditRecord {
                timestamp_ticks: timestamp,
                context_id,
                tokens_consumed: tokens,
            })
        } else {
            None
        }
    }
}

/// Read hardware tick counter
pub fn read_ticks() -> u64 {
    unsafe { tack_read_ticks() }
}

#[derive(Debug, Clone, Copy)]
pub enum HostError {
    InitializationFailed,
}

#[derive(Debug, Clone, Copy)]
pub enum TransactionError {
    ExecutionFailed,
}

#[derive(Debug, Clone, Copy)]
pub struct AuditRecord {
    pub timestamp_ticks: u64,
    pub context_id: u64,
    pub tokens_consumed: u32,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ffi_initialization() {
        assert!(host_initialize_and_seal().is_ok());
    }

    #[test]
    fn test_capability_setting() {
        host_set_capabilities(0xFF, 0, 0, 0);
    }

    #[test]
    fn test_tick_counter() {
        let t1 = read_ticks();
        let t2 = read_ticks();
        assert!(t2 >= t1);
    }
}
