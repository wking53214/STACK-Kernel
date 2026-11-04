//! The kernel's own policy: configuration, never payload.
//!
//! Everything the pipeline compares a request against comes from here:
//! which seats a decision must carry, which operation names exist and
//! what each one runs, the audience this kernel answers to, and the
//! limits every execution runs under. A payload names what it wants; the
//! policy says what is possible.

use std::collections::BTreeMap;

use stack_receipt::record::check_text;
use stack_receipt::{Provenance, RosterPolicy, ValidationError, MAX_ID_BYTES, MAX_OPERATION_BYTES, MAX_SEATS};

use crate::executor::{ExecutionLimits, LimitsError, WorkerKind};

/// Why a policy was refused.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ConfigError {
    /// `kernel_id` breaks the identifier rules.
    #[error("kernel_id refused: {0}")]
    KernelId(ValidationError),
    /// `audience` breaks the identifier rules.
    #[error("audience refused: {0}")]
    Audience(ValidationError),
    /// No seat is required: a decision could satisfy the policy with no gate.
    #[error("required_seats is empty; a policy that requires no seat admits an empty decision")]
    NoRequiredSeats,
    /// More seats than a decision record can carry.
    #[error("required_seats holds more than {MAX_SEATS} seats")]
    TooManySeats,
    /// A required seat name breaks the identifier rules.
    #[error("required seat refused: {0}")]
    Seat(ValidationError),
    /// A required seat is listed twice.
    #[error("required seat listed twice: {0}")]
    DuplicateSeat(String),
    /// No operation is mapped: nothing could ever execute.
    #[error("operations is empty; no operation name maps to a worker")]
    NoOperations,
    /// An operation name breaks the rules `stack-authority` applies.
    #[error("operation name refused: {0}")]
    Operation(ValidationError),
    /// The execution limits are out of range.
    #[error("execution limits refused: {0}")]
    Limits(LimitsError),
    /// The provenance stamped on every receipt record is invalid.
    #[error("provenance refused: {0}")]
    Provenance(ValidationError),
}

/// What this kernel requires and runs. Built by the operator; never read
/// from a request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KernelPolicy {
    /// This kernel's identity in its receipt log.
    pub kernel_id: String,
    /// The audience a Trident envelope must be sealed for and a capability
    /// must name: this kernel.
    pub audience: String,
    /// Seats (`repository:gate`) a decision must carry with a bound PASS.
    /// A CNS root does not commit to the required roster (register D-11),
    /// so the kernel holds it.
    pub required_seats: Vec<String>,
    /// Operation name to the worker it runs. An operation not listed here
    /// is refused before authorization, whatever any capability says.
    pub operations: BTreeMap<String, WorkerKind>,
    /// Limits every execution runs under.
    pub limits: ExecutionLimits,
    /// Who the receipts say produced them.
    pub provenance: Provenance,
}

impl KernelPolicy {
    /// Checks every field.
    pub fn validate(&self) -> Result<(), ConfigError> {
        check_text("kernel_id", &self.kernel_id, 1, MAX_ID_BYTES).map_err(ConfigError::KernelId)?;
        check_text("audience", &self.audience, 1, MAX_ID_BYTES).map_err(ConfigError::Audience)?;
        if self.required_seats.is_empty() {
            return Err(ConfigError::NoRequiredSeats);
        }
        if self.required_seats.len() > MAX_SEATS {
            return Err(ConfigError::TooManySeats);
        }
        for (i, seat) in self.required_seats.iter().enumerate() {
            check_text("required_seat", seat, 1, MAX_ID_BYTES).map_err(ConfigError::Seat)?;
            if self.required_seats.iter().take(i).any(|s| s == seat) {
                return Err(ConfigError::DuplicateSeat(seat.clone()));
            }
        }
        if self.operations.is_empty() {
            return Err(ConfigError::NoOperations);
        }
        for name in self.operations.keys() {
            check_text("operation", name, 1, MAX_OPERATION_BYTES).map_err(ConfigError::Operation)?;
        }
        self.limits.validate().map_err(ConfigError::Limits)?;
        self.provenance.validate().map_err(ConfigError::Provenance)?;
        Ok(())
    }

    /// The roster policy the receipt verifier is given: the same seats,
    /// so the kernel and an auditor require the same thing.
    pub fn roster_policy(&self) -> RosterPolicy {
        RosterPolicy {
            required_seats: self.required_seats.clone(),
        }
    }

    /// The worker an operation name maps to, if any.
    pub fn worker_for(&self, operation: &str) -> Option<WorkerKind> {
        self.operations.get(operation).copied()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy() -> KernelPolicy {
        KernelPolicy {
            kernel_id: "kernel-a".into(),
            audience: "kernel-a".into(),
            required_seats: vec!["Governance_Gateway:door".into(), "DIT:judge".into()],
            operations: BTreeMap::from([("echo".to_owned(), WorkerKind::ReturnBytes)]),
            limits: ExecutionLimits::with_deadline_ns(300_000_000),
            provenance: Provenance {
                component: "stack-admission".into(),
                version: "0.1.0".into(),
                host_id: "host".into(),
            },
        }
    }

    #[test]
    fn a_complete_policy_validates_and_maps_operations() {
        let p = policy();
        assert_eq!(p.validate(), Ok(()));
        assert_eq!(p.worker_for("echo"), Some(WorkerKind::ReturnBytes));
        assert_eq!(p.worker_for("rm"), None);
        assert_eq!(p.roster_policy().required_seats, p.required_seats);
    }

    #[test]
    fn each_field_is_checked() {
        let mut p = policy();
        p.kernel_id = String::new();
        assert!(matches!(p.validate(), Err(ConfigError::KernelId(_))));
        let mut p = policy();
        p.audience = "a\nb".into();
        assert!(matches!(p.validate(), Err(ConfigError::Audience(_))));
        let mut p = policy();
        p.required_seats.clear();
        assert_eq!(p.validate(), Err(ConfigError::NoRequiredSeats));
        let mut p = policy();
        p.required_seats = vec!["x".into(); MAX_SEATS + 1];
        assert_eq!(p.validate(), Err(ConfigError::TooManySeats));
        let mut p = policy();
        p.required_seats.push(String::new());
        assert!(matches!(p.validate(), Err(ConfigError::Seat(_))));
        let mut p = policy();
        p.required_seats.push("DIT:judge".into());
        assert_eq!(p.validate(), Err(ConfigError::DuplicateSeat("DIT:judge".into())));
        let mut p = policy();
        p.operations.clear();
        assert_eq!(p.validate(), Err(ConfigError::NoOperations));
        let mut p = policy();
        p.operations.insert("x".repeat(MAX_OPERATION_BYTES + 1), WorkerKind::ReturnBytes);
        assert!(matches!(p.validate(), Err(ConfigError::Operation(_))));
        let mut p = policy();
        p.limits.wall_clock_deadline_ns = 0;
        assert!(matches!(p.validate(), Err(ConfigError::Limits(_))));
        let mut p = policy();
        p.provenance.host_id = String::new();
        assert!(matches!(p.validate(), Err(ConfigError::Provenance(_))));
    }
}
