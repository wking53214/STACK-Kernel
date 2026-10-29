//! # The puzzle gate: nothing leaves the checkpoint alone
//!
//! **Status: prototype.** The design, its rules and the evidence behind the
//! defaults are in `manual/sections/trident_puzzles.md`. This module is not
//! wired into any other crate.
//!
//! A hostile payload can be cut into harmless pieces that each pass
//! inspection and join up on the far side. The gate treats every item as a
//! piece of a declared puzzle and releases nothing until all pieces are
//! present and the assembled whole has passed inspection. A puzzle has a
//! lifetime; if it is not complete in time it is destroyed and the sender
//! takes a breach.
//!
//! Every piece is a [`crate::HandoffEnvelope`] verified by the owning
//! [`crate::Trident`] first, so authenticity, binding and freshness are not
//! the gate's concern and cannot be skipped by a caller.

mod breaker;
pub mod config;
pub mod gate;
pub mod inspect;
pub mod piece;
pub mod rules;
pub mod telemetry;
#[cfg(test)]
mod rules_evidence;

pub use config::PuzzleConfig;
pub use gate::{BusyReason, CloseReason, Closed, GateStats, Outcome, PuzzleGate, PuzzleRefusal, Whole};
pub use inspect::{DenyListError, DenyListInspector, Finding, InspectInput, Inspector};
pub use rules::{RuleConfig, RuleError, RuleInspector};
pub use piece::{abort_payload, parse_message, root_of, split, Message, Piece, PieceError, PuzzleId, SplitError, ROOT_DOMAIN};
