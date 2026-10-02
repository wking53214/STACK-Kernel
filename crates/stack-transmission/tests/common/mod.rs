// Shared helpers for the integration tests. Included with `mod common;`.
#![allow(dead_code)]

use std::time::Duration;

use stack_transmission::{Transmission, TransmissionConfig};

/// A stand-in operating mode. Every field is derived from `tag`, so a
/// worker that ever read fields from two different gears would see them
/// disagree. The key id is a test fixture number, not key material.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Mode {
    pub tag: u64,
    pub policy_version: u64,
    pub test_fixture_key_id: u64,
    pub enforcing: bool,
}

impl Mode {
    pub fn for_epoch(tag: u64) -> Self {
        Self {
            tag,
            policy_version: tag.wrapping_mul(3).wrapping_add(1),
            test_fixture_key_id: tag ^ 0xA5A5,
            enforcing: tag % 2 == 0,
        }
    }

    pub fn is_consistent(&self) -> bool {
        *self == Self::for_epoch(self.tag)
    }
}

pub fn tx(cfg: TransmissionConfig) -> Transmission<Mode> {
    Transmission::new(Mode::for_epoch(0), cfg).unwrap()
}

pub fn wait_until(what: &str, mut cond: impl FnMut() -> bool) {
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    while !cond() {
        assert!(std::time::Instant::now() < deadline, "timed out waiting for {what}");
        std::thread::sleep(Duration::from_millis(1));
    }
}
