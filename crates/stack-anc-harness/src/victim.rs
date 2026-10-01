//! Known-good and known-bad token validators used to calibrate the harness.
//!
//! Both functions take the same inputs and return the same answer. They
//! differ only in timing: [`leaky_validate`] stops at the first differing
//! byte, so its run time tells an attacker how long the matching prefix is.
//! [`ct_validate`] always reads every byte and combines the result without a
//! data-dependent branch.

use subtle::ConstantTimeEq;

/// Length of the token both victims compare.
pub const TOKEN_LEN: usize = 32;

/// Early-exit byte comparison. Deliberately leaky: do not use outside tests.
///
/// Each byte read goes through `std::hint::black_box` so the optimizer cannot
/// replace the loop with a fixed-width vector compare (which would hide the
/// leak the calibration is meant to show).
pub fn leaky_validate(expected: &[u8; TOKEN_LEN], candidate: &[u8; TOKEN_LEN]) -> bool {
    for i in 0..TOKEN_LEN {
        if std::hint::black_box(expected[i]) != std::hint::black_box(candidate[i]) {
            return false;
        }
    }
    true
}

/// Constant-time comparison via `subtle::ConstantTimeEq`.
pub fn ct_validate(expected: &[u8; TOKEN_LEN], candidate: &[u8; TOKEN_LEN]) -> bool {
    bool::from(expected.ct_eq(candidate))
}
