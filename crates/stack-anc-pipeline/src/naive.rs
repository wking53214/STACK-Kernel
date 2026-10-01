//! Counterexample: [`crate::validators::balanced_dummy`] without
//! `black_box` on the filler work. Measurement only; never use it.
//!
//! The filler computes a value that nothing reads, so an optimizing
//! compiler deletes it. In a release build this function compiles to the
//! same machine code as [`crate::validators::early_exit`], and it leaks
//! exactly as much. `examples/verify.rs` shows both facts: the disassembly
//! (instruction count, no dummy loop) and the timing test.
//!
//! In a debug build nothing is optimized away, so the filler does run
//! there. That is one more reason debug-mode timings are not evidence.

use crate::validators::{probe, MAX_DUMMY_STEPS, TOKEN_LEN};
use core::hint::black_box;

/// Same shape as `balanced_dummy`, but the filler result is unused and not
/// passed through `black_box`. The token bytes are still read through
/// `black_box`, exactly as in `early_exit`, so the only difference from
/// `balanced_dummy` is the missing barrier on the filler.
#[inline(never)]
pub fn balanced_dummy_no_black_box(
    expected: &[u8; TOKEN_LEN],
    candidate: &[u8; TOKEN_LEN],
) -> bool {
    let mut i = 0;
    while i < TOKEN_LEN {
        probe::real_step();
        if black_box(expected[i]) != black_box(candidate[i]) {
            unobserved_filler(TOKEN_LEN - 1 - i);
            return false;
        }
        i += 1;
    }
    true
}

#[inline(always)]
fn unobserved_filler(steps: usize) {
    let steps = steps.min(MAX_DUMMY_STEPS);
    let mut hits: u8 = 0;
    let mut j = 0;
    while j < steps {
        probe::dummy_step();
        let x = j as u8;
        let y = !x;
        if x == y {
            hits = hits.wrapping_add(1);
        }
        j += 1;
    }
    // Deliberately unused: this is the bug being demonstrated.
    let _ = hits;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::validators::probe;

    #[test]
    fn source_level_behaviour_matches_balanced_dummy() {
        // At the source level (and in this unoptimized test build) the
        // filler runs; the optimizer is what removes it in release.
        let secret = [0x42u8; TOKEN_LEN]; // test fixture, not a key
        let mut wrong = secret;
        wrong[0] ^= 1;
        let _ = probe::take();
        assert!(!balanced_dummy_no_black_box(&secret, &wrong));
        let c = probe::take();
        assert_eq!((c.real, c.dummy), (1, MAX_DUMMY_STEPS as u64));
        assert!(balanced_dummy_no_black_box(&secret, &secret));
    }
}
