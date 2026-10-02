//! The three token validators this strategy compares.
//!
//! All three answer the same question ("is `candidate` equal to
//! `expected`?") and return the same answer for every input. They differ
//! only in how the work is laid out on the CPU, which is what an attacker
//! with a stopwatch sees.
//!
//! | validator          | branches on secret data | work on a wrong guess             |
//! |--------------------|-------------------------|-----------------------------------|
//! | [`early_exit`]     | yes, once per byte      | stops at the first wrong byte     |
//! | [`balanced_dummy`] | yes, once per byte      | stops, then runs filler work      |
//! | [`constant_time`]  | no                      | always reads all 32 byte pairs    |
//!
//! # Why equal instruction counts are not equal time
//!
//! [`balanced_dummy`] is built so that every path retires about the same
//! number of instructions: a guess that is wrong at byte `i` does `i + 1`
//! real compare steps and then `TOKEN_LEN - 1 - i` dummy steps, so every
//! wrong guess performs [`TOKEN_LEN`] steps in total. That is a statement
//! about how many instructions run, not about how long they take. A modern
//! core does not charge a fixed price per instruction:
//!
//! * **Branch prediction and speculative execution.** The core guesses the
//!   outcome of every conditional branch and runs ahead speculatively. The
//!   early-exit branch is "not taken" 31 times and "taken" once; where the
//!   taken branch lands (byte 0 or byte 31) changes how many predictions
//!   were right, and a wrong prediction throws away about 15 to 20 cycles
//!   of speculative work. The dummy loop has its own branch, with its own
//!   trip count that depends on the secret position, so its predictor
//!   state also differs by path. Equal instruction counts, different
//!   numbers of mispredictions.
//! * **Cache and TLB state.** A real step loads two bytes from the token
//!   buffers; a dummy step touches only the stack. Which cache lines (and
//!   which page-table entries in the TLB) are warm afterwards therefore
//!   depends on where the loop stopped, and a later request pays for it.
//! * **Data-dependent instruction latency.** Loads, XORs and compares have
//!   fixed latency on current cores, but integer division and, on some
//!   cores, some multiplies finish sooner for small operands. A filler
//!   block that used division would take a time that depends on the values
//!   it divides. The dummy step here deliberately uses only NOT, add,
//!   compare and stack traffic for that reason.
//! * **Dependency chains (instruction-level parallelism).** A core runs
//!   independent instructions side by side, so time follows the longest
//!   chain of instructions that wait on each other, not the count. Measured
//!   while building this crate: a first version of the filler carried one
//!   value from step to step through a stack slot (store, reload, XOR,
//!   store again). Each step was 11 instructions, exactly like a real step,
//!   yet 31 filler steps took about 70 ns against about 27 ns for 31 real
//!   steps (bare medians 92 ns versus 49 ns, release build, 4-CPU Xeon VM),
//!   so the fast-fail path became the SLOW one and leaked in the opposite
//!   direction. The current filler has no step-to-step chain.
//! * **Frequency scaling and SMT contention.** The clock speed moves with
//!   temperature and power draw, and a sibling hyperthread shares the
//!   execution ports. Two instruction streams of equal length but
//!   different mix (loads versus ALU operations) contend differently for
//!   those ports, and power draw depends on the instruction mix too.
//!
//! Even with all of that tuned (the current filler: 11 instructions per
//! step, same as a real step, no chain, no multiply or divide), the
//! release-build measurement still separates a guess wrong at byte 0 from
//! one wrong at byte 31 (see the crate docs for the numbers). Equal counts
//! narrowed the gap; they did not close it.
//!
//! [`constant_time`] avoids the whole question by not having two paths: the
//! instruction stream, the memory addresses touched and the branch history
//! are the same for every input. That is the only one of the three whose
//! timing argument does not depend on microarchitectural details.
//!
//! # Why `core::hint::black_box`
//!
//! The dummy work in [`balanced_dummy`] computes a value nobody uses. An
//! optimizing compiler is entitled to delete such code, and LLVM does:
//! [`crate::naive::balanced_dummy_no_black_box`] is the same function
//! without `black_box`, and its release build contains no dummy loop at all
//! (see `examples/verify.rs`, which disassembles both). `black_box` tells
//! the compiler "assume this value is observed", so the work survives.
//! It is a hint, not a guarantee; the disassembly check is the evidence.

use core::hint::black_box;
use subtle::{Choice, ConstantTimeEq};

/// Length of the token every validator compares, in bytes.
pub const TOKEN_LEN: usize = 32;

/// Largest number of dummy steps [`balanced_dummy`] runs for one request
/// (a guess wrong at byte 0). This is the extra, attacker-triggerable work
/// on every fast-fail.
pub const MAX_DUMMY_STEPS: usize = TOKEN_LEN - 1;

/// Which validator a [`crate::PipelineGate`] runs. A closed set, so it is
/// safe to use as a metric label.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Validator {
    /// [`early_exit`]: the leaky baseline. Measurement only.
    EarlyExit,
    /// [`balanced_dummy`]: equal step counts, unequal paths. Measurement
    /// only.
    BalancedDummy,
    /// [`constant_time`]: the production choice and the default.
    ConstantTime,
}

impl Validator {
    /// Every validator, in a fixed order.
    pub const ALL: [Validator; 3] = [
        Validator::EarlyExit,
        Validator::BalancedDummy,
        Validator::ConstantTime,
    ];

    /// Closed-set metric label.
    pub const fn label(self) -> &'static str {
        match self {
            Validator::EarlyExit => "early_exit",
            Validator::BalancedDummy => "balanced_dummy",
            Validator::ConstantTime => "constant_time",
        }
    }

    /// Whether this validator has secret-dependent control flow.
    pub const fn is_leaky(self) -> bool {
        !matches!(self, Validator::ConstantTime)
    }

    /// Run this validator. `true` means the tokens are equal.
    ///
    /// For [`Validator::ConstantTime`] the `Choice` is converted to `bool`
    /// only here, at the single point where the caller needs a decision.
    /// The decision is the response itself, so branching on it afterwards
    /// reveals nothing the response does not.
    #[inline]
    pub fn run(self, expected: &[u8; TOKEN_LEN], candidate: &[u8; TOKEN_LEN]) -> bool {
        match self {
            Validator::EarlyExit => early_exit(expected, candidate),
            Validator::BalancedDummy => balanced_dummy(expected, candidate),
            Validator::ConstantTime => bool::from(constant_time(expected, candidate)),
        }
    }
}

/// (a) The leaky baseline: compare byte by byte, stop at the first
/// difference.
///
/// Run time grows with the length of the matching prefix, so an attacker
/// who times many guesses can recover the token one byte at a time (about
/// 256 guesses per byte instead of 2^256 for the whole token). Do not use
/// outside measurement.
///
/// Each byte is read through `black_box`. Without it, LLVM may turn this
/// 32-byte loop into two fixed 16-byte vector compares, which happens to be
/// close to constant time and would hide the leak this baseline is meant to
/// show. That rewrite is an optimizer choice, not a guarantee; a longer or
/// differently shaped loop keeps its early exit.
#[inline(never)]
pub fn early_exit(expected: &[u8; TOKEN_LEN], candidate: &[u8; TOKEN_LEN]) -> bool {
    let mut i = 0;
    while i < TOKEN_LEN {
        probe::real_step();
        if black_box(expected[i]) != black_box(candidate[i]) {
            return false;
        }
        i += 1;
    }
    true
}

/// (b) The brief's design: early exit, then filler work so that every path
/// retires about the same number of instructions.
///
/// A guess wrong at byte `i` performs `i + 1` real compare steps and then
/// `TOKEN_LEN - 1 - i` dummy steps; a correct guess performs `TOKEN_LEN`
/// real steps. Every path therefore performs [`TOKEN_LEN`] steps, and the
/// dummy step is shaped to retire the same number of instructions as a real
/// step: two bytes forced through a stack slot by `black_box` and compared,
/// then a loop test. In the release build inspected (Rust 1.94, x86_64) both
/// loop bodies are 11 instructions, and a whole call retires 368
/// instructions for a guess wrong at byte 0, 362 for one wrong at byte 31
/// and 359 for a match (hand count from the disassembly, counting the
/// alignment no-ops that execute). For comparison, [`early_exit`] retires
/// 15 and 356. `examples/verify.rs` prints the loop-body counts under
/// `disassembly`.
///
/// Still secret-dependent: the exit branch, the dummy loop's trip count and
/// the mix of loads versus ALU work all depend on where the first wrong
/// byte is. See the module docs for why equal counts are not equal time.
///
/// Denial-of-service cost: every fast-fail runs up to [`MAX_DUMMY_STEPS`]
/// (31) dummy steps that an attacker can trigger at will with a guess wrong
/// at byte 0: 341 extra instructions per request (31 steps of 11), about
/// 17 ns of bare median time and about 29 ns of CPU per request through
/// the gate on the machine measured (see the crate docs). The work is
/// bounded and per request, so it cannot be amplified, but it is CPU the
/// attacker chooses to spend on the server's side.
///
/// The dummy work cannot be put under a budget: a budget that ran out
/// would switch the dummy off, the fast path would become fast again, and
/// an attacker who floods until the budget is gone would get the leak back.
#[inline(never)]
pub fn balanced_dummy(expected: &[u8; TOKEN_LEN], candidate: &[u8; TOKEN_LEN]) -> bool {
    let mut i = 0;
    while i < TOKEN_LEN {
        probe::real_step();
        if black_box(expected[i]) != black_box(candidate[i]) {
            dummy_block(TOKEN_LEN - 1 - i);
            return false;
        }
        i += 1;
    }
    true
}

/// The filler for [`balanced_dummy`]: `steps` rounds of arithmetic whose
/// result is handed to `black_box` so the compiler must keep it. `steps` is
/// at most [`MAX_DUMMY_STEPS`] because the caller derives it from a byte
/// index below [`TOKEN_LEN`]; the `min` makes the bound local.
#[inline(always)]
fn dummy_block(steps: usize) {
    let steps = steps.min(MAX_DUMMY_STEPS);
    let mut hits: u8 = 0;
    let mut j = 0;
    while j < steps {
        probe::dummy_step();
        // Two values forced through memory, like the two token bytes of a
        // real step, then a compare, like the real comparison. Neither
        // value depends on the previous step, so, like the real steps, the
        // iterations can overlap in the pipeline.
        let x = black_box(j as u8);
        let y = black_box(!x);
        if x == y {
            hits = hits.wrapping_add(1);
        }
        j += 1;
    }
    black_box(hits);
}

/// (c) The constant-time validator.
///
/// * Fixed iteration count: the loop always runs [`TOKEN_LEN`] times, the
///   full maximum length (inputs of any other length never reach it; the
///   gate rejects them by length alone).
/// * No early exit and no secret-dependent branch: differences are
///   accumulated with XOR then bitwise OR into one byte.
/// * No secret-dependent memory index: the only index is the loop counter.
/// * One decision at the end, through `subtle::ConstantTimeEq`, returned as
///   a `subtle::Choice` so the caller decides when to turn it into a
///   `bool`.
///
/// What this does not prove: a compiler is free to reintroduce a branch
/// (for example, exiting once the accumulator is all ones). LLVM does not
/// do so for this loop in the build measured here, and `examples/verify.rs`
/// checks the disassembly for conditional branches, but only formal tools
/// (ct-verif, binsec/rel) could prove it, and those are not available in
/// this workspace. The evidence produced is statistical plus one
/// disassembly inspection.
#[inline(never)]
pub fn constant_time(expected: &[u8; TOKEN_LEN], candidate: &[u8; TOKEN_LEN]) -> Choice {
    let mut diff: u8 = 0;
    let mut i = 0;
    while i < TOKEN_LEN {
        probe::ct_step();
        diff |= expected[i] ^ candidate[i];
        i += 1;
    }
    diff.ct_eq(&0u8)
}

/// Step counters for tests. Under `cfg(test)` each validator step bumps a
/// thread-local counter so a unit test can prove there is no early return;
/// in every other build the calls are empty and compile to nothing.
#[cfg(test)]
pub(crate) mod probe {
    use std::cell::Cell;

    thread_local! {
        static REAL: Cell<u64> = const { Cell::new(0) };
        static DUMMY: Cell<u64> = const { Cell::new(0) };
        static CT: Cell<u64> = const { Cell::new(0) };
    }

    /// Counts read by [`take`].
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
    pub(crate) struct Counts {
        pub real: u64,
        pub dummy: u64,
        pub ct: u64,
    }

    pub(crate) fn real_step() {
        REAL.with(|c| c.set(c.get() + 1));
    }

    pub(crate) fn dummy_step() {
        DUMMY.with(|c| c.set(c.get() + 1));
    }

    pub(crate) fn ct_step() {
        CT.with(|c| c.set(c.get() + 1));
    }

    /// Read and zero all counters of the calling thread.
    pub(crate) fn take() -> Counts {
        Counts {
            real: REAL.with(|c| c.replace(0)),
            dummy: DUMMY.with(|c| c.replace(0)),
            ct: CT.with(|c| c.replace(0)),
        }
    }
}

#[cfg(not(test))]
pub(crate) mod probe {
    #[inline(always)]
    pub(crate) fn real_step() {}
    #[inline(always)]
    pub(crate) fn dummy_step() {}
    #[inline(always)]
    pub(crate) fn ct_step() {}
}

#[cfg(test)]
mod tests {
    use super::*;

    // Test fixture, not a key.
    const SECRET: [u8; TOKEN_LEN] = [0x42; TOKEN_LEN];

    fn wrong_at(pos: usize) -> [u8; TOKEN_LEN] {
        let mut c = SECRET;
        c[pos] ^= 0x01;
        c
    }

    #[test]
    fn constant_time_always_runs_the_full_length() {
        let _ = probe::take();
        for pos in 0..TOKEN_LEN {
            let r = constant_time(&SECRET, &wrong_at(pos));
            assert!(!bool::from(r));
            let c = probe::take();
            assert_eq!(c.ct, TOKEN_LEN as u64, "wrong at {pos}");
            assert_eq!((c.real, c.dummy), (0, 0));
        }
        assert!(bool::from(constant_time(&SECRET, &SECRET)));
        assert_eq!(probe::take().ct, TOKEN_LEN as u64);
        // Every byte wrong: still exactly TOKEN_LEN steps.
        let _ = constant_time(&SECRET, &[0u8; TOKEN_LEN]);
        assert_eq!(probe::take().ct, TOKEN_LEN as u64);
    }

    #[test]
    fn early_exit_stops_at_first_difference() {
        // Shows the probe can see an early return, so the constant-time
        // test above is not vacuous.
        let _ = probe::take();
        for pos in 0..TOKEN_LEN {
            assert!(!early_exit(&SECRET, &wrong_at(pos)));
            let c = probe::take();
            assert_eq!(c.real, pos as u64 + 1);
            assert_eq!(c.dummy, 0);
        }
    }

    #[test]
    fn balanced_dummy_performs_token_len_steps_on_every_path() {
        let _ = probe::take();
        for pos in 0..TOKEN_LEN {
            assert!(!balanced_dummy(&SECRET, &wrong_at(pos)));
            let c = probe::take();
            assert_eq!(c.real, pos as u64 + 1, "wrong at {pos}");
            assert_eq!(c.dummy, (TOKEN_LEN - 1 - pos) as u64, "wrong at {pos}");
            assert_eq!(c.real + c.dummy, TOKEN_LEN as u64);
        }
        assert!(balanced_dummy(&SECRET, &SECRET));
        let c = probe::take();
        assert_eq!((c.real, c.dummy), (TOKEN_LEN as u64, 0));
    }

    #[test]
    fn dummy_block_is_capped() {
        let _ = probe::take();
        dummy_block(usize::MAX);
        assert_eq!(probe::take().dummy, MAX_DUMMY_STEPS as u64);
    }

    #[test]
    fn labels_are_distinct() {
        let labels: Vec<_> = Validator::ALL.iter().map(|v| v.label()).collect();
        assert_eq!(labels, ["early_exit", "balanced_dummy", "constant_time"]);
        assert!(Validator::EarlyExit.is_leaky());
        assert!(Validator::BalancedDummy.is_leaky());
        assert!(!Validator::ConstantTime.is_leaky());
    }
}
