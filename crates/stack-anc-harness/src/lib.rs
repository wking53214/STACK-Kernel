//! stack-anc-harness: the statistical engine that every TACK ANC (Active
//! Timing Cancellation) strategy is verified with.
//!
//! Status: new design. This crate is test tooling; nothing in the TACK
//! runtime links it in production.
//!
//! # What it answers
//!
//! "Does the run time of this operation depend on which of two input
//! classes it was given?" If it does, an attacker who can time requests
//! learns something about the input (for example, how many leading bytes of
//! a guessed token were right). ANC strategies try to make the answer "no";
//! this harness checks them.
//!
//! # Method (dudect, Reparaz, Balasch, Verbauwhede 2017; TVLA threshold)
//!
//! 1. Draw a random A/B class for every sample up front with a seeded
//!    splitmix64, so the two classes are interleaved in time and share the
//!    same machine noise.
//! 2. Warm up, then build a batch of inputs outside the timed region and
//!    time only the operation on each.
//! 3. Compare the two timing distributions with Welch's t test on all
//!    samples, on several upper-cropped subsets (to see past interrupt
//!    tails), and on centered squared samples (differences in spread).
//!    Also report the Kolmogorov-Smirnov D and p as a distribution-free
//!    cross-check.
//! 4. Leak if the largest |t| exceeds [`T_THRESHOLD`] (4.5).
//!
//! # Quick use
//!
//! ```
//! use sstack_anc_harness::{measure_pair, MeasureConfig, Class, T_THRESHOLD};
//! use sstack_anc_harness::victim::{ct_validate, TOKEN_LEN};
//!
//! // Test fixture, not a real key or token.
//! let secret = [0x42u8; TOKEN_LEN];
//! let cfg = MeasureConfig::with_samples(2_000);
//! let report = measure_pair(
//!     &cfg,
//!     |class, rng| match class {
//!         Class::A => secret,                        // fixed: correct token
//!         Class::B => rng.bytes::<TOKEN_LEN>(),      // random: wrong token
//!     },
//!     |candidate| ct_validate(&secret, candidate),
//! ).unwrap();
//! let verdict = report.verdict(T_THRESHOLD);
//! println!("{verdict:?} max|t|={}", report.max_abs_t);
//! ```
//!
//! # Reading a verdict
//!
//! * `NoLeakDetected` maps to CNS `PASS`. It means "not detected at this n
//!   on this machine", not "proven constant time". Small leaks need large n.
//! * `LeakDetected` maps to `TERMINAL_BREACH` for the build under test.
//! * `Inconclusive` maps to `RETRY`: collect more samples.
//!
//! False positives: the verdict takes the max over roughly 8 statistics, so
//! the family-wise false positive rate at 4.5 is higher than the single
//! test's (about 7e-6 under a normal model), though still small; noisy
//! shared machines raise it further. `examples/calibrate.rs` measures it
//! with repeated A/A runs.

pub mod cpu;
pub mod env;
pub mod error;
pub mod measure;
pub mod report;
pub mod stats;
pub mod victim;

pub use error::HarnessError;
pub use measure::{
    measure_pair, Class, MeasureConfig, SplitMix64, TimeUnit, Timer, DEFAULT_BATCH,
    DEFAULT_CROP_PERCENTILES, DEFAULT_SEED, MAX_BATCH, MAX_CROP_PERCENTILES, MAX_SAMPLES,
    MAX_WARMUP,
};
pub use report::{
    analyze, ClassSummary, CroppedT, GateOutcome, InconclusiveReason, Report, RunInfo, Statistic,
    Verdict,
};

/// The TVLA leak threshold on |t|. Above it, the two classes are treated
/// as distinguishable.
pub const T_THRESHOLD: f64 = 4.5;
