//! dudect-style timing measurement.
//!
//! How one run works:
//! 1. A seeded splitmix64 generator draws the class (A or B) of every sample
//!    before any timing starts. Classes are therefore interleaved at random
//!    in time, so slow drift (frequency scaling, a neighbour process waking
//!    up) hits both classes equally instead of looking like a leak.
//! 2. `warmup` untimed-for-the-report iterations run first (caches, branch
//!    predictors, lazy page faults, CPU frequency ramp).
//! 3. Samples are processed in batches of `config.batch`. For each batch,
//!    `prepare(class, rng)` first builds every input of the batch OUTSIDE
//!    the timed region; then each input is fed to `operation(&input)` and
//!    only that call is timed. Input and output are passed through
//!    `std::hint::black_box` so the optimizer can neither hoist the work out
//!    of the timed region nor delete it. Outputs are dropped after the end
//!    timestamp; inputs are dropped when the batch is cleared.
//!
//!    Why batches: preparing an input immediately before timing it leaves
//!    class-dependent residue in the CPU (store buffer contents, store to
//!    load forwarding, branch history, cache lines touched by the input
//!    generator). The calibration run on this crate's development machine
//!    showed exactly that: with `batch = 1`, a `subtle` constant-time
//!    compare of a fixed token against random tokens gave |t| above 200
//!    because class B's input bytes had just been written by the generator.
//!    dudect avoids this by preparing all inputs up front; batching does the
//!    same with bounded memory.
//! 4. The samples are handed to [`crate::report::analyze`].
//!
//! Nothing is emitted to telemetry inside the timed loop, so the harness
//! does not add noise that correlates with the class.

use crate::cpu;
use crate::env;
use crate::error::HarnessError;
use crate::report::{analyze, Report, RunInfo};
use serde::Serialize;
use std::hint::black_box;
use std::time::Instant;

/// Hard cap on timed samples per run. At 9 bytes per sample (an `f64` time
/// plus a one-byte class) this is at most about 180 MB.
pub const MAX_SAMPLES: usize = 20_000_000;
/// Hard cap on warm-up iterations.
pub const MAX_WARMUP: usize = 1_000_000;
/// Hard cap on the prepare-ahead batch size (inputs held in memory at once).
pub const MAX_BATCH: usize = 65_536;
/// Default prepare-ahead batch size.
pub const DEFAULT_BATCH: usize = 1_024;
/// Hard cap on the number of crop percentiles.
pub const MAX_CROP_PERCENTILES: usize = 32;
/// Default upper crop percentiles, as fractions of the pooled distribution.
pub const DEFAULT_CROP_PERCENTILES: [f64; 6] = [0.50, 0.75, 0.90, 0.95, 0.99, 0.999];
/// Default seed. A fixed seed makes class sequences and inputs reproducible;
/// it is not a secret and not a key.
pub const DEFAULT_SEED: u64 = 0x7ac4_a1c0_5eed_0001;

/// Stream separators so the class sequence, the timed inputs and the warm-up
/// inputs come from independent splitmix64 streams of one seed.
const INPUT_STREAM: u64 = 0x9e37_79b9_7f4a_7c15;
const WARMUP_STREAM: u64 = 0xd1b5_4a32_d192_ed03;

/// The two input classes being compared.
///
/// Typical use (fixed-vs-random, as in dudect and TVLA): class A gets a
/// fixed input that exercises one path (for example, the correct token),
/// class B gets a fresh random input (for example, a random wrong token).
/// For an A/A sanity run, give both classes identical treatment.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
pub enum Class {
    /// First class. Its mean is the minuend in every t statistic, so a
    /// positive t means A was slower.
    A,
    /// Second class.
    B,
}

impl Class {
    /// Closed-set metric label.
    pub const fn label(self) -> &'static str {
        match self {
            Class::A => "a",
            Class::B => "b",
        }
    }
}

/// splitmix64 pseudo-random generator (Steele, Lea, Flood 2014).
///
/// Fast, seedable, and good enough to schedule classes and build test
/// inputs. NOT cryptographic: never use it for keys or tokens outside tests.
#[derive(Debug, Clone)]
pub struct SplitMix64 {
    state: u64,
}

impl SplitMix64 {
    /// Seed a generator.
    pub const fn new(seed: u64) -> Self {
        Self { state: seed }
    }

    /// Next 64 random bits.
    pub fn next_u64(&mut self) -> u64 {
        self.state = self.state.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = self.state;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }

    /// A fair coin.
    pub fn next_bool(&mut self) -> bool {
        self.next_u64() >> 63 == 1
    }

    /// A fair class draw.
    pub fn next_class(&mut self) -> Class {
        if self.next_bool() {
            Class::B
        } else {
            Class::A
        }
    }

    /// Fill a buffer with random bytes.
    pub fn fill_bytes(&mut self, out: &mut [u8]) {
        for chunk in out.chunks_mut(8) {
            let bytes = self.next_u64().to_le_bytes();
            let n = chunk.len();
            chunk.copy_from_slice(&bytes[..n]);
        }
    }

    /// A random byte array (handy for fixed-size tokens).
    pub fn bytes<const N: usize>(&mut self) -> [u8; N] {
        let mut out = [0u8; N];
        self.fill_bytes(&mut out);
        out
    }
}

/// Which clock times each sample.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Default)]
pub enum Timer {
    /// `std::time::Instant` (on Linux, `clock_gettime(CLOCK_MONOTONIC)`
    /// through the vDSO). Portable. Samples are in nanoseconds. The clock
    /// itself costs roughly 20 to 50 ns, which is added equally to both
    /// classes.
    #[default]
    Instant,
    /// The x86_64 time-stamp counter, read between `lfence` barriers.
    /// Samples are in reference cycles. Finer grained than `Instant`; on
    /// other architectures `measure_pair` returns
    /// `HarnessError::Unsupported`.
    Rdtsc,
}

/// Unit of the samples in a [`Report`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum TimeUnit {
    /// Nanoseconds (from [`Timer::Instant`]).
    Nanoseconds,
    /// Time-stamp counter ticks (from [`Timer::Rdtsc`]).
    Cycles,
    /// Caller-supplied samples given to `analyze` in some other unit.
    Other,
}

impl Timer {
    /// The unit this timer produces.
    pub const fn unit(self) -> TimeUnit {
        match self {
            Timer::Instant => TimeUnit::Nanoseconds,
            Timer::Rdtsc => TimeUnit::Cycles,
        }
    }

    /// Whether this timer works on the current target.
    pub const fn is_supported(self) -> bool {
        match self {
            Timer::Instant => true,
            Timer::Rdtsc => cfg!(target_arch = "x86_64"),
        }
    }
}

/// Configuration for one [`measure_pair`] run. Every field has a hard bound
/// checked by [`MeasureConfig::validate`]; out-of-bound values are rejected,
/// never clamped.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct MeasureConfig {
    /// Total timed samples across both classes. Each class gets about half.
    /// Default 100_000. Bounds: 4 ..= [`MAX_SAMPLES`].
    pub samples: usize,
    /// Warm-up iterations run before timing; their times are discarded.
    /// Default 1_000. Bounds: 0 ..= [`MAX_WARMUP`].
    pub warmup: usize,
    /// Seed for the class sequence and for the `rng` handed to `prepare`.
    /// Default [`DEFAULT_SEED`].
    pub seed: u64,
    /// Upper crop percentiles as fractions strictly between 0 and 1.
    /// Default [`DEFAULT_CROP_PERCENTILES`]. At most
    /// [`MAX_CROP_PERCENTILES`] entries; may be empty.
    pub crop_percentiles: Vec<f64>,
    /// Clock used for timing. Default [`Timer::Instant`].
    pub timer: Timer,
    /// Minimum samples per class for a verdict other than `Inconclusive`.
    /// Default 1_000. Bounds: 2 ..= `samples`.
    pub min_per_class: u64,
    /// How many inputs are prepared ahead of timing. Memory held at once is
    /// `batch * size_of::<I>()` plus whatever each input owns. Default
    /// [`DEFAULT_BATCH`]. Bounds: 1 ..= [`MAX_BATCH`]. `1` means prepare
    /// immediately before each timed call (not recommended, see module
    /// docs).
    pub batch: usize,
}

impl Default for MeasureConfig {
    fn default() -> Self {
        Self {
            samples: 100_000,
            warmup: 1_000,
            seed: DEFAULT_SEED,
            crop_percentiles: DEFAULT_CROP_PERCENTILES.to_vec(),
            timer: Timer::Instant,
            min_per_class: 1_000,
            batch: DEFAULT_BATCH,
        }
    }
}

impl MeasureConfig {
    /// Default config with a different total sample count. `min_per_class`
    /// is lowered to `samples / 4` if the default would not fit.
    pub fn with_samples(samples: usize) -> Self {
        let d = Self::default();
        let quarter = u64::try_from(samples / 4).unwrap_or(u64::MAX).max(2);
        Self {
            samples,
            min_per_class: d.min_per_class.min(quarter),
            ..d
        }
    }

    /// Check every bound. Called by `measure_pair` before any work.
    pub fn validate(&self) -> Result<(), HarnessError> {
        let bad = |field, reason| Err(HarnessError::InvalidConfig { field, reason });
        if self.samples < 4 {
            return bad("samples", "must be at least 4");
        }
        if self.samples > MAX_SAMPLES {
            return bad("samples", "exceeds MAX_SAMPLES");
        }
        if self.warmup > MAX_WARMUP {
            return bad("warmup", "exceeds MAX_WARMUP");
        }
        validate_crop_percentiles(&self.crop_percentiles)?;
        if self.batch == 0 {
            return bad("batch", "must be at least 1");
        }
        if self.batch > MAX_BATCH {
            return bad("batch", "exceeds MAX_BATCH");
        }
        if self.min_per_class < 2 {
            return bad("min_per_class", "must be at least 2");
        }
        if u64::try_from(self.samples).map_or(true, |s| self.min_per_class > s) {
            return bad("min_per_class", "exceeds samples");
        }
        if !self.timer.is_supported() {
            return Err(HarnessError::Unsupported("timer"));
        }
        Ok(())
    }
}

/// Shared bound check for crop percentiles (also used by `analyze`).
pub(crate) fn validate_crop_percentiles(ps: &[f64]) -> Result<(), HarnessError> {
    if ps.len() > MAX_CROP_PERCENTILES {
        return Err(HarnessError::InvalidConfig {
            field: "crop_percentiles",
            reason: "more than MAX_CROP_PERCENTILES entries",
        });
    }
    if ps.iter().any(|p| !(*p > 0.0 && *p < 1.0)) {
        return Err(HarnessError::InvalidConfig {
            field: "crop_percentiles",
            reason: "each must be strictly between 0 and 1",
        });
    }
    Ok(())
}

#[cfg(target_arch = "x86_64")]
#[allow(unsafe_code)]
#[inline(always)]
fn read_tsc() -> u64 {
    // SAFETY: `_mm_lfence` and `_rdtsc` read no memory and have no
    // preconditions beyond CPU support. `lfence` needs SSE2 and `rdtsc` is
    // present on every x86_64 CPU; SSE2 is part of the x86_64 baseline, so
    // both instructions exist on any machine this code can run on. The
    // fences stop the counter read from being reordered around the timed
    // operation.
    unsafe {
        core::arch::x86_64::_mm_lfence();
        let t = core::arch::x86_64::_rdtsc();
        core::arch::x86_64::_mm_lfence();
        t
    }
}

#[cfg(not(target_arch = "x86_64"))]
#[inline(always)]
fn read_tsc() -> u64 {
    // Unreachable in practice: `validate` rejects `Timer::Rdtsc` here.
    0
}

/// Time one call of `operation` on `input`. Only the call is inside the
/// timed region; the output is dropped after the end timestamp.
#[inline(always)]
fn time_once<I, R, O>(timer: Timer, operation: &mut O, input: &I) -> f64
where
    O: FnMut(&I) -> R,
{
    match timer {
        Timer::Instant => {
            let start = Instant::now();
            let out = black_box(operation(black_box(input)));
            let end = Instant::now();
            drop(out);
            end.duration_since(start).as_nanos() as f64
        }
        Timer::Rdtsc => {
            let start = read_tsc();
            let out = black_box(operation(black_box(input)));
            let end = read_tsc();
            drop(out);
            end.saturating_sub(start) as f64
        }
    }
}

/// Prepare each batch of inputs ahead, then time each call. Pushes one time
/// per class into `out` when given; warm-up passes `None`.
fn run_batched<I, R, P, O>(
    timer: Timer,
    batch: usize,
    classes: &[Class],
    rng: &mut SplitMix64,
    prepare: &mut P,
    operation: &mut O,
    mut out: Option<&mut Vec<f64>>,
) where
    P: FnMut(Class, &mut SplitMix64) -> I,
    O: FnMut(&I) -> R,
{
    let mut inputs: Vec<I> = Vec::with_capacity(batch.min(classes.len()));
    for chunk in classes.chunks(batch.max(1)) {
        inputs.clear();
        inputs.extend(chunk.iter().map(|&c| prepare(c, rng)));
        for input in &inputs {
            let t = time_once(timer, operation, input);
            match out.as_deref_mut() {
                Some(v) => v.push(t),
                None => {
                    black_box(t);
                }
            }
        }
    }
}

/// Measure whether `operation`'s run time depends on the input class.
///
/// * `config`: bounds and knobs, see [`MeasureConfig`].
/// * `prepare(class, rng) -> I`: builds the input for one sample. Runs
///   outside the timed region, a batch at a time (see
///   [`MeasureConfig::batch`]), in the same order as the timed calls. Use `rng` (seeded from `config.seed`) for any
///   randomness so runs are reproducible.
/// * `operation(&I) -> R`: the code under test. Only this call is timed.
///   Its result is kept alive with `black_box` so it is not optimised away.
///
/// Returns a [`Report`]; call [`Report::verdict`] with
/// [`crate::T_THRESHOLD`] to get a pass or fail. Errors only on an invalid
/// config or unsupported timer, before any timing is done.
///
/// A panic in `prepare` or `operation` propagates to the caller; the
/// harness does not catch it.
pub fn measure_pair<I, R, P, O>(
    config: &MeasureConfig,
    mut prepare: P,
    mut operation: O,
) -> Result<Report, HarnessError>
where
    P: FnMut(Class, &mut SplitMix64) -> I,
    O: FnMut(&I) -> R,
{
    let span = tracing::info_span!(
        "tack.anc_harness.measure",
        samples = config.samples,
        warmup = config.warmup,
        timer = ?config.timer,
    );
    let _guard = span.enter();

    if let Err(e) = config.validate() {
        let outcome = match e {
            HarnessError::Unsupported(_) => "unsupported",
            _ => "invalid_config",
        };
        metrics::counter!("tack_anc_harness_runs_total", "outcome" => outcome).increment(1);
        tracing::warn!(error = %e, "harness config rejected");
        return Err(e);
    }
    let timer = config.timer;

    // 1. Class schedule, drawn before any timing.
    let mut class_rng = SplitMix64::new(config.seed);
    let classes: Vec<Class> = (0..config.samples)
        .map(|_| class_rng.next_class())
        .collect();

    let env_before = env::snapshot();

    // 2. Warm-up on an independent stream so the warm-up length does not
    //    change the timed inputs.
    let mut warm_rng = SplitMix64::new(config.seed ^ WARMUP_STREAM);
    let warm_classes: Vec<Class> = (0..config.warmup).map(|_| warm_rng.next_class()).collect();
    run_batched(
        timer,
        config.batch,
        &warm_classes,
        &mut warm_rng,
        &mut prepare,
        &mut operation,
        None,
    );
    drop(warm_classes);

    // 3. Timed loop.
    let mut input_rng = SplitMix64::new(config.seed ^ INPUT_STREAM);
    let mut samples: Vec<f64> = Vec::with_capacity(config.samples);
    let thread_cpu_before = cpu::thread_cpu_time().ok();
    let process_cpu_before = cpu::process_cpu_time().ok();
    let wall_start = Instant::now();
    run_batched(
        timer,
        config.batch,
        &classes,
        &mut input_rng,
        &mut prepare,
        &mut operation,
        Some(&mut samples),
    );
    let wall = wall_start.elapsed();
    let thread_cpu = thread_cpu_before
        .zip(cpu::thread_cpu_time().ok())
        .map(|(b, a)| a.since(&b).total().as_secs_f64());
    let process_cpu = process_cpu_before
        .zip(cpu::process_cpu_time().ok())
        .map(|(b, a)| a.since(&b).total().as_secs_f64());

    // 4. Analysis and telemetry, after all timing is done.
    let mut report = analyze(
        &classes,
        &samples,
        timer.unit(),
        &config.crop_percentiles,
        config.min_per_class,
    )?;
    let wall_seconds = wall.as_secs_f64();
    report.run = Some(RunInfo {
        timer,
        seed: config.seed,
        warmup: config.warmup,
        wall_seconds,
        thread_cpu_seconds: thread_cpu,
        process_cpu_seconds: process_cpu,
        thread_cpu_utilization: thread_cpu
            .filter(|_| wall_seconds > 0.0)
            .map(|c| c / wall_seconds),
        env: env_before,
    });

    metrics::counter!("tack_anc_harness_runs_total", "outcome" => "completed").increment(1);
    metrics::counter!("tack_anc_harness_samples_total", "class" => Class::A.label())
        .increment(report.n_a);
    metrics::counter!("tack_anc_harness_samples_total", "class" => Class::B.label())
        .increment(report.n_b);
    metrics::histogram!("tack_anc_harness_run_seconds").record(wall_seconds);
    tracing::info!(
        n_a = report.n_a,
        n_b = report.n_b,
        max_abs_t = report.max_abs_t,
        wall_seconds,
        "harness run complete"
    );
    Ok(report)
}
