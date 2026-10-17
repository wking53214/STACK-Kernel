//! # tack-inlet: the Inlet Winnowing Filter
//!
//! **Status: new design.** Of the seven components of the TACK governance
//! kernel, only the Sentinel Hash-Chain exists today (in `sentinel_os`). The
//! Inlet Winnowing Filter did not exist in any TACK repository before this
//! crate; this is its reference implementation.
//!
//! ## The metaphor
//!
//! A combine harvester has a grain inlet with a winnowing fan. The fan blows
//! the light chaff away before anything reaches the threshing drum, so the
//! drum only ever sees grain. This crate is that fan for the kernel: it sits
//! at the boundary and blows away malformed or dangerous text before any
//! other component sees it.
//!
//! ## The goal
//!
//! Two promises:
//!
//! 1. Nothing malformed or dangerous crosses the kernel boundary. "Malformed"
//!    means not valid UTF-8. "Dangerous" means a fixed list of character
//!    classes used to disguise text, taken from Unicode 16.0 properties:
//!    control characters and the line and paragraph separators, all twelve
//!    `Bidi_Control` characters (the overrides behind the Trojan Source
//!    attack and the implicit marks), every invisible
//!    `Default_Ignorable_Code_Point` (zero-width characters, tag characters,
//!    variation selectors, Hangul fillers and the rest), and Unicode
//!    noncharacters. See [`Reason`] for the exact code points.
//! 2. The check itself cannot be turned into a weapon. A filter that takes
//!    quadratic time, recurses, or allocates memory sized by a number the
//!    attacker chose is itself an attack surface. This one does a fixed
//!    amount of work per byte, uses a fixed amount of memory, refuses
//!    anything over a length cap before reading it, and caps the number of
//!    chunks a stream may arrive in ([`StreamConfig::max_chunks`], default
//!    4096), so the sender's framing cannot multiply the work either.
//!
//! ## The design
//!
//! Three stages, in order:
//!
//! 1. **Length precheck.** The input's length is compared with
//!    [`InletConfig::max_len`] (default 64 KiB) before a single body byte is
//!    read. Too long means [`Reason::Oversize`] and a `RETRY` verdict. A
//!    caller that knows a declared length (for example an HTTP
//!    `Content-Length`) can call [`Inlet::precheck`] before reading the body
//!    at all.
//! 2. **The automaton.** A table-driven deterministic finite automaton reads
//!    the input once, byte by byte. It checks UTF-8 structure (rejecting
//!    overlong encodings, surrogates, code points above U+10FFFF and
//!    truncated sequences) and the banned classes in the same pass. See the
//!    `dfa` module source for how the table is built.
//! 3. **The verdict.** A [`Verdict`] carries the CNS outcome, the state
//!    resolution, the reason and byte offset of the first violation, the
//!    number of violations, every distinct reason seen, and the full SHA-256
//!    of the bytes judged.
//!
//! ### Scan the whole input, always
//!
//! The automaton does not stop at the first violation. It scans the whole
//! (capped) input, recording the first offset and counting the rest. The
//! point is timing: with early exit, an input with a bad byte at offset 10
//! is refused much faster than one with a bad byte at offset 60,000, so an
//! observer timing the refusals learns where the bad byte is, and can probe
//! byte by byte. With a full scan, time depends on length only. The cost is
//! that hostile input is always scanned in full, so a flood of bad inputs
//! costs as much CPU as a flood of good ones of the same length. The length
//! cap bounds that cost. The measured numbers are in the `timing` test.
//!
//! ### Refuse, do not repair
//!
//! The inlet never cleans an input and passes the cleaned copy on. Contrast
//! `sanitize_context` in `observe-perceive`, which drops bad values and
//! continues. The CNS gate contract says a failing query is aborted rather
//! than repaired, and a filter that silently rewrites input changes what the
//! downstream components judge without anyone deciding that. The inlet
//! refuses, says why and where, and leaves the correction to the sender.
//!
//! ## Outcomes and resolutions
//!
//! The inlet is an `ALPHA` gate: it runs before any work starts.
//!
//! | Trip | Outcome | Resolution | Why |
//! |---|---|---|---|
//! | [`Reason::Oversize`] | `RETRY` | reject | Nothing was read; a shorter input may pass. |
//! | [`Reason::ChunkLimit`] | `RETRY` | reject | The stream came in more pieces than allowed; resending in larger chunks may pass. |
//! | [`Reason::Truncated`], [`Reason::UnexpectedContinuation`], [`Reason::InvalidByte`], [`Reason::Surrogate`], [`Reason::AboveMax`] | `RETRY` | reject | Encoding faults that honest but buggy clients produce (split buffers, Latin-1 mislabelled as UTF-8, CESU-8). Re-encoding repairs them. |
//! | [`Reason::C0Control`], [`Reason::DelOrC1Control`], [`Reason::ZeroWidth`], [`Reason::BidiMark`], [`Reason::Noncharacter`] | `RETRY` | reject | Characters that honest text sometimes carries (a pasted terminal escape, an editor's BOM, a zero-width joiner or variation selector inside an emoji, a subdivision flag built from tag characters, a right-to-left mark in Arabic or Hebrew text). Removing them repairs the input. |
//! | [`Reason::Overlong`], [`Reason::BidiControl`] | `TERMINAL_BREACH` | quarantine | Their main known use is deception: an overlong form disguises a character from byte-level filters, and a bidi override makes text display differently from how it parses. |
//!
//! When an input contains several reasons, the outcome is the most final one
//! (any terminal reason makes the whole input terminal), matching the CNS
//! `resolve` precedence. The inlet never produces rollback (it holds no
//! state) or halt (a hostile input must not be able to stop it).
//!
//! A Latin-1 capital A with grave or acute accent (bytes C0 and C1) is
//! byte-identical to an overlong lead byte. The automaton looks one byte
//! ahead: C0 or C1 followed by a continuation byte (80..BF) is an overlong
//! form and terminal; followed by anything else it is a lone
//! [`Reason::InvalidByte`] and repairable. So Latin-1 text mislabelled as
//! UTF-8 draws `RETRY`, except in the rare case where A-grave or A-acute is
//! immediately followed by a byte in 80..BF (a Windows-1252 punctuation mark
//! or a Latin-1 symbol such as the inverted question mark), which is still
//! judged overlong. A deployment that ingests Latin-1
//! should transcode before the inlet.
//!
//! ## Telemetry
//!
//! See [`telemetry`] for metric names and alert rules. Spans are
//! `tack.inlet.winnow`, `tack.inlet.precheck` and `tack.inlet.stream`. Logs
//! carry the input's length and, when the deployment supplies a
//! [`telemetry::LogKey`], a keyed digest (HMAC-SHA256 of the SHA-256); never
//! its bytes and never its plain SHA-256, which reverses low-entropy input.
//! A stream dropped without [`Scanner::finish`] is still recorded.
//!
//! ## Where timing can still leak (kernel convention 6)
//!
//! * The pass/refuse outcome changes which log event fires (`debug` on pass,
//!   `warn` on refusal) and, with a subscriber that records `warn` but not
//!   `debug`, a refusal costs more. That reveals the outcome, which the
//!   sender learns anyway; it does not reveal where the bad byte was.
//! * The `reason_seen` counter loop runs once per distinct reason (at most
//!   14), so its cost depends on how many classes appeared, not on where.
//! * The refusal log line writes `first_offset` and `count` zero-padded to
//!   8 digits, so its size does not reveal the position of the first bad
//!   byte. Its `reason` field still varies in length with the reason, which
//!   reveals the class, not the position.
//! * A stream stopped by the chunk cap is refused after fewer bytes than a
//!   full scan, which reveals the chunk count, which the sender chose.
//! * An oversize refusal is fast, because the body is not read. That reveals
//!   only the length, which the sender chose.
//! * The per-byte loop is written without data-dependent branches, but the
//!   compiler gives no guarantee. The timing test measures instead.
//! * If a caller returns [`Verdict::first_offset`] to the sender, the sender
//!   learns the position directly and the timing care here is moot for that
//!   caller. Whether to return it is the caller's decision.
//!
//! ## Example
//!
//! ```
//! use stack_inlet::{GateOutcome, Inlet, InletConfig, Reason};
//!
//! let inlet = Inlet::new(InletConfig::default()).unwrap();
//! assert!(inlet.winnow("plain text\n".as_bytes()).is_pass());
//!
//! // A right-to-left override (U+202E) is the Trojan Source class.
//! let v = inlet.winnow("if (a) {\u{202E} }".as_bytes());
//! assert_eq!(v.outcome(), GateOutcome::TerminalBreach);
//! assert_eq!(v.reason(), Some(Reason::BidiControl));
//! assert_eq!(v.first_offset(), Some(8));
//! ```

#![forbid(unsafe_code)]
#![warn(missing_docs)]

mod config;
mod dfa;
pub mod telemetry;
mod verdict;

use std::sync::Arc;
use std::time::Instant;

use sha2::{Digest, Sha256};
use tracing::Span;

pub use config::{
    ConfigError, InletConfig, StreamConfig, DEFAULT_MAX_CHUNKS, DEFAULT_MAX_LEN,
    MAX_CHUNKS_CEILING, MAX_LEN_CEILING,
};
pub use verdict::{GateOutcome, GatePosition, Reason, ReasonSet, Resolution, Verdict, GATE_NAME};

use dfa::Dfa;
use telemetry::LogKey;

/// Number of byte classes in the automaton's transition table. Exposed for
/// documentation and tests.
pub const BYTE_CLASS_COUNT: usize = dfa::CLASS_COUNT;

/// The inlet. Cheap to clone; holds only its configuration and, if the
/// deployment supplied one, a shared log key.
#[derive(Debug, Clone)]
pub struct Inlet {
    config: InletConfig,
    stream: StreamConfig,
    log_key: Option<Arc<LogKey>>,
}

impl Inlet {
    /// Build an inlet from a checked configuration, with
    /// [`StreamConfig::default`] and no log key.
    ///
    /// # Errors
    ///
    /// Returns the [`ConfigError`] from [`InletConfig::validate`].
    pub fn new(config: InletConfig) -> Result<Self, ConfigError> {
        Self::with_stream_config(config, StreamConfig::default())
    }

    /// Build an inlet with an explicit stream configuration.
    ///
    /// # Errors
    ///
    /// Returns the [`ConfigError`] from [`InletConfig::validate`] or
    /// [`StreamConfig::validate`].
    pub fn with_stream_config(
        config: InletConfig,
        stream: StreamConfig,
    ) -> Result<Self, ConfigError> {
        config.validate()?;
        stream.validate()?;
        Ok(Self {
            config,
            stream,
            log_key: None,
        })
    }

    /// Use `key` for the `input_hmac` field of log events. Without a key,
    /// log events carry no digest at all. See [`telemetry`].
    #[must_use]
    pub fn with_log_key(mut self, key: LogKey) -> Self {
        self.log_key = Some(Arc::new(key));
        self
    }

    /// The configuration in force.
    #[must_use]
    pub const fn config(&self) -> &InletConfig {
        &self.config
    }

    /// The stream configuration in force.
    #[must_use]
    pub const fn stream_config(&self) -> &StreamConfig {
        &self.stream
    }

    /// Refuse a declared length before reading any body byte.
    ///
    /// Returns `Ok(())` when `declared_len` is within the cap; the body must
    /// still go through [`Inlet::winnow`] or a [`Scanner`], which re-check the
    /// real length. Returns the oversize verdict otherwise, and records it in
    /// telemetry. The verdict's [`Verdict::len`] is clamped to the cap plus
    /// one; the declared value appears only as the span field
    /// `declared_len`.
    ///
    /// # Errors
    ///
    /// The [`Reason::Oversize`] verdict when `declared_len` exceeds the cap.
    pub fn precheck(&self, declared_len: u64) -> Result<(), Verdict> {
        let span = tracing::info_span!("tack.inlet.precheck", declared_len);
        let _entered = span.enter();
        let started = Instant::now();
        let len = usize::try_from(declared_len).unwrap_or(usize::MAX);
        if len <= self.config.max_len {
            return Ok(());
        }
        let v = Verdict::oversize(len, self.config.max_len, 0);
        telemetry::emit(&v, started.elapsed(), self.log_key.as_deref());
        Err(v)
    }

    /// Judge one in-memory input.
    ///
    /// The length is checked first; an input over the cap is refused without
    /// reading its bytes. Otherwise the automaton scans every byte and the
    /// SHA-256 of the input is computed, whatever the input contains.
    #[must_use]
    pub fn winnow(&self, input: &[u8]) -> Verdict {
        let span = tracing::info_span!("tack.inlet.winnow", len = input.len());
        let _entered = span.enter();
        let started = Instant::now();
        let v = if input.len() > self.config.max_len {
            Verdict::oversize(input.len(), self.config.max_len, 0)
        } else {
            let mut dfa = Dfa::new();
            dfa.scan(input);
            let r = dfa.finish();
            let digest: [u8; 32] = Sha256::digest(input).into();
            Verdict::from_scan(input.len(), r.scanned, r.count, r.first, r.seen, digest)
        };
        telemetry::emit(&v, started.elapsed(), self.log_key.as_deref());
        v
    }

    /// Start a streaming scan, for input that arrives in chunks.
    ///
    /// The scanner keeps a fixed-size state (the automaton's few integers and
    /// a SHA-256 context) however much is fed to it, and it enforces the same
    /// length cap cumulatively, plus [`StreamConfig::max_chunks`] on the
    /// number of calls.
    #[must_use]
    pub fn scanner(&self) -> Scanner {
        Scanner {
            max_len: self.config.max_len,
            max_chunks: self.stream.max_chunks,
            dfa: Dfa::new(),
            hasher: Sha256::new(),
            offered: 0,
            chunks: 0,
            stopped: None,
            finished: false,
            log_key: self.log_key.clone(),
            started: Instant::now(),
            span: tracing::info_span!("tack.inlet.stream", chunks = tracing::field::Empty),
        }
    }
}

/// Result of feeding a chunk to a [`Scanner`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[must_use]
pub enum Feed {
    /// The chunk was scanned; more may follow.
    Continue,
    /// The cumulative length passed the cap, or this call passed the chunk
    /// cap. The chunk was not scanned, and nothing fed after this will be.
    /// Stop reading and call [`Scanner::finish`].
    OverLimit,
}

/// Which cap stopped a stream.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Stop {
    Length,
    Chunks,
}

/// A streaming scan in progress. Produced by [`Inlet::scanner`].
///
/// Feeding the same bytes in any chunking (within the chunk cap) gives the
/// same verdict as [`Inlet::winnow`] on the whole input, except for an
/// oversize refusal, where [`Verdict::scanned`] reports how much was scanned
/// before the cap was passed.
///
/// A scanner dropped without [`Scanner::finish`] still reports: the drop
/// judges what had been fed so far (a sequence cut off at the end counts as
/// truncated) and records it (see [`telemetry::STREAMS_ABANDONED_TOTAL`]),
/// so a probe whose connection closes is not invisible.
#[derive(Debug)]
pub struct Scanner {
    max_len: usize,
    max_chunks: usize,
    dfa: Dfa,
    hasher: Sha256,
    offered: usize,
    chunks: usize,
    stopped: Option<Stop>,
    finished: bool,
    log_key: Option<Arc<LogKey>>,
    started: Instant,
    span: Span,
}

impl Scanner {
    /// Scan the next chunk.
    ///
    /// Both caps are checked before the chunk is read: a call past
    /// [`StreamConfig::max_chunks`] (empty chunks count) or a chunk that
    /// would take the total past the length cap is not scanned at all. No
    /// span is entered here, so the per-call cost is a few comparisons plus
    /// the scan itself.
    pub fn feed(&mut self, chunk: &[u8]) -> Feed {
        if self.stopped.is_some() {
            return Feed::OverLimit;
        }
        self.chunks = self.chunks.saturating_add(1);
        if self.chunks > self.max_chunks {
            self.stopped = Some(Stop::Chunks);
            return Feed::OverLimit;
        }
        self.offered = self.offered.saturating_add(chunk.len());
        if self.offered > self.max_len {
            self.stopped = Some(Stop::Length);
            return Feed::OverLimit;
        }
        self.dfa.scan(chunk);
        self.hasher.update(chunk);
        Feed::Continue
    }

    /// End the input and return the verdict. Records telemetry.
    #[must_use]
    pub fn finish(mut self) -> Verdict {
        self.finished = true;
        let span = std::mem::replace(&mut self.span, Span::none());
        let _entered = span.enter();
        span.record("chunks", self.chunks);
        let v = self.verdict();
        telemetry::emit(&v, self.started.elapsed(), self.log_key.as_deref());
        v
    }

    /// The verdict on what has been fed so far. Consumes the hash state, so
    /// it is called at most once (from `finish` or from `drop`).
    fn verdict(&mut self) -> Verdict {
        match self.stopped {
            Some(Stop::Length) => Verdict::oversize(self.offered, self.max_len, self.dfa.pos()),
            Some(Stop::Chunks) => Verdict::chunk_limit(self.offered, self.dfa.pos()),
            None => {
                let r = self.dfa.finish();
                let digest: [u8; 32] = std::mem::take(&mut self.hasher).finalize().into();
                Verdict::from_scan(self.offered, r.scanned, r.count, r.first, r.seen, digest)
            }
        }
    }
}

impl Drop for Scanner {
    fn drop(&mut self) {
        if self.finished {
            return;
        }
        self.finished = true;
        let span = std::mem::replace(&mut self.span, Span::none());
        let _entered = span.enter();
        span.record("chunks", self.chunks);
        let v = self.verdict();
        telemetry::emit_abandoned(&v, self.started.elapsed(), self.log_key.as_deref());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_config_is_valid() {
        assert_eq!(InletConfig::default().max_len, 64 * 1024);
        assert!(InletConfig::default().validate().is_ok());
    }

    #[test]
    fn bad_configs_are_refused() {
        assert_eq!(
            Inlet::new(InletConfig { max_len: 0 }).err(),
            Some(ConfigError::ZeroMaxLen)
        );
        assert_eq!(
            Inlet::new(InletConfig {
                max_len: MAX_LEN_CEILING + 1
            })
            .err(),
            Some(ConfigError::AboveCeiling {
                requested: MAX_LEN_CEILING + 1,
                ceiling: MAX_LEN_CEILING
            })
        );
        assert!(Inlet::new(InletConfig {
            max_len: MAX_LEN_CEILING
        })
        .is_ok());
    }

    #[test]
    fn bad_stream_configs_are_refused() {
        let c = InletConfig::default();
        assert_eq!(StreamConfig::default().max_chunks, 4096);
        assert_eq!(
            Inlet::with_stream_config(c, StreamConfig { max_chunks: 0 }).err(),
            Some(ConfigError::ZeroMaxChunks)
        );
        assert_eq!(
            Inlet::with_stream_config(
                c,
                StreamConfig {
                    max_chunks: MAX_CHUNKS_CEILING + 1
                }
            )
            .err(),
            Some(ConfigError::ChunksAboveCeiling {
                requested: MAX_CHUNKS_CEILING + 1,
                ceiling: MAX_CHUNKS_CEILING
            })
        );
        assert!(Inlet::with_stream_config(
            c,
            StreamConfig {
                max_chunks: MAX_CHUNKS_CEILING
            }
        )
        .is_ok());
    }

    #[test]
    fn log_keys_refuse_short_and_placeholder_values() {
        assert_eq!(
            LogKey::new(b"short").err(),
            Some(ConfigError::LogKeyTooShort { len: 5, min: 32 })
        );
        assert_eq!(
            LogKey::new(&[]).err(),
            Some(ConfigError::LogKeyTooShort { len: 0, min: 32 })
        );
        assert_eq!(
            LogKey::new(&[0u8; 32]).err(),
            Some(ConfigError::LogKeyPlaceholder)
        );
        // TEST FIXTURE KEY: not a real key, never used outside this test.
        let fixture: Vec<u8> = (0u8..32).collect();
        let k = LogKey::new(&fixture).unwrap();
        assert_eq!(format!("{k:?}"), "LogKey(<redacted>)");
        let d = [7u8; 32];
        assert_eq!(k.log_tag(&d), k.log_tag(&d));
        assert_ne!(k.log_tag(&d), d);
    }

    #[test]
    fn chunk_cap_counts_empty_chunks() {
        let inlet = Inlet::with_stream_config(
            InletConfig { max_len: 64 },
            StreamConfig { max_chunks: 3 },
        )
        .unwrap();
        let mut sc = inlet.scanner();
        assert_eq!(sc.feed(b""), Feed::Continue);
        assert_eq!(sc.feed(b"ab"), Feed::Continue);
        assert_eq!(sc.feed(b""), Feed::Continue);
        assert_eq!(sc.feed(b""), Feed::OverLimit);
        assert_eq!(sc.feed(b"c"), Feed::OverLimit);
        let v = sc.finish();
        assert_eq!(v.reason(), Some(Reason::ChunkLimit));
        assert_eq!(v.outcome(), GateOutcome::Retry);
        assert_eq!(v.resolution(), Some(Resolution::Reject));
        assert_eq!((v.len(), v.scanned(), v.first_offset()), (2, 2, Some(2)));
        assert!(v.sha256().is_none());
    }
}
