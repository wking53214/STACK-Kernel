//! Configuration for the inlet: the numbers an operator may tune.
//!
//! The inlet has two knobs: the hard length cap ([`InletConfig::max_len`])
//! and, for streams, the cap on the number of chunks
//! ([`StreamConfig::max_chunks`]). A deployment may also supply a log key
//! ([`crate::telemetry::LogKey`]); there is no default key. Everything else
//! about its behaviour (which bytes are banned, which outcome each trip maps
//! to) is fixed in code on purpose: a filter whose ban list can be edited at
//! runtime is a filter an attacker can try to talk into editing.
//!
//! The chunk cap lives in its own struct rather than in [`InletConfig`] so
//! that existing code building `InletConfig { max_len }` keeps compiling;
//! [`crate::Inlet::new`] applies [`StreamConfig::default`].

use thiserror::Error;

/// Default hard length cap: 64 KiB.
///
/// Chosen as a size that holds any reasonable single instruction, prompt or
/// structured request while keeping the worst case small. Measured on the
/// build machine (release build, no SHA hardware extensions): a full 64 KiB
/// check took about 0.6 ms, roughly half of it the automaton (about 4.3 ns
/// per byte) and half the SHA-256. Other hardware will differ; the `timing`
/// test prints the numbers for the machine it runs on.
pub const DEFAULT_MAX_LEN: usize = 64 * 1024;

/// Absolute ceiling on [`InletConfig::max_len`]: 16 MiB.
///
/// A configuration above this is refused at construction. The ceiling exists
/// so that no configuration mistake can turn the inlet into a CPU weapon (the
/// scan is linear, so the cap is also a cap on work per request) and so that
/// every offset, count and length a [`crate::Verdict`] reports fits in 32
/// bits when a caller serialises it (an oversize verdict's length is clamped
/// to the cap plus one for this reason).
pub const MAX_LEN_CEILING: usize = 16 * 1024 * 1024;

/// Inlet configuration. Construct with [`InletConfig::default`] and adjust.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InletConfig {
    /// Hard cap on input length in bytes. Default [`DEFAULT_MAX_LEN`] (64 KiB).
    ///
    /// Checked before a single body byte is read: an input longer than this is
    /// refused on its length alone. Must be between 1 and [`MAX_LEN_CEILING`].
    pub max_len: usize,
}

impl Default for InletConfig {
    fn default() -> Self {
        Self {
            max_len: DEFAULT_MAX_LEN,
        }
    }
}

impl InletConfig {
    /// Check the configuration. Called by [`crate::Inlet::new`].
    ///
    /// # Errors
    ///
    /// [`ConfigError::ZeroMaxLen`] when `max_len` is zero, and
    /// [`ConfigError::AboveCeiling`] when it exceeds [`MAX_LEN_CEILING`].
    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.max_len == 0 {
            return Err(ConfigError::ZeroMaxLen);
        }
        if self.max_len > MAX_LEN_CEILING {
            return Err(ConfigError::AboveCeiling {
                requested: self.max_len,
                ceiling: MAX_LEN_CEILING,
            });
        }
        Ok(())
    }
}

/// Default cap on the number of chunks one stream may be fed: 4096.
///
/// At the default 64 KiB length cap that is an average of 16 bytes per chunk,
/// which any real transport exceeds (HTTP/2 DATA frames default to 16 KiB).
/// A caller whose transport delivers smaller pieces should buffer them or
/// raise the cap.
pub const DEFAULT_MAX_CHUNKS: usize = 4096;

/// Absolute ceiling on [`StreamConfig::max_chunks`]: 16 Mi chunks, the most
/// one-byte chunks a stream at [`MAX_LEN_CEILING`] could need.
pub const MAX_CHUNKS_CEILING: usize = MAX_LEN_CEILING;

/// Stream configuration. Construct with [`StreamConfig::default`] and adjust.
///
/// The length cap bounds the bytes a stream may carry, not the number of
/// calls a sender's framing produces: without this cap, a million empty
/// frames (HTTP/2 DATA, WebSocket continuation) would each cost a call while
/// never reaching the length cap. Every call to [`crate::Scanner::feed`]
/// counts, empty or not.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StreamConfig {
    /// Most chunks one stream may be fed. Default [`DEFAULT_MAX_CHUNKS`]
    /// (4096). The next call returns [`crate::Feed::OverLimit`] and the
    /// verdict is [`crate::Reason::ChunkLimit`]. Must be between 1 and
    /// [`MAX_CHUNKS_CEILING`].
    pub max_chunks: usize,
}

impl Default for StreamConfig {
    fn default() -> Self {
        Self {
            max_chunks: DEFAULT_MAX_CHUNKS,
        }
    }
}

impl StreamConfig {
    /// Check the configuration. Called by [`crate::Inlet::with_stream_config`].
    ///
    /// # Errors
    ///
    /// [`ConfigError::ZeroMaxChunks`] when `max_chunks` is zero, and
    /// [`ConfigError::ChunksAboveCeiling`] when it exceeds
    /// [`MAX_CHUNKS_CEILING`].
    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.max_chunks == 0 {
            return Err(ConfigError::ZeroMaxChunks);
        }
        if self.max_chunks > MAX_CHUNKS_CEILING {
            return Err(ConfigError::ChunksAboveCeiling {
                requested: self.max_chunks,
                ceiling: MAX_CHUNKS_CEILING,
            });
        }
        Ok(())
    }
}

/// Why a configuration was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum ConfigError {
    /// A zero cap would refuse every input, including empty ones, which is a
    /// configuration mistake rather than a policy.
    #[error("max_len must be at least 1 byte")]
    ZeroMaxLen,
    /// The requested cap is above the hard ceiling.
    #[error("max_len {requested} exceeds the hard ceiling of {ceiling} bytes")]
    AboveCeiling {
        /// The value that was asked for.
        requested: usize,
        /// The ceiling it exceeded, [`MAX_LEN_CEILING`].
        ceiling: usize,
    },
    /// A zero chunk cap would refuse every stream.
    #[error("max_chunks must be at least 1")]
    ZeroMaxChunks,
    /// The requested chunk cap is above the hard ceiling.
    #[error("max_chunks {requested} exceeds the hard ceiling of {ceiling}")]
    ChunksAboveCeiling {
        /// The value that was asked for.
        requested: usize,
        /// The ceiling it exceeded, [`MAX_CHUNKS_CEILING`].
        ceiling: usize,
    },
    /// A log key shorter than the minimum was supplied.
    #[error("log key is {len} bytes; at least {min} are required")]
    LogKeyTooShort {
        /// Length of the key supplied.
        len: usize,
        /// The minimum, [`crate::telemetry::LogKey::MIN_LEN`].
        min: usize,
    },
    /// A log key whose bytes are all equal (for example all zero) was
    /// supplied. That is a placeholder, not a key.
    #[error("log key bytes are all equal; supply a real secret")]
    LogKeyPlaceholder,
}
