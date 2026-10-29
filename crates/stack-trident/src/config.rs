//! Every cap the Trident enforces, with documented defaults and hard
//! ceilings that config validation will not let a caller exceed.

use crate::canonical::{Limits, MAX_SAFE_INTEGER};
use crate::envelope::MAX_AUDIENCE_BYTES;

/// Hard ceiling on `max_depth`. The parser and encoder recurse once per
/// level, so this is also the worst-case recursion depth.
pub const MAX_DEPTH_CEILING: usize = 128;
/// Hard ceiling on `max_envelope_bytes`: 16 MiB.
pub const MAX_ENVELOPE_BYTES_CEILING: usize = 16 * 1024 * 1024;
/// Hard ceiling on `max_nodes`.
pub const MAX_NODES_CEILING: usize = 1_000_000;
/// Hard ceiling on either skew window: one hour.
pub const MAX_SKEW_CEILING_MS: u64 = 3_600_000;
/// Hard ceiling on `replay_cache_capacity`.
pub const REPLAY_CAPACITY_CEILING: usize = 4_194_304;
/// Hard ceiling on `max_tracked_senders`.
pub const TRACKED_SENDERS_CEILING: usize = 65_536;
/// Hard ceiling on `breaker_threshold`.
pub const BREAKER_THRESHOLD_CEILING: u32 = 1024;
/// Hard ceiling on `breaker_window_ms`: one day.
pub const BREAKER_WINDOW_CEILING_MS: u64 = 86_400_000;

/// Which terminal breaches count toward a sender's circuit breaker.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BreakerAttribution {
    /// Count a terminal breach only when prong 1 passed (the envelope was
    /// provably made with the sender's key) and the breach is not a replay
    /// (anyone who saw a genuine envelope can replay it). In practice this
    /// counts envelopes where the key holder signed a digest that does not
    /// match the payload. An attacker without the key cannot quarantine
    /// anyone. This is the default.
    AuthenticatedOnly,
    /// Count every terminal breach whose `sender` field names a key in the
    /// ring, whether or not the MAC verified. Trips sooner on a forgery
    /// flood, but lets anyone who knows a sender's public fingerprint get
    /// that sender quarantined, which is a denial of service against it.
    ClaimedSender,
}

/// Why a [`TridentConfig`] was refused.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("config field `{field}` is {value}; allowed range is {min}..={max}")]
pub struct ConfigError {
    /// Field name.
    pub field: &'static str,
    /// Offered value.
    pub value: u64,
    /// Smallest allowed value.
    pub min: u64,
    /// Largest allowed value.
    pub max: u64,
}

/// All caps and windows. Every field has a default and a hard ceiling.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TridentConfig {
    /// Largest accepted envelope, in bytes, raw or canonically encoded.
    /// Default 65,536 (64 KiB). Ceiling 16 MiB.
    pub max_envelope_bytes: usize,
    /// Deepest accepted nesting. The envelope object is level 1, so a
    /// payload may nest `max_depth - 1` levels. Default 32. Ceiling 128.
    pub max_depth: usize,
    /// Most JSON values in one envelope. Default 16,384. Ceiling 1,000,000.
    pub max_nodes: usize,
    /// How far in the past `issued_at_unix_ms` may be. Default 60,000 ms.
    /// Ceiling one hour.
    pub max_past_skew_ms: u64,
    /// How far in the future `issued_at_unix_ms` may be. Default 5,000 ms.
    /// Ceiling one hour.
    pub max_future_skew_ms: u64,
    /// When true (the default), the Trident keeps an epoch floor and
    /// refuses (RETRY) any envelope issued before it. At start the floor is
    /// the larger of `start time + max_future_skew_ms` and
    /// `restored_high_water_ms + 1`. On every operator reset it is raised to
    /// the larger of its old value, `now + max_future_skew_ms` and the
    /// highest `issued_at_unix_ms` ever accepted plus one, so it never goes
    /// down. This closes the replay hole that an in-memory replay cache
    /// otherwise has after a restart or reset, at the cost of refusing
    /// everything for `max_future_skew_ms` after start. Across a restart it
    /// is only as good as `restored_high_water_ms`: with that left at 0,
    /// it assumes the wall clock has not gone backwards since the previous
    /// process accepted its last envelope.
    pub enforce_startup_epoch: bool,
    /// The high-water mark (see `Trident::high_water_ms`) the previous run
    /// of this receiver reported, persisted by the caller and handed back
    /// on restart. With `enforce_startup_epoch` on, nothing issued at or
    /// before it is accepted, whatever the clock says. Default 0 (nothing
    /// restored). At most 2^53 - 1.
    pub restored_high_water_ms: u64,
    /// This receiver's identifier. When non-empty, only envelopes sealed
    /// for it (`seal_for` with the same string) pass prong 1, so an
    /// envelope captured on its way to one receiver cannot be replayed into
    /// another receiver that trusts the same sender key. Required: an empty
    /// audience is refused by [`TridentConfig::validate`] unless
    /// `allow_unbound_audience` is set. At most 256 bytes.
    pub audience: String,
    /// Explicit opt-out of the audience requirement. With it set and
    /// `audience` empty, no receiver is bound: any receiver with an empty
    /// audience and the sender's key accepts the envelope once, and a
    /// warning says so. Default false. [`TridentConfig::unbound_audience`]
    /// is the named way to ask for it.
    pub allow_unbound_audience: bool,
    /// Most (sender, nonce) pairs remembered. An entry lives for
    /// `replay_retention_ms()` after acceptance. When the cache is full, a
    /// sender holding fewer than its fair share
    /// (`replay_cache_capacity / key ring size`) evicts the oldest entry of
    /// the sender holding the most, and a sender at or over its share is
    /// refused (RETRY). Eviction does not reopen a replay: the evicted
    /// envelope's sequence is at or below its sender's retained high-water
    /// mark, so a replay of it fails the sequence check. Default 65,536
    /// (about 1,000 accepts per second at the default 65 s window).
    /// Ceiling 4,194,304.
    pub replay_cache_capacity: usize,
    /// Most senders with receiver-side state (last sequence, breach
    /// history, quarantine). Only senders that were in the key ring when
    /// they were accepted or counted by the breaker get state, so an
    /// attacker cannot grow it by inventing fingerprints. When full, an
    /// entry that is idle (no acceptance within `replay_retention_ms()`, no
    /// breach within `breaker_window_ms`, not quarantined) is evicted to
    /// make room; its old envelopes are all stale by then. Default 1,024.
    /// Ceiling 65,536.
    pub max_tracked_senders: usize,
    /// Terminal breaches (as counted by `breaker_attribution`) from one
    /// sender inside `breaker_window_ms` that quarantine it. Default 5.
    /// Ceiling 1,024.
    pub breaker_threshold: u32,
    /// The breaker's sliding window. Default 60,000 ms. Ceiling one day.
    pub breaker_window_ms: u64,
    /// Which breaches count. Default [`BreakerAttribution::AuthenticatedOnly`].
    pub breaker_attribution: BreakerAttribution,
}

impl Default for TridentConfig {
    fn default() -> Self {
        Self {
            max_envelope_bytes: 65_536,
            max_depth: 32,
            max_nodes: 16_384,
            max_past_skew_ms: 60_000,
            max_future_skew_ms: 5_000,
            enforce_startup_epoch: true,
            restored_high_water_ms: 0,
            audience: String::new(),
            allow_unbound_audience: false,
            replay_cache_capacity: 65_536,
            max_tracked_senders: 1_024,
            breaker_threshold: 5,
            breaker_window_ms: 60_000,
            breaker_attribution: BreakerAttribution::AuthenticatedOnly,
        }
    }
}

fn check(field: &'static str, value: u64, min: u64, max: u64) -> Result<(), ConfigError> {
    if (min..=max).contains(&value) {
        Ok(())
    } else {
        Err(ConfigError {
            field,
            value,
            min,
            max,
        })
    }
}

fn as_u64(n: usize) -> u64 {
    u64::try_from(n).unwrap_or(u64::MAX)
}

impl TridentConfig {
    /// The default config with the audience requirement explicitly waived:
    /// no receiver is bound, and [`TridentConfig::validate`] warns that any
    /// holder of the shared key can replay an envelope to any receiver.
    /// For tests and single-receiver setups. A deployment where more than
    /// one receiver trusts a sender key sets `audience` instead.
    pub fn unbound_audience() -> Self {
        Self {
            allow_unbound_audience: true,
            ..Self::default()
        }
    }

    /// Checks every field against its range. The Trident refuses to start
    /// with a config that fails this.
    ///
    /// An empty `audience` fails here (field `audience`) unless
    /// `allow_unbound_audience` is set, so a receiver that binds no audience
    /// is always a decision and never an accident.
    ///
    /// A config that passes may still rest on an assumption the operator
    /// should know about. Each one is reported once per call as a
    /// `tracing::warn!` and never changes the result: an empty `audience`
    /// that was explicitly allowed (any receiver with the shared key accepts
    /// the envelope), and `enforce_startup_epoch` with
    /// `restored_high_water_ms` left at 0 (the restart replay guard then
    /// trusts the wall clock).
    pub fn validate(&self) -> Result<(), ConfigError> {
        check(
            "max_envelope_bytes",
            as_u64(self.max_envelope_bytes),
            64,
            as_u64(MAX_ENVELOPE_BYTES_CEILING),
        )?;
        // Depth 2 is the minimum that lets the envelope object hold a
        // payload array or object at all.
        check("max_depth", as_u64(self.max_depth), 2, as_u64(MAX_DEPTH_CEILING))?;
        check("max_nodes", as_u64(self.max_nodes), 11, as_u64(MAX_NODES_CEILING))?;
        check("max_past_skew_ms", self.max_past_skew_ms, 1, MAX_SKEW_CEILING_MS)?;
        check("max_future_skew_ms", self.max_future_skew_ms, 0, MAX_SKEW_CEILING_MS)?;
        check("restored_high_water_ms", self.restored_high_water_ms, 0, MAX_SAFE_INTEGER)?;
        check(
            "audience",
            as_u64(self.audience.len()),
            0,
            as_u64(MAX_AUDIENCE_BYTES),
        )?;
        check(
            "replay_cache_capacity",
            as_u64(self.replay_cache_capacity),
            1,
            as_u64(REPLAY_CAPACITY_CEILING),
        )?;
        check(
            "max_tracked_senders",
            as_u64(self.max_tracked_senders),
            1,
            as_u64(TRACKED_SENDERS_CEILING),
        )?;
        check(
            "breaker_threshold",
            u64::from(self.breaker_threshold),
            1,
            u64::from(BREAKER_THRESHOLD_CEILING),
        )?;
        check("breaker_window_ms", self.breaker_window_ms, 1, BREAKER_WINDOW_CEILING_MS)?;
        if self.audience.is_empty() {
            if !self.allow_unbound_audience {
                tracing::error!(
                    "stack.trident needs an audience: set `audience` to this receiver's identifier, or set `allow_unbound_audience` (TridentConfig::unbound_audience) to bind none"
                );
                return Err(ConfigError {
                    field: "audience",
                    value: 0,
                    min: 1,
                    max: as_u64(MAX_AUDIENCE_BYTES),
                });
            }
            tracing::warn!(
                "stack.trident audience binding is off: any holder of the shared key can replay this envelope to any receiver"
            );
        }
        if self.enforce_startup_epoch && self.restored_high_water_ms == 0 {
            tracing::warn!(
                "stack.trident restart replay guard assumes the wall clock did not go backwards: restored_high_water_ms is 0"
            );
        }
        Ok(())
    }

    /// The parse and encode caps derived from this config.
    pub fn limits(&self) -> Limits {
        Limits {
            max_bytes: self.max_envelope_bytes,
            max_depth: self.max_depth,
            max_nodes: self.max_nodes,
        }
    }

    /// How long a replay-cache entry is kept after acceptance:
    /// `max_past_skew_ms + max_future_skew_ms + 1`. An entry is dropped once
    /// `now >= accepted_at + retention`. At that instant an envelope issued
    /// as late as `accepted_at + max_future_skew_ms` is already stale
    /// (`issued_at < now - max_past_skew_ms`), so there is no boundary
    /// millisecond where it is neither remembered nor stale. The same
    /// window decides when a sender entry is idle enough to evict.
    pub fn replay_retention_ms(&self) -> u64 {
        self.max_past_skew_ms
            .saturating_add(self.max_future_skew_ms)
            .saturating_add(1)
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use tracing::field::{Field, Visit};
    use tracing::span::{Attributes, Id, Record};
    use tracing::{Event, Level, Metadata, Subscriber};

    use super::*;

    #[test]
    fn default_with_an_audience_is_valid() {
        TridentConfig {
            audience: "receiver-a".to_owned(),
            ..TridentConfig::default()
        }
        .validate()
        .unwrap();
    }

    #[test]
    fn default_without_an_audience_is_refused_and_says_so() {
        let err = TridentConfig::default().validate().unwrap_err();
        assert_eq!(err.field, "audience");
        assert!(!TridentConfig::default().allow_unbound_audience);
    }

    #[test]
    fn unbound_audience_is_the_explicit_opt_out_and_still_warns() {
        let cfg = TridentConfig::unbound_audience();
        assert!(cfg.audience.is_empty() && cfg.allow_unbound_audience);
        let warnings = warnings_from(&cfg);
        assert!(warnings.iter().any(|w| w.contains("audience binding is off")), "{warnings:?}");
    }

    #[test]
    fn allowing_unbound_does_not_excuse_a_bad_audience() {
        let too_long = TridentConfig {
            audience: "x".repeat(MAX_AUDIENCE_BYTES + 1),
            allow_unbound_audience: true,
            ..TridentConfig::default()
        };
        assert_eq!(too_long.validate().unwrap_err().field, "audience");
    }

    #[test]
    fn a_set_audience_needs_no_opt_out_and_raises_no_audience_warning() {
        let cfg = TridentConfig {
            audience: "receiver-a".to_owned(),
            ..TridentConfig::default()
        };
        let warnings = warnings_from(&cfg);
        assert!(!warnings.iter().any(|w| w.contains("audience")), "{warnings:?}");
    }

    /// A subscriber that keeps the message of every WARN event. The crate
    /// has no log-capture fixture and no `tracing-subscriber` dev-dependency,
    /// so this is the smallest thing that can see the warnings.
    struct WarnCapture(Arc<Mutex<Vec<String>>>);

    struct Message(String);

    impl Visit for Message {
        fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
            if field.name() == "message" {
                self.0 = format!("{value:?}");
            }
        }
    }

    impl Subscriber for WarnCapture {
        fn enabled(&self, metadata: &Metadata<'_>) -> bool {
            *metadata.level() == Level::WARN
        }
        fn new_span(&self, _: &Attributes<'_>) -> Id {
            Id::from_u64(1)
        }
        fn record(&self, _: &Id, _: &Record<'_>) {}
        fn record_follows_from(&self, _: &Id, _: &Id) {}
        fn event(&self, event: &Event<'_>) {
            let mut message = Message(String::new());
            event.record(&mut message);
            self.0.lock().unwrap().push(message.0);
        }
        fn enter(&self, _: &Id) {}
        fn exit(&self, _: &Id) {}
    }

    fn warnings_from(cfg: &TridentConfig) -> Vec<String> {
        let sink = Arc::new(Mutex::new(Vec::new()));
        tracing::subscriber::with_default(WarnCapture(sink.clone()), || cfg.validate().unwrap());
        let warnings = sink.lock().unwrap().clone();
        warnings
    }

    #[test]
    fn default_config_warns_once_per_replay_assumption() {
        let warnings = warnings_from(&TridentConfig::unbound_audience());
        assert_eq!(warnings.len(), 2, "{warnings:?}");
        assert!(warnings[0].contains("audience binding is off"), "{warnings:?}");
        assert!(warnings[1].contains("wall clock did not go backwards"), "{warnings:?}");
    }

    #[test]
    fn bound_audience_and_restored_high_water_do_not_warn() {
        let cfg = TridentConfig {
            audience: "receiver-a".to_owned(),
            restored_high_water_ms: 1,
            ..TridentConfig::default()
        };
        assert_eq!(warnings_from(&cfg), Vec::<String>::new());

        let epoch_off = TridentConfig {
            enforce_startup_epoch: false,
            ..TridentConfig::unbound_audience()
        };
        let warnings = warnings_from(&epoch_off);
        assert_eq!(warnings.len(), 1, "{warnings:?}");
        assert!(warnings[0].contains("audience binding is off"), "{warnings:?}");
    }

    #[test]
    fn ceilings_are_enforced() {
        let c = TridentConfig {
            max_depth: 129,
            ..TridentConfig::default()
        };
        assert_eq!(c.validate().unwrap_err().field, "max_depth");
        let c = TridentConfig {
            breaker_threshold: 0,
            ..TridentConfig::default()
        };
        assert_eq!(c.validate().unwrap_err().field, "breaker_threshold");
        let c = TridentConfig {
            max_envelope_bytes: MAX_ENVELOPE_BYTES_CEILING + 1,
            ..TridentConfig::default()
        };
        assert_eq!(c.validate().unwrap_err().field, "max_envelope_bytes");
    }
}
