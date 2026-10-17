//! The Trident verifier.

use std::borrow::Cow;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, RwLock};
use std::time::Instant;

use metrics::{counter, gauge, histogram};
use sha2::{Digest, Sha256};
use subtle::{Choice, ConstantTimeEq};
use tracing::field;

use crate::canonical::{decode_hex_lower, parse_strict, sha256_hex, CanonicalError, Limits};
use crate::clock::{Clock, SystemClock};
use crate::config::{BreakerAttribution, ConfigError, TridentConfig};
use crate::envelope::{encode_payload_counted, hmac_sha256, HandoffEnvelope, Nonce, ENVELOPE_OWN_NODES, ENVELOPE_VERSION};
use crate::keys::{Fingerprint, KeyRing};
use crate::state::{ReplayCache, SenderTable, State};
use crate::telemetry::{self as t, gauge_value, HaltCause};
use crate::vocab::{GateOutcome, GatePosition, ReasonCode, Resolution};
use crate::verdict::{Verdict, VerifiedHandoff};

/// Returned by operator calls that cannot run because the Trident is halted
/// on a poisoned lock. Call [`Trident::operator_reset`] first.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("the trident is halted; an operator reset is required")]
pub struct HaltedError;

/// The receiver. Verifies [`HandoffEnvelope`]s against a caller-supplied
/// [`KeyRing`] and keeps the bounded freshness and breaker state.
///
/// `Send + Sync`: share it behind an `Arc`. Prongs 1 and 2 run without a
/// lock; prong 3 and the state commit run inside one short critical
/// section, so two copies of one envelope racing each other cannot both be
/// accepted. That section also re-checks every custody fact read earlier
/// (halt, quarantine, and that the sender's key is still in the ring), and
/// the operator calls that change those facts take the same lock, so once
/// `operator_halt`, `replace_keyring` or a breaker trip has returned, no
/// in-flight verification can commit an acceptance that contradicts it.
#[derive(Debug)]
pub struct Trident {
    config: TridentConfig,
    limits: Limits,
    keyring: RwLock<Arc<KeyRing>>,
    clock: Arc<dyn Clock>,
    state: Mutex<State>,
    halted: AtomicBool,
}

/// Stateful prong 3 results that are masked from the reply when prong 1
/// failed; see the crate docs, "What the reply reveals".
struct StatefulFreshness {
    replayed: bool,
    out_of_order: bool,
}

impl Trident {
    /// Builds a Trident. Fails if `config` is outside its documented ranges.
    ///
    /// With `enforce_startup_epoch` on, envelopes issued before
    /// `now + max_future_skew_ms`, or at or before
    /// `config.restored_high_water_ms`, are refused, so none accepted by a
    /// previous process can be replayed into this one. Without a restored
    /// high-water mark that relies on the clock not having gone backwards
    /// since the previous process stopped.
    pub fn new(config: TridentConfig, keyring: KeyRing, clock: Arc<dyn Clock>) -> Result<Self, ConfigError> {
        config.validate()?;
        let high_water_ms = config.restored_high_water_ms;
        let epoch_floor_ms = Self::epoch_floor(&config, clock.as_ref(), 0, high_water_ms);
        let state = State {
            replay: ReplayCache::new(config.replay_cache_capacity),
            senders: SenderTable::new(
                config.max_tracked_senders,
                config.replay_retention_ms(),
                config.breaker_window_ms,
            ),
            epoch_floor_ms,
            high_water_ms,
        };
        Ok(Self {
            limits: config.limits(),
            config,
            keyring: RwLock::new(Arc::new(keyring)),
            clock,
            state: Mutex::new(state),
            halted: AtomicBool::new(false),
        })
    }

    /// [`Trident::new`] with the system wall clock.
    pub fn with_system_clock(config: TridentConfig, keyring: KeyRing) -> Result<Self, ConfigError> {
        Self::new(config, keyring, Arc::new(SystemClock))
    }

    /// The epoch floor: the largest of the previous floor,
    /// `now + max_future_skew_ms` and one past the high-water mark, so it
    /// never goes down even when the clock does. 0 when disabled.
    fn epoch_floor(config: &TridentConfig, clock: &dyn Clock, previous: u64, high_water_ms: u64) -> u64 {
        if config.enforce_startup_epoch {
            let from_clock = clock.now_unix_ms().saturating_add(config.max_future_skew_ms);
            let past_accepted = if high_water_ms > 0 {
                high_water_ms.saturating_add(1)
            } else {
                0
            };
            previous.max(from_clock).max(past_accepted)
        } else {
            0
        }
    }

    /// The active config.
    pub fn config(&self) -> &TridentConfig {
        &self.config
    }

    /// Verifies an envelope that arrived as bytes. This is the path for
    /// anything crossing a repository or process boundary.
    pub fn verify_wire(&self, bytes: &[u8]) -> Verdict {
        let started = Instant::now();
        let span = tracing::info_span!(
            t::SPAN_VERIFY,
            path = "wire",
            input_len = bytes.len(),
            input_sha256 = field::Empty,
            outcome = field::Empty,
            resolution = field::Empty,
        );
        let _entered = span.enter();
        // Hash the raw input for the log only when it is within the size
        // cap: hashing an over-budget input is the work the cap prevents.
        if bytes.len() <= self.config.max_envelope_bytes {
            span.record("input_sha256", sha256_hex(bytes).as_str());
        }
        let verdict = self.verify_wire_inner(bytes);
        self.finish(&span, &verdict, started);
        verdict
    }

    /// Verifies an envelope already in memory (an in-process handoff). The
    /// same caps apply: its canonical encoding must fit the byte, depth and
    /// node limits before any hashing happens.
    pub fn verify(&self, env: &HandoffEnvelope) -> Verdict {
        let started = Instant::now();
        let span = tracing::info_span!(
            t::SPAN_VERIFY,
            path = "in_process",
            input_len = field::Empty,
            input_sha256 = field::Empty,
            outcome = field::Empty,
            resolution = field::Empty,
        );
        let _entered = span.enter();
        let verdict = if self.halted.load(Ordering::SeqCst) {
            Self::halted_verdict()
        } else {
            self.evaluate(Cow::Borrowed(env), Some(&span))
        };
        self.finish(&span, &verdict, started);
        verdict
    }

    fn verify_wire_inner(&self, bytes: &[u8]) -> Verdict {
        // Fast path only: the halt flag is checked again inside the prong 3
        // critical section, where it decides.
        if self.halted.load(Ordering::SeqCst) {
            return Self::halted_verdict();
        }
        let value = match parse_strict(bytes, &self.limits) {
            Ok(v) => v,
            Err(e) => return Self::admission(e),
        };
        let Some(env) = HandoffEnvelope::from_value(value) else {
            return Verdict::refuse(vec![ReasonCode::MalformedEnvelope], Resolution::Reject);
        };
        self.evaluate(Cow::Owned(env), None)
    }

    fn quarantined_verdict() -> Verdict {
        Verdict::refuse(vec![ReasonCode::Quarantined], Resolution::Quarantine)
    }

    fn admission(e: CanonicalError) -> Verdict {
        let reason = match e {
            CanonicalError::TooLarge => ReasonCode::EnvelopeTooLarge,
            CanonicalError::TooDeep => ReasonCode::TooDeep,
            CanonicalError::TooManyNodes => ReasonCode::TooManyNodes,
            CanonicalError::Malformed => ReasonCode::MalformedJson,
            CanonicalError::NonInteger => ReasonCode::NonIntegerNumber,
            CanonicalError::NonFinite => ReasonCode::NonFiniteNumber,
            CanonicalError::IntegerOutOfRange => ReasonCode::IntegerOutOfRange,
            CanonicalError::DuplicateKey => ReasonCode::DuplicateKey,
        };
        Verdict::refuse(vec![reason], Resolution::Reject)
    }

    fn halted_verdict() -> Verdict {
        Verdict::refuse(vec![ReasonCode::Halted], Resolution::Halt)
    }

    fn enter_halt(&self, cause: HaltCause) {
        if !self.halted.swap(true, Ordering::SeqCst) {
            counter!(t::HALTS_TOTAL, "cause" => cause.as_str()).increment(1);
            tracing::error!(cause = cause.as_str(), "stack.trident halted; operator reset required");
        }
    }

    fn lock_state(&self) -> Option<MutexGuard<'_, State>> {
        match self.state.lock() {
            Ok(g) => Some(g),
            Err(_) => {
                self.enter_halt(HaltCause::Poisoned);
                None
            }
        }
    }

    fn keyring_snapshot(&self) -> Option<Arc<KeyRing>> {
        match self.keyring.read() {
            Ok(g) => Some(Arc::clone(&g)),
            Err(_) => {
                self.enter_halt(HaltCause::Poisoned);
                None
            }
        }
    }

    /// Admission (canonical encoding), custody, then all three prongs.
    fn evaluate(&self, env: Cow<'_, HandoffEnvelope>, record_into: Option<&tracing::Span>) -> Verdict {
        // ---- Admission: canonical encoding under the caps. No hashing yet.
        // The node count starts at the envelope object and its nine scalars
        // and the byte cap is applied to the whole canonical wire form, so an
        // in-process envelope meets exactly the caps its wire form would.
        let payload_bytes = match encode_payload_counted(&env.payload, &self.limits, ENVELOPE_OWN_NODES) {
            Ok(b) => b,
            Err(e) => return Self::admission(e),
        };
        match env.canonical_len(payload_bytes.len(), true, &self.limits) {
            Ok(n) if n <= self.limits.max_bytes => {}
            Ok(_) => return Self::admission(CanonicalError::TooLarge),
            Err(e) => return Self::admission(e),
        }
        let mac_input = match env.mac_input(&payload_bytes, &self.config.audience, &self.limits) {
            Ok(b) => b,
            Err(e) => return Self::admission(e),
        };
        if let Some(span) = record_into {
            span.record("input_len", mac_input.len());
            span.record("input_sha256", sha256_hex(&mac_input).as_str());
        }

        // ---- Custody: quarantine is public state, so refusing early here
        // tells a caller nothing it could not learn from the refusal itself.
        // This is a fast path; the prong 3 section checks again and decides.
        let fp = Fingerprint::from_hex(&env.sender);
        if let Some(fp) = fp.as_ref() {
            let Some(st) = self.lock_state() else {
                return Self::halted_verdict();
            };
            if st.senders.is_quarantined(fp) {
                return Self::quarantined_verdict();
            }
        }
        let Some(keyring) = self.keyring_snapshot() else {
            return Self::halted_verdict();
        };

        let mut reasons: Vec<ReasonCode> = Vec::with_capacity(8);

        // ---- Prong 1: authenticity. The HMAC is computed on every path so
        // an unknown or malformed sender costs the same work as a known one.
        let key = fp.as_ref().and_then(|f| keyring.get(f));
        let provided_mac = decode_hex_lower::<32>(&env.mac);
        // Workload equalizer for the no-key path: a throwaway HMAC key
        // derived from the public sender field. It is not a key: its result
        // is always discarded, because `authentic` below is ANDed with
        // "a key was found". The crate holds no constant key of any kind.
        let equalizer: [u8; 32] = match fp.as_ref() {
            Some(f) => *f.as_bytes(),
            None => Sha256::digest(env.sender.as_bytes()).into(),
        };
        let key_bytes: &[u8] = key.map_or(&equalizer[..], |k| k.as_bytes());
        let computed = hmac_sha256(key_bytes, &mac_input);
        let tag_eq: Choice = match computed {
            Some(c) => c.ct_eq(&provided_mac.unwrap_or([0u8; 32])),
            None => Choice::from(0),
        };
        let mut authentic = bool::from(
            tag_eq & Choice::from(u8::from(key.is_some())) & Choice::from(u8::from(provided_mac.is_some())),
        );
        if fp.is_none() {
            reasons.push(ReasonCode::MalformedSender);
        } else if key.is_none() {
            reasons.push(ReasonCode::UnknownSender);
        }
        if provided_mac.is_none() {
            reasons.push(ReasonCode::MalformedMac);
        } else if key.is_some() && !authentic {
            reasons.push(ReasonCode::MacMismatch);
        }

        // ---- Prong 2: binding and closed vocabularies.
        if env.version != ENVELOPE_VERSION {
            reasons.push(ReasonCode::UnsupportedVersion);
        }
        let position = GatePosition::parse(&env.gate_position);
        if position.is_none() {
            reasons.push(ReasonCode::UnknownGatePosition);
        }
        let gate_outcome = GateOutcome::parse(&env.gate_outcome);
        if gate_outcome.is_none() {
            reasons.push(ReasonCode::UnknownGateOutcome);
        }
        let recomputed: [u8; 32] = Sha256::digest(&payload_bytes).into();
        match decode_hex_lower::<32>(&env.subject_digest) {
            None => reasons.push(ReasonCode::MalformedDigest),
            Some(claimed) => {
                if !bool::from(claimed.ct_eq(&recomputed)) {
                    reasons.push(ReasonCode::SubjectDigestMismatch);
                }
            }
        }
        let hashed = mac_input.len().saturating_add(payload_bytes.len());
        counter!(t::HASHED_BYTES_TOTAL).increment(u64::try_from(hashed).unwrap_or(u64::MAX));

        // ---- Prong 3: freshness, then commit or breaker, in one section.
        let nonce = Nonce::from_hex(&env.nonce);
        let Some(mut st) = self.lock_state() else {
            return Self::halted_verdict();
        };
        // Custody again, now under the lock that operator calls and breaker
        // trips also take, so a halt, quarantine or revocation that has
        // already returned cannot be overtaken by this verification.
        if self.halted.load(Ordering::SeqCst) {
            return Self::halted_verdict();
        }
        if fp.as_ref().is_some_and(|f| st.senders.is_quarantined(f)) {
            return Self::quarantined_verdict();
        }
        // `replace_keyring` swaps the ring while holding this lock, so the
        // ring read here is the one in force. A sender whose key was
        // removed since the snapshot is refused as unknown, and counts as
        // unauthenticated from here on.
        let still_trusted = match (key.is_some(), fp.as_ref()) {
            (true, Some(f)) => match self.keyring.read() {
                Ok(current) => Arc::ptr_eq(&current, &keyring) || current.contains(f),
                Err(_) => {
                    drop(st);
                    self.enter_halt(HaltCause::Poisoned);
                    return Self::halted_verdict();
                }
            },
            _ => false,
        };
        if key.is_some() && !still_trusted {
            // Prong 1 reasons come first; an authentic envelope had none.
            reasons.retain(|r| *r != ReasonCode::MacMismatch);
            reasons.insert(0, ReasonCode::UnknownSender);
            authentic = false;
        }
        let now = self.clock.now_unix_ms();
        if let Some(f) = fp.as_ref() {
            st.replay.expire_sender(f, now);
        }
        if env.issued_at_unix_ms < now.saturating_sub(self.config.max_past_skew_ms) {
            reasons.push(ReasonCode::Stale);
        }
        if env.issued_at_unix_ms > now.saturating_add(self.config.max_future_skew_ms) {
            reasons.push(ReasonCode::FromFuture);
        }
        if env.issued_at_unix_ms < st.epoch_floor_ms {
            reasons.push(ReasonCode::IssuedBeforeEpoch);
        }
        if nonce.is_none() {
            reasons.push(ReasonCode::MalformedNonce);
        }
        // Always computed; reported only for authentic envelopes.
        let stateful = match (fp, nonce) {
            (Some(f), Some(n)) => StatefulFreshness {
                replayed: st.replay.contains(&f, &n),
                out_of_order: st
                    .senders
                    .get(&f)
                    .and_then(|s| s.last_sequence)
                    .is_some_and(|last| env.sequence <= last),
            },
            _ => StatefulFreshness {
                replayed: false,
                out_of_order: false,
            },
        };
        if authentic {
            if stateful.replayed {
                reasons.push(ReasonCode::Replay);
            }
            if stateful.out_of_order {
                reasons.push(ReasonCode::SequenceNotIncreasing);
            }
        }

        // ---- Accept path: capacity, then commit.
        if let (true, Some(f), Some(n), Some(position), Some(gate_outcome)) =
            (reasons.is_empty(), fp, nonce, position, gate_outcome)
        {
            if st.replay.is_full() {
                st.replay.sweep(now);
            }
            let mut room = !st.replay.is_full();
            if !room {
                // Full of live entries. A sender under its fair share takes
                // the oldest entry of the sender holding the most; a sender
                // at or over its share waits (RETRY). Safe: the evicted
                // envelope's sequence is at or below its sender's retained
                // high-water mark, so replaying it fails the sequence check.
                let share = (self.config.replay_cache_capacity / keyring.len().max(1)).max(1);
                if st.replay.count(&f) < share && st.replay.evict_from_largest() {
                    counter!(t::REPLAY_EVICTIONS_TOTAL).increment(1);
                    room = true;
                }
            }
            if !room {
                reasons.push(ReasonCode::ReplayCacheFull);
            } else if let Some(sender_state) = st.senders.get_or_insert(f, now) {
                sender_state.last_sequence = Some(env.sequence);
                sender_state.last_accepted_at = Some(now);
                st.high_water_ms = st.high_water_ms.max(env.issued_at_unix_ms);
                let expires_at = now.saturating_add(self.config.replay_retention_ms());
                st.replay.insert(f, n, expires_at);
                gauge!(t::REPLAY_CACHE_ENTRIES).set(gauge_value(st.replay.len()));
                drop(st);
                let env = env.into_owned();
                return Verdict::Accepted(Box::new(VerifiedHandoff {
                    sender: f,
                    sequence: env.sequence,
                    issued_at_unix_ms: env.issued_at_unix_ms,
                    nonce: n,
                    gate_position: position,
                    gate_outcome,
                    subject_digest: env.subject_digest,
                    payload: env.payload,
                }));
            } else {
                reasons.push(ReasonCode::SenderTableFull);
            }
        }

        // ---- Refuse path: breaker accounting.
        let outcome = GateOutcome::resolve(reasons.iter().map(|r| r.outcome()));
        let mut resolution = Resolution::Reject;
        let counts = match self.config.breaker_attribution {
            BreakerAttribution::AuthenticatedOnly => {
                authentic
                    && reasons
                        .iter()
                        .any(|r| r.outcome() == GateOutcome::TerminalBreach && *r != ReasonCode::Replay)
            }
            BreakerAttribution::ClaimedSender => still_trusted && outcome == GateOutcome::TerminalBreach,
        };
        if let (true, Some(f)) = (counts, fp) {
            let window = self.config.breaker_window_ms;
            let threshold = self.config.breaker_threshold;
            match st.senders.get_or_insert(f, now) {
                Some(s) => {
                    if s.record_breach(now, window, threshold) {
                        s.quarantined_since = Some(now);
                        s.breaches.clear();
                        resolution = Resolution::Quarantine;
                        let q = st.senders.quarantined_count();
                        counter!(t::QUARANTINE_TRIPS_TOTAL).increment(1);
                        gauge!(t::QUARANTINED_SENDERS).set(gauge_value(q));
                        tracing::warn!(
                            sender = %f,
                            threshold,
                            window_ms = window,
                            "stack.trident sender quarantined by breaker"
                        );
                    }
                }
                None => counter!(t::BREAKER_UNTRACKED_TOTAL).increment(1),
            }
        }
        gauge!(t::REPLAY_CACHE_ENTRIES).set(gauge_value(st.replay.len()));
        drop(st);
        Verdict::refuse(reasons, resolution)
    }

    fn finish(&self, span: &tracing::Span, verdict: &Verdict, started: Instant) {
        // Labels carry the Trident's own result, not the sender's gate claim.
        let outcome = verdict.check_outcome().as_str();
        let resolution = match verdict {
            Verdict::Accepted(_) => "accept",
            Verdict::Refused(r) => r.resolution.as_str(),
        };
        counter!(t::VERIFICATIONS_TOTAL, "outcome" => outcome, "resolution" => resolution).increment(1);
        for r in verdict.reasons() {
            counter!(t::CHECK_FAILURES_TOTAL, "check" => r.check().as_str(), "reason" => r.as_str())
                .increment(1);
        }
        histogram!(t::VERIFY_DURATION_SECONDS, "outcome" => outcome).record(started.elapsed().as_secs_f64());
        span.record("outcome", outcome);
        span.record("resolution", resolution);
        match verdict {
            Verdict::Accepted(_) => tracing::debug!(outcome, "stack.trident accepted handoff"),
            Verdict::Refused(r) => {
                let codes: Vec<&'static str> = r.reasons.iter().map(|c| c.as_str()).collect();
                tracing::warn!(outcome, resolution, reasons = ?codes, "stack.trident refused handoff");
            }
        }
    }

    // ------------------------------------------------------------------
    // Operator controls
    // ------------------------------------------------------------------

    /// Lifts a sender's quarantine and clears its breach history. Returns
    /// whether the sender was quarantined.
    pub fn release(&self, fp: &Fingerprint) -> Result<bool, HaltedError> {
        let _span = tracing::info_span!(t::SPAN_RELEASE, sender = %fp).entered();
        let mut st = self.lock_state().ok_or(HaltedError)?;
        let released = st.senders.release(fp);
        if released {
            counter!(t::QUARANTINE_RELEASES_TOTAL).increment(1);
            gauge!(t::QUARANTINED_SENDERS).set(gauge_value(st.senders.quarantined_count()));
            tracing::info!(sender = %fp, "stack.trident quarantine released by operator");
        }
        Ok(released)
    }

    /// Senders currently quarantined, sorted.
    pub fn quarantined(&self) -> Result<Vec<Fingerprint>, HaltedError> {
        Ok(self.lock_state().ok_or(HaltedError)?.senders.quarantined())
    }

    /// Whether the Trident is halted.
    pub fn is_halted(&self) -> bool {
        self.halted.load(Ordering::SeqCst)
    }

    /// Stops accepting work. Every verification returns
    /// `Halted` / RETRY / halt until [`Trident::operator_reset`].
    ///
    /// The flag is set while holding the state lock, and every commit
    /// re-reads it under that lock, so no envelope is accepted after this
    /// returns, including one whose verification was already under way.
    pub fn operator_halt(&self) {
        let _span = tracing::warn_span!(t::SPAN_HALT).entered();
        // A poisoned lock still serializes; holding its guard is enough.
        let guard = self.state.lock();
        self.enter_halt(HaltCause::Operator);
        drop(guard);
    }

    /// The highest `issued_at_unix_ms` this receiver has accepted (or was
    /// given as `restored_high_water_ms`). Persist it, for example on every
    /// accept or periodically plus `max_future_skew_ms` of margin, and pass
    /// it back as `TridentConfig::restored_high_water_ms` on restart: the
    /// new process then refuses everything the old one could have accepted,
    /// even if the clock has gone backwards.
    pub fn high_water_ms(&self) -> Result<u64, HaltedError> {
        Ok(self.lock_state().ok_or(HaltedError)?.high_water_ms)
    }

    /// Resumes after a halt. Rebuilds freshness state from empty (clearing
    /// any lock poisoning), keeps every quarantine, and, when
    /// `enforce_startup_epoch` is on, raises the epoch floor to the largest
    /// of its old value, `now + max_future_skew_ms` and one past the
    /// highest `issued_at_unix_ms` ever accepted. So nothing accepted
    /// before the reset can be replayed after it, even if the clock has
    /// gone backwards in between. The floor never goes down.
    pub fn operator_reset(&self) {
        let _span = tracing::info_span!(t::SPAN_RESET).entered();
        self.state.clear_poison();
        self.keyring.clear_poison();
        let mut st = match self.state.lock() {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        };
        let floor = Self::epoch_floor(&self.config, self.clock.as_ref(), st.epoch_floor_ms, st.high_water_ms);
        st.replay.clear();
        st.senders.reset_keep_quarantine();
        st.epoch_floor_ms = floor;
        gauge!(t::REPLAY_CACHE_ENTRIES).set(0.0);
        gauge!(t::QUARANTINED_SENDERS).set(gauge_value(st.senders.quarantined_count()));
        drop(st);
        self.halted.store(false, Ordering::SeqCst);
        counter!(t::OPERATOR_RESETS_TOTAL).increment(1);
        tracing::warn!(epoch_floor_ms = floor, "stack.trident reset by operator");
    }

    /// Swaps in a new key ring. Receiver state for senders not in the new
    /// ring is dropped once it is idle (no acceptance within the replay
    /// retention window, no breach within the breaker window). Until then
    /// it stays as a tombstone, and quarantines stay until an operator
    /// lifts them, so a reload that drops and restores a sender cannot
    /// reset its sequence high-water mark.
    ///
    /// The swap happens while holding the state lock, and every commit
    /// re-checks the ring under that lock, so once this returns no envelope
    /// signed by a removed key is accepted, including one whose
    /// verification was already under way.
    pub fn replace_keyring(&self, keyring: KeyRing) -> Result<(), HaltedError> {
        let _span = tracing::info_span!(t::SPAN_REPLACE_KEYRING, keys = keyring.len()).entered();
        let ring = Arc::new(keyring);
        // Lock order everywhere: state, then key ring.
        let mut st = self.lock_state().ok_or(HaltedError)?;
        {
            let mut slot = match self.keyring.write() {
                Ok(g) => g,
                Err(_) => {
                    drop(st);
                    self.enter_halt(HaltCause::Poisoned);
                    return Err(HaltedError);
                }
            };
            *slot = Arc::clone(&ring);
        }
        let now = self.clock.now_unix_ms();
        st.senders.retain_for(&ring, now);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::clock::ManualClock;
    use crate::envelope::{seal, seal_for, EnvelopeDraft};
    use crate::keys::SecretKey;
    use serde_json::json;

    #[test]
    fn poisoned_state_halts_until_reset() {
        let clock = Arc::new(ManualClock::new(1_000_000));
        let mut ring = KeyRing::new(4);
        // TEST FIXTURE KEY. Not for any deployment.
        let key = SecretKey::from_bytes(vec![0x42; 32]).unwrap();
        let fp_hex = key.fingerprint().to_hex();
        ring.insert(SecretKey::from_bytes(vec![0x42; 32]).unwrap()).unwrap();
        let trident = Arc::new(Trident::new(TridentConfig::default(), ring, clock.clone()).unwrap());
        clock.advance(10_000);

        let tr = Arc::clone(&trident);
        let joined = std::thread::spawn(move || {
            let _guard = tr.state.lock().unwrap();
            panic!("poisoning the state lock for this test");
        })
        .join();
        assert!(joined.is_err());

        let env = seal(
            EnvelopeDraft {
                sequence: 1,
                issued_at_unix_ms: clock.now_unix_ms(),
                nonce: Nonce::from_bytes([1; 16]),
                gate_position: GatePosition::Alpha,
                gate_outcome: GateOutcome::Pass,
                payload: json!({"k": 1}),
            },
            &key,
            &trident.limits,
        )
        .unwrap();
        assert_eq!(env.sender, fp_hex);

        let v = trident.verify(&env);
        let r = v.refusal().unwrap();
        assert_eq!(r.reasons, vec![ReasonCode::Halted]);
        assert_eq!(r.resolution, Resolution::Halt);
        assert_eq!(r.outcome, GateOutcome::Retry);
        assert!(trident.is_halted());
        assert_eq!(trident.quarantined(), Err(HaltedError));

        trident.operator_reset();
        assert!(!trident.is_halted());
        // The reset raised the epoch floor: the envelope issued before it is
        // refused, a fresh one is accepted.
        assert!(trident.verify(&env).refusal().unwrap().has(ReasonCode::IssuedBeforeEpoch));
        clock.advance(10_000);
        let fresh = seal(
            EnvelopeDraft {
                sequence: 2,
                issued_at_unix_ms: clock.now_unix_ms(),
                nonce: Nonce::from_bytes([2; 16]),
                gate_position: GatePosition::Alpha,
                gate_outcome: GateOutcome::Pass,
                payload: json!({"k": 2}),
            },
            &key,
            &trident.limits,
        )
        .unwrap();
        assert!(trident.verify(&fresh).is_accepted());
    }

    fn draft(seq: u64, at: u64) -> EnvelopeDraft {
        EnvelopeDraft {
            sequence: seq,
            issued_at_unix_ms: at,
            nonce: Nonce::from_bytes([u8::try_from(seq).unwrap(); 16]),
            gate_position: GatePosition::Alpha,
            gate_outcome: GateOutcome::Pass,
            payload: json!({"k": seq}),
        }
    }

    #[test]
    fn audience_binds_the_envelope_to_one_receiver() {
        let clock = Arc::new(ManualClock::new(1_000_000));
        // TEST FIXTURE KEY. Not for any deployment.
        let key = SecretKey::from_bytes(vec![0x43; 32]).unwrap();
        let mut ring = KeyRing::new(4);
        ring.insert(SecretKey::from_bytes(vec![0x43; 32]).unwrap()).unwrap();
        let cfg = TridentConfig {
            audience: "rx-1".into(),
            ..TridentConfig::default()
        };
        let trident = Trident::new(cfg, ring, clock.clone()).unwrap();
        clock.advance(10_000);
        let now = clock.now_unix_ms();
        let unbound = seal(draft(1, now), &key, &trident.limits).unwrap();
        assert_eq!(trident.verify(&unbound).reasons(), &[ReasonCode::MacMismatch]);
        let other = seal_for(draft(2, now), &key, "rx-2", &trident.limits).unwrap();
        assert_eq!(trident.verify(&other).reasons(), &[ReasonCode::MacMismatch]);
        let mine = seal_for(draft(3, now), &key, "rx-1", &trident.limits).unwrap();
        assert!(trident.verify(&mine).is_accepted());
        let long = "a".repeat(crate::envelope::MAX_AUDIENCE_BYTES + 1);
        assert!(seal_for(draft(4, now), &key, &long, &trident.limits).is_err());
        let bad = TridentConfig {
            audience: long,
            ..TridentConfig::default()
        };
        assert_eq!(bad.validate().unwrap_err().field, "audience");
    }

    #[test]
    fn epoch_floor_never_goes_down_and_honours_restored_high_water() {
        let clock = Arc::new(ManualClock::new(1_000_000));
        let cfg = TridentConfig {
            restored_high_water_ms: 2_000_000,
            ..TridentConfig::default()
        };
        let trident = Trident::new(cfg, KeyRing::new(1), clock.clone()).unwrap();
        assert_eq!(trident.state.lock().unwrap().epoch_floor_ms, 2_000_001);
        assert_eq!(trident.high_water_ms(), Ok(2_000_000));
        trident.operator_reset();
        assert_eq!(trident.state.lock().unwrap().epoch_floor_ms, 2_000_001);
        clock.set(3_000_000);
        trident.operator_reset();
        assert_eq!(trident.state.lock().unwrap().epoch_floor_ms, 3_005_000);
        clock.set(0);
        trident.operator_reset();
        assert_eq!(trident.state.lock().unwrap().epoch_floor_ms, 3_005_000);
    }
}
