//! The gate: holds pieces until the puzzle is whole, inspects the whole, and
//! releases it. Everything is bounded and everything fails closed.

use std::collections::{BTreeMap, BTreeSet, HashMap, VecDeque};
use std::fmt;
use std::sync::{Arc, Mutex};
use std::time::Instant;

use metrics::{counter, gauge, histogram};

use super::breaker::SenderState;
use super::config::PuzzleConfig;
use super::inspect::{Finding, InspectInput, Inspector};
use super::piece::{parse_message, root_of, Message, Piece, PieceError, PuzzleId};
use super::telemetry as t;
use crate::clock::Clock;
use crate::config::ConfigError;
use crate::envelope::HandoffEnvelope;
use crate::keys::Fingerprint;
use crate::trident::Trident;
use crate::verdict::{Refusal, Verdict, VerifiedHandoff};
use crate::vocab::GateOutcome;

type Key = (Fingerprint, PuzzleId);

/// Most close events kept for [`PuzzleGate::take_closed`]. The oldest are
/// dropped first.
const MAX_CLOSED_EVENTS: usize = 4_096;

/// A finished, inspected puzzle.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Whole {
    /// The authenticated sender.
    pub sender: Fingerprint,
    /// The puzzle.
    pub puzzle: PuzzleId,
    /// The pieces joined in index order. This is what passed inspection.
    pub bytes: Vec<u8>,
    /// How many pieces it had.
    pub pieces: u32,
}

/// Why the gate said "busy" instead of "no". Busy never costs the sender a
/// breach: the limit is the gate's, not the sender's fault.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BusyReason {
    /// The sender already has the most open puzzles allowed.
    TooManyOpen,
    /// The holding area is full and no older puzzle could be evicted.
    HoldingAreaFull,
    /// The gate tracks as many senders as it may and none is idle.
    TooManySenders,
}

/// Why the gate refused a message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PuzzleRefusal {
    /// The gate's lock was poisoned by a panic; it refuses everything.
    Halted,
    /// The sender's own gate said retry or terminal breach, so its pieces are
    /// not released.
    SenderGateNotPass,
    /// The sender is quarantined until this Unix time in milliseconds.
    Quarantined {
        /// End of the quarantine.
        until_ms: u64,
    },
    /// Over a limit; see [`BusyReason`].
    Busy(BusyReason),
    /// The payload is not a well-formed puzzle message.
    Malformed(PieceError),
    /// An abort for a puzzle that is not open and was not recently closed.
    UnknownPuzzle,
    /// The puzzle was closed a moment ago; late pieces are ignored.
    AlreadyClosed,
    /// A piece disagrees with its puzzle's declaration or with a piece
    /// already held.
    Conflict,
    /// The same whole from the same sender was released inside the replay
    /// window.
    ReplayedWhole,
    /// The pieces do not hash to the declared root.
    RootMismatch,
    /// The inspector found the whole hostile.
    ContentBlocked(&'static str),
    /// The inspector found the whole suspicious.
    ContentSuspicious(&'static str),
}

impl PuzzleRefusal {
    /// The closed spelling used as a metric label. An inspector's own reason
    /// text is deliberately not part of it.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Halted => "halted",
            Self::SenderGateNotPass => "sender_gate_not_pass",
            Self::Quarantined { .. } => "quarantined",
            Self::Busy(BusyReason::TooManyOpen) => "busy_too_many_open",
            Self::Busy(BusyReason::HoldingAreaFull) => "busy_holding_area_full",
            Self::Busy(BusyReason::TooManySenders) => "busy_too_many_senders",
            Self::Malformed(_) => "malformed",
            Self::UnknownPuzzle => "unknown_puzzle",
            Self::AlreadyClosed => "already_closed",
            Self::Conflict => "conflict",
            Self::ReplayedWhole => "replayed_whole",
            Self::RootMismatch => "root_mismatch",
            Self::ContentBlocked(_) => "content_blocked",
            Self::ContentSuspicious(_) => "content_suspicious",
        }
    }

    /// Whether this refusal costs the sender a breach. Refusals that are the
    /// gate's doing (busy, quarantined, halted) or that cannot be pinned on
    /// the sender (unknown puzzle, late pieces, an uncertain finding) do not.
    pub fn counts_as_breach(&self) -> bool {
        matches!(
            self,
            Self::Malformed(_) | Self::Conflict | Self::ReplayedWhole | Self::RootMismatch | Self::ContentBlocked(_)
        )
    }
}

/// The gate's answer to one message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    /// Accepted and held; this many pieces are still missing.
    Held {
        /// Pieces still missing.
        remaining: u32,
    },
    /// The puzzle is complete and passed inspection.
    Released(Whole),
    /// The sender cancelled an open puzzle.
    Aborted,
    /// Refused by the gate.
    Refused(PuzzleRefusal),
    /// Refused by the Trident before the gate saw it. The gate's state is
    /// untouched and nothing is counted against the claimed sender.
    Rejected(Refusal),
}

/// Why a puzzle stopped being open.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CloseReason {
    /// Complete and released.
    Released,
    /// Cancelled by its sender.
    Aborted,
    /// Reached its deadline incomplete.
    Exploded,
    /// Pushed out to make room, being the oldest incomplete puzzle.
    Evicted,
    /// A piece contradicted the declaration or an earlier piece.
    Conflict,
    /// The pieces did not hash to the declared root.
    RootMismatch,
    /// The inspector found it hostile.
    Hostile,
    /// The inspector found it suspicious.
    Suspicious,
    /// Its sender was quarantined.
    Quarantined,
}

impl CloseReason {
    /// The closed spelling used as a metric label.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Released => "released",
            Self::Aborted => "aborted",
            Self::Exploded => "exploded",
            Self::Evicted => "evicted",
            Self::Conflict => "conflict",
            Self::RootMismatch => "root_mismatch",
            Self::Hostile => "hostile",
            Self::Suspicious => "suspicious",
            Self::Quarantined => "quarantined",
        }
    }
}

impl Outcome {
    /// The closed spelling used as the `outcome` metric label.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Held { .. } => "held",
            Self::Released(_) => "released",
            Self::Aborted => "aborted",
            Self::Refused(_) => "refused",
            Self::Rejected(_) => "rejected",
        }
    }
}

/// A puzzle that is no longer open.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Closed {
    /// The sender.
    pub sender: Fingerprint,
    /// The puzzle.
    pub puzzle: PuzzleId,
    /// Why it closed.
    pub reason: CloseReason,
    /// Pieces it held.
    pub pieces: u32,
    /// Bytes it held.
    pub bytes: usize,
    /// Whether closing it cost the sender a breach.
    pub breach: bool,
}

/// A snapshot of what the gate holds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GateStats {
    /// Open puzzles.
    pub open_puzzles: usize,
    /// Bytes of pieces held.
    pub held_bytes: usize,
    /// Senders with gate-side state.
    pub tracked_senders: usize,
}

struct Open {
    total: u32,
    root: [u8; 32],
    pieces: BTreeMap<u32, Vec<u8>>,
    bytes: usize,
    first_ms: u64,
    deadline_ms: u64,
    seq: u64,
}

#[derive(Default)]
struct State {
    open: HashMap<Key, Open>,
    by_deadline: BTreeSet<(u64, u64)>,
    by_seq: BTreeMap<u64, Key>,
    held_bytes: usize,
    next_seq: u64,
    senders: HashMap<Fingerprint, SenderState>,
    released: HashMap<(Fingerprint, [u8; 32]), u64>,
    released_order: VecDeque<((Fingerprint, [u8; 32]), u64)>,
    tombs: HashMap<Key, u64>,
    tomb_order: VecDeque<(Key, u64)>,
    closed: VecDeque<Closed>,
}

impl State {
    fn publish_gauges(&self) {
        gauge!(t::OPEN_PUZZLES).set(t::gauge_value(self.open.len()));
        gauge!(t::HELD_BYTES).set(t::gauge_value(self.held_bytes));
    }

    fn push_closed(&mut self, c: Closed) {
        if self.closed.len() >= MAX_CLOSED_EVENTS {
            self.closed.pop_front();
        }
        self.closed.push_back(c);
    }

    fn remember_closed(&mut self, key: Key, now: u64, cfg: &PuzzleConfig) {
        let expires = now.saturating_add(cfg.max_lifetime_ms);
        self.tombs.insert(key, expires);
        self.tomb_order.push_back((key, expires));
        loop {
            let over = self.tomb_order.len() > cfg.memory_capacity;
            let stale = self.tomb_order.front().is_some_and(|&(_, e)| e <= now);
            if !(over || stale) {
                break;
            }
            if let Some((k, e)) = self.tomb_order.pop_front() {
                if self.tombs.get(&k) == Some(&e) {
                    self.tombs.remove(&k);
                }
            }
        }
    }

    fn tomb_live(&self, key: &Key, now: u64) -> bool {
        self.tombs.get(key).is_some_and(|&e| now < e)
    }

    fn remember_release(&mut self, fp: Fingerprint, root: [u8; 32], now: u64, cfg: &PuzzleConfig) {
        if cfg.replay_window_ms == 0 {
            return;
        }
        let k = (fp, root);
        self.released.insert(k, now);
        self.released_order.push_back((k, now));
        loop {
            let over = self.released_order.len() > cfg.memory_capacity;
            let stale = self.released_order.front().is_some_and(|&(_, t)| now.saturating_sub(t) >= cfg.replay_window_ms);
            if !(over || stale) {
                break;
            }
            if let Some((k, t)) = self.released_order.pop_front() {
                if self.released.get(&k) == Some(&t) {
                    self.released.remove(&k);
                }
            }
        }
    }

    fn is_replay(&self, fp: Fingerprint, root: [u8; 32], now: u64, cfg: &PuzzleConfig) -> bool {
        cfg.replay_window_ms > 0
            && self.released.get(&(fp, root)).is_some_and(|&t| now.saturating_sub(t) < cfg.replay_window_ms)
    }

    fn ensure_sender(&mut self, fp: Fingerprint, now: u64, cfg: &PuzzleConfig) -> Result<(), BusyReason> {
        if self.senders.contains_key(&fp) {
            return Ok(());
        }
        if self.senders.len() >= cfg.max_tracked_senders {
            let idle = self.senders.iter().find(|(_, s)| s.is_idle(now, cfg)).map(|(k, _)| *k);
            match idle {
                Some(k) => {
                    self.senders.remove(&k);
                }
                None => return Err(BusyReason::TooManySenders),
            }
        }
        self.senders.insert(fp, SenderState::default());
        Ok(())
    }

    fn quarantine_until(&mut self, fp: Fingerprint, now: u64) -> Option<u64> {
        self.senders.get_mut(&fp).and_then(|s| s.quarantine_remaining(now))
    }

    /// Counts a breach against `fp`; if that starts a quarantine, destroys
    /// the sender's open puzzles.
    fn breach(&mut self, fp: Fingerprint, now: u64, cfg: &PuzzleConfig) {
        let started = self.senders.get_mut(&fp).is_some_and(|s| s.record_breach(now, cfg));
        counter!(t::BREACHES_TOTAL).increment(1);
        if started {
            counter!(t::QUARANTINE_TRIPS_TOTAL).increment(1);
            tracing::warn!(target: "stack_trident::puzzle", sender = %fp, "sender quarantined by the puzzle gate");
            let keys: Vec<Key> = self.open.keys().filter(|k| k.0 == fp).copied().collect();
            for k in keys {
                self.close(k, CloseReason::Quarantined, false, now, cfg);
            }
        }
    }

    /// Destroys an open puzzle. Nothing it held is released.
    fn close(&mut self, key: Key, reason: CloseReason, breach: bool, now: u64, cfg: &PuzzleConfig) {
        let Some(open) = self.open.remove(&key) else {
            return;
        };
        self.by_deadline.remove(&(open.deadline_ms, open.seq));
        self.by_seq.remove(&open.seq);
        self.held_bytes = self.held_bytes.saturating_sub(open.bytes);
        if let Some(s) = self.senders.get_mut(&key.0) {
            s.open = s.open.saturating_sub(1);
        }
        self.remember_closed(key, now, cfg);
        counter!(t::CLOSED_TOTAL, "reason" => reason.as_str()).increment(1);
        self.publish_gauges();
        self.push_closed(Closed {
            sender: key.0,
            puzzle: key.1,
            reason,
            pieces: u32::try_from(open.pieces.len()).unwrap_or(u32::MAX),
            bytes: open.bytes,
            breach,
        });
        if breach {
            self.breach(key.0, now, cfg);
        }
    }

    /// Explodes every puzzle past its deadline.
    fn sweep(&mut self, now: u64, cfg: &PuzzleConfig) -> usize {
        let mut n = 0;
        while let Some(&(dl, seq)) = self.by_deadline.iter().next() {
            if dl > now {
                break;
            }
            if let Some(key) = self.by_seq.get(&seq).copied() {
                self.close(key, CloseReason::Exploded, true, now, cfg);
                n += 1;
            }
            self.by_deadline.remove(&(dl, seq));
        }
        n
    }

    /// Evicts the oldest incomplete puzzles (never `keep`) until a puzzle of
    /// `need_bytes` fits. Returns false if nothing more can be evicted.
    fn make_room(&mut self, new_puzzle: bool, need_bytes: usize, keep: Option<Key>, now: u64, cfg: &PuzzleConfig) -> bool {
        loop {
            let slot_ok = !new_puzzle || self.open.len() < cfg.max_open_total;
            let bytes_ok = self.held_bytes.saturating_add(need_bytes) <= cfg.max_held_bytes;
            if slot_ok && bytes_ok {
                return true;
            }
            let victim = self.by_seq.values().find(|k| Some(**k) != keep).copied();
            match victim {
                Some(k) => self.close(k, CloseReason::Evicted, true, now, cfg),
                None => return false,
            }
        }
    }

    fn abort(&mut self, key: Key, now: u64, cfg: &PuzzleConfig) -> Outcome {
        if self.open.contains_key(&key) {
            self.close(key, CloseReason::Aborted, false, now, cfg);
            Outcome::Aborted
        } else if self.tomb_live(&key, now) {
            Outcome::Refused(PuzzleRefusal::AlreadyClosed)
        } else {
            Outcome::Refused(PuzzleRefusal::UnknownPuzzle)
        }
    }

    fn conflict(&mut self, key: Key, now: u64, cfg: &PuzzleConfig) -> Outcome {
        self.close(key, CloseReason::Conflict, true, now, cfg);
        Outcome::Refused(PuzzleRefusal::Conflict)
    }

    fn piece(&mut self, fp: Fingerprint, p: Piece, now: u64, cfg: &PuzzleConfig, inspector: &dyn Inspector) -> Outcome {
        let key: Key = (fp, p.puzzle);
        if self.tomb_live(&key, now) {
            return Outcome::Refused(PuzzleRefusal::AlreadyClosed);
        }
        let incoming = p.data.len();
        if let Some(o) = self.open.get(&key) {
            if o.total != p.total || o.root != p.root {
                return self.conflict(key, now, cfg);
            }
            if let Some(prev) = o.pieces.get(&p.index) {
                if *prev == p.data {
                    let have = u32::try_from(o.pieces.len()).unwrap_or(u32::MAX);
                    return Outcome::Held { remaining: o.total.saturating_sub(have) };
                }
                return self.conflict(key, now, cfg);
            }
            if !self.make_room(false, incoming, Some(key), now, cfg) {
                return Outcome::Refused(PuzzleRefusal::Busy(BusyReason::HoldingAreaFull));
            }
            if !self.open.contains_key(&key) {
                // Evicting other puzzles of this same sender quarantined it.
                let until_ms = self.quarantine_until(fp, now).unwrap_or(now);
                return Outcome::Refused(PuzzleRefusal::Quarantined { until_ms });
            }
        } else {
            if self.is_replay(fp, p.root, now, cfg) {
                self.breach(fp, now, cfg);
                return Outcome::Refused(PuzzleRefusal::ReplayedWhole);
            }
            if self.senders.get(&fp).is_some_and(|s| s.open >= cfg.max_open_per_sender) {
                return Outcome::Refused(PuzzleRefusal::Busy(BusyReason::TooManyOpen));
            }
            if !self.make_room(true, incoming, None, now, cfg) {
                return Outcome::Refused(PuzzleRefusal::Busy(BusyReason::HoldingAreaFull));
            }
            if let Some(until_ms) = self.quarantine_until(fp, now) {
                return Outcome::Refused(PuzzleRefusal::Quarantined { until_ms });
            }
            let seq = self.next_seq;
            self.next_seq = self.next_seq.wrapping_add(1);
            let deadline_ms = now.saturating_add(cfg.idle_ms).min(now.saturating_add(cfg.max_lifetime_ms));
            self.open.insert(
                key,
                Open { total: p.total, root: p.root, pieces: BTreeMap::new(), bytes: 0, first_ms: now, deadline_ms, seq },
            );
            self.by_deadline.insert((deadline_ms, seq));
            self.by_seq.insert(seq, key);
            if let Some(s) = self.senders.get_mut(&fp) {
                s.open += 1;
            }
        }

        // Add the piece and let the deadline follow progress.
        gauge!(t::OPEN_PUZZLES).set(t::gauge_value(self.open.len()));
        gauge!(t::HELD_BYTES).set(t::gauge_value(self.held_bytes.saturating_add(incoming)));
        let Some(o) = self.open.get_mut(&key) else {
            return Outcome::Refused(PuzzleRefusal::UnknownPuzzle);
        };
        o.pieces.insert(p.index, p.data);
        o.bytes = o.bytes.saturating_add(incoming);
        self.held_bytes = self.held_bytes.saturating_add(incoming);
        let new_deadline = now.saturating_add(cfg.idle_ms).min(o.first_ms.saturating_add(cfg.max_lifetime_ms));
        if new_deadline != o.deadline_ms {
            self.by_deadline.remove(&(o.deadline_ms, o.seq));
            o.deadline_ms = new_deadline;
            self.by_deadline.insert((new_deadline, o.seq));
        }
        let have = u32::try_from(o.pieces.len()).unwrap_or(u32::MAX);
        if have < o.total {
            return Outcome::Held { remaining: o.total - have };
        }

        // Complete: recompute the root, assemble, inspect.
        let declared = o.root;
        let root = root_of(o.pieces.values().map(Vec::as_slice));
        let whole: Vec<u8> = o.pieces.values().flat_map(|v| v.iter().copied()).collect();
        if root != declared {
            self.close(key, CloseReason::RootMismatch, true, now, cfg);
            return Outcome::Refused(PuzzleRefusal::RootMismatch);
        }
        let started = Instant::now();
        let finding = {
            let history: &[Vec<u8>] = match self.senders.get_mut(&fp) {
                Some(s) => &*s.history.make_contiguous(),
                None => &[],
            };
            inspector.inspect(&InspectInput { sender: &fp, puzzle: p.puzzle, whole: &whole, history })
        };
        let kind = match finding {
            Finding::Pass => "pass",
            Finding::Suspicious(_) => "suspicious",
            Finding::Hostile(_) => "hostile",
        };
        histogram!(t::INSPECT_DURATION_SECONDS, "finding" => kind).record(started.elapsed().as_secs_f64());
        match finding {
            Finding::Hostile(reason) => {
                self.close(key, CloseReason::Hostile, true, now, cfg);
                Outcome::Refused(PuzzleRefusal::ContentBlocked(reason))
            }
            Finding::Suspicious(reason) => {
                self.close(key, CloseReason::Suspicious, false, now, cfg);
                Outcome::Refused(PuzzleRefusal::ContentSuspicious(reason))
            }
            Finding::Pass => {
                self.remember_release(fp, declared, now, cfg);
                if let Some(s) = self.senders.get_mut(&fp) {
                    s.push_history(&whole, cfg);
                }
                self.close(key, CloseReason::Released, false, now, cfg);
                Outcome::Released(Whole { sender: fp, puzzle: p.puzzle, bytes: whole, pieces: have })
            }
        }
    }
}

/// The puzzle gate. See the module documentation and the design note.
pub struct PuzzleGate {
    cfg: PuzzleConfig,
    trident: Arc<Trident>,
    inspector: Arc<dyn Inspector>,
    clock: Arc<dyn Clock>,
    state: Mutex<State>,
}

impl fmt::Debug for PuzzleGate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PuzzleGate").field("cfg", &self.cfg).finish_non_exhaustive()
    }
}

impl PuzzleGate {
    /// A gate that verifies every piece with `trident`, inspects every
    /// finished whole with `inspector`, and reads time from `clock` (use the
    /// Trident's clock so both agree).
    pub fn new(
        cfg: PuzzleConfig,
        trident: Arc<Trident>,
        inspector: Arc<dyn Inspector>,
        clock: Arc<dyn Clock>,
    ) -> Result<Self, ConfigError> {
        cfg.validate()?;
        Ok(Self { cfg, trident, inspector, clock, state: Mutex::new(State::default()) })
    }

    /// The configuration in force.
    pub fn config(&self) -> &PuzzleConfig {
        &self.cfg
    }

    /// Verifies an in-process envelope with the Trident and offers it.
    pub fn offer_envelope(&self, env: &HandoffEnvelope) -> Outcome {
        self.offer_verdict(self.trident.verify(env))
    }

    /// Verifies wire bytes with the Trident and offers the result.
    pub fn offer_wire(&self, bytes: &[u8]) -> Outcome {
        self.offer_verdict(self.trident.verify_wire(bytes))
    }

    /// Destroys every puzzle past its deadline and returns how many. The gate
    /// also does this before handling any message; call this from a timer so
    /// explosions happen on time when no traffic arrives.
    pub fn sweep(&self) -> usize {
        let _span = tracing::info_span!(t::SPAN_SWEEP).entered();
        let now = self.clock.now_unix_ms();
        match self.state.lock() {
            Ok(mut st) => st.sweep(now, &self.cfg),
            Err(_) => 0,
        }
    }

    /// Takes the puzzles that closed since the last call, oldest first.
    pub fn take_closed(&self) -> Vec<Closed> {
        match self.state.lock() {
            Ok(mut st) => st.closed.drain(..).collect(),
            Err(_) => Vec::new(),
        }
    }

    /// What the gate holds right now.
    pub fn stats(&self) -> GateStats {
        match self.state.lock() {
            Ok(st) => GateStats { open_puzzles: st.open.len(), held_bytes: st.held_bytes, tracked_senders: st.senders.len() },
            Err(_) => GateStats { open_puzzles: 0, held_bytes: 0, tracked_senders: 0 },
        }
    }

    fn offer_verdict(&self, verdict: Verdict) -> Outcome {
        let span = tracing::info_span!(t::SPAN_OFFER, outcome = tracing::field::Empty, refusal = tracing::field::Empty);
        let _entered = span.enter();
        let outcome = match verdict {
            Verdict::Refused(r) => Outcome::Rejected(r),
            Verdict::Accepted(h) => self.offer_verified(&h),
        };
        counter!(t::MESSAGES_TOTAL, "outcome" => outcome.as_str()).increment(1);
        span.record("outcome", outcome.as_str());
        match &outcome {
            Outcome::Refused(r) => {
                counter!(t::REFUSALS_TOTAL, "reason" => r.as_str()).increment(1);
                span.record("refusal", r.as_str());
                match r {
                    PuzzleRefusal::ContentBlocked(why) => {
                        tracing::warn!(target: "stack_trident::puzzle", why = *why, "stack.trident puzzle blocked a whole");
                    }
                    PuzzleRefusal::ContentSuspicious(why) => {
                        tracing::warn!(target: "stack_trident::puzzle", why = *why, "stack.trident puzzle refused a suspicious whole");
                    }
                    _ => tracing::debug!(target: "stack_trident::puzzle", refusal = r.as_str(), "stack.trident puzzle refused a message"),
                }
            }
            Outcome::Rejected(_) => tracing::debug!(target: "stack_trident::puzzle", "stack.trident puzzle message rejected by the Trident"),
            _ => {}
        }
        outcome
    }

    fn offer_verified(&self, h: &VerifiedHandoff) -> Outcome {
        if h.gate_outcome != GateOutcome::Pass {
            return Outcome::Refused(PuzzleRefusal::SenderGateNotPass);
        }
        let parsed = parse_message(&h.payload, &self.cfg);
        let now = self.clock.now_unix_ms();
        let Ok(mut st) = self.state.lock() else {
            return Outcome::Refused(PuzzleRefusal::Halted);
        };
        let st = &mut *st;
        st.sweep(now, &self.cfg);
        let fp = h.sender;
        if let Err(busy) = st.ensure_sender(fp, now, &self.cfg) {
            return Outcome::Refused(PuzzleRefusal::Busy(busy));
        }
        if let Some(until_ms) = st.quarantine_until(fp, now) {
            return Outcome::Refused(PuzzleRefusal::Quarantined { until_ms });
        }
        match parsed {
            Err(e) => {
                st.breach(fp, now, &self.cfg);
                Outcome::Refused(PuzzleRefusal::Malformed(e))
            }
            Ok(Message::Abort(id)) => st.abort((fp, id), now, &self.cfg),
            Ok(Message::Piece(p)) => st.piece(fp, p, now, &self.cfg, self.inspector.as_ref()),
        }
    }
}
