//! # tack-trident: the Inter-Agent Trident
//!
//! **Status: new design.** Of the seven TACK kernel components, only the
//! Sentinel Hash-Chain exists today (in `sentinel_os`). This crate is a
//! reference implementation of a component that does not yet exist in any
//! TACK repository. It borrows one check from `sentinel_os` (TRANSPLANTED)
//! and the gate vocabulary from CNS; nothing else here is running anywhere.
//!
//! ## The metaphor
//!
//! A trident has three prongs, and all three must strike. The sword-poke is
//! the guard at the gate who tests every arrival instead of trusting the
//! uniform. Here the "uniform" is an envelope that says who sent it, what it
//! is about, and when. The guard believes none of it and checks all of it.
//!
//! ## The goal
//!
//! Zero trust on every handoff between repositories and agents. When one
//! agent hands work to another, the receiver re-derives every claim in the
//! envelope from things it controls (its own key ring, its own clock, its
//! own hash of the payload, its own memory of what it has already seen) and
//! trusts none of the claims as written.
//!
//! ## Architecture, in order
//!
//! A [`HandoffEnvelope`] has ten fields: `version`, `sender` (the sender's
//! key fingerprint), `sequence`, `issued_at_unix_ms`, `nonce`,
//! `gate_position` (`alpha` or `omega`), `gate_outcome` (`pass`, `retry` or
//! `terminal_breach`), `subject_digest`, `payload` (any JSON) and `mac`.
//! A [`Trident`] checks it in four stages.
//!
//! 1. **Admission** (cheap, public, early exit). The raw byte length is
//!    compared with `max_envelope_bytes` before a single byte is parsed.
//!    Then a strict parser reads the JSON while counting nesting depth and
//!    values, and stops the moment either cap is passed. It also refuses
//!    floats, `NaN`/`Infinity`, integers beyond 2^53 - 1, duplicate keys and
//!    anything else outside strict JSON. Then the object must have exactly
//!    the ten fields with the right JSON types. Nothing in this stage
//!    touches a key or a hash, so a payload bomb costs the receiver at most
//!    one bounded pass over bounded input.
//! 2. **Custody** (early exit). If the Trident is halted, or the claimed
//!    sender is quarantined, the envelope is refused. Both facts are public
//!    state, so returning early leaks nothing. This is a fast path: both
//!    facts, and whether the sender's key is still in the ring, are checked
//!    again inside the stage 4 critical section, and that check decides.
//! 3. **The three prongs, all of them, every time.** For an envelope that
//!    got this far, all three prongs run to completion and every failing
//!    check is reported. The receiver never stops at the first failure,
//!    so neither the time taken nor the list of reasons tells an attacker
//!    which prong they got past first.
//!    * *Prong 1, authenticity.* HMAC-SHA256 under the sender's key, found
//!      by fingerprint in a [`KeyRing`] the caller supplies. There is no
//!      built-in or default key. The MAC covers a domain separator
//!      ([`MAC_DOMAIN`], or [`MAC_AUDIENCE_DOMAIN`] plus the receiver's
//!      configured `audience` when one is set) followed by the canonical
//!      encoding of every field except `mac`, and is compared in constant
//!      time. With an audience configured, an envelope sealed for another
//!      receiver (see [`seal_for`]) fails here, even when both receivers
//!      trust the same sender key.
//!    * *Prong 2, binding.* SHA-256 over the canonical payload, compared
//!      with `subject_digest`. This is the TRANSPLANTED check that
//!      `sentinel_os` (`twin_custody.verify_subject_binding`) applies to
//!      ledger rows: a verdict moved onto content it was not issued for is
//!      caught because the digest is recomputed, not read. This prong also
//!      enforces the closed vocabularies for `version`, `gate_position` and
//!      `gate_outcome`.
//!    * *Prong 3, freshness.* `issued_at_unix_ms` must fall inside the skew
//!      window and at or after the epoch floor, which never goes down (see
//!      `TridentConfig::enforce_startup_epoch`). The (sender, nonce) pair
//!      must not be in the bounded replay cache, and `sequence` must be
//!      strictly greater than the last one accepted from that sender.
//! 4. **Commit or breaker.** Under the state lock, custody is re-checked
//!    (halt, quarantine, key still in the ring); the operator calls and
//!    breaker trips that change those facts take the same lock, so none of
//!    them can be overtaken by a verification already under way. If
//!    everything passed, the sender's sequence and the nonce are recorded,
//!    in the same critical section as the prong 3 lookups, and a
//!    [`VerifiedHandoff`] with typed fields is returned. If not, and the failure is a terminal breach attributable
//!    to a known sender, it counts toward that sender's circuit breaker:
//!    `breaker_threshold` (K) counted breaches inside `breaker_window_ms`
//!    quarantine the sender until an operator calls [`Trident::release`].
//!
//! ## Canonical encoding
//!
//! Sorted object keys, no insignificant whitespace, integers only, floats
//! and non-finite numbers and duplicate keys refused. The precise rules
//! are in [`canonical`]. For this integer-only subset the output is RFC
//! 8785 (JCS). **The producer must produce exactly these bytes**, or every
//! envelope it sends fails prong 1 and prong 2. The wire form itself does
//! not have to be canonical: the receiver re-encodes what it parsed, so
//! whitespace or key order on the wire does not matter, but the parsed
//! values must be identical.
//!
//! ## Outcomes and resolutions
//!
//! Every [`ReasonCode`] maps to one CNS outcome (see
//! [`ReasonCode::outcome`]); a refusal's outcome is the CNS resolution of
//! all of them (any TERMINAL_BREACH wins, then RETRY). For an accepted
//! envelope, [`Verdict::outcome`] is the CNS resolution of PASS and the
//! sender's authenticated `gate_outcome`, so an upstream TERMINAL_BREACH or
//! RETRY is never read as PASS by a consumer that acts on the outcome.
//! [`Verdict::check_outcome`] is the Trident's own result alone and is what
//! the metrics label. The state resolution is:
//!
//! * **reject** for every refusal except the two below. Nothing changes.
//! * **quarantine** when the sender is already quarantined, and on the
//!   envelope that trips the breaker.
//! * **halt** when the Trident is halted, either by
//!   [`Trident::operator_halt`] or because a lock was poisoned by a panic
//!   elsewhere (the state may be inconsistent, so it stops rather than
//!   guesses). [`Trident::operator_reset`] resumes.
//! * **rollback** is never used: state changes only after every check has
//!   passed, in one critical section, so there is nothing partial to undo.
//!
//! ## What the reply reveals, and timing
//!
//! * Admission and custody refusals return early. Their timing and reason
//!   depend only on public facts (length, structure, halt and quarantine).
//! * Prong 1 always computes one HMAC over the same input. With no key for
//!   the claimed sender, it keys the HMAC with a throwaway value derived
//!   from the public `sender` field and discards the result. Remaining
//!   timing differences: the key ring's hash-map lookup, and HMAC keys
//!   longer than 64 bytes being pre-hashed.
//! * `UnknownSender` versus `MacMismatch` tells a caller whether a
//!   fingerprint is in the ring. Fingerprints are public identifiers, so
//!   this is accepted; see the open questions.
//! * The stateful freshness results (`Replay`, `SequenceNotIncreasing`)
//!   are always computed but reported only when prong 1 passed. Otherwise
//!   anyone who knows a sender's fingerprint could send forged envelopes
//!   and read that sender's sequence counter and replay cache back out of
//!   the reasons. This is a deliberate narrowing of "report every failing
//!   prong", limited to unauthenticated envelopes.
//! * Capacity handling adds work only when a table is full: a scan over
//!   senders holding replay entries to find the largest holder, and a scan
//!   of the sender table for an idle entry. Its timing depends on receiver
//!   load, not on anything secret in the envelope, and it runs only after
//!   every prong has passed.
//! * The metrics and logs add a small, reason-count-dependent cost per
//!   verification. That cost is correlated with the reasons, which the
//!   reply already states, so it reveals nothing new. It could matter if
//!   a future caller hides the reasons from senders. The Trident does not
//!   pad its own response time; ANC (Active Timing Cancellation) is the
//!   layer that does.
//!
//! ## Telemetry
//!
//! Metric names are in [`telemetry`]. Labels come only from closed enums.
//! The verify span, `tack.trident.verify`, records the input length and the
//! full SHA-256 hex digest of the input (the raw bytes on the wire path,
//! the canonical MAC input on the in-process path), never the input
//! itself. An input over the size cap is logged by length only, because
//! hashing it would be the unbounded work the cap exists to stop.
//!
//! ## Open questions
//!
//! 1. **Interop with CNS `subject_digest`.** `cns.gate.subject_digest` in
//!    `/home/user/CNS/cns/gate.py` does not hash JSON. It hashes a
//!    type-tagged, length-prefixed rendering, and it accepts floats. A
//!    Python producer that fills `subject_digest` with the CNS function
//!    will fail prong 2 on every envelope. Either the envelope specifies
//!    the CNS rendering (and this crate ports it, including its float rule,
//!    and its string lengths counted in code points), or the Python side
//!    adds a JCS producer. The canonical encoding here has been checked
//!    against Python's `json.dumps(sort_keys=True, separators=(",", ":"),
//!    ensure_ascii=False)` only for keys inside the Basic Multilingual
//!    Plane.
//! 2. Whether the reply should collapse `UnknownSender` and `MacMismatch`.
//! 3. Freshness state lives in memory. The epoch floor closes the replay
//!    window after an operator reset exactly (it is raised above the
//!    highest `issued_at_unix_ms` ever accepted). After a restart it is
//!    exact only if the caller persisted [`Trident::high_water_ms`] and
//!    passes it back as `TridentConfig::restored_high_water_ms`; otherwise
//!    it assumes the wall clock has not gone backwards across the restart.
//!    A multi-replica receiver needs shared replay state or sender
//!    affinity.
//! 4. **Symmetric keys.** HMAC keys are shared secrets: any receiver that
//!    holds a sender's key can also forge envelopes as that sender, and
//!    `audience` binding only stops honest receivers from accepting a
//!    redirected envelope. Prefer one key per (sender, receiver) pair, or
//!    move to signatures. `audience` is empty by default, which binds no
//!    receiver; set it whenever more than one receiver trusts a sender key.

#![forbid(unsafe_code)]

pub mod canonical;
pub mod clock;
pub mod config;
pub mod envelope;
pub mod keys;
mod state;
pub mod telemetry;
mod trident;
pub mod verdict;
pub mod vocab;

pub use canonical::{CanonicalError, Limits, MAX_SAFE_INTEGER};
pub use clock::{Clock, ManualClock, SystemClock};
pub use config::{BreakerAttribution, ConfigError, TridentConfig};
pub use envelope::{
    seal, seal_for, EnvelopeDraft, HandoffEnvelope, Nonce, SealError, ENVELOPE_OWN_NODES, ENVELOPE_VERSION,
    FIELD_NAMES, MAC_AUDIENCE_DOMAIN, MAC_DOMAIN, MAX_AUDIENCE_BYTES,
};
pub use keys::{Fingerprint, KeyError, KeyRing, SecretKey};
pub use trident::{HaltedError, Trident};
pub use verdict::{Refusal, Verdict, VerifiedHandoff};
pub use vocab::{Check, GateOutcome, GatePosition, ReasonCode, Resolution};
