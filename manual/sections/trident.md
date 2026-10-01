## 2. Inter-Agent Trident

The Inter-Agent Trident accepts a handoff only when all three of its checks pass, and refuses everything else with one of 28 typed reasons.

*New design: reference implementation compiled and tested on Rust 1.94*

### Metaphor and goal

A trident has three prongs, and a strike counts only when all three land. Picture the guard at a gate who tests every arrival instead of trusting the uniform. Here the uniform is an envelope that claims who sent it, what it is about and when.

The goal is zero trust on every handoff between repositories or agents. Zero trust means no message is believed because of where it came from. The receiver re-derives each claim from its own key ring, its own clock, its own payload hash and its own record of past envelopes.

Each prong answers one question:

| Prong | Question it answers | How the receiver checks | What the receiver relies on |
|---|---|---|---|
| 1. Authenticity | Did a holder of the sender's key make this envelope? | HMAC-SHA256 over every other field, compared in constant time | Its own key ring |
| 2. Binding | Is the gate verdict about this exact content? | SHA-256 of the canonical payload, compared with `subject_digest` | Its own hash |
| 3. Freshness | Is the envelope new and in order? | Clock window, epoch floor, replay cache and sequence number | Its own clock and memory |

Terms used below:

- **HMAC.** A keyed hash: a 32-byte tag that only a holder of the secret key can produce.
- **Constant-time compare.** A comparison whose duration does not depend on where the first differing byte sits.
- **Nonce.** A random value used once per envelope, here 16 bytes.
- **Replay.** A genuine envelope, captured and sent again.
- **Canonical encoding.** One exact byte form for every value, so sender and receiver hash identical bytes.

This is a new design. No TACK repository has a Trident today; of the seven components, only the Sentinel Hash-Chain in sentinel_os exists. The crate borrows two things that do exist: the TRANSPLANTED check from sentinel_os and the gate vocabulary from CNS.

### Mechanism

**The envelope.** A handoff travels as a JSON object with exactly ten fields. The producer fills them with `seal` or `seal_for`, and the receiver checks them with the `Trident` type in the `tack-trident` crate.

| Field | Meaning |
|---|---|
| `version` | Envelope format; must be 1 |
| `sender` | The sender's key fingerprint, 64 lowercase hex characters |
| `sequence` | Per-sender counter that must strictly increase |
| `issued_at_unix_ms` | Issue time in Unix milliseconds |
| `nonce` | 16 random bytes as 32 lowercase hex characters |
| `gate_position` | `alpha` (before execution) or `omega` (on the result), as in CNS `GatePosition` |
| `gate_outcome` | `pass`, `retry` or `terminal_breach`, as in CNS `GateOutcome` |
| `subject_digest` | SHA-256 of the canonical payload |
| `payload` | The content the sender's gate judged, any JSON |
| `mac` | HMAC-SHA256 tag over the other nine fields |

A fingerprint is the SHA-256 of `tack-trident/fingerprint/v1`, a newline and the key bytes. That fixed prefix is a domain separator: it stops a hash made for one purpose from matching a hash made for another. The MAC input likewise starts with `tack-trident/mac/v1` and a newline.

**Four stages.** The receiver runs four stages in order. The first two are cheap, depend only on public facts and return early. The prongs then always run in full.

1. **Admission.** Size, nesting depth, value count, strict JSON and the ten-field shape. No key or hash is touched.
2. **Custody.** Refuse if the receiver is halted or the claimed sender is quarantined.
3. **The three prongs.** All three run to completion, and every failing check is reported, not just the first.
4. **Commit or breaker.** Under one lock, record the acceptance, or count the breach toward the sender's circuit breaker.

**Admission bounds the work.** The input length is compared with the cap before a single byte is decoded (src/canonical.rs):

```rust
pub fn parse_strict(input: &[u8], limits: &Limits) -> Result<Value, CanonicalError> {
    if input.len() > limits.max_bytes {
        return Err(CanonicalError::TooLarge);
    }
    let text = std::str::from_utf8(input).map_err(|_| CanonicalError::Malformed)?;
```

The hand-written parser then counts nesting and values, and stops the moment either cap is passed. It refuses floats, `NaN`, `Infinity`, integers beyond 2^53 - 1, duplicate keys, lone surrogates, leading zeros, a byte-order mark and trailing bytes. A payload bomb, an input built to exhaust memory or stack, therefore costs one bounded pass and no hashing.

Integers only, within 2^53 - 1, keeps the encoding identical to RFC 8785 (the JSON Canonicalization Scheme) and safe for JavaScript readers. Duplicate keys are refused because two parsers may keep different copies of the key. That disagreement is the root of a parser-differential attack.

An envelope built in memory meets the same caps. `Trident::verify` re-encodes it under the byte, depth and node limits before hashing anything. It counts the envelope object and its nine scalar fields, exactly as the wire parser does.

Every cap lives in `TridentConfig` (src/config.rs). `Trident::new` refuses a config outside the ranges below.

| Setting | Default | Ceiling | What it bounds |
|---|---|---|---|
| `max_envelope_bytes` | 65,536 (64 KiB) | 16 MiB | Bytes read, parsed and hashed per envelope |
| `max_depth` | 32 | 128 | Nesting, and so recursion depth |
| `max_nodes` | 16,384 | 1,000,000 | JSON values per envelope |
| `max_past_skew_ms` | 60,000 | One hour | How old an envelope may be |
| `max_future_skew_ms` | 5,000 | One hour | How far ahead it may be; also the start-up blackout |
| `replay_cache_capacity` | 65,536 | 4,194,304 | Remembered (sender, nonce) pairs |
| `max_tracked_senders` | 1,024 | 65,536 | Senders with receiver-side state |
| `breaker_threshold` | 5 | 1,024 | Counted breaches that quarantine a sender |
| `breaker_window_ms` | 60,000 | One day | The breaker's sliding window |
| `audience` | Empty (no binding) | 256 bytes | This receiver's identity in the MAC input |
| `restored_high_water_ms` | 0 | 2^53 - 1 | High-water mark carried across a restart |

There is no default key. A `KeyRing` starts empty and authenticates nothing until the caller inserts keys of 32 to 128 bytes. All-zero keys are refused, and a key's debug output is redacted.

**Prong 1, authenticity.** The receiver looks up the key by fingerprint and computes one HMAC. With no key for the sender, it still computes the HMAC under a throwaway key derived from `sender`, and discards the result. An unknown sender therefore costs the same hashing work as a known one (src/trident.rs):

```rust
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
```

`Choice` is the `subtle` crate's constant-time boolean. The envelope is authentic only if the tag matched, a key was found and the tag was well-formed hex.

The MAC can also bind the receiver. With `TridentConfig::audience` set, the MAC input names that receiver. An envelope sealed with `seal_for` for one receiver then fails prong 1 at any other, even one that trusts the same key.

**Prong 2, binding.** The receiver hashes the canonical payload itself and compares the result with the claimed digest in constant time (src/trident.rs):

```rust
        let recomputed: [u8; 32] = Sha256::digest(&payload_bytes).into();
        match decode_hex_lower::<32>(&env.subject_digest) {
            None => reasons.push(ReasonCode::MalformedDigest),
            Some(claimed) => {
                if !bool::from(claimed.ct_eq(&recomputed)) {
                    reasons.push(ReasonCode::SubjectDigestMismatch);
                }
            }
        }
```

This is the TRANSPLANTED check from sentinel_os, applied to handoffs. A transplanted verdict is a real gate decision moved onto content it was not issued for. Recomputing the digest catches it, because the receiver never takes the stated digest as truth.

Prong 2 also enforces the closed vocabularies. `version` must be 1, `gate_position` exactly `alpha` or `omega`, and `gate_outcome` exactly one of the three CNS spellings, with no case folding.

**Python that exists.** No Python Trident exists. The nearest Python is `verify_subject_binding` in sentinel_os/sentinel_os/twin_custody.py, which recomputes a ledger row's CNS digest and compares it with the stored one. Its digest is not the Trident's: CNS `subject_digest` hashes a type-tagged rendering and accepts floats, while prong 2 hashes RFC 8785 JSON.

The practical consequence: a Python producer that fills `subject_digest` with the CNS function fails prong 2 on every envelope. Either the envelope adopts the CNS rendering, or the Python side gains an RFC 8785 producer. That choice is open and needs the owner's decision.

**Prong 3, freshness.** `issued_at_unix_ms` must be no more than 60,000 ms older or 5,000 ms newer than the receiver's clock. The (sender, nonce) pair must not be in the replay cache. The `sequence` must exceed the sender's last accepted value.

The envelope must also be issued at or after the epoch floor, a time below which nothing is accepted. After a restart or reset, the in-memory replay cache is empty. The floor covers that gap by refusing anything issued before the start time plus 5,000 ms.

The floor also sits above the highest issue time ever accepted, and it never goes down, even if the clock does. Across a restart, the caller persists `Trident::high_water_ms` and passes it back as `restored_high_water_ms`.

The replay and sequence results are always computed, but reported only when prong 1 passed. Otherwise a forger who knows a public fingerprint could read that sender's counter and cache back out of the refusal.

**Commit under one lock.** Prong 3 and the commit share one critical section: code that only one thread can run at a time. Before committing, it re-checks the custody facts read earlier (src/trident.rs):

```rust
        if self.halted.load(Ordering::SeqCst) {
            return Self::halted_verdict();
        }
        if fp.as_ref().is_some_and(|f| st.senders.is_quarantined(f)) {
            return Self::quarantined_verdict();
        }
```

It then confirms the sender's key is still in the current ring; a key revoked mid-verification yields `unknown_sender`. `operator_halt`, `replace_keyring` and breaker trips take the same lock. Once any of them returns, no verification already in flight can commit an acceptance that contradicts it.

**Circuit breaker.** A circuit breaker counts a sender's failures and isolates the sender after too many. Five counted terminal breaches inside 60,000 ms quarantine the sender until an operator calls `release`. Which breaches count is a setting (src/trident.rs):

```rust
        let counts = match self.config.breaker_attribution {
            BreakerAttribution::AuthenticatedOnly => {
                authentic
                    && reasons
                        .iter()
                        .any(|r| r.outcome() == GateOutcome::TerminalBreach && *r != ReasonCode::Replay)
            }
            BreakerAttribution::ClaimedSender => still_trusted && outcome == GateOutcome::TerminalBreach,
        };
```

The default, `AuthenticatedOnly`, counts a breach only when the MAC verified and the breach is not a replay. In practice that means a key holder signed a digest that does not match its payload. `ClaimedSender` trips sooner on forgery floods, but lets anyone who knows a fingerprint get that sender quarantined.

**What the caller acts on.** `Verdict::outcome` folds the sender's authenticated gate verdict into the Trident's own result (src/verdict.rs):

```rust
    pub fn outcome(&self) -> GateOutcome {
        match self {
            Self::Accepted(h) => GateOutcome::resolve([GateOutcome::Pass, h.gate_outcome]),
            Self::Refused(r) => r.outcome,
        }
    }
```

`resolve` applies the CNS precedence: any TERMINAL_BREACH wins, then any RETRY, and PASS only when nothing objected. An authentic, fresh envelope whose upstream gate said TERMINAL_BREACH therefore still yields TERMINAL_BREACH. `Verdict::check_outcome` is the Trident's own result alone, and the metrics label that.

**Timing.** Admission and custody refusals return early, but their timing depends only on public facts: length, structure, halt and quarantine. Inside the prongs, the remaining differences are the key ring's hash-map lookup and HMAC keys over 64 bytes being pre-hashed.

Metrics and logs add a cost that grows with the number of reasons. The reply already states the reasons, so this reveals nothing new unless a future caller hides them. Table scans run only when a table is full, after every prong passed, so their cost tracks load, not secrets.

The Trident does not pad its own response time. ANC (Active Timing Cancellation) is the layer that does.

### Failure mode and state resolution

Every check returns a typed `Verdict`; none is written to panic. Library code has no `unwrap`, `expect`, `panic!` or `unsafe`, and one `debug_assert_eq!` guards an internal length invariant in debug builds only. A lock poisoned by a panic elsewhere halts the receiver instead of letting it guess at its own state.

Each reason maps to one CNS outcome. TERMINAL_BREACH means the envelope proves an integrity failure or a hostile act. RETRY means an honest sender could plausibly produce the fault and fix it.

| Trip | Outcome | State resolution | Why |
|---|---|---|---|
| `envelope_too_large`: input or canonical form over 65,536 bytes | RETRY | reject | The sender can shrink or split the payload. It is checked before parsing, so it costs one length compare. |
| `too_deep`, `too_many_nodes`: over 32 levels or 16,384 values | RETRY | reject | The parser stops at the cap before recursing further. The sender can flatten or trim the payload. |
| `malformed_json`, `non_integer_number`, `non_finite_number`, `integer_out_of_range` | RETRY | reject | Usually a producer encoding bug. Python's `json.dumps` emits `NaN` and `Infinity` by default. |
| `duplicate_key` | TERMINAL_BREACH | reject | No standard JSON library emits duplicate keys; they signal a parser-differential attack. Unauthenticated, so the breaker ignores it. |
| `malformed_envelope`: wrong field set or JSON type | RETRY | reject | A structural encoding bug, and repairable. |
| `halted` | RETRY | halt | The receiver's state may be inconsistent, so it stops. A still-fresh envelope issued after the new floor may pass after `operator_reset`. |
| `quarantined`: the claimed sender is isolated | TERMINAL_BREACH | quarantine | Only an operator `release` lifts it. Quarantine is not secret, so the early return reveals nothing. |
| Breaker trip: 5 counted breaches from one sender in 60,000 ms | TERMINAL_BREACH | quarantine | Under the default attribution, repeated authenticated breaches mark the key holder as hostile or broken. The quarantine survives `operator_reset` and `replace_keyring`. A full sender table drops the breach and counts it in `tack_trident_breaker_untracked_total`. |
| `malformed_sender`, `malformed_mac` | RETRY | reject | Encoding bugs. The HMAC still runs, with a throwaway key or against zeros, so the work is equal. |
| `unknown_sender` | TERMINAL_BREACH | reject | No sender correction repairs it. It costs the same HMAC work as a known sender. |
| `mac_mismatch` | TERMINAL_BREACH | reject | An integrity failure. The default breaker ignores it, so forgeries naming a sender cannot get that sender quarantined. |
| `unsupported_version`, `unknown_gate_position`, `unknown_gate_outcome` | RETRY | reject | Closed vocabularies matching CNS. A newer producer can downgrade. |
| `malformed_digest` | RETRY | reject | An encoding bug. The payload is still hashed, so the work is equal. |
| `subject_digest_mismatch` | TERMINAL_BREACH | reject, or quarantine on the envelope that trips the breaker | The TRANSPLANTED check. With a valid MAC, this is the breach the default breaker counts. |
| `stale`, `from_future` | RETRY | reject | Clock drift. The sender re-issues with a fresh time, nonce and sequence. A clock before 1970 reads 0 and fails closed. |
| `issued_before_epoch` | RETRY | reject | Closes the replay window after a restart or reset. Honest senders simply re-issue. |
| `malformed_nonce` | RETRY | reject | An encoding bug. |
| `replay`: the (sender, nonce) pair was already accepted | TERMINAL_BREACH | reject | An honest sender never reuses a nonce. Anyone who saw the envelope can replay it, so the breaker ignores it. |
| `sequence_not_increasing` | RETRY | reject | Out-of-order sends from an honest sender are plausible. The sender re-issues with the next sequence. |
| `replay_cache_full`: full of live entries, sender at its fair share | RETRY | reject | The sender is at its fair share (capacity divided by ring size), so it waits and cannot starve other senders. Senders under their share evict the largest holder's oldest entry instead. |
| `sender_table_full`: full, with no idle entry to evict | RETRY | reject | Bounded state. Only ring members ever get entries. |
| Accepted, but the sender's `gate_outcome` is `retry` or `terminal_breach` | RETRY or TERMINAL_BREACH | none: accepted, freshness state advances | The Trident vouches that the claim is authentic and fresh, not that the subject is good. |

Rollback is never produced. Freshness state changes only after every check has passed, in one critical section, so there is nothing partial to undo. A reject leaves freshness state untouched; a counted breach adds only a timestamp to the sender's breaker history.

`operator_reset` rebuilds the replay cache, sequences and breach history from empty, and raises the epoch floor. It keeps every quarantine, so a reset never releases a quarantined sender; only `release` does.

### Observability and telemetry

Metrics go through the `metrics` facade, and every label value comes from a closed enum. Nothing an envelope contains ever becomes a label, so an attacker cannot grow the number of metric series. `tests/telemetry.rs` asserts the metrics fire, using `DebuggingRecorder` with `metrics::with_local_recorder`.

| Name | Type | Labels | Meaning |
|---|---|---|---|
| `tack_trident_verifications_total` | counter | `outcome` (pass, retry, terminal_breach), `resolution` (accept, reject, quarantine, halt) | One per `verify` or `verify_wire` call. `outcome` is the Trident's own result. |
| `tack_trident_check_failures_total` | counter | `check` (six groups), `reason` (28 spellings) | One per reported reason. Masked freshness results are not counted. |
| `tack_trident_verify_duration_seconds` | histogram | `outcome` | Wall time from call entry to verdict, admission included. |
| `tack_trident_hashed_bytes_total` | counter | none | Bytes fed to the prong 1 HMAC and the prong 2 SHA-256. Stays 0 for early admission and custody refusals. |
| `tack_trident_quarantine_trips_total` | counter | none | Senders quarantined by the breaker. |
| `tack_trident_quarantine_releases_total` | counter | none | Quarantines lifted by `release`. |
| `tack_trident_quarantined_senders` | gauge | none | Senders currently quarantined. |
| `tack_trident_replay_cache_entries` | gauge | none | Replay cache size; 0 after a reset. |
| `tack_trident_replay_evictions_total` | counter | none | Entries evicted so a sender under its fair share could be accepted. |
| `tack_trident_halts_total` | counter | `cause` (poisoned, operator) | Transitions into the halted state, once per transition. |
| `tack_trident_operator_resets_total` | counter | none | Calls to `operator_reset`. |
| `tack_trident_breaker_untracked_total` | counter | none | Counted breaches not recorded because the sender table was full. |

The two gauges carry no suffix, because the kernel convention defines suffixes only for counters and duration histograms.

Spans, named `tack.trident.<operation>`:

- `tack.trident.verify` (INFO). Fields: `path` (wire or in_process), `input_len`, `input_sha256`, `outcome`, `resolution`. It holds one event: WARN `tack.trident refused handoff` with the reason codes, or DEBUG `tack.trident accepted handoff`.
- On a breaker trip, the verify span adds WARN `tack.trident sender quarantined by breaker`, naming the validated ring fingerprint in full. On a first halt it adds ERROR `tack.trident halted; operator reset required` with the cause.
- `tack.trident.seal` (DEBUG). Producer-side sealing.
- `tack.trident.release` (INFO). Field `sender`, the full fingerprint. Event INFO `tack.trident quarantine released by operator`.
- `tack.trident.reset` (INFO). Event WARN `tack.trident reset by operator` with `epoch_floor_ms`.
- `tack.trident.halt` (WARN). Wraps `operator_halt`.
- `tack.trident.replace_keyring` (INFO). Field `keys`, the ring size.

The verify span records the input's length and full 64-character SHA-256 digest, never the input itself. An input over the size cap is logged by length only, because hashing it is the work the cap prevents. On the in-process path the digest covers the canonical MAC input, since there are no raw bytes.

```yaml
groups:
  - name: tack-trident
    rules:
      - alert: TridentSenderQuarantined
        expr: increase(tack_trident_quarantine_trips_total[5m]) > 0
        labels: {severity: critical}
        annotations: {summary: "A key holder repeatedly signed digests that do not match the payload. Review, then release."}
      - alert: TridentHalted
        expr: increase(tack_trident_halts_total[5m]) > 0
        labels: {severity: critical}
        annotations: {summary: "The receiver refuses every handoff until operator_reset (cause poisoned or operator)."}
      - alert: TridentTransplantedVerdict
        expr: increase(tack_trident_check_failures_total{reason="subject_digest_mismatch"}[5m]) > 0
        labels: {severity: critical}
        annotations: {summary: "A payload does not match its signed digest: content swapped after judgement or in transit."}
      - alert: TridentForgeryAttempts
        expr: sum(rate(tack_trident_check_failures_total{reason=~"mac_mismatch|unknown_sender"}[5m])) > 1
        for: 10m
        labels: {severity: warning}
        annotations: {summary: "Sustained authenticity failures: forgery, a key-rotation mismatch or a missing ring entry."}
      - alert: TridentReplayDetected
        expr: increase(tack_trident_check_failures_total{reason="replay"}[5m]) > 0
        labels: {severity: warning}
        annotations: {summary: "An authenticated envelope was re-sent: a replay attack or a sender reusing nonces."}
      - alert: TridentCapacityExhausted
        expr: increase(tack_trident_check_failures_total{check="capacity"}[5m]) > 0
        labels: {severity: warning}
        annotations: {summary: "Replay cache or sender table is full, and honest traffic gets RETRY."}
      - alert: TridentReplayEvictions
        expr: sum(rate(tack_trident_replay_evictions_total[5m])) > 0
        for: 10m
        labels: {severity: warning}
        annotations: {summary: "Key holders are sending at or above the replay cache's design rate."}
      - alert: TridentReplayCacheNearFull
        expr: tack_trident_replay_cache_entries > 0.9 * 65536
        for: 5m
        labels: {severity: warning}
        annotations: {summary: "Replay cache above 90% of the default capacity. Substitute the configured value."}
      - alert: TridentAdmissionFlood
        expr: sum(rate(tack_trident_check_failures_total{check="admission"}[5m])) > 10
        for: 10m
        labels: {severity: warning}
        annotations: {summary: "Oversize, deep or malformed input at a sustained rate: a payload bomb or a broken producer."}
      - alert: TridentClockSkew
        expr: sum(rate(tack_trident_check_failures_total{reason=~"stale|from_future"}[10m])) > 0.5
        for: 15m
        labels: {severity: warning}
        annotations: {summary: "Sender and receiver clocks disagree beyond the skew window."}
      - alert: TridentHighRefusalRatio
        expr: sum(rate(tack_trident_verifications_total{outcome!="pass"}[5m])) / sum(rate(tack_trident_verifications_total[5m])) > 0.2
        for: 15m
        labels: {severity: warning}
        annotations: {summary: "More than 20% of handoffs are refused."}
      - alert: TridentSlowVerify
        expr: histogram_quantile(0.99, sum by (le) (rate(tack_trident_verify_duration_seconds_bucket[5m]))) > 0.05
        for: 10m
        labels: {severity: warning}
        annotations: {summary: "p99 verification time above 50 ms. Needs an exporter that renders histogram buckets."}
```

### Red-team results

The red team wrote 22 attacks as tests in `tests/redteam.rs`. Against the first build, 13 broke and 9 held. After the fixes, all 22 pass.

TOCTOU (time of check to time of use) names a check that goes stale before the action it guards. The red team forced these races by pausing a verifying thread inside a metrics call, then changing receiver state from another thread.

| Attack | Result | Fix or limitation |
|---|---|---|
| TOCTOU: an in-flight envelope accepted after `operator_halt` returned | Broke, then fixed | `operator_halt` sets the flag under the state lock, and the commit re-reads it under that lock. |
| TOCTOU: an envelope accepted after `replace_keyring` revoked its key | Broke, then fixed | The ring is swapped under the state lock. The commit re-checks ring membership and returns `unknown_sender`. |
| TOCTOU: an envelope accepted after the breaker quarantined its sender | Broke, then fixed | The commit section re-checks quarantine before any freshness or commit work. |
| Cross-receiver replay: one envelope accepted by two receivers sharing a sender key | Broke, then fixed by opt-in | New `audience` setting and `seal_for` bind the receiver into the MAC. Limitation: the default audience is empty, so binding is off until configured. |
| Replay into a restarted receiver whose clock is 30 s behind | Broke, then fixed with caller help | `high_water_ms` to persist and `restored_high_water_ms` to restore. Limitation: without them, restart safety assumes the clock never went backwards. |
| Replay after `operator_reset` with the clock stepped back 30 s | Broke, then fixed | The floor is the largest of its old value, now plus 5,000 ms, and the high-water mark plus 1. |
| One key holder fills the shared replay cache (64-slot test) and starves others | Broke, then fixed | Per-sender nonce queues and a fair share of capacity divided by ring size. New counter `tack_trident_replay_evictions_total`. |
| Replay at the exact retention boundary after a key-ring reload | Broke, then fixed | Retention is now 60,000 + 5,000 + 1 ms by default. Removed senders stay as tombstones until idle. |
| Sequence regression after a key-ring reload drops and restores a sender | Broke, then fixed | Tombstones keep the sender's last accepted sequence. |
| A ring larger than the sender table (1 slot, 2 keys) locks out a member | Broke, then fixed | A full table evicts one idle entry. Ring size is still not checked at construction. |
| Upstream TERMINAL_BREACH surfaces as Trident PASS | Broke, then fixed | `Verdict::outcome` folds in `gate_outcome`. `check_outcome` keeps the Trident's own result for metrics. |
| In-process refusal cost: refusing 2,000,000 keys took 1.33 s, versus 12.45 ms just over the cap (debug build) | Broke, then fixed | Wide objects are refused before keys are collected. Exact escaped lengths are checked before writing. |
| Wire and in-process caps disagree on node count | Broke, partly fixed | `verify` and `verify_wire` now agree exactly. Limitation: `seal` counts payload nodes only, so it can seal up to 10 nodes over the receiver's cap. |
| Keyless forgery flood (50) and replay flood (100) to quarantine a sender | Held | Default `AuthenticatedOnly` attribution counts neither. |
| Forgeries probing a sender's sequence counter and replay cache | Held | Refusals and metric labels were identical for a hit and a miss. |
| Metric label cardinality from 300 envelopes of junk strings | Held | Every emitted label came from the closed vocabularies. |
| Raw input, log injection and truncated digests in logs | Held | No marker or injected text appeared, and every digest was 64 lowercase hex. |
| Unequal prong work across known, unknown and malformed senders; hashing amplification | Held | Equal hashed-byte counts; a near-cap envelope hashed at most twice its wire length. No wall-clock timing benchmark was run. |
| Panics from bytes: every prefix, 4,000 random strings, 4,000 edits, a 1,000,000-deep bomb | Held | No panic, and nothing accepted, including at the ceiling config. |
| Worst-case wire shapes at default caps: wide object, escapes, repeated nesting | Held | Each finished under the 1.5 s debug-build bound. |
| Fail-open and unit confusion: seconds for milliseconds, empty ring, clocks at 0 and `u64::MAX` | Held | Never accepted, never PASS, never an empty reason list, across 500 corrupted envelopes. |
| Concurrent double acceptance: 16 threads, 32 envelopes each | Held | No sequence was accepted twice. |

Two red-team tests had their setup changed, not their assertions. `rt_cross_receiver_replay_is_refused` gives each receiver its own audience, because two identical receivers cannot be told apart. `rt_replay_after_restart_with_clock_regression_is_refused` passes the persisted high-water mark to the restarted receiver.

Known limitations that remain:

- **Symmetric keys.** HMAC keys are shared secrets, so any receiver holding a sender's key can forge as that sender. Only per-pair keys or signatures would stop that.
- **In-memory state.** Replay cache, sequences and quarantines live in process memory. Quarantines are lost on restart, and several replicas need shared replay state or sender affinity.
- **CNS digest interop.** A Python producer using CNS `subject_digest` fails prong 2 until one digest format is chosen.
- **Ring membership leak.** `unknown_sender` versus `mac_mismatch` reveals whether a fingerprint is in the ring. Fingerprints are public identifiers, so this was accepted.
- **Key zeroing.** `SecretKey` zeroes its bytes on drop as a best effort only, because the write cannot be volatile without `unsafe`.
- **Timing evidence.** Equal work is shown by hashed-byte counts, not by a wall-clock measurement.

Three property tests ran 512 cases each: a one-byte flip of a sealed envelope is refused, sealed envelopes pass, and re-encoding is stable. `cargo clippy -p tack-trident --all-targets -- -D warnings` exits 0 with no warnings.

The final run of `cargo test -p tack-trident --all-targets` passed 93 tests in five binaries: unit, properties, redteam, telemetry and trident, in that order.

```text
test result: ok. 32 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.67s
test result: ok. 3 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.36s
test result: ok. 22 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 4.62s
test result: ok. 5 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.05s
test result: ok. 31 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.02s
```
