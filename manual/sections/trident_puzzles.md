## Trident puzzles: nothing leaves the checkpoint alone

A hostile payload can be cut into harmless-looking pieces that each pass inspection and join up again on the far side. The puzzle gate closes that gap by holding every piece until the whole puzzle is present, then inspecting the assembled whole.

*New design. A prototype of this gate is `stack_trident::puzzle`. Its defaults come from a synthetic simulation, not from production traffic.*

### The problem

The Trident was meant to find what hides inside something that looks legitimate. Today it checks one envelope at a time: who sent it (prong 1), whether the content matches its fingerprint (prong 2), and whether it is fresh (prong 3). All three can pass for an envelope whose payload is one tiny piece of a larger hostile thing. The envelope is genuine, intact and fresh, and the piece looks like nothing. Once enough pieces have crossed, the receiver assembles them, and the hostile whole exists only on the receiver's side.

Checking each piece more carefully does not help, because no single piece is hostile. The thing to inspect is the whole, at the place where the whole is built.

### The idea in one paragraph

Treat every item as a piece of a declared puzzle. A piece says which puzzle it belongs to, its place in it, how many pieces there are, and a fingerprint of the finished picture. The gate keeps the pieces and releases nothing until all of them are present and the assembled whole has passed inspection. A puzzle has a lifetime, like a potato in a microwave. If the last piece does not arrive in time, the puzzle is destroyed and nothing partial escapes, and the sender takes a breach. An honest sender who changes its mind can cancel cleanly, which is the slit in the potato.

Terms used below:

- **Piece.** One envelope whose payload is a slice of a puzzle.
- **Whole.** The pieces joined in index order.
- **Root.** SHA-256 over the SHA-256 digests of the pieces, in order. The sender states it up front. The receiver recomputes it, so a piece that does not belong makes the root disagree.
- **Explosion.** Destruction of an incomplete puzzle at the end of its lifetime.
- **Look-back.** Inspection of the end of the last few released wholes together with the current one, so a payload split across two or three puzzles is still seen.

### What exists today and what is new

| | Today | With the gate |
|---|---|---|
| Unit of inspection | One envelope | One assembled whole, plus the tails of recent wholes |
| Who can add to a puzzle | n/a | Only the authenticated sender, because every piece is a verified envelope |
| Incomplete work | n/a | Held under caps, then destroyed at the end of its lifetime |
| Sender memory | Sequence, nonce cache, breach count | Adds open puzzles, recent tails and a breaker with a free allowance |

The gate does not replace the Trident. It owns an `Arc<Trident>` and calls `verify` or `verify_wire` on every piece, so a piece that fails authenticity, binding or freshness never reaches the gate's own logic. Authentication cannot be skipped by a caller.

### The rules

1. **Nothing leaves alone.** A piece is never released by itself. Only a finished, inspected whole is released.
2. **Every piece is a verified envelope.** The payload is a strict JSON object. A piece has exactly the keys `kind`, `puzzle`, `index`, `total`, `root` and `data`. An abort has exactly `kind` and `puzzle`. Any other key, any wrong type and any non-canonical spelling (upper-case hex, odd length) is refused. A label has to account for everything inside; unexplained leftovers are how a Trojan rides in.
3. **A puzzle belongs to one sender.** The key is the sender's fingerprint plus a 16-byte puzzle id. Another sender cannot add to, abort or read it.
4. **The declaration is binding.** The first piece fixes `total` and `root`. A later piece with a different `total` or `root`, a repeated index with different bytes, or an index at or above `total` is a conflict.
5. **Completion is checked, not trusted.** When all indices are present the gate recomputes the root from the pieces. A mismatch means the sender signed an inconsistent set. The puzzle is destroyed.
6. **The whole is inspected, with look-back.** The gate gives the inspector the whole and the retained tails of the sender's last `lookback_wholes` released wholes (oldest first). A finding of `Hostile` destroys the puzzle and counts as a breach. A finding of `Suspicious` destroys the puzzle and does not count as one, because a false alarm must not push an honest sender toward quarantine.
7. **Lifetime follows progress.** A puzzle's deadline is `idle_ms` after its latest piece, never later than `max_lifetime_ms` after its first. Reaching the deadline is an explosion. An explosion counts as a breach.
8. **Abort is the slit.** An authenticated abort for an open puzzle destroys it with no breach. An abort for an unknown puzzle is refused and counts for nothing.
9. **Limits answer "busy", not "guilty".** More than `max_open_per_sender` open puzzles, or a full holding area that cannot make room, refuses the newcomer without a breach. A declared `total` over `max_pieces`, or a piece over `max_piece_bytes`, is a declaration the sender chose to make: it is refused and counts as a breach.
10. **A full holding area evicts the oldest incomplete puzzle.** Honest puzzles finish in milliseconds. Hoarders linger. Age is a better signal of abuse than size. The evicted puzzle's sender takes a breach.
11. **Repeated wholes are remembered.** A root released in the last `replay_window_ms` is refused if it is submitted again as a new puzzle. The memory is bounded and first-in first-out.
12. **The breaker has a free allowance.** A sender may take `breaker_free` breaches inside `breaker_window_ms` with no consequence. The next `breaker_threshold` breaches quarantine it for `quarantine_ms`, and the quarantine ends by itself. All its open puzzles are destroyed.
13. **The inspector is required.** The gate has no default inspector. A gate that inspects nothing would look like protection and be none.

### Why these defaults

The numbers come from a synthetic simulation of 100,000 puzzles (516,000 pieces) across 12 kinds of honest traffic and 14 kinds of hostile traffic, run in virtual time. The detector in the simulation was imperfect on purpose (about 60 percent recall, 0.5 percent false alarms). Every workload number was assumed. The simulation, its raw output and its caveats are kept with the project notes; the findings that set the defaults are:

| Finding | Default it set |
|---|---|
| A fixed lifetime exploded 96 percent of slow honest streams | Progress-based lifetime with a hard cap (rule 7) |
| A limit of 8 open puzzles refused 7 percent of honest bursts; 16 completed 99.3 percent | `max_open_per_sender` 16, refusal is "busy" (rule 9) |
| Under 5,000 compromised senders, "evict the biggest holder" evicted 5.6 percent of honest puzzles; "evict the oldest" evicted 0.1 percent | Oldest-first eviction (rule 10) |
| Without sender authentication, targeted framing quarantined 100 of 100 victims; with it, none | Authentication before anything else (rules 2 and 3) |
| At 5 percent false alarms, 37 honest senders were quarantined | `Suspicious` is not a breach (rule 6) |
| Splits over three or four puzzles passed a look-back of one; a look-back of three closed the structure | `lookback_wholes` 3 |
| Breaker off: hostile items through rose from 493 to 1,483 | The breaker stays (rule 12) |

What the simulation could not show: whether any real inspector finds real hostile meaning. The remaining hostile content that got through was disguised well enough for the simulated detector to miss it. That limit belongs to the inspector, not to the gate.

### Limits that remain

- **The gate decides where to look, not what is hostile.** Its value is bounded by the inspector it is given. `DenyListInspector` is a reference tripwire for known byte patterns. `RuleInspector` is the first real inspector and is bounded by its lists: it misses paraphrase, encodings and look-alike characters (see "The rules inspector").
- **Patterns longer than the retained tail are invisible across joins.** `history_tail_bytes` bounds memory and therefore the longest pattern a split can be caught in.
- **A split wider than the look-back still passes.** Any window can be exceeded. The window is a setting; the arms race is not closed.
- **Meaning assembled by a reader is out of reach.** If the receiver is a person or a language model that connects separate messages, no byte-level gate sees the assembly.
- **Sequence order is unchanged.** Pieces are envelopes, so the Trident's per-sender strictly increasing `sequence` rule still applies. Network reordering of envelopes is refused by prong 3 as it is today; the order of piece indices inside a puzzle is free.
- **State is in memory.** A restart forgets open puzzles, tails, replay memory and breaches, which is safe (open puzzles are destroyed) but resets quarantines.
- **Two senders can each hold half.** Wholes are tracked per sender. A receiver that combines wholes from different senders is making its own join, outside this gate.

### Interface sketch

```rust
let gate = PuzzleGate::new(config, Arc::new(trident), Arc::new(inspector), clock)?;
match gate.offer_envelope(&envelope) {
    Outcome::Held { remaining } => { /* wait for more pieces */ }
    Outcome::Released(whole)    => { /* whole.bytes passed inspection */ }
    Outcome::Aborted            => { /* sender cancelled */ }
    Outcome::Refused(reason)    => { /* typed reason; see counts_as_breach() */ }
}
let closed = gate.take_closed(); // explosions, evictions, quarantines since last call
```

The inspector is a trait with one method that takes the whole and the history tails and returns `Pass`, `Suspicious(reason)` or `Hostile(reason)`.

### Test plan

Tests come first and each attack is its own test:

- A hostile marker split across the pieces of one puzzle is released by no piece and blocked at the whole.
- The same marker split across two, three and four consecutive puzzles is blocked with a look-back of three.
- A hoarder (never sends the last piece) explodes, takes a breach, and is quarantined after the free allowance.
- A flooder past `max_open_per_sender` is refused "busy" and takes no breach.
- A declared `total` over the cap, an oversize piece, an unknown key, and upper-case hex are each refused.
- A misfit set (root disagrees) is destroyed and counts as a breach.
- A repeated whole is refused inside the replay window and accepted after it.
- An honest slow stream completes under the progress timer and explodes under the hard cap.
- A full holding area evicts the oldest incomplete puzzle, not an honest young one.
- A forged envelope (wrong MAC) never touches any puzzle and never counts against the claimed sender.
- A small deterministic mixed run (a few hundred puzzles of every kind) checks the end state: no hostile whole released, no honest sender quarantined.

### Decisions on the open questions

Decided by the owner on 2026-10-29, following the recommendations in the design discussion.

- [x] **Quarantine and the Trident's breaker.** Keep them separate, with automatic expiry, so a burst of honest explosions cannot lock a sender out until someone intervenes.
- [x] **Persistence.** None for now. A restart destroys open puzzles, which is safe, but it resets quarantines. Revisit when something depends on the gate, because persistence adds a store to bound and secure.
- [x] **Relax the sequence rule inside a puzzle.** No. It would weaken replay protection exactly where state is held longest.
- [x] **Which inspector first.** Rules, not a model: `RuleInspector` (see below). A model-based inspector can come later; it would need to be quick or run outside the gate lock, because inspection holds the lock.
- [ ] **The "busy" reply on the wire.** Deferred until the gate is wired into something that sends replies. Without a typed reply with a retry-after hint, honest clients will retry in a storm.
- [x] **Metrics and spans.** Built, with closed labels (see "Observability").
- [ ] **Is the release timing a leak?** Parked. Releasing a whole when the last piece arrives reveals when it arrived; releasing on a fixed schedule hides it at the cost of delay. The randomized-padding measurement in the ANC crates is where the answer will come from.

### The rules inspector

`RuleInspector` (`puzzle::rules`) is the first real inspector. It is cheap and honest, and it is bounded by its lists.

What it does:

- **Normalizes before matching.** ASCII case is folded, zero-width and bidirectional-control characters and other control characters are dropped, and whitespace runs become one space. A marker hidden by spacing, case or invisible characters is still seen.
- **Matches the operator's deny patterns**, optionally also through spacing (`T R O J A N`).
- **Matches injection phrases**, ported from the tightened GSA `BaselinePolicy` rules (instruction override, prompt leak, "you are now", DAN mode, override of safety rules), over word tokens so punctuation does not hide a phrase.
- **Matches one narrow harmful-build rule**: a build verb, a malware artifact and a harm cue in one sentence.
- **Looks back.** The same checks run on the tails of the sender's recent wholes joined to the head of this one, so a phrase cut across puzzles is seen.
- **Checks shape and says `Suspicious`, never `Hostile`**: not valid UTF-8, a NUL byte, too many control characters, or a whole over the size cap. A `Suspicious` finding is not a breach.

Measured on the evidence in `src/puzzle/rules_evidence.rs` (all are assertions in the tests):

| Set | Result |
|---|---|
| Dev attacks (the forms the rules were written against) | 18 of 18 caught |
| Held-out attacks (other phrasings, measured once before any change) | 12 of 14 caught |
| Red-team obfuscations (case, spacing, invisible and control characters, punctuation) | 18 of 18 caught; with normalization switched off, 6 of 18 |
| Phrase cut over 2, 3 and 4 puzzles | caught with look-back 3; a 5-way cut escapes, and look-back 4 catches it |
| Paraphrases | 0 of 8 caught |
| Encodings and look-alike characters (fullwidth, Cyrillic, leetspeak, ROT13, base64, French) | 0 of 6 caught |
| Benign text, including routine text with scary words | 6 of 49 flagged |

The two held-out misses are natural variants outside the ported word lists ("every previous", "all earlier"). They are recorded, not tuned against: extending the lists is cheap, but it needs a fresh held-out set to measure the fix.

The six benign flags are asserted by name. Two come from the deny list used in the evidence config (`TROJAN` in "trojan horse prop", and `TROJAN` matched through spacing in "intro Jan"). Four come from the ported phrase rules: defender-style requests ("build a tool that detects malware spreading across the company network"), a question about DAN mode, and "disregard the above figure". The benign set is chosen to overlap scary vocabulary, so 12 percent is a pessimistic bound for that kind of text, not a rate for real traffic, which is unknown.

What it cannot see, by design: a paraphrase, an encoding, a translation, a look-alike character from another script, and meaning that a reader assembles from separate messages. The gate releases all of these, and the tests assert that they are released so the gap cannot go quiet.

Cost, measured once in a release build in a container (not a benchmark): about 58 ms for a 256 KiB prose whole and about 230 ms for 1 MB of input built to be slow, linear with no quadratic behaviour. Inspection runs while the gate holds its lock, so at the largest default whole a gate that inspects only large wholes handles on the order of 15 per second.

### Observability

Metrics go through the `metrics` facade and every label value comes from a closed set (`puzzle::telemetry`). Nothing a sender, a puzzle or an inspector says becomes a label; an inspector's own reason text is logged only. `tests/puzzle_telemetry.rs` asserts that each metric fires and that every label value is in its closed set, including with 150 senders and an inspector that returns odd reasons.

| Name | Type | Labels | Meaning |
|---|---|---|---|
| `stack_trident_puzzle_messages_total` | counter | `outcome` (held, released, aborted, refused, rejected) | One per message offered to the gate. |
| `stack_trident_puzzle_refusals_total` | counter | `reason` (14 spellings: halted, sender_gate_not_pass, quarantined, three busy kinds, malformed, unknown_puzzle, already_closed, conflict, replayed_whole, root_mismatch, content_blocked, content_suspicious) | One per refusal. |
| `stack_trident_puzzle_closed_total` | counter | `reason` (released, aborted, exploded, evicted, conflict, root_mismatch, hostile, suspicious, quarantined) | One per puzzle that stopped being open. |
| `stack_trident_puzzle_breaches_total` | counter | none | Breaches counted against senders. |
| `stack_trident_puzzle_quarantine_trips_total` | counter | none | Senders quarantined by the gate's breaker. |
| `stack_trident_puzzle_open_puzzles` | gauge | none | Puzzles currently open. |
| `stack_trident_puzzle_held_bytes` | gauge | none | Bytes held in open puzzles. |
| `stack_trident_puzzle_inspect_duration_seconds` | histogram | `finding` (pass, suspicious, hostile) | Wall time of one inspection, which holds the gate lock. |

Spans: `stack.trident.puzzle.offer` (INFO, fields `outcome` and `refusal`) and `stack.trident.puzzle.sweep` (INFO). A blocked or suspicious whole logs a WARN event with the inspector's reason text.

Example alert rules. They have not been run against a Prometheus:

```yaml
groups:
  - name: stack-trident-puzzle
    rules:
      - alert: PuzzleSenderQuarantined
        expr: increase(stack_trident_puzzle_quarantine_trips_total[5m]) > 0
        labels: {severity: warning}
        annotations: {summary: "A sender was quarantined by the puzzle gate. It lifts by itself."}
      - alert: PuzzleHostileContent
        expr: increase(stack_trident_puzzle_refusals_total{reason="content_blocked"}[5m]) > 0
        labels: {severity: warning}
        annotations: {summary: "The inspector blocked a hostile whole."}
      - alert: PuzzleExplosions
        expr: sum(rate(stack_trident_puzzle_closed_total{reason="exploded"}[10m])) > 0.1
        for: 10m
        labels: {severity: warning}
        annotations: {summary: "Puzzles are timing out at a sustained rate: a hoarder or a broken producer."}
      - alert: PuzzleBusy
        expr: sum(rate(stack_trident_puzzle_refusals_total{reason=~"busy_.*"}[10m])) > 0.1
        for: 10m
        labels: {severity: warning}
        annotations: {summary: "Honest senders are being told busy. Raise the limits or find the flooder."}
      - alert: PuzzleSlowInspection
        expr: histogram_quantile(0.99, sum by (le) (rate(stack_trident_puzzle_inspect_duration_seconds_bucket[5m]))) > 0.1
        for: 10m
        labels: {severity: warning}
        annotations: {summary: "p99 inspection time above 100 ms. Inspection holds the gate lock. Needs an exporter that renders histogram buckets."}
```
