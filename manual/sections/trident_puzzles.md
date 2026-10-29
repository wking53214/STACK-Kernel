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

- **The gate decides where to look, not what is hostile.** Its value is bounded by the inspector it is given. The reference `DenyListInspector` is a tripwire for known byte patterns, as the baseline policy in GSA is: it misses paraphrase.
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

### Open questions

- [ ] Should a puzzle quarantine feed the Trident's own breaker, which needs an operator to release, or stay separate with automatic expiry? The prototype keeps it separate so a burst of honest explosions cannot lock a sender out until someone intervenes.
- [ ] Should the gate persist open puzzles, tails and quarantines across a restart? Persistence keeps a quarantined attacker quarantined; it also adds a store to bound and secure.
- [ ] Should the Trident's per-sender sequence rule be relaxed inside a puzzle so honest network reordering is tolerated? That would weaken replay protection exactly where state is held longest.
- [ ] Which inspector will the first production gate use? The gate is only as good as its inspector, and none is chosen.
- [ ] What should the "busy" reply look like on the wire so honest clients back off instead of retrying in a storm?
- [ ] Should metrics and spans be added with closed-enum labels, as the Trident has? The prototype logs closes with `tracing` and has no metrics yet.
- [ ] Is the timing of release a leak? Releasing a whole at completion time reveals when the last piece arrived; releasing on a fixed schedule hides it at the cost of delay. The padding layers in the ANC crates are the place to answer this.
