## 4. Minotaur String

The Minotaur String caps every walk at 64 levels of nesting and 100,000 steps by default, and flags loops using memory fixed at construction.

*New design: reference implementation compiled and tested on Rust 1.94*

### Metaphor and goal

In the myth, Ariadne gives Theseus a ball of string before he enters the Minotaur's labyrinth. He ties one end at the entrance and lets it out as he walks. At any moment the string tells him how deep he is, whether he is crossing his own path, and how to get back out.

The crate `tack-minotaur` gives a program the same string, called a `Thread`. Its tied end is the anchor: depth 0, no steps taken. A walk is one run of work from the anchor, such as an agent's chain of tool calls or a recursive planner.

Going one level deeper, such as a recursive call or a sub-agent, is a descend. Moving to a new state, such as a tool call with its arguments, is a record. Each record carries a fingerprint, a 32-byte SHA-256 digest that stands for that state.

The goal is to stop four failure patterns before they consume the machine, while always being able to unwind to the anchor.

| Pattern | What it looks like | Cap that stops it |
|---|---|---|
| Runaway recursion | Nesting grows without bound | `max_depth` |
| Agent tool-call loop | The same call with the same arguments, again and again | `revisit_allowance` |
| State-space explosion | A search keeps finding new states forever | `max_steps` and `max_untracked_transitions` |
| Replay | The orchestrator rewinds and resubmits just before each cap | The lifetime budget |

Facts first: the Minotaur String existed in no TACK repository before this crate. Nothing in sentinel_os, CNS, observe-perceive, ghost_tools or Resume_OS calls it yet, and no Python version exists. The default caps are engineering guesses, not values measured from real agent traces.

### Mechanism

The design has four parts: a depth guard, an exact revisit map, two fallback detectors for a full map, and a breadcrumb trail. Every cap lives in `MinotaurConfig`, which `Thread::new` validates. An invalid value means no Thread is built.

| Field | Default | Ceiling | What it bounds |
|---|---|---|---|
| `max_depth` | 64 | 2^16 | Nesting levels in one walk |
| `max_steps` | 100,000 | 2^40 | Transitions in one walk |
| `max_distinct_states` | 4,096 | 2^20 | Entries in the exact revisit map, and so its memory |
| `revisit_allowance` | 3 | 2^16 | Revisits of one state before it counts as a loop (0 is legal) |
| `breadcrumb_len` (K) | 32 | 4,096 | Fingerprints carried back in a trip |
| `max_cycle_period` | 256 | 2^24 | Longest cycle the Brent detector promises to find |
| `max_untracked_transitions` | 16,384 | 2^40 | Steps onto states the full map could not hold (0 is legal) |
| `max_trips_before_halt` | 8 | 2^16 | Trips before the Thread halts |

A ninth cap is derived, not configured. The lifetime budget is `max_steps` times `max_trips_before_halt`, so 800,000 accepted transitions by default. It spans all walks and only an operator reset clears it.

**Depth is counted by guards.** `descend()` returns a `DepthGuard`, a value whose drop code gives the level back. Drop code is cleanup Rust runs automatically on every exit from a scope: normal return, early return, `?` error propagation and panic unwinding.

The guard holds an exclusive borrow of the Thread. A borrow is Rust's compile-time permission to use a value, and an exclusive one locks everyone else out until the guard is gone. The guard has its own `descend()` and `record()`, and only read access to everything else (src/thread.rs):

```rust
pub struct DepthGuard<'t> {
    thread: &'t mut Thread,
    epoch: u64,
}

impl Deref for DepthGuard<'_> {
    type Target = Thread;

    fn deref(&self) -> &Thread {
        self.thread
    }
}

impl DepthGuard<'_> {
    /// Whether the Thread has rewound since this guard was issued.
    #[must_use]
    pub const fn is_stale(&self) -> bool {
        self.thread.epoch != self.epoch
    }

    /// Refuse the call if the Thread is halted or this guard is stale.
    fn check_current(&self) -> Result<(), Trip> {
        if self.thread.halted {
            return Err(self.thread.halted_trip());
        }
        if self.is_stale() {
            return Err(self.thread.stale_trip());
        }
        Ok(())
    }

    /// Go one level deeper from this scope; see [`Thread::descend`].
    ///
    /// # Errors
    /// [`TripKind::Halted`] if the Thread is halted, [`TripKind::StaleGuard`]
    /// if the Thread rewound since this guard was issued (nothing changes in
    /// either case), otherwise as [`Thread::descend`].
    pub fn descend(&mut self) -> Result<DepthGuard<'_>, Trip> {
        self.check_current()?;
        self.thread.descend()
    }
```

Each guard remembers the Thread's epoch, a counter the Thread bumps on every rewind. A guard from an earlier epoch is stale: it refuses work with a `StaleGuard` trip, and dropping it gives nothing back (src/thread.rs):

```rust
impl Drop for DepthGuard<'_> {
    fn drop(&mut self) {
        if self.thread.epoch == self.epoch {
            self.thread.depth = self.thread.depth.saturating_sub(1);
        }
    }
}
```

`rewind()` and `operator_reset()` take `&mut Thread`, a mutable reference, which a guard never hands out. So code holding only a guard cannot call them. A doctest (an example in the docs that the test suite compiles) marked `compile_fail,E0596` in src/lib.rs must fail with exactly that compiler error:

```rust
//! use tack_minotaur::{MinotaurConfig, Thread};
//! let mut thread = Thread::new(MinotaurConfig::default()).unwrap();
//! let mut guard = thread.descend().unwrap();
//! guard.rewind(); // error: cannot borrow data in dereference of `DepthGuard` as mutable
```

A small trait (Rust's word for an interface), `Walk`, lets one recursive function take either the root Thread or a guard. It offers `descend`, `record` and a read-only `thread()` accessor, and has no rewind and no reset.

**Revisits are counted exactly, up to a memory cap.** A hash map from fingerprint to visit count holds up to 4,096 entries, allocated once at full size and never grown. It uses the standard library's hash function with a random key (SipHash), so an attacker who picks fingerprints cannot force slow hash collisions.

This excerpt of `Thread::record` (src/thread.rs) shows three cases: a known state, a new state with room, and a new state without room.

```rust
        let allowance = self.cfg.revisit_allowance;
        let mut exact_loop = None;
        let mut recent_loop = None;
        if let Some(v) = self.visits.get_mut(&state) {
            v.count = v.count.saturating_add(1);
            let gap = step.saturating_sub(v.last_step);
            v.last_step = step;
            if v.count.saturating_sub(1) > allowance {
                exact_loop = Some(gap);
            }
        } else if self.visits.len() < self.cfg.max_distinct_states {
            self.visits.insert(
                state,
                Visit {
                    count: 1,
                    last_step: step,
                },
            );
        } else {
            if !self.degraded {
                self.degraded = true;
                telemetry::degraded(self.visits.len(), step);
            }
            self.untracked = self.untracked.saturating_add(1);
            if self.untracked > self.cfg.max_untracked_transitions {
                return Err(self.trip(TripKind::StateSpaceExhausted {
                    tracked: self.visits.len(),
                    limit: self.cfg.max_untracked_transitions,
                }));
            }
            recent_loop = self.recent.observe(state, step, allowance);
        }
```

**When the map is full, the Thread degrades instead of growing.** Two fixed-size detectors take over, and memory stays constant at the cost of some precision. The `tack_minotaur_degraded_total` counter fires once for that walk.

- Brent's algorithm finds a cycle by comparing each new step against one saved step, called the tortoise. This streaming version (src/brent.rs) finds any strictly repeating cycle up to 256 steps long.
- The recent-state table (src/recent.rs) holds up to 256 states the full map could not hold, the smaller of `max_cycle_period` and `max_distinct_states`. It keeps exact visit counts and applies the same loop rule as the map.

Eviction follows the CLOCK rule. A hand sweeps the slots, sparing entries revisited since its last pass, and evicts the first entry that was not revisited.

A state whose visits are fewer than the table size apart is never evicted between them. Counts are never too high, so a walk of distinct states never trips the table.

**Breadcrumbs travel with every trip.** The last K fingerprints (32 by default) sit in a ring buffer, a fixed-size queue that drops its oldest entry. On a trip they are copied into the `Trip`, so the caller can see where the walk was heading.

The trip path always writes and hashes all K slots, whatever the walk length or log level (src/thread.rs):

```rust
        let k = self.cfg.breadcrumb_len;
        let len = self.breadcrumbs.len();
        // Write all K slots (the path, then zero padding), then cut to the
        // path length; the truncation is free for a `Copy` type.
        let mut path = Vec::with_capacity(k);
        path.extend(self.breadcrumbs.iter().copied());
        path.resize(k, Fingerprint::ZERO);
        let digest = telemetry::path_digest(&path);
        path.truncate(len);
```

**Rollback is split in two.** The Thread holds counters and fingerprints, never the caller's data. On a trip the Thread rewinds itself to the anchor, and the caller restores its own snapshot.

`rollback_on_trip` does the caller's half for any state that can be cloned (src/lib.rs):

```rust
pub fn rollback_on_trip<S: Clone, T>(
    state: &mut S,
    f: impl FnOnce(&mut S) -> Result<T, Trip>,
) -> Result<T, Trip> {
    let snapshot = state.clone();
    match f(state) {
        Ok(v) => Ok(v),
        Err(t) => {
            *state = snapshot;
            Err(t)
        }
    }
}
```

**CNS vocabulary.** Each `Trip` carries a `GateOutcome` whose strings match `GateOutcome` in /home/user/CNS/cns/gate.py: `pass`, `retry` and `terminal_breach`. The enum is re-declared in Rust, not imported, because CNS is a Python package.

The crate sets no `GatePosition`. An in-flight guard is neither ALPHA (before execution) nor OMEGA (on the result), so that choice is still open.

The Thread is `Send + Sync`, meaning it is safe to move to and share between OS threads, and a guard is `Send`. Both can be held across `.await` in async code. One Thread guards one walk at a time.

### Failure mode and state resolution

No call panics across the API: each returns `Result<_, Trip>`, a typed verdict. Every trip except `Halted` and `StaleGuard` fires after the walk has changed state, so it rolls back. Quarantine is never used, because the Thread has no identity for the walker; the caller decides whether to isolate its agent.

RETRY means the caller may resubmit with a correction; TERMINAL_BREACH means abort, because no correction repairs it.

| Trip | Outcome | State resolution | Why |
|---|---|---|---|
| `DepthExceeded { limit }`: a descend would pass `max_depth` | RETRY | Rollback: the Thread rewinds to the anchor, live guards go stale, and the caller restores its snapshot | A flatter decomposition of the same task can succeed. |
| `StepBudgetExhausted { limit }`: transition number `max_steps + 1` | RETRY | Rollback | Smaller walks can succeed. This backstop bounds all work, including cycles too long for the detectors. |
| `LoopDetected { period, detector: Exact }`: a mapped state visited more than 1 + `revisit_allowance` times | RETRY | Rollback | The walk is not making progress, but a different next step can. |
| `LoopDetected` with detector `Brent` or `Recent`: the same rule once the map is full | RETRY | Rollback | It is the map's rule, applied with fixed memory. |
| `StateSpaceExhausted { tracked, limit }`: more than `max_untracked_transitions` steps onto states the full map cannot hold | RETRY | Rollback | A narrower search can succeed. It also catches long cycles and long revisit gaps that the detectors miss. |
| Any trip that brings the trip count to `max_trips_before_halt` | TERMINAL_BREACH | Rollback, then halt until `operator_reset` | A caller that keeps tripping is itself looping, so no correction from it will help. The Trip keeps its original kind. |
| `LifetimeBudgetExhausted { limit }`: a transition arrives after `max_steps` times `max_trips_before_halt` were already accepted | TERMINAL_BREACH | Rollback, then halt | It bounds a caller that replays walks and rewinds just before each per-walk cap. |
| `Halted`: any call while the Thread is halted | TERMINAL_BREACH | Halt: nothing changes, the path is empty, and no rollback is counted | Fail closed until an operator acts. It logs at debug only, so a stream of refused calls cannot flood the log. |
| `StaleGuard`: a call through a guard issued before the last rewind | RETRY | Reject: nothing changes, and it does not count toward the halt | The caller must unwind to the root and resubmit from there. |
| Invalid config: a field below its minimum or above its ceiling | Not a verdict: `Thread::new` returns `Err(ConfigError)` | Reject: no Thread is built | Every allocation is sized by a validated field. |

The trip count runs from construction or the last `operator_reset`. `rewind()` does not clear it, so rewinding does not forgive a Thread that keeps tripping. Each Trip reports the depth and step count at the moment it fired, before the rewind.

### Observability and telemetry

Nothing is emitted for a passing step. The per-step code only enters a trace-level span (a named, timed region of work), which costs one check when tracing is off. Metrics fire when a walk ends, degrades, halts or is reset.

Every label value comes from a closed enum, never from caller data. A free-form label would let an attacker create endless time series, which is called a cardinality attack.

| Name | Type | Labels | Meaning |
|---|---|---|---|
| `tack_minotaur_trips_total` | counter | `reason` (depth_exceeded, step_budget_exhausted, loop_detected, state_space_exhausted, halted, stale_guard, lifetime_budget_exhausted), `outcome` (retry, terminal_breach) | One per Trip, including refusals. |
| `tack_minotaur_loops_detected_total` | counter | `detector` (exact, brent, recent) | Loops found, by the detector that found them. |
| `tack_minotaur_rollbacks_total` | counter | none | Trips resolved by rewinding: every trip except `halted` and `stale_guard` refusals. |
| `tack_minotaur_halts_total` | counter | none | Times a Thread entered the halted state. |
| `tack_minotaur_operator_resets_total` | counter | none | Calls to `operator_reset`. |
| `tack_minotaur_degraded_total` | counter | none | Walks whose exact map filled, counted once per walk. |
| `tack_minotaur_walk_steps` | histogram | `end` (trip, rewind, operator_reset) | Transitions recorded when the walk ended. |
| `tack_minotaur_walk_max_depth` | histogram | `end` | Deepest depth reached in the walk. |
| `tack_minotaur_walk_distinct_states` | histogram | `end` | States held in the exact map when the walk ended. |
| `tack_minotaur_walk_duration_seconds` | histogram | `end` | Wall time from the anchor to the end of the walk. |

The crate opens five spans.

| Span | Level | Covers |
|---|---|---|
| `tack.minotaur.descend` | trace | Every descend call |
| `tack.minotaur.record` | trace | Every record call |
| `tack.minotaur.trip` | info | Trip handling: rewind, metrics and the log event |
| `tack.minotaur.rewind` | debug | An orchestrator rewind |
| `tack.minotaur.operator_reset` | info | An operator reset |

Log events use the target `tack.minotaur`. A trip logs at warn, or at error when it halts the Thread, with reason, outcome, resolution, period, depth, steps, `path_len` and `path_sha256`. Refusals log "refused; nothing changed" at debug, and degrading and operator resets log at info.

No event carries a fingerprint or a state. `path_sha256` is the full 64-hex SHA-256 of the padded breadcrumb path, so two log lines can be matched without revealing the path.

The alert rules below are proposed and are not shipped in the crate. They were parsed as YAML but never loaded into Prometheus, and the thresholds are guesses to calibrate.

```yaml
groups:
  - name: tack-minotaur
    rules:
      - alert: TackMinotaurHalted
        expr: increase(tack_minotaur_halts_total[5m]) > 0
        labels:
          severity: critical
        annotations:
          summary: "A Thread halted after max_trips_before_halt trips or its lifetime budget, and refuses work until operator_reset."
      - alert: TackMinotaurWorkAgainstHaltedThread
        expr: sum(rate(tack_minotaur_trips_total{reason="halted"}[5m])) > 0
        for: 5m
        labels:
          severity: critical
        annotations:
          summary: "Callers keep sending work to a halted Thread: the orchestrator ignores TERMINAL_BREACH, or no operator has acted."
      - alert: TackMinotaurStaleGuardSpin
        expr: sum(rate(tack_minotaur_trips_total{reason="stale_guard"}[5m])) > 1
        for: 10m
        labels:
          severity: warning
        annotations:
          summary: "A caller keeps working through stale guards instead of unwinding to the root. These refusals never escalate to a halt."
      - alert: TackMinotaurLoopStorm
        expr: sum(rate(tack_minotaur_loops_detected_total[5m])) > 1
        for: 10m
        labels:
          severity: warning
        annotations:
          summary: "Walks are looping at a sustained rate, for example an agent stuck in tool-call loops."
      - alert: TackMinotaurRunawayRecursion
        expr: sum(rate(tack_minotaur_trips_total{reason="depth_exceeded"}[5m])) > 0.1
        for: 10m
        labels:
          severity: warning
        annotations:
          summary: "Sustained depth trips: recursion or sub-agent nesting is running away."
      - alert: TackMinotaurStateSpaceExhausted
        expr: increase(tack_minotaur_trips_total{reason="state_space_exhausted"}[15m]) > 0
        labels:
          severity: warning
        annotations:
          summary: "A walk kept reaching new states after the exact map filled: a state-space explosion, or a loop with long gaps."
      - alert: TackMinotaurLifetimeBudgetHalt
        expr: increase(tack_minotaur_trips_total{reason="lifetime_budget_exhausted"}[15m]) > 0
        labels:
          severity: warning
        annotations:
          summary: "A Thread used its lifetime budget: walks are being replayed, or a long-lived Thread lacks a periodic operator reset."
      - alert: TackMinotaurDegradedOften
        expr: sum(rate(tack_minotaur_degraded_total[15m])) / clamp_min(sum(rate(tack_minotaur_walk_steps_count[15m])), 1e-9) > 0.5
        for: 30m
        labels:
          severity: info
        annotations:
          summary: "Over half of walks fill the exact map, so max_distinct_states is probably too small and detection runs in the less precise degraded mode."
```

### Red-team results

An independent red-team wrote 11 attacks and 2 control tests, each asserting the safe behaviour. On the first build 6 failed, including 2 blockers. After the fixes all 13 pass.

| Attack | Result | Fix or limitation |
|---|---|---|
| Call `rewind()` through a guard while the outer guards are live (blocker) | Broke: real nesting reached 400 with `max_depth` 8 and no trip | Fixed: the guard lost mutable access to the Thread (`DerefMut` removed). `guard.rewind()` is now a compile error, pinned to E0596 by a doctest. |
| Clear a halt from a guard by swapping in a fresh Thread with `std::mem::replace` (blocker) | Broke: the halted Thread took new work, depth reached 11 against `max_depth` 2, and no reset was counted | Fixed by the same change: `mem::replace` and `operator_reset()` through a guard are compile errors (E0596). The optional operator token was not added. |
| Keep descending through a stale guard after a `DepthExceeded` trip (major) | Broke: 32 live guards with `max_depth` 4 | Fixed: a stale guard returns `StaleGuard` (RETRY, reject) and does not touch the Thread. |
| Fill the map, then repeat state A with a fresh filler state between visits, timed so Brent's tortoise always lands on a filler (major) | Broke: A was visited 8,193 times, and the trip was `StateSpaceExhausted`, not a loop | Fixed: the recent-state table now trips `LoopDetected` (detector `Recent`) at A's 5th visit. |
| Replay one 100-step walk 1,000 times with `rewind()` just before the cap (minor) | Broke: 100,000 transitions and 0 trips | Fixed: the lifetime budget halts the caller with `LifetimeBudgetExhausted`. Limitation: it is derived, not tunable, so a long-lived Thread needs periodic operator resets. |
| Time a trip after 4 steps against one after 4,096 steps (minor) | Partial: the 4,096-step trip took 172.6 times as long with warn logging on, and 8.2 times with it off | Fixed: a trip always writes and hashes all K slots. The test now passes (ratio under 4, medians of 15), and it passed 8 of 8 runs for this manual. |
| Hostile fingerprints driving metric label cardinality | Held | Labels come only from enums. tests/telemetry.rs checks the three label values the fixes added. |
| Fingerprints or raw state in logs and spans, and truncated hashes | Held | A capturing subscriber searched every field at trace level and found no fingerprint. `path_sha256` was always 64 hex characters. |
| Flood a halted Thread with 50,000 calls | Held | Each refusal changed nothing, and exactly one event at warn or above was emitted. |
| Caps at their ceilings (map size and K at 1), with overflow checks on | Held | No panic and no integer overflow. |
| Random operation mixes, property-tested with 256 cases | Held | No trip mapped to PASS, and every internal counter stayed within its cap. |
| Repeat a state the full map could not hold, at gaps longer than the recent table (probe run for this manual, default config) | Escapes loop detection | Limitation: a repeat every 256 steps trips `LoopDetected` at the 5th visit. A repeat every 257 steps reaches 64 visits before `StateSpaceExhausted` stops it. |
| Spin on a stale guard instead of unwinding | Not escalated | Limitation: stale refusals never count toward the halt. Only the `stale_guard` metric and its alert show it. |
| Timing after the fix (release build, medians of 101 trips, no log subscriber) | No detectable dependence on walk length at that sample size: ratios 0.93 and 1.02 in two runs | Limitation: a trip costs 1.6 to 1.8 µs at K = 32, against about 58 ns for a passing new-state step. `Trip::path.len()` still reveals min(steps, K), so the ANC (Active Timing Cancellation) wrapper must enclose the Minotaur calls. |
| Read state fingerprints from `Trip.path` across a trust boundary | Open | Limitation: the orchestrator must strip the path before a Trip reaches the constrained agent. The crate offers no redacted form yet. |

Four red-team tests were edited after the fixes, mainly because their attack lines no longer compiled. The compile errors are pinned by doctests instead, and each edit is listed in the fix record.

Final run of `cargo test -p tack-minotaur --all-targets` (debug build): 60 tests in six targets, all passing. `cargo test -p tack-minotaur --doc` passed 6 of 6, including 4 compile_fail doctests, and clippy with `-D warnings` was clean.

```text
$ cargo test -p tack-minotaur --all-targets   (summary lines only)
     Running unittests src/lib.rs (target/debug/deps/tack_minotaur-8585c0e493b6235e)
test result: ok. 15 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.20s
     Running tests/async_use.rs (target/debug/deps/async_use-daeb62f68e0af4b3)
test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s
     Running tests/props.rs (target/debug/deps/props-b979d5c68d7ee352)
test result: ok. 2 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 2.82s
     Running tests/redteam.rs (target/debug/deps/redteam-f388812ab3c87090)
test result: ok. 13 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 1.50s
     Running tests/telemetry.rs (target/debug/deps/telemetry-636ef5cfa659a0b5)
test result: ok. 9 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s
     Running tests/thread.rs (target/debug/deps/thread-33a6808a0fd668f3)
test result: ok. 20 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.79s
$ cargo test -p tack-minotaur --doc
test result: ok. 6 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.14s
```
