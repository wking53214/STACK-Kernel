## 5. Traffic Cop and Green Wave Routing

A request that finds its lane empty is dispatched within one epoch (8 ms by default) plus poll latency, whatever other lanes do.

*New design: reference implementation compiled and tested on Rust 1.94*

### Metaphor and goal

A traffic cop at a busy crossing gives each direction its turn. However long the queue on one road grows, the cross street still gets waved through on its turn. That is the fairness half of this component.

A green wave is the other half. The lights along an avenue are timed so that a car moving at the design speed meets green at every light and never stops.

In the kernel, the pieces map like this:

| On the street | In the kernel | What it is |
|---|---|---|
| A direction of traffic | Lane | A tenant or priority class, with its own bounded queue |
| One turn of the cop | Phase | A fixed slice of time, 1 ms by default, owned by exactly one lane |
| One full cycle of turns | Epoch | A fixed number of phases, 8 by default, so 8 ms |
| A light along the avenue | Stage | One processing step, due a set number of phases after dispatch |
| Waving cars through | Dispatch | Taking requests from the owning lane's queue and handing them on |

The goal has four parts:

1. **Deterministic.** The same configuration and the same arrivals on the same clock give the same dispatch order and times on every run.
2. **Fair.** A lane that floods cannot starve another lane. The lead bound holds only while the driver polls in every phase, and missed phases are counted.
3. **Auditable.** Every refusal is a typed verdict with a reason and a metric. Every decision uses only public inputs: lane, queue depth and clock.
4. **Quieter in time.** Results leave only on epoch boundaries. This release quantization reveals which epoch work finished in, not when inside it.

Point 4 is the bridge to ANC (Active Timing Cancellation), the component that suppresses the timing signal that remains.

Terms used below:

- **Poll.** One call that dispatches work for the current phase, made at every phase start.
- **Poll latency.** How late after a phase start the poll runs: zero on a test clock, real on a machine.
- **Smooth weighted round-robin.** A way to spread a lane's turns evenly through the cycle. The nginx web server uses it to pick upstream servers.
- **Work-conserving.** A scheduler that never leaves capacity idle while work waits. This one deliberately is not.
- **Ticket.** The receipt a dispatched request carries to its stages and to completion.
- **ALPHA and OMEGA.** The two ends of the CNS gate. ALPHA checks before work starts; OMEGA judges a produced result.
- **Fail closed.** Unknown or malformed input is refused, never passed.

This is a new design. Only the Sentinel Hash-Chain exists today, in sentinel_os. The scheduler is a standalone Rust crate, `tack-greenwave`, and no Python repository calls it yet.

### Mechanism

The crate has a pure core and a thin driver. The core, `TrafficCop`, never reads the system clock and never sleeps. It asks an injected `Clock`, so tests drive time by hand with `ManualClock`.

The driver, `GreenWaveDriver`, supplies real time on tokio, the Rust async runtime. The core works in five steps, each a small module:

| Step | Module | What it does |
|---|---|---|
| Grid | src/timing.rs | Cuts time into phases and epochs from the clock's origin, with checked arithmetic. |
| Phase table | src/table.rs | Gives each phase to one lane, once, at build time. A lane of weight w owns w phases. |
| Admit and poll | src/cop.rs | Admission queues a request in its lane. A poll dispatches only from the current phase's owner. |
| Green wave | src/wave.rs | Stage i of a request dispatched in phase p is due in phase p + offset_i. |
| Release | src/timing.rs | A completed result leaves at the first epoch boundary strictly after completion. |

Verdicts use the CNS vocabulary of cns/gate.py, redeclared in src/outcome.rs because CNS is Python. Admission, poll, stage checks and reset sit at ALPHA; completion sits at OMEGA.

**The phase table.** Each lane keeps a running credit, which grows by its weight before every phase. The lane with the most credit takes the phase, and its credit drops by the total weight. Ties go to the lowest lane index (src/table.rs):

```rust
        for slot in 0..phases {
            let mut best: Option<(usize, i64)> = None;
            for (lane, (c, &w)) in credit.iter_mut().zip(weights).enumerate() {
                *c += i64::from(w);
                match best {
                    Some((_, b)) if *c <= b => {}
                    _ => best = Some((lane, *c)),
                }
            }
            let Some((lane, _)) = best else {
                return Err(ConfigError::NoLanes);
            };
            if let Some(c) = credit.get_mut(lane) {
                *c -= total;
            }
```

This spreads a lane's turns out instead of bunching them. Weights {5, 1, 1} give owners [0, 0, 1, 0, 2, 0, 0], the sequence nginx documents, and `phase_assignment_is_deterministic` in tests/scheduling.rs asserts it. Weights must sum exactly to the phases per epoch, so every phase has one owner and every lane has at least one phase.

**Owner-only dispatch.** A poll finds the current phase, counts any phases that passed with no poll, and looks up the owner. Only the owner's queue is touched, oldest first, up to the per-phase budget `max_dispatch_per_phase` (src/cop.rs):

```rust
        let abs = self.timing.abs_phase(now);
        let cur = self.current_phase;
        let missed = abs.saturating_sub(cur).saturating_sub(1);
        if missed > 0 {
            telemetry::record_phases_missed(missed);
            tracing::warn!(missed, from_phase = cur, to_phase = abs, "phases passed without a poll");
        }
        if abs != cur {
            self.current_phase = abs;
            self.dispatched_in_phase = 0;
        }
        let Some(owner) = self.table.owner(self.timing.phase_in_epoch(abs)) else {
            // Unreachable: phase_in_epoch is below the table length.
            telemetry::record_op(Op::Poll, GateOutcome::Pass);
            return Ok(Vec::new());
        };
        let budget = self.max_dispatch.saturating_sub(self.dispatched_in_phase).min(limit) as usize;
```

Missed phases are not made up later. Making one up would move a lane's work into another lane's phase, which is the coupling this design removes. They are counted in `tack_greenwave_phases_missed_total` instead.

**The fairness bound.** Lane L of weight w owns w phase starts in every window one epoch long. Each of those phases dispatches up to M requests from L's queue and none from any other queue. A request with k requests ahead of it therefore waits at most ceil((floor(k / M) + 1) / w) epochs, plus poll latency.

With k = 0 that is one epoch plus poll latency. No term depends on another lane, which is why a flood elsewhere cannot add delay. The bound is not strict: a request that arrives just after its own lane's poll waits exactly one epoch on a perfect clock.

**The green wave.** A stage calls `stage_check` before running. Too early is RETRY with the due time. After the due phase has ended it is still PASS, flagged late and counted (src/cop.rs):

```rust
    fn try_stage_check(&mut self, ticket: &DispatchTicket, stage: usize) -> Result<StageClearance, Trip> {
        let now = self.observe(Op::StageCheck)?;
        self.check_live(Op::StageCheck, ticket)?;
        let slot = self
            .wave
            .slot(ticket.dispatch_phase, stage)
            .map_err(|reason| self.trip(Op::StageCheck, reason, None))?;
        if now < slot.due_at {
            return Err(self.trip(Op::StageCheck, TripReason::NotYetDue, Some(slot.due_at)));
        }
        let late = now >= slot.due_at.saturating_add(self.timing.phase_len());
        Ok(StageClearance { slot, late })
    }
```

Offsets must be non-decreasing and each below the phases per epoch. The whole wave therefore fits inside one epoch after dispatch.

**Release quantization.** `complete` returns the first epoch boundary strictly after the clock's current time (src/timing.rs):

```rust
    pub fn release_at(&self, completed_at: Nanos) -> Option<Nanos> {
        self.epoch_index(completed_at)
            .checked_add(1)?
            .checked_mul(self.epoch_len)
    }
```

A completion exactly on a boundary waits a full epoch. Either way, the release time depends on which epoch the work finished in, not where inside it.

**Tickets are bound to their issuer.** Each cop takes a process-unique issuer number at build time and stamps it on every ticket. Each lane keeps a bounded map of live tickets, and `complete` retires one. Both `stage_check` and `complete` run this check (src/cop.rs):

```rust
    fn check_live(&self, op: Op, ticket: &DispatchTicket) -> Result<(), Trip> {
        if ticket.issuer != self.issuer {
            return Err(self.trip(op, TripReason::ForeignTicket, None));
        }
        let live = self
            .lanes
            .get(ticket.lane.index())
            .and_then(|q| q.live.get(&ticket.id.seq));
        if live != Some(ticket) {
            return Err(self.trip(op, TripReason::TicketNotLive, None));
        }
        Ok(())
    }
```

A lane keeps at most queue_cap + 4 x weight x max_dispatch_per_phase live tickets, capped at 1,048,576 (`config::live_ticket_cap`). At the cap, that lane's own oldest ticket expires, so one lane never touches another's tickets. Request ids are per-lane sequences for the same reason.

**The driver.** `GreenWaveDriver` keeps the core behind a `std::sync::Mutex` that is never held across an `.await`. Its poll loop runs on a dedicated thread from tokio's blocking pool. The thread sleeps until 200 microseconds before each phase start, busy-waits through the boundary, then polls.

Three measures stop a flood on one lane from holding up the poll. First, a full lane is refused without taking the lock, using lock-free copies of each lane's depth, the halt flag and the clock watermark. The verdict is the core's own (src/driver.rs):

```rust
    fn refuse_full_lane(&self, lane: LaneId) -> Option<Trip> {
        let s = &self.shared;
        let m = s.lanes.get(lane.index())?;
        if s.halted.load(Ordering::Acquire) || m.depth.load(Ordering::Acquire) < m.cap {
            return None;
        }
        let now = self.clock.now();
        if now < s.watermark.load(Ordering::Acquire) {
            return None; // possible regression: let the core halt
        }
        let abs = s.table.next_phase_after(lane, s.timing.abs_phase(now))?;
        let retry_after = s.timing.phase_start(abs)?;
        let trip = Trip::new(Op::Admit, TripReason::QueueFull, Some(retry_after));
        telemetry::record_trip(&trip);
        telemetry::record_op(Op::Admit, trip.outcome());
        Some(trip)
    }
```

Second, async callers give way to a waiting poll, at most 1,024 yields each. Third, the loop takes the lock once per phase. A stale copy can only err towards "full", so the worst case is one spurious RETRY; it never admits past the cap.

Before each poll the driver reserves room in its output channel, and the poll takes no more requests than there is room for. Each request then goes out on a reserved permit, a send that cannot fail.

**Bounds.** Every buffer is sized from validated configuration, never from a request:

| Setting | Default | Hard cap | What it bounds |
|---|---|---|---|
| `phase_len_ns` | 1,000,000 (1 ms) | At least 1,000 in the core, 1,000,000 in the driver | Grid resolution |
| `phases_per_epoch` | 8 | 1 to 1,024 | Phase table size |
| Epoch length | 8 ms | At most 60 s | Delay added by quantization |
| `lanes` | 4 lanes of weight 2 | 1 to 64 lanes | Lane count |
| `queue_cap` per lane | 64 | 1 to 65,536 each, 1,048,576 in total | Queued requests |
| `max_dispatch_per_phase` | 4 | 1 to 1,024 | Work and memory per poll |
| `stage_offsets` | [0, 1, 2, 3] | 1 to 32 stages, each below phases per epoch | Wave table |
| Live tickets per lane | 64 + 4 x 2 x 4 = 96 | At most 1,048,576 | Ticket memory |
| Driver busy-wait | Wake 200 microseconds early | 50,000,000 spins | About a fifth of a core at 1 ms phases |

`PhaseTable::build` is public, so it repeats the lane, phase and weight checks before it allocates anything.

**Tradeoffs.**

| Choice | Benefit | Cost |
|---|---|---|
| Not work-conserving: an idle owner's phase stays idle | One lane's load cannot change another lane's timing | Throughput is lost while some lanes idle and others are full |
| Release only on epoch boundaries | Hides where inside an epoch work finished | Adds up to one epoch per response; still reveals the epoch count |
| Missed phases are lost, not made up | Lanes never borrow each other's phases | A late driver costs that lane its turn |
| Live tickets expire at a per-lane cap | Memory stays bounded per lane | Work slower than the cap allows has its completion refused |

**The Python that exists.** A search of the five TACK repositories found no Python scheduler like this. Two nearby pieces live in sentinel_os/sentinel_os, read on 2026-10-01. `rate_limiter_v2.py` is a Redis token bucket per validated API key that answers HTTP 429 with a Retry-After header.

That limiter caps how fast each caller sends, but it gives no caller a guaranteed turn. Its docstring says it fails open when Redis is unavailable, the opposite of this crate's fail-closed rule. `queue_schema.py` keeps pending jobs in one Redis list per queue, so one caller's backlog can sit ahead of everyone else's.

**Facts and assumptions.**

- Fact: the bound, caps and verdicts are asserted by the crate's tests on a manual clock.
- Fact: driver timing comes from one 4 vCPU Linux VM and varies between runs.
- Assumption: an authenticated upstream assigns lane identity; the caller does not choose it. Treating `unknown_lane` as TERMINAL_BREACH rests on this.
- Assumption: placing it between `rate_limiter_v2.py` and the worker pool is a proposal; nothing is wired.

### Failure mode and state resolution

Every operation returns a typed `Trip` or a success value. Library code contains no `unwrap`, `expect`, `panic!` or `unsafe`. The outcome and resolution come from the reason through one table in src/error.rs, so call sites cannot disagree.

| Trip | Outcome | State resolution | Why |
|---|---|---|---|
| `queue_full` (admit): the lane's queue is at its cap | RETRY | reject | Load, not misbehaviour. The payload comes back; `retry_after` is the lane's next phase start, when its queue can first shrink. |
| `not_yet_due` (stage_check): the stage's due phase has not started | RETRY | reject | Running early would break the wave for the requests behind. `retry_after` is the due time. |
| `unknown_lane` (admit): the lane index is not in the table | TERMINAL_BREACH | reject | Lane identity comes from upstream; picking another lane would be lane hopping. No sequence number is used. |
| `unknown_stage` (stage_check): the stage index is past the wave | TERMINAL_BREACH | reject | The stage does not exist in the validated wave. |
| `completion_before_dispatch` (complete): the clock reads earlier than the ticket's dispatch time | TERMINAL_BREACH | reject | The ticket is not on this scheduler's timeline. |
| `foreign_ticket` (stage_check, complete): another cop's issuer number | TERMINAL_BREACH | reject | No correction makes another scheduler's ticket valid here. |
| `ticket_not_live` (stage_check, complete): already completed, or expired at the lane cap | TERMINAL_BREACH | reject | One release per request. A replay or an expired ticket cannot be repaired. |
| `overflow` (any operation): a time or sequence sum passes the u64 range | TERMINAL_BREACH | reject | Only near the end of the clock's range. Checked arithmetic fails closed, never wraps. |
| `clock_regressed` (any operation, including reset) | TERMINAL_BREACH | halt | Every bound assumes time never goes backwards. Queues and live tickets are kept for the operator. |
| `halted` (any operation while halted) | TERMINAL_BREACH | halt | Nothing the caller changes repairs it. Only an operator `reset` does. |
| `driver_stopped` (driver loop): the runtime is shutting down | TERMINAL_BREACH | reject | The loop could not run. Nothing was taken out of a queue. |
| `ConfigError`, 16 variants (build) | TERMINAL_BREACH | halt | The scheduler is never built. Includes `phase_too_short_for_driver` below 1 ms. |
| Not a trip: a stage runs after its due phase ended | PASS, with `late = true` | none | Quantization absorbs lateness up to the epoch boundary. Counted in `tack_greenwave_stage_late_total`. |
| Not a trip: phases pass with no poll | PASS on the next poll | none | Lost phases are not made up. Counted in `tack_greenwave_phases_missed_total`. |
| Not a trip: a lane dispatches past its live-ticket cap | PASS | none; that lane's oldest ticket expires | Memory stays bounded per lane. Counted in `tack_greenwave_tickets_expired_total`. |
| Not a trip: the output channel is full or closed | none | none; the loop waits, or stops before dequeuing | Backpressure. No dispatched request is dropped. |

The halt comes from one function that every operation calls first (src/cop.rs):

```rust
    fn observe(&mut self, op: Op) -> Result<Nanos, Trip> {
        if self.halted {
            return Err(self.trip(op, TripReason::Halted, None));
        }
        let now = self.clock.now();
        if now < self.last_now {
            self.halted = true;
            telemetry::halted_enter();
            tracing::error!(
                previous = self.last_now,
                observed = now,
                "clock went backwards; halting until operator reset"
            );
            return Err(self.trip(op, TripReason::ClockRegressed, None));
        }
        self.last_now = now;
        Ok(now)
    }
```

**Never quarantine, never roll back.** The crate knows no sender identity beyond the lane, and a busy lane is already contained by its own queue and phases. A refusal changes no state, so there is nothing to roll back.

**Operator reset.** A reset from halt clears it, re-anchors the clock watermark and restarts phase accounting. A reset while running changes nothing, so it cannot refresh a dispatch budget. If the clock went back unobserved, the reset trips `clock_regressed` and halts.

Queued requests survive a halt and a reset. Tickets issued before a regression may then fail `complete` with `completion_before_dispatch`, which is the safe direction.

### Observability and telemetry

Metrics use the `metrics` facade, and every label value comes from a closed enum. Lane ids are not labels; per-lane depth comes from `TrafficCop::lane_depth`.

| Name | Type | Labels | Meaning |
|---|---|---|---|
| `tack_greenwave_admissions_total` | counter | `outcome` (pass, retry, terminal_breach) | One per `admit` call. |
| `tack_greenwave_trips_total` | counter | `op` (admit, poll, stage_check, complete, reset), `reason` (11 values), `outcome` (retry, terminal_breach), `resolution` (reject, halt) | One per refusal, except two uncounted driver-side `overflow` cases (next phase start, tokio `Instant`). |
| `tack_greenwave_polls_total` | counter | `outcome` (pass, terminal_breach) | One per poll. |
| `tack_greenwave_dispatched_total` | counter | none | Requests dispatched. |
| `tack_greenwave_stage_checks_total` | counter | `outcome` (pass, retry, terminal_breach) | One per `stage_check` call. |
| `tack_greenwave_stage_late_total` | counter | none | Stage checks that passed after the due phase had ended. |
| `tack_greenwave_releases_total` | counter | `outcome` (pass, terminal_breach) | One per `complete` call. |
| `tack_greenwave_phases_missed_total` | counter | none | Phases that passed with no poll, including those before the first poll. |
| `tack_greenwave_config_rejected_total` | counter | `reason` (16 `ConfigError` values) | Configurations refused at build time. |
| `tack_greenwave_resets_total` | counter | none | Resets that cleared a halt or found nothing. One that finds a regression is a trip. |
| `tack_greenwave_tickets_expired_total` | counter | none | Live tickets expired at their lane's cap. |
| `tack_greenwave_queue_wait_seconds` | histogram | none | Admission to dispatch, one sample per dispatched request. |
| `tack_greenwave_queue_depth` | gauge | none | Requests waiting across every scheduler in the process. |
| `tack_greenwave_halted` | gauge | none | Number of halted schedulers in the process. |

The two gauges are shared by every scheduler in a process, with no instance label. They only move by increments and decrements, so a new scheduler cannot clear another's halt.

tests/telemetry.rs asserts that 13 of the 14 metrics fire, using `DebuggingRecorder` with `metrics::with_local_recorder`. No crate test covers `tack_greenwave_tickets_expired_total`; a scratch program for this manual saw it reach 1. tests/driver_metrics.rs uses a global recorder, because the driver polls on its own thread.

Spans, named `tack.greenwave.<operation>`:

- `tack.greenwave.build` (INFO; fields `lanes`, `phases`, `stages`). Wraps `TrafficCop::new`.
- `tack.greenwave.admit` (DEBUG; field `lane`). Core and driver admission.
- `tack.greenwave.poll` (DEBUG). WARN events inside report missed phases and expired tickets.
- `tack.greenwave.stage_check` (TRACE; fields `seq`, `stage`).
- `tack.greenwave.complete` (TRACE; field `seq`). The completion time is not a field.
- `tack.greenwave.reset` (INFO; field `was_halted`).
- `tack.greenwave.drive` (INFO; field `max_phases`). The driver's poll loop.
- `tack.greenwave.release_wait` (TRACE; field `seq`). The driver holding a result until release.

A clock regression logs one ERROR event with the previous and observed clock readings.

**No raw input to log.** The payload is a generic type with no trait bound, so the cop cannot read it, and there is nothing to hash. Logs carry lane indexes, sequence numbers, phases and grid times.

**Timing side channels.** This crate exists partly to reduce one, so its own leaks matter:

- The `stage_check`, `complete` and `release_wait` spans are at TRACE, because subscribers stamp spans with wall-clock time. Enabling TRACE for less trusted readers reopens that channel.
- A refused admission is faster than an accepted one, and the driver refuses full lanes without the lock. This reveals queue fullness, which is public in this design.
- No metric records service or hold time. The histogram covers admission to dispatch, which depends only on public inputs.
- Released results leave at the boundary plus runtime timer jitter. The crate assumes that jitter is unrelated to the request, but it is not zero, so ANC must bound it.
- Quantization hides where inside an epoch work finished, not how many epochs it took.

```yaml
groups:
  - name: tack-greenwave
    rules:
      - alert: TackGreenwaveHalted
        expr: max(tack_greenwave_halted) >= 1
        labels: {severity: critical}
        annotations: {summary: "A clock went backwards; the scheduler refuses all work until an operator reset."}
      - alert: TackGreenwaveConfigRejected
        expr: increase(tack_greenwave_config_rejected_total[15m]) > 0
        labels: {severity: critical}
        annotations: {summary: "A configuration failed validation; that instance never started."}
      - alert: TackGreenwavePhasesMissed
        expr: sum(rate(tack_greenwave_phases_missed_total[5m])) > 0
        for: 5m
        labels: {severity: warning}
        annotations: {summary: "Lanes are losing turns; the one-epoch bound is void. Check CPU saturation."}
      - alert: TackGreenwaveQueueFullSustained
        expr: sum(rate(tack_greenwave_trips_total{reason="queue_full"}[5m])) > 0
        for: 15m
        labels: {severity: warning}
        annotations: {summary: "A lane sheds load continuously. Check weights and queue caps."}
      - alert: TackGreenwaveTerminalBreaches
        expr: sum(rate(tack_greenwave_trips_total{outcome="terminal_breach",reason!~"halted|clock_regressed"}[5m])) > 0
        for: 5m
        labels: {severity: warning}
        annotations: {summary: "Unknown lanes or stages, foreign or replayed tickets: a routing fault or forged input."}
      - alert: TackGreenwaveTicketsExpiring
        expr: sum(rate(tack_greenwave_tickets_expired_total[5m])) > 0
        for: 10m
        labels: {severity: warning}
        annotations: {summary: "Work outlives its lane's live-ticket cap; those completions are refused."}
      - alert: TackGreenwaveWaveBroken
        expr: sum(rate(tack_greenwave_stage_late_total[5m])) / clamp_min(sum(rate(tack_greenwave_stage_checks_total{outcome="pass"}[5m])), 1e-9) > 0.01
        for: 10m
        labels: {severity: warning}
        annotations: {summary: "Over 1% of stage runs are behind the wave."}
      - alert: TackGreenwaveQueueWaitOverEpoch
        expr: histogram_quantile(0.99, sum by (le) (rate(tack_greenwave_queue_wait_seconds_bucket[5m]))) > 0.008
        for: 10m
        labels: {severity: warning}
        annotations: {summary: "p99 queue wait over the 8 ms default epoch. Needs histogram buckets."}
```

### Red-team results

The red team wrote 25 attacks as tests in tests/redteam.rs. Against the first build, 15 failed and 10 held: 1 blocker, 5 major and 9 minor, 3 of them partial. After the fixes all 25 pass in most runs, but the real-time driver tests still fail intermittently under full CPU load.

| Attack | Result | Fix or limitation |
|---|---|---|
| 8,000 tasks flood a full lane and delay another lane's poll through the driver's shared async mutex | Broke (blocker), then fixed | The victim waited 592 to 1,083 ms (epoch 10 ms). Full lanes now skip the lock, which is synchronous, and the poll has its own thread. Five runs here: 4.7 to 9.9 ms, limit 20 ms. |
| The driver cannot keep the default 1 ms grid, even idle | Broke, then fixed with a limit | tokio's timer lost 70 phases in 60 iterations. An OS thread now sleeps and busy-waits: 0 missed, about 2.8 ms worst wait when isolated. |
| Sub-millisecond phases pass validation but cannot be driven | Broke, then fixed | 100 microsecond phases lost 428 in 40 polls. The driver now refuses phases under 1 ms; the core still accepts them. |
| A ticket from another cop accepted at `complete` and `stage_check` | Broke, then fixed | Issuer numbers on tickets. Both calls now return `foreign_ticket`. |
| One ticket completed twice, and a stage cleared after completion | Broke, then fixed | Per-lane live-ticket map. Both now return `ticket_not_live`. |
| Global request ids leak other tenants' volume | Broke, then fixed | Lane 0 saw an id gap of 38 when lane 1 was busy. Per-lane ids now give 1 either way. |
| Building a second scheduler clears the critical halt gauge | Broke, then fixed | Gauges are now sums, never set, and the alert reads `>= 1`. It stays at 1 after a second build. |
| Tracing timestamps record the completion instant | Partial, then fixed by level | Spans and events in `complete`, `stage_check` and `release_wait` are now TRACE. Limitation: enabling TRACE reopens the channel. |
| The fairness bound was claimed as strict | Partial, then fixed in docs | A request waited exactly one epoch (7,000 ns). Docs now say at most one epoch plus poll latency. |
| `reset` refreshes the phase budget mid-phase, and absorbs an unobserved clock regression | Broke, then fixed | One phase dispatched 4 against a budget of 2. A reset while running now changes nothing, or trips `clock_regressed`. |
| Missed phases before the first poll are not counted | Broke, then fixed | 100 unpolled phases counted 0. Accounting now starts at build and at reset, and the same case counts 99. |
| Public `PhaseTable::build` skips every cap | Broke, then fixed | A 12,000 by 12,000 table took 2.2 s. Caps are now checked first; refusal takes microseconds. |
| The driver destroys dispatched payloads when the output closes mid-batch | Broke, then fixed | 2 of 3 dispatched payloads were dropped. Now 1 is sent, 2 stay queued and none is destroyed. |
| 512 random sequences of up to 200 operations: clock jumps near u64::MAX, regressions, forged lanes, stale tickets, resets | Held | No panic, no PASS while halted, no trip with a PASS outcome; caps and phase ownership held. |
| Hostile configurations: arbitrary integers, 0 to 69 lanes, 0 to 39 offsets | Held | No panic. Building succeeds exactly when `validate` succeeds. |
| Label cardinality from all 65,536 lane ids, and log injection through payloads | Held | 13 distinct metric series. Payloads never appear in Debug or Display output. |
| Unknown-lane side effects, cross-lane dispatch timing, release quantization | Held | An unknown lane changes nothing. A 50-per-step flood left another lane's dispatch times identical. Four completions in one epoch shared a release time. |

The two "Held" property tests ran 512 cases each, and the starvation property test in tests/starvation_prop.rs runs 256; no fuzzer was used.

Three test edits were made during the fixes:

- `rt_halted_gauge_not_cleared_by_second_cop` lost an intermediate snapshot, which itself zeroed the recorder's gauge. Its final assertion is unchanged.
- `rt_empty_lane_bound_strictly_under_one_epoch` now asserts `<=` instead of `<`, as the finding proposed.
- `no_lane_starves` keys its map by the full `RequestId`, since per-lane sequences repeat. No assertion changed.

Known limitations that remain:

- **Full CPU load costs phases.** The red-team binary failed 3 of 14 full runs for this manual. Two failures were `rt_driver_default_config_misses_no_phases`, at 10.5 and 12.9 ms against an 8 ms limit; the third was not identified. That test passed all 4 isolated runs.
- **No fix without privileges.** Per the fix agent, the flood test holds all 4 vCPUs and the kernel wakes the driver up to about 4 ms late. Raising the driver thread's priority would need `unsafe` system calls, which the crate rules forbid. Missed phases are counted, and the bound holds only when none are lost.
- **One unexplained failure.** tests/driver_metrics.rs failed once in 16 runs, after 1.18 s, with its message not captured. Load is the assumed cause.
- **Blind metric reading.** Two red-team driver tests read `phases_missed_total` through a thread-local recorder that cannot see the driver thread, so it reads 0.
- **Coverage gaps.** The ticket tests assert only that a refusal happens, and the sub-millisecond test returns early on refusal. A scratch program confirmed `foreign_ticket`, `ticket_not_live`, expiry at a cap of 5 and `phase_too_short_for_driver`. No crate test covers expiry or `driver_stopped`.
- **Process scope.** Issuer numbers are unique per process, and each clock anchors its own epoch boundaries.
- **Stale comment.** The `HALTED` doc comment in src/telemetry.rs says dropping a halted scheduler lowers the gauge. The `Drop` impl in src/cop.rs deliberately does not; the comment needs fixing.

`cargo clippy -p tack-greenwave --all-targets -- -D warnings` finishes with no warnings. Across 10 runs of `cargo test -p tack-greenwave --all-targets` for this manual, 7 passed all 47 tests. Three failed one test each, twice in the red-team binary and once in driver_metrics.

Failing runs stop at the failing binary, as in `test result: FAILED. 24 passed; 1 failed; 0 ignored; 0 measured; 0 filtered out; finished in 3.52s`. The final run passed; its lines are unit, driver, driver_metrics, redteam, scheduling, starvation_prop and telemetry:

```text
test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s
test result: ok. 2 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.02s
test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.06s
test result: ok. 25 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 3.54s
test result: ok. 15 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.04s
test result: ok. 2 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.25s
test result: ok. 2 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s
```
