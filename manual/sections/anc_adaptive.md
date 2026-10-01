## ANC strategy 2: adaptive rolling-average blinding

The brief's rolling-average target leaked (max |t| up to 24.7, leak line 4.5); the epoch-quantized fix stayed below 4.5 at 100,000 per class.

*New design: reference implementation compiled and tested on Rust 1.94*

ANC (Active Timing Cancellation) is the kernel's defence against attackers who learn a secret from how long replies take. This crate, `tack-anc-adaptive`, is a new design and is not deployed anywhere. Of the seven TACK components, only the Sentinel Hash-Chain in sentinel_os exists today.

Max |t| is a test statistic, explained under the verification harness; above 4.5 counts as a detected leak. A pass means no detectable leak at that sample size, on one 4-vCPU virtual machine; it is never a proof. The fix's Sleep mode still failed a stricter test of distribution shape (KS) in every full-size run, while its Hybrid mode passed.

At the production leak budget the fix also spent most of its time at its fixed cap, which the brief did not expect.

### Mechanics

**The idea.** Padding holds each reply until a target time, so a fast path and a slow path look alike from outside. Strategy 1 uses one fixed target, sized for the slowest case. Strategy 2 lets the target follow recent load, so replies come back sooner when the server is quiet.

The crate's own picture is a bus timetable. Strategy 1 prints one timetable and never changes it. Strategy 2 rewrites it from recent boarding times, and the danger is that the timetable becomes a record of who boarded.

**The brief's design, kept so it can be measured.** `NaiveRollingTarget` sets the target to the mean, or the 99th percentile (p99), of the last 256 work times plus 10 us (microseconds). The target stays between a floor, the lowest allowed target, and a cap, the hard ceiling. It has three leaks, each shown in `tests/naive.rs`:

1. **Late release.** A request slower than the target leaves when it finishes, so its reply time is its raw, secret-dependent work time.
2. **Poisoning.** An attacker fills the window with fast requests, pulls the target below the slow path, then probes.
3. **A target that records history.** Every reply shows the current target, which is a statistic of other users' secret-dependent work.

**The fix: an epoch-quantized target.** `EpochQuantizedTarget` follows predictive mitigation (Askarov, Zhang and Myers, CCS 2010). The server predicts a release time and changes the prediction only when a reply misses it. Its rules are short:

- The target is always a public level: the floor times a power of two, never above the cap. The verify runs used 64, 128, 256, 512, 1,024 and 2,048 us.
- A misprediction is work that runs past the target. The level doubles until it covers the work, and the reply leaves at that level, never at the raw time. This is an escalated release.
- The level steps down by one only at an epoch boundary, a wall-clock tick fixed at construction. The epoch that ended must have had requests, no misprediction, and work the lower level would also have covered.
- Work past the cap is a RETRY. The value is dropped and the reply leaves at the next whole multiple of the cap.

**Counting the leak.** An attacker can still learn when the target changed, which replies left at a raised level, and each overrun's cap multiple. The controller charges each of these as a change. A bit is one yes-or-no answer, and the bound counts the bits those changes can carry:

```text
leak <= N * log2(2 * (R + 1)) bits   N charged changes among R requests in one window
window budget    128 bits per 60 s    a rate: when spent, back to the cap for the rest of the window
lifetime budget  8 x 128 = 1,024 bits when spent, held at the cap until an operator reset
```

The ANC analysis gives N * log2(R + 1); the crate adds one bit per change for its direction, so its bound is the larger. It is a counting argument under the threat model, not a published theorem checked here.

The descent from a public starting level, the warm-up, is not charged; only its end is. Charging it let 35 s of honest traffic freeze an earlier build in red-team tests.

**Order of events for one request.**

1. Read the monotonic clock, one that never runs backwards. This is the admission time.
2. Check public facts only: the halted flag, the input length, a free slot and the spin budget. A failure returns at once.
3. Take a snapshot of the target from the controller.
4. Run the operation under `catch_unwind`, so a panic cannot escape the pad.
5. Plan the release from the snapshot, then record the work time in the controller. Both run inside the padded wait.
6. Wait until the admission time plus the planned release. Sleep mode sleeps; Hybrid mode sleeps, then busy-waits (spins) the last 250 us by default, for precision.
7. Only then free the slot, emit metrics and logs, and return.

**Trips and resolutions.** Each trip maps to the CNS GateOutcome vocabulary (PASS, RETRY, TERMINAL_BREACH) and to one state resolution. RETRY means the caller may resubmit; TERMINAL_BREACH means no correction repairs it.

| Trip | Outcome | Resolution | Why |
|---|---|---|---|
| `SlotsFull` | RETRY | reject | Load, not the secret. Shed at admission, before any secret work. |
| `InputTooLarge` | RETRY | reject | Length is public and checked first. The digest is not computed, so the sender cannot choose the logging cost. |
| `Overrun`, work past the cap | RETRY | reject | The value is dropped. The reply leaves on the cap grid, and its multiple is charged to the budget. |
| `OperationPanicked` | TERMINAL_BREACH | quarantine | Caught, released on schedule and counted. A halt would let one request stop the pad for everyone. |
| `ClockFailure` | TERMINAL_BREACH | halt | Padding cannot be trusted without a monotonic clock. |
| `Halted` | TERMINAL_BREACH | halt | Every request after a clock failure, until an operator calls `reset()`. |
| `LeakBudgetSpent`, controller | RETRY | rollback | The target returns to the cap for the rest of the window. Waiting repairs it, and requests are still served. |
| `LeakLifetimeSpent`, controller | TERMINAL_BREACH | rollback | The target stays at the cap until `reset_controller()`. Requests are still served. |

An escalated release is not a trip: the value is returned and counted in `tack_anc_overrun_total`. The leak budget never halts the pad, because a flood that forces mispredictions could then force a shutdown.

**Telemetry.** Metric labels come only from closed sets: `strategy="adaptive"`, `controller`, and one of `outcome`, `reason`, `disposition` or `direction`. The only duration histogram, `tack_anc_response_seconds`, holds the post-padding time the client already sees. No metric carries the pre-padding work time.

| Metric | What it shows |
|---|---|
| `tack_anc_requests_total{outcome}` | One per request, sheds included |
| `tack_anc_shed_total{reason}` | Refused at admission: `slots_full`, `input_too_large` or `halted` |
| `tack_anc_overrun_total{disposition}` | `late` (naive), `escalated` (epoch) or `retry` (past the cap) |
| `tack_anc_target_changes_total{direction}` | `increase`, `decrease` or `rollback` |
| `tack_anc_leak_budget_bits`, `tack_anc_leak_lifetime_bits` | Bits charged in this window, and since the last reset |
| `tack_anc_controller_frozen`, `tack_anc_controller_frozen_until_reset` | 1 while the target is held at the cap |
| `tack_anc_spin_reserved_nanoseconds_total` | Spin reserved at admission; the spin actually done would reveal target minus work |

Spans are `tack.anc.adaptive_pad` for each request, plus `tack.anc.adaptive_reset` and `tack.anc.adaptive_controller_reset`. Inputs are logged at debug level, after release, as their length and full SHA-256 hex. The change and budget metrics are derived from work times, so the metrics endpoint must stay private.

Proposed alert rules follow. They use the crate's metric names but were not loaded into a Prometheus server here. The metric behind the lifetime alert is emitted but not yet asserted by a recorder test.

```yaml
- alert: TackAncAdaptiveOverrun
  expr: sum by (controller) (rate(tack_anc_overrun_total{strategy="adaptive"}[5m])) > 0
  for: 5m
- alert: TackAncLeakBudgetSpent
  expr: increase(tack_anc_leak_budget_exhausted_total{strategy="adaptive"}[10m]) > 0
  for: 0m
- alert: TackAncLeakLifetimeSpent
  expr: tack_anc_controller_frozen_until_reset{strategy="adaptive"} == 1
  for: 0m
- alert: TackAncHalted
  expr: tack_anc_halted{strategy="adaptive"} == 1
  for: 0m
```

The first two are warnings and the last two are critical. A window freeze lifts on its own, so its alert asks for investigation, not a reset.

### Pros and cons

**Verdict on the brief's design.** The rolling mean failed. It was detected in all 4 runs (max |t| 11.5 to 24.7). In the two main runs, 4.3 and 5.0 percent of replies left late.

The p99 variant was not detected in honest traffic, but its max |t| sat at 3.0 to 3.9 in all 4 runs. With a 16-entry window, an attacker who refilled it with fast requests before each probe brought the leak back. Max |t| was 9.5 to 11.1 at 10,000 probes per class.

Where the measurements contradict the brief:

1. **Feedback that carries the delta instead of cancelling it.** The rolling mean changed about 189,000 times in 202,000 requests, a bound near 3.5 million bits.
2. **No room on this host for both adapting and a small budget.** Under a 1,000,000-bit measurement budget, the epoch target made 734 and 855 changes per one-minute Sleep run, about 13,700 and 15,900 bits. The 128-bit production budget froze it within 0.55 to 0.95 s, leaving 82 and 98 percent of those runs' replies at the cap.
3. **A target path that still followed the class mix, which the ANC analysis asked to avoid.** Level sequences differed in every run, and class A's mean reply moved 8.7 and 9.9 us between mixes (rolling mean: 20.2 and 14.0 us). The crate predicts this when the floor, 64 us here, is below the worst-case work under load.
4. **A budget trip that changed class.** The ANC analysis mapped a spent budget to TERMINAL_BREACH, but the red team showed one slow request could then force an operator-only freeze. A window spend is now RETRY, and only a lifetime spend is terminal.

| Design | Pros | Cons |
|---|---|---|
| Naive rolling target (the brief) | Lowest added median latency for class A: about 80 us (mean) and 108 us (p99) over the unprotected victim. One ring buffer, little code. | Leaks through late release, poisoning and target history. The mean form was detected in every run. Never deploy it, yet its constructor is still public (open finding). |
| Epoch target, Sleep | No detectable leak on \|t\| in any run. Every visible change is counted and budgeted. No CPU while waiting: 53 to 54 us of thread CPU per request. | Adds about 180 to 184 us at the class A median. KS flagged a difference between the classes in all 3 full-size pinned runs. |
| Epoch target, Hybrid, 250 us tail | Lowest max \|t\| (2.27 and 1.29), and KS did not flag it. | The target must cover the tail, so it sat at 512 us and added about 500 us at the median. About 219 us of CPU per request, 4 times Sleep. |
| Epoch target at the production budget | Leak capped at 128 bits per window and 1,024 bits between operator resets. | On this host it froze within a second and held 82 to 98 percent of replies at the 2,048 us cap. It then behaves like strategy 1 with more moving parts. |

### Recommended Rust pattern

If you adapt at all, use `EpochQuantizedTarget`, never `NaiveRollingTarget`. Use Hybrid mode when a KS pass matters, and set the floor at or above the worst-case work plus the spin tail at nominal load. Then both classes share the floor level, and the target moves with load only.

The pattern has three parts: a pure release plan, a controller update inside the padded wait, and a controller that charges every visible move. The pad core, from `src/pad.rs`:

```rust
        let tail_need = match adm.mode {
            WaitMode::Hybrid => self.config.spin_tail,
            WaitMode::Sleep => Duration::ZERO,
        };
        let need = work.saturating_add(tail_need);
        let plan = snap.plan(need);
        {
            let mut g = self.lock();
            let rec = g.record(&snap, need, completion);
            ev.changes = ev.changes.merge(rec);
            ev.status = Some(g.status());
        }
        let waited = start
            .checked_add(plan.release())
            .ok_or(ClockFault)
            .and_then(|target| wait::wait(&self.clock, target, adm.mode, self.config.spin_tail));
        if waited.is_err() {
            return self.clock_failure(start, ev);
        }
```

`snap.plan` is pure arithmetic, so the release schedule is testable without a clock. In Hybrid mode the pad plans `work + spin_tail`, so every released request sleeps, then spins. Without that rule, replies after a sleep ran about 0.9 us slower, and the classes differed at KS D 0.69 on the development host.

The upward rule, from `src/controller/epoch.rs`. Every miss is charged, even when a concurrent request already raised the level:

```rust
    fn record(&mut self, snapshot: &Snapshot, work: Duration, now: Instant) -> Changes {
        let mut ch = Changes::default();
        self.roll_window(now);
        self.epoch_requests = self.epoch_requests.saturating_add(1);
        self.epoch_max = self.epoch_max.max(work);
        if work <= snapshot.target {
            return ch;
        }
        // A miss: the release (a higher level, or the cap grid) depends on
        // this request's work time, so it is charged whatever the level
        // does (rule 4).
        self.epoch_mispredicted = true;
        self.warmup = false;
        let mut charge = 0u32;
        if !self.frozen {
            let needed =
                ladder::covering_level(self.cfg.floor, self.cfg.cap, 0, work).unwrap_or(self.top);
            if needed > self.level {
                let steps = needed - self.level;
                self.level = needed;
                self.increases_total = self.increases_total.saturating_add(u64::from(steps));
                charge = steps;
                ch.increases = steps;
            }
        }
        if work > self.cfg.cap {
            charge = charge.saturating_add(overrun_charge(self.cfg.cap, work));
        } else if charge == 0 {
            charge = 1;
        }
        self.count_change(charge);
        self.check_budget(&mut ch);
        ch
    }
```

The red team found that a request escalated after a concurrent raise left below the current level, with nothing charged. The `charge = 1` branch closes that. An overrun adds `ceil(log2(k))` changes for its cap multiple `k`, frozen or not.

The downward rule, from the same file. Decreases happen only at public epoch ticks, and the warm-up descent is charged once, at its end:

```rust
        let eligible = !self.frozen && self.level > 0 && self.epoch_requests > 0;
        if eligible
            && !self.epoch_mispredicted
            && self.epoch_max <= self.cfg.level_target(self.level - 1)
        {
            self.level -= 1;
            self.decreases_total = self.decreases_total.saturating_add(1);
            // Rule 5: a warm-up step follows the public default; only the
            // end of the run is charged.
            if !self.warmup {
                self.count_change(1);
            }
            ch.decreases = ch.decreases.saturating_add(1);
        } else if eligible && self.warmup {
            // The warm-up run stops here: charge its end once.
            self.warmup = false;
            self.count_change(1);
        }
```

### Anti-DoS mitigation

The risk is that padding itself becomes what a flood buys. If every fast failure is held to the target, many cheap requests buy many expensive waits.

The crate answers with four limits, all applied before any secret-dependent work:

- **Sleep by default.** A sleeping request blocks its thread and holds a slot, but uses no CPU.
- **A concurrency cap.** A non-blocking semaphore, a counter of free slots, sheds requests at admission with RETRY. It never queues, because a queue would make admission time depend on position.
- **A spin budget.** Hybrid spinning draws on a token bucket, a counter that refills at a fixed rate. Each request reserves a fixed charge that is never refunded, so the fallback to Sleep depends only on public load.
- **The cap.** A slow flood cannot push the target past it. In verify, all 256 slow requests against the rolling target got RETRY, and the target stopped at the 2,048 us cap.

Admission, from `src/pad.rs`:

```rust
    fn admit(&self, start: Instant, input_len: Option<usize>) -> Result<Admitted<'_>, Trip> {
        if self.is_halted() {
            return Err(Trip::Halted);
        }
        if input_len.is_some_and(|n| n > self.config.max_input_len) {
            return Err(Trip::InputTooLarge);
        }
        let permit = self.slots.try_acquire().ok_or(Trip::SlotsFull)?;
        let charge = self.config.spin_charge();
        let (mode, reserved, fallback) = if self.budget.try_reserve(charge, start) {
            (self.config.mode, charge, false)
        } else {
            (WaitMode::Sleep, Duration::ZERO, true)
        };
        Ok(Admitted {
            _permit: permit,
            mode,
            reserved,
            fallback,
        })
    }
```

Every limit lives in a config struct. Out-of-range values are rejected at construction, never clamped.

| Limit | Default | Accepted range |
|---|---|---|
| `max_concurrent` (slots) | 64 | 1 to 65,536 |
| `spin_tail` (Hybrid) | 250 us | 0 to 10 s, and below the cap |
| `spin_budget` | 250 ms of CPU per second, 50 ms burst | above 0, at most 64 s each |
| `max_input_len` | 64 KiB | 0 to 64 MiB |
| `cap` | none; the operator must choose | floor to 10 s |
| `epoch` | 1 s | 1 ms to 1 h |
| `leak_budget` | 128 bits per 60 s window | above 0, at most 1,000,000 bits; window 1 ms to 24 h |
| `leak_lifetime_windows` | 8, which is 1,024 bits | 1 to 1,000,000 |
| Naive `window` | 256 samples | 1 to 65,536, allocated once, at most 1 MiB |
| Sleep rounds per wait | 64 | fixed |

**What the flood test measured.** For 3 s, 10 threads per slot sent fast-fail requests at an epoch pad, alongside one honest client. Pinned to one CPU with one slot, the process used 0.258 and 0.248 cores in Hybrid, and 0.272 and 0.280 in Sleep. Each 3 s run shed 95,981 to 100,435 requests.

Reserved spin was 0.300 s against a bound of 0.310 to 0.311 s: 0.1 CPU seconds per second plus a 10 ms burst. The offered rate was 17 times admission capacity in Hybrid and 5 times in Sleep.

Unpinned, with 4 CPUs and 2 slots, the process used 0.887 and 0.942 cores of 4. Only 0.52 and 0.69 of its 2.67 and 2.83 CPU seconds were spent inside the pad. The rest was the flood workers' own retry loop, which in a deployment falls on the network path.

**What it did not protect.** The flood forced 4 and 8 target changes in Hybrid and 52 and 45 in Sleep. After the Sleep flood the window bound was 910 and 758 bits, about 6 to 7 times the production budget. A real flood can therefore freeze the controller at the cap, which costs latency, not secrecy.

Shedding is first come, first served. Pinned, the honest client finished 6 of 52 and 8 of 53 requests in Hybrid, and 1 of 51 and 0 of 51 in Sleep. With 2 slots unpinned it finished 110 of 119 and 167 of 171, so per-sender quotas belong at the inlet.

### Verification harness

The harness asks one question: can a stopwatch tell two groups of guesses apart? Class A guesses differ from the secret at byte 0, the fastest early exit. Class B guesses match bytes 0 to 30 and differ at byte 31, the slowest wrong path.

The victim calls `leaky_validate`, an early-exit compare, 256 times, then runs 10,000 multiply-add steps. In the middle third of each run that work is 4 times larger, with 2 memory-streaming threads, so timing drifts like a loaded server.

Each sample's class is drawn at random from a recorded seed and interleaved, so drift hits both classes alike. Each sample is timed from the call to the return, which is what a client sees.

**The tests.** A Welch t-test asks whether two groups have different mean times, without assuming equal spread. The harness also reruns it on only the samples below several percentiles, which removes slow outliers; this is cropping. A second-order test compares spreads.

The verdict is the largest |t| of those tests, and above 4.5 is a leak. A two-sample Kolmogorov-Smirnov (KS) test compares the whole shape of the two distributions; its D is the largest gap between them. The ANC analysis also asks for its p value to be at least 0.001.

Calibration comes first. The harness must flag the unpadded `leaky_validate` and pass the constant-time `ct_validate` at the same n, or the run proves nothing.

| Layer | Where | Profile and n | Runs in `cargo test`? | Role |
|---|---|---|---|---|
| Smoke test | `tests/leak.rs` | Debug, 2,000 per class, victim amplified to about 40 and 164 us | Yes | Calibration at that n, rolling mean flagged, epoch Hybrid passes. Not evidence. |
| Controller rules | `tests/epoch.rs`, `tests/naive.rs` | Synthetic clock times | Yes | Doubling, decreases, both budgets, freeze and thaw, and identical trajectories when the floor covers both classes. A property test with 64 cases keeps the target on the ladder. |
| Metrics | `tests/telemetry.rs` | `DebuggingRecorder` with `metrics::with_local_recorder` | Yes | 15 of the 20 metrics are asserted to fire, with closed-set labels. The 5 added by the fixes, for the lifetime budget and panics, are not yet. |
| Red team | `tests/redteam.rs` | 17 attack tests; one property test with 2,000 cases | Yes | 3 tests for open findings fail. |
| Evidence run | `examples/verify.rs` | Release, 100,000 per class | Compiled, not run | Calibration, leak tests, poisoning, trajectory, flood and the production budget, printed as JSON. |

**CI today, and the gap.** `cargo test --all-targets` runs the smoke test but only compiles the evidence run. The example prints JSON and exits 0 even when it finds a leak, and the pinned runs took 454 and 473 s. CI therefore needs a separate release job, for example nightly, that gates on the JSON:

```text
cargo build --release -p tack-anc-adaptive --example verify
./target/release/examples/verify > verify.json
jq -e '.calibration.passed
  and ([.runs[] | select(.name | startswith("epoch_")) | .detect.max_abs_t < 4.5] | all)
  and .poisoning.epoch.detect.max_abs_t < 4.5
  and .budget_default.detect.max_abs_t < 4.5' verify.json
```

This gate exited 0 on all 4 recorded runs. The same gate pointed at the naive rows exited 1 on all 4. A stricter gate that also requires the KS and crop lines (`.detect.pass_all`) exited 1 on the 3 full-size pinned runs, because of epoch Sleep.

**Measured results on this machine.** The host is an Intel Xeon at 2.10 GHz, a KVM virtual machine with 4 vCPUs and 16 GB. The build is release, with overflow checks on, timed with `std::time::Instant` in nanoseconds.

Runs 1 and 2 were pinned to one CPU with `taskset`, a tool that restricts a process to chosen CPUs. The 1-minute load average was 0.39 and 0.86 at the start and reached about 2.2 during runs. Other agents' test binaries also ran briefly, seen for up to about 15 s in run 1 and 20 s in run 2.

Each max |t| and CPU cell lists run 1 / run 2. Classes were drawn at random, so the n column gives the class A and class B counts, the same in both runs. CPU under flood is whole-process CPU per wall second over the 3 s flood, pinned to one CPU.

| Configuration | n per class | max \|t\| | detected? | CPU under flood |
|---|---|---|---|---|
| Calibration: unpadded `leaky_validate` | 100,322 A, 99,678 B | 2,254 / 1,601 | Yes, 2 of 2 (intended) | not flooded |
| Calibration: unpadded `ct_validate` | 100,322 A, 99,678 B | 1.05 / 2.82 | No, 0 of 2 | not flooded |
| Unprotected drifting victim | 100,322 A, 99,678 B | 1,551 / 1,129 | Yes, 2 of 2 | not flooded |
| Naive rolling mean (the brief's design) | 100,322 A, 99,678 B | 24.7 / 20.9 | Yes, 2 of 2 | not flooded |
| Naive rolling p99 | 100,322 A, 99,678 B | 3.01 / 3.88 | No, 0 of 2 (marginal) | not flooded |
| Naive p99, fast-flood poisoning | 10,017 A, 9,983 B | 9.47 / 11.09 | Yes, 2 of 2 | not flooded |
| Epoch, Sleep | 100,322 A, 99,678 B | 3.68 / 2.06 | No by \|t\|; KS flagged 2 of 2 | 0.272 / 0.280 cores (Sleep flood) |
| Epoch, Hybrid, 250 us tail | 100,322 A, 99,678 B | 2.27 / 1.29 | No, 0 of 2 | 0.258 / 0.248 cores (Hybrid flood, 100 ms per second spin budget) |
| Epoch, same poisoning attack | 10,017 A, 9,983 B | 1.38 / 0.94 | No, 0 of 2 | not flooded |
| Epoch, Sleep, production budget | 19,980 A, 20,020 B | 0.99 / 1.24 | No, 0 of 2 | not flooded |

**What the numbers say.** Calibration passed in both runs, so the method can see a leak on this host. An earlier pinned run and an unpinned run at 10,000 per class gave the same |t| verdict on every row. Detected |t| values moved 15 to 30 percent between runs, and values under the line moved by up to 1.8, so do not rank them.

KS flagged epoch Sleep in all 3 full-size pinned runs, with D of 0.0148, 0.0150 and 0.0215 against a line of 0.0087. Epoch Hybrid was not flagged in any of them.

KS also flagged the constant-time control once (run 2, p 7e-6), so this line has false alarms here. But the Sleep flag repeated in every run, and the control's did not.

One untested candidate cause: in Sleep mode the sleep lasts target minus work, so class B sleeps roughly 5 to 9 us less. If wake-up delay depends on sleep length, that is a timing side channel under kernel convention 6.

Uncropped, the smallest mean shift the test could flag was 13.4 to 13.9 us (Sleep) and 20.0 to 20.4 us (Hybrid). The secret's own median gap, 5.5 to 8.9 us, is smaller, so the cropped tests carry the sensitivity. They found the unprotected gap at |t| 1,551 and 1,129.

At the production budget the controller froze after 6,102 and 2,069 requests, warm-up included (0.95 and 0.55 s). It thawed at the next 60 s window boundary, then froze again. Its mean target was 1,711 and 2,020 us, against 148 and 163 us for the same pad under the measurement budget.

**Test suite status.** `cargo clippy -p tack-anc-adaptive --all-targets -- -D warnings` is clean, re-run for this section. With `--no-fail-fast`, 61 tests pass and 3 fail across 8 targets. The passes are unit 14, epoch 14, leak 1, naive 6, pad 7, red team 14 of 17 and telemetry 5.

The 3 failures are the red team's open findings, kept as failing tests, so the brief's command fails. Its final summary line, re-run for this section:

```text
test result: FAILED. 14 passed; 3 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.21s
error: test failed, to rerun pass `-p tack-anc-adaptive --test redteam`
```

Cargo stops at the first failing target, so `tests/telemetry.rs` ran only in the `--no-fail-fast` pass. The red team wrote 17 tests against the first build: 11 broke it and 6 held, and the fixes closed 8 of the 11.

### What this does not guarantee

- **No proof.** A pass is no detectable leak at that n on one virtual machine. The tests rule out shifts they could see, not all shifts.
- **Not zero leakage.** The budget meters the leak and does not remove it. By default the controller allows up to 1,024 bits between operator resets. A frozen controller still leaks its overruns and misses, and is charged for them.
- **Sleep mode's distribution.** KS separated the two classes under epoch Sleep in every full-size pinned run, for a reason not yet tested. Prefer Hybrid where that matters. A flood drains the spin budget and forces Sleep: about 1,200 of 5,000 served requests spun in the pinned Hybrid flood.
- **Slot occupancy (open finding).** A slow request holds its slot until its later release. A third party probing admission can then see `SlotsFull` and learn that a victim was slow.
- **Overrun multiples.** The blocking API cannot stop work at the cap, so an overrun's release still tells `ceil(work / cap)`. It is charged, but the multiple is not capped; a pre-emptible API is the real fix.
- **Reply content.** A RETRY reply differs from a value. Every trip is counted, but an overrun RETRY is influenced by the secret like an escalation.
- **Panic output.** A caught panic is released on schedule, but the panic hook prints at the moment of the panic, inside the wait. With `panic = "abort"` there is nothing to catch.
- **Availability (open finding).** One request per epoch with work near the cap holds every request at the cap. Shedding does not give honest clients a fair share.
- **A reachable naive controller.** `AdaptivePad::naive` carries a "never select it in a deployment profile" warning, but nothing enforces it (open finding).
- **One machine.** The numbers come from one KVM guest pinned to one CPU and shared with other agents. Each production host and CI runner needs its own calibrated runs.
- **The threat model.** The bound assumes the attacker sees only reply contents and times. Attackers with code on the same physical core, who can watch caches, are out of scope, as is anyone who can read the metrics endpoint.
