## ANC strategy 1: deterministic ceiling padding

Ceiling padding showed no detectable leak in 9 of 9 release runs at about 100,000 per class (worst max |t| 2.93; leak line 4.5).

*New design: reference implementation compiled and tested on Rust 1.94*

ANC (Active Timing Cancellation) is the kernel's defence against attackers who learn a secret from how long replies take. This crate, `tack-anc-ceiling`, is a new design and is not deployed anywhere. Of the seven TACK components, only the Sentinel Hash-Chain in sentinel_os exists today.

A pass here means no detectable leak at that sample size, on one 4-vCPU (virtual CPU) machine. It is never a proof. The same runs, plus a red-team pass, also show where the brief's design had to change.

### Mechanics

**The leak.** A token check that stops at the first wrong byte is called an early exit. On this machine, a guess wrong at byte 0 finished 22 to 24 ns sooner, at the median, than one wrong at byte 31.

An attacker who times many guesses learns how many leading bytes of the 32-byte token were right. The attacker then extends the guess one byte at a time.

The idea of the fix is a train that leaves on the timetable, not when the last passenger boards. The pad holds each reply until a fixed ceiling after the request was admitted, whatever the secret-dependent work did. A fast guess and a slow guess therefore leave at the same offset.

**One request, step by step.**

1. Read the monotonic clock and call it `start`. A monotonic clock only moves forward, unlike wall-clock time, which an operator or a time-sync service can reset.
2. Check public facts only: the halted flag, the input length, a free concurrency slot and the spin budget. A failed check returns at once with a fixed code that carries nothing from the input or the secret. An empty spin budget only switches the wait to Sleep.
3. Run the operation. This is the only secret-dependent step.
4. Read the clock again. Compute the bucket k: the smallest whole number for which k times the ceiling reaches the completion time. On time is k = 1.
5. Wait until `start + k * ceiling`, then return the reply. The pad never releases early.

**Three ways to wait.** Figures come from the three release runs at a 300 microsecond (us) ceiling. "Late" is release time minus target, measured idle, and p50 is the median; p99 is the time 99 percent of replies beat.

| Wait mode | How it waits | CPU per request | Late at p50, idle | Weak point |
|---|---|---|---|---|
| Sleep | Asks the operating system to wake the thread at the target | 28 to 30 us | 97 to 126 us | The scheduler sets the wake-up time, and cache state left by the work can nudge it |
| Spin | Busy-waits: loops reading the clock instead of giving up the CPU | 306 to 308 us | 0.11 to 0.13 us | Burns a core for the whole wait; paused by the scheduler when CPUs are oversubscribed |
| Hybrid | Sleeps until the target minus a short tail, then spins the tail (150 us here) | 100 to 104 us | 0.12 to 0.15 us | Late whenever the sleep overshoots the tail |

**Overruns.** An overrun is work that ends after the ceiling. The hard ceiling is the ceiling times `hard_ceiling_buckets`, default 4.

Up to the hard ceiling, the value is released at the next whole multiple of the ceiling. Past it, the value is dropped and a RETRY leaves on the retry window W: 16 hard ceilings, or 64 ceilings, by default.

```text
time from admission:  0        C        2C       4C = hard ceiling          64C = W
on time, k = 1        [work][wait]|
overrun, k = 2        [work..........][wait]|
hard overrun, k > 4   [work.............................][drop][wait.......]|  RETRY
```

The rounding is one small function, from `src/wait.rs`:

```rust
pub fn release_bucket(elapsed: Duration, ceiling: Duration) -> u64 {
    let c = ceiling.as_nanos().max(1);
    let k = elapsed.as_nanos().div_ceil(c).max(1);
    u64::try_from(k).unwrap_or(u64::MAX)
}
```

**Trips and their CNS outcomes.** A trip is a refusal. Each maps to the vocabulary of the CNS contracts package: PASS, RETRY (repairable; the caller may resubmit) or TERMINAL_BREACH (no resubmission repairs it).

| Trip | When | CNS outcome | Resolution | Why |
|---|---|---|---|---|
| `SlotsFull` | All `max_concurrent` slots are held | RETRY | reject | Load, not a fault. It is refused before any secret work and returned at once, so the fast reply reflects load only. |
| `InputTooLarge` | Input longer than `max_input_len` | RETRY | reject | The sender already knows the length. A shorter input can pass. |
| `Overrun` | Work ended past the hard ceiling | RETRY | reject | The late value is discarded, so nothing changed. The reply leaves on the retry window, never at the completion time. |
| `ClockFailure` | The clock went backwards, stopped, or overflowed | TERMINAL_BREACH | halt | Padding means nothing without a trustworthy clock. The pad refuses all work until an operator calls `reset()`. |
| `Halted` | Any request after a clock failure | TERMINAL_BREACH | halt | The same halt, held until operator reset. |
| `TimerUnavailable` | Async call on a tokio runtime without its timer | TERMINAL_BREACH | reject | A deployment error that resubmitting cannot fix. The pad itself is healthy, so it does not halt. |

Two events are not trips, and both are counted. An overrun inside the hard ceiling is served as PASS at bucket k. An empty spin budget is served as PASS in Sleep mode.

Quarantine and rollback are not used, because the pad keeps no per-sender state to isolate and no data to restore. The pad sees only bytes and their length, so checking for malformed input is the caller's job. A bad `CeilingConfig` fails at construction with `ConfigError`, and out-of-range values are never clamped.

### Pros and cons

**Verdict on the brief's design.** The brief's core rule held: releasing at admission plus a fixed ceiling left no detectable early-exit gap in any release run. Three other parts did not survive testing as written.

1. **Overrun rounding still leaked.** The brief rounds a late reply up to the next ceiling multiple. In red-team tests, 8 work times gave 8 distinct release times, and a slow destructor (cleanup code for a discarded value) added 8.1 ms.
2. **The fix released the RETRY later than the analysis asked.** The ANC analysis wants an overrun RETRY to leave at the ceiling. A blocking worker cannot be stopped mid-task, so the code drops the value and releases at 64 ceilings by default.
3. **The flood rules bound CPU, not service.** At 4 to 10 times the admission capacity, a legitimate client finished as few as 1 of 45 requests. Across all 9 flood runs, it succeeded on the first try once.

The brief's claim that every response leaves at the same offset held at the median: Spin and Hybrid class medians sat within 4 ns. At p99.9, the time 99.9 percent of replies beat, replies took 0.93 to 2.03 ms against a 300 us ceiling. Scheduler stalls caused that tail, and they hit both classes alike.

| Approach | Pros | Cons |
|---|---|---|
| Ceiling padding as a whole | Release time does not depend on how long the work took. There is no adaptive target, so no bits leak through target changes. It wraps code that cannot be made constant time. | Every reply pays the full ceiling: the median went from 40 to 65 ns of work to about 301 us. Work past the ceiling leaks. There is no default ceiling, so each operation needs its own measured one. |
| Sleep | Uses almost no CPU: 28 to 30 us per request. Under flood it cost 0.011 to 0.042 cores inside the pad. | 97 to 126 us late at p50, so the median reply took 398 to 407 us. Class medians differed by 154 to 274 ns, which no test flagged. |
| Spin | Most precise when idle: 0.11 to 0.13 us late at p50. | Burns the whole wait: 306 to 308 us of CPU per request. Without a budget a flood takes about one core per slot. Late by 1.1 ms at p99 under an unpinned flood. |
| Hybrid (recommended) | Spin-grade precision at a third of the CPU: 0.12 to 0.15 us late at p50 for 100 to 104 us of CPU. The budget held flood CPU to 0.15 to 0.18 cores inside the pad. | Late when the sleep overshoots the tail. A flood can drain the budget and force Sleep: 2,397 of 5,457 replies fell back in the unpinned run. |

### Recommended Rust pattern

Use one `CeilingPad` per protected operation, shared across threads with `Arc`, Rust's shared-ownership pointer. Choose the ceiling above the operation's worst-case time on the target host, use Hybrid mode, and keep the spin budget limited.

The order of events inside the pad is the reusable pattern. Read the clock before anything secret happens, admit on public facts, run the work, then wait for a time computed from `start` alone. From `src/pad.rs`:

```rust
    fn run_blocking<T>(
        &self,
        input_len: Option<usize>,
        op: impl FnOnce() -> T,
    ) -> (PadResult<T>, Event) {
        let start = self.clock.now();
        let adm = match self.admit(start, input_len, false) {
            Ok(a) => a,
            Err(trip) => return (Err(trip), self.early(start, trip)),
        };
        let value = op();
        let completion = self.clock.now();
        let tail = self.config.spin_tail;
        let (value, waited) = match self.plan(start, completion) {
            Ok((target, k, true)) => {
                let w = wait::wait_blocking(&self.clock, target, adm.mode, tail);
                (Some(value), w.map(|()| (k, true)))
            }
            Ok((_, _, false)) => {
                // Hard overrun: drop the discarded value inside the padded
                // time, then release on the retry window.
                drop(value);
                let (mode, tail) = self.retry_wait(adm.mode, tail);
                let w = self
                    .retry_target(start, self.clock.now())
                    .and_then(|(target, k)| {
                        wait::wait_blocking(&self.clock, target, mode, tail).map(|()| (k, false))
                    });
                (None, w)
            }
            Err(e) => (Some(value), Err(e)),
        };
        self.conclude(start, adm, value, waited)
    }
```

Three lines carry the red-team fixes. `drop(value)` runs before the wait, so a slow destructor is absorbed by the padding instead of added after it. `retry_target` rounds up to the retry window, and `retry_wait` never spins longer than the charge reserved at admission.

`conclude` reads the release time first; only then does the slot go free and telemetry run. The async API, `pad_async`, serves code built on tokio, Rust's common async runtime, and follows the same order. It also cancels the work at the hard ceiling, and treats work that finished late before the timer fired as the same hard overrun.

| Field | Default | Accepted range | Recommendation |
|---|---|---|---|
| `ceiling` | None; required | 1 us to 10 s | Above the worst-case work time, measured on the target host |
| `mode` | Hybrid | Sleep, Spin, Hybrid | Hybrid |
| `spin_tail` | 250 us | 0 to 10 s | Cover the host's blocking sleep lateness at p99 |
| `async_spin_tail` | 2.5 ms | 0 to 10 s | Longer than tokio's 1 ms timer tick |
| `spin_budget` | 250 ms of spin per second, 50 ms burst | Each up to 64 s; burst at least one request's charge | Keep it limited; `Unlimited` is for experiments only |
| `max_concurrent` | 64 | 1 to 65,536 | At or below the CPU count when using Spin |
| `hard_ceiling_buckets` | 4 | 1 to 1,024 | 1 for secret-heavy operations |
| `retry_release_factor` | 16 | 1 to 64 | Lower it to trade overrun margin for capacity |
| `max_input_len` | 64 KiB | 0 to 64 MiB | The smallest size the protocol allows |

For secret-heavy operations, set `hard_ceiling_buckets = 1` and call `pad_async`, which can cancel slow work. Run `CeilingPad::check_async_runtime()` once at startup so a runtime without tokio's timer is caught before traffic arrives.

### Anti-DoS mitigation

Padding holds every request for the whole ceiling, and Spin burns a core while it does. Without limits, a flood of cheap failing guesses would buy expensive waiting on the server. Three limits stop that, and the measured result is that they bound server CPU but not fairness.

1. **A concurrency cap.** A non-blocking counting semaphore, which is a counter of free slots, admits at most `max_concurrent` requests. There is no queue: a request takes a slot now or is shed with RETRY before any secret work.
2. **A spin budget.** This is a token bucket: a counter of spin nanoseconds that refills at a fixed rate up to a cap. Each request reserves a fixed charge at admission, and a request the bucket cannot cover sleeps instead of spinning.
3. **A fixed ceiling.** The ceiling comes from configuration only, and no request field can change it.

The charge is the ceiling for Spin and the tail for Hybrid, whatever the work later takes. It is never refunded, so whether a request spins depends on how many requests arrived, not on the secret. From `src/config.rs`:

```rust
fn charge(mode: WaitMode, ceiling: Duration, tail: Duration) -> Duration {
    match mode {
        WaitMode::Sleep => Duration::ZERO,
        WaitMode::Spin => ceiling,
        WaitMode::Hybrid => tail.min(ceiling),
    }
}
```

Admission checks run in a fixed order, all on public facts, before the operation is called. From `src/pad.rs`:

```rust
    fn admit(
        &self,
        start: Instant,
        input_len: Option<usize>,
        async_api: bool,
    ) -> Result<Admitted<'_>, Trip> {
        if self.is_halted() {
            return Err(Trip::Halted);
        }
        if input_len.is_some_and(|n| n > self.config.max_input_len) {
            return Err(Trip::InputTooLarge);
        }
        let permit = self.slots.try_acquire().ok_or(Trip::SlotsFull)?;
        let charge = if async_api {
            self.config.async_spin_charge()
        } else {
            self.config.spin_charge()
        };
        let (mode, reserved, fallback_from) = if self.budget.try_reserve(charge, start) {
            (self.config.mode, charge, None)
        } else {
            (WaitMode::Sleep, Duration::ZERO, Some(self.config.mode))
        };
        Ok(Admitted {
            _permit: permit,
            mode,
            reserved,
            fallback_from,
        })
    }
```

**The flood test.** Attacker threads sent fast-failing guesses for 3 s per configuration at a 1 ms ceiling. Runs 1 and 2 were pinned to one CPU with 2 threads and 1 slot; run 3 had 4 CPUs, 8 threads, 2 slots.

Offered load was 4.0 to 4.5 times admission capacity when pinned and 9.2 to 10.3 times unpinned. A legitimate client sent a correct token every 5 ms and retried each request up to 200 times. Cells list runs 1, 2 and 3.

| Flood configuration | Served / shed | Spin reserved vs budget bound | Legitimate requests completed |
|---|---|---|---|
| Spin, no budget | 2,920 / 9,908; 2,974 / 10,484; 5,647 / 49,814 | No bound | 9 of 51; 15 of 54; 38 of 60 |
| Hybrid, budget 250 ms/s plus 25 ms burst, tail 250 us | 2,919 / 9,036; 2,978 / 10,196; 5,457 / 56,744 | 0.730, 0.745 and 0.765 s vs 0.777 s | 8 of 46; 3 of 48; 67 of 82 |
| Sleep | 2,698 / 9,617; 2,724 / 10,067; 5,110 / 55,844 | None reserved | 1 of 45; 2 of 47; 50 of 71 |

Reserved spin stayed under the bound, which is the rate times wall time plus the burst. In the pinned runs the single slot already limited spin to the budget rate, so no request fell back. Only the unpinned run made the budget act.

The cap is first come, first served. A flood thread that was just served resubmits at once and usually wins the free slot, so the legitimate client is starved. Per-sender quotas or quarantine must come from an upstream component, and which component owns that is an open decision.

Every metric carries a closed `strategy="ceiling"` label, and every other label comes from a closed enum. These rules are from the crate docs and the build record; the spin threshold uses the default budget, summed over pads:

```yaml
groups:
  - name: tack-anc-ceiling
    rules:
      - alert: TackAncCeilingShedSustained
        expr: sum(rate(tack_anc_shed_total{strategy="ceiling",reason="slots_full"}[1m])) > 0
        for: 5m
        labels: {severity: warning}
      - alert: TackAncCeilingSpinOverBudget
        expr: sum(rate(tack_anc_spin_reserved_nanoseconds_total{strategy="ceiling"}[5m])) / 1e9 > 0.25 + 0.05 / 300
        for: 10m
        labels: {severity: warning}
      - alert: TackAncCeilingOverrun
        expr: increase(tack_anc_overrun_total{strategy="ceiling"}[15m]) > 0
        labels: {severity: warning}
      - alert: TackAncCeilingHalted
        expr: max(tack_anc_halted{strategy="ceiling"}) > 0
        labels: {severity: critical}
```

### Verification harness

The test sends two classes of guess. Class A is wrong at byte 0, the fastest exit; class B is wrong only at byte 31, the slowest wrong path. Classes are drawn at random from a recorded seed and interleaved, so drift in CPU speed hits both alike.

Each sample is timed from the pad call to its return, which is what a client sees. A Welch t-test asks whether two groups have different average times, without assuming equal spread.

The harness also runs that test on cropped data, with slow outliers above a percentile removed. It runs it on squared deviations too, which compares spread. A leak is called when the largest of these |t| values exceeds 4.5.

A Kolmogorov-Smirnov (KS) test, which compares the whole shape of two distributions, is reported beside it. Before any padded run, the same harness must flag the unpadded leaky check and pass a constant-time control. That calibration step shows the instrument can see the leak it is looking for.

| Layer | Runs in CI | Build | n per class | What it checks |
|---|---|---|---|---|
| `tests/leak.rs` | Yes, in `cargo test --all-targets` | Debug | 20,000 | Calibration, then Spin at a 50 us ceiling; about 2.4 s |
| `tests/behaviour.rs`, `tests/redteam.rs`, `tests/telemetry.rs` | Yes | Debug | Not statistical | Never early, overrun rounding, drop cost absorbed, budget fallback, shedding, metrics firing under a test recorder |
| `examples/verify.rs` | No; CI only compiles it | Release | 100,000 | The reported numbers below; about 4 minutes per run |

The CI guard's assertions follow, from `tests/leak.rs`; crops are held to the looser line of 10 used by dudect, a published timing-test tool. Debug-build timings are a regression guard, not evidence.

```rust
    let t_raw = padded.t_raw.unwrap().abs();
    let t2 = padded.t_second_order.unwrap().abs();
    let crop_max = padded
        .cropped
        .iter()
        .filter_map(|c| c.t)
        .fold(0.0f64, |m, t| m.max(t.abs()));
    assert!(t_raw < T_THRESHOLD, "first-order leak: {padded:?}");
    assert!(t2 < T_THRESHOLD, "second-order leak: {padded:?}");
    assert!(crop_max < CROP_LINE, "cropped leak: {padded:?}");
    assert!(padded.a.median.unwrap() >= 50_000.0);
```

**Measured results on this machine.** One 4-vCPU virtual machine, CPU model string "Intel(R) Xeon(R) Processor @ 2.10GHz", load average 0.1 to 0.9. All runs used the verify defaults: 300 us ceiling, 150 us Hybrid tail and seed 0x7ac4ce11, with no spin budget in the leak runs.

Runs 1 and 2 were pinned to one CPU with `taskset`; run 3 was an unpinned extra run on 4 CPUs. Each cell lists runs 1, 2 and 3. CPU under flood is thread CPU inside pad calls, with whole-process CPU in brackets.

| Configuration | n per class | max \|t\| | detected? | CPU under flood |
|---|---|---|---|---|
| Unpadded `leaky_validate` (calibration) | 100,084 A, 99,916 B | 668.5, 784.8, 771.6 | Yes, 3 of 3 (intended) | Not run: no pad |
| Unpadded `ct_validate` (control) | 100,084 A, 99,916 B | 1.65, 1.24, 1.54 | No, 0 of 3 | Not run: no pad |
| Padded, Sleep | 100,084 A, 99,916 B | 1.42, 2.73, 2.70 | No, 0 of 3 | 0.013, 0.011, 0.042 cores (0.106, 0.095, 0.49) |
| Padded, Spin (flood with no budget) | 100,084 A, 99,916 B | 1.23, 1.86, 1.37 | No, 0 of 3 | 0.92, 0.92, 1.74 cores (0.995, 0.994, 2.15) |
| Padded, Hybrid (flood with budget) | 100,084 A, 99,916 B | 1.30, 2.36, 2.93 | No, 0 of 3 | 0.15, 0.18, 0.18 cores (0.245, 0.248, 0.63) |

Across the 9 padded runs, second-order |t| was at most 1.26, and KS p was 0.044 or higher. The calibration leak came from the 50th-percentile crop each time; the uncropped |t| alone ranged from 1.5 to 16.8.

Overruns were rare: 9 released late and 3 RETRYs in 1.8 million padded requests. The checked work takes 40 to 65 ns at the median, so these came from scheduler stalls, not from the work.

**Red team and test status.** A red-team pass wrote 17 attack tests against the first build: 9 broke it, 1 partly broke it, and 7 held. The fixes made all 9 pass, though rt04 is now flaky.

One pre-existing async test had its upper bound raised from 50 ms to 300 ms for the new retry window. My final re-run of `cargo test -p tack-anc-ceiling --all-targets` ended with this summary line:

```text
test result: FAILED. 15 passed; 2 failed; 0 ignored; 0 measured; 0 filtered out; finished in 2.66s
```

The failures were rt10, the open finding below, and rt04. Over 12 full runs, rt10 failed every time. The fix record called the suite stable over 4 runs, but these runs were not.

Three timing tests failed intermittently on this shared host: rt04 in 3 of 12 runs, rt15 in 2, and `hard_overrun_is_retry_released_on_a_boundary_not_at_completion` in 2. Test rt15 hit an unplanned overrun, and in rt04's captured failures the later class switched between runs, with outliers up to 41.7 ms. The behaviour test passed 20 of 20 runs on its own.

The 10 unit tests, the leak guard and both telemetry tests passed every time they ran.

### What this does not guarantee

- **It is not a proof.** A pass means no detectable leak at about 100,000 per class on one virtual machine. The smallest mean shift these runs could flag was 1.9 to 4.7 us, about 80 to 210 times the 22 to 24 ns gap.
- **The stronger evidence is the design.** The release time is computed from `start` alone, and Spin and Hybrid class medians matched within 4 ns. Those two facts, not the t-test alone, carry the claim.
- **Sleep mode has an unexplained gap.** Its class medians differed by 154 to 274 ns, with class A later in all 3 runs. No test flagged it, and 3 runs cannot separate it from chance, so measure Sleep at a larger n before relying on it.
- **Work past the ceiling leaks.** Each overrun can reveal up to log2(H + 1) bits, where H is `hard_ceiling_buckets`, while work plus drop ends inside W. In the blocking API, each further W of work time t adds one more release time: log2(H + ceil(t / W)) bits.
- **Other clients can see an overrun.** An overrunning request holds its slot longer, so a probe that arrives meanwhile is shed. Red-team test rt10 shows this and still fails; it is documented, not fixed.
- **A RETRY is visible as content.** An overrun RETRY reads differently from a value. It is counted, not hidden.
- **Service under flood is not protected.** The cap bounds CPU but lets the flood starve legitimate clients.
- **Two paths were never leak-tested.** The t-tests used an unlimited spin budget, so replies served during a budget fallback were not measured. The async API was measured for precision only, and its Sleep mode was 1.17 to 1.18 ms late at p50.
- **Telemetry runs inside the visible time.** Metrics and logs run after the release time is read but before the call returns, adding a few nanoseconds that differ by outcome. With debug logging on, the input's SHA-256 is computed there too, costing time by input length, which the sender already knows.
- **The debug digest is unkeyed.** A low-entropy input such as a token guess can be recovered from its SHA-256 by dictionary search. Keep debug logs off, or private, on secret-bearing paths.
- **The threat model has edges.** Attackers on the same physical core, through its cache or a sibling hardware thread (SMT), are out of scope. The metrics endpoint must stay private, because the overrun and fallback counters describe load.
- **Timer detection can abort.** `TimerUnavailable` is detected by creating a timer inside `catch_unwind`, so a `panic = "abort"` build aborts instead of returning the trip.
- **These numbers describe one host.** Rerun `examples/verify.rs` on the target machine before choosing a ceiling or a mode.
