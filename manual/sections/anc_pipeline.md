## ANC strategy 3: instruction-level pipeline padding

The brief's padding design leaked in 9 of 9 release measurements, while the branch-free compare showed no detectable leak in 12 of 12.

*New design: reference implementation compiled and tested on Rust 1.94*

ANC (Active Timing Cancellation) is the kernel's defence against attackers who learn secrets from how long replies take. This crate, `tack-anc-pipeline`, is a new design that is not deployed anywhere. Of the seven TACK components, only the Sentinel Hash-Chain exists today.

Each measurement timed 100,000 guesses in each of two classes. A max |t|, the test statistic explained below, above 4.5 counts as a detected leak. A pass means no detectable leak at that n on one machine; it is never a proof.

### Mechanics

**The leak.** A server checks a 32-byte secret token. The simplest check compares byte by byte and stops at the first wrong byte, which is called an early exit. A guess wrong at byte 0 is therefore answered a little sooner than one wrong at byte 31.

An attacker who times many guesses learns how many leading bytes were right. That cuts the search from 2^256 possible tokens to about 256 guesses per byte, one byte at a time.

**Where strategy 3 acts.** Strategies 1 and 2 pad up: they hold every reply until a clock target, whatever path the check took. Strategy 3 works at the source instead, in the instructions the CPU runs for each guess. The ANC analysis says strategy 3 "makes the paths identical", and the measurements show that holds only for `constant_time`.

Picture two runners who leave a checkpoint by different routes. Pad-up holds both at the finish line until a fixed time.

The brief's design adds laps on a side track, so both routes have equal step counts. `constant_time` removes the fork, so there is only one route. Equal step counts turned out not to mean equal time, because the side track has different ground.

**Three validators.** The crate builds three versions of the same check and measures them side by side. A branch is a point where the CPU picks its next instruction based on a value. When that value comes from the secret, the choice can show up in timing.

| Validator | Work on a guess first wrong at byte i | Branches on secret data | Role |
|---|---|---|---|
| `early_exit` | i + 1 compare steps, then stop | Yes, one per byte | Leaky baseline, measurement only |
| `balanced_dummy` | i + 1 compare steps, then 31 minus i dummy steps, so 32 steps on every path | Yes | The brief's design, measurement only |
| `constant_time` | All 32 byte pairs, then one decision at the end | No | The default and the only production choice |

All three are meant to give the same answer for every input. That is property-tested: five properties at 512 random cases each, two of them through the gate.

**The brief's design in code.** A guess first wrong at byte `i` runs `i + 1` real steps. A filler loop then runs the other `31 - i`. From `src/validators.rs`:

```rust
#[inline(never)]
pub fn balanced_dummy(expected: &[u8; TOKEN_LEN], candidate: &[u8; TOKEN_LEN]) -> bool {
    let mut i = 0;
    while i < TOKEN_LEN {
        probe::real_step();
        if black_box(expected[i]) != black_box(candidate[i]) {
            dummy_block(TOKEN_LEN - 1 - i);
            return false;
        }
        i += 1;
    }
    true
}
```

The filler follows, also from `src/validators.rs`. `core::hint::black_box` tells the compiler to assume a value is used. Without it, the compiler sees that nothing reads the filler's result and deletes the loop.

```rust
#[inline(always)]
fn dummy_block(steps: usize) {
    let steps = steps.min(MAX_DUMMY_STEPS);
    let mut hits: u8 = 0;
    let mut j = 0;
    while j < steps {
        probe::dummy_step();
        // Two values forced through memory, like the two token bytes of a
        // real step, then a compare, like the real comparison. Neither
        // value depends on the previous step, so, like the real steps, the
        // iterations can overlap in the pipeline.
        let x = black_box(j as u8);
        let y = black_box(!x);
        if x == y {
            hits = hits.wrapping_add(1);
        }
        j += 1;
    }
    black_box(hits);
}
```

**Why equal counts are not equal time.** A CPU core is a pipeline: an assembly line that works on several instructions at once. It also guesses ahead at branches. Time depends on how smoothly that line flows, not only on how many instructions pass through it.

| Effect | What it means | How the dummy path differs |
|---|---|---|
| Branch prediction | The core guesses each branch and runs ahead. A wrong guess throws away about 15 to 20 cycles of work. | The exit branch and the dummy loop's trip count both depend on where the wrong byte is. |
| Dependency chains | Independent instructions run side by side, so time follows the longest chain of instructions that wait on each other. | A first filler carried one value from step to step. Its 31 steps took about 70 ns, against about 27 ns for 31 real steps. |
| Cache and TLB | Recently used memory, and recently used address translations (the TLB, or translation lookaside buffer), are faster to reach again. | Real steps read the token buffers; dummy steps touch only the stack. |
| Variable-latency instructions | On some cores, divide and some multiplies finish sooner for small values. | The filler avoids them and uses only NOT, add, compare and stack traffic. |
| Instruction mix and SMT | Loads and arithmetic use different execution ports. A sibling hardware thread (SMT, simultaneous multithreading) shares those ports. | The dummy step swaps token loads for stack stores, so it contends differently. |

That first filler made the fast-fail path the slow one, so it leaked in the reverse direction. The final filler was tuned in two rounds against the disassembly, which is the machine code read back from the compiled binary.

In the final release binary both loop bodies are 11 instructions, with no step-to-step chain and no multiply or divide. The function still has 4 conditional branches, and it was still detected in every measurement.

**The gate around the validator.** Every check goes through a `PipelineGate`, which runs the cheap, public checks first. It rejects any input that is not exactly 32 bytes from the length alone, before reading a byte. It then takes one of a capped number of in-flight slots, runs the validator, gives the slot back and emits telemetry.

Every trip maps to the CNS outcome RETRY (repairable: the caller may resubmit) with the resolution reject (nothing changed).

| Trip | Cause | CNS outcome | Resolution | Why |
|---|---|---|---|---|
| `InputTooLarge` | More than 32 bytes | RETRY | reject | Decided from the length alone, so a gigabyte input costs one integer compare. The sender already knows the length. |
| `Malformed` | Fewer than 32 bytes | RETRY | reject | Decided from the length alone. Sending 32 bytes repairs it. |
| `SlotsFull` | In-flight count already at `max_in_flight` | RETRY | reject | Load shedding before any secret work. The caller may retry later. |
| `Mismatch` | 32 bytes, wrong value | RETRY | reject | The caller may resubmit the right token. The reply is a fixed code that never names the wrong byte. |

No trip yields TERMINAL_BREACH, quarantine, rollback or halt. The gate keeps no state except an in-flight counter that each request restores, so there is nothing to isolate or restore. Isolating a sender who keeps guessing belongs upstream, for example in TACK Inlet, and which component owns it is an open decision.

No decision reads the clock, so the kernel's "clock unavailable" trip cannot arise. There is no ceiling and no adaptive controller either, so "ceiling overrun" and "leakage budget spent" do not exist here.

Bad configuration fails when the gate is built, never on a request. `PipelineGate::new` refuses a `max_in_flight` of 0 or above 65,536, and a leaky validator unless `allow_leaky_validators` is set. `TokenSecret::from_bytes` refuses a wrong-length or all-zero secret, and no default key exists.

### Pros and cons

**Verdict on the brief's design.** Equal instruction counts did not give equal time on this machine, so the brief's premise does not hold here. Ship `constant_time`, and keep `balanced_dummy` only as a measured counterexample.

| Approach | Pros | Cons |
|---|---|---|
| `balanced_dummy` (the brief's design) | Keeps the familiar early-exit shape. Equal step counts are easy to check: a unit test counts 32 steps on every path. | Detected in 9 of 9 measurements (max \|t\| 89 to 192). Without `black_box` the filler is deleted and the full leak returns (max \|t\| 926 to 947). Adds 27 to 28 ns of bare median time to every byte-0 failure. Its shed rate also tracks the secret. |
| `constant_time` (recommended) | No detectable leak in 12 of 12 measurements (max \|t\| 0.56 to 2.60). The release code has 12 instructions, no conditional branch and no loop. Fastest bare validator measured: 32 ns median, against 39 to 61 ns for `early_exit`. | The no-branch property belongs to one binary, and a compiler or target change can undo it. Not formally verified. Every call pays the full 32-byte cost, which is small here. |
| Strategy 3 as a whole, against pad-up | No padding target, no clock in the decision and no controller whose state can leak. The reply leaves at decision time, so no padding delay is added. No loop an attacker can stretch. | Covers only the code it controls; the network stack, allocator and metrics exporter need their own checks. Must be re-measured after every compiler upgrade. Telemetry runs inside the timed window. |

### Recommended Rust pattern

Use `constant_time`, and call it only through the gate. The pattern has three parts: a branch-free compare, a gate that checks length first, and a config whose default is the safe validator.

The compare comes first, from `src/validators.rs`. `subtle` is a Rust crate for constant-time operations. Its `Choice` type carries a yes-or-no answer as a byte, so callers are not tempted to branch on it early.

```rust
#[inline(never)]
pub fn constant_time(expected: &[u8; TOKEN_LEN], candidate: &[u8; TOKEN_LEN]) -> Choice {
    let mut diff: u8 = 0;
    let mut i = 0;
    while i < TOKEN_LEN {
        probe::ct_step();
        diff |= expected[i] ^ candidate[i];
        i += 1;
    }
    diff.ct_eq(&0u8)
}
```

The loop always runs 32 times. XOR gives zero for equal bytes, OR gathers any difference into one byte, and `ct_eq` makes the single decision at the end. The only index is the loop counter, so the memory addresses touched do not depend on the secret either.

The release build has no conditional branch. It turned the loop into two 16-byte vector compares, a mask and one `sete` (set a byte from a flag).

The listing is `objdump` output recorded by the verify example in run 1. Runs 2 and 3 reported the same address and counts.

```text
700f0: movdqu (%rdi),%xmm0
700f4: movdqu 0x10(%rdi),%xmm1
700f9: movdqu (%rsi),%xmm2
700fd: pcmpeqb %xmm0,%xmm2
70101: movdqu 0x10(%rsi),%xmm0
70106: pcmpeqb %xmm1,%xmm0
7010a: pand   %xmm2,%xmm0
7010e: pmovmskb %xmm0,%eax
70112: xor    %edi,%edi
70114: xor    $0xffff,%eax
70119: sete   %dil
7011d: jmp    *0x7dab5(%rip)        # edbd8 <_DYNAMIC+0x6a8>
```

The final `jmp` is an indirect tail call, which the example identifies as `subtle`'s `black_box`; it is not a branch on data. The `Choice` becomes a `bool` in one place, `Validator::run`, because the decision is the reply itself.

The gate comes second, from `src/gate.rs`. The cheapest and most public checks run first, and the secret is touched only by the validator call at the end.

```rust
    fn decide(&self, candidate: &[u8]) -> CheckResult {
        if candidate.len() > TOKEN_LEN {
            return Err(Trip::InputTooLarge);
        }
        let Ok(token) = <&[u8; TOKEN_LEN]>::try_from(candidate) else {
            return Err(Trip::Malformed);
        };
        let Some(_slot) = self.try_slot() else {
            return Err(Trip::SlotsFull);
        };
        if self.config.validator.run(self.secret.bytes(), token) {
            Ok(Accepted)
        } else {
            Err(Trip::Mismatch)
        }
    }
```

The config comes third, also from `src/gate.rs`. The default is the safe validator, and `validate` refuses `EarlyExit` or `BalancedDummy` unless `allow_leaky_validators` is set.

```rust
impl Default for PipelineConfig {
    fn default() -> Self {
        Self {
            validator: Validator::ConstantTime,
            allow_leaky_validators: false,
            max_in_flight: DEFAULT_MAX_IN_FLIGHT,
            record_response_time: true,
        }
    }
}
```

The same idea already exists in sentinel_os. Its `api_key_auth.py` compares keys with Python's `hmac.compare_digest` and never exits early, but that code has not been measured with this harness.

**Telemetry.** The gate emits `tack_anc_requests_total`, `tack_anc_shed_total`, `tack_anc_token_mismatch_total`, `tack_anc_leaky_validator_active` and `tack_anc_response_seconds`. Every label comes from a closed enum, and each check opens one debug span, `tack.anc.pipeline_check`.

Debug logs carry the input length, plus the full SHA-256 hex for inputs within the 32-byte cap; raw input is never logged. Hashing 32 bytes costs the same for every value, so it adds no class-dependent time. A red-team test with debug logging and a live recorder on the path stayed at max |t| 1.81, in a debug build.

A gate built with a leaky validator sets the gauge (a metric that holds a current value) `tack_anc_leaky_validator_active` to 1. The critical alert `TackAncPipelineLeakyValidatorActive` fires on it. The red team found two ways this alert misses or goes stale, listed in the last subsection.

Two rules keep the telemetry from leaking. Metrics are emitted inside the window the client times, so their cost may depend only on the outcome and trip reason. The test `class_a_and_class_b_take_the_same_telemetry_path` checks this for guesses wrong at bytes 0 and 31.

No metric counts dummy steps. That count would equal 31 minus the position of the wrong byte, a direct leak to anyone who reads it.

### Anti-DoS mitigation

The brief's worry is that padding lets a flood of cheap failures buy expensive work. Strategy 3 has no padding loop and no padding target, so there is nothing an attacker can stretch. Each request costs a small, bounded amount: 218 to 282 ns of CPU through the gate when idle, for every validator.

| Control | Bound | What it stops |
|---|---|---|
| Length check before any byte is read | 32 bytes, a constant | Oversized input. A red-team test sent a 64 MiB input 20 times with debug logging on, and every check stayed under its 50 ms line. |
| In-flight slots | `max_in_flight`: default 64, allowed 1 to 65,536, refused outside that range rather than clamped | Unbounded concurrency inside the validator |
| Dummy-step cap (`balanced_dummy` only) | 31 steps per request, enforced by `steps.min(MAX_DUMMY_STEPS)` | A filler loop sized by the caller |
| No allocation sized by input | Only the 64-character digest, and only when debug logging is on | Memory growth from attacker-chosen sizes |

The slot counter uses one atomic compare-and-swap (CAS). A CAS reads a counter and updates it in one indivisible step, so two threads cannot both take the last slot. From `src/gate.rs`:

```rust
    fn try_slot(&self) -> Option<Slot<'_>> {
        let max = self.config.max_in_flight;
        self.in_flight
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |n| {
                if n < max {
                    Some(n + 1)
                } else {
                    None
                }
            })
            .ok()
            .map(|_| Slot(&self.in_flight))
    }
```

The red team ran 8 threads of 20,000 checks each against a cap of 2. A watcher thread never saw more than 2 in flight, and the counter returned to 0.

**The filler cannot be put on a budget.** Under `balanced_dummy`, every fast failure runs up to 31 dummy steps, at the attacker's choice. A budget that ran out would switch the filler off and make the fast path fast again. An attacker could flood until the budget was gone, then read the leak.

**Flood measurement.** The verify example ran 20 fast-fail threads and 1 legitimate client against `max_in_flight = 2`, for 2 seconds per validator. Every flood request is wrong at byte 0, the cheapest failure, and a shed request is retried at once. That is ten times the cap in concurrency, not ten times a rate.

| Run | Validator | CPU used | Requests per second | Shed | Legitimate client p99 |
|---|---|---|---|---|---|
| 1 / 2, pinned to 1 CPU | `early_exit` | 0.988 / 0.986 cores | 1.43 M / 1.67 M | 0 / 70,361 | 1,522 / 668 ns |
| 1 / 2, pinned to 1 CPU | `balanced_dummy` | 0.994 / 0.990 cores | 1.64 M / 1.59 M | 97,163 / 41,960 | 665 / 703 ns |
| 1 / 2, pinned to 1 CPU | `constant_time` | 0.991 / 0.994 cores | 1.70 M / 1.73 M | 0 / 0 | 658 / 582 ns |
| 3, unpinned, 4 CPUs | `early_exit` | 3.78 cores | 1.09 M | 173 | 294 µs |
| 3, unpinned, 4 CPUs | `balanced_dummy` | 3.86 cores | 1.22 M | 2,628 | 198 µs |
| 3, unpinned, 4 CPUs | `constant_time` | 3.79 cores | 1.21 M | 261 | 102 µs |

In every flood the shed and request metrics matched the observed outcomes exactly, and no slot leaked. The legitimate client never failed, and its mean attempts per success were at most 1.0007. Pinned shed counts were uneven (`early_exit` 0, then 70,361), which suggests scheduling: a thread preempted while it holds a slot.

**Verdict on the anti-DoS goal.** The gate bounds the cost of each request and the number in flight. It does not bound total CPU: the flood took the whole pinned core, and about 3.8 of 4 cores unpinned.

A shed request still costs a CAS and its telemetry, and flooders retry at once. Total CPU protection therefore needs a rate limiter or CPU quota in front of the gate.

CPU per request rose from 575 to 691 ns pinned to 3.1 to 3.5 µs unpinned. The flood ran with the test recorder installed globally, which takes a lock on every metric call. Contention on that lock and on the shared slot counter is the likely cause, but that is an inference that was not profiled.

**Shedding as a second channel.** A shed reply returns faster than a mismatch. For `constant_time` that reveals load, not the secret. A red-team probe that saw only reply codes stayed at |t| 1.87 or less over 14 runs.

For the leaky validators the shed rate tracks the secret, because slot hold time depends on where the guess goes wrong. The probe detected `early_exit` in all 14 runs. It detected `balanced_dummy` in 8 of 8 isolated runs, and in both re-runs here (t = -7.64 and -19.46).

Reading this channel needs no clock at all. The crate's `SlotsFull` docs and the ANC analysis both say a shed reflects load only, and that holds for `constant_time` alone.

### Verification harness

The harness asks one question: can a stopwatch tell two groups of guesses apart? Class A guesses are wrong at byte 0 and class B guesses are wrong at byte 31, the two ends of the leak.

Exactly 100,000 of each class are shuffled with a seeded generator. Inputs are built in batches of 1,024 outside the timed region, after 5,000 warm-up calls, so building them does not land in the measurement.

A Welch t-test asks whether two groups have different mean times, without assuming equal spread. Its |t| is the gap between the means in units of their noise.

The harness reruns it on only the samples below the 50th, 75th, 90th, 95th, 99th and 99.9th percentiles of both classes together. That cropping removes slow outliers such as interrupts.

A second-order test compares squared distances from the mean, which catches equal means with unequal spread. The verdict is the largest |t| of those eight tests, and above 4.5 is a leak that maps to TERMINAL_BREACH. Too few samples gives RETRY, never a pass.

A two-sample Kolmogorov-Smirnov (KS) test compares the whole shape of the two distributions. The ANC analysis also requires its p value to be at least 0.001 for a pass.

Calibration comes first. The harness must flag a known-leaky compare and pass a known constant-time one at the same n, or the run proves nothing.

Cropping matters in practice. For `early_exit` through the gate in run 1, the uncropped t was only 0.33 while the cropped t was 768. Rare slow outliers hid a clean 22 ns shift in the median.

| Layer | Where | Profile and n | Runs in `cargo test`? | Role |
|---|---|---|---|---|
| Smoke test | `tests/leak.rs` | Debug, 20,000 per class | Yes | Checks the setup works at that n: calibration, `early_exit` flagged, `constant_time` passes. Not evidence. |
| Red-team timing tests | `tests/redteam.rs` | Debug, 20,000 per class; the shed probe sends 1.5 million requests | Yes | Whether the number of differing bits matters, debug logging and a live recorder on the path, and the reply-code shed channel |
| Evidence run | `examples/verify.rs` | Release, 100,000 per class | Compiled, not run | Calibration, timing through the gate and bare, CPU cost, flood and disassembly, printed as one JSON document |

The smoke test's calibration gate, from `tests/leak.rs`:

```rust
    let lv = leaky.verdict(T_THRESHOLD);
    let cv = ct.verdict(T_THRESHOLD);
    assert!(
        lv.is_leak(),
        "calibration failed: leaky victim not flagged {lv:?}"
    );
    assert!(cv.is_pass(), "calibration failed: ct victim flagged {cv:?}");
```

The builder ran the smoke test ten times and all passed: `constant_time` max |t| 1.0 to 2.3, `early_exit` 386 to 540. Debug timings are not evidence, so the example refuses to run in a debug build.

**CI today, and the gap.** `cargo test --all-targets` runs the smoke and red-team tests, but it only compiles the example. The example prints JSON and exits 0 even when it finds a leak. CI therefore needs a separate release job that runs it and gates on its summary.

The gate below was run against the three recorded runs. It exited 0 on each, and exited 1 when `constant_time` was swapped for `balanced_dummy`.

```text
cargo run --release -p tack-anc-pipeline --example verify > verify.json
jq -e '.profile == "release" and .summary.evidence_valid
  and ([.summary.primary_gate.constant_time,
        .summary.primary_gate_with_debugging_recorder.constant_time,
        .summary.secondary_gate.constant_time,
        .summary.bare.constant_time] | all(.harness_gate_outcome == "PASS"))
  and .summary.constant_time_conditional_branches == 0' verify.json
```

A shared CI runner is noisier than this VM. The in-run calibration (`evidence_valid`) stops a run that could not see the known leak from counting as a pass.

**Measured results on this machine.** The host is an Intel Xeon at 2.10 GHz, a KVM virtual machine with 4 vCPUs. The build is release, with overflow checks on. The timer is `std::time::Instant` in nanoseconds, and the 1-minute load average stayed between 0.18 and 1.80.

Runs 1 and 2 were pinned to one CPU with `taskset`, a tool that restricts a process to chosen CPUs. Run 3 was an extra unpinned run, so the flood could use all 4 cores. Each cell lists run 1 / run 2 / run 3, and only the three gate rows were flooded.

| Configuration | n per class | max \|t\| | detected? | CPU under flood |
|---|---|---|---|---|
| Calibration: known-leaky compare | 100,000 | 757 / 827 / 796 | Yes, 3 of 3 | not flooded |
| Calibration: known constant-time compare | 100,000 | 1.04 / 0.94 / 1.29 | No, 0 of 3 | not flooded |
| `early_exit` through the gate | 100,000 | 768 / 698 / 714 | Yes, 3 of 3 | 0.988 / 0.986 / 3.78 cores |
| `balanced_dummy` through the gate | 100,000 | 89 / 118 / 94 | Yes, 3 of 3 | 0.994 / 0.990 / 3.86 cores |
| `constant_time` through the gate | 100,000 | 1.72 / 1.17 / 1.78 | No, 0 of 3 | 0.991 / 0.994 / 3.79 cores |
| `early_exit`, test recorder on the path | 100,000 | 357 / 324 / 329 | Yes, 3 of 3 | not flooded |
| `constant_time`, test recorder on the path | 100,000 | 2.08 / 1.39 / 1.28 | No, 0 of 3 | not flooded |
| `early_exit`, fixed versus random guess | 100,000 | 246 / 714 / 776 | Yes, 3 of 3 | not flooded |
| `balanced_dummy`, fixed versus random guess | 100,000 | 126 / 137 / 170 | Yes, 3 of 3 | not flooded |
| `constant_time`, fixed versus random guess | 100,000 | 2.02 / 2.60 / 0.56 | No, 0 of 3 | not flooded |
| `early_exit`, bare | 100,000 | 906 / 888 / 875 | Yes, 3 of 3 | not flooded |
| `balanced_dummy`, bare | 100,000 | 190 / 189 / 192 | Yes, 3 of 3 | not flooded |
| `balanced_dummy` without `black_box`, bare | 100,000 | 947 / 926 / 943 | Yes, 3 of 3 | not flooded |
| `constant_time`, bare | 100,000 | 1.72 / 1.66 / 2.36 | No, 0 of 3 | not flooded |

"Bare" means the validator alone, outside the gate. "Fixed versus random" is the pair used by dudect, a published leak-test tool: one fixed wrong guess against fresh random guesses. The test recorder is `metrics_util`'s `DebuggingRecorder`, which takes a lock on every metric call.

The smallest detectable shift below is the mean gap the uncropped test would just flag, given the measured noise.

| Configuration | Median A / B (ns) | Smallest detectable mean shift, uncropped (ns) |
|---|---|---|
| `early_exit` through the gate | 239 / 260 to 261 | 8.3 to 95.8 |
| `balanced_dummy` through the gate | 267 to 268 / 263 | 12.6 to 18.4 |
| `constant_time` through the gate | 239 to 240 / 239 to 240 | 8.3 to 17.0 |
| `early_exit`, bare | 39 / 60 to 61 | 3.3 to 10.3 |
| `balanced_dummy`, bare | 66 to 67 / 60 to 61 | 2.7 to 16.7 |
| `constant_time`, bare | 32 / 32 | 4.0 to 44.0 |

**What the numbers say.** Calibration passed in all three runs, so the method can see a leak on this machine. Every verdict matched across the three runs. The size of a detected |t| moved a lot, so treat the verdict as stable and the size as rough.

`balanced_dummy` overshoots. Bare, a guess wrong at byte 0 takes 66 to 67 ns, against 60 to 61 ns for byte 31. It became about 6 ns slower, where `early_exit` is about 21 to 22 ns faster.

Through the gate, that shift is 4 to 5 ns at the median, below the uncropped test's reach of 12.6 to 18.4 ns. On 8 of its 9 rows the uncropped t stayed under 4.5. The cropped tests caught it every time, at 89 to 192, with a KS p of 0.

Without `black_box` the filler is gone. `objdump` places `balanced_dummy_no_black_box` at the same address as `early_exit` (0x700a0), and it times like `early_exit`: 39 against 61 ns.

`constant_time` passed all 12 of its rows, and its lowest KS p was 0.049, above the 0.001 line. The test recorder added about 740 ns per check (medians 975 to 986 against 239 to 240 ns), and `constant_time` still passed with it.

The crate's own docs quote an earlier run on a 2.80 GHz VM, for example `balanced_dummy` at max cropped t 32.4. Its verdicts agree with the table above.

**Test suite status.** `cargo clippy -p tack-anc-pipeline --all-targets -- -D warnings` is clean, re-run for this section. With `--no-fail-fast`, the builder's 28 tests all pass: 15 unit, 5 equivalence, 1 flood, 1 leak, 1 logs and 5 telemetry.

The red team's 17 tests live in `tests/redteam.rs` in the same crate, and 6 of them fail on open findings. The brief's command therefore fails. Its final summary line, re-run for this section:

```text
test result: FAILED. 11 passed; 6 failed; 0 ignored; 0 measured; 0 filtered out; finished in 16.01s
error: test failed, to rerun pass `-p tack-anc-pipeline --test redteam`
```

Cargo stops at the first failing target, so `tests/telemetry.rs` did not run in that pass. Five red-team tests fail on every run. The `balanced_dummy` shed-channel test failed in both re-runs here and in 4 of the red team's 7 runs.

### What this does not guarantee

**Not a proof.** A pass means no detectable leak at 100,000 samples per class, on one VM. The uncropped test could miss a mean shift below about 8 to 17 ns through the gate.

**One binary.** The no-branch listing is static evidence for this x86_64 binary built by Rust 1.94. A compiler upgrade, or another target such as aarch64, can bring a branch back, so rerun the verify example after either.

Formal tools that could check the no-branch property, such as ct-verif and binsec/rel, are not available under the workspace's dependency rules. No formal verification was done.

**Only the compare.** The network stack, TLS, allocator and production metrics exporter were not measured. A production exporter's cost per call is unknown; the test recorder added about 740 ns.

**Not against neighbours.** An attacker on the same physical core, or sharing its cache, is out of scope. That needs isolation, not a code shape.

**The metrics endpoint must stay private.** For a leaky validator, `tack_anc_response_seconds` is a histogram of the leak. Whether that histogram should default to off for this strategy is an open question.

**Not rate limiting, lockout or replay protection.** The token is a static bearer token: whoever presents it gets in. The gate keeps no per-sender state, so a captured token replays forever. Those controls belong to the layer that issues and carries the token, such as TACK Inlet.

**Not total CPU protection.** The gate caps the cost of each request and how many run at once. A flood still takes every core it is allowed.

**Open findings.** `balanced_dummy` should stay only as a measured counterexample, never a production option. The fix step was skipped because no finding was a blocker or major, so six minor red-team findings remain open.

| Open finding | Effect | Proposed fix |
|---|---|---|
| An all-0xFF secret is accepted | Any repeated-byte or low-entropy key is accepted; only all zeros is refused. | Refuse a secret whose 32 bytes are all the same value, compared with `ct_eq`. Document that entropy is the key generator's job. |
| The debug log carries the unkeyed SHA-256 of the secret on every PASS | A log reader can test guesses offline, with no rate limit or alert. That is infeasible for a random 256-bit token but practical for a weak one. | Log HMAC-SHA256 under a random per-process key, or omit the digest on PASS. Add to convention 4: for credentials, log only a keyed digest. |
| The leaky gauge is missed when the recorder starts after the gate | The critical alert never fires. | Set the gauge on every check, or add a publish step to run after the exporter starts. Add an `absent()` alert. |
| The leaky gauge never clears | The critical alert keeps firing after the leaky gate is gone, which trains operators to silence it. | Decrement the gauge when a leaky gate is dropped, so it counts live leaky gates. |
| The guessing alert divides by all requests | Two cheap malformed requests per guess cut the ratio to 0.333, under the 0.5 line, which is itself an unmeasured placeholder. | Divide by requests that reached the validator, and add an absolute-rate alert on mismatches. |
| The `SlotsFull` docs say a shed reflects load only | Wrong for both leaky validators, whose shed rate tracks the secret. | Correct the docs, and never pair a leaky validator with a small `max_in_flight`. |

`TokenSecret` zeroes its bytes on drop only on a best-effort basis. Without volatile writes or a zeroize crate, the compiler does not promise to keep the overwrite, and copies may remain in old stack frames.
