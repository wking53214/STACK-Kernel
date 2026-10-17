## ANC analysis: what can and cannot be cancelled

ANC cannot make the timing delta zero; the testable goal is no detectable difference at 100,000 samples per class (Welch |t| at most 4.5).

*New design: analysis only. No ANC code exists in the STACK repositories today. The tests it defines run in the stack-anc-harness crate, compiled and tested on Rust 1.94.*

### The problem ANC is meant to solve

A timing side channel is a leak where the time a server takes to answer reveals a secret. The textbook case is a token check that stops at the first wrong byte. A guess with a longer correct prefix takes slightly longer, so an attacker can recover the token one byte at a time.

The brief describes ANC (Active Timing Cancellation) as closed-loop feedback that forces "destructive interference" in execution time. Closed-loop feedback means a controller that measures recent runtimes and adjusts the padding it adds. The analysis below tests that idea against physics and the published work, then sets the yardsticks for the three strategies.

### Threat model

| Item | Assumption |
|---|---|
| Attacker capability | Sends any number of chosen requests over the network, and can flood. |
| What the attacker observes | The response and the time it arrives. Nothing else. |
| Secret | The expected token held by the validator. |
| Victim | A secret-dependent early-exit validator: a byte compare that returns at the first mismatch. |
| Attacker goal | Learn the length of the matching prefix from response time, then extend it byte by byte. |
| Out of scope | Attacker code on the same physical core (cache or SMT attacks), power and electromagnetic probes. These need isolation, not padding. |

Two assumptions carry weight. First, the attacker cannot read the kernel's metrics endpoint; a histogram of pre-padding work time would hand them the leak directly. Second, the flood is part of the threat, because ANC's own padding is something a flood can exploit.

### Why the delta cannot be driven to zero

**Time only adds.** In sound, destructive interference works because a wave swings both positive and negative, so two waves can cancel. Execution time has no negative swing: a server can add delay but never remove it.

Two levers remove the delta instead of blurring it: pad every path up to one observable time, or make the paths identical. Strategies 1 and 2 pad up; Strategy 3 makes the paths identical.

| Lever | How it works | What it costs | What still leaks |
|---|---|---|---|
| Pad up | Hold every response until a target time at or above the slowest path. | Latency: every fast path pays up to the slow path's time. | Overruns past the target, wake-up jitter, and any feedback in how the target is chosen. |
| Make paths identical | Constant-time code: no branch, memory address or variable-latency instruction depends on the secret. | CPU: every call does the full work. | Whatever the compiler or hardware adds back. |

Padding that sleeps also meets a floor, because the timer and scheduler wake the thread at an imprecise moment. The secret-dependent work just before the wait may also shift that moment, through cache and CPU frequency state. That residue has not been measured here, and nothing makes it zero.

**Feedback leaks.** A padding target computed from observed runtimes is a function of past secret-dependent timings. Each change in the target is visible in response times, so the controller's state becomes a channel of its own.

Askarov, Zhang and Myers (CCS 2010) bound this with epochs. An epoch is a stretch where the release schedule is fixed. It ends only when a response misses its predicted time, and a public rule, such as doubling the interval, sets the next schedule.

The attacker then learns little beyond when the epochs changed. Search-engine summaries of the paper give a bound of log² T bits over running time T for the doubling rule. The paper itself was blocked here, so its exact statement and constant are unverified.

Zhang, Askarov and Myers (PLDI 2012) build the same predictive idea into a programming language. Programs that pass its type checker leak only a bounded amount over time. That summary comes from the abstract as shown in search results; the paper was not opened.

The counting argument below does not depend on the unverified constant. It uses one fact: an observation with at most M possible values carries at most log2 M bits.

```text
Epoch form:   N target changes, each at one of R+1 request positions,
              each new target set by a public rule
              leak <= N * log2(R + 1) bits

Ladder form:  U scheduled updates at public times, each picking one of K public target levels
              leak <= U * log2(K) bits
              example: K = 16 levels, one update per minute
              leak <= 4 bits per minute = 5,760 bits per day (worst case)

Both forms assume every reply leaves exactly at the current target.
```

The example shows the tradeoff. An adaptive target turns a leak that grows with every request into a metered one, but the meter can still run high. The budget must be a configured number with an alert, not an assumption.

**Noise hides the delta; it does not remove it.** Residual variation comes from timer resolution, the scheduler, CPU frequency scaling, cache and branch predictor state, and SMT sibling contention. SMT (simultaneous multithreading) means two hardware threads sharing one core.

Noise that does not depend on the secret raises the number of samples an attacker needs, but it does not stop the attack. The tlsfuzzer timing guide tells testers to isolate cores, including hyperthread siblings, and warns that thermal throttling adds jitter. It also notes that a CPU frequency change shifts every measurement at once.

Crosby, Wallach and Riedi (ACM TISSEC 2009) measured how finely a remote attacker can time a server. Search results quoting their abstract give 15 to 100 microseconds across the Internet and as good as 100 nanoseconds on a LAN. The paper itself was blocked here.

Brumley and Boneh (USENIX Security 2003) extracted RSA private keys from an OpenSSL-based web server on a local network. That comes from search summaries of the abstract; the paper was blocked here.

The attack led to RSA blinding being turned on by default. Blinding mixes a random value into each private-key operation, so its time stops tracking the attacker's input. A 2020 replication attempt had not recovered a key when its log ends, even after switching back to the unblinded mod_ssl 2.8.12.

**Measurement cannot prove zero.** A statistical test either finds a difference or fails to find one at a given sample size. Failing to find one bounds the difference the test could see; it does not show the difference is absent.

### How leaks are detected

Detection compares two classes of requests, for example "mismatch at byte 0" and "mismatch at byte 31". The harness calibration uses dudect's fixed-versus-random pair instead: the correct token against random tokens. The Welch t-test asks whether two classes have different mean times without assuming equal spread; a large |t| means the means differ.

TVLA (Test Vector Leakage Assessment) is the industry method for side-channel testing that set the 4.5 line. A p value is the chance of seeing a difference this large if the two classes were really the same.

| Test | What it catches | Line used here | Source |
|---|---|---|---|
| First-order Welch t | Different mean times | \|t\| above 4.5 is a leak | TVLA (Goodwill et al., NIST workshop 2011, seen through search results); dudect source comment |
| Cropped first-order t | A mean difference hidden under slow outliers such as interrupts | Same 4.5 line; the harness crops at 50, 75, 90, 95, 99 and 99.9 percent | dudect source, which crops at 100 percentiles |
| Second-order Welch t | Same mean, different spread | Same 4.5 line | dudect source, which calls it the second order test |
| Two-sample Kolmogorov-Smirnov | Any difference in the shape of the two distributions | Reported beside the verdict; p below 0.001 is flagged for review | Standard statistics; not part of dudect or TVLA |

The harness verdict takes the largest |t| over eight statistics (uncropped, six crops, second order) and calls a leak above 4.5. On normal data a single test crosses 4.5 by chance about 7 times in a million. Taking the maximum of eight raises that rate somewhat.

dudect (Reparaz, Balasch and Verbauwhede, DATE 2017) is a small tool that runs these Welch tests on real timings. Its source sets its failure line at 10, with the comment "Pankaj likes 4.5 but let's be more lenient". Pankaj is most likely Pankaj Rohatgi, a TVLA co-author; this manual keeps the stricter 4.5.

The dudect README asks whether passing means the code is constant time, and answers "Absolutely not." The guide for tlsfuzzer, a TLS test suite, suggests a Kolmogorov-Smirnov test for a different job: checking that p values from repeated runs are uniform. Its own pairwise timing tests are the Wilcoxon signed-rank and sign tests.

The size of what a test can see shrinks with the square root of the sample count. The tlsfuzzer guide states the rule as sample size proportional to 1/e² for an effect of size e. In the block below, F_A(x) is the fraction of class A times at or below x.

```text
Welch t          t = (mean_A - mean_B) / sqrt(var_A/n_A + var_B/n_B)
Second order     same t, computed on (x - mean_of_its_class)^2
KS statistic     D = max over x of |F_A(x) - F_B(x)|
KS line          D_crit = 1.95 * sqrt((n_A + n_B) / (n_A * n_B))   (asymptotic, p = 0.001)
                 at n_A = n_B = 100,000: D_crit = 0.0087
Smallest mean    delta_min = 4.5 * sqrt(var_A/n_A + var_B/n_B)
shift flagged    at n = 100,000 per class, equal spread: about 0.020 standard deviations
                 a true shift of exactly delta_min is flagged in about half of runs
```

The harness maps each verdict onto the CNS outcomes. A leak is TERMINAL_BREACH, and the resolution is reject: the build under test is not promoted. Too few samples or no computable statistic is RETRY, so an unclear run never passes.

From `stack-anc-harness/src/lib.rs`:

```rust
/// The TVLA leak threshold on |t|. Above it, the two classes are treated
/// as distinguishable.
pub const T_THRESHOLD: f64 = 4.5;
```

From `stack-anc-harness/src/report.rs`:

```rust
    pub const fn gate_outcome(&self) -> GateOutcome {
        match self {
            Verdict::NoLeakDetected { .. } => GateOutcome::Pass,
            Verdict::LeakDetected { .. } => GateOutcome::TerminalBreach,
            Verdict::Inconclusive { .. } => GateOutcome::Retry,
        }
    }
```

**Proof is available only for Strategy 3.** Formal tools can check constant-time code without running it. ct-verif (Almeida et al., USENIX Security 2016) checks LLVM IR, the compiler's intermediate form, through a product program that runs two copies together.

binsec/rel checks machine code by relational symbolic execution. Symbolic execution runs a program on stand-ins for its inputs instead of real values, and relational means two copies at once. Its README calls it bounded verification and bug-finding, first published at IEEE S&P 2020.

A pad-up strategy has no such proof, because its guarantee depends on clocks and schedulers these tools do not model. Even a constant-time proof holds only under the tool's hardware model. ct-verif also leaves the final compile stage unchecked, and binsec/rel covers only paths within its exploration bound.

### Calibration on the test machine

A test that cannot see a known leak proves nothing, so the harness was first run on known cases. These are in-process timings of the 32-byte compare, not network timings. Each run used 200,000 samples: 99,885 in one class and 100,115 in the other.

```text
cargo run --release -p stack-anc-harness --example calibrate 200000 50
```

| Case | Timer | Largest \|t\| | Verdict |
|---|---|---|---|
| Early-exit victim | Instant (ns) | 1229.6 | Leak, TERMINAL_BREACH |
| Early-exit victim | rdtsc (cycles) | 1125.6 | Leak, TERMINAL_BREACH |
| Constant-time control | Instant (ns) | 2.28 | No leak detected, PASS |
| Constant-time control | rdtsc (cycles) | 1.98 | No leak detected, PASS |
| Constant-time control, each input built just before timing | Instant (ns) | 221.0 | False leak |
| A/A, 50 seeds | Instant (ns) | 2.86 at most | 0 of 50 flagged |

Instant is Rust's monotonic clock; rdtsc is the CPU cycle counter. A/A means both classes run the same thing, so any leak verdict is a false positive. The machine was a 4-CPU Intel Xeon at 2.80 GHz.

The early-exit leak is about 27 ns at the median (48 against 21 ns). That is below the 100 ns LAN figure above, which slows a remote attack but does not remove the leak.

Most of the detection comes from the cropped tests. Uncropped t was 23.9 and 11.5 here, and 5.2 and 5.1 in an earlier recorded run; cropped t topped 800 in every run.

The fifth row shows the harness can fake a leak. Building each random input right before timing it left residue that the timer counted. Strategy runs must keep input generation outside the timed region, as the default batching does.

Zero false positives in 50 A/A runs only shows that the false positive rate is not large. It does not measure a rate as small as the single-test figure.

### Achievable goals

| Goal | Applies to | How it is established | Strength |
|---|---|---|---|
| No detectable difference at n, with the smallest detectable shift stated | All three strategies | Uncropped, cropped and second-order Welch t, plus KS, at 100,000 per class | Evidence at that n and on that machine |
| Leakage bounded in bits | Any strategy whose target adapts | Counting epoch changes or scheduled updates against a configured budget | Bound under the counting model; the counter is testable |
| Constant-time code | Strategy 3 only | binsec/rel on the built binary, plus the statistical tests; ct-verif is built around C compiled with Clang | Proof under the tool's hardware model and, for binsec/rel, its exploration bound |
| Survives a fast-fail flood | All three strategies | Flood test with CPU and latency limits | Measured against a configured budget |

### The measures the three strategies are judged on

| Measure | Definition | Pass line |
|---|---|---|
| Calibration | The harness must flag the unpadded early-exit victim and pass the constant-time control at the same n. | If it cannot see the known leak, the run proves nothing. Met on the test machine above. |
| Detectability | Largest \|t\| over uncropped, cropped and second-order Welch t per class pair, with KS D and its p value beside it. | \|t\| at most 4.5 at 100,000 per class: samples = 200,000 in the harness, which counts both classes. A KS p below 0.001 is reviewed, not an automatic fail, because at large n KS flags differences too small to exploit. |
| Smallest detectable shift | delta_min in nanoseconds from the formula above, using the per-class variances the harness reports. | Reported, never omitted. |
| Leakage bound | Bits under the counting model, from the controller's counters. | At or under the configured budget; not applicable to a fixed target. |
| CPU cost | CPU seconds per request, measured with getrusage (the OS call that reports CPU time used), idle and under flood. | Padding CPU under flood stays within the configured CPU budget. |
| Added tail latency | p50, p99 and p99.9 of response time minus the unpadded baseline: the median, and the times 99 and 99.9 percent of replies beat. | Reported per class; a fixed ceiling makes p50 cost high by design. |

### The anti-DoS principle

**Shed at admission, before any secret-dependent work, using public information only.** Public information is what the attacker already sees or could compute: request size, framing, arrival times, and outcomes already sent. A count of padded requests in flight is also public, because each is held until its public release time.

The risk the brief names is real. If every fast failure is padded up to the slow path's time, a flood of cheap failures buys expensive padding. What that padding costs depends on how it waits.

| Padding style | What it consumes | Cap needed | Precision |
|---|---|---|---|
| Sleep until the target | A concurrency slot: a task, a connection, its memory. No CPU. | A semaphore (a counter of free slots) on padded requests in flight; shed when full. | Coarse: timer and scheduler wake-up jitter. |
| Spin until the target | A CPU core for the whole wait. | A CPU budget per window, charged at the full target time for each padded request; shed when spent. | Fine, but the spin itself contends with other work. |
| Sleep, then spin the last stretch | Mostly a slot, a short spin at the end. | Both caps. | Fine, with bounded CPU. |

One trap needs naming. A spin lasts the target minus the work time, so a budget that counts only spin time drains faster on fast, early-fail paths. Its shed rate would then track the secret; charging the full target per request keeps it public.

Two timing notes follow. A shed reply is fast, but its speed reflects load, which is public under the rules above. Telemetry must record after the release time, or its cost lands inside the measured window.

### Trips shared by the three strategies

| Trip | GateOutcome | Resolution | Why |
|---|---|---|---|
| Admission full: slots or CPU budget spent | RETRY | reject | Decided on public load before secret work; nothing changed, so a later resubmit can succeed. |
| Input over the size cap or badly framed | RETRY | reject | Size and framing are public and checked before secret work; a corrected input can pass. |
| Work overran the hard ceiling | RETRY | reject | A deadline timer, not the worker, sends the reply at the ceiling, and the late verdict is discarded. The reply text still reveals the overrun, and slow secret paths may overrun more often, so the overrun rate is counted. |
| Adaptive leakage budget spent | TERMINAL_BREACH for the controller; requests continue | rollback | The target returns to its configured public maximum and stops adapting; that last change is one more counted step. Halting would let a flood force a shutdown. |
| Monotonic clock unavailable | TERMINAL_BREACH | halt | No padding guarantee holds without a clock, and no correction to the input repairs that. |

Quarantine is not used. Isolating a sender belongs to admission control, not to timing.

### What exists today

`sentinel_os/api_key_auth.py` already applies the Strategy 3 idea. `_find_key_constant_time` compares the presented key against every configured key with `hmac.compare_digest` and never exits early.

No test in sentinel_os measures its timing. Python's own docstring for `compare_digest` warns that inputs of different lengths may reveal their lengths, though not their values.

Its failure replies also differ in text: "Invalid API key" versus "API key is disabled". That is a content channel, not a timing one, and it tells a caller that the key it sent exists but is disabled.
