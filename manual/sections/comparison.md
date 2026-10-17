## Comparison: the three ANC strategies

Use Strategy 3's branch-free compare (max |t| at most 2.60, no added delay) where code allows, and a Strategy 1 ceiling elsewhere.

*New design: reference implementations compiled and tested on Rust 1.94*

### What is being compared

All three strategies fight the same leak: a token check that answers sooner when a guess goes wrong earlier. Strategy 1 holds every reply until a fixed time after admission. Strategy 2 moves that time with recent load, and Strategy 3 removes the secret-dependent branch from the code itself.

Strategies 2 and 3 were built twice: as the brief described them, and as fixed after measurement. The brief's Strategy 1 design survived with changes, so it has one row. The brief's Strategy 2 and 3 designs get rows of their own.

Max |t| is the largest of eight Welch t-statistics, and above 4.5 counts as a detected leak. Each cell gives the range over the release runs at about 100,000 requests per class. A low value means no leak was detected at that sample size, never that none exists.

### Side by side

| Design | Max \|t\| measured | CPU under flood | Added latency | Leakage model | Protects against | Main failure mode |
|---|---|---|---|---|---|---|
| Strategy 1: fixed ceiling, Hybrid wait (`tack-anc-ceiling`) | 1.30 to 2.93; all 9 padded runs, every mode, at most 2.93 | 0.245 and 0.248 cores with the spin budget; 0.995 and 0.994 for Spin without one | Every reply waits the whole ceiling: median about 301 us at a 300 us ceiling, for 40 to 65 ns of work | While work fits the ceiling, release time depends on admission time alone; each overrun reveals up to log2(H + 1) bits, H = `hard_ceiling_buckets` (default 4) | Any secret-dependent work whose worst case fits the ceiling, including code that cannot be made constant time | Work past the ceiling leaks; a third party's shed reply reveals an overrun (rt10, open); a flood starved an honest client to 1 of 45 requests |
| Strategy 2 as fixed: epoch-quantized target (`tack-anc-adaptive`) | Hybrid 2.27 and 1.29; Sleep 3.68 and 2.06, but KS flagged Sleep in 3 of 3 full-size runs | 0.258 and 0.248 cores (Hybrid); 0.272 and 0.280 (Sleep) | About 180 to 184 us (Sleep) or 501 us (Hybrid) at the class A median; at the production budget the target averaged 1,711 and 2,020 us | Counted: at most N x log2(2(R + 1)) bits for N charged target changes among R requests; default budget 128 bits per 60 s, 1,024 bits between operator resets | Drifting load, and the fast-flood poisoning that breaks the brief's design (max \|t\| 1.38 and 0.94) | The 128-bit budget froze it within 0.55 to 0.95 s, holding 82 to 98 percent of replies at its 2,048 us cap |
| Strategy 2 as briefed: rolling-average target | Mean form 11.5 to 24.7, detected in all 4 runs; p99 form 3.0 to 3.9; p99 under poisoning 9.47 and 11.09 | Not flooded | About 80 us (mean form) and 100 to 108 us (p99 form) at the class A median | Not bounded: a late reply leaves at its raw work time; 188,485 and 189,969 target changes in 202,000 requests, a bound near 3.5 million bits | Nothing reliably | 4.3 to 5.0 percent of replies released late; poisoning; a target that records other users' timings |
| Strategy 3 as fixed: `constant_time` compare (`tack-anc-pipeline`) | 0.56 to 2.60 across 12 configurations and runs; never detected | 0.991 and 0.994 cores while serving 1.70 M to 1.73 M requests per second | None added: 239 to 240 ns median through the gate; the bare compare takes 32 ns, faster than the early-exit check's 39 to 61 ns | In this x86_64 release binary, no branch or memory address depends on the secret: the disassembly shows zero conditional branches. Nothing adapts, so no bits are counted | Timing of the compare itself; the only design a formal tool could check | A compiler or target change can bring a branch back; covers only the code it controls; does not cap total CPU |
| Strategy 3 as briefed: `balanced_dummy` filler | 89 to 192, detected in 9 of 9 runs; 926 to 947 when the filler is optimised away | 0.994 and 0.990 cores | About 27 to 28 ns more per byte-0 failure, bare | Equal instruction counts, unequal time: the filler path ran 4 to 6 ns slower, the reverse of the original leak | Nothing measurable on this host | Detected in every run; its shed rate also tracks the secret |

CPU under flood is whole-process CPU per wall second, with the process pinned to one CPU. The flood setups differed by crate, so compare CPU down a column only with care.

Strategy 1 used 2 flood threads and 1 slot, and Strategy 2 used 10 threads and 1 slot. Strategy 3 used 20 threads and 2 slots, with nothing to pad.

The two padding strategies spent that CPU holding requests, within their spin budgets. Strategy 3 spent it answering flood requests, each costing 218 to 282 ns idle, so its total needs a rate limit in front.

The ANC analysis says Strategy 3 "makes the paths identical". The measurements show that holds only for `constant_time`; the brief's `balanced_dummy` equalises step counts and still leaks.

### Recommended combination

1. **Strategy 3 for every comparison of a secret with a guess:** tokens, MACs (message authentication codes) and API keys. Use `constant_time` through `PipelineGate`, and rerun its verify example after any compiler or target change.
2. **Strategy 1 around work that cannot be made branch-free:** a whole request path that includes Minotaur, Bumpers or logging, for example. Use Hybrid mode, a limited spin budget, `hard_ceiling_buckets = 1` and the async API. Set the ceiling above the worst case measured on the target host.
3. **Strategy 2 only on a quiet, dedicated host** where the floor covers the worst-case work plus the spin tail. Elsewhere it ends at its cap and behaves like Strategy 1 with more moving parts. Never deploy the rolling-average controller.
4. **Controls outside ANC:** per-sender quotas ahead of every pad, because no strategy kept honest clients served under flood. Keep the metrics endpoint private, since several metrics describe secret-dependent work.

The order follows what each strategy removes. Strategy 3 removes the timing difference at its source, adds no delay, and is the only one a formal tool could check.

Strategy 1 is the fallback because its release time depends on the admission time alone; its price is latency, paid on every reply. Strategy 2 adds a controller whose state is itself a channel. On this host, the budget that meters that channel pinned it at the cap anyway.
