## Open questions

65 decisions remain; the one that touches most components is who owns per-sender quotas, since no component keeps honest clients served under flood.

*New design decisions, except the six Sentinel items, which concern sentinel_os as it exists today*

Each item is one question, then its tradeoff. They come from every builder's open questions and every red team's unfixed findings, merged where several agents raised the same point.

### Kernel-wide

- [ ] Which component owns per-sender quotas and quarantine for repeated refusals: Inlet, a new admission layer, or each caller? Every component is stateless about senders, so floods starve honest clients; per-sender state costs memory and needs an authenticated identity.
- [ ] Should kernel convention 4 log a keyed digest (HMAC under a per-process key) instead of plain SHA-256? A plain digest lets a log reader test guesses of a low-entropy input offline; a keyed one cannot be matched across processes.
- [ ] Should GateOutcome and GatePosition move into one shared stack-core crate? Each crate re-declares the CNS vocabulary today, which can drift; a shared crate is one more dependency every component tracks.
- [ ] Should every TACK fingerprint hash carry a domain-separation tag, a fixed prefix naming its purpose? Plain SHA-256 matches digests made elsewhere, which is convenient but lets a digest from one context pass in another.
- [x] May the CNS subject_digest encoding be reproduced in Rust and in this manual? Resolved 2026-10-06: yes. CNS is public under Apache-2.0, so the confidentiality marking that raised this question no longer exists.
- [x] Which subject_digest format will Python producers and the Trident share: the CNS rendering or RFC 8785 canonical JSON? Resolved 2026-10-28: the CNS rendering. The Trident ports it (src/cns_digest.rs) and the MAC still covers the canonical JSON.
- [ ] Which histogram bucket boundaries should the kernel standardize? The metrics facade leaves buckets to the exporter, so components may export histograms that cannot be compared.
- [ ] Should gauges carry a closed-enum instance label? Two instances of one component in a process overwrite each other's gauges today; a label needs every deployment to name its instances up front.
- [ ] Should every gauge be written as 0 at construction, so absence alerts work? Some gauges stay absent until their first event, but writing 0 at build time resets a series another instance shares.
- [ ] Should metrics and logs move off the request path, through a bounded channel to a telemetry thread? Outcome-dependent nanoseconds land in the time a caller sees today; a channel is one more queue to bound, and it can drop events.
- [ ] Should the allowed dependency list grow to admit a formal constant-time checker, the sha2 assembly feature, a confusables table or a signature scheme? Each closes a limit recorded in this manual, at the cost of more code in the trusted base.

### ANC strategies and harness

- [ ] Should Spin mode leave production profiles, or be refused when `max_concurrent` exceeds the CPU count? Spin was the most precise when idle (0.11 to 0.13 µs late) but about 1.1 ms late at p99 in the recorded unpinned flood, with 8 threads on 4 CPUs.
- [ ] Should `hard_ceiling_buckets = 1` be required for secret-heavy operations? Each overrun can reveal up to log2(H + 1) bits; H = 1 turns more slow requests into RETRY.
- [ ] Should epoch Sleep mode be dropped, since KS flagged it in every full-size run? Hybrid passed KS but used about 4 times the CPU and added about 501 µs instead of 180 µs.
- [ ] Should the adaptive controller ship at all, given that its 128-bit budget froze it within a second on this host? A larger floor or epoch keeps it adapting longer, but gives back most of its latency benefit over Strategy 1.
- [ ] Should `AdaptivePad::naive` and `balanced_dummy` stay reachable in the public API? They are measured counterexamples that tests depend on. `AdaptivePad::naive` now needs `allow_naive_controller`, as `balanced_dummy` needs `allow_leaky_validators`; the open question is whether to hide them behind a cargo feature as well.
- [x] Should a pad hold every slot until one fixed release time, or isolate slots per sender? Decided: hold every slot for one fixed time from admission (the cap, or the hard ceiling). Capacity cost is up to H times; extra registers that open on backlog are the planned offset.
- [ ] What should `scaling.max_slots`, `reaction_delay`, `cooldown_windows` and the spillway size and wait be? Defaults leave both features off. Needs measured traffic: how fast backlog builds and how long a bursty peak lasts.
- [ ] Which routes belong on the fast gate? Needs a list of operations that are fixed-cost and never read a secret, with a review step that records why each qualifies. Metrics now separate the lanes with `strategy="ceiling_fast"`; the fast-overrun alert is critical.
- [x] Open-slot count is exported as `stack_anc_slots_open`, and spillway use as `stack_anc_spilled_total`.
- [ ] What should the fixed hold time (speed limit) be? Placeholder is the existing cap. Proposed: 99.9th percentile of measured work time times about 1.5, so fewer than 0.1 percent of honest requests are cut off. Evidence so far (one single-vCPU 2.1 GHz Xeon VM, benign load, the token-validate op only; no production callers exist): the op itself takes about 63 to 110 ns at p99 and 75 to 231 ns at p99.9, so the formula gives about 0.35 µs, which is below host timer and scheduler jitter and so meaningless. What the data does support is a 300 µs ceiling with a 1.2 ms hold: over 9 runs of 200,000 requests the overrun rate was at most 2e-5 (4 of 200,000), about 50 times under the 0.1 percent target. Padded latency at p99.9 reached about 1.2 to 2 ms on that VM. Re-measure on production hardware and with real handler work before fixing the value.
- [ ] Is it acceptable that one slow request per epoch pins every request at the adaptive cap? Partly addressed by the opt-in `tolerated_slow_permille`, which stops rare slow requests from raising the shared level. The remaining limit is the leak budget: each slow request spends it, and a spent budget freezes the controller at the cap. Decide how many slow requests per minute are acceptable, size `leak_budget` to match, then turn the tolerance on and re-run the release-mode verify example.
- [ ] Should the async Hybrid tail grow past 2.5 ms, or the async API sleep on a dedicated timer thread? The 2.5 ms tail missed tokio wake-ups at p99.9 (3.6 ms late); a longer tail spins more CPU.
- [ ] Should Strategy 3's response-time histogram default to off? For a leaky validator it is a histogram of the leak if the metrics endpoint is ever exposed; turning it off loses latency monitoring.
- [ ] What threshold should the StackAncPipelineGuessing alert use? The 0.5 line is a placeholder. The denominator is settled: divide by `stack_anc_validated_total` (requests that reached the validator), so cheap malformed requests cannot dilute the ratio.
- [ ] Should a secret made of one repeated byte, such as all 0xFF, be refused like all zeros? It catches common unset shapes; entropy remains the key generator's job.
- [ ] Should CI estimate the harness's A/A false-positive rate from 1,000 runs, or raise the line for the largest of eight correlated statistics? 0 of 50 runs bounds the rate only below about 6 percent; a higher line weakens detection.
- [ ] Should every crate's calibration use the same rule, the largest of eight statistics? Strategy 1 checks the control's uncropped \|t\| only, and Strategy 2's control once reached a cropped t of 10.8.
- [ ] Should strategy crates be required to prepare both classes' inputs with identical work? Building inputs just before timing faked a leak of max \|t\| 221 in calibration; class-dependent preparation could do the same.
- [ ] How should ANC consume Green Wave's `release_at`: pad inside the epoch, or use the epoch index only? The two crates were built separately and share no interface yet; the choice decides which component owns release timing.

### Inlet

- [ ] Should a C0 or C1 byte followed by 80..BF stay TERMINAL_BREACH? It is byte-identical to an overlong '/' (C0 AF), so relaxing it spares some honest Latin-1 text but reopens a filter disguise.
- [ ] Is the ban on U+200D and variation selectors intended for every deployment? They can carry hidden payloads, but ordinary emoji use them, so emoji-heavy deployments must strip them before the inlet.
- [ ] Should callers return `first_offset` to the sender? It helps honest senders fix their input, and tells an attacker exactly where the filter fired.
- [ ] Should the input digest be optional, skipped on pass and fail alike? SHA-256 is about half the inlet's cost on this machine; skipping it for one outcome only would add a timing difference.

### Trident

- [x] Should audience binding be on by default? Resolved: an audience is required. An empty one is refused at start unless `allow_unbound_audience` is set, because two receivers that share a sender key and bind no audience each accept the same envelope.
- [ ] Should shared HMAC keys give way to per-pair keys or signatures? Any receiver holding a sender's key can forge as that sender; per-pair keys multiply key management, and signatures need an unlisted dependency.
- [ ] Should the receiver persist its replay high-water mark by default? Without it, restart safety assumes the clock never ran backwards; persisting needs storage the crate does not own.
- [ ] Should replay state and quarantines move to a shared store? They live in process memory, so a restart loses quarantines and replicas need shared state or sender affinity.
- [ ] Should `unknown_sender` and `mac_mismatch` collapse into one reply code? Today the reply reveals ring membership; fingerprints are public identifiers, so this was accepted.
- [ ] Should `duplicate_key` stay TERMINAL_BREACH or become RETRY? It is the signature of a parser-differential attack, but it is unauthenticated, so it never feeds the breaker either way.
- [ ] Should masked stateful failures be counted in metrics? Counting adds visibility, but must not let a metrics reader probe a sender's hidden state.
- [ ] Should `seal()` apply the receiver's full node cap? A producer can seal up to 10 nodes over it and be refused; a strict seal breaks a red-team test that seals exactly `max_nodes`.

### Bumpers

- [ ] Should an over-long string be TERMINAL_BREACH, like the numeric hard band, instead of RETRY? RETRY lets a caller shorten it; TERMINAL_BREACH treats `max_len` as a limit no correction repairs.
- [ ] Should key case drift, such as `Timeout` for `timeout`, be an allowed correction? It is friendlier to callers, but two keys that differ only in case would become one.
- [ ] Which of integer-only numbers, optional defaults and control characters inside strings should be supported? Each needs a policy decision before any code is written.
- [ ] Should normalization equalize its work across paths instead of relying on ANC to wrap it? Equal work removes several small timing differences, but costs CPU on every request.

### Minotaur

- [ ] Which CNS GatePosition should a Minotaur trip carry? It runs during execution, neither before it (ALPHA) nor on the result (OMEGA); a third position would change CNS.
- [ ] Should LoopDetected be TERMINAL_BREACH on first occurrence in some profiles, such as an agent repeating an identical tool call? Today one loop is repairable, and repeats escalate to a halt.
- [ ] Should the crate offer a Trip without its path? The path helps debugging, but exposes state fingerprints if a trip reaches the agent being constrained.
- [ ] Should the lifetime step budget become a tunable config field? Today it is `max_steps` times `max_trips_before_halt`, so long-lived Threads need periodic operator resets.
- [ ] Should the defaults (`max_depth` 64, `max_steps` 100,000, revisit allowance 3) be calibrated against real tool-call logs? They are engineering guesses; wrong caps either trip honest walks or let runaway ones run long.

### Green Wave

- [ ] Should a halt drain or return queued requests? Queues survive halt and reset today, and tickets issued before a clock regression then fail at completion.
- [ ] Is a work-conserving mode wanted, one that lends idle phases to other lanes? It raises throughput, but makes one tenant's latency depend on another tenant's load.
- [ ] Should `UnknownLane` be RETRY instead of TERMINAL_BREACH? The current choice assumes an authenticated upstream assigns lanes; RETRY would suit callers that pick their own lane.
- [ ] Do several processes need a shared epoch origin? Each clock anchors its own boundaries today, so separate processes release on different grids.
- [ ] Should the driver thread run at raised priority? Under full CPU load it missed phases, which voids the fairness bound; raising priority needs unsafe system calls the crate rules forbid.
- [ ] Should `queue_wait_seconds` be split by lane class through a closed enum? Operators would see which tenant waits, at the cost of more series.

### Transmission

- [ ] Should the clutch stay up for a minimum time between shifts? Without it, a worker parked through back-to-back shifts can time out; a minimum delays urgent shifts.
- [ ] Should `in_flight_capacity` wait up to the engage timeout, like the clutch wait? Waiting smooths bursts, but adds a second queue that must be bounded.
- [ ] Should each Gear carry a SHA-256 digest of its config, so every shift can be recorded in the Sentinel ledger? That needs a serialization bound on the gear type, which the crate does not require today.
- [ ] Is an async wrapper built on `spawn_blocking` wanted? The API blocks today; the wrapper would live beside the crate, not inside it.
- [ ] Should an operator be able to clear a leaked guard's count without a restart? A forgotten guard blocks every shift until restart; a manual clear risks shifting under live work.

### Sentinel (touches sentinel_os)

- [ ] Should sentinel_os's truncated hashes be raised as an issue? `twin_custody.py` prints 16-character hash prefixes, against rule 4 of its CLAUDE.md; full hashes make messages longer but searchable.
- [ ] Is the uneven treatment of retired keys in the Python intended? A retired-key signature passes, a retired-key seed is SEED_FORGED and a retired-key anchor is accepted; stack-sentinel now refuses the signature and anchor by default.
- [ ] Should Python's `check_head_anchor` also refuse a signed anchor that seals zero rows? stack-sentinel now requires at least one row by default; Python still lets such an anchor vouch for any chain.
- [ ] Is the outcome mapping right: an unknown key or unreadable anchor is RETRY, and any inconsistency inside an export is TERMINAL_BREACH with quarantine? RETRY reflects that the auditor's own inputs can change the answer.
- [ ] Should sentinel_os hash the columns VERIFIED ignores, such as `timestamp` and `call_sid`? It needs a ledger format change; today a 27-year move of a timestamp still verifies.
- [ ] Should auditors require a fresh anchor, or raise `min_anchor_entries`? A chain cut back to an older genuine anchor still verifies; a stricter rule refuses honest chains whose anchor job stalled.
