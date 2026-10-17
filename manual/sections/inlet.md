## 1. Inlet Winnowing Filter

The Inlet Winnowing Filter refuses malformed UTF-8 and 4,307 banned characters before any other component sees them, at fixed cost per byte.

*New design: reference implementation compiled and tested on Rust 1.94*

### Metaphor and goal

A combine harvester has a winnowing fan at its grain inlet. The fan blows the light chaff away before anything reaches the threshing drum, so the drum only ever sees grain.

The inlet is that fan for the TACK kernel. It sits at the kernel boundary and refuses bad text before any other component reads it. In CNS terms it is an ALPHA gate: a check that runs before any work starts.

It is a new design. No TACK repository had an inlet filter before the `tack-inlet` crate, and no Python version exists. Of the seven components, only the Sentinel Hash-Chain in sentinel_os exists today.

The goal has two parts. First, nothing malformed or disguised crosses the boundary. Second, the check itself cannot be turned into a weapon.

"Malformed" means not valid UTF-8, the standard way to write Unicode text as bytes. "Disguised" means a character that hides or reorders what a human reviewer sees. The banned classes come from fixed Unicode 16.0 properties:

- **Control characters.** Invisible commands such as NUL or a pasted terminal escape. Tab, line feed and carriage return are allowed.
- **Bidirectional (bidi) controls.** Characters that change the direction text is displayed in. The overrides power the Trojan Source attack, where code displays in one order and parses in another.
- **Default-ignorable characters.** Characters that render as nothing: zero-width spaces, tag characters, variation selectors, Hangul fillers. Any two of them can spell out a hidden message.
- **Noncharacters.** Character numbers that Unicode reserves for internal use and never for interchange.

Together the classes hold 4,307 code points, the numbers Unicode assigns to characters. A test pins that count.

The second goal matters because a filter is itself an attack surface. A filter that backtracks, recurses or allocates memory sized by an attacker's number can be made to stall. This one does fixed work per byte, uses fixed memory, and refuses over-cap input before reading it.

### Mechanism

The filter works in three stages: a length check, one pass of an automaton over the bytes, and a typed verdict. The one-shot entry point shows all three (src/lib.rs):

```rust
    #[must_use]
    pub fn winnow(&self, input: &[u8]) -> Verdict {
        let span = tracing::info_span!("tack.inlet.winnow", len = input.len());
        let _entered = span.enter();
        let started = Instant::now();
        let v = if input.len() > self.config.max_len {
            Verdict::oversize(input.len(), self.config.max_len, 0)
        } else {
            let mut dfa = Dfa::new();
            dfa.scan(input);
            let r = dfa.finish();
            let digest: [u8; 32] = Sha256::digest(input).into();
            Verdict::from_scan(input.len(), r.scanned, r.count, r.first, r.seen, digest)
        };
        telemetry::emit(&v, started.elapsed(), self.log_key.as_deref());
        v
    }
```

**Stage 1: length first.** The input's length is compared with `max_len` before any byte is examined. Over the cap, the verdict is `oversize` and the body is never read. A caller that knows a declared length, such as an HTTP `Content-Length` header, can call `Inlet::precheck` before reading the body at all.

Each cap lives in a configuration struct with a documented default, and the log key has no default at all. An out-of-range value stops the inlet from being built.

| Setting | Default | Allowed range | Purpose |
|---|---|---|---|
| `InletConfig::max_len` | 64 KiB | 1 byte to 16 MiB | Bounds bytes, and so CPU, per request |
| `StreamConfig::max_chunks` | 4,096 | 1 to 16,777,216 | Bounds calls per stream, empty calls included |
| `LogKey` | None: there is no default key | At least 32 bytes, not all equal | Keys the digest written to logs |

**Stage 2: the automaton.** A deterministic finite automaton (DFA) is a machine with a fixed set of states. It reads one byte, looks up its next state in a table, and never re-reads an earlier byte. Its whole run-time state is a few integers, which is what makes it safe to point at hostile input.

A UTF-8 character is a lead byte that gives its length, then up to three continuation bytes in the range 80..BF. The states track where the reader is inside one character.

Extra states follow the byte prefixes of banned characters, so a banned character's last byte lands on a table entry marked "violation". The current specification needs 36 states.

The table is not written by hand. It is computed at compile time from a readable function, `step`, and bytes that behave alike in every state share one of 53 classes. A unit test re-checks every state and byte pair against `step`; the padded table is 8 KiB.

This arm of `step` handles the byte prefix E2 80, which covers U+2000 to U+203F (src/dfa.rs). That one prefix holds zero-width spaces, bidi marks, the line separators and the Trojan Source overrides:

```rust
        S_E2_80 => match b {
            0x8B..=0x8D => done(ZW),
            0x8E | 0x8F => done(MARK),
            0xA8 | 0xA9 => done(C1),
            0xAA..=0xAE => done(BIDI),
            _ if c => done(NONE),
            _ => abort(TRUNCATED, b),
        },
```

**Scan the whole input, always.** The automaton does not stop at the first violation. With early exit, a bad byte at offset 10 is refused faster than one at offset 60,000. Anyone timing the refusals would learn where the bad byte is.

So the loop records violations with mask arithmetic instead of `if` statements. A mask here is a number that is either all one-bits or all zero-bits, so bad and good bytes run the same instructions (src/dfa.rs):

```rust
        for &b in chunk {
            let e = TABLE[usize::from(state) & (ROWS - 1)]
                [usize::from(CLASS[usize::from(b)]) & (COLS - 1)];
            tally.record((e >> PEND_SHIFT) & REASON_BITS, seq_start);
            tally.record((e >> CUR_SHIFT) & REASON_BITS, pos);
            let m = 0usize.wrapping_sub(usize::from(e & START_BIT != 0));
            seq_start = (pos & m) | (seq_start & !m);
            state = (e & NEXT_MASK) as u8;
            pos = pos.saturating_add(1);
        }
```

```rust
    #[inline(always)]
    fn record(&mut self, code: u16, off: usize) {
        let has = usize::from(code != 0);
        let is_first = has & usize::from(self.count == 0);
        let m = 0usize.wrapping_sub(is_first);
        self.first_off = (off & m) | (self.first_off & !m);
        self.first_code = (usize::from(code) & m) | (self.first_code & !m);
        // Bit 0 collects "no violation" and is masked off when read.
        self.seen |= 1u16 << (code & REASON_BITS);
        self.count = self.count.saturating_add(has);
    }
```

Each table entry packs four fields. They are the next state, a violation for the character in progress, a violation at this byte, and a "new character" flag.

The tradeoff is that hostile input is always scanned in full, so bad input costs as much CPU as good input. The length cap bounds that cost.

**Stage 3: the verdict.** A `Verdict` carries the outcome, the resolution, the first violation's reason and offset, the violation count, and all reasons seen. It also holds the full SHA-256 of the bytes judged, binding the verdict to its exact subject (the CNS `subject_digest` idea). Its fields are private and it has no public constructor, so a caller cannot hand-build a PASS.

**Streams.** Input that arrives in pieces goes through a `Scanner`, created by `Inlet::scanner`. It enforces the length cap across all chunks, and it checks both caps before reading a chunk (src/lib.rs):

```rust
    pub fn feed(&mut self, chunk: &[u8]) -> Feed {
        if self.stopped.is_some() {
            return Feed::OverLimit;
        }
        self.chunks = self.chunks.saturating_add(1);
        if self.chunks > self.max_chunks {
            self.stopped = Some(Stop::Chunks);
            return Feed::OverLimit;
        }
        self.offered = self.offered.saturating_add(chunk.len());
        if self.offered > self.max_len {
            self.stopped = Some(Stop::Length);
            return Feed::OverLimit;
        }
        self.dfa.scan(chunk);
        self.hasher.update(chunk);
        Feed::Continue
    }
```

A property test checks a rule against thousands of generated inputs. One such test, with 10,000 cases, checks that any chunking gives the same verdict as `winnow`. A scanner dropped without `finish` still judges and records what it was fed.

**Refuse, do not repair.** The inlet never cleans an input and passes the cleaned copy on. That is the opposite of `sanitize_context` in observe-perceive, which drops bad context values and carries on. A filter that silently rewrites input changes what later gates judge, without anyone deciding that.

No Python code implements the inlet today. The Rust crate is the only implementation.

**Measured versus assumed.** On the build host, which lacks SHA hardware instructions, a full 64 KiB check took about 0.6 ms. About half of that was SHA-256. A re-run for this manual, on a host with SHA instructions, took 338 to 357 microseconds.

One property is assumed rather than proved. Rust does not promise to keep the loop free of data-dependent branches, so the timing test measures timing instead of assuming it.

### Failure mode and state resolution

Every trip returns a typed `Verdict`. Library code has no `unwrap`, `expect` or `panic`, and no input the red team tried made it panic. Each of the 14 reasons maps to the CNS vocabulary: RETRY (the sender may fix and resend) or TERMINAL_BREACH (no fix repairs it).

The inlet uses only two of the four kernel resolutions. It holds no state, so there is nothing to roll back, and halting would let one hostile request stop the inlet for everyone.

Quarantine here means the verdict marks the input for review and `tack_inlet_quarantined_total` rises. The inlet knows no sender, so isolating the sender is the caller's job.

| Trip | Outcome | State resolution | Why |
|---|---|---|---|
| Length over `max_len`, whether one-shot, declared, or cumulative in a stream (`oversize`) | RETRY | reject | The body is not read. A shorter or split input may pass. |
| Stream fed more than `max_chunks` calls (`chunk_limit`) | RETRY | reject | Resending in larger chunks may pass. Empty chunks count, so framing cannot multiply the work. |
| Multi-byte sequence cut short (`truncated`) | RETRY | reject | Typical of a buffer split mid-character. Resending whole characters repairs it. |
| Continuation byte 80..BF where a character should start (`unexpected_continuation`) | RETRY | reject | An encoding fault, such as text in Latin-1 (an older one-byte Western encoding) labelled as UTF-8. Re-encoding repairs it. |
| Byte F8..FF, or a lone C0 or C1 not followed by a continuation byte (`invalid_byte`) | RETRY | reject | Never valid UTF-8, and usually a mislabelled encoding. A lone C0 or C1 cannot disguise anything. |
| Encoded surrogate (half of a UTF-16 character pair), ED followed by A0..BF (`surrogate`) | RETRY | reject | Non-standard encoders such as CESU-8 and WTF-8 produce it. It is an honest fault that re-encoding repairs. |
| Code point above U+10FFFF: F4 then 90..BF, or a lead byte F5..F7 (`above_max`) | RETRY | reject | Invalid, but also what some mislabelled Latin-1 bytes produce. Repairable. |
| Overlong form, a character written with more bytes than it needs: C0 or C1 then 80..BF, E0 then 80..9F, F0 then 80..8F (`overlong`) | TERMINAL_BREACH | quarantine | No conforming encoder writes one. Its classic use is hiding a character such as `/` from byte-level filters. |
| Bidi override or isolate, U+202A..U+202E or U+2066..U+2069 (`bidi_control`) | TERMINAL_BREACH | quarantine | The text displays in a different order from the one a parser reads. Stripping it does not erase the evidence of intent. |
| Bidi mark ALM, LRM or RLM: U+061C, U+200E, U+200F (`bidi_mark`) | RETRY | reject | Honest right-to-left text carries these marks, and they cannot reorder letters. |
| C0 control other than tab, LF and CR (`c0_control`) | RETRY | reject | Often a pasted terminal escape. Removing it repairs the input. |
| DEL, a C1 control, or the separators U+2028 and U+2029 (`del_or_c1_control`) | RETRY | reject | Control characters, and separators that JavaScript and many log viewers treat as line breaks. Removable. |
| Invisible character: Unicode default-ignorable, less the bidi controls, plus U+FFF9..U+FFFB, 4,165 code points in all (`zero_width`) | RETRY | reject | Honest text carries some, such as an editor's byte-order mark or an emoji's joiner. Removing them repairs the input. |
| Noncharacter: U+FDD0..U+FDEF, or U+xFFFE and U+xFFFF in any plane (`noncharacter`) | RETRY | reject | Reserved for internal use and never valid in interchange. Removable. |
| Several violations in one input | The most final outcome present | quarantine if any reason is terminal, else reject | The CNS `resolve` rule: any terminal breach decides the whole set. |
| Bad configuration: a cap of 0 or above its ceiling, or a short or placeholder log key | Not a verdict: `ConfigError` | reject: the inlet or key is never built | Failing closed at start-up means no request is ever served under a bad cap. |

Severity is fixed per reason, and an input's outcome is the most final severity it contains (src/verdict.rs):

```rust
    pub const fn severity(self) -> GateOutcome {
        match self {
            Self::BidiControl | Self::Overlong => GateOutcome::TerminalBreach,
            _ => GateOutcome::Retry,
        }
    }
```

```rust
        let (outcome, resolution) = if seen.bits() & TERMINAL_MASK != 0 {
            (GateOutcome::TerminalBreach, Some(Resolution::Quarantine))
        } else if count > 0 {
            (GateOutcome::Retry, Some(Resolution::Reject))
        } else {
            (GateOutcome::Pass, None)
        };
```

So the reported reason and the outcome can differ. An input whose first problem is a byte-order mark and whose later problem is a bidi override reports reason `zero_width` with outcome TERMINAL_BREACH.

Unknown input fails closed too, meaning it is refused rather than passed. Every table cell no input can reach holds an `invalid_byte` violation.

One byte of lookahead separates a Latin-1 accident from an attack. Bytes C0 and C1 are both overlong lead bytes and the Latin-1 spelling of A-grave and A-acute (src/dfa.rs):

```rust
        S_C0 => {
            if c {
                // An overlong lead (reported at its own offset) followed by
                // a continuation byte, which is then a stray.
                ent(S_START, OVERLONG, UNEXPECTED, false)
            } else {
                abort(INVALID, b)
            }
        }
```

Followed by a continuation byte, the pair is overlong and terminal. Followed by anything else, it is a repairable `invalid_byte`. One case remains a known limitation: A-grave or A-acute followed by a byte in 80..BF is byte-identical to an overlong form and stays terminal.

### Observability and telemetry

The control room receives seven metrics, three spans and one log event per verdict. A counter only counts up; a histogram records how values are spread.

Every label comes from a closed list. A label is a tag on a metric, and each new label value creates a new time series. Free-form labels would therefore let an attacker exhaust the metrics store.

| Name | Type | Labels | Meaning |
|---|---|---|---|
| `tack_inlet_verdicts_total` | counter | `outcome`, `reason` | One per verdict. `reason` is the first violation's reason, or `none` on a pass. A passing precheck emits nothing. |
| `tack_inlet_violations_total` | counter | none | Adds each verdict's violation count: 0 on a pass, 1 for a cap refusal. |
| `tack_inlet_reason_seen_total` | counter | `reason` | Once per verdict for each distinct reason present, even one that was not first. |
| `tack_inlet_quarantined_total` | counter | none | One per TERMINAL_BREACH verdict, whose resolution is always quarantine. |
| `tack_inlet_streams_abandoned_total` | counter | `outcome` | Streams dropped without `finish`, by the outcome so far. A non-pass abandoned stream also counts in every other metric. |
| `tack_inlet_input_bytes` | histogram | none | Input length per verdict. An oversize refusal records the cap plus one, never the declared length. |
| `tack_inlet_scan_duration_seconds` | histogram | `outcome` | Wall time from the start of the operation to the verdict, SHA-256 included. |

The `outcome` label takes `pass`, `retry` or `terminal_breach`. The `reason` label takes the 14 reason names or `none`. Every verdict passes through this one function (src/telemetry.rs):

```rust
    counter!(VERDICTS_TOTAL, "outcome" => outcome, "reason" => reason).increment(1);
    counter!(VIOLATIONS_TOTAL).increment(u64::try_from(v.count()).unwrap_or(u64::MAX));
    for r in v.reasons().iter() {
        counter!(REASON_SEEN_TOTAL, "reason" => r.as_str()).increment(1);
    }
    if v.outcome() == GateOutcome::TerminalBreach {
        counter!(QUARANTINED_TOTAL).increment(1);
    }
    histogram!(INPUT_BYTES).record(v.len() as f64);
    histogram!(SCAN_DURATION_SECONDS, "outcome" => outcome).record(elapsed.as_secs_f64());
```

The test file tests/telemetry.rs asserts that these metrics fire, using `DebuggingRecorder` with `metrics::with_local_recorder`. It also checks that every label value comes from the closed lists.

Spans are named, timed regions of work in the `tracing` log. All three are at info level:

- `tack.inlet.winnow`, field `len`: wraps one `Inlet::winnow` call.
- `tack.inlet.precheck`, field `declared_len`: wraps one `Inlet::precheck` call. The declared length appears here and nowhere else.
- `tack.inlet.stream`, field `chunks`: created by `Inlet::scanner` and entered only at `finish` or drop, never per chunk.

Log events, target `tack_inlet::telemetry`:

- DEBUG `inlet admitted input`: outcome, len, input_hmac.
- WARN `inlet refused input`: outcome, reason, resolution, first_offset, count, len, scanned, abandoned, input_hmac.
- WARN `inlet refused input on length or chunk count`: outcome, reason, resolution, len, scanned, abandoned, body_read=false.
- DEBUG `inlet stream abandoned while clean`: len.

No log carries raw input or the plain SHA-256. The red team recovered a 4-digit input from its logged digest by hashing all 10,000 candidates. So logs carry `input_hmac`: a full-length HMAC-SHA256, under a key the deployment supplies, of the input's SHA-256.

HMAC is a keyed hash, so without the key nobody can test guesses against the logged 64-character value. With no key, the field reads `unkeyed` and no digest is logged. This deliberately departs from kernel convention 4, which says to log the plain SHA-256; the convention itself needs a kernel-wide change.

Telemetry must not reveal where a bad byte sits. The fields `first_offset` and `count` are zero-padded to 8 digits. In the red-team test, a refusal line measured 231 bytes, timestamp excluded, with the bad byte at offset 0 or at 65,535.

Two timing differences remain, and both are documented. First, a pass logs at DEBUG and a refusal at WARN. A subscriber that keeps only WARN therefore makes refusals slower, which reveals only the outcome the sender learns anyway.

Second, the length of the `reason` string reveals the class of violation, but not its position.

Alert rules are Prometheus expressions evaluated over these metrics on a schedule. The first four below are the ones in src/telemetry.rs, and the last two come from the build record.

```yaml
groups:
  - name: tack-inlet
    rules:
      - alert: TackInletTerminalBreach
        expr: increase(tack_inlet_quarantined_total[5m]) > 0
        labels:
          severity: warning
        annotations:
          summary: An overlong form or bidi override reached the inlet. Find the WARN line by input_hmac.
      - alert: TackInletRetryFlood
        expr: sum(rate(tack_inlet_verdicts_total{outcome="retry"}[5m])) > 10
        labels:
          severity: warning
        annotations:
          summary: More than 10 repairable refusals a second, from a broken encoder or a probe.
      - alert: TackInletAbandonedRefusals
        expr: increase(tack_inlet_streams_abandoned_total{outcome!="pass"}[5m]) > 0
        labels:
          severity: warning
        annotations:
          summary: Streams were dropped with a refusal pending, such as a probe that hung up.
      - alert: TackInletChunkLimit
        expr: increase(tack_inlet_verdicts_total{reason="chunk_limit"}[5m]) > 0
        labels:
          severity: info
        annotations:
          summary: Senders hit the chunk cap, from a tiny-frame client or a framing attack.
      - alert: TackInletScanSlow
        expr: histogram_quantile(0.99, sum by (le) (rate(tack_inlet_scan_duration_seconds_bucket[5m]))) > 0.005
        for: 10m
        labels:
          severity: warning
        annotations:
          summary: The p99 time to a verdict is above 5 ms, from CPU starvation or a raised max_len.
      - alert: TackInletBidiSeen
        expr: increase(tack_inlet_reason_seen_total{reason="bidi_control"}[1h]) > 0
        labels:
          severity: info
        annotations:
          summary: Trojan Source characters appeared, even where they were not an input's first violation.
```

The ScanSlow rule needs the exporter configured to emit histogram buckets. Its 5 ms threshold sits well above the measured 0.6 ms for a full check at the default cap.

### Red-team results

The red team ran 24 tests covering 23 attacks against the built crate. Before fixes, 13 failed (1 blocker, 4 major, 8 minor); after the fix pass, all 24 pass. The automaton itself never failed open, meaning it never passed an input its documented ban list covers.

| Attack | Result | Fix or limitation |
|---|---|---|
| "ASCII smuggling": a hidden instruction in 46 invisible tag characters (blocker) | Broke: admitted as PASS. Fixed: now RETRY. | The whole block U+E0000..U+E0FFF is banned as `zero_width`. Cost: subdivision flag emoji (England, Scotland, Wales) are refused too. |
| "Emoji smuggling": 22 hidden bytes in variation selectors (major) | Broke. Fixed: now RETRY. | All 256 selectors are banned. Cost: ordinary emoji with U+FE0F draw RETRY, so emoji deployments strip selectors first. |
| 38 other invisible format characters, such as the U+3164 Hangul filler (major) | Broke: 38 of 38 admitted. Fixed: 0 of 38. | The ban list is now Unicode 16.0 `Default_Ignorable_Code_Point` plus U+FFF9..U+FFFB. |
| Bidi marks ALM, LRM and RLM (major) | Broke. Fixed. | New reason `bidi_mark`, RETRY, because honest right-to-left text carries them. |
| One million empty `feed` calls on a 64-byte cap (major) | Broke: about 90 full scans of CPU, then PASS. Fixed. | New `max_chunks` cap, default 4,096. The stream now stops after 4,097 calls with RETRY, in 56 microseconds. |
| Line and paragraph separators U+2028 and U+2029 (minor) | Broke. Fixed. | Refused as `del_or_c1_control`, like the C1 line break NEL. |
| `precheck(u64::MAX)` reports an attacker-sized length (minor) | Broke: len 18446744073709551615. Fixed. | The length is clamped to the cap plus one: 65,537 at the default. |
| The same declared length poisons `tack_inlet_input_bytes` (minor) | Broke: one value ruined the histogram's sum. Fixed. | The same clamp applies, so the histogram records 65,537. |
| 64 KiB fed as 65,536 one-byte chunks (minor) | Broke: 11.0 times the cost of one chunk. Fixed. | The span is entered only at finish: 2.6 times with the chunk cap raised. At the default cap the stream stops at chunk 4,097. |
| Refusal log length encodes the bad byte's position (minor) | Broke: 254 versus 258 bytes. Fixed: 231 and 231. | Offsets and counts are zero-padded to 8 digits. The `reason` length still reveals the class. |
| A stream dropped before `finish` leaves no trace (minor) | Broke. Fixed. | `Drop` now judges and records what was fed, so a dropped Trojan Source probe reaches the quarantine counter. |
| The logged plain SHA-256 reveals a 4-digit input (minor) | Broke: input recovered. Fixed: not recovered. | Logs carry a keyed HMAC or `unkeyed`. Kernel convention 4 still needs the same change. |
| Honest Latin-1 text quarantined as overlong (minor) | Broke. Fixed for the common case: now RETRY. | One byte of lookahead after C0 and C1. Limitation: C0 or C1 followed by 80..BF stays terminal. |
| Overlong disguises of `/` and NUL, whole and fed one byte at a time | Held | None needed. |
| Fail-open search: 6,000 chunked property cases, plus 4,706,304 exhaustive or sampled short inputs, against an independent reference | Held: 0 disagreements | None needed. This is property testing and exhaustive sweeps, not fuzzing. |
| Panics from extreme lengths, empty input, a 1-byte cap, or 16 MiB of violations | Held | None needed. Overflow checks were on. |
| Off-by-one errors at the cap, for precheck, winnow and streams | Held | None needed. |
| Over-cap input refused without reading the body | Held | None needed. |
| Memory growth | Held: `Scanner` is 272 bytes, `Verdict` 80 bytes | Allocation was not counted directly; that needs unsafe code the workspace forbids. |
| Timing: bad-byte position and violation density | Held: time ratios of 0.968 to 1.005 in a release build | No detectable leak at 41 rounds of 3 calls. Not a proof that the loop is branch-free. |
| Label cardinality, raw input in logs, and log injection | Held | None needed. |
| 8 threads sharing one inlet | Held | The inlet has no shared mutable state. |
| Declared length versus real length, and a verdict reused for other bytes | Held | Limitation: input in shared-writable memory could change between scan and digest. There is no `Verdict::binds` helper yet. |
| A caller returns `first_offset` to the sender | Open: the caller's choice | The sender then learns the position directly, and the full scan no longer hides it. |

The fix pass edited some existing tests and recorded each edit. Tests in hand_cases.rs and logging.rs that asserted the exact behaviour a fix changed now assert the new behaviour. In redteam.rs, the reference ban list grew to match the new bans, and a log-capture cache race was fixed.

Final run of `cargo test -p tack-inlet --all-targets` for this manual: 71 passed and 0 failed across 7 targets. The doctest passes separately, and `cargo clippy -p tack-inlet --all-targets -- -D warnings` is clean.

```text
     Running unittests src/lib.rs (target/debug/deps/tack_inlet-a6affdc3e6919659)
test result: ok. 11 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s
     Running tests/hand_cases.rs (target/debug/deps/hand_cases-f0e9726ed489621d)
test result: ok. 26 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 7.97s
     Running tests/logging.rs (target/debug/deps/logging-4172f678d50bc4e8)
test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s
     Running tests/properties.rs (target/debug/deps/properties-444cc55320bbd33d)
test result: ok. 5 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 16.52s
     Running tests/redteam.rs (target/debug/deps/redteam-e2187e76ca1219e8)
test result: ok. 24 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 75.95s
     Running tests/telemetry.rs (target/debug/deps/telemetry-bde3c05481a8fb29)
test result: ok. 3 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.01s
     Running tests/timing.rs (target/debug/deps/timing-766d8378526bc8e8)
test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 5.90s
```
