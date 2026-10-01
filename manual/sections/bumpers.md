## 3. Elastic Bumpers

Elastic Bumpers absorbs small parameter drift before work starts, at most 3 counted corrections per request by default, and refuses everything else.

*New design: reference implementation compiled and tested on Rust 1.94*

### Metaphor and goal

A loading dock has rubber bumpers along its edge. A truck that backs in slightly off line hits the rubber, and the rubber guides it into place. A truck that arrives at speed still stops at the concrete behind the rubber.

Callers drift the same way. One sends `"High"` where the rule says `"high"`; another sends 1500 milliseconds to a parameter declared in seconds. Refusing every such request makes the system brittle, and accepting anything makes it unsafe.

The bumper sits between those extremes and does three things:

1. It normalizes small drift into the canonical form the operator declared.
2. It records every change as a typed correction and counts it.
3. It refuses anything outside the elastic band with a CNS verdict: RETRY (fix and resend) or TERMINAL_BREACH (no fix applies).

It runs at ALPHA, the CNS gate position that checks a request before execution, so a refusal means the work never starts. Counting matters because a correction is the system changing what a caller asked for. Uncounted drift can hide a broken client, or an attacker walking a value toward its limit one nudge at a time.

Terms used below:

- **Soft band and hard band.** Two nested ranges per number. The soft band is the normal range; the hard band is the outer limit, the concrete.
- **Clamp.** Move a value to the nearest edge of a range.
- **NaN.** "Not a number", the floating-point value (IEEE 754 standard) produced by operations such as 0/0. Every `<`, `>` or `==` test with it is false.
- **Case folding.** Treating `HIGH` and `high` as the same word. Here only ASCII letters are folded.
- **SHA-256 hex digest.** A 64-character fingerprint of some bytes. It identifies a value without revealing it.
- **Fail closed.** Unknown or malformed input is refused, never passed.

This is a new design. Only the Sentinel Hash-Chain exists today, in sentinel_os. The bumper is a standalone Rust crate, `stack-bumpers`, and no Python repository calls it yet.

### Mechanism

The operator declares one rule, a `ParamSpec`, per parameter. Each rule has one of three shapes, and the shape decides which drift is absorbed and which is refused.

| Shape | Operator declares | Drift absorbed (one correction each) | Refused |
|---|---|---|---|
| Numeric | Four bounds, `hard_min <= soft_min <= soft_max <= hard_max`, and optional units | A value between a soft and a hard edge is clamped to the nearest soft edge. A value tagged with a declared alternate unit is converted. | NaN, infinity or a value past a hard edge: TERMINAL_BREACH. An undeclared unit: RETRY. |
| Enum | Canonical names plus aliases | Surrounding whitespace is trimmed, ASCII case is folded, and an alias becomes its canonical name. | Text that matches no declared name: RETRY. |
| String | A byte length range (`min_len`, default 1, to `max_len`), a trim policy and a character policy | Surrounding whitespace is trimmed under `TrimPolicy::Trim`. | Too long or too short, never truncated. Whitespace, control or format characters on a strict `Reject` string. All RETRY. |

The numeric bands, as drawn in the `NumericSpec` doc comment in src/spec.rs:

```text
  hard_min      soft_min                 soft_max      hard_max
     |-------------|========================|-------------|
     ^ TERMINAL    ^ clamp up to here       ^ clamp down  ^ TERMINAL
       below                                  to here       above
```

A `Bumper` holds the rules and a `BumperConfig`, and never changes after it is built, so one instance can serve every thread. Its one operation, `Bumper::normalize`, takes the whole parameter map. It returns `Normalized` (PASS, with values and the correction list) or `Rejection` (RETRY or TERMINAL_BREACH, with every trip found).

**A declaration.** The test fixture declares `timeout` in seconds: soft band 0.5 to 30, hard band 0 to 300. Milliseconds and minutes are accepted alternates (tests/common/mod.rs):

```rust
            ParamSpec::required(
                "timeout",
                NumericSpec::new(0.0, 0.5, 30.0, 300.0)
                    .unwrap()
                    .with_units(
                        "s",
                        &[("ms", UnitScale::Divide(1000.0)), ("min", UnitScale::Multiply(60.0))],
                    )
                    .unwrap(),
            ),
```

**Each rewrite is its own correction.** Two minutes becomes 120 seconds, then is clamped to 30, which costs two corrections. The fixture's `priority` rule declares `high` with the alias `hi`, so `" HI "` costs three (both tests in tests/corrections.rs):

```rust
fn unit_conversion_then_clamp_counts_two() {
    // 2 min = 120 s, over soft_max 30, under hard_max 300.
    let n = fixture().normalize(&req(&[("timeout", qty(2.0, "min"))])).unwrap();
    assert_eq!(n.get("timeout").unwrap().as_f64(), Some(30.0));
    assert_eq!(kinds(&n), ["unit_converted", "clamped"]);
}
```

```rust
fn enum_trim_fold_and_alias_each_count() {
    let n = fixture().normalize(&req(&[("priority", text(" HI "))])).unwrap();
    assert_eq!(n.get("priority").unwrap().as_str(), Some("high"));
    assert_eq!(kinds(&n), ["trimmed", "case_folded", "alias_resolved"]);
}
```

Counting per rewrite means a heavily drifted value spends more of the budget than a lightly drifted one.

**Why NaN is never clamped.** Rust's `f64::clamp(NaN, lo, hi)` returns NaN. A "clamp everything into range" step built on it lets NaN straight through while looking safe. The crate writes its own clamp (src/bumper.rs):

```rust
fn clamp_number(spec: &NumericSpec, x: f64) -> Result<(f64, Option<(f64, SoftEdge)>), TripReason> {
    if !x.is_finite() {
        return Err(TripReason::NonFinite);
    }
    let x = canonical_zero(x);
    if !(x >= spec.hard_min() && x <= spec.hard_max()) {
        return Err(TripReason::OutsideHardBand);
    }
    if x < spec.soft_min() {
        Ok((spec.soft_min(), Some((x, SoftEdge::Min))))
    } else if x > spec.soft_max() {
        Ok((spec.soft_max(), Some((x, SoftEdge::Max))))
    } else {
        Ok((x, None))
    }
}
```

The hard-band test is a negated "inside" test, which is true for NaN. NaN would fail it even without the first check. `canonical_zero` turns negative zero into positive zero, so equal values always have equal bits and hash the same.

**Check order.** Size comes first, then finiteness, then shape. A NaN sent to an enum or string parameter is therefore TERMINAL `non_finite`, not a repairable type mismatch (src/bumper.rs):

```rust
    fn normalize_one(&self, spec: &ParamSpec, value: &ParamValue, out: &mut Vec<Correction>) -> Result<NormalizedValue, TripReason> {
        if self.text_over_cap(value) {
            return Err(TripReason::InputTooLarge);
        }
        // NaN and infinities are TERMINAL whatever shape the parameter has,
        // so a non-finite number sent to an enum or string parameter is not
        // downgraded to a repairable type_mismatch.
        if is_non_finite(value) {
            return Err(TripReason::NonFinite);
        }
        let name = spec.name();
        match spec.kind() {
            SpecKind::Numeric(n) => normalize_numeric(name, n, value, out).map(NormalizedValue::Number),
            SpecKind::Enum(e) => normalize_enum(name, e, value, out).map(NormalizedValue::Variant),
            SpecKind::Text(s) => normalize_text(name, s, value, out).map(NormalizedValue::Text),
        }
    }
```

**Unknown keys fail closed.** A key that no rule declares is RETRY `unknown_param`, but its value is still checked for the TERMINAL conditions first. The raw key is never echoed; the trip carries its byte length and full SHA-256 digest (src/bumper.rs):

```rust
            let Some(spec) = self.specs.get(key) else {
                // The value under an unknown key is still checked for the
                // TERMINAL conditions, so an oversized or non-finite value
                // cannot hide behind the repairable unknown_param verdict.
                let key_over_cap = key.len() > self.config.max_input_bytes;
                let reason = if key_over_cap || self.text_over_cap(value) {
                    TripReason::InputTooLarge
                } else if is_non_finite(value) {
                    TripReason::NonFinite
                } else {
                    TripReason::UnknownParam
                };
                // The key is hashed at most once, and never when it is over
                // the cap, so refusal work stays bounded by the cap.
                let param = if key_over_cap {
                    log_trip(None, reason, LogInput::OverCap(key.len()));
                    TripParam::UnknownOverCap { len: key.len() }
                } else {
                    let sha256 = telemetry::sha256_hex(key.as_bytes());
                    log_trip(None, reason, LogInput::Digest(key.len(), &sha256));
                    TripParam::Unknown { len: key.len(), sha256 }
                };
                trips.push(Trip { param, reason });
                continue;
            };
```

**Request-level rules.**

- Unless the request is over `max_params`, every entry is evaluated even after one trips. The caller learns every problem in one round.
- The verdict is the most severe trip: any TERMINAL_BREACH wins, then any RETRY, and PASS only with no trips. This matches `resolve` in cns/gate.py.
- Corrections are summed across the request. Going over `correction_budget` adds one RETRY trip, `correction_budget_exceeded`.
- Corrections computed for a parameter that then trips are discarded and do not count against the budget.
- Normalization is idempotent (a second pass changes nothing) and monotone (clamping never reorders two values). Both are property-tested with 2048 cases each in tests/properties.rs.

**Every bound has a cap.** All caps live in `BumperConfig` (src/config.rs):

| Cap | Default | What exceeding it does |
|---|---|---|
| `correction_budget` | 3 | RETRY `correction_budget_exceeded`. Zero makes the bumper strict: any drift is RETRY. |
| `max_params` | 64 | A request over it is TERMINAL `too_many_params` before any entry is read. Declaring more rules than this fails the build. |
| `max_input_bytes` | 4096 | A text value, unit name or unknown key over it is TERMINAL `input_too_large`. The text is measured, never hashed. |
| `max_name_bytes` | 64 | A declared name over it fails the build. |
| `max_enum_names` | 64 | An enum with more names fails the build. |
| `max_units` | 8 | A numeric rule with more units fails the build. |

Copies are bounded too. Enum text longer than the longest declared name is refused before it is folded, and string text is copied only after its length check. A refusal lists at most `max_params` plus the rule count plus 1 trips.

**The Python that exists.** No Python version of the bumper exists. The closest existing code is `sanitize_context` in observe-perceive/observe_consolidated.py (line 237, read on 2026-10-01). It drops bad values instead of clamping them.

| Behaviour | `sanitize_context` (Python, exists) | Elastic Bumpers (Rust, new) |
|---|---|---|
| Number out of range | Dropped; the engine treats the signal as absent | Clamped inside the soft-to-hard margin, refused past the hard edge |
| NaN, infinity or non-numeric | Dropped | Refused with a verdict, never dropped |
| Key with no declared bounds | Passed through unchanged | RETRY `unknown_param` |
| Record of changes | Free-text notes. The one production call site, line 1435, binds them to `_context_notes` and never reads them. | A typed `Correction` list, returned to the caller and counted in metrics |
| Raw input in records | Notes include the dropped value | Never; byte length and full SHA-256 only |

Dropping suits a consumer that already handles absence well, as the observe-perceive engine does. It loses information, though: a reading of 101 against a limit of 100 becomes no reading. Clamping keeps the signal but changes it, so it is safe only inside a declared band with every change visible.

**Facts and assumptions.**

- Fact: the verdict strings `pass`, `retry`, `terminal_breach`, `alpha` and `omega` match cns/gate.py. They are redeclared in Rust because CNS is a Python package.
- Assumption: the caller parses its wire format into a map first. A map cannot hold duplicate keys, so that parser must refuse them.
- Assumption: the parser bounds the raw request size. The bumper caps what it reads and copies, but an oversized value is already in memory when it arrives.
- Assumption: callers tag units explicitly, as a `Quantity` with a unit name. The bumper never guesses a unit from a number's size.

### Failure mode and state resolution

Every trip resolves as reject: the request is refused whole and nothing is stored.

| Trip | Outcome | State resolution | Why |
|---|---|---|---|
| NaN or infinity in a number or quantity, under any key, declared or not | TERMINAL_BREACH (`non_finite`) | Reject | Not drift: an upstream arithmetic bug or a hostile input. Refused before any type check or arithmetic. |
| Finite number past the hard band after unit conversion, including an overflow such as `f64::MAX` minutes | TERMINAL_BREACH (`outside_hard_band`) | Reject | The concrete behind the rubber. No honest near miss lands here. |
| More than `max_params` (64) entries | TERMINAL_BREACH (`too_many_params`), exactly one trip | Reject | The cap sits far above any declared rule set. Refusing before reading any entry keeps the work bounded. |
| Text value, unit name or unknown key over `max_input_bytes` (4096), including a value under an unknown key | TERMINAL_BREACH (`input_too_large`) | Reject | Every string rule's `max_len` is at most this cap, so honest drift never reaches it. |
| Key that no rule declares (exact, case-sensitive match) | RETRY (`unknown_param`) | Reject | Fail closed. The caller can remove or rename the key. |
| Required parameter absent | RETRY (`missing_required`) | Reject | The bumper never invents a default. |
| Wrong value shape, such as text for a number | RETRY (`type_mismatch`) | Reject | Parsing text into a number is not drift correction. |
| Enum text that matches no name after trimming and folding | RETRY (`unknown_variant`) | Reject | Repairable by the caller. |
| Undeclared unit, any case variant of one, or a unit on a unitless parameter | RETRY (`unknown_unit`) | Reject | Guessing rescales silently: `ms` and `Ms` differ by a factor of a billion. |
| String over `max_len` after trimming | RETRY (`too_long`) | Reject | Truncation would change the meaning. |
| String under `min_len` (default 1) after trimming, including empty or whitespace-only text | RETRY (`too_short`) | Reject | A present parameter that carries nothing is a silent drop by another name. |
| Surrounding whitespace on a `Reject` string | RETRY (`whitespace_rejected`) | Reject | A silent trim could make two distinct identifiers equal. |
| Control, format or separator character (Unicode categories Cc, Cf, Zl, Zp) where the rule refuses them, the default for `Reject` | RETRY (`disallowed_char`) | Reject | Zero-width and right-to-left override characters make distinct identifiers look equal. |
| More corrections than `correction_budget` (3) | RETRY (`correction_budget_exceeded`) | Reject | Too much drift: the caller must fix its inputs instead of leaning on the bumper. |
| Bad rule or config at build time, such as an inverted band or colliding aliases | `Err(SpecError)`; no bumper is built | Reject at startup | An ambiguous rule is a rule an attacker gets to pick, so it is caught when declared. |

Reject is the only resolution because the bumper is a pure function: its output depends only on its rules and the request. It holds no state to roll back, knows no sender to quarantine, and one bad request is no reason to halt. A caller that tracks senders can escalate to quarantine using the trip counters below.

Workspace lints deny `panic`, `unwrap` and `expect` in library code, and no test or red-team input produced a panic. The one fallback in the verdict code, `unwrap_or(GateOutcome::Retry)` in `reject`, fails closed: an empty trip list would still read RETRY, never PASS.

### Observability and telemetry

The control room receives five metrics, two spans and seven alert rules, and no metric label or log line carries raw caller input.

Metrics go through the `metrics` facade, a shared Rust API where the application picks the exporter, such as Prometheus. Every label value comes from a closed enum in the crate. A label built from caller text would let a caller create unlimited time series, which is a cardinality attack on the metrics backend.

| Name | Type | Labels | Meaning |
|---|---|---|---|
| `tack_bumpers_requests_total` | Counter | `outcome`: pass, retry, terminal_breach | One per `Bumper::normalize` call, on every path, including the early return. |
| `tack_bumpers_trips_total` | Counter | `reason`: one of 14 trip labels; `outcome`: retry or terminal_breach, fixed by the reason | One per trip in a refused request. One request can add several. |
| `tack_bumpers_corrections_total` | Counter | `kind`: clamped, unit_converted, trimmed, case_folded, alias_resolved | One per correction, only in requests that passed. A refused request applies nothing. |
| `tack_bumpers_corrections_per_request` | Histogram | None | Corrections applied per passing request, from 0 up to the budget. |
| `tack_bumpers_normalize_duration_seconds` | Histogram | `outcome` | Wall time of one normalize call, in seconds. |

A span is a named, timed scope in a trace, and an event is one log record inside it. DEBUG and WARN are log levels; production usually enables WARN and filters out DEBUG. Caller text appears only as its byte length and full SHA-256 digest, never raw or truncated.

| Span or event | Level | Fields | When |
|---|---|---|---|
| Span `stack.bumpers.normalize` | DEBUG | `params` (entry count), `outcome`, then `corrections` or `trips` | Each `Bumper::normalize` call |
| Span `stack.bumpers.build` | DEBUG | None | Each `Bumper::new` call |
| Event `bumper trip` | DEBUG | `param` (rule name, absent for unknown keys and request-level trips), `reason`, `outcome`, `input_len`, and `input_sha256` or `input_over_cap=true` | Once per trip |
| Event `bumper trip` (budget) | DEBUG | `corrections`, `budget`, `reason` | A request over the correction budget |
| Event `bumper terminal breach` | WARN | `outcome`, `trips`, a count per TERMINAL reason, `retry_trips` | Exactly one per TERMINAL_BREACH request |
| Event `bumper correction` | DEBUG | `param`, `kind` | Once per applied correction |
| Events `bumper built` and `bumper spec refused` | DEBUG and WARN | Rule count, or the `SpecError` text, which is operator config | Each build |

A declared value's digest is computed only when DEBUG is enabled. An unknown key within the cap is hashed once in any case, because its trip record carries the digest. Text over `max_input_bytes` is never hashed, so refusal work stays bounded by the cap.

The tests in tests/telemetry.rs assert that each metric fires, using `DebuggingRecorder` (an in-memory recorder from `metrics-util`) under `metrics::with_local_recorder`. The test in tests/logging.rs captures real log output. It checks that the digest appears and that the raw input never does.

**Timing side channels.** The bumper is not constant time, so ANC (Active Timing Cancellation) must wrap the whole request boundary. Refused requests do extra work: one counter per trip, one SHA-256 per unknown key within the cap, and one WARN line per TERMINAL_BREACH.

Enum lookup cost varies with the input, and `Reject` strings are scanned per character. Dividing a subnormal number (a float so close to zero that it loses precision) can be slower on some CPUs. At DEBUG, each trip on declared text adds one SHA-256 of at most 4096 bytes, so the log level changes timing.

A request over `max_params` returns before reading any entry, which is observably faster. That is deliberate, because the cap is public.

Alert rules are Prometheus expressions over these metrics. The histogram alert needs the exporter to configure buckets, because the `metrics` facade does not set them.

```yaml
groups:
  - name: stack-bumpers
    rules:
      - alert: TackBumpersTerminalBreach
        expr: sum(rate(tack_bumpers_requests_total{outcome="terminal_breach"}[5m])) > 0
        for: 5m
        labels: {severity: warning}
        annotations: {summary: "Callers keep hitting the concrete (hard band, NaN or infinity, size caps). Each is refused; a steady rate means a broken or hostile upstream."}
      - alert: TackBumpersNonFiniteInput
        expr: sum(increase(tack_bumpers_trips_total{reason="non_finite"}[10m])) > 0
        for: 0m
        labels: {severity: critical}
        annotations: {summary: "NaN or infinity reached the ALPHA gate under some key. It was refused, but its upstream source needs finding."}
      - alert: TackBumpersRetryRatioHigh
        expr: sum(rate(tack_bumpers_requests_total{outcome="retry"}[15m])) / clamp_min(sum(rate(tack_bumpers_requests_total[15m])), 1e-9) > 0.05
        for: 15m
        labels: {severity: warning}
        annotations: {summary: "Over 5% of requests are refused as repairable, often after a client release renamed parameters."}
      - alert: TackBumpersCorrectionBudgetExhausted
        expr: sum(rate(tack_bumpers_trips_total{reason="correction_budget_exceeded"}[15m])) > 0
        for: 15m
        labels: {severity: warning}
        annotations: {summary: "Callers keep needing more corrections than the budget allows. They should fix their inputs."}
      - alert: TackBumpersDriftRising
        expr: sum(rate(tack_bumpers_corrections_total[1h])) / clamp_min(sum(rate(tack_bumpers_requests_total{outcome="pass"}[1h])), 1e-9) > 0.5
        for: 1h
        labels: {severity: info}
        annotations: {summary: "Passing requests average over 0.5 corrections each. Break down by kind; a slow walk toward an edge can be deliberate."}
      - alert: TackBumpersUnknownParamProbe
        expr: sum(rate(tack_bumpers_trips_total{reason="unknown_param"}[5m])) > 1
        for: 10m
        labels: {severity: warning}
        annotations: {summary: "A sustained stream of unknown keys looks like parameter-name enumeration. Trip records carry key digests for correlation."}
      - alert: TackBumpersSlowNormalize
        expr: histogram_quantile(0.99, sum by (le) (rate(tack_bumpers_normalize_duration_seconds_bucket[5m]))) > 0.001
        for: 10m
        labels: {severity: warning}
        annotations: {summary: "p99 normalize time is over 1 ms. Needs exporter histogram buckets."}
```

### Red-team results

The red team wrote 21 attacks as tests in tests/redteam.rs. Seven broke and were fixed, 14 held, and none produced a panic or a fail-open PASS.

Timings below are minimums over a few runs of a debug build, so read them as ratios, not as benchmarks.

| Attack | Result | Fix or limitation |
|---|---|---|
| Empty value for a required string: `""` under any trim policy, or whitespace-only text under `Trim` | Broke (major), then fixed | `StringSpec` gained `min_len`, default 1, checked after trimming. Short text is RETRY `too_short`. A minimum above `max_len` is refused at build. |
| Log flooding: 64 NaN entries, about 1 KiB, wrote 64 WARN lines | Broke (minor), then fixed | Per-trip lines moved to DEBUG. Each TERMINAL_BREACH request writes one WARN summary of counts, from one call site. |
| 64 MiB text over the cap: the WARN line hashed all of it, 1.32 s against 122 µs at the cap | Broke (minor), then fixed | Over-cap text is logged by length with `input_over_cap=true` and never hashed. Rerun: 42.9 µs against 43.6 µs at the cap. |
| Unknown keys over the cap were hashed twice in full, 2.00 times the cost of one pass | Broke (minor), then fixed | In-cap keys are hashed once and the digest reused. Over-cap keys are recorded by length only. Rerun: 364 µs against 3.05 s for one pass. |
| A 1 MiB text value or unit under an unknown key got RETRY, hiding it from the TERMINAL alert | Broke (minor), then fixed | The unknown-key path checks the value's size first. Over the cap is TERMINAL `input_too_large`. |
| NaN or infinity sent to an enum or string parameter, or under an unknown key, got RETRY | Broke (minor), then fixed | The finiteness check now runs before any type or rule lookup, on every path. The result is TERMINAL `non_finite`. |
| Look-alike identifiers on a `Reject` string: zero-width space, byte order mark, NUL, right-to-left override, ANSI escape (a terminal control sequence) | Broke (minor), then fixed in part | New `CharPolicy::RefuseControlAndFormat`, the default for `Reject`, refuses Cc, Cf, Zl and Zp as RETRY `disallowed_char`. Limits are listed below. |
| Random maps of 0 to 70 entries with float edge values, Unicode whitespace, near-miss keys and 5000-byte values | Held | Property-tested with 1024 cases. No panic, no PASS for a bad input, and every PASS output satisfied its rule. |
| Unit confusion: case, whitespace, NUL, zero-width and full-width spellings of `ms`; a bare number read by size; `f64::MAX` minutes | Held | Every spelling was RETRY `unknown_unit`. A bare 200 was clamped visibly to 30. The overflow was TERMINAL `outside_hard_band`. |
| Negative zero escaping through unit-conversion underflow | Held | No `-0.0` reached the output. The red team corrected one false positive in its own test: -1e-320 ms gives a subnormal, not -0.0. |
| Stacking corrections across parameters past the budget, and budget exhaustion masking a TERMINAL trip | Held | Five corrections were RETRY and exactly three passed. With a NaN added, the verdict was TERMINAL and both trips were reported. |
| Raw input or log injection (CR, LF, ANSI escapes) through every log path | Held | No marker reached the logs. The full SHA-256 digests were present. |
| Raw input echoed through the `Display` or `Debug` text of a `Rejection` | Held | No marker appeared. The unknown-key digest was present. |
| Label cardinality: 300 hostile keys carrying label-injection syntax | Held | Every label came from the closed enums. The series count stayed within 24. |
| Telemetry gaps on the early return and on refused corrections | Held | Both counters fired on the over-`max_params` path. A refused request created no `corrections_total` series. |
| 65 entries with 1 MiB keys, to force reading or hashing them | Held | TERMINAL with one trip in 39 µs, against 1.60 s to hash the keys once. |
| Unicode look-alikes against case folding: Kelvin sign, Turkish dotted capital I, sharp s, full-width k, combining accent | Held | All were `unknown_variant`, because only ASCII is folded. `KILL` still folded to `kill`. |
| Ambiguous rules: aliases colliding after folding, and more rules than `max_params` | Held | `AliasCollision` and `TooManyParams` at build time. |
| Every cap at `usize::MAX` and the budget at `u32::MAX`, with overflow checks on | Held | No panic and no wraparound. Limitation: `validate()` still accepts such extreme caps. |
| Trips placed at the first, middle and last keys | Held | All 5 were reported. 64 unknown keys plus 2 missing parameters gave 66 trips, within the bound. |
| One shared bumper across 8 threads, and changing the input after the verdict | Held | Results matched the single-thread run. `Normalized` owns its values. |

Known limitations:

- **Look-alike letters.** Confusable letters from other scripts (Cyrillic a for Latin a), combining marks and Hangul filler letters still pass a `Reject` string. Catching them needs a confusables table, which no allowed dependency provides.
- **Unicode version.** The Cf table is written by hand from Unicode 16.0. A code point added to Cf later passes until the table is updated.
- **Timing.** Work still varies with the path and the log level, as listed under timing side channels. ANC has to cover it.
- **Stateless.** The bumper cannot escalate repeated `unknown_param` trips to quarantine; a caller that tracks senders must.
- **Open questions.** Should key case drift (`Timeout` for `timeout`) be corrected? Should integer-only numbers and optional defaults be supported? Which histogram buckets should the kernel standardize?

`cargo clippy -p stack-bumpers --all-targets -- -D warnings` exits 0, and the doctest passes (1 passed). The final run of `cargo test -p stack-bumpers --all-targets` passed 122 tests in eight binaries: unit, corrections, float_edges, logging, properties, redteam, spec_construction and telemetry, in that order.

```text
test result: ok. 18 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s
test result: ok. 39 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s
test result: ok. 13 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s
test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s
test result: ok. 9 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.66s
test result: ok. 21 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 10.45s
test result: ok. 14 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s
test result: ok. 7 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s
```
