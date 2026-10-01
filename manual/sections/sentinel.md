## 7. Sentinel Hash-Chain

Edits to hashed fields, deleted rows and cut tails in sentinel_os's ledger are detectable offline; the Rust verifier matched Python in all 211 cases.

*Exists today in sentinel_os. The Rust verifier, tack-sentinel, is a new design: reference implementation compiled and tested on Rust 1.94*

### Metaphor and goal

Picture a factory logbook where every page carries a tamper seal, and each seal also covers the page before it. Tear out or rewrite one page and every seal after it breaks. The last seal is photographed, and the photo is locked in a safe outside the factory.

That photo is the head anchor. Without it, someone could cut off the last few pages and reseal the rest, and the shorter book would look perfect. With it, the auditor sees that pages are missing.

The goal is persistent memory whose every alteration, reordering or truncation can be detected offline. Offline means by an auditor who does not trust the running system and never connects to it. The auditor needs an exported copy of the ledger, the anchor file and the signing key.

| Term | Plain meaning |
|---|---|
| SHA-256 hash | A 64-character fingerprint of some bytes. Change any byte and the fingerprint changes unpredictably. |
| Hash chain | Each ledger row includes the previous row's hash in the bytes it hashes, so the rows link like the seals. |
| HMAC | A hash mixed with a secret key. Only a key holder can make one or check one. |
| Canonical form | The exact set of fields the writer hashed for a row, rebuilt the same way every time. |
| Export | A JSON file holding every ledger row, in the format `sentinel_os.ledger_export.v1`. |

Facts first. The Sentinel Hash-Chain is the only TACK component that exists today, written in Python in sentinel_os. The crate `tack-sentinel` is new: an independent second implementation of sentinel_os's offline verifier, written in Rust.

It reads the same export and anchor files and prints the same verdict words, without importing, calling or trusting any Python. It is read-only: it opens no database, writes no file and keeps nothing between calls. Two independent implementations that agree on every verdict are evidence that the rule is written down correctly.

The threat is someone who can change the database or the export but does not hold the attestation key. Examples are a database owner role, a restored backup or a rewritten table. A holder of the service key can rebuild the chain and re-sign the anchor, and neither tool can see that (sentinel_os `APPLY_verdict_receipts.md`, section 6).

### Mechanism

**The Python that exists.** The writer appends each row inside a Postgres transaction. An advisory lock, a database-wide mutex, serializes "read the last hash, compute the next one, insert", so two writers cannot fork the chain. When an anchor path is configured, the writer seals the new head and row count into the anchor file after each commit.

| File in sentinel_os | Role |
|---|---|
| `sentinel_os/governance/ledger_postgres.py` | The writer: `append` and its siblings, the anchor seal after each commit, and `verify_chain`, the online check. |
| `sentinel_os/canonical_fields.py` | Field lists the writer and every verifier share, such as `OPTIONAL_HASHED_FIELDS`. |
| `sentinel_os/twin_custody.py` | The witness: `canonical_form`, `recompute_current_hash`, `deep_verify_row`, `verify_rows` and the anchor functions. |
| `sentinel_os/governance/authorized_by_attestation.py` | HMAC signatures over a row's `authorized_by` claim (`abv2`, `abv3`), key fingerprints, and seed derivation. |
| `tools/verify_receipts.py` | The offline command. It prints one of six verdicts, then the first failing row and the reason. |

The row hash is SHA-256 over Python's `json.dumps` of the canonical form, written by this helper in `sentinel_os/sentinel_os/twin_custody.py`:

```text
def _ledger_dumps(obj: Any) -> bytes:
    # Byte-for-byte the serialization ledger_postgres.py uses at append time:
    # json.dumps(canonical_entry, sort_keys=True, default=str).encode()
    # (note: default separators, NOT the compact separators of canonical_json)
    return json.dumps(obj, sort_keys=True, default=str).encode()
```

| Verdict | What it means |
|---|---|
| `VERIFIED` | Every row and the anchor hold. |
| `TAMPERED` | A hash, a link or a signature does not hold. |
| `TRANSPLANTED` | A row's `subject_digest` is not the CNS digest of its own `input_data`, so a verdict was moved onto other content. |
| `SEED_FORGED` | A `shuffle_seed` does not re-derive under a held key, so the agent, not the server, chose the gate order. |
| `TRUNCATED` | The chain is shorter than, or differs from, its signed anchor. |
| `UNATTESTED` | An unsigned claim after the `attestation_policy` marker, or a signature by a key the auditor does not trust. |

A `shuffle_seed` is reserved for a future layer that shuffles gate order; the server derives it by HMAC from the previous hash. The `attestation_policy` marker is a chain row after which every `authorized_by` claim must be signed. A `subject_digest` is the CNS digest of the content a decision judged, recomputed by `src/cns.rs`.

The CNS encoding behind that digest is not reproduced here, because the CNS source is marked confidential.

**The Rust verifier in six steps.**

1. **Read JSON exactly as Python does.** `src/pyjson.rs` keeps Python's int and float types, its float printing and its default separators (comma-space, colon-space). One wrong byte changes every hash: a sensitivity check during the build, using compact separators, produced 192 mismatches.
2. **Rebuild each row's canonical form.** `src/canonical.rs` covers the 16 named record kinds plus the base row. A column Python reads as `row["x"]` must exist; one read as `row.get("x")` may be absent.
3. **Walk the chain in id order from the literal `"genesis"`.** Per row: the link, the hash, the subject digest, the seed, the signature, then an unsigned claim after the marker. This order names the attack rather than its side effect.
4. **Check keyed values in constant time.** Every signature, seed and anchor is an HMAC-SHA256. Comparisons use the `subtle` crate, so their time does not depend on where two digests first differ.
5. **Check the anchor.** Its HMAC must verify, and the row at the anchored count must carry the anchored head hash. Rows appended after the seal are expected and are not a finding.
6. **Assemble a `Report`.** The verdict word comes from the first finding, as Python prints it. The CNS outcome is the most severe across all findings.

The row hash streams the canonical form straight into SHA-256, so a large column is never copied (`src/canonical.rs`):

```rust
fn hash_canon(c: &CanonRef<'_>, skip: Option<&str>) -> String {
    let mut sink = Sha256Sink::default();
    write_entries(
        &mut sink,
        c.iter().filter(|(k, _)| skip != Some(**k)).map(|(k, v)| (*k, v.as_ref())),
        Separators::Python,
    );
    sink.hex()
}
```

The walk differs from Python in one deliberate way (`src/verify.rs`). Python stops at the first failing row. This walk stops there only for a TERMINAL_BREACH; after a repairable finding it keeps going and records the first later breach as an escalation.

```rust
    for (pos, row) in rows.iter().enumerate() {
        rows_checked = pos + 1;
        let checks = match (&first, &policy) {
            (None, _) => Checks::All,
            (Some(_), Some(p)) if p.enforced_key_held(keys) => Checks::All,
            (Some(_), _) => Checks::ExportOnly,
        };
        if let Some((reason, detail)) = check_row(row, prev, policy.as_ref(), keys, config, checks) {
            let terminal = reason.gate_outcome() == GateOutcome::TerminalBreach;
            let finding = Finding {
                reason,
                row_id: Some(row.id),
                row_position: Some(pos),
                detail,
            };
            if first.is_none() {
                first = Some(finding);
                if terminal {
                    break;
                }
            } else if terminal {
                escalation = Some(finding);
                break;
            }
        }
```

`Checks::ExportOnly` covers an auditor who lacks the key the policy enforces. Later rows then get only the checks that need no key: link, hash, subject digest and unsigned claim. Otherwise a seed checked under the wrong key would look like a forgery.

The anchor check compares digests with `subtle`'s constant-time equality (`src/attest.rs`). Signatures and seeds use the same comparison on a streamed payload.

```rust
pub(crate) fn digest_matches(key: &SecretKey, msg: &[u8], candidate: &str) -> bool {
    match hmac_hex(key, msg) {
        Some(expected) => bool::from(expected.as_bytes().ct_eq(candidate.as_bytes())),
        None => false,
    }
}
```

**Caps.** Every bound lives in `VerifierConfig` (`src/config.rs`). Nothing is sized by a number read from the input.

| Field | Default | What it bounds |
|---|---|---|
| `max_export_bytes` | 64 MiB | Export size, checked by length before the export is hashed or parsed. |
| `max_anchor_bytes` | 64 KiB | Anchor size. A real anchor is about 300 bytes. |
| `max_rows` | 1,000,000 | Rows in one export. |
| `max_keys`, `max_key_file_bytes` | 64 keys, 1 MiB | Keys from one key file, and the file's size. |
| `max_keyed_bytes` | 512 MiB | Bytes one export may feed to HMAC, summed over every key tried. |
| `json` (`ParseLimits`) | depth 256, 4,300 digits, 12 bytes per input byte plus 1 MiB | JSON nesting, integer length, and parser memory. |
| `accept_retired_key_signatures` | false | Whether a signature valid only under a retired key passes. |
| `accept_retired_key_anchor` | false | Whether an anchor sealed with a retired key vouches for the chain. |
| `min_anchor_entries` | 1 | Fewest rows a genuine anchor must seal to vouch for a non-empty chain. |

The last three are deliberate departures from the Python tool, which accepts all three cases. `VerifierConfig::python_compatible()` restores Python's behaviour for parity testing; it is not meant for audits.

**Parity with Python.** A differential test runs two programs on the same inputs and compares the answers. A script ran the real Python tool on 211 mutated exports and recorded its output for the Rust test to replay. Verdict word, row id, anchor note and exit code matched in every case, under `python_compatible()`.

Python printed TAMPERED 94 times, VERIFIED 76, TRUNCATED 22, UNATTESTED 10, SEED_FORGED 4 and TRANSPLANTED 3, and refused 2 for lack of a key. A separate corpus of 442 JSON texts matched Python's `json.dumps` byte for byte in both separator styles, and matched the CNS digest.

On one tampered export, with row 3's `reason` edited and nothing rechained, Python prints the first line and Rust the second:

```text
TAMPERED row=3 TAMPERED: hash-mismatch: recomputed 5dfa53b8e41e02ea.. != stored 7a0c6031e0bae39b..
TAMPERED row=3 hash mismatch: recomputed 5dfa53b8e41e02ea6044da75eeae6da56b7b630bc1ae6bbe309f323074a4e81b but the row stores 7a0c6031e0bae39b45119bc898f9639fc2b9a419b8e3abeac5a6a47a8c8e9568
```

The detail text differs on purpose. Python prints 16-character hash prefixes; this crate never shortens a hash or echoes raw row content.

**Stricter than Python.** Each case fails closed where Python accepts input no honest writer produces, or stops with an uncaught exception:

- duplicate JSON keys, unpaired surrogate escapes and nesting deeper than 256 are refused as malformed;
- a row `id` must be a JSON integer that fits in 64 bits;
- where Python raises an uncaught `AttributeError` or `TypeError`, such as on a `data` column holding a string, this crate reports TAMPERED;
- keys come only from the caller or `--key-file`, never from the `ICEBERG_LEDGER_ATTESTATION_KEY*` environment variables;
- a seed or signature that cannot possibly match is refused before any HMAC is computed.

**What VERIFIED covers.** Each record kind hashes a fixed set of columns, and only those. Columns such as `id`, `timestamp`, `call_sid` and `cassette_snapshot` can change without changing any hash. This is sentinel_os's ledger design, and `Report::unhashed_columns` lists the unhashed columns an export carried.

**Speed and memory.** On a 20,000-row, 22,924,415-byte export built with sentinel_os's own functions, both tools printed VERIFIED. Over seven interleaved runs, the Rust release build took a median 0.517 s, ranging from 0.501 to 0.558 s. Python took a median 0.828 s, ranging from 0.784 to 0.962 s.

Peak resident memory was about 163 MB for Rust and 97 MB for Python. These are single-host measurements on a shared 4-core machine, not a benchmark. The documented memory bound is about 12 times the export, so about 770 MiB at the default cap.

### Failure mode and state resolution

Every call returns a typed result. Library code has no `unwrap`, `expect` or `panic`, which workspace lints enforce. Property tests, which check a rule over many generated inputs, fed it random bytes and column values, and none panicked.

The reason, not the verdict word, decides the CNS outcome by one rule (`src/verdict.rs`). RETRY when the finding depends on what the auditor supplied, the anchor or the keys, so supplying it can change the answer. TERMINAL_BREACH when the export itself is inconsistent, so no correction repairs it.

```rust
    pub fn gate_outcome(self) -> GateOutcome {
        use Reason::*;
        match self {
            AnchorMissing | AnchorUnreadable | AnchorUnknownKey | AnchorUnverifiable | AnchorRetiredKey
            | AnchorMakesNoClaim | SignatureUnknownKey | SignatureUnverifiable | SeedUnverifiable => {
                GateOutcome::Retry
            }
            _ => GateOutcome::TerminalBreach,
        }
    }
```

RETRY resolves as reject: nothing changed, and the caller may resubmit with the correction. TERMINAL_BREACH resolves as quarantine: the export is not accepted as evidence, the finding is counted, and the report names the row for review.

| Trip | Outcome | State resolution | Why |
|---|---|---|---|
| TAMPERED `chain_broken`: `previous_hash` does not equal the prior row's `current_hash` | TERMINAL_BREACH | quarantine | A deleted, inserted or renumbered row breaks the link. The export is inconsistent, and no resubmission repairs it. |
| TAMPERED `hash_mismatch`: the recomputed hash differs from the stored one | TERMINAL_BREACH | quarantine | The row was edited after it was written. |
| TAMPERED `recompute_failed`: a required column is missing or has the wrong shape | TERMINAL_BREACH | quarantine | The canonical form cannot be rebuilt, so the row cannot match its hash. Python crashes on two of these shapes. |
| TAMPERED `signature_invalid`: a signature does not match under the key it names | TERMINAL_BREACH | quarantine | The claim, its chain position or, for `abv3`, the row content changed after signing. A rechained tail trips it too. |
| TRANSPLANTED `subject_digest_mismatch`, `subject_not_encodable` | TERMINAL_BREACH | quarantine | A verdict was moved onto content it was not issued for. Rechaining does not hide it, because the digest is recomputed from content. |
| SEED_FORGED `seed_not_derived`, `seed_retired_key` | TERMINAL_BREACH | quarantine | The server did not fix the gate order under a key the auditor trusts. |
| SEED_FORGED `seed_unverifiable`: a seed is present but no key is held | RETRY | reject | Supplying the key can change the answer. It is reachable only by calling `deep_verify_row` directly. |
| UNATTESTED `unsigned_after_policy` | TERMINAL_BREACH | quarantine | After the marker every claim must be signed. Stripping a signature and rechaining is exactly this attack. |
| UNATTESTED `signature_retired_key` | TERMINAL_BREACH | quarantine | The operator stopped trusting that key. This matches sentinel_os's `verify_chain` under enforcement, not `twin_custody`. |
| UNATTESTED `signature_unknown_key_after_policy` | TERMINAL_BREACH | quarantine | The auditor already holds the enforced key. The writer chose the fingerprint, so the named key need not exist. |
| UNATTESTED `signature_unknown_key`, `signature_unverifiable` | RETRY | reject | The export may be honest but signed by a key the auditor did not supply. Supplying it can change the answer. |
| TRUNCATED `anchor_missing`, `anchor_unreadable` | RETRY | reject | Without a readable anchor a cut tail looks perfect, so a pass is impossible. Python prints `TRUNCATED row=-` here. |
| TRUNCATED `anchor_unknown_key`, `anchor_unverifiable`, `anchor_retired_key` | RETRY | reject | The answer depends on the auditor's keys. The repair is an anchor sealed with a current, held key. |
| TRUNCATED `anchor_makes_no_claim`: a genuine anchor seals fewer than `min_anchor_entries` rows | RETRY | reject | An anchor sealed at ledger setup vouches for nothing. A newer anchor lets the check run. |
| TRUNCATED `anchor_invalid` | TERMINAL_BREACH | quarantine | The anchor's own HMAC fails, so the anchor was altered. |
| TRUNCATED `tail_missing` | TERMINAL_BREACH | quarantine | The export has fewer rows than the anchor sealed, so the tail was cut. |
| TRUNCATED `head_mismatch` | TERMINAL_BREACH | quarantine | The row at the anchored position carries another hash, so the chain was rebuilt after sealing. |
| Escalation: a later row breaches after a RETRY first finding | TERMINAL_BREACH | quarantine | A repairable finding must not hide a broken seal further down. |
| Refusal (`VerifyError`): too large, not JSON, not an export, bad rows or ids, too many rows, keyed work over budget | RETRY | reject | Malformed or over-budget input is never a pass. Nothing was read into any state; Python also prints no verdict for a malformed export. |
| Refusal `no_trusted_key_material` | RETRY | reject | Every signature and the anchor are HMACs, so no verdict could be checked. Python also refuses, with exit 2. |

A report's outcome is the most severe across the first finding, the anchor note (`also`) and the escalation (`src/verdict.rs`):

```rust
    pub fn gate_outcome(&self) -> GateOutcome {
        self.findings()
            .map(|f| f.reason.gate_outcome())
            .max()
            .unwrap_or(GateOutcome::Pass)
    }
```

The verifier never uses rollback or halt. It holds no state, so it has nothing of its own to restore; restoring the ledger is the operator's decision. Halting would let one bad export stop every other audit, which helps an attacker and protects nothing.

The CLI, `tack-sentinel-verify`, takes the Python tool's flags and exit codes. It exits 0 only on VERIFIED, and 1 on a finding or an unreadable export. It exits 2 when no trusted key is held or the arguments are wrong.

### Observability and telemetry

Metrics go through the `metrics` facade and spans through `tracing` (`src/telemetry.rs`). A counter only goes up; a histogram records a distribution, here of durations. Every label value comes from a closed Rust enum, because labels built from input would let an attacker create unlimited time series.

| Name | Type | Labels | Meaning |
|---|---|---|---|
| `tack_sentinel_verifications_total` | counter | `verdict`, `outcome` | One per export that reached a verdict. `outcome` is that of the most severe finding. |
| `tack_sentinel_trips_total` | counter | `verdict`, `reason` (23 values), `outcome`, `resolution` | One per finding: the first, the anchor note and the escalation. |
| `tack_sentinel_input_rejected_total` | counter | `reason` (10 values), `outcome` (always `retry`) | One per export or key set refused before a verdict. |
| `tack_sentinel_rows_checked_total` | counter | none | Rows the chain walk examined. It adds 0 when the anchor was missing or unreadable. |
| `tack_sentinel_verify_duration_seconds` | histogram | `outcome` | Wall time of one `verify_export` call. A refusal is recorded as `retry`. |

Each finding is counted with four closed labels (`src/telemetry.rs`):

```rust
fn record_trip(f: &Finding) {
    let r = f.reason;
    metrics::counter!(
        TRIPS_TOTAL,
        "verdict" => r.verdict().label(),
        "reason" => r.label(),
        "outcome" => r.gate_outcome().as_str(),
        "resolution" => r.resolution().as_str()
    )
    .increment(1);
}
```

Spans, each named `tack.sentinel.<operation>`:

- `tack.sentinel.verify_export`: `export_len`, `anchor_len`, and `export_sha256` as full hex for an export under the cap. At the end it records `verdict`, `outcome`, `anchor_entries`, `anchor_sealed_at` and `anchor_key_fingerprint`.
- `tack.sentinel.parse_export`: `export_len`.
- `tack.sentinel.parse_anchor`: `anchor_len`, plus `anchor_sha256` as full hex once the anchor is known to be within its cap.
- `tack.sentinel.verify_rows`: `rows`.
- `tack.sentinel.check_anchor`: no fields.

Inside `verify_export`, each finding emits one `warn` event with `finding` (first, also or escalation), `verdict`, `reason`, `outcome`, `resolution`, `row_id` and `row_position`. A refusal emits `reason` and `outcome`. `Verifier::new` emits a `warn` with `reason` when it refuses a key set with no trusted key.

The code never logs raw input, and a red-team test found none in any span or event. Report text shows a stored value as it is only when it is a 64-hex hash, a 16-hex key fingerprint or `genesis`. Anything else appears as its type, length and full SHA-256.

The one short identifier is the 16-hex key fingerprint, which the Python wire format fixes inside signatures and anchors. It names a key publicly and is not an integrity hash. Key `Debug` output uses the full 64-hex key digest instead.

The `tack-sentinel-verify` binary installs no metrics recorder and no tracing subscriber, so on its own it emits nothing. The telemetry reaches a control room only when the library runs inside a host process that installs both. The duration alert reads `_bucket` series, so the host's exporter must publish that metric as a bucketed histogram, not as a summary.

The alert rules ship as `telemetry::ALERT_RULES`. Here they are as a Prometheus rule file, with expressions copied from the crate:

```yaml
groups:
  - name: tack-sentinel
    rules:
      - alert: TackSentinelTamperEvidence
        expr: sum(increase(tack_sentinel_trips_total{outcome="terminal_breach"}[15m])) > 0
        labels: {severity: critical}
        annotations: {summary: "An export failed a hash, link, signature, subject binding, seed or anchor-head check, or carries a signature by a retired key or by an unknown key after the attestation policy. The ledger or its export was altered. Quarantine the export and compare it with the witness copy."}
      - alert: TackSentinelTruncation
        expr: sum(increase(tack_sentinel_trips_total{verdict="truncated",outcome="terminal_breach"}[15m])) > 0
        labels: {severity: critical}
        annotations: {summary: "The chain is shorter than its signed anchor, or the anchored head is not in it, or the anchor itself was altered. Rows were cut or the chain was rebuilt."}
      - alert: TackSentinelVerificationCannotComplete
        expr: sum(increase(tack_sentinel_verifications_total{outcome="retry"}[1h])) + sum(increase(tack_sentinel_input_rejected_total[1h])) > 3
        for: 15m
        labels: {severity: warning}
        annotations: {summary: "Verifications keep ending in RETRY: the anchor is missing, stale, empty or sealed with a retired key, a key is not held, or exports are malformed or over budget. Audits are not happening even though nothing tripped."}
      - alert: TackSentinelNoCleanVerification
        expr: absent_over_time(tack_sentinel_verifications_total{verdict="verified"}[26h])
        labels: {severity: warning}
        annotations: {summary: "No export verified cleanly in 26 hours. For a daily audit job this means the job stopped or every run failed."}
      - alert: TackSentinelSlowVerification
        expr: histogram_quantile(0.99, sum by (le) (rate(tack_sentinel_verify_duration_seconds_bucket[1h]))) > 60
        for: 30m
        labels: {severity: info}
        annotations: {summary: "Verification p99 above one minute. The ledger has outgrown the export cap planning, or the host is starved."}
```

This is an offline tool, so Active Timing Cancellation (ANC) does not apply as it is used today. Two things would leak if it ever served requests. The walk stops at the first breach, so its run time reveals where the breach is.

An over-cap export is also refused by its length, faster than a readable one is verified. Report details carry value lengths too. Such a caller should return only the verdict word to an untrusted party and pad its response time with ANC.

### Red-team results

The red team wrote 24 attacks as tests in `tests/redteam.rs`. Against the first build, 15 broke or partly broke and 9 held. After the fixes, all 24 pass.

Masking means a harmless-looking finding that hides a serious one. Amplification means a small input that costs far more memory or time than its size suggests.

| Attack | Result | Fix or limitation |
|---|---|---|
| A forged claim after the last anchor, signed `abv3` with a made-up fingerprint | Broke, then fixed | It was RETRY, asking for a key that does not exist. New `signature_unknown_key_after_policy` is TERMINAL_BREACH when the auditor holds the enforced key. |
| Masking: an unknown-key signature on row 1 hides an unrechained edit on row 8 | Broke, then fixed | The walk stopped after 1 of 16 rows with RETRY. It now keeps checking and reports the edit as `Report::escalation`. |
| A cut tail plus an unknown-key signature on row 1 | Broke, then fixed | The TERMINAL anchor finding was ignored. `Report::gate_outcome` now takes the most severe finding, and each finding gets a warn event. |
| A signature valid only under a retired key | Broke, then fixed | It passed. It is now `signature_retired_key`, TERMINAL_BREACH, unless `accept_retired_key_signatures` is set. |
| An anchor sealed with a retired key vouches for a cut chain | Broke, then fixed | It printed VERIFIED. It is now `anchor_retired_key`, RETRY, unless `accept_retired_key_anchor` is set. |
| A `Verifier` built from retired keys only | Broke, then fixed | It printed VERIFIED. `Verifier::new` now requires at least one trusted key. |
| Amplification: 16 MiB of small integers in an unused top-level field | Broke, then fixed | Peak memory was 32.0 times the input. Unknown members are now syntax-checked without being built; a rerun measured 0.02 times. |
| Amplification: a 16 MiB signature made of dots | Broke, then fixed | Peak memory was 18.5 times the input. Signatures are now split by borrowing; a rerun measured 1.02 times. |
| Amplification: a 512 KiB `record_kind` plus a seed, with 64 keys held | Broke, then fixed | Verification was 40.6 times slower. Shapes are checked before any HMAC, and `max_keyed_bytes` caps keyed work. The test now requires 4 times or less. |
| A 64 MiB export over a 1 KiB cap | Broke, then fixed | Refusal took 1.34 s, because the export was hashed first. Length is now checked first, and the test requires under 100 ms. |
| A 64 MiB anchor, with a tracing subscriber listening | Broke, then fixed | Refusal took 1.41 s, hashing the anchor for a span field. The digest is now recorded only after the size check. |
| A command-line argument that is not UTF-8 | Broke, then fixed | The CLI panicked with exit 101 and echoed the bytes. It now reads OS strings, exits 2 and prints only the length. |
| A genuine anchor that seals zero rows | Broke, then fixed | A cut, rewritten chain printed VERIFIED. It is now `anchor_makes_no_claim`, RETRY, with `min_anchor_entries` defaulting to 1. |
| Replaying an old but genuine anchor | Broke, partly fixed | `Report::anchor` now shows the anchored count, seal time and key. Limitation: a chain cut back to that count still verifies. |
| Changing unhashed columns such as `timestamp` | Partly broke, documented | A 27-year move still verifies, by sentinel_os design. `Report::unhashed_columns` now names such columns. |
| Nesting at the 256-level cap through every recursive path, on a 1 MiB stack | Held | No stack overflow. |
| Any JSON value in any of 13 columns, or the column dropped (property test, 256 cases) | Held | No panic, and no row with a broken hash or link verified. |
| Random edits of 1 to 5 bytes to the export (property test, 256 cases) | Held | No panic. |
| Newlines, ANSI escapes and a fake `VERIFIED row=1` planted in hashes, signatures, claims and anchor fields | Held | Report text never echoed them. Non-hash values appear as type, length and digest. |
| Metric label cardinality under every hostile input | Held | Every metric name and label value came from the closed sets. |
| Raw input or shortened hashes in spans | Held | Every span is `tack.sentinel.*`, and every `*sha256` field is 64 hex. |
| One `Verifier` shared by 8 threads, 30 runs each | Held | Every result matched the single-thread result. The verifier holds no mutable state. |
| Digest comparison time by position of the first wrong character | Held | No detectable difference at 2,000 runs per side. This is a smoke test only, because HMAC time dominates. |
| Anchor counts off by one, a 4,000-digit count, and row ids at the 64-bit limits | Held | Each gave the expected finding, and an id of 2^63 is refused. |

One red-team test was changed after the fixes. `redteam_unhashed_columns_change_under_verified` now asserts VERIFIED plus `timestamp` in `Report::unhashed_columns`, the documented behaviour. Two pre-existing tests now run under `python_compatible()`, because the new defaults refuse inputs Python accepts; their assertions are unchanged.

Known limitations that remain:

- **Key holders.** A holder of the service key can rebuild the chain and re-sign the anchor. HMAC cannot tell key holders apart, which is the sentinel_os design.
- **Unhashed columns.** VERIFIED says nothing about `timestamp`, `id`, `call_sid` or `cassette_snapshot`. Covering them needs a sentinel_os ledger format change.
- **Masking without the enforced key.** If the auditor lacks the key the policy enforces, forged seeds or signatures behind an early RETRY row stay RETRY. Supplying that key turns them into TERMINAL_BREACH.
- **Stale anchors.** A chain cut back to an older genuine anchor still verifies, unless `min_anchor_entries` is raised or the auditor reads `Report::anchor`.
- **Signature length.** The proposed 86-byte signature cap was not applied, because Python reports an over-long fingerprint as UNATTESTED, not TAMPERED. Borrowing alone fixed the memory cost.
- **Rows before the marker.** Unsigned claims written before the first `attestation_policy` row are not judged, as in Python.
- **Keys in memory.** Keys sit in an ordinary `Vec<u8>`, neither locked in memory nor wiped on drop.
- **Alert expressions.** Two issues were found while writing this section, by reading the rules; neither was run against Prometheus. `TackSentinelVerificationCannotComplete` adds two `sum()` results, so it cannot fire while either counter has no series; wrapping each side in `(... or vector(0))` fixes that.
- **Stalled-job alert.** `TackSentinelNoCleanVerification` uses `absent_over_time`, but a long-running host keeps exporting the counter after its first VERIFIED, unless its exporter expires idle series. Adding `sum(increase(tack_sentinel_verifications_total{verdict="verified"}[26h])) == 0` as an alternative would catch a stalled job.
- **Test strength.** The byte-edit and column-value attacks are property tests with 256 cases each, not coverage-guided fuzzing.

`tests/properties.rs` adds nine properties: four at 256 cases and five at 48. `cargo clippy -p tack-sentinel --all-targets -- -D warnings` finished with no warnings.

The final run of `cargo test -p tack-sentinel --all-targets` passed 77 tests in seven targets: unit, binary, acceptance, differential, properties, redteam and telemetry, in that order.

```text
test result: ok. 15 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s
test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s
test result: ok. 21 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.72s
test result: ok. 3 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.82s
test result: ok. 9 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.72s
test result: ok. 24 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 3.56s
test result: ok. 5 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.01s
```
