# What a stack-sentinel verdict establishes

This note says exactly what the offline verifier checks, what each verdict
word means, and what none of them means. It also defines the machine-readable
scope record (`sentinel-scope/1`) that a downstream consumer must read beside
the verdict. Every claim below names the test that holds it; a claim with no
test is marked as such.

## 1. The one integrity claim

The record states it in a fixed field:

```
"integrity_claim": "hash chain over hashed columns only"
```

`VERIFIED` means all of the following, and nothing more:

* every row's **hashed columns** (section 5) recompute to its stored
  `current_hash`, and every `previous_hash` links to the row before, from the
  literal `"genesis"`;
* every present `subject_digest` is the CNS digest of the row's own
  `input_data`; every present `shuffle_seed` re-derives, and every present
  signature verifies, under a key the auditor trusts;
* after the chain's first `attestation_policy` marker, no row makes an
  `authorized_by` claim without a signature;
* a head anchor was supplied, its HMAC verifies under a trusted key (its
  optional `name` included), it seals at least one row, and the row at its
  count carries its head hash.

`VERIFIED` does **not** mean:

* **that every stored column is intact.** Unhashed columns change freely
  under `VERIFIED` (section 5).
* **that every row is bound by a key.** Rows after the anchor's count are
  covered only by the unkeyed chain, which anyone able to write the file can
  recompute. An older genuine anchor verifies a chain cut back to its count.
* **that the original action was legitimate.** The ledger records what the
  writer recorded. Anyone holding the service key can re-sign a rebuilt chain
  and a new anchor (`APPLY_verdict_receipts.md`, section 6).
* **anything about execution.** The ledger holds decisions, not evidence
  that any decision was carried out.

## 2. The verdict words

The six words, their exit codes and the default CLI output are unchanged
(`acceptance::the_cli_prints_what_the_python_tool_prints_and_exits_the_same_way`,
`scope::the_cli_json_flag_prints_the_scope_line_with_the_same_exit_codes`).

| word | establishes | reasons (`reason` in the record) |
|---|---|---|
| `VERIFIED` (exit 0) | section 1, nothing more | none |
| `TAMPERED` (exit 1) | a hashed column, a link or a signature does not hold | `chain_broken`, `hash_mismatch`, `recompute_failed`, `signature_invalid` |
| `TRANSPLANTED` (exit 1) | a decision's subject binding fails | `subject_digest_mismatch`, `subject_not_encodable`, `subject_digest_missing` (only with `require_subject_digest`) |
| `SEED_FORGED` (exit 1) | a `shuffle_seed` does not re-derive under a trusted key | `seed_not_derived`, `seed_retired_key`, `seed_unverifiable` |
| `TRUNCATED` (exit 1) | the chain is shorter than, or differs from, its anchor; **or no anchor could be judged** | `tail_missing`, `head_mismatch`, `anchor_missing`, `anchor_unreadable`, `anchor_invalid`, `anchor_unknown_key`, `anchor_unverifiable`, `anchor_retired_key`, `anchor_makes_no_claim` |
| `UNATTESTED` (exit 1) | an unsigned claim after the policy marker, or a key the auditor does not trust | `unsigned_after_policy`, `signature_unknown_key`, `signature_unknown_key_after_policy`, `signature_retired_key`, `signature_unverifiable` |

`TRUNCATED` covers both "the chain was cut" and "the verifier cannot judge
the anchor". Tell them apart by `reason` and `gate_outcome`: a `retry`
outcome means the finding depends on what the auditor supplied (anchor or
keys) and a correction may change it; `terminal_breach` means the export
itself is inconsistent.

## 3. The scope record, `sentinel-scope/1`

`Verifier::verify_export_scoped` returns it, `ScopedReport::to_json` renders
it, and `stack-sentinel-verify --json` prints it as one line instead of the
verdict lines. The rendering is deterministic: compact separators, keys
sorted, non-ASCII escaped (golden file
`tests/fixtures/scope/pre_receipts_verified.json`). No raw export content and
no column or key name taken from the export appears in it.

| field | type | meaning |
|---|---|---|
| `schema` | string | always `sentinel-scope/1` |
| `verdict` | string | one of the six words |
| `reason` | string or null | the first finding's reason code; null for `VERIFIED` |
| `row` | int or null | the first finding's row `id`; null when it names no row |
| `gate_outcome` | string | `pass`, `retry` or `terminal_breach`: the most severe over every finding |
| `integrity_claim` | string | the fixed claim of section 1 |
| `rows_checked` | int | rows the walk examined |
| `rows_total` | int | rows in the export |
| `export_sha256` | string | full SHA-256 hex of the export bytes |
| `subject_digest_required` | bool | whether this run ran with `require_subject_digest` (section 6) |
| `hashed_columns` | list of string | column paths that entered some row's hash (union over kinds) |
| `unhashed_columns` | list of string | column paths some row carried outside its hash (union over kinds) |
| `other_unhashed_columns` | bool | some row carried a column outside the shipped set (its name is not reported) |
| `by_record_kind` | list of object | per kind present: `kind`, `rows`, `hashed`, `unhashed` (section 5) |
| `anchor` | object or null | `entries` (decimal string), `sealed_at`, `key_fingerprint` (16-hex label, not a MAC), `vouched` (bool); null when no anchor was readable |
| `also` | object or null | the anchor finding printed beside a row finding: `reason`, `row`, `verdict` |
| `escalation` | object or null | a later TERMINAL_BREACH finding after a RETRY first finding: `reason`, `row`, `verdict` |
| `limitations` | list of string | codes from section 4, in a fixed order |

Column paths: a shipped column name (the whole value), `<column>.<key>` for
a named key of a mapping the kind hashes by key, and, in the unhashed lists
only, `data.*` or `input_data.*` for "keys of this mapping other than the
hashed ones". A name can be in both union lists when kinds differ;
`by_record_kind` resolves it.

## 4. Limitation codes

Computed from the export, the anchor and the result. A consumer must handle
every code it receives and must treat an unknown code as a reason not to
rely on the verdict.

| code | present when |
|---|---|
| `unhashed_columns_present` | `unhashed_columns` is non-empty or `other_unhashed_columns` is true |
| `rows_after_last_anchor_unkeyed` | fewer rows are sealed by a vouched anchor than the export holds (or no anchor vouched) |
| `anchor_stale_possible` | an anchor vouched: the verifier cannot tell it is the latest one |
| `anchor_not_verified` | no anchor vouched (missing, unreadable, or HMAC not accepted) |
| `partial_rows_checked` | `rows_checked < rows_total` |
| `decision_rows_without_subject_digest` | some `governance_decision` row has no `subject_digest` and this run did not judge it |
| `no_execution_record` | always: the ledger holds no execution evidence |

Tests: `scope::scope_record_carries_the_schema_claim_and_counts`,
`scope::scope_record_names_the_failing_row_and_the_partial_walk`,
`scope::an_anchor_over_a_prefix_leaves_later_rows_unkeyed`,
`scope::a_missing_anchor_is_reported_as_not_verified`,
`properties::rows_after_a_prefix_anchor_are_covered_only_by_the_unkeyed_chain`
(an edited and rechained row after a prefix anchor verifies, and the record
says `rows_after_last_anchor_unkeyed`; an edit before the anchor's count is
`head_mismatch`).

### How a consumer must interpret a result

1. Never treat a bare `VERIFIED` as complete record integrity. Read the
   scope record; a consumer that cannot is not entitled to more than "the
   hashed columns chain".
2. Require `schema == "sentinel-scope/1"` and reject any other schema.
3. Before relying on any column, check it is in the `hashed` list of that
   row's kind in `by_record_kind` and not in its `unhashed` list. A decision
   keyed on an unhashed column (`timestamp` for an obligation horizon,
   `call_sid` for idempotency, `cassette_snapshot`) has no integrity from
   this verifier.
4. Handle every limitation code. In particular,
   `rows_after_last_anchor_unkeyed` means the newest rows can be rewritten
   by anyone who can write the file; require a fresher anchor for them.
5. Check `subject_digest_required` matches your policy; with it false, a
   decision without a digest is unbound (`decision_rows_without_subject_digest`).
6. `no_execution_record` is always present: never infer that an action
   happened from this verdict.

## 5. Known unhashed columns

What each record kind hashes is the `sentinel_os` ledger design, reproduced
as it is (`twin_custody.canonical_form`, `canonical_fields.py`). The lists
below come from `canonical::hashed_columns` and
`canonical::hashed_mapping_keys`, each citing the Python by line.
`scope::the_reported_hashed_paths_are_exactly_what_moves_the_hash` checks, for
every kind, that each reported hashed path moves the row hash and every
other shipped column or mapping key does not.

Never hashed on any kind: `id`, `timestamp`, `cassette_snapshot`, `call_sid`
(`current_hash` is the hash itself).

Mappings hashed by key only (every other key is `data.*` / `input_data.*`):

| kind | hashed keys |
|---|---|
| `governance_decision` | `data.parameter_changed`, **truthiness only** (`bool(...)`) |
| `regulatory_cassette_inserted`, `_removed` | `data.mode`, `data.regulation` |
| `regulatory_disclosure` | `data.regulation`, `.check`, `.action`, `.subject` |
| `outcome_harm_event` | `data.harmed_decision`, `.harm_kind`, `.subject`, `.discovered_at` |
| `recommendation_shadow_run` | `data.recommendation_kind`, `.subject` |
| `human_selection` | `data.human_selection`, `.rationale` |
| contract kinds | `data.<CONTRACT_CANONICAL_FIELDS[kind]>` |
| `attestation_policy` | `data.key_fingerprint`, `.enforced_at` |
| `observed_event` | `input_data.<OBSERVED_EVENT_CANONICAL_FIELDS>` (13 keys) |

A base row (no `record_kind`, or one the ledger does not know, such as
`legacy`) hashes `action_type`, `node`, `previous_value`, `applied_value`,
`reason`, all of `data` and `previous_hash`; its `record_kind` is unhashed.
Typed kinds other than `governance_decision` do not hash `reason` or `node`
(except `decision_supersession` and `attestation_policy`, which hash
`reason`). Optional hashed
fields (`OPTIONAL_HASHED_FIELDS`) enter only on kinds that apply them, and
only when truthy: on such a kind a null value is covered (making it truthy
moves the hash) but a change between falsy values (null, `""`) is not; on a
base row, `observed_event` or `attestation_policy` they are never hashed.

`scope::every_known_unhashed_column_changes_under_verified_and_is_listed`
edits each of these on a fixture row (`timestamp`, `call_sid`,
`cassette_snapshot`, `reason` and `node` on a `cassette_binding`, an extra
`data` key on a decision, an extra `input_data` key on an observed event,
`record_kind` and a null `authorized_by` on a legacy row): the verdict stays
`VERIFIED`, and the record lists the column as unhashed for that kind.

## 6. Options that change what is judged

* `VerifierConfig::require_subject_digest` (default false, the Python
  behaviour). When true, a `governance_decision` after the first row that
  shows the receipts layer had begun (an `attestation_policy` marker, or a
  decision carrying a `subject_digest`) must carry `subject_digest`, else
  `TRANSPLANTED` `subject_digest_missing` (terminal). A chain with neither
  shows no boundary and is not judged; the record then reports
  `decision_rows_without_subject_digest`. Tests:
  `scope::a_stripped_subject_digest_passes_when_not_required_as_today`,
  `scope::a_stripped_subject_digest_is_transplanted_when_required`,
  `scope::requiring_the_digest_leaves_honest_and_pre_receipts_exports_verified`.
* The retired-key and zero-entry-anchor options are described in
  `config.rs`; `VerifierConfig::python_compatible` restores the Python
  behaviour for parity testing only.

## 7. Named anchors

An anchor may carry a `name` that the Python writer signs with the other
fields. The verifier includes it in the HMAC payload exactly as
`twin_custody.head_anchor_payload` does; an unnamed anchor signs and
verifies byte for byte as before. Tests: `named_anchor::*`, over anchors
written by the real Python code (`tests/fixtures/named_anchor/generate.py`).
The name itself is not reported in the scope record.

## 8. Not established by any test here

* That the hashed columns mean what the writer intended: the verifier
  checks bytes, not semantics.
* Which person stands behind a key.
* Cross-language agreement beyond the checked-in differential corpus: the
  live cross-check against `sentinel_os` (`tests/crosscheck.rs`) is ignored
  unless that checkout is available.
