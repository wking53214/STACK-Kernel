# stack-receipt: execution receipts and their verifier

Status: new crate, Phase 4b of CNS-KERNEL-INTEGRATION-HARDENING, under
decision C (a versioned receipt and verifier in STACK-Kernel; the
sentinel_os ledger untouched). `stack-admission` uses it; no service calls the admission pipeline yet.
Every claim below names the test that proves it; anything not tested is
listed as a limitation.

## 1. Evidence, not authority

A receipt records what the kernel saw, what it believed authorized an
action, what it actually ran, and how the run ended. It grants nothing.

| What a receipt proves | What it does not prove |
|---|---|
| The holder of the receipt key signed these records, in this order, with these contents (`tests/sign.rs`, `tests/tamper.rs`) | That a human stood behind any key |
| The decision root is the root of the recorded seats and verdicts (`tests/decision.rs`) | That `SuperGate.decide` issued the decision (its proof is an HMAC under a process-local key) |
| The capability binding the kernel recorded is consistent with the proposal (`tests/tamper.rs`) | That the capability's issuer signature was valid (not re-verified here) |
| The attempted action equals the authorized one (`tests/tamper.rs`) | That the action was legitimate, wise or wanted |
| The chain is intact from genesis to its head | That the log was not rolled back to an earlier head |
| A `Completed` outcome: the worker exited 0 within the deadline and sent a well-formed frame | That the result is genuine: the result is the worker's own claim |

A receipt never reports success because a request was accepted
(`verify::a_receipt_never_reports_success_because_a_request_was_accepted`).
A hash chain proves order and integrity only. A signature proves that
the holder of the key signed, nothing about identity.

## 2. Lifecycle

One log per kernel. One execution has events in this order and no other
(`verify::verify_execution`; every deviation in `tests/tamper.rs`):

| Stage | Written when | Carries | Terminal |
|---|---|---|---|
| `proposed` | the request arrives, before any check | subject (identity, CNS digest), decision evidence (root, seats, verdicts exactly as CNS rendered them), proposed action, optional Trident handoff provenance, optional native digest | no |
| `authorized` | `stack-authority` returned an `AuthorizedAction` | capability binding (digest, id, issuer, issuer key id, policy ref, audience, subject digest, decision root, one-time, authorized-at), authorized action | no |
| `rejected` | the kernel refused, before or after authorization | reason | yes |
| `attempted` | BEFORE the payload starts (write-ahead) | actual action (operation, resource, argument digest, all as INTENDED by the producer: the executor delivers neither the arguments nor the resource to the worker, so none of them is proof of what the worker received; see R2-X-02), started-at | no |
| terminal | the run ended | outcome, completed-at, monotonic elapsed | yes |
| `interrupted` (an outcome) | the kernel stopped the run before any kill | reason | yes |
| `unknown` (an outcome) | the kernel could not observe the end | reason | yes |
| `recovered` | a restarted kernel found the execution open (its last record was `proposed`, `authorized` or `attempted`), before it accepts any work | the last stage it found | yes |

Terminal outcomes: `completed`, `terminated` (kill sent and confirmed),
`termination_unconfirmed` (kill sent, worker not confirmed dead: it may
still be acting), `timed_out`, `crashed`, `seccomp_violation`,
`resource_limit`, `result_missing`, `exited_non_zero`,
`result_oversized`, `interrupted`, `unknown`. Only `completed` is
success, and `completed` means exactly: exit 0 within the deadline with
a well-formed result frame. The result bytes are SELF-REPORTED by the
worker; a hostile worker can forge a well-formed result. The result
digest is recorded as self-reported and the verifier lists it as such
even when the supplied bytes match
(`verify::a_matching_result_digest_is_still_self_reported_and_termination_unconfirmed_is_flagged`).

The supervised executor's `SpawnFailed`, `SupervisorError` and
`InvalidLimits` map to `unknown` with a reason: after `attempted` was
written the kernel cannot claim more than that nothing is known.

### The write-ahead rule

The recorder's `Execution<S>` handle is consumed by every transition, so
the order above is a type error to violate (`tests/recorder.rs`).
`attempt` returning `Err(AttemptUnrecorded)` means the caller must not
execute; `finish` returning `Err(TerminalUnrecorded { observed_outcome })`
means the attempt stays open in the log and the verifier reports the
execution as `INCOMPLETE` with outcome `unknown`
(`tamper::a_receipt_generation_failure_leaves_an_incomplete_unknown_execution`).
A kernel killed between `attempted` and the terminal event leaves the
same state (`log::a_process_killed_between_attempted_and_terminal_leaves_the_attempt_open`,
a real SIGKILL of a child process).

## 3. Record schema and canonical encoding, `stack-receipt/1`

Big-endian integers; `u16`-length-prefixed UTF-8 strings with no control
character; `u16`-counted lists; one tag byte per enum variant and per
optional field; 32-byte digests raw. Bounds: identifiers 1 to 128 bytes,
free text up to 1024, operation up to 64, at most 64 seats and 64
verdicts, record up to 64 KiB (`record.rs`, `tests/encoding.rs`).

```text
canonical record
  "stack-receipt/1\n"   16 bytes
  sequence              u64, from 1, strictly plus one
  prev_hash             32 bytes, previous record hash or genesis
  kernel_id             str
  execution_id          16 bytes
  recorded_at_ms        u64, the writer's clock
  key_id                32 bytes, receipt key id (inside the hashed region)
  provenance            component str, version str, host_id str
  event                 tag u8 then the event's fields (encode.rs)
record_hash   = SHA-256("stack-receipt/record-hash/1\n" || canonical record)
genesis       = SHA-256("stack-receipt/genesis/1\n")
key_id        = SHA-256("stack-receipt/key-id/1\n" || public key), full, never shortened
signature     = Ed25519("stack-receipt/signature/1\n" || record_hash), verified strictly
```

The encoding is binary rather than the CNS text rendering because records
carry raw digests, signed integers and nested optional structures and
this crate's verifier is their only reader; the CNS rendering is used
where it is normative, for the decision root. Determinism, exact round
trip, and field-by-field sensitivity (72 single-field mutations, every
one changes the hash, none collide) are in `tests/encoding.rs`.

Decision root: `subject_digest({"seats": [...], "verdicts": [{"gate",
"position", "outcome", "subject", "digest"}, ...]})` under the CNS
length-prefixed rendering, reproduced in `cns.rs` and held to the shared
CNS vectors (31 of 38 lie in this crate's float-free, `i64` domain and
all reproduce byte for byte, `tests/cns_vectors.rs`) and to seven roots
produced by the real `cns_composition.super_gate.SuperGate.decide`
(`tests/fixtures/cns-decision-roots.json`, generated read-only by the
committed script under `python3 -I` at CNS commit
`4acd8f958a091900d43f553eba7fe83f7d33c4d6`; `tests/decision.rs`).

### Format version 2: supervisor-observed facts (D1-C)

Status: implemented and tested in this crate and in `stack-admission`, which writes it whenever the supervisor reports its facts. A run refused before spawn, or an executor that reports none, still writes version 1 (see "Wired" below).

A terminal event may carry the two facts the supervisor observed
(`cpp/CONTAINMENT.md`, "Supervisor-observed facts and payload claims"):
`exit_observed` (`not_observed`, `exited` with a code, `signaled` with a signal,
`killed_by_supervisor` with a signal, `unreaped`) and `frame_status`
(`not_read`, `valid`, `missing`, `malformed`, `oversized`, `trailing`,
`conflicting`). They are written under their own tag so version 1 is untouched:

| | Version 1 | Version 2 |
|---|---|---|
| record tag | `stack-receipt/1\n` | `stack-receipt/2\n` |
| event | every event, terminal tag 5 (`Event::Terminal`) | only the terminal tag 6 (`Event::TerminalObserved`): the version 1 terminal body, then `exit_observed` (u8, plus i32 for exited, signaled, killed) and `frame_status` (u8) |
| written by | `Recorder::finish` (unchanged) | `Recorder::finish_observed` |

A record has one encoding: the decoder refuses a version 2 body under the
version 1 tag and the reverse (`tests/observed_v2.rs`
`a_record_has_one_encoding_so_the_version_and_the_event_must_agree`), and a tag
it does not know (`stack-receipt/4`) is `BadTag`. A log may hold both versions.

Compatibility: a version 1 log verifies unchanged. `tests/fixtures/v1_log.bin` was
written by the version 1 writer before this format existed; `tests/compat_v1.rs`
asserts that the current writer still produces those exact bytes for version 1
events, that the log verifies as `VERIFIED_WITH_LIMITATIONS` with no finding, and
that the facts it cannot show come out as the limitation
`supervisor_observed_facts_not_recorded`, not as a failure.

Verification of a version 2 terminal (`Check::ObservedFactsConsistentWithOutcome`):
`completed` needs `exited` 0 and `valid`; `result_missing` needs `exited` 0 and a
frame that is not `valid`; `unreaped` goes with `termination_unconfirmed` and
with nothing else. A violation is the rejecting finding
`observed_facts_contradict_outcome`. `valid` beside `timed_out`, `crashed` or
`exited_non_zero` is allowed: the frame is a fact about the pipe, not about success.
The facts are the supervisor's observation. Nothing in a receipt, version 2 or
not, makes the result bytes anything but the worker's own claim
(`result_is_self_reported` stays a limitation of every `completed`).

Wired (Step 1, R3-K-01): `stack-admission` records its terminal through
`Executor::run_observed` and `Recorder::finish_observed`, so a real admission run
writes a version 2 terminal (`tests/observed_terminal.rs`). An executor that
observes nothing, and a run refused before spawn, still write a version 1 terminal
and carry `supervisor_observed_facts_not_recorded`.

### Format version 2 additions: worker identity and use evidence (Step 2, R-7, G-5)

Status: implemented and tested (`tests/worker_use_evidence.rs`,
`stack-admission/tests/worker_use_native.rs`, `stack-authority/tests/use_evidence.rs`).
Two further version 2 events, under the same `stack-receipt/2` tag and the same
one-encoding rule; version 1 records are untouched (`tests/compat_v1.rs` pins the
bytes).

| Event | Version 1 tag byte | Version 2 tag byte | Addition |
|---|---|---|---|
| `Attempted` | 4 | 8 | after `started_at_ms`: `image_sha256` (32 bytes), then the limits the supervisor was given as explicit fields: `wall_clock_deadline_ns`, `cpu_seconds`, `address_space_bytes`, `max_output_bytes`, `file_size_bytes` (u64 each), `nofile` (u32). 76 bytes. |
| `Authorized` | 2 | 7 | after the action: the use store's evidence, a kind byte then `not_provided`, `non_durable_memory`, `durable` (record hash, position u64, head) or `no_new_record` (position, head) |

The limits are written explicitly (76 bytes) and not as a digest: a 32-byte digest of the
limits plus the 8-byte deadline is 40 bytes, but only the explicit form lets a verifier
state under which limits the worker ran without already knowing them. The deadline
is recorded in nanoseconds, exactly as applied; `AppliedLimits::wall_clock_deadline_ms`
rounds up. They are the limits the kernel handed the supervisor. A zero
`cpu_seconds` or `nofile` means the supervisor derived the value, and the derived
value is not reported back (so it is not in the record).

`image_sha256` is the digest the supervisor pinned at construction and re-verifies
against the image it executes on every run (R2-K-21). It is the kernel's statement
of which program ran; a verifier that holds the release record checks it with
`Expectations::worker_image_sha256` (finding `worker_image_mismatch`), and the
limits with `Expectations::worker_limits` (finding `worker_limits_mismatch`). With
neither supplied the verifier says `worker_expectation_not_supplied`.

Use evidence: `stack-authority`'s `UseStore::record_use_evidenced` returns where
the use was recorded. `FileUseStore` gives the new record's hash, its position
(from 1) and the store head; `MemoryUseStore` gives the labeled marker
`non_durable_memory`, never a position; a store that predates the method gives
`not_provided`. The verifier reports absence in a version 1 `Authorized` as the
limitation `use_evidence_not_recorded`, `not_provided` as
`use_evidence_not_provided_by_store`, `non_durable_memory` as
`use_evidence_non_durable`, and a durable record at position 0 as the finding
`use_evidence_malformed`. The evidence is what the store REPORTED. It is not
checked against the store file here, and two executions claiming the same
position are not cross-checked (planned).

### Format version 3: recovery after a restart (I-6)

Status: implemented and tested in this crate and in `stack-admission`, which writes it when it starts.

A crash leaves an execution open: its last record is `proposed`, `authorized` or
`attempted` and nothing closes it, so the verifier reports the whole log
`INCOMPLETE` for as long as the log exists. A kernel that starts over a log
closes those executions with one `Recovered` record each, written before it
accepts any work (`Recorder::recover_open_executions`, called from
`Admission::new`).

| | Version 3 |
|---|---|
| record tag | `stack-receipt/3\n` |
| event | only tag 9 (`Event::Recovered`): one byte, the last stage found (1 `proposed`, 2 `authorized`, 3 `attempted`) |
| written by | `Recorder::recover_open_executions` |

The record claims one thing: that a restart found the execution open at that
stage. It does not claim an outcome. If the last stage was `attempted`, the
payload may have run to completion, may have been cut off, or may never have
started, and the verifier reports `execution.outcome` as `unknown` and lists the
limitation `execution_recovered_outcome_unknown`. It never reports such an
execution as `completed`, `timed_out` or any other outcome. If the last stage
was `proposed` or `authorized` nothing ran, and the execution has no outcome.

The verifier does not take the record's word for the stage. It compares the
named stage with the stage the chain shows (`recovery_claim_matches_chain`); a
mismatch is the reject finding `recovered_stage_mismatch`, so a record cannot
hide that a payload may have run. A terminal, a rejection or a second recovery
after a `Recovered` record is `duplicate_terminal`. Each recovery is also an
info finding, `recovered_after_restart`, so a consumer sees that the execution
was closed by a restart and not by the run.

Effect on the log's state: the recovered execution no longer holds the log
`INCOMPLETE`. A log whose only open executions were recovered verifies
`VERIFIED_WITH_LIMITATIONS`, as every log does. The unknown outcome is carried
by `execution.outcome` and the limitation, not by the state. The log-level field
`unknown_outcomes` lists every execution whose outcome is unknown, so a consumer
that reads only the state and that field cannot miss one (see "What a consumer
must not infer").

Recovery relies on a single writer: it assumes no other process is still driving
the executions it finds open. `FileReceiptLog` holds an exclusive advisory lock,
so a second kernel over the same file is refused. A log type that cannot list its
records (`ReceiptLog::acknowledged_records`, which refuses by default) makes the
kernel fail to start rather than skip recovery. If a write fails partway through,
the kernel does not start; the records already written stay, and the next start
recovers the rest. The tests are `tests/recovered.rs` (this crate) and
`crates/stack-admission/tests/recovery.rs`.

Cautions found in the independent review:

* Recovery reads the records through the log's own locked file handle, not by
  path, so a file swapped in at the path after `open` is not read
  (`recovery_reads_the_log_the_kernel_holds_not_whatever_is_at_the_path`).
* `Recorder::recover_open_executions` is public and the recorder is `Clone`.
  Call it once at startup, before any execution is proposed. Called while
  executions are in flight in the same process, it would close live ones, and
  their genuine later records would be rejected (`duplicate_terminal`).
* Recovery writes one record (two fsyncs) per open execution, with no bound, so
  a log with very many open executions makes start-up slow. It fails closed, not
  open.
* Recovery does not weaken the rollback limitation, but it hides one symptom of
  it. An attacker who restores an older copy of the log that ends mid-execution,
  at or after the auditor's anchor, no longer leaves `INCOMPLETE`: the next
  start signs a `Recovered` record and the log verifies. Only an anchor taken at
  or after the cut sequence catches it (`anchor_mismatch`).
* A version 3 log cannot be read by code that predates version 3 (`BadTag`, so
  the whole log reads as corrupt). There is no downgrade path.
* A recovered `attempted` execution verifies as `VERIFIED_WITH_LIMITATIONS`, the
  same state as a completed one, and differs only in `execution.outcome` and the
  limitation. A consumer that gates on `state` alone accepts an execution whose
  outcome nobody knows.

### Which native component each digest refers to (G-4, R-6)

Four digests sit in a record and are never merged or truncated:

| Field | Refers to | Checked by |
|---|---|---|
| `subject.digest` | the CNS content, recomputed by the kernel from the payload's `subject` | `Expectations::subject_content` (`subject_digest_mismatch`) |
| `handoff` (sender fingerprint, sequence, nonce, assurance) | the Trident handoff: the MAC verification result. The Trident verified the envelope MAC under a shared key and the kernel records that it did so under the Production profile. The MAC itself is not in the record | not re-checked here (`handoff_provenance_not_rechecked`) |
| `native_digest` (label and digest) | optional: the sender's own digest of its native record, for example a Sentinel ledger row hash, passed in the payload's `native_digest` field and authenticated by the Trident MAC with the rest of the payload | `Expectations::native_digest` (`native_digest_mismatch`); without it `native_component_not_verified` |
| `capability.cap_digest` | the signed capability bytes | not re-checked (`capability_signature_not_rechecked`) |

The kernel does not recompute the native digest: no Sentinel verification hook
exists in admission (planned). Tampering with the native digest and tampering with
the subject digest are caught by different expectations and neither finding implies
the other (`tests/worker_use_evidence.rs`
`tampering_the_native_digest_is_caught_and_the_subject_digest_still_checks_out` and
`tampering_the_cns_subject_digest_is_caught_and_the_native_digest_still_checks_out`;
the same through a real run in `stack-admission/tests/worker_use_native.rs`).

### Outcome vocabulary

The campaign names map onto the existing outcomes without a rename
(`OutcomeKind::campaign_name`; the full table, with the stage names and the
in-memory `RUNNING`, is in `cpp/CONTAINMENT.md`). `as_str` is unchanged.

| Campaign | Receipt outcome kind(s) |
|---|---|
| `COMPLETED` | `completed` |
| `TIMED_OUT` | `timed_out` |
| `TERMINATED` | `terminated` |
| `TERMINATION_UNCONFIRMED` | `termination_unconfirmed` |
| `CRASHED` | `crashed`, `seccomp_violation`, `resource_limit`, `exited_non_zero` |
| `RESULT_INVALID` | `result_missing` (exit 0, frame not valid), `result_oversized` |
| `INTERRUPTED` | `interrupted` (a recorded deliberate stop) and, for a host that died mid-run, an `attempted` with no terminal event, which the verifier reports as `INCOMPLETE`, outcome `unknown` (`terminal_missing`) |
| `UNKNOWN` | `unknown` |
| `RUNNING` | none: an in-memory state, never a terminal receipt event |
| `PROPOSED`, `AUTHORIZED`, `REJECTED`, `ATTEMPTED` | stages `proposed`, `authorized`, `rejected`, `attempted` |

## 4. The log file, `stack-receipt/log/1`

Magic (32 bytes), two hashed header slots (generation, committed length,
chain head), then frames of `u32` length, canonical record, signature,
record hash. An append writes the frame, `sync_data`, writes the next
slot, `sync_data`, then returns. The design is `stack-trident`'s replay
store, reimplemented: with the committed length in a hashed slot, an
edited length prefix on the final frame cannot pass as a crash. Open
takes the exclusive advisory lock, verifies every frame and signature
under the keys given, adopts one complete chain-valid frame past the
committed length (a crash between frame sync and slot write), discards a
torn frame whose readable prefix is what the writer would have written,
and fails closed on anything else. A write failure poisons the log until
it is reopened. `tests/log.rs` covers each case, including every single
byte flip of a clean file (fails closed, or, only for a flip inside the
newest header slot, yields exactly the same records).

## 5. Verifier

`verify_receipt_chain(records, execution_id, trusted, expectations)` and
`verify_log(records, trusted, expectations)`; `verify_log_bytes` parses
the file format first. Output: `Verification { state, execution, scope,
findings }`, with `to_json()` so no consumer gets a bare word (register
D-07, kept outside this repo).

### States, exactly

| State | Meaning |
|---|---|
| `VERIFIED` | every check this verifier can perform passed AND `scope.not_checked` is empty |
| `VERIFIED_WITH_LIMITATIONS` | every check performed passed; `scope.not_checked` lists what was not |
| `REJECTED` | at least one check failed; the receipt is not evidence of what it claims |
| `INCOMPLETE` | the chain is intact but the execution has no terminal event and no `Recovered` record, or never reached an attempt |
| `UNKNOWN` | nothing to judge: no record carries the execution id, or the log is empty |

`VERIFIED` is defined strictly and is never produced in practice:
`action_legitimacy_not_established` always applies
(`verify::verified_is_strictly_every_check_passed_and_nothing_unchecked`).
A consumer MUST read `scope.not_checked` before relying on a
`VERIFIED_WITH_LIMITATIONS` result, and MUST read `execution.outcome`:
a `timed_out`, `terminated` or rejected execution verifies as well as a
`completed` one, because the receipt is honest about what happened. The
state is about the evidence; the outcome is about the action. An
attempt with no terminal event is `INCOMPLETE` with outcome `unknown`
and is never success. Once a restart has closed it with a `Recovered` record
(format version 3) the state is no longer `INCOMPLETE`, but the outcome is still
`unknown` and it is still never success. A log can therefore verify
`VERIFIED_WITH_LIMITATIONS` while executions in it have an unknown outcome:
`LogVerification::unknown_outcomes` (the JSON field `unknown_outcomes`, execution
ids as hex) lists them in order of first appearance, and a consumer that gates on
the state MUST also require it to be empty or accept each id. It lists an attempt
with no terminal, an attempt a restart closed, and a recorded `Unknown` terminal.
It does not list an execution a restart closed before its attempt (it never ran),
a rejection, or `termination_unconfirmed` (that outcome has its own finding).
`REJECTED` dominates `INCOMPLETE`.

### Scope

`checked`: `hash_chain`, `sequence_monotonic`, `kernel_id_consistent`,
`signatures` (under a trusted, active key whose window contains the
record's claimed time), `stage_order`, `decision_root_recomputed`,
`subject_digest_recomputed` (content supplied), `roster_complete`
(non-empty, no duplicate seat, one bound PASS verdict per seat, alpha
before omega; for `authorized` executions), `roster_policy` (policy
supplied), `capability_binding_consistent`, `action_consistent`
(proposed, authorized and actual agree), `audience` (expected audience
supplied), `outcome_consistent_with_stage_order`,
`result_digest_recomputed` (result bytes supplied),
`recovery_claim_matches_chain` (a `Recovered` record is present).

`not_checked`: `action_legitimacy_not_established` (always),
`capability_signature_not_rechecked`,
`decision_proof_not_checkable_hmac_is_process_local`,
`native_component_not_verified`, `handoff_provenance_not_rechecked`,
`subject_content_not_supplied`, `roster_policy_not_supplied`,
`audience_not_supplied`, `result_bytes_not_supplied`,
`result_is_self_reported` (every `completed`), `timestamps_are_writer_claims`,
`log_rollback_not_detectable_without_anchor`, `torn_tail_ignored`,
`supervisor_observed_facts_not_recorded`, `worker_identity_not_recorded`,
`worker_expectation_not_supplied`, `use_evidence_not_recorded`,
`use_evidence_not_provided_by_store`, `use_evidence_non_durable`,
`execution_recovered_outcome_unknown` (an execution a restart closed after its
`attempted` record).

### Findings

Each carries a code, a severity (`reject`, `incomplete`, `info`), the
record sequence when one applies, and a detail that never contains input
content. Reject: `log_corrupt`, `sequence_gap`, `prev_hash_mismatch`,
`kernel_id_mismatch`, `receipt_key_untrusted`, `receipt_key_revoked`,
`receipt_key_outside_window`, `bad_signature`, `missing_proposed`,
`duplicate_proposed`, `attempted_without_authorized`,
`terminal_without_attempted`, `duplicate_terminal`,
`event_after_terminal`, `stage_order_violation`,
`decision_root_mismatch`, `empty_roster`, `duplicate_seat`,
`required_seat_missing`, `required_seat_not_passed`, `verdict_not_pass`,
`verdict_unbound`, `verdict_for_unseated_gate`, `verdict_count_mismatch`,
`omega_before_alpha`, `duplicate_verdict`, `seat_not_judged`,
`duplicate_gate_name`, `required_seat_wrong_position`,
`capability_decision_root_mismatch`,
`capability_subject_mismatch`, `authorized_action_differs_from_proposed`,
`actual_action_differs_from_authorized`, `audience_mismatch`,
`subject_digest_mismatch`, `result_digest_mismatch`,
`recovered_stage_mismatch`. Incomplete:
`terminal_missing`, `not_attempted`, `not_authorized`. Info:
`empty_log`, `execution_not_found`, `worker_may_still_be_running`,
`torn_tail_discarded`, `trailing_frame_adopted`, `recovered_after_restart`.

### What a consumer must not infer

* `VERIFIED_WITH_LIMITATIONS` is not "the action was right". It is "these
  records are intact, signed by the receipt key, internally consistent,
  and say what `execution.outcome` says".
* A `completed` outcome is not "the result is genuine". The worker wrote
  the result; the kernel checked only its framing.
* A verified decision root is not "CNS issued this decision". The root
  binds seats and verdicts; the issuance proof is process-local to CNS.
  The roster the policy REQUIRED is the verifier's own input, because a
  CNS root does not commit to it (register D-11).
* A missing finding is not a passed check. Read `scope.checked`.
* An intact chain is not a current chain. See rollback below.
* A log that verifies `VERIFIED_WITH_LIMITATIONS` after a restart is not "every
  run in it finished". An execution a restart closed has outcome `unknown`: the
  payload may have run. Check `unknown_outcomes` (empty, or each id accepted),
  and read `execution.outcome` and the limitation
  `execution_recovered_outcome_unknown`; the state alone does not tell you.

### The tamper matrix (`tests/tamper.rs` unless noted)

| Scenario | Test | Result |
|---|---|---|
| result digest edited without the key | `tampered_result_digest_without_the_key_is_rejected` | REJECTED `bad_signature` |
| every byte of every record flipped and rehashed | `every_byte_of_every_record_flipped_and_rehashed_is_rejected` | REJECTED, each flip |
| every byte of a real log file flipped | `every_byte_of_a_log_file_flipped_is_rejected_or_identical` | REJECTED, or identical records (newest slot only) |
| record removed, reordered, duplicated, last dropped | `a_record_removed_reordered_or_duplicated_is_rejected` | REJECTED; last dropped: INCOMPLETE `unknown` |
| swapped signature | `a_swapped_signature_is_rejected` | REJECTED |
| wrong key, or a key trusted for another kernel | `a_wrong_receipt_key_is_rejected_even_when_trusted_for_another_kernel` | REJECTED |
| expired, not yet valid, revoked, back-dated | `an_expired_not_yet_valid_or_revoked_receipt_key_is_rejected` | REJECTED |
| insider edits result digest | `an_insider_tampered_result_digest_is_caught_only_with_the_result_bytes` | REJECTED with bytes; limitation without |
| transplanted subject digest | `a_transplanted_subject_digest_is_caught_only_with_the_content` | REJECTED with content; limitation without |
| subject changed after decision | `a_subject_changed_after_the_decision_is_rejected_without_any_content` | REJECTED |
| decision changed after authorization (three shapes) | `a_decision_changed_after_authorization_is_rejected` | REJECTED; the third shape is a different capability, listed as not rechecked |
| empty roster | `an_empty_roster_is_rejected` | REJECTED |
| missing required seat | `a_missing_policy_required_seat_is_rejected_only_when_the_policy_is_supplied` | REJECTED with policy |
| RETRY, TERMINAL_BREACH verdict | `a_retry_or_terminal_breach_verdict_under_an_authorized_execution_is_rejected` | REJECTED |
| unbound pass, unseated verdict | `an_unbound_pass_and_an_unseated_verdict_are_rejected` | REJECTED |
| Completed without Attempted / Authorized / Proposed | `completed_without_attempted_or_without_authorized_is_rejected` | REJECTED |
| actual action differs from authorized | `an_actual_action_that_differs_from_the_authorized_one_is_rejected` | REJECTED |
| Completed after timeout, duplicate terminal, event after terminal | `completed_after_a_timeout_or_any_second_terminal_is_rejected` | REJECTED |
| duplicate Proposed / Authorized / Attempted | `a_second_proposed_or_authorized_or_attempted_is_rejected` | REJECTED |
| wrong audience, wrong kernel, spliced record | `a_wrong_audience_or_kernel_is_rejected_when_expected` | REJECTED |
| terminal missing | `the_terminal_event_missing_is_incomplete_and_unknown_from_records_and_from_a_real_crash` | INCOMPLETE `unknown` |
| receipt generation fails after Attempted | `a_receipt_generation_failure_leaves_an_incomplete_unknown_execution` | INCOMPLETE `unknown` |
| kernel SIGKILLed between Attempted and terminal | `log::a_process_killed_between_attempted_and_terminal_leaves_the_attempt_open` | INCOMPLETE `unknown` |

## 5a. Supported topology

[tested] unless marked.

* **Single process.** One recorder owns the log and appends in order.
* **Several processes on ONE host, one at a time.** `FileReceiptLog` holds an
  exclusive advisory lock for its life; a second process fails at open with
  `LogError::Locked` and so cannot write. Two real processes opening one log:
  exactly one holds it
  (`log_failure_modes::two_processes_open_one_log_exactly_one_holds_it`).
  A local operating-system lock on one machine: not concurrent writing, not
  distributed consensus.
* **Multiple hosts** [not supported]. No replication, no shared log, no
  consensus. [BLOCKED: no multi-host environment to test in.]

A process that dies after `Attempted` is written leaves the attempt open and
the verifier reports INCOMPLETE with an unknown outcome, never success
(`log_failure_modes::attempt_written_and_the_process_aborts_is_incomplete_never_success`,
`attempt_written_and_the_handle_dropped_is_incomplete_never_success`, and
`log::a_process_killed_between_attempted_and_terminal_leaves_the_attempt_open`).
A frame present twice fails closed on open
(`a_frame_appended_twice_byte_for_byte_fails_closed_on_open`,
`a_frame_inserted_twice_inside_the_committed_chain_fails_closed_on_open`).
Rollback to an earlier valid state is not detected from the file: the
verifier sees a crash (INCOMPLETE) and lists
`log_rollback_not_detectable_without_anchor`; comparing `head()` with a head
recorded elsewhere detects it
(`rollback_to_an_earlier_state_reads_as_a_crash_and_is_detected_only_against_an_external_head`).
Unavailable storage at open fails closed
(`real_unavailable_storage_at_open_fails_closed`); a failing append mid-run is
tested through a failing log wrapper at the trait (see section 6).

## 6. Limitations, stated

* One receipt key per kernel at a time; rotation is two overlapping
  anchors in `TrustedReceiptKeys` and both keys at `FileReceiptLog::open`
  while old records remain.
* One active writer per log, enforced by an advisory lock that a process
  ignoring it can bypass.
* Rollback to an earlier committed state (a valid header slot rewritten,
  and the frames after it removed) is undetectable from the file alone
  (`log::rollback_to_an_earlier_committed_state_is_not_detected_by_the_file_alone`).
  A zeroed or invalid slot is detected: the log reports corruption.
  `Recorder::head()` and `FileReceiptLog::head()` expose the chain head. An
  auditor who saved a `Head` earlier, somewhere the writer cannot reach, can
  pass it as `Expectations::anchor`. The verifier then rejects a log that no
  longer holds that record (`log_does_not_reach_anchor`, `anchor_mismatch`;
  `tests/anchor.rs`). A rollback to a point at or after the anchor stays
  undetectable, so the limitation is still listed. Same class as D-09 and D-28 (D-28 is kept outside this repo).
* A log file that is deleted or truncated to zero length is created again as
  a new, empty log at the next open, with no error and no marker that an
  earlier log existed.
* `MAX_LOG_BYTES` (1 GiB) is checked when a log is opened or parsed, not when a
  record is appended. A log can grow past it and then fail to reopen.
* A holder of the receipt key can write any consistent history,
  including back-dated records; the key's trust window bounds the
  claimed times, not the real ones. Every timestamp is a writer claim.
* The capability's issuer signature, the Trident handoff MAC and the
  producer's native digest are carried, not re-verified.
* No subject content outside the float-free `i64` CNS domain can have
  its digest recomputed here; the verifier then reports
  `subject_content_not_supplied` only if nothing was given, and the
  caller must not pass an approximation.
* A write or sync failure poisons the log; no test injects such a
  failure at the file layer (the failing-log wrapper injects it at the
  trait).
* No timing uniformity is claimed anywhere.

## 7. Public API for the integration crate

```rust
// Writer
FileReceiptLog::open(path, kernel_id: &str, keys: &[ReceiptPublicKey]) -> Result<FileReceiptLog, LogError>
ReceiptSigner::from_secret_bytes(&[u8; 32]) -> Result<ReceiptSigner, WeakKey>
Recorder::new(Box<dyn ReceiptLog>, ReceiptSigner, Provenance, Box<dyn Clock>) -> Result<Recorder, RecordError>
Recorder::propose(&self, ExecutionId, Proposed) -> Result<Execution<ProposedStage>, RecordError>
Execution<ProposedStage>::authorize(self, &AuthorizedAction) -> Result<Execution<AuthorizedStage>, RecordError>
Execution<ProposedStage>::reject(self, &str) -> Result<Closed, RecordError>
Execution<AuthorizedStage>::attempt(self, ActualAction, started_at_ms: u64) -> Result<Execution<AttemptedStage>, AttemptUnrecorded>
Execution<AuthorizedStage>::reject(self, &str) -> Result<Closed, RecordError>
Execution<AttemptedStage>::finish(self, Terminal) -> Result<Closed, TerminalUnrecorded>
Recorder::head(&self) -> Result<Head, RecordError>
Recorder::recover_open_executions(&self) -> Result<Vec<ExecutionId>, RecordError>

// Verifier
TrustedReceiptKeys::new(max) ; insert(ReceiptKeyAnchor::new(kernel_id, ReceiptPublicKey, not_before_ms, not_after_ms)?) ; revoke(&ReceiptKeyId)
verify_log_bytes(&[u8], &TrustedReceiptKeys, &Expectations) -> LogVerification
verify_log(&[SignedRecord], &TrustedReceiptKeys, &Expectations) -> LogVerification
verify_receipt_chain(&[SignedRecord], ExecutionId, &TrustedReceiptKeys, &Expectations) -> Verification
Verification::to_json(&self) -> String ; LogVerification::to_json(&self) -> String
```

## Execution authorization (D2-A) and the receipt

Implemented: the capability digest the C++ host receives is `Authorized.capability.cap_digest`,
recorded in full in the receipt. The host's audit ring carries only a label derived from it,
which is not evidence. A receipt cannot show that the host was reached only through the
authorized entry points: in-process code can call the raw C symbols (see
`crates/stack-ffi/ABI.md` section 9). The worker image and limits (`Attempted`) and the use
evidence (`Authorized`) are version 2 additions described above.