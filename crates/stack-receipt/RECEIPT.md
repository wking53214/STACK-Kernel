# stack-receipt: execution receipts and their verifier

Status: new crate, Phase 4b of CNS-KERNEL-INTEGRATION-HARDENING, under
decision C (a versioned receipt and verifier in STACK-Kernel; the
sentinel_os ledger untouched). Nothing outside this crate calls it yet.
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
| `attempted` | BEFORE the payload starts (write-ahead) | actual action (operation, resource, argument digest as INTENDED by the producer, not proof the worker received them; see R2-X-02), started-at | no |
| terminal | the run ended | outcome, completed-at, monotonic elapsed | yes |
| `interrupted` (an outcome) | the kernel stopped the run before any kill | reason | yes |
| `unknown` (an outcome) | the kernel could not observe the end | reason | yes |

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
D-07).

### States, exactly

| State | Meaning |
|---|---|
| `VERIFIED` | every check this verifier can perform passed AND `scope.not_checked` is empty |
| `VERIFIED_WITH_LIMITATIONS` | every check performed passed; `scope.not_checked` lists what was not |
| `REJECTED` | at least one check failed; the receipt is not evidence of what it claims |
| `INCOMPLETE` | the chain is intact but the execution has no terminal event, or never reached an attempt |
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
and is never success. `REJECTED` dominates `INCOMPLETE`.

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
`result_digest_recomputed` (result bytes supplied).

`not_checked`: `action_legitimacy_not_established` (always),
`capability_signature_not_rechecked`,
`decision_proof_not_checkable_hmac_is_process_local`,
`native_component_not_verified`, `handoff_provenance_not_rechecked`,
`subject_content_not_supplied`, `roster_policy_not_supplied`,
`audience_not_supplied`, `result_bytes_not_supplied`,
`result_is_self_reported` (every `completed`), `timestamps_are_writer_claims`,
`log_rollback_not_detectable_without_anchor`, `torn_tail_ignored`.

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
`omega_before_alpha`, `capability_decision_root_mismatch`,
`capability_subject_mismatch`, `authorized_action_differs_from_proposed`,
`actual_action_differs_from_authorized`, `audience_mismatch`,
`subject_digest_mismatch`, `result_digest_mismatch`. Incomplete:
`terminal_missing`, `not_attempted`, `not_authorized`. Info:
`empty_log`, `execution_not_found`, `worker_may_still_be_running`,
`torn_tail_discarded`, `trailing_frame_adopted`.

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

## 6. Limitations, stated

* One receipt key per kernel at a time; rotation is two overlapping
  anchors in `TrustedReceiptKeys` and both keys at `FileReceiptLog::open`
  while old records remain.
* One active writer per log, enforced by an advisory lock that a process
  ignoring it can bypass.
* Rollback to an earlier committed state (both header slots rewritten
  consistently, or the newest slot and the last frame both removed) is
  undetectable from the file alone
  (`log::rollback_to_an_earlier_committed_state_is_not_detected_by_the_file_alone`);
  `Recorder::head()` and `FileReceiptLog::head()` expose the chain head
  for an external anchor. Same class as D-09 and D-28.
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

// Verifier
TrustedReceiptKeys::new(max) ; insert(ReceiptKeyAnchor::new(kernel_id, ReceiptPublicKey, not_before_ms, not_after_ms)?) ; revoke(&ReceiptKeyId)
verify_log_bytes(&[u8], &TrustedReceiptKeys, &Expectations) -> LogVerification
verify_log(&[SignedRecord], &TrustedReceiptKeys, &Expectations) -> LogVerification
verify_receipt_chain(&[SignedRecord], ExecutionId, &TrustedReceiptKeys, &Expectations) -> Verification
Verification::to_json(&self) -> String ; LogVerification::to_json(&self) -> String
```
