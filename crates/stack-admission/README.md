# stack-admission: CNS decision to kernel authority to receipt

Status: new crate, branch `race02-e2e`, Phase 5 of the CNS and
STACK-Kernel integration (decision E). Nothing outside this crate calls
it. Every claim below names the test that proves it; anything not tested
is listed under "Limits" or marked BLOCKED. The integration contract with
CNS is `docs/cns-kernel-integration.md` at the repository root.

## 1. What it is

One entry point, `Admission::process(envelope_bytes) -> AdmissionResult`.
A request is a `stack-trident` envelope whose payload carries a CNS
decision, a `stack-capability/1` capability and the action wanted. The
pipeline either refuses it with a typed reason, recording the refusal in
the receipt log where the log is reachable, or runs it under a
write-ahead receipt and reports what happened.

```text
payload = { "subject":    { CNS content, integers only },
            "decision":   { "seats": [..], "verdicts": [..], "root": ".." },
            "capability": "<lowercase hex, stack-capability/1 wire bytes>",
            "operation":  "..", "resource": "/..", "args": { .. } }
```

| Stage | Does | Fails closed as |
|---|---|---|
| 1 handoff | `Trident::verify_wire` under the Production profile; `Assurance::Production`; the sender's own gate claim must be PASS | `Refused { stage: Handoff }`, nothing recorded (no subject to speak of) |
| 2 payload | strict parse: exactly six fields plus one optional `native_digest` (label and 64 lowercase hex), bounded strings, resource path rules | `Refused { stage: Payload }`, nothing recorded |
| 3 binding | the kernel recomputes the subject digest (`cns-digest/1`, restricted v1) and the decision root; every verdict must carry that digest and name one subject; the roster must hold exactly one bound PASS per seat the KERNEL POLICY requires, at the position (`seat_positions`: alpha or omega) the policy states for it, with no two seats sharing a gate name | `Refused { stage: Binding }`, `proposed` then `rejected` recorded |
| 4 authorization | the operation must be in the kernel's map; then `Authority::authorize` with an `ActionRequest` built from the kernel's own recomputed values, audience and clock, with the durable use store | `Refused { stage: Authorization }`, recorded |
| 5 write-ahead | `authorized` then `attempted` (operation, resource, SHA-256 of the argument bytes) made durable before the executor is called | no attempt record, no execution: `Refused { stage: Attempt }` |
| 6 execution | the `Executor` seam; the real implementation is the supervised C++ worker program behind `stack-ffi` (fork then exec of an absolute path from `WorkerConfig`, after the host's capability and rate-limit checks), under the kernel's limits | the outcome as the executor observed it |
| 7 terminal | the terminal event from the observed outcome; `Completed` only for a `Completed` report; a report that contradicts itself is `Unknown` | `AdmissionResult::TerminalLost`, attempt left open |
| 8 result | `AdmissionResult::Success` only for a `Completed` whose terminal record is durable | every other ending is `Unsuccessful`, `TerminalLost` or `Refused` |

## 2. Trust placement

| Party | Does | Is never believed about |
|---|---|---|
| CNS | defines the gate vocabulary, the subject digest, the decision root | whether the kernel may act: a CNS PASS grants nothing |
| Trident | authenticates the envelope (HMAC, audience, freshness, replay) | who sent it (a shared key proves possession, not a person), or that the request is legitimate |
| Issuer (outside the kernel and outside CNS; here only a TEST FIXTURE) | signs `stack-capability/1` after checking the decision | nothing is trusted until `Authority::authorize` verifies the signature against the kernel's own trust set |
| Kernel (this crate) | recomputes digest and root, applies its own roster policy, authorizes, records, executes, records again | the payload: no comparison has a payload value on both sides |
| Receipt verifier | recomputes the chain, signatures, root, subject digest, result digest | whether the action was right: `action_legitimacy_not_established` always applies |

Permission exists only as a `stack_authority::AuthorizedAction`, and only
`Authority::authorize` makes one. The kernel never treats a CNS PASS, a
matching digest, a Trident acceptance or a decision's HMAC as permission.
A signed decision proves a decision was signed, not that anything
executed. Tests: `a_valid_pass_decision_with_no_capability_does_not_execute`,
`a_missing_required_gate_is_refused_whatever_the_capability_says` (CNS
itself said `allowed: true` for that decision).

## 3. Status

| Item | State | Evidence |
|---|---|---|
| Stages 1 to 8 | implemented | `tests/admission.rs`, `tests/execution.rs`, `tests/adversarial.rs` |
| Kernel policy (seats, operation map, limits, provenance) | implemented, validated | `config::tests` |
| Executor seam over the supervised C++ worker program, fail-closed when the worker path is unset or unusable, governed before spawn | implemented | `tests/smoke.rs`, `tests/worker_governance.rs`; the only file naming `stack-ffi` is `src/executor.rs` |
| Worker identity in the receipt: the `Attempted` record binds the worker image SHA-256 the supervisor pinned and the limits it was given (version 2) | implemented | `tests/worker_use_native.rs` |
| Use evidence in the receipt: the `Authorized` record binds the use store's record hash and position (`FileUseStore`) or a labeled non-durable marker (version 2) | implemented | `tests/worker_use_native.rs` |
| Native digest kept apart from the CNS subject digest; each tamper caught by its own expectation | implemented | `tests/worker_use_native.rs` |
| Independent verification of the log | implemented in tests, with fresh trusted keys and the auditor's own expectations | `tests/execution.rs` |
| Fixtures from the real CNS SuperGate (8 cases) | committed, regenerates byte for byte | `tests/fixtures/gen_cns_governed_decisions.py` |
| Capability issuer | EXPERIMENTAL: exists only as a test helper with fixture seeds | `tests/common/mod.rs` (the only signing path in the crate) |
| Real worker programs and argument delivery | PLANNED: the C ABI runs a fixed built-in set | see Limits |
| UAI-1 envelopes as the decision carrier | BLOCKED: decision pending (register R2-E-06) | none |
| Two or more hosts sharing replay, use or receipt state | BLOCKED: one VM here, and the stores are single-writer by lock | `a_second_verifier_on_the_same_stores_cannot_start_it_is_locked_not_reconciled` |

### Which native component each digest refers to

The CNS subject digest is the kernel's own recomputation over the payload's
`subject`. The handoff fields are the result of the Trident MAC verification (the
MAC is not in the record). The optional `native_digest` is the sender's own digest
of its native record, for example a Sentinel ledger row hash; it travels inside the
MAC-authenticated payload, is recorded as given under its label, and is NOT
recomputed by the kernel (a Sentinel verification hook is planned). See
`crates/stack-receipt/RECEIPT.md`, "Which native component each digest refers to".

## 4. Scenario to test

All tests assert the observable result. Every refusal test also asserts
that no worker ran, by a run counter at the executor seam. The built-in
workers run under a seccomp filter that forbids `open(2)`, so a worker
cannot write a counter file itself; the counter wraps the executor, and
`authorization_precedes_the_attempt_and_the_attempt_precedes_execution`
additionally reads the receipt FILE from inside the executor call.

| Scenario | Test |
|---|---|
| valid, authorized, end to end: `VERIFIED_WITH_LIMITATIONS`, limitations asserted | `a_valid_authorized_request_runs_and_verifies_with_stated_limitations` |
| valid CNS PASS and handoff, NO capability | `a_valid_pass_decision_with_no_capability_does_not_execute` |
| untrusted or unauthorized issuer; known id with an untrusted key | `a_capability_from_an_untrusted_or_unauthorized_issuer_does_not_execute` |
| invalid capability signature | `an_invalid_capability_signature_does_not_execute` |
| capability for another subject, decision, operation, resource, audience | `a_capability_for_another_subject_decision_operation_resource_or_audience_does_not_execute` |
| wrong receiver audience in the Trident envelope | `an_envelope_sealed_for_another_receiver_is_refused_by_the_trident` |
| a real roster with the `CNS:same_subject` seat (known gap, pinned) | `a_real_decision_that_carries_the_same_subject_seat_is_refused_today` |
| missing, unbound or foreign audience at start | `a_development_trident_or_a_missing_or_foreign_audience_is_refused_at_build`, `the_production_trident_refuses_an_unbound_opt_out_even_with_an_audience` |
| transplanted subject digest | `a_transplanted_subject_digest_is_refused_because_the_kernel_recomputes_it` |
| subject changed after the decision | `a_subject_changed_after_the_decision_is_refused` |
| decision changed after authorization | `a_decision_changed_after_authorization_is_refused_by_root_or_by_the_capability` |
| replay of an accepted envelope | `a_replayed_envelope_is_refused_by_the_trident`, `an_accepted_envelope_replayed_is_refused_and_does_not_run_again` |
| replay after restart (reopened `FileStore` and use store) | `an_accepted_envelope_replayed_after_a_restart_is_refused` |
| replay with a second verifier on the same store | `a_second_verifier_on_the_same_stores_cannot_start_it_is_locked_not_reconciled` (locked, not reconciled) |
| one-time capability in a fresh envelope | `a_one_time_capability_presented_in_a_fresh_envelope_is_refused_as_replay`, `a_one_time_capability_presented_again_in_a_fresh_envelope_is_refused_after_it_ran` |
| concurrent replay | `concurrent_presentations_of_one_envelope_or_one_capability_execute_once` |
| revoked, expired, not yet valid capability | `a_revoked_or_expired_or_not_yet_valid_capability_does_not_execute` |
| wrong operation, wrong resource, operation outside the kernel's map | the scope test above, `an_operation_outside_the_kernels_map_is_refused_before_the_capability_is_consumed` |
| missing required CNS gate | `a_missing_required_gate_is_refused_whatever_the_capability_says` |
| RETRY, TERMINAL_BREACH, unbound verdicts, empty decision | `retry_terminal_breach_unbound_and_empty_decisions_are_refused`, `a_sender_gate_claim_other_than_pass_is_refused_even_when_authentic` |
| malformed payload | `a_malformed_payload_is_refused_before_anything_is_recorded` |
| truncated receipt is INCOMPLETE | `a_receipt_cut_short_is_incomplete_or_rejected_never_verified` |
| tampered result digest is REJECTED | `a_tampered_result_digest_is_rejected` |
| every byte flip of the receipt is REJECTED or changes nothing | `every_byte_flip_of_the_receipt_file_is_rejected_or_changes_nothing` |
| the verifier lists what it did not check | `the_verifier_lists_every_item_it_did_not_check` |
| an auditor with other expectations rejects the same log | `an_auditor_with_other_expectations_rejects_the_same_log` |
| execution timeout is `TimedOut`, not success | `an_execution_timeout_is_a_timed_out_receipt_and_not_success` |
| non-returning payload terminated within a measured bound | `a_non_returning_payload_is_terminated_within_a_measured_bound` (prints the measurement) |
| kernel killed during execution | `a_kernel_killed_during_execution_leaves_an_incomplete_unknown_execution` |
| terminal write failure | `a_terminal_that_cannot_be_recorded_is_a_typed_non_success_and_leaves_the_attempt_open` |
| attempted write failure means no execution | `an_attempt_that_cannot_be_recorded_does_not_run` |
| ordering authorization < attempt < execution | `authorization_precedes_the_attempt_and_the_attempt_precedes_execution` |
| other endings (crash, abort, exit, seccomp) | `every_ending_other_than_a_completion_is_recorded_as_itself_and_is_not_success` |
| executor failure or a self-contradicting report | `an_executor_failure_or_a_contradictory_report_is_unknown_never_completed` |

Measured non-returning termination, debug build, 300 ms deadline: the
supervisor reports 300.9 to 301.2 ms; the whole pipeline (parse, three
signed records, fork, kill, reap, one more record) took 419 to 446 ms.
The asserted bound is the deadline plus 2 s. These are one machine's
numbers, not a guarantee.

## 5. Limits, stated

* **Single host.** One VM, one clock. The replay store, the use store and
  the receipt log are each single-writer by an advisory lock; a second
  kernel on the same files does not start. Two hosts cannot agree on what
  was accepted, and nothing here simulates that. BLOCKED.
* **Results are self-reported.** `Completed` means the worker exited 0
  within the deadline with a well-formed frame. The worker is a separate
  program that writes its frame itself and can write any bytes it likes
  (`cpp/CONTAINMENT.md`, R2-K-08); since decision A it holds none of the kernel
  process's memory, but the bytes are still its own claim. The receipt records the digest and the verifier lists
  `result_is_self_reported` on every completion.
* **Symmetric Trident HMAC.** A handoff proves possession of a shared
  key, not an identity, and any receiver holding the key could have sealed
  it. Identity of the sender is not established. The capability is an
  Ed25519 signature by an issuer; that is the only non-repudiable link.
* **The decision's own proof is not checkable.** CNS's `Decision.proof` is
  an HMAC under a process-local key. The kernel recomputes the root and
  checks the verdicts against its policy; it does not and cannot check
  that SuperGate issued them. The issuer is what ties a decision to a
  capability, and it is outside this repository.
* **Arguments and the resource are not delivered, and the arguments are
  not authorized.** The C ABI runs a fixed set of built-in workers and
  carries neither argument bytes nor a resource. The pipeline validates
  `args`, canonicalizes them and records their SHA-256 as the attempted
  argument digest, and it authorizes the `resource` and records it in the
  `attempted` action, but the worker sees neither; the record is the
  digest and the resource the kernel intended to use, not proof of
  delivery (R2-X-02, wording corrected). Neither the subject digest nor
  the capability covers `args`. Until a worker reads them and a binding
  exists, `args` and `resource` must not be read as what the worker
  acted on.
* **A roster with the `CNS:same_subject` seat is refused.** A real
  SuperGate decision built with `same_subject=` carries a pseudo seat whose
  verdict binds its own object, not the content; the kernel requires every
  verdict to bind the recomputed digest, so it refuses (R2-X-05,
  `a_real_decision_that_carries_the_same_subject_seat_is_refused_today`).
  Safe direction; a deployment cannot use that CNS feature yet.
* **Refusals before the payload parses leave no receipt.** A Trident
  refusal (including a replay) or an unparseable payload is returned to
  the caller but not written to the receipt log: there is no subject to
  record. An auditor reading the log alone does not see them (R2-X-03).
* **A one-time capability is consumed at authorization.** If the
  `authorized` or `attempted` record then cannot be written, nothing runs
  and the capability stays spent.
* **A refused request with a false root is recorded with the kernel's
  root.** The false claimed root is a binding finding in the rejection
  reason, not written into the proposal, so a refusal does not make the
  log read as tampered.
* **Lock descriptors are inherited by workers.** A supervised worker is
  forked from the whole process before it execs; between the fork and its
  descriptor clean-up it holds a copy of every advisory-lock descriptor (after
  the exec it holds none, tested: only fds 0 to 2 and the result pipe). The
  window is unchanged by decision A and not claimed fixed. A restart that races a worker
  still setting up can find a store locked and fails closed (R2-X-01).
* **Clock and keys are trusted.** One clock serves the Trident, the
  authority and the recorder. The Trident's external high-water mark
  (DEPLOYMENT.md item 7), revocation distribution and receipt-key
  anchoring are the operator's, and are not exercised here. A rollback of
  the receipt log to an earlier head is undetectable from the file alone.
* **Not run here:** other CPU architectures, a network file system,
  CNS's Node implementation, a real issuer, any CNS version other than the
  two named in the integration document.

## 6. Running it

```text
CARGO_TARGET_DIR=<dir> cargo test -p stack-admission --locked
cargo clippy --workspace --all-targets --locked -- -D warnings
```

The whole suite takes about 40 seconds in a debug build; 30 of those are
`every_byte_flip_of_the_receipt_file_is_rejected_or_changes_nothing`,
which verifies all 1928 single-byte flips.

To regenerate the CNS fixtures (read-only against a CNS checkout; the
committed file is byte-identical for CNS `4acd8f9` and, apart from the
recorded commit, for CNS main `221c5c9`):

```text
python3 -I -B tests/fixtures/gen_cns_governed_decisions.py <CNS checkout> <commit> \
    > tests/fixtures/cns-governed-decisions.json
```

An operator builds `Admission::new(policy, parts)` from `KernelPolicy`
(kernel id, audience, required seats, operation to worker map, limits,
provenance) and `Parts` (Production `TridentConfig`, key ring with issuer
metadata, durable `FileStore`, `TrustSet`, `RevocationList`, durable use
store, durable receipt log, receipt key, executor, clock). `new` refuses a
non-Production Trident, a differing audience, a non-durable store or log,
and a log for another kernel.

## 7. Defects found while building this crate

| Id | Finding | Evidence | Effect |
|---|---|---|---|
| R2-X-01 | A supervised worker is a fork of the whole process and holds a copy of every advisory-lock descriptor (replay store, use store, receipt log) until its setup closes them. | scratch experiment: 3 threads forking workers continuously, 1,008,508 of 1,101,388 lock re-acquisitions in the parent failed in 8 s; one intermittent "still locked" start in about 60 runs of `tests/adversarial.rs` | fail closed, intermittent restart failures; the planned fork+exec clean worker (I-05) removes it |
| R2-X-02 | `args` are validated and digested and the `resource` is authorized, but the worker receives neither, and no capability or digest covers `args`; the receipt's `attempted` record was documented as "bytes actually passed" and "exactly what is about to run". | `src/executor.rs` (`_args` unused); `RECEIPT.md` section 2 | the receipt field overstates; harmless while no worker reads arguments |
| R2-X-03 | A Trident refusal or an unparseable payload is not written to the receipt log. | `a_malformed_payload_is_refused_before_anything_is_recorded` | an auditor of the log alone does not see refused replays |
| R2-X-04 | The payload has no version field. | `src/payload.rs` | a future format change cannot be told from a malformed payload |
| R2-X-05 | A real CNS roster using `same_subject=` is refused. | `a_real_decision_that_carries_the_same_subject_seat_is_refused_today` | safe direction; a CNS feature the kernel cannot admit yet |

Observed and not a defect: a blocked worker does not outlive its killed
supervisor (`PR_SET_PDEATHSIG`, measured 8 ms in
`a_kernel_killed_during_execution_leaves_an_incomplete_unknown_execution`);
`cpp/CONTAINMENT.md` does not mention it and the header does.

## 8. Execution authorization and revocation of a running worker (D2-A, R-5)

| Item | State | Evidence |
|---|---|---|
| `SupervisedExecutor` runs only through `run_authorized` with the `AuthorizedAction`; `run` and `run_observed` are refused and spawn nothing | implemented, tested | `tests/authorization_required.rs` |
| The C++ host gets the capability digest and refuses an all-zero one; the full digest is in the receipt, the audit ring holds only a label | implemented, tested | `stack-ffi/tests/authorized_run.rs`, `cpp/tests/ffi_authorized_caller.c` |
| A signed capability revoked while a real 3 s spin worker runs kills it (< 1 s, measured 58 ms); terminal is `Terminated`, not a success; an unrelated run is unaffected | implemented, tested | `tests/revocation_real_worker.rs` |
| Real admission runs record the observed terminal, the worker image and limits, and the use evidence (receipt format version 2) | implemented, tested | `tests/observed_terminal.rs`, `tests/worker_use_native.rs` |

Non-guarantee: code in the same process can call the raw C symbols with any digest; this is
an anti-misuse boundary, not protection from malicious in-process code. Remaining limits:
the worker kinds are a fixed built-in set, arguments are not delivered, the native digest is
not recomputed by the kernel, and storage is single process and single host.

## D2-C follow-up (deferred): a separate kernel process owning execution

Status: NOT implemented. Nothing in this repository is a daemon, an IPC client or a
process boundary between a caller and the kernel.

D2-A (this wave) is an anti-misuse boundary. In Rust, the governed run needs an
`AuthorizedAction`, which only `Authority::authorize` can mint. In C++, the host refuses an
all-zero capability digest and records a label of the digest in its audit trail. It is not a
defence against hostile code in the calling process: that code can call the raw C symbols
with any 32 non-zero bytes, and a test pins that
(`cpp/tests/ffi_authorized_caller.c`, "NON-GUARANTEE"). The only design that gives a real
boundary is a separate kernel process (a daemon) that alone owns the host, the worker
supervisor, the authority checks and the receipt log, reached over IPC through a thin client
crate; it would live as new crates in this repository. Priority P2. Revisit when hostile
code inside the calling process enters the threat model.