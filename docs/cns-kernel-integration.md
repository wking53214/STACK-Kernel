# CNS and STACK-Kernel: integration specification

Matrix version: **2** (2026-11-06). Companion to
[`cns-digest-contract.md`](cns-digest-contract.md), which is the contract
for the subject digest alone. This page is the contract for the whole
chain from a CNS decision to a kernel receipt, as implemented and tested
by `crates/stack-admission` (`crates/stack-admission/README.md` is its
status page). Where this page and a named test disagree, the test is right
and this page is a defect.

Identifiers such as `D-11`, `R2-E-06` and `R2-X-05` refer to a project decision register that is not in this repository.

Pinned against:

| What | Value |
|---|---|
| CNS package | version 2.3.0, commit `4acd8f958a091900d43f553eba7fe83f7d33c4d6` (on CNS `origin/main`). The version string reads 2.3.0 at this commit, but the `v2.3.0` tag points at `41592fb7b6735abe140f745353c09ba3eed8e7a2`, a different commit. Also reproduced at CNS `origin/main` head `0fdbb19deee1f7aa7c01503d2f95d5d1e2da84b7` (2026-11-05): the governed fixture regenerates identically except `cns_commit`, and the vendored digest vectors and differential corpus are byte-identical to that head |
| Digest | `cns-digest/1`, restricted v1 (vectors schema `cns-digest-vectors/2`) |
| Capability | `stack-capability/1` (`stack-authority`) |
| Receipt | `stack-receipt/1`, log `stack-receipt/log/1` (`stack-receipt`) |
| Admission payload | the six-field object below. It carries no version field (R2-X-04); it is versioned by this page |

## 1. Who decides what (decision E)

| Concern | Owner | Where |
|---|---|---|
| Gate vocabulary, verdict shape, subject digest, decision root | CNS | `cns/gate.py`, `cns_composition/super_gate.py` |
| Translating a decision into a capability, after checking it | the ISSUER, outside the kernel and outside CNS | not in this repository; a TEST FIXTURE in `crates/stack-admission/tests/common/mod.rs` |
| Which seats a decision must carry for this kernel | the kernel's policy (configuration) | `KernelPolicy::required_seats` and `KernelPolicy::seat_positions` |
| Whether an action is permitted | the kernel, only by `Authority::authorize` | `stack-authority` |
| What happened | the receipt, and its independent verifier | `stack-receipt` |

CNS grants no permission. The kernel never treats a CNS PASS, a digest
match, a Trident acceptance, or a decision's HMAC or signature as
permission. An HMAC proves possession of a shared key, not a person. A
signed decision proves a decision was signed, not that anything executed.

## 2. Data flow

```text
   CNS (Python / Node)                    ISSUER (outside both)
  ---------------------                  -----------------------
  gates judge content                    reads decision, checks it,
  SuperGate.decide ──► Decision          signs stack-capability/1
     seats, verdicts, root, proof          (subject_digest, decision_root,
        │                                   audience, operation, resource,
        │                                   window, one_time)
        │                                         │
        └───────────────┬─────────────────────────┘
                        ▼
              sender builds the payload
   { subject, decision{seats,verdicts,root}, capability, operation,
     resource, args }   and seals it in a Trident envelope for the kernel
                        │            (HMAC, audience, freshness, sequence)
 ═══════════════════════▼═══════════ STACK-Kernel: stack-admission ═══════
  1 Trident verify (Production, Assurance::Production, sender claim PASS)
        │ refuse: typed, not recorded (no subject yet)
  2 strict payload parse (six fields plus optional `native_digest`; bounds; lowercase hex)
        │ refuse: typed, not recorded
  3 kernel recomputes  subject_digest = cns-digest/1(subject)
                       decision_root  = cns-digest/1({seats, verdicts})  (no context; section 4)
        records `proposed` (claimed seats and verdicts, kernel root)
        checks: root, every verdict bound to the digest, one identity,
                non-empty roster, KERNEL-POLICY seats present and PASS
        │ refuse: `rejected` recorded
  4 operation in kernel map?  (else `rejected`)  then
        Authority::authorize(capability,
            ActionRequest{ kernel digest, kernel root, operation,
                           resource }, kernel audience, kernel clock,
            durable use store)  ──►  AuthorizedAction   (the only permission)
        default policy: a capability that is not one-time is refused
        (`rejected`) before `authorized` is written
        records `authorized`        │ refuse: `rejected` recorded
  5 records `attempted`  ◄─ durable BEFORE the worker starts
        │ cannot record: nothing runs
  5b revocation re-check: a failed re-check closes the attempt as
     `Interrupted`; nothing runs
  6 Executor seam ──► supervised C++ child (deadline, seccomp, rlimits)
  7 records terminal from the OBSERVED outcome
        │ cannot record: TerminalLost, attempt stays open
  8 AdmissionResult::Success  only for a recorded Completed
 ═══════════════════════▼═════════════════════════════════════════════════
              receipt log (signed, hash-chained, single writer)
                        ▼
   independent verifier (fresh trusted keys, own expectations):
   VERIFIED_WITH_LIMITATIONS / REJECTED / INCOMPLETE / UNKNOWN
```

## 3. The payload

```text
{ "subject":    { map with text keys; integers only; inside restricted v1 },
  "decision":   { "seats":    [ "repository:gate", .. ],
                  "verdicts": [ { "gate", "position", "outcome",
                                  "subject", "digest" }, .. ],
                  "root":     "<64 lowercase hex>" },
  "capability": "<lowercase hex of the stack-capability/1 wire bytes>",
  "operation":  "<name>",
  "resource":   "/absolute/path",
  "args":       <JSON value inside restricted v1>,
  "native_digest": <optional: { "label": "...", "digest": "<64 lowercase hex>" }> }
```

Exactly these six fields, plus the optional seventh, `native_digest`. An
extra or missing field, upper-case hex, or an unknown outcome or position
is refused by the payload parser before anything is recorded
(`payload::tests::every_shape_violation_is_refused`,
`a_malformed_payload_is_refused_before_anything_is_recorded`). A float, an
integer beyond 2^53 - 1, or a duplicate key is refused earlier, by the
Trident's canonical parser at step 1, which records nothing
(`stack-trident/src/cns_digest.rs::floats_and_out_of_range_integers_are_refused`,
`stack-trident/src/canonical.rs::duplicate_keys_refused`).
The verdict key `digest` is CNS's `GateResult.subject_digest`.
`GateResult.reason` is not in the payload, not in the root and not read.

## 4. What the kernel recomputes, exactly

| Value | Definition | Reproduced by | Held to |
|---|---|---|---|
| subject digest | `hex(SHA-256(rendering(subject)))`, `cns-digest/1` | `stack_trident::cns_digest` (restricted domain) | the shared vectors (`stack-trident/tests/cns_digest.rs`); agreement with the receipt crate's independent implementation (`binding::tests::the_two_digest_implementations_agree_on_restricted_content`); the fixtures (`the_kernel_recomputes_what_cns_bound_exactly`) |
| decision root | `subject_digest({"seats": [..], "verdicts": [{"gate","position","outcome","subject","digest"}, ..]})` | `stack_receipt::decision_root` | seven roots from the real SuperGate (`stack-receipt/tests/decision.rs`) and eight more here (`tests/fixtures/cns-governed-decisions.json`) |
| verdict to seat | a verdict belongs to the seat whose text after the last `:` is its `gate` | `stack_receipt::seat_gate` | `retry_terminal_breach_unbound_and_empty_decisions_are_refused` |

The root above is the one for a decision made without a context. CNS's
`decide()` can take a `context` (for example the action, the tenant or the
policy version). Its root then also covers `"context": <digest>`
(`super_gate.py::_root`). The payload has no context field, and the
kernel's root content has no context input, so such a root does not match
the kernel's recomputation and the decision is refused as a root mismatch.
This follows from reading the code. No kernel test exercises a
context-bearing decision. Such decisions are not supported (section 8).

Not recomputable by the kernel: `Decision.proof` (an HMAC under a key local
to the CNS process) and the decision's `nonce`, `issued_at` and
`expires_at`. They are not in the payload and nothing depends on them.

## 5. Compatibility matrix

"Requires" is what the kernel side must do when CNS changes that element.
A change CNS makes silently fails closed in every row marked FC: the kernel
refuses, it does not accept something different.

| CNS element | CNS source | Kernel consumer | Pinned by | A CNS change requires, kernel side |
|---|---|---|---|---|
| `GateOutcome` values `pass`, `retry`, `terminal_breach` | `cns/gate.py` | `stack_receipt::GateOutcome::parse`; admission accepts only `pass` | `a_sender_gate_claim_other_than_pass_is_refused_even_when_authentic`, `retry_terminal_breach_unbound_and_empty_decisions_are_refused`, `payload` tests (unknown outcome) | A new or renamed value: FC (payload refused as `UnknownOutcome`). To admit it, add the variant to `stack-receipt`, decide in `check_authorized_decision` whether it can ever authorize, add a fixture case and a test. A rename of `pass` refuses everything. |
| `GatePosition` values `alpha`, `omega` | `cns/gate.py` | `GatePosition::parse`; alpha before omega enforced | `payload` tests (unknown position); verifier finding `omega_before_alpha` | New position: FC. Ordering rule change: review `check_authorized_decision`. |
| `GateResult` fields in the root: `gate`, `position`, `outcome`, `subject`, `subject_digest` | `cns_composition/super_gate.py::_verdict` | `payload::verdict`, `decision_root` | `the_kernel_recomputes_what_cns_bound_exactly`, `stack-receipt/tests/decision.rs` | Adding, removing or renaming a field in `_verdict`: every root recomputes differently, every decision is refused (FC: `RootMismatch`). Requires `decision_root` and the payload verdict shape to change together and the vectors to be regenerated. |
| `GateResult.reason` | `cns/gate.py` | none | n/a | Not consumed. No kernel change for any edit to it. If CNS ever puts `reason` in the root, treat it as the row above. |
| `GateResult.subject`, `subject_digest` bound and equal across verdicts | `GateResult.binds`, `unbound` | `binding::check` (`VerdictNotBoundToSubject`, `IdentityDisagreement`), `DecisionFinding::VerdictUnbound` | `a_transplanted_subject_digest_is_refused_because_the_kernel_recomputes_it`, `a_subject_changed_after_the_decision_is_refused`, `retry_terminal_breach_unbound_and_empty_decisions_are_refused` | A change in what a gate binds to (a different content object) is a change to the payload `subject`: the sender must send the object the gates judged. Kernel code unchanged. |
| `subject_digest` rendering, `cns-digest/1` | `cns/gate.py::_canonical`, `subject_digest`; `contracts/digest-vectors.json` | `stack_trident::cns_digest`, `stack_receipt::cns` | the vendored vectors, `stack-trident/tests/cns_digest.rs`, `stack-sentinel/tests/cns_vectors.rs` | A change to any digest valid today needs a new `digest_version`, and the Trident, the receipt crate and the Sentinel change with it; the capability's `subject_digest` is then a different value and issuers must reissue. `cns-digest-contract.md` states the procedure. |
| `restricted_v1` domain (no float, integers within 2^53 - 1, depth 31) | `cns_composition/digest_vectors.py` | the Trident's parser; the payload's `subject` and `args` must lie inside it | `stack-trident/tests/cns_digest.rs`; the fixtures' subject is integer-only | CNS content with a float or a larger integer cannot be admitted: the Trident refuses the envelope. Widening is a kernel review (`cns-digest-contract.md`). A governed subject must be modelled with integers (for example minor units) to cross. |
| Decision root | `super_gate.py::_root` | `stack_receipt::decision_root` | as above | See `GateResult` fields. |
| `context` digest in the root (CNS `decide(context=...)`) | `super_gate.py::_root`, `digest_context` | none: the payload has no context, and the kernel recomputes the root without one | none | Not supported. A context-bearing decision is refused as a root mismatch. Supporting it needs a payload field, a root input and fixtures, and is a kernel feature with its own review. FC. |
| Roster `Decision.seats` as `repository:gate` | `SuperGate.seats` | `DecisionEvidence.seats`; matched to `KernelPolicy::required_seats` | `a_missing_required_gate_is_refused_whatever_the_capability_says` | A renamed repository or gate means the kernel's configured required seats no longer match: FC (`RequiredSeatMissing`). Update `KernelPolicy`, a configuration change, not a code change. |
| The required roster | CNS `required=` argument | NOT consumed from CNS: a CNS root does not commit to it (register D-11) | the missing-seat fixture is `allowed: true` in CNS and is refused here | None, by design. The kernel's policy is the source. A CNS that required fewer seats still cannot lower the kernel's requirement. |
| `CNS:same_subject` pseudo seat (added by `SuperGate` when `same_subject=` is given) | `super_gate.py::SubjectAgreement` | refused today: its verdict names `same_subject` as its subject and binds `subject_digest({"identity","digest","seats"})`, not the content, so `binding::check` reports `VerdictNotBoundToSubject` and `IdentityDisagreement` | `a_real_decision_that_carries_the_same_subject_seat_is_refused_today` (R2-X-05) | Rosters used with this kernel must not use `same_subject=` until the kernel learns to recompute that verdict (it can: identity, the kernel's digest and the other seats are all known to it). That is a kernel feature with its own review, not a configuration change. FC. |
| `Decision.allowed`, `Decision.outcome` | `super_gate.py` | none | the same fixture | Not consumed. The kernel derives its own verdict from the verdicts. |
| `Decision.proof` (HMAC), `nonce`, times | `super_gate.py::_proof` | none; not checkable by the kernel | verifier limitation `decision_proof_not_checkable_hmac_is_process_local` | Moving the proof to a signature would let a kernel check issuance. That would be a new row and a new kernel feature; today the issuer carries the trust. |
| UAI-1 envelopes (`cns_interop`) | `cns_interop`, Node and Python receivers | none | none | BLOCKED (register R2-E-06): different key derivation, no resource scope, no slot for a verdict or terms. A Rust UAI-1 verifier is a separate decision. |
| Digest differential corpus and vectors | `contracts/*.json` | vendored in `stack-sentinel/tests/fixtures` | the two Rust suites | Adding vectors keeps `cns-digest/1`; update the vendored copies and the exact counts. |

## 6. What the issuer must sign

The kernel authorizes exactly what the capability says and what the kernel
itself computed agree on. An issuer that translates a decision must check
the decision (policy is the issuer's), then sign, with its Ed25519 key:

| Capability field | Must equal | Checked by |
|---|---|---|
| `audience` | the kernel's audience | `Authority::authorize` (`AudienceMismatch`) |
| `subject_digest` | the kernel's recomputed subject digest | `SubjectMismatch` |
| `decision_root` | the kernel's recomputed root | `DecisionMismatch` |
| `operations` | contains the requested operation | `OperationDenied` |
| `resources` | one scope covers the requested resource | `ResourceDenied` |
| `not_before_ms`, `expires_at_ms` | the window at the kernel's clock | `NotYetValid`, `Expired` |
| `one_time` | true for an irreversible action; consumed in a durable store | `Replay` |
| `issuer_id`, signing key | present in the kernel's trust set | `UnknownIssuer`, `UntrustedKey`, `BadSignature` |

Not in the capability: the arguments, the worker, any limit. `args` are
neither covered by the subject digest nor by the capability (R2-X-02), and
no built-in worker reads them. The kernel maps an operation name to a
worker and limits by its own configuration; a capability cannot choose
either.

## 7. What the receipt carries and what an auditor may conclude

The receipt (`crates/stack-receipt/RECEIPT.md`) records: the subject
identity and the kernel's digest; the decision's seats and verdicts under
the kernel's recomputed root; the Trident handoff provenance; the
capability binding `Authority::authorize` returned; the attempted
operation, resource and argument digest; and the observed outcome. An
auditor who supplies the subject content, the required roster, the
audience, the kernel id and the result bytes gets, for a completed run,
`VERIFIED_WITH_LIMITATIONS` with exactly these unchecked items
(`a_valid_authorized_request_runs_and_verifies_with_stated_limitations`):
`action_legitimacy_not_established`, `capability_signature_not_rechecked`,
`decision_proof_not_checkable_hmac_is_process_local`,
`handoff_provenance_not_rechecked`, `result_is_self_reported`,
`timestamps_are_writer_claims`,
`log_rollback_not_detectable_without_anchor`.

`VERIFIED_WITH_LIMITATIONS` means the records are intact, signed by the
receipt key, internally consistent, and say what `outcome` says. It does
not mean the action was legitimate, the decision was issued by CNS, or the
result is genuine.

## 8. Open and BLOCKED

| Item | State |
|---|---|
| A real issuer, its key custody, and its decision-checking policy | BLOCKED (outside this repository; decision E places it outside the kernel and CNS) |
| UAI-1 as the decision carrier | BLOCKED (R2-E-06) |
| Two or more kernel hosts with shared replay, use and receipt state | BLOCKED (single VM; stores are single-writer) |
| CNS Node implementation, and the PostgreSQL ledger, in the chain | not exercised |
| A roster with the `CNS:same_subject` seat | refused today (R2-X-05); PLANNED |
| A payload version field | PLANNED (R2-X-04) |
| Delivery and authorization of `args` | PLANNED (R2-X-02) |
| Receipt record of Trident refusals | PLANNED (R2-X-03) |
| Decisions made with a CNS `context` | NOT SUPPORTED: refused as a root mismatch; no test (section 4) |

## 9. Change procedure

1. A CNS change touching a row in section 5: open a STACK-Kernel change
   before the new CNS commit is trusted; regenerate `tests/fixtures/cns-governed-decisions.json`
   with `gen_cns_governed_decisions.py` against the new CNS commit and
   review the diff by eye.
2. If the regenerated file differs in anything but `cns_commit`, the
   change is breaking for the kernel: apply the "requires" column, bump the
   matrix version here, and say which CNS commit each side was tested at.
3. If it differs in nothing but `cns_commit`, record the commit in the
   table at the top.
