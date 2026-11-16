# Requirements for a real capability issuer

Status: requirements, plus a library (`crates/stack-issuer`) that implements part of them. There is no issuer service, no production signer and no requester authentication; see that crate's README for what is covered and what is not. Every capability in the tests is signed by a fixture key derived from a public label (`crates/stack-authority/tests/common/mod.rs`, `crates/stack-admission/tests/common/mod.rs`, `crates/stack-issuer/tests/common/mod.rs`). This document states what an issuer must do for the kernel's claims to hold. It contains no key material, no service code and no new wire format.

Evidence labels: INSPECTED means read in the source named. DECISION means the repository owner must decide it; this document does not decide it. Where an owner answer is recorded below, it is labelled as one.

Identifiers such as `D-19` refer to a project decision register that is not in this repository.

## 1. What the kernel already checks, so the issuer need not duplicate it

`Authority::authorize` (`crates/stack-authority/src/authority.rs`) checks the following. The table groups them; it is not the order the code runs them (the code resolves the trust anchor before verifying the signature, checks the window before the audience, checks the binding before recording the use, and refuses a reusable capability under `require_one_time` before recording it):

| Check | Where | Label |
|---|---|---|
| Ed25519 signature, strict (small-order keys and non-canonical signatures refused) | `trust.rs` `verify_strict` | INSPECTED |
| Issuer known, key trusted for the purpose `CapabilityIssuer`, anchor status and window | `trust.rs` `TrustSet`, `TrustAnchor` | INSPECTED |
| Revocation by capability id, capability digest, or issuer key | `authority.rs`, `trust.rs` `RevocationList` | INSPECTED |
| Audience equals the kernel's configured audience | `authority.rs` | INSPECTED |
| `subject_digest` and `decision_root` equal the values the kernel recomputed | `authority.rs`, `stack-admission` `binding.rs` | INSPECTED |
| Operation is an exact name in the capability; resource is inside a scope on a path-segment boundary | `authority.rs`, `scope.rs` | INSPECTED |
| Window, and a lifetime cap (default 24 hours) | `authority.rs` `max_lifetime_ms` | INSPECTED |
| One-time use recorded in a durable store | `store.rs`, `file_store.rs` | INSPECTED |
| For a `stack-capability/2` capability: the arguments digest, worker label and limits digest equal what the kernel will run (before the use is recorded) | `authority.rs` step 12a, `tests/binding.rs` | EXECUTED |

## 2. What only an issuer can establish

The kernel recomputes the CNS decision root from the roster it is given. It cannot verify that a real CNS decision produced that roster: the CNS proof is an HMAC under a key local to the CNS process, "unverifiable here" (`crates/stack-receipt/src/decision.rs`). Any authenticated sender can therefore present a self-consistent roster of PASS verdicts. The only thing between that and execution is the issuer's decision to sign.

So the issuer is the component that must establish, before signing, that:

1. a real CNS decision exists for this subject;
2. that decision carries a bound PASS from every seat the kernel requires, at the positions the kernel requires;
3. the subject content hashes to the `subject_digest` being signed.

If the issuer does not do this, the kernel's authorization check proves only that someone with a trusted key signed something.

## 3. Requirements

MUST means the kernel's claims do not hold without it.

**Key custody**
- R-1 (MUST). The signing key is held in an HSM, a cloud KMS, or an equivalent device that does not export it. It is never in this repository, an environment variable, a container image, or a test fixture.
- R-2 (MUST). Production and non-production use different keys. A fixture key must never appear in a production trust set.
- R-3 (MUST). Each key is registered in the kernel's `TrustSet` with purpose `CapabilityIssuer` and a `not_before`/`not_after` window.

**Issuance policy**
- R-4 (MUST). The issuer derives `audience`, `subject_digest` and `decision_root` from sources it verified. It does not copy them from the requester.
- R-5 (MUST). The issuer verifies the CNS decision (section 2) before signing. It applies the same required roster and seat positions as the kernel's `KernelPolicy`, from one shared source, so the two cannot drift.
- R-6 (MUST). Operations and resources are the minimum needed. No wildcard resource scope such as `Prefix("/")` unless the owner has accepted that breadth in writing. The library enforces this with a required list of resource roots: every scope must lie at or under a root, and `/` is refused as a root. The kernel does not decode paths, so a root should not be one a worker might read percent-encoded or backslash segments under.
- R-7 (SHOULD). `one_time` is true unless a documented reason says otherwise. The kernel's `require_one_time_capabilities` has no default: an operator states it, and `true` is recommended (`crates/stack-admission/src/config.rs`).
- R-8 (SHOULD). Lifetimes are minutes, far under the 24-hour cap.
- R-9 (MUST). `cap_id` and `nonce` are unique and drawn from a cryptographically secure source.

**Arguments, worker kind and limits**
- R-10 (MUST). The issuer issues `stack-capability/2` capabilities that bind the execution: the SHA-256 of the canonical arguments, the worker kind's label and the SHA-256 of the limits. It computes the three with the kernel's own functions (`stack_admission::execution_binding`, `ExecutionLimits::binding_digest`) from the same policy the kernel runs, so they agree byte for byte. The kernel should set `require_execution_binding` to true, which refuses a version 1 capability (`KernelPolicy` has no default, and some test policies set it false). A version 1 capability binds nothing about how the operation runs, and the kernel then relies on `refuse_arguments`. Neither version makes the worker receive the arguments: that is still not implemented (R2-X-02). Three cautions. (1) The arguments digest is over the canonical bytes (`stack_trident::canonical::to_canonical_bytes`), and `null` and `{}` are different values with different digests, although the kernel's `refuse_arguments` treats both as "no arguments": an issuer and a requester must agree on one spelling. (2) A policy with both `refuse_arguments` and `require_execution_binding` false accepts any arguments on a version 1 capability, and the receipt records their digest beside an authorization that never covered them; do not run that pair in production (policy validation does not refuse it). (3) A capability must fit the verifier's size cap (default 16 KiB, `AuthorityConfig::max_capability_bytes`) and, hex-encoded, the Trident envelope; the format's absolute maximum is 70,946 bytes, which no default accepts. Version 2 adds 67 to 130 bytes to a version 1 capability.
- R-11 (MUST). The operation-to-worker map lives in the kernel's `KernelPolicy.operations`. The issuer and the kernel operator agree on what each operation name runs.

**Revocation and rotation**
- R-12 (MUST). The issuer can revoke by capability id, by digest and by issuer key.
- R-13 (MUST). The kernel's revocation list and trust set are in-memory configuration set through `Authority::with_revocations` and `with_trust`; there is no loader, persistence, or distribution. A real deployment needs an authenticated, audited, persisted channel and a stated maximum staleness (`AUTHORITY.md`, section 8). The kernel's `recheck` and its change hook cancel in-flight runs when that list changes.
- R-14 (MUST). Rotation uses two anchors with overlapping windows. Retiring a key is a status change that keeps its record. `TrustSet::remove` deletes the record, which defeats the "a revoked key cannot be re-inserted" property, so operators use revoke, not remove.
- R-15 (MUST). Changes to the trust set and revocation list are made only through an operator path that is authenticated and logged. Today `Admission::authority()` hands out a reference that can change both.

**Audit and failure**
- R-16 (MUST). Every issuance is logged in an append-only record separate from the kernel's receipt log: capability id and digest, requester, subject digest, decision root, operations, resources, window, time.
- R-17 (SHOULD). The issuance log, the use store and the receipt log can be reconciled. A capability that was used and has no issuance record is a finding.
- R-18 (MUST). If the issuer is unavailable, no capability is issued and nothing runs. There is no fallback issuer and no default key.
- R-19 (MUST). The issuer's and the kernel's clocks are monotonic and synchronised within the skew the window allows. The kernel trusts its clock, and `AUTHORITY.md` records that clock regression is untested.

**Topology**
- R-20 (MUST). One-time use is a per-store fact. Each audience has one use store. Several kernels with one audience need a shared store, which the repository does not provide, or one audience per kernel.

## 4. What would show the issuer meets this

Acceptance criteria, with what the library (`crates/stack-issuer`, tests in `tests/issue.rs`, `tests/hardening.rs` and `tests/hooks.rs`) covers:

- It refuses to sign when the CNS decision is forged, lacks a required seat, has a seat at the wrong position, or does not match the subject content. **Partly.** Covered: missing seat, wrong position, root mismatch, a decision about other content, and the shape checks the kernel's payload parser makes. A required `DecisionVerifier` hook is called for the rest; the crate ships only a refuse-all placeholder. Not covered: a forged but self-consistent decision, until a verifier backed by a channel to CNS exists.
- It refuses requester-supplied digests that differ from the ones it derived. **By absence.** The request type has no digest field, so none can be supplied.
- It never emits a wildcard scope or a lifetime above its configured maximum. **Yes** for scopes outside the configured roots and for a prefix on `/`; **yes** for the lifetime ceiling.
- One decision cannot produce more than a configured number of capabilities. **Partly** (`max_per_decision`). It holds for one open log handle on a regular file, across restarts, with concurrent callers; the handle refuses to continue if the file is renamed, replaced or removed, or if the process forked. It does not hold if the log is rotated without carrying its history (and the old issuer stopped), if an operator edits or truncates the file, or if a requester varies the decision root (a relabelled verdict, an extra PASS seat or a reordered roster each give a new root; only a verifier that accepts exactly CNS-produced roots stops that). It is per root, not per requester.
- A requester is issued only what a policy allows. **Hook only:** a required `Authorizer` is called before signing; no real policy ships.
- A rotation exercise with overlapping anchors leaves no window in which a valid capability is refused or a retired key is accepted. Not covered.
- A revocation reaches the kernel within the stated bound, and an in-flight run for the revoked capability is cancelled. Not covered.
- With the issuer stopped, an admission attempt fails and nothing runs. **Partly:** with the signer, entropy or log down, `issue` returns no capability. No service exists to stop.
- A secret scan of the repository, the kernel image and its configuration finds no signing key. Not run; `src/` of the crate holds no key and `ed25519-dalek` is a dev-dependency only.
- The issuance log reconciles with the use store and the receipt log over a test period. Not covered; no reconciler exists.

## 5. Decisions for the owner (not made here)

- Who operates the issuer, and on what key-custody system. (Owner decision recorded 2026-11-15: the library takes a `Signer` and no backend is chosen yet.)
- Whether the Python `cns_interop` Ed25519 signing code (register D-19, not in this repository) becomes the issuer, or a new service does. (Owner decision recorded 2026-11-15, for the library: a new component, `stack-issuer`, which only consumes CNS decisions.) Whichever it is, CNS must not become an authorization or execution authority; the issuer must stay separate from CNS's contract role.
- ~~Whether to add a capability format version that binds an arguments digest, the worker kind and the limits.~~ Decided and implemented as `stack-capability/2`. Open: when the issuer starts issuing it, and when the kernel's `require_execution_binding` is turned on.
- The revocation transport and its maximum staleness.
- The maximum lifetime and whether any reusable capability is ever acceptable.
- Whether a separate kernel process should own execution (the deferred D2-C design in `crates/stack-admission/README.md`).
