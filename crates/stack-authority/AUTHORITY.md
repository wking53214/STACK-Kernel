# stack-authority: the authorization boundary

Status: new crate, Phase 2 of CNS-KERNEL-INTEGRATION-HARDENING, under
decision B (the kernel only verifies). Nothing outside this crate calls it
yet. Every claim below is backed by a named test in `tests/`; anything
not tested is marked as a limitation or an open question.

## 1. The concepts, kept separate

| Concept | Where it lives | What it proves | What it does not prove |
|---|---|---|---|
| Content identity | elsewhere (Trident canonical JSON, Sentinel chain): SHA-256 of canonical bytes | these bytes are these bytes | who produced them, whether anyone may act on them |
| CNS subject binding | `Capability.subject_digest`, a CNS `subject_digest` (64 lowercase hex) that the enforcement boundary recomputes from the content and passes in `ActionRequest` | the capability was issued about this content; tamper-evidence only, because anyone can compute the digest | authority of any kind. A digest match alone authorizes nothing (`adversarial::transplanted_subject_digest`, `changed_decision_root`) |
| Authentication | Ed25519 signature over the exact signed region, checked with `verify_strict` | the holder of the issuer key signed exactly these bytes | anything about a human; that the key is trusted; that the capability is current |
| Trusted issuer identity | `TrustSet` of `TrustAnchor`s: `(issuer_id, key_id)` resolving to exactly one anchor with purpose `CapabilityIssuer`, status `Active`, window containing now | the kernel's operator chose to trust that key for that issuer, for that period | that the operator was right to |
| Authorization | `Authority::authorize`: the thirteen checks in section 4, then one atomic use record | this capability permits this operation on this resource for this verifier, under this decision, now, and (if one-time) has not been used before | that the action was performed, or performed correctly |
| Enforcement | the caller's boundary, which must demand an `AuthorizedAction` before executing | out of scope here | |
| Outcome, receipt | out of scope here; `AuthorizedAction` carries every field a receipt needs (section 7) | | |

A CNS PASS, a matching decision root or a matching subject digest never
authorizes anything in this crate. They are conditions the signed
capability must also satisfy, checked after the signature.

## 2. Trust model

The kernel holds public keys only. There is no signing key, no signing
code and no default key in `src/`; `tests/no_signing_in_src.rs` greps the
source for `SigningKey`, `SecretKey`, `Signer`, `.sign(`, key-generation
and key-file features, and for any 64-hex-character literal. Issuing
happens outside the kernel; in this repository only `tests/common` can
sign, with TEST FIXTURE keys seeded from SHA-256 of a public label.

A `TrustAnchor` is: `issuer_id` (1 to 128 bytes, no control character),
`public_key` (validated: undecodable and small-order points refused,
`trust::weak_or_invalid_public_keys_are_refused`), `key_id` (full SHA-256
of the key under the tag `stack-authority/key-id/1\n`, derived and never
supplied, never shortened; a label for lookup, not a MAC), `purpose`
(`CapabilityIssuer`, the only purpose today; a key trusted for anything
else later can never be mistaken for an issuer key), `not_before_ms`
inclusive, `not_after_ms` exclusive, `status` Active or Revoked.

A `TrustSet` is bounded and holds each key id at most once, under one
issuer (`trust::trust_set_is_bounded_and_one_key_appears_once`).
Resolution checks identity, then status, then window, and reports a typed
`ResolveError` (`trust::resolution_checks_identity_then_status_then_window`).
An empty set trusts nothing.

### Key rotation

Add a second anchor for the issuer with a window overlapping the first.
In the overlap both keys verify; before it only the old key does; after it
only the new one. No swap, no gap, and capabilities signed under each key
verify only under their own anchor (`trust::rotation_is_two_overlapping_anchors`,
`authorize::trust_set_lives_in_the_authority_and_can_rotate_while_running`).
The `Authority` holds the set behind a lock so rotation happens while it
runs; a poisoned lock denies (`AuthzError::TrustUnavailable`).

### Issuer revocation

`TrustSet::revoke(key_id)` marks the anchor Revoked. It stays in the set,
so a capability under that key is refused as `IssuerRevoked` (a different
fact from an untrusted key) and the same key cannot be re-inserted to
restore trust (`adversarial::revoked_issuer`). Removal is also possible
but loses the record.

### Capability revocation

`RevocationList` of `cap_id` values and of capability digests, bounded.
When full, a revocation fails with `TrustError::Full`; the operator must
treat that as an incident, since a revocation that could not be recorded
is a capability still in force (`trust::revocation_list_is_bounded_and_matches_by_id_or_digest`).
Revocation is checked right after the signature, so a revoked capability
is refused at every instant of its window (`adversarial::revoked_capability`).

Distributing the trust set and the revocation list to every verifier is
the operator's job. This crate consults only the copies it is given.

Revocation after authorization (implemented, tested). `authorize` is a
point-in-time decision. `Authority::revocation_epoch` is a monotonic
counter that advances on every write access to the revocation list or the
trust set; `Authority::recheck(&AuthorizedAction)` re-evaluates revocation
by id and digest and the issuer key's presence and revocation, failing
closed when either lock is poisoned; `Authority::set_change_hook` lets the
enforcement layer run a re-check after each change
(`revocation_epoch::*`). The key's validity window is not re-applied by
`recheck`. Acting on a failed re-check (refusing before spawn, asking a
running worker to stop) is the admission layer's job, see the
`stack-admission` rustdoc (`CancellableExecutor`, `Admission::enforce_revocations`)
and its tests (`stack-admission/tests/revocation.rs`: revoked between
authorize and spawn, revoked while running, unrelated capability unaffected,
unreadable revocation list fails closed). Implemented and tested with a test
executor, and with the real worker: `SupervisedExecutor` implements the stop
hook, so a signed capability revoked while a 3 s spin worker runs kills that
worker (measured 58 ms from revocation to a recorded, dead worker, asserted
under 1 s), the receipt terminal is a non-success `Terminated`, and an unrelated
run is unaffected (`stack-admission/tests/revocation_real_worker.rs`).

## 3. Wire format, `stack-capability/1`

Big-endian integers; `u16`-length-prefixed UTF-8 strings with no control
character (below U+0020, or U+007F); sets in strictly increasing byte
order with no duplicate, so one set has one encoding.

```
signed region
  "stack-capability/1\n"            19 bytes, domain and version tag
  cap_id          u16 len, 1..=128 bytes
  issuer_id       u16 len, 1..=128 bytes
  audience        u16 len, 1..=128 bytes
  subject_digest  32 bytes raw (CNS subject digest)
  decision_root   32 bytes raw (CNS decision root)
  operations      u16 count 1..=64; each u16 len, 1..=64 bytes; sorted
  resources       u16 count 1..=64; each u8 kind (0 exact, 1 prefix),
                  u16 len, 1..=1024 bytes of path; sorted by (path, kind)
  not_before_ms   u64
  expires_at_ms   u64, strictly greater than not_before_ms
  one_time        u8, 0 or 1
  policy_ref      u16 len, 0..=256 bytes
  nonce           16 bytes
  key_id          32 bytes (inside the signed region, so a capability is
                  bound to one key and rotation cannot make it ambiguous)
signature         64 bytes, Ed25519 over the signed region
```

Nothing may follow the signature. The parser refuses truncation at every
length, trailing bytes, a wrong domain tag, an unsupported version,
out-of-bounds lengths on every field, invalid UTF-8, control characters,
empty sets, unsorted or duplicate members, bad scope kinds and booleans,
bad paths and inverted windows (`tests/capability.rs`). It never
allocates for a declared length before the bytes are present, and a
single-bit mutation sweep over the whole wire never panics.

The capability digest is SHA-256 over `stack-authority/capability-digest/1\n`
and the whole wire form, signature included. Signatures are deterministic
and verification is strict, so one capability has one digest. It is 32
bytes, written as 64 hex characters, never truncated, and is the
capability's name in the use store and in receipts
(`capability::digest_is_domain_separated_full_sha256_and_covers_the_signature`).

Resource path rules (`src/scope.rs`): starts with `/`; the root alone is
allowed; no empty segment, no trailing `/`, no `.` or `..` segment; no
control character; at most 1024 bytes; no normalisation of any kind.
`Exact` covers the identical path. `Prefix(p)` covers `p` and any path
extending `p` at a segment boundary: `/data/a` covers `/data/a/b` and never
`/data/ab`. `Prefix(/)` covers every valid path. A request path failing
the rules is covered by nothing (`authorize::resource_scopes_are_exact_or_segment_prefix`,
`adversarial::wrong_resource_prefix_confusion_traversal_empty_segment_case`).

## 4. The decision, in order

`Authority::authorize(bytes, &ActionRequest, &dyn Clock, &dyn UseStore)`:

1. The store must be durable unless configuration allows otherwise.
   Checked first, before parsing: a verifier that could forget a use does
   not run (`authorize::production_config_refuses_a_non_durable_store_before_anything_else`).
2. Size cap, then strict parse.
3. Trust resolution of `(issuer_id, key_id)` at now.
4. Signature, strict (`verify_strict`: non-canonical scalars and
   small-order points refused, `trust::non_canonical_signature_scalar_is_refused`).
5. Revocation by id or digest.
6. Lifetime cap, before the clock, so an over-long capability is refused
   at every instant (`adversarial::lifetime_above_cap`).
7. Window: `not_before_ms <= now < expires_at_ms`.
8. Audience equals the verifier's configured identity.
9. Subject digest equals the request's.
10. Decision root equals the request's.
11. Operation is a member of the set, byte for byte.
12. Some scope covers the resource.
13. The use store records the use, last.

Steps 1 to 4 reveal only facts about the bytes presented and the
verifier's public configuration. Nothing after step 4 is reached for
bytes a trusted issuer did not sign, so every later refusal describes a
genuine capability its holder already has in full
(`adversarial::invalid_signature_every_single_byte_flip_in_signed_region_and_signature`
asserts that no byte flip reaches a post-signature refusal). `UnknownIssuer`
versus `UntrustedKey` tells a caller whether an issuer id is in the trust
set; issuer ids and key ids are public labels, so this is accepted.

Two shapes differ from the brief, after reading `stack-trident`: the
verifying identity (audience) is `AuthorityConfig`, as
`TridentConfig.audience` is, and now comes from the `Clock` only. Neither
can be chosen by whoever builds the `ActionRequest`, which carries only
subject digest, decision root, operation and resource. A request
descriptor is data: every field in it is compared with a field the issuer
signed (`adversarial::hostile_request_descriptor_with_a_self_made_capability`,
`permissive_capability_with_valid_signature_but_wrong_audience`).

## 5. One-time use and the use store

The store is consulted last, so a request refused for any other reason
consumes nothing (`adversarial::replay_of_a_one_time_capability`,
`no_refusal_after_the_signature_stage_touches_the_store_or_leaks_past_it`).
`record_use` is one atomic check-and-record: a one-time digest already
recorded is `Replay`; an id already recorded under another digest is
`CapabilityIdReused`, in both orders and across a restart
(`adversarial::reused_cap_id_with_different_content`,
`store::id_reuse_with_different_content_is_refused_across_restart`); a
reusable capability is recorded once and accepted thereafter. Thirty-two
threads presenting one one-time capability get exactly one acceptance
(`adversarial::concurrent_consumption_by_many_threads_accepted_exactly_once`).
A store that cannot answer denies (`adversarial::store_unavailable_denies`).

`MemoryUseStore` is not durable and says so; the production configuration
refuses it. `FileUseStore` is an append-only log of fixed-size records,
each chained to the previous by SHA-256 under a domain tag, written with
one `write_all` and `sync_data` before the use is reported, under the
exclusive advisory lock of `File::try_lock` for the life of the store
(`store::the_lock_is_exclusive_while_held`). On open the chain is
verified. A torn tail (fewer than one record of trailing bytes consistent
with the chain head) is tolerated and cut off at the next write; the use
it would have recorded was never reported (`store::a_torn_tail_is_tolerated_and_cut_off_at_the_next_write`,
every cut point). Any other inconsistency (every single byte of the file
altered, junk appended, a length edit, a wrong header, swapped records,
the whole file zeroed) is corruption: open fails and the verifier has no
store to run with (`store::corruption_fails_closed_on_open`,
`adversarial::corrupted_store_fails_closed`). A write or sync failure
poisons the store until it is reopened (not reached by a test: no I/O
fault injection exists here). Uses survive a reopen and a second verifier
process over the same log (`adversarial::replay_after_restart`).

### Supported topology

Labels: [tested] means a named test reproduces it on the real `FileUseStore`;
[not supported] means no claim is made and nothing is tested.

* **Single process** [tested]. Any number of threads share one store;
  a one-time capability is authorized exactly once
  (`store::concurrent_consumption_is_accepted_exactly_once`,
  `adversarial::concurrent_consumption_by_many_threads_accepted_exactly_once`).
* **Several processes on ONE host, one at a time** [tested]. The store holds
  an exclusive advisory file lock (`File::try_lock`) for its whole life, so
  processes on the same host and the same local file system take turns: the
  process that does not hold the lock fails to open and has no store, so it
  denies. Two real processes racing one one-time capability yield exactly one
  authorization, the other is denied as locked or as a replay
  (`store_failure_modes::two_processes_race_one_one_time_capability_exactly_one_is_authorized`).
  After the winner exits, a later process refuses the capability as a replay
  (same test). A process killed after the commit has still consumed the
  capability (`store_failure_modes::lost_ack_real_process_aborts_after_the_commit_and_the_retry_is_a_replay`).
  This is mutual exclusion on one machine. It is not concurrent sharing: there
  is never more than one active user of a log.
* **Multiple hosts** [not supported]. There is no replication, no shared
  store and no distributed consensus here, and the file lock is not one: it
  is a local operating-system lock. Two hosts with separate logs each accept
  a one-time capability once. A log on a network file system is not tested
  and not claimed. [BLOCKED: no multi-host environment exists to test in.]

Failure behavior, each reproduced on the real store:
a use committed but never acknowledged stays consumed
(`store_failure_modes::lost_ack_in_process_the_use_is_committed_and_the_retry_is_a_replay`);
a record present twice fails closed on open
(`a_record_appended_twice_byte_for_byte_fails_closed_on_open`,
`a_record_replacing_its_neighbour_byte_for_byte_fails_closed_on_open`);
rollback to a prior valid state is NOT detected from the file, and a use
forgotten by the rollback can then be consumed again; it IS detected by
comparing `FileUseStore::head()` with a head recorded elsewhere
(`rollback_to_a_prior_state_is_not_detected_from_the_file_and_is_detected_against_an_external_head`);
storage unavailable at open, or lost while running, denies
(`real_unavailable_storage_at_open_fails_closed`,
`storage_lost_mid_run_denies_and_the_failed_attempt_consumes_nothing`; the
mid-run failure is injected by a wrapper over the real store, because no
real write fault can be provoked here).

## 6. HMAC in stack-trident versus Ed25519 here

Trident's HMAC-SHA256 under a shared key proves that someone holding that
key produced the envelope. Any receiver that holds the key can also forge
as the sender, so a receiver cannot prove to a third party that the sender
spoke, and a key given to many receivers is a key any of them can abuse.
That is the right tool for a channel between two parties who already
share a secret.

Authority is different: one issuer, many verifiers, and the verifier must
hold nothing that could mint a grant. Ed25519 gives receiver separation
(every kernel holds public keys only; compromising a kernel yields no
issuing power) and non-repudiation (a valid signature under an issuer key
can be shown to anyone who has the trust set, and the kernel cannot have
produced it). What it does not give: proof that a human acted, proof that
the issuer's policy was right, or anything about timing beyond the window
the issuer wrote into the signed bytes.

## 7. What `AuthorizedAction` carries for a receipt

Capability digest, `cap_id`, `issuer_id`, `key_id`, `policy_ref`,
audience, operation, resource, subject digest, decision root, one-time
flag, `authorized_at_ms` (the verifier's clock). Only `authorize` can
construct it (`authorize::happy_path_mints_an_authorized_action_with_every_receipt_field`).
It is marked `must_use`. It is permission to perform exactly the operation
and resource it names, once if the capability was one-time; it records
nothing about what then happened.

### Authorization at the execution boundary (D2-A)

Implemented and tested. `stack-ffi`'s safe governed entry points take `&AuthorizedAction`,
which only `Authority::authorize` can mint, and pass its capability digest to the C++ host.
`AuthorizedAction::use_evidence()` returns what the use store reported (record hash and
position for `FileUseStore`, a labeled non-durable marker for `MemoryUseStore`, `NotProvided`
for a store that predates the method); `stack-authority/tests/use_evidence.rs`.
Non-guarantee: code in the same process can call the raw C symbols with any digest, so this is
an anti-misuse boundary, not protection from malicious in-process code. A separate kernel
process (D2-C) is deferred and NOT implemented; see `crates/stack-ffi/ABI.md`.

## 8. Limitations, stated

* Revocation and trust-set distribution are the operator's job; a
  verifier with a stale list accepts what a current one refuses.
* The clock is trusted. Every window check and the store's expiry pruning
  read it. A clock moved backwards after an entry was pruned could let an
  expired one-time capability be presented again; no test covers clock
  regression, and the mitigation (anchoring the high-water mark, as
  Trident does) is left to integration.
* One-time use is a per-store fact. Two verifiers with separate logs each
  accept a one-time capability once. The topology is one store per
  audience; a shared store across replicas is not provided.
* The chain detects alteration, reordering and truncation that does not
  land on a record boundary. A rollback to an earlier record boundary is
  not detectable from the file alone, and is pinned as such
  (`store::rollback_to_a_record_boundary_is_not_detected_by_the_file_alone`).
  `FileUseStore::head` exposes the chain head for an operator to anchor
  elsewhere.
* The lock is advisory. It keeps cooperating opens apart, in one process
  or in two; it does not stop a process that ignores it.
* The log is never compacted; expired entries leave the index, not the
  file. A fresh log is safe only once every entry in the old one has
  expired.
* The store is poisoned on a write or sync failure, but no test injects
  such a failure.
* No timing uniformity is claimed. Refusals before the signature return
  early; the signature check always runs for a resolvable key.
* Trust-set and revocation-list contents are public configuration;
  `UnknownIssuer` versus `UntrustedKey` reveals whether an issuer id is
  known.

## 9. Open questions for integration

1. Who computes `subject_digest` for the request? It must be recomputed
   from the content by the enforcement boundary, as Trident's prong 2
   does, never copied from the caller.
2. Where does `decision_root` come from? CNS `super_gate._root` lives in
   Python; nothing in STACK-Kernel reproduces it today (register D-11,
   D-12). The kernel needs either the root as a verified input or a Rust
   reimplementation checked against CNS vectors.
3. How does Trident's verified envelope combine with this crate? The
   natural seam is: Trident admits the envelope, the boundary derives the
   `ActionRequest` from the verified handoff, and this crate authorizes.
   Whether an `Assurance` flag or outcome on the Trident side should gate
   the call, or be recorded beside the `AuthorizedAction`, is undecided.
4. Issuer side: no issuer exists. `cns_interop` holds Ed25519 signing in
   Python (register D-19); whether it becomes the issuer of this format is
   a human decision.
5. Receipt home (decision C): `AuthorizedAction` is the input; the
   receipt type and verifier are Phase 4.
