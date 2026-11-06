# Deploying stack-trident

This document says what a deployment of the Trident verifier may rely on,
what it must provide, and what the crate does not protect against. Every
claim below is backed by a named test in `crates/stack-trident/tests/`
(`replay_durable.rs`, `profile.rs`, `redteam.rs`, `trident.rs`,
`replay_shared.rs`, `store_conformance.rs`, `replay_race02.rs`) or is
marked as a limit. Nothing here is proven by inspection alone.

Labels. **[implemented]**: the code does it. **[tested]**: a named test
exercises it (implies implemented). **[experimental]**: implemented and
tested only in a form not meant for deployment. **[planned]**: neither
implemented nor tested; no claim is made. **[blocked]**: cannot be tested
in this environment. Statements in sections 2 to 5 that name a test are
[tested]; a statement marked as a limit is a limit, not a claim. Section
1a labels each statement.

## 1. Supported topologies

### One active verifier per replay store

A `Trident` built with `Trident::new_with_store` on a `FileStore` is the
only verifier that may use that file. The store takes an exclusive advisory
lock (`File::try_lock`) when opened; a second verifier, in the same process
or another, fails at open time with `StoreError::Locked`
(`a_second_verifier_on_the_same_store_fails_to_start_and_sees_all_prior_accepts_after_the_first_is_dropped`).

### Restart

When the process stops and a new one opens the same store:

* every envelope the old process accepted is refused, on the in-process and
  the wire path (`replay_after_restart_is_refused`);
* a lower or equal sequence from a sender is refused
  (`sequence_rollback_after_restart_is_refused`);
* an accepted nonce with a new sequence is refused
  (`duplicate_nonce_with_a_new_sequence_after_restart_is_refused`);
* quarantines and their releases are carried over
  (`a_quarantine_survives_a_restart`);
* with the clock moved back by hours, the verifier refuses to start
  (`StartError::ClockBehindStore`) unless
  `dangerously_allow_clock_behind_store` is set, and then still refuses the
  old envelopes before and after the clock catches up
  (`replay_after_restart_with_the_clock_moved_back_hours_is_refused`).

After a restart the start-up epoch floor applies as before: nothing is
accepted for `max_future_skew_ms`, and nothing issued at or before the
stored high-water mark is ever accepted.

A verifier on a non-durable `MemoryStore` (what `Trident::new` gives) has
none of this. Restart safety then rests on the wall clock and on the
caller persisting `Trident::high_water_ms` into
`TridentConfig::restored_high_water_ms`, as before. The Production profile
refuses it (`production_refuses_a_memory_store`).

### Not supported

* **Several verifiers sharing a store, on one host or across hosts.** The
  lock refuses it on one host. Across hosts there is no shared store at
  all: the crate does not replicate state and does not simulate doing so.
  Nothing in this crate makes two verifiers on two hosts agree on what was
  accepted. A deployment with more than one verifier routes each sender to
  exactly one of them (sender affinity) and gives each its own store.
  Section 1a describes the trait contract that a future shared store will
  have to meet; meeting it in a test does not make sharing supported.
* **A store on a network file system.** The lock and the fsync semantics
  are those of a local file system; nothing is tested elsewhere.
* **Hot standby from the same file.** A standby must wait for the active
  verifier's lock to be released, and then takes over everything the active
  one accepted (the second half of the two-verifier test above).

### Summary: single process, one host, never multi-host

[tested] unless marked.

* **Single process.** Many threads, one verifier: an envelope is accepted
  exactly once (`concurrent_acceptance_of_the_same_envelope_is_accepted_exactly_once_across_the_store`).
* **Several processes on ONE host, one active at a time.** The exclusive
  advisory lock admits one verifier per store file; the other process fails at
  open with `StoreError::Locked` and so cannot verify. Two real processes
  racing one envelope yield exactly one acceptance, and a later process
  refuses it as a replay
  (`store_failure_modes::two_processes_race_one_envelope_exactly_one_accepts`).
  A process that dies after the commit has still consumed the envelope
  (`store_failure_modes::lost_ack_real_process_aborts_after_the_commit_and_the_replay_is_refused`).
  This is a local operating-system lock, mutual exclusion on one machine, not
  concurrent sharing and not distributed consensus.
* **Multiple hosts** [not supported]. No replication, no shared store, no
  consensus. [BLOCKED: no multi-host environment to test in.]

A record present twice in the committed region fails closed at start
(`store_failure_modes::a_record_overwriting_its_neighbour_byte_for_byte_fails_closed_at_startup`);
one appended past the committed length is never counted
(`a_record_appended_twice_past_the_committed_length_is_never_counted`).
Rollback to an older valid copy is not detected from the file; it is refused
when the operator supplies `restored_high_water_ms` at or above the true
high-water, and the boundary is exact
(`rollback_is_not_detected_from_the_file_and_the_external_mark_boundary_is_exact`,
`an_older_copy_of_the_store_is_refused_when_an_external_mark_is_supplied`).
Storage lost while running refuses the envelope
(`a_storage_write_failure_refuses_and_leaves_state_unchanged_so_a_later_retry_is_accepted_once`;
at the admission boundary `stack-admission` `storage_unavailable::the_replay_store_lost_mid_run_denies_at_the_handoff_and_executes_nothing`).

## 1a. The replay store contract: check-and-commit

Decision D (RACE-02, R2-E-04). The Trident decides acceptance; the store
can only turn an acceptance into a refusal.

* [tested] `ReplayStore::commit` is an atomic check-and-commit. It refuses
  a record with `StoreError::Conflict` when the (sender, nonce) pair is
  still inside its retention window, when the sequence is not strictly
  greater than the sender's stored sequence, or when `issued_at_unix_ms` is
  below the stored epoch floor. A refused record leaves no trace
  (`common::conformance::replay_store_conformance`).
* [tested] The Trident maps a conflict to a refusal with the existing
  reason (`IssuedBeforeEpoch`, `Replay`, `SequenceNotIncreasing`), never to
  success, and leaves its memory unchanged
  (`a_store_conflict_refuses_with_the_matching_reason_and_does_not_poison_memory`).
  Conflicts are counted in `stack_trident_store_conflicts_total`
  [implemented].
* [tested] `operator_reset` publishes its epoch floor with
  `ReplayStore::raise_epoch_floor`; a verifier started later on the same
  store starts at that floor
  (`an_epoch_floor_raised_by_one_verifier_binds_the_other_through_the_store`).
  The `FileStore` persists the floor as a record and keeps it through
  compaction (`file_store_conflicts_survive_a_restart_and_a_compaction`).
  An older binary refuses a log holding a floor record as corrupt
  [implemented, fail closed].
* [tested] `MemoryStore` and `FileStore` implement the same check
  (`memory_store_conforms`, `file_store_conforms`). Both are single-writer.
  The `FileStore`'s torn-tail rules carry over: a discarded torn record is
  not consumed, an adopted one is
  (`file_store_torn_tail_record_is_not_consumed`,
  `file_store_torn_header_slot_record_is_consumed`).
* [tested] Behaviour change: an operator reset clears the verifier's
  memory of sender sequences but not the store's, so a sequence lowered
  after a reset is refused
  (`a_sequence_lowered_after_an_operator_reset_is_refused_by_the_store`).
  A `FileStore` restart already behaved this way.
* [experimental] Two `Trident` instances in ONE process sharing ONE
  test-only store (`SharedStore` in `tests/replay_shared.rs`, state behind
  `Arc<Mutex<..>>`) accept a given envelope at most once, sequentially and
  with 16 racing threads, and refuse a duplicate sequence or nonce in both
  directions (`two_verifiers_sharing_one_store_accept_the_same_envelope_at_most_once`,
  `two_verifiers_racing_one_envelope_accept_it_exactly_once`,
  `a_duplicate_sequence_across_two_verifiers_is_refused`,
  `a_duplicate_nonce_across_two_verifiers_is_refused`,
  `shared_store_conforms_when_reached_through_many_handles`). These are
  TRAIT-SEMANTICS tests on one machine with one clock. They are not
  multi-host tests and support no multi-host claim.
* [planned] A store shared across hosts (a kernel-owned PostgreSQL store).
  Not implemented, not tested, no claim. Design only:
  `SHARED_STORE_DESIGN.md`.
* [blocked] Any multi-host proof: this environment is one machine with one
  clock.
* Limit: the in-crate stores prune nonces by the record's own
  `accepted_at_unix_ms`. On a shared store, writers with different clocks
  would prune for each other; the design document requires database time
  for that reason.
* Limit: the check view (sender sequences, live nonces) is held in memory
  by both stores and is bounded by the retention window, not by
  `replay_cache_capacity`, the same posture as the restore at start.

## 2. Production checklist

A Production Trident is `Trident::new_with_store` with
`TridentConfig::production(audience)` (or `profile =
DeploymentProfile::Production`). It refuses to start unless all of the
following hold; each refusal is a typed error naming the field
(`production_refuses_no_audience_the_unbound_opt_out_epoch_off_and_wide_skew_at_startup`,
`production_refuses_a_memory_store`,
`production_refuses_legacy_keys_at_start_and_on_ring_replacement`).

1. `audience` is set to this receiver's identifier and
   `allow_unbound_audience` is false. Senders seal with `seal_for` and the
   same string.
2. The replay store is durable (`FileStore`), on local storage, with the
   file and its directory writable by the verifier and by nothing else.
3. `enforce_startup_epoch` is true.
4. `max_past_skew_ms <= PRODUCTION_PAST_SKEW_CAP_MS` (5 minutes) and
   `max_future_skew_ms <= PRODUCTION_FUTURE_SKEW_CAP_MS` (1 minute).
5. Every key in the ring was added with `KeyRing::insert_with_meta`: a
   non-empty `issuer_id`, a purpose, a validity window. `KeyRing::insert`
   entries (legacy, no issuer) are refused at start and by
   `replace_keyring`.
6. `dangerously_allow_clock_behind_store` is false, except for one
   deliberate restart after a clock correction. It is logged at warn.
7. The external high-water mark (section 3) is persisted somewhere the
   store file's writer cannot reach, and handed back as
   `restored_high_water_ms` on every start.
8. Downstream, admission code calls `VerifiedHandoff::require_production`
   before acting on a handoff
   (`production_marks_handoffs_production_and_development_marks_them_development`).
   A Development Trident can never produce a Production-assured handoff.
9. Alerts: `stack_trident_store_failures_total` above zero (the verifier is
   refusing valid work with `state_unavailable`, or will lose quarantine
   marks on restart); `stack_trident_halts_total{cause="store_failure"}`
   (see section 3); `stack_trident_store_conflicts_total` above zero (the
   store caught what memory did not: a replay through another writer, or
   state memory had dropped); `stack_trident_check_failures_total{reason="key_revoked"}`
   and `{reason="key_expired"}` for senders still using old keys.

Key rotation: issue the new key with `not_before_ms` at the start of the
overlap and swap the ring in before then; give the old key `not_after_ms`
at the end of the overlap; after that it refuses itself (`KeyExpired`).
Mark a leaked key `Revoked` and swap at once; the swap takes the state
lock, so a verification already past the MAC check is still refused
(`rt_toctou_key_revoked_between_prong_checks_is_refused`,
`a_rotation_overlap_is_expressed_with_validity_windows`,
`keys_not_yet_valid_expired_retired_and_revoked_are_refused_with_distinct_reasons`).

Recovery from a corrupt store: the verifier does not start on a damaged
file and there is no repair tool. Start it on a fresh file with
`restored_high_water_ms` set to the last known mark. The epoch floor then
refuses everything issued at or before that mark, which covers every
envelope the old store had accepted; what is lost is quarantine marks and
sender sequences, so a sender may restart its counter from any value above
zero once.

## 3. What the store protects against, and what it cannot

The file is an append-only log: a 32-byte magic, two alternating header
slots (generation, committed length, chain head, SHA-256 of those), then
records that each carry the full 32-byte previous chain hash and their own
SHA-256. A commit appends, `sync_data`, writes the next slot, `sync_data`,
and only then is the acceptance committed in memory and returned to the
caller. The in-memory commit never runs before the durable one.

Detected at start, refusing to run (`StartError::Store`):

* a flipped byte inside the committed region
  (`a_flipped_byte_in_the_middle_fails_closed_at_startup`);
* a file shorter than its header commits, whether the cut is inside a
  record, at a record boundary, or inside the header
  (`a_truncation_in_the_middle_fails_closed_at_startup`);
* two records swapped (`swapped_records_fail_closed_at_startup`);
* a directory, a missing parent, a file that is not a store
  (`unavailable_storage_at_startup_fails_closed`);
* an unreadable header slot that no torn slot write explains
  (`a_torn_header_slot_write_does_not_forget_the_last_acceptance`, second
  half);
* in a 400-round fuzz of one to three random edits, every damaged file
  either refuses to start or refuses every previously accepted envelope
  (`random_damage_to_the_store_never_yields_a_trident_that_accepts_an_accepted_envelope`).

Tolerated, because one crash leaves exactly this:

* a partial or garbled record past the committed length (a crash while
  writing the record): discarded, never acknowledged, cut off by the next
  commit (`a_torn_tail_is_tolerated_and_cut_off_by_the_next_commit`);
* one complete, chain-valid record past the committed length together
  with an unreadable newest slot (a crash while writing the slot): the
  record is adopted, so that envelope is refused as a replay
  (`a_torn_header_slot_write_does_not_forget_the_last_acceptance`). Adoption
  is the restrictive direction: the sender either never saw the acceptance
  and resends under a new sequence, or did and is simply not allowed a
  second one.

A storage write that fails during a commit refuses the envelope
(`state_unavailable`, RETRY) and changes nothing in memory, so the same
envelope is accepted exactly once when storage recovers
(`a_storage_write_failure_refuses_and_leaves_state_unchanged_so_a_later_retry_is_accepted_once`).

A quarantine mark the store fails to persist (D-24) is counted in
`stack_trident_store_failures_total`. Under Production it also halts the
verifier (fail closed, `stack_trident_halts_total{cause="store_failure"}`):
every envelope is refused `Halted` until `operator_reset` persists the
mark, and a reset while the store still fails stays halted
(`production_fails_closed_when_a_quarantine_mark_cannot_be_persisted`,
`a_store_failure_halt_is_counted_with_its_cause`). Under Development the
in-memory quarantine stands and the verifier keeps working
(`development_counts_a_failed_quarantine_mark_and_keeps_the_in_memory_quarantine`).
A release mark that fails is counted and is restrictive in every profile:
the quarantine returns on restart
(`a_failed_release_mark_is_counted_and_the_quarantine_returns_on_restart`).

Replay after a key rotation and a restart on the same store is refused,
and stays refused as a replay even if the old key is mistakenly made
active again (`replay_after_key_rotation_and_restart_is_refused`).

Not detectable from the file alone:

* **A writer with access to the file.** The chain is unkeyed SHA-256: it
  proves consistency, not authorship. Anyone who can write the file can
  rewrite it consistently, truncate it to a record boundary and rewrite
  the slots to match, or empty it. Protect the file with the operating
  system; the crate does not and cannot.
* **An older full copy of the store** (a restored disk snapshot, a backup
  put back, a container started from an old image). Its chain is intact.
  It is caught only by the external high-water mark: persist
  `Trident::high_water_ms()` on every accept, or periodically plus
  `max_future_skew_ms` of margin, in a place the store's writer cannot
  reach (a different host, an append-only service, a monitoring system),
  and pass it back as `restored_high_water_ms`. A durable store whose
  high-water mark is behind that value refuses to start with
  `StartError::StoreBehindExternalMark`
  (`an_older_copy_of_the_store_is_refused_when_an_external_mark_is_supplied`).
  Without the mark the older copy starts, and the acceptances it has
  forgotten are refused only for as long as the epoch floor and the skew
  window happen to cover them. The same test shows both halves.

Compaction rewrites the log without nonces past their retention window and
keeps every sender sequence, the high-water mark and every quarantine; it
locks, writes and syncs a fresh file before renaming it over the old one
(`compaction_keeps_sequences_live_nonces_and_quarantines`). The compaction
threshold is `FileStoreOptions::compact_after_bytes`.

## 4. The limits of HMAC

Prong 1 is HMAC-SHA256 under a key shared between the sender and every
receiver that verifies it. A MAC that verifies proves exactly this: whoever
sealed the envelope held that key. It does not prove:

* **who the holder was.** Any holder of the key can seal, including every
  receiver that holds it to verify. A receiver that trusts a sender key can
  forge that sender toward any other receiver that trusts the same key;
  audience binding stops honest receivers from accepting a redirected
  envelope (`cross_receiver_redirection_with_the_same_key_between_two_production_receivers_is_refused`,
  `rt_cross_receiver_replay_is_refused`), it does not stop a dishonest
  holder from sealing a fresh one. Prefer one key per (sender, receiver)
  pair, or move to signatures for non-repudiation.
* **that the action was legitimate.** The Trident judges the envelope, not
  the request in it. `gate_outcome` is the sender's claim, carried, not
  re-judged. Authorisation is a separate layer.
* **the issuer.** `KeyMeta::issuer_id` is a label the ring operator asserts
  at ring-build time so that an acceptance can be traced to an issuance
  decision. The MAC does not cover it and cannot vouch for it.

A refusal reveals whether the claimed fingerprint is in the ring
(`UnknownSender` versus `MacMismatch`) and, with key metadata, what state
the key is in (`KeyNotYetValid`, `KeyExpired`, `KeyRetired`, `KeyRevoked`).
Fingerprints are public identifiers and a key's state is known to its
holder, so this is accepted; a deployment that must hide ring membership
collapses these reasons at its own boundary. No new oracle on key bytes is
added: the stateful freshness results stay masked for any envelope that is
not authentic under a usable key.

## 5. Assurance

`VerifiedHandoff::assurance` is `Assurance::Production` only for a handoff
accepted by a Production-profile Trident, which by construction had every
item in section 2 at start. The checks on the envelope are the same under
both profiles; what differs is what the deployment was allowed to assume.
Admission code refuses a `Development` handoff with
`require_production()`.
