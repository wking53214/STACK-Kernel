# Shared replay store: design (PLANNED)

**Status: PLANNED. Nothing in this document is implemented or tested.**
It makes no claim about any running system. It describes a kernel-owned
PostgreSQL replay store that would let more than one Trident verifier, on
more than one host, share one view of what was accepted. Multi-host
testing is BLOCKED in the environment where this was written (one machine,
one clock, no database server), and no PostgreSQL client exists in the
workspace. Building it needs a dependency decision (section 9) and a
separate approval.

Labels used below: **[implemented]** the code does it today; **[tested]**
a named test exercises it; **[planned]** neither. Unless a line says
otherwise, everything here is [planned].

## 1. What already exists and what this builds on

* [tested] The `ReplayStore` trait is an atomic check-and-commit
  (decision D, `DEPLOYMENT.md` section 1a): `commit` refuses with
  `StoreError::Conflict` when the nonce is still recorded, the sequence is
  not strictly greater than the sender's stored sequence, or `issued_at`
  is below the stored epoch floor, and a refused record leaves no trace.
* [tested] A reusable conformance suite
  (`tests/common/conformance.rs`: `replay_store_conformance`,
  `replay_store_shared_conformance`) that a new store must pass.
* [tested] The Trident maps a conflict to the matching refusal reason and
  leaves its memory unchanged. The Trident stays the authority that
  decides acceptance; the store can only turn an acceptance into a
  refusal.

A PostgreSQL store is one more implementation of that trait. It does not
change how the Trident judges an envelope.

## 2. Ownership

The store is owned by STACK-Kernel: its schema, its migrations, its
credentials and its deployment. It runs in a database (or a schema with
its own role) that only Trident verifiers write to.

### Why the CNS ledger is not reused

* Different object. The CNS ledger records decisions and their
  redemption under CNS's vocabulary. The Trident's state is per-sender
  sequences, nonces and an epoch floor for handoff envelopes. Sharing a
  table would couple two independently versioned contracts.
* Different authority. CNS grants no permission; the kernel decides
  acceptance. If the kernel's replay state lived in a CNS-owned ledger,
  every CNS writer (Python and Node receivers, their operators) would
  hold write access to the kernel's acceptance state.
* Known defect class. RACE-02 R2-C-01 showed the CNS PostgreSQL ledger
  purging by database time while judging expiry by receiver time, which
  made an expired decision redeemable repeatedly. This design takes the
  lesson (section 5) but does not inherit the code.
* Release coupling. A CNS schema change would become a kernel outage.

## 3. Schema

All instants that the database compares are database time
(`timestamptz`, from `now()` or `clock_timestamp()`). Values that come
from envelopes (`issued_at_unix_ms`, sequences) are stored as the 64-bit
unsigned values the trait carries; PostgreSQL has no unsigned 64-bit
type, so they are `numeric(20,0)` with a range check.

```sql
CREATE TABLE trident_store (
    store_id        text PRIMARY KEY,
    schema_version  integer NOT NULL,
    epoch_floor_ms  numeric(20,0) NOT NULL DEFAULT 0
                    CHECK (epoch_floor_ms BETWEEN 0 AND 18446744073709551615),
    retention       interval NOT NULL,      -- nonce retention, fixed per store
    max_clock_skew  interval NOT NULL       -- allowed verifier-to-database skew
);

CREATE TABLE trident_writer (
    store_id        text NOT NULL REFERENCES trident_store,
    writer_id       text NOT NULL,          -- one per verifier process
    fencing_token   bigint NOT NULL,        -- from a sequence, never reused
    lease_expires   timestamptz NOT NULL,
    revoked         boolean NOT NULL DEFAULT false,
    PRIMARY KEY (store_id, writer_id)
);
CREATE SEQUENCE trident_fencing_token;

CREATE TABLE trident_sender (
    store_id        text NOT NULL REFERENCES trident_store,
    sender          bytea NOT NULL CHECK (length(sender) = 32),
    last_sequence   numeric(20,0) NOT NULL
                    CHECK (last_sequence BETWEEN 0 AND 18446744073709551615),
    max_issued_ms   numeric(20,0) NOT NULL, -- per-sender high-water mark
    last_accepted   timestamptz NOT NULL,   -- database time
    PRIMARY KEY (store_id, sender)
);

CREATE TABLE trident_nonce (
    store_id        text NOT NULL REFERENCES trident_store,
    sender          bytea NOT NULL CHECK (length(sender) = 32),
    nonce           bytea NOT NULL CHECK (length(nonce) = 16),
    expires_at      timestamptz NOT NULL,   -- database time
    PRIMARY KEY (store_id, sender, nonce)
);
CREATE INDEX trident_nonce_expiry ON trident_nonce (store_id, expires_at);

CREATE TABLE trident_quarantine (
    store_id        text NOT NULL REFERENCES trident_store,
    sender          bytea NOT NULL CHECK (length(sender) = 32),
    since_ms        numeric(20,0) NOT NULL,
    PRIMARY KEY (store_id, sender)
);
```

The store-wide high-water mark is `max(max_issued_ms)` over senders, so a
commit never takes a store-wide row lock to maintain it.

## 4. The atomic check-and-commit

One transaction per `commit`, at `READ COMMITTED`. Each statement is a
compare-and-set on one row; a statement that changes no row is a conflict
and the transaction is rolled back, so a refused record leaves no trace.

```sql
BEGIN;

-- (a) Fencing and epoch floor, under a SHARE lock on the store row so
--     that raise_epoch_floor (which UPDATEs that row) is ordered against
--     every in-flight commit. Zero rows: fenced, or below the floor.
SELECT s.epoch_floor_ms
  FROM trident_store s
  JOIN trident_writer w ON w.store_id = s.store_id
 WHERE s.store_id = $store
   AND w.writer_id = $writer
   AND w.fencing_token = $token
   AND NOT w.revoked
   AND w.lease_expires > clock_timestamp()
   FOR SHARE OF s;
-- client: no row => Fenced; row with $issued_at < epoch_floor_ms => floor
--         conflict; either way ROLLBACK.

-- (b) Nonce: insert, or reclaim an expired entry. Zero rows: consumed.
INSERT INTO trident_nonce (store_id, sender, nonce, expires_at)
VALUES ($store, $sender, $nonce, now() + (SELECT retention FROM trident_store WHERE store_id = $store))
ON CONFLICT (store_id, sender, nonce) DO UPDATE
   SET expires_at = EXCLUDED.expires_at
 WHERE trident_nonce.expires_at <= now()
RETURNING 1;

-- (c) Sender sequence: strictly increasing compare-and-set. Zero rows:
--     the stored sequence is equal or higher.
INSERT INTO trident_sender (store_id, sender, last_sequence, max_issued_ms, last_accepted)
VALUES ($store, $sender, $sequence, $issued_at, now())
ON CONFLICT (store_id, sender) DO UPDATE
   SET last_sequence = EXCLUDED.last_sequence,
       max_issued_ms = GREATEST(trident_sender.max_issued_ms, EXCLUDED.max_issued_ms),
       last_accepted = EXCLUDED.last_accepted
 WHERE trident_sender.last_sequence < EXCLUDED.last_sequence
RETURNING 1;

COMMIT;
```

`INSERT ... ON CONFLICT DO UPDATE ... WHERE` locks the conflicting row and
evaluates the `WHERE` against its latest committed version, so two
concurrent commits of the same sender serialize on that row and exactly
one passes. To report every cause the trait can name (nonce and sequence
together), the client, after a rollback, runs one read-only query for
the three facts and builds `StoreError::Conflict` from it; the refusal
itself does not depend on that read.

`raise_epoch_floor`:

```sql
UPDATE trident_store SET epoch_floor_ms = GREATEST(epoch_floor_ms, $floor)
 WHERE store_id = $store;
```

It waits for the SHARE locks of in-flight commits, so once it returns no
commit that read the old floor can still be in flight.

`load` reads the store row, every sender, every nonce with
`expires_at > now()`, and every quarantine, in one `REPEATABLE READ`
transaction. `record_quarantine` and `record_release` are an upsert and a
delete on `trident_quarantine`, fenced like (a).

## 5. Database time for retention

* Retention and purge use database time only: `expires_at = now() +
  retention`, purge `DELETE ... WHERE expires_at <= now()`. No verifier
  clock ever decides whether a nonce may be forgotten. (The in-crate
  stores prune by the record's own `accepted_at_unix_ms`; on a shared
  store that would let a fast verifier prune for everyone.)
* The Trident's stale check still uses the verifier clock against the
  sender's `issued_at`. For the nonce to outlive every envelope that any
  verifier could still judge fresh, `retention` must be at least
  `max_past_skew_ms + max_future_skew_ms + 2 * max_clock_skew`.
* At start, and periodically, each verifier compares its clock with
  `clock_timestamp()` and refuses to start (or halts) when the difference
  exceeds `max_clock_skew`. A non-numeric or missing database time is a
  refusal, never a pass (R2-C-04 is the counter-example).
* The schema refuses a `retention` shorter than that bound at store
  creation; the verifier re-checks its own config against it at start.

## 6. Fencing token

Each verifier process registers once at start: it takes
`nextval('trident_fencing_token')`, inserts its `trident_writer` row with
a lease, and renews the lease well inside its length. Every write checks
token, lease and `revoked` in the same transaction as the write
(statement (a)). This is what stops a verifier that was paused (GC, VM
freeze, network partition) past its lease, or one an operator revoked,
from committing when it wakes. A fenced commit is a refusal
(`StateUnavailable`, RETRY) and the Trident halts until an operator
restarts it; the trait would gain a `Fenced` error variant [planned].

## 7. Replication and durability

* `is_durable()` returns `true` only when the store has verified, at
  start, that commits are synchronously replicated:
  `synchronous_commit` is `on`, `remote_write` or `remote_apply`, and
  `synchronous_standby_names` names a quorum. Otherwise the Production
  profile refuses it, exactly as it refuses a `MemoryStore` today.
* Reason: an acknowledged acceptance that exists only on a primary which
  is then lost, followed by promotion of an asynchronous replica, forgets
  nonces and sequences that verifiers already acted on, and the replays
  are accepted.
* `remote_apply` is preferred, so a read on a promoted standby sees every
  acknowledged commit.
* A restore from backup is still caught only by the external high-water
  mark (`restored_high_water_ms`), as with the `FileStore`.
* Two primaries at once (split brain) is outside what the store can
  detect; the cluster manager must fence the old primary.

## 8. Ambiguous commit results

If the connection fails after `COMMIT` was sent and before its result
arrived, the commit may or may not have happened.

* The store returns an error, never `Ok`; the Trident refuses the
  envelope (`StateUnavailable`, RETRY) and changes nothing in memory.
* The next attempt re-reads: if the commit landed, the same envelope is
  refused as `Replay`; if not, it is accepted once.
* Consequence, stated openly: an envelope whose commit landed but whose
  acknowledgement was lost is never accepted by anyone. At most once is
  kept; exactly once is not. Recognising "my own lost commit" (an
  idempotency key per writer and envelope) would recover it but would
  let one envelope produce two acceptances (one lost, one returned) in
  the verifier's own history, so it is not proposed.

## 9. Failure modes

| Event | Store result | Trident behaviour |
|---|---|---|
| Database unreachable at start | `load` error | refuses to start |
| Database unreachable later | `Io` | `StateUnavailable`, RETRY |
| Statement or lock timeout | `Io` | `StateUnavailable`, RETRY |
| Lost commit acknowledgement | `Io` | refuse, re-read on retry (section 8) |
| Nonce, sequence or floor conflict | `Conflict` | `Replay` / `SequenceNotIncreasing` / `IssuedBeforeEpoch` |
| Lease expired, writer revoked | `Fenced` [planned variant] | refuse, halt |
| Verifier clock outside `max_clock_skew` | start refused or halt | refuse everything |
| Asynchronous replication detected | `is_durable() == false` | Production refuses to start |
| Schema version mismatch | `load` error | refuses to start |
| Quarantine mark not written | `Io` | Production halts (D-24, [tested] for the `FileStore`) |
| Network partition from the database | `Io` | availability lost, safety kept |

Design consequence to resolve before building: the Trident holds its
state lock across `ReplayStore::commit` [implemented]. With a network
store every verification in a process would wait behind one database
round trip. Options: keep it (simple, slow), or split the trait into a
prepare step under the lock and a commit step outside it with the
in-memory commit after; the second needs its own retest cycle.

## 10. Dependency question

No PostgreSQL client is in the workspace. Two ways to reach the database,
plus a third for completeness:

| | Rust client crate (`postgres` or `tokio-postgres`) | `psql` subprocess (as CNS's Node ledger does) | Kernel-owned sidecar process |
|---|---|---|---|
| New dependencies | a client plus its tree (`tokio` under both crates, TLS stack of choice); supply-chain review needed | none in Rust; `psql` binary on every host | the sidecar's own (one of the left two) |
| Error typing | SQLSTATE codes and typed errors; lost-acknowledgement detectable | exit code and stderr text; coarse, parsing is fragile | whatever the sidecar protocol defines |
| Ambiguous commit detection (section 8) | yes, connection error after COMMIT | hard: a killed or timed-out `psql` looks like many other failures | depends on the left two |
| Latency per commit | one round trip on a pooled connection | process spawn per commit, or a long-lived `psql` fed through a pipe | one local IPC hop plus the database round trip |
| Transaction control | exact | `--single-transaction`, `ON_ERROR_STOP`; per-statement row counts need careful output parsing | exact inside the sidecar |
| Workspace lints (`unsafe` denied in our code) | met; `unsafe` lives in dependencies | met | met in our code |
| Credentials | in-process (env, file, TLS client cert) | `PGPASSFILE` / env for a child process | isolated in the sidecar |
| Testability here | BLOCKED: no database server | BLOCKED: no database server | BLOCKED |

Stated recommendation, not a decision: a Rust client crate, because
section 8 depends on telling a lost acknowledgement apart from a refused
statement, and `psql` output does not reliably allow that. The cost is a
new dependency tree that needs review and an explicit owner approval. The
`psql` route avoids that cost and is how CNS's Node ledger works; it is
viable only with a long-lived session and strict output parsing, and its
ambiguity handling would have to refuse on every unclassified failure.

## 11. What must be true before any claim

1. The owner approves a dependency (section 10).
2. The store passes `replay_store_conformance` and
   `replay_store_shared_conformance` against a real database.
3. Two verifier processes on two hosts, with independent clocks, against
   a synchronously replicated cluster, pass the at-most-once tests of
   `tests/replay_shared.rs` rewritten across processes, plus failover,
   lease expiry, partition and lost-acknowledgement injection.
4. `DEPLOYMENT.md` moves the shared-store line from [planned] only for
   what those tests show.
