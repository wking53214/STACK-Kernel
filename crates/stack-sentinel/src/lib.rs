//! # stack-sentinel: the Sentinel Hash-Chain offline verifier
//!
//! ## What exists today, and what this crate is
//!
//! The Sentinel Hash-Chain is the one STACK component that exists today. It
//! lives in the Python repository `sentinel_os`, where every ledger row is
//! written to Postgres with a SHA-256 hash that covers the row before it.
//! This crate is new. It is an independent second implementation, in Rust,
//! of that repository's **offline verifier**: it reads the same export file
//! and the same anchor file and prints the same verdict words, without
//! importing, calling or trusting any Python code. Two implementations that
//! agree on every verdict are evidence that the rule is written down
//! correctly; one that disagrees points at a bug in one of them.
//!
//! It is read-only. It opens no database, writes no file, and holds no state
//! between calls.
//!
//! ## The metaphor
//!
//! A tamper seal on a factory logbook. Every page carries the hash of the
//! page before it, so tearing out or rewriting a page breaks every seal
//! after it. The last seal is also photographed and kept in a safe outside
//! the factory (the *head anchor*), so tearing off the last few pages and
//! re-sealing the rest is caught too.
//!
//! ## The goal
//!
//! Persistent memory whose every alteration, reordering or truncation is
//! detectable offline, by someone who does not trust the running system.
//!
//! ## How the Python implementation works (the thing being reproduced)
//!
//! File and function names are the real ones in `sentinel_os`.
//!
//! * **`sentinel_os/canonical_fields.py`** holds the lists the writer and
//!   the verifiers share: `OPTIONAL_HASHED_FIELDS` (fields that enter a
//!   row's hash only when present and truthy, so rows written before a field
//!   existed keep their bytes), `CONTRACT_CANONICAL_FIELDS`,
//!   `OBSERVED_EVENT_CANONICAL_FIELDS`, and the `attestation_policy` form.
//! * **`sentinel_os/twin_custody.py`** is the witness. `canonical_form(row)`
//!   rebuilds, per record kind, the dictionary the writer hashed;
//!   `recompute_current_hash(row)` hashes it as
//!   `sha256(json.dumps(form, sort_keys=True, default=str).encode())`;
//!   `deep_verify_row` checks one row (hash, then subject binding, then
//!   shuffle seed, then signature); `verify_rows` walks the chain from the
//!   literal `"genesis"`; and `read_head_anchor`, `verify_head_anchor` and
//!   `check_head_anchor` handle the anchor.
//! * **`sentinel_os/governance/authorized_by_attestation.py`** signs a row's
//!   `authorized_by` claim with HMAC-SHA256 under a service key.
//!   `key_fingerprint` names a key; `abv2.<fp>.<digest>` covers the claim,
//!   the previous hash and the record kind; `abv3.<fp>.<digest>` also covers
//!   `content_prehash`, the hash of the whole canonical row minus the
//!   signature. `verify_shuffle_seed` re-derives the reserved Layer 1 seed.
//! * **`tools/verify_receipts.py`** is the offline command: `--export`,
//!   `--anchor`, `--trusted-fingerprints`, `--key-file`. It prints exactly
//!   one of six verdicts, then the first failing row and the reason. The
//!   delivery note is `APPLY_verdict_receipts.md`.
//!
//! ## The six verdicts, all implemented
//!
//! | verdict | what it means | needs |
//! |---|---|---|
//! | `VERIFIED` | every row and the anchor hold | export, anchor, key |
//! | `TAMPERED` | a hash, a link or a signature does not hold | export (a key for signatures) |
//! | `TRANSPLANTED` | `subject_digest` is not the CNS digest of the row's own `input_data` | export |
//! | `SEED_FORGED` | a `shuffle_seed` does not re-derive under a held key | export, key |
//! | `TRUNCATED` | the chain is shorter than, or differs from, its signed anchor | export, anchor, key |
//! | `UNATTESTED` | an unsigned claim after the `attestation_policy` marker, or a key the auditor does not trust | export, key |
//!
//! `VERIFIED` covers only the columns each row's record kind hashes
//! ([`canonical::hashed_columns`]; for several kinds only named keys of the
//! `data` mapping). Every other column (`id`, `timestamp`, `call_sid`,
//! `cassette_snapshot`, `record_kind` on a base row, any column an export
//! adds) can be changed without changing any hash, so `VERIFIED` says
//! nothing about it. This is the `sentinel_os` ledger design, reproduced as
//! it is. [`Report::unhashed_columns`] lists, from a closed set of names,
//! the unhashed columns an export carried.
//!
//! Every verdict the Python tool can print, this crate can print. What it
//! cannot see is outside both tools: which human stands behind a key, and
//! anything done by a holder of the service key, who can re-sign a rebuilt
//! chain and a new anchor (`APPLY_verdict_receipts.md`, section 6).
//!
//! ## Design
//!
//! * [`pyjson`] reads JSON the way `json.loads` does and writes it the way
//!   `json.dumps` does: Python's default separators (a comma and a space, a
//!   colon and a space) for the row hash, compact separators for HMAC
//!   payloads and the anchor, `ensure_ascii` escaping as lowercase `\uXXXX`,
//!   exact Python ints, and Python's `repr(float)`.
//! * [`canonical`] rebuilds each record kind's canonical form, reading each
//!   column the way the Python does (`row["x"]` must exist, `row.get("x")`
//!   may be absent).
//! * [`cns`] reproduces `cns.gate.subject_digest`, the length-prefixed CNS
//!   encoding.
//! * [`attest`] and [`anchor`] check the HMACs in constant time.
//! * [`verify`] walks the chain and assembles a [`Report`].
//!
//! ## Outcomes and failure handling
//!
//! Every call returns a typed result and never panics. A [`Report`] maps to
//! the CNS `GateOutcome`: `PASS` only for `VERIFIED`; `RETRY` when the
//! finding depends on what the auditor supplied (the anchor or the keys);
//! `TERMINAL_BREACH` when the export itself is inconsistent, or when a key
//! finding cannot be repaired by supplying a key (a retired-key signature,
//! or an unknown key named after a policy marker whose key the verifier
//! holds). A report's outcome is the most severe across all its findings,
//! and after a RETRY finding the walk keeps checking later rows, so a
//! repairable finding cannot hide a broken seal further down. `RETRY`
//! resolves as **reject** (nothing changed, resubmit with the correction)
//! and `TERMINAL_BREACH` as **quarantine** (the export is not accepted as
//! evidence, the finding is counted, the report names the first failing row
//! for review). Inputs that cannot reach a verdict at all (too large, not
//! JSON, not an export, no trusted key) are a [`VerifyError`], always
//! `RETRY` and reject. See [`verdict`] for the full table and why rollback
//! and halt are never used here.
//!
//! ## Telemetry
//!
//! Metrics `stack_sentinel_*` through the `metrics` facade with closed-enum
//! labels only, and spans `stack.sentinel.*` through `tracing`. Raw export
//! content is never logged: spans carry its length and full SHA-256, and
//! report details show stored values only when they are a well-formed hash,
//! otherwise as type, length and full SHA-256. See [`telemetry`].
//!
//! ## Keys
//!
//! No key is compiled in, defaulted or generated. The caller supplies every
//! key, and a verifier with none refuses to run. Test keys in this crate's
//! tests are labelled as test fixtures. The one short identifier this crate
//! produces is the Python wire format's 16-hex key fingerprint, which
//! signatures and anchors carry; every hash it computes or reports is the
//! full 64-hex SHA-256.
//!
//! ## Timing
//!
//! This is an offline tool, not a request path, so Active Timing
//! Cancellation (ANC) does not apply to it as used. Two things would matter
//! if it were ever put on a request path: the chain walk stops at the first
//! TERMINAL_BREACH row, so its run time reveals where the failure is, and
//! report details carry value lengths. Refusals are not constant-time
//! either: an over-cap export is refused by its length alone, faster than a
//! readable one is verified. Such a caller should return only the
//! verdict word to an untrusted party and pad the response time with ANC.
//! HMAC comparisons are constant-time already.
//!
//! ## Where this is stricter than Python
//!
//! Each of these fails closed where the Python would either accept an input
//! no honest writer produces or stop with an uncaught exception:
//!
//! * duplicate JSON object keys, unpaired surrogate escapes, and nesting
//!   deeper than 256 are refused as malformed;
//! * a row `id` must be a JSON integer that fits in 64 bits (Python's
//!   `int()` also accepts strings and floats);
//! * anchor fields must have the types the writer gives them;
//! * where the Python raises `AttributeError` or `TypeError` that nothing
//!   catches (a `data` column that is truthy but not a mapping, a
//!   non-ASCII signature digest), this crate reports `TAMPERED` instead of
//!   stopping;
//! * keys come only from the caller; the Python tool also reads the
//!   `ICEBERG_LEDGER_ATTESTATION_KEY*` environment;
//! * a key set with no trusted key (only retired keys) is refused;
//! * by default a signature valid only under a retired key, an anchor sealed
//!   with a retired key, and an anchor sealing zero rows are findings, where
//!   the Python accepts them ([`VerifierConfig::python_compatible`] restores
//!   the Python behaviour for parity testing);
//! * the keyed work one export may cause is capped
//!   ([`VerifierConfig::max_keyed_bytes`]), and seeds and signatures that
//!   cannot match are refused without computing any HMAC.

pub mod anchor;
pub mod attest;
pub mod canonical;
pub mod cns;
pub mod config;
pub mod error;
pub mod pyjson;
pub mod telemetry;
pub mod verdict;
pub mod verify;

pub use anchor::{
    check_head_anchor, check_head_anchor_with, parse_head_anchor, verify_head_anchor, AnchorError, HeadAnchor,
};
pub use attest::{key_fingerprint, parse_key_file, AttestationStatus, KeyError, KeySet, SecretKey};
pub use canonical::{canonical_form, hashed_columns, recompute_current_hash, RecomputeError};
pub use cns::subject_digest;
pub use config::VerifierConfig;
pub use error::VerifyError;
pub use verdict::{AnchorSummary, Finding, GateOutcome, Reason, Report, Resolution, Verdict};
pub use verify::{
    deep_verify_row, deep_verify_row_with, parse_export, verify_rows, verify_rows_with, ChainWalk, LedgerRow, Verifier,
    EXPORT_FORMAT,
};
