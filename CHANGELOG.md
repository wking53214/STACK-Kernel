# Changelog

## Unreleased

### Naming

In prose and comments the kernel is written ≡TACK. Crate, binary, file, metric, span and environment-variable names use `stack` or `STACK`. The repository is named STACK-Kernel.

### Renamed (breaking for anything outside this repository)

Anything that reads these names from outside the repository needs the new spelling. That includes dashboards, alert rules, scripts and CI.

| Kind | Old | New |
|---|---|---|
| Crates | `tack-*` (for example `tack-sentinel`) | `stack-*` |
| Binary | `tack-sentinel-verify` | `stack-sentinel-verify` |
| Prometheus metrics | `tack_*` (for example `tack_sentinel_trips_total`) | `stack_*` |
| Alert names | `Tack*` (for example `TackSentinelTamperEvidence`) | `Stack*` |
| Tracing spans | `tack.*` (for example `tack.greenwave.admit`) | `stack.*` |
| Environment variables | `TACK_ADAPTIVE_*`, `TACK_VERIFY_*`, `TACK_ANC_PIPELINE_*`, `TACK_SENTINEL_REDTEAM_CHILD` | the same names with the prefix `STACK_` |
| C++ CMake project and targets | `tack_containment_stack`, `tack_containment`, `tack_tests`, `tack_production_hardened` | `stack_containment`, `stack_containment`, `stack_tests`, `stack_production_hardened` |
| C++ ctest names | `TACKTests`, `TACKProductionHardened` | `STACKTests`, `STACKProductionHardened` |

Not renamed, on purpose:

- The key bytes `tack-sentinel-other-test-fixture-key-not-a-real-secret` and the files under `crates/stack-sentinel/tests/fixtures/`. The recorded Python signatures and fingerprints depend on them.
- The recorded runs in `manual/measurements/` and the review records in `manual/review/`.

### Added

- `manual/sections/trident_puzzles.md`: design note for the Trident puzzle gate, which holds every piece of a declared puzzle until the whole is present and has passed inspection, so a hostile payload cut into harmless pieces is inspected where it is assembled. Defaults come from a synthetic simulation; the note lists what that simulation could not show.
- `stack-trident` `puzzle` (prototype, not wired into anything): `PuzzleConfig` with documented defaults and hard ceilings, and the strict piece format. A piece is a verified envelope whose payload has exactly the keys `kind`, `puzzle`, `index`, `total`, `root` and `data`; an abort has exactly `kind` and `puzzle`. Extra keys, upper-case or odd-length hex, text or float numbers and out-of-range values are refused. `root_of` commits to the finished puzzle with a domain-separated SHA-256 over the piece digests; `split` is the producer side.
- `stack-trident` `puzzle`: the `Inspector` trait, `InspectInput` (the assembled whole plus the trailing bytes of the sender's last released wholes) and `Finding` (`Pass`, `Suspicious`, `Hostile`). There is no default inspector. `DenyListInspector` is a reference tripwire for known byte patterns, including a pattern split across a join; it misses any paraphrase.
- `stack-trident` `puzzle`: `PuzzleGate`, which owns an `Arc<Trident>` and verifies every piece through it before touching any state. It holds pieces until a puzzle is complete, recomputes the root, inspects the whole with look-back over the tails of the sender's last released wholes, and only then releases. Incomplete puzzles explode after an idle limit (capped by a hard lifetime) and the sender takes a breach; an authenticated abort is free; over-limit senders get a "busy" refusal with no breach; a full holding area evicts the oldest incomplete puzzle; released roots are remembered for a replay window; a breaker allows a free allowance of breaches, then quarantines the sender for a limited time. A `Suspicious` finding is never a breach. State is in memory and inspection runs under the gate lock.
- `stack-trident` tests: `tests/puzzle.rs` (one test per rule) and `tests/puzzle_redteam.rs` (a hoarder, a marker cut over four puzzles, a flooder beside an honest sender, and a deterministic mixed run in which no hostile whole is released and no honest sender is quarantined).
- Docs: a puzzle gate section in the `stack-trident` crate docs and a pointer from `manual/sections/trident.md`, including the note that inspection runs under the gate lock.

### Changed

- `stack-trident` (breaking for any producer of envelopes): `subject_digest` is now the CNS digest (`cns.gate.subject_digest`) of the payload, not the SHA-256 of its canonical JSON. This makes the CNS rendering the one binding-digest format across Enforcer, GSA, CCC, CCCb, DIT, the Sentinel witness and the Trident. The envelope version stays 1 because the Trident has no deployed producers. A new `cns_digest` module holds the port, and tests/cns_digest.rs checks it against the shared CNS digest vectors. The MAC, the strict parser and the canonical JSON are unchanged. Floats and integers beyond 2^53 - 1 are still refused. Closes the open question on a shared digest format.
- `stack-anc-adaptive`: `Trip::OperationPanicked` now resolves to `Resolution::Reject`, and the `Resolution::Quarantine` variant is removed from that crate. The pad has no sender identity and isolates nothing, so the old label described an action it did not take.
- `cpp` (`stack_host_binding.hpp`): the seccomp allowlist now carries an aarch64 syscall table beside the x86_64 one, and a `static_assert` holds each entry to the libc `__NR_*` value. On aarch64 the old x86_64 numbers allowed io_setup, io_destroy, quotactl, munlockall, flistxattr, mlock and accept while read, write, exit, exit_group, rt_sigaction, clock_gettime and futex got ENOSYS.
- `cpp` (`stack_host_binding.hpp`): `GovernedMinotaurHost::SetActiveCapabilities` now checks the in-flight counter under `capability_lock_`, and `ExecuteGovernedTransaction` raises that counter inside the same locked block as its capability snapshot. A capability change can no longer be applied between an unlocked counter read and the write while a transaction is starting.
- `stack-trident`: `TridentConfig::validate` now emits a `tracing::warn!` when `audience` is empty (any holder of the shared key can replay the envelope to any receiver) and another when `enforce_startup_epoch` is on with `restored_high_water_ms` at 0 (the restart replay guard then trusts the wall clock). Defaults and the result of `validate` are unchanged, so the default config warns twice.
- CI: a `workspace` job runs `cargo test --workspace --locked` for every crate outside the four ANC crates, which keep their own jobs. No clippy gate yet (findings remain) and no C++ job (Catch2 is not on the runner).
- `cpp` (`stack_host_binding.hpp`): the seccomp allowlist now includes `timer_settime` (x86_64 223, aarch64 110, each held to `__NR_timer_settime` by a `static_assert`). Before this, a sealed thread got ENOSYS when `HardenedPosixPreemptionGuard::Arm()` armed its deadline timer, so `ExecuteGovernedTransaction` could not succeed on any thread that had installed the filter.
- `cpp` (`stack_host_binding.hpp`, `ffi_wrapper.cpp`): every thread that calls `InitializeAndSeal` or `ExecuteGovernedTransaction` now installs its own seccomp filter, once, after creating its deadline timer. Before this the sealed state was one flag per host (and one process-global flag in the FFI), so only the first thread was filtered and every later thread ran unfiltered. The filter is not applied process wide with `SECCOMP_FILTER_FLAG_TSYNC`: that reaches threads that never called in and still leaves them unable to run a transaction, because `timer_create` is not allowlisted. A failed install leaves the thread unsealed and returns an error, as before.
