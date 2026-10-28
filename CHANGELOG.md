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

### Changed

- `stack-anc-adaptive`: `Trip::OperationPanicked` now resolves to `Resolution::Reject`, and the `Resolution::Quarantine` variant is removed from that crate. The pad has no sender identity and isolates nothing, so the old label described an action it did not take.
- `cpp` (`stack_host_binding.hpp`): the seccomp allowlist now carries an aarch64 syscall table beside the x86_64 one, and a `static_assert` holds each entry to the libc `__NR_*` value. On aarch64 the old x86_64 numbers allowed io_setup, io_destroy, quotactl, munlockall, flistxattr, mlock and accept while read, write, exit, exit_group, rt_sigaction, clock_gettime and futex got ENOSYS.
- `cpp` (`stack_host_binding.hpp`): `GovernedMinotaurHost::SetActiveCapabilities` now checks the in-flight counter under `capability_lock_`, and `ExecuteGovernedTransaction` raises that counter inside the same locked block as its capability snapshot. A capability change can no longer be applied between an unlocked counter read and the write while a transaction is starting.
- `stack-trident`: `TridentConfig::validate` now emits a `tracing::warn!` when `audience` is empty (any holder of the shared key can replay the envelope to any receiver) and another when `enforce_startup_epoch` is on with `restored_high_water_ms` at 0 (the restart replay guard then trusts the wall clock). Defaults and the result of `validate` are unchanged, so the default config warns twice.
- CI: a `workspace` job runs `cargo test --workspace --locked` for every crate outside the four ANC crates, which keep their own jobs. No clippy gate yet (findings remain) and no C++ job (Catch2 is not on the runner).
- `stack-trident`: `SenderState::is_idle` in `state.rs` uses `Option::is_none_or` in place of `map_or(true, ..)` (clippy `unnecessary_map_or`). Same result for every input.
- `stack-greenwave`: `Timing::is_epoch_boundary` uses `u64::is_multiple_of` in place of `t % epoch_len == 0` (clippy `manual_is_multiple_of`). `epoch_len` is always at least 1000, so the two forms agree.
- `stack-p3-2`: six clippy findings cleared with no behaviour change. `HardPreemptionKernel` drops its `config` field, which was stored by `new` after `validate()` and never read. `parse_limit` uses `Range::contains` and `GovernedLimits::effective` uses `Option::is_some_and`, each equal to the expression it replaces. `check_preemption_boundary` keeps its public `Result<(), TrapEvent>` return type and carries a targeted `#[allow(clippy::result_large_err)]` with a reason comment, because boxing the error would change a public signature. The `governed_workload` example uses `u64::is_multiple_of` in `is_canary_task`; its only caller passes a divisor above zero.
