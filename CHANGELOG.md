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
