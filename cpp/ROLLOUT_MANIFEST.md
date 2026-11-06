# C++ containment layer: integration notes

This file used to describe a staged rollout to seventeen named repositories
and declared "all 20 components production-locked". This repository records
no such rollout, and the layer is not production-locked. What follows is what a consumer of these
headers has to do, and what state the layer is in.

## Integrating the headers

- Link the `stack_containment` CMake INTERFACE target from
  `cpp/CMakeLists.txt`, or add `cpp/include` to the include path. Build
  with C++23, `-fno-exceptions -fno-rtti`, and on x86_64 `-mavx2`.
- To run an untrusted payload that must be stopped: call
  `stack::supervised::SupervisedExecutor::Run` with explicit `Limits`
  (wall-clock deadline required: non-zero, at most one hour) and classify on `ExecutionReport::outcome`.
  Treat anything but `Completed` as failure. Read `CONTAINMENT.md` first.
- To run a trusted payload under the governor on the calling thread: call
  `GovernedMinotaurHost::ExecuteGovernedTransaction`. The calling thread is
  sealed with a seccomp allowlist on first use and stays sealed. The hard
  timeout is a cooperative CPU-time deadline, not a stop.
- `SeccompAuditRing` is telemetry. Its signing is an XOR placeholder; do not
  use it as a receipt.
- `SIMDCapabilityToken` is a caller-supplied request mask checked against a
  host-global active mask; it is not a credential and there is no issuer.

## State of the layer

| Area | State |
|---|---|
| Build and tests | 26 ctest entries in this build. CI job `cpp` runs 25 of them; the 26th is root-only. All are compiled with `-Werror`. |
| Supervised execution | Implemented and tested on x86_64 (`supervised_exec_tests.cpp`, the worker tests and the FFI tests). aarch64 not built. |
| In-process path | Cooperative deadline; D-01 and D-03 fixed; D-02 not fixable on this path. |
| Capability model | C++ layer: mask check only; no authorization, issuer, expiry or revocation. The Rust `stack-authority` crate adds signed-capability checks for the authorized FFI entry points; no capability issuer is built (see `docs/issuer-requirements.md`). |
| Audit as receipt | Not usable: the signing is an XOR placeholder, so the ring is telemetry only. |
| FFI | Distinct failure codes; `supervised_run` exposed. Transactions are token-bucket limited to 1000 tokens per second per domain, by design. The earlier reserved-floor bug that rate-limited every Standard transaction is fixed (R2-K-01). |
| Known test issues | None recorded as open. The two scheduling-dependent cases were made deterministic in RACE-02 step 5b; see `CONTAINMENT.md`. |

The checklist that was here ("All 20 components validated", "ABI stability
matrix verified", "Chaos stress test passes") had no artefacts behind it
and is withdrawn.
