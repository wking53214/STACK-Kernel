# The C++ "Capability Mutation Race" test: why it failed, measured

*Test: `test_defect2_concurrent_mutation` in `cpp/tests/layer4_redteam.cpp` ("DEFECT 2: Capability Mutation Race"). Host: a shared 4-vCPU virtual machine, g++ 13.3, `-std=c++23 -O2 -mavx2`, one process launch per run.*

## Before the fix

100 launches of the standalone `layer4_redteam` binary on current main: the Defect 2 test failed in **30 of 100** launches. No other test in the binary failed in any launch.

| Failure message | Launches |
|---|---|
| `Validation: 100, Updates: 0` | 28 |
| `Validation: 0, Updates: 24` | 1 |
| `Validation: 0, Updates: 20` | 1 |

## What the capability code does (read, then checked)

`SetActiveCapabilities()` returns `false` whenever a transaction is in flight. That is the documented rule, not a race. `ExecuteGovernedTransaction()` raises the in-flight counter under the same lock as its snapshot, so a transaction cannot start between the setter's check and its write.

A deterministic check with no threads and no timing (one transaction whose payload tries to change the mask) printed `tx ok=1, set during tx=0, set after tx=1`: a change during a transaction is refused, and the same change after it succeeds.

ThreadSanitizer cannot be used here: the seccomp filter the host installs blocks the system calls the sanitizer needs (it dies with error 38 before the first test finishes). So there is no TSan evidence either way, and the argument rests on the code reading and the deterministic check above.

## Cause: the test, not the code

The test asserts that both sides made progress (`validation_count > 0 && update_count > 0`), but it does not control the scheduling that decides that:

1. **Setter starvation (28 of 30 failures).** The setter makes 25 attempts and does not retry a refused one. Two executor threads keep a transaction in flight almost continuously, so every attempt can be refused: `Updates: 0`.
2. **Wrong final mask (2 of 30 failures).** The setter alternates `0xFF` and `0xAA` and ends on `0xFF`. If that last attempt is refused, the mask stays `0xAA`, and every executor transaction (which needs bit `0x01`) fails validation: `Validation: 0`.

The Catch2 version of this test in `tests_all_components.cpp` already retries until each change is applied, for exactly this reason. The `layer4` version never got that fix.

## What the fix has to keep

Both original assertions stay. The fix removes the dependence on scheduling and adds a stronger end-state check. Results after the fix are in the next section once recorded.
