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

Both original assertions stay (`validation_count > 0` and `update_count > 0`). The fix removes the dependence on scheduling and adds stronger checks:

* Each executor runs one transaction under the initial mask before the setter is released, so "executors made progress" no longer depends on scheduling.
* The setter retries each change until it is applied (the same fix the Catch2 version already had), so all 25 flips land (`update_count == 25`) and the last one, `0xFF`, is the end state.
* After the threads join, a transaction on a fresh domain must pass. That proves the final write landed.
* A new test, `test_defect2_inflight_rule_is_deterministic`, checks the rule itself with no threads and no timing: a change made during a transaction is refused, and the same change after it is accepted.

Both the final transaction and the new test run on their own threads: the seccomp filter stays on the thread that installs it, and a filtered main thread cannot start the threads the later tests need.

## After the fix

| Condition | Runs | Defect 2 failures | Whole binary not 7/7 |
|---|---|---|---|
| Quiet host | 300 | 0 | 0 |
| Four busy loops competing for the four CPUs | 200 | 0 | 0 |

(Before: 30 of 100.)

## Does the test still catch the bug it is named for?

Mutation check: with the in-flight guard removed from `SetActiveCapabilities()` in a copy of the header, the new deterministic test fails (`set during: 1`). The original concurrent test passed on that same broken code in 5 of 5 launches, so it could not have caught that bug. The new deterministic test is what gives this area real coverage.

## What this does not show

* No ThreadSanitizer result (see above), so the claim that the code has no data race rests on reading it and on the deterministic check, not on a tool.
* Writer starvation is real by design: under sustained load `SetActiveCapabilities()` can keep returning `false`. Callers that must apply a change have to retry, as the fixed test now does. Nothing in the code changed.
* The same "no retry" pattern may exist in other test files. Only this test was checked.
