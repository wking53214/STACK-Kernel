## Summary

TACK checks fail closed (682 of 692 tests pass); ANC bounds timing leaks but cannot zero them, and a t-test cannot prove one absent.

*Exists today in sentinel_os: the Sentinel Hash-Chain only. New design: everything else, reference implementations compiled and tested on Rust 1.94.*

Fail closed means a check refuses what it cannot judge instead of passing it. Red-team tests, attacks written by separate agents, probed this in ten of the eleven crates. ANC (Active Timing Cancellation) defends against attackers who time replies to learn secrets; a t-test asks whether two groups of times differ on average.

| Component | Exists today or new | Tests passing | Red-team result | Key limit |
|---|---|---|---|---|
| 1. Inlet Winnowing Filter | New | 71 of 71 | 13 of 24 broke the first build, 1 a blocker; all 24 pass after fixes | Refuses ordinary emoji that use U+FE0F or zero-width joiners; some honest Latin-1 text is still quarantined |
| 2. Inter-Agent Trident | New | 93 of 93 | 13 of 22 broke the first build; all 22 pass | Shared HMAC keys let any receiver forge as a sender; audience binding is off by default |
| 3. Elastic Bumpers | New | 122 of 122 | 7 of 21 broke the first build; all 21 pass | Look-alike letters from other scripts still pass identifier checks |
| 4. Minotaur String | New | 60 of 60 | 6 of 13 failed on the first build, 2 of them blockers; all 13 pass | Some long-gap repeats escape loop detection until a step budget stops them; trips expose state fingerprints |
| 5. Traffic Cop and Green Wave Routing | New | 47 of 47 in this re-run; driver tests failed 3 of 10 earlier runs | 15 of 25 failed on the first build, 1 a blocker; all 25 pass in most runs | Under full CPU load the driver misses phases, which voids the fairness bound for that window |
| 6. Tractor Transmission | New | 45 of 45 | 8 of 14 failed on the first build; all 14 pass | A leaked guard blocks every shift until the process restarts |
| 7. Sentinel Hash-Chain | Exists today in sentinel_os; the Rust verifier is new | 77 of 77 | 15 of 24 broke or partly broke the first build; all 24 pass | A service-key holder can rebuild the chain; columns such as `timestamp` are not hashed |
| ANC Strategy 1: fixed ceiling | New | 44 of 45 | 10 of 17 broke or partly broke the first build; 16 of 17 pass | Every reply waits the whole ceiling, and work past it leaks |
| ANC Strategy 2: epoch-quantized target | New | 61 of 64 | 11 of 17 broke the first build; 14 of 17 pass | At the production budget it froze within a second and held replies at its cap |
| ANC Strategy 3: `constant_time` compare | New | 39 of 45 | 6 of 17 failed, all minor and not yet fixed; 11 of 17 pass | The no-branch property belongs to one binary; a compiler or target change can undo it |
| ANC measurement harness | New, test tooling | 23 of 23 | No red team; 0 of 50 A/A calibration runs flagged | A pass means no leak detected at that sample size, never proof of none |

All 11 crates compile on Rust 1.94 and pass clippy with warnings denied. Of 194 red-team tests, 104 failed against the first builds and 10 still fail, all in the three ANC strategy crates. The ANC strategies were measured in release builds, about 100,000 requests per class, on one shared 4-vCPU KVM virtual machine (Intel Xeon, 2.10 GHz).
