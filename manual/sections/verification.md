## Verification pipeline

A build ships only if all 16 timing verdicts stay at or below |t| 4.5, at 100,000 samples per class, on the first attempt.

*New design: the job below has not run on GitHub Actions. Its gate expressions were run against the recorded verify output, and its test commands were re-run for this section.*

### What the job does

The job has two parts. `unit` runs on every pull request, on a GitHub-hosted machine: `cargo test` and `cargo clippy -D warnings` for each of the 11 crates.

`timing` runs nightly and on release tags, on a self-hosted runner: a machine the team owns, which GitHub sends jobs to. It calibrates the harness, runs the three strategies' release-mode `examples/verify` programs pinned to one core, and gates on their JSON output.

Timing runs apart from `unit` for two reasons. It measures for about 13 minutes: 232 s for Strategy 1, 453 to 511 s for Strategy 2, 9 s for Strategy 3. It also needs a quiet machine, and a shared hosted runner is noisier than even the VM used for this manual.

```yaml
name: tack-kernel-verify

on:
  pull_request:
  push:
    tags: ["v*"]
  schedule:
    - cron: "17 3 * * *"

permissions:
  contents: read

jobs:
  unit:
    runs-on: ubuntu-24.04
    timeout-minutes: 45
    strategy:
      fail-fast: false
      matrix:
        crate: [tack-inlet, tack-trident, tack-bumpers, tack-minotaur,
                tack-greenwave, tack-transmission, tack-sentinel,
                tack-anc-harness, tack-anc-ceiling, tack-anc-adaptive,
                tack-anc-pipeline]
    steps:
      - uses: actions/checkout@v4
      - run: rustup toolchain install 1.94 --profile minimal --component clippy
      - run: cargo +1.94 test -p ${{ matrix.crate }} --all-targets
      - run: cargo +1.94 clippy -p ${{ matrix.crate }} --all-targets -- -D warnings

  timing:
    if: github.event_name != 'pull_request'
    runs-on: [self-hosted, linux, x64, tack-timing]
    concurrency: {group: tack-timing, cancel-in-progress: false}
    timeout-minutes: 60
    env:
      CPU: "3"
      MAX_LOAD: "0.5"
    steps:
      - name: First attempt only (a rerun cannot turn a timing failure green)
        run: test "$GITHUB_RUN_ATTEMPT" = 1
      - uses: actions/checkout@v4
      - name: Runner check (a noisy host gives RETRY, never PASS)
        run: |
          read -r load _ < /proc/loadavg
          awk -v l="$load" -v m="$MAX_LOAD" 'BEGIN { exit !(l < m) }'
          test "$(cat /sys/devices/system/cpu/smt/active)" = 0
          grep -qx performance /sys/devices/system/cpu/cpu$CPU/cpufreq/scaling_governor
      - name: Build release examples, one binary per crate
        run: |
          rustup toolchain install 1.94 --profile minimal
          mkdir -p bin out
          cargo +1.94 build --release -p tack-anc-harness --example calibrate
          cp target/release/examples/calibrate bin/
          for c in ceiling adaptive pipeline; do
            cargo +1.94 build --release -p tack-anc-$c --example verify
            cp target/release/examples/verify bin/verify-$c
          done
      - name: Calibrate the harness on this host
        run: |
          taskset -c "$CPU" bin/calibrate 200000 1000 > out/calibrate.json
          jq -e '.aa.false_positives_max_abs_t <= 10
            and ([.victims[] | .leaky.gate_outcome == "TERMINAL_BREACH"
                  and .ct.gate_outcome == "PASS"] | all)' out/calibrate.json
      - name: Measure the three strategies
        run: |
          for c in ceiling adaptive pipeline; do
            taskset -c "$CPU" bin/verify-$c > out/$c.json
          done
      - name: Gate on max |t| (a failure is TERMINAL_BREACH for this build)
        run: |
          jq -e '.build == "release" and .calibration.passed
            and ([.padded[] | .detect.harness_max_abs_t < 4.5] | all)' out/ceiling.json
          jq -e '.calibration.passed
            and ([.runs[] | select(.name | startswith("epoch_")) | .detect.max_abs_t < 4.5] | all)
            and .poisoning.epoch.detect.max_abs_t < 4.5
            and .budget_default.detect.max_abs_t < 4.5' out/adaptive.json
          jq -e '.profile == "release" and .summary.evidence_valid
            and ([.summary.primary_gate.constant_time,
                  .summary.primary_gate_with_debugging_recorder.constant_time,
                  .summary.secondary_gate.constant_time,
                  .summary.bare.constant_time] | all(.harness_gate_outcome == "PASS"))
            and .summary.constant_time_conditional_branches == 0' out/pipeline.json
      - name: KS hold (p below 0.001 needs a recorded owner decision)
        run: |
          jq -e '[.padded[] | .detect.ks_p >= 0.001] | all' out/ceiling.json
          jq -e '([.runs[] | select(.name | startswith("epoch_")) | .detect.ks_p >= 0.001] | all)
            and .poisoning.epoch.detect.ks_p >= 0.001
            and .budget_default.detect.ks_p >= 0.001' out/adaptive.json
          jq -e '[.summary.primary_gate.constant_time,
                  .summary.primary_gate_with_debugging_recorder.constant_time,
                  .summary.secondary_gate.constant_time,
                  .summary.bare.constant_time] | all(.ks_p >= 0.001)' out/pipeline.json
      - if: always()
        uses: actions/upload-artifact@v4
        with:
          name: timing-${{ github.sha }}
          path: out/
          retention-days: 400
```

The three `verify` programs share one binary name, so each is copied out right after its build. The `jq -e` lines exit non-zero when their expression is false, which fails the step.

The Strategy 2 and 3 gates are the ones their sections tested; the Strategy 1 gate was written for this section. Against the recorded results, the |t| gate exited 0 on all 10 runs: 3, 4 and 3 for Strategies 1, 2 and 3.

The KS hold exited 1 on all 3 full-size pinned Strategy 2 runs, because of epoch Sleep, and 0 everywhere else. So today the nightly job would stop at that step until the owner decides about Sleep mode.

### The runner

The tlsfuzzer timing guide lists the noise sources to control. They are CPU frequency scaling, SMT (two hardware threads sharing one core), CPU pinning and thermal throttling. The runner check enforces three of them before any measurement.

| Requirement | Why | Checked by |
|---|---|---|
| A dedicated host, one timing job at a time | Another job's load lands in both classes unevenly | `concurrency` group and the runner label |
| Measurements pinned to core 3, isolated from the scheduler | Moving between cores changes cache state mid-run | `taskset -c "$CPU"`; isolation is set in the host's boot configuration |
| SMT off | A sibling thread shares the core's execution ports | `smt/active` must read 0 |
| Fixed CPU frequency | A frequency change shifts every sample at once | `performance` governor |
| 1-minute load below 0.5 | Other agents' test binaries ran during some measurements in this manual | `/proc/loadavg` |

### Thresholds

The harness computes eight statistics per configuration and keeps the largest |t|. Welch's t-test asks whether two groups have different mean times without assuming equal spread. Cropping reruns it on the samples below a percentile, removing slow outliers.

| Check | Line | On failure |
|---|---|---|
| Calibration: unpadded early-exit victim | Flagged above 4.5 | RETRY: the run proves nothing; measure again at the next scheduled run |
| Calibration: unpadded constant-time control | At or below 4.5 | RETRY, as above |
| Harness A/A runs, both classes identical | At most 10 of 1,000 above 4.5 | RETRY: the runner is too noisy to judge; fix it |
| First-order Welch t, uncropped | \|t\| at most 4.5 | TERMINAL_BREACH: the build is rejected |
| Cropped first-order t, at 50, 75, 90, 95, 99 and 99.9 percent | \|t\| at most 4.5 | TERMINAL_BREACH |
| Second-order Welch t, which compares spread | \|t\| at most 4.5 | TERMINAL_BREACH |
| Two-sample Kolmogorov-Smirnov (KS), which compares whole distributions | p at least 0.001, so D below 0.0087 at 100,000 per class | Hold: never an automatic pass; the owner records a decision |
| Disassembly of `constant_time` | Zero conditional branches | TERMINAL_BREACH |

KS is a hold, not a breach, because at this n it also reacts to host noise. The constant-time control crossed it once in Strategy 2's run 2 (p 7e-6), while epoch Sleep crossed it in every full-size run.

The `cargo test` smoke tests use smaller samples, debug builds and, for Strategy 1, a looser crop line of 10. They guard against regressions and are not evidence.

### Sample sizes

| Run | Samples | Smallest mean shift the uncropped test could flag |
|---|---|---|
| Harness calibration | 200,000 per run across both classes; 1,000 A/A runs (50 recorded so far) | Not applicable |
| Strategy 1 verify | 100,000 per class target, drawn at random (100,084 A and 99,916 B) | 1.9 to 4.7 us, padded |
| Strategy 2 verify | 100,000 per class; 10,000 probes per class for poisoning; about 20,000 per class at the production budget | 13.4 to 20.4 us, epoch target |
| Strategy 3 verify | Exactly 100,000 per class | 8.3 to 17.0 ns, through the gate |
| `cargo test` smoke tests | 20,000 per class (Strategies 1 and 3), 2,000 per class (Strategy 2) | Not evidence |

No reported result may use fewer than 10,000 per class. Sensitivity grows with the square root of n, so four times the samples halves the smallest shift the test can see.

### Expected false alarms

Under normal noise, one statistic crosses 4.5 by chance about 7 times in a million. The largest of eight crosses it at most 8 times as often, and the job gates 16 verdicts. So in theory at most about 1 night in 1,150 goes red by chance.

That figure is theory, not measurement. The harness flagged 0 of 50 A/A runs. That only bounds the real rate per verdict below about 6 percent (the rule of three: 3 divided by the number of runs).

At 6 percent per verdict, 63 percent of nights would go red by chance. So the job runs 1,000 A/A runs each night. If none is flagged, the bound falls to 0.3 percent per verdict, about 5 percent of nights.

### No retry to green

A timing failure is TERMINAL_BREACH for that build, with the resolution reject: it does not ship. That commit is not measured again for release until the owner records a root cause.

The reason is arithmetic. A leak exactly at the detection limit is flagged in about half of runs. Rerunning until green would pass it 87.5 percent of the time within three tries.

The job's first step refuses any rerun attempt. A later green run on the same commit does not clear an earlier red one; only the owner's written root cause does.

Runner and calibration failures are RETRY, because the instrument failed, not the build. They are checked before any strategy result is read, so they cannot be used to discard one.

### Where the job stands today

The `unit` job fails today on three crates. The red teams' open findings stay as failing tests, never skipped, so a fix or an owner decision is what turns them green. The final summary lines of `cargo test -p <crate> --all-targets`, re-run for this section:

```text
$ cargo test -p tack-anc-ceiling --all-targets
test result: FAILED. 16 passed; 1 failed; 0 ignored; 0 measured; 0 filtered out; finished in 2.64s
error: test failed, to rerun pass `-p tack-anc-ceiling --test redteam`
$ cargo test -p tack-anc-adaptive --all-targets
test result: FAILED. 14 passed; 3 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.20s
error: test failed, to rerun pass `-p tack-anc-adaptive --test redteam`
$ cargo test -p tack-anc-pipeline --all-targets
test result: FAILED. 11 passed; 6 failed; 0 ignored; 0 measured; 0 filtered out; finished in 17.11s
error: test failed, to rerun pass `-p tack-anc-pipeline --test redteam`
```

The other eight crates passed every test in this re-run, and clippy with warnings denied exited 0 for all eleven. Two timing-sensitive suites are flaky on a loaded host. They are Strategy 1's rt04 and Green Wave's driver tests, which failed 3 of 10 earlier full runs.

### What a pass does and does not establish

A pass establishes:

- No difference above |t| 4.5 between the classes on any of the eight statistics at 100,000 per class, on that runner, binary and load.
- That the same run flagged the known leak and passed the constant-time control, so it could see a leak of that kind.
- The smallest mean shift it could have flagged, printed per configuration as `delta_min_ns`.
- For `constant_time`, zero conditional branches in that release binary.

A pass does not establish:

- That any code is constant time. A t-test detects leaks; it cannot prove their absence.
- Anything about a shift smaller than `delta_min_ns`, or about class pairs and inputs not tested.
- Anything about other CPUs, compilers, or targets such as aarch64.
- Anything about the network, TLS, the allocator or a production metrics exporter.
- Protection from attackers on the same core or cache, or from anyone who can read the metrics endpoint.
- Fair service under flood: the flood tests bound CPU, not who gets served.
