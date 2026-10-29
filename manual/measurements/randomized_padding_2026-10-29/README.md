# Randomized padding experiment (2026-10-29)

Measurement only. Nothing in a shipped ANC crate changed. The question, the
method, the controls and the results are in
[`../randomized_padding_2026-10-29.md`](../randomized_padding_2026-10-29.md).

## Files

| File | What it is |
|---|---|
| `crates/stack-anc-ceiling/examples/padding_jitter.rs` | The experiment. One launch = one (mode, block): seven cells, each cell a padding policy |
| `run_experiment.sh` | Runs the launches, each a separate process, pinned to the last CPU |
| `analyze.py` | Combines the blocks and writes `summary.json` and `tables.md` |
| `runs/block<B>_<mode>.json` | One file per launch: per-cell, per-class, per-pair statistics |
| `supplementary_256_levels/` | Experiment B: the same harness with 256 jitter levels and a smooth draw (Spin and Hybrid, 3 blocks each), same layout as above |
| `summary.json`, `tables.md` | Output of `analyze.py`: every combined number, and the tables the write-up quotes |
| `runs/launch.log` | Start and end time, pinning and load of every launch |

## Rerun

```text
cargo build --release -p stack-anc-ceiling --example padding_jitter --locked
./manual/measurements/randomized_padding_2026-10-29/run_experiment.sh /tmp/runs 0 4
python3 manual/measurements/randomized_padding_2026-10-29/analyze.py /tmp/runs /tmp/summary.json /tmp/tables.md
```

Experiment B:

```text
STACK_JITTER_CELLS=supp STACK_JITTER_LEVELS=256 ./manual/measurements/randomized_padding_2026-10-29/run_experiment.sh /tmp/supp 5 7 spin hybrid
python3 manual/measurements/randomized_padding_2026-10-29/analyze.py /tmp/supp /tmp/supp.json /tmp/supp.md manual/measurements/randomized_padding_2026-10-29/summary.json
```

The last argument reuses the main run's estimate of how long the injected
delays really are, because a small run estimates them too noisily.

A full run (3 modes x 5 blocks) takes about an hour (the recorded run took 58 minutes). Use `N_TOTAL=12000`
for a quick smoke run. Seeds are recorded in every file; with the same seeds
the class schedule and the jitter draws repeat exactly, the timings do not.

## What is stored and what is not

Each launch computes its statistics (Welch t, the crate's cropped t values,
the second-order t, KS, a permutation p-value, bootstrap confidence
intervals, percentiles of every class) from the per-sample timings in
memory, then writes only those. The per-sample timings themselves (7,559,974
kept values) are not committed: as raw 64-bit floats they would be about 60 MB
plus the class and draw of each.

## Host limits

A shared 4-vCPU container. Other jobs ran on the same machine, so the load
average of each cell is recorded and the noise is larger than on a quiet
machine. Results here are measurements on this host, not proof for another.
