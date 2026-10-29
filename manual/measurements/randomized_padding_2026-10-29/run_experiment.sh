#!/usr/bin/env bash
# Runs the randomized padding experiment: one separate process launch per
# (block, mode), pinned to one CPU. Usage:
#   ./run_experiment.sh <out_dir> <first_block> <last_block> [modes...]
# Example (the recorded run used blocks 0..4 in three batches):
#   ./run_experiment.sh runs 0 1
# Needs the release example built first:
#   cargo build --release -p stack-anc-ceiling --example padding_jitter --locked
set -euo pipefail
out_dir=${1:?out_dir}
first=${2:?first_block}
last=${3:?last_block}
shift 3 || true
modes=("$@")
if [ ${#modes[@]} -eq 0 ]; then modes=(sleep spin hybrid); fi
bin=${BIN:-target/release/examples/padding_jitter}
cpu=${CPU:-$(( $(nproc) - 1 ))}
mkdir -p "$out_dir"

pin=()
if command -v taskset >/dev/null 2>&1; then pin=(taskset -c "$cpu"); fi
prio=()
if nice -n -5 true >/dev/null 2>&1; then prio=(nice -n -5); fi

for block in $(seq "$first" "$last"); do
  # Rotate the mode order per block so time drift is not tied to a mode.
  n=${#modes[@]}
  for i in $(seq 0 $(( n - 1 ))); do
    mode=${modes[$(( (i + block) % n ))]}
    out="$out_dir/block${block}_${mode}.json"
    echo "$(date -u +%FT%TZ) start block=$block mode=$mode pin=${pin[*]:-none} prio=${prio[*]:-none} load=$(cut -d' ' -f1-3 /proc/loadavg)" | tee -a "$out_dir/launch.log"
    STACK_JITTER_MODE=$mode STACK_JITTER_BLOCK=$block STACK_JITTER_N_TOTAL=${N_TOTAL:-72000} \
      STACK_JITTER_OUT=$out "${prio[@]}" "${pin[@]}" "$bin" 2>>"$out_dir/launch.log"
    echo "$(date -u +%FT%TZ) done block=$block mode=$mode load=$(cut -d' ' -f1-3 /proc/loadavg)" | tee -a "$out_dir/launch.log"
  done
done
