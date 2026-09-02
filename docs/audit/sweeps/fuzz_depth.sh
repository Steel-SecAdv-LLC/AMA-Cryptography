#!/usr/bin/env bash
# Copyright (C) 2025-2026 Steel Security Advisors LLC
# SPDX-License-Identifier: Apache-2.0
#
# PR #394 readiness falsification, Phase D: fuzz depth per target.  Runs every
# libFuzzer target in the given build directory with fuzzing.yml's exact
# recipe (seed corpus, dictionary, -max_len from
# tools/check_fuzz_input_reachability.py) for a fixed wall-clock budget, and
# records what the run actually reached: executions, edge coverage (cov),
# features (ft), final corpus size, and the exit code.  A target that crashes
# or times out is a row with a non-zero exit, never a missing row.
#
# Usage: docs/audit/sweeps/fuzz_depth.sh <build-dir> <out.tsv> <log-dir> [seconds]
set -u
build="$1"; out="$2"; logdir="$3"; secs="${4:-60}"
mkdir -p "$logdir"
work="$(mktemp -d)"
printf 'target\tseconds\tmax_len\tseed_inputs\tdictionary\texecs\tcov\tft\tcorpus_final\texit\tlog\n' > "$out"
for bin in "$build"/bin/fuzz_*; do
  t="$(basename "$bin")"
  [ -x "$bin" ] || continue
  corpus="$work/corpus/$t"; mkdir -p "$corpus" "$work/artifacts/$t"
  seeds=0
  if [ -d "fuzz/seed_corpus/$t" ]; then
    cp -r "fuzz/seed_corpus/$t/." "$corpus/"; seeds=$(ls -1 "$corpus" | wc -l)
  fi
  dict="none"; dict_arg=""
  if [ -f "fuzz/dictionaries/$t.dict" ]; then dict="fuzz/dictionaries/$t.dict"; dict_arg="-dict=$dict"; fi
  max_len="$(python3 tools/check_fuzz_input_reachability.py --max-len "$t" 2>/dev/null || echo 4096)"
  log="$logdir/$t.log"
  "$bin" -max_total_time="$secs" -max_len="$max_len" $dict_arg -print_final_stats=1 \
      -artifact_prefix="$work/artifacts/$t/" "$corpus" > "$log" 2>&1
  rc=$?
  execs=$(grep -oE 'stat::number_of_executed_units: *[0-9]+' "$log" | grep -oE '[0-9]+$' || echo n/a)
  last=$(grep -E '^#[0-9]+[[:space:]]+(DONE|NEW|REDUCE|pulse|INITED)' "$log" | tail -1)
  cov=$(echo "$last" | grep -oE 'cov: [0-9]+' | grep -oE '[0-9]+' || echo n/a)
  ft=$(echo "$last" | grep -oE 'ft: [0-9]+' | grep -oE '[0-9]+' || echo n/a)
  corp=$(echo "$last" | grep -oE 'corp: [0-9]+' | grep -oE '[0-9]+' || echo n/a)
  printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' "$t" "$secs" "$max_len" "$seeds" "$dict" "${execs:-n/a}" "${cov:-n/a}" "${ft:-n/a}" "${corp:-n/a}" "$rc" "docs/audit/logs/phaseD/fuzz/$t.log" >> "$out"
done
rm -rf "$work"
echo "DONE $(date -u +%FT%TZ)" >> "$out.done"
