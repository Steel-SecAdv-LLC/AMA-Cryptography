#!/usr/bin/env bash
# Copyright (C) 2025-2026 Steel Security Advisors LLC
# SPDX-License-Identifier: Apache-2.0
# Item 6: full C suite under Valgrind memcheck (CI runs only a 6-test subset).
# Every test binary runs under
#   valgrind --error-exitcode=1 --leak-check=full
#            --errors-for-leak-kinds=definite,indirect --track-origins=yes
# Exit 77 from the underlying test (its own skip convention, e.g. NEON tests
# on x86) is honoured as SKIP.  Any valgrind-detected error or test failure is
# a FAIL.  One ledger row per run is appended at the end with the aggregate.
set -u -o pipefail
here="$(cd "$(dirname "$0")" && pwd)"
repo="$(cd "$here/../.." && pwd)"
cmds="${1:?usage: valgrind_suite.sh <ctest-commands.tsv>}"
logdir="$here/logs/item6-valgrind"
mkdir -p "$logdir"

pass=0; fail=0; skip=0; failed_names=()
start=$(date -u +%Y-%m-%dT%H:%M:%SZ)
t0=$(date +%s)
while IFS=$'\t' read -r name cmd args; do
  log="$logdir/$name.log"
  valgrind --error-exitcode=1 --leak-check=full \
           --errors-for-leak-kinds=definite,indirect --track-origins=yes \
           "$cmd" ${args:-} >"$log" 2>&1
  rc=$?
  if [ "$rc" -eq 0 ]; then
    pass=$((pass+1)); echo "[vg] PASS $name"
  elif [ "$rc" -eq 77 ]; then
    skip=$((skip+1)); echo "[vg] SKIP $name (test's own skip code)"
  else
    fail=$((fail+1)); failed_names+=("$name(rc=$rc)"); echo "[vg] FAIL $name rc=$rc"
  fi
done <"$cmds"
t1=$(date +%s)

echo "VALGRIND SUITE: pass=$pass fail=$fail skip=$skip runtime=$((t1-t0))s"
[ "$fail" -gt 0 ] && printf 'FAILED: %s\n' "${failed_names[@]}"

# Aggregate log for the ledger: concatenated ERROR SUMMARY lines
agg="$here/logs/item6-valgrind-summary.log"
{ echo "run started $start; pass=$pass fail=$fail skip=$skip wall=$((t1-t0))s"
  grep -H "ERROR SUMMARY" "$logdir"/*.log | sed "s|$logdir/||"; } >"$agg"
sha=$(sha256sum "$agg" | cut -d' ' -f1)
rc_total=$([ "$fail" -eq 0 ] && echo 0 || echo 1)
v=$([ "$fail" -eq 0 ] && echo PASS || echo FAIL)
echo "6,\"valgrind --error-exitcode=1 --leak-check=full --errors-for-leak-kinds=definite,indirect --track-origins=yes over all $((pass+fail+skip)) ctest binaries (see logs/item6-valgrind/)\",$rc_total,\"zero definite/indirect leaks and zero memcheck errors across the full C suite; test skip code 77 honoured\",$v,verification/v5-audit/logs/item6-valgrind-summary.log,$sha,$((t1-t0))s,$start" >>"$here/ledger.csv"
exit "$rc_total"
