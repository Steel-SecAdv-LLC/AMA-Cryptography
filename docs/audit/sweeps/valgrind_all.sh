#!/usr/bin/env bash
# Copyright (C) 2025-2026 Steel Security Advisors LLC
# SPDX-License-Identifier: Apache-2.0
#
# PR #394 readiness falsification, Phase D: Valgrind memcheck over the FULL
# registered C test set, not the six-binary subset static-analysis.yml runs
# ("running the full ctest suite under Valgrind would exceed the runner
# timeout").  Every CTest command in the given build directory is run under
# the lane's exact valgrind flags with a per-test wall-clock cap; the outcome
# of each is one TSV row and one retained log.  A timeout is recorded as
# exit 124 and reported as unverified, never as clean.
#
# Usage: docs/audit/sweeps/valgrind_all.sh <build-dir> <out.tsv> <log-dir> [cap-seconds]
set -u
build="$1"; out="$2"; logdir="$3"; cap="${4:-2400}"
mkdir -p "$logdir"
printf 'test\tcommand\tenvironment\texit\tduration_s\terrors\tdefinitely_lost\tlog\n' > "$out"
# `ctest -N -V` prints every registered test's exact command line; run the
# same command, under valgrind, from the build directory ctest would use.
# ctest -N -V prints, per test: "N: Test command: <cmd>", optionally
# "N: Environment variables:" followed by "N:  KEY=VALUE" lines, then
# "  Test #N: <name>".  The dispatch-only and backend-equivalence tests are
# driven entirely by that environment (AMA_DISPATCH_ONLY=<kernel>); without
# it they exit 77 (skip), which is a row that proves nothing.  The row is
# emitted at the name line with the command and environment seen before it.
ctest --test-dir "$build" -N -V \
  | awk '
      /Test command:/      {sub(/^.*Test command: */, ""); cmd=$0; env=""; inenv=0; next}
      /Environment variables:/ {inenv=1; next}
      inenv && /^[0-9]+: +[A-Za-z_][A-Za-z0-9_]*=/ {sub(/^[0-9]+: +/, ""); env=env " " $0; next}
      /^ *Test +#[0-9]+: / {inenv=0; print $3 "\t" cmd "\t" env}' \
  | while IFS=$'\t' read -r name cmd envs; do
      log="$logdir/$name.log"
      start=$(date +%s)
      ( cd "$build" && env $envs timeout "$cap" valgrind --error-exitcode=1 --leak-check=full \
          --show-leak-kinds=definite,indirect --errors-for-leak-kinds=definite \
          --track-origins=yes $(echo "$cmd" | tr -d '"') ) > "$log" 2>&1
      rc=$?
      dur=$(( $(date +%s) - start ))
      errs=$(grep -oE 'ERROR SUMMARY: [0-9]+ errors' "$log" | tail -1 | grep -oE '[0-9]+' || echo 'n/a')
      lost=$(grep -oE 'definitely lost: [0-9,]+ bytes' "$log" | tail -1 | grep -oE '[0-9,]+ bytes' || echo 'n/a')
      printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' "$name" "$cmd" "${envs# }" "$rc" "$dur" "${errs:-n/a}" "${lost:-n/a}" "docs/audit/logs/phaseD/valgrind/$name.log" >> "$out"
    done
echo "DONE $(date -u +%FT%TZ)" >> "$out.done"
