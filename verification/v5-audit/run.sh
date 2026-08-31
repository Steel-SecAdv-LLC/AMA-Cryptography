#!/usr/bin/env bash
# verification/v5-audit/run.sh — ledger-recording command runner for the v5.0 audit.
#
# Usage: run.sh <item-id> <threshold-description> <log-basename> -- <command> [args...]
#
# Executes the command with stdout+stderr captured to logs/<log-basename>.log,
# records the wall-clock runtime measured around the child process, appends one
# append-only CSV row to ledger.csv, and exits with the command's own exit code
# so failure propagates to the caller.  The verdict column is mechanical:
# PASS iff exit code == 0, FAIL otherwise.  Items whose pass criterion is not
# "exit 0" must wrap the criterion in a script that exits nonzero on violation
# before invoking this runner, so the verdict stays mechanical.
set -u -o pipefail

here="$(cd "$(dirname "$0")" && pwd)"
ledger="$here/ledger.csv"
logdir="$here/logs"
mkdir -p "$logdir"

item="$1"; threshold="$2"; logname="$3"
shift 3
[ "$1" = "--" ] && shift

log="$logdir/${logname}.log"

start_ns=$(date +%s%N)
"$@" >"$log" 2>&1
rc=$?
end_ns=$(date +%s%N)
runtime_s=$(( (end_ns - start_ns) / 1000000000 )).$(printf '%03d' $(( ((end_ns - start_ns) / 1000000) % 1000 )))

sha=$(sha256sum "$log" | cut -d' ' -f1)
verdict=FAIL
[ "$rc" -eq 0 ] && verdict=PASS

# CSV-quote the command (double any embedded quotes).
cmd_str="$(printf '%q ' "$@")"
cmd_csv="\"${cmd_str//\"/\"\"}\""
thr_csv="\"${threshold//\"/\"\"}\""

if [ ! -f "$ledger" ]; then
  echo "item,command,exit_code,threshold,verdict,log_path,log_sha256,runtime_s,utc_timestamp" >"$ledger"
fi
echo "${item},${cmd_csv},${rc},${thr_csv},${verdict},verification/v5-audit/logs/${logname}.log,${sha},${runtime_s},$(date -u +%Y-%m-%dT%H:%M:%SZ)" >>"$ledger"

exit "$rc"
