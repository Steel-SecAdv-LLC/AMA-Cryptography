#!/usr/bin/env bash
# Copyright (C) 2025-2026 Steel Security Advisors LLC
# SPDX-License-Identifier: Apache-2.0
#
# docs/audit/run_logged.sh — ledger-recording command runner for the PR #394
# readiness-falsification mandate.
#
# Usage:
#   run_logged.sh <id> <purpose> <log-relpath-without-.log> -- <command> [args...]
#
# Runs the command with stdout+stderr captured to docs/audit/logs/<log>.log,
# records wall-clock duration, the host description, the exit code and the
# SHA-256 of the retained log, and appends ONE tab-separated row to
# docs/audit/ledger.tsv.  The runner exits with the command's own exit code so
# failure propagates.  Nothing here interprets the result: a row is evidence
# only together with its retained log, and a command that was not run through
# this runner does not appear in the ledger.
#
# Environment:
#   AUDIT_HOST   optional override for the host column (used for qemu-user and
#                sanitizer runs where the *effective* machine is not lscpu's).
#   AUDIT_CWD    optional working directory for the command (default: repo root).
set -u -o pipefail

here="$(cd "$(dirname "$0")" && pwd)"
repo="$(cd "$here/../.." && pwd)"
ledger="$here/ledger.tsv"
logroot="$here/logs"

id="$1"; purpose="$2"; logname="$3"
shift 3
[ "${1:-}" = "--" ] && shift

log="$logroot/${logname}.log"
mkdir -p "$(dirname "$log")"

if [ -z "${AUDIT_HOST:-}" ]; then
  model="$(lscpu 2>/dev/null | sed -n 's/^Model name:[[:space:]]*//p' | head -1)"
  AUDIT_HOST="$(uname -m) $(uname -s) $(uname -r) ${model:-unknown-cpu} $(nproc)cpu"
fi

start_ns=$(date +%s%N)
( cd "${AUDIT_CWD:-$repo}" && "$@" ) >"$log" 2>&1
rc=$?
end_ns=$(date +%s%N)
duration_s=$(( (end_ns - start_ns) / 1000000000 )).$(printf '%03d' $(( ((end_ns - start_ns) / 1000000) % 1000 )))

# Retained logs are LF-only bytes: progress bars emit CR, and the repository's
# line-ending gate measures committed bytes.
sed -i 's/\r$//; s/\r/\n/g' "$log"
sha="$(sha256sum "$log" | cut -d' ' -f1)"
cmd_str="$(printf '%q ' "$@")"
last="$(tail -n 1 "$log" | tr '\t' ' ' | cut -c1-160)"

if [ ! -f "$ledger" ]; then
  printf 'id\tcommand\tpurpose\texit_code\tlog\tlog_sha256\tduration_s\thost\tutc\tlast_line\n' >"$ledger"
fi
printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
  "$id" "$cmd_str" "$purpose" "$rc" "docs/audit/logs/${logname}.log" "$sha" \
  "$duration_s" "$AUDIT_HOST" "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$last" >>"$ledger"

exit "$rc"
