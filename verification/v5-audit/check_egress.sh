#!/usr/bin/env bash
# Copyright (C) 2025-2026 Steel Security Advisors LLC
# SPDX-License-Identifier: Apache-2.0
#
# Phase-0 gap 2: per-host egress verification with a MECHANICAL, PRE-STATED
# criterion.  The prior session's verdict ("non-200s are expected responses
# proving reachability") was a judgment word applied after seeing the result;
# the directive forbids that.  Here both criteria are fixed before the run:
#
#   C1 (reachability): curl exit code == 0.  curl only exits 0 after DNS
#      resolution, TCP connect, TLS handshake AND a complete HTTP response.
#      C1 is the criterion that decides verified/unverified.
#
#   C2 (protocol status): for hosts whose expected unauthenticated status is
#      fixed by their published protocol, that exact status is asserted.
#      A host with no protocol-defined expectation is declared
#      REACHABILITY-ONLY *here*, before the run, and its status is recorded as
#      data rather than graded.
#
# Exit 0 iff every host satisfies C1 and every host carrying a C2 expectation
# matches it exactly.  Any other outcome exits 1 and the host is UNVERIFIED.

set -u
fail=0

# host|url|expected_status|basis   ("-" = reachability-only, status recorded not graded)
HOSTS=(
"rekor.sigstore.dev|https://rekor.sigstore.dev/api/v1/log|200|public Rekor read API returns 200 unauthenticated"
"tuf-repo-cdn.sigstore.dev|https://tuf-repo-cdn.sigstore.dev/1.root.json|200|sigstore TUF repo serves VERSIONED root metadata (N.root.json); the unversioned /root.json does not exist there -- the v2 run asserted that wrong path and correctly FAILED"
"pypi.org|https://pypi.org/simple/|200|PEP 503 simple index is public"
"registry-1.docker.io|https://registry-1.docker.io/v2/|401|Docker Registry HTTP API V2: unauthenticated ping MUST return 401 + WWW-Authenticate"
"storage.googleapis.com|https://storage.googleapis.com/|-|no protocol-defined unauthenticated status for the service root"
"freetsa.org|https://freetsa.org/|-|TSA landing page carries no protocol-fixed status"
)

printf '%-28s %-6s %-8s %-10s %s\n' HOST CURL STATUS VERDICT BASIS
for row in "${HOSTS[@]}"; do
  IFS='|' read -r host url want basis <<<"$row"
  code=$(curl -sS -o /dev/null -w '%{http_code}' --max-time 30 "$url" 2>/dev/null)
  ce=$?
  if [ $ce -ne 0 ]; then
    verdict=UNVERIFIED; fail=1
  elif [ "$want" = "-" ]; then
    verdict=REACHABLE            # C1 satisfied; C2 not applicable by prior declaration
  elif [ "$code" = "$want" ]; then
    verdict=VERIFIED             # C1 + C2
  else
    verdict=UNVERIFIED; fail=1   # C2 mismatch is a failure, not a judgment call
  fi
  printf '%-28s %-6s %-8s %-10s %s\n' "$host" "$ce" "$code" "$verdict" "$basis"
done

echo
if [ $fail -eq 0 ]; then echo "EGRESS: all hosts satisfied their pre-stated criteria"; else echo "EGRESS: at least one host UNVERIFIED"; fi
exit $fail
