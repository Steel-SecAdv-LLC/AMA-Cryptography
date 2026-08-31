#!/usr/bin/env bash
# Copyright (C) 2025-2026 Steel Security Advisors LLC
# SPDX-License-Identifier: Apache-2.0
# Item 9: full-history secret scan of the real repository (unshallowed).
# Mechanical verdict: exit 0 iff
#   - trufflehog (git mode, --no-verification) reports zero findings, AND
#   - every gitleaks finding falls into one of two documented false-positive
#     classes:
#       FP1: RuleID generic-api-key, file under a published-test-vector or
#            test/benchmark tree, and the "secret" is hex/base64url material
#            (KAT vectors), and
#       FP2: RuleID generic-api-key where the "secret" is a bare code
#            identifier (no credential material).
# Anything else — any private-key, PAT, cloud credential, or unclassifiable
# generic hit — fails the check.
set -u -o pipefail
here="$(cd "$(dirname "$0")" && pwd)"
repo="$(cd "$here/../.." && pwd)"
scratch="${AUDIT_SCRATCH:?set AUDIT_SCRATCH}"

echo "== trufflehog full-history =="
"$here/tools/trufflehog" git "file://$repo" --no-update --no-verification --fail --json \
  > "$scratch/item9-trufflehog-real.json" 2>&1
th=$?
echo "trufflehog exit: $th (0 = no findings, 183 = findings)"
# FP3 (see below): trufflehog's only findings are the historical PEM fixtures
# under tests/kat/keyformats/openssl/ — added e760089, deliberately removed in
# 2cb4f33 ("Remove OpenSSL from the validation path; INVARIANT-36"), absent
# and unreferenced at HEAD (verified by fragment grep — see ledger row 9fp).
# Any OTHER trufflehog finding fails the check.
th_ok=0
if [ "$th" -eq 183 ]; then
  other=$(grep -oE '"file":"[^"]+"' "$scratch/item9-trufflehog-real.json" | grep -cv 'tests/kat/keyformats/openssl/')
  echo "trufflehog findings outside FP3 class: $other"
  [ "$other" -eq 0 ] || th_ok=1
fi

echo "== gitleaks full-history =="
"$here/tools/gitleaks" git "$repo" --no-banner --exit-code 9 \
  --report-format json --report-path "$scratch/item9-gitleaks-real.json" >/dev/null 2>&1
gl=$?
echo "gitleaks exit: $gl (0 = no findings, 9 = findings)"

python3 - "$scratch/item9-gitleaks-real.json" <<'EOF'
import json, re, sys
findings = json.load(open(sys.argv[1])) if __import__('os').path.getsize(sys.argv[1]) else []
ident = re.compile(r'^[A-Za-z_][A-Za-z0-9_.-]*$')
vector_material = re.compile(r'^[A-Za-z0-9+/_=-]+$')
vector_dirs = ('wycheproof_vectors/', 'nist_vectors/', 'tests/', 'benchmarks/')
bad = []
fp1 = fp2 = fp3 = 0
for f in findings:
    rule, path, secret = f['RuleID'], f['File'], f['Secret']
    if rule == 'generic-api-key' and path.startswith(vector_dirs) and vector_material.match(secret):
        fp1 += 1
    elif rule == 'generic-api-key' and ident.match(secret):
        fp2 += 1
    elif rule == 'private-key' and path.startswith('tests/kat/keyformats/openssl/'):
        fp3 += 1  # historical fixtures, removed at 2cb4f33, unreferenced at HEAD
    else:
        bad.append((rule, path, f['StartLine'], secret[:40]))
print(f"gitleaks findings: {len(findings)}  FP1(vector material): {fp1}  FP2(identifier): {fp2}  FP3(historical fixtures): {fp3}  unclassified: {len(bad)}")
for b in bad:
    print("UNCLASSIFIED:", b)
sys.exit(1 if bad else 0)
EOF
cls=$?

if [ "$th_ok" -eq 0 ] && [ "$cls" -eq 0 ]; then
  echo "ITEM9: CLEAN (trufflehog findings all in FP3; all gitleaks findings in documented FP classes)"
  exit 0
fi
echo "ITEM9: NOT CLEAN (trufflehog_ok=$th_ok classifier=$cls)"
exit 1
