#!/usr/bin/env bash
# Copyright (C) 2025-2026 Steel Security Advisors LLC
# SPDX-License-Identifier: Apache-2.0
# Item 1: verify the run-33338946996 dry-run's own signatures + provenance.
#
# Modes:
#   negative — byte-flip a copy of one wheel; cosign verify-blob and
#              slsa-verifier MUST both fail on it (exit 0 iff both fail).
#   clean    — verify every artifact (25 wheels + sdist) with cosign
#              verify-blob against its sigstore bundle AND slsa-verifier
#              against the SLSA provenance (exit 0 iff all 52 checks pass).
set -u -o pipefail

here="$(cd "$(dirname "$0")" && pwd)"
dist="$here/artifacts/signed-distribution"
prov="$here/artifacts/ama-cryptography.intoto.jsonl"
cosign="$here/tools/cosign"
slsa="$here/tools/slsa-verifier"
identity="https://github.com/Steel-SecAdv-LLC/AMA-Cryptography/.github/workflows/release.yml@refs/heads/steel/systempqc-maint1"
issuer="https://token.actions.githubusercontent.com"

mode="${1:?usage: $0 negative|clean}"

cosign_verify() { # $1=artifact $2=bundle
  "$cosign" verify-blob "$1" \
    --bundle "$2" --new-bundle-format \
    --certificate-identity "$identity" \
    --certificate-oidc-issuer "$issuer"
}

slsa_verify() { # $1=artifact
  "$slsa" verify-artifact "$1" \
    --provenance-path "$prov" \
    --source-uri github.com/Steel-SecAdv-LLC/AMA-Cryptography \
    --source-branch steel/systempqc-maint1
}

if [ "$mode" = negative ]; then
  sample="$dist/ama_cryptography-5.0.0-cp311-cp311-manylinux_2_26_x86_64.manylinux_2_28_x86_64.whl"
  tmp="$(mktemp -d)"
  cp "$sample" "$tmp/tampered.whl"
  # Flip one byte mid-file.
  size=$(stat -c%s "$tmp/tampered.whl")
  off=$((size / 2))
  orig=$(dd if="$tmp/tampered.whl" bs=1 skip="$off" count=1 2>/dev/null | xxd -p)
  flipped=$(printf '%02x' $(( 0x$orig ^ 0xff )))
  printf "\x$flipped" | dd of="$tmp/tampered.whl" bs=1 seek="$off" count=1 conv=notrunc 2>/dev/null
  echo "byte at offset $off: $orig -> $flipped"

  echo "--- cosign on tampered wheel (must FAIL) ---"
  if cosign_verify "$tmp/tampered.whl" "$sample.sigstore.json"; then
    echo "NEGATIVE CONTROL BROKEN: cosign accepted a tampered wheel"; rm -rf "$tmp"; exit 1
  fi
  echo "cosign rejected tampered wheel: OK"

  echo "--- slsa-verifier on tampered wheel (must FAIL) ---"
  if slsa_verify "$tmp/tampered.whl"; then
    echo "NEGATIVE CONTROL BROKEN: slsa-verifier accepted a tampered wheel"; rm -rf "$tmp"; exit 1
  fi
  echo "slsa-verifier rejected tampered wheel: OK"
  rm -rf "$tmp"
  exit 0
fi

if [ "$mode" = clean ]; then
  fail=0; n=0
  for a in "$dist"/*.whl "$dist"/*.tar.gz; do
    n=$((n+1))
    if ! cosign_verify "$a" "$a.sigstore.json"; then
      echo "COSIGN FAIL: $(basename "$a")"; fail=1
    fi
    if ! slsa_verify "$a"; then
      echo "SLSA FAIL: $(basename "$a")"; fail=1
    fi
    echo "verified($n): $(basename "$a")"
  done
  echo "artifacts checked: $n (expect 26)"
  [ "$n" -eq 26 ] || fail=1
  exit "$fail"
fi

echo "unknown mode: $mode"; exit 2
