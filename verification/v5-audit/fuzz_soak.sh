#!/usr/bin/env bash
# Copyright (C) 2025-2026 Steel Security Advisors LLC
# SPDX-License-Identifier: Apache-2.0
# Item 11: libFuzzer soak — every target >= 2 h with the real seed corpus.
# 2 concurrent workers (4-core host shared with other verification lanes).
# UBSan made fatal at runtime (halt_on_error) because FUZZ_FLAGS carries no
# -fno-sanitize-recover; LSan runs at exit (libFuzzer default detect_leaks).
set -u -o pipefail

repo="$(cd "$(dirname "$0")/../.." && pwd)"
here="$repo/verification/v5-audit"
bin="$repo/build-fuzz/bin"
seeds="$repo/fuzz/seed_corpus"
dicts="$repo/fuzz/dictionaries"
work="$repo/build-fuzz/corpus-work"
arts="$repo/build-fuzz/crash-artifacts"
logs="$here/logs"
budget="${FUZZ_BUDGET_S:-7200}"

targets=(fuzz_kyber fuzz_dilithium fuzz_ed25519 fuzz_aes_gcm fuzz_sphincs
         fuzz_x25519 fuzz_chacha20poly1305 fuzz_sha3 fuzz_hkdf
         fuzz_secp256k1 fuzz_frost fuzz_argon2 fuzz_agent_binding
         fuzz_consttime fuzz_ascon)

run_one() {
  t="$1"
  mkdir -p "$work/$t" "$arts/$t"
  dict_arg=()
  [ -f "$dicts/$t.dict" ] && dict_arg=(-dict="$dicts/$t.dict")
  log="$logs/item11-$t.log"
  export UBSAN_OPTIONS="halt_on_error=1:print_stacktrace=1"
  start=$(date -u +%Y-%m-%dT%H:%M:%SZ)
  "$bin/$t" -max_total_time="$budget" -timeout=60 -rss_limit_mb=2560 \
    -print_final_stats=1 -artifact_prefix="$arts/$t/" \
    "${dict_arg[@]}" "$work/$t" "$seeds/$t" >"$log" 2>&1
  rc=$?
  # libFuzzer's own reported runtime
  rt=$(grep -oE "Done [0-9]+ runs in [0-9]+ second" "$log" | grep -oE "in [0-9]+" | grep -oE "[0-9]+" || echo "unreported")
  sha=$(sha256sum "$log" | cut -d' ' -f1)
  v=FAIL; [ "$rc" -eq 0 ] && v=PASS
  echo "11.$t,\"$t -max_total_time=$budget -timeout=60 -rss_limit_mb=2560 -print_final_stats=1 [dict+seed corpus] (UBSAN_OPTIONS=halt_on_error=1)\",$rc,\"exit 0 after full $budget s soak; any crash/UB/leak/timeout is nonzero\",$v,verification/v5-audit/logs/item11-$t.log,$sha,${rt}s,$start" >>"$here/ledger.csv"
  echo "[$(date -u +%H:%M:%SZ)] $t done rc=$rc tool_runtime=${rt}s"
}

export -f run_one
export repo here bin seeds dicts work arts logs budget

printf '%s\n' "${targets[@]}" | xargs -P2 -I{} bash -c 'run_one "$@"' _ {}
echo "ALL_TARGETS_DISPATCHED_AND_COMPLETE"
