#!/usr/bin/env bash
# Copyright (C) 2025-2026 Steel Security Advisors LLC
# SPDX-License-Identifier: Apache-2.0
# Item 18: TSan then Helgrind, each >= 2 h, threads = max(64, 8 x cores).
set -u
repo="$(cd "$(dirname "$0")/../../.." && pwd)"
logs="$repo/verification/v5-audit/logs"
d="$repo/verification/v5-audit/item18"
cores=$(nproc)
threads=$(( 8*cores > 64 ? 8*cores : 64 ))
secs="${AMA_T18_SECONDS:-7200}"

echo "item18: cores=$cores threads=$threads seconds_per_tool=$secs"

# --- TSan ---
echo "[$(date -u +%H:%M:%SZ)] TSan start"
AMA_T18_THREADS=$threads AMA_T18_SECONDS=$secs \
TSAN_OPTIONS="halt_on_error=0:exitcode=66:history_size=4" \
  "$d/thread_stress_tsan" > "$logs/item18-tsan.log" 2>&1
echo "TSAN_EXIT=$?" | tee -a "$logs/item18-tsan.log"
grep -c "data race" "$logs/item18-tsan.log" | sed 's/^/TSAN_DATA_RACE_REPORTS=/' | tee -a "$logs/item18-tsan.log"

# --- Helgrind ---
echo "[$(date -u +%H:%M:%SZ)] Helgrind start"
AMA_T18_THREADS=$threads AMA_T18_SECONDS=$secs \
  valgrind --tool=helgrind --error-exitcode=1 \
    "$d/thread_stress_plain" > "$logs/item18-helgrind.log" 2>&1
echo "HELGRIND_EXIT=$?" | tee -a "$logs/item18-helgrind.log"
grep -c "Possible data race" "$logs/item18-helgrind.log" | sed 's/^/HELGRIND_RACE_REPORTS=/' | tee -a "$logs/item18-helgrind.log"
echo "[$(date -u +%H:%M:%SZ)] item18 complete"
