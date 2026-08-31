#!/usr/bin/env bash
# Copyright (C) 2025-2026 Steel Security Advisors LLC
# SPDX-License-Identifier: Apache-2.0
# Phase 0.3: require avx512f, avx512vl, vaes, vpclmulqdq in lscpu flags.
set -u
flags=$(lscpu)
rc=0
for f in avx512f avx512vl vaes vpclmulqdq; do
  if echo "$flags" | grep -qw "$f"; then echo "PRESENT: $f"; else echo "ABSENT:  $f"; rc=1; fi
done
exit $rc
