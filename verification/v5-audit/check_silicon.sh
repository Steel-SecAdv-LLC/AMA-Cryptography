#!/usr/bin/env bash
# Phase 0.3: require avx512f, avx512vl, vaes, vpclmulqdq in lscpu flags.
set -u
flags=$(lscpu)
rc=0
for f in avx512f avx512vl vaes vpclmulqdq; do
  if echo "$flags" | grep -qw "$f"; then echo "PRESENT: $f"; else echo "ABSENT:  $f"; rc=1; fi
done
exit $rc
