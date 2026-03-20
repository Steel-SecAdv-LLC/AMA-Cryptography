# Ed25519 Field Representation Investigation Report

**Date:** 2026-03-20
**Branch:** `claude/ed25519-field-investigation-1kTrF`
**Platform:** Intel Xeon @ 2.10GHz (AVX-512, SHA-NI, AES-NI, BMI2)
**Compiler:** GCC 13.3.0, C11, `-O3 -march=native -funroll-loops`

## Executive Summary

Replaced the Ed25519 field arithmetic from radix 2^25.5 (10 limbs, `int64_t`)
to radix 2^51 (5 limbs, `uint64_t` + `__uint128_t`). This reduces the
schoolbook cross-product count from ~100 to 25 for multiplication and from ~55
to 15 for squaring. The result: **+156% improvement** in Ed25519 sign/verify
throughput, exceeding the 15K ops/sec target.

---

## Phase 1 — Radix 2^51 Field Arithmetic (`fe51.h`)

### Design
- 5 limbs of `uint64_t`, each holding ≤51 bits in reduced form
- `__uint128_t` intermediates for 64×64→128 bit products
- Reduction via 2^255 ≡ 19 (mod p): limbs wrapping past index 4 are folded
  back with a ×19 multiplier
- Subtraction uses 4p bias + carry chain (sub_reduce pattern) to maintain
  unsigned invariants across chained group operations

### Functions Implemented
`fe51_frombytes`, `fe51_tobytes`, `fe51_add`, `fe51_sub`, `fe51_neg`,
`fe51_carry`, `fe51_mul`, `fe51_sq`, `fe51_invert`, `fe51_pow22523`,
`fe51_isnegative`, `fe51_iszero`

### Key Bug Fixes
1. **fe51_sq diagonal coefficient**: Initial implementation used `f3_38 * f3`
   (=38·f3²) for the h1 diagonal term. Correct value is `f3_19 * f3` (=19·f3²).
   Cross-terms use 2×19=38; diagonal terms use 1×19.

2. **Carry chain limb growth**: After the main carry loop, `h[0] += c * 19`
   without a second carry to h[1]. In chained operations (e.g., mul→mul→mul),
   h[0] grows past 2^63, overflowing uint64_t precomputations. Fix: added
   second carry `c = h[0] >> 51; h[0] &= MASK51; h[1] += c;` in both
   `fe51_mul` and `fe51_sq`.

3. **Subtraction underflow in group operations**: Initial `fe51_sub` used 2p
   bias (limbs ~2^52). In `ge25519_p2_dbl`, the formula computes
   `F = 2·ZZ − (YY − XX)`. After the inner sub, (YY−XX) has limbs up to
   ~2^53 (from the 2p bias + inputs). The outer sub then underflows: 2p (~2^52)
   is insufficient to cover a 2^53 operand. Fix: changed to 4p bias + carry
   chain after subtraction (sub_reduce), matching donna64. Limbs are now
   always in [0, ~2^52) after sub.

---

## Phase 2 — Radix 2^64 Field Arithmetic (`fe64.h`)

### Design
- 4 limbs of `uint64_t`, full 64-bit limbs
- `__uint128_t` intermediates
- Reduction via 2^256 ≡ 38 (mod p)
- Row-by-row `fe64_mul512` to avoid uint128_t overflow in accumulations

### Key Bug Fix
- **uint128_t overflow in schoolbook sum**: Summing 4 terms of
  `(uint128_t)f[i]*g[j]` overflows 128 bits. Replaced with row-by-row
  multi-precision algorithm: `prod = f[i]*g[j] + r[i+j] + carry` where
  each accumulation is provably ≤ 2^128−1.

### Benchmark Result
- fe64_mul: ~53M ops/sec (39 cycles/op)
- fe64_sq: ~51M ops/sec (41 cycles/op)

---

## Phase 3 — Isolated Benchmark Results

| Operation | fe51 | fe64 | Winner |
|---|---:|---:|---|
| mul (ops/sec) | 49M | 53M | fe64 (+8%) |
| mul (cycles/op) | 42 | 39 | fe64 |
| sq (ops/sec) | 59M | 51M | **fe51 (+16%)** |
| sq (cycles/op) | 35 | 41 | **fe51** |

**Winner: fe51.** Squaring dominates Ed25519 (inversion uses ~250 squarings
via the addition chain). The 16% advantage in squaring outweighs the 8%
disadvantage in multiplication. Cross-validation: 10K random inputs for
frombytes/tobytes, mul, sq, add/sub, and 100 random inputs for invert —
all match between fe51 and fe64.

---

## Phase 4 — Wiring fe51 into Ed25519

### Changes to `ama_ed25519.c`
1. Changed `typedef int64_t fe25519[10]` → `typedef uint64_t fe25519[5]`
2. Replaced ~370 lines of ref10 field arithmetic with thin inline wrappers
   delegating to `fe51.h`
3. Converted `ed_d`, `ed_d2`, `sqrt_m1` constants to radix 2^51 format
4. Updated `ge25519_cmov` and constant-time table lookup loops from 10→5 limbs,
   `int64_t`→`uint64_t` mask
5. Moved base point `B` to lazy decompression (avoids hardcoded limb values)
6. Restored `load_3`/`load_4` helpers (needed by scalar arithmetic, removed
   with field arithmetic)

### Validation
- RFC 8032 test vectors: all pass (keygen, sign, verify)
- C KAT tests: 49/49 pass
- Python tests: 817 passed, 4 skipped, 0 failed

---

## Phase 5 — End-to-End Performance

### Results (median of 3 runs, 50K keygen, 50K sign, 20K verify)

| Operation | Phase 0 (ref10) | Phase 5 (fe51) | Delta |
|---|---:|---:|---:|
| Ed25519 keygen | 8,566 | **22,123** | **+158%** |
| Ed25519 sign (240B) | 8,272 | **21,177** | **+156%** |
| Ed25519 verify (240B) | 3,904 | **9,979** | **+156%** |

Target was ≥15K sign ops/sec — achieved 21K. The consistent ~2.5× improvement
across all three operations is expected: reducing 100 cross-products to 25
(×4 reduction) minus overhead from wider intermediates and carry chain
differences.

### Cycle Counts
- Keygen: ~95K cycles/op (was ~245K)
- Sign: ~99K cycles/op (was ~254K)
- Verify: ~210K cycles/op (was ~538K)

---

## Side-Channel Note

The unrolled Keccak-f[1600] permutation (from the prior performance
investigation, Phase 2) uses `#pragma GCC unroll 24`. This eliminates the
loop branch overhead but may introduce timing variations if the compiler
generates different instruction scheduling for different rounds. A dedicated
constant-time audit should verify that:
1. The unrolled code has uniform execution time regardless of state values
2. No conditional branches or variable-latency instructions were introduced
3. The `rotl64` branchless implementation remains branch-free after unrolling

This is a documentation-only note — no code changes made to Keccak.

---

## Files Created/Modified

### New Files
- `src/c/fe51.h` — radix 2^51 field arithmetic (5 limbs, __uint128_t)
- `src/c/fe64.h` — radix 2^64 field arithmetic (4 limbs, __uint128_t)
- `tests/c/test_field_bench.c` — cross-validation + benchmark harness
- `tests/c/bench_ed25519.c` — end-to-end Ed25519 benchmark

### Modified Files
- `src/c/ama_ed25519.c` — replaced ref10 field arithmetic with fe51 wrappers
- `docs/CSRC_ALIGN_REPORT.md` — updated with measured performance values
