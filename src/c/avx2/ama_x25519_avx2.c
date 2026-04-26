/**
 * Copyright 2025-2026 Steel Security Advisors LLC
 * Licensed under the Apache License, Version 2.0
 *
 * @file ama_x25519_avx2.c
 * @brief AVX2 4-way X25519 Montgomery ladder (RFC 7748)
 *
 * 4-way SIMD path that processes four independent X25519 scalar
 * multiplications in parallel.  Used by the additive batch API
 * `ama_x25519_scalarmult_batch` only for full 4-lane chunks
 * (count / 4 of them), and only when the dispatcher has the kernel
 * wired in via `AMA_DISPATCH_USE_X25519_AVX2=1`.  The wrapper does
 * not pad shorter batches up to four lanes — counts of 1, 2, or 3,
 * the (count % 4) tail of longer batches, and `ama_x25519_key_exchange`
 * itself all stay on the scalar fe64 / fe51 / gf16 path; this kernel
 * is purely additive.
 *
 * Field representation:
 *   radix-2^25.5 (10 limbs, alternating 26 / 25 bits) — donna's
 *   reference layout from `vendor/ed25519-donna/curve25519-donna-32bit.h`.
 *   Packed 4-way as 10 × __m256i.  Each __m256i holds four 64-bit lanes;
 *   the LOW 32 bits of each lane carry one ladder's limb_i, the HIGH
 *   32 bits are kept zero so `_mm256_mul_epu32` (low32 × low32 → 64)
 *   computes one lane-product per multiplication.
 *
 * Constant-time cswap across all four lanes:
 *   For each ladder step, the per-lane scalar bit is materialised into
 *   a 64-bit all-ones / all-zeros mask in the matching __m256i lane,
 *   then the standard `t = mask & (p XOR q); p ^= t; q ^= t` swap is
 *   applied limb-by-limb.  No data-dependent branch anywhere in the
 *   hot loop.  INVARIANT-12 (constant-time secret-dependent ops).
 *
 * Constant-time guarantee:
 *   The CPUID-based dispatch gate (ama_has_avx2()) is the ONLY place
 *   the host's feature bits are consulted; the kernel itself is
 *   straight-line and never branches on a scalar bit.  All four
 *   lanes always carry live ladders (the wrapper only ever calls in
 *   for full 4-lane chunks), so per-lane timing uniformity is
 *   trivially uniform across the call — there are no zero-fill
 *   placeholder lanes.
 *
 * Correctness:
 *   The kernel is byte-identical to four sequential
 *   `ama_x25519_key_exchange` calls (verified by
 *   `tests/c/test_x25519.c` — RFC 7748 §5.2 TVs broadcast across all
 *   four lanes plus 1024 deterministically constructed (scalar, point)
 *   vectors against the scalar reference, matching the cross-check
 *   budget of `tests/c/test_x25519_field_equiv.c`).
 *
 * TODO(AVX-512-IFMA): the kernel's real home is AVX-512 IFMA
 * (`vpmadd52luq` / `vpmadd52huq` on Cannon Lake+, Ice Lake+,
 * Sapphire Rapids, Zen 5).  IFMA gives a 4-way 52-bit lane-wise
 * multiply that drops donna-32bit's ~100-cross-product schedule to
 * ~25 — the regime where 4× SIMD finally beats 4× scalar fe64.
 * The field layout, cswap, and dispatch glue carry over
 * unchanged; only `fe_mul_x4` / `fe_sqr_x4` swap to IFMA intrinsics.
 *
 * AI Co-Architects: Eris + | Eden ~ | Devin * | Claude @
 */

#include <stdint.h>
#include <stddef.h>
#include <string.h>

#if defined(__x86_64__) || defined(_M_X64)
#include <immintrin.h>
#include "ama_cryptography.h"
#include "ama_avx2_internal.h"

/* ============================================================================
 * Scalar 10-limb radix-2^25.5 helpers
 *
 * These mirror `vendor/ed25519-donna/curve25519-donna-32bit.h` but are
 * kept as private static helpers in this TU so the AVX2 path stays
 * self-contained.  The donna header is `DONNA_INLINE static` and not
 * directly callable from outside its includer; redeclaring the few
 * helpers we need (expand / contract) keeps the dependency surface
 * minimal and avoids re-pulling the entire ed25519-donna scalar
 * field-element implementation into this kernel.
 * ============================================================================ */

typedef uint32_t fe25519_10[10];

static const uint32_t reduce_mask_25 = (1u << 25) - 1u;
static const uint32_t reduce_mask_26 = (1u << 26) - 1u;

/* Decode a 32-byte little-endian u-coordinate into 10-limb form.
 * Equivalent to donna's `curve25519_expand`; the high bit of byte 31
 * is silently dropped (RFC 7748 §5: ignore the most significant bit of
 * the u-coordinate). */
static void fe25519_10_expand(fe25519_10 out, const uint8_t in[32]) {
    uint32_t x0 = (uint32_t)in[0]  | ((uint32_t)in[1]  << 8) |
                  ((uint32_t)in[2]  << 16) | ((uint32_t)in[3]  << 24);
    uint32_t x1 = (uint32_t)in[4]  | ((uint32_t)in[5]  << 8) |
                  ((uint32_t)in[6]  << 16) | ((uint32_t)in[7]  << 24);
    uint32_t x2 = (uint32_t)in[8]  | ((uint32_t)in[9]  << 8) |
                  ((uint32_t)in[10] << 16) | ((uint32_t)in[11] << 24);
    uint32_t x3 = (uint32_t)in[12] | ((uint32_t)in[13] << 8) |
                  ((uint32_t)in[14] << 16) | ((uint32_t)in[15] << 24);
    uint32_t x4 = (uint32_t)in[16] | ((uint32_t)in[17] << 8) |
                  ((uint32_t)in[18] << 16) | ((uint32_t)in[19] << 24);
    uint32_t x5 = (uint32_t)in[20] | ((uint32_t)in[21] << 8) |
                  ((uint32_t)in[22] << 16) | ((uint32_t)in[23] << 24);
    uint32_t x6 = (uint32_t)in[24] | ((uint32_t)in[25] << 8) |
                  ((uint32_t)in[26] << 16) | ((uint32_t)in[27] << 24);
    uint32_t x7 = (uint32_t)in[28] | ((uint32_t)in[29] << 8) |
                  ((uint32_t)in[30] << 16) | ((uint32_t)in[31] << 24);

    out[0] = (                        x0       ) & 0x3ffffff;
    out[1] = ((((uint64_t)x1 << 32) | x0) >> 26) & 0x1ffffff;
    out[2] = ((((uint64_t)x2 << 32) | x1) >> 19) & 0x3ffffff;
    out[3] = ((((uint64_t)x3 << 32) | x2) >> 13) & 0x1ffffff;
    out[4] = ((                       x3) >>  6) & 0x3ffffff;
    out[5] = (                        x4       ) & 0x1ffffff;
    out[6] = ((((uint64_t)x5 << 32) | x4) >> 25) & 0x3ffffff;
    out[7] = ((((uint64_t)x6 << 32) | x5) >> 19) & 0x1ffffff;
    out[8] = ((((uint64_t)x7 << 32) | x6) >> 12) & 0x3ffffff;
    out[9] = ((                       x7) >>  6) & 0x1ffffff;
}

/* Canonical 32-byte little-endian encoding.  Equivalent to donna's
 * `curve25519_contract`: three carry passes to fully reduce, then
 * conditionally subtract p = 2^255 - 19 via the `+19; -(2^255-19)`
 * branchless trick. */
static void fe25519_10_contract(uint8_t out[32], const fe25519_10 in) {
    uint32_t f[10];
    int i;
    for (i = 0; i < 10; i++) f[i] = in[i];

#define CARRY_PASS()                                              \
    f[1] += f[0] >> 26; f[0] &= reduce_mask_26;                   \
    f[2] += f[1] >> 25; f[1] &= reduce_mask_25;                   \
    f[3] += f[2] >> 26; f[2] &= reduce_mask_26;                   \
    f[4] += f[3] >> 25; f[3] &= reduce_mask_25;                   \
    f[5] += f[4] >> 26; f[4] &= reduce_mask_26;                   \
    f[6] += f[5] >> 25; f[5] &= reduce_mask_25;                   \
    f[7] += f[6] >> 26; f[6] &= reduce_mask_26;                   \
    f[8] += f[7] >> 25; f[7] &= reduce_mask_25;                   \
    f[9] += f[8] >> 26; f[8] &= reduce_mask_26

#define CARRY_PASS_FULL()                                         \
    CARRY_PASS();                                                 \
    f[0] += 19 * (f[9] >> 25); f[9] &= reduce_mask_25

#define CARRY_PASS_FINAL()                                        \
    CARRY_PASS();                                                 \
    f[9] &= reduce_mask_25

    CARRY_PASS_FULL();
    CARRY_PASS_FULL();

    /* now f is between 0 and 2^255-1, properly carried */
    f[0] += 19;
    CARRY_PASS_FULL();

    /* now between 19 and 2^255-1, offset by 19 */
    f[0] += (reduce_mask_26 + 1) - 19;
    f[1] += (reduce_mask_25 + 1) - 1;
    f[2] += (reduce_mask_26 + 1) - 1;
    f[3] += (reduce_mask_25 + 1) - 1;
    f[4] += (reduce_mask_26 + 1) - 1;
    f[5] += (reduce_mask_25 + 1) - 1;
    f[6] += (reduce_mask_26 + 1) - 1;
    f[7] += (reduce_mask_25 + 1) - 1;
    f[8] += (reduce_mask_26 + 1) - 1;
    f[9] += (reduce_mask_25 + 1) - 1;

    CARRY_PASS_FINAL();

#undef CARRY_PASS
#undef CARRY_PASS_FULL
#undef CARRY_PASS_FINAL

    /* Pack 10 limbs into 32 little-endian bytes by shifting limbs
     * into their canonical bit positions and OR-merging adjacent
     * boundaries. */
    f[1] <<= 2;
    f[2] <<= 3;
    f[3] <<= 5;
    f[4] <<= 6;
    f[6] <<= 1;
    f[7] <<= 3;
    f[8] <<= 4;
    f[9] <<= 6;

    memset(out, 0, 32);
#define F(i, s)                                                   \
    out[(s) + 0] |= (uint8_t)(f[i] & 0xff);                       \
    out[(s) + 1]  = (uint8_t)((f[i] >> 8)  & 0xff);               \
    out[(s) + 2]  = (uint8_t)((f[i] >> 16) & 0xff);               \
    out[(s) + 3]  = (uint8_t)((f[i] >> 24) & 0xff)
    F(0,  0);
    F(1,  3);
    F(2,  6);
    F(3,  9);
    F(4, 12);
    F(5, 16);
    F(6, 19);
    F(7, 22);
    F(8, 25);
    F(9, 28);
#undef F
}

/* ============================================================================
 * 4-way packed type and packing helpers
 * ============================================================================ */

typedef __m256i bignum25519_x4[10];

/* Pack four scalar 10-limb field elements into 10 __m256i lanes.
 * Lane k of every output __m256i holds limb_i of input k.  HIGH 32
 * bits of each lane are zero — required for `_mm256_mul_epu32` to
 * yield the correct 32x32->64 product. */
static inline void pack_4way(bignum25519_x4 out,
                             const fe25519_10 a,
                             const fe25519_10 b,
                             const fe25519_10 c,
                             const fe25519_10 d) {
    int i;
    for (i = 0; i < 10; i++) {
        out[i] = _mm256_setr_epi64x((int64_t)a[i], (int64_t)b[i],
                                    (int64_t)c[i], (int64_t)d[i]);
    }
}

/* Inverse of pack_4way.  Extracts limb_i for each lane back to four
 * scalar 10-limb arrays. */
static inline void unpack_4way(fe25519_10 a, fe25519_10 b,
                               fe25519_10 c, fe25519_10 d,
                               const bignum25519_x4 in) {
    int i;
    uint64_t tmp[4];
    for (i = 0; i < 10; i++) {
        _mm256_storeu_si256((__m256i *)tmp, in[i]);
        a[i] = (uint32_t)tmp[0];
        b[i] = (uint32_t)tmp[1];
        c[i] = (uint32_t)tmp[2];
        d[i] = (uint32_t)tmp[3];
    }
}

/* ============================================================================
 * 4-way field arithmetic (radix-2^25.5)
 *
 * Each routine is a direct lift of the donna scalar reference at
 * `vendor/ed25519-donna/curve25519-donna-32bit.h`:
 *   - uint32_t r0..r9          → __m256i (low 32 bits per lane = limb)
 *   - uint64_t m0..m9, c        → __m256i (full 64-bit lane = accumulator)
 *   - mul32x32_64(a, b)         → _mm256_mul_epu32(a, b)
 *   - addition (32 or 64 bit)   → _mm256_add_epi64(a, b)
 *   - shift / mask              → _mm256_srli_epi64 / _mm256_and_si256
 * ============================================================================ */

/* out = a + b (no reduction).  Limb-wise 64-bit addition.  Caller is
 * responsible for ensuring this remains representable until the next
 * mul/sq/contract reduces. */
static inline void fe_add_x4(bignum25519_x4 out,
                             const bignum25519_x4 a,
                             const bignum25519_x4 b) {
    int i;
    for (i = 0; i < 10; i++)
        out[i] = _mm256_add_epi64(a[i], b[i]);
}

/* out = a - b (with `2P` offset to keep limbs non-negative).
 * Mirrors donna's `curve25519_sub` plus a single reduction pass so
 * the output's per-limb magnitude stays bounded for subsequent
 * mul / sq calls.
 *
 * Donna's twoP / fourP constants are pre-computed multiples of p
 * spread across the limbs so the subtraction never underflows a
 * uint32_t lane.  Since our packed lanes are 64-bit, we use the
 * `twoP` constants (sufficient for one chained sub before the next
 * reduction step). */
static inline void fe_sub_x4(bignum25519_x4 out,
                             const bignum25519_x4 a,
                             const bignum25519_x4 b) {
    /* 2P offsets — keep lane non-negative when b > a. */
    const __m256i twoP0     = _mm256_set1_epi64x(0x07ffffda);
    const __m256i twoP13579 = _mm256_set1_epi64x(0x03fffffe);
    const __m256i twoP2468  = _mm256_set1_epi64x(0x07fffffe);

    out[0] = _mm256_add_epi64(twoP0,     _mm256_sub_epi64(a[0], b[0]));
    out[1] = _mm256_add_epi64(twoP13579, _mm256_sub_epi64(a[1], b[1]));
    out[2] = _mm256_add_epi64(twoP2468,  _mm256_sub_epi64(a[2], b[2]));
    out[3] = _mm256_add_epi64(twoP13579, _mm256_sub_epi64(a[3], b[3]));
    out[4] = _mm256_add_epi64(twoP2468,  _mm256_sub_epi64(a[4], b[4]));
    out[5] = _mm256_add_epi64(twoP13579, _mm256_sub_epi64(a[5], b[5]));
    out[6] = _mm256_add_epi64(twoP2468,  _mm256_sub_epi64(a[6], b[6]));
    out[7] = _mm256_add_epi64(twoP13579, _mm256_sub_epi64(a[7], b[7]));
    out[8] = _mm256_add_epi64(twoP2468,  _mm256_sub_epi64(a[8], b[8]));
    out[9] = _mm256_add_epi64(twoP13579, _mm256_sub_epi64(a[9], b[9]));
}

/* Final carry-propagate + reduce.  Identical structure to donna's
 * post-multiplication carry chain (see scalar mul lines after the
 * cross-product accumulation).  Brings every limb back into its
 * canonical 26 / 25 bit window with a final `* 19` wraparound from
 * limb 9 into limb 0. */
static inline void fe_reduce_x4(bignum25519_x4 out, const __m256i m_in[10]) {
    const __m256i mask26 = _mm256_set1_epi64x(0x3ffffff);
    const __m256i mask25 = _mm256_set1_epi64x(0x1ffffff);
    __m256i m0, m1, m2, m3, m4, m5, m6, m7, m8, m9, c, p;
    __m256i r0, r1, r2, r3, r4, r5, r6, r7, r8, r9;

    m0 = m_in[0]; m1 = m_in[1]; m2 = m_in[2]; m3 = m_in[3]; m4 = m_in[4];
    m5 = m_in[5]; m6 = m_in[6]; m7 = m_in[7]; m8 = m_in[8]; m9 = m_in[9];

    r0 = _mm256_and_si256(m0, mask26); c = _mm256_srli_epi64(m0, 26);
    m1 = _mm256_add_epi64(m1, c);
    r1 = _mm256_and_si256(m1, mask25); c = _mm256_srli_epi64(m1, 25);
    m2 = _mm256_add_epi64(m2, c);
    r2 = _mm256_and_si256(m2, mask26); c = _mm256_srli_epi64(m2, 26);
    m3 = _mm256_add_epi64(m3, c);
    r3 = _mm256_and_si256(m3, mask25); c = _mm256_srli_epi64(m3, 25);
    m4 = _mm256_add_epi64(m4, c);
    r4 = _mm256_and_si256(m4, mask26); c = _mm256_srli_epi64(m4, 26);
    m5 = _mm256_add_epi64(m5, c);
    r5 = _mm256_and_si256(m5, mask25); c = _mm256_srli_epi64(m5, 25);
    m6 = _mm256_add_epi64(m6, c);
    r6 = _mm256_and_si256(m6, mask26); c = _mm256_srli_epi64(m6, 26);
    m7 = _mm256_add_epi64(m7, c);
    r7 = _mm256_and_si256(m7, mask25); c = _mm256_srli_epi64(m7, 25);
    m8 = _mm256_add_epi64(m8, c);
    r8 = _mm256_and_si256(m8, mask26); c = _mm256_srli_epi64(m8, 26);
    m9 = _mm256_add_epi64(m9, c);
    r9 = _mm256_and_si256(m9, mask25); p = _mm256_srli_epi64(m9, 25);

    /* m0 = r0 + p * 19; bottom 26 bits → r0, carry → r1.
     * NOTE: `_mm256_mul_epu32(p, v19)` would truncate p to 32 bits.
     * In donna's scalar reference that's fine because reduced-limb
     * inputs bound m9 below 2^57, keeping `p = m9 >> 25` inside
     * uint32_t.  Our ladder feeds fe_mul_x4 with *unreduced* outputs
     * of fe_add_x4 / fe_sub_x4 (limbs up to ~2^28), which lifts m9 to
     * ~2^60 and makes p occupy up to ~35 bits — larger than the
     * mul_epu32 input window.  Compute `p * 19 = (p<<4) + (p<<1) + p`
     * with 64-bit shift+add so the full carry survives.  Same trick
     * the OpenSSL / boringssl 64-bit reductions use for the same
     * reason. */
    __m256i p19 = _mm256_add_epi64(
                     _mm256_add_epi64(_mm256_slli_epi64(p, 4),
                                      _mm256_slli_epi64(p, 1)),
                     p);
    m0 = _mm256_add_epi64(r0, p19);
    r0 = _mm256_and_si256(m0, mask26); p = _mm256_srli_epi64(m0, 26);
    r1 = _mm256_add_epi64(r1, p);

    out[0] = r0; out[1] = r1; out[2] = r2; out[3] = r3; out[4] = r4;
    out[5] = r5; out[6] = r6; out[7] = r7; out[8] = r8; out[9] = r9;
}

/* out = a * b, reduced.  Direct lift of donna's `curve25519_mul`. */
static inline void fe_mul_x4(bignum25519_x4 out,
                             const bignum25519_x4 a,
                             const bignum25519_x4 b) {
    const __m256i v2  = _mm256_set1_epi64x(2);
    const __m256i v19 = _mm256_set1_epi64x(19);

    /* Local copies — donna's scalar reuses r0..r9 and s0..s9 and
     * mutates r1, r3, r5, r7 (×2) then most of r1..r9 (×19).  We do
     * the same in-place trick on YMM registers since they're cheap. */
    __m256i r0 = b[0], r1 = b[1], r2 = b[2], r3 = b[3], r4 = b[4];
    __m256i r5 = b[5], r6 = b[6], r7 = b[7], r8 = b[8], r9 = b[9];
    __m256i s0 = a[0], s1 = a[1], s2 = a[2], s3 = a[3], s4 = a[4];
    __m256i s5 = a[5], s6 = a[6], s7 = a[7], s8 = a[8], s9 = a[9];
    __m256i m0, m1, m2, m3, m4, m5, m6, m7, m8, m9;

#define MUL(x, y) _mm256_mul_epu32((x), (y))
#define ADD(x, y) _mm256_add_epi64((x), (y))

    /* Odd partial products before r-doubling */
    m1 = ADD(MUL(r0, s1), MUL(r1, s0));
    m3 = ADD(ADD(MUL(r0, s3), MUL(r1, s2)), ADD(MUL(r2, s1), MUL(r3, s0)));
    m5 = ADD(ADD(ADD(MUL(r0, s5), MUL(r1, s4)), ADD(MUL(r2, s3), MUL(r3, s2))),
             ADD(MUL(r4, s1), MUL(r5, s0)));
    m7 = ADD(ADD(ADD(MUL(r0, s7), MUL(r1, s6)), ADD(MUL(r2, s5), MUL(r3, s4))),
             ADD(ADD(MUL(r4, s3), MUL(r5, s2)), ADD(MUL(r6, s1), MUL(r7, s0))));
    m9 = ADD(ADD(ADD(MUL(r0, s9), MUL(r1, s8)), ADD(MUL(r2, s7), MUL(r3, s6))),
             ADD(ADD(ADD(MUL(r4, s5), MUL(r5, s4)), ADD(MUL(r6, s3), MUL(r7, s2))),
                 ADD(MUL(r8, s1), MUL(r9, s0))));

    /* Double odd-indexed limbs (matches donna's `r1 *= 2; ...`) */
    r1 = MUL(r1, v2);
    r3 = MUL(r3, v2);
    r5 = MUL(r5, v2);
    r7 = MUL(r7, v2);

    /* Even partial products (with doubled odd limbs) */
    m0 = MUL(r0, s0);
    m2 = ADD(ADD(MUL(r0, s2), MUL(r1, s1)), MUL(r2, s0));
    m4 = ADD(ADD(MUL(r0, s4), MUL(r1, s3)), ADD(MUL(r2, s2), ADD(MUL(r3, s1), MUL(r4, s0))));
    m6 = ADD(ADD(ADD(MUL(r0, s6), MUL(r1, s5)), ADD(MUL(r2, s4), MUL(r3, s3))),
             ADD(MUL(r4, s2), ADD(MUL(r5, s1), MUL(r6, s0))));
    m8 = ADD(ADD(ADD(MUL(r0, s8), MUL(r1, s7)), ADD(MUL(r2, s6), MUL(r3, s5))),
             ADD(ADD(MUL(r4, s4), MUL(r5, s3)), ADD(MUL(r6, s2), ADD(MUL(r7, s1), MUL(r8, s0)))));

    /* `r3 = (r3 / 2) * 19` in the scalar reference — r3 was doubled
     * above, and donna recomputes r3 = r3_orig * 19.  We mirror that
     * by multiplying the doubled values by `19/2` is not integer, so
     * we instead derive from the original b[i] values (donna does the
     * `(r3 / 2) * 19` because in scalar, /2 of an even number is a
     * shift). For us: rebuild from b[i] (cheap — single mul). */
    r1 = MUL(b[1], v19);
    r2 = MUL(b[2], v19);
    r3 = MUL(b[3], v19);
    r4 = MUL(b[4], v19);
    r5 = MUL(b[5], v19);
    r6 = MUL(b[6], v19);
    r7 = MUL(b[7], v19);
    r8 = MUL(b[8], v19);
    r9 = MUL(b[9], v19);

    /* Wrapped odd partial products (limb_i * 19 * limb_j with i+j > 9) */
    m1 = ADD(m1, ADD(ADD(ADD(MUL(r9, s2), MUL(r8, s3)), ADD(MUL(r7, s4), MUL(r6, s5))),
                     ADD(ADD(MUL(r5, s6), MUL(r4, s7)), ADD(MUL(r3, s8), MUL(r2, s9)))));
    m3 = ADD(m3, ADD(ADD(ADD(MUL(r9, s4), MUL(r8, s5)), ADD(MUL(r7, s6), MUL(r6, s7))),
                     ADD(MUL(r5, s8), MUL(r4, s9))));
    m5 = ADD(m5, ADD(ADD(MUL(r9, s6), MUL(r8, s7)), ADD(MUL(r7, s8), MUL(r6, s9))));
    m7 = ADD(m7, ADD(MUL(r9, s8), MUL(r8, s9)));

    /* Double *19'd odd limbs again for the even wrapped partials.
     * Donna's scalar reaches the same final values via two separate
     * passes (first `r{1,3,5,7} *= 2` before the m_even computation,
     * then `r{1,2,...,9} *= 19` with `r{3,5,7} = (r/2)*19` to undo
     * the earlier *2 selectively, then `r{3,5,7,9} *= 2` to restore).
     * We rebuilt r1..r9 directly from b[i]*19 above; here we double
     * r1 / r3 / r5 / r7 / r9 to land on the donna-final values
     * { 38·b1, 19·b2, 38·b3, 19·b4, 38·b5, 19·b6, 38·b7, 19·b8,
     *   38·b9 } that the wrapped-even partials need. */
    r1 = MUL(r1, v2);
    r3 = MUL(r3, v2);
    r5 = MUL(r5, v2);
    r7 = MUL(r7, v2);
    r9 = MUL(r9, v2);

    m0 = ADD(m0, ADD(ADD(ADD(MUL(r9, s1), MUL(r8, s2)), ADD(MUL(r7, s3), MUL(r6, s4))),
                     ADD(ADD(MUL(r5, s5), MUL(r4, s6)), ADD(ADD(MUL(r3, s7), MUL(r2, s8)),
                                                            MUL(r1, s9)))));
    m2 = ADD(m2, ADD(ADD(ADD(MUL(r9, s3), MUL(r8, s4)), ADD(MUL(r7, s5), MUL(r6, s6))),
                     ADD(ADD(MUL(r5, s7), MUL(r4, s8)), MUL(r3, s9))));
    m4 = ADD(m4, ADD(ADD(MUL(r9, s5), MUL(r8, s6)), ADD(ADD(MUL(r7, s7), MUL(r6, s8)),
                                                        MUL(r5, s9))));
    m6 = ADD(m6, ADD(ADD(MUL(r9, s7), MUL(r8, s8)), MUL(r7, s9)));
    m8 = ADD(m8, MUL(r9, s9));

#undef MUL
#undef ADD

    /* Final carry-propagate + reduce */
    __m256i m[10] = { m0, m1, m2, m3, m4, m5, m6, m7, m8, m9 };
    fe_reduce_x4(out, m);
}

/* out = in^2 — implemented via fe_mul_x4(in, in).  Donna provides a
 * dedicated squaring kernel for performance, but for the 4-way path
 * the bottleneck is the carry chain (which dominates over the mul
 * count), and a separate sq kernel adds significant code surface for
 * a marginal win.  Re-using fe_mul_x4 keeps the code small and
 * verifiably correct against the scalar reference. */
static inline void fe_sq_x4(bignum25519_x4 out, const bignum25519_x4 in) {
    fe_mul_x4(out, in, in);
}

/* out = in * 121665.  The Montgomery ladder needs a single
 * multiply-by-constant per step (a24 = (A-2)/4 = 121665).  Lane-wise
 * mul-by-imm followed by a reduction pass. */
static inline void fe_mul_121665_x4(bignum25519_x4 out,
                                    const bignum25519_x4 in) {
    const __m256i v121665 = _mm256_set1_epi64x(121665);
    __m256i m[10];
    int i;
    for (i = 0; i < 10; i++)
        m[i] = _mm256_mul_epu32(in[i], v121665);
    fe_reduce_x4(out, m);
}

/* Constant-time 4-way conditional swap.  `mask` is a __m256i whose
 * lane k is all-ones (swap that ladder) or all-zeros (no swap).
 * Equivalent to `_mm256_blendv_epi8(p, q, mask)` followed by storing
 * the original p into q's slot, but the XOR form is simpler and
 * exactly as constant-time. */
static inline void fe_cswap_x4(bignum25519_x4 p, bignum25519_x4 q,
                               __m256i mask) {
    int i;
    for (i = 0; i < 10; i++) {
        __m256i t = _mm256_and_si256(mask, _mm256_xor_si256(p[i], q[i]));
        p[i] = _mm256_xor_si256(p[i], t);
        q[i] = _mm256_xor_si256(q[i], t);
    }
}

static inline void fe_copy_x4(bignum25519_x4 out, const bignum25519_x4 in) {
    int i;
    for (i = 0; i < 10; i++) out[i] = in[i];
}

static inline void fe_set1_x4(bignum25519_x4 out, uint32_t v) {
    int i;
    for (i = 0; i < 10; i++) out[i] = _mm256_setzero_si256();
    out[0] = _mm256_set1_epi64x((int64_t)v);
}

/* 4-way Fermat inversion (1/z = z^(p-2) mod p).  Same straight-line
 * addition chain as donna's `curve25519_recip`, executed lane-wise
 * across all four ladders simultaneously. */
static void fe_invert_x4(bignum25519_x4 out, const bignum25519_x4 z) {
    bignum25519_x4 t0, t1, t2, t3;
    int i;

    fe_sq_x4 (t0, z);
    fe_sq_x4 (t1, t0); fe_sq_x4(t1, t1);
    fe_mul_x4(t1, z, t1);
    fe_mul_x4(t0, t0, t1);
    fe_sq_x4 (t2, t0);
    fe_mul_x4(t1, t1, t2);
    fe_sq_x4 (t2, t1);
    for (i = 0; i < 4; i++)  fe_sq_x4(t2, t2);
    fe_mul_x4(t1, t2, t1);
    fe_sq_x4 (t2, t1);
    for (i = 0; i < 9; i++)  fe_sq_x4(t2, t2);
    fe_mul_x4(t2, t2, t1);
    fe_sq_x4 (t3, t2);
    for (i = 0; i < 19; i++) fe_sq_x4(t3, t3);
    fe_mul_x4(t2, t3, t2);
    fe_sq_x4 (t2, t2);
    for (i = 0; i < 9; i++)  fe_sq_x4(t2, t2);
    fe_mul_x4(t1, t2, t1);
    fe_sq_x4 (t2, t1);
    for (i = 0; i < 49; i++) fe_sq_x4(t2, t2);
    fe_mul_x4(t2, t2, t1);
    fe_sq_x4 (t3, t2);
    for (i = 0; i < 99; i++) fe_sq_x4(t3, t3);
    fe_mul_x4(t2, t3, t2);
    fe_sq_x4 (t2, t2);
    for (i = 0; i < 49; i++) fe_sq_x4(t2, t2);
    fe_mul_x4(t1, t2, t1);
    fe_sq_x4 (t1, t1);
    for (i = 0; i < 4; i++)  fe_sq_x4(t1, t1);
    fe_mul_x4(out, t1, t0);
}

/* ============================================================================
 * 4-way Montgomery ladder — RFC 7748 Appendix A
 * ============================================================================ */

void ama_x25519_scalarmult_x4_avx2(uint8_t out[4][32],
                                    const uint8_t scalar[4][32],
                                    const uint8_t point[4][32]) {
    /* All sensitive ladder state lives in one struct so the secure
     * scrub at the end is a single contiguous memzero rather than a
     * 17-call ladder of per-variable zeroings (each of which the
     * compiler has to keep undefeated against DCE individually). */
    struct {
        uint8_t        k[4][32];
        fe25519_10     u_a, u_b, u_c, u_d;
        fe25519_10     r_a, r_b, r_c, r_d;
        uint64_t       swap[4];
        bignum25519_x4 x1, x2, z2, x3, z3;
        bignum25519_x4 A, AA, B, BB, E, C, D, DA, CB, t0, t1;
    } s;

    int lane, t;

    /* Decode and clamp each lane's scalar (RFC 7748 §5). */
    for (lane = 0; lane < 4; lane++) {
        memcpy(s.k[lane], scalar[lane], 32);
        s.k[lane][0]  &= 248;
        s.k[lane][31] &= 127;
        s.k[lane][31] |= 64;
    }

    /* Decode each lane's u-coordinate into 10-limb form, then pack
     * the four scalar bignums into 10 __m256i lanes. */
    fe25519_10_expand(s.u_a, point[0]);
    fe25519_10_expand(s.u_b, point[1]);
    fe25519_10_expand(s.u_c, point[2]);
    fe25519_10_expand(s.u_d, point[3]);

    pack_4way(s.x1, s.u_a, s.u_b, s.u_c, s.u_d);

    /* Ladder initial state — same as RFC 7748 / donna scalar:
     *   x2 = 1, z2 = 0, x3 = x1, z3 = 1.
     * Set as broadcast constants since all four lanes start identically. */
    fe_set1_x4(s.x2, 1);
    fe_set1_x4(s.z2, 0);
    fe_copy_x4(s.x3, s.x1);
    fe_set1_x4(s.z3, 1);

    /* Ladder body — 255 steps from bit 254 down to bit 0.  Per-step
     * the cswap mask is built from each lane's k_t bit XORed with the
     * running per-lane swap state.  No data-dependent branch. */
    s.swap[0] = s.swap[1] = s.swap[2] = s.swap[3] = 0;

    for (t = 254; t >= 0; t--) {
        uint64_t kt[4];
        uint64_t mask[4];
        for (lane = 0; lane < 4; lane++) {
            kt[lane] = (uint64_t)((s.k[lane][t >> 3] >> (t & 7)) & 1);
            s.swap[lane] ^= kt[lane];
            /* mask = -swap (0 → 0x000…000, 1 → 0xFFF…FFF). */
            mask[lane] = (uint64_t)(0 - s.swap[lane]);
            s.swap[lane] = kt[lane];
        }
        __m256i m = _mm256_setr_epi64x((int64_t)mask[0], (int64_t)mask[1],
                                       (int64_t)mask[2], (int64_t)mask[3]);
        fe_cswap_x4(s.x2, s.x3, m);
        fe_cswap_x4(s.z2, s.z3, m);

        fe_add_x4(s.A,  s.x2, s.z2);     /* A  = x2 + z2    */
        fe_sq_x4 (s.AA, s.A);            /* AA = A^2        */
        fe_sub_x4(s.B,  s.x2, s.z2);     /* B  = x2 - z2    */
        fe_sq_x4 (s.BB, s.B);            /* BB = B^2        */
        fe_sub_x4(s.E,  s.AA, s.BB);     /* E  = AA - BB    */
        fe_add_x4(s.C,  s.x3, s.z3);     /* C  = x3 + z3    */
        fe_sub_x4(s.D,  s.x3, s.z3);     /* D  = x3 - z3    */
        fe_mul_x4(s.DA, s.D, s.A);       /* DA = D * A      */
        fe_mul_x4(s.CB, s.C, s.B);       /* CB = C * B      */
        fe_add_x4(s.t0, s.DA, s.CB);     /* t0 = DA + CB    */
        fe_sq_x4 (s.x3, s.t0);           /* x3 = (DA+CB)^2  */
        fe_sub_x4(s.t0, s.DA, s.CB);     /* t0 = DA - CB    */
        fe_sq_x4 (s.t1, s.t0);           /* t1 = (DA-CB)^2  */
        fe_mul_x4(s.z3, s.x1, s.t1);     /* z3 = x1 * (DA-CB)^2 */
        fe_mul_x4(s.x2, s.AA, s.BB);     /* x2 = AA * BB    */
        fe_mul_121665_x4(s.t0, s.E);     /* t0 = a24 * E    */
        fe_add_x4(s.t1, s.AA, s.t0);     /* t1 = AA + a24*E */
        fe_mul_x4(s.z2, s.E, s.t1);      /* z2 = E * (AA + a24*E) */
    }

    /* Final swap based on the residual swap state. */
    {
        __m256i m = _mm256_setr_epi64x(
            (int64_t)(uint64_t)(0 - s.swap[0]),
            (int64_t)(uint64_t)(0 - s.swap[1]),
            (int64_t)(uint64_t)(0 - s.swap[2]),
            (int64_t)(uint64_t)(0 - s.swap[3]));
        fe_cswap_x4(s.x2, s.x3, m);
        fe_cswap_x4(s.z2, s.z3, m);
    }

    /* Result lane k = x2_k / z2_k mod p.  4-way Fermat inversion. */
    fe_invert_x4(s.z2, s.z2);
    fe_mul_x4(s.x2, s.x2, s.z2);

    /* Unpack and contract to canonical 32-byte form per lane. */
    unpack_4way(s.r_a, s.r_b, s.r_c, s.r_d, s.x2);
    fe25519_10_contract(out[0], s.r_a);
    fe25519_10_contract(out[1], s.r_b);
    fe25519_10_contract(out[2], s.r_c);
    fe25519_10_contract(out[3], s.r_d);

    /* Secure cleanup of all sensitive ladder state in one shot.
     * Because every secret local lives in `s`, a single memzero of the
     * struct covers them all and is trivial to extend the next time a
     * helper-temporary lands in this function. */
    ama_secure_memzero(&s, sizeof(s));
}

#else
typedef int ama_x25519_avx2_not_available;
#endif /* __x86_64__ */
