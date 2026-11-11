/* Copyright (C) 2025-2026 Steel Security Advisors LLC */
/* SPDX-License-Identifier: Apache-2.0 */
/**
 * @file ama_argon2_avx2.c
 * @brief AVX2-vectorized Argon2 G compression function (RFC 9106)
 *
 * Drop-in replacement for the scalar argon2_G in ama_argon2.c. The
 * dispatcher wires this to ama_dispatch_table_t::argon2_g when AVX2
 * is available; ama_argon2.c calls through the pointer for every G
 * in the memory fill loop.
 *
 * Vectorization strategy — 4-way packed BlaMka G:
 *   Each BlaMka round of argon2_G operates on 16 uint64_t and performs
 *   8 G operations — 4 "column-like" tuples and 4 "diagonal-like"
 *   tuples (RFC 9106 §3.5). AVX2's 256-bit register holds exactly four
 *   uint64_t, so we pack the four tuples into (a,b,c,d) YMM registers
 *   and execute the four G's in a single AVX2 G sequence. The
 *   diagonal pass is handled by rotating the b/c/d lanes by 1/2/3
 *   slots with _mm256_permute4x64_epi64 and running the same kernel
 *   again, then rotating back.
 *
 * BlaMka G fidelity (RFC 9106 §3.5):
 *   fBlaMka(a, b) = a + b + 2 * (a mod 2^32) * (b mod 2^32)
 *   G(a, b, c, d):
 *     a = fBlaMka(a, b); d = rotr64(d^a, 32);
 *     c = fBlaMka(c, d); b = rotr64(b^c, 24);
 *     a = fBlaMka(a, b); d = rotr64(d^a, 16);
 *     c = fBlaMka(c, d); b = rotr64(b^c, 63);
 *   The 32-bit product is implemented with _mm256_mul_epu32 which
 *   multiplies the LOW 32 bits of each 64-bit lane into a full 64-bit
 *   product — exactly the (a mod 2^32) * (b mod 2^32) that BlaMka
 *   requires.
 *
 * The full Argon2 G compression computes R = X XOR Y, applies a
 * BlaMka round to each of the 8 rows of Z = R, then to each of the
 * 8 "column groups" (pairs of qwords spanning all rows), and
 * returns R XOR Z.
 *
 * Correctness: byte-identical to the scalar argon2_G. Verified by
 * RFC 9106 test vectors (tests/c/test_argon2id.c).
 *
 * AI Co-Architects: Eris + | Eden ~ | Devin * | Claude @
 */

#include "../internal/ama_string_ops.h"  /* first: no vector register holds what memcpy/memset move */
#include <stdint.h>
#include <stddef.h>
#include <string.h>

#if defined(__x86_64__) || defined(_M_X64)
#include <immintrin.h>
#include "ama_cryptography.h"
#include "ama_avx2_internal.h"
#include "../internal/ama_ct_barrier.h"

/* ============================================================================
 * BlaMka building blocks
 * ============================================================================ */

/* Rotate right 64-bit in each YMM lane by 32: swap low/high 32-bit halves. */
static inline __m256i rotr64_32(__m256i x) {
    return _mm256_shuffle_epi32(x, _MM_SHUFFLE(2, 3, 0, 1));
}

/* Rotate right 64-bit by 24: byte shuffle moving bytes (3..2) cyclically. */
static inline __m256i rotr64_24(__m256i x) {
    const __m256i mask = _mm256_setr_epi8(
         3,  4,  5,  6,  7,  0,  1,  2,
        11, 12, 13, 14, 15,  8,  9, 10,
         3,  4,  5,  6,  7,  0,  1,  2,
        11, 12, 13, 14, 15,  8,  9, 10);
    return _mm256_shuffle_epi8(x, mask);
}

/* Rotate right 64-bit by 16: byte shuffle by 2 bytes. */
static inline __m256i rotr64_16(__m256i x) {
    const __m256i mask = _mm256_setr_epi8(
         2,  3,  4,  5,  6,  7,  0,  1,
        10, 11, 12, 13, 14, 15,  8,  9,
         2,  3,  4,  5,  6,  7,  0,  1,
        10, 11, 12, 13, 14, 15,  8,  9);
    return _mm256_shuffle_epi8(x, mask);
}

/* Rotate right 64-bit by 63  ==  rotate left 64-bit by 1. */
static inline __m256i rotr64_63(__m256i x) {
    return _mm256_or_si256(_mm256_add_epi64(x, x),
                           _mm256_srli_epi64(x, 63));
}

/* fBlaMka packed 4-wide: a + b + 2*lo32(a)*lo32(b).
 * _mm256_mul_epu32 yields the unsigned 64-bit product of the low 32 bits
 * of each pair of lanes — exactly (a mod 2^32) * (b mod 2^32). */
static inline __m256i blamka_add(__m256i a, __m256i b) {
    __m256i lolo   = _mm256_mul_epu32(a, b);
    __m256i twolo  = _mm256_add_epi64(lolo, lolo);
    __m256i ab     = _mm256_add_epi64(a, b);
    return _mm256_add_epi64(ab, twolo);
}

/* Packed 4-wide BlaMka G. a/b/c/d each hold 4 independent qwords that
 * participate in 4 parallel G invocations. */
static inline void blamka_g4(__m256i *a, __m256i *b,
                              __m256i *c, __m256i *d) {
    *a = blamka_add(*a, *b);
    *d = rotr64_32(_mm256_xor_si256(*d, *a));
    *c = blamka_add(*c, *d);
    *b = rotr64_24(_mm256_xor_si256(*b, *c));
    *a = blamka_add(*a, *b);
    *d = rotr64_16(_mm256_xor_si256(*d, *a));
    *c = blamka_add(*c, *d);
    *b = rotr64_63(_mm256_xor_si256(*b, *c));
}

/* Rotate the 4 lanes of a YMM register left by N (N=1,2,3).
 * _MM_SHUFFLE(hi3,hi2,hi1,lo0) selects: out[i] = src[<nibble i>].
 *   rot_l1 wants out = [src1,src2,src3,src0] => (0,3,2,1)
 *   rot_l2 wants out = [src2,src3,src0,src1] => (1,0,3,2)
 *   rot_l3 wants out = [src3,src0,src1,src2] => (2,1,0,3)
 */
#define ROT_L1(x) _mm256_permute4x64_epi64((x), _MM_SHUFFLE(0, 3, 2, 1))
#define ROT_L2(x) _mm256_permute4x64_epi64((x), _MM_SHUFFLE(1, 0, 3, 2))
#define ROT_L3(x) _mm256_permute4x64_epi64((x), _MM_SHUFFLE(2, 1, 0, 3))

/* One full BlaMka round on four register quads (a, b, c, d) = v[0..3],
 * v[4..7], v[8..11], v[12..15].  Equivalent to blamka_round(v[0],...,v[15])
 * in the scalar path:
 *   column-like: G(v0,v4,v8,v12) ... G(v3,v7,v11,v15)
 *   diagonal-like: G(v0,v5,v10,v15) ... G(v3,v4,v9,v14) */
static inline void blamka_round_regs(__m256i *a, __m256i *b, __m256i *c, __m256i *d) {
    /* Column-like pass: lanes already aligned. */
    blamka_g4(a, b, c, d);

    /* Diagonal-like pass: rotate b/c/d lanes so the new 4 tuples match
     *   (v0,v5,v10,v15), (v1,v6,v11,v12), (v2,v7,v8,v13), (v3,v4,v9,v14). */
    *b = ROT_L1(*b);
    *c = ROT_L2(*c);
    *d = ROT_L3(*d);

    blamka_g4(a, b, c, d);

    /* Un-rotate: left-by-N and left-by-(4-N) are inverses mod 4. */
    *b = ROT_L3(*b);
    *c = ROT_L2(*c);
    *d = ROT_L1(*d);
}

/* Two 128-bit halves (qwords p[0..1] and q[0..1]) as one YMM register. */
static inline __m256i load_pair2(const uint64_t *p, const uint64_t *q) {
    return _mm256_inserti128_si256(
        _mm256_castsi128_si256(_mm_loadu_si128((const __m128i *)p)),
        _mm_loadu_si128((const __m128i *)q), 1);
}

static inline void store_pair2(uint64_t *p, uint64_t *q, __m256i v) {
    _mm_storeu_si128((__m128i *)p, _mm256_castsi256_si128(v));
    _mm_storeu_si128((__m128i *)q, _mm256_extracti128_si256(v, 1));
}

/* ============================================================================
 * Argon2 G compression (RFC 9106 §3.5)
 *
 *   R       = X XOR Y                     (128 qwords = 1024 B)
 *   Z       = R
 *   row-pass:   for row r in 0..7: blamka_round(Z[16r..16r+15])
 *   col-pass:   for col c in 0..7:
 *                   blamka_round( Z[2c+0], Z[2c+1], Z[2c+16], Z[2c+17],
 *                                 Z[2c+32], Z[2c+33], ... , Z[2c+113] )
 *   result  = R XOR Z
 *
 * Every XOR is fused into the round beside it: R = X ^ Y feeds the row pass
 * in registers, and R ^ Z is taken on the column pass's output, which goes
 * straight to `out`.  The previous layout ran each XOR, the Z = R copy and the
 * column gather/scatter as separate load-to-store loops, and with no integer
 * instruction on any of those chains clang 18's execution-domain pass moved
 * them as VMOVUPS/VXORPS -- 192 consuming sites on password-derived blocks,
 * none on Intel's Data Operand Independent Timing list
 * (tools/check_ct_operand.py --target argon2id).  Here every chain touches
 * the round's VPMULUDQ/VPADDQ/shift arithmetic.  The column pairs are joined
 * and split with VINSERTI128/VEXTRACTI128 rather than through a scratch
 * buffer.  tests/c/test_argon2_g_avx2_equiv.c holds the kernel to the scalar
 * G; the RFC 9106 vectors hold both.
 * ============================================================================ */

void ama_argon2_g_avx2(uint64_t out[128],
                        const uint64_t x[128],
                        const uint64_t y[128]) {
    uint64_t R[128];
    uint64_t Z[128];

    /* Each loop's offset goes through a value barrier, so that the loop exits
     * on its own counter.  x and y are the previous and the reference block,
     * and from the second half of pass 0 the reference block's ADDRESS is
     * password-derived by RFC 9106 sec. 3.4's design.  Left to itself the
     * compiler strength-reduces x + o into a pointer induction and tests that
     * pointer against an end pointer derived from it.  The branch's outcome
     * is the same for every password, but the secret-operand gate sees a
     * branch on a password-derived value: gcc 15.2 picked y's pointer on the
     * shipped LTO library (CI job 128734018389), and gcc 13.3 already tested
     * a pointer here, just not a derived one.  With the offset opaque, the
     * exit compares the counter. */
    /* Row pass: R = X ^ Y, then Z = blamka_round(R) row by row. */
    for (int row = 0; row < 8; row++) {
        const int o = (int)ama_ct_value_barrier_u32((uint32_t)row) * 16;
        __m256i a = _mm256_xor_si256(_mm256_loadu_si256((const __m256i *)(x + o)),
                                     _mm256_loadu_si256((const __m256i *)(y + o)));
        __m256i b = _mm256_xor_si256(_mm256_loadu_si256((const __m256i *)(x + o + 4)),
                                     _mm256_loadu_si256((const __m256i *)(y + o + 4)));
        __m256i c = _mm256_xor_si256(_mm256_loadu_si256((const __m256i *)(x + o + 8)),
                                     _mm256_loadu_si256((const __m256i *)(y + o + 8)));
        __m256i d = _mm256_xor_si256(_mm256_loadu_si256((const __m256i *)(x + o + 12)),
                                     _mm256_loadu_si256((const __m256i *)(y + o + 12)));
        _mm256_storeu_si256((__m256i *)(R + o), a);
        _mm256_storeu_si256((__m256i *)(R + o + 4), b);
        _mm256_storeu_si256((__m256i *)(R + o + 8), c);
        _mm256_storeu_si256((__m256i *)(R + o + 12), d);
        blamka_round_regs(&a, &b, &c, &d);
        _mm256_storeu_si256((__m256i *)(Z + o), a);
        _mm256_storeu_si256((__m256i *)(Z + o + 4), b);
        _mm256_storeu_si256((__m256i *)(Z + o + 8), c);
        _mm256_storeu_si256((__m256i *)(Z + o + 12), d);
    }

    /* Column pass: the 16 qwords of column group `col` are the pairs
     * (Z[2col + 16r], Z[2col + 16r + 1]) for r = 0..7, in row order, so the
     * quads are rows (0,1), (2,3), (4,5), (6,7).  out = R ^ round(...). */
    for (int col = 0; col < 8; col++) {
        const int o = 2 * (int)ama_ct_value_barrier_u32((uint32_t)col);
        __m256i a = load_pair2(Z + o, Z + o + 16);
        __m256i b = load_pair2(Z + o + 32, Z + o + 48);
        __m256i c = load_pair2(Z + o + 64, Z + o + 80);
        __m256i d = load_pair2(Z + o + 96, Z + o + 112);
        blamka_round_regs(&a, &b, &c, &d);
        store_pair2(out + o, out + o + 16, _mm256_xor_si256(a, load_pair2(R + o, R + o + 16)));
        store_pair2(out + o + 32, out + o + 48,
                    _mm256_xor_si256(b, load_pair2(R + o + 32, R + o + 48)));
        store_pair2(out + o + 64, out + o + 80,
                    _mm256_xor_si256(c, load_pair2(R + o + 64, R + o + 80)));
        store_pair2(out + o + 96, out + o + 112,
                    _mm256_xor_si256(d, load_pair2(R + o + 96, R + o + 112)));
    }

    /* R and Z hold password-derived block material; the driver scrubs its
     * heap matrix (ama_argon2.c) but the last invocation's stack frame would
     * otherwise survive.  Same INVARIANT-6/12 treatment the AVX2
     * dilithium/AES-GCM kernels give their staging buffers. */
    ama_secure_memzero(R, sizeof(R));
    ama_secure_memzero(Z, sizeof(Z));
}

#else
typedef int ama_argon2_avx2_not_available;
#endif /* __x86_64__ */
