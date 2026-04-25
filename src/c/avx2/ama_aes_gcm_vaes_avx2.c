/**
 * Copyright 2025-2026 Steel Security Advisors LLC
 * Licensed under the Apache License, Version 2.0
 *
 * @file ama_aes_gcm_vaes_avx2.c
 * @brief VAES + VPCLMULQDQ AES-256-GCM (AVX2 / YMM, no AVX-512)
 *
 * PR A (2026-04). Bulk-throughput AES-256-GCM kernel built on the
 * VEX-encoded YMM forms of VAES and VPCLMULQDQ.  Independent of
 * AVX-512: only AVX OS save-area state (XCR0 bits 1+2) is required,
 * so the kernel runs on every Ice Lake+ / Alder Lake+ / Zen 3+ host
 * without paying the Skylake-SP / Cascade Lake ZMM downclock penalty.
 *
 * Dispatch gate (src/c/dispatch/ama_dispatch.c):
 *   ama_cpuid_has_vaes_aesgcm() == 1
 *     <=> CPUID(VAES) && CPUID(VPCLMULQDQ) && CPUID(PCLMULQDQ)
 *      && CPUID(AVX2) && CPUID(AES-NI)
 *      && OSXSAVE && (XCR0 & {SSE,AVX})
 *
 * Both VPCLMULQDQ (CPUID.(EAX=7,ECX=0):ECX[10], YMM CLMUL for the
 * 4-block GHASH fold) and baseline PCLMULQDQ (CPUID.(EAX=1):ECX[1],
 * XMM CLMUL for single-block edge paths — AAD blocks, H power
 * precompute, trailing partial, length block) are required
 * explicitly because the ISA documents them as architecturally
 * independent feature bits; every shipped Intel/AMD CPU has both,
 * but the bundle's safety contract should not depend on that
 * empirical observation (Devin Review #3140732664).
 *
 * AES-NI is still required because AESKEYGENASSIST (the key-schedule
 * primitive for AES-256) is a 128-bit XMM opcode and has no YMM/VAES
 * equivalent — VAES only provides the AES round opcodes (vaesenc /
 * vaesenclast).  The existing AVX2 AES-NI key schedule from
 * ama_aes_gcm_avx2.c is reused verbatim.
 *
 * Inner loop:
 *   - 4 counter blocks per iteration, packed two-per-YMM (256 bits)
 *   - vaesenc ymm / vaesenclast ymm rounds (round keys broadcast once)
 *   - 4-lane Karatsuba GHASH using _mm256_clmulepi64_epi128 (YMM
 *     VPCLMULQDQ): two (block, H_power) lane-pairs per YMM, 8 YMM
 *     CLMULs per 4-block iteration instead of 16 XMM CLMULs.  The
 *     intrinsic applies the imm8 selector independently per 128-bit
 *     lane, so the algebra is identical to the XMM-per-lane form.
 *   - GHASH reduction is the standard reflected GCM polynomial
 *     reduction (Intel "Carry-Less Multiplication and its Usage for
 *     Computing the GCM Mode" whitepaper, Algorithm 5), executed in
 *     the XMM domain after a horizontal lane fold — the reduction
 *     itself is intrinsically scalar in the high bits (shifts of
 *     57 / 62 / 63 and 1 / 2 / 7 across the 128-bit polynomial), so
 *     widening it past XMM yields no benefit.
 *   - Short-AAD / trailing-partial / final length-block paths stay
 *     XMM: they are single-block GHASH multiplies and vectorising
 *     them does not pay back the pack/fold overhead.
 *
 * INVARIANT-1   : zero external crypto deps; kernel written in-tree.
 *                 Algorithmic provenance: Intel intel-ipsec-mb (BSD-3),
 *                 cited for reference only — no code copied.
 * INVARIANT-12  : tag compare unchanged, GHASH uses VAES + VPCLMULQDQ
 *                 carry-less multiply (YMM for the 4-block fold, XMM
 *                 for single-block edge paths), no table lookups.
 * INVARIANT-15  : no dispatch reorder, kernel entered only via the
 *                 ama_dispatch_table function pointer set inside the
 *                 existing dispatch_init_internal() once-call.
 *
 * MSVC escape hatch: MSVC ships VAES intrinsics under
 * <immintrin.h>, but until a green sample build lands on
 * windows-latest CI we leave the dispatch slot NULL on _MSC_VER.
 * The dispatcher's NULL-fallback path is the existing AVX2 AES-NI
 * implementation, which is byte-identical and already validated by
 * #253 / #254 / #260 / #261.  A #pragma message in the build log
 * makes the skip visible.
 *
 * AI Co-Architects: Eris ✠ | Eden ♱ | Devin ⚛︎ | Claude ⊛
 */

#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include "ama_cryptography.h"
#include "ama_avx2_internal.h"

/* MSVC: leave kernel out, let dispatcher fall back to AVX2 AES-NI. */
#if defined(_MSC_VER)

#pragma message("ama_aes_gcm_vaes_avx2.c: VAES path skipped on MSVC; dispatcher uses AVX2 AES-NI fallback")

typedef int ama_aes_gcm_vaes_avx2_msvc_skipped;

#elif defined(__x86_64__) || defined(_M_X64)

#include <immintrin.h>
#include <wmmintrin.h>  /* AES-NI (xmm key expansion) */
#include <tmmintrin.h>  /* SSSE3 _mm_shuffle_epi8 */

/* AES-256 key expansion (AES-NI, 128-bit) is declared in
 * ama_avx2_internal.h and defined in ama_aes_gcm_avx2.c; reused here
 * so any future bug-fix to the key schedule lands in exactly one place. */

/* ============================================================================
 * Byte-reverse helpers
 *
 * GCM uses reflected bit ordering; PCLMULQDQ multiplies in natural bit
 * ordering.  Per the Intel whitepaper, all GHASH operands (H, data
 * blocks, accumulator output) must be byte-swapped when crossing the
 * GCM <-> PCLMULQDQ domain boundary.
 *
 * The shuffle masks are declared as file-scope `static const __m{128,256}i`
 * via a typed union so the compiler treats them as a single .rodata
 * constant per width.  This makes the `vpshufb` operand a hoist-able
 * RIP-relative load instead of an unguaranteed loop-invariant move from
 * an `uint8_t` array (Copilot review #3140468406 / #3140468448).
 * ============================================================================ */
static const union {
    uint8_t bytes[16];
    __m128i v;
} bswap_mask128 = {
    .bytes = { 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0 }
};

static inline __m128i bswap128(__m128i v) {
    return _mm_shuffle_epi8(v, bswap_mask128.v);
}

/* ============================================================================
 * Single-block AES-256 encryption (AES-NI / XMM).
 *
 * Used for one-off operations — H = AES_K(0), J0 keystream, AAD-only
 * tag derivation, partial trailing block.  Bulk traffic goes through
 * the YMM VAES path below.
 * ============================================================================ */
static inline __m128i aes256_encrypt_block_xmm(__m128i block, const __m128i rk[15]) {
    block = _mm_xor_si128(block, rk[0]);
    block = _mm_aesenc_si128(block, rk[1]);
    block = _mm_aesenc_si128(block, rk[2]);
    block = _mm_aesenc_si128(block, rk[3]);
    block = _mm_aesenc_si128(block, rk[4]);
    block = _mm_aesenc_si128(block, rk[5]);
    block = _mm_aesenc_si128(block, rk[6]);
    block = _mm_aesenc_si128(block, rk[7]);
    block = _mm_aesenc_si128(block, rk[8]);
    block = _mm_aesenc_si128(block, rk[9]);
    block = _mm_aesenc_si128(block, rk[10]);
    block = _mm_aesenc_si128(block, rk[11]);
    block = _mm_aesenc_si128(block, rk[12]);
    block = _mm_aesenc_si128(block, rk[13]);
    return _mm_aesenclast_si128(block, rk[14]);
}

/* ============================================================================
 * GHASH — single-block GF(2^128) multiply (XMM, PCLMULQDQ).
 *
 * Inputs / output in GCM native byte order.  Used for AAD blocks, the
 * final length block, and the trailing-partial-block tail — i.e. all
 * code paths where vector-wide GHASH gives no benefit.
 * ============================================================================ */
static inline __m128i ghash_mul_xmm(__m128i a_gcm, __m128i b_gcm) {
    __m128i a = bswap128(a_gcm);
    __m128i b = bswap128(b_gcm);

    __m128i lo   = _mm_clmulepi64_si128(a, b, 0x00);
    __m128i hi   = _mm_clmulepi64_si128(a, b, 0x11);
    __m128i mid1 = _mm_clmulepi64_si128(a, b, 0x01);
    __m128i mid2 = _mm_clmulepi64_si128(a, b, 0x10);
    __m128i mid  = _mm_xor_si128(mid1, mid2);
    lo = _mm_xor_si128(lo, _mm_slli_si128(mid, 8));
    hi = _mm_xor_si128(hi, _mm_srli_si128(mid, 8));

    /* Reflected-bit 1-bit-left shift correction over [hi:lo]. */
    __m128i lo_carry_top = _mm_srli_si128(_mm_srli_epi64(lo, 63), 8);
    {
        __m128i carry = _mm_srli_epi64(hi, 63);
        carry = _mm_slli_si128(carry, 8);
        hi = _mm_or_si128(_mm_slli_epi64(hi, 1), carry);
    }
    hi = _mm_or_si128(hi, lo_carry_top);
    {
        __m128i carry = _mm_srli_epi64(lo, 63);
        carry = _mm_slli_si128(carry, 8);
        lo = _mm_or_si128(_mm_slli_epi64(lo, 1), carry);
    }

    /* Reduction (Intel whitepaper, Alg. 5). */
    __m128i A = _mm_slli_epi64(lo, 63);
    __m128i B = _mm_slli_epi64(lo, 62);
    __m128i C = _mm_slli_epi64(lo, 57);
    __m128i D = _mm_xor_si128(A, _mm_xor_si128(B, C));
    lo = _mm_xor_si128(lo, _mm_slli_si128(D, 8));

    __m128i E = _mm_srli_epi64(lo, 1);
    __m128i F = _mm_srli_epi64(lo, 2);
    __m128i G = _mm_srli_epi64(lo, 7);
    __m128i result = _mm_xor_si128(hi, lo);
    result = _mm_xor_si128(result, E);
    result = _mm_xor_si128(result, F);
    result = _mm_xor_si128(result, G);
    result = _mm_xor_si128(result, _mm_srli_si128(D, 8));

    return bswap128(result);
}

/* ============================================================================
 * 4-block parallel VAES + 4-lane Karatsuba GHASH.
 *
 * Encrypts 4 counter blocks (packed 2-per-YMM) and folds 4 ciphertext
 * blocks into the GHASH accumulator using two vpclmulqdq ymm
 * carry-less multiplies per lane.  The fold uses the Horner-style
 * "reduce-once-per-4" optimisation:
 *
 *     out_acc = (((acc XOR C0) * H^4)
 *               XOR (C1 * H^3)
 *               XOR (C2 * H^2)
 *               XOR (C3 * H^1)) mod GCM_POLY
 *
 * The four powers H^1..H^4 are precomputed once per call.
 *
 * The aggregated lo/hi/mid limbs are accumulated across all four
 * lanes *before* a single Montgomery reduction, so we pay the
 * reduction cost once per 4 blocks rather than 4 times.
 * ============================================================================ */
static inline __m128i ghash_mul_raw_lo(__m128i a_gcm, __m128i b_gcm,
                                        __m128i *out_hi, __m128i *out_mid) {
    __m128i a = bswap128(a_gcm);
    __m128i b = bswap128(b_gcm);
    __m128i lo   = _mm_clmulepi64_si128(a, b, 0x00);
    __m128i hi   = _mm_clmulepi64_si128(a, b, 0x11);
    __m128i mid1 = _mm_clmulepi64_si128(a, b, 0x01);
    __m128i mid2 = _mm_clmulepi64_si128(a, b, 0x10);
    *out_hi  = hi;
    *out_mid = _mm_xor_si128(mid1, mid2);
    return lo;
}

/* Final reduction of a deferred {lo, hi, mid} limb triple to a single
 * GCM-domain accumulator value.  Folds mid into [hi:lo], applies the
 * 1-bit reflected-shift correction, then runs the same Algorithm 5
 * reduction as ghash_mul_xmm. */
static inline __m128i ghash_reduce(__m128i lo, __m128i hi, __m128i mid) {
    lo = _mm_xor_si128(lo, _mm_slli_si128(mid, 8));
    hi = _mm_xor_si128(hi, _mm_srli_si128(mid, 8));

    /* Reflected-bit shift-left correction. */
    __m128i lo_carry_top = _mm_srli_si128(_mm_srli_epi64(lo, 63), 8);
    {
        __m128i carry = _mm_srli_epi64(hi, 63);
        carry = _mm_slli_si128(carry, 8);
        hi = _mm_or_si128(_mm_slli_epi64(hi, 1), carry);
    }
    hi = _mm_or_si128(hi, lo_carry_top);
    {
        __m128i carry = _mm_srli_epi64(lo, 63);
        carry = _mm_slli_si128(carry, 8);
        lo = _mm_or_si128(_mm_slli_epi64(lo, 1), carry);
    }

    __m128i A = _mm_slli_epi64(lo, 63);
    __m128i B = _mm_slli_epi64(lo, 62);
    __m128i C = _mm_slli_epi64(lo, 57);
    __m128i D = _mm_xor_si128(A, _mm_xor_si128(B, C));
    lo = _mm_xor_si128(lo, _mm_slli_si128(D, 8));

    __m128i E = _mm_srli_epi64(lo, 1);
    __m128i F = _mm_srli_epi64(lo, 2);
    __m128i G = _mm_srli_epi64(lo, 7);
    __m128i result = _mm_xor_si128(hi, lo);
    result = _mm_xor_si128(result, E);
    result = _mm_xor_si128(result, F);
    result = _mm_xor_si128(result, G);
    result = _mm_xor_si128(result, _mm_srli_si128(D, 8));

    return bswap128(result);
}

/* Multiply two GCM-domain values and return reduced GHASH product. */
static inline __m128i ghash_mul_full(__m128i a_gcm, __m128i b_gcm) {
    __m128i hi, mid;
    __m128i lo = ghash_mul_raw_lo(a_gcm, b_gcm, &hi, &mid);
    return ghash_reduce(lo, hi, mid);
}

/* ============================================================================
 * 4-lane Karatsuba GHASH using YMM VPCLMULQDQ (_mm256_clmulepi64_epi128).
 *
 * Stage-2 widen (2026-04, this PR): folds 4 GHASH lanes with 8 YMM
 * carry-less multiplies instead of 16 XMM ones.  Intrinsic
 * _mm256_clmulepi64_epi128 applies the imm8 selector independently to
 * each 128-bit lane of the YMM operand pair, so packing two (block,H)
 * lane-pairs per YMM gives the same algebra as the XMM version with
 * half the CLMUL count.
 *
 * Inputs are in GCM-native byte order (XMM).  Packing:
 *
 *     a_pair0 = [ x0 | ct1 ]       b_pair0 = [ H4 | H3 ]
 *     a_pair1 = [ ct2| ct3 ]       b_pair1 = [ H2 | H  ]
 *
 * After byte-reversing both pairs (YMM shuffle with a broadcast
 * bswap mask) we issue the 4 Karatsuba imm variants per pair, XOR
 * across pairs, and horizontally fold the two 128-bit lanes of each
 * resulting YMM into one XMM triple.  That XMM triple is the exact
 * aggregate the original XMM path produced, so the downstream
 * ghash_reduce() is reused unchanged and byte-identity with the
 * AES-NI reference is preserved (verified by the 2132-trial
 * equivalence test in tests/c/test_aes_gcm_vaes_equiv.c).
 *
 * The Montgomery reduction itself stays XMM: the high-bit shifts
 * 57/62/63 and 1/2/7 are intrinsically scalar across the 128-bit
 * polynomial, so widening the reduction past XMM yields no benefit.
 * ============================================================================ */
static const union {
    uint8_t bytes[32];
    __m256i v;
} bswap_mask256 = {
    .bytes = {
        15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0,
        15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0
    }
};

static inline __m256i bswap256(__m256i v) {
    return _mm256_shuffle_epi8(v, bswap_mask256.v);
}

static inline __m256i pack_pair_ymm(__m128i lane0, __m128i lane1) {
    return _mm256_inserti128_si256(_mm256_castsi128_si256(lane0), lane1, 1);
}

static inline __m128i fold_ymm_to_xmm(__m256i v) {
    return _mm_xor_si128(_mm256_castsi256_si128(v),
                          _mm256_extracti128_si256(v, 1));
}

/* YMM Karatsuba: (a_p0,b_p0) and (a_p1,b_p1) each cover 2 GHASH lanes.
 * Output is the cross-lane-summed {lo, hi, mid} triple in XMM, ready
 * for ghash_reduce(). */
static inline void ghash_mul_4lanes_ymm(
    __m128i x0_gcm, __m128i c1_gcm, __m128i c2_gcm, __m128i c3_gcm,
    __m128i H4_gcm, __m128i H3_gcm, __m128i H2_gcm, __m128i H_gcm,
    __m128i *out_lo, __m128i *out_hi, __m128i *out_mid)
{
    __m256i a_p0 = bswap256(pack_pair_ymm(x0_gcm,  c1_gcm));
    __m256i b_p0 = bswap256(pack_pair_ymm(H4_gcm,  H3_gcm));
    __m256i a_p1 = bswap256(pack_pair_ymm(c2_gcm,  c3_gcm));
    __m256i b_p1 = bswap256(pack_pair_ymm(H2_gcm,  H_gcm));

    __m256i lo_p0   = _mm256_clmulepi64_epi128(a_p0, b_p0, 0x00);
    __m256i hi_p0   = _mm256_clmulepi64_epi128(a_p0, b_p0, 0x11);
    __m256i m1_p0   = _mm256_clmulepi64_epi128(a_p0, b_p0, 0x01);
    __m256i m2_p0   = _mm256_clmulepi64_epi128(a_p0, b_p0, 0x10);

    __m256i lo_p1   = _mm256_clmulepi64_epi128(a_p1, b_p1, 0x00);
    __m256i hi_p1   = _mm256_clmulepi64_epi128(a_p1, b_p1, 0x11);
    __m256i m1_p1   = _mm256_clmulepi64_epi128(a_p1, b_p1, 0x01);
    __m256i m2_p1   = _mm256_clmulepi64_epi128(a_p1, b_p1, 0x10);

    __m256i lo_sum  = _mm256_xor_si256(lo_p0, lo_p1);
    __m256i hi_sum  = _mm256_xor_si256(hi_p0, hi_p1);
    __m256i mid_sum = _mm256_xor_si256(_mm256_xor_si256(m1_p0, m2_p0),
                                        _mm256_xor_si256(m1_p1, m2_p1));

    *out_lo  = fold_ymm_to_xmm(lo_sum);
    *out_hi  = fold_ymm_to_xmm(hi_sum);
    *out_mid = fold_ymm_to_xmm(mid_sum);
}

/* ============================================================================
 * Counter-block helpers (32-bit big-endian counter in tail 4 bytes).
 *
 * gcm_inc_counter_xmm advances by 1; the ctr_block_4 helper produces
 * 4 consecutive counter blocks packed two-per-YMM, ready for VAES.
 * ============================================================================ */
static inline __m128i gcm_inc_counter_xmm(__m128i cb) {
    uint8_t buf[16];
    _mm_storeu_si128((__m128i *)buf, cb);
    uint32_t ctr = ((uint32_t)buf[12] << 24) | ((uint32_t)buf[13] << 16) |
                   ((uint32_t)buf[14] << 8)  | ((uint32_t)buf[15]);
    ctr++;
    buf[12] = (uint8_t)(ctr >> 24);
    buf[13] = (uint8_t)(ctr >> 16);
    buf[14] = (uint8_t)(ctr >> 8);
    buf[15] = (uint8_t)(ctr);
    return _mm_loadu_si128((const __m128i *)buf);
}

/* Encrypt 4 counter blocks (cb0..cb3) packed in 2 YMMs through 14 VAES
 * AES-256 rounds.  Round keys are broadcast XMM->YMM once per call by
 * the outer encrypt/decrypt routine. */
static inline void vaes256_encrypt_4blocks(
    __m128i cb0, __m128i cb1, __m128i cb2, __m128i cb3,
    const __m256i rky[15],
    __m128i *ks0, __m128i *ks1, __m128i *ks2, __m128i *ks3)
{
    __m256i a = _mm256_inserti128_si256(_mm256_castsi128_si256(cb0), cb1, 1);
    __m256i b = _mm256_inserti128_si256(_mm256_castsi128_si256(cb2), cb3, 1);

    a = _mm256_xor_si256(a, rky[0]);
    b = _mm256_xor_si256(b, rky[0]);
    /* 13 full rounds + 1 final */
    for (int r = 1; r <= 13; r++) {
        a = _mm256_aesenc_epi128(a, rky[r]);
        b = _mm256_aesenc_epi128(b, rky[r]);
    }
    a = _mm256_aesenclast_epi128(a, rky[14]);
    b = _mm256_aesenclast_epi128(b, rky[14]);

    *ks0 = _mm256_castsi256_si128(a);
    *ks1 = _mm256_extracti128_si256(a, 1);
    *ks2 = _mm256_castsi256_si128(b);
    *ks3 = _mm256_extracti128_si256(b, 1);
}

/* ============================================================================
 * GCM "len(AAD) || len(C)" final block builder.
 * ============================================================================ */
static inline __m128i gcm_len_block(uint64_t aad_len, uint64_t ct_len) {
    uint64_t aad_bits = aad_len * 8;
    uint64_t ct_bits  = ct_len  * 8;
    uint8_t lb[16];
    lb[0]  = (uint8_t)(aad_bits >> 56); lb[1]  = (uint8_t)(aad_bits >> 48);
    lb[2]  = (uint8_t)(aad_bits >> 40); lb[3]  = (uint8_t)(aad_bits >> 32);
    lb[4]  = (uint8_t)(aad_bits >> 24); lb[5]  = (uint8_t)(aad_bits >> 16);
    lb[6]  = (uint8_t)(aad_bits >> 8);  lb[7]  = (uint8_t)(aad_bits);
    lb[8]  = (uint8_t)(ct_bits  >> 56); lb[9]  = (uint8_t)(ct_bits  >> 48);
    lb[10] = (uint8_t)(ct_bits  >> 40); lb[11] = (uint8_t)(ct_bits  >> 32);
    lb[12] = (uint8_t)(ct_bits  >> 24); lb[13] = (uint8_t)(ct_bits  >> 16);
    lb[14] = (uint8_t)(ct_bits  >> 8);  lb[15] = (uint8_t)(ct_bits);
    return _mm_loadu_si128((const __m128i *)lb);
}

/* ============================================================================
 * Process AAD into a GHASH accumulator using single-block PCLMULQDQ.
 * AAD is generally short (<= 64 bytes in practice) so vectorising past
 * single-block does not pay back the setup cost.
 * ============================================================================ */
static inline __m128i ghash_aad(const uint8_t *aad, size_t aad_len, __m128i H) {
    __m128i acc = _mm_setzero_si128();
    size_t n = aad_len / 16;
    for (size_t i = 0; i < n; i++) {
        __m128i blk = _mm_loadu_si128((const __m128i *)(aad + i * 16));
        acc = ghash_mul_xmm(_mm_xor_si128(acc, blk), H);
    }
    size_t tail = aad_len - n * 16;
    if (tail > 0) {
        uint8_t pad[16] = {0};
        memcpy(pad, aad + n * 16, tail);
        __m128i blk = _mm_loadu_si128((const __m128i *)pad);
        acc = ghash_mul_xmm(_mm_xor_si128(acc, blk), H);
    }
    return acc;
}

/* ============================================================================
 * Public entry — VAES AES-256-GCM encrypt.
 *
 * Signature matches ama_aes256_gcm_encrypt_avx2 so it can be plugged
 * into ama_dispatch_table.aes_gcm_encrypt one-for-one.  Prototype
 * lives in src/c/avx2/ama_avx2_internal.h.
 * ============================================================================ */
void ama_aes256_gcm_encrypt_vaes_avx2(
    const uint8_t *plaintext, size_t plaintext_len,
    const uint8_t *aad, size_t aad_len,
    const uint8_t key[32], const uint8_t nonce[12],
    uint8_t *ciphertext, uint8_t tag[16])
{
    __m128i rk[15];
    ama_aes256_expand_key_avx2(key, rk);

    /* Broadcast each round key XMM -> YMM (used by the 4-way VAES path). */
    __m256i rky[15];
    for (int i = 0; i < 15; i++) {
        rky[i] = _mm256_broadcastsi128_si256(rk[i]);
    }

    /* H = AES_K(0^128), GCM-domain. */
    __m128i H  = aes256_encrypt_block_xmm(_mm_setzero_si128(), rk);
    __m128i H2 = ghash_mul_full(H,  H);
    __m128i H3 = ghash_mul_full(H2, H);
    __m128i H4 = ghash_mul_full(H3, H);

    /* J0 = nonce || 0x00000001; counter starts at J0+1. */
    uint8_t j0_buf[16];
    memcpy(j0_buf, nonce, 12);
    j0_buf[12] = 0; j0_buf[13] = 0; j0_buf[14] = 0; j0_buf[15] = 1;
    __m128i J0 = _mm_loadu_si128((const __m128i *)j0_buf);
    __m128i cb = gcm_inc_counter_xmm(J0);

    __m128i ghash_acc = ghash_aad(aad, aad_len, H);

    size_t full_blocks = plaintext_len / 16;
    size_t i = 0;

    /* 4-block parallel inner loop. */
    while (i + 4 <= full_blocks) {
        __m128i cb0 = cb; cb = gcm_inc_counter_xmm(cb);
        __m128i cb1 = cb; cb = gcm_inc_counter_xmm(cb);
        __m128i cb2 = cb; cb = gcm_inc_counter_xmm(cb);
        __m128i cb3 = cb; cb = gcm_inc_counter_xmm(cb);

        __m128i ks0, ks1, ks2, ks3;
        vaes256_encrypt_4blocks(cb0, cb1, cb2, cb3, rky, &ks0, &ks1, &ks2, &ks3);

        __m128i ct0 = _mm_xor_si128(ks0, _mm_loadu_si128((const __m128i *)(plaintext + (i+0)*16)));
        __m128i ct1 = _mm_xor_si128(ks1, _mm_loadu_si128((const __m128i *)(plaintext + (i+1)*16)));
        __m128i ct2 = _mm_xor_si128(ks2, _mm_loadu_si128((const __m128i *)(plaintext + (i+2)*16)));
        __m128i ct3 = _mm_xor_si128(ks3, _mm_loadu_si128((const __m128i *)(plaintext + (i+3)*16)));

        _mm_storeu_si128((__m128i *)(ciphertext + (i+0)*16), ct0);
        _mm_storeu_si128((__m128i *)(ciphertext + (i+1)*16), ct1);
        _mm_storeu_si128((__m128i *)(ciphertext + (i+2)*16), ct2);
        _mm_storeu_si128((__m128i *)(ciphertext + (i+3)*16), ct3);

        /* Aggregate-then-reduce 4-lane GHASH:
         *   ((acc ^ C0) * H^4) ^ (C1 * H^3) ^ (C2 * H^2) ^ (C3 * H^1)
         * Implemented with YMM VPCLMULQDQ — two lane-pairs per YMM,
         * 8 _mm256_clmulepi64_epi128 ops per 4 blocks instead of 16
         * XMM ops.  Montgomery reduction stays XMM (intrinsically
         * scalar in the high bits). */
        __m128i x0 = _mm_xor_si128(ghash_acc, ct0);
        __m128i lo, hi, mid;
        ghash_mul_4lanes_ymm(x0, ct1, ct2, ct3,
                              H4, H3, H2, H,
                              &lo, &hi, &mid);
        ghash_acc = ghash_reduce(lo, hi, mid);

        i += 4;
    }

    /* Trailing full blocks (< 4 left). */
    for (; i < full_blocks; i++) {
        __m128i ks = aes256_encrypt_block_xmm(cb, rk);
        cb = gcm_inc_counter_xmm(cb);
        __m128i pt = _mm_loadu_si128((const __m128i *)(plaintext + i * 16));
        __m128i ct = _mm_xor_si128(ks, pt);
        _mm_storeu_si128((__m128i *)(ciphertext + i * 16), ct);
        ghash_acc = ghash_mul_xmm(_mm_xor_si128(ghash_acc, ct), H);
    }

    /* Trailing partial block. */
    size_t remaining = plaintext_len - full_blocks * 16;
    if (remaining > 0) {
        __m128i ks = aes256_encrypt_block_xmm(cb, rk);
        uint8_t pad_pt[16] = {0}, pad_ct[16] = {0};
        memcpy(pad_pt, plaintext + full_blocks * 16, remaining);
        __m128i pt_block = _mm_loadu_si128((const __m128i *)pad_pt);
        __m128i ct_block = _mm_xor_si128(ks, pt_block);
        _mm_storeu_si128((__m128i *)pad_ct, ct_block);
        memcpy(ciphertext + full_blocks * 16, pad_ct, remaining);

        memset(pad_ct + remaining, 0, 16 - remaining);
        ct_block = _mm_loadu_si128((const __m128i *)pad_ct);
        ghash_acc = ghash_mul_xmm(_mm_xor_si128(ghash_acc, ct_block), H);
    }

    /* Length block + tag. */
    __m128i len_blk = gcm_len_block((uint64_t)aad_len, (uint64_t)plaintext_len);
    ghash_acc = ghash_mul_xmm(_mm_xor_si128(ghash_acc, len_blk), H);

    __m128i enc_j0 = aes256_encrypt_block_xmm(J0, rk);
    __m128i tag_val = _mm_xor_si128(ghash_acc, enc_j0);
    _mm_storeu_si128((__m128i *)tag, tag_val);

    /* Scrub key material from stack. */
    ama_secure_memzero(rk,  sizeof(rk));
    ama_secure_memzero(rky, sizeof(rky));
    /* Zero the AVX upper halves to avoid an SSE/AVX transition penalty
     * for the next caller running in the legacy SSE register file. */
    _mm256_zeroupper();
}

/* ============================================================================
 * Public entry — VAES AES-256-GCM decrypt with constant-time tag verify.
 * Prototype in src/c/avx2/ama_avx2_internal.h.
 * ============================================================================ */
ama_error_t ama_aes256_gcm_decrypt_vaes_avx2(
    const uint8_t *ciphertext, size_t ciphertext_len,
    const uint8_t *aad, size_t aad_len,
    const uint8_t key[32], const uint8_t nonce[12],
    const uint8_t tag[16], uint8_t *plaintext)
{
    __m128i rk[15];
    ama_aes256_expand_key_avx2(key, rk);

    __m256i rky[15];
    for (int i = 0; i < 15; i++) {
        rky[i] = _mm256_broadcastsi128_si256(rk[i]);
    }

    __m128i H  = aes256_encrypt_block_xmm(_mm_setzero_si128(), rk);
    __m128i H2 = ghash_mul_full(H,  H);
    __m128i H3 = ghash_mul_full(H2, H);
    __m128i H4 = ghash_mul_full(H3, H);

    uint8_t j0_buf[16];
    memcpy(j0_buf, nonce, 12);
    j0_buf[12] = 0; j0_buf[13] = 0; j0_buf[14] = 0; j0_buf[15] = 1;
    __m128i J0 = _mm_loadu_si128((const __m128i *)j0_buf);

    /* Compute tag over ciphertext+AAD BEFORE writing any plaintext. */
    __m128i ghash_acc = ghash_aad(aad, aad_len, H);

    size_t full_blocks = ciphertext_len / 16;
    size_t i = 0;

    while (i + 4 <= full_blocks) {
        __m128i ct0 = _mm_loadu_si128((const __m128i *)(ciphertext + (i+0)*16));
        __m128i ct1 = _mm_loadu_si128((const __m128i *)(ciphertext + (i+1)*16));
        __m128i ct2 = _mm_loadu_si128((const __m128i *)(ciphertext + (i+2)*16));
        __m128i ct3 = _mm_loadu_si128((const __m128i *)(ciphertext + (i+3)*16));

        /* YMM VPCLMULQDQ 4-lane GHASH fold (stage-2 widen). */
        __m128i x0 = _mm_xor_si128(ghash_acc, ct0);
        __m128i lo, hi, mid;
        ghash_mul_4lanes_ymm(x0, ct1, ct2, ct3,
                              H4, H3, H2, H,
                              &lo, &hi, &mid);
        ghash_acc = ghash_reduce(lo, hi, mid);

        i += 4;
    }
    for (; i < full_blocks; i++) {
        __m128i ct = _mm_loadu_si128((const __m128i *)(ciphertext + i * 16));
        ghash_acc = ghash_mul_xmm(_mm_xor_si128(ghash_acc, ct), H);
    }
    size_t remaining = ciphertext_len - full_blocks * 16;
    if (remaining > 0) {
        uint8_t pad_ct[16] = {0};
        memcpy(pad_ct, ciphertext + full_blocks * 16, remaining);
        __m128i ct = _mm_loadu_si128((const __m128i *)pad_ct);
        ghash_acc = ghash_mul_xmm(_mm_xor_si128(ghash_acc, ct), H);
    }

    __m128i len_blk = gcm_len_block((uint64_t)aad_len, (uint64_t)ciphertext_len);
    ghash_acc = ghash_mul_xmm(_mm_xor_si128(ghash_acc, len_blk), H);

    __m128i enc_j0 = aes256_encrypt_block_xmm(J0, rk);
    __m128i computed_tag = _mm_xor_si128(ghash_acc, enc_j0);

    /* Constant-time tag compare — INVARIANT-12. */
    uint8_t computed_tag_bytes[16];
    _mm_storeu_si128((__m128i *)computed_tag_bytes, computed_tag);
    if (ama_consttime_memcmp(computed_tag_bytes, tag, 16) != 0) {
        ama_secure_memzero(rk, sizeof(rk));
        ama_secure_memzero(rky, sizeof(rky));
        ama_secure_memzero(computed_tag_bytes, sizeof(computed_tag_bytes));
        _mm256_zeroupper();
        return AMA_ERROR_VERIFY_FAILED;
    }

    /* Tag verified — decrypt via CTR mode (4-way pipelined). */
    __m128i cb = gcm_inc_counter_xmm(J0);
    i = 0;
    while (i + 4 <= full_blocks) {
        __m128i cb0 = cb; cb = gcm_inc_counter_xmm(cb);
        __m128i cb1 = cb; cb = gcm_inc_counter_xmm(cb);
        __m128i cb2 = cb; cb = gcm_inc_counter_xmm(cb);
        __m128i cb3 = cb; cb = gcm_inc_counter_xmm(cb);

        __m128i ks0, ks1, ks2, ks3;
        vaes256_encrypt_4blocks(cb0, cb1, cb2, cb3, rky, &ks0, &ks1, &ks2, &ks3);

        __m128i pt0 = _mm_xor_si128(ks0, _mm_loadu_si128((const __m128i *)(ciphertext + (i+0)*16)));
        __m128i pt1 = _mm_xor_si128(ks1, _mm_loadu_si128((const __m128i *)(ciphertext + (i+1)*16)));
        __m128i pt2 = _mm_xor_si128(ks2, _mm_loadu_si128((const __m128i *)(ciphertext + (i+2)*16)));
        __m128i pt3 = _mm_xor_si128(ks3, _mm_loadu_si128((const __m128i *)(ciphertext + (i+3)*16)));

        _mm_storeu_si128((__m128i *)(plaintext + (i+0)*16), pt0);
        _mm_storeu_si128((__m128i *)(plaintext + (i+1)*16), pt1);
        _mm_storeu_si128((__m128i *)(plaintext + (i+2)*16), pt2);
        _mm_storeu_si128((__m128i *)(plaintext + (i+3)*16), pt3);

        i += 4;
    }
    for (; i < full_blocks; i++) {
        __m128i ks = aes256_encrypt_block_xmm(cb, rk);
        cb = gcm_inc_counter_xmm(cb);
        __m128i ct = _mm_loadu_si128((const __m128i *)(ciphertext + i * 16));
        _mm_storeu_si128((__m128i *)(plaintext + i * 16), _mm_xor_si128(ks, ct));
    }
    if (remaining > 0) {
        __m128i ks = aes256_encrypt_block_xmm(cb, rk);
        uint8_t pad_ct[16] = {0}, pad_pt[16] = {0};
        memcpy(pad_ct, ciphertext + full_blocks * 16, remaining);
        __m128i ct = _mm_loadu_si128((const __m128i *)pad_ct);
        __m128i pt = _mm_xor_si128(ks, ct);
        _mm_storeu_si128((__m128i *)pad_pt, pt);
        memcpy(plaintext + full_blocks * 16, pad_pt, remaining);
    }

    ama_secure_memzero(rk,  sizeof(rk));
    ama_secure_memzero(rky, sizeof(rky));
    ama_secure_memzero(computed_tag_bytes, sizeof(computed_tag_bytes));
    _mm256_zeroupper();
    return AMA_SUCCESS;
}

#else
typedef int ama_aes_gcm_vaes_avx2_not_x86_64;
#endif /* _MSC_VER / __x86_64__ / _M_X64 */
