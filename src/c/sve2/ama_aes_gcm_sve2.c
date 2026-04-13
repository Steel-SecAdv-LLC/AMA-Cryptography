/**
 * Copyright 2025-2026 Steel Security Advisors LLC
 * Licensed under the Apache License, Version 2.0
 *
 * @file ama_aes_gcm_sve2.c
 * @brief ARM SVE2-optimized AES-256-GCM helpers with proper GHASH
 *
 * SVE2 does not provide AES instructions directly; those come from the
 * ARMv8 Crypto Extensions (FEAT_AES). This file provides SVE2-accelerated
 * helper functions that complement the NEON AES-GCM implementation:
 *   - Vectorized bulk XOR for CTR mode keystream application
 *   - Proper GF(2^128) carry-less multiplication using PMULL/PMULL2
 *     instructions from the ARMv8 Crypto Extensions (FEAT_PMULL)
 *   - GHASH precomputation of H^1..H^4 power table
 *
 * The GHASH multiply implements correct GF(2^128) polynomial multiplication
 * and reduction modulo the GCM polynomial (x^128 + x^7 + x^2 + x + 1)
 * using Karatsuba decomposition and the Intel/ARM standard two-phase
 * reduction algorithm.
 *
 * Constant-time: all operations are data-independent (no secret-dependent
 * branches or memory access patterns).
 *
 * AI Co-Architects: Eris + | Eden ~ | Devin * | Claude @
 */

#include <stdint.h>
#include <stddef.h>
#include <string.h>

#if defined(__ARM_FEATURE_SVE2)
#include <arm_sve.h>

/* ============================================================================
 * SVE2-accelerated bulk XOR (for CTR mode keystream application)
 *
 * XORs `len` bytes from `src` with `keystream` into `dst`.
 * Uses SVE2's scalable vectors for maximum throughput.
 * ============================================================================ */
void ama_bulk_xor_sve2(uint8_t *dst, const uint8_t *src,
                        const uint8_t *keystream, size_t len) {
    size_t i = 0;
    while (i < len) {
        svbool_t pg = svwhilelt_b8((int64_t)i, (int64_t)len);
        svuint8_t vs = svld1_u8(pg, src + i);
        svuint8_t vk = svld1_u8(pg, keystream + i);
        svst1_u8(pg, dst + i, sveor_u8_x(pg, vs, vk));
        i += svcntb();
    }
}

#endif /* __ARM_FEATURE_SVE2 */

/* ============================================================================
 * PMULL-based GF(2^128) GHASH implementation
 *
 * Uses ARMv8 Crypto Extensions PMULL/PMULL2 (FEAT_PMULL) for carry-less
 * multiplication, available on all AArch64 cores with crypto extensions.
 * This is independent of SVE2 but co-located here because it complements
 * the SVE2 bulk XOR for AES-GCM on ARM platforms.
 *
 * The implementation follows the same Karatsuba + two-phase reduction
 * pattern used in the AVX2 PCLMULQDQ path (ama_aes_gcm_avx2.c).
 *
 * GCM polynomial (reflected): x^128 + x^127 + x^126 + x^121 + 1
 * Standard form: x^128 + x^7 + x^2 + x + 1
 * ============================================================================ */

#if defined(__aarch64__) && defined(__ARM_FEATURE_CRYPTO)
#include <arm_neon.h>

/**
 * Byte-reverse a 128-bit NEON register.
 *
 * GCM uses big-endian (reflected-bit) ordering while PMULL operates in
 * natural bit ordering. All GHASH operands must be byte-swapped when
 * crossing the GCM<->PMULL domain boundary.
 */
static inline uint8x16_t bswap128_neon(uint8x16_t v) {
    return vrev64q_u8(vextq_u8(v, v, 8));
}

/**
 * Shift a 128-bit value left by 1 bit (cross-lane safe).
 * Equivalent to the x86 sll128_1 helper in ama_aes_gcm_avx2.c.
 */
static inline uint64x2_t sll128_1_neon(uint64x2_t v) {
    /* Extract bit 63 of each lane as carry */
    uint64x2_t carry = vshrq_n_u64(v, 63);
    /* Move lo-lane carry into hi-lane position */
    carry = vextq_u64(vdupq_n_u64(0), carry, 1);
    /* Shift each lane left by 1 and OR with carry */
    return vorrq_u64(vshlq_n_u64(v, 1), carry);
}

/**
 * GF(2^128) multiply using PMULL (Karatsuba + two-phase reduction).
 *
 * Inputs and output are in GCM native byte order (big-endian, reflected-bit).
 * Internally byte-swaps into PMULL little-endian domain, performs Karatsuba
 * carry-less multiplication, corrects for the reflected-bit 1-bit left shift,
 * and reduces modulo the reflected GCM polynomial x^128+x^127+x^126+x^121+1
 * using the standard two-phase algorithm (matching Intel whitepaper Algorithm 5
 * and ARM's recommended GHASH implementation).
 *
 * Constant-time: no secret-dependent branches or memory accesses.
 */
static inline uint8x16_t ghash_mul_pmull(uint8x16_t a_gcm, uint8x16_t b_gcm) {
    /* Byte-swap into PMULL (little-endian) domain */
    uint8x16_t a8 = bswap128_neon(a_gcm);
    uint8x16_t b8 = bswap128_neon(b_gcm);

    /* Reinterpret as poly128 operands for PMULL */
    poly64x2_t a = vreinterpretq_p64_u8(a8);
    poly64x2_t b = vreinterpretq_p64_u8(b8);

    /* Karatsuba decomposition: 3 carry-less multiplications
     * lo = a_lo * b_lo  (PMULL, selecting low 64-bit halves)
     * hi = a_hi * b_hi  (PMULL2, selecting high 64-bit halves)
     * mid = (a_lo * b_hi) XOR (a_hi * b_lo)
     */
    /* PMULL:  multiply low 64-bit halves -> 128-bit result */
    poly128_t lo_p = vmull_p64(
        vget_low_p64(a),
        vget_low_p64(b)
    );
    /* PMULL2: multiply high 64-bit halves -> 128-bit result */
    poly128_t hi_p = vmull_high_p64(a, b);
    /* Cross terms for Karatsuba middle */
    poly128_t mid1_p = vmull_p64(
        vget_low_p64(a),
        vget_high_p64(b)
    );
    poly128_t mid2_p = vmull_p64(
        vget_high_p64(a),
        vget_low_p64(b)
    );

    uint64x2_t lo  = vreinterpretq_u64_p128(lo_p);
    uint64x2_t hi  = vreinterpretq_u64_p128(hi_p);
    uint64x2_t mid = veorq_u64(
        vreinterpretq_u64_p128(mid1_p),
        vreinterpretq_u64_p128(mid2_p)
    );

    /* Fold middle term into lo and hi:
     * lo ^= mid << 64  (mid's low 64 bits go into lo's high lane)
     * hi ^= mid >> 64  (mid's high 64 bits go into hi's low lane) */
    lo = veorq_u64(lo, vextq_u64(vdupq_n_u64(0), mid, 1));
    hi = veorq_u64(hi, vextq_u64(mid, vdupq_n_u64(0), 1));

    /* PMULL on byte-swapped (reflected) data produces a product that is
     * shifted left by 1 bit. Correct by shifting the full 256-bit
     * [hi:lo] left by 1, propagating carry from lo[127] into hi[0]. */
    uint64x2_t lo_msb = vshrq_n_u64(lo, 63);
    uint64x2_t hi_carry = vextq_u64(vdupq_n_u64(0), lo_msb, 1);
    hi = vorrq_u64(sll128_1_neon(hi), hi_carry);
    lo = sll128_1_neon(lo);

    /* Modular reduction of [hi:lo] mod x^128+x^127+x^126+x^121+1
     * (reflected GCM polynomial). Two-phase algorithm matching
     * Intel whitepaper Algorithm 5 / ARM recommended implementation.
     *
     * Phase 1: Fold lo into itself using the polynomial bits */
    uint64x2_t A = vshlq_n_u64(lo, 63);
    uint64x2_t B = vshlq_n_u64(lo, 62);
    uint64x2_t C = vshlq_n_u64(lo, 57);
    uint64x2_t D = veorq_u64(A, veorq_u64(B, C));
    lo = veorq_u64(lo, vextq_u64(vdupq_n_u64(0), D, 1));

    /* Phase 2: Reduce into final 128-bit result */
    uint64x2_t E = vshrq_n_u64(lo, 1);
    uint64x2_t F = vshrq_n_u64(lo, 2);
    uint64x2_t G = vshrq_n_u64(lo, 7);
    uint64x2_t result = veorq_u64(hi, lo);
    result = veorq_u64(result, E);
    result = veorq_u64(result, F);
    result = veorq_u64(result, G);
    result = veorq_u64(result, vextq_u64(D, vdupq_n_u64(0), 1));

    /* Byte-swap back to GCM native order */
    return bswap128_neon(vreinterpretq_u8_u64(result));
}

/**
 * Precompute H^1, H^2, H^3, H^4 powers for 4-way GHASH.
 *
 * H is the GHASH key (AES_K(0^128)) in GCM native byte order.
 * Each H_powers[i] = H^(i+1) in GF(2^128), computed via proper
 * carry-less multiplication and polynomial reduction.
 *
 * Constant-time: no secret-dependent branches.
 */
void ama_ghash_precompute_sve2(const uint8_t H[16],
                                uint8_t H_powers[4][16]) {
    /* H^1 = H */
    memcpy(H_powers[0], H, 16);

    /* Load H into NEON register for PMULL operations */
    uint8x16_t h_vec = vld1q_u8(H);

    /* H^2 = H * H in GF(2^128) */
    uint8x16_t h2 = ghash_mul_pmull(h_vec, h_vec);
    vst1q_u8(H_powers[1], h2);

    /* H^3 = H^2 * H in GF(2^128) */
    uint8x16_t h3 = ghash_mul_pmull(h2, h_vec);
    vst1q_u8(H_powers[2], h3);

    /* H^4 = H^2 * H^2 in GF(2^128) (or H^3 * H) */
    uint8x16_t h4 = ghash_mul_pmull(h2, h2);
    vst1q_u8(H_powers[3], h4);
}

#else
/* Fallback: no PMULL support available */
typedef int ama_aes_gcm_sve2_pmull_not_available;
#endif /* __aarch64__ && __ARM_FEATURE_CRYPTO */
