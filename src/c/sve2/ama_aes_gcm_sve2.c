/**
 * Copyright 2025-2026 Steel Security Advisors LLC
 * Licensed under the Apache License, Version 2.0
 *
 * @file ama_aes_gcm_sve2.c
 * @brief ARM SVE2-optimized AES-256-GCM stub
 *
 * SVE2 does not provide AES instructions directly; those come from the
 * ARMv8 Crypto Extensions (FEAT_AES). This file provides SVE2-accelerated
 * helper functions that complement the NEON AES-GCM implementation,
 * such as vectorized XOR and GHASH table computation.
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

/* ============================================================================
 * GF(2^128) multiplication for GHASH
 *
 * Schoolbook carry-less multiplication with reduction modulo the GCM
 * irreducible polynomial x^128 + x^7 + x^2 + x + 1 (R = 0xe1 || 0^120
 * in the bit-reflected representation used by GCM).
 *
 * Constant-time with respect to operand values: the mask trick ensures
 * no secret-dependent branches or memory accesses.
 * ============================================================================ */
static void ghash_mul_gf128(const uint8_t X[16], const uint8_t Y[16],
                             uint8_t out[16]) {
    uint8_t V[16];
    uint8_t Z[16];

    memcpy(V, Y, 16);
    memset(Z, 0, 16);

    for (int i = 0; i < 16; i++) {
        for (int j = 7; j >= 0; j--) {
            /* If bit (i*8 + (7-j)) of X is set, Z ^= V */
            uint8_t mask = (uint8_t)(-(int8_t)((X[i] >> j) & 1));
            for (int k = 0; k < 16; k++)
                Z[k] ^= V[k] & mask;

            /* V >>= 1 in GF(2^128); if old LSB was 1, XOR R = 0xe1 || 0^120 */
            uint8_t lsb = V[15] & 1;
            for (int k = 15; k > 0; k--)
                V[k] = (uint8_t)((V[k] >> 1) | (V[k-1] << 7));
            V[0] >>= 1;
            V[0] ^= (uint8_t)(0xe1 & (-(int)lsb));
        }
    }

    memcpy(out, Z, 16);
}

/* ============================================================================
 * SVE2-accelerated GHASH precomputation
 *
 * Precomputes H^1, H^2, H^3, H^4 powers for 4-way Karatsuba GHASH.
 * Uses the schoolbook GF(2^128) multiply above; a future optimisation may
 * replace this with PMULL/PMULL2 from the ARMv8 Crypto Extensions.
 * ============================================================================ */
void ama_ghash_precompute_sve2(const uint8_t H[16],
                                uint8_t H_powers[4][16]) {
    /* H^1 = H */
    memcpy(H_powers[0], H, 16);

    /* H^2 = H*H, H^3 = H^2*H, H^4 = H^3*H */
    for (int i = 1; i < 4; i++) {
        ghash_mul_gf128(H_powers[i-1], H, H_powers[i]);
    }
}

#else
typedef int ama_aes_gcm_sve2_not_available;
#endif /* __ARM_FEATURE_SVE2 */
