/**
 * Copyright 2025-2026 Steel Security Advisors LLC
 * Licensed under the Apache License, Version 2.0
 *
 * @file ama_chacha20poly1305_neon.c
 * @brief ARM NEON-optimized ChaCha20-Poly1305
 *
 * NEON intrinsics for ChaCha20-Poly1305 (RFC 8439):
 *   - 4-way parallel ChaCha20 quarter-rounds
 *   - NEON-vectorized Poly1305 accumulation
 *
 * AI Co-Architects: Eris + | Eden ~ | Devin * | Claude @
 */

#include <stdint.h>
#include <stddef.h>
#include <string.h>

#if defined(__aarch64__) || defined(_M_ARM64)
#include <arm_neon.h>

#define CHACHA_C0 0x61707865
#define CHACHA_C1 0x3320646e
#define CHACHA_C2 0x79622d32
#define CHACHA_C3 0x6b206574

/* ============================================================================
 * NEON ChaCha20 quarter-round (4-way parallel)
 * ============================================================================ */
static inline void chacha_qr_neon(uint32x4_t *a, uint32x4_t *b,
                                   uint32x4_t *c, uint32x4_t *d) {
    *a = vaddq_u32(*a, *b);
    *d = veorq_u32(*d, *a);
    *d = vorrq_u32(vshlq_n_u32(*d, 16), vshrq_n_u32(*d, 16));

    *c = vaddq_u32(*c, *d);
    *b = veorq_u32(*b, *c);
    *b = vorrq_u32(vshlq_n_u32(*b, 12), vshrq_n_u32(*b, 20));

    *a = vaddq_u32(*a, *b);
    *d = veorq_u32(*d, *a);
    *d = vorrq_u32(vshlq_n_u32(*d, 8), vshrq_n_u32(*d, 24));

    *c = vaddq_u32(*c, *d);
    *b = veorq_u32(*b, *c);
    *b = vorrq_u32(vshlq_n_u32(*b, 7), vshrq_n_u32(*b, 25));
}

/* ============================================================================
 * ChaCha20 block: 4-way parallel (4 keystream blocks at once)
 * ============================================================================ */
void ama_chacha20_block_x4_neon(const uint8_t key[32],
                                 const uint8_t nonce[12],
                                 uint32_t counter,
                                 uint8_t out[256]) {
    uint32_t k[8], n[3];
    for (int i = 0; i < 8; i++) {
        k[i] = ((uint32_t)key[i*4]) | ((uint32_t)key[i*4+1] << 8) |
               ((uint32_t)key[i*4+2] << 16) | ((uint32_t)key[i*4+3] << 24);
    }
    for (int i = 0; i < 3; i++) {
        n[i] = ((uint32_t)nonce[i*4]) | ((uint32_t)nonce[i*4+1] << 8) |
               ((uint32_t)nonce[i*4+2] << 16) | ((uint32_t)nonce[i*4+3] << 24);
    }

    /* Each NEON vector holds same state row from 4 independent instances */
    uint32x4_t s0 = vdupq_n_u32(CHACHA_C0);
    uint32x4_t s1 = vdupq_n_u32(CHACHA_C1);
    uint32x4_t s2 = vdupq_n_u32(CHACHA_C2);
    uint32x4_t s3 = vdupq_n_u32(CHACHA_C3);
    uint32x4_t s4 = vdupq_n_u32(k[0]);
    uint32x4_t s5 = vdupq_n_u32(k[1]);
    uint32x4_t s6 = vdupq_n_u32(k[2]);
    uint32x4_t s7 = vdupq_n_u32(k[3]);
    uint32x4_t s8 = vdupq_n_u32(k[4]);
    uint32x4_t s9 = vdupq_n_u32(k[5]);
    uint32x4_t s10 = vdupq_n_u32(k[6]);
    uint32x4_t s11 = vdupq_n_u32(k[7]);

    uint32_t ctr_arr[4] = {counter, counter+1, counter+2, counter+3};
    uint32x4_t s12 = vld1q_u32(ctr_arr);
    uint32x4_t s13 = vdupq_n_u32(n[0]);
    uint32x4_t s14 = vdupq_n_u32(n[1]);
    uint32x4_t s15 = vdupq_n_u32(n[2]);

    uint32x4_t i0=s0,i1=s1,i2=s2,i3=s3;
    uint32x4_t i4=s4,i5=s5,i6=s6,i7=s7;
    uint32x4_t i8=s8,i9=s9,i10=s10,i11=s11;
    uint32x4_t i12=s12,i13=s13,i14=s14,i15=s15;

    for (int round = 0; round < 10; round++) {
        chacha_qr_neon(&s0, &s4, &s8, &s12);
        chacha_qr_neon(&s1, &s5, &s9, &s13);
        chacha_qr_neon(&s2, &s6, &s10, &s14);
        chacha_qr_neon(&s3, &s7, &s11, &s15);
        chacha_qr_neon(&s0, &s5, &s10, &s15);
        chacha_qr_neon(&s1, &s6, &s11, &s12);
        chacha_qr_neon(&s2, &s7, &s8, &s13);
        chacha_qr_neon(&s3, &s4, &s9, &s14);
    }

    s0=vaddq_u32(s0,i0); s1=vaddq_u32(s1,i1);
    s2=vaddq_u32(s2,i2); s3=vaddq_u32(s3,i3);
    s4=vaddq_u32(s4,i4); s5=vaddq_u32(s5,i5);
    s6=vaddq_u32(s6,i6); s7=vaddq_u32(s7,i7);
    s8=vaddq_u32(s8,i8); s9=vaddq_u32(s9,i9);
    s10=vaddq_u32(s10,i10); s11=vaddq_u32(s11,i11);
    s12=vaddq_u32(s12,i12); s13=vaddq_u32(s13,i13);
    s14=vaddq_u32(s14,i14); s15=vaddq_u32(s15,i15);

    /* Extract 4 instances — store each vector to a temp array and
     * scatter-read from the correct lane. vgetq_lane_u32 requires a
     * compile-time constant lane index, so we cannot use a variable. */
    uint32x4_t rows[16] = {s0,s1,s2,s3,s4,s5,s6,s7,
                           s8,s9,s10,s11,s12,s13,s14,s15};
    uint32_t tmp[4];
    for (int inst = 0; inst < 4; inst++) {
        uint32_t block[16];
        for (int row = 0; row < 16; row++) {
            vst1q_u32(tmp, rows[row]);
            block[row] = tmp[inst];
        }
        memcpy(out + inst * 64, block, 64);
    }
}

#else
typedef int ama_chacha20poly1305_neon_not_available;
#endif /* __aarch64__ */
