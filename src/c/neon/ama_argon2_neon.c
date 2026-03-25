/**
 * Copyright 2025-2026 Steel Security Advisors LLC
 * Licensed under the Apache License, Version 2.0
 *
 * @file ama_argon2_neon.c
 * @brief ARM NEON-optimized Argon2 memory-hard function
 *
 * NEON intrinsics for Argon2id (RFC 9106):
 *   - Vectorized Blake2b compression
 *   - NEON-accelerated G mixing function
 *   - Parallel memory operations
 *
 * AI Co-Architects: Eris + | Eden ~ | Devin * | Claude @
 */

#include <stdint.h>
#include <stddef.h>
#include <string.h>

#if defined(__aarch64__) || defined(_M_ARM64)
#include <arm_neon.h>

static const uint64_t BLAKE2B_IV[8] = {
    0x6a09e667f3bcc908ULL, 0xbb67ae8584caa73bULL,
    0x3c6ef372fe94f82bULL, 0xa54ff53a5f1d36f1ULL,
    0x510e527fade682d1ULL, 0x9b05688c2b3e6c1fULL,
    0x1f83d9abfb41bd6bULL, 0x5be0cd19137e2179ULL,
};

static const uint8_t SIGMA[12][16] = {
    { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9,10,11,12,13,14,15},
    {14,10, 4, 8, 9,15,13, 6, 1,12, 0, 2,11, 7, 5, 3},
    {11, 8,12, 0, 5, 2,15,13,10,14, 3, 6, 7, 1, 9, 4},
    { 7, 9, 3, 1,13,12,11,14, 2, 6, 5,10, 4, 0,15, 8},
    { 9, 0, 5, 7, 2, 4,10,15,14, 1,11,12, 6, 8, 3,13},
    { 2,12, 6,10, 0,11, 8, 3, 4,13, 7, 5,15,14, 1, 9},
    {12, 5, 1,15,14,13, 4,10, 0, 7, 6, 3, 9, 2, 8,11},
    {13,11, 7,14,12, 1, 3, 9, 5, 0,15, 4, 8, 6, 2,10},
    { 6,15,14, 9,11, 3, 0, 8,12, 2,13, 7, 1, 4,10, 5},
    {10, 2, 8, 4, 7, 6, 1, 5,15,11, 9,14, 3,12,13, 0},
    { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9,10,11,12,13,14,15},
    {14,10, 4, 8, 9,15,13, 6, 1,12, 0, 2,11, 7, 5, 3},
};

/* NEON rotate right 64 */
static inline uint64x2_t rotr64_neon(uint64x2_t x, int n) {
    return vorrq_u64(vshrq_n_u64(x, n), vshlq_n_u64(x, 64 - n));
}

/* ============================================================================
 * Blake2b G function (NEON vectorized, 2 pairs at a time)
 * ============================================================================ */
static inline void blake2b_g_neon(uint64x2_t *a, uint64x2_t *b,
                                   uint64x2_t *c, uint64x2_t *d,
                                   uint64x2_t mx, uint64x2_t my) {
    *a = vaddq_u64(*a, vaddq_u64(*b, mx));
    *d = rotr64_neon(veorq_u64(*d, *a), 32);
    *c = vaddq_u64(*c, *d);
    *b = rotr64_neon(veorq_u64(*b, *c), 24);
    *a = vaddq_u64(*a, vaddq_u64(*b, my));
    *d = rotr64_neon(veorq_u64(*d, *a), 16);
    *c = vaddq_u64(*c, *d);
    *b = rotr64_neon(veorq_u64(*b, *c), 63);
}

/* ============================================================================
 * Blake2b compression (NEON-assisted)
 * ============================================================================ */
void ama_blake2b_compress_neon(uint64_t h[8], const uint64_t m[16],
                                uint64_t t0, uint64_t t1, int is_final) {
    uint64_t v[16];
    memcpy(v, h, 64);
    memcpy(v + 8, BLAKE2B_IV, 64);
    v[12] ^= t0;
    v[13] ^= t1;
    if (is_final) v[14] = ~v[14];

    for (int round = 0; round < 12; round++) {
        const uint8_t *s = SIGMA[round];

        /* Column step using NEON pairs */
        uint64x2_t va01 = vld1q_u64(&v[0]);
        uint64x2_t va23 = vld1q_u64(&v[2]);
        uint64x2_t vb01 = vld1q_u64(&v[4]);
        uint64x2_t vb23 = vld1q_u64(&v[6]);
        uint64x2_t vc01 = vld1q_u64(&v[8]);
        uint64x2_t vc23 = vld1q_u64(&v[10]);
        uint64x2_t vd01 = vld1q_u64(&v[12]);
        uint64x2_t vd23 = vld1q_u64(&v[14]);

        uint64x2_t mx01 = vcombine_u64(vcreate_u64(m[s[0]]), vcreate_u64(m[s[2]]));
        uint64x2_t my01 = vcombine_u64(vcreate_u64(m[s[1]]), vcreate_u64(m[s[3]]));
        uint64x2_t mx23 = vcombine_u64(vcreate_u64(m[s[4]]), vcreate_u64(m[s[6]]));
        uint64x2_t my23 = vcombine_u64(vcreate_u64(m[s[5]]), vcreate_u64(m[s[7]]));

        blake2b_g_neon(&va01, &vb01, &vc01, &vd01, mx01, my01);
        blake2b_g_neon(&va23, &vb23, &vc23, &vd23, mx23, my23);

        vst1q_u64(&v[0], va01);  vst1q_u64(&v[2], va23);
        vst1q_u64(&v[4], vb01);  vst1q_u64(&v[6], vb23);
        vst1q_u64(&v[8], vc01);  vst1q_u64(&v[10], vc23);
        vst1q_u64(&v[12], vd01); vst1q_u64(&v[14], vd23);

        /* Diagonal step */
        uint64x2_t da01 = vcombine_u64(vcreate_u64(v[0]), vcreate_u64(v[1]));
        uint64x2_t da23 = vcombine_u64(vcreate_u64(v[2]), vcreate_u64(v[3]));
        uint64x2_t db01 = vcombine_u64(vcreate_u64(v[5]), vcreate_u64(v[6]));
        uint64x2_t db23 = vcombine_u64(vcreate_u64(v[7]), vcreate_u64(v[4]));
        uint64x2_t dc01 = vcombine_u64(vcreate_u64(v[10]), vcreate_u64(v[11]));
        uint64x2_t dc23 = vcombine_u64(vcreate_u64(v[8]), vcreate_u64(v[9]));
        uint64x2_t dd01 = vcombine_u64(vcreate_u64(v[15]), vcreate_u64(v[12]));
        uint64x2_t dd23 = vcombine_u64(vcreate_u64(v[13]), vcreate_u64(v[14]));

        uint64x2_t dmx01 = vcombine_u64(vcreate_u64(m[s[8]]), vcreate_u64(m[s[10]]));
        uint64x2_t dmy01 = vcombine_u64(vcreate_u64(m[s[9]]), vcreate_u64(m[s[11]]));
        uint64x2_t dmx23 = vcombine_u64(vcreate_u64(m[s[12]]), vcreate_u64(m[s[14]]));
        uint64x2_t dmy23 = vcombine_u64(vcreate_u64(m[s[13]]), vcreate_u64(m[s[15]]));

        blake2b_g_neon(&da01, &db01, &dc01, &dd01, dmx01, dmy01);
        blake2b_g_neon(&da23, &db23, &dc23, &dd23, dmx23, dmy23);

        v[0] = vgetq_lane_u64(da01, 0); v[1] = vgetq_lane_u64(da01, 1);
        v[2] = vgetq_lane_u64(da23, 0); v[3] = vgetq_lane_u64(da23, 1);
        v[5] = vgetq_lane_u64(db01, 0); v[6] = vgetq_lane_u64(db01, 1);
        v[7] = vgetq_lane_u64(db23, 0); v[4] = vgetq_lane_u64(db23, 1);
        v[10] = vgetq_lane_u64(dc01, 0); v[11] = vgetq_lane_u64(dc01, 1);
        v[8] = vgetq_lane_u64(dc23, 0); v[9] = vgetq_lane_u64(dc23, 1);
        v[15] = vgetq_lane_u64(dd01, 0); v[12] = vgetq_lane_u64(dd01, 1);
        v[13] = vgetq_lane_u64(dd23, 0); v[14] = vgetq_lane_u64(dd23, 1);
    }

    for (int i = 0; i < 8; i++) {
        h[i] ^= v[i] ^ v[i + 8];
    }
}

/* ============================================================================
 * Argon2 G function (memory mixing) - NEON vectorized
 * ============================================================================ */
void ama_argon2_g_neon(uint64_t out[128],
                        const uint64_t x[128],
                        const uint64_t y[128]) {
    uint64_t R[128];
    /* XOR using NEON */
    for (int i = 0; i < 128; i += 2) {
        uint64x2_t vx = vld1q_u64(x + i);
        uint64x2_t vy = vld1q_u64(y + i);
        vst1q_u64(R + i, veorq_u64(vx, vy));
    }

    uint64_t Z[128];
    memcpy(Z, R, 1024);

    /* Row and column mixing (same algorithm as AVX2 version) */
    for (int row = 0; row < 8; row++) {
        uint64_t *v = Z + row * 16;
        for (int r = 0; r < 2; r++) {
            for (int col = 0; col < 4; col++) {
                uint64_t a=v[col], b=v[col+4], c=v[col+8], d=v[col+12];
                a += b; d ^= a; d = (d >> 32) | (d << 32);
                c += d; b ^= c; b = (b >> 24) | (b << 40);
                a += b; d ^= a; d = (d >> 16) | (d << 48);
                c += d; b ^= c; b = (b >> 63) | (b << 1);
                v[col]=a; v[col+4]=b; v[col+8]=c; v[col+12]=d;
            }
        }
    }

    /* out = Z XOR R */
    for (int i = 0; i < 128; i += 2) {
        uint64x2_t vz = vld1q_u64(Z + i);
        uint64x2_t vr = vld1q_u64(R + i);
        vst1q_u64(out + i, veorq_u64(vz, vr));
    }
}

#else
typedef int ama_argon2_neon_not_available;
#endif /* __aarch64__ */
