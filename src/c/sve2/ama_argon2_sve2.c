/**
 * Copyright 2025-2026 Steel Security Advisors LLC
 * Licensed under the Apache License, Version 2.0
 *
 * @file ama_argon2_sve2.c
 * @brief ARM SVE2-optimized Argon2 memory-hard function
 *
 * SVE2 scalable-vector intrinsics for Argon2id (RFC 9106):
 *   - Vectorized Blake2b G function
 *   - SVE2-accelerated memory XOR operations
 *
 * -------------------------------------------------------------------
 * STATUS: NOT WIRED INTO DISPATCH.
 *
 * Same caveat as `src/c/neon/ama_argon2_neon.c`: the G round below
 * implements plain Blake2b G, not RFC 9106 §3.5 BlaMka G. Wiring it
 * would break Argon2id tags. Before wiring, port the AVX2 correction
 * in `src/c/avx2/ama_argon2_avx2.c` — PR #239 — and verify against
 * the scalar path on SVE2 hardware (or qemu-aarch64 --cpu max,sve2=on).
 * -------------------------------------------------------------------
 *
 * AI Co-Architects: Eris + | Eden ~ | Devin * | Claude @
 */

#include <stdint.h>
#include <stddef.h>
#include <string.h>

#if defined(__ARM_FEATURE_SVE2)
#include <arm_sve.h>

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

/* ============================================================================
 * Blake2b compression using SVE2 (scalar rounds, SVE2-assisted XOR)
 * ============================================================================ */
void ama_blake2b_compress_sve2(uint64_t h[8], const uint64_t m[16],
                                uint64_t t0, uint64_t t1, int is_final) {
    uint64_t v[16];
    memcpy(v, h, 64);
    memcpy(v + 8, BLAKE2B_IV, 64);
    v[12] ^= t0;
    v[13] ^= t1;
    if (is_final) v[14] = ~v[14];

    for (int round = 0; round < 12; round++) {
        const uint8_t *s = SIGMA[round];

        /* G function rounds (sequential due to data dependencies) */
        #define G_SVE2(a, b, c, d, mx, my) do { \
            v[a] += v[b] + m[mx]; v[d] ^= v[a]; \
            v[d] = (v[d] >> 32) | (v[d] << 32); \
            v[c] += v[d]; v[b] ^= v[c]; \
            v[b] = (v[b] >> 24) | (v[b] << 40); \
            v[a] += v[b] + m[my]; v[d] ^= v[a]; \
            v[d] = (v[d] >> 16) | (v[d] << 48); \
            v[c] += v[d]; v[b] ^= v[c]; \
            v[b] = (v[b] >> 63) | (v[b] << 1); \
        } while(0)

        G_SVE2(0, 4, 8, 12, s[0], s[1]);
        G_SVE2(1, 5, 9, 13, s[2], s[3]);
        G_SVE2(2, 6,10, 14, s[4], s[5]);
        G_SVE2(3, 7,11, 15, s[6], s[7]);
        G_SVE2(0, 5,10, 15, s[8], s[9]);
        G_SVE2(1, 6,11, 12, s[10], s[11]);
        G_SVE2(2, 7, 8, 13, s[12], s[13]);
        G_SVE2(3, 4, 9, 14, s[14], s[15]);

        #undef G_SVE2
    }

    /* Finalize using SVE2 XOR */
    svbool_t pg = svwhilelt_b64(0, 8);
    svuint64_t vh = svld1_u64(pg, h);
    svuint64_t vv0 = svld1_u64(pg, v);
    svuint64_t vv8 = svld1_u64(pg, v + 8);
    svst1_u64(pg, h, sveor_u64_x(pg, vh, sveor_u64_x(pg, vv0, vv8)));
}

/* ============================================================================
 * Argon2 G function with SVE2-accelerated XOR
 * ============================================================================ */
void ama_argon2_g_sve2(uint64_t out[128],
                        const uint64_t x[128],
                        const uint64_t y[128]) {
    uint64_t R[128], Z[128];

    /* R = X XOR Y using SVE2 */
    size_t i = 0;
    while (i < 128) {
        svbool_t pg = svwhilelt_b64((int64_t)i, 128LL);
        svuint64_t vx = svld1_u64(pg, x + i);
        svuint64_t vy = svld1_u64(pg, y + i);
        svst1_u64(pg, R + i, sveor_u64_x(pg, vx, vy));
        i += svcntd();
    }

    memcpy(Z, R, 1024);

    /* Row and column mixing */
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

    /* out = Z XOR R using SVE2 */
    i = 0;
    while (i < 128) {
        svbool_t pg = svwhilelt_b64((int64_t)i, 128LL);
        svuint64_t vz = svld1_u64(pg, Z + i);
        svuint64_t vr = svld1_u64(pg, R + i);
        svst1_u64(pg, out + i, sveor_u64_x(pg, vz, vr));
        i += svcntd();
    }
}

#else
typedef int ama_argon2_sve2_not_available;
#endif /* __ARM_FEATURE_SVE2 */
