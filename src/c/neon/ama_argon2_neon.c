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
 * -------------------------------------------------------------------
 * STATUS: WIRED INTO DISPATCH (BlaMka-correct, NEON-vectorised XOR).
 *
 * Prior versions of this kernel used the plain Blake2b G round
 * (a += b; d = rotr(d^a, 32); ...) and the wrong outer structure
 * (row-pass executed twice instead of row-pass + column-pass), which
 * is why it shipped tagged "NOT WIRED INTO DISPATCH" — installing it
 * into `ama_dispatch_table_t::argon2_g` would have produced incorrect
 * Argon2id tags and failed every RFC 9106 KAT.
 *
 * The current implementation matches the AVX2 reference fix in
 * `src/c/avx2/ama_argon2_avx2.c` byte-for-byte: it XOR's R = X^Y
 * using NEON 2-wide u64 vectors, runs row-wise + column-wise BlaMka
 * G rounds on Z (with the multiplication-hardened add
 * a + b + 2*lo32(a)*lo32(b) in scalar — vmull_u32 is also available
 * for a future 2-wide BlaMka G port, but is not in the hot path of
 * this kernel today), and XOR's Z ^ R into the output with NEON.
 * Byte-identity with the scalar argon2_G is verified two ways:
 *   - `tests/c/test_argon2id.c` runs the RFC 9106 KAT through the
 *     dispatched pipeline (NEON when wired, scalar when forced via
 *     `ama_test_force_argon2_g_scalar()`).
 *   - `tests/c/test_argon2_g_neon_equiv.c` calls this kernel
 *     DIRECTLY against the in-test scalar BlaMka G over ≥1024
 *     random (X, Y) blocks plus boundary corner cases.
 * -------------------------------------------------------------------
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

/* NEON rotate right by compile-time constants used in Blake2b G.
 * vshrq_n_u64 / vshlq_n_u64 require compile-time constant shift amounts,
 * so we define specialised macros instead of a variable-shift function. */
#define ROTR64_NEON(x, n) vorrq_u64(vshrq_n_u64((x), (n)), vshlq_n_u64((x), 64 - (n)))

/* ============================================================================
 * Blake2b G function (NEON vectorized, 2 pairs at a time)
 * ============================================================================ */
static inline void blake2b_g_neon(uint64x2_t *a, uint64x2_t *b,
                                   uint64x2_t *c, uint64x2_t *d,
                                   uint64x2_t mx, uint64x2_t my) {
    *a = vaddq_u64(*a, vaddq_u64(*b, mx));
    *d = ROTR64_NEON(veorq_u64(*d, *a), 32);
    *c = vaddq_u64(*c, *d);
    *b = ROTR64_NEON(veorq_u64(*b, *c), 24);
    *a = vaddq_u64(*a, vaddq_u64(*b, my));
    *d = ROTR64_NEON(veorq_u64(*d, *a), 16);
    *c = vaddq_u64(*c, *d);
    *b = ROTR64_NEON(veorq_u64(*b, *c), 63);
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
 * BlaMka building blocks (mirrors scalar reference in ama_argon2.c).
 *
 * fBlaMka(a, b) = a + b + 2 * trunc32(a) * trunc32(b)  (RFC 9106 §3.5)
 * BLAMKA_G applies one G round to a 4-tuple in place; blamka_round runs
 * the column-like + diagonal-like passes over 16 qwords.  The scalar
 * BlaMka body matches the AVX2 `blamka_g4` aggregate after lane unpack
 * exactly — byte-identity to the scalar path is the test invariant.
 * ============================================================================ */
static inline uint64_t neon_fblamka(uint64_t a, uint64_t b) {
    uint64_t mask = UINT64_C(0xFFFFFFFF);
    return a + b + 2 * (a & mask) * (b & mask);
}

#define NEON_BLAMKA_G(a, b, c, d)                                     \
    do {                                                              \
        (a) = neon_fblamka((a), (b));                                 \
        (d) = (((d) ^ (a)) >> 32) | (((d) ^ (a)) << 32);              \
        (c) = neon_fblamka((c), (d));                                 \
        (b) = (((b) ^ (c)) >> 24) | (((b) ^ (c)) << 40);              \
        (a) = neon_fblamka((a), (b));                                 \
        (d) = (((d) ^ (a)) >> 16) | (((d) ^ (a)) << 48);              \
        (c) = neon_fblamka((c), (d));                                 \
        (b) = (((b) ^ (c)) >> 63) | (((b) ^ (c)) << 1);               \
    } while (0)

static inline void neon_blamka_round(uint64_t v[16]) {
    NEON_BLAMKA_G(v[0],  v[4],  v[8],  v[12]);
    NEON_BLAMKA_G(v[1],  v[5],  v[9],  v[13]);
    NEON_BLAMKA_G(v[2],  v[6],  v[10], v[14]);
    NEON_BLAMKA_G(v[3],  v[7],  v[11], v[15]);

    NEON_BLAMKA_G(v[0],  v[5],  v[10], v[15]);
    NEON_BLAMKA_G(v[1],  v[6],  v[11], v[12]);
    NEON_BLAMKA_G(v[2],  v[7],  v[8],  v[13]);
    NEON_BLAMKA_G(v[3],  v[4],  v[9],  v[14]);
}

/* ============================================================================
 * Argon2 G compression (RFC 9106 §3.5) — NEON path.
 *
 * Matches the AVX2 reference structure exactly:
 *   R = X XOR Y      (NEON 2-wide u64 vectors)
 *   Z = R
 *   row-pass:    8 rows, each a contiguous run of 16 qwords
 *   column-pass: 8 column groups, each gathering 2 qwords per row
 *                across all 8 rows (16 qwords total)
 *   out = R XOR Z    (NEON 2-wide u64 vectors)
 *
 * The interior BlaMka G runs scalar — the NEON BlaMka G port is
 * deferred (see comment at top of file).  This keeps the kernel
 * BlaMka-correct so the dispatcher can wire it without breaking
 * RFC 9106 KATs, while still gaining the NEON XOR speedup on the
 * 1024-byte block load/store edges of the compression.
 * ============================================================================ */
void ama_argon2_g_neon(uint64_t out[128],
                        const uint64_t x[128],
                        const uint64_t y[128]) {
    uint64_t R[128];
    uint64_t Z[128];

    /* R = X XOR Y (NEON 2-wide). */
    for (int i = 0; i < 128; i += 2) {
        uint64x2_t vx = vld1q_u64(x + i);
        uint64x2_t vy = vld1q_u64(y + i);
        vst1q_u64(R + i, veorq_u64(vx, vy));
    }

    memcpy(Z, R, sizeof(Z));

    /* Row-wise BlaMka: 8 rows of 16 qwords each (contiguous). */
    for (int row = 0; row < 8; row++) {
        neon_blamka_round(&Z[row * 16]);
    }

    /* Column-wise BlaMka: gather non-contiguous stride-16 pairs into a
     * scratch buffer, run blamka_round, scatter back.  Mirrors the
     * AVX2 column-pass scratch idiom verbatim. */
    for (int col = 0; col < 8; col++) {
        uint64_t scratch[16];
        for (int row = 0; row < 8; row++) {
            scratch[2 * row    ] = Z[2 * col + row * 16    ];
            scratch[2 * row + 1] = Z[2 * col + row * 16 + 1];
        }
        neon_blamka_round(scratch);
        for (int row = 0; row < 8; row++) {
            Z[2 * col + row * 16    ] = scratch[2 * row    ];
            Z[2 * col + row * 16 + 1] = scratch[2 * row + 1];
        }
    }

    /* out = Z XOR R (NEON 2-wide). */
    for (int i = 0; i < 128; i += 2) {
        uint64x2_t vz = vld1q_u64(Z + i);
        uint64x2_t vr = vld1q_u64(R + i);
        vst1q_u64(out + i, veorq_u64(vz, vr));
    }
}

#else
typedef int ama_argon2_neon_not_available;
#endif /* __aarch64__ */
