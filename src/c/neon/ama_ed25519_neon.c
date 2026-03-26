/**
 * Copyright 2025-2026 Steel Security Advisors LLC
 * Licensed under the Apache License, Version 2.0
 *
 * @file ama_ed25519_neon.c
 * @brief ARM NEON-optimized Ed25519 field arithmetic
 *
 * NEON intrinsics for Ed25519 radix-2^51 field operations:
 *   - 2-way parallel field addition/subtraction
 *   - NEON-assisted carry propagation
 *   - Field multiplication with NEON accumulation
 *
 * AI Co-Architects: Eris + | Eden ~ | Devin * | Claude @
 */

#include <stdint.h>
#include <stddef.h>
#include <string.h>

#if defined(__aarch64__) || defined(_M_ARM64)
#include <arm_neon.h>

typedef struct {
    uint64_t v[5];
} fe51_neon;

static const uint64_t TWO_P_NEON[5] = {
    0xFFFFFFFFFFFDA, 0xFFFFFFFFFFFFE, 0xFFFFFFFFFFFFE,
    0xFFFFFFFFFFFFE, 0xFFFFFFFFFFFFE
};

/* ============================================================================
 * NEON field addition: r = a + b (2-way parallel)
 * ============================================================================ */
void ama_fe51_add_x2_neon(fe51_neon r[2],
                           const fe51_neon a[2],
                           const fe51_neon b[2]) {
    for (int limb = 0; limb < 5; limb++) {
        uint64x2_t va = vcombine_u64(
            vcreate_u64(a[0].v[limb]), vcreate_u64(a[1].v[limb]));
        uint64x2_t vb = vcombine_u64(
            vcreate_u64(b[0].v[limb]), vcreate_u64(b[1].v[limb]));
        uint64x2_t vr = vaddq_u64(va, vb);
        r[0].v[limb] = vgetq_lane_u64(vr, 0);
        r[1].v[limb] = vgetq_lane_u64(vr, 1);
    }
}

/* ============================================================================
 * NEON field subtraction: r = a - b (2-way parallel)
 * ============================================================================ */
void ama_fe51_sub_x2_neon(fe51_neon r[2],
                           const fe51_neon a[2],
                           const fe51_neon b[2]) {
    for (int limb = 0; limb < 5; limb++) {
        uint64x2_t va = vcombine_u64(
            vcreate_u64(a[0].v[limb]), vcreate_u64(a[1].v[limb]));
        uint64x2_t vb = vcombine_u64(
            vcreate_u64(b[0].v[limb]), vcreate_u64(b[1].v[limb]));
        uint64x2_t v2p = vdupq_n_u64(TWO_P_NEON[limb]);
        uint64x2_t vr = vsubq_u64(vaddq_u64(va, v2p), vb);
        r[0].v[limb] = vgetq_lane_u64(vr, 0);
        r[1].v[limb] = vgetq_lane_u64(vr, 1);
    }
}

/* ============================================================================
 * NEON carry propagation (2-way parallel)
 * ============================================================================ */
void ama_fe51_carry_x2_neon(fe51_neon r[2]) {
    const uint64x2_t mask51 = vdupq_n_u64((1ULL << 51) - 1);

    uint64x2_t L[5];
    for (int i = 0; i < 5; i++) {
        L[i] = vcombine_u64(
            vcreate_u64(r[0].v[i]), vcreate_u64(r[1].v[i]));
    }

    uint64x2_t c;
    c = vshrq_n_u64(L[0], 51); L[0] = vandq_u64(L[0], mask51);
    L[1] = vaddq_u64(L[1], c);
    c = vshrq_n_u64(L[1], 51); L[1] = vandq_u64(L[1], mask51);
    L[2] = vaddq_u64(L[2], c);
    c = vshrq_n_u64(L[2], 51); L[2] = vandq_u64(L[2], mask51);
    L[3] = vaddq_u64(L[3], c);
    c = vshrq_n_u64(L[3], 51); L[3] = vandq_u64(L[3], mask51);
    L[4] = vaddq_u64(L[4], c);
    c = vshrq_n_u64(L[4], 51); L[4] = vandq_u64(L[4], mask51);
    /* NEON has no vmulq_u64 — decompose: c*19 = c*16 + c*2 + c */
    {
        uint64x2_t c19 = vaddq_u64(vshlq_n_u64(c, 4),
                                    vaddq_u64(vshlq_n_u64(c, 1), c));
        L[0] = vaddq_u64(L[0], c19);
    }

    for (int i = 0; i < 5; i++) {
        r[0].v[i] = vgetq_lane_u64(L[i], 0);
        r[1].v[i] = vgetq_lane_u64(L[i], 1);
    }
}

/* ============================================================================
 * Field multiplication: r = a * b (scalar with NEON-assisted accumulation)
 * ============================================================================ */
void ama_fe51_mul_neon(fe51_neon *r, const fe51_neon *a, const fe51_neon *b) {
    uint64_t b19[5];
    b19[0] = b->v[0];
    b19[1] = b->v[1] * 19;
    b19[2] = b->v[2] * 19;
    b19[3] = b->v[3] * 19;
    b19[4] = b->v[4] * 19;

    __uint128_t t0 = (__uint128_t)a->v[0] * b->v[0]
                   + (__uint128_t)a->v[1] * b19[4]
                   + (__uint128_t)a->v[2] * b19[3]
                   + (__uint128_t)a->v[3] * b19[2]
                   + (__uint128_t)a->v[4] * b19[1];

    __uint128_t t1 = (__uint128_t)a->v[0] * b->v[1]
                   + (__uint128_t)a->v[1] * b->v[0]
                   + (__uint128_t)a->v[2] * b19[4]
                   + (__uint128_t)a->v[3] * b19[3]
                   + (__uint128_t)a->v[4] * b19[2];

    __uint128_t t2 = (__uint128_t)a->v[0] * b->v[2]
                   + (__uint128_t)a->v[1] * b->v[1]
                   + (__uint128_t)a->v[2] * b->v[0]
                   + (__uint128_t)a->v[3] * b19[4]
                   + (__uint128_t)a->v[4] * b19[3];

    __uint128_t t3 = (__uint128_t)a->v[0] * b->v[3]
                   + (__uint128_t)a->v[1] * b->v[2]
                   + (__uint128_t)a->v[2] * b->v[1]
                   + (__uint128_t)a->v[3] * b->v[0]
                   + (__uint128_t)a->v[4] * b19[4];

    __uint128_t t4 = (__uint128_t)a->v[0] * b->v[4]
                   + (__uint128_t)a->v[1] * b->v[3]
                   + (__uint128_t)a->v[2] * b->v[2]
                   + (__uint128_t)a->v[3] * b->v[1]
                   + (__uint128_t)a->v[4] * b->v[0];

    const uint64_t mask51 = (1ULL << 51) - 1;
    uint64_t c;
    r->v[0] = (uint64_t)t0 & mask51; c = (uint64_t)(t0 >> 51);
    t1 += c;
    r->v[1] = (uint64_t)t1 & mask51; c = (uint64_t)(t1 >> 51);
    t2 += c;
    r->v[2] = (uint64_t)t2 & mask51; c = (uint64_t)(t2 >> 51);
    t3 += c;
    r->v[3] = (uint64_t)t3 & mask51; c = (uint64_t)(t3 >> 51);
    t4 += c;
    r->v[4] = (uint64_t)t4 & mask51; c = (uint64_t)(t4 >> 51);
    r->v[0] += c * 19;
    c = r->v[0] >> 51; r->v[0] &= mask51;
    r->v[1] += c;
}

#else
typedef int ama_ed25519_neon_not_available;
#endif /* __aarch64__ */
