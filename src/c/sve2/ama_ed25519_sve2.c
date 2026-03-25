/**
 * Copyright 2025-2026 Steel Security Advisors LLC
 * Licensed under the Apache License, Version 2.0
 *
 * @file ama_ed25519_sve2.c
 * @brief ARM SVE2-optimized Ed25519 field arithmetic
 *
 * SVE2 scalable-vector intrinsics for Ed25519 radix-2^51 operations.
 * Processes multiple independent field elements using scalable vectors.
 *
 * AI Co-Architects: Eris + | Eden ~ | Devin * | Claude @
 */

#include <stdint.h>
#include <stddef.h>
#include <string.h>

#if defined(__ARM_FEATURE_SVE2)
#include <arm_sve.h>

typedef struct {
    uint64_t v[5];
} fe51_sve2;

/* ============================================================================
 * SVE2 batch field addition
 *
 * Adds N independent field element pairs using scalable vectors.
 * Processes as many elements as the hardware vector length allows.
 * ============================================================================ */
void ama_fe51_add_batch_sve2(fe51_sve2 *r, const fe51_sve2 *a,
                              const fe51_sve2 *b, size_t count) {
    for (int limb = 0; limb < 5; limb++) {
        size_t i = 0;
        while (i < count) {
            svbool_t pg = svwhilelt_b64((int64_t)i, (int64_t)count);

            /* Gather limb values from struct arrays */
            /* Since fe51_sve2 is 40 bytes (5 * uint64), stride = 5 */
            uint64_t a_limbs[8], b_limbs[8]; /* Max SVE VL = 2048 bits = 32 uint64 */
            size_t batch = 0;
            for (size_t j = i; j < count && batch < 8; j++, batch++) {
                a_limbs[batch] = a[j].v[limb];
                b_limbs[batch] = b[j].v[limb];
            }

            svuint64_t va = svld1_u64(pg, a_limbs);
            svuint64_t vb = svld1_u64(pg, b_limbs);
            svuint64_t vr = svadd_u64_x(pg, va, vb);

            uint64_t r_limbs[8];
            svst1_u64(pg, r_limbs, vr);
            batch = 0;
            for (size_t j = i; j < count && batch < 8; j++, batch++) {
                r[j].v[limb] = r_limbs[batch];
            }

            i += svcntd();
        }
    }
}

/* ============================================================================
 * SVE2 batch field subtraction (with 2p addition to avoid underflow)
 * ============================================================================ */
static const uint64_t TWO_P_SVE2[5] = {
    0xFFFFFFFFFFFDA, 0xFFFFFFFFFFFFE, 0xFFFFFFFFFFFFE,
    0xFFFFFFFFFFFFE, 0xFFFFFFFFFFFFE
};

void ama_fe51_sub_batch_sve2(fe51_sve2 *r, const fe51_sve2 *a,
                              const fe51_sve2 *b, size_t count) {
    for (int limb = 0; limb < 5; limb++) {
        size_t i = 0;
        svuint64_t v2p = svdup_n_u64(TWO_P_SVE2[limb]);
        while (i < count) {
            svbool_t pg = svwhilelt_b64((int64_t)i, (int64_t)count);
            uint64_t a_limbs[8], b_limbs[8];
            size_t batch = 0;
            for (size_t j = i; j < count && batch < 8; j++, batch++) {
                a_limbs[batch] = a[j].v[limb];
                b_limbs[batch] = b[j].v[limb];
            }
            svuint64_t va = svld1_u64(pg, a_limbs);
            svuint64_t vb = svld1_u64(pg, b_limbs);
            svuint64_t vr = svsub_u64_x(pg, svadd_u64_x(pg, va, v2p), vb);
            uint64_t r_limbs[8];
            svst1_u64(pg, r_limbs, vr);
            batch = 0;
            for (size_t j = i; j < count && batch < 8; j++, batch++) {
                r[j].v[limb] = r_limbs[batch];
            }
            i += svcntd();
        }
    }
}

#else
typedef int ama_ed25519_sve2_not_available;
#endif /* __ARM_FEATURE_SVE2 */
