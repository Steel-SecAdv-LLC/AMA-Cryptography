/**
 * Copyright 2025-2026 Steel Security Advisors LLC
 * Licensed under the Apache License, Version 2.0
 *
 * Unit tests for X25519 implementation (RFC 7748)
 *
 * Validates:
 * - Single-step scalar-mult vectors from RFC 7748 Section 5.2
 * - Alice / Bob key-exchange vector from RFC 7748 Section 6.1 in both
 *   directions (public-key derivation and shared-secret agreement)
 * - Random keypair DH symmetry
 * - Low-order point rejection (all-zero shared secret -> AMA_ERROR_CRYPTO)
 * - NULL parameter validation
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "ama_cryptography.h"

#define TEST_ASSERT(condition, message)                          \
    do {                                                         \
        if (!(condition)) {                                      \
            fprintf(stderr, "FAIL: %s\n", message);              \
            return 1;                                            \
        } else {                                                 \
            printf("PASS: %s\n", message);                       \
        }                                                        \
    } while (0)

/* RFC 7748 Section 5.2 Test Vector 1 */
static const uint8_t tv1_scalar[32] = {
    0xa5,0x46,0xe3,0x6b,0xf0,0x52,0x7c,0x9d, 0x3b,0x16,0x15,0x4b,0x82,0x46,0x5e,0xdd,
    0x62,0x14,0x4c,0x0a,0xc1,0xfc,0x5a,0x18, 0x50,0x6a,0x22,0x44,0xba,0x44,0x9a,0xc4
};
static const uint8_t tv1_u[32] = {
    0xe6,0xdb,0x68,0x67,0x58,0x30,0x30,0xdb, 0x35,0x94,0xc1,0xa4,0x24,0xb1,0x5f,0x7c,
    0x72,0x66,0x24,0xec,0x26,0xb3,0x35,0x3b, 0x10,0xa9,0x03,0xa6,0xd0,0xab,0x1c,0x4c
};
static const uint8_t tv1_out[32] = {
    0xc3,0xda,0x55,0x37,0x9d,0xe9,0xc6,0x90, 0x8e,0x94,0xea,0x4d,0xf2,0x8d,0x08,0x4f,
    0x32,0xec,0xcf,0x03,0x49,0x1c,0x71,0xf7, 0x54,0xb4,0x07,0x55,0x77,0xa2,0x85,0x52
};

/* RFC 7748 Section 5.2 Test Vector 2 */
static const uint8_t tv2_scalar[32] = {
    0x4b,0x66,0xe9,0xd4,0xd1,0xb4,0x67,0x3c, 0x5a,0xd2,0x26,0x91,0x95,0x7d,0x6a,0xf5,
    0xc1,0x1b,0x64,0x21,0xe0,0xea,0x01,0xd4, 0x2c,0xa4,0x16,0x9e,0x79,0x18,0xba,0x0d
};
static const uint8_t tv2_u[32] = {
    0xe5,0x21,0x0f,0x12,0x78,0x68,0x11,0xd3, 0xf4,0xb7,0x95,0x9d,0x05,0x38,0xae,0x2c,
    0x31,0xdb,0xe7,0x10,0x6f,0xc0,0x3c,0x3e, 0xfc,0x4c,0xd5,0x49,0xc7,0x15,0xa4,0x93
};
static const uint8_t tv2_out[32] = {
    0x95,0xcb,0xde,0x94,0x76,0xe8,0x90,0x7d, 0x7a,0xad,0xe4,0x5c,0xb4,0xb8,0x73,0xf8,
    0x8b,0x59,0x5a,0x68,0x79,0x9f,0xa1,0x52, 0xe6,0xf8,0xf7,0x64,0x7a,0xac,0x79,0x57
};

/* RFC 7748 Section 6.1: Alice/Bob key-exchange vector */
static const uint8_t alice_sk[32] = {
    0x77,0x07,0x6d,0x0a,0x73,0x18,0xa5,0x7d, 0x3c,0x16,0xc1,0x72,0x51,0xb2,0x66,0x45,
    0xdf,0x4c,0x2f,0x87,0xeb,0xc0,0x99,0x2a, 0xb1,0x77,0xfb,0xa5,0x1d,0xb9,0x2c,0x2a
};
static const uint8_t alice_pk[32] = {
    0x85,0x20,0xf0,0x09,0x89,0x30,0xa7,0x54, 0x74,0x8b,0x7d,0xdc,0xb4,0x3e,0xf7,0x5a,
    0x0d,0xbf,0x3a,0x0d,0x26,0x38,0x1a,0xf4, 0xeb,0xa4,0xa9,0x8e,0xaa,0x9b,0x4e,0x6a
};
static const uint8_t bob_sk[32] = {
    0x5d,0xab,0x08,0x7e,0x62,0x4a,0x8a,0x4b, 0x79,0xe1,0x7f,0x8b,0x83,0x80,0x0e,0xe6,
    0x6f,0x3b,0xb1,0x29,0x26,0x18,0xb6,0xfd, 0x1c,0x2f,0x8b,0x27,0xff,0x88,0xe0,0xeb
};
static const uint8_t bob_pk[32] = {
    0xde,0x9e,0xdb,0x7d,0x7b,0x7d,0xc1,0xb4, 0xd3,0x5b,0x61,0xc2,0xec,0xe4,0x35,0x37,
    0x3f,0x83,0x43,0xc8,0x5b,0x78,0x67,0x4d, 0xad,0xfc,0x7e,0x14,0x6f,0x88,0x2b,0x4f
};
static const uint8_t expected_shared[32] = {
    0x4a,0x5d,0x9d,0x5b,0xa4,0xce,0x2d,0xe1, 0x72,0x8e,0x3b,0xf4,0x80,0x35,0x0f,0x25,
    0xe0,0x7e,0x21,0xc9,0x47,0xd1,0x9e,0x33, 0x76,0xf0,0x9b,0x3c,0x1e,0x16,0x17,0x42
};

int main(void) {
    uint8_t out[32];

    /* RFC 7748 §5.2 TV1: scalar * u */
    TEST_ASSERT(ama_x25519_key_exchange(out, tv1_scalar, tv1_u) == AMA_SUCCESS,
                "RFC 7748 TV1 completes");
    TEST_ASSERT(memcmp(out, tv1_out, 32) == 0,
                "RFC 7748 TV1 output matches");

    /* RFC 7748 §5.2 TV2 */
    TEST_ASSERT(ama_x25519_key_exchange(out, tv2_scalar, tv2_u) == AMA_SUCCESS,
                "RFC 7748 TV2 completes");
    TEST_ASSERT(memcmp(out, tv2_out, 32) == 0,
                "RFC 7748 TV2 output matches");

    /* RFC 7748 §6.1: public-key derivation (scalar * 9) */
    uint8_t basepoint[32] = {0};
    basepoint[0] = 9;
    TEST_ASSERT(ama_x25519_key_exchange(out, alice_sk, basepoint) == AMA_SUCCESS,
                "Alice pk derivation completes");
    TEST_ASSERT(memcmp(out, alice_pk, 32) == 0,
                "Alice pk matches RFC 7748 §6.1");
    TEST_ASSERT(ama_x25519_key_exchange(out, bob_sk, basepoint) == AMA_SUCCESS,
                "Bob pk derivation completes");
    TEST_ASSERT(memcmp(out, bob_pk, 32) == 0,
                "Bob pk matches RFC 7748 §6.1");

    /* RFC 7748 §6.1: shared secret in both directions */
    TEST_ASSERT(ama_x25519_key_exchange(out, alice_sk, bob_pk) == AMA_SUCCESS,
                "Alice->Bob DH completes");
    TEST_ASSERT(memcmp(out, expected_shared, 32) == 0,
                "Alice->Bob shared secret matches RFC 7748 §6.1");
    TEST_ASSERT(ama_x25519_key_exchange(out, bob_sk, alice_pk) == AMA_SUCCESS,
                "Bob->Alice DH completes");
    TEST_ASSERT(memcmp(out, expected_shared, 32) == 0,
                "Bob->Alice shared secret matches RFC 7748 §6.1");

    /* Random keypair DH symmetry */
    uint8_t sk_a[32], pk_a[32], sk_b[32], pk_b[32], s1[32], s2[32];
    TEST_ASSERT(ama_x25519_keypair(pk_a, sk_a) == AMA_SUCCESS, "keypair A");
    TEST_ASSERT(ama_x25519_keypair(pk_b, sk_b) == AMA_SUCCESS, "keypair B");
    TEST_ASSERT(ama_x25519_key_exchange(s1, sk_a, pk_b) == AMA_SUCCESS, "A*B");
    TEST_ASSERT(ama_x25519_key_exchange(s2, sk_b, pk_a) == AMA_SUCCESS, "B*A");
    TEST_ASSERT(memcmp(s1, s2, 32) == 0, "random DH symmetric");

    /* Low-order point rejection: the all-zero u-coordinate produces an
     * all-zero shared secret, which RFC 7748 §6.1 says implementations
     * MAY detect. AMA rejects with AMA_ERROR_CRYPTO. */
    uint8_t lo_u[32] = {0};
    uint8_t dummy_sk[32];
    memset(dummy_sk, 0x42, sizeof(dummy_sk));
    dummy_sk[0]  &= 248;
    dummy_sk[31] &= 127;
    dummy_sk[31] |= 64;
    TEST_ASSERT(ama_x25519_key_exchange(out, dummy_sk, lo_u) == AMA_ERROR_CRYPTO,
                "low-order u=0 rejected");

    /* NULL parameter validation */
    TEST_ASSERT(ama_x25519_keypair(NULL, sk_a) == AMA_ERROR_INVALID_PARAM,
                "keypair rejects NULL pk");
    TEST_ASSERT(ama_x25519_keypair(pk_a, NULL) == AMA_ERROR_INVALID_PARAM,
                "keypair rejects NULL sk");
    TEST_ASSERT(ama_x25519_key_exchange(NULL, sk_a, pk_b) == AMA_ERROR_INVALID_PARAM,
                "DH rejects NULL out");
    TEST_ASSERT(ama_x25519_key_exchange(out, NULL, pk_b) == AMA_ERROR_INVALID_PARAM,
                "DH rejects NULL sk");
    TEST_ASSERT(ama_x25519_key_exchange(out, sk_a, NULL) == AMA_ERROR_INVALID_PARAM,
                "DH rejects NULL pk");

    /* ========================================================================
     * Batch API (ama_x25519_scalarmult_batch)
     *
     * On x86-64 with AVX2 the batch API dispatches to a 4-way
     * Montgomery ladder kernel for chunks of 4; tail and N==1 fall
     * through to the scalar single-shot path.  We exercise both:
     *   1. AVX2 path (default when CPU supports it)
     *   2. Scalar fallback (force-disabled via test hook)
     * Each sub-test must produce byte-identical output to the
     * single-shot `ama_x25519_key_exchange` reference.
     * ====================================================================== */
    extern void ama_test_force_x25519_x4_scalar(void);
    extern void ama_test_force_x25519_x4_avx2(void);
    extern void ama_test_restore_x25519_x4_avx2(void);

    /* RFC 7748 §5.2 TVs broadcast across all four lanes — exercises
     * the kernel directly with known-answer vectors. */
    {
        uint8_t b_scalars[4][32], b_points[4][32], b_outs[4][32];
        int k;
        for (k = 0; k < 4; k++) {
            memcpy(b_scalars[k], tv1_scalar, 32);
            memcpy(b_points[k],  tv1_u,      32);
        }
        TEST_ASSERT(ama_x25519_scalarmult_batch(b_outs, (const uint8_t (*)[32])b_scalars, (const uint8_t (*)[32])b_points, 4) == AMA_SUCCESS,
                    "batch RFC 7748 TV1 ×4 success");
        for (k = 0; k < 4; k++) {
            TEST_ASSERT(memcmp(b_outs[k], tv1_out, 32) == 0,
                        "batch TV1 lane matches RFC expected");
        }
        for (k = 0; k < 4; k++) {
            memcpy(b_scalars[k], tv2_scalar, 32);
            memcpy(b_points[k],  tv2_u,      32);
        }
        TEST_ASSERT(ama_x25519_scalarmult_batch(b_outs, (const uint8_t (*)[32])b_scalars, (const uint8_t (*)[32])b_points, 4) == AMA_SUCCESS,
                    "batch RFC 7748 TV2 ×4 success");
        for (k = 0; k < 4; k++) {
            TEST_ASSERT(memcmp(b_outs[k], tv2_out, 32) == 0,
                        "batch TV2 lane matches RFC expected");
        }
    }

    /* count == 0: no-op success (must NOT touch out / scalars / points). */
    TEST_ASSERT(ama_x25519_scalarmult_batch(NULL, NULL, NULL, 0) == AMA_SUCCESS,
                "batch count==0 is a no-op");

    /* count == 1: scalar fast-path (bypasses 4-way kernel); must match
     * single-shot byte-for-byte. */
    {
        uint8_t one_scalar[1][32], one_point[1][32], one_out[1][32], expected[32];
        memcpy(one_scalar[0], alice_sk, 32);
        memcpy(one_point[0],  bob_pk,   32);
        ama_x25519_key_exchange(expected, alice_sk, bob_pk);
        TEST_ASSERT(ama_x25519_scalarmult_batch(one_out, (const uint8_t (*)[32])one_scalar, (const uint8_t (*)[32])one_point, 1) == AMA_SUCCESS,
                    "batch N=1 success");
        TEST_ASSERT(memcmp(one_out[0], expected, 32) == 0,
                    "batch N=1 matches single-shot");
    }

    /* Exhaustive cross-check: 64 random vectors via batch == 64 sequential
     * single-shots.  Run TWICE — once with the AVX2 kernel wired in, once
     * with it forced off — to cover both code paths in the same binary. */
    {
        const size_t N = 64;
        uint8_t (*scs)[32]   = malloc(N * 32);
        uint8_t (*pts)[32]   = malloc(N * 32);
        uint8_t (*bouts)[32] = malloc(N * 32);
        uint8_t (*souts)[32] = malloc(N * 32);
        TEST_ASSERT(scs && pts && bouts && souts, "batch: malloc");
        size_t i, j;
        for (i = 0; i < N; i++) {
            for (j = 0; j < 32; j++) {
                scs[i][j] = (uint8_t)((i + 1) * 13 + j * 7);
                pts[i][j] = (uint8_t)((i + 5) * 11 + j * 3);
            }
        }
        /* Single-shot reference. */
        for (i = 0; i < N; i++) {
            TEST_ASSERT(ama_x25519_key_exchange(souts[i], scs[i], pts[i]) == AMA_SUCCESS,
                        "batch ref: single-shot success");
        }

        /* Pass 1 — force the AVX2 4-way kernel on (regardless of the
         * `AMA_DISPATCH_USE_X25519_AVX2` env default-off policy).  On
         * hosts without AVX2 this is a no-op and the call falls through
         * to scalar — still correct, just same path as Pass 2. */
        ama_test_force_x25519_x4_avx2();
        TEST_ASSERT(ama_x25519_scalarmult_batch(bouts,
                                                 (const uint8_t (*)[32])scs,
                                                 (const uint8_t (*)[32])pts, N) == AMA_SUCCESS,
                    "batch random ×64 (AVX2 forced) success");
        for (i = 0; i < N; i++) {
            TEST_ASSERT(memcmp(bouts[i], souts[i], 32) == 0,
                        "batch lane matches single-shot (AVX2 forced)");
        }

        /* Pass 2 — forced scalar fallback. */
        ama_test_force_x25519_x4_scalar();
        TEST_ASSERT(ama_x25519_scalarmult_batch(bouts,
                                                 (const uint8_t (*)[32])scs,
                                                 (const uint8_t (*)[32])pts, N) == AMA_SUCCESS,
                    "batch random ×64 (scalar forced) success");
        for (i = 0; i < N; i++) {
            TEST_ASSERT(memcmp(bouts[i], souts[i], 32) == 0,
                        "batch lane matches single-shot (scalar forced)");
        }
        ama_test_restore_x25519_x4_avx2();

        /* Tail-lane coverage: counts that don't divide by 4 (1, 2, 3,
         * 5, 6, 7, 9, 13) must still produce correct results — the
         * 4-way kernel handles the integral-of-4 prefix and the
         * scalar fallback handles the (count % 4) tail. */
        const size_t tail_counts[] = { 1, 2, 3, 5, 6, 7, 9, 13 };
        for (j = 0; j < sizeof(tail_counts) / sizeof(tail_counts[0]); j++) {
            size_t tc = tail_counts[j];
            TEST_ASSERT(ama_x25519_scalarmult_batch(bouts, (const uint8_t (*)[32])scs, (const uint8_t (*)[32])pts, tc) == AMA_SUCCESS,
                        "batch tail-count success");
            for (i = 0; i < tc; i++) {
                TEST_ASSERT(memcmp(bouts[i], souts[i], 32) == 0,
                            "batch tail-count lane matches single-shot");
            }
        }

        free(scs); free(pts); free(bouts); free(souts);
    }

    /* Aggregate low-order rejection: any zero shared-secret lane causes
     * the whole batch to fail with AMA_ERROR_CRYPTO and ALL outputs to
     * be zeroed.  Lane 2 here uses u=0 (small-order) while the others
     * use legitimate points; we expect the entire batch to fail and
     * every output slot to be scrubbed. */
    {
        uint8_t b_scalars[4][32], b_points[4][32], b_outs[4][32];
        int k;
        memset(b_outs, 0xAA, sizeof(b_outs));
        for (k = 0; k < 4; k++) {
            memcpy(b_scalars[k], dummy_sk, 32);
            memcpy(b_points[k],  bob_pk,   32);
        }
        memset(b_points[2], 0, 32);  /* lane 2: low-order u = 0 */
        TEST_ASSERT(ama_x25519_scalarmult_batch(b_outs, (const uint8_t (*)[32])b_scalars, (const uint8_t (*)[32])b_points, 4) == AMA_ERROR_CRYPTO,
                    "batch low-order rejection (any-lane → whole-batch fail)");
        uint8_t accum = 0;
        size_t i, j;
        for (i = 0; i < 4; i++) for (j = 0; j < 32; j++) accum |= b_outs[i][j];
        TEST_ASSERT(accum == 0, "batch low-order: ALL outputs zeroed on failure");
    }

    /* NULL parameter validation. */
    {
        uint8_t b_outs[1][32], b_scalars[1][32], b_points[1][32];
        memset(b_scalars, 0, sizeof(b_scalars));
        memset(b_points,  0, sizeof(b_points));
        TEST_ASSERT(ama_x25519_scalarmult_batch(NULL, (const uint8_t (*)[32])b_scalars, (const uint8_t (*)[32])b_points, 1) == AMA_ERROR_INVALID_PARAM,
                    "batch rejects NULL out");
        TEST_ASSERT(ama_x25519_scalarmult_batch(b_outs, NULL, (const uint8_t (*)[32])b_points, 1) == AMA_ERROR_INVALID_PARAM,
                    "batch rejects NULL scalars");
        TEST_ASSERT(ama_x25519_scalarmult_batch(b_outs, (const uint8_t (*)[32])b_scalars, NULL, 1) == AMA_ERROR_INVALID_PARAM,
                    "batch rejects NULL points");
    }


    printf("\nAll X25519 tests passed.\n");
    return 0;
}
