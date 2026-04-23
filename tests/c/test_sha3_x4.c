/**
 * Copyright 2025-2026 Steel Security Advisors LLC
 * Licensed under the Apache License, Version 2.0
 *
 * @file test_sha3_x4.c
 * @brief Byte-for-byte equivalence test: 4-way batched SHAKE128 vs.
 *        four independent scalar ama_shake128_inc_* streams.
 *
 * This is the correctness gate for the Dilithium/Kyber matrix
 * expansion wiring.  If this test ever fails, the 4-way kernel
 * (ama_keccak_f1600_x4_avx2) or the batched wrapper is producing a
 * different byte stream than the scalar reference — which would
 * silently corrupt KAT output for ML-DSA-65 and ML-KEM-1024 once the
 * wiring lands in dil_expand_matrix / kyber_gen_matrix.
 */

#include "../../src/c/internal/ama_sha3_x4.h"
#include "ama_cryptography.h"
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>

static int failed = 0;

#define CHECK(cond, msg) do {                                     \
    if (!(cond)) { printf("  FAIL: %s\n", msg); failed++; }       \
    else         { printf("  PASS: %s\n", msg); }                 \
} while (0)

/* Emits nblocks * 168 bytes via the scalar incremental SHAKE128 API,
 * the same path dil_poly_uniform / kyber_poly_uniform currently use. */
static void shake128_scalar_blocks(const uint8_t *in, size_t in_len,
                                    uint8_t *out, size_t nblocks)
{
    ama_sha3_ctx ctx;
    ama_shake128_inc_init(&ctx);
    ama_shake128_inc_absorb(&ctx, in, in_len);
    ama_shake128_inc_finalize(&ctx);
    ama_shake128_inc_squeeze(&ctx, out, nblocks * AMA_SHAKE128_X4_RATE);
}

/* Emits nblocks * 136 bytes via the scalar incremental SHAKE256 API,
 * the same path dil_poly_uniform_eta / dil_poly_uniform_gamma1 /
 * kyber_gennoise currently use. */
static void shake256_scalar_blocks(const uint8_t *in, size_t in_len,
                                    uint8_t *out, size_t nblocks)
{
    ama_sha3_ctx ctx;
    ama_shake256_inc_init(&ctx);
    ama_shake256_inc_absorb(&ctx, in, in_len);
    ama_shake256_inc_finalize(&ctx);
    ama_shake256_inc_squeeze(&ctx, out, nblocks * AMA_SHAKE256_X4_RATE);
}

static int check_equiv_128(const char *label,
                       const uint8_t in0[], size_t in0_len,
                       const uint8_t in1[], size_t in1_len,
                       const uint8_t in2[], size_t in2_len,
                       const uint8_t in3[], size_t in3_len,
                       size_t nblocks)
{
    const size_t per_lane = nblocks * AMA_SHAKE128_X4_RATE;
    int result = 0;

    uint8_t *ref0 = (uint8_t *)malloc(per_lane);
    uint8_t *ref1 = (uint8_t *)malloc(per_lane);
    uint8_t *ref2 = (uint8_t *)malloc(per_lane);
    uint8_t *ref3 = (uint8_t *)malloc(per_lane);
    uint8_t *x4_0 = (uint8_t *)malloc(per_lane);
    uint8_t *x4_1 = (uint8_t *)malloc(per_lane);
    uint8_t *x4_2 = (uint8_t *)malloc(per_lane);
    uint8_t *x4_3 = (uint8_t *)malloc(per_lane);

    shake128_scalar_blocks(in0, in0_len, ref0, nblocks);
    shake128_scalar_blocks(in1, in1_len, ref1, nblocks);
    shake128_scalar_blocks(in2, in2_len, ref2, nblocks);
    shake128_scalar_blocks(in3, in3_len, ref3, nblocks);

    ama_shake128_x4_ctx x4ctx;
    ama_error_t rc = ama_shake128_x4_absorb_once(&x4ctx,
        in0, in0_len, in1, in1_len, in2, in2_len, in3, in3_len);
    CHECK(rc == AMA_SUCCESS, "shake128 x4 absorb returns success");
    if (rc != AMA_SUCCESS) {
        /* Absorb failed: further comparison would run memcmp on
         * uninitialized output buffers.  Bail out early after freeing. */
        goto done;
    }

    rc = ama_shake128_x4_squeezeblocks(&x4ctx, x4_0, x4_1, x4_2, x4_3, nblocks);
    CHECK(rc == AMA_SUCCESS, "shake128 x4 squeeze returns success");
    if (rc != AMA_SUCCESS) {
        goto done;
    }

    int eq0 = (memcmp(ref0, x4_0, per_lane) == 0);
    int eq1 = (memcmp(ref1, x4_1, per_lane) == 0);
    int eq2 = (memcmp(ref2, x4_2, per_lane) == 0);
    int eq3 = (memcmp(ref3, x4_3, per_lane) == 0);

    char msg[128];
    snprintf(msg, sizeof(msg), "%s lane 0 byte-identical (nblocks=%zu)", label, nblocks);
    CHECK(eq0, msg);
    snprintf(msg, sizeof(msg), "%s lane 1 byte-identical (nblocks=%zu)", label, nblocks);
    CHECK(eq1, msg);
    snprintf(msg, sizeof(msg), "%s lane 2 byte-identical (nblocks=%zu)", label, nblocks);
    CHECK(eq2, msg);
    snprintf(msg, sizeof(msg), "%s lane 3 byte-identical (nblocks=%zu)", label, nblocks);
    CHECK(eq3, msg);

    result = eq0 && eq1 && eq2 && eq3;

done:
    free(ref0); free(ref1); free(ref2); free(ref3);
    free(x4_0); free(x4_1); free(x4_2); free(x4_3);
    return result;
}

static int check_equiv_256(const char *label,
                       const uint8_t in0[], size_t in0_len,
                       const uint8_t in1[], size_t in1_len,
                       const uint8_t in2[], size_t in2_len,
                       const uint8_t in3[], size_t in3_len,
                       size_t nblocks)
{
    const size_t per_lane = nblocks * AMA_SHAKE256_X4_RATE;
    int result = 0;

    uint8_t *ref0 = (uint8_t *)malloc(per_lane);
    uint8_t *ref1 = (uint8_t *)malloc(per_lane);
    uint8_t *ref2 = (uint8_t *)malloc(per_lane);
    uint8_t *ref3 = (uint8_t *)malloc(per_lane);
    uint8_t *x4_0 = (uint8_t *)malloc(per_lane);
    uint8_t *x4_1 = (uint8_t *)malloc(per_lane);
    uint8_t *x4_2 = (uint8_t *)malloc(per_lane);
    uint8_t *x4_3 = (uint8_t *)malloc(per_lane);

    shake256_scalar_blocks(in0, in0_len, ref0, nblocks);
    shake256_scalar_blocks(in1, in1_len, ref1, nblocks);
    shake256_scalar_blocks(in2, in2_len, ref2, nblocks);
    shake256_scalar_blocks(in3, in3_len, ref3, nblocks);

    ama_shake256_x4_ctx x4ctx;
    ama_error_t rc = ama_shake256_x4_absorb_once(&x4ctx,
        in0, in0_len, in1, in1_len, in2, in2_len, in3, in3_len);
    CHECK(rc == AMA_SUCCESS, "shake256 x4 absorb returns success");
    if (rc != AMA_SUCCESS) {
        goto done;
    }

    rc = ama_shake256_x4_squeezeblocks(&x4ctx, x4_0, x4_1, x4_2, x4_3, nblocks);
    CHECK(rc == AMA_SUCCESS, "shake256 x4 squeeze returns success");
    if (rc != AMA_SUCCESS) {
        goto done;
    }

    int eq0 = (memcmp(ref0, x4_0, per_lane) == 0);
    int eq1 = (memcmp(ref1, x4_1, per_lane) == 0);
    int eq2 = (memcmp(ref2, x4_2, per_lane) == 0);
    int eq3 = (memcmp(ref3, x4_3, per_lane) == 0);

    char msg[128];
    snprintf(msg, sizeof(msg), "%s lane 0 byte-identical (nblocks=%zu)", label, nblocks);
    CHECK(eq0, msg);
    snprintf(msg, sizeof(msg), "%s lane 1 byte-identical (nblocks=%zu)", label, nblocks);
    CHECK(eq1, msg);
    snprintf(msg, sizeof(msg), "%s lane 2 byte-identical (nblocks=%zu)", label, nblocks);
    CHECK(eq2, msg);
    snprintf(msg, sizeof(msg), "%s lane 3 byte-identical (nblocks=%zu)", label, nblocks);
    CHECK(eq3, msg);

    result = eq0 && eq1 && eq2 && eq3;

done:
    free(ref0); free(ref1); free(ref2); free(ref3);
    free(x4_0); free(x4_1); free(x4_2); free(x4_3);
    return result;
}

int main(void) {
    printf("===========================================\n");
    printf("4-way SHAKE128/SHAKE256 vs scalar equivalence test\n");
    printf("===========================================\n\n");

    /* Inputs that mimic the ML-DSA-65 matrix expansion: 32-byte seed +
     * 2-byte (row, col) index, one pair per lane. */
    uint8_t seed[32];
    for (size_t i = 0; i < 32; i++) seed[i] = (uint8_t)(i * 7 + 11);

    uint8_t in0[34], in1[34], in2[34], in3[34];
    memcpy(in0, seed, 32); in0[32] = 0; in0[33] = 0;
    memcpy(in1, seed, 32); in1[32] = 0; in1[33] = 1;
    memcpy(in2, seed, 32); in2[32] = 0; in2[33] = 2;
    memcpy(in3, seed, 32); in3[32] = 1; in3[33] = 0;

    /* 5 blocks = exactly what dil_poly_uniform pre-squeezes. */
    (void)check_equiv_128("DSA matrix seeds",
                          in0, 34, in1, 34, in2, 34, in3, 34, 5);

    /* Kyber matrix expansion: 32-byte seed + (x, y) bytes. */
    uint8_t k0[34], k1[34], k2[34], k3[34];
    memcpy(k0, seed, 32); k0[32] = 0; k0[33] = 0;
    memcpy(k1, seed, 32); k1[32] = 1; k1[33] = 0;
    memcpy(k2, seed, 32); k2[32] = 2; k2[33] = 0;
    memcpy(k3, seed, 32); k3[32] = 3; k3[33] = 0;

    /* 4 blocks = what kyber_poly_uniform pre-squeezes (stream[672]). */
    (void)check_equiv_128("KEM matrix seeds",
                          k0, 34, k1, 34, k2, 34, k3, 34, 4);

    /* Multi-call squeeze: first 2 blocks, then 3 more — should equal
     * one 5-block squeeze (tests the permute-before-emit bookkeeping). */
    {
        const size_t total = 5;
        uint8_t ref[4][168 * 5];
        shake128_scalar_blocks(in0, 34, ref[0], total);
        shake128_scalar_blocks(in1, 34, ref[1], total);
        shake128_scalar_blocks(in2, 34, ref[2], total);
        shake128_scalar_blocks(in3, 34, ref[3], total);

        ama_shake128_x4_ctx ctx;
        ama_error_t rc = ama_shake128_x4_absorb_once(&ctx,
            in0, 34, in1, 34, in2, 34, in3, 34);
        CHECK(rc == AMA_SUCCESS, "shake128 split-squeeze absorb returns success");

        uint8_t out[4][168 * 5];
        rc = ama_shake128_x4_squeezeblocks(&ctx, out[0], out[1], out[2], out[3], 2);
        CHECK(rc == AMA_SUCCESS, "shake128 first partial squeeze (2 blocks)");
        rc = ama_shake128_x4_squeezeblocks(&ctx,
            out[0] + 2 * 168, out[1] + 2 * 168, out[2] + 2 * 168, out[3] + 2 * 168, 3);
        CHECK(rc == AMA_SUCCESS, "shake128 second partial squeeze (3 blocks)");

        CHECK(memcmp(ref[0], out[0], 168 * 5) == 0, "shake128 split-squeeze lane 0 byte-identical");
        CHECK(memcmp(ref[1], out[1], 168 * 5) == 0, "shake128 split-squeeze lane 1 byte-identical");
        CHECK(memcmp(ref[2], out[2], 168 * 5) == 0, "shake128 split-squeeze lane 2 byte-identical");
        CHECK(memcmp(ref[3], out[3], 168 * 5) == 0, "shake128 split-squeeze lane 3 byte-identical");
    }

    /* SHAKE128: inputs longer than one block must be refused. */
    {
        uint8_t big[AMA_SHAKE128_X4_RATE + 1] = {0};
        ama_shake128_x4_ctx ctx;
        ama_error_t rc = ama_shake128_x4_absorb_once(&ctx,
            big, sizeof(big), in0, 34, in1, 34, in2, 34);
        CHECK(rc == AMA_ERROR_INVALID_PARAM, "shake128 absorb rejects input > rate");
    }

    /* SHAKE128: inputs exactly equal to rate must also be refused —
     * the one-block fast path cannot safely write 0x1F at block[rate]
     * without a second padding block (Copilot review finding, PR #260). */
    {
        uint8_t full[AMA_SHAKE128_X4_RATE] = {0};
        ama_shake128_x4_ctx ctx;
        ama_error_t rc = ama_shake128_x4_absorb_once(&ctx,
            full, sizeof(full), in0, 34, in1, 34, in2, 34);
        CHECK(rc == AMA_ERROR_INVALID_PARAM, "shake128 absorb rejects input == rate");

        rc = ama_shake128_x4_absorb_once(&ctx,
            in0, 34, full, sizeof(full), in1, 34, in2, 34);
        CHECK(rc == AMA_ERROR_INVALID_PARAM, "shake128 absorb rejects in_len == rate on lane 1");

        rc = ama_shake128_x4_absorb_once(&ctx,
            in0, 34, in1, 34, full, sizeof(full), in2, 34);
        CHECK(rc == AMA_ERROR_INVALID_PARAM, "shake128 absorb rejects in_len == rate on lane 2");

        rc = ama_shake128_x4_absorb_once(&ctx,
            in0, 34, in1, 34, in2, 34, full, sizeof(full));
        CHECK(rc == AMA_ERROR_INVALID_PARAM, "shake128 absorb rejects in_len == rate on lane 3");
    }

    /* SHAKE256 - Dilithium eta/gamma1 sampling: 64-byte seed (CRH) +
     * 2-byte nonce = 66 bytes, fits in a single SHAKE256 block (136). */
    uint8_t crh[64];
    for (size_t i = 0; i < 64; i++) crh[i] = (uint8_t)(i * 13 + 5);

    uint8_t e0[66], e1[66], e2[66], e3[66];
    memcpy(e0, crh, 64); e0[64] = 0; e0[65] = 0;   /* eta nonce 0 */
    memcpy(e1, crh, 64); e1[64] = 1; e1[65] = 0;   /* eta nonce 1 */
    memcpy(e2, crh, 64); e2[64] = 2; e2[65] = 0;   /* eta nonce 2 */
    memcpy(e3, crh, 64); e3[64] = 3; e3[65] = 0;   /* eta nonce 3 */

    /* 2 blocks = what dil_poly_uniform_eta pre-squeezes (stream[136*2]). */
    (void)check_equiv_256("DSA eta seeds",
                          e0, 66, e1, 66, e2, 66, e3, 66, 2);

    /* 5 blocks = what dil_poly_uniform_gamma1 needs (640 bytes → 5 blocks = 680 bytes
     * after ceiling to the SHAKE256 block size). */
    (void)check_equiv_256("DSA gamma1 seeds",
                          e0, 66, e1, 66, e2, 66, e3, 66, 5);

    /* Kyber gennoise: 32-byte seed + (nonce, 0). */
    uint8_t n0[34], n1[34], n2[34], n3[34];
    memcpy(n0, seed, 32); n0[32] = 0; n0[33] = 0;
    memcpy(n1, seed, 32); n1[32] = 1; n1[33] = 0;
    memcpy(n2, seed, 32); n2[32] = 2; n2[33] = 0;
    memcpy(n3, seed, 32); n3[32] = 3; n3[33] = 0;

    /* 1 block = 136 bytes, enough for KYBER_ETA1 * KYBER_N / 4 = 128 bytes of noise. */
    (void)check_equiv_256("KEM gennoise seeds",
                          n0, 33, n1, 33, n2, 33, n3, 33, 1);

    /* SHAKE256 multi-call squeeze: 1 + 1 blocks == 2 blocks in one call. */
    {
        uint8_t ref[4][136 * 2];
        shake256_scalar_blocks(e0, 66, ref[0], 2);
        shake256_scalar_blocks(e1, 66, ref[1], 2);
        shake256_scalar_blocks(e2, 66, ref[2], 2);
        shake256_scalar_blocks(e3, 66, ref[3], 2);

        ama_shake256_x4_ctx ctx;
        ama_error_t rc = ama_shake256_x4_absorb_once(&ctx,
            e0, 66, e1, 66, e2, 66, e3, 66);
        CHECK(rc == AMA_SUCCESS, "shake256 split-squeeze absorb returns success");

        uint8_t out[4][136 * 2];
        rc = ama_shake256_x4_squeezeblocks(&ctx, out[0], out[1], out[2], out[3], 1);
        CHECK(rc == AMA_SUCCESS, "shake256 first partial squeeze (1 block)");
        rc = ama_shake256_x4_squeezeblocks(&ctx,
            out[0] + 136, out[1] + 136, out[2] + 136, out[3] + 136, 1);
        CHECK(rc == AMA_SUCCESS, "shake256 second partial squeeze (1 block)");

        CHECK(memcmp(ref[0], out[0], 136 * 2) == 0, "shake256 split-squeeze lane 0 byte-identical");
        CHECK(memcmp(ref[1], out[1], 136 * 2) == 0, "shake256 split-squeeze lane 1 byte-identical");
        CHECK(memcmp(ref[2], out[2], 136 * 2) == 0, "shake256 split-squeeze lane 2 byte-identical");
        CHECK(memcmp(ref[3], out[3], 136 * 2) == 0, "shake256 split-squeeze lane 3 byte-identical");
    }

    /* SHAKE256: inputs longer than one block must be refused. */
    {
        uint8_t big[AMA_SHAKE256_X4_RATE + 1] = {0};
        ama_shake256_x4_ctx ctx;
        ama_error_t rc = ama_shake256_x4_absorb_once(&ctx,
            big, sizeof(big), e0, 66, e1, 66, e2, 66);
        CHECK(rc == AMA_ERROR_INVALID_PARAM, "shake256 absorb rejects input > rate");
    }

    /* SHAKE256: inputs exactly equal to rate must also be refused —
     * same boundary-safety requirement as the SHAKE128 case above. */
    {
        uint8_t full[AMA_SHAKE256_X4_RATE] = {0};
        ama_shake256_x4_ctx ctx;
        ama_error_t rc = ama_shake256_x4_absorb_once(&ctx,
            full, sizeof(full), e0, 66, e1, 66, e2, 66);
        CHECK(rc == AMA_ERROR_INVALID_PARAM, "shake256 absorb rejects input == rate");

        rc = ama_shake256_x4_absorb_once(&ctx,
            e0, 66, full, sizeof(full), e1, 66, e2, 66);
        CHECK(rc == AMA_ERROR_INVALID_PARAM, "shake256 absorb rejects in_len == rate on lane 1");

        rc = ama_shake256_x4_absorb_once(&ctx,
            e0, 66, e1, 66, full, sizeof(full), e2, 66);
        CHECK(rc == AMA_ERROR_INVALID_PARAM, "shake256 absorb rejects in_len == rate on lane 2");

        rc = ama_shake256_x4_absorb_once(&ctx,
            e0, 66, e1, 66, e2, 66, full, sizeof(full));
        CHECK(rc == AMA_ERROR_INVALID_PARAM, "shake256 absorb rejects in_len == rate on lane 3");
    }

    printf("\n===========================================\n");
    if (failed) {
        printf("%d 4-way SHAKE equivalence check(s) FAILED\n", failed);
        return 1;
    }
    printf("All 4-way SHAKE128/SHAKE256 equivalence tests passed!\n");
    printf("===========================================\n");
    return 0;
}
