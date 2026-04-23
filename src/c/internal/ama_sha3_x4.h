/**
 * Copyright 2025-2026 Steel Security Advisors LLC
 * Licensed under the Apache License, Version 2.0
 *
 * @file internal/ama_sha3_x4.h
 * @brief 4-way batched SHAKE128 wrapper (internal, not exported)
 *
 * Drives the existing AVX2 4-lane Keccak-f[1600] permutation
 * (ama_keccak_f1600_x4_avx2 in src/c/avx2/ama_sha3_avx2.c) from the
 * Dilithium and Kyber matrix-expansion paths.
 *
 * Public contract (byte-for-byte identical to running four
 * independent ama_shake128_inc_* streams):
 *
 *   for lane in 0..3:
 *       ama_shake128_inc_init(&ctx_lane)
 *       ama_shake128_inc_absorb(&ctx_lane, in_lane, in_len_lane)
 *       ama_shake128_inc_finalize(&ctx_lane)
 *       ama_shake128_inc_squeeze(&ctx_lane, out_lane, nblocks * 168)
 *
 * The x4 variant is only a performance optimization: each lane's
 * Keccak state is independent, the four states are packed into YMM
 * registers on AVX2 (one theta/rho/pi/chi/iota sequence per round),
 * and unpacked identically.  Generic fallback invokes the
 * single-state dispatch pointer four times.
 *
 * Inputs:
 *   - Each input buffer MUST fit within a single SHAKE128 block
 *     (<= SHAKE128_RATE = 168 bytes).  The matrix-expansion callers
 *     use 32-byte seeds + 2-byte index pairs = 34 bytes, well under.
 *   - Output buffers must hold nblocks * 168 bytes per lane.
 *
 * This file is internal; do not include it from headers published
 * under include/.
 */

#ifndef AMA_INTERNAL_SHA3_X4_H
#define AMA_INTERNAL_SHA3_X4_H

#include "ama_cryptography.h"
#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

#define AMA_SHAKE128_X4_RATE 168

typedef struct {
    _Alignas(64) uint64_t states[4][25];
    size_t blocks_squeezed;   /* count of full rate blocks emitted per lane */
    int finalized;
} ama_shake128_x4_ctx;

/**
 * Absorb four short inputs (each <= 168 bytes), apply SHAKE128
 * domain separator 0x1F and final-bit 0x80, and leave all four
 * states ready to squeeze via ama_shake128_x4_squeezeblocks().
 *
 * Returns AMA_ERROR_INVALID_PARAM if any input is NULL or exceeds
 * one rate block; AMA_SUCCESS otherwise.
 */
ama_error_t ama_shake128_x4_absorb_once(
    ama_shake128_x4_ctx *ctx,
    const uint8_t *in0, size_t in0_len,
    const uint8_t *in1, size_t in1_len,
    const uint8_t *in2, size_t in2_len,
    const uint8_t *in3, size_t in3_len);

/**
 * Squeeze nblocks * 168 bytes from each lane.  On AVX2 the four
 * permutations run interleaved in a single 24-round loop; on other
 * tiers, the single-state dispatch pointer is called four times per
 * block.
 *
 * Must be preceded by ama_shake128_x4_absorb_once().  Can be called
 * repeatedly; each call advances every lane's squeeze position by
 * nblocks * 168 bytes.
 */
ama_error_t ama_shake128_x4_squeezeblocks(
    ama_shake128_x4_ctx *ctx,
    uint8_t *out0,
    uint8_t *out1,
    uint8_t *out2,
    uint8_t *out3,
    size_t nblocks);

#ifdef __cplusplus
}
#endif

#endif /* AMA_INTERNAL_SHA3_X4_H */
