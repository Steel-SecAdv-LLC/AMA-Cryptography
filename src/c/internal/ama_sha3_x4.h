/**
 * Copyright 2025-2026 Steel Security Advisors LLC
 * Licensed under the Apache License, Version 2.0
 *
 * @file internal/ama_sha3_x4.h
 * @brief 4-way batched SHAKE128 / SHAKE256 wrappers (internal, not exported)
 *
 * Drives the existing AVX2 4-lane Keccak-f[1600] permutation
 * (ama_keccak_f1600_x4_avx2 in src/c/avx2/ama_sha3_avx2.c) from the
 * Dilithium and Kyber sampling paths.
 *
 * Public contract (byte-for-byte identical to running four
 * independent ama_shakeNNN_inc_* streams):
 *
 *   for lane in 0..3:
 *       ama_shakeNNN_inc_init(&ctx_lane)
 *       ama_shakeNNN_inc_absorb(&ctx_lane, in_lane, in_len_lane)
 *       ama_shakeNNN_inc_finalize(&ctx_lane)
 *       ama_shakeNNN_inc_squeeze(&ctx_lane, out_lane, nblocks * rate)
 *
 * The x4 variant is only a performance optimization: each lane's
 * Keccak state is independent, the four states are packed into YMM
 * registers on AVX2 (one theta/rho/pi/chi/iota sequence per round),
 * and unpacked identically.  Generic fallback invokes the
 * single-state dispatch pointer four times.
 *
 * Inputs:
 *   - Each input buffer MUST be STRICTLY smaller than a single rate
 *     block (SHAKE128_X4_RATE = 168, SHAKE256_X4_RATE = 136 bytes).
 *     A full-rate input would require a second padding block; the
 *     one-block fast path here cannot safely write the 0x1F domain
 *     separator at block[in_len] when in_len == rate.  Callers whose
 *     inputs are 32-66 bytes (matrix/noise seed + nonce) meet this
 *     bound by a wide margin; absorb_once() returns
 *     AMA_ERROR_INVALID_PARAM for in_len >= rate.
 *   - Output buffers must hold nblocks * rate bytes per lane.
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
#define AMA_SHAKE256_X4_RATE 136

typedef struct {
    _Alignas(64) uint64_t states[4][25];
    size_t blocks_squeezed;   /* count of full rate blocks emitted per lane */
    int finalized;
} ama_shake128_x4_ctx;

/* SHAKE128 and SHAKE256 share the same 4-lane Keccak state layout;
 * only the rate (168 vs 136) and the padding/squeeze step differ.
 * Reusing the struct keeps stack footprint predictable across callers. */
typedef ama_shake128_x4_ctx ama_shake256_x4_ctx;

/* ------------------------------------------------------------------ */
/* SHAKE128 x4                                                        */
/* ------------------------------------------------------------------ */

/**
 * Absorb four short inputs (each STRICTLY less than
 * AMA_SHAKE128_X4_RATE = 168 bytes), apply the SHAKE domain separator
 * 0x1F and final-bit 0x80, and leave all four states ready to squeeze
 * via ama_shake128_x4_squeezeblocks().
 *
 * Returns AMA_ERROR_INVALID_PARAM if any input is NULL or is
 * >= AMA_SHAKE128_X4_RATE; AMA_SUCCESS otherwise.  See the file-level
 * comment for why full-rate inputs are rejected rather than padded
 * across two blocks.
 */
ama_error_t ama_shake128_x4_absorb_once(
    ama_shake128_x4_ctx *ctx,
    const uint8_t *in0, size_t in0_len,
    const uint8_t *in1, size_t in1_len,
    const uint8_t *in2, size_t in2_len,
    const uint8_t *in3, size_t in3_len);

/**
 * Squeeze nblocks * 168 bytes from each lane.  Must be preceded by
 * ama_shake128_x4_absorb_once().  Multi-call safe; each call advances
 * every lane's squeeze position by nblocks * 168 bytes.
 */
ama_error_t ama_shake128_x4_squeezeblocks(
    ama_shake128_x4_ctx *ctx,
    uint8_t *out0,
    uint8_t *out1,
    uint8_t *out2,
    uint8_t *out3,
    size_t nblocks);

/* ------------------------------------------------------------------ */
/* SHAKE256 x4                                                        */
/* ------------------------------------------------------------------ */

/**
 * Same contract as ama_shake128_x4_absorb_once() but with
 * SHAKE256 rate = AMA_SHAKE256_X4_RATE = 136 bytes.  Same SHAKE
 * domain separator (0x1F); only the capacity/rate differ per
 * FIPS 202.  Each input must be STRICTLY less than 136 bytes;
 * in_len >= rate returns AMA_ERROR_INVALID_PARAM for the same
 * padding-safety reason as the SHAKE128 variant.
 */
ama_error_t ama_shake256_x4_absorb_once(
    ama_shake256_x4_ctx *ctx,
    const uint8_t *in0, size_t in0_len,
    const uint8_t *in1, size_t in1_len,
    const uint8_t *in2, size_t in2_len,
    const uint8_t *in3, size_t in3_len);

/**
 * Squeeze nblocks * 136 bytes from each SHAKE256 lane.
 */
ama_error_t ama_shake256_x4_squeezeblocks(
    ama_shake256_x4_ctx *ctx,
    uint8_t *out0,
    uint8_t *out1,
    uint8_t *out2,
    uint8_t *out3,
    size_t nblocks);

#ifdef __cplusplus
}
#endif

#endif /* AMA_INTERNAL_SHA3_X4_H */
