/* Copyright (C) 2025-2026 Steel Security Advisors LLC */
/* SPDX-License-Identifier: Apache-2.0 */
/**
 * @file ama_neon_dit.h
 * @brief Lane moves between general and NEON registers, pinned to
 *        instructions on Arm's DIT list.
 *
 * Arm's Data Independent Timing list (tools/ct_operand/allowlists.json, from
 * the DIT register description, DDI 0601) names UMOV, INS and DUP for moving
 * a lane between the general and SIMD files, and does not name FMOV.  gcc 13
 * lowers vgetq_lane_u64(v, 0) to `fmov x, d`, vgetq_lane_u32(v, 0) to
 * `fmov w, s`, and vcombine_u64(vcreate_u64(a), vcreate_u64(b)) to
 * `fmov d, x` + `ins`, so a kernel written only in listed operations still
 * moved secret state with an unlisted instruction (Keccak theta's column
 * parities, the AES-256 key schedule's words).  These helpers name the
 * encoding instead of leaving it to the compiler.
 *
 * GNU C inline assembly only; elsewhere (MSVC ARM64, which this repository
 * does not analyse) they fall back to the intrinsic.
 */
#ifndef AMA_NEON_DIT_H
#define AMA_NEON_DIT_H

#include <stdint.h>

/* AArch64 only, as ama_neon_internal.h: on any other target (a static
 * analyser reading this header on x86-64, say) it declares nothing. */
#if defined(__aarch64__) || defined(_M_ARM64)
#include <arm_neon.h>

/* Lane 0 of a 2 x 64-bit vector, by UMOV. */
static inline uint64_t ama_neon_lane0_u64(uint64x2_t v) {
#if defined(__GNUC__) || defined(__clang__)
    uint64_t r;
    __asm__("umov %0, %1.d[0]" : "=r"(r) : "w"(v));
    return r;
#else
    return vgetq_lane_u64(v, 0);
#endif
}

/* Lane 1 of a 2 x 64-bit vector, by UMOV. */
static inline uint64_t ama_neon_lane1_u64(uint64x2_t v) {
#if defined(__GNUC__) || defined(__clang__)
    uint64_t r;
    __asm__("umov %0, %1.d[1]" : "=r"(r) : "w"(v));
    return r;
#else
    return vgetq_lane_u64(v, 1);
#endif
}

/* Lane 0 of a 4 x 32-bit vector, by UMOV. */
static inline uint32_t ama_neon_lane0_u32(uint32x4_t v) {
#if defined(__GNUC__) || defined(__clang__)
    uint32_t r;
    __asm__("umov %w0, %1.s[0]" : "=r"(r) : "w"(v));
    return r;
#else
    return vgetq_lane_u32(v, 0);
#endif
}

/* Lane 3 of a 4 x 32-bit vector, by UMOV. */
static inline uint32_t ama_neon_lane3_u32(uint32x4_t v) {
#if defined(__GNUC__) || defined(__clang__)
    uint32_t r;
    __asm__("umov %w0, %1.s[3]" : "=r"(r) : "w"(v));
    return r;
#else
    return vgetq_lane_u32(v, 3);
#endif
}

/* {lo, hi} as a 2 x 64-bit vector, by DUP then INS. */
static inline uint64x2_t ama_neon_u64x2(uint64_t lo, uint64_t hi) {
#if defined(__GNUC__) || defined(__clang__)
    uint64x2_t v;
    __asm__("dup %0.2d, %1\n\tins %0.d[1], %2" : "=&w"(v) : "r"(lo), "r"(hi));
    return v;
#else
    return vcombine_u64(vcreate_u64(lo), vcreate_u64(hi));
#endif
}

#endif /* __aarch64__ || _M_ARM64 */

#endif /* AMA_NEON_DIT_H */
