/* Copyright (C) 2025-2026 Steel Security Advisors LLC */
/* SPDX-License-Identifier: Apache-2.0 */
/**
 * @file ama_wide_mul.h
 * @brief 64 x 64 -> 128-bit unsigned multiplication on every supported
 *        toolchain.
 *
 * GCC and Clang have a 128-bit integer type; MSVC has the _umul128 (x64) and
 * __umulh (ARM64) intrinsics instead; anything else gets four 32-bit
 * products.  The product is exact on all three routes, so code built on this
 * header — the Ed25519 verify scalar reduction, the MSVC field arithmetic —
 * computes the same bytes everywhere.
 */
#ifndef AMA_WIDE_MUL_H
#define AMA_WIDE_MUL_H

#include <stdint.h>

#if defined(__SIZEOF_INT128__)

__extension__ typedef unsigned __int128 ama_uint128;

/* lo = low 64 bits of a * b; returns the high 64 bits. */
static inline uint64_t ama_umul128(uint64_t a, uint64_t b, uint64_t *lo) {
    ama_uint128 p = (ama_uint128)a * b;
    *lo = (uint64_t)p;
    return (uint64_t)(p >> 64);
}

#elif defined(_MSC_VER) && defined(_M_X64)

#include <intrin.h>
#pragma intrinsic(_umul128)

static inline uint64_t ama_umul128(uint64_t a, uint64_t b, uint64_t *lo) {
    uint64_t hi;
    *lo = _umul128(a, b, &hi);
    return hi;
}

#elif defined(_MSC_VER) && defined(_M_ARM64)

#include <intrin.h>

static inline uint64_t ama_umul128(uint64_t a, uint64_t b, uint64_t *lo) {
    *lo = a * b;
    return __umulh(a, b);
}

#else

static inline uint64_t ama_umul128(uint64_t a, uint64_t b, uint64_t *lo) {
    const uint64_t a0 = (uint32_t)a, a1 = a >> 32;
    const uint64_t b0 = (uint32_t)b, b1 = b >> 32;
    const uint64_t p00 = a0 * b0, p01 = a0 * b1, p10 = a1 * b0, p11 = a1 * b1;
    const uint64_t mid = (p00 >> 32) + (uint32_t)p01 + (uint32_t)p10;
    *lo = (mid << 32) | (uint32_t)p00;
    return p11 + (p01 >> 32) + (p10 >> 32) + (mid >> 32);
}

#endif

#endif /* AMA_WIDE_MUL_H */
