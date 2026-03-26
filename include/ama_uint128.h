/**
 * Copyright 2025-2026 Steel Security Advisors LLC
 * Licensed under the Apache License, Version 2.0
 *
 * @file ama_uint128.h
 * @brief Portable 128-bit unsigned integer for GCC/Clang and MSVC
 *
 * GCC/Clang: thin wrapper around native unsigned __int128.
 * MSVC x64:  {lo, hi} struct with _umul128 / __shiftright128 intrinsics.
 *
 * Provides a single type `ama_uint128` and inline helpers so that
 * cryptographic field arithmetic (Ed25519 fe51, Poly1305) compiles
 * identically on all three major compilers.
 *
 * AI Co-Architects: Eris + | Eden ~ | Devin * | Claude @
 */

#ifndef AMA_UINT128_H
#define AMA_UINT128_H

#include <stdint.h>

/* ===================================================================
 * GCC / Clang — native 128-bit integer
 * =================================================================== */
#if defined(__GNUC__) || defined(__clang__)

typedef unsigned __int128 ama_uint128;

#define AMA_MUL64(a, b)       ((ama_uint128)(a) * (b))
#define AMA_U128_LO(x)        ((uint64_t)(x))
#define AMA_U128_HI(x)        ((uint64_t)((x) >> 64))
#define AMA_U128_SHR(x, n)    ((x) >> (n))
#define AMA_U128_ADD(a, b)     ((a) + (b))
#define AMA_U128_ADD64(a, b)   ((a) + (uint64_t)(b))
#define AMA_U128_FROM64(a)     ((ama_uint128)(a))

/* ===================================================================
 * MSVC x64 — struct + intrinsics
 * =================================================================== */
#elif defined(_MSC_VER) && defined(_M_X64)

#include <intrin.h>

typedef struct {
    uint64_t lo;
    uint64_t hi;
} ama_uint128;

/* 64×64 → 128 unsigned multiply */
static __forceinline ama_uint128 ama_mul64(uint64_t a, uint64_t b) {
    ama_uint128 r;
    r.lo = _umul128(a, b, &r.hi);
    return r;
}

/* Extract low 64 bits */
static __forceinline uint64_t ama_u128_lo(ama_uint128 x) {
    return x.lo;
}

/* Extract high 64 bits */
static __forceinline uint64_t ama_u128_hi(ama_uint128 x) {
    return x.hi;
}

/* Right-shift by n bits (0 < n < 128) */
static __forceinline ama_uint128 ama_u128_shr(ama_uint128 x, int n) {
    ama_uint128 r;
    if (n == 0) {
        return x;
    } else if (n < 64) {
        r.lo = __shiftright128(x.lo, x.hi, (unsigned char)n);
        r.hi = x.hi >> n;
    } else if (n == 64) {
        r.lo = x.hi;
        r.hi = 0;
    } else {
        r.lo = x.hi >> (n - 64);
        r.hi = 0;
    }
    return r;
}

/* 128 + 128 addition */
static __forceinline ama_uint128 ama_u128_add(ama_uint128 a, ama_uint128 b) {
    ama_uint128 r;
    r.lo = a.lo + b.lo;
    r.hi = a.hi + b.hi + (r.lo < a.lo);
    return r;
}

/* 128 + 64 addition */
static __forceinline ama_uint128 ama_u128_add64(ama_uint128 a, uint64_t b) {
    ama_uint128 r;
    r.lo = a.lo + b;
    r.hi = a.hi + (r.lo < a.lo);
    return r;
}

/* Widen a uint64_t to ama_uint128 */
static __forceinline ama_uint128 ama_u128_from64(uint64_t a) {
    ama_uint128 r;
    r.lo = a;
    r.hi = 0;
    return r;
}

#define AMA_MUL64(a, b)       ama_mul64((a), (b))
#define AMA_U128_LO(x)        ama_u128_lo((x))
#define AMA_U128_HI(x)        ama_u128_hi((x))
#define AMA_U128_SHR(x, n)    ama_u128_shr((x), (n))
#define AMA_U128_ADD(a, b)     ama_u128_add((a), (b))
#define AMA_U128_ADD64(a, b)   ama_u128_add64((a), (b))
#define AMA_U128_FROM64(a)     ama_u128_from64((a))

#else
#error "ama_uint128.h: unsupported compiler — need GCC, Clang, or MSVC x64"
#endif

#endif /* AMA_UINT128_H */
