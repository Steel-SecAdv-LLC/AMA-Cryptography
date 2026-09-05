/* Copyright (C) 2025-2026 Steel Security Advisors LLC */
/* SPDX-License-Identifier: Apache-2.0 */
/**
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
#include "ama_neon_internal.h"

/* Defined in ama_consttime.c; forward-declared to avoid pulling the full
 * public header into this kernel TU (mirrors src/c/ama_sha256.c). */
extern void ama_secure_memzero(void *ptr, size_t len);

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
    uint64_t scratch[16];
    for (int col = 0; col < 8; col++) {
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

    /* R/Z/scratch hold password-derived block material; the driver scrubs
     * its heap matrix (ama_argon2.c) but the last invocation's stack frame
     * would otherwise survive.  Same INVARIANT-6/12 treatment the AVX2
     * dilithium/AES-GCM kernels give their staging buffers. */
    ama_secure_memzero(R, sizeof(R));
    ama_secure_memzero(Z, sizeof(Z));
    ama_secure_memzero(scratch, sizeof(scratch));
}

#else
typedef int ama_argon2_neon_not_available;
#endif /* __aarch64__ */
