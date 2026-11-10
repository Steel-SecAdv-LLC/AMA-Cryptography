/* Copyright (C) 2025-2026 Steel Security Advisors LLC */
/* SPDX-License-Identifier: Apache-2.0 */
/**
 * @file ama_dilithium_sve2.c
 * @brief ARM SVE2-optimized ML-DSA-65 (Dilithium) NTT / invNTT
 *
 * SVE2 scalable-vector intrinsics for Dilithium polynomial arithmetic.
 * Every vector loop steps by one whole vector under a constant predicate
 * (svptrue), so the same binary runs on any SVE2 vector width (128-2048
 * bit); see WHOLE VECTORS UNDER A CONSTANT PREDICATE below for why the
 * loops are no longer svwhilelt-predicated, and what a vector length that
 * is not a power of two gets.
 *
 * Dilithium uses q = 8380417 (23-bit prime), so products are up to
 * ~46 bits.  The NTT butterfly requires 64-bit widening multiply
 * followed by 32-bit Montgomery reduction.  SVE2's svmullb_s64 /
 * svmullt_s64 provide the widening multiply for even/odd 32-bit
 * element pairs.
 *
 * AI Co-Architects: Eris + | Eden ~ | Devin * | Claude @
 */

#include "../internal/ama_string_ops.h"  /* first: no vector register holds what memcpy/memset move */
#include <stdint.h>
#include <stddef.h>
#include <string.h>

#if defined(__ARM_FEATURE_SVE2)
#include <arm_sve.h>
#include "ama_sve2_internal.h"
#include "../../../include/ama_cryptography.h"  /* ama_secure_memzero */

#define DILITHIUM_Q     8380417
#define DILITHIUM_N     256
#define DILITHIUM_D     13
#define DILITHIUM_QINV  58728449  /* q^{-1} mod 2^32 */

/* SECRET SCRATCH — INVARIANT-6/12 applied to this file, mirroring
 * ama_kyber_sve2.c.
 *
 * Each NTT/invNTT kernel below stages coefficients through int32_t stack
 * arrays, because SVE2's svmullb/svmullt produce the 64-bit product Dilithium's
 * Montgomery reduction needs only for even/odd element pairs, so the reduction
 * is done element-wise between a store and a reload.  Those coefficients are
 * secret on the signing path: ML-DSA-65 signing NTTs the secret vectors s1/s2
 * and the secret mask y, all reaching here through the wired forward/inverse NTT
 * dispatch slots (ama_dispatch.c) — the same class of secret staging buffer the
 * PR that added the scrub erased in the AES and Kyber kernels while leaving this
 * file, its identical twin, with none (audit M5).
 *
 * The buffers are hoisted to function scope rather than scrubbed where they were
 * declared, exactly as ama_kyber_sve2.c does and for the same reason: declared
 * inside the butterfly loop a scrub would place one compiler barrier per vector
 * iteration in the hottest loop; hoisted, one scrub per public call erases every
 * coefficient any iteration staged, because each iteration overwrites the same
 * storage.
 *
 * Not applied to ama_dilithium_poly_pointwise_sve2: it holds no stack staging
 * buffer — it operates register-to-memory on the caller's polynomials — and the
 * stronger guarantee there is not writing a secret down, not erasing it after. */
#define AMA_DILITHIUM_SVE2_SCRUB(buf) ama_secure_memzero((buf), sizeof(buf))

/* ============================================================================
 * Scalar 64-bit Montgomery reduction for Dilithium
 *
 * Computes: (a * q^{-1} mod 2^32), then (a - t*q) >> 32
 * Input:  |a| < q * 2^32
 * Output: in range (-q, q)
 * ============================================================================ */
static inline int32_t dil_montgomery_reduce_scalar(int64_t a) {
    int32_t t = (int32_t)((int64_t)(int32_t)a * DILITHIUM_QINV);
    return (int32_t)((a - (int64_t)t * DILITHIUM_Q) >> 32);
}

/* NOTE: an SVE2 `barrett_reduce_dil_sve2` helper used to live here but
 * was never called — the NTT/invNTT butterflies use the scalar
 * Montgomery reduction above for the per-element reduction, and the
 * pointwise multiply does the same.  Removed alongside the other
 * unused SVE2 helpers below.
 */

/* NOTE: SVE2 helpers `ama_dilithium_poly_add_sve2`,
 * `ama_dilithium_poly_sub_sve2`, and `ama_dilithium_power2round_sve2`
 * were removed alongside the unwired SVE2 ChaCha20 / Argon2 / SPHINCS+
 * / Ed25519 TUs.  They were never reached from `ama_dispatch.c`
 * (the dispatch table exposes no `dilithium_poly_add` / `_poly_sub` /
 * `_power2round` function-pointer slots) and had no external callers
 * via `grep -rn ama_dilithium_poly_add_sve2 .` — dead code, removed per
 * the project's "no speculative API surface" principle.  The wired
 * surface (forward NTT, inverse NTT, pointwise multiply) is unchanged
 * and remains hooked in the `AMA_HAVE_SVE2_IMPL` block of
 * dispatch_init_internal() in `src/c/dispatch/ama_dispatch.c`.
 */

/* ============================================================================
 * WHOLE VECTORS UNDER A CONSTANT PREDICATE
 *
 * The loops below were svwhilelt_b32-predicated, with svcntp_b32 for the
 * number of active lanes, until 2026-11-10.  WHILELT and CNTP take register
 * operands and are not on Arm's DIT list, and Valgrind cannot execute SVE,
 * so the secret-operand gate could neither run this file nor admit it by
 * reading it (src/c/sve2/ama_kyber_sve2.c has the whole of the argument).
 * Every loop now steps by one full vector under svptrue with plain integer
 * bounds, and the file is compiled without the auto-vectoriser.  The ranges
 * are 256 coefficients and the powers of two under it, tiled by whole
 * vectors exactly when the lane count is a power of two; for a vector
 * length that is not (the architecture allows 384 bits, 12 lanes) this
 * returns 0 and both transforms take the scalar path throughout.
 * ============================================================================ */
static inline uint64_t dil_sve2_lanes(void) {
    const uint64_t lanes = svcntw();
    return (lanes & (lanes - 1u)) == 0u ? lanes : 0u;
}

/* log2 of a lane count dil_sve2_lanes() returned.  The vector loops count
 * whole vectors up to `range >> shift` and form the offset as `v << shift`:
 * stepping an offset by a lane count the compiler cannot see is a power of
 * two made clang 18.1 compute the trip count with UDIV (measured
 * 2026-11-10, one in each forward NTT), and no division is on the DIT list
 * whatever its operands are. */
static inline unsigned dil_sve2_shift(uint64_t lanes) {
    return lanes != 0u ? 63u - (unsigned)__builtin_clzll(lanes) : 0u;
}

/* ============================================================================
 * Forward NTT — Cooley-Tukey butterfly (SVE2 vectorized, 32-bit Dilithium)
 *
 * Signature: void (*)(int32_t poly[256], const int32_t zetas[256])
 *
 * For layers where the butterfly stride (len) >= VL_words we vectorize
 * the inner loop using SVE2 widening multiply (svmullb_s64 / svmullt_s64)
 * for the 64-bit products needed by Montgomery reduction.
 *
 * For narrow layers (len < VL_words) we use scalar Montgomery reduction.
 * ============================================================================ */
void ama_dilithium_ntt_sve2(int32_t poly[DILITHIUM_N],
                             const int32_t zetas[256]) {
    unsigned int log_len, block, len, start, j, k;
    int32_t zeta, t;
    const uint64_t lanes = dil_sve2_lanes();  /* int32_t lanes, or 0: scalar */
    const unsigned shift = dil_sve2_shift(lanes);
    const svbool_t pg = svptrue_b32();

    /* Secret staging buffers, hoisted to function scope and scrubbed once on
     * return — see SECRET SCRATCH above. */
    int32_t hi_buf[64], t_buf[64];

    k = 0;
    /* Layers by the log of their stride and blocks by their count, so every
     * bound is a shift.  Written as `len >>= 1` and `start += 2 * len`, the
     * number of blocks was a quotient the compiler could not see to be a
     * power of two, and clang 18.1 formed it with UDIV (measured 2026-11-10
     * in both forward transforms); no division is on the DIT list. */
    for (log_len = 8; log_len-- > 0;) {
        len = 1u << log_len;
        for (block = 0; block < ((unsigned)DILITHIUM_N >> (log_len + 1u)); block++) {
            start = block << (log_len + 1u);
            zeta = zetas[++k];

            if (lanes != 0u && len >= lanes) {
                /* Vectorized Cooley-Tukey butterfly.
                 * For each pair (poly[lo_idx], poly[hi_idx]):
                 *   t = montgomery_reduce((int64_t)zeta * poly[hi_idx])
                 *   poly[hi_idx] = poly[lo_idx] - t
                 *   poly[lo_idx] = poly[lo_idx] + t
                 *
                 * Montgomery reduction needs 64-bit intermediate:
                 *   full = zeta * hi           (64-bit)
                 *   u = (int32_t)full * QINV   (low 32 bits of full * QINV)
                 *   t = (full - u*Q) >> 32
                 *
                 * We use scalar reduction in a vectorized load/store loop
                 * because SVE2's svmullb/svmullt operate on even/odd pairs
                 * within a single vector, not broadcast-scalar × vector.
                 * The loads and stores are still fully vectorized.
                 */
                for (size_t v = 0; v < ((size_t)len >> shift); v++) {
                    const size_t i = v << shift;
                    svint32_t lo = svld1_s32(pg, poly + start + i);
                    svint32_t hi = svld1_s32(pg, poly + start + len + i);

                    /* Perform Montgomery reduction element-wise.
                     * Extract hi to memory, reduce, re-load.  lo is
                     * used directly as an SVE register for butterfly.
                     * hi_buf/t_buf are function-scope secret scratch. */
                    svst1_s32(pg, hi_buf, hi);

                    for (uint64_t e = 0; e < lanes; e++) {
                        t_buf[e] = dil_montgomery_reduce_scalar(
                            (int64_t)zeta * hi_buf[e]);
                    }

                    svint32_t vt = svld1_s32(pg, t_buf);
                    svst1_s32(pg, poly + start + len + i, svsub_s32_x(pg, lo, vt));
                    svst1_s32(pg, poly + start + i,       svadd_s32_x(pg, lo, vt));
                }
            } else {
                /* Scalar path for narrow layers */
                for (j = start; j < start + len; ++j) {
                    t = dil_montgomery_reduce_scalar((int64_t)zeta * poly[j + len]);
                    poly[j + len] = poly[j] - t;
                    poly[j] = poly[j] + t;
                }
            }
        }
    }
    AMA_DILITHIUM_SVE2_SCRUB(hi_buf);
    AMA_DILITHIUM_SVE2_SCRUB(t_buf);
}

/* ============================================================================
 * Inverse NTT — Gentleman-Sande butterfly (SVE2 vectorized, 32-bit Dilithium)
 *
 * Signature: void (*)(int32_t poly[256], const int32_t zetas[256])
 *
 * Walks the zetas table in reverse (k = 256 → 1).
 * ============================================================================ */
void ama_dilithium_invntt_sve2(int32_t poly[DILITHIUM_N],
                                const int32_t zetas[256]) {
    unsigned int log_len, block, start, len, j, k;
    int32_t t_scalar, zeta;
    const int32_t f = 41978;  /* Mont^(-1) * N^(-1) mod q */
    const uint64_t lanes = dil_sve2_lanes();  /* int32_t lanes, or 0: scalar */
    const unsigned shift = dil_sve2_shift(lanes);
    const svbool_t pg = svptrue_b32();

    /* Secret staging buffers, hoisted to function scope and scrubbed once on
     * return — see SECRET SCRATCH above. */
    int32_t diff_buf[64], hi_buf[64], buf[64];

    k = 256;
    /* Layers and blocks by shifts, as in the forward transform. */
    for (log_len = 0; log_len <= 7; log_len++) {
        len = 1u << log_len;
        for (block = 0; block < ((unsigned)DILITHIUM_N >> (log_len + 1u)); block++) {
            start = block << (log_len + 1u);
            zeta = -zetas[--k];

            if (lanes != 0u && len >= lanes) {
                for (size_t v = 0; v < ((size_t)len >> shift); v++) {
                    const size_t i = v << shift;
                    svint32_t lo = svld1_s32(pg, poly + start + i);
                    svint32_t hi = svld1_s32(pg, poly + start + len + i);

                    /* GS butterfly:
                     *   t = lo
                     *   lo = t + hi
                     *   hi = montgomery_reduce(zeta * (t - hi)) */
                    svint32_t sum  = svadd_s32_x(pg, lo, hi);
                    svint32_t diff = svsub_s32_x(pg, lo, hi);

                    /* Montgomery reduction of zeta * diff.
                     * diff_buf/hi_buf are function-scope secret scratch. */
                    svst1_s32(pg, diff_buf, diff);

                    for (uint64_t e = 0; e < lanes; e++) {
                        hi_buf[e] = dil_montgomery_reduce_scalar(
                            (int64_t)zeta * diff_buf[e]);
                    }

                    svst1_s32(pg, poly + start + i,       sum);
                    svint32_t vhi = svld1_s32(pg, hi_buf);
                    svst1_s32(pg, poly + start + len + i, vhi);
                }
            } else {
                /* Scalar path for narrow layers */
                for (j = start; j < start + len; ++j) {
                    t_scalar = poly[j];
                    poly[j] = t_scalar + poly[j + len];
                    poly[j + len] = t_scalar - poly[j + len];
                    poly[j + len] = dil_montgomery_reduce_scalar(
                        (int64_t)zeta * poly[j + len]);
                }
            }
        }
    }

    /* Final scaling by f = Mont^{-1} * N^{-1} mod q */
    if (lanes != 0u) {
        for (size_t v = 0; v < ((size_t)DILITHIUM_N >> shift); v++) {
            const size_t i = v << shift;
            svint32_t va = svld1_s32(pg, poly + i);
            svst1_s32(pg, buf, va);  /* buf is function-scope secret scratch */

            for (uint64_t e = 0; e < lanes; e++) {
                buf[e] = dil_montgomery_reduce_scalar((int64_t)f * buf[e]);
            }

            svint32_t vr = svld1_s32(pg, buf);
            svst1_s32(pg, poly + i, vr);
        }
    } else {
        for (size_t i = 0; i < DILITHIUM_N; i++) {
            poly[i] = dil_montgomery_reduce_scalar((int64_t)f * poly[i]);
        }
    }
    AMA_DILITHIUM_SVE2_SCRUB(diff_buf);
    AMA_DILITHIUM_SVE2_SCRUB(hi_buf);
    AMA_DILITHIUM_SVE2_SCRUB(buf);
}

/* ============================================================================
 * SVE2 polynomial pointwise multiply with 64-bit Montgomery reduction
 * ============================================================================ */
void ama_dilithium_poly_pointwise_sve2(int32_t r[DILITHIUM_N],
                                        const int32_t a[DILITHIUM_N],
                                        const int32_t b[DILITHIUM_N]) {
    for (int i = 0; i < DILITHIUM_N; i++) {
        r[i] = dil_montgomery_reduce_scalar((int64_t)a[i] * b[i]);
    }
}

#else
typedef int ama_dilithium_sve2_not_available;
#endif /* __ARM_FEATURE_SVE2 */
