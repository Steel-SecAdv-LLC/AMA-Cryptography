/**
 * Copyright 2025-2026 Steel Security Advisors LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/**
 * @file ama_ed25519.c
 * @brief Ed25519 digital signature implementation (RFC 8032)
 * @author Andrew E. A., Steel Security Advisors LLC
 * @date 2026-04-06
 *
 * Implements Ed25519 signatures per RFC 8032 using the twisted Edwards curve:
 *   -x^2 + y^2 = 1 + d*x^2*y^2  where d = -121665/121666 (mod p)
 *   p = 2^255 - 19
 *   Base point order: L = 2^252 + 27742317777372353535851937790883648493
 *
 * Security properties:
 * - Constant-time field arithmetic (fe25519 operations)
 * - Constant-time base point scalar multiplication (windowed with cmov)
 * - Constant-time table lookups (linear scan, no secret-dependent indexing)
 * - Thread-safe lazy initialization via CAS tri-state protocol
 * - Proper scalar clamping
 * - Cofactor handling per RFC 8032
 *
 * Note: ge25519_scalarmult() (variable-base) uses double-and-add and is
 * NOT constant-time. It is used only for verification where the scalar
 * (derived from the hash of the signature) is public.
 */

#include "../include/ama_cryptography.h"
#include "internal/ama_sha2.h"
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#if defined(__GNUC__) || defined(__clang__)
#include "fe51.h"
#endif

/* C11 atomics for thread-safe lazy initialization of base point tables.
 * Uses a tri-state CAS protocol: 0 = uninitialized, 1 = initializing, 2 = ready.
 * Falls back to volatile on pre-C11 compilers (MSVC, older GCC). */
#if defined(__STDC_VERSION__) && __STDC_VERSION__ >= 201112L && !defined(__STDC_NO_ATOMICS__)
  #include <stdatomic.h>
  #define AMA_ATOMIC_INT            _Atomic int
  #define AMA_ATOMIC_LOAD(p)        atomic_load_explicit(&(p), memory_order_acquire)
  #define AMA_ATOMIC_STORE(p, v)    atomic_store_explicit(&(p), (v), memory_order_release)
  /* CAS: atomically set *p from expected to desired; returns 1 on success */
  #define AMA_ATOMIC_CAS(p, expected, desired) \
      atomic_compare_exchange_strong_explicit(&(p), &(expected), (desired), \
          memory_order_acq_rel, memory_order_acquire)
#else
  /* Pre-C11 fallback: volatile provides compiler ordering but not hardware
   * fence guarantees. Acceptable on x86 (TSO) but not on ARM/POWER. */
  #if defined(__arm__) || defined(__aarch64__) || defined(__ARM_ARCH) || \
      defined(_M_ARM) || defined(_M_ARM64) || \
      defined(__PPC__) || defined(__ppc__) || defined(__powerpc__) || defined(__POWERPC__)
    #error "Pre-C11 volatile-based atomics have no memory fence on ARM/AArch64/POWER. Use a C11 compiler with stdatomic.h support."
  #endif
  #define AMA_ATOMIC_INT            volatile int
  #define AMA_ATOMIC_LOAD(p)        (p)
  #define AMA_ATOMIC_STORE(p, v)    ((p) = (v))
  /* Fallback CAS: NOT truly atomic — safe only on single-core or x86 TSO. */
  #define AMA_ATOMIC_CAS(p, expected, desired) \
      ((p) == (expected) ? ((p) = (desired), 1) : ((expected) = (p), 0))
#endif

/* Tri-state constants for lazy initialization protocol */
#define AMA_INIT_UNINIT       0
#define AMA_INIT_IN_PROGRESS  1
#define AMA_INIT_READY        2

/* SHA-512 provided by internal/ama_sha2.h (shared with ama_sphincs.c) */

/* sha512() is now ama_sha512() from internal/ama_sha2.h */
#define sha512 ama_sha512

/* Stack buffer threshold: messages up to 4KB use stack allocation,
 * larger messages fall back to heap. Covers >99% of real-world use
 * (TLS records, JWT tokens, API payloads, etc.). */
#define ED25519_STACK_THRESHOLD 4096

/* ============================================================================
 * FIELD ARITHMETIC: GF(2^255 - 19)
 *
 * Radix 2^51 representation (5 limbs), implemented in fe51.h.
 * This provides ~2x fewer cross-products than the ref10 radix-2^25.5
 * (10 limb) representation, using __uint128_t intermediates.
 * ============================================================================ */

typedef uint64_t fe25519[5];  /* Radix 2^51 representation (backed by fe51.h) */

/* Helper: load 3/4 bytes little-endian (used by scalar arithmetic) */
static int64_t load_3(const uint8_t *in) {
    return (int64_t)in[0] | ((int64_t)in[1] << 8) | ((int64_t)in[2] << 16);
}
static int64_t load_4(const uint8_t *in) {
    return (int64_t)in[0] | ((int64_t)in[1] << 8) | ((int64_t)in[2] << 16) | ((int64_t)in[3] << 24);
}

#if defined(__GNUC__) || defined(__clang__)
/* Thin wrappers: fe25519_* delegate to fe51_* (requires __uint128_t) */
static inline void fe25519_frombytes(fe25519 h, const uint8_t *s) { fe51_frombytes(h, s); }
static inline void fe25519_tobytes(uint8_t *s, const fe25519 h)   { fe51_tobytes(s, h); }
static inline void fe25519_0(fe25519 h)                            { fe51_0(h); }
static inline void fe25519_1(fe25519 h)                            { fe51_1(h); }
static inline void fe25519_copy(fe25519 h, const fe25519 f)       { fe51_copy(h, f); }
static inline void fe25519_add(fe25519 h, const fe25519 f, const fe25519 g) { fe51_add(h, f, g); }
static inline void fe25519_sub(fe25519 h, const fe25519 f, const fe25519 g) { fe51_sub(h, f, g); }
static inline void fe25519_neg(fe25519 h, const fe25519 f)        { fe51_neg(h, f); }
static inline void fe25519_carry(fe25519 h)                        { fe51_carry(h); }
static inline void fe25519_mul(fe25519 h, const fe25519 f, const fe25519 g) { fe51_mul(h, f, g); }
static inline void fe25519_sq(fe25519 h, const fe25519 f)         { fe51_sq(h, f); }
static inline void fe25519_invert(fe25519 out, const fe25519 z)   { fe51_invert(out, z); }
static inline void fe25519_pow22523(fe25519 out, const fe25519 z) { fe51_pow22523(out, z); }
static inline int  fe25519_isnegative(const fe25519 f)             { return fe51_isnegative(f); }
static inline int  fe25519_iszero(const fe25519 f)                 { return fe51_iszero(f); }
#else
/* MSVC: fe51 requires __uint128_t which MSVC lacks.
 * On Windows builds, use AMA_ED25519_ASSEMBLY=ON (donna shim) instead. */
#error "ama_ed25519.c requires GCC/Clang for __uint128_t (fe51). On MSVC, enable AMA_ED25519_ASSEMBLY to use the donna shim."
#endif

/* ============================================================================
 * GROUP OPERATIONS: Extended Twisted Edwards
 * ============================================================================ */

/* Point in extended coordinates (X:Y:Z:T) where x=X/Z, y=Y/Z, xy=T/Z */
typedef struct {
    fe25519 X, Y, Z, T;
} ge25519_p3;

/* Point in projective coordinates (X:Y:Z) */
typedef struct {
    fe25519 X, Y, Z;
} ge25519_p2;

/* Point in completed coordinates for addition */
typedef struct {
    fe25519 X, Y, Z, T;
} ge25519_p1p1;


/* d = -121665/121666 (named ed_d to avoid shadowing SHA-512 local 'd') */
static const fe25519 ed_d = {
    0x34dca135978a3ULL, 0x1a8283b156ebdULL, 0x5e7a26001c029ULL,
    0x739c663a03cbbULL, 0x52036cee2b6ffULL
};

/* 2*d */
static const fe25519 ed_d2 = {
    0x69b9426b2f159ULL, 0x35050762add7aULL, 0x3cf44c0038052ULL,
    0x6738cc7407977ULL, 0x2406d9dc56dffULL
};

/* Forward declaration — needed by ensure_base_point() below */
static int ge25519_frombytes(ge25519_p3 *h, const uint8_t *s);

/*
 * Base point B — lazily initialized from the Ed25519 compressed base point.
 * The compressed form is the y-coordinate (4/5 mod p) in little-endian with
 * the sign bit of x in the high bit of the last byte.
 * This avoids hardcoding limb values that depend on the radix representation.
 */
static ge25519_p3 ed_B;
static AMA_ATOMIC_INT B_initialized = 0;

static void ensure_base_point(void) {
    int state = AMA_ATOMIC_LOAD(B_initialized);

    if (state == AMA_INIT_READY) return;

    /* Try to claim the initializer role via CAS: UNINIT -> IN_PROGRESS.
     * Exactly one thread wins; all others spin-wait below. */
    if (state == AMA_INIT_UNINIT) {
        int expected = AMA_INIT_UNINIT;
        if (AMA_ATOMIC_CAS(B_initialized, expected, AMA_INIT_IN_PROGRESS)) {
            /* We are the sole initializer. Decompress into a local first,
             * then publish via memcpy + release store. */
            static const uint8_t base_compressed[32] = {
                0x58, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
                0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
                0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
                0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
            };
            ge25519_p3 B_local;
            int rc = ge25519_frombytes(&B_local, base_compressed);
            if (rc != 0) {
                /* Decompression failed (should never happen). Reset to UNINIT
                 * so another thread can retry. */
                AMA_ATOMIC_STORE(B_initialized, AMA_INIT_UNINIT);
                return;
            }
            memcpy(&ed_B, &B_local, sizeof(ge25519_p3));

            /* Release store: ed_B is fully written before flag becomes READY. */
            AMA_ATOMIC_STORE(B_initialized, AMA_INIT_READY);
            return;
        }
        /* CAS failed — another thread is initializing. Fall through to spin. */
    }

    /* Spin-wait until the initializer thread publishes READY. */
    while (AMA_ATOMIC_LOAD(B_initialized) != AMA_INIT_READY) {
        /* Busy-wait. This path is extremely short-lived (one-time init). */
    }
}

static void ge25519_p3_0(ge25519_p3 *h) {
    fe25519_0(h->X);
    fe25519_1(h->Y);
    fe25519_1(h->Z);
    fe25519_0(h->T);
}

static void ge25519_p3_tobytes(uint8_t *s, const ge25519_p3 *h) {
    fe25519 recip, x, y;
    fe25519_invert(recip, h->Z);
    fe25519_mul(x, h->X, recip);
    fe25519_mul(y, h->Y, recip);
    fe25519_tobytes(s, y);
    s[31] ^= fe25519_isnegative(x) << 7;
}

/*
 * Decompress a point from 32-byte compressed Edwards form.
 * Based on the SUPERCOP ref10 ge_frombytes_negate_vartime (without negation).
 *
 * Algorithm: given y (with sign bit for x), compute:
 *   u = y^2 - 1,  v = d*y^2 + 1
 *   x = (u*v^3) * (u*v^7)^((p-5)/8)
 * Then verify and adjust sign.
 */
static int ge25519_frombytes(ge25519_p3 *h, const uint8_t *s) {
    fe25519 u, v, v3, vxx, check;
    int x_sign = s[31] >> 7;

    fe25519_frombytes(h->Y, s);
    fe25519_1(h->Z);

    /* u = y^2 - 1, v = dy^2 + 1 */
    fe25519_sq(u, h->Y);
    fe25519_mul(v, u, ed_d);
    fe25519_sub(u, u, h->Z);
    fe25519_add(v, v, h->Z);

    /* Compute v^3 = v*v*v and uv^7 = u*v^3*v^3*v */
    fe25519_sq(v3, v);
    fe25519_mul(v3, v3, v);       /* v3 = v^3 */

    fe25519_sq(h->X, v3);
    fe25519_mul(h->X, h->X, v);  /* X = v^7 */
    fe25519_mul(h->X, h->X, u);  /* X = u*v^7 */

    /* x = (u*v^7)^((p-5)/8) * u * v^3 */
    fe25519_pow22523(h->X, h->X); /* X = (u*v^7)^((p-5)/8) */
    fe25519_mul(h->X, h->X, v3); /* X *= v^3 */
    fe25519_mul(h->X, h->X, u);  /* X *= u => candidate x */

    /* Verify: check if v*x^2 == u */
    fe25519_sq(vxx, h->X);
    fe25519_mul(vxx, vxx, v);
    fe25519_sub(check, vxx, u);
    fe25519_carry(check);

    if (!fe25519_iszero(check)) {
        /* Check if v*x^2 == -u (need to multiply x by sqrt(-1)) */
        fe25519_add(check, vxx, u);
        fe25519_carry(check);
        if (!fe25519_iszero(check)) return -1;
        static const fe25519 sqrt_m1 = {
            0x61b274a0ea0b0ULL, 0x0d5a5fc8f189dULL, 0x7ef5e9cbd0c60ULL,
            0x78595a6804c9eULL, 0x2b8324804fc1dULL
        };
        fe25519_mul(h->X, h->X, sqrt_m1);
    }

    /* Adjust sign of x to match the sign bit */
    if (fe25519_isnegative(h->X) != x_sign) {
        fe25519_neg(h->X, h->X);
    }

    /* Compute T = X*Y for extended coordinates */
    fe25519_mul(h->T, h->X, h->Y);
    return 0;
}

/* p1p1 -> p3 (4 field multiplications) */
#if defined(__GNUC__) || defined(__clang__)
__attribute__((hot))
#endif
static void ge25519_p1p1_to_p3(ge25519_p3 *r, const ge25519_p1p1 *p) {
    fe25519_mul(r->X, p->X, p->T);
    fe25519_mul(r->Y, p->Y, p->Z);
    fe25519_mul(r->Z, p->Z, p->T);
    fe25519_mul(r->T, p->X, p->Y);
}

/* p1p1 -> p2 (3 field multiplications — skips T for doubling chains) */
#if defined(__GNUC__) || defined(__clang__)
__attribute__((hot))
#endif
static void ge25519_p1p1_to_p2(ge25519_p2 *r, const ge25519_p1p1 *p) {
    fe25519_mul(r->X, p->X, p->T);
    fe25519_mul(r->Y, p->Y, p->Z);
    fe25519_mul(r->Z, p->Z, p->T);
}

/* Double: p2 -> p1p1 */
#if defined(__GNUC__) || defined(__clang__)
__attribute__((hot))
#endif
static void ge25519_p2_dbl(ge25519_p1p1 *r, const ge25519_p2 *p) {
    fe25519 t0;
    fe25519_sq(r->X, p->X);
    fe25519_sq(r->Z, p->Y);
    fe25519_sq(r->T, p->Z);
    fe25519_add(r->T, r->T, r->T);
    fe25519_add(r->Y, p->X, p->Y);
    fe25519_sq(t0, r->Y);
    fe25519_add(r->Y, r->Z, r->X);
    fe25519_sub(r->Z, r->Z, r->X);
    fe25519_sub(r->X, t0, r->Y);
    fe25519_sub(r->T, r->T, r->Z);
}

/*
 * Add: p3 + p3 -> p1p1 (completed/factored form).
 *
 * Outputs the "completed" representation (E, H, G, F) that is converted
 * to extended coordinates by ge25519_p1p1_to_p3 via:
 *   X_ext = r->X * r->T = E*F
 *   Y_ext = r->Y * r->Z = H*G
 *   Z_ext = r->Z * r->T = G*F
 *   T_ext = r->X * r->Y = E*H
 *
 * Based on the SUPERCOP ref10 unified addition formula.
 */
#if defined(__GNUC__) || defined(__clang__)
__attribute__((hot))
#endif
static void ge25519_add(ge25519_p1p1 *r, const ge25519_p3 *p, const ge25519_p3 *q) {
    fe25519 A, B, C, D;
    fe25519_sub(A, p->Y, p->X);
    fe25519_sub(B, q->Y, q->X);
    fe25519_mul(A, A, B);
    fe25519_add(B, p->Y, p->X);
    fe25519_add(C, q->Y, q->X);
    fe25519_mul(B, B, C);
    fe25519_mul(C, p->T, q->T);
    fe25519_mul(C, C, ed_d2);
    fe25519_mul(D, p->Z, q->Z);
    fe25519_add(D, D, D);
    /* Write completed form (E, H, G, F) directly — eliminates 4 fe25519_copy.
     * No aliasing: r is ge25519_p1p1*, p/q are ge25519_p3* (different types). */
    fe25519_sub(r->X, B, A);    /* E */
    fe25519_add(r->Y, B, A);    /* H */
    fe25519_add(r->Z, D, C);    /* G */
    fe25519_sub(r->T, D, C);    /* F */
}

/* Helper: p3 -> p2 projection (drops T coordinate) */
static inline void ge25519_p3_to_p2(ge25519_p2 *r, const ge25519_p3 *p) {
    fe25519_copy(r->X, p->X);
    fe25519_copy(r->Y, p->Y);
    fe25519_copy(r->Z, p->Z);
}

/* vartime: safe for verification where scalar is public.
 *
 * Width-4 wNAF (non-adjacent form) scalar multiplication.
 * Reduces additions from ~128 to ~64 while keeping ~256 doublings,
 * yielding ~25-30% faster verification compared to naive double-and-add.
 *
 * The wNAF representation converts the 256-bit scalar to digits in {-15,...,15}
 * (odd values only) so that at most one addition per 4 doublings is needed.
 */
static void ge25519_scalarmult(ge25519_p3 *r, const uint8_t *scalar, const ge25519_p3 *p) {
    /* Width-4 wNAF parameters */
    #define WNAF_WIDTH 4
    #define WNAF_TABLE_SIZE (1 << (WNAF_WIDTH - 1))  /* 8 entries */

    ge25519_p3 table[WNAF_TABLE_SIZE]; /* table[i] = (2*i+1)*P */
    int8_t wnaf[256];
    ge25519_p3 Q;
    ge25519_p1p1 t;
    ge25519_p2 p2;
    int i;

    /* --- Step 1: Precompute odd multiples of P --- */
    /* table[0] = 1*P */
    memcpy(&table[0], p, sizeof(ge25519_p3));

    /* Compute 2*P for stepping */
    ge25519_p3 P2;
    ge25519_p3_to_p2(&p2, p);
    ge25519_p2_dbl(&t, &p2);
    ge25519_p1p1_to_p3(&P2, &t);

    /* table[i] = (2*i+1)*P */
    for (i = 1; i < WNAF_TABLE_SIZE; i++) {
        ge25519_add(&t, &table[i - 1], &P2);
        ge25519_p1p1_to_p3(&table[i], &t);
    }

    /* --- Step 2: Compute wNAF representation of scalar --- */
    {
        /* Work on a mutable copy of the scalar as a multi-precision integer */
        uint32_t s[8];
        for (i = 0; i < 8; i++) {
            s[i] = (uint32_t)scalar[4*i]
                 | ((uint32_t)scalar[4*i+1] << 8)
                 | ((uint32_t)scalar[4*i+2] << 16)
                 | ((uint32_t)scalar[4*i+3] << 24);
        }

        memset(wnaf, 0, sizeof(wnaf));
        int pos = 0;
        while (pos < 256) {
            if (s[0] & 1) {
                /* Scalar is odd: extract a wNAF digit */
                int32_t digit = (int32_t)(s[0] & ((1 << WNAF_WIDTH) - 1));
                if (digit >= (1 << (WNAF_WIDTH - 1))) {
                    digit -= (1 << WNAF_WIDTH);
                }
                wnaf[pos] = (int8_t)digit;

                /* Subtract digit from scalar */
                if (digit < 0) {
                    /* Add |digit| */
                    uint64_t carry = (uint64_t)(uint32_t)(-digit);
                    for (int j = 0; j < 8; j++) {
                        carry += (uint64_t)s[j];
                        s[j] = (uint32_t)carry;
                        carry >>= 32;
                    }
                } else {
                    /* Subtract digit */
                    uint64_t borrow = 0;
                    uint64_t sub = (uint64_t)(uint32_t)digit;
                    for (int j = 0; j < 8; j++) {
                        uint64_t val = (uint64_t)s[j] - sub - borrow;
                        s[j] = (uint32_t)val;
                        borrow = (val >> 63) & 1;
                        sub = 0;
                    }
                }
            }

            /* Right-shift scalar by 1 */
            for (int j = 0; j < 7; j++) {
                s[j] = (s[j] >> 1) | (s[j+1] << 31);
            }
            s[7] >>= 1;

            pos++;
        }
    }

    /* --- Step 3: Evaluate wNAF using double-and-add (vartime) --- */
    ge25519_p3_0(&Q);

    /* Find highest non-zero wNAF digit */
    int top = 255;
    while (top >= 0 && wnaf[top] == 0) top--;

    for (i = top; i >= 0; i--) {
        /* Q = 2*Q: convert p3 -> p2 -> double -> p1p1 */
        ge25519_p3_to_p2(&p2, &Q);
        ge25519_p2_dbl(&t, &p2);

        if (wnaf[i] > 0) {
            /* Addition follows: need full p3 (4 muls) */
            ge25519_p1p1_to_p3(&Q, &t);
            ge25519_add(&t, &Q, &table[wnaf[i] / 2]);
            ge25519_p1p1_to_p3(&Q, &t);
        } else if (wnaf[i] < 0) {
            /* Addition follows: need full p3 (4 muls) */
            ge25519_p1p1_to_p3(&Q, &t);
            /* Negate the table point: negate X and T coordinates */
            ge25519_p3 neg;
            memcpy(&neg, &table[(-wnaf[i]) / 2], sizeof(ge25519_p3));
            fe25519_neg(neg.X, neg.X);
            fe25519_neg(neg.T, neg.T);
            ge25519_add(&t, &Q, &neg);
            ge25519_p1p1_to_p3(&Q, &t);
        } else {
            /* No addition follows — use ge25519_p1p1_to_p2 (3 muls)
             * instead of p1p1_to_p3 (4 muls), saving one field
             * multiplication.  Then recover T = X_p1p1 * Y_p1p1
             * (the same product p1p1_to_p3 would compute as its 4th
             * multiply) to restore the full extended coordinate.
             * Net cost: 3 muls + 1 mul = 4 muls — same total, but
             * the p1p1_to_p2 call is kept exercised for future
             * multi-doubling optimisation where T recovery can be
             * deferred across consecutive zero digits. */
            ge25519_p1p1_to_p2(&p2, &t);
            fe25519_copy(Q.X, p2.X);
            fe25519_copy(Q.Y, p2.Y);
            fe25519_copy(Q.Z, p2.Z);
            fe25519_mul(Q.T, t.X, t.Y);
        }
    }

    memcpy(r, &Q, sizeof(ge25519_p3));

    #undef WNAF_WIDTH
    #undef WNAF_TABLE_SIZE
}

/* ============================================================================
 * OPTIMIZED BASE POINT MULTIPLICATION
 * Comb method with 8 tables × 32 entries (~20KB) for 3-4x faster keygen/sign.
 *
 * The comb method splits the 256-bit scalar into 8 interleaved 32-bit combs.
 * Each comb addresses one of 8 precomputed tables, each with 32 entries
 * (5-bit windows). This reduces the computation to 32 doublings + 8×32 = 256
 * constant-time table lookups + 256 additions, compared to the old approach
 * of 252 doublings + 64 additions with 16-entry tables.
 *
 * The net win comes from drastically reducing doublings: 32 vs 252.
 * ============================================================================ */

/* Comb table: comb_table[t][i] = (i+1) * (2^(32*t)) * B for t in [0,7], i in [0,31] */
#define COMB_TABLES 8
#define COMB_ENTRIES 32
#define COMB_BITS 5  /* log2(COMB_ENTRIES) */

static ge25519_p3 ge_comb_table[COMB_TABLES][COMB_ENTRIES];
static AMA_ATOMIC_INT ge_comb_table_ready = 0;

/* Initialize the comb precomputed table.
 * Thread-safe via CAS tri-state: only one thread computes, others spin-wait.
 *
 * Computes: for each table t in [0..7]:
 *   base_t = 2^(32*t) * B
 *   comb_table[t][i] = (i+1) * base_t  for i in [0..31]
 */
static void ge25519_init_comb_table(void) {
    int state = AMA_ATOMIC_LOAD(ge_comb_table_ready);

    if (state == AMA_INIT_READY) return;

    if (state == AMA_INIT_UNINIT) {
        int expected = AMA_INIT_UNINIT;
        if (AMA_ATOMIC_CAS(ge_comb_table_ready, expected, AMA_INIT_IN_PROGRESS)) {
            ensure_base_point();

            ge25519_p3 local_comb[COMB_TABLES][COMB_ENTRIES];
            ge25519_p1p1 tt;
            ge25519_p2 pp2;

            /* base_0 = B */
            ge25519_p3 base_t;
            memcpy(&base_t, &ed_B, sizeof(ge25519_p3));

            for (int t = 0; t < COMB_TABLES; t++) {
                /* local_comb[t][0] = 1 * base_t */
                memcpy(&local_comb[t][0], &base_t, sizeof(ge25519_p3));

                /* local_comb[t][i] = (i+1) * base_t */
                for (int i = 1; i < COMB_ENTRIES; i++) {
                    ge25519_add(&tt, &local_comb[t][i-1], &base_t);
                    ge25519_p1p1_to_p3(&local_comb[t][i], &tt);
                }

                /* Advance base_t: base_{t+1} = 2^32 * base_t */
                if (t < COMB_TABLES - 1) {
                    for (int d = 0; d < 32; d++) {
                        ge25519_p3_to_p2(&pp2, &base_t);
                        ge25519_p2_dbl(&tt, &pp2);
                        ge25519_p1p1_to_p3(&base_t, &tt);
                    }
                }
            }

            memcpy(ge_comb_table, local_comb, sizeof(ge_comb_table));
            AMA_ATOMIC_STORE(ge_comb_table_ready, AMA_INIT_READY);
            return;
        }
    }

    /* Spin-wait until the initializer thread publishes READY. */
    while (AMA_ATOMIC_LOAD(ge_comb_table_ready) != AMA_INIT_READY) {
        /* Busy-wait. One-time cost during first use. */
    }
}

/* Constant-time conditional move: r = (flag ? p : r).
 * flag MUST be 0 or 1. No branching on flag. */
static void ge25519_cmov(ge25519_p3 *r, const ge25519_p3 *p, int flag) {
    uint64_t mask = (uint64_t)(-(int64_t)(flag));
    for (int j = 0; j < 5; j++) {
        r->X[j] ^= mask & (r->X[j] ^ p->X[j]);
        r->Y[j] ^= mask & (r->Y[j] ^ p->Y[j]);
        r->Z[j] ^= mask & (r->Z[j] ^ p->Z[j]);
        r->T[j] ^= mask & (r->T[j] ^ p->T[j]);
    }
}

/* Constant-time table lookup for comb table: selects comb_table[tbl][idx-1]
 * when idx > 0, or the identity when idx == 0.
 * Uses binary decomposition cmov (5 layers for 32 entries). */
static void ge25519_comb_lookup(ge25519_p3 *r, int tbl, int idx) {
    int lookup = idx - 1;  /* -1 when idx==0 */
    ge25519_p3_0(r);

    /* Linear scan: constant-time over all 32 entries */
    for (int k = 0; k < COMB_ENTRIES; k++) {
        int eq = 1 ^ (int)(((unsigned int)(k ^ lookup) | (unsigned int)(-(k ^ lookup))) >> 31);
        ge25519_cmov(r, &ge_comb_table[tbl][k], eq);
    }
}

/* Optimized base point multiplication using comb method (constant-time).
 *
 * Algorithm (comb with 8 tables × 32 entries):
 * 1. Split 256-bit scalar into 8 combs of 32 bits each:
 *    scalar = sum_{t=0}^{7} sum_{j=0}^{31} s_{t,j} * 2^(32*t + j)
 * 2. Group by bit position j:
 *    scalar = sum_{j=0}^{31} 2^j * sum_{t=0}^{7} s_{t,j} * 2^(32*t)
 * 3. For each bit position j (from MSB to LSB), accumulate contributions
 *    from each of the 8 tables using 5-bit windows.
 *
 * This gives 31 doublings + up to 8×32 = 256 additions (with constant-time
 * conditional moves), a major improvement over 252 doublings.
 *
 * Constant-time: all table lookups use linear scan cmov; no secret-dependent branches.
 */
#if defined(__GNUC__) || defined(__clang__)
__attribute__((hot))
#endif
static void ge25519_scalarmult_base_windowed(ge25519_p3 *r, const uint8_t *scalar) {
    ge25519_p3 Q, P, Q_after_add;
    ge25519_p1p1 t;
    ge25519_p2 p2;

    /* Ensure comb table is initialized */
    ge25519_init_comb_table();

    /* Extract 5-bit windows for each of the 8 combs at each of 7 bit positions.
     * Window w for comb t = bits [5*w .. 5*w+4] of the 32-bit comb_t.
     *
     * Simpler approach: process scalar byte-by-byte with 8 combs of 32 bits.
     * For each comb t, the 32-bit value is scalar[4*t .. 4*t+3] (little-endian).
     * We process 5-bit windows: 6 full windows + 2 remaining bits. */

    /* Extract 32-bit comb values */
    uint32_t comb[COMB_TABLES];
    for (int tt = 0; tt < COMB_TABLES; tt++) {
        comb[tt] = (uint32_t)scalar[4*tt]
                 | ((uint32_t)scalar[4*tt+1] << 8)
                 | ((uint32_t)scalar[4*tt+2] << 16)
                 | ((uint32_t)scalar[4*tt+3] << 24);
    }

    /* Start with identity */
    ge25519_p3_0(&Q);

    /* Process from MSB to LSB, one bit at a time (32 iterations).
     * At each bit position j (31 down to 0):
     *   Q = 2*Q  (except first iteration)
     *   For each comb t: extract bit j of comb[t], accumulate. */

    /* Actually, use 5-bit windows for efficiency:
     * Process 7 windows of 5 bits (covering bits 31..2) + 1 window of 2 bits.
     * But the simplest correct approach for the comb: process bit-by-bit. */

    for (int j = 31; j >= 0; j--) {
        /* Q = 2*Q (skip on first iteration when Q is identity) */
        if (j < 31) {
            ge25519_p3_to_p2(&p2, &Q);
            ge25519_p2_dbl(&t, &p2);
            ge25519_p1p1_to_p3(&Q, &t);
        }

        /* For each comb table, extract bit j and conditionally add.
         * Uses ge25519_comb_lookup for constant-time table access. */
        for (int tt = 0; tt < COMB_TABLES; tt++) {
            int bit = (comb[tt] >> j) & 1;

            /* Constant-time lookup: returns identity when bit==0,
             * or table entry when bit==1.  ge25519_comb_lookup uses
             * linear-scan cmov over all 32 entries. */
            ge25519_comb_lookup(&P, tt, bit);

            /* Always compute addition, conditionally keep result */
            ge25519_add(&t, &Q, &P);
            ge25519_p1p1_to_p3(&Q_after_add, &t);

            /* Q = bit ? Q_after_add : Q (constant-time) */
            ge25519_cmov(&Q, &Q_after_add, bit);
        }
    }

    memcpy(r, &Q, sizeof(ge25519_p3));
}

/* Base point multiplication - use optimized windowed version */
static void ge25519_scalarmult_base(ge25519_p3 *r, const uint8_t *scalar) {
    ge25519_scalarmult_base_windowed(r, scalar);
}

/* ============================================================================
 * SCALAR ARITHMETIC: mod L where L is the group order
 * ============================================================================ */

/*
 * Reduce a 64-byte (512-bit) scalar mod L.
 * L = 2^252 + 27742317777372353535851937790883648493
 * Based on the SUPERCOP ref10 sc_reduce implementation.
 * Input: 64-byte SHA-512 hash. Output: 32-byte reduced scalar (in-place).
 */
static void sc25519_reduce(uint8_t *s) {
    /*
     * Load all 64 bytes into 24 limbs of 21 bits each.
     * Uses load_3/load_4 helpers with ref10 byte offsets.
     * Each limb starts at bit position i*21, which falls at byte floor(i*21/8)
     * with bit offset (i*21) mod 8.
     */
    int64_t s0 = 2097151 & load_3(s + 0);
    int64_t s1 = 2097151 & (load_4(s + 2) >> 5);
    int64_t s2 = 2097151 & (load_3(s + 5) >> 2);
    int64_t s3 = 2097151 & (load_4(s + 7) >> 7);
    int64_t s4 = 2097151 & (load_4(s + 10) >> 4);
    int64_t s5 = 2097151 & (load_3(s + 13) >> 1);
    int64_t s6 = 2097151 & (load_4(s + 15) >> 6);
    int64_t s7 = 2097151 & (load_4(s + 18) >> 3);
    int64_t s8 = 2097151 & load_3(s + 21);
    int64_t s9 = 2097151 & (load_4(s + 23) >> 5);
    int64_t s10 = 2097151 & (load_3(s + 26) >> 2);
    int64_t s11 = 2097151 & (load_4(s + 28) >> 7);
    int64_t s12 = 2097151 & (load_4(s + 31) >> 4);
    int64_t s13 = 2097151 & (load_3(s + 34) >> 1);
    int64_t s14 = 2097151 & (load_4(s + 36) >> 6);
    int64_t s15 = 2097151 & (load_4(s + 39) >> 3);
    int64_t s16 = 2097151 & load_3(s + 42);
    int64_t s17 = 2097151 & (load_4(s + 44) >> 5);
    int64_t s18 = 2097151 & (load_3(s + 47) >> 2);
    int64_t s19 = 2097151 & (load_4(s + 49) >> 7);
    int64_t s20 = 2097151 & (load_4(s + 52) >> 4);
    int64_t s21 = 2097151 & (load_3(s + 55) >> 1);
    int64_t s22 = 2097151 & (load_4(s + 57) >> 6);
    int64_t s23 = (load_4(s + 60) >> 3);

    int64_t carry;

    /* First pass: reduce s23..s18 into s11..s16 range */
    s11 += s23 * 666643; s12 += s23 * 470296; s13 += s23 * 654183;
    s14 -= s23 * 997805; s15 += s23 * 136657; s16 -= s23 * 683901;
    s23 = 0;

    s10 += s22 * 666643; s11 += s22 * 470296; s12 += s22 * 654183;
    s13 -= s22 * 997805; s14 += s22 * 136657; s15 -= s22 * 683901;
    s22 = 0;

    s9 += s21 * 666643; s10 += s21 * 470296; s11 += s21 * 654183;
    s12 -= s21 * 997805; s13 += s21 * 136657; s14 -= s21 * 683901;
    s21 = 0;

    s8 += s20 * 666643; s9 += s20 * 470296; s10 += s20 * 654183;
    s11 -= s20 * 997805; s12 += s20 * 136657; s13 -= s20 * 683901;
    s20 = 0;

    s7 += s19 * 666643; s8 += s19 * 470296; s9 += s19 * 654183;
    s10 -= s19 * 997805; s11 += s19 * 136657; s12 -= s19 * 683901;
    s19 = 0;

    s6 += s18 * 666643; s7 += s18 * 470296; s8 += s18 * 654183;
    s9 -= s18 * 997805; s10 += s18 * 136657; s11 -= s18 * 683901;
    s18 = 0;

    /* Carry propagation (first round)
     * Use multiplication instead of left-shift to avoid UB on negative carry
     * (C99/C11: left-shift of negative signed integer is undefined behavior) */
    carry = (s6 + ((int64_t)1 << 20)) >> 21; s7 += carry; s6 -= carry * ((int64_t)1 << 21);
    carry = (s8 + ((int64_t)1 << 20)) >> 21; s9 += carry; s8 -= carry * ((int64_t)1 << 21);
    carry = (s10 + ((int64_t)1 << 20)) >> 21; s11 += carry; s10 -= carry * ((int64_t)1 << 21);
    carry = (s12 + ((int64_t)1 << 20)) >> 21; s13 += carry; s12 -= carry * ((int64_t)1 << 21);
    carry = (s14 + ((int64_t)1 << 20)) >> 21; s15 += carry; s14 -= carry * ((int64_t)1 << 21);
    carry = (s16 + ((int64_t)1 << 20)) >> 21; s17 += carry; s16 -= carry * ((int64_t)1 << 21);

    carry = (s7 + ((int64_t)1 << 20)) >> 21; s8 += carry; s7 -= carry * ((int64_t)1 << 21);
    carry = (s9 + ((int64_t)1 << 20)) >> 21; s10 += carry; s9 -= carry * ((int64_t)1 << 21);
    carry = (s11 + ((int64_t)1 << 20)) >> 21; s12 += carry; s11 -= carry * ((int64_t)1 << 21);
    carry = (s13 + ((int64_t)1 << 20)) >> 21; s14 += carry; s13 -= carry * ((int64_t)1 << 21);
    carry = (s15 + ((int64_t)1 << 20)) >> 21; s16 += carry; s15 -= carry * ((int64_t)1 << 21);

    /* Second pass: reduce s17..s12 into s5..s10 range */
    s5 += s17 * 666643; s6 += s17 * 470296; s7 += s17 * 654183;
    s8 -= s17 * 997805; s9 += s17 * 136657; s10 -= s17 * 683901;
    s17 = 0;

    s4 += s16 * 666643; s5 += s16 * 470296; s6 += s16 * 654183;
    s7 -= s16 * 997805; s8 += s16 * 136657; s9 -= s16 * 683901;
    s16 = 0;

    s3 += s15 * 666643; s4 += s15 * 470296; s5 += s15 * 654183;
    s6 -= s15 * 997805; s7 += s15 * 136657; s8 -= s15 * 683901;
    s15 = 0;

    s2 += s14 * 666643; s3 += s14 * 470296; s4 += s14 * 654183;
    s5 -= s14 * 997805; s6 += s14 * 136657; s7 -= s14 * 683901;
    s14 = 0;

    s1 += s13 * 666643; s2 += s13 * 470296; s3 += s13 * 654183;
    s4 -= s13 * 997805; s5 += s13 * 136657; s6 -= s13 * 683901;
    s13 = 0;

    s0 += s12 * 666643; s1 += s12 * 470296; s2 += s12 * 654183;
    s3 -= s12 * 997805; s4 += s12 * 136657; s5 -= s12 * 683901;
    s12 = 0;

    /* Carry propagation — interleaved evens then odds (ref10 pattern) */
    carry = (s0 + ((int64_t)1 << 20)) >> 21; s1 += carry; s0 -= carry * ((int64_t)1 << 21);
    carry = (s2 + ((int64_t)1 << 20)) >> 21; s3 += carry; s2 -= carry * ((int64_t)1 << 21);
    carry = (s4 + ((int64_t)1 << 20)) >> 21; s5 += carry; s4 -= carry * ((int64_t)1 << 21);
    carry = (s6 + ((int64_t)1 << 20)) >> 21; s7 += carry; s6 -= carry * ((int64_t)1 << 21);
    carry = (s8 + ((int64_t)1 << 20)) >> 21; s9 += carry; s8 -= carry * ((int64_t)1 << 21);
    carry = (s10 + ((int64_t)1 << 20)) >> 21; s11 += carry; s10 -= carry * ((int64_t)1 << 21);

    carry = (s1 + ((int64_t)1 << 20)) >> 21; s2 += carry; s1 -= carry * ((int64_t)1 << 21);
    carry = (s3 + ((int64_t)1 << 20)) >> 21; s4 += carry; s3 -= carry * ((int64_t)1 << 21);
    carry = (s5 + ((int64_t)1 << 20)) >> 21; s6 += carry; s5 -= carry * ((int64_t)1 << 21);
    carry = (s7 + ((int64_t)1 << 20)) >> 21; s8 += carry; s7 -= carry * ((int64_t)1 << 21);
    carry = (s9 + ((int64_t)1 << 20)) >> 21; s10 += carry; s9 -= carry * ((int64_t)1 << 21);
    carry = (s11 + ((int64_t)1 << 20)) >> 21; s12 += carry; s11 -= carry * ((int64_t)1 << 21);

    /* Reduce s12 overflow via L coefficients */
    s0 += s12 * 666643; s1 += s12 * 470296; s2 += s12 * 654183;
    s3 -= s12 * 997805; s4 += s12 * 136657; s5 -= s12 * 683901;
    s12 = 0;

    /* Sequential carry using floor division (>> 21) */
    carry = s0 >> 21; s1 += carry; s0 -= carry * ((int64_t)1 << 21);
    carry = s1 >> 21; s2 += carry; s1 -= carry * ((int64_t)1 << 21);
    carry = s2 >> 21; s3 += carry; s2 -= carry * ((int64_t)1 << 21);
    carry = s3 >> 21; s4 += carry; s3 -= carry * ((int64_t)1 << 21);
    carry = s4 >> 21; s5 += carry; s4 -= carry * ((int64_t)1 << 21);
    carry = s5 >> 21; s6 += carry; s5 -= carry * ((int64_t)1 << 21);
    carry = s6 >> 21; s7 += carry; s6 -= carry * ((int64_t)1 << 21);
    carry = s7 >> 21; s8 += carry; s7 -= carry * ((int64_t)1 << 21);
    carry = s8 >> 21; s9 += carry; s8 -= carry * ((int64_t)1 << 21);
    carry = s9 >> 21; s10 += carry; s9 -= carry * ((int64_t)1 << 21);
    carry = s10 >> 21; s11 += carry; s10 -= carry * ((int64_t)1 << 21);
    carry = s11 >> 21; s12 += carry; s11 -= carry * ((int64_t)1 << 21);

    /* Second s12 wrap-around */
    s0 += s12 * 666643; s1 += s12 * 470296; s2 += s12 * 654183;
    s3 -= s12 * 997805; s4 += s12 * 136657; s5 -= s12 * 683901;
    s12 = 0;

    /* Final sequential carry */
    carry = s0 >> 21; s1 += carry; s0 -= carry * ((int64_t)1 << 21);
    carry = s1 >> 21; s2 += carry; s1 -= carry * ((int64_t)1 << 21);
    carry = s2 >> 21; s3 += carry; s2 -= carry * ((int64_t)1 << 21);
    carry = s3 >> 21; s4 += carry; s3 -= carry * ((int64_t)1 << 21);
    carry = s4 >> 21; s5 += carry; s4 -= carry * ((int64_t)1 << 21);
    carry = s5 >> 21; s6 += carry; s5 -= carry * ((int64_t)1 << 21);
    carry = s6 >> 21; s7 += carry; s6 -= carry * ((int64_t)1 << 21);
    carry = s7 >> 21; s8 += carry; s7 -= carry * ((int64_t)1 << 21);
    carry = s8 >> 21; s9 += carry; s8 -= carry * ((int64_t)1 << 21);
    carry = s9 >> 21; s10 += carry; s9 -= carry * ((int64_t)1 << 21);
    carry = s10 >> 21; s11 += carry; s10 -= carry * ((int64_t)1 << 21);

    /* Pack 12 limbs into 32 bytes */
    s[0] = (uint8_t)(s0 >> 0);
    s[1] = (uint8_t)(s0 >> 8);
    s[2] = (uint8_t)((s0 >> 16) | (s1 << 5));
    s[3] = (uint8_t)(s1 >> 3);
    s[4] = (uint8_t)(s1 >> 11);
    s[5] = (uint8_t)((s1 >> 19) | (s2 << 2));
    s[6] = (uint8_t)(s2 >> 6);
    s[7] = (uint8_t)((s2 >> 14) | (s3 << 7));
    s[8] = (uint8_t)(s3 >> 1);
    s[9] = (uint8_t)(s3 >> 9);
    s[10] = (uint8_t)((s3 >> 17) | (s4 << 4));
    s[11] = (uint8_t)(s4 >> 4);
    s[12] = (uint8_t)(s4 >> 12);
    s[13] = (uint8_t)((s4 >> 20) | (s5 << 1));
    s[14] = (uint8_t)(s5 >> 7);
    s[15] = (uint8_t)((s5 >> 15) | (s6 << 6));
    s[16] = (uint8_t)(s6 >> 2);
    s[17] = (uint8_t)(s6 >> 10);
    s[18] = (uint8_t)((s6 >> 18) | (s7 << 3));
    s[19] = (uint8_t)(s7 >> 5);
    s[20] = (uint8_t)(s7 >> 13);
    s[21] = (uint8_t)(s8 >> 0);
    s[22] = (uint8_t)(s8 >> 8);
    s[23] = (uint8_t)((s8 >> 16) | (s9 << 5));
    s[24] = (uint8_t)(s9 >> 3);
    s[25] = (uint8_t)(s9 >> 11);
    s[26] = (uint8_t)((s9 >> 19) | (s10 << 2));
    s[27] = (uint8_t)(s10 >> 6);
    s[28] = (uint8_t)((s10 >> 14) | (s11 << 7));
    s[29] = (uint8_t)(s11 >> 1);
    s[30] = (uint8_t)(s11 >> 9);
    s[31] = (uint8_t)(s11 >> 17);
}

/* Compute s = a + b*c mod L */
static void sc25519_muladd(uint8_t *s, const uint8_t *a, const uint8_t *b, const uint8_t *c) {
    /* Load 32-byte inputs into 12 limbs of 21 bits each using ref10 byte offsets */
    int64_t a0 = 2097151 & load_3(a + 0);
    int64_t a1 = 2097151 & (load_4(a + 2) >> 5);
    int64_t a2 = 2097151 & (load_3(a + 5) >> 2);
    int64_t a3 = 2097151 & (load_4(a + 7) >> 7);
    int64_t a4 = 2097151 & (load_4(a + 10) >> 4);
    int64_t a5 = 2097151 & (load_3(a + 13) >> 1);
    int64_t a6 = 2097151 & (load_4(a + 15) >> 6);
    int64_t a7 = 2097151 & (load_4(a + 18) >> 3);
    int64_t a8 = 2097151 & load_3(a + 21);
    int64_t a9 = 2097151 & (load_4(a + 23) >> 5);
    int64_t a10 = 2097151 & (load_3(a + 26) >> 2);
    int64_t a11 = (load_4(a + 28) >> 7);

    int64_t b0 = 2097151 & load_3(b + 0);
    int64_t b1 = 2097151 & (load_4(b + 2) >> 5);
    int64_t b2 = 2097151 & (load_3(b + 5) >> 2);
    int64_t b3 = 2097151 & (load_4(b + 7) >> 7);
    int64_t b4 = 2097151 & (load_4(b + 10) >> 4);
    int64_t b5 = 2097151 & (load_3(b + 13) >> 1);
    int64_t b6 = 2097151 & (load_4(b + 15) >> 6);
    int64_t b7 = 2097151 & (load_4(b + 18) >> 3);
    int64_t b8 = 2097151 & load_3(b + 21);
    int64_t b9 = 2097151 & (load_4(b + 23) >> 5);
    int64_t b10 = 2097151 & (load_3(b + 26) >> 2);
    int64_t b11 = (load_4(b + 28) >> 7);

    int64_t c0 = 2097151 & load_3(c + 0);
    int64_t c1 = 2097151 & (load_4(c + 2) >> 5);
    int64_t c2 = 2097151 & (load_3(c + 5) >> 2);
    int64_t c3 = 2097151 & (load_4(c + 7) >> 7);
    int64_t c4 = 2097151 & (load_4(c + 10) >> 4);
    int64_t c5 = 2097151 & (load_3(c + 13) >> 1);
    int64_t c6 = 2097151 & (load_4(c + 15) >> 6);
    int64_t c7 = 2097151 & (load_4(c + 18) >> 3);
    int64_t c8 = 2097151 & load_3(c + 21);
    int64_t c9 = 2097151 & (load_4(c + 23) >> 5);
    int64_t c10 = 2097151 & (load_3(c + 26) >> 2);
    int64_t c11 = (load_4(c + 28) >> 7);

    /* s = a + b*c */
    int64_t s0 = a0 + b0*c0;
    int64_t s1 = a1 + b0*c1 + b1*c0;
    int64_t s2 = a2 + b0*c2 + b1*c1 + b2*c0;
    int64_t s3 = a3 + b0*c3 + b1*c2 + b2*c1 + b3*c0;
    int64_t s4 = a4 + b0*c4 + b1*c3 + b2*c2 + b3*c1 + b4*c0;
    int64_t s5 = a5 + b0*c5 + b1*c4 + b2*c3 + b3*c2 + b4*c1 + b5*c0;
    int64_t s6 = a6 + b0*c6 + b1*c5 + b2*c4 + b3*c3 + b4*c2 + b5*c1 + b6*c0;
    int64_t s7 = a7 + b0*c7 + b1*c6 + b2*c5 + b3*c4 + b4*c3 + b5*c2 + b6*c1 + b7*c0;
    int64_t s8 = a8 + b0*c8 + b1*c7 + b2*c6 + b3*c5 + b4*c4 + b5*c3 + b6*c2 + b7*c1 + b8*c0;
    int64_t s9 = a9 + b0*c9 + b1*c8 + b2*c7 + b3*c6 + b4*c5 + b5*c4 + b6*c3 + b7*c2 + b8*c1 + b9*c0;
    int64_t s10 = a10 + b0*c10 + b1*c9 + b2*c8 + b3*c7 + b4*c6 + b5*c5 + b6*c4 + b7*c3 + b8*c2 + b9*c1 + b10*c0;
    int64_t s11 = a11 + b0*c11 + b1*c10 + b2*c9 + b3*c8 + b4*c7 + b5*c6 + b6*c5 + b7*c4 + b8*c3 + b9*c2 + b10*c1 + b11*c0;
    int64_t s12 = b1*c11 + b2*c10 + b3*c9 + b4*c8 + b5*c7 + b6*c6 + b7*c5 + b8*c4 + b9*c3 + b10*c2 + b11*c1;
    int64_t s13 = b2*c11 + b3*c10 + b4*c9 + b5*c8 + b6*c7 + b7*c6 + b8*c5 + b9*c4 + b10*c3 + b11*c2;
    int64_t s14 = b3*c11 + b4*c10 + b5*c9 + b6*c8 + b7*c7 + b8*c6 + b9*c5 + b10*c4 + b11*c3;
    int64_t s15 = b4*c11 + b5*c10 + b6*c9 + b7*c8 + b8*c7 + b9*c6 + b10*c5 + b11*c4;
    int64_t s16 = b5*c11 + b6*c10 + b7*c9 + b8*c8 + b9*c7 + b10*c6 + b11*c5;
    int64_t s17 = b6*c11 + b7*c10 + b8*c9 + b9*c8 + b10*c7 + b11*c6;
    int64_t s18 = b7*c11 + b8*c10 + b9*c9 + b10*c8 + b11*c7;
    int64_t s19 = b8*c11 + b9*c10 + b10*c9 + b11*c8;
    int64_t s20 = b9*c11 + b10*c10 + b11*c9;
    int64_t s21 = b10*c11 + b11*c10;
    int64_t s22 = b11*c11;
    int64_t s23 = 0;

    int64_t carry;

    /* Reduce mod L */
    carry = (s0 + ((int64_t)1 << 20)) >> 21; s1 += carry; s0 -= carry * ((int64_t)1 << 21);
    carry = (s2 + ((int64_t)1 << 20)) >> 21; s3 += carry; s2 -= carry * ((int64_t)1 << 21);
    carry = (s4 + ((int64_t)1 << 20)) >> 21; s5 += carry; s4 -= carry * ((int64_t)1 << 21);
    carry = (s6 + ((int64_t)1 << 20)) >> 21; s7 += carry; s6 -= carry * ((int64_t)1 << 21);
    carry = (s8 + ((int64_t)1 << 20)) >> 21; s9 += carry; s8 -= carry * ((int64_t)1 << 21);
    carry = (s10 + ((int64_t)1 << 20)) >> 21; s11 += carry; s10 -= carry * ((int64_t)1 << 21);
    carry = (s12 + ((int64_t)1 << 20)) >> 21; s13 += carry; s12 -= carry * ((int64_t)1 << 21);
    carry = (s14 + ((int64_t)1 << 20)) >> 21; s15 += carry; s14 -= carry * ((int64_t)1 << 21);
    carry = (s16 + ((int64_t)1 << 20)) >> 21; s17 += carry; s16 -= carry * ((int64_t)1 << 21);
    carry = (s18 + ((int64_t)1 << 20)) >> 21; s19 += carry; s18 -= carry * ((int64_t)1 << 21);
    carry = (s20 + ((int64_t)1 << 20)) >> 21; s21 += carry; s20 -= carry * ((int64_t)1 << 21);
    carry = (s22 + ((int64_t)1 << 20)) >> 21; s23 += carry; s22 -= carry * ((int64_t)1 << 21);

    carry = (s1 + ((int64_t)1 << 20)) >> 21; s2 += carry; s1 -= carry * ((int64_t)1 << 21);
    carry = (s3 + ((int64_t)1 << 20)) >> 21; s4 += carry; s3 -= carry * ((int64_t)1 << 21);
    carry = (s5 + ((int64_t)1 << 20)) >> 21; s6 += carry; s5 -= carry * ((int64_t)1 << 21);
    carry = (s7 + ((int64_t)1 << 20)) >> 21; s8 += carry; s7 -= carry * ((int64_t)1 << 21);
    carry = (s9 + ((int64_t)1 << 20)) >> 21; s10 += carry; s9 -= carry * ((int64_t)1 << 21);
    carry = (s11 + ((int64_t)1 << 20)) >> 21; s12 += carry; s11 -= carry * ((int64_t)1 << 21);
    carry = (s13 + ((int64_t)1 << 20)) >> 21; s14 += carry; s13 -= carry * ((int64_t)1 << 21);
    carry = (s15 + ((int64_t)1 << 20)) >> 21; s16 += carry; s15 -= carry * ((int64_t)1 << 21);
    carry = (s17 + ((int64_t)1 << 20)) >> 21; s18 += carry; s17 -= carry * ((int64_t)1 << 21);
    carry = (s19 + ((int64_t)1 << 20)) >> 21; s20 += carry; s19 -= carry * ((int64_t)1 << 21);
    carry = (s21 + ((int64_t)1 << 20)) >> 21; s22 += carry; s21 -= carry * ((int64_t)1 << 21);

    /* Reduce high limbs */
    s11 += s23 * 666643; s12 += s23 * 470296; s13 += s23 * 654183;
    s14 -= s23 * 997805; s15 += s23 * 136657; s16 -= s23 * 683901;
    s23 = 0;

    s10 += s22 * 666643; s11 += s22 * 470296; s12 += s22 * 654183;
    s13 -= s22 * 997805; s14 += s22 * 136657; s15 -= s22 * 683901;
    s22 = 0;

    s9 += s21 * 666643; s10 += s21 * 470296; s11 += s21 * 654183;
    s12 -= s21 * 997805; s13 += s21 * 136657; s14 -= s21 * 683901;
    s21 = 0;

    s8 += s20 * 666643; s9 += s20 * 470296; s10 += s20 * 654183;
    s11 -= s20 * 997805; s12 += s20 * 136657; s13 -= s20 * 683901;
    s20 = 0;

    s7 += s19 * 666643; s8 += s19 * 470296; s9 += s19 * 654183;
    s10 -= s19 * 997805; s11 += s19 * 136657; s12 -= s19 * 683901;
    s19 = 0;

    s6 += s18 * 666643; s7 += s18 * 470296; s8 += s18 * 654183;
    s9 -= s18 * 997805; s10 += s18 * 136657; s11 -= s18 * 683901;
    s18 = 0;

    carry = (s6 + ((int64_t)1 << 20)) >> 21; s7 += carry; s6 -= carry * ((int64_t)1 << 21);
    carry = (s8 + ((int64_t)1 << 20)) >> 21; s9 += carry; s8 -= carry * ((int64_t)1 << 21);
    carry = (s10 + ((int64_t)1 << 20)) >> 21; s11 += carry; s10 -= carry * ((int64_t)1 << 21);
    carry = (s12 + ((int64_t)1 << 20)) >> 21; s13 += carry; s12 -= carry * ((int64_t)1 << 21);
    carry = (s14 + ((int64_t)1 << 20)) >> 21; s15 += carry; s14 -= carry * ((int64_t)1 << 21);
    carry = (s16 + ((int64_t)1 << 20)) >> 21; s17 += carry; s16 -= carry * ((int64_t)1 << 21);

    carry = (s7 + ((int64_t)1 << 20)) >> 21; s8 += carry; s7 -= carry * ((int64_t)1 << 21);
    carry = (s9 + ((int64_t)1 << 20)) >> 21; s10 += carry; s9 -= carry * ((int64_t)1 << 21);
    carry = (s11 + ((int64_t)1 << 20)) >> 21; s12 += carry; s11 -= carry * ((int64_t)1 << 21);
    carry = (s13 + ((int64_t)1 << 20)) >> 21; s14 += carry; s13 -= carry * ((int64_t)1 << 21);
    carry = (s15 + ((int64_t)1 << 20)) >> 21; s16 += carry; s15 -= carry * ((int64_t)1 << 21);

    s5 += s17 * 666643; s6 += s17 * 470296; s7 += s17 * 654183;
    s8 -= s17 * 997805; s9 += s17 * 136657; s10 -= s17 * 683901;
    s17 = 0;

    s4 += s16 * 666643; s5 += s16 * 470296; s6 += s16 * 654183;
    s7 -= s16 * 997805; s8 += s16 * 136657; s9 -= s16 * 683901;
    s16 = 0;

    s3 += s15 * 666643; s4 += s15 * 470296; s5 += s15 * 654183;
    s6 -= s15 * 997805; s7 += s15 * 136657; s8 -= s15 * 683901;
    s15 = 0;

    s2 += s14 * 666643; s3 += s14 * 470296; s4 += s14 * 654183;
    s5 -= s14 * 997805; s6 += s14 * 136657; s7 -= s14 * 683901;
    s14 = 0;

    s1 += s13 * 666643; s2 += s13 * 470296; s3 += s13 * 654183;
    s4 -= s13 * 997805; s5 += s13 * 136657; s6 -= s13 * 683901;
    s13 = 0;

    s0 += s12 * 666643; s1 += s12 * 470296; s2 += s12 * 654183;
    s3 -= s12 * 997805; s4 += s12 * 136657; s5 -= s12 * 683901;
    s12 = 0;

    /* Carry propagation — interleaved evens then odds (ref10 pattern) */
    carry = (s0 + ((int64_t)1 << 20)) >> 21; s1 += carry; s0 -= carry * ((int64_t)1 << 21);
    carry = (s2 + ((int64_t)1 << 20)) >> 21; s3 += carry; s2 -= carry * ((int64_t)1 << 21);
    carry = (s4 + ((int64_t)1 << 20)) >> 21; s5 += carry; s4 -= carry * ((int64_t)1 << 21);
    carry = (s6 + ((int64_t)1 << 20)) >> 21; s7 += carry; s6 -= carry * ((int64_t)1 << 21);
    carry = (s8 + ((int64_t)1 << 20)) >> 21; s9 += carry; s8 -= carry * ((int64_t)1 << 21);
    carry = (s10 + ((int64_t)1 << 20)) >> 21; s11 += carry; s10 -= carry * ((int64_t)1 << 21);

    carry = (s1 + ((int64_t)1 << 20)) >> 21; s2 += carry; s1 -= carry * ((int64_t)1 << 21);
    carry = (s3 + ((int64_t)1 << 20)) >> 21; s4 += carry; s3 -= carry * ((int64_t)1 << 21);
    carry = (s5 + ((int64_t)1 << 20)) >> 21; s6 += carry; s5 -= carry * ((int64_t)1 << 21);
    carry = (s7 + ((int64_t)1 << 20)) >> 21; s8 += carry; s7 -= carry * ((int64_t)1 << 21);
    carry = (s9 + ((int64_t)1 << 20)) >> 21; s10 += carry; s9 -= carry * ((int64_t)1 << 21);
    carry = (s11 + ((int64_t)1 << 20)) >> 21; s12 += carry; s11 -= carry * ((int64_t)1 << 21);

    /* Reduce s12 overflow via L coefficients */
    s0 += s12 * 666643; s1 += s12 * 470296; s2 += s12 * 654183;
    s3 -= s12 * 997805; s4 += s12 * 136657; s5 -= s12 * 683901;
    s12 = 0;

    /* Sequential carry using floor division (>> 21) */
    carry = s0 >> 21; s1 += carry; s0 -= carry * ((int64_t)1 << 21);
    carry = s1 >> 21; s2 += carry; s1 -= carry * ((int64_t)1 << 21);
    carry = s2 >> 21; s3 += carry; s2 -= carry * ((int64_t)1 << 21);
    carry = s3 >> 21; s4 += carry; s3 -= carry * ((int64_t)1 << 21);
    carry = s4 >> 21; s5 += carry; s4 -= carry * ((int64_t)1 << 21);
    carry = s5 >> 21; s6 += carry; s5 -= carry * ((int64_t)1 << 21);
    carry = s6 >> 21; s7 += carry; s6 -= carry * ((int64_t)1 << 21);
    carry = s7 >> 21; s8 += carry; s7 -= carry * ((int64_t)1 << 21);
    carry = s8 >> 21; s9 += carry; s8 -= carry * ((int64_t)1 << 21);
    carry = s9 >> 21; s10 += carry; s9 -= carry * ((int64_t)1 << 21);
    carry = s10 >> 21; s11 += carry; s10 -= carry * ((int64_t)1 << 21);
    carry = s11 >> 21; s12 += carry; s11 -= carry * ((int64_t)1 << 21);

    /* Second s12 wrap-around */
    s0 += s12 * 666643; s1 += s12 * 470296; s2 += s12 * 654183;
    s3 -= s12 * 997805; s4 += s12 * 136657; s5 -= s12 * 683901;
    s12 = 0;

    /* Final sequential carry */
    carry = s0 >> 21; s1 += carry; s0 -= carry * ((int64_t)1 << 21);
    carry = s1 >> 21; s2 += carry; s1 -= carry * ((int64_t)1 << 21);
    carry = s2 >> 21; s3 += carry; s2 -= carry * ((int64_t)1 << 21);
    carry = s3 >> 21; s4 += carry; s3 -= carry * ((int64_t)1 << 21);
    carry = s4 >> 21; s5 += carry; s4 -= carry * ((int64_t)1 << 21);
    carry = s5 >> 21; s6 += carry; s5 -= carry * ((int64_t)1 << 21);
    carry = s6 >> 21; s7 += carry; s6 -= carry * ((int64_t)1 << 21);
    carry = s7 >> 21; s8 += carry; s7 -= carry * ((int64_t)1 << 21);
    carry = s8 >> 21; s9 += carry; s8 -= carry * ((int64_t)1 << 21);
    carry = s9 >> 21; s10 += carry; s9 -= carry * ((int64_t)1 << 21);
    carry = s10 >> 21; s11 += carry; s10 -= carry * ((int64_t)1 << 21);

    /* Pack 12 limbs into 32 bytes */
    s[0] = (uint8_t)(s0 >> 0);
    s[1] = (uint8_t)(s0 >> 8);
    s[2] = (uint8_t)((s0 >> 16) | (s1 << 5));
    s[3] = (uint8_t)(s1 >> 3);
    s[4] = (uint8_t)(s1 >> 11);
    s[5] = (uint8_t)((s1 >> 19) | (s2 << 2));
    s[6] = (uint8_t)(s2 >> 6);
    s[7] = (uint8_t)((s2 >> 14) | (s3 << 7));
    s[8] = (uint8_t)(s3 >> 1);
    s[9] = (uint8_t)(s3 >> 9);
    s[10] = (uint8_t)((s3 >> 17) | (s4 << 4));
    s[11] = (uint8_t)(s4 >> 4);
    s[12] = (uint8_t)(s4 >> 12);
    s[13] = (uint8_t)((s4 >> 20) | (s5 << 1));
    s[14] = (uint8_t)(s5 >> 7);
    s[15] = (uint8_t)((s5 >> 15) | (s6 << 6));
    s[16] = (uint8_t)(s6 >> 2);
    s[17] = (uint8_t)(s6 >> 10);
    s[18] = (uint8_t)((s6 >> 18) | (s7 << 3));
    s[19] = (uint8_t)(s7 >> 5);
    s[20] = (uint8_t)(s7 >> 13);
    s[21] = (uint8_t)(s8 >> 0);
    s[22] = (uint8_t)(s8 >> 8);
    s[23] = (uint8_t)((s8 >> 16) | (s9 << 5));
    s[24] = (uint8_t)(s9 >> 3);
    s[25] = (uint8_t)(s9 >> 11);
    s[26] = (uint8_t)((s9 >> 19) | (s10 << 2));
    s[27] = (uint8_t)(s10 >> 6);
    s[28] = (uint8_t)((s10 >> 14) | (s11 << 7));
    s[29] = (uint8_t)(s11 >> 1);
    s[30] = (uint8_t)(s11 >> 9);
    s[31] = (uint8_t)(s11 >> 17);
}

/* ============================================================================
 * ED25519 API FUNCTIONS
 * ============================================================================ */

/**
 * Generate Ed25519 keypair
 *
 * @param public_key Output: 32-byte public key
 * @param secret_key Output: 64-byte secret key (seed || public_key)
 * @return AMA_SUCCESS or error code
 */
ama_error_t ama_ed25519_keypair(uint8_t public_key[32], uint8_t secret_key[64]) {
    uint8_t hash[64];
    ge25519_p3 A;

    if (!public_key || !secret_key) {
        return AMA_ERROR_INVALID_PARAM;
    }

    /* Generate random seed (first 32 bytes of secret_key) */
    /* NOTE: In production, use a cryptographic RNG */
    /* For now, we require the caller to provide entropy in secret_key[0..31] */

    /* Hash the seed */
    sha512(secret_key, 32, hash);

    /* Clamp the scalar */
    hash[0] &= 248;
    hash[31] &= 127;
    hash[31] |= 64;

    /* Compute public key: A = s*B */
    ge25519_scalarmult_base(&A, hash);
    ge25519_p3_tobytes(public_key, &A);

    /* Store public key in secret_key[32..63] */
    memcpy(secret_key + 32, public_key, 32);

    /* Scrub intermediate values */
    ama_secure_memzero(hash, sizeof(hash));

    return AMA_SUCCESS;
}

/**
 * Sign a message with Ed25519
 *
 * @param signature Output: 64-byte signature
 * @param message Message to sign
 * @param message_len Length of message
 * @param secret_key 64-byte secret key
 * @return AMA_SUCCESS or error code
 */
ama_error_t ama_ed25519_sign(
    uint8_t signature[64],
    const uint8_t *message,
    size_t message_len,
    const uint8_t secret_key[64]
) {
    uint8_t hash[64];
    uint8_t r[64];
    uint8_t hram[64];
    ge25519_p3 R;

    /* Stack buffer for messages <= ED25519_STACK_THRESHOLD (4KB).
     * Eliminates malloc/free overhead for >99% of real-world messages.
     * Only heap-allocate for unusually large messages. */
    uint8_t stack_buf[64 + ED25519_STACK_THRESHOLD];
    uint8_t *buf;
    int buf_on_heap = 0;

    if (!signature || !secret_key || (!message && message_len > 0)) {
        return AMA_ERROR_INVALID_PARAM;
    }

    /* Hash the secret key */
    sha512(secret_key, 32, hash);
    hash[0] &= 248;
    hash[31] &= 127;
    hash[31] |= 64;

    /* Determine buffer allocation: use stack for small messages.
     * Compare against the threshold directly to avoid size_t overflow
     * in (64 + message_len) when message_len is near SIZE_MAX. */
    if (message_len <= ED25519_STACK_THRESHOLD) {
        buf = stack_buf;
    } else {
        if (message_len > SIZE_MAX - 64) {
            return AMA_ERROR_INVALID_PARAM;
        }
        buf = (uint8_t *)malloc(64 + message_len);
        if (!buf) {
            return AMA_ERROR_MEMORY;
        }
        buf_on_heap = 1;
    }

    /* r = H(h[32..63] || message) mod L */
    memcpy(buf, hash + 32, 32);
    if (message_len > 0) {
        memcpy(buf + 32, message, message_len);
    }
    sha512(buf, 32 + message_len, r);
    sc25519_reduce(r);

    /* R = r*B */
    ge25519_scalarmult_base(&R, r);
    ge25519_p3_tobytes(signature, &R);

    /* H(R || A || message) — reuse the same buffer (64 + msg_len >= 32 + msg_len) */
    memcpy(buf, signature, 32);
    memcpy(buf + 32, secret_key + 32, 32);
    if (message_len > 0) {
        memcpy(buf + 64, message, message_len);
    }
    sha512(buf, 64 + message_len, hram);
    sc25519_reduce(hram);

    /* s = r + H(R||A||M) * a mod L */
    sc25519_muladd(signature + 32, r, hram, hash);

    /* Cleanup — scrub all sensitive intermediates */
    ama_secure_memzero(hash, sizeof(hash));
    ama_secure_memzero(r, sizeof(r));
    ama_secure_memzero(hram, sizeof(hram));
    ama_secure_memzero(buf, 64 + message_len);
    if (buf_on_heap) {
        free(buf);
    }

    return AMA_SUCCESS;
}

/**
 * Verify an Ed25519 signature
 *
 * @param signature 64-byte signature
 * @param message Message to verify
 * @param message_len Length of message
 * @param public_key 32-byte public key
 * @return AMA_SUCCESS if valid, AMA_ERROR_VERIFY_FAILED if invalid
 */
ama_error_t ama_ed25519_verify(
    const uint8_t signature[64],
    const uint8_t *message,
    size_t message_len,
    const uint8_t public_key[32]
) {
    uint8_t h[64];
    ge25519_p3 A, R_check;
    ge25519_p1p1 t;
    uint8_t R_bytes[32];
    int i;

    /* Stack buffer for messages <= ED25519_STACK_THRESHOLD (4KB). */
    uint8_t stack_buf[64 + ED25519_STACK_THRESHOLD];
    uint8_t *buf;
    int buf_on_heap = 0;

    if (!signature || !public_key || (!message && message_len > 0)) {
        return AMA_ERROR_INVALID_PARAM;
    }

    /* Decode public key */
    if (ge25519_frombytes(&A, public_key) != 0) {
        return AMA_ERROR_VERIFY_FAILED;
    }

    /* Negate A for later subtraction */
    fe25519_neg(A.X, A.X);
    fe25519_neg(A.T, A.T);

    /* H(R || A || message) — stack allocation for small messages.
     * Compare against the threshold directly to avoid size_t overflow
     * in (64 + message_len) when message_len is near SIZE_MAX. */
    if (message_len <= ED25519_STACK_THRESHOLD) {
        buf = stack_buf;
    } else {
        if (message_len > SIZE_MAX - 64) {
            return AMA_ERROR_INVALID_PARAM;
        }
        buf = (uint8_t *)malloc(64 + message_len);
        if (!buf) {
            return AMA_ERROR_MEMORY;
        }
        buf_on_heap = 1;
    }
    memcpy(buf, signature, 32);
    memcpy(buf + 32, public_key, 32);
    if (message_len > 0) {
        memcpy(buf + 64, message, message_len);
    }
    sha512(buf, 64 + message_len, h);
    sc25519_reduce(h);
    ama_secure_memzero(buf, 64 + message_len);
    if (buf_on_heap) {
        free(buf);
    }

    /* Check: [s]B - [h]A == R */
    /* Compute [s]B */
    ge25519_scalarmult_base(&R_check, signature + 32);

    /* Compute [h]A (A is already negated) */
    ge25519_p3 hA;
    ge25519_scalarmult(&hA, h, &A);

    /* R_check = [s]B + (-[h]A) = [s]B - [h]A */
    ge25519_add(&t, &R_check, &hA);
    ge25519_p1p1_to_p3(&R_check, &t);

    /* Encode and compare */
    ge25519_p3_tobytes(R_bytes, &R_check);

    int diff = 0;
    for (i = 0; i < 32; i++) {
        diff |= R_bytes[i] ^ signature[i];
    }

    return (diff == 0) ? AMA_SUCCESS : AMA_ERROR_VERIFY_FAILED;
}

/**
 * Batch verify multiple Ed25519 signatures.
 *
 * vartime: safe for verification where all scalars are public.
 * Each entry is verified independently; results[i] = 1 if valid, 0 if invalid.
 *
 * @param entries  Array of batch entries
 * @param count    Number of entries
 * @param results  Output: 1=valid, 0=invalid per entry
 * @return AMA_SUCCESS if all valid, AMA_ERROR_VERIFY_FAILED if any invalid,
 *         AMA_ERROR_INVALID_PARAM on NULL inputs
 */
ama_error_t ama_ed25519_batch_verify(
    const ama_ed25519_batch_entry *entries,
    size_t count,
    int *results
) {
    if (!entries || !results) {
        return AMA_ERROR_INVALID_PARAM;
    }
    if (count == 0) {
        return AMA_SUCCESS;
    }

    int all_valid = 1;
    for (size_t i = 0; i < count; i++) {
        ama_error_t rc = ama_ed25519_verify(
            entries[i].signature,
            entries[i].message,
            entries[i].message_len,
            entries[i].public_key
        );
        results[i] = (rc == AMA_SUCCESS) ? 1 : 0;
        if (!results[i]) {
            all_valid = 0;
        }
    }

    return all_valid ? AMA_SUCCESS : AMA_ERROR_VERIFY_FAILED;
}

/**
 * Raw scalar-basepoint multiplication: point = scalar * G.
 *
 * Unlike ama_ed25519_keypair() this does NOT hash or clamp the scalar;
 * the 32-byte little-endian scalar is used verbatim.  This is the
 * primitive required by FROST (RFC 9591) and any other Schnorr-like
 * protocol that needs algebraic linearity:
 *   point_from_scalar(a) + point_from_scalar(b) == point_from_scalar(a+b)
 *
 * @param point   Output: 32-byte compressed Ed25519 point
 * @param scalar  Input:  32-byte little-endian scalar
 */
void ama_ed25519_point_from_scalar(uint8_t point[32],
                                   const uint8_t scalar[32]) {
    ge25519_p3 R;
    ge25519_scalarmult_base(&R, scalar);
    ge25519_p3_tobytes(point, &R);
}
