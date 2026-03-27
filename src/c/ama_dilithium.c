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
 * @file ama_dilithium.c
 * @brief ML-DSA-65 (CRYSTALS-Dilithium) Digital Signature - Native C Implementation
 * @author Andrew E. A., Steel Security Advisors LLC
 * @date 2026-03-08
 *
 * Full native implementation of ML-DSA-65 (NIST FIPS 204) digital signatures.
 * Implements keypair generation, signing, and verification using the
 * Module-LWE and Module-SIS hardness assumptions.
 *
 * Parameters (ML-DSA-65 / Dilithium3):
 * - Security level: NIST Level 3 (~192-bit quantum security)
 * - Public key: 1952 bytes
 * - Secret key: 4032 bytes
 * - Signature: 3309 bytes
 * - k = 6, l = 5, eta = 4, tau = 49, beta = 196
 * - gamma1 = 2^19, gamma2 = (q-1)/32, omega = 55
 *
 * Standards:
 * - NIST FIPS 204 (ML-DSA)
 * - Module-LWE / Module-SIS hardness
 *
 * Security notes:
 * - Constant-time polynomial arithmetic
 * - No secret-dependent branches
 * - Rejection sampling for signatures
 */

#include "../include/ama_cryptography.h"
#include "../include/ama_dispatch.h"
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include "ama_platform_rand.h"

/* Forward declarations from ama_sha3.c */
extern ama_error_t ama_sha3_256(const uint8_t* input, size_t input_len, uint8_t* output);
extern ama_error_t ama_sha3_512(const uint8_t* input, size_t input_len, uint8_t* output);
extern ama_error_t ama_shake128(const uint8_t* input, size_t input_len,
                                 uint8_t* output, size_t output_len);
extern ama_error_t ama_shake256(const uint8_t* input, size_t input_len,
                                 uint8_t* output, size_t output_len);
extern ama_error_t ama_shake256_inc_init(ama_sha3_ctx* ctx);
extern ama_error_t ama_shake256_inc_absorb(ama_sha3_ctx* ctx, const uint8_t* data, size_t len);
extern ama_error_t ama_shake256_inc_finalize(ama_sha3_ctx* ctx);
extern ama_error_t ama_shake256_inc_squeeze(ama_sha3_ctx* ctx, uint8_t* output, size_t outlen);
extern ama_error_t ama_shake128_inc_init(ama_sha3_ctx* ctx);
extern ama_error_t ama_shake128_inc_absorb(ama_sha3_ctx* ctx, const uint8_t* data, size_t len);
extern ama_error_t ama_shake128_inc_finalize(ama_sha3_ctx* ctx);
extern ama_error_t ama_shake128_inc_squeeze(ama_sha3_ctx* ctx, uint8_t* output, size_t outlen);

/* ============================================================================
 * ML-DSA-65 PARAMETERS (NIST FIPS 204)
 * ============================================================================ */

#define DIL_N 256
#define DIL_Q 8380417
#define DIL_K 6
#define DIL_L 5
#define DIL_ETA 4
#define DIL_TAU 49
#define DIL_BETA 196
#define DIL_GAMMA1 (1 << 19)
#define DIL_GAMMA2 ((DIL_Q - 1) / 32)
#define DIL_OMEGA 55
#define DIL_D 13

#define DIL_SEEDBYTES 32
#define DIL_CTILDEBYTES 48  /* ML-DSA-65: 48; mode 2: 32; mode 5: 64 */
#define DIL_CRHBYTES 64
#define DIL_TRBYTES 64

#define DIL_POLYZ_PACKEDBYTES 640
#define DIL_POLYW1_PACKEDBYTES 128
#define DIL_POLYETA_PACKEDBYTES 128
#define DIL_POLYT1_PACKEDBYTES 320
#define DIL_POLYT0_PACKEDBYTES 416

/* ============================================================================
 * POLYNOMIAL TYPES
 * ============================================================================ */

typedef struct {
    int32_t coeffs[DIL_N];
} dil_poly;

typedef struct {
    dil_poly vec[DIL_L];
} dil_polyvecl;

typedef struct {
    dil_poly vec[DIL_K];
} dil_polyveck;

/* ============================================================================
 * NTT TWIDDLE FACTORS FOR DILITHIUM (q = 8380417)
 * ============================================================================ */

/* Primitive 256th root of unity mod q in Montgomery form */
static const int32_t dil_zetas[DIL_N] = {
         0,    25847, -2608894,  -518909,   237124,  -777960,  -876248,   466468,
   1826347,  2353451,  -359251, -2091905,  3119733, -2884855,  3111497,  2680103,
   2725464,  1024112, -1079900,  3585928,  -549488, -1119584,  2619752, -2108549,
  -2118186, -3859737, -1399561, -3277672,  1757237,   -19422,  4010497,   280005,
   2706023,    95776,  3077325,  3530437, -1661693, -3592148, -2537516,  3915439,
  -3861115, -3043716,  3574422, -2867647,  3539968,  -300467,  2348700,  -539299,
  -1699267, -1643818,  3505694, -3821735,  3507263, -2140649, -1600420,  3699596,
    811944,   531354,   954230,  3881043,  3900724, -2556880,  2071892, -2797779,
  -3930395, -1528703, -3677745, -3041255, -1452451,  3475950,  2176455, -1585221,
  -1257611,  1939314, -4083598, -1000202, -3190144, -3157330, -3632928,   126922,
   3412210,  -983419,  2147896,  2715295, -2967645, -3693493,  -411027, -2477047,
   -671102, -1228525,   -22981, -1308169,  -381987,  1349076,  1852771, -1430430,
  -3343383,   264944,   508951,  3097992,    44288, -1100098,   904516,  3958618,
  -3724342,    -8578,  1653064, -3249728,  2389356,  -210977,   759969, -1316856,
    189548, -3553272,  3159746, -1851402, -2409325,  -177440,  1315589,  1341330,
   1285669, -1584928,  -812732, -1439742, -3019102, -3881060, -3628969,  3839961,
   2091667,  3407706,  2316500,  3817976, -3342478,  2244091, -2446433, -3562462,
    266997,  2434439, -1235728,  3513181, -3520352, -3759364, -1197226, -3193378,
    900702,  1859098,   909542,   819034,   495491, -1613174,   -43260,  -522500,
   -655327, -3122442,  2031748,  3207046, -3556995,  -525098,  -768622, -3595838,
    342297,   286988, -2437823,  4108315,  3437287, -3342277,  1735879,   203044,
   2842341,  2691481, -2590150,  1265009,  4055324,  1247620,  2486353,  1595974,
  -3767016,  1250494,  2635921, -3548272, -2994039,  1869119,  1903435, -1050970,
  -1333058,  1237275, -3318210, -1430225,  -451100,  1312455,  3306115, -1962642,
  -1279661,  1917081, -2546312, -1374803,  1500165,   777191,  2235880,  3406031,
   -542412, -2831860, -1671176, -1846953, -2584293, -3724270,   594136, -3776993,
  -2013608,  2432395,  2454455,  -164721,  1957272,  3369112,   185531, -1207385,
  -3183426,   162844,  1616392,  3014001,   810149,  1652634, -3694233, -1799107,
  -3038916,  3523897,  3866901,   269760,  2213111,  -975884,  1717735,   472078,
   -426683,  1723600, -1803090,  1910376, -1667432, -1104333,  -260646, -3833893,
  -2939036, -2235985,  -420899, -2286327,   183443,  -976891,  1612842, -3545687,
   -554416,  3919660,   -48306, -1362209,  3937738,  1400424,  -846154,  1976782
};

/* ============================================================================
 * MONTGOMERY AND MODULAR ARITHMETIC
 * ============================================================================ */

#define DIL_MONT (-4186625)   /* 2^32 mod q */
#define DIL_QINV 58728449     /* q^(-1) mod 2^32 */

/**
 * Montgomery reduction for Dilithium
 * Computes a * R^-1 mod q where R = 2^32
 */
static int32_t dil_montgomery_reduce(int64_t a) {
    int32_t t;
    t = (int32_t)((int64_t)(int32_t)a * DIL_QINV);
    t = (int32_t)((a - (int64_t)t * DIL_Q) >> 32);
    return t;
}

/**
 * Barrett reduction mod q
 * Reduces a to range [0, q)
 */
static int32_t dil_reduce32(int32_t a) {
    int32_t t;
    t = (a + (1 << 22)) >> 23;
    t = a - t * DIL_Q;
    return t;
}

/**
 * Conditional addition of q
 * If a is negative, add q
 */
static int32_t dil_caddq(int32_t a) {
    a += (a >> 31) & DIL_Q;
    return a;
}

/**
 * Freeze: reduce and make positive
 */
static int32_t dil_freeze(int32_t a) {
    a = dil_reduce32(a);
    a = dil_caddq(a);
    return a;
}

/* ============================================================================
 * NTT FOR DILITHIUM
 * ============================================================================ */

/**
 * Forward NTT (Number Theoretic Transform) for Dilithium
 */
static void dil_ntt(int32_t a[DIL_N]) {
    /* Dispatch to SIMD implementation when available (INVARIANT-4: graceful fallback) */
    const ama_dispatch_table_t *dt = ama_get_dispatch_table();
    if (dt->dilithium_ntt) {
        dt->dilithium_ntt(a, dil_zetas);
        return;
    }

    /* Generic C implementation */
    unsigned int len, start, j, k;
    int32_t zeta, t;

    k = 0;
    for (len = 128; len > 0; len >>= 1) {
        for (start = 0; start < DIL_N; start = j + len) {
            zeta = dil_zetas[++k];
            for (j = start; j < start + len; ++j) {
                t = dil_montgomery_reduce((int64_t)zeta * a[j + len]);
                a[j + len] = a[j] - t;
                a[j] = a[j] + t;
            }
        }
    }
}

/**
 * Inverse NTT for Dilithium
 */
static void dil_invntt(int32_t a[DIL_N]) {
    unsigned int start, len, j, k;
    int32_t t, zeta;
    const int32_t f = 41978;  /* Mont^(-1) * N^(-1) mod q */

    k = 256;
    for (len = 1; len < DIL_N; len <<= 1) {
        for (start = 0; start < DIL_N; start = j + len) {
            zeta = -dil_zetas[--k];
            for (j = start; j < start + len; ++j) {
                t = a[j];
                a[j] = t + a[j + len];
                a[j + len] = t - a[j + len];
                a[j + len] = dil_montgomery_reduce((int64_t)zeta * a[j + len]);
            }
        }
    }

    for (j = 0; j < DIL_N; ++j) {
        a[j] = dil_montgomery_reduce((int64_t)f * a[j]);
    }
}

/* ============================================================================
 * POLYNOMIAL OPERATIONS
 * ============================================================================ */

/**
 * Pointwise multiplication in NTT domain with Montgomery reduction
 */
static void dil_poly_pointwise_montgomery(dil_poly *c, const dil_poly *a,
                                           const dil_poly *b) {
    /* Dispatch to SIMD implementation when available (INVARIANT-4: graceful fallback) */
    const ama_dispatch_table_t *dt = ama_get_dispatch_table();
    if (dt->dilithium_pointwise) {
        dt->dilithium_pointwise(c->coeffs, a->coeffs, b->coeffs);
        return;
    }

    /* Generic C implementation */
    unsigned int i;
    for (i = 0; i < DIL_N; ++i) {
        c->coeffs[i] = dil_montgomery_reduce((int64_t)a->coeffs[i] * b->coeffs[i]);
    }
}

/**
 * Add two polynomials
 */
static void dil_poly_add(dil_poly *c, const dil_poly *a, const dil_poly *b) {
    unsigned int i;
    for (i = 0; i < DIL_N; ++i) {
        c->coeffs[i] = a->coeffs[i] + b->coeffs[i];
    }
}

/**
 * Subtract two polynomials
 */
static void dil_poly_sub(dil_poly *c, const dil_poly *a, const dil_poly *b) {
    unsigned int i;
    for (i = 0; i < DIL_N; ++i) {
        c->coeffs[i] = a->coeffs[i] - b->coeffs[i];
    }
}

/**
 * Reduce all coefficients mod q
 */
static void dil_poly_reduce(dil_poly *a) {
    unsigned int i;
    for (i = 0; i < DIL_N; ++i) {
        a->coeffs[i] = dil_reduce32(a->coeffs[i]);
    }
}

/**
 * Conditional addition of q to all negative coefficients
 */
static void dil_poly_caddq(dil_poly *a) {
    unsigned int i;
    for (i = 0; i < DIL_N; ++i) {
        a->coeffs[i] = dil_caddq(a->coeffs[i]);
    }
}

/**
 * Forward NTT on polynomial
 */
static void dil_poly_ntt(dil_poly *a) {
    dil_ntt(a->coeffs);
}

/**
 * Inverse NTT on polynomial
 */
static void dil_poly_invntt(dil_poly *a) {
    dil_invntt(a->coeffs);
}

/**
 * Check infinity norm of polynomial
 * Returns 1 if any coefficient exceeds bound (in centered representation)
 */
static int dil_poly_chknorm(const dil_poly *a, int32_t B) {
    unsigned int i;
    int32_t t;

    if (B > (DIL_Q - 1) / 8) {
        return 1;
    }

    for (i = 0; i < DIL_N; ++i) {
        t = a->coeffs[i] >> 31;
        t = a->coeffs[i] - (t & 2 * a->coeffs[i]);  /* absolute value */
        if (t >= B) {
            return 1;
        }
    }
    return 0;
}

/* ============================================================================
 * ROUNDING AND DECOMPOSITION (FIPS 204)
 * ============================================================================ */

/**
 * Power2Round: decompose a = a1*2^d + a0
 */
static int32_t dil_power2round(int32_t *a0, int32_t a) {
    int32_t a1;
    a = dil_freeze(a);
    a1 = (a + (1 << (DIL_D - 1)) - 1) >> DIL_D;
    *a0 = a - (a1 << DIL_D);
    return a1;
}

/**
 * Decompose: a = a1*alpha + a0 with |a0| <= alpha/2
 * For ML-DSA-65: alpha = 2*gamma2 = (q-1)/16
 */
static int32_t dil_decompose(int32_t *a0, int32_t a) {
    int32_t a1;
    a = dil_freeze(a);

    a1 = (a + 127) >> 7;
    a1 = (a1 * 1025 + (1 << 21)) >> 22;
    a1 &= 15;  /* mod 16 for gamma2 = (q-1)/32 */

    *a0 = a - a1 * 2 * DIL_GAMMA2;
    *a0 -= (((DIL_Q - 1) / 2 - *a0) >> 31) & DIL_Q;
    return a1;
}

/**
 * MakeHint: compute hint bit
 */
static unsigned int dil_make_hint(int32_t a0, int32_t a1) {
    if (a0 > DIL_GAMMA2 || a0 < -DIL_GAMMA2 ||
        (a0 == -DIL_GAMMA2 && a1 != 0)) {
        return 1;
    }
    return 0;
}

/**
 * UseHint: recover high bits from hint
 */
static int32_t dil_use_hint(int32_t a, unsigned int hint) {
    int32_t a0, a1;

    a1 = dil_decompose(&a0, a);

    if (hint == 0) {
        return a1;
    }

    if (a0 > 0) {
        return (a1 + 1) & 15;
    } else {
        return (a1 - 1) & 15;
    }
}

/* ============================================================================
 * POLYNOMIAL PACKING / UNPACKING
 * ============================================================================ */

/**
 * Pack polynomial with eta-range coefficients
 * For eta = 4: each coefficient in [0, 2*eta] packed into 4 bits
 */
static void dil_polyeta_pack(uint8_t *r, const dil_poly *a) {
    unsigned int i;
    uint8_t t[8];

    for (i = 0; i < DIL_N / 2; ++i) {
        t[0] = (uint8_t)(DIL_ETA - a->coeffs[2*i + 0]);
        t[1] = (uint8_t)(DIL_ETA - a->coeffs[2*i + 1]);
        r[i] = t[0] | (t[1] << 4);
    }
}

/**
 * Unpack polynomial with eta-range coefficients
 */
static void dil_polyeta_unpack(dil_poly *r, const uint8_t *a) {
    unsigned int i;

    for (i = 0; i < DIL_N / 2; ++i) {
        r->coeffs[2*i + 0] = (int32_t)(a[i] & 0x0F);
        r->coeffs[2*i + 1] = (int32_t)(a[i] >> 4);
        r->coeffs[2*i + 0] = DIL_ETA - r->coeffs[2*i + 0];
        r->coeffs[2*i + 1] = DIL_ETA - r->coeffs[2*i + 1];
    }
}

/**
 * Pack t1 polynomial (10-bit coefficients)
 */
static void dil_polyt1_pack(uint8_t *r, const dil_poly *a) {
    unsigned int i;

    for (i = 0; i < DIL_N / 4; ++i) {
        r[5*i + 0] = (uint8_t)(a->coeffs[4*i + 0] >> 0);
        r[5*i + 1] = (uint8_t)((a->coeffs[4*i + 0] >> 8) |
                                (a->coeffs[4*i + 1] << 2));
        r[5*i + 2] = (uint8_t)((a->coeffs[4*i + 1] >> 6) |
                                (a->coeffs[4*i + 2] << 4));
        r[5*i + 3] = (uint8_t)((a->coeffs[4*i + 2] >> 4) |
                                (a->coeffs[4*i + 3] << 6));
        r[5*i + 4] = (uint8_t)(a->coeffs[4*i + 3] >> 2);
    }
}

/**
 * Unpack t1 polynomial
 */
static void dil_polyt1_unpack(dil_poly *r, const uint8_t *a) {
    unsigned int i;

    for (i = 0; i < DIL_N / 4; ++i) {
        r->coeffs[4*i + 0] = ((a[5*i + 0] >> 0) | ((int32_t)a[5*i + 1] << 8)) & 0x3FF;
        r->coeffs[4*i + 1] = ((a[5*i + 1] >> 2) | ((int32_t)a[5*i + 2] << 6)) & 0x3FF;
        r->coeffs[4*i + 2] = ((a[5*i + 2] >> 4) | ((int32_t)a[5*i + 3] << 4)) & 0x3FF;
        r->coeffs[4*i + 3] = ((a[5*i + 3] >> 6) | ((int32_t)a[5*i + 4] << 2)) & 0x3FF;
    }
}

/**
 * Pack t0 polynomial (13-bit coefficients centered around 2^(d-1))
 */
static void dil_polyt0_pack(uint8_t *r, const dil_poly *a) {
    unsigned int i;
    int32_t t[8];

    for (i = 0; i < DIL_N / 8; ++i) {
        t[0] = (1 << (DIL_D - 1)) - a->coeffs[8*i + 0];
        t[1] = (1 << (DIL_D - 1)) - a->coeffs[8*i + 1];
        t[2] = (1 << (DIL_D - 1)) - a->coeffs[8*i + 2];
        t[3] = (1 << (DIL_D - 1)) - a->coeffs[8*i + 3];
        t[4] = (1 << (DIL_D - 1)) - a->coeffs[8*i + 4];
        t[5] = (1 << (DIL_D - 1)) - a->coeffs[8*i + 5];
        t[6] = (1 << (DIL_D - 1)) - a->coeffs[8*i + 6];
        t[7] = (1 << (DIL_D - 1)) - a->coeffs[8*i + 7];

        r[13*i +  0] = (uint8_t)(t[0]);
        r[13*i +  1] = (uint8_t)(t[0] >> 8);
        r[13*i +  1] |= (uint8_t)(t[1] << 5);
        r[13*i +  2] = (uint8_t)(t[1] >> 3);
        r[13*i +  3] = (uint8_t)(t[1] >> 11);
        r[13*i +  3] |= (uint8_t)(t[2] << 2);
        r[13*i +  4] = (uint8_t)(t[2] >> 6);
        r[13*i +  4] |= (uint8_t)(t[3] << 7);
        r[13*i +  5] = (uint8_t)(t[3] >> 1);
        r[13*i +  6] = (uint8_t)(t[3] >> 9);
        r[13*i +  6] |= (uint8_t)(t[4] << 4);
        r[13*i +  7] = (uint8_t)(t[4] >> 4);
        r[13*i +  8] = (uint8_t)(t[4] >> 12);
        r[13*i +  8] |= (uint8_t)(t[5] << 1);
        r[13*i +  9] = (uint8_t)(t[5] >> 7);
        r[13*i +  9] |= (uint8_t)(t[6] << 6);
        r[13*i + 10] = (uint8_t)(t[6] >> 2);
        r[13*i + 11] = (uint8_t)(t[6] >> 10);
        r[13*i + 11] |= (uint8_t)(t[7] << 3);
        r[13*i + 12] = (uint8_t)(t[7] >> 5);
    }
}

/**
 * Unpack t0 polynomial
 */
static void dil_polyt0_unpack(dil_poly *r, const uint8_t *a) {
    unsigned int i;

    for (i = 0; i < DIL_N / 8; ++i) {
        r->coeffs[8*i + 0]  = a[13*i + 0];
        r->coeffs[8*i + 0] |= (int32_t)a[13*i + 1] << 8;
        r->coeffs[8*i + 0] &= 0x1FFF;

        r->coeffs[8*i + 1]  = a[13*i + 1] >> 5;
        r->coeffs[8*i + 1] |= (int32_t)a[13*i + 2] << 3;
        r->coeffs[8*i + 1] |= (int32_t)a[13*i + 3] << 11;
        r->coeffs[8*i + 1] &= 0x1FFF;

        r->coeffs[8*i + 2]  = a[13*i + 3] >> 2;
        r->coeffs[8*i + 2] |= (int32_t)a[13*i + 4] << 6;
        r->coeffs[8*i + 2] &= 0x1FFF;

        r->coeffs[8*i + 3]  = a[13*i + 4] >> 7;
        r->coeffs[8*i + 3] |= (int32_t)a[13*i + 5] << 1;
        r->coeffs[8*i + 3] |= (int32_t)a[13*i + 6] << 9;
        r->coeffs[8*i + 3] &= 0x1FFF;

        r->coeffs[8*i + 4]  = a[13*i + 6] >> 4;
        r->coeffs[8*i + 4] |= (int32_t)a[13*i + 7] << 4;
        r->coeffs[8*i + 4] |= (int32_t)a[13*i + 8] << 12;
        r->coeffs[8*i + 4] &= 0x1FFF;

        r->coeffs[8*i + 5]  = a[13*i + 8] >> 1;
        r->coeffs[8*i + 5] |= (int32_t)a[13*i + 9] << 7;
        r->coeffs[8*i + 5] &= 0x1FFF;

        r->coeffs[8*i + 6]  = a[13*i + 9] >> 6;
        r->coeffs[8*i + 6] |= (int32_t)a[13*i + 10] << 2;
        r->coeffs[8*i + 6] |= (int32_t)a[13*i + 11] << 10;
        r->coeffs[8*i + 6] &= 0x1FFF;

        r->coeffs[8*i + 7]  = a[13*i + 11] >> 3;
        r->coeffs[8*i + 7] |= (int32_t)a[13*i + 12] << 5;
        r->coeffs[8*i + 7] &= 0x1FFF;

        r->coeffs[8*i + 0] = (1 << (DIL_D - 1)) - r->coeffs[8*i + 0];
        r->coeffs[8*i + 1] = (1 << (DIL_D - 1)) - r->coeffs[8*i + 1];
        r->coeffs[8*i + 2] = (1 << (DIL_D - 1)) - r->coeffs[8*i + 2];
        r->coeffs[8*i + 3] = (1 << (DIL_D - 1)) - r->coeffs[8*i + 3];
        r->coeffs[8*i + 4] = (1 << (DIL_D - 1)) - r->coeffs[8*i + 4];
        r->coeffs[8*i + 5] = (1 << (DIL_D - 1)) - r->coeffs[8*i + 5];
        r->coeffs[8*i + 6] = (1 << (DIL_D - 1)) - r->coeffs[8*i + 6];
        r->coeffs[8*i + 7] = (1 << (DIL_D - 1)) - r->coeffs[8*i + 7];
    }
}

/**
 * Pack z polynomial (gamma1-range coefficients, 20 bits)
 */
static void dil_polyz_pack(uint8_t *r, const dil_poly *a) {
    unsigned int i;
    int32_t t[4];

    for (i = 0; i < DIL_N / 2; ++i) {
        t[0] = DIL_GAMMA1 - a->coeffs[2*i + 0];
        t[1] = DIL_GAMMA1 - a->coeffs[2*i + 1];

        r[5*i + 0] = (uint8_t)(t[0]);
        r[5*i + 1] = (uint8_t)(t[0] >> 8);
        r[5*i + 2] = (uint8_t)(t[0] >> 16);
        r[5*i + 2] |= (uint8_t)(t[1] << 4);
        r[5*i + 3] = (uint8_t)(t[1] >> 4);
        r[5*i + 4] = (uint8_t)(t[1] >> 12);
    }
}

/**
 * Unpack z polynomial
 */
static void dil_polyz_unpack(dil_poly *r, const uint8_t *a) {
    unsigned int i;

    for (i = 0; i < DIL_N / 2; ++i) {
        r->coeffs[2*i + 0]  = a[5*i + 0];
        r->coeffs[2*i + 0] |= (int32_t)a[5*i + 1] << 8;
        r->coeffs[2*i + 0] |= (int32_t)a[5*i + 2] << 16;
        r->coeffs[2*i + 0] &= 0xFFFFF;

        r->coeffs[2*i + 1]  = a[5*i + 2] >> 4;
        r->coeffs[2*i + 1] |= (int32_t)a[5*i + 3] << 4;
        r->coeffs[2*i + 1] |= (int32_t)a[5*i + 4] << 12;
        r->coeffs[2*i + 1] &= 0xFFFFF;

        r->coeffs[2*i + 0] = DIL_GAMMA1 - r->coeffs[2*i + 0];
        r->coeffs[2*i + 1] = DIL_GAMMA1 - r->coeffs[2*i + 1];
    }
}

/**
 * Pack w1 polynomial (4-bit coefficients for gamma2 = (q-1)/32)
 */
static void dil_polyw1_pack(uint8_t *r, const dil_poly *a) {
    unsigned int i;
    for (i = 0; i < DIL_N / 2; ++i) {
        r[i] = (uint8_t)(a->coeffs[2*i + 0] | (a->coeffs[2*i + 1] << 4));
    }
}

/* ============================================================================
 * SAMPLING FROM SHAKE
 * ============================================================================ */

/**
 * Sample uniform polynomial from SHAKE128 stream (FIPS 204 RejNTTPoly)
 * Rejection sampling to get coefficients in [0, q)
 * Uses incremental SHAKE128 for proper XOF streaming.
 */
static void dil_poly_uniform(dil_poly *a, const uint8_t seed[DIL_SEEDBYTES],
                              uint16_t nonce) {
    unsigned int ctr, pos;
    uint8_t buf[DIL_SEEDBYTES + 2];
    uint8_t stream[168 * 5];  /* 5 SHAKE128 blocks */
    int32_t t;
    ama_sha3_ctx shake_ctx;

    memcpy(buf, seed, DIL_SEEDBYTES);
    buf[DIL_SEEDBYTES] = (uint8_t)(nonce & 0xFF);
    buf[DIL_SEEDBYTES + 1] = (uint8_t)(nonce >> 8);

    ama_shake128_inc_init(&shake_ctx);
    ama_shake128_inc_absorb(&shake_ctx, buf, DIL_SEEDBYTES + 2);
    ama_shake128_inc_finalize(&shake_ctx);
    ama_shake128_inc_squeeze(&shake_ctx, stream, sizeof(stream));

    ctr = 0;
    pos = 0;
    while (ctr < DIL_N) {
        if (pos + 3 > sizeof(stream)) {
            /* Squeeze more bytes from the XOF */
            ama_shake128_inc_squeeze(&shake_ctx, stream, sizeof(stream));
            pos = 0;
        }
        t  = stream[pos++];
        t |= (int32_t)stream[pos++] << 8;
        t |= (int32_t)stream[pos++] << 16;
        t &= 0x7FFFFF;  /* 23 bits */

        if (t < DIL_Q) {
            a->coeffs[ctr++] = t;
        }
    }
}

/**
 * Sample polynomial with coefficients in [-eta, eta] from SHAKE256 stream
 * Uses proper rejection sampling for eta = 4: each 4-bit nibble in [0, 8]
 * maps to coefficient eta - nibble. Nibbles > 2*eta are rejected and the
 * next nibble is consumed. This ensures a uniform distribution over [-4, 4].
 */
/**
 * Sample polynomial with coefficients in [-eta, eta] from SHAKE256 stream
 * (FIPS 204 RejBoundedPoly). Uses incremental SHAKE256 for proper XOF streaming.
 */
static void dil_poly_uniform_eta(dil_poly *a, const uint8_t seed[DIL_CRHBYTES],
                                  uint16_t nonce) {
    uint8_t buf[DIL_CRHBYTES + 2];
    uint8_t stream[136 * 2];  /* 2 SHAKE256 blocks */
    unsigned int ctr, pos;
    ama_sha3_ctx shake_ctx;

    memcpy(buf, seed, DIL_CRHBYTES);
    buf[DIL_CRHBYTES] = (uint8_t)(nonce & 0xFF);
    buf[DIL_CRHBYTES + 1] = (uint8_t)(nonce >> 8);

    ama_shake256_inc_init(&shake_ctx);
    ama_shake256_inc_absorb(&shake_ctx, buf, DIL_CRHBYTES + 2);
    ama_shake256_inc_finalize(&shake_ctx);
    ama_shake256_inc_squeeze(&shake_ctx, stream, sizeof(stream));

    ctr = 0;
    pos = 0;
    while (ctr < DIL_N) {
        uint8_t t0, t1;

        if (pos >= sizeof(stream)) {
            ama_shake256_inc_squeeze(&shake_ctx, stream, sizeof(stream));
            pos = 0;
        }

        t0 = stream[pos] & 0x0F;
        t1 = stream[pos] >> 4;
        pos++;

        if (t0 < 2 * DIL_ETA + 1) {
            a->coeffs[ctr++] = DIL_ETA - (int32_t)t0;
        }
        if (t1 < 2 * DIL_ETA + 1 && ctr < DIL_N) {
            a->coeffs[ctr++] = DIL_ETA - (int32_t)t1;
        }
    }
}

/**
 * Sample polynomial with coefficients in [-(gamma1-1), gamma1] from SHAKE256
 */
static void dil_poly_uniform_gamma1(dil_poly *a, const uint8_t seed[DIL_CRHBYTES],
                                     uint16_t nonce) {
    uint8_t buf[DIL_CRHBYTES + 2];
    uint8_t stream[DIL_POLYZ_PACKEDBYTES];

    memcpy(buf, seed, DIL_CRHBYTES);
    buf[DIL_CRHBYTES] = (uint8_t)(nonce & 0xFF);
    buf[DIL_CRHBYTES + 1] = (uint8_t)(nonce >> 8);

    ama_shake256(buf, DIL_CRHBYTES + 2, stream, DIL_POLYZ_PACKEDBYTES);
    dil_polyz_unpack(a, stream);
}

/**
 * Sample challenge polynomial c with exactly tau nonzero +/-1 coefficients.
 * Uses proper incremental SHAKE256 absorb/squeeze per FIPS 204.
 */
static void dil_poly_challenge(dil_poly *c, const uint8_t seed[DIL_CTILDEBYTES]) {
    uint8_t buf[136];  /* SHAKE256 rate block */
    unsigned int i, b, pos;
    uint64_t signs;
    ama_sha3_ctx shake_ctx;

    /* Absorb seed, finalize, then squeeze first block */
    ama_shake256_inc_init(&shake_ctx);
    ama_shake256_inc_absorb(&shake_ctx, seed, DIL_CTILDEBYTES);
    ama_shake256_inc_finalize(&shake_ctx);
    ama_shake256_inc_squeeze(&shake_ctx, buf, sizeof(buf));

    /* First 8 bytes encode signs */
    signs = 0;
    for (i = 0; i < 8; ++i) {
        signs |= (uint64_t)buf[i] << (8 * i);
    }

    memset(c->coeffs, 0, sizeof(c->coeffs));

    pos = 8;
    for (i = DIL_N - DIL_TAU; i < DIL_N; ++i) {
        /* Rejection sampling: get uniform value in [0, i] */
        do {
            if (pos >= sizeof(buf)) {
                /* Squeeze next block from the same SHAKE256 state */
                ama_shake256_inc_squeeze(&shake_ctx, buf, sizeof(buf));
                pos = 0;
            }
            b = buf[pos++];
        } while (b > i);

        c->coeffs[i] = c->coeffs[b];
        c->coeffs[b] = 1 - 2 * (int32_t)(signs & 1);
        signs >>= 1;
    }
}

/* ============================================================================
 * VECTOR OPERATIONS
 * ============================================================================ */

static void dil_polyvecl_ntt(dil_polyvecl *v) {
    unsigned int i;
    for (i = 0; i < DIL_L; ++i) {
        dil_poly_ntt(&v->vec[i]);
    }
}

static int dil_polyvecl_chknorm(const dil_polyvecl *v, int32_t bound) {
    unsigned int i;
    for (i = 0; i < DIL_L; ++i) {
        if (dil_poly_chknorm(&v->vec[i], bound)) {
            return 1;
        }
    }
    return 0;
}

static void dil_polyveck_ntt(dil_polyveck *v) {
    unsigned int i;
    for (i = 0; i < DIL_K; ++i) {
        dil_poly_ntt(&v->vec[i]);
    }
}

static void dil_polyveck_invntt(dil_polyveck *v) {
    unsigned int i;
    for (i = 0; i < DIL_K; ++i) {
        dil_poly_invntt(&v->vec[i]);
    }
}

static void dil_polyveck_add(dil_polyveck *w, const dil_polyveck *u,
                              const dil_polyveck *v) {
    unsigned int i;
    for (i = 0; i < DIL_K; ++i) {
        dil_poly_add(&w->vec[i], &u->vec[i], &v->vec[i]);
    }
}

static void dil_polyveck_sub(dil_polyveck *w, const dil_polyveck *u,
                              const dil_polyveck *v) {
    unsigned int i;
    for (i = 0; i < DIL_K; ++i) {
        dil_poly_sub(&w->vec[i], &u->vec[i], &v->vec[i]);
    }
}

static void dil_polyveck_reduce(dil_polyveck *v) {
    unsigned int i;
    for (i = 0; i < DIL_K; ++i) {
        dil_poly_reduce(&v->vec[i]);
    }
}

static void dil_polyveck_caddq(dil_polyveck *v) {
    unsigned int i;
    for (i = 0; i < DIL_K; ++i) {
        dil_poly_caddq(&v->vec[i]);
    }
}

static int dil_polyveck_chknorm(const dil_polyveck *v, int32_t bound) {
    unsigned int i;
    for (i = 0; i < DIL_K; ++i) {
        if (dil_poly_chknorm(&v->vec[i], bound)) {
            return 1;
        }
    }
    return 0;
}

/**
 * Matrix-vector multiply: w = A * v (in NTT domain)
 * A is k x l, v is length l, w is length k
 */
static void dil_polyvec_matrix_pointwise(dil_polyveck *w,
                                          const dil_poly mat[DIL_K][DIL_L],
                                          const dil_polyvecl *v) {
    unsigned int i, j;
    dil_poly t;

    for (i = 0; i < DIL_K; ++i) {
        dil_poly_pointwise_montgomery(&w->vec[i], &mat[i][0], &v->vec[0]);
        for (j = 1; j < DIL_L; ++j) {
            dil_poly_pointwise_montgomery(&t, &mat[i][j], &v->vec[j]);
            dil_poly_add(&w->vec[i], &w->vec[i], &t);
        }
    }
}

/**
 * Power2Round on vector
 */
static void dil_polyveck_power2round(dil_polyveck *v1, dil_polyveck *v0,
                                      const dil_polyveck *v) {
    unsigned int i, j;
    for (i = 0; i < DIL_K; ++i) {
        for (j = 0; j < DIL_N; ++j) {
            v1->vec[i].coeffs[j] = dil_power2round(
                &v0->vec[i].coeffs[j], v->vec[i].coeffs[j]);
        }
    }
}

/**
 * Decompose on vector
 */
static void dil_polyveck_decompose(dil_polyveck *v1, dil_polyveck *v0,
                                    const dil_polyveck *v) {
    unsigned int i, j;
    for (i = 0; i < DIL_K; ++i) {
        for (j = 0; j < DIL_N; ++j) {
            v1->vec[i].coeffs[j] = dil_decompose(
                &v0->vec[i].coeffs[j], v->vec[i].coeffs[j]);
        }
    }
}

/**
 * MakeHint on vectors
 */
static unsigned int dil_polyveck_make_hint(uint8_t hint[DIL_OMEGA + DIL_K],
                                            const dil_polyveck *v0,
                                            const dil_polyveck *v1) {
    unsigned int i, j, s = 0;

    for (i = 0; i < DIL_K; ++i) {
        for (j = 0; j < DIL_N; ++j) {
            if (dil_make_hint(v0->vec[i].coeffs[j], v1->vec[i].coeffs[j])) {
                if (s >= DIL_OMEGA) {
                    return DIL_OMEGA + 1;  /* Too many hints */
                }
                hint[s++] = (uint8_t)j;
            }
        }
        hint[DIL_OMEGA + i] = (uint8_t)s;
    }
    return s;
}

/**
 * UseHint on vector
 */
static void dil_polyveck_use_hint(dil_polyveck *w, const dil_polyveck *v,
                                   const uint8_t hint[DIL_OMEGA + DIL_K]) {
    unsigned int i, j, k_idx;

    /* Unpack hint bits into per-coefficient flags */
    uint8_t hint_flags[DIL_K][DIL_N];
    memset(hint_flags, 0, sizeof(hint_flags));
    k_idx = 0;
    for (i = 0; i < DIL_K; ++i) {
        unsigned int limit = hint[DIL_OMEGA + i];
        for (; k_idx < limit; ++k_idx) {
            /* hint[k_idx] is uint8_t (0-255), always valid index for DIL_N=256 */
            hint_flags[i][hint[k_idx]] = 1;
        }
    }

    /* Single pass: apply use_hint with correct flag for each coefficient */
    for (i = 0; i < DIL_K; ++i) {
        for (j = 0; j < DIL_N; ++j) {
            w->vec[i].coeffs[j] = dil_use_hint(v->vec[i].coeffs[j], hint_flags[i][j]);
        }
    }
}

/* ============================================================================
 * KEY GENERATION, SIGNING, AND VERIFICATION
 * ============================================================================ */

/**
 * Expand matrix A from seed (produces k x l matrix of polynomials in NTT domain)
 */
static void dil_expand_matrix(dil_poly mat[DIL_K][DIL_L],
                               const uint8_t rho[DIL_SEEDBYTES]) {
    unsigned int i, j;
    for (i = 0; i < DIL_K; ++i) {
        for (j = 0; j < DIL_L; ++j) {
            dil_poly_uniform(&mat[i][j], rho, (uint16_t)((i << 8) + j));
        }
    }
}

#ifdef AMA_TESTING_MODE
/**
 * Random bytes hook for KAT testing.
 * When non-NULL, replaces /dev/urandom for deterministic output.
 * Only available in test builds (AMA_TESTING_MODE).
 */
ama_error_t (*ama_dilithium_randombytes_hook)(uint8_t* buf, size_t len) = NULL;
#endif

/* Get random bytes from OS (or from test hook if set) */
static ama_error_t dil_randombytes(uint8_t *buf, size_t len) {
#ifdef AMA_TESTING_MODE
    if (ama_dilithium_randombytes_hook) {
        return ama_dilithium_randombytes_hook(buf, len);
    }
#endif
    return ama_randombytes(buf, len);
}

/**
 * ML-DSA-65 Key Pair Generation (NIST FIPS 204, Algorithm 1)
 *
 * Generates a keypair for ML-DSA-65 (Dilithium Level 3).
 *
 * @param public_key Output buffer for public key (1952 bytes)
 * @param secret_key Output buffer for secret key (4032 bytes)
 * @return AMA_SUCCESS or error code
 */
AMA_API ama_error_t ama_dilithium_keypair(uint8_t *public_key, uint8_t *secret_key) {
    uint8_t seedbuf[2 * DIL_SEEDBYTES + DIL_CRHBYTES];
    uint8_t *rho, *rhoprime, *key;
    dil_poly mat[DIL_K][DIL_L];
    dil_polyvecl s1, s1hat;
    dil_polyveck s2, t1, t0, t;
    uint8_t tr[DIL_TRBYTES];
    unsigned int i;
    ama_error_t rc;

    if (!public_key || !secret_key) {
        return AMA_ERROR_INVALID_PARAM;
    }

    /* Generate random seed xi */
    rc = dil_randombytes(seedbuf, DIL_SEEDBYTES);
    if (rc != AMA_SUCCESS) {
        return rc;
    }

    /* (rho, rho', K) = H(xi || k || l) per FIPS 204 Algorithm 1
     * H = SHAKE256, k = DIL_K = 6, l = DIL_L = 5 for ML-DSA-65 */
    {
        uint8_t h_input[DIL_SEEDBYTES + 2];
        memcpy(h_input, seedbuf, DIL_SEEDBYTES);
        h_input[DIL_SEEDBYTES] = (uint8_t)DIL_K;
        h_input[DIL_SEEDBYTES + 1] = (uint8_t)DIL_L;
        ama_shake256(h_input, DIL_SEEDBYTES + 2, seedbuf, sizeof(seedbuf));
        ama_secure_memzero(h_input, sizeof(h_input));
    }
    rho = seedbuf;
    rhoprime = rho + DIL_SEEDBYTES;
    key = rhoprime + DIL_CRHBYTES;

    /* Expand matrix A from rho */
    dil_expand_matrix(mat, rho);

    /* Sample secret vectors s1 and s2 */
    for (i = 0; i < DIL_L; ++i) {
        dil_poly_uniform_eta(&s1.vec[i], rhoprime, (uint16_t)i);
    }
    for (i = 0; i < DIL_K; ++i) {
        dil_poly_uniform_eta(&s2.vec[i], rhoprime, (uint16_t)(DIL_L + i));
    }

    /* Compute t = A*s1 + s2 */
    s1hat = s1;
    dil_polyvecl_ntt(&s1hat);
    dil_polyvec_matrix_pointwise(&t, mat, &s1hat);
    dil_polyveck_invntt(&t);
    dil_polyveck_add(&t, &t, &s2);
    dil_polyveck_reduce(&t);
    dil_polyveck_caddq(&t);

    /* Power2Round: t = t1*2^d + t0 */
    dil_polyveck_power2round(&t1, &t0, &t);

    /* Pack public key: rho || t1 */
    memcpy(public_key, rho, DIL_SEEDBYTES);
    for (i = 0; i < DIL_K; ++i) {
        dil_polyt1_pack(public_key + DIL_SEEDBYTES + i * DIL_POLYT1_PACKEDBYTES,
                        &t1.vec[i]);
    }

    /* Compute tr = H(pk) */
    ama_shake256(public_key, AMA_ML_DSA_65_PUBLIC_KEY_BYTES, tr, DIL_TRBYTES);

    /* Pack secret key: rho || key || tr || s1 || s2 || t0 */
    memcpy(secret_key, rho, DIL_SEEDBYTES);
    memcpy(secret_key + DIL_SEEDBYTES, key, DIL_SEEDBYTES);
    memcpy(secret_key + 2 * DIL_SEEDBYTES, tr, DIL_TRBYTES);

    for (i = 0; i < DIL_L; ++i) {
        dil_polyeta_pack(secret_key + 2 * DIL_SEEDBYTES + DIL_TRBYTES +
                         i * DIL_POLYETA_PACKEDBYTES, &s1.vec[i]);
    }
    for (i = 0; i < DIL_K; ++i) {
        dil_polyeta_pack(secret_key + 2 * DIL_SEEDBYTES + DIL_TRBYTES +
                         DIL_L * DIL_POLYETA_PACKEDBYTES +
                         i * DIL_POLYETA_PACKEDBYTES, &s2.vec[i]);
    }
    for (i = 0; i < DIL_K; ++i) {
        dil_polyt0_pack(secret_key + 2 * DIL_SEEDBYTES + DIL_TRBYTES +
                        (DIL_L + DIL_K) * DIL_POLYETA_PACKEDBYTES +
                        i * DIL_POLYT0_PACKEDBYTES, &t0.vec[i]);
    }

    /* Scrub sensitive data */
    ama_secure_memzero(seedbuf, sizeof(seedbuf));
    ama_secure_memzero(&s1, sizeof(s1));
    ama_secure_memzero(&s1hat, sizeof(s1hat));
    ama_secure_memzero(&s2, sizeof(s2));

    return AMA_SUCCESS;
}

/**
 * Deterministic ML-DSA-65 keypair from seed (for KAT testing).
 *
 * Generates a keypair deterministically from a provided 32-byte seed,
 * bypassing the random number generator entirely.
 *
 * @param xi         Seed value (32 bytes, replaces random generation)
 * @param public_key Output buffer for public key (1952 bytes)
 * @param secret_key Output buffer for secret key (4032 bytes)
 * @return AMA_SUCCESS or error code
 */
AMA_API ama_error_t ama_dilithium_keypair_from_seed(
    const uint8_t xi[32],
    uint8_t *public_key, uint8_t *secret_key)
{
    uint8_t seedbuf[2 * DIL_SEEDBYTES + DIL_CRHBYTES];
    uint8_t *rho, *rhoprime, *key;
    dil_poly mat[DIL_K][DIL_L];
    dil_polyvecl s1, s1hat;
    dil_polyveck s2, t1, t0, t;
    uint8_t tr[DIL_TRBYTES];
    unsigned int i;

    if (!xi || !public_key || !secret_key) {
        return AMA_ERROR_INVALID_PARAM;
    }

    /* (rho, rho', K) = H(xi || k || l) per FIPS 204 Algorithm 1 */
    {
        uint8_t h_input[DIL_SEEDBYTES + 2];
        memcpy(h_input, xi, DIL_SEEDBYTES);
        h_input[DIL_SEEDBYTES] = (uint8_t)DIL_K;
        h_input[DIL_SEEDBYTES + 1] = (uint8_t)DIL_L;
        ama_shake256(h_input, DIL_SEEDBYTES + 2, seedbuf, sizeof(seedbuf));
        ama_secure_memzero(h_input, sizeof(h_input));
    }
    rho = seedbuf;
    rhoprime = rho + DIL_SEEDBYTES;
    key = rhoprime + DIL_CRHBYTES;

    /* Expand matrix A from rho */
    dil_expand_matrix(mat, rho);

    /* Sample secret vectors s1 and s2 */
    for (i = 0; i < DIL_L; ++i) {
        dil_poly_uniform_eta(&s1.vec[i], rhoprime, (uint16_t)i);
    }
    for (i = 0; i < DIL_K; ++i) {
        dil_poly_uniform_eta(&s2.vec[i], rhoprime, (uint16_t)(DIL_L + i));
    }

    /* Compute t = A*s1 + s2 */
    s1hat = s1;
    dil_polyvecl_ntt(&s1hat);
    dil_polyvec_matrix_pointwise(&t, mat, &s1hat);
    dil_polyveck_invntt(&t);
    dil_polyveck_add(&t, &t, &s2);
    dil_polyveck_reduce(&t);
    dil_polyveck_caddq(&t);

    /* Power2Round: t = t1*2^d + t0 */
    dil_polyveck_power2round(&t1, &t0, &t);

    /* Pack public key: rho || t1 */
    memcpy(public_key, rho, DIL_SEEDBYTES);
    for (i = 0; i < DIL_K; ++i) {
        dil_polyt1_pack(public_key + DIL_SEEDBYTES + i * DIL_POLYT1_PACKEDBYTES,
                        &t1.vec[i]);
    }

    /* Compute tr = H(pk) */
    ama_shake256(public_key, AMA_ML_DSA_65_PUBLIC_KEY_BYTES, tr, DIL_TRBYTES);

    /* Pack secret key: rho || key || tr || s1 || s2 || t0 */
    memcpy(secret_key, rho, DIL_SEEDBYTES);
    memcpy(secret_key + DIL_SEEDBYTES, key, DIL_SEEDBYTES);
    memcpy(secret_key + 2 * DIL_SEEDBYTES, tr, DIL_TRBYTES);

    for (i = 0; i < DIL_L; ++i) {
        dil_polyeta_pack(secret_key + 2 * DIL_SEEDBYTES + DIL_TRBYTES +
                         i * DIL_POLYETA_PACKEDBYTES, &s1.vec[i]);
    }
    for (i = 0; i < DIL_K; ++i) {
        dil_polyeta_pack(secret_key + 2 * DIL_SEEDBYTES + DIL_TRBYTES +
                         DIL_L * DIL_POLYETA_PACKEDBYTES +
                         i * DIL_POLYETA_PACKEDBYTES, &s2.vec[i]);
    }
    for (i = 0; i < DIL_K; ++i) {
        dil_polyt0_pack(secret_key + 2 * DIL_SEEDBYTES + DIL_TRBYTES +
                        (DIL_L + DIL_K) * DIL_POLYETA_PACKEDBYTES +
                        i * DIL_POLYT0_PACKEDBYTES, &t0.vec[i]);
    }

    /* Scrub sensitive data */
    ama_secure_memzero(seedbuf, sizeof(seedbuf));
    ama_secure_memzero(&s1, sizeof(s1));
    ama_secure_memzero(&s1hat, sizeof(s1hat));
    ama_secure_memzero(&s2, sizeof(s2));

    return AMA_SUCCESS;
}

/**
 * ML-DSA-65 Signing (NIST FIPS 204, Algorithm 2)
 *
 * Signs a message using ML-DSA-65 with rejection sampling.
 *
 * @param signature Output buffer for signature (3309 bytes max)
 * @param signature_len Pointer to signature length (in/out)
 * @param message Message to sign
 * @param message_len Length of message
 * @param secret_key Secret key (4032 bytes)
 * @return AMA_SUCCESS or error code
 */
AMA_API ama_error_t ama_dilithium_sign(uint8_t *signature, size_t *signature_len,
                                const uint8_t *message, size_t message_len,
                                const uint8_t *secret_key) {
    uint8_t *rho, *key, *tr;
    uint8_t mu[DIL_CRHBYTES];
    uint8_t rhoprime[DIL_CRHBYTES];
    uint8_t hashbuf[DIL_SEEDBYTES + DIL_CRHBYTES];
    dil_poly mat[DIL_K][DIL_L];
    dil_polyvecl s1, y, z;
    dil_polyveck s2, t0, w1, w0, ct0, cs2;
    dil_poly cp;
    uint8_t hint[DIL_OMEGA + DIL_K];
    unsigned int n, i;
    uint16_t nonce = 0;
    int reject;

    memset(hint, 0, sizeof(hint));

    if (!signature || !signature_len || !message || !secret_key) {
        return AMA_ERROR_INVALID_PARAM;
    }

    if (*signature_len < AMA_ML_DSA_65_SIGNATURE_BYTES) {
        *signature_len = AMA_ML_DSA_65_SIGNATURE_BYTES;
        return AMA_ERROR_INVALID_PARAM;
    }

    /* Unpack secret key */
    rho = (uint8_t *)secret_key;
    key = (uint8_t *)secret_key + DIL_SEEDBYTES;
    tr = (uint8_t *)secret_key + 2 * DIL_SEEDBYTES;

    for (i = 0; i < DIL_L; ++i) {
        dil_polyeta_unpack(&s1.vec[i],
            secret_key + 2 * DIL_SEEDBYTES + DIL_TRBYTES +
            i * DIL_POLYETA_PACKEDBYTES);
    }
    for (i = 0; i < DIL_K; ++i) {
        dil_polyeta_unpack(&s2.vec[i],
            secret_key + 2 * DIL_SEEDBYTES + DIL_TRBYTES +
            DIL_L * DIL_POLYETA_PACKEDBYTES +
            i * DIL_POLYETA_PACKEDBYTES);
    }
    for (i = 0; i < DIL_K; ++i) {
        dil_polyt0_unpack(&t0.vec[i],
            secret_key + 2 * DIL_SEEDBYTES + DIL_TRBYTES +
            (DIL_L + DIL_K) * DIL_POLYETA_PACKEDBYTES +
            i * DIL_POLYT0_PACKEDBYTES);
    }

    /* Expand A from rho */
    dil_expand_matrix(mat, rho);

    /* Transform s1 and s2 to NTT domain */
    dil_polyvecl s1hat = s1;
    dil_polyvecl_ntt(&s1hat);
    dil_polyveck s2hat = s2;
    dil_polyveck_ntt(&s2hat);
    dil_polyveck t0hat = t0;
    dil_polyveck_ntt(&t0hat);

    /* Compute mu = H(tr || M) */
    {
        /* Guard against integer overflow in allocation size */
        if (message_len > SIZE_MAX - DIL_TRBYTES) {
            return AMA_ERROR_INVALID_PARAM;
        }
        uint8_t *mu_input = (uint8_t *)malloc(DIL_TRBYTES + message_len);
        if (!mu_input) {
            return AMA_ERROR_MEMORY;
        }
        memcpy(mu_input, tr, DIL_TRBYTES);
        memcpy(mu_input + DIL_TRBYTES, message, message_len);
        ama_shake256(mu_input, DIL_TRBYTES + message_len, mu, DIL_CRHBYTES);
        ama_secure_memzero(mu_input, DIL_TRBYTES + message_len);
        free(mu_input);
    }

    /* Compute rhoprime = H(key || mu) for deterministic signing */
    memcpy(hashbuf, key, DIL_SEEDBYTES);
    memcpy(hashbuf + DIL_SEEDBYTES, mu, DIL_CRHBYTES);
    ama_shake256(hashbuf, DIL_SEEDBYTES + DIL_CRHBYTES, rhoprime, DIL_CRHBYTES);

    /* Rejection sampling loop
     * Expected iterations ~4-5 for ML-DSA-65. Cap at 1000 to prevent
     * pathological hangs (probability of reaching cap < 2^{-500}). */
    reject = 1;
    unsigned int attempts = 0;
    const unsigned int MAX_SIGN_ATTEMPTS = 1000;
    while (reject) {
        if (++attempts > MAX_SIGN_ATTEMPTS) {
            ama_secure_memzero(&s1, sizeof(s1));
            ama_secure_memzero(&s1hat, sizeof(s1hat));
            ama_secure_memzero(&s2hat, sizeof(s2hat));
            ama_secure_memzero(mu, sizeof(mu));
            ama_secure_memzero(rhoprime, sizeof(rhoprime));
            return AMA_ERROR_CRYPTO;
        }
        /* Sample y from [-gamma1+1, gamma1] */
        for (i = 0; i < DIL_L; ++i) {
            dil_poly_uniform_gamma1(&y.vec[i], rhoprime, (uint16_t)(DIL_L * nonce + i));
        }
        nonce++;

        /* Compute w = A*NTT(y) */
        dil_polyvecl yhat = y;
        dil_polyvecl_ntt(&yhat);
        dil_polyvec_matrix_pointwise(&w1, mat, &yhat);
        dil_polyveck_invntt(&w1);
        dil_polyveck_reduce(&w1);
        dil_polyveck_caddq(&w1);

        /* Decompose w into w1 and w0 */
        dil_polyveck_decompose(&w1, &w0, &w1);

        /* Pack w1 and compute challenge hash */
        {
            uint8_t w1_packed[DIL_K * DIL_POLYW1_PACKEDBYTES];
            uint8_t challenge_seed[DIL_CRHBYTES + DIL_K * DIL_POLYW1_PACKEDBYTES];

            for (i = 0; i < DIL_K; ++i) {
                dil_polyw1_pack(w1_packed + i * DIL_POLYW1_PACKEDBYTES, &w1.vec[i]);
            }

            memcpy(challenge_seed, mu, DIL_CRHBYTES);
            memcpy(challenge_seed + DIL_CRHBYTES, w1_packed,
                   DIL_K * DIL_POLYW1_PACKEDBYTES);
            ama_shake256(challenge_seed,
                        DIL_CRHBYTES + DIL_K * DIL_POLYW1_PACKEDBYTES,
                        signature, DIL_CTILDEBYTES);
        }

        /* Compute challenge polynomial c from c_tilde */
        dil_poly_challenge(&cp, signature);
        dil_poly_ntt(&cp);

        /* Compute z = y + c*s1 */
        for (i = 0; i < DIL_L; ++i) {
            dil_poly_pointwise_montgomery(&z.vec[i], &cp, &s1hat.vec[i]);
            dil_poly_invntt(&z.vec[i]);
            dil_poly_add(&z.vec[i], &z.vec[i], &y.vec[i]);
            dil_poly_reduce(&z.vec[i]);
        }

        /* Check ||z||_inf < gamma1 - beta */
        if (dil_polyvecl_chknorm(&z, DIL_GAMMA1 - DIL_BETA))
            continue;

        /* Compute w0 - c*s2 */
        for (i = 0; i < DIL_K; ++i) {
            dil_poly_pointwise_montgomery(&cs2.vec[i], &cp, &s2hat.vec[i]);
            dil_poly_invntt(&cs2.vec[i]);
        }
        dil_polyveck_sub(&w0, &w0, &cs2);
        dil_polyveck_reduce(&w0);

        /* Check ||w0 - cs2||_inf < gamma2 - beta */
        if (dil_polyveck_chknorm(&w0, DIL_GAMMA2 - DIL_BETA))
            continue;

        /* Compute c*t0 */
        for (i = 0; i < DIL_K; ++i) {
            dil_poly_pointwise_montgomery(&ct0.vec[i], &cp, &t0hat.vec[i]);
            dil_poly_invntt(&ct0.vec[i]);
            dil_poly_reduce(&ct0.vec[i]);
        }

        /* Check ||ct0||_inf < gamma2 */
        if (dil_polyveck_chknorm(&ct0, DIL_GAMMA2))
            continue;

        /* Compute hints: make_hint(w0-cs2+ct0, w1) per FIPS 204 */
        memset(hint, 0, sizeof(hint));
        dil_polyveck_add(&w0, &w0, &ct0);
        n = dil_polyveck_make_hint(hint, &w0, &w1);
        if (n > DIL_OMEGA)
            continue;

        /* All checks passed */
        reject = 0;
    }

    /* Pack signature: c_tilde (48 bytes) || z (L * polyz_packed) || hints */
    /* c_tilde already written at signature[0..47] */
    for (i = 0; i < DIL_L; ++i) {
        dil_polyz_pack(signature + DIL_CTILDEBYTES + i * DIL_POLYZ_PACKEDBYTES,
                       &z.vec[i]);
    }

    /* Pack hints */
    memcpy(signature + DIL_CTILDEBYTES + DIL_L * DIL_POLYZ_PACKEDBYTES,
           hint, DIL_OMEGA + DIL_K);

    *signature_len = AMA_ML_DSA_65_SIGNATURE_BYTES;

    /* Scrub sensitive data */
    ama_secure_memzero(&s1, sizeof(s1));
    ama_secure_memzero(&s1hat, sizeof(s1hat));
    ama_secure_memzero(&s2hat, sizeof(s2hat));
    ama_secure_memzero(mu, sizeof(mu));
    ama_secure_memzero(rhoprime, sizeof(rhoprime));

    return AMA_SUCCESS;
}

/**
 * ML-DSA-65 Verification (NIST FIPS 204, Algorithm 3)
 *
 * Verifies a signature on a message using the public key.
 *
 * @param message Message to verify
 * @param message_len Length of message
 * @param signature Signature to verify (3309 bytes)
 * @param signature_len Length of signature
 * @param public_key Public key (1952 bytes)
 * @return AMA_SUCCESS if valid, AMA_ERROR_VERIFY_FAILED if invalid
 */
AMA_API ama_error_t ama_dilithium_verify(const uint8_t *message, size_t message_len,
                                  const uint8_t *signature, size_t signature_len,
                                  const uint8_t *public_key) {
    uint8_t rho[DIL_SEEDBYTES];
    uint8_t mu[DIL_CRHBYTES];
    uint8_t c_tilde[DIL_CTILDEBYTES];
    uint8_t c_tilde2[DIL_CTILDEBYTES];
    dil_poly mat[DIL_K][DIL_L];
    dil_polyvecl z;
    dil_polyveck t1, w1prime, h_vec;
    dil_poly cp;
    uint8_t hint[DIL_OMEGA + DIL_K];
    uint8_t tr[DIL_TRBYTES];
    unsigned int i;

    if (!message || !signature || !public_key) {
        return AMA_ERROR_INVALID_PARAM;
    }

    if (signature_len != AMA_ML_DSA_65_SIGNATURE_BYTES) {
        return AMA_ERROR_VERIFY_FAILED;
    }

    /* Unpack public key: rho || t1 */
    memcpy(rho, public_key, DIL_SEEDBYTES);
    for (i = 0; i < DIL_K; ++i) {
        dil_polyt1_unpack(&t1.vec[i],
            public_key + DIL_SEEDBYTES + i * DIL_POLYT1_PACKEDBYTES);
    }

    /* Unpack signature: c_tilde || z || hints */
    memcpy(c_tilde, signature, DIL_CTILDEBYTES);
    for (i = 0; i < DIL_L; ++i) {
        dil_polyz_unpack(&z.vec[i],
            signature + DIL_CTILDEBYTES + i * DIL_POLYZ_PACKEDBYTES);
    }
    memcpy(hint, signature + DIL_CTILDEBYTES + DIL_L * DIL_POLYZ_PACKEDBYTES,
           DIL_OMEGA + DIL_K);

    /* Verify hint encoding */
    {
        unsigned int prev = 0;
        for (i = 0; i < DIL_K; ++i) {
            unsigned int limit = hint[DIL_OMEGA + i];
            if (limit < prev || limit > DIL_OMEGA) {
                return AMA_ERROR_VERIFY_FAILED;
            }
            prev = limit;
        }
        for (i = prev; i < DIL_OMEGA; ++i) {
            if (hint[i] != 0) {
                return AMA_ERROR_VERIFY_FAILED;
            }
        }
    }

    /* Check ||z||_inf < gamma1 - beta */
    if (dil_polyvecl_chknorm(&z, DIL_GAMMA1 - DIL_BETA)) {
        return AMA_ERROR_VERIFY_FAILED;
    }

    /* Expand A from rho */
    dil_expand_matrix(mat, rho);

    /* Compute tr = H(pk) */
    ama_shake256(public_key, AMA_ML_DSA_65_PUBLIC_KEY_BYTES, tr, DIL_TRBYTES);

    /* Compute mu = H(tr || M) */
    {
        /* Guard against integer overflow in allocation size */
        if (message_len > SIZE_MAX - DIL_TRBYTES) {
            return AMA_ERROR_VERIFY_FAILED;
        }
        uint8_t *mu_input = (uint8_t *)malloc(DIL_TRBYTES + message_len);
        if (!mu_input) {
            return AMA_ERROR_MEMORY;
        }
        memcpy(mu_input, tr, DIL_TRBYTES);
        memcpy(mu_input + DIL_TRBYTES, message, message_len);
        ama_shake256(mu_input, DIL_TRBYTES + message_len, mu, DIL_CRHBYTES);
        ama_secure_memzero(mu_input, DIL_TRBYTES + message_len);
        free(mu_input);
    }

    /* Compute challenge polynomial c from c_tilde */
    dil_poly_challenge(&cp, c_tilde);
    dil_poly_ntt(&cp);

    /* Compute w1' = A*NTT(z) - c*NTT(t1*2^d) in NTT domain */
    dil_polyvecl zhat = z;
    dil_polyvecl_ntt(&zhat);
    dil_polyvec_matrix_pointwise(&w1prime, mat, &zhat);

    /* Compute c * t1 * 2^d */
    for (i = 0; i < DIL_K; ++i) {
        unsigned int j;
        for (j = 0; j < DIL_N; ++j) {
            t1.vec[i].coeffs[j] <<= DIL_D;
        }
        dil_poly_ntt(&t1.vec[i]);
        dil_poly_pointwise_montgomery(&h_vec.vec[i], &cp, &t1.vec[i]);
    }

    /* w1' = Az - ct1*2^d */
    dil_polyveck_sub(&w1prime, &w1prime, &h_vec);
    dil_polyveck_reduce(&w1prime);
    dil_polyveck_invntt(&w1prime);
    dil_polyveck_reduce(&w1prime);
    dil_polyveck_caddq(&w1prime);

    /* Use hints to recover w1 */
    dil_polyveck_use_hint(&w1prime, &w1prime, hint);

    /* Recompute c_tilde' = H(mu || w1') */
    {
        uint8_t w1_packed[DIL_K * DIL_POLYW1_PACKEDBYTES];
        uint8_t *challenge_input;
        size_t challenge_len = DIL_CRHBYTES + DIL_K * DIL_POLYW1_PACKEDBYTES;

        for (i = 0; i < DIL_K; ++i) {
            dil_polyw1_pack(w1_packed + i * DIL_POLYW1_PACKEDBYTES,
                           &w1prime.vec[i]);
        }

        challenge_input = (uint8_t *)malloc(challenge_len);
        if (!challenge_input) {
            return AMA_ERROR_MEMORY;
        }
        memcpy(challenge_input, mu, DIL_CRHBYTES);
        memcpy(challenge_input + DIL_CRHBYTES, w1_packed,
               DIL_K * DIL_POLYW1_PACKEDBYTES);
        ama_shake256(challenge_input, challenge_len, c_tilde2, DIL_CTILDEBYTES);
        ama_secure_memzero(challenge_input, challenge_len);
        free(challenge_input);
    }

    /* Verify c_tilde == c_tilde2 (constant-time comparison) */
    {
        int match = ama_consttime_memcmp(c_tilde, c_tilde2, DIL_CTILDEBYTES);

        /* Scrub verification intermediates before returning */
        ama_secure_memzero(mu, sizeof(mu));
        ama_secure_memzero(c_tilde, sizeof(c_tilde));
        ama_secure_memzero(c_tilde2, sizeof(c_tilde2));

        if (match != 0) {
            return AMA_ERROR_VERIFY_FAILED;
        }
    }

    return AMA_SUCCESS;
}

/**
 * ML-DSA-65 Verification with context (FIPS 204, Algorithm 5 — external/pure)
 *
 * Applies the domain-separation wrapper M' = 0x00 || len(ctx) || ctx || M
 * defined in FIPS 204 Section 5.4, then delegates to ama_dilithium_verify().
 *
 * @param message       Raw message to verify
 * @param message_len   Length of message
 * @param ctx           Context string (0–255 bytes, per FIPS 204 §5.3)
 * @param ctx_len       Length of context (must be <= 255)
 * @param signature     Signature to verify (3309 bytes)
 * @param signature_len Length of signature
 * @param public_key    Public key (1952 bytes)
 * @return AMA_SUCCESS if valid, AMA_ERROR_VERIFY_FAILED if invalid
 */
AMA_API ama_error_t ama_dilithium_verify_ctx(
    const uint8_t *message, size_t message_len,
    const uint8_t *ctx, size_t ctx_len,
    const uint8_t *signature, size_t signature_len,
    const uint8_t *public_key) {

    uint8_t *wrapped;
    size_t wrapped_len;
    ama_error_t result;

    if (message == NULL || signature == NULL || public_key == NULL) {
        return AMA_ERROR_INVALID_PARAM;
    }
    if (ctx_len > 0 && ctx == NULL) {
        return AMA_ERROR_INVALID_PARAM;
    }

    /* FIPS 204 Section 5.3: context must be at most 255 bytes */
    if (ctx_len > 255) {
        return AMA_ERROR_INVALID_PARAM;
    }

    /* Overflow guard: wrapped_len = 2 + ctx_len + message_len */
    if (message_len > SIZE_MAX - 2 - ctx_len) {
        return AMA_ERROR_INVALID_PARAM;
    }
    wrapped_len = 2 + ctx_len + message_len;

    wrapped = (uint8_t *)calloc((size_t)1, wrapped_len);
    if (!wrapped) {
        return AMA_ERROR_MEMORY;
    }

    /* M' = 0x00 || IntegerToBytes(|ctx|, 1) || ctx || M */
    wrapped[0] = 0x00;
    wrapped[1] = (uint8_t)ctx_len;
    if (ctx_len > 0 && ctx != NULL) {
        memcpy(wrapped + 2, ctx, ctx_len);
    }
    memcpy(wrapped + 2 + ctx_len, message, message_len);

    result = ama_dilithium_verify(wrapped, wrapped_len, signature,
                                  signature_len, public_key);

    ama_secure_memzero(wrapped, wrapped_len);
    free(wrapped);
    return result;
}

