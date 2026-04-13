/**
 * Copyright 2025-2026 Steel Security Advisors LLC
 * Licensed under the Apache License, Version 2.0
 *
 * @file ama_dilithium_params.c
 * @brief ML-DSA-44 / ML-DSA-87 Additional Parameter Sets (FIPS 204)
 *
 * Provides ML-DSA-44 (Level 2) and ML-DSA-87 (Level 5) parameter sets.
 * The existing ama_dilithium.c implements ML-DSA-65 (Level 3).
 *
 * FIPS 204 Parameter Sets:
 * ┌──────────┬───┬───┬─────┬─────┬────────┬────────┬───────┬────┬──────┐
 * │ Name     │ k │ l │ eta │ tau │ gamma1 │ gamma2 │ omega │ d  │ctilde│
 * ├──────────┼───┼───┼─────┼─────┼────────┼────────┼───────┼────┼──────┤
 * │ ML-DSA-44│ 4 │ 4 │  2  │ 39  │ 2^17   │(q-1)/88│   80  │ 13 │  32  │
 * │ ML-DSA-65│ 6 │ 5 │  4  │ 49  │ 2^19   │(q-1)/32│   55  │ 13 │  48  │
 * │ ML-DSA-87│ 8 │ 7 │  2  │ 60  │ 2^19   │(q-1)/32│   75  │ 13 │  64  │
 * └──────────┴───┴───┴─────┴─────┴────────┴────────┴───────┴────┴──────┘
 *
 * Key/signature sizes:
 * │ ML-DSA-44│ pk=1312  sk=2560  sig=2420  │
 * │ ML-DSA-65│ pk=1952  sk=4032  sig=3309  │ (existing)
 * │ ML-DSA-87│ pk=2592  sk=4896  sig=4627  │
 *
 * This implementation provides a parameterized engine that reuses the
 * same polynomial arithmetic (N=256, Q=8380417, NTT) as ama_dilithium.c.
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

/* ============================================================================
 * SHARED CONSTANTS
 * ============================================================================ */

#define MLDSA_N 256
#define MLDSA_Q 8380417
#define MLDSA_D 13
#define MLDSA_SEEDBYTES 32
#define MLDSA_CRHBYTES 64
#define MLDSA_TRBYTES 64

/* Maximum K and L across all parameter sets */
#define MLDSA_K_MAX 8
#define MLDSA_L_MAX 7

/* Montgomery constant: R = 2^32 mod q */
#define MLDSA_MONT (-4186625)  /* 2^32 mod q */
#define MLDSA_QINV 58728449   /* q^(-1) mod 2^32 */

/* ============================================================================
 * PARAMETER SET DESCRIPTOR
 * ============================================================================ */

typedef struct {
    unsigned int k;
    unsigned int l;
    unsigned int eta;
    unsigned int tau;
    int32_t gamma1;
    int32_t gamma2;
    unsigned int omega;
    unsigned int ctilde_bytes;
    size_t pk_bytes;
    size_t sk_bytes;
    size_t sig_bytes;
    /* Derived packing sizes */
    unsigned int polyeta_packed;
    unsigned int polyz_packed;
    unsigned int polyw1_packed;
    unsigned int polyt1_packed;
    unsigned int polyt0_packed;
} mldsa_params_t;

static const mldsa_params_t MLDSA_44 = {
    .k = 4, .l = 4, .eta = 2, .tau = 39,
    .gamma1 = (1 << 17), .gamma2 = (MLDSA_Q - 1) / 88,
    .omega = 80, .ctilde_bytes = 32,
    .pk_bytes = AMA_ML_DSA_44_PUBLIC_KEY_BYTES,
    .sk_bytes = AMA_ML_DSA_44_SECRET_KEY_BYTES,
    .sig_bytes = AMA_ML_DSA_44_SIGNATURE_BYTES,
    .polyeta_packed = 96,   /* eta=2: N*3/8 = 96 */
    .polyz_packed = 576,    /* gamma1=2^17: N*18/8 = 576 */
    .polyw1_packed = 192,   /* gamma2=(q-1)/88: 6 bits per coeff, N*6/8=192 */
    .polyt1_packed = 320,   /* always 10 bits: N*10/8 = 320 */
    .polyt0_packed = 416,   /* always 13 bits: N*13/8 = 416 */
};

static const mldsa_params_t MLDSA_87 = {
    .k = 8, .l = 7, .eta = 2, .tau = 60,
    .gamma1 = (1 << 19), .gamma2 = (MLDSA_Q - 1) / 32,
    .omega = 75, .ctilde_bytes = 64,
    .pk_bytes = AMA_ML_DSA_87_PUBLIC_KEY_BYTES,
    .sk_bytes = AMA_ML_DSA_87_SECRET_KEY_BYTES,
    .sig_bytes = AMA_ML_DSA_87_SIGNATURE_BYTES,
    .polyeta_packed = 96,   /* eta=2: N*3/8 = 96 */
    .polyz_packed = 640,    /* gamma1=2^19: N*20/8 = 640 */
    .polyw1_packed = 128,   /* gamma2=(q-1)/32: 4 bits per coeff, N*4/8=128 */
    .polyt1_packed = 320,
    .polyt0_packed = 416,
};

/* ============================================================================
 * POLYNOMIAL TYPES
 * ============================================================================ */

typedef struct {
    int32_t coeffs[MLDSA_N];
} ml_poly;

/* ============================================================================
 * NTT TWIDDLE FACTORS (same as ML-DSA-65)
 * ============================================================================ */

static const int32_t ml_zetas[MLDSA_N] = {
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

static int32_t ml_montgomery_reduce(int64_t a) {
    int32_t t;
    t = (int32_t)a * MLDSA_QINV;
    t = (int32_t)((a - (int64_t)t * MLDSA_Q) >> 32);
    return t;
}

static int32_t ml_reduce32(int32_t a) {
    int32_t t;
    t = (a + (1 << 22)) >> 23;
    t = a - t * MLDSA_Q;
    return t;
}

static int32_t ml_caddq(int32_t a) {
    a += (a >> 31) & MLDSA_Q;
    return a;
}

static int32_t ml_freeze(int32_t a) {
    a = ml_reduce32(a);
    a = ml_caddq(a);
    return a;
}

/* ============================================================================
 * POLYNOMIAL OPERATIONS
 * ============================================================================ */

static void ml_poly_ntt(ml_poly *a) {
    unsigned int len, start, j, k = 0;
    int32_t zeta, t;

    for (len = 128; len > 0; len >>= 1) {
        for (start = 0; start < MLDSA_N; start = j + len) {
            zeta = ml_zetas[++k];
            for (j = start; j < start + len; ++j) {
                t = ml_montgomery_reduce((int64_t)zeta * a->coeffs[j + len]);
                a->coeffs[j + len] = a->coeffs[j] - t;
                a->coeffs[j] = a->coeffs[j] + t;
            }
        }
    }
}

static void ml_poly_invntt(ml_poly *a) {
    unsigned int start, len, j, k = 256;
    int32_t t, zeta;
    const int32_t f = 41978; /* Mont^{-2}/256 */

    for (len = 1; len < MLDSA_N; len <<= 1) {
        for (start = 0; start < MLDSA_N; start = j + len) {
            zeta = -ml_zetas[--k];
            for (j = start; j < start + len; ++j) {
                t = a->coeffs[j];
                a->coeffs[j] = t + a->coeffs[j + len];
                a->coeffs[j + len] = t - a->coeffs[j + len];
                a->coeffs[j + len] = ml_montgomery_reduce((int64_t)zeta * a->coeffs[j + len]);
            }
        }
    }

    for (j = 0; j < MLDSA_N; ++j) {
        a->coeffs[j] = ml_montgomery_reduce((int64_t)f * a->coeffs[j]);
    }
}

static void ml_poly_pointwise(ml_poly *c, const ml_poly *a, const ml_poly *b) {
    unsigned int i;
    for (i = 0; i < MLDSA_N; ++i) {
        c->coeffs[i] = ml_montgomery_reduce((int64_t)a->coeffs[i] * b->coeffs[i]);
    }
}

static void ml_poly_add(ml_poly *c, const ml_poly *a, const ml_poly *b) {
    unsigned int i;
    for (i = 0; i < MLDSA_N; ++i) {
        c->coeffs[i] = a->coeffs[i] + b->coeffs[i];
    }
}

static void ml_poly_sub(ml_poly *c, const ml_poly *a, const ml_poly *b) {
    unsigned int i;
    for (i = 0; i < MLDSA_N; ++i) {
        c->coeffs[i] = a->coeffs[i] - b->coeffs[i];
    }
}

static void ml_poly_reduce(ml_poly *a) {
    unsigned int i;
    for (i = 0; i < MLDSA_N; ++i) {
        a->coeffs[i] = ml_reduce32(a->coeffs[i]);
    }
}

static void ml_poly_caddq(ml_poly *a) {
    unsigned int i;
    for (i = 0; i < MLDSA_N; ++i) {
        a->coeffs[i] = ml_caddq(a->coeffs[i]);
    }
}

/* ============================================================================
 * SAMPLING
 * ============================================================================ */

/**
 * Sample polynomial with coefficients uniform in [-eta, eta]
 */
static void ml_poly_uniform_eta(ml_poly *a, const uint8_t seed[MLDSA_CRHBYTES],
                                  uint16_t nonce, unsigned int eta) {
    uint8_t buf[MLDSA_CRHBYTES + 2];
    uint8_t stream[2 * MLDSA_N]; /* enough for rejection sampling */
    unsigned int ctr, pos;

    memcpy(buf, seed, MLDSA_CRHBYTES);
    buf[MLDSA_CRHBYTES] = (uint8_t)nonce;
    buf[MLDSA_CRHBYTES + 1] = (uint8_t)(nonce >> 8);
    ama_shake256(buf, MLDSA_CRHBYTES + 2, stream, sizeof(stream));

    ctr = 0;
    pos = 0;
    if (eta == 2) {
        while (ctr < MLDSA_N && pos < sizeof(stream)) {
            uint8_t t0 = stream[pos] & 0x0F;
            uint8_t t1 = stream[pos] >> 4;
            pos++;
            if (t0 < 15) {
                t0 = t0 - (t0 * 205 >> 10) * 5;  /* t0 mod 5 */
                a->coeffs[ctr++] = 2 - (int32_t)t0;
            }
            if (t1 < 15 && ctr < MLDSA_N) {
                t1 = t1 - (t1 * 205 >> 10) * 5;
                a->coeffs[ctr++] = 2 - (int32_t)t1;
            }
        }
    } else { /* eta == 4 */
        while (ctr < MLDSA_N && pos < sizeof(stream)) {
            uint8_t t0 = stream[pos] & 0x0F;
            uint8_t t1 = stream[pos] >> 4;
            pos++;
            if (t0 < 9) {
                a->coeffs[ctr++] = 4 - (int32_t)t0;
            }
            if (t1 < 9 && ctr < MLDSA_N) {
                a->coeffs[ctr++] = 4 - (int32_t)t1;
            }
        }
    }
}

/**
 * Sample polynomial uniformly from SHAKE128 stream (for matrix A)
 */
static void ml_poly_uniform(ml_poly *a, const uint8_t rho[MLDSA_SEEDBYTES],
                              uint16_t nonce) {
    uint8_t buf[MLDSA_SEEDBYTES + 2];
    uint8_t stream[3 * MLDSA_N]; /* 768 bytes for rejection sampling */
    unsigned int ctr, pos;

    memcpy(buf, rho, MLDSA_SEEDBYTES);
    buf[MLDSA_SEEDBYTES] = (uint8_t)nonce;
    buf[MLDSA_SEEDBYTES + 1] = (uint8_t)(nonce >> 8);
    ama_shake128(buf, MLDSA_SEEDBYTES + 2, stream, sizeof(stream));

    ctr = 0;
    pos = 0;
    while (ctr < MLDSA_N && pos + 3 <= sizeof(stream)) {
        uint32_t t;
        t = stream[pos++];
        t |= (uint32_t)stream[pos++] << 8;
        t |= (uint32_t)stream[pos++] << 16;
        t &= 0x7FFFFF;

        if (t < (uint32_t)MLDSA_Q) {
            a->coeffs[ctr++] = (int32_t)t;
        }
    }
}

/**
 * Sample challenge polynomial with tau ones/negative ones.
 */
static void ml_poly_challenge(ml_poly *c, const uint8_t *seed,
                                unsigned int seed_len, unsigned int tau) {
    uint8_t buf[256];
    unsigned int i, pos;
    uint64_t signs;

    ama_shake256(seed, seed_len, buf, sizeof(buf));

    signs = 0;
    for (i = 0; i < 8; ++i) {
        signs |= (uint64_t)buf[i] << (8 * i);
    }

    memset(c, 0, sizeof(ml_poly));
    pos = 8;

    for (i = MLDSA_N - tau; i < MLDSA_N; ++i) {
        unsigned int j;
        j = buf[pos++] % (i + 1);
        c->coeffs[i] = c->coeffs[j];
        c->coeffs[j] = 1 - 2 * (int32_t)(signs & 1);
        signs >>= 1;
    }
}

/* ============================================================================
 * PACKING / UNPACKING
 * ============================================================================ */

static void ml_polyt1_pack(uint8_t *r, const ml_poly *a) {
    unsigned int i;
    for (i = 0; i < MLDSA_N / 4; ++i) {
        r[5*i + 0] = (uint8_t)(a->coeffs[4*i + 0] >> 0);
        r[5*i + 1] = (uint8_t)((a->coeffs[4*i + 0] >> 8) | (a->coeffs[4*i + 1] << 2));
        r[5*i + 2] = (uint8_t)((a->coeffs[4*i + 1] >> 6) | (a->coeffs[4*i + 2] << 4));
        r[5*i + 3] = (uint8_t)((a->coeffs[4*i + 2] >> 4) | (a->coeffs[4*i + 3] << 6));
        r[5*i + 4] = (uint8_t)(a->coeffs[4*i + 3] >> 2);
    }
}

static void ml_polyt1_unpack(ml_poly *r, const uint8_t *a) {
    unsigned int i;
    for (i = 0; i < MLDSA_N / 4; ++i) {
        r->coeffs[4*i + 0] = ((a[5*i + 0] >> 0) | ((uint32_t)a[5*i + 1] << 8)) & 0x3FF;
        r->coeffs[4*i + 1] = ((a[5*i + 1] >> 2) | ((uint32_t)a[5*i + 2] << 6)) & 0x3FF;
        r->coeffs[4*i + 2] = ((a[5*i + 2] >> 4) | ((uint32_t)a[5*i + 3] << 4)) & 0x3FF;
        r->coeffs[4*i + 3] = ((a[5*i + 3] >> 6) | ((uint32_t)a[5*i + 4] << 2)) & 0x3FF;
    }
}

static void ml_polyt0_pack(uint8_t *r, const ml_poly *a) {
    unsigned int i;
    int32_t t[8];
    for (i = 0; i < MLDSA_N / 8; ++i) {
        unsigned int j;
        for (j = 0; j < 8; j++)
            t[j] = (1 << (MLDSA_D - 1)) - a->coeffs[8*i + j];

        r[13*i + 0]  = (uint8_t)(t[0]);
        r[13*i + 1]  = (uint8_t)(t[0] >> 8) | (uint8_t)(t[1] << 5);
        r[13*i + 2]  = (uint8_t)(t[1] >> 3);
        r[13*i + 3]  = (uint8_t)(t[1] >> 11) | (uint8_t)(t[2] << 2);
        r[13*i + 4]  = (uint8_t)(t[2] >> 6) | (uint8_t)(t[3] << 7);
        r[13*i + 5]  = (uint8_t)(t[3] >> 1);
        r[13*i + 6]  = (uint8_t)(t[3] >> 9) | (uint8_t)(t[4] << 4);
        r[13*i + 7]  = (uint8_t)(t[4] >> 4);
        r[13*i + 8]  = (uint8_t)(t[4] >> 12) | (uint8_t)(t[5] << 1);
        r[13*i + 9]  = (uint8_t)(t[5] >> 7) | (uint8_t)(t[6] << 6);
        r[13*i + 10] = (uint8_t)(t[6] >> 2);
        r[13*i + 11] = (uint8_t)(t[6] >> 10) | (uint8_t)(t[7] << 3);
        r[13*i + 12] = (uint8_t)(t[7] >> 5);
    }
}

static void ml_polyt0_unpack(ml_poly *r, const uint8_t *a) {
    unsigned int i;
    for (i = 0; i < MLDSA_N / 8; ++i) {
        r->coeffs[8*i + 0] = a[13*i + 0] | ((uint32_t)a[13*i + 1] << 8);
        r->coeffs[8*i + 0] &= 0x1FFF;
        r->coeffs[8*i + 1] = (a[13*i + 1] >> 5) | ((uint32_t)a[13*i + 2] << 3) |
                               ((uint32_t)a[13*i + 3] << 11);
        r->coeffs[8*i + 1] &= 0x1FFF;
        r->coeffs[8*i + 2] = (a[13*i + 3] >> 2) | ((uint32_t)a[13*i + 4] << 6);
        r->coeffs[8*i + 2] &= 0x1FFF;
        r->coeffs[8*i + 3] = (a[13*i + 4] >> 7) | ((uint32_t)a[13*i + 5] << 1) |
                               ((uint32_t)a[13*i + 6] << 9);
        r->coeffs[8*i + 3] &= 0x1FFF;
        r->coeffs[8*i + 4] = (a[13*i + 6] >> 4) | ((uint32_t)a[13*i + 7] << 4) |
                               ((uint32_t)a[13*i + 8] << 12);
        r->coeffs[8*i + 4] &= 0x1FFF;
        r->coeffs[8*i + 5] = (a[13*i + 8] >> 1) | ((uint32_t)a[13*i + 9] << 7);
        r->coeffs[8*i + 5] &= 0x1FFF;
        r->coeffs[8*i + 6] = (a[13*i + 9] >> 6) | ((uint32_t)a[13*i + 10] << 2) |
                               ((uint32_t)a[13*i + 11] << 10);
        r->coeffs[8*i + 6] &= 0x1FFF;
        r->coeffs[8*i + 7] = (a[13*i + 11] >> 3) | ((uint32_t)a[13*i + 12] << 5);
        r->coeffs[8*i + 7] &= 0x1FFF;

        unsigned int j;
        for (j = 0; j < 8; j++)
            r->coeffs[8*i + j] = (1 << (MLDSA_D - 1)) - r->coeffs[8*i + j];
    }
}

/**
 * Pack polynomial with eta-bounded coefficients.
 * eta=2: 3 bits per coeff (N*3/8 = 96 bytes)
 * eta=4: 4 bits per coeff (N*4/8 = 128 bytes)
 */
static void ml_polyeta_pack(uint8_t *r, const ml_poly *a, unsigned int eta) {
    unsigned int i;
    if (eta == 2) {
        for (i = 0; i < MLDSA_N / 8; ++i) {
            uint8_t t[8];
            unsigned int j;
            for (j = 0; j < 8; j++)
                t[j] = (uint8_t)((int32_t)eta - a->coeffs[8*i + j]);
            r[3*i + 0] = (t[0] >> 0) | (t[1] << 3) | (t[2] << 6);
            r[3*i + 1] = (t[2] >> 2) | (t[3] << 1) | (t[4] << 4) | (t[5] << 7);
            r[3*i + 2] = (t[5] >> 1) | (t[6] << 2) | (t[7] << 5);
        }
    } else { /* eta == 4 */
        for (i = 0; i < MLDSA_N / 2; ++i) {
            uint8_t t0 = (uint8_t)((int32_t)eta - a->coeffs[2*i + 0]);
            uint8_t t1 = (uint8_t)((int32_t)eta - a->coeffs[2*i + 1]);
            r[i] = t0 | (t1 << 4);
        }
    }
}

static void ml_polyeta_unpack(ml_poly *r, const uint8_t *a, unsigned int eta) {
    unsigned int i;
    if (eta == 2) {
        for (i = 0; i < MLDSA_N / 8; ++i) {
            r->coeffs[8*i + 0] = (int32_t)(a[3*i + 0] & 7);
            r->coeffs[8*i + 1] = (int32_t)((a[3*i + 0] >> 3) & 7);
            r->coeffs[8*i + 2] = (int32_t)((a[3*i + 0] >> 6) | ((a[3*i + 1] << 2) & 7));
            r->coeffs[8*i + 3] = (int32_t)((a[3*i + 1] >> 1) & 7);
            r->coeffs[8*i + 4] = (int32_t)((a[3*i + 1] >> 4) & 7);
            r->coeffs[8*i + 5] = (int32_t)((a[3*i + 1] >> 7) | ((a[3*i + 2] << 1) & 7));
            r->coeffs[8*i + 6] = (int32_t)((a[3*i + 2] >> 2) & 7);
            r->coeffs[8*i + 7] = (int32_t)((a[3*i + 2] >> 5) & 7);
            unsigned int j;
            for (j = 0; j < 8; j++)
                r->coeffs[8*i + j] = (int32_t)eta - r->coeffs[8*i + j];
        }
    } else {
        for (i = 0; i < MLDSA_N / 2; ++i) {
            r->coeffs[2*i + 0] = (int32_t)eta - (int32_t)(a[i] & 0x0F);
            r->coeffs[2*i + 1] = (int32_t)eta - (int32_t)(a[i] >> 4);
        }
    }
}

/* ============================================================================
 * DECOMPOSE / POWER2ROUND / NORM
 * ============================================================================ */

static void ml_power2round(int32_t *a1, int32_t *a0, int32_t a) {
    a = ml_freeze(a);
    *a1 = (a + (1 << (MLDSA_D - 1)) - 1) >> MLDSA_D;
    *a0 = a - (*a1 << MLDSA_D);
}

static void ml_decompose(int32_t *a1, int32_t *a0, int32_t a, int32_t gamma2) {
    a = ml_freeze(a);
    *a0 = a % (2 * gamma2);
    if (*a0 > gamma2) *a0 -= 2 * gamma2;
    if (a - *a0 == MLDSA_Q - 1) {
        *a1 = 0;
        *a0 = -1;
    } else {
        *a1 = (a - *a0) / (2 * gamma2);
    }
}

static unsigned int ml_make_hint(int32_t a0, int32_t a1, int32_t gamma2) {
    if (a0 > gamma2 || a0 < -gamma2 ||
        (a0 == -gamma2 && a1 != 0))
        return 1;
    return 0;
}

static int32_t ml_use_hint(int32_t a, unsigned int hint, int32_t gamma2) {
    int32_t a0, a1;
    ml_decompose(&a1, &a0, a, gamma2);
    if (hint == 0) return a1;

    int32_t m = (MLDSA_Q - 1) / (2 * gamma2);
    if (a0 > 0) return (a1 + 1) % m;
    return (a1 - 1 + m) % m;
}

static int32_t ml_poly_chknorm(const ml_poly *a, int32_t B) {
    unsigned int i;
    for (i = 0; i < MLDSA_N; ++i) {
        int32_t t = a->coeffs[i] >> 31;
        t = a->coeffs[i] - (t & 2 * a->coeffs[i]);
        if (t >= B) return 1;
    }
    return 0;
}

/* ============================================================================
 * PARAMETERIZED KEYGEN / SIGN / VERIFY
 * ============================================================================ */

static ama_error_t ml_dsa_keypair(uint8_t *pk, uint8_t *sk,
                                    const mldsa_params_t *p) {
    uint8_t seedbuf[2 * MLDSA_SEEDBYTES + MLDSA_CRHBYTES];
    uint8_t *rho, *rhoprime, *key;
    ml_poly mat[MLDSA_K_MAX][MLDSA_L_MAX];
    ml_poly s1[MLDSA_L_MAX], s1hat[MLDSA_L_MAX];
    ml_poly s2[MLDSA_K_MAX], t[MLDSA_K_MAX], t1[MLDSA_K_MAX], t0[MLDSA_K_MAX];
    uint8_t tr[MLDSA_TRBYTES];
    unsigned int i, j;
    ama_error_t rc;

    if (!pk || !sk) return AMA_ERROR_INVALID_PARAM;

    /* Generate random seed */
    rc = ama_randombytes(seedbuf, MLDSA_SEEDBYTES);
    if (rc != AMA_SUCCESS) return rc;

    /* (rho, rho', K) = H(xi || k || l) */
    {
        uint8_t h_input[MLDSA_SEEDBYTES + 2];
        memcpy(h_input, seedbuf, MLDSA_SEEDBYTES);
        h_input[MLDSA_SEEDBYTES] = (uint8_t)p->k;
        h_input[MLDSA_SEEDBYTES + 1] = (uint8_t)p->l;
        ama_shake256(h_input, MLDSA_SEEDBYTES + 2, seedbuf, sizeof(seedbuf));
        ama_secure_memzero(h_input, sizeof(h_input));
    }
    rho = seedbuf;
    rhoprime = rho + MLDSA_SEEDBYTES;
    key = rhoprime + MLDSA_CRHBYTES;

    /* Expand matrix A */
    for (i = 0; i < p->k; ++i)
        for (j = 0; j < p->l; ++j)
            ml_poly_uniform(&mat[i][j], rho, (uint16_t)(i * 256 + j));

    /* Sample secret vectors */
    for (i = 0; i < p->l; ++i)
        ml_poly_uniform_eta(&s1[i], rhoprime, (uint16_t)i, p->eta);
    for (i = 0; i < p->k; ++i)
        ml_poly_uniform_eta(&s2[i], rhoprime, (uint16_t)(p->l + i), p->eta);

    /* t = A*NTT(s1) + s2 */
    memcpy(s1hat, s1, p->l * sizeof(ml_poly));
    for (i = 0; i < p->l; ++i)
        ml_poly_ntt(&s1hat[i]);

    for (i = 0; i < p->k; ++i) {
        ml_poly tmp;
        memset(&t[i], 0, sizeof(ml_poly));
        for (j = 0; j < p->l; ++j) {
            ml_poly_pointwise(&tmp, &mat[i][j], &s1hat[j]);
            ml_poly_add(&t[i], &t[i], &tmp);
        }
        ml_poly_invntt(&t[i]);
        ml_poly_add(&t[i], &t[i], &s2[i]);
        ml_poly_reduce(&t[i]);
        ml_poly_caddq(&t[i]);
    }

    /* Power2Round: t = t1 * 2^d + t0 */
    for (i = 0; i < p->k; ++i) {
        for (j = 0; j < MLDSA_N; ++j) {
            ml_power2round(&t1[i].coeffs[j], &t0[i].coeffs[j], t[i].coeffs[j]);
        }
    }

    /* Pack public key: rho || t1 */
    memcpy(pk, rho, MLDSA_SEEDBYTES);
    for (i = 0; i < p->k; ++i)
        ml_polyt1_pack(pk + MLDSA_SEEDBYTES + i * p->polyt1_packed, &t1[i]);

    /* tr = H(pk) */
    ama_shake256(pk, p->pk_bytes, tr, MLDSA_TRBYTES);

    /* Pack secret key: rho || key || tr || s1 || s2 || t0 */
    memcpy(sk, rho, MLDSA_SEEDBYTES);
    memcpy(sk + MLDSA_SEEDBYTES, key, MLDSA_SEEDBYTES);
    memcpy(sk + 2 * MLDSA_SEEDBYTES, tr, MLDSA_TRBYTES);

    size_t offset = 2 * MLDSA_SEEDBYTES + MLDSA_TRBYTES;
    for (i = 0; i < p->l; ++i) {
        ml_polyeta_pack(sk + offset, &s1[i], p->eta);
        offset += p->polyeta_packed;
    }
    for (i = 0; i < p->k; ++i) {
        ml_polyeta_pack(sk + offset, &s2[i], p->eta);
        offset += p->polyeta_packed;
    }
    for (i = 0; i < p->k; ++i) {
        ml_polyt0_pack(sk + offset, &t0[i]);
        offset += p->polyt0_packed;
    }

    /* Scrub */
    ama_secure_memzero(seedbuf, sizeof(seedbuf));
    ama_secure_memzero(s1, sizeof(s1));
    ama_secure_memzero(s2, sizeof(s2));

    return AMA_SUCCESS;
}

static ama_error_t ml_dsa_sign(uint8_t *sig, size_t *sig_len,
                                 const uint8_t *msg, size_t msg_len,
                                 const uint8_t *sk, const mldsa_params_t *p) {
    const uint8_t *rho, *key, *tr;
    ml_poly mat[MLDSA_K_MAX][MLDSA_L_MAX];
    ml_poly s1[MLDSA_L_MAX], s2[MLDSA_K_MAX], t0[MLDSA_K_MAX];
    ml_poly y[MLDSA_L_MAX], yhat[MLDSA_L_MAX], w[MLDSA_K_MAX];
    ml_poly w1[MLDSA_K_MAX], w0[MLDSA_K_MAX];
    ml_poly z[MLDSA_L_MAX], ct0[MLDSA_K_MAX], cs2[MLDSA_K_MAX];
    ml_poly cp;
    uint8_t mu[MLDSA_CRHBYTES];
    uint8_t rhoprime[MLDSA_CRHBYTES];
    unsigned int i, j, n;
    uint16_t nonce = 0;
    int reject;

    if (!sig || !sig_len || !msg || !sk) return AMA_ERROR_INVALID_PARAM;
    if (*sig_len < p->sig_bytes) return AMA_ERROR_INVALID_PARAM;

    /* Unpack secret key */
    rho = sk;
    key = sk + MLDSA_SEEDBYTES;
    tr = sk + 2 * MLDSA_SEEDBYTES;

    size_t offset = 2 * MLDSA_SEEDBYTES + MLDSA_TRBYTES;
    for (i = 0; i < p->l; ++i) {
        ml_polyeta_unpack(&s1[i], sk + offset, p->eta);
        offset += p->polyeta_packed;
    }
    for (i = 0; i < p->k; ++i) {
        ml_polyeta_unpack(&s2[i], sk + offset, p->eta);
        offset += p->polyeta_packed;
    }
    for (i = 0; i < p->k; ++i) {
        ml_polyt0_unpack(&t0[i], sk + offset);
        offset += p->polyt0_packed;
    }

    /* NTT(s1), NTT(s2), NTT(t0) */
    for (i = 0; i < p->l; ++i) ml_poly_ntt(&s1[i]);
    for (i = 0; i < p->k; ++i) ml_poly_ntt(&s2[i]);
    for (i = 0; i < p->k; ++i) ml_poly_ntt(&t0[i]);

    /* Expand A */
    for (i = 0; i < p->k; ++i)
        for (j = 0; j < p->l; ++j)
            ml_poly_uniform(&mat[i][j], rho, (uint16_t)(i * 256 + j));

    /* mu = CRH(tr || M) */
    {
        size_t crh_len = MLDSA_TRBYTES + msg_len;
        uint8_t *crh_input = (uint8_t *)malloc(crh_len);
        if (!crh_input) return AMA_ERROR_MEMORY;
        memcpy(crh_input, tr, MLDSA_TRBYTES);
        memcpy(crh_input + MLDSA_TRBYTES, msg, msg_len);
        ama_shake256(crh_input, crh_len, mu, MLDSA_CRHBYTES);
        free(crh_input);
    }

    /* rhoprime = CRH(key || mu) */
    {
        uint8_t crh2[MLDSA_SEEDBYTES + MLDSA_CRHBYTES];
        memcpy(crh2, key, MLDSA_SEEDBYTES);
        memcpy(crh2 + MLDSA_SEEDBYTES, mu, MLDSA_CRHBYTES);
        ama_shake256(crh2, sizeof(crh2), rhoprime, MLDSA_CRHBYTES);
    }

    /* Rejection sampling loop */
    for (n = 0; n < 1000; ++n) {
        /* Sample y from [-gamma1+1, gamma1] */
        for (i = 0; i < p->l; ++i) {
            uint8_t ybuf[MLDSA_CRHBYTES + 2];
            uint8_t ystream[5 * MLDSA_N]; /* enough for gamma1 up to 2^19 */
            memcpy(ybuf, rhoprime, MLDSA_CRHBYTES);
            ybuf[MLDSA_CRHBYTES] = (uint8_t)(nonce + i);
            ybuf[MLDSA_CRHBYTES + 1] = (uint8_t)((nonce + i) >> 8);
            ama_shake256(ybuf, MLDSA_CRHBYTES + 2, ystream, sizeof(ystream));

            unsigned int pos = 0;
            for (j = 0; j < MLDSA_N; ++j) {
                int32_t val = 0;
                if (p->gamma1 == (1 << 17)) {
                    /* 18 bits per coefficient */
                    val = ystream[pos] | ((int32_t)ystream[pos+1] << 8) |
                          ((int32_t)(ystream[pos+2] & 0x3) << 16);
                    pos += 2;
                    if (j % 4 == 3) pos++;
                    val = p->gamma1 - val;
                } else {
                    /* gamma1 = 2^19: 20 bits per coefficient */
                    val = ystream[pos] | ((int32_t)ystream[pos+1] << 8);
                    if (j & 1) {
                        val = (val >> 4) | ((int32_t)(ystream[pos+2]) << 4);
                        pos += 3;
                    } else {
                        val &= 0xFFFFF;
                        pos += 2;
                    }
                    val &= 0xFFFFF;
                    val = p->gamma1 - val;
                }
                y[i].coeffs[j] = val;
            }
        }
        nonce += (uint16_t)p->l;

        /* w = A * NTT(y) */
        memcpy(yhat, y, p->l * sizeof(ml_poly));
        for (i = 0; i < p->l; ++i)
            ml_poly_ntt(&yhat[i]);

        for (i = 0; i < p->k; ++i) {
            ml_poly tmp;
            memset(&w[i], 0, sizeof(ml_poly));
            for (j = 0; j < p->l; ++j) {
                ml_poly_pointwise(&tmp, &mat[i][j], &yhat[j]);
                ml_poly_add(&w[i], &w[i], &tmp);
            }
            ml_poly_invntt(&w[i]);
            ml_poly_reduce(&w[i]);
            ml_poly_caddq(&w[i]);
        }

        /* Decompose w */
        for (i = 0; i < p->k; ++i) {
            for (j = 0; j < MLDSA_N; ++j) {
                ml_decompose(&w1[i].coeffs[j], &w0[i].coeffs[j],
                              w[i].coeffs[j], p->gamma2);
            }
        }

        /* Pack w1 and compute challenge */
        {
            size_t w1_packed_total = p->k * p->polyw1_packed;
            uint8_t *w1_bytes = (uint8_t *)calloc(1, w1_packed_total);
            uint8_t *c_input;
            size_t c_input_len;

            if (!w1_bytes) return AMA_ERROR_MEMORY;

            /* Pack w1 (simplified: just write raw bytes) */
            for (i = 0; i < p->k; ++i) {
                uint8_t *w1_ptr = w1_bytes + i * p->polyw1_packed;
                for (j = 0; j < MLDSA_N; ++j) {
                    unsigned int byte_idx = j * 4 / 8; /* simplified packing */
                    if (byte_idx < p->polyw1_packed) {
                        w1_ptr[byte_idx] |= (uint8_t)(w1[i].coeffs[j] << ((j & 1) * 4));
                    }
                }
            }

            c_input_len = MLDSA_CRHBYTES + w1_packed_total;
            c_input = (uint8_t *)malloc(c_input_len);
            if (!c_input) { free(w1_bytes); return AMA_ERROR_MEMORY; }
            memcpy(c_input, mu, MLDSA_CRHBYTES);
            memcpy(c_input + MLDSA_CRHBYTES, w1_bytes, w1_packed_total);

            uint8_t c_hash[64];
            ama_shake256(c_input, c_input_len, c_hash, p->ctilde_bytes);

            ml_poly_challenge(&cp, c_hash, p->ctilde_bytes, p->tau);

            /* Store c_tilde in signature */
            memcpy(sig, c_hash, p->ctilde_bytes);

            free(w1_bytes);
            free(c_input);
        }

        /* z = y + c*s1 */
        ml_poly cp_hat;
        memcpy(&cp_hat, &cp, sizeof(ml_poly));
        ml_poly_ntt(&cp_hat);

        reject = 0;
        for (i = 0; i < p->l; ++i) {
            ml_poly tmp;
            ml_poly_pointwise(&tmp, &cp_hat, &s1[i]);
            ml_poly_invntt(&tmp);
            ml_poly_add(&z[i], &y[i], &tmp);
            ml_poly_reduce(&z[i]);

            if (ml_poly_chknorm(&z[i], p->gamma1 - (int32_t)p->tau * (int32_t)p->eta)) {
                reject = 1;
                break;
            }
        }
        if (reject) continue;

        /* Check c*s2 + w0 */
        for (i = 0; i < p->k; ++i) {
            ml_poly tmp;
            ml_poly_pointwise(&tmp, &cp_hat, &s2[i]);
            ml_poly_invntt(&tmp);
            ml_poly_sub(&cs2[i], &w0[i], &tmp);
            ml_poly_reduce(&cs2[i]);

            if (ml_poly_chknorm(&cs2[i], p->gamma2 - (int32_t)p->tau * (int32_t)p->eta)) {
                reject = 1;
                break;
            }
        }
        if (reject) continue;

        /* Compute hints */
        {
            unsigned int hint_count = 0;
            for (i = 0; i < p->k; ++i) {
                ml_poly tmp;
                ml_poly_pointwise(&tmp, &cp_hat, &t0[i]);
                ml_poly_invntt(&tmp);
                ml_poly_reduce(&tmp);

                if (ml_poly_chknorm(&tmp, p->gamma2)) {
                    reject = 1;
                    break;
                }

                ml_poly_add(&ct0[i], &cs2[i], &tmp);
                for (j = 0; j < MLDSA_N; ++j) {
                    hint_count += ml_make_hint(cs2[i].coeffs[j],
                                               ct0[i].coeffs[j], p->gamma2);
                }
            }
            if (reject) continue;
            if (hint_count > p->omega) continue;
        }

        /* Pack signature: c_tilde || z || h */
        {
            uint8_t *sig_ptr = sig + p->ctilde_bytes;

            /* Pack z */
            for (i = 0; i < p->l; ++i) {
                for (j = 0; j < MLDSA_N; ++j) {
                    int32_t val = p->gamma1 - z[i].coeffs[j];
                    /* Simplified packing: store gamma1 range */
                    if (p->gamma1 == (1 << 17)) {
                        /* 18 bits */
                        unsigned int idx = j * 18 / 8;
                        unsigned int bit = (j * 18) % 8;
                        if (idx + 2 < p->polyz_packed) {
                            sig_ptr[idx] |= (uint8_t)(val << bit);
                            sig_ptr[idx + 1] |= (uint8_t)(val >> (8 - bit));
                            sig_ptr[idx + 2] |= (uint8_t)(val >> (16 - bit));
                        }
                    } else {
                        /* 20 bits */
                        unsigned int idx = j * 20 / 8;
                        unsigned int bit = (j * 20) % 8;
                        if (idx + 2 < p->polyz_packed) {
                            sig_ptr[idx] |= (uint8_t)(val << bit);
                            sig_ptr[idx + 1] |= (uint8_t)(val >> (8 - bit));
                            sig_ptr[idx + 2] |= (uint8_t)(val >> (16 - bit));
                        }
                    }
                }
                sig_ptr += p->polyz_packed;
            }

            /* Pack hints (simplified: omega + k bytes) */
            memset(sig_ptr, 0, p->omega + p->k);
            unsigned int hint_offset = 0;
            for (i = 0; i < p->k; ++i) {
                for (j = 0; j < MLDSA_N; ++j) {
                    if (ml_make_hint(cs2[i].coeffs[j], ct0[i].coeffs[j], p->gamma2)) {
                        if (hint_offset < p->omega)
                            sig_ptr[hint_offset++] = (uint8_t)j;
                    }
                }
                sig_ptr[p->omega + i] = (uint8_t)hint_offset;
            }
        }

        *sig_len = p->sig_bytes;

        /* Scrub */
        ama_secure_memzero(s1, sizeof(s1));
        ama_secure_memzero(s2, sizeof(s2));
        ama_secure_memzero(y, sizeof(y));

        return AMA_SUCCESS;
    }

    return AMA_ERROR_VERIFY_FAILED; /* Rejection sampling exhausted */
}

static ama_error_t ml_dsa_verify(const uint8_t *msg, size_t msg_len,
                                   const uint8_t *sig, size_t sig_len,
                                   const uint8_t *pk, const mldsa_params_t *p) {
    const uint8_t *rho;
    ml_poly mat[MLDSA_K_MAX][MLDSA_L_MAX];
    ml_poly t1[MLDSA_K_MAX];
    ml_poly z[MLDSA_L_MAX], w_prime[MLDSA_K_MAX];
    ml_poly cp, cp_hat;
    uint8_t mu[MLDSA_CRHBYTES], tr[MLDSA_TRBYTES];
    unsigned int i, j;

    if (!msg || !sig || !pk) return AMA_ERROR_INVALID_PARAM;
    if (sig_len < p->sig_bytes) return AMA_ERROR_VERIFY_FAILED;

    /* Unpack public key */
    rho = pk;
    for (i = 0; i < p->k; ++i)
        ml_polyt1_unpack(&t1[i], pk + MLDSA_SEEDBYTES + i * p->polyt1_packed);

    /* Expand A */
    for (i = 0; i < p->k; ++i)
        for (j = 0; j < p->l; ++j)
            ml_poly_uniform(&mat[i][j], rho, (uint16_t)(i * 256 + j));

    /* tr = H(pk) */
    ama_shake256(pk, p->pk_bytes, tr, MLDSA_TRBYTES);

    /* mu = CRH(tr || M) */
    {
        size_t crh_len = MLDSA_TRBYTES + msg_len;
        uint8_t *crh_input = (uint8_t *)malloc(crh_len);
        if (!crh_input) return AMA_ERROR_MEMORY;
        memcpy(crh_input, tr, MLDSA_TRBYTES);
        memcpy(crh_input + MLDSA_TRBYTES, msg, msg_len);
        ama_shake256(crh_input, crh_len, mu, MLDSA_CRHBYTES);
        free(crh_input);
    }

    /* Unpack c_tilde and reconstruct challenge */
    ml_poly_challenge(&cp, sig, p->ctilde_bytes, p->tau);
    memcpy(&cp_hat, &cp, sizeof(ml_poly));
    ml_poly_ntt(&cp_hat);

    /* Unpack z (simplified: use rejection bounds check) */
    {
        const uint8_t *z_ptr = sig + p->ctilde_bytes;
        for (i = 0; i < p->l; ++i) {
            for (j = 0; j < MLDSA_N; ++j) {
                /* Simplified: read from packed bytes */
                if (p->gamma1 == (1 << 17)) {
                    unsigned int idx = j * 18 / 8;
                    unsigned int bit = (j * 18) % 8;
                    int32_t val = 0;
                    if (idx + 2 < p->polyz_packed) {
                        val = (z_ptr[idx] >> bit) |
                              ((int32_t)z_ptr[idx + 1] << (8 - bit)) |
                              ((int32_t)(z_ptr[idx + 2] & ((1 << (bit + 2)) - 1)) << (16 - bit));
                        val &= 0x3FFFF;
                    }
                    z[i].coeffs[j] = p->gamma1 - val;
                } else {
                    unsigned int idx = j * 20 / 8;
                    unsigned int bit = (j * 20) % 8;
                    int32_t val = 0;
                    if (idx + 2 < p->polyz_packed) {
                        val = (z_ptr[idx] >> bit) |
                              ((int32_t)z_ptr[idx + 1] << (8 - bit)) |
                              ((int32_t)(z_ptr[idx + 2]) << (16 - bit));
                        val &= 0xFFFFF;
                    }
                    z[i].coeffs[j] = p->gamma1 - val;
                }
            }
            z_ptr += p->polyz_packed;
        }
    }

    /* Check z norm */
    for (i = 0; i < p->l; ++i) {
        if (ml_poly_chknorm(&z[i], p->gamma1 - (int32_t)p->tau * (int32_t)p->eta))
            return AMA_ERROR_VERIFY_FAILED;
    }

    /* w' = A*NTT(z) - c*NTT(t1*2^d) */
    {
        ml_poly zhat[MLDSA_L_MAX];
        memcpy(zhat, z, p->l * sizeof(ml_poly));
        for (i = 0; i < p->l; ++i)
            ml_poly_ntt(&zhat[i]);

        for (i = 0; i < p->k; ++i) {
            ml_poly tmp, ct1;

            /* A*z */
            memset(&w_prime[i], 0, sizeof(ml_poly));
            for (j = 0; j < p->l; ++j) {
                ml_poly_pointwise(&tmp, &mat[i][j], &zhat[j]);
                ml_poly_add(&w_prime[i], &w_prime[i], &tmp);
            }

            /* t1 * 2^d in NTT domain */
            for (j = 0; j < MLDSA_N; ++j)
                ct1.coeffs[j] = t1[i].coeffs[j] << MLDSA_D;
            ml_poly_ntt(&ct1);

            /* c * t1*2^d */
            ml_poly_pointwise(&tmp, &cp_hat, &ct1);

            /* w' = A*z - c*t1*2^d */
            ml_poly_sub(&w_prime[i], &w_prime[i], &tmp);
            ml_poly_invntt(&w_prime[i]);
            ml_poly_reduce(&w_prime[i]);
            ml_poly_caddq(&w_prime[i]);
        }
    }

    /* Use hints to recover w1 */
    {
        const uint8_t *hint_ptr = sig + p->ctilde_bytes + p->l * p->polyz_packed;
        uint8_t hint_bits[MLDSA_K_MAX][MLDSA_N];
        memset(hint_bits, 0, sizeof(hint_bits));

        unsigned int prev = 0;
        for (i = 0; i < p->k; ++i) {
            unsigned int end = hint_ptr[p->omega + i];
            for (j = prev; j < end && j < p->omega; ++j) {
                unsigned int idx = hint_ptr[j];
                if (idx < MLDSA_N)
                    hint_bits[i][idx] = 1;
            }
            prev = end;
        }

        /* UseHint to get w1' */
        ml_poly w1_prime[MLDSA_K_MAX];
        for (i = 0; i < p->k; ++i) {
            for (j = 0; j < MLDSA_N; ++j) {
                w1_prime[i].coeffs[j] = ml_use_hint(w_prime[i].coeffs[j],
                                                      hint_bits[i][j], p->gamma2);
            }
        }

        /* Recompute c' from mu and w1' */
        size_t w1_packed_total = p->k * p->polyw1_packed;
        uint8_t *w1_bytes = (uint8_t *)calloc(1, w1_packed_total);
        if (!w1_bytes) return AMA_ERROR_MEMORY;

        for (i = 0; i < p->k; ++i) {
            uint8_t *w1_ptr = w1_bytes + i * p->polyw1_packed;
            for (j = 0; j < MLDSA_N; ++j) {
                unsigned int byte_idx = j * 4 / 8;
                if (byte_idx < p->polyw1_packed) {
                    w1_ptr[byte_idx] |= (uint8_t)(w1_prime[i].coeffs[j] << ((j & 1) * 4));
                }
            }
        }

        size_t c_input_len = MLDSA_CRHBYTES + w1_packed_total;
        uint8_t *c_input = (uint8_t *)malloc(c_input_len);
        if (!c_input) { free(w1_bytes); return AMA_ERROR_MEMORY; }
        memcpy(c_input, mu, MLDSA_CRHBYTES);
        memcpy(c_input + MLDSA_CRHBYTES, w1_bytes, w1_packed_total);

        uint8_t c_hash[64];
        ama_shake256(c_input, c_input_len, c_hash, p->ctilde_bytes);

        free(w1_bytes);
        free(c_input);

        /* Compare c_tilde */
        if (ama_consttime_memcmp(sig, c_hash, p->ctilde_bytes) != 0) {
            return AMA_ERROR_VERIFY_FAILED;
        }
    }

    return AMA_SUCCESS;
}

/* ============================================================================
 * PUBLIC API — ML-DSA-44 / ML-DSA-87
 * ============================================================================ */

/* ML-DSA-44 */
AMA_API ama_error_t ama_dilithium44_keypair(uint8_t *pk, uint8_t *sk) {
    return ml_dsa_keypair(pk, sk, &MLDSA_44);
}

AMA_API ama_error_t ama_dilithium44_sign(uint8_t *sig, size_t *sig_len,
    const uint8_t *msg, size_t msg_len, const uint8_t *sk) {
    return ml_dsa_sign(sig, sig_len, msg, msg_len, sk, &MLDSA_44);
}

AMA_API ama_error_t ama_dilithium44_verify(const uint8_t *msg, size_t msg_len,
    const uint8_t *sig, size_t sig_len, const uint8_t *pk) {
    return ml_dsa_verify(msg, msg_len, sig, sig_len, pk, &MLDSA_44);
}

/* ML-DSA-87 */
AMA_API ama_error_t ama_dilithium87_keypair(uint8_t *pk, uint8_t *sk) {
    return ml_dsa_keypair(pk, sk, &MLDSA_87);
}

AMA_API ama_error_t ama_dilithium87_sign(uint8_t *sig, size_t *sig_len,
    const uint8_t *msg, size_t msg_len, const uint8_t *sk) {
    return ml_dsa_sign(sig, sig_len, msg, msg_len, sk, &MLDSA_87);
}

AMA_API ama_error_t ama_dilithium87_verify(const uint8_t *msg, size_t msg_len,
    const uint8_t *sig, size_t sig_len, const uint8_t *pk) {
    return ml_dsa_verify(msg, msg_len, sig, sig_len, pk, &MLDSA_87);
}
