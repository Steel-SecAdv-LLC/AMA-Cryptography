/* Copyright (C) 2025-2026 Steel Security Advisors LLC */
/* SPDX-License-Identifier: Apache-2.0 */
/**
 * @file ama_dilithium.c
 * @brief ML-DSA-65 (CRYSTALS-Dilithium) Digital Signature - Native C Implementation
 * @author Andrew E. A., Steel Security Advisors LLC
 * @date 2026-04-06
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
 *
 * Provenance:
 *   Implemented from: NIST FIPS 204 (August 2024 final), §5-§8 pseudocode.
 *   No code derived from pq-crystals/dilithium, PQClean, liboqs, or any
 *   other third-party PQC implementation. The AVX2/NEON/SVE2 NTT paths
 *   in `src/c/avx2/`, `src/c/neon/`, and `src/c/sve2/` are in-house.
 *   The external/pure domain-separation wrapper
 *   (`ama_dilithium_verify_ctx`) follows FIPS 204 §5.4 directly.
 *   Validated: 25/25 ACVP ML-DSA-65 KeyGen vectors and 15/15 ACVP
 *   ML-DSA-65 SigVer TG 3 (external/pure) vectors. See
 *   `src/c/PROVENANCE.md` for full provenance rationale and
 *   `CSRC_ALIGN_REPORT.md` for KAT results.
 */

#include "../include/ama_cryptography.h"
#include "../include/ama_dispatch.h"
#include "internal/ama_sha3_x4.h"
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
 * ML-DSA PARAMETER SETS (NIST FIPS 204 Table 1)
 *
 * As with ML-KEM, `n`, `q`, `d` and the NTT layer are identical across every
 * ML-DSA parameter set — the zeta table, the Montgomery constants and every
 * reduction bound are shared verbatim.  What varies is the matrix shape
 * (k x l), the secret range `eta`, the challenge weight `tau`, the masking
 * bound `gamma1`, the decomposition modulus `gamma2`, the hint budget
 * `omega`, and the commitment-hash width `ctilde`.
 *
 * Those become a runtime parameter block rather than three copies of a
 * 2100-line implementation.  Vectors are sized at DIL_K_MAX / DIL_L_MAX so
 * every set pays the ML-DSA-87 stack footprint; that is a deliberate trade of
 * stack for a single audited body of code.
 * ============================================================================ */

#define DIL_N 256
#define DIL_Q 8380417
#define DIL_D 13

/** Largest matrix dimensions across the supported sets (ML-DSA-87: 8 x 7). */
#define DIL_K_MAX 8
#define DIL_L_MAX 7
/** Largest hint budget (ML-DSA-44). */
#define DIL_OMEGA_MAX 80
/** Largest commitment-hash width (ML-DSA-87). */
#define DIL_CTILDEBYTES_MAX 64
/** Largest packed-polynomial widths across the supported sets. */
#define DIL_POLYZ_PACKEDBYTES_MAX   640   /* gamma1 = 2^19 -> 20 bits */
#define DIL_POLYW1_PACKEDBYTES_MAX  192   /* gamma2 = (q-1)/88 -> 6 bits */
#define DIL_POLYETA_PACKEDBYTES_MAX 128   /* eta = 4 -> 4 bits */
#define DIL_POLYT1_PACKEDBYTES 320        /* 10 bits, every parameter set */
#define DIL_POLYT0_PACKEDBYTES 416        /* 13 bits, every parameter set */

#define DIL_SEEDBYTES 32
#define DIL_RNDBYTES 32  /* FIPS 204 Section 6.2 Algorithm 7: rnd in {0,1}^256. */
#define DIL_CRHBYTES 64
#define DIL_TRBYTES 64

/** Largest secret/public key and signature across the supported sets. */
#define DIL_PUBLICKEY_BYTES_MAX 2592
#define DIL_SECRETKEY_BYTES_MAX 4896
#define DIL_SIGNATURE_BYTES_MAX 4627

/* ============================================================================
 * POLYNOMIAL TYPES
 * ============================================================================ */

typedef struct {
    int32_t coeffs[DIL_N];
} dil_poly;

typedef struct {
    dil_poly vec[DIL_L_MAX];
} dil_polyvecl;

typedef struct {
    dil_poly vec[DIL_K_MAX];
} dil_polyveck;

/**
 * One ML-DSA parameter set.
 *
 * The packed-polynomial widths and the three key/signature byte lengths are
 * derived, not independent; ama_ml_dsa_test_params_selfcheck() (AMA_TESTING_MODE)
 * re-derives every one of them from (k, l, eta, gamma1, gamma2, omega, ctilde)
 * and fails the build's test suite on any disagreement, so a mistyped row
 * cannot ship as a plausible-looking wrong parameter set.
 */
typedef struct {
    ama_ml_dsa_param_set_t ps;
    const char *name;
    unsigned k;
    unsigned l;
    int32_t  eta;
    unsigned tau;
    int32_t  beta;          /* = tau * eta */
    int32_t  gamma1;
    int32_t  gamma2;
    unsigned omega;
    size_t   ctildebytes;
    size_t   polyz_packedbytes;
    size_t   polyw1_packedbytes;
    size_t   polyeta_packedbytes;
    size_t   pk_bytes;
    size_t   sk_bytes;
    size_t   sig_bytes;
} dil_params;

static const dil_params DIL_PARAM_SETS[3] = {
    { AMA_ML_DSA_44, "ML-DSA-44", 4, 4, 2, 39,  78, (1 << 17), (DIL_Q - 1) / 88, 80, 32,
      576, 192,  96, 1312, 2560, 2420 },
    { AMA_ML_DSA_65, "ML-DSA-65", 6, 5, 4, 49, 196, (1 << 19), (DIL_Q - 1) / 32, 55, 48,
      640, 128, 128, 1952, 4032, 3309 },
    { AMA_ML_DSA_87, "ML-DSA-87", 8, 7, 2, 60, 120, (1 << 19), (DIL_Q - 1) / 32, 75, 64,
      640, 128,  96, 2592, 4896, 4627 }
};

static const dil_params *dil_params_for(ama_ml_dsa_param_set_t ps) {
    switch (ps) {
        case AMA_ML_DSA_44: return &DIL_PARAM_SETS[0];
        case AMA_ML_DSA_65: return &DIL_PARAM_SETS[1];
        case AMA_ML_DSA_87: return &DIL_PARAM_SETS[2];
        default:            return NULL;
    }
}

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
 *
 * Returns the CENTRED representative of a mod q, not a value in [0, q): the
 * result is negative for roughly half of all inputs, which is what makes the
 * `dil_caddq` in `dil_freeze` below necessary rather than decorative.  This
 * header used to claim [0, q), and every bound derived from that claim would
 * have been wrong by a factor of two in the wrong direction.
 *
 * Image, enumerated rather than quoted: over a >= 6q-wide band of the input
 * domain — which covers every value this file passes it, the widest being the
 * l-fold accumulator bounded by l*q — the result lies in [-4235259, 4235258],
 * i.e. |t| <= 0.506q.  Over the whole int32 domain it widens to
 * [-6282956, 6282505], |t| <= 0.750q.  The inverse-NTT precondition argued at
 * the keygen call site rests on the first of those two figures.
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
 * Forward NTT (Number Theoretic Transform) for Dilithium.
 * Accepts a cached dispatch table pointer to avoid repeated ama_get_dispatch_table() calls.
 */
/* Scalar reference exposed so the dispatch auto-tune can microbench
 * the SIMD NTT slots against a single source of truth — `dil_ntt_cached`
 * / `dil_invntt_cached` below delegate to the same helpers.
 *
 * Hidden visibility — see the matching block in `src/c/ama_kyber.c`
 * (Copilot review #326): these symbols are internal contract surface
 * between this TU and `src/c/dispatch/ama_dispatch.c` only and must
 * not expand the libama_cryptography.so user-observable ABI. */
#if defined(__GNUC__) || defined(__clang__)
__attribute__((visibility("hidden")))
#endif
void ama_dilithium_ntt_generic_ref(int32_t poly[DIL_N], const int32_t zetas_tab[DIL_N]);
#if defined(__GNUC__) || defined(__clang__)
__attribute__((visibility("hidden")))
#endif
void ama_dilithium_invntt_generic_ref(int32_t poly[DIL_N], const int32_t zetas_tab[DIL_N]);

static void dil_ntt_scalar(int32_t a[DIL_N], const int32_t zetas_tab[DIL_N]) {
    unsigned int len, start, j, k;
    int32_t zeta, t;

    k = 0;
    for (len = 128; len > 0; len >>= 1) {
        for (start = 0; start < DIL_N; start = j + len) {
            zeta = zetas_tab[++k];
            for (j = start; j < start + len; ++j) {
                t = dil_montgomery_reduce((int64_t)zeta * a[j + len]);
                a[j + len] = a[j] - t;
                a[j] = a[j] + t;
            }
        }
    }
}

static void dil_invntt_scalar(int32_t a[DIL_N], const int32_t zetas_tab[DIL_N]) {
    unsigned int start, len, j, k;
    int32_t t, zeta;
    const int32_t f = 41978;  /* Mont^(-1) * N^(-1) mod q */

    k = 256;
    for (len = 1; len < DIL_N; len <<= 1) {
        for (start = 0; start < DIL_N; start = j + len) {
            zeta = -zetas_tab[--k];
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

#if defined(__GNUC__) || defined(__clang__)
__attribute__((visibility("hidden")))
#endif
void ama_dilithium_ntt_generic_ref(int32_t poly[DIL_N], const int32_t zetas_tab[DIL_N]) {
    dil_ntt_scalar(poly, zetas_tab);
}

#if defined(__GNUC__) || defined(__clang__)
__attribute__((visibility("hidden")))
#endif
void ama_dilithium_invntt_generic_ref(int32_t poly[DIL_N], const int32_t zetas_tab[DIL_N]) {
    dil_invntt_scalar(poly, zetas_tab);
}

static void dil_ntt_cached(int32_t a[DIL_N], const ama_dispatch_table_t *dt) {
    /* Dispatch to SIMD implementation when available (INVARIANT-4: graceful fallback) */
    if (dt->dilithium_ntt) {
        dt->dilithium_ntt(a, dil_zetas);
        return;
    }
    dil_ntt_scalar(a, dil_zetas);
}

/**
 * Inverse NTT for Dilithium.
 * Accepts a cached dispatch table pointer to avoid repeated ama_get_dispatch_table() calls.
 */
#ifdef AMA_TESTING_MODE
#include "internal/ama_testing_exports.h"

/* Largest |coefficient| seen at ANY inverse-NTT entry since the last reset.
 *
 * The inverse NTT's input precondition (|coeff| < q — see the bound note at
 * the keygen call site) is what keeps its unreduced additive butterfly inside
 * int32, and it is a precondition of the CALL SITES rather than something the
 * transform can enforce on itself.  A future edit that drops one of the three
 * `reduce`-before-`invntt` calls would reintroduce an l*q input silently: the
 * signatures would still verify, every KAT would still pass, and only the
 * overflow margin would change.  This counter is what makes that observable,
 * and `tests/c/test_dilithium_invntt_bound.c` is what reads it.
 *
 * Instrumented here, at the dispatch wrapper, rather than inside
 * `dil_invntt_scalar` — so the measurement covers the SIMD kernels too, which
 * carry the same precondition and are what actually runs on a host with AVX2
 * or NEON.
 *
 * `AMA_TESTING_MODE` is PRIVATE to the `ama_cryptography_test` CMake target,
 * so the shipped shared and static libraries contain neither the counter nor
 * the loop that maintains it. */
static _Thread_local int32_t dil_test_invntt_max_input = 0;

/* OFF until a test asks for it, and that is not tidiness.
 *
 * `ama_cryptography_test` is the archive `tests/c/test_dudect.c` links, and
 * dudect has an `ML-DSA-65 sign` lane — so this accumulator sits inside a
 * measured constant-time path.  Its inner comparison branches on the
 * coefficient magnitude, which is secret-derived: left unconditional it would
 * put a data-dependent branch into the very lane that exists to prove there
 * is none, either producing a false verdict or masking a real one.  Gated on a
 * flag no dudect binary ever sets, the loop does not execute there at all and
 * the only residue is one perfectly-predicted test against a value that is
 * constant for the life of the process — identical in both dudect classes by
 * construction, and therefore invisible to the statistic.
 *
 * `ama_dilithium_test_invntt_bound_reset()` is what arms it, so a test that
 * reads the bound necessarily enabled it first and one that does not never
 * pays for it. */
static _Thread_local int dil_test_invntt_bound_armed = 0;

void ama_dilithium_test_invntt_bound_reset(void) {
    dil_test_invntt_max_input = 0;
    dil_test_invntt_bound_armed = 1;
}

int32_t ama_dilithium_test_invntt_bound_get(void) {
    return dil_test_invntt_max_input;
}

static void dil_test_note_invntt_input(const int32_t a[DIL_N]) {
    unsigned int i;
    if (!dil_test_invntt_bound_armed) return;
    for (i = 0; i < DIL_N; ++i) {
        int32_t v = a[i] < 0 ? -a[i] : a[i];
        if (v > dil_test_invntt_max_input) dil_test_invntt_max_input = v;
    }
}
#endif /* AMA_TESTING_MODE */

static void dil_invntt_cached(int32_t a[DIL_N], const ama_dispatch_table_t *dt) {
#ifdef AMA_TESTING_MODE
    dil_test_note_invntt_input(a);
#endif
    /* Dispatch to SIMD implementation when available (INVARIANT-4: graceful fallback) */
    if (dt->dilithium_invntt) {
        dt->dilithium_invntt(a, dil_zetas);
        return;
    }
    dil_invntt_scalar(a, dil_zetas);
}

/* ============================================================================
 * POLYNOMIAL OPERATIONS
 * ============================================================================ */

/**
 * Pointwise multiplication in NTT domain with Montgomery reduction.
 * Accepts a cached dispatch table pointer to avoid repeated ama_get_dispatch_table() calls.
 */
static void dil_poly_pointwise_montgomery_cached(dil_poly *c, const dil_poly *a,
                                                  const dil_poly *b,
                                                  const ama_dispatch_table_t *dt) {
    /* Dispatch to SIMD implementation when available (INVARIANT-4: graceful fallback) */
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

/* Cached dispatch table pointer, set once per top-level API call */
static _Thread_local const ama_dispatch_table_t *dil_cached_dt = NULL;

static void dil_ntt(int32_t a[DIL_N]) {
    dil_ntt_cached(a, dil_cached_dt ? dil_cached_dt : ama_get_dispatch_table());
}
static void dil_invntt(int32_t a[DIL_N]) {
    dil_invntt_cached(a, dil_cached_dt ? dil_cached_dt : ama_get_dispatch_table());
}
static void dil_poly_pointwise_montgomery(dil_poly *c, const dil_poly *a,
                                           const dil_poly *b) {
    dil_poly_pointwise_montgomery_cached(c, a, b,
        dil_cached_dt ? dil_cached_dt : ama_get_dispatch_table());
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
 * Decompose: a = a1*alpha + a0 with |a0| <= alpha/2, where alpha = 2*gamma2
 * (FIPS 204 Algorithm 36 `Decompose`).
 *
 * Both branches are the reference implementation's exact fixed-point
 * reciprocal sequences — the divisor differs with gamma2, so the magic
 * constants and the final mask do too.  gamma2 = (q-1)/32 gives a1 in [0, 15]
 * (mask 15); gamma2 = (q-1)/88 gives a1 in [0, 43], where the reference
 * subtracts a borrow instead of masking because 44 is not a power of two.
 */
static int32_t dil_decompose(int32_t *a0, int32_t a, const dil_params *P) {
    int32_t a1;
    a = dil_freeze(a);

    a1 = (a + 127) >> 7;
    if (P->gamma2 == (DIL_Q - 1) / 32) {
        a1 = (a1 * 1025 + (1 << 21)) >> 22;
        a1 &= 15;
    } else {
        a1 = (a1 * 11275 + (1 << 23)) >> 24;
        a1 ^= ((43 - a1) >> 31) & a1;   /* clamp a1 == 44 back to 0 */
    }

    *a0 = a - a1 * 2 * P->gamma2;
    *a0 -= (((DIL_Q - 1) / 2 - *a0) >> 31) & DIL_Q;
    return a1;
}

/**
 * MakeHint: compute hint bit (FIPS 204 Algorithm 39).
 */
static unsigned int dil_make_hint(int32_t a0, int32_t a1, const dil_params *P) {
    if (a0 > P->gamma2 || a0 < -P->gamma2 ||
        (a0 == -P->gamma2 && a1 != 0)) {
        return 1;
    }
    return 0;
}

/**
 * UseHint: recover high bits from hint (FIPS 204 Algorithm 40).
 *
 * The wrap-around is modulo the number of possible high parts: 16 for
 * gamma2 = (q-1)/32, 44 for gamma2 = (q-1)/88.  A mask only works for the
 * former, so the latter is written out explicitly rather than approximated.
 */
static int32_t dil_use_hint(int32_t a, unsigned int hint, const dil_params *P) {
    int32_t a0, a1;

    a1 = dil_decompose(&a0, a, P);

    if (hint == 0) {
        return a1;
    }

    if (P->gamma2 == (DIL_Q - 1) / 32) {
        return (a0 > 0) ? ((a1 + 1) & 15) : ((a1 - 1) & 15);
    }
    if (a0 > 0) {
        return (a1 == 43) ? 0 : a1 + 1;
    }
    return (a1 == 0) ? 43 : a1 - 1;
}

/* ============================================================================
 * POLYNOMIAL PACKING / UNPACKING
 * ============================================================================ */

/**
 * Pack a polynomial with coefficients in [-eta, eta] (FIPS 204 §7.2 SimpleBitPack
 * of eta - c).
 *
 * Two layouts, selected by eta, because the bit width differs and so does the
 * grouping: eta = 2 packs 8 coefficients into 3 octets (3 bits each, 96 octets
 * per polynomial), eta = 4 packs 2 coefficients into 1 octet (4 bits each, 128
 * octets).  ML-DSA-44 and ML-DSA-87 use eta = 2; ML-DSA-65 uses eta = 4.
 */
static void dil_polyeta_pack(uint8_t *r, const dil_poly *a, const dil_params *P) {
    unsigned int i;
    uint8_t t[8];

    if (P->eta == 2) {
        for (i = 0; i < DIL_N / 8; ++i) {
            t[0] = (uint8_t)(P->eta - a->coeffs[8*i + 0]);
            t[1] = (uint8_t)(P->eta - a->coeffs[8*i + 1]);
            t[2] = (uint8_t)(P->eta - a->coeffs[8*i + 2]);
            t[3] = (uint8_t)(P->eta - a->coeffs[8*i + 3]);
            t[4] = (uint8_t)(P->eta - a->coeffs[8*i + 4]);
            t[5] = (uint8_t)(P->eta - a->coeffs[8*i + 5]);
            t[6] = (uint8_t)(P->eta - a->coeffs[8*i + 6]);
            t[7] = (uint8_t)(P->eta - a->coeffs[8*i + 7]);

            r[3*i + 0] = (uint8_t)((t[0] >> 0) | (t[1] << 3) | (t[2] << 6));
            r[3*i + 1] = (uint8_t)((t[2] >> 2) | (t[3] << 1) | (t[4] << 4) | (t[5] << 7));
            r[3*i + 2] = (uint8_t)((t[5] >> 1) | (t[6] << 2) | (t[7] << 5));
        }
        return;
    }

    for (i = 0; i < DIL_N / 2; ++i) {
        t[0] = (uint8_t)(P->eta - a->coeffs[2*i + 0]);
        t[1] = (uint8_t)(P->eta - a->coeffs[2*i + 1]);
        r[i] = (uint8_t)(t[0] | (t[1] << 4));
    }
}

/**
 * Unpack a polynomial with coefficients in [-eta, eta].
 *
 * The packing is not surjective onto its bit width: eta = 2 stores `eta - c` in
 * 3 bits, so the decodable range is [-5, 2] while the legal range is [-2, 2];
 * eta = 4 stores it in 4 bits, decoding to [-11, 4] against a legal [-4, 4].
 * FIPS 204 Algorithm 25 (skDecode) is explicit that a coefficient outside
 * [-eta, eta] makes the secret key invalid and the decode must return
 * "invalid".  Silently accepting one lets a malformed or hostile private key
 * into the signer, where it produces signatures nothing verifies and drives the
 * rejection loop off its calibrated bounds.
 *
 * @return 0 if every coefficient is in [-eta, eta], -1 otherwise.  On -1 the
 *         contents of *r are unspecified and must not be used.
 */
static int dil_polyeta_unpack(dil_poly *r, const uint8_t *a, const dil_params *P) {
    unsigned int i;

    if (P->eta == 2) {
        for (i = 0; i < DIL_N / 8; ++i) {
            r->coeffs[8*i + 0] =  (a[3*i + 0] >> 0) & 7;
            r->coeffs[8*i + 1] =  (a[3*i + 0] >> 3) & 7;
            r->coeffs[8*i + 2] = ((a[3*i + 0] >> 6) | ((int32_t)a[3*i + 1] << 2)) & 7;
            r->coeffs[8*i + 3] =  (a[3*i + 1] >> 1) & 7;
            r->coeffs[8*i + 4] =  (a[3*i + 1] >> 4) & 7;
            r->coeffs[8*i + 5] = ((a[3*i + 1] >> 7) | ((int32_t)a[3*i + 2] << 1)) & 7;
            r->coeffs[8*i + 6] =  (a[3*i + 2] >> 2) & 7;
            r->coeffs[8*i + 7] =  (a[3*i + 2] >> 5) & 7;

            r->coeffs[8*i + 0] = P->eta - r->coeffs[8*i + 0];
            r->coeffs[8*i + 1] = P->eta - r->coeffs[8*i + 1];
            r->coeffs[8*i + 2] = P->eta - r->coeffs[8*i + 2];
            r->coeffs[8*i + 3] = P->eta - r->coeffs[8*i + 3];
            r->coeffs[8*i + 4] = P->eta - r->coeffs[8*i + 4];
            r->coeffs[8*i + 5] = P->eta - r->coeffs[8*i + 5];
            r->coeffs[8*i + 6] = P->eta - r->coeffs[8*i + 6];
            r->coeffs[8*i + 7] = P->eta - r->coeffs[8*i + 7];
        }
    } else {
        for (i = 0; i < DIL_N / 2; ++i) {
            r->coeffs[2*i + 0] = (int32_t)(a[i] & 0x0F);
            r->coeffs[2*i + 1] = (int32_t)(a[i] >> 4);
            r->coeffs[2*i + 0] = P->eta - r->coeffs[2*i + 0];
            r->coeffs[2*i + 1] = P->eta - r->coeffs[2*i + 1];
        }
    }

    /* skDecode's range gate.  Accumulated with a branchless OR rather than an
     * early return: the coefficients of a secret vector are secret, and a loop
     * that exits at the first out-of-range value leaks its index. */
    {
        int32_t bad = 0;
        for (i = 0; i < DIL_N; ++i) {
            bad |= (P->eta - r->coeffs[i]) >> 31;              /* c >  eta */
            bad |= (r->coeffs[i] + (int32_t)P->eta) >> 31;     /* c < -eta */
        }
        return bad ? -1 : 0;
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
 * Pack a z / y polynomial (FIPS 204 §7.2 BitPack of gamma1 - c).
 *
 * gamma1 = 2^17 needs 18 bits per coefficient (4 coefficients -> 9 octets,
 * 576 per polynomial, ML-DSA-44); gamma1 = 2^19 needs 20 bits (2 coefficients
 * -> 5 octets, 640 per polynomial, ML-DSA-65 and ML-DSA-87).
 */
static void dil_polyz_pack(uint8_t *r, const dil_poly *a, const dil_params *P) {
    unsigned int i;
    uint32_t t[4];

    if (P->gamma1 == (1 << 17)) {
        for (i = 0; i < DIL_N / 4; ++i) {
            t[0] = (uint32_t)(P->gamma1 - a->coeffs[4*i + 0]);
            t[1] = (uint32_t)(P->gamma1 - a->coeffs[4*i + 1]);
            t[2] = (uint32_t)(P->gamma1 - a->coeffs[4*i + 2]);
            t[3] = (uint32_t)(P->gamma1 - a->coeffs[4*i + 3]);

            r[9*i + 0] = (uint8_t)(t[0]);
            r[9*i + 1] = (uint8_t)(t[0] >> 8);
            r[9*i + 2] = (uint8_t)((t[0] >> 16) | (t[1] << 2));
            r[9*i + 3] = (uint8_t)(t[1] >> 6);
            r[9*i + 4] = (uint8_t)((t[1] >> 14) | (t[2] << 4));
            r[9*i + 5] = (uint8_t)(t[2] >> 4);
            r[9*i + 6] = (uint8_t)((t[2] >> 12) | (t[3] << 6));
            r[9*i + 7] = (uint8_t)(t[3] >> 2);
            r[9*i + 8] = (uint8_t)(t[3] >> 10);
        }
        return;
    }

    for (i = 0; i < DIL_N / 2; ++i) {
        t[0] = (uint32_t)(P->gamma1 - a->coeffs[2*i + 0]);
        t[1] = (uint32_t)(P->gamma1 - a->coeffs[2*i + 1]);

        r[5*i + 0] = (uint8_t)(t[0]);
        r[5*i + 1] = (uint8_t)(t[0] >> 8);
        r[5*i + 2] = (uint8_t)(t[0] >> 16);
        r[5*i + 2] |= (uint8_t)(t[1] << 4);
        r[5*i + 3] = (uint8_t)(t[1] >> 4);
        r[5*i + 4] = (uint8_t)(t[1] >> 12);
    }
}

/**
 * Unpack a z / y polynomial.
 */
static void dil_polyz_unpack(dil_poly *r, const uint8_t *a, const dil_params *P) {
    unsigned int i;

    if (P->gamma1 == (1 << 17)) {
        for (i = 0; i < DIL_N / 4; ++i) {
            r->coeffs[4*i + 0]  = a[9*i + 0];
            r->coeffs[4*i + 0] |= (int32_t)a[9*i + 1] << 8;
            r->coeffs[4*i + 0] |= (int32_t)a[9*i + 2] << 16;
            r->coeffs[4*i + 0] &= 0x3FFFF;

            r->coeffs[4*i + 1]  = a[9*i + 2] >> 2;
            r->coeffs[4*i + 1] |= (int32_t)a[9*i + 3] << 6;
            r->coeffs[4*i + 1] |= (int32_t)a[9*i + 4] << 14;
            r->coeffs[4*i + 1] &= 0x3FFFF;

            r->coeffs[4*i + 2]  = a[9*i + 4] >> 4;
            r->coeffs[4*i + 2] |= (int32_t)a[9*i + 5] << 4;
            r->coeffs[4*i + 2] |= (int32_t)a[9*i + 6] << 12;
            r->coeffs[4*i + 2] &= 0x3FFFF;

            r->coeffs[4*i + 3]  = a[9*i + 6] >> 6;
            r->coeffs[4*i + 3] |= (int32_t)a[9*i + 7] << 2;
            r->coeffs[4*i + 3] |= (int32_t)a[9*i + 8] << 10;
            r->coeffs[4*i + 3] &= 0x3FFFF;

            r->coeffs[4*i + 0] = P->gamma1 - r->coeffs[4*i + 0];
            r->coeffs[4*i + 1] = P->gamma1 - r->coeffs[4*i + 1];
            r->coeffs[4*i + 2] = P->gamma1 - r->coeffs[4*i + 2];
            r->coeffs[4*i + 3] = P->gamma1 - r->coeffs[4*i + 3];
        }
        return;
    }

    for (i = 0; i < DIL_N / 2; ++i) {
        r->coeffs[2*i + 0]  = a[5*i + 0];
        r->coeffs[2*i + 0] |= (int32_t)a[5*i + 1] << 8;
        r->coeffs[2*i + 0] |= (int32_t)a[5*i + 2] << 16;
        r->coeffs[2*i + 0] &= 0xFFFFF;

        r->coeffs[2*i + 1]  = a[5*i + 2] >> 4;
        r->coeffs[2*i + 1] |= (int32_t)a[5*i + 3] << 4;
        r->coeffs[2*i + 1] |= (int32_t)a[5*i + 4] << 12;
        r->coeffs[2*i + 1] &= 0xFFFFF;

        r->coeffs[2*i + 0] = P->gamma1 - r->coeffs[2*i + 0];
        r->coeffs[2*i + 1] = P->gamma1 - r->coeffs[2*i + 1];
    }
}

/**
 * Pack a w1 polynomial (FIPS 204 §7.2 SimpleBitPack).
 *
 * gamma2 = (q-1)/88 leaves w1 in [0, 43], needing 6 bits (4 coefficients ->
 * 3 octets, 192 per polynomial, ML-DSA-44); gamma2 = (q-1)/32 leaves w1 in
 * [0, 15], needing 4 bits (2 coefficients -> 1 octet, 128 per polynomial).
 */
static void dil_polyw1_pack(uint8_t *r, const dil_poly *a, const dil_params *P) {
    unsigned int i;

    if (P->gamma2 == (DIL_Q - 1) / 88) {
        for (i = 0; i < DIL_N / 4; ++i) {
            r[3*i + 0] = (uint8_t)(a->coeffs[4*i + 0] | (a->coeffs[4*i + 1] << 6));
            r[3*i + 1] = (uint8_t)((a->coeffs[4*i + 1] >> 2) | (a->coeffs[4*i + 2] << 4));
            r[3*i + 2] = (uint8_t)((a->coeffs[4*i + 2] >> 4) | (a->coeffs[4*i + 3] << 2));
        }
        return;
    }

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
                                  uint16_t nonce, const dil_params *P) {
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

        /* eta = 2 rejects nibbles >= 15 and then folds mod 5 (FIPS 204
         * Algorithm 31 RejBoundedPoly); eta = 4 rejects nibbles >= 9.
         * Getting this wrong yields a secret vector with the right *shape*
         * and the wrong *distribution*, which no roundtrip test can see —
         * only the FIPS 204 key-generation KATs catch it. */
        if (P->eta == 2) {
            if (t0 < 15) {
                t0 = (uint8_t)(t0 - (205 * t0 >> 10) * 5);
                a->coeffs[ctr++] = 2 - (int32_t)t0;
            }
            if (t1 < 15 && ctr < DIL_N) {
                t1 = (uint8_t)(t1 - (205 * t1 >> 10) * 5);
                a->coeffs[ctr++] = 2 - (int32_t)t1;
            }
        } else {
            if (t0 < 9) {
                a->coeffs[ctr++] = 4 - (int32_t)t0;
            }
            if (t1 < 9 && ctr < DIL_N) {
                a->coeffs[ctr++] = 4 - (int32_t)t1;
            }
        }
    }
    /* `stream` is the RejBoundedPoly input for s1/s2 and `buf` carries
     * rhoprime; `shake_ctx` still holds the absorbed state.  All three are
     * secret-derived (INVARIANT-12). */
    ama_secure_memzero(stream, sizeof(stream));
    ama_secure_memzero(buf, sizeof(buf));
    ama_secure_memzero(&shake_ctx, sizeof(shake_ctx));
}

/**
 * Rejection-sample one eta polynomial from an already-squeezed
 * SHAKE256 stream window.  Byte-for-byte equivalent to the scalar
 * dil_poly_uniform_eta() rejection loop above.  Returns 1 on
 * successful fill, 0 if the window was exhausted first.
 */
static int dil_rej_eta_from_stream(dil_poly *a,
                                    const uint8_t *stream, size_t stream_len,
                                    const dil_params *P)
{
    unsigned int ctr = 0;
    size_t pos = 0;
    while (ctr < DIL_N && pos < stream_len) {
        uint8_t t0 = stream[pos] & 0x0F;
        uint8_t t1 = stream[pos] >> 4;
        pos++;
        if (P->eta == 2) {
            if (t0 < 15) {
                t0 = (uint8_t)(t0 - (205 * t0 >> 10) * 5);
                a->coeffs[ctr++] = 2 - (int32_t)t0;
            }
            if (t1 < 15 && ctr < DIL_N) {
                t1 = (uint8_t)(t1 - (205 * t1 >> 10) * 5);
                a->coeffs[ctr++] = 2 - (int32_t)t1;
            }
        } else {
            if (t0 < 9) {
                a->coeffs[ctr++] = 4 - (int32_t)t0;
            }
            if (t1 < 9 && ctr < DIL_N) {
                a->coeffs[ctr++] = 4 - (int32_t)t1;
            }
        }
    }
    return (ctr == DIL_N) ? 1 : 0;
}

/**
 * Batched eta sampler: fills `count` contiguous polys with nonces
 * `nonce_base..nonce_base+count-1`, grouped four-at-a-time through
 * ama_shake256_x4_absorb_once / squeezeblocks.  Trailing 0..3 polys
 * use the scalar dil_poly_uniform_eta() fallback.
 *
 * Byte-for-byte identical to calling dil_poly_uniform_eta() once per
 * poly at these nonces; the four lanes' SHAKE256 streams are proven
 * byte-equivalent to four independent scalar streams by
 * tests/c/test_sha3_x4.c.
 *
 * The per-lane fallback (scalar dil_poly_uniform_eta) for an
 * underfilled batched window fires with probability ~1e-5 per poly
 * at 43.75 % rejection over 272 bytes — rare but not vanishing, so
 * preserved for correctness.
 */
static void dil_polyvec_uniform_eta(dil_poly *polys, unsigned int count,
                                     const uint8_t seed[DIL_CRHBYTES],
                                     uint16_t nonce_base, const dil_params *P)
{
    const size_t kInitialBlocks = 2;  /* matches scalar dil_poly_uniform_eta stream[136*2] */
    unsigned int idx = 0;

    while (idx + 4 <= count) {
        uint8_t bufs[4][DIL_CRHBYTES + 2];
        for (int lane = 0; lane < 4; lane++) {
            uint16_t nonce = (uint16_t)(nonce_base + idx + (unsigned int)lane);
            memcpy(bufs[lane], seed, DIL_CRHBYTES);
            bufs[lane][DIL_CRHBYTES]     = (uint8_t)(nonce & 0xFF);
            bufs[lane][DIL_CRHBYTES + 1] = (uint8_t)(nonce >> 8);
        }

        ama_shake256_x4_ctx ctx;
        ama_shake256_x4_absorb_once(&ctx,
            bufs[0], DIL_CRHBYTES + 2,
            bufs[1], DIL_CRHBYTES + 2,
            bufs[2], DIL_CRHBYTES + 2,
            bufs[3], DIL_CRHBYTES + 2);

        uint8_t streams[4][AMA_SHAKE256_X4_RATE * 2];
        ama_shake256_x4_squeezeblocks(&ctx,
            streams[0], streams[1], streams[2], streams[3], kInitialBlocks);

        for (int lane = 0; lane < 4; lane++) {
            int ok = dil_rej_eta_from_stream(&polys[idx + (unsigned int)lane],
                                              streams[lane],
                                              AMA_SHAKE256_X4_RATE * kInitialBlocks, P);
            if (!ok) {
                /* Rare underfill (~1e-5 per poly): fall back to scalar,
                 * which has its own incremental re-squeeze loop. */
                uint16_t nonce = (uint16_t)(nonce_base + idx + (unsigned int)lane);
                dil_poly_uniform_eta(&polys[idx + (unsigned int)lane], seed, nonce, P);
            }
        }

        /* `streams` is the RejBoundedPoly input for s1/s2 and `bufs` carries
         * rhoprime — both secret-derived, neither previously scrubbed
         * (INVARIANT-12).  The x4 sponge state absorbed rhoprime||nonce and is
         * equally recoverable until re-permuted — scrub it in the same class. */
        ama_secure_memzero(streams, sizeof(streams));
        ama_secure_memzero(bufs, sizeof(bufs));
        ama_secure_memzero(&ctx, sizeof(ctx));
        idx += 4;
    }

    /* Trailing 0..3 polys via scalar (e.g., the last 3 polys of the
     * 11-poly keygen sampling pattern: DIL_L + DIL_K = 11 = 4+4+3). */
    while (idx < count) {
        uint16_t nonce = (uint16_t)(nonce_base + idx);
        dil_poly_uniform_eta(&polys[idx], seed, nonce, P);
        idx++;
    }
}

/**
 * Sample polynomial with coefficients in [-(gamma1-1), gamma1] from SHAKE256
 */
static void dil_poly_uniform_gamma1(dil_poly *a, const uint8_t seed[DIL_CRHBYTES],
                                     uint16_t nonce, const dil_params *P) {
    uint8_t buf[DIL_CRHBYTES + 2];
    uint8_t stream[DIL_POLYZ_PACKEDBYTES_MAX];

    memcpy(buf, seed, DIL_CRHBYTES);
    buf[DIL_CRHBYTES] = (uint8_t)(nonce & 0xFF);
    buf[DIL_CRHBYTES + 1] = (uint8_t)(nonce >> 8);

    ama_shake256(buf, DIL_CRHBYTES + 2, stream, P->polyz_packedbytes);
    dil_polyz_unpack(a, stream, P);
    /* `stream` is the packed masking vector y and `buf` carries rhoprime
     * (INVARIANT-12). y is the ephemeral whose disclosure, with the emitted
     * z = y + c*s1 and the public c, hands over s1. */
    ama_secure_memzero(stream, sizeof(stream));
    ama_secure_memzero(buf, sizeof(buf));
}

/**
 * Batched gamma1 sampler for one sign attempt: fills DIL_L polys with
 * nonces (DIL_L * attempt + 0 .. DIL_L - 1) via ama_shake256_x4.  For
 * ML-DSA-65 this is 5 polys = 4 batched + 1 scalar.
 *
 * Per-attempt batching only: rejection retry in the sign loop
 * re-expands all L gamma1 polys from a fresh nonce block, matching
 * the reference AVX2 approach.
 *
 * gamma1 has no rejection loop — dil_polyz_unpack() consumes exactly
 * DIL_POLYZ_PACKEDBYTES = 640 bytes.  Five SHAKE256 rate blocks
 * (5 * 136 = 680 bytes) more than cover it; the tail 40 bytes are
 * discarded exactly as the scalar ama_shake256(..., 640) call does.
 */
static void dil_polyvecl_uniform_gamma1(dil_polyvecl *y,
                                         const uint8_t seed[DIL_CRHBYTES],
                                         uint16_t nonce_base,
                                         const dil_params *P)
{
    /* 5 * 136 = 680 >= 640, the widest polyz_packedbytes (gamma1 = 2^19).
     * ML-DSA-44 needs only 576 and simply discards more of the tail, exactly
     * as the scalar ama_shake256(..., polyz_packedbytes) call does. */
    const size_t kGamma1Blocks = 5;
    unsigned int idx = 0;

    while (idx + 4 <= P->l) {
        uint8_t bufs[4][DIL_CRHBYTES + 2];
        for (int lane = 0; lane < 4; lane++) {
            uint16_t nonce = (uint16_t)(nonce_base + idx + (unsigned int)lane);
            memcpy(bufs[lane], seed, DIL_CRHBYTES);
            bufs[lane][DIL_CRHBYTES]     = (uint8_t)(nonce & 0xFF);
            bufs[lane][DIL_CRHBYTES + 1] = (uint8_t)(nonce >> 8);
        }

        ama_shake256_x4_ctx ctx;
        ama_shake256_x4_absorb_once(&ctx,
            bufs[0], DIL_CRHBYTES + 2,
            bufs[1], DIL_CRHBYTES + 2,
            bufs[2], DIL_CRHBYTES + 2,
            bufs[3], DIL_CRHBYTES + 2);

        uint8_t streams[4][AMA_SHAKE256_X4_RATE * 5];
        ama_shake256_x4_squeezeblocks(&ctx,
            streams[0], streams[1], streams[2], streams[3], kGamma1Blocks);

        for (int lane = 0; lane < 4; lane++) {
            dil_polyz_unpack(&y->vec[idx + (unsigned int)lane], streams[lane], P);
        }

        /* `streams` *is* the packed masking vector y for four lanes, which is
         * the single most sensitive ephemeral in ML-DSA: y together with the
         * emitted z = y + c*s1 and the public c yields c*s1 and hence s1.
         * `dil_sign_internal` scrubs its own copy of y; this one was missed
         * (INVARIANT-12).  The x4 sponge absorbed rhoprime||kappa and is
         * recoverable until re-permuted — scrub it in the same class. */
        ama_secure_memzero(streams, sizeof(streams));
        ama_secure_memzero(bufs, sizeof(bufs));
        ama_secure_memzero(&ctx, sizeof(ctx));
        idx += 4;
    }

    /* Trailing 0..3 polys via scalar (ML-DSA-44: l = 4, none; ML-DSA-65:
     * l = 5, one; ML-DSA-87: l = 7, three). */
    while (idx < P->l) {
        uint16_t nonce = (uint16_t)(nonce_base + idx);
        dil_poly_uniform_gamma1(&y->vec[idx], seed, nonce, P);
        idx++;
    }
}

/**
 * Sample challenge polynomial c with exactly tau nonzero +/-1 coefficients.
 * Uses proper incremental SHAKE256 absorb/squeeze per FIPS 204.
 */
static void dil_poly_challenge(dil_poly *c, const uint8_t *seed, const dil_params *P) {
    uint8_t buf[136];  /* SHAKE256 rate block */
    unsigned int i, b, pos;
    uint64_t signs;
    ama_sha3_ctx shake_ctx;

    /* Absorb seed, finalize, then squeeze first block */
    ama_shake256_inc_init(&shake_ctx);
    ama_shake256_inc_absorb(&shake_ctx, seed, P->ctildebytes);
    ama_shake256_inc_finalize(&shake_ctx);
    ama_shake256_inc_squeeze(&shake_ctx, buf, sizeof(buf));

    /* First 8 bytes encode signs */
    signs = 0;
    for (i = 0; i < 8; ++i) {
        signs |= (uint64_t)buf[i] << (8 * i);
    }

    memset(c->coeffs, 0, sizeof(c->coeffs));  // PUBLIC-DATA: c->coeffs — ML-DSA challenge polynomial (public part of signature), pre-use init filled by rejection sampling

    pos = 8;
    for (i = DIL_N - P->tau; i < DIL_N; ++i) {
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

static void dil_polyvecl_ntt(dil_polyvecl *v, unsigned int l) {
    unsigned int i;
    for (i = 0; i < l; ++i) {
        dil_poly_ntt(&v->vec[i]);
    }
}

static int dil_polyvecl_chknorm(const dil_polyvecl *v, int32_t bound, unsigned int l) {
    unsigned int i;
    for (i = 0; i < l; ++i) {
        if (dil_poly_chknorm(&v->vec[i], bound)) {
            return 1;
        }
    }
    return 0;
}

static void dil_polyveck_ntt(dil_polyveck *v, unsigned int k) {
    unsigned int i;
    for (i = 0; i < k; ++i) {
        dil_poly_ntt(&v->vec[i]);
    }
}

static void dil_polyveck_invntt(dil_polyveck *v, unsigned int k) {
    unsigned int i;
    for (i = 0; i < k; ++i) {
        dil_poly_invntt(&v->vec[i]);
    }
}

static void dil_polyveck_add(dil_polyveck *w, const dil_polyveck *u,
                              const dil_polyveck *v, unsigned int k) {
    unsigned int i;
    for (i = 0; i < k; ++i) {
        dil_poly_add(&w->vec[i], &u->vec[i], &v->vec[i]);
    }
}

static void dil_polyveck_sub(dil_polyveck *w, const dil_polyveck *u,
                              const dil_polyveck *v, unsigned int k) {
    unsigned int i;
    for (i = 0; i < k; ++i) {
        dil_poly_sub(&w->vec[i], &u->vec[i], &v->vec[i]);
    }
}

static void dil_polyveck_reduce(dil_polyveck *v, unsigned int k) {
    unsigned int i;
    for (i = 0; i < k; ++i) {
        dil_poly_reduce(&v->vec[i]);
    }
}

static void dil_polyveck_caddq(dil_polyveck *v, unsigned int k) {
    unsigned int i;
    for (i = 0; i < k; ++i) {
        dil_poly_caddq(&v->vec[i]);
    }
}

static int dil_polyveck_chknorm(const dil_polyveck *v, int32_t bound, unsigned int k) {
    unsigned int i;
    for (i = 0; i < k; ++i) {
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
                                          const dil_poly *mat,
                                          const dil_polyvecl *v,
                                          const dil_params *P) {
    unsigned int i, j;
    dil_poly t;

    for (i = 0; i < P->k; ++i) {
        const dil_poly *row = mat + (size_t)i * P->l;
        dil_poly_pointwise_montgomery(&w->vec[i], &row[0], &v->vec[0]);
        for (j = 1; j < P->l; ++j) {
            dil_poly_pointwise_montgomery(&t, &row[j], &v->vec[j]);
            dil_poly_add(&w->vec[i], &w->vec[i], &t);
        }
    }
}

/**
 * Power2Round on vector
 */
static void dil_polyveck_power2round(dil_polyveck *v1, dil_polyveck *v0,
                                      const dil_polyveck *v, unsigned int k) {
    unsigned int i, j;
    for (i = 0; i < k; ++i) {
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
                                    const dil_polyveck *v, const dil_params *P) {
    unsigned int i, j;
    for (i = 0; i < P->k; ++i) {
        for (j = 0; j < DIL_N; ++j) {
            v1->vec[i].coeffs[j] = dil_decompose(
                &v0->vec[i].coeffs[j], v->vec[i].coeffs[j], P);
        }
    }
}

/**
 * MakeHint on vectors
 */
static unsigned int dil_polyveck_make_hint(uint8_t *hint,
                                            const dil_polyveck *v0,
                                            const dil_polyveck *v1,
                                            const dil_params *P) {
    unsigned int i, j, s = 0;

    for (i = 0; i < P->k; ++i) {
        for (j = 0; j < DIL_N; ++j) {
            if (dil_make_hint(v0->vec[i].coeffs[j], v1->vec[i].coeffs[j], P)) {
                if (s >= P->omega) {
                    return (unsigned int)P->omega + 1;  /* Too many hints */
                }
                hint[s++] = (uint8_t)j;
            }
        }
        hint[P->omega + i] = (uint8_t)s;
    }
    return s;
}

/**
 * UseHint on vector
 */
static void dil_polyveck_use_hint(dil_polyveck *w, const dil_polyveck *v,
                                   const uint8_t *hint, const dil_params *P) {
    unsigned int i, j, k_idx;

    /* Unpack hint bits into per-coefficient flags */
    uint8_t hint_flags[DIL_K_MAX][DIL_N];
    memset(hint_flags, 0, sizeof(hint_flags));  // PUBLIC-DATA: hint_flags — ML-DSA hint flags (public part of signature), pre-use init filled by make_hint
    k_idx = 0;
    for (i = 0; i < P->k; ++i) {
        unsigned int limit = hint[P->omega + i];
        for (; k_idx < limit; ++k_idx) {
            /* hint[k_idx] is uint8_t (0-255), always valid index for DIL_N=256 */
            hint_flags[i][hint[k_idx]] = 1;
        }
    }

    /* Single pass: apply use_hint with correct flag for each coefficient */
    for (i = 0; i < P->k; ++i) {
        for (j = 0; j < DIL_N; ++j) {
            w->vec[i].coeffs[j] = dil_use_hint(v->vec[i].coeffs[j], hint_flags[i][j], P);
        }
    }
}

/* ============================================================================
 * KEY GENERATION, SIGNING, AND VERIFICATION
 * ============================================================================ */

/**
 * Sample one matrix polynomial from an already-squeezed SHAKE128 stream.
 * Returns 1 if the 256 coefficients were fully sampled from the given
 * stream window, 0 if the stream ran out and the caller must re-sample
 * via the scalar path (which re-squeezes as needed).
 *
 * Byte-for-byte equivalent to the first phase of dil_poly_uniform()
 * below when the stream is the initial 5-block squeeze.  When AVX2 is
 * available the dispatch table's vectorised rej_uniform batches 8
 * candidates per 24-byte chunk; otherwise the 3-byte scalar loop runs.
 */
static int dil_rej_uniform_from_stream(dil_poly *a,
                                        const uint8_t *stream, size_t stream_len)
{
    const ama_dispatch_table_t *dt = dil_cached_dt ? dil_cached_dt : ama_get_dispatch_table();
    if (dt->dilithium_rej_uniform) {
        int n = dt->dilithium_rej_uniform(a->coeffs, DIL_N, stream, stream_len);
        return (n == (int)DIL_N) ? 1 : 0;
    }

    /* Scalar fallback: 3 bytes -> 23-bit candidate, accept if < q. */
    unsigned int ctr = 0;
    size_t pos = 0;

    while (ctr < DIL_N && pos + 3 <= stream_len) {
        int32_t t;
        t  = stream[pos++];
        t |= (int32_t)stream[pos++] << 8;
        t |= (int32_t)stream[pos++] << 16;
        t &= 0x7FFFFF;  /* 23 bits */

        if (t < DIL_Q) {
            a->coeffs[ctr++] = t;
        }
    }

    return (ctr == DIL_N) ? 1 : 0;
}

/**
 * Expand matrix A from seed (produces k x l matrix of polynomials in NTT domain).
 *
 * Batched over four lanes via ama_shake128_x4_absorb_once /
 * ama_shake128_x4_squeezeblocks (see src/c/internal/ama_sha3_x4.h).
 * Per-lane coefficients are byte-for-byte identical to the scalar
 * dil_poly_uniform() reference; the batching only changes how the
 * four independent Keccak states are laid out in memory during the
 * permutation.
 *
 * For ML-DSA-65 (DIL_K=6, DIL_L=5) the flat matrix has 30 entries →
 * 7 full groups of 4 + 2 trailing polys sampled via the scalar path.
 *
 * The rejection-sampling fallback (scalar re-squeeze) is a
 * probability-< 10^-30 branch for 256-coefficient samples from 5
 * rate blocks at a 0.1 % rejection rate, but is preserved for
 * correctness across all possible (rho, nonce) inputs.
 */
static void dil_sample_uniform_n(dil_poly *out,
                                  const uint16_t *nonces,
                                  unsigned int count,
                                  const uint8_t rho[DIL_SEEDBYTES]) {
    const size_t kInitialBlocks = 5;   /* matches scalar dil_poly_uniform stream */
    unsigned int flat = 0;

    while (flat + 4 <= count) {
        uint8_t bufs[4][DIL_SEEDBYTES + 2];

        for (int lane = 0; lane < 4; lane++) {
            uint16_t nonce = nonces[flat + (unsigned int)lane];
            memcpy(bufs[lane], rho, DIL_SEEDBYTES);
            bufs[lane][DIL_SEEDBYTES]     = (uint8_t)(nonce & 0xFF);
            bufs[lane][DIL_SEEDBYTES + 1] = (uint8_t)(nonce >> 8);
        }

        ama_shake128_x4_ctx ctx;
        ama_shake128_x4_absorb_once(&ctx,
            bufs[0], DIL_SEEDBYTES + 2,
            bufs[1], DIL_SEEDBYTES + 2,
            bufs[2], DIL_SEEDBYTES + 2,
            bufs[3], DIL_SEEDBYTES + 2);

        uint8_t streams[4][AMA_SHAKE128_X4_RATE * 5];
        ama_shake128_x4_squeezeblocks(&ctx,
            streams[0], streams[1], streams[2], streams[3], kInitialBlocks);

        for (int lane = 0; lane < 4; lane++) {
            unsigned int f = flat + (unsigned int)lane;
            int ok = dil_rej_uniform_from_stream(&out[f],
                                                  streams[lane],
                                                  AMA_SHAKE128_X4_RATE * kInitialBlocks);
            if (!ok) {
                /* Rare fallback (<1e-30 probability for 5 blocks at 0.1% reject):
                 * redo this single poly via the scalar path, which has its own
                 * incremental re-squeeze loop. */
                dil_poly_uniform(&out[f], rho, nonces[f]);
            }
        }

        flat += 4;
    }

    /* Trailing 0..3 polys: use the scalar path directly. */
    while (flat < count) {
        dil_poly_uniform(&out[flat], rho, nonces[flat]);
        flat++;
    }
}

static void dil_expand_matrix(dil_poly *mat,
                               const uint8_t rho[DIL_SEEDBYTES],
                               const dil_params *P) {
    uint16_t nonces[DIL_K_MAX * DIL_L_MAX];
    const unsigned int total = P->k * P->l;
    unsigned int f;

    /* Flat index f maps to A[i][j] with i = f / l, j = f % l — the same layout
     * mat[] itself uses — so sampling in flat order fills the matrix in place.
     * k*l is 16, 30 and 56 for ML-DSA-44/-65/-87, so the trailing scalar tail
     * runs 0, 2 and 0 times respectively. */
    for (f = 0; f < total; ++f) {
        nonces[f] = (uint16_t)(((f / P->l) << 8) + (f % P->l));
    }
    dil_sample_uniform_n(mat, nonces, total, rho);
}

/**
 * Expand a single row of A — the low-stack alternative to dil_expand_matrix.
 *
 * The full matrix is 56 polynomials at ML-DSA-87, which is 57 KB of automatic
 * storage on its own.  A caller that consumes A one row at a time (t = A*s1 is
 * exactly that shape) needs only `l` of them, so it can hold 7 KB instead —
 * see the frame budget documented on dil_pubkey_from_sk.
 *
 * Byte-for-byte identical to the corresponding slice of dil_expand_matrix: the
 * SHAKE-128 stream for A[i][j] depends only on (rho, nonce), and the nonce is
 * (i << 8) + j regardless of how the samples are grouped into x4 batches.
 * tests/c/test_dilithium_matrix_row_equiv.c asserts that against the whole-
 * matrix expansion for every parameter set rather than leaving it as a claim.
 */
static void dil_expand_matrix_row(dil_poly *row,
                                   const uint8_t rho[DIL_SEEDBYTES],
                                   unsigned int i,
                                   const dil_params *P) {
    uint16_t nonces[DIL_L_MAX];
    unsigned int j;

    for (j = 0; j < P->l; ++j) {
        nonces[j] = (uint16_t)((i << 8) + j);
    }
    dil_sample_uniform_n(row, nonces, P->l, rho);
}

/**
 * w = A*v with A expanded one row at a time — the low-stack form of
 * `dil_expand_matrix` + `dil_polyvec_matrix_pointwise`.
 *
 * Every consumer of A in this file uses it strictly row-wise, so materialising
 * all `k*l` polynomials only ever cost stack.  At ML-DSA-87 that is 56 KB of
 * automatic storage in a single frame, and — because `mat` is dimensioned
 * `[DIL_K_MAX * DIL_L_MAX]` rather than at the runtime `k*l` — ML-DSA-44 paid
 * it too, for a matrix a quarter that size.  One row is 7 KB.
 *
 * This matters most on the *verification* path, which is driven by whoever
 * supplies the signature and is the one an embedded or musl-default 128 KB
 * thread stack has to survive.  It is the same argument, and the same fix,
 * that `dil_pubkey_from_sk` already carries; `tests/c/test_pq_parser_stack.c`
 * now measures all of keygen, sign and verify against a stated budget so the
 * figure cannot drift back.
 *
 * Byte-identical to the two-step form: `dil_expand_matrix_row` samples with
 * exactly the nonces `dil_expand_matrix` assigns to the same row, and the
 * accumulation order is unchanged.  `test_nistp.c` pins the row/whole-matrix
 * equality directly.
 */
static void dil_matrix_pointwise_rowwise(dil_polyveck *w,
                                          const uint8_t rho[DIL_SEEDBYTES],
                                          const dil_polyvecl *v,
                                          const dil_params *P) {
    dil_poly row[DIL_L_MAX];
    dil_poly t;
    unsigned int i, j;

    for (i = 0; i < P->k; ++i) {
        dil_expand_matrix_row(row, rho, i, P);
        dil_poly_pointwise_montgomery(&w->vec[i], &row[0], &v->vec[0]);
        for (j = 1; j < P->l; ++j) {
            dil_poly_pointwise_montgomery(&t, &row[j], &v->vec[j]);
            dil_poly_add(&w->vec[i], &w->vec[i], &t);
        }
    }
    /* A is public (it is expanded from the public rho), so this is hygiene
     * rather than a secrecy requirement — but `t` held A[i][j] * v[j] with a
     * secret v on the keygen and signing paths. */
    ama_secure_memzero(&t, sizeof(t));
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
 * ML-DSA key generation (FIPS 204 Algorithm 6 `ML-DSA.KeyGen_internal`).
 *
 * One body for both the random and the deterministic entry points: pass `xi`
 * to reproduce a KAT vector, or NULL to draw the 32-octet seed from the
 * CSPRNG.  The two used to be separate near-identical functions.
 */
static ama_error_t dil_keygen_internal(const dil_params *P,
                                       const uint8_t *xi,
                                       uint8_t *public_key, uint8_t *secret_key) {
    uint8_t seedbuf[2 * DIL_SEEDBYTES + DIL_CRHBYTES];
    uint8_t *rho, *rhoprime, *key;
    dil_polyvecl s1, s1hat;
    dil_polyveck s2, t1, t0, t;
    uint8_t tr[DIL_TRBYTES];
    size_t eta_off, t0_off;
    unsigned int i;
    ama_error_t rc;

    if (!P || !public_key || !secret_key) {
        return AMA_ERROR_INVALID_PARAM;
    }

    /* Cache dispatch table pointer for all NTT calls in this function */
    dil_cached_dt = ama_get_dispatch_table();

    if (xi) {
        memcpy(seedbuf, xi, DIL_SEEDBYTES);
    } else {
        rc = dil_randombytes(seedbuf, DIL_SEEDBYTES);
        if (rc != AMA_SUCCESS) {
            return rc;
        }
    }

    /* (rho, rho', K) = H(xi || k || l) per FIPS 204 Algorithm 6.
     * The trailing (k, l) octets are what domain-separate the parameter sets:
     * without them the same xi would produce related keys at 44/65/87. */
    {
        uint8_t h_input[DIL_SEEDBYTES + 2];
        memcpy(h_input, seedbuf, DIL_SEEDBYTES);
        h_input[DIL_SEEDBYTES] = (uint8_t)P->k;
        h_input[DIL_SEEDBYTES + 1] = (uint8_t)P->l;
        ama_shake256(h_input, DIL_SEEDBYTES + 2, seedbuf, sizeof(seedbuf));
        ama_secure_memzero(h_input, sizeof(h_input));
    }
    rho = seedbuf;
    rhoprime = rho + DIL_SEEDBYTES;
    key = rhoprime + DIL_CRHBYTES;

    /* Sample secret vectors s1 (nonces 0..l-1) and s2 (nonces l..l+k-1) in
     * contiguous batched passes over the shared rhoprime seed. */
    dil_polyvec_uniform_eta(&s1.vec[0], P->l, rhoprime, 0, P);
    dil_polyvec_uniform_eta(&s2.vec[0], P->k, rhoprime, (uint16_t)P->l, P);

    /* Compute t = A*s1 + s2, expanding A one row at a time — A is used exactly
     * once here, so holding all 56 polynomials only ever cost 57 KB of frame. */
    s1hat = s1;
    dil_polyvecl_ntt(&s1hat, P->l);
    dil_matrix_pointwise_rowwise(&t, rho, &s1hat, P);
    /* Reduce BEFORE the inverse NTT, not only after it.
     *
     * `dil_invntt_scalar` and every SIMD counterpart carry an implicit input
     * precondition that the FIPS 204 reference states explicitly for
     * `poly_invntt_tomont` ("input coefficients need to be less than Q in
     * absolute value"), and it is load-bearing rather than decorative.  The
     * inverse transform performs no modular reduction on the additive half of
     * its butterfly: at each of the 8 levels `a[j] = a[j] + a[j + len]` adds
     * two values that were themselves sums at the level below, so the bound on
     * the accumulating position doubles per level and the structural worst case
     * is 2^8 = 256x the input bound.  With |input| < q that is 256q =
     * 2,145,386,752, which fits int32 with 0.1% to spare — the reference's
     * precondition is exactly the margin.
     *
     * The producer here is a sum of l Montgomery products.  Each is in (-q, q)
     * by `dil_montgomery_reduce`'s own bound, and `dil_poly_add` does not
     * reduce, so the accumulator is bounded by l*q — 5q for ML-DSA-65 — and by
     * nothing tighter.  256 * 5q = 10,726,933,760 overflows int32 by ~5x, and
     * signed overflow is undefined behaviour, not a wrap this code could rely
     * on.  Measured over 36,990 invNTT calls from 400 keygen/sign/verify
     * cycles, entry reached 2.415q and intermediates 0.167 * INT32_MAX; the
     * 6x observed headroom is sign cancellation in the sampled data, not a
     * bound, and this project does not rest a memory-safety property on it.
     *
     * `dil_reduce32`'s image was enumerated rather than quoted: exhaustively
     * over a >= 6q-wide band of its input domain it lands in [-4235259,
     * 4235258], so after this call the worst case is 256 * 4235259 =
     * 1,084,226,304 — inside int32 with a 1.98x margin, and provable rather
     * than probabilistic.  (Its image over the whole int32 domain is wider,
     * |t| <= 6282956, which still gives 256 * 6282956 = 1,608,436,736 and a
     * 1.33x margin; the tighter figure is the one that applies here.)
     *
     * The three single-pointwise-product sites in signing need no such call:
     * a lone `dil_montgomery_reduce` output is already in (-q, q), and 256 *
     * (q-1) = 2,145,386,496 is under INT32_MAX by 0.1% — the reference's own
     * tight case, and the reason its precondition is stated in exactly those
     * terms.
     *
     * Mathematically transparent: reduction is the identity modulo q, the
     * inverse NTT is linear over Z_q, and the result is reduced and caddq'd
     * downstream regardless.  Verified byte-identical rather than argued —
     * the SHA3-256 digest over the public and secret keys of 64 distinct
     * seeds is unchanged with and without these three calls, sign/verify
     * round-trips 64/64 either way, and the C suite passes either way.
     *
     * The verify path below already does this (see `dil_polyveck_reduce`
     * immediately before the invNTT in `ama_dilithium_verify`), as do the
     * three single-pointwise-product sites in signing whose inputs are already
     * < q by construction.  These three call sites — keygen, the secret-key
     * consistency check, and w = A*NTT(y) in signing — were the only ones that
     * fed an l-fold accumulator straight in. */
    dil_polyveck_reduce(&t, P->k);
    dil_polyveck_invntt(&t, P->k);
    dil_polyveck_add(&t, &t, &s2, P->k);
    dil_polyveck_reduce(&t, P->k);
    dil_polyveck_caddq(&t, P->k);

    /* Power2Round: t = t1*2^d + t0 */
    dil_polyveck_power2round(&t1, &t0, &t, P->k);

    /* Pack public key: rho || t1 */
    memcpy(public_key, rho, DIL_SEEDBYTES);
    for (i = 0; i < P->k; ++i) {
        dil_polyt1_pack(public_key + DIL_SEEDBYTES + i * DIL_POLYT1_PACKEDBYTES,
                        &t1.vec[i]);
    }

    /* Compute tr = H(pk) */
    ama_shake256(public_key, P->pk_bytes, tr, DIL_TRBYTES);

    /* Pack secret key: rho || key || tr || s1 || s2 || t0 */
    memcpy(secret_key, rho, DIL_SEEDBYTES);
    memcpy(secret_key + DIL_SEEDBYTES, key, DIL_SEEDBYTES);
    memcpy(secret_key + 2 * DIL_SEEDBYTES, tr, DIL_TRBYTES);

    eta_off = 2 * DIL_SEEDBYTES + DIL_TRBYTES;
    for (i = 0; i < P->l; ++i) {
        dil_polyeta_pack(secret_key + eta_off + i * P->polyeta_packedbytes,
                         &s1.vec[i], P);
    }
    for (i = 0; i < P->k; ++i) {
        dil_polyeta_pack(secret_key + eta_off +
                         (P->l + i) * P->polyeta_packedbytes, &s2.vec[i], P);
    }
    t0_off = eta_off + (size_t)(P->l + P->k) * P->polyeta_packedbytes;
    for (i = 0; i < P->k; ++i) {
        dil_polyt0_pack(secret_key + t0_off + i * DIL_POLYT0_PACKEDBYTES,
                        &t0.vec[i]);
    }

    /* Scrub sensitive data */
    ama_secure_memzero(seedbuf, sizeof(seedbuf));
    ama_secure_memzero(&s1, sizeof(s1));
    ama_secure_memzero(&s1hat, sizeof(s1hat));
    ama_secure_memzero(&s2, sizeof(s2));
    ama_secure_memzero(&t0, sizeof(t0));

    return AMA_SUCCESS;
}

/**
 * Recompute the public key from an expanded ML-DSA private key, and check the
 * private key's internal consistency while doing it.
 *
 * The expanded key `rho || K || tr || s1 || s2 || t0` is redundant: rho, s1 and
 * s2 already determine t = A*s1 + s2, and therefore both t0 and the public key
 * rho || t1, and therefore tr = H(rho || t1).  Recomputing that chain is the
 * only way to tell a genuine expanded key from one whose fields disagree.
 *
 * Two things depend on this being available:
 *
 *  - importing a private key that carries only `expandedKey` (RFC 9881 §6).
 *    RFC 9881 §8.2 names exactly the two failures this catches, and Appendix
 *    C.4 ships the vectors: a key whose tr does not match its public key, and
 *    a key whose s1/s2 imply a t whose low bits are not the stored t0.  The
 *    RFC observes that implementations which "neglect to check consistency of
 *    tr and t_0" do not detect either.  Both are exercised in
 *    tests/test_key_formats.py.
 *  - deriving the public half of a key that arrived without one, which is what
 *    lets an expandedKey-only PKCS#8 file produce a usable keypair at all.
 *
 * Every input is a private key the caller already holds, and the answer is
 * pass/fail on data the caller supplied, so this is not on a secret-dependent
 * timing path in the sense the signer is; it is nevertheless written without
 * early exits so that a partial failure does not narrow down which field
 * disagreed.  `sk_bad` and `diff` are accumulated across the whole key and only
 * read at the end for that reason — this function never returns early on a
 * data-dependent condition.
 *
 * Bounded stack — the reason this does not simply reuse the keygen body
 * ---------------------------------------------------------------------
 * Keygen and sign hold the entire k x l matrix A plus five or six length-k
 * vectors in automatic storage.  At ML-DSA-87 that is 56 + ~40 polynomials,
 * about 110 KB, which is fine for those two: they are called by an application
 * that decided to make a key or a signature.
 *
 * This function is different in kind, because it is reachable **from a file
 * parser**.  `ama_cryptography.key_formats.load_pkcs8` calls it on every
 * `expandedKey`-only ML-DSA key it imports, so the frame size is chosen by
 * whoever hands you a key file.  110 KB is more than the default thread stack
 * on musl (128 KB total) once anything else is on it, and more than most
 * embedded RTOS task stacks; a parser that overflows the stack on a
 * well-formed input is a denial of service at best.
 *
 * So the matrix is expanded **one row at a time** and every length-k vector is
 * replaced by a single working polynomial, giving a frame of:
 *
 *     mat_row   l polys   <=  7 * 1024 =  7168 B
 *     s1hat     l polys   <=  7 * 1024 =  7168 B
 *     acc, tmp, t0_i, t1_i   4 * 1024  =  4096 B
 *     pk                                =  2592 B
 *     tr                                =    64 B
 *     ------------------------------------------
 *     total                             ~= 21 KB
 *
 * a little over five times smaller than the keygen shape, and — because every
 * array is sized at DIL_*_MAX rather than at the runtime parameter set — a
 * bound that does not depend on which parameter set the key file names.
 *
 * This is measured, not asserted: `tests/c/test_pq_parser_stack.c` runs the
 * call on a painted, caller-supplied thread stack and reports the real
 * high-water mark over the whole call chain, against the budget stated there
 * (`AMA_PQ_PARSER_STACK_BUDGET`, 48 KB). The pre-rewrite implementation read
 * 123,608 bytes; it now reads **26-29 KB** for this function, identical across
 * all three ML-DSA sets.
 *
 * The range rather than a single figure is deliberate. The exact number moves
 * a few hundred octets with the compiler and the optimisation level — gcc
 * -O2 and clang -O2 disagree by about 1.8 KB on the same source — so a comment
 * quoting one measurement is a comment that goes stale on somebody else's
 * toolchain. The *budget* is the invariant, and the harness is what enforces
 * it; the figure here is context, not a claim to check against.
 *
 * The worst case on that parser path is not this function, though, and the
 * previous version of this comment pointed a reader away from it:
 * `ama_ml_kem_pubkey_from_privkey` is reached from the same `load_pkcs8` and
 * measures 33-35 KB. Anyone optimising the import path should start there.
 *
 * Row-wise expansion costs some SHAKE-128 x4 batching efficiency (a row of 5
 * batches as 4 + 1 rather than joining the next row), which is the right trade
 * on a validation path and is measured in docs/KEY_FORMATS.md.
 * `ama_ml_dsa_test_matrix_row_equiv` (exercised by tests/c/test_nistp.c) pins
 * the byte-identity of the two expansions.
 *
 * @param public_key  May be NULL to check without emitting the public key.
 * @return AMA_SUCCESS if the key is internally consistent;
 *         AMA_ERROR_INVALID_PARAM for a NULL/short argument or an out-of-range
 *         s1/s2 coefficient; AMA_ERROR_VERIFY_FAILED if the recomputed t0 or
 *         tr disagrees with the key's own.
 */
static ama_error_t dil_pubkey_from_sk(const dil_params *P,
                                      const uint8_t *secret_key,
                                      uint8_t *public_key) {
    dil_poly mat_row[DIL_L_MAX];
    dil_polyvecl s1hat;
    dil_poly acc, tmp, t0_i, t1_i;
    uint8_t pk[AMA_ML_DSA_87_PUBLIC_KEY_BYTES];
    uint8_t tr[DIL_TRBYTES];
    const uint8_t *rho, *tr_stored;
    size_t eta_off, t0_off;
    unsigned int i, j;
    int32_t diff = 0;
    int sk_bad = 0;
    ama_error_t rc = AMA_SUCCESS;

    if (!P || !secret_key) {
        return AMA_ERROR_INVALID_PARAM;
    }

    dil_cached_dt = ama_get_dispatch_table();

    rho = secret_key;
    tr_stored = secret_key + 2 * DIL_SEEDBYTES;
    eta_off = 2 * DIL_SEEDBYTES + DIL_TRBYTES;
    t0_off = eta_off + (size_t)(P->l + P->k) * P->polyeta_packedbytes;

    /* s1 is unpacked straight into the NTT working vector: the time-domain
     * copy the keygen body keeps is never read again here. */
    for (i = 0; i < P->l; ++i) {
        sk_bad |= dil_polyeta_unpack(&s1hat.vec[i],
            secret_key + eta_off + i * P->polyeta_packedbytes, P);
    }
    dil_polyvecl_ntt(&s1hat, P->l);

    memcpy(pk, rho, DIL_SEEDBYTES);

    /* t = A*s1 + s2, then Power2Round into (t1, t0) — the keygen chain, taken
     * one row of A at a time so neither A nor any length-k vector is ever
     * materialised in full.  An out-of-range s1/s2 coefficient leaves values in
     * [-11, 4] (see dil_polyeta_unpack), so the arithmetic below stays in range
     * and `sk_bad` can be decided after the loop instead of inside it. */
    for (i = 0; i < P->k; ++i) {
        dil_expand_matrix_row(mat_row, rho, i, P);
        dil_poly_pointwise_montgomery(&acc, &mat_row[0], &s1hat.vec[0]);
        for (j = 1; j < P->l; ++j) {
            dil_poly_pointwise_montgomery(&tmp, &mat_row[j], &s1hat.vec[j]);
            dil_poly_add(&acc, &acc, &tmp);
        }
        /* Same l-fold accumulator, same precondition — see the bound note in
         * the keygen path above.  `acc` is a sum of l Montgomery products and
         * is therefore bounded only by l*q on entry. */
        dil_poly_reduce(&acc);
        dil_poly_invntt(&acc);

        sk_bad |= dil_polyeta_unpack(&tmp,
            secret_key + eta_off + (P->l + i) * P->polyeta_packedbytes, P);
        dil_poly_add(&acc, &acc, &tmp);
        dil_poly_reduce(&acc);
        dil_poly_caddq(&acc);

        for (j = 0; j < DIL_N; ++j) {
            t1_i.coeffs[j] = dil_power2round(&t0_i.coeffs[j], acc.coeffs[j]);
        }
        dil_polyt1_pack(pk + DIL_SEEDBYTES + i * DIL_POLYT1_PACKEDBYTES, &t1_i);

        /* The stored t0 for this row, compared in place rather than collected. */
        dil_polyt0_unpack(&tmp, secret_key + t0_off + i * DIL_POLYT0_PACKEDBYTES);
        for (j = 0; j < DIL_N; ++j) {
            diff |= t0_i.coeffs[j] ^ tmp.coeffs[j];
        }
    }

    ama_shake256(pk, P->pk_bytes, tr, DIL_TRBYTES);

    /* Precedence matches the pre-row-wise implementation: an out-of-range
     * coefficient is a malformed key (INVALID_PARAM), and only a well-formed
     * key can go on to disagree with itself (VERIFY_FAILED). */
    if (sk_bad) {
        rc = AMA_ERROR_INVALID_PARAM;
    } else if (diff != 0 || ama_consttime_memcmp(tr, tr_stored, DIL_TRBYTES) != 0) {
        rc = AMA_ERROR_VERIFY_FAILED;
    } else if (public_key) {
        memcpy(public_key, pk, P->pk_bytes);
    }

    ama_secure_memzero(&s1hat, sizeof(s1hat));
    ama_secure_memzero(&acc, sizeof(acc));
    ama_secure_memzero(&tmp, sizeof(tmp));
    ama_secure_memzero(&t0_i, sizeof(t0_i));
    ama_secure_memzero(&t1_i, sizeof(t1_i));
    ama_secure_memzero(pk, sizeof(pk));
    ama_secure_memzero(tr, sizeof(tr));
    return rc;
}

/**
 * mu = H(tr || prefix || M, 64) — FIPS 204 Algorithm 7 line 6 / Algorithm 8
 * line 7, with the §5.2 context prefix absorbed in place when there is one.
 *
 * Streamed through the incremental SHAKE-256 interface rather than assembled in
 * one buffer. The buffer version allocated `TRBYTES + message_len` on the heap,
 * copied the whole message into it, hashed, scrubbed and freed — so signing an
 * n-byte message needed 2n bytes of live memory and n bytes of extra copying,
 * on a path an attacker can drive with a message of their choosing. Four such
 * allocations existed across this file; none remain.
 *
 * The digest is byte-identical either way: SHAKE-256 absorption is a stream, so
 * absorbing three pieces and absorbing their concatenation are the same
 * operation. tests/test_pqc_param_sets.py and the ACVP corpora pin that
 * against NIST's own vectors in both the plain and context forms.
 */
static ama_error_t dil_hash_mu(const uint8_t *tr,
                               const uint8_t *prefix, size_t prefix_len,
                               const uint8_t *message, size_t message_len,
                               uint8_t mu[DIL_CRHBYTES]) {
    ama_sha3_ctx ctx;
    ama_error_t rc;

    rc = ama_shake256_inc_init(&ctx);
    if (rc == AMA_SUCCESS) {
        rc = ama_shake256_inc_absorb(&ctx, tr, DIL_TRBYTES);
    }
    if (rc == AMA_SUCCESS && prefix_len) {
        rc = ama_shake256_inc_absorb(&ctx, prefix, prefix_len);
    }
    if (rc == AMA_SUCCESS && message_len) {
        rc = ama_shake256_inc_absorb(&ctx, message, message_len);
    }
    if (rc == AMA_SUCCESS) {
        rc = ama_shake256_inc_finalize(&ctx);
    }
    if (rc == AMA_SUCCESS) {
        rc = ama_shake256_inc_squeeze(&ctx, mu, DIL_CRHBYTES);
    }
    /* The absorbed state is a function of the message and of tr; neither is a
     * long-term secret, but the state is scrubbed on every path regardless
     * because a Keccak state left on the stack is the shape a later overread
     * finds. */
    ama_secure_memzero(&ctx, sizeof(ctx));
    return rc;
}

/**
 * The FIPS 204 §5.2 external/pure context prefix,
 * `0x00 || IntegerToBytes(|ctx|, 1) || ctx`.
 *
 * Built into a fixed 257-octet automatic buffer — `ctx_len` is capped at 255 by
 * the specification, so the bound is structural and needs no allocation. This
 * replaces `dil_wrap_ctx`, which malloc'd `2 + ctx_len + message_len` and
 * copied the entire message in order to prepend two octets to it.
 */
#define DIL_CTX_PREFIX_MAX (2u + 255u)

static ama_error_t dil_build_ctx_prefix(const uint8_t *ctx, size_t ctx_len,
                                        uint8_t prefix[DIL_CTX_PREFIX_MAX],
                                        size_t *prefix_len) {
    if (ctx_len > 255) {
        return AMA_ERROR_INVALID_PARAM;
    }
    if (ctx_len && !ctx) {
        return AMA_ERROR_INVALID_PARAM;
    }
    prefix[0] = 0x00;
    prefix[1] = (uint8_t)ctx_len;
    if (ctx_len) {
        memcpy(prefix + 2, ctx, ctx_len);
    }
    *prefix_len = 2 + ctx_len;
    return AMA_SUCCESS;
}

/**
 * The complete signing-intermediate scrub (INVARIANT-12), in one place.
 *
 * It was written out three times — success, rejection-cap bail-out, and (not
 * at all) the `dil_hash_mu` failure return — and the three copies had drifted:
 * **`s2` and `t0` appeared in none of them**, while the comment beside the
 * success copy presented its list as exhaustive.
 *
 * That omission is not a partial leak.  `t0` plus the public `t1` gives
 * `t = t1*2^d + t0` exactly, `rho` regenerates `A`, and then `A*s1 = t - s2`
 * with the leaked `s2` determines `s1` from an over-determined system (k >= l)
 * solved independently at each NTT coordinate.  s2 + t0 + the public key *is*
 * an ML-DSA private key, left in the frame of a function whose contract says
 * it clears everything derivable from the secret.
 *
 * One macro, three call sites, and a new intermediate has exactly one list to
 * be added to.
 */
#define DIL_SIGN_SCRUB()                                                       \
    do {                                                                       \
        ama_secure_memzero(&s1, sizeof(s1));                                   \
        ama_secure_memzero(&s2, sizeof(s2));                                   \
        ama_secure_memzero(&t0, sizeof(t0));                                   \
        ama_secure_memzero(&y, sizeof(y));                                     \
        ama_secure_memzero(&yhat, sizeof(yhat));                               \
        ama_secure_memzero(&cs2, sizeof(cs2));                                 \
        ama_secure_memzero(&ct0, sizeof(ct0));                                 \
        ama_secure_memzero(&cp, sizeof(cp));                                   \
        ama_secure_memzero(&w0, sizeof(w0));                                   \
        ama_secure_memzero(&w1, sizeof(w1));                                   \
        ama_secure_memzero(mu, sizeof(mu));                                    \
        ama_secure_memzero(rhoprime, sizeof(rhoprime));                        \
        ama_secure_memzero(hashbuf, sizeof(hashbuf));                          \
    } while (0)

static ama_error_t dil_sign_internal(const dil_params *P,
                                     uint8_t *signature, size_t *signature_len,
                                     const uint8_t *prefix, size_t prefix_len,
                                     const uint8_t *message, size_t message_len,
                                     const uint8_t *secret_key) {
    uint8_t *rho, *key, *tr;
    uint8_t mu[DIL_CRHBYTES];
    uint8_t rhoprime[DIL_CRHBYTES];
    /* FIPS 204 §6.2 Algorithm 7 line 3 layout: K (32) || rnd (32) || mu (64) */
    uint8_t hashbuf[DIL_SEEDBYTES + DIL_RNDBYTES + DIL_CRHBYTES];
    dil_poly mat[DIL_K_MAX * DIL_L_MAX];
    dil_polyvecl s1, y, z;
    /* `yhat` is declared here rather than beside its first use so that its
     * stack slot is in scope at *every* exit — including the `dil_hash_mu`
     * failure return, which precedes the rejection loop. */
    dil_polyvecl yhat;
    dil_polyveck s2, t0, w1, w0, ct0, cs2;
    dil_poly cp;
    uint8_t hint[DIL_OMEGA_MAX + DIL_K_MAX];
    size_t eta_off, t0_off;
    unsigned int n, i;
    uint16_t nonce = 0;
    int reject;

    memset(hint, 0, sizeof(hint));  // PUBLIC-DATA: hint — ML-DSA hint buffer (public part of signature), pre-use init filled by make_hint

    if (!P || !signature || !signature_len || !message || !secret_key) {
        return AMA_ERROR_INVALID_PARAM;
    }

    /* Cache dispatch table pointer for all NTT calls in this function */
    dil_cached_dt = ama_get_dispatch_table();

    if (*signature_len < P->sig_bytes) {
        *signature_len = P->sig_bytes;
        return AMA_ERROR_INVALID_PARAM;
    }

    /* Unpack secret key */
    rho = (uint8_t *)secret_key;
    key = (uint8_t *)secret_key + DIL_SEEDBYTES;
    tr = (uint8_t *)secret_key + 2 * DIL_SEEDBYTES;

    eta_off = 2 * DIL_SEEDBYTES + DIL_TRBYTES;
    t0_off = eta_off + (size_t)(P->l + P->k) * P->polyeta_packedbytes;
    {
        /* skDecode (FIPS 204 Algorithm 25) rejects a secret vector with a
         * coefficient outside [-eta, eta].  Accumulated across the whole key
         * before branching so the refusal does not reveal which polynomial
         * carried the offending coefficient. */
        int sk_bad = 0;
        for (i = 0; i < P->l; ++i) {
            sk_bad |= dil_polyeta_unpack(&s1.vec[i],
                secret_key + eta_off + i * P->polyeta_packedbytes, P);
        }
        for (i = 0; i < P->k; ++i) {
            sk_bad |= dil_polyeta_unpack(&s2.vec[i],
                secret_key + eta_off + (P->l + i) * P->polyeta_packedbytes, P);
        }
        if (sk_bad) {
            ama_secure_memzero(&s1, sizeof(s1));
            ama_secure_memzero(&s2, sizeof(s2));
            return AMA_ERROR_INVALID_PARAM;
        }
    }
    for (i = 0; i < P->k; ++i) {
        dil_polyt0_unpack(&t0.vec[i],
            secret_key + t0_off + i * DIL_POLYT0_PACKEDBYTES);
    }

    /* Expand A from rho */
    dil_expand_matrix(mat, rho, P);

    /* Transform s1, s2 and t0 to the NTT domain, IN PLACE.
     *
     * The time-domain copies are dead the moment their transform exists —
     * nothing below this point reads them — so the three separate `*hat`
     * vectors were 23.5 KB of frame holding a second copy of the secret key
     * that also had to be scrubbed.  From here on `s1`, `s2` and `t0` hold
     * NTT-domain values. */
    dil_polyvecl_ntt(&s1, P->l);
    dil_polyveck_ntt(&s2, P->k);
    dil_polyveck_ntt(&t0, P->k);

    /* mu = H(tr || prefix || M) — streamed, no allocation. */
    {
        ama_error_t mu_rc = dil_hash_mu(tr, prefix, prefix_len,
                                        message, message_len, mu);
        if (mu_rc != AMA_SUCCESS) {
            /* s1, s2 and t0 are already unpacked at this point, so this
             * return had to scrub too — it was the one signing exit that
             * scrubbed nothing at all. */
            DIL_SIGN_SCRUB();
            return mu_rc;
        }
    }

    /*
     * FIPS 204 Section 6.2 Algorithm 7 (ML-DSA.Sign_internal) line 3:
     *   rho' = H(K || rnd || mu, 64)
     *
     * This entry point is the FIPS 204 *deterministic* signer - the variant
     * exercised by every NIST ACVP-Server "deterministic" sigGen group - so
     * we pin rnd = 0^256 here. Pre-3.1.0 AMA omitted the rnd field entirely,
     * which silently diverged from the FIPS 204 spec and from every NIST
     * deterministic ACVP vector. Round-trip self-tests still passed because
     * verify recomputes mu from the signature's c-tilde head, so the defect
     * could only be caught by byte-exact ACVP-Server replay; this fix lands
     * together with the FIPS 204/205 KAT pin.
     */
    memcpy(hashbuf, key, DIL_SEEDBYTES);
    memset(hashbuf + DIL_SEEDBYTES, 0, DIL_RNDBYTES);  /* rnd = 0^256 (deterministic) */  // PUBLIC-DATA: rnd portion — FIPS 204 deterministic-signer fills rnd field with zeros (public spec'd constant)
    memcpy(hashbuf + DIL_SEEDBYTES + DIL_RNDBYTES, mu, DIL_CRHBYTES);
    ama_shake256(hashbuf, DIL_SEEDBYTES + DIL_RNDBYTES + DIL_CRHBYTES,
                 rhoprime, DIL_CRHBYTES);

    /* Rejection sampling loop
     * Expected iterations ~4-5 across the parameter sets. Cap at 1000 to prevent
     * pathological hangs (probability of reaching cap < 2^{-500}). */
    reject = 1;
    unsigned int attempts = 0;
    const unsigned int MAX_SIGN_ATTEMPTS = 1000;
    /* `yhat` is hoisted to the top of the function (see its declaration) so
     * its stack slot is visible at every exit and can be scrubbed.  An in-loop
     * declaration left the last iteration's NTT(y) on the stack with no
     * subsequent overwrite — recoverable from a stack snapshot. */
    while (reject) {
        if (++attempts > MAX_SIGN_ATTEMPTS) {
            DIL_SIGN_SCRUB();
            return AMA_ERROR_CRYPTO;
        }
        /* Sample y from [-gamma1+1, gamma1] — per-attempt batched through
         * SHAKE256-x4 (DIL_L = 5 = 4 batched + 1 scalar).  Rejection
         * retry re-enters with a fresh nonce block, matching the
         * reference AVX2 approach (no cross-attempt amortization). */
        dil_polyvecl_uniform_gamma1(&y, rhoprime, (uint16_t)(P->l * nonce), P);
        nonce++;

        /* Compute w = A*NTT(y).  yhat is hoisted (see above) so its
         * stack slot persists past the loop for scrub. */
        yhat = y;
        dil_polyvecl_ntt(&yhat, P->l);
        dil_polyvec_matrix_pointwise(&w1, mat, &yhat, P);
        /* Same l-fold accumulator, same precondition — see the bound note in
         * the keygen path above.  This one runs once per rejection-sampling
         * attempt, so it is the hottest of the three. */
        dil_polyveck_reduce(&w1, P->k);
        dil_polyveck_invntt(&w1, P->k);
        dil_polyveck_reduce(&w1, P->k);
        dil_polyveck_caddq(&w1, P->k);

        /* Decompose w into w1 and w0 */
        dil_polyveck_decompose(&w1, &w0, &w1, P);

        /* Pack w1 and compute challenge hash */
        {
            uint8_t w1_packed[DIL_K_MAX * DIL_POLYW1_PACKEDBYTES_MAX];
            uint8_t challenge_seed[DIL_CRHBYTES +
                                   DIL_K_MAX * DIL_POLYW1_PACKEDBYTES_MAX];
            const size_t w1_len = (size_t)P->k * P->polyw1_packedbytes;

            for (i = 0; i < P->k; ++i) {
                dil_polyw1_pack(w1_packed + i * P->polyw1_packedbytes, &w1.vec[i], P);
            }

            memcpy(challenge_seed, mu, DIL_CRHBYTES);
            memcpy(challenge_seed + DIL_CRHBYTES, w1_packed, w1_len);
            ama_shake256(challenge_seed, DIL_CRHBYTES + w1_len,
                        signature, P->ctildebytes);
        }

        /* Compute challenge polynomial c from c_tilde */
        dil_poly_challenge(&cp, signature, P);
        dil_poly_ntt(&cp);

        /* Compute z = y + c*s1 */
        for (i = 0; i < P->l; ++i) {
            dil_poly_pointwise_montgomery(&z.vec[i], &cp, &s1.vec[i]);
            dil_poly_invntt(&z.vec[i]);
            dil_poly_add(&z.vec[i], &z.vec[i], &y.vec[i]);
            dil_poly_reduce(&z.vec[i]);
        }

        /* Check ||z||_inf < gamma1 - beta */
        if (dil_polyvecl_chknorm(&z, P->gamma1 - P->beta, P->l))
            continue;

        /* Compute w0 - c*s2 */
        for (i = 0; i < P->k; ++i) {
            dil_poly_pointwise_montgomery(&cs2.vec[i], &cp, &s2.vec[i]);
            dil_poly_invntt(&cs2.vec[i]);
        }
        dil_polyveck_sub(&w0, &w0, &cs2, P->k);
        dil_polyveck_reduce(&w0, P->k);

        /* Check ||w0 - cs2||_inf < gamma2 - beta */
        if (dil_polyveck_chknorm(&w0, P->gamma2 - P->beta, P->k))
            continue;

        /* Compute c*t0 */
        for (i = 0; i < P->k; ++i) {
            dil_poly_pointwise_montgomery(&ct0.vec[i], &cp, &t0.vec[i]);
            dil_poly_invntt(&ct0.vec[i]);
            dil_poly_reduce(&ct0.vec[i]);
        }

        /* Check ||ct0||_inf < gamma2 */
        if (dil_polyveck_chknorm(&ct0, P->gamma2, P->k))
            continue;

        /* Compute hints: make_hint(w0-cs2+ct0, w1) per FIPS 204 */
        memset(hint, 0, sizeof(hint));  // PUBLIC-DATA: hint — ML-DSA hint buffer (public part of signature), pre-use init
        dil_polyveck_add(&w0, &w0, &ct0, P->k);
        n = dil_polyveck_make_hint(hint, &w0, &w1, P);
        if (n > P->omega)
            continue;

        /* All checks passed */
        reject = 0;
    }

    /* Pack signature: c_tilde || z (l * polyz_packed) || hints (omega + k) */
    /* c_tilde already written at signature[0..47] */
    for (i = 0; i < P->l; ++i) {
        dil_polyz_pack(signature + P->ctildebytes + i * P->polyz_packedbytes,
                       &z.vec[i], P);
    }

    /* Pack hints */
    memcpy(signature + P->ctildebytes + (size_t)P->l * P->polyz_packedbytes,
           hint, P->omega + P->k);

    *signature_len = P->sig_bytes;

    /* Scrub sensitive data.
     *
     * INVARIANT-12: every signing intermediate is scrubbed on every exit —
     * see DIL_SIGN_SCRUB above for the inventory and for what the previous
     * enumeration left behind. */
    DIL_SIGN_SCRUB();

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
static ama_error_t dil_verify_internal(const dil_params *P,
                                       const uint8_t *prefix, size_t prefix_len,
                                       const uint8_t *message, size_t message_len,
                                       const uint8_t *signature, size_t signature_len,
                                       const uint8_t *public_key) {
    uint8_t rho[DIL_SEEDBYTES];
    uint8_t mu[DIL_CRHBYTES];
    uint8_t c_tilde[DIL_CTILDEBYTES_MAX];
    uint8_t c_tilde2[DIL_CTILDEBYTES_MAX];
    dil_polyvecl z;
    dil_polyveck t1, w1prime, h_vec;
    dil_poly cp;
    uint8_t hint[DIL_OMEGA_MAX + DIL_K_MAX];
    uint8_t tr[DIL_TRBYTES];
    unsigned int i;

    if (!P || !message || !signature || !public_key) {
        return AMA_ERROR_INVALID_PARAM;
    }

    /* Cache dispatch table pointer for all NTT calls in this function */
    dil_cached_dt = ama_get_dispatch_table();

    if (signature_len != P->sig_bytes) {
        return AMA_ERROR_VERIFY_FAILED;
    }

    /* Unpack public key: rho || t1 */
    memcpy(rho, public_key, DIL_SEEDBYTES);
    for (i = 0; i < P->k; ++i) {
        dil_polyt1_unpack(&t1.vec[i],
            public_key + DIL_SEEDBYTES + i * DIL_POLYT1_PACKEDBYTES);
    }

    /* Unpack signature: c_tilde || z || hints */
    memcpy(c_tilde, signature, P->ctildebytes);
    for (i = 0; i < P->l; ++i) {
        dil_polyz_unpack(&z.vec[i],
            signature + P->ctildebytes + i * P->polyz_packedbytes, P);
    }
    memcpy(hint, signature + P->ctildebytes + (size_t)P->l * P->polyz_packedbytes,
           P->omega + P->k);

    /* Verify hint encoding — FIPS 204 Algorithm 21 (HintBitUnpack).
     *
     * Three rules, and the third one was missing.
     *
     *   1. The cumulative counts `y[omega + i]` are non-decreasing and never
     *      exceed omega.
     *   2. Every octet past the last count is zero, so the unused tail of the
     *      hint array carries no second encoding.
     *   3. **Within each polynomial's slice the indices are strictly
     *      increasing.**  Algorithm 21 states it as `if y[j-1] >= y[j] then
     *      return falsum`, and the reference implementation notes beside it
     *      that the ordering exists "for strong unforgeability".
     *
     * Rule 3 is not a formality.  `dil_polyveck_use_hint` sets
     * `hint_flags[i][y[j]] = 1` for each index in the slice, so the *set* of
     * indices determines w1 and the *order* does not.  Without the check, any
     * permutation of a polynomial's indices is a distinct byte string that
     * verifies for the same message under the same key — signature
     * malleability, and a break of SUF-CMA rather than of EUF-CMA.  With eight
     * indices in one polynomial, as a randomly sampled ML-DSA-65 signature
     * routinely has, that is 8! = 40,320 valid encodings of one signature.
     * Reproduced on the first randomly generated signature; pinned by
     * `test_a_permuted_hint_is_refused` in tests/test_pqc_param_sets.py.
     *
     * Every input here is public (it is a signature), so the loop's data
     * dependence is not a timing concern — the same posture as the rest of
     * verification. */
    {
        unsigned int prev = 0;
        for (i = 0; i < P->k; ++i) {
            unsigned int limit = hint[P->omega + i];
            unsigned int j;
            if (limit < prev || limit > P->omega) {
                return AMA_ERROR_VERIFY_FAILED;
            }
            for (j = prev + 1; j < limit; ++j) {
                if (hint[j] <= hint[j - 1]) {
                    return AMA_ERROR_VERIFY_FAILED;
                }
            }
            prev = limit;
        }
        for (i = prev; i < P->omega; ++i) {
            if (hint[i] != 0) {
                return AMA_ERROR_VERIFY_FAILED;
            }
        }
    }

    /* Check ||z||_inf < gamma1 - beta */
    if (dil_polyvecl_chknorm(&z, P->gamma1 - P->beta, P->l)) {
        return AMA_ERROR_VERIFY_FAILED;
    }

    /* Compute tr = H(pk) */
    ama_shake256(public_key, P->pk_bytes, tr, DIL_TRBYTES);

    /* mu = H(tr || prefix || M) — streamed, no allocation. */
    {
        ama_error_t mu_rc = dil_hash_mu(tr, prefix, prefix_len,
                                        message, message_len, mu);
        if (mu_rc != AMA_SUCCESS) {
            return mu_rc;
        }
    }

    /* Compute challenge polynomial c from c_tilde */
    dil_poly_challenge(&cp, c_tilde, P);
    dil_poly_ntt(&cp);

    /* Compute w1' = A*NTT(z) - c*NTT(t1*2^d) in NTT domain.
     *
     * A is expanded one row at a time.  Verification is the most
     * attacker-reachable entry point in the module — anyone who can hand you a
     * signature reaches it — so it is the one that has to survive a small
     * thread stack.  Holding the whole 56-polynomial matrix put the frame at
     * ~101 KB, on the wrong side of musl's 128 KB default once anything else
     * was below it. */
    dil_polyvecl zhat = z;
    dil_polyvecl_ntt(&zhat, P->l);
    dil_matrix_pointwise_rowwise(&w1prime, rho, &zhat, P);

    /* Compute c * t1 * 2^d */
    for (i = 0; i < P->k; ++i) {
        unsigned int j;
        for (j = 0; j < DIL_N; ++j) {
            t1.vec[i].coeffs[j] <<= DIL_D;
        }
        dil_poly_ntt(&t1.vec[i]);
        dil_poly_pointwise_montgomery(&h_vec.vec[i], &cp, &t1.vec[i]);
    }

    /* w1' = Az - ct1*2^d */
    dil_polyveck_sub(&w1prime, &w1prime, &h_vec, P->k);
    dil_polyveck_reduce(&w1prime, P->k);
    dil_polyveck_invntt(&w1prime, P->k);
    dil_polyveck_reduce(&w1prime, P->k);
    dil_polyveck_caddq(&w1prime, P->k);

    /* Use hints to recover w1 */
    dil_polyveck_use_hint(&w1prime, &w1prime, hint, P);

    /* Recompute c_tilde' = H(mu || w1').
     *
     * Both halves are bounded by the parameter table — 64 octets of mu and at
     * most DIL_K_MAX * DIL_POLYW1_PACKEDBYTES_MAX (1536) of packed w1 — so this
     * never needed the heap at all. It malloc'd anyway, on a path reachable by
     * anyone who can present a signature, which turned an allocator failure
     * into a verification failure of a valid signature. */
    {
        uint8_t challenge_input[DIL_CRHBYTES +
                                DIL_K_MAX * DIL_POLYW1_PACKEDBYTES_MAX];
        const size_t w1_len = (size_t)P->k * P->polyw1_packedbytes;
        const size_t challenge_len = DIL_CRHBYTES + w1_len;

        memcpy(challenge_input, mu, DIL_CRHBYTES);
        for (i = 0; i < P->k; ++i) {
            dil_polyw1_pack(challenge_input + DIL_CRHBYTES +
                                i * P->polyw1_packedbytes,
                            &w1prime.vec[i], P);
        }
        ama_shake256(challenge_input, challenge_len, c_tilde2, P->ctildebytes);
        ama_secure_memzero(challenge_input, sizeof(challenge_input));
    }

    /* Verify c_tilde == c_tilde2 (constant-time comparison) */
    {
        int match = ama_consttime_memcmp(c_tilde, c_tilde2, P->ctildebytes);

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

/* ============================================================================
 * PUBLIC API — PARAMETER-DRIVEN (ML-DSA-44 / -65 / -87)
 *
 * The legacy `ama_dilithium_*` entry points below are preserved as thin
 * wrappers pinned to ML-DSA-65.  They are the ABI every existing caller and
 * every existing test uses, and pinning them keeps that behaviour bit-exact:
 * adding parameter sets must not change what an existing call does.
 * ============================================================================ */

AMA_API size_t ama_ml_dsa_public_key_bytes(ama_ml_dsa_param_set_t ps) {
    const dil_params *P = dil_params_for(ps);
    return P ? P->pk_bytes : 0u;
}

AMA_API size_t ama_ml_dsa_secret_key_bytes(ama_ml_dsa_param_set_t ps) {
    const dil_params *P = dil_params_for(ps);
    return P ? P->sk_bytes : 0u;
}

AMA_API size_t ama_ml_dsa_signature_bytes(ama_ml_dsa_param_set_t ps) {
    const dil_params *P = dil_params_for(ps);
    return P ? P->sig_bytes : 0u;
}

AMA_API const char *ama_ml_dsa_param_set_name(ama_ml_dsa_param_set_t ps) {
    const dil_params *P = dil_params_for(ps);
    return P ? P->name : NULL;
}

AMA_API ama_error_t ama_ml_dsa_keypair(ama_ml_dsa_param_set_t ps,
                                       uint8_t *public_key, uint8_t *secret_key) {
    const dil_params *P = dil_params_for(ps);
    if (!P) return AMA_ERROR_INVALID_PARAM;
    return dil_keygen_internal(P, NULL, public_key, secret_key);
}

AMA_API ama_error_t ama_ml_dsa_keypair_from_seed(ama_ml_dsa_param_set_t ps,
                                                 const uint8_t xi[32],
                                                 uint8_t *public_key,
                                                 uint8_t *secret_key) {
    const dil_params *P = dil_params_for(ps);
    if (!P || !xi) return AMA_ERROR_INVALID_PARAM;
    return dil_keygen_internal(P, xi, public_key, secret_key);
}

AMA_API ama_error_t ama_ml_dsa_pubkey_from_privkey(ama_ml_dsa_param_set_t ps,
                                                   const uint8_t *secret_key,
                                                   uint8_t *public_key) {
    const dil_params *P = dil_params_for(ps);
    if (!P || !secret_key || !public_key) return AMA_ERROR_INVALID_PARAM;
    return dil_pubkey_from_sk(P, secret_key, public_key);
}

AMA_API ama_error_t ama_ml_dsa_privkey_check(ama_ml_dsa_param_set_t ps,
                                             const uint8_t *secret_key) {
    const dil_params *P = dil_params_for(ps);
    if (!P || !secret_key) return AMA_ERROR_INVALID_PARAM;
    return dil_pubkey_from_sk(P, secret_key, NULL);
}

AMA_API ama_error_t ama_ml_dsa_sign(ama_ml_dsa_param_set_t ps,
                                    uint8_t *signature, size_t *signature_len,
                                    const uint8_t *message, size_t message_len,
                                    const uint8_t *secret_key) {
    const dil_params *P = dil_params_for(ps);
    if (!P) return AMA_ERROR_INVALID_PARAM;
    return dil_sign_internal(P, signature, signature_len, NULL, 0,
                             message, message_len, secret_key);
}

AMA_API ama_error_t ama_ml_dsa_verify(ama_ml_dsa_param_set_t ps,
                                      const uint8_t *message, size_t message_len,
                                      const uint8_t *signature, size_t signature_len,
                                      const uint8_t *public_key) {
    const dil_params *P = dil_params_for(ps);
    if (!P) return AMA_ERROR_INVALID_PARAM;
    return dil_verify_internal(P, NULL, 0, message, message_len,
                               signature, signature_len, public_key);
}

AMA_API ama_error_t ama_ml_dsa_sign_ctx(ama_ml_dsa_param_set_t ps,
                                        uint8_t *signature, size_t *signature_len,
                                        const uint8_t *message, size_t message_len,
                                        const uint8_t *ctx, size_t ctx_len,
                                        const uint8_t *secret_key) {
    const dil_params *P = dil_params_for(ps);
    uint8_t prefix[DIL_CTX_PREFIX_MAX];
    size_t prefix_len = 0;
    ama_error_t rc;

    if (!P || !message || !signature || !signature_len || !secret_key) {
        return AMA_ERROR_INVALID_PARAM;
    }
    rc = dil_build_ctx_prefix(ctx, ctx_len, prefix, &prefix_len);
    if (rc != AMA_SUCCESS) {
        return rc;
    }
    rc = dil_sign_internal(P, signature, signature_len, prefix, prefix_len,
                           message, message_len, secret_key);
    ama_secure_memzero(prefix, sizeof(prefix));
    return rc;
}

AMA_API ama_error_t ama_ml_dsa_verify_ctx(ama_ml_dsa_param_set_t ps,
                                          const uint8_t *message, size_t message_len,
                                          const uint8_t *ctx, size_t ctx_len,
                                          const uint8_t *signature, size_t signature_len,
                                          const uint8_t *public_key) {
    const dil_params *P = dil_params_for(ps);
    uint8_t prefix[DIL_CTX_PREFIX_MAX];
    size_t prefix_len = 0;
    ama_error_t rc;

    if (!P || !message || !signature || !public_key) {
        return AMA_ERROR_INVALID_PARAM;
    }
    rc = dil_build_ctx_prefix(ctx, ctx_len, prefix, &prefix_len);
    if (rc != AMA_SUCCESS) {
        return rc;
    }
    rc = dil_verify_internal(P, prefix, prefix_len, message, message_len,
                             signature, signature_len, public_key);
    ama_secure_memzero(prefix, sizeof(prefix));
    return rc;
}

/* ============================================================================
 * LEGACY ML-DSA-65 ENTRY POINTS (unchanged ABI)
 * ============================================================================ */

/**
 * ML-DSA-65 key pair generation (FIPS 204 Algorithm 1).
 *
 * @param public_key Output buffer for public key (1952 bytes)
 * @param secret_key Output buffer for secret key (4032 bytes)
 * @return AMA_SUCCESS or error code
 */
AMA_API ama_error_t ama_dilithium_keypair(uint8_t *public_key, uint8_t *secret_key) {
    return ama_ml_dsa_keypair(AMA_ML_DSA_65, public_key, secret_key);
}

/**
 * Deterministic ML-DSA-65 keypair from a 32-byte seed (KAT testing).
 */
AMA_API ama_error_t ama_dilithium_keypair_from_seed(const uint8_t xi[32],
                                                    uint8_t *public_key,
                                                    uint8_t *secret_key) {
    return ama_ml_dsa_keypair_from_seed(AMA_ML_DSA_65, xi, public_key, secret_key);
}

AMA_API ama_error_t ama_dilithium_sign(uint8_t *signature, size_t *signature_len,
                                       const uint8_t *message, size_t message_len,
                                       const uint8_t *secret_key) {
    return ama_ml_dsa_sign(AMA_ML_DSA_65, signature, signature_len,
                           message, message_len, secret_key);
}

AMA_API ama_error_t ama_dilithium_verify(const uint8_t *message, size_t message_len,
                                         const uint8_t *signature, size_t signature_len,
                                         const uint8_t *public_key) {
    return ama_ml_dsa_verify(AMA_ML_DSA_65, message, message_len,
                             signature, signature_len, public_key);
}

#ifdef AMA_TESTING_MODE
/**
 * Test-only: re-derive every length in DIL_PARAM_SETS from the primitive
 * parameters and assert the table agrees.
 *
 * A mistyped row is otherwise a wrong-but-self-consistent parameter set: it
 * signs, it verifies against itself, and it interoperates with nothing.  This
 * turns that into a named test failure.  Returns 0 on success, or 1 + the
 * index of the first bad row.
 */
int ama_ml_dsa_test_params_selfcheck(void);
int ama_ml_dsa_test_params_selfcheck(void) {
    unsigned idx;
    for (idx = 0; idx < 3; idx++) {
        const dil_params *P = &DIL_PARAM_SETS[idx];
        size_t polyz = (P->gamma1 == (1 << 17)) ? 576u : 640u;
        size_t polyw1 = (P->gamma2 == (DIL_Q - 1) / 88) ? 192u : 128u;
        size_t polyeta = (P->eta == 2) ? 96u : 128u;

        if (P->k > DIL_K_MAX || P->l > DIL_L_MAX) return (int)(1 + idx);
        if (P->omega > DIL_OMEGA_MAX) return (int)(1 + idx);
        if (P->ctildebytes > DIL_CTILDEBYTES_MAX) return (int)(1 + idx);
        if (P->beta != (int32_t)P->tau * P->eta) return (int)(1 + idx);
        if (P->polyz_packedbytes != polyz) return (int)(1 + idx);
        if (P->polyw1_packedbytes != polyw1) return (int)(1 + idx);
        if (P->polyeta_packedbytes != polyeta) return (int)(1 + idx);
        if (P->pk_bytes != DIL_SEEDBYTES + (size_t)P->k * DIL_POLYT1_PACKEDBYTES)
            return (int)(1 + idx);
        if (P->sk_bytes != 2u * DIL_SEEDBYTES + DIL_TRBYTES +
                           (size_t)(P->l + P->k) * polyeta +
                           (size_t)P->k * DIL_POLYT0_PACKEDBYTES)
            return (int)(1 + idx);
        if (P->sig_bytes != P->ctildebytes + (size_t)P->l * polyz + P->omega + P->k)
            return (int)(1 + idx);
        if (dil_params_for(P->ps) != P) return (int)(1 + idx);
    }
    return 0;
}

/**
 * Test-only: assert that row-wise matrix expansion is byte-identical to the
 * whole-matrix expansion, for every parameter set.
 *
 * `dil_pubkey_from_sk` expands A one row at a time so its frame stays bounded
 * on a parser-reachable path (see the commentary there). That is only safe
 * because the SHAKE-128 stream for A[i][j] depends solely on (rho, nonce) and
 * not on how the samples were grouped into x4 batches — a property the public
 * API cannot distinguish, since a divergence would simply produce a different
 * (but internally consistent) public key and every self-round-trip would still
 * pass. The ML-DSA KATs would catch it, but only as "ML-DSA is wrong"; this
 * names it.
 *
 * Returns 0 on success, or 1 + the index of the first parameter set that
 * disagreed.
 */
int ama_ml_dsa_test_matrix_row_equiv(void);
int ama_ml_dsa_test_matrix_row_equiv(void) {
    static dil_poly mat[DIL_K_MAX * DIL_L_MAX];
    static dil_poly row[DIL_L_MAX];
    uint8_t rho[DIL_SEEDBYTES];
    unsigned idx, i, j, c;

    for (i = 0; i < DIL_SEEDBYTES; i++) {
        rho[i] = (uint8_t)(0x11 * (i + 1));
    }
    for (idx = 0; idx < 3; idx++) {
        const dil_params *P = &DIL_PARAM_SETS[idx];
        dil_expand_matrix(mat, rho, P);
        for (i = 0; i < P->k; i++) {
            dil_expand_matrix_row(row, rho, i, P);
            for (j = 0; j < P->l; j++) {
                for (c = 0; c < DIL_N; c++) {
                    if (row[j].coeffs[c] != mat[(size_t)i * P->l + j].coeffs[c]) {
                        return (int)(1 + idx);
                    }
                }
            }
        }
    }
    return 0;
}
#endif

/**
 * ML-DSA-65 signing with the FIPS 204 §5.2 external/pure context wrapper.
 *
 * Applies M' = 0x00 || IntegerToBytes(|ctx|, 1) || ctx || M before signing.
 * Pass `ctx = NULL, ctx_len = 0` for the empty-context form.  Rejects
 * `ctx_len > 255`.
 */
AMA_API ama_error_t ama_dilithium_sign_ctx(
    uint8_t *signature, size_t *signature_len,
    const uint8_t *message, size_t message_len,
    const uint8_t *ctx, size_t ctx_len,
    const uint8_t *secret_key)
{
    return ama_ml_dsa_sign_ctx(AMA_ML_DSA_65, signature, signature_len,
                               message, message_len, ctx, ctx_len, secret_key);
}

/**
 * ML-DSA-65 verification with the FIPS 204 §5.2 external/pure context wrapper.
 */
AMA_API ama_error_t ama_dilithium_verify_ctx(
    const uint8_t *message, size_t message_len,
    const uint8_t *ctx, size_t ctx_len,
    const uint8_t *signature, size_t signature_len,
    const uint8_t *public_key)
{
    return ama_ml_dsa_verify_ctx(AMA_ML_DSA_65, message, message_len,
                                 ctx, ctx_len, signature, signature_len, public_key);
}

/* ============================================================================
 * BENCHMARK-ONLY NTT KERNEL ACCESSORS (declared in include/ama_cryptography.h)
 *
 * These thin wrappers route a caller-supplied poly[256] through the same
 * `dil_ntt_cached` / `dil_invntt_cached` routines used by ML-DSA sign/verify,
 * but bind the dispatch slot explicitly so `benchmark_c_raw.c` can time the
 * scalar reference loop and the dispatched SIMD kernel separately. The static
 * `dil_zetas` table stays internal — these accessors are the only sanctioned
 * way for external code to drive the NTT in isolation.
 *
 * Each wrapper records which path it actually took into a static last-used
 * tracker that `ama_dilithium_{ntt,invntt}_bench_last_dispatch_get()` exposes.
 * The tracker lets a regression test verify the selector wiring directly
 * rather than relying on output byte-equality (which would still pass if a
 * wrapper silently ignored `use_dispatch` because both paths are designed
 * to produce identical bytes). Storage is single-threaded plain `int`,
 * matching the bench-harness use pattern; the wrappers are not in the
 * production hot path.
 *
 * Not for production use. ML-DSA-65 production callers go through
 * `ama_dilithium_sign()` / `ama_dilithium_verify()` (FIPS 204 §6.1 / §6.2).
 * ============================================================================ */

/* Last-used trackers: -1 = wrapper has not been called yet in this process,
 * 0 = scalar reference loop ran, 1 = dispatched SIMD kernel ran. The values
 * are read via the public getters declared in the header. */
static int ama_dilithium_ntt_bench_last_dispatch    = -1;
static int ama_dilithium_invntt_bench_last_dispatch = -1;

AMA_API void ama_dilithium_ntt_bench(int32_t poly[256], int use_dispatch) {
    const ama_dispatch_table_t *dt = ama_get_dispatch_table();
    if (use_dispatch && dt->dilithium_ntt) {
        /* Production dispatch path: AVX2 / NEON / SVE2 / AVX-512 when wired
         * AND the caller asked for it. */
        dt->dilithium_ntt(poly, dil_zetas);
        ama_dilithium_ntt_bench_last_dispatch = 1;
    } else {
        /* Scalar reference: either the caller forced it (use_dispatch == 0)
         * or no SIMD slot was wired on this host. Synthesise a dispatch
         * table with the slot cleared so dil_ntt_cached falls through to
         * the generic C implementation. */
        ama_dispatch_table_t scalar = *dt;
        scalar.dilithium_ntt = NULL;
        dil_ntt_cached(poly, &scalar);
        ama_dilithium_ntt_bench_last_dispatch = 0;
    }
}

AMA_API void ama_dilithium_invntt_bench(int32_t poly[256], int use_dispatch) {
    const ama_dispatch_table_t *dt = ama_get_dispatch_table();
    if (use_dispatch && dt->dilithium_invntt) {
        dt->dilithium_invntt(poly, dil_zetas);
        ama_dilithium_invntt_bench_last_dispatch = 1;
    } else {
        ama_dispatch_table_t scalar = *dt;
        scalar.dilithium_invntt = NULL;
        dil_invntt_cached(poly, &scalar);
        ama_dilithium_invntt_bench_last_dispatch = 0;
    }
}

AMA_API int ama_dilithium_ntt_bench_last_dispatch_get(void) {
    return ama_dilithium_ntt_bench_last_dispatch;
}

AMA_API int ama_dilithium_invntt_bench_last_dispatch_get(void) {
    return ama_dilithium_invntt_bench_last_dispatch;
}

AMA_API int ama_dilithium_ntt_dispatch_slot_wired(void) {
    return ama_get_dispatch_table()->dilithium_ntt != NULL;
}

AMA_API int ama_dilithium_invntt_dispatch_slot_wired(void) {
    return ama_get_dispatch_table()->dilithium_invntt != NULL;
}
