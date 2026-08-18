/* Copyright (C) 2025-2026 Steel Security Advisors LLC */
/* SPDX-License-Identifier: Apache-2.0 */
/**
 * @file ama_kyber.c
 * @brief CRYSTALS-Kyber-1024 Key Encapsulation Mechanism - Native C Implementation
 * @author Andrew E. A., Steel Security Advisors LLC
 * @date 2026-04-06
 *
 * IMPLEMENTATION STATUS: FULL NATIVE (FIPS 203 COMPLIANT)
 * =======================================================
 * This file provides Kyber-1024 (ML-KEM-1024) key encapsulation.
 * Full native C implementation — no external PQC dependencies required.
 * Passes all NIST FIPS 203 KAT (Known Answer Test) vectors (10/10).
 *
 * Build (default):
 *   cmake -DAMA_USE_NATIVE_PQC=ON ..
 *
 * Parameters (Kyber-1024 / ML-KEM-1024):
 * - Security level: NIST Level 5 (~256-bit classical, ~128-bit quantum)
 * - Public key: 1568 bytes
 * - Secret key: 3168 bytes
 * - Ciphertext: 1568 bytes
 * - Shared secret: 32 bytes
 *
 * Standards:
 * - NIST FIPS 203 (ML-KEM)
 * - Module-LWE hardness assumption
 * - Fujisaki-Okamoto transform for IND-CCA2 security
 *
 * Provenance:
 *   Implemented from: NIST FIPS 203 (August 2024 final), §5-§7 pseudocode.
 *   No code derived from pq-crystals/kyber, PQClean, liboqs, or any other
 *   third-party PQC implementation. The AVX2 NTT in `src/c/avx2/` is also
 *   in-house; it is not derived from the pq-crystals AVX2 variant.
 *   Validated: 25/25 ACVP ML-KEM-1024 KeyGen vectors and 25/25 ACVP
 *   ML-KEM-1024 EncapDecap vectors (decapsulation path — AMA does not
 *   expose the encap randomness `m`). See `src/c/PROVENANCE.md` for full
 *   provenance rationale and `CSRC_ALIGN_REPORT.md` for KAT results.
 *
 * For production use: pip install ama-cryptography[quantum]
 */

#include "../include/ama_cryptography.h"
#include "../include/ama_dispatch.h"
#include "internal/ama_sha3_x4.h"
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include "ama_platform_rand.h"
#include "internal/ama_testing_exports.h"

/* Forward declarations from ama_sha3.c */
extern ama_error_t ama_sha3_256(const uint8_t* input, size_t input_len, uint8_t* output);
extern ama_error_t ama_sha3_512(const uint8_t* input, size_t input_len, uint8_t* output);
extern ama_error_t ama_shake128(const uint8_t* input, size_t input_len,
                                 uint8_t* output, size_t output_len);
extern ama_error_t ama_shake256(const uint8_t* input, size_t input_len,
                                 uint8_t* output, size_t output_len);

/* ============================================================================
 * ML-KEM PARAMETER SETS (FIPS 203 Table 2)
 *
 * `n` and `q` are fixed for every ML-KEM parameter set — the ring
 * Z_q[X]/(X^256 + 1) and therefore the whole NTT layer, the Montgomery/Barrett
 * reduction constants, and the zeta table are shared verbatim across
 * ML-KEM-512/768/1024.  What varies is the module rank `k`, the CBD parameter
 * `eta1` for the secret/error vectors, and the ciphertext compression widths
 * `du`/`dv`.
 *
 * Those five numbers are therefore a *runtime* parameter block rather than
 * three copies of the implementation.  Duplicating ~1900 lines per parameter
 * set would triple the audit surface, triple the places a reduction-bound
 * argument has to be re-checked, and guarantee the three copies drift.
 * Array sizing uses KYBER_K_MAX so the stack footprint is the ML-KEM-1024
 * footprint for every set; that is a deliberate trade of a few KiB of stack
 * for one body of code.
 * ============================================================================ */

#define KYBER_N 256
#define KYBER_Q 3329

/** Largest module rank across the supported parameter sets (ML-KEM-1024). */
#define KYBER_K_MAX 4
/** Largest CBD parameter across the supported sets (eta1 = 3 for ML-KEM-512). */
#define KYBER_ETA_MAX 3
/** Largest CBD noise buffer: eta * n / 4 = 3 * 256 / 4. */
#define KYBER_NOISE_BYTES_MAX (KYBER_ETA_MAX * KYBER_N / 4)

/* Polynomial ring: R = Z_q[X]/(X^256 + 1) */

typedef struct {
    int16_t coeffs[KYBER_N];
} poly;

typedef struct {
    poly vec[KYBER_K_MAX];
} polyvec;

/**
 * One ML-KEM parameter set.
 *
 * The three byte-length fields are derived, not independent: they are
 * `384k + 32`, `768k + 96` and `32*(du*k + dv)` respectively.  They are
 * materialised here so every length check is a single comparison against a
 * named constant, and `kyber_params_selfcheck()` (AMA_TESTING_MODE) asserts
 * they agree with the formulas so a mistyped table entry cannot ship.
 */
typedef struct {
    ama_ml_kem_param_set_t ps;
    const char *name;
    unsigned    k;
    unsigned    eta1;
    unsigned    eta2;
    unsigned    du;
    unsigned    dv;
    size_t      pk_bytes;
    size_t      sk_bytes;
    size_t      ct_bytes;
} kyber_params;

static const kyber_params KYBER_PARAM_SETS[3] = {
    /* ps                  name           k eta1 eta2 du dv    pk    sk    ct */
    { AMA_ML_KEM_512,  "ML-KEM-512",  2,  3,   2, 10, 4,  800, 1632,  768 },
    { AMA_ML_KEM_768,  "ML-KEM-768",  3,  2,   2, 10, 4, 1184, 2400, 1088 },
    { AMA_ML_KEM_1024, "ML-KEM-1024", 4,  2,   2, 11, 5, 1568, 3168, 1568 }
};

static const kyber_params *kyber_params_for(ama_ml_kem_param_set_t ps) {
    switch (ps) {
        case AMA_ML_KEM_512:  return &KYBER_PARAM_SETS[0];
        case AMA_ML_KEM_768:  return &KYBER_PARAM_SETS[1];
        case AMA_ML_KEM_1024: return &KYBER_PARAM_SETS[2];
        default:              return NULL;
    }
}

/** Octets of a compressed polyvec `u` for this parameter set. */
#define KYBER_U_BYTES(P) ((size_t)(P)->k * (KYBER_N * (size_t)(P)->du / 8))
/** Octets of the compressed polynomial `v` for this parameter set. */
#define KYBER_V_BYTES(P) ((size_t)(KYBER_N * (size_t)(P)->dv / 8))
/** Offset of rho inside a packed public key (and of pk inside a secret key). */
#define KYBER_T_BYTES(P) ((size_t)(P)->k * 384u)

/* Forward declarations */
static void poly_add(poly* r, const poly* a, const poly* b);
static void poly_sub(poly* r, const poly* a, const poly* b);
static void poly_ntt(poly* r);
static void poly_invntt(poly* r);
static void poly_basemul(poly* r, const poly* a, const poly* b);
static void poly_reduce(poly* r);
static void poly_compress(uint8_t* r, const poly* a, int bits);
static void poly_decompress(poly* r, const uint8_t* a, int bits);
static void poly_tobytes(uint8_t* r, const poly* a);
static void poly_frombytes(poly* r, const uint8_t* a);
/* FIPS 203 §7.2 encapsulation-key input validation.  Defined beside the other
 * key-checking entry points below, but used by kyber_encapsulate_internal
 * above it, so it is declared here. */
static ama_error_t kyber_pubkey_check(const kyber_params* P,
                                      const uint8_t* ek, size_t ek_len);
static int16_t montgomery_reduce(int32_t a);
static int16_t coeff_normalize(int16_t a);
/* Division-free FIPS 203 Compress_d — defined beside coeff_normalize, whose
 * [0, q-1] output is its documented input domain. */
static inline uint32_t kyber_compress_d(uint32_t x_normalized, unsigned d);
static void poly_tomont(poly* r);

/* Public wrapper prototypes (called from ama_core.c via extern) */
AMA_API ama_error_t ama_kyber_keypair(uint8_t* pk, size_t pk_len,
                               uint8_t* sk, size_t sk_len);
AMA_API ama_error_t ama_kyber_encapsulate(const uint8_t* pk, size_t pk_len,
                                   uint8_t* ct, size_t* ct_len,
                                   uint8_t* ss, size_t ss_len);
AMA_API ama_error_t ama_kyber_decapsulate(const uint8_t* ct, size_t ct_len,
                                   const uint8_t* sk, size_t sk_len,
                                   uint8_t* ss, size_t ss_len);

/**
 * Kyber context (algorithm-specific)
 */
typedef struct {
    uint8_t public_key[AMA_KYBER_1024_PUBLIC_KEY_BYTES];
    uint8_t secret_key[AMA_KYBER_1024_SECRET_KEY_BYTES];
    int keys_generated;
} kyber_context_t;

/* ============================================================================
 * NATIVE KYBER HELPER FUNCTIONS
 * ============================================================================ */

/* Polyvec operations for native KEM */
static void polyvec_ntt(polyvec* r, unsigned int k) {
    unsigned int i;
    for (i = 0; i < k; i++) {
        poly_ntt(&r->vec[i]);
    }
}

static void polyvec_invntt(polyvec* r, unsigned int k) {
    unsigned int i;
    for (i = 0; i < k; i++) {
        poly_invntt(&r->vec[i]);
    }
}

static void polyvec_add(polyvec* r, const polyvec* a, const polyvec* b, unsigned int k) {
    unsigned int i;
    for (i = 0; i < k; i++) {
        poly_add(&r->vec[i], &a->vec[i], &b->vec[i]);
    }
}

static void polyvec_reduce(polyvec* r, unsigned int k) {
    unsigned int i;
    for (i = 0; i < k; i++) {
        poly_reduce(&r->vec[i]);
    }
}

/* polyvec_basemul_acc: r = sum_{i=0..K-1} basemul(a[i], b[i]).
 *
 * Reduction-pairing / coefficient-range audit:
 *
 *   (This is an arithmetic-range correctness note, NOT an INVARIANT-12
 *   constant-time claim — the ranges below are public, not derived from
 *   secret material.)
 *
 *   The trailing poly_reduce(r) (Barrett) is load-bearing and CANNOT be
 *   removed.  After accumulating k basemul outputs, each in (-2q, 2q)
 *   (basemul sums two montgomery_reduce outputs each in (-q, q)), the
 *   running sum is in (-2kq, 2kq).  The worst case across the supported
 *   parameter sets is k = KYBER_K_MAX = 4, giving (-8q, 8q)
 *   ≈ (-26632, 26632) — still fitting int16_t but outside the
 *   [-q/2, q/2] domain that poly_tomont /
 *   poly_invntt / polyvec_tobytes expect.  Removing it would silently
 *   corrupt NTT-domain coefficients and would be detected by the KAT
 *   suite, but only after producing wrong ciphertexts on encaps.
 *
 *   Similar audit results in the generic C path:
 *     - poly_invntt's final montgomery_reduce(f * x) is the only
 *       reduction; output is in (-q, q), exactly what the callers
 *       (poly_add, poly_sub, coeff_normalize) tolerate.  No pair.
 *     - poly_ntt's per-butterfly montgomery_reduce keeps |coeff|
 *       bounded by q + |a|/R.  After log2(KYBER_N)=8 layers the
 *       bound is ≲ 9q (per Bos–Friedberger §3.3); the trailing
 *       polyvec_reduce in callers covers it.  No interior pair.
 *
 *   The generic-C reduction layout is already algorithmically minimal
 *   at q=3329 / int16 coefficients.
 */
static void polyvec_basemul_acc(poly* r, const polyvec* a, const polyvec* b, unsigned int k) {
    unsigned int i;
    poly t;

    poly_basemul(r, &a->vec[0], &b->vec[0]);
    for (i = 1; i < k; i++) {
        poly_basemul(&t, &a->vec[i], &b->vec[i]);
        poly_add(r, r, &t);
    }
    poly_reduce(r);
}

/**
 * Serialize polyvec to bytes
 */
static void polyvec_tobytes(uint8_t* r, const polyvec* a, unsigned int k) {
    unsigned int i;
    for (i = 0; i < k; i++) {
        poly_tobytes(r + i * 384, &a->vec[i]);
    }
}

/**
 * Deserialize bytes to polyvec
 */
static void polyvec_frombytes(polyvec* r, const uint8_t* a, unsigned int k) {
    unsigned int i;
    for (i = 0; i < k; i++) {
        poly_frombytes(&r->vec[i], a + i * 384);
    }
}

/**
 * Compress polyvec at the parameter set's `du` (10 bits for ML-KEM-512/768,
 * 11 for ML-KEM-1024).
 */
static void polyvec_compress(uint8_t* r, const polyvec* a, const kyber_params* P) {
    unsigned int i;
    const size_t stride = (size_t)KYBER_N * P->du / 8u;
    for (i = 0; i < P->k; i++) {
        poly_compress(r + i * stride, &a->vec[i], (int)P->du);
    }
}

/**
 * Decompress polyvec at the parameter set's `du`.
 */
static void polyvec_decompress(polyvec* r, const uint8_t* a, const kyber_params* P) {
    unsigned int i;
    const size_t stride = (size_t)KYBER_N * P->du / 8u;
    for (i = 0; i < P->k; i++) {
        poly_decompress(&r->vec[i], a + i * stride, (int)P->du);
    }
}

/**
 * Sample polynomial uniformly from SHAKE128 stream (for matrix A)
 */
static void kyber_poly_uniform(poly* a, const uint8_t seed[32], uint8_t x, uint8_t y) {
    uint8_t buf[34];
    uint8_t stream[672];  /* Sufficient for rejection sampling */
    unsigned int ctr, pos;
    uint16_t val0, val1;

    memcpy(buf, seed, 32);
    buf[32] = x;
    buf[33] = y;

    ama_shake128(buf, 34, stream, sizeof(stream));

    ctr = 0;
    pos = 0;
    while (ctr < KYBER_N && pos + 3 <= sizeof(stream)) {
        val0 = ((stream[pos] | ((uint16_t)stream[pos + 1] << 8)) & 0xFFF);
        val1 = ((stream[pos + 1] >> 4) | ((uint16_t)stream[pos + 2] << 4)) & 0xFFF;
        pos += 3;

        if (val0 < KYBER_Q) {
            a->coeffs[ctr++] = (int16_t)val0;
        }
        if (ctr < KYBER_N && val1 < KYBER_Q) {
            a->coeffs[ctr++] = (int16_t)val1;
        }
    }
}

/**
 * Rejection-sample one polynomial from an already-squeezed SHAKE128
 * stream window.  Returns 1 if all KYBER_N coefficients were filled,
 * 0 if the stream was exhausted first.
 *
 * Byte-for-byte equivalent to the rejection loop in kyber_poly_uniform().
 */
static int kyber_rej_uniform_from_stream(poly *a,
                                          const uint8_t *stream, size_t stream_len)
{
    unsigned int ctr = 0;
    size_t pos = 0;

    while (ctr < KYBER_N && pos + 3 <= stream_len) {
        uint16_t val0 = ((stream[pos] | ((uint16_t)stream[pos + 1] << 8)) & 0xFFF);
        uint16_t val1 = ((stream[pos + 1] >> 4) | ((uint16_t)stream[pos + 2] << 4)) & 0xFFF;
        pos += 3;

        if (val0 < KYBER_Q) {
            a->coeffs[ctr++] = (int16_t)val0;
        }
        if (ctr < KYBER_N && val1 < KYBER_Q) {
            a->coeffs[ctr++] = (int16_t)val1;
        }
    }

    return (ctr == KYBER_N) ? 1 : 0;
}

/**
 * Expand matrix A from seed (K x K matrix in NTT domain).
 *
 * Batched over four lanes via ama_shake128_x4_absorb_once /
 * ama_shake128_x4_squeezeblocks.  Per-lane coefficients are
 * byte-for-byte identical to the scalar kyber_poly_uniform()
 * reference above.
 *
 * For Kyber-1024 (KYBER_K=4), the matrix has 16 polys → 4 full
 * groups of 4 with no trailing scalar work.  The initial 4-block
 * squeeze (672 bytes per lane) matches the scalar stream[672].
 */
/**
 * Flush one batch of exactly four matrix entries through the 4-way SHAKE128
 * kernel.  Split out of kyber_gen_matrix so the caller's loop carries nothing
 * but the (i, j) matrix indices — which is what lets both a reader and the
 * optimiser see that `mat[i].vec[j]` is in bounds.
 */
static void kyber_gen_matrix_flush4(uint8_t bufs[4][34],
                                    poly *polys[4],
                                    uint8_t xy[4][2],
                                    const uint8_t seed[32]) {
    /* 4 blocks matches the scalar kyber_poly_uniform stream[672] budget. */
    const size_t kInitialBlocks = 4;
    ama_shake128_x4_ctx ctx;
    uint8_t streams[4][AMA_SHAKE128_X4_RATE * 4];
    int lane;

    ama_shake128_x4_absorb_once(&ctx,
        bufs[0], 34, bufs[1], 34, bufs[2], 34, bufs[3], 34);
    ama_shake128_x4_squeezeblocks(&ctx,
        streams[0], streams[1], streams[2], streams[3], kInitialBlocks);

    for (lane = 0; lane < 4; lane++) {
        int ok = kyber_rej_uniform_from_stream(polys[lane],
                                               streams[lane],
                                               AMA_SHAKE128_X4_RATE * kInitialBlocks);
        if (!ok) {
            /* Scalar fallback (effectively unreachable: ML-KEM's ~18.7 %
             * rejection rate over 448 candidates per 4 blocks gives expected
             * accepts >> 256, matching the scalar reference's one-shot
             * squeeze budget exactly). */
            kyber_poly_uniform(polys[lane], seed, xy[lane][0], xy[lane][1]);
        }
    }
}

/**
 * Expand the seed into the k x k matrix A (or its transpose), in the NTT
 * domain, per FIPS 203 Algorithm 13 §4.2.2.
 *
 * Iteration is over the matrix indices (i, j) directly rather than over a
 * flattened counter with a division.  That is not cosmetic: with a flattened
 * `i = flat / k`, GCC could not bound `i` once `k` became a runtime value and
 * emitted -Waggressive-loop-optimizations "iteration 4 invokes undefined
 * behavior" against `mat[i]` on the constprop clone.  Iterating `i < P->k`
 * with the precondition below makes the bound structural, so the warning is
 * gone because the property is now provable rather than because it was
 * suppressed.
 *
 * Entries are batched four at a time through the 4-way SHAKE128 kernel.
 * k*k is 4, 9 and 16 for ML-KEM-512/-768/-1024, so ML-KEM-768 finishes with
 * one entry on the scalar path — byte-identical output either way, since both
 * paths absorb the same 34-octet seed||x||y and apply the same rejection
 * sampling.
 */
static void kyber_gen_matrix(polyvec *mat, const uint8_t seed[32],
                             int transposed, const kyber_params* P) {
    uint8_t bufs[4][34];
    poly *polys[4];
    uint8_t xy[4][2];
    unsigned int i, j, pending = 0;

    /* Precondition, not a fallback: a parameter block with k outside
     * [1, KYBER_K_MAX] would overflow `polyvec`, and every shipped row is
     * checked against this bound by ama_ml_kem_test_params_selfcheck(). */
    if (P->k == 0u || P->k > KYBER_K_MAX) {
        return;
    }

    for (i = 0; i < P->k; i++) {
        for (j = 0; j < P->k; j++) {
            uint8_t x = transposed ? (uint8_t)i : (uint8_t)j;
            uint8_t y = transposed ? (uint8_t)j : (uint8_t)i;

            memcpy(bufs[pending], seed, 32);
            bufs[pending][32] = x;
            bufs[pending][33] = y;
            xy[pending][0] = x;
            xy[pending][1] = y;
            polys[pending] = &mat[i].vec[j];

            if (++pending == 4u) {
                kyber_gen_matrix_flush4(bufs, polys, xy, seed);
                pending = 0;
            }
        }
    }

    /* Trailing 0..3 entries — reached only by ML-KEM-768 (k*k = 9). */
    for (i = 0; i < pending; i++) {
        kyber_poly_uniform(polys[i], seed, xy[i][0], xy[i][1]);
    }
}

/**
 * Sample noise polynomial with CBD, eta = 3 (FIPS 203 Algorithm 8).
 *
 * Only ML-KEM-512 uses eta1 = 3.  Three bits per coefficient half means the
 * natural unit is 3 octets -> 4 coefficients, so this cannot reuse the
 * 32-bit-word trick the eta = 2 path uses, and there is no SIMD kernel for
 * it in the dispatch table (adding one would be a separate, measured
 * change — see docs/DESIGN_NOTES.md).  Consumes eta*n/4 = 192 octets.
 */
static void kyber_poly_cbd3(poly* r, const uint8_t* buf) {
    unsigned int i, j;
    uint32_t t, d;
    int16_t a, b;

    for (i = 0; i < KYBER_N / 4; i++) {
        /* Load 3 octets little-endian -> 24 bits -> 4 coefficients. */
        t = (uint32_t)buf[3 * i] |
            ((uint32_t)buf[3 * i + 1] << 8) |
            ((uint32_t)buf[3 * i + 2] << 16);

        d = t & 0x00249249u;
        d += (t >> 1) & 0x00249249u;
        d += (t >> 2) & 0x00249249u;

        for (j = 0; j < 4; j++) {
            a = (int16_t)((d >> (6 * j + 0)) & 0x7);
            b = (int16_t)((d >> (6 * j + 3)) & 0x7);
            r->coeffs[4 * i + j] = (int16_t)(a - b);
        }
    }
}

/**
 * Sample noise polynomial with CBD (eta = 2)
 *
 * Routes to the AVX2 bit-count path via the dispatch table when
 * available; coefficient output is byte-for-byte identical to the
 * generic inline fallback below.
 */
static void kyber_poly_cbd_eta(poly* r, const uint8_t* buf) {
    const ama_dispatch_table_t *dt = ama_get_dispatch_table();
    if (dt->kyber_cbd2) {
        dt->kyber_cbd2(r->coeffs, buf);
        return;
    }

    /* Generic C implementation — CBD with eta = 2: need eta*N/4 = 128 bytes */
    unsigned int i, j;
    uint32_t t, d;
    int16_t a, b;

    for (i = 0; i < KYBER_N / 8; i++) {
        t = buf[4*i] | ((uint32_t)buf[4*i + 1] << 8) |
            ((uint32_t)buf[4*i + 2] << 16) | ((uint32_t)buf[4*i + 3] << 24);

        d = t & 0x55555555;
        d += (t >> 1) & 0x55555555;

        for (j = 0; j < 8; j++) {
            a = (int16_t)((d >> (4*j + 0)) & 0x3);
            b = (int16_t)((d >> (4*j + 2)) & 0x3);
            r->coeffs[8*i + j] = a - b;
        }
    }
}

/**
 * Sample a noise vector with CBD at a given eta (FIPS 203 Algorithm 8 via
 * SamplePolyCBD over a SHAKE256 stream).
 *
 * `eta` is passed explicitly rather than read from the parameter block
 * because the same routine samples both the eta1 vectors (s, e, r, e1) and
 * — via kyber_cbd_poly() below — the eta2 polynomial e2, and for ML-KEM-512
 * those differ (eta1 = 3, eta2 = 2).  Conflating them was the single most
 * likely way to get ML-KEM-512 subtly wrong, so the caller always says which
 * one it means.
 *
 * The 4-way SHAKE256 batch is taken only when the parameter set has exactly
 * four lanes to fill *and* the per-lane noise fits in one rate block. That is
 * ML-KEM-1024 and nothing else: ML-KEM-768 has three lanes and ML-KEM-512
 * needs 192 octets (eta1 = 3), which exceeds the 136-octet SHAKE256 rate.
 * Both fall to the scalar loop, whose output is byte-identical by
 * construction — the batch and the scalar path absorb the same 33-octet
 * seed||nonce and squeeze the same stream. tests/c/test_kyber_cbd2_equiv.c
 * and the FIPS 203 KATs for all three sets pin that equality.
 */
static void kyber_gennoise(polyvec* r, const uint8_t seed[32], uint8_t nonce,
                           unsigned int k, unsigned int eta) {
    const size_t noise_bytes = (size_t)eta * KYBER_N / 4u;
    unsigned int i;

    if (k == 4 && noise_bytes <= AMA_SHAKE256_X4_RATE) {
        uint8_t bufs[4][34];
        for (i = 0; i < 4; i++) {
            memcpy(bufs[i], seed, 32);
            bufs[i][32] = nonce + (uint8_t)i;
            bufs[i][33] = 0;
        }

        ama_shake256_x4_ctx ctx;
        ama_shake256_x4_absorb_once(&ctx,
            bufs[0], 33, bufs[1], 33, bufs[2], 33, bufs[3], 33);

        uint8_t streams[4][AMA_SHAKE256_X4_RATE];
        ama_shake256_x4_squeezeblocks(&ctx,
            streams[0], streams[1], streams[2], streams[3], 1);

        for (i = 0; i < 4; i++) {
            kyber_poly_cbd_eta(&r->vec[i], streams[i]);
        }
        /* The CBD input *is* the secret vector s (and e, from which s follows
         * given the public t = A*s + e and A), and `bufs` carries sigma.
         * INVARIANT-12 applies to both arms of one function, and until the
         * commit carrying this comment NEITHER arm was complete: the batched
         * arm scrubbed nothing, and the scalar arm below scrubbed `stream`
         * but never the `buf` holding sigma||nonce.  Both are closed now. */
        ama_secure_memzero(streams, sizeof(streams));
        ama_secure_memzero(bufs, sizeof(bufs));
        /* The x4 sponge state was seeded with sigma||nonce and, until it is
         * re-permuted, its absorbed lanes are as recoverable as `streams`
         * itself (a Keccak state is invertible within a permutation).  Scrub
         * it in the same class as streams/bufs — INVARIANT-12. */
        ama_secure_memzero(&ctx, sizeof(ctx));
        return;
    }

    /* Scalar path — ML-KEM-512 and ML-KEM-768. */
    {
        uint8_t buf[34];
        uint8_t stream[KYBER_NOISE_BYTES_MAX];
        for (i = 0; i < k; i++) {
            memcpy(buf, seed, 32);
            buf[32] = nonce + (uint8_t)i;
            buf[33] = 0;
            ama_shake256(buf, 33, stream, noise_bytes);
            if (eta == 3) {
                kyber_poly_cbd3(&r->vec[i], stream);
            } else {
                kyber_poly_cbd_eta(&r->vec[i], stream);
            }
        }
        ama_secure_memzero(stream, sizeof(stream));
        /* `buf` is sigma||nonce — the CBD seed, not a derivative of it.  It
         * is the same secret class as `stream` (which it generates) and as
         * the x4 arm's `bufs`, which is scrubbed above.  Scrubbing only the
         * expanded stream left the seed itself in a dead frame, where the
         * whole noise vector is re-derivable from it. */
        ama_secure_memzero(buf, sizeof(buf));
    }
}

/**
 * Sample a single CBD noise polynomial (the e2 term of CPAPKE.Enc).
 */
static void kyber_cbd_poly(poly* r, const uint8_t seed[32], uint8_t nonce, unsigned int eta) {
    const size_t noise_bytes = (size_t)eta * KYBER_N / 4u;
    uint8_t buf[33];
    uint8_t stream[KYBER_NOISE_BYTES_MAX];

    memcpy(buf, seed, 32);
    buf[32] = nonce;
    ama_shake256(buf, 33, stream, noise_bytes);
    if (eta == 3) {
        kyber_poly_cbd3(r, stream);
    } else {
        kyber_poly_cbd_eta(r, stream);
    }
    ama_secure_memzero(stream, sizeof(stream));
    /* Same class as `stream`: `buf` holds the CBD seed (the FO coins `r`
     * during encapsulation and the decapsulation re-encryption), from which
     * this polynomial is fully re-derivable.  INVARIANT-12. */
    ama_secure_memzero(buf, sizeof(buf));
}

#ifdef AMA_TESTING_MODE
/**
 * Random bytes hook for KAT testing.
 * When non-NULL, all random byte generation uses this function instead of
 * /dev/urandom, allowing deterministic KAT vector reproduction.
 * Only available in test builds (AMA_TESTING_MODE).
 */
ama_error_t (*ama_kyber_randombytes_hook)(uint8_t* buf, size_t len) = NULL;
#endif

/**
 * Get random bytes from OS (or from test hook if set)
 */
static ama_error_t kyber_randombytes(uint8_t* buf, size_t len) {
#ifdef AMA_TESTING_MODE
    if (ama_kyber_randombytes_hook) {
        return ama_kyber_randombytes_hook(buf, len);
    }
#endif
    return ama_randombytes(buf, len);
}

/**
 * Generate Kyber-1024 keypair
 *
 * Native ML-KEM-1024 implementation (FIPS 203 compliant).
 *
 * @param public_key Output buffer for public key (1568 bytes)
 * @param public_key_len Length of public key buffer
 * @param secret_key Output buffer for secret key (3168 bytes)
 * @param secret_key_len Length of secret key buffer
 * @return AMA_SUCCESS or error code
 */
/**
 * ML-KEM key generation (FIPS 203 Algorithm 16 `ML-KEM.KeyGen_internal`).
 *
 * One body serves both the random and the deterministic entry points: pass
 * `d` and `z` to reproduce a KAT vector, or NULL for both to draw them from
 * the CSPRNG.  The two used to be separate near-identical functions, which is
 * exactly the shape where a fix lands in one copy and not the other.
 *
 * `d` and `z` are either both NULL or both non-NULL; a caller that supplies
 * one and not the other is rejected rather than half-seeded.
 */
static ama_error_t kyber_keygen_internal(const kyber_params* P,
                                         uint8_t* public_key, size_t public_key_len,
                                         uint8_t* secret_key, size_t secret_key_len,
                                         const uint8_t* d_in, const uint8_t* z_in) {
    if (!P || !public_key || !secret_key) {
        return AMA_ERROR_INVALID_PARAM;
    }
    if ((d_in == NULL) != (z_in == NULL)) {
        return AMA_ERROR_INVALID_PARAM;
    }
    if (public_key_len < P->pk_bytes || secret_key_len < P->sk_bytes) {
        return AMA_ERROR_INVALID_PARAM;
    }

#ifdef AMA_USE_NATIVE_PQC
    {
        uint8_t d[32], buf[64];
        uint8_t *rho, *sigma;
        polyvec a[KYBER_K_MAX], s, e, pkpv;
        const size_t t_bytes = KYBER_T_BYTES(P);
        unsigned int i;
        ama_error_t err;

        if (d_in) {
            memcpy(d, d_in, 32);
        } else {
            err = kyber_randombytes(d, 32);
            if (err != AMA_SUCCESS) {
                return err;
            }
        }

        /* G(d || byte(k)) = (rho, sigma) per FIPS 203 Algorithm 16.
         * The domain-separating `k` octet is what keeps the same `d` from
         * producing related keys across parameter sets — it is the reason
         * this byte is `P->k` and not a constant. */
        {
            uint8_t g_input[33];
            memcpy(g_input, d, 32);
            g_input[32] = (uint8_t)P->k;
            ama_sha3_512(g_input, 33, buf);
            ama_secure_memzero(g_input, sizeof(g_input));
        }
        rho = buf;
        sigma = buf + 32;

        /* Generate matrix A from rho (in NTT domain) */
        kyber_gen_matrix(a, rho, 0, P);

        /* Sample secret vector s and error vector e from CBD, then NTT.
         *
         * Pipelined for L1-residency: each polyvec is NTT'd immediately
         * after sampling, before the next SHAKE256 batch is
         * absorbed/squeezed.  Working set per phase is one polyvec
         * instead of two — keeps the just-sampled coefficients hot through
         * the NTT butterflies.  Output is byte-identical to a
         * sample-all-then-NTT-all layout because NTT acts on each
         * polynomial independently. */
        kyber_gennoise(&s, sigma, 0, P->k, P->eta1);
        polyvec_ntt(&s, P->k);
        kyber_gennoise(&e, sigma, (uint8_t)P->k, P->k, P->eta1);
        polyvec_ntt(&e, P->k);

        /* Compute t = A*s + e (in NTT domain).
         * basemul output has implicit R^{-1} Montgomery factor.
         * poly_tomont compensates by multiplying by R, so the
         * result is in the same domain as NTT(e) for correct addition. */
        for (i = 0; i < P->k; i++) {
            polyvec_basemul_acc(&pkpv.vec[i], &a[i], &s, P->k);
            poly_tomont(&pkpv.vec[i]);
            poly_add(&pkpv.vec[i], &pkpv.vec[i], &e.vec[i]);
        }
        polyvec_reduce(&pkpv, P->k);

        /* Pack public key: pk = (t || rho) */
        polyvec_tobytes(public_key, &pkpv, P->k);
        memcpy(public_key + t_bytes, rho, 32);

        /* Pack secret key: sk = (s || pk || H(pk) || z) */
        polyvec_reduce(&s, P->k);  /* Reduce NTT(s) before serialization —
                                      coeff_normalize only handles [-q, 2q-1],
                                      but NTT output can exceed this */
        polyvec_tobytes(secret_key, &s, P->k);
        memcpy(secret_key + t_bytes, public_key, P->pk_bytes);

        /* H(pk) */
        ama_sha3_256(public_key, P->pk_bytes, secret_key + t_bytes + P->pk_bytes);

        /* z for implicit rejection */
        if (z_in) {
            memcpy(secret_key + t_bytes + P->pk_bytes + 32, z_in, 32);
        } else {
            err = kyber_randombytes(secret_key + t_bytes + P->pk_bytes + 32, 32);
            if (err != AMA_SUCCESS) {
                /* Late-error path: the NTT-domain s vector and the
                 * (rho, sigma) seed in `buf` are already populated.  Scrub
                 * before returning so the secret state never survives the
                 * error path on the caller's stack. */
                ama_secure_memzero(d, sizeof(d));
                ama_secure_memzero(buf, sizeof(buf));
                ama_secure_memzero(&s, sizeof(s));
                ama_secure_memzero(&e, sizeof(e));
                ama_secure_memzero(&pkpv, sizeof(pkpv));
                ama_secure_memzero(secret_key, P->sk_bytes);
                return err;
            }
        }

        /* Scrub sensitive data */
        ama_secure_memzero(d, sizeof(d));
        ama_secure_memzero(buf, sizeof(buf));
        ama_secure_memzero(&s, sizeof(s));
        ama_secure_memzero(&e, sizeof(e));

        return AMA_SUCCESS;
    }
#else
    (void)public_key;
    (void)secret_key;
    (void)d_in;
    (void)z_in;
    return AMA_ERROR_NOT_IMPLEMENTED;
#endif
}

/* ============================================================================
 * INTERNAL CPA ENCRYPTION (CPAPKE.Enc)
 * ============================================================================
 * Deterministic encryption used by both encapsulation and decapsulation.
 * Takes message m and coins (randomness) as explicit inputs.
 * This separation is critical for the Fujisaki-Okamoto transform:
 * decapsulation must re-encrypt with the SAME coins to compare ciphertexts.
 * ============================================================================ */
#ifdef AMA_USE_NATIVE_PQC
static void kyber_cpapke_enc(uint8_t *ct, const uint8_t *m,
                              const uint8_t *pk, const uint8_t *coins,
                              const kyber_params* P) {
    polyvec a[KYBER_K_MAX], sp, ep, pkpv, bp;
    poly v, epp, mp_poly;
    unsigned int i;
    const uint8_t *rho;

    /* Extract rho from public key */
    rho = pk + KYBER_T_BYTES(P);

    /* Decode public key */
    polyvec_frombytes(&pkpv, pk, P->k);

    /* Generate matrix A^T from rho */
    kyber_gen_matrix(a, rho, 1, P);

    /* Sample r, e1, e2 from coins.  NTT r immediately after sampling
     * so r's coefficients stay L1-resident through the NTT butterflies
     * (r is the only sampled polyvec used in the NTT domain in this
     * function — e1 and e2 are added in the coefficient domain after
     * invntt below, so they are intentionally NOT NTT'd here).
     *
     * Note the eta split, which FIPS 203 Algorithm 14 (K-PKE.Encrypt) is
     * explicit about and which is easy to get wrong: `y` (here `sp`) is
     * sampled with eta1, while BOTH error terms `e1` (here `ep`) and `e2`
     * (here `epp`) are sampled with eta2.  The three coincide for ML-KEM-768
     * and ML-KEM-1024 (eta1 = eta2 = 2), so a single-eta implementation looks
     * correct until ML-KEM-512 (eta1 = 3, eta2 = 2) — where it silently
     * produces a ciphertext no other implementation decapsulates.  What pins
     * this is `tests/kat/fips203/ml_kem_512.kat` — the vendored Wycheproof
     * ML-KEM-512 corpus (C2SP/wycheproof `testvectors_v1/mlkem_512_test.json`,
     * provenance in tests/kat/README.md), replayed by
     * `tests/test_pqc_param_sets.py::test_ml_kem_known_answer_vectors`.  Its
     * ct/ss pairs drive the FO re-encryption and therefore this function at
     * eta1 = 3.
     *
     * The path is named because the corpus does not live under
     * `wycheproof_vectors/`: that directory carries the classical suites only,
     * and its README says so in as many words.  "The vendored Wycheproof
     * ML-KEM-512 corpus" alone sent a reader there, found nothing, and read as
     * a dangling citation for a stated conformance property. */
    kyber_gennoise(&sp, coins, 0, P->k, P->eta1);
    polyvec_ntt(&sp, P->k);
    kyber_gennoise(&ep, coins, (uint8_t)P->k, P->k, P->eta2);
    kyber_cbd_poly(&epp, coins, (uint8_t)(2u * P->k), P->eta2);

    /* Compute u = A^T * r + e1 */
    for (i = 0; i < P->k; i++) {
        polyvec_basemul_acc(&bp.vec[i], &a[i], &sp, P->k);
    }
    polyvec_invntt(&bp, P->k);
    polyvec_add(&bp, &bp, &ep, P->k);
    polyvec_reduce(&bp, P->k);

    /* Compute v = t^T * r + e2 + Decompress(m, 1) */
    polyvec_basemul_acc(&v, &pkpv, &sp, P->k);
    poly_invntt(&v);
    poly_add(&v, &v, &epp);

    /* Encode message into polynomial */
    memset(&mp_poly, 0, sizeof(mp_poly));  // PUBLIC-DATA: mp_poly — ML-KEM CPA encryption message polynomial, pre-use init filled by Encode_1 bit-unpacking of plaintext `m` below (`mp_poly.coeffs[8*i + j] = ((m[i] >> j) & 1) * ...`)
    for (i = 0; i < 32; i++) {
        unsigned int j;
        for (j = 0; j < 8; j++) {
            mp_poly.coeffs[8*i + j] = (int16_t)(((m[i] >> j) & 1) *
                                                  ((KYBER_Q + 1) / 2));
        }
    }
    poly_add(&v, &v, &mp_poly);
    poly_reduce(&v);

    /* Compress and pack ciphertext */
    polyvec_compress(ct, &bp, P);
    poly_compress(ct + KYBER_U_BYTES(P), &v, (int)P->dv);

    /* The CPA encryption is re-run on the decapsulation path with the
     * recovered message, so its intermediates are secret-key-derived there.
     * Scrub them here rather than relying on each caller. */
    ama_secure_memzero(&sp, sizeof(sp));
    ama_secure_memzero(&ep, sizeof(ep));
    ama_secure_memzero(&epp, sizeof(epp));
    ama_secure_memzero(&bp, sizeof(bp));
    ama_secure_memzero(&v, sizeof(v));
    ama_secure_memzero(&mp_poly, sizeof(mp_poly));
}
#endif

/**
 * ML-KEM encapsulation (FIPS 203 Algorithm 17, over `ML-KEM.Encaps_internal`).
 *
 * One body serves both the random and the deterministic entry points, matching
 * `kyber_keypair_internal`'s `d`/`z` idiom above: pass `m_in` to encapsulate
 * under a caller-chosen message (FIPS 203 Algorithm 17 takes `m` as an input;
 * it is Algorithm 20 that draws it), or NULL to draw it from the CSPRNG. Two
 * near-identical copies is exactly the shape where a fix lands in one and not
 * the other, so there is one.
 *
 * The deterministic arm exists for `kyber_pubkey_from_sk`'s pairwise check,
 * which must not consume entropy — see the commentary there.
 */
static ama_error_t kyber_encapsulate_internal(
    const kyber_params* P,
    const uint8_t* public_key,
    size_t public_key_len,
    const uint8_t* m_in,
    uint8_t* ciphertext,
    size_t* ciphertext_len,
    uint8_t* shared_secret,
    size_t shared_secret_len
) {
    if (!P || !public_key || !ciphertext || !ciphertext_len || !shared_secret) {
        return AMA_ERROR_INVALID_PARAM;
    }
    if (public_key_len != P->pk_bytes ||
        shared_secret_len != AMA_ML_KEM_SHARED_SECRET_BYTES) {
        return AMA_ERROR_INVALID_PARAM;
    }

#ifdef AMA_USE_NATIVE_PQC
    {
        uint8_t m[32], kr[64];
        ama_error_t err;

        /* FIPS 203 §7.2 input validation, which the specification places
         * *before* encapsulation rather than leaving to the caller.  Without
         * it, an encapsulation key with an out-of-range coefficient — which
         * every conformant peer rejects — is silently encapsulated to, and the
         * two sides end up holding different shared secrets with nothing
         * raised anywhere.  See kyber_pubkey_check. */
        err = kyber_pubkey_check(P, public_key, public_key_len);
        if (err != AMA_SUCCESS) {
            return err;
        }

        if (*ciphertext_len < P->ct_bytes) {
            *ciphertext_len = P->ct_bytes;
            return AMA_ERROR_INVALID_PARAM;
        }

        /* Message m: supplied by the caller, or drawn from the CSPRNG. */
        if (m_in) {
            memcpy(m, m_in, 32);
        } else {
            err = kyber_randombytes(m, 32);
            if (err != AMA_SUCCESS) {
                return err;
            }
        }

        /* (K, r) = G(m || H(pk)) per FIPS 203 Algorithm 17
         * H = SHA3-256, G = SHA3-512 */
        {
            uint8_t pk_hash[32];
            uint8_t g_input[64];
            ama_sha3_256(public_key, P->pk_bytes, pk_hash);
            memcpy(g_input, m, 32);
            memcpy(g_input + 32, pk_hash, 32);
            ama_sha3_512(g_input, 64, kr);
            ama_secure_memzero(g_input, sizeof(g_input));
        }

        /* Deterministic CPA encryption with m and coins r = kr+32 */
        kyber_cpapke_enc(ciphertext, m, public_key, kr + 32, P);

        /* Shared secret = first 32 bytes of kr (= K) */
        memcpy(shared_secret, kr, 32);

        *ciphertext_len = P->ct_bytes;

        /* Scrub sensitive data */
        ama_secure_memzero(m, sizeof(m));
        ama_secure_memzero(kr, sizeof(kr));

        return AMA_SUCCESS;
    }
#else
    (void)public_key;
    (void)ciphertext;
    (void)ciphertext_len;
    (void)shared_secret;
    return AMA_ERROR_NOT_IMPLEMENTED;
#endif
}

/**
 * ML-KEM decapsulation (FIPS 203 Algorithm 18).
 *
 * Implicit rejection is unconditional and constant time: both the honest
 * shared secret and the rejection value H(z || ct) are always computed, and
 * the choice between them is a masked copy.  A branch here would leak whether
 * the ciphertext was well formed, which is the entire IND-CCA2 property.
 */
static ama_error_t kyber_decapsulate_internal(
    const kyber_params* P,
    const uint8_t* ciphertext,
    size_t ciphertext_len,
    const uint8_t* secret_key,
    size_t secret_key_len,
    uint8_t* shared_secret,
    size_t shared_secret_len
) {
    if (!P || !ciphertext || !secret_key || !shared_secret) {
        return AMA_ERROR_INVALID_PARAM;
    }
    if (ciphertext_len != P->ct_bytes ||
        secret_key_len != P->sk_bytes ||
        shared_secret_len != AMA_ML_KEM_SHARED_SECRET_BYTES) {
        return AMA_ERROR_INVALID_PARAM;
    }

#ifdef AMA_USE_NATIVE_PQC
    {
        polyvec bp, skpv;
        poly v, mp;
        uint8_t m[32], kr[64];
        uint8_t ct_cmp[AMA_ML_KEM_MAX_CIPHERTEXT_BYTES];
        const uint8_t *pk;
        const uint8_t *h_pk;
        const uint8_t *z;
        unsigned int i;
        int fail;

        /* Parse secret key: s || pk || H(pk) || z */
        polyvec_frombytes(&skpv, secret_key, P->k);
        pk = secret_key + KYBER_T_BYTES(P);
        h_pk = pk + P->pk_bytes;
        z = h_pk + 32;

        /* Decompress ciphertext */
        polyvec_decompress(&bp, ciphertext, P);
        poly_decompress(&v, ciphertext + KYBER_U_BYTES(P), (int)P->dv);

        /* Compute s^T * u (inner product in NTT domain) */
        polyvec_ntt(&bp, P->k);
        polyvec_basemul_acc(&mp, &skpv, &bp, P->k);
        poly_invntt(&mp);

        /* Compute v - s^T * u to recover message */
        poly_sub(&mp, &v, &mp);
        poly_reduce(&mp);

        /* Decode message from polynomial.
         * Each coefficient is approximately 0 (bit=0) or (q+1)/2 (bit=1).
         * We normalize to [0,q-1] then check if closer to 0 or q/2. */
        for (i = 0; i < 32; i++) {
            m[i] = 0;
            unsigned int j;
            for (j = 0; j < 8; j++) {
                int16_t t = coeff_normalize(mp.coeffs[8*i + j]);
                /* Compress_1: round(2t/q) mod 2.  Division-free — mp is
                 * secret-key-derived, see kyber_compress_d (KyberSlash). */
                t = (int16_t)kyber_compress_d((uint32_t)t, 1);
                m[i] |= (uint8_t)((t & 1) << j);
            }
        }

        /* Re-derive (K, r) = G(m || H(pk)) per FIPS 203 Algorithm 18 */
        {
            uint8_t g_input[64];
            memcpy(g_input, m, 32);
            memcpy(g_input + 32, h_pk, 32);
            ama_sha3_512(g_input, 64, kr);
            ama_secure_memzero(g_input, sizeof(g_input));
        }

        /* Re-encrypt with recovered m and derived coins r = kr+32.
         * This is the core of the FO transform: if the recovered message
         * is correct, re-encryption produces the same ciphertext. */
        kyber_cpapke_enc(ct_cmp, m, pk, kr + 32, P);

        /* Constant-time comparison of ciphertexts */
        fail = ama_consttime_memcmp(ciphertext, ct_cmp, P->ct_bytes);

        /* Compute BOTH outcomes, then select in constant time.
         * This prevents timing side-channels from leaking whether
         * decapsulation succeeded or triggered implicit rejection. */
        {
            /* Always compute the implicit rejection value: H(z || ct).
             * Stack-allocated to avoid a malloc failure path that would
             * leak the decapsulation outcome (IND-CCA2 side-channel). */
            uint8_t ss_reject[32];
            uint8_t rej_input[32 + AMA_ML_KEM_MAX_CIPHERTEXT_BYTES];
            memcpy(rej_input, z, 32);
            memcpy(rej_input + 32, ciphertext, P->ct_bytes);
            ama_shake256(rej_input, 32 + P->ct_bytes, ss_reject, 32);
            ama_secure_memzero(rej_input, sizeof(rej_input));

            /* Start with the valid shared secret (kr), then conditionally
             * overwrite with the rejection value if ciphertexts didn't match.
             * ama_consttime_copy(condition, dst, src, len):
             *   copies src -> dst if condition != 0 */
            memcpy(shared_secret, kr, 32);
            ama_consttime_copy(fail, shared_secret, ss_reject, 32);

            ama_secure_memzero(ss_reject, sizeof(ss_reject));
        }

        /* Scrub sensitive data.
         *
         * INVARIANT-12: the decap success path leaves recoverable secret
         * material on the stack — the secret key polyvec (`skpv`), the
         * recovered message polynomial (`mp`), the decompressed ciphertext
         * (`bp`, `v`), and the re-encrypted ciphertext used by the FO
         * comparator (`ct_cmp`).  All are derivable from the secret key
         * once seen, so they are scrubbed alongside `m` and `kr`. */
        ama_secure_memzero(m, sizeof(m));
        ama_secure_memzero(kr, sizeof(kr));
        ama_secure_memzero(&bp, sizeof(bp));
        ama_secure_memzero(&skpv, sizeof(skpv));
        ama_secure_memzero(&v, sizeof(v));
        ama_secure_memzero(&mp, sizeof(mp));
        ama_secure_memzero(ct_cmp, sizeof(ct_cmp));

        return AMA_SUCCESS;
    }
#else
    (void)ciphertext;
    (void)secret_key;
    (void)shared_secret;
    return AMA_ERROR_NOT_IMPLEMENTED;
#endif
}

/* ============================================================================
 * DEBUG / TEST FUNCTIONS
 * ============================================================================
 * These functions are only compiled when AMA_KYBER_BUILD_DIAGNOSTICS is
 * defined.  They provide NTT roundtrip verification, polynomial
 * multiplication tests, and CPA encrypt/decrypt roundtrip diagnostics
 * for development validation — and rely on <stdio.h> printf, which
 * downstream embedded / FFI-only consumers cannot necessarily link.
 *
 * Gating rationale (separate from AMA_TESTING_MODE):
 *   AMA_TESTING_MODE enables generic test hooks (randombytes overrides
 *   for KAT determinism, etc.) that are valuable across the test suite
 *   but stay compact and quiet.  The Kyber diagnostic block is loud
 *   (printf-heavy), large (~600 lines), and only consumed by the
 *   focused tests/c/test_kyber_cpa.c harness.  Decoupling its gate
 *   keeps the production .so free of the diagnostic surface area
 *   while preserving the AMA_TESTING_MODE hooks the rest of the test
 *   suite depends on.  Default: OFF.  CMake enables it only when
 *   AMA_BUILD_TESTS is ON.
 *
 * Threat-model note: the printf calls expose intermediate polynomial
 * state to anyone with stdout access — including potentially a
 * reverser of a tools build.  Production builds MUST NOT define
 * AMA_KYBER_BUILD_DIAGNOSTICS.
 * ============================================================================ */
#ifdef AMA_KYBER_BUILD_DIAGNOSTICS
#include <stdio.h>

/* The diagnostics below are ML-KEM-1024-specific by construction: every
 * buffer in them is sized with AMA_ML_KEM_1024_* and every printed expectation
 * was derived for k = 4.  Rather than pretend they are parameter-generic,
 * they keep the old compile-time names as local aliases for the ML-KEM-1024
 * values, scoped to this block and #undef'd at its end.  A future diagnostic
 * for another parameter set gets its own aliases; nothing outside this block
 * can see these names, so the runtime parameter block stays the single source
 * of truth for the shipped code paths. */
#define KYBER_K    4
#define KYBER_ETA1 2
#define KYBER_ETA2 2
#define KYBER_DU   11
#define KYBER_DV   5
#define KYBER_DIAG_P (kyber_params_for(AMA_ML_KEM_1024))

/**
 * Debug: test NTT -> INVNTT roundtrip and polynomial arithmetic correctness.
 * Returns 0 if all sub-tests pass, 1 if any fails.
 */
int ama_kyber_debug_ntt_roundtrip(void) {
    poly a, b, c, d;
    int i;

    /* Test 0: Basic polynomial multiplication correctness.
     * a = [1, 0, 0, ...], b = [1, 0, 0, ...]
     * a * b should = [1, 0, 0, ...] in R_q = Z_q[X]/(X^256+1) */
    printf("  --- Poly mul test: [1,0,...] * [1,0,...] ---\n");
    memset(&a, 0, sizeof(a));  // PUBLIC-DATA: a (diag) — AMA_KYBER_BUILD_DIAGNOSTICS — test vector polynomial; gated out of production .so
    memset(&b, 0, sizeof(b));  // PUBLIC-DATA: b (diag) — AMA_KYBER_BUILD_DIAGNOSTICS — test vector polynomial; gated out of production .so
    a.coeffs[0] = 1;
    b.coeffs[0] = 1;

    memcpy(&c, &a, sizeof(poly));
    memcpy(&d, &b, sizeof(poly));
    poly_ntt(&c);
    poly_ntt(&d);

    printf("  NTT([1,0,...])[0..7]: %d %d %d %d %d %d %d %d\n",
           c.coeffs[0], c.coeffs[1], c.coeffs[2], c.coeffs[3],
           c.coeffs[4], c.coeffs[5], c.coeffs[6], c.coeffs[7]);

    poly result;
    poly_basemul(&result, &c, &d);
    printf("  basemul[0..7]: %d %d %d %d %d %d %d %d\n",
           result.coeffs[0], result.coeffs[1], result.coeffs[2], result.coeffs[3],
           result.coeffs[4], result.coeffs[5], result.coeffs[6], result.coeffs[7]);

    poly_invntt(&result);
    printf("  INVNTT(basemul)[0..7]: %d %d %d %d %d %d %d %d\n",
           coeff_normalize(result.coeffs[0]), coeff_normalize(result.coeffs[1]),
           coeff_normalize(result.coeffs[2]), coeff_normalize(result.coeffs[3]),
           coeff_normalize(result.coeffs[4]), coeff_normalize(result.coeffs[5]),
           coeff_normalize(result.coeffs[6]), coeff_normalize(result.coeffs[7]));
    printf("  Expected: [1, 0, 0, 0, ...]\n");

    /* Test 0b: [1,0,...] * [0,1,0,...] = [0,1,0,...] (X * 1 = X) */
    printf("  --- Poly mul test: [1,0,...] * [0,1,0,...] ---\n");
    memset(&b, 0, sizeof(b));  // PUBLIC-DATA: b (diag) — AMA_KYBER_BUILD_DIAGNOSTICS — roundtrip test vector
    b.coeffs[1] = 1;
    memcpy(&d, &b, sizeof(poly));
    poly_ntt(&d);
    poly_basemul(&result, &c, &d);
    poly_invntt(&result);
    printf("  Result[0..7]: %d %d %d %d %d %d %d %d\n",
           coeff_normalize(result.coeffs[0]), coeff_normalize(result.coeffs[1]),
           coeff_normalize(result.coeffs[2]), coeff_normalize(result.coeffs[3]),
           coeff_normalize(result.coeffs[4]), coeff_normalize(result.coeffs[5]),
           coeff_normalize(result.coeffs[6]), coeff_normalize(result.coeffs[7]));
    printf("  Expected: [0, 1, 0, 0, ...]\n");

    /* Test 0c: polyvec_basemul_acc (inner product, KYBER_K) test
     * s = ([1,0,...], [0,...], [0,...], [0,...])
     * u = ([3,0,...], [0,...], [0,...], [0,...])
     * s^T * u should = 3 */
    printf("  --- polyvec_basemul_acc test ---\n");
    {
        polyvec sv, uv;
        poly ip;
        memset(&sv, 0, sizeof(sv));  // PUBLIC-DATA: sv (diag) — AMA_KYBER_BUILD_DIAGNOSTICS — encryption test vector
        memset(&uv, 0, sizeof(uv));  // PUBLIC-DATA: uv (diag) — AMA_KYBER_BUILD_DIAGNOSTICS — encryption test vector
        sv.vec[0].coeffs[0] = 1;
        uv.vec[0].coeffs[0] = 3;

        /* NTT both */
        polyvec_ntt(&sv, KYBER_K);
        polyvec_ntt(&uv, KYBER_K);

        polyvec_basemul_acc(&ip, &sv, &uv, KYBER_K);
        poly_invntt(&ip);

        printf("  s^T*u[0..3]: %d %d %d %d (expected: 3 0 0 0)\n",
               coeff_normalize(ip.coeffs[0]), coeff_normalize(ip.coeffs[1]),
               coeff_normalize(ip.coeffs[2]), coeff_normalize(ip.coeffs[3]));
    }

    /* Test 0d: Manual keygen+encrypt+decrypt with trivial A=I, s=[1,...], e=0 */
    printf("  --- Trivial keygen/enc/dec test ---\n");
    {
        polyvec A[KYBER_K], sv, ev, pkpv_test;
        polyvec sp_test, ep_test, bp_test;
        poly epp_test, v_test, stu_test, mp_test;
        unsigned int ii;

        /* A = identity matrix (in NTT domain) */
        memset(A, 0, sizeof(A));  // PUBLIC-DATA: A (diag) — AMA_KYBER_BUILD_DIAGNOSTICS — test matrix
        for (ii = 0; ii < KYBER_K; ii++) {
            A[ii].vec[ii].coeffs[0] = 1;  /* A[i][i] = 1 polynomial */
            poly_ntt(&A[ii].vec[ii]);       /* Convert to NTT domain */
        }

        /* s = ([1,0,...], [0,...], [0,...], [0,...]) */
        memset(&sv, 0, sizeof(sv));  // PUBLIC-DATA: sv (diag) — AMA_KYBER_BUILD_DIAGNOSTICS — encapsulation test vector
        sv.vec[0].coeffs[0] = 1;
        polyvec_ntt(&sv, KYBER_K);

        /* e = zero */
        memset(&ev, 0, sizeof(ev));  // PUBLIC-DATA: ev (diag) — AMA_KYBER_BUILD_DIAGNOSTICS — encapsulation test vector
        polyvec_ntt(&ev, KYBER_K);

        /* t = A*s + e (in NTT domain) */
        for (ii = 0; ii < KYBER_K; ii++) {
            polyvec_basemul_acc(&pkpv_test.vec[ii], &A[ii], &sv, KYBER_K);
            poly_tomont(&pkpv_test.vec[ii]);
            poly_add(&pkpv_test.vec[ii], &pkpv_test.vec[ii], &ev.vec[ii]);
        }
        polyvec_reduce(&pkpv_test, KYBER_K);

        /* r = ([2,0,...], [0,...], ...) */
        memset(&sp_test, 0, sizeof(sp_test));  // PUBLIC-DATA: sp_test (diag) — AMA_KYBER_BUILD_DIAGNOSTICS — secret-portion test vector
        sp_test.vec[0].coeffs[0] = 2;
        polyvec_ntt(&sp_test, KYBER_K);

        /* e1 = 0, e2 = 0 */
        memset(&ep_test, 0, sizeof(ep_test));  // PUBLIC-DATA: ep_test (diag) — AMA_KYBER_BUILD_DIAGNOSTICS — error-portion test vector
        memset(&epp_test, 0, sizeof(epp_test));  // PUBLIC-DATA: epp_test (diag) — AMA_KYBER_BUILD_DIAGNOSTICS — error-prime-prime test vector

        /* u = INVNTT(A^T * r) + e1 */
        /* For A=I, A^T=I, so A^T*r = r. u should = [2,0,...] in vec[0] */
        for (ii = 0; ii < KYBER_K; ii++) {
            polyvec_basemul_acc(&bp_test.vec[ii], &A[ii], &sp_test, KYBER_K);
        }
        polyvec_invntt(&bp_test, KYBER_K);
        polyvec_add(&bp_test, &bp_test, &ep_test, KYBER_K);
        polyvec_reduce(&bp_test, KYBER_K);

        printf("  u[0][0..3]: %d %d %d %d (expected: 2 0 0 0)\n",
               coeff_normalize(bp_test.vec[0].coeffs[0]),
               coeff_normalize(bp_test.vec[0].coeffs[1]),
               coeff_normalize(bp_test.vec[0].coeffs[2]),
               coeff_normalize(bp_test.vec[0].coeffs[3]));

        /* v = INVNTT(t^T * r) + e2 + m */
        /* t = s = [1,0,...] in vec[0], r = [2,0,...] in vec[0]
         * t^T * r = 1*2 = 2 (constant poly). v should = [2+msg_coeff,0,...] */
        polyvec_basemul_acc(&v_test, &pkpv_test, &sp_test, KYBER_K);
        poly_invntt(&v_test);
        poly_add(&v_test, &v_test, &epp_test);

        /* Add message = all zeros for simplicity */
        memset(&mp_test, 0, sizeof(mp_test));  // PUBLIC-DATA: mp_test (diag) — AMA_KYBER_BUILD_DIAGNOSTICS — message polynomial test vector
        poly_add(&v_test, &v_test, &mp_test);
        poly_reduce(&v_test);

        printf("  v[0..3]: %d %d %d %d (expected: 2 0 0 0)\n",
               coeff_normalize(v_test.coeffs[0]),
               coeff_normalize(v_test.coeffs[1]),
               coeff_normalize(v_test.coeffs[2]),
               coeff_normalize(v_test.coeffs[3]));

        /* Decrypt: s^T * u */
        polyvec_ntt(&bp_test, KYBER_K);
        polyvec_basemul_acc(&stu_test, &sv, &bp_test, KYBER_K);
        poly_invntt(&stu_test);

        printf("  s^T*u[0..3]: %d %d %d %d (expected: 2 0 0 0)\n",
               coeff_normalize(stu_test.coeffs[0]),
               coeff_normalize(stu_test.coeffs[1]),
               coeff_normalize(stu_test.coeffs[2]),
               coeff_normalize(stu_test.coeffs[3]));

        /* v - s^T*u */
        poly_sub(&stu_test, &v_test, &stu_test);
        poly_reduce(&stu_test);

        printf("  v-s^T*u[0..3]: %d %d %d %d (expected: 0 0 0 0)\n",
               coeff_normalize(stu_test.coeffs[0]),
               coeff_normalize(stu_test.coeffs[1]),
               coeff_normalize(stu_test.coeffs[2]),
               coeff_normalize(stu_test.coeffs[3]));
    }

    /* Test 0e: Non-trivial polynomial multiplication verification
     * Multiply two known polynomials using NTT/basemul/INVNTT vs naive */
    printf("  --- Non-trivial poly mul test ---\n");
    {
        poly pa, pb, pc_ntt, pc_naive;
        int pi;

        /* pa = [1, 2, 3, 4, 0, 0, ...], pb = [5, 6, 0, ...] */
        memset(&pa, 0, sizeof(pa));  // PUBLIC-DATA: pa (diag) — AMA_KYBER_BUILD_DIAGNOSTICS — schoolbook test matrix
        memset(&pb, 0, sizeof(pb));  // PUBLIC-DATA: pb (diag) — AMA_KYBER_BUILD_DIAGNOSTICS — schoolbook test matrix
        pa.coeffs[0] = 1; pa.coeffs[1] = 2; pa.coeffs[2] = 3; pa.coeffs[3] = 4;
        pb.coeffs[0] = 5; pb.coeffs[1] = 6;

        /* NTT multiplication */
        poly pa_ntt, pb_ntt;
        memcpy(&pa_ntt, &pa, sizeof(poly));
        memcpy(&pb_ntt, &pb, sizeof(poly));
        poly_ntt(&pa_ntt);
        poly_ntt(&pb_ntt);
        poly_basemul(&pc_ntt, &pa_ntt, &pb_ntt);
        poly_invntt(&pc_ntt);

        /* Naive multiplication in Z_q[X]/(X^256+1) */
        memset(&pc_naive, 0, sizeof(pc_naive));  // PUBLIC-DATA: pc_naive (diag) — AMA_KYBER_BUILD_DIAGNOSTICS — naive multiply result
        for (pi = 0; pi < KYBER_N; pi++) {
            if (pa.coeffs[pi] == 0) continue;
            int pj;
            for (pj = 0; pj < KYBER_N; pj++) {
                if (pb.coeffs[pj] == 0) continue;
                int idx = pi + pj;
                if (idx < KYBER_N) {
                    pc_naive.coeffs[idx] = (int16_t)((pc_naive.coeffs[idx] +
                        (int32_t)pa.coeffs[pi] * pb.coeffs[pj]) % KYBER_Q);
                } else {
                    /* X^256 = -1 in the ring */
                    idx -= KYBER_N;
                    pc_naive.coeffs[idx] = (int16_t)((pc_naive.coeffs[idx] -
                        (int32_t)pa.coeffs[pi] * pb.coeffs[pj]) % KYBER_Q);
                }
            }
        }

        /* Compare */
        printf("  NTT result[0..5]:   %d %d %d %d %d %d\n",
               coeff_normalize(pc_ntt.coeffs[0]), coeff_normalize(pc_ntt.coeffs[1]),
               coeff_normalize(pc_ntt.coeffs[2]), coeff_normalize(pc_ntt.coeffs[3]),
               coeff_normalize(pc_ntt.coeffs[4]), coeff_normalize(pc_ntt.coeffs[5]));
        printf("  Naive result[0..5]: %d %d %d %d %d %d\n",
               coeff_normalize(pc_naive.coeffs[0]), coeff_normalize(pc_naive.coeffs[1]),
               coeff_normalize(pc_naive.coeffs[2]), coeff_normalize(pc_naive.coeffs[3]),
               coeff_normalize(pc_naive.coeffs[4]), coeff_normalize(pc_naive.coeffs[5]));
        /* (1+2x+3x^2+4x^3)(5+6x) = 5+16x+27x^2+38x^3+24x^4 */
        printf("  Expected:           5 16 27 38 24 0\n");

        int match_pm = 1;
        for (pi = 0; pi < KYBER_N; pi++) {
            if (coeff_normalize(pc_ntt.coeffs[pi]) != coeff_normalize(pc_naive.coeffs[pi])) {
                match_pm = 0;
                break;
            }
        }
        printf("  Poly mul match: %s\n", match_pm ? "YES" : "NO");

        /* Test with larger values (uniform-like) */
        printf("  --- Large-coeff poly mul test ---\n");
        for (pi = 0; pi < KYBER_N; pi++) {
            pa.coeffs[pi] = (int16_t)((pi * 1234 + 567) % KYBER_Q);
            pb.coeffs[pi] = (int16_t)((pi * 891 + 123) % KYBER_Q);
        }
        memcpy(&pa_ntt, &pa, sizeof(poly));
        memcpy(&pb_ntt, &pb, sizeof(poly));
        poly_ntt(&pa_ntt);
        poly_ntt(&pb_ntt);
        poly_basemul(&pc_ntt, &pa_ntt, &pb_ntt);
        poly_invntt(&pc_ntt);

        /* Naive multiplication */
        memset(&pc_naive, 0, sizeof(pc_naive));  // PUBLIC-DATA: pc_naive (diag) — AMA_KYBER_BUILD_DIAGNOSTICS — naive multiply result
        for (pi = 0; pi < KYBER_N; pi++) {
            int pj;
            for (pj = 0; pj < KYBER_N; pj++) {
                int idx = pi + pj;
                int32_t prod = (int32_t)pa.coeffs[pi] * pb.coeffs[pj];
                if (idx < KYBER_N) {
                    pc_naive.coeffs[idx] = (int16_t)(((int32_t)pc_naive.coeffs[idx] + prod) % KYBER_Q);
                } else {
                    idx -= KYBER_N;
                    pc_naive.coeffs[idx] = (int16_t)(((int32_t)pc_naive.coeffs[idx] - prod) % KYBER_Q);
                }
            }
        }

        match_pm = 1;
        int first_mismatch = -1;
        for (pi = 0; pi < KYBER_N; pi++) {
            if (coeff_normalize(pc_ntt.coeffs[pi]) != coeff_normalize(pc_naive.coeffs[pi])) {
                match_pm = 0;
                if (first_mismatch < 0) first_mismatch = pi;
            }
        }
        printf("  Large poly mul match: %s", match_pm ? "YES" : "NO");
        if (!match_pm) {
            printf(" (first mismatch at [%d]: NTT=%d, naive=%d)",
                   first_mismatch,
                   coeff_normalize(pc_ntt.coeffs[first_mismatch]),
                   coeff_normalize(pc_naive.coeffs[first_mismatch]));
        }
        printf("\n");
    }

    /* Test 0f: Manual keygen with non-trivial values
     * Construct A, s, e manually, do CPA encrypt/decrypt */
    printf("  --- Manual keygen with non-trivial values ---\n");
    {
        polyvec A_man[KYBER_K], s_man, e_man, t_man;
        polyvec sp_man, ep_man, bp_man;
        poly epp_man, v_man, stu_man, mp_man;
        unsigned int ii, jj;

        /* A = simple known matrix (each entry is a constant polynomial) */
        memset(A_man, 0, sizeof(A_man));  // PUBLIC-DATA: A_man (diag) — AMA_KYBER_BUILD_DIAGNOSTICS — manual-encoding test matrix
        for (ii = 0; ii < KYBER_K; ii++) {
            for (jj = 0; jj < KYBER_K; jj++) {
                A_man[ii].vec[jj].coeffs[0] = (int16_t)((ii * KYBER_K + jj + 1) % KYBER_Q);
                poly_ntt(&A_man[ii].vec[jj]);
            }
        }

        /* s = ([1, -1, 0, ...], [2, 0, ...], [0, 1, ...], [-1, 0, ...]) */
        memset(&s_man, 0, sizeof(s_man));  // PUBLIC-DATA: s_man (diag) — AMA_KYBER_BUILD_DIAGNOSTICS — manual test vector
        s_man.vec[0].coeffs[0] = 1; s_man.vec[0].coeffs[1] = -1;
        s_man.vec[1].coeffs[0] = 2;
        s_man.vec[2].coeffs[1] = 1;
        s_man.vec[3].coeffs[0] = -1;
        polyvec_ntt(&s_man, KYBER_K);

        /* e = zero for simplicity */
        memset(&e_man, 0, sizeof(e_man));  // PUBLIC-DATA: e_man (diag) — AMA_KYBER_BUILD_DIAGNOSTICS — manual test vector
        polyvec_ntt(&e_man, KYBER_K);

        /* t = A*s + e (NTT domain) */
        for (ii = 0; ii < KYBER_K; ii++) {
            polyvec_basemul_acc(&t_man.vec[ii], &A_man[ii], &s_man, KYBER_K);
            poly_tomont(&t_man.vec[ii]);
            poly_add(&t_man.vec[ii], &t_man.vec[ii], &e_man.vec[ii]);
        }
        polyvec_reduce(&t_man, KYBER_K);

        /* r = ([1, 0, ...], [0, ...], [0, ...], [0, ...]) */
        memset(&sp_man, 0, sizeof(sp_man));  // PUBLIC-DATA: sp_man (diag) — AMA_KYBER_BUILD_DIAGNOSTICS — manual test vector
        sp_man.vec[0].coeffs[0] = 1;
        polyvec_ntt(&sp_man, KYBER_K);

        /* e1 = 0, e2 = 0 */
        memset(&ep_man, 0, sizeof(ep_man));  // PUBLIC-DATA: ep_man (diag) — AMA_KYBER_BUILD_DIAGNOSTICS — manual test vector
        memset(&epp_man, 0, sizeof(epp_man));  // PUBLIC-DATA: epp_man (diag) — AMA_KYBER_BUILD_DIAGNOSTICS — manual test vector

        /* Encrypt: u = INVNTT(A^T * r) + e1, v = INVNTT(t^T * r) + e2 + m */
        /* A^T: transpose A_man */
        polyvec A_T[KYBER_K];
        for (ii = 0; ii < KYBER_K; ii++)
            for (jj = 0; jj < KYBER_K; jj++)
                memcpy(&A_T[ii].vec[jj], &A_man[jj].vec[ii], sizeof(poly));

        for (ii = 0; ii < KYBER_K; ii++) {
            polyvec_basemul_acc(&bp_man.vec[ii], &A_T[ii], &sp_man, KYBER_K);
        }
        polyvec_invntt(&bp_man, KYBER_K);
        polyvec_add(&bp_man, &bp_man, &ep_man, KYBER_K);
        polyvec_reduce(&bp_man, KYBER_K);

        polyvec_basemul_acc(&v_man, &t_man, &sp_man, KYBER_K);
        poly_invntt(&v_man);
        poly_add(&v_man, &v_man, &epp_man);

        /* Add message = 0xAB */
        memset(&mp_man, 0, sizeof(mp_man));  // PUBLIC-DATA: mp_man (diag) — AMA_KYBER_BUILD_DIAGNOSTICS — manual message polynomial test
        uint8_t test_msg[32];
        memset(test_msg, 0xAB, 32);
        for (ii = 0; ii < 32; ii++) {
            for (jj = 0; jj < 8; jj++) {
                mp_man.coeffs[8*ii + jj] = (int16_t)(((test_msg[ii] >> jj) & 1) *
                                                       ((KYBER_Q + 1) / 2));
            }
        }
        poly_add(&v_man, &v_man, &mp_man);
        poly_reduce(&v_man);

        /* Decrypt: s^T * u */
        polyvec_ntt(&bp_man, KYBER_K);
        polyvec_basemul_acc(&stu_man, &s_man, &bp_man, KYBER_K);
        poly_invntt(&stu_man);

        poly_sub(&stu_man, &v_man, &stu_man);
        poly_reduce(&stu_man);

        printf("  Manual residual[0..7]:");
        for (ii = 0; ii < 8; ii++) {
            int16_t cv = coeff_normalize(stu_man.coeffs[ii]);
            int ctr = (int)cv;
            if (ctr > KYBER_Q/2) ctr -= KYBER_Q;
            printf(" %d", ctr);
        }
        printf("\n");
        printf("  Expected ~1665/-1665 for 1-bits, ~0 for 0-bits\n");

        /* Decode message */
        uint8_t m_test[32];
        for (ii = 0; ii < 32; ii++) {
            m_test[ii] = 0;
            for (jj = 0; jj < 8; jj++) {
                int16_t tv = coeff_normalize(stu_man.coeffs[8*ii + jj]);
                tv = (int16_t)kyber_compress_d((uint32_t)tv, 1);
                m_test[ii] |= (uint8_t)((tv & 1) << jj);
            }
        }
        int man_match = (memcmp(test_msg, m_test, 32) == 0);
        printf("  Manual CPA: %s\n", man_match ? "PASS" : "FAIL");
        if (!man_match) {
            printf("  m_orig: %02X, m_recov: %02X\n", test_msg[0], m_test[0]);
        }
    }

    /* Test 0g: Detailed keygen consistency test */
    printf("  --- Detailed keygen consistency ---\n");
    {
        uint8_t pk3[AMA_KYBER_1024_PUBLIC_KEY_BYTES];
        uint8_t sk3[AMA_KYBER_1024_SECRET_KEY_BYTES];
        polyvec A3[KYBER_K], s3, t3, as3;
        const uint8_t *rho3;

        ama_error_t rc3 = kyber_keygen_internal(KYBER_DIAG_P, pk3, sizeof(pk3),
                                                sk3, sizeof(sk3), NULL, NULL);
        if (rc3 != AMA_SUCCESS) { printf("    keygen failed\n"); }

        rho3 = pk3 + KYBER_K * 384;
        polyvec_frombytes(&t3, pk3, KYBER_K);     /* t_hat from pk */
        polyvec_frombytes(&s3, sk3, KYBER_K);     /* s_hat from sk */

        /* Regenerate A */
        kyber_gen_matrix(A3, rho3, 0, KYBER_DIAG_P);

        /* Recompute A*s */
        unsigned int ki;
        for (ki = 0; ki < KYBER_K; ki++) {
            polyvec_basemul_acc(&as3.vec[ki], &A3[ki], &s3, KYBER_K);
            poly_tomont(&as3.vec[ki]);
        }
        polyvec_reduce(&as3, KYBER_K);

        /* Compare as3 with t3 (they should differ only by NTT(e)) */
        /* But we can't check NTT(e) directly. Instead test the full roundtrip: */
        /* Encrypt with t3, s3, A3 then decrypt with s3 */
        polyvec sp3, ep3, bp3;
        poly epp3, v3, stu3, mp3;
        uint8_t msg3[32], msg_dec3[32];
        memset(msg3, 0xAB, 32);
        memset(&sp3, 0, sizeof(sp3));  // PUBLIC-DATA: sp3 (diag) — AMA_KYBER_BUILD_DIAGNOSTICS — round-3 test vector
        sp3.vec[0].coeffs[0] = 1; /* Simple r */
        polyvec_ntt(&sp3, KYBER_K);
        memset(&ep3, 0, sizeof(ep3));  // PUBLIC-DATA: ep3 (diag) — AMA_KYBER_BUILD_DIAGNOSTICS — round-3 test vector
        memset(&epp3, 0, sizeof(epp3));  // PUBLIC-DATA: epp3 (diag) — AMA_KYBER_BUILD_DIAGNOSTICS — round-3 test vector

        /* A^T for encryption */
        polyvec A3T[KYBER_K];
        for (ki = 0; ki < KYBER_K; ki++) {
            unsigned int kj;
            for (kj = 0; kj < KYBER_K; kj++)
                kyber_poly_uniform(&A3T[ki].vec[kj], rho3, (uint8_t)ki, (uint8_t)kj);
        }

        /* u = INVNTT(A^T * r) */
        for (ki = 0; ki < KYBER_K; ki++) {
            polyvec_basemul_acc(&bp3.vec[ki], &A3T[ki], &sp3, KYBER_K);
        }
        polyvec_invntt(&bp3, KYBER_K);
        polyvec_reduce(&bp3, KYBER_K);

        printf("    u[0][0..3]: %d %d %d %d\n",
               coeff_normalize(bp3.vec[0].coeffs[0]),
               coeff_normalize(bp3.vec[0].coeffs[1]),
               coeff_normalize(bp3.vec[0].coeffs[2]),
               coeff_normalize(bp3.vec[0].coeffs[3]));

        /* v = INVNTT(t^T * r) + msg */
        polyvec_basemul_acc(&v3, &t3, &sp3, KYBER_K);
        poly_invntt(&v3);
        memset(&mp3, 0, sizeof(mp3));  // PUBLIC-DATA: mp3 (diag) — AMA_KYBER_BUILD_DIAGNOSTICS — round-3 message polynomial test
        for (ki = 0; ki < 32; ki++) {
            unsigned int kj;
            for (kj = 0; kj < 8; kj++)
                mp3.coeffs[8*ki + kj] = (int16_t)(((msg3[ki] >> kj) & 1) * ((KYBER_Q+1)/2));
        }
        poly_add(&v3, &v3, &mp3);
        poly_reduce(&v3);

        /* Decrypt: s^T * u */
        polyvec_ntt(&bp3, KYBER_K);
        polyvec_basemul_acc(&stu3, &s3, &bp3, KYBER_K);
        poly_invntt(&stu3);
        poly_sub(&stu3, &v3, &stu3);
        poly_reduce(&stu3);

        printf("    v-s^T*u[0..7]:");
        for (ki = 0; ki < 8; ki++) {
            int16_t cv2 = coeff_normalize(stu3.coeffs[ki]);
            int ctr2 = (int)cv2;
            if (ctr2 > KYBER_Q/2) ctr2 -= KYBER_Q;
            printf(" %d", ctr2);
        }
        printf("\n");

        /* Decode */
        for (ki = 0; ki < 32; ki++) {
            msg_dec3[ki] = 0;
            unsigned int kj;
            for (kj = 0; kj < 8; kj++) {
                int16_t tv2 = coeff_normalize(stu3.coeffs[8*ki + kj]);
                tv2 = (int16_t)kyber_compress_d((uint32_t)tv2, 1);
                msg_dec3[ki] |= (uint8_t)((tv2 & 1) << kj);
            }
        }
        int m3 = (memcmp(msg3, msg_dec3, 32) == 0);
        printf("    Keygen-based CPA: %s (m_dec[0]=%02X)\n",
               m3 ? "PASS" : "FAIL", msg_dec3[0]);
    }

    /* Test 0h: Verify keygen correctness
     * Check that t_hat = basemul(A, s_hat)*tomont + e_hat where INVNTT(e_hat) is small */
    printf("  --- Keygen verification test ---\n");
    {
        uint8_t pk2[AMA_KYBER_1024_PUBLIC_KEY_BYTES];
        uint8_t sk2[AMA_KYBER_1024_SECRET_KEY_BYTES];
        polyvec A2[KYBER_K], s_hat, t_hat, as_hat;
        const uint8_t *rho2;

        ama_error_t rc2 = kyber_keygen_internal(KYBER_DIAG_P, pk2, sizeof(pk2), sk2, sizeof(sk2), NULL, NULL);
        if (rc2 != AMA_SUCCESS) { printf("    keygen failed\n"); return 1; }

        rho2 = pk2 + KYBER_K * 384;
        polyvec_frombytes(&t_hat, pk2, KYBER_K);
        polyvec_frombytes(&s_hat, sk2, KYBER_K);
        kyber_gen_matrix(A2, rho2, 0, KYBER_DIAG_P);  /* Non-transposed A */

        /* Compute A*s in NTT domain */
        unsigned int ki;
        for (ki = 0; ki < KYBER_K; ki++) {
            polyvec_basemul_acc(&as_hat.vec[ki], &A2[ki], &s_hat, KYBER_K);
            poly_tomont(&as_hat.vec[ki]);
        }
        polyvec_reduce(&as_hat, KYBER_K);

        /* e_hat = t_hat - A*s (in NTT domain) */
        polyvec e_hat;
        for (ki = 0; ki < KYBER_K; ki++) {
            poly_sub(&e_hat.vec[ki], &t_hat.vec[ki], &as_hat.vec[ki]);
        }

        /* INVNTT(e_hat) should give e with small coefficients [-2,2] */
        polyvec_invntt(&e_hat, KYBER_K);
        int max_e = 0;
        for (ki = 0; ki < KYBER_K; ki++) {
            for (int ci = 0; ci < KYBER_N; ci++) {
                int16_t val = coeff_normalize(e_hat.vec[ki].coeffs[ci]);
                /* Map to centered: if val > q/2, val -= q */
                int centered = (int)val;
                if (centered > KYBER_Q / 2) centered -= KYBER_Q;
                if (abs(centered) > max_e) max_e = abs(centered);
            }
        }
        printf("    max |INVNTT(e_hat)| = %d (should be <= 2 for eta=2)\n", max_e);

        /* Also show first few coefficients */
        printf("    INVNTT(e_hat)[0][0..7]:");
        for (int ci = 0; ci < 8; ci++) {
            int16_t val = coeff_normalize(e_hat.vec[0].coeffs[ci]);
            int centered = (int)val;
            if (centered > KYBER_Q / 2) centered -= KYBER_Q;
            printf(" %d", centered);
        }
        printf("\n");
    }

    /* Test 1: NTT roundtrip (expected: x -> x*R where R=2285) */
    printf("  --- NTT->INVNTT roundtrip ---\n");
    for (i = 0; i < KYBER_N; i++) {
        a.coeffs[i] = (int16_t)(i % KYBER_Q);
    }
    memcpy(&b, &a, sizeof(poly));
    poly_ntt(&b);
    poly_invntt(&b);

    /* Check if result = a * R mod q */
    int max_diff_r = 0;
    for (i = 0; i < KYBER_N; i++) {
        int16_t orig = coeff_normalize(a.coeffs[i]);
        int16_t recovered = coeff_normalize(b.coeffs[i]);
        int16_t expected = (int16_t)(((int32_t)orig * 2285) % KYBER_Q);
        int diff = abs((int)expected - (int)recovered);
        if (diff > KYBER_Q / 2) diff = KYBER_Q - diff;
        if (diff > max_diff_r) max_diff_r = diff;
    }
    printf("  NTT->INVNTT vs a*R: max_diff=%d (should be 0)\n", max_diff_r);
    printf("  a[0..3]: %d %d %d %d\n", a.coeffs[0], a.coeffs[1], a.coeffs[2], a.coeffs[3]);
    printf("  b[0..3]: %d %d %d %d (after NTT->INVNTT)\n",
           coeff_normalize(b.coeffs[0]), coeff_normalize(b.coeffs[1]),
           coeff_normalize(b.coeffs[2]), coeff_normalize(b.coeffs[3]));
    printf("  Expected (a*R): %d %d %d %d\n",
           (int)(0*2285%KYBER_Q), (int)(1*2285%KYBER_Q),
           (int)(2*2285%KYBER_Q), (int)(3*2285%KYBER_Q));

    return (max_diff_r == 0) ? 0 : 1;
}

int ama_kyber_debug_cpa_roundtrip(void) {
#ifdef AMA_USE_NATIVE_PQC
    uint8_t pk[AMA_KYBER_1024_PUBLIC_KEY_BYTES];
    uint8_t sk[AMA_KYBER_1024_SECRET_KEY_BYTES];
    unsigned int i;
    const uint8_t *rho;

    /* Generate keypair */
    ama_error_t rc = kyber_keygen_internal(KYBER_DIAG_P, pk, sizeof(pk), sk, sizeof(sk), NULL, NULL);
    if (rc != AMA_SUCCESS) { printf("  CPA: keygen failed\n"); return 1; }

    /* === Test 1: Inline CPA encrypt/decrypt WITHOUT compression === */
    printf("  --- Test 1: No-compression CPA roundtrip ---\n");
    {
        polyvec a[KYBER_K], sp, ep;
        poly epp, mp_poly, v_poly, stu_poly;
        polyvec bp_enc;
        uint8_t m_orig[32], m_recov[32], coins[32];
        polyvec skpv, pkpv;

        memset(m_orig, 0xAB, 32);
        memset(coins, 0xCD, 32);

        /* Parse keys */
        rho = pk + KYBER_K * 384;
        polyvec_frombytes(&pkpv, pk, KYBER_K);
        polyvec_frombytes(&skpv, sk, KYBER_K);

        /* Generate matrix A^T */
        kyber_gen_matrix(a, rho, 1, KYBER_DIAG_P);

        /* Sample r, e1, e2 from coins */
        kyber_gennoise(&sp, coins, 0, KYBER_K, KYBER_ETA1);
        kyber_gennoise(&ep, coins, (uint8_t)KYBER_K, KYBER_K, KYBER_ETA1);
        {
            uint8_t noise_buf[33];
            uint8_t noise_stream[KYBER_ETA2 * KYBER_N / 4];
            memcpy(noise_buf, coins, 32);
            noise_buf[32] = 2 * (uint8_t)KYBER_K;
            ama_shake256(noise_buf, 33, noise_stream, sizeof(noise_stream));
            kyber_poly_cbd_eta(&epp, noise_stream);
        }

        /* NTT(r) */
        polyvec_ntt(&sp, KYBER_K);

        /* Compute u = INVNTT(A^T * r) + e1 */
        for (i = 0; i < KYBER_K; i++) {
            polyvec_basemul_acc(&bp_enc.vec[i], &a[i], &sp, KYBER_K);
        }
        polyvec_invntt(&bp_enc, KYBER_K);
        polyvec_add(&bp_enc, &bp_enc, &ep, KYBER_K);
        polyvec_reduce(&bp_enc, KYBER_K);

        /* Compute v = INVNTT(t^T * r) + e2 + m_poly */
        polyvec_basemul_acc(&v_poly, &pkpv, &sp, KYBER_K);
        poly_invntt(&v_poly);
        poly_add(&v_poly, &v_poly, &epp);

        memset(&mp_poly, 0, sizeof(mp_poly));  // PUBLIC-DATA: mp_poly — ML-KEM CPA decryption message polynomial, pre-use init filled by decapsulate
        for (i = 0; i < 32; i++) {
            unsigned int j;
            for (j = 0; j < 8; j++) {
                mp_poly.coeffs[8*i + j] = (int16_t)(((m_orig[i] >> j) & 1) *
                                                      ((KYBER_Q + 1) / 2));
            }
        }
        poly_add(&v_poly, &v_poly, &mp_poly);
        poly_reduce(&v_poly);

        /* --- Now decrypt (no compression) --- */
        /* Compute s^T * u: NTT(u), basemul(s, NTT(u)), INVNTT */
        polyvec_ntt(&bp_enc, KYBER_K);
        polyvec_basemul_acc(&stu_poly, &skpv, &bp_enc, KYBER_K);
        poly_invntt(&stu_poly);

        /* v - s^T * u */
        poly_sub(&stu_poly, &v_poly, &stu_poly);
        poly_reduce(&stu_poly);

        /* Show residual */
        printf("  Residual coeffs[0..7]:");
        for (i = 0; i < 8; i++) {
            printf(" %d", coeff_normalize(stu_poly.coeffs[i]));
        }
        printf("\n");
        printf("  Expected: ~1665 for 1-bits, ~0 for 0-bits (0xAB=11010101)\n");

        /* Decode message */
        for (i = 0; i < 32; i++) {
            m_recov[i] = 0;
            unsigned int j;
            for (j = 0; j < 8; j++) {
                int16_t t = coeff_normalize(stu_poly.coeffs[8*i + j]);
                t = (int16_t)kyber_compress_d((uint32_t)t, 1);
                m_recov[i] |= (uint8_t)((t & 1) << j);
            }
        }

        int match = (memcmp(m_orig, m_recov, 32) == 0);
        printf("  No-compress CPA: %s\n", match ? "PASS" : "FAIL");
        if (!match) {
            printf("  m_orig[0..3]:  %02X %02X %02X %02X\n",
                   m_orig[0], m_orig[1], m_orig[2], m_orig[3]);
            printf("  m_recov[0..3]: %02X %02X %02X %02X\n",
                   m_recov[0], m_recov[1], m_recov[2], m_recov[3]);
            return 1;
        }
    }

    /* === Test 2: Full CPA with compression (original test) === */
    printf("  --- Test 2: With-compression CPA roundtrip ---\n");
    {
        uint8_t ct[AMA_KYBER_1024_CIPHERTEXT_BYTES];
        uint8_t m_orig[32], m_recov[32], coins[32];
        polyvec bp, skpv;
        poly v, mp;

        memset(m_orig, 0xAB, 32);
        memset(coins, 0xCD, 32);

        polyvec_frombytes(&skpv, sk, KYBER_K);
        kyber_cpapke_enc(ct, m_orig, pk, coins, KYBER_DIAG_P);

        polyvec_decompress(&bp, ct, KYBER_DIAG_P);
        poly_decompress(&v, ct + KYBER_K * (KYBER_N * KYBER_DU / 8), KYBER_DV);

        polyvec_ntt(&bp, KYBER_K);
        polyvec_basemul_acc(&mp, &skpv, &bp, KYBER_K);
        poly_invntt(&mp);

        poly_sub(&mp, &v, &mp);
        poly_reduce(&mp);

        printf("  Residual coeffs[0..7]:");
        for (i = 0; i < 8; i++) {
            printf(" %d", coeff_normalize(mp.coeffs[i]));
        }
        printf("\n");

        for (i = 0; i < 32; i++) {
            m_recov[i] = 0;
            unsigned int j;
            for (j = 0; j < 8; j++) {
                int16_t t = coeff_normalize(mp.coeffs[8*i + j]);
                t = (int16_t)kyber_compress_d((uint32_t)t, 1);
                m_recov[i] |= (uint8_t)((t & 1) << j);
            }
        }

        int match = (memcmp(m_orig, m_recov, 32) == 0);
        printf("  With-compress CPA: %s\n", match ? "PASS" : "FAIL");
        if (!match) {
            printf("  m_orig[0..3]:  %02X %02X %02X %02X\n",
                   m_orig[0], m_orig[1], m_orig[2], m_orig[3]);
            printf("  m_recov[0..3]: %02X %02X %02X %02X\n",
                   m_recov[0], m_recov[1], m_recov[2], m_recov[3]);
        }
        return match ? 0 : 1;
    }
#else
    return 1;
#endif
}

#undef KYBER_K
#undef KYBER_ETA1
#undef KYBER_ETA2
#undef KYBER_DU
#undef KYBER_DV
#undef KYBER_DIAG_P
#endif /* AMA_KYBER_BUILD_DIAGNOSTICS - end of debug/test functions */

/* ============================================================================
 * PUBLIC API — PARAMETER-DRIVEN (ML-KEM-512 / -768 / -1024)
 *
 * The legacy `ama_kyber_*` entry points below are preserved as thin wrappers
 * pinned to ML-KEM-1024.  They are the ABI every existing caller and every
 * existing test uses, and pinning them keeps that behaviour bit-exact: adding
 * parameter sets must not change what an existing call does.
 * ============================================================================ */

AMA_API size_t ama_ml_kem_public_key_bytes(ama_ml_kem_param_set_t ps) {
    const kyber_params *P = kyber_params_for(ps);
    return P ? P->pk_bytes : 0u;
}

AMA_API size_t ama_ml_kem_secret_key_bytes(ama_ml_kem_param_set_t ps) {
    const kyber_params *P = kyber_params_for(ps);
    return P ? P->sk_bytes : 0u;
}

AMA_API size_t ama_ml_kem_ciphertext_bytes(ama_ml_kem_param_set_t ps) {
    const kyber_params *P = kyber_params_for(ps);
    return P ? P->ct_bytes : 0u;
}

AMA_API const char *ama_ml_kem_param_set_name(ama_ml_kem_param_set_t ps) {
    const kyber_params *P = kyber_params_for(ps);
    return P ? P->name : NULL;
}

AMA_API ama_error_t ama_ml_kem_keypair(ama_ml_kem_param_set_t ps,
                                       uint8_t *pk, size_t pk_len,
                                       uint8_t *sk, size_t sk_len) {
    const kyber_params *P = kyber_params_for(ps);
    if (!P) return AMA_ERROR_INVALID_PARAM;
    return kyber_keygen_internal(P, pk, pk_len, sk, sk_len, NULL, NULL);
}

AMA_API ama_error_t ama_ml_kem_keypair_from_seed(ama_ml_kem_param_set_t ps,
                                                 const uint8_t d[32],
                                                 const uint8_t z[32],
                                                 uint8_t *pk, size_t pk_len,
                                                 uint8_t *sk, size_t sk_len) {
    const kyber_params *P = kyber_params_for(ps);
    if (!P || !d || !z) return AMA_ERROR_INVALID_PARAM;
    return kyber_keygen_internal(P, pk, pk_len, sk, sk_len, d, z);
}

/**
 * Recover the encapsulation key embedded in an ML-KEM decapsulation key, and
 * check the decapsulation key's internal consistency while doing it.
 *
 * FIPS 203 §7.1 lays the decapsulation key out as
 * `dk_PKE || ek || H(ek) || z`, so the encapsulation key is present verbatim
 * and needs no recomputation — but three of those four fields are mutually
 * redundant, and a key whose fields disagree is one that decapsulates to a
 * shared secret the sender never derived.  Because ML-KEM's implicit rejection
 * (Algorithm 18 line 8) is *designed* to fail silently, that mismatch produces
 * no error anywhere downstream: the two parties simply hold different secrets
 * and the failure surfaces as an unexplained protocol error much later.  This
 * is the only place it can be caught.
 *
 * Two checks, matching the two failure shapes that
 * draft-ietf-lamps-kyber-certificates Appendix C.4.1 ships vectors for:
 *
 *  1. `H(ek)` must be SHA3-256 of the embedded `ek`.  Catches a mutated
 *     digest field (example 3), and is cheap enough to be unconditional.
 *  2. A pairwise consistency check — encapsulate to `ek`, decapsulate with
 *     `dk`, require the two shared secrets to agree.  Catches a mutated
 *     `dk_PKE` that left a correct digest behind (example 2), which check 1
 *     cannot see.  This is the same operation FIPS 140-3 requires as a
 *     key-pair consistency test.
 *
 * **This predicate consumes no entropy.**  The pairwise check encapsulates
 * under the fixed message `KYBER_PCT_M` rather than a random one, so it is a
 * pure function of the key it is handed.  That is not a nicety:
 *
 *  - It is reachable from a *file parser* (`load_pkcs8` of an `expandedKey`-only
 *    ML-KEM key), so with a random `m` anyone who can hand you a key file could
 *    draw 32 bytes from the CSPRNG per import.
 *  - A validation predicate that is not reproducible cannot be a KAT, and a
 *    FIPS 140-3 self-test that depends on the RNG cannot run before the RNG's
 *    own health checks have.
 *  - A non-deterministic checker turns any latent failure into a flake.
 *
 * The fixed `m` costs nothing in soundness.  `m` is an *input* to Algorithm 17;
 * the check's power comes from the round trip agreeing, and a `dk_PKE` mutation
 * that survives decapsulation of a correctly-formed ciphertext for one `m`
 * survives it for essentially all of them (decapsulation failure is a property
 * of the key, not of the message).  Nothing derived from `m` leaves this
 * function: the ciphertext and both shared secrets are scrubbed before return.
 *
 * @param public_key  May be NULL to check without emitting the encapsulation
 *                    key.  When non-NULL it must have room for `pk_bytes`.
 * @return AMA_SUCCESS if consistent; AMA_ERROR_INVALID_PARAM for a NULL or
 *         wrong-length argument; AMA_ERROR_VERIFY_FAILED if the embedded
 *         digest is wrong or the pair does not round-trip.
 */
/* The fixed pairwise-check message.  ASCII so that it is visibly a domain
 * constant rather than key material, and zero-padded to the 32 octets FIPS 203
 * Algorithm 17 requires.  Never used for a real encapsulation: `m` reaches this
 * value only through `kyber_pubkey_from_sk`, whose outputs are all scrubbed. */
static const uint8_t KYBER_PCT_M[32] = "AMA ML-KEM pairwise check v1";

static ama_error_t kyber_pubkey_from_sk(const kyber_params *P,
                                        const uint8_t *secret_key, size_t sk_len,
                                        uint8_t *public_key, size_t pk_len) {
    const uint8_t *ek, *h_stored;
    uint8_t h_computed[32];
    uint8_t ct[AMA_ML_KEM_MAX_CIPHERTEXT_BYTES];
    uint8_t ss_enc[AMA_ML_KEM_SHARED_SECRET_BYTES];
    uint8_t ss_dec[AMA_ML_KEM_SHARED_SECRET_BYTES];
    size_t ct_len = sizeof(ct);
    ama_error_t rc;
    int mismatch;

    if (!P || !secret_key || sk_len != P->sk_bytes) {
        return AMA_ERROR_INVALID_PARAM;
    }
    if (public_key && pk_len < P->pk_bytes) {
        return AMA_ERROR_INVALID_PARAM;
    }

    ek = secret_key + KYBER_T_BYTES(P);
    h_stored = ek + P->pk_bytes;

    ama_sha3_256(ek, P->pk_bytes, h_computed);
    if (ama_consttime_memcmp(h_computed, h_stored, 32) != 0) {
        ama_secure_memzero(h_computed, sizeof(h_computed));
        return AMA_ERROR_VERIFY_FAILED;
    }
    ama_secure_memzero(h_computed, sizeof(h_computed));

    rc = kyber_encapsulate_internal(P, ek, P->pk_bytes, KYBER_PCT_M, ct, &ct_len,
                                    ss_enc, sizeof(ss_enc));
    if (rc == AMA_SUCCESS) {
        rc = kyber_decapsulate_internal(P, ct, ct_len, secret_key, sk_len,
                                        ss_dec, sizeof(ss_dec));
    }
    if (rc != AMA_SUCCESS) {
        ama_secure_memzero(ss_enc, sizeof(ss_enc));
        ama_secure_memzero(ss_dec, sizeof(ss_dec));
        return rc;
    }

    mismatch = ama_consttime_memcmp(ss_enc, ss_dec, sizeof(ss_enc));
    ama_secure_memzero(ss_enc, sizeof(ss_enc));
    ama_secure_memzero(ss_dec, sizeof(ss_dec));
    if (mismatch != 0) {
        return AMA_ERROR_VERIFY_FAILED;
    }

    if (public_key) {
        memcpy(public_key, ek, P->pk_bytes);
    }
    return AMA_SUCCESS;
}

AMA_API ama_error_t ama_ml_kem_pubkey_from_privkey(ama_ml_kem_param_set_t ps,
                                                   const uint8_t *sk, size_t sk_len,
                                                   uint8_t *pk, size_t pk_len) {
    const kyber_params *P = kyber_params_for(ps);
    if (!P || !pk) return AMA_ERROR_INVALID_PARAM;
    return kyber_pubkey_from_sk(P, sk, sk_len, pk, pk_len);
}

AMA_API ama_error_t ama_ml_kem_privkey_check(ama_ml_kem_param_set_t ps,
                                             const uint8_t *sk, size_t sk_len) {
    const kyber_params *P = kyber_params_for(ps);
    if (!P) return AMA_ERROR_INVALID_PARAM;
    return kyber_pubkey_from_sk(P, sk, sk_len, NULL, 0);
}

/**
 * FIPS 203 §7.2 input validation for an encapsulation key.
 *
 * §7.2 requires *two* checks before `ek` is used, and the second one is the one
 * implementations skip:
 *
 *  1. **Type check** — `|ek| = 384k + 32`.
 *  2. **Modulus check** — `ByteEncode_12(ByteDecode_12(ek_hat))` must reproduce
 *     `ek_hat` exactly.  `ByteDecode_12` reduces mod q (Algorithm 13 takes
 *     `m = q` at `d = 12`), so re-encoding differs precisely when some 12-bit
 *     field holds a value `>= q`.  The check is therefore "every one of the
 *     256k coefficients is in [0, q)", which is what this computes directly
 *     rather than by round-tripping a buffer.
 *
 * Why it matters, stated concretely: 4096 - 3329 = 767 of every 4096 encodable
 * values are out of range, so a *random* byte string of the right length has a
 * vanishing probability of passing, while a single flipped bit in a real key
 * has about a 1-in-5 chance of pushing its coefficient out of range.  A
 * conformant peer rejects such a key; AMA accepted it, encapsulated to it, and
 * derived a shared secret nobody else would derive.  Because ML-KEM's implicit
 * rejection is designed to fail silently, the two parties then simply hold
 * different secrets — the same class of invisible failure that
 * `kyber_pubkey_from_sk`'s pairwise check exists to catch, reachable by anyone
 * who can hand you an encapsulation key.
 *
 * Not constant time, and deliberately so: `ek` is public by definition.
 *
 * @return AMA_SUCCESS if `ek` is a valid encapsulation key;
 *         AMA_ERROR_INVALID_PARAM on a NULL pointer, unknown parameter set, or
 *         wrong length (the type check); AMA_ERROR_VERIFY_FAILED if a
 *         coefficient is out of range (the modulus check).
 */
static ama_error_t kyber_pubkey_check(const kyber_params *P,
                                      const uint8_t *ek, size_t ek_len) {
    unsigned int i, j;

    if (!P || !ek) {
        return AMA_ERROR_INVALID_PARAM;
    }
    if (ek_len != P->pk_bytes) {
        return AMA_ERROR_INVALID_PARAM;
    }
    /* `ek = ByteEncode_12(t_hat) || rho`: k polynomials of 384 octets, then the
     * 32-octet seed, which carries no constraint. */
    for (i = 0; i < P->k; i++) {
        const uint8_t *a = ek + (size_t)i * 384u;
        for (j = 0; j < KYBER_N / 2; j++) {
            uint16_t c0 = (uint16_t)(((uint16_t)a[3*j] |
                                      ((uint16_t)a[3*j + 1] << 8)) & 0xFFF);
            uint16_t c1 = (uint16_t)(((uint16_t)(a[3*j + 1] >> 4) |
                                      ((uint16_t)a[3*j + 2] << 4)) & 0xFFF);
            if (c0 >= KYBER_Q || c1 >= KYBER_Q) {
                return AMA_ERROR_VERIFY_FAILED;
            }
        }
    }
    return AMA_SUCCESS;
}

AMA_API ama_error_t ama_ml_kem_pubkey_check(ama_ml_kem_param_set_t ps,
                                            const uint8_t *pk, size_t pk_len) {
    const kyber_params *P = kyber_params_for(ps);
    if (!P) return AMA_ERROR_INVALID_PARAM;
    return kyber_pubkey_check(P, pk, pk_len);
}

AMA_API ama_error_t ama_ml_kem_encapsulate(ama_ml_kem_param_set_t ps,
                                           const uint8_t *pk, size_t pk_len,
                                           uint8_t *ct, size_t *ct_len,
                                           uint8_t *ss, size_t ss_len) {
    const kyber_params *P = kyber_params_for(ps);
    if (!P) return AMA_ERROR_INVALID_PARAM;
    return kyber_encapsulate_internal(P, pk, pk_len, NULL, ct, ct_len, ss, ss_len);
}

AMA_API ama_error_t ama_ml_kem_decapsulate(ama_ml_kem_param_set_t ps,
                                           const uint8_t *ct, size_t ct_len,
                                           const uint8_t *sk, size_t sk_len,
                                           uint8_t *ss, size_t ss_len) {
    const kyber_params *P = kyber_params_for(ps);
    if (!P) return AMA_ERROR_INVALID_PARAM;
    return kyber_decapsulate_internal(P, ct, ct_len, sk, sk_len, ss, ss_len);
}

/* ============================================================================
 * LEGACY ML-KEM-1024 ENTRY POINTS (unchanged ABI)
 * ============================================================================ */

/**
 * Public wrapper for Kyber keypair generation (called from ama_core.c)
 */
AMA_API ama_error_t ama_kyber_keypair(uint8_t* pk, size_t pk_len,
                               uint8_t* sk, size_t sk_len) {
    return ama_ml_kem_keypair(AMA_ML_KEM_1024, pk, pk_len, sk, sk_len);
}

/**
 * Deterministic Kyber-1024 keypair from seed (for KAT testing).
 *
 * @param d    Seed for key generation (32 bytes)
 * @param z    Seed for implicit rejection (32 bytes)
 * @param pk   Output public key buffer (1568 bytes)
 * @param sk   Output secret key buffer (3168 bytes)
 * @return AMA_SUCCESS or error code
 */
AMA_API ama_error_t ama_kyber_keypair_from_seed(
    const uint8_t d[32], const uint8_t z[32],
    uint8_t *pk, uint8_t *sk)
{
    return ama_ml_kem_keypair_from_seed(AMA_ML_KEM_1024, d, z,
                                        pk, AMA_ML_KEM_1024_PUBLIC_KEY_BYTES,
                                        sk, AMA_ML_KEM_1024_SECRET_KEY_BYTES);
}

/**
 * Public wrapper for Kyber encapsulation (called from ama_core.c)
 */
AMA_API ama_error_t ama_kyber_encapsulate(const uint8_t* pk, size_t pk_len,
                                   uint8_t* ct, size_t* ct_len,
                                   uint8_t* ss, size_t ss_len) {
    return ama_ml_kem_encapsulate(AMA_ML_KEM_1024, pk, pk_len, ct, ct_len, ss, ss_len);
}

/**
 * Public wrapper for Kyber decapsulation (called from ama_core.c)
 */
AMA_API ama_error_t ama_kyber_decapsulate(const uint8_t* ct, size_t ct_len,
                                   const uint8_t* sk, size_t sk_len,
                                   uint8_t* ss, size_t ss_len) {
    return ama_ml_kem_decapsulate(AMA_ML_KEM_1024, ct, ct_len, sk, sk_len, ss, ss_len);
}

#ifdef AMA_TESTING_MODE
/**
 * Test-only: assert the derived byte lengths in KYBER_PARAM_SETS agree with
 * the FIPS 203 formulas (pk = 384k+32, sk = 768k+96, ct = 32(du*k+dv)).
 *
 * A mistyped table entry is otherwise invisible until a KAT fails at a length
 * nobody expected; this turns it into a named test failure.  Returns 0 on
 * success, or 1 + the index of the first bad row.
 */
int ama_ml_kem_test_params_selfcheck(void);
int ama_ml_kem_test_params_selfcheck(void) {
    unsigned idx;
    for (idx = 0; idx < 3; idx++) {
        const kyber_params *P = &KYBER_PARAM_SETS[idx];
        if (P->pk_bytes != 384u * P->k + 32u) return (int)(1 + idx);
        if (P->sk_bytes != 768u * P->k + 96u) return (int)(1 + idx);
        if (P->ct_bytes != 32u * (P->du * P->k + P->dv)) return (int)(1 + idx);
        if (P->k > KYBER_K_MAX) return (int)(1 + idx);
        if (P->eta1 > KYBER_ETA_MAX || P->eta2 > KYBER_ETA_MAX) return (int)(1 + idx);
        if (kyber_params_for(P->ps) != P) return (int)(1 + idx);
    }
    return 0;
}
#endif

/* ============================================================================
 * POLYNOMIAL ARITHMETIC - COMPLETE IMPLEMENTATION
 * ============================================================================
 * Full implementation of Kyber polynomial operations including NTT,
 * Montgomery arithmetic, compression, and serialization.
 * ============================================================================ */

/**
 * Montgomery reduction
 * Computes a * R^-1 mod q where R = 2^16
 * Uses the identity: a * q^-1 mod R * q subtracted from a gives a multiple of R
 */
static int16_t montgomery_reduce(int32_t a) {
    int32_t t;
    int16_t u;

    u = (int16_t)((int64_t)a * 62209);  /* q^-1 mod 2^16 = 62209 */
    t = (int32_t)u * KYBER_Q;
    t = a - t;
    t >>= 16;

    return (int16_t)t;
}

/**
 * Barrett reduction
 * Reduces a mod q for values up to 2^26
 */
static int16_t barrett_reduce(int16_t a) {
    /* All intermediates in int32: v*a is at most 20159 * 32768 < 2^31, the
     * shifted quotient t lies in [-10, 9] (exhaustively verified over every
     * int16_t input), and a - t*q lies in [0, q] for in-contract inputs and
     * within (-2q, 2q) for the full int16_t range — so the single narrowing
     * cast at the return cannot change the value.  Bit-identical to the
     * previous int16_t-accumulator form over all 65,536 inputs. */
    const int32_t v = ((1 << 26) + KYBER_Q / 2) / KYBER_Q;
    int32_t t = (v * (int32_t)a) >> 26;
    t *= KYBER_Q;
    return (int16_t)(a - t);
}

/**
 * Conditional subtraction of q
 */
static int16_t csubq(int16_t a) {
    a -= KYBER_Q;
    a += (a >> 15) & KYBER_Q;
    return a;
}

/* NTT twiddle factors (zetas) - primitive 256th root of unity in Montgomery form */
static const int16_t zetas[128] = {
    2285, 2571, 2970, 1812, 1493, 1422, 287, 202,
    3158, 622, 1577, 182, 962, 2127, 1855, 1468,
    573, 2004, 264, 383, 2500, 1458, 1727, 3199,
    2648, 1017, 732, 608, 1787, 411, 3124, 1758,
    1223, 652, 2777, 1015, 2036, 1491, 3047, 1785,
    516, 3321, 3009, 2663, 1711, 2167, 126, 1469,
    2476, 3239, 3058, 830, 107, 1908, 3082, 2378,
    2931, 961, 1821, 2604, 448, 2264, 677, 2054,
    2226, 430, 555, 843, 2078, 871, 1550, 105,
    422, 587, 177, 3094, 3038, 2869, 1574, 1653,
    3083, 778, 1159, 3182, 2552, 1483, 2727, 1119,
    1739, 644, 2457, 349, 418, 329, 3173, 3254,
    817, 1097, 603, 610, 1322, 2044, 1864, 384,
    2114, 3193, 1218, 1994, 2455, 220, 2142, 1670,
    2144, 1799, 2051, 794, 1819, 2475, 2459, 478,
    3221, 3021, 996, 991, 958, 1869, 1522, 1628
};

/* Note: The inverse NTT uses the SAME zetas table as the forward NTT,
 * accessed in reverse order (k = 127 down to 1). This is because the
 * Gentleman-Sande butterfly with the same twiddle factor correctly
 * inverts the Cooley-Tukey butterfly. See NIST FIPS 203 / pqcrystals. */

/* Scalar reference exposed so the dispatch auto-tune can microbench
 * the SIMD NTT slots against a single source of truth — `poly_ntt` /
 * `poly_invntt` below delegate to the same helpers.
 *
 * Hidden visibility — these symbols are internal contract surface
 * between this TU and `src/c/dispatch/ama_dispatch.c` only; they
 * are NOT public ABI.  Without the visibility attribute, the
 * default on every non-MSVC build is "exported from libama_cryptography.so"
 * (Copilot review #326), which would expand the user-observable
 * symbol surface and lock the project into back-compat for an
 * internal helper.  MSVC has no equivalent for static-archive
 * symbols at this scope; the surface there is governed by the
 * separate `__declspec(dllexport)`-driven AMA_API macro which is
 * deliberately not applied here. */
#if defined(__GNUC__) || defined(__clang__)
__attribute__((visibility("hidden")))
#endif
void ama_kyber_ntt_generic_ref(int16_t coeffs[256], const int16_t zetas_tab[128]);
#if defined(__GNUC__) || defined(__clang__)
__attribute__((visibility("hidden")))
#endif
void ama_kyber_invntt_generic_ref(int16_t coeffs[256], const int16_t zetas_tab[128]);

static void kyber_ntt_scalar(int16_t coeffs[256], const int16_t zetas_tab[128]) {
    unsigned int len, start, j, k;
    int16_t t, zeta;

    k = 1;
    for (len = 128; len >= 2; len >>= 1) {
        for (start = 0; start < KYBER_N; start = j + len) {
            zeta = zetas_tab[k++];
            for (j = start; j < start + len; j++) {
                t = montgomery_reduce((int32_t)zeta * coeffs[j + len]);
                coeffs[j + len] = coeffs[j] - t;
                coeffs[j] = coeffs[j] + t;
            }
        }
    }
}

static void kyber_invntt_scalar(int16_t coeffs[256], const int16_t zetas_tab[128]) {
    unsigned int len, start, j, k;
    int16_t t, zeta;
    const int16_t f = 1441;  /* f = 128^{-1} mod q, in Montgomery form */

    k = 127;
    for (len = 2; len <= 128; len <<= 1) {
        for (start = 0; start < KYBER_N; start = j + len) {
            zeta = zetas_tab[k--];
            for (j = start; j < start + len; j++) {
                t = coeffs[j];
                coeffs[j] = barrett_reduce(t + coeffs[j + len]);
                coeffs[j + len] = montgomery_reduce((int32_t)zeta * (coeffs[j + len] - t));
            }
        }
    }

    /* Multiply by f = 128^{-1} */
    for (j = 0; j < KYBER_N; j++) {
        coeffs[j] = montgomery_reduce((int32_t)f * coeffs[j]);
    }
}

#if defined(__GNUC__) || defined(__clang__)
__attribute__((visibility("hidden")))
#endif
void ama_kyber_ntt_generic_ref(int16_t coeffs[256], const int16_t zetas_tab[128]) {
    kyber_ntt_scalar(coeffs, zetas_tab);
}

#if defined(__GNUC__) || defined(__clang__)
__attribute__((visibility("hidden")))
#endif
void ama_kyber_invntt_generic_ref(int16_t coeffs[256], const int16_t zetas_tab[128]) {
    kyber_invntt_scalar(coeffs, zetas_tab);
}

/**
 * Number Theoretic Transform (forward NTT)
 * Converts polynomial from coefficient form to NTT form for fast multiplication.
 * Uses Cooley-Tukey butterfly with Montgomery reduction.
 */
static void poly_ntt(poly* r) {
    /* Dispatch to SIMD implementation when available (INVARIANT-4: graceful fallback) */
    const ama_dispatch_table_t *dt = ama_get_dispatch_table();
    if (dt->kyber_ntt) {
        dt->kyber_ntt(r->coeffs, zetas);
        return;
    }
    kyber_ntt_scalar(r->coeffs, zetas);
}

/**
 * Inverse Number Theoretic Transform
 * Converts polynomial from NTT form back to coefficient form.
 * Uses Gentleman-Sande butterfly with Montgomery reduction.
 */
static void poly_invntt(poly* r) {
    /* Dispatch to SIMD implementation when available (INVARIANT-4: graceful fallback) */
    const ama_dispatch_table_t *dt = ama_get_dispatch_table();
    if (dt->kyber_invntt) {
        dt->kyber_invntt(r->coeffs, zetas);
        return;
    }
    kyber_invntt_scalar(r->coeffs, zetas);
}

/**
 * Base multiplication of two polynomials in NTT domain
 * Multiplication in Z_q[X]/(X^2 - zeta) for degree-2 components
 */
static void basemul(int16_t r[2], const int16_t a[2], const int16_t b[2], int16_t zeta) {
    r[0] = montgomery_reduce((int32_t)a[1] * b[1]);
    r[0] = montgomery_reduce((int32_t)r[0] * zeta);
    r[0] += montgomery_reduce((int32_t)a[0] * b[0]);

    r[1] = montgomery_reduce((int32_t)a[0] * b[1]);
    r[1] += montgomery_reduce((int32_t)a[1] * b[0]);
}

/**
 * Pointwise multiplication of polynomials in NTT domain
 */
static void poly_basemul(poly* r, const poly* a, const poly* b) {
    /* Dispatch to SIMD implementation when available (INVARIANT-4: graceful fallback) */
    const ama_dispatch_table_t *dt = ama_get_dispatch_table();
    if (dt->kyber_pointwise) {
        dt->kyber_pointwise(r->coeffs, a->coeffs, b->coeffs, zetas);
        return;
    }

    /* Generic C implementation */
    unsigned int i;
    for (i = 0; i < KYBER_N / 4; i++) {
        basemul(&r->coeffs[4*i], &a->coeffs[4*i], &b->coeffs[4*i], zetas[64 + i]);
        basemul(&r->coeffs[4*i + 2], &a->coeffs[4*i + 2], &b->coeffs[4*i + 2], -zetas[64 + i]);
    }
}

/**
 * Add two polynomials
 *
 * Dispatches to an SVE2 svadd_s16_x kernel when the slot is non-NULL;
 * falls back to the inline scalar loop below (which modern GCC/Clang
 * already auto-vectorise at -O3 on AVX2/NEON targets, so no
 * dispatched helper is wired on those tiers today).  Output range
 * is the int16 sum [a+b]; callers needing canonical [-q+1, q-1] must
 * follow with poly_reduce().
 */
static void poly_add(poly* r, const poly* a, const poly* b) {
    const ama_dispatch_table_t *dt = ama_get_dispatch_table();
    if (dt->kyber_poly_add) {
        dt->kyber_poly_add(r->coeffs, a->coeffs, b->coeffs);
        return;
    }
    for (int i = 0; i < KYBER_N; i++) {
        r->coeffs[i] = a->coeffs[i] + b->coeffs[i];
    }
}

/**
 * Subtract two polynomials
 *
 * Dispatches to an SVE2 svsub_s16_x kernel when the slot is non-NULL;
 * falls back to the inline scalar loop below.  Same auto-vectorisation
 * rationale as poly_add().
 */
static void poly_sub(poly* r, const poly* a, const poly* b) {
    const ama_dispatch_table_t *dt = ama_get_dispatch_table();
    if (dt->kyber_poly_sub) {
        dt->kyber_poly_sub(r->coeffs, a->coeffs, b->coeffs);
        return;
    }
    for (int i = 0; i < KYBER_N; i++) {
        r->coeffs[i] = a->coeffs[i] - b->coeffs[i];
    }
}

/**
 * Reduce all coefficients mod q
 *
 * Dispatches to an SVE2 vector-load + scalar-Barrett kernel when the
 * slot is non-NULL; falls back to the inline scalar Barrett loop
 * below.
 */
static void poly_reduce(poly* r) {
    const ama_dispatch_table_t *dt = ama_get_dispatch_table();
    if (dt->kyber_poly_reduce) {
        dt->kyber_poly_reduce(r->coeffs);
        return;
    }
    for (int i = 0; i < KYBER_N; i++) {
        r->coeffs[i] = barrett_reduce(r->coeffs[i]);
    }
}

/**
 * Convert polynomial to Montgomery domain.
 * Multiplies each coefficient by R^2 mod q = 1353, then Montgomery-reduces,
 * effectively multiplying by R mod q. This compensates for the R^{-1} factor
 * introduced by Montgomery multiplication in basemul.
 */
static void poly_tomont(poly* r) {
    const int16_t f = 1353;  /* R^2 mod q = 2^32 mod 3329 = 1353 */
    for (int i = 0; i < KYBER_N; i++) {
        r->coeffs[i] = montgomery_reduce((int32_t)f * r->coeffs[i]);
    }
}

/**
 * Normalize coefficient to [0, q-1] range.
 * After NTT/Barrett operations, coefficients may be negative.
 * First conditionally add q to make non-negative, then csubq to
 * reduce values in [q, 2q-1] back to [0, q-1].
 */
static int16_t coeff_normalize(int16_t a) {
    a += (a >> 15) & KYBER_Q;  /* Make non-negative: [-q,q] -> [0,2q-1] */
    return csubq(a);            /* Reduce: [0,2q-1] -> [0,q-1] */
}

/* FIPS 203 Compress_d, division-free (the KyberSlash fix).
 *
 * Compress_d(x) = round(2^d * x / q) mod 2^d, which reads most directly as
 *
 *     (((uint32_t)x << d) + q/2) / KYBER_Q
 *
 * and that is how this file computed it.  The operand of that division is
 * secret on two reachable paths: the Compress_1 message decode in
 * decapsulation works on mp = v - s^T u (a function of the secret key), and
 * poly_compress runs over the re-encryption inside the FO transform.  A
 * division by a compile-time constant is only constant-time if the compiler
 * lowers it to a reciprocal multiply — usual at -O2/-O3, but NOT guaranteed,
 * and this project builds Debug at -O0 where a hardware divide with
 * operand-dependent latency is emitted.  That is precisely the KyberSlash
 * defect class (secret-dependent division timing in ML-KEM compression,
 * exploitable as a decapsulation timing oracle for key recovery), and it
 * contradicts INVARIANT-12 and CRYPTO_REVIEW_CHECKLIST's "no variable-time
 * division/modulo on secret values".  ama_dilithium.c's dil_decompose already
 * uses the multiply/shift idiom for the same reason.
 *
 * The replacement is a Granlund-Montgomery reciprocal multiply chosen so it is
 * EXACT, not approximate, over this function's whole domain:
 *
 *     M = ceil(2^40 / q) = 330282857,  S = 40
 *     Compress_d(x) = ((((uint64_t)x << d) + q/2) * M >> S) & (2^d - 1)
 *
 * Callers always pass x through coeff_normalize() first, so x is in [0, q-1]
 * and the widest intermediate (d = 11) is 3328*2^11 + 1664 = 6_817_408 < 2^23;
 * the 64-bit product cannot overflow.  Equivalence to the division form was
 * verified by exhaustive comparison over every x in [0, q-1] for every width
 * d in {1, 4, 5, 10, 11} — all 16_645 pairs agree, so the ciphertext bytes and
 * every KAT are unchanged by construction.  The 64-bit multiply is a
 * fixed-latency instruction on every supported target, unlike the divide it
 * replaces. */
#define AMA_KYBER_COMPRESS_MULT  330282857ULL  /* ceil(2^40 / KYBER_Q) */
#define AMA_KYBER_COMPRESS_SHIFT 40

static inline uint32_t kyber_compress_d(uint32_t x_normalized, unsigned d) {
    uint64_t n = ((uint64_t)x_normalized << d) + (KYBER_Q / 2);
    uint32_t quotient = (uint32_t)((n * AMA_KYBER_COMPRESS_MULT) >> AMA_KYBER_COMPRESS_SHIFT);
    /* The `mod 2^d` of the definition, applied HERE rather than left to the
     * caller.  It is not cosmetic at d = 1: x = q-1 = 3328 gives
     * round(2*3328/3329) = 2, and FIPS 203 Compress_1(3328) is 2 mod 2 = 0.
     * 832 of the 3,329 coefficients exceed 2^d before the mask at d=1 (104 at
     * d=4, 52 at d=5, 1 at d=10 — tests/c/test_kyber_compress.c counts them).
     * Every current call site happens to mask with the matching width, so the
     * shipped ciphertext bytes are unchanged by this line — but a helper whose
     * documented contract is `mod 2^d` and whose return value is not is a trap
     * for the next caller, and the values it gets wrong are the ones nearest
     * the decision boundary an attacker steers toward.
     *
     * `d` is a plaintext parameter (the compression width, a literal at every
     * call site), never secret, so selecting the mask on it is not a timing
     * channel — and it folds away entirely, since this is `static inline` and
     * every call passes a constant.  The `d >= 32` arm keeps the shift defined
     * for a width this function is never called with; UB in a fallback is
     * still UB (C11 6.5.7p3). */
    uint32_t mask = (d >= 32u) ? 0xFFFFFFFFu : ((1u << d) - 1u);
    return quotient & mask;
}

#ifdef AMA_TESTING_MODE
/**
 * Test-only export of Compress_d.
 *
 * `kyber_compress_d` is `static inline`, so tests/c/test_kyber_compress.c
 * cannot link it directly, and a copy of the implementation in the test would
 * verify the copy rather than the code that ships.  This forwards to the real
 * definition, so the exhaustive equivalence proof for the Granlund-Montgomery
 * reciprocal is executed against the shipped translation unit.
 * Not declared in any public header — visible only to AMA_TESTING_MODE builds.
 */
uint32_t ama_kyber_compress_d_for_test(uint32_t x_normalized, unsigned d) {
    return kyber_compress_d(x_normalized, d);
}
#endif

/**
 * Serialize polynomial to bytes (12-bit coefficients)
 * Packs 256 coefficients into 384 bytes
 */
static void poly_tobytes(uint8_t* r, const poly* a) {
    unsigned int i;
    uint16_t t0, t1;

    for (i = 0; i < KYBER_N / 2; i++) {
        t0 = (uint16_t)coeff_normalize(a->coeffs[2*i]);
        t1 = (uint16_t)coeff_normalize(a->coeffs[2*i + 1]);

        r[3*i + 0] = (uint8_t)(t0);
        r[3*i + 1] = (uint8_t)((t0 >> 8) | (t1 << 4));
        r[3*i + 2] = (uint8_t)(t1 >> 4);
    }
}

/**
 * Deserialize bytes to polynomial
 * Unpacks 384 bytes into 256 12-bit coefficients
 */
static void poly_frombytes(poly* r, const uint8_t* a) {
    unsigned int i;

    for (i = 0; i < KYBER_N / 2; i++) {
        r->coeffs[2*i] = ((uint16_t)a[3*i] | ((uint16_t)a[3*i + 1] << 8)) & 0xFFF;
        r->coeffs[2*i + 1] = ((uint16_t)(a[3*i + 1] >> 4) | ((uint16_t)a[3*i + 2] << 4)) & 0xFFF;
    }
}

/**
 * Compress polynomial to fewer bits
 * Used for ciphertext compression
 */
static void poly_compress(uint8_t* r, const poly* a, int bits) {
    unsigned int i, j;
    uint8_t t[8];

    if (bits == 4) {
        /* Compress to 4 bits per coefficient */
        for (i = 0; i < KYBER_N / 2; i++) {
            for (j = 0; j < 2; j++) {
                int16_t coeff = coeff_normalize(a->coeffs[2*i + j]);
                t[j] = (uint8_t)(kyber_compress_d((uint32_t)coeff, 4) & 0xF);
            }
            r[i] = (uint8_t)(t[0] | (t[1] << 4));
        }
    } else if (bits == 5) {
        /* Compress to 5 bits per coefficient */
        for (i = 0; i < KYBER_N / 8; i++) {
            for (j = 0; j < 8; j++) {
                int16_t coeff = coeff_normalize(a->coeffs[8*i + j]);
                t[j] = (uint8_t)(kyber_compress_d((uint32_t)coeff, 5) & 0x1F);
            }
            /* (uint8_t) narrowing is the packing itself: high bits of a
             * shifted 5-bit field continue in the next byte (same explicit-
             * cast style as the 10-bit branch below). */
            r[5*i + 0] = (uint8_t)((t[0]) | (t[1] << 5));
            r[5*i + 1] = (uint8_t)((t[1] >> 3) | (t[2] << 2) | (t[3] << 7));
            r[5*i + 2] = (uint8_t)((t[3] >> 1) | (t[4] << 4));
            r[5*i + 3] = (uint8_t)((t[4] >> 4) | (t[5] << 1) | (t[6] << 6));
            r[5*i + 4] = (uint8_t)((t[6] >> 2) | (t[7] << 3));
        }
    } else if (bits == 10) {
        /* Compress to 10 bits per coefficient */
        for (i = 0; i < KYBER_N / 4; i++) {
            uint16_t d[4];
            for (j = 0; j < 4; j++) {
                int16_t coeff = coeff_normalize(a->coeffs[4*i + j]);
                d[j] = (uint16_t)(kyber_compress_d((uint32_t)coeff, 10) & 0x3FF);
            }
            r[5*i + 0] = (uint8_t)(d[0]);
            r[5*i + 1] = (uint8_t)((d[0] >> 8) | (d[1] << 2));
            r[5*i + 2] = (uint8_t)((d[1] >> 6) | (d[2] << 4));
            r[5*i + 3] = (uint8_t)((d[2] >> 4) | (d[3] << 6));
            r[5*i + 4] = (uint8_t)(d[3] >> 2);
        }
    } else if (bits == 11) {
        /* Compress to 11 bits per coefficient (Kyber-1024) */
        for (i = 0; i < KYBER_N / 8; i++) {
            uint16_t d[8];
            for (j = 0; j < 8; j++) {
                int16_t coeff = coeff_normalize(a->coeffs[8*i + j]);
                d[j] = (uint16_t)(kyber_compress_d((uint32_t)coeff, 11) & 0x7FF);
            }
            r[11*i + 0]  = (uint8_t)(d[0]);
            r[11*i + 1]  = (uint8_t)((d[0] >> 8) | (d[1] << 3));
            r[11*i + 2]  = (uint8_t)((d[1] >> 5) | (d[2] << 6));
            r[11*i + 3]  = (uint8_t)(d[2] >> 2);
            r[11*i + 4]  = (uint8_t)((d[2] >> 10) | (d[3] << 1));
            r[11*i + 5]  = (uint8_t)((d[3] >> 7) | (d[4] << 4));
            r[11*i + 6]  = (uint8_t)((d[4] >> 4) | (d[5] << 7));
            r[11*i + 7]  = (uint8_t)(d[5] >> 1);
            r[11*i + 8]  = (uint8_t)((d[5] >> 9) | (d[6] << 2));
            r[11*i + 9]  = (uint8_t)((d[6] >> 6) | (d[7] << 5));
            r[11*i + 10] = (uint8_t)(d[7] >> 3);
        }
    }
}

/**
 * Decompress polynomial from compressed representation
 */
static void poly_decompress(poly* r, const uint8_t* a, int bits) {
    unsigned int i;

    if (bits == 4) {
        for (i = 0; i < KYBER_N / 2; i++) {
            r->coeffs[2*i + 0] = (int16_t)((((uint32_t)(a[i] & 0xF) * KYBER_Q) + 8) >> 4);
            r->coeffs[2*i + 1] = (int16_t)((((uint32_t)(a[i] >> 4) * KYBER_Q) + 8) >> 4);
        }
    } else if (bits == 5) {
        uint8_t t[8];
        for (i = 0; i < KYBER_N / 8; i++) {
            t[0] = a[5*i + 0] & 0x1F;
            t[1] = (a[5*i + 0] >> 5) | ((a[5*i + 1] << 3) & 0x1F);
            t[2] = (a[5*i + 1] >> 2) & 0x1F;
            t[3] = (a[5*i + 1] >> 7) | ((a[5*i + 2] << 1) & 0x1F);
            t[4] = (a[5*i + 2] >> 4) | ((a[5*i + 3] << 4) & 0x1F);
            t[5] = (a[5*i + 3] >> 1) & 0x1F;
            t[6] = (a[5*i + 3] >> 6) | ((a[5*i + 4] << 2) & 0x1F);
            t[7] = a[5*i + 4] >> 3;

            for (int j = 0; j < 8; j++) {
                r->coeffs[8*i + j] = (int16_t)((((uint32_t)t[j] * KYBER_Q) + 16) >> 5);
            }
        }
    } else if (bits == 10) {
        for (i = 0; i < KYBER_N / 4; i++) {
            r->coeffs[4*i + 0] = (int16_t)(((((uint16_t)a[5*i] | ((uint16_t)a[5*i + 1] << 8)) & 0x3FF) * KYBER_Q + 512) >> 10);
            r->coeffs[4*i + 1] = (int16_t)((((((uint16_t)a[5*i + 1] >> 2) | ((uint16_t)a[5*i + 2] << 6)) & 0x3FF) * KYBER_Q + 512) >> 10);
            r->coeffs[4*i + 2] = (int16_t)((((((uint16_t)a[5*i + 2] >> 4) | ((uint16_t)a[5*i + 3] << 4)) & 0x3FF) * KYBER_Q + 512) >> 10);
            r->coeffs[4*i + 3] = (int16_t)((((((uint16_t)a[5*i + 3] >> 6) | ((uint16_t)a[5*i + 4] << 2)) & 0x3FF) * KYBER_Q + 512) >> 10);
        }
    } else if (bits == 11) {
        for (i = 0; i < KYBER_N / 8; i++) {
            /* Every assembled value is an 11-bit field scattered over at
             * most 2^11 (largest term: a byte shifted left by 3, < 2^11),
             * so the (uint16_t) narrowing after int promotion is
             * value-preserving. */
            uint16_t t0 = (uint16_t)(((uint16_t)a[11*i]) | (((uint16_t)a[11*i + 1] & 0x07) << 8));
            uint16_t t1 = (uint16_t)(((uint16_t)a[11*i + 1] >> 3) | (((uint16_t)a[11*i + 2] & 0x3F) << 5));
            uint16_t t2 = (uint16_t)(((uint16_t)a[11*i + 2] >> 6) | ((uint16_t)a[11*i + 3] << 2) | (((uint16_t)a[11*i + 4] & 0x01) << 10));
            uint16_t t3 = (uint16_t)(((uint16_t)a[11*i + 4] >> 1) | (((uint16_t)a[11*i + 5] & 0x0F) << 7));
            uint16_t t4 = (uint16_t)(((uint16_t)a[11*i + 5] >> 4) | (((uint16_t)a[11*i + 6] & 0x7F) << 4));
            uint16_t t5 = (uint16_t)(((uint16_t)a[11*i + 6] >> 7) | ((uint16_t)a[11*i + 7] << 1) | (((uint16_t)a[11*i + 8] & 0x03) << 9));
            uint16_t t6 = (uint16_t)(((uint16_t)a[11*i + 8] >> 2) | (((uint16_t)a[11*i + 9] & 0x1F) << 6));
            uint16_t t7 = (uint16_t)(((uint16_t)a[11*i + 9] >> 5) | ((uint16_t)a[11*i + 10] << 3));

            r->coeffs[8*i + 0] = (int16_t)(((uint32_t)(t0 & 0x7FF) * KYBER_Q + 1024) >> 11);
            r->coeffs[8*i + 1] = (int16_t)(((uint32_t)(t1 & 0x7FF) * KYBER_Q + 1024) >> 11);
            r->coeffs[8*i + 2] = (int16_t)(((uint32_t)(t2 & 0x7FF) * KYBER_Q + 1024) >> 11);
            r->coeffs[8*i + 3] = (int16_t)(((uint32_t)(t3 & 0x7FF) * KYBER_Q + 1024) >> 11);
            r->coeffs[8*i + 4] = (int16_t)(((uint32_t)(t4 & 0x7FF) * KYBER_Q + 1024) >> 11);
            r->coeffs[8*i + 5] = (int16_t)(((uint32_t)(t5 & 0x7FF) * KYBER_Q + 1024) >> 11);
            r->coeffs[8*i + 6] = (int16_t)(((uint32_t)(t6 & 0x7FF) * KYBER_Q + 1024) >> 11);
            r->coeffs[8*i + 7] = (int16_t)(((uint32_t)(t7 & 0x7FF) * KYBER_Q + 1024) >> 11);
        }
    }
}
