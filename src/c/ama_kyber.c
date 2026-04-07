/**
 * Copyright 2025-2026 Steel Security Advisors LLC
 * Licensed under the Apache License, Version 2.0
 *
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
 * For production use: pip install ama-cryptography[quantum]
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

/* Kyber-1024 parameters */
#define KYBER_N 256
#define KYBER_Q 3329
#define KYBER_K 4
#define KYBER_ETA1 2
#define KYBER_ETA2 2
#define KYBER_DU 11
#define KYBER_DV 5

/* Polynomial ring: R = Z_q[X]/(X^256 + 1) */

typedef struct {
    int16_t coeffs[KYBER_N];
} poly;

typedef struct {
    poly vec[KYBER_K];
} polyvec;

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
static int16_t montgomery_reduce(int32_t a);
static int16_t coeff_normalize(int16_t a);
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
static void polyvec_ntt(polyvec* r) {
    unsigned int i;
    for (i = 0; i < KYBER_K; i++) {
        poly_ntt(&r->vec[i]);
    }
}

static void polyvec_invntt(polyvec* r) {
    unsigned int i;
    for (i = 0; i < KYBER_K; i++) {
        poly_invntt(&r->vec[i]);
    }
}

static void polyvec_add(polyvec* r, const polyvec* a, const polyvec* b) {
    unsigned int i;
    for (i = 0; i < KYBER_K; i++) {
        poly_add(&r->vec[i], &a->vec[i], &b->vec[i]);
    }
}

static void polyvec_reduce(polyvec* r) {
    unsigned int i;
    for (i = 0; i < KYBER_K; i++) {
        poly_reduce(&r->vec[i]);
    }
}

/**
 * Inner product of two polynomial vectors in NTT domain
 */
static void polyvec_basemul_acc(poly* r, const polyvec* a, const polyvec* b) {
    unsigned int i;
    poly t;

    poly_basemul(r, &a->vec[0], &b->vec[0]);
    for (i = 1; i < KYBER_K; i++) {
        poly_basemul(&t, &a->vec[i], &b->vec[i]);
        poly_add(r, r, &t);
    }
    poly_reduce(r);
}

/**
 * Serialize polyvec to bytes
 */
static void polyvec_tobytes(uint8_t* r, const polyvec* a) {
    unsigned int i;
    for (i = 0; i < KYBER_K; i++) {
        poly_tobytes(r + i * 384, &a->vec[i]);
    }
}

/**
 * Deserialize bytes to polyvec
 */
static void polyvec_frombytes(polyvec* r, const uint8_t* a) {
    unsigned int i;
    for (i = 0; i < KYBER_K; i++) {
        poly_frombytes(&r->vec[i], a + i * 384);
    }
}

/**
 * Compress polyvec (du = 11 bits per coefficient for Kyber-1024)
 */
static void polyvec_compress(uint8_t* r, const polyvec* a) {
    unsigned int i;
    for (i = 0; i < KYBER_K; i++) {
        poly_compress(r + i * (KYBER_N * KYBER_DU / 8), &a->vec[i], KYBER_DU);
    }
}

/**
 * Decompress polyvec
 */
static void polyvec_decompress(polyvec* r, const uint8_t* a) {
    unsigned int i;
    for (i = 0; i < KYBER_K; i++) {
        poly_decompress(&r->vec[i], a + i * (KYBER_N * KYBER_DU / 8), KYBER_DU);
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
 * Expand matrix A from seed (K x K matrix in NTT domain)
 */
static void kyber_gen_matrix(polyvec mat[KYBER_K], const uint8_t seed[32], int transposed) {
    unsigned int i, j;
    for (i = 0; i < KYBER_K; i++) {
        for (j = 0; j < KYBER_K; j++) {
            if (transposed) {
                kyber_poly_uniform(&mat[i].vec[j], seed, (uint8_t)i, (uint8_t)j);
            } else {
                kyber_poly_uniform(&mat[i].vec[j], seed, (uint8_t)j, (uint8_t)i);
            }
        }
    }
}

/**
 * Sample noise polynomial with CBD (eta = 2)
 */
static void kyber_poly_cbd_eta(poly* r, const uint8_t* buf) {
    unsigned int i, j;
    uint32_t t, d;
    int16_t a, b;

    /* CBD with eta = 2: need eta*N/4 = 128 bytes */
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
 * Sample noise vector using SHAKE256 and CBD
 */
static void kyber_gennoise(polyvec* r, const uint8_t seed[32], uint8_t nonce) {
    unsigned int i;
    uint8_t buf[34];
    uint8_t stream[KYBER_ETA1 * KYBER_N / 4];

    for (i = 0; i < KYBER_K; i++) {
        memcpy(buf, seed, 32);
        buf[32] = nonce + (uint8_t)i;
        buf[33] = 0;
        ama_shake256(buf, 33, stream, sizeof(stream));
        kyber_poly_cbd_eta(&r->vec[i], stream);
    }
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
static ama_error_t kyber_keypair_generate(
    uint8_t* public_key,
    size_t public_key_len,
    uint8_t* secret_key,
    size_t secret_key_len
) {
    if (public_key_len < AMA_KYBER_1024_PUBLIC_KEY_BYTES ||
        secret_key_len < AMA_KYBER_1024_SECRET_KEY_BYTES) {
        return AMA_ERROR_INVALID_PARAM;
    }

#ifdef AMA_USE_NATIVE_PQC
    {
        /* Native Kyber-1024 key generation (NIST FIPS 203, Algorithm 15) */
        uint8_t d[32], buf[64];
        uint8_t *rho, *sigma;
        polyvec a[KYBER_K], s, e, pkpv;
        unsigned int i;
        ama_error_t err;

        /* Generate random seed d */
        err = kyber_randombytes(d, 32);
        if (err != AMA_SUCCESS) {
            return err;
        }

        /* G(d || byte(k)) = (rho, sigma) per FIPS 203 Algorithm 15
         * G = SHA3-512, k = KYBER_K = 4 for Kyber-1024 */
        {
            uint8_t g_input[33];
            memcpy(g_input, d, 32);
            g_input[32] = (uint8_t)KYBER_K;
            ama_sha3_512(g_input, 33, buf);
            ama_secure_memzero(g_input, sizeof(g_input));
        }
        rho = buf;
        sigma = buf + 32;

        /* Generate matrix A from rho (in NTT domain) */
        kyber_gen_matrix(a, rho, 0);

        /* Sample secret vector s and error vector e from CBD */
        kyber_gennoise(&s, sigma, 0);
        kyber_gennoise(&e, sigma, (uint8_t)KYBER_K);

        /* NTT(s) */
        polyvec_ntt(&s);
        polyvec_ntt(&e);

        /* Compute t = A*s + e (in NTT domain).
         * basemul output has implicit R^{-1} Montgomery factor.
         * poly_tomont compensates by multiplying by R, so the
         * result is in the same domain as NTT(e) for correct addition. */
        for (i = 0; i < KYBER_K; i++) {
            polyvec_basemul_acc(&pkpv.vec[i], &a[i], &s);
            poly_tomont(&pkpv.vec[i]);
            poly_add(&pkpv.vec[i], &pkpv.vec[i], &e.vec[i]);
        }
        polyvec_reduce(&pkpv);

        /* Pack public key: pk = (t || rho) */
        polyvec_tobytes(public_key, &pkpv);
        memcpy(public_key + KYBER_K * 384, rho, 32);

        /* Pack secret key: sk = (s || pk || H(pk) || z) */
        polyvec_reduce(&s);  /* Reduce NTT(s) before serialization — coeff_normalize
                                only handles [-q, 2q-1], but NTT output can exceed this */
        polyvec_tobytes(secret_key, &s);
        memcpy(secret_key + KYBER_K * 384, public_key, AMA_KYBER_1024_PUBLIC_KEY_BYTES);

        /* H(pk) */
        ama_sha3_256(public_key, AMA_KYBER_1024_PUBLIC_KEY_BYTES,
                     secret_key + KYBER_K * 384 + AMA_KYBER_1024_PUBLIC_KEY_BYTES);

        /* Random z for implicit rejection */
        err = kyber_randombytes(
            secret_key + KYBER_K * 384 + AMA_KYBER_1024_PUBLIC_KEY_BYTES + 32, 32);
        if (err != AMA_SUCCESS) {
            return err;
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
                              const uint8_t *pk, const uint8_t *coins) {
    polyvec a[KYBER_K], sp, ep, pkpv, bp;
    poly v, epp, mp_poly;
    unsigned int i;
    const uint8_t *rho;

    /* Extract rho from public key */
    rho = pk + KYBER_K * 384;

    /* Decode public key */
    polyvec_frombytes(&pkpv, pk);

    /* Generate matrix A^T from rho */
    kyber_gen_matrix(a, rho, 1);

    /* Sample r, e1, e2 from coins */
    kyber_gennoise(&sp, coins, 0);
    kyber_gennoise(&ep, coins, (uint8_t)KYBER_K);
    {
        uint8_t noise_buf[33];
        uint8_t noise_stream[KYBER_ETA2 * KYBER_N / 4];
        memcpy(noise_buf, coins, 32);
        noise_buf[32] = 2 * (uint8_t)KYBER_K;
        ama_shake256(noise_buf, 33, noise_stream, sizeof(noise_stream));
        kyber_poly_cbd_eta(&epp, noise_stream);
    }

    /* NTT(r) */
    polyvec_ntt(&sp);

    /* Compute u = A^T * r + e1 */
    for (i = 0; i < KYBER_K; i++) {
        polyvec_basemul_acc(&bp.vec[i], &a[i], &sp);
    }
    polyvec_invntt(&bp);
    polyvec_add(&bp, &bp, &ep);
    polyvec_reduce(&bp);

    /* Compute v = t^T * r + e2 + Decompress(m, 1) */
    polyvec_basemul_acc(&v, &pkpv, &sp);
    poly_invntt(&v);
    poly_add(&v, &v, &epp);

    /* Encode message into polynomial */
    memset(&mp_poly, 0, sizeof(mp_poly));
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
    polyvec_compress(ct, &bp);
    poly_compress(ct + KYBER_K * (KYBER_N * KYBER_DU / 8), &v, KYBER_DV);
}
#endif

/**
 * Encapsulate shared secret
 *
 * Native ML-KEM-1024 implementation (FIPS 203 compliant).
 *
 * @param public_key Recipient's public key (1568 bytes)
 * @param public_key_len Length of public key
 * @param ciphertext Output buffer for ciphertext (1568 bytes)
 * @param ciphertext_len Pointer to ciphertext length (in/out)
 * @param shared_secret Output buffer for shared secret (32 bytes)
 * @param shared_secret_len Length of shared secret buffer
 * @return AMA_SUCCESS or error code
 */
static ama_error_t kyber_encapsulate(
    const uint8_t* public_key,
    size_t public_key_len,
    uint8_t* ciphertext,
    size_t* ciphertext_len,
    uint8_t* shared_secret,
    size_t shared_secret_len
) {
    if (public_key_len != AMA_KYBER_1024_PUBLIC_KEY_BYTES ||
        shared_secret_len != AMA_KYBER_1024_SHARED_SECRET_BYTES) {
        return AMA_ERROR_INVALID_PARAM;
    }

#ifdef AMA_USE_NATIVE_PQC
    {
        /* Native Kyber-1024 encapsulation (NIST FIPS 203, Algorithm 17) */
        uint8_t m[32], kr[64];
        ama_error_t err;

        if (*ciphertext_len < AMA_KYBER_1024_CIPHERTEXT_BYTES) {
            *ciphertext_len = AMA_KYBER_1024_CIPHERTEXT_BYTES;
            return AMA_ERROR_INVALID_PARAM;
        }

        /* Generate random message m */
        err = kyber_randombytes(m, 32);
        if (err != AMA_SUCCESS) {
            return err;
        }

        /* (K, r) = G(m || H(pk)) per FIPS 203 Algorithm 17
         * H = SHA3-256, G = SHA3-512 */
        {
            uint8_t pk_hash[32];
            uint8_t g_input[64];
            ama_sha3_256(public_key, AMA_KYBER_1024_PUBLIC_KEY_BYTES, pk_hash);
            memcpy(g_input, m, 32);
            memcpy(g_input + 32, pk_hash, 32);
            ama_sha3_512(g_input, 64, kr);
            ama_secure_memzero(g_input, sizeof(g_input));
        }

        /* Deterministic CPA encryption with m and coins r = kr+32 */
        kyber_cpapke_enc(ciphertext, m, public_key, kr + 32);

        /* Shared secret = first 32 bytes of kr (= K) */
        memcpy(shared_secret, kr, 32);

        *ciphertext_len = AMA_KYBER_1024_CIPHERTEXT_BYTES;

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
 * Decapsulate shared secret
 *
 * Native ML-KEM-1024 implementation (FIPS 203 compliant).
 *
 * Uses implicit rejection for IND-CCA2 security: returns a deterministic
 * but random-looking value if decapsulation fails.
 *
 * @param ciphertext Ciphertext to decapsulate (1568 bytes)
 * @param ciphertext_len Length of ciphertext
 * @param secret_key Recipient's secret key (3168 bytes)
 * @param secret_key_len Length of secret key
 * @param shared_secret Output buffer for shared secret (32 bytes)
 * @param shared_secret_len Length of shared secret buffer
 * @return AMA_SUCCESS or error code
 */
static ama_error_t kyber_decapsulate(
    const uint8_t* ciphertext,
    size_t ciphertext_len,
    const uint8_t* secret_key,
    size_t secret_key_len,
    uint8_t* shared_secret,
    size_t shared_secret_len
) {
    if (ciphertext_len != AMA_KYBER_1024_CIPHERTEXT_BYTES ||
        secret_key_len != AMA_KYBER_1024_SECRET_KEY_BYTES ||
        shared_secret_len != AMA_KYBER_1024_SHARED_SECRET_BYTES) {
        return AMA_ERROR_INVALID_PARAM;
    }

#ifdef AMA_USE_NATIVE_PQC
    {
        /* Native Kyber-1024 decapsulation (NIST FIPS 203, Algorithm 18) */
        /* Uses implicit rejection for IND-CCA2 security */
        polyvec bp, skpv;
        poly v, mp;
        uint8_t m[32], kr[64];
        uint8_t ct_cmp[AMA_KYBER_1024_CIPHERTEXT_BYTES];
        const uint8_t *pk;
        const uint8_t *h_pk;
        const uint8_t *z;
        unsigned int i;
        int fail;

        /* Parse secret key: s || pk || H(pk) || z */
        polyvec_frombytes(&skpv, secret_key);
        pk = secret_key + KYBER_K * 384;
        h_pk = pk + AMA_KYBER_1024_PUBLIC_KEY_BYTES;
        z = h_pk + 32;

        /* Decompress ciphertext */
        polyvec_decompress(&bp, ciphertext);
        poly_decompress(&v, ciphertext + KYBER_K * (KYBER_N * KYBER_DU / 8), KYBER_DV);

        /* Compute s^T * u (inner product in NTT domain) */
        polyvec_ntt(&bp);
        polyvec_basemul_acc(&mp, &skpv, &bp);
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
                /* Compress_1: round(2t/q) mod 2 */
                t = (int16_t)((((uint32_t)t << 1) + KYBER_Q / 2) / KYBER_Q);
                m[i] |= (uint8_t)((t & 1) << j);
            }
        }

        /* Re-derive (K, r) = G(m || H(pk)) per FIPS 203 Algorithm 18
         * G = SHA3-512 */
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
        kyber_cpapke_enc(ct_cmp, m, pk, kr + 32);

        /* Constant-time comparison of ciphertexts */
        fail = ama_consttime_memcmp(ciphertext, ct_cmp, AMA_KYBER_1024_CIPHERTEXT_BYTES);

        /* Compute BOTH outcomes, then select in constant time.
         * This prevents timing side-channels from leaking whether
         * decapsulation succeeded or triggered implicit rejection. */
        {
            /* Always compute the implicit rejection value: H(z || ct) */
            uint8_t ss_reject[32];
            uint8_t *rej_input = (uint8_t *)malloc(32 + AMA_KYBER_1024_CIPHERTEXT_BYTES);
            if (!rej_input) {
                ama_secure_memzero(m, sizeof(m));
                ama_secure_memzero(kr, sizeof(kr));
                return AMA_ERROR_MEMORY;
            }
            memcpy(rej_input, z, 32);
            memcpy(rej_input + 32, ciphertext, AMA_KYBER_1024_CIPHERTEXT_BYTES);
            ama_shake256(rej_input, 32 + AMA_KYBER_1024_CIPHERTEXT_BYTES,
                        ss_reject, 32);
            ama_secure_memzero(rej_input, 32 + AMA_KYBER_1024_CIPHERTEXT_BYTES);
            free(rej_input);

            /* Start with the valid shared secret (kr), then conditionally
             * overwrite with the rejection value if ciphertexts didn't match.
             * ama_consttime_copy(condition, dst, src, len):
             *   copies src -> dst if condition != 0 */
            memcpy(shared_secret, kr, 32);
            ama_consttime_copy(fail, shared_secret, ss_reject, 32);

            ama_secure_memzero(ss_reject, sizeof(ss_reject));
        }

        /* Scrub sensitive data */
        ama_secure_memzero(m, sizeof(m));
        ama_secure_memzero(kr, sizeof(kr));

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
 * These functions are only compiled in test builds (AMA_TESTING_MODE).
 * They provide NTT roundtrip verification, polynomial multiplication tests,
 * and CPA encrypt/decrypt roundtrip diagnostics for development validation.
 * ============================================================================ */
#ifdef AMA_TESTING_MODE
#include <stdio.h>

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
    memset(&a, 0, sizeof(a));
    memset(&b, 0, sizeof(b));
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
    memset(&b, 0, sizeof(b));
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

    /* Test 0c: polyvec_basemul_acc (inner product) test
     * s = ([1,0,...], [0,...], [0,...], [0,...])
     * u = ([3,0,...], [0,...], [0,...], [0,...])
     * s^T * u should = 3 */
    printf("  --- polyvec_basemul_acc test ---\n");
    {
        polyvec sv, uv;
        poly ip;
        memset(&sv, 0, sizeof(sv));
        memset(&uv, 0, sizeof(uv));
        sv.vec[0].coeffs[0] = 1;
        uv.vec[0].coeffs[0] = 3;

        /* NTT both */
        polyvec_ntt(&sv);
        polyvec_ntt(&uv);

        polyvec_basemul_acc(&ip, &sv, &uv);
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
        unsigned int ii, jj;

        /* A = identity matrix (in NTT domain) */
        memset(A, 0, sizeof(A));
        for (ii = 0; ii < KYBER_K; ii++) {
            A[ii].vec[ii].coeffs[0] = 1;  /* A[i][i] = 1 polynomial */
            poly_ntt(&A[ii].vec[ii]);       /* Convert to NTT domain */
        }

        /* s = ([1,0,...], [0,...], [0,...], [0,...]) */
        memset(&sv, 0, sizeof(sv));
        sv.vec[0].coeffs[0] = 1;
        polyvec_ntt(&sv);

        /* e = zero */
        memset(&ev, 0, sizeof(ev));
        polyvec_ntt(&ev);

        /* t = A*s + e (in NTT domain) */
        for (ii = 0; ii < KYBER_K; ii++) {
            polyvec_basemul_acc(&pkpv_test.vec[ii], &A[ii], &sv);
            poly_tomont(&pkpv_test.vec[ii]);
            poly_add(&pkpv_test.vec[ii], &pkpv_test.vec[ii], &ev.vec[ii]);
        }
        polyvec_reduce(&pkpv_test);

        /* r = ([2,0,...], [0,...], ...) */
        memset(&sp_test, 0, sizeof(sp_test));
        sp_test.vec[0].coeffs[0] = 2;
        polyvec_ntt(&sp_test);

        /* e1 = 0, e2 = 0 */
        memset(&ep_test, 0, sizeof(ep_test));
        memset(&epp_test, 0, sizeof(epp_test));

        /* u = INVNTT(A^T * r) + e1 */
        /* For A=I, A^T=I, so A^T*r = r. u should = [2,0,...] in vec[0] */
        for (ii = 0; ii < KYBER_K; ii++) {
            polyvec_basemul_acc(&bp_test.vec[ii], &A[ii], &sp_test);
        }
        polyvec_invntt(&bp_test);
        polyvec_add(&bp_test, &bp_test, &ep_test);
        polyvec_reduce(&bp_test);

        printf("  u[0][0..3]: %d %d %d %d (expected: 2 0 0 0)\n",
               coeff_normalize(bp_test.vec[0].coeffs[0]),
               coeff_normalize(bp_test.vec[0].coeffs[1]),
               coeff_normalize(bp_test.vec[0].coeffs[2]),
               coeff_normalize(bp_test.vec[0].coeffs[3]));

        /* v = INVNTT(t^T * r) + e2 + m */
        /* t = s = [1,0,...] in vec[0], r = [2,0,...] in vec[0]
         * t^T * r = 1*2 = 2 (constant poly). v should = [2+msg_coeff,0,...] */
        polyvec_basemul_acc(&v_test, &pkpv_test, &sp_test);
        poly_invntt(&v_test);
        poly_add(&v_test, &v_test, &epp_test);

        /* Add message = all zeros for simplicity */
        memset(&mp_test, 0, sizeof(mp_test));
        poly_add(&v_test, &v_test, &mp_test);
        poly_reduce(&v_test);

        printf("  v[0..3]: %d %d %d %d (expected: 2 0 0 0)\n",
               coeff_normalize(v_test.coeffs[0]),
               coeff_normalize(v_test.coeffs[1]),
               coeff_normalize(v_test.coeffs[2]),
               coeff_normalize(v_test.coeffs[3]));

        /* Decrypt: s^T * u */
        polyvec_ntt(&bp_test);
        polyvec_basemul_acc(&stu_test, &sv, &bp_test);
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
        memset(&pa, 0, sizeof(pa));
        memset(&pb, 0, sizeof(pb));
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
        memset(&pc_naive, 0, sizeof(pc_naive));
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
        memset(&pc_naive, 0, sizeof(pc_naive));
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
        memset(A_man, 0, sizeof(A_man));
        for (ii = 0; ii < KYBER_K; ii++) {
            for (jj = 0; jj < KYBER_K; jj++) {
                A_man[ii].vec[jj].coeffs[0] = (int16_t)((ii * KYBER_K + jj + 1) % KYBER_Q);
                poly_ntt(&A_man[ii].vec[jj]);
            }
        }

        /* s = ([1, -1, 0, ...], [2, 0, ...], [0, 1, ...], [-1, 0, ...]) */
        memset(&s_man, 0, sizeof(s_man));
        s_man.vec[0].coeffs[0] = 1; s_man.vec[0].coeffs[1] = -1;
        s_man.vec[1].coeffs[0] = 2;
        s_man.vec[2].coeffs[1] = 1;
        s_man.vec[3].coeffs[0] = -1;
        polyvec_ntt(&s_man);

        /* e = zero for simplicity */
        memset(&e_man, 0, sizeof(e_man));
        polyvec_ntt(&e_man);

        /* t = A*s + e (NTT domain) */
        for (ii = 0; ii < KYBER_K; ii++) {
            polyvec_basemul_acc(&t_man.vec[ii], &A_man[ii], &s_man);
            poly_tomont(&t_man.vec[ii]);
            poly_add(&t_man.vec[ii], &t_man.vec[ii], &e_man.vec[ii]);
        }
        polyvec_reduce(&t_man);

        /* r = ([1, 0, ...], [0, ...], [0, ...], [0, ...]) */
        memset(&sp_man, 0, sizeof(sp_man));
        sp_man.vec[0].coeffs[0] = 1;
        polyvec_ntt(&sp_man);

        /* e1 = 0, e2 = 0 */
        memset(&ep_man, 0, sizeof(ep_man));
        memset(&epp_man, 0, sizeof(epp_man));

        /* Encrypt: u = INVNTT(A^T * r) + e1, v = INVNTT(t^T * r) + e2 + m */
        /* A^T: transpose A_man */
        polyvec A_T[KYBER_K];
        for (ii = 0; ii < KYBER_K; ii++)
            for (jj = 0; jj < KYBER_K; jj++)
                memcpy(&A_T[ii].vec[jj], &A_man[jj].vec[ii], sizeof(poly));

        for (ii = 0; ii < KYBER_K; ii++) {
            polyvec_basemul_acc(&bp_man.vec[ii], &A_T[ii], &sp_man);
        }
        polyvec_invntt(&bp_man);
        polyvec_add(&bp_man, &bp_man, &ep_man);
        polyvec_reduce(&bp_man);

        polyvec_basemul_acc(&v_man, &t_man, &sp_man);
        poly_invntt(&v_man);
        poly_add(&v_man, &v_man, &epp_man);

        /* Add message = 0xAB */
        memset(&mp_man, 0, sizeof(mp_man));
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
        polyvec_ntt(&bp_man);
        polyvec_basemul_acc(&stu_man, &s_man, &bp_man);
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
                tv = (int16_t)((((uint32_t)tv << 1) + KYBER_Q / 2) / KYBER_Q);
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

        ama_error_t rc3 = kyber_keypair_generate(pk3, sizeof(pk3), sk3, sizeof(sk3));
        if (rc3 != AMA_SUCCESS) { printf("    keygen failed\n"); }

        rho3 = pk3 + KYBER_K * 384;
        polyvec_frombytes(&t3, pk3);     /* t_hat from pk */
        polyvec_frombytes(&s3, sk3);     /* s_hat from sk */

        /* Regenerate A */
        kyber_gen_matrix(A3, rho3, 0);

        /* Recompute A*s */
        unsigned int ki;
        for (ki = 0; ki < KYBER_K; ki++) {
            polyvec_basemul_acc(&as3.vec[ki], &A3[ki], &s3);
            poly_tomont(&as3.vec[ki]);
        }
        polyvec_reduce(&as3);

        /* Compare as3 with t3 (they should differ only by NTT(e)) */
        /* But we can't check NTT(e) directly. Instead test the full roundtrip: */
        /* Encrypt with t3, s3, A3 then decrypt with s3 */
        polyvec sp3, ep3, bp3;
        poly epp3, v3, stu3, mp3;
        uint8_t msg3[32], msg_dec3[32];
        memset(msg3, 0xAB, 32);
        memset(&sp3, 0, sizeof(sp3));
        sp3.vec[0].coeffs[0] = 1; /* Simple r */
        polyvec_ntt(&sp3);
        memset(&ep3, 0, sizeof(ep3));
        memset(&epp3, 0, sizeof(epp3));

        /* A^T for encryption */
        polyvec A3T[KYBER_K];
        for (ki = 0; ki < KYBER_K; ki++) {
            unsigned int kj;
            for (kj = 0; kj < KYBER_K; kj++)
                kyber_poly_uniform(&A3T[ki].vec[kj], rho3, (uint8_t)ki, (uint8_t)kj);
        }

        /* u = INVNTT(A^T * r) */
        for (ki = 0; ki < KYBER_K; ki++) {
            polyvec_basemul_acc(&bp3.vec[ki], &A3T[ki], &sp3);
        }
        polyvec_invntt(&bp3);
        polyvec_reduce(&bp3);

        printf("    u[0][0..3]: %d %d %d %d\n",
               coeff_normalize(bp3.vec[0].coeffs[0]),
               coeff_normalize(bp3.vec[0].coeffs[1]),
               coeff_normalize(bp3.vec[0].coeffs[2]),
               coeff_normalize(bp3.vec[0].coeffs[3]));

        /* v = INVNTT(t^T * r) + msg */
        polyvec_basemul_acc(&v3, &t3, &sp3);
        poly_invntt(&v3);
        memset(&mp3, 0, sizeof(mp3));
        for (ki = 0; ki < 32; ki++) {
            unsigned int kj;
            for (kj = 0; kj < 8; kj++)
                mp3.coeffs[8*ki + kj] = (int16_t)(((msg3[ki] >> kj) & 1) * ((KYBER_Q+1)/2));
        }
        poly_add(&v3, &v3, &mp3);
        poly_reduce(&v3);

        /* Decrypt: s^T * u */
        polyvec_ntt(&bp3);
        polyvec_basemul_acc(&stu3, &s3, &bp3);
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
                tv2 = (int16_t)((((uint32_t)tv2 << 1) + KYBER_Q / 2) / KYBER_Q);
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

        ama_error_t rc2 = kyber_keypair_generate(pk2, sizeof(pk2), sk2, sizeof(sk2));
        if (rc2 != AMA_SUCCESS) { printf("    keygen failed\n"); return 1; }

        rho2 = pk2 + KYBER_K * 384;
        polyvec_frombytes(&t_hat, pk2);
        polyvec_frombytes(&s_hat, sk2);
        kyber_gen_matrix(A2, rho2, 0);  /* Non-transposed A */

        /* Compute A*s in NTT domain */
        unsigned int ki;
        for (ki = 0; ki < KYBER_K; ki++) {
            polyvec_basemul_acc(&as_hat.vec[ki], &A2[ki], &s_hat);
            poly_tomont(&as_hat.vec[ki]);
        }
        polyvec_reduce(&as_hat);

        /* e_hat = t_hat - A*s (in NTT domain) */
        polyvec e_hat;
        for (ki = 0; ki < KYBER_K; ki++) {
            poly_sub(&e_hat.vec[ki], &t_hat.vec[ki], &as_hat.vec[ki]);
        }

        /* INVNTT(e_hat) should give e with small coefficients [-2,2] */
        polyvec_invntt(&e_hat);
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
    ama_error_t rc = kyber_keypair_generate(pk, sizeof(pk), sk, sizeof(sk));
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
        polyvec_frombytes(&pkpv, pk);
        polyvec_frombytes(&skpv, sk);

        /* Generate matrix A^T */
        kyber_gen_matrix(a, rho, 1);

        /* Sample r, e1, e2 from coins */
        kyber_gennoise(&sp, coins, 0);
        kyber_gennoise(&ep, coins, (uint8_t)KYBER_K);
        {
            uint8_t noise_buf[33];
            uint8_t noise_stream[KYBER_ETA2 * KYBER_N / 4];
            memcpy(noise_buf, coins, 32);
            noise_buf[32] = 2 * (uint8_t)KYBER_K;
            ama_shake256(noise_buf, 33, noise_stream, sizeof(noise_stream));
            kyber_poly_cbd_eta(&epp, noise_stream);
        }

        /* NTT(r) */
        polyvec_ntt(&sp);

        /* Compute u = INVNTT(A^T * r) + e1 */
        for (i = 0; i < KYBER_K; i++) {
            polyvec_basemul_acc(&bp_enc.vec[i], &a[i], &sp);
        }
        polyvec_invntt(&bp_enc);
        polyvec_add(&bp_enc, &bp_enc, &ep);
        polyvec_reduce(&bp_enc);

        /* Compute v = INVNTT(t^T * r) + e2 + m_poly */
        polyvec_basemul_acc(&v_poly, &pkpv, &sp);
        poly_invntt(&v_poly);
        poly_add(&v_poly, &v_poly, &epp);

        memset(&mp_poly, 0, sizeof(mp_poly));
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
        polyvec_ntt(&bp_enc);
        polyvec_basemul_acc(&stu_poly, &skpv, &bp_enc);
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
                t = (int16_t)((((uint32_t)t << 1) + KYBER_Q / 2) / KYBER_Q);
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

        polyvec_frombytes(&skpv, sk);
        kyber_cpapke_enc(ct, m_orig, pk, coins);

        polyvec_decompress(&bp, ct);
        poly_decompress(&v, ct + KYBER_K * (KYBER_N * KYBER_DU / 8), KYBER_DV);

        polyvec_ntt(&bp);
        polyvec_basemul_acc(&mp, &skpv, &bp);
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
                t = (int16_t)((((uint32_t)t << 1) + KYBER_Q / 2) / KYBER_Q);
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

#endif /* AMA_TESTING_MODE - end of debug/test functions */

/* ============================================================================
 * PUBLIC WRAPPERS FOR CORE DISPATCH
 * ============================================================================ */

/**
 * Public wrapper for Kyber keypair generation (called from ama_core.c)
 */
AMA_API ama_error_t ama_kyber_keypair(uint8_t* pk, size_t pk_len,
                               uint8_t* sk, size_t sk_len) {
    return kyber_keypair_generate(pk, pk_len, sk, sk_len);
}

/**
 * Deterministic Kyber-1024 keypair from seed (for KAT testing).
 *
 * Generates a Kyber keypair deterministically from provided seed values,
 * bypassing the random number generator entirely.
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
#ifdef AMA_USE_NATIVE_PQC
    uint8_t buf[64];
    uint8_t *rho, *sigma;
    polyvec a[KYBER_K], s, e, pkpv;
    unsigned int i;

    if (!d || !z || !pk || !sk) {
        return AMA_ERROR_INVALID_PARAM;
    }

    /* G(d || byte(k)) = (rho, sigma) per FIPS 203 Algorithm 15 */
    {
        uint8_t g_input[33];
        memcpy(g_input, d, 32);
        g_input[32] = (uint8_t)KYBER_K;
        ama_sha3_512(g_input, 33, buf);
        ama_secure_memzero(g_input, sizeof(g_input));
    }
    rho = buf;
    sigma = buf + 32;

    /* Generate matrix A from rho (in NTT domain) */
    kyber_gen_matrix(a, rho, 0);

    /* Sample secret vector s and error vector e from CBD */
    kyber_gennoise(&s, sigma, 0);
    kyber_gennoise(&e, sigma, (uint8_t)KYBER_K);

    /* NTT(s), NTT(e) */
    polyvec_ntt(&s);
    polyvec_ntt(&e);

    /* Compute t = A*s + e (in NTT domain) */
    for (i = 0; i < KYBER_K; i++) {
        polyvec_basemul_acc(&pkpv.vec[i], &a[i], &s);
        poly_tomont(&pkpv.vec[i]);
        poly_add(&pkpv.vec[i], &pkpv.vec[i], &e.vec[i]);
    }
    polyvec_reduce(&pkpv);

    /* Pack public key: pk = (t || rho) */
    polyvec_tobytes(pk, &pkpv);
    memcpy(pk + KYBER_K * 384, rho, 32);

    /* Pack secret key: sk = (s || pk || H(pk) || z) */
    polyvec_reduce(&s);
    polyvec_tobytes(sk, &s);
    memcpy(sk + KYBER_K * 384, pk, AMA_KYBER_1024_PUBLIC_KEY_BYTES);

    /* H(pk) */
    ama_sha3_256(pk, AMA_KYBER_1024_PUBLIC_KEY_BYTES,
                 sk + KYBER_K * 384 + AMA_KYBER_1024_PUBLIC_KEY_BYTES);

    /* z for implicit rejection (provided by caller) */
    memcpy(sk + KYBER_K * 384 + AMA_KYBER_1024_PUBLIC_KEY_BYTES + 32, z, 32);

    /* Scrub sensitive data */
    ama_secure_memzero(buf, sizeof(buf));
    ama_secure_memzero(&s, sizeof(s));
    ama_secure_memzero(&e, sizeof(e));

    return AMA_SUCCESS;
#else
    (void)d; (void)z; (void)pk; (void)sk;
    return AMA_ERROR_NOT_IMPLEMENTED;
#endif
}

/**
 * Public wrapper for Kyber encapsulation (called from ama_core.c)
 */
AMA_API ama_error_t ama_kyber_encapsulate(const uint8_t* pk, size_t pk_len,
                                   uint8_t* ct, size_t* ct_len,
                                   uint8_t* ss, size_t ss_len) {
    return kyber_encapsulate(pk, pk_len, ct, ct_len, ss, ss_len);
}

/**
 * Public wrapper for Kyber decapsulation (called from ama_core.c)
 */
AMA_API ama_error_t ama_kyber_decapsulate(const uint8_t* ct, size_t ct_len,
                                   const uint8_t* sk, size_t sk_len,
                                   uint8_t* ss, size_t ss_len) {
    return kyber_decapsulate(ct, ct_len, sk, sk_len, ss, ss_len);
}

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
    int16_t t;
    const int16_t v = ((1 << 26) + KYBER_Q / 2) / KYBER_Q;
    t = ((int32_t)v * a) >> 26;
    t *= KYBER_Q;
    return a - t;
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

    /* Generic C implementation */
    unsigned int len, start, j, k;
    int16_t t, zeta;

    k = 1;
    for (len = 128; len >= 2; len >>= 1) {
        for (start = 0; start < KYBER_N; start = j + len) {
            zeta = zetas[k++];
            for (j = start; j < start + len; j++) {
                t = montgomery_reduce((int32_t)zeta * r->coeffs[j + len]);
                r->coeffs[j + len] = r->coeffs[j] - t;
                r->coeffs[j] = r->coeffs[j] + t;
            }
        }
    }
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

    /* Generic C implementation */
    unsigned int len, start, j, k;
    int16_t t, zeta;
    const int16_t f = 1441;  /* f = 128^{-1} mod q, in Montgomery form */

    k = 127;
    for (len = 2; len <= 128; len <<= 1) {
        for (start = 0; start < KYBER_N; start = j + len) {
            zeta = zetas[k--];
            for (j = start; j < start + len; j++) {
                t = r->coeffs[j];
                r->coeffs[j] = barrett_reduce(t + r->coeffs[j + len]);
                r->coeffs[j + len] = montgomery_reduce((int32_t)zeta * (r->coeffs[j + len] - t));
            }
        }
    }

    /* Multiply by f = 128^{-1} */
    for (j = 0; j < KYBER_N; j++) {
        r->coeffs[j] = montgomery_reduce((int32_t)f * r->coeffs[j]);
    }
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
 */
static void poly_add(poly* r, const poly* a, const poly* b) {
    for (int i = 0; i < KYBER_N; i++) {
        r->coeffs[i] = a->coeffs[i] + b->coeffs[i];
    }
}

/**
 * Subtract two polynomials
 */
static void poly_sub(poly* r, const poly* a, const poly* b) {
    for (int i = 0; i < KYBER_N; i++) {
        r->coeffs[i] = a->coeffs[i] - b->coeffs[i];
    }
}

/**
 * Reduce all coefficients mod q
 */
static void poly_reduce(poly* r) {
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
                t[j] = (uint8_t)(((((uint32_t)coeff << 4) + KYBER_Q / 2) / KYBER_Q) & 0xF);
            }
            r[i] = t[0] | (t[1] << 4);
        }
    } else if (bits == 5) {
        /* Compress to 5 bits per coefficient */
        for (i = 0; i < KYBER_N / 8; i++) {
            for (j = 0; j < 8; j++) {
                int16_t coeff = coeff_normalize(a->coeffs[8*i + j]);
                t[j] = (uint8_t)(((((uint32_t)coeff << 5) + KYBER_Q / 2) / KYBER_Q) & 0x1F);
            }
            r[5*i + 0] = (t[0]) | (t[1] << 5);
            r[5*i + 1] = (t[1] >> 3) | (t[2] << 2) | (t[3] << 7);
            r[5*i + 2] = (t[3] >> 1) | (t[4] << 4);
            r[5*i + 3] = (t[4] >> 4) | (t[5] << 1) | (t[6] << 6);
            r[5*i + 4] = (t[6] >> 2) | (t[7] << 3);
        }
    } else if (bits == 10) {
        /* Compress to 10 bits per coefficient */
        for (i = 0; i < KYBER_N / 4; i++) {
            uint16_t d[4];
            for (j = 0; j < 4; j++) {
                int16_t coeff = coeff_normalize(a->coeffs[4*i + j]);
                d[j] = (uint16_t)(((((uint32_t)coeff << 10) + KYBER_Q / 2) / KYBER_Q) & 0x3FF);
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
                d[j] = (uint16_t)(((((uint32_t)coeff << 11) + KYBER_Q / 2) / KYBER_Q) & 0x7FF);
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
            uint16_t t0 = ((uint16_t)a[11*i]) | (((uint16_t)a[11*i + 1] & 0x07) << 8);
            uint16_t t1 = ((uint16_t)a[11*i + 1] >> 3) | (((uint16_t)a[11*i + 2] & 0x3F) << 5);
            uint16_t t2 = ((uint16_t)a[11*i + 2] >> 6) | ((uint16_t)a[11*i + 3] << 2) | (((uint16_t)a[11*i + 4] & 0x01) << 10);
            uint16_t t3 = ((uint16_t)a[11*i + 4] >> 1) | (((uint16_t)a[11*i + 5] & 0x0F) << 7);
            uint16_t t4 = ((uint16_t)a[11*i + 5] >> 4) | (((uint16_t)a[11*i + 6] & 0x7F) << 4);
            uint16_t t5 = ((uint16_t)a[11*i + 6] >> 7) | ((uint16_t)a[11*i + 7] << 1) | (((uint16_t)a[11*i + 8] & 0x03) << 9);
            uint16_t t6 = ((uint16_t)a[11*i + 8] >> 2) | (((uint16_t)a[11*i + 9] & 0x1F) << 6);
            uint16_t t7 = ((uint16_t)a[11*i + 9] >> 5) | ((uint16_t)a[11*i + 10] << 3);

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
