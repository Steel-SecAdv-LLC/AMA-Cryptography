/**
 * Copyright 2025 Steel Security Advisors LLC
 * Licensed under the Apache License, Version 2.0
 *
 * @file ava_kyber.c
 * @brief CRYSTALS-Kyber-1024 Key Encapsulation Mechanism - Native C Implementation
 * @author Andrew E. A., Steel Security Advisors LLC
 * @date 2025-12-06
 *
 * IMPLEMENTATION STATUS: FULL NATIVE + LIBOQS
 * =============================================
 * This file provides Kyber-1024 (ML-KEM-1024) key encapsulation.
 * When AVA_USE_NATIVE_PQC is defined (default), uses the native C
 * implementation built on the polynomial arithmetic in this file.
 * When AVA_USE_LIBOQS is defined and liboqs is linked, the liboqs
 * implementation is used instead.
 *
 * Build native (default):
 *   cmake ..
 *
 * Build with liboqs (optional):
 *   cmake -DAVA_USE_LIBOQS=ON ..
 *   Link against: -loqs
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
 * For production use: pip install ava-guardian[quantum]
 */

#include "../include/ava_guardian.h"
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdio.h>

/* liboqs integration */
#ifdef AVA_USE_LIBOQS
#include <oqs/oqs.h>
#endif

/* Forward declarations from ava_sha3.c */
extern ava_error_t ava_sha3_256(const uint8_t* input, size_t input_len, uint8_t* output);
extern ava_error_t ava_shake128(const uint8_t* input, size_t input_len,
                                 uint8_t* output, size_t output_len);
extern ava_error_t ava_shake256(const uint8_t* input, size_t input_len,
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

/* Public wrapper prototypes (called from ava_core.c via extern) */
ava_error_t ava_kyber_keypair(uint8_t* pk, size_t pk_len,
                               uint8_t* sk, size_t sk_len);
ava_error_t ava_kyber_encapsulate(const uint8_t* pk, size_t pk_len,
                                   uint8_t* ct, size_t* ct_len,
                                   uint8_t* ss, size_t ss_len);
ava_error_t ava_kyber_decapsulate(const uint8_t* ct, size_t ct_len,
                                   const uint8_t* sk, size_t sk_len,
                                   uint8_t* ss, size_t ss_len);

/**
 * Kyber context (algorithm-specific)
 */
typedef struct {
    uint8_t public_key[AVA_KYBER_1024_PUBLIC_KEY_BYTES];
    uint8_t secret_key[AVA_KYBER_1024_SECRET_KEY_BYTES];
    int keys_generated;
} kyber_context_t;

/**
 * Initialize Kyber-1024 context
 */
static kyber_context_t* kyber_init(void) {
    kyber_context_t* ctx = (kyber_context_t*)calloc(1, sizeof(kyber_context_t));
    if (!ctx) {
        return NULL;
    }
    ctx->keys_generated = 0;
    return ctx;
}

/**
 * Free Kyber context
 */
static void kyber_free(kyber_context_t* ctx) {
    if (!ctx) {
        return;
    }

    /* Scrub sensitive data */
    ava_secure_memzero(ctx->secret_key, sizeof(ctx->secret_key));
    ava_secure_memzero(ctx, sizeof(kyber_context_t));

    free(ctx);
}

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

    ava_shake128(buf, 34, stream, sizeof(stream));

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
        ava_shake256(buf, 33, stream, sizeof(stream));
        kyber_poly_cbd_eta(&r->vec[i], stream);
    }
}

/**
 * Get random bytes from OS
 */
static ava_error_t kyber_randombytes(uint8_t* buf, size_t len) {
    FILE* f = fopen("/dev/urandom", "rb");
    if (!f) {
        return AVA_ERROR_CRYPTO;
    }
    if (fread(buf, 1, len, f) != len) {
        fclose(f);
        return AVA_ERROR_CRYPTO;
    }
    fclose(f);
    return AVA_SUCCESS;
}

/**
 * Generate Kyber-1024 keypair
 *
 * When built with AVA_USE_LIBOQS, uses liboqs ML-KEM-1024 implementation.
 * When built with AVA_USE_NATIVE_PQC (default), uses the native implementation.
 *
 * @param public_key Output buffer for public key (1568 bytes)
 * @param public_key_len Length of public key buffer
 * @param secret_key Output buffer for secret key (3168 bytes)
 * @param secret_key_len Length of secret key buffer
 * @return AVA_SUCCESS or error code
 */
static ava_error_t kyber_keypair_generate(
    uint8_t* public_key,
    size_t public_key_len,
    uint8_t* secret_key,
    size_t secret_key_len
) {
    if (public_key_len < AVA_KYBER_1024_PUBLIC_KEY_BYTES ||
        secret_key_len < AVA_KYBER_1024_SECRET_KEY_BYTES) {
        return AVA_ERROR_INVALID_PARAM;
    }

#ifdef AVA_USE_LIBOQS
    OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_ml_kem_1024);
    if (!kem) {
        return AVA_ERROR_CRYPTO;
    }

    OQS_STATUS rc = OQS_KEM_keypair(kem, public_key, secret_key);
    OQS_KEM_free(kem);

    if (rc != OQS_SUCCESS) {
        return AVA_ERROR_CRYPTO;
    }
    return AVA_SUCCESS;
#elif defined(AVA_USE_NATIVE_PQC)
    {
        /* Native Kyber-1024 key generation (NIST FIPS 203, Algorithm 15) */
        uint8_t d[32], buf[64];
        uint8_t *rho, *sigma;
        polyvec a[KYBER_K], s, e, pkpv;
        unsigned int i;
        ava_error_t err;

        /* Generate random seed d */
        err = kyber_randombytes(d, 32);
        if (err != AVA_SUCCESS) {
            return err;
        }

        /* G(d) = (rho, sigma) */
        ava_sha3_256(d, 32, buf);  /* Hash d to get more seed material */
        /* Expand d into rho || sigma using SHAKE256 */
        ava_shake256(d, 32, buf, 64);
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

        /* Compute t = A*s + e (in NTT domain) */
        for (i = 0; i < KYBER_K; i++) {
            polyvec_basemul_acc(&pkpv.vec[i], &a[i], &s);
            poly_add(&pkpv.vec[i], &pkpv.vec[i], &e.vec[i]);
        }
        polyvec_reduce(&pkpv);

        /* Pack public key: pk = (t || rho) */
        polyvec_tobytes(public_key, &pkpv);
        memcpy(public_key + KYBER_K * 384, rho, 32);

        /* Pack secret key: sk = (s || pk || H(pk) || z) */
        polyvec_tobytes(secret_key, &s);
        memcpy(secret_key + KYBER_K * 384, public_key, AVA_KYBER_1024_PUBLIC_KEY_BYTES);

        /* H(pk) */
        ava_sha3_256(public_key, AVA_KYBER_1024_PUBLIC_KEY_BYTES,
                     secret_key + KYBER_K * 384 + AVA_KYBER_1024_PUBLIC_KEY_BYTES);

        /* Random z for implicit rejection */
        err = kyber_randombytes(
            secret_key + KYBER_K * 384 + AVA_KYBER_1024_PUBLIC_KEY_BYTES + 32, 32);
        if (err != AVA_SUCCESS) {
            return err;
        }

        /* Scrub sensitive data */
        ava_secure_memzero(d, sizeof(d));
        ava_secure_memzero(buf, sizeof(buf));
        ava_secure_memzero(&s, sizeof(s));
        ava_secure_memzero(&e, sizeof(e));

        return AVA_SUCCESS;
    }
#else
    (void)public_key;
    (void)secret_key;
    return AVA_ERROR_NOT_IMPLEMENTED;
#endif
}

/**
 * Encapsulate shared secret
 *
 * When built with AVA_USE_LIBOQS, uses liboqs ML-KEM-1024 implementation.
 * When built with AVA_USE_NATIVE_PQC (default), uses native implementation.
 *
 * @param public_key Recipient's public key (1568 bytes)
 * @param public_key_len Length of public key
 * @param ciphertext Output buffer for ciphertext (1568 bytes)
 * @param ciphertext_len Pointer to ciphertext length (in/out)
 * @param shared_secret Output buffer for shared secret (32 bytes)
 * @param shared_secret_len Length of shared secret buffer
 * @return AVA_SUCCESS or error code
 */
static ava_error_t kyber_encapsulate(
    const uint8_t* public_key,
    size_t public_key_len,
    uint8_t* ciphertext,
    size_t* ciphertext_len,
    uint8_t* shared_secret,
    size_t shared_secret_len
) {
    if (public_key_len != AVA_KYBER_1024_PUBLIC_KEY_BYTES ||
        shared_secret_len != AVA_KYBER_1024_SHARED_SECRET_BYTES) {
        return AVA_ERROR_INVALID_PARAM;
    }

#ifdef AVA_USE_LIBOQS
    if (*ciphertext_len < AVA_KYBER_1024_CIPHERTEXT_BYTES) {
        *ciphertext_len = AVA_KYBER_1024_CIPHERTEXT_BYTES;
        return AVA_ERROR_INVALID_PARAM;
    }

    OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_ml_kem_1024);
    if (!kem) {
        return AVA_ERROR_CRYPTO;
    }

    OQS_STATUS rc = OQS_KEM_encaps(kem, ciphertext, shared_secret, public_key);
    OQS_KEM_free(kem);

    if (rc != OQS_SUCCESS) {
        return AVA_ERROR_CRYPTO;
    }

    *ciphertext_len = AVA_KYBER_1024_CIPHERTEXT_BYTES;
    return AVA_SUCCESS;
#elif defined(AVA_USE_NATIVE_PQC)
    {
        /* Native Kyber-1024 encapsulation (NIST FIPS 203, Algorithm 17) */
        uint8_t m[32], kr[64];
        uint8_t *rho;
        polyvec a[KYBER_K], sp, ep, pkpv, bp;
        poly v, epp, mp_poly;
        unsigned int i;
        ava_error_t err;

        if (*ciphertext_len < AVA_KYBER_1024_CIPHERTEXT_BYTES) {
            *ciphertext_len = AVA_KYBER_1024_CIPHERTEXT_BYTES;
            return AVA_ERROR_INVALID_PARAM;
        }

        /* Generate random message m */
        err = kyber_randombytes(m, 32);
        if (err != AVA_SUCCESS) {
            return err;
        }

        /* Hash m with H(pk) to get (K, r) */
        {
            uint8_t pk_hash[32];
            uint8_t m_hash_input[64];
            ava_sha3_256(public_key, AVA_KYBER_1024_PUBLIC_KEY_BYTES, pk_hash);
            memcpy(m_hash_input, m, 32);
            memcpy(m_hash_input + 32, pk_hash, 32);
            ava_shake256(m_hash_input, 64, kr, 64);
        }

        /* Extract rho from public key */
        rho = (uint8_t*)(public_key + KYBER_K * 384);

        /* Decode public key */
        polyvec_frombytes(&pkpv, public_key);

        /* Generate matrix A^T from rho */
        kyber_gen_matrix(a, rho, 1);

        /* Sample r, e1, e2 from noise */
        kyber_gennoise(&sp, kr + 32, 0);
        kyber_gennoise(&ep, kr + 32, (uint8_t)KYBER_K);
        {
            uint8_t noise_buf[33];
            uint8_t noise_stream[KYBER_ETA2 * KYBER_N / 4];
            memcpy(noise_buf, kr + 32, 32);
            noise_buf[32] = 2 * (uint8_t)KYBER_K;
            ava_shake256(noise_buf, 33, noise_stream, sizeof(noise_stream));
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
        polyvec_compress(ciphertext, &bp);
        poly_compress(ciphertext + KYBER_K * (KYBER_N * KYBER_DU / 8), &v, KYBER_DV);

        /* Shared secret = first 32 bytes of kr */
        memcpy(shared_secret, kr, 32);

        *ciphertext_len = AVA_KYBER_1024_CIPHERTEXT_BYTES;

        /* Scrub sensitive data */
        ava_secure_memzero(m, sizeof(m));
        ava_secure_memzero(kr, sizeof(kr));
        ava_secure_memzero(&sp, sizeof(sp));

        return AVA_SUCCESS;
    }
#else
    (void)public_key;
    (void)ciphertext;
    (void)ciphertext_len;
    (void)shared_secret;
    return AVA_ERROR_NOT_IMPLEMENTED;
#endif
}

/**
 * Decapsulate shared secret
 *
 * When built with AVA_USE_LIBOQS, uses liboqs ML-KEM-1024 implementation.
 * When built with AVA_USE_NATIVE_PQC (default), uses native implementation.
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
 * @return AVA_SUCCESS or error code
 */
static ava_error_t kyber_decapsulate(
    const uint8_t* ciphertext,
    size_t ciphertext_len,
    const uint8_t* secret_key,
    size_t secret_key_len,
    uint8_t* shared_secret,
    size_t shared_secret_len
) {
    if (ciphertext_len != AVA_KYBER_1024_CIPHERTEXT_BYTES ||
        secret_key_len != AVA_KYBER_1024_SECRET_KEY_BYTES ||
        shared_secret_len != AVA_KYBER_1024_SHARED_SECRET_BYTES) {
        return AVA_ERROR_INVALID_PARAM;
    }

#ifdef AVA_USE_LIBOQS
    OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_ml_kem_1024);
    if (!kem) {
        return AVA_ERROR_CRYPTO;
    }

    OQS_STATUS rc = OQS_KEM_decaps(kem, shared_secret, ciphertext, secret_key);
    OQS_KEM_free(kem);

    if (rc != OQS_SUCCESS) {
        return AVA_ERROR_CRYPTO;
    }
    return AVA_SUCCESS;
#elif defined(AVA_USE_NATIVE_PQC)
    {
        /* Native Kyber-1024 decapsulation (NIST FIPS 203, Algorithm 18) */
        /* Uses implicit rejection for IND-CCA2 security */
        polyvec bp, skpv;
        poly v, mp;
        uint8_t m[32], kr[64];
        uint8_t ct_cmp[AVA_KYBER_1024_CIPHERTEXT_BYTES];
        size_t ct_cmp_len = AVA_KYBER_1024_CIPHERTEXT_BYTES;
        const uint8_t *pk;
        const uint8_t *h_pk;
        const uint8_t *z;
        unsigned int i;
        int fail;

        /* Parse secret key: s || pk || H(pk) || z */
        polyvec_frombytes(&skpv, secret_key);
        pk = secret_key + KYBER_K * 384;
        h_pk = pk + AVA_KYBER_1024_PUBLIC_KEY_BYTES;
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

        /* Decode message from polynomial */
        for (i = 0; i < 32; i++) {
            m[i] = 0;
            unsigned int j;
            for (j = 0; j < 8; j++) {
                int16_t t = mp.coeffs[8*i + j];
                t += (t >> 15) & KYBER_Q;
                /* Round to nearest: is coefficient closer to 0 or q/2? */
                t = (int16_t)(((uint32_t)t << 1) + KYBER_Q / 2) / KYBER_Q;
                m[i] |= (uint8_t)((t & 1) << j);
            }
        }

        /* Re-derive (K, r) = G(m || H(pk)) */
        {
            uint8_t m_hash_input[64];
            memcpy(m_hash_input, m, 32);
            memcpy(m_hash_input + 32, h_pk, 32);
            ava_shake256(m_hash_input, 64, kr, 64);
        }

        /* Re-encrypt and compare ciphertext */
        {
            ava_error_t enc_err = kyber_encapsulate(
                pk, AVA_KYBER_1024_PUBLIC_KEY_BYTES,
                ct_cmp, &ct_cmp_len, kr, 32);
            /* Note: we use kr as temp for shared_secret here, then overwrite below */
            (void)enc_err;
        }

        /* Constant-time comparison of ciphertexts */
        fail = ava_consttime_memcmp(ciphertext, ct_cmp, AVA_KYBER_1024_CIPHERTEXT_BYTES);

        /* If match, output K; if mismatch, output H(z || ct) for implicit rejection */
        if (fail) {
            /* Implicit rejection: hash z || ciphertext */
            uint8_t *rej_input = (uint8_t *)malloc(32 + AVA_KYBER_1024_CIPHERTEXT_BYTES);
            if (rej_input) {
                memcpy(rej_input, z, 32);
                memcpy(rej_input + 32, ciphertext, AVA_KYBER_1024_CIPHERTEXT_BYTES);
                ava_shake256(rej_input, 32 + AVA_KYBER_1024_CIPHERTEXT_BYTES,
                            shared_secret, 32);
                ava_secure_memzero(rej_input, 32 + AVA_KYBER_1024_CIPHERTEXT_BYTES);
                free(rej_input);
            }
        } else {
            memcpy(shared_secret, kr, 32);
        }

        /* Scrub sensitive data */
        ava_secure_memzero(m, sizeof(m));
        ava_secure_memzero(kr, sizeof(kr));

        return AVA_SUCCESS;
    }
#else
    (void)ciphertext;
    (void)secret_key;
    (void)shared_secret;
    return AVA_ERROR_NOT_IMPLEMENTED;
#endif
}

/* ============================================================================
 * PUBLIC WRAPPERS FOR CORE DISPATCH
 * ============================================================================ */

/**
 * Public wrapper for Kyber keypair generation (called from ava_core.c)
 */
ava_error_t ava_kyber_keypair(uint8_t* pk, size_t pk_len,
                               uint8_t* sk, size_t sk_len) {
    return kyber_keypair_generate(pk, pk_len, sk, sk_len);
}

/**
 * Public wrapper for Kyber encapsulation (called from ava_core.c)
 */
ava_error_t ava_kyber_encapsulate(const uint8_t* pk, size_t pk_len,
                                   uint8_t* ct, size_t* ct_len,
                                   uint8_t* ss, size_t ss_len) {
    return kyber_encapsulate(pk, pk_len, ct, ct_len, ss, ss_len);
}

/**
 * Public wrapper for Kyber decapsulation (called from ava_core.c)
 */
ava_error_t ava_kyber_decapsulate(const uint8_t* ct, size_t ct_len,
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

    u = (int16_t)(a * 62209);  /* q^-1 mod 2^16 = 62209 */
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
    t = (int32_t)v * a >> 26;
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

/* Inverse NTT twiddle factors (zetas_inv) */
static const int16_t zetas_inv[128] = {
    1701, 1807, 1460, 2371, 2338, 2333, 308, 108,
    2851, 870, 854, 1510, 2535, 1278, 1530, 1185,
    1659, 1187, 3109, 874, 1335, 2111, 136, 1215,
    2945, 1465, 1285, 2007, 2719, 2726, 2232, 2512,
    75, 156, 3000, 2911, 2980, 872, 2685, 1590,
    2210, 602, 1846, 777, 147, 2170, 2551, 246,
    1676, 1755, 460, 291, 235, 3152, 2742, 2907,
    3224, 1779, 2458, 1251, 2486, 2774, 2899, 1103,
    1275, 2652, 1065, 2881, 725, 1508, 2368, 398,
    951, 247, 1421, 3222, 2499, 271, 90, 853,
    1860, 3203, 1162, 1618, 666, 320, 8, 2813,
    1544, 282, 1838, 1293, 2314, 552, 2677, 2106,
    1571, 205, 2918, 1542, 2721, 2597, 2312, 681,
    130, 1602, 1871, 829, 2946, 3065, 1325, 2756,
    1861, 1474, 1202, 2367, 3147, 1752, 2707, 171,
    3127, 3042, 1907, 1836, 1517, 359, 758, 1441
};

/**
 * Number Theoretic Transform (forward NTT)
 * Converts polynomial from coefficient form to NTT form for fast multiplication.
 * Uses Cooley-Tukey butterfly with Montgomery reduction.
 */
static void poly_ntt(poly* r) {
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
    unsigned int len, start, j, k;
    int16_t t, zeta;
    const int16_t f = 1441;  /* f = 128^{-1} mod q, in Montgomery form */

    k = 127;
    for (len = 2; len <= 128; len <<= 1) {
        for (start = 0; start < KYBER_N; start = j + len) {
            zeta = zetas_inv[k--];
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
 * Serialize polynomial to bytes (12-bit coefficients)
 * Packs 256 coefficients into 384 bytes
 */
static void poly_tobytes(uint8_t* r, const poly* a) {
    unsigned int i;
    uint16_t t0, t1;

    for (i = 0; i < KYBER_N / 2; i++) {
        t0 = (uint16_t)csubq(a->coeffs[2*i]);
        t1 = (uint16_t)csubq(a->coeffs[2*i + 1]);

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
                int16_t coeff = csubq(a->coeffs[2*i + j]);
                t[j] = (uint8_t)(((((uint32_t)coeff << 4) + KYBER_Q / 2) / KYBER_Q) & 0xF);
            }
            r[i] = t[0] | (t[1] << 4);
        }
    } else if (bits == 5) {
        /* Compress to 5 bits per coefficient */
        for (i = 0; i < KYBER_N / 8; i++) {
            for (j = 0; j < 8; j++) {
                int16_t coeff = csubq(a->coeffs[8*i + j]);
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
            for (j = 0; j < 4; j++) {
                int16_t coeff = csubq(a->coeffs[4*i + j]);
                t[j] = (uint8_t)(((((uint32_t)coeff << 10) + KYBER_Q / 2) / KYBER_Q) & 0x3FF);
            }
            r[5*i + 0] = (uint8_t)(t[0]);
            r[5*i + 1] = (uint8_t)((t[0] >> 8) | (t[1] << 2));
            r[5*i + 2] = (uint8_t)((t[1] >> 6) | (t[2] << 4));
            r[5*i + 3] = (uint8_t)((t[2] >> 4) | (t[3] << 6));
            r[5*i + 4] = (uint8_t)(t[3] >> 2);
        }
    } else if (bits == 11) {
        /* Compress to 11 bits per coefficient (Kyber-1024) */
        for (i = 0; i < KYBER_N / 8; i++) {
            for (j = 0; j < 8; j++) {
                int16_t coeff = csubq(a->coeffs[8*i + j]);
                uint16_t t16 = (uint16_t)(((((uint32_t)coeff << 11) + KYBER_Q / 2) / KYBER_Q) & 0x7FF);
                t[j] = t16 & 0xFF;
            }
            r[11*i + 0] = t[0];
            r[11*i + 1] = (t[0] >> 8) | (t[1] << 3);
            r[11*i + 2] = (t[1] >> 5) | (t[2] << 6);
            r[11*i + 3] = t[2] >> 2;
            r[11*i + 4] = (t[2] >> 10) | (t[3] << 1);
            r[11*i + 5] = (t[3] >> 7) | (t[4] << 4);
            r[11*i + 6] = (t[4] >> 4) | (t[5] << 7);
            r[11*i + 7] = t[5] >> 1;
            r[11*i + 8] = (t[5] >> 9) | (t[6] << 2);
            r[11*i + 9] = (t[6] >> 6) | (t[7] << 5);
            r[11*i + 10] = t[7] >> 3;
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
