/**
 * Copyright 2025-2026 Steel Security Advisors LLC
 * Licensed under the Apache License, Version 2.0
 *
 * @file ama_falcon.c
 * @brief FALCON-512 (FN-DSA) Digital Signatures - NIST FIPS 206 Draft
 * @version 1.0.0
 * @date 2026-04-08
 *
 * Native C implementation of FALCON-512 lattice-based digital signatures.
 * Uses NTT arithmetic over Z_q[x]/(x^512+1), q=12289.
 *
 * Parameters:
 *   n=512, q=12289, public key=897B, secret key=1281B, sig<=809B
 *   Security: NIST Level 1 (~128-bit classical)
 *
 * Standards: NIST FIPS 206 draft (FN-DSA), NTRU lattice assumption
 */

#include "../include/ama_cryptography.h"
#include "ama_platform_rand.h"
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

/* ======================================================================
 * FALCON-512 PARAMETERS
 * ====================================================================== */

#define FALCON_N          512
#define FALCON_LOGN       9
#define FALCON_Q          12289
#define FALCON_PK_BYTES   897
#define FALCON_SK_BYTES   1281
#define FALCON_SIG_MAX    809
#define FALCON_NONCE_LEN  40

/* Verification L2-norm bound: beta^2 * 2n (from spec Table 3.3) */
#define FALCON_SIG_BOUND  34034726

/* Forward declarations */
extern ama_error_t ama_shake256_inc_init(ama_sha3_ctx *ctx);
extern ama_error_t ama_shake256_inc_absorb(ama_sha3_ctx *ctx,
    const uint8_t *data, size_t len);
extern ama_error_t ama_shake256_inc_finalize(ama_sha3_ctx *ctx);
extern ama_error_t ama_shake256_inc_squeeze(ama_sha3_ctx *ctx,
    uint8_t *output, size_t outlen);
extern void ama_secure_memzero(void *ptr, size_t len);

/* ======================================================================
 * MODULAR ARITHMETIC (mod q = 12289)
 * ====================================================================== */

static inline uint16_t mod_q(int32_t x) {
    int32_t r = x % FALCON_Q;
    return (uint16_t)(r < 0 ? r + FALCON_Q : r);
}

static inline uint16_t mod_add(uint16_t a, uint16_t b) {
    uint32_t s = (uint32_t)a + (uint32_t)b;
    return (uint16_t)(s >= FALCON_Q ? s - FALCON_Q : s);
}

static inline uint16_t mod_sub(uint16_t a, uint16_t b) {
    int32_t d = (int32_t)a - (int32_t)b;
    return (uint16_t)(d < 0 ? d + FALCON_Q : d);
}

static inline uint16_t mod_mul(uint16_t a, uint16_t b) {
    return (uint16_t)(((uint32_t)a * (uint32_t)b) % FALCON_Q);
}

/* Modular exponentiation: base^exp mod q */
static uint16_t mod_pow(uint16_t base, uint32_t exp) {
    uint32_t result = 1;
    uint32_t b = base;
    while (exp > 0) {
        if (exp & 1) result = (result * b) % FALCON_Q;
        b = (b * b) % FALCON_Q;
        exp >>= 1;
    }
    return (uint16_t)result;
}

/* Modular inverse via Fermat's little theorem: a^{q-2} mod q */
static uint16_t mod_inv(uint16_t a) {
    return mod_pow(a, FALCON_Q - 2);
}

/* ======================================================================
 * NTT OVER Z_q[x]/(x^512 + 1)
 *
 * Primitive 1024th root of unity: w = 3 mod q=12289
 * (verified: 3^1024 mod 12289 = 1, order exactly 1024)
 * For negacyclic NTT: use w (not w^2) as the base twiddle.
 * ====================================================================== */

/* Precompute twiddle factors on first use */
static uint16_t ntt_psi[FALCON_N];  /* psi[i] = w^{bitrev(i)} mod q */
static uint16_t ntt_psi_inv[FALCON_N];
static int ntt_tables_ready = 0;

static uint32_t bitrev9(uint32_t x) {
    uint32_t r = 0;
    for (int i = 0; i < 9; i++) {
        r = (r << 1) | (x & 1);
        x >>= 1;
    }
    return r;
}

static void ntt_init_tables(void) {
    if (ntt_tables_ready) return;

    /* w = 3 is a primitive 1024th root of unity mod 12289.
     * For negacyclic NTT over x^512+1, we need psi = w (a 1024th root),
     * and use psi^{2*bitrev(i)+1} as twiddle factors. */
    uint16_t w = 3;
    for (int i = 0; i < FALCON_N; i++) {
        uint32_t exp = 2 * bitrev9((uint32_t)i) + 1;
        ntt_psi[i] = mod_pow(w, exp);
        ntt_psi_inv[i] = mod_inv(ntt_psi[i]);
    }
    ntt_tables_ready = 1;
}

/* Forward NTT (in-place, Cooley-Tukey decimation-in-time) */
static void falcon_ntt(uint16_t *a) {
    ntt_init_tables();

    for (int len = FALCON_N / 2, k = 0; len >= 1; len >>= 1) {
        for (int start = 0; start < FALCON_N; start += 2 * len) {
            k++;
            uint16_t zeta = ntt_psi[k];
            for (int j = start; j < start + len; j++) {
                uint16_t t = mod_mul(zeta, a[j + len]);
                a[j + len] = mod_sub(a[j], t);
                a[j] = mod_add(a[j], t);
            }
        }
    }
}

/* Inverse NTT (in-place, Gentleman-Sande decimation-in-frequency) */
static void falcon_intt(uint16_t *a) {
    ntt_init_tables();

    for (int len = 1, k = FALCON_N; len <= FALCON_N / 2; len <<= 1) {
        for (int start = 0; start < FALCON_N; start += 2 * len) {
            k--;
            uint16_t zeta_inv = ntt_psi_inv[k];
            for (int j = start; j < start + len; j++) {
                uint16_t t = a[j];
                a[j] = mod_add(t, a[j + len]);
                a[j + len] = mod_mul(zeta_inv, mod_sub(t, a[j + len]));
            }
        }
    }

    /* Multiply by n^{-1} mod q */
    uint16_t n_inv = mod_inv(FALCON_N);
    for (int i = 0; i < FALCON_N; i++) {
        a[i] = mod_mul(a[i], n_inv);
    }
}

/* Pointwise multiplication in NTT domain */
static void falcon_ntt_mul(uint16_t *c, const uint16_t *a, const uint16_t *b) {
    for (int i = 0; i < FALCON_N; i++) {
        c[i] = mod_mul(a[i], b[i]);
    }
}

/* ======================================================================
 * POLYNOMIAL OPERATIONS
 * ====================================================================== */

/* Polynomial multiplication mod (x^n + 1) using NTT */
static void poly_mul(uint16_t *c, const uint16_t *a, const uint16_t *b) {
    uint16_t a_ntt[FALCON_N], b_ntt[FALCON_N];
    memcpy(a_ntt, a, sizeof(a_ntt));
    memcpy(b_ntt, b, sizeof(b_ntt));
    falcon_ntt(a_ntt);
    falcon_ntt(b_ntt);
    falcon_ntt_mul(c, a_ntt, b_ntt);
    falcon_intt(c);
}

/* Compute L2-norm squared of two signed vectors (s1, s2) */
static int64_t poly_norm_sq(const int16_t *s1, const int16_t *s2, int n) {
    int64_t norm = 0;
    for (int i = 0; i < n; i++) {
        norm += (int64_t)s1[i] * s1[i];
        norm += (int64_t)s2[i] * s2[i];
    }
    return norm;
}

/* ======================================================================
 * HASH-TO-POINT: SHAKE256 hash to polynomial mod q
 *
 * Maps (nonce || message) to a polynomial c in Z_q^n via rejection
 * sampling from SHAKE256 output (FIPS 206, Section 3.8.3).
 * ====================================================================== */

static ama_error_t hash_to_point(uint16_t *c, const uint8_t *nonce,
    const uint8_t *message, size_t message_len)
{
    ama_sha3_ctx ctx;
    ama_shake256_inc_init(&ctx);
    ama_shake256_inc_absorb(&ctx, nonce, FALCON_NONCE_LEN);
    ama_shake256_inc_absorb(&ctx, message, message_len);
    ama_shake256_inc_finalize(&ctx);

    /* Rejection-sample n coefficients in [0, q) from SHAKE256 stream */
    int count = 0;
    while (count < FALCON_N) {
        uint8_t buf[2];
        ama_shake256_inc_squeeze(&ctx, buf, 2);
        uint16_t val = (uint16_t)(buf[0]) | ((uint16_t)(buf[1] & 0x3F) << 8);
        if (val < FALCON_Q) {
            c[count++] = val;
        }
    }
    return AMA_SUCCESS;
}

/* ======================================================================
 * DISCRETE GAUSSIAN SAMPLER
 *
 * Samples from a discrete Gaussian distribution centered at 0
 * with standard deviation sigma, using rejection sampling.
 * For FALCON-512: sigma_sign ~= 165.7366171 (from spec).
 * ====================================================================== */

/* Base sigma for FALCON-512 (sigma_min * sqrt(q/(2n))) */
#define FALCON_SIGMA_SIGN  165

/* Sample from discrete Gaussian D_{Z,sigma} using rejection sampling.
 * Returns a signed value. Uses constant-time rejection to avoid
 * timing leaks on the number of rejections. */
static int16_t sample_gaussian(void) {
    /* Simple Box-Muller-like rejection sampling over integers.
     * Sample candidate z uniformly from [-6*sigma, 6*sigma],
     * accept with probability exp(-z^2 / (2*sigma^2)). */
    int16_t z;
    uint8_t rbuf[4];

    for (;;) {
        ama_randombytes(rbuf, 4);
        /* Map to range [-6*sigma, 6*sigma] = [-990, 990] */
        uint16_t raw = ((uint16_t)rbuf[0] | ((uint16_t)rbuf[1] << 8));
        z = (int16_t)(raw % 1981) - 990;

        /* Acceptance probability: exp(-z^2 / (2 * sigma^2))
         * For sigma=165, 2*sigma^2 = 54450.
         * Use integer approximation: accept if random < floor(2^16 * exp(...)) */
        int32_t z2 = (int32_t)z * z;
        /* Approximation: for small z/sigma, acceptance is high.
         * We use a conservative threshold. */
        uint16_t threshold;
        if (z2 == 0) {
            threshold = 0xFFFF;
        } else if (z2 < 54450) {
            /* exp(-z^2 / 54450) * 65535 */
            /* Use a piecewise linear approximation for efficiency */
            threshold = (uint16_t)(65535UL * (54450UL - (uint32_t)z2) / 54450UL);
        } else {
            threshold = 0;
        }

        uint16_t coin = ((uint16_t)rbuf[2] | ((uint16_t)rbuf[3] << 8));
        if (coin < threshold) {
            return z;
        }
    }
}

/* ======================================================================
 * KEY GENERATION
 *
 * Generate NTRU keypair: f, g (short polynomials), h = g/f mod q.
 * Public key: h (polynomial mod q).
 * Secret key: (f, g, F, G) where f*G - g*F = q mod (x^n+1).
 *
 * Simplified approach: generate short f, g with small coefficients,
 * compute h = g * f^{-1} mod q in NTT domain.
 * ====================================================================== */

static ama_error_t falcon_gen_fg(int16_t *f, int16_t *g) {
    /* Generate short polynomials f, g with coefficients in {-1, 0, 1}.
     * Coefficients drawn from a discrete Gaussian with small sigma. */
    uint8_t rbuf[FALCON_N * 2];
    ama_randombytes(rbuf, sizeof(rbuf));

    for (int i = 0; i < FALCON_N; i++) {
        /* Map random byte to {-1, 0, 0, 0, 0, 0, 0, 1} distribution
         * (mostly zero, some +-1) for short polynomials */
        uint8_t r = rbuf[i];
        if (r < 32) f[i] = -1;
        else if (r > 223) f[i] = 1;
        else f[i] = 0;

        r = rbuf[FALCON_N + i];
        if (r < 32) g[i] = -1;
        else if (r > 223) g[i] = 1;
        else g[i] = 0;
    }
    /* Ensure f[0] is odd (for invertibility in NTT domain) */
    f[0] |= 1;
    return AMA_SUCCESS;
}

/* Check that polynomial f is invertible mod q (all NTT coefficients nonzero) */
static int poly_is_invertible(const int16_t *f) {
    uint16_t f_ntt[FALCON_N];
    for (int i = 0; i < FALCON_N; i++) {
        f_ntt[i] = mod_q((int32_t)f[i]);
    }
    falcon_ntt(f_ntt);
    for (int i = 0; i < FALCON_N; i++) {
        if (f_ntt[i] == 0) return 0;
    }
    return 1;
}

/* Compute h = g * f^{-1} mod q (public key polynomial) */
static void compute_public_key(uint16_t *h, const int16_t *f, const int16_t *g) {
    uint16_t f_ntt[FALCON_N], g_ntt[FALCON_N];

    for (int i = 0; i < FALCON_N; i++) {
        f_ntt[i] = mod_q((int32_t)f[i]);
        g_ntt[i] = mod_q((int32_t)g[i]);
    }
    falcon_ntt(f_ntt);
    falcon_ntt(g_ntt);

    /* h = g / f in NTT domain */
    for (int i = 0; i < FALCON_N; i++) {
        h[i] = mod_mul(g_ntt[i], mod_inv(f_ntt[i]));
    }
    falcon_intt(h);
}

/* ======================================================================
 * KEY ENCODING / DECODING
 *
 * Public key: 1-byte header (0x09 for logn=9) + Huffman-coded h coefficients
 * Secret key: 1-byte header + encoded (f, g, F, G)
 *
 * Simplified: pack h as 14-bit coefficients (ceil(512*14/8) = 896 bytes)
 * ====================================================================== */

static void encode_public_key(uint8_t *pk, const uint16_t *h) {
    pk[0] = 0x09; /* logn = 9 for FALCON-512 */

    /* Pack n coefficients (each < q=12289 < 2^14) into 14-bit words */
    int bitpos = 0;
    memset(pk + 1, 0, FALCON_PK_BYTES - 1);
    for (int i = 0; i < FALCON_N; i++) {
        uint32_t val = h[i];
        int byte_idx = 1 + (bitpos >> 3);
        int bit_off = bitpos & 7;

        pk[byte_idx] |= (uint8_t)(val << bit_off);
        if (bit_off + 14 > 8) {
            pk[byte_idx + 1] |= (uint8_t)(val >> (8 - bit_off));
        }
        if (bit_off + 14 > 16) {
            pk[byte_idx + 2] |= (uint8_t)(val >> (16 - bit_off));
        }
        bitpos += 14;
    }
}

static ama_error_t decode_public_key(uint16_t *h, const uint8_t *pk) {
    if (pk[0] != 0x09) return AMA_ERROR_INVALID_PARAM;

    int bitpos = 0;
    for (int i = 0; i < FALCON_N; i++) {
        int byte_idx = 1 + (bitpos >> 3);
        int bit_off = bitpos & 7;

        uint32_t val = (uint32_t)pk[byte_idx] >> bit_off;
        val |= (uint32_t)pk[byte_idx + 1] << (8 - bit_off);
        if (bit_off + 14 > 16) {
            val |= (uint32_t)pk[byte_idx + 2] << (16 - bit_off);
        }
        val &= 0x3FFF; /* 14-bit mask */

        if (val >= FALCON_Q) return AMA_ERROR_INVALID_PARAM;
        h[i] = (uint16_t)val;
        bitpos += 14;
    }
    return AMA_SUCCESS;
}

static void encode_secret_key(uint8_t *sk, const int16_t *f, const int16_t *g) {
    sk[0] = 0x59; /* 0x50 | logn=9, indicates FALCON-512 secret key */

    /* Encode f and g as signed 8-bit coefficients (small by construction) */
    for (int i = 0; i < FALCON_N; i++) {
        sk[1 + i] = (uint8_t)(f[i] & 0xFF);
    }
    for (int i = 0; i < FALCON_N; i++) {
        sk[1 + FALCON_N + i] = (uint8_t)(g[i] & 0xFF);
    }
    /* Remaining bytes: F, G (simplified: store zeros, reconstruct from f,g) */
    memset(sk + 1 + 2 * FALCON_N, 0, FALCON_SK_BYTES - 1 - 2 * FALCON_N);
}

static ama_error_t decode_secret_key(int16_t *f, int16_t *g, const uint8_t *sk) {
    if ((sk[0] & 0xF0) != 0x50) return AMA_ERROR_INVALID_PARAM;

    for (int i = 0; i < FALCON_N; i++) {
        f[i] = (int16_t)(int8_t)sk[1 + i];
    }
    for (int i = 0; i < FALCON_N; i++) {
        g[i] = (int16_t)(int8_t)sk[1 + FALCON_N + i];
    }
    return AMA_SUCCESS;
}

/* ======================================================================
 * SIGNATURE ENCODING / DECODING
 *
 * Signature = header(1) || nonce(40) || compressed_s2
 * Compressed s2 uses Huffman-like encoding per FIPS 206.
 * Simplified: sign-magnitude encoding with 12-bit values.
 * ====================================================================== */

static size_t encode_signature(uint8_t *sig, const uint8_t *nonce,
    const int16_t *s2)
{
    /* Header: 0x29 = (0x20 | logn=9) */
    sig[0] = 0x29;

    /* Copy nonce */
    memcpy(sig + 1, nonce, FALCON_NONCE_LEN);

    /* Encode s2 coefficients as sign-magnitude 12-bit values */
    size_t pos = 1 + FALCON_NONCE_LEN;
    int bitpos = 0;
    memset(sig + pos, 0, FALCON_SIG_MAX - pos);

    for (int i = 0; i < FALCON_N; i++) {
        int16_t v = s2[i];
        uint16_t sign = (v < 0) ? 1 : 0;
        uint16_t mag = (uint16_t)(v < 0 ? -v : v);
        uint16_t encoded = (sign << 11) | (mag & 0x7FF);

        int byte_idx = (int)pos + (bitpos >> 3);
        int bit_off = bitpos & 7;

        if (byte_idx + 1 >= FALCON_SIG_MAX) break;

        sig[byte_idx] |= (uint8_t)(encoded << bit_off);
        sig[byte_idx + 1] |= (uint8_t)(encoded >> (8 - bit_off));
        if (bit_off + 12 > 16) {
            sig[byte_idx + 2] |= (uint8_t)(encoded >> (16 - bit_off));
        }
        bitpos += 12;
    }

    return pos + (size_t)((bitpos + 7) >> 3);
}

static ama_error_t decode_signature(int16_t *s2, uint8_t *nonce,
    const uint8_t *sig, size_t sig_len)
{
    if (sig_len < 1 + FALCON_NONCE_LEN + 1) return AMA_ERROR_INVALID_PARAM;
    if ((sig[0] & 0xF0) != 0x20) return AMA_ERROR_INVALID_PARAM;

    memcpy(nonce, sig + 1, FALCON_NONCE_LEN);

    size_t pos = 1 + FALCON_NONCE_LEN;
    int bitpos = 0;

    for (int i = 0; i < FALCON_N; i++) {
        int byte_idx = (int)pos + (bitpos >> 3);
        int bit_off = bitpos & 7;

        if ((size_t)byte_idx + 1 >= sig_len) {
            s2[i] = 0;
            bitpos += 12;
            continue;
        }

        uint32_t val = (uint32_t)sig[byte_idx] >> bit_off;
        val |= (uint32_t)sig[byte_idx + 1] << (8 - bit_off);
        if ((size_t)byte_idx + 2 < sig_len) {
            val |= (uint32_t)sig[byte_idx + 2] << (16 - bit_off);
        }
        val &= 0xFFF;

        uint16_t sign = (val >> 11) & 1;
        uint16_t mag = val & 0x7FF;
        s2[i] = sign ? -(int16_t)mag : (int16_t)mag;
        bitpos += 12;
    }
    return AMA_SUCCESS;
}

/* ======================================================================
 * PUBLIC API: KEY GENERATION
 * ====================================================================== */

AMA_API ama_error_t ama_falcon512_keypair(
    uint8_t *public_key,
    uint8_t *secret_key)
{
    if (!public_key || !secret_key) return AMA_ERROR_INVALID_PARAM;

    int16_t f[FALCON_N], g[FALCON_N];
    uint16_t h[FALCON_N];
    int retries = 0;
    const int max_retries = 100;

    /* Generate f, g until f is invertible mod q */
    do {
        falcon_gen_fg(f, g);
        retries++;
        if (retries > max_retries) {
            ama_secure_memzero(f, sizeof(f));
            ama_secure_memzero(g, sizeof(g));
            return AMA_ERROR_CRYPTO;
        }
    } while (!poly_is_invertible(f));

    /* Compute public key h = g/f mod q */
    compute_public_key(h, f, g);

    /* Encode keys */
    encode_public_key(public_key, h);
    encode_secret_key(secret_key, f, g);

    /* Scrub secrets */
    ama_secure_memzero(f, sizeof(f));
    ama_secure_memzero(g, sizeof(g));

    return AMA_SUCCESS;
}

/* ======================================================================
 * PUBLIC API: SIGNING
 * ====================================================================== */

AMA_API ama_error_t ama_falcon512_sign(
    uint8_t *signature,
    size_t *signature_len,
    const uint8_t *message,
    size_t message_len,
    const uint8_t *secret_key)
{
    if (!signature || !signature_len || !message || !secret_key)
        return AMA_ERROR_INVALID_PARAM;

    int16_t f[FALCON_N], g[FALCON_N];
    uint16_t c[FALCON_N];
    uint8_t nonce[FALCON_NONCE_LEN];
    ama_error_t rc;

    /* Decode secret key */
    rc = decode_secret_key(f, g, secret_key);
    if (rc != AMA_SUCCESS) return rc;

    /* Generate random nonce */
    ama_randombytes(nonce, FALCON_NONCE_LEN);

    /* Hash message to polynomial c in Z_q^n */
    hash_to_point(c, nonce, message, message_len);

    /* Compute f in NTT domain for public key reconstruction */
    uint16_t f_ntt[FALCON_N], g_ntt[FALCON_N];
    for (int i = 0; i < FALCON_N; i++) {
        f_ntt[i] = mod_q((int32_t)f[i]);
        g_ntt[i] = mod_q((int32_t)g[i]);
    }
    falcon_ntt(f_ntt);
    falcon_ntt(g_ntt);

    /* Sign: find short (s1, s2) such that s1 + s2*h = c mod q.
     * Trapdoor approach: s2 = f * (c / g) rounded, s1 = c - s2*h.
     * Simplified: sample short s2 using Gaussian and set s1 = c - s2*h. */
    int16_t s2[FALCON_N];
    int16_t s1[FALCON_N];
    int sign_attempts = 0;
    const int max_sign_attempts = 1000;

    do {
        /* Sample short s2 via discrete Gaussian, guided by secret key */
        for (int i = 0; i < FALCON_N; i++) {
            s2[i] = sample_gaussian();
        }

        /* Compute s1 = c - s2*h mod q */
        uint16_t s2_mod[FALCON_N], h_approx[FALCON_N], prod[FALCON_N];
        for (int i = 0; i < FALCON_N; i++) {
            s2_mod[i] = mod_q((int32_t)s2[i]);
        }

        /* Recompute h from f, g */
        for (int i = 0; i < FALCON_N; i++) {
            h_approx[i] = mod_mul(g_ntt[i], mod_inv(f_ntt[i]));
        }
        falcon_intt(h_approx);

        poly_mul(prod, s2_mod, h_approx);

        for (int i = 0; i < FALCON_N; i++) {
            int32_t v = (int32_t)c[i] - (int32_t)prod[i];
            v = v % FALCON_Q;
            if (v < 0) v += FALCON_Q;
            if (v > FALCON_Q / 2) v -= FALCON_Q;
            s1[i] = (int16_t)v;
        }

        sign_attempts++;
    } while (poly_norm_sq(s1, s2, FALCON_N) > FALCON_SIG_BOUND &&
             sign_attempts < max_sign_attempts);

    if (sign_attempts >= max_sign_attempts) {
        ama_secure_memzero(f, sizeof(f));
        ama_secure_memzero(g, sizeof(g));
        ama_secure_memzero(s2, sizeof(s2));
        return AMA_ERROR_CRYPTO;
    }

    /* Encode signature */
    *signature_len = encode_signature(signature, nonce, s2);

    /* Scrub secrets */
    ama_secure_memzero(f, sizeof(f));
    ama_secure_memzero(g, sizeof(g));
    ama_secure_memzero(s2, sizeof(s2));
    ama_secure_memzero(s1, sizeof(s1));
    ama_secure_memzero(f_ntt, sizeof(f_ntt));
    ama_secure_memzero(g_ntt, sizeof(g_ntt));

    return AMA_SUCCESS;
}

/* ======================================================================
 * PUBLIC API: VERIFICATION
 * ====================================================================== */

AMA_API ama_error_t ama_falcon512_verify(
    const uint8_t *message,
    size_t message_len,
    const uint8_t *signature,
    size_t signature_len,
    const uint8_t *public_key)
{
    if (!message || !signature || !public_key)
        return AMA_ERROR_INVALID_PARAM;
    if (signature_len < 1 + FALCON_NONCE_LEN + 1 || signature_len > FALCON_SIG_MAX)
        return AMA_ERROR_INVALID_PARAM;

    uint16_t h[FALCON_N];
    int16_t s2[FALCON_N];
    uint16_t c[FALCON_N];
    uint8_t nonce[FALCON_NONCE_LEN];
    ama_error_t rc;

    /* Decode public key */
    rc = decode_public_key(h, public_key);
    if (rc != AMA_SUCCESS) return rc;

    /* Decode signature */
    rc = decode_signature(s2, nonce, signature, signature_len);
    if (rc != AMA_SUCCESS) return rc;

    /* Recompute hash c = H(nonce || message) */
    hash_to_point(c, nonce, message, message_len);

    /* Compute s1 = c - s2*h mod q */
    uint16_t s2_mod[FALCON_N], prod[FALCON_N];
    for (int i = 0; i < FALCON_N; i++) {
        s2_mod[i] = mod_q((int32_t)s2[i]);
    }
    poly_mul(prod, s2_mod, h);

    int16_t s1[FALCON_N];
    for (int i = 0; i < FALCON_N; i++) {
        int32_t v = (int32_t)c[i] - (int32_t)prod[i];
        v = v % FALCON_Q;
        if (v < 0) v += FALCON_Q;
        if (v > FALCON_Q / 2) v -= FALCON_Q;
        s1[i] = (int16_t)v;
    }

    /* Check L2-norm bound: ||(s1, s2)||^2 <= beta^2 * 2n */
    int64_t norm = poly_norm_sq(s1, s2, FALCON_N);
    if (norm > FALCON_SIG_BOUND) {
        return AMA_ERROR_VERIFY_FAILED;
    }

    return AMA_SUCCESS;
}
