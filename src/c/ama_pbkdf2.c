/* Copyright (C) 2025-2026 Steel Security Advisors LLC */
/* SPDX-License-Identifier: Apache-2.0 */
/**
 * @file ama_pbkdf2.c
 * @brief Native PBKDF2-HMAC-SHA256 / PBKDF2-HMAC-SHA512 (NIST SP 800-132)
 * @author Andrew E. A., Steel Security Advisors LLC
 * @date 2026-08-18
 *
 * PBKDF2 per NIST SP 800-132 / RFC 8018 Section 5.2, on the in-tree SHA-2
 * cores (ama_sha256.c streaming context; internal/ama_sha2.h SHA-512
 * streaming context).  Zero external dependencies.
 *
 * Why this exists: the Python layer derived the BIP39 master seed
 * (PBKDF2-HMAC-SHA512, 2048 iterations) and the key-encryption keys
 * (PBKDF2-HMAC-SHA256) through hashlib.pbkdf2_hmac, which is OpenSSL's
 * PBKDF2 — a key-derivation primitive delegated to an unauthorized vendor
 * (INVARIANT-1).  AMA already owned every piece of the construction; this
 * file assembles them.
 *
 * Construction (RFC 8018 Section 5.2), for each output block l = 1..ceil:
 *     U_1 = HMAC(P, S || INT_32BE(l));  U_j = HMAC(P, U_{j-1})
 *     T_l = U_1 XOR U_2 XOR ... XOR U_c
 *
 * Performance: the HMAC key schedule is hoisted out of the iteration loop.
 * The contexts that have absorbed (K' XOR ipad) and (K' XOR opad) are
 * computed once per call and struct-copied per HMAC invocation, so each
 * iteration costs two compression-function passes over one block plus the
 * finalization padding — not the four passes of a naive HMAC-per-iteration
 * loop.  At the KDF iteration counts this construction exists for, that is
 * the difference between the cost the operator budgeted and double it.
 *
 * Both entry points are constant-time with respect to the password bytes in
 * the same sense the HMAC kernels are: the only length-dependent branch is
 * the RFC 2104 long-key pre-hash, which depends on password_len, not on its
 * value.  All key-derived intermediates are scrubbed on every exit path.
 */

#include "../include/ama_cryptography.h"  /* AMA_API, ama_error_t */
#include "ama_sha256.h"                   /* SHA-256 streaming context */
#include "internal/ama_sha2.h"            /* SHA-512 streaming context */

#include <string.h>
#include <stdint.h>

/* Scrub sensitive state — compiler cannot optimize this away */
extern void ama_secure_memzero(void *ptr, size_t len);

/* SP 800-132: derived-key length is bounded by (2^32 - 1) * hLen. */
#define PBKDF2_MAX_BLOCKS 0xFFFFFFFFu

/**
 * @brief PBKDF2-HMAC-SHA256 (NIST SP 800-132 / RFC 8018 Section 5.2).
 *
 * Byte-identical to hashlib.pbkdf2_hmac("sha256", password, salt,
 * iterations, out_len).
 *
 * @param password      Password bytes (may be NULL iff password_len == 0)
 * @param password_len  Password length in bytes
 * @param salt          Salt bytes (may be NULL iff salt_len == 0)
 * @param salt_len      Salt length in bytes
 * @param iterations    Iteration count c (must be >= 1)
 * @param out           Output buffer for the derived key
 * @param out_len       Derived key length in bytes (must be >= 1 and
 *                      <= (2^32 - 1) * 32)
 * @return              AMA_SUCCESS, or AMA_ERROR_INVALID_PARAM
 */
AMA_API ama_error_t ama_pbkdf2_hmac_sha256(
    const uint8_t *password, size_t password_len,
    const uint8_t *salt, size_t salt_len,
    uint32_t iterations,
    uint8_t *out, size_t out_len
) {
    uint8_t k_prime[AMA_SHA256_BLOCK_SIZE];
    uint8_t pad[AMA_SHA256_BLOCK_SIZE];
    uint8_t u_block[AMA_SHA256_DIGEST_SIZE];
    uint8_t t_accum[AMA_SHA256_DIGEST_SIZE];
    ama_sha256_ctx ictx_base, octx_base, ctx;
    size_t offset, take, i;
    uint32_t block_index, j;

    if (!out || out_len == 0 || iterations == 0) {
        return AMA_ERROR_INVALID_PARAM;
    }
    if (!password && password_len > 0) {
        return AMA_ERROR_INVALID_PARAM;
    }
    if (!salt && salt_len > 0) {
        return AMA_ERROR_INVALID_PARAM;
    }
    if ((uint64_t)out_len > (uint64_t)PBKDF2_MAX_BLOCKS * AMA_SHA256_DIGEST_SIZE) {
        return AMA_ERROR_INVALID_PARAM;
    }

    /* K' — zero-padded to the block; oversized passwords collapse to
     * SHA-256(password) per RFC 2104 Section 2.  Zero-fill via the scrub
     * primitive so the whole buffer lifecycle stays in one class
     * (ama_hmac_sha384.c convention). */
    ama_secure_memzero(k_prime, sizeof(k_prime));
    if (password_len > AMA_SHA256_BLOCK_SIZE) {
        ama_sha256(k_prime, password, password_len);  /* OUTPUT-FIRST: writes 32; [32..63] stay zero */
    } else if (password_len > 0) {
        memcpy(k_prime, password, password_len);
    }

    /* Hoisted key schedule: contexts that have absorbed K'^ipad / K'^opad. */
    for (i = 0; i < AMA_SHA256_BLOCK_SIZE; i++) {
        pad[i] = (uint8_t)(k_prime[i] ^ 0x36);
    }
    ama_sha256_init(&ictx_base);
    ama_sha256_update(&ictx_base, pad, AMA_SHA256_BLOCK_SIZE);
    for (i = 0; i < AMA_SHA256_BLOCK_SIZE; i++) {
        pad[i] = (uint8_t)(k_prime[i] ^ 0x5c);
    }
    ama_sha256_init(&octx_base);
    ama_sha256_update(&octx_base, pad, AMA_SHA256_BLOCK_SIZE);

    offset = 0;
    for (block_index = 1; offset < out_len; block_index++) {
        uint8_t index_be[4];
        index_be[0] = (uint8_t)(block_index >> 24);
        index_be[1] = (uint8_t)(block_index >> 16);
        index_be[2] = (uint8_t)(block_index >> 8);
        index_be[3] = (uint8_t)(block_index);

        /* U_1 = HMAC(P, S || INT(l)) */
        ctx = ictx_base;
        if (salt_len > 0) {
            ama_sha256_update(&ctx, salt, salt_len);
        }
        ama_sha256_update(&ctx, index_be, sizeof(index_be));
        ama_sha256_final(&ctx, u_block);
        ctx = octx_base;
        ama_sha256_update(&ctx, u_block, AMA_SHA256_DIGEST_SIZE);
        ama_sha256_final(&ctx, u_block);
        memcpy(t_accum, u_block, AMA_SHA256_DIGEST_SIZE);

        /* U_j = HMAC(P, U_{j-1}); T ^= U_j */
        for (j = 1; j < iterations; j++) {
            ctx = ictx_base;
            ama_sha256_update(&ctx, u_block, AMA_SHA256_DIGEST_SIZE);
            ama_sha256_final(&ctx, u_block);
            ctx = octx_base;
            ama_sha256_update(&ctx, u_block, AMA_SHA256_DIGEST_SIZE);
            ama_sha256_final(&ctx, u_block);
            for (i = 0; i < AMA_SHA256_DIGEST_SIZE; i++) {
                t_accum[i] ^= u_block[i];
            }
        }

        take = out_len - offset;
        if (take > AMA_SHA256_DIGEST_SIZE) {
            take = AMA_SHA256_DIGEST_SIZE;
        }
        memcpy(out + offset, t_accum, take);
        offset += take;
    }

    /* Scrub key material and key-derived state from the stack. */
    ama_secure_memzero(k_prime, sizeof(k_prime));
    ama_secure_memzero(pad, sizeof(pad));
    ama_secure_memzero(u_block, sizeof(u_block));
    ama_secure_memzero(t_accum, sizeof(t_accum));
    ama_secure_memzero(&ictx_base, sizeof(ictx_base));
    ama_secure_memzero(&octx_base, sizeof(octx_base));
    ama_secure_memzero(&ctx, sizeof(ctx));
    return AMA_SUCCESS;
}

/**
 * @brief PBKDF2-HMAC-SHA512 (NIST SP 800-132 / RFC 8018 Section 5.2).
 *
 * Byte-identical to hashlib.pbkdf2_hmac("sha512", password, salt,
 * iterations, out_len).  This is the BIP39 seed-derivation KDF
 * (2048 iterations, salt "mnemonic" || passphrase).
 *
 * @param password      Password bytes (may be NULL iff password_len == 0)
 * @param password_len  Password length in bytes
 * @param salt          Salt bytes (may be NULL iff salt_len == 0)
 * @param salt_len      Salt length in bytes
 * @param iterations    Iteration count c (must be >= 1)
 * @param out           Output buffer for the derived key
 * @param out_len       Derived key length in bytes (must be >= 1 and
 *                      <= (2^32 - 1) * 64)
 * @return              AMA_SUCCESS, or AMA_ERROR_INVALID_PARAM
 */
AMA_API ama_error_t ama_pbkdf2_hmac_sha512(
    const uint8_t *password, size_t password_len,
    const uint8_t *salt, size_t salt_len,
    uint32_t iterations,
    uint8_t *out, size_t out_len
) {
    uint8_t k_prime[AMA_SHA512_BLOCK_SIZE];
    uint8_t pad[AMA_SHA512_BLOCK_SIZE];
    uint8_t u_block[AMA_SHA512_DIGEST_SIZE];
    uint8_t t_accum[AMA_SHA512_DIGEST_SIZE];
    ama_sha512_ctx ictx_base, octx_base, ctx;
    size_t offset, take, i;
    uint32_t block_index, j;

    if (!out || out_len == 0 || iterations == 0) {
        return AMA_ERROR_INVALID_PARAM;
    }
    if (!password && password_len > 0) {
        return AMA_ERROR_INVALID_PARAM;
    }
    if (!salt && salt_len > 0) {
        return AMA_ERROR_INVALID_PARAM;
    }
    if ((uint64_t)out_len > (uint64_t)PBKDF2_MAX_BLOCKS * AMA_SHA512_DIGEST_SIZE) {
        return AMA_ERROR_INVALID_PARAM;
    }

    ama_secure_memzero(k_prime, sizeof(k_prime));
    if (password_len > AMA_SHA512_BLOCK_SIZE) {
        ama_sha512_oneshot(password, password_len, k_prime);  /* writes 64; [64..127] stay zero */
    } else if (password_len > 0) {
        memcpy(k_prime, password, password_len);
    }

    for (i = 0; i < AMA_SHA512_BLOCK_SIZE; i++) {
        pad[i] = (uint8_t)(k_prime[i] ^ 0x36);
    }
    ama_sha512_ctx_init(&ictx_base);
    ama_sha512_ctx_update(&ictx_base, pad, AMA_SHA512_BLOCK_SIZE);
    for (i = 0; i < AMA_SHA512_BLOCK_SIZE; i++) {
        pad[i] = (uint8_t)(k_prime[i] ^ 0x5c);
    }
    ama_sha512_ctx_init(&octx_base);
    ama_sha512_ctx_update(&octx_base, pad, AMA_SHA512_BLOCK_SIZE);

    offset = 0;
    for (block_index = 1; offset < out_len; block_index++) {
        uint8_t index_be[4];
        index_be[0] = (uint8_t)(block_index >> 24);
        index_be[1] = (uint8_t)(block_index >> 16);
        index_be[2] = (uint8_t)(block_index >> 8);
        index_be[3] = (uint8_t)(block_index);

        ctx = ictx_base;
        if (salt_len > 0) {
            ama_sha512_ctx_update(&ctx, salt, salt_len);
        }
        ama_sha512_ctx_update(&ctx, index_be, sizeof(index_be));
        ama_sha512_ctx_final(&ctx, u_block, AMA_SHA512_DIGEST_SIZE);
        ctx = octx_base;
        ama_sha512_ctx_update(&ctx, u_block, AMA_SHA512_DIGEST_SIZE);
        ama_sha512_ctx_final(&ctx, u_block, AMA_SHA512_DIGEST_SIZE);
        memcpy(t_accum, u_block, AMA_SHA512_DIGEST_SIZE);

        for (j = 1; j < iterations; j++) {
            ctx = ictx_base;
            ama_sha512_ctx_update(&ctx, u_block, AMA_SHA512_DIGEST_SIZE);
            ama_sha512_ctx_final(&ctx, u_block, AMA_SHA512_DIGEST_SIZE);
            ctx = octx_base;
            ama_sha512_ctx_update(&ctx, u_block, AMA_SHA512_DIGEST_SIZE);
            ama_sha512_ctx_final(&ctx, u_block, AMA_SHA512_DIGEST_SIZE);
            for (i = 0; i < AMA_SHA512_DIGEST_SIZE; i++) {
                t_accum[i] ^= u_block[i];
            }
        }

        take = out_len - offset;
        if (take > AMA_SHA512_DIGEST_SIZE) {
            take = AMA_SHA512_DIGEST_SIZE;
        }
        memcpy(out + offset, t_accum, take);
        offset += take;
    }

    ama_secure_memzero(k_prime, sizeof(k_prime));
    ama_secure_memzero(pad, sizeof(pad));
    ama_secure_memzero(u_block, sizeof(u_block));
    ama_secure_memzero(t_accum, sizeof(t_accum));
    ama_secure_memzero(&ictx_base, sizeof(ictx_base));
    ama_secure_memzero(&octx_base, sizeof(octx_base));
    ama_secure_memzero(&ctx, sizeof(ctx));
    return AMA_SUCCESS;
}
