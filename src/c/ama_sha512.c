/* Copyright (C) 2025-2026 Steel Security Advisors LLC */
/* SPDX-License-Identifier: Apache-2.0 */
/**
 * @file ama_sha512.c
 * @brief Public SHA-512 / SHA-384 one-shot exports (NIST FIPS 180-4)
 * @author Andrew E. A., Steel Security Advisors LLC
 * @date 2026-08-18
 *
 * The SHA-512/384 core has lived in internal/ama_sha2.h since the
 * HMAC-SHA-384 consolidation, serving Ed25519 (RFC 8032), SLH-DSA-SHA2,
 * HKDF-SHA-512 and HMAC-SHA-384 — but only as header-static functions,
 * invisible to the Python layer.  That gap is why Python callers needing
 * SHA-384/512 (the FIPS 186-5 hash pairings for P-384/P-521, the RFC 3161
 * digest table) reached for stdlib hashlib, whose constructors resolve to
 * OpenSSL — a violation of INVARIANT-1's "non-primitive operations only"
 * carve-out.  This TU closes the gap the same way ama_sha256.c closed it
 * for SHA-256: surface the existing in-tree core, add nothing new
 * cryptographically.
 *
 * Signature convention follows the SHA-3 family (ama_sha3_256/384/512):
 * rc-checked ama_error_t, input-first argument order — NOT the older
 * output-first void convention of ama_sha256, whose argument order is
 * called out in pqc_backends.py as a standing footgun.
 *
 * The internal header's own one-shots are named ama_sha512_oneshot /
 * ama_sha384_oneshot (renamed from ama_sha512/ama_sha384 when these public
 * exports were introduced), so the public names are free for this TU.
 */

#include "../include/ama_cryptography.h"  /* AMA_API, ama_error_t */
#include "internal/ama_sha2.h"            /* shared SHA-512/384 streaming core */

/**
 * @brief One-shot SHA-512 (FIPS 180-4 Section 6.4).
 *
 * Byte-identical to hashlib.sha512(input).digest().
 *
 * @param input     Input bytes (may be NULL iff input_len == 0)
 * @param input_len Input length in bytes
 * @param output    Output buffer (must be at least 64 bytes)
 * @return          AMA_SUCCESS, or AMA_ERROR_INVALID_PARAM on NULL output /
 *                  NULL input with input_len > 0
 */
AMA_API ama_error_t ama_sha512(
    const uint8_t* input,
    size_t input_len,
    uint8_t* output
) {
    ama_sha512_ctx ctx;

    if (!input && input_len > 0) {
        return AMA_ERROR_INVALID_PARAM;
    }
    if (!output) {
        return AMA_ERROR_INVALID_PARAM;
    }

    ama_sha512_ctx_init(&ctx);
    if (input_len > 0) {
        ama_sha512_ctx_update(&ctx, input, input_len);
    }
    ama_sha512_ctx_final(&ctx, output, AMA_SHA512_DIGEST_SIZE);

    /* The context buffered up to a block of caller data; the caller may be
     * hashing key material (the PBKDF2/HMAC constructions above this do).
     * Same scrub posture as the SHA-3 one-shots. */
    ama_secure_memzero(&ctx, sizeof(ctx));
    return AMA_SUCCESS;
}

/**
 * @brief One-shot SHA-384 (FIPS 180-4 Section 6.5).
 *
 * Byte-identical to hashlib.sha384(input).digest().  Shares the SHA-512
 * compression function; differs only in IV (Section 5.3.4) and 48-byte
 * truncation.
 *
 * @param input     Input bytes (may be NULL iff input_len == 0)
 * @param input_len Input length in bytes
 * @param output    Output buffer (must be at least 48 bytes)
 * @return          AMA_SUCCESS, or AMA_ERROR_INVALID_PARAM on NULL output /
 *                  NULL input with input_len > 0
 */
AMA_API ama_error_t ama_sha384(
    const uint8_t* input,
    size_t input_len,
    uint8_t* output
) {
    ama_sha512_ctx ctx;

    if (!input && input_len > 0) {
        return AMA_ERROR_INVALID_PARAM;
    }
    if (!output) {
        return AMA_ERROR_INVALID_PARAM;
    }

    ama_sha384_ctx_init(&ctx);
    if (input_len > 0) {
        ama_sha512_ctx_update(&ctx, input, input_len);
    }
    ama_sha512_ctx_final(&ctx, output, AMA_SHA384_DIGEST_SIZE);

    ama_secure_memzero(&ctx, sizeof(ctx));
    return AMA_SUCCESS;
}
