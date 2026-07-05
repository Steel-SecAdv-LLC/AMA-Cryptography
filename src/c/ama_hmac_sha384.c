/**
 * Copyright 2025-2026 Steel Security Advisors LLC
 * Licensed under the Apache License, Version 2.0
 *
 * @file ama_hmac_sha384.c
 * @brief Native HMAC-SHA-384 implementation (RFC 2104 / FIPS 198-1)
 * @author Andrew E. A., Steel Security Advisors LLC
 * @date 2026-07-05
 *
 * Zero-dependency HMAC-SHA-384, mirroring the existing HMAC-SHA-512 public
 * binding (ama_hmac_sha512 in ama_hkdf.c) and the HMAC-SHA-256 standalone
 * kernel (ama_hmac_sha256.c).  SHA-384 shares the SHA-512 compression function
 * (FIPS 180-4 §6.4) but uses a distinct IV (§5.3.4) and truncates the 512-bit
 * state to the leftmost 384 bits — both provided by the shared streaming core
 * in internal/ama_sha2.h (ama_sha384_ctx_init / ama_sha512_ctx_update /
 * ama_sha512_ctx_final), so this file no longer carries its own copy of the
 * SHA-512 core.
 *
 * Construction: HMAC(K, m) = SHA-384((K' XOR opad) || SHA-384((K' XOR ipad) || m))
 * Where K' = key padded to the SHA-384 block size (128 bytes).  Keys longer
 * than 128 bytes are SHA-384-hashed first (RFC 2104 §2 — the 128-byte
 * threshold, twice SHA-256's 64).
 *
 * The public entry point returns ama_error_t so the Python ctypes binding
 * (native_hmac_sha384) mirrors native_hmac_sha512's rc-checked contract
 * exactly.  Output is byte-identical to
 * hmac.new(key, msg, hashlib.sha384).digest(); ipad/opad are streamed through
 * the SHA-384 context with no heap concat, keeping the pad XOR over the full
 * 128-byte block (constant-time posture matching ama_hmac_sha256.c and the
 * ama_hmac_sha512_3 kernel).
 */

#include "../include/ama_cryptography.h"  /* AMA_API, ama_error_t, AMA_SUCCESS */
#include "internal/ama_sha2.h"            /* shared SHA-512/384 streaming core */
#include <string.h>
#include <stdint.h>

/* Block size is the SHA-512 block (128 bytes); digest is 48 bytes.  Both come
 * from internal/ama_sha2.h (AMA_SHA512_BLOCK_SIZE / AMA_SHA384_DIGEST_SIZE). */

/**
 * @brief Compute HMAC-SHA-384 (RFC 2104 / FIPS 198-1).
 *
 * Byte-identical to hmac.new(key, msg, hashlib.sha384).digest().
 *
 * @param key      HMAC key (any length; keys > 128 bytes are SHA-384-hashed
 *                 first per RFC 2104 §2)
 * @param key_len  Key length in bytes
 * @param msg      Message to authenticate (may be NULL iff msg_len == 0)
 * @param msg_len  Message length in bytes
 * @param out      Output buffer (must be at least 48 bytes)
 * @return         AMA_SUCCESS on success, AMA_ERROR_INVALID_PARAM if key or
 *                 out is NULL (or msg is NULL with msg_len > 0)
 */
AMA_API ama_error_t ama_hmac_sha384(const uint8_t *key, size_t key_len,
                                    const uint8_t *msg, size_t msg_len,
                                    uint8_t out[48]) {
    uint8_t k_prime[AMA_SHA512_BLOCK_SIZE];
    uint8_t ipad[AMA_SHA512_BLOCK_SIZE];
    uint8_t opad[AMA_SHA512_BLOCK_SIZE];
    uint8_t inner_hash[AMA_SHA384_DIGEST_SIZE];
    ama_sha512_ctx ctx;
    unsigned int i;

    if (!key || !out) {
        return AMA_ERROR_INVALID_PARAM;
    }
    if (!msg && msg_len > 0) {
        return AMA_ERROR_INVALID_PARAM;
    }

    /* Step 1: Derive K'.  Zero-pad first so the whole buffer lifecycle stays
     * in one scrub class (matches ama_hmac_sha256.c INVARIANT-6 rationale);
     * oversized keys collapse to SHA-384(key) zero-padded to the block. */
    ama_secure_memzero(k_prime, AMA_SHA512_BLOCK_SIZE);
    if (key_len > AMA_SHA512_BLOCK_SIZE) {
        ama_sha384(key, key_len, k_prime);  /* writes 48 bytes; [48..127] stay zero */
    } else {
        memcpy(k_prime, key, key_len);
    }

    /* Step 2: Compute ipad and opad */
    for (i = 0; i < AMA_SHA512_BLOCK_SIZE; i++) {
        ipad[i] = k_prime[i] ^ 0x36;
        opad[i] = k_prime[i] ^ 0x5c;
    }

    /* Step 3: Inner hash = SHA-384(ipad || msg) */
    ama_sha384_ctx_init(&ctx);
    ama_sha512_ctx_update(&ctx, ipad, AMA_SHA512_BLOCK_SIZE);
    ama_sha512_ctx_update(&ctx, msg, msg_len);
    ama_sha512_ctx_final(&ctx, inner_hash, AMA_SHA384_DIGEST_SIZE);

    /* Step 4: Outer hash = SHA-384(opad || inner_hash) */
    ama_sha384_ctx_init(&ctx);
    ama_sha512_ctx_update(&ctx, opad, AMA_SHA512_BLOCK_SIZE);
    ama_sha512_ctx_update(&ctx, inner_hash, AMA_SHA384_DIGEST_SIZE);
    ama_sha512_ctx_final(&ctx, out, AMA_SHA384_DIGEST_SIZE);

    /* Scrub key material from stack */
    ama_secure_memzero(k_prime, sizeof(k_prime));
    ama_secure_memzero(ipad, sizeof(ipad));
    ama_secure_memzero(opad, sizeof(opad));
    ama_secure_memzero(inner_hash, sizeof(inner_hash));

    return AMA_SUCCESS;
}
