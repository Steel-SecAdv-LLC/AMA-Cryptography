/**
 * Copyright 2025-2026 Steel Security Advisors LLC
 * Licensed under the Apache License, Version 2.0
 *
 * @file ama_hmac_sha512.c
 * @brief Native HMAC-SHA-512 implementation (RFC 2104 / FIPS 198-1)
 * @author Andrew E. A., Steel Security Advisors LLC
 * @date 2026-03-16
 *
 * Replaces Python's stdlib hmac.new(..., hashlib.sha512) in
 * key_management.py for BIP32 HD key derivation.
 * Satisfies INVARIANT-1 (zero external crypto dependencies).
 *
 * Construction: HMAC(K, m) = SHA-512((K' XOR opad) || SHA-512((K' XOR ipad) || m))
 * Where K' = key padded to SHA-512 block size (128 bytes).
 * If key > 128 bytes, K' = SHA-512(key) zero-padded to 128 bytes.
 */

#include "ama_cryptography.h"
#include "ama_hmac_sha512.h"
#include "ama_sha512.h"
#include <string.h>

/* Scrub sensitive stack data */
extern void ama_secure_memzero(void *ptr, size_t len);

void ama_hmac_sha512(const uint8_t *key, size_t key_len,
                      const uint8_t *data, size_t data_len,
                      uint8_t out[64]) {
    uint8_t k_prime[AMA_SHA512_BLOCK_SIZE];
    uint8_t ipad[AMA_SHA512_BLOCK_SIZE];
    uint8_t opad[AMA_SHA512_BLOCK_SIZE];
    uint8_t inner_hash[AMA_SHA512_DIGEST_SIZE];
    ama_sha512_ctx ctx;
    unsigned int i;

    /* Step 1: Derive K' from key */
    memset(k_prime, 0, AMA_SHA512_BLOCK_SIZE);
    if (key_len > AMA_SHA512_BLOCK_SIZE) {
        /* Key longer than block size: K' = SHA-512(key), zero-padded */
        ama_sha512(k_prime, key, key_len);
    } else {
        /* Key fits in block: K' = key, zero-padded */
        memcpy(k_prime, key, key_len);
    }

    /* Step 2: Compute ipad and opad */
    for (i = 0; i < AMA_SHA512_BLOCK_SIZE; i++) {
        ipad[i] = k_prime[i] ^ 0x36;
        opad[i] = k_prime[i] ^ 0x5c;
    }

    /* Step 3: Inner hash = SHA-512(ipad || data) */
    ama_sha512_init(&ctx);
    ama_sha512_update(&ctx, ipad, AMA_SHA512_BLOCK_SIZE);
    ama_sha512_update(&ctx, data, data_len);
    ama_sha512_final(&ctx, inner_hash);

    /* Step 4: Outer hash = SHA-512(opad || inner_hash) */
    ama_sha512_init(&ctx);
    ama_sha512_update(&ctx, opad, AMA_SHA512_BLOCK_SIZE);
    ama_sha512_update(&ctx, inner_hash, AMA_SHA512_DIGEST_SIZE);
    ama_sha512_final(&ctx, out);

    /* Scrub key material from stack */
    ama_secure_memzero(k_prime, sizeof(k_prime));
    ama_secure_memzero(ipad, sizeof(ipad));
    ama_secure_memzero(opad, sizeof(opad));
    ama_secure_memzero(inner_hash, sizeof(inner_hash));
}
