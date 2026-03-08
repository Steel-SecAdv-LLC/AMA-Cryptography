/**
 * Copyright 2025-2026 Steel Security Advisors LLC
 * Licensed under the Apache License, Version 2.0
 *
 * @file ama_hmac_sha256.c
 * @brief Native HMAC-SHA-256 implementation (RFC 2104 / FIPS 198-1)
 * @author Andrew E. A., Steel Security Advisors LLC
 * @date 2026-03-08
 *
 * Replaces OpenSSL EVP_MAC(HMAC-SHA256) / HMAC_CTX calls in
 * ama_sphincs.c spx_prf_msg() for zero-dependency SPHINCS+ operation.
 *
 * Construction: HMAC(K, m) = SHA-256((K' XOR opad) || SHA-256((K' XOR ipad) || m))
 * Where K' = key padded to SHA-256 block size (64 bytes).
 * If key > 64 bytes, K' = SHA-256(key) zero-padded to 64 bytes.
 */

#include "ama_hmac_sha256.h"
#include "ama_sha256.h"
#include <string.h>

/* Scrub sensitive stack data */
extern void ama_secure_memzero(void *ptr, size_t len);

void ama_hmac_sha256(const uint8_t *key, size_t key_len,
                      const uint8_t *data, size_t data_len,
                      uint8_t out[32]) {
    uint8_t k_prime[AMA_SHA256_BLOCK_SIZE];
    uint8_t ipad[AMA_SHA256_BLOCK_SIZE];
    uint8_t opad[AMA_SHA256_BLOCK_SIZE];
    uint8_t inner_hash[AMA_SHA256_DIGEST_SIZE];
    ama_sha256_ctx ctx;
    unsigned int i;

    /* Step 1: Derive K' from key */
    memset(k_prime, 0, AMA_SHA256_BLOCK_SIZE);
    if (key_len > AMA_SHA256_BLOCK_SIZE) {
        /* Key longer than block size: K' = SHA-256(key), zero-padded */
        ama_sha256(k_prime, key, key_len);
    } else {
        /* Key fits in block: K' = key, zero-padded */
        memcpy(k_prime, key, key_len);
    }

    /* Step 2: Compute ipad and opad */
    for (i = 0; i < AMA_SHA256_BLOCK_SIZE; i++) {
        ipad[i] = k_prime[i] ^ 0x36;
        opad[i] = k_prime[i] ^ 0x5c;
    }

    /* Step 3: Inner hash = SHA-256(ipad || data) */
    ama_sha256_init(&ctx);
    ama_sha256_update(&ctx, ipad, AMA_SHA256_BLOCK_SIZE);
    ama_sha256_update(&ctx, data, data_len);
    ama_sha256_final(&ctx, inner_hash);

    /* Step 4: Outer hash = SHA-256(opad || inner_hash) */
    ama_sha256_init(&ctx);
    ama_sha256_update(&ctx, opad, AMA_SHA256_BLOCK_SIZE);
    ama_sha256_update(&ctx, inner_hash, AMA_SHA256_DIGEST_SIZE);
    ama_sha256_final(&ctx, out);

    /* Scrub key material from stack */
    ama_secure_memzero(k_prime, sizeof(k_prime));
    ama_secure_memzero(ipad, sizeof(ipad));
    ama_secure_memzero(opad, sizeof(opad));
    ama_secure_memzero(inner_hash, sizeof(inner_hash));
}

void ama_hmac_sha256_2(const uint8_t *key, size_t key_len,
                        const uint8_t *data1, size_t data1_len,
                        const uint8_t *data2, size_t data2_len,
                        uint8_t out[32]) {
    uint8_t k_prime[AMA_SHA256_BLOCK_SIZE];
    uint8_t ipad[AMA_SHA256_BLOCK_SIZE];
    uint8_t opad[AMA_SHA256_BLOCK_SIZE];
    uint8_t inner_hash[AMA_SHA256_DIGEST_SIZE];
    ama_sha256_ctx ctx;
    unsigned int i;

    memset(k_prime, 0, AMA_SHA256_BLOCK_SIZE);
    if (key_len > AMA_SHA256_BLOCK_SIZE) {
        ama_sha256(k_prime, key, key_len);
    } else {
        memcpy(k_prime, key, key_len);
    }

    for (i = 0; i < AMA_SHA256_BLOCK_SIZE; i++) {
        ipad[i] = k_prime[i] ^ 0x36;
        opad[i] = k_prime[i] ^ 0x5c;
    }

    /* Inner hash = SHA-256(ipad || data1 || data2) */
    ama_sha256_init(&ctx);
    ama_sha256_update(&ctx, ipad, AMA_SHA256_BLOCK_SIZE);
    ama_sha256_update(&ctx, data1, data1_len);
    ama_sha256_update(&ctx, data2, data2_len);
    ama_sha256_final(&ctx, inner_hash);

    /* Outer hash */
    ama_sha256_init(&ctx);
    ama_sha256_update(&ctx, opad, AMA_SHA256_BLOCK_SIZE);
    ama_sha256_update(&ctx, inner_hash, AMA_SHA256_DIGEST_SIZE);
    ama_sha256_final(&ctx, out);

    ama_secure_memzero(k_prime, sizeof(k_prime));
    ama_secure_memzero(ipad, sizeof(ipad));
    ama_secure_memzero(opad, sizeof(opad));
    ama_secure_memzero(inner_hash, sizeof(inner_hash));
}
