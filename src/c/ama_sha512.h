/**
 * Copyright 2025-2026 Steel Security Advisors LLC
 * Licensed under the Apache License, Version 2.0
 *
 * @file ama_sha512.h
 * @brief Native SHA-512 implementation (NIST FIPS 180-4)
 * @author Andrew E. A., Steel Security Advisors LLC
 * @date 2026-03-16
 *
 * Provides SHA-512 hashing without external dependencies.
 * Used by HMAC-SHA512 for BIP32 HD key derivation.
 */

#ifndef AMA_SHA512_H
#define AMA_SHA512_H

#include <stddef.h>
#include <stdint.h>

#define AMA_SHA512_DIGEST_SIZE 64
#define AMA_SHA512_BLOCK_SIZE  128

/**
 * @brief SHA-512 streaming context
 */
typedef struct {
    uint64_t state[8];          /**< Hash state (H0..H7) */
    uint8_t  buffer[128];       /**< Partial block buffer */
    size_t   buffer_len;        /**< Bytes in buffer */
    uint64_t total_len;         /**< Total bytes processed */
} ama_sha512_ctx;

/**
 * @brief Initialize SHA-512 context with IV per FIPS 180-4 Section 5.3.5
 */
void ama_sha512_init(ama_sha512_ctx *ctx);

/**
 * @brief Absorb data into SHA-512 context
 */
void ama_sha512_update(ama_sha512_ctx *ctx, const uint8_t *data, size_t len);

/**
 * @brief Finalize and produce 64-byte digest
 */
void ama_sha512_final(ama_sha512_ctx *ctx, uint8_t digest[64]);

/**
 * @brief One-shot SHA-512: hash input to 64-byte output
 */
void ama_sha512(uint8_t *out, const uint8_t *in, size_t inlen);

#endif /* AMA_SHA512_H */
