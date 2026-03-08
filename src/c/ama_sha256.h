/**
 * Copyright 2025-2026 Steel Security Advisors LLC
 * Licensed under the Apache License, Version 2.0
 *
 * @file ama_sha256.h
 * @brief Native SHA-256 implementation (NIST FIPS 180-4)
 * @author Andrew E. A., Steel Security Advisors LLC
 * @date 2026-03-08
 *
 * Provides SHA-256 hashing without OpenSSL dependency.
 * Used by SPHINCS+-SHA2-256f-simple (FIPS 205) internally.
 */

#ifndef AMA_SHA256_H
#define AMA_SHA256_H

#include <stddef.h>
#include <stdint.h>

#define AMA_SHA256_DIGEST_SIZE 32
#define AMA_SHA256_BLOCK_SIZE  64

/**
 * @brief SHA-256 streaming context
 */
typedef struct {
    uint32_t state[8];          /**< Hash state (H0..H7) */
    uint8_t  buffer[64];        /**< Partial block buffer */
    size_t   buffer_len;        /**< Bytes in buffer */
    uint64_t total_len;         /**< Total bytes processed */
} ama_sha256_ctx;

/**
 * @brief Initialize SHA-256 context with IV per FIPS 180-4 Section 5.3.3
 */
void ama_sha256_init(ama_sha256_ctx *ctx);

/**
 * @brief Absorb data into SHA-256 context
 */
void ama_sha256_update(ama_sha256_ctx *ctx, const uint8_t *data, size_t len);

/**
 * @brief Finalize and produce 32-byte digest
 */
void ama_sha256_final(ama_sha256_ctx *ctx, uint8_t digest[32]);

/**
 * @brief One-shot SHA-256: hash input to 32-byte output
 */
void ama_sha256(uint8_t *out, const uint8_t *in, size_t inlen);

/**
 * @brief SHA-256 with two concatenated inputs: SHA-256(in1 || in2)
 */
void ama_sha256_2(uint8_t *out, const uint8_t *in1, size_t in1len,
                   const uint8_t *in2, size_t in2len);

#endif /* AMA_SHA256_H */
