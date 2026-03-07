/**
 * Copyright 2025 Steel Security Advisors LLC
 * Licensed under the Apache License, Version 2.0
 *
 * @file ama_hmac_sha256.h
 * @brief Native HMAC-SHA-256 implementation (RFC 2104 / FIPS 198-1)
 * @author Andrew E. A., Steel Security Advisors LLC
 * @date 2026-03-07
 *
 * Provides HMAC-SHA-256 without OpenSSL dependency.
 * Used by SPHINCS+ spx_prf_msg() (FIPS 205 Section 11.1).
 */

#ifndef AMA_HMAC_SHA256_H
#define AMA_HMAC_SHA256_H

#include <stddef.h>
#include <stdint.h>

/**
 * @brief Compute HMAC-SHA-256
 *
 * Standard HMAC construction per RFC 2104:
 *   HMAC(K, m) = H((K' XOR opad) || H((K' XOR ipad) || m))
 *
 * Where K' is the key padded/hashed to block size.
 *
 * @param key      HMAC key
 * @param key_len  Key length in bytes
 * @param data     Message data
 * @param data_len Data length in bytes
 * @param out      Output buffer (32 bytes)
 */
void ama_hmac_sha256(const uint8_t *key, size_t key_len,
                      const uint8_t *data, size_t data_len,
                      uint8_t out[32]);

/**
 * @brief Compute HMAC-SHA-256 with two concatenated data segments
 *
 * Equivalent to HMAC-SHA-256(key, data1 || data2) but avoids
 * requiring the caller to concatenate buffers.
 *
 * @param key       HMAC key
 * @param key_len   Key length in bytes
 * @param data1     First data segment
 * @param data1_len First segment length
 * @param data2     Second data segment
 * @param data2_len Second segment length
 * @param out       Output buffer (32 bytes)
 */
void ama_hmac_sha256_2(const uint8_t *key, size_t key_len,
                        const uint8_t *data1, size_t data1_len,
                        const uint8_t *data2, size_t data2_len,
                        uint8_t out[32]);

#endif /* AMA_HMAC_SHA256_H */
