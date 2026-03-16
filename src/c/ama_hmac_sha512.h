/**
 * Copyright 2025-2026 Steel Security Advisors LLC
 * Licensed under the Apache License, Version 2.0
 *
 * @file ama_hmac_sha512.h
 * @brief Native HMAC-SHA-512 implementation (RFC 2104 / FIPS 198-1)
 * @author Andrew E. A., Steel Security Advisors LLC
 * @date 2026-03-16
 *
 * Provides HMAC-SHA-512 without external dependencies.
 * Used by BIP32 HD key derivation in key_management.py
 * to satisfy INVARIANT-1 (zero external crypto dependencies).
 */

#ifndef AMA_HMAC_SHA512_H
#define AMA_HMAC_SHA512_H

#include <stddef.h>
#include <stdint.h>

/**
 * @brief Compute HMAC-SHA-512
 *
 * Standard HMAC construction per RFC 2104:
 *   HMAC(K, m) = H((K' XOR opad) || H((K' XOR ipad) || m))
 *
 * Where K' is the key padded/hashed to block size (128 bytes for SHA-512).
 *
 * @param key      HMAC key
 * @param key_len  Key length in bytes
 * @param data     Message data
 * @param data_len Data length in bytes
 * @param out      Output buffer (64 bytes)
 */
void ama_hmac_sha512(const uint8_t *key, size_t key_len,
                      const uint8_t *data, size_t data_len,
                      uint8_t out[64]);

#endif /* AMA_HMAC_SHA512_H */
