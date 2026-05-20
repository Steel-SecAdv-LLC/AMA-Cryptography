/**
 * Copyright 2025-2026 Steel Security Advisors LLC
 * Licensed under the Apache License, Version 2.0
 *
 * @file ama_hmac_sha256.h
 * @brief Native HMAC-SHA-256 implementation (RFC 2104 / FIPS 198-1)
 * @author Andrew E. A., Steel Security Advisors LLC
 * @date 2026-04-06
 *
 * Provides HMAC-SHA-256 without OpenSSL dependency.
 * Used by SPHINCS+ spx_prf_msg() (FIPS 205 Section 11.1).
 */

#ifndef AMA_HMAC_SHA256_H
#define AMA_HMAC_SHA256_H

#include <stddef.h>
#include <stdint.h>

#include "ama_cryptography.h"  /* AMA_API export-attribute macro */

/**
 * @brief Compute HMAC-SHA-256
 *
 * Standard HMAC construction per RFC 2104:
 *   HMAC(K, m) = H((K' XOR opad) || H((K' XOR ipad) || m))
 *
 * Where K' is the key padded/hashed to block size.
 *
 * AMA_API marks the function as ``__declspec(dllexport)`` on MSVC
 * builds of the shared library — without it the symbol is hidden
 * from libama_cryptography.dll's export table and the Python
 * binding's ``lib.ama_hmac_sha256`` lookup raises AttributeError at
 * import time, which is how every `Python {3.9..3.13} on
 * windows-latest` lane on PR #326 (and the parallel
 * `Test windows-latest / Python ...` lane) regressed from green on
 * `ef4b561` to red on `58e7a2d`+ once the v3.2.0 Python binding
 * commit `40a933c` started calling this symbol from ctypes.
 * Expands to a no-op on Linux/macOS where default symbol visibility
 * already exposes the C function from the .so / .dylib.
 *
 * @param key      HMAC key
 * @param key_len  Key length in bytes
 * @param data     Message data
 * @param data_len Data length in bytes
 * @param out      Output buffer (32 bytes)
 */
AMA_API void ama_hmac_sha256(const uint8_t *key, size_t key_len,
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
AMA_API void ama_hmac_sha256_2(const uint8_t *key, size_t key_len,
                                const uint8_t *data1, size_t data1_len,
                                const uint8_t *data2, size_t data2_len,
                                uint8_t out[32]);

#endif /* AMA_HMAC_SHA256_H */
