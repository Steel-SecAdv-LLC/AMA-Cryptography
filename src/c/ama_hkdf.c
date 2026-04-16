/**
 * Copyright 2025-2026 Steel Security Advisors LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/**
 * @file ama_hkdf.c
 * @brief HKDF (RFC 5869) key derivation using HMAC-SHA3-256
 * @author Andrew E. A., Steel Security Advisors LLC
 * @date 2026-04-06
 *
 * Implements HKDF (HMAC-based Key Derivation Function) per RFC 5869,
 * using HMAC-SHA3-256 as the underlying PRF.
 *
 * Security properties:
 * - Extract-then-Expand paradigm
 * - 256-bit security level with SHA3-256
 * - Constant-time operations where possible
 */

#include "../include/ama_cryptography.h"
#include "internal/ama_sha2.h"
#include <string.h>
#include <stdint.h>
#include <stdlib.h>

/* ========================================================================== */
/* HMAC-SHA-512 (RFC 2104) — public API for BIP32 key derivation             */
/* ========================================================================== */

AMA_API ama_error_t ama_hmac_sha512(
    const uint8_t *key, size_t key_len,
    const uint8_t *msg, size_t msg_len,
    uint8_t out[64]
) {
    if (!key || !out) {
        return AMA_ERROR_INVALID_PARAM;
    }
    if (!msg && msg_len > 0) {
        return AMA_ERROR_INVALID_PARAM;
    }
    /* Delegate to the 3-part internal HMAC with msg as part1, empty part2/part3 */
    int rc = ama_hmac_sha512_3(key, key_len, msg, msg_len, NULL, 0, NULL, 0, out);
    if (rc == 0)  return AMA_SUCCESS;
    if (rc == -2) return AMA_ERROR_OVERFLOW;
    return AMA_ERROR_MEMORY;
}

/* SHA3-256 constants */
#define SHA3_256_BLOCK_SIZE 136  /* Rate for SHA3-256 */
#define SHA3_256_DIGEST_SIZE 32

/* Forward declaration from ama_sha3.c */
extern ama_error_t ama_sha3_256(const uint8_t* input, size_t input_len, uint8_t* output);

/**
 * HMAC-SHA3-256
 *
 * Computes HMAC using SHA3-256 as the underlying hash function.
 * Uses standard HMAC construction: H((K XOR opad) || H((K XOR ipad) || message))
 *
 * @param key HMAC key
 * @param key_len Length of key
 * @param data Data to authenticate
 * @param data_len Length of data
 * @param output Output buffer (32 bytes)
 * @return AMA_SUCCESS or error code
 */
static ama_error_t hmac_sha3_256(
    const uint8_t* key,
    size_t key_len,
    const uint8_t* data,
    size_t data_len,
    uint8_t* output
) {
    uint8_t k_ipad[SHA3_256_BLOCK_SIZE];
    uint8_t k_opad[SHA3_256_BLOCK_SIZE];
    uint8_t key_hash[SHA3_256_DIGEST_SIZE];
    uint8_t inner_hash[SHA3_256_DIGEST_SIZE];
    uint8_t* inner_data = NULL;
    uint8_t* outer_data = NULL;
    const uint8_t* actual_key;
    size_t actual_key_len;
    size_t i;
    ama_error_t rc;

    /* If key is longer than block size, hash it first */
    if (key_len > SHA3_256_BLOCK_SIZE) {
        rc = ama_sha3_256(key, key_len, key_hash);
        if (rc != AMA_SUCCESS) {
            return rc;
        }
        actual_key = key_hash;
        actual_key_len = SHA3_256_DIGEST_SIZE;
    } else {
        actual_key = key;
        actual_key_len = key_len;
    }

    /* Initialize ipad and opad */
    memset(k_ipad, 0x36, sizeof(k_ipad));
    memset(k_opad, 0x5c, sizeof(k_opad));

    /* XOR key into pads */
    for (i = 0; i < actual_key_len; i++) {
        k_ipad[i] ^= actual_key[i];
        k_opad[i] ^= actual_key[i];
    }

    /* SECURITY FIX: Guard against integer overflow in allocation size.
     * SHA3_256_BLOCK_SIZE + data_len could wrap on 32-bit platforms if
     * data_len is near SIZE_MAX (audit finding HKDF-OVF-1). */
    if (data_len > SIZE_MAX - SHA3_256_BLOCK_SIZE) {
        rc = AMA_ERROR_OVERFLOW;
        goto cleanup;
    }

    /* Inner hash: H(K XOR ipad || data) */
    inner_data = (uint8_t*)malloc(SHA3_256_BLOCK_SIZE + data_len);
    if (!inner_data) {
        rc = AMA_ERROR_MEMORY;
        goto cleanup;
    }
    memcpy(inner_data, k_ipad, SHA3_256_BLOCK_SIZE);
    if (data_len > 0) {
        memcpy(inner_data + SHA3_256_BLOCK_SIZE, data, data_len);
    }
    rc = ama_sha3_256(inner_data, SHA3_256_BLOCK_SIZE + data_len, inner_hash);
    if (rc != AMA_SUCCESS) {
        goto cleanup;
    }

    /* Outer hash: H(K XOR opad || inner_hash) */
    outer_data = (uint8_t*)malloc(SHA3_256_BLOCK_SIZE + SHA3_256_DIGEST_SIZE);
    if (!outer_data) {
        rc = AMA_ERROR_MEMORY;
        goto cleanup;
    }
    memcpy(outer_data, k_opad, SHA3_256_BLOCK_SIZE);
    memcpy(outer_data + SHA3_256_BLOCK_SIZE, inner_hash, SHA3_256_DIGEST_SIZE);
    rc = ama_sha3_256(outer_data, SHA3_256_BLOCK_SIZE + SHA3_256_DIGEST_SIZE, output);

cleanup:
    /* Scrub sensitive data */
    ama_secure_memzero(k_ipad, sizeof(k_ipad));
    ama_secure_memzero(k_opad, sizeof(k_opad));
    ama_secure_memzero(key_hash, sizeof(key_hash));
    ama_secure_memzero(inner_hash, sizeof(inner_hash));
    if (inner_data) {
        ama_secure_memzero(inner_data, SHA3_256_BLOCK_SIZE + data_len);
        free(inner_data);
    }
    if (outer_data) {
        ama_secure_memzero(outer_data, SHA3_256_BLOCK_SIZE + SHA3_256_DIGEST_SIZE);
        free(outer_data);
    }

    return rc;
}

/**
 * Public HMAC-SHA3-256 API.
 * Delegates to the internal hmac_sha3_256() used by HKDF.
 */
AMA_API ama_error_t ama_hmac_sha3_256(
    const uint8_t *key, size_t key_len,
    const uint8_t *msg, size_t msg_len,
    uint8_t out[32]
) {
    if (!key || !out) {
        return AMA_ERROR_INVALID_PARAM;
    }
    if (!msg && msg_len > 0) {
        return AMA_ERROR_INVALID_PARAM;
    }
    /* Guard against size_t overflow in SHA3_256_BLOCK_SIZE + msg_len */
    if (msg_len > SIZE_MAX - SHA3_256_BLOCK_SIZE) {
        return AMA_ERROR_INVALID_PARAM;
    }
    return hmac_sha3_256(key, key_len, msg, msg_len, out);
}

/**
 * HKDF-Extract
 *
 * Extracts a pseudorandom key from the input key material.
 * PRK = HMAC-SHA3-256(salt, IKM)
 *
 * @param salt Optional salt (can be NULL for zero-length)
 * @param salt_len Length of salt
 * @param ikm Input key material
 * @param ikm_len Length of IKM
 * @param prk Output pseudorandom key (32 bytes)
 * @return AMA_SUCCESS or error code
 */
static ama_error_t hkdf_extract(
    const uint8_t* salt,
    size_t salt_len,
    const uint8_t* ikm,
    size_t ikm_len,
    uint8_t* prk
) {
    uint8_t default_salt[SHA3_256_DIGEST_SIZE];

    /* If no salt, use zeros */
    if (salt == NULL || salt_len == 0) {
        memset(default_salt, 0, sizeof(default_salt));
        salt = default_salt;
        salt_len = sizeof(default_salt);
    }

    return hmac_sha3_256(salt, salt_len, ikm, ikm_len, prk);
}

/**
 * HKDF-Expand
 *
 * Expands the pseudorandom key to the desired length.
 * T(0) = empty
 * T(i) = HMAC-SHA3-256(PRK, T(i-1) || info || i)
 * OKM = T(1) || T(2) || ... || T(N)
 *
 * @param prk Pseudorandom key from Extract
 * @param prk_len Length of PRK (should be 32)
 * @param info Optional context information
 * @param info_len Length of info
 * @param okm Output key material
 * @param okm_len Desired output length
 * @return AMA_SUCCESS or error code
 */
static ama_error_t hkdf_expand(
    const uint8_t* prk,
    size_t prk_len,
    const uint8_t* info,
    size_t info_len,
    uint8_t* okm,
    size_t okm_len
) {
    uint8_t T[SHA3_256_DIGEST_SIZE];
    uint8_t stack_buf[256];   /* Stack buffer for typical expand_len values */
    uint8_t *expand_data = NULL;
    int expand_on_heap = 0;
    size_t expand_len;
    size_t done = 0;
    size_t todo;
    uint8_t counter = 1;
    ama_error_t rc = AMA_SUCCESS;

    /* Maximum output is 255 * hash_length */
    if (okm_len > 255 * SHA3_256_DIGEST_SIZE) {
        return AMA_ERROR_INVALID_PARAM;
    }

    /* Allocate buffer for T_prev || info || counter.
     * Use stack buffer when small enough to eliminate malloc/free overhead
     * in the common case (SHA3_256_DIGEST_SIZE + info_len + 1 <= 256). */
    expand_len = SHA3_256_DIGEST_SIZE + info_len + 1;
    if (expand_len <= sizeof(stack_buf)) {
        expand_data = stack_buf;
    } else {
        expand_data = (uint8_t *)malloc(expand_len);
        if (!expand_data) {
            return AMA_ERROR_MEMORY;
        }
        expand_on_heap = 1;
    }

    memset(T, 0, sizeof(T));

    while (done < okm_len) {
        size_t offset = 0;

        /* Build: T(i-1) || info || counter */
        if (counter > 1) {
            memcpy(expand_data, T, SHA3_256_DIGEST_SIZE);
            offset = SHA3_256_DIGEST_SIZE;
        }
        if (info_len > 0) {
            memcpy(expand_data + offset, info, info_len);
            offset += info_len;
        }
        expand_data[offset] = counter;
        offset++;

        /* T(i) = HMAC(PRK, T(i-1) || info || i) */
        rc = hmac_sha3_256(prk, prk_len, expand_data, offset, T);
        if (rc != AMA_SUCCESS) {
            goto cleanup;
        }

        /* Copy to output */
        todo = okm_len - done;
        if (todo > SHA3_256_DIGEST_SIZE) {
            todo = SHA3_256_DIGEST_SIZE;
        }
        memcpy(okm + done, T, todo);
        done += todo;
        counter++;
    }

cleanup:
    ama_secure_memzero(T, sizeof(T));
    ama_secure_memzero(expand_data, expand_len);
    if (expand_on_heap) {
        free(expand_data);
    }

    return rc;
}

/**
 * HKDF key derivation (RFC 5869)
 *
 * Derives key material using HKDF with HMAC-SHA3-256.
 * Combines Extract and Expand operations.
 *
 * @param salt Optional salt value (can be NULL)
 * @param salt_len Length of salt
 * @param ikm Input key material
 * @param ikm_len Length of IKM
 * @param info Optional context information (can be NULL)
 * @param info_len Length of info
 * @param okm Output key material buffer
 * @param okm_len Desired length of output
 * @return AMA_SUCCESS or error code
 */
ama_error_t ama_hkdf(
    const uint8_t* salt,
    size_t salt_len,
    const uint8_t* ikm,
    size_t ikm_len,
    const uint8_t* info,
    size_t info_len,
    uint8_t* okm,
    size_t okm_len
) {
    uint8_t prk[SHA3_256_DIGEST_SIZE];
    ama_error_t rc;

    /* Validate parameters */
    if (!ikm && ikm_len > 0) {
        return AMA_ERROR_INVALID_PARAM;
    }
    if (!okm) {
        return AMA_ERROR_INVALID_PARAM;
    }
    if (okm_len == 0) {
        return AMA_SUCCESS;
    }

    /* Extract */
    rc = hkdf_extract(salt, salt_len, ikm, ikm_len, prk);
    if (rc != AMA_SUCCESS) {
        goto cleanup;
    }

    /* Expand */
    rc = hkdf_expand(prk, sizeof(prk), info, info_len, okm, okm_len);

cleanup:
    ama_secure_memzero(prk, sizeof(prk));

    return rc;
}
