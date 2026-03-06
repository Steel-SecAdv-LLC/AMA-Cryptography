/**
 * Copyright 2025 Steel Security Advisors LLC
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
 * @date 2025-12-06
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
#include <string.h>
#include <stdint.h>
#include <stdlib.h>

/* SHA3-256 constants */
#define SHA3_256_BLOCK_SIZE 136  /* Rate for SHA3-256 */
#define SHA3_256_DIGEST_SIZE 32

/* Forward declaration from ama_sha3.c */
extern ava_error_t ama_sha3_256(const uint8_t* input, size_t input_len, uint8_t* output);

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
 * @return AVA_SUCCESS or error code
 */
static ava_error_t hmac_sha3_256(
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
    ava_error_t rc;

    /* If key is longer than block size, hash it first */
    if (key_len > SHA3_256_BLOCK_SIZE) {
        rc = ama_sha3_256(key, key_len, key_hash);
        if (rc != AVA_SUCCESS) {
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

    /* Inner hash: H(K XOR ipad || data) */
    inner_data = (uint8_t*)malloc(SHA3_256_BLOCK_SIZE + data_len);
    if (!inner_data) {
        rc = AVA_ERROR_MEMORY;
        goto cleanup;
    }
    memcpy(inner_data, k_ipad, SHA3_256_BLOCK_SIZE);
    if (data_len > 0) {
        memcpy(inner_data + SHA3_256_BLOCK_SIZE, data, data_len);
    }
    rc = ama_sha3_256(inner_data, SHA3_256_BLOCK_SIZE + data_len, inner_hash);
    if (rc != AVA_SUCCESS) {
        goto cleanup;
    }

    /* Outer hash: H(K XOR opad || inner_hash) */
    outer_data = (uint8_t*)malloc(SHA3_256_BLOCK_SIZE + SHA3_256_DIGEST_SIZE);
    if (!outer_data) {
        rc = AVA_ERROR_MEMORY;
        goto cleanup;
    }
    memcpy(outer_data, k_opad, SHA3_256_BLOCK_SIZE);
    memcpy(outer_data + SHA3_256_BLOCK_SIZE, inner_hash, SHA3_256_DIGEST_SIZE);
    rc = ama_sha3_256(outer_data, SHA3_256_BLOCK_SIZE + SHA3_256_DIGEST_SIZE, output);

cleanup:
    /* Scrub sensitive data */
    ava_secure_memzero(k_ipad, sizeof(k_ipad));
    ava_secure_memzero(k_opad, sizeof(k_opad));
    ava_secure_memzero(key_hash, sizeof(key_hash));
    ava_secure_memzero(inner_hash, sizeof(inner_hash));
    if (inner_data) {
        ava_secure_memzero(inner_data, SHA3_256_BLOCK_SIZE + data_len);
        free(inner_data);
    }
    if (outer_data) {
        ava_secure_memzero(outer_data, SHA3_256_BLOCK_SIZE + SHA3_256_DIGEST_SIZE);
        free(outer_data);
    }

    return rc;
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
 * @return AVA_SUCCESS or error code
 */
static ava_error_t hkdf_extract(
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
 * @return AVA_SUCCESS or error code
 */
static ava_error_t hkdf_expand(
    const uint8_t* prk,
    size_t prk_len,
    const uint8_t* info,
    size_t info_len,
    uint8_t* okm,
    size_t okm_len
) {
    uint8_t T[SHA3_256_DIGEST_SIZE];
    uint8_t* expand_data = NULL;
    size_t expand_len;
    size_t done = 0;
    size_t todo;
    uint8_t counter = 1;
    ava_error_t rc = AVA_SUCCESS;

    /* Maximum output is 255 * hash_length */
    if (okm_len > 255 * SHA3_256_DIGEST_SIZE) {
        return AVA_ERROR_INVALID_PARAM;
    }

    /* Allocate buffer for T_prev || info || counter */
    expand_len = SHA3_256_DIGEST_SIZE + info_len + 1;
    expand_data = (uint8_t*)malloc(expand_len);
    if (!expand_data) {
        return AVA_ERROR_MEMORY;
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
        if (rc != AVA_SUCCESS) {
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
    ava_secure_memzero(T, sizeof(T));
    if (expand_data) {
        ava_secure_memzero(expand_data, expand_len);
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
 * @return AVA_SUCCESS or error code
 */
ava_error_t ama_hkdf(
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
    ava_error_t rc;

    /* Validate parameters */
    if (!ikm && ikm_len > 0) {
        return AVA_ERROR_INVALID_PARAM;
    }
    if (!okm) {
        return AVA_ERROR_INVALID_PARAM;
    }
    if (okm_len == 0) {
        return AVA_SUCCESS;
    }

    /* Extract */
    rc = hkdf_extract(salt, salt_len, ikm, ikm_len, prk);
    if (rc != AVA_SUCCESS) {
        goto cleanup;
    }

    /* Expand */
    rc = hkdf_expand(prk, sizeof(prk), info, info_len, okm, okm_len);

cleanup:
    ava_secure_memzero(prk, sizeof(prk));

    return rc;
}
