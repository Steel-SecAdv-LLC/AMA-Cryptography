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
 * @file ama_core.c
 * @brief Core AMA Cryptography context and lifecycle management
 * @author Andrew E. A., Steel Security Advisors LLC
 * @date 2025-12-06
 *
 * PQC DISPATCH
 * ============
 * This file dispatches PQC operations to the native C backend:
 * - AMA_USE_NATIVE_PQC (default): Uses native C implementations from
 *   ama_dilithium.c, ama_kyber.c, and ama_sphincs.c
 * - All implementations pass NIST FIPS 203/204/205 KAT validation
 *
 * Build (default):
 *   cmake -DAMA_USE_NATIVE_PQC=ON ..
 */

#include "../include/ama_cryptography.h"
#include <stdlib.h>
#include <string.h>

/* Native PQC implementations */
#ifdef AMA_USE_NATIVE_PQC
extern ama_error_t ama_dilithium_keypair(uint8_t *public_key, uint8_t *secret_key);
extern ama_error_t ama_dilithium_sign(uint8_t *signature, size_t *signature_len,
                                       const uint8_t *message, size_t message_len,
                                       const uint8_t *secret_key);
extern ama_error_t ama_dilithium_verify(const uint8_t *message, size_t message_len,
                                         const uint8_t *signature, size_t signature_len,
                                         const uint8_t *public_key);

extern ama_error_t ama_sphincs_keypair(uint8_t *public_key, uint8_t *secret_key);
extern ama_error_t ama_sphincs_sign(uint8_t *signature, size_t *signature_len,
                                     const uint8_t *message, size_t message_len,
                                     const uint8_t *secret_key);
extern ama_error_t ama_sphincs_verify(const uint8_t *message, size_t message_len,
                                       const uint8_t *signature, size_t signature_len,
                                       const uint8_t *public_key);
#endif

/**
 * AMA Cryptography context structure (opaque)
 */
struct ama_context_t {
    ama_algorithm_t algorithm;
    void* algorithm_ctx;  /* Algorithm-specific context */
    uint32_t magic;       /* Magic number for validation */
};

#define AMA_CONTEXT_MAGIC 0x414D4143  /* "AMAC" */

/**
 * Version information
 */
const char* ama_version_string(void) {
    return AMA_CRYPTOGRAPHY_VERSION_STRING;
}

void ama_version_number(int* major, int* minor, int* patch) {
    if (major) *major = AMA_CRYPTOGRAPHY_VERSION_MAJOR;
    if (minor) *minor = AMA_CRYPTOGRAPHY_VERSION_MINOR;
    if (patch) *patch = AMA_CRYPTOGRAPHY_VERSION_PATCH;
}

/**
 * Initialize AMA Cryptography context
 */
ama_context_t* ama_context_init(ama_algorithm_t algorithm) {
    ama_context_t* ctx;

    /* Validate algorithm */
    if (algorithm < AMA_ALG_ML_DSA_65 || algorithm > AMA_ALG_HYBRID) {
        return NULL;
    }

    /* Allocate context */
    ctx = (ama_context_t*)calloc(1, sizeof(ama_context_t));
    if (!ctx) {
        return NULL;
    }

    ctx->algorithm = algorithm;
    ctx->magic = AMA_CONTEXT_MAGIC;
    ctx->algorithm_ctx = NULL;

    return ctx;
}

/**
 * Free AMA Cryptography context
 */
void ama_context_free(ama_context_t* ctx) {
    if (!ctx) {
        return;
    }

    /* Validate magic number */
    if (ctx->magic != AMA_CONTEXT_MAGIC) {
        return;
    }

    /* Free algorithm-specific context */
    if (ctx->algorithm_ctx) {
        free(ctx->algorithm_ctx);
        ctx->algorithm_ctx = NULL;
    }

    /* Scrub context */
    ama_secure_memzero(ctx, sizeof(ama_context_t));

    /* Free memory */
    free(ctx);
}

/**
 * Validate context
 */
static inline int validate_context(const ama_context_t* ctx) {
    return (ctx != NULL && ctx->magic == AMA_CONTEXT_MAGIC);
}

/**
 * Get expected key sizes for algorithm
 */
static void get_key_sizes(
    ama_algorithm_t alg,
    size_t* public_key_size,
    size_t* secret_key_size,
    size_t* signature_size
) {
    switch (alg) {
        case AMA_ALG_ML_DSA_65:
            *public_key_size = AMA_ML_DSA_65_PUBLIC_KEY_BYTES;
            *secret_key_size = AMA_ML_DSA_65_SECRET_KEY_BYTES;
            *signature_size = AMA_ML_DSA_65_SIGNATURE_BYTES;
            break;

        case AMA_ALG_KYBER_1024:
            *public_key_size = AMA_KYBER_1024_PUBLIC_KEY_BYTES;
            *secret_key_size = AMA_KYBER_1024_SECRET_KEY_BYTES;
            *signature_size = 0;  /* KEM doesn't have signatures */
            break;

        case AMA_ALG_SPHINCS_256F:
            *public_key_size = AMA_SPHINCS_256F_PUBLIC_KEY_BYTES;
            *secret_key_size = AMA_SPHINCS_256F_SECRET_KEY_BYTES;
            *signature_size = AMA_SPHINCS_256F_SIGNATURE_BYTES;
            break;

        case AMA_ALG_ED25519:
            *public_key_size = AMA_ED25519_PUBLIC_KEY_BYTES;
            *secret_key_size = AMA_ED25519_SECRET_KEY_BYTES;
            *signature_size = AMA_ED25519_SIGNATURE_BYTES;
            break;

        default:
            *public_key_size = 0;
            *secret_key_size = 0;
            *signature_size = 0;
            break;
    }
}

/**
 * Key generation
 */
ama_error_t ama_keypair_generate(
    ama_context_t* ctx,
    uint8_t* public_key,
    size_t public_key_len,
    uint8_t* secret_key,
    size_t secret_key_len
) {
    size_t expected_pk_size, expected_sk_size, sig_size;

    if (!validate_context(ctx)) {
        return AMA_ERROR_INVALID_PARAM;
    }

    if (!public_key || !secret_key) {
        return AMA_ERROR_INVALID_PARAM;
    }

    /* Check sizes */
    get_key_sizes(ctx->algorithm, &expected_pk_size, &expected_sk_size, &sig_size);

    if (public_key_len < expected_pk_size || secret_key_len < expected_sk_size) {
        return AMA_ERROR_INVALID_PARAM;
    }

#ifdef AMA_USE_NATIVE_PQC
    /* Native PQC dispatch */
    switch (ctx->algorithm) {
        case AMA_ALG_ML_DSA_65:
            return ama_dilithium_keypair(public_key, secret_key);

        case AMA_ALG_KYBER_1024:
            /* Kyber keypair generation dispatches to ama_kyber.c internal */
            /* The kyber_keypair_generate is static in ama_kyber.c, so we
             * call it through a thin wrapper defined below */
            {
                extern ama_error_t ama_kyber_keypair(uint8_t* pk, size_t pk_len,
                                                      uint8_t* sk, size_t sk_len);
                return ama_kyber_keypair(public_key, public_key_len,
                                        secret_key, secret_key_len);
            }

        case AMA_ALG_SPHINCS_256F:
            return ama_sphincs_keypair(public_key, secret_key);

        case AMA_ALG_ED25519:
            return AMA_ERROR_NOT_IMPLEMENTED;

        case AMA_ALG_HYBRID:
            /* Hybrid: generate Dilithium keypair */
            return ama_dilithium_keypair(public_key, secret_key);

        default:
            return AMA_ERROR_NOT_IMPLEMENTED;
    }
#endif

    return AMA_ERROR_NOT_IMPLEMENTED;
}

/**
 * Sign message
 */
ama_error_t ama_sign(
    ama_context_t* ctx,
    const uint8_t* message,
    size_t message_len,
    const uint8_t* secret_key,
    size_t secret_key_len,
    uint8_t* signature,
    size_t* signature_len
) {
    if (!validate_context(ctx)) {
        return AMA_ERROR_INVALID_PARAM;
    }

    if (!message || !secret_key || !signature || !signature_len) {
        return AMA_ERROR_INVALID_PARAM;
    }

#ifdef AMA_USE_NATIVE_PQC
    /* Native PQC dispatch */
    switch (ctx->algorithm) {
        case AMA_ALG_ML_DSA_65:
            if (secret_key_len < AMA_ML_DSA_65_SECRET_KEY_BYTES) {
                return AMA_ERROR_INVALID_PARAM;
            }
            if (*signature_len < AMA_ML_DSA_65_SIGNATURE_BYTES) {
                *signature_len = AMA_ML_DSA_65_SIGNATURE_BYTES;
                return AMA_ERROR_INVALID_PARAM;
            }
            return ama_dilithium_sign(signature, signature_len,
                                      message, message_len, secret_key);

        case AMA_ALG_SPHINCS_256F:
            if (secret_key_len < AMA_SPHINCS_256F_SECRET_KEY_BYTES) {
                return AMA_ERROR_INVALID_PARAM;
            }
            if (*signature_len < AMA_SPHINCS_256F_SIGNATURE_BYTES) {
                *signature_len = AMA_SPHINCS_256F_SIGNATURE_BYTES;
                return AMA_ERROR_INVALID_PARAM;
            }
            return ama_sphincs_sign(signature, signature_len,
                                    message, message_len, secret_key);

        case AMA_ALG_KYBER_1024:
            return AMA_ERROR_INVALID_PARAM;  /* KEM doesn't support signing */

        case AMA_ALG_HYBRID:
            /* Hybrid: sign with Dilithium */
            if (secret_key_len < AMA_ML_DSA_65_SECRET_KEY_BYTES) {
                return AMA_ERROR_INVALID_PARAM;
            }
            if (*signature_len < AMA_ML_DSA_65_SIGNATURE_BYTES) {
                *signature_len = AMA_ML_DSA_65_SIGNATURE_BYTES;
                return AMA_ERROR_INVALID_PARAM;
            }
            return ama_dilithium_sign(signature, signature_len,
                                      message, message_len, secret_key);

        default:
            break;
    }
    (void)secret_key_len;
#else
    /* Suppress unused parameter warnings */
    (void)message_len;
    (void)secret_key_len;
#endif

    return AMA_ERROR_NOT_IMPLEMENTED;
}

/**
 * Verify signature
 */
ama_error_t ama_verify(
    ama_context_t* ctx,
    const uint8_t* message,
    size_t message_len,
    const uint8_t* signature,
    size_t signature_len,
    const uint8_t* public_key,
    size_t public_key_len
) {
    if (!validate_context(ctx)) {
        return AMA_ERROR_INVALID_PARAM;
    }

    if (!message || !signature || !public_key) {
        return AMA_ERROR_INVALID_PARAM;
    }

#ifdef AMA_USE_NATIVE_PQC
    /* Native PQC dispatch */
    switch (ctx->algorithm) {
        case AMA_ALG_ML_DSA_65:
            if (public_key_len < AMA_ML_DSA_65_PUBLIC_KEY_BYTES) {
                return AMA_ERROR_INVALID_PARAM;
            }
            return ama_dilithium_verify(message, message_len,
                                        signature, signature_len, public_key);

        case AMA_ALG_SPHINCS_256F:
            if (public_key_len < AMA_SPHINCS_256F_PUBLIC_KEY_BYTES) {
                return AMA_ERROR_INVALID_PARAM;
            }
            return ama_sphincs_verify(message, message_len,
                                      signature, signature_len, public_key);

        case AMA_ALG_KYBER_1024:
            return AMA_ERROR_INVALID_PARAM;  /* KEM doesn't support verification */

        case AMA_ALG_HYBRID:
            if (public_key_len < AMA_ML_DSA_65_PUBLIC_KEY_BYTES) {
                return AMA_ERROR_INVALID_PARAM;
            }
            return ama_dilithium_verify(message, message_len,
                                        signature, signature_len, public_key);

        default:
            break;
    }
    (void)message_len;
    (void)signature_len;
    (void)public_key_len;
#else
    /* Suppress unused parameter warnings */
    (void)message_len;
    (void)signature_len;
    (void)public_key_len;
#endif

    return AMA_ERROR_NOT_IMPLEMENTED;
}

/**
 * KEM Encapsulation
 *
 * Generates a shared secret and ciphertext using the recipient's public key.
 * The shared secret can be used for symmetric encryption.
 */
ama_error_t ama_kem_encapsulate(
    ama_context_t* ctx,
    const uint8_t* public_key,
    size_t public_key_len,
    uint8_t* ciphertext,
    size_t* ciphertext_len,
    uint8_t* shared_secret,
    size_t shared_secret_len
) {
    if (!validate_context(ctx)) {
        return AMA_ERROR_INVALID_PARAM;
    }

    if (!public_key || !ciphertext || !ciphertext_len || !shared_secret) {
        return AMA_ERROR_INVALID_PARAM;
    }

#ifdef AMA_USE_NATIVE_PQC
    /* Native Kyber-1024 encapsulation */
    if (ctx->algorithm == AMA_ALG_KYBER_1024) {
        extern ama_error_t ama_kyber_encapsulate(const uint8_t* pk, size_t pk_len,
                                                  uint8_t* ct, size_t* ct_len,
                                                  uint8_t* ss, size_t ss_len);
        return ama_kyber_encapsulate(public_key, public_key_len,
                                     ciphertext, ciphertext_len,
                                     shared_secret, shared_secret_len);
    }
    /* Signature algorithms don't support encapsulation */
    if (ctx->algorithm == AMA_ALG_ML_DSA_65 ||
        ctx->algorithm == AMA_ALG_SPHINCS_256F) {
        return AMA_ERROR_INVALID_PARAM;
    }
#else
    /* Suppress unused parameter warnings */
    (void)public_key_len;
    (void)shared_secret_len;
#endif

    return AMA_ERROR_NOT_IMPLEMENTED;
}

/**
 * KEM Decapsulation
 *
 * Recovers the shared secret from a ciphertext using the recipient's secret key.
 * Uses implicit rejection for IND-CCA2 security.
 */
ama_error_t ama_kem_decapsulate(
    ama_context_t* ctx,
    const uint8_t* ciphertext,
    size_t ciphertext_len,
    const uint8_t* secret_key,
    size_t secret_key_len,
    uint8_t* shared_secret,
    size_t shared_secret_len
) {
    if (!validate_context(ctx)) {
        return AMA_ERROR_INVALID_PARAM;
    }

    if (!ciphertext || !secret_key || !shared_secret) {
        return AMA_ERROR_INVALID_PARAM;
    }

#ifdef AMA_USE_NATIVE_PQC
    /* Native Kyber-1024 decapsulation */
    if (ctx->algorithm == AMA_ALG_KYBER_1024) {
        extern ama_error_t ama_kyber_decapsulate(const uint8_t* ct, size_t ct_len,
                                                  const uint8_t* sk, size_t sk_len,
                                                  uint8_t* ss, size_t ss_len);
        return ama_kyber_decapsulate(ciphertext, ciphertext_len,
                                     secret_key, secret_key_len,
                                     shared_secret, shared_secret_len);
    }
    if (ctx->algorithm == AMA_ALG_ML_DSA_65 ||
        ctx->algorithm == AMA_ALG_SPHINCS_256F) {
        return AMA_ERROR_INVALID_PARAM;
    }
#else
    /* Suppress unused parameter warnings */
    (void)ciphertext_len;
    (void)secret_key_len;
    (void)shared_secret_len;
#endif

    return AMA_ERROR_NOT_IMPLEMENTED;
}
