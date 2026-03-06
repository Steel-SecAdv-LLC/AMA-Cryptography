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
 * @file ava_core.c
 * @brief Core Ava Guardian ♱ context and lifecycle management
 * @author Andrew E. A., Steel Security Advisors LLC
 * @date 2025-12-06
 *
 * PQC DISPATCH
 * ============
 * This file dispatches PQC operations to the native C backend:
 * - AVA_USE_NATIVE_PQC (default): Uses native C implementations from
 *   ava_dilithium.c, ava_kyber.c, and ava_sphincs.c
 * - All implementations pass NIST FIPS 203/204/205 KAT validation
 *
 * Build (default):
 *   cmake -DAVA_USE_NATIVE_PQC=ON ..
 */

#include "../include/ava_guardian.h"
#include <stdlib.h>
#include <string.h>

/* liboqs integration - conditionally include if available */
#ifdef AVA_USE_LIBOQS
#include <oqs/oqs.h>
#endif

/* Native PQC implementations */
#ifdef AVA_USE_NATIVE_PQC
extern ava_error_t ava_dilithium_keypair(uint8_t *public_key, uint8_t *secret_key);
extern ava_error_t ava_dilithium_sign(uint8_t *signature, size_t *signature_len,
                                       const uint8_t *message, size_t message_len,
                                       const uint8_t *secret_key);
extern ava_error_t ava_dilithium_verify(const uint8_t *message, size_t message_len,
                                         const uint8_t *signature, size_t signature_len,
                                         const uint8_t *public_key);

extern ava_error_t ava_sphincs_keypair(uint8_t *public_key, uint8_t *secret_key);
extern ava_error_t ava_sphincs_sign(uint8_t *signature, size_t *signature_len,
                                     const uint8_t *message, size_t message_len,
                                     const uint8_t *secret_key);
extern ava_error_t ava_sphincs_verify(const uint8_t *message, size_t message_len,
                                       const uint8_t *signature, size_t signature_len,
                                       const uint8_t *public_key);
#endif

/**
 * Ava Guardian ♱ context structure (opaque)
 */
struct ava_context_t {
    ava_algorithm_t algorithm;
    void* algorithm_ctx;  /* Algorithm-specific context */
    uint32_t magic;       /* Magic number for validation */
#ifdef AVA_USE_LIBOQS
    OQS_SIG* sig;         /* liboqs signature context (for Dilithium) */
    OQS_KEM* kem;         /* liboqs KEM context (for Kyber) */
#endif
};

#define AVA_CONTEXT_MAGIC 0x41564147  /* "AVAG" */

/**
 * Version information
 */
const char* ava_version_string(void) {
    return AVA_GUARDIAN_VERSION_STRING;
}

void ava_version_number(int* major, int* minor, int* patch) {
    if (major) *major = AVA_GUARDIAN_VERSION_MAJOR;
    if (minor) *minor = AVA_GUARDIAN_VERSION_MINOR;
    if (patch) *patch = AVA_GUARDIAN_VERSION_PATCH;
}

/**
 * Initialize Ava Guardian ♱ context
 */
ava_context_t* ava_context_init(ava_algorithm_t algorithm) {
    ava_context_t* ctx;

    /* Validate algorithm */
    if (algorithm < AVA_ALG_ML_DSA_65 || algorithm > AVA_ALG_HYBRID) {
        return NULL;
    }

    /* Allocate context */
    ctx = (ava_context_t*)calloc(1, sizeof(ava_context_t));
    if (!ctx) {
        return NULL;
    }

    ctx->algorithm = algorithm;
    ctx->magic = AVA_CONTEXT_MAGIC;
    ctx->algorithm_ctx = NULL;

#ifdef AVA_USE_LIBOQS
    ctx->sig = NULL;
    ctx->kem = NULL;

    /* Initialize liboqs objects based on algorithm */
    switch (algorithm) {
        case AVA_ALG_ML_DSA_65:
            ctx->sig = OQS_SIG_new(OQS_SIG_alg_ml_dsa_65);
            if (!ctx->sig) {
                free(ctx);
                return NULL;
            }
            break;

        case AVA_ALG_KYBER_1024:
            ctx->kem = OQS_KEM_new(OQS_KEM_alg_ml_kem_1024);
            if (!ctx->kem) {
                free(ctx);
                return NULL;
            }
            break;

        case AVA_ALG_SPHINCS_256F:
            ctx->sig = OQS_SIG_new(OQS_SIG_alg_sphincs_sha2_256f_simple);
            if (!ctx->sig) {
                free(ctx);
                return NULL;
            }
            break;

        case AVA_ALG_ED25519:
            /* Ed25519 not provided by liboqs - use separate implementation */
            break;

        case AVA_ALG_HYBRID:
            /* Hybrid mode: initialize both Dilithium and Ed25519 */
            ctx->sig = OQS_SIG_new(OQS_SIG_alg_ml_dsa_65);
            if (!ctx->sig) {
                free(ctx);
                return NULL;
            }
            break;

        default:
            break;
    }
#endif

    return ctx;
}

/**
 * Free Ava Guardian ♱ context
 */
void ava_context_free(ava_context_t* ctx) {
    if (!ctx) {
        return;
    }

    /* Validate magic number */
    if (ctx->magic != AVA_CONTEXT_MAGIC) {
        return;
    }

#ifdef AVA_USE_LIBOQS
    /* Free liboqs signature context */
    if (ctx->sig) {
        OQS_SIG_free(ctx->sig);
        ctx->sig = NULL;
    }

    /* Free liboqs KEM context */
    if (ctx->kem) {
        OQS_KEM_free(ctx->kem);
        ctx->kem = NULL;
    }
#endif

    /* Free algorithm-specific context */
    if (ctx->algorithm_ctx) {
        free(ctx->algorithm_ctx);
        ctx->algorithm_ctx = NULL;
    }

    /* Scrub context */
    ava_secure_memzero(ctx, sizeof(ava_context_t));

    /* Free memory */
    free(ctx);
}

/**
 * Validate context
 */
static inline int validate_context(const ava_context_t* ctx) {
    return (ctx != NULL && ctx->magic == AVA_CONTEXT_MAGIC);
}

/**
 * Get expected key sizes for algorithm
 */
static void get_key_sizes(
    ava_algorithm_t alg,
    size_t* public_key_size,
    size_t* secret_key_size,
    size_t* signature_size
) {
    switch (alg) {
        case AVA_ALG_ML_DSA_65:
            *public_key_size = AVA_ML_DSA_65_PUBLIC_KEY_BYTES;
            *secret_key_size = AVA_ML_DSA_65_SECRET_KEY_BYTES;
            *signature_size = AVA_ML_DSA_65_SIGNATURE_BYTES;
            break;

        case AVA_ALG_KYBER_1024:
            *public_key_size = AVA_KYBER_1024_PUBLIC_KEY_BYTES;
            *secret_key_size = AVA_KYBER_1024_SECRET_KEY_BYTES;
            *signature_size = 0;  /* KEM doesn't have signatures */
            break;

        case AVA_ALG_SPHINCS_256F:
            *public_key_size = AVA_SPHINCS_256F_PUBLIC_KEY_BYTES;
            *secret_key_size = AVA_SPHINCS_256F_SECRET_KEY_BYTES;
            *signature_size = AVA_SPHINCS_256F_SIGNATURE_BYTES;
            break;

        case AVA_ALG_ED25519:
            *public_key_size = AVA_ED25519_PUBLIC_KEY_BYTES;
            *secret_key_size = AVA_ED25519_SECRET_KEY_BYTES;
            *signature_size = AVA_ED25519_SIGNATURE_BYTES;
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
ava_error_t ava_keypair_generate(
    ava_context_t* ctx,
    uint8_t* public_key,
    size_t public_key_len,
    uint8_t* secret_key,
    size_t secret_key_len
) {
    size_t expected_pk_size, expected_sk_size, sig_size;

    if (!validate_context(ctx)) {
        return AVA_ERROR_INVALID_PARAM;
    }

    if (!public_key || !secret_key) {
        return AVA_ERROR_INVALID_PARAM;
    }

    /* Check sizes */
    get_key_sizes(ctx->algorithm, &expected_pk_size, &expected_sk_size, &sig_size);

    if (public_key_len < expected_pk_size || secret_key_len < expected_sk_size) {
        return AVA_ERROR_INVALID_PARAM;
    }

#ifdef AVA_USE_LIBOQS
    OQS_STATUS rc;

    /* Handle signature algorithms */
    if (ctx->sig) {
        rc = OQS_SIG_keypair(ctx->sig, public_key, secret_key);
        if (rc != OQS_SUCCESS) {
            return AVA_ERROR_CRYPTO;
        }
        return AVA_SUCCESS;
    }

    /* Handle KEM algorithms */
    if (ctx->kem) {
        rc = OQS_KEM_keypair(ctx->kem, public_key, secret_key);
        if (rc != OQS_SUCCESS) {
            return AVA_ERROR_CRYPTO;
        }
        return AVA_SUCCESS;
    }

    /* Ed25519 not provided by liboqs */
    if (ctx->algorithm == AVA_ALG_ED25519) {
        return AVA_ERROR_NOT_IMPLEMENTED;
    }
#elif defined(AVA_USE_NATIVE_PQC)
    /* Native PQC dispatch */
    switch (ctx->algorithm) {
        case AVA_ALG_ML_DSA_65:
            return ava_dilithium_keypair(public_key, secret_key);

        case AVA_ALG_KYBER_1024:
            /* Kyber keypair generation dispatches to ava_kyber.c internal */
            /* The kyber_keypair_generate is static in ava_kyber.c, so we
             * call it through a thin wrapper defined below */
            {
                extern ava_error_t ava_kyber_keypair(uint8_t* pk, size_t pk_len,
                                                      uint8_t* sk, size_t sk_len);
                return ava_kyber_keypair(public_key, public_key_len,
                                        secret_key, secret_key_len);
            }

        case AVA_ALG_SPHINCS_256F:
            return ava_sphincs_keypair(public_key, secret_key);

        case AVA_ALG_ED25519:
            return AVA_ERROR_NOT_IMPLEMENTED;

        case AVA_ALG_HYBRID:
            /* Hybrid: generate Dilithium keypair */
            return ava_dilithium_keypair(public_key, secret_key);

        default:
            return AVA_ERROR_NOT_IMPLEMENTED;
    }
#endif

    return AVA_ERROR_NOT_IMPLEMENTED;
}

/**
 * Sign message
 */
ava_error_t ava_sign(
    ava_context_t* ctx,
    const uint8_t* message,
    size_t message_len,
    const uint8_t* secret_key,
    size_t secret_key_len,
    uint8_t* signature,
    size_t* signature_len
) {
    if (!validate_context(ctx)) {
        return AVA_ERROR_INVALID_PARAM;
    }

    if (!message || !secret_key || !signature || !signature_len) {
        return AVA_ERROR_INVALID_PARAM;
    }

#ifdef AVA_USE_LIBOQS
    OQS_STATUS rc;

    if (ctx->sig) {
        /* Validate secret key length */
        if (secret_key_len < ctx->sig->length_secret_key) {
            return AVA_ERROR_INVALID_PARAM;
        }

        /* Validate signature buffer size */
        if (*signature_len < ctx->sig->length_signature) {
            *signature_len = ctx->sig->length_signature;
            return AVA_ERROR_INVALID_PARAM;
        }

        /* Sign the message */
        rc = OQS_SIG_sign(ctx->sig, signature, signature_len,
                         message, message_len, secret_key);
        if (rc != OQS_SUCCESS) {
            return AVA_ERROR_CRYPTO;
        }
        return AVA_SUCCESS;
    }

    /* KEM doesn't support signing */
    if (ctx->kem) {
        return AVA_ERROR_INVALID_PARAM;
    }

    /* Ed25519 not provided by liboqs */
    if (ctx->algorithm == AVA_ALG_ED25519) {
        (void)secret_key_len;
        return AVA_ERROR_NOT_IMPLEMENTED;
    }
#elif defined(AVA_USE_NATIVE_PQC)
    /* Native PQC dispatch */
    switch (ctx->algorithm) {
        case AVA_ALG_ML_DSA_65:
            if (secret_key_len < AVA_ML_DSA_65_SECRET_KEY_BYTES) {
                return AVA_ERROR_INVALID_PARAM;
            }
            if (*signature_len < AVA_ML_DSA_65_SIGNATURE_BYTES) {
                *signature_len = AVA_ML_DSA_65_SIGNATURE_BYTES;
                return AVA_ERROR_INVALID_PARAM;
            }
            return ava_dilithium_sign(signature, signature_len,
                                      message, message_len, secret_key);

        case AVA_ALG_SPHINCS_256F:
            if (secret_key_len < AVA_SPHINCS_256F_SECRET_KEY_BYTES) {
                return AVA_ERROR_INVALID_PARAM;
            }
            if (*signature_len < AVA_SPHINCS_256F_SIGNATURE_BYTES) {
                *signature_len = AVA_SPHINCS_256F_SIGNATURE_BYTES;
                return AVA_ERROR_INVALID_PARAM;
            }
            return ava_sphincs_sign(signature, signature_len,
                                    message, message_len, secret_key);

        case AVA_ALG_KYBER_1024:
            return AVA_ERROR_INVALID_PARAM;  /* KEM doesn't support signing */

        case AVA_ALG_HYBRID:
            /* Hybrid: sign with Dilithium */
            if (secret_key_len < AVA_ML_DSA_65_SECRET_KEY_BYTES) {
                return AVA_ERROR_INVALID_PARAM;
            }
            if (*signature_len < AVA_ML_DSA_65_SIGNATURE_BYTES) {
                *signature_len = AVA_ML_DSA_65_SIGNATURE_BYTES;
                return AVA_ERROR_INVALID_PARAM;
            }
            return ava_dilithium_sign(signature, signature_len,
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

    return AVA_ERROR_NOT_IMPLEMENTED;
}

/**
 * Verify signature
 */
ava_error_t ava_verify(
    ava_context_t* ctx,
    const uint8_t* message,
    size_t message_len,
    const uint8_t* signature,
    size_t signature_len,
    const uint8_t* public_key,
    size_t public_key_len
) {
    if (!validate_context(ctx)) {
        return AVA_ERROR_INVALID_PARAM;
    }

    if (!message || !signature || !public_key) {
        return AVA_ERROR_INVALID_PARAM;
    }

#ifdef AVA_USE_LIBOQS
    OQS_STATUS rc;

    if (ctx->sig) {
        /* Validate public key length */
        if (public_key_len < ctx->sig->length_public_key) {
            return AVA_ERROR_INVALID_PARAM;
        }

        /* Verify the signature */
        rc = OQS_SIG_verify(ctx->sig, message, message_len,
                           signature, signature_len, public_key);
        if (rc != OQS_SUCCESS) {
            return AVA_ERROR_VERIFY_FAILED;
        }
        return AVA_SUCCESS;
    }

    /* KEM doesn't support verification */
    if (ctx->kem) {
        return AVA_ERROR_INVALID_PARAM;
    }

    /* Ed25519 not provided by liboqs */
    if (ctx->algorithm == AVA_ALG_ED25519) {
        (void)message_len;
        (void)signature_len;
        (void)public_key_len;
        return AVA_ERROR_NOT_IMPLEMENTED;
    }
#elif defined(AVA_USE_NATIVE_PQC)
    /* Native PQC dispatch */
    switch (ctx->algorithm) {
        case AVA_ALG_ML_DSA_65:
            if (public_key_len < AVA_ML_DSA_65_PUBLIC_KEY_BYTES) {
                return AVA_ERROR_INVALID_PARAM;
            }
            return ava_dilithium_verify(message, message_len,
                                        signature, signature_len, public_key);

        case AVA_ALG_SPHINCS_256F:
            if (public_key_len < AVA_SPHINCS_256F_PUBLIC_KEY_BYTES) {
                return AVA_ERROR_INVALID_PARAM;
            }
            return ava_sphincs_verify(message, message_len,
                                      signature, signature_len, public_key);

        case AVA_ALG_KYBER_1024:
            return AVA_ERROR_INVALID_PARAM;  /* KEM doesn't support verification */

        case AVA_ALG_HYBRID:
            if (public_key_len < AVA_ML_DSA_65_PUBLIC_KEY_BYTES) {
                return AVA_ERROR_INVALID_PARAM;
            }
            return ava_dilithium_verify(message, message_len,
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

    return AVA_ERROR_NOT_IMPLEMENTED;
}

/**
 * KEM Encapsulation
 *
 * Generates a shared secret and ciphertext using the recipient's public key.
 * The shared secret can be used for symmetric encryption.
 */
ava_error_t ava_kem_encapsulate(
    ava_context_t* ctx,
    const uint8_t* public_key,
    size_t public_key_len,
    uint8_t* ciphertext,
    size_t* ciphertext_len,
    uint8_t* shared_secret,
    size_t shared_secret_len
) {
    if (!validate_context(ctx)) {
        return AVA_ERROR_INVALID_PARAM;
    }

    if (!public_key || !ciphertext || !ciphertext_len || !shared_secret) {
        return AVA_ERROR_INVALID_PARAM;
    }

#ifdef AVA_USE_LIBOQS
    OQS_STATUS rc;

    if (ctx->kem) {
        /* Validate public key length */
        if (public_key_len < ctx->kem->length_public_key) {
            return AVA_ERROR_INVALID_PARAM;
        }

        /* Validate ciphertext buffer size */
        if (*ciphertext_len < ctx->kem->length_ciphertext) {
            *ciphertext_len = ctx->kem->length_ciphertext;
            return AVA_ERROR_INVALID_PARAM;
        }

        /* Validate shared secret buffer size */
        if (shared_secret_len < ctx->kem->length_shared_secret) {
            return AVA_ERROR_INVALID_PARAM;
        }

        /* Encapsulate */
        rc = OQS_KEM_encaps(ctx->kem, ciphertext, shared_secret, public_key);
        if (rc != OQS_SUCCESS) {
            return AVA_ERROR_CRYPTO;
        }

        *ciphertext_len = ctx->kem->length_ciphertext;
        return AVA_SUCCESS;
    }

    /* Signature algorithms don't support encapsulation */
    if (ctx->sig) {
        return AVA_ERROR_INVALID_PARAM;
    }
#elif defined(AVA_USE_NATIVE_PQC)
    /* Native Kyber-1024 encapsulation */
    if (ctx->algorithm == AVA_ALG_KYBER_1024) {
        extern ava_error_t ava_kyber_encapsulate(const uint8_t* pk, size_t pk_len,
                                                  uint8_t* ct, size_t* ct_len,
                                                  uint8_t* ss, size_t ss_len);
        return ava_kyber_encapsulate(public_key, public_key_len,
                                     ciphertext, ciphertext_len,
                                     shared_secret, shared_secret_len);
    }
    /* Signature algorithms don't support encapsulation */
    if (ctx->algorithm == AVA_ALG_ML_DSA_65 ||
        ctx->algorithm == AVA_ALG_SPHINCS_256F) {
        return AVA_ERROR_INVALID_PARAM;
    }
#else
    /* Suppress unused parameter warnings */
    (void)public_key_len;
    (void)shared_secret_len;
#endif

    return AVA_ERROR_NOT_IMPLEMENTED;
}

/**
 * KEM Decapsulation
 *
 * Recovers the shared secret from a ciphertext using the recipient's secret key.
 * Uses implicit rejection for IND-CCA2 security.
 */
ava_error_t ava_kem_decapsulate(
    ava_context_t* ctx,
    const uint8_t* ciphertext,
    size_t ciphertext_len,
    const uint8_t* secret_key,
    size_t secret_key_len,
    uint8_t* shared_secret,
    size_t shared_secret_len
) {
    if (!validate_context(ctx)) {
        return AVA_ERROR_INVALID_PARAM;
    }

    if (!ciphertext || !secret_key || !shared_secret) {
        return AVA_ERROR_INVALID_PARAM;
    }

#ifdef AVA_USE_LIBOQS
    OQS_STATUS rc;

    if (ctx->kem) {
        /* Validate ciphertext length */
        if (ciphertext_len < ctx->kem->length_ciphertext) {
            return AVA_ERROR_INVALID_PARAM;
        }

        /* Validate secret key length */
        if (secret_key_len < ctx->kem->length_secret_key) {
            return AVA_ERROR_INVALID_PARAM;
        }

        /* Validate shared secret buffer size */
        if (shared_secret_len < ctx->kem->length_shared_secret) {
            return AVA_ERROR_INVALID_PARAM;
        }

        /* Decapsulate */
        rc = OQS_KEM_decaps(ctx->kem, shared_secret, ciphertext, secret_key);
        if (rc != OQS_SUCCESS) {
            return AVA_ERROR_CRYPTO;
        }

        return AVA_SUCCESS;
    }

    /* Signature algorithms don't support decapsulation */
    if (ctx->sig) {
        return AVA_ERROR_INVALID_PARAM;
    }
#elif defined(AVA_USE_NATIVE_PQC)
    /* Native Kyber-1024 decapsulation */
    if (ctx->algorithm == AVA_ALG_KYBER_1024) {
        extern ava_error_t ava_kyber_decapsulate(const uint8_t* ct, size_t ct_len,
                                                  const uint8_t* sk, size_t sk_len,
                                                  uint8_t* ss, size_t ss_len);
        return ava_kyber_decapsulate(ciphertext, ciphertext_len,
                                     secret_key, secret_key_len,
                                     shared_secret, shared_secret_len);
    }
    if (ctx->algorithm == AVA_ALG_ML_DSA_65 ||
        ctx->algorithm == AVA_ALG_SPHINCS_256F) {
        return AVA_ERROR_INVALID_PARAM;
    }
#else
    /* Suppress unused parameter warnings */
    (void)ciphertext_len;
    (void)secret_key_len;
    (void)shared_secret_len;
#endif

    return AVA_ERROR_NOT_IMPLEMENTED;
}
