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
 * @file ama_core.c
 * @brief Core AMA Cryptography context and lifecycle management
 * @author Andrew E. A., Steel Security Advisors LLC
 * @date 2026-04-06
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

extern ama_error_t ama_kyber_keypair(uint8_t* pk, size_t pk_len,
                                      uint8_t* sk, size_t sk_len);
extern ama_error_t ama_kyber_encapsulate(const uint8_t* pk, size_t pk_len,
                                          uint8_t* ct, size_t* ct_len,
                                          uint8_t* ss, size_t ss_len);
extern ama_error_t ama_kyber_decapsulate(const uint8_t* ct, size_t ct_len,
                                          const uint8_t* sk, size_t sk_len,
                                          uint8_t* ss, size_t ss_len);

/* Ed25519 — concrete backend is either the fe51 reference (default) or the
 * donna shim (AMA_ED25519_ASSEMBLY=ON); both expose the same three symbols.
 * Selected at build time via CMakeLists.txt, not at runtime — the dispatcher
 * reports `ed25519 = AMA_IMPL_GENERIC` either way. */
extern ama_error_t ama_ed25519_keypair(uint8_t public_key[32],
                                        uint8_t secret_key[64]);
extern ama_error_t ama_ed25519_sign(uint8_t signature[64],
                                     const uint8_t *message,
                                     size_t message_len,
                                     const uint8_t secret_key[64]);
extern ama_error_t ama_ed25519_verify(const uint8_t signature[64],
                                       const uint8_t *message,
                                       size_t message_len,
                                       const uint8_t public_key[32]);

/* Platform CSPRNG (src/c/ama_platform_rand.c).  Used to derive the 32-byte
 * Ed25519 seed inside `ama_keypair_generate(AMA_ALG_ED25519)` before
 * delegating to `ama_ed25519_keypair`, whose contract requires the caller
 * to supply the seed in `secret_key[0..31]`. */
extern ama_error_t ama_randombytes(uint8_t *buf, size_t len);
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

#ifndef AMA_INTEGRITY_TRUST_ANCHOR_PUBKEY_HEX
#define AMA_INTEGRITY_TRUST_ANCHOR_PUBKEY_HEX ""
#endif

const char* ama_integrity_trust_anchor_pubkey_hex(void) {
    return AMA_INTEGRITY_TRUST_ANCHOR_PUBKEY_HEX;
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
            return ama_kyber_keypair(public_key, public_key_len,
                                    secret_key, secret_key_len);

        case AMA_ALG_SPHINCS_256F:
            return ama_sphincs_keypair(public_key, secret_key);

        case AMA_ALG_ED25519: {
            /* AMA Ed25519 convention: caller fills secret_key[0..31] with
             * seed bytes before invoking ama_ed25519_keypair.  Draw the
             * seed from the platform CSPRNG, then delegate.  Scrub on
             * any failure path — INVARIANT-6. */
            ama_error_t rc_rand = ama_randombytes(secret_key, 32);
            if (rc_rand != AMA_SUCCESS) {
                ama_secure_memzero(secret_key, expected_sk_size);
                return rc_rand;
            }
            ama_error_t rc = ama_ed25519_keypair(public_key, secret_key);
            if (rc != AMA_SUCCESS) {
                ama_secure_memzero(secret_key, expected_sk_size);
                ama_secure_memzero(public_key, expected_pk_size);
            }
            return rc;
        }

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

        case AMA_ALG_ED25519:
            if (secret_key_len < AMA_ED25519_SECRET_KEY_BYTES) {
                return AMA_ERROR_INVALID_PARAM;
            }
            if (*signature_len < AMA_ED25519_SIGNATURE_BYTES) {
                *signature_len = AMA_ED25519_SIGNATURE_BYTES;
                return AMA_ERROR_INVALID_PARAM;
            }
            /* Ed25519 sig is fixed-size; the in/out signature_len protocol
             * matches ML-DSA / SPHINCS+ even though the backend doesn't
             * write the length itself. */
            *signature_len = AMA_ED25519_SIGNATURE_BYTES;
            return ama_ed25519_sign(signature, message, message_len, secret_key);

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

        case AMA_ALG_ED25519:
            if (public_key_len < AMA_ED25519_PUBLIC_KEY_BYTES) {
                return AMA_ERROR_INVALID_PARAM;
            }
            if (signature_len < AMA_ED25519_SIGNATURE_BYTES) {
                return AMA_ERROR_VERIFY_FAILED;
            }
            return ama_ed25519_verify(signature, message, message_len,
                                      public_key);

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
