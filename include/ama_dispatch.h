/**
 * Copyright 2025-2026 Steel Security Advisors LLC
 * Licensed under the Apache License, Version 2.0
 *
 * @file ama_dispatch.h
 * @brief Runtime SIMD dispatch declarations
 *
 * Function pointer table for routing cryptographic inner loops to
 * SIMD-optimized implementations based on CPU feature detection.
 * Thread-safe initialization via platform once-primitives (INVARIANT-2).
 */

#ifndef AMA_DISPATCH_H
#define AMA_DISPATCH_H

#include "ama_cryptography.h"
#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Implementation level enum */
typedef enum {
    AMA_IMPL_GENERIC = 0,
    AMA_IMPL_AVX2    = 1,
    AMA_IMPL_AVX512  = 2,
    AMA_IMPL_NEON    = 3,
    AMA_IMPL_SVE2    = 4,
} ama_impl_level_t;

/* Dispatch info (read-only after init) */
typedef struct {
    ama_impl_level_t sha3;
    ama_impl_level_t kyber;
    ama_impl_level_t dilithium;
    ama_impl_level_t sphincs;
    ama_impl_level_t aes_gcm;
    ama_impl_level_t ed25519;
    ama_impl_level_t chacha20poly1305;
    ama_impl_level_t argon2;
    const char *arch_name;
} ama_dispatch_info_t;

/* ============================================================================
 * Function pointer types for dispatchable operations
 * ============================================================================ */

/** Keccak-f[1600] permutation (24 rounds on 25 x uint64_t state) */
typedef void (*ama_keccak_f1600_fn)(uint64_t state[25]);

/** SHA3-256: full hash (input, len) -> output[32] */
typedef ama_error_t (*ama_sha3_256_fn)(const uint8_t *input, size_t input_len,
                                        uint8_t output[32]);

/** Kyber NTT forward transform */
typedef void (*ama_kyber_ntt_fn)(int16_t poly[256], const int16_t zetas[128]);

/** Kyber polynomial pointwise multiply (basemul in Z_q[X]/(X^2-zeta)) */
typedef void (*ama_kyber_pointwise_fn)(int16_t r[256],
                                       const int16_t a[256],
                                       const int16_t b[256],
                                       const int16_t zetas[128]);

/** Dilithium NTT forward transform */
typedef void (*ama_dilithium_ntt_fn)(int32_t poly[256],
                                     const int32_t zetas[256]);

/** Dilithium inverse NTT */
typedef void (*ama_dilithium_invntt_fn)(int32_t poly[256],
                                        const int32_t zetas[256]);

/** Dilithium polynomial pointwise multiply */
typedef void (*ama_dilithium_pointwise_fn)(int32_t r[256],
                                           const int32_t a[256],
                                           const int32_t b[256]);

/** Ed25519 keypair generation */
typedef ama_error_t (*ama_ed25519_keypair_fn)(uint8_t public_key[32],
                                              uint8_t secret_key[64]);

/** Ed25519 signing */
typedef ama_error_t (*ama_ed25519_sign_fn)(uint8_t signature[64],
                                            const uint8_t *message,
                                            size_t message_len,
                                            const uint8_t secret_key[64]);

/** Ed25519 signature verification */
typedef ama_error_t (*ama_ed25519_verify_fn)(const uint8_t signature[64],
                                              const uint8_t *message,
                                              size_t message_len,
                                              const uint8_t public_key[32]);

/* ============================================================================
 * Dispatch function table (global, set once at init)
 *
 * After ama_dispatch_init(), function pointers are either:
 *   - Non-NULL: points to the optimal implementation (SIMD or generic).
 *     Guaranteed non-NULL: keccak_f1600.
 *     Wired when SIMD detected: sha3_256, kyber_ntt, kyber_invntt,
 *     kyber_pointwise, dilithium_ntt, dilithium_invntt,
 *     dilithium_pointwise (AVX2 and NEON; SVE2 wires keccak_f1600,
 *     kyber_*, and dilithium_* but not sha3_256).
 *   - NULL: no dispatch available; caller must use its own inline generic
 *     implementation.
 *
 * Callers MUST NULL-check before calling any field except keccak_f1600.
 * ============================================================================ */

typedef struct {
    ama_keccak_f1600_fn       keccak_f1600;        /**< Always non-NULL after init */
    ama_sha3_256_fn           sha3_256;             /**< Non-NULL when SIMD detected; callers MUST NULL-check */
    ama_kyber_ntt_fn          kyber_ntt;            /**< Non-NULL when SIMD detected; callers MUST NULL-check */
    ama_kyber_ntt_fn          kyber_invntt;         /**< Non-NULL when SIMD detected; callers MUST NULL-check */
    ama_kyber_pointwise_fn    kyber_pointwise;      /**< Non-NULL when SIMD detected; callers MUST NULL-check */
    ama_dilithium_ntt_fn      dilithium_ntt;        /**< Non-NULL when SIMD detected; callers MUST NULL-check */
    ama_dilithium_invntt_fn   dilithium_invntt;     /**< Non-NULL when SIMD detected; callers MUST NULL-check */
    ama_dilithium_pointwise_fn dilithium_pointwise; /**< Non-NULL when SIMD detected; callers MUST NULL-check */
    ama_ed25519_keypair_fn    ed25519_keypair;      /**< Non-NULL when AVX2 detected; callers MUST NULL-check */
    ama_ed25519_sign_fn       ed25519_sign;          /**< Non-NULL when AVX2 detected; callers MUST NULL-check */
    ama_ed25519_verify_fn     ed25519_verify;        /**< Non-NULL when AVX2 detected; callers MUST NULL-check */
} ama_dispatch_table_t;

/* ============================================================================
 * Public API
 * ============================================================================ */

/** Initialize dispatch (thread-safe, idempotent). */
AMA_API void ama_dispatch_init(void);

/** Get dispatch info (detection results). */
AMA_API const ama_dispatch_info_t *ama_get_dispatch_info(void);

/** Get the dispatch function table. Calls ama_dispatch_init() if needed. */
AMA_API const ama_dispatch_table_t *ama_get_dispatch_table(void);

/** Print dispatch info to stderr (diagnostics). */
AMA_API void ama_print_dispatch_info(void);

/** Implementation level name string. */
AMA_API const char *ama_impl_level_name(ama_impl_level_t level);

#ifdef __cplusplus
}
#endif

#endif /* AMA_DISPATCH_H */
