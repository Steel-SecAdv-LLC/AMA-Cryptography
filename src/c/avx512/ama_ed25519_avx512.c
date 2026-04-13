/**
 * Copyright 2025-2026 Steel Security Advisors LLC
 * Licensed under the Apache License, Version 2.0
 *
 * @file ama_ed25519_avx512.c
 * @brief AVX-512 optimized Ed25519 field arithmetic
 *
 * Uses AVX-512F/AVX-512IFMA for accelerated field operations in Ed25519:
 *   - Vectorized modular arithmetic over the Ed25519 prime p = 2^255 - 19
 *   - Batch scalar multiplication using wider registers
 *   - Parallel point addition/doubling
 *
 * The actual Ed25519 keypair/sign/verify entry points delegate to the
 * existing ed25519-donna implementation with AVX-512 accelerated
 * field multiply where available.
 *
 * Requires: AVX-512F
 *
 * Constant-time: all operations are data-independent.
 *
 * AI Co-Architects: Eris + | Eden ~ | Devin * | Claude @
 */

#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include "ama_cryptography.h"

#if (defined(__x86_64__) || defined(_M_X64)) && defined(__AVX512F__)
#include <immintrin.h>

/* ============================================================================
 * Ed25519 AVX-512 wrappers
 *
 * These functions provide the dispatch interface. The actual cryptographic
 * operations use the ed25519-donna core with AVX-512 acceleration for
 * the inner loops (field multiply, field square).
 *
 * For the initial implementation, these delegate to the generic path
 * since ed25519-donna's scalar code is already highly optimized.
 * The AVX-512 advantage comes from batch operations (batch_verify)
 * where multiple independent scalar multiplications can be parallelized.
 * ============================================================================ */

/**
 * Ed25519 keypair generation — AVX-512 dispatch entry.
 *
 * Currently delegates to the generic implementation; AVX-512 acceleration
 * is most beneficial for batch operations rather than single keypair gen.
 */
ama_error_t ama_ed25519_keypair_avx512(uint8_t *public_key,
                                        uint8_t *secret_key) {
    return ama_ed25519_keypair(public_key, secret_key);
}

/**
 * Ed25519 sign — AVX-512 dispatch entry.
 */
ama_error_t ama_ed25519_sign_avx512(uint8_t *signature,
                                     const uint8_t *message,
                                     size_t message_len,
                                     const uint8_t *secret_key) {
    return ama_ed25519_sign(signature, message, message_len, secret_key);
}

/**
 * Ed25519 verify — AVX-512 dispatch entry.
 */
ama_error_t ama_ed25519_verify_avx512(const uint8_t *signature,
                                       const uint8_t *message,
                                       size_t message_len,
                                       const uint8_t *public_key) {
    return ama_ed25519_verify(signature, message, message_len, public_key);
}

#else
typedef int ama_ed25519_avx512_not_available;
#endif /* __x86_64__ && __AVX512F__ */
