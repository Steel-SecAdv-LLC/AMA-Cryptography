/**
 * Copyright 2025-2026 Steel Security Advisors LLC
 * Licensed under the Apache License, Version 2.0
 *
 * @file ed25519_donna_shim.c
 * @brief AMA API shim for ed25519-donna (public domain, Andrew Moon)
 *
 * Compiles ed25519-donna as a single translation unit with AMA's public API.
 * Uses donna's built-in reference SHA-512 and AMA's platform CSPRNG.
 *
 * Field representation: donna's 64-bit path uses radix 2^51 (5 x uint64_t),
 * the same family as AMA's fe51.h. However, donna's scalar multiplication
 * is self-contained — it uses its own field ops, group ops, and precomputed
 * Niels basepoint table internally. On x86-64 with GCC, donna activates
 * inline assembly for constant-time table selection
 * (ed25519-donna-64bit-x86.h).
 *
 * This shim replaces ama_ed25519.c when AMA_ED25519_ASSEMBLY is enabled.
 */

#include "../include/ama_cryptography.h"
#include <string.h>
#include <stdlib.h>

/* --- donna compilation flags ---
 * ED25519_REFHASH: use donna's built-in SHA-512 (no OpenSSL dependency)
 * ED25519_CUSTOMRANDOM: we provide ed25519_randombytes_unsafe below
 */
#define ED25519_REFHASH
#define ED25519_CUSTOMRANDOM

/* Provide randombytes for donna's batch verification (not used by sign/verify
 * but needed to compile). Backed by AMA's platform CSPRNG. */
#include "ama_platform_rand.h"

static void
ed25519_randombytes_unsafe(void *p, size_t len) {
    ama_randombytes((uint8_t *)p, len);
}

/* Suppress -Wmissing-prototypes for donna's static functions */
#if defined(__GNUC__) || defined(__clang__)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wmissing-prototypes"
#pragma GCC diagnostic ignored "-Wstrict-prototypes"
#pragma GCC diagnostic ignored "-Wunused-function"
#endif

/* Include donna's single-file compilation unit */
#include "vendor/ed25519-donna/ed25519.c"

#if defined(__GNUC__) || defined(__clang__)
#pragma GCC diagnostic pop
#endif

/* ============================================================================
 * AMA API WRAPPERS
 *
 * donna's API:
 *   ed25519_publickey(sk_32byte, pk_32byte)
 *   ed25519_sign(msg, msglen, sk_32byte, pk_32byte, sig_64byte)
 *   ed25519_sign_open(msg, msglen, pk_32byte, sig_64byte) -> 0 ok, -1 fail
 *
 * AMA's API:
 *   ama_ed25519_keypair(pk_32byte, sk_64byte)     // sk = seed || pk
 *   ama_ed25519_sign(sig, msg, msglen, sk_64byte)
 *   ama_ed25519_verify(sig, msg, msglen, pk_32byte)
 * ============================================================================ */

ama_error_t ama_ed25519_keypair(uint8_t public_key[32], uint8_t secret_key[64]) {
    if (!public_key || !secret_key) {
        return AMA_ERROR_INVALID_PARAM;
    }

    /* Generate a 32-byte cryptographic random seed into the first half. */
    ama_randombytes(secret_key, 32);

    /* Derive the public key from the seed. */
    ed25519_publickey(secret_key, public_key);

    /* AMA convention: secret_key = seed[0..31] || public_key[32..63] */
    memcpy(secret_key + 32, public_key, 32);

    return AMA_SUCCESS;
}

ama_error_t ama_ed25519_sign(
    uint8_t signature[64],
    const uint8_t *message,
    size_t message_len,
    const uint8_t secret_key[64]
) {
    if (!signature || !secret_key || (!message && message_len > 0)) {
        return AMA_ERROR_INVALID_PARAM;
    }

    /* donna: ed25519_sign(msg, msglen, sk_32, pk_32, sig_out) */
    ed25519_sign(message, message_len,
                 secret_key,        /* 32-byte seed */
                 secret_key + 32,   /* 32-byte public key */
                 signature);

    return AMA_SUCCESS;
}

ama_error_t ama_ed25519_verify(
    const uint8_t signature[64],
    const uint8_t *message,
    size_t message_len,
    const uint8_t public_key[32]
) {
    if (!signature || !public_key || (!message && message_len > 0)) {
        return AMA_ERROR_INVALID_PARAM;
    }

    /* donna returns 0 on success, -1 on failure */
    int result = ed25519_sign_open(message, message_len, public_key, signature);

    return (result == 0) ? AMA_SUCCESS : AMA_ERROR_VERIFY_FAILED;
}
