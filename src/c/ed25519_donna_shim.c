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

    /* AMA convention: caller provides the 32-byte seed in secret_key[0..31].
     * The Python wrapper (native_ed25519_keypair) fills these bytes with
     * cryptographic randomness before calling us, and
     * native_ed25519_keypair_from_seed loads a deterministic seed.
     * We must NOT overwrite secret_key[0..31] here. */

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

/* ============================================================================
 * BATCH VERIFICATION — donna Bos-Carter multi-scalar multiplication
 *
 * donna's ed25519_sign_open_batch() uses a binary heap for multi-scalar
 * multiplication (Bos-Carter method), supporting up to 64 signatures per
 * batch for ~2.5x throughput vs sequential verify.
 *
 * donna's API expects separate arrays of pointers:
 *   const unsigned char **m     — messages
 *   size_t              *mlen   — message lengths
 *   const unsigned char **pk    — 32-byte public keys
 *   const unsigned char **RS    — 64-byte signatures (R || S)
 *   size_t               num    — number of entries
 *   int                 *valid  — per-entry result (1=valid, 0=invalid)
 *
 * We convert from AMA's ama_ed25519_batch_entry struct array.
 * ============================================================================ */

ama_error_t ama_ed25519_batch_verify(
    const ama_ed25519_batch_entry *entries,
    size_t count,
    int *results
) {
    if (!entries || !results) {
        return AMA_ERROR_INVALID_PARAM;
    }
    if (count == 0) {
        return AMA_SUCCESS;
    }

    /* SECURITY FIX: Guard against integer overflow in ALL allocation sizes.
     * Each malloc below uses count * sizeof(...); validate each size so no
     * allocation can wrap to a smaller-than-expected buffer (audit C-MEM-1). */
    if (count > SIZE_MAX / sizeof(const unsigned char *) ||
        count > SIZE_MAX / sizeof(size_t)) {
        return AMA_ERROR_INVALID_PARAM;
    }

    /* Allocate pointer arrays for donna's batch verify interface */
    const unsigned char **msgs = (const unsigned char **)malloc(count * sizeof(const unsigned char *));
    size_t *mlens = (size_t *)malloc(count * sizeof(size_t));
    const unsigned char **pks = (const unsigned char **)malloc(count * sizeof(const unsigned char *));
    const unsigned char **sigs = (const unsigned char **)malloc(count * sizeof(const unsigned char *));

    if (!msgs || !mlens || !pks || !sigs) {
        free(msgs);
        free(mlens);
        free(pks);
        free(sigs);
        return AMA_ERROR_MEMORY;
    }

    /* Convert ama_ed25519_batch_entry structs to donna's separate arrays */
    for (size_t i = 0; i < count; i++) {
        msgs[i] = entries[i].message;
        mlens[i] = entries[i].message_len;
        pks[i] = entries[i].public_key;
        sigs[i] = entries[i].signature;
    }

    /* donna's batch verify: returns 0 if all valid, nonzero otherwise.
     * Per-entry results are written to the valid[] array (1=valid, 0=invalid). */
    int ret = ed25519_sign_open_batch(msgs, mlens, pks, sigs, count, results);

    free(msgs);
    free(mlens);
    free(pks);
    free(sigs);

    /* Map donna's return: 0 = all valid, nonzero = at least one invalid */
    return (ret == 0) ? AMA_SUCCESS : AMA_ERROR_VERIFY_FAILED;
}

/* ============================================================================
 * FROST PRIMITIVES — Ed25519 group operations via donna internals
 *
 * donna provides: ge25519_scalarmult_base_niels, ge25519_pack,
 * ge25519_unpack_negative_vartime, expand256_modm, contract256_modm,
 * mul256_modm, add256_modm, ed25519_hash (SHA-512).
 * ============================================================================ */

AMA_API void ama_ed25519_point_from_scalar(uint8_t point[32],
                                           const uint8_t scalar[32]) {
    bignum256modm s;
    ge25519 ALIGN(16) R;
    expand256_modm(s, scalar, 32);
    ge25519_scalarmult_base_niels(&R, ge25519_niels_base_multiples, s);
    ge25519_pack(point, &R);
}

AMA_API ama_error_t ama_ed25519_point_add(uint8_t result[32],
                                          const uint8_t p[32],
                                          const uint8_t q[32]) {
    ge25519 ALIGN(16) P, Q, R;
    /* donna's unpack negates Y; we negate back */
    if (!ge25519_unpack_negative_vartime(&P, p)) return AMA_ERROR_INVALID_PARAM;
    curve25519_neg(P.x, P.x);
    curve25519_neg(P.t, P.t);
    if (!ge25519_unpack_negative_vartime(&Q, q)) return AMA_ERROR_INVALID_PARAM;
    curve25519_neg(Q.x, Q.x);
    curve25519_neg(Q.t, Q.t);

    ge25519_p1p1 ALIGN(16) r_p1p1;
    ge25519_add_p1p1(&r_p1p1, &P, &Q);
    ge25519_p1p1_to_full(&R, &r_p1p1);
    ge25519_pack(result, &R);
    return AMA_SUCCESS;
}

/* Renamed from ama_ed25519_scalar_mult (audit finding C7).
 * NOT constant-time — public_scalar MUST be non-secret. */
AMA_API ama_error_t ama_ed25519_scalarmult_public(uint8_t result[32],
                                                  const uint8_t public_scalar[32],
                                                  const uint8_t point[32]) {
    ge25519 ALIGN(16) P, R;
    bignum256modm s1, s2_zero = {0};
    if (!ge25519_unpack_negative_vartime(&P, point)) return AMA_ERROR_INVALID_PARAM;
    curve25519_neg(P.x, P.x);
    curve25519_neg(P.t, P.t);
    expand256_modm(s1, public_scalar, 32);
    /* r = s1*P + 0*G via donna's double-scalar mult */
    ge25519_double_scalarmult_vartime(&R, &P, s1, s2_zero);
    ge25519_pack(result, &R);
    return AMA_SUCCESS;
}

AMA_API void ama_ed25519_sc_reduce(uint8_t s[64]) {
    bignum256modm m;
    expand256_modm(m, s, 64);
    contract256_modm(s, m);
}

AMA_API void ama_ed25519_sc_muladd(uint8_t out[32],
                                   const uint8_t a[32],
                                   const uint8_t b[32],
                                   const uint8_t c[32]) {
    /* out = a + b*c mod l */
    bignum256modm ma, mb, mc, mr;
    expand256_modm(ma, a, 32);
    expand256_modm(mb, b, 32);
    expand256_modm(mc, c, 32);
    mul256_modm(mr, mb, mc);     /* mr = b*c */
    add256_modm(mr, ma, mr);     /* mr = a + b*c */
    contract256_modm(out, mr);
}

AMA_API void ama_ed25519_sha512(const uint8_t *data, size_t len,
                                uint8_t out[64]) {
    ed25519_hash(out, data, len);
}
