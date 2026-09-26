/* Copyright (C) 2025-2026 Steel Security Advisors LLC */
/* SPDX-License-Identifier: Apache-2.0 */
/**
 * @file ama_hmac_sha256.c
 * @brief Native HMAC-SHA-256 implementation (RFC 2104 / FIPS 198-1)
 * @author Andrew E. A., Steel Security Advisors LLC
 * @date 2026-04-06
 *
 * Replaces OpenSSL EVP_MAC(HMAC-SHA256) / HMAC_CTX calls in
 * ama_slhdsa.c sha2_PRF_msg() for zero-dependency SLH-DSA/SPHINCS+ operation.
 *
 * Construction: HMAC(K, m) = SHA-256((K' XOR opad) || SHA-256((K' XOR ipad) || m))
 * Where K' = key padded to SHA-256 block size (64 bytes).
 * If key > 64 bytes, K' = SHA-256(key) zero-padded to 64 bytes.
 */

#include "ama_hmac_sha256.h"
#include "ama_sha256.h"
#include <stdlib.h>
#include <string.h>

/* Scrub sensitive stack data */
extern void ama_secure_memzero(void *ptr, size_t len);

/**
 * Whether the caller's arguments can be dereferenced as described.
 *
 * Both entry points are `void`, and both are exported and ctypes-facing, so
 * a downstream binding that gets a length wrong hands this code a NULL with a
 * non-zero length and the SHA-256 kernel dereferences it.  The 2026-09 audit
 * reached a SIGSEGV that way (C-5).
 *
 * A `void` function cannot report a caller bug, and the return type is not
 * changed here because eighteen internal call sites pass stack arrays and
 * would gain a return value nobody could act on.  The one place an error can
 * actually be reported is the Python boundary, and `native_hmac_sha256` /
 * `native_hmac_sha256_2` reject these arguments before they arrive.
 *
 * Everywhere else a refusal must neither dereference nor RETURN, because
 * every value a MAC function can leave in `out` is a value some caller will
 * compare a received tag against.  The previous revision zeroed `out` and
 * returned; 0^32 is a public constant, so a verifier whose expected-tag
 * computation hit this branch accepted the tag 00..00 for any message it was
 * handed (2026-09-24 review of PR #394, c-sym-core#1).  Filling `out` with
 * CSPRNG bytes instead is not available to this translation unit: it is in
 * the unconditional source list, and ama_platform_rand.c is linked only when
 * AMA_USE_NATIVE_PQC=ON.  So a contract violation ends the process with
 * abort(): fail-closed and defined, which is the outcome the 4.x releases
 * reached through the SIGSEGV, without the undefined behaviour.  abort() is
 * declared noreturn by every C library this builds against, so no path
 * falls through from the refusal into the dereference.
 */
static int hmac_args_are_dereferenceable(const uint8_t *key, size_t key_len,
                                          const uint8_t *data, size_t data_len) {
    if (!key && key_len > 0) {
        return 0;
    }
    if (!data && data_len > 0) {
        return 0;
    }
    return 1;
}

void ama_hmac_sha256(const uint8_t *key, size_t key_len,
                      const uint8_t *data, size_t data_len,
                      uint8_t out[32]) {
    uint8_t k_prime[AMA_SHA256_BLOCK_SIZE];
    uint8_t ipad[AMA_SHA256_BLOCK_SIZE];
    uint8_t opad[AMA_SHA256_BLOCK_SIZE];
    uint8_t inner_hash[AMA_SHA256_DIGEST_SIZE];
    ama_sha256_ctx ctx;
    unsigned int i;

    if (!out) {
        return;  /* nowhere to write; nothing else is safe to touch either */
    }
    if (!hmac_args_are_dereferenceable(key, key_len, data, data_len)) {
        abort();  /* never returns a tag for a call it could not compute */
    }

    /* Step 1: Derive K' from key.  `k_prime` will hold the HMAC key
     * (possibly truncated via SHA-256) for the lifetime of the call —
     * use the secure scrub primitive on the initial zero pad so the
     * whole buffer lifecycle stays in the same scrub class as the
     * exit scrub below (INVARIANT-6). */
    ama_secure_memzero(k_prime, AMA_SHA256_BLOCK_SIZE);
    if (key_len > AMA_SHA256_BLOCK_SIZE) {
        /* Key longer than block size: K' = SHA-256(key), zero-padded */
        ama_sha256(k_prime, key, key_len);
    } else {
        /* Key fits in block: K' = key, zero-padded.  A zero-length key
         * (RFC 2104 permits it; callers may pass NULL for it) must not
         * reach memcpy: memcpy(dst, NULL, 0) is undefined behaviour and
         * a UBSan/ASan trap. */
        if (key_len > 0) {
            memcpy(k_prime, key, key_len);
        }
    }

    /* Step 2: Compute ipad and opad */
    for (i = 0; i < AMA_SHA256_BLOCK_SIZE; i++) {
        ipad[i] = k_prime[i] ^ 0x36;
        opad[i] = k_prime[i] ^ 0x5c;
    }

    /* Step 3: Inner hash = SHA-256(ipad || data) */
    ama_sha256_init(&ctx);
    ama_sha256_update(&ctx, ipad, AMA_SHA256_BLOCK_SIZE);
    ama_sha256_update(&ctx, data, data_len);
    ama_sha256_final(&ctx, inner_hash);

    /* Step 4: Outer hash = SHA-256(opad || inner_hash) */
    ama_sha256_init(&ctx);
    ama_sha256_update(&ctx, opad, AMA_SHA256_BLOCK_SIZE);
    ama_sha256_update(&ctx, inner_hash, AMA_SHA256_DIGEST_SIZE);
    ama_sha256_final(&ctx, out);

    /* Scrub key material from stack */
    ama_secure_memzero(k_prime, sizeof(k_prime));
    ama_secure_memzero(ipad, sizeof(ipad));
    ama_secure_memzero(opad, sizeof(opad));
    ama_secure_memzero(inner_hash, sizeof(inner_hash));
}

void ama_hmac_sha256_2(const uint8_t *key, size_t key_len,
                        const uint8_t *data1, size_t data1_len,
                        const uint8_t *data2, size_t data2_len,
                        uint8_t out[32]) {
    uint8_t k_prime[AMA_SHA256_BLOCK_SIZE];
    uint8_t ipad[AMA_SHA256_BLOCK_SIZE];
    uint8_t opad[AMA_SHA256_BLOCK_SIZE];
    uint8_t inner_hash[AMA_SHA256_DIGEST_SIZE];
    ama_sha256_ctx ctx;
    unsigned int i;

    if (!out) {
        return;
    }
    if (!hmac_args_are_dereferenceable(key, key_len, data1, data1_len) ||
        !hmac_args_are_dereferenceable(key, key_len, data2, data2_len)) {
        abort();  /* never returns a tag for a call it could not compute */
    }

    /* Derive K' — see ama_hmac_sha256() for INVARIANT-6 rationale. */
    ama_secure_memzero(k_prime, AMA_SHA256_BLOCK_SIZE);
    if (key_len > AMA_SHA256_BLOCK_SIZE) {
        ama_sha256(k_prime, key, key_len);
    } else if (key_len > 0) {
        memcpy(k_prime, key, key_len);
    }

    for (i = 0; i < AMA_SHA256_BLOCK_SIZE; i++) {
        ipad[i] = k_prime[i] ^ 0x36;
        opad[i] = k_prime[i] ^ 0x5c;
    }

    /* Inner hash = SHA-256(ipad || data1 || data2) */
    ama_sha256_init(&ctx);
    ama_sha256_update(&ctx, ipad, AMA_SHA256_BLOCK_SIZE);
    ama_sha256_update(&ctx, data1, data1_len);
    ama_sha256_update(&ctx, data2, data2_len);
    ama_sha256_final(&ctx, inner_hash);

    /* Outer hash */
    ama_sha256_init(&ctx);
    ama_sha256_update(&ctx, opad, AMA_SHA256_BLOCK_SIZE);
    ama_sha256_update(&ctx, inner_hash, AMA_SHA256_DIGEST_SIZE);
    ama_sha256_final(&ctx, out);

    ama_secure_memzero(k_prime, sizeof(k_prime));
    ama_secure_memzero(ipad, sizeof(ipad));
    ama_secure_memzero(opad, sizeof(opad));
    ama_secure_memzero(inner_hash, sizeof(inner_hash));
}
