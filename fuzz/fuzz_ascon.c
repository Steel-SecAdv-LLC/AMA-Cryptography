/* Copyright (C) 2025-2026 Steel Security Advisors LLC */
/* SPDX-License-Identifier: Apache-2.0 */
/**
 * @file fuzz_ascon.c
 * @brief libFuzzer harness for Ascon-AEAD128 and Ascon-Hash256
 *
 * This target asserts *security properties*, not merely the absence of
 * crashes.  A harness that only calls the API and returns finds memory-safety
 * bugs; it cannot find a construction that is memory-safe and wrong.  Every
 * abort() below marks a property that must hold for arbitrary inputs:
 *
 *   1. Round-trip fidelity.  decrypt(encrypt(P)) == P for every input, at
 *      every length — including the empty message and every offset around the
 *      128-bit AEAD rate and 64-bit hash rate boundaries.
 *   2. Tag forgery rejection.  Flipping any bit of the tag must produce
 *      AMA_ERROR_VERIFY_FAILED.
 *   3. Associated-data binding.  Altering, truncating or dropping the AD must
 *      invalidate the tag.  Dropping it entirely is called out separately
 *      because it is the case the |A| > 0 guard in the absorb phase controls:
 *      an implementation that absorbed a padding block for empty AD would
 *      round-trip fine and produce non-standard tags forever.
 *   4. Fail-closed decryption.  A rejected decryption must not write into the
 *      caller's plaintext buffer.  The harness fills it with a sentinel and
 *      verifies every byte survives.
 *   5. Nonce and key binding.  Changing either must invalidate the tag.
 *   6. Hash determinism and length.  Ascon-Hash256 must be a pure function of
 *      its input and always produce 32 bytes.
 *
 * Ascon is a *core* target: it depends on no other primitive in this library,
 * so it builds and fuzzes under AMA_USE_NATIVE_PQC=OFF as well as the default
 * configuration.
 */

#include "../include/ama_cryptography.h"
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_BODY 4096

static void fail(const char *why) {
    /* Write the reason before aborting so the crash artifact is
     * self-describing rather than just a stack trace. */
    fprintf(stderr, "ASCON PROPERTY VIOLATION: %s\n", why);
    abort();
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    /* Layout: key[16] || nonce[16] || split || body.
     * `split` divides the body between associated data and plaintext, so the
     * fuzzer explores both length axes with one input. */
    if (size < 33) {
        return 0;
    }

    const uint8_t *key = data;
    const uint8_t *nonce = data + 16;
    const size_t body_len_raw = size - 33;
    const size_t body_len = body_len_raw > MAX_BODY ? MAX_BODY : body_len_raw;
    const uint8_t *body = data + 33;

    const size_t split = body_len ? ((size_t)data[32] % (body_len + 1)) : 0;
    const uint8_t *aad = body;
    const size_t aad_len = split;
    const uint8_t *pt = body + split;
    const size_t pt_len = body_len - split;

    uint8_t *ct = (uint8_t *)malloc(pt_len ? pt_len : 1);
    uint8_t *out = (uint8_t *)malloc(pt_len ? pt_len : 1);
    uint8_t tag[AMA_ASCON_AEAD128_TAG_LEN];
    if (ct == NULL || out == NULL) {
        free(ct);
        free(out);
        return 0;
    }

    if (ama_ascon_aead128_encrypt(key, nonce, pt, pt_len, aad, aad_len,
                                  ct, tag) != AMA_SUCCESS) {
        fail("encrypt rejected a well-formed input");
    }

    /* 1. Round-trip fidelity. */
    if (ama_ascon_aead128_decrypt(key, nonce, ct, pt_len, aad, aad_len,
                                  tag, out) != AMA_SUCCESS) {
        fail("decrypt rejected its own ciphertext");
    }
    if (pt_len != 0 && memcmp(out, pt, pt_len) != 0) {
        fail("round-trip did not recover the plaintext");
    }

    /* 2. Tag forgery rejection + 4. fail-closed, checked together. */
    {
        uint8_t forged[AMA_ASCON_AEAD128_TAG_LEN];
        const unsigned bit = (unsigned)(data[32] & 0x7Fu);
        memcpy(forged, tag, sizeof forged);
        forged[(bit >> 3) % AMA_ASCON_AEAD128_TAG_LEN] ^=
            (uint8_t)(1u << (bit & 7u));

        memset(out, 0xA5, pt_len ? pt_len : 1);
        if (ama_ascon_aead128_decrypt(key, nonce, ct, pt_len, aad, aad_len,
                                      forged, out) != AMA_ERROR_VERIFY_FAILED) {
            fail("a single-bit tag forgery was accepted");
        }
        for (size_t i = 0; i < pt_len; ++i) {
            if (out[i] != 0xA5) {
                fail("fail-closed violated: rejected decrypt wrote plaintext");
            }
        }
    }

    /* 3. Associated-data binding. */
    if (aad_len != 0) {
        uint8_t *bad_aad = (uint8_t *)malloc(aad_len);
        if (bad_aad != NULL) {
            memcpy(bad_aad, aad, aad_len);
            bad_aad[data[32] % aad_len] ^= 0x40;
            if (ama_ascon_aead128_decrypt(key, nonce, ct, pt_len,
                                          bad_aad, aad_len, tag,
                                          out) != AMA_ERROR_VERIFY_FAILED) {
                fail("tampered associated data was accepted");
            }
            free(bad_aad);
        }
        /* Truncation. */
        if (ama_ascon_aead128_decrypt(key, nonce, ct, pt_len, aad, aad_len - 1,
                                      tag, out) != AMA_ERROR_VERIFY_FAILED) {
            fail("truncated associated data was accepted");
        }
        /* Removal — the empty-AD guard. */
        if (ama_ascon_aead128_decrypt(key, nonce, ct, pt_len, NULL, 0,
                                      tag, out) != AMA_ERROR_VERIFY_FAILED) {
            fail("removing the associated data was accepted");
        }
    }

    /* 5. Nonce and key binding. */
    {
        uint8_t alt[16];
        memcpy(alt, nonce, 16);
        alt[data[32] % 16] ^= 0x01;
        if (ama_ascon_aead128_decrypt(key, alt, ct, pt_len, aad, aad_len,
                                      tag, out) != AMA_ERROR_VERIFY_FAILED) {
            fail("a modified nonce was accepted");
        }
        memcpy(alt, key, 16);
        alt[data[32] % 16] ^= 0x01;
        if (ama_ascon_aead128_decrypt(alt, nonce, ct, pt_len, aad, aad_len,
                                      tag, out) != AMA_ERROR_VERIFY_FAILED) {
            fail("a modified key was accepted");
        }
    }

    /* Ciphertext tampering, where there is any ciphertext to tamper with. */
    if (pt_len != 0) {
        ct[data[32] % pt_len] ^= 0x80;
        if (ama_ascon_aead128_decrypt(key, nonce, ct, pt_len, aad, aad_len,
                                      tag, out) != AMA_ERROR_VERIFY_FAILED) {
            fail("tampered ciphertext was accepted");
        }
    }

    /* 6. Hash determinism and length. */
    {
        uint8_t d1[AMA_ASCON_HASH256_DIGEST_LEN];
        uint8_t d2[AMA_ASCON_HASH256_DIGEST_LEN];
        if (ama_ascon_hash256(body, body_len, d1) != AMA_SUCCESS ||
            ama_ascon_hash256(body, body_len, d2) != AMA_SUCCESS) {
            fail("hash rejected a well-formed input");
        }
        if (memcmp(d1, d2, sizeof d1) != 0) {
            fail("Ascon-Hash256 is not deterministic");
        }
        /* Hashing one byte fewer must give a different digest — a length
         * -extension or padding defect shows up here immediately. */
        if (body_len > 0) {
            uint8_t d3[AMA_ASCON_HASH256_DIGEST_LEN];
            if (ama_ascon_hash256(body, body_len - 1, d3) != AMA_SUCCESS) {
                fail("hash rejected a shorter input");
            }
            if (memcmp(d1, d3, sizeof d1) == 0) {
                fail("Ascon-Hash256 collided on inputs of different length");
            }
        }
    }

    free(ct);
    free(out);
    return 0;
}
