/* Copyright (C) 2025-2026 Steel Security Advisors LLC */
/* SPDX-License-Identifier: Apache-2.0 */
/**
 * @file test_hybrid_sig.c
 * @brief AMA_ALG_HYBRID is Ed25519 + ML-DSA-65 with domain separation (v2).
 *
 * Pins: the sizes the context API reports; keypair / sign / verify round
 * trip; a tampered message, a tampered Ed25519 half and a tampered ML-DSA
 * half each fail; each half verifies standalone ONLY over its domain-bound
 * input (the Ed25519 half against 0x00 || len || domain || M, the ML-DSA half
 * with the domain as context) and NOT over the raw message; the raw-message
 * standalone signatures cannot be spliced in.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "ama_cryptography.h"

static int checks = 0, failures = 0;
#define CHECK(cond, msg) do { checks++; if (!(cond)) { failures++; fprintf(stderr, "FAIL: %s (%s:%d)\n", msg, __FILE__, __LINE__); } } while (0)

static const char DOMAIN[] = AMA_HYBRID_SIG_DOMAIN;

int main(void) {
    ama_context_t *ctx = ama_context_init(AMA_ALG_HYBRID);
    static uint8_t pk[AMA_HYBRID_PUBLIC_KEY_BYTES], sk[AMA_HYBRID_SECRET_KEY_BYTES];
    static uint8_t sig[AMA_HYBRID_SIGNATURE_BYTES], sig2[AMA_HYBRID_SIGNATURE_BYTES];
    static uint8_t wrapped[2 + sizeof(DOMAIN) - 1 + 64];
    static uint8_t ed_sig[64], pq_sig[AMA_ML_DSA_65_SIGNATURE_BYTES];
    const uint8_t message[64] = "hybrid v2: Ed25519 + ML-DSA-65 over the domain-bound message";
    size_t sig_len = sizeof sig, pq_len = sizeof pq_sig, wlen;
    size_t dlen = sizeof(DOMAIN) - 1;

    CHECK(ctx != NULL, "context for AMA_ALG_HYBRID");
    if (!ctx) return 1;
    CHECK(AMA_HYBRID_PUBLIC_KEY_BYTES == 32 + 1952, "public key size");
    CHECK(AMA_HYBRID_SECRET_KEY_BYTES == 64 + 4032, "secret key size");
    CHECK(AMA_HYBRID_SIGNATURE_BYTES == 64 + 3309, "signature size");
    CHECK(dlen <= 255, "domain fits the FIPS 204 ctx length");

    CHECK(ama_keypair_generate(ctx, pk, sizeof pk, sk, sizeof sk) == AMA_SUCCESS, "keypair");
    /* Ed25519 convention: sk[32..63] holds the public key. */
    CHECK(memcmp(sk + 32, pk, 32) == 0, "Ed25519 half of sk carries its public key");

    CHECK(ama_sign(ctx, message, sizeof message, sk, sizeof sk, sig, &sig_len) == AMA_SUCCESS, "sign");
    CHECK(sig_len == AMA_HYBRID_SIGNATURE_BYTES, "sign reports the full length");
    CHECK(ama_verify(ctx, message, sizeof message, sig, sig_len, pk, sizeof pk) == AMA_SUCCESS, "verify");

    /* Deterministic: both components are deterministic signers. */
    sig_len = sizeof sig2;
    CHECK(ama_sign(ctx, message, sizeof message, sk, sizeof sk, sig2, &sig_len) == AMA_SUCCESS, "sign again");
    CHECK(memcmp(sig, sig2, sizeof sig) == 0, "hybrid signature is deterministic");

    /* Tampering. */
    {
        uint8_t m2[64]; memcpy(m2, message, 64); m2[3] ^= 1;
        CHECK(ama_verify(ctx, m2, sizeof m2, sig, sizeof sig, pk, sizeof pk) == AMA_ERROR_VERIFY_FAILED, "tampered message");
        memcpy(sig2, sig, sizeof sig); sig2[5] ^= 1;
        CHECK(ama_verify(ctx, message, sizeof message, sig2, sizeof sig2, pk, sizeof pk) == AMA_ERROR_VERIFY_FAILED, "tampered Ed25519 half");
        memcpy(sig2, sig, sizeof sig); sig2[64 + 100] ^= 1;
        CHECK(ama_verify(ctx, message, sizeof message, sig2, sizeof sig2, pk, sizeof pk) == AMA_ERROR_VERIFY_FAILED, "tampered ML-DSA half");
        CHECK(ama_verify(ctx, message, sizeof message, sig, sizeof sig - 1, pk, sizeof pk) == AMA_ERROR_VERIFY_FAILED, "short signature");
    }

    /* Domain binding of each half. */
    wrapped[0] = 0x00; wrapped[1] = (uint8_t)dlen; memcpy(wrapped + 2, DOMAIN, dlen);
    memcpy(wrapped + 2 + dlen, message, sizeof message);
    wlen = 2 + dlen + sizeof message;
    CHECK(ama_ed25519_verify(sig, wrapped, wlen, pk) == AMA_SUCCESS, "Ed25519 half verifies over the wrapped input");
    CHECK(ama_ed25519_verify(sig, message, sizeof message, pk) != AMA_SUCCESS, "Ed25519 half is not a signature over the raw message");
    CHECK(ama_dilithium_verify_ctx(message, sizeof message, (const uint8_t *)DOMAIN, dlen,
                                   sig + 64, sizeof sig - 64, pk + 32) == AMA_SUCCESS,
          "ML-DSA half verifies with the domain as context");
    CHECK(ama_dilithium_verify(message, sizeof message, sig + 64, sizeof sig - 64, pk + 32) != AMA_SUCCESS,
          "ML-DSA half is not a signature over the raw message");

    /* Splicing standalone signatures over the raw message in. */
    CHECK(ama_ed25519_sign(ed_sig, message, sizeof message, sk) == AMA_SUCCESS, "standalone Ed25519 sign");
    memcpy(sig2, ed_sig, 64); memcpy(sig2 + 64, sig + 64, sizeof sig - 64);
    CHECK(ama_verify(ctx, message, sizeof message, sig2, sizeof sig2, pk, sizeof pk) == AMA_ERROR_VERIFY_FAILED, "spliced standalone Ed25519");
    CHECK(ama_dilithium_sign(pq_sig, &pq_len, message, sizeof message, sk + 64) == AMA_SUCCESS, "standalone ML-DSA sign");
    memcpy(sig2, sig, 64); memcpy(sig2 + 64, pq_sig, pq_len);
    CHECK(ama_verify(ctx, message, sizeof message, sig2, sizeof sig2, pk, sizeof pk) == AMA_ERROR_VERIFY_FAILED, "spliced standalone ML-DSA");

    /* Capacity checks. */
    sig_len = 100;
    CHECK(ama_sign(ctx, message, sizeof message, sk, sizeof sk, sig2, &sig_len) == AMA_ERROR_INVALID_PARAM, "undersized signature buffer");
    CHECK(sig_len == AMA_HYBRID_SIGNATURE_BYTES, "required length reported");
    CHECK(ama_keypair_generate(ctx, pk, 32, sk, sizeof sk) != AMA_SUCCESS, "undersized public key buffer refused");

    ama_context_free(ctx);
    printf("%d checks, %d failures\n", checks, failures);
    return failures ? 1 : 0;
}
