/* Copyright (C) 2025-2026 Steel Security Advisors LLC */
/* SPDX-License-Identifier: Apache-2.0 */
/**
 * The expanded Ed25519 signing form: INVARIANT-51 verified at key load
 * =====================================================================
 *
 * ama_ed25519_expand_secret_key derives A = [a]B once and binds a, prefix
 * and A under a tag; ama_ed25519_sign_expanded re-checks the tag on every
 * signature instead of re-deriving A.  This suite establishes, on every
 * field backend the host carries:
 *
 *   1. Conformance.  The expanded path reproduces the RFC 8032 §7.1 vectors
 *      (TEST 1, 2, 3 and SHA(abc)) byte for byte, so it is Ed25519 and not
 *      merely consistent with itself.
 *   2. Equivalence.  For 32 keys and a message-length sweep that crosses the
 *      4 KiB stack threshold in ama_ed25519.c, the expanded path's bytes
 *      equal ama_ed25519_sign's, and ama_ed25519_verify accepts them.  The
 *      public key sits at AMA_ED25519_EXPANDED_PUBLIC_KEY_OFFSET.
 *   3. The property.  Every one of the 1,024 bits of an expanded key is
 *      flipped in turn: each flip is refused with AMA_ERROR_INVALID_PARAM
 *      and 64 zero signature bytes, and restoring the bit restores signing.
 *      A flipped bit is what a storage fault or a mis-copied record
 *      produces; the tag makes every such flip a refusal.
 *   4. Refusal at load.  A 64-byte key whose public half disagrees (single
 *      bit flips at five positions, another key's half, an all-zero half)
 *      is refused at expansion with 128 zero bytes, and that zero buffer is
 *      refused by the signer too, so a caller ignoring the return code
 *      still cannot sign.
 *   5. Contract edges: NULL arguments, a NULL message with a zero length,
 *      determinism.
 *
 * Every assertion is a comparison against an independent oracle (the RFC,
 * or the 64-byte path) or a refusal; a pinned constant of this path's own
 * would also pass against a signer returning a constant.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "ama_cryptography.h"

#define TEST_ASSERT(condition, message) \
    do { \
        if (!(condition)) { \
            fprintf(stderr, "FAIL: %s\n", message); \
            return 1; \
        } else { \
            printf("PASS: %s\n", message); \
        } \
    } while (0)

/* A quiet assert for loops: reports and returns only on failure. */
#define LOOP_ASSERT(condition, fmt, ...) \
    do { \
        if (!(condition)) { \
            fprintf(stderr, "FAIL: " fmt "\n", __VA_ARGS__); \
            return 1; \
        } \
    } while (0)

typedef struct {
    const char *name;
    const char *seed_hex;
    const char *pk_hex;
    const char *msg_hex;
    const char *sig_hex;
} rfc_vector_t;

/* RFC 8032 §7.1.  TEST 1024 is not embedded (1,023-byte message); the
 * length sweep in step 2 covers that size class against the 64-byte path. */
static const rfc_vector_t RFC8032[] = {
    {"TEST 1 (empty message)",
     "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
     "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
     "",
     "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155"
     "5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"},
    {"TEST 2 (one byte)",
     "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
     "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
     "72",
     "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da"
     "085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00"},
    {"TEST 3 (two bytes)",
     "c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7",
     "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025",
     "af82",
     "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac"
     "18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a"},
    {"TEST SHA(abc) (64 bytes)",
     "833fe62409237b9d62ec77587520911e9a759cec1d19755b7da901b96dca3d42",
     "ec172b93ad5e563bf4932c70e1245034c35467ef2efd4d64ebf819683467e2bf",
     "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a"
     "2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f",
     "dc2a4459e7369633a52b1bf277839a00201009a3efbf3ecb69bea2186c26b589"
     "09351fc9ac90b3ecfdfbc7c66431e0303dca179c138ac17ad9bef1177331a704"},
};

static int hexval(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

static size_t unhex(uint8_t *out, size_t cap, const char *hex) {
    size_t n = strlen(hex) / 2, i;
    if (n > cap) return (size_t)-1;
    for (i = 0; i < n; i++) {
        int hi = hexval(hex[2 * i]), lo = hexval(hex[2 * i + 1]);
        if (hi < 0 || lo < 0) return (size_t)-1;
        out[i] = (uint8_t)((hi << 4) | lo);
    }
    return n;
}

/* Deterministic, reproducible fill: a test that fails must fail again. */
static uint32_t prng_state = 0x243F6A88u;
static uint8_t prng_byte(void) {
    prng_state ^= prng_state << 13;
    prng_state ^= prng_state >> 17;
    prng_state ^= prng_state << 5;
    return (uint8_t)(prng_state >> 24);
}
static void prng_fill(uint8_t *buf, size_t len) {
    size_t i;
    for (i = 0; i < len; i++) buf[i] = prng_byte();
}

static int all_zero(const uint8_t *buf, size_t len) {
    uint8_t acc = 0;
    size_t i;
    for (i = 0; i < len; i++) acc = (uint8_t)(acc | buf[i]);
    return acc == 0;
}

static const size_t LENGTHS[] = {
    0, 1, 2, 31, 32, 33, 63, 64, 65, 127, 128, 255, 256, 1023, 1024,
    4095, 4096, 4097, 8192, 65536
};
#define N_LENGTHS (sizeof(LENGTHS) / sizeof(LENGTHS[0]))
#define MAX_MSG 65536u
#define N_KEYS 32u

static int run_suite(const char *backend_label) {
    uint8_t pk[32], sk[64], expanded[AMA_ED25519_EXPANDED_KEY_BYTES];
    uint8_t sig_a[64], sig_b[64];
    uint8_t *msg = (uint8_t *)malloc(MAX_MSG);
    size_t v, k, li;
    unsigned bit;

    printf("--- backend: %s ---\n", backend_label);
    if (!msg) {
        fprintf(stderr, "FAIL: malloc\n");
        return 1;
    }

    /* 1. RFC 8032 conformance through the expanded path. */
    for (v = 0; v < sizeof(RFC8032) / sizeof(RFC8032[0]); v++) {
        uint8_t exp_pk[32], exp_sig[64];
        size_t mlen = unhex(msg, MAX_MSG, RFC8032[v].msg_hex);
        LOOP_ASSERT(unhex(sk, 32, RFC8032[v].seed_hex) == 32, "%s: seed hex", RFC8032[v].name);
        LOOP_ASSERT(unhex(exp_pk, 32, RFC8032[v].pk_hex) == 32, "%s: pk hex", RFC8032[v].name);
        LOOP_ASSERT(unhex(exp_sig, 64, RFC8032[v].sig_hex) == 64, "%s: sig hex", RFC8032[v].name);
        LOOP_ASSERT(mlen != (size_t)-1, "%s: msg hex", RFC8032[v].name);
        LOOP_ASSERT(ama_ed25519_keypair(pk, sk) == AMA_SUCCESS, "%s: keypair", RFC8032[v].name);
        LOOP_ASSERT(memcmp(pk, exp_pk, 32) == 0, "%s: RFC public key", RFC8032[v].name);
        LOOP_ASSERT(ama_ed25519_expand_secret_key(expanded, sk) == AMA_SUCCESS,
                    "%s: expand", RFC8032[v].name);
        LOOP_ASSERT(memcmp(expanded + AMA_ED25519_EXPANDED_PUBLIC_KEY_OFFSET, exp_pk, 32) == 0,
                    "%s: expanded form carries the RFC public key", RFC8032[v].name);
        LOOP_ASSERT(ama_ed25519_sign_expanded(sig_a, mlen ? msg : NULL, mlen, expanded) == AMA_SUCCESS,
                    "%s: sign_expanded", RFC8032[v].name);
        LOOP_ASSERT(memcmp(sig_a, exp_sig, 64) == 0,
                    "%s: expanded path reproduces the RFC signature", RFC8032[v].name);
        printf("PASS: %s through the expanded path\n", RFC8032[v].name);
    }

    /* 2. Equivalence with the 64-byte path across keys and lengths. */
    for (k = 0; k < N_KEYS; k++) {
        prng_fill(sk, 32);
        LOOP_ASSERT(ama_ed25519_keypair(pk, sk) == AMA_SUCCESS, "key %zu: keypair", k);
        LOOP_ASSERT(ama_ed25519_expand_secret_key(expanded, sk) == AMA_SUCCESS, "key %zu: expand", k);
        LOOP_ASSERT(memcmp(expanded + AMA_ED25519_EXPANDED_PUBLIC_KEY_OFFSET, pk, 32) == 0,
                    "key %zu: public key at the documented offset", k);
        for (li = 0; li < N_LENGTHS; li++) {
            size_t mlen = LENGTHS[li];
            prng_fill(msg, mlen);
            LOOP_ASSERT(ama_ed25519_sign(sig_a, msg, mlen, sk) == AMA_SUCCESS,
                        "key %zu len %zu: sign", k, mlen);
            LOOP_ASSERT(ama_ed25519_sign_expanded(sig_b, msg, mlen, expanded) == AMA_SUCCESS,
                        "key %zu len %zu: sign_expanded", k, mlen);
            LOOP_ASSERT(memcmp(sig_a, sig_b, 64) == 0,
                        "key %zu len %zu: expanded path equals the 64-byte path", k, mlen);
            LOOP_ASSERT(ama_ed25519_verify(sig_b, msg, mlen, pk) == AMA_SUCCESS,
                        "key %zu len %zu: verify accepts the expanded-path signature", k, mlen);
        }
    }
    printf("PASS: %u keys x %zu lengths (0..65536, across the 4 KiB stack threshold): "
           "expanded == 64-byte path, all verified\n", N_KEYS, N_LENGTHS);

    /* 3. Every bit of the expanded key is load-bearing. */
    prng_fill(sk, 32);
    LOOP_ASSERT(ama_ed25519_keypair(pk, sk) == AMA_SUCCESS, "%s", "property key: keypair");
    LOOP_ASSERT(ama_ed25519_expand_secret_key(expanded, sk) == AMA_SUCCESS, "%s", "property key: expand");
    memcpy(msg, "expanded-key bit sweep", 22);
    LOOP_ASSERT(ama_ed25519_sign_expanded(sig_a, msg, 22, expanded) == AMA_SUCCESS, "%s", "property key: sign");
    for (bit = 0; bit < 8u * AMA_ED25519_EXPANDED_KEY_BYTES; bit++) {
        ama_error_t rc;
        expanded[bit / 8] ^= (uint8_t)(1u << (bit % 8));
        memset(sig_b, 0xA5, 64);
        rc = ama_ed25519_sign_expanded(sig_b, msg, 22, expanded);
        LOOP_ASSERT(rc == AMA_ERROR_INVALID_PARAM, "bit %u flipped: expected refusal, rc=%d", bit, (int)rc);
        LOOP_ASSERT(all_zero(sig_b, 64), "bit %u flipped: signature not zeroed", bit);
        expanded[bit / 8] ^= (uint8_t)(1u << (bit % 8));
        LOOP_ASSERT(ama_ed25519_sign_expanded(sig_b, msg, 22, expanded) == AMA_SUCCESS &&
                    memcmp(sig_a, sig_b, 64) == 0,
                    "bit %u restored: signing did not resume", bit);
    }
    printf("PASS: all %u expanded-key bits: each flip refused with a zero signature, "
           "each restore signs again\n", 8u * AMA_ED25519_EXPANDED_KEY_BYTES);

    /* 4. Refusal at load. */
    {
        static const unsigned positions[] = {0, 1, 7, 128, 255};
        uint8_t other_pk[32], other_sk[64], bad[64];
        size_t i;

        for (i = 0; i < sizeof(positions) / sizeof(positions[0]); i++) {
            memcpy(bad, sk, 64);
            bad[32 + positions[i] / 8] ^= (uint8_t)(1u << (positions[i] % 8));
            memset(expanded, 0xA5, sizeof(expanded));
            LOOP_ASSERT(ama_ed25519_expand_secret_key(expanded, bad) == AMA_ERROR_INVALID_PARAM,
                        "public-half bit %u flipped: expansion not refused", positions[i]);
            LOOP_ASSERT(all_zero(expanded, sizeof(expanded)),
                        "public-half bit %u flipped: expanded buffer not zeroed", positions[i]);
            LOOP_ASSERT(ama_ed25519_sign_expanded(sig_b, msg, 22, expanded) == AMA_ERROR_INVALID_PARAM &&
                        all_zero(sig_b, 64),
                        "public-half bit %u flipped: the refused buffer still signs", positions[i]);
        }
        printf("PASS: expansion refuses a flipped public half at 5 positions; "
               "the zeroed result cannot sign\n");

        prng_fill(other_sk, 32);
        LOOP_ASSERT(ama_ed25519_keypair(other_pk, other_sk) == AMA_SUCCESS, "%s", "other key: keypair");
        memcpy(bad, sk, 32);
        memcpy(bad + 32, other_pk, 32);
        TEST_ASSERT(ama_ed25519_expand_secret_key(expanded, bad) == AMA_ERROR_INVALID_PARAM &&
                    all_zero(expanded, sizeof(expanded)),
                    "expansion refuses another key's public half");

        memcpy(bad, sk, 32);
        memset(bad + 32, 0, 32);
        TEST_ASSERT(ama_ed25519_expand_secret_key(expanded, bad) == AMA_ERROR_INVALID_PARAM &&
                    all_zero(expanded, sizeof(expanded)),
                    "expansion refuses an all-zero public half");
    }

    /* 5. Contract edges. */
    LOOP_ASSERT(ama_ed25519_expand_secret_key(expanded, sk) == AMA_SUCCESS, "%s", "edges: expand");
    TEST_ASSERT(ama_ed25519_expand_secret_key(NULL, sk) == AMA_ERROR_INVALID_PARAM,
                "expand: NULL output rejected");
    TEST_ASSERT(ama_ed25519_expand_secret_key(expanded, NULL) == AMA_ERROR_INVALID_PARAM,
                "expand: NULL secret key rejected");
    TEST_ASSERT(ama_ed25519_sign_expanded(NULL, msg, 22, expanded) == AMA_ERROR_INVALID_PARAM,
                "sign_expanded: NULL signature rejected");
    TEST_ASSERT(ama_ed25519_sign_expanded(sig_a, msg, 22, NULL) == AMA_ERROR_INVALID_PARAM,
                "sign_expanded: NULL expanded key rejected");
    TEST_ASSERT(ama_ed25519_sign_expanded(sig_a, NULL, 22, expanded) == AMA_ERROR_INVALID_PARAM,
                "sign_expanded: NULL message with non-zero length rejected");
    TEST_ASSERT(ama_ed25519_sign_expanded(sig_a, NULL, 0, expanded) == AMA_SUCCESS &&
                ama_ed25519_sign(sig_b, NULL, 0, sk) == AMA_SUCCESS &&
                memcmp(sig_a, sig_b, 64) == 0,
                "sign_expanded: NULL message with zero length signs the empty message");
    TEST_ASSERT(ama_ed25519_sign_expanded(sig_a, msg, 22, expanded) == AMA_SUCCESS &&
                ama_ed25519_sign_expanded(sig_b, msg, 22, expanded) == AMA_SUCCESS &&
                memcmp(sig_a, sig_b, 64) == 0,
                "sign_expanded: deterministic");

    /* An unrepresentable length is refused before any secret is touched,
     * and the refusal still writes all 64 signature bytes as zero. */
    memset(sig_a, 0xA5, 64);
    TEST_ASSERT(ama_ed25519_sign_expanded(sig_a, msg, SIZE_MAX, expanded) == AMA_ERROR_INVALID_PARAM &&
                all_zero(sig_a, 64),
                "sign_expanded: an unrepresentable message length is refused with a zeroed signature");
    memset(sig_a, 0xA5, 64);
    TEST_ASSERT(ama_ed25519_sign(sig_a, msg, SIZE_MAX, sk) == AMA_ERROR_INVALID_PARAM &&
                all_zero(sig_a, 64),
                "sign: an unrepresentable message length is refused with a zeroed signature");

    ama_secure_memzero(expanded, sizeof(expanded));
    ama_secure_memzero(sk, sizeof(sk));
    free(msg);
    return 0;
}

int main(void) {
    printf("===========================================\n");
    printf("Ed25519 expanded signing form\n");
    printf("===========================================\n\n");

    if (run_suite("default (fe51)") != 0) return 1;

    ama_ed25519_set_mulx_override(1);
    if (strcmp(ama_ed25519_active_backend(), "fe51") != 0) {
        if (run_suite("fe64-mulx (override)") != 0) return 1;
    } else {
        printf("--- backend: fe64-mulx not available on this build/host; "
               "suite ran on the default backend only ---\n");
    }
    ama_ed25519_set_mulx_override(0);

    printf("\nAll expanded-key tests passed.\n");
    return 0;
}
