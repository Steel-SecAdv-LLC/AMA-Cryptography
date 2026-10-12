/* Copyright (C) 2025-2026 Steel Security Advisors LLC */
/* SPDX-License-Identifier: Apache-2.0 */
/**
 * The exported entry points no other suite reached.
 *
 * The 2026-10-08 diagnostics measured 13 of the shared library's exported
 * entry points reached by no C test and no fuzz harness: the generic KEM
 * wrappers, ama_dilithium_sign_ctx, the three HKDF-SHA2 one-shots, the two
 * PBKDF2 one-shots, ama_sha384, ama_sha3_384, the trust-anchor hex readout,
 * and the two Ed25519 fold introspection knobs (the constant-time gate
 * drives those, but ctest did not).  This suite closes that set, so the
 * export-coverage measurement reads zero.
 *
 * Vector provenance: FIPS 180-4 / FIPS 202 example digests ("" and "abc"),
 * RFC 5869 Appendix A.1 and A.3, RFC 7914 Section 11 (the published
 * PBKDF2-HMAC-SHA256 vectors).  HKDF-SHA384/512 and PBKDF2-HMAC-SHA512 have
 * no published RFC vectors, so each is checked against the RFC's own
 * construction composed from the library's ama_hmac_sha384/512 primitives
 * (whose FIPS 198-1 KATs live in their own suites) — the specification's
 * formula, not another implementation, is the oracle (INVARIANT-36).
 */

#include <stdio.h>
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

static int hex_to_bytes(const char *hex, uint8_t *out, size_t out_len) {
    for (size_t i = 0; i < out_len; i++) {
        unsigned int byte;
        if (sscanf(hex + 2 * i, "%2x", &byte) != 1) {
            return -1;
        }
        out[i] = (uint8_t)byte;
    }
    return 0;
}

static int test_sha384(void) {
    uint8_t out[48];
    uint8_t expected[48];

    /* FIPS 180-4, "abc". */
    TEST_ASSERT(ama_sha384((const uint8_t *)"abc", 3, out) == AMA_SUCCESS,
                "sha384: 'abc' computes");
    hex_to_bytes(
        "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed"
        "8086072ba1e7cc2358baeca134c825a7",
        expected, 48);
    TEST_ASSERT(memcmp(out, expected, 48) == 0, "sha384: 'abc' known answer");

    /* Empty message, NULL input with input_len == 0 (the documented form). */
    TEST_ASSERT(ama_sha384(NULL, 0, out) == AMA_SUCCESS, "sha384: empty computes");
    hex_to_bytes(
        "38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da"
        "274edebfe76f65fbd51ad2f14898b95b",
        expected, 48);
    TEST_ASSERT(memcmp(out, expected, 48) == 0, "sha384: empty known answer");

    TEST_ASSERT(ama_sha384(NULL, 1, out) == AMA_ERROR_INVALID_PARAM,
                "sha384: NULL input with a length is refused");
    TEST_ASSERT(ama_sha384((const uint8_t *)"abc", 3, NULL) == AMA_ERROR_INVALID_PARAM,
                "sha384: NULL output is refused");
    return 0;
}

static int test_sha3_384(void) {
    uint8_t out[48];
    uint8_t expected[48];

    /* FIPS 202, "abc". */
    TEST_ASSERT(ama_sha3_384((const uint8_t *)"abc", 3, out) == AMA_SUCCESS,
                "sha3-384: 'abc' computes");
    hex_to_bytes(
        "ec01498288516fc926459f58e2c6ad8df9b473cb0fc08c2596da7cf0e49be4b2"
        "98d88cea927ac7f539f1edf228376d25",
        expected, 48);
    TEST_ASSERT(memcmp(out, expected, 48) == 0, "sha3-384: 'abc' known answer");

    TEST_ASSERT(ama_sha3_384(NULL, 0, out) == AMA_SUCCESS, "sha3-384: empty computes");
    hex_to_bytes(
        "0c63a75b845e4f7d01107d852e4c2485c51a50aaaa94fc61995e71bbee983a2a"
        "c3713831264adb47fb6bd1e058d5f004",
        expected, 48);
    TEST_ASSERT(memcmp(out, expected, 48) == 0, "sha3-384: empty known answer");

    TEST_ASSERT(ama_sha3_384(NULL, 1, out) == AMA_ERROR_INVALID_PARAM,
                "sha3-384: NULL input with a length is refused");
    TEST_ASSERT(ama_sha3_384((const uint8_t *)"abc", 3, NULL) == AMA_ERROR_INVALID_PARAM,
                "sha3-384: NULL output is refused");
    return 0;
}

static int test_hkdf_sha256(void) {
    uint8_t okm[42];
    uint8_t expected[42];

    /* RFC 5869 Appendix A.1. */
    const uint8_t ikm[22] = {
        0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
        0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
    };
    const uint8_t salt[13] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a,
        0x0b, 0x0c,
    };
    const uint8_t info[10] = {
        0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9,
    };
    TEST_ASSERT(ama_hkdf_sha256(salt, sizeof(salt), ikm, sizeof(ikm), info,
                                sizeof(info), okm, sizeof(okm)) == AMA_SUCCESS,
                "hkdf-sha256: RFC 5869 A.1 derives");
    hex_to_bytes(
        "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf"
        "34007208d5b887185865",
        expected, 42);
    TEST_ASSERT(memcmp(okm, expected, 42) == 0, "hkdf-sha256: RFC 5869 A.1 known answer");

    /* RFC 5869 Appendix A.3 (no salt, no info). */
    TEST_ASSERT(ama_hkdf_sha256(NULL, 0, ikm, sizeof(ikm), NULL, 0, okm,
                                sizeof(okm)) == AMA_SUCCESS,
                "hkdf-sha256: RFC 5869 A.3 derives");
    hex_to_bytes(
        "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d"
        "9d201395faa4b61a96c8",
        expected, 42);
    TEST_ASSERT(memcmp(okm, expected, 42) == 0, "hkdf-sha256: RFC 5869 A.3 known answer");
    return 0;
}

/* RFC 5869 composed from the library's own HMAC: extract, then two expand
 * blocks.  hash_len is 48 (SHA-384) or 64 (SHA-512). */
static int hkdf_sha2_matches_composition(
    size_t hash_len,
    ama_error_t (*hkdf)(const uint8_t *, size_t, const uint8_t *, size_t,
                        const uint8_t *, size_t, uint8_t *, size_t),
    ama_error_t (*hmac)(const uint8_t *, size_t, const uint8_t *, size_t, uint8_t *),
    const char *label_derives, const char *label_matches) {
    const uint8_t ikm[22] = {
        0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
        0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
    };
    const uint8_t salt[13] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a,
        0x0b, 0x0c,
    };
    const uint8_t info[10] = {
        0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9,
    };
    uint8_t okm[128];
    uint8_t prk[64];
    uint8_t t1[64];
    uint8_t t2[64];
    uint8_t msg[64 + 10 + 1];
    size_t okm_len = hash_len + hash_len / 2; /* spans two expand blocks */

    TEST_ASSERT(hkdf(salt, sizeof(salt), ikm, sizeof(ikm), info, sizeof(info),
                     okm, okm_len) == AMA_SUCCESS,
                label_derives);

    /* Extract: PRK = HMAC(salt, IKM).  Expand: T(1) = HMAC(PRK, info||0x01),
     * T(2) = HMAC(PRK, T(1)||info||0x02). */
    TEST_ASSERT(hmac(salt, sizeof(salt), ikm, sizeof(ikm), prk) == AMA_SUCCESS,
                "hkdf composition: extract computes");
    memcpy(msg, info, sizeof(info));
    msg[sizeof(info)] = 0x01;
    TEST_ASSERT(hmac(prk, hash_len, msg, sizeof(info) + 1, t1) == AMA_SUCCESS,
                "hkdf composition: T(1) computes");
    memcpy(msg, t1, hash_len);
    memcpy(msg + hash_len, info, sizeof(info));
    msg[hash_len + sizeof(info)] = 0x02;
    TEST_ASSERT(hmac(prk, hash_len, msg, hash_len + sizeof(info) + 1, t2) == AMA_SUCCESS,
                "hkdf composition: T(2) computes");
    TEST_ASSERT(memcmp(okm, t1, hash_len) == 0 &&
                    memcmp(okm + hash_len, t2, okm_len - hash_len) == 0,
                label_matches);
    return 0;
}

static int test_hkdf_sha384_sha512(void) {
    if (hkdf_sha2_matches_composition(48, ama_hkdf_sha384, ama_hmac_sha384,
                                      "hkdf-sha384: derives",
                                      "hkdf-sha384: matches RFC 5869 composed "
                                      "from ama_hmac_sha384")) {
        return 1;
    }
    if (hkdf_sha2_matches_composition(64, ama_hkdf_sha512, ama_hmac_sha512,
                                      "hkdf-sha512: derives",
                                      "hkdf-sha512: matches RFC 5869 composed "
                                      "from ama_hmac_sha512")) {
        return 1;
    }
    return 0;
}

static int test_pbkdf2_sha256(void) {
    uint8_t out[64];
    uint8_t expected[64];

    /* RFC 7914 Section 11, the published PBKDF2-HMAC-SHA256 vectors. */
    TEST_ASSERT(ama_pbkdf2_hmac_sha256((const uint8_t *)"passwd", 6,
                                       (const uint8_t *)"salt", 4, 1, out,
                                       sizeof(out)) == AMA_SUCCESS,
                "pbkdf2-sha256: RFC 7914 c=1 derives");
    hex_to_bytes(
        "55ac046e56e3089fec1691c22544b605f94185216dde0465e68b9d57c20dacbc"
        "49ca9cccf179b645991664b39d77ef317c71b845b1e30bd509112041d3a19783",
        expected, 64);
    TEST_ASSERT(memcmp(out, expected, 64) == 0, "pbkdf2-sha256: RFC 7914 c=1 known answer");

    TEST_ASSERT(ama_pbkdf2_hmac_sha256((const uint8_t *)"Password", 8,
                                       (const uint8_t *)"NaCl", 4, 80000, out,
                                       sizeof(out)) == AMA_SUCCESS,
                "pbkdf2-sha256: RFC 7914 c=80000 derives");
    hex_to_bytes(
        "4ddcd8f60b98be21830cee5ef22701f9641a4418d04c0414aeff08876b34ab56"
        "a1d425a1225833549adb841b51c9b3176a272bdebba1d078478f62b397f33c8d",
        expected, 64);
    TEST_ASSERT(memcmp(out, expected, 64) == 0,
                "pbkdf2-sha256: RFC 7914 c=80000 known answer");

    TEST_ASSERT(ama_pbkdf2_hmac_sha256((const uint8_t *)"p", 1, (const uint8_t *)"s",
                                       1, 0, out, 32) == AMA_ERROR_INVALID_PARAM,
                "pbkdf2-sha256: zero iterations refused");
    return 0;
}

static int test_pbkdf2_sha512(void) {
    /* No RFC publishes PBKDF2-HMAC-SHA512 vectors, so check the RFC 8018
     * Section 5.2 construction composed from the library's HMAC: with c=2,
     * block i is F = U1 ^ U2, U1 = HMAC(P, S || INT_BE(i)), U2 = HMAC(P, U1).
     * dkLen = 96 spans two blocks, so the block counter is exercised. */
    const uint8_t password[8] = {'P', 'a', 's', 's', 'w', 'o', 'r', 'd'};
    const uint8_t salt[4] = {'N', 'a', 'C', 'l'};
    uint8_t out[96];
    uint8_t expected[128];
    uint8_t u1[64];
    uint8_t u2[64];
    uint8_t msg[8];

    TEST_ASSERT(ama_pbkdf2_hmac_sha512(password, sizeof(password), salt,
                                       sizeof(salt), 2, out, sizeof(out)) == AMA_SUCCESS,
                "pbkdf2-sha512: c=2 dkLen=96 derives");
    for (uint32_t block = 1; block <= 2; block++) {
        memcpy(msg, salt, sizeof(salt));
        msg[4] = (uint8_t)(block >> 24);
        msg[5] = (uint8_t)(block >> 16);
        msg[6] = (uint8_t)(block >> 8);
        msg[7] = (uint8_t)block;
        TEST_ASSERT(ama_hmac_sha512(password, sizeof(password), msg, sizeof(msg),
                                    u1) == AMA_SUCCESS,
                    "pbkdf2-sha512 composition: U1 computes");
        TEST_ASSERT(ama_hmac_sha512(password, sizeof(password), u1, 64, u2) == AMA_SUCCESS,
                    "pbkdf2-sha512 composition: U2 computes");
        for (size_t i = 0; i < 64; i++) {
            expected[(block - 1) * 64 + i] = (uint8_t)(u1[i] ^ u2[i]);
        }
    }
    TEST_ASSERT(memcmp(out, expected, sizeof(out)) == 0,
                "pbkdf2-sha512: matches RFC 8018 composed from ama_hmac_sha512");

    TEST_ASSERT(ama_pbkdf2_hmac_sha512(password, sizeof(password), salt,
                                       sizeof(salt), 0, out, 32) == AMA_ERROR_INVALID_PARAM,
                "pbkdf2-sha512: zero iterations refused");
    return 0;
}

static int test_kem_context_api(void) {
    uint8_t pk[AMA_ML_KEM_1024_PUBLIC_KEY_BYTES];
    uint8_t sk[AMA_ML_KEM_1024_SECRET_KEY_BYTES];
    uint8_t ct[AMA_ML_KEM_1024_CIPHERTEXT_BYTES];
    uint8_t ss_enc[AMA_ML_KEM_SHARED_SECRET_BYTES];
    uint8_t ss_dec[AMA_ML_KEM_SHARED_SECRET_BYTES];
    size_t ct_len = sizeof(ct);
    ama_context_t *kem = ama_context_init(AMA_ALG_KYBER_1024);
    ama_context_t *sig = ama_context_init(AMA_ALG_ML_DSA_65);

    TEST_ASSERT(kem != NULL, "kem: Kyber-1024 context initialises");
    TEST_ASSERT(sig != NULL, "kem: ML-DSA-65 context initialises");
    TEST_ASSERT(ama_keypair_generate(kem, pk, sizeof(pk), sk, sizeof(sk)) == AMA_SUCCESS,
                "kem: keypair generates");

    TEST_ASSERT(ama_kem_encapsulate(kem, pk, sizeof(pk), ct, &ct_len, ss_enc,
                                    sizeof(ss_enc)) == AMA_SUCCESS,
                "kem: encapsulate succeeds");
    TEST_ASSERT(ct_len == AMA_ML_KEM_1024_CIPHERTEXT_BYTES,
                "kem: ciphertext length reported");
    TEST_ASSERT(ama_kem_decapsulate(kem, ct, ct_len, sk, sizeof(sk), ss_dec,
                                    sizeof(ss_dec)) == AMA_SUCCESS,
                "kem: decapsulate succeeds");
    TEST_ASSERT(ama_consttime_memcmp(ss_enc, ss_dec, sizeof(ss_enc)) == 0,
                "kem: shared secrets agree");

    /* FIPS 203 implicit rejection: a tampered ciphertext decapsulates to a
     * well-formed but different shared secret, not an error. */
    ct[0] ^= 0x01;
    TEST_ASSERT(ama_kem_decapsulate(kem, ct, ct_len, sk, sizeof(sk), ss_dec,
                                    sizeof(ss_dec)) == AMA_SUCCESS,
                "kem: tampered ciphertext still decapsulates (implicit rejection)");
    TEST_ASSERT(ama_consttime_memcmp(ss_enc, ss_dec, sizeof(ss_enc)) != 0,
                "kem: tampered ciphertext yields a different secret");
    ct[0] ^= 0x01;

    /* INVARIANT-5 boundary rows. */
    TEST_ASSERT(ama_kem_encapsulate(NULL, pk, sizeof(pk), ct, &ct_len, ss_enc,
                                    sizeof(ss_enc)) == AMA_ERROR_INVALID_PARAM,
                "kem: NULL context refused");
    TEST_ASSERT(ama_kem_encapsulate(sig, pk, sizeof(pk), ct, &ct_len, ss_enc,
                                    sizeof(ss_enc)) == AMA_ERROR_INVALID_PARAM,
                "kem: signature-algorithm context refused for encapsulation");
    TEST_ASSERT(ama_kem_decapsulate(sig, ct, ct_len, sk, sizeof(sk), ss_dec,
                                    sizeof(ss_dec)) == AMA_ERROR_INVALID_PARAM,
                "kem: signature-algorithm context refused for decapsulation");
    TEST_ASSERT(ama_kem_encapsulate(kem, NULL, sizeof(pk), ct, &ct_len, ss_enc,
                                    sizeof(ss_enc)) == AMA_ERROR_INVALID_PARAM,
                "kem: NULL public key refused");
    TEST_ASSERT(ama_kem_decapsulate(kem, ct, ct_len, NULL, sizeof(sk), ss_dec,
                                    sizeof(ss_dec)) == AMA_ERROR_INVALID_PARAM,
                "kem: NULL secret key refused");

    ama_secure_memzero(ss_enc, sizeof(ss_enc));
    ama_secure_memzero(ss_dec, sizeof(ss_dec));
    ama_secure_memzero(sk, sizeof(sk));
    ama_context_free(kem);
    ama_context_free(sig);
    return 0;
}

static int test_dilithium_sign_ctx(void) {
    static uint8_t pk[AMA_ML_DSA_65_PUBLIC_KEY_BYTES];
    static uint8_t sk[AMA_ML_DSA_65_SECRET_KEY_BYTES];
    static uint8_t sig[AMA_ML_DSA_65_SIGNATURE_BYTES];
    size_t sig_len = sizeof(sig);
    const uint8_t msg[] = "export-coverage: ML-DSA-65 context signing";
    const uint8_t ctx[] = "AMA test context";
    uint8_t big_ctx[256] = {0};

    TEST_ASSERT(ama_dilithium_keypair(pk, sk) == AMA_SUCCESS,
                "dilithium_sign_ctx: keypair generates");

    TEST_ASSERT(ama_dilithium_sign_ctx(sig, &sig_len, msg, sizeof(msg) - 1, ctx,
                                       sizeof(ctx) - 1, sk) == AMA_SUCCESS,
                "dilithium_sign_ctx: signs");
    TEST_ASSERT(sig_len == AMA_ML_DSA_65_SIGNATURE_BYTES,
                "dilithium_sign_ctx: signature length reported");
    TEST_ASSERT(ama_dilithium_verify_ctx(msg, sizeof(msg) - 1, ctx, sizeof(ctx) - 1,
                                         sig, sig_len, pk) == AMA_SUCCESS,
                "dilithium_sign_ctx: verifies under the same context");
    TEST_ASSERT(ama_dilithium_verify_ctx(msg, sizeof(msg) - 1,
                                         (const uint8_t *)"other", 5, sig, sig_len,
                                         pk) == AMA_ERROR_VERIFY_FAILED,
                "dilithium_sign_ctx: a different context is rejected");
    sig[0] ^= 0x01;
    TEST_ASSERT(ama_dilithium_verify_ctx(msg, sizeof(msg) - 1, ctx, sizeof(ctx) - 1,
                                         sig, sig_len, pk) == AMA_ERROR_VERIFY_FAILED,
                "dilithium_sign_ctx: a tampered signature is rejected");
    sig[0] ^= 0x01;

    /* The ctx = "" case is ama_dilithium_sign()'s wrapper exactly. */
    sig_len = sizeof(sig);
    TEST_ASSERT(ama_dilithium_sign_ctx(sig, &sig_len, msg, sizeof(msg) - 1, NULL, 0,
                                       sk) == AMA_SUCCESS,
                "dilithium_sign_ctx: empty context signs");
    TEST_ASSERT(ama_dilithium_verify(msg, sizeof(msg) - 1, sig, sig_len, pk) == AMA_SUCCESS,
                "dilithium_sign_ctx: empty context verifies via ama_dilithium_verify");

    /* FIPS 204 Section 5.2 line 4: ctx longer than 255 octets is refused. */
    sig_len = sizeof(sig);
    TEST_ASSERT(ama_dilithium_sign_ctx(sig, &sig_len, msg, sizeof(msg) - 1, big_ctx,
                                       sizeof(big_ctx), sk) != AMA_SUCCESS,
                "dilithium_sign_ctx: a 256-octet context is refused");

    ama_secure_memzero(sk, sizeof(sk));
    return 0;
}

static int test_trust_anchor_hex(void) {
    /* Per the header contract: release builds bake a 32-byte key in through
     * AMA_INTEGRITY_TRUST_ANCHOR_PUBKEY_HEX and return it as 64 hex
     * characters; developer builds return "". */
    const char *hex = ama_integrity_trust_anchor_pubkey_hex();
    size_t len;
    TEST_ASSERT(hex != NULL, "trust anchor: readout is non-NULL");
    len = strlen(hex);
    TEST_ASSERT(len == 0 || len == 64,
                "trust anchor: empty (developer build) or 64 hex characters");
    for (size_t i = 0; i < len; i++) {
        char c = hex[i];
        TEST_ASSERT((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') ||
                        (c >= 'A' && c <= 'F'),
                    "trust anchor: hex alphabet");
    }
    return 0;
}

static int test_ed25519_fold_introspection(void) {
    const char *initial = ama_ed25519_active_fold();
    TEST_ASSERT(initial != NULL, "fold: active_fold is non-NULL");
    TEST_ASSERT(strcmp(initial, "avx2") == 0 || strcmp(initial, "sse2") == 0 ||
                    strcmp(initial, "portable") == 0,
                "fold: active_fold names a documented fold");

    /* The override forces SSE2 on an AVX2 host and is a no-op elsewhere;
     * either way active_fold() must keep reporting a documented fold and
     * -1 must restore the default. */
    ama_ed25519_set_avx2_fold_override(0);
    if (strcmp(initial, "avx2") == 0) {
        TEST_ASSERT(strcmp(ama_ed25519_active_fold(), "sse2") == 0,
                    "fold: override 0 forces the SSE2 fold on an AVX2 host");
    } else {
        TEST_ASSERT(strcmp(ama_ed25519_active_fold(), initial) == 0,
                    "fold: override 0 is a no-op without the AVX2 unit");
    }
    ama_ed25519_set_avx2_fold_override(-1);
    TEST_ASSERT(strcmp(ama_ed25519_active_fold(), initial) == 0,
                "fold: override -1 restores the default");
    return 0;
}

int main(void) {
    printf("===========================================\n");
    printf("Export Coverage Test Suite\n");
    printf("===========================================\n\n");

    if (test_sha384() || test_sha3_384() || test_hkdf_sha256() ||
        test_hkdf_sha384_sha512() || test_pbkdf2_sha256() || test_pbkdf2_sha512() ||
        test_kem_context_api() || test_dilithium_sign_ctx() ||
        test_trust_anchor_hex() || test_ed25519_fold_introspection()) {
        return 1;
    }

    printf("\nAll export-coverage tests passed.\n");
    return 0;
}
