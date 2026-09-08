/* Copyright (C) 2025-2026 Steel Security Advisors LLC */
/* SPDX-License-Identifier: Apache-2.0 */
/**
 * @file test_ml_kem_decaps_hash_check.c
 * @brief FIPS 203 Sec 7.3 decapsulation input check 3 — the hash check — is
 *        performed by ML-KEM.Decaps itself, for every parameter set and for
 *        the legacy Kyber-1024 entry point.
 *
 * FIPS 203 Sec 7.3 lists three input checks a decapsulation key and
 * ciphertext must pass before ML-KEM.Decaps runs: the ciphertext length,
 * the key length, and
 *
 *     test <- H(dk[384k : 768k+32]);  if test != dk[768k+32 : 768k+64] fail.
 *
 * The first two were enforced; the third existed only in the separate
 * ama_ml_kem_privkey_check() entry point, which no decapsulation caller
 * invokes.  A key whose stored digest disagreed with its embedded
 * encapsulation key therefore decapsulated to AMA_SUCCESS and an
 * implicit-rejection secret the peer never derived — a silent protocol
 * failure where the standard requires a refused input.
 *
 * What this test pins, per parameter set:
 *   1. A consistent key decapsulates to the encapsulator's secret.
 *   2. A one-bit change to the stored digest is refused with
 *      AMA_ERROR_INVALID_PARAM and the output buffer is not written.
 *   3. A one-bit change to the embedded encapsulation key (which makes the
 *      stored digest stale) is refused the same way.
 *   4. A one-bit change to dk_PKE — which leaves the digest correct — is NOT
 *      refused: it takes the implicit-rejection path and returns AMA_SUCCESS
 *      with a different secret, exactly as before.  The hash check must not
 *      over-reject; only ama_ml_kem_privkey_check()'s pairwise round trip
 *      can see that mutation.
 *   5. A corrupted ciphertext with a consistent key still takes implicit
 *      rejection: AMA_SUCCESS, different secret.
 *
 * Against the tree before the check was added, cases 2 and 3 fail
 * (rc == AMA_SUCCESS, output written), which is what makes this test
 * discriminating rather than descriptive.
 */
#include "../../include/ama_cryptography.h"
#include <stdio.h>
#include <string.h>

static int failures = 0;

#define CHECK(cond, ...) do { \
    if (!(cond)) { failures++; printf("  FAIL: " __VA_ARGS__); printf("\n"); } \
} while (0)

static void run_param_set(ama_ml_kem_param_set_t ps, size_t pk_len, size_t sk_len, size_t ct_len) {
    uint8_t pk[AMA_ML_KEM_1024_PUBLIC_KEY_BYTES];
    uint8_t sk[AMA_ML_KEM_1024_SECRET_KEY_BYTES];
    uint8_t sk_mut[AMA_ML_KEM_1024_SECRET_KEY_BYTES];
    uint8_t ct[AMA_ML_KEM_1024_CIPHERTEXT_BYTES];
    uint8_t ct_bad[AMA_ML_KEM_1024_CIPHERTEXT_BYTES];
    uint8_t ss_enc[AMA_ML_KEM_SHARED_SECRET_BYTES];
    uint8_t ss_dec[AMA_ML_KEM_SHARED_SECRET_BYTES];
    uint8_t sentinel[AMA_ML_KEM_SHARED_SECRET_BYTES];
    size_t out_len = ct_len;
    const size_t k = (size_t)ps / 256u;
    const size_t off_ek = 384u * k;
    const size_t off_h = 768u * k + 32u;
    ama_error_t rc;

    printf("ML-KEM-%d\n", (int)ps);
    memset(sentinel, 0x5a, sizeof(sentinel));

    rc = ama_ml_kem_keypair(ps, pk, pk_len, sk, sk_len);
    CHECK(rc == AMA_SUCCESS, "keypair rc=%d", (int)rc);
    rc = ama_ml_kem_encapsulate(ps, pk, pk_len, ct, &out_len, ss_enc, sizeof(ss_enc));
    CHECK(rc == AMA_SUCCESS && out_len == ct_len, "encapsulate rc=%d len=%zu", (int)rc, out_len);

    /* 1. Consistent key: secrets agree. */
    rc = ama_ml_kem_decapsulate(ps, ct, ct_len, sk, sk_len, ss_dec, sizeof(ss_dec));
    CHECK(rc == AMA_SUCCESS, "valid decapsulate rc=%d", (int)rc);
    CHECK(memcmp(ss_enc, ss_dec, sizeof(ss_enc)) == 0, "valid decapsulate secret mismatch");

    /* 2. Stored digest mutated: refused, output untouched. */
    memcpy(sk_mut, sk, sk_len);
    sk_mut[off_h] ^= 0x01;
    memcpy(ss_dec, sentinel, sizeof(ss_dec));
    rc = ama_ml_kem_decapsulate(ps, ct, ct_len, sk_mut, sk_len, ss_dec, sizeof(ss_dec));
    CHECK(rc == AMA_ERROR_INVALID_PARAM, "mutated H(ek) accepted: rc=%d (want %d)",
          (int)rc, (int)AMA_ERROR_INVALID_PARAM);
    CHECK(memcmp(ss_dec, sentinel, sizeof(ss_dec)) == 0, "mutated H(ek): output buffer was written");

    /* 3. Embedded ek mutated (digest now stale): refused, output untouched. */
    memcpy(sk_mut, sk, sk_len);
    sk_mut[off_ek] ^= 0x01;
    memcpy(ss_dec, sentinel, sizeof(ss_dec));
    rc = ama_ml_kem_decapsulate(ps, ct, ct_len, sk_mut, sk_len, ss_dec, sizeof(ss_dec));
    CHECK(rc == AMA_ERROR_INVALID_PARAM, "mutated ek accepted: rc=%d", (int)rc);
    CHECK(memcmp(ss_dec, sentinel, sizeof(ss_dec)) == 0, "mutated ek: output buffer was written");

    /* 4. dk_PKE mutated, digest still correct: NOT refused (implicit rejection). */
    memcpy(sk_mut, sk, sk_len);
    sk_mut[0] ^= 0x01;
    rc = ama_ml_kem_decapsulate(ps, ct, ct_len, sk_mut, sk_len, ss_dec, sizeof(ss_dec));
    CHECK(rc == AMA_SUCCESS, "dk_PKE mutation was refused by the hash check: rc=%d", (int)rc);
    CHECK(memcmp(ss_enc, ss_dec, sizeof(ss_enc)) != 0, "dk_PKE mutation had no effect");

    /* 5. Corrupted ciphertext, consistent key: implicit rejection unchanged. */
    memcpy(ct_bad, ct, ct_len);
    ct_bad[0] ^= 0xFF;
    rc = ama_ml_kem_decapsulate(ps, ct_bad, ct_len, sk, sk_len, ss_dec, sizeof(ss_dec));
    CHECK(rc == AMA_SUCCESS, "corrupted ciphertext surfaced as an error: rc=%d", (int)rc);
    CHECK(memcmp(ss_enc, ss_dec, sizeof(ss_enc)) != 0, "corrupted ciphertext decapsulated to the real secret");

    /* The legacy Kyber-1024 entry point is the same code and must refuse too. */
    if (ps == AMA_ML_KEM_1024) {
        memcpy(sk_mut, sk, sk_len);
        sk_mut[off_h] ^= 0x01;
        memcpy(ss_dec, sentinel, sizeof(ss_dec));
        rc = ama_kyber_decapsulate(ct, ct_len, sk_mut, sk_len, ss_dec, sizeof(ss_dec));
        CHECK(rc == AMA_ERROR_INVALID_PARAM, "ama_kyber_decapsulate accepted a mutated H(ek): rc=%d", (int)rc);
        CHECK(memcmp(ss_dec, sentinel, sizeof(ss_dec)) == 0, "ama_kyber_decapsulate wrote the output on refusal");
    }
}

int main(void) {
    setbuf(stdout, NULL);
    printf("=== FIPS 203 Sec 7.3 decapsulation hash check ===\n");
    run_param_set(AMA_ML_KEM_512, AMA_ML_KEM_512_PUBLIC_KEY_BYTES,
                  AMA_ML_KEM_512_SECRET_KEY_BYTES, AMA_ML_KEM_512_CIPHERTEXT_BYTES);
    run_param_set(AMA_ML_KEM_768, AMA_ML_KEM_768_PUBLIC_KEY_BYTES,
                  AMA_ML_KEM_768_SECRET_KEY_BYTES, AMA_ML_KEM_768_CIPHERTEXT_BYTES);
    run_param_set(AMA_ML_KEM_1024, AMA_ML_KEM_1024_PUBLIC_KEY_BYTES,
                  AMA_ML_KEM_1024_SECRET_KEY_BYTES, AMA_ML_KEM_1024_CIPHERTEXT_BYTES);
    if (failures) {
        printf("FAILED: %d check(s)\n", failures);
        return 1;
    }
    printf("ALL PASSED\n");
    return 0;
}
