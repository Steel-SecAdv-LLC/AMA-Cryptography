/* Copyright (C) 2025-2026 Steel Security Advisors LLC */
/* SPDX-License-Identifier: Apache-2.0 */
/**
 * @file test_pq_privkey_check_determinism.c
 * @brief The PQ private-key consistency predicates must consume no entropy.
 *
 * `ama_ml_kem_privkey_check` / `ama_ml_kem_pubkey_from_privkey` run a pairwise
 * encapsulate/decapsulate round trip, and `ama_ml_dsa_privkey_check` /
 * `ama_ml_dsa_pubkey_from_privkey` re-expand the matrix. Both are reachable
 * from a *file parser* — `ama_cryptography.key_formats.load_pkcs8` calls them
 * on every `expandedKey`-only ML-KEM/ML-DSA key it imports.
 *
 * A validation predicate that draws from the CSPRNG on a parse path is wrong in
 * four separate ways, so this is asserted rather than assumed:
 *
 *   1. Anyone who can hand you a key file drains RNG state on demand.
 *   2. A predicate that is not reproducible cannot be a KAT.
 *   3. A FIPS 140-3 self-test cannot depend on an RNG whose own health checks
 *      may not have run yet.
 *   4. Any latent failure becomes a flake rather than a bug.
 *
 * The ML-KEM check used to encapsulate under a random `m`, which is exactly
 * this defect; it now uses a fixed one. The test installs a randombytes hook
 * that *fails closed and counts*, so the predicate cannot both call the RNG and
 * pass: a single draw either trips the counter or propagates the error.
 *
 * Requires AMA_TESTING_MODE (the hook symbols exist only there), which is what
 * `ama_cryptography_test` is built with.
 */

#include "ama_cryptography.h"

#include <stdint.h>
#include <stdio.h>
#include <string.h>

/* Test-only externs, matching tests/c/test_kat.c. Deliberately not declared in
 * the public header: production builds must not carry an RNG override. */
extern ama_error_t (*ama_kyber_randombytes_hook)(uint8_t *buf, size_t len);
extern ama_error_t (*ama_dilithium_randombytes_hook)(uint8_t *buf, size_t len);

static unsigned long g_rng_calls;

static ama_error_t counting_failing_rng(uint8_t *buf, size_t len) {
    (void)buf;
    (void)len;
    g_rng_calls++;
    /* Fail closed: if a predicate does draw, it must not quietly succeed. */
    return AMA_ERROR_CRYPTO;
}

#define CHECK(cond, ...)                                                       \
    do {                                                                       \
        if (!(cond)) {                                                         \
            printf("FAIL: " __VA_ARGS__);                                      \
            printf("\n");                                                      \
            return 1;                                                          \
        }                                                                      \
    } while (0)

static int check_ml_kem(ama_ml_kem_param_set_t ps) {
    const char *name = ama_ml_kem_param_set_name(ps);
    size_t pk_len = ama_ml_kem_public_key_bytes(ps);
    size_t sk_len = ama_ml_kem_secret_key_bytes(ps);
    static uint8_t pk[AMA_ML_KEM_MAX_PUBLIC_KEY_BYTES];
    static uint8_t sk[AMA_ML_KEM_MAX_SECRET_KEY_BYTES];
    static uint8_t out_a[AMA_ML_KEM_MAX_PUBLIC_KEY_BYTES];
    static uint8_t out_b[AMA_ML_KEM_MAX_PUBLIC_KEY_BYTES];
    uint8_t d[32], z[32];
    unsigned int i;
    ama_error_t rc;

    /* Deterministic keygen, so the whole test is reproducible. */
    for (i = 0; i < 32; i++) {
        d[i] = (uint8_t)i;
        z[i] = (uint8_t)(0x80 + i);
    }
    rc = ama_ml_kem_keypair_from_seed(ps, d, z, pk, pk_len, sk, sk_len);
    CHECK(rc == AMA_SUCCESS, "%s: keypair_from_seed returned %d", name, (int)rc);

    g_rng_calls = 0;
    ama_kyber_randombytes_hook = counting_failing_rng;

    rc = ama_ml_kem_privkey_check(ps, sk, sk_len);
    CHECK(rc == AMA_SUCCESS, "%s: privkey_check returned %d with the RNG poisoned "
                             "— the predicate is not deterministic", name, (int)rc);
    CHECK(g_rng_calls == 0, "%s: privkey_check drew from the CSPRNG %lu time(s) "
                            "on what is a parser-reachable validation path",
          name, g_rng_calls);

    rc = ama_ml_kem_pubkey_from_privkey(ps, sk, sk_len, out_a, pk_len);
    CHECK(rc == AMA_SUCCESS, "%s: pubkey_from_privkey returned %d", name, (int)rc);
    CHECK(g_rng_calls == 0, "%s: pubkey_from_privkey drew from the CSPRNG", name);
    CHECK(memcmp(out_a, pk, pk_len) == 0,
          "%s: recovered encapsulation key differs from the generated one", name);

    /* Deterministic means *repeatable*, not merely RNG-free. */
    rc = ama_ml_kem_pubkey_from_privkey(ps, sk, sk_len, out_b, pk_len);
    CHECK(rc == AMA_SUCCESS, "%s: second pubkey_from_privkey returned %d", name, (int)rc);
    CHECK(memcmp(out_a, out_b, pk_len) == 0, "%s: two runs disagreed", name);

    /* The check must still *fail* on a corrupted key with the RNG poisoned —
     * otherwise "no entropy consumed" could be bought by not checking at all. */
    sk[0] ^= 0x01;  /* first octet of dk_PKE: digest stays valid, round trip breaks */
    rc = ama_ml_kem_privkey_check(ps, sk, sk_len);
    CHECK(rc == AMA_ERROR_VERIFY_FAILED,
          "%s: a mutated dk_PKE was accepted (returned %d) — the pairwise check "
          "is not doing anything", name, (int)rc);
    CHECK(g_rng_calls == 0, "%s: the failing path drew from the CSPRNG", name);
    sk[0] ^= 0x01;

    ama_kyber_randombytes_hook = NULL;
    printf("ok: %s privkey check is deterministic (0 RNG draws)\n", name);
    return 0;
}

static int check_ml_dsa(ama_ml_dsa_param_set_t ps) {
    const char *name = ama_ml_dsa_param_set_name(ps);
    size_t pk_len = ama_ml_dsa_public_key_bytes(ps);
    size_t sk_len = ama_ml_dsa_secret_key_bytes(ps);
    static uint8_t pk[AMA_ML_DSA_MAX_PUBLIC_KEY_BYTES];
    static uint8_t sk[AMA_ML_DSA_MAX_SECRET_KEY_BYTES];
    static uint8_t out[AMA_ML_DSA_MAX_PUBLIC_KEY_BYTES];
    uint8_t xi[32];
    unsigned int i;
    ama_error_t rc;

    for (i = 0; i < 32; i++) {
        xi[i] = (uint8_t)(0x40 + i);
    }
    rc = ama_ml_dsa_keypair_from_seed(ps, xi, pk, sk);
    CHECK(rc == AMA_SUCCESS, "%s: keypair_from_seed returned %d", name, (int)rc);
    (void)sk_len;

    g_rng_calls = 0;
    ama_dilithium_randombytes_hook = counting_failing_rng;

    rc = ama_ml_dsa_privkey_check(ps, sk);
    CHECK(rc == AMA_SUCCESS, "%s: privkey_check returned %d with the RNG poisoned",
          name, (int)rc);
    CHECK(g_rng_calls == 0, "%s: privkey_check drew from the CSPRNG %lu time(s)",
          name, g_rng_calls);

    rc = ama_ml_dsa_pubkey_from_privkey(ps, sk, out);
    CHECK(rc == AMA_SUCCESS, "%s: pubkey_from_privkey returned %d", name, (int)rc);
    CHECK(g_rng_calls == 0, "%s: pubkey_from_privkey drew from the CSPRNG", name);
    CHECK(memcmp(out, pk, pk_len) == 0,
          "%s: recovered public key differs from the generated one", name);

    /* tr sits at offset 2*32 in the expanded key; corrupting it must be caught. */
    sk[64] ^= 0x01;
    rc = ama_ml_dsa_privkey_check(ps, sk);
    CHECK(rc == AMA_ERROR_VERIFY_FAILED,
          "%s: a mutated tr was accepted (returned %d)", name, (int)rc);
    CHECK(g_rng_calls == 0, "%s: the failing path drew from the CSPRNG", name);
    sk[64] ^= 0x01;

    ama_dilithium_randombytes_hook = NULL;
    printf("ok: %s privkey check is deterministic (0 RNG draws)\n", name);
    return 0;
}

int main(void) {
    const ama_ml_kem_param_set_t kem_sets[] = {
        AMA_ML_KEM_512, AMA_ML_KEM_768, AMA_ML_KEM_1024
    };
    const ama_ml_dsa_param_set_t dsa_sets[] = {
        AMA_ML_DSA_44, AMA_ML_DSA_65, AMA_ML_DSA_87
    };
    size_t i;

    printf("PQ private-key consistency checks: determinism contract\n");
    for (i = 0; i < sizeof(kem_sets) / sizeof(kem_sets[0]); i++) {
        if (check_ml_kem(kem_sets[i]) != 0) {
            ama_kyber_randombytes_hook = NULL;
            return 1;
        }
    }
    for (i = 0; i < sizeof(dsa_sets) / sizeof(dsa_sets[0]); i++) {
        if (check_ml_dsa(dsa_sets[i]) != 0) {
            ama_dilithium_randombytes_hook = NULL;
            return 1;
        }
    }
    printf("PASS\n");
    return 0;
}
