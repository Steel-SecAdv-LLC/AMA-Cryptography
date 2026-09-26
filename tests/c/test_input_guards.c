/* Copyright (C) 2025-2026 Steel Security Advisors LLC */
/* SPDX-License-Identifier: Apache-2.0 */
/**
 * Public-API input guards (INVARIANT-5) that no suite executed, in
 * ama_kyber.c, ama_dilithium.c, ama_slhdsa.c and ama_nistp.c.
 *
 * WHY THIS FILE EXISTS
 *
 * `tools/measure_branch_coverage.py --python-suite`, run on 2026-09-26 over
 * ctest, pytest, the Wycheproof runner and the ACVP runner together, found
 * each refusal below executed by nothing.  The Python layer validates most of
 * these arguments before it reaches C, so a C caller -- the audience of the
 * public header -- was the only one relying on the C guard, and no test
 * stood behind it.
 *
 * WHICH CASES ARE PINS
 *
 * Most rows are RANGE: they exercise the domain of a NULL, unknown-set or
 * short-buffer refusal, were not mutation-tested, and claim no more than
 * that.  The rows marked PIN are the ones whose guard was deleted and the
 * library rebuilt, and the test then failed (AGENTS.md 6.2):
 *
 *   - ML-KEM: a ciphertext or encapsulation key one octet LONG, and a
 *     ciphertext buffer one octet SHORT.  Without the length checks the first
 *     two are accepted (a second byte string for one ciphertext or key) and
 *     the third writes past the caller's buffer.
 *   - ML-DSA and SLH-DSA: a 256-octet context.  FIPS 204 and 205 cap |ctx| at
 *     255 because it is encoded in one octet; without the cap the length
 *     octet wraps to 0 and the 257-octet prefix buffer overflows by one.
 *   - ECDSA over P-256/384/521: a private key of 0 or >= n, an unknown flag
 *     bit, a digest length the API does not define, and a zero or
 *     out-of-range r or s in the DER <-> raw converters; and key generation
 *     and hedged signing under a failing CSPRNG, through the
 *     AMA_TESTING_MODE hook ama_nistp.c gained for it.
 *
 * Mutation record, gcc 13.3.0 Release, x86-64, full ctest; in every case
 * this is the only test that fails:
 *
 *   decapsulate's ciphertext-length check ....... fails (accepts ct || 0x00)
 *   encapsulate's ciphertext-buffer check ........ fails (writes past it)
 *   ML-DSA's |ctx| <= 255 ........................ aborts (stack protector:
 *                                                  the prefix overflows)
 *   SLH-DSA's |ctx| <= 255 ....................... fails
 *   ECDSA private-key range, sign flags, verify
 *   flags, digest length, raw -> DER s range ..... each fails
 *   ML-KEM modulus check's c1 operand ............ fails
 *   every CSPRNG check: ML-KEM keygen (d and z)
 *   and encapsulation, ML-DSA keygen and hedged
 *   sign, SLH-DSA keygen and sign (FIPS 205 and
 *   legacy), ECDSA keygen and hedged sign ......... each fails
 *   ECDSA keygen rejection sampling, DER -> raw
 *   r range ....................................... each fails
 *
 * Measured redundant, so the rows are SMOKE: the identity refusal in
 * nistp_load_point (the curve equation also rejects (0, 0) and (0, 1) on all
 * three curves, b != 0).
 *
 * One rule is enforced twice, and the test pins the rule (6.3):
 * encapsulate checks the key length itself and again inside
 * kyber_pubkey_check.  Deleting either alone leaves encapsulate refusing a
 * long key; the direct ama_ml_kem_pubkey_check row fails when the inner one
 * is deleted, and deleting both fails the encapsulate row.
 */

#include <stdio.h>
#include <string.h>
#include "ama_cryptography.h"

static int failures = 0;

#define CHECK(cond, ...)                         \
    do {                                         \
        if (!(cond)) {                           \
            printf("FAIL: " __VA_ARGS__);        \
            printf("\n");                        \
            failures++;                          \
        } else {                                 \
            printf("PASS: " __VA_ARGS__);        \
            printf("\n");                        \
        }                                        \
    } while (0)

#define INVALID AMA_ERROR_INVALID_PARAM

/* ------------------------------------------------------------------------ */
/* ML-KEM                                                                    */
/* ------------------------------------------------------------------------ */

static void ml_kem_guards(ama_ml_kem_param_set_t ps, const char *name) {
    static uint8_t pk[1568 + 1], sk[3168 + 1], ct[1568 + 1], pk2[1568];
    uint8_t d[32], z[32], ss[32];
    const size_t pkb = ama_ml_kem_public_key_bytes(ps);
    const size_t skb = ama_ml_kem_secret_key_bytes(ps);
    const size_t ctb = ama_ml_kem_ciphertext_bytes(ps);
    size_t ct_len;

    memset(d, 0x31, sizeof d);
    memset(z, 0x32, sizeof z);
    if (ama_ml_kem_keypair_from_seed(ps, d, z, pk, pkb, sk, skb) != AMA_SUCCESS) {
        CHECK(0, "%s: keypair from seed", name);
        return;
    }
    ct_len = ctb;
    if (ama_ml_kem_encapsulate(ps, pk, pkb, ct, &ct_len, ss, 32) != AMA_SUCCESS) {
        CHECK(0, "%s: encapsulate", name);
        return;
    }
    pk[pkb] = 0;
    ct[ctb] = 0;

    /* PIN: trailing octets are a second encoding, not the same input. */
    ct_len = ctb;
    CHECK(ama_ml_kem_encapsulate(ps, pk, pkb + 1, ct, &ct_len, ss, 32) == INVALID,
          "%s: encapsulate refuses an encapsulation key one octet long", name);
    CHECK(ama_ml_kem_decapsulate(ps, ct, ctb + 1, sk, skb, ss, 32) == INVALID,
          "%s: decapsulate refuses a ciphertext one octet long", name);
    CHECK(ama_ml_kem_decapsulate(ps, ct, ctb - 1, sk, skb, ss, 32) == INVALID,
          "%s: decapsulate refuses a ciphertext one octet short", name);
    CHECK(ama_ml_kem_decapsulate(ps, ct, ctb, sk, skb + 1, ss, 32) == INVALID,
          "%s: decapsulate refuses a secret key of the wrong length", name);
    CHECK(ama_ml_kem_decapsulate(ps, ct, ctb, sk, skb, ss, 31) == INVALID,
          "%s: decapsulate refuses a 31-octet shared-secret buffer", name);

    /* PIN: the ciphertext buffer is reported, not overrun. */
    ct_len = ctb - 1;
    CHECK(ama_ml_kem_encapsulate(ps, pk, pkb, ct, &ct_len, ss, 32) == INVALID &&
              ct_len == ctb,
          "%s: encapsulate refuses a short ciphertext buffer and reports the size", name);

    CHECK(ama_ml_kem_encapsulate(ps, NULL, pkb, ct, &ct_len, ss, 32) == INVALID &&
              ama_ml_kem_encapsulate(ps, pk, pkb, NULL, &ct_len, ss, 32) == INVALID &&
              ama_ml_kem_encapsulate(ps, pk, pkb, ct, NULL, ss, 32) == INVALID &&
              ama_ml_kem_encapsulate(ps, pk, pkb, ct, &ct_len, NULL, 32) == INVALID &&
              ama_ml_kem_encapsulate(ps, pk, pkb, ct, &ct_len, ss, 31) == INVALID,
          "%s: encapsulate refuses each NULL argument and a short secret", name);
    CHECK(ama_ml_kem_decapsulate(ps, NULL, ctb, sk, skb, ss, 32) == INVALID &&
              ama_ml_kem_decapsulate(ps, ct, ctb, NULL, skb, ss, 32) == INVALID &&
              ama_ml_kem_decapsulate(ps, ct, ctb, sk, skb, NULL, 32) == INVALID,
          "%s: decapsulate refuses each NULL argument", name);

    CHECK(ama_ml_kem_pubkey_check(ps, pk, pkb + 1) == INVALID &&
              ama_ml_kem_pubkey_check(ps, NULL, pkb) == INVALID,
          "%s: pubkey_check refuses a wrong length and NULL", name);
    CHECK(ama_ml_kem_pubkey_from_privkey(ps, sk, skb - 1, pk2, pkb) == INVALID &&
              ama_ml_kem_pubkey_from_privkey(ps, sk, skb, pk2, pkb - 1) == INVALID &&
              ama_ml_kem_pubkey_from_privkey(ps, NULL, skb, pk2, pkb) == INVALID &&
              ama_ml_kem_pubkey_from_privkey(ps, sk, skb, NULL, pkb) == INVALID,
          "%s: pubkey_from_privkey refuses wrong lengths and NULLs", name);
    CHECK(ama_ml_kem_privkey_check(ps, NULL, skb) == INVALID,
          "%s: privkey_check refuses NULL", name);
    CHECK(ama_ml_kem_keypair_from_seed(ps, NULL, z, pk, pkb, sk, skb) == INVALID &&
              ama_ml_kem_keypair_from_seed(ps, d, NULL, pk, pkb, sk, skb) == INVALID &&
              ama_ml_kem_keypair_from_seed(ps, d, z, NULL, pkb, sk, skb) == INVALID &&
              ama_ml_kem_keypair_from_seed(ps, d, z, pk, pkb - 1, sk, skb) == INVALID &&
              ama_ml_kem_keypair_from_seed(ps, d, z, pk, pkb, sk, skb - 1) == INVALID,
          "%s: keypair_from_seed refuses NULLs and short buffers", name);
}

extern ama_error_t (*ama_kyber_randombytes_hook)(uint8_t *buf, size_t len);
extern ama_error_t (*ama_dilithium_randombytes_hook)(uint8_t *buf, size_t len);

/* Reports failure AFTER writing: `ama_randombytes` is not all-or-nothing (its
 * getrandom loop can fail after earlier iterations wrote), so a refusal must
 * neither use nor leave the partial draw. */
static ama_error_t failing_randombytes(uint8_t *buf, size_t len) {
    memset(buf, 0xA7, len);
    return AMA_ERROR_CRYPTO;
}

/* PIN: FIPS 203 section 7.2's modulus check refuses an out-of-range
 * coefficient in EITHER half of a packed pair.  Twelve-bit coefficients are
 * packed two to three octets; the Python suite and the ACVP vectors only ever
 * put the bad value in the first (c0), so the `c1 >= q` operand was executed
 * by nothing.  Mutation: drop it -> the key is accepted. */
static void ml_kem_second_coefficient(ama_ml_kem_param_set_t ps, const char *name) {
    static uint8_t pk[1568], sk[3168], ct[1568];
    uint8_t d[32], z[32], ss[32];
    const size_t pkb = ama_ml_kem_public_key_bytes(ps);
    size_t ct_len = sizeof ct;

    memset(d, 0x33, sizeof d);
    memset(z, 0x34, sizeof z);
    if (ama_ml_kem_keypair_from_seed(ps, d, z, pk, pkb, sk,
                                     ama_ml_kem_secret_key_bytes(ps)) != AMA_SUCCESS) {
        CHECK(0, "%s: keypair from seed", name);
        return;
    }
    /* c1 of the first pair = (a[1] >> 4) | (a[2] << 4); make it q = 0xD01. */
    pk[1] = (uint8_t)((pk[1] & 0x0Fu) | 0x10u);
    pk[2] = 0xD0u;
    CHECK(ama_ml_kem_pubkey_check(ps, pk, pkb) == AMA_ERROR_VERIFY_FAILED &&
              ama_ml_kem_encapsulate(ps, pk, pkb, ct, &ct_len, ss, 32) ==
                  AMA_ERROR_VERIFY_FAILED,
          "%s: a key whose second packed coefficient is q is refused", name);
}

/* One good draw, then failure: reaches the SECOND draw of key generation
 * (z, after d), which an always-failing source never gets to. */
static int kyber_good_draws = 0;
static ama_error_t kyber_fail_later_randombytes(uint8_t *buf, size_t len) {
    if (kyber_good_draws-- > 0) {
        memset(buf, 0x3C, len);
        return AMA_SUCCESS;
    }
    return failing_randombytes(buf, len);
}

/* The converse: the FIRST draw fails and every later one succeeds.  With an
 * always-failing source, deleting the first draw's check is covered up by
 * the second draw failing too (measured); this isolates it. */
static int kyber_draws_seen = 0;
static ama_error_t kyber_fail_first_randombytes(uint8_t *buf, size_t len) {
    if (kyber_draws_seen++ == 0) return failing_randombytes(buf, len);
    memset(buf, 0x3D, len);
    return AMA_SUCCESS;
}

/* PIN: key generation (either of its two draws) and encapsulation fail
 * closed on a CSPRNG failure.  Mutation: delete any one of the three
 * `err != AMA_SUCCESS` checks -> AMA_SUCCESS. */
static void ml_kem_csprng_failure(ama_ml_kem_param_set_t ps, const char *name) {
    static uint8_t pk[1568], sk[3168], ct[1568];
    uint8_t d[32], z[32], ss[32];
    const size_t pkb = ama_ml_kem_public_key_bytes(ps);
    const size_t skb = ama_ml_kem_secret_key_bytes(ps);
    size_t ct_len = sizeof ct;

    memset(d, 0x35, sizeof d);
    memset(z, 0x36, sizeof z);
    if (ama_ml_kem_keypair_from_seed(ps, d, z, pk, pkb, sk, skb) != AMA_SUCCESS) {
        CHECK(0, "%s: keypair from seed", name);
        return;
    }
    ama_kyber_randombytes_hook = failing_randombytes;
    CHECK(ama_ml_kem_keypair(ps, pk, pkb, sk, skb) == AMA_ERROR_CRYPTO,
          "%s: key generation fails closed on a CSPRNG failure", name);
    kyber_draws_seen = 0;
    ama_kyber_randombytes_hook = kyber_fail_first_randombytes;
    CHECK(ama_ml_kem_keypair(ps, pk, pkb, sk, skb) == AMA_ERROR_CRYPTO,
          "%s: key generation fails closed when only its first draw (d) fails", name);
    kyber_good_draws = 1;
    ama_kyber_randombytes_hook = kyber_fail_later_randombytes;
    CHECK(ama_ml_kem_keypair(ps, pk, pkb, sk, skb) == AMA_ERROR_CRYPTO,
          "%s: key generation fails closed when only its second draw (z) fails", name);
    ama_kyber_randombytes_hook = failing_randombytes;
    CHECK(ama_ml_kem_encapsulate(ps, pk, pkb, ct, &ct_len, ss, 32) == AMA_ERROR_CRYPTO,
          "%s: encapsulation fails closed on a CSPRNG failure", name);
    ama_kyber_randombytes_hook = NULL;
}

static void ml_kem_unknown_set(void) {
    const ama_ml_kem_param_set_t bad = (ama_ml_kem_param_set_t)1;
    uint8_t buf[64] = {0};
    size_t len = sizeof buf;
    CHECK(ama_ml_kem_public_key_bytes(bad) == 0 && ama_ml_kem_secret_key_bytes(bad) == 0 &&
              ama_ml_kem_ciphertext_bytes(bad) == 0,
          "ML-KEM: an unknown parameter set has no sizes");
    CHECK(ama_ml_kem_keypair_from_seed(bad, buf, buf, buf, 64, buf, 64) == INVALID &&
              ama_ml_kem_pubkey_check(bad, buf, 64) == INVALID &&
              ama_ml_kem_pubkey_from_privkey(bad, buf, 64, buf, 64) == INVALID &&
              ama_ml_kem_privkey_check(bad, buf, 64) == INVALID &&
              ama_ml_kem_encapsulate(bad, buf, 64, buf, &len, buf, 32) == INVALID &&
              ama_ml_kem_decapsulate(bad, buf, 64, buf, 64, buf, 32) == INVALID,
          "ML-KEM: every entry point refuses an unknown parameter set");
}

/* ------------------------------------------------------------------------ */
/* ML-DSA                                                                    */
/* ------------------------------------------------------------------------ */

static void ml_dsa_guards(ama_ml_dsa_param_set_t ps, const char *name) {
    static uint8_t pk[2592], sk[4896], sig[4627], ctx[256];
    uint8_t xi[32], rnd_msg[3] = {'a', 'b', 'c'};
    const size_t sigb = ama_ml_dsa_signature_bytes(ps);
    size_t sig_len;

    memset(xi, 0x41, sizeof xi);
    memset(ctx, 0x43, sizeof ctx);
    if (ama_ml_dsa_keypair_from_seed(ps, xi, pk, sk) != AMA_SUCCESS) {
        CHECK(0, "%s: keypair from seed", name);
        return;
    }

    /* PIN: |ctx| = 256 is not encodable in the one-octet length. */
    sig_len = sizeof sig;
    CHECK(ama_ml_dsa_sign_ctx(ps, sig, &sig_len, rnd_msg, 3, ctx, 256, sk) == INVALID,
          "%s: sign refuses a 256-octet context", name);
    sig_len = sizeof sig;
    CHECK(ama_ml_dsa_sign_ctx(ps, sig, &sig_len, rnd_msg, 3, ctx, 255, sk) == AMA_SUCCESS,
          "%s: control: a 255-octet context signs", name);
    CHECK(ama_ml_dsa_verify_ctx(ps, rnd_msg, 3, ctx, 256, sig, sig_len, pk) == INVALID,
          "%s: verify refuses a 256-octet context", name);
    CHECK(ama_ml_dsa_verify_ctx(ps, rnd_msg, 3, ctx, 255, sig, sig_len, pk) == AMA_SUCCESS,
          "%s: control: the 255-octet context verifies", name);
    sig_len = sizeof sig;
    CHECK(ama_ml_dsa_sign_ctx(ps, sig, &sig_len, rnd_msg, 3, NULL, 1, sk) == INVALID &&
              ama_ml_dsa_verify_ctx(ps, rnd_msg, 3, NULL, 1, sig, sigb, pk) == INVALID,
          "%s: a NULL context with a non-zero length is refused", name);

    /* The signature buffer is reported, not overrun. */
    sig_len = sigb - 1;
    CHECK(ama_ml_dsa_sign_ctx(ps, sig, &sig_len, rnd_msg, 3, NULL, 0, sk) == INVALID &&
              sig_len == sigb,
          "%s: sign refuses a short signature buffer and reports the size", name);

    sig_len = sizeof sig;
    CHECK(ama_ml_dsa_sign_ctx(ps, NULL, &sig_len, rnd_msg, 3, NULL, 0, sk) == INVALID &&
              ama_ml_dsa_sign_ctx(ps, sig, NULL, rnd_msg, 3, NULL, 0, sk) == INVALID &&
              ama_ml_dsa_sign_ctx(ps, sig, &sig_len, NULL, 3, NULL, 0, sk) == INVALID &&
              ama_ml_dsa_sign_ctx(ps, sig, &sig_len, rnd_msg, 3, NULL, 0, NULL) == INVALID,
          "%s: sign refuses each NULL argument", name);
    CHECK(ama_ml_dsa_sign_hedged(ps, NULL, &sig_len, rnd_msg, 3, NULL, 0, sk) == INVALID &&
              ama_ml_dsa_sign_hedged(ps, sig, &sig_len, rnd_msg, 3, NULL, 0, NULL) == INVALID,
          "%s: hedged sign refuses NULL arguments", name);
    CHECK(ama_ml_dsa_verify_ctx(ps, NULL, 3, NULL, 0, sig, sigb, pk) == INVALID &&
              ama_ml_dsa_verify_ctx(ps, rnd_msg, 3, NULL, 0, NULL, sigb, pk) == INVALID &&
              ama_ml_dsa_verify_ctx(ps, rnd_msg, 3, NULL, 0, sig, sigb, NULL) == INVALID,
          "%s: verify refuses each NULL argument", name);
    CHECK(ama_ml_dsa_keypair(ps, NULL, sk) == INVALID &&
              ama_ml_dsa_keypair(ps, pk, NULL) == INVALID &&
              ama_ml_dsa_keypair_from_seed(ps, NULL, pk, sk) == INVALID &&
              ama_ml_dsa_keypair_from_seed(ps, xi, NULL, sk) == INVALID &&
              ama_ml_dsa_pubkey_from_privkey(ps, NULL, pk) == INVALID &&
              ama_ml_dsa_pubkey_from_privkey(ps, sk, NULL) == INVALID &&
              ama_ml_dsa_privkey_check(ps, NULL) == INVALID,
          "%s: key entry points refuse each NULL argument", name);
}

/* PIN: key generation and HEDGED signing fail closed on a CSPRNG failure.
 * The hedged case is the one FIPS 204 Algorithm 2 line 5 names: falling back
 * to rnd = 0 would hand the caller the deterministic variant under the
 * hedged name.  Mutation: delete either check -> AMA_SUCCESS. */
static void ml_dsa_csprng_failure(ama_ml_dsa_param_set_t ps, const char *name) {
    static uint8_t pk[2592], sk[4896], sig[4627];
    uint8_t xi[32];
    const uint8_t msg[3] = {'d', 'e', 'f'};
    size_t sig_len = sizeof sig;

    memset(xi, 0x45, sizeof xi);
    if (ama_ml_dsa_keypair_from_seed(ps, xi, pk, sk) != AMA_SUCCESS) {
        CHECK(0, "%s: keypair from seed", name);
        return;
    }
    ama_dilithium_randombytes_hook = failing_randombytes;
    CHECK(ama_ml_dsa_keypair(ps, pk, sk) == AMA_ERROR_CRYPTO,
          "%s: key generation fails closed on a CSPRNG failure", name);
    CHECK(ama_ml_dsa_sign_hedged(ps, sig, &sig_len, msg, 3, NULL, 0, sk) == AMA_ERROR_CRYPTO,
          "%s: hedged signing fails closed on a CSPRNG failure", name);
    ama_dilithium_randombytes_hook = NULL;
}

static void ml_dsa_unknown_set(void) {
    const ama_ml_dsa_param_set_t bad = (ama_ml_dsa_param_set_t)1;
    uint8_t buf[64] = {0};
    size_t len = sizeof buf;
    CHECK(ama_ml_dsa_param_set_name(bad) == NULL && ama_ml_dsa_signature_bytes(bad) == 0 &&
              ama_ml_dsa_public_key_bytes(bad) == 0 && ama_ml_dsa_secret_key_bytes(bad) == 0,
          "ML-DSA: an unknown parameter set has no name and no sizes");
    CHECK(ama_ml_dsa_keypair(bad, buf, buf) == INVALID &&
              ama_ml_dsa_keypair_from_seed(bad, buf, buf, buf) == INVALID &&
              ama_ml_dsa_pubkey_from_privkey(bad, buf, buf) == INVALID &&
              ama_ml_dsa_privkey_check(bad, buf) == INVALID &&
              ama_ml_dsa_sign_ctx(bad, buf, &len, buf, 1, NULL, 0, buf) == INVALID &&
              ama_ml_dsa_sign_hedged(bad, buf, &len, buf, 1, NULL, 0, buf) == INVALID &&
              ama_ml_dsa_verify_ctx(bad, buf, 1, NULL, 0, buf, 64, buf) == INVALID,
          "ML-DSA: every entry point refuses an unknown parameter set");
}

/* ------------------------------------------------------------------------ */
/* SLH-DSA                                                                   */
/* ------------------------------------------------------------------------ */

extern ama_error_t (*ama_sphincs_randombytes_hook)(uint8_t *buf, size_t len);

static void slh_dsa_guards(ama_slhdsa_param_set_t ps, const char *name,
                           size_t pk_bytes, size_t sk_bytes, size_t sig_bytes) {
    static uint8_t pk[64], sk[128], sig[49856], ctx[256], addrnd[32];
    uint8_t seed[3][32];
    const uint8_t msg[3] = {'x', 'y', 'z'};
    size_t sig_len;

    memset(seed, 0x51, sizeof seed);
    memset(ctx, 0x53, sizeof ctx);
    memset(addrnd, 0x55, sizeof addrnd);
    if (ama_slhdsa_keygen_from_seed(ps, seed[0], seed[1], seed[2], pk, sk) != AMA_SUCCESS) {
        CHECK(0, "%s: keygen from seed", name);
        return;
    }
    (void)pk_bytes;
    (void)sk_bytes;

    /* PIN: |ctx| = 256.  Every entry point builds the same prefix, and each
     * is checked, because each calls the builder itself. */
    sig_len = sizeof sig;
    CHECK(ama_slhdsa_sign(ps, sig, &sig_len, msg, 3, ctx, 256, sk) == INVALID &&
              ama_slhdsa_sign_deterministic(ps, sig, &sig_len, msg, 3, ctx, 256, sk) ==
                  INVALID &&
              ama_slhdsa_sign_addrnd(ps, sig, &sig_len, msg, 3, ctx, 256, addrnd, sk) ==
                  INVALID &&
              ama_slhdsa_verify(ps, sig, sig_bytes, msg, 3, ctx, 256, pk) == INVALID,
          "%s: sign, deterministic sign, addrnd sign and verify refuse a 256-octet context",
          name);
    CHECK(ama_slhdsa_sign(ps, sig, &sig_len, msg, 3, NULL, 1, sk) == INVALID &&
              ama_slhdsa_verify(ps, sig, sig_bytes, msg, 3, NULL, 1, pk) == INVALID,
          "%s: a NULL context with a non-zero length is refused", name);

    /* A NULL message is the empty message only when its length is 0. */
    sig_len = sizeof sig;
    CHECK(ama_slhdsa_sign(ps, sig, &sig_len, NULL, 1, NULL, 0, sk) == INVALID &&
              ama_slhdsa_sign_deterministic(ps, sig, &sig_len, NULL, 1, NULL, 0, sk) ==
                  INVALID &&
              ama_slhdsa_sign_addrnd(ps, sig, &sig_len, NULL, 1, NULL, 0, addrnd, sk) ==
                  INVALID &&
              ama_slhdsa_verify(ps, sig, sig_bytes, NULL, 1, NULL, 0, pk) == INVALID,
          "%s: a NULL message with a non-zero length is refused everywhere", name);

    /* The signature buffer is reported, not overrun. */
    {
        int ok = 1;
        sig_len = sig_bytes - 1;
        ok &= ama_slhdsa_sign(ps, sig, &sig_len, msg, 3, NULL, 0, sk) == INVALID &&
              sig_len == sig_bytes;
        sig_len = sig_bytes - 1;
        ok &= ama_slhdsa_sign_deterministic(ps, sig, &sig_len, msg, 3, NULL, 0, sk) ==
                  INVALID &&
              sig_len == sig_bytes;
        sig_len = sig_bytes - 1;
        ok &= ama_slhdsa_sign_addrnd(ps, sig, &sig_len, msg, 3, NULL, 0, addrnd, sk) ==
                  INVALID &&
              sig_len == sig_bytes;
        CHECK(ok, "%s: every signer refuses a short buffer and reports the size", name);
    }

    sig_len = sizeof sig;
    CHECK(ama_slhdsa_sign(ps, NULL, &sig_len, msg, 3, NULL, 0, sk) == INVALID &&
              ama_slhdsa_sign(ps, sig, NULL, msg, 3, NULL, 0, sk) == INVALID &&
              ama_slhdsa_sign(ps, sig, &sig_len, msg, 3, NULL, 0, NULL) == INVALID &&
              ama_slhdsa_sign_deterministic(ps, NULL, &sig_len, msg, 3, NULL, 0, sk) ==
                  INVALID &&
              ama_slhdsa_sign_deterministic(ps, sig, &sig_len, msg, 3, NULL, 0, NULL) ==
                  INVALID &&
              ama_slhdsa_sign_addrnd(ps, sig, &sig_len, msg, 3, NULL, 0, NULL, sk) ==
                  INVALID &&
              ama_slhdsa_sign_addrnd(ps, NULL, &sig_len, msg, 3, NULL, 0, addrnd, sk) ==
                  INVALID &&
              ama_slhdsa_verify(ps, NULL, sig_bytes, msg, 3, NULL, 0, pk) == INVALID &&
              ama_slhdsa_verify(ps, sig, sig_bytes, msg, 3, NULL, 0, NULL) == INVALID,
          "%s: sign and verify refuse each NULL argument", name);
    CHECK(ama_slhdsa_keygen(ps, NULL, sk) == INVALID &&
              ama_slhdsa_keygen(ps, pk, NULL) == INVALID &&
              ama_slhdsa_keygen_from_seed(ps, NULL, seed[1], seed[2], pk, sk) == INVALID &&
              ama_slhdsa_keygen_from_seed(ps, seed[0], NULL, seed[2], pk, sk) == INVALID &&
              ama_slhdsa_keygen_from_seed(ps, seed[0], seed[1], NULL, pk, sk) == INVALID &&
              ama_slhdsa_keygen_from_seed(ps, seed[0], seed[1], seed[2], NULL, sk) ==
                  INVALID &&
              ama_slhdsa_keygen_from_seed(ps, seed[0], seed[1], seed[2], pk, NULL) ==
                  INVALID,
          "%s: keygen refuses each NULL argument", name);
}

static void slh_dsa_unknown_set_and_legacy(void) {
    const ama_slhdsa_param_set_t bad = (ama_slhdsa_param_set_t)7;
    static uint8_t pk[64], sk[128];
    uint8_t buf[64] = {0};
    size_t len = sizeof buf;

    CHECK(ama_slhdsa_keygen(bad, pk, sk) == INVALID &&
              ama_slhdsa_keygen_from_seed(bad, buf, buf, buf, pk, sk) == INVALID &&
              ama_slhdsa_sign(bad, buf, &len, buf, 1, NULL, 0, sk) == INVALID &&
              ama_slhdsa_sign_deterministic(bad, buf, &len, buf, 1, NULL, 0, sk) == INVALID &&
              ama_slhdsa_sign_addrnd(bad, buf, &len, buf, 1, NULL, 0, buf, sk) == INVALID &&
              ama_slhdsa_verify(bad, buf, 64, buf, 1, NULL, 0, pk) == INVALID,
          "SLH-DSA: every entry point refuses an unknown parameter set");

    /* PIN: every SLH-DSA draw fails closed -- the FIPS 205 key generation and
     * hedged signing, and the legacy SHA2-256f keypair and signer.  Until
     * 2026-09-26 only the legacy pair consulted the test hook, so the first
     * two exits could not be reached.  Mutation: delete any one check. */
    {
        static uint8_t sig[AMA_SLHDSA_SHA2_256F_SIGNATURE_BYTES];
        uint8_t seed[32];
        const uint8_t msg[1] = {'m'};
        size_t sig_len = sizeof sig;
        memset(seed, 0x57, sizeof seed);
        if (ama_slhdsa_keygen_from_seed(AMA_SLHDSA_SHA2_256F, seed, seed, seed, pk, sk) !=
            AMA_SUCCESS) {
            CHECK(0, "SLH-DSA: keygen from seed");
            return;
        }
        ama_sphincs_randombytes_hook = failing_randombytes;
        CHECK(ama_slhdsa_keygen(AMA_SLHDSA_SHA2_256F, pk, sk) == AMA_ERROR_CRYPTO,
              "SLH-DSA: key generation fails closed on a CSPRNG failure");
        CHECK(ama_slhdsa_sign(AMA_SLHDSA_SHA2_256F, sig, &sig_len, msg, 1, NULL, 0, sk) ==
                  AMA_ERROR_CRYPTO,
              "SLH-DSA: hedged signing fails closed on a CSPRNG failure");
        CHECK(ama_sphincs_sign(sig, &sig_len, msg, 1, sk) == AMA_ERROR_CRYPTO,
              "SLH-DSA: the legacy signer fails closed on a CSPRNG failure");
        memset(pk, 0xEE, sizeof pk);
        CHECK(ama_sphincs_keypair(pk, sk) == AMA_ERROR_CRYPTO,
              "SLH-DSA: the legacy keypair fails closed on a CSPRNG failure");
        ama_sphincs_randombytes_hook = NULL;

        /* The legacy pair's own argument guards. */
        sig_len = sizeof sig;
        CHECK(ama_sphincs_keypair(NULL, sk) == INVALID && ama_sphincs_keypair(pk, NULL) == INVALID,
              "SLH-DSA: the legacy keypair refuses each NULL argument");
        CHECK(ama_sphincs_sign(NULL, &sig_len, msg, 1, sk) == INVALID &&
                  ama_sphincs_sign(sig, NULL, msg, 1, sk) == INVALID &&
                  ama_sphincs_sign(sig, &sig_len, NULL, 1, sk) == INVALID &&
                  ama_sphincs_sign(sig, &sig_len, msg, 1, NULL) == INVALID,
              "SLH-DSA: the legacy signer refuses each NULL argument");
        sig_len = sizeof sig - 1;
        CHECK(ama_sphincs_sign(sig, &sig_len, msg, 1, sk) == INVALID && sig_len == sizeof sig,
              "SLH-DSA: the legacy signer refuses a short buffer and reports the size");
        CHECK(ama_sphincs_verify(msg, 1, NULL, sizeof sig, pk) == INVALID &&
                  ama_sphincs_verify(msg, 1, sig, sizeof sig, NULL) == INVALID &&
                  ama_sphincs_verify(NULL, 1, sig, sizeof sig, pk) == INVALID,
              "SLH-DSA: the legacy verifier refuses each NULL argument");
    }
}

/* ------------------------------------------------------------------------ */
/* ECDSA over P-256 / P-384 / P-521                                          */
/* ------------------------------------------------------------------------ */

static void nistp_guards(ama_nist_curve_t curve, const char *name) {
    static uint8_t d[66], pub[132], der[160], raw[132], raw2[132], out[160];
    uint8_t digest[64];
    const size_t nb = ama_nistp_field_bytes(curve);
    size_t der_len, raw_len, out_len;

    memset(digest, 0x5D, sizeof digest);
    if (ama_nistp_keypair(curve, d, pub) != AMA_SUCCESS) {
        CHECK(0, "%s: keypair", name);
        return;
    }
    der_len = sizeof der;
    if (ama_nistp_ecdsa_sign(curve, digest, 32, d, der, &der_len) != AMA_SUCCESS) {
        CHECK(0, "%s: sign", name);
        return;
    }

    /* PIN: a private key outside [1, n-1] is refused, not reduced. */
    {
        uint8_t bad_d[66];
        int ok = 1;
        memset(bad_d, 0x00, nb);
        der_len = sizeof der;
        ok &= ama_nistp_ecdsa_sign(curve, digest, 32, bad_d, der, &der_len) == INVALID;
        ok &= ama_nistp_ecdsa_sign_raw(curve, digest, 32, bad_d, raw) == INVALID;
        memset(bad_d, 0xFF, nb);  /* >= n on every curve */
        der_len = sizeof der;
        ok &= ama_nistp_ecdsa_sign(curve, digest, 32, bad_d, der, &der_len) == INVALID;
        CHECK(ok, "%s: sign refuses a private key of 0 and one >= n", name);
    }

    /* PIN: undefined flag bits are refused, not ignored. */
    der_len = sizeof der;
    CHECK(ama_nistp_ecdsa_sign_ex(curve, digest, 32, d, der, &der_len, 0x4u) == INVALID &&
              ama_nistp_ecdsa_sign_raw_ex(curve, digest, 32, d, raw, 0x80000000u) ==
                  INVALID,
          "%s: sign refuses an undefined flag bit", name);

    /* A good signature to drive the verifiers and converters with. */
    der_len = sizeof der;
    CHECK(ama_nistp_ecdsa_sign(curve, digest, 32, d, der, &der_len) == AMA_SUCCESS,
          "%s: control: sign", name);
    CHECK(ama_nistp_ecdsa_verify_ex(curve, digest, 32, pub, der, der_len, 0x2u) == INVALID &&
              ama_nistp_ecdsa_verify_ex(curve, digest, 32, pub, der, der_len, 0u) ==
                  AMA_SUCCESS,
          "%s: verify refuses an undefined flag bit (control: flags 0 verifies)", name);

    /* PIN: the only digest lengths are 32, 48 and 64 octets.  Stops at the
     * first acceptance, and tries 0 last: with the length check deleted,
     * signing a 0-octet digest does not return (measured), so the order is
     * what turns that mutation into a failure instead of a ctest timeout. */
    {
        static const size_t bad_lengths[] = {20, 31, 33, 63, 0};
        int ok = 1;
        for (size_t i = 0; ok && i < sizeof bad_lengths / sizeof bad_lengths[0]; i++) {
            size_t dl = bad_lengths[i];
            size_t l2 = sizeof out;
            ok = ok && ama_nistp_ecdsa_sign(curve, digest, dl, d, out, &l2) == INVALID;
            ok = ok && ama_nistp_ecdsa_sign_raw(curve, digest, dl, d, raw2) == INVALID;
            ok = ok && ama_nistp_ecdsa_verify(curve, digest, dl, pub, der, der_len) != AMA_SUCCESS;
        }
        CHECK(ok, "%s: sign, raw sign and verify refuse undefined digest lengths", name);
    }

    raw_len = sizeof raw;
    CHECK(ama_nistp_sig_der_to_raw(curve, der, der_len, raw, &raw_len) == AMA_SUCCESS &&
              raw_len == 2 * nb,
          "%s: control: DER converts to raw", name);
    CHECK(ama_nistp_ecdsa_verify_raw(curve, digest, 32, pub, raw, 2 * nb) == AMA_SUCCESS &&
              ama_nistp_ecdsa_verify_raw(curve, digest, 32, pub, raw, 2 * nb - 1) !=
                  AMA_SUCCESS &&
              ama_nistp_ecdsa_verify_raw(curve, digest, 31, pub, raw, 2 * nb) !=
                  AMA_SUCCESS,
          "%s: raw verify refuses a short signature and a bad digest length", name);

    /* PIN: r and s in [1, n-1] on both conversions. */
    {
        int ok = 1;
        memcpy(raw2, raw, 2 * nb);
        memset(raw2, 0x00, nb);                         /* r = 0 */
        out_len = sizeof out;
        ok &= ama_nistp_sig_raw_to_der(curve, raw2, 2 * nb, out, &out_len) == INVALID;
        memcpy(raw2, raw, 2 * nb);
        memset(raw2 + nb, 0xFF, nb);                    /* s >= n */
        out_len = sizeof out;
        ok &= ama_nistp_sig_raw_to_der(curve, raw2, 2 * nb, out, &out_len) == INVALID;
        memcpy(raw2, raw, 2 * nb);
        memset(raw2 + nb, 0x00, nb);                    /* s = 0 */
        out_len = sizeof out;
        ok &= ama_nistp_sig_raw_to_der(curve, raw2, 2 * nb, out, &out_len) == INVALID;
        out_len = sizeof out;
        ok &= ama_nistp_sig_raw_to_der(curve, raw, 2 * nb - 1, out, &out_len) == INVALID;
        CHECK(ok, "%s: raw -> DER refuses r = 0, s = 0, s >= n and a short input", name);
    }
    {
        /* DER with r = 0 and with s = 0: well-formed DER, out-of-range value. */
        uint8_t der_r0[8] = {0x30, 0x06, 0x02, 0x01, 0x00, 0x02, 0x01, 0x01};
        uint8_t der_s0[8] = {0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x00};
        int ok = 1;
        raw_len = sizeof raw2;
        ok &= ama_nistp_sig_der_to_raw(curve, der_r0, 8, raw2, &raw_len) == INVALID;
        raw_len = sizeof raw2;
        ok &= ama_nistp_sig_der_to_raw(curve, der_s0, 8, raw2, &raw_len) == INVALID;
        raw_len = sizeof raw2;
        ok &= ama_nistp_sig_der_to_raw(curve, der, sizeof der, raw2, &raw_len) == INVALID;
        CHECK(ok, "%s: DER -> raw refuses r = 0, s = 0 and an over-long input", name);
    }

    /* Compressing a public key that is not on the curve is refused. */
    {
        uint8_t off_curve[132];
        memcpy(off_curve, pub, 2 * nb);
        off_curve[2 * nb - 1] ^= 1u;
        out_len = sizeof out;
        CHECK(ama_nistp_point_encode(curve, off_curve, 1, out, &out_len) == INVALID,
              "%s: point_encode refuses a public key that is not on the curve", name);
    }
}

extern ama_error_t (*ama_nistp_randombytes_hook)(uint8_t *buf, size_t len);


/* PIN: key generation and hedged signing fail closed on a CSPRNG failure --
 * no key is released and no signature is emitted.  Mutation: delete either
 * `!= AMA_SUCCESS` check in ama_nistp.c -> AMA_SUCCESS over hook bytes. */
static void nistp_csprng_failure(ama_nist_curve_t curve, const char *name) {
    static uint8_t d[66], pub[132], der[160];
    uint8_t digest[32];
    const size_t nb = ama_nistp_field_bytes(curve);
    size_t der_len = sizeof der;
    int scrubbed = 1;

    memset(digest, 0x5D, sizeof digest);
    if (ama_nistp_keypair(curve, d, pub) != AMA_SUCCESS) {
        CHECK(0, "%s: keypair", name);
        return;
    }
    ama_nistp_randombytes_hook = failing_randombytes;
    memset(der, 0xEE, sizeof der);
    CHECK(ama_nistp_ecdsa_sign_hedged(curve, digest, 32, d, der, &der_len) ==
              AMA_ERROR_CRYPTO && der[0] == 0xEE,
          "%s: hedged signing fails closed on a CSPRNG failure, emitting nothing", name);
    CHECK(ama_nistp_keypair(curve, d, pub) == AMA_ERROR_CRYPTO,
          "%s: key generation fails closed on a CSPRNG failure", name);
    for (size_t i = 0; i < nb; i++) scrubbed &= d[i] == 0;
    CHECK(scrubbed, "%s: ... and scrubs the private-key buffer", name);
    ama_nistp_randombytes_hook = NULL;
}

/* Draws served in order: all-zero (the scalar 0), all-0xFF (>= n on every
 * curve), then a valid scalar.  Key generation must reject the first two and
 * keep drawing. */
static int nistp_draw = 0;
static ama_error_t sequenced_randombytes(uint8_t *buf, size_t len) {
    memset(buf, nistp_draw == 0 ? 0x00 : nistp_draw == 1 ? 0xFF : 0x5B, len);
    nistp_draw++;
    return AMA_SUCCESS;
}

/* PIN: rejection sampling and the r >= n half of both converters (the
 * identity rows are SMOKE; see the header). */
static void nistp_edges(ama_nist_curve_t curve, const char *name) {
    static uint8_t d[66], pub[132], der[160], raw[132];
    const size_t nb = ama_nistp_field_bytes(curve);
    size_t len;

    nistp_draw = 0;
    ama_nistp_randombytes_hook = sequenced_randombytes;
    CHECK(ama_nistp_keypair(curve, d, pub) == AMA_SUCCESS && nistp_draw == 3 && d[1] == 0x5B &&
              ama_nistp_pubkey_validate(curve, pub) == AMA_SUCCESS,
          "%s: key generation rejects a zero and an out-of-range draw, then succeeds", name);
    ama_nistp_randombytes_hook = NULL;

    /* The header's verdict for an invalid key is VERIFY_FAILED.  SMOKE: the
     * identity refusal is redundant with the curve equation here. */
    memset(pub, 0, 2 * nb);
    CHECK(ama_nistp_pubkey_validate(curve, pub) == AMA_ERROR_VERIFY_FAILED,
          "%s: the identity (0, 0) is not a valid public key", name);
    pub[2 * nb - 1] = 1;
    CHECK(ama_nistp_pubkey_validate(curve, pub) == AMA_ERROR_VERIFY_FAILED,
          "%s: (0, 1) is not a valid public key", name);
    CHECK(ama_nistp_pubkey_bytes(curve) == 2 * nb, "%s: public-key size", name);

    /* r = 2^(8nb) - 1 >= n, as a positive DER INTEGER (leading 0x00). */
    der[0] = 0x30;
    der[2] = 0x02;
    der[3] = (uint8_t)(nb + 1);
    der[4] = 0x00;
    memset(der + 5, 0xFF, nb);
    der[5 + nb] = 0x02;
    der[6 + nb] = 0x01;
    der[7 + nb] = 0x01;
    {
        size_t body = 6 + nb;          /* 02 len 00 FF.. 02 01 01 */
        size_t der_len;
        if (body < 0x80) {
            der[1] = (uint8_t)body;
            der_len = 2 + body;
        } else {                        /* P-521: one long-form length octet */
            memmove(der + 3, der + 2, body);
            der[1] = 0x81;
            der[2] = (uint8_t)body;
            der_len = 3 + body;
        }
        len = sizeof raw;
        CHECK(ama_nistp_sig_der_to_raw(curve, der, der_len, raw, &len) == INVALID,
              "%s: DER -> raw refuses r >= n", name);
    }
    memset(raw, 0xFF, nb);
    memset(raw + nb, 0x01, nb);
    len = sizeof der;
    CHECK(ama_nistp_sig_raw_to_der(curve, raw, 2 * nb, der, &len) == INVALID,
          "%s: raw -> DER refuses r >= n", name);
}

static void nistp_unknown_curve(void) {
    const ama_nist_curve_t bad = (ama_nist_curve_t)99;
    CHECK(ama_nistp_field_bytes(bad) == 0 && ama_nistp_pubkey_bytes(bad) == 0 &&
              ama_nistp_sig_der_max_len(bad) == 0 && ama_nistp_curve_name(bad) == NULL,
          "NIST P: an unknown curve has no sizes and no name");
}

int main(void) {
    printf("===========================================\n");
    printf("Public-API input guards (INVARIANT-5)\n");
    printf("===========================================\n");

    ml_kem_guards(AMA_ML_KEM_512, "ML-KEM-512");
    ml_kem_guards(AMA_ML_KEM_768, "ML-KEM-768");
    ml_kem_guards(AMA_ML_KEM_1024, "ML-KEM-1024");
    ml_kem_second_coefficient(AMA_ML_KEM_768, "ML-KEM-768");
    ml_kem_csprng_failure(AMA_ML_KEM_1024, "ML-KEM-1024");
    ml_kem_unknown_set();

    ml_dsa_guards(AMA_ML_DSA_44, "ML-DSA-44");
    ml_dsa_guards(AMA_ML_DSA_65, "ML-DSA-65");
    ml_dsa_guards(AMA_ML_DSA_87, "ML-DSA-87");
    ml_dsa_csprng_failure(AMA_ML_DSA_65, "ML-DSA-65");
    ml_dsa_unknown_set();

    slh_dsa_guards(AMA_SLHDSA_SHA2_256F, "SLH-DSA-SHA2-256f",
                   AMA_SLHDSA_SHA2_256F_PUBLIC_KEY_BYTES,
                   AMA_SLHDSA_SHA2_256F_SECRET_KEY_BYTES,
                   AMA_SLHDSA_SHA2_256F_SIGNATURE_BYTES);
    slh_dsa_guards(AMA_SLHDSA_SHAKE_128S, "SLH-DSA-SHAKE-128s",
                   AMA_SLHDSA_SHAKE_128S_PUBLIC_KEY_BYTES,
                   AMA_SLHDSA_SHAKE_128S_SECRET_KEY_BYTES,
                   AMA_SLHDSA_SHAKE_128S_SIGNATURE_BYTES);
    slh_dsa_unknown_set_and_legacy();

    nistp_guards(AMA_NIST_CURVE_P256, "P-256");
    nistp_guards(AMA_NIST_CURVE_P384, "P-384");
    nistp_guards(AMA_NIST_CURVE_P521, "P-521");
    nistp_csprng_failure(AMA_NIST_CURVE_P256, "P-256");
    nistp_csprng_failure(AMA_NIST_CURVE_P521, "P-521");
    nistp_edges(AMA_NIST_CURVE_P256, "P-256");
    nistp_edges(AMA_NIST_CURVE_P384, "P-384");
    nistp_edges(AMA_NIST_CURVE_P521, "P-521");
    nistp_unknown_curve();

    printf("\n%s: %d failure(s)\n", failures ? "FAILED" : "PASSED", failures);
    return failures ? 1 : 0;
}
