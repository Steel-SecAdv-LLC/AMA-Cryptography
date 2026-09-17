/* Copyright (C) 2025-2026 Steel Security Advisors LLC */
/* SPDX-License-Identifier: Apache-2.0 */
/**
 * @file test_slhdsa_context_separation.c
 * @brief FIPS 205 §9 vs §10.2: the shipped API is context-separated, and the
 *        internal interface is reachable only from a test build.
 *
 * WHY THIS TEST EXISTS
 *
 * `ama_sphincs_sign` / `ama_sphincs_verify` and the exported
 * `ama_slhdsa_sign_internal` signed and verified the RAW message with no
 * §10.2 wrapper — they were FIPS 205 §9 `slh_sign_internal` /
 * `slh_verify_internal` under public names, in the shipped shared object.
 * Because `ama_slhdsa_sign` / `ama_slhdsa_verify` sign
 * M' = 0x00 || IntegerToBytes(|ctx|, 1) || ctx || M under the SAME key, the
 * two interfaces cross-verified.  Measured on this tree before the fix, both
 * directions held:
 *
 *     ama_slhdsa_sign(M, ctx = "")      verified by ama_sphincs_verify(00 00 || M)
 *     ama_sphincs_sign(00 01 'x' || M)  verified by ama_slhdsa_verify(M, ctx = "x")
 *
 * so any component that signed caller-influenced bytes through the legacy or
 * the generic (`ama_sign` with AMA_ALG_SPHINCS_256F) API was a signing oracle
 * for FIPS 205 pure signatures on attacker-chosen (ctx, M) pairs.  Those two
 * exact probes are cases 4 and 5 below, as negative assertions.
 *
 * FIPS 205 §9 says the internal functions shall not be exposed to
 * applications other than for testing.  They still exist, because NIST ACVP's
 * `signatureInterface == "internal"` groups are that testing — but only under
 * AMA_TESTING_MODE, declared in src/c/internal/ama_testing_exports.h and
 * absent from every shipped library.  This file is their only caller in the
 * repository, which is why the ACVP internal-interface replay (part B) lives
 * here rather than in tests/test_pqc_kat.py: the Python layer loads the
 * production .so, where those symbols are correctly missing.
 *
 * See INVARIANT-50.
 *
 * Like test_kat and test_ml_kem_acvp_encaps this reads its fixture from the
 * source tree and needs the repository root as its working directory (CMake
 * sets it).
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "ama_cryptography.h"
#include "../../src/c/internal/ama_testing_exports.h"
#include "kat_slot_guard.h"

#define SIGVER_PATH "tests/kat/fips205/SLH-DSA-sigVer-FIPS205.json"

/* The corpus is pretty-printed one JSON key per line; the longest line is the
 * 49856-byte signature as hex plus its key and quotes (99740 bytes measured).
 * 128 KiB leaves room for a re-export with different indentation without
 * silently truncating — a truncated line would be reported as a malformed
 * field, not skipped (see json_hex_field). */
#define LINE_MAX_BYTES 131072u

#define MSG_MAX_BYTES  8192u
/* Deliberately larger than a well-formed signature: the group's "invalid
 * signature - too large" cases carry 49857 bytes, and a scanner that could not
 * hold them would report them malformed and drop the two negative vectors that
 * exercise the length precondition — exactly the cases most worth running. */
#define SIG_MAX_BYTES  (AMA_SLHDSA_SHA2_256F_SIGNATURE_BYTES + 64u)
#define PK_MAX_BYTES   AMA_SLHDSA_SHA2_256F_PUBLIC_KEY_BYTES

static int failures = 0;
static int checks = 0;

static void check(int condition, const char *what) {
    checks++;
    if (!condition) {
        failures++;
        fprintf(stderr, "FAIL: %s\n", what);
    }
}

/* ===========================================================================
 * Part A — the shipped API is context-separated
 * =========================================================================== */

static void part_a_context_separation(void) {
    uint8_t pk[AMA_SPHINCS_256F_PUBLIC_KEY_BYTES];
    uint8_t sk[AMA_SPHINCS_256F_SECRET_KEY_BYTES];
    uint8_t addrnd[32];
    static uint8_t sig_legacy[AMA_SPHINCS_256F_SIGNATURE_BYTES];
    static uint8_t sig_ctx[AMA_SPHINCS_256F_SIGNATURE_BYTES];
    static uint8_t sig_internal[AMA_SPHINCS_256F_SIGNATURE_BYTES];
    static uint8_t probe[64];
    size_t sig_len;
    const uint8_t msg[] = "transfer 1000 to mallory";
    const size_t msg_len = sizeof(msg) - 1;
    size_t i;

    if (ama_sphincs_keypair(pk, sk) != AMA_SUCCESS) {
        fprintf(stderr, "FAIL: ama_sphincs_keypair\n");
        failures++;
        return;
    }

    /* 1. The legacy API and the §10.2 API with the empty context are the same
     *    signature scheme: each one's signature verifies under the other. */
    sig_len = sizeof sig_legacy;
    check(ama_sphincs_sign(sig_legacy, &sig_len, msg, msg_len, sk) == AMA_SUCCESS,
          "ama_sphincs_sign");
    check(ama_slhdsa_verify(AMA_SLHDSA_SHA2_256F, sig_legacy, sig_len,
                            msg, msg_len, NULL, 0, pk) == AMA_SUCCESS,
          "legacy signature verifies under slhdsa_verify(ctx = \"\")");

    sig_len = sizeof sig_ctx;
    check(ama_slhdsa_sign(AMA_SLHDSA_SHA2_256F, sig_ctx, &sig_len,
                          msg, msg_len, NULL, 0, sk) == AMA_SUCCESS,
          "ama_slhdsa_sign(ctx = \"\")");
    check(ama_sphincs_verify(msg, msg_len, sig_ctx, sig_len, pk) == AMA_SUCCESS,
          "slhdsa(ctx = \"\") signature verifies under ama_sphincs_verify");

    /* 2. ama_sphincs_verify_ctx with an empty context is ama_sphincs_verify. */
    check(ama_sphincs_verify_ctx(msg, msg_len, NULL, 0,
                                 sig_legacy, sig_len, pk) == AMA_SUCCESS,
          "ama_sphincs_verify_ctx(ctx = \"\") accepts the legacy signature");

    /* 3. The legacy API really signs the WRAPPED string: the §9 verifier
     *    accepts 0x00 || 0x00 || M and rejects M. */
    probe[0] = 0x00;
    probe[1] = 0x00;
    memcpy(probe + 2, msg, msg_len);
    check(ama_slhdsa_verify_internal(AMA_SLHDSA_SHA2_256F, sig_legacy, sig_len,
                                     probe, msg_len + 2, pk) == AMA_SUCCESS,
          "ama_sphincs_sign signs 0x00 || 0x00 || M");
    check(ama_slhdsa_verify_internal(AMA_SLHDSA_SHA2_256F, sig_legacy, sig_len,
                                     msg, msg_len, pk) == AMA_ERROR_VERIFY_FAILED,
          "ama_sphincs_sign does NOT sign the raw M");

    /* 4. ORACLE PROBE ONE (was: accepted).  A §10.2 signature over (ctx = "", M)
     *    must not be accepted by the legacy verifier as a signature over
     *    0x00 || 0x00 || M.  It was, because the legacy verifier hashed its
     *    argument raw; now the legacy verifier wraps too, so what it hashes is
     *    0x00 || 0x00 || 0x00 || 0x00 || M and the digests differ. */
    check(ama_sphincs_verify(probe, msg_len + 2, sig_ctx, sig_len, pk)
              == AMA_ERROR_VERIFY_FAILED,
          "ORACLE CLOSED: slhdsa_sign(M, ctx=\"\") is not a sphincs_verify(00 00 || M) signature");

    /* 5. ORACLE PROBE TWO (was: accepted).  A legacy signature over the bytes
     *    0x00 || 0x01 || 'x' || M must not be accepted by the §10.2 verifier
     *    as a signature over M under ctx = "x". */
    probe[0] = 0x00;
    probe[1] = 0x01;
    probe[2] = 'x';
    memcpy(probe + 3, msg, msg_len);
    sig_len = sizeof sig_legacy;
    check(ama_sphincs_sign(sig_legacy, &sig_len, probe, msg_len + 3, sk) == AMA_SUCCESS,
          "ama_sphincs_sign over a forged wrapper");
    {
        const uint8_t ctx_x[1] = { 'x' };
        check(ama_slhdsa_verify(AMA_SLHDSA_SHA2_256F, sig_legacy, sig_len,
                                msg, msg_len, ctx_x, 1, pk) == AMA_ERROR_VERIFY_FAILED,
              "ORACLE CLOSED: sphincs_sign(00 01 'x' || M) is not a ctx=\"x\" signature over M");
    }

    /* 6. Distinct contexts stay distinct, and a §9 signature is not a §10.2
     *    signature under any context (the internal interface signs no prefix
     *    at all, so no ctx reproduces it). */
    for (i = 0; i < sizeof addrnd; ++i) addrnd[i] = (uint8_t)(0x5a ^ i);
    sig_len = sizeof sig_internal;
    check(ama_slhdsa_sign_internal(AMA_SLHDSA_SHA2_256F, sig_internal, &sig_len,
                                   msg, msg_len, addrnd, sk) == AMA_SUCCESS,
          "ama_slhdsa_sign_internal");
    check(ama_slhdsa_verify_internal(AMA_SLHDSA_SHA2_256F, sig_internal, sig_len,
                                     msg, msg_len, pk) == AMA_SUCCESS,
          "§9 sign/verify round-trip");
    check(ama_sphincs_verify(msg, msg_len, sig_internal, sig_len, pk)
              == AMA_ERROR_VERIFY_FAILED,
          "a §9 signature is rejected by the shipped verifier");
    check(ama_slhdsa_verify(AMA_SLHDSA_SHA2_256F, sig_internal, sig_len,
                            msg, msg_len, NULL, 0, pk) == AMA_ERROR_VERIFY_FAILED,
          "a §9 signature is rejected by slhdsa_verify(ctx = \"\")");

    /* 7. ama_slhdsa_sign_addrnd is §10.2, not §9: with the same addrnd it
     *    reproduces the deterministic-style signature over the WRAPPED string,
     *    and it verifies through the context API under the context it was
     *    given — never under a different one. */
    {
        const uint8_t ctx_a[3] = { 'a', 'p', 'p' };
        static uint8_t sig_a[AMA_SPHINCS_256F_SIGNATURE_BYTES];
        size_t len_a = sizeof sig_a;
        check(ama_slhdsa_sign_addrnd(AMA_SLHDSA_SHA2_256F, sig_a, &len_a,
                                     msg, msg_len, ctx_a, sizeof ctx_a,
                                     addrnd, sk) == AMA_SUCCESS,
              "ama_slhdsa_sign_addrnd");
        check(ama_slhdsa_verify(AMA_SLHDSA_SHA2_256F, sig_a, len_a,
                                msg, msg_len, ctx_a, sizeof ctx_a, pk) == AMA_SUCCESS,
              "sign_addrnd verifies under its own context");
        check(ama_slhdsa_verify(AMA_SLHDSA_SHA2_256F, sig_a, len_a,
                                msg, msg_len, NULL, 0, pk) == AMA_ERROR_VERIFY_FAILED,
              "sign_addrnd does not verify under a different context");
        /* Byte-exactness against the §9 core through the wrapper the entry
         * point builds itself: sign_addrnd(M, ctx, addrnd) must equal
         * sign_internal(0x00 || |ctx| || ctx || M, addrnd). */
        probe[0] = 0x00;
        probe[1] = (uint8_t)sizeof ctx_a;
        memcpy(probe + 2, ctx_a, sizeof ctx_a);
        memcpy(probe + 2 + sizeof ctx_a, msg, msg_len);
        sig_len = sizeof sig_internal;
        check(ama_slhdsa_sign_internal(AMA_SLHDSA_SHA2_256F, sig_internal, &sig_len,
                                       probe, msg_len + 2 + sizeof ctx_a,
                                       addrnd, sk) == AMA_SUCCESS,
              "ama_slhdsa_sign_internal over the explicit wrapper");
        check(len_a == sig_len && memcmp(sig_a, sig_internal, sig_len) == 0,
              "sign_addrnd builds exactly the §10.2 wrapper");
    }

    /* 8. The EMPTY MESSAGE is a message.  FIPS 205 is defined over M in B*,
     *    and these entry points used to reject a NULL pointer outright — so
     *    whether a zero-length buffer could be signed depended on whether the
     *    caller's allocator returned NULL for a zero-byte request. */
    {
        static uint8_t sig_empty[AMA_SPHINCS_256F_SIGNATURE_BYTES];
        static uint8_t sig_empty2[AMA_SPHINCS_256F_SIGNATURE_BYTES];
        const uint8_t nonnull[1] = { 0 };
        size_t len_e = sizeof sig_empty;
        size_t len_e2 = sizeof sig_empty2;

        check(ama_slhdsa_sign(AMA_SLHDSA_SHA2_256F, sig_empty, &len_e,
                              NULL, 0, NULL, 0, sk) == AMA_SUCCESS,
              "ama_slhdsa_sign accepts (NULL, 0) as the empty message");
        check(ama_slhdsa_verify(AMA_SLHDSA_SHA2_256F, sig_empty, len_e,
                                NULL, 0, NULL, 0, pk) == AMA_SUCCESS,
              "ama_slhdsa_verify accepts (NULL, 0) as the empty message");
        /* (NULL, 0) and (ptr, 0) must be the same message. */
        check(ama_slhdsa_verify(AMA_SLHDSA_SHA2_256F, sig_empty, len_e,
                                nonnull, 0, NULL, 0, pk) == AMA_SUCCESS,
              "(NULL, 0) and (ptr, 0) are the same empty message");
        check(ama_slhdsa_sign_deterministic(AMA_SLHDSA_SHA2_256F, sig_empty2, &len_e2,
                                            NULL, 0, NULL, 0, sk) == AMA_SUCCESS,
              "ama_slhdsa_sign_deterministic accepts the empty message");
        check(ama_slhdsa_verify(AMA_SLHDSA_SHA2_256F, sig_empty2, len_e2,
                                NULL, 0, NULL, 0, pk) == AMA_SUCCESS,
              "the deterministic empty-message signature verifies");
        len_e = sizeof sig_empty;
        check(ama_sphincs_sign(sig_empty, &len_e, NULL, 0, sk) == AMA_SUCCESS,
              "ama_sphincs_sign accepts the empty message");
        check(ama_sphincs_verify(NULL, 0, sig_empty, len_e, pk) == AMA_SUCCESS,
              "ama_sphincs_verify accepts the empty message");
        check(ama_slhdsa_verify(AMA_SLHDSA_SHA2_256F, sig_empty, len_e,
                                NULL, 0, NULL, 0, pk) == AMA_SUCCESS,
              "the legacy empty-message signature is the §10.2 ctx=\"\" one");

        /* A NULL pointer with a NON-zero length is still a caller bug. */
        len_e = sizeof sig_empty;
        check(ama_slhdsa_sign(AMA_SLHDSA_SHA2_256F, sig_empty, &len_e,
                              NULL, 1, NULL, 0, sk) == AMA_ERROR_INVALID_PARAM,
              "(NULL, nonzero) is still rejected by ama_slhdsa_sign");
        check(ama_slhdsa_verify(AMA_SLHDSA_SHA2_256F, sig_empty, len_e,
                                NULL, 1, NULL, 0, pk) == AMA_ERROR_INVALID_PARAM,
              "(NULL, nonzero) is still rejected by ama_slhdsa_verify");
        len_e = sizeof sig_empty;
        check(ama_sphincs_sign(sig_empty, &len_e, NULL, 1, sk) == AMA_ERROR_INVALID_PARAM,
              "(NULL, nonzero) is still rejected by ama_sphincs_sign");
    }

    ama_secure_memzero(sk, sizeof sk);
    ama_secure_memzero(addrnd, sizeof addrnd);
}

/* ===========================================================================
 * Part B — NIST ACVP SLH-DSA-sigVer, signatureInterface == "internal"
 *
 * These vectors sign the raw message with no wrapper, so they can only be
 * replayed through the §9 interface.  They ran in tests/test_pqc_kat.py via
 * ama_sphincs_verify for as long as that entry point WAS the §9 verifier;
 * they belong here now that it is not.
 * =========================================================================== */

static int hex_nibble(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

/* Match `"<key>": "<hex>"` on a single line and decode the hex.
 * Returns 1 on a match that fit, 0 for "not this key", -1 for a match that was
 * malformed or did not fit — never silently skipped, because a vector that
 * quietly fails to load is a vector that quietly stops being checked. */
static int json_hex_field(const char *line, const char *key,
                          uint8_t *out, size_t out_max, size_t *out_len) {
    const char *p = line;
    size_t n;

    while (*p == ' ' || *p == '\t') p++;
    if (*p != '"') return 0;
    p++;
    n = strlen(key);
    if (strncmp(p, key, n) != 0 || p[n] != '"') return 0;
    p += n + 1;
    if (*p != ':') return -1;
    p++;
    while (*p == ' ') p++;
    if (*p != '"') return -1;
    p++;

    *out_len = 0;
    while (*p && *p != '"') {
        int hi = hex_nibble(p[0]);
        int lo = (p[1] != '\0') ? hex_nibble(p[1]) : -1;
        if (hi < 0 || lo < 0) return -1;
        if (*out_len >= out_max) return -1;
        out[(*out_len)++] = (uint8_t)((hi << 4) | lo);
        p += 2;
    }
    if (*p != '"') return -1;   /* unterminated => the line was truncated */
    return 1;
}

/* Match `"<key>": "<value>"` for a plain (non-hex) string. */
static int json_str_field(const char *line, const char *key,
                          char *out, size_t out_max) {
    const char *p = line;
    size_t n, i = 0;

    while (*p == ' ' || *p == '\t') p++;
    if (*p != '"') return 0;
    p++;
    n = strlen(key);
    if (strncmp(p, key, n) != 0 || p[n] != '"') return 0;
    p += n + 1;
    if (*p != ':') return -1;
    p++;
    while (*p == ' ') p++;
    if (*p != '"') return -1;
    p++;
    while (*p && *p != '"') {
        if (i + 1 >= out_max) return -1;
        out[i++] = *p++;
    }
    if (*p != '"') return -1;
    out[i] = '\0';
    return 1;
}

static int part_b_acvp_internal_sigver(void) {
    static char line[LINE_MAX_BYTES];
    static uint8_t pk[PK_MAX_BYTES], msg[MSG_MAX_BYTES], sig[SIG_MAX_BYTES];
    static char sbuf[64];
    size_t pk_len = 0, msg_len = 0, sig_len = 0;
    int in_target_group = 0, param_ok = 0, iface_ok = 0;
    int have_pk = 0, have_msg = 0;
    int expect_pass = 0, have_expect = 0;
    int tcid = 0, cases = 0, malformed = 0;
    FILE *f;

    f = fopen(SIGVER_PATH, "r");
    if (!f) {
        fprintf(stderr, "FAIL: cannot open %s (run from the repository root)\n",
                SIGVER_PATH);
        return 1;
    }
    printf("NIST ACVP SLH-DSA-SHA2-256f sigVer, internal interface (%s)\n",
           SIGVER_PATH);

    while (fgets(line, sizeof line, f)) {
        int rc;

        /* A new group resets the selector: the file interleaves twelve
         * parameter sets and both interfaces. */
        if (strstr(line, "\"tgId\"") != NULL) {
            param_ok = iface_ok = in_target_group = 0;
            continue;
        }
        rc = json_str_field(line, "parameterSet", sbuf, sizeof sbuf);
        if (rc == 1) {
            param_ok = (strcmp(sbuf, "SLH-DSA-SHA2-256f") == 0);
            in_target_group = param_ok && iface_ok;
            continue;
        }
        rc = json_str_field(line, "signatureInterface", sbuf, sizeof sbuf);
        if (rc == 1) {
            iface_ok = (strcmp(sbuf, "internal") == 0);
            in_target_group = param_ok && iface_ok;
            continue;
        }
        if (!in_target_group) continue;

        if (sscanf(line, " \"tcId\": %d", &tcid) == 1) {
            have_pk = have_msg = have_expect = 0;
            continue;
        }
        if (strstr(line, "\"testPassed\"") != NULL) {
            expect_pass = (strstr(line, "true") != NULL);
            have_expect = 1;
            continue;
        }
        rc = json_hex_field(line, "pk", pk, sizeof pk, &pk_len);
        if (rc != 0) { if (rc < 0) malformed++; else have_pk = 1; continue; }
        rc = json_hex_field(line, "message", msg, sizeof msg, &msg_len);
        if (rc != 0) { if (rc < 0) malformed++; else have_msg = 1; continue; }
        rc = json_hex_field(line, "signature", sig, sizeof sig, &sig_len);
        if (rc == 0) continue;
        if (rc < 0) { malformed++; continue; }

        /* "signature" is the last field of a case, so everything is loaded. */
        if (!have_pk || !have_msg || !have_expect) {
            fprintf(stderr, "FAIL: tcId %d incomplete (pk=%d msg=%d passed=%d)\n",
                    tcid, have_pk, have_msg, have_expect);
            failures++;
            continue;
        }
        cases++;
        {
            ama_error_t vrc = ama_slhdsa_verify_internal(AMA_SLHDSA_SHA2_256F,
                                                         sig, sig_len,
                                                         msg, msg_len, pk);
            int got = (vrc == AMA_SUCCESS);
            checks++;
            if (got != expect_pass) {
                failures++;
                fprintf(stderr, "FAIL: ACVP tcId %d: expected %s, got %s (rc=%d)\n",
                        tcid, expect_pass ? "valid" : "invalid",
                        got ? "valid" : "invalid", (int)vrc);
            }
        }
    }
    fclose(f);

    if (malformed != 0) {
        fprintf(stderr, "FAIL: %d malformed/oversized field(s) in %s — the "
                        "scanner must read every case or say so\n",
                malformed, SIGVER_PATH);
        failures++;
    }
    /* Non-vacuity: the group ACVP publishes for this parameter set has 14
     * cases.  An emptied or re-shaped corpus must be a failure, not a silent
     * "0 vectors checked, all passed". */
    if (cases < 14) {
        fprintf(stderr, "FAIL: only %d internal-interface vector(s) replayed; "
                        "expected at least 14\n", cases);
        failures++;
    }
    printf("    %d internal-interface vectors replayed\n", cases);
    return 0;
}

/* ===========================================================================
 * Part C — argument-validation matrix (coverage triage, 2026-09-17)
 *
 * Branch-coverage measurement showed every NULL-pointer leg, the unknown-
 * parameter-set leg, the ctx_len > 255 leg, the short-buffer legs and the
 * CSPRNG-failure legs of the ten entry points untaken: the guards existed
 * but nothing drove them.  Each check below flips exactly one argument.
 *
 * The empty-message signing at the end is behavioural, not a rejection:
 * FIPS 205 defines M ∈ B*, (NULL, 0) is the empty message, and the SHA2
 * H_msg path has a memcpy that is legitimately SKIPPED only when
 * message_len == 0 — an arc no other test reaches.
 * =========================================================================== */
static ama_error_t failing_randombytes(uint8_t *buf, size_t len) {
    memset(buf, 0, len);
    return AMA_ERROR_CRYPTO;
}

/* Test-only KAT hook, defined in src/c/ama_slhdsa.c under AMA_TESTING_MODE;
 * declared the same way tests/c/test_kat.c declares it. */
extern ama_error_t (*ama_sphincs_randombytes_hook)(uint8_t *buf, size_t len);

static void part_c_argument_validation(void) {
    static uint8_t sig[AMA_SLHDSA_SHA2_256F_SIGNATURE_BYTES];
    static uint8_t pk[AMA_SLHDSA_SHA2_256F_PUBLIC_KEY_BYTES];
    static uint8_t sk[AMA_SLHDSA_SHA2_256F_SECRET_KEY_BYTES];
    const ama_slhdsa_param_set_t bad_ps = (ama_slhdsa_param_set_t)99;
    const uint8_t msg[] = "part C";
    const size_t msg_len = sizeof(msg) - 1;
    uint8_t seed[32], addrnd[32];
    size_t sig_len;
    ama_error_t rc;

    printf("  part C: argument-validation matrix\n");
    memset(seed, 0x42, sizeof seed);
    memset(addrnd, 0x24, sizeof addrnd);

    /* --- keygen legs ------------------------------------------------------ */
    check(ama_slhdsa_keygen(bad_ps, pk, sk) == AMA_ERROR_INVALID_PARAM,
          "keygen refuses an unknown parameter set");
    check(ama_slhdsa_keygen(AMA_SLHDSA_SHA2_256F, NULL, sk) == AMA_ERROR_INVALID_PARAM,
          "keygen refuses a NULL pk");
    check(ama_slhdsa_keygen(AMA_SLHDSA_SHA2_256F, pk, NULL) == AMA_ERROR_INVALID_PARAM,
          "keygen refuses a NULL sk");
    check(ama_slhdsa_keygen_from_seed(bad_ps, seed, seed, seed, pk, sk)
              == AMA_ERROR_INVALID_PARAM,
          "keygen_from_seed refuses an unknown parameter set");
    check(ama_slhdsa_keygen_from_seed(AMA_SLHDSA_SHA2_256F, NULL, seed, seed, pk, sk)
              == AMA_ERROR_INVALID_PARAM, "keygen_from_seed refuses a NULL sk_seed");
    check(ama_slhdsa_keygen_from_seed(AMA_SLHDSA_SHA2_256F, seed, NULL, seed, pk, sk)
              == AMA_ERROR_INVALID_PARAM, "keygen_from_seed refuses a NULL sk_prf");
    check(ama_slhdsa_keygen_from_seed(AMA_SLHDSA_SHA2_256F, seed, seed, NULL, pk, sk)
              == AMA_ERROR_INVALID_PARAM, "keygen_from_seed refuses a NULL pk_seed");
    check(ama_slhdsa_keygen_from_seed(AMA_SLHDSA_SHA2_256F, seed, seed, seed, NULL, sk)
              == AMA_ERROR_INVALID_PARAM, "keygen_from_seed refuses a NULL pk");
    check(ama_slhdsa_keygen_from_seed(AMA_SLHDSA_SHA2_256F, seed, seed, seed, pk, NULL)
              == AMA_ERROR_INVALID_PARAM, "keygen_from_seed refuses a NULL sk");

    /* A real deterministic keypair for everything below. */
    rc = ama_slhdsa_keygen_from_seed(AMA_SLHDSA_SHA2_256F, seed, seed, seed, pk, sk);
    check(rc == AMA_SUCCESS, "keygen_from_seed produced the part C keypair");

    /* --- hedged sign legs ------------------------------------------------- */
    sig_len = sizeof sig;
    check(ama_slhdsa_sign(bad_ps, sig, &sig_len, msg, msg_len, NULL, 0, sk)
              == AMA_ERROR_INVALID_PARAM, "sign refuses an unknown parameter set");
    check(ama_slhdsa_sign(AMA_SLHDSA_SHA2_256F, NULL, &sig_len, msg, msg_len,
                          NULL, 0, sk) == AMA_ERROR_INVALID_PARAM,
          "sign refuses a NULL signature");
    check(ama_slhdsa_sign(AMA_SLHDSA_SHA2_256F, sig, NULL, msg, msg_len,
                          NULL, 0, sk) == AMA_ERROR_INVALID_PARAM,
          "sign refuses a NULL signature_len");
    check(ama_slhdsa_sign(AMA_SLHDSA_SHA2_256F, sig, &sig_len, msg, msg_len,
                          NULL, 0, NULL) == AMA_ERROR_INVALID_PARAM,
          "sign refuses a NULL sk");
    check(ama_slhdsa_sign(AMA_SLHDSA_SHA2_256F, sig, &sig_len, NULL, msg_len,
                          NULL, 0, sk) == AMA_ERROR_INVALID_PARAM,
          "sign refuses a NULL message with nonzero length");
    check(ama_slhdsa_sign(AMA_SLHDSA_SHA2_256F, sig, &sig_len, msg, msg_len,
                          NULL, 1, sk) == AMA_ERROR_INVALID_PARAM,
          "sign refuses a NULL ctx with nonzero length");
    {
        static uint8_t big_ctx[256];
        sig_len = sizeof sig;
        check(ama_slhdsa_sign(AMA_SLHDSA_SHA2_256F, sig, &sig_len, msg, msg_len,
                              big_ctx, sizeof big_ctx, sk) == AMA_ERROR_INVALID_PARAM,
              "sign refuses ctx_len > 255");
    }
    sig_len = AMA_SLHDSA_SHA2_256F_SIGNATURE_BYTES - 1;
    check(ama_slhdsa_sign(AMA_SLHDSA_SHA2_256F, sig, &sig_len, msg, msg_len,
                          NULL, 0, sk) == AMA_ERROR_INVALID_PARAM,
          "sign refuses a short signature buffer");
    check(sig_len == AMA_SLHDSA_SHA2_256F_SIGNATURE_BYTES,
          "a short-buffer rejection reports the required size");

    /* --- deterministic and addrnd sign legs -------------------------------- */
    sig_len = sizeof sig;
    check(ama_slhdsa_sign_deterministic(bad_ps, sig, &sig_len, msg, msg_len,
                                        NULL, 0, sk) == AMA_ERROR_INVALID_PARAM,
          "sign_deterministic refuses an unknown parameter set");
    check(ama_slhdsa_sign_deterministic(AMA_SLHDSA_SHA2_256F, NULL, &sig_len,
                                        msg, msg_len, NULL, 0, sk)
              == AMA_ERROR_INVALID_PARAM, "sign_deterministic refuses a NULL signature");
    check(ama_slhdsa_sign_deterministic(AMA_SLHDSA_SHA2_256F, sig, NULL,
                                        msg, msg_len, NULL, 0, sk)
              == AMA_ERROR_INVALID_PARAM, "sign_deterministic refuses a NULL signature_len");
    check(ama_slhdsa_sign_deterministic(AMA_SLHDSA_SHA2_256F, sig, &sig_len,
                                        NULL, msg_len, NULL, 0, sk)
              == AMA_ERROR_INVALID_PARAM,
          "sign_deterministic refuses a NULL message with nonzero length");
    sig_len = AMA_SLHDSA_SHA2_256F_SIGNATURE_BYTES - 1;
    check(ama_slhdsa_sign_deterministic(AMA_SLHDSA_SHA2_256F, sig, &sig_len,
                                        msg, msg_len, NULL, 0, sk)
              == AMA_ERROR_INVALID_PARAM,
          "sign_deterministic refuses a short signature buffer");

    sig_len = sizeof sig;
    check(ama_slhdsa_sign_addrnd(bad_ps, sig, &sig_len, msg, msg_len,
                                 NULL, 0, addrnd, sk) == AMA_ERROR_INVALID_PARAM,
          "sign_addrnd refuses an unknown parameter set");
    check(ama_slhdsa_sign_addrnd(AMA_SLHDSA_SHA2_256F, NULL, &sig_len, msg,
                                 msg_len, NULL, 0, addrnd, sk)
              == AMA_ERROR_INVALID_PARAM, "sign_addrnd refuses a NULL signature");
    check(ama_slhdsa_sign_addrnd(AMA_SLHDSA_SHA2_256F, sig, NULL, msg,
                                 msg_len, NULL, 0, addrnd, sk)
              == AMA_ERROR_INVALID_PARAM, "sign_addrnd refuses a NULL signature_len");
    check(ama_slhdsa_sign_addrnd(AMA_SLHDSA_SHA2_256F, sig, &sig_len, msg,
                                 msg_len, NULL, 0, NULL, sk)
              == AMA_ERROR_INVALID_PARAM, "sign_addrnd refuses a NULL addrnd");
    check(ama_slhdsa_sign_addrnd(AMA_SLHDSA_SHA2_256F, sig, &sig_len, msg,
                                 msg_len, NULL, 0, addrnd, NULL)
              == AMA_ERROR_INVALID_PARAM, "sign_addrnd refuses a NULL sk");
    check(ama_slhdsa_sign_addrnd(AMA_SLHDSA_SHA2_256F, sig, &sig_len, NULL,
                                 msg_len, NULL, 0, addrnd, sk)
              == AMA_ERROR_INVALID_PARAM,
          "sign_addrnd refuses a NULL message with nonzero length");
    sig_len = AMA_SLHDSA_SHA2_256F_SIGNATURE_BYTES - 1;
    check(ama_slhdsa_sign_addrnd(AMA_SLHDSA_SHA2_256F, sig, &sig_len, msg,
                                 msg_len, NULL, 0, addrnd, sk)
              == AMA_ERROR_INVALID_PARAM,
          "sign_addrnd refuses a short signature buffer");

    /* --- verify legs -------------------------------------------------------- */
    check(ama_slhdsa_verify(bad_ps, sig, sizeof sig, msg, msg_len, NULL, 0, pk)
              == AMA_ERROR_INVALID_PARAM, "verify refuses an unknown parameter set");
    check(ama_slhdsa_verify(AMA_SLHDSA_SHA2_256F, NULL, sizeof sig, msg, msg_len,
                            NULL, 0, pk) == AMA_ERROR_INVALID_PARAM,
          "verify refuses a NULL signature");
    check(ama_slhdsa_verify(AMA_SLHDSA_SHA2_256F, sig, sizeof sig, msg, msg_len,
                            NULL, 0, NULL) == AMA_ERROR_INVALID_PARAM,
          "verify refuses a NULL pk");
    check(ama_slhdsa_verify(AMA_SLHDSA_SHA2_256F, sig, sizeof sig, NULL, msg_len,
                            NULL, 0, pk) == AMA_ERROR_INVALID_PARAM,
          "verify refuses a NULL message with nonzero length");
    check(ama_slhdsa_verify(AMA_SLHDSA_SHA2_256F, sig, sizeof sig, msg, msg_len,
                            NULL, 1, pk) == AMA_ERROR_INVALID_PARAM,
          "verify refuses a NULL ctx with nonzero length");

    /* --- legacy SPHINCS+ wrapper legs --------------------------------------- */
    check(ama_sphincs_keypair(NULL, sk) == AMA_ERROR_INVALID_PARAM,
          "sphincs_keypair refuses a NULL pk");
    check(ama_sphincs_keypair(pk, NULL) == AMA_ERROR_INVALID_PARAM,
          "sphincs_keypair refuses a NULL sk");
    sig_len = sizeof sig;
    check(ama_sphincs_sign(NULL, &sig_len, msg, msg_len, sk)
              == AMA_ERROR_INVALID_PARAM, "sphincs_sign refuses a NULL signature");
    check(ama_sphincs_sign(sig, NULL, msg, msg_len, sk)
              == AMA_ERROR_INVALID_PARAM, "sphincs_sign refuses a NULL signature_len");
    check(ama_sphincs_sign(sig, &sig_len, msg, msg_len, NULL)
              == AMA_ERROR_INVALID_PARAM, "sphincs_sign refuses a NULL sk");
    check(ama_sphincs_sign(sig, &sig_len, NULL, msg_len, sk)
              == AMA_ERROR_INVALID_PARAM,
          "sphincs_sign refuses a NULL message with nonzero length");
    sig_len = AMA_SLHDSA_SHA2_256F_SIGNATURE_BYTES - 1;
    check(ama_sphincs_sign(sig, &sig_len, msg, msg_len, sk)
              == AMA_ERROR_INVALID_PARAM,
          "sphincs_sign refuses a short signature buffer");
    check(ama_sphincs_verify(msg, msg_len, NULL, sizeof sig, pk)
              == AMA_ERROR_INVALID_PARAM, "sphincs_verify refuses a NULL signature");
    check(ama_sphincs_verify(msg, msg_len, sig, sizeof sig, NULL)
              == AMA_ERROR_INVALID_PARAM, "sphincs_verify refuses a NULL pk");
    check(ama_sphincs_verify(NULL, msg_len, sig, sizeof sig, pk)
              == AMA_ERROR_INVALID_PARAM,
          "sphincs_verify refuses a NULL message with nonzero length");
    {
        static uint8_t big_ctx[256];
        check(ama_sphincs_verify_ctx(msg, msg_len, big_ctx, sizeof big_ctx,
                                     sig, sizeof sig, pk) == AMA_ERROR_INVALID_PARAM,
              "sphincs_verify_ctx refuses ctx_len > 255");
        check(ama_sphincs_verify_ctx(msg, msg_len, NULL, 1,
                                     sig, sizeof sig, pk) == AMA_ERROR_INVALID_PARAM,
              "sphincs_verify_ctx refuses a NULL ctx with nonzero length");
    }

    /* --- CSPRNG failure fails closed (hook-reachable draw sites) ------------ */
    ama_sphincs_randombytes_hook = failing_randombytes;
    check(ama_sphincs_keypair(pk, sk) == AMA_ERROR_CRYPTO,
          "sphincs_keypair fails closed on CSPRNG failure");
    sig_len = sizeof sig;
    check(ama_sphincs_sign(sig, &sig_len, msg, msg_len, sk) == AMA_ERROR_CRYPTO,
          "sphincs_sign fails closed on CSPRNG failure");
    ama_sphincs_randombytes_hook = NULL;

    /* Rebuild the deterministic keypair — the hook test scrambled sk/pk. */
    rc = ama_slhdsa_keygen_from_seed(AMA_SLHDSA_SHA2_256F, seed, seed, seed, pk, sk);
    check(rc == AMA_SUCCESS, "keypair rebuilt after the hook tests");

    /* --- the EMPTY message is signable and verifiable (FIPS 205, M ∈ B*) ---- */
    sig_len = sizeof sig;
    rc = ama_slhdsa_sign_deterministic(AMA_SLHDSA_SHA2_256F, sig, &sig_len,
                                       NULL, 0, NULL, 0, sk);
    check(rc == AMA_SUCCESS, "the empty message signs");
    check(sig_len == AMA_SLHDSA_SHA2_256F_SIGNATURE_BYTES,
          "the empty-message signature has the advertised length");
    check(ama_slhdsa_verify(AMA_SLHDSA_SHA2_256F, sig, sig_len, NULL, 0,
                            NULL, 0, pk) == AMA_SUCCESS,
          "the empty-message signature verifies");
    check(ama_slhdsa_verify(AMA_SLHDSA_SHA2_256F, sig, sig_len - 1, NULL, 0,
                            NULL, 0, pk) == AMA_ERROR_VERIFY_FAILED,
          "a truncated signature is refused");
    sig[100] ^= 0x01;
    check(ama_slhdsa_verify(AMA_SLHDSA_SHA2_256F, sig, sig_len, NULL, 0,
                            NULL, 0, pk) == AMA_ERROR_VERIFY_FAILED,
          "a corrupted empty-message signature is refused");

    /* Success paths of the hedged FIPS 205 §10.2 wrappers.  Everything above
     * exercises rejection legs; the all-arguments-valid arcs of
     * ama_slhdsa_keygen / ama_slhdsa_sign / ama_slhdsa_sign_addrnd were
     * otherwise only reachable from the Python suite (production library),
     * not this instrumented C binary. */
    {
        uint8_t hpk[AMA_SLHDSA_SHA2_256F_PUBLIC_KEY_BYTES];
        uint8_t hsk[AMA_SLHDSA_SHA2_256F_SECRET_KEY_BYTES];
        const uint8_t hmsg[4] = {0x68, 0x65, 0x64, 0x67};
        check(ama_slhdsa_keygen(AMA_SLHDSA_SHA2_256F, hpk, hsk) == AMA_SUCCESS,
              "hedged keygen succeeds with valid arguments");

        sig_len = sizeof(sig);
        check(ama_slhdsa_sign(AMA_SLHDSA_SHA2_256F, sig, &sig_len,
                              hmsg, sizeof(hmsg), NULL, 0, hsk) == AMA_SUCCESS,
              "hedged sign succeeds with valid arguments");
        check(sig_len == AMA_SLHDSA_SHA2_256F_SIGNATURE_BYTES,
              "hedged sign reports the advertised signature length");
        check(ama_slhdsa_verify(AMA_SLHDSA_SHA2_256F, sig, sig_len,
                                hmsg, sizeof(hmsg), NULL, 0, hpk) == AMA_SUCCESS,
              "the hedged signature verifies");

        sig_len = sizeof(sig);
        check(ama_slhdsa_sign_addrnd(AMA_SLHDSA_SHA2_256F, sig, &sig_len,
                                     hmsg, sizeof(hmsg), NULL, 0,
                                     addrnd, hsk) == AMA_SUCCESS,
              "sign_addrnd succeeds with valid arguments");
        check(ama_slhdsa_verify(AMA_SLHDSA_SHA2_256F, sig, sig_len,
                                hmsg, sizeof(hmsg), NULL, 0, hpk) == AMA_SUCCESS,
              "the caller-randomness signature verifies");

        /* Rejection legs the earlier sweeps missed: NULL secret key and an
         * oversized context on the deterministic and addrnd entry points. */
        {
            static uint8_t big_ctx[256];
            sig_len = sizeof(sig);
            check(ama_slhdsa_sign_deterministic(AMA_SLHDSA_SHA2_256F, sig, &sig_len,
                                                hmsg, sizeof(hmsg), NULL, 0,
                                                NULL) == AMA_ERROR_INVALID_PARAM,
                  "deterministic sign refuses a NULL secret key");
            check(ama_slhdsa_sign_deterministic(AMA_SLHDSA_SHA2_256F, sig, &sig_len,
                                                hmsg, sizeof(hmsg), big_ctx,
                                                sizeof big_ctx,
                                                hsk) == AMA_ERROR_INVALID_PARAM,
                  "deterministic sign refuses a 256-byte context");
            check(ama_slhdsa_sign_addrnd(AMA_SLHDSA_SHA2_256F, sig, &sig_len,
                                         hmsg, sizeof(hmsg), big_ctx,
                                         sizeof big_ctx,
                                         addrnd, hsk) == AMA_ERROR_INVALID_PARAM,
                  "sign_addrnd refuses a 256-byte context");
        }
    }

    /* FIPS 205 §9 internal interface (testing-mode exports): parameter-set
     * and pointer validation mirrors the public wrappers. */
    {
        uint8_t ipk[AMA_SLHDSA_SHA2_256F_PUBLIC_KEY_BYTES];
        memset(ipk, 0, sizeof(ipk));
        sig_len = sizeof(sig);
        check(ama_slhdsa_sign_internal((ama_slhdsa_param_set_t)99, sig, &sig_len,
                                       msg, sizeof(msg), addrnd,
                                       sk) == AMA_ERROR_INVALID_PARAM,
              "sign_internal refuses an unknown parameter set");
        check(ama_slhdsa_sign_internal(AMA_SLHDSA_SHA2_256F, NULL, &sig_len,
                                       msg, sizeof(msg), addrnd,
                                       sk) == AMA_ERROR_INVALID_PARAM,
              "sign_internal refuses a NULL signature buffer");
        check(ama_slhdsa_verify_internal((ama_slhdsa_param_set_t)99, sig,
                                         AMA_SLHDSA_SHA2_256F_SIGNATURE_BYTES,
                                         msg, sizeof(msg),
                                         ipk) == AMA_ERROR_INVALID_PARAM,
              "verify_internal refuses an unknown parameter set");
        check(ama_slhdsa_verify_internal(AMA_SLHDSA_SHA2_256F, NULL,
                                         AMA_SLHDSA_SHA2_256F_SIGNATURE_BYTES,
                                         msg, sizeof(msg),
                                         ipk) == AMA_ERROR_INVALID_PARAM,
              "verify_internal refuses a NULL signature");
        check(ama_slhdsa_verify_internal(AMA_SLHDSA_SHA2_256F, sig,
                                         AMA_SLHDSA_SHA2_256F_SIGNATURE_BYTES,
                                         msg, sizeof(msg),
                                         NULL) == AMA_ERROR_INVALID_PARAM,
              "verify_internal refuses a NULL public key");
    }

    /* SLH-DSA-SHAKE-128s: the SHAKE H_msg/PRF/thash codepaths are otherwise
     * exercised only by the Python KAT corpus against the production library,
     * never inside this instrumented binary.  Signing 128s at -O0 is too slow
     * for the suite, but a full verify of a well-formed-length garbage
     * signature walks the complete SHAKE recompute path (FORS, hypertree,
     * H_msg) and must land on a clean VERIFY_FAILED. */
    {
        uint8_t spk[AMA_SLHDSA_SHAKE_128S_PUBLIC_KEY_BYTES];
        uint8_t ssk[AMA_SLHDSA_SHAKE_128S_SECRET_KEY_BYTES];
        static uint8_t ssig[AMA_SLHDSA_SHAKE_128S_SIGNATURE_BYTES];
        uint8_t sseed[16];
        size_t i;
        for (i = 0; i < sizeof(sseed); ++i) sseed[i] = (uint8_t)(0xa5 ^ i);
        for (i = 0; i < sizeof(ssig); ++i) ssig[i] = (uint8_t)(i * 31 + 7);
        check(ama_slhdsa_keygen_from_seed(AMA_SLHDSA_SHAKE_128S, sseed, sseed,
                                          sseed, spk, ssk) == AMA_SUCCESS,
              "SHAKE-128s keygen_from_seed succeeds");
        check(ama_slhdsa_verify(AMA_SLHDSA_SHAKE_128S, ssig, sizeof(ssig),
                                msg, sizeof(msg), NULL, 0,
                                spk) == AMA_ERROR_VERIFY_FAILED,
              "SHAKE-128s cleanly refuses a garbage signature of valid length");
    }
}

int main(void) {
    KAT_SLOT_GUARD_OR_EXIT();  /* per-slot KAT sweep: refuse a pin the host did not honour */

    printf("SLH-DSA context separation (FIPS 205 §9 vs §10.2)\n");
    part_a_context_separation();
    printf("    part A: %d checks\n", checks);
    part_b_acvp_internal_sigver();
    part_c_argument_validation();

    if (failures != 0) {
        fprintf(stderr, "\nFAILED: %d of %d checks\n", failures, checks);
        return 1;
    }
    printf("\nPASSED: %d checks\n", checks);
    return 0;
}
