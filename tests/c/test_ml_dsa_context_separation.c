/* Copyright (C) 2025-2026 Steel Security Advisors LLC */
/* SPDX-License-Identifier: Apache-2.0 */
/**
 * @file test_ml_dsa_context_separation.c
 * @brief The shipped ML-DSA signers are FIPS 204 §5.2 external, and the
 *        internal interface is reachable only from the testing archive
 *        (INVARIANT-50).
 *
 * The raw Algorithm 7/8 pair shipped as `ama_ml_dsa_sign` / `ama_ml_dsa_verify`
 * until 2026-09-23 and cross-verified with the context API under one key.  It
 * now exists only as `ama_ml_dsa_sign_internal` / `_verify_internal` in the
 * AMA_TESTING_MODE archive this test links; tests/test_ml_dsa_interfaces.py
 * asserts the names are absent from the shipped shared object.
 *
 * What this file pins, per parameter set:
 *   A. the context API IS the §5.2 wrapper: sign_ctx(M, ctx) is byte-equal to
 *      sign_internal(0x00 || |ctx| || ctx || M) for empty, short and 255-byte
 *      contexts (both are deterministic);
 *   B. domain separation holds on the shipped verifier: an internal signature
 *      over the raw M is rejected by verify_ctx(M, ctx = "");
 *   C. and the other way: an external signature is rejected by
 *      verify_internal over the raw M;
 *   D. every sigGen record in the vendored ML-DSA-44 and ML-DSA-87 KAT corpus
 *      (tests/kat/fips204, 15 internal + 15 external per file) byte-exact:
 *      the internal records through sign_internal, the external ones through
 *      sign_ctx.  The Python suite loads the shipped library and can no
 *      longer reach the internal records, so they are replayed here.
 *
 * Reads its corpus relative to the repository root (CMake sets it).
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "ama_cryptography.h"
#include "../../src/c/internal/ama_testing_exports.h"

#define MAX_PK  2592u
#define MAX_SK  4896u
#define MAX_SIG 4627u
#define MSG_LEN 48u
#define KAT_LINE_MAX 32768u
#define KAT_MSG_MAX  8192u

static int failures = 0;

#define CHECK(cond, ps, what) do {                                      \
    if (!(cond)) {                                                      \
        failures++;                                                     \
        fprintf(stderr, "FAIL: ML-DSA-%d: %s\n", (int)(ps), (what));    \
    } else {                                                            \
        printf("PASS: ML-DSA-%d: %s\n", (int)(ps), (what));             \
    }                                                                   \
} while (0)

static void run(ama_ml_dsa_param_set_t ps) {
    static uint8_t pk[MAX_PK], sk[MAX_SK];
    static uint8_t sig_ctx[MAX_SIG], sig_raw[MAX_SIG];
    static uint8_t wrapped[2u + 255u + MSG_LEN];
    uint8_t msg[MSG_LEN], ctx[255];
    const size_t ctx_lens[3] = {0u, 3u, 255u};
    size_t i, k;

    for (i = 0; i < MSG_LEN; i++) msg[i] = (uint8_t)(0x5Au ^ i);
    for (i = 0; i < sizeof ctx; i++) ctx[i] = (uint8_t)(i * 7u + 1u);
    if (ama_ml_dsa_keypair(ps, pk, sk) != AMA_SUCCESS) {
        failures++;
        fprintf(stderr, "FAIL: ML-DSA-%d: keypair\n", (int)ps);
        return;
    }

    for (k = 0; k < 3; k++) {
        const size_t cl = ctx_lens[k];
        size_t len_ctx = MAX_SIG, len_raw = MAX_SIG;
        wrapped[0] = 0x00;
        wrapped[1] = (uint8_t)cl;
        memcpy(wrapped + 2, ctx, cl);
        memcpy(wrapped + 2 + cl, msg, MSG_LEN);
        CHECK(ama_ml_dsa_sign_ctx(ps, sig_ctx, &len_ctx, msg, MSG_LEN,
                                  cl ? ctx : NULL, cl, sk) == AMA_SUCCESS &&
              ama_ml_dsa_sign_internal(ps, sig_raw, &len_raw, wrapped,
                                       2u + cl + MSG_LEN, sk) == AMA_SUCCESS &&
              len_ctx == len_raw && memcmp(sig_ctx, sig_raw, len_ctx) == 0,
              ps, cl == 0 ? "A: sign_ctx == sign_internal(wrapper), empty ctx"
                  : cl == 3 ? "A: sign_ctx == sign_internal(wrapper), 3-byte ctx"
                            : "A: sign_ctx == sign_internal(wrapper), 255-byte ctx");
    }

    {
        size_t len = MAX_SIG;
        CHECK(ama_ml_dsa_sign_internal(ps, sig_raw, &len, msg, MSG_LEN, sk) == AMA_SUCCESS &&
              ama_ml_dsa_verify_ctx(ps, msg, MSG_LEN, NULL, 0, sig_raw, len, pk)
                  == AMA_ERROR_VERIFY_FAILED,
              ps, "B: an internal signature over M is rejected by verify_ctx(M, \"\")");
    }
    {
        size_t len = MAX_SIG;
        CHECK(ama_ml_dsa_sign_ctx(ps, sig_ctx, &len, msg, MSG_LEN, NULL, 0, sk) == AMA_SUCCESS &&
              ama_ml_dsa_verify_internal(ps, msg, MSG_LEN, sig_ctx, len, pk)
                  == AMA_ERROR_VERIFY_FAILED,
              ps, "C: an external signature is rejected by verify_internal over M");
    }
    ama_secure_memzero(sk, sizeof sk);
}

/* Decode `hex` into `out`; returns the byte count, or (size_t)-1. */
static size_t unhex(const char *hex, uint8_t *out, size_t cap) {
    size_t n = 0;
    while (hex[0] && hex[0] != '\n' && hex[0] != '\r') {
        unsigned v = 0;
        int k;
        if (n == cap) return (size_t)-1;
        for (k = 0; k < 2; k++) {
            char c = hex[k];
            v <<= 4;
            if (c >= '0' && c <= '9') v |= (unsigned)(c - '0');
            else if (c >= 'A' && c <= 'F') v |= (unsigned)(c - 'A' + 10);
            else if (c >= 'a' && c <= 'f') v |= (unsigned)(c - 'a' + 10);
            else return (size_t)-1;
        }
        out[n++] = (uint8_t)v;
        hex += 2;
    }
    return n;
}

/* D: replay every sigGen record of one corpus file. */
static void replay(ama_ml_dsa_param_set_t ps, const char *path) {
    static char line[KAT_LINE_MAX];
    static uint8_t sk[MAX_SK], msg[KAT_MSG_MAX], ctx[255];
    static uint8_t want[MAX_SIG], got[MAX_SIG];
    size_t sk_len = 0, msg_len = 0, ctx_len = 0, want_len = 0;
    int internal = -1, n_internal = 0, n_external = 0, bad = 0;
    FILE *f = fopen(path, "r");
    if (!f) {
        failures++;
        fprintf(stderr, "FAIL: cannot open %s\n", path);
        return;
    }
    while (fgets(line, sizeof line, f)) {
        if (strncmp(line, "skey = ", 7) == 0) {
            sk_len = unhex(line + 7, sk, sizeof sk);
        } else if (strncmp(line, "msg = ", 6) == 0) {
            msg_len = unhex(line + 6, msg, sizeof msg);
        } else if (strncmp(line, "ctx = ", 6) == 0) {
            ctx_len = unhex(line + 6, ctx, sizeof ctx);
        } else if (strncmp(line, "sigmode = ", 10) == 0) {
            internal = strncmp(line + 10, "internal", 8) == 0;
        } else if (strncmp(line, "sig = ", 6) == 0) {
            size_t got_len = MAX_SIG;
            ama_error_t rc;
            want_len = unhex(line + 6, want, sizeof want);
            if (internal < 0 || sk_len == (size_t)-1 || msg_len == (size_t)-1 ||
                ctx_len == (size_t)-1 || want_len == (size_t)-1) {
                bad++;
                continue;
            }
            rc = internal
                ? ama_ml_dsa_sign_internal(ps, got, &got_len, msg, msg_len, sk)
                : ama_ml_dsa_sign_ctx(ps, got, &got_len, msg, msg_len,
                                      ctx_len ? ctx : NULL, ctx_len, sk);
            if (rc != AMA_SUCCESS || got_len != want_len || memcmp(got, want, got_len) != 0) bad++;
            if (internal) n_internal++; else n_external++;
            internal = -1;
            msg_len = ctx_len = 0;
        }
    }
    fclose(f);
    ama_secure_memzero(sk, sizeof sk);
    CHECK(bad == 0 && n_internal >= 15 && n_external >= 15, ps,
          "D: every vendored sigGen record reproduced byte-exact (internal and external)");
    printf("      %s: %d internal + %d external records\n", path, n_internal, n_external);
}

int main(void) {
    run(AMA_ML_DSA_44);
    run(AMA_ML_DSA_65);
    run(AMA_ML_DSA_87);
    replay(AMA_ML_DSA_44, "tests/kat/fips204/ml_dsa_44.kat");
    replay(AMA_ML_DSA_87, "tests/kat/fips204/ml_dsa_87.kat");
    printf("\n%d failure(s)\n", failures);
    return failures ? 1 : 0;
}
