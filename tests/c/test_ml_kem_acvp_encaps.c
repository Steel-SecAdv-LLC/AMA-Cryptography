/* Copyright (C) 2025-2026 Steel Security Advisors LLC */
/* SPDX-License-Identifier: Apache-2.0 */
/**
 * @file test_ml_kem_acvp_encaps.c
 * @brief NIST ACVP ML-KEM encapsulation AFT replay (FIPS 203 Algorithm 17).
 *
 * Reads tests/kat/fips203/acvp/acvp_encapsulation_aft.kat — the encapsulation
 * AFT group of ACVP-Server v1.1.0.42 ML-KEM-encapDecap-FIPS203, all three
 * parameter sets, 25 cases each — and checks that encapsulating with the
 * vector's m reproduces its ciphertext c and shared key k byte for byte.
 * Production encapsulation draws m from the CSPRNG; the derandomised entry
 * point is the AMA_TESTING_MODE export in src/c/internal/ama_testing_exports.h.
 *
 * Like test_kat, this reads the fixture from the source tree and needs the
 * repository root as its working directory (CMake sets it).
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "ama_cryptography.h"
#include "../../src/c/internal/ama_testing_exports.h"

#define KAT_PATH "tests/kat/fips203/acvp/acvp_encapsulation_aft.kat"
#define MAX_HEX  (2 * 1568 + 8)

static int hex_decode(const char *hex, uint8_t *out, size_t max, size_t *len) {
    size_t n = strlen(hex);
    size_t i;
    if (n % 2 != 0 || n / 2 > max) return 0;
    for (i = 0; i < n; i += 2) {
        unsigned v;
        if (sscanf(hex + i, "%2x", &v) != 1) return 0;
        out[i / 2] = (uint8_t)v;
    }
    *len = n / 2;
    return 1;
}

static void chomp(char *s) {
    size_t n = strlen(s);
    while (n > 0 && (s[n - 1] == '\n' || s[n - 1] == '\r' || s[n - 1] == ' ')) s[--n] = '\0';
}

int main(void) {
    FILE *f = fopen(KAT_PATH, "r");
    static char line[MAX_HEX + 64];
    static uint8_t ek[1568], m[32], c_exp[1568], k_exp[32], ct[1568], ss[32];
    size_t ek_len = 0, m_len = 0, c_len = 0, k_len = 0;
    int set = 0, tcid = 0, have = 0, cases = 0, failures = 0;

    if (!f) {
        fprintf(stderr, "FAIL: cannot open %s (run from the repository root)\n", KAT_PATH);
        return 1;
    }
    printf("ML-KEM ACVP encapsulation AFT replay (%s)\n", KAT_PATH);

    while (fgets(line, sizeof line, f)) {
        chomp(line);
        if (line[0] == '#' || line[0] == '\0') {
            if (line[0] == '\0' && have == 6) {
                ama_ml_kem_param_set_t ps = (ama_ml_kem_param_set_t)set;
                size_t ct_len = sizeof ct;
                ama_error_t rc = ama_kyber_test_encapsulate_derand(ps, ek, ek_len, m, ct, &ct_len, ss, sizeof ss);
                cases++;
                if (rc != AMA_SUCCESS || ct_len != c_len || k_len != 32 ||
                    memcmp(ct, c_exp, c_len) != 0 || memcmp(ss, k_exp, 32) != 0) {
                    fprintf(stderr, "FAIL: ML-KEM-%d tcId %d (rc=%d, ct_len=%zu/%zu, c %s, k %s)\n",
                            set, tcid, (int)rc, ct_len, c_len,
                            memcmp(ct, c_exp, c_len) == 0 ? "ok" : "MISMATCH",
                            memcmp(ss, k_exp, 32) == 0 ? "ok" : "MISMATCH");
                    failures++;
                }
                have = 0;
            }
            continue;
        }
        if (sscanf(line, "set = %d", &set) == 1) { have = 1; continue; }
        if (sscanf(line, "tcId = %d", &tcid) == 1) { have = 2; continue; }
        if (strncmp(line, "ek = ", 5) == 0) { have = hex_decode(line + 5, ek, sizeof ek, &ek_len) ? 3 : 0; continue; }
        if (strncmp(line, "m = ", 4) == 0)  { have = hex_decode(line + 4, m, sizeof m, &m_len) && m_len == 32 ? 4 : 0; continue; }
        if (strncmp(line, "c = ", 4) == 0)  { have = hex_decode(line + 4, c_exp, sizeof c_exp, &c_len) ? 5 : 0; continue; }
        if (strncmp(line, "k = ", 4) == 0)  { have = hex_decode(line + 4, k_exp, sizeof k_exp, &k_len) ? 6 : 0; continue; }
        fprintf(stderr, "FAIL: unexpected line: %.60s\n", line);
        failures++;
    }
    if (have == 6) {  /* file without a trailing blank line */
        ama_ml_kem_param_set_t ps = (ama_ml_kem_param_set_t)set;
        size_t ct_len = sizeof ct;
        ama_error_t rc = ama_kyber_test_encapsulate_derand(ps, ek, ek_len, m, ct, &ct_len, ss, sizeof ss);
        cases++;
        if (rc != AMA_SUCCESS || ct_len != c_len || memcmp(ct, c_exp, c_len) != 0 || memcmp(ss, k_exp, 32) != 0) failures++;
    }
    fclose(f);

    if (cases != 75) {
        fprintf(stderr, "FAIL: expected 75 cases (3 parameter sets x 25), parsed %d\n", cases);
        return 1;
    }
    printf("%d cases, %d failures\n", cases, failures);
    return failures ? 1 : 0;
}
