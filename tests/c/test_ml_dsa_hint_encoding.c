/* Copyright (C) 2025-2026 Steel Security Advisors LLC */
/* SPDX-License-Identifier: Apache-2.0 */
/**
 * ML-DSA verification refuses every non-canonical hint encoding
 * (FIPS 204 Algorithm 21, HintBitUnpack), on all three parameter sets.
 *
 * WHY THIS FILE EXISTS
 *
 * `ama_ml_dsa_verify_ctx` checks four properties of the hint field before it
 * uses it: each cumulative count is at least the one before it and at most
 * omega, the indices inside one polynomial's slice are strictly increasing,
 * and every octet past the last count is zero.  Measured on 2026-09-26 with
 * `tools/measure_branch_coverage.py --python-suite` over ctest, pytest, the
 * Wycheproof runner and the ACVP runner together, three of those four
 * rejections were executed by NO suite: the source comment above the check
 * cited `test_a_permuted_hint_is_refused` in tests/test_pqc_param_sets.py as
 * the pin for the ordering rule, and no such test exists anywhere in the
 * tree's history.  A guard nothing executes is a guard whose deletion breaks
 * nothing.
 *
 * WHY EACH CASE IS A PIN AND NOT A SMOKE TEST
 *
 * Verification recomputes w1 through `dil_polyveck_use_hint`, which turns
 * the hint field into a SET of flagged coefficients per polynomial.  Each
 * malformed encoding below is chosen so that it denotes the SAME set as the
 * honest signature — so without its guard it verifies, and is a second valid
 * byte string for one signature (a break of SUF-CMA, not of EUF-CMA):
 *
 *   - two indices of one polynomial swapped (ordering rule);
 *   - a non-zero octet in the unused tail (padding rule);
 *   - the count of an EMPTY interior polynomial lowered by one (the
 *     `limit < prev` rule).  The unpack loop never rewinds, so the flags are
 *     unchanged; only the count check sees the difference.
 *
 * The fourth rule (`limit > omega`) keeps `use_hint` inside the hint array.
 * For the VERDICT it is redundant: without it the c-tilde comparison still
 * refuses such a signature (measured: deleting it fails no C test).  Its case
 * below is therefore SMOKE, kept so all four rules are stated in one place.
 *
 * The signer's side of the same encoding is here too: MakeHint's boundary
 * case (a0 = -gamma2 with a1 = 0 must give hint 0), which no suite executed
 * either -- see case_make_hint_edge.
 *
 * Mutation record (AGENTS.md 6.2), gcc 13.3.0 Release, x86-64, full ctest:
 * deleting the ordering check or the padding check fails this test on all
 * three parameter sets, deleting the `limit < prev` operand fails it on
 * ML-DSA-65 and -87 (see case_decreasing_count for ML-DSA-44), deleting
 * MakeHint's `&& a1 != 0` fails it on all three, and in each case this is
 * the only C test that fails.
 *
 * The message search is deterministic: ML-DSA signing here is the FIPS 204
 * deterministic variant, so the same key and message always produce the
 * same hint layout, and the first qualifying message is the same every run.
 */

#include <stdio.h>
#include <string.h>
#include "ama_cryptography.h"

typedef struct {
    ama_ml_dsa_param_set_t ps;
    const char *name;
    size_t ctildebytes;
    unsigned l, k, omega;
    size_t polyz_packedbytes;
    unsigned empty_poly_msg;  /* see case_decreasing_count; 0 = none found */
    unsigned make_hint_edge_msg;  /* see case_make_hint_edge */
} hint_layout;

/* FIPS 204 Table 1 and Table 2; the signature length each row implies is
 * checked against the library's own figure in main() before any case runs. */
static const hint_layout LAYOUTS[] = {
    { AMA_ML_DSA_44, "ML-DSA-44", 32, 4, 4, 80, 576, 0, 9635 },
    { AMA_ML_DSA_65, "ML-DSA-65", 48, 5, 6, 55, 640, 8097, 26439 },
    { AMA_ML_DSA_87, "ML-DSA-87", 64, 7, 8, 75, 640, 6831, 6381 },
};

#define MAX_PK  2592
#define MAX_SK  4896
#define MAX_SIG 4627
#define SEARCH_LIMIT 4096u

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

static uint8_t pk[MAX_PK], sk[MAX_SK];
static uint8_t sig[MAX_SIG], forged[MAX_SIG];

static size_t hint_offset(const hint_layout *L) {
    return L->ctildebytes + (size_t)L->l * L->polyz_packedbytes;
}

static ama_error_t verify(const hint_layout *L, const uint8_t *msg,
                          const uint8_t *s, size_t sig_len) {
    return ama_ml_dsa_verify_ctx(L->ps, msg, 4, NULL, 0, s, sig_len, pk);
}

static int sign_message(const hint_layout *L, unsigned m, uint8_t msg[4],
                        size_t *sig_len) {
    msg[0] = (uint8_t)(m >> 24);
    msg[1] = (uint8_t)(m >> 16);
    msg[2] = (uint8_t)(m >> 8);
    msg[3] = (uint8_t)m;
    *sig_len = sizeof(sig);
    return ama_ml_dsa_sign_ctx(L->ps, sig, sig_len, msg, 4, NULL, 0, sk) == AMA_SUCCESS;
}

/* The cumulative count stored for polynomial i; count(-1) is 0. */
static unsigned count_at(const uint8_t *h, const hint_layout *L, int i) {
    return i < 0 ? 0u : h[L->omega + (unsigned)i];
}

/* Ordering rule: swap two indices inside one polynomial's slice. */
static void case_permuted(const hint_layout *L) {
    uint8_t msg[4];
    size_t sig_len;
    for (unsigned m = 0; m < SEARCH_LIMIT; m++) {
        if (!sign_message(L, m, msg, &sig_len)) break;
        const uint8_t *h = sig + hint_offset(L);
        for (int i = 0; i < (int)L->k; i++) {
            unsigned lo = count_at(h, L, i - 1), hi = count_at(h, L, i);
            if (hi - lo < 2) continue;
            memcpy(forged, sig, sig_len);
            uint8_t *fh = forged + hint_offset(L);
            fh[lo] = h[lo + 1];
            fh[lo + 1] = h[lo];
            CHECK(verify(L, msg, sig, sig_len) == AMA_SUCCESS,
                  "%s: the honest signature verifies (m=%u)", L->name, m);
            CHECK(verify(L, msg, forged, sig_len) == AMA_ERROR_VERIFY_FAILED,
                  "%s: indices %u,%u of polynomial %d swapped is refused",
                  L->name, h[lo], h[lo + 1], i);
            return;
        }
    }
    CHECK(0, "%s: no signature with two hints in one polynomial in %u messages",
          L->name, SEARCH_LIMIT);
}

/* Padding rule: a non-zero octet after the last index. */
static void case_dirty_tail(const hint_layout *L) {
    uint8_t msg[4];
    size_t sig_len;
    for (unsigned m = 0; m < SEARCH_LIMIT; m++) {
        if (!sign_message(L, m, msg, &sig_len)) break;
        const uint8_t *h = sig + hint_offset(L);
        unsigned used = count_at(h, L, (int)L->k - 1);
        if (used >= L->omega) continue;
        memcpy(forged, sig, sig_len);
        forged[hint_offset(L) + L->omega - 1] = 0x01;
        CHECK(verify(L, msg, forged, sig_len) == AMA_ERROR_VERIFY_FAILED,
              "%s: a non-zero octet in the unused hint tail is refused (%u of %u used)",
              L->name, used, L->omega);
        return;
    }
    CHECK(0, "%s: no signature with an unused hint tail in %u messages",
          L->name, SEARCH_LIMIT);
}

/* `limit < prev`: lower the count of an empty interior polynomial i from c
 * to c - 1.  Without the check the validation loop sets prev = c - 1 and, if
 * polynomial i + 1 is non-empty, compares only the boundary between the
 * index before the gap and the one after it; the unpack loop never rewinds,
 * so it assigns every index where it did.
 *
 * Honest signatures rarely have an empty polynomial, so the message is
 * pinned rather than searched for.  Measured over 200,000 messages per set
 * (the keys below, messages 0..199999): 10 qualifying signatures under
 * ML-DSA-65, the first at message 8097; 10 under ML-DSA-87, the first at
 * 6831; none under ML-DSA-44 in 3,200,000 (its omega = 80 over k = 4 leaves
 * each polynomial ~15 indices).  The check is one code path shared by all
 * three sets, so ML-DSA-44 is left to the other two.  Those rates are also
 * the size of the hole without the check: roughly one honest signature in
 * 20,000 would have a second valid encoding. */
static void case_decreasing_count(const hint_layout *L) {
    uint8_t msg[4];
    size_t sig_len;
    if (L->empty_poly_msg == 0) {
        printf("NOTE: %s: no honest signature with an empty interior polynomial "
               "exists to pin (measured; see above)\n", L->name);
        return;
    }
    if (!sign_message(L, L->empty_poly_msg, msg, &sig_len)) {
        CHECK(0, "%s: signing failed", L->name);
        return;
    }
    const uint8_t *h = sig + hint_offset(L);
    for (int i = 1; i + 1 < (int)L->k; i++) {
        unsigned c = count_at(h, L, i);
        if (c == 0 || count_at(h, L, i - 1) != c) continue;
        if (count_at(h, L, i + 1) != c && h[c] <= h[c - 1]) continue;
        memcpy(forged, sig, sig_len);
        forged[hint_offset(L) + L->omega + (unsigned)i] = (uint8_t)(c - 1);
        CHECK(verify(L, msg, sig, sig_len) == AMA_SUCCESS,
              "%s: the honest signature verifies (m=%u)", L->name, L->empty_poly_msg);
        CHECK(verify(L, msg, forged, sig_len) == AMA_ERROR_VERIFY_FAILED,
              "%s: count of empty polynomial %d lowered %u -> %u is refused",
              L->name, i, c, c - 1);
        return;
    }
    CHECK(0, "%s: message %u no longer has an empty interior polynomial -- the "
          "key or signing changed; re-measure and re-pin", L->name, L->empty_poly_msg);
}

/* The signing side: MakeHint's boundary case (FIPS 204 Algorithm 39, in the
 * reference form `a0 > gamma2 || a0 < -gamma2 || (a0 == -gamma2 && a1 != 0)`).
 * At a0 == -gamma2 with a1 == 0 the hint must be 0; the clause that says so
 * was executed by no suite.  The message for each set is one whose ACCEPTED
 * signing attempt meets that coefficient (found by instrumenting the branch
 * over messages 0..49999 under the keys below: the first hits are 9635, 26439
 * and 6381).  Deleting `&& a1 != 0` flips that hint to 1, verification's
 * UseHint then recovers a different w1, and the honest signature no longer
 * verifies. */
static void case_make_hint_edge(const hint_layout *L) {
    uint8_t msg[4];
    size_t sig_len;
    if (!sign_message(L, L->make_hint_edge_msg, msg, &sig_len)) {
        CHECK(0, "%s: signing failed", L->name);
        return;
    }
    CHECK(verify(L, msg, sig, sig_len) == AMA_SUCCESS,
          "%s: a signature whose MakeHint met a0 = -gamma2, a1 = 0 verifies (m=%u)",
          L->name, L->make_hint_edge_msg);
}

/* `limit > omega`: the bound that keeps use_hint inside the hint array. */
static void case_count_past_omega(const hint_layout *L) {
    uint8_t msg[4];
    size_t sig_len;
    if (!sign_message(L, 0, msg, &sig_len)) {
        CHECK(0, "%s: signing failed", L->name);
        return;
    }
    memcpy(forged, sig, sig_len);
    forged[hint_offset(L) + L->omega + L->k - 1] = (uint8_t)(L->omega + 1);
    CHECK(verify(L, msg, forged, sig_len) == AMA_ERROR_VERIFY_FAILED,
          "%s: a final count of omega + 1 is refused", L->name);
}

int main(void) {
    printf("===========================================\n");
    printf("ML-DSA hint encoding (FIPS 204 Algorithm 21)\n");
    printf("===========================================\n");
    for (size_t n = 0; n < sizeof(LAYOUTS) / sizeof(LAYOUTS[0]); n++) {
        const hint_layout *L = &LAYOUTS[n];
        uint8_t xi[32];
        size_t expect = hint_offset(L) + L->omega + L->k;
        CHECK(ama_ml_dsa_signature_bytes(L->ps) == expect,
              "%s: layout table matches the library's signature length (%zu)",
              L->name, expect);
        if (ama_ml_dsa_signature_bytes(L->ps) != expect) continue;
        memset(xi, (int)(0x42 + n), sizeof(xi));
        if (ama_ml_dsa_keypair_from_seed(L->ps, xi, pk, sk) != AMA_SUCCESS) {
            CHECK(0, "%s: keypair from seed", L->name);
            continue;
        }
        case_permuted(L);
        case_dirty_tail(L);
        case_decreasing_count(L);
        case_count_past_omega(L);
        case_make_hint_edge(L);
    }
    printf("\n%s: %d failure(s)\n", failures ? "FAILED" : "PASSED", failures);
    return failures ? 1 : 0;
}
