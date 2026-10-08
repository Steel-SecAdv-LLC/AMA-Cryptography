/* Copyright (C) 2025-2026 Steel Security Advisors LLC */
/* SPDX-License-Identifier: Apache-2.0 */
/**
 * src/c/ama_base64.c: the constant-time Base64 / Base64url codec.
 *
 * WHAT IS CHECKED, AND AGAINST WHAT
 *
 * 1. RFC 4648 §10's test vectors, both variants, both directions.
 * 2. A differential against a deliberately naive, table-driven reference
 *    written below.  The reference is the specification spelled the obvious
 *    way -- an alphabet string indexed by each 6-bit group, a linear search
 *    for each character -- and is variable-time by design: it is the oracle
 *    here and nothing else.  Its decoder accepts a string exactly when every
 *    character is in the alphabet, the padding is the length's own, and
 *    re-encoding the result returns the input (RFC 4648 §3.5's zero pad bits,
 *    stated as "encoding is a function").
 *      - every string of length 0..4 over a 74-character probe alphabet
 *        (both variants' alphabets, '=', five near neighbours, 0x80 and NUL):
 *        30,397,351 strings per variant, 60,794,702 in all; accept/refuse
 *        and output must agree with the reference exactly;
 *      - 200,000 random octet strings of length 0..96, encoded by both and
 *        compared, then decoded and compared with the original;
 *      - 200,000 random 8- and 12-character strings over the same alphabet,
 *        which reach multi-group inputs the exhaustive pass cannot.
 *    The codec reads every differential input from an exact-size heap copy,
 *    so a read past the end is a heap overflow under AddressSanitizer.
 * 3. A refused decode zeroes every octet it wrote.
 * 4. Argument refusals: NULL out_len, NULL buffers with non-zero lengths, a
 *    buffer one octet short, an unknown variant, and *out_len cleared on
 *    each.
 *
 * Mutation record (AGENTS.md 6.2), measured 2026-10-08, gcc 13.3.0 -O2 with
 * AddressSanitizer, each guard removed alone:
 *
 *   pad-bit check (§3.5) .................. fails: "Zh==", "Zm9=", "Zh" + differential
 *   alphabet error mask ................... fails: "Z===", "Zg=A", "Zm9v!g==" + differential
 *   char62/char63 variant selection ....... fails: RFC 4648 vectors + differential
 *   zero-on-refusal ....................... fails: section 3
 *   decode out_cap check .................. fails: section 4
 *   encode out_cap check .................. fails: section 4
 *   one-character final group refusal ..... fails: the "follow" case (without
 *                                           it, "A" is read with the next
 *                                           character and accepted as 0x00)
 *   padded length % 4 check ............... fails: ASan stack-buffer-overflow
 *   unknown-variant refusal in encode ..... fails: empty input, unknown variant
 *   'Z' -> 'Y' in the upper-case range .... fails: RFC 4648 vectors
 *   *out_len cleared on refusal ........... fails: every named refusal
 *   NULL output with a claimed capacity ... fails: SIGSEGV, both directions
 *                                           (added 2026-10-08: the earlier
 *                                           NULL-output cases passed a zero
 *                                           capacity, so the capacity check
 *                                           refused them and this guard was
 *                                           unpinned)
 *
 * Redundant by construction (6.3): the '=' count requires the second-to-last
 * '=' to be followed by a last one (`& last`).  Without that, "Zg=A" counts
 * one pad, and the '=' it leaves inside the body is outside the alphabet, so
 * the alphabet mask refuses it anyway; removing the AND alone passes every
 * test.  The property -- one encoding per octet string -- is pinned by the
 * differential and the alphabet-mask mutation above, not by that AND, which
 * stays because it is what the count means.
 */
#include "ama_cryptography.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int failures = 0;

#define CHECK(cond, what)                                   \
    do {                                                    \
        if (!(cond)) {                                      \
            failures++;                                     \
            if (failures <= 20) {                           \
                printf("FAIL %s:%d: %s\n", __FILE__, __LINE__, (what)); \
            }                                               \
        }                                                   \
    } while (0)

static const char STD_ALPHABET[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
static const char URL_ALPHABET[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

/* ---- the naive reference (variable-time; an oracle only) ---------------- */

static size_t ref_encode(char *out, const uint8_t *in, size_t n, int url) {
    const char *a = url ? URL_ALPHABET : STD_ALPHABET;
    size_t k = 0;
    size_t i = 0;
    for (; n - i >= 3u; i += 3u) {
        uint32_t w = ((uint32_t)in[i] << 16) | ((uint32_t)in[i + 1u] << 8) | (uint32_t)in[i + 2u];
        out[k++] = a[(w >> 18) & 63u];
        out[k++] = a[(w >> 12) & 63u];
        out[k++] = a[(w >> 6) & 63u];
        out[k++] = a[w & 63u];
    }
    if (n - i == 1u) {
        uint32_t w = (uint32_t)in[i] << 16;
        out[k++] = a[(w >> 18) & 63u];
        out[k++] = a[(w >> 12) & 63u];
        if (!url) {
            out[k++] = '=';
            out[k++] = '=';
        }
    } else if (n - i == 2u) {
        uint32_t w = ((uint32_t)in[i] << 16) | ((uint32_t)in[i + 1u] << 8);
        out[k++] = a[(w >> 18) & 63u];
        out[k++] = a[(w >> 12) & 63u];
        out[k++] = a[(w >> 6) & 63u];
        if (!url) {
            out[k++] = '=';
        }
    }
    return k;
}

/* 1 and the decoded octets when `s` is the canonical encoding of something;
 * 0 otherwise. */
static int ref_decode(uint8_t *out, size_t *out_len, const char *s, size_t n, int url) {
    const char *a = url ? URL_ALPHABET : STD_ALPHABET;
    size_t body = n;
    if (!url) {
        if (n % 4u != 0u) {
            return 0;
        }
        while (body > 0u && n - body < 2u && s[body - 1u] == '=') {
            body--;
        }
    }
    uint32_t acc = 0;
    int bits = 0;
    size_t k = 0;
    for (size_t i = 0; i < body; i++) {
        const char *p = (s[i] == '\0') ? NULL : strchr(a, s[i]);
        if (p == NULL) {
            return 0;
        }
        acc = (acc << 6) | (uint32_t)(p - a);
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            out[k++] = (uint8_t)(acc >> bits);
            acc &= (1u << bits) - 1u;
        }
    }
    char again[64] = {0};
    if (k > 45u || ref_encode(again, out, k, url) != n || memcmp(again, s, n) != 0) {
        return 0;
    }
    *out_len = k;
    return 1;
}

/* ---- helpers ------------------------------------------------------------- */

static ama_base64_variant_t variant_of(int url) {
    return url ? AMA_BASE64_URL_UNPADDED : AMA_BASE64_STANDARD_PADDED;
}

/* Both decoders on one string; they must agree on the verdict and, when they
 * accept, on every octet.  The codec reads an exact-size heap copy, so a read
 * one character past the input is a heap overflow AddressSanitizer reports. */
static int agree(const char *s, size_t n, int url) {
    uint8_t want[64] = {0};
    uint8_t got[64];
    size_t want_len = 0;
    size_t got_len = 99;
    int ref_ok = ref_decode(want, &want_len, s, n, url);
    char *exact = (char *)malloc(n == 0u ? 1u : n);
    if (exact == NULL) {
        return 0;
    }
    memcpy(exact, s, n);
    ama_error_t rc = ama_base64_decode(got, sizeof got, exact, n, variant_of(url), &got_len);
    free(exact);
    if (ref_ok != (rc == AMA_SUCCESS)) {
        return 0;
    }
    if (!ref_ok) {
        return got_len == 0u;
    }
    return got_len == want_len && memcmp(got, want, want_len) == 0;
}

static void report_disagreement(const char *s, size_t n, int url) {
    if (failures <= 20) {
        printf("  disagreement (%s) on \"", url ? "url" : "std");
        for (size_t i = 0; i < n; i++) {
            unsigned char c = (unsigned char)s[i];
            if (c >= 0x20u && c < 0x7Fu) {
                putchar(c);
            } else {
                printf("\\x%02x", c);
            }
        }
        printf("\"\n");
    }
}

/* ---- 1. RFC 4648 §10 ----------------------------------------------------- */

static void test_rfc4648_vectors(void) {
    static const char *const plain[] = {"", "f", "fo", "foo", "foob", "fooba", "foobar"};
    static const char *const std[] = {"",     "Zg==",     "Zm8=",    "Zm9v",
                                      "Zm9vYg==", "Zm9vYmE=", "Zm9vYmFy"};
    static const char *const url[] = {"", "Zg", "Zm8", "Zm9v", "Zm9vYg", "Zm9vYmE", "Zm9vYmFy"};
    for (size_t t = 0; t < sizeof plain / sizeof plain[0]; t++) {
        char enc[16];
        uint8_t dec[16];
        size_t n = 0;
        size_t len = strlen(plain[t]);
        const uint8_t *p = (const uint8_t *)plain[t];

        CHECK(ama_base64_encoded_len(len, AMA_BASE64_STANDARD_PADDED) == strlen(std[t]),
              "standard encoded length");
        CHECK(ama_base64_encoded_len(len, AMA_BASE64_URL_UNPADDED) == strlen(url[t]),
              "url encoded length");
        CHECK(ama_base64_encode(enc, sizeof enc, p, len, AMA_BASE64_STANDARD_PADDED, &n)
                      == AMA_SUCCESS &&
                  n == strlen(std[t]) && memcmp(enc, std[t], n) == 0,
              "RFC 4648 §10 standard encode");
        CHECK(ama_base64_encode(enc, sizeof enc, p, len, AMA_BASE64_URL_UNPADDED, &n)
                      == AMA_SUCCESS &&
                  n == strlen(url[t]) && memcmp(enc, url[t], n) == 0,
              "RFC 4648 §10 url encode");
        CHECK(ama_base64_decode(dec, sizeof dec, std[t], strlen(std[t]),
                                AMA_BASE64_STANDARD_PADDED, &n) == AMA_SUCCESS &&
                  n == len && memcmp(dec, p, len) == 0,
              "RFC 4648 §10 standard decode");
        CHECK(ama_base64_decode(dec, sizeof dec, url[t], strlen(url[t]),
                                AMA_BASE64_URL_UNPADDED, &n) == AMA_SUCCESS &&
                  n == len && memcmp(dec, p, len) == 0,
              "RFC 4648 §10 url decode");
    }
    /* The two characters the variants do not share. */
    {
        static const uint8_t hi[3] = {0xFB, 0xFF, 0xBF};
        char enc[8];
        size_t n = 0;
        CHECK(ama_base64_encode(enc, sizeof enc, hi, 3, AMA_BASE64_STANDARD_PADDED, &n)
                      == AMA_SUCCESS && n == 4u && memcmp(enc, "+/+/", 4) == 0,
              "standard alphabet's 62 and 63");
        CHECK(ama_base64_encode(enc, sizeof enc, hi, 3, AMA_BASE64_URL_UNPADDED, &n)
                      == AMA_SUCCESS && n == 4u && memcmp(enc, "-_-_", 4) == 0,
              "url alphabet's 62 and 63");
    }
}

/* ---- named refusals ------------------------------------------------------ */

static void test_named_refusals(void) {
    static const char *const bad_std[] = {
        "Zh==",     /* pad bits not zero (§3.5) */
        "Zm9=",     /* pad bits not zero */
        "Zg=",      /* length not a multiple of four */
        "Z===",     /* three '=' */
        "Zg=A",     /* '=' inside the body */
        "Zm9v!g==", /* outside the alphabet */
        "Zm-v",     /* url character in standard input */
        "=Zg=",     /* leading '=' */
        "Zg==Zg==", /* padding before the end */
        "Zm8==",    /* five characters */
    };
    static const char *const bad_url[] = {
        "Zh", "Zm9", "Zg==", "Z", "Zm+v", "Zm/v", "Zm9v=", "Zm9vY",
    };
    for (size_t t = 0; t < sizeof bad_std / sizeof bad_std[0]; t++) {
        uint8_t out[16];
        size_t n = 99;
        CHECK(ama_base64_decode(out, sizeof out, bad_std[t], strlen(bad_std[t]),
                                AMA_BASE64_STANDARD_PADDED, &n) != AMA_SUCCESS && n == 0u,
              bad_std[t]);
    }
    for (size_t t = 0; t < sizeof bad_url / sizeof bad_url[0]; t++) {
        uint8_t out[16];
        size_t n = 99;
        CHECK(ama_base64_decode(out, sizeof out, bad_url[t], strlen(bad_url[t]),
                                AMA_BASE64_URL_UNPADDED, &n) != AMA_SUCCESS && n == 0u,
              bad_url[t]);
    }
    /* A one-character final group, followed in memory by a valid character
     * the length excludes.  A decoder that does not refuse the length reads
     * that character as the group's second and accepts "A" as one 0x00. */
    {
        static const char follow[] = "AAAAAA";
        uint8_t out[16];
        size_t n = 99;
        CHECK(ama_base64_decode(out, sizeof out, follow, 1, AMA_BASE64_URL_UNPADDED, &n)
                      != AMA_SUCCESS && n == 0u,
              "a one-character final group is refused, not read past");
        n = 99;
        CHECK(ama_base64_decode(out, sizeof out, follow, 5, AMA_BASE64_URL_UNPADDED, &n)
                      != AMA_SUCCESS && n == 0u,
              "a one-character final group after a full group is refused");
    }
}

/* ---- 2. differentials ---------------------------------------------------- */

/* Both alphabets, '=', and five near neighbours; 0x80 and NUL are added in
 * test_exhaustive_short_strings for 74 characters. */
static const char PROBE[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/-_="
    "@[`{.";

static void test_exhaustive_short_strings(void) {
    char probe[sizeof PROBE + 2];
    size_t k = sizeof PROBE - 1u;
    memcpy(probe, PROBE, k);
    probe[k++] = (char)0x80; /* high bit: not ASCII */
    probe[k++] = (char)0x00; /* NUL: an embedded terminator */
    const size_t a = k;      /* 74 */
    unsigned long checked = 0;

    for (int url = 0; url < 2; url++) {
        char s[4];
        checked++;
        if (!agree(s, 0, url)) {
            failures++;
            report_disagreement(s, 0, url);
        }
        for (size_t len = 1; len <= 4u; len++) {
            size_t total = 1;
            for (size_t i = 0; i < len; i++) {
                total *= a;
            }
            for (size_t idx = 0; idx < total; idx++) {
                size_t v = idx;
                for (size_t i = 0; i < len; i++) {
                    s[i] = probe[v % a];
                    v /= a;
                }
                checked++;
                if (!agree(s, len, url)) {
                    failures++;
                    report_disagreement(s, len, url);
                }
            }
        }
    }
    printf("  exhaustive: %lu strings of length 0..4 agree with the reference\n", checked);
}

static uint64_t rng_state = 0x9E3779B97F4A7C15ull;

static uint32_t next_u32(void) {
    /* xorshift64*: deterministic, so a failure reproduces. */
    rng_state ^= rng_state >> 12;
    rng_state ^= rng_state << 25;
    rng_state ^= rng_state >> 27;
    return (uint32_t)((rng_state * 0x2545F4914F6CDD1Dull) >> 32);
}

static void test_random_round_trips(void) {
    for (int it = 0; it < 200000; it++) {
        uint8_t buf[96];
        size_t len = next_u32() % 97u;
        for (size_t i = 0; i < len; i++) {
            buf[i] = (uint8_t)next_u32();
        }
        for (int url = 0; url < 2; url++) {
            char want[136];
            char got[136];
            uint8_t back[96];
            size_t want_len = ref_encode(want, buf, len, url);
            size_t got_len = 0;
            size_t back_len = 0;
            ama_error_t rc =
                ama_base64_encode(got, sizeof got, buf, len, variant_of(url), &got_len);
            if (rc != AMA_SUCCESS || got_len != want_len || memcmp(got, want, want_len) != 0 ||
                got_len != ama_base64_encoded_len(len, variant_of(url))) {
                failures++;
                printf("FAIL: encode differs from the reference at len %zu\n", len);
                return;
            }
            rc = ama_base64_decode(back, sizeof back, got, got_len, variant_of(url), &back_len);
            if (rc != AMA_SUCCESS || back_len != len || memcmp(back, buf, len) != 0) {
                failures++;
                printf("FAIL: decode does not invert encode at len %zu\n", len);
                return;
            }
        }
    }
}

static void test_random_multi_group_strings(void) {
    const size_t a = sizeof PROBE - 1u;
    for (int it = 0; it < 200000; it++) {
        char s[12];
        size_t len = (next_u32() & 1u) ? 8u : 12u;
        for (size_t i = 0; i < len; i++) {
            /* Mostly in-alphabet, so the verdict is decided late. */
            uint32_t r = next_u32();
            s[i] = (r % 8u == 0u) ? PROBE[r % a] : STD_ALPHABET[r % 64u];
        }
        if (len == 12u && (next_u32() & 1u)) {
            s[11] = '=';
            if (next_u32() & 1u) {
                s[10] = '=';
            }
        }
        for (int url = 0; url < 2; url++) {
            if (!agree(s, len, url)) {
                failures++;
                report_disagreement(s, len, url);
            }
        }
    }
}

/* ---- 3. a refused decode zeroes what it wrote ---------------------------- */

static void test_refusal_zeroes_output(void) {
    uint8_t out[16];
    size_t n = 99;
    /* Two full groups decode before the bad pad bits in the third. */
    memset(out, 0xA5, sizeof out);
    CHECK(ama_base64_decode(out, sizeof out, "Zm9vYmFyZh==", 12, AMA_BASE64_STANDARD_PADDED,
                            &n) != AMA_SUCCESS,
          "pad bits refused after two good groups");
    int zero = 1;
    for (size_t i = 0; i < 7u; i++) {
        zero &= out[i] == 0u;
    }
    CHECK(zero, "a refused decode zeroes every octet it wrote");
    CHECK(out[7] == 0xA5u, "and nothing past them");
    /* A bad character in the FIRST group, good ones after it: the decoder
     * runs to the end rather than stopping, and still zeroes. */
    memset(out, 0xA5, sizeof out);
    CHECK(ama_base64_decode(out, sizeof out, "Z!9vYmFy", 8, AMA_BASE64_URL_UNPADDED, &n)
              != AMA_SUCCESS,
          "early bad character refused");
    zero = 1;
    for (size_t i = 0; i < 6u; i++) {
        zero &= out[i] == 0u;
    }
    CHECK(zero, "an early refusal zeroes the later groups it decoded too");
}

/* ---- 4. argument refusals ------------------------------------------------ */

static void test_argument_refusals(void) {
    static const uint8_t data[3] = {1, 2, 3};
    char enc[8];
    uint8_t dec[8];
    size_t n = 99;
    const ama_base64_variant_t bogus = (ama_base64_variant_t)0;

    CHECK(ama_base64_encode(enc, sizeof enc, data, 3, AMA_BASE64_STANDARD_PADDED, NULL)
              == AMA_ERROR_INVALID_PARAM, "encode: NULL out_len");
    CHECK(ama_base64_decode(dec, sizeof dec, "AQID", 4, AMA_BASE64_STANDARD_PADDED, NULL)
              == AMA_ERROR_INVALID_PARAM, "decode: NULL out_len");
    n = 99;
    CHECK(ama_base64_encode(enc, sizeof enc, NULL, 3, AMA_BASE64_STANDARD_PADDED, &n)
              == AMA_ERROR_INVALID_PARAM && n == 0u, "encode: NULL input");
    n = 99;
    CHECK(ama_base64_encode(NULL, 0, data, 3, AMA_BASE64_STANDARD_PADDED, &n)
              == AMA_ERROR_INVALID_PARAM && n == 0u, "encode: NULL output");
    n = 99;
    CHECK(ama_base64_encode(enc, 3, data, 3, AMA_BASE64_STANDARD_PADDED, &n)
              == AMA_ERROR_INVALID_PARAM && n == 0u, "encode: output one short");
    n = 99;
    CHECK(ama_base64_encode(enc, sizeof enc, data, 3, bogus, &n) == AMA_ERROR_INVALID_PARAM &&
              n == 0u, "encode: unknown variant");
    n = 99;
    CHECK(ama_base64_decode(dec, sizeof dec, NULL, 4, AMA_BASE64_STANDARD_PADDED, &n)
              == AMA_ERROR_INVALID_PARAM && n == 0u, "decode: NULL input");
    n = 99;
    CHECK(ama_base64_decode(NULL, 0, "AQID", 4, AMA_BASE64_STANDARD_PADDED, &n)
              == AMA_ERROR_INVALID_PARAM && n == 0u, "decode: NULL output");
    /* A NULL buffer with a capacity that would otherwise suffice: only the
     * NULL check stands between this and a write through NULL (the capacity
     * check alone refuses the two cases above). */
    n = 99;
    CHECK(ama_base64_decode(NULL, sizeof dec, "AQID", 4, AMA_BASE64_STANDARD_PADDED, &n)
              == AMA_ERROR_INVALID_PARAM && n == 0u, "decode: NULL output, claimed capacity");
    n = 99;
    CHECK(ama_base64_encode(NULL, sizeof enc, data, 3, AMA_BASE64_STANDARD_PADDED, &n)
              == AMA_ERROR_INVALID_PARAM && n == 0u, "encode: NULL output, claimed capacity");
    n = 99;
    memset(dec, 0xA5, sizeof dec);
    CHECK(ama_base64_decode(dec, 2, "AQID", 4, AMA_BASE64_STANDARD_PADDED, &n)
              == AMA_ERROR_INVALID_PARAM && n == 0u && dec[0] == 0xA5u,
          "decode: output one short, nothing written");
    n = 99;
    CHECK(ama_base64_decode(dec, sizeof dec, "AQID", 4, bogus, &n) == AMA_ERROR_INVALID_PARAM &&
              n == 0u, "decode: unknown variant");
    CHECK(ama_base64_encoded_len(3, bogus) == 0u, "encoded_len: unknown variant");
    /* Empty input is where an unknown variant is refused by the entry point
     * itself rather than by a zero encoded length. */
    n = 99;
    CHECK(ama_base64_encode(enc, sizeof enc, data, 0, bogus, &n) == AMA_ERROR_INVALID_PARAM &&
              n == 0u, "encode: unknown variant, empty input");
    n = 99;
    CHECK(ama_base64_decode(dec, sizeof dec, "", 0, bogus, &n) == AMA_ERROR_INVALID_PARAM &&
              n == 0u, "decode: unknown variant, empty input");
    CHECK(ama_base64_encoded_len(SIZE_MAX, AMA_BASE64_STANDARD_PADDED) == 0u,
          "encoded_len: overflow refused");
    /* The boundary, exactly (PR #415 review).  F = SIZE_MAX / 4 full groups
     * is the most that fit: padded, 3F octets encode to 4F characters and
     * 3F + 1 do not fit; unpadded, 3F + 2 octets encode to 4F + 3 = SIZE_MAX
     * and 3F + 3 do not fit.  The former cutoff refused everything above
     * 3F - 3, which fails the first, second and fourth rows (PIN), and no
     * check at all fails the overflow row above (PIN).  The `- tail` term is
     * not separately pinned: with it dropped, the padded 3F + 1 case computes
     * 4F + 4 = SIZE_MAX + 1, which wraps to exactly 0 for every size_t
     * (SIZE_MAX % 4 == 3), so that mutant is equivalent (AGENTS.md 6.3). */
    {
        const size_t f = SIZE_MAX / 4u;
        CHECK(ama_base64_encoded_len(3u * f, AMA_BASE64_STANDARD_PADDED) == 4u * f,
              "encoded_len: padded, largest representable");
        CHECK(ama_base64_encoded_len(3u * f - 1u, AMA_BASE64_STANDARD_PADDED) == 4u * f,
              "encoded_len: padded, partial last group at the boundary");
        CHECK(ama_base64_encoded_len(3u * f + 1u, AMA_BASE64_STANDARD_PADDED) == 0u,
              "encoded_len: padded, first unrepresentable");
        CHECK(ama_base64_encoded_len(3u * f + 2u, AMA_BASE64_URL_UNPADDED) == SIZE_MAX,
              "encoded_len: unpadded, largest representable");
        CHECK(ama_base64_encoded_len(3u * f + 3u, AMA_BASE64_URL_UNPADDED) == 0u,
              "encoded_len: unpadded, first unrepresentable");
    }
    /* Empty in, empty out, with NULL buffers: nothing to read or write. */
    n = 99;
    CHECK(ama_base64_encode(NULL, 0, NULL, 0, AMA_BASE64_STANDARD_PADDED, &n) == AMA_SUCCESS &&
              n == 0u, "encode: empty");
    n = 99;
    CHECK(ama_base64_decode(NULL, 0, NULL, 0, AMA_BASE64_URL_UNPADDED, &n) == AMA_SUCCESS &&
              n == 0u, "decode: empty");
}

int main(void) {
    printf("ama_base64: constant-time Base64 / Base64url codec\n");
    test_rfc4648_vectors();
    test_named_refusals();
    test_exhaustive_short_strings();
    test_random_round_trips();
    test_random_multi_group_strings();
    test_refusal_zeroes_output();
    test_argument_refusals();
    if (failures != 0) {
        printf("FAILED: %d check(s)\n", failures);
        return 1;
    }
    printf("PASSED\n");
    return 0;
}
