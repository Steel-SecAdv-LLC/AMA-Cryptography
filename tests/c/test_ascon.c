/* Copyright (C) 2025-2026 Steel Security Advisors LLC */
/* SPDX-License-Identifier: Apache-2.0 */
/**
 * @file test_ascon.c
 * @brief Known-answer and property tests for Ascon-AEAD128 / Ascon-Hash256
 *
 * The verification is layered deliberately, because a mode-level KAT alone
 * cannot distinguish "the permutation is right" from "two errors cancelled":
 *
 *   1. The substitution layer is checked against the lookup-table
 *      representation in SP 800-232 Table 6, for all 32 inputs.  The shipped
 *      code evaluates the S-box bitsliced; the table is the specification's
 *      own independent statement of the same function.
 *   2. Ascon-p[12] is checked against the precomputed Ascon-Hash256
 *      initialization state published in SP 800-232 Appendix A.3.  That value
 *      comes from the standard, not from this implementation.
 *   3. Both modes are then swept over the full published KAT corpus —
 *      1089 Ascon-AEAD128 vectors and 1025 Ascon-Hash256 vectors, covering
 *      every plaintext length 0..32 crossed with every AD length 0..32, which
 *      exercises the empty-input, sub-rate, exact-rate and rate+1 boundaries
 *      in both the rate-128 AEAD and the rate-64 hash.
 *   4. Negative and contract tests: tag forgery, AD tampering, nonce reuse
 *      detection, and the fail-closed guarantee that a rejected decryption
 *      leaves the caller's plaintext buffer untouched.
 *
 * Vector provenance is recorded in tests/kat/ascon/README.md.
 */

#include "../../include/ama_cryptography.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

static int g_failures = 0;
static int g_checks = 0;

#define CHECK(cond, ...)                                                      \
    do {                                                                      \
        g_checks++;                                                           \
        if (!(cond)) {                                                        \
            g_failures++;                                                     \
            printf("  FAIL %s:%d: ", __FILE__, __LINE__);                     \
            printf(__VA_ARGS__);                                              \
            printf("\n");                                                     \
        }                                                                     \
    } while (0)

/* ============================================================================
 * 1. SUBSTITUTION LAYER vs SP 800-232 TABLE 6
 * ============================================================================ */

/** Table 6: lookup-table representation of the 5-bit SBOX. */
static const uint8_t SBOX_TABLE[32] = {
    0x04, 0x0B, 0x1F, 0x14, 0x1A, 0x15, 0x09, 0x02,
    0x1B, 0x05, 0x08, 0x12, 0x1D, 0x03, 0x06, 0x1C,
    0x1E, 0x13, 0x07, 0x0E, 0x00, 0x0D, 0x11, 0x18,
    0x10, 0x0C, 0x01, 0x19, 0x16, 0x0A, 0x0F, 0x17
};

/**
 * The same 22 boolean operations the shipped substitution layer applies to
 * 64-bit words, transcribed here at a width of one bit.
 *
 * What this proves and what it does not, stated plainly: the shipped p_S
 * cannot be called in isolation — every entry point runs a full round, so
 * p_C and p_L are always mixed in — and inverting p_L to recover the S-box
 * output would take more test machinery than the thing under test.  So this
 * checks the *expression* against the specification's own independent
 * statement of the same function (Table 6).  It catches a transcription error
 * in the boolean chain, which is the realistic failure mode; it does not by
 * itself prove the shipped code runs this chain.
 *
 * That second half is what test_permutation_precomputed_state covers: a wrong
 * S-box in the shipped path cannot produce the correct 320-bit Appendix A.3
 * output.  The two together pin both halves.
 */
static uint8_t sbox_bitsliced_reference(uint8_t x) {
    /* The same 22 boolean operations the shipped code applies to 64-bit
     * words, applied here to single bits.  If this diverges from Table 6 the
     * shipped substitution layer is wrong, because they are the same
     * expression. */
    uint8_t x0 = (uint8_t)((x >> 4) & 1u);
    uint8_t x1 = (uint8_t)((x >> 3) & 1u);
    uint8_t x2 = (uint8_t)((x >> 2) & 1u);
    uint8_t x3 = (uint8_t)((x >> 1) & 1u);
    uint8_t x4 = (uint8_t)(x & 1u);
    uint8_t t0, t1, t2, t3, t4;

    x0 ^= x4; x4 ^= x3; x2 ^= x1;
    t0 = (uint8_t)(~x0 & 1u & x1);
    t1 = (uint8_t)(~x1 & 1u & x2);
    t2 = (uint8_t)(~x2 & 1u & x3);
    t3 = (uint8_t)(~x3 & 1u & x4);
    t4 = (uint8_t)(~x4 & 1u & x0);
    x0 ^= t1; x1 ^= t2; x2 ^= t3; x3 ^= t4; x4 ^= t0;
    x1 ^= x0; x0 ^= x4; x3 ^= x2; x2 = (uint8_t)(~x2 & 1u);

    return (uint8_t)((x0 << 4) | (x1 << 3) | (x2 << 2) | (x3 << 1) | x4);
}

static void test_sbox_matches_table6(void) {
    printf("Test: substitution layer vs SP 800-232 Table 6\n");
    for (unsigned x = 0; x < 32u; ++x) {
        uint8_t got = sbox_bitsliced_reference((uint8_t)x);
        CHECK(got == SBOX_TABLE[x],
              "SBOX(0x%02x) = 0x%02x, Table 6 says 0x%02x",
              x, got, SBOX_TABLE[x]);
    }
}

/* ============================================================================
 * 2. Ascon-p[12] vs SP 800-232 APPENDIX A.3 PRECOMPUTED STATE
 * ============================================================================ */

static void test_permutation_precomputed_state(void) {
    /* SP 800-232 Appendix A.3: the state after Ascon-p[12](IV || 0^256) for
     * Ascon-Hash256, published so implementations may skip the computation.
     * This library computes it instead, which is precisely what lets the
     * published value serve as an independent check on the permutation. */
    uint64_t state[5] = { 0x0000080100CC0002ULL, 0, 0, 0, 0 };
    static const uint64_t expected[5] = {
        0x9B1E5494E934D681ULL, 0x4BC3A01E333751D2ULL,
        0xAE65396C6B34B81AULL, 0x3C7FD4A4D56A4DB3ULL,
        0x1A5C464906C5976DULL
    };

    printf("Test: Ascon-p[12] vs SP 800-232 Appendix A.3\n");
    ama_ascon_permutation_for_test(state, 12u);
    for (unsigned i = 0; i < 5u; ++i) {
        CHECK(state[i] == expected[i],
              "S%u = 0x%016llx, expected 0x%016llx",
              i, (unsigned long long)state[i],
              (unsigned long long)expected[i]);
    }
}

/* ============================================================================
 * KAT FILE PARSING
 * ============================================================================ */

static FILE *try_open_kat(const char *name) {
    char path[512];
    const char *prefixes[] = { "", "../", "../../" };
    for (int i = 0; i < 3; i++) {
        snprintf(path, sizeof(path), "%s%s", prefixes[i], name);
        FILE *f = fopen(path, "r");
        if (f) return f;
    }
    return NULL;
}

static int hexval(int c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    return -1;
}

static size_t unhex(const char *s, uint8_t *out, size_t cap) {
    size_t n = 0;
    while (s[0] && s[1] && hexval(s[0]) >= 0 && hexval(s[1]) >= 0 && n < cap) {
        out[n++] = (uint8_t)(hexval(s[0]) * 16 + hexval(s[1]));
        s += 2;
    }
    return n;
}

/**
 * Return the value part of a "Name = value" line, or NULL.
 *
 * Written to tolerate a trailing space on an empty value, which is how the
 * LWC KAT format writes a zero-length field.  Matching on the literal
 * "Name = " prefix instead silently leaves the previous record's value in
 * place for every empty field — a parser bug that makes the empty-AD and
 * empty-message vectors test the wrong thing while still reporting a count.
 */
static const char *kat_field(const char *line, const char *name) {
    size_t n = strlen(name);
    if (strncmp(line, name, n) != 0) return NULL;
    const char *p = line + n;
    while (*p == ' ') p++;
    if (*p != '=') return NULL;
    p++;
    while (*p == ' ') p++;
    return p;
}

static void strip_eol(char *s) {
    size_t l = strlen(s);
    while (l && (s[l - 1] == '\n' || s[l - 1] == '\r')) s[--l] = 0;
}

/* ============================================================================
 * 3a. Ascon-Hash256 KAT SWEEP
 * ============================================================================ */

static void test_hash256_kat(void) {
    char line[8192];
    uint8_t msg[2048], md[32], got[32];
    size_t msg_len = 0;
    long total = 0, bad = 0;

    printf("Test: Ascon-Hash256 known-answer vectors\n");
    FILE *f = try_open_kat("tests/kat/ascon/ascon_hash256.kat");
    if (!f) {
        printf("  FAIL cannot open tests/kat/ascon/ascon_hash256.kat\n");
        g_failures++;
        g_checks++;
        return;
    }

    while (fgets(line, sizeof line, f)) {
        const char *v;
        strip_eol(line);
        if ((v = kat_field(line, "Msg")) != NULL) {
            msg_len = unhex(v, msg, sizeof msg);
        } else if ((v = kat_field(line, "MD")) != NULL) {
            unhex(v, md, sizeof md);
            total++;
            if (ama_ascon_hash256(msg, msg_len, got) != AMA_SUCCESS ||
                memcmp(got, md, 32) != 0) {
                if (bad < 3) {
                    printf("  FAIL hash vector %ld (msg_len=%zu)\n",
                           total, msg_len);
                }
                bad++;
            }
        }
    }
    fclose(f);

    g_checks++;
    if (bad != 0) g_failures++;
    CHECK(total >= 1025, "expected >= 1025 hash vectors, parsed %ld", total);
    printf("  %ld vectors, %ld mismatches\n", total, bad);
}

/* ============================================================================
 * 3b. Ascon-AEAD128 KAT SWEEP (encrypt and decrypt)
 * ============================================================================ */

static void test_aead128_kat(void) {
    char line[8192];
    uint8_t key[16], nonce[16];
    uint8_t pt[2048], ad[2048], ct_expected[2048];
    uint8_t ct[2048], tag[16], back[2048];
    size_t pt_len = 0, ad_len = 0, ct_len = 0;
    long total = 0, bad_enc = 0, bad_dec = 0;

    printf("Test: Ascon-AEAD128 known-answer vectors\n");
    FILE *f = try_open_kat("tests/kat/ascon/ascon_aead128.kat");
    if (!f) {
        printf("  FAIL cannot open tests/kat/ascon/ascon_aead128.kat\n");
        g_failures++;
        g_checks++;
        return;
    }

    while (fgets(line, sizeof line, f)) {
        const char *v;
        strip_eol(line);
        if ((v = kat_field(line, "Key")) != NULL) {
            unhex(v, key, sizeof key);
        } else if ((v = kat_field(line, "Nonce")) != NULL) {
            unhex(v, nonce, sizeof nonce);
        } else if ((v = kat_field(line, "PT")) != NULL) {
            pt_len = unhex(v, pt, sizeof pt);
        } else if ((v = kat_field(line, "AD")) != NULL) {
            ad_len = unhex(v, ad, sizeof ad);
        } else if ((v = kat_field(line, "CT")) != NULL) {
            ct_len = unhex(v, ct_expected, sizeof ct_expected);
            total++;

            /* The KAT concatenates ciphertext || tag. */
            if (ct_len != pt_len + 16) {
                bad_enc++;
                continue;
            }
            if (ama_ascon_aead128_encrypt(key, nonce, pt, pt_len,
                                          ad, ad_len, ct, tag) != AMA_SUCCESS ||
                memcmp(ct, ct_expected, pt_len) != 0 ||
                memcmp(tag, ct_expected + pt_len, 16) != 0) {
                if (bad_enc < 3) {
                    printf("  FAIL encrypt vector %ld (pt=%zu ad=%zu)\n",
                           total, pt_len, ad_len);
                }
                bad_enc++;
                continue;
            }
            if (ama_ascon_aead128_decrypt(key, nonce, ct, pt_len,
                                          ad, ad_len, tag, back) != AMA_SUCCESS ||
                (pt_len != 0 && memcmp(back, pt, pt_len) != 0)) {
                if (bad_dec < 3) {
                    printf("  FAIL decrypt vector %ld (pt=%zu ad=%zu)\n",
                           total, pt_len, ad_len);
                }
                bad_dec++;
            }
        }
    }
    fclose(f);

    g_checks += 2;
    if (bad_enc != 0) g_failures++;
    if (bad_dec != 0) g_failures++;
    CHECK(total >= 1089, "expected >= 1089 AEAD vectors, parsed %ld", total);
    printf("  %ld vectors, %ld encrypt mismatches, %ld decrypt mismatches\n",
           total, bad_enc, bad_dec);
}

/* ============================================================================
 * 4. NEGATIVE AND CONTRACT TESTS
 * ============================================================================ */

static void test_aead_rejects_forgeries(void) {
    const uint8_t key[16] = { 0, 1, 2, 3, 4, 5, 6, 7,
                              8, 9, 10, 11, 12, 13, 14, 15 };
    const uint8_t nonce[16] = { 16, 17, 18, 19, 20, 21, 22, 23,
                                24, 25, 26, 27, 28, 29, 30, 31 };
    const uint8_t pt[40] = { 0 };
    const uint8_t ad[9] = { 9, 8, 7, 6, 5, 4, 3, 2, 1 };
    uint8_t ct[40], tag[16], out[40];

    printf("Test: Ascon-AEAD128 forgery rejection and fail-closed decrypt\n");

    CHECK(ama_ascon_aead128_encrypt(key, nonce, pt, sizeof pt,
                                    ad, sizeof ad, ct, tag) == AMA_SUCCESS,
          "encrypt failed");

    /* Every single-bit flip in the tag must be rejected. */
    for (unsigned byte = 0; byte < 16u; ++byte) {
        for (unsigned bit = 0; bit < 8u; ++bit) {
            uint8_t bad_tag[16];
            memcpy(bad_tag, tag, 16);
            bad_tag[byte] ^= (uint8_t)(1u << bit);
            CHECK(ama_ascon_aead128_decrypt(key, nonce, ct, sizeof ct,
                                            ad, sizeof ad, bad_tag,
                                            out) == AMA_ERROR_VERIFY_FAILED,
                  "tag flip byte %u bit %u accepted", byte, bit);
        }
    }

    /* Fail-closed: a rejected decryption must not touch the output buffer. */
    {
        uint8_t sentinel[40];
        uint8_t bad_tag[16];
        memset(sentinel, 0xA5, sizeof sentinel);
        memcpy(bad_tag, tag, 16);
        bad_tag[0] ^= 0x01;
        CHECK(ama_ascon_aead128_decrypt(key, nonce, ct, sizeof ct,
                                        ad, sizeof ad, bad_tag,
                                        sentinel) == AMA_ERROR_VERIFY_FAILED,
              "forged tag accepted");
        for (size_t i = 0; i < sizeof sentinel; ++i) {
            CHECK(sentinel[i] == 0xA5,
                  "fail-closed violated: output byte %zu was written", i);
        }
    }

    /* Tampering with associated data must invalidate the tag. */
    {
        uint8_t bad_ad[9];
        memcpy(bad_ad, ad, sizeof ad);
        bad_ad[4] ^= 0x20;
        CHECK(ama_ascon_aead128_decrypt(key, nonce, ct, sizeof ct,
                                        bad_ad, sizeof bad_ad, tag,
                                        out) == AMA_ERROR_VERIFY_FAILED,
              "AD tampering accepted");
    }

    /* Truncating the associated data must invalidate the tag. */
    CHECK(ama_ascon_aead128_decrypt(key, nonce, ct, sizeof ct,
                                    ad, sizeof ad - 1, tag,
                                    out) == AMA_ERROR_VERIFY_FAILED,
          "AD truncation accepted");

    /* Dropping the associated data entirely must invalidate the tag.  This
     * is the case the |A| > 0 guard in the absorb phase controls: if the
     * implementation absorbed a padding block for empty AD, an empty-AD
     * message would produce a different tag than the specification's. */
    CHECK(ama_ascon_aead128_decrypt(key, nonce, ct, sizeof ct,
                                    NULL, 0, tag,
                                    out) == AMA_ERROR_VERIFY_FAILED,
          "AD removal accepted");

    /* A different nonce must invalidate the tag. */
    {
        uint8_t bad_nonce[16];
        memcpy(bad_nonce, nonce, 16);
        bad_nonce[15] ^= 0x01;
        CHECK(ama_ascon_aead128_decrypt(key, bad_nonce, ct, sizeof ct,
                                        ad, sizeof ad, tag,
                                        out) == AMA_ERROR_VERIFY_FAILED,
              "nonce change accepted");
    }

    /* A different key must invalidate the tag. */
    {
        uint8_t bad_key[16];
        memcpy(bad_key, key, 16);
        bad_key[0] ^= 0x80;
        CHECK(ama_ascon_aead128_decrypt(bad_key, nonce, ct, sizeof ct,
                                        ad, sizeof ad, tag,
                                        out) == AMA_ERROR_VERIFY_FAILED,
              "key change accepted");
    }
}

static void test_nonce_reuse_is_visible(void) {
    /* Ascon-AEAD128 is not nonce-misuse resistant, and this pins the property
     * as documented rather than leaving it to be discovered.
     *
     * The extent matters and is asserted precisely: only the FIRST 16-byte
     * rate block XORs to the plaintext XOR.  The sponge absorbs plaintext
     * into the rate before permuting, so from block two onward the two states
     * have diverged and the keystreams differ — unlike a stream cipher, where
     * the whole message would leak.  The single-block message below is
     * therefore exactly one block by design; tests/test_ascon.py asserts the
     * multi-block half of the same property. */
    const uint8_t key[16] = { 0 };
    const uint8_t nonce[16] = { 1 };
    uint8_t p1[16], p2[16], c1[16], c2[16], t1[16], t2[16];

    printf("Test: nonce reuse leaks the plaintext XOR (documented property)\n");
    for (unsigned i = 0; i < 16u; ++i) {
        p1[i] = (uint8_t)i;
        p2[i] = (uint8_t)(0xFF - i);
    }
    CHECK(ama_ascon_aead128_encrypt(key, nonce, p1, 16, NULL, 0, c1, t1)
          == AMA_SUCCESS, "encrypt 1 failed");
    CHECK(ama_ascon_aead128_encrypt(key, nonce, p2, 16, NULL, 0, c2, t2)
          == AMA_SUCCESS, "encrypt 2 failed");
    for (unsigned i = 0; i < 16u; ++i) {
        CHECK((c1[i] ^ c2[i]) == (p1[i] ^ p2[i]),
              "keystream reuse property broken at byte %u", i);
    }
}

static void test_parameter_validation(void) {
    uint8_t key[16] = { 0 }, nonce[16] = { 0 }, tag[16] = { 0 };
    uint8_t buf[16] = { 0 }, digest[32] = { 0 };

    printf("Test: parameter validation\n");
    CHECK(ama_ascon_hash256(NULL, 0, NULL) == AMA_ERROR_INVALID_PARAM,
          "NULL digest accepted");
    CHECK(ama_ascon_hash256(NULL, 8, digest) == AMA_ERROR_INVALID_PARAM,
          "NULL message with nonzero length accepted");
    CHECK(ama_ascon_hash256(NULL, 0, digest) == AMA_SUCCESS,
          "NULL message with zero length rejected");
    CHECK(ama_ascon_aead128_encrypt(NULL, nonce, buf, 16, NULL, 0, buf, tag)
          == AMA_ERROR_INVALID_PARAM, "NULL key accepted");
    CHECK(ama_ascon_aead128_encrypt(key, NULL, buf, 16, NULL, 0, buf, tag)
          == AMA_ERROR_INVALID_PARAM, "NULL nonce accepted");
    CHECK(ama_ascon_aead128_encrypt(key, nonce, NULL, 16, NULL, 0, buf, tag)
          == AMA_ERROR_INVALID_PARAM, "NULL plaintext with length accepted");
    CHECK(ama_ascon_aead128_encrypt(key, nonce, NULL, 0, NULL, 0, buf, tag)
          == AMA_SUCCESS, "empty plaintext rejected");
}

static void test_empty_inputs(void) {
    /* SP 800-232 vector 1: empty plaintext, empty AD. */
    const uint8_t key[16] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                              0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F };
    const uint8_t nonce[16] = { 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
                                0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F };
    static const uint8_t expected_tag[16] = {
        0x4F, 0x9C, 0x27, 0x82, 0x11, 0xBE, 0xC9, 0x31,
        0x6B, 0xF6, 0x8F, 0x46, 0xEE, 0x8B, 0x2E, 0xC6
    };
    /* Ascon-Hash256 of the empty message. */
    static const uint8_t expected_digest[32] = {
        0x0B, 0x3B, 0xE5, 0x85, 0x0F, 0x2F, 0x6B, 0x98,
        0xCA, 0xF2, 0x9F, 0x8F, 0xDE, 0xA8, 0x9B, 0x64,
        0xA1, 0xFA, 0x70, 0xAA, 0x24, 0x9B, 0x8F, 0x83,
        0x9B, 0xD5, 0x3B, 0xAA, 0x30, 0x4D, 0x92, 0xB2
    };
    uint8_t tag[16], digest[32];

    printf("Test: empty-input vectors pinned inline\n");
    CHECK(ama_ascon_aead128_encrypt(key, nonce, NULL, 0, NULL, 0, NULL, tag)
          == AMA_SUCCESS, "empty encrypt failed");
    CHECK(memcmp(tag, expected_tag, 16) == 0, "empty-input tag mismatch");
    CHECK(ama_ascon_hash256(NULL, 0, digest) == AMA_SUCCESS,
          "empty hash failed");
    CHECK(memcmp(digest, expected_digest, 32) == 0,
          "empty-message digest mismatch");
}

int main(void) {
    printf("=== Ascon (NIST SP 800-232) test suite ===\n\n");

    test_sbox_matches_table6();
    test_permutation_precomputed_state();
    test_hash256_kat();
    test_aead128_kat();
    test_aead_rejects_forgeries();
    test_nonce_reuse_is_visible();
    test_parameter_validation();
    test_empty_inputs();

    printf("\n%d checks, %d failures\n", g_checks, g_failures);
    return g_failures == 0 ? 0 : 1;
}
