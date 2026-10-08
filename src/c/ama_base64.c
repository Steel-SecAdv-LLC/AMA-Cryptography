/* Copyright (C) 2025-2026 Steel Security Advisors LLC */
/* SPDX-License-Identifier: Apache-2.0 */
/**
 * @file ama_base64.c
 * @brief Constant-time Base64 and Base64url codec (RFC 4648 §4, §5)
 *
 * Private keys leave this library as PEM (Base64, RFC 7468) and as JWK
 * (unpadded Base64url, RFC 7515 §2).  A table-driven codec -- CPython's
 * binascii and most others -- indexes a 64-entry alphabet by each secret
 * 6-bit group when encoding, and a 256-entry reverse table by each secret
 * character when decoding: a memory access whose address is the secret,
 * which INVARIANT-12 rule 4 prohibits.  This codec has no tables.  A 6-bit
 * group becomes its character by masked offset arithmetic, and a character
 * is classified against every range of the alphabet with unsigned-borrow
 * masks, so the instructions retired and the addresses touched depend only
 * on the lengths.
 *
 * Decoding is strict and canonical.  Every character must be in the
 * variant's alphabet, the padding must be exactly what RFC 4648 prescribes
 * for the length (none at all for the unpadded variant), and the unused low
 * bits of the last group must be zero (§3.5), so one octet string has exactly
 * one accepted encoding.  All three are evaluated over the whole input and
 * folded into one error mask: there is no exit at the first bad character,
 * whose position would otherwise be observable.  A refused decode zeroes
 * every octet it wrote.
 *
 * Two values derived from the input decide control flow, and both are
 * declassified (AMA_CT_DECLASSIFY, see internal/ama_ct_declassify.h) where
 * they are computed: the number of '=' characters, which fixes the decoded
 * length the caller receives in *out_len, and the accept/refuse verdict,
 * which the caller receives as the return code.  Nothing else derived from
 * the input reaches a branch or an address.  The `base64` targets of
 * tools/check_ghash_constant_time.py hold this: instruction counts equal
 * across secret classes, and a Memcheck taint run over a secret input.
 */

#include "../include/ama_cryptography.h"
#include "internal/ama_ct_declassify.h"
#include <stddef.h>
#include <stdint.h>

/* All-ones when lo <= c <= hi, else zero.  In unsigned 32-bit arithmetic,
 * (lo - 1 - c) has its top bit set exactly when c >= lo and (c - hi - 1)
 * exactly when c <= hi, for every c, lo, hi below 2^31; the AND keeps the top
 * bit when both hold, and negation widens it to a mask with no branch and no
 * signed shift. */
static uint32_t in_range(uint32_t c, uint32_t lo, uint32_t hi) {
    uint32_t t = ((lo - 1u - c) & (c - hi - 1u)) >> 31;
    return 0u - t;
}

static uint32_t eq_mask(uint32_t a, uint32_t b) {
    return in_range(a, b, b);
}

/* All-ones when v != 0, else zero. */
static uint32_t nonzero_mask(uint32_t v) {
    return 0u - ((v | (0u - v)) >> 31);
}

/* The two characters in which the variants differ.  `variant` is public. */
static uint32_t char62(ama_base64_variant_t variant) {
    return (variant == AMA_BASE64_URL_UNPADDED) ? (uint32_t)'-' : (uint32_t)'+';
}

static uint32_t char63(ama_base64_variant_t variant) {
    return (variant == AMA_BASE64_URL_UNPADDED) ? (uint32_t)'_' : (uint32_t)'/';
}

static char enc6(uint32_t v, uint32_t c62, uint32_t c63) {
    uint32_t out = 0;
    out |= in_range(v, 0u, 25u) & (v + (uint32_t)'A');
    out |= in_range(v, 26u, 51u) & (v - 26u + (uint32_t)'a');
    out |= in_range(v, 52u, 61u) & (v - 52u + (uint32_t)'0');
    out |= eq_mask(v, 62u) & c62;
    out |= eq_mask(v, 63u) & c63;
    return (char)out;
}

/* Bit 6 of dec6's result: set when the character is outside the alphabet. */
#define DEC6_INVALID 0x40u

/* The value 0..63 of character c in bits 0-5, and DEC6_INVALID when c is
 * not in the variant's alphabet.  A pure function: the decoder ORs the flags
 * of a group in one statement of its own, so no expression both writes and
 * reads the verdict (tests/test_unsequenced_predicate_gate.py). */
static uint32_t dec6(uint32_t c, uint32_t c62, uint32_t c63) {
    uint32_t m_upper = in_range(c, (uint32_t)'A', (uint32_t)'Z');
    uint32_t m_lower = in_range(c, (uint32_t)'a', (uint32_t)'z');
    uint32_t m_digit = in_range(c, (uint32_t)'0', (uint32_t)'9');
    uint32_t m_62 = eq_mask(c, c62);
    uint32_t m_63 = eq_mask(c, c63);
    uint32_t v = 0;
    v |= m_upper & (c - (uint32_t)'A');
    v |= m_lower & (c - (uint32_t)'a' + 26u);
    v |= m_digit & (c - (uint32_t)'0' + 52u);
    v |= m_62 & 62u;
    v |= m_63 & 63u;
    return (v & 63u) | (~(m_upper | m_lower | m_digit | m_62 | m_63) & DEC6_INVALID);
}

static void zero_bytes(uint8_t *p, size_t n) {
    volatile uint8_t *q = p;
    for (size_t i = 0; i < n; i++) {
        q[i] = 0;
    }
}

static int variant_ok(ama_base64_variant_t variant) {
    return variant == AMA_BASE64_STANDARD_PADDED || variant == AMA_BASE64_URL_UNPADDED;
}

AMA_API size_t ama_base64_encoded_len(size_t bin_len, ama_base64_variant_t variant) {
    /* Largest bin_len whose padded encoding, (bin_len / 3 + 1) * 4, fits in
     * size_t; the unpadded encoding is never longer. */
    if (!variant_ok(variant) || bin_len > (SIZE_MAX / 4u) * 3u - 3u) {
        return 0;
    }
    size_t full = bin_len / 3u;
    size_t rem = bin_len % 3u;
    if (variant == AMA_BASE64_URL_UNPADDED) {
        return full * 4u + (rem == 0u ? 0u : rem + 1u);
    }
    return (full + (rem != 0u ? 1u : 0u)) * 4u;
}

AMA_API ama_error_t ama_base64_encode(char *out, size_t out_cap,
                                      const uint8_t *in, size_t in_len,
                                      ama_base64_variant_t variant,
                                      size_t *out_len) {
    if (out_len == NULL) {
        return AMA_ERROR_INVALID_PARAM;
    }
    *out_len = 0;
    if (!variant_ok(variant) || (in == NULL && in_len > 0u)) {
        return AMA_ERROR_INVALID_PARAM;
    }
    size_t need = ama_base64_encoded_len(in_len, variant);
    if ((need == 0u && in_len > 0u) || out_cap < need || (out == NULL && need > 0u)) {
        return AMA_ERROR_INVALID_PARAM;
    }
    const uint32_t c62 = char62(variant);
    const uint32_t c63 = char63(variant);
    size_t i = 0;
    size_t o = 0;
    for (; in_len - i >= 3u; i += 3u) {
        uint32_t w = ((uint32_t)in[i] << 16) | ((uint32_t)in[i + 1u] << 8) | (uint32_t)in[i + 2u];
        out[o++] = enc6((w >> 18) & 63u, c62, c63);
        out[o++] = enc6((w >> 12) & 63u, c62, c63);
        out[o++] = enc6((w >> 6) & 63u, c62, c63);
        out[o++] = enc6(w & 63u, c62, c63);
    }
    /* The tail's shape is in_len % 3: public. */
    size_t rem = in_len - i;
    if (rem != 0u) {
        uint32_t w = (uint32_t)in[i] << 16;
        if (rem == 2u) {
            w |= (uint32_t)in[i + 1u] << 8;
        }
        out[o++] = enc6((w >> 18) & 63u, c62, c63);
        out[o++] = enc6((w >> 12) & 63u, c62, c63);
        if (rem == 2u) {
            out[o++] = enc6((w >> 6) & 63u, c62, c63);
        }
        if (variant == AMA_BASE64_STANDARD_PADDED) {
            if (rem == 1u) {
                out[o++] = '=';
            }
            out[o++] = '=';
        }
    }
    *out_len = o;
    return AMA_SUCCESS;
}

AMA_API ama_error_t ama_base64_decode(uint8_t *out, size_t out_cap,
                                      const char *in, size_t in_len,
                                      ama_base64_variant_t variant,
                                      size_t *out_len) {
    if (out_len == NULL) {
        return AMA_ERROR_INVALID_PARAM;
    }
    *out_len = 0;
    if (!variant_ok(variant) || (in == NULL && in_len > 0u)) {
        return AMA_ERROR_INVALID_PARAM;
    }
    /* Structure first, from the public length alone. */
    size_t pad = 0;
    if (variant == AMA_BASE64_STANDARD_PADDED) {
        if (in_len % 4u != 0u) {
            return AMA_ERROR_INVALID_PARAM;
        }
        if (in_len > 0u) {
            /* The '=' count, read without a branch on either character.  It
             * decides the decoded length, which the caller receives in
             * *out_len, so it is public by the function's own output; it is
             * declassified here, where it is computed, and nowhere else. */
            uint32_t last = eq_mask((uint8_t)in[in_len - 1u], (uint32_t)'=');
            uint32_t second = eq_mask((uint8_t)in[in_len - 2u], (uint32_t)'=') & last;
            uint32_t npad = (last & 1u) + (second & 1u);
            AMA_CT_DECLASSIFY(&npad, sizeof npad);
            pad = (size_t)npad;
        }
    }
    const size_t body = in_len - pad;
    const size_t full = body / 4u;
    const size_t rem = body % 4u;
    /* A final group of one character carries six bits, and no octet string
     * encodes to it.  Reachable only unpadded: a padded input is a multiple
     * of four with at most two '=', so its body leaves 0, 2 or 3 -- and that
     * is also why the '=' count needs no check of its own, it is always the
     * one the body length requires.  An '=' anywhere but the last two places
     * is outside the alphabet, and dec6 flags it. */
    if (rem == 1u) {
        return AMA_ERROR_INVALID_PARAM;
    }
    const size_t need = full * 3u + (rem == 0u ? 0u : rem - 1u);
    /* need > 0 exactly when body > 0 (a one-character tail was refused
     * above), so a NULL `out` is refused for any input that decodes to an
     * octet.  Stated on `body`, the bound the loops below read, so the
     * relation is visible to a path-sensitive analyser as well. */
    if (out_cap < need || (out == NULL && body > 0u)) {
        return AMA_ERROR_INVALID_PARAM;
    }
    const uint32_t c62 = char62(variant);
    const uint32_t c63 = char63(variant);
    uint32_t bad = 0;
    size_t i = 0;
    size_t o = 0;
    for (; body - i >= 4u; i += 4u) {
        const uint32_t d0 = dec6((uint8_t)in[i], c62, c63);
        const uint32_t d1 = dec6((uint8_t)in[i + 1u], c62, c63);
        const uint32_t d2 = dec6((uint8_t)in[i + 2u], c62, c63);
        const uint32_t d3 = dec6((uint8_t)in[i + 3u], c62, c63);
        bad |= (d0 | d1 | d2 | d3) & DEC6_INVALID;
        uint32_t w = ((d0 & 63u) << 18) | ((d1 & 63u) << 12) | ((d2 & 63u) << 6) | (d3 & 63u);
        out[o++] = (uint8_t)(w >> 16);
        out[o++] = (uint8_t)(w >> 8);
        out[o++] = (uint8_t)w;
    }
    if (rem != 0u) {
        const uint32_t d0 = dec6((uint8_t)in[i], c62, c63);
        const uint32_t d1 = dec6((uint8_t)in[i + 1u], c62, c63);
        /* The third character exists only when rem == 3; rem is public. */
        const uint32_t d2 = (rem == 3u) ? dec6((uint8_t)in[i + 2u], c62, c63) : 0u;
        bad |= (d0 | d1 | d2) & DEC6_INVALID;
        uint32_t w = ((d0 & 63u) << 18) | ((d1 & 63u) << 12) | ((d2 & 63u) << 6);
        out[o++] = (uint8_t)(w >> 16);
        if (rem == 3u) {
            out[o++] = (uint8_t)(w >> 8);
        }
        /* RFC 4648 §3.5: the bits below the last emitted octet must be zero,
         * or two encodings would decode to one key. */
        bad |= nonzero_mask((rem == 2u) ? (w & 0xFFFFu) : (w & 0xFFu));
    }
    /* The verdict is the return code: public by the function's own output. */
    AMA_CT_DECLASSIFY(&bad, sizeof bad);
    if (bad != 0u) {
        zero_bytes(out, o);
        return AMA_ERROR_INVALID_PARAM;
    }
    *out_len = o;
    return AMA_SUCCESS;
}
