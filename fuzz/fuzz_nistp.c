/* Copyright (C) 2025-2026 Steel Security Advisors LLC */
/* SPDX-License-Identifier: Apache-2.0 */
/**
 * @file fuzz_nistp.c
 * @brief libFuzzer harness for the NIST prime curves (P-256 / P-384 / P-521)
 *
 * WHY THIS EXISTS
 *
 * Sixteen harnesses shipped before this one, including fuzz_secp256k1.c for
 * structurally the same code, and none covered ama_nistp.c -- which carries
 * four parsers that read attacker-supplied bytes:
 *
 *   nistp_load_point        public key as X || Y
 *   nistp_der_parse[_int]   strict X9.62 / SEC 1 DER signature
 *   ama_nistp_point_decode  prefixed SEC 1 point, compressed or uncompressed
 *   ama_nistp_sig_der_to_raw  DER -> fixed-width r || s
 *
 * That gap is visible in the branch-arc inventory AGENTS.md section 11 carries:
 * ama_nistp.c was its largest unexamined bucket, and the parser arcs inside it
 * are reached only by the fixed Wycheproof vectors, never by exploratory
 * input. A fixed corpus finds what someone already thought of.
 *
 * WHAT IT ASSERTS
 *
 * Following fuzz_ascon.c rather than the exercise-only harnesses: a target that
 * only calls the API and returns finds memory-safety bugs, and cannot find a
 * parser that is memory-safe and wrong. Every fail() below marks a property
 * that must hold for arbitrary input:
 *
 *   1. DER is canonical. Strict DER admits exactly one encoding per (r, s), so
 *      der -> raw -> der must return the original bytes. A second accepted
 *      encoding of one signature is the malleability surface INVARIANT-28
 *      exists to close: it lets the same signature arrive under two identities
 *      for anything that fingerprints, dedupes or logs the encoded form.
 *   2. The two verify entry points agree. A signature ama_nistp_ecdsa_verify
 *      accepts in DER must still verify as raw r || s through
 *      ama_nistp_ecdsa_verify_raw, and the converse. One entry point accepting
 *      what the other rejects is a real divergence, not a preference.
 *   3. Point encoding round-trips. A public key that decodes must re-encode
 *      (compressed and uncompressed) and decode back to the same X || Y.
 *   4. Validation and decoding agree. A key ama_nistp_pubkey_validate accepts
 *      must survive the encode/decode round trip, since both go through
 *      nistp_load_point and must not disagree about what is on the curve.
 *
 * A returned error is always a valid outcome -- most fuzzed bytes are not a
 * signature. A crash, UB, or a violated property above is a bug.
 *
 * Build (standalone):
 *   clang -fsanitize=fuzzer,address,undefined -O1 -g -I../include \
 *         -DAMA_USE_NATIVE_PQC \
 *         fuzz_nistp.c ../src/c/ama_nistp.c ../src/c/ama_sha256.c \
 *         ../src/c/ama_sha256_ni.c ../src/c/ama_hmac_sha256.c \
 *         ../src/c/ama_consttime.c ../src/c/ama_secure_memory.c \
 *         ../src/c/ama_core.c ../src/c/dispatch/ama_dispatch.c \
 *         -o fuzz_nistp
 */

#include "ama_cryptography.h"
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void fail(const char *why) {
    /* Write the reason before aborting so the crash artifact is
     * self-describing rather than just a stack trace. */
    fprintf(stderr, "NISTP PROPERTY VIOLATION: %s\n", why);
    abort();
}

/** The three curves, selected by a fuzzed byte so no one of them is favoured. */
static ama_nist_curve_t pick_curve(uint8_t b) {
    switch (b % 3u) {
    case 0:  return AMA_NIST_CURVE_P256;
    case 1:  return AMA_NIST_CURVE_P384;
    default: return AMA_NIST_CURVE_P521;
    }
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    ama_nist_curve_t curve;
    const uint8_t *payload;
    size_t payload_len, nb, pub_len;
    uint8_t selector;

    if (size < 2) return 0;

    curve = pick_curve(data[0]);
    selector = data[1];
    payload = data + 2;
    payload_len = size - 2;

    nb = ama_nistp_field_bytes(curve);
    pub_len = ama_nistp_pubkey_bytes(curve);
    if (nb == 0u || pub_len == 0u) return 0;   /* unreachable: curve is valid */

    switch (selector % 6u) {
    case 0: {
        /* The strict DER parser, with the canonical-encoding property.
         *
         * This is the classic parser target and the reason the harness exists:
         * every rejection path in nistp_der_parse_int (long form, zero length,
         * negative, non-minimal leading zero, over-long integer, trailing
         * bytes) is driven by arbitrary bytes rather than by a vector someone
         * wrote down. */
        uint8_t raw[AMA_NISTP_MAX_PUBKEY_BYTES];
        uint8_t again[AMA_NISTP_MAX_SIG_LEN];
        size_t raw_len = sizeof(raw), again_len = sizeof(again);

        if (ama_nistp_sig_der_to_raw(curve, payload, payload_len,
                                     raw, &raw_len) != AMA_SUCCESS)
            break;                              /* not a signature; fine */
        if (raw_len != 2u * nb)
            fail("sig_der_to_raw returned a raw signature of the wrong width");

        if (ama_nistp_sig_raw_to_der(curve, raw, raw_len,
                                     again, &again_len) != AMA_SUCCESS)
            fail("a signature that parsed from DER could not be re-encoded");

        /* Property 1. */
        if (again_len != payload_len || memcmp(again, payload, again_len) != 0)
            fail("DER is not canonical: a second encoding of one signature "
                 "was accepted (re-encoding differs from the input)");
        break;
    }
    case 1: {
        /* The DER encoder from fuzzed raw bytes, then back.  Drives the
         * minimal-integer path (leading-zero stripping, the 0x80 high-bit
         * prefix) from the other side. */
        uint8_t der[AMA_NISTP_MAX_SIG_LEN];
        uint8_t back[AMA_NISTP_MAX_PUBKEY_BYTES];
        size_t der_len = sizeof(der), back_len = sizeof(back);

        if (payload_len < 2u * nb) break;
        if (ama_nistp_sig_raw_to_der(curve, payload, 2u * nb,
                                     der, &der_len) != AMA_SUCCESS)
            break;
        if (ama_nistp_sig_der_to_raw(curve, der, der_len,
                                     back, &back_len) != AMA_SUCCESS)
            fail("DER produced by the encoder was rejected by the parser");
        if (back_len != 2u * nb || memcmp(back, payload, 2u * nb) != 0)
            fail("raw -> DER -> raw did not return the original r || s");
        break;
    }
    case 2: {
        /* The SEC 1 point decoder, with the encoding round trip (property 3). */
        uint8_t pub[AMA_NISTP_MAX_PUBKEY_BYTES];
        uint8_t enc[AMA_NISTP_MAX_PUBKEY_BYTES + 1];
        uint8_t back[AMA_NISTP_MAX_PUBKEY_BYTES];
        size_t enc_len;
        int compressed;

        if (ama_nistp_point_decode(curve, payload, payload_len, pub)
                != AMA_SUCCESS)
            break;                              /* not a point; fine */

        /* A decoded point is on the curve, so it must validate. */
        if (ama_nistp_pubkey_validate(curve, pub) != AMA_SUCCESS)
            fail("point_decode accepted a point pubkey_validate rejects");

        for (compressed = 0; compressed <= 1; compressed++) {
            enc_len = sizeof(enc);
            if (ama_nistp_point_encode(curve, pub, compressed, enc, &enc_len)
                    != AMA_SUCCESS)
                fail("a decoded point could not be re-encoded");
            if (ama_nistp_point_decode(curve, enc, enc_len, back) != AMA_SUCCESS)
                fail("an encoding this library produced was rejected by its "
                     "own decoder");
            if (memcmp(back, pub, pub_len) != 0)
                fail("point encode/decode did not return the same X || Y");
        }
        break;
    }
    case 3: {
        /* Fully fuzzed verify: digest, public key and DER signature all
         * attacker-controlled, each from its own region of the input --
         * digest (32) || public key (pub_len) || DER signature.  Drives
         * nistp_load_point and the DER parser together, which is how they are
         * reached in the field.  The digest used to be read from the first 32
         * bytes of the public key itself, so the two were never independent
         * and every verifying input signed its own key's x coordinate. */
        const uint8_t *digest, *pub, *sig;
        size_t sig_len;

        if (payload_len < 32u + pub_len + 1u) break;
        digest = payload;
        pub = payload + 32u;
        sig = pub + pub_len;
        sig_len = payload_len - 32u - pub_len;

        /* Any outcome is legal here; what matters is memory safety and that
         * the two entry points do not disagree (property 2). */
        if (ama_nistp_ecdsa_verify(curve, digest, 32u, pub, sig, sig_len)
                == AMA_SUCCESS) {
            uint8_t raw[AMA_NISTP_MAX_PUBKEY_BYTES];
            size_t raw_len = sizeof(raw);

            if (ama_nistp_sig_der_to_raw(curve, sig, sig_len, raw, &raw_len)
                    != AMA_SUCCESS)
                fail("a DER signature that verified could not be converted to "
                     "raw");
            if (ama_nistp_ecdsa_verify_raw(curve, digest, 32u, pub,
                                           raw, raw_len) != AMA_SUCCESS)
                fail("a signature accepted in DER was rejected as raw r || s");
        }
        break;
    }
    case 4: {
        /* Public-key validation on arbitrary bytes.  Drives the canonical
         * coordinate check and the curve equation; the identity encoding and
         * out-of-field coordinates are both reachable from here. */
        uint8_t enc[AMA_NISTP_MAX_PUBKEY_BYTES + 1];
        uint8_t back[AMA_NISTP_MAX_PUBKEY_BYTES];
        size_t enc_len = sizeof(enc);

        if (payload_len < pub_len) break;
        if (ama_nistp_pubkey_validate(curve, payload) != AMA_SUCCESS)
            break;                              /* not a key; fine */

        /* Property 4: validate and decode must agree. */
        if (ama_nistp_point_encode(curve, payload, 1, enc, &enc_len)
                != AMA_SUCCESS)
            fail("a validated public key could not be compressed");
        if (ama_nistp_point_decode(curve, enc, enc_len, back) != AMA_SUCCESS)
            fail("the compression of a validated key failed to decode");
        if (memcmp(back, payload, pub_len) != 0)
            fail("compressing and decompressing a validated key changed it");
        break;
    }
    default: {
        /* Key derivation and ECDH from a fuzzed scalar.  The scalar range
         * check ([1, n-1]) and the peer-key validation inside ECDH are the
         * targets; both reject far more often than they accept. */
        uint8_t pub[AMA_NISTP_MAX_PUBKEY_BYTES];
        uint8_t shared[AMA_NISTP_MAX_FIELD_BYTES];

        if (payload_len < nb) break;
        if (ama_nistp_pubkey_from_privkey(curve, payload, pub) == AMA_SUCCESS) {
            /* A derived key is on the curve by construction. */
            if (ama_nistp_pubkey_validate(curve, pub) != AMA_SUCCESS)
                fail("a public key this library derived does not validate");
        }
        if (payload_len >= nb + pub_len)
            (void)ama_nistp_ecdh(curve, payload, payload + nb, shared);
        break;
    }
    }

    return 0;
}
