/* Copyright (C) 2025-2026 Steel Security Advisors LLC */
/* SPDX-License-Identifier: Apache-2.0 */
/**
 * libFuzzer harness for Kyber-1024 KEM (FIPS 203 ML-KEM).
 *
 * Fuzz targets:
 * - Keypair + encapsulate/decapsulate round-trip
 * - Decapsulate with a one-byte-corrupted ciphertext (implicit rejection)
 * - Deterministic keygen from a fuzzed seed
 * - Decapsulate a FULLY attacker-controlled ciphertext, at its own length
 * - Encapsulate to a FULLY attacker-controlled encapsulation key
 * - Decapsulate under a fully fuzzed secret key
 *
 * The last three did not exist until they were added here, and the first of
 * them was listed in this comment as though it did.  What the harness
 * actually reached was: a round-trip with no attacker input in it at all, a
 * ciphertext differing from a valid one in a single byte at a fuzzer-chosen
 * position, and a seed-driven keygen.  The two entry points an attacker
 * actually supplies bytes to — `ama_kyber_decapsulate`'s ciphertext and
 * `ama_kyber_encapsulate`'s public key — were never fuzzed.  The sibling
 * harnesses had both: fuzz_dilithium has "verify with fully fuzzed inputs",
 * fuzz_x25519 has "key exchange with fuzzed peer public key".  The KEM, which
 * is the primitive with an IND-CCA2 argument to protect, had neither.
 *
 * The contract assertions below are the point of cases 3 and 5, not decoration.
 * FIPS 203 Sec 6.3 implicit rejection means a decapsulation whose
 * re-encryption fails returns a pseudorandom shared secret and SUCCESS — if
 * the RETURN CODE distinguished a valid ciphertext from an invalid one, that
 * code would be exactly the plaintext-checking oracle the Fujisaki-Okamoto
 * transform exists to deny, and no amount of constant-time care below it
 * would matter.  So over arbitrary attacker bytes at the correct length, the
 * only acceptable answer is AMA_SUCCESS, and anything else traps.
 *
 * Build (standalone):
 *   clang -fsanitize=fuzzer,address -O1 -g -I../include \
 *         -DAMA_USE_NATIVE_PQC \
 *         fuzz_kyber.c ../src/c/ama_kyber.c ../src/c/ama_sha3.c \
 *         ../src/c/ama_sha256.c ../src/c/ama_consttime.c ../src/c/ama_core.c \
 *         ../src/c/ama_platform_rand.c -o fuzz_kyber
 */

#include "ama_cryptography.h"
#include <stdint.h>
#include <stddef.h>
#include <string.h>

/* Cache a keypair across iterations for speed */
static int keys_initialized = 0;
static uint8_t cached_pk[AMA_KYBER_1024_PUBLIC_KEY_BYTES];
static uint8_t cached_sk[AMA_KYBER_1024_SECRET_KEY_BYTES];

static void ensure_keys(void) {
    if (!keys_initialized) {
        if (ama_kyber_keypair(cached_pk, sizeof(cached_pk),
                               cached_sk, sizeof(cached_sk)) == AMA_SUCCESS) {
            keys_initialized = 1;
        }
    }
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 2) return 0;

    uint8_t selector = data[0];
    const uint8_t *payload = data + 1;
    size_t payload_len = size - 1;

    switch (selector % 6) {
    case 0: {
        /* Encapsulate/decapsulate round-trip */
        ensure_keys();
        if (!keys_initialized) break;

        uint8_t ct[AMA_KYBER_1024_CIPHERTEXT_BYTES];
        size_t ct_len = sizeof(ct);
        uint8_t ss_enc[AMA_KYBER_1024_SHARED_SECRET_BYTES];
        uint8_t ss_dec[AMA_KYBER_1024_SHARED_SECRET_BYTES];

        ama_error_t rc = ama_kyber_encapsulate(
            cached_pk, sizeof(cached_pk),
            ct, &ct_len, ss_enc, sizeof(ss_enc));
        if (rc != AMA_SUCCESS) break;

        rc = ama_kyber_decapsulate(
            ct, ct_len,
            cached_sk, sizeof(cached_sk),
            ss_dec, sizeof(ss_dec));
        if (rc != AMA_SUCCESS) {
            __builtin_trap();
        }

        /* Shared secrets must match */
        if (memcmp(ss_enc, ss_dec, AMA_KYBER_1024_SHARED_SECRET_BYTES) != 0) {
            __builtin_trap();
        }
        break;
    }
    case 1: {
        /* Decapsulate corrupted ciphertext — implicit rejection */
        ensure_keys();
        if (!keys_initialized) break;

        uint8_t ct[AMA_KYBER_1024_CIPHERTEXT_BYTES];
        size_t ct_len = sizeof(ct);
        uint8_t ss_enc[AMA_KYBER_1024_SHARED_SECRET_BYTES];
        uint8_t ss_dec[AMA_KYBER_1024_SHARED_SECRET_BYTES];

        ama_error_t rc = ama_kyber_encapsulate(
            cached_pk, sizeof(cached_pk),
            ct, &ct_len, ss_enc, sizeof(ss_enc));
        if (rc != AMA_SUCCESS) break;

        /* Corrupt ciphertext using fuzz data */
        if (payload_len > 0) {
            size_t pos = payload[0] % ct_len;
            ct[pos] ^= (payload_len > 1) ? payload[1] : 0x01;
        }

        /* Decapsulate with corrupted ciphertext — must not crash
         * (implicit rejection returns a pseudorandom SS, not an error) */
        ama_kyber_decapsulate(
            ct, ct_len,
            cached_sk, sizeof(cached_sk),
            ss_dec, sizeof(ss_dec));
        break;
    }
    case 2: {
        /* Deterministic keygen from seed */
        if (payload_len < 64) break;

        uint8_t pk[AMA_KYBER_1024_PUBLIC_KEY_BYTES];
        uint8_t sk[AMA_KYBER_1024_SECRET_KEY_BYTES];

        ama_kyber_keypair_from_seed(payload, payload + 32, pk, sk);
        break;
    }
    case 3: {
        /* Decapsulate a FULLY attacker-controlled ciphertext.
         *
         * The payload IS the ciphertext and is passed at its own length, so
         * truncated, over-long and exact-length inputs all occur.  Two
         * contracts, both of which a corrupted-by-one-byte input can never
         * test:
         *
         *   exact length  -> AMA_SUCCESS, always.  Implicit rejection is
         *                    indistinguishable from success in the return
         *                    code (FIPS 203 Sec 6.3); any other code here is
         *                    a decapsulation oracle.
         *   other length  -> refused.  The length is public, so refusing it
         *                    is not an oracle — but silently processing it
         *                    would be a parser bug.
         */
        ensure_keys();
        if (!keys_initialized) break;

        uint8_t ss_dec[AMA_KYBER_1024_SHARED_SECRET_BYTES];
        ama_error_t rc = ama_kyber_decapsulate(
            payload, payload_len,
            cached_sk, sizeof(cached_sk),
            ss_dec, sizeof(ss_dec));

        if (payload_len == AMA_KYBER_1024_CIPHERTEXT_BYTES) {
            if (rc != AMA_SUCCESS) {
                __builtin_trap();
            }
        } else if (rc == AMA_SUCCESS) {
            __builtin_trap();
        }
        break;
    }
    case 4: {
        /* Encapsulate to a FULLY attacker-controlled encapsulation key.
         *
         * This is the FIPS 203 Sec 7.2 input-validation path
         * (kyber_pubkey_check): an encapsulation key whose 12-bit
         * coefficients do not re-encode is rejected rather than silently
         * encapsulated to.  Arbitrary bytes at the exact key length are the
         * only way to reach the interesting half of that check.
         *
         * Success or refusal are both legitimate answers; what is not
         * legitimate is a crash, or a success that produced a ciphertext of
         * the wrong length.
         */
        uint8_t ct[AMA_KYBER_1024_CIPHERTEXT_BYTES];
        size_t ct_len = sizeof(ct);
        uint8_t ss_enc[AMA_KYBER_1024_SHARED_SECRET_BYTES];

        ama_error_t rc = ama_kyber_encapsulate(
            payload, payload_len, ct, &ct_len, ss_enc, sizeof(ss_enc));

        if (rc == AMA_SUCCESS) {
            if (payload_len != AMA_KYBER_1024_PUBLIC_KEY_BYTES ||
                ct_len != AMA_KYBER_1024_CIPHERTEXT_BYTES) {
                __builtin_trap();
            }
        }
        break;
    }
    case 5: {
        /* Decapsulate a valid ciphertext under a FULLY fuzzed secret key.
         *
         * Exercises the secret-key parse (polyvec_frombytes over arbitrary
         * bytes, and the pk / H(pk) / z slices taken from inside it) on the
         * path a malformed imported key file reaches.  The same return-code
         * contract applies: at the exact secret-key length the answer is
         * AMA_SUCCESS whatever the bytes decode to, because the FO verdict
         * must not be visible in the code.
         */
        ensure_keys();
        if (!keys_initialized) break;

        uint8_t ct[AMA_KYBER_1024_CIPHERTEXT_BYTES];
        size_t ct_len = sizeof(ct);
        uint8_t ss_enc[AMA_KYBER_1024_SHARED_SECRET_BYTES];
        uint8_t ss_dec[AMA_KYBER_1024_SHARED_SECRET_BYTES];

        if (ama_kyber_encapsulate(cached_pk, sizeof(cached_pk),
                                  ct, &ct_len, ss_enc,
                                  sizeof(ss_enc)) != AMA_SUCCESS) {
            break;
        }

        ama_error_t rc = ama_kyber_decapsulate(
            ct, ct_len, payload, payload_len, ss_dec, sizeof(ss_dec));

        if (payload_len == AMA_KYBER_1024_SECRET_KEY_BYTES) {
            if (rc != AMA_SUCCESS) {
                __builtin_trap();
            }
        } else if (rc == AMA_SUCCESS) {
            __builtin_trap();
        }
        break;
    }
    }

    return 0;
}
