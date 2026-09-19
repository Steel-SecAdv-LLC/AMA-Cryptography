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

        /* Corrupt ciphertext using fuzz data.
         *
         * Two big-endian position bytes, then the XOR mask.  A single
         * position byte capped the corruption position at byte 255 of a
         * 1,568-byte ciphertext: all of v (bytes 1408..1567) and the tail
         * of u were unreachable through this case, while the seed corpus
         * carried files NAMED for those positions ("corrupt-u-v-boundary",
         * "corrupt-last-byte") that actually hit bytes 128 and 31.
         * tools/build_kyber_seed_corpus.py writes the matching layout. */
        if (payload_len >= 2) {
            size_t pos = (((size_t)payload[0] << 8) | payload[1]) % ct_len;
            ct[pos] ^= (payload_len > 2) ? payload[2] : 0x01;
        } else if (payload_len == 1) {
            /* One payload byte: position only (mod 256), default mask. */
            ct[payload[0] % ct_len] ^= 0x01;
        }

        /* Decapsulate the corrupted ciphertext.  "Must not crash" was the
         * whole assertion here, and it certifies nothing: a KEM that skipped
         * the Fujisaki-Okamoto re-encryption check and returned K derived
         * from m' for ANY ciphertext would fuzz clean forever.  The contract
         * is that implicit rejection produces a DIFFERENT shared secret —
         * K = J(z || c) — never an error and never the real one. */
        rc = ama_kyber_decapsulate(
            ct, ct_len,
            cached_sk, sizeof(cached_sk),
            ss_dec, sizeof(ss_dec));
        if (rc != AMA_SUCCESS) {
            __builtin_trap();  /* implicit rejection is silent, not an error */
        }
        if (memcmp(ss_dec, ss_enc, sizeof(ss_enc)) == 0) {
            /* Only reachable if the corruption was a no-op (mask 0), which
             * the position/mask layout above allows. */
            if (payload_len > 2 && payload[2] != 0) {
                __builtin_trap();  /* FO check did not reject */
            }
        }

        /* Implicit rejection is deterministic in (z, c): decapsulating the
         * same corrupted ciphertext twice must agree.  A rejection value
         * drawn from the RNG instead of J(z || c) fails here. */
        {
            uint8_t ss_again[AMA_KYBER_1024_SHARED_SECRET_BYTES];
            if (ama_kyber_decapsulate(ct, ct_len, cached_sk, sizeof(cached_sk),
                                      ss_again, sizeof(ss_again)) != AMA_SUCCESS) {
                __builtin_trap();
            }
            if (memcmp(ss_again, ss_dec, sizeof(ss_dec)) != 0) {
                __builtin_trap();  /* rejection value is not a function of (z, c) */
            }
        }
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
         * path a malformed imported key file reaches.
         *
         * The contract has TWO verdicts now, and they are different in kind:
         *
         *   - The FO verdict must stay invisible.  Implicit rejection returns
         *     a pseudorandom shared secret, never an error, so a key that
         *     parses must not reveal through the return code whether the
         *     re-encryption matched.
         *   - The FIPS 203 Sec 7.3 key check IS visible, by standard.  A
         *     decapsulation key whose embedded H(ek) does not equal
         *     SHA3-256(ek) is an invalid input and is refused outright.
         *
         * So the harness computes H(ek) itself and asserts the matching
         * verdict, rather than accepting either.  Before the Sec 7.3 check
         * landed this case asserted "AMA_SUCCESS whatever the bytes decode
         * to", which a fuzzed 3,168-byte key now falsifies on essentially
         * every input -- the assertion described the old library.
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
            /* dk = dk_PKE || ek || H(ek) || z, so ek starts where the last
             * (public key + 32 + 32) bytes begin. */
            const size_t ek_off = AMA_KYBER_1024_SECRET_KEY_BYTES -
                                  AMA_KYBER_1024_PUBLIC_KEY_BYTES - 64u;
            uint8_t h_computed[32];
            ama_sha3_256(payload + ek_off, AMA_KYBER_1024_PUBLIC_KEY_BYTES, h_computed);
            const int h_matches =
                memcmp(h_computed,
                       payload + ek_off + AMA_KYBER_1024_PUBLIC_KEY_BYTES, 32) == 0;

            if (h_matches) {
                /* A well-formed key: the FO verdict must not surface. */
                if (rc != AMA_SUCCESS) {
                    __builtin_trap();
                }
            } else {
                /* FIPS 203 Sec 7.3: refused as an invalid input, and with
                 * that specific code -- not a generic failure, and never a
                 * silent success into a shared secret the peer never had. */
                if (rc != AMA_ERROR_INVALID_PARAM) {
                    __builtin_trap();
                }
            }
        } else if (rc == AMA_SUCCESS) {
            __builtin_trap();
        }
        break;
    }
    }

    return 0;
}
