/* Copyright (C) 2025-2026 Steel Security Advisors LLC */
/* SPDX-License-Identifier: Apache-2.0 */
/**
 * libFuzzer harness for Ed25519 sign/verify (RFC 8032).
 *
 * Fuzz targets:
 * - Keypair generation from fuzzed seed
 * - Sign arbitrary messages, verify the signature succeeds
 * - Verify that corrupted signatures are rejected
 * - Verify with arbitrary (attacker-controlled) inputs
 *
 * Build (standalone):
 *   clang -fsanitize=fuzzer,address -O1 -g -I../include \
 *         fuzz_ed25519.c ../src/c/ama_ed25519.c ../src/c/ama_sha3.c \
 *         ../src/c/ama_consttime.c ../src/c/ama_core.c -o fuzz_ed25519
 */

#include "ama_cryptography.h"
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 33) return 0;  /* Need at least 1 selector + 32 bytes seed */

    uint8_t selector = data[0];
    const uint8_t *payload = data + 1;
    size_t payload_len = size - 1;

    switch (selector % 3) {
    case 0: {
        /* Sign/verify round-trip: fuzzed seed + fuzzed message */
        if (payload_len < 32) break;

        uint8_t pk[32], sk[64];
        uint8_t sig[64];

        /* Use first 32 bytes as seed */
        memcpy(sk, payload, 32);
        ama_ed25519_keypair(pk, sk);

        const uint8_t *msg = payload + 32;
        size_t msg_len = payload_len - 32;

        /* Sign */
        ama_error_t rc = ama_ed25519_sign(sig, msg, msg_len, sk);
        if (rc != AMA_SUCCESS) break;

        /* Verify must succeed */
        rc = ama_ed25519_verify(sig, msg, msg_len, pk);
        if (rc != AMA_SUCCESS) {
            __builtin_trap();  /* Sign-then-verify must always pass */
        }

        /* Corrupt one byte of the signature — verify must reject */
        if (msg_len > 0) {
            sig[0] ^= 0x01;
            rc = ama_ed25519_verify(sig, msg, msg_len, pk);
            if (rc == AMA_SUCCESS) {
                __builtin_trap();  /* Corrupted signature must not verify */
            }
            sig[0] ^= 0x01;  /* restore */
        }

        /* Message binding.  Sound HERE and only here: the keypair comes from
         * ama_ed25519_keypair, so A is a full-order point and the signature
         * is genuinely bound to this message.  A verifier that ignored the
         * message would pass every check above and fail this one. */
        if (msg_len > 0) {
            uint8_t *other = (uint8_t *)malloc(msg_len);
            if (other != NULL) {
                memcpy(other, msg, msg_len);
                other[0] ^= 0x01u;
                const int still =
                    ama_ed25519_verify(sig, other, msg_len, pk) == AMA_SUCCESS;
                free(other);
                if (still) {
                    __builtin_trap();  /* signature is not bound to the message */
                }
            }
        }
        break;
    }
    case 1: {
        /* Verify with fully fuzzed inputs (attacker-controlled) */
        if (payload_len < 64 + 32) break;  /* sig + pk minimum */

        const uint8_t *sig = payload;
        const uint8_t *pk = payload + 64;
        const uint8_t *msg = payload + 64 + 32;
        size_t msg_len = payload_len - 64 - 32;

        /* Attacker-controlled (sig, pk, msg): exercised for memory safety.
         *
         * No acceptance assertion can live here, and two attempts measured
         * why:
         *
         *   - "fuzz bytes must never verify" is false.  The seed corpus
         *     carries genuine (sig, pk, msg) triples and the selector byte
         *     lets a mutation route one into this case, so the trap fired on
         *     a CORRECT verification (crash-6593403c..., 142 bytes).
         *   - "an accepted signature must stop verifying when the message
         *     changes" is false for a LOW-ORDER public key.  Measured: the
         *     all-zero encoding (pk = R = S = 0) decodes to a point of order
         *     4, and the group equation then holds for many messages, so the
         *     same signature verifies for both 0x00.. and 0x01.. -- a
         *     property of the scheme under a degenerate key, not a defect in
         *     this verifier.  Establishing full order here would need the
         *     complete small-order set, which does not belong in a harness.
         *
         * The binding and corruption assertions therefore live in case 0,
         * which owns the keypair and so knows A is full order.
         *
         * NOTE: that low-order acceptance is a real, separately-reportable
         * property of ama_ed25519_verify -- RFC 8032 does not require
         * rejecting a small-order A, and neither the frozen oracle (904
         * verify records, 0 with a low-order key) nor Wycheproof's
         * ed25519_test.json (0 such groups) pins it either way.
         */
        (void)ama_ed25519_verify(sig, msg, msg_len, pk);
        break;
    }
    case 2: {
        /* Keypair generation from arbitrary seed */
        if (payload_len < 32) break;

        uint8_t pk[32], sk[64];
        memcpy(sk, payload, 32);
        ama_ed25519_keypair(pk, sk);

        /* Verify pk is stored in sk[32..63] */
        if (memcmp(pk, sk + 32, 32) != 0) {
            __builtin_trap();
        }
        break;
    }
    }

    return 0;
}
