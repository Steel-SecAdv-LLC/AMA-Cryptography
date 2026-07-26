/* Copyright (C) 2025-2026 Steel Security Advisors LLC */
/* SPDX-License-Identifier: Apache-2.0 */
/**
 * libFuzzer harness for secp256k1 elliptic curve operations.
 *
 * Fuzz targets:
 * - Public key derivation from a fuzzed private key
 * - Scalar multiplication with fuzzed point/scalar
 * - ECDSA signing with a fuzzed digest + private key
 * - ECDSA verification with a fully fuzzed (signature, digest, public key) —
 *   this drives the strict DER parser (der_parse_signature) and the whole
 *   verify path with attacker-controlled bytes, the classic parser fuzz target
 * - ECDSA verify_ex under both the strict and allow-high-s policies, plus
 *   unknown flag bits (forward-compat)
 *
 * Every target must be memory-safe on arbitrary input; a returned error is a
 * valid outcome, a crash/UB is a bug.
 *
 * Build (standalone):
 *   clang -fsanitize=fuzzer,address,undefined -O1 -g -I../include \
 *         -DAMA_USE_NATIVE_PQC \
 *         fuzz_secp256k1.c ../src/c/ama_secp256k1.c ../src/c/ama_sha256.c \
 *         ../src/c/ama_sha256_ni.c ../src/c/ama_hmac_sha256.c \
 *         ../src/c/ama_consttime.c ../src/c/ama_secure_memory.c \
 *         ../src/c/ama_core.c ../src/c/dispatch/ama_dispatch.c \
 *         -o fuzz_secp256k1
 */

#include "ama_cryptography.h"
#include <stdint.h>
#include <stddef.h>
#include <string.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 1) return 0;

    uint8_t selector = data[0];
    const uint8_t *payload = data + 1;
    size_t payload_len = size - 1;

    switch (selector % 5) {
    case 0: {
        /* Public key from private key */
        if (payload_len < 32) break;

        uint8_t compressed_pk[33];
        /* May return error for out-of-range keys — that's fine */
        ama_secp256k1_pubkey_from_privkey(payload, compressed_pk);
        break;
    }
    case 1: {
        /* Scalar multiplication with fuzzed point */
        if (payload_len < 96) break;  /* 32 scalar + 32 x + 32 y */

        const uint8_t *scalar = payload;
        const uint8_t *point_x = payload + 32;
        const uint8_t *point_y = payload + 64;
        uint8_t out_x[32], out_y[32];

        /* Must not crash; may return error for invalid inputs */
        ama_secp256k1_point_mul(scalar, point_x, point_y, out_x, out_y);
        break;
    }
    case 2: {
        /* ECDSA signing with a fuzzed 32-byte digest + private key. */
        if (payload_len < 64) break;

        const uint8_t *digest = payload;
        const uint8_t *privkey = payload + 32;
        uint8_t sig[AMA_SECP256K1_ECDSA_MAX_SIG_LEN];
        size_t sig_len = 0;

        /* Out-of-range keys return an error; a valid key returns a signature.
         * Either way must be crash-free. */
        ama_secp256k1_ecdsa_sign(sig, &sig_len, digest, privkey);
        break;
    }
    case 3: {
        /* ECDSA verify with a fully fuzzed (signature, digest, public key).
         * This is the DER-parser + verify fuzz target: sig is the variable-
         * length tail so the fuzzer mutates DER structure and length. */
        if (payload_len < 96) break;

        const uint8_t *digest = payload;
        const uint8_t *pubkey = payload + 32;      /* 64-byte X||Y */
        const uint8_t *sig = payload + 96;
        size_t sig_len = payload_len - 96;

        ama_secp256k1_ecdsa_verify(sig, sig_len, digest, pubkey);
        break;
    }
    case 4: {
        /* ECDSA verify_ex under strict, allow-high-s, and an unknown flag bit
         * (forward-compat: unknown bits must be ignored, never crash). */
        if (payload_len < 96) break;

        const uint8_t *digest = payload;
        const uint8_t *pubkey = payload + 32;
        const uint8_t *sig = payload + 96;
        size_t sig_len = payload_len - 96;

        ama_secp256k1_ecdsa_verify_ex(sig, sig_len, digest, pubkey,
                                      AMA_SECP256K1_ECDSA_VERIFY_STRICT);
        ama_secp256k1_ecdsa_verify_ex(sig, sig_len, digest, pubkey,
                                      AMA_SECP256K1_ECDSA_ALLOW_HIGH_S);
        ama_secp256k1_ecdsa_verify_ex(sig, sig_len, digest, pubkey,
                                      (uint32_t)0x80000000u);  /* unknown flag */
        break;
    }
    }

    return 0;
}
