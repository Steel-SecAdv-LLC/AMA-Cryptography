/* Copyright (C) 2025-2026 Steel Security Advisors LLC */
/* SPDX-License-Identifier: Apache-2.0 */
/**
 * libFuzzer harness for the RFC 8554 HSS/LMS verifier (src/c/ama_lms.c).
 *
 * The verifier parses attacker-supplied bytes: typecodes in the public key
 * and in the signature select the tree height, the Winternitz width and every
 * length that follows, and an HSS signature is a chain of variable-length LMS
 * signatures and embedded public keys walked level by level.  That is the
 * parser class CRYPTO_REVIEW_CHECKLIST.md requires a fuzz target for, and
 * until this harness it had none: ARCHITECTURE.md said the fuzz targets
 * covered "all C implementations" while no harness linked ama_lms.c at all.
 *
 * Input layout:
 *   byte 0        mode: bit 0 clear -> ama_hss_verify, set -> ama_lms_verify
 *   bytes 1..2    message length, big-endian, clamped to what follows the key
 *   next K bytes  public key: AMA_HSS_PUBKEY_LEN (HSS) or AMA_LMS_PUBKEY_LEN
 *   next M bytes  message
 *   the rest      signature
 *
 * Properties — a violation traps, so libFuzzer reports it as a crash:
 *   1. the verdict is AMA_SUCCESS, AMA_ERROR_VERIFY_FAILED or
 *      AMA_ERROR_INVALID_PARAM, and nothing else;
 *   2. AMA_ERROR_INVALID_PARAM exactly when the PUBLIC KEY is malformed, the
 *      contract include/ama_cryptography.h states for both verifiers, judged
 *      by ama_hss_pubkey_levels / ama_lms_pubkey_params on the same key;
 *   3. a second call on the same input returns the same verdict;
 *   4. a signature that verifies is bound to its message: the same key and
 *      signature over the message with its first bit flipped (or over one
 *      zero byte, when the message is empty) do not verify;
 *   5. a signature that verifies is consumed exactly: the same signature
 *      with one byte appended does not verify (RFC 8554 §5.4.2 and §6.3 —
 *      trailing data is a second encoding of the same signature);
 *   6. ama_lms_signature_length returns 0 or a length within the buffer, a
 *      re-parse of exactly that prefix returns the same length, and a
 *      single-tree signature that verifies is exactly that length.
 *
 * The seed corpus (tools/build_lms_seed_corpus.py) carries both RFC 8554
 * Appendix F test cases, as HSS signatures and as their inner single-tree
 * LMS signatures, so the accepting path — and property 4 — is exercised
 * from the first execution rather than only after the mutator forges one.
 *
 * Build (through fuzz/CMakeLists.txt, which instruments the library too):
 *   cmake -B build-fuzz -G Ninja -DAMA_BUILD_FUZZ=ON -DCMAKE_C_COMPILER=clang \
 *         -DCMAKE_CXX_COMPILER=clang++
 *   cmake --build build-fuzz --target fuzz_lms
 *   ./build-fuzz/bin/fuzz_lms fuzz/seed_corpus/fuzz_lms
 */

#include "ama_cryptography.h"
#include <stddef.h>
#include <stdint.h>
#include <string.h>

/* Mode byte plus the two message-length bytes. */
#define FUZZ_LMS_HEADER 3
/* The header plus the longer of the two public keys (AMA_HSS_PUBKEY_LEN). */
#define FUZZ_LMS_MIN_INPUT 63
/* Scratch for properties 4 and 5.  The message-length field cannot exceed
 * 65,535, and a signature is at most the input, which the lane caps at its
 * -max_len; inputs whose signature would not fit skip property 5. */
#define FUZZ_LMS_FLIP_MAX 65536
#define FUZZ_LMS_TRAIL_MAX 65536

typedef ama_error_t (*fuzz_lms_verify_fn)(const uint8_t *, size_t, const uint8_t *, size_t,
                                          const uint8_t *, size_t);

static uint8_t g_flipped[FUZZ_LMS_FLIP_MAX];
static uint8_t g_trailing[FUZZ_LMS_TRAIL_MAX];

/* libFuzzer's entry point, declared so -Wmissing-prototypes has one. */
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < FUZZ_LMS_MIN_INPUT) return 0;

    const int single_tree = (data[0] & 1u) != 0u;
    const size_t key_len = single_tree ? (size_t)AMA_LMS_PUBKEY_LEN : (size_t)AMA_HSS_PUBKEY_LEN;
    const fuzz_lms_verify_fn verify = single_tree ? ama_lms_verify : ama_hss_verify;
    const uint8_t *key = data + FUZZ_LMS_HEADER;
    const size_t rest = size - FUZZ_LMS_HEADER;
    /* size >= FUZZ_LMS_MIN_INPUT, so rest covers the longer key. */
    const size_t after_key = rest - key_len;
    size_t msg_len = ((size_t)data[1] << 8) | (size_t)data[2];
    if (msg_len > after_key) msg_len = after_key;
    const uint8_t *msg = key + key_len;
    const uint8_t *sig = msg + msg_len;
    const size_t sig_len = after_key - msg_len;

    const ama_error_t rc = verify(msg, msg_len, sig, sig_len, key, key_len);

    /* 1. The verdict set. */
    if (rc != AMA_SUCCESS && rc != AMA_ERROR_VERIFY_FAILED && rc != AMA_ERROR_INVALID_PARAM) {
        __builtin_trap();
    }

    /* 2. INVALID_PARAM is the malformed-key verdict, and only that. */
    int key_ok;
    if (single_tree) {
        key_ok = ama_lms_pubkey_params(key, key_len, NULL, NULL, NULL, NULL) == AMA_SUCCESS;
    } else {
        uint32_t levels = 0;
        key_ok = ama_hss_pubkey_levels(key, key_len, &levels) == AMA_SUCCESS;
    }
    if ((rc == AMA_ERROR_INVALID_PARAM) == (key_ok != 0)) {
        __builtin_trap();
    }

    /* 3. Deterministic. */
    if (verify(msg, msg_len, sig, sig_len, key, key_len) != rc) {
        __builtin_trap();
    }

    /* 4. An accepted signature does not also accept a different message. */
    if (rc == AMA_SUCCESS) {
        size_t flipped_len = 1u;
        g_flipped[0] = 0u;
        if (msg_len != 0u) {
            memcpy(g_flipped, msg, msg_len);
            g_flipped[0] ^= 0x01u;
            flipped_len = msg_len;
        }
        if (verify(g_flipped, flipped_len, sig, sig_len, key, key_len) == AMA_SUCCESS) {
            __builtin_trap();
        }
    }

    /* 5. An accepted signature does not also accept itself plus a byte. */
    if (rc == AMA_SUCCESS && sig_len < FUZZ_LMS_TRAIL_MAX) {
        memcpy(g_trailing, sig, sig_len);
        g_trailing[sig_len] = 0u;
        if (verify(msg, msg_len, g_trailing, sig_len + 1u, key, key_len) == AMA_SUCCESS) {
            __builtin_trap();
        }
    }

    /* 6. The length walker agrees with itself and with the verifier. */
    const size_t head = ama_lms_signature_length(sig, sig_len);
    if (head > sig_len) {
        __builtin_trap();
    }
    if (head != 0u && ama_lms_signature_length(sig, head) != head) {
        __builtin_trap();
    }
    if (single_tree && rc == AMA_SUCCESS && head != sig_len) {
        __builtin_trap();
    }

    return 0;
}
