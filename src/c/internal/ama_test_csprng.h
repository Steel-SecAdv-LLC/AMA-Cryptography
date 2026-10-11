/* Copyright (C) 2025-2026 Steel Security Advisors LLC */
/* SPDX-License-Identifier: Apache-2.0 */
/*
 * ama_test_csprng.h -- the one definition of a file's test CSPRNG hook.
 *
 * Six translation units draw randomness through a file-local function that
 * a test can redirect, in AMA_TESTING_MODE only, to replay a KAT seed or to
 * simulate a CSPRNG failure and assert the fail-closed exit.  They carried
 * six hand-written copies of the same pointer and wrapper (ML-KEM, ML-DSA,
 * SLH-DSA, FROST, NIST-P, X25519), and the tests declared each pointer by
 * hand with no prototype to check against; a change to the pattern had to
 * be made in every copy and could be missed in one.
 *
 * AMA_TEST_CSPRNG(hook, draw) defines both halves.  In a testing build:
 * the exported pointer `hook`, NULL until a test sets it, and the static
 * `draw` that consults it before the platform CSPRNG.  In a shipped build:
 * `draw` alone, calling ama_randombytes() directly, so the shipped object
 * carries neither the pointer nor the branch.  The hooks a test may set are
 * declared, with this prototype, in ama_testing_exports.h.
 *
 * Invoked without a trailing semicolon: the expansion ends in a function
 * body, and -Wpedantic rejects the empty declaration a semicolon would add.
 */
#ifndef AMA_TEST_CSPRNG_H
#define AMA_TEST_CSPRNG_H

#include <stddef.h>
#include <stdint.h>

#include "ama_cryptography.h"
#include "../ama_platform_rand.h"

#ifdef AMA_TESTING_MODE
#define AMA_TEST_CSPRNG(hook, draw)                                          \
    ama_error_t (*hook)(uint8_t *buf, size_t len) = NULL;                    \
    static ama_error_t draw(uint8_t *buf, size_t len) {                      \
        if (hook) {                                                          \
            return hook(buf, len);                                           \
        }                                                                    \
        return ama_randombytes(buf, len);                                    \
    }
#else
#define AMA_TEST_CSPRNG(hook, draw)                                          \
    static ama_error_t draw(uint8_t *buf, size_t len) {                      \
        return ama_randombytes(buf, len);                                    \
    }
#endif

#endif /* AMA_TEST_CSPRNG_H */
