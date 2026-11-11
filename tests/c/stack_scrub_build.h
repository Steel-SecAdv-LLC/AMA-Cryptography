/* Copyright (C) 2025-2026 Steel Security Advisors LLC */
/* SPDX-License-Identifier: Apache-2.0 */
/**
 * @file stack_scrub_build.h
 * @brief What the library's own compiler flags select in
 *        src/c/internal/ama_stack_wipe.h, as data (stack_scrub_build.c).
 */
#ifndef STACK_SCRUB_BUILD_H
#define STACK_SCRUB_BUILD_H

#include <stddef.h>

/* Every family src/c/internal/ama_stack_wipe.h gives a depth
 * (tests/test_stack_scrub_surface.py holds the two lists equal). */
#define SCRUB_FAMILIES(X)                                                           \
    X(BASE64) X(ASCON) X(HYBRID) X(SHA256) X(AES) X(HMAC_SHA256) X(SHA3) X(AEAD) X(SHA512)    \
    X(HMAC) X(X25519) X(KDF) X(SECP256K1) X(FROST) X(ED25519) X(NISTP) X(ARGON2)    \
    X(SLH_DSA) X(ML_DSA_CHECK) X(ML_KEM) X(ML_DSA_KEYGEN) X(ML_DSA_SIGN)

/* 1 when the library's flags optimise, 0 when they do not. */
extern const int scrub_library_is_optimised;

/* The depth each family's entry points clear in this build. */
#define SCRUB_DECLARE_DEPTH(family) extern const size_t scrub_depth_##family;
SCRUB_FAMILIES(SCRUB_DECLARE_DEPTH)

#endif /* STACK_SCRUB_BUILD_H */
