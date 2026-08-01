/* Copyright (C) 2025-2026 Steel Security Advisors LLC */
/* SPDX-License-Identifier: Apache-2.0 */
/**
 * @file ama_testing_exports.h
 * @brief Declarations for symbols exported only under AMA_TESTING_MODE.
 *
 * WHY THIS HEADER EXISTS
 *
 * Several primitives expose an internal routine to the C test suite so a
 * property can be isolated from the public entry point that wraps it — the
 * constant-time scalar negate in FROST, the Kyber NTT and CPA round-trips.
 * These are deliberately absent from every public header: they are not ABI,
 * and `AMA_TESTING_MODE` is what admits them.
 *
 * "Absent from every public header" had become "absent from every header",
 * which is a different thing.  Each definition sat with no prototype in
 * scope, and each consumer carried its own `extern` — `ama_frost.c`'s
 * `scalar_negate` export is declared separately in `tests/c/test_frost.c` and
 * again in `tests/c/test_dudect.c`, the Kyber pair again in
 * `tests/c/test_kyber_cpa.c`.  Nothing connected the transcriptions, so a
 * signature change would have produced a silent ABI mismatch rather than a
 * compile error, on functions whose arguments are raw `uint8_t[32]` buffers.
 *
 * `-Wmissing-prototypes` reported it and nothing acted on the report, because
 * the CI job named "Strict Compiler Warnings (Werror)" did not pass
 * `-Werror`.  One declaration, included by the definition and by every
 * consumer, restores the check the compiler was already willing to do.
 *
 * The declarations are deliberately NOT wrapped in `#ifdef AMA_TESTING_MODE`.
 * CMake sets that macro `PRIVATE` on the `ama_cryptography_test` library
 * target, so the test executables that *link* it do not carry it — a guarded
 * header would therefore vanish exactly where it is included, and the callers
 * would fall back to implicit declarations. gcc accepts those silently; clang
 * 16+ rejects them, which is how this was caught.
 *
 * Declaring a symbol that a given configuration does not define is harmless:
 * the failure surfaces at link time, loudly, in the one configuration that
 * calls it. That is the correct failure mode, and strictly better than the
 * unchecked `extern` this header replaces.
 */
#ifndef AMA_TESTING_EXPORTS_H
#define AMA_TESTING_EXPORTS_H

#include <stdint.h>

/* --- src/c/ama_frost.c -------------------------------------------------- */

/**
 * Test-only export of FROST's `scalar_negate`, so tests/c/test_frost.c can
 * exercise the branchless borrow loop directly at the INVARIANT-12 boundaries
 * (s in {0, 1, l-1, mid-range}) and tests/c/test_dudect.c can measure it.
 */
void ama_frost_test_scalar_negate(uint8_t neg[32], const uint8_t s[32]);

/** Test-only export of FROST's `scalar_add`, for the same reason. */
void ama_frost_test_scalar_add(uint8_t c[32], const uint8_t a[32], const uint8_t b[32]);

/* --- src/c/ama_kyber.c -------------------------------------------------- */
/* Defined under AMA_KYBER_BUILD_DIAGNOSTICS — a switch separate from
 * AMA_TESTING_MODE, and likewise kept out of the production .so. */

/** NTT -> INVNTT round-trip and polynomial arithmetic. 0 on success. */
int ama_kyber_debug_ntt_roundtrip(void);

/** CPA-secure keygen/encrypt/decrypt round-trip. 0 on success. */
int ama_kyber_debug_cpa_roundtrip(void);

#endif /* AMA_TESTING_EXPORTS_H */
