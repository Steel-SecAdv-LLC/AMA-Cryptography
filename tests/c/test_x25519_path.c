/**
 * Copyright 2025-2026 Steel Security Advisors LLC
 * Licensed under the Apache License, Version 2.0
 *
 * X25519 field-path pinning regression test.
 *
 * The build emits exactly one of three field-arithmetic ladders:
 *   - fe64 (radix 2^64, 4 limbs) on x86-64 GCC/Clang with __int128
 *   - fe51 (radix 2^51, 5 limbs) on other 64-bit GCC/Clang with __int128
 *   - gf16 (radix 2^16, 16 limbs) on MSVC / 32-bit / no-__int128 targets
 *
 * The choice is *deterministic at compile time*. This test pins the
 * expectation: given the host compiler/target the build was configured
 * for, exactly one specific path must be selected. A future build-flag
 * change (e.g., turning fe64 off without renaming the macro, or
 * accidentally hiding `__SIZEOF_INT128__`) will be flagged here.
 *
 * The expectation is computed from the same preprocessor predicates
 * that ama_x25519.c uses, so the test moves in lockstep with the
 * source-of-truth selector — no risk of test/source drift.
 */

#include <stdio.h>
#include <string.h>

#include "ama_cryptography.h"

/* Replicate the build-time selector from ama_x25519.c. If either file
 * is edited, the assertion below catches drift between them. */
#if (defined(__GNUC__) || defined(__clang__)) && defined(__SIZEOF_INT128__)
#  define EXPECT_FE64_AVAILABLE 1
#  define EXPECT_FE51_AVAILABLE 1
#else
#  define EXPECT_FE64_AVAILABLE 0
#  define EXPECT_FE51_AVAILABLE 0
#endif

#if defined(AMA_X25519_FORCE_FE64) && EXPECT_FE64_AVAILABLE
#  define EXPECTED_PATH "fe64"
#elif defined(AMA_X25519_FORCE_FE51) && EXPECT_FE51_AVAILABLE
#  define EXPECTED_PATH "fe51"
#elif EXPECT_FE64_AVAILABLE && (defined(__x86_64__) || defined(_M_X64))
#  define EXPECTED_PATH "fe64"
#elif EXPECT_FE51_AVAILABLE
#  define EXPECTED_PATH "fe51"
#else
#  define EXPECTED_PATH "gf16"
#endif

int main(void) {
    const char *got = ama_x25519_field_path();

    printf("X25519 field-path pin\n");
    printf("  expected:  %s\n", EXPECTED_PATH);
    printf("  selected:  %s\n", got);

    if (strcmp(got, EXPECTED_PATH) != 0) {
        fprintf(stderr,
                "FAIL: x25519 field path mismatch — build flags drifted.\n"
                "      Update ama_x25519.c selector or this test, but not\n"
                "      one without the other.\n");
        return 1;
    }

#if defined(__x86_64__) || defined(_M_X64)
    /* On x86-64 GCC/Clang we should always land on fe64 unless the build
     * is explicitly forcing something else via AMA_X25519_FORCE_FE51. */
#  if !defined(AMA_X25519_FORCE_FE51)
    if (strcmp(got, "fe64") != 0) {
        fprintf(stderr,
                "FAIL: x86-64 build did not select fe64 path "
                "(got %s). The radix-2^64 wiring has regressed.\n", got);
        return 1;
    }
#  endif
#endif

    printf("PASS: x25519 field path pinned to %s\n", got);
    return 0;
}
