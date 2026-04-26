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

/* Source of truth for fe-availability comes from the field-element
 * headers themselves, which both publish AMA_FE{51,64}_AVAILABLE
 * exactly when their preconditions are met (see fe51.h:25, fe64.h:26).
 * Including them here lets the test mirror ama_x25519.c's selector
 * by reading the same macros, instead of recomputing the predicate
 * from raw __SIZEOF_INT128__ / __GNUC__ checks that could drift if
 * either header tightens or relaxes its precondition. (Copilot
 * Review 2026-04-26: previously test_x25519_path.c re-derived the
 * predicate locally and therefore could quietly disagree with the
 * production selector.) */
#include "fe51.h"
#include "fe64.h"

#if defined(AMA_FE51_AVAILABLE) && AMA_FE51_AVAILABLE
#  define EXPECT_FE51_AVAILABLE 1
#else
#  define EXPECT_FE51_AVAILABLE 0
#endif

#if defined(AMA_FE64_AVAILABLE) && AMA_FE64_AVAILABLE
#  define EXPECT_FE64_AVAILABLE 1
#else
#  define EXPECT_FE64_AVAILABLE 0
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

#if (defined(__x86_64__) || defined(_M_X64)) \
    && EXPECT_FE64_AVAILABLE && !defined(AMA_X25519_FORCE_FE51)
    /* On x86-64 toolchains where fe64 is *available* (GCC/Clang with
     * __int128) and the build isn't explicitly forcing fe51, the
     * dispatcher must land on fe64 — this is the defensive
     * regression pin for the radix-2^64 wiring.
     *
     * Gated on EXPECT_FE64_AVAILABLE so MSVC/clang-cl x64 builds
     * (where fe64 is unavailable and the selector intentionally
     * falls back to gf16) and any hypothetical x86-64 toolchain
     * without __int128 don't trigger a false-positive failure here.
     * (Copilot Review 2026-04-26.) */
    if (strcmp(got, "fe64") != 0) {
        fprintf(stderr,
                "FAIL: x86-64 build with fe64 available did not select "
                "fe64 path (got %s). The radix-2^64 wiring has "
                "regressed.\n", got);
        return 1;
    }
#endif

    printf("PASS: x25519 field path pinned to %s\n", got);
    return 0;
}
