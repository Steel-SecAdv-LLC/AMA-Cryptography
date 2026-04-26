/**
 * Copyright 2025-2026 Steel Security Advisors LLC
 * Licensed under the Apache License, Version 2.0
 *
 * fe51 vs fe64 byte-equivalence test for X25519 scalar multiplication.
 *
 * Two wrapper TUs (`x25519_equiv_fe{51,64}.c`) compile ama_x25519.c
 * twice with the field path forced via `AMA_X25519_FORCE_FE{51,64}`,
 * exposing `x25519_scalarmult_fe51` and `x25519_scalarmult_fe64` with
 * external linkage. This test runs both ladders against the same
 * 1024 random (clamped) scalars and the same random base points and
 * asserts byte-for-byte equality of every output.
 *
 * Any disagreement means the two field representations are no longer
 * arithmetic-equivalent — typically the regressed path has a carry-
 * chain or reduction bug. The first `1024` provides ~10 KB of
 * test-vector entropy, which is sufficient to surface limb-overflow
 * regressions empirically.
 *
 * Built only when AMA_FE64_AVAILABLE && AMA_FE51_AVAILABLE — i.e. on
 * 64-bit GCC/Clang hosts. The wiring lives in tests/c/CMakeLists.txt
 * gated on `CMAKE_SYSTEM_PROCESSOR MATCHES x86_64` to match the fe64
 * default-on platform.
 */

#define _POSIX_C_SOURCE 200809L

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

/* External linkage — defined by the wrapper TUs. */
extern void x25519_scalarmult_fe51(uint8_t q[32], const uint8_t n[32],
                                   const uint8_t p[32]);
extern void x25519_scalarmult_fe64(uint8_t q[32], const uint8_t n[32],
                                   const uint8_t p[32]);

#define N_VECTORS 1024

static void fill_random(uint8_t *buf, size_t len, uint64_t *state) {
    /* xorshift64* — deterministic, repeatable, sufficient for test
     * vectors. We do NOT use this for cryptographic randomness. */
    for (size_t i = 0; i < len; i++) {
        uint64_t x = *state;
        x ^= x >> 12; x ^= x << 25; x ^= x >> 27;
        *state = x;
        buf[i] = (uint8_t)((x * 0x2545F4914F6CDD1DULL) >> 56);
    }
}

int main(void) {
    uint64_t rng = 0xA17EBABE2026ULL;  /* fixed seed for reproducibility */
    uint8_t scalar[32], point[32], out_fe51[32], out_fe64[32];
    int mismatches = 0;

    printf("X25519 fe51 vs fe64 byte-equivalence test\n");
    printf("  vectors:  %d\n", N_VECTORS);
    printf("  rng seed: 0x%016llx (deterministic)\n",
           (unsigned long long)rng);

    for (int i = 0; i < N_VECTORS; i++) {
        fill_random(scalar, 32, &rng);
        fill_random(point,  32, &rng);

        /* Note: the scalarmult routines clamp the scalar internally
         * per RFC 7748 §5, so we don't need to clamp here. */

        x25519_scalarmult_fe51(out_fe51, scalar, point);
        x25519_scalarmult_fe64(out_fe64, scalar, point);

        if (memcmp(out_fe51, out_fe64, 32) != 0) {
            mismatches++;
            if (mismatches <= 4) {  /* surface up to 4 example diffs */
                fprintf(stderr, "  MISMATCH on vector %d\n", i);
                fprintf(stderr, "    scalar:    ");
                for (int j = 0; j < 32; j++) fprintf(stderr, "%02x", scalar[j]);
                fprintf(stderr, "\n    point:     ");
                for (int j = 0; j < 32; j++) fprintf(stderr, "%02x", point[j]);
                fprintf(stderr, "\n    fe51 out:  ");
                for (int j = 0; j < 32; j++) fprintf(stderr, "%02x", out_fe51[j]);
                fprintf(stderr, "\n    fe64 out:  ");
                for (int j = 0; j < 32; j++) fprintf(stderr, "%02x", out_fe64[j]);
                fprintf(stderr, "\n");
            }
        }
    }

    if (mismatches != 0) {
        fprintf(stderr,
                "\nFAIL: %d / %d vectors disagreed between fe51 and fe64.\n"
                "      One of the two field implementations is broken.\n",
                mismatches, N_VECTORS);
        return 1;
    }

    printf("\nPASS: %d / %d vectors byte-identical across fe51 and fe64.\n",
           N_VECTORS, N_VECTORS);
    return 0;
}
