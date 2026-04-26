/**
 * Copyright 2025-2026 Steel Security Advisors LLC
 * Licensed under the Apache License, Version 2.0
 *
 * @file tests/c/test_x25519_fe64_mulx_equiv.c
 * @brief MULX+ADX kernel vs pure-C fe64 schoolbook byte-equivalence
 * @date 2026-04-26
 *
 * Cross-checks the hand-tuned MULX+ADX field multiplication kernel
 * (`ama_x25519_fe64_mul_mulx`, `ama_x25519_fe64_sq_mulx`, defined in
 * `src/c/internal/ama_x25519_fe64_mulx.c`) against the pure-C
 * `fe64_mul` / `fe64_sq` reference (`src/c/fe64.h`) across N_VECTORS
 * random (a, b) pairs. Both implementations must reduce to the same
 * canonical 32-byte little-endian encoding for every input — even
 * limb representations that differ by a non-canonical multiple of
 * `p = 2^255 - 19` are normalized to the same encoding by
 * `fe64_tobytes`.
 *
 * Skips with CTest exit code 77 ("Skipped") on hosts where the
 * runtime CPUID gate (`ama_cpuid_has_x25519_mulx()`) returns 0 —
 * the kernel is then never linked into the runtime path and the
 * equivalence claim is vacuously true on that host. (The kernel TU
 * is still compiled into the library so the link itself is fine; we
 * just refuse to *call* the MULX entry points without the gate.)
 *
 * Built only when AMA_HAVE_X25519_FE64_MULX_IMPL && AMA_FE64_AVAILABLE
 * — gated in tests/c/CMakeLists.txt on x86-64 GCC/Clang non-MSVC.
 */

#define _POSIX_C_SOURCE 200809L

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "../../include/ama_cpuid.h"

/* The MULX+ADX kernel exposes two hidden-visibility entry points. We
 * declare them locally here — the test executable links the kernel TU
 * via the `ama_cryptography_test` static library. */
extern void ama_x25519_fe64_mul_mulx(uint64_t h[4], const uint64_t f[4],
                                     const uint64_t g[4]);
extern void ama_x25519_fe64_sq_mulx(uint64_t h[4], const uint64_t f[4]);

/* Pull in the pure-C reference. fe64.h is header-only and the
 * functions are `static inline`, so just including it gives us the
 * reference symbols privately. */
#define AMA_FE64_INCLUDE_FOR_TEST 1
#include "../../src/c/fe64.h"

#define N_VECTORS 4096

static void fill_random(uint8_t *buf, size_t len, uint64_t *state) {
    /* xorshift64* — deterministic, repeatable, sufficient for test
     * vectors. Not cryptographic. */
    for (size_t i = 0; i < len; i++) {
        uint64_t x = *state;
        x ^= x >> 12; x ^= x << 25; x ^= x >> 27;
        *state = x;
        buf[i] = (uint8_t)((x * 0x2545F4914F6CDD1DULL) >> 56);
    }
}

static void hexdump(const char *label, const uint8_t *bytes) {
    fprintf(stderr, "    %s ", label);
    for (int i = 0; i < 32; i++) fprintf(stderr, "%02x", bytes[i]);
    fprintf(stderr, "\n");
}

int main(void) {
    if (!ama_cpuid_has_x25519_mulx()) {
        fprintf(stderr,
                "SKIP: host lacks BMI2 + ADX (CPUID.(EAX=7,ECX=0):"
                "EBX[8]+EBX[19]); MULX+ADX kernel not exercised on "
                "this runner.\n");
        return 77;  /* CTest skip code */
    }

    uint64_t rng = 0xC25519BABE2026ULL;
    uint8_t a_bytes[32], b_bytes[32];
    uint8_t out_purec[32], out_mulx[32];
    int mul_mismatches = 0;
    int sq_mismatches  = 0;

    printf("X25519 fe64 MULX+ADX vs pure-C byte-equivalence\n");
    printf("  vectors:  %d\n", N_VECTORS);
    printf("  rng seed: 0x%016llx (deterministic)\n",
           (unsigned long long)rng);

    for (int i = 0; i < N_VECTORS; i++) {
        fill_random(a_bytes, 32, &rng);
        fill_random(b_bytes, 32, &rng);

        fe64 a, b, h_purec, h_mulx;
        fe64_frombytes(a, a_bytes);
        fe64_frombytes(b, b_bytes);

        /* --- multiplication --- */
        fe64_mul(h_purec, a, b);
        ama_x25519_fe64_mul_mulx(h_mulx, a, b);

        fe64_tobytes(out_purec, h_purec);
        fe64_tobytes(out_mulx,  h_mulx);

        if (memcmp(out_purec, out_mulx, 32) != 0) {
            mul_mismatches++;
            if (mul_mismatches <= 4) {
                fprintf(stderr, "  MUL MISMATCH on vector %d\n", i);
                hexdump("a:        ", a_bytes);
                hexdump("b:        ", b_bytes);
                hexdump("pure-C:   ", out_purec);
                hexdump("MULX+ADX: ", out_mulx);
            }
        }

        /* --- squaring --- */
        fe64_sq(h_purec, a);
        ama_x25519_fe64_sq_mulx(h_mulx, a);

        fe64_tobytes(out_purec, h_purec);
        fe64_tobytes(out_mulx,  h_mulx);

        if (memcmp(out_purec, out_mulx, 32) != 0) {
            sq_mismatches++;
            if (sq_mismatches <= 4) {
                fprintf(stderr, "  SQ  MISMATCH on vector %d\n", i);
                hexdump("a:        ", a_bytes);
                hexdump("pure-C:   ", out_purec);
                hexdump("MULX+ADX: ", out_mulx);
            }
        }
    }

    if (mul_mismatches != 0 || sq_mismatches != 0) {
        fprintf(stderr,
                "\nFAIL: %d mul mismatches, %d sq mismatches across "
                "%d vectors. The MULX+ADX kernel diverged from the "
                "pure-C fe64 reference.\n",
                mul_mismatches, sq_mismatches, N_VECTORS);
        return 1;
    }

    printf("\nPASS: %d / %d vectors byte-identical between MULX+ADX "
           "kernel and pure-C fe64 reference (mul + sq).\n",
           N_VECTORS, N_VECTORS);
    return 0;
}
