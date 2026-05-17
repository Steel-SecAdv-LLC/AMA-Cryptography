/**
 * Copyright 2025-2026 Steel Security Advisors LLC
 * Licensed under the Apache License, Version 2.0
 *
 * @file test_sha3_wrapper_equiv.c
 * @brief Wrapper-level SHA3 SIMD-vs-scalar equivalence test.
 *
 * `test_keccak_equiv.c` pins the Keccak-f[1600] permutation in
 * isolation.  `test_sha3.c` runs NIST KATs through the public
 * wrappers.  Neither asserts that the **public wrapper API**
 * (`ama_sha3_256`, `ama_sha3_512`, `ama_shake128_inc_*`,
 * `ama_shake256_inc_*`) produces byte-identical output when the
 * underlying dispatched Keccak permutation is swapped between the
 * SIMD kernel and the scalar reference.
 *
 * That gap matters because the wrappers do their own absorb / pad /
 * squeeze plumbing on top of the dispatched permutation; a
 * regression in the wrapper's interaction with the dispatched
 * pointer (e.g. a stale state copy or a one-off byte-order slip in
 * a SIMD-only code path) would slip through both KAT and
 * permutation-level tests.
 *
 * Methodology — for each of SHA3-256, SHA3-512, SHAKE128 and
 * SHAKE256:
 *   1. Compute the digest / XOF output on input X with the
 *      dispatched (SIMD where wired) Keccak.
 *   2. Use the `AMA_TESTING_MODE` hook
 *      `ama_test_force_keccak_f1600_scalar()` to flip the dispatch
 *      table back onto the scalar reference.
 *   3. Recompute on the same input X.
 *   4. Restore the dispatched pointer.
 *   5. Assert byte-identity of the two outputs.
 *
 * Test fails immediately on any mismatch; SKIPs with code 77 when
 * the dispatcher's `keccak_f1600` pointer is already the scalar
 * reference (no SIMD wired -> comparison would be tautological).
 */

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "ama_cryptography.h"
#include "ama_dispatch.h"

/* SHAKE / SHA3 wrappers and the streaming SHAKE API ship under the
 * core public header; their behaviour is the system under test.
 *
 * The AMA_TESTING_MODE force/restore hooks are linked in from
 * libama_cryptography_test (which is what tests/c/CMakeLists.txt
 * wires this binary against).  We do not require the consumer to be
 * compiled with AMA_TESTING_MODE — only that the library exposes
 * the symbols, matching the pattern used by
 * test_aes_gcm_scalar_kat.c et al. */

extern void ama_test_force_keccak_f1600_scalar(void);
extern void ama_test_restore_keccak_f1600(void);
extern void ama_keccak_f1600_generic(uint64_t state[25]);

static uint64_t xs_state = 0xA5A5C0FFEE013579ULL;
static uint64_t xs_next(void) {
    uint64_t x = xs_state;
    x ^= x >> 12; x ^= x << 25; x ^= x >> 27;
    xs_state = x;
    return x * 0x2545F4914F6CDD1DULL;
}

static void fill_random(uint8_t *buf, size_t n) {
    for (size_t i = 0; i < n; i++) buf[i] = (uint8_t)(xs_next() & 0xFF);
}

#define MAX_INPUT 4096
#define MAX_OUTPUT 1024

/* Each test_lengths element exercises a distinct interesting
 * boundary relative to the rate (136 B SHA3-256/SHAKE256, 168 B
 * SHAKE128, 72 B SHA3-512): empty, single-byte, sub-rate,
 * exact-rate, just-over-rate, multi-block, and a large input that
 * spans more than 16 blocks of absorption. */
static const size_t test_lengths[] = {
    0, 1, 31, 71, 72, 73,
    135, 136, 137,
    167, 168, 169,
    271, 272, 273,
    335, 336, 337,
    1024, 2048, 3217, 4096
};
static const size_t n_test_lengths =
    sizeof(test_lengths) / sizeof(test_lengths[0]);

static int run_sha3_256(void) {
    uint8_t input[MAX_INPUT];
    uint8_t out_simd[32], out_scal[32];
    for (size_t li = 0; li < n_test_lengths; li++) {
        size_t L = test_lengths[li];
        fill_random(input, L);

        if (ama_sha3_256(input, L, out_simd) != AMA_SUCCESS) {
            fprintf(stderr, "FAIL: sha3_256 (SIMD) len=%zu\n", L);
            return 1;
        }
        ama_test_force_keccak_f1600_scalar();
        ama_error_t rc = ama_sha3_256(input, L, out_scal);
        ama_test_restore_keccak_f1600();
        if (rc != AMA_SUCCESS) {
            fprintf(stderr, "FAIL: sha3_256 (scalar) len=%zu\n", L);
            return 1;
        }
        if (memcmp(out_simd, out_scal, 32) != 0) {
            fprintf(stderr, "FAIL: sha3_256 SIMD != scalar at len=%zu\n", L);
            return 1;
        }
    }
    printf("  PASS: ama_sha3_256 byte-identical across %zu lengths\n",
           n_test_lengths);
    return 0;
}

static int run_sha3_512(void) {
    uint8_t input[MAX_INPUT];
    uint8_t out_simd[64], out_scal[64];
    for (size_t li = 0; li < n_test_lengths; li++) {
        size_t L = test_lengths[li];
        fill_random(input, L);

        if (ama_sha3_512(input, L, out_simd) != AMA_SUCCESS) {
            fprintf(stderr, "FAIL: sha3_512 (SIMD) len=%zu\n", L);
            return 1;
        }
        ama_test_force_keccak_f1600_scalar();
        ama_error_t rc = ama_sha3_512(input, L, out_scal);
        ama_test_restore_keccak_f1600();
        if (rc != AMA_SUCCESS) {
            fprintf(stderr, "FAIL: sha3_512 (scalar) len=%zu\n", L);
            return 1;
        }
        if (memcmp(out_simd, out_scal, 64) != 0) {
            fprintf(stderr, "FAIL: sha3_512 SIMD != scalar at len=%zu\n", L);
            return 1;
        }
    }
    printf("  PASS: ama_sha3_512 byte-identical across %zu lengths\n",
           n_test_lengths);
    return 0;
}

/* The SHAKE wrappers are streaming (init / absorb / finalize /
 * squeeze).  We test absorb of a variable-length input followed by
 * a 1 KiB squeeze — long enough to cross multiple rate-sized
 * squeeze blocks (rate is 168 B for SHAKE128, 136 B for SHAKE256). */
static int run_shake128(void) {
    uint8_t input[MAX_INPUT];
    uint8_t out_simd[MAX_OUTPUT], out_scal[MAX_OUTPUT];
    for (size_t li = 0; li < n_test_lengths; li++) {
        size_t L = test_lengths[li];
        fill_random(input, L);

        ama_sha3_ctx ctx;
        if (ama_shake128_inc_init(&ctx) != AMA_SUCCESS ||
            ama_shake128_inc_absorb(&ctx, input, L) != AMA_SUCCESS ||
            ama_shake128_inc_finalize(&ctx) != AMA_SUCCESS ||
            ama_shake128_inc_squeeze(&ctx, out_simd, MAX_OUTPUT) != AMA_SUCCESS) {
            fprintf(stderr, "FAIL: shake128 SIMD pipeline len=%zu\n", L);
            return 1;
        }

        ama_test_force_keccak_f1600_scalar();
        ama_error_t rc =
            ama_shake128_inc_init(&ctx) |
            ama_shake128_inc_absorb(&ctx, input, L) |
            ama_shake128_inc_finalize(&ctx) |
            ama_shake128_inc_squeeze(&ctx, out_scal, MAX_OUTPUT);
        ama_test_restore_keccak_f1600();
        if (rc != AMA_SUCCESS) {
            fprintf(stderr, "FAIL: shake128 scalar pipeline len=%zu\n", L);
            return 1;
        }

        if (memcmp(out_simd, out_scal, MAX_OUTPUT) != 0) {
            fprintf(stderr, "FAIL: shake128 SIMD != scalar at len=%zu\n", L);
            return 1;
        }
    }
    printf("  PASS: ama_shake128 byte-identical across %zu lengths "
           "(1024-B squeeze)\n", n_test_lengths);
    return 0;
}

static int run_shake256(void) {
    uint8_t input[MAX_INPUT];
    uint8_t out_simd[MAX_OUTPUT], out_scal[MAX_OUTPUT];
    for (size_t li = 0; li < n_test_lengths; li++) {
        size_t L = test_lengths[li];
        fill_random(input, L);

        ama_sha3_ctx ctx;
        if (ama_shake256_inc_init(&ctx) != AMA_SUCCESS ||
            ama_shake256_inc_absorb(&ctx, input, L) != AMA_SUCCESS ||
            ama_shake256_inc_finalize(&ctx) != AMA_SUCCESS ||
            ama_shake256_inc_squeeze(&ctx, out_simd, MAX_OUTPUT) != AMA_SUCCESS) {
            fprintf(stderr, "FAIL: shake256 SIMD pipeline len=%zu\n", L);
            return 1;
        }

        ama_test_force_keccak_f1600_scalar();
        ama_error_t rc =
            ama_shake256_inc_init(&ctx) |
            ama_shake256_inc_absorb(&ctx, input, L) |
            ama_shake256_inc_finalize(&ctx) |
            ama_shake256_inc_squeeze(&ctx, out_scal, MAX_OUTPUT);
        ama_test_restore_keccak_f1600();
        if (rc != AMA_SUCCESS) {
            fprintf(stderr, "FAIL: shake256 scalar pipeline len=%zu\n", L);
            return 1;
        }

        if (memcmp(out_simd, out_scal, MAX_OUTPUT) != 0) {
            fprintf(stderr, "FAIL: shake256 SIMD != scalar at len=%zu\n", L);
            return 1;
        }
    }
    printf("  PASS: ama_shake256 byte-identical across %zu lengths "
           "(1024-B squeeze)\n", n_test_lengths);
    return 0;
}

int main(void) {
    printf("==========================================\n");
    printf("SHA3 wrapper SIMD-vs-scalar equivalence\n");
    printf("==========================================\n");

    const ama_dispatch_table_t *dt = ama_get_dispatch_table();
    if (dt == NULL || dt->keccak_f1600 == ama_keccak_f1600_generic) {
        printf("SKIP: dispatched keccak_f1600 already == scalar reference\n"
               "      (no SIMD Keccak kernel on this build/CPU; comparison\n"
               "       would be tautological)\n");
        printf("==========================================\n");
        return 77;
    }

    if (run_sha3_256()) return 1;
    if (run_sha3_512()) return 1;
    if (run_shake128()) return 1;
    if (run_shake256()) return 1;

    printf("==========================================\n");
    printf("All wrapper-level SHA3 SIMD parity checks passed\n");
    printf("==========================================\n");
    return 0;
}
