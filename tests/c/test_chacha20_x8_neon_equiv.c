/**
 * Copyright 2025-2026 Steel Security Advisors LLC
 * Licensed under the Apache License, Version 2.0
 *
 * @file test_chacha20_x8_neon_equiv.c
 * @brief Byte-for-byte equivalence test for the NEON ChaCha20 8-way
 *        block kernel (ama_chacha20_block_x8_neon) against the scalar
 *        single-block ChaCha20 reference.
 *
 * The NEON kernel emits 8 × 64 = 512 bytes of keystream for a single
 * key/nonce starting at `counter`.  We compute the same 512 bytes via
 * eight sequential calls to the scalar block function and assert
 * byte-for-byte equality.  This catches lane-shuffle / column-vs-
 * diagonal mistakes in the NEON path that the higher-level
 * test_chacha20poly1305 KAT would miss because that test fixes the
 * counter at zero and processes only one block at a time.
 *
 * SKIP_RETURN_CODE 77 conditions (surfaces as "Skipped" in ctest):
 *   - Non-AArch64 build or AMA_HAVE_NEON_IMPL undefined.
 *   - AArch64 host where the dispatcher leaves chacha20_block_x8 NULL
 *     (no NEON, env opt-out, etc).
 */

#include "ama_cryptography.h"
#include "ama_cpuid.h"
#include "ama_dispatch.h"
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#if defined(AMA_HAVE_NEON_IMPL) && (defined(__aarch64__) || defined(_M_ARM64))
extern void ama_chacha20_block_x8_neon(const uint8_t key[32],
                                        const uint8_t nonce[12],
                                        uint32_t counter,
                                        uint8_t out[512]);
#endif

/* Local scalar ChaCha20 block reference.  Lives in the test TU so the
 * production library's `chacha20_block` static symbol does not need
 * to be exported just for a test, and so a future rename / refactor
 * of the production implementation cannot accidentally invalidate the
 * equivalence contract by mutating the reference side of the test.
 *
 * Spec is RFC 8439 §2.3: column rounds + diagonal rounds, 10 double
 * rounds, then add the initial state into the working state.  This
 * is the same algorithm the in-tree production scalar implements; we
 * just keep an independent copy here as the equivalence ground truth.
 */
#if defined(AMA_HAVE_NEON_IMPL) && (defined(__aarch64__) || defined(_M_ARM64))
static uint32_t rotl32_ref(uint32_t v, int n) {
    return (v << n) | (v >> (32 - n));
}
static uint32_t load32_le_ref(const uint8_t *p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}
static void store32_le_ref(uint8_t *p, uint32_t v) {
    p[0] = (uint8_t)v;        p[1] = (uint8_t)(v >> 8);
    p[2] = (uint8_t)(v >> 16); p[3] = (uint8_t)(v >> 24);
}
#define QR_REF(a, b, c, d) do {                          \
    (a) += (b); (d) = rotl32_ref((d) ^ (a), 16);          \
    (c) += (d); (b) = rotl32_ref((b) ^ (c), 12);          \
    (a) += (b); (d) = rotl32_ref((d) ^ (a), 8);           \
    (c) += (d); (b) = rotl32_ref((b) ^ (c), 7);           \
} while (0)
static void chacha20_block_ref(const uint8_t key[32],
                                const uint8_t nonce[12],
                                uint32_t counter,
                                uint8_t out[64]) {
    uint32_t s[16];
    s[0] = 0x61707865; s[1] = 0x3320646e;
    s[2] = 0x79622d32; s[3] = 0x6b206574;
    for (int i = 0; i < 8; i++) s[4 + i] = load32_le_ref(key + i * 4);
    s[12] = counter;
    s[13] = load32_le_ref(nonce);
    s[14] = load32_le_ref(nonce + 4);
    s[15] = load32_le_ref(nonce + 8);
    uint32_t w[16];
    memcpy(w, s, sizeof(s));
    for (int r = 0; r < 10; r++) {
        QR_REF(w[0], w[4], w[8],  w[12]);
        QR_REF(w[1], w[5], w[9],  w[13]);
        QR_REF(w[2], w[6], w[10], w[14]);
        QR_REF(w[3], w[7], w[11], w[15]);
        QR_REF(w[0], w[5], w[10], w[15]);
        QR_REF(w[1], w[6], w[11], w[12]);
        QR_REF(w[2], w[7], w[8],  w[13]);
        QR_REF(w[3], w[4], w[9],  w[14]);
    }
    for (int i = 0; i < 16; i++) store32_le_ref(out + i * 4, w[i] + s[i]);
}

static uint64_t prng_state;
static uint64_t prng_next(void) {
    uint64_t z = (prng_state += 0x9E3779B97F4A7C15ULL);
    z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ULL;
    z = (z ^ (z >> 27)) * 0x94D049BB133111EBULL;
    return z ^ (z >> 31);
}
static void prng_fill(uint8_t *buf, size_t n) {
    for (size_t i = 0; i < n; i++) buf[i] = (uint8_t)(prng_next() >> 24);
}
#endif /* AMA_HAVE_NEON_IMPL && __aarch64__ */

int main(void) {
    printf("===============================================\n");
    printf("NEON ChaCha20 8-way vs scalar single-block test\n");
    printf("===============================================\n\n");

#if !defined(AMA_HAVE_NEON_IMPL) || (!defined(__aarch64__) && !defined(_M_ARM64))
    printf("  SKIP: NEON ChaCha20 sources not compiled in.\n");
    return 77;
#else
    const ama_dispatch_table_t *dt = ama_get_dispatch_table();
    if (dt->chacha20_block_x8 != ama_chacha20_block_x8_neon) {
        printf("  SKIP: dispatcher did not select the NEON ChaCha20\n"
               "        8-way kernel (env opt-out or alternative ISA).\n");
        return 77;
    }

    int failed = 0;
    int passed = 0;

    prng_state = 0xCAFEBABEFEEDFACEULL;

    for (int trial = 0; trial < 1024; trial++) {
        uint8_t key[32], nonce[12];
        uint32_t counter = (uint32_t)prng_next();
        prng_fill(key, 32); prng_fill(nonce, 12);

        uint8_t simd_out[512];
        uint8_t gen_out[512];

        dt->chacha20_block_x8(key, nonce, counter, simd_out);

        /* Reference: 8 sequential single-block calls. */
        for (uint32_t i = 0; i < 8; i++) {
            chacha20_block_ref(key, nonce, counter + i,
                                gen_out + i * 64);
        }

        if (memcmp(simd_out, gen_out, 512) != 0) {
            /* Find the first differing byte for a useful trace. */
            int first_diff = -1;
            for (int b = 0; b < 512; b++) {
                if (simd_out[b] != gen_out[b]) { first_diff = b; break; }
            }
            printf("  FAIL: trial=%d counter=%u first_diff_byte=%d\n",
                   trial, counter, first_diff);
            failed++;
            continue;
        }
        passed++;
    }

    printf("\n===============================================\n");
    if (failed) {
        printf("FAILED: %d byte-identity check(s) between NEON 8-way\n"
               "        and scalar single-block.  PASSED: %d.\n",
               failed, passed);
        return 1;
    }
    printf("All %d ChaCha20 8-way equivalence checks passed\n", passed);
    printf("===============================================\n");
    return 0;
#endif
}
