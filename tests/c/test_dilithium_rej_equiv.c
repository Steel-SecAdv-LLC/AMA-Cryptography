/**
 * Copyright 2025-2026 Steel Security Advisors LLC
 * Licensed under the Apache License, Version 2.0
 *
 * Byte-equivalence test for the vectorized ML-DSA-65 rejection sampler
 * (ama_dilithium_rej_uniform_avx2) against a scalar reference matching
 * the 3-byte-per-candidate algorithm in FIPS 204 §7.3.
 *
 * Generates pseudo-random byte streams with a reproducible PRNG, runs
 * both implementations, and asserts identical output arrays and identical
 * accepted counts.  A regression in the mask extraction, the 23-bit
 * trim, or the compaction LUT would flip some accepted values to zero
 * or into the wrong slot, caught here by direct memcmp.
 */

#include <stdio.h>
#include <stdint.h>
#include <string.h>

#define DILITHIUM_Q 8380417

extern int ama_dilithium_rej_uniform_avx2(int32_t *out, size_t outlen,
                                          const uint8_t *buf, size_t buflen);

static int scalar_rej_uniform(int32_t *out, size_t outlen,
                              const uint8_t *buf, size_t buflen) {
    size_t ctr = 0, pos = 0;
    while (pos + 3 <= buflen && ctr < outlen) {
        uint32_t t = ((uint32_t)buf[pos]) |
                     ((uint32_t)buf[pos + 1] << 8) |
                     ((uint32_t)buf[pos + 2] << 16);
        t &= 0x7FFFFF;
        pos += 3;
        if (t < (uint32_t)DILITHIUM_Q) {
            out[ctr++] = (int32_t)t;
        }
    }
    return (int)ctr;
}

static uint64_t xs_state = 0xFEEDFACECAFEBABEULL;
static uint8_t xs_byte(void) {
    uint64_t x = xs_state;
    x ^= x >> 12; x ^= x << 25; x ^= x >> 27;
    xs_state = x;
    return (uint8_t)((x * 0x2545F4914F6CDD1DULL) >> 56);
}

int main(void) {
    printf("ML-DSA-65 rejection sampler AVX2-vs-scalar equivalence\n");
    printf("=======================================================\n");

#if !defined(__x86_64__) && !defined(_M_X64)
    printf("SKIP: AVX2 rejection sampler requires x86-64\n");
    return 0;
#else
    const int TRIALS = 256;
    const size_t BUF_LEN = 840; /* typical SHAKE128 squeezeblocks × ~5 */
    const size_t OUT_LEN = 256;

    uint8_t buf[840];
    int32_t out_avx[256];
    int32_t out_ref[256];

    int fail = 0;

    for (int trial = 0; trial < TRIALS; trial++) {
        for (size_t i = 0; i < BUF_LEN; i++) buf[i] = xs_byte();
        memset(out_avx, 0xAA, sizeof(out_avx));
        memset(out_ref, 0xAA, sizeof(out_ref));

        int n_avx = ama_dilithium_rej_uniform_avx2(out_avx, OUT_LEN, buf, BUF_LEN);
        int n_ref = scalar_rej_uniform(out_ref, OUT_LEN, buf, BUF_LEN);

        if (n_avx != n_ref) {
            fprintf(stderr, "FAIL: trial %d — counts differ (avx=%d, ref=%d)\n",
                    trial, n_avx, n_ref);
            fail++;
            continue;
        }
        for (int i = 0; i < n_ref; i++) {
            if (out_avx[i] != out_ref[i]) {
                fprintf(stderr, "FAIL: trial %d — slot %d differs (avx=%d, ref=%d)\n",
                        trial, i, out_avx[i], out_ref[i]);
                fail++;
                break;
            }
        }
    }

    /* Edge cases: buflen < 24 (AVX2 main loop never runs; scalar tail only). */
    {
        const size_t short_lens[] = {0, 1, 2, 3, 22, 23};
        for (size_t li = 0; li < sizeof(short_lens)/sizeof(short_lens[0]); li++) {
            size_t blen = short_lens[li];
            for (size_t i = 0; i < blen; i++) buf[i] = xs_byte();
            memset(out_avx, 0xAA, sizeof(out_avx));
            memset(out_ref, 0xAA, sizeof(out_ref));
            int n_avx = ama_dilithium_rej_uniform_avx2(out_avx, OUT_LEN, buf, blen);
            int n_ref = scalar_rej_uniform(out_ref, OUT_LEN, buf, blen);
            if (n_avx != n_ref || memcmp(out_avx, out_ref, (size_t)n_ref * sizeof(int32_t)) != 0) {
                fprintf(stderr, "FAIL: short buflen %zu mismatch\n", blen);
                fail++;
            }
        }
    }

    /* Edge case: outlen tiny (forces early scalar tail). */
    {
        for (size_t i = 0; i < BUF_LEN; i++) buf[i] = xs_byte();
        for (size_t olen = 0; olen <= 9; olen++) {
            memset(out_avx, 0xAA, sizeof(out_avx));
            memset(out_ref, 0xAA, sizeof(out_ref));
            int n_avx = ama_dilithium_rej_uniform_avx2(out_avx, olen, buf, BUF_LEN);
            int n_ref = scalar_rej_uniform(out_ref, olen, buf, BUF_LEN);
            if (n_avx != n_ref || (n_ref > 0 && memcmp(out_avx, out_ref, (size_t)n_ref * sizeof(int32_t)) != 0)) {
                fprintf(stderr, "FAIL: small outlen %zu mismatch (avx=%d ref=%d)\n",
                        olen, n_avx, n_ref);
                fail++;
            }
        }
    }

    if (fail) {
        fprintf(stderr, "\n%d failures\n", fail);
        return 1;
    }
    printf("PASS: %d random trials + short-buflen + small-outlen edge cases\n", TRIALS);
    printf("=======================================================\n");
    return 0;
#endif
}
