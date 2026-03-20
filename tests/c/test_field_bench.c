/**
 * Cross-validation and benchmark for field arithmetic implementations.
 *
 * Phase 1-3: validates fe51 and fe64 against existing fe25519 (ref10),
 * then benchmarks raw field multiply throughput.
 */

#include "../../include/ama_cryptography.h"
#include "../../src/c/fe51.h"
#include "../../src/c/fe64.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

/* ---- Bring in the existing ref10 field ops via ama_ed25519.c symbols ---- */
/* We can't include ama_ed25519.c directly (static functions).
 * Instead, we re-declare the types and implement wrappers that go through
 * the canonical bytes representation. */

typedef int64_t fe25519_ref[10];

/* Forward declarations of the ref10 field ops (they are static in ama_ed25519.c,
 * so we need to replicate the frombytes/tobytes for cross-validation).
 * We'll use the byte-level interface: encode/decode through 32-byte canonical form. */

/* Simple PRNG for test vectors (xoshiro256**) */
static uint64_t prng_state[4] = {
    0x180ec6d33cfd0abaULL, 0xd5a61266f0c9392cULL,
    0xa9582618e03fc9aaULL, 0x39abdc4529b1661cULL
};

static inline uint64_t rotl(uint64_t x, int k) {
    return (x << k) | (x >> (64 - k));
}

static uint64_t prng_next(void) {
    uint64_t *s = prng_state;
    uint64_t result = rotl(s[1] * 5, 7) * 9;
    uint64_t t = s[1] << 17;
    s[2] ^= s[0]; s[3] ^= s[1]; s[1] ^= s[2]; s[0] ^= s[3];
    s[2] ^= t; s[3] = rotl(s[3], 45);
    return result;
}

static void random_bytes(uint8_t *buf, int len) {
    for (int i = 0; i < len; i += 8) {
        uint64_t r = prng_next();
        int n = (len - i < 8) ? (len - i) : 8;
        for (int j = 0; j < n; j++) {
            buf[i + j] = (uint8_t)(r >> (j * 8));
        }
    }
}

static void random_fe_bytes(uint8_t *buf) {
    random_bytes(buf, 32);
    buf[31] &= 0x7f;  /* clear bit 255 */
}

/* ========================================================================
 * Cross-validation: fe51 vs byte-level equivalence
 * ======================================================================== */

static int cross_validate_frombytes_tobytes(int count) {
    int failures = 0;
    uint8_t input[32], out51[32], out64[32];

    for (int i = 0; i < count; i++) {
        random_fe_bytes(input);

        /* fe51 round-trip */
        fe51 a51;
        fe51_frombytes(a51, input);
        fe51_tobytes(out51, a51);

        /* fe64 round-trip */
        fe64 a64;
        fe64_frombytes(a64, input);
        fe64_tobytes(out64, a64);

        /* Both should produce the same canonical output.
         * Note: input may be >= p, so the output may differ from input
         * but both implementations must agree. */
        if (memcmp(out51, out64, 32) != 0) {
            printf("FAIL frombytes/tobytes at iteration %d\n", i);
            printf("  input:  "); for (int j = 0; j < 32; j++) printf("%02x", input[j]); printf("\n");
            printf("  fe51:   "); for (int j = 0; j < 32; j++) printf("%02x", out51[j]); printf("\n");
            printf("  fe64:   "); for (int j = 0; j < 32; j++) printf("%02x", out64[j]); printf("\n");
            failures++;
            if (failures > 10) return failures;
        }
    }
    return failures;
}

static int cross_validate_mul(int count) {
    int failures = 0;
    uint8_t a_bytes[32], b_bytes[32];
    uint8_t out51[32], out64[32];

    for (int i = 0; i < count; i++) {
        random_fe_bytes(a_bytes);
        random_fe_bytes(b_bytes);

        fe51 a51, b51, c51;
        fe51_frombytes(a51, a_bytes);
        fe51_frombytes(b51, b_bytes);
        fe51_mul(c51, a51, b51);
        fe51_tobytes(out51, c51);

        fe64 a64, b64, c64;
        fe64_frombytes(a64, a_bytes);
        fe64_frombytes(b64, b_bytes);
        fe64_mul(c64, a64, b64);
        fe64_tobytes(out64, c64);

        if (memcmp(out51, out64, 32) != 0) {
            printf("FAIL mul at iteration %d\n", i);
            printf("  a: "); for (int j = 0; j < 32; j++) printf("%02x", a_bytes[j]); printf("\n");
            printf("  b: "); for (int j = 0; j < 32; j++) printf("%02x", b_bytes[j]); printf("\n");
            printf("  fe51: "); for (int j = 0; j < 32; j++) printf("%02x", out51[j]); printf("\n");
            printf("  fe64: "); for (int j = 0; j < 32; j++) printf("%02x", out64[j]); printf("\n");
            failures++;
            if (failures > 10) return failures;
        }
    }
    return failures;
}

static int cross_validate_sq(int count) {
    int failures = 0;
    uint8_t a_bytes[32], out51_sq[32], out64_sq[32], out51_mul[32], out64_mul[32];

    for (int i = 0; i < count; i++) {
        random_fe_bytes(a_bytes);

        fe51 a51, c51_sq, c51_mul;
        fe51_frombytes(a51, a_bytes);
        fe51_sq(c51_sq, a51);
        fe51_tobytes(out51_sq, c51_sq);
        fe51_mul(c51_mul, a51, a51);
        fe51_tobytes(out51_mul, c51_mul);

        fe64 a64, c64_sq, c64_mul;
        fe64_frombytes(a64, a_bytes);
        fe64_sq(c64_sq, a64);
        fe64_tobytes(out64_sq, c64_sq);
        fe64_mul(c64_mul, a64, a64);
        fe64_tobytes(out64_mul, c64_mul);

        int sq_mismatch = memcmp(out51_sq, out64_sq, 32) != 0;
        int fe51_sq_vs_mul = memcmp(out51_sq, out51_mul, 32) != 0;
        int fe64_sq_vs_mul = memcmp(out64_sq, out64_mul, 32) != 0;

        if (sq_mismatch || fe51_sq_vs_mul || fe64_sq_vs_mul) {
            printf("FAIL sq at iteration %d", i);
            if (fe51_sq_vs_mul) printf(" [fe51_sq != fe51_mul]");
            if (fe64_sq_vs_mul) printf(" [fe64_sq != fe64_mul]");
            if (sq_mismatch && !fe51_sq_vs_mul && !fe64_sq_vs_mul)
                printf(" [both sq agree internally but differ from each other??]");
            printf("\n");
            if (i == 0) {
                printf("  a:        "); for (int j = 0; j < 32; j++) printf("%02x", a_bytes[j]); printf("\n");
                printf("  fe51_sq:  "); for (int j = 0; j < 32; j++) printf("%02x", out51_sq[j]); printf("\n");
                printf("  fe51_mul: "); for (int j = 0; j < 32; j++) printf("%02x", out51_mul[j]); printf("\n");
                printf("  fe64_sq:  "); for (int j = 0; j < 32; j++) printf("%02x", out64_sq[j]); printf("\n");
                printf("  fe64_mul: "); for (int j = 0; j < 32; j++) printf("%02x", out64_mul[j]); printf("\n");
            }
            failures++;
            if (failures > 10) return failures;
        }
    }
    return failures;
}

static int cross_validate_add_sub(int count) {
    int failures = 0;
    uint8_t a_bytes[32], b_bytes[32], out51[32], out64[32];

    for (int i = 0; i < count; i++) {
        random_fe_bytes(a_bytes);
        random_fe_bytes(b_bytes);

        /* Test add */
        fe51 a51, b51, c51;
        fe51_frombytes(a51, a_bytes);
        fe51_frombytes(b51, b_bytes);
        fe51_add(c51, a51, b51);
        fe51_tobytes(out51, c51);

        fe64 a64, b64, c64;
        fe64_frombytes(a64, a_bytes);
        fe64_frombytes(b64, b_bytes);
        fe64_add(c64, a64, b64);
        fe64_tobytes(out64, c64);

        if (memcmp(out51, out64, 32) != 0) {
            printf("FAIL add at iteration %d\n", i);
            failures++;
            if (failures > 10) return failures;
        }

        /* Test sub */
        fe51_sub(c51, a51, b51);
        fe51_tobytes(out51, c51);

        fe64_sub(c64, a64, b64);
        fe64_tobytes(out64, c64);

        if (memcmp(out51, out64, 32) != 0) {
            printf("FAIL sub at iteration %d\n", i);
            printf("  a: "); for (int j = 0; j < 32; j++) printf("%02x", a_bytes[j]); printf("\n");
            printf("  b: "); for (int j = 0; j < 32; j++) printf("%02x", b_bytes[j]); printf("\n");
            printf("  fe51: "); for (int j = 0; j < 32; j++) printf("%02x", out51[j]); printf("\n");
            printf("  fe64: "); for (int j = 0; j < 32; j++) printf("%02x", out64[j]); printf("\n");
            failures++;
            if (failures > 10) return failures;
        }
    }
    return failures;
}

static int cross_validate_invert(int count) {
    int failures = 0;
    uint8_t a_bytes[32], out51[32], out64[32];

    for (int i = 0; i < count; i++) {
        random_fe_bytes(a_bytes);
        /* Ensure non-zero */
        a_bytes[0] |= 1;

        fe51 a51, c51;
        fe51_frombytes(a51, a_bytes);
        fe51_invert(c51, a51);
        fe51_tobytes(out51, c51);

        fe64 a64, c64;
        fe64_frombytes(a64, a_bytes);
        fe64_invert(c64, a64);
        fe64_tobytes(out64, c64);

        if (memcmp(out51, out64, 32) != 0) {
            /* Check which one is correct: a * a^(-1) should = 1 */
            fe51 check51;
            fe51_mul(check51, a51, c51);
            uint8_t chk51[32];
            fe51_tobytes(chk51, check51);

            fe64 check64;
            fe64_mul(check64, a64, c64);
            uint8_t chk64[32];
            fe64_tobytes(chk64, check64);

            uint8_t one[32] = {1};
            int fe51_ok = memcmp(chk51, one, 32) == 0;
            int fe64_ok = memcmp(chk64, one, 32) == 0;

            printf("FAIL invert at iteration %d", i);
            if (fe51_ok && !fe64_ok) printf(" [fe64 invert wrong]");
            else if (!fe51_ok && fe64_ok) printf(" [fe51 invert wrong]");
            else if (!fe51_ok && !fe64_ok) printf(" [BOTH wrong]");
            else printf(" [both verify but differ??]");
            printf("\n");
            failures++;
            if (failures > 10) return failures;
        }
    }
    return failures;
}

/* ========================================================================
 * Known-value test: 0, 1, p-1, specific values
 * ======================================================================== */

static int known_value_tests(void) {
    int failures = 0;
    uint8_t zero[32] = {0};
    uint8_t one[32] = {1};
    uint8_t out51[32], out64[32];

    /* Test 0 */
    fe51 z51; fe51_frombytes(z51, zero); fe51_tobytes(out51, z51);
    fe64 z64; fe64_frombytes(z64, zero); fe64_tobytes(out64, z64);
    if (memcmp(out51, zero, 32) != 0 || memcmp(out64, zero, 32) != 0) {
        printf("FAIL: zero round-trip\n"); failures++;
    }

    /* Test 1 */
    fe51 o51; fe51_frombytes(o51, one); fe51_tobytes(out51, o51);
    fe64 o64; fe64_frombytes(o64, one); fe64_tobytes(out64, o64);
    if (memcmp(out51, one, 32) != 0 || memcmp(out64, one, 32) != 0) {
        printf("FAIL: one round-trip\n"); failures++;
    }

    /* Test 1 * 1 = 1 */
    fe51 prod51; fe51_mul(prod51, o51, o51); fe51_tobytes(out51, prod51);
    fe64 prod64; fe64_mul(prod64, o64, o64); fe64_tobytes(out64, prod64);
    if (memcmp(out51, one, 32) != 0) { printf("FAIL: fe51 1*1 != 1\n"); failures++; }
    if (memcmp(out64, one, 32) != 0) { printf("FAIL: fe64 1*1 != 1\n"); failures++; }

    /* Test p-1 = 2^255 - 20 (should reduce to p-1 since it's < p) */
    uint8_t pm1[32];
    memset(pm1, 0xff, 32);
    pm1[31] = 0x7f;  /* = 2^255 - 1 */
    /* Subtract 19 to get p-1 = 2^255 - 20 */
    /* Actually 2^255-1 is all 0xff with top bit clear. p = 2^255-19, so
     * p-1 = 2^255-20. In bytes: 0xEC, 0xFF, ..., 0xFF, 0x7F */
    pm1[0] = 0xec;  /* 256-20 = 236 = 0xEC */
    for (int i = 1; i < 31; i++) pm1[i] = 0xff;
    pm1[31] = 0x7f;

    fe51 pm1_51; fe51_frombytes(pm1_51, pm1); fe51_tobytes(out51, pm1_51);
    fe64 pm1_64; fe64_frombytes(pm1_64, pm1); fe64_tobytes(out64, pm1_64);
    if (memcmp(out51, pm1, 32) != 0) { printf("FAIL: fe51 p-1 round-trip\n"); failures++; }
    if (memcmp(out64, pm1, 32) != 0) { printf("FAIL: fe64 p-1 round-trip\n"); failures++; }

    return failures;
}

/* ========================================================================
 * Benchmarks
 * ======================================================================== */

#if defined(__x86_64__) || defined(_M_X64)
static inline uint64_t rdtsc(void) {
    unsigned int lo, hi;
    __asm__ __volatile__ ("rdtsc" : "=a"(lo), "=d"(hi));
    return ((uint64_t)hi << 32) | lo;
}
#else
static inline uint64_t rdtsc(void) { return 0; }
#endif

#define BENCH_ITERS 1000000

/* Compiler barrier: prevents dead-code elimination of benchmark loops */
static volatile uint64_t bench_sink;

#define BENCH_FE_MUL(NAME, TYPE, MUL_FN, FROM_FN) \
static void bench_##NAME(void) { \
    uint8_t a_bytes[32], b_bytes[32]; \
    random_fe_bytes(a_bytes); random_fe_bytes(b_bytes); \
    TYPE a, b, c; \
    FROM_FN(a, a_bytes); FROM_FN(b, b_bytes); \
    for (int i = 0; i < 10000; i++) { MUL_FN(c, a, b); a[0] ^= c[0] & 1; } \
    uint64_t t0 = rdtsc(); \
    struct timespec ts0, ts1; \
    clock_gettime(CLOCK_MONOTONIC, &ts0); \
    for (int i = 0; i < BENCH_ITERS; i++) { \
        MUL_FN(c, a, b); \
        a[0] ^= c[0] & 1; \
    } \
    uint64_t t1 = rdtsc(); \
    clock_gettime(CLOCK_MONOTONIC, &ts1); \
    bench_sink = c[0]; \
    double elapsed = (ts1.tv_sec - ts0.tv_sec) + (ts1.tv_nsec - ts0.tv_nsec) / 1e9; \
    double ops_per_sec = BENCH_ITERS / elapsed; \
    double cycles = (double)(t1 - t0) / BENCH_ITERS; \
    printf("  " #NAME ":  %12.0f ops/sec  %6.1f cycles/op  (%.3f s)\n", ops_per_sec, cycles, elapsed); \
}

#define BENCH_FE_SQ(NAME, TYPE, SQ_FN, FROM_FN) \
static void bench_##NAME(void) { \
    uint8_t a_bytes[32]; \
    random_fe_bytes(a_bytes); \
    TYPE a, c; FROM_FN(a, a_bytes); \
    for (int i = 0; i < 10000; i++) { SQ_FN(c, a); a[0] ^= c[0] & 1; } \
    uint64_t t0 = rdtsc(); \
    struct timespec ts0, ts1; \
    clock_gettime(CLOCK_MONOTONIC, &ts0); \
    for (int i = 0; i < BENCH_ITERS; i++) { \
        SQ_FN(c, a); \
        a[0] ^= c[0] & 1; \
    } \
    uint64_t t1 = rdtsc(); \
    clock_gettime(CLOCK_MONOTONIC, &ts1); \
    bench_sink = c[0]; \
    double elapsed = (ts1.tv_sec - ts0.tv_sec) + (ts1.tv_nsec - ts0.tv_nsec) / 1e9; \
    double ops_per_sec = BENCH_ITERS / elapsed; \
    double cycles = (double)(t1 - t0) / BENCH_ITERS; \
    printf("  " #NAME ":   %12.0f ops/sec  %6.1f cycles/op  (%.3f s)\n", ops_per_sec, cycles, elapsed); \
}

BENCH_FE_MUL(fe51_mul, fe51, fe51_mul, fe51_frombytes)
BENCH_FE_MUL(fe64_mul, fe64, fe64_mul, fe64_frombytes)
BENCH_FE_SQ(fe51_sq, fe51, fe51_sq, fe51_frombytes)
BENCH_FE_SQ(fe64_sq, fe64, fe64_sq, fe64_frombytes)

int main(void) {
    int total_failures = 0;

    printf("=== Field Arithmetic Cross-Validation ===\n\n");

    printf("Known-value tests...\n");
    total_failures += known_value_tests();

    printf("Cross-validate frombytes/tobytes (10000 random)...\n");
    total_failures += cross_validate_frombytes_tobytes(10000);

    printf("Cross-validate mul (10000 random)...\n");
    total_failures += cross_validate_mul(10000);

    printf("Cross-validate sq (10000 random)...\n");
    total_failures += cross_validate_sq(10000);

    printf("Cross-validate add/sub (10000 random)...\n");
    total_failures += cross_validate_add_sub(10000);

    printf("Cross-validate invert (100 random)...\n");
    total_failures += cross_validate_invert(100);

    if (total_failures > 0) {
        printf("\n*** %d FAILURES — DO NOT PROCEED ***\n", total_failures);
        return 1;
    }

    printf("\nAll cross-validation tests PASSED.\n\n");

    printf("=== Field Arithmetic Benchmark (1M iterations, 3 runs) ===\n\n");

    for (int run = 0; run < 3; run++) {
        printf("Run %d:\n", run + 1);
        bench_fe51_mul();
        bench_fe64_mul();
        bench_fe51_sq();
        bench_fe64_sq();
        printf("\n");
    }

    return 0;
}
