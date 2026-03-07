/**
 * Copyright 2025 Steel Security Advisors LLC
 * Licensed under the Apache License, Version 2.0
 *
 * Performance benchmarks for C implementations
 */

#define _POSIX_C_SOURCE 199309L
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <stdint.h>
#include "ama_cryptography.h"

#define ITERATIONS 10000
#define WARMUP 100

static double benchmark_operation(void (*op)(void), const char* name) {
    struct timespec start, end;
    int i;

    /* Warmup */
    for (i = 0; i < WARMUP; i++) {
        op();
    }

    /* Timed run */
    clock_gettime(CLOCK_MONOTONIC, &start);
    for (i = 0; i < ITERATIONS; i++) {
        op();
    }
    clock_gettime(CLOCK_MONOTONIC, &end);

    double elapsed = (end.tv_sec - start.tv_sec) + (end.tv_nsec - start.tv_nsec) / 1e9;
    double ops_per_sec = ITERATIONS / elapsed;
    double us_per_op = (elapsed / ITERATIONS) * 1e6;

    printf("  %-25s %10.0f ops/sec  (%.3f µs/op)\n", name, ops_per_sec, us_per_op);
    return ops_per_sec;
}

/* Test data */
static uint8_t test_message[1024];
static uint8_t test_output[64];
static uint8_t test_key[64];

/* Benchmark functions */
static void bench_sha3_256_short(void) {
    ama_sha3_256((const uint8_t*)"Hello, World!", 13, test_output);
}

static void bench_sha3_256_1kb(void) {
    ama_sha3_256(test_message, 1024, test_output);
}

static void bench_hkdf_32(void) {
    ama_hkdf(test_key, 32, test_key, 32, (const uint8_t*)"info", 4, test_output, 32);
}

static void bench_hkdf_64(void) {
    ama_hkdf(test_key, 32, test_key, 32, (const uint8_t*)"info", 4, test_output, 64);
}

static void bench_consttime_memcmp(void) {
    ama_consttime_memcmp(test_message, test_message + 512, 512);
}

static void bench_secure_memzero(void) {
    ama_secure_memzero(test_output, 64);
}

static void bench_ed25519_sign(void) {
    uint8_t sig[64];
    ama_ed25519_sign(sig, test_message, 32, test_key);
}

static void bench_sha3_streaming(void) {
    ama_sha3_ctx ctx;
    ama_sha3_init(&ctx);
    /* Simulate streaming: 4 chunks of 256 bytes each */
    ama_sha3_update(&ctx, test_message, 256);
    ama_sha3_update(&ctx, test_message + 256, 256);
    ama_sha3_update(&ctx, test_message + 512, 256);
    ama_sha3_update(&ctx, test_message + 768, 256);
    ama_sha3_final(&ctx, test_output);
}

int main(void) {
    /* Initialize test data */
    memset(test_message, 0xAA, sizeof(test_message));
    memset(test_key, 0x42, sizeof(test_key));

    /* Generate Ed25519 keypair for signing benchmark */
    uint8_t pk[32], sk[64];
    memcpy(sk, test_key, 32);
    ama_ed25519_keypair(pk, sk);
    memcpy(test_key, sk, 64);

    printf("============================================================\n");
    printf("AMA CRYPTOGRAPHY - C LIBRARY PERFORMANCE BENCHMARKS\n");
    printf("============================================================\n");
    printf("Iterations: %d (+ %d warmup)\n\n", ITERATIONS, WARMUP);

    printf("SHA3-256 (Keccak-f[1600]):\n");
    benchmark_operation(bench_sha3_256_short, "SHA3-256 (13 bytes)");
    benchmark_operation(bench_sha3_256_1kb, "SHA3-256 (1 KB)");
    benchmark_operation(bench_sha3_streaming, "SHA3-256 streaming (1 KB)");

    printf("\nHKDF-SHA3-256:\n");
    benchmark_operation(bench_hkdf_32, "HKDF (32-byte output)");
    benchmark_operation(bench_hkdf_64, "HKDF (64-byte output)");

    printf("\nConstant-Time Utilities:\n");
    benchmark_operation(bench_consttime_memcmp, "consttime_memcmp (512 bytes)");
    benchmark_operation(bench_secure_memzero, "secure_memzero (64 bytes)");

    printf("\nEd25519 (native C):\n");
    benchmark_operation(bench_ed25519_sign, "Ed25519 sign (32-byte msg)");

    printf("\n============================================================\n");
    printf("Benchmarks complete.\n");
    printf("============================================================\n");

    return 0;
}
