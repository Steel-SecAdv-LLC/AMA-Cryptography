/**
 * Ed25519 end-to-end benchmark — measures keygen, sign, verify ops/sec.
 * Uses rdtsc for cycle counting.
 */
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <time.h>
#include "ama_cryptography.h"

static inline uint64_t rdtsc(void) {
    uint32_t lo, hi;
    __asm__ volatile("rdtsc" : "=a"(lo), "=d"(hi));
    return ((uint64_t)hi << 32) | lo;
}

static double now_sec(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec + ts.tv_nsec * 1e-9;
}

int main(void) {
    uint8_t pk[32], sk[64], sig[64];
    uint8_t msg[240];
    memset(msg, 0xAB, sizeof(msg));

    /* Warm up */
    memset(sk, 0x42, 32);
    ama_ed25519_keypair(pk, sk);
    ama_ed25519_sign(sig, msg, sizeof(msg), sk);

    int N_keygen = 50000;
    int N_sign   = 50000;
    int N_verify = 20000;

    printf("=== Ed25519 End-to-End Benchmark ===\n\n");

    for (int run = 0; run < 3; run++) {
        printf("Run %d:\n", run + 1);

        /* Keygen */
        double t0 = now_sec();
        uint64_t c0 = rdtsc();
        for (int i = 0; i < N_keygen; i++) {
            sk[0] = (uint8_t)i;
            sk[1] = (uint8_t)(i >> 8);
            ama_ed25519_keypair(pk, sk);
        }
        uint64_t c1 = rdtsc();
        double t1 = now_sec();
        double keygen_ops = N_keygen / (t1 - t0);
        double keygen_cyc = (double)(c1 - c0) / N_keygen;
        printf("  keygen:   %10.0f ops/sec  %7.0f cycles/op\n", keygen_ops, keygen_cyc);

        /* Sign */
        memset(sk, 0x42, 32);
        ama_ed25519_keypair(pk, sk);
        t0 = now_sec();
        c0 = rdtsc();
        for (int i = 0; i < N_sign; i++) {
            msg[0] = (uint8_t)i;
            ama_ed25519_sign(sig, msg, sizeof(msg), sk);
        }
        c1 = rdtsc();
        t1 = now_sec();
        double sign_ops = N_sign / (t1 - t0);
        double sign_cyc = (double)(c1 - c0) / N_sign;
        printf("  sign:     %10.0f ops/sec  %7.0f cycles/op\n", sign_ops, sign_cyc);

        /* Verify */
        ama_ed25519_sign(sig, msg, sizeof(msg), sk);
        t0 = now_sec();
        c0 = rdtsc();
        for (int i = 0; i < N_verify; i++) {
            ama_ed25519_verify(sig, msg, sizeof(msg), pk);
        }
        c1 = rdtsc();
        t1 = now_sec();
        double verify_ops = N_verify / (t1 - t0);
        double verify_cyc = (double)(c1 - c0) / N_verify;
        printf("  verify:   %10.0f ops/sec  %7.0f cycles/op\n", verify_ops, verify_cyc);

        printf("\n");
    }

    return 0;
}
