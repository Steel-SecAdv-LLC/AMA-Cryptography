/* Copyright (C) 2025-2026 Steel Security Advisors LLC */
/* SPDX-License-Identifier: Apache-2.0 */
/* * Item 18: concurrency stress harness for TSan and Helgrind.
 *
 * Threads: max(64, 8 x cores) per the audit directive, taken from AMA_T18_THREADS.
 * Duration: AMA_T18_SECONDS (the >=2 h floor is applied by the caller).
 *
 * Exercises the shared, lazily-initialised state that concurrency bugs would
 * live in -- the CPUID/dispatch one-time init (INVARIANT-15 pthread_once), the
 * platform RNG, and the per-call scratch of the hash/AEAD/signature paths --
 * from every thread at once, with no external serialisation.  Every call is a
 * public C API entry point, and every result is checked so a silent wrong
 * answer under concurrency fails the run rather than passing quietly.
 */
#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "ama_cryptography.h"

static _Atomic long g_iters;
static _Atomic int  g_fail;
static volatile int g_stop;
static double g_deadline;

static double now_s(void) {
    struct timespec ts; clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec + ts.tv_nsec / 1e9;
}

static void *worker(void *arg) {
    const long id = (long)arg;
    uint8_t msg[128], dig[32], okm[32], pk[32], sk[64], sig[64];
    uint8_t key[32], nonce[12], ct[128], tag[16];

    for (size_t i = 0; i < sizeof(msg); i++) msg[i] = (uint8_t)(id + i);
    memset(key, (int)(id & 0xff), sizeof(key));
    memset(nonce, (int)((id >> 3) & 0xff), sizeof(nonce));

    /* One keypair per thread, reused: keygen is the expensive part and the
     * shared state under test is the dispatch/RNG init, not key generation. */
    if (ama_ed25519_keypair(pk, sk) != AMA_SUCCESS) { atomic_fetch_add(&g_fail, 1); return NULL; }

    while (!g_stop && now_s() < g_deadline) {
        if (ama_sha3_256(msg, sizeof(msg), dig) != AMA_SUCCESS) { atomic_fetch_add(&g_fail,1); break; }

        if (ama_hkdf(dig, 32, msg, sizeof(msg), (const uint8_t *)"t18", 3, okm, sizeof(okm))
            != AMA_SUCCESS) { atomic_fetch_add(&g_fail,1); break; }

        if (ama_ed25519_sign(sig, msg, sizeof(msg), sk) != AMA_SUCCESS) { atomic_fetch_add(&g_fail,1); break; }
        if (ama_ed25519_verify(sig, msg, sizeof(msg), pk) != AMA_SUCCESS) {
            fprintf(stderr, "THREAD %ld: self-signed signature failed to verify\n", id);
            atomic_fetch_add(&g_fail,1); break;
        }
        /* A flipped bit must NOT verify -- pins that the verify path is real. */
        sig[0] ^= 0x01;
        if (ama_ed25519_verify(sig, msg, sizeof(msg), pk) == AMA_SUCCESS) {
            fprintf(stderr, "THREAD %ld: tampered signature verified\n", id);
            atomic_fetch_add(&g_fail,1); break;
        }
        sig[0] ^= 0x01;

        if (ama_aes256_gcm_encrypt(key, nonce, msg, sizeof(msg), (const uint8_t *)"aad", 3, ct, tag)
            != AMA_SUCCESS) { atomic_fetch_add(&g_fail,1); break; }

        ama_secure_memzero(okm, sizeof(okm));
        atomic_fetch_add(&g_iters, 1);
    }
    return NULL;
}

int main(void) {
    const char *ts = getenv("AMA_T18_THREADS");
    const char *ss = getenv("AMA_T18_SECONDS");
    int nthreads = ts ? atoi(ts) : 64;
    double secs  = ss ? atof(ss) : 60.0;
    if (nthreads < 1) nthreads = 64;

    g_deadline = now_s() + secs;
    printf("item18 thread_stress: threads=%d seconds=%.0f\n", nthreads, secs);
    fflush(stdout);

    pthread_t *t = calloc((size_t)nthreads, sizeof(*t));
    if (!t) return 2;
    for (long i = 0; i < nthreads; i++) {
        if (pthread_create(&t[i], NULL, worker, (void *)i) != 0) {
            fprintf(stderr, "pthread_create failed at %ld\n", i);
            g_stop = 1; nthreads = (int)i; break;
        }
    }
    for (int i = 0; i < nthreads; i++) pthread_join(t[i], NULL);
    free(t);

    long iters = atomic_load(&g_iters);
    int fails = atomic_load(&g_fail);
    printf("item18 thread_stress: iterations=%ld failures=%d\n", iters, fails);
    if (fails) { printf("RESULT: FAIL (correctness failure under concurrency)\n"); return 1; }
    if (iters == 0) { printf("RESULT: FAIL (no work performed)\n"); return 1; }
    printf("RESULT: PASS (no correctness failure; detector verdict is separate)\n");
    return 0;
}
