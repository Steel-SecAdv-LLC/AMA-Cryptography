/* Copyright (C) 2025-2026 Steel Security Advisors LLC */
/* SPDX-License-Identifier: Apache-2.0 */
/**
 * @file test_concurrent_init.c
 * @brief Something for the ThreadSanitizer lane to observe
 *
 * `.github/workflows/static-analysis.yml`'s `thread-sanitizer` job states the
 * class it exists to catch: "A data race on the dispatch table would cause
 * SIMD kernels to be called with NULL function pointers from one thread while
 * another is still initialising; TSan is the only sanitiser that detects this
 * class."  But ThreadSanitizer reports a race only when two threads actually
 * access the same location concurrently, and until this file was added no test
 * in `tests/c/` ever had two threads running at once: of the C test files
 * exactly one — `test_pq_parser_stack.c` — called `pthread_create`, and it
 * calls `pthread_join` on the next statement, so the worker never overlaps
 * anything.  The lane instrumented correctly and then watched a
 * single-threaded program, which made it structurally incapable of reporting
 * the class it was created for.
 *
 * That was not theoretical.  `nistp_use_mulx4()` in `src/c/ama_nistp.c` cached
 * its CPUID verdict in a plain `int`, lazily, on a path any thread doing
 * P-curve arithmetic can reach first — the "lockless flag + plain variable"
 * pattern INVARIANT-15 and `src/c/internal/ama_once.h` both prohibit outright.
 * This test is what let TSan see it: added first, it reported the race; the
 * gate was then made atomic and the report went away.  Both directions are
 * recorded in the commit that introduced this file.
 *
 * The shape is deliberate.  Every thread waits at a start gate before touching
 * anything, so the lazy initialisers are entered from N threads at genuinely
 * the same moment rather than one after another; a test that merely spawns
 * threads sequentially reproduces the old vacuity with more code.  The
 * entry points are the ones with lazily-built shared state: the dispatch
 * table, the CPUID probes behind it, the NIST-P and secp256k1 generator
 * combs.  Ed25519 no longer has any: its block below asserts the first call on
 * every thread is already the RFC 8032 answer.
 */

#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "ama_cryptography.h"
#include "ama_dispatch.h"

#define THREADS 8
#define ROUNDS  4

/* The uncompressed SEC 1 encoding of the P-256 generator (FIPS 186-4 D.1.2.3).
 * Hardcoded on purpose: deriving a point with ama_nistp_keypair() first would
 * run nistp_comb_build() under NISTP_COMB_ONCE, and the gate this test exists
 * to expose is written inside that once on the keygen path — which is exactly
 * how the race stayed invisible.  ama_nistp_point_decode reaches the same gate
 * through nistp_load_point with no once in the way, so the threads must hit it
 * from cold, before anything in this process has built a comb. */
static const uint8_t P256_GENERATOR[65] = {
    0x04,
    0x6B, 0x17, 0xD1, 0xF2, 0xE1, 0x2C, 0x42, 0x47, 0xF8, 0xBC, 0xE6, 0xE5,
    0x63, 0xA4, 0x40, 0xF2, 0x77, 0x03, 0x7D, 0x81, 0x2D, 0xEB, 0x33, 0xA0,
    0xF4, 0xA1, 0x39, 0x45, 0xD8, 0x98, 0xC2, 0x96,
    0x4F, 0xE3, 0x42, 0xE2, 0xFE, 0x1A, 0x7F, 0x9B, 0x8E, 0xE7, 0xEB, 0x4A,
    0x7C, 0x0F, 0x9E, 0x16, 0x2B, 0xCE, 0x33, 0x57, 0x6B, 0x31, 0x5E, 0xCE,
    0xCB, 0xB6, 0x40, 0x68, 0x37, 0xBF, 0x51, 0xF5
};

/* A single-use start gate, built from a mutex and a condition variable.
 *
 * NOT pthread_barrier_*.  Barriers are the _POSIX_BARRIERS *option*, not a
 * requirement of the base standard: macOS ships pthreads without them, and
 * the first version of this file named the type unconditionally and failed to
 * compile on both macOS C lanes.  Mutexes and condition variables are
 * mandatory wherever pthreads exists, so this is the portable spelling of the
 * same rendezvous — the last thread to arrive releases all of them at once,
 * which is the property the test needs. */
static pthread_mutex_t gate_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t gate_open = PTHREAD_COND_INITIALIZER;
static int gate_arrived = 0;
static int gate_released = 0;

static void gate_wait(void) {
    pthread_mutex_lock(&gate_lock);
    if (++gate_arrived == THREADS) {
        gate_released = 1;
        pthread_cond_broadcast(&gate_open);
    } else {
        while (!gate_released)
            pthread_cond_wait(&gate_open, &gate_lock);
    }
    pthread_mutex_unlock(&gate_lock);
}

static int failures = 0;
static pthread_mutex_t failures_lock = PTHREAD_MUTEX_INITIALIZER;

static void record_failure(const char *what) {
    pthread_mutex_lock(&failures_lock);
    ++failures;
    fprintf(stderr, "  FAIL: %s\n", what);
    pthread_mutex_unlock(&failures_lock);
}

/* Every call below reaches state that is built once and then shared.  The
 * point is not the return values — other tests cover correctness — it is that
 * N threads enter the initialisers together. */
static void *worker(void *arg) {
    (void)arg;
    gate_wait();

    for (int round = 0; round < ROUNDS; ++round) {
        /* FIRST, from cold: the two attacker-input P-256 paths that reach the
         * field arithmetic without going through the generator comb's
         * pthread_once.  Ordering matters — see P256_GENERATOR above. */
        {
            uint8_t decoded[64];
            if (ama_nistp_point_decode(AMA_NIST_CURVE_P256, P256_GENERATOR,
                                       sizeof(P256_GENERATOR), decoded) != AMA_SUCCESS) {
                record_failure("ama_nistp_point_decode");
            } else if (ama_nistp_pubkey_validate(AMA_NIST_CURVE_P256, decoded)
                       != AMA_SUCCESS) {
                record_failure("ama_nistp_pubkey_validate");
            }
        }

        /* Dispatch table + the CPUID probes behind it. */
        if (ama_get_dispatch_table() == NULL) {
            record_failure("ama_get_dispatch_table() returned NULL");
        }

        /* NIST-P: the generator comb (AMA_CALL_ONCE) and, on x86-64 with
         * BMI2+ADX, the MULX gate this test was written to expose. */
        for (int i = 0; i < 3; ++i) {
            static const ama_nist_curve_t curves[3] = {
                AMA_NIST_CURVE_P256, AMA_NIST_CURVE_P384, AMA_NIST_CURVE_P521
            };
            /* Sized from the widest curve (P-521): 66-byte scalar, 133-byte
             * uncompressed point.  Queried rather than assumed. */
            uint8_t sk[66], pk[133];
            if (ama_nistp_keypair(curves[i], sk, pk) != AMA_SUCCESS) {
                record_failure("ama_nistp_keypair");
            }
        }

        /* secp256k1: its own generator comb, same once-primitive. */
        {
            uint8_t sk[32], pk[33];
            memset(sk, 0x11, sizeof(sk));
            if (ama_secp256k1_pubkey_from_privkey(sk, pk) != AMA_SUCCESS) {
                record_failure("ama_secp256k1_pubkey_from_privkey");
            }
        }

        /* Ed25519: there is NO lazily-built state on this path any more.  The
         * base-point tables are `static const` (src/c/internal/
         * ama_ed25519_tables.h) and neither src/c/ama_ed25519.c nor the group
         * template writes a file-scope variable, so there is nothing to build
         * once or to race on.  What N threads entering cold can still prove
         * here is the
         * behavioural half of that claim: the very first call on every thread
         * returns the RFC 8032 §7.1 test-1 public key and signature, with no
         * warm-up call anywhere in the process and no ordering between
         * threads.  A backend that still depended on a first-caller
         * initialiser would have to get that right under this contention;
         * one with nothing to initialise gets it right by construction. */
        {
            static const uint8_t seed[32] = {
                0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60,
                0xba, 0x84, 0x4a, 0xf4, 0x92, 0xec, 0x2c, 0xc4,
                0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32, 0x69, 0x19,
                0x70, 0x3b, 0xac, 0x03, 0x1c, 0xae, 0x7f, 0x60
            };
            static const uint8_t pk_expected[32] = {
                0xd7, 0x5a, 0x98, 0x01, 0x82, 0xb1, 0x0a, 0xb7,
                0xd5, 0x4b, 0xfe, 0xd3, 0xc9, 0x64, 0x07, 0x3a,
                0x0e, 0xe1, 0x72, 0xf3, 0xda, 0xa6, 0x23, 0x25,
                0xaf, 0x02, 0x1a, 0x68, 0xf7, 0x07, 0x51, 0x1a
            };
            static const uint8_t sig_expected[64] = {
                0xe5, 0x56, 0x43, 0x00, 0xc3, 0x60, 0xac, 0x72,
                0x90, 0x86, 0xe2, 0xcc, 0x80, 0x6e, 0x82, 0x8a,
                0x84, 0x87, 0x7f, 0x1e, 0xb8, 0xe5, 0xd9, 0x74,
                0xd8, 0x73, 0xe0, 0x65, 0x22, 0x49, 0x01, 0x55,
                0x5f, 0xb8, 0x82, 0x15, 0x90, 0xa3, 0x3b, 0xac,
                0xc6, 0x1e, 0x39, 0x70, 0x1c, 0xf9, 0xb4, 0x6b,
                0xd2, 0x5b, 0xf5, 0xf0, 0x59, 0x5b, 0xbe, 0x24,
                0x65, 0x51, 0x41, 0x43, 0x8e, 0x7a, 0x10, 0x0b
            };
            uint8_t pk[32], sk[64], sig[64];
            memcpy(sk, seed, 32);
            if (ama_ed25519_keypair(pk, sk) != AMA_SUCCESS) {
                record_failure("ama_ed25519_keypair");
            } else if (memcmp(pk, pk_expected, 32) != 0) {
                record_failure("ama_ed25519_keypair: first call on this thread is not RFC 8032 test 1");
            } else if (ama_ed25519_sign(sig, NULL, 0, sk) != AMA_SUCCESS) {
                record_failure("ama_ed25519_sign");
            } else if (memcmp(sig, sig_expected, 64) != 0) {
                record_failure("ama_ed25519_sign: first call on this thread is not RFC 8032 test 1");
            } else if (ama_ed25519_verify(sig, NULL, 0, pk) != AMA_SUCCESS) {
                record_failure("ama_ed25519_verify");
            }
        }

        /* SIMD-dispatched symmetric paths. */
        {
            uint8_t digest[32];
            const uint8_t input[4] = { 1, 2, 3, 4 };
            if (ama_sha3_256(input, sizeof(input), digest) != AMA_SUCCESS) {
                record_failure("ama_sha3_256");
            }
        }
        {
            uint8_t key[32], nonce[12], ct[16], tag[16];
            const uint8_t pt[16] = { 0 };
            memset(key, 0x22, sizeof(key));
            memset(nonce, 0x33, sizeof(nonce));
            if (ama_aes256_gcm_encrypt(key, nonce, pt, sizeof(pt), NULL, 0, ct, tag)
                != AMA_SUCCESS) {
                record_failure("ama_aes256_gcm_encrypt");
            }
        }
    }
    return NULL;
}

int main(void) {
    pthread_t threads[THREADS];

    printf("Concurrent one-time-initialisation test (%d threads x %d rounds)\n",
           THREADS, ROUNDS);
    printf("  Under -fsanitize=thread this is what makes the lane non-vacuous.\n");

    for (int i = 0; i < THREADS; ++i) {
        if (pthread_create(&threads[i], NULL, worker, NULL) != 0) {
            fprintf(stderr, "pthread_create failed at %d\n", i);
            return 1;
        }
    }
    for (int i = 0; i < THREADS; ++i) {
        pthread_join(threads[i], NULL);
    }

    if (failures != 0) {
        fprintf(stderr, "FAILED: %d error(s) across %d threads\n", failures, THREADS);
        return 1;
    }
    printf("PASS: %d threads completed %d rounds each with no error\n", THREADS, ROUNDS);
    return 0;
}
