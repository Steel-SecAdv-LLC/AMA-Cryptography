/* Copyright (C) 2025-2026 Steel Security Advisors LLC */
/* SPDX-License-Identifier: Apache-2.0 */
/**
 * FROST round 2 consumes its nonce pair even when calls on one buffer
 * overlap in time (INVARIANT-49).
 *
 * THE DEFECT THIS PINS.  ama_frost_round2_sign() refused an all-zero nonce
 * pair at entry, read the nonces straight from the caller's buffer while it
 * hashed the message and the commitments, and zeroed the buffer only at
 * exit.  Two calls on one buffer that overlapped -- a participant service
 * answering a coordinator's retries on a thread pool, or Python threads
 * sharing one bytearray, since ctypes drops the GIL for the call -- both
 * passed the entry check and both returned AMA_SUCCESS.  Three such shares
 * over three messages are the 3x3 linear system mod l that recovers the
 * hiding nonce, the binding nonce and the long-term share (test_frost.c,
 * Test 8e, is the sequential form of the same attack).
 *
 * THE PROBE.  THREADS threads wait at a gate, are released together, and
 * each calls round 2 on the SAME nonce buffer over its own message.  The
 * message is large (MSG_BYTES), so under the old code each call spent its
 * whole multi-pass SHA-512 computation with the pair still unconsumed and
 * every thread that started inside that window signed.  The verdict per
 * round: exactly one AMA_SUCCESS, every other call AMA_ERROR_INVALID_PARAM,
 * the buffer zero afterwards, and the one share produced verifies -- the
 * winner signed with the real pair, not a partly zeroed copy of it.
 *
 * Measured 2026-09-24 on the pre-fix code (x86-64 gcc 13.3 Release, three
 * CPUs): 7 or 8 of the 8 calls returned AMA_SUCCESS in every one of the 16
 * rounds, and in one round the last share did not even verify -- a thread
 * had zeroed the pair while another was still reading it.  With the claim in
 * place the one-success verdict is deterministic, not probabilistic: the lock
 * orders the claims, and every claim after the first finds the zeros the
 * first one wrote.
 *
 * WHAT THIS DOES NOT SEE.  Claiming at entry without the lock leaves a window
 * of two statements (copy, then zero) in which two callers can both copy
 * before either zeroes.  This probe does not hit that window -- measured: with
 * the lock removed it passed five runs of five -- so the lock is pinned by the
 * ThreadSanitizer lane instead, which runs this binary and reports a data race
 * in frost_claim_nonce_pair when the lock is removed.
 *
 * POSIX threads only (registered with NOT WIN32), as test_concurrent_init.c.
 */

#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "ama_cryptography.h"

#define THREADS 8
#define ROUNDS 16
#define MSG_BYTES (1024u * 1024u)

/* Single-use start gate from a mutex and a condition variable -- not
 * pthread_barrier_*, which macOS does not ship (see test_concurrent_init.c). */
static pthread_mutex_t gate_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t gate_open = PTHREAD_COND_INITIALIZER;
static int gate_arrived = 0;
static int gate_generation = 0;

static void gate_wait(void) {
    pthread_mutex_lock(&gate_lock);
    const int generation = gate_generation;
    if (++gate_arrived == THREADS) {
        gate_arrived = 0;
        gate_generation++;
        pthread_cond_broadcast(&gate_open);
    } else {
        while (generation == gate_generation)
            pthread_cond_wait(&gate_open, &gate_lock);
    }
    pthread_mutex_unlock(&gate_lock);
}

/* Shared session state.  Every worker reads it; only main() writes it, and
 * only while no worker is running (before pthread_create, after join). */
static uint8_t g_group_pk[32];
static uint8_t g_shares[3 * 64];
static uint8_t g_commitments[2 * 64];
static uint8_t g_nonces[2 * 64];   /* [0..64) participant 1, the contended pair */
static const uint8_t g_signers[2] = {1, 2};
static uint8_t *g_messages[THREADS];

typedef struct {
    int id;
    ama_error_t rc;
    uint8_t share[32];
} worker_t;

static void *worker(void *arg) {
    worker_t *w = (worker_t *)arg;
    gate_wait();
    w->rc = ama_frost_round2_sign(w->share, g_messages[w->id], MSG_BYTES,
                                  g_shares + 0 * 64, 1, g_nonces,
                                  g_commitments, g_signers, 2, g_group_pk);
    return NULL;
}

static int all_zero(const uint8_t *p, size_t n) {
    uint8_t acc = 0;
    for (size_t i = 0; i < n; i++) acc |= p[i];
    return acc == 0;
}

int main(void) {
    int failures = 0;
    int max_successes = 0;

    printf("FROST round 2: concurrent calls on one nonce buffer (INVARIANT-49)\n");
    printf("===================================================================\n");

    for (int t = 0; t < THREADS; t++) {
        g_messages[t] = (uint8_t *)malloc(MSG_BYTES);
        if (!g_messages[t]) {
            fprintf(stderr, "malloc failed\n");
            return 1;
        }
        /* Distinct messages: the attack needs distinct challenges. */
        memset(g_messages[t], 0x30 + t, MSG_BYTES);
    }

    if (ama_frost_keygen_trusted_dealer(2, 3, g_group_pk, g_shares, NULL) != AMA_SUCCESS) {
        fprintf(stderr, "FAIL: keygen\n");
        return 1;
    }

    for (int round = 0; round < ROUNDS; round++) {
        pthread_t tid[THREADS];
        worker_t w[THREADS];
        int successes = 0, refusals = 0, winner = -1;

        if (ama_frost_round1_commit(g_nonces, g_commitments, g_shares + 0 * 64) != AMA_SUCCESS ||
            ama_frost_round1_commit(g_nonces + 64, g_commitments + 64,
                                    g_shares + 1 * 64) != AMA_SUCCESS) {
            fprintf(stderr, "FAIL: round 1\n");
            return 1;
        }

        for (int t = 0; t < THREADS; t++) {
            w[t].id = t;
            w[t].rc = AMA_ERROR_CRYPTO;   /* poisoned: every worker overwrites */
            memset(w[t].share, 0, sizeof w[t].share);
            if (pthread_create(&tid[t], NULL, worker, &w[t]) != 0) {
                fprintf(stderr, "FAIL: pthread_create\n");
                return 1;
            }
        }
        for (int t = 0; t < THREADS; t++) {
            pthread_join(tid[t], NULL);
        }

        for (int t = 0; t < THREADS; t++) {
            if (w[t].rc == AMA_SUCCESS) {
                successes++;
                winner = t;
            } else if (w[t].rc == AMA_ERROR_INVALID_PARAM) {
                refusals++;
            }
        }
        if (successes > max_successes) max_successes = successes;

        if (successes != 1 || refusals != THREADS - 1) {
            fprintf(stderr, "FAIL: round %d: %d of %d concurrent calls on one nonce "
                            "pair returned AMA_SUCCESS (%d refused); exactly one may\n",
                    round, successes, THREADS, refusals);
            failures++;
        }
        if (!all_zero(g_nonces, 64)) {
            fprintf(stderr, "FAIL: round %d: the nonce pair is not zero afterwards\n", round);
            failures++;
        }
        if (winner >= 0 &&
            ama_frost_verify_share(w[winner].share, 1, g_shares + 0 * 64 + 32,
                                   g_commitments, g_signers, 2,
                                   g_messages[winner], MSG_BYTES,
                                   g_group_pk) != AMA_SUCCESS) {
            fprintf(stderr, "FAIL: round %d: the one share produced does not verify\n",
                    round);
            failures++;
        }
    }

    for (int t = 0; t < THREADS; t++) free(g_messages[t]);
    ama_secure_memzero(g_shares, sizeof g_shares);
    ama_secure_memzero(g_nonces, sizeof g_nonces);

    printf("  %d rounds x %d threads; most successes in one round: %d\n",
           ROUNDS, THREADS, max_successes);
    printf("\n%s (%d failure(s))\n", failures ? "FAILED" : "PASSED", failures);
    return failures ? 1 : 0;
}
